"""Tests for the experimental lab.

Run from the repository root:

    python3 -m unittest discover -s lab/tests -t . -v

No pytest, no fixtures, no network. Each test is either a correctness check on a
formula or a regression test for a specific bug found while porting the design notes
into working code.
"""

from __future__ import annotations

import math
import unittest

import numpy as np

from lab.data import synthetic
from lab.features import contract, pipeline
from lab.model import belief, logistic, monitor, temporal_cv
from lab.privacy import dp


def sample_events():
    records, truth = synthetic.generate(seed=3, scripted_clients=7, human_clients=9, events_each=40)
    return records, truth


class ContractTests(unittest.TestCase):
    def base_event(self, **overrides):
        payload = dict(
            event_id="e-1",
            observed_at=1767225600.0,
            source_id="feed:test",
            client_key="0123456789abcdef",
            channel="site_visit",
            protocol="h2",
            ua_family="firefox",
            fingerprint_hash="ja4:abc",
            network_class="residential",
            bytes_in=100,
            latency_ms=12.5,
        )
        payload.update(overrides)
        return contract.EventRecord(**payload)

    def test_accepts_valid_record(self):
        self.base_event().validate()

    def test_rejects_unknown_channel(self):
        with self.assertRaises(contract.ContractViolation):
            self.base_event(channel="exfil").validate()

    def test_rejects_non_finite_time(self):
        with self.assertRaises(contract.ContractViolation):
            self.base_event(observed_at=float("nan")).validate()

    def test_rejects_short_client_key(self):
        with self.assertRaises(contract.ContractViolation):
            self.base_event(client_key="abc").validate()

    def test_client_key_is_salted_and_epoch_scoped(self):
        a = contract.derive_client_key(b"secret", "2026-11", "203.0.113.5")
        b = contract.derive_client_key(b"secret", "2026-11", "203.0.113.5")
        c = contract.derive_client_key(b"secret", "2026-12", "203.0.113.5")
        self.assertEqual(a, b)
        self.assertNotEqual(a, c)
        self.assertNotIn("203.0.113.5", a)
        self.assertEqual(len(a), 16)

    def test_refuses_to_hash_without_secret(self):
        with self.assertRaises(contract.ContractViolation):
            contract.derive_client_key(b"", "2026-11", "203.0.113.5")


class FeatureTests(unittest.TestCase):
    def test_robust_cv_survives_tight_gaps_where_std_over_mean_explodes(self):
        # A burst of sub-millisecond gaps followed by one page load: the case where a
        # plain coefficient of variation reports double-digit dispersion for traffic
        # that is actually metronomic for most of its packets.
        gaps = [0.0008] * 200 + [5.0]
        mean = sum(gaps) / len(gaps)
        std = math.sqrt(sum((g - mean) ** 2 for g in gaps) / (len(gaps) - 1))
        naive_cv = std / mean
        robust = pipeline._robust_cv(gaps)
        self.assertGreater(naive_cv, 10.0, "the naive ratio should be absurd here")
        self.assertLess(robust, 2.0, "the MAD-based ratio should stay bounded")
        self.assertGreaterEqual(robust, 0.0)

    def test_clockwork_share_separates_periodic_from_bursty(self):
        periodic = [30.0, 30.1, 29.9, 30.05, 29.95, 30.0]
        bursty = [1.0, 2.0, 400.0, 3.0, 900.0, 5.0]
        self.assertGreater(pipeline._clockwork_share(periodic), 0.9)
        self.assertLess(pipeline._clockwork_share(bursty), 0.2)

    def test_min_events_floor_drops_thin_rows(self):
        records, _ = sample_events()
        rows = pipeline.build_feature_table(records, min_events=50)
        self.assertTrue(all(r.events >= 50 for r in rows))
        full = pipeline.build_feature_table(records, min_events=5)
        self.assertGreaterEqual(len(full), len(rows))

    def test_feature_vector_is_finite(self):
        records, _ = sample_events()
        rows = pipeline.build_feature_table(records, min_events=5)
        self.assertTrue(rows)
        for row in rows:
            for value in row.vector():
                self.assertTrue(math.isfinite(value), f"non-finite feature in {row.client_key}")


class TemporalValidationTests(unittest.TestCase):
    def test_folds_never_leak_future_into_past(self):
        records, truth = sample_events()
        rows = pipeline.build_feature_table(records, min_events=5)
        labels = [1.0 if truth.get(r.client_key) == "scripted" else 0.0 for r in rows]
        report = temporal_cv.run_validation(rows, labels, pipeline.FEATURE_NAMES, n_folds=3)
        self.assertEqual(report["leakage_check"], "passed")
        self.assertTrue(report["folds"])
        for fold in report["folds"]:
            self.assertLessEqual(fold["n_train"], len(rows))

    def test_too_few_rows_is_an_error(self):
        records, truth = sample_events()
        rows = pipeline.build_feature_table(records, min_events=5)
        labels = [1.0 if truth.get(r.client_key) == "scripted" else 0.0 for r in rows]
        with self.assertRaises(ValueError):
            temporal_cv.run_validation(rows, labels, pipeline.FEATURE_NAMES, n_folds=99)


class ModelTests(unittest.TestCase):
    def test_auc_on_separable_data(self):
        y = np.array([0.0, 0.0, 1.0, 1.0])
        scores = np.array([0.1, 0.2, 0.8, 0.9])
        self.assertAlmostEqual(logistic.roc_auc(y, scores), 1.0)

    def test_auc_handles_ties(self):
        y = np.array([0.0, 1.0])
        self.assertAlmostEqual(logistic.roc_auc(y, np.array([0.5, 0.5])), 0.5)

    def test_subset_model_predicts_on_full_matrix(self):
        # Regression test: the shadow model trains on alternating columns. Before the
        # fix it received the full matrix at inference time and raised a broadcast error.
        rng = np.random.default_rng(0)
        X = rng.normal(size=(40, 6))
        y = (X[:, 0] + X[:, 2] > 0).astype(float)
        names = [f"f{i}" for i in range(6)]
        model = logistic.fit(X, y, names, columns=[0, 2, 4])
        scores = model.predict_proba(X)
        self.assertEqual(scores.shape, (40,))
        self.assertTrue(np.all((scores >= 0.0) & (scores <= 1.0)))


class MonitorTests(unittest.TestCase):
    def test_psi_near_zero_for_same_distribution(self):
        rng = np.random.default_rng(1)
        a = rng.random(500)
        b = rng.random(500)
        self.assertLess(monitor.psi(a, b), 0.1)

    def test_psi_large_for_shifted_distribution(self):
        rng = np.random.default_rng(2)
        a = rng.random(500) * 0.2
        b = rng.random(500) * 0.2 + 0.8
        self.assertGreater(monitor.psi(a, b), 0.25)

    def test_psi_does_not_explode_on_saturated_scores(self):
        # Regression test: quantile binning produced PSI in the thousands when every
        # score was exactly 0.0 or 1.0, which is normal classifier output.
        a = np.array([0.0] * 300 + [1.0] * 200)
        b = np.array([0.0] * 280 + [1.0] * 220)
        self.assertLess(monitor.psi(a, b), 0.5)

    def test_volatility_gate_flags_outlier(self):
        history = [0.2, 0.25, 0.22, 0.3, 0.27, 0.24, 0.26]
        z, outlier = monitor.volatility_z(0.9, history)
        self.assertTrue(outlier)
        z2, outlier2 = monitor.volatility_z(0.26, history)
        self.assertFalse(outlier2)

    def test_shadow_flags_more_when_labels_are_corrupted(self):
        records, truth = sample_events()
        rows = pipeline.build_feature_table(records, min_events=5)
        labels = [1.0 if truth.get(r.client_key) == "scripted" else 0.0 for r in rows]
        cut = max(2, len(rows) // 2)
        clean = monitor.shadow_divergence(rows[:cut], labels[:cut], rows[cut:], labels[cut:], pipeline.FEATURE_NAMES)
        noisy_labels = list(labels[:cut])
        for i in range(0, len(noisy_labels), 3):
            noisy_labels[i] = 1.0 - noisy_labels[i]
        noisy = monitor.shadow_divergence(rows[:cut], noisy_labels, rows[cut:], labels[cut:], pipeline.FEATURE_NAMES)
        self.assertGreater(noisy.divergence, clean.divergence)


class BeliefTests(unittest.TestCase):
    def test_normalize_projects_onto_simplex(self):
        p = belief.normalize([-1.0, 2.0, 2.0])
        self.assertAlmostEqual(float(p.sum()), 1.0, places=9)
        self.assertTrue(np.all(p > 0))

    def test_normalize_handles_all_zero(self):
        p = belief.normalize([0.0, 0.0, 0.0])
        self.assertAlmostEqual(float(p.sum()), 1.0, places=9)

    def test_below_threshold_returns_naive_posterior(self):
        result = belief.reflexive_update([0.5, 0.3, 0.2], [0.2, 0.7, 0.1], source_benefit=0.3)
        np.testing.assert_allclose(result.posterior, result.naive)
        self.assertEqual(result.iterations, 0)
        self.assertTrue(result.converged)

    def test_high_benefit_pulls_posterior_back_toward_prior(self):
        prior = [0.34, 0.33, 0.33]
        likelihoods = [0.05, 0.90, 0.05]
        naive = belief.bayes_update(prior, likelihoods)
        result = belief.reflexive_update(prior, likelihoods, source_benefit=0.95)
        shift_naive = float(np.abs(naive - np.array(prior)).sum())
        shift_reflexive = float(np.abs(result.posterior - np.array(prior)).sum())
        self.assertLess(shift_reflexive, shift_naive)
        self.assertTrue(result.converged)
        self.assertLessEqual(result.iterations, 64)

    def test_posterior_never_leaves_simplex(self):
        result = belief.reflexive_update([0.9, 0.05, 0.05], [0.01, 0.99, 0.01], source_benefit=0.99)
        self.assertAlmostEqual(float(result.posterior.sum()), 1.0, places=9)
        self.assertTrue(np.all(result.posterior >= 0.0))
        self.assertTrue(np.all(np.isfinite(result.posterior)))

    def test_extreme_benefit_barely_moves_belief(self):
        prior = [0.34, 0.33, 0.33]
        result = belief.reflexive_update(prior, [0.0, 1.0, 0.0], source_benefit=1.0, beta=50.0)
        self.assertLess(float(np.abs(result.posterior - np.array(prior)).sum()), 0.01)


class PrivacyTests(unittest.TestCase):
    def test_budget_refuses_to_overspend(self):
        budget = dp.Budget(total_epsilon=0.5)
        budget.spend(0.3, "first")
        with self.assertRaises(dp.BudgetExhausted):
            budget.spend(0.3, "second")
        self.assertAlmostEqual(budget.remaining, 0.2, places=9)

    def test_noisy_count_is_close_with_large_epsilon(self):
        rng = np.random.default_rng(0)
        estimates = [dp.noisy_count(1000, 10.0, rng) for _ in range(50)]
        self.assertLess(abs(sum(estimates) / len(estimates) - 1000), 40)

    def test_suppression_drops_small_cells(self):
        cells = {"a": 1, "b": 4, "c": 5, "d": 100}
        self.assertEqual(set(dp.suppress_small_cells(cells, k=5)), {"c", "d"})


class EndToEndTests(unittest.TestCase):
    def test_pipeline_reports_expected_sections(self):
        from lab.orchestrator import run_pipeline

        records, truth = synthetic.generate(seed=5)
        report = run_pipeline.run(records, truth)
        for key in (
            "data",
            "features",
            "temporal_validation",
            "holdout",
            "shadow_model",
            "poisoning_probe",
            "differential_privacy",
            "reflexive_update",
        ):
            self.assertIn(key, report)
        self.assertEqual(report["temporal_validation"]["expanding"]["leakage_check"], "passed")
        self.assertTrue(report["poisoning_probe"]["reacted"])


if __name__ == "__main__":
    unittest.main()
