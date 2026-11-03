"""Tests for the economics layer: arithmetic, proportionality, ladder, loop.

The arithmetic tests use small synthetic numbers so the expected values can be computed by
hand. The policy tests check the properties that make the ladder load-bearing rather than
decorative: requirements only grow as value grows, ceilings only tighten, fingerprint depth is
non-decreasing, and competing controls are never silently double-counted.

Adaptation gets the most attention, because it is the only module that rewrites the plan. Two
properties matter and both are asserted directly: applying the same lesson twice changes
nothing, and tightening never loosens anything.
"""

from __future__ import annotations

import unittest

from lab.economics import adaptation, fingerprint, resilience, tiers
from lab.economics.model import Asset, Control, Plan, Threat

SMALL = Asset("test asset", 10_000.0, tier=1)


def simple_plan(value=10_000.0, tier=1, controls=()):
    return Plan(asset=Asset("test asset", value, tier=tier), controls=list(controls))


THREAT = Threat("theft", setup_cost=100, monthly_maintenance=10, likelihood=0.5, impact_fraction=0.4)


class ModelTests(unittest.TestCase):
    def test_expected_loss_is_probability_times_impact_times_value(self):
        plan = simple_plan(10_000.0, controls=())
        self.assertAlmostEqual(plan.expected_loss([THREAT]), 0.5 * 0.4 * 10_000)

    def test_controls_multiply(self):
        plan = simple_plan(
            10_000.0,
            controls=[
                Control("a", 10, ("theft",), reduction=0.5),
                Control("b", 10, ("theft",), reduction=0.5),
            ],
        )
        # base likelihood 0.5, halved twice
        self.assertAlmostEqual(plan.success_probability(THREAT), 0.5 * 0.25)
        self.assertAlmostEqual(plan.expected_loss([THREAT]), 0.5 * 0.25 * 0.4 * 10_000)

    def test_control_rejects_impossible_values(self):
        with self.assertRaises(ValueError):
            Control("bad", 10, ("theft",), reduction=1.5)
        with self.assertRaises(ValueError):
            Control("subsidy", 10, ("theft",), setup_effect=0.5)
        with self.assertRaises(ValueError):
            Control("subsidy", 10, ("theft",), maintenance_effect=0.9)

    def test_attacker_loot_is_capped_by_what_they_can_realise(self):
        cheap = Threat("scan", 10, 0, 1.0, 0.5, loot_cap=200)
        self.assertEqual(cheap.loot(1_000_000), 200)
        self.assertEqual(THREAT.loot(10_000), 0.4 * 10_000)

    def test_attacker_return_uses_their_costs_not_mine(self):
        plan = simple_plan(10_000.0, controls=[Control("hard", 100, ("theft",), setup_effect=2.0, maintenance_effect=3.0)])
        self.assertAlmostEqual(plan.attacker_setup(THREAT), 200)
        self.assertAlmostEqual(plan.attacker_maintenance(THREAT), 30)
        loot = 0.5 * 4_000
        self.assertAlmostEqual(plan.attacker_return(THREAT, months=12), loot - 200 - 30 * 12)

    def test_breakeven_is_none_when_setup_exceeds_loot(self):
        plan = simple_plan(1_000.0, controls=[Control("expensive", 10, ("theft",), setup_effect=100.0)])
        self.assertIsNone(plan.breakeven_months(THREAT))

    def test_breakeven_is_numeric_when_profitable(self):
        plan = simple_plan(10_000.0, controls=[])
        self.assertAlmostEqual(plan.breakeven_months(THREAT), (2_000 - 100) / 10)

    def test_roi_and_benefit(self):
        control = Control("worth it", 100, ("theft",), reduction=0.5)
        plan = simple_plan(10_000.0, controls=[control])
        self.assertAlmostEqual(plan.benefit(control, [THREAT]), 1_000.0)
        self.assertAlmostEqual(plan.roi(control, [THREAT]), 10.0)

    def test_missing_required_control(self):
        plan = simple_plan()
        codes = {verdict.code for verdict in plan.evaluate([THREAT], required=["digest_ledger"])}
        self.assertIn("control_missing", codes)

    def test_control_exceeding_asset_value(self):
        plan = simple_plan(1_000.0, controls=[Control("overkill", 5_000, ("theft",), reduction=0.9)])
        codes = {verdict.code for verdict in plan.evaluate([THREAT])}
        self.assertIn("control_exceeds_asset", codes)

    def test_overinvestment_when_benefit_below_cost(self):
        plan = simple_plan(1_000.0, controls=[Control("thin", 500, ("theft",), reduction=0.01)])
        codes = {verdict.code for verdict in plan.evaluate([THREAT])}
        self.assertIn("control_overinvestment", codes)

    def test_spend_ceiling(self):
        plan = simple_plan(1_000.0, controls=[Control("big", 400, ("theft",), reduction=0.5)])
        plan.ceiling_ratio = 0.2
        codes = {verdict.code for verdict in plan.evaluate([THREAT])}
        self.assertIn("spend_ceiling_exceeded", codes)

    def test_redundancy_is_reported_at_three_controls(self):
        plan = simple_plan(
            10_000.0,
            controls=[
                Control("a", 10, ("theft",), reduction=0.4),
                Control("b", 10, ("theft",), reduction=0.4),
                Control("c", 10, ("theft",), reduction=0.4),
            ],
        )
        codes = {verdict.code for verdict in plan.evaluate([THREAT])}
        self.assertIn("control_redundancy", codes)

    def test_summary_shape(self):
        plan = tiers.plan_for(Asset("audit", 250_000.0, tier=2))
        summary = plan.summary(tiers.DEFAULT_THREATS)
        self.assertEqual(set(summary), {"asset", "annual_control_cost", "spend_ratio", "expected_loss", "residual_by_threat", "controls", "attacker"})
        self.assertEqual(set(summary["attacker"]), {threat.name for threat in tiers.DEFAULT_THREATS})


class TierTests(unittest.TestCase):
    def test_tier_boundaries(self):
        self.assertEqual(tiers.tier_for(4_999).tier, 0)
        self.assertEqual(tiers.tier_for(5_000).tier, 1)
        self.assertEqual(tiers.tier_for(49_999).tier, 1)
        self.assertEqual(tiers.tier_for(50_000).tier, 2)
        self.assertEqual(tiers.tier_for(500_000).tier, 3)
        self.assertEqual(tiers.tier_for(5_000_000).tier, 4)
        self.assertEqual(tiers.tier_for(10**9).tier, 4)

    def test_unknown_tier_raises(self):
        with self.assertRaises(ValueError):
            tiers.spec(9)

    def test_requirements_only_grow(self):
        for previous, current in zip(tiers.TIERS, tiers.TIERS[1:]):
            self.assertTrue(set(previous.required) <= set(current.required), f"tier {current.tier} dropped a requirement")

    def test_ceilings_only_tighten(self):
        ratios = [spec.spend_ceiling for spec in tiers.TIERS]
        self.assertEqual(ratios, sorted(ratios, reverse=True))

    def test_fingerprint_depth_is_monotone(self):
        depths = [spec.fingerprint_depth for spec in tiers.TIERS]
        self.assertEqual(depths, sorted(depths))

    def test_plan_for_meets_the_floor_exactly(self):
        asset = Asset("audit", 250_000.0, tier=2)
        plan = tiers.plan_for(asset)
        self.assertEqual({control.name for control in plan.controls}, set(tiers.required(2)))

    def test_plan_for_accepts_extras_and_rejects_unknown(self):
        asset = Asset("audit", 250_000.0, tier=2)
        plan = tiers.plan_for(asset, extra=["source_seal"])
        self.assertIn("source_seal", {control.name for control in plan.controls})
        with self.assertRaises(KeyError):
            tiers.plan_for(asset, extra=["unicorn"])

    def test_promotion_is_justified_by_attacker_profit(self):
        plan = tiers.plan_for(Asset("audit", 250_000.0, tier=2))
        hint = tiers.promotion_hint(plan)
        self.assertIsNotNone(hint)
        self.assertEqual(hint["to_tier"], 3)
        self.assertIn("key_compromise", hint["why"])
        self.assertIn("key_custody_separation", hint["controls_to_add"])
        self.assertGreater(hint["new_spend_ratio"], plan.spend_ratio)

    def test_no_promotion_from_the_top(self):
        plan = tiers.plan_for(Asset("audit", 10_000_000.0, tier=4))
        self.assertIsNone(tiers.promotion_hint(plan))

    def test_controls_cover_known_threats_only(self):
        known = {threat.name for threat in tiers.DEFAULT_THREATS}
        for control in tiers.CONTROLS.values():
            self.assertTrue(set(control.covers) <= known, f"{control.name} covers an unknown threat")

    def test_every_control_is_reachable_from_some_tier(self):
        reachable = {name for spec in tiers.TIERS for name in spec.required}
        self.assertTrue(set(tiers.CONTROLS) <= reachable)


class FingerprintTests(unittest.TestCase):
    def incidents(self, count=3):
        return [
            fingerprint.Incident(
                codes=("ciphertext_tampered",) if index == 0 else ("plaintext_tampered", "record_removed"),
                when=1_760_000_000.0 + index * 3_600,
                boundary="wire" if index == 0 else "sink",
                evaded=("decoy_sweep_uniform",) if index else (),
            )
            for index in range(count)
        ]

    def test_depth_follows_the_tier(self):
        for spec in tiers.TIERS:
            self.assertEqual(fingerprint.depth_for(spec.tier), spec.fingerprint_depth)

    def test_depth_one_collects_technique_only(self):
        profile = fingerprint.build_profile(self.incidents(), 1)
        self.assertTrue(profile.techniques)
        self.assertIsNone(profile.precision)
        self.assertIsNone(profile.cadence_hours)

    def test_depth_two_adds_boundaries_and_evasion(self):
        profile = fingerprint.build_profile(self.incidents(), 2)
        self.assertEqual(profile.boundaries, ["sink", "wire"])
        self.assertIn("decoy_sweep_uniform", profile.evaded)

    def test_cadence_needs_three_incidents(self):
        short = fingerprint.build_profile(self.incidents(2), 3)
        self.assertIsNone(short.cadence_hours)
        self.assertTrue(short.refused)
        full = fingerprint.build_profile(self.incidents(3), 3)
        self.assertEqual(len(full.cadence_hours), 2)
        self.assertEqual(full.confidence, "medium")

    def test_precision_labels(self):
        careless = fingerprint.build_profile([fingerprint.Incident(("x",), 0.0)], 3)
        self.assertEqual(careless.precision, "careless")
        tailored = fingerprint.build_profile(
            [fingerprint.Incident(("x",), 0.0, evaded=fingerprint.EVADABLE_CHECKS)], 3
        )
        self.assertEqual(tailored.precision, "tailored")

    def test_linkage_refused_without_enough_signal(self):
        profile = fingerprint.build_profile([fingerprint.Incident(("ciphertext_tampered",), 0.0)], 4)
        self.assertIsNone(profile.linkage)
        self.assertTrue(profile.refused)

    def test_profile_has_no_identity_field(self):
        profile = fingerprint.build_profile(self.incidents(), 4)
        body = profile.as_dict()
        for forbidden in ("identity", "person", "name", "attribution"):
            self.assertNotIn(forbidden, body)
        self.assertIn("confidence", body)

    def test_depth_gap_costs_more_the_further_it_must_go(self):
        near = fingerprint.depth_gap(3, 2)
        far = fingerprint.depth_gap(4, 1)
        self.assertLess(near["annual_cost"], far["annual_cost"])
        self.assertIsNone(fingerprint.depth_gap(2, 2))


class ResilienceTests(unittest.TestCase):
    def test_top_tier_covers_every_failure_class(self):
        plan = tiers.plan_for(Asset("audit", 10_000_000.0, tier=4))
        covered = resilience.coverage(plan)
        missing = [failure for failure, state in covered.items() if not state["covered"]]
        self.assertEqual(missing, [], f"tier 4 leaves {missing} uncovered")

    def test_low_tier_leaves_gaps(self):
        plan = tiers.plan_for(Asset("notes", 1_000.0, tier=0))
        self.assertTrue(resilience.gaps(plan))

    def test_rehearsal_is_flagged_below_the_top(self):
        self.assertIsNotNone(resilience.drill_gap(tiers.plan_for(Asset("audit", 250_000.0, tier=2))))
        self.assertIsNone(resilience.drill_gap(tiers.plan_for(Asset("audit", 10_000_000.0, tier=4))))

    def test_recovery_plan_preserves_evidence_first(self):
        plan = tiers.plan_for(Asset("audit", 10_000_000.0, tier=4))
        steps = resilience.recovery_plan(plan, "substituted_record")
        self.assertIn("preserve the current state", steps[0])
        self.assertTrue(any("digest_chain" in step or "source_seal_records" in step for step in steps))

    def test_recovery_plan_admits_nothing_is_covered(self):
        steps = resilience.recovery_plan(tiers.plan_for(Asset("notes", 1_000.0, tier=0)), "host_rebuilt")
        self.assertTrue(any("rebuild" in step for step in steps))

    def test_archive_checks_preserve_evidence(self):
        plan = tiers.plan_for(Asset("audit", 250_000.0, tier=2))
        self.assertTrue(resilience.coverage(plan)["substituted_record"]["evidence_kept"])


class AdaptationTests(unittest.TestCase):
    def setUp(self):
        self.plan = tiers.plan_for(Asset("audit", 250_000.0, tier=2))
        self.threats = tiers.DEFAULT_THREATS

    def test_add_lesson_adds_and_costs(self):
        after, log = adaptation.run(self.plan, ["key_compromise"], adaptation.Log())
        self.assertIn("key_custody_separation", {control.name for control in after.controls})
        self.assertGreater(after.annual_control_cost, self.plan.annual_control_cost)
        self.assertEqual(log.applied, {"key_compromise"})

    def test_second_pass_changes_nothing(self):
        once, _ = adaptation.run(self.plan, ["key_compromise", "attacker_profitable"], adaptation.Log())
        twice, _ = adaptation.run(once, ["key_compromise", "attacker_profitable"], adaptation.Log())
        self.assertEqual(once.annual_control_cost, twice.annual_control_cost)
        self.assertEqual(
            {control.name for control in once.controls}, {control.name for control in twice.controls}
        )

    def test_strengthening_only_raises(self):
        plan = tiers.plan_for(Asset("audit", 250_000.0, tier=2))
        before = {control.name: control.reduction for control in plan.controls}
        after, _ = adaptation.run(plan, ["ciphertext_tampered"], adaptation.Log())
        for control in after.controls:
            self.assertGreaterEqual(control.reduction, before[control.name])

    def test_strengthening_is_capped(self):
        plan = tiers.plan_for(Asset("audit", 250_000.0, tier=2))
        log = adaptation.Log()
        lesson = adaptation.LESSONS["ciphertext_tampered"]
        for _ in range(20):
            plan = adaptation.apply_lesson(plan, lesson, adaptation.Log())
        envelope = next(control for control in plan.controls if control.name == "aes_gcm_envelope")
        self.assertLessEqual(envelope.reduction, 0.95)

    def test_promotion_adds_the_next_tier(self):
        after, log = adaptation.run(self.plan, ["attacker_profitable"], adaptation.Log())
        self.assertTrue(set(tiers.required(3)) <= {control.name for control in after.controls})
        self.assertEqual(log.entries[0]["tier"], (2, 3))

    def test_promotion_from_the_top_is_a_no_op(self):
        top = tiers.plan_for(Asset("audit", 10_000_000.0, tier=4))
        after, log = adaptation.run(top, ["attacker_profitable"], adaptation.Log())
        self.assertEqual(after.annual_control_cost, top.annual_control_cost)

    def test_trim_removes_unprofitable_extras_but_never_obligations(self):
        inflated = tiers.plan_for(Asset("audit", 250_000.0, tier=2), extra=["boot_attestation"])
        trimmed, log = adaptation.trim(inflated, self.threats, adaptation.Log())
        names = {control.name for control in trimmed.controls}
        self.assertNotIn("boot_attestation", names)
        self.assertTrue(set(tiers.required(2)) <= names)
        self.assertEqual(log.entries[-1]["removed"], ["boot_attestation"])

    def test_unknown_code_teaches_nothing_and_says_so(self):
        after, log = adaptation.run(self.plan, ["something_unmodelled"], adaptation.Log())
        self.assertEqual(after.annual_control_cost, self.plan.annual_control_cost)
        self.assertIn("no lesson", log.entries[-1]["skipped"])

    def test_debt_lists_findings_with_no_change(self):
        log = adaptation.Log()
        log.record("key_compromise", {"action": "add"})
        self.assertEqual(log.debt(["key_compromise", "boot_rollback"]), ["boot_rollback"])

    def test_effect_is_measured_not_asserted(self):
        after, _ = adaptation.run(self.plan, ["boot_measurement_mismatch"], adaptation.Log())
        measured = adaptation.effect(self.plan, after, self.threats)
        self.assertLess(measured["expected_loss"][1], measured["expected_loss"][0])
        self.assertGreater(measured["annual_cost"][1], measured["annual_cost"][0])
        self.assertIsInstance(measured["still_profitable"], list)

    def test_adaptation_keeps_the_tier_floor(self):
        after, _ = adaptation.run(self.plan, ["envelope_missing", "record_replayed"], adaptation.Log())
        self.assertTrue(set(tiers.required(2)) <= {control.name for control in after.controls})


class ProportionalityTests(unittest.TestCase):
    def test_cheap_asset_cannot_justify_expensive_controls(self):
        plan = tiers.plan_for(Asset("hobby notes", 1_000.0, tier=0), extra=["boot_attestation"])
        codes = {verdict.code for verdict in plan.evaluate(tiers.DEFAULT_THREATS)}
        self.assertIn("control_exceeds_asset", codes)

    def test_expensive_asset_is_helped_by_the_same_controls(self):
        cheap = tiers.plan_for(Asset("notes", 1_000.0, tier=0), extra=["boot_attestation"])
        rich = tiers.plan_for(Asset("audit", 10_000_000.0, tier=4))
        self.assertIn("control_exceeds_asset", {verdict.code for verdict in cheap.evaluate(tiers.DEFAULT_THREATS)})
        self.assertNotIn("control_exceeds_asset", {verdict.code for verdict in rich.evaluate(tiers.DEFAULT_THREATS)})

    def test_maintenance_effects_move_attacker_return_more_than_setup_effects(self):
        """The claim the doc makes, tested rather than assumed."""
        base = Threat("theft", setup_cost=1_000, monthly_maintenance=100, likelihood=0.5, impact_fraction=0.2)
        asset_value = 100_000.0
        setup_only = simple_plan(asset_value, controls=[Control("harder", 10, ("theft",), setup_effect=3.0)])
        upkeep_only = simple_plan(asset_value, controls=[Control("costlier", 10, ("theft",), maintenance_effect=3.0)])
        self.assertLess(upkeep_only.attacker_return(base), setup_only.attacker_return(base))


if __name__ == "__main__":
    unittest.main()
