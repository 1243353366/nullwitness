"""End-to-end run over synthetic data.

    python3 -m lab.orchestrator.run_pipeline            # synthetic, default seed
    python3 -m lab.orchestrator.run_pipeline --jsonl events.jsonl

The run is deterministic for a given seed and writes `lab/reports/last_run.json`.
Nothing in this path touches the network or the filesystem outside the repo.
"""

from __future__ import annotations

import argparse
import json
import math
import pathlib
from typing import Dict, List, Sequence

import numpy as np

from lab.data import synthetic
from lab.features import contract, pipeline
from lab.model import belief, logistic, monitor, temporal_cv
from lab.privacy import dp

REPORT_PATH = pathlib.Path(__file__).resolve().parent.parent / "reports" / "last_run.json"


def load_jsonl(path: pathlib.Path) -> List[contract.EventRecord]:
    records = []
    for line_no, line in enumerate(path.read_text().splitlines(), start=1):
        if not line.strip():
            continue
        try:
            payload = json.loads(line)
            records.append(contract.EventRecord(**payload))
        except Exception as exc:  # noqa: BLE001 - re-raised with line context
            raise contract.ContractViolation(f"{path}:{line_no}: {exc}") from exc
    return contract.validate_all(records)


def _labels(rows: Sequence[pipeline.ClientFeatures], truth: Dict[str, str]) -> List[float]:
    return [1.0 if truth.get(r.client_key) == "scripted" else 0.0 for r in rows]


def run(
    records: Sequence[contract.EventRecord],
    truth: Dict[str, str],
    min_events: int = 5,
    folds: int = 4,
    input_kind: str = "synthetic",
    input_path: str | None = None,
) -> dict:
    names = pipeline.FEATURE_NAMES
    rows = pipeline.build_feature_table(records, min_events=min_events)
    if not rows:
        raise SystemExit("no client had enough events to build a feature row")
    labels = _labels(rows, truth)

    # A small dataset (documentation fixtures, a first week of real traffic) cannot
    # support ordered folds. Say so in the report instead of raising, because the rest
    # of the run is still useful.
    def _validate(growth: str) -> dict:
        try:
            return temporal_cv.run_validation(rows, labels, names, n_folds=folds, growth=growth)
        except ValueError as exc:
            return {"status": "skipped", "reason": str(exc), "growth": growth, "folds": [], "mean_auc": None}

    expanding = _validate("expanding")
    rolling = _validate("rolling")

    # Final model: earliest 70% trains, latest 30% is held out for the report.
    cut = max(1, int(len(rows) * 0.7))
    train_rows, test_rows = rows[:cut], rows[cut:]
    train_labels, test_labels = labels[:cut], labels[cut:]
    label_map = dict(zip([r.client_key for r in train_rows], train_labels))
    X_train = np.asarray([r.vector(names) for r in train_rows], dtype=float)
    y_train = np.asarray([label_map[r.client_key] for r in train_rows])
    model = logistic.fit(X_train, y_train, names)

    test_map = dict(zip([r.client_key for r in test_rows], test_labels))
    X_test = np.asarray([r.vector(names) for r in test_rows], dtype=float)
    y_test = np.asarray([test_map[r.client_key] for r in test_rows])
    test_scores = model.predict_proba(X_test)

    train_scores = model.predict_proba(X_train)
    # Two drift numbers, because they answer different questions:
    #   stability_psi: halves of the same training period, so a large value means
    #                  the tooling is noisy or the estimator is unstable.
    #   holdout_psi:   later period against the training period, so a large value is
    #                  either real drift or a shift in class mix. Worth a look, not
    #                  automatically a problem.
    midpoint = max(1, len(train_scores) // 2)
    holdout = {
        "n_train": len(train_rows),
        "n_test": len(test_rows),
        "auc": round(logistic.roc_auc(y_test, test_scores), 4) if 0 < y_test.sum() < len(y_test) else None,
        "stability_psi": round(monitor.psi(train_scores[:midpoint], train_scores[midpoint:]), 4),
        "holdout_psi": round(monitor.psi(train_scores, test_scores), 4),
    }

    shadow = monitor.shadow_divergence(train_rows, train_labels, test_rows, test_labels, names)

    # Controlled probe: corrupt a quarter of the training labels and see whether the
    # monitors move. A guard that cannot be provoked is decoration.
    rng_probe = np.random.default_rng(11)
    corrupt = np.asarray(train_labels, dtype=float).copy()
    flip_idx = rng_probe.choice(len(corrupt), size=max(1, len(corrupt) // 4), replace=False)
    corrupt[flip_idx] = 1.0 - corrupt[flip_idx]
    poisoned = monitor.shadow_divergence(train_rows, corrupt.tolist(), test_rows, test_labels, names)

    # Differential privacy over the published aggregate, not over the model.
    rng = np.random.default_rng(20261103)
    budget = dp.Budget(total_epsilon=1.0)
    flagged = {r.client_key: 1 for r, s in zip(test_rows, test_scores) if s >= 0.5}
    dq: Dict[str, object] = {}
    try:
        budget.spend(0.3, "flagged_count")
        dq["flagged_clients_noisy"] = dp.noisy_count(len(flagged), 0.3, rng)
        dq["mean_score_noisy"] = round(dp.noisy_mean(test_scores.tolist(), 0.0, 1.0, 0.2, rng), 4)
        budget.spend(0.2, "mean_score")
    except dp.BudgetExhausted as exc:  # pragma: no cover - budget is sized to fit
        dq["error"] = str(exc)
    dq["epsilon_spent"] = round(budget.spent, 2)
    dq["epsilon_remaining"] = round(budget.remaining, 2)
    hour_counts = {
        str(hour): sum(1 for e in records if int((e.observed_at % 86400) // 3600) == hour)
        for hour in range(24)
    }
    dq["suppressed_hour_cells"] = len(hour_counts) - len(dp.suppress_small_cells(hour_counts, k=250))

    # Reflexive update demo: evidence pushes hard toward "automated", with a high
    # inferred benefit to the source, so the update is deliberately attenuated.
    prior = [0.34, 0.33, 0.33]  # benign / automated / manipulating
    likelihoods = [0.05, 0.90, 0.05]
    reflexive = belief.reflexive_update(
        prior=prior,
        likelihoods=likelihoods,
        source_benefit=0.95,
        theta=0.7,
        beta=4.0,
    )
    z, is_outlier = monitor.volatility_z(0.98, [0.2, 0.25, 0.22, 0.3, 0.27, 0.24, 0.26])

    return {
        "input": {"kind": input_kind, "path": input_path},
        "data": synthetic.summarize(records),
        "features": {"rows": len(rows), "feature_count": len(names), "min_events": min_events},
        "temporal_validation": {"expanding": expanding, "rolling": rolling},
        "holdout": holdout,
        "top_coefficients": [
            {"feature": name, "weight": round(weight, 4)} for name, weight in model.coefficients()[:5]
        ],
        "shadow_model": shadow.summary(),
        "poisoning_probe": {
            "clean": shadow.summary(),
            "label_noise_25pct": poisoned.summary(),
            "reacted": poisoned.divergence > shadow.divergence * 1.5,
        },
        "differential_privacy": dq,
        "reflexive_update": {
            "prior": [round(x, 4) for x in prior],
            "naive": [round(float(x), 4) for x in reflexive.naive],
            "posterior": [round(float(x), 4) for x in reflexive.posterior],
            **reflexive.summary(),
        },
        "volatility_gate": {"z": round(z, 3), "outlier": is_outlier},
    }


def _print_summary(report: dict) -> None:
    data = report["data"]
    print(f"events={data['events']} clients={data['clients']} span_h={data['span_hours']}")
    print(f"feature rows={report['features']['rows']}")
    for growth in ("expanding", "rolling"):
        block = report["temporal_validation"][growth]
        if block.get("status") == "skipped":
            print(f"{growth:>9} temporal CV: skipped ({block['reason']})")
            continue
        aucs = [f["auc"] for f in block["folds"] if f["auc"] is not None]
        print(f"{growth:>9} temporal CV: mean_auc={block['mean_auc']} folds={aucs}")
    hold = report["holdout"]
    print(f"holdout auc={hold['auc']} stability_psi={hold['stability_psi']} holdout_psi={hold['holdout_psi']}")
    shadow = report["shadow_model"]
    print(f"shadow mean_divergence={shadow['mean_divergence']} flagged={shadow['flagged']}/{shadow['total']}")
    probe = report["poisoning_probe"]
    print(
        "poisoning probe: clean={0} noisy={1} reacted={2}".format(
            probe["clean"]["mean_divergence"], probe["label_noise_25pct"]["mean_divergence"], probe["reacted"]
        )
    )
    refl = report["reflexive_update"]
    print(
        f"reflexive: naive={refl['naive']} -> posterior={refl['posterior']} "
        f"iters={refl['iterations']} converged={refl['converged']}"
    )
    print("top features: " + ", ".join(f"{c['feature']}={c['weight']}" for c in report["top_coefficients"]))


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the experimental behavioral lab end to end.")
    parser.add_argument("--jsonl", type=pathlib.Path, help="load schema-compliant events instead of synthetic data")
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--min-events", type=int, default=5, help="events per client required to build a feature row")
    parser.add_argument("--folds", type=int, default=4, help="temporal validation folds")
    parser.add_argument("--write-report", action="store_true", help=f"write {REPORT_PATH}")
    args = parser.parse_args(argv)

    if args.jsonl:
        records = load_jsonl(args.jsonl)
        truth = {r.client_key: str(r.labels.get("population", "human")) for r in records}
        truth = {k: ("scripted" if v == "scripted" else "human") for k, v in truth.items()}
    else:
        records, truth = synthetic.generate(seed=args.seed)

    report = run(
        records,
        truth,
        min_events=args.min_events,
        folds=args.folds,
        input_kind="events" if args.jsonl else "synthetic",
        input_path=str(args.jsonl) if args.jsonl else None,
    )
    _print_summary(report)

    if args.write_report:
        REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
        REPORT_PATH.write_text(json.dumps(report, indent=2) + "\n")
        print(f"report written to {REPORT_PATH.relative_to(REPORT_PATH.parent.parent.parent)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
