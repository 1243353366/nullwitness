"""Rolling-window temporal validation.

The failure this module exists to prevent is temporal leakage: shuffling network
events into random folds lets a model train on tomorrow and be tested on yesterday,
which inflates every metric and hides drift. Folds here are strictly ordered and
non-overlapping in time, and the test window always begins after the training
window ends.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Sequence, Tuple

import numpy as np

from lab.features.pipeline import ClientFeatures
from lab.model import logistic


@dataclass
class Fold:
    index: int
    train_times: Tuple[float, float]
    test_times: Tuple[float, float]
    train_rows: List[ClientFeatures]
    test_rows: List[ClientFeatures]

    @property
    def label(self) -> str:
        return f"fold {self.index}: train < {self.test_times[0]:.0f} | test [{self.test_times[0]:.0f}, {self.test_times[1]:.0f})"


def make_folds(rows: Sequence[ClientFeatures], n_folds: int = 4, growth: str = "expanding") -> List[Fold]:
    """Split by first-seen time into ordered train/test pairs.

    `growth="expanding"` keeps every earlier row in the training set, which is what
    a production retrain does. `growth="rolling"` uses only the most recent block,
    which is what you want when the phenomenon is non-stationary.
    """
    if n_folds < 2:
        raise ValueError("need at least 2 folds")
    ordered = sorted(rows, key=lambda r: r.first_seen)
    if len(ordered) < n_folds * 4:
        raise ValueError(f"{len(ordered)} rows is too few for {n_folds} folds")

    block = len(ordered) // (n_folds + 1)
    folds: List[Fold] = []
    for i in range(n_folds):
        test_start = block * (i + 1)
        test_end = min(len(ordered), test_start + block)
        if test_end <= test_start:
            continue
        train_rows = ordered[:test_start] if growth == "expanding" else ordered[test_start - block : test_start]
        test_rows = ordered[test_start:test_end]
        folds.append(
            Fold(
                index=i,
                train_times=(train_rows[0].first_seen, train_rows[-1].first_seen),
                test_times=(test_rows[0].first_seen, test_rows[-1].first_seen),
                train_rows=list(train_rows),
                test_rows=list(test_rows),
            )
        )
    if not folds:
        raise ValueError("no usable folds")
    return folds


def _matrix(rows: Sequence[ClientFeatures], names: Sequence[str]) -> np.ndarray:
    return np.asarray([r.vector(names) for r in rows], dtype=float)


def run_validation(
    rows: Sequence[ClientFeatures],
    labels: Sequence[float],
    names: Sequence[str],
    n_folds: int = 4,
    growth: str = "expanding",
) -> dict:
    """Fit and score per fold, and confirm no test timestamp precedes its training set."""
    label_map = dict(zip([r.client_key for r in rows], labels))
    folds = make_folds(rows, n_folds=n_folds, growth=growth)
    results = []
    for fold in folds:
        X_train = _matrix(fold.train_rows, names)
        y_train = np.asarray([label_map[r.client_key] for r in fold.train_rows])
        X_test = _matrix(fold.test_rows, names)
        y_test = np.asarray([label_map[r.client_key] for r in fold.test_rows])

        leakage = max(r.first_seen for r in fold.train_rows) >= min(r.first_seen for r in fold.test_rows)
        if leakage:
            raise AssertionError(f"temporal leakage in {fold.label}")

        model = logistic.fit(X_train, y_train, names)
        scores = model.predict_proba(X_test)
        entry = {
            "fold": fold.index,
            "label": fold.label,
            "n_train": len(fold.train_rows),
            "n_test": len(fold.test_rows),
            "positives_test": int(y_test.sum()),
        }
        try:
            entry["auc"] = round(logistic.roc_auc(y_test, scores), 4)
        except ValueError:
            entry["auc"] = None
        results.append(entry)

    aucs = [r["auc"] for r in results if r["auc"] is not None]
    return {
        "growth": growth,
        "folds": results,
        "mean_auc": round(float(np.mean(aucs)), 4) if aucs else None,
        "std_auc": round(float(np.std(aucs)), 4) if aucs else None,
        "leakage_check": "passed",
    }
