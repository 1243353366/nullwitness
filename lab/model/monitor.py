"""Monitoring: drift, volatility gating, and shadow divergence.

Three separate jobs, deliberately kept separate:

- `psi` answers "did the score distribution move", which is the drift check the
  source document asks for.
- `volatility_z` answers "is this single observation strange enough that I should
  not learn from it", the z-score filter from the document's weakness section.
- `shadow_divergence` answers "do two models that saw different feature views
  disagree", which is a cheap stand-in for adversarial-input detection. It is not
  a certified defense against poisoning, and the document's claim that it turns a
  "nerd project" into a hardened system is overstated: it raises the cost of a
  naive poisoning attempt and nothing more.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Sequence, Tuple

import numpy as np

from lab.features.pipeline import ClientFeatures
from lab.model import logistic

EPS = 1e-6


def psi(
    expected: Sequence[float],
    actual: Sequence[float],
    bins: int = 10,
    mode: str = "equal_width",
    smoothing: float = 1.0,
) -> float:
    """Population Stability Index between two score samples.

    Rough reading: < 0.1 stable, 0.1-0.25 worth watching, > 0.25 substantially
    shifted.

    The first version of this used quantile edges. That is the textbook recipe and
    it is wrong for classifier output: confident scores pile up at 0.0 and 1.0, the
    edges collapse onto duplicates, and any bin that happens to be empty in one
    sample produces a huge PSI. Equal-width bins over the observed range, with
    Laplace smoothing, do not have that failure mode.

    `mode="quantile"` is kept for continuous quantities (latencies, byte counts),
    where it is the right choice.
    """
    e = np.asarray(expected, dtype=float)
    a = np.asarray(actual, dtype=float)
    if e.size == 0 or a.size == 0:
        raise ValueError("psi needs both samples")
    if not (np.all(np.isfinite(e)) and np.all(np.isfinite(a))):
        raise ValueError("psi inputs must be finite")

    if mode == "quantile":
        edges = np.unique(np.quantile(e, np.linspace(0, 1, bins + 1)))
        if edges.size < 3:
            return 0.0
        edges[0], edges[-1] = -np.inf, np.inf
    elif mode == "equal_width":
        low = float(min(e.min(), a.min()))
        high = float(max(e.max(), a.max()))
        if high - low < 1e-12:
            return 0.0
        # A hair of padding keeps the extremes inside the outer bins.
        pad = (high - low) * 1e-6
        edges = np.linspace(low - pad, high + pad, bins + 1)
    else:
        raise ValueError(f"unknown psi mode: {mode!r}")

    e_counts = np.histogram(e, bins=edges)[0].astype(float)
    a_counts = np.histogram(a, bins=edges)[0].astype(float)
    e_pct = (e_counts + smoothing) / (e.size + smoothing * bins)
    a_pct = (a_counts + smoothing) / (a.size + smoothing * bins)
    return float(np.sum((a_pct - e_pct) * np.log(a_pct / e_pct)))


def volatility_z(value: float, history: Sequence[float], max_z: float = 3.0) -> Tuple[float, bool]:
    """Z-score of one observation against a baseline. Returns (z, is_outlier)."""
    hist = np.asarray(history, dtype=float)
    if hist.size < 5:
        return 0.0, False
    sd = float(hist.std(ddof=1))
    if sd < 1e-9:
        return 0.0, False
    z = (float(value) - float(hist.mean())) / sd
    return float(z), bool(abs(z) > max_z)


@dataclass
class ShadowReport:
    divergence: float
    flagged: int
    total: int
    threshold: float

    def summary(self) -> Dict[str, float]:
        return {
            "mean_divergence": round(self.divergence, 4),
            "flagged": self.flagged,
            "total": self.total,
            "threshold": self.threshold,
        }


def shadow_divergence(
    train_rows: Sequence[ClientFeatures],
    train_labels: Sequence[float],
    test_rows: Sequence[ClientFeatures],
    test_labels: Sequence[float],
    names: Sequence[str],
    threshold: float = 0.35,
) -> ShadowReport:
    """Train two models on disjoint feature views and compare their scores.

    Primary sees every feature; shadow sees alternating features only. Disjoint
    views are what makes this a real check: two models on identical inputs agree
    by construction.
    """
    label_map = dict(zip([r.client_key for r in train_rows], train_labels))
    test_label_map = dict(zip([r.client_key for r in test_rows], test_labels))

    X_train = np.asarray([r.vector(names) for r in train_rows], dtype=float)
    y_train = np.asarray([label_map[r.client_key] for r in train_rows])
    X_test = np.asarray([r.vector(names) for r in test_rows], dtype=float)
    y_test = np.asarray([test_label_map[r.client_key] for r in test_rows])

    primary = logistic.fit(X_train, y_train, names)
    even = list(range(0, len(names), 2))
    shadow = logistic.fit(X_train, y_train, names, columns=even)

    p_primary = primary.predict_proba(X_test)
    p_shadow = shadow.predict_proba(X_test)
    deltas = np.abs(p_primary - p_shadow)
    flagged = int((deltas > threshold).sum())
    return ShadowReport(
        divergence=float(deltas.mean()),
        flagged=flagged,
        total=int(deltas.size),
        threshold=threshold,
    )
