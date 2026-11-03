"""A small, deterministic logistic regression.

No PyTorch here on purpose. The source document's modeling layer needs a GPU, an
ONNX export step, and a training harness to say anything; this needs numpy and 80
lines, which means it actually runs in CI and the numbers below mean something.

A calibrated gradient-boosted model is a reasonable upgrade later. The point of the
lab is the plumbing around the model (temporal validation, drift, suppression,
shadow divergence), which does not change when the estimator does.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional, Sequence, Tuple

import numpy as np


@dataclass
class Standardizer:
    mean: np.ndarray
    scale: np.ndarray

    @classmethod
    def fit(cls, X: np.ndarray) -> "Standardizer":
        mean = X.mean(axis=0)
        scale = X.std(axis=0)
        # A constant column carries no signal; set scale to 1 so it contributes 0.
        scale = np.where(scale < 1e-9, 1.0, scale)
        return cls(mean=mean, scale=scale)

    def transform(self, X: np.ndarray) -> np.ndarray:
        return (X - self.mean) / self.scale


@dataclass
class LogisticModel:
    weights: np.ndarray
    bias: float
    standardizer: Standardizer
    feature_names: Sequence[str]
    columns: Optional[List[int]] = None

    def _select(self, X: np.ndarray) -> np.ndarray:
        # The shadow model trains on a subset of columns, so it has to select the
        # same subset at inference time instead of assuming the full matrix.
        return X if self.columns is None else X[:, self.columns]

    def decision_function(self, X: np.ndarray) -> np.ndarray:
        return self.standardizer.transform(self._select(X)) @ self.weights + self.bias

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        z = np.clip(self.decision_function(X), -30.0, 30.0)
        return 1.0 / (1.0 + np.exp(-z))

    def coefficients(self) -> List[Tuple[str, float]]:
        pairs = zip(self.feature_names, self.weights.tolist())
        return sorted(pairs, key=lambda kv: abs(kv[1]), reverse=True)


def _sigmoid(z: np.ndarray) -> np.ndarray:
    return 1.0 / (1.0 + np.exp(-np.clip(z, -30.0, 30.0)))


def fit(
    X: np.ndarray,
    y: np.ndarray,
    feature_names: Sequence[str],
    l2: float = 1e-3,
    learning_rate: float = 0.15,
    epochs: int = 900,
    columns: Optional[Sequence[int]] = None,
) -> LogisticModel:
    """Full-batch gradient descent with L2.

    `columns` restricts training to a subset of features, which is how the shadow
    model in `monitor.py` is built from a different view of the same data.
    """
    if X.shape[0] == 0:
        raise ValueError("no training rows")
    if X.shape[0] != y.shape[0]:
        raise ValueError("X and y disagree on row count")
    if not set(np.unique(y)).issubset({0.0, 1.0}):
        raise ValueError("labels must be 0/1")

    selected = None if columns is None else list(columns)
    if selected is not None:
        X = X[:, selected]
        feature_names = [feature_names[i] for i in selected]

    standardizer = Standardizer.fit(X)
    Z = standardizer.transform(X)
    n, d = Z.shape
    w = np.zeros(d)
    b = 0.0

    for _ in range(epochs):
        p = _sigmoid(Z @ w + b)
        error = p - y
        grad_w = (Z.T @ error) / n + l2 * w
        grad_b = float(error.mean())
        w -= learning_rate * grad_w
        b -= learning_rate * grad_b

    return LogisticModel(
        weights=w,
        bias=b,
        standardizer=standardizer,
        feature_names=list(feature_names),
        columns=selected,
    )


def roc_auc(y: np.ndarray, scores: np.ndarray) -> float:
    """Rank-based AUC (Mann-Whitney U), ties averaged."""
    y = np.asarray(y)
    scores = np.asarray(scores)
    pos = scores[y == 1]
    neg = scores[y == 0]
    if len(pos) == 0 or len(neg) == 0:
        raise ValueError("AUC needs both classes present")
    order = np.argsort(scores, kind="mergesort")
    ranks = np.empty(len(scores), dtype=float)
    sorted_scores = scores[order]
    i = 0
    while i < len(sorted_scores):
        j = i
        while j + 1 < len(sorted_scores) and sorted_scores[j + 1] == sorted_scores[i]:
            j += 1
        average_rank = (i + j) / 2.0 + 1.0
        ranks[order[i : j + 1]] = average_rank
        i = j + 1
    rank_sum_pos = ranks[y == 1].sum()
    n_pos, n_neg = len(pos), len(neg)
    return float((rank_sum_pos - n_pos * (n_pos + 1) / 2.0) / (n_pos * n_neg))
