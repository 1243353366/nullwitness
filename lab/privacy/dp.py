"""Differential privacy helpers used by the aggregation and reporting layers.

Scope note: these are counting and reporting primitives, not a privacy proof for
the whole lab. A sensitivity analysis per query is the user's responsibility, and
`Budget` will refuse to keep spending once epsilon is exhausted rather than
silently degrading the guarantee.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Dict, Iterable, Optional

import numpy as np


class BudgetExhausted(RuntimeError):
    """Raised instead of returning an answer with a weaker guarantee than claimed."""


@dataclass
class Budget:
    """Simple epsilon accountant (sequential composition only)."""

    total_epsilon: float
    spent: float = 0.0
    log: list = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.total_epsilon <= 0:
            raise ValueError("total_epsilon must be positive")

    @property
    def remaining(self) -> float:
        return max(0.0, self.total_epsilon - self.spent)

    def spend(self, epsilon: float, label: str = "") -> None:
        if epsilon <= 0 or not math.isfinite(epsilon):
            raise ValueError("epsilon must be a positive finite number")
        if epsilon > self.remaining + 1e-12:
            raise BudgetExhausted(
                f"query {label!r} needs epsilon={epsilon}, remaining={self.remaining:.4f}"
            )
        self.spent += epsilon
        self.log.append({"label": label, "epsilon": epsilon, "remaining": self.remaining})


def laplace_mechanism(value: float, sensitivity: float, epsilon: float, rng: np.random.Generator) -> float:
    """Add Lap(sensitivity/epsilon) noise to a scalar query result."""
    if sensitivity < 0:
        raise ValueError("sensitivity must be non-negative")
    if epsilon <= 0:
        raise ValueError("epsilon must be positive")
    if sensitivity == 0:
        return float(value)
    scale = sensitivity / epsilon
    return float(value + rng.laplace(loc=0.0, scale=scale))


def noisy_count(count: int, epsilon: float, rng: np.random.Generator) -> int:
    """Counting query with L1 sensitivity 1. Rounded and clamped at zero."""
    noise = laplace_mechanism(0.0, 1.0, epsilon, rng)
    return max(0, int(round(count + noise)))


def noisy_mean(values: Iterable[float], lower: float, upper: float, epsilon: float, rng: np.random.Generator) -> Optional[float]:
    """Bounded-mean query. Sensitivity is (upper-lower)/n for the mean of n items."""
    vals = [min(upper, max(lower, float(v))) for v in values]
    if not vals:
        return None
    sensitivity = (upper - lower) / len(vals)
    return laplace_mechanism(sum(vals) / len(vals), sensitivity, epsilon, rng)


def suppress_small_cells(counts: Dict[str, int], k: int = 5) -> Dict[str, int]:
    """Drop cells below k so no published cell describes a tiny group."""
    if k < 2:
        raise ValueError("k must be at least 2")
    return {key: value for key, value in counts.items() if value >= k}
