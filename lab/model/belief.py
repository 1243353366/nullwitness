"""Reflexive belief update.

The source document proposes a "reflexive adjustment" after Lefebvre: if the
apparent benefit of an information input to its source exceeds a threshold, move
the belief state away from the direction the input pushes, then renormalize.

The original snippet is three lines and six bugs:

    anti = 1.0 - impact_vector          # impact > 1 yields negative "probabilities"
    anti /= anti.sum()                  # sum can be zero, or negative
    adj = 0.4 * posterior + 0.6 * anti  # arbitrary weights, no fixed point
    return adj / adj.sum()              # no floor, no NaN guard, no convergence test

What this module does instead:

- Works with the *displacement* the evidence produced (`naive - prior`) rather than
  a second pseudo-distribution, so the attenuated update is a convex combination
  that cannot leave the simplex.
- Attenuates with `1 - tanh(beta * (benefit - theta))`, which is bounded in [0, 1],
  smooth at the threshold, and never negative.
- Repeats to a fixed point and *checks* convergence, because a reflexive loop that
  oscillates is a bug, not a feature.

This is a model of an analyst's caution, not a claim about how a real adversary
thinks. Lefebvre's framework is not an empirically validated predictor, and nothing
here should be read as one.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Dict, List, Sequence

import numpy as np

SIMPLPEX_FLOOR = 1e-12


def normalize(p: Sequence[float], floor: float = SIMPLPEX_FLOOR) -> np.ndarray:
    """Project a vector onto the probability simplex with a floor.

    Negative entries are clamped, a floor is applied so no hypothesis reaches
    exactly zero (which would make log-likelihood updates explode later), and the
    result is renormalized. Total mass is 1.0 up to floating point.
    """
    arr = np.asarray(p, dtype=float)
    if arr.ndim != 1 or arr.size == 0:
        raise ValueError("belief state must be a non-empty vector")
    if not np.all(np.isfinite(arr)):
        raise ValueError("belief state contains non-finite values")
    arr = np.clip(arr, floor, None)
    total = arr.sum()
    if total <= 0:
        return np.full(arr.shape, 1.0 / arr.size)
    return arr / total


def bayes_update(prior: Sequence[float], likelihoods: Sequence[float]) -> np.ndarray:
    """Naive posterior from per-hypothesis likelihoods."""
    p = normalize(prior)
    lik = np.asarray(likelihoods, dtype=float)
    if lik.shape != p.shape:
        raise ValueError("likelihood vector must match the belief state")
    if not np.all(np.isfinite(lik)) or np.any(lik < 0):
        raise ValueError("likelihoods must be finite and non-negative")
    return normalize(p * lik)


@dataclass
class ReflexiveResult:
    posterior: np.ndarray
    naive: np.ndarray
    prior: np.ndarray
    attenuation: float
    iterations: int
    converged: bool
    l1_trace: List[float] = field(default_factory=list)

    def summary(self) -> Dict[str, float]:
        return {
            "attenuation": round(self.attenuation, 4),
            "iterations": self.iterations,
            "converged": self.converged,
            "naive_top": int(np.argmax(self.naive)),
            "posterior_top": int(np.argmax(self.posterior)),
            "l1_shift": round(float(np.abs(self.posterior - self.naive).sum()), 6),
        }


def reflexive_update(
    prior: Sequence[float],
    likelihoods: Sequence[float],
    source_benefit: float,
    theta: float = 0.7,
    beta: float = 4.0,
    tolerance: float = 1e-9,
    max_iters: int = 64,
) -> ReflexiveResult:
    """Bayes update, then discount it in proportion to inferred manipulation risk.

    `source_benefit` in [0, 1] is the analyst's estimate of how much the input's
    author gains if the belief moves where the input pushes. Above `theta`, the
    update is attenuated; at benefit = 1.0 the belief barely moves from the prior.
    """
    if not 0.0 <= theta <= 1.0:
        raise ValueError("theta must be in [0, 1]")
    if not math.isfinite(source_benefit):
        raise ValueError("source_benefit must be finite")
    benefit = min(1.0, max(0.0, float(source_benefit)))

    p_prior = normalize(prior)
    naive = bayes_update(p_prior, likelihoods)

    if benefit <= theta:
        return ReflexiveResult(
            posterior=naive,
            naive=naive,
            prior=p_prior,
            attenuation=1.0,
            iterations=0,
            converged=True,
            l1_trace=[],
        )

    # Bounded in [0, 1); strictly below 1 once benefit exceeds theta, which is what
    # makes the iteration below a contraction.
    attenuation = 1.0 - math.tanh(beta * (benefit - theta))
    attenuation = max(0.0, min(1.0, attenuation))

    current = p_prior.copy()
    trace: List[float] = []
    converged = False
    iterations = 0
    for iterations in range(1, max_iters + 1):
        displacement = naive - p_prior
        nxt = normalize(p_prior + attenuation * displacement)
        delta = float(np.abs(nxt - current).sum())
        trace.append(delta)
        current = nxt
        if delta < tolerance:
            converged = True
            break

    return ReflexiveResult(
        posterior=current,
        naive=naive,
        prior=p_prior,
        attenuation=attenuation,
        iterations=iterations,
        converged=converged,
        l1_trace=trace,
    )


def infer_source_benefit(push: Sequence[float], salience: float) -> float:
    """Heuristic estimate of how much the input's author gains from a belief shift.

    `push` is the signed displacement the input tried to produce (positive means
    "move probability toward this hypothesis"). `salience` is how loudly it was
    delivered, 0..1. Concentrated, loud pushes score high; diffuse evidence scores
    low. This is a design choice, not a measurement, and it is the weakest number
    in the lab.
    """
    arr = np.asarray(push, dtype=float)
    if arr.size == 0:
        raise ValueError("push vector is empty")
    mass = float(np.abs(arr).sum())
    if mass <= 0:
        return 0.0
    concentration = float(np.max(np.abs(arr))) / mass
    return float(min(1.0, max(0.0, concentration * min(1.0, max(0.0, salience)))))
