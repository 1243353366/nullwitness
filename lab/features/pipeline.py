"""Feature engineering.

Per-client aggregates over a window. Two rules keep this honest:

- Every feature is an aggregate. Nothing here reconstructs an individual address,
  and no feature is designed to re-identify a person across networks. The pipeline
  answers "does this traffic look scripted", not "who is this".
- Every statistic is robust or explicitly labelled fragile. The source document used
  `std/mean` for inter-arrival jitter; that ratio explodes when the mean approaches
  zero, which is exactly what happens with tightly packed handshake packets. The
  `robust_cv` feature here uses median absolute deviation instead, so a burst of
  sub-millisecond gaps cannot manufacture a huge value.
"""

from __future__ import annotations

import collections
import math
from dataclasses import dataclass
from typing import Dict, List, Sequence, Tuple

from lab.features.contract import EventRecord, quantile

FEATURE_NAMES: Tuple[str, ...] = (
    "log_events",
    "median_gap_log",
    "robust_cv",
    "p90_gap_log",
    "gap_dispersion",
    "clockwork_share",
    "hour_entropy",
    "ua_diversity",
    "fp_stability",
    "h2_share",
    "datacenter_share",
    "bytes_cv",
    "latency_cv",
    "channel_diversity",
    "burstiness",
)

MAD_SCALE = 1.4826  # makes MAD comparable to a standard deviation for normal data


@dataclass
class ClientFeatures:
    client_key: str
    first_seen: float
    last_seen: float
    events: int
    values: Dict[str, float]

    def vector(self, names: Sequence[str] = FEATURE_NAMES) -> List[float]:
        return [self.values[n] for n in names]


def _safe_div(num: float, den: float, default: float = 0.0) -> float:
    if den == 0 or not math.isfinite(den):
        return default
    out = num / den
    return out if math.isfinite(out) else default


def _entropy(counts: Sequence[int]) -> float:
    """Shannon entropy in bits."""
    total = sum(counts)
    if total <= 0:
        return 0.0
    acc = 0.0
    for c in counts:
        if c <= 0:
            continue
        p = c / total
        acc -= p * math.log2(p)
    return acc


def _normalized_entropy(counts: Sequence[int]) -> float:
    """Entropy divided by log2(distinct), so 0..1 regardless of vocabulary size."""
    distinct = sum(1 for c in counts if c > 0)
    if distinct <= 1:
        return 0.0
    return _entropy(counts) / math.log2(distinct)


def _coefficient_of_variation(values: Sequence[float]) -> float:
    if len(values) < 2:
        return 0.0
    mean = sum(values) / len(values)
    if mean == 0:
        return 0.0
    var = sum((v - mean) ** 2 for v in values) / (len(values) - 1)
    return _safe_div(math.sqrt(var), abs(mean))


def _robust_cv(gaps: Sequence[float]) -> float:
    """MAD-based dispersion of inter-arrival gaps.

    Returns 0 when there are too few gaps or the median is zero.
    """
    if len(gaps) < 3:
        return 0.0
    median = quantile(list(gaps), 0.5)
    if median is None or median <= 0:
        return 0.0
    deviations = [abs(g - median) for g in gaps]
    mad = quantile(deviations, 0.5) or 0.0
    return MAD_SCALE * mad / median


def _clockwork_share(gaps: Sequence[float]) -> float:
    """Share of gaps within +/-10% of the median gap.

    Automation that polls on a fixed interval scores near 1.0. Humans, whose gaps
    are bimodal and heavy-tailed, score low even when they are habitual.
    """
    if len(gaps) < 3:
        return 0.0
    median = quantile(list(gaps), 0.5)
    if not median:
        return 0.0
    band = 0.10 * median
    inside = sum(1 for g in gaps if abs(g - median) <= band)
    return inside / len(gaps)


def _burstiness(timestamps: Sequence[float]) -> float:
    """Fano factor of per-minute event counts.

    1.0 is Poisson-like and unremarkable. Values well above 1 mean clustering
    (retries, page loads, a person reading); near 0 means metronomic arrivals,
    which is the automation signal.
    """
    if len(timestamps) < 3:
        return 0.0
    start = timestamps[0]
    buckets: collections.Counter = collections.Counter()
    for t in timestamps:
        buckets[int((t - start) // 60)] += 1
    counts = [buckets.get(b, 0) for b in range(max(buckets) + 1)]
    mean = sum(counts) / len(counts)
    if mean <= 0:
        return 0.0
    var = sum((c - mean) ** 2 for c in counts) / len(counts)
    return _safe_div(var, mean)


def extract_client_features(events: Sequence[EventRecord]) -> ClientFeatures:
    if not events:
        raise ValueError("no events for client")
    ordered = sorted(events, key=lambda e: e.observed_at)
    times = [e.observed_at for e in ordered]
    gaps = [b - a for a, b in zip(times, times[1:])]

    ua_counts = collections.Counter(e.ua_family for e in ordered)
    fp_counts = collections.Counter(e.fingerprint_hash for e in ordered)
    channel_counts = collections.Counter(e.channel for e in ordered)
    hour_counts = collections.Counter(int((t % 86400.0) // 3600) for t in times)
    byte_values = [float(e.bytes_in) for e in ordered]
    latency_values = [float(e.latency_ms) for e in ordered]

    values = {
        "log_events": math.log1p(len(ordered)),
        "median_gap_log": math.log1p(quantile(gaps, 0.5) or 0.0),
        "robust_cv": _robust_cv(gaps),
        "p90_gap_log": math.log1p(quantile(gaps, 0.9) or 0.0),
        "gap_dispersion": math.log1p((quantile(gaps, 0.9) or 0.0) - (quantile(gaps, 0.1) or 0.0)),
        "clockwork_share": _clockwork_share(gaps),
        "hour_entropy": _normalized_entropy(list(hour_counts.values())),
        "ua_diversity": min(1.0, len(ua_counts) / len(ordered)),
        "fp_stability": max(fp_counts.values()) / len(ordered),
        "h2_share": sum(1 for e in ordered if e.protocol == "h2") / len(ordered),
        "datacenter_share": sum(1 for e in ordered if e.network_class == "datacenter") / len(ordered),
        "bytes_cv": _coefficient_of_variation(byte_values),
        "latency_cv": _coefficient_of_variation(latency_values),
        "channel_diversity": min(1.0, len(channel_counts) / 4.0),
        "burstiness": math.log1p(_burstiness(times)),
    }
    return ClientFeatures(
        client_key=ordered[0].client_key,
        first_seen=times[0],
        last_seen=times[-1],
        events=len(ordered),
        values=values,
    )


def group_by_client(events: Sequence[EventRecord]) -> Dict[str, List[EventRecord]]:
    grouped: Dict[str, List[EventRecord]] = collections.defaultdict(list)
    for event in events:
        grouped[event.client_key].append(event)
    return dict(grouped)


def build_feature_table(
    events: Sequence[EventRecord],
    window: Tuple[float, float] | None = None,
    min_events: int = 5,
) -> List[ClientFeatures]:
    """Feature rows for clients with at least `min_events` inside the window.

    `min_events` is the k-anonymity floor for this layer: a client with one or two
    events produces a row that describes a single request, not a behavior pattern.
    """
    if window:
        low, high = window
        events = [e for e in events if low <= e.observed_at < high]
    rows = []
    for client_events in group_by_client(events).values():
        if len(client_events) < min_events:
            continue
        rows.append(extract_client_features(client_events))
    rows.sort(key=lambda r: r.first_seen)
    return rows
