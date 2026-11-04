"""Event contract for the experimental lab.

Every layer of the pipeline reads and writes `EventRecord`. The contract is the
stable part; the layers are replaceable.

Design rules encoded here, not just documented:

1. No raw identifiers. Client addresses are never stored. The ingestion layer
   keeps a salted, truncated key (`client_key`) that is only useful for grouping
   within one salt epoch.
2. Coarse by default. `ua_family`, `protocol`, and `network_class` are small
   closed vocabularies so feature vectors stay stable and low-cardinality.
3. Time is explicit and UTC. `observed_at` is a float of seconds since epoch;
   nothing in the lab reads the wall clock implicitly.
"""

from __future__ import annotations

import dataclasses
import hashlib
import hmac
import math
import uuid
from typing import Any, Dict, Iterable, List, Optional

PROTOCOLS = ("http/1.1", "h2", "h3", "unknown")
UA_FAMILIES = (
    "curl",
    "python-requests",
    "go-http-client",
    "headless-chromium",
    "chrome",
    "firefox",
    "safari",
    "other",
    "unknown",
)
NETWORK_CLASSES = ("residential", "mobile", "datacenter", "unknown")
# `canary_probe` exists because the two are not the same observation. `canary_access` means
# a token this operator issued was fetched: the document leaked. `canary_probe` means
# something requested a well-formed token path that this key never issued: somebody is
# guessing the shape, or scraping for canaries to strip. Collapsing them made the first
# signal free to forge by anyone who could count to sixteen hex characters.
CHANNELS = ("feed_item", "canary_access", "canary_probe", "honeytoken_access", "site_visit")


class ContractViolation(ValueError):
    """Raised when a record does not satisfy the event contract."""


@dataclasses.dataclass(frozen=True)
class EventRecord:
    event_id: str
    observed_at: float
    source_id: str
    client_key: str
    channel: str
    protocol: str
    ua_family: str
    fingerprint_hash: str
    network_class: str
    bytes_in: int
    latency_ms: float
    labels: Dict[str, Any] = dataclasses.field(default_factory=dict)

    def validate(self) -> None:
        if not self.event_id:
            raise ContractViolation("event_id is empty")
        if not math.isfinite(self.observed_at) or self.observed_at <= 0:
            raise ContractViolation(f"observed_at is not a positive epoch: {self.observed_at!r}")
        if self.channel not in CHANNELS:
            raise ContractViolation(f"unknown channel: {self.channel!r}")
        if self.protocol not in PROTOCOLS:
            raise ContractViolation(f"unknown protocol: {self.protocol!r}")
        if self.ua_family not in UA_FAMILIES:
            raise ContractViolation(f"unknown ua_family: {self.ua_family!r}")
        if self.network_class not in NETWORK_CLASSES:
            raise ContractViolation(f"unknown network_class: {self.network_class!r}")
        if not self.client_key or len(self.client_key) < 8:
            raise ContractViolation("client_key must be a salted hash of at least 8 chars")
        if self.bytes_in < 0:
            raise ContractViolation("bytes_in must be non-negative")
        if not math.isfinite(self.latency_ms) or self.latency_ms < 0:
            raise ContractViolation("latency_ms must be finite and non-negative")
        if not isinstance(self.labels, dict):
            raise ContractViolation("labels must be a mapping")

    def to_row(self) -> Dict[str, Any]:
        self.validate()
        row = dataclasses.asdict(self)
        row["labels"] = dict(self.labels)
        return row


def derive_client_key(secret: bytes, salt_epoch: str, address: str) -> str:
    """Salted, truncated key for an address.

    Irreversible without the secret, stable only within one salt epoch. Rotation
    is a deliberate operation: rotate the epoch and yesterday's key no longer
    joins to today's.
    """
    if not secret:
        raise ContractViolation("refusing to derive keys without a secret")
    msg = f"{salt_epoch}|{address}".encode("utf-8")
    return hmac.new(secret, msg, hashlib.sha256).hexdigest()[:16]


def new_event(**kwargs: Any) -> EventRecord:
    kwargs.setdefault("event_id", str(uuid.uuid4()))
    record = EventRecord(**kwargs)
    record.validate()
    return record


def validate_all(records: Iterable[EventRecord]) -> List[EventRecord]:
    out = []
    for record in records:
        record.validate()
        out.append(record)
    return out


def quantile(values: List[float], q: float) -> Optional[float]:
    """Linear-interpolated quantile, stdlib only, no numpy dependency."""
    if not values:
        return None
    if not 0.0 <= q <= 1.0:
        raise ContractViolation("q must be between 0 and 1")
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    pos = q * (len(ordered) - 1)
    low = math.floor(pos)
    high = math.ceil(pos)
    if low == high:
        return ordered[int(pos)]
    frac = pos - low
    return ordered[low] * (1 - frac) + ordered[high] * frac
