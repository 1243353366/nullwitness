"""Endpoint integrity: a source seal over the plaintext, verified at the sink.

Ciphertext authentication answers "was the envelope changed". It cannot answer "was the
content wrong before anyone encrypted it", because at that moment there is no ciphertext and
no observer. The only thing that can answer it is a record made at the source, before the
encryption, by something the attacker does not control.

So this module seals each record at the point of capture: a per-record MAC and a running
chain head. The seal is verified where the plaintext re-emerges, which pins the location of
a change:

| ciphertext authentic | seal authentic | where the change happened |
| --- | --- | --- |
| no | -- | in transit or at rest, between the two endpoints |
| yes | no | after decryption at the sink, or before sealing at the source |
| yes | yes | nowhere between the boundaries: any problem is inside an endpoint |

The third row is the one worth sitting with. A record can be perfectly sealed and perfectly
authenticated and still be a lie, because the endpoint that made the seal was already
compromised. No cryptographic layer fixes that; properties four and five decide whether the
sealing endpoint deserves belief, and if they are missing, this seal records an attacker's
work with impeccable integrity.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Sequence

from lab.crypto.keys import KeyRing
from lab.crypto.model import ENDPOINT, Issue

SEAL_PURPOSE = "seal"
GENESIS = b"\x00" * 32


@dataclass(frozen=True)
class SealedRecord:
    seq: int
    record_id: str
    body: bytes
    digest: str
    mac: str


def _record_mac(ring: KeyRing, stream: str, prev_head: bytes, seq: int, record_id: str, digest: str) -> str:
    key = ring.subkey(SEAL_PURPOSE, context=stream.encode("utf-8")).material
    message = b"|".join(
        [prev_head, stream.encode("utf-8"), str(seq).encode("ascii"), record_id.encode("utf-8"), digest.encode("ascii")]
    )
    return hmac.new(key, message, hashlib.sha256).hexdigest()


class SourceSeal:
    """Seals records as they are captured, chaining each to the one before it.

    The chain is what makes deletion visible. Without a predecessor link, dropping a record
    leaves a set of individually valid records and nothing to compare them to; the sequence
    number would have to be trusted on its own.
    """

    def __init__(self, ring: KeyRing, stream: str):
        self.ring = ring
        self.stream = stream
        self.head = GENESIS
        self.seq = 0

    def seal(self, record_id: str, body: bytes) -> SealedRecord:
        digest = hashlib.sha256(body).hexdigest()
        mac = _record_mac(self.ring, self.stream, self.head, self.seq, record_id, digest)
        self.head = bytes.fromhex(mac)
        record = SealedRecord(seq=self.seq, record_id=record_id, body=body, digest=digest, mac=mac)
        self.seq += 1
        return record

    def head_hex(self) -> str:
        return self.head.hex()


def seal_many(ring: KeyRing, stream: str, records: Iterable[tuple]) -> List[SealedRecord]:
    """Seal `(record_id, body)` pairs in order. Same thing the capture path does."""
    seal = SourceSeal(ring, stream)
    return [seal.seal(record_id, body) for record_id, body in records]


def verify_seal(
    ring: KeyRing,
    stream: str,
    records: Sequence[SealedRecord],
    expected_head: Optional[str] = None,
) -> List[Issue]:
    """Recompute the chain and say precisely what is wrong with it.

    `expected_head` is the head the source recorded, ideally somewhere the attacker does not
    control, such as the integrity ledger. Without it, a chain that was truncated at the end
    still verifies: every remaining record is genuine, and the last one is simply the last
    one. That is not a flaw in the chain, it is the difference between integrity and
    completeness.
    """
    issues: List[Issue] = []
    seen: Dict[str, int] = {}
    head = GENESIS
    expected_seq = 0
    remaining = {record.seq for record in records}

    for record in records:
        remaining.discard(record.seq)
        if record.seq != expected_seq:
            # A gap and a swap look identical at the point of the surprise. They differ in
            # whether the missing sequence shows up later, so ask the rest of the list.
            code = "record_reordered" if expected_seq in remaining else "record_removed"
            issues.append(
                Issue(
                    ENDPOINT,
                    code,
                    "high",
                    f"record {record.record_id} carries sequence {record.seq} where {expected_seq} was expected: "
                    "records were dropped or reordered at the plaintext layer, which no ciphertext check would show",
                )
            )
            expected_seq = record.seq
        if record.record_id in seen:
            issues.append(
                Issue(
                    ENDPOINT,
                    "record_replayed",
                    "medium",
                    f"record {record.record_id} appears twice (sequences {seen[record.record_id]} and {record.seq})",
                )
            )
        seen[record.record_id] = record.seq

        expected_digest = hashlib.sha256(record.body).hexdigest()
        if expected_digest != record.digest:
            issues.append(
                Issue(
                    ENDPOINT,
                    "plaintext_tampered",
                    "high",
                    f"record {record.record_id} does not hash to its sealed digest: the content changed after it "
                    "was sealed, which points at the sink after decryption or at the source before encryption",
                )
            )
            break  # the chain is unverifiable from here on; saying more would be noise

        expected_mac = _record_mac(ring, stream, head, record.seq, record.record_id, record.digest)
        if not hmac.compare_digest(expected_mac, record.mac):
            issues.append(
                Issue(
                    ENDPOINT,
                    "seal_forged",
                    "high",
                    f"record {record.record_id} carries a seal this key did not produce: the record was injected "
                    "after capture, or the sealing key is not the key that made this chain",
                )
            )
            break

        head = bytes.fromhex(record.mac)
        expected_seq = record.seq + 1

    if expected_head is not None and head.hex() != expected_head:
        issues.append(
            Issue(
                ENDPOINT,
                "stream_head_mismatch",
                "high",
                "the chain head at the sink does not match the head recorded at the source: records were "
                "appended or removed at the end of the stream, where every surviving record still verifies",
            )
        )

    return issues


def verify_seal_report(ring: KeyRing, stream: str, records: Sequence[SealedRecord], expected_head: Optional[str] = None):
    """The report-shaped version, for callers assembling a full trust report."""
    from lab.crypto.model import TrustReport

    report = TrustReport()
    issues = verify_seal(ring, stream, records, expected_head)
    report.extend(issues)
    if not issues:
        report.ok(ENDPOINT)
    return report
