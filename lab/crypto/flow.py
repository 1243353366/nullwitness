"""The whole chain in one pass: capture, seal, encrypt, ship, decrypt, verify.

This module exists to make the composition checkable, because each property is easy to hold
on its own and easy to lose when joined. A record's journey has five points where something
can go wrong, and the report says which point, not merely that something did:

    capture -> seal -> encrypt -> [ storage or transit ] -> decrypt -> verify -> consume
                ^                                                  ^
         endpoint integrity, source side                  endpoint integrity, sink side
                          payload + authenticated encryption covers the middle
        boot and firmware integrity covers the machine at either end, or nothing does

The useful part is that a failure is attributable. A ciphertext that does not authenticate
was changed between the endpoints. A ciphertext that authenticates while the seal fails was
changed *after* decryption at the sink (or the source sealed something the source denies,
which its own recorded head settles). And a record that passes both is a record the source
made, faithfully transported: if it is a lie, the lie was manufactured inside an endpoint,
before the seal, where only code and boot integrity can see it.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional, Sequence

from lab.crypto import envelope
from lab.crypto.envelope import ReplayGuard
from lab.crypto.keys import KeyRing
from lab.crypto.model import AUTHENTICATED, ENDPOINT, PAYLOAD, Issue, TrustReport

# Findings that are arithmetic consequences of an earlier failure rather than independent
# evidence. One record that fails to decrypt removes a link from the chain, and everything
# downstream then looks unlinked. Reporting that at full severity trains a reader to skim.
CASCADE_CODES = {"record_removed", "record_reordered", "seal_forged", "stream_head_mismatch", "record_unexpected"}
from lab.crypto.seal import SealedRecord, SourceSeal, verify_seal


def _aad(stream: str, seq: int) -> bytes:
    """Bind the ciphertext to its stream and position, so it cannot be moved."""
    return b"|".join([b"nullwitness-record", stream.encode("utf-8"), str(seq).encode("ascii")])


@dataclass
class Partition:
    """One sealed-and-encrypted record on the wire."""

    stream: str
    seq: int
    record_id: str
    blob: bytes


class Source:
    """The endpoint that captures and encrypts. Assumes it is not yet compromised."""

    def __init__(self, ring: KeyRing, stream: str):
        self.ring = ring
        self.stream = stream
        self.seal = SourceSeal(ring, stream)
        self.sealed: List[SealedRecord] = []

    def emit(self, record_id: str, body: bytes) -> Partition:
        sealed = self.seal.seal(record_id, body)
        self.sealed.append(sealed)
        blob = envelope.encrypt(self.ring, body, aad=_aad(self.stream, sealed.seq))
        return Partition(stream=self.stream, seq=sealed.seq, record_id=record_id, blob=blob)

    @property
    def head(self) -> str:
        return self.seal.head_hex()


class Sink:
    """The endpoint that decrypts and verifies. Assumes it is not yet compromised either."""

    def __init__(self, ring: KeyRing, stream: str):
        self.ring = ring
        self.stream = stream
        self.guard = ReplayGuard()

    def receive(self, partition: Partition) -> bytes:
        body = envelope.decrypt(self.ring, partition.blob, aad=_aad(partition.stream, partition.seq))
        self.guard.accept(partition.stream, partition.seq)
        return body


def audit_stream(
    ring: KeyRing,
    stream: str,
    partitions: Sequence[Partition],
    sealed: Sequence[SealedRecord],
    expected_head: Optional[str] = None,
    guard: Optional[ReplayGuard] = None,
) -> TrustReport:
    """Verify both boundaries over a shipped stream and attribute what fails to a location.

    `sealed` is the source's own view of the chain, which a real deployment reads from the
    integrity ledger rather than from the same directory as the ciphertext. Passing it
    explicitly keeps that dependency visible.
    """
    report = TrustReport()
    guard = guard or ReplayGuard()
    recovered: List[SealedRecord] = []
    ciphertext_failures = 0

    for partition in sorted(partitions, key=lambda p: p.seq):
        try:
            body = envelope.decrypt(ring, partition.blob, aad=_aad(partition.stream, partition.seq))
        except envelope.Tampered as failure:
            ciphertext_failures += 1
            report.add(
                Issue(
                    AUTHENTICATED,
                    "ciphertext_tampered",
                    "high",
                    f"record {partition.stream}/{partition.seq} does not authenticate: {failure}",
                )
            )
            continue
        try:
            guard.accept(partition.stream, partition.seq)
        except (envelope.Replay, envelope.OutOfOrder) as failure:
            report.add(Issue(AUTHENTICATED, "record_replayed", "high", f"record {partition.stream}/{partition.seq}: {failure}"))
            continue
        source_view = next((record for record in sealed if record.seq == partition.seq), None)
        if source_view is None:
            report.add(
                Issue(
                    ENDPOINT,
                    "record_unexpected",
                    "high",
                    f"record {partition.stream}/{partition.seq} decrypts but was never sealed at the source: "
                    "an envelope was minted by something other than the capture path",
                )
            )
            continue
        recovered.append(
            SealedRecord(
                seq=source_view.seq,
                record_id=source_view.record_id,
                body=body,
                digest=source_view.digest,
                mac=source_view.mac,
            )
        )

    endpoint_issues = verify_seal(ring, stream, recovered, expected_head)
    if ciphertext_failures:
        endpoint_issues = [
            Issue(
                issue.property,
                issue.code,
                "low",
                f"consequence of an unauthenticated record earlier in the stream, not separate evidence: {issue.detail}",
            )
            if issue.code in CASCADE_CODES
            else issue
            for issue in endpoint_issues
        ]
    report.extend(endpoint_issues)
    if not endpoint_issues and len(recovered) == len(partitions):
        report.ok(ENDPOINT)
    elif not endpoint_issues:
        report.skip(ENDPOINT, "records failed earlier in the chain, so the plaintext chain was not fully verified")

    if not ciphertext_failures:
        report.ok(AUTHENTICATED)

    # Payload encryption is only a claim about what a reader could see, and the strongest
    # statement available without a key is that the ciphertext does not contain the plaintext.
    if all(not _contains(p.blob, r.body) for p in partitions for r in sealed if len(r.body) >= 8):
        report.ok(PAYLOAD)
    else:
        report.add(
            Issue(
                PAYLOAD,
                "plaintext_visible",
                "high",
                "a record's cleartext appears inside its envelope: the payload was not encrypted, only wrapped",
            )
        )
    return report


def _contains(haystack: bytes, needle: bytes) -> bool:
    return needle in haystack


def combine(*reports: TrustReport) -> TrustReport:
    """Merge per-property reports into one, keeping the unchecked notes.

    A merged report that silently drops "not examined" is how a chain looks complete when it
    has a hole, so the notes travel with the findings.
    """
    merged = TrustReport()
    for report in reports:
        merged.extend(list(report.issues))
        for name in report.verified:
            merged.ok(name)
        merged.unchecked.extend(report.unchecked)
    return merged
