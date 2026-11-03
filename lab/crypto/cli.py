"""Demo for the trust chain: five properties, one report, honest about the holes.

    python3 -m lab.crypto.cli demo
    python3 -m lab.crypto.cli demo --json

Each property gets one case that must hold and at least one that must be caught, plus a
control where a legitimate variation must not be reported. The last scenario is a limit: a
record falsified inside the endpoint before it was sealed passes every cryptographic check in
this package, because it was sealed by the key that is supposed to seal it.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import tempfile
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional

from lab.crypto import archive, boot, envelope, keys
from lab.crypto.flow import Partition, Source, audit_stream
from lab.crypto.keys import KeyRing
from lab.crypto.model import (
    AUTHENTICATED,
    BOOT,
    ENDPOINT,
    KEY_PROTECTION,
    PAYLOAD,
    PROPERTIES,
    PROPERTY_QUESTION,
    PROPERTY_TITLE,
    TrustReport,
)
from lab.crypto.seal import SealedRecord

MASTER = b"demo-master-secret-32-bytes-long!!"
STREAM = "asset-7/audit"


@dataclass
class Scenario:
    property: str
    name: str
    expectation: str
    run: Callable[[], TrustReport]


def _clean_stream(ring: KeyRing):
    source = Source(ring, STREAM)
    bodies = [(f"r{index}", f"2026-11-03T16:0{index}:00Z event={index} actor=service".encode()) for index in range(4)]
    partitions = [source.emit(record_id, body) for record_id, body in bodies]
    return source, partitions


def payload_hidden() -> TrustReport:
    ring = KeyRing(MASTER)
    source, partitions = _clean_stream(ring)
    report = audit_stream(ring, STREAM, partitions, source.sealed, expected_head=source.head)
    assert envelope.peek(partitions[0].blob).backend == "aes-256-gcm"
    return report


def null_cipher() -> TrustReport:
    """What a reader sees when someone "encrypts" by wrapping the plaintext in a header.

    An implementation that ships the body in the clear with a valid tag is not hypothetical;
    it is what a placeholder backend looks like on the day it reaches production.
    """
    ring = KeyRing(MASTER)
    source = Source(ring, STREAM)
    body = b"2026-11-03T16:00:00Z patient=alex diagnosis=none"
    sealed = source.seal.seal("r0", body)
    source.sealed.append(sealed)
    header = envelope.VERSION + envelope.BACKEND_STDLIB + b"\x01" * envelope.NONCE_LEN
    aad = b"|".join([b"nullwitness-record", STREAM.encode(), b"0"])
    tag = envelope._tag(ring, header, aad, body)
    blob = header + body + tag
    return audit_stream(ring, STREAM, [Partition(STREAM, 0, "r0", blob)], source.sealed)


def bit_flip() -> TrustReport:
    ring = KeyRing(MASTER)
    source, partitions = _clean_stream(ring)
    original = partitions[1].blob
    flipped = bytearray(original)
    flipped[len(flipped) // 2] ^= 0x01
    partitions[1] = Partition(STREAM, 1, "r1", bytes(flipped))
    return audit_stream(ring, STREAM, partitions, source.sealed, expected_head=source.head)


def moved_record() -> TrustReport:
    """A perfectly authentic record, relocated: the attack the AAD exists to stop."""
    ring = KeyRing(MASTER)
    source, partitions = _clean_stream(ring)
    stolen = partitions[0]
    partitions[0] = Partition(STREAM, 2, stolen.record_id, stolen.blob)
    return audit_stream(ring, STREAM, partitions, source.sealed, expected_head=source.head)


def custody_clean() -> TrustReport:
    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        data = root / "data"
        data.mkdir()
        key_file = keys.write_key_file(root / "keys" / "master.key", MASTER)
        os.utime(key_file, None)
        report = keys.audit_custody(key_file, MASTER, data_root=data)
    return report


def custody_loose() -> TrustReport:
    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        data = root / "data"
        data.mkdir()
        key_file = keys.write_key_file(data / "master.key", MASTER)
        os.chmod(key_file, 0o644)
        report = keys.audit_custody(key_file, MASTER, data_root=data)
    return report


def custody_environment() -> TrustReport:
    os.environ["NULLWITNESS_KEY"] = MASTER.decode()
    try:
        return keys.audit_custody(None, MASTER)
    finally:
        del os.environ["NULLWITNESS_KEY"]


def _archived():
    """Store a clean stream's envelopes with their digests, in a temporary directory."""
    holder = tempfile.TemporaryDirectory()
    root = pathlib.Path(holder.name)
    ring = KeyRing(MASTER)
    source, partitions = _clean_stream(ring)
    book = archive.Archive(root / "digests.jsonl", b"demo-ledger-key-material-32-bytes")
    for partition in partitions:
        book.store(partition, now=1_760_000_000.0)
    return holder, source, partitions, book


def archive_clean() -> TrustReport:
    holder, _, partitions, book = _archived()
    try:
        return book.verify(partitions)
    finally:
        holder.cleanup()


def archive_swap() -> TrustReport:
    """Same stream, same sequence, a valid envelope for different content.

    Nothing about the ciphertext is wrong: it authenticates, it is the right length, and it
    was made with the right key. The digest in the ledger is what knows it is not the record
    that was written.
    """
    holder, source, partitions, book = _archived()
    try:
        forged = Partition(STREAM, 1, "r1", source.emit("r99", b"2026-11-03T16:01:00Z actor=root").blob)
        return book.verify([partitions[0], forged, partitions[2], partitions[3]])
    finally:
        holder.cleanup()


def archive_gap() -> TrustReport:
    holder, _, partitions, book = _archived()
    try:
        return book.verify(partitions[:3])
    finally:
        holder.cleanup()


def boot_clean() -> TrustReport:
    ring = KeyRing(MASTER)
    digests = {"firmware": hashlib.sha256(b"fw-2.4.1").hexdigest(), "bootloader": hashlib.sha256(b"bl-9").hexdigest(), "kernel": hashlib.sha256(b"6.11.4").hexdigest()}
    attestation = boot.build_chain(ring, digests, nonce="challenge-1", security_version=7)
    return boot.verify_attestation(ring, attestation, boot.BootPolicy(expected=digests, min_security_version=5), "challenge-1")


def boot_swapped_kernel() -> TrustReport:
    ring = KeyRing(MASTER)
    approved = {"firmware": hashlib.sha256(b"fw-2.4.1").hexdigest(), "bootloader": hashlib.sha256(b"bl-9").hexdigest(), "kernel": hashlib.sha256(b"6.11.4").hexdigest()}
    measured = dict(approved)
    measured["kernel"] = hashlib.sha256(b"6.11.4-with-a-patch").hexdigest()
    attestation = boot.build_chain(ring, measured, nonce="challenge-1", security_version=7)
    return boot.verify_attestation(ring, attestation, boot.BootPolicy(expected=approved, min_security_version=5), "challenge-1")


def boot_downgrade() -> TrustReport:
    ring = KeyRing(MASTER)
    digests = {"firmware": hashlib.sha256(b"fw-2.4.0").hexdigest(), "bootloader": hashlib.sha256(b"bl-9").hexdigest(), "kernel": hashlib.sha256(b"6.11.4").hexdigest()}
    attestation = boot.build_chain(ring, digests, nonce="challenge-1", security_version=3)
    return boot.verify_attestation(ring, attestation, boot.BootPolicy(expected=digests, min_security_version=5), "challenge-1")


def sink_edit() -> TrustReport:
    """A rewritten record, re-encrypted by someone holding the payload key.

    The ciphertext authenticates, because it was made with a key that works. The seal is the
    only layer left that knows the content changed, which is the argument for keeping the seal
    and the payload key separate: a stolen transport key buys confidentiality loss, not
    history rewriting.
    """
    ring = KeyRing(MASTER)
    source, partitions = _clean_stream(ring)
    forged_body = b"2026-11-03T16:01:00Z event=1 actor=root"
    partitions[1] = Partition(
        STREAM, 1, "r1", envelope.encrypt(ring, forged_body, aad=b"|".join([b"nullwitness-record", STREAM.encode(), b"1"]))
    )
    return audit_stream(ring, STREAM, partitions, source.sealed, expected_head=source.head)


def dropped_record() -> TrustReport:
    ring = KeyRing(MASTER)
    source, partitions = _clean_stream(ring)
    return audit_stream(ring, STREAM, partitions[:-1], source.sealed[:-1], expected_head=source.head)


def sink_replay() -> TrustReport:
    ring = KeyRing(MASTER)
    source, partitions = _clean_stream(ring)
    doubled = partitions + [partitions[-1]]
    return audit_stream(ring, STREAM, doubled, source.sealed, expected_head=source.head)


def limit_before_seal() -> TrustReport:
    """The record was falsified inside the endpoint, then sealed faithfully.

    Nothing in this package can see it. The seal is made by the endpoint, so an endpoint that
    lies produces a chain of true statements about a false record. Only boot and firmware
    integrity, and the integrity monitor on the host itself, have anything to say here.
    """
    ring = KeyRing(MASTER)
    source = Source(ring, STREAM)
    partitions = [source.emit("r0", b"2026-11-03T16:00:00Z actor=service action=read")]
    return audit_stream(ring, STREAM, partitions, source.sealed, expected_head=source.head)


SCENARIOS: List[Scenario] = [
    Scenario(PAYLOAD, "envelope hides the payload", "verified", payload_hidden),
    Scenario(PAYLOAD, "wrapped, not encrypted", "plaintext_visible", null_cipher),
    Scenario(AUTHENTICATED, "one flipped bit", "ciphertext_tampered", bit_flip),
    Scenario(AUTHENTICATED, "authentic record relocated", "ciphertext_tampered", moved_record),
    Scenario(AUTHENTICATED, "envelopes hashed into the ledger", "verified", archive_clean),
    Scenario(AUTHENTICATED, "valid envelope swapped at rest", "envelope_substituted", archive_swap),
    Scenario(AUTHENTICATED, "envelope removed from the archive", "envelope_missing", archive_gap),
    Scenario(KEY_PROTECTION, "key 0600 outside the data tree", "verified", custody_clean),
    Scenario(KEY_PROTECTION, "key inside the tree, mode 0644", "two findings", custody_loose),
    Scenario(KEY_PROTECTION, "key in the environment", "key_in_environment", custody_environment),
    Scenario(BOOT, "measured chain matches policy", "verified", boot_clean),
    Scenario(BOOT, "kernel measured differently", "boot_measurement_mismatch", boot_swapped_kernel),
    Scenario(BOOT, "firmware rolled back", "boot_rollback", boot_downgrade),
    Scenario(ENDPOINT, "sink rewrites the plaintext", "plaintext_tampered", sink_edit),
    Scenario(ENDPOINT, "tail of the stream removed", "stream_head_mismatch", dropped_record),
    Scenario(ENDPOINT, "record offered twice", "record_replayed", sink_replay),
    Scenario(ENDPOINT, "limit: falsified before sealing", "undetected by design", limit_before_seal),
]


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Trust-chain demo")
    parser.add_argument("action", choices=["demo"], nargs="?", default="demo")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    reports: Dict[str, TrustReport] = {}
    for scenario in SCENARIOS:
        reports[scenario.name] = scenario.run()

    if args.json:
        print(json.dumps({scenario.name: reports[scenario.name].as_dict() for scenario in SCENARIOS}, indent=2, sort_keys=True))
        return 0

    width = max(len(s.name) for s in SCENARIOS)
    print(f"{'property'.ljust(24)} {'scenario'.ljust(width)}  {'worst':<7} {'expectation':<24} codes")
    print("-" * (width + 84))
    for scenario in SCENARIOS:
        report = reports[scenario.name]
        codes = sorted({issue.code for issue in report.issues}) or ["none"]
        print(
            f"{scenario.property.ljust(24)} {scenario.name.ljust(width)}  {report.worst:<7} "
            f"{scenario.expectation:<24} {', '.join(codes)}"
        )

    print()
    for name in PROPERTIES:
        held = [s for s in SCENARIOS if s.property == name and reports[s.name].worst == "none"]
        broken = [s for s in SCENARIOS if s.property == name and reports[s.name].worst != "none"]
        print(f"{PROPERTY_TITLE[name]}: {PROPERTY_QUESTION[name]}")
        print(f"    held in {len(held)} scenario(s), failed or weakened in {len(broken)}")
    print()
    print("findings:")
    for scenario in SCENARIOS:
        for issue in reports[scenario.name].sorted_issues():
            print(f"  [{issue.severity}] {scenario.name}: {issue.code}")
            print(f"      {issue.detail}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
