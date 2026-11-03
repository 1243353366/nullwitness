"""Tests for the trust chain: five properties, each with a case that holds and one that fails.

Two conventions in this file:

- Primitives are checked against published vectors where they exist. HKDF is tested with
  RFC 5869's own test data, because a key-derivation bug that is self-consistent produces a
  system that works perfectly and is wrong.
- Every property has a *control*: a legitimate variation that must not be reported. The
  crypto layer is easier to over-report than the integrity monitor, so the controls matter
  more here, not less.

The limit case is asserted too: a record falsified inside an endpoint before it was sealed
passes everything here. That is not a bug to fix, it is what property four and five are for.
"""

from __future__ import annotations

import hashlib
import os
import pathlib
import tempfile
import unittest

from lab.crypto import boot, envelope, keys
from lab.crypto.envelope import OutOfOrder, Replay, ReplayGuard, Tampered
from lab.crypto.flow import Partition, Sink, Source, audit_stream, combine
from lab.crypto.keys import KeyRing, audit_custody, hkdf, write_key_file
from lab.crypto.model import (
    AUTHENTICATED,
    BOOT,
    ENDPOINT,
    KEY_PROTECTION,
    PAYLOAD,
    Issue,
    TrustReport,
)
from lab.crypto.seal import SealedRecord, SourceSeal, seal_many, verify_seal

MASTER = b"unit-test-master-secret-32-bytes!!"
STREAM = "asset-1/audit"
AAD = b"asset-1|0"


def aad_for(stream: str, seq: int) -> bytes:
    return b"|".join([b"nullwitness-record", stream.encode("utf-8"), str(seq).encode("ascii")])


class HkdfTests(unittest.TestCase):
    def test_rfc5869_case_1(self):
        """The vector from RFC 5869 A.1, so derivation is right rather than self-consistent."""
        ikm = bytes.fromhex("0b" * 22)
        salt = bytes.fromhex("000102030405060708090a0b0c")
        info = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
        out = hkdf(ikm, info, 42, salt)
        self.assertEqual(
            out.hex(),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
        )

    def test_length_is_exact(self):
        self.assertEqual(len(hkdf(b"a", b"b", 17)), 17)
        self.assertEqual(len(hkdf(b"a", b"b", 32)), 32)

    def test_refuses_absurd_length(self):
        with self.assertRaises(ValueError):
            hkdf(b"a", b"b", 255 * 32 + 1)


class KeyRingTests(unittest.TestCase):
    def test_rejects_short_master(self):
        with self.assertRaises(ValueError):
            KeyRing(b"short")

    def test_purposes_do_not_share_key_material(self):
        ring = KeyRing(MASTER)
        self.assertNotEqual(ring.subkey("payload").material, ring.subkey("seal").material)

    def test_same_purpose_is_stable(self):
        ring = KeyRing(MASTER)
        self.assertEqual(ring.subkey("payload").material, ring.subkey("payload").material)

    def test_generation_changes_the_key(self):
        ring = KeyRing(MASTER)
        self.assertNotEqual(ring.subkey("payload").material, ring.rotated().subkey("payload").material)

    def test_repr_does_not_leak_material(self):
        ring = KeyRing(MASTER)
        self.assertNotIn(MASTER.decode("latin-1"), repr(ring))
        self.assertNotIn(ring.subkey("payload").material.hex(), repr(ring.subkey("payload")))


class EnvelopeTests(unittest.TestCase):
    def setUp(self):
        self.ring = KeyRing(MASTER)

    def test_roundtrip(self):
        blob = envelope.encrypt(self.ring, b"the record body", AAD)
        self.assertEqual(envelope.decrypt(self.ring, blob, AAD), b"the record body")

    def test_ciphertext_does_not_contain_the_plaintext(self):
        body = b"2026-11-03T16:00:00Z patient=alex diagnosis=none"
        blob = envelope.encrypt(self.ring, body, AAD)
        self.assertNotIn(body, blob)

    def test_peek_reveals_only_metadata(self):
        info = envelope.peek(envelope.encrypt(self.ring, b"x" * 100, AAD))
        self.assertEqual(info.backend, "hmac-ctr-etm")
        self.assertEqual(info.ciphertext_length, 100)
        self.assertEqual(info.tag_length, 32)

    def test_flipped_ciphertext_byte_is_caught(self):
        blob = bytearray(envelope.encrypt(self.ring, b"the record body", AAD))
        blob[envelope.HEADER_LEN] ^= 0x01
        with self.assertRaises(Tampered):
            envelope.decrypt(self.ring, bytes(blob), AAD)

    def test_changed_aad_is_caught(self):
        blob = envelope.encrypt(self.ring, b"body", AAD)
        with self.assertRaises(Tampered):
            envelope.decrypt(self.ring, blob, b"asset-2|0")

    def test_truncation_is_caught(self):
        blob = envelope.encrypt(self.ring, b"body", AAD)
        with self.assertRaises(Tampered):
            envelope.decrypt(self.ring, blob[:-4], AAD)

    def test_wrong_key_is_caught(self):
        blob = envelope.encrypt(self.ring, b"body", AAD)
        with self.assertRaises(Tampered):
            envelope.decrypt(KeyRing(b"another-master-secret-32-bytes-long"), blob, AAD)

    def test_rewritten_header_is_caught(self):
        blob = bytearray(envelope.encrypt(self.ring, b"body", AAD))
        blob[4] ^= 0xFF  # nonce
        with self.assertRaises(Tampered):
            envelope.decrypt(self.ring, bytes(blob), AAD)

    def test_nonces_differ_between_calls(self):
        first = envelope.peek(envelope.encrypt(self.ring, b"body", AAD)).nonce
        second = envelope.peek(envelope.encrypt(self.ring, b"body", AAD)).nonce
        self.assertNotEqual(first, second)


class ReplayGuardTests(unittest.TestCase):
    def test_accepts_a_monotone_stream(self):
        guard = ReplayGuard()
        for seq in range(4):
            guard.accept(STREAM, seq)
        self.assertEqual(guard.high_water(STREAM), 3)

    def test_repeat_is_a_replay(self):
        guard = ReplayGuard()
        guard.accept(STREAM, 0)
        with self.assertRaises(Replay):
            guard.accept(STREAM, 0)

    def test_older_record_is_out_of_order(self):
        guard = ReplayGuard()
        guard.accept(STREAM, 5)
        with self.assertRaises(OutOfOrder):
            guard.accept(STREAM, 3)


class SealTests(unittest.TestCase):
    def setUp(self):
        self.ring = KeyRing(MASTER)
        self.records = seal_many(
            self.ring, STREAM, [(f"r{i}", f"body {i}".encode()) for i in range(4)]
        )

    def test_clean_chain_verifies(self):
        self.assertEqual(verify_seal(self.ring, STREAM, self.records), [])

    def test_altered_body_is_caught(self):
        broken = list(self.records)
        broken[2] = SealedRecord(2, "r2", b"body 2 edited", broken[2].digest, broken[2].mac)
        codes = {issue.code for issue in verify_seal(self.ring, STREAM, broken)}
        self.assertIn("plaintext_tampered", codes)

    def test_removed_record_is_caught(self):
        codes = {issue.code for issue in verify_seal(self.ring, STREAM, self.records[:2] + self.records[3:])}
        self.assertIn("record_removed", codes)

    def test_reordered_records_are_caught(self):
        shuffled = [self.records[0], self.records[2], self.records[1], self.records[3]]
        codes = {issue.code for issue in verify_seal(self.ring, STREAM, shuffled)}
        self.assertIn("record_reordered", codes)

    def test_injected_record_is_caught(self):
        sealed = SourceSeal(self.ring, STREAM)
        sealed.seal("r0", b"body 0")
        injected = SealedRecord(1, "r9", b"body 9", hashlib.sha256(b"body 9").hexdigest(), "0" * 64)
        codes = {issue.code for issue in verify_seal(self.ring, STREAM, [self.records[0], injected])}
        self.assertIn("seal_forged", codes)

    def test_missing_tail_needs_a_head_to_notice(self):
        """Completeness is not integrity: a clean prefix verifies without an anchor."""
        prefix = self.records[:2]
        self.assertEqual(verify_seal(self.ring, STREAM, prefix), [])
        codes = {issue.code for issue in verify_seal(self.ring, STREAM, prefix, expected_head=SourceSeal(self.ring, STREAM).head_hex())}
        self.assertIn("stream_head_mismatch", codes)

    def test_a_different_stream_key_does_not_verify(self):
        codes = {issue.code for issue in verify_seal(self.ring, "asset-2/audit", self.records)}
        self.assertIn("seal_forged", codes)


class BootTests(unittest.TestCase):
    def setUp(self):
        self.ring = KeyRing(MASTER)
        self.digests = {
            "firmware": hashlib.sha256(b"fw").hexdigest(),
            "bootloader": hashlib.sha256(b"bl").hexdigest(),
            "kernel": hashlib.sha256(b"kernel").hexdigest(),
        }
        self.policy = boot.BootPolicy(expected=dict(self.digests), min_security_version=5)

    def report(self, attestation, challenge="c1"):
        return boot.verify_attestation(self.ring, attestation, self.policy, challenge)

    def test_clean_chain_holds(self):
        attestation = boot.build_chain(self.ring, self.digests, "c1", security_version=6)
        self.assertEqual(self.report(attestation).worst, "none")

    def test_unsigned_report_is_not_evidence(self):
        attestation = boot.build_chain(self.ring, self.digests, "c1", security_version=6)
        forged = boot.Attestation(attestation.stages, attestation.nonce, attestation.security_version, "")
        codes = {issue.code for issue in self.report(forged).issues}
        self.assertEqual(codes, {"attestation_unauthenticated"})

    def test_stale_report_is_rejected_before_measurements_are_read(self):
        attestation = boot.build_chain(self.ring, self.digests, "c1", security_version=6)
        codes = {issue.code for issue in self.report(attestation, challenge="c2").issues}
        self.assertEqual(codes, {"attestation_replayed"})

    def test_different_kernel_fails_policy(self):
        measured = dict(self.digests)
        measured["kernel"] = hashlib.sha256(b"kernel-patched").hexdigest()
        attestation = boot.build_chain(self.ring, measured, "c1", security_version=6)
        codes = {issue.code for issue in self.report(attestation).issues}
        self.assertIn("boot_measurement_mismatch", codes)

    def test_broken_chain_is_caught(self):
        stages = [
            boot.Stage("firmware", self.digests["firmware"], extends="0" * 64),
            boot.Stage("bootloader", self.digests["bootloader"], extends=self.digests["kernel"]),
            boot.Stage("kernel", self.digests["kernel"], extends=None),
        ]
        attestation = boot.attest(self.ring, stages, "c1", security_version=6)
        codes = {issue.code for issue in self.report(attestation).issues}
        self.assertIn("boot_chain_broken", codes)

    def test_rollback_fails_the_version_floor(self):
        attestation = boot.build_chain(self.ring, self.digests, "c1", security_version=4)
        codes = {issue.code for issue in self.report(attestation).issues}
        self.assertIn("boot_rollback", codes)

    def test_missing_stage_is_caught(self):
        stages = [
            boot.Stage("firmware", self.digests["firmware"], extends=self.digests["kernel"]),
            boot.Stage("kernel", self.digests["kernel"], extends=None),
        ]
        attestation = boot.attest(self.ring, stages, "c1", security_version=6)
        codes = {issue.code for issue in self.report(attestation).issues}
        self.assertIn("boot_stage_missing", codes)

    def test_unknown_stage_without_policy_is_not_a_finding(self):
        att = boot.build_chain(self.ring, self.digests, "c1", security_version=6)
        report = boot.verify_attestation(self.ring, att, boot.BootPolicy(expected={}), "c1")
        self.assertEqual(report.issues, [])
        self.assertEqual(len(report.unchecked), 3)


class CustodyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = pathlib.Path(self.tmp.name)
        self.data = self.root / "data"
        self.data.mkdir()

    def test_proper_custody_holds(self):
        key_file = write_key_file(self.root / "keys" / "master.key", MASTER)
        report = audit_custody(key_file, MASTER, data_root=self.data, now=key_file.stat().st_mtime + 10)
        self.assertEqual(report.worst, "none")
        self.assertIn(KEY_PROTECTION, report.verified)

    def test_key_file_is_written_0600(self):
        key_file = write_key_file(self.root / "master.key", MASTER)
        self.assertEqual(key_file.stat().st_mode & 0o777, 0o600)

    def test_loose_permissions_are_high(self):
        key_file = write_key_file(self.root / "master.key", MASTER)
        os.chmod(key_file, 0o640)
        codes = {issue.code for issue in audit_custody(key_file, MASTER).issues}
        self.assertIn("key_permissions_loose", codes)

    def test_key_inside_the_data_tree_is_high(self):
        key_file = write_key_file(self.data / "master.key", MASTER)
        codes = {issue.code for issue in audit_custody(key_file, MASTER, data_root=self.data).issues}
        self.assertIn("key_colocated_with_data", codes)

    def test_key_in_environment_is_high(self):
        os.environ["NULLWITNESS_KEY"] = MASTER.decode()
        try:
            codes = {issue.code for issue in audit_custody(None, MASTER).issues}
        finally:
            del os.environ["NULLWITNESS_KEY"]
        self.assertIn("key_in_environment", codes)

    def test_short_master_is_reported(self):
        key_file = write_key_file(self.root / "master.key", b"short")
        codes = {issue.code for issue in audit_custody(key_file, b"short").issues}
        self.assertIn("key_material_weak", codes)

    def test_old_key_is_reported(self):
        key_file = write_key_file(self.root / "master.key", MASTER)
        codes = {
            issue.code
            for issue in audit_custody(key_file, MASTER, now=key_file.stat().st_mtime + 200 * 86400).issues
        }
        self.assertIn("key_not_rotated", codes)

    def test_missing_key_path_is_unchecked_not_clean(self):
        report = audit_custody(None, MASTER)
        self.assertEqual(report.worst, "none")
        self.assertTrue(report.unchecked)

    def test_copies_are_found(self):
        write_key_file(self.data / "leak.bin", MASTER)
        found = keys.find_copies(MASTER, [self.data])
        self.assertEqual([path.name for path in found], ["leak.bin"])


class FlowTests(unittest.TestCase):
    def setUp(self):
        self.ring = KeyRing(MASTER)

    def stream(self, count=4):
        source = Source(self.ring, STREAM)
        partitions = [source.emit(f"r{i}", f"2026-11-03T16:0{i}:00Z event={i} actor=service".encode()) for i in range(count)]
        return source, partitions

    def test_clean_stream_verifies_three_properties(self):
        source, partitions = self.stream()
        report = audit_stream(self.ring, STREAM, partitions, source.sealed, expected_head=source.head)
        self.assertEqual(report.worst, "none")
        self.assertEqual({PAYLOAD, AUTHENTICATED, ENDPOINT} - set(report.verified), set())

    def test_roundtrip_through_a_sink(self):
        source, partitions = self.stream(2)
        sink = Sink(self.ring, STREAM)
        bodies = [sink.receive(partition) for partition in partitions]
        self.assertIn(b"event=1", bodies[1])

    def test_flipped_byte_is_attributed_to_the_wire(self):
        source, partitions = self.stream()
        blob = bytearray(partitions[1].blob)
        blob[envelope.HEADER_LEN + 2] ^= 0x40
        partitions[1] = Partition(STREAM, 1, "r1", bytes(blob))
        report = audit_stream(self.ring, STREAM, partitions, source.sealed, expected_head=source.head)
        codes = {issue.code for issue in report.issues if issue.severity == "high"}
        self.assertEqual(codes, {"ciphertext_tampered"})

    def test_re_encrypted_forgery_is_attributed_to_the_plaintext(self):
        source, partitions = self.stream()
        forged = envelope.encrypt(self.ring, b"2026-11-03T16:01:00Z event=1 actor=root", aad=aad_for(STREAM, 1))
        partitions[1] = Partition(STREAM, 1, "r1", forged)
        report = audit_stream(self.ring, STREAM, partitions, source.sealed, expected_head=source.head)
        codes = {issue.code for issue in report.issues}
        self.assertIn("plaintext_tampered", codes)
        self.assertNotIn("ciphertext_tampered", codes)

    def test_removed_record_and_truncated_tail(self):
        source, partitions = self.stream()
        report = audit_stream(self.ring, STREAM, partitions[:-1], source.sealed[:-1], expected_head=source.head)
        codes = {issue.code for issue in report.issues}
        self.assertIn("stream_head_mismatch", codes)

    def test_replayed_envelope_is_caught(self):
        source, partitions = self.stream()
        report = audit_stream(self.ring, STREAM, partitions + [partitions[-1]], source.sealed, expected_head=source.head)
        codes = {issue.code for issue in report.issues}
        self.assertIn("record_replayed", codes)

    def test_null_cipher_is_reported_as_visible_plaintext(self):
        """An implementation that ships the body in the clear with a valid tag."""
        source = Source(self.ring, STREAM)
        body = b"2026-11-03T16:00:00Z patient=alex diagnosis=none"
        sealed = source.seal.seal("r0", body)
        source.sealed.append(sealed)
        header = envelope.VERSION + envelope.BACKEND_STDLIB + b"\x11" * envelope.NONCE_LEN
        tag = envelope._tag(self.ring, header, aad_for(STREAM, 0), body)
        partition = Partition(STREAM, 0, "r0", header + body + tag)
        report = audit_stream(self.ring, STREAM, [partition], source.sealed)
        codes = {issue.code for issue in report.issues}
        self.assertIn("plaintext_visible", codes)

    def test_limit_a_lie_sealed_at_the_source_is_invisible(self):
        """The endpoint falsifies the record, then seals it. Everything verifies."""
        source = Source(self.ring, STREAM)
        partitions = [source.emit("r0", b"2026-11-03T16:00:00Z actor=root action=delete")]
        report = audit_stream(self.ring, STREAM, partitions, source.sealed, expected_head=source.head)
        self.assertEqual(report.worst, "none", "no cryptographic layer here can see a source-side lie")


class ReportTests(unittest.TestCase):
    def test_worst_and_order(self):
        report = TrustReport()
        report.add(Issue(PAYLOAD, "a", "low", "x"))
        report.add(Issue(BOOT, "b", "high", "y"))
        self.assertEqual(report.worst, "high")
        self.assertEqual(report.sorted_issues()[0].severity, "high")

    def test_by_property_covers_every_property(self):
        report = TrustReport()
        report.add(Issue(ENDPOINT, "a", "high", "x"))
        self.assertEqual(len(report.by_property()), 5)

    def test_combine_keeps_unchecked_notes(self):
        first = TrustReport()
        first.skip(BOOT, "no attestation supplied")
        second = TrustReport()
        second.add(Issue(PAYLOAD, "b", "high", "y"))
        merged = combine(first, second)
        self.assertEqual(merged.worst, "high")
        self.assertEqual(len(merged.unchecked), 1)


if __name__ == "__main__":
    unittest.main()
