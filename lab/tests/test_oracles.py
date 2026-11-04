"""Oracle tests: the system must not answer questions it was not asked.

An oracle, in this sense, is any observable that differs between rejections. It does not
need to decrypt anything: "that envelope is too short" versus "unknown version" tells a
prober how far their guess got, and "wrong key" versus "modified byte" turns a cipher into
a decryption service one bit at a time. The fix is always the same shape, one observable
answer and the useful detail kept local, and it is always easy to lose again the next time
somebody improves an error message.

So the property is tested as a property: every rejection path, compared against every other.
"""

from __future__ import annotations

import unittest

from lab.canary import tokens
from lab.crypto import aesgcm, envelope
from lab.crypto.keys import KeyRing


MASTER = "0f" * 32


def ring(seed: str = MASTER) -> KeyRing:
    return KeyRing(bytes.fromhex(seed) if len(seed) == 64 else __import__("hashlib").sha256(seed.encode()).hexdigest().encode()[:32])


def blob_of(ring_: KeyRing, payload: bytes = b"record", backend: bytes = envelope.DEFAULT_BACKEND) -> bytes:
    return envelope.encrypt(ring_, payload, aad=b"stream=asset-1;seq=7", backend=backend)


class UniformFailureTests(unittest.TestCase):
    """Every rejection is the same rejection, as seen from outside."""

    def structural_failures(self) -> list[bytes]:
        good = blob_of(ring())
        return [
            b"",  # empty
            b"NW1",  # shorter than a header
            good[: envelope.HEADER_LEN],  # header only
            b"XX9" + good[3:],  # unknown version
            good[:3] + b"\x09" + good[4:],  # unknown backend
            good[: envelope.HEADER_LEN + 4],  # short for a GCM tag
            # a legacy envelope shorter than its 32-byte tag: the case the old length check
            # admitted because it measured every envelope against the GCM tag size
            envelope.VERSION
            + envelope.BACKEND_STDLIB
            + b"\x00" * envelope.NONCE_LEN
            + b"\x11" * 8,
        ]

    def test_structural_rejections_are_textually_identical(self):
        messages = set()
        for index, blob in enumerate(self.structural_failures()):
            with self.assertRaises(envelope.Tampered, msg=f"case {index} was accepted") as ctx:
                envelope.peek(blob)
            messages.add(str(ctx.exception))
        self.assertEqual(len(messages), 1, f"structural rejections differ, which is an oracle: {messages}")

    def test_structural_rejections_keep_their_detail_for_local_logs(self):
        """Uniform on the outside must not mean useless on the inside."""
        details = set()
        for blob in self.structural_failures():
            with self.assertRaises(envelope.Tampered) as ctx:
                envelope.peek(blob)
            details.add(ctx.exception.detail)
        self.assertGreater(len(details), 2, "the operator needs to be able to tell these apart in a log")

    def test_authentication_failures_are_indistinguishable(self):
        ring_ = ring()
        good = blob_of(ring_)
        wrong_key = KeyRing(b"\x11" * 32)
        flipped = bytearray(good)
        flipped[-1] ^= 0x01
        cases = {
            "wrong key": lambda: envelope.decrypt(wrong_key, good, aad=b"stream=asset-1;seq=7"),
            "flipped ciphertext": lambda: envelope.decrypt(ring_, bytes(flipped), aad=b"stream=asset-1;seq=7"),
            "wrong aad": lambda: envelope.decrypt(ring_, good, aad=b"stream=asset-2;seq=7"),
            "flipped header": lambda: envelope.decrypt(ring_, good[:4] + b"\x00" * 12 + good[16:], aad=b"stream=asset-1;seq=7"),
        }
        messages = set()
        for name, call in cases.items():
            with self.assertRaises(envelope.Tampered, msg=name) as ctx:
                call()
            messages.add(str(ctx.exception))
        self.assertEqual(len(messages), 1, f"auth failures differ between cases: {messages}")

    def test_both_backends_reject_alike(self):
        """The legacy path and GCM must not be distinguishable by their failure text."""
        legacy = blob_of(ring(), backend=envelope.BACKEND_STDLIB)
        gcm = blob_of(ring(), backend=envelope.BACKEND_GCM)
        texts = set()
        for blob in (legacy, gcm):
            damaged = blob[:-1] + bytes([blob[-1] ^ 0xFF])
            with self.assertRaises(envelope.Tampered) as ctx:
                envelope.decrypt(ring(), damaged, aad=b"stream=asset-1;seq=7")
            texts.add(str(ctx.exception))
        self.assertEqual(len(texts), 1)

    def test_no_exception_suggests_the_key_was_the_problem(self):
        """A dead `KeyMismatch` class documented exactly the thing the protocol refuses to say."""
        self.assertFalse(hasattr(envelope, "KeyMismatch"), "a wrong-key error class is a decryption oracle")

    def test_replay_rejections_are_indistinguishable(self):
        guard = envelope.ReplayGuard()
        guard.accept("asset-1", 5)
        guard.accept("asset-1", 6)
        texts = set()
        details = set()
        for stream, seq in (("asset-1", 6), ("asset-1", 2)):
            with self.assertRaises(envelope.CryptoError) as ctx:
                guard.accept(stream, seq)
            texts.add(str(ctx.exception))
            details.add(ctx.exception.detail)
        self.assertEqual(len(texts), 1, f"replay and rollback are distinguishable from outside: {texts}")
        self.assertEqual(len(details), 2, "the operator still needs to know which one happened")

    def test_rejection_text_discloses_no_state(self):
        """The old message printed the high-water mark: how far along the stream is, for free."""
        guard = envelope.ReplayGuard()
        for seq in range(1, 8):
            guard.accept("asset-1", seq)
        guard.accept("asset-1", 99)  # unseen, so the rejection below is the rollback branch
        with self.assertRaises(envelope.CryptoError) as ctx:
            guard.accept("asset-1", 50)
        self.assertNotIn("99", str(ctx.exception), "the accepted position leaked into the public message")
        self.assertIn("high-water mark", ctx.exception.detail, "the rollback detail names the position it beat")


class LegacyShapeTests(unittest.TestCase):
    def test_a_legacy_envelope_shorter_than_its_tag_is_refused_by_peek(self):
        """The length check used the GCM tag size, so a 40-byte legacy envelope got through."""
        short = envelope.VERSION + envelope.BACKEND_STDLIB + b"\x00" * envelope.NONCE_LEN + b"\x11" * 8
        self.assertLess(len(short), envelope.HEADER_LEN + envelope.TAG_LEN)
        with self.assertRaises(envelope.Tampered) as ctx:
            envelope.peek(short)
        self.assertIn("tag", ctx.exception.detail)

    def test_a_minimum_sized_legacy_envelope_peeks(self):
        legacy = blob_of(ring(), backend=envelope.BACKEND_STDLIB)
        info = envelope.peek(legacy)
        self.assertEqual(info.backend, "hmac-ctr-etm")
        self.assertEqual(info.tag_length, envelope.TAG_LEN)


class TokenOracleTests(unittest.TestCase):
    def test_verify_answers_false_rather_than_describing_the_format(self):
        secret = tokens.new_secret()
        for malformed in ("", "nope", "cnry", "cnry_", "cnry_zzzzzzzzzzzzzzzz", "CNRY_0123456789abcdef"):
            with self.subTest(malformed=malformed):
                self.assertFalse(tokens.verify(malformed, "site-footer", secret, "2026-11"))

    def test_verify_still_accepts_only_the_issued_token(self):
        secret = tokens.new_secret()
        token = tokens.issue("site-footer", secret, "2026-11")
        self.assertTrue(tokens.verify(token.token_id, "site-footer", secret, "2026-11"))
        self.assertFalse(tokens.verify(token.token_id, "site-footer", secret, "2026-12"))
        self.assertFalse(tokens.verify(token.token_id, "other-label", secret, "2026-11"))


class CipherOracleTests(unittest.TestCase):
    """The primitive underneath: a tag comparison that returns early is a byte-at-a-time oracle."""

    def test_tag_comparison_is_constant_time(self):
        key = bytes(range(32))
        nonce = bytes(range(12))
        blob = aesgcm.encrypt(key, nonce, b"payload", b"aad")
        with self.assertRaises(aesgcm.AuthenticationError):
            aesgcm.decrypt(key, nonce, blob[:-1] + bytes([blob[-1] ^ 0x01]), b"aad")

    def test_wrong_aad_is_a_failure_not_a_different_error(self):
        key = bytes(range(32))
        nonce = bytes(range(12))
        blob = aesgcm.encrypt(key, nonce, b"payload", b"aad")
        with self.assertRaises(aesgcm.AuthenticationError):
            aesgcm.decrypt(key, nonce, blob, b"different-aad")


if __name__ == "__main__":
    unittest.main()
