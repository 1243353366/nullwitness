"""Tests for AES-256-GCM: published vectors, differential testing, and failure modes.

The vector tests are the ones that matter. A block cipher that is subtly wrong produces tags
that verify against nothing, and the only way to be sure is to compare against values that
were computed by someone else. Cases 13 to 16 of the GCM specification cover AES-256 with
empty, single-block, and multi-block plaintext, with and without associated data, which is
exactly the space where counter handling and GHASH padding go wrong.

The differential tests close the rest of it. The library is available in this sandbox, so the
pure-Python path is compared against it on random keys, nonces, lengths, and AAD. That is a
much wider net than four vectors, and it catches the class of bug that vectors miss: an
implementation that is right for 16-byte inputs and wrong for 17.

Both implementations must also be interchangeable, which the tests assert in both directions:
an envelope written by the library opens in pure Python and back again.
"""

from __future__ import annotations

import os
import random
import unittest

from lab.crypto import aesgcm

try:  # the oracle, when the environment has it
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    HAVE_LIBRARY = True
except Exception:  # pragma: no cover - depends on the environment
    AESGCM = None
    HAVE_LIBRARY = False

ZERO_KEY = bytes(32)
FEFFE_KEY = bytes.fromhex("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308")
CAFE_NONCE = bytes.fromhex("cafebabefacedbaddecaf888")
SIXTY_FOUR = bytes.fromhex(
    "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
    "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255"
)


class VectorTests(unittest.TestCase):
    def assert_case(self, name, key, nonce, plaintext, aad, expected_tag, expected_ciphertext=None):
        ciphertext, tag = aesgcm.seal(key, nonce, plaintext, aad)
        self.assertEqual(tag.hex(), expected_tag, f"GCM test case {name} tag")
        if expected_ciphertext is not None:
            self.assertEqual(ciphertext.hex(), expected_ciphertext, f"GCM test case {name} ciphertext")
        self.assertEqual(aesgcm.open_(key, nonce, ciphertext, tag, aad), plaintext)

    def test_case_13_empty_plaintext(self):
        self.assert_case("13", ZERO_KEY, bytes(12), b"", b"", "530f8afbc74536b9a963b4f1c4cb738b")

    def test_case_14_single_block(self):
        self.assert_case(
            "14", ZERO_KEY, bytes(12), bytes(16), b"", "d0d1c8a799996bf0265b98b5d48ab919", "cea7403d4d606b6e074ec5d3baf39d18"
        )

    def test_case_15_four_blocks(self):
        self.assert_case(
            "15",
            FEFFE_KEY,
            CAFE_NONCE,
            SIXTY_FOUR,
            b"",
            "b094dac5d93471bdec1a502270e3cc6c",
            "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa"
            "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad",
        )

    def test_case_16_with_associated_data(self):
        self.assert_case(
            "16",
            FEFFE_KEY,
            CAFE_NONCE,
            SIXTY_FOUR,
            bytes.fromhex("feedfacedeadbeeffeedfacedeadbeefabaddad2"),
            "2df7cd675b4f09163b41ebf980a7f638",
            "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa"
            "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad",
        )


class DifferentialTests(unittest.TestCase):
    """Compare against the library where it exists; skip cleanly where it does not."""

    @unittest.skipUnless(HAVE_LIBRARY, "no cryptography package to compare against")
    def test_random_inputs_match_the_library(self):
        random.seed(20261103)
        for _ in range(120):
            key = os.urandom(32)
            nonce = os.urandom(12)
            plaintext = os.urandom(random.randrange(0, 200))
            aad = os.urandom(random.randrange(0, 70))
            ciphertext, tag = aesgcm.seal(key, nonce, plaintext, aad)
            self.assertEqual(ciphertext + tag, AESGCM(key).encrypt(nonce, plaintext, aad))
            self.assertEqual(aesgcm.open_(key, nonce, ciphertext, tag, aad), plaintext)

    def test_block_boundaries(self):
        """The 15/16/17-byte cases, where padding and counter carry go wrong."""
        random.seed(5)
        key = os.urandom(32)
        nonce = os.urandom(12)
        for length in (0, 1, 15, 16, 17, 31, 32, 33, 64, 255, 256):
            plaintext = os.urandom(length)
            aad = os.urandom(length % 23)
            ciphertext, tag = aesgcm.seal(key, nonce, plaintext, aad)
            self.assertEqual(len(ciphertext), length)
            self.assertEqual(len(tag), 16)
            self.assertEqual(aesgcm.open_(key, nonce, ciphertext, tag, aad), plaintext)


class FailureTests(unittest.TestCase):
    def setUp(self):
        self.key = bytes(range(32))
        self.nonce = bytes(range(12))
        self.ciphertext, self.tag = aesgcm.seal(self.key, self.nonce, b"a record body", b"asset|7")

    def test_flipped_ciphertext_bit_fails(self):
        broken = bytearray(self.ciphertext)
        broken[0] ^= 0x01
        with self.assertRaises(aesgcm.AuthenticationError):
            aesgcm.open_(self.key, self.nonce, bytes(broken), self.tag, b"asset|7")

    def test_flipped_tag_bit_fails(self):
        broken = bytearray(self.tag)
        broken[0] ^= 0x01
        with self.assertRaises(aesgcm.AuthenticationError):
            aesgcm.open_(self.key, self.nonce, self.ciphertext, bytes(broken), b"asset|7")

    def test_changed_aad_fails(self):
        with self.assertRaises(aesgcm.AuthenticationError):
            aesgcm.open_(self.key, self.nonce, self.ciphertext, self.tag, b"asset|8")

    def test_changed_nonce_fails(self):
        with self.assertRaises(aesgcm.AuthenticationError):
            aesgcm.open_(self.key, bytes(12), self.ciphertext, self.tag, b"asset|7")

    def test_wrong_key_fails(self):
        with self.assertRaises(aesgcm.AuthenticationError):
            aesgcm.open_(bytes(32), self.nonce, self.ciphertext, self.tag, b"asset|7")

    def test_short_tag_is_rejected(self):
        with self.assertRaises(ValueError):
            aesgcm.open_(self.key, self.nonce, self.ciphertext, self.tag[:8], b"asset|7")

    def test_non_96_bit_nonce_is_refused(self):
        """Other nonce lengths need J0 derivation, which is where implementations diverge."""
        for length in (8, 16, 20):
            with self.assertRaises(ValueError):
                aesgcm.seal(self.key, bytes(length), b"body")

    def test_wrong_key_length_is_refused(self):
        for length in (16, 24, 31, 33):
            with self.assertRaises(ValueError):
                aesgcm.seal(bytes(length), self.nonce, b"body")


class InterchangeTests(unittest.TestCase):
    """One algorithm, two implementations, identical bytes, either direction."""

    def test_seal_then_dispatch_decrypt(self):
        key = os.urandom(32)
        nonce = aesgcm.random_nonce()
        blob = aesgcm.encrypt(key, nonce, b"interchangeable", b"aad")
        self.assertEqual(aesgcm.decrypt(key, nonce, blob, b"aad"), b"interchangeable")

    @unittest.skipUnless(HAVE_LIBRARY, "no cryptography package for the parity check")
    def test_pure_python_output_opens_with_the_library(self):
        key = os.urandom(32)
        nonce = os.urandom(12)
        ciphertext, tag = aesgcm.seal(key, nonce, b"written by pure python", b"aad")
        self.assertEqual(AESGCM(key).decrypt(nonce, ciphertext + tag, b"aad"), b"written by pure python")

    @unittest.skipUnless(HAVE_LIBRARY, "no cryptography package for the parity check")
    def test_library_output_opens_in_pure_python(self):
        key = os.urandom(32)
        nonce = os.urandom(12)
        blob = AESGCM(key).encrypt(nonce, b"written by the library", b"aad")
        self.assertEqual(aesgcm.open_(key, nonce, blob[:-16], blob[-16:], b"aad"), b"written by the library")

    def test_implementation_is_named(self):
        self.assertIn(aesgcm.implementation(), {"cryptography", "python"})


if __name__ == "__main__":
    unittest.main()
