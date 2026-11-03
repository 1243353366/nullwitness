"""Payload encryption and authenticated encryption: the envelope itself.

Two properties live here, and they are separate questions:

- **payload encryption** asks whether an unauthorized reader can see the contents.
- **authenticated encryption** asks whether an unauthorized writer can modify the
  ciphertext without that being noticed.

The second is the one that gets dropped, usually by using a cipher without a MAC and
believing the first property covers both. It does not: an attacker who cannot read a byte
can still flip one, and a flipped byte in a log that decides whether someone was fired is a
worse outcome than the log being unreadable.

## About the construction, plainly

The sandbox this repository runs in has no `cryptography` package, so the AEAD here is
built from the standard library: an HMAC-SHA256 counter-mode keystream for confidentiality
and HMAC-SHA256 over the header and ciphertext for authentication (encrypt-then-MAC, with
different subkeys for each job).

**This is a lab construction and it is not a substitute for AES-GCM or ChaCha20-Poly1305.**
It has no hardware acceleration, it has no nonce-misuse resistance, it is written in Python
so its timing is not constant, and reusing a nonce under one key is catastrophic in exactly
the same way it is for any counter-mode cipher. The reason it exists is that the boundary
checks below are the interesting part of this package and they are library-agnostic: swap
`_keystream` and `_tag` for AES-GCM and every check still holds. Do that before protecting
anything real.

What the construction does get right, and what the tests assert:

- encrypt-then-MAC, never MAC-then-encrypt, so no padding oracle can exist
- separate subkeys for keystream and tag, so neither primitive's output is usable as the
  other's input
- the header is inside the MAC, so the version and nonce cannot be rewritten
- associated data is inside the MAC, so the context a record belongs to is authenticated
  with it: a record cannot be moved to another asset, epoch, or sequence number
"""

from __future__ import annotations

import hashlib
import hmac
import os
from dataclasses import dataclass
from typing import Dict, Optional, Set

from lab.crypto.keys import KeyRing

VERSION = b"NW1"
BACKEND_STDLIB = b"\x01"
NONCE_LEN = 12
TAG_LEN = 32
HEADER_LEN = len(VERSION) + 1 + NONCE_LEN

PAYLOAD_PURPOSE = "payload"
AUTH_PURPOSE = "authenticate"


class CryptoError(Exception):
    """Base class so callers can catch the family without catching everything."""


class Tampered(CryptoError):
    """The ciphertext, header, or associated data does not authenticate."""


class KeyMismatch(CryptoError):
    """Right shape, wrong key: decryption would produce noise, so it refuses."""


class Replay(CryptoError):
    """A record that was already accepted, offered again."""


class OutOfOrder(CryptoError):
    """A record older than the high-water mark for its stream."""


def _keystream(ring: KeyRing, nonce: bytes, length: int) -> bytes:
    key = ring.subkey(PAYLOAD_PURPOSE, context=nonce).material
    out = bytearray()
    counter = 0
    while len(out) < length:
        out += hmac.new(key, nonce + counter.to_bytes(8, "big"), hashlib.sha256).digest()
        counter += 1
    return bytes(out[:length])


def _tag(ring: KeyRing, header: bytes, aad: bytes, ciphertext: bytes) -> bytes:
    key = ring.subkey(AUTH_PURPOSE).material
    message = header + len(aad).to_bytes(8, "big") + aad + ciphertext
    return hmac.new(key, message, hashlib.sha256).digest()


def encrypt(ring: KeyRing, plaintext: bytes, aad: bytes = b"", nonce: Optional[bytes] = None) -> bytes:
    """Encrypt and authenticate. The AAD is the context: asset, epoch, sequence.

    Callers should put the record's identity and position in the AAD. Without it the
    ciphertext is authentic but anonymous, which lets an attacker move a valid record into
    a place where it means something else.
    """
    nonce = os.urandom(NONCE_LEN) if nonce is None else nonce
    if len(nonce) != NONCE_LEN:
        raise ValueError(f"nonce must be {NONCE_LEN} bytes")
    header = VERSION + BACKEND_STDLIB + nonce
    ciphertext = bytes(a ^ b for a, b in zip(plaintext, _keystream(ring, nonce, len(plaintext))))
    return header + ciphertext + _tag(ring, header, aad, ciphertext)


@dataclass(frozen=True)
class EnvelopeInfo:
    """What a reader can learn without a key, which is what an attacker sees."""

    backend: str
    nonce: bytes
    ciphertext_length: int
    tag_length: int


def peek(blob: bytes) -> EnvelopeInfo:
    if len(blob) < HEADER_LEN + TAG_LEN:
        raise Tampered(f"envelope is {len(blob)} bytes, shorter than a header and tag")
    if blob[:3] != VERSION:
        raise Tampered(f"unknown envelope version {blob[:3]!r}")
    backend = "hmac-ctr-etm" if blob[3:4] == BACKEND_STDLIB else f"unknown({blob[3:4]!r})"
    return EnvelopeInfo(
        backend=backend,
        nonce=blob[4:HEADER_LEN],
        ciphertext_length=len(blob) - HEADER_LEN - TAG_LEN,
        tag_length=TAG_LEN,
    )


def decrypt(ring: KeyRing, blob: bytes, aad: bytes = b"") -> bytes:
    """Authenticate first, decrypt second. Never the other way round."""
    info = peek(blob)  # raises Tampered on a truncated or mis-versioned envelope
    header = blob[:HEADER_LEN]
    ciphertext = blob[HEADER_LEN:-TAG_LEN]
    tag = blob[-TAG_LEN:]
    expected = _tag(ring, header, aad, ciphertext)
    if not hmac.compare_digest(tag, expected):
        # One failure mode on purpose. Distinguishing "wrong key" from "modified ciphertext"
        # in an error message is a free oracle, so the caller supplies the context instead.
        raise Tampered(
            "ciphertext, header, or associated data does not authenticate: this envelope was "
            "modified, or it was encrypted under a different key, and the two are not "
            "distinguishable from inside the protocol"
        )
    stream = _keystream(ring, info.nonce, len(ciphertext))
    return bytes(a ^ b for a, b in zip(ciphertext, stream))


class ReplayGuard:
    """Monotone acceptance per stream.

    Authenticated encryption proves a record is genuine. It says nothing about whether the
    record is *new*: a perfect ciphertext replayed is a perfect ciphertext. Replay is not a
    cryptography problem, it is a state problem, so the state lives here.
    """

    def __init__(self) -> None:
        self._high: Dict[str, int] = {}
        self._seen: Set[tuple] = set()

    def accept(self, stream: str, seq: int) -> None:
        if (stream, seq) in self._seen:
            raise Replay(f"record {stream}/{seq} was already accepted: the same envelope was offered twice")
        high = self._high.get(stream)
        if high is not None and seq <= high:
            raise OutOfOrder(
                f"record {stream}/{seq} arrives below the high-water mark {high}: "
                "authentic, but in the past, which is how a deletion is hidden"
            )
        self._seen.add((stream, seq))
        self._high[stream] = seq

    def high_water(self, stream: str) -> Optional[int]:
        return self._high.get(stream)

    def snapshot(self) -> Dict[str, int]:
        return dict(self._high)
