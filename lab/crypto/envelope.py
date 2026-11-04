"""Payload encryption and authenticated encryption: the envelope itself.

Two properties live here, and they are separate questions:

- **payload encryption** asks whether an unauthorized reader can see the contents.
- **authenticated encryption** asks whether an unauthorized writer can modify the
  ciphertext without that being noticed.

The second is the one that gets dropped, usually by using a cipher without a MAC and
believing the first property covers both. It does not: an attacker who cannot read a byte
can still flip one, and a flipped byte in a log that decides whether someone was fired is a
worse outcome than the log being unreadable.

## The cipher

**AES-256-GCM**, the standard authenticated cipher, with the nonce and associated data
exactly where they belong. GCM authenticates the ciphertext and the AAD together, so the
header and the context a record belongs to are as protected as the body:

- the header is inside the tag, so the version and nonce cannot be rewritten
- the AAD carries the stream and sequence, so a record cannot be moved to another asset or
  epoch where it would mean something else
- one tag failure, one error, no detail: a distinguishable failure is a free oracle

Two implementations sit behind that, producing byte-identical envelopes:

- `cryptography`'s AESGCM when installed, which is constant-time and hardware-accelerated
- the pure-Python AES-256-GCM in `aesgcm.py` when it is not, checked against the published
  GCM test vectors and cross-checked against the library on random inputs

The pure-Python path is a portability fallback with an honest caveat, not a recommendation:
its S-box is a table and its GHASH is a bit loop, so it leaks through timing. `aesgcm.py`
says so at the top, and `lab/TRUST-CHAIN.md` repeats it where a reader deciding what to
deploy will see it.

The legacy HMAC-CTR construction from the first version of this file (`backend 0x01`) is
still readable, because envelopes written by it exist and a format change that strands old
records is not a format change, it is data loss. New records use GCM (`backend 0x02`).
"""

from __future__ import annotations

import hashlib
import hmac
import os
from dataclasses import dataclass
from typing import Dict, Optional, Set

from lab.crypto import aesgcm
from lab.crypto.keys import KeyRing

VERSION = b"NW1"
BACKEND_STDLIB = b"\x01"  # legacy HMAC-CTR: read-only support, kept so old records open
BACKEND_GCM = b"\x02"  # AES-256-GCM
DEFAULT_BACKEND = BACKEND_GCM
NONCE_LEN = aesgcm.NONCE_BYTES
TAG_LEN = 32  # legacy tag length; GCM's is aesgcm.TAG_BYTES
GCM_TAG_LEN = aesgcm.TAG_BYTES
HEADER_LEN = len(VERSION) + 1 + NONCE_LEN

PAYLOAD_PURPOSE = "payload"
AUTH_PURPOSE = "authenticate"


class CryptoError(Exception):
    """Base class so callers can catch the family without catching everything."""


class _Uniform(CryptoError):
    """An error whose observable form is fixed, with the specifics kept local.

    A distinguishable failure is an oracle: it answers a question the attacker could
    otherwise only guess. "Wrong key" versus "modified byte" is the classic version (it
    turns a cipher into a decryption service), but the same shape appears anywhere a
    rejection explains itself, including "that envelope was too short" versus "unknown
    version", which tells a prober how far their guess got.

    So `str()` returns one sentence for every instance of the class, and the detail that
    an operator actually wants sits in `.detail`, which is for logs on the host that
    raised it. Nothing on a network path may serialise `.detail` or the class name; see
    `lab/TRUST-CHAIN.md` and the disclosure section of `lab/README.md`.
    """

    PUBLIC = "rejected"

    def __init__(self, detail: str = "") -> None:
        self.detail = detail
        super().__init__(self.PUBLIC)

    def __str__(self) -> str:
        return self.PUBLIC


class Tampered(_Uniform):
    """The ciphertext, header, or associated data does not authenticate."""

    PUBLIC = (
        "envelope does not authenticate: it was truncated or rewritten, or it was written "
        "under a different key, and those are not distinguishable from outside the protocol"
    )


class Replay(_Uniform):
    """A record that was already accepted, offered again."""

    PUBLIC = (
        "record is not acceptable for this stream: it was seen before, or it is older than "
        "the position this stream has already accepted"
    )


class OutOfOrder(_Uniform):
    """A record older than the high-water mark for its stream."""

    PUBLIC = (
        "record is not acceptable for this stream: it was seen before, or it is older than "
        "the position this stream has already accepted"
    )


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


def encrypt(
    ring: KeyRing,
    plaintext: bytes,
    aad: bytes = b"",
    nonce: Optional[bytes] = None,
    backend: bytes = DEFAULT_BACKEND,
) -> bytes:
    """Encrypt and authenticate. The AAD is the context: asset, epoch, sequence.

    Callers should put the record's identity and position in the AAD. Without it the
    ciphertext is authentic but anonymous, which lets an attacker move a valid record into
    a place where it means something else.
    """
    nonce = os.urandom(NONCE_LEN) if nonce is None else nonce
    if len(nonce) != NONCE_LEN:
        raise ValueError(f"nonce must be {NONCE_LEN} bytes")
    header = VERSION + backend + nonce
    if backend == BACKEND_GCM:
        # GCM authenticates the header through the AAD, so the version, backend byte, and
        # nonce are covered without a separate MAC pass over them.
        sealed = aesgcm.encrypt(ring.subkey(PAYLOAD_PURPOSE).material, nonce, plaintext, header + aad)
        return header + sealed
    if backend == BACKEND_STDLIB:
        ciphertext = bytes(a ^ b for a, b in zip(plaintext, _keystream(ring, nonce, len(plaintext))))
        return header + ciphertext + _tag(ring, header, aad, ciphertext)
    raise ValueError(f"unknown backend {backend!r}")


@dataclass(frozen=True)
class EnvelopeInfo:
    """What a reader can learn without a key, which is what an attacker sees."""

    backend: str
    nonce: bytes
    ciphertext_length: int
    tag_length: int


BACKEND_NAMES = {BACKEND_STDLIB: "hmac-ctr-etm", BACKEND_GCM: "aes-256-gcm"}
BACKEND_TAG_LEN = {BACKEND_STDLIB: TAG_LEN, BACKEND_GCM: GCM_TAG_LEN}


def peek(blob: bytes) -> EnvelopeInfo:
    """Read the public shape of an envelope, or refuse with one uniform answer.

    The minimum length is per backend, because the two tag lengths differ: a 40-byte
    legacy envelope is structurally short, and the check used to admit it by testing
    against the GCM tag length. What came next was a slice that mixed tag bytes into the
    ciphertext, which failed authentication for the wrong reason and said so.
    """
    if len(blob) < HEADER_LEN:
        raise Tampered(f"{len(blob)} bytes cannot hold a {HEADER_LEN}-byte header")
    backend_id = blob[3:4]
    tag_len = BACKEND_TAG_LEN.get(backend_id)
    if blob[:3] != VERSION:
        raise Tampered(f"unknown envelope version {blob[:3]!r}")
    if tag_len is None:
        raise Tampered(f"unknown backend {backend_id!r}")
    if len(blob) < HEADER_LEN + tag_len:
        raise Tampered(f"{len(blob)} bytes cannot hold a header and a {tag_len}-byte tag")
    return EnvelopeInfo(
        backend=BACKEND_NAMES[backend_id],
        nonce=blob[4:HEADER_LEN],
        ciphertext_length=len(blob) - HEADER_LEN - tag_len,
        tag_length=tag_len,
    )


def decrypt(ring: KeyRing, blob: bytes, aad: bytes = b"") -> bytes:
    """Authenticate first, decrypt second. Never the other way round."""
    info = peek(blob)  # raises Tampered on a truncated, mis-versioned, or unknown envelope
    header = blob[:HEADER_LEN]
    if blob[3:4] == BACKEND_GCM:
        try:
            return aesgcm.decrypt(ring.subkey(PAYLOAD_PURPOSE).material, info.nonce, blob[HEADER_LEN:], header + aad)
        except aesgcm.AuthenticationError:
            raise Tampered(
                "ciphertext, header, or associated data does not authenticate: this envelope was "
                "modified, or it was encrypted under a different key, and the two are not "
                "distinguishable from inside the protocol"
            ) from None
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
        # Both branches return the same sentence. The distinction is real and the operator
        # needs it, so it lives in `.detail`; the caller is what decides whether that detail
        # reaches a log or a network response, and it must be the former.
        if (stream, seq) in self._seen:
            raise Replay(f"replay of {stream}/{seq}: the same envelope was offered twice")
        high = self._high.get(stream)
        if high is not None and seq <= high:
            raise OutOfOrder(
                f"{stream}/{seq} arrives below the high-water mark {high}: authentic, but in the past, "
                "which is how a deletion is hidden"
            )
        self._seen.add((stream, seq))
        self._high[stream] = seq

    def high_water(self, stream: str) -> Optional[int]:
        return self._high.get(stream)

    def snapshot(self) -> Dict[str, int]:
        return dict(self._high)
