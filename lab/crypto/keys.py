"""Key protection: one master secret, purpose-separated subkeys, and an audit of custody.

The first honest sentence about key protection is that software cannot provide it. If the
attacker has root on the machine holding the key, they have the key, and every guarantee
downstream becomes a statement about a period that has already ended. What software *can*
do is make the theft expensive, make the separation real, and make the custody visible:

- derive one subkey per purpose, so compromising the transport key does not let an attacker
  forge a source seal, and possessing the ledger key does not let them read payloads
- never let the master key travel with the data it protects
- refuse the key placements that quietly make the whole chain decorative: world-readable
  key files, keys inside the watched tree, keys in the environment, one key for everything
- keep key age visible, because an unrotated key is an unbounded exposure window

Derivation is HKDF-SHA256 (RFC 5869). The suite checks it against the RFC's own test
vectors rather than against itself.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import pathlib
import stat
from dataclasses import dataclass
from typing import Dict, Iterable, Optional, Sequence

from lab.crypto.model import KEY_PROTECTION, Issue, TrustReport

SALT = b"nullwitness-hkdf-v1"
MIN_MASTER_BYTES = 32
DEFAULT_ROTATION_DAYS = 90.0


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt or b"\x00" * 32, ikm, hashlib.sha256).digest()


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    if length > 255 * 32:
        raise ValueError("HKDF-Expand is limited to 255 blocks of 32 bytes")
    out = b""
    block = b""
    counter = 1
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        out += block
        counter += 1
    return out[:length]


def hkdf(ikm: bytes, info: bytes, length: int, salt: bytes = SALT) -> bytes:
    return hkdf_expand(hkdf_extract(salt, ikm), info, length)


@dataclass(frozen=True)
class SubKey:
    """A purpose-bound key. Its repr is redacted on purpose: keys end up in logs."""

    purpose: str
    material: bytes
    generation: int = 0

    def __repr__(self) -> str:  # pragma: no cover - trivial, but the redaction matters
        return f"SubKey(purpose={self.purpose!r}, generation={self.generation}, material=<redacted>)"

    __str__ = __repr__


class KeyRing:
    """One master secret, many purpose-bound subkeys, no key reuse across purposes."""

    def __init__(self, master: bytes, salt: bytes = SALT, generation: int = 0):
        if not master:
            raise ValueError("a key ring needs a master secret")
        if len(master) < MIN_MASTER_BYTES:
            raise ValueError(
                f"master secret is {len(master)} bytes; {MIN_MASTER_BYTES} is the floor, "
                "because a short master is a short password"
            )
        self._master = bytes(master)
        self._salt = salt
        self.generation = generation
        self._cache: Dict[tuple, SubKey] = {}

    def __repr__(self) -> str:
        return f"KeyRing(generation={self.generation}, master=<redacted>)"

    __str__ = __repr__

    def subkey(self, purpose: str, context: bytes = b"") -> SubKey:
        """Derive a subkey for a purpose. Same purpose, same key: callers rely on that."""
        if not purpose:
            raise ValueError("a subkey without a purpose defeats the point of subkeys")
        cache_key = (purpose, context, self.generation)
        if cache_key not in self._cache:
            info = b"|".join(
                [b"nullwitness-subkey", purpose.encode("utf-8"), context, str(self.generation).encode("ascii")]
            )
            self._cache[cache_key] = SubKey(
                purpose=purpose, material=hkdf(self._master, info, 32, self._salt), generation=self.generation
            )
        return self._cache[cache_key]

    def rotated(self) -> "KeyRing":
        """Next generation. Old subkeys stay derivable from the old ring, which is how a
        rotation keeps historical records readable without keeping the old master."""
        return KeyRing(self._master, self._salt, generation=self.generation + 1)

    def master_digest(self) -> str:
        """A non-reversible fingerprint for audits and off-box attestation."""
        return hkdf(self._master, b"nullwitness-master-fingerprint", 16, self._salt).hex()


def write_key_file(path: pathlib.Path, master: bytes) -> pathlib.Path:
    """Create a key file with 0600 from the first byte, not after the fact.

    os.open with the mode set at creation is the only way to avoid a window where the key
    exists with the umask's permissions. Then chmod explicitly, because open() honours the
    umask and the default umask is not the operator's promise.
    """
    path = pathlib.Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    handle = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(handle, master)
    finally:
        os.close(handle)
    os.chmod(path, 0o600)
    return path


def audit_custody(
    key_path: Optional[pathlib.Path],
    master: Optional[bytes],
    data_root: Optional[pathlib.Path] = None,
    max_age_days: float = DEFAULT_ROTATION_DAYS,
    now: Optional[float] = None,
    environment_names: Sequence[str] = ("NULLWITNESS_KEY", "NULLWITNESS_MASTER_KEY"),
) -> TrustReport:
    """Answer "can an attacker obtain the keys?" as a list of specific ways they can.

    This produces findings, not a verdict. `key_in_environment` on a laptop running a demo
    is not the same risk as on a shared build host, and only the operator knows which one
    they are looking at.
    """
    report = TrustReport()

    if master is not None and len(master) < MIN_MASTER_BYTES:
        report.add(
            Issue(
                KEY_PROTECTION,
                "key_material_weak",
                "high",
                f"master secret is {len(master)} bytes; below {MIN_MASTER_BYTES} it is a password, "
                "and guessing a password is not a cryptanalytic problem",
            )
        )

    for name in environment_names:
        if os.environ.get(name):
            report.add(
                Issue(
                    KEY_PROTECTION,
                    "key_in_environment",
                    "high",
                    f"{name} holds key material in the environment: every child process and every "
                    "core dump inherits it, and ps on some systems shows it",
                )
            )

    if key_path is None:
        report.skip(KEY_PROTECTION, "no key path supplied, so file custody was not examined")
        return report

    key_path = pathlib.Path(key_path)
    if not key_path.exists():
        report.skip(KEY_PROTECTION, f"{key_path.name} does not exist, so file custody was not examined")
        return report

    mode = stat.S_IMODE(key_path.stat().st_mode)
    if mode & 0o077:
        report.add(
            Issue(
                KEY_PROTECTION,
                "key_permissions_loose",
                "high",
                f"{key_path.name} is mode {mode:04o}: group or other can read the key, which makes "
                "every downstream guarantee a claim about a host you do not control",
            )
        )

    if data_root is not None:
        data_root = pathlib.Path(data_root)
        try:
            key_path.resolve().relative_to(data_root.resolve())
        except ValueError:
            pass
        else:
            report.add(
                Issue(
                    KEY_PROTECTION,
                    "key_colocated_with_data",
                    "high",
                    f"{key_path.name} lives inside the tree it protects ({data_root.name}): one copy "
                    "of one directory hands an attacker both the ciphertext and the key",
                )
            )

    if now is not None:
        age_days = max(0.0, (now - key_path.stat().st_mtime) / 86400.0)
        if age_days > max_age_days:
            report.add(
                Issue(
                    KEY_PROTECTION,
                    "key_not_rotated",
                    "medium",
                    f"{key_path.name} has not changed in {age_days:.0f} days (policy {max_age_days:.0f}): "
                    "the exposure window is the age of the key, not the age of the incident",
                )
            )

    if not report.issues:
        report.ok(KEY_PROTECTION)
    return report


def find_copies(master: bytes, roots: Iterable[pathlib.Path], limit: int = 1 << 20) -> list:
    """Where else the master secret exists. One copy is the point; two is a leak."""
    found = []
    for root in roots:
        root = pathlib.Path(root)
        if not root.exists():
            continue
        for path in sorted(root.rglob("*")):
            if not path.is_file() or path.stat().st_size > limit:
                continue
            if ".git" in path.parts:
                continue
            try:
                if master in path.read_bytes():
                    found.append(path)
            except OSError:
                continue
    return found
