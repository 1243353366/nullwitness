"""Hash the envelopes into the ledger, so substitution at rest needs no key to catch.

Encryption answers "can it be read". The ledger of digests answers a different question:
"is this the envelope that was written". Those are worth separating, for one practical
reason. Verification of a ciphertext needs the key, and the key is exactly what an operator
may not want on the machine doing the checking: an archive verifier, a backup scanner, or a
colleague confirming a file has not changed should not need decryption rights to do it.

So each envelope is hashed at write time and the digest goes into the HMAC-chained ledger from
`lab/integrity/ledger.py`. What that buys:

- **substitution** is caught without decrypting: same length, same key, different record, and
  the digest no longer matches. A re-encrypted forgery is caught here too, which is the one
  thing the ciphertext tag cannot catch when the attacker holds the payload key.
- **removal** is caught as a ledger entry with no envelope behind it, because the ledger
  records what was written, not what survived.
- **ledger rewriting** is caught by the chain: every entry carries the MAC of its predecessor.

The limit is the limit the ledger already has, and it is worth restating rather than
inheriting quietly: an attacker with the ledger key, the anchor, and the machine can roll both
back to a consistent earlier state. The anchor has to leave the host. `lab/INTEGRITY.md`
carries that argument; this module does not improve on it.
"""

from __future__ import annotations

import hashlib
import pathlib
from typing import Dict, List, Optional

from lab.crypto.model import AUTHENTICATED, Issue, TrustReport
from lab.integrity.ledger import Ledger

PAYLOAD_KEY_NAME = "sha256"


def digest(blob: bytes) -> str:
    """The hash. Named so the tests and the ledger agree on one function."""
    return hashlib.sha256(blob).hexdigest()


class Archive:
    """Envelopes plus the digest chain that remembers which envelopes existed."""

    def __init__(self, ledger_path: pathlib.Path, key: bytes, store: Optional[pathlib.Path] = None):
        self.ledger = Ledger(pathlib.Path(ledger_path), key)
        self.store_dir = pathlib.Path(store) if store is not None else None

    def store(self, partition, now: float) -> str:
        """Record an envelope and its digest. Returns the digest it recorded."""
        recorded = digest(partition.blob)
        path = None
        if self.store_dir is not None:
            target = self.store_dir / partition.stream.replace("/", "_")
            target.mkdir(parents=True, exist_ok=True)
            path = target / f"{partition.seq:08d}.env"
            path.write_bytes(partition.blob)
        payload: Dict[str, object] = {
            "kind": "envelope",
            "stream": partition.stream,
            "seq": partition.seq,
            "record_id": partition.record_id,
            "digest": recorded,
            "bytes": len(partition.blob),
        }
        if path is not None:
            payload["path"] = path.name
        self.ledger.append(payload, now)
        return recorded

    def recorded(self) -> Dict[tuple, Dict[str, object]]:
        out: Dict[tuple, Dict[str, object]] = {}
        for entry in self.ledger.entries():
            payload = entry.payload
            if payload.get("kind") != "envelope":
                continue
            out[(payload.get("stream"), payload.get("seq"))] = payload
        return out

    def verify(self, partitions, ledger_issues: Optional[List[str]] = None) -> TrustReport:
        """Compare what is on disk against what the ledger says was written."""
        report = TrustReport()
        problems = ledger_issues if ledger_issues is not None else self.ledger.verify()
        for problem in problems:
            report.add(
                Issue(
                    AUTHENTICATED,
                    "digest_ledger_tampered",
                    "high",
                    f"the digest ledger does not verify ({problem}): which envelopes existed is no longer a "
                    "trustworthy statement, so every comparison below is suspect",
                )
            )

        recorded = self.recorded()
        present = set()
        for partition in partitions:
            key = (partition.stream, partition.seq)
            present.add(key)
            entry = recorded.get(key)
            if entry is None:
                report.add(
                    Issue(
                        AUTHENTICATED,
                        "envelope_unrecorded",
                        "medium",
                        f"{partition.stream}/{partition.seq} exists but the ledger never recorded writing it: "
                        "either it was added after the fact, or the write was not logged",
                    )
                )
                continue
            if entry.get("digest") != digest(partition.blob):
                report.add(
                    Issue(
                        AUTHENTICATED,
                        "envelope_substituted",
                        "high",
                        f"{partition.stream}/{partition.seq} hashes to {digest(partition.blob)[:16]} but the ledger "
                        f"recorded {str(entry.get('digest'))[:16]}: the envelope was replaced, and this check needs no "
                        "decryption key to notice",
                    )
                )

        for key in recorded:
            if key not in present:
                report.add(
                    Issue(
                        AUTHENTICATED,
                        "envelope_missing",
                        "high",
                        f"the ledger recorded {key[0]}/{key[1]} but no envelope with that identity is present: records "
                        "were removed from the archive, and the surviving ones are all intact",
                    )
                )

        if not report.issues:
            report.ok(AUTHENTICATED)
        return report


def hash_partitions(partitions) -> Dict[str, str]:
    """The cheap thing: a digest map, for callers who do not want a ledger yet."""
    return {f"{partition.stream}/{partition.seq}": digest(partition.blob) for partition in partitions}
