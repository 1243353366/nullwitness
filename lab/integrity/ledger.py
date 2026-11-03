"""A tamper-evident, append-only ledger for evidence checkpoints.

The point of this module is narrower than "logging". A log you can edit is not
evidence. This ledger is built so that three specific operations are detectable after
the fact:

- **truncation:** dropping the tail of the file. Detected with an external anchor that
  records the head sequence and MAC, stored separately from the ledger body.
- **reordering or splicing:** inserting, removing, or moving an entry. Detected because
  every entry carries the MAC of its predecessor.
- **forgery:** writing a plausible-looking entry without the HMAC key. Detected on
  verify, since the MAC covers sequence, timestamp, predecessor, and payload.

Honest limit: if an attacker controls both the ledger body and the anchor, and neither
leaves the machine, they can roll both back to a consistent earlier state. The anchor
has to go somewhere else (append-only object storage, a second host, a print-out, a
timestamping service). `lab/INTEGRITY.md` says this plainly, and the demo shows the
failure so nobody assumes otherwise.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import pathlib
from dataclasses import dataclass
from typing import Dict, List, Optional

MAC_CHARS = 32


@dataclass(frozen=True)
class Entry:
    seq: int
    ts: float
    prev: str
    payload: Dict[str, object]
    mac: str

    def as_line(self) -> str:
        return json.dumps(
            {"seq": self.seq, "ts": self.ts, "prev": self.prev, "payload": self.payload, "mac": self.mac},
            sort_keys=True,
        )


def compute_mac(key: bytes, seq: int, ts: float, prev: str, payload: Dict[str, object]) -> str:
    body = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    message = f"{seq}|{ts:.6f}|{prev}|{body}".encode("utf-8")
    return hmac.new(key, message, hashlib.sha256).hexdigest()[:MAC_CHARS]


class Ledger:
    """Append-only chain. The anchor file is the external witness of the head."""

    GENESIS = "0" * MAC_CHARS

    def __init__(self, path: pathlib.Path, key: bytes):
        if not key:
            raise ValueError("the ledger needs an HMAC key; an unkeyed chain is decoration")
        self.path = pathlib.Path(path)
        self.key = key
        self.anchor_path = self.path.with_name(self.path.name + ".head")

    # ------------------------------------------------------------------ reading

    def entries(self) -> List[Entry]:
        if not self.path.is_file():
            return []
        out: List[Entry] = []
        for line in self.path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            raw = json.loads(line)
            out.append(
                Entry(
                    seq=int(raw["seq"]),
                    ts=float(raw["ts"]),
                    prev=str(raw["prev"]),
                    payload=dict(raw["payload"]),
                    mac=str(raw["mac"]),
                )
            )
        return out

    def anchor(self) -> Optional[Dict[str, object]]:
        if not self.anchor_path.is_file():
            return None
        return json.loads(self.anchor_path.read_text(encoding="utf-8"))

    # ------------------------------------------------------------------ writing

    def append(self, payload: Dict[str, object], ts: float) -> Entry:
        existing = self.entries()
        seq = (existing[-1].seq + 1) if existing else 0
        prev = existing[-1].mac if existing else self.GENESIS
        mac = compute_mac(self.key, seq, ts, prev, payload)
        entry = Entry(seq=seq, ts=ts, prev=prev, payload=payload, mac=mac)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(entry.as_line() + "\n")
        self._write_anchor(entry)
        return entry

    def _write_anchor(self, entry: Entry) -> None:
        self.anchor_path.write_text(
            json.dumps({"seq": entry.seq, "mac": entry.mac, "ts": entry.ts}, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    # --------------------------------------------------------------- verifying

    def verify(self) -> List[str]:
        """Return problem codes, most severe first. Empty list means the chain holds."""
        entries = self.entries()
        anchor = self.anchor()
        problems: List[str] = []

        if anchor is None and entries:
            problems.append("anchor_missing")
        if not entries:
            return problems or ["empty"]

        expected_prev = self.GENESIS
        expected_seq = 0
        previous_ts = float("-inf")
        for entry in entries:
            if entry.seq != expected_seq:
                problems.append("gap" if entry.seq > expected_seq else "reordered")
            if entry.prev != expected_prev:
                problems.append("reordered")
            if compute_mac(self.key, entry.seq, entry.ts, entry.prev, entry.payload) != entry.mac:
                problems.append("forged")
            if entry.ts < previous_ts:
                problems.append("time_regression")
            expected_prev = entry.mac
            expected_seq = entry.seq + 1
            previous_ts = entry.ts

        if anchor is not None:
            if int(anchor["seq"]) > entries[-1].seq:
                problems.append("truncated")
            elif int(anchor["seq"]) == entries[-1].seq and str(anchor["mac"]) != entries[-1].mac:
                problems.append("truncated")

        # Stable, deduplicated, deterministic order.
        order = ["forged", "reordered", "truncated", "gap", "time_regression", "anchor_missing", "empty"]
        return sorted(set(problems), key=order.index)
