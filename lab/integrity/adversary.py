"""Scripted tampering, used by the demo and the tests.

These functions are the adversary side of `lab.integrity.monitor`: each one performs a
concrete act of destruction, suppression, manipulation, or fabrication against a
workspace the demo owns in a temporary directory. They exist so the detectors are
exercised against real file operations rather than against hand-written fixtures
asserting a property they assume.

Scope note: this is not a toolkit for use elsewhere. Every function operates on a path
the caller passes in, changes nothing outside it, needs no privileges, and is written to
be executed only in the demo's throwaway directory. The interesting artefact is the
detector, not the mutator.
"""

from __future__ import annotations

import json
import os
import pathlib
from typing import List, Optional

from lab.integrity.ledger import Ledger
from lab.integrity.monitor import Monitor


def delete_file(root: pathlib.Path, rel: str) -> None:
    (pathlib.Path(root) / rel).unlink()


def truncate_file(root: pathlib.Path, rel: str, keep: int = 0) -> None:
    path = pathlib.Path(root) / rel
    raw = path.read_bytes()
    path.write_bytes(raw[:keep])


def backdate_edit(root: pathlib.Path, rel: str, text: str, seconds_older: float = 3600.0) -> None:
    """Rewrite content, then set mtime into the past. ctime cannot be forged in
    userland, which is exactly why the metadata channel is worth keeping."""
    path = pathlib.Path(root) / rel
    original_mtime = path.stat().st_mtime
    path.write_text(text, encoding="utf-8")
    os.utime(path, (original_mtime - seconds_older, original_mtime - seconds_older))


def append_legitimately(root: pathlib.Path, rel: str, text: str) -> None:
    with (pathlib.Path(root) / rel).open("a", encoding="utf-8") as handle:
        handle.write(text)


def rotate(root: pathlib.Path, rel: str, suffix: str = ".1") -> None:
    path = pathlib.Path(root) / rel
    path.rename(path.with_name(path.name + suffix))


def forge_entry(monitor: Monitor) -> None:
    """Write a plausible entry without the HMAC key."""
    entries = monitor.ledger.entries()
    last = entries[-1]
    fake = {
        "seq": last.seq + 1,
        "ts": last.ts + 60.0,
        "prev": last.mac,
        "payload": {
            "files": dict(last.payload.get("files", {})),
            "clock": {
                "wall": last.ts + 60.0,
                "monotonic": float(dict(last.payload.get("clock", {})).get("monotonic", last.ts)) + 60.0,
            },
            "status": {"agent_running": True},
        },
        "mac": "0" * 32,
    }
    with monitor.ledger.path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(fake, sort_keys=True) + "\n")


def rollback_body(monitor: Monitor, keep: int) -> None:
    """Drop the tail of the ledger but leave the external anchor alone."""
    lines = monitor.ledger.path.read_text(encoding="utf-8").splitlines(keepends=True)
    monitor.ledger.path.write_text("".join(lines[:keep]), encoding="utf-8")


def rollback_body_and_anchor(monitor: Monitor, keep: int) -> None:
    """Drop the tail and rewrite the anchor to match.

    This is the documented failure case. If the attacker can write both files and the
    anchor never left the host, the rollback is internally consistent and this monitor
    cannot see it. The mitigation is architectural: ship the anchor off-box.
    """
    rollback_body(monitor, keep)
    entries = monitor.ledger.entries()
    if not entries:
        monitor.ledger.anchor_path.unlink(missing_ok=True)
        return
    head = entries[-1]
    monitor.ledger.anchor_path.write_text(
        json.dumps({"seq": head.seq, "mac": head.mac, "ts": head.ts}, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def replace_with_copy(root: pathlib.Path, rel: str) -> None:
    """Same bytes, new inode: a restore-from-elsewhere rather than an edit."""
    path = pathlib.Path(root) / rel
    raw = path.read_bytes()
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_bytes(raw)
    os.replace(tmp, path)


def silence(monitor: Monitor, workspace_activity: Optional[List[str]] = None) -> None:
    """Collection stops while the endpoint keeps writing.

    There is nothing to execute here: suppression is an absence of checkpoints. The
    helper exists so the demo reads in one direction, and so the docstring can say that
    the detector is looking for a hole, not for a process.
    """
    return None


__all__ = [
    "delete_file",
    "truncate_file",
    "backdate_edit",
    "append_legitimately",
    "rotate",
    "forge_entry",
    "rollback_body",
    "rollback_body_and_anchor",
    "replace_with_copy",
    "silence",
    "Ledger",
]
