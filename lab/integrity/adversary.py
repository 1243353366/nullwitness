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


# --------------------------------------------------------------------- aware side
#
# The functions below belong to a different character than the ones above: an adversary
# who has read this repository. Each one is chosen because it defeats a check the base
# monitor actually performs, not because it is clever. They exist so the counter layer in
# `lab.integrity.counterforensics` is tested against the technique it claims to catch.


def overwrite_same_size(root: pathlib.Path, rel: str, text: str) -> None:
    """Rewrite a file's content without changing its length.

    Truncation shrinks, appends grow, and both are easy to notice. An in-place overwrite
    padded back to the original length keeps the size channel quiet and leaves the digest
    as the only witness.
    """
    path = pathlib.Path(root) / rel
    size = path.stat().st_size
    body = text.encode("utf-8")
    path.write_bytes((body + b" " * size)[:size])


def restore_from_copy(root: pathlib.Path, rel: str, settle: float = 0.01) -> None:
    """Delete a file's content and put the identical bytes back.

    Digest comparison sees nothing, because the bytes match. What it cannot hide is ctime,
    which userland cannot set: writing to the inode moves it. The settle delay exists
    because this is the one detector that depends on ordering rather than on a large
    difference, and a filesystem with coarse timestamps should not be confused with a
    clean host.
    """
    import time

    path = pathlib.Path(root) / rel
    raw = path.read_bytes()
    mtime = path.stat().st_mtime
    time.sleep(settle)
    path.write_bytes(b"")
    path.write_bytes(raw)
    os.utime(path, (mtime, mtime))


def launder_rotation(root: pathlib.Path, rel: str, filler_from: str, suffix: str = ".1") -> None:
    """Make a deletion look like a rotation by rotating somebody else into the slot.

    The base monitor forgives a vanished file when a same-digest copy turns up under a
    rotation suffix. Satisfying the shape of that rule without satisfying its content is
    the whole trick, and the counter check is whether the rotated slot really holds what
    the original held.
    """
    root = pathlib.Path(root)
    (root / filler_from).rename(root / (rel + suffix))
    (root / rel).unlink()


def scatter(root: pathlib.Path, count: int, prefix: str = "evidence/noise-") -> list:
    """Create a burst of low-value changes around whatever else is happening."""
    made = []
    for index in range(count):
        rel = f"{prefix}{index}.log"
        (pathlib.Path(root) / rel).write_text(f"heartbeat {index}\n", encoding="utf-8")
        made.append(rel)
    return made


def plant_shadow_ledger(monitor: Monitor, name: str = "checkpoints.jsonl.orig") -> pathlib.Path:
    """Write a second, clean-looking chain beside the real one.

    Forging the real chain needs the key. Building a plausible alternative does not: a
    reader who opens the wrong file, or a defender who keeps the friendlier one, is
    exactly the audience. The entries are deliberately well formed, which is what makes
    them detectable as a shape that does not belong.
    """
    entries = monitor.ledger.entries()
    path = monitor.ledger.path.with_name(name)
    lines = []
    for entry in entries[:1]:
        lines.append(
            json.dumps(
                {"seq": entry.seq, "ts": entry.ts, "prev": "0" * 32, "payload": {"files": {}}, "mac": "a" * 32},
                sort_keys=True,
            )
        )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def copy_key(monitor: Monitor, dest_rel: str) -> pathlib.Path:
    """Copy the HMAC key into the watched tree.

    The cheapest way to defeat a hash chain is to own the key. This does not exfiltrate
    anything: it writes the key where the key search will find it, so the detector has a
    real artefact to find rather than a fixture.
    """
    path = monitor.root / dest_rel
    path.write_bytes(monitor.ledger.key)
    return path


def creep_clock(monitor: Monitor, base_wall: float, base_monotonic: float, steps: int = 6, drift: float = 0.9, interval: float = 60.0) -> float:
    """Move the wall clock by less than tolerance on every checkpoint.

    A per-step comparison allows a few seconds of jitter. Walking the clock in sub-tolerance
    steps means no single step looks wrong while the timeline slides. Returns the final
    wall timestamp so the caller verifies at the same moment.
    """
    wall = base_wall
    for step in range(1, steps + 1):
        wall = base_wall + step * interval + step * drift
        monitor.checkpoint(now=wall, monotonic=base_monotonic + step * interval)
    return wall
