"""Counter-anti-forensics: catching the adversary who read this repository.

The base monitor in `lab.integrity.monitor` answers a naive attacker: someone deleting,
truncating, or editing evidence. That attacker is caught because the channels disagree.

This module assumes a different attacker. One who has read the playbook, knows the
deception is symmetric, and uses the same ideas against the monitor:

- keep the size the same, so size-based sanity checks see nothing
- put the bytes back afterwards, so the manifest digest matches again
- launder a deletion as a log rotation, so rotation handling covers it
- touch nothing that looks like a decoy, so the canaries stay quiet
- bury one real change under a burst of harmless ones, so attention is diluted
- write a second ledger, so a reader can be pointed at the friendlier history
- steal the HMAC key, so the chain becomes decorative
- move the clock in steps too small to trip a per-step tolerance

Every one of those is detectable, and none of them is detectable by looking harder at a
single channel. They share a structure: the technique conserves the quantity the obvious
check measures, and disturbs something adjacent that the check does not measure. Same
size, different bytes. Same digest, later ctime. Same rotation pattern, different content
in the rotated slot. Same clock, different rate. So each detector here is a statement
about which adjacent quantity cannot be conserved at the same time, and the report says
which pair of facts is in contradiction.

Two things this module is not:

- It is not an accusation engine. It produces evidence that a *host* was handled with
  knowledge of the monitor. Correlating that to a person is out of scope here and stays
  out of scope; that is a human process with its own rules.
- It is not a countermeasure. Nothing here disables an attacker's tooling, plants
  anything that could be mistaken for their work, or contacts anything off-box. Detection
  only, on assets the operator nominates.

The honest limit is in `lab/COUNTER-ANTI-FORENSICS.md`: an adversary who knows the decoy
list and only edits evidence that is not being watched is invisible to this, because
there is nothing to contradict. Coverage is the only answer to that, not cleverness.
"""

from __future__ import annotations

import hashlib
import json
import math
import pathlib
import statistics
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Set

from lab.integrity.monitor import Finding, FileState, Monitor, Report

# Severity for signals that only this layer can raise. Anything absent is graded by the
# base rules in lab.integrity.monitor.grade, so the two layers agree on what "high" means.
SEVERITY = {
    "shadow_ledger": "high",
    "key_material_copy": "high",
    "content_substitution": "medium",
    "restored_from_copy": "medium",
    "rotation_laundering": "medium",
    "clock_creep": "medium",
    "planted_artifact": "medium",
    "churn_dilution": "low",
    "canary_avoidance": "low",
}

KIND = {
    "shadow_ledger": "fabrication",
    "key_material_copy": "manipulation",
    "content_substitution": "manipulation",
    "restored_from_copy": "manipulation",
    "rotation_laundering": "destruction",
    "clock_creep": "manipulation",
    "planted_artifact": "fabrication",
    "churn_dilution": "suppression",
    "canary_avoidance": "evasion",
}

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}


@dataclass(frozen=True)
class Policy:
    """Thresholds for the statistical detectors.

    These are the knobs an operator tunes against their own baseline. Defaults are
    deliberately conservative: a low-severity lead that is wrong costs an investigation,
    and a high-severity finding that is wrong costs the monitor's credibility.
    """

    max_rotation_chain: int = 3
    churn_factor: float = 4.0
    churn_minimum: int = 6
    churn_history: int = 8
    clock_creep_budget: float = 2.0
    mtime_exact_tolerance: float = 1e-3
    ctime_move_threshold: float = 1e-3
    max_scan_bytes: int = 1 << 20


def _finding(
    signal: str,
    detail: str,
    channels: Sequence[str],
    subjects: Optional[Sequence[str]] = None,
    severity: Optional[str] = None,
) -> Finding:
    return Finding(
        kind=KIND.get(signal, "manipulation"),
        signal=signal,
        severity=severity or SEVERITY.get(signal, "low"),
        channels=list(channels),
        detail=detail,
        subjects=list(subjects or []),
    )


# --------------------------------------------------------------------- detectors
#
# Each function is pure: it takes recorded facts and returns a Finding or None. That is
# what lets the suite exercise a detector against a hand-built state instead of having to
# stage a real attack for every edge case.


def content_substitution(before: FileState, after: FileState) -> Optional[Finding]:
    """Same length, different bytes: an overwrite in place.

    The size check exists because truncation usually shrinks a file. Overwriting the
    region that mattered, then padding to the original length, conserves the size and
    leaves the manifest digest as the only witness. Naming it a substitution rather than
    a modification matters: appends are the normal traffic, in-place rewrites are not.
    """
    if before.size != after.size or before.digest == after.digest:
        return None
    return _finding(
        "content_substitution",
        (
            f"{after.path} is still {after.size} bytes but its content changed: "
            "an in-place overwrite that preserved length, not an append"
        ),
        ["manifest", "metadata"],
        [after.path],
    )


def restored_from_copy(before: FileState, after: FileState, policy: Policy = Policy()) -> Optional[Finding]:
    """Identical bytes, but the inode changed underneath them.

    Deleting evidence and putting it back defeats digest comparison completely: the
    manifest and the checkpoint agree, because they are looking at the same bytes. The
    copy that does the restoring also has to preserve mtime to stay invisible, and mtime
    is the one timestamp userland can set. ctime is not settable, so the restoration has
    to move it.

    Legitimate causes exist and are common: a backup restore, a package upgrade that
    reinstalls an unchanged config, `cp -p`. So this is a lead that needs the operator to
    say "was anything restored on this host, and by whom", not a verdict.
    """
    if before.digest != after.digest:
        return None
    mtime_held = abs(after.mtime - before.mtime) <= policy.mtime_exact_tolerance
    inode_moved = after.inode != before.inode
    ctime_moved = after.ctime > before.ctime + policy.ctime_move_threshold
    if not ctime_moved:
        return None
    if not (mtime_held or inode_moved):
        return None
    how = "new inode" if inode_moved else "same inode"
    return _finding(
        "restored_from_copy",
        (
            f"{after.path} holds exactly the checkpointed bytes, yet its ctime moved "
            f"({before.ctime:.3f} -> {after.ctime:.3f}) with mtime {'held' if mtime_held else 'changed'} "
            f"and {how}: the file was written after the checkpoint without changing what it says"
        ),
        ["manifest", "metadata"],
        [after.path],
    )


def rotation_laundering(
    rel: str,
    before: FileState,
    current: Dict[str, FileState],
    suffixes: Sequence[str] = (".1", ".gz", ".old", ".bak"),
    max_chain: int = 3,
) -> Optional[Finding]:
    """A disappearance dressed as log rotation.

    Rotation is real and frequent, so the base monitor forgives a vanished file when a
    same-digest copy appears under a rotation suffix. The abuse is obvious once stated:
    rotate a *different* file into that slot, delete the original, and the forgiveness
    rule covers the deletion. The check that separates them is whether the rotated slot
    actually holds what the original held.
    """
    rotated = {name: state for name, state in current.items() if _is_rotation_of(rel, name, suffixes)}
    if not rotated:
        return None
    chain = [name for name in rotated if name[len(rel):].count(".") > max_chain]
    if any(state.digest == before.digest for state in rotated.values()):
        if chain:
            return _finding(
                "rotation_laundering",
                (
                    f"{rel} was rotated {max_chain}+ times in one window ({', '.join(sorted(rotated))}): "
                    "beyond the retention policy, which pushes earlier content out of reach"
                ),
                ["manifest"],
                [rel],
            )
        return None
    holder = sorted(rotated)[0]
    return _finding(
        "rotation_laundering",
        (
            f"{rel} disappeared and {holder} exists under a rotation suffix, but it does not hold "
            f"{rel}'s checkpointed content (recorded {before.digest[:12]}, found {rotated[holder].digest[:12]}): "
            "the rotation covers a deletion instead of recording one"
        ),
        ["manifest"],
        [rel, holder],
    )


def _is_rotation_of(rel: str, name: str, suffixes: Sequence[str]) -> bool:
    if name == rel or not name.startswith(rel):
        return False
    return name[len(rel):].startswith(tuple(suffixes))


def churn_dilution(changed: Sequence[str], history: Sequence[int], policy: Policy = Policy()) -> Optional[Finding]:
    """A burst of harmless changes around one that matters.

    Attention is a finite resource, and a report with forty entries is read like a report
    with none. The counter is to compare the volume against this host's own history rather
    than against a constant: a busy server is not an attacker, and a quiet one that
    suddenly churns is worth a look regardless of absolute numbers.
    """
    if len(changed) < policy.churn_minimum:
        return None
    baseline = statistics.median(history[-policy.churn_history:]) if history else 0
    if len(changed) < max(policy.churn_minimum, policy.churn_factor * max(baseline, 1)):
        return None
    return _finding(
        "churn_dilution",
        (
            f"{len(changed)} evidence files changed in one window against a median of {baseline:g} "
            "in prior windows: volume this far above the host's own baseline dilutes review "
            "and is worth reading in full before it is triaged"
        ),
        ["manifest", "metadata"],
        sorted(changed)[:8],
    )


def canary_avoidance(
    touched: Iterable[str],
    decoys: Iterable[str],
    tracked: Iterable[str],
    lead_below: float = 0.15,
    improbable_below: float = 0.02,
) -> Optional[Finding]:
    """Precision is the tell.

    A decoy only works once. Someone who has read the monitor's configuration knows which
    files are bait and can work around them, which is exactly what makes them visible
    here: an actor moving through a set of lookalike files who touches every real one and
    no decoy at all is behaving unlike an actor who cannot tell them apart.

    The number in the finding is the probability of that avoidance happening blind, from
    a hypergeometric count: choosing k of n files at random and landing entirely outside
    the decoys. Small numbers are interesting, not conclusive. A single lucky edit is not
    an incident, and the finding says so.
    """
    decoy_set = set(decoys)
    tracked_set = set(tracked)
    touched_set = set(touched) & tracked_set
    if not decoy_set or not touched_set:
        return None
    if touched_set & decoy_set:
        return None
    # Only files the monitor was already covering count. Files that merely appeared are
    # churn, and counting them would inflate the denominator until this arithmetic says
    # nothing at all.
    safe = tracked_set - decoy_set
    hits = touched_set - decoy_set
    if len(hits) < 2 or not hits <= safe:
        return None
    total, chosen = len(tracked_set), len(hits)
    if chosen > total or total == 0:
        return None
    try:
        blind = math.comb(len(safe), chosen) / math.comb(total, chosen)
    except (ValueError, ZeroDivisionError):
        blind = 0.0
    if blind > lead_below:
        return None
    severity = "medium" if blind <= improbable_below else "low"
    likelihood = f"a blind actor avoids the decoys {blind:.1%} of the time"
    return _finding(
        "canary_avoidance",
        (
            f"{len(hits)} evidence files changed and none of the {len(decoy_set)} decoys did; "
            f"{likelihood}. Precision this clean points at knowledge of the decoy list, "
            "which is a lead about who read the configuration, not proof of who edited"
        ),
        ["manifest", "metadata"],
        sorted(hits),
        severity=severity,
    )


def shadow_ledger(
    state_dir: pathlib.Path,
    real_ledger: pathlib.Path,
    real_anchor: Optional[pathlib.Path] = None,
) -> List[Finding]:
    """A second history in the same place.

    Forging the chain needs the key. Faking the *record* does not: drop a plausible
    ledger beside the real one and a reader who opens the wrong file sees a clean
    timeline. The giveaway is that a monitor's state directory should contain exactly the
    files the monitor wrote, so anything else shaped like a ledger or an anchor is either
    debris or a decoy aimed at whoever reads the evidence.
    """
    findings: List[Finding] = []
    state_dir = pathlib.Path(state_dir)
    if not state_dir.is_dir():
        return findings
    known = {pathlib.Path(real_ledger).resolve()}
    # The anchor the monitor writes sits beside the ledger under a derived name; it is
    # part of the real state, not a rival one.
    default_anchor = pathlib.Path(str(real_ledger) + ".head").resolve()
    known.add(pathlib.Path(real_anchor).resolve() if real_anchor is not None else default_anchor)
    for path in sorted(state_dir.iterdir()):
        if not path.is_file() or path.resolve() in known:
            continue
        if path.name.startswith("."):
            continue
        ledger_shaped = _looks_like_ledger(path)
        anchor_shaped = path.read_text(encoding="utf-8", errors="replace").strip().startswith("{") and path.suffix in {".head", ".anchor"}
        if ledger_shaped:
            findings.append(
                _finding(
                    "shadow_ledger",
                    (
                        f"{path.name} sits beside the real ledger and parses as a second chain: "
                        "a reader pointed at it would see a different history, so its presence "
                        "means someone built an alternative record"
                    ),
                    ["ledger"],
                    [path.name],
                )
            )
        elif anchor_shaped:
            findings.append(
                _finding(
                    "planted_artifact",
                    f"{path.name} is shaped like a ledger anchor but is not the one this monitor wrote",
                    ["ledger"],
                    [path.name],
                )
            )
    return findings


def _looks_like_ledger(path: pathlib.Path) -> bool:
    try:
        head = path.read_text(encoding="utf-8", errors="replace").splitlines()[:5]
    except OSError:
        return False
    if not head:
        return False
    try:
        first = json.loads(head[0])
    except (json.JSONDecodeError, IndexError):
        return False
    return isinstance(first, dict) and {"seq", "mac", "prev", "payload"} <= set(first)


def key_material_copy(key: bytes, root: pathlib.Path, policy: Policy = Policy()) -> List[Finding]:
    """The key outside the key store.

    Every guarantee in this repository rests on the attacker not having the HMAC key.
    Stealing it is the cheapest way to win, so the one thing worth searching the whole
    workspace for is the key itself. A copy anywhere under the watched tree means the
    chain's integrity claim has to be treated as void for the period it existed.
    """
    findings: List[Finding] = []
    if not key:
        return findings
    root = pathlib.Path(root)
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.stat().st_size > policy.max_scan_bytes:
            continue
        if ".git" in path.parts:
            continue
        try:
            body = path.read_bytes()
        except OSError:
            continue
        if key in body:
            findings.append(
                _finding(
                    "key_material_copy",
                    (
                        f"{path.relative_to(root).as_posix()} contains the ledger HMAC key: "
                        "with the key outside its store, entries can be minted to match any "
                        "history, and every chain guarantee is void from that point"
                    ),
                    ["ledger"],
                    [path.relative_to(root).as_posix()],
                )
            )
    return findings


def clock_creep(entries: Sequence[object], budget: float = Policy().clock_creep_budget) -> Optional[Finding]:
    """Clock changes too small to trip a per-step tolerance.

    The base check compares wall-clock delta against monotonic delta per checkpoint and
    allows a few seconds of jitter. Step the clock by slightly less than that on every
    checkpoint and each individual step looks like ntp trimming its shoes while the
    timeline quietly slides. Per-step checks cannot see integration, so this one
    integrates: the running sum of (wall delta - monotonic delta) is the total
    displacement, and displacement is what moves a timestamp out of a window.
    """
    if len(entries) < 3:
        return None
    total = 0.0
    steps = 0
    for previous, current in zip(entries, entries[1:]):
        wall = float(current.ts) - float(previous.ts)
        mono = float(dict(current.payload.get("clock", {})).get("monotonic", current.ts)) - float(
            dict(previous.payload.get("clock", {})).get("monotonic", previous.ts)
        )
        drift = wall - mono
        if abs(drift) < 1e-9:
            continue
        total += drift
        steps += 1
    if abs(total) <= budget:
        return None
    return _finding(
        "clock_creep",
        (
            f"wall clock and monotonic clock have diverged by {total:+.1f}s across {steps} checkpoints, "
            "with each step inside tolerance: the timeline was walked, not jumped, which is how a "
            "per-step check is evaded"
        ),
        ["ledger", "status"],
    )


# ------------------------------------------------------------------------ monitor


class CounterForensics(Monitor):
    """A monitor that also expects its own playbook to be used against it."""

    def __init__(self, *args, decoys: Iterable[str] = (), key_path: Optional[pathlib.Path] = None, policy: Policy = Policy(), **kwargs):
        super().__init__(*args, **kwargs)
        self.decoys: Set[str] = set(decoys)
        self.key_path = pathlib.Path(key_path) if key_path is not None else None
        self.policy = policy

    def verify(self, now: Optional[float] = None, monotonic: Optional[float] = None) -> Report:
        report = super().verify(now=now, monotonic=monotonic)
        entries = self.ledger.entries()
        if entries:
            self._counter_checks(entries, report, now)
        report.findings.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 3), f.signal, f.detail))
        return report

    # ------------------------------------------------------------------ checks

    def _counter_checks(self, entries, report: Report, now: Optional[float]) -> None:
        latest = entries[-1]
        recorded = {rel: FileState.from_dict(rel, dict(raw)) for rel, raw in dict(latest.payload.get("files", {})).items()}
        current = self.snapshot(now if now is not None else 0.0)
        changed: List[str] = []
        appeared: List[str] = []
        vanished: List[str] = []

        for rel, before in recorded.items():
            after = current.get(rel)
            if after is None:
                vanished.append(rel)
                laundered = rotation_laundering(
                    rel,
                    before,
                    current,
                    suffixes=self.rotation_suffixes,
                    max_chain=self.policy.max_rotation_chain,
                )
                if laundered is not None:
                    report.findings.append(laundered)
                continue
            for finding in (
                content_substitution(before, after),
                restored_from_copy(before, after, self.policy),
            ):
                if finding is not None:
                    report.findings.append(finding)
            if after.digest != before.digest:
                changed.append(rel)

        appeared = sorted(set(current) - set(recorded))
        touched = sorted(set(changed) | set(appeared) | set(vanished))

        history = self._change_history(entries)
        dilution = churn_dilution(touched, history, self.policy)
        if dilution is not None:
            report.findings.append(dilution)

        avoidance = canary_avoidance(touched, self.decoys, set(recorded))
        if avoidance is not None:
            report.findings.append(avoidance)

        report.findings.extend(
            shadow_ledger(
                self.ledger.path.parent,
                self.ledger.path,
                self.ledger.anchor_path if hasattr(self.ledger, "anchor_path") else None,
            )
        )
        report.findings.extend(key_material_copy(self.ledger.key, self.root, self.policy))

        creep = clock_creep(entries, self.policy.clock_creep_budget)
        if creep is not None:
            report.findings.append(creep)

    def _change_history(self, entries) -> List[int]:
        """Change counts per checkpoint, so churn is judged against this host's norm."""
        counts: List[int] = []
        for previous, current in zip(entries, entries[1:]):
            before = dict(previous.payload.get("files", {}))
            after = dict(current.payload.get("files", {}))
            delta = sum(
                1
                for rel, raw in after.items()
                if rel not in before or before[rel].get("digest") != raw.get("digest")
            )
            counts.append(delta + len(set(after) - set(before)) + len(set(before) - set(after)))
        return counts
