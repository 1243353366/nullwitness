"""Endpoint forensic-integrity monitor.

The premise: detecting tools is a losing game, because an adversary can use a built-in
utility, a custom script, or a technique nobody has published yet. What they cannot
cheaply avoid is leaving the *evidence-producing environment* in a state that
contradicts itself.

So this monitor does not look for `shred`, `wevtutil`, or a known binary hash. It keeps
four channels that are expensive to tamper with coherently and then compares them:

| Channel | What it holds | Why it is separate |
| --- | --- | --- |
| `ledger` | HMAC-chained checkpoints of everything below | rewriting it breaks a hash chain the attacker does not have the key for |
| `manifest` | digests of evidence files | changing content changes a digest |
| `metadata` | size, mtime, ctime, inode | changing content usually changes these, and they are recorded independently of the digest |
| `status` | the collector's own claim that it is running | least trustworthy, and useful precisely because a compromised agent lies |

Findings are graded by how many independent channels agree. One channel claiming
tampering is a lead. Two channels agreeing is a finding. That rule is the whole design,
and it is also the answer to "why not just match tool signatures": a signature covers
one channel, a contradiction spans several.

Nothing here touches the network, escalates privileges, or inspects other processes. It
reads file state under a root directory the operator nominates, and it keeps its chain
somewhere the operator chooses. The threat model, including the case where the attacker
is root on the endpoint and wins, is in `lab/INTEGRITY.md`.
"""

from __future__ import annotations

import hashlib
import pathlib
import time
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence

from lab.integrity.ledger import Entry, Ledger


@dataclass(frozen=True)
class FileState:
    path: str
    size: int
    digest: str
    mtime: float
    ctime: float
    inode: int

    def as_dict(self) -> Dict[str, object]:
        return {
            "size": self.size,
            "digest": self.digest,
            "mtime": self.mtime,
            "ctime": self.ctime,
            "inode": self.inode,
        }

    @classmethod
    def from_dict(cls, path: str, raw: Dict[str, object]) -> "FileState":
        return cls(
            path=path,
            size=int(raw["size"]),
            digest=str(raw["digest"]),
            mtime=float(raw["mtime"]),
            ctime=float(raw["ctime"]),
            inode=int(raw["inode"]),
        )


@dataclass
class Finding:
    kind: str
    signal: str
    severity: str
    channels: List[str]
    detail: str
    subjects: List[str] = field(default_factory=list)

    def as_dict(self) -> Dict[str, object]:
        return {
            "kind": self.kind,
            "signal": self.signal,
            "severity": self.severity,
            "channels": self.channels,
            "detail": self.detail,
            "subjects": self.subjects,
        }


@dataclass
class Report:
    findings: List[Finding] = field(default_factory=list)
    ledger_problems: List[str] = field(default_factory=list)
    checkpoints: int = 0

    @property
    def worst(self) -> str:
        for level in ("high", "medium", "low"):
            if any(f.severity == level for f in self.findings):
                return level
        return "none"

    def by_kind(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for finding in self.findings:
            counts[finding.kind] = counts.get(finding.kind, 0) + 1
        return dict(sorted(counts.items()))

    def as_dict(self) -> Dict[str, object]:
        return {
            "checkpoints": self.checkpoints,
            "worst": self.worst,
            "by_kind": self.by_kind(),
            "ledger_problems": self.ledger_problems,
            "findings": [f.as_dict() for f in self.findings],
        }


HIGH_SIGNALS = {
    "ledger_forged",
    "ledger_truncated",
    "ledger_reordered",
    "file_deleted",
    "file_truncated",
    "backdated_edit",
    "impossible_state",
    "agent_silent",
    "channel_silenced",
    "clock_regression",
}

KIND_OF = {
    "ledger_forged": "manipulation",
    "ledger_reordered": "manipulation",
    "ledger_truncated": "destruction",
    "ledger_gap": "suppression",
    "ledger_empty": "suppression",
    "anchor_missing": "manipulation",
    "file_deleted": "destruction",
    "file_truncated": "destruction",
    "backdated_edit": "manipulation",
    "metadata_inconsistent": "manipulation",
    "clock_skew": "manipulation",
    "clock_regression": "manipulation",
    "agent_silent": "suppression",
    "sampling_gap": "suppression",
    "channel_silenced": "suppression",
    "impossible_state": "fabrication",
    "uncorroborated_state": "fabrication",
    "file_modified": "manipulation",
    "file_replaced": "manipulation",
    "rotation": "manipulation",
}

STRONG_CHANNELS = {"ledger", "manifest", "metadata"}


def grade(signal: str, channels: Sequence[str]) -> str:
    """Severity from the signal class and the number of independent channels agreeing."""
    if signal in HIGH_SIGNALS:
        return "high"
    agreements = len(set(channels) & STRONG_CHANNELS)
    if agreements >= 2:
        return "medium"
    return "low"


def _digest(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


class Monitor:
    """Checkpoints a directory's evidence state and verifies it against four channels."""

    def __init__(
        self,
        root: pathlib.Path,
        ledger_path: pathlib.Path,
        key: bytes,
        patterns: Iterable[str] = ("evidence/*",),
        interval: float = 60.0,
        rotation_suffixes: Sequence[str] = (".1", ".gz", ".old", ".bak"),
        gap_factor: float = 3.0,
        clock_tolerance: float = 5.0,
    ):
        self.root = pathlib.Path(root)
        self.patterns = tuple(patterns)
        self.interval = float(interval)
        self.rotation_suffixes = tuple(rotation_suffixes)
        self.gap_factor = float(gap_factor)
        self.clock_tolerance = float(clock_tolerance)
        self.ledger = Ledger(ledger_path, key)

    # ---------------------------------------------------------------- snapshot

    def evidence_paths(self) -> List[pathlib.Path]:
        found: List[pathlib.Path] = []
        for pattern in self.patterns:
            found.extend(p for p in self.root.glob(pattern) if p.is_file())
        return sorted(found)

    def snapshot(self, now: float) -> Dict[str, FileState]:
        """Digest channel plus metadata channel, read in one pass but stored apart."""
        states: Dict[str, FileState] = {}
        for path in self.evidence_paths():
            stat = path.stat()
            rel = self.rel(path)
            states[rel] = FileState(
                path=rel,
                size=stat.st_size,
                digest=_digest(path),
                mtime=stat.st_mtime,
                ctime=stat.st_ctime,
                inode=stat.st_ino,
            )
        return states

    def rel(self, path: pathlib.Path) -> str:
        try:
            return str(path.relative_to(self.root))
        except ValueError:
            return str(path)

    # -------------------------------------------------------------- checkpoint

    def checkpoint(self, now: Optional[float] = None, monotonic: Optional[float] = None, agent_running: bool = True) -> Entry:
        now = time.time() if now is None else now
        monotonic = time.monotonic() if monotonic is None else monotonic
        states = self.snapshot(now)
        payload = {
            "files": {rel: state.as_dict() for rel, state in states.items()},
            "clock": {"wall": now, "monotonic": monotonic},
            "status": {"agent_running": bool(agent_running), "collector": "lab-integrity"},
        }
        return self.ledger.append(payload, now)

    # ------------------------------------------------------------------ verify

    def verify(self, now: Optional[float] = None, monotonic: Optional[float] = None) -> Report:
        now = time.time() if now is None else now
        monotonic = time.monotonic() if monotonic is None else monotonic
        entries = self.ledger.entries()
        problems = self.ledger.verify()
        report = Report(ledger_problems=problems, checkpoints=len(entries))
        if not entries:
            report.findings.append(
                Finding(
                    kind="suppression",
                    signal="ledger_empty",
                    severity="high",
                    channels=["ledger"],
                    detail="no checkpoints recorded: collection never ran, or its output was removed",
                )
            )
            return report

        self._check_ledger(entries, problems, report)
        latest = entries[-1]
        baseline = entries[0]
        self._check_files(latest, report, now)
        self._check_clock(entries, report, monotonic)
        self._check_suppression(entries, report, now)

        report.findings.sort(key=lambda f: ({"high": 0, "medium": 1, "low": 2}[f.severity], f.signal, f.detail))
        return report

    # ---------------------------------------------------------------- detectors

    def _check_ledger(self, entries: List[Entry], problems: Sequence[str], report: Report) -> None:
        mapping = {
            "forged": ("ledger_forged", ["ledger"], "an entry's MAC does not verify: written without the key"),
            "reordered": ("ledger_reordered", ["ledger"], "the hash chain does not link: entries were spliced"),
            "truncated": ("ledger_truncated", ["ledger"], "the anchor records a later head than the file contains: tail dropped"),
            "gap": ("ledger_gap", ["ledger"], "sequence numbers skip: entries removed from the middle"),
            "anchor_missing": ("anchor_missing", ["ledger"], "no external anchor: the chain has no independent witness"),
            "time_regression": ("clock_regression", ["ledger"], "a later entry carries an earlier timestamp: backdating"),
        }
        for problem in problems:
            signal, channels, detail = mapping.get(problem, (f"ledger_{problem}", ["ledger"], problem))
            report.findings.append(
                Finding(
                    kind=KIND_OF.get(signal, "manipulation"),
                    signal=signal,
                    severity=grade(signal, channels),
                    channels=list(channels),
                    detail=detail,
                    subjects=[f"seq {e.seq}" for e in entries[:1]],
                )
            )

        # Fabrication: a checkpoint that claims a file state from the future.
        for entry in entries:
            for rel, raw in dict(entry.payload.get("files", {})).items():
                mtime = float(dict(raw)["mtime"])
                if mtime > float(entry.ts) + 1.0:
                    report.findings.append(
                        Finding(
                            kind="fabrication",
                            signal="impossible_state",
                            severity=grade("impossible_state", ["ledger", "metadata"]),
                            channels=["ledger", "metadata"],
                            detail=f"checkpoint {entry.seq} records {rel} modified at {mtime:.0f}, after the checkpoint itself ({float(entry.ts):.0f})",
                            subjects=[rel],
                        )
                    )

    def _check_files(self, latest: Entry, report: Report, now: float) -> None:
        recorded = {rel: FileState.from_dict(rel, dict(raw)) for rel, raw in dict(latest.payload.get("files", {})).items()}
        current = self.snapshot(now)
        recorded_names = set(recorded)

        for rel, before in recorded.items():
            after = current.get(rel)
            if after is None:
                if self._was_rotated(rel, before, current):
                    report.findings.append(
                        Finding(
                            kind="manipulation",
                            signal="rotation",
                            severity="low",
                            channels=["manifest"],
                            detail=f"{rel} was rotated, and a file with the same digest exists under a rotation suffix",
                            subjects=[rel],
                        )
                    )
                else:
                    report.findings.append(
                        Finding(
                            kind="destruction",
                            signal="file_deleted",
                            severity=grade("file_deleted", ["manifest", "metadata"]),
                            channels=["manifest", "metadata"],
                            detail=f"{rel} was present at checkpoint {latest.seq} and is gone now",
                            subjects=[rel],
                        )
                    )
                continue

            if after.digest != before.digest:
                if after.mtime < before.mtime - 1.0:
                    report.findings.append(
                        Finding(
                            kind="manipulation",
                            signal="backdated_edit",
                            severity=grade("backdated_edit", ["manifest", "metadata"]),
                            channels=["manifest", "metadata"],
                            detail=(
                                f"{rel} content changed but its mtime went backwards "
                                f"({before.mtime:.0f} -> {after.mtime:.0f}): edited, then timestamped to look older"
                            ),
                            subjects=[rel],
                        )
                    )
                elif after.size < before.size:
                    report.findings.append(
                        Finding(
                            kind="destruction",
                            signal="file_truncated",
                            severity=grade("file_truncated", ["manifest", "metadata"]),
                            channels=["manifest", "metadata"],
                            detail=f"{rel} shrank from {before.size} to {after.size} bytes and its digest changed",
                            subjects=[rel],
                        )
                    )
                else:
                    report.findings.append(
                        Finding(
                            kind="manipulation",
                            signal="file_modified",
                            severity="low",
                            channels=["manifest"],
                            detail=f"{rel} content changed since checkpoint {latest.seq} (growth, consistent with normal appends)",
                            subjects=[rel],
                        )
                    )
            elif after.inode != before.inode:
                report.findings.append(
                    Finding(
                        kind="manipulation",
                        signal="file_replaced",
                        severity="low",
                        channels=["metadata"],
                        detail=f"{rel} has the same content but a different inode: replaced rather than edited in place",
                        subjects=[rel],
                    )
                )

            if after.mtime > after.ctime + 1.0:
                report.findings.append(
                    Finding(
                        kind="manipulation",
                        signal="metadata_inconsistent",
                        severity=grade("metadata_inconsistent", ["metadata"]),
                        channels=["metadata"],
                        detail=f"{rel} has mtime {after.mtime:.0f} later than ctime {after.ctime:.0f}, which normal writes do not produce",
                        subjects=[rel],
                    )
                )

        for rel in sorted(set(current) - recorded_names):
            report.findings.append(
                Finding(
                    kind="fabrication",
                    signal="uncorroborated_state",
                    severity="low",
                    channels=["manifest"],
                    detail=f"{rel} exists now but was not in checkpoint {latest.seq}: it appeared outside the collection path",
                    subjects=[rel],
                )
            )

    def _was_rotated(self, rel: str, before: FileState, current: Dict[str, FileState]) -> bool:
        for candidate, state in current.items():
            if not candidate.startswith(rel):
                continue
            if not candidate[len(rel):].startswith(self.rotation_suffixes):
                continue
            if state.digest == before.digest:
                return True
        return False

    def _check_clock(self, entries: List[Entry], report: Report, monotonic: float) -> None:
        if len(entries) < 2:
            return
        previous, latest = entries[-2], entries[-1]
        previous_mono = float(dict(previous.payload.get("clock", {})).get("monotonic", previous.ts))
        latest_mono = float(dict(latest.payload.get("clock", {})).get("monotonic", latest.ts))
        wall_delta = float(latest.ts) - float(previous.ts)
        mono_delta = latest_mono - previous_mono
        if wall_delta < 0:
            return  # already reported as ledger time_regression
        if abs(wall_delta - mono_delta) > self.clock_tolerance:
            report.findings.append(
                Finding(
                    kind="manipulation",
                    signal="clock_skew",
                    severity=grade("clock_skew", ["ledger", "status"]),
                    channels=["ledger", "status"],
                    detail=(
                        f"wall clock advanced {wall_delta:.1f}s while the monotonic clock advanced "
                        f"{mono_delta:.1f}s: the system time was changed under collection"
                    ),
                )
            )

    def _check_suppression(self, entries: List[Entry], report: Report, now: float) -> None:
        latest = entries[-1]
        elapsed = now - float(latest.ts)
        status = dict(latest.payload.get("status", {}))
        agent_running = bool(status.get("agent_running", False))

        if elapsed > self.gap_factor * self.interval:
            if agent_running:
                report.findings.append(
                    Finding(
                        kind="suppression",
                        signal="agent_silent",
                        severity=grade("agent_silent", ["ledger", "status"]),
                        channels=["ledger", "status"],
                        detail=(
                            f"the collector last checked in {elapsed:.0f}s ago and still reports itself running: "
                            "it was stopped, or its output is being withheld"
                        ),
                    )
                )
            else:
                report.findings.append(
                    Finding(
                        kind="suppression",
                        signal="sampling_gap",
                        severity=grade("sampling_gap", ["ledger"]),
                        channels=["ledger"],
                        detail=f"no checkpoint for {elapsed:.0f}s (expected every {self.interval:.0f}s)",
                    )
                )

        # Activity continued while collection did not: the strongest suppression signal.
        modified_after_checkpoint = [
            path for path in self.evidence_paths() if path.stat().st_mtime > float(latest.ts) + 1.0
        ]
        if modified_after_checkpoint and elapsed > self.interval:
            report.findings.append(
                Finding(
                    kind="suppression",
                    signal="channel_silenced",
                    severity=grade("channel_silenced", ["ledger", "metadata"]),
                    channels=["ledger", "metadata"],
                    detail=(
                        f"{len(modified_after_checkpoint)} evidence file(s) changed after checkpoint {latest.seq} "
                        f"but no checkpoint covers them: the channel was silenced, not idle"
                    ),
                    subjects=sorted(self.rel(p) for p in modified_after_checkpoint),
                )
            )
