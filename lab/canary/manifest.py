"""Tamper detection for canary artefacts.

This is the mirror image of "delete the canary so nobody notices". A canary that is
missing or modified is itself the alert, so the defender's job is to make absence and
editing loud, cheap, and routine.

A manifest is a snapshot of relative paths and SHA-256 digests. `verify` compares the
filesystem against it and classifies every difference. Nothing here needs root, a
daemon, or a database: it is a check you can run from cron, from CI, or by hand.
"""

from __future__ import annotations

import hashlib
import json
import pathlib
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Mapping, Optional

CHUNK = 1 << 20


@dataclass
class TamperReport:
    missing: List[str] = field(default_factory=list)
    modified: List[str] = field(default_factory=list)
    added: List[str] = field(default_factory=list)
    intact: List[str] = field(default_factory=list)

    @property
    def clean(self) -> bool:
        return not (self.missing or self.modified or self.added)

    @property
    def signals(self) -> List[str]:
        """Every finding as a short, log-friendly signal."""
        out = [f"missing:{p}" for p in self.missing]
        out += [f"modified:{p}" for p in self.modified]
        out += [f"added:{p}" for p in self.added]
        return out

    def summary(self) -> Dict[str, object]:
        return {
            "clean": self.clean,
            "missing": self.missing,
            "modified": self.modified,
            "added": self.added,
            "intact": len(self.intact),
        }


def digest_file(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            block = handle.read(CHUNK)
            if not block:
                break
            h.update(block)
    return h.hexdigest()


def snapshot(root: pathlib.Path, paths: Iterable[str]) -> Dict[str, str]:
    """Map relative path to digest for every path that exists under `root`."""
    root = pathlib.Path(root)
    manifest: Dict[str, str] = {}
    for rel in paths:
        target = (root / rel).resolve()
        if root.resolve() not in target.parents and target != root.resolve():
            raise ValueError(f"path escapes the canary root: {rel}")
        if target.is_file():
            manifest[rel] = digest_file(target)
    return manifest


def save(manifest: Mapping[str, str], path: pathlib.Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"version": 1, "files": dict(sorted(manifest.items()))}, indent=2) + "\n")


def load(path: pathlib.Path) -> Dict[str, str]:
    payload = json.loads(path.read_text())
    if payload.get("version") != 1:
        raise ValueError(f"{path}: unsupported manifest version")
    files = payload.get("files")
    if not isinstance(files, dict):
        raise ValueError(f"{path}: manifest has no files mapping")
    return dict(files)


def verify(root: pathlib.Path, manifest: Mapping[str, str], watch: Optional[Iterable[str]] = None) -> TamperReport:
    """Compare the filesystem against a manifest.

    `watch` limits added-file detection to a known set of directories or names, so a
    noisy directory does not report every unrelated file as "added".
    """
    root = pathlib.Path(root)
    report = TamperReport()
    for rel, expected in manifest.items():
        target = root / rel
        if not target.is_file():
            report.missing.append(rel)
            continue
        if digest_file(target) == expected:
            report.intact.append(rel)
        else:
            report.modified.append(rel)
    if watch:
        known = set(manifest)
        for rel in watch:
            candidate = root / rel
            if candidate.is_file() and rel not in known:
                report.added.append(rel)
    return report


def events_from_report(report: TamperReport, client_key: str, observed_at: float):
    """Turn findings into event-contract records so the pipeline can consume them.

    A tamper finding is attributed to the operator's own host, not to a visitor: the
    `client_key` passed here is the host's own key. This keeps tamper signal and
    access signal in one stream without pretending to know who touched the file.
    """
    import time
    import uuid

    from lab.features import contract

    events = []
    for signal in report.signals:
        kind, _, rel = signal.partition(":")
        events.append(
            contract.EventRecord(
                event_id=uuid.uuid4().hex,
                observed_at=observed_at,
                source_id=f"canary:{kind}",
                client_key=client_key,
                channel="canary_access",
                protocol="unknown",
                ua_family="unknown",
                fingerprint_hash="local",
                network_class="unknown",
                bytes_in=0,
                latency_ms=0.0,
                labels={"signal": kind, "path": rel},
            )
        )
    return events
