"""Demo for the counter-anti-forensic layer.

    python3 -m lab.integrity.af_demo            # table of detections
    python3 -m lab.integrity.af_demo --json     # machine-readable reports

The scenarios are not variations on "delete a file". Each one is a technique chosen
because it defeats a check the base monitor performs, staged against a workspace that
also carries two decoys, so the decoy-aware case can be shown honestly.

Three scenarios are controls: a real log rotation, a legitimate busy window, and a quiet
host must stay quiet. One is a limit: an adversary who edits evidence outside the watched
set is invisible here, because there is nothing to contradict.
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import shutil
import tempfile
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional

from lab.integrity import adversary
from lab.integrity.counterforensics import CounterForensics, Policy

BASE = 1_767_225_600.0  # 2026-01-01T00:00:00Z
INTERVAL = 60.0
KEY = b"demo-key-not-a-secret"
EVIDENCE = {
    "evidence/audit.log": "2026-01-01T00:00:00Z launch agent=collector pid=4242\n",
    "evidence/processes.jsonl": '{"pid":4242,"name":"collector","state":"running"}\n',
    "evidence/auth-events.log": "2026-01-01T00:00:00Z auth method=token user=operator\n",
    "evidence/netflow-summary.jsonl": '{"flows":12,"bytes":4096}\n',
    "evidence/task-scheduler.log": "2026-01-01T00:00:00Z task=collect runs=1\n",
    "evidence/session-notes.log": "2026-01-01T00:00:00Z session opened user=operator\n",
    "evidence/agent-cache.jsonl": '{"cache":"warm","entries":12}\n',
    "evidence/agent-journal.jsonl": '{"uptime":900,"restarts":0}\n',
}
# Three files that look exactly like the other five and are watched for exactly one
# purpose: nobody with a legitimate task needs them.
DECOYS = ("evidence/session-notes.log", "evidence/agent-cache.jsonl", "evidence/agent-journal.jsonl")
NON_DECOYS = tuple(sorted(set(EVIDENCE) - set(DECOYS)))


@dataclass
class Scenario:
    name: str
    expectation: str
    run: Callable[[CounterForensics, pathlib.Path], Optional[float]]


def fresh_workspace(root: pathlib.Path) -> None:
    (root / "evidence").mkdir(parents=True, exist_ok=True)
    (root / "integrity").mkdir(parents=True, exist_ok=True)
    for rel, body in EVIDENCE.items():
        path = root / rel
        path.write_text(body, encoding="utf-8")
        aged = BASE - 30.0
        os.utime(path, (aged, aged))


def build_monitor(root: pathlib.Path) -> CounterForensics:
    return CounterForensics(
        root=root,
        ledger_path=root / "integrity" / "checkpoints.jsonl",
        key=KEY,
        patterns=("evidence/*",),
        interval=INTERVAL,
        decoys=DECOYS,
        policy=Policy(),
    )


def three_checkpoints(monitor: CounterForensics) -> None:
    for step in range(3):
        monitor.checkpoint(now=BASE + step * INTERVAL, monotonic=1000.0 + step * INTERVAL)


SCENARIOS: List[Scenario] = [
    Scenario("clean", "no findings", lambda monitor, root: None),
    Scenario(
        "overwrite in place, same length",
        "content_substitution",
        lambda monitor, root: adversary.overwrite_same_size(
            root, "evidence/audit.log", "2026-01-01T00:00:00Z launch agent=collector pid=9999\n"
        ),
    ),
    Scenario(
        "delete the bytes, put them back",
        "restored_from_copy",
        lambda monitor, root: adversary.restore_from_copy(root, "evidence/audit.log"),
    ),
    Scenario(
        "launder a deletion as rotation",
        "rotation_laundering",
        lambda monitor, root: adversary.launder_rotation(root, "evidence/audit.log", "evidence/processes.jsonl"),
    ),
    Scenario(
        "control: a real rotation",
        "no destruction finding",
        lambda monitor, root: adversary.rotate(root, "evidence/audit.log"),
    ),
    Scenario(
        "bury it in churn",
        "churn_dilution",
        lambda monitor, root: (adversary.scatter(root, 6), adversary.truncate_file(root, "evidence/processes.jsonl", keep=10))[-1],
    ),
    Scenario(
        "control: a legitimately busy window",
        "no dilution finding",
        lambda monitor, root: (adversary.scatter(root, 3), adversary.append_legitimately(root, "evidence/audit.log", "x\n"))[-1],
    ),
    Scenario(
        "sweep the real files, avoid every decoy",
        "canary_avoidance",
        lambda monitor, root: [
            adversary.append_legitimately(root, rel, "2026-01-01T00:03:00Z touched\n") for rel in NON_DECOYS
        ][-1],
    ),
    Scenario(
        "control: one real file, decoys untouched",
        "no precision finding",
        lambda monitor, root: adversary.append_legitimately(root, "evidence/audit.log", "2026-01-01T00:04:00Z ok\n"),
    ),
    Scenario(
        "plant a second ledger",
        "shadow_ledger",
        lambda monitor, root: adversary.plant_shadow_ledger(monitor),
    ),
    Scenario(
        "copy the HMAC key into the tree",
        "key_material_copy",
        lambda monitor, root: adversary.copy_key(monitor, "evidence/backup-notes.bin"),
    ),
    Scenario(
        "walk the clock under tolerance",
        "clock_creep",
        lambda monitor, root: adversary.creep_clock(
            monitor,
            base_wall=BASE + 2 * INTERVAL,
            base_monotonic=1000.0 + 2 * INTERVAL,
            steps=6,
            drift=0.9,
            interval=INTERVAL,
        ),
    ),
    Scenario(
        "limit: edit outside the watched set",
        "undetected by design",
        lambda monitor, root: (root / "secrets").mkdir(exist_ok=True)
        or (root / "secrets" / "notes.txt").write_text("not watched\n", encoding="utf-8"),
    ),
]


def run_scenario(scenario: Scenario, keep_dir: Optional[pathlib.Path] = None):
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="counter-")) if keep_dir is None else keep_dir
    try:
        fresh_workspace(tmp)
        monitor = build_monitor(tmp)
        three_checkpoints(monitor)
        override = scenario.run(monitor, tmp)
        verify_at = override if isinstance(override, float) else BASE + 3 * INTERVAL
        return monitor.verify(now=verify_at, monotonic=1000.0 + (verify_at - BASE))
    finally:
        if keep_dir is None:
            shutil.rmtree(tmp, ignore_errors=True)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Counter-anti-forensics demo")
    parser.add_argument("--json", action="store_true", help="emit reports as JSON")
    parser.add_argument("--keep", type=pathlib.Path, default=None, help="keep the clean workspace at this path")
    args = parser.parse_args(argv)

    reports: Dict[str, object] = {}
    for scenario in SCENARIOS:
        keep_dir = None
        if args.keep is not None and scenario.name == "clean":
            keep_dir = args.keep
            if keep_dir.exists():
                shutil.rmtree(keep_dir)
            keep_dir.mkdir(parents=True)
        reports[scenario.name] = run_scenario(scenario, keep_dir)

    if args.json:
        print(json.dumps({name: report.as_dict() for name, report in reports.items()}, indent=2, sort_keys=True))
        return 0

    width = max(len(s.name) for s in SCENARIOS)
    print(f"{'scenario'.ljust(width)}  {'worst':<7} {'expectation':<24} signals")
    print("-" * (width + 58))
    for scenario in SCENARIOS:
        report = reports[scenario.name]
        signals = sorted({f.signal for f in report.findings}) or ["none"]
        print(f"{scenario.name.ljust(width)}  {report.worst:<7} {scenario.expectation:<24} {', '.join(signals)}")
    print()
    for scenario in SCENARIOS:
        for finding in reports[scenario.name].findings:
            if finding.severity == "low" and finding.signal in {"file_modified", "rotation", "file_replaced"}:
                continue
            print(f"[{finding.severity}] {scenario.name}: {finding.signal} via {'+'.join(finding.channels)}")
            print(f"    {finding.detail}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
