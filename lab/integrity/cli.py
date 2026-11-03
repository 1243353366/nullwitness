"""Demo runner for the forensic-integrity monitor.

    python3 -m lab.integrity.cli demo           # table of detections
    python3 -m lab.integrity.cli demo --json    # machine-readable reports

Each scenario gets a fresh workspace in a temporary directory, runs three clean
checkpoints, applies one act of tampering, and then verifies. Two scenarios are
controls: a legitimate append and a legitimate log rotation must not be reported as
destruction. One scenario is a limit: a rollback that also rewrites the anchor is
undetectable without an off-box witness, and the demo says so instead of hiding it.
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import shutil
import tempfile
import time
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional

from lab.integrity import adversary
from lab.integrity.monitor import Monitor, Report

BASE = 1_767_225_600.0  # 2026-01-01T00:00:00Z
INTERVAL = 60.0
EVIDENCE = {
    "evidence/audit.log": "2026-01-01T00:00:00Z launch agent=collector pid=4242\n",
    "evidence/processes.jsonl": '{"pid":4242,"name":"collector","state":"running"}\n',
}


@dataclass
class Scenario:
    name: str
    expectation: str
    run: Callable[[Monitor, pathlib.Path], Optional[float]]


def fresh_workspace(root: pathlib.Path) -> None:
    """Create the workspace and age its files to before the first checkpoint.

    Without this step the demo would compare file mtimes from the real clock against
    checkpoint timestamps from the fixed BASE, and every scenario would report an
    impossible state. A fixture has to be internally consistent to be a fair test.
    """
    (root / "evidence").mkdir(parents=True, exist_ok=True)
    for rel, body in EVIDENCE.items():
        path = root / rel
        path.write_text(body, encoding="utf-8")
        aged = BASE - 30.0
        os.utime(path, (aged, aged))


def build_monitor(root: pathlib.Path) -> Monitor:
    return Monitor(
        root=root,
        ledger_path=root / "integrity" / "checkpoints.jsonl",
        key=b"demo-key-not-a-secret",
        patterns=("evidence/*",),
        interval=INTERVAL,
    )


def three_checkpoints(monitor: Monitor) -> None:
    for step in range(3):
        monitor.checkpoint(now=BASE + step * INTERVAL, monotonic=1000.0 + step * INTERVAL)


SCENARIOS: List[Scenario] = [
    Scenario(
        "clean",
        "no findings",
        lambda monitor, root: None,
    ),
    Scenario(
        "delete evidence",
        "destruction",
        lambda monitor, root: adversary.delete_file(root, "evidence/processes.jsonl"),
    ),
    Scenario(
        "truncate evidence",
        "destruction",
        lambda monitor, root: adversary.truncate_file(root, "evidence/audit.log", keep=25),
    ),
    Scenario(
        "edit then backdate",
        "manipulation",
        lambda monitor, root: adversary.backdate_edit(
            root, "evidence/audit.log", "2026-01-01T00:00:00Z launch agent=collector pid=1\n", seconds_older=7200
        ),
    ),
    Scenario(
        "forge a ledger entry",
        "manipulation",
        lambda monitor, root: adversary.forge_entry(monitor),
    ),
    Scenario(
        "drop the ledger tail",
        "destruction",
        lambda monitor, root: adversary.rollback_body(monitor, keep=2),
    ),
    Scenario(
        "silence the collector",
        "suppression",
        lambda monitor, root: (
            adversary.append_legitimately(root, "evidence/audit.log", "2026-01-01T00:05:00Z still working\n"),
            BASE + 6 * INTERVAL,
        )[-1],
    ),
    Scenario(
        "control: legitimate append",
        "low severity at most",
        lambda monitor, root: adversary.append_legitimately(
            root, "evidence/audit.log", "2026-01-01T00:01:00Z heartbeat ok\n"
        ),
    ),
    Scenario(
        "control: log rotation",
        "no destruction finding",
        lambda monitor, root: adversary.rotate(root, "evidence/audit.log"),
    ),
    Scenario(
        "limit: rollback plus anchor rewrite",
        "undetected on one host",
        lambda monitor, root: adversary.rollback_body_and_anchor(monitor, keep=2),
    ),
]


def run_scenario(scenario: Scenario, keep_dir: Optional[pathlib.Path] = None) -> Report:
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="integrity-")) if keep_dir is None else keep_dir
    try:
        fresh_workspace(tmp)
        monitor = build_monitor(tmp)
        three_checkpoints(monitor)

        override_now = scenario.run(monitor, tmp)
        verify_at = override_now if isinstance(override_now, float) else BASE + 2 * INTERVAL + INTERVAL
        monotonic_at = 1000.0 + (verify_at - BASE)
        return monitor.verify(now=verify_at, monotonic=monotonic_at)
    finally:
        if keep_dir is None:
            shutil.rmtree(tmp, ignore_errors=True)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Forensic-integrity monitor demo")
    parser.add_argument("action", choices=["demo", "antiforensics"], nargs="?", default="demo")
    parser.add_argument("--json", action="store_true", help="emit reports as JSON")
    parser.add_argument("--keep", type=pathlib.Path, default=None, help="keep a single workspace at this path")
    args = parser.parse_args(argv)

    if args.action == "antiforensics":
        from lab.integrity import af_demo

        passthrough = ["--json"] if args.json else []
        return af_demo.main(passthrough)

    reports: Dict[str, Report] = {}
    for scenario in SCENARIOS:
        keep_dir = None
        if args.keep is not None and scenario.name == "delete evidence":
            keep_dir = args.keep
            if keep_dir.exists():
                shutil.rmtree(keep_dir)
            keep_dir.mkdir(parents=True)
        reports[scenario.name] = run_scenario(scenario, keep_dir)

    if args.json:
        print(json.dumps({name: report.as_dict() for name, report in reports.items()}, indent=2, sort_keys=True))
        return 0

    width = max(len(s.name) for s in SCENARIOS)
    print(f"{'scenario'.ljust(width)}  {'worst':<7} {'expectation':<22} findings")
    print("-" * (width + 60))
    for scenario in SCENARIOS:
        report = reports[scenario.name]
        signals = sorted({f.signal for f in report.findings}) or ["none"]
        print(
            f"{scenario.name.ljust(width)}  {report.worst:<7} {scenario.expectation:<22} {', '.join(signals)}"
        )

    print()
    for scenario in SCENARIOS:
        report = reports[scenario.name]
        for finding in report.findings:
            print(f"[{finding.severity}] {scenario.name}: {finding.signal} via {'+'.join(finding.channels)}")
            print(f"    {finding.detail}")
    print()
    totals = {"high": 0, "medium": 0, "low": 0}
    for report in reports.values():
        for finding in report.findings:
            totals[finding.severity] += 1
    print(f"findings by severity: high={totals['high']} medium={totals['medium']} low={totals['low']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
