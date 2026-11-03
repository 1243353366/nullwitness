"""Tests for the forensic-integrity monitor.

Two kinds of case appear here, and both matter equally:

- positive: each act of destruction, suppression, manipulation, or fabrication is
  detected with the right kind and severity.
- negative: legitimate activity is not reported as tampering. A monitor that cries wolf
  on every append gets switched off within a week, which is worse than not having one.

The limit case is also a test. A rollback that rewrites the anchor too is undetectable
on a single host, and the suite asserts that rather than implying otherwise.
"""

from __future__ import annotations

import json
import os
import pathlib
import tempfile
import unittest

from lab.integrity import adversary
from lab.integrity.ledger import Ledger
from lab.integrity.monitor import Monitor, grade

BASE = 1_767_225_600.0
STEP = 60.0
KEY = b"test-key"
EVIDENCE = {
    "evidence/audit.log": "2026-01-01T00:00:00Z launch agent=collector pid=4242\n",
    "evidence/processes.jsonl": '{"pid":4242,"name":"collector","state":"running"}\n',
}


class LedgerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = pathlib.Path(self.tmp.name) / "checkpoints.jsonl"

    def build(self, count=3) -> Ledger:
        ledger = Ledger(self.path, KEY)
        for i in range(count):
            ledger.append({"i": i}, BASE + i * STEP)
        return ledger

    def test_clean_chain_verifies(self):
        ledger = self.build()
        self.assertEqual(ledger.verify(), [])
        self.assertEqual(len(ledger.entries()), 3)

    def test_refuses_unkeyed_chain(self):
        with self.assertRaises(ValueError):
            Ledger(self.path, b"")

    def test_forged_entry_detected(self):
        ledger = self.build()
        entries = ledger.entries()
        raw = json.loads(entries[-1].as_line())
        raw["seq"] = 99
        raw["mac"] = "0" * 32
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(raw, sort_keys=True) + "\n")
        self.assertIn("forged", ledger.verify())

    def test_truncated_tail_detected(self):
        ledger = self.build()
        lines = self.path.read_text(encoding="utf-8").splitlines(keepends=True)
        self.path.write_text("".join(lines[:2]), encoding="utf-8")
        self.assertIn("truncated", ledger.verify())

    def test_reordered_entries_detected(self):
        ledger = self.build()
        lines = self.path.read_text(encoding="utf-8").splitlines(keepends=True)
        self.path.write_text("".join([lines[0], lines[2], lines[1]]), encoding="utf-8")
        self.assertIn("reordered", ledger.verify())

    def test_removed_middle_entry_detected(self):
        ledger = self.build()
        lines = self.path.read_text(encoding="utf-8").splitlines(keepends=True)
        self.path.write_text("".join([lines[0], lines[2]]), encoding="utf-8")
        problems = ledger.verify()
        self.assertTrue({"gap", "reordered"} & set(problems), problems)

    def test_backdated_entry_detected(self):
        ledger = Ledger(self.path, KEY)
        ledger.append({"i": 0}, BASE + 120)
        ledger.append({"i": 1}, BASE)  # earlier timestamp, appended later
        self.assertIn("time_regression", ledger.verify())


class MonitorTests(unittest.TestCase):
    def workspace(self) -> pathlib.Path:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = pathlib.Path(tmp.name)
        (root / "evidence").mkdir()
        for rel, body in EVIDENCE.items():
            path = root / rel
            path.write_text(body, encoding="utf-8")
            os.utime(path, (BASE - 30, BASE - 30))
        return root

    def monitor(self, root: pathlib.Path) -> Monitor:
        return Monitor(root=root, ledger_path=root / "integrity" / "checkpoints.jsonl", key=KEY, interval=STEP)

    def baseline(self, monitor: Monitor, count: int = 3) -> None:
        for step in range(count):
            monitor.checkpoint(now=BASE + step * STEP, monotonic=1000.0 + step * STEP)

    def verify(self, monitor: Monitor, at: float = BASE + 2 * STEP + STEP):
        return monitor.verify(now=at, monotonic=1000.0 + (at - BASE))

    def signals(self, report) -> set:
        return {f.signal for f in report.findings}

    # ---------------------------------------------------------------- positives

    def test_clean_workspace_has_no_findings(self):
        monitor = self.monitor(self.workspace())
        self.baseline(monitor)
        report = self.verify(monitor)
        self.assertEqual(report.findings, [], report.as_dict())
        self.assertEqual(report.worst, "none")

    def test_deleted_evidence_is_destruction(self):
        root = self.workspace()
        monitor = self.monitor(root)
        self.baseline(monitor)
        adversary.delete_file(root, "evidence/processes.jsonl")
        report = self.verify(monitor)
        finding = next(f for f in report.findings if f.signal == "file_deleted")
        self.assertEqual(finding.kind, "destruction")
        self.assertEqual(finding.severity, "high")
        self.assertEqual(set(finding.channels), {"manifest", "metadata"})

    def test_truncated_evidence_is_destruction(self):
        root = self.workspace()
        monitor = self.monitor(root)
        self.baseline(monitor)
        adversary.truncate_file(root, "evidence/audit.log", keep=10)
        report = self.verify(monitor)
        finding = next(f for f in report.findings if f.signal == "file_truncated")
        self.assertEqual(finding.kind, "destruction")
        self.assertEqual(finding.severity, "high")

    def test_backdated_edit_is_manipulation(self):
        root = self.workspace()
        monitor = self.monitor(root)
        self.baseline(monitor)
        adversary.backdate_edit(root, "evidence/audit.log", "rewritten\n", seconds_older=7200)
        report = self.verify(monitor)
        finding = next(f for f in report.findings if f.signal == "backdated_edit")
        self.assertEqual(finding.kind, "manipulation")
        self.assertEqual(finding.severity, "high")

    def test_forged_checkpoint_is_manipulation(self):
        root = self.workspace()
        monitor = self.monitor(root)
        self.baseline(monitor)
        adversary.forge_entry(monitor)
        report = self.verify(monitor)
        self.assertIn("ledger_forged", self.signals(report))
        self.assertIn("forged", report.ledger_problems)

    def test_ledger_rollback_is_destruction(self):
        root = self.workspace()
        monitor = self.monitor(root)
        self.baseline(monitor)
        adversary.rollback_body(monitor, keep=2)
        report = self.verify(monitor, at=BASE + 2 * STEP)
        self.assertIn("ledger_truncated", self.signals(report))

    def test_silent_collector_is_suppression(self):
        root = self.workspace()
        monitor = self.monitor(root)
        self.baseline(monitor)
        adversary.append_legitimately(root, "evidence/audit.log", "working\n")
        report = self.verify(monitor, at=BASE + 10 * STEP)
        self.assertIn("agent_silent", self.signals(report))
        self.assertIn("channel_silenced", self.signals(report))
        severity = {f.signal: f.severity for f in report.findings}
        self.assertEqual(severity["agent_silent"], "high")
        self.assertEqual(severity["channel_silenced"], "high")

    def test_clock_skew_detected(self):
        root = self.workspace()
        monitor = self.monitor(root)
        monitor.checkpoint(now=BASE, monotonic=1000.0)
        monitor.checkpoint(now=BASE + STEP, monotonic=1000.0 + 900.0)  # wall moved 60, monotonic 900
        report = self.verify(monitor, at=BASE + STEP)
        self.assertIn("clock_skew", self.signals(report))

    def test_impossible_state_is_fabrication(self):
        root = self.workspace()
        monitor = self.monitor(root)
        self.baseline(monitor)
        future = BASE + 10_000
        monitor.ledger.append(
            {
                "files": {"evidence/audit.log": {"size": 1, "digest": "x" * 64, "mtime": future, "ctime": future, "inode": 1}},
                "clock": {"wall": future, "monotonic": 5000.0},
                "status": {"agent_running": True},
            },
            BASE + STEP,
        )
        report = self.verify(monitor, at=BASE + 2 * STEP)
        finding = next(f for f in report.findings if f.signal == "impossible_state")
        self.assertEqual(finding.kind, "fabrication")

    def test_empty_ledger_is_suppression(self):
        monitor = self.monitor(self.workspace())
        report = self.verify(monitor)
        self.assertIn("ledger_empty", self.signals(report))

    # ---------------------------------------------------------------- negatives

    def test_legitimate_append_is_low_severity_only(self):
        root = self.workspace()
        monitor = self.monitor(root)
        self.baseline(monitor)
        adversary.append_legitimately(root, "evidence/audit.log", "2026-01-01T00:01:00Z heartbeat\n")
        report = self.verify(monitor)
        self.assertNotIn("file_deleted", self.signals(report))
        self.assertNotIn("file_truncated", self.signals(report))
        self.assertNotIn("backdated_edit", self.signals(report))
        self.assertTrue(all(f.severity == "low" for f in report.findings), report.as_dict())

    def test_rotation_is_not_destruction(self):
        root = self.workspace()
        monitor = self.monitor(root)
        self.baseline(monitor)
        adversary.rotate(root, "evidence/audit.log")
        report = self.verify(monitor)
        self.assertNotIn("file_deleted", self.signals(report))
        self.assertEqual(report.worst, "low")

    def test_small_clock_step_is_tolerated(self):
        root = self.workspace()
        monitor = self.monitor(root)
        monitor.checkpoint(now=BASE, monotonic=1000.0)
        monitor.checkpoint(now=BASE + STEP + 2.0, monotonic=1000.0 + STEP)  # NTP-sized step
        report = self.verify(monitor, at=BASE + 1.5 * STEP)
        self.assertNotIn("clock_skew", self.signals(report))

    def test_idle_but_reporting_collector_is_not_suppression(self):
        root = self.workspace()
        monitor = self.monitor(root)
        self.baseline(monitor)
        report = self.verify(monitor, at=BASE + 2 * STEP + STEP * 0.5)
        self.assertNotIn("agent_silent", self.signals(report))
        self.assertNotIn("channel_silenced", self.signals(report))

    # ------------------------------------------------------------------- limits

    def test_rollback_with_anchor_rewrite_is_undetected_on_one_host(self):
        """The documented limitation, asserted so nobody assumes otherwise.

        Both the chain and its witness live on the same filesystem here, so an attacker
        who can write both produces a consistent shorter history. Shipping the anchor
        off-box is the mitigation, and it is an architectural decision, not a code one.
        """
        root = self.workspace()
        monitor = self.monitor(root)
        self.baseline(monitor)
        adversary.rollback_body_and_anchor(monitor, keep=2)
        report = self.verify(monitor, at=BASE + STEP)
        self.assertEqual(report.findings, [], report.as_dict())


class GradingTests(unittest.TestCase):
    def test_single_channel_is_not_high(self):
        self.assertEqual(grade("file_modified", ["manifest"]), "low")

    def test_two_strong_channels_reach_medium(self):
        self.assertEqual(grade("metadata_inconsistent", ["manifest", "metadata"]), "medium")

    def test_listed_signals_are_high_regardless(self):
        for signal in ("file_deleted", "file_truncated", "ledger_forged", "agent_silent"):
            self.assertEqual(grade(signal, ["manifest"]), "high", signal)


if __name__ == "__main__":
    unittest.main()
