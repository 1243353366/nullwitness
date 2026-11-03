"""Tests for the counter-anti-forensic layer.

The units here are the detectors, because each one is a claim of the form "this quantity
cannot be conserved at the same time as that one". A detector test can therefore be
written as a pair of states, which is cheaper and more exact than staging an attack.

The integration tests stage the attack anyway, against a real temporary directory with
real file operations, because a detector that is right about a dataclass and wrong about a
filesystem is not right. Controls are included for the same reason they exist in the base
suite: a layer that fires on log rotation trains its operator to ignore it.

The limit case is asserted too. An adversary who edits evidence outside the watched set is
invisible here, and the suite says so out loud instead of leaving it to be discovered.
"""

from __future__ import annotations

import json
import os
import pathlib
import tempfile
import unittest

from lab.integrity import adversary
from lab.integrity.counterforensics import (
    CounterForensics,
    Policy,
    canary_avoidance,
    churn_dilution,
    clock_creep,
    content_substitution,
    key_material_copy,
    restored_from_copy,
    rotation_laundering,
    shadow_ledger,
)
from lab.integrity.ledger import Ledger
from lab.integrity.monitor import FileState

BASE = 1_767_225_600.0
STEP = 60.0
KEY = b"counter-test-key"
EVIDENCE = {
    "evidence/audit.log": "2026-01-01T00:00:00Z launch agent=collector pid=4242\n",
    "evidence/processes.jsonl": '{"pid":4242,"name":"collector","state":"running"}\n',
    "evidence/auth-events.log": "2026-01-01T00:00:00Z auth method=token user=operator\n",
    "evidence/task-scheduler.log": "2026-01-01T00:00:00Z task=collect runs=1\n",
    "evidence/session-notes.log": "2026-01-01T00:00:00Z session opened user=operator\n",
    "evidence/agent-cache.jsonl": '{"cache":"warm","entries":12}\n',
}
DECOYS = ("evidence/session-notes.log", "evidence/agent-cache.jsonl")
REAL = tuple(rel for rel in sorted(EVIDENCE) if rel not in DECOYS)


def state(rel: str, size: int = 40, digest: str = "a" * 64, mtime: float = BASE, ctime: float = BASE, inode: int = 7) -> FileState:
    return FileState(path=rel, size=size, digest=digest, mtime=mtime, ctime=ctime, inode=inode)


class ContentSubstitutionTests(unittest.TestCase):
    def test_same_size_new_bytes_is_a_substitution(self):
        finding = content_substitution(state("e/a.log"), state("e/a.log", digest="b" * 64))
        self.assertIsNotNone(finding)
        self.assertEqual(finding.signal, "content_substitution")
        self.assertEqual(finding.severity, "medium")
        self.assertIn("preserved length", finding.detail)

    def test_growth_is_not_a_substitution(self):
        self.assertIsNone(content_substitution(state("e/a.log"), state("e/a.log", size=60, digest="b" * 64)))

    def test_unchanged_is_not_a_substitution(self):
        self.assertIsNone(content_substitution(state("e/a.log"), state("e/a.log")))


class RestoredFromCopyTests(unittest.TestCase):
    def test_identical_bytes_with_moved_ctime_is_a_restore(self):
        finding = restored_from_copy(state("e/a.log"), state("e/a.log", ctime=BASE + 5))
        self.assertIsNotNone(finding)
        self.assertEqual(finding.signal, "restored_from_copy")
        self.assertIn("wrote", finding.detail.replace("written", "wrote"))

    def test_new_inode_with_identical_bytes_is_a_restore(self):
        finding = restored_from_copy(state("e/a.log"), state("e/a.log", ctime=BASE + 5, inode=99))
        self.assertIsNotNone(finding)
        self.assertIn("new inode", finding.detail)

    def test_a_normal_edit_is_not_a_restore(self):
        self.assertIsNone(restored_from_copy(state("e/a.log"), state("e/a.log", digest="b" * 64, ctime=BASE + 5)))

    def test_a_file_nobody_wrote_is_not_a_restore(self):
        self.assertIsNone(restored_from_copy(state("e/a.log"), state("e/a.log", mtime=BASE + 7, inode=99)))

    def test_identical_bytes_in_a_new_inode_is_still_a_restore(self):
        finding = restored_from_copy(state("e/a.log"), state("e/a.log", ctime=BASE + 5, mtime=BASE + 7, inode=99))
        self.assertIsNotNone(finding)


class RotationLaunderingTests(unittest.TestCase):
    def test_real_rotation_is_clean(self):
        before = state("e/a.log", digest="a" * 64)
        current = {"e/a.log.1": state("e/a.log.1", digest="a" * 64)}
        self.assertIsNone(rotation_laundering("e/a.log", before, current))

    def test_rotation_holding_other_content_is_laundering(self):
        before = state("e/a.log", digest="a" * 64)
        current = {"e/a.log.1": state("e/a.log.1", digest="c" * 64)}
        finding = rotation_laundering("e/a.log", before, current)
        self.assertIsNotNone(finding)
        self.assertEqual(finding.signal, "rotation_laundering")
        self.assertEqual(finding.kind, "destruction")

    def test_chain_past_retention_is_laundering(self):
        before = state("e/a.log", digest="a" * 64)
        current = {"e/a.log.1.2.3.4": state("e/a.log.1.2.3.4", digest="a" * 64)}
        finding = rotation_laundering("e/a.log", before, current, max_chain=3)
        self.assertIsNotNone(finding)
        self.assertIn("retention policy", finding.detail)

    def test_no_rotation_file_means_nothing_to_say(self):
        self.assertIsNone(rotation_laundering("e/a.log", state("e/a.log"), {}))


class ChurnDilutionTests(unittest.TestCase):
    def test_burst_against_a_quiet_baseline_is_dilution(self):
        finding = churn_dilution([f"e/f{i}" for i in range(8)], history=[0, 1, 0, 0])
        self.assertIsNotNone(finding)
        self.assertEqual(finding.signal, "churn_dilution")
        self.assertEqual(finding.severity, "low")

    def test_busy_host_is_not_dilution(self):
        self.assertIsNone(churn_dilution([f"e/f{i}" for i in range(8)], history=[20, 24, 18]))

    def test_quiet_window_is_not_dilution(self):
        self.assertIsNone(churn_dilution(["e/a.log", "e/b.log"], history=[0, 0]))


class CanaryAvoidanceTests(unittest.TestCase):
    def setUp(self):
        self.tracked = [f"e/f{i}.log" for i in range(8)]
        self.decoys = self.tracked[:3]
        self.real = self.tracked[3:]

    def test_sweeping_every_real_file_is_improbable(self):
        finding = canary_avoidance(self.real, self.decoys, self.tracked)
        self.assertIsNotNone(finding)
        self.assertEqual(finding.signal, "canary_avoidance")
        self.assertEqual(finding.severity, "medium")
        self.assertIn("1.", finding.detail)

    def test_a_single_edit_proves_nothing(self):
        self.assertIsNone(canary_avoidance(self.real[:1], self.decoys, self.tracked))

    def test_touching_a_decoy_clears_the_lead(self):
        self.assertIsNone(canary_avoidance(self.real + self.decoys[:1], self.decoys, self.tracked))

    def test_small_sets_are_not_significant(self):
        tracked = ["e/a.log", "e/b.log", "e/c.log"]
        decoys = ("e/c.log",)
        # Two of three is not precision, it is arithmetic.
        self.assertIsNone(canary_avoidance(["e/a.log", "e/b.log"], decoys, tracked))

    def test_coverage_of_the_sweep_decides_the_severity(self):
        wide = [f"e/f{i}.log" for i in range(10)]  # 3 decoys, 7 real
        call = lambda hits: canary_avoidance(wide[3 : 3 + hits], wide[:3], wide)
        self.assertIsNone(call(4), "4 of 7 is 17% by chance, not precision")
        self.assertEqual(call(5).severity, "low")
        self.assertEqual(call(7).severity, "medium")


class ShadowLedgerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = pathlib.Path(self.tmp.name)
        self.state = self.root / "integrity"
        self.state.mkdir()
        self.ledger_path = self.state / "checkpoints.jsonl"
        ledger = Ledger(self.ledger_path, KEY)
        ledger.append({"files": {}}, BASE)

    def test_a_clean_state_directory_is_clean(self):
        self.assertEqual(shadow_ledger(self.state, self.ledger_path, self.ledger_path.with_name("checkpoints.jsonl.head")), [])

    def test_a_second_chain_is_flagged(self):
        (self.state / "checkpoints.jsonl.orig").write_text(
            json.dumps({"seq": 0, "ts": BASE, "prev": "0" * 32, "payload": {}, "mac": "a" * 32}) + "\n",
            encoding="utf-8",
        )
        findings = shadow_ledger(self.state, self.ledger_path)
        self.assertEqual([f.signal for f in findings], ["shadow_ledger"])
        self.assertEqual(findings[0].severity, "high")

    def test_debris_is_not_a_chain(self):
        (self.state / "notes.txt").write_text("rebooted at noon\n", encoding="utf-8")
        self.assertEqual(shadow_ledger(self.state, self.ledger_path), [])


class KeyMaterialTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = pathlib.Path(self.tmp.name)

    def test_clean_tree_has_no_key_copy(self):
        (self.root / "a.log").write_text("nothing here\n", encoding="utf-8")
        self.assertEqual(key_material_copy(KEY, self.root), [])

    def test_a_copy_is_high(self):
        (self.root / "backup.bin").write_bytes(b"prefix" + KEY + b"suffix")
        findings = key_material_copy(KEY, self.root)
        self.assertEqual([f.signal for f in findings], ["key_material_copy"])
        self.assertEqual(findings[0].severity, "high")
        self.assertEqual(findings[0].subjects, ["backup.bin"])


class ClockCreepTests(unittest.TestCase):
    def build(self, drift: float, steps: int = 6):
        ledger_entries = []
        for step in range(steps + 1):
            wall = BASE + step * STEP + step * drift
            mono = 1000.0 + step * STEP

            class Entry:
                pass

            entry = Entry()
            entry.ts = wall
            entry.payload = {"clock": {"wall": wall, "monotonic": mono}}
            ledger_entries.append(entry)
        return ledger_entries

    def test_sub_threshold_steps_accumulate(self):
        finding = clock_creep(self.build(0.9), budget=2.0)
        self.assertIsNotNone(finding)
        self.assertEqual(finding.signal, "clock_creep")
        self.assertIn("+5.4s", finding.detail)

    def test_a_steady_clock_is_clean(self):
        self.assertIsNone(clock_creep(self.build(0.0)))

    def test_small_total_is_clean(self):
        self.assertIsNone(clock_creep(self.build(0.2, steps=3), budget=2.0))


class IntegrationTests(unittest.TestCase):
    """The whole layer, against a real directory, with real file operations."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = pathlib.Path(self.tmp.name)
        (self.root / "evidence").mkdir()
        (self.root / "integrity").mkdir()
        for rel, body in EVIDENCE.items():
            path = self.root / rel
            path.write_text(body, encoding="utf-8")
            aged = BASE - 30.0
            os.utime(path, (aged, aged))

    def monitor(self) -> CounterForensics:
        return CounterForensics(
            root=self.root,
            ledger_path=self.root / "integrity" / "checkpoints.jsonl",
            key=KEY,
            patterns=("evidence/*",),
            interval=STEP,
            decoys=DECOYS,
        )

    def start(self, monitor: CounterForensics) -> None:
        for step in range(3):
            monitor.checkpoint(now=BASE + step * STEP, monotonic=1000.0 + step * STEP)

    def signals(self, monitor: CounterForensics, now: float = BASE + 3 * STEP):
        report = monitor.verify(now=now, monotonic=1000.0 + (now - BASE))
        return {f.signal for f in report.findings}, report

    def test_quiet_host_stays_quiet(self):
        monitor = self.monitor()
        self.start(monitor)
        signals, report = self.signals(monitor)
        self.assertEqual(signals, set(), f"a clean host produced {report.as_dict()}")

    def test_in_place_overwrite_is_caught(self):
        monitor = self.monitor()
        self.start(monitor)
        adversary.overwrite_same_size(self.root, "evidence/audit.log", "2026-01-01T00:00:00Z launch operator=root\n")
        signals, _ = self.signals(monitor)
        self.assertIn("content_substitution", signals)

    def test_delete_and_restore_is_caught(self):
        monitor = self.monitor()
        self.start(monitor)
        adversary.restore_from_copy(self.root, "evidence/audit.log")
        signals, _ = self.signals(monitor)
        self.assertIn("restored_from_copy", signals)

    def test_laundered_rotation_is_caught(self):
        monitor = self.monitor()
        self.start(monitor)
        adversary.launder_rotation(self.root, "evidence/audit.log", "evidence/processes.jsonl")
        signals, _ = self.signals(monitor)
        self.assertIn("rotation_laundering", signals)

    def test_decoy_sweep_is_caught(self):
        monitor = self.monitor()
        self.start(monitor)
        for rel in REAL:
            adversary.append_legitimately(self.root, rel, "2026-01-01T00:03:00Z touched\n")
        signals, _ = self.signals(monitor)
        self.assertIn("canary_avoidance", signals)

    def test_shadow_ledger_is_caught(self):
        monitor = self.monitor()
        self.start(monitor)
        adversary.plant_shadow_ledger(monitor)
        signals, _ = self.signals(monitor)
        self.assertIn("shadow_ledger", signals)

    def test_stolen_key_is_caught(self):
        monitor = self.monitor()
        self.start(monitor)
        adversary.copy_key(monitor, "evidence/backup-notes.bin")
        signals, report = self.signals(monitor)
        self.assertIn("key_material_copy", signals)
        self.assertEqual(report.worst, "high")

    def test_clock_creep_is_caught(self):
        monitor = self.monitor()
        self.start(monitor)
        final = adversary.creep_clock(
            monitor,
            base_wall=BASE + 2 * STEP,
            base_monotonic=1000.0 + 2 * STEP,
            steps=6,
            drift=0.9,
            interval=STEP,
        )
        signals, _ = self.signals(monitor, now=final)
        self.assertIn("clock_creep", signals)

    def test_controls_raise_nothing_above_low(self):
        for name, act in (
            ("rotation", lambda m: adversary.rotate(self.root, "evidence/audit.log")),
            ("busy window", lambda m: adversary.scatter(self.root, 3)),
            ("single append", lambda m: adversary.append_legitimately(self.root, "evidence/audit.log", "ok\n")),
            ("one real file touched", lambda m: adversary.append_legitimately(self.root, "evidence/auth-events.log", "ok\n")),
        ):
            with self.subTest(name):
                for path in self.root.rglob("*"):
                    if path.is_file():
                        path.unlink()
                for rel, body in EVIDENCE.items():
                    target = self.root / rel
                    target.write_text(body, encoding="utf-8")
                    aged = BASE - 30.0
                    os.utime(target, (aged, aged))
                monitor = self.monitor()
                self.start(monitor)
                act(monitor)
                _, report = self.signals(monitor)
                self.assertIn(report.worst, {"none", "low"}, f"{name}: {report.as_dict()}")

    def test_limit_edits_outside_the_watched_set_are_invisible(self):
        monitor = self.monitor()
        self.start(monitor)
        (self.root / "secrets").mkdir()
        (self.root / "secrets" / "notes.txt").write_text("not watched\n", encoding="utf-8")
        signals, _ = self.signals(monitor)
        self.assertEqual(signals, set(), "the limit case should be undetected, and is")


if __name__ == "__main__":
    unittest.main()
