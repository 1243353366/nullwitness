"""Guards on INDEX.md: it stays complete, it resolves, and it does not drift.

The whole value of a single entry point is that it is true. These tests are what make that
a property rather than an intention: adding a file without regenerating the index fails
the suite.
"""

from __future__ import annotations

import pathlib
import re
import unittest

from tools import build_index
from tools.build_index import (
    COMMANDS,
    SKIP_DIRS,
    SKIP_NAMES,
    SKIP_SUFFIXES,
    available,
    build,
    load_root,
    tracked_files,
    walk,
)


class IndexTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = load_root(__import__("pathlib").Path(__file__).resolve().parent)
        cls.text = (cls.root / "INDEX.md").read_text(encoding="utf-8")

    def test_index_matches_the_tree(self):
        self.assertEqual(
            self.text,
            build(self.root),
            "INDEX.md is stale: run python3 tools/build_index.py",
        )

    def test_an_unstaged_file_is_still_part_of_the_tree(self):
        """The index is generated before `git add`, and `--check` runs against the same list.

        When discovery came from `git ls-files` alone, a file written but not yet staged was
        invisible to both, so a stale index passed its own check. Twice.
        """
        import subprocess as _subprocess

        tracked = pathlib.Path(__file__).resolve().parents[2] / "lab" / "index_probe.tmp"
        tracked.write_text("probe\n", encoding="utf-8")
        try:
            listed = build_index.tracked_files(pathlib.Path(__file__).resolve().parents[2])
            self.assertIsNotNone(listed)
            self.assertIn("lab/index_probe.tmp", [str(name) for name in listed],
                          "an untracked file must be visible: the index is written before staging")
        finally:
            tracked.unlink()
            status = _subprocess.run(
                ["git", "-C", str(pathlib.Path(__file__).resolve().parents[2]), "status", "--porcelain"],
                capture_output=True, text=True,
            )
            self.assertNotIn("index_probe", status.stdout, "the probe leaked into the working tree")

    def test_every_file_is_listed(self):
        missing = [rel for rel in walk(self.root) if f"]({rel})" not in self.text]
        self.assertEqual(missing, [], f"not indexed: {missing}")

    def test_every_relative_link_resolves(self):
        broken = [
            target
            for target in re.findall(r"\]\(([^)]+)\)", self.text)
            if not target.startswith(("http", "#"))
            and not (self.root / target.split("#")[0]).exists()
        ]
        self.assertEqual(broken, [], f"broken links in INDEX.md: {broken}")

    def test_every_listed_command_can_actually_run_here(self):
        """A single entry point that advertises unrunnable commands is worse than no entry point."""
        files = walk(self.root)
        for command, _what, needs in COMMANDS:
            runnable = all(available(self.root, files, path) for path in needs)
            listed = f"`{command}`" in self.text
            self.assertEqual(
                listed,
                runnable,
                f"{command} is {'missing from' if runnable else 'wrongly listed in'} INDEX.md",
            )

    def test_file_exclusions_are_deliberate_not_accidental(self):
        """walk() hides build output; anything else it hides is a silent omission."""
        tracked = tracked_files(self.root) or []
        indexed = set(walk(self.root))
        for rel in tracked:
            if rel in indexed:
                continue
            parts = rel.split("/")
            excused = (
                any(part in SKIP_DIRS for part in parts)
                or parts[-1] in SKIP_NAMES
                or (pathlib.PurePosixPath(rel).suffix in SKIP_SUFFIXES and parts[-1] != "scenarios.json")
            )
            self.assertTrue(excused, f"{rel} is tracked but excluded from INDEX.md without a rule")

    def test_the_document_count_includes_this_page(self):
        declared = int(re.search(r"\*\*(\d+) documents", self.text).group(1))
        on_disk = len([rel for rel in walk(self.root) if rel.endswith(".md")])
        self.assertEqual(declared, on_disk, f"header says {declared} documents, tree has {on_disk}")

    def test_generation_is_idempotent(self):
        # A document that changes when regenerated from an unchanged tree is not checkable.
        self.assertEqual(build(self.root), build(self.root))


if __name__ == "__main__":
    unittest.main()
