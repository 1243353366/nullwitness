"""Guards on INDEX.md: it stays complete, it resolves, and it does not drift.

The whole value of a single entry point is that it is true. These tests are what make that
a property rather than an intention: adding a file without regenerating the index fails
the suite.
"""

from __future__ import annotations

import pathlib
import re
import unittest

from tools.build_index import COMMANDS, SKIP_DIRS, SKIP_NAMES, SKIP_SUFFIXES, build, load_root, tracked_files, walk


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
        for command, _what, needs in COMMANDS:
            runnable = all((self.root / path).exists() for path in needs)
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
