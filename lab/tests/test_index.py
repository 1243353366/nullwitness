"""Guards on INDEX.md: it stays complete, it resolves, and it does not drift.

The whole value of a single entry point is that it is true. These tests are what make that
a property rather than an intention: adding a file without regenerating the index fails
the suite.
"""

from __future__ import annotations

import re
import unittest

from tools.build_index import build, load_root, walk


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

    def test_generation_is_idempotent(self):
        # A document that changes when regenerated from an unchanged tree is not checkable.
        self.assertEqual(build(self.root), build(self.root))


if __name__ == "__main__":
    unittest.main()
