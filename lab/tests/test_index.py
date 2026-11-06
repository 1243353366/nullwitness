"""The index is generated, so the thing worth testing is that it still matches the tree.

The docstring of tools/build_index.py promised this file at this path. It did not exist, so CI ran
bare `pytest`, collected nothing, and exited 5: a red badge that never meant anything about the
repository.
"""
from __future__ import annotations

import pathlib
import shutil
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[2]


def run(args, cwd=ROOT):
    return subprocess.run([sys.executable, "tools/build_index.py", *args],
                          cwd=cwd, capture_output=True, text=True)


def test_the_committed_index_matches_the_tree():
    result = run(["--check"])
    assert result.returncode == 0, (result.stdout + result.stderr).strip()


def test_generation_is_a_fixed_point():
    """Regenerating a current index must not change it, or --check means nothing."""
    before = (ROOT / "INDEX.md").read_text(encoding="utf-8")
    assert run([]).returncode == 0
    assert (ROOT / "INDEX.md").read_text(encoding="utf-8") == before


def test_drift_is_detected_in_a_copy():
    """A stale index must fail loudly instead of agreeing with itself."""
    with tempfile.TemporaryDirectory() as tmp:
        copy = pathlib.Path(tmp) / "repo"
        shutil.copytree(ROOT, copy, ignore=shutil.ignore_patterns(".git", "__pycache__"))
        index = copy / "INDEX.md"
        index.write_text(index.read_text(encoding="utf-8") + "\n- not in the tree\n", encoding="utf-8")
        result = run(["--check"], cwd=copy)
        assert result.returncode == 1, "a stale index passed the check"
        assert "stale" in (result.stdout + result.stderr).lower()
