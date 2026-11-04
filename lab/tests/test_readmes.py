"""Every factual claim the READMEs make, checked against the tree.

A README is a set of assertions that nothing normally re-tests, which is why both of these
had drifted: one said the repository contained no scripts while shipping a generator, the
other advertised 68 tests in a suite of 333 and called a pure-Python cipher "NIST-verified".
The claims that can be checked mechanically are checked here, so the next drift is a failing
test rather than a wrong page.

What this cannot check is judgement: whether a component is worth its complexity, or whether
a "not implemented" row is still the right decision. It checks names, paths, counts, and one
recorded run.
"""

from __future__ import annotations

import pathlib
import re
import subprocess
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
READMES = {ROOT / "README.md": ROOT, ROOT / "lab" / "README.md": ROOT / "lab"}
STDLIB = {"unittest", "json", "http.server", "venv", "pip"}


def relative_links(text: str, base: pathlib.Path) -> list[str]:
    targets = []
    for target in re.findall(r"\]\(([^)]+)\)", text):
        if target.startswith(("http", "#", "mailto:")):
            continue
        path = (base / target.split("#")[0]).resolve()
        targets.append((target, path))
    return targets


class LinkTests(unittest.TestCase):
    def test_every_relative_link_resolves(self):
        broken = []
        for readme, base in READMES.items():
            text = readme.read_text(encoding="utf-8")
            broken += [f"{readme.name}: {target}" for target, path in relative_links(text, base) if not path.exists()]
        self.assertEqual(broken, [], f"broken links: {broken}")

    def test_no_link_points_at_the_other_branch_by_relative_path(self):
        """A branch-local path that only exists over there is the failure mode this catches."""
        for readme, base in READMES.items():
            for target, path in relative_links(readme.read_text(encoding="utf-8"), base):
                if target.startswith("../") and not path.exists():
                    self.fail(f"{readme}: {target} leaves the branch and lands nowhere")


class CommandTests(unittest.TestCase):
    def test_every_python_module_command_exists(self):
        missing = []
        for readme, _base in READMES.items():
            for module in re.findall(r"python3 -m ([A-Za-z0-9_.]+)", readme.read_text(encoding="utf-8")):
                if module in STDLIB:
                    # `python3 -m unittest` is the runner, not something this repo ships.
                    continue
                as_file = ROOT / (module.replace(".", "/") + ".py")
                as_package = ROOT / module.replace(".", "/") / "__init__.py"
                if not (as_file.exists() or as_package.exists()):
                    missing.append(f"{readme.name}: {module}")
        self.assertEqual(missing, [], f"documented modules that do not exist: {missing}")

    def test_every_make_directory_exists(self):
        missing = []
        for readme, _base in READMES.items():
            for directory in re.findall(r"make -C (\S+)", readme.read_text(encoding="utf-8")):
                if not (ROOT / directory / "Makefile").exists():
                    missing.append(f"{readme.name}: {directory}")
        self.assertEqual(missing, [], f"documented make targets that do not exist: {missing}")


class CountTests(unittest.TestCase):
    def test_no_hardcoded_test_counts(self):
        """Counts belong in INDEX.md, which is generated. Prose counts go stale silently."""
        pattern = re.compile(r"\b\d+\s+(?:unit)?tests?\b|\b\d+\s+unittest cases\b|\b\d+\s+test cases\b")
        offenders = []
        for readme in READMES:
            for number, line in enumerate(readme.read_text(encoding="utf-8").splitlines(), 1):
                if pattern.search(line):
                    offenders.append(f"{readme.name}:{number}: {line.strip()}")
        self.assertEqual(offenders, [], f"hardcoded test counts: {offenders}")


class LayoutTests(unittest.TestCase):
    """The `## Layout` block claims a shape for the directory, so the shape has to hold."""

    def test_every_layout_path_exists(self):
        text = (ROOT / "lab" / "README.md").read_text(encoding="utf-8")
        block = re.search(r"## Layout\s*```(.*?)```", text, re.S)
        self.assertIsNotNone(block, "the Layout block is gone; update this test with the doc")
        missing = []
        for line in block.group(1).splitlines():
            if not line.strip():
                continue
            # One space after a long filename, several after a short one: split on any run
            # of whitespace and take the first field.
            token = line.split()[0]
            if token == "lab/":
                continue
            path = (ROOT / "lab" / token).resolve()
            if not path.exists():
                missing.append(token)
        self.assertEqual(missing, [], f"Layout lists paths that do not exist: {missing}")


class StatusTableTests(unittest.TestCase):
    """`## Status by component` names a file per row and says what state it is in."""

    def test_every_status_row_names_a_real_file(self):
        text = (ROOT / "lab" / "README.md").read_text(encoding="utf-8")
        section = re.search(r"## Status by component(.*?)\n## ", text, re.S)
        self.assertIsNotNone(section, "the status table moved; update this test with the doc")
        missing = []
        for line in section.group(1).splitlines():
            cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
            if len(cells) < 2 or cells[1] in {"File", "---"} or set(cells[1]) <= {"-"}:
                continue
            token = cells[1].strip("`")
            if token in {"n/a", ""}:
                continue
            if not (ROOT / "lab" / token).exists():
                missing.append(token)
        self.assertEqual(missing, [], f"status rows naming files that do not exist: {missing}")


class RecordedRunTests(unittest.TestCase):
    """The one block that claims to be a real run, checked by making the run."""

    def test_the_documented_example_output_still_reproduces(self):
        text = (ROOT / "lab" / "README.md").read_text(encoding="utf-8")
        block = re.search(r"Example output from a clean run:\s*```(.*?)```", text, re.S)
        self.assertIsNotNone(block)
        documented = [line.strip() for line in block.group(1).strip().splitlines() if line.strip()]

        finished = subprocess.run(
            ["python3", "-m", "lab.orchestrator.run_pipeline"],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            timeout=300,
        )
        self.assertEqual(finished.returncode, 0, finished.stderr)
        actual = [line.strip() for line in finished.stdout.splitlines() if line.strip()]

        for line in documented:
            if line.startswith("top features:"):
                # the trailing list is elided in the doc and depends on float formatting
                self.assertTrue(any(a.startswith("top features:") for a in actual), "no feature line in the run")
                continue
            self.assertIn(line, actual, f"documented line no longer appears in a clean run: {line!r}")


if __name__ == "__main__":
    unittest.main()
