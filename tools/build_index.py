"""Generate INDEX.md, the single entry point for the repository.

A "living document" that is maintained by hand stops being true within a week. So the
index is generated from the tree, and `--check` fails when the committed copy has drifted
from what the tree actually contains. `lab/tests/test_index.py` runs that check in the
normal test suite, which means a change that forgets the index breaks the build instead of
quietly making the link wrong.

    python3 tools/build_index.py            # rewrite INDEX.md
    python3 tools/build_index.py --check     # fail if INDEX.md is stale

Output is deterministic: no timestamps, no absolute paths, sorted walk. That is what makes
the check meaningful.
"""

from __future__ import annotations

import argparse
import ast
import pathlib
import re
import subprocess
import sys
from typing import Dict, List, Optional

ROOT_MARKERS = ("README.md", "AUTHORS-NOTE.md")
SKIP_DIRS = {".git", "__pycache__", ".venv", "node_modules", "out", "reports", "target", "build"}
SKIP_SUFFIXES = {".pyc", ".class", ".o", ".so", ".json"}
SKIP_NAMES = {".gitignore"}

# Curated one-liners. Anything absent falls back to the file's own first line of prose.
DESCRIPTIONS: Dict[str, str] = {
    "README.md": "What the repository is, what it refuses to do, and what runs where.",
    "AUTHORS-NOTE.md": "Provenance: the ideas are borrowed, the assembly and the abuse are the contribution.",
    "LEGAL.md": "Legal boundaries for the material: jurisdiction, consent, and evidence handling.",
    "SAFETY.md": "Safety constraints that apply to everything here.",
    "INDEX.md": "This file. Every document, module, and command in one place.",
    "examples/scenarios.json": "Three documented scenarios the bridge reads and validates against the contract.",
    "lab/README.md": "Orientation for the lab: what runs, what is verified, what is not.",
    "lab/ARCHITECTURE.md": "Layer by layer: ingestion, storage, features, model, monitoring, integrity.",
    "lab/INTEGRITY.md": "Forensic-integrity monitor: channels, threat model, false positives, and the case that defeats it.",
    "lab/ETHICS-AND-LIMITS.md": "What the lab will not build and why: attribution, probing, bait documents, manipulation.",
    "lab/DESIGN-NOTES.md": "Design reasoning, including the rejected approaches.",
    "lab/WEAKNESSES-AND-FIXES.md": "Known weaknesses and what was done about each.",
    "lab/schema/001_schema.sql": "TimescaleDB hypertable, retention, compression, row-level security, k-anonymous rollup.",
    "lab/ingest/collector.hpp": "Bounded queue with counted drops and an explicit backpressure signal.",
    "lab/ingest/main.cpp": "Ingestion self-test: saturates a small queue and fails on a hang rather than blocking.",
    "lab/model/belief.py": "Reflexive belief update as a contractive iteration with a fixed point.",
    "lab/model/logistic.py": "Logistic baseline, numpy only.",
    "lab/model/temporal_cv.py": "Rolling temporal validation with an explicit leakage assertion.",
    "lab/model/monitor.py": "Drift monitoring: tie-safe PSI, volatility gate, shadow divergence, poisoning probe.",
    "lab/privacy/dp.py": "Differential privacy primitives with sequential-composition accounting.",
    "lab/features/pipeline.py": "Per-client feature engineering with MAD-based dispersion.",
    "lab/features/contract.py": "The closed event vocabulary shared by every component.",
    "lab/data/synthetic.py": "Synthetic generators: no real traffic, no real people.",
    "lab/canary/tokens.py": "Canary token issuance and encoding.",
    "lab/canary/listener.py": "Stdlib callback listener that hashes the source address and stores no address.",
    "lab/canary/manifest.py": "Tamper detection where a missing or edited canary is the alert.",
    "lab/enrich/enrich.R": "R enrichment with parameterised queries and a length-capped sanitiser.",
    "lab/docker-compose.yml": "Local stack definition. Unverified here: no Docker in the sandbox.",
    "lab/integrity/ledger.py": "HMAC-chained checkpoint ledger with an external anchor. Detects forgery, splicing, truncation.",
    "lab/integrity/monitor.py": "Four-channel evidence-state monitor and the agreement grading rule.",
    "lab/integrity/adversary.py": "Scripted tampering used by the demo and the tests. Demo-only, throwaway paths.",
    "lab/integrity/cli.py": "Ten-scenario demo, including two controls and one documented limit.",
    "lab/tests/test_integrity.py": "Integrity cases: positives, negatives, and the single-host rollback limit.",
    "lab/tests/test_index.py": "Fails when INDEX.md has drifted from the tree.",
    "bridge/src/lab/bridge/Bridge.java": "Reads scenarios.json, refuses out-of-scope capabilities, emits contract events, writes the report.",
    "bridge/src/lab/bridge/Json.java": "Minimal dependency-free JSON reader and writer.",
    "bridge/Makefile": "Build and self-test with -Xlint:all -Werror.",
    "tools/build_index.py": "Generates this index and verifies it has not drifted.",
    "LICENSE": "License terms for the repository.",
    "lab/requirements.txt": "Pinned Python dependencies for the lab.",
    "archive/README.md": "Material kept for history, not for use.",
}

START_HERE = [
    ("AUTHORS-NOTE.md", "Read this first: most of what follows is assembly, not invention."),
    ("README.md", "The map: what is documented, what runs, what is refused."),
    ("LEGAL.md", "The boundaries the material is written inside."),
    ("SAFETY.md", "Constraints that apply everywhere."),
    ("lab/README.md", "Orientation for the executable half."),
    ("lab/INTEGRITY.md", "The current focus: detecting tampering with the evidence environment."),
]

# (command, what it does, paths that must exist for it to be runnable here). The third
# element is the point: the index used to list the lab and bridge commands on `main`,
# where neither exists, so the one document meant to be trustworthy advertised four
# commands that could only fail. A command is listed when its target is in this branch.
COMMANDS = [
    ("python3 -m unittest discover -s lab/tests -t .", "every Python test", ("lab/tests",)),
    ("python3 -m lab.integrity.cli demo", "integrity monitor, ten scenarios", ("lab/integrity/cli.py",)),
    ("python3 -m lab.integrity.cli demo --json", "the same findings as JSON", ("lab/integrity/cli.py",)),
    ("python3 -m lab.economics.cli design", "four levers, two outcomes, and what the arithmetic says", ("lab/economics/cli.py",)),
    ("python3 -m lab.economics.cli axes", "capability, legitimacy, perception, dependency, and who owns them", ("lab/economics/cli.py",)),
    ("python3 -m lab.orchestrator.run_pipeline --write-report", "traffic pipeline end to end, synthetic data", ("lab/orchestrator/run_pipeline.py",)),
    ("make -C lab/ingest check", "C++ bounded-queue self-test", ("lab/ingest/Makefile",)),
    ("make -C bridge check JAVAC=javac JAVA=java", "Java bridge self-test", ("bridge/Makefile",)),
    ("make -C bridge run JAVAC=javac JAVA=java", "bridge reads scenarios.json, writes the report", ("bridge/Makefile",)),
    ("python3 tools/build_index.py --check", "verify this index matches the tree", ("tools/build_index.py",)),
]


def available(root: pathlib.Path, files: List[str], need: str) -> bool:
    """Whether a command's target is *tracked* in this branch.

    Checking the filesystem was not enough, and the failure is the same one that bit the
    `has_lab` check: switching branches leaves ignored directories behind, so
    `lab/tests/__pycache__` survives a checkout to a docs-only branch and `lab/tests`
    still exists as an empty directory. The index then advertised the test command on a
    branch with no tests. Tracked files are the authority.
    """
    prefix = need.rstrip("/") + "/"
    return any(rel == need or rel.startswith(prefix) for rel in files)


def load_root(start: pathlib.Path) -> pathlib.Path:
    for candidate in [start] + list(start.parents):
        if all((candidate / marker).exists() for marker in ROOT_MARKERS):
            return candidate
    raise SystemExit("could not find the repository root (README.md and AUTHORS-NOTE.md)")


def tracked_files(root: pathlib.Path) -> Optional[List[str]]:
    """The repository's files, from git rather than from the working directory.

    Walking the directory was wrong in a way that took a while to notice: ignored build
    output survives a branch switch, so an index generated on a docs-only branch listed a
    compiled binary that is not in that branch at all. A document about the repository
    should describe what the repository contains, and git is the authority on that.
    """
    try:
        finished = subprocess.run(
            ["git", "-C", str(root), "ls-files", "-z"],
            capture_output=True,
            check=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    names = [name for name in finished.stdout.decode("utf-8").split("\0") if name]
    return names or None


def walk(root: pathlib.Path) -> List[str]:
    candidates = tracked_files(root)
    if candidates is None:
        candidates = [
            str(path.relative_to(root)) for path in sorted(root.rglob("*")) if path.is_file()
        ]
    found: List[str] = []
    for name in candidates:
        rel = pathlib.PurePosixPath(name)
        if any(part in SKIP_DIRS for part in rel.parts):
            continue
        if rel.name in SKIP_NAMES:
            continue
        if rel.suffix in SKIP_SUFFIXES and rel.name not in {"scenarios.json"}:
            continue
        if not (root / str(rel)).is_file():
            continue
        found.append(str(rel))
    return sorted(found)


def first_markdown_line(path: pathlib.Path) -> Optional[str]:
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        text = line.strip()
        if text and not text.startswith(("#", ">", "|", "*", "-", "`", "!")):
            return re.sub(r"\s+", " ", text)
    return None


def first_docstring_line(path: pathlib.Path) -> Optional[str]:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
    except SyntaxError:
        return None
    doc = ast.get_docstring(tree)
    if not doc:
        return None
    for line in doc.splitlines():
        if line.strip():
            return re.sub(r"\s+", " ", line.strip())
    return None


def describe(path: pathlib.Path, rel: str) -> str:
    if rel in DESCRIPTIONS:
        return DESCRIPTIONS[rel]
    if rel.startswith("archive/"):
        return "archived: kept for history, not for use"
    suffix = path.suffix
    if suffix == ".md":
        return first_markdown_line(path) or "document"
    if suffix == ".py":
        return first_docstring_line(path) or "Python module"
    if suffix in {".java", ".cpp", ".hpp", ".h", ".c"}:
        return "source"
    if suffix == ".sql":
        return "schema"
    if suffix == ".r" or suffix == ".R":
        return "R script"
    if suffix in {".yml", ".yaml"}:
        return "stack definition"
    if suffix == ".json":
        return "fixture data"
    if suffix == ".txt":
        return "text"
    return "file"


def truncate(text: str, width: int = 150) -> str:
    text = text.strip()
    if len(text) <= width:
        return text
    return text[: width - 1].rstrip() + "…"


def counts(root: pathlib.Path, files: List[str]) -> Dict[str, int]:
    """Counts exclude INDEX.md itself.

    A document that counts its own length is not idempotent: writing it changes the
    total, which changes the text, which changes the total. Excluding the artefact keeps
    generation a fixed point, which is what makes --check trustworthy.
    """
    stats = {"tests": 0, "python": 0, "docs": 0, "other_code": 0, "lines": 0}
    for rel in files:
        path = root / rel
        if rel == "INDEX.md":
            # Counted as a document, excluded from the line total. Both halves matter:
            # leaving it out of the count under-reported the repository by one document,
            # and including its length would make regeneration non-idempotent.
            stats["docs"] += 1
            continue
        suffix = path.suffix
        if suffix == ".py":
            stats["python"] += 1
        elif suffix == ".md":
            stats["docs"] += 1
        elif suffix in {".java", ".cpp", ".hpp", ".h", ".c", ".sql", ".R", ".r"}:
            stats["other_code"] += 1
        try:
            body = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        stats["lines"] += body.count("\n") + (0 if body.endswith("\n") or not body else 1)
        if suffix == ".py":
            stats["tests"] += len(re.findall(r"^\s*def test_", body, flags=re.MULTILINE))
    return stats


def grouping(rel: str) -> str:
    parent = str(pathlib.PurePosixPath(rel).parent)
    return "Repository root" if parent == "." else parent + "/"


def build(root: pathlib.Path) -> str:
    files = walk(root)
    stats = counts(root, files)
    # Presence of the directory is not the test: an ignored artefact such as
    # lab/reports/ leaves the directory behind on main and the index would then advertise
    # commands that cannot run there. Presence of a tracked lab document is the test.
    has_lab = "lab/README.md" in files
    has_bridge = "bridge/Makefile" in files

    out: List[str] = []
    out.append("# Index")
    out.append("")
    out.append("One entry point for everything in this repository. Generated from the tree by")
    out.append("`tools/build_index.py`, and checked by a test, so a stale link fails the suite instead")
    out.append("of rotting quietly.")
    out.append("")
    out.append(
        f"**{stats['docs']} documents · {stats['python']} Python modules · "
        f"{stats['tests']} test cases · {stats['other_code']} other source files · "
        f"{stats['lines']:,} lines.**"
    )
    out.append("")
    if not has_lab:
        out.append(
            "This branch is the written material, and the only thing here that runs is the "
            "generator that builds this page. The executable lab is on the "
            "[`experimental` branch](https://github.com/1243353366/nullwitness/tree/experimental), "
            "indexed by the `INDEX.md` there."
        )
        out.append("")

    out.append("## Start here")
    out.append("")
    out.append("| Read | Why |")
    out.append("| --- | --- |")
    for rel, why in START_HERE:
        if (root / rel).is_file():
            out.append(f"| [`{rel}`]({rel}) | {why} |")
    out.append("")

    runnable = [
        (command, what)
        for command, what, needs in COMMANDS
        if all(available(root, files, path) for path in needs)
    ]
    elsewhere = [command for command, what, needs in COMMANDS if (command, what) not in runnable]
    out.append("## Commands" if runnable else "## Commands (none on this branch)")
    out.append("")
    if runnable:
        out.append("| Command | What it does |")
        out.append("| --- | --- |")
        for command, what in runnable:
            out.append(f"| `{command}` | {what} |")
        out.append("")
    if elsewhere:
        out.append(
            f"{len(elsewhere)} more command{'s' if len(elsewhere) > 1 else ''} need files that are not on this "
            "branch; the `INDEX.md` on `experimental` lists them."
        )
        out.append("")

    out.append("## Branches")
    out.append("")
    out.append("| Branch | Holds |")
    out.append("| --- | --- |")
    if has_lab:
        out.append(
            "| `main` | The written material, the archived material, and this generator. No lab, no pipeline. |"
        )
        out.append(
            "| `experimental` | This branch: the written material plus the lab and the bridge, and the generator. |"
        )
    else:
        out.append(
            "| `main` | This branch: the written material, the archived material, and the generator that builds "
            "this page. That generator is the only thing here that runs. |"
        )
        out.append(
            "| `experimental` | The written material plus the lab and the bridge: pipeline, canaries, integrity "
            "monitor, economics, and the tests. |"
        )
    out.append("| `build/static-educational-sandbox` | Earlier static build. |")
    out.append("")

    out.append("## Every file")
    out.append("")
    current = None
    for rel in files:
        group = grouping(rel)
        if group != current:
            if current is not None:
                out.append("")
            out.append(f"**{group}**")
            out.append("")
            current = group
        out.append(f"- [`{rel}`]({rel}): {truncate(describe(root / rel, rel))}")
    out.append("")

    if has_lab:
        out.append("## What this does not do")
        out.append("")
        out.append(
            "No cross-network attribution, no active probing, no bait documents, no manipulation of a"
        )
        out.append(
            "person. The integrity monitor does not claim to survive root on the endpoint holding both"
        )
        out.append(
            "the anchor and the key. Both statements are load-bearing: "
            "[`lab/ETHICS-AND-LIMITS.md`](lab/ETHICS-AND-LIMITS.md) and "
            "[`lab/INTEGRITY.md`](lab/INTEGRITY.md)."
        )
        out.append("")

    return "\n".join(out).rstrip() + "\n"


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Generate or verify INDEX.md")
    parser.add_argument("--check", action="store_true", help="exit 1 if INDEX.md is stale")
    parser.add_argument("--root", type=pathlib.Path, default=None)
    args = parser.parse_args(argv)

    root = args.root or load_root(pathlib.Path(__file__).resolve().parent)
    target = root / "INDEX.md"
    rendered = build(root)

    if args.check:
        existing = target.read_text(encoding="utf-8") if target.is_file() else ""
        if existing != rendered:
            print("INDEX.md is stale: run python3 tools/build_index.py", file=sys.stderr)
            return 1
        print("INDEX.md is current")
        return 0

    target.write_text(rendered, encoding="utf-8")
    print(f"wrote {target.relative_to(root)} ({len(rendered.splitlines())} lines)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
