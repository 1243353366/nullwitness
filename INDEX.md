# Index

One entry point for everything in this repository. Generated from the tree by
`tools/build_index.py`, and checked by a test, so a stale link fails the suite instead
of rotting quietly.

**6 documents · 2 Python modules · 0 test cases · 0 other source files · 1,518 lines.**

This branch is documentation only. The executable lab is on the [`experimental` branch](https://github.com/1243353366/nullwitness/tree/experimental), indexed by the `INDEX.md` there.

## Start here

| Read | Why |
| --- | --- |
| [`AUTHORS-NOTE.md`](AUTHORS-NOTE.md) | Read this first: most of what follows is assembly, not invention. |
| [`README.md`](README.md) | The map: what is documented, what runs, what is refused. |
| [`LEGAL.md`](LEGAL.md) | The boundaries the material is written inside. |
| [`SAFETY.md`](SAFETY.md) | Constraints that apply everywhere. |

## Commands on the experimental branch

| Command | What it does |
| --- | --- |
| `python3 -m unittest discover -s lab/tests -t .` | every Python test |
| `python3 -m lab.integrity.cli demo` | integrity monitor, ten scenarios |
| `python3 -m lab.integrity.cli demo --json` | the same findings as JSON |
| `python3 -m lab.orchestrator.run_pipeline --write-report` | traffic pipeline end to end, synthetic data |
| `make -C lab/ingest check` | C++ bounded-queue self-test |
| `make -C bridge check JAVAC=javac JAVA=java` | Java bridge self-test |
| `make -C bridge run JAVAC=javac JAVA=java` | bridge reads scenarios.json, writes the report |
| `python3 tools/build_index.py --check` | verify this index matches the tree |

## Branches

| Branch | Holds |
| --- | --- |
| `main` | The written material, static by design. Nothing executes here. |
| `experimental` | The written material plus the lab and the bridge: pipeline, canaries, integrity monitor. |
| `build/static-educational-sandbox` | Earlier static build. |

## Every file

**Repository root**

- [`AUTHORS-NOTE.md`](AUTHORS-NOTE.md): Provenance: the ideas are borrowed, the assembly and the abuse are the contribution.
- [`INDEX.md`](INDEX.md): This file. Every document, module, and command in one place.
- [`LEGAL.md`](LEGAL.md): Legal boundaries for the material: jurisdiction, consent, and evidence handling.
- [`LICENSE`](LICENSE): License terms for the repository.
- [`README.md`](README.md): What the repository is, what it refuses to do, and what runs where.
- [`SAFETY.md`](SAFETY.md): Safety constraints that apply to everything here.

**archive/**

- [`archive/README.md`](archive/README.md): Material kept for history, not for use.

**archive/canary-check/**

- [`archive/canary-check/file-4tr.rs.txt`](archive/canary-check/file-4tr.rs.txt): archived: kept for history, not for use
- [`archive/canary-check/file1.python`](archive/canary-check/file1.python): archived: kept for history, not for use

**examples/**

- [`examples/scenarios.json`](examples/scenarios.json): Three documented scenarios the bridge reads and validates against the contract.
- [`examples/simulation-walkthrough.md`](examples/simulation-walkthrough.md): This is a non-executable educational example. It contains no live exploit steps, no

**tools/**

- [`tools/__init__.py`](tools/__init__.py): Repository tooling.
- [`tools/build_index.py`](tools/build_index.py): Generates this index and verifies it has not drifted.
