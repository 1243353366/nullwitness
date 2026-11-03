# Index

One entry point for everything in this repository. Generated from the tree by
`tools/build_index.py`, and checked by a test, so a stale link fails the suite instead
of rotting quietly.

**14 documents · 30 Python modules · 72 test cases · 6 other source files · 10,131 lines.**

## Start here

| Read | Why |
| --- | --- |
| [`AUTHORS-NOTE.md`](AUTHORS-NOTE.md) | Read this first: most of what follows is assembly, not invention. |
| [`README.md`](README.md) | The map: what is documented, what runs, what is refused. |
| [`LEGAL.md`](LEGAL.md) | The boundaries the material is written inside. |
| [`SAFETY.md`](SAFETY.md) | Constraints that apply everywhere. |
| [`lab/README.md`](lab/README.md) | Orientation for the executable half. |
| [`lab/INTEGRITY.md`](lab/INTEGRITY.md) | The current focus: detecting tampering with the evidence environment. |

## Commands

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

**bridge/**

- [`bridge/Makefile`](bridge/Makefile): Build and self-test with -Xlint:all -Werror.
- [`bridge/README.md`](bridge/README.md): the two agreed, so this module does three jobs and no more:

**bridge/src/lab/bridge/**

- [`bridge/src/lab/bridge/Bridge.java`](bridge/src/lab/bridge/Bridge.java): Reads scenarios.json, refuses out-of-scope capabilities, emits contract events, writes the report.
- [`bridge/src/lab/bridge/Json.java`](bridge/src/lab/bridge/Json.java): Minimal dependency-free JSON reader and writer.

**examples/**

- [`examples/scenarios.json`](examples/scenarios.json): Three documented scenarios the bridge reads and validates against the contract.
- [`examples/simulation-walkthrough.md`](examples/simulation-walkthrough.md): This is a non-executable educational example. It contains no live exploit steps, no

**lab/**

- [`lab/.env.example`](lab/.env.example): file
- [`lab/ARCHITECTURE.md`](lab/ARCHITECTURE.md): Layer by layer: ingestion, storage, features, model, monitoring, integrity.
- [`lab/DESIGN-NOTES.md`](lab/DESIGN-NOTES.md): Design reasoning, including the rejected approaches.
- [`lab/ETHICS-AND-LIMITS.md`](lab/ETHICS-AND-LIMITS.md): What the lab will not build and why: attribution, probing, bait documents, manipulation.
- [`lab/INTEGRITY.md`](lab/INTEGRITY.md): Forensic-integrity monitor: channels, threat model, false positives, and the case that defeats it.
- [`lab/README.md`](lab/README.md): Orientation for the lab: what runs, what is verified, what is not.
- [`lab/WEAKNESSES-AND-FIXES.md`](lab/WEAKNESSES-AND-FIXES.md): Known weaknesses and what was done about each.
- [`lab/__init__.py`](lab/__init__.py): Python module

**lab/canary/**

- [`lab/canary/listener.py`](lab/canary/listener.py): Stdlib callback listener that hashes the source address and stores no address.
- [`lab/canary/manifest.py`](lab/canary/manifest.py): Tamper detection where a missing or edited canary is the alert.
- [`lab/canary/tokens.py`](lab/canary/tokens.py): Canary token issuance and encoding.

**lab/data/**

- [`lab/data/__init__.py`](lab/data/__init__.py): Python module
- [`lab/data/synthetic.py`](lab/data/synthetic.py): Synthetic generators: no real traffic, no real people.

**lab/**

- [`lab/docker-compose.yml`](lab/docker-compose.yml): Local stack definition. Unverified here: no Docker in the sandbox.

**lab/enrich/**

- [`lab/enrich/enrich.R`](lab/enrich/enrich.R): R enrichment with parameterised queries and a length-capped sanitiser.

**lab/features/**

- [`lab/features/__init__.py`](lab/features/__init__.py): Python module
- [`lab/features/contract.py`](lab/features/contract.py): The closed event vocabulary shared by every component.
- [`lab/features/pipeline.py`](lab/features/pipeline.py): Per-client feature engineering with MAD-based dispersion.

**lab/ingest/**

- [`lab/ingest/Makefile`](lab/ingest/Makefile): file
- [`lab/ingest/collector.hpp`](lab/ingest/collector.hpp): Bounded queue with counted drops and an explicit backpressure signal.
- [`lab/ingest/collector_selftest`](lab/ingest/collector_selftest): file
- [`lab/ingest/main.cpp`](lab/ingest/main.cpp): Ingestion self-test: saturates a small queue and fails on a hang rather than blocking.

**lab/integrity/**

- [`lab/integrity/__init__.py`](lab/integrity/__init__.py): Forensic-integrity monitoring: evidence-state tamper detection.
- [`lab/integrity/adversary.py`](lab/integrity/adversary.py): Scripted tampering used by the demo and the tests. Demo-only, throwaway paths.
- [`lab/integrity/cli.py`](lab/integrity/cli.py): Ten-scenario demo, including two controls and one documented limit.
- [`lab/integrity/ledger.py`](lab/integrity/ledger.py): HMAC-chained checkpoint ledger with an external anchor. Detects forgery, splicing, truncation.
- [`lab/integrity/monitor.py`](lab/integrity/monitor.py): Four-channel evidence-state monitor and the agreement grading rule.

**lab/model/**

- [`lab/model/__init__.py`](lab/model/__init__.py): Python module
- [`lab/model/belief.py`](lab/model/belief.py): Reflexive belief update as a contractive iteration with a fixed point.
- [`lab/model/logistic.py`](lab/model/logistic.py): Logistic baseline, numpy only.
- [`lab/model/monitor.py`](lab/model/monitor.py): Drift monitoring: tie-safe PSI, volatility gate, shadow divergence, poisoning probe.
- [`lab/model/temporal_cv.py`](lab/model/temporal_cv.py): Rolling temporal validation with an explicit leakage assertion.

**lab/orchestrator/**

- [`lab/orchestrator/__init__.py`](lab/orchestrator/__init__.py): Python module
- [`lab/orchestrator/run_pipeline.py`](lab/orchestrator/run_pipeline.py): End-to-end run over synthetic data.

**lab/privacy/**

- [`lab/privacy/__init__.py`](lab/privacy/__init__.py): Python module
- [`lab/privacy/dp.py`](lab/privacy/dp.py): Differential privacy primitives with sequential-composition accounting.

**lab/**

- [`lab/requirements.txt`](lab/requirements.txt): Pinned Python dependencies for the lab.

**lab/schema/**

- [`lab/schema/001_schema.sql`](lab/schema/001_schema.sql): TimescaleDB hypertable, retention, compression, row-level security, k-anonymous rollup.

**lab/source/**

- [`lab/source/nerdshit.md`](lab/source/nerdshit.md): title: nerdshit (source dump, unedited)

**lab/tests/**

- [`lab/tests/__init__.py`](lab/tests/__init__.py): Python module
- [`lab/tests/test_canary.py`](lab/tests/test_canary.py): Tests for the canary modules: tokens, tamper detection, callback listener.
- [`lab/tests/test_index.py`](lab/tests/test_index.py): Fails when INDEX.md has drifted from the tree.
- [`lab/tests/test_integrity.py`](lab/tests/test_integrity.py): Integrity cases: positives, negatives, and the single-host rollback limit.
- [`lab/tests/test_lab.py`](lab/tests/test_lab.py): Tests for the experimental lab.

**tools/**

- [`tools/__init__.py`](tools/__init__.py): Repository tooling.
- [`tools/build_index.py`](tools/build_index.py): Generates this index and verifies it has not drifted.

## What this does not do

No cross-network attribution, no active probing, no bait documents, no manipulation of a
person. The integrity monitor does not claim to survive root on the endpoint holding both
the anchor and the key. Both statements are load-bearing: [`lab/ETHICS-AND-LIMITS.md`](lab/ETHICS-AND-LIMITS.md) and [`lab/INTEGRITY.md`](lab/INTEGRITY.md).
