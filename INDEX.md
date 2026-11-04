# Index

One entry point for everything in this repository. Generated from the tree by
`tools/build_index.py`, and checked by a test, so a stale link fails the suite instead
of rotting quietly.

**21 documents · 58 Python modules · 333 test cases · 6 other source files · 19,434 lines.**

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
| `python3 -m lab.economics.cli design` | four levers, two outcomes, and what the arithmetic says |
| `python3 -m lab.economics.cli axes` | capability, legitimacy, perception, dependency, and who owns them |
| `python3 -m lab.orchestrator.run_pipeline --write-report` | traffic pipeline end to end, synthetic data |
| `make -C lab/ingest check` | C++ bounded-queue self-test |
| `make -C bridge check JAVAC=javac JAVA=java` | Java bridge self-test |
| `make -C bridge run JAVAC=javac JAVA=java` | bridge reads scenarios.json, writes the report |
| `python3 tools/build_index.py --check` | verify this index matches the tree |

## Branches

| Branch | Holds |
| --- | --- |
| `main` | The written material, the archived material, and this generator. No lab, no pipeline. |
| `experimental` | This branch: the written material plus the lab and the bridge, and the generator. |
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
- [`lab/CONSTRAINT-AXES.md`](lab/CONSTRAINT-AXES.md): structure under it: every lever presses on exactly one of four constraints, and the four have
- [`lab/COUNTER-ANTI-FORENSICS.md`](lab/COUNTER-ANTI-FORENSICS.md): The base monitor in `lab/integrity/` catches an attacker who deletes, truncates, or edits
- [`lab/DEFENSE-ECONOMICS.md`](lab/DEFENSE-ECONOMICS.md): Four principles, each with a module that computes it rather than asserting it:
- [`lab/DESIGN-NOTES.md`](lab/DESIGN-NOTES.md): Design reasoning, including the rejected approaches.
- [`lab/ETHICS-AND-LIMITS.md`](lab/ETHICS-AND-LIMITS.md): What the lab will not build and why: attribution, probing, bait documents, manipulation.
- [`lab/INCENTIVE-DESIGN.md`](lab/INCENTIVE-DESIGN.md): You do not control someone's decision. You influence the conditions under which they make it.
- [`lab/INTEGRITY.md`](lab/INTEGRITY.md): Forensic-integrity monitor: channels, threat model, false positives, and the case that defeats it.
- [`lab/README.md`](lab/README.md): Orientation for the lab: what runs, what is verified, what is not.
- [`lab/RESPONSE-TIMING.md`](lab/RESPONSE-TIMING.md): Acting early is a decision. So is waiting. This is the arithmetic for both, taken from the same
- [`lab/TRUST-CHAIN.md`](lab/TRUST-CHAIN.md): Five properties, in the order they bind:
- [`lab/WEAKNESSES-AND-FIXES.md`](lab/WEAKNESSES-AND-FIXES.md): Known weaknesses and what was done about each.
- [`lab/__init__.py`](lab/__init__.py): Python module

**lab/canary/**

- [`lab/canary/listener.py`](lab/canary/listener.py): Stdlib callback listener that hashes the source address and stores no address.
- [`lab/canary/manifest.py`](lab/canary/manifest.py): Tamper detection where a missing or edited canary is the alert.
- [`lab/canary/tokens.py`](lab/canary/tokens.py): Canary token issuance and encoding.

**lab/crypto/**

- [`lab/crypto/__init__.py`](lab/crypto/__init__.py): The trust chain: five properties, each with code that enforces or checks it.
- [`lab/crypto/aesgcm.py`](lab/crypto/aesgcm.py): AES-256-GCM: the real cipher, and why it is here in pure Python.
- [`lab/crypto/archive.py`](lab/crypto/archive.py): Hash the envelopes into the ledger, so substitution at rest needs no key to catch.
- [`lab/crypto/boot.py`](lab/crypto/boot.py): Boot and firmware integrity: does the environment handling the plaintext deserve belief?
- [`lab/crypto/cli.py`](lab/crypto/cli.py): Demo for the trust chain: five properties, one report, honest about the holes.
- [`lab/crypto/envelope.py`](lab/crypto/envelope.py): Payload encryption and authenticated encryption: the envelope itself.
- [`lab/crypto/flow.py`](lab/crypto/flow.py): The whole chain in one pass: capture, seal, encrypt, ship, decrypt, verify.
- [`lab/crypto/keys.py`](lab/crypto/keys.py): Key protection: one master secret, purpose-separated subkeys, and an audit of custody.
- [`lab/crypto/model.py`](lab/crypto/model.py): The five properties, as a shared vocabulary.
- [`lab/crypto/seal.py`](lab/crypto/seal.py): Endpoint integrity: a source seal over the plaintext, verified at the sink.

**lab/data/**

- [`lab/data/__init__.py`](lab/data/__init__.py): Python module
- [`lab/data/synthetic.py`](lab/data/synthetic.py): Synthetic generators: no real traffic, no real people.

**lab/**

- [`lab/docker-compose.yml`](lab/docker-compose.yml): Local stack definition. Unverified here: no Docker in the sandbox.

**lab/economics/**

- [`lab/economics/__init__.py`](lab/economics/__init__.py): Defense economics: cost, resilience, adaptation, and proportionality with numbers.
- [`lab/economics/adaptation.py`](lab/economics/adaptation.py): Adaptation: each finding becomes a change that costs the attacker more next time.
- [`lab/economics/cli.py`](lab/economics/cli.py): Command line for the economics layer.
- [`lab/economics/constraints.py`](lab/economics/constraints.py): Four axes: what the adversary is actually being denied.
- [`lab/economics/discipline.py`](lab/economics/discipline.py): Win and loss discipline: bank the win, bill the loss.
- [`lab/economics/environment.py`](lab/economics/environment.py): Incentive design: change the conditions, not the decision.
- [`lab/economics/fingerprint.py`](lab/economics/fingerprint.py): Profiling the attacker in proportion to what they are getting out of you.
- [`lab/economics/model.py`](lab/economics/model.py): Defense economics: what a control costs, what it buys, and when the answer is "nothing".
- [`lab/economics/resilience.py`](lab/economics/resilience.py): Resilience: what survives, what you get back, and how long it takes.
- [`lab/economics/tiers.py`](lab/economics/tiers.py): The tier ladder: what an asset's value obliges you to run, and what it obliges you to skip.
- [`lab/economics/timing.py`](lab/economics/timing.py): When to act, priced instead of felt.

**lab/enrich/**

- [`lab/enrich/enrich.R`](lab/enrich/enrich.R): R enrichment with parameterised queries and a length-capped sanitiser.

**lab/features/**

- [`lab/features/__init__.py`](lab/features/__init__.py): Python module
- [`lab/features/contract.py`](lab/features/contract.py): The closed event vocabulary shared by every component.
- [`lab/features/pipeline.py`](lab/features/pipeline.py): Per-client feature engineering with MAD-based dispersion.

**lab/ingest/**

- [`lab/ingest/Makefile`](lab/ingest/Makefile): file
- [`lab/ingest/collector.hpp`](lab/ingest/collector.hpp): Bounded queue with counted drops and an explicit backpressure signal.
- [`lab/ingest/main.cpp`](lab/ingest/main.cpp): Ingestion self-test: saturates a small queue and fails on a hang rather than blocking.

**lab/integrity/**

- [`lab/integrity/__init__.py`](lab/integrity/__init__.py): Forensic-integrity monitoring: evidence-state tamper detection.
- [`lab/integrity/adversary.py`](lab/integrity/adversary.py): Scripted tampering used by the demo and the tests. Demo-only, throwaway paths.
- [`lab/integrity/af_demo.py`](lab/integrity/af_demo.py): Demo for the counter-anti-forensic layer.
- [`lab/integrity/cli.py`](lab/integrity/cli.py): Ten-scenario demo, including two controls and one documented limit.
- [`lab/integrity/counterforensics.py`](lab/integrity/counterforensics.py): Counter-anti-forensics: catching the adversary who read this repository.
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
- [`lab/tests/test_aesgcm.py`](lab/tests/test_aesgcm.py): Tests for AES-256-GCM: published vectors, differential testing, and failure modes.
- [`lab/tests/test_canary.py`](lab/tests/test_canary.py): Tests for the canary modules: tokens, tamper detection, callback listener.
- [`lab/tests/test_counterforensics.py`](lab/tests/test_counterforensics.py): Tests for the counter-anti-forensic layer.
- [`lab/tests/test_crypto.py`](lab/tests/test_crypto.py): Tests for the trust chain: five properties, each with a case that holds and one that fails.
- [`lab/tests/test_economics.py`](lab/tests/test_economics.py): Tests for the economics layer: arithmetic, proportionality, ladder, loop.
- [`lab/tests/test_enrich_r.py`](lab/tests/test_enrich_r.py): Verification for `lab/enrich/enrich.R`.
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
