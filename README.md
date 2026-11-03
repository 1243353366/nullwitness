# Data Deception and Legal Boundaries

*Repository: **nullwitness**. The title above is the subject, not the product name.
Read [`AUTHORS-NOTE.md`](AUTHORS-NOTE.md) first: most of what follows is assembly and
experimentation on existing ideas, not invention, and the note is explicit about which
parts are established, which are unvalidated, and which are deliberately speculative.*

A static, non-executing educational sandbox for discussing defensive data handling,
canary records, and the legal and ethical boundaries of data deception.

## What is in this repository on `main`

| Path | What it is |
| --- | --- |
| [`README.md`](README.md) | This file. |
| [`AUTHORS-NOTE.md`](AUTHORS-NOTE.md) | Where the ideas came from, what is borrowed, and what that means for how to read the rest. Worth reading before the technical material. |
| [`LEGAL.md`](LEGAL.md) | Legal and risk notes: the concepts a real response has to satisfy, and the questions to bring to counsel. |
| [`SAFETY.md`](SAFETY.md) | Safety boundaries: what this project will and will not discuss, acceptable defensive measures, and a decision framework. |
| [`examples/simulation-walkthrough.md`](examples/simulation-walkthrough.md) | A worked discussion of a fictional exposure scenario, from first question to a written decision record. |
| [`examples/scenarios.json`](examples/scenarios.json) | Three fictional scenarios in machine-readable form, for reuse in workshops or review exercises. |
| [`archive/README.md`](archive/README.md) | Notes on the archived code dumps described below. |
| [`archive/canary-check/`](archive/canary-check/) | Two historical, unmaintained code dumps. Not part of the lesson, not built, not working as stored. |
| [`LICENSE`](LICENSE) | CC0 1.0 Universal (public domain dedication) for the written material. |

`lab/` and `bridge/` do not exist on `main`. They live on the `experimental` branch and
are described at the end of this file.

## The educational material is static on `main`

Everything outside `archive/` on this branch is prose and one JSON file:

- no build step, package manifest, dependencies, or test suite
- no service, container, or deployment configuration
- no scripts to run and no setup instructions
- no network requests, and no interaction with any system
- examples are fictional text and JSON, for discussion only

Do not put real credentials, personal information, or confidential data in examples,
issues, or pull requests. The values in the examples are invented; `example.invalid`
is reserved for documentation and resolves nowhere.

The word "simulation" here means reading and discussing a fictional scenario. It does
not mean running a technical simulator.

The `experimental` branch breaks all five of those properties on purpose. That branch
is an engineering experiment with a build step, dependencies, tests, and containers;
this one is the written argument. Keep them separate and neither has to pretend.

## The one caveat: the archive

Earlier commits added code dumps that contradict the "nothing here runs" framing this
README used to state, so they are called out rather than hidden:

- `archive/canary-check/file-4tr.rs.txt` is not Rust. It is three programs (Rust, Go,
  Java) concatenated with shell-style comment banners, so it compiles in no language,
  and its Java section is truncated.
- `archive/canary-check/file1.python` (extracted from the former `project.zip`) is the
  same operation in Python, with no path validation or error handling.

Both look for a file named `attacker.txt` in the home directory and delete it, which
is detection evasion rather than defensive work, so neither is maintained, documented
as runnable, or connected to anything here. See [`archive/README.md`](archive/README.md)
for the reasoning. Treat them as historical artifacts, not as examples to follow.

## Experimental lab (separate branch)

The [`experimental` branch](https://github.com/1243353366/nullwitness/tree/experimental) carries an executable lab built on top of this
repository. `main` stays documentation only, exactly as described above: the prose here
states boundaries, and the lab is where those boundaries are enforced in code.

| Piece | Where | What it is |
| --- | --- | --- |
| Pipeline | [`lab/`](https://github.com/1243353366/nullwitness/tree/experimental/lab) | Behavioral analytics on telemetry from assets the operator controls: bounded C++ ingestion with backpressure, a TimescaleDB schema with retention and row-level security, per-client features, rolling temporal validation, drift monitoring, differential privacy primitives. Stores no addresses. |
| Canaries | [`lab/canary/`](https://github.com/1243353366/nullwitness/tree/experimental/lab/canary) | Token issuance, a stdlib callback listener, and tamper detection that treats a missing or edited canary as the alert. |
| Integrity | [`lab/integrity/`](https://github.com/1243353366/nullwitness/tree/experimental/lab/integrity) | Forensic-integrity monitor. Detects manipulation, destruction, suppression, and fabrication of evidence by comparing four independent channels instead of matching tool signatures. |
| Bridge | [`bridge/`](https://github.com/1243353366/nullwitness/tree/experimental/bridge) | Dependency-free Java. Reads [`examples/scenarios.json`](examples/scenarios.json), fails if a scenario claims an out-of-scope capability as authorized, emits events the lab consumes, and writes the lab's latest run back out as Markdown. |
| Scope | [`lab/ETHICS-AND-LIMITS.md`](https://github.com/1243353366/nullwitness/blob/experimental/lab/ETHICS-AND-LIMITS.md) | What the lab refuses to build, and why: cross-network identity attribution, active probing, bait documents, reflexive manipulation of a person. |
| Limits | [`lab/INTEGRITY.md`](https://github.com/1243353366/nullwitness/blob/experimental/lab/INTEGRITY.md) | Threat model for the integrity monitor, including the attacker who defeats it, and the false-positive policy that keeps it switched on. |

```bash
git checkout experimental

python3 -m lab.orchestrator.run_pipeline --write-report   # pipeline, synthetic data
python3 -m lab.integrity.cli demo                         # evidence-integrity demo
python3 -m unittest discover -s lab/tests -t .            # 68 tests
make -C lab/ingest check                                  # C++ ingestion self-test
make -C bridge check                                      # Java bridge self-test
```

The lab's numbers come from synthetic data with a known answer. They check that the
plumbing works, not that the model predicts anything, and
[`lab/DESIGN-NOTES.md`](https://github.com/1243353366/nullwitness/blob/experimental/lab/DESIGN-NOTES.md) does the base-rate arithmetic that
explains why.

## Topics

- Containing a suspected data exposure
- Revoking or rotating credentials through authorized processes
- Using clearly fictional canary records in systems you control
- Preserving evidence and documenting decisions
- Distinguishing defensive measures on your own systems from actions directed at
  external systems
- Where legal risk actually turns: control, authorization, and evidence handling

## Start here

1. [`SAFETY.md`](SAFETY.md) for the boundaries and the decision framework.
2. [`examples/simulation-walkthrough.md`](examples/simulation-walkthrough.md) for the
   fictional case worked end to end.
3. [`LEGAL.md`](LEGAL.md) before turning any of it into a real decision.

## Scope and disclaimer

This project is general education, not legal advice and not incident-response advice.
Laws and obligations vary by jurisdiction, contract, industry, and facts. Consult
qualified counsel and your organization's security and privacy teams before acting in
a real incident. If an exposure is in progress, follow your incident-response process
instead of this repository.

The examples do not establish that any particular measure is lawful. A measure
confined to systems you control may still raise privacy, employment, contractual,
regulatory, or evidence-handling issues.
