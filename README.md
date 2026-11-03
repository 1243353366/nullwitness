# Data Deception and Legal Boundaries

A static, non-executing educational sandbox for discussing defensive data handling,
canary records, and the legal and ethical boundaries of data deception.

## What is actually in this repository

| Path | What it is |
| --- | --- |
| [`README.md`](README.md) | This file. |
| [`LEGAL.md`](LEGAL.md) | Legal and risk notes: the concepts a real response has to satisfy, and the questions to bring to counsel. |
| [`SAFETY.md`](SAFETY.md) | Safety boundaries: what this project will and will not discuss, acceptable defensive measures, and a decision framework. |
| [`examples/simulation-walkthrough.md`](examples/simulation-walkthrough.md) | A worked discussion of a fictional exposure scenario, from first question to a written decision record. |
| [`examples/scenarios.json`](examples/scenarios.json) | Three fictional scenarios in machine-readable form, for reuse in workshops or review exercises. |
| [`archive/README.md`](archive/README.md) | Notes on the archived code dumps described below. |
| [`archive/canary-check/`](archive/canary-check/) | Two historical, unmaintained code dumps. Not part of the lesson, not built, not working as stored. |
| [`LICENSE`](LICENSE) | CC0 1.0 Universal (public domain dedication) for the written material. |

## The educational material is static

Everything outside `archive/` is prose and one JSON file:

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
