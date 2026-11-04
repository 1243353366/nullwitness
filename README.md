# Data Deception and Legal Boundaries

*Repository: **nullwitness**. The title above is the subject, not the product name.*

**Everything in one place: [`INDEX.md`](INDEX.md)**, a generated entry point listing every
document, module, and command. `python3 tools/build_index.py --check` fails if it no longer
matches the tree, and on the `experimental` branch the test suite enforces the same thing
on every run, so it cannot silently go stale.
Read [`AUTHORS-NOTE.md`](AUTHORS-NOTE.md) first: most of what follows is assembly and
experimentation on existing ideas, not invention, and the note is explicit about which
parts are established, which are unvalidated, and which are deliberately speculative.*

A static educational sandbox for discussing defensive data handling, canary records,
and the legal and ethical boundaries of data deception. Nothing here collects, transmits,
or acts on data; the only thing that executes is the index generator described below.

## What is in this repository on `main`

| Path | What it is |
| --- | --- |
| [`README.md`](README.md) | This file. |
| [`INDEX.md`](INDEX.md) | Generated entry point: every document, module, and runnable command in one page. |
| [`tools/build_index.py`](tools/build_index.py) | The only executable file on this branch. Regenerates `INDEX.md` from the tree, no dependencies. |
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

Everything outside `archive/` on this branch is prose, one JSON file, and one generator:

- no package manifest, no dependencies, no test suite
- one executable file, `tools/build_index.py`, which writes `INDEX.md` and nothing else.
  It reads the tree and prints a table; it is the reason this page can be trusted to list
  what is here
- no service, container, or deployment configuration
- no setup instructions. The only command is `python3 tools/build_index.py --check`, which
  fails if `INDEX.md` does not match the tree
- no network requests, and no interaction with any system
- examples are fictional text and JSON, for discussion only

Do not put real credentials, personal information, or confidential data in examples,
issues, or pull requests. The values in the examples are invented; `example.invalid`
is reserved for documentation and resolves nowhere.

The word "simulation" here means reading and discussing a fictional scenario. It does
not mean running a technical simulator.

The `experimental` branch breaks every one of those properties on purpose. That branch
is an engineering experiment with a build step, dependencies, tests, and containers;
this one is the written argument. Keep them separate and neither has to pretend.

The generator is the one file the two branches share: it is identical on both, and it
has to be, because it is what stops either branch's `INDEX.md` from drifting.

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
| Trust chain | [`lab/crypto/`](https://github.com/1243353366/nullwitness/tree/experimental/lab/crypto) | The five properties that decide whether an encrypted record means anything: payload encryption, authenticated encryption, key protection, boot and firmware integrity, endpoint integrity. AES-256-GCM envelope with the stream and sequence bound into the AAD, HKDF purpose-separated subkeys, measured-boot attestation with anti-rollback, a source seal that pins where a change happened, and envelope digests chained into the integrity ledger so substitution is caught without a decryption key. |
| Four axes | [`lab/economics/constraints.py`](https://github.com/1243353366/nullwitness/blob/experimental/lab/economics/constraints.py) | Capability, legitimacy, perception, dependency: the constraints the levers actually press on, priced by marginal contribution rather than in isolation, with the owner of each axis named. Three of the four are not fully yours to move, and the module reports which require someone else's hand. |
| Incentive design | [`lab/economics/environment.py`](https://github.com/1243353366/nullwitness/blob/experimental/lab/economics/environment.py) | You do not control a decision, you change the conditions it is made in. Levers priced by mechanism (payoff, latency, visibility, cost, consequence), saturating instead of stacking, with `cheapest_flip` to stop spending once the decision moves and a gate that refuses the same machinery aimed at your own people. Two of the levers are written down and permanently refused, because they target the operator's own staff rather than the adversary. |
| Response timing | [`lab/economics/timing.py`](https://github.com/1243353366/nullwitness/blob/experimental/lab/economics/timing.py) | When to act and when to hold, priced rather than felt: bleed rate against evidence forfeited, tactics shift, and self-inflicted loss, with `hold` as the baseline every other action is measured against. CISA's containment considerations, made executable, including the maturity gate on sandbox redirection. |
| Win and loss discipline | [`lab/economics/discipline.py`](https://github.com/1243353366/nullwitness/blob/experimental/lab/economics/discipline.py) | A win changes nothing by default and may justify exactly one change, only if it pays for itself; an ego move is refused outright. A loss must cost the attacker something and leave reusable leverage, or it is recorded as wasted. `cost_imposed_per_damage` is the exchange rate that says whether the position is actually improving. |
| Defense economics | [`lab/economics/`](https://github.com/1243353366/nullwitness/tree/experimental/lab/economics) | Tiers, cost, and the four principles that keep the rest proportionate: economic asymmetry (attacker return, with maintenance priced as the recurring lever), proportionality (benefit versus cost, per control and per asset), resilience (what survives and what recovers), adaptation (each finding becomes a measured change, idempotently). |
| Counter-anti-forensics | [`lab/integrity/counterforensics.py`](https://github.com/1243353366/nullwitness/tree/experimental/lab/integrity/counterforensics.py) | The same deception turned around: an adversary who read this repository, and the detectors that catch each technique by naming the quantity it cannot conserve. Decoy-aware precision, sub-tolerance clock walking, laundered rotation, stolen keys, planted histories. |
| Limits | [`lab/INTEGRITY.md`](https://github.com/1243353366/nullwitness/blob/experimental/lab/INTEGRITY.md) | Threat model for the integrity monitor, including the attacker who defeats it, and the false-positive policy that keeps it switched on. |
| Disclosure | [`lab/README.md`](https://github.com/1243353366/nullwitness/blob/experimental/lab/README.md#disclosure) | What the lab still gets wrong. Uniform error text that does not buy uniform timing, details that are an oracle if a caller serialises them, verification that is precise on purpose, and a pilot stack that has never been started because the sandbox has no Docker daemon. Kept honest by a test, not by good intentions. |

```bash
git checkout experimental

python3 -m lab.orchestrator.run_pipeline --write-report   # pipeline, synthetic data
python3 -m lab.integrity.cli demo                         # evidence-integrity demo
python3 -m unittest discover -s lab/tests -t .            # the whole suite
python3 -m lab.integrity.af_demo                          # counter-anti-forensics demo
python3 -m lab.crypto.cli demo                            # trust chain, five properties
python3 -m lab.economics.cli demo                         # tiers, cost, resilience, adaptation
make -C lab/ingest check                                  # C++ ingestion self-test
make -C bridge check                                      # Java bridge self-test, needs a JDK on PATH
```

The lab's numbers come from synthetic data with a known answer. They check that the
plumbing works, not that the model predicts anything, and
[`lab/TRUST-CHAIN.md`](https://github.com/1243353366/nullwitness/blob/experimental/lab/TRUST-CHAIN.md) is the one to read before quoting any of this as "encrypted": it
separates what the ciphertext guarantees from what the endpoint does, and says which property
each finding belongs to.

[`lab/COUNTER-ANTI-FORENSICS.md`](https://github.com/1243353366/nullwitness/blob/experimental/lab/COUNTER-ANTI-FORENSICS.md) covers the symmetric case: an adversary who read
this repository and uses its own deception against it, which techniques that buys them,
and which quantity each technique cannot keep consistent.

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
