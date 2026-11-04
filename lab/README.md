# lab: experimental branch

The `experimental` branch turns the research dump in
[`source/nerdshit.md`](source/nerdshit.md) into something that runs, fails loudly, and
can be audited. It is built on top of `main`, which stays a documentation branch: prose,
one JSON file, and the index generator. Two files are shared with `main` rather than
copied, `tools/build_index.py` and the parts of `README.md` that describe both branches,
because an index that drifts between branches is worse than no index.

**Status: experimental.** Most layers are tested implementations with honest gaps:
the pipeline, the canaries, the integrity monitor, the trust chain, and the economics
all run and all have tests. Some parts of the source are deliberately not implemented,
and some single files are unverified for environmental reasons; both cases are stated
below rather than implied.

## What this is

A behavioral analytics pipeline for telemetry on assets the operator controls: your
own web surface, your own published canaries, your own feeds. It answers "does this
traffic look scripted", per client, per window, with validation that does not leak the
future into the past and monitoring that can be provoked into firing.

It is not an attribution system and does not try to identify a person. That was a
decision, not a limitation: see [ETHICS-AND-LIMITS.md](ETHICS-AND-LIMITS.md).

## Status by component

| Area | File | State |
| --- | --- | --- |
| Event contract | `features/contract.py` | tested |
| Synthetic data | `data/synthetic.py` | tested, deliberately overlapping |
| Feature engineering | `features/pipeline.py` | tested, regression-covered |
| Temporal validation | `model/temporal_cv.py` | tested, leakage assertion |
| Logistic baseline | `model/logistic.py` | tested |
| Reflexive belief update | `model/belief.py` | tested, convergence-checked |
| Monitoring (PSI, z-gate, shadow) | `model/monitor.py` | tested, poisoning probe |
| Privacy primitives | `privacy/dp.py` | tested, sequential composition only |
| Orchestration | `orchestrator/run_pipeline.py` | tested end to end |
| Canary tokens | `canary/tokens.py` | tested |
| Canary tamper detection | `canary/manifest.py` | tested |
| Canary callback listener | `canary/listener.py` | tested, live request in the suite; separates issued from probed tokens |
| Java bridge to `main` | `../bridge/` | compiled with `-Werror`, self-tested |
| Forensic-integrity monitor | `integrity/monitor.py` | tested, 10-scenario demo |
| Tamper-evident ledger | `integrity/ledger.py` | tested, forgery and rollback covered |
| Ingestion queue (C++) | `ingest/collector.hpp` | compiled and self-tested with g++ |
| Schema (SQL) | `schema/001_schema.sql` | applied twice against PostgreSQL 18.6; every statement outside the TimescaleDB extension succeeds |
| Enrichment (R) | `enrich/enrich.R` | parsed and run against PostgreSQL 18.6 (R 4.6.2, DBI 1.3.0, RPostgres 1.4.10) |
| Container run | `docker-compose.yml` | **unverified**, no Docker in the lab sandbox; the YAML parses, the role bootstrap runs against a live server, and the rest is asserted by `tests/test_pilot.py` |
| ONNX / INT8 edge inference | n/a | not implemented |
| Cross-network attribution | n/a | excluded, see ethics page |
| Active probing | n/a | excluded, see ethics page |

One file is still unverified, for an environmental reason: no Docker in the sandbox, so
`docker-compose.yml` is a definition rather than a running stack.

The other two were marked unverified for weeks and are now exercised, which is how four
defects surfaced in files nobody could run:

- `enrich.R` did not parse at all. A regex written as a literal range from `\u0000`
  fails, because R forbids a nul character in a string. The file had never executed.
- The same script's batch loop could not terminate. It called `enrich_batch(con)` with no
  cursor on every pass, so it re-read the first page forever and printed progress while
  writing nothing.
- `enrich.R` writes to `enrichment` and reads `semantic_anchors`, and neither table
  existed in `001_schema.sql`. The enrichment step could never have run against the
  schema it was written for.
- The schema was not re-runnable: `CREATE ROLE` failed on a second application, and a
  grant pointed at a sequence that does not exist.

All four are fixed and covered by `lab/tests/test_enrich_r.py`, which skips when R or a
database is absent rather than reporting a pass it did not earn. Run it against a live
instance with:

```bash
RSCRIPT=/path/to/Rscript \
LAB_VERIFY_DSN="host=/tmp port=5432 dbname=lab user=postgres" \
python3 -m unittest lab.tests.test_enrich_r -v
```

## Quickstart

```bash
# runs the whole pipeline on synthetic data and prints a report
python3 -m lab.orchestrator.run_pipeline --write-report

# every test, including regression tests for each bug fixed during the port
python3 -m unittest discover -s lab/tests -t . -v

# C++ ingestion self-test: saturates a bounded queue, aborts on deadlock
make -C lab/ingest check

# Java bridge: scope check against main's scenarios, event fixtures, doc summary
# needs a JDK 21 on PATH; override with JAVAC=/path/javac JAVA=/path/java
make -C bridge check
make -C bridge run

# forensic-integrity monitor: destruction, suppression, manipulation, fabrication
python3 -m lab.integrity.cli demo

# canary callback listener, with a token you can place in a document you own
python3 -m lab.canary.listener --jsonl lab/reports/canary_events.jsonl \
    --label vendor-export-2026-11 --port 8080
```

Example output from a clean run:

```
events=1800 clients=30 span_h=22.56
feature rows=30
expanding temporal CV: mean_auc=0.963 folds=[0.8889, 1.0, 1.0]
  rolling temporal CV: mean_auc=0.963 folds=[0.8889, 1.0, 1.0]
holdout auc=1.0 stability_psi=0.0051 holdout_psi=0.4811
shadow mean_divergence=0.0018 flagged=0/9
poisoning probe: clean=0.0018 noisy=0.1863 reacted=True
reflexive: naive=[0.0514, 0.8986, 0.0499] -> posterior=[0.2712, 0.4656, 0.2632] iters=2 converged=True
top features: channel_diversity=-1.1117, datacenter_share=1.0795, fp_stability=1.007, ...
```

Read those numbers carefully. They describe synthetic populations with a known answer
and a deliberate 30% overlap. They are a plumbing check, not a performance claim. The
base-rate arithmetic in [DESIGN-NOTES.md](DESIGN-NOTES.md) is the number that matters
before anyone deploys this.

## Layout

```
lab/
  source/nerdshit.md        the original document, converted and untouched
  README.md                 this file
  ARCHITECTURE.md           layers, event contract, how to run
  DESIGN-NOTES.md           what is established, heuristic, or guess
  WEAKNESSES-AND-FIXES.md   every bug in the source and the test that covers it
  ETHICS-AND-LIMITS.md      what was not built and why
  features/                 event contract, feature engineering
  data/                     synthetic generators
  model/                    logistic baseline, temporal CV, belief update, monitors
  privacy/                  differential privacy primitives, suppression
  orchestrator/             deterministic end-to-end run
  canary/                   token issuance, tamper detection, callback listener
  integrity/                evidence-state monitor: ledger, detectors, adversarial demo
  INTEGRITY.md              threat model, channels, false-positive policy, limits
  COUNTER-ANTI-FORENSICS.md the adversary who read this repo: techniques, detectors, limits
  TRUST-CHAIN.md            the five properties: encryption, authentication, keys, boot, endpoint
  crypto/aesgcm.py          AES-256-GCM; NIST test vectors plus differential testing, constant-time only via the library
  crypto/archive.py         envelope digests chained into the integrity ledger
  DEFENSE-ECONOMICS.md      asymmetry, proportionality, resilience, adaptation with numbers
  economics/                the same four as code: tiers, cost model, profiling depth, the loop
  economics/timing.py       act now or hold, priced against the evidence a tip-off would cost
  RESPONSE-TIMING.md        CISA's containment considerations, made executable
  economics/environment.py  incentive design: the conditions, not the decision
  INCENTIVE-DESIGN.md       levers, substitution, and where deterrence ends and manipulation starts
  economics/constraints.py  capability, legitimacy, perception, dependency: who owns each axis
  CONSTRAINT-AXES.md        the four, priced by margin, and why they do not add up
  tests/                    the whole suite, unittest only, no pytest needed
  ingest/                   C++ bounded queue, Makefile, self-test
  schema/                   TimescaleDB schema, RLS, rollup view
  enrich/                   R enrichment with parameterized queries
  docker-compose.yml        TimescaleDB plus a pipeline runner
  ../bridge/                Java bridge: main's scenarios -> lab events -> docs summary
```

## The integrity half

`lab/integrity/` detects tampering with the *evidence-producing environment*, not with a
list of known tools. It keeps four channels that fail differently when attacked (an
HMAC chain, file digests, filesystem metadata, and the collector's own status) and
reports a finding when they stop agreeing. Deletion, truncation, backdating, clock
movement, forgery, and a silenced collector each surface with the channels that
corroborate them.

`lab/COUNTER-ANTI-FORENSICS.md` assumes the adversary read this repository and turns its
own deception around. `lab/integrity/counterforensics.py` catches those techniques by
naming the quantity each one cannot conserve, and shows the ones it cannot catch.

`lab/INTEGRITY.md` carries the threat model, including the case that defeats it: root on
the endpoint with the anchor and key on the same host. That scenario is a test, not a
footnote.

```bash
python3 -m lab.integrity.cli demo
```

## The canary half

`lab/canary/` is the detection side of the canary idea, which is the half that holds
up: mint a token, put it somewhere you control, log the callback, and treat a missing
or edited canary file as an alert rather than as background noise.

- `tokens.py` issues deterministic token ids from `(label, salt epoch)` so rotation is
  an epoch change, and verifies that a callback carries a token you actually issued.
- `listener.py` is a stdlib HTTP listener. It hashes the connecting address with the
  salt epoch and writes one contract event per callback. It stores no address, sets no
  cookie, serves no script, and sends no body.
- `manifest.py` snapshots digests and reports missing, modified, and added files. Its
  findings become events attributed to your own host, so tamper signal and access
  signal land in one stream.

What is not here: decoy documents, tracking pixels, or anything that makes a request
happen without the visitor acting. A token is a string; where it goes and what notice
accompanies it is the operator's call and the operator's obligation.

## Disclosure

Every audit turns up things it did not fix, and a document that lists only its
achievements is a marketing page. This section is the list of what is still wrong or
still untested, written where a reader deciding whether to trust the code will find it.
It is checked by `tests/test_pilot.py`, so it cannot quietly disappear.

### What the oracle pass found, and what it did not fix

An oracle here means any observable that differs between two rejections, which is a
question answered for free. The rejections in `crypto/envelope.py` all returned
different text: too short, unknown version, unknown backend, wrong key. Each of those
tells a prober how far their guess got, and "wrong key" versus "modified byte" is the
shape that turns a cipher into a decryption service. They are now one sentence, with the
specifics in an exception attribute that is for local logs, not for a wire.

What that fix does not do:

- **Uniform text is not uniform time.** The message is identical on every path; the
  machine is not. `crypto/aesgcm.py` is a table-based AES and a bit-loop GHASH, so the
  pure-Python fallback leaks through cache and instruction timing, which is exactly why
  it is a fallback. The `cryptography` path is constant-time and is what anything exposed
  should use. An attacker who can measure decryption latency against the stdlib path can
  still separate cases that the error message refuses to separate.
- **The detail attribute is an oracle if somebody serialises it.** `Tampered.detail`,
  `Replay.detail`, and the exception class names contain exactly the information the
  public message withholds. The lab's own paths never put them on a response, and a
  caller that wraps these exceptions into JSON undoes the fix. That is a property of the
  caller, and no amount of work in this module can enforce it.
- **Verification remains a partial oracle by design.** `integrity/ledger.py` reports
  which entry failed and how (`forged`, `truncated`, `gap`, `reordered`). That is the
  operator's diagnosis and it is deliberately precise. It must not be handed to whoever
  is being investigated.
- **`canary_probe` depends on the operator telling the listener what it issued.** If
  `--known-label` is not passed, real hits get recorded as probes. The listener cannot
  derive labels without them, and a default of "assume everything is issued" would
  restore the forging problem this change removes. Between a false negative and a signal
  anyone can raise, this picks the false negative and says so.
- **`latency_ms` is still a placeholder.** The listener writes `0.0`. Nothing downstream
  depends on it, but a feature that reads it will read a constant.

### What the pilot pass found, and what is still unverified

The pilot stack is `docker-compose.yml`: TimescaleDB with the schema applied, plus a
one-shot pipeline runner. It could not have worked. It told the runner to authenticate as
`lab_analysis`, and the schema creates that role `NOLOGIN`, so no password would ever
have been accepted. It published Postgres on every interface. Its readiness check asked
only whether the socket was open, which is the wrong question on a volume from an older
schema: the server is healthy and the tables are missing.

Those are fixed: the runner gets no credentials it does not use, `schema/002_pilot_roles.sh`
grants `LOGIN` to the least-privilege roles only when a password is supplied, the port
binds to loopback, and readiness waits for the schema's own tables. Fixing the bootstrap
found a second defect in the fix itself: `psql -c` does not interpolate `-v` variables, so
the first version failed on a bare colon instead of granting anything, which is why that
script is now tested against a live server with a password containing a quote.

Still unverified or uncovered:

- **No Docker daemon in the lab sandbox.** The stack has never been brought up. The YAML
  parses, the role bootstrap runs against a real PostgreSQL 18.6, and `tests/test_pilot.py`
  asserts the properties the file claims. None of that is the same as `up` returning a
  working database, and the honest status is still **unverified**.
- **The enrichment step is not in the stack.** `enrich/enrich.R` needs R with DBI and
  RPostgres plus a libpq client; the runner image is `python:3.12-slim`. It is documented
  as a host step because shipping it as a service would mean an image that starts and then
  fails at the last step. The database therefore has no in-stack writer: the pilot proves
  the schema applies, not that the enrichment loop closes.
- **The image tag is mutable.** The default is `timescale/timescaledb:latest-pg16`, which
  is a pilot convenience and a reproducibility problem. It is pinnable via
  `TIMESCALE_IMAGE`, and nothing forces you to pin it.
- **No TLS between the runner and the database**, no backup, no retention policy, and no
  restore test. Postgres on loopback with a password in an env file is a laptop posture;
  it is not a deployment posture.
- **Init scripts run once.** An existing `timescale-data` volume keeps whatever the schema
  and roles were on first init. There are no migrations, so a changed schema on a live
  volume is invisible until something queries a column that is not there.
- **The C++ ingestion collector is not in the stack.** Nothing in the composed pilot
  writes to the database, so end-to-end ingest is exercised by `make -C lab/ingest check`
  alone.

## Relationship to `main`

`main` is the static educational sandbox: prose about defensive data handling and the
legal boundaries of data deception. This branch is the part where the ideas are
turned into code, which is exactly what that repo's own safety page says it does not
do. So the branch keeps the same boundaries in a different form: the lab is scoped to
assets you control, it stores no addresses, and it refuses the parts of the source
that would point at people.

If the experiment stops being useful, deleting the branch deletes the lab. `main` keeps
its own copies of the prose and the generator, so it loses nothing but the links into
this branch, and its `INDEX.md` regenerates without them.
