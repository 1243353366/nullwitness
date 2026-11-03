# Architecture

Six layers, one event contract, no hidden coupling. Every layer can be replaced
without touching the others, which is the only reason the whole thing is worth
structuring.

```
                 ┌──────────────────────────┐
   own assets    │  L1 ingest (C++)         │  bounded queue, backpressure,
   only ────────►│  lab/ingest/             │  drop counters, no network client
                 └───────────┬──────────────┘
                             │ EventRecord
                 ┌───────────▼──────────────┐
                 │  L2 store + enrich       │  TimescaleDB hypertable,
                 │  lab/schema/ lab/enrich/ │  parameterized SQL, retention,
                 └───────────┬──────────────┘  RLS, k-anon rollup view
                             │
                 ┌───────────▼──────────────┐
                 │  L3 features (Python)    │  per-client aggregates only,
                 │  lab/features/           │  robust dispersion, cadence,
                 └───────────┬──────────────┘  diversity, entropy
                             │ FeatureRow
                 ┌───────────▼──────────────┐
                 │  L4 model                │  logistic baseline, reflexive
                 │  lab/model/              │  belief update, temporal CV
                 └───────────┬──────────────┘
                             │ scores + confidence
                 ┌───────────▼──────────────┐
                 │  L5 orchestration        │  one deterministic run,
                 │  lab/orchestrator/       │  JSON report artifact
                 └───────────┬──────────────┘
                             │ report
                 ┌───────────▼──────────────┐
                 │  L6 monitoring           │  PSI drift, volatility gate,
                 │  lab/model/monitor.py    │  shadow divergence, DP aggregates
                 └──────────────────────────┘
```

## The bridge to `main`

`main` authors policy in prose: which assets an operator controls, which actions sit
inside their authority, which do not. `bridge/` is a dependency-free Java program that
reads those scenarios, fails when a scenario claims an excluded capability as
authorized, converts the documented assets into contract events, and writes the lab's
latest report back out as Markdown. That makes the documentation a checked artefact
instead of a paragraph, and keeps the two branches from drifting apart silently.

Key derivation is implemented twice, once in Java and once in Python, and the bridge
self-test asserts they agree byte for byte. A contract with one implementation is a
convention; with two, it is a test.

## The event contract

`lab/features/contract.py` is the stable interface. Every layer speaks it.

| Field | Type | Why it exists |
| --- | --- | --- |
| `event_id` | uuid string | idempotency, dedupe |
| `observed_at` | float epoch seconds, UTC | the only ordering key; partition key |
| `source_id` | string | which owned asset produced the record |
| `client_key` | 16 hex chars | salted, truncated hash; no address is stored |
| `channel` | closed vocabulary | `feed_item`, `canary_access`, `honeytoken_access`, `site_visit` |
| `protocol` | closed vocabulary | `http/1.1`, `h2`, `h3`, `unknown` |
| `ua_family` | closed vocabulary | coarse classification, not the raw header |
| `fingerprint_hash` | string | salted hash of a TLS/HTTP fingerprint, stable within a salt epoch |
| `network_class` | closed vocabulary | `residential`, `mobile`, `datacenter`, `unknown`, derived from published cloud ranges |
| `bytes_in`, `latency_ms` | numbers | request shape and pace |
| `labels` | mapping | provenance, population tag in synthetic data, nothing personal |

Two rules are enforced by `validate()` and by tests: no free-text personal data, and no
unbounded vocabulary. A closed vocabulary is what keeps the feature vector stable and
the privacy surface small; a free-text `user_agent` field would be neither.

## Layer responsibilities

### L1 ingest (`lab/ingest/`)

Bounded MPSC queue, producer/worker split, `try_push` drops counted, backpressure
counter at 80% fill, graceful `close()`. Ships a `CountingSource` for the self-test and
a `FeedSource` interface for real sources. There is no HTTP client in this repository
on purpose: the layer that talks to a feed is the layer that decides what a feed is,
and that belongs to whoever deploys it, with their own egress policy.

### L2 store and enrich (`lab/schema/`, `lab/enrich/`)

Plain table converted with `create_hypertable()`, primary key `(observed_at, event_id)`,
one-day chunks, compression after 7 days, retention at 30 days, RLS on both tables, a
read-only analysis role, and a materialized rollup with a 5-client floor. The R script
uses `dbBind` for every value and caps input length.

### L3 features (`lab/features/`)

Per-client aggregates over a window: cadence, dispersion, diversity, entropy,
protocol and network mix, payload and latency stability. Two properties matter:

- **Aggregate only.** No feature identifies a person. `fingerprint_hash` groups
  sessions within a salt epoch; rotating the epoch severs the grouping.
- **Robust by default.** `robust_cv` uses median absolute deviation, and
  `clockwork_share` is interval-based. The naive `std/mean` variant that the source
  proposed is kept in the test suite as a counter-example.

### L4 model (`lab/model/`)

`logistic.py` is a deterministic numpy logistic regression with L2, plus rank-based
AUC. `temporal_cv.py` builds ordered, non-overlapping folds and asserts that no
training row is newer than a test row. `belief.py` is the reflexive update described in
[WEAKNESSES-AND-FIXES.md](WEAKNESSES-AND-FIXES.md).

### L5 orchestration (`lab/orchestrator/`)

One deterministic run: validate, featurize, validate temporally two ways, fit a final
model, compute drift, run the poisoning probe, spend a small privacy budget on the
published aggregate, and write `lab/reports/last_run.json`. The report is the
interface; the console output is a convenience.

### Detection half: canaries (`lab/canary/`)

Token issuance, a stdlib callback listener, and a tamper manifest. The listener takes
a request, hashes the source with the salt epoch, and appends one contract event. The
manifest compares current digests against a snapshot and reports missing, modified,
and added files as events attributed to the operator's own host. Both feed the same
pipeline, which is the point: access signal and tamper signal in one schema.

### Evidence integrity (`lab/integrity/`)

A parallel subsystem, not a layer of the traffic pipeline. It answers a different
question: not "what is this visitor doing" but "is the environment that produces our
evidence still self-consistent". Four channels (HMAC-chained checkpoints, file digests,
filesystem metadata, collector status) are compared, and findings are graded by how many
independent channels agree. Same discipline as the rest of the lab: thresholds are
policy, negative controls are tested, and the failure case is documented rather than
hidden.

### L6 monitoring (`lab/model/monitor.py`)

Three independent jobs kept independent: drift (PSI), per-observation volatility gate
(z-score against a baseline), and shadow divergence between two feature views. The
positivity probe in the orchestrator corrupts 25% of training labels to prove the
shadow monitor moves when the input is wrong.

## Running it

```bash
# python layers, synthetic data, no services required
python3 -m lab.orchestrator.run_pipeline --write-report

# unit and regression tests
python3 -m unittest discover -s lab/tests -t . -v

# C++ ingestion self-test (saturates a real queue, fails on hang)
make -C lab/ingest check

# optional: database and containerised run
cp lab/.env.example lab/.env      # then edit
docker compose -f lab/docker-compose.yml up --build
```

`docker compose` and the SQL file are **unverified in the lab sandbox**, which has no
Docker daemon, no PostgreSQL server, and no R. They are written to be reviewed and
run elsewhere. The Python and C++ paths are executed by the test suite on every run.

## Deliberate omissions

- No network client, no feed adapters, no credentials handling beyond environment
  variables.
- No client-side beacon, document generator, or PDF payload.
- No geolocation, reputation, or OSINT enrichment calls: enrichment is derived from
  data already in the database, which keeps the pipeline offline and reproducible.
- No cross-network identity resolution. See [ETHICS-AND-LIMITS.md](ETHICS-AND-LIMITS.md).
