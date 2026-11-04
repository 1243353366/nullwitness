# Weaknesses and fixes

The source dump contains a weakness review of its own architecture. This page records
what was wrong, what the fix is in this branch, and which test proves the fix works.
Every claim below is backed by a command you can run.

| Weakness in the source | Root cause | Fix in this branch | Proof |
| --- | --- | --- | --- |
| Ingestion deadlock / dropped data | unbounded `std::queue`, one mutex, waits without predicates | bounded queue with predicates, `push` blocks, `try_push` counts drops, backpressure signal, `close()` unblocks everyone | `make -C lab/ingest check` |
| TimescaleDB composite key | `PRIMARY KEY (observation_id, observed_at)` on a table also declared `PARTITION BY RANGE` | plain table, `create_hypertable()`, primary key `(observed_at, event_id)` with the time column first | `lab/schema/001_schema.sql` |
| SQL injection through semantic anchors | `paste0()` string building in R around attacker-controlled text | `DBI::dbBind` everywhere, input sanitized and capped, analysis role has no DDL | `lab/enrich/enrich.R` |
| Reflexive adjustment produces invalid states | `1 - impact` can be negative, division by a zero sum, no simplex projection, no convergence check | attenuation bounded by `tanh`, convex displacement blend, floor + renormalize, iteration to a verified fixed point | `python3 -m unittest lab.tests.test_lab.BeliefTests` |
| Jitter "signature" is numerically unstable | `std/mean` on inter-arrival gaps blows up as the mean approaches zero | MAD-based robust dispersion, plus a clockwork-share feature that is interval-based | `FeatureTests.test_robust_cv_survives_tight_gaps_where_std_over_mean_explodes` |
| Drift detection is unusable on classifier output | PSI with quantile bins over scores that saturate at 0.0 and 1.0 | equal-width bins with Laplace smoothing, quantile mode kept for continuous quantities | `MonitorTests.test_psi_does_not_explode_on_saturated_scores` |
| Shadow model is decorative | two models on identical inputs agree by construction | shadow trains on a disjoint feature view; a controlled label-corruption probe shows the divergence move | `MonitorTests.test_shadow_flags_more_when_labels_are_corrupted` |
| Temporal validation leaks | k-fold shuffling over time series | ordered, non-overlapping folds with an assertion that training never reaches the test window | `TemporalValidationTests` |
| Enrichment layer cannot run at all | `enrich.R` writes to `enrichment` and reads `semantic_anchors`, and neither table was ever created by `001_schema.sql` | both tables added with the indexes the queries need, and the sanitiser's length cap enforced by a CHECK constraint | `python3 -m unittest lab.tests.test_enrich_r` |
| Enrichment script never parsed | regex written as a literal `\u0000` range, which R rejects in a string literal | `\p{Cc}\p{Cf}` classes, which also catch the zero-width characters worth worrying about | `StaticTests.test_no_nul_escape_in_a_string_literal` |
| Enrichment loop could not terminate | batch paging called with no cursor, so every pass re-read the same page | cursor advances on `event_id`, the ordering column, and the loop breaks on a non-advancing cursor | `DatabaseTests.test_paging_inserts_once_and_terminates` |
| "Quantize to INT8 and deploy on kernel inspection rigs" | no model, no export, no measurement | not implemented; a numpy logistic regression that trains in under a second and reports real AUC | `python3 -m lab.orchestrator.run_pipeline` |

## The three that mattered

### 1. The ingestion queue

A `std::queue` behind one mutex, with `wait()` calls that take no predicate, deadlocks
the first time a notify lands between a producer's unlock and a consumer's wait. The
symptom in production is not an exception, it is a process that stops consuming while
the health check still passes.

The replacement uses predicates on both condition variables, a real bound, and a drop
counter. Two design choices differ from the source's fix:

- The source proposed `boost::lockfree::queue`. Lock-free removes lock contention,
  which was not the failure mode. The failure mode was unbounded memory under
  sustained overload, and a lock-free queue that drops silently makes that *harder*
  to see. `try_push` returning false is the useful signal.
- Backpressure is counted, not just logged. `fill_ratio() >= 0.80` raises a
  `backpressure_signals` counter that maps directly onto a Prometheus gauge, and the
  producer sheds with a 200 microsecond pause instead of blocking forever on a feed
  that never drains.

The self-test saturates a 64 slot queue with 20,000 records and asserts that
`pushed + dropped == total`, that `consumed == pushed`, that the high-water mark was
published, and that backpressure fired. A watchdog aborts the run if any of that
turns into a hang, so a deadlock fails the build.

### 2. The hypertable primary key

Two partitioning schemes were stacked: `PARTITION BY RANGE (observed_at)` declares a
native partitioned table, and `create_hypertable()` expects a plain table to convert.
Only one can win, and the error it produces points at the wrong line.

The second half of the bug is subtler: TimescaleDB requires the partitioning column in
every unique index. `PRIMARY KEY (observation_id, observed_at)` happens to satisfy
that, but only by accident of ordering. `(observed_at, event_id)` states the intent,
and the index is useful for the queries the pipeline actually runs: time-bucketed
rollups and per-client recency.

Retention and compression are in the schema file. A behavioral observation table
without a retention policy is a growing liability, and the source's own privacy
section argues for one.

### 3. The reflexive adjustment

The original:

```python
anti = 1.0 - impact_vector      # negative entries as soon as impact > 1
anti /= anti.sum()              # ZeroDivisionError, or a negative "probability"
adjustment = 0.4 * naive_posterior + 0.6 * anti   # no justification for the weights
return adjustment / adjustment.sum()              # no floor, no convergence test
```

Four distinct failures: invalid probability states, undefined division, a blend of two
distributions that is not the thing being modelled, and a procedure claimed to be an
adjustment that is executed exactly once.

The replacement models the *displacement* the evidence produced and attenuates it:

```python
displacement = naive - prior
posterior = normalize(prior + attenuation * displacement)
```

with `attenuation = 1 - tanh(beta * (benefit - theta))`, which is bounded in `[0, 1)`
above the threshold, smooth at it, and strictly contractive, so the loop converges.
The loop runs to a tolerance and reports whether it did. The tests cover the below
threshold case, the attenuation direction, simplex membership under extreme benefit,
and convergence.

This is a model of analyst caution, not a theory of adversary cognition. See
[DESIGN-NOTES.md](DESIGN-NOTES.md) for what is and is not claimed.

## Deliberately not fixed, because it should not exist

The source also proposes active probing, cross-VPN fingerprint attribution, and bait
documents impersonating public records. Those are excluded by scope rather than
pending work; the reasoning is in [ETHICS-AND-LIMITS.md](ETHICS-AND-LIMITS.md).
