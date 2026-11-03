# bridge: Java glue between the documentation and the lab

`main` states boundaries in prose. The lab enforces them in code. Nothing checked that
the two agreed, so this module does three jobs and no more:

1. **Reads** [`examples/scenarios.json`](../examples/scenarios.json) from the repository
   root. Those scenarios are the authored policy: for each case, which assets the
   operator controls, which options sit inside their authority, and which do not.
2. **Refuses** to proceed if a scenario lists an option the lab has declared out of
   scope (touching a recipient's account or storage, active probing, geolocation,
   de-anonymization, tracking beacons) as being inside the operator's authority. A
   contradiction exits with status 2 and names the scenario and the option.
3. **Translates** each documented asset into contract-compliant lab events, and writes
   the lab's latest report back out as a Markdown table the docs can include.

Java is the bridge because it is the component least likely to be mistaken for the
pipeline: no model, no heuristics, no decisions about behaviour, and deleting it
leaves the lab intact. Plain JDK 21, no dependencies, no network.

## Usage

```bash
make check    # compile with -Xlint:all -Werror and run the self-test
make run      # boundary check, emit events, refresh lab/reports/SUMMARY.md
```

Both targets run from the repository root, because the paths they touch are
repository-relative.

```bash
cd ..
java -cp bridge/out lab.bridge.Bridge --selftest
java -cp bridge/out lab.bridge.Bridge \
    --scenarios examples/scenarios.json \
    --emit lab/reports/scenario_events.jsonl \
    --summary lab/reports/last_run.json \
    --summary-out lab/reports/SUMMARY.md
```

The emitted JSONL is a drop-in input for the lab:

```bash
python3 -m lab.orchestrator.run_pipeline --jsonl lab/reports/scenario_events.jsonl \
    --min-events 5 --folds 2 --write-report
```

Expect `Temporal CV: skipped` there. Six documented assets cannot support ordered
folds, and the pipeline says so instead of raising. That is the correct outcome for a
fixture: it proves the contract is wired end to end, not that anything is predictive.

## What the self-test covers

- JSON round trip including escapes and unicode, and rejection of malformed input
  (trailing commas, missing colons, bare words).
- The three real scenarios parse without error.
- The authored boundary agrees with the lab's scope, and two synthetic violations are
  caught: an excluded capability claimed as authorized, and a scenario with no
  out-of-authority option documented at all.
- Event count matches documented assets times observations per asset.
- Key derivation is byte-identical to `contract.derive_client_key` in Python, checked
  against an independent implementation so a change on one side fails here.

The last one is the reason this file exists in a language nobody would otherwise pick:
two implementations of one rule, cross-checked, is the only way the bridge can be
trusted to speak the same contract as the pipeline.
