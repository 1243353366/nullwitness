# Design notes: what is established, what is a heuristic, what is a guess

The source dump mixes three very different kinds of claim without marking them. This
page marks them, because a pipeline whose parts have unknown epistemic status is not
auditable.

## Status of each component

| Component | Status | Notes |
| --- | --- | --- |
| Inter-arrival cadence features | Established practice | Used widely in bot and scraper detection. Effective against undirected automation, weak against anyone who has read the same literature. |
| MAD-based robust dispersion | Established statistics | Standard robust estimator; the right tool for heavy-tailed timing data. |
| Clockwork share (interval regularity) | Reasonable heuristic | Sensitive to polling loops, blind to jittered scripts, which is why it is one feature and not the model. |
| Rolling-window temporal validation | Established, mandatory | Any other split leaks future information into training and inflates every metric. |
| Population Stability Index | Established heuristic | Not a statistical test, no p-value, no threshold that generalizes. Treat 0.25 as a prompt to look, not a verdict. |
| Logistic regression baseline | Established | Chosen because it trains in a second, its coefficients are readable, and it cannot hide a plumbing error behind capacity. |
| Shadow-model divergence | Engineering heuristic | Detects gross label corruption. Not a defense against a careful adversary, and not certified against anything. |
| Laplace mechanism, sequential composition | Mathematically sound primitive | The budget accounting here is sequential only. Parallel composition and per-query sensitivity are the operator's job. |
| k-anonymity cell suppression | Weak guarantee | Prevents publishing single-record cells. Does not prevent differencing across several published tables, and is not l-diversity. |
| Level-k reasoning | Contested in the literature | The lab does not implement it as a predictor. It appears only as a discussion frame for why an adversary might behave inconsistently. |
| Lefebvre's reflexive control | Not empirically validated | Implemented as an attenuation heuristic on belief updates, explicitly not as a model of how a person thinks. |
| ONNX export and INT8 quantization | Not implemented | No model worth exporting. Claiming edge inference without a measured latency budget is a slide, not a system. |
| Cross-VPN behavioral identity | Rejected | Does not work technically and is surveillance by construction. See [ETHICS-AND-LIMITS.md](ETHICS-AND-LIMITS.md). |
| Jitter-based geolocation | Rejected | Timing at a server is dominated by the server's own scheduling and the last hop. It is not an instrument for locating people. |

## The base rate problem

The demo reports AUC around 0.96 on synthetic data. That number says the plumbing
works. It says nothing about deployment, because precision depends on prevalence, and
this is where behavioral detection projects usually fail.

If 1% of clients are automated, and the model achieves 90% sensitivity at a 5% false
positive rate:

```
PPV = (0.90 * 0.01) / (0.90 * 0.01 + 0.05 * 0.99)
    = 0.009 / 0.0585
    = 0.154
```

Roughly six of every seven alerts are wrong. At 0.1% prevalence it is worse than one in
fifty. AUC hides this completely, which is why `lab/orchestrator/run_pipeline.py`
reports fold counts alongside AUC and why the schema keeps raw events instead of only
scores: any threshold has to be chosen with a prevalence estimate and a cost of false
positives in hand.

## Why the model is a logistic regression

Not humility, plumbing. Temporal validation, drift detection, suppression, and shadow
divergence are the parts that break in production. A linear model fails loudly when
the features are wrong; a boosted ensemble of depth 8 will happily memorize a leak in
the feature table and report 0.99. Upgrade the estimator after the harness is trusted,
and re-run the poisoning probe when you do.

## What would count as validation

None of this has been validated. A credible study would need:

1. Labeled data with a known, realistic prevalence, not a balanced synthetic set.
2. An adversary who adapts, or at minimum a held-out period long enough to catch
   drift.
3. A cost model for false positives, since the operator's cost of wrongly flagging a
   person is the thing that decides the threshold.
4. Reproducibility: seeds, feature hashes, and the exact split, so someone else can
   fail to reproduce it independently.

Point 3 is why the ethics page is not an appendix. In a system that points at people,
the false positive rate is the ethical question, not a metric.

## On the original document's own claim

The author's note says the work is assembly rather than invention, and that sections
range from established technique to deliberate speculation. That is an unusually
honest framing and this branch takes it seriously: the parts that are assembly are
kept and attributed, the parts that are speculation are labelled, and the parts that
are neither, because they do not work, are dropped and named in
[ETHICS-AND-LIMITS.md](ETHICS-AND-LIMITS.md).
