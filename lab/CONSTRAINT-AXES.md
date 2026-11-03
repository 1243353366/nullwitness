# Four axes

`INCENTIVE-DESIGN.md` lists levers and prices them by mechanism. That list is a menu. This is the
structure under it: every lever presses on exactly one of four constraints, and the four have
different owners, different evidence, and different ways of being wrong.

| Axis | The question it asks | Owner | Evidence available | Confidence |
| --- | --- | --- | --- | --- |
| **Capability** | can they do it at all? | you | measured: what exists, what it takes to reach | 0.9 |
| **Legitimacy** | is it permitted, and who says so? | mostly others | documented and reported, acted on by someone with standing | 0.5 |
| **Perception** | what do they believe will happen to them? | shared | inferred from their behaviour afterwards | 0.4 |
| **Dependency** | what do they need that you can deny? | you, over your own estate | measured, but only for the threats it applies to | 0.7 |

The owner column is the reason this exists. Three of the four axes are not fully yours to move,
and a single "posture score" averages that difference away. Capability and dependency are yours to
buy. Legitimacy needs a regulator, a court, or a peer network to act, and all you can supply is
the record. Perception is somebody else's belief, observable only through their behaviour.

## What each axis is not

- **Capability is not posture.** Denying the act says nothing about whether you would notice a
  different act.
- **Legitimacy is not yours to enforce.** You cannot sanction anyone. `legitimacy_file` raises
  their expected consequence by about five percent for $400 a year, which makes it the cheapest
  axis and the one most often left unclaimed.
- **Perception is not knowledge.** A perception lever with no capability behind it is a bluff, and
  `perception_unsupported` refuses to credit it.
- **Dependency is not leverage.** Denying what they need from your own estate is defence.
  Arranging what a person needs until compliance is cheaper is coercion, and it never reaches the
  arithmetic because `permissible` refuses it upstream.

## Priced by margin, not in isolation

Axes compound the way a chain does, not the way a sum does, so each one is priced by what it
contributes **given the others**: the return you would give back by removing it alone.

Base design for a $250,000 audit trail, `data_minimisation + rotation_window + sealed_capture`,
against plaintext manipulation:

| Axis | Levers | Cost/yr | Marginal contribution | Share | Confidence |
| --- | --- | --- | --- | --- | --- |
| capability | data_minimisation | 800 | 14,400 | 40% | 0.9 |
| legitimacy | none | 0 | 0 | 0% | 0.5 |
| perception | sealed_capture | 1,200 | 3,600 | 10% | 0.4 |
| dependency | rotation_window | 900 | 10,000 | 28% | 0.7 |

Their return falls from 36,700 to 900 and the decision is deterred. Note that the marginals sum to
28,000 against 35,800 actually moved: the axes **carry each other**, and the 7,800 difference is
the complementarity that an additive model would report as efficiency. This is also why an
isolated per-axis score flatters whichever axis was bought first, which is the mistake
`profile` was built to avoid.

## What one more lever buys

| Addition | Cost/yr | Their return | Decision |
| --- | --- | --- | --- |
| as designed | 2,900 | 900 | deterred |
| + capability (baseline_hardening) | 5,900 | −300 | deterred |
| + legitimacy (legitimacy_file) | 3,300 | 540 | deterred |
| + perception (offhost_anchor) | 4,400 | −4,950 | deterred |
| + dependency (offline_restore) | 4,000 | 900 | deterred, and this lever does not answer this threat |

Two things in that table are worth more than the numbers. Perception is the most productive
purchase here and the least demonstrable (confidence 0.4), so it improves the position and
weakens the report. And `offline_restore` buys nothing at all, because a restore does not help
against an edit you cannot detect. That is not a modelling artefact, it is the repository's whole
argument showing up in its own arithmetic: the integrity layer is what makes a dependency lever
usable, and without it the spend is real and the effect is zero.

## The same design against a different threat

Run the identical design against ciphertext substitution and it is attractive again: 31,120 of
return against a 147,280 starting point. Capability contributes 54,000, dependency 25,440, and
perception 1,440. Nothing about the design changed; the threat did.

The lesson is not "buy more". It is that **axes are threat-specific, so a profile is a statement
about one threat class.** A design tuned to defeat manipulation is not a design that survives
substitution, and a document that presents one aggregate score is claiming a generality it has
not earned. `profile` therefore takes a threat, and `axes` runs the catalogue.

## The ownership verdict has a scope

`axis_owned_by_others` fires only while the decision is still open. Once a design is deterred, it
stops nagging about legitimacy even though the axis stays unclaimed, because the hand-off has not
become more urgent merely by being successful. The gap is still listed in `ownership_gaps`, so the
structure remains visible without turning a settled decision into a standing reproach. That is a
deliberate choice and the opposite choice is defensible: the paperwork is worth filing whether or
not the current threat is deterred, since it is what lets someone else act next time.

## Caveats

- The confidence figures are epistemic guesses about how much of each effect you could
  demonstrate, not measurements. Their ordering is the durable part.
- Four axes are a model, not an ontology. They were chosen because each one fails differently,
  not because reality has four parts.
- `marginal` is order-dependent in a strictly mathematical sense; the leave-one-out form used
  here is one choice among several (Shapley values would be the rigorous version, at a cost this
  problem does not justify).
