# Defense economics

Four principles, each with a module that computes it rather than asserting it:

| Principle | Question it answers | Module |
| --- | --- | --- |
| Economic asymmetry | does attacking me still pay? | `lab/economics/model.py` |
| Proportionality | is this control worth more than it costs? | `model.py`, `tiers.py` |
| Resilience | what survives, and what do I get back? | `lab/economics/resilience.py` |
| Adaptation | did the last failure change the next one? | `lab/economics/adaptation.py` |

## Economic asymmetry

    attacker_return = p_success × loot − setup_cost − maintenance_cost × months

Attacking is work with a budget. The point of a defense is to make the work pay less, and the
term that gets ignored is the last one. Raising setup cost is a one-time tax, paid once and
then amortised over every future attempt. Raising maintenance cost is a subscription: the
attacker has to keep re-earning access they already bought. For the same money, the recurring
tax is the better purchase, and the tests assert it rather than leaving it as a slogan
(`test_maintenance_effects_move_attacker_return_more_than_setup_effects`).

Which controls raise maintenance here:

| Control | setup × | monthly × | Why it recurs |
| --- | --- | --- | --- |
| `source_seal` | 1.5 | **6.0** | every write must defeat the seal again, not once |
| `boot_attestation` | 3.0 | **8.0** | an implant must survive attestation at every boot |
| `rotation_cadence` | 1.2 | **5.0** | a stolen key expires, so it must be stolen again |
| `aes_gcm_envelope` | 2.0 | **4.0** | a lost key stops being a quiet edit and becomes a broken tag |
| `digest_anchor_offhost` | 1.8 | **3.0** | keeping a host consistent with an anchor it cannot reach is ongoing work |

The second half of asymmetry is that **their gain is not your loss**, and conflating the two
makes every trivial threat look like a crisis. A scanner does not net a slice of a
quarter-million-dollar asset; it nets a credential worth a few hundred. So `Threat` carries
`impact_fraction` for your expected loss and `loot_cap` for their realised gain, and
`opportunistic_scan` is priced at a $200 ceiling. Without that split, a report ranks
opportunistic scanning alongside a firmware implant, and the reader stops reading.

## Proportionality

    benefit(control) = expected_loss_without − expected_loss_with   vs   annual_cost(control)

Both directions of the ratio matter and both are checked:

- **Benefit below cost** is a finding (`control_overinvestment`), even though the control
  works. A working control that returns 0.08× its cost is a budget being spent on a feeling.
- **Cost above the asset's value** is a finding (`control_exceeds_asset`), and it is not
  softened because the control is good. Measured boot on a hobby project is not extra safety,
  it is maintenance debt with a security theme.

The ladder makes proportionality legible instead of arguable:

| Tier | Name | Asset value | Controls | Ceiling | Depth |
| --- | --- | --- | --- | --- | --- |
| 0 | public | under 5k | 1 | 30% | 1 |
| 1 | operational | 5k to 50k | 2 | 25% | 2 |
| 2 | sensitive | 50k to 500k | 4 | 20% | 2 |
| 3 | regulated | 500k to 5M | 7 | 15% | 3 |
| 4 | targeted | above 5M | 11 | 10% | 4 |

Requirements are floors and they only grow. The ceiling only tightens, because a larger asset
amortises the same control better: 20% of a $250,000 asset is a real budget, 20% of a
$10,000,000 asset is an endowment. **The tier moves on evidence, not on ambition**:
`promotion_hint` fires when an attempt still returns a profit at the current rung, which is the
observable form of "they are getting more out of this than it costs them".

## Resilience

Prevention and resilience are separate budgets, and an organization that spends everything on
the first has nothing left for the day the first stops being true. Two halves:

- **Evidence that survives.** A chain head held off-host, digests that do not need the
  decryption key, and sealed source records. Evidence is the first casualty of a fix, so
  `recovery_plan` opens every runbook with "preserve the current state before touching
  anything".
- **Recovery that has been tried.** Split key escrow, a rotation window that bounds a theft, an
  immutable copy. A backup that has never been restored is a hypothesis, which is why
  `drill_gap` exists and why the top tier is the only one that does not report it.

At tier 2 with a $250,000 asset, the honest coverage is: archive substitution and rollback
covered (digest chain, off-host anchor), and `file_deleted`, `key_lost`, `key_stolen`,
`host_rebuilt`, `storage_corrupted` **not** covered. Those are tier 3 purchases, and the report
says so rather than implying that login-ability is resilience.

## Adaptation

    finding → reading → change → effect, measured

`adaptation.LESSONS` maps finding codes to one reading and one action. The loop is mechanical
enough to be honest about:

- **idempotent**: re-running the loop over old findings changes nothing. This matters because
  re-running over old findings is exactly what happens in practice, and a loop that ratchets on
  every pass corrupts the plan silently.
- **monotone where it should be**: tightening only raises reductions or adds controls.
- **capable of loosening, deliberately**: `trim` removes a control whose benefit is below its
  cost, unless the tier requires it. Adaptation that can only add is how a control set becomes a
  museum.

Worked example from `python3 -m lab.economics.cli demo`, tier 2, $250,000 asset:

1. Plan: 4 controls, $2,800/year, 1.1% of asset value, expected loss $37,515.
2. A key was reachable and a kernel measured differently. Lessons add `key_custody_separation`
   and `boot_attestation`: +$20,500, expected loss $37,515 → $29,231, and the firmware implant's
   attacker return goes from −$87,750 to −$419,212.
3. The same arithmetic reviews the decision: `boot_attestation` returns 0.08× its cost at this
   asset value. `trim` removes it, leaving $5,300 and an expected loss of $30,694, with every
   tier obligation intact.

Step 3 is the one that makes the rest credible. Adaptation that cannot be reviewed by its own
numbers is just accumulation with a narrative.

## Wins and losses

Two failure modes of nerve, pulling in opposite directions, and they share one gate.

**A win must not cost more than it earned.** A detection feels like permission: the evidence is
fresh, the argument is already won, and every proposal made in that mood is a proposal to
expand. So `settle_win` changes nothing by default, allows **one** change, and only if that
change pays for itself against the same threat book as everything else. The moves a success is
not allowed to authorise:

| Move | Why it is refused |
| --- | --- |
| `public_attribution` | converts a private advantage into a public target, and an inference into a claim you must defend |
| `retaliate` | out of scope here, and usually out of scope legally |
| `sweep_scope` | breaks operations, so the cost lands on you and the benefit is speculative |
| `buy_controls` | a scare is not a threat model; the control still has to return more than it costs |
| `tighten_everything` | degrades the baseline you need to compare against next time |

A win that changes nothing is the outcome to prefer, and it gets its own verdict (`win_banked`)
rather than a shrug. One change per win is a rate limit on momentum: three plausible changes
proposed in the same confident hour add up to a plan nobody reviewed.

**A loss must hurt them and pay you.** Not one requirement, two:

- **it should cost them.** An attempt that paid nothing (`loss_free_for_them`) is an invitation
  to repeat. Growth, not damage, is the thing to watch.
- **it should leave you something:** evidence, a characterised operator, a measured hardening
  delta. A loss with no leverage (`loss_wasted`) is a rehearsal for the next one. A hardening
  step already in the plan (`hardening_already_in_place`) is worse than nothing, because it looks
  like diligence.

The number that ties the halves together is `cost_imposed_per_damage`: what they spent divided by
what the incident cost you. Rising across incidents is the only evidence the position is
improving, and it is exactly what an ego-driven escalation destroys, because escalation raises
your costs without raising theirs.

Worked year from `python3 -m lab.economics.cli discipline`, tier 2, $250,000 asset:

| Day | Event | Outcome |
| --- | --- | --- |
| 30 | decoy swept, real files untouched | converted: they paid 9,500 against 2,000 of damage, two leverage items, `rotation_cadence` added so `key_compromise` is dearer to repeat |
| 40 | substitution caught at the archive boundary | one change allowed (`key_custody_separation`, it pays); `boot_attestation` refused at 1,462 benefit against 18,000 cost |
| 90 | replay refused, proposal: go public | refused as an ego move; the win is banked unchanged |
| 120 | laptop stolen, unsealed notes | wasted: 300 of attacker cost, no leverage, nothing learned |

Scorecard: 2 wins (1 banked, 2 refusals), 2 losses (1 converted, 1 wasted), 20,000 damage against
9,800 of attacker cost, `cost_imposed_per_damage` 0.49, net position −10,200. They are still
ahead on this asset, and the report says so instead of letting four tidy verdicts imply otherwise.

## Profiling in proportion

Fingerprint depth follows the tier, because the reason to know more about an operator is that
they are getting more out of you: depth 1 (technique), 2 (sequence, boundaries, what was
evaded), 3 (cadence, precision signature), 4 (repertoire across incidents). Two refusals are
built in rather than documented: cadence needs three or more incidents, and cross-incident
linkage needs at least three incidents and three techniques. Below that the honest output is
"unknown operator", and the module emits that string instead of a confident guess.

It also has no identity field, and will not grow one. The product of this module is behaviour:
what they reach for, how patient they are, how carefully they avoid specific checks. That is
enough to price the next attempt and nowhere near enough to accuse a person, which is the
correct ratio.

## The numbers are the weak part, deliberately

The arithmetic is exact and tested. The inputs are estimates:

- `likelihood` is an annual probability someone guessed. It is the input that moves conclusions
  most and deserves the most suspicion.
- `impact_fraction` is a planning figure, not an actuarial one.
- Control `annual_cost` excludes the part that actually dominates: staff attention. A control
  that needs an hour a week costs more than its licence.
- Setup and maintenance costs for attackers are order-of-magnitude, and they are the numbers an
  operator is most likely to disagree with. That is why they are inputs and not constants.

So the model is built to be argued with at the level of a number rather than a conclusion. It
rounds money to the nearest hundred in reports, because decimal places on a guess are false
precision, and it separates "this control is not justified by the threat book" from "this
control is not justified", because the threat book is the part that might be wrong.

## Running it

```
python3 -m lab.economics.cli ladder
python3 -m lab.economics.cli report --value 250000
python3 -m lab.economics.cli adapt --value 250000 --codes key_compromise,boot_measurement_mismatch
python3 -m lab.economics.cli demo
```
