# Response timing

Acting early is a decision. So is waiting. This is the arithmetic for both, taken from the same
budget as everything else in `lab/economics/`, and grounded in what CISA actually says.

## What CISA says

*Federal Government Cybersecurity Incident and Vulnerability Response Playbooks*, CISA, August
2024. Three passages carry this module:

**On the adversary watching you back** (Containment → Considerations):

> Some adversaries may actively monitor defensive response measures, and shift their methods to
> evade detection and containment. Defenders should therefore develop as complete a picture as
> possible of the attacker's capabilities and potential reactions to avoid "tipping off" the
> adversary. Containment is challenging because defenders must be as complete as possible in
> identifying adversary activity, while considering the risk of allowing the adversary to persist
> until the full scope of the compromise can be determined.

**On evidence as a containment criterion** (same list, alongside mission impact and duration):

> Any impact on the collection, preservation, securing, and documentation of evidence.

**On OPSEC in preparation** (Response → Operational Security):

> Avoid "tipping off" an attacker by having processes and systems to reduce the likelihood of
> detection of IR activities (e.g., do not submit malware samples to a public analysis service or
> notify users of potentially comprised machines via email).

And CISA does not only warn about holding, it lists it as a containment activity:

> Directing the adversary to a sandbox (a form of containment) to monitor the actor's activity,
> gather additional evidence, and identify attack vectors. Note: this containment activity is
> limited to advanced SOCs with mature capabilities.

**One precision, because it matters.** The playbook says adversaries "shift their methods" and
makes evidence preservation an explicit containment consideration. It does not say, in those
words, that they will destroy evidence. The destruction motive is the standard reading of that
passage, and it is real, but it belongs to the operator's threat model rather than to the quote.
That is why `destroy_if_tipped` is an input here and not a constant baked into the code.

## The arithmetic

    damage_if_hold     = damage_per_hour × dwell_hours
    damage_avoided     = stops_damage × damage_if_hold
    evidence_forfeited = evidence_value × reveals × destroy_if_tipped
    tactics_cost       = tactics_shift_cost × reveals × capability
    self_inflicted     = 0.5 × evidence_value   (when the action destroys evidence itself)
    net                = damage_avoided − evidence_forfeited − tactics_cost − self_inflicted

`hold` is the baseline row and scores exactly zero: absorb the bleed, keep every piece of
evidence. Everything else is priced against it, which turns "should we contain now" into a
number an operator can disagree with.

## Worked: a slow bleed with evidence still on the table

80 per hour, 48 hours of dwell, 40,000 of evidence uncollected, a 70% chance they burn it if
alerted, from `python3 -m lab.economics.cli timing`:

| Action | Damage stopped | Evidence lost | Tactics cost | Self-inflicted | Net |
| --- | --- | --- | --- | --- | --- |
| hold | 0 | 0 | 0 | 0 | **0** |
| preserve_evidence | 0 | 560 | 350 | 0 | −910 |
| observe | 0 | 1,400 | 875 | 0 | −2,275 |
| silent_containment | 2,112 | 4,200 | 2,625 | 0 | −4,713 |
| sandbox_redirect (unavailable, maturity 1) | 1,344 | 9,800 | 6,125 | 0 | −14,581 |
| evict | 3,840 | 25,200 | 15,750 | 20,000 | **−57,110** |

Eviction is refused as premature: it spends 25,200 of evidence and 15,750 of future cost to
stop 3,840 of damage, and destroys 20,000 more itself. The recommendation is
`preserve_evidence → observe → silent_containment`, with a cumulative leak of 21% across the
whole sequence. Note that every quiet step is negative too: observation does not pay for itself,
it is a cost paid for better arithmetic later. Pretending otherwise is how a hold gets sold as a
free option when it is not.

## Worked: a fast bleed

9,000 per hour, 12 hours of dwell, most evidence already collected:

| Action | Damage stopped | Evidence lost | Tactics cost | Self-inflicted | Net |
| --- | --- | --- | --- | --- | --- |
| evict | 108,000 | 4,320 | 2,700 | 4,000 | **96,980** |
| silent_containment | 59,400 | 720 | 450 | 0 | 58,230 |
| sandbox_redirect | 37,800 | 1,680 | 1,050 | 0 | 35,070 |

Here eviction wins outright and the sequence includes it. The model does not have a preference
for patience; it has a preference for the arithmetic, and the arithmetic changes with the bleed
rate rather than with the mood of the room.

## Sequence, not instinct

Each revealing action leaks, and leaks combine rather than average:

    leak(sequence) = 1 − Π(1 − reveals_i)

The recommended order is therefore fixed: capture, then observe, then contain quietly, then
decide about eviction with the picture complete. CISA's eradication guidance says the same in
operational terms:

> Therefore, eradication plans should be well formulated and coordinated before execution.

and coordinate with service providers, vendors and law enforcement "prior to the initiation of
eradication efforts". A piecemeal eviction is the expensive way to do it once, badly.

## What this changes about the rest of the repository

`destroy_if_tipped` is the hinge, and the trust chain is what moves it. Sealed source records and
an off-host anchor mean an adversary who destroys the endpoint destroys less, so
`evidence_forfeited` falls and acting early gets cheaper. Integrity work is not only about
proving what happened afterwards: it lowers the price of every containment decision made during
the incident, which is a benefit that never shows up in an incident report.

## The caveats this module does not paper over

- **Option value is not priced.** Observation buys information, and information has value in
  later decisions. The model charges for observation and does not credit that value, so quiet
  steps read negative by design. That is the conservative direction, and the doc says which way
  the error leans rather than hiding it.
- **A hold needs a window and a trigger.** `dwell_hours` is an estimate of how long you have. A
  hold without a defined trigger to act is just a delay with a nicer name, so `judge` refuses a
  revealing action on arithmetic, not on principle: change the bleed rate and the same call
  reverses.
- **Maturity is gated.** Sandbox redirection is refused below `advanced` because CISA restricts
  it there, and because watching an adversary in place requires noticing when the watching stops
  working.
- **Nobody holds alone.** CISA's containment guidance for major incidents is that activities
  "should be closely coordinated with CISA". The arithmetic decides the timing; it does not
  decide who else knows, and holding quietly is not the same as holding in secret.
