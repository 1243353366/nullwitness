# Incentive design

You do not control someone's decision. You influence the conditions under which they make it.
That sentence is the whole of this document, and the reason it is worth a module rather than a
paragraph is that it is easy to say and hard to design against: it implies that the deliverable
is a set of **conditions**, not an outcome, and that any claim about the outcome is a claim about
someone else's reasoning that you cannot verify.

## What the model refuses to claim

Four things, each of which would make the arithmetic look better and be less true:

- **That they will not attack.** Output is a return and a margin, never a promise.
- **That deterrence is absolute.** It is relative to `opportunity_return`, what the same effort
  earns elsewhere. +2,000 is deterred when the alternative is +5,000 and attractive when it is
  +500. Rising above the alternative is the goal.
- **That outside punishment is available to you.** No lever here retaliates, names, or pursues.
- **That influencing a person and influencing an adversary are the same act.** They are not, and
  `permissible` refuses the second use in code rather than leaving it to taste (below).

There is a fifth, subtler refusal. Deterrence is **unobservable by construction**: you never see
the attempt that did not happen, so "we deterred them" is unfalsifiable from your own logs alone.
What you can measure is what you do see: attempts that continue to arrive, what they cost the
attacker according to their own tradecraft, and whether peers with weaker conditions are being
hit instead. Everything else is inference, and the module labels it as such.

## The levers

| Lever | Mechanism | Effect | Why it works |
| --- | --- | --- | --- |
| `data_minimisation` | loot | ×0.4 loot | if the payoff is not stored, no cost model changes their mind and nothing needs detecting |
| `rotation_window` | latency | ×0.6 loot, ×2.0 upkeep | value that expires pays for a shorter time while costing them the same to take |
| `sealed_capture` | visibility | ×2.0 upkeep | a record that proves it was edited turns a quiet edit into a loud one |
| `offhost_anchor` | visibility | ×2.5 upkeep | keeping consistent with something unreachable is recurring work |
| `decoy_fields` | visibility | ×1.6 upkeep | doubt is a tax: every field they cannot vouch for is checked twice |
| `baseline_hardening` | cost | ×1.8 setup | the ordinary one, and the weakest: it raises the price of the first foothold once |
| `precision_profiling` | consequence | ×1.3 setup, ×1.3 upkeep | credible characterisation raises the cost of being remembered; incredible profiling raises nothing |

Levers saturate within a mechanism: the second visibility lever is worth less than the first,
because the first already made the same thing visible. Stacking is not addition.

## Worked: the comparison that matters

$250,000 asset, an integrity attack whose loot ceiling is $40,000, and an attacker whose next best
use of the same effort is worth $2,000. From `python3 -m lab.economics.cli design`:

| Design | Levers | Cost/yr | Their return | Margin | Decision |
| --- | --- | --- | --- | --- | --- |
| nothing | none | 0 | 36,700 | +34,700 | attractive |
| compete on price | baseline_hardening | 3,000 | 35,500 | +33,500 | attractive |
| make tampering visible | sealed_capture, offhost_anchor | 2,700 | 31,975 | +29,975 | attractive |
| shape the payoff | data_minimisation, rotation_window | 1,700 | 4,500 | +2,500 | attractive |
| both, cheaply | + sealed_capture | **2,900** | **900** | **−1,100** | **deterred** |
| both, expensively | sealed_capture, offhost_anchor, decoy_fields, baseline_hardening | 6,400 | 29,982 | +27,982 | attractive |

$6,400 of competing on price leaves the attempt at +29,982. $2,900 of shaping the payoff moves it
to +900, below their alternative. The expensive row is not a strawman: it is the shape of a
control set assembled from cost levers alone, which is what happens when "harden everything" is
treated as a strategy. The cheap row spends on **what is worth taking**, and only adds the
visibility lever because it keeps the upkeep tax on the attempt that still happens.

`cheapest_flip` exists to stop the spending at the moment the decision moves. Everything beyond
that is buying a decision that has already been made, which is the same failure as the escalation
in `DEFENSE-ECONOMICS.md`, just quieter.

## Substitution: the win that is a transfer

Deterrence relocates an attempt; it does not delete it. The same design run reports where it goes
next:

| Target | Their return |
| --- | --- |
| peer A: same sector, no levers | 12,700 |
| peer B: publishes inventory | 4,000 |
| peer C: already hardened | −5,000 |

That is a win for you and a loss for peer A. A design document that omits the second half is a
sales document, and the honest version also asks whether the relocation is toward a peer who will
tell you about it, because that is the only version that helps anyone other than you.

## The ethical line, enforced

Applied to an adversary, this is deterrence: shaping the payoff of an action someone is choosing
to take against you. Applied to your own users, staff, or a third party, the identical machinery
is manipulation. "You don't control the decision, you influence the conditions" describes a
deterrent, a nudge, a dark pattern, and a coercive workplace equally well, and no amount of
security rationale changes which one is being built.

The distinguishing question is not intent, it is **who bears the cost of the design**. An
adversary chose the relationship and can leave it by going elsewhere. A colleague did not choose
to be the object of your design, and the same lever that makes an attack unattractive makes
dissent expensive. So `permissible` refuses:

- `nudge_users_to_accept_risk`: redesigning the interface so people click through what they would
  otherwise question.
- `pressure_insider_by_design`: shaping a colleague's environment so reporting feels costlier than
  staying quiet.

Both are in the catalogue to be refused, because a gate nobody can see being tested is a comment.
If the goal is fewer risky decisions by your own people, the version that survives review is
transparency plus a cheaper safe path, not a better-hidden nudge.

## How this ties to the rest

- `tiers.py` sets what an asset's value obliges; this sets **which conditions** to buy with it.
- `timing.py` decides when to act; acting is a lever too, and the most visible one.
- `discipline.py` keeps wins from becoming bigger positions; `cheapest_flip` applies the same
  restraint to design.
- The trust chain raises the maintenance term, which is what makes an environment expensive to
  hold rather than merely hard to enter.

## Caveats

- `opportunity_return` is an estimate of someone else's alternatives, and it decides the verdict.
  Change it and the same environment moves between "deterred" and "attractive" without anything
  about your defense changing. That is a fact about deterrence, not a defect in the model.
- `loot_mult` values are planning figures for the shape of the effect, not measurements. The
  ranking is the durable part; the second decimal place is not.
- A "deterred" verdict is a statement about a rational actor facing these conditions. Rational
  actors are a subset of the ones you will meet.
