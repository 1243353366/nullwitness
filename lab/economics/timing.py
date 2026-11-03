"""When to act, priced instead of felt.

CISA's *Federal Government Cybersecurity Incident and Vulnerability Response Playbooks* (August
2024) make the case directly, and the wording is worth having in front of you rather than
paraphrased:

> Some adversaries may actively monitor defensive response measures, and shift their methods to
> evade detection and containment. Defenders should therefore develop as complete a picture as
> possible of the attacker's capabilities and potential reactions to avoid "tipping off" the
> adversary. Containment is challenging because defenders must be as complete as possible in
> identifying adversary activity, while considering the risk of allowing the adversary to
> persist until the full scope of the compromise can be determined.

And as a containment selection criterion, alongside mission impact and duration:

> Any impact on the collection, preservation, securing, and documentation of evidence.

CISA also sanctions the deliberate hold rather than only warning about it. One listed
containment activity is:

> Directing the adversary to a sandbox (a form of containment) to monitor the actor's activity,
> gather additional evidence, and identify attack vectors. Note: this containment activity is
> limited to advanced SOCs with mature capabilities.

One precision matters for honesty. The playbook says adversaries "shift their methods", and it
makes evidence preservation a containment consideration; it does not say in those words that
they will destroy evidence. The evidence-destruction motive is the standard reading of the same
passage in practice, and it is the reason `destroy_if_tipped` is an input here rather than a
constant: the operator sets it, because it depends on the adversary and on whether your records
survive them (`lab/TRUST-CHAIN.md` is what lowers it).

## The arithmetic of holding

    damage_if_hold   = damage_per_hour × dwell_hours
    damage_avoided   = stops_damage × damage_if_hold
    evidence_forfeited = evidence_value × reveals × destroy_if_tipped
    tactics_cost     = tactics_shift_cost × reveals × capability
    self_inflicted   = 0.5 × evidence_value  (when the action destroys evidence itself)
    net              = damage_avoided − evidence_forfeited − tactics_cost − self_inflicted

Every term is a thing an operator can argue with, which is the point. "We should contain now"
and "we should keep watching" are both defensible, and neither is an argument. The model
converts the disagreement into: how fast is the bleed, how much evidence is still uncollected,
how much does this action reveal, and how much do they learn.

## The finding that makes holding cheap

`evict` and `public_disclosure` reveal almost everything; `preserve_evidence` and deeper
instrumentation reveal almost nothing. The interesting actions sit between: silent containment
(segment without notifying anyone) stops most of the damage and reveals a little, and
`sandbox_redirect` gathers evidence while costing the adversary time, which is why CISA lists it
and why it also carries a maturity caveat that this module enforces.

Note what the trust chain does to this arithmetic. Sealed source records and an off-host anchor
mean an adversary who destroys the endpoint destroys less: `destroy_if_tipped` falls, so
`evidence_forfeited` falls, so acting early becomes cheaper than it would otherwise be. Integrity
work is not only about proving what happened after the fact; it changes the price of every
response decision made during the incident.

## Why sequence matters

Each revealing action leaks independently, so two of them leak more than either alone:

    leak(sequence) = 1 − Π(1 − reveals_i)

and a leak is not recoverable: once they know you know, the evidence you were waiting to collect
is the evidence they now have time to destroy. CISA's eradication guidance says the same thing
in operational terms: "eradication plans should be well formulated and coordinated before
execution", and coordinate with providers and law enforcement "prior to the initiation of
eradication efforts". A piecemeal eviction is the expensive way to do it once badly.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence, Tuple

from lab.economics.model import Verdict

# CISA lists sandbox redirection as a containment option "limited to advanced SOCs with mature
# capabilities". The gate is enforced rather than footnoted.
MATURITY_NAMES = {0: "developing", 1: "established", 2: "advanced"}


@dataclass(frozen=True)
class Action:
    """A response move, described by what it stops and what it teaches the adversary."""

    name: str
    stops_damage: float  # fraction of the ongoing bleed it halts
    reveals: float  # probability the adversary notices and reacts
    preserves_evidence: bool
    response_hours: float
    min_maturity: int = 0
    note: str = ""


@dataclass(frozen=True)
class Situation:
    """What is true right now, from the defender's side and the attacker's."""

    damage_per_hour: float  # current rate of loss while uncontained
    dwell_hours: float  # how long you can keep observing before they act on their objective
    evidence_value: float  # worth of the evidence still uncollected
    destroy_if_tipped: float  # probability they destroy evidence once alerted
    tactics_shift_cost: float  # what a change of tactics costs you, in the same currency
    capability: float  # how much they learn and adapt, 0..1
    maturity: int = 1  # SOC maturity, per CISA's caveat

    @property
    def damage_if_hold(self) -> float:
        return self.damage_per_hour * self.dwell_hours


ACTIONS: Tuple[Action, ...] = (
    Action(
        "hold",
        stops_damage=0.0,
        reveals=0.0,
        preserves_evidence=True,
        response_hours=0.0,
        note="the baseline every other row is priced against: absorb the bleed, keep every piece of evidence",
    ),
    Action(
        "observe",
        stops_damage=0.0,
        reveals=0.05,
        preserves_evidence=True,
        response_hours=0.0,
        note="collect, characterise, change nothing. CISA's 'as complete a picture as possible'",
    ),
    Action(
        "preserve_evidence",
        stops_damage=0.0,
        reveals=0.02,
        preserves_evidence=True,
        response_hours=0.5,
        note="image, seal, and anchor what exists before anything else happens; the cheapest action here",
    ),
    Action(
        "instrument_deeper",
        stops_damage=0.05,
        reveals=0.10,
        preserves_evidence=True,
        response_hours=1.0,
        note="more sensors at the boundary they are using, so the picture fills in faster",
    ),
    Action(
        "silent_containment",
        stops_damage=0.55,
        reveals=0.15,
        preserves_evidence=True,
        response_hours=2.0,
        note="segment and cut lateral paths without notifying anyone: most of the damage stop, little of the reveal",
    ),
    Action(
        "sandbox_redirect",
        stops_damage=0.35,
        reveals=0.35,
        preserves_evidence=True,
        response_hours=4.0,
        min_maturity=2,
        note="CISA's listed option: keep them working where you can watch, gather evidence, learn their vectors",
    ),
    Action(
        "evict",
        stops_damage=1.0,
        reveals=0.90,
        preserves_evidence=False,
        response_hours=6.0,
        note="remove access now; the adversary learns they were caught and the remaining evidence is theirs to burn",
    ),
    Action(
        "notify_users",
        stops_damage=0.10,
        reveals=1.0,
        preserves_evidence=False,
        response_hours=0.5,
        note="CISA's own example of tipping them off: phone, not email, and not before you are ready",
    ),
    Action(
        "public_disclosure",
        stops_damage=0.05,
        reveals=1.0,
        preserves_evidence=False,
        response_hours=2.0,
        note="maximum reveal, minimum stop: a communications decision, not a containment one",
    ),
)

BY_NAME: Dict[str, Action] = {action.name: action for action in ACTIONS}


def cost_of(action: Action, situation: Situation) -> Dict[str, float]:
    """Break the action's net benefit into the terms that decide it."""
    damage_avoided = action.stops_damage * situation.damage_if_hold
    evidence_forfeited = situation.evidence_value * action.reveals * situation.destroy_if_tipped
    tactics_cost = situation.tactics_shift_cost * action.reveals * situation.capability
    self_inflicted = 0.0 if action.preserves_evidence else 0.5 * situation.evidence_value
    net = damage_avoided - evidence_forfeited - tactics_cost - self_inflicted
    return {
        "damage_avoided": round(damage_avoided, 2),
        "evidence_forfeited": round(evidence_forfeited, 2),
        "tactics_cost": round(tactics_cost, 2),
        "self_inflicted": round(self_inflicted, 2),
        "net": round(net, 2),
        "reveals": action.reveals,
        "leak_if_taken_alone": round(action.reveals, 4),
    }


def assess(situation: Situation, actions: Sequence[Action] = ACTIONS) -> List[dict]:
    """Every available action, priced, best first."""
    rows: List[dict] = []
    for action in actions:
        row = {"action": action.name, "note": action.note, **cost_of(action, situation)}
        row["available"] = situation.maturity >= action.min_maturity
        if not row["available"]:
            row["why_not"] = (
                f"needs maturity {MATURITY_NAMES[action.min_maturity]}; this SOC is "
                f"{MATURITY_NAMES[situation.maturity]}"
            )
        rows.append(row)
    return sorted(rows, key=lambda row: (row["available"], row["net"]), reverse=True)


def _leak(reveals: Sequence[float]) -> float:
    remaining = 1.0
    for value in reveals:
        remaining *= 1.0 - value
    return round(1.0 - remaining, 4)


def judge(situation: Situation, proposed: str) -> List[Verdict]:
    """Should this move happen now, and if not, why not.

    The verdict set is deliberately narrow. "Hold" is not a recommendation to do nothing: it is
    a decision to spend the dwell window on the two actions that cost almost nothing to take and
    cannot be taken later.
    """
    action = BY_NAME.get(proposed)
    if action is None:
        raise KeyError(f"unknown action {proposed!r}")
    verdicts: List[Verdict] = []
    rows = {row["action"]: row for row in assess(situation)}
    chosen = rows[action.name]
    best_silent = max(
        (row for row in rows.values() if row["available"] and row["reveals"] <= 0.15),
        key=lambda row: row["net"],
    )
    best_overall = max((row for row in rows.values() if row["available"]), key=lambda row: row["net"])

    if not chosen["available"]:
        verdicts.append(
            Verdict(
                "action_unavailable",
                "medium",
                f"{action.name}: {chosen['why_not']}. CISA lists sandbox redirection for advanced SOCs because "
                "watching an adversary in place requires the capability to notice when it stops working",
            )
        )

    if chosen["net"] < best_overall["net"] and chosen["reveals"] >= 0.3:
        verdicts.append(
            Verdict(
                "premature_action_refused",
                "high",
                f"{action.name} is not the move yet: it nets {chosen['net']:,.0f} against {best_overall['action']} at "
                f"{best_overall['net']:,.0f}. It forfeits {chosen['evidence_forfeited']:,.0f} of evidence and "
                f"{chosen['tactics_cost']:,.0f} of future cost to stop {chosen['damage_avoided']:,.0f} of damage. "
                "Tip them off when you are ready, not when you are uneasy",
            )
        )
    elif chosen["reveals"] >= 0.5 and chosen["net"] < best_silent["net"]:
        verdicts.append(
            Verdict(
                "silent_option_better",
                "medium",
                f"{action.name} nets {chosen['net']:,.0f} against {best_silent['action']} at {best_silent['net']:,.0f}, "
                f"and reveals {chosen['reveals']:.0%} against {best_silent['reveals']:.0%}: the quieter move stops less "
                "and is worth more",
            )
        )

    if not action.preserves_evidence:
        verdicts.append(
            Verdict(
                "evidence_at_risk",
                "medium",
                f"{action.name} does not preserve evidence: it costs {chosen['self_inflicted']:,.0f} of the "
                f"{situation.evidence_value:,.0f} still uncollected before the adversary is even involved. Capture first, "
                "then act",
            )
        )

    if chosen["net"] > 0 and chosen["net"] == best_overall["net"]:
        verdicts.append(
            Verdict(
                "act_now_justified",
                "low",
                f"{action.name} is the best move available: {chosen['damage_avoided']:,.0f} of damage avoided against "
                f"{chosen['evidence_forfeited'] + chosen['tactics_cost'] + chosen['self_inflicted']:,.0f} of combined "
                "evidence and adaptation cost",
            )
        )
    elif chosen["reveals"] <= 0.15 and chosen["net"] <= 0:
        verdicts.append(
            Verdict(
                "hold_justified",
                "low",
                f"{action.name} does not pay for itself and is worth taking anyway: it costs about "
                f"{abs(chosen['net']):,.0f} and buys the picture the later decision depends on. Observation is a cost paid "
                "for better arithmetic, not a benefit, and a hold is that cost plus the damage you chose to absorb",
            )
        )
    return verdicts


def sequence(situation: Situation, steps: Sequence[str]) -> Dict[str, object]:
    """A planned order of moves, with the leak it accumulates.

    Two revealing moves do not leak additively, they leak in combination: after the first, the
    adversary is watching for the second. This is why eradication is planned before it starts
    rather than improvised one host at a time.
    """
    reveals = []
    net = 0.0
    ordered: List[dict] = []
    for step in steps:
        action = BY_NAME.get(step)
        if action is None:
            raise KeyError(f"unknown action {step!r}")
        cost = cost_of(action, situation)
        reveals.append(action.reveals)
        net += cost["net"]
        ordered.append({"action": step, "net": cost["net"], "reveals": action.reveals, "available": situation.maturity >= action.min_maturity})
    return {
        "steps": ordered,
        "cumulative_net": round(net, 2),
        "cumulative_leak": _leak(reveals),
        "note": (
            "ordered so that nearly silent steps run first and the irreversible, revealing ones run last, once and "
            "together: a leak cannot be un-leaked"
            if steps
            else "no steps"
        ),
    }


def recommended_sequence(situation: Situation) -> List[str]:
    """Capture, watch, then contain quietly, then decide about eviction with the full picture."""
    steps = ["preserve_evidence"]
    if situation.evidence_value > 0 and situation.dwell_hours > 0:
        steps.append("observe")
    if situation.maturity >= 2:
        steps.append("sandbox_redirect")
    steps.append("silent_containment")
    if recommended_eviction(situation):
        steps.append("evict")
    return steps


def recommended_eviction(situation: Situation) -> bool:
    """Evict when the bleed outruns what the quiet phase can still buy."""
    quiet = cost_of(BY_NAME["silent_containment"], situation)["net"]
    evict = cost_of(BY_NAME["evict"], situation)["net"]
    return evict > quiet
