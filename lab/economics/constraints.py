"""Four axes: what the adversary is actually being denied.

`environment.py` lists seven levers and prices them by mechanism. That list is a menu. This is
the structure underneath it. Every lever presses on exactly one of four constraints, and the
four have different owners, different evidence, and different failure modes:

| Axis | The question it asks | Whose hand moves it |
| --- | --- | --- |
| **Capability** | can they do it at all? | yours: what exists, what it takes to reach |
| **Legitimacy** | is it permitted, and who says so? | mostly not yours: law, regulators, standards, courts |
| **Perception** | what do they believe will happen to them? | shared: your visibility, their beliefs |
| **Dependency** | what do they need that you can deny? | yours over your own estate, never over a person |

That ownership column is the reason this module exists. Three of the four axes are not fully
yours to move, and a design document that reports a single aggregate "posture score" hides which
parts require someone else to act. So the output names the gap and, where it can, who is missing.

## What each axis is not

- **Capability is not posture.** Denying the act says nothing about whether you would notice a
  different act. Data minimisation that leaves the audit trail unwatched is a capability lever
  bought in place of a perception one.
- **Legitimacy is not deterrence you own.** You cannot sanction anyone. You can produce the
  paperwork and the report that lets a regulator, a court, or a peer network act, which is why
  `legitimacy_file` raises the adversary's expected consequence by about five percent and costs
  almost nothing. It is the cheapest axis and the one that most often goes unclaimed.
- **Perception is not knowledge.** It is their belief, which you measure only through their
  behaviour. A perception lever with no detection capability behind it is a claim you cannot
  support, so `profile` refuses to credit it (`perception_unsupported`).
- **Dependency is not leverage.** Denying what they need from *your own estate* is defence.
  Arranging what a person needs so that compliance becomes the cheaper option is coercion, and
  it is refused upstream by `permissible`.

## Why the axes do not add up

They compound the way a chain does, not the way a sum does. Raising setup cost on an actor who
never learns you did it buys nothing, because perception was zero. Producing a beautiful
legitimacy file for an incident nobody reported buys nothing, because the report was the lever.
The binding axis is therefore the one furthest from moving the decision, and the module reports
it as the thing to fix rather than the average of four presentable numbers.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence

from lab.economics import environment as envmod
from lab.economics.environment import AXES, Environment, Lever, MECHANISMS
from lab.economics.model import Threat, Verdict


@dataclass(frozen=True)
class Axis:
    name: str
    question: str
    owner: str  # "you", "shared", "others"
    evidence: str
    confidence: float  # how much of the effect you can actually demonstrate
    note: str


AXIS_DEFS: Dict[str, Axis] = {
    "capability": Axis(
        "capability",
        "can they do it at all?",
        "you",
        "measured: what exists to take, what it takes to reach it",
        0.9,
        "the only axis whose effect you can state without appealing to someone else's reasoning",
    ),
    "legitimacy": Axis(
        "legitimacy",
        "is it permitted, and who says so?",
        "others",
        "documented and reported; acted on by regulators, courts, peers",
        0.5,
        "you cannot sanction anyone, only produce the record that lets someone with standing act",
    ),
    "perception": Axis(
        "perception",
        "what do they believe will happen to them?",
        "shared",
        "inferred from their behaviour after the fact",
        0.4,
        "their belief, so the effect exists only while you can keep it credible",
    ),
    "dependency": Axis(
        "dependency",
        "what do they need that you can deny?",
        "you",
        "measured over your own estate only",
        0.7,
        "denying what they need from your data is defence; arranging what a person needs is coercion",
    ),
}


def _return_with(environment: Environment, threat: Threat, levers: Sequence[Lever]) -> float:
    trial = Environment(
        asset=environment.asset,
        levers=list(levers),
        maturity=environment.maturity,
        opportunity_return=environment.opportunity_return,
    )
    return trial.attacker_return(threat)


def profile(environment: Environment, threat: Threat) -> Dict[str, object]:
    """Score the four axes, name the binding one, and list what needs another hand."""
    bare = _return_with(environment, threat, [])
    complete = _return_with(environment, threat, environment.levers)
    total = max(bare - complete, 0.0)
    rows: List[dict] = []

    # Axes compound rather than add, so each one is priced by what it contributes *given the
    # others*: the return you would give back by removing it and nothing else. Pricing them in
    # isolation double counts the same payoff and flatters whichever axis was bought first.
    for axis in AXES:
        definition = AXIS_DEFS[axis]
        levers = [lever for lever in environment.levers if lever.axis == axis]
        without = _return_with(environment, threat, [lever for lever in environment.levers if lever.axis != axis])
        marginal = without - complete
        share = 0.0 if total <= 0 else max(0.0, min(1.0, marginal / total))
        rows.append(
            {
                "axis": axis,
                "question": definition.question,
                "owner": definition.owner,
                "levers": [lever.name for lever in levers],
                "cost": sum(lever.annual_cost for lever in levers),
                "marginal": round(marginal, 2),
                "share": round(share, 4),
                "confidence": definition.confidence,
                "demonstrable": round(share * definition.confidence, 4),
                "evidence": definition.evidence,
            }
        )

    by_marginal = sorted(rows, key=lambda row: (row["marginal"], row["cost"]))
    binding = by_marginal[0]
    decisive = by_marginal[-1]
    decision = environment.decision(threat)

    verdicts: List[Verdict] = []
    if decision["decision"] != "deterred":
        verdicts.append(
            Verdict(
                "axis_binding",
                "medium" if binding["share"] > 0 else "high",
                f"{binding['axis']} contributes {binding['marginal']:,.0f} of the {total:,.0f} already moved: it is the axis "
                "furthest from the decision. An aggregate posture score averages this away, which is exactly the mistake it "
                "exists to prevent",
            )
        )

    perception = next(row for row in rows if row["axis"] == "perception")
    capability = next(row for row in rows if row["axis"] == "capability")
    if perception["levers"] and capability["marginal"] <= 0 and perception["marginal"] > 0:
        verdicts.append(
            Verdict(
                "perception_unsupported",
                "medium",
                "perception levers are in place with no capability behind them: a claim of consequence with nothing that "
                "produces one is a bluff, and a bluff that is tested once stops working",
            )
        )
    if decisive["confidence"] < 0.6 and decision["decision"] == "deterred":
        verdicts.append(
            Verdict(
                "deterrence_not_demonstrable",
                "medium",
                f"the decision rests most on {decisive['axis']}, whose effect is inferred from behaviour rather than measured "
                f"(confidence {decisive['confidence']:.1f}). Report it as an expectation, not a result, or the first quiet "
                "quarter gets read as proof that it worked",
            )
        )

    for row in rows:
        if row["owner"] == "others" and row["marginal"] <= 0 and decision["decision"] != "deterred":
            verdicts.append(
                Verdict(
                    "axis_owned_by_others",
                    "medium",
                    f"{row['axis']} is unclaimed. You cannot move it alone, and nobody else can move it without the record: "
                    "documenting and reporting the incident is the hand-off, not a formality after the technical work",
                )
            )
    misdirected = [lever.name for lever in environment.levers if not lever.applies(threat)]
    if misdirected:
        verdicts.append(
            Verdict(
                "lever_wrong_threat_class",
                "medium",
                f"{', '.join(misdirected)} does not answer {threat.name}: the cost is real and the effect is zero, which is "
                "the quietest way for a design to be wrong. Scoping is part of the axis, not a detail of it",
            )
        )

    dependency = next(row for row in rows if row["axis"] == "dependency")
    if dependency["marginal"] <= 0:
        verdicts.append(
            Verdict(
                "dependency_unaddressed",
                "low",
                "nothing denies the adversary what they need from your estate, so the threat model rests entirely on "
                "stopping the act rather than on making the result useless or restorable",
            )
        )

    return {
        "threat": threat.name,
        "bare_return": round(bare, 2),
        "with_levers": round(complete, 2),
        "decision": decision,
        "axes": rows,
        "binding": binding["axis"],
        "decisive": decisive["axis"],
        "moved": round(total, 2),
        "ownership_gaps": [row["axis"] for row in rows if row["owner"] == "others" and row["marginal"] <= 0],
        "verdicts": verdicts,
    }


def coverage(environment: Environment) -> Dict[str, object]:
    """Which axes the design touches at all, and which it leans on for everything."""
    touched = {axis: [lever.name for lever in environment.levers if lever.axis == axis] for axis in AXES}
    spend = {axis: sum(lever.annual_cost for lever in environment.levers if lever.axis == axis) for axis in AXES}
    total = sum(spend.values()) or 1.0
    return {
        "touched": {axis: bool(names) for axis, names in touched.items()},
        "levers": touched,
        "spend": spend,
        "share_of_spend": {axis: round(value / total, 4) for axis, value in spend.items()},
        "concentrated": max(spend.values()) / total > 0.75 if total else False,
    }
