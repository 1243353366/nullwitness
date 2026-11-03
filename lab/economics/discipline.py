"""Win and loss discipline: bank the win, bill the loss.

Two failures of nerve, and they pull in opposite directions.

**A win that costs more than it earned.** A detection feels like permission. The evidence is
fresh, the argument is already won, the room is paying attention, and every proposal made in
that mood is a proposal to expand: more controls, wider scope, public attribution, a
countermeasure. The gate exists because that mood is exactly when the arithmetic stops being
consulted. A win changes nothing by default. It may justify **one** change, and only if that
change pays for itself against the same threat book as everything else.

The specific moves this module refuses to let a success authorise:

| Move | Why it is refused here |
| --- | --- |
| public attribution | converts a private advantage into a public target, and an inference into a claim you must defend |
| retaliation | out of scope in this repository, and almost always out of scope legally |
| sweeping scope expansion | breaks operations, and the cost lands on you while the benefit is speculative |
| buying after a scare | a scare is not a threat model; the control still has to return more than it costs |
| tightening everything | degrades the baseline you will need to compare against next time |

**A loss that costs them nothing and teaches you nothing.** The second half is about the loss,
and it has two requirements rather than one. It should hurt them: the attempt should have cost
more than they expected to spend, and the next attempt should cost more still. And it should
leave you something: evidence, a characterised operator, a measured hardening delta. A loss with
neither is a rehearsal for the next one.

So `convert_loss` refuses to record a loss as settled unless it produced at least one item of
leverage, and it refuses to call a loss an exchange when the attacker paid nothing. Both
refusals are findings, not exceptions, because the point is to make the gap visible in a report
rather than to fail a build.

The measure that ties the two halves together is `cost_imposed_per_damage`: what the attacker
spent divided by what the incident cost you. Rising across incidents is the only evidence that
the position is improving, and it is the number an ego-driven escalation destroys, because
escalation raises your costs without raising theirs.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

from lab.economics import adaptation, tiers
from lab.economics.model import Control, Plan, Threat, Verdict

EGO_MOVES = (
    "public_attribution",
    "retaliate",
    "sweep_scope",
    "buy_controls",
    "tighten_everything",
)


@dataclass(frozen=True)
class Win:
    """A success, and whatever it is about to be used to justify."""

    episode: str
    detected_by: str
    attacker_cost: float  # what the attempt cost them: setup plus maintenance actually spent
    proposed: Tuple[str, ...] = ()  # lesson codes proposed *because* the win happened
    claimed_reason: str = ""
    ego_move: str = ""  # one of EGO_MOVES when the proposal is a reaction rather than a reading
    when: float = 0.0  # ordering only; chronology matters because a win and a loss teach differently


@dataclass(frozen=True)
class Loss:
    """A failure, priced from both sides."""

    episode: str
    kind: str
    damage: float  # what it cost you
    attacker_cost: float  # what it cost them to do it
    leverage: Tuple[str, ...] = ()  # evidence, characterisation, or a measured delta
    hardening: Tuple[str, ...] = ()  # finding codes or control names applied as a result
    note: str = ""
    when: float = 0.0


@dataclass
class Settled:
    """The audit trail of both kinds of event."""

    wins: List[dict] = field(default_factory=list)
    losses: List[dict] = field(default_factory=list)
    spend_added_by_wins: float = 0.0
    spend_added_by_losses: float = 0.0

    def scorecard(self) -> Dict[str, object]:
        damage = sum(entry["damage"] for entry in self.losses)
        imposed = sum(entry["attacker_cost"] for entry in self.losses)
        converted = [entry for entry in self.losses if entry["converted"]]
        refused = [entry for entry in self.wins if entry["refused"]]
        return {
            "wins": len(self.wins),
            "wins_banked_unchanged": len([entry for entry in self.wins if not entry["changes"]]),
            "wins_refused_escalation": len(refused),
            "spend_added_by_wins": round(self.spend_added_by_wins, 2),
            "losses": len(self.losses),
            "losses_converted": len(converted),
            "losses_wasted": len([entry for entry in self.losses if not entry["converted"]]),
            "spend_added_by_losses": round(self.spend_added_by_losses, 2),
            "damage_taken": round(damage, 2),
            "attacker_cost_incurred": round(imposed, 2),
            "cost_imposed_per_damage": None if not damage else round(imposed / damage, 2),
            "net_position": round(imposed - damage, 2),
        }


def _benefit_of_adding(plan: Plan, control: Control, threats: Sequence[Threat]) -> float:
    """`plan.benefit` prices removing a control; this prices adding one that is not there yet."""
    with_control = Plan(
        asset=plan.asset,
        controls=list(plan.controls) + [control],
        horizon_months=plan.horizon_months,
        ceiling_ratio=plan.ceiling_ratio,
    )
    return plan.expected_loss(threats) - with_control.expected_loss(threats)


def _check(plan: Plan, control: Control, threats: Sequence[Threat]) -> Optional[str]:
    """Why this change should not happen now, or None if it can.

    The same two tests as everywhere else in the repository, applied to the one moment they are
    least likely to be applied: right after winning.
    """
    if control.annual_cost > plan.asset.value:
        return f"{control.name} costs more than the asset is worth"
    after_ratio = (plan.annual_control_cost + control.annual_cost) / plan.asset.value
    if after_ratio > plan.ceiling_ratio:
        return (
            f"it would put spend at {after_ratio:.1%} of asset value, above the {plan.ceiling_ratio:.0%} ceiling "
            f"for this tier"
        )
    benefit = _benefit_of_adding(plan, control, threats)
    if benefit < control.annual_cost:
        return f"{control.name} returns {benefit:,.0f} against {control.annual_cost:,.0f} of annual cost"
    return None


def settle_win(plan: Plan, win: Win, threats: Sequence[Threat], settled: Optional[Settled] = None) -> Tuple[Plan, Settled]:
    """A win banks its evidence and changes nothing else, unless one change pays for itself.

    Rate limited to one change, because the failure mode this guards against is momentum: three
    plausible changes proposed in the same confident hour add up to a plan nobody reviewed.
    """
    settled = settled or Settled()
    entry: Dict[str, object] = {
        "episode": win.episode,
        "when": win.when,
        "detected_by": win.detected_by,
        "attacker_cost": win.attacker_cost,
        "proposed": list(win.proposed),
        "changes": [],
        "refused": [],
        "verdicts": [],
    }

    if win.ego_move and win.ego_move not in EGO_MOVES:
        raise ValueError(f"unknown ego move {win.ego_move!r}; known: {', '.join(EGO_MOVES)}")

    if win.ego_move:
        entry["refused"].append({"move": win.ego_move, "why": "this is a reaction to winning, not a reading of the threat book"})
        entry["verdicts"].append(
            Verdict(
                "win_escalation_refused",
                "medium",
                f"{win.episode}: a win is being used to justify {win.ego_move}. The win is the expensive part already paid for; "
                "spending it on a bigger position is how a success converts into a larger exposure",
            )
        )

    current = plan
    applied = 0
    for code in win.proposed:
        if applied:
            entry["refused"].append({"code": code, "why": "one change per win: momentum is the failure mode, not the lack of ideas"})
            continue
        lesson = adaptation.LESSONS.get(code)
        if lesson is None:
            if not win.ego_move:
                entry["refused"].append({"code": code, "why": "no lesson: the win does not specify what to change"})
            continue
        if win.ego_move:
            entry["refused"].append({"code": code, "why": "refused while the proposal is an ego move"})
            continue
        candidate, _ = adaptation.run(current, [code], adaptation.Log())
        added = [control for control in candidate.controls if control.name not in {item.name for item in current.controls}]
        changed = [
            (control, next(item for item in current.controls if item.name == control.name))
            for control in candidate.controls
            if control.name in {item.name for item in current.controls}
            and control.reduction > next(item for item in current.controls if item.name == control.name).reduction
        ]
        if not added and not changed:
            entry["refused"].append({"code": code, "why": "already in place: the win changed nothing because nothing needed changing"})
            continue
        blocker = None
        for control in added:
            blocker = _check(current, control, threats)
            if blocker:
                break
        if blocker is None and changed:
            # A strengthened control has no new cost, so only the ceiling can block it.
            if current.spend_ratio > current.ceiling_ratio:
                blocker = "spend is above the ceiling"
        if blocker:
            entry["refused"].append({"code": code, "why": blocker})
            entry["verdicts"].append(
                Verdict(
                    "win_escalation_refused",
                    "medium",
                    f"{win.episode}: {code} was proposed after a win and refused: {blocker}. A success is the worst time to buy, "
                    "because the argument is already won and the arithmetic is not being consulted",
                )
            )
            continue

        spend_added = candidate.annual_control_cost - current.annual_control_cost
        entry["changes"].append(
            {
                "code": code,
                "added": [control.name for control in added],
                "strengthened": [control.name for control, _ in changed],
                "spend_added": spend_added,
            }
        )
        settled.spend_added_by_wins += spend_added
        current = candidate
        applied += 1

    if not entry["changes"] and not entry["refused"]:
        entry["verdicts"].append(
            Verdict(
                "win_banked",
                "low",
                f"{win.episode}: banked. The attempt cost them {win.attacker_cost:,.0f} and the position is unchanged, which is the "
                "outcome to prefer: a win that changes nothing cannot be the reason the next loss is bigger",
            )
        )
    settled.wins.append(entry)
    return current, settled


def _harden(plan: Plan, code: str) -> Plan:
    """Hardening is nameable either as a finding code or as the control to add.

    Unknown names raise rather than doing nothing: a hardening step that silently applies
    nothing is the exact failure `hardening_already_in_place` exists to expose, and a typo
    should not be able to look like diligence.
    """
    if code in tiers.CONTROLS:
        if code in {control.name for control in plan.controls}:
            return plan
        return Plan(
            asset=plan.asset,
            controls=list(plan.controls) + [tiers.CONTROLS[code]],
            horizon_months=plan.horizon_months,
            ceiling_ratio=plan.ceiling_ratio,
        )
    if code in adaptation.LESSONS:
        return adaptation.run(plan, [code], adaptation.Log())[0]
    raise KeyError(f"unknown hardening step {code!r}: not a control and not a lesson")


def convert_loss(plan: Plan, loss: Loss, threats: Sequence[Threat], settled: Optional[Settled] = None) -> Tuple[Plan, Settled]:
    """A loss has to hurt them and pay you, or it is recorded as wasted."""
    settled = settled or Settled()
    before_setup = {threat.name: plan.attacker_setup(threat) for threat in threats}
    entry: Dict[str, object] = {
        "episode": loss.episode,
        "when": loss.when,
        "kind": loss.kind,
        "damage": loss.damage,
        "attacker_cost": loss.attacker_cost,
        "leverage": list(loss.leverage),
        "hardening": list(loss.hardening),
        "converted": False,
        "verdicts": [],
    }

    current = plan
    for code in loss.hardening:
        current = _harden(current, code)
    added_cost = current.annual_control_cost - plan.annual_control_cost
    settled.spend_added_by_losses += added_cost
    entry["spend_added"] = added_cost

    after_setup = {threat.name: current.attacker_setup(threat) for threat in threats}
    raised = [name for name, value in after_setup.items() if value > before_setup[name]]
    entry["next_attempt_costlier_for"] = raised

    if loss.attacker_cost <= 0:
        entry["verdicts"].append(
            Verdict(
                "loss_free_for_them",
                "high",
                f"{loss.episode}: the attacker paid nothing for this. A cost-free attempt is an invitation to repeat it, "
                "whatever it cost you",
            )
        )
    if not loss.leverage:
        entry["verdicts"].append(
            Verdict(
                "loss_wasted",
                "high",
                f"{loss.episode}: nothing reusable came out of this. No evidence, no characterisation, no measured delta, so the "
                "next attempt starts from the same position and the loss bought nothing",
            )
        )

    entry["converted"] = bool(loss.leverage) and loss.attacker_cost > 0
    if entry["converted"]:
        entry["verdicts"].append(
            Verdict(
                "loss_converted",
                "low",
                f"{loss.episode}: cost them {loss.attacker_cost:,.0f} against {loss.damage:,.0f} of damage, and produced "
                f"{len(loss.leverage)} item(s) of leverage with {len(raised)} threat(s) now dearer to repeat",
            )
        )
    if loss.hardening and not raised:
        code = "hardening_already_in_place" if added_cost == 0 else "hardening_without_effect"
        detail = (
            f"{loss.episode}: every hardening step listed was already in the plan, so the loss changed nothing about the next attempt"
            if added_cost == 0
            else f"{loss.episode}: hardening was paid for but no threat became more expensive to repeat. That is spend, not leverage"
        )
        entry["verdicts"].append(Verdict(code, "medium" if code.endswith("effect") else "low", detail))

    settled.losses.append(entry)
    return current, settled


def year(plan: Plan, wins: Sequence[Win], losses: Sequence[Loss], threats: Sequence[Threat]) -> Tuple[Plan, Settled]:
    """Run a set of events in order and return the plan, the audit trail, and the scorecard."""
    settled = Settled()
    current = plan
    events = sorted(
        [("win", win.when, index, win) for index, win in enumerate(wins)]
        + [("loss", loss.when, index, loss) for index, loss in enumerate(losses)],
        key=lambda item: (item[1], item[0] != "loss", item[2]),
    )
    for kind, _, _, event in events:
        if kind == "win":
            current, settled = settle_win(current, event, threats, settled)
        else:
            current, settled = convert_loss(current, event, threats, settled)
    return current, settled


def ego_debt(settled: Settled) -> List[str]:
    """The scoreboard for the first failure mode: wins that turned into bigger positions."""
    debt: List[str] = []
    for entry in settled.wins:
        for refusal in entry["refused"]:
            debt.append(f"{entry['episode']}: {refusal.get('move') or refusal.get('code')} ({refusal['why']})")
    return debt
