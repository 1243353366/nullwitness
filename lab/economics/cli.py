"""Command line for the economics layer.

    python3 -m lab.economics.cli ladder
    python3 -m lab.economics.cli report --value 250000
    python3 -m lab.economics.cli report --value 250000 --json
    python3 -m lab.economics.cli adapt --value 250000 --codes envelope_substituted,key_compromise
    python3 -m lab.economics.cli demo

The report answers four questions in order, because that is the order they have to be answered
in: what does this asset oblige me to run, what is that costing me against the loss it prevents,
what does the attacker still get out of it, and what would I recover if it went wrong today.
"""

from __future__ import annotations

import argparse
import json
from typing import Dict, List, Optional, Sequence

from lab.economics import adaptation, discipline, fingerprint, resilience, tiers, timing
from lab.economics.model import Asset, Plan, Threat, Verdict
from lab.economics.tiers import CONTROLS, DEFAULT_THREATS


def _asset(value: float, tier: Optional[int] = None, name: str = "asset") -> Asset:
    return Asset(name=name, value=value, tier=tier if tier is not None else tiers.tier_for(value).tier)


def _money(value: float) -> str:
    return f"{value:,.0f}"


def _render_report(asset: Asset, plan: Plan, threats: Sequence[Threat], depth: int) -> str:
    spec = tiers.spec(asset.tier)
    lines: List[str] = []
    lines.append(f"{asset.name}: value {_money(asset.value)}, tier {asset.tier} ({spec.name})")
    lines.append("")

    lines.append("obligations")
    for name in spec.required:
        present = name in {control.name for control in plan.controls}
        lines.append(f"  [{'x' if present else ' '}] {name}")
    lines.append("")

    lines.append(f"cost and return (annual, {_money(plan.annual_control_cost)} total, "
                 f"{plan.spend_ratio:.1%} of asset value, ceiling {plan.ceiling_ratio:.0%})")
    lines.append(f"  {'control':<26} {'cost':>8} {'benefit':>10} {'roi':>6} {'maint x':>8}")
    for control in plan.controls:
        roi = plan.roi(control, threats)
        lines.append(
            f"  {control.name:<26} {_money(control.annual_cost):>8} {_money(plan.benefit(control, threats)):>10} "
            f"{('inf' if roi == float('inf') else f'{roi:.2f}'):>6} {control.maintenance_effect:>8.1f}"
        )
    lines.append(f"  expected loss with this plan: {_money(plan.expected_loss(threats))}")
    lines.append("")

    lines.append("attacker economics")
    lines.append(f"  {'threat':<26} {'loot':>9} {'setup':>9} {'monthly':>8} {'return':>10} {'breakeven':>10}")
    for threat in threats:
        breakeven = plan.breakeven_months(threat)
        lines.append(
            f"  {threat.name:<26} {_money(threat.loot(asset.value)):>9} {_money(plan.attacker_setup(threat)):>9} "
            f"{_money(plan.attacker_maintenance(threat)):>8} {_money(plan.attacker_return(threat)):>10} "
            f"{('never' if breakeven is None else f'{breakeven:.1f}mo'):>10}"
        )
    lines.append("")

    lines.append(f"fingerprint depth {depth} ({fingerprint.DEPTH_NAMES[depth]}): "
                 f"{fingerprint.DEPTH_CAPABILITY[depth]}")
    gap = fingerprint.depth_gap(asset.tier, depth)
    if gap:
        lines.append(f"  tier {asset.tier} would want depth {gap['to']}: +{_money(gap['annual_cost'])} annual")
    lines.append("")

    lines.append("recovery")
    for failure, state in resilience.coverage(plan).items():
        if state["covered"]:
            lines.append(
                f"  {failure:<22} covered by {', '.join(state['guarantees'])} "
                f"(about {state['best_recovery_hours']:g}h, evidence kept: {state['evidence_kept']})"
            )
        else:
            lines.append(f"  {failure:<22} not covered")
    drill = resilience.drill_gap(plan)
    if drill:
        lines.append(f"  warning: {drill['code']}: {drill['suggest']}")
    lines.append("")

    verdicts = plan.evaluate(threats, required=spec.required)
    lines.append("verdicts")
    if not verdicts:
        lines.append("  none")
    for verdict in sorted(verdicts, key=lambda item: ({"high": 0, "medium": 1, "low": 2}[item.severity], item.code)):
        lines.append(f"  [{verdict.severity}] {verdict.code}: {verdict.detail}")
    lines.append("")

    hint = tiers.promotion_hint(plan, threats)
    if hint:
        lines.append(
            f"promotion: tier {hint['from_tier']} -> {hint['to_tier']} ({hint['to_name']}) because "
            f"{hint['why']}; add {', '.join(hint['controls_to_add'])} for +{_money(hint['added_annual_cost'])}, "
            f"which puts spend at {hint['new_spend_ratio']:.1%} and fingerprint depth at "
            f"{hint['fingerprint_depth_change'][1]}"
        )
    else:
        lines.append("promotion: no evidence that the next rung is justified yet")
    return "\n".join(lines)


def _report_dict(asset: Asset, plan: Plan, threats: Sequence[Threat], depth: int) -> Dict[str, object]:
    spec = tiers.spec(asset.tier)
    return {
        "asset": {"name": asset.name, "value": asset.value, "tier": asset.tier, "tier_name": spec.name},
        "obligations": list(spec.required),
        "plan": plan.summary(threats),
        "verdicts": [
            {"code": verdict.code, "severity": verdict.severity, "detail": verdict.detail}
            for verdict in plan.evaluate(threats, required=spec.required)
        ],
        "fingerprint": {"depth": depth, "name": fingerprint.DEPTH_NAMES[depth], "gap": fingerprint.depth_gap(asset.tier, depth)},
        "recovery": resilience.coverage(plan),
        "gaps": resilience.gaps(plan),
        "drill": resilience.drill_gap(plan),
        "promotion": tiers.promotion_hint(plan, threats),
    }


def _year_events():
    """Four events in one year, written to exercise both halves of the discipline."""
    wins = [
        discipline.Win(
            "day 40: substitution caught at the archive boundary",
            "digest_chain",
            attacker_cost=6_160,
            when=40,
            proposed=("boot_measurement_mismatch", "key_compromise"),
            claimed_reason="we caught them, so we must be a target",
        ),
        discipline.Win(
            "day 90: replay refused",
            "replay check",
            attacker_cost=400,
            when=90,
            proposed=("public_attribution",),
            ego_move="public_attribution",
        ),
    ]
    losses = [
        discipline.Loss(
            "day 30: decoy swept, real files untouched",
            "evidence_quality",
            damage=2_000,
            attacker_cost=9_500,
            when=30,
            leverage=("precision signature recorded", "timing matches the earlier attempt"),
            hardening=("rotation_cadence",),
        ),
        discipline.Loss(
            "day 120: laptop stolen, unsealed notes gone",
            "record_lost",
            damage=18_000,
            attacker_cost=300,
            when=120,
        ),
    ]
    return wins, losses


def _discipline(value: float) -> str:
    asset = _asset(value, name="customer audit trail")
    plan = tiers.plan_for(asset)
    wins, losses = _year_events()
    after, settled = discipline.year(plan, wins, losses, DEFAULT_THREATS)

    lines = [f"{asset.name}: tier {asset.tier}, plan {_money(plan.annual_control_cost)}/year", ""]
    for entry in sorted(settled.losses, key=lambda item: item["when"]):
        lines.append(f"loss  {entry['episode']}")
        lines.append(
            f"      damage {_money(entry['damage'])}, attacker paid {_money(entry['attacker_cost'])}, "
            f"leverage {len(entry['leverage'])}, hardening spend {_money(entry.get('spend_added', 0))}"
        )
        if entry["next_attempt_costlier_for"]:
            lines.append(f"      dearer to repeat: {', '.join(entry['next_attempt_costlier_for'])}")
        for verdict in entry["verdicts"]:
            lines.append(f"      [{verdict.severity}] {verdict.code}: {verdict.detail}")
    lines.append("")
    for entry in sorted(settled.wins, key=lambda item: item["when"]):
        lines.append(f"win   {entry['episode']}")
        lines.append(f"      attacker paid {_money(entry['attacker_cost'])}; changes: {[c['code'] for c in entry['changes']] or 'none'}")
        for refusal in entry["refused"]:
            lines.append(f"      refused {refusal.get('move') or refusal.get('code')}: {refusal['why']}")
        for verdict in entry["verdicts"]:
            lines.append(f"      [{verdict.severity}] {verdict.code}: {verdict.detail}")
    lines.append("")

    card = settled.scorecard()
    lines.append("scorecard")
    for key in ("wins", "wins_banked_unchanged", "wins_refused_escalation", "spend_added_by_wins",
                "losses", "losses_converted", "losses_wasted", "spend_added_by_losses",
                "damage_taken", "attacker_cost_incurred", "cost_imposed_per_damage", "net_position"):
        lines.append(f"  {key:<26} {card[key]}")
    lines.append("")
    lines.append(f"  plan {_money(plan.annual_control_cost)} -> {_money(after.annual_control_cost)}; "
                 f"obligations held: {set(tiers.required(asset.tier)) <= {control.name for control in after.controls}}")
    lines.append(
        "  cost_imposed_per_damage below 1.0 means they are still ahead on this asset: the exchange rate is the number to "
        "move, and no win changes it on its own"
    )
    return "\n".join(lines)


TIMING_SCENARIOS = {
    "slow bleed, evidence still worth collecting": dict(
        damage_per_hour=80,
        dwell_hours=48,
        evidence_value=40_000,
        destroy_if_tipped=0.7,
        tactics_shift_cost=25_000,
        capability=0.7,
        maturity=1,
    ),
    "fast bleed, evidence mostly collected": dict(
        damage_per_hour=9_000,
        dwell_hours=12,
        evidence_value=8_000,
        destroy_if_tipped=0.6,
        tactics_shift_cost=5_000,
        capability=0.6,
        maturity=2,
    ),
}


def _timing() -> str:
    lines: List[str] = []
    for title, values in TIMING_SCENARIOS.items():
        situation = timing.Situation(**values)
        lines.append(f"{title}: bleeding {_money(situation.damage_per_hour)}/hour, "
                     f"{situation.dwell_hours:g}h of dwell, {_money(situation.evidence_value)} of evidence uncollected")
        lines.append(f"  {'action':<20} {'avail':>6} {'stopped':>9} {'evid lost':>10} {'tactics':>9} {'self':>8} {'net':>11}")
        for row in timing.assess(situation):
            lines.append(
                f"  {row['action']:<20} {('yes' if row['available'] else 'no'):>6} {_money(row['damage_avoided']):>9} "
                f"{_money(row['evidence_forfeited']):>10} {_money(row['tactics_cost']):>9} {_money(row['self_inflicted']):>8} "
                f"{_money(row['net']):>11}"
            )
        steps = timing.recommended_sequence(situation)
        plan = timing.sequence(situation, steps)
        lines.append(f"  sequence: {' -> '.join(steps)}")
        lines.append(f"  cumulative leak across the sequence: {plan['cumulative_leak']:.0%}; net {_money(plan['cumulative_net'])}")
        for action in ("evict", "silent_containment"):
            for verdict in timing.judge(situation, action):
                lines.append(f"  [{verdict.severity}] {verdict.code}: {verdict.detail}")
        lines.append("")
    lines.append("A hold is not inaction: it is capture plus observation, paid for while the adversary is unaware,")
    lines.append("so that the revealing move happens once, on your schedule, with the picture complete.")
    return "\n".join(lines)


def _ladder(value: float, threats: Sequence[Threat]) -> str:
    lines = [f"ladder for an asset worth {_money(value)}", ""]
    lines.append(f"  {'tier':<5} {'name':<12} {'controls':>8} {'cost':>9} {'spend':>7} {'exp loss':>10} {'depth':>6}")
    for spec in tiers.TIERS:
        plan = tiers.plan_for(Asset("probe", max(value, 1.0), tier=spec.tier))
        lines.append(
            f"  {spec.tier:<5} {spec.name:<12} {len(spec.required):>8} {_money(plan.annual_control_cost):>9} "
            f"{plan.spend_ratio:>6.1%} {_money(plan.expected_loss(threats)):>10} {spec.fingerprint_depth:>6}"
        )
    lines.append("")
    lines.append("  The tier an asset is actually in is set by its value, not by ambition:")
    at = tiers.tier_for(value)
    lines.append(f"  {_money(value)} lands at tier {at.tier} ({at.name}), fingerprint depth {at.fingerprint_depth}.")
    return "\n".join(lines)


def _demo() -> str:
    threats = DEFAULT_THREATS
    value = 250_000.0
    asset = _asset(value, name="customer audit trail")
    plan = tiers.plan_for(asset)
    out = [_render_report(asset, plan, threats, fingerprint.depth_for(asset.tier)), ""]

    out.append("=" * 78)
    out.append("two failures arrive: a key was reachable, and a kernel measured differently")
    out.append("=" * 78)
    codes = ["key_compromise", "boot_measurement_mismatch"]
    after, log = adaptation.run(plan, codes, adaptation.Log())
    measured = adaptation.effect(plan, after, threats)
    for code in codes:
        out.append(f"  what it taught: {adaptation.LESSONS[code].reading}")
    out.append(f"  what changed:  {after.annual_control_cost - plan.annual_control_cost:+,.0f} annual cost")
    out.append(
        f"  measured:      expected loss {measured['expected_loss'][0]:,.0f} -> {measured['expected_loss'][1]:,.0f}, "
        f"firmware_implant attacker return {measured['attacker_return']['firmware_implant'][0]:,.0f} -> "
        f"{measured['attacker_return']['firmware_implant'][1]:,.0f}"
    )
    again, _ = adaptation.run(after, codes, adaptation.Log())
    out.append(
        f"  idempotent:    second pass changes nothing ({again.annual_control_cost == after.annual_control_cost})"
    )
    out.append(f"  still profitable: {', '.join(measured['still_profitable']) or 'nothing material'}")
    out.append("")

    out.append("the same arithmetic now reviews its own decision")
    over = [
        verdict
        for verdict in after.evaluate(threats, required=tiers.spec(asset.tier).required)
        if verdict.code == "control_overinvestment"
    ]
    if over:
        for verdict in over:
            out.append(f"  [proportionality] {verdict.detail}")
        trimmed, _ = adaptation.trim(after, threats, adaptation.Log())
        out.append(
            f"  after trim:    cost {_money(trimmed.annual_control_cost)}, expected loss "
            f"{_money(trimmed.expected_loss(threats))}, still holds every tier obligation: "
            f"{set(tiers.spec(asset.tier).required) <= {control.name for control in trimmed.controls}}"
        )
    else:
        trim_check, _ = adaptation.trim(after, threats, adaptation.Log())
        out.append(f"  nothing to trim: every control pays for itself at this asset value")
    out.append("")

    out.append("=" * 78)
    out.append("the loop, over three incidents, in proportion to what they are getting")
    out.append("=" * 78)
    incidents = [
        fingerprint.Incident(("ciphertext_tampered",), when=1_760_000_000.0, boundary="wire"),
        fingerprint.Incident(("plaintext_tampered", "record_removed"), when=1_760_360_000.0, boundary="sink", evaded=("decoy_sweep_uniform",)),
        fingerprint.Incident(("envelope_substituted", "stream_head_mismatch"), when=1_760_400_000.0, boundary="archive", evaded=("decoy_sweep_uniform", "clock_creep")),
    ]
    graded, _ = adaptation.run(after, [code for incident in incidents for code in incident.codes], adaptation.Log())
    for depth in (1, 2, 3, 4):
        profile = fingerprint.build_profile(incidents, depth)
        out.append(
            f"  depth {depth} ({fingerprint.DEPTH_NAMES[depth]}): "
            f"techniques {len(profile.techniques)}, precision {profile.precision or 'n/a'}, "
            f"cadence {profile.cadence_hours or 'n/a'}, confidence {profile.confidence}"
        )
        for refusal in profile.refused:
            out.append(f"      refused: {refusal}")
    out.append("")
    out.append(f"  after acting on all three incidents: cost {_money(graded.annual_control_cost)}, "
               f"expected loss {_money(graded.expected_loss(threats))}, spend {graded.spend_ratio:.1%}")
    return "\n".join(out)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Defense economics")
    parser.add_argument("action", choices=["ladder", "report", "adapt", "demo", "discipline", "timing"], nargs="?", default="report")
    parser.add_argument("--value", type=float, default=250_000.0)
    parser.add_argument("--tier", type=int, default=None)
    parser.add_argument("--name", default="asset")
    parser.add_argument("--codes", default="", help="comma-separated finding codes to adapt to")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    threats = DEFAULT_THREATS

    if args.action == "demo":
        print(_demo())
        return 0

    if args.action == "ladder":
        print(_ladder(args.value, threats))
        return 0

    if args.action == "timing":
        if args.json:
            payload = {}
            for title, values in TIMING_SCENARIOS.items():
                situation = timing.Situation(**values)
                steps = timing.recommended_sequence(situation)
                payload[title] = {
                    "assess": timing.assess(situation),
                    "judgements": {action: [v.__dict__ for v in timing.judge(situation, action)]
                                   for action in ("evict", "silent_containment")},
                    "sequence": timing.sequence(situation, steps),
                }
            print(json.dumps(payload, indent=2, sort_keys=True))
            return 0
        print(_timing())
        return 0

    if args.action == "discipline":
        if args.json:
            asset = _asset(args.value, name="customer audit trail")
            wins, losses = _year_events()
            after, settled = discipline.year(tiers.plan_for(asset), wins, losses, threats)
            print(json.dumps(
                {"scorecard": settled.scorecard(), "wins": settled.wins, "losses": settled.losses,
                 "ego_debt": discipline.ego_debt(settled)},
                indent=2, sort_keys=True, default=str,
            ))
            return 0
        print(_discipline(args.value))
        return 0

    asset = _asset(args.value, tier=args.tier, name=args.name)
    plan = tiers.plan_for(asset)

    if args.action == "adapt":
        codes = [code.strip() for code in args.codes.split(",") if code.strip()]
        after, log = adaptation.run(plan, codes, adaptation.Log())
        if args.json:
            print(json.dumps({"log": log.entries, "effect": adaptation.effect(plan, after, threats)}, indent=2, sort_keys=True))
            return 0
        print(f"adapted to {len(codes)} finding code(s)")
        for entry in log.entries:
            print(f"  {entry}")
        effect = adaptation.effect(plan, after, threats)
        print(f"  expected loss {effect['expected_loss'][0]:,.0f} -> {effect['expected_loss'][1]:,.0f}")
        print(f"  annual cost {effect['annual_cost'][0]:,.0f} -> {effect['annual_cost'][1]:,.0f}")
        for threat_name, (before, after_return) in effect["attacker_return"].items():
            if before != after_return:
                print(f"  {threat_name}: attacker return {before:,.0f} -> {after_return:,.0f}")
        return 0

    depth = fingerprint.depth_for(asset.tier)
    if args.json:
        print(json.dumps(_report_dict(asset, plan, threats, depth), indent=2, sort_keys=True))
    else:
        print(_render_report(asset, plan, threats, depth))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
