"""Adaptation: each finding becomes a change that costs the attacker more next time.

The loop has four steps and most organizations run two of them:

    finding -> reading -> change -> effect, measured

Skipping the third is logging. Skipping the fourth is faith. This module makes the loop
mechanical enough to be honest about: a finding code maps to one reading, one action, and a
measurable change in either the attacker's return or the expected loss. After the change, the
arithmetic runs again and says whether it worked.

Two properties are enforced rather than hoped for:

- **idempotent.** Applying the same lesson twice changes nothing. Re-running the loop over old
  findings is normal, and it must not ratchet the plan on every pass.
- **monotone where it should be.** Tightening only raises reductions or adds controls. A
  tightening that could loosen something is a bug, not a nuance, and the tests assert the
  direction. The exception is deliberate: `trim` removes a control that is not paying for
  itself, because adaptation that can only add is how a control set becomes a museum.

Adaptation debt is the number that matters operationally: findings that arrived and produced no
change. A team with a growing debt is collecting evidence of its own blind spots and filing it.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from lab.economics.model import Asset, Control, Plan, Threat
from lab.economics.tiers import CONTROLS, spec, TIERS


@dataclass(frozen=True)
class Lesson:
    """One finding code, read once, turned into one action."""

    code: str
    reading: str
    action: str  # add | strengthen | promote | trim | retain
    target: str = ""
    delta: float = 0.0
    note: str = ""


LESSONS: Dict[str, Lesson] = {
    "ciphertext_tampered": Lesson(
        "ciphertext_tampered",
        "someone wrote to the wire or the store with enough access to matter",
        "strengthen",
        "aes_gcm_envelope",
        0.10,
        "raise the envelope's cost: the attack happened, so the estimate of their capability was low",
    ),
    "envelope_substituted": Lesson(
        "envelope_substituted",
        "a valid envelope was replaced by another valid envelope, which means the swap was undetectable to the cipher",
        "add",
        "digest_anchor_offhost",
        note="the digest chain caught it; putting its head off-host means the next attempt must reach further",
    ),
    "envelope_missing": Lesson(
        "envelope_missing",
        "records were removed and the survivors all verified",
        "add",
        "digest_ledger",
        note="completeness needs a record of what was written, not just a check of what remains",
    ),
    "plaintext_tampered": Lesson(
        "plaintext_tampered",
        "content changed outside the cipher, which is the layer encryption cannot see",
        "strengthen",
        "source_seal",
        0.10,
        "seal earlier and more often: the endpoint is the exposed surface",
    ),
    "seal_forged": Lesson(
        "seal_forged",
        "a record carried a seal the key did not produce",
        "strengthen",
        "key_custody_separation",
        0.05,
        "if the seal key is reachable, separation was nominal rather than real",
    ),
    "stream_head_mismatch": Lesson(
        "stream_head_mismatch",
        "the tail of a stream was removed where every surviving record verified",
        "add",
        "digest_anchor_offhost",
        note="a head that lives only on the compromised host is not an anchor",
    ),
    "record_replayed": Lesson(
        "record_replayed",
        "a genuine record was offered twice",
        "add",
        "replay_guard",
        note="authenticity without freshness is not authentication of a moment",
    ),
    "boot_measurement_mismatch": Lesson(
        "boot_measurement_mismatch",
        "the code handling the plaintext was not the code that was approved",
        "add",
        "boot_attestation",
        note="at this point the question stopped being about records and became about the machine",
    ),
    "boot_rollback": Lesson(
        "boot_rollback",
        "firmware was downgraded to a version with a known flaw",
        "strengthen",
        "boot_attestation",
        0.10,
        "raise the security-version floor and keep the counter where it cannot be reset",
    ),
    "key_permissions_loose": Lesson(
        "key_permissions_loose",
        "the key was readable by more principals than the one that needs it",
        "add",
        "key_custody_separation",
        note="cheap control, expensive finding: separation is mostly a permissions problem",
    ),
    "ledger_rollback": Lesson(
        "ledger_rollback",
        "the ledger and its anchor were rolled back together",
        "add",
        "digest_anchor_offhost",
        note="move the anchor somewhere the attacker does not already have root",
    ),
    "digest_ledger_tampered": Lesson(
        "digest_ledger_tampered",
        "the digest chain did not verify",
        "add",
        "digest_anchor_offhost",
        note="a chain nobody witnesses is a chain they can rewrite",
    ),
    "decoy_sweep_uniform": Lesson(
        "decoy_sweep_uniform",
        "every real file was touched and no decoy was: the sweep was tailored rather than blind",
        "add",
        "fingerprint_depth_high",
        note="precision is the tell, so the cheapest response is to record it properly next time",
    ),
    # Economics verdicts are findings too, and they are the ones that move the ladder.
    "key_compromise": Lesson(
        "key_compromise",
        "a key was reachable by someone it should not have been: the plan priced that as unlikely",
        "add",
        "key_custody_separation",
        note="separation is not a stronger lock, it is a smaller blast radius when one key goes",
    ),
    "attacker_profitable": Lesson(
        "attacker_profitable",
        "an attempt still pays for the attacker at this tier",
        "promote",
        note="this is the evidence that justifies the next rung, which is what makes the ladder movement honest",
    ),
    "control_missing": Lesson(
        "control_missing",
        "the tier's floor was not being met, so the expected loss was uncovered by the spend",
        "promote",
        note="meeting the floor first; extras come after",
    ),
    "control_overinvestment": Lesson(
        "control_overinvestment",
        "a control returns less than it costs, which is a finding about the budget rather than the threat",
        "trim",
        note="deliberate loosening: review with `trim`, which removes only controls the tier does not require",
    ),
    "clock_creep": Lesson(
        "clock_creep",
        "accumulated clock drift indicates checkpoints were stretched rather than skipped",
        "add",
        "replay_guard",
        note="freshness checks turn a patient attacker into an impatient one",
    ),
}


@dataclass
class Log:
    """What was learned and what was done about it."""

    entries: List[dict] = field(default_factory=list)
    applied: set = field(default_factory=set)

    def record(self, code: str, summary: dict) -> None:
        self.entries.append({"code": code, **summary})
        self.applied.add(code)

    def debt(self, seen: Iterable[str]) -> List[str]:
        """Findings that arrived and produced no change: the operational number."""
        return sorted({code for code in seen if code not in self.applied})


def _strengthen(control: Control, delta: float) -> Control:
    raised = min(0.95, round(control.reduction + delta, 4))
    return replace(control, reduction=raised)


def apply_lesson(plan: Plan, lesson: Lesson, log: Log) -> Plan:
    """One lesson, applied once. A second application is a no-op, by construction."""
    if lesson.code in log.applied:
        log.entries.append({"code": lesson.code, "skipped": "already applied"})
        return plan

    present = {control.name: control for control in plan.controls}
    controls = list(plan.controls)
    changed: Dict[str, object] = {"action": lesson.action, "target": lesson.target}

    if lesson.action == "add":
        if lesson.target in present:
            log.record(lesson.code, {**changed, "skipped": "control already present"})
            return plan
        if lesson.target not in CONTROLS:
            raise KeyError(f"lesson {lesson.code} names unknown control {lesson.target!r}")
        controls.append(CONTROLS[lesson.target])
        changed["added"] = lesson.target

    elif lesson.action == "strengthen":
        if lesson.target not in present:
            log.record(lesson.code, {**changed, "skipped": "control not in plan; add it first"})
            return plan
        strengthened = _strengthen(present[lesson.target], lesson.delta)
        controls = [strengthened if control.name == lesson.target else control for control in controls]
        changed["reduction"] = (present[lesson.target].reduction, strengthened.reduction)

    elif lesson.action == "promote":
        current = plan.asset.tier
        if current >= len(TIERS) - 1:
            log.record(lesson.code, {**changed, "skipped": "top tier already"})
            return plan
        for name in spec(current + 1).required:
            if name not in present:
                controls.append(CONTROLS[name])
                changed.setdefault("added", []).append(name)
        changed["tier"] = (current, current + 1)

    elif lesson.action == "trim":
        # Trimming needs the threat book to judge, so it is a review action rather than an
        # automatic removal: the plan is unchanged here and the log says who has to decide.
        changed["note"] = "review with trim(): removing controls needs the threat book, not just the code"
        changed["action"] = "trim_review"

    elif lesson.action == "retain":
        changed["note"] = lesson.note
    else:
        raise ValueError(f"unknown lesson action {lesson.action!r}")

    log.record(lesson.code, changed)
    return Plan(
        asset=plan.asset,
        controls=controls,
        horizon_months=plan.horizon_months,
        ceiling_ratio=plan.ceiling_ratio,
    )


def run(plan: Plan, codes: Sequence[str], log: Optional[Log] = None) -> Tuple[Plan, Log]:
    """Apply every known lesson for the findings, in a fixed order, idempotently."""
    log = log or Log()
    current = plan
    for code in sorted(set(codes)):
        lesson = LESSONS.get(code)
        if lesson is None:
            log.entries.append({"code": code, "skipped": "no lesson: this finding taught nothing yet"})
            continue
        current = apply_lesson(current, lesson, log)
    return current, log


def trim(plan: Plan, threats: Sequence[Threat], log: Optional[Log] = None) -> Tuple[Plan, Log]:
    """Remove controls that cost more than the loss they prevent.

    Adaptation that only adds is how a control set becomes a museum. This is the deliberate
    loosening the module allows, and it is driven by the same arithmetic as everything else: a
    control whose benefit is below its cost is removed, with a record of having done it.
    """
    log = log or Log()
    kept: List[Control] = []
    removed: List[str] = []
    for control in plan.controls:
        if plan.benefit(control, threats) < control.annual_cost and control.name not in spec(plan.asset.tier).required:
            removed.append(control.name)
            continue
        kept.append(control)
    if removed:
        log.record("trim", {"action": "trim", "removed": removed, "why": "benefit below annual cost"})
    return (
        Plan(asset=plan.asset, controls=kept, horizon_months=plan.horizon_months, ceiling_ratio=plan.ceiling_ratio),
        log,
    )


def effect(before: Plan, after: Plan, threats: Sequence[Threat]) -> Dict[str, object]:
    """Did the change actually do anything? Measured, not assumed."""
    return {
        "expected_loss": (round(before.expected_loss(threats), 2), round(after.expected_loss(threats), 2)),
        "annual_cost": (round(before.annual_control_cost, 2), round(after.annual_control_cost, 2)),
        "spend_ratio": (round(before.spend_ratio, 4), round(after.spend_ratio, 4)),
        "attacker_return": {
            threat.name: (round(before.attacker_return(threat), 2), round(after.attacker_return(threat), 2))
            for threat in threats
        },
        "still_profitable": [threat.name for threat in threats if after.attacker_return(threat) > 0],
    }
