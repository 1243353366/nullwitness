"""Resilience: what survives, what you get back, and how long it takes.

Prevention and resilience are separate budgets and they fail separately. An organization that
has spent everything on stopping the attack has nothing left for the case where it is stopped
being true, and the case arrives eventually. This module prices the second budget.

Resilience has two halves and they are not the same purchase:

- **trustworthy evidence.** Not "we have logs". Evidence that survives the incident: a chain
  whose head lives somewhere the attacker did not reach, digests that do not depend on the key,
  and enough context to say what happened without asking the person who did it.
- **recovery options.** The ability to get back to a known state: an immutable copy, a way to
  restore it that has been tried, and keys that can be reconstructed after loss rather than
  only before theft.

Each guarantee below names the failure classes it covers, the control in `tiers.py` that
provides it, and a recovery time. The recovery times are planning figures in hours: the point
is the order of magnitude and the difference between "restore and verify" and "reconstruct from
memory", not a service-level commitment.

The check that matters most is not coverage, it is **rehearsal**. A backup that has never been
restored is a hypothesis. `drill_gap` exists to name that, because a resilience plan with no
drill in it is the most common way this whole budget gets spent on a feeling.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence, Tuple

from lab.economics.model import Plan

FAILURE_CLASSES = (
    "file_deleted",
    "backdated_edit",
    "substituted_record",
    "ledger_forged",
    "ledger_rolled_back",
    "key_lost",
    "key_stolen",
    "host_rebuilt",
    "storage_corrupted",
)


@dataclass(frozen=True)
class Guarantee:
    """One thing that survives one class of failure, and what it costs to have it."""

    name: str
    covers: Tuple[str, ...]
    provided_by: Tuple[str, ...]  # control names from tiers.CONTROLS
    evidence: bool  # does it preserve evidence, or only restore state
    recovery_hours: float
    note: str


GUARANTEES: Tuple[Guarantee, ...] = (
    Guarantee(
        name="digest_chain",
        covers=("substituted_record", "backdated_edit"),
        provided_by=("baseline_hashing", "digest_ledger"),
        evidence=True,
        recovery_hours=0.0,
        note="you can prove what the record was without being able to read it, which is what makes "
        "verification cheap enough to run continuously",
    ),
    Guarantee(
        name="source_seal_records",
        covers=("substituted_record", "backdated_edit", "file_deleted"),
        provided_by=("source_seal",),
        evidence=True,
        recovery_hours=0.0,
        note="sealed at capture, so the record's original content survives the endpoint that lost it",
    ),
    Guarantee(
        name="offhost_anchor",
        covers=("ledger_rolled_back", "ledger_forged"),
        provided_by=("digest_anchor_offhost",),
        evidence=True,
        recovery_hours=1.0,
        note="the only guarantee that survives an attacker who owns the host and both its files",
    ),
    Guarantee(
        name="append_only_history",
        covers=("ledger_forged", "ledger_rolled_back"),
        provided_by=("digest_ledger",),
        evidence=True,
        recovery_hours=2.0,
        note="rewriting history requires rewriting the chain, which requires the key and the anchor",
    ),
    Guarantee(
        name="key_reconstruction",
        covers=("key_lost",),
        provided_by=("key_custody_separation",),
        evidence=False,
        recovery_hours=4.0,
        note="split escrow: any two of three holders can rebuild, and no single holder can open it alone",
    ),
    Guarantee(
        name="key_rotation_containment",
        covers=("key_stolen",),
        provided_by=("rotation_cadence",),
        evidence=False,
        recovery_hours=8.0,
        note="a stolen key is dated: the loss is bounded by the rotation window, not by the asset's lifetime",
    ),
    Guarantee(
        name="attested_rebuild",
        covers=("host_rebuilt",),
        provided_by=("boot_attestation",),
        evidence=False,
        recovery_hours=6.0,
        note="a rebuilt host can prove what it is, which is the difference between recovery and hope",
    ),
    Guarantee(
        name="restore_drill",
        covers=("host_rebuilt", "storage_corrupted", "file_deleted"),
        provided_by=("adversarial_drills",),
        evidence=False,
        recovery_hours=12.0,
        note="an unrestored backup is a hypothesis; this is the control that turns it into a recovery option",
    ),
)


def coverage(plan: Plan) -> Dict[str, dict]:
    """For each failure class: what you would get back, and what you would not."""
    present = {control.name for control in plan.controls}
    result: Dict[str, dict] = {}
    for failure in FAILURE_CLASSES:
        available = [
            guarantee
            for guarantee in GUARANTEES
            if failure in guarantee.covers and present.intersection(guarantee.provided_by)
        ]
        result[failure] = {
            "covered": bool(available),
            "guarantees": [guarantee.name for guarantee in available],
            "evidence_kept": any(guarantee.evidence for guarantee in available),
            "best_recovery_hours": min((guarantee.recovery_hours for guarantee in available), default=None),
            "note": (
                "no guarantee in the plan covers this: the failure is survivable only by luck"
                if not available
                else "; ".join(guarantee.note for guarantee in available[:1])
            ),
        }
    return result


def gaps(plan: Plan) -> List[dict]:
    """Failure classes with no guarantee, and the cheapest control that would cover each."""
    covered = coverage(plan)
    out: List[dict] = []
    for failure, state in covered.items():
        if state["covered"]:
            continue
        options = [
            guarantee for guarantee in GUARANTEES if failure in guarantee.covers
        ]
        cheapest = sorted(options, key=lambda guarantee: len(guarantee.provided_by))[0] if options else None
        out.append(
            {
                "failure": failure,
                "would_need": list(cheapest.provided_by) if cheapest else [],
                "evidence": cheapest.evidence if cheapest else False,
            }
        )
    return out


def drill_gap(plan: Plan) -> Optional[dict]:
    """The most common way this budget is wasted: coverage on paper, never rehearsed."""
    present = {control.name for control in plan.controls}
    if "adversarial_drills" in present:
        return None
    return {
        "code": "recovery_unrehearsed",
        "detail": "no drill in the plan: restoration and evidence verification are untested procedures, so their "
        "stated recovery times are assumptions rather than measurements",
        "suggest": "one restore of the archive and one verification of the digest chain from the off-host anchor, "
        "quarterly, timed and recorded",
    }


def recovery_plan(plan: Plan, failure: str) -> List[str]:
    """The steps, in order, for one failure class. Written to be pasted into a runbook."""
    present = {control.name for control in plan.controls}
    steps = ["preserve the current state before touching anything: evidence is the first casualty of a fix"]
    for guarantee in GUARANTEES:
        if failure not in guarantee.covers:
            continue
        if not present.intersection(guarantee.provided_by):
            continue
        steps.append(f"{guarantee.name}: {guarantee.note} (about {guarantee.recovery_hours:g}h)")
    if len(steps) == 1:
        steps.append(
            f"nothing in this plan covers {failure}: the honest recovery is a rebuild, and the evidence of what "
            "happened is whatever survived the host"
        )
    return steps
