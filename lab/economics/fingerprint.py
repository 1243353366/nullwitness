"""Profiling the attacker in proportion to what they are getting out of you.

The instruction is "fingerprint them more as it gets more valuable for them", and the operative
word is *them*. A tier 1 asset can afford to know what technique hit it. A tier 4 asset can
afford to know how that operator works: what they reach for first, how patient they are, how
careful they are about the checks this repository makes, and whether the last incident and this
one look like the same hand.

Four depth levels, and each one is a real capability with a real cost:

| Depth | What it adds | What it costs |
| --- | --- | --- |
| 0 | nothing: you know something happened | nothing, and you learn nothing |
| 1 | technique codes and timestamps | parsing what you already record |
| 2 | sequence across channels, which boundary caught it, what was evaded | correlation, and retention long enough to correlate |
| 3 | cadence, dwell, precision signature, tooling era | attention per incident, plus a baseline to compare against |
| 4 | repertoire across incidents, infrastructure notes, confidence-weighted linkage | an analyst habit, and the discipline to record confidence |

The honest part, and the reason this module returns confidence and never a name: attribution is
probabilistic. It produces a profile, not a person, and a profile with a stated confidence is
useful while a profile with an implied certainty is a liability. The specific failure to avoid
is the one that ends in an accusation, so `build_profile` refuses to emit an identity field at
all: there is no field to fill in later.

The second honest part: depth 3 and 4 need a baseline to be meaningful. "Careful" is only a
signal against a distribution, and the distribution comes from having watched for a while. A
tier 4 asset that turns on deep profiling after the first incident has a sample size of one.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from lab.economics.tiers import spec

DEPTH_NAMES = {
    0: "none",
    1: "technique",
    2: "sequence",
    3: "cadence",
    4: "repertoire",
}

DEPTH_CAPABILITY = {
    0: "that something happened",
    1: "which technique fired and when",
    2: "the order across channels, which boundary caught it, and what was avoided",
    3: "how patient and how careful: cadence, dwell, precision signature",
    4: "a repertoire across incidents, with confidence-weighted linkage",
}

DEPTH_COST = {
    0: 0,
    1: 0,  # already recorded by every control in this repository
    2: 900,
    3: 4_000,
    4: 6_000,
}

# Findings that reveal technique rather than merely failure. The mapping is to the attacker's
# action, which is what a profile is made of.
TECHNIQUE_NAMES = {
    "ciphertext_tampered": "ciphertext_edit",
    "plaintext_tampered": "plaintext_edit",
    "envelope_substituted": "envelope_swap",
    "envelope_missing": "archive_deletion",
    "envelope_unrecorded": "backdated_insert",
    "record_removed": "record_deletion",
    "record_reordered": "record_reorder",
    "record_replayed": "replay",
    "seal_forged": "seal_forgery",
    "stream_head_mismatch": "tail_truncation",
    "boot_measurement_mismatch": "code_modification",
    "boot_chain_broken": "chain_splicing",
    "boot_rollback": "firmware_downgrade",
    "key_permissions_loose": "key_exposure",
    "key_colocated_with_data": "key_exposure",
    "key_in_environment": "key_exposure",
    "ledger_rollback": "ledger_rollback",
    "digest_ledger_tampered": "ledger_edit",
}

# Checks an attacker can choose to avoid. Avoiding them is the closest thing to a signature that
# exists here: it costs them effort, so it is a costly signal rather than a free accident.
EVADABLE_CHECKS = (
    "decoy_sweep_uniform",
    "clock_creep",
    "content_substitution",
    "restored_from_copy",
    "rotation_laundering",
    "key_material_copy",
)


@dataclass
class Incident:
    """One observed event, described the way the monitors actually report it."""

    codes: Tuple[str, ...]
    when: float  # epoch seconds
    boundary: str = ""  # which check saw it: wire, sink, source, boot, archive
    evaded: Tuple[str, ...] = ()  # checks it was in a position to trip and did not
    note: str = ""


@dataclass
class Profile:
    depth: int
    techniques: List[str] = field(default_factory=list)
    sequence: List[str] = field(default_factory=list)
    boundaries: List[str] = field(default_factory=list)
    evaded: List[str] = field(default_factory=list)
    cadence_hours: Optional[List[float]] = None
    precision: Optional[str] = None
    linkage: Optional[str] = None
    confidence: str = "low"
    refused: List[str] = field(default_factory=list)

    def as_dict(self) -> Dict[str, object]:
        return {
            "depth": self.depth,
            "depth_name": DEPTH_NAMES[self.depth],
            "techniques": self.techniques,
            "sequence": self.sequence,
            "boundaries": self.boundaries,
            "evaded": self.evaded,
            "cadence_hours": self.cadence_hours,
            "precision": self.precision,
            "linkage": self.linkage,
            "confidence": self.confidence,
            "refused": self.refused,
        }


def depth_for(tier: int) -> int:
    """Depth is a function of what they stand to gain, which is a function of the tier."""
    return spec(tier).fingerprint_depth


def _precision(evaded: Sequence[str]) -> str:
    """How many evadable checks were dodged, out of how many existed.

    Deliberately coarse. A three-way label is honest about what one incident can support; a
    percentage would imply a sample size that does not exist.
    """
    if not evaded:
        return "careless"
    ratio = len(set(evaded)) / len(EVADABLE_CHECKS)
    if ratio >= 0.8:
        return "tailored"
    if ratio >= 0.3:
        return "selective"
    return "careless"


def build_profile(incidents: Sequence[Incident], depth: int) -> Profile:
    """Extract what the requested depth can support, and name what it cannot.

    Nothing here produces an identity, and the function will not add a field for one. What it
    produces is behaviour: technique, order, cadence, precision, and (at depth 4) whether two
    incidents look like one operator. That is enough to make the next attempt more expensive and
    nowhere near enough to accuse anyone, which is the correct ratio.
    """
    ordered = sorted(incidents, key=lambda incident: incident.when)
    profile = Profile(depth=depth)

    if depth >= 1:
        for incident in ordered:
            for code in incident.codes:
                technique = TECHNIQUE_NAMES.get(code, code)
                if technique not in profile.techniques:
                    profile.techniques.append(technique)
                profile.sequence.append(technique)

    if depth >= 2:
        profile.boundaries = sorted({incident.boundary for incident in ordered if incident.boundary})
        profile.evaded = sorted({check for incident in ordered for check in incident.evaded})

    if depth >= 3:
        if len(ordered) >= 3:
            profile.cadence_hours = [
                round((following.when - previous.when) / 3600.0, 2)
                for previous, following in zip(ordered, ordered[1:])
            ]
            profile.confidence = "medium"
        else:
            profile.refused.append(
                "cadence needs three or more incidents; with fewer, an interval is an anecdote"
            )
        profile.precision = _precision(profile.evaded)

    if depth >= 4:
        if len(profile.techniques) >= 3 and len(ordered) >= 3:
            profile.linkage = (
                "consistent repertoire across incidents: "
                + ", ".join(profile.techniques[:4])
                + (" and others" if len(profile.techniques) > 4 else "")
            )
            profile.confidence = "medium"
        else:
            profile.refused.append(
                "cross-incident linkage needs at least three incidents and three techniques; "
                "below that the honest answer is 'unknown operator'"
            )

    if depth == 0 and incidents:
        profile.refused.append("depth 0 collects nothing: an incident that is not characterised cannot be compared")
    return profile


def depth_gap(tier: int, current_depth: int) -> Optional[dict]:
    """What the tier's depth would add, and what it costs to get there."""
    wanted = depth_for(tier)
    if current_depth >= wanted:
        return None
    added_cost = sum(DEPTH_COST[level] for level in range(current_depth + 1, wanted + 1))
    return {
        "from": current_depth,
        "to": wanted,
        "adds": DEPTH_CAPABILITY[wanted],
        "annual_cost": added_cost,
        "note": "depth without a baseline is decoration; the cost includes retention and attention, not just parsing",
    }
