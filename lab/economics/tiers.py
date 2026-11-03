"""The tier ladder: what an asset's value obliges you to run, and what it obliges you to skip.

Proportionality is only meaningful if it has steps. A single "best practice" baseline applied
to everything is how a hobby project ends up maintaining measured boot, and how a regulated
system ends up with a README's worth of hashing. So the ladder is explicit, the requirements
are per rung, and the fingerprint depth rises with the rung because the attacker's incentive
rises with the value.

| Tier | Name | Asset value (annualized) | Obligations |
| --- | --- | --- | --- |
| 0 | public | under 5k | integrity hashing, baseline logging |
| 1 | operational | 5k to 50k | plus a tamper-evident digest ledger |
| 2 | sensitive | 50k to 500k | plus authenticated encryption, off-host anchor |
| 3 | regulated | 500k to 5M | plus key custody separation, source seal, rotation |
| 4 | targeted | above 5M | plus measured boot, replay guards, drills, deep profiling |

Two rules make the ladder work rather than decorate:

- **Requirements are floors, not shopping lists.** A tier 1 asset running tier 3 controls is
  not "extra safe"; it is spending the asset's value on protection bounded by the same value.
  The model flags that as overinvestment, and the flag is not softened because the controls are
  good ones.
- **The ladder moves.** Value changes, and so does the attacker's incentive to spend on you.
  `promotion_hint` watches for the specific signal: an attempt that still pays for the attacker
  at the current tier. That is the moment the next rung is justified by evidence rather than by
  a spreadsheet.

The costs below are planning figures for a small team: an order of magnitude, not a quote. They
exist so the ratio can be computed at all, and `lab/DEFENSE-ECONOMICS.md` says plainly that the
inputs are the weak part while the arithmetic is the checked part.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence, Tuple

from lab.economics.model import Asset, Control, Plan, Threat

# --- the control catalogue -------------------------------------------------------------
# Costs are annual, in currency units, for a small team maintaining the control.

CONTROLS: Dict[str, Control] = {
    "baseline_hashing": Control(
        name="baseline_hashing",
        annual_cost=300,
        covers=("opportunistic_scan", "ciphertext_substitution"),
        reduction=0.10,
        setup_effect=1.1,
        note="SHA-256 over stored artifacts; the cheapest way to make silent edits visible",
    ),
    "digest_ledger": Control(
        name="digest_ledger",
        annual_cost=600,
        covers=("ciphertext_substitution", "plaintext_manipulation", "ledger_rollback"),
        reduction=0.35,
        setup_effect=1.4,
        maintenance_effect=2.5,
        note="HMAC chain over digests: an attacker must keep it consistent, not just edit files",
    ),
    "digest_anchor_offhost": Control(
        name="digest_anchor_offhost",
        annual_cost=1_500,
        covers=("ledger_rollback",),
        reduction=0.60,
        setup_effect=1.8,
        maintenance_effect=3.0,
        note="the one control that makes rollback cost recurring effort instead of a one-time edit",
    ),
    "aes_gcm_envelope": Control(
        name="aes_gcm_envelope",
        annual_cost=400,
        covers=("ciphertext_substitution", "credential_theft"),
        reduction=0.55,
        setup_effect=2.0,
        maintenance_effect=4.0,
        note="authenticated encryption: a lost key stops being a quiet edit and becomes a broken tag",
    ),
    "key_custody_separation": Control(
        name="key_custody_separation",
        annual_cost=2_500,
        covers=("key_compromise", "ciphertext_substitution"),
        reduction=0.45,
        setup_effect=1.6,
        maintenance_effect=1.5,
        note="purpose-separated subkeys: a stolen transport key cannot forge source seals",
    ),
    "source_seal": Control(
        name="source_seal",
        annual_cost=1_200,
        covers=("plaintext_manipulation",),
        reduction=0.50,
        setup_effect=1.5,
        maintenance_effect=6.0,
        note="sealing at capture: an endpoint implant must defeat the seal on every write, forever",
    ),
    "rotation_cadence": Control(
        name="rotation_cadence",
        annual_cost=900,
        covers=("key_compromise",),
        reduction=0.30,
        setup_effect=1.2,
        maintenance_effect=5.0,
        note="rotation turns a permanent key theft into a dated one, which is a maintenance tax",
    ),
    "replay_guard": Control(
        name="replay_guard",
        annual_cost=500,
        covers=("plaintext_manipulation", "ciphertext_substitution"),
        reduction=0.20,
        setup_effect=1.2,
        maintenance_effect=2.0,
        note="monotone sequence per stream; makes deletion and re-offer visible",
    ),
    "boot_attestation": Control(
        name="boot_attestation",
        annual_cost=18_000,
        covers=("firmware_implant",),
        reduction=0.65,
        setup_effect=3.0,
        maintenance_effect=8.0,
        note="measured boot with policy: an implant must survive attestation at every boot",
    ),
    "adversarial_drills": Control(
        name="adversarial_drills",
        annual_cost=12_000,
        covers=("firmware_implant", "plaintext_manipulation", "credential_theft"),
        reduction=0.15,
        setup_effect=1.3,
        maintenance_effect=1.2,
        note="you find your own gaps first; the cheap version of this is a test suite that attacks you",
    ),
    "fingerprint_depth_high": Control(
        name="fingerprint_depth_high",
        annual_cost=6_000,
        covers=("firmware_implant",),
        reduction=0.05,
        setup_effect=1.1,
        maintenance_effect=1.4,
        note="profiling per incident: it does not stop this attack, it raises the cost of the next one",
    ),
}


# --- the ladder ------------------------------------------------------------------------

@dataclass(frozen=True)
class TierSpec:
    tier: int
    name: str
    upper_value: float  # exclusive upper bound; the top tier is open-ended
    required: Tuple[str, ...]
    fingerprint_depth: int
    spend_ceiling: float  # fraction of asset value

    def admits(self, value: float) -> bool:
        lower = 0.0 if self.tier == 0 else TIERS[self.tier - 1].upper_value
        return lower <= value < self.upper_value


TIERS: Tuple[TierSpec, ...] = (
    TierSpec(0, "public", 5_000, ("baseline_hashing",), 1, 0.30),
    TierSpec(1, "operational", 50_000, ("baseline_hashing", "digest_ledger"), 2, 0.25),
    TierSpec(
        2,
        "sensitive",
        500_000,
        ("baseline_hashing", "digest_ledger", "digest_anchor_offhost", "aes_gcm_envelope"),
        2,
        0.20,
    ),
    TierSpec(
        3,
        "regulated",
        5_000_000,
        (
            "baseline_hashing",
            "digest_ledger",
            "digest_anchor_offhost",
            "aes_gcm_envelope",
            "key_custody_separation",
            "source_seal",
            "rotation_cadence",
        ),
        3,
        0.15,
    ),
    TierSpec(
        4,
        "targeted",
        float("inf"),
        (
            "baseline_hashing",
            "digest_ledger",
            "digest_anchor_offhost",
            "aes_gcm_envelope",
            "key_custody_separation",
            "source_seal",
            "rotation_cadence",
            "replay_guard",
            "boot_attestation",
            "adversarial_drills",
            "fingerprint_depth_high",
        ),
        4,
        0.10,
    ),
)


def tier_for(value: float) -> TierSpec:
    for spec in TIERS:
        if spec.admits(value):
            return spec
    return TIERS[-1]


def spec(tier: int) -> TierSpec:
    for item in TIERS:
        if item.tier == tier:
            return item
    raise ValueError(f"no tier {tier}; the ladder is 0 to {len(TIERS) - 1}")


def required(tier: int) -> Tuple[str, ...]:
    return spec(tier).required


def plan_for(asset: Asset, extra: Sequence[str] = ()) -> Plan:
    """The plan the ladder obliges you to run, plus anything explicitly added.

    Building this from the tier rather than from a wish list is the whole point: the floor is
    a floor, and extras have to justify themselves against the ratio like everything else.
    """
    names: List[str] = list(spec(asset.tier).required)
    for name in extra:
        if name not in CONTROLS:
            raise KeyError(f"unknown control {name!r}")
        if name not in names:
            names.append(name)
    return Plan(
        asset=asset,
        controls=[CONTROLS[name] for name in names],
        ceiling_ratio=spec(asset.tier).spend_ceiling,
    )


# --- the threat book -------------------------------------------------------------------
# Deliberately conservative: impact fractions near the value of the asset, and setup costs
# that assume a competent, motivated attacker rather than a script.

DEFAULT_THREATS: Tuple[Threat, ...] = (
    Threat("opportunistic_scan", setup_cost=50, monthly_maintenance=0, likelihood=0.60, impact_fraction=0.005, loot_cap=200),
    Threat("credential_theft", setup_cost=500, monthly_maintenance=20, likelihood=0.25, impact_fraction=0.35, loot_cap=6_000),
    Threat("ciphertext_substitution", setup_cost=2_000, monthly_maintenance=60, likelihood=0.08, impact_fraction=0.60),
    Threat(
        "plaintext_manipulation",
        setup_cost=1_500,
        monthly_maintenance=150,
        likelihood=0.10,
        impact_fraction=0.45,
        loot_cap=40_000,
    ),
    Threat("ledger_rollback", setup_cost=9_000, monthly_maintenance=200, likelihood=0.05, impact_fraction=0.70),
    Threat("key_compromise", setup_cost=4_000, monthly_maintenance=250, likelihood=0.06, impact_fraction=0.80),
    Threat("firmware_implant", setup_cost=60_000, monthly_maintenance=2_500, likelihood=0.01, impact_fraction=0.90),
)


def threats_as_dict(threats: Sequence[Threat] = DEFAULT_THREATS) -> Dict[str, Threat]:
    return {threat.name: threat for threat in threats}


# --- the movement ----------------------------------------------------------------------

def promotion_hint(plan: Plan, threats: Sequence[Threat] = DEFAULT_THREATS) -> Optional[dict]:
    """Is the next rung justified by evidence rather than by a spreadsheet?

    The signal is not "the asset is expensive". It is "an attempt still pays for the attacker
    at this tier", which is the observable form of "they are getting more out of this than it
    costs them". That is the point at which the ladder should move.
    """
    spec_now = spec(plan.asset.tier)
    if spec_now.tier == len(TIERS) - 1:
        return None
    profitable = [
        threat.name
        for threat in threats
        if plan.attacker_return(threat) > 0 and threat.impact_fraction * plan.asset.value >= 0.01 * plan.asset.value
    ]
    if not profitable:
        return None
    nxt = spec(spec_now.tier + 1)
    new_controls = [name for name in nxt.required if name not in {control.name for control in plan.controls}]
    added_cost = sum(CONTROLS[name].annual_cost for name in new_controls)
    return {
        "from_tier": spec_now.tier,
        "to_tier": nxt.tier,
        "to_name": nxt.name,
        "why": f"{', '.join(profitable)} still returns a profit at tier {spec_now.tier}",
        "controls_to_add": new_controls,
        "added_annual_cost": added_cost,
        "new_spend_ratio": (plan.annual_control_cost + added_cost) / plan.asset.value,
        "fingerprint_depth_change": (spec_now.fingerprint_depth, nxt.fingerprint_depth),
    }
