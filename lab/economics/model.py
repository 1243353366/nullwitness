"""Defense economics: what a control costs, what it buys, and when the answer is "nothing".

Three of the four principles in `lab/DEFENSE-ECONOMICS.md` are arithmetic, and arithmetic is
worth writing down because the intuitions people substitute for it are reliably wrong in one
direction: controls feel cheap and losses feel unlikely, so spend drifts to whatever the
last incident justified and then stays there.

**Economic asymmetry** is one equation per threat:

    attacker_return = p_success * loot - setup_cost - maintenance_cost * months

Attackers are businesses. A negative return is deterrence; it is not detection, and it is not
permanent. The interesting lever is the third term, and it is the one defenders ignore: raising
setup cost buys you a one-time tax, while raising maintenance cost means an attacker has to keep
paying for access they already have. A control that forces re-earning access every month is
worth more than one that makes the first break-in twice as hard, for the same money.

**Proportionality** is a ratio, and it gets violated in both directions:

    benefit(control) = expected_loss_without - expected_loss_with   vs   annual_cost(control)

A control whose benefit is below its cost is a net loss even when it works perfectly. One whose
cost exceeds the asset's value is a category error. The uncomfortable part is that a cheap asset
with expensive controls is not "extra safe", it is a worse position than doing less, because the
spend is real and the protection is bounded by the same asset value.

**Resilience** is a different axis from prevention: what survives, and how fast you get back.
A control that stops an attack and a control that makes an attack survivable have separate
budgets, and an organization with only the first is one novel technique from having neither.

**Adaptation** is the loop: every finding that arrived becomes a policy change that costs the
attacker more next time. If findings accumulate and the plan does not change, that is not
adaptation, it is logging.

## What the numbers are

They are estimates, and the code says so where it matters. `likelihood` and `impact_fraction`
are planning guesses; the model takes them as inputs rather than inventing them so that an
operator can disagree with a number instead of with a conclusion. The arithmetic between the
inputs and the verdict is exact and tested. Decimal places on a guess are false precision, so
`report` rounds money to the nearest hundred.

One assumption worth stating in the code rather than a footnote: control reductions are
multiplied independently, so two controls that each remove 50% of one threat leave 25%. Real
controls overlap, and overlapping controls are exactly where budgets go to die. If two controls
claim the same threat, the model reports the redundancy instead of quietly multiplying it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}


@dataclass(frozen=True)
class Asset:
    """What is being defended, in the only unit that matters for proportionality."""

    name: str
    value: float  # annualized loss if fully compromised, in currency units
    tier: int  # 0..4, see tiers.py
    notes: str = ""


@dataclass(frozen=True)
class Threat:
    """A way the asset is lost, priced from the attacker's side first.

    `setup_cost` and `monthly_maintenance` are what the attacker pays, not what you pay.
    They are order-of-magnitude planning figures: an implant that survives monitoring costs
    more per month than a phishing kit, and a technique the defender has never seen costs more
    to build than one they have published.
    """

    name: str
    setup_cost: float
    monthly_maintenance: float
    likelihood: float  # annual probability of an attempt, absent controls
    impact_fraction: float  # fraction of asset.value lost if it succeeds
    loot_cap: float = float("inf")  # absolute ceiling on what an attacker can realise

    def loot(self, asset_value: float) -> float:
        """What the attacker actually gets, which is not what the defender loses.

        An opportunistic scan against a quarter-million-dollar asset does not net the scanner
        a fraction of the asset; it nets a credential worth a few hundred. Pricing their gain as
        a slice of your value makes every trivial threat look like a profitable operation and
        every report read like a crisis, so the two quantities are kept separate: `impact`
        drives the defender's expected loss, `loot` drives the attacker's return.
        """
        return min(self.impact_fraction * asset_value, self.loot_cap)


@dataclass(frozen=True)
class Control:
    """A defense with a price, coverage, and an effect on the attacker's cost structure.

    `reduction` is the fraction of a covered threat's expected loss it removes. `setup_effect`
    and `maintenance_effect` multiply the attacker's costs: 1.0 leaves them alone, 2.0 doubles
    them. Maintenance effects are the ones to look for first, because they recur.
    """

    name: str
    annual_cost: float
    covers: Tuple[str, ...]
    reduction: float = 0.0
    setup_effect: float = 1.0
    maintenance_effect: float = 1.0
    note: str = ""

    def __post_init__(self) -> None:
        if not 0.0 <= self.reduction <= 1.0:
            raise ValueError(f"{self.name}: reduction must be a fraction between 0 and 1")
        if self.setup_effect < 1.0 or self.maintenance_effect < 1.0:
            raise ValueError(f"{self.name}: a control cannot make an attack cheaper")


@dataclass(frozen=True)
class Verdict:
    code: str
    severity: str
    detail: str


@dataclass
class Plan:
    """A control set for one asset, with the arithmetic that judges it."""

    asset: Asset
    controls: List[Control] = field(default_factory=list)
    horizon_months: int = 12
    ceiling_ratio: float = 0.20  # spend ceiling as a fraction of asset value

    # --- costs -----------------------------------------------------------------------
    @property
    def annual_control_cost(self) -> float:
        return sum(control.annual_cost for control in self.controls)

    @property
    def spend_ratio(self) -> float:
        if self.asset.value <= 0:
            raise ValueError("an asset with no value cannot have a spend ratio")
        return self.annual_control_cost / self.asset.value

    def coverage_for(self, threat_name: str) -> List[Control]:
        return [control for control in self.controls if threat_name in control.covers]

    def success_probability(self, threat: Threat) -> float:
        """Attempt likelihood reduced by every control that covers it.

        Independent multiplication, which is optimistic: real controls overlap, and this
        model reports redundancy separately rather than pretending to model dependence.
        """
        probability = threat.likelihood
        for control in self.coverage_for(threat.name):
            probability *= 1.0 - control.reduction
        return max(0.0, min(1.0, probability))

    def attacker_setup(self, threat: Threat) -> float:
        cost = threat.setup_cost
        for control in self.coverage_for(threat.name):
            cost *= control.setup_effect
        return cost

    def attacker_maintenance(self, threat: Threat) -> float:
        cost = threat.monthly_maintenance
        for control in self.coverage_for(threat.name):
            cost *= control.maintenance_effect
        return cost

    # --- loss ------------------------------------------------------------------------
    def expected_loss(self, threats: Sequence[Threat]) -> float:
        total = 0.0
        for threat in threats:
            total += self.success_probability(threat) * threat.impact_fraction * self.asset.value
        return total

    def residual_by_threat(self, threats: Sequence[Threat]) -> Dict[str, float]:
        return {
            threat.name: self.success_probability(threat) * threat.impact_fraction * self.asset.value
            for threat in threats
        }

    def expected_loss_without(self, control: Control, threats: Sequence[Threat]) -> float:
        """The counterfactual: what the loss would be if this control were removed."""
        reduced = Plan(
            asset=self.asset,
            controls=[item for item in self.controls if item.name != control.name],
            horizon_months=self.horizon_months,
            ceiling_ratio=self.ceiling_ratio,
        )
        return reduced.expected_loss(threats)

    def benefit(self, control: Control, threats: Sequence[Threat]) -> float:
        return self.expected_loss_without(control, threats) - self.expected_loss(threats)

    def roi(self, control: Control, threats: Sequence[Threat]) -> float:
        """Benefit per unit of annual cost. Below 1.0 means the control loses money."""
        if control.annual_cost <= 0:
            return float("inf")
        return self.benefit(control, threats) / control.annual_cost

    # --- attacker -------------------------------------------------------------------
    def attacker_return(self, threat: Threat, months: Optional[int] = None) -> float:
        """Their expected value, in the same currency, over the horizon."""
        months = self.horizon_months if months is None else months
        loot = self.success_probability(threat) * threat.loot(self.asset.value)
        return loot - self.attacker_setup(threat) - self.attacker_maintenance(threat) * months

    def breakeven_months(self, threat: Threat) -> Optional[float]:
        """How long an attacker must hold access before the attempt pays.

        `None` means never: with this control set the attempt cannot pay at any horizon, which
        is the strongest thing a defender can say about a threat.
        """
        loot = self.success_probability(threat) * threat.loot(self.asset.value)
        maintenance = self.attacker_maintenance(threat)
        setup = self.attacker_setup(threat)
        if loot <= setup:
            return None
        if maintenance <= 0:
            return 0.0
        return (loot - setup) / maintenance

    # --- judgement ------------------------------------------------------------------
    def evaluate(self, threats: Sequence[Threat], required: Iterable[str] = ()) -> List[Verdict]:
        verdicts: List[Verdict] = []
        present = {control.name for control in self.controls}

        for name in required:
            if name not in present:
                verdicts.append(
                    Verdict(
                        "control_missing",
                        "high",
                        f"{name} is required at tier {self.asset.tier} and is not in the plan: the tier's "
                        "expected loss is not covered by the spend",
                    )
                )

        for control in self.controls:
            if control.annual_cost > self.asset.value:
                verdicts.append(
                    Verdict(
                        "control_exceeds_asset",
                        "high",
                        f"{control.name} costs {control.annual_cost:.0f} to protect an asset worth "
                        f"{self.asset.value:.0f}: this is not caution, it is a worse position than doing less",
                    )
                )
                continue
            ratio = self.roi(control, threats)
            if ratio < 1.0:
                verdicts.append(
                    Verdict(
                        "control_overinvestment",
                        "medium",
                        f"{control.name} returns {ratio:.2f}x its cost in reduced expected loss "
                        f"({self.benefit(control, threats):.0f} benefit for {control.annual_cost:.0f} annual cost): "
                        "it may still be justified by a threat this model does not price, but it is not justified "
                        "by the ones it does",
                    )
                )

        if self.spend_ratio > self.ceiling_ratio:
            verdicts.append(
                Verdict(
                    "spend_ceiling_exceeded",
                    "medium",
                    f"annual spend is {self.spend_ratio:.0%} of asset value, above the {self.ceiling_ratio:.0%} "
                    "ceiling for this tier: the marginal control should be judged against the next tier's "
                    "requirements, not added to this one",
                )
            )

        for threat in threats:
            overlapping = self.coverage_for(threat.name)
            if len(overlapping) >= 3:
                verdicts.append(
                    Verdict(
                        "control_redundancy",
                        "low",
                        f"{threat.name} is covered by {', '.join(c.name for c in overlapping)}: the model multiplies "
                        "their reductions independently, which overstates the result, and the overlap is where the "
                        "next budget cut should come from",
                    )
                )
            if (
                self.attacker_return(threat) > 0
                and threat.impact_fraction * self.asset.value >= 0.01 * self.asset.value
            ):
                verdicts.append(
                    Verdict(
                        "attacker_profitable",
                        "medium",
                        f"{threat.name} still pays for the attacker over {self.horizon_months} months "
                        f"({self.attacker_return(threat):.0f} expected return): the plan does not make this "
                        "attempt economically irrational",
                    )
                )
        return verdicts

    def summary(self, threats: Sequence[Threat]) -> Dict[str, object]:
        return {
            "asset": {"name": self.asset.name, "value": round(self.asset.value, 2), "tier": self.asset.tier},
            "annual_control_cost": round(self.annual_control_cost, 2),
            "spend_ratio": round(self.spend_ratio, 4),
            "expected_loss": round(self.expected_loss(threats), 2),
            "residual_by_threat": {name: round(value, 2) for name, value in self.residual_by_threat(threats).items()},
            "controls": [
                {
                    "name": control.name,
                    "annual_cost": control.annual_cost,
                    "benefit": round(self.benefit(control, threats), 2),
                    "roi": None if self.roi(control, threats) == float("inf") else round(self.roi(control, threats), 2),
                    "maintenance_effect": control.maintenance_effect,
                }
                for control in self.controls
            ],
            "attacker": {
                threat.name: {
                    "return": round(self.attacker_return(threat), 2),
                    "setup": round(self.attacker_setup(threat), 2),
                    "monthly": round(self.attacker_maintenance(threat), 2),
                    "breakeven_months": (
                        None if self.breakeven_months(threat) is None else round(self.breakeven_months(threat), 1)
                    ),
                }
                for threat in threats
            },
        }
