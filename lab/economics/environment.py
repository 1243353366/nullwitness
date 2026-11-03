"""Incentive design: change the conditions, not the decision.

You cannot make someone not attack you. You can change what attacking costs, what it pays,
how long the payoff stays worth having, and how much of it you can see. The decision stays
theirs; the environment it is made in is yours to design. That is the whole of this module, and
it is worth separating from prevention because the failure modes are different: prevention
fails loudly when it is breached, and incentive design fails quietly, by not moving anything.

Four things the model refuses to claim.

**That they will not attack.** It reports a return and a decision margin, never a promise. The
output is "the attempt returns −12,400 against a next-best alternative of +3,000", not "we are
safe". A decision is a fact about their reasoning under conditions you set, and conditions
change.

**That deterrence is absolute.** It is relative. `opportunity_return` is what the same effort
earns elsewhere, and an attempt that returns +2,000 is deterred when the alternative returns
+5,000 and attractive when it returns +500. Rising above the alternative is the goal, which is
why `substitution` exists: making yourself a worse target than the peers is a real strategy with
a real cost to somebody else, and the module says so rather than calling it a win.

**That punishment from outside is available to you.** No lever here retaliates, names, or
pursues. Those are other organizations' tools under other authorities; in this repository they
are out of scope.

**That influencing people is the same as influencing an adversary.** It is not, and the
distinction is not rhetorical. Applied to an adversary, this is deterrence: shaping the payoff
of an action they are choosing to take against you. Applied to your own users, staff, or a third
party, the same machinery is manipulation, and "you don't control the decision, you influence the
conditions" describes a nudge, a dark pattern, and a coercive workplace equally well.
`permissible` is the gate, and it refuses the second category rather than leaving the choice to
whoever is holding the keyboard.

## The levers

Each one moves one of the attacker's terms. Diminishing returns apply within a mechanism, because
two ways of raising their cost do not add up the way the arithmetic would like.

| Lever | Mechanism | Effect | Why it works |
| --- | --- | --- | --- |
| `data_minimisation` | loot | ×0.4 loot | the strongest lever: if the payoff is not there to take, no cost model changes their mind, and nothing needs detecting |
| `rotation_window` | latency | ×0.6 loot, ×2.0 upkeep | value that expires lowers the payoff without touching the defense |
| `sealed_capture` | visibility | ×2.0 upkeep | a tampered record that proves it was tampered turns every quiet edit into a loud one |
| `offhost_anchor` | visibility | ×2.5 upkeep | they cannot un-see a comparison they cannot reach |
| `decoy_fields` | visibility | ×1.6 upkeep | doubt about whether the thing they found is the real thing is a recurring tax |
| `baseline_hardening` | cost | ×1.8 setup | the ordinary one: raise the price of the first foothold |
| `precision_profiling` | consequence | ×1.3 setup, ×1.3 upkeep | only bites when it is credible, which is why it is gated on maturity |

The honest read of that table is that the top three change *what is worth taking*, and the bottom
three change *what it costs to take it*. A design that only does the bottom three is a design that
competes on price with every other target. The ones that change the payoff are the ones that make
the arithmetic unattractive no matter how cheap the attempt gets.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from itertools import combinations
from typing import Dict, List, Optional, Sequence, Tuple

from lab.economics.model import Asset, Threat, Verdict

# Who the lever is aimed at. Only the first is in scope.
SUBJECTS = ("adversary", "user", "third_party")

MECHANISMS = ("loot", "latency", "visibility", "cost", "consequence")

# Which constraint a lever actually presses on. See lab/CONSTRAINT-AXES.md: the mechanisms
# describe the arithmetic, the axes describe what the adversary is being denied.
AXES = ("capability", "legitimacy", "perception", "dependency")

# Within one mechanism, extra levers saturate: the second visibility lever is worth less than the
# first, because the first already made the same thing visible. The exponent below is how fast
# the marginal lever decays.
SATURATION = 0.55


@dataclass(frozen=True)
class Lever:
    """One change to the conditions under which the decision is made."""

    name: str
    mechanism: str
    axis: str = "capability"
    setup_mult: float = 1.0
    maintenance_mult: float = 1.0
    loot_mult: float = 1.0
    annual_cost: float = 0.0
    subject: str = "adversary"
    applies_to: Tuple[str, ...] = ()  # empty means every threat
    min_maturity: int = 0
    note: str = ""

    def __post_init__(self) -> None:
        if self.mechanism not in MECHANISMS:
            raise ValueError(f"{self.name}: unknown mechanism {self.mechanism!r}")
        if self.axis not in AXES:
            raise ValueError(f"{self.name}: unknown axis {self.axis!r}")
        if self.subject not in SUBJECTS:
            raise ValueError(f"{self.name}: unknown subject {self.subject!r}")
        if self.setup_mult < 1.0 or self.maintenance_mult < 1.0:
            raise ValueError(f"{self.name}: a lever cannot make an attempt cheaper")
        if not 0.0 < self.loot_mult <= 1.0:
            raise ValueError(f"{self.name}: loot_mult must be a fraction in (0, 1]")

    def applies(self, threat: Threat) -> bool:
        """A lever aimed at the wrong threat class is spend, not design."""
        return not self.applies_to or threat.name in self.applies_to


LEVERS: Dict[str, Lever] = {
    "data_minimisation": Lever(
        "data_minimisation",
        "loot",
        axis="capability",
        loot_mult=0.40,
        annual_cost=800,
        note="they cannot take what is not stored, which is the only leverage that survives a competent attacker",
    ),
    "rotation_window": Lever(
        "rotation_window",
        "latency",
        axis="dependency",
        loot_mult=0.60,
        maintenance_mult=2.0,
        annual_cost=900,
        note="value that expires costs them the same to take and pays for a shorter time",
    ),
    "sealed_capture": Lever(
        "sealed_capture",
        "visibility",
        axis="perception",
        maintenance_mult=2.0,
        annual_cost=1_200,
        note="a record that proves it was edited turns a quiet edit into a loud one",
    ),
    "offhost_anchor": Lever(
        "offhost_anchor",
        "visibility",
        axis="perception",
        maintenance_mult=2.5,
        annual_cost=1_500,
        note="keeping consistent with something they cannot reach is recurring work",
    ),
    "decoy_fields": Lever(
        "decoy_fields",
        "visibility",
        axis="perception",
        maintenance_mult=1.6,
        annual_cost=700,
        note="doubt is a tax: every field they cannot vouch for has to be checked twice",
    ),
    "baseline_hardening": Lever(
        "baseline_hardening",
        "cost",
        axis="capability",
        setup_mult=1.8,
        annual_cost=3_000,
        note="raises the price of the first foothold, once, which is the weakest of the six",
    ),
    "precision_profiling": Lever(
        "precision_profiling",
        "consequence",
        axis="perception",
        setup_mult=1.3,
        maintenance_mult=1.3,
        annual_cost=6_000,
        min_maturity=2,
        note="credible characterisation raises the expected cost of being remembered; incredible profiling raises nothing",
    ),
    "offline_restore": Lever(
        "offline_restore",
        "loot",
        axis="dependency",
        loot_mult=0.85,
        annual_cost=1_100,
        applies_to=("ciphertext_substitution", "ledger_rollback"),
        note="removes the dependency they were counting on: a hold over data you can restore is not a hold. It does not help against an edit you cannot detect, which is the whole reason the integrity layer comes first",
    ),
    "legitimacy_file": Lever(
        "legitimacy_file",
        "consequence",
        axis="legitimacy",
        setup_mult=1.0,
        maintenance_mult=1.05,
        annual_cost=400,
        note="the paperwork that lets someone else act: a documented, reported, standards-aligned incident is one a regulator or peer network can respond to",
    ),
    # Kept in the catalogue to demonstrate the gate, and refused by `permissible`.
    "nudge_users_to_accept_risk": Lever(
        "nudge_users_to_accept_risk",
        "loot",
        axis="dependency",
        loot_mult=1.0,
        annual_cost=0,
        subject="user",
        note="redesigns the interface so people click through what they would otherwise question",
    ),
    "pressure_insider_by_design": Lever(
        "pressure_insider_by_design",
        "consequence",
        axis="dependency",
        subject="user",
        note="shapes a colleague's environment so that reporting feels costlier than staying quiet",
    ),
}


@dataclass
class Environment:
    """A set of conditions, and what they do to a rational attempt."""

    asset: Asset
    levers: List[Lever] = field(default_factory=list)
    maturity: int = 1
    opportunity_return: float = 0.0  # what the same effort earns elsewhere

    @property
    def annual_cost(self) -> float:
        return sum(lever.annual_cost for lever in self.levers)

    def active(self, threat: Optional[Threat] = None) -> List[Lever]:
        return [lever for lever in self.levers if threat is None or lever.applies(threat)]

    def _saturated(self, mechanism: str, threat: Optional[Threat] = None) -> Tuple[float, float, float]:
        """Combine the levers in one mechanism, with the marginal one worth less."""
        selected = [lever for lever in self.active(threat) if lever.mechanism == mechanism]
        setup = maintenance = loot = 1.0

        def strength(lever: Lever) -> float:
            return (lever.setup_mult - 1.0) + (lever.maintenance_mult - 1.0) + (1.0 - lever.loot_mult)

        # Strongest lever first, so the decay lands on the weakest one. Ordering by cost instead
        # let a cheap lever push an expensive, stronger one into the decayed slot, which made
        # stacking worse than not stacking: the one behaviour this model must never produce.
        for index, lever in enumerate(sorted(selected, key=strength, reverse=True)):
            weight = (1.0 - SATURATION) ** index
            setup *= 1.0 + (lever.setup_mult - 1.0) * weight
            maintenance *= 1.0 + (lever.maintenance_mult - 1.0) * weight
            loot *= 1.0 - (1.0 - lever.loot_mult) * weight
        return setup, maintenance, loot

    def terms(self, threat: Optional[Threat] = None) -> Dict[str, float]:
        setup = maintenance = loot = 1.0
        for mechanism in MECHANISMS:
            part = self._saturated(mechanism, threat)
            setup *= part[0]
            maintenance *= part[1]
            loot *= part[2]
        return {"setup": round(setup, 4), "maintenance": round(maintenance, 4), "loot": round(loot, 4)}

    def attacker_return(self, threat: Threat, months: int = 12) -> float:
        terms = self.terms(threat)
        loot = threat.loot(self.asset.value) * terms["loot"]
        return loot - threat.setup_cost * terms["setup"] - threat.monthly_maintenance * terms["maintenance"] * months

    def decision(self, threat: Threat) -> dict:
        """What a rational actor does facing these conditions, relative to their alternative."""
        attack = self.attacker_return(threat)
        margin = attack - self.opportunity_return
        if margin <= -0.2 * max(abs(self.opportunity_return), 1.0):
            verdict = "deterred"
        elif margin < 0:
            verdict = "marginal"
        else:
            verdict = "attractive"
        return {
            "threat": threat.name,
            "return": round(attack, 2),
            "opportunity_return": round(self.opportunity_return, 2),
            "margin": round(margin, 2),
            "decision": verdict,
        }

    def evaluation(self, threats: Sequence[Threat]) -> List[dict]:
        return [self.decision(threat) for threat in threats]


def permissible(lever: Lever) -> Optional[Verdict]:
    """The gate. Shaping an adversary's payoff is defence; shaping a person's choice is not.

    The distinction is not about intent, it is about who bears the cost of the design. An
    adversary chose to be in the relationship and can leave it at any time by going elsewhere. A
    user, a colleague, or a third party did not choose to be the object of your design, and the
    same machinery that makes an attack unattractive makes dissent expensive. So the second use
    is refused here rather than treated as a matter of taste.
    """
    if lever.subject == "adversary":
        return None
    if lever.subject == "third_party":
        return Verdict(
            "lever_third_party_refused",
            "high",
            f"{lever.name} designs the conditions of someone who is not a party to your defense at all: out of scope, "
            "and outside most legal boundaries",
        )
    return Verdict(
        "lever_manipulation_refused",
        "high",
        f"{lever.name} shapes the choices of your own people rather than an adversary's payoff. That is manipulation with "
        "a security rationale, and the rationale does not change what it is. If the goal is fewer risky decisions, the "
        "version that survives review is transparency and a cheaper safe path, not a better-hidden nudge",
    )


def admit(environment: Environment, lever_names: Sequence[str]) -> Tuple[Environment, List[Verdict]]:
    """Add levers, refusing the impermissible ones and the ones the place is too young to hold."""
    verdicts: List[Verdict] = []
    accepted: List[Lever] = list(environment.levers)
    for name in lever_names:
        lever = LEVERS.get(name)
        if lever is None:
            raise KeyError(f"unknown lever {name!r}")
        refusal = permissible(lever)
        if refusal:
            verdicts.append(refusal)
            continue
        if environment.maturity < lever.min_maturity:
            verdicts.append(
                Verdict(
                    "lever_too_advanced",
                    "medium",
                    f"{lever.name} needs maturity {lever.min_maturity}; at {environment.maturity} the credible version of "
                    "this lever does not exist yet, and an incredible one teaches the adversary what to avoid",
                )
            )
            continue
        accepted = [existing for existing in accepted if existing.name != lever.name] + [lever]
    return replace(environment, levers=accepted), verdicts


def cheapest_flip(
    environment: Environment,
    threat: Threat,
    candidates: Sequence[str] = ("data_minimisation", "rotation_window", "sealed_capture", "decoy_fields", "baseline_hardening"),
    max_levers: int = 3,
) -> Optional[dict]:
    """The least expensive set of conditions that moves the decision past their alternative.

    Not "the best defense": the cheapest change that makes this attempt the worse use of their
    time. Anything beyond that is spending on a decision that has already moved.
    """
    pool = [LEVERS[name] for name in candidates if name in LEVERS and LEVERS[name].min_maturity <= environment.maturity]
    baseline = environment.decision(threat)
    if baseline["decision"] == "deterred":
        return {"already": True, "spend": 0.0, "levers": [], "decision": baseline}

    best: Optional[dict] = None
    for size in range(1, max_levers + 1):
        for combination in combinations(pool, size):
            trial = replace(environment, levers=list(environment.levers) + list(combination))
            verdict = trial.decision(threat)
            if verdict["decision"] != "deterred":
                continue
            spend = sum(lever.annual_cost for lever in combination)
            if best is None or spend < best["spend"]:
                best = {
                    "already": False,
                    "levers": [lever.name for lever in combination],
                    "spend": spend,
                    "decision": verdict,
                    "before": baseline,
                }
    return best


def substitution(environment: Environment, peers: Sequence[Tuple[str, float]]) -> dict:
    """What happens to the attempt you just made unattractive.

    Deterrence on your own asset relocates the attempt; it does not delete it. That is a win for
    you and a loss for whoever is next, and a design document that does not say so is a sales
    document. The honest version also asks whether the relocation is toward a peer that will tell
    you about it, because that is the only version that helps anyone else.
    """
    mine = environment.attacker_return
    ranked = sorted(
        [{"peer": name, "return": round(value, 2)} for name, value in peers],
        key=lambda item: item["return"],
        reverse=True,
    )
    return {
        "your_terms": environment.terms(),
        "annual_cost": round(environment.annual_cost, 2),
        "peer_ranking": ranked,
        "note": (
            "the attempt follows the cheapest available environment; raising your cost moves it to the top of this list, "
            "which is a transfer rather than a reduction"
        ),
    }
