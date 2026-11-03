"""Boot and firmware integrity: does the environment handling the plaintext deserve belief?

Encryption assumes the machine doing the encrypting is the machine you intended. Measured
boot is how that assumption becomes checkable: firmware measures the next stage before
handing control to it, each stage extends a digest chain, and the platform signs the result.
The verifier then compares the report against a policy of expected measurements.

Four things have to hold, and each fails separately:

1. **the report is authentic.** A signature over the report, checked with a key that did not
   travel with the report.
2. **the report is fresh.** A challenge nonce the verifier chose, inside the signed body.
   Without it, an attacker replays last week's clean report forever, and it verifies.
3. **the chain is continuous.** Stage *n* records the digest of stage *n+1*. A measurement
   that does not link to the next one was not taken by the chain it claims to be part of.
4. **the measurements match policy.** This is the only check that knows what "correct" means,
   and it is worthless if the policy is updated from the same host it is checking.

Honest scope note: the signature here is an HMAC with an attestation subkey, not a real
platform signature. A shared-secret signature means anyone who can read the attestation key
can mint a report, which in production is exactly what a TPM's hardware-bound key prevents.
This is a lab stand-in that keeps the verification logic testable; the logic is the artefact,
and `lab/TRUST-CHAIN.md` says which parts would change against a real attestation service.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence

from lab.crypto.keys import KeyRing
from lab.crypto.model import BOOT, Issue, TrustReport

ATTESTATION_PURPOSE = "attestation"
# Stages in the order a machine reaches them. A real platform may add more; what matters is
# that each one measures the next.
STAGE_ORDER = ("firmware", "bootloader", "kernel")


@dataclass(frozen=True)
class Stage:
    name: str
    digest: str
    extends: Optional[str] = None  # digest of the next stage, recorded by this one

    def as_dict(self) -> Dict[str, Optional[str]]:
        return {"name": self.name, "digest": self.digest, "extends": self.extends}


@dataclass(frozen=True)
class Attestation:
    stages: Sequence[Stage]
    nonce: str
    security_version: int
    signature: str = ""

    def canonical(self) -> bytes:
        body = {
            "nonce": self.nonce,
            "security_version": self.security_version,
            "stages": [stage.as_dict() for stage in self.stages],
        }
        return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")


@dataclass
class BootPolicy:
    """Expected measurements. `expected=None` means "no opinion", not "anything passes"."""

    expected: Dict[str, str] = field(default_factory=dict)
    order: Sequence[str] = STAGE_ORDER
    min_security_version: int = 1

    def expectation_for(self, name: str) -> Optional[str]:
        return self.expected.get(name)


def _sign(ring: KeyRing, body: bytes) -> str:
    key = ring.subkey(ATTESTATION_PURPOSE).material
    return hmac.new(key, body, hashlib.sha256).hexdigest()


def attest(ring: KeyRing, stages: Sequence[Stage], nonce: str, security_version: int = 1) -> Attestation:
    """Produce a report the way a platform would: measure, then sign the whole thing."""
    unsigned = Attestation(stages=tuple(stages), nonce=nonce, security_version=security_version)
    return Attestation(
        stages=tuple(stages), nonce=nonce, security_version=security_version, signature=_sign(ring, unsigned.canonical())
    )


def verify_attestation(
    ring: KeyRing,
    attestation: Attestation,
    policy: BootPolicy,
    challenge: str,
) -> TrustReport:
    """Check authenticity, freshness, continuity, then policy, in that order.

    Order matters for the report a human reads: an unauthenticated or stale report has no
    business producing measurement findings, because those findings would be about numbers an
    attacker chose.
    """
    report = TrustReport()

    unsigned = Attestation(attestation.stages, attestation.nonce, attestation.security_version)
    if not hmac.compare_digest(_sign(ring, unsigned.canonical()), attestation.signature or ""):
        report.add(
            Issue(
                BOOT,
                "attestation_unauthenticated",
                "high",
                "the boot report does not carry a signature from the attestation key: nothing in it is evidence, "
                "so the measurements below were not evaluated",
            )
        )
        return report

    if attestation.nonce != challenge:
        report.add(
            Issue(
                BOOT,
                "attestation_replayed",
                "high",
                f"report answers challenge {attestation.nonce!r} but this verifier asked {challenge!r}: a clean "
                "report from another moment is not evidence about this one",
            )
        )
        return report

    if attestation.security_version < policy.min_security_version:
        report.add(
            Issue(
                BOOT,
                "boot_rollback",
                "high",
                f"security version {attestation.security_version} is below the policy floor "
                f"{policy.min_security_version}: firmware was downgraded, which is how a patched flaw returns",
            )
        )

    names = [stage.name for stage in attestation.stages]
    missing = [name for name in policy.order if name not in names]
    unexpected = [name for name in names if name not in policy.order]
    if missing:
        report.add(
            Issue(
                BOOT,
                "boot_stage_missing",
                "high",
                f"report has no measurement for {', '.join(missing)}: an unmeasured stage is an unchecked one",
            )
        )
    if unexpected:
        report.add(
            Issue(
                BOOT,
                "boot_stage_unexpected",
                "medium",
                f"report includes stages the policy does not know: {', '.join(unexpected)}",
            )
        )

    for index, stage in enumerate(attestation.stages):
        if index + 1 < len(attestation.stages):
            following = attestation.stages[index + 1]
            if stage.extends != following.digest:
                report.add(
                    Issue(
                        BOOT,
                        "boot_chain_broken",
                        "high",
                        f"{stage.name} records extending {str(stage.extends)[:12]} but {following.name} measures "
                        f"{following.digest[:12]}: these measurements did not happen in the order claimed",
                    )
                )
        expected = policy.expectation_for(stage.name)
        if expected is None:
            report.skip(BOOT, f"no expected measurement for stage {stage.name}")
        elif expected != stage.digest:
            report.add(
                Issue(
                    BOOT,
                    "boot_measurement_mismatch",
                    "high",
                    f"{stage.name} measures {stage.digest[:16]} but policy expects {expected[:16]}: the code that "
                    "handles the plaintext is not the code that was approved",
                )
            )

    if not report.issues:
        report.ok(BOOT)
    return report


def build_chain(ring: KeyRing, digests: Dict[str, str], nonce: str, security_version: int = 1) -> Attestation:
    """Convenience: a properly linked chain from a name -> digest map."""
    stages: List[Stage] = []
    for index, name in enumerate(STAGE_ORDER):
        following = STAGE_ORDER[index + 1] if index + 1 < len(STAGE_ORDER) else None
        stages.append(
            Stage(
                name=name,
                digest=digests[name],
                extends=digests[following] if following else None,
            )
        )
    return attest(ring, stages, nonce, security_version)
