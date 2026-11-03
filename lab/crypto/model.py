"""The five properties, as a shared vocabulary.

Every claim in this package belongs to exactly one of five properties, and naming them
consistently is the point: a finding that says "confidentiality is fine" while integrity
is broken is worse than no finding, because it invites a reader to stop at the wrong word.

The properties are a chain, not a list. Encryption protects a record nobody can read;
authenticated encryption protects a record nobody can alter; key protection decides whether
either of those statements means anything; boot and firmware integrity decide whether the
machine doing the encryption is the machine you think; endpoint integrity decides whether
what got encrypted is what actually happened.

The last two are the ones that get skipped, and they are the ones that decide the value of
the first three. A perfect ciphertext from a compromised endpoint is a faithful record of a
lie.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List

# The five properties, in the order they appear in the chain.
PAYLOAD = "payload_encryption"
AUTHENTICATED = "authenticated_encryption"
KEY_PROTECTION = "key_protection"
BOOT = "boot_integrity"
ENDPOINT = "endpoint_integrity"

PROPERTIES = (PAYLOAD, AUTHENTICATED, KEY_PROTECTION, BOOT, ENDPOINT)

PROPERTY_TITLE = {
    PAYLOAD: "Payload encryption",
    AUTHENTICATED: "Authenticated encryption",
    KEY_PROTECTION: "Key protection",
    BOOT: "Boot and firmware integrity",
    ENDPOINT: "Endpoint integrity",
}

PROPERTY_QUESTION = {
    PAYLOAD: "can an unauthorized reader see the contents?",
    AUTHENTICATED: "can an unauthorized writer modify the ciphertext unnoticed?",
    KEY_PROTECTION: "can an attacker obtain the keys?",
    BOOT: "is the environment handling the plaintext the one you expect?",
    ENDPOINT: "was the data manipulated before encryption or after decryption?",
}

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}


@dataclass(frozen=True)
class Issue:
    """One failed or weakened property, with the property named explicitly."""

    property: str
    code: str
    severity: str
    detail: str

    def as_dict(self) -> Dict[str, str]:
        return {
            "property": self.property,
            "code": self.code,
            "severity": self.severity,
            "detail": self.detail,
        }


@dataclass
class TrustReport:
    """What holds, what does not, and what was not checked.

    `unchecked` exists because the most misleading report is a short one. A property that
    could not be evaluated must say so rather than being absent from the output.
    """

    issues: List[Issue] = field(default_factory=list)
    verified: List[str] = field(default_factory=list)
    unchecked: List[str] = field(default_factory=list)

    def add(self, issue: Issue) -> None:
        self.issues.append(issue)

    def extend(self, issues: List[Issue]) -> None:
        self.issues.extend(issues)

    def ok(self, property_name: str) -> None:
        if property_name not in self.verified:
            self.verified.append(property_name)

    def skip(self, property_name: str, why: str) -> None:
        self.unchecked.append(f"{property_name}: {why}")

    @property
    def worst(self) -> str:
        for level in ("high", "medium", "low"):
            if any(issue.severity == level for issue in self.issues):
                return level
        return "none"

    def by_property(self) -> Dict[str, List[Issue]]:
        out: Dict[str, List[Issue]] = {name: [] for name in PROPERTIES}
        for issue in self.issues:
            out.setdefault(issue.property, []).append(issue)
        return out

    def sorted_issues(self) -> List[Issue]:
        return sorted(self.issues, key=lambda i: (SEVERITY_ORDER.get(i.severity, 3), i.property, i.code))

    def as_dict(self) -> Dict[str, object]:
        return {
            "worst": self.worst,
            "verified": sorted(self.verified),
            "unchecked": list(self.unchecked),
            "issues": [issue.as_dict() for issue in self.sorted_issues()],
        }
