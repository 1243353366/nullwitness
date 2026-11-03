"""Canary tokens: issue, verify, and build callback URLs.

A canary is an identifier you plant somewhere you control so that *use* of that
artefact becomes visible. This module is the detection half of the idea: it mints
tokens, and it verifies that a callback carries a token you actually issued.

It deliberately does not generate decoy documents, tracking pixels, or any
client-side payload. A token is a string; where you put it and how it gets requested
is the operator's decision, and the visible-notice obligations that come with that
belong to them.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import urllib.parse
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterable, List, Optional

TOKEN_PREFIX = "cnry"


class TokenError(ValueError):
    """Raised when a token cannot be verified against the issuing key."""


@dataclass(frozen=True)
class CanaryToken:
    token_id: str
    label: str
    salt_epoch: str
    created_at: str

    @property
    def token_url_path(self) -> str:
        return f"/c/{self.token_id}"

    def callback_url(self, base_url: str) -> str:
        return base_url.rstrip("/") + self.token_url_path


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def new_secret(n_bytes: int = 32) -> str:
    """A fresh HMAC key, base32 encoded so it survives copy and paste."""
    return base64.b32encode(secrets.token_bytes(n_bytes)).decode("ascii")


def issue(label: str, secret: str, salt_epoch: str) -> CanaryToken:
    """Deterministic token id from (label, epoch), so the same label always reissues.

    Determinism matters for operations: rotating a canary means changing the epoch,
    and every downstream report keys on the same stable identifier instead of a
    random value nobody can trace back to a document.
    """
    if not label or not label.strip():
        raise TokenError("label must be non-empty")
    if not secret:
        raise TokenError("refusing to issue tokens without a secret")
    if not salt_epoch:
        raise TokenError("salt_epoch must be non-empty")
    material = f"{salt_epoch}|{label.strip().lower()}".encode("utf-8")
    digest = hmac.new(secret.encode("utf-8"), material, hashlib.sha256).hexdigest()
    return CanaryToken(
        token_id=f"{TOKEN_PREFIX}_{digest[:16]}",
        label=label.strip(),
        salt_epoch=salt_epoch,
        created_at=_now_iso(),
    )


def verify(token_id: str, label: str, secret: str, salt_epoch: str) -> bool:
    """True only if `token_id` is what this key would have issued for (label, epoch)."""
    if not token_id or not token_id.startswith(f"{TOKEN_PREFIX}_"):
        raise TokenError("not a canary token id")
    expected = issue(label, secret, salt_epoch).token_id
    return hmac.compare_digest(expected, token_id)


def parse_path(path: str) -> Optional[str]:
    """Extract a token id from a request path, or None if the path is not a callback."""
    if not path:
        return None
    path = urllib.parse.urlparse(path).path
    if not path.startswith("/c/"):
        return None
    token = path[len("/c/") :].strip("/")
    if not token.startswith(f"{TOKEN_PREFIX}_") or len(token) != len(f"{TOKEN_PREFIX}_") + 16:
        return None
    if any(ch not in "0123456789abcdef" for ch in token[len(TOKEN_PREFIX) + 1 :]):
        return None
    return token


def manifest_lines(tokens: Iterable[CanaryToken]) -> List[str]:
    """One tab-separated line per token, for a rotated registry file."""
    return ["\t".join([t.token_id, t.label, t.salt_epoch, t.created_at]) for t in tokens]
