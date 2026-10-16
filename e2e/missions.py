"""Mission tokens: the trusted input a PEP takes the Mission from.

A stand-in for a verified token claim (for example an OAuth access token
carrying a Mission). The issuer signs ``{mission, sub, exp}`` with a key the
PEPs verify; the agent holds the token but cannot mint or alter one. A
delegated token names the delegator and carries the delegator's Mission, as
the profile requires.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from typing import Any


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def mint(key: bytes, mission: str, sub: str, ttl: float = 600.0,
         delegated_by: str | None = None, exp: float | None = None) -> str:
    """A token for ``mission``, expiring ``ttl`` seconds from now, or at
    ``exp`` when given."""
    claims: dict[str, Any] = {"mission": mission, "sub": sub,
                              "exp": time.time() + ttl if exp is None else exp}
    if delegated_by is not None:
        claims["delegated_by"] = delegated_by
    body = _b64(json.dumps(claims, sort_keys=True).encode("utf-8"))
    sig = _b64(hmac.new(key, body.encode("ascii"), hashlib.sha256).digest())
    return f"{body}.{sig}"


def delegate(key: bytes, parent_token: str, sub: str) -> str:
    """A token for a sub-agent, carrying the delegator's Mission."""
    parent = verify(key, parent_token)
    if parent is None:
        raise ValueError("invalid parent token")
    # Never longer than the delegator's own credential: its expiry is read
    # once, so a clock that moves in between cannot push the child's past it.
    exp = min(float(parent["exp"]), time.time() + 600.0)
    return mint(key, parent["mission"], sub, delegated_by=parent["sub"], exp=exp)


def verify(key: bytes, token: str) -> dict[str, Any] | None:
    """The claims of a valid, unexpired token, or None."""
    try:
        body, sig = token.split(".")
        expected = _b64(hmac.new(key, body.encode("ascii"), hashlib.sha256).digest())
        if not hmac.compare_digest(sig, expected):
            return None
        claims = json.loads(_unb64(body))
    except (ValueError, UnicodeDecodeError):
        return None
    if not isinstance(claims, dict) or float(claims.get("exp", 0)) < time.time():
        return None
    if not isinstance(claims.get("mission"), str) or not isinstance(claims.get("sub"), str):
        return None
    return claims
