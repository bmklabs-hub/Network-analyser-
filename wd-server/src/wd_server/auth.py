"""Probe authentication — the minimal seam.  ADR-27.

The roadmap puts real auth and tenancy in Phase 6. This file exists in
Phase 2 anyway, because of what happens if it doesn't: every handler, every
query and every template gets written with no notion of *who is calling*,
and retrofitting identity means revisiting every one of them and hoping you
found them all.

So the seam is built now and filled in later:

  * a bearer token, checked against WD_PROBE_TOKENS
  * resolved into a `ProbeIdentity` that ALREADY carries `tenant_id`
    (always "default" today — Phase 6 replaces the lookup, not the callers)

Two rules this file enforces:

  1. **Fail closed.** No tokens configured → 503 with the fix in the message.
     An open ingest endpoint is a nuisance in a lab and an incident in
     production. "Secure unless configured otherwise" is the only safe default.

  2. **Tenancy comes from the credential, never from the payload.** The probe
     cannot tell us which tenant it belongs to; we tell it. (ADR-12: trusting
     a field the client controls is the opposite of what RLS guarantees.)
"""

from __future__ import annotations

import hmac
from dataclasses import dataclass

from fastapi import Header, HTTPException, Request, status

DEFAULT_TENANT = "default"


@dataclass(frozen=True)
class ProbeIdentity:
    probe_id: str
    tenant_id: str = DEFAULT_TENANT


def require_probe(
    request: Request,
    authorization: str | None = Header(default=None),
) -> ProbeIdentity:
    tokens: dict[str, str] = request.app.state.settings.probe_tokens

    if not tokens:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "Ingest is disabled: no probe tokens configured. "
            "Start the server with WD_PROBE_TOKENS=<probe-id>=<token>.",
        )

    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED, "Missing bearer token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    presented = authorization[7:].strip()

    # Constant-time comparison: a plain `==` returns faster the earlier the
    # first wrong character is, which leaks the token one byte at a time to
    # anyone patient enough to measure. Cheap to prevent, so prevent it.
    for token, probe_id in tokens.items():
        if hmac.compare_digest(token.encode(), presented.encode()):
            return ProbeIdentity(probe_id=probe_id)

    raise HTTPException(
        status.HTTP_401_UNAUTHORIZED, "Invalid probe token",
        headers={"WWW-Authenticate": "Bearer"},
    )
