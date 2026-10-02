from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    rp_id: str
    rp_name: str
    origin: str
    database_path: str
    challenge_ttl_seconds: int = 300
    session_ttl_seconds: int = 1800


def get_settings() -> Settings:
    """Read RP configuration from the server environment only."""
    rp_id = os.environ.get("WEBAUTHN_RP_ID", "localhost")
    origin = os.environ.get("WEBAUTHN_ORIGIN", "http://localhost:8000")
    if not rp_id:
        raise RuntimeError("WEBAUTHN_RP_ID must not be empty")
    if "//" not in origin:
        raise RuntimeError("WEBAUTHN_ORIGIN must be an absolute origin")
    return Settings(
        rp_id=rp_id,
        rp_name=os.environ.get("WEBAUTHN_RP_NAME", "WebAuthn Demo"),
        origin=origin,
        database_path=os.environ.get("WEBAUTHN_DB", "webauthn.sqlite"),
        challenge_ttl_seconds=int(os.environ.get("WEBAUTHN_CHALLENGE_TTL", "300")),
        session_ttl_seconds=int(os.environ.get("WEBAUTHN_SESSION_TTL", "1800")),
    )
