from __future__ import annotations

import hashlib
import secrets


def generate_session_token() -> str:
    """Random opaque URL-safe token (256 bits of entropy)."""
    return secrets.token_urlsafe(32)


def hash_token(token: str) -> bytes:
    return hashlib.sha256(token.encode("utf-8")).digest()
