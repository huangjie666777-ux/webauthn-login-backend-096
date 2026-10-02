from __future__ import annotations

import secrets
import time

from app.db import connect


class UserExistsError(Exception):
    pass


class ChallengeError(Exception):
    pass


class Repository:
    def __init__(self, database_path: str):
        self.database_path = database_path

    def _conn(self):
        return connect(self.database_path)

    def create_challenge(self, username: str, operation: str, ttl_seconds: int) -> bytes:
        challenge = secrets.token_bytes(32)
        now = int(time.time())
        conn = self._conn()
        try:
            conn.execute(
                "INSERT INTO challenges(challenge, username, operation, consumed, expires_at)"
                " VALUES (?, ?, ?, 0, ?)",
                (challenge, username, operation, now + ttl_seconds),
            )
        finally:
            conn.close()
        return challenge

    def reserve_registration(self, username: str) -> bytes:
        """Create a user without credentials. Re-registration is rejected."""
        user_handle = secrets.token_bytes(32)
        now = int(time.time())
        conn = self._conn()
        try:
            conn.execute("BEGIN IMMEDIATE")
            try:
                row = conn.execute(
                    "SELECT 1 FROM users WHERE username = ?", (username,)
                ).fetchone()
                if row is not None:
                    conn.execute("ROLLBACK")
                    raise UserExistsError(f"user {username!r} already exists")
                conn.execute(
                    "INSERT INTO users(username, user_handle, created_at) VALUES (?, ?, ?)",
                    (username, user_handle, now),
                )
                conn.execute("COMMIT")
            except Exception:
                conn.execute("ROLLBACK")
                raise
        finally:
            conn.close()
        return user_handle

    def complete_registration(
        self,
        *,
        challenge: bytes,
        credential_id: bytes,
        public_key_spki: bytes,
        sign_count: int,
    ) -> str:
        now = int(time.time())
        conn = self._conn()
        try:
            conn.execute("BEGIN IMMEDIATE")
            try:
                row = conn.execute(
                    "SELECT username, expires_at, consumed FROM challenges"
                    " WHERE challenge = ? AND operation = 'create'",
                    (challenge,),
                ).fetchone()
                if row is None:
                    conn.execute("ROLLBACK")
                    raise ChallengeError("unknown registration challenge")
                if row["consumed"] or row["expires_at"] <= now:
                    conn.execute(
                        "DELETE FROM challenges WHERE expires_at <= ?", (now,)
                    )
                    conn.execute("ROLLBACK")
                    raise ChallengeError("challenge expired or already used")
                username = row["username"]
                user_row = conn.execute(
                    "SELECT id FROM users WHERE username = ?", (username,)
                ).fetchone()
                if user_row is None:
                    conn.execute("ROLLBACK")
                    raise ChallengeError("registration session no longer exists")
                user_id = user_row["id"]
                existing_credential = conn.execute(
                    "SELECT 1 FROM credentials WHERE credential_id = ?",
                    (credential_id,),
                ).fetchone()
                if existing_credential is not None:
                    conn.execute("ROLLBACK")
                    raise ChallengeError("credential is already registered")
                if conn.execute(
                    "SELECT 1 FROM credentials WHERE user_id = ?", (user_id,)
                ).fetchone():
                    conn.execute("ROLLBACK")
                    raise UserExistsError(f"user {username!r} already has a credential")
                conn.execute(
                    "INSERT INTO credentials(user_id, credential_id, public_key_spki,"
                    " sign_count, created_at) VALUES (?, ?, ?, ?, ?)",
                    (user_id, credential_id, public_key_spki, sign_count, now),
                )
                conn.execute(
                    "DELETE FROM challenges WHERE challenge = ?", (challenge,)
                )
                conn.execute("COMMIT")
                return username
            except Exception:
                conn.execute("ROLLBACK")
                raise
        finally:
            conn.close()

    def abort_registration(self, challenge: bytes) -> None:
        """Remove the challenge; the credential-less user is cleaned too."""
        conn = self._conn()
        try:
            conn.execute("BEGIN IMMEDIATE")
            try:
                row = conn.execute(
                    "SELECT username FROM challenges"
                    " WHERE challenge = ? AND operation = 'create'",
                    (challenge,),
                ).fetchone()
                if row is not None:
                    user_row = conn.execute(
                        "SELECT u.id FROM users u"
                        " LEFT JOIN credentials c ON c.user_id = u.id"
                        " WHERE u.username = ? AND c.id IS NULL",
                        (row["username"],),
                    ).fetchone()
                    if user_row is not None:
                        conn.execute(
                            "DELETE FROM users WHERE id = ?", (user_row["id"],)
                        )
                    conn.execute(
                        "DELETE FROM challenges WHERE challenge = ?", (challenge,)
                    )
                conn.execute("COMMIT")
            except Exception:
                conn.execute("ROLLBACK")
                raise
        finally:
            conn.close()

    def credential_for_login(self, username: str) -> bytes | None:
        conn = self._conn()
        try:
            row = conn.execute(
                "SELECT c.credential_id FROM credentials c"
                " JOIN users u ON u.id = c.user_id WHERE u.username = ?",
                (username,),
            ).fetchone()
            return row["credential_id"] if row else None
        finally:
            conn.close()

    def consume_assertion(
        self,
        *,
        challenge: bytes,
        credential_id: bytes,
        new_sign_count: int,
    ) -> str:
 now = int(time.time())
        conn = self._conn()
        try:
            conn.execute("BEGIN IMMEDIATE")
            try:
                challenge_row = conn.execute(
                    "SELECT username, expires_at, consumed FROM challenges"
                    " WHERE challenge = ? AND operation = 'get'",
                    (challenge,),
                ).fetchone()
                if challenge_row is None:
                    conn.execute("ROLLBACK")
                    raise ChallengeError("unknown login challenge")
                if challenge_row["consumed"] or challenge_row["expires_at"] <= now:
                    conn.execute("DELETE FROM challenges WHERE expires_at <= ?", (now,))
                    conn.execute("ROLLBACK")
                    raise ChallengeError("challenge expired or already used")
                credential_row = conn.execute(
                    "SELECT c.id, c.user_id, c.public_key_spki, c.sign_count,"
                    " u.username FROM credentials c"
                    " JOIN users u ON u.id = c.user_id"
                    " WHERE c.credential_id = ?",
                    (credential_id,),
                ).fetchone()
                if credential_row is None:
                    conn.execute("ROLLBACK")
                    raise ChallengeError("unknown credential")
                if credential_row["username"] != challenge_row["username"]:
                    conn.execute("ROLLBACK")
                    raise ChallengeError("credential does not belong to this user")
                old_count = credential_row["sign_count"]
                if not (old_count == 0 and new_sign_count == 0) and (
                    new_sign_count <= old_count
                ):
                    conn.execute("ROLLBACK")
                    raise ChallengeError("sign count did not strictly increase")
                conn.execute(
                    "UPDATE credentials SET sign_count = ? WHERE id = ?",
                    (new_sign_count, credential_row["id"]),
                )
                conn.execute(
                    "DELETE FROM challenges WHERE challenge = ?", (challenge,)
                )
                conn.execute("COMMIT")
                return credential_row["public_key_spki"]
            except Exception:
                conn.execute("ROLLBACK")
                raise
        finally:
            conn.close()

    def create_session(self, token_hash: bytes, username: str, ttl_seconds: int) -> None:
        now = int(time.time())
        conn = self._conn()
        try:
            conn.execute(
                "INSERT INTO sessions(token_hash, user_id, expires_at)"
                " SELECT ?, id, ? FROM users WHERE username = ?",
                (token_hash, now + ttl_seconds, username),
            )
        finally:
            conn.close()

    def session_user(self, token_hash: bytes) -> str | None:
        now = int(time.time())
        conn = self._conn()
        try:
            conn.execute("DELETE FROM sessions WHERE expires_at <= ?", (now,))
            conn.commit() if False else None
            row = conn.execute(
                "SELECT u.username FROM sessions s"
                " JOIN users u ON u.id = s.user_id"
                " WHERE s.token_hash = ? AND s.expires_at > ?",
                (token_hash, now),
            ).fetchone()
            return row["username"] if row else None
        finally:
            conn.close()

    def delete_session(self, token_hash: bytes) -> None:
        conn = self._conn()
        try:
            conn.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash,))
        finally:
            conn.close()

    def purge_expired(self) -> None:
        now = int(time.time())
        conn = self._conn()
        try:
            conn.execute("DELETE FROM challenges WHERE expires_at <= ?", (now,))
            conn.execute("DELETE FROM sessions WHERE expires_at <= ?", (now,))
        finally:
            conn.close()
