from __future__ import annotations

import sqlite3

SCHEMA_STATEMENTS = [
    """
CREATE TABLE IF NOT EXISTS users (
    id          INTEGER PRIMARY KEY,
    username    TEXT NOT NULL UNIQUE,
    user_handle BLOB NOT NULL,
    created_at  INTEGER NOT NULL
)
""",
    """
CREATE TABLE IF NOT EXISTS credentials (
    id              INTEGER PRIMARY KEY,
    user_id         INTEGER NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
    credential_id   BLOB NOT NULL UNIQUE,
    public_key_spki BLOB NOT NULL,
    sign_count      INTEGER NOT NULL,
    created_at      INTEGER NOT NULL
)
""",
    """
CREATE TABLE IF NOT EXISTS challenges (
    challenge  BLOB PRIMARY KEY,
    username   TEXT NOT NULL,
    operation  TEXT NOT NULL CHECK (operation IN ('create', 'get')),
    consumed   INTEGER NOT NULL DEFAULT 0,
    expires_at INTEGER NOT NULL
)
""",
    """
CREATE TABLE IF NOT EXISTS sessions (
    token_hash BLOB PRIMARY KEY,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at INTEGER NOT NULL
)
""",
]


def connect(database_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(database_path, timeout=30, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=30000")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def initialize_database(database_path: str) -> None:
    conn = connect(database_path)
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("BEGIN IMMEDIATE")
        try:
            for statement in SCHEMA_STATEMENTS:
                conn.execute(statement)
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise
    finally:
        conn.close()
