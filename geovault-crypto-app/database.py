"""
GeoVault - SQLite persistence layer
===================================

Design rules
------------
* **No plaintext secrets are ever written to the database.** Every helper in
  this module receives data that has *already* been hashed or encrypted by a
  crypto module (``modules/*``) and stores it verbatim.
* All SQL uses parameterised queries (no string formatting) to prevent
  SQL injection.
* Each call opens a short-lived connection, which is the safest pattern for
  Streamlit's multi-threaded script runner.

Tables
------
``users``               PBKDF2 verifier + salt, AES-128-EAX biometric template
``secret_messages``     Vigenère + AES-256-CBC super-encrypted tokens
``encrypted_files``     ChaCha20 file metadata (ciphertext lives on disk)
``blockchain_ledger``   PoW blocks with AES-GCM encrypted asset metadata
``app_meta``            Key/value store (e.g. the HMAC-signed ledger tip anchor)
"""

from __future__ import annotations

import sqlite3
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Callable, Iterator, Optional

import config

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    username         TEXT    NOT NULL UNIQUE,      -- always lower-case
    password_hash    TEXT    NOT NULL,             -- hex verifier: PBKDF2-HMAC-SHA256 -> HKDF
    password_salt    TEXT    NOT NULL,             -- hex, 16 random bytes
    kdf_iterations   INTEGER NOT NULL,
    bio_template     BLOB    NOT NULL,             -- AES-128-EAX: nonce(16) | tag(16) | ciphertext
    bio_algorithm    TEXT    NOT NULL,
    failed_attempts  INTEGER NOT NULL DEFAULT 0,
    locked_until     REAL    NOT NULL DEFAULT 0,   -- unix epoch seconds
    created_at       TEXT    NOT NULL,
    last_login       TEXT
);

CREATE TABLE IF NOT EXISTS secret_messages (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    owner       TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,
    title       TEXT NOT NULL,
    ciphertext  TEXT NOT NULL,                     -- super-encrypted token (Vigenere + AES-256-CBC)
    algorithm   TEXT NOT NULL,
    created_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS encrypted_files (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    owner          TEXT    NOT NULL REFERENCES users(username) ON DELETE CASCADE,
    original_name  TEXT    NOT NULL,
    stored_name    TEXT    NOT NULL UNIQUE,        -- random file name inside storage/files
    mime_type      TEXT,
    size_bytes     INTEGER NOT NULL,
    sha256_plain   TEXT    NOT NULL,               -- integrity check after decryption
    kdf_salt       TEXT    NOT NULL,               -- hex
    nonce          TEXT    NOT NULL,               -- hex
    algorithm      TEXT    NOT NULL,
    created_at     TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS blockchain_ledger (
    block_index               INTEGER PRIMARY KEY,
    timestamp                 TEXT    NOT NULL,
    asset_name                TEXT    NOT NULL,
    encrypted_asset_metadata  TEXT    NOT NULL,    -- base64(AES-256-GCM nonce|tag|ciphertext)
    previous_hash             TEXT    NOT NULL,
    nonce                     INTEGER NOT NULL,
    current_hash              TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS app_meta (
    key    TEXT PRIMARY KEY,
    value  TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_secret_messages_owner ON secret_messages(owner);
CREATE INDEX IF NOT EXISTS idx_encrypted_files_owner ON encrypted_files(owner);
"""


# --------------------------------------------------------------------------- #
# Connection helpers
# --------------------------------------------------------------------------- #
def utc_now_iso() -> str:
    """ISO-8601 UTC timestamp with second precision."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def get_connection() -> sqlite3.Connection:
    """
    Open a new connection in *autocommit* mode (``isolation_level=None``).
    Explicit transactions are managed by :func:`transaction`.
    """
    config.ensure_storage()
    conn = sqlite3.connect(config.DB_PATH, timeout=15, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


@contextmanager
def transaction(immediate: bool = True) -> Iterator[sqlite3.Connection]:
    """
    Context manager yielding a connection inside an explicit transaction.

    ``BEGIN IMMEDIATE`` grabs the write lock up-front, which serialises
    concurrent writers (important for appending blockchain blocks).
    """
    conn = get_connection()
    try:
        conn.execute("BEGIN IMMEDIATE" if immediate else "BEGIN")
        yield conn
        conn.execute("COMMIT")
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    finally:
        conn.close()


def _fetchone(sql: str, params: tuple = ()) -> Optional[dict]:
    conn = get_connection()
    try:
        row = conn.execute(sql, params).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def _fetchall(sql: str, params: tuple = ()) -> list[dict]:
    conn = get_connection()
    try:
        return [dict(r) for r in conn.execute(sql, params).fetchall()]
    finally:
        conn.close()


def _execute(sql: str, params: tuple = ()) -> int:
    """Run a single write statement; returns ``lastrowid`` (or rowcount for UPDATE/DELETE)."""
    with transaction() as conn:
        cur = conn.execute(sql, params)
        return cur.lastrowid if sql.lstrip().upper().startswith("INSERT") else cur.rowcount


def init_db() -> None:
    """Create all tables and indexes (idempotent)."""
    conn = get_connection()
    try:
        conn.executescript(SCHEMA)
    finally:
        conn.close()


# --------------------------------------------------------------------------- #
# users
# --------------------------------------------------------------------------- #
def create_user(
    username: str,
    password_hash: str,
    password_salt: str,
    kdf_iterations: int,
    bio_template: bytes,
    bio_algorithm: str,
) -> int:
    """Insert a new user. Raises ``sqlite3.IntegrityError`` if the username exists."""
    return _execute(
        """INSERT INTO users (username, password_hash, password_salt, kdf_iterations,
                              bio_template, bio_algorithm, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (username, password_hash, password_salt, kdf_iterations,
         sqlite3.Binary(bio_template), bio_algorithm, utc_now_iso()),
    )


def get_user(username: str) -> Optional[dict]:
    return _fetchone("SELECT * FROM users WHERE username = ?", (username,))


def user_exists(username: str) -> bool:
    return _fetchone("SELECT 1 AS x FROM users WHERE username = ?", (username,)) is not None


def record_login_failure(username: str, max_attempts: int, lockout_seconds: int) -> int:
    """Increment the failure counter; lock the account when the limit is hit. Returns the new count."""
    with transaction() as conn:
        row = conn.execute("SELECT failed_attempts FROM users WHERE username = ?", (username,)).fetchone()
        if row is None:
            return 0
        attempts = row["failed_attempts"] + 1
        locked_until = 0.0
        if attempts >= max_attempts:
            locked_until = time.time() + lockout_seconds
            attempts = 0  # reset counter after applying the lock
        conn.execute(
            "UPDATE users SET failed_attempts = ?, locked_until = ? WHERE username = ?",
            (attempts, locked_until, username),
        )
        return attempts


def record_login_success(username: str) -> None:
    _execute(
        "UPDATE users SET failed_attempts = 0, locked_until = 0, last_login = ? WHERE username = ?",
        (utc_now_iso(), username),
    )


# --------------------------------------------------------------------------- #
# secret_messages  (ciphertext produced by modules.super_encryption)
# --------------------------------------------------------------------------- #
def insert_secret_message(owner: str, title: str, ciphertext: str, algorithm: str) -> int:
    return _execute(
        "INSERT INTO secret_messages (owner, title, ciphertext, algorithm, created_at) VALUES (?, ?, ?, ?, ?)",
        (owner, title, ciphertext, algorithm, utc_now_iso()),
    )


def list_secret_messages(owner: str) -> list[dict]:
    return _fetchall("SELECT * FROM secret_messages WHERE owner = ? ORDER BY id DESC", (owner,))


def get_secret_message(message_id: int, owner: str) -> Optional[dict]:
    return _fetchone("SELECT * FROM secret_messages WHERE id = ? AND owner = ?", (message_id, owner))


def delete_secret_message(message_id: int, owner: str) -> bool:
    return _execute("DELETE FROM secret_messages WHERE id = ? AND owner = ?", (message_id, owner)) > 0


# --------------------------------------------------------------------------- #
# encrypted_files  (ciphertext produced by modules.file_crypto)
# --------------------------------------------------------------------------- #
def insert_encrypted_file(
    owner: str,
    original_name: str,
    stored_name: str,
    mime_type: Optional[str],
    size_bytes: int,
    sha256_plain: str,
    kdf_salt: str,
    nonce: str,
    algorithm: str,
) -> int:
    return _execute(
        """INSERT INTO encrypted_files (owner, original_name, stored_name, mime_type, size_bytes,
                                        sha256_plain, kdf_salt, nonce, algorithm, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (owner, original_name, stored_name, mime_type, size_bytes,
         sha256_plain, kdf_salt, nonce, algorithm, utc_now_iso()),
    )


def list_encrypted_files(owner: str) -> list[dict]:
    return _fetchall("SELECT * FROM encrypted_files WHERE owner = ? ORDER BY id DESC", (owner,))


def get_encrypted_file(file_id: int, owner: str) -> Optional[dict]:
    return _fetchone("SELECT * FROM encrypted_files WHERE id = ? AND owner = ?", (file_id, owner))


def delete_encrypted_file(file_id: int, owner: str) -> bool:
    return _execute("DELETE FROM encrypted_files WHERE id = ? AND owner = ?", (file_id, owner)) > 0


# --------------------------------------------------------------------------- #
# blockchain_ledger
# --------------------------------------------------------------------------- #
_BLOCK_COLUMNS = ("block_index", "timestamp", "asset_name", "encrypted_asset_metadata",
                  "previous_hash", "nonce", "current_hash")


def _row_to_block(row: Optional[sqlite3.Row | dict]) -> Optional[dict]:
    """Map the DB column ``block_index`` to the public field name ``index``."""
    if row is None:
        return None
    data = dict(row)
    data["index"] = data.pop("block_index")
    return data


def get_all_blocks() -> list[dict]:
    return [_row_to_block(r) for r in _fetchall("SELECT * FROM blockchain_ledger ORDER BY block_index ASC")]


def get_last_block() -> Optional[dict]:
    return _row_to_block(_fetchone("SELECT * FROM blockchain_ledger ORDER BY block_index DESC LIMIT 1"))


def count_blocks() -> int:
    row = _fetchone("SELECT COUNT(*) AS n FROM blockchain_ledger")
    return int(row["n"]) if row else 0


def append_block_atomic(
    builder: Callable[[Optional[dict]], Optional[tuple[dict, dict[str, str]]]],
) -> Optional[dict]:
    """
    Append a block inside a single ``BEGIN IMMEDIATE`` transaction.

    ``builder(last_block)`` receives the current chain tip (or ``None``) and
    must return ``(block_dict, meta_updates)`` - or ``None`` to abort without
    writing. Holding the write lock while building guarantees that two
    sessions can never mine on top of the same parent block.
    """
    with transaction() as conn:
        last = _row_to_block(
            conn.execute("SELECT * FROM blockchain_ledger ORDER BY block_index DESC LIMIT 1").fetchone()
        )
        built = builder(last)
        if built is None:
            return None
        block, meta_updates = built
        conn.execute(
            f"INSERT INTO blockchain_ledger ({', '.join(_BLOCK_COLUMNS)}) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (block["index"], block["timestamp"], block["asset_name"], block["encrypted_asset_metadata"],
             block["previous_hash"], block["nonce"], block["current_hash"]),
        )
        for key, value in meta_updates.items():
            conn.execute(
                "INSERT INTO app_meta (key, value) VALUES (?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (key, value),
            )
        return block


def overwrite_block(block: dict) -> None:
    """
    Raw UPDATE of a block row **bypassing all validation**.
    Used only by the blockchain *Tamper Lab* demo to simulate an attacker.
    """
    _execute(
        """UPDATE blockchain_ledger
           SET timestamp = ?, asset_name = ?, encrypted_asset_metadata = ?,
               previous_hash = ?, nonce = ?, current_hash = ?
           WHERE block_index = ?""",
        (block["timestamp"], block["asset_name"], block["encrypted_asset_metadata"],
         block["previous_hash"], block["nonce"], block["current_hash"], block["index"]),
    )


def delete_block(index: int) -> bool:
    """Raw DELETE of a block (Tamper Lab demo only)."""
    return _execute("DELETE FROM blockchain_ledger WHERE block_index = ?", (index,)) > 0


def clear_ledger(meta_keys: tuple[str, ...] = ()) -> None:
    """Delete every block and the given meta keys (ledger reset)."""
    with transaction() as conn:
        conn.execute("DELETE FROM blockchain_ledger")
        for key in meta_keys:
            conn.execute("DELETE FROM app_meta WHERE key = ?", (key,))


# --------------------------------------------------------------------------- #
# app_meta
# --------------------------------------------------------------------------- #
def get_meta(key: str) -> Optional[str]:
    row = _fetchone("SELECT value FROM app_meta WHERE key = ?", (key,))
    return row["value"] if row else None


def set_meta(key: str, value: str) -> None:
    _execute(
        "INSERT INTO app_meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (key, value),
    )


# --------------------------------------------------------------------------- #
# Dashboard statistics
# --------------------------------------------------------------------------- #
def get_user_stats(owner: str) -> dict[str, Any]:
    msgs = _fetchone("SELECT COUNT(*) AS n FROM secret_messages WHERE owner = ?", (owner,))
    files = _fetchone("SELECT COUNT(*) AS n, COALESCE(SUM(size_bytes), 0) AS total "
                      "FROM encrypted_files WHERE owner = ?", (owner,))
    return {
        "secret_messages": int(msgs["n"]) if msgs else 0,
        "encrypted_files": int(files["n"]) if files else 0,
        "encrypted_bytes": int(files["total"]) if files else 0,
        "ledger_blocks": count_blocks(),
    }
