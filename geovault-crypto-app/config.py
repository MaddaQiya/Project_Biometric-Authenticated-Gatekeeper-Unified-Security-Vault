"""
GeoVault - Central configuration & key hierarchy
================================================

This module is the *single source of truth* for filesystem paths and for the
application's key hierarchy. Both developers should import keys from here
instead of hard-coding secrets inside their own modules.

Key hierarchy
-------------

                 GEOVAULT_MASTER_SECRET (env)  or  storage/.master_secret
                                     |
                         HKDF-SHA256 (salt = HKDF_SALT)
          +-----------------+--------+---------+-------------------+
          |                 |                  |                   |
   dongle/hmac-sha256  auth/password-pepper  ledger/aes-256-gcm  ledger/anchor-hmac
   (dongle_guard)      (auth_biometric)      (blockchain)        (blockchain)

Each purpose string yields an independent, domain-separated sub-key, so a
compromise of one sub-key never reveals the master secret or its siblings.
"""

from __future__ import annotations

import os
import secrets
from functools import lru_cache
from pathlib import Path

from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import HKDF

# --------------------------------------------------------------------------- #
# Paths
# --------------------------------------------------------------------------- #
BASE_DIR: Path = Path(__file__).resolve().parent
STORAGE_DIR: Path = Path(os.environ.get("GEOVAULT_STORAGE_DIR", BASE_DIR / "storage"))
DB_PATH: Path = STORAGE_DIR / "geovault.db"
FILES_DIR: Path = STORAGE_DIR / "files"  # ChaCha20 ciphertext blobs (Dev 2)
MASTER_SECRET_FILE: Path = STORAGE_DIR / ".master_secret"

# --------------------------------------------------------------------------- #
# Dongle settings
# --------------------------------------------------------------------------- #
DONGLE_FILENAME: str = ".geovault_dongle"
#: Extra dongle search locations (os.pathsep separated) - handy for testing
#: without a physical USB stick, e.g.  set GEOVAULT_DONGLE_PATH=C:\fake_usb
DONGLE_PATH_ENV: str = "GEOVAULT_DONGLE_PATH"
#: Local directory checked as a configurable testing fallback when present.
DEFAULT_FALLBACK_DONGLE_DIR: Path = BASE_DIR / "virtual_usb"

# --------------------------------------------------------------------------- #
# Misc settings
# --------------------------------------------------------------------------- #
MASTER_SECRET_ENV: str = "GEOVAULT_MASTER_SECRET"
#: When enabled, the lock screen exposes an in-app dongle provisioning panel.
DEV_MODE: bool = os.environ.get("GEOVAULT_DEV_MODE", "0").strip().lower() in {"1", "true", "yes"}
#: Blockchain Proof-of-Work difficulty (number of leading hex zeros).
POW_DIFFICULTY: int = 2

# --------------------------------------------------------------------------- #
# Key-derivation purposes (domain separation labels)
# --------------------------------------------------------------------------- #
HKDF_SALT: bytes = b"GeoVault/v1/key-hierarchy"
PURPOSE_DONGLE_HMAC = "dongle/hmac-sha256"
PURPOSE_PASSWORD_PEPPER = "auth/password-pepper"
PURPOSE_LEDGER_AES = "ledger/aes-256-gcm"
PURPOSE_LEDGER_ANCHOR = "ledger/anchor-hmac"


def ensure_storage() -> None:
    """Create the storage directories if they do not exist yet."""
    STORAGE_DIR.mkdir(parents=True, exist_ok=True)
    FILES_DIR.mkdir(parents=True, exist_ok=True)


def _parse_secret(raw: str) -> bytes:
    """Accept a hex string (preferred) or fall back to raw UTF-8 bytes."""
    raw = raw.strip()
    try:
        return bytes.fromhex(raw)
    except ValueError:
        return raw.encode("utf-8")


@lru_cache(maxsize=1)
def get_master_secret() -> bytes:
    """
    Return the application master secret.

    Resolution order:
      1. ``GEOVAULT_MASTER_SECRET`` environment variable (hex recommended).
      2. ``storage/.master_secret`` file.
      3. Generate a fresh 256-bit secret with a CSPRNG and persist it to (2).

    .. warning::
       Losing this secret makes every dongle, password verifier and ledger
       ciphertext unrecoverable. Back it up, and use the same value on every
       machine that must accept the same dongle.
    """
    env_value = os.environ.get(MASTER_SECRET_ENV)
    if env_value:
        secret = _parse_secret(env_value)
        if len(secret) < 16:
            raise RuntimeError(f"{MASTER_SECRET_ENV} must be at least 16 bytes (32 hex chars).")
        return secret

    ensure_storage()
    if MASTER_SECRET_FILE.exists():
        secret = _parse_secret(MASTER_SECRET_FILE.read_text(encoding="utf-8"))
        if len(secret) < 16:
            raise RuntimeError(f"{MASTER_SECRET_FILE} is corrupted (secret too short).")
        return secret

    secret = secrets.token_bytes(32)
    try:
        # O_EXCL avoids a race where two processes generate different secrets.
        fd = os.open(MASTER_SECRET_FILE, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        return _parse_secret(MASTER_SECRET_FILE.read_text(encoding="utf-8"))
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(secret.hex())
    return secret


def derive_subkey(purpose: str, length: int = 32) -> bytes:
    """
    Derive a domain-separated sub-key from the master secret with HKDF-SHA256.

    :param purpose: One of the ``PURPOSE_*`` labels (or a new unique label).
    :param length:  Key length in bytes (16 = AES-128, 32 = AES-256/ChaCha20).
    """
    return HKDF(
        master=get_master_secret(),
        key_len=length,
        salt=HKDF_SALT,
        hashmod=SHA256,
        context=purpose.encode("utf-8"),
    )
