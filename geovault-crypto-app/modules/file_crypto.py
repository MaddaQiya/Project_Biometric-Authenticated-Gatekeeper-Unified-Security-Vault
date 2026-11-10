"""
B.A.G.U.S. Vault - ChaCha20 File Byte-Stream Encryption
=======================================================

High-speed symmetric stream encryption for forensic documents (PDF, DOCX, TXT, CSV,
images, archives) using Daniel J. Bernstein's **ChaCha20** stream cipher:
  1. Generate a 16-byte CSPRNG salt (`kdf_salt`) and 12-byte stream cipher `nonce`.
  2. Derive a 256-bit key from `passphrase` and `kdf_salt` via PBKDF2-HMAC-SHA256 (200,000 iterations).
  3. Compute the plaintext SHA-256 digest (`sha256_plain`) prior to encryption.
  4. Encrypt document bytes using `Crypto.Cipher.ChaCha20`.
  5. Package into standalone `.bagus.enc` envelope containing embedded metadata for one-click restoration.
"""

from __future__ import annotations

import hashlib
import json
import struct
from dataclasses import dataclass
from typing import Optional

from Crypto.Cipher import ChaCha20
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes

ALGORITHM_ID: str = "ChaCha20-Stream"
KDF_ITERATIONS: int = 200_000
SALT_BYTES: int = 16
NONCE_BYTES: int = 12
MAGIC_HEADER: bytes = b"BAGUSENC1\x00"


@dataclass
class EncryptedFileBundle:
    """Output of :func:`encrypt_file_bytes`, aligned with SQLite `encrypted_files` schema."""

    ciphertext: bytes
    sha256_plain: str      # hex SHA-256 digest of original plaintext bytes
    kdf_salt: str          # hex-encoded 16-byte salt
    nonce: str             # hex-encoded ChaCha20 nonce (12 bytes)
    algorithm: str = ALGORITHM_ID


def _derive_chacha_key(passphrase: str, salt: bytes) -> bytes:
    return PBKDF2(
        passphrase,
        salt,
        dkLen=32,
        count=KDF_ITERATIONS,
        hmac_hash_module=SHA256,
    )


def encrypt_file_bytes(plain_bytes: bytes, passphrase: str) -> EncryptedFileBundle:
    """
    Encrypt raw binary file bytes with a PBKDF2-derived ChaCha20 keystream.

    :param plain_bytes: Original binary content of the document.
    :param passphrase:  User-supplied encryption passphrase.
    :returns:           :class:`EncryptedFileBundle` containing ciphertext and parameters.
    """
    if not plain_bytes:
        raise ValueError("Cannot encrypt an empty file byte stream.")
    if not passphrase:
        raise ValueError("Encryption passphrase cannot be empty.")

    salt = get_random_bytes(SALT_BYTES)
    nonce = get_random_bytes(NONCE_BYTES)
    key = _derive_chacha_key(passphrase, salt)

    sha256_plain = hashlib.sha256(plain_bytes).hexdigest()

    cipher = ChaCha20.new(key=key, nonce=nonce)
    ciphertext = cipher.encrypt(plain_bytes)

    return EncryptedFileBundle(
        ciphertext=ciphertext,
        sha256_plain=sha256_plain,
        kdf_salt=salt.hex(),
        nonce=nonce.hex(),
        algorithm=ALGORITHM_ID,
    )


def decrypt_file_bytes(
    cipher_bytes: bytes,
    passphrase: str,
    kdf_salt_hex: str,
    nonce_hex: str,
    expected_sha256: str,
) -> bytes:
    """
    Decrypt a ChaCha20 ciphertext stream and verify its plaintext SHA-256 digest.

    :param cipher_bytes:    Raw encrypted bytes.
    :param passphrase:      User-supplied decryption passphrase.
    :param kdf_salt_hex:    Hex salt stored in metadata.
    :param nonce_hex:       Hex nonce stored in metadata.
    :param expected_sha256: Hex SHA-256 of the original file for integrity verification.
    :returns:               Verified plaintext file bytes.
    :raises ValueError:     If decryption fails or SHA-256 integrity check fails.
    """
    if not cipher_bytes:
        raise ValueError("Ciphertext byte stream is empty.")
    if not passphrase:
        raise ValueError("Decryption passphrase cannot be empty.")

    try:
        salt = bytes.fromhex(kdf_salt_hex)
        nonce = bytes.fromhex(nonce_hex)
    except Exception as exc:
        raise ValueError(f"Malformed salt or nonce hexadecimal: {exc}") from exc

    key = _derive_chacha_key(passphrase, salt)
    cipher = ChaCha20.new(key=key, nonce=nonce)
    plain_bytes = cipher.decrypt(cipher_bytes)

    actual_sha256 = hashlib.sha256(plain_bytes).hexdigest()
    if actual_sha256.lower() != expected_sha256.strip().lower():
        raise ValueError(
            f"Integrity check failed: plaintext SHA-256 mismatch!\n"
            f"Expected: {expected_sha256}\n"
            f"Actual:   {actual_sha256}\n"
            f"(Incorrect passphrase or tampered ciphertext)."
        )

    return plain_bytes


# --------------------------------------------------------------------------- #
# Standalone .bagus.enc Package Envelope Helpers
# --------------------------------------------------------------------------- #
def pack_bagus_envelope(
    bundle: EncryptedFileBundle,
    original_name: str,
    mime_type: Optional[str] = None,
) -> bytes:
    """
    Package an encrypted bundle into a self-contained `.bagus.enc` binary file:
      [MAGIC_HEADER (10B)] [HEADER_LEN (4B uint32)] [JSON_HEADER] [CIPHERTEXT_BYTES]
    """
    meta = {
        "format": "B.A.G.U.S._EVIDENCE_ENVELOPE",
        "version": 1,
        "algorithm": bundle.algorithm,
        "original_name": original_name,
        "mime_type": mime_type or "application/octet-stream",
        "sha256_plain": bundle.sha256_plain,
        "kdf_salt": bundle.kdf_salt,
        "nonce": bundle.nonce,
        "kdf_iterations": KDF_ITERATIONS,
    }
    meta_json = json.dumps(meta, separators=(",", ":")).encode("utf-8")
    header_len = struct.pack(">I", len(meta_json))
    return MAGIC_HEADER + header_len + meta_json + bundle.ciphertext


def unpack_bagus_envelope(package_bytes: bytes, passphrase: str) -> tuple[bytes, dict]:
    """
    Unpack and decrypt a standalone `.bagus.enc` binary file.
    Returns ``(plain_bytes, metadata_dict)``.
    """
    magic_len = len(MAGIC_HEADER)
    if len(package_bytes) < magic_len + 4:
        raise ValueError("Invalid file format: file too small to be a .bagus.enc package.")
    if package_bytes[:magic_len] != MAGIC_HEADER:
        raise ValueError("Invalid file signature: missing B.A.G.U.S. Vault magic header.")

    header_len = struct.unpack(">I", package_bytes[magic_len:magic_len + 4])[0]
    header_end = magic_len + 4 + header_len
    if len(package_bytes) < header_end:
        raise ValueError("Corrupt file: header length exceeds file size.")

    raw_meta = package_bytes[magic_len + 4:header_end].decode("utf-8")
    meta = json.loads(raw_meta)
    ciphertext = package_bytes[header_end:]

    plain_bytes = decrypt_file_bytes(
        cipher_bytes=ciphertext,
        passphrase=passphrase,
        kdf_salt_hex=meta["kdf_salt"],
        nonce_hex=meta["nonce"],
        expected_sha256=meta["sha256_plain"],
    )

    return plain_bytes, meta
