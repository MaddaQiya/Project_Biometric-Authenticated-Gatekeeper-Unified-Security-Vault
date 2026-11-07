"""
GeoVault - ChaCha20 File Byte-Stream Encryption              [DEVELOPER 2 STUB]
===============================================================================

Contract for Developer 2
------------------------
Implement stream encryption and decryption for arbitrary binary files (PDF, GeoJSON,
shapefiles, DOCX, archives, etc.) using **ChaCha20** (``Crypto.Cipher.ChaCha20``):
  1. Generate a random 16-byte ``kdf_salt`` and 12-byte (or 8-byte RFC 7539) ``nonce``.
  2. Derive a 32-byte key from ``passphrase`` + ``kdf_salt`` (PBKDF2-HMAC-SHA256).
  3. Compute ``sha256_plain = SHA256(file_bytes).hexdigest()`` so integrity can be
     verified upon decryption.
  4. Encrypt the byte stream with ``ChaCha20.new(key=key, nonce=nonce)`` and return an
     :class:`EncryptedFileBundle` so ``app.py`` can write the ciphertext to
     ``storage/files/<stored_name>`` and persist metadata via ``database.insert_encrypted_file``.

Do NOT modify ``app.py`` or ``database.py`` signatures—only implement the functions below.
"""

from __future__ import annotations

from dataclasses import dataclass

ALGORITHM_ID: str = "ChaCha20-Stream"


class FileCryptoNotImplementedError(NotImplementedError):
    """Raised while Developer 2's file_crypto module is still a stub."""


@dataclass
class EncryptedFileBundle:
    """Output of :func:`encrypt_file_bytes`, matching ``encrypted_files`` DB columns."""

    ciphertext: bytes
    sha256_plain: str      # hex SHA-256 digest of original plaintext bytes
    kdf_salt: str          # hex-encoded random salt
    nonce: str             # hex-encoded ChaCha20 nonce
    algorithm: str = ALGORITHM_ID


def encrypt_file_bytes(plain_bytes: bytes, passphrase: str) -> EncryptedFileBundle:
    """
    Encrypt raw file bytes with ChaCha20.

    :param plain_bytes: Original binary content of the uploaded document.
    :param passphrase:  User-supplied encryption passphrase.
    :returns:           :class:`EncryptedFileBundle` containing ciphertext and metadata.
    """
    raise FileCryptoNotImplementedError(
        "Developer 2: implement encrypt_file_bytes() in modules/file_crypto.py"
    )


def decrypt_file_bytes(
    cipher_bytes: bytes,
    passphrase: str,
    kdf_salt_hex: str,
    nonce_hex: str,
    expected_sha256: str,
) -> bytes:
    """
    Decrypt a ChaCha20 ciphertext blob and verify its SHA-256 plaintext digest.

    :param cipher_bytes:    Raw encrypted bytes read from ``storage/files/<stored_name>``.
    :param passphrase:      User-supplied decryption passphrase.
    :param kdf_salt_hex:    Hex salt stored in ``encrypted_files.kdf_salt``.
    :param nonce_hex:       Hex nonce stored in ``encrypted_files.nonce``.
    :param expected_sha256: Hex SHA-256 of the original file for integrity verification.
    :returns:               Original plaintext file bytes.
    :raises ValueError:     If the decrypted SHA-256 digest does not match ``expected_sha256``.
    """
    raise FileCryptoNotImplementedError(
        "Developer 2: implement decrypt_file_bytes() in modules/file_crypto.py"
    )
