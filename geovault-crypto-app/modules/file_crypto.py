"""
GeoVault - ChaCha20 File Byte-Stream Encryption
===============================================

High-speed symmetric stream encryption for binary documents (PDF, GeoJSON, KML,
archives, office files) using Daniel J. Bernstein's **ChaCha20** stream cipher:
  1. Generate a 16-byte CSPRNG salt (`kdf_salt`) and stream cipher `nonce`.
  2. Derive a 256-bit key from `passphrase` and `kdf_salt` via PBKDF2-HMAC-SHA256.
  3. Compute the plaintext SHA-256 digest (`sha256_plain`) prior to encryption.
  4. XOR the document byte stream with the ChaCha20 keystream (`Crypto.Cipher.ChaCha20`)
     and verify `SHA-256(decrypted_bytes) == expected_sha256` upon decryption.
"""

from __future__ import annotations

from dataclasses import dataclass

ALGORITHM_ID: str = "ChaCha20-Stream"


class FileCryptoNotImplementedError(NotImplementedError):
    """Raised when a ChaCha20 file stream routine has not been bound yet."""


@dataclass
class EncryptedFileBundle:
    """Output of :func:`encrypt_file_bytes`, aligned with ``encrypted_files`` schema columns."""

    ciphertext: bytes
    sha256_plain: str      # hex SHA-256 digest of original plaintext bytes
    kdf_salt: str          # hex-encoded 16-byte salt
    nonce: str             # hex-encoded ChaCha20 nonce
    algorithm: str = ALGORITHM_ID


def encrypt_file_bytes(plain_bytes: bytes, passphrase: str) -> EncryptedFileBundle:
    """
    Encrypt raw binary file bytes with a PBKDF2-derived ChaCha20 keystream.

    :param plain_bytes: Original binary content of the uploaded document.
    :param passphrase:  User-supplied encryption passphrase.
    :returns:           :class:`EncryptedFileBundle` containing ciphertext and KDF/nonce parameters.
    """
    raise FileCryptoNotImplementedError(
        "encrypt_file_bytes() is not yet bound in modules/file_crypto.py"
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

    :param cipher_bytes:    Raw encrypted bytes read from ``storage/files/<stored_name>``.
    :param passphrase:      User-supplied decryption passphrase.
    :param kdf_salt_hex:    Hex salt stored in ``encrypted_files.kdf_salt``.
    :param nonce_hex:       Hex nonce stored in ``encrypted_files.nonce``.
    :param expected_sha256: Hex SHA-256 of the original file for integrity verification.
    :returns:               Verified plaintext file bytes.
    :raises ValueError:     If the decrypted SHA-256 digest does not match ``expected_sha256``.
    """
    raise FileCryptoNotImplementedError(
        "decrypt_file_bytes() is not yet bound in modules/file_crypto.py"
    )
