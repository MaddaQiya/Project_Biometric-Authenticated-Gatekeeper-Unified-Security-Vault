"""
B.A.G.U.S. Vault - Text Super Encryption (Vigenere + AES-256-CBC)
================================================================

Two-layer cascade encryption pipeline for classified intelligence dispatches:
  1. Classical polyalphabetic substitution layer:
     Extended Vigenère cipher over UTF-8 byte stream (modulo 256):
       C_i = (P_i + K_{i mod |K|}) mod 256
       P_i = (C_i - K_{i mod |K|}) mod 256
  2. Modern symmetric block cipher layer:
     AES-256 in Cipher Block Chaining (CBC) mode with PKCS#7 block padding,
     a fresh 16-byte CSPRNG initialization vector (IV), and a 256-bit key
     derived from the passphrase and a 16-byte salt via PBKDF2-HMAC-SHA256.
"""

from __future__ import annotations

import base64
import json
from typing import Any

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

ALGORITHM_ID: str = "Vigenere + AES-256-CBC"
KDF_ITERATIONS: int = 100_000
SALT_BYTES: int = 16
IV_BYTES: int = 16


def _vigenere_core_bytes(data: bytes, key: bytes, encrypt: bool) -> bytes:
    """Apply polyalphabetic addition/subtraction modulo 256 over raw bytes."""
    if not key:
        raise ValueError("Vigenère keyword must not be empty.")
    key_len = len(key)
    out = bytearray(len(data))
    for i, byte in enumerate(data):
        k = key[i % key_len]
        out[i] = (byte + k) % 256 if encrypt else (byte - k) % 256
    return bytes(out)


def vigenere_encrypt(plaintext: str, key: str) -> str:
    """
    Apply polyalphabetic Vigenère substitution to ``plaintext`` using ``key``.
    Returns Base64-encoded intermediate ciphertext.
    """
    plain_bytes = plaintext.encode("utf-8")
    key_bytes = key.encode("utf-8")
    v_bytes = _vigenere_core_bytes(plain_bytes, key_bytes, encrypt=True)
    return base64.b64encode(v_bytes).decode("ascii")


def vigenere_decrypt(ciphertext_b64: str, key: str) -> str:
    """
    Invert polyalphabetic Vigenère substitution on Base64-encoded ``ciphertext_b64`` using ``key``.
    Returns original UTF-8 plaintext.
    """
    try:
        v_bytes = base64.b64decode(ciphertext_b64.encode("ascii"))
    except Exception as exc:
        raise ValueError(f"Invalid Base64 Vigenère ciphertext: {exc}") from exc
    key_bytes = key.encode("utf-8")
    plain_bytes = _vigenere_core_bytes(v_bytes, key_bytes, encrypt=False)
    return plain_bytes.decode("utf-8", errors="replace")


def super_encrypt_detailed(plaintext: str, vigenere_key: str, aes_passphrase: str) -> dict[str, Any]:
    """
    Execute the cascade encryption pipeline and return intermediate telemetry for HUD preview:
      Plaintext -> [Step 1: Vigenère] -> [Step 2: PKCS#7 Pad + AES-256-CBC] -> Token
    """
    if not plaintext:
        raise ValueError("Plaintext content cannot be empty.")
    if not vigenere_key:
        raise ValueError("Vigenère key cannot be empty.")
    if not aes_passphrase:
        raise ValueError("AES-256 passphrase cannot be empty.")

    # Step 1: Classical Vigenère substitution (byte-level modulo 256)
    plain_bytes = plaintext.encode("utf-8")
    v_bytes = _vigenere_core_bytes(plain_bytes, vigenere_key.encode("utf-8"), encrypt=True)
    vigenere_b64 = base64.b64encode(v_bytes).decode("ascii")
    vigenere_hex = v_bytes.hex()

    # Step 2: Modern AES-256-CBC with PBKDF2-HMAC-SHA256 key derivation
    salt = get_random_bytes(SALT_BYTES)
    iv = get_random_bytes(IV_BYTES)
    aes_key = PBKDF2(
        aes_passphrase,
        salt,
        dkLen=32,
        count=KDF_ITERATIONS,
        hmac_hash_module=SHA256,
    )
    cipher = AES.new(aes_key, AES.MODE_CBC, iv=iv)
    padded = pad(v_bytes, AES.block_size, style="pkcs7")
    aes_ct = cipher.encrypt(padded)

    envelope = {
        "v": 1,
        "algo": ALGORITHM_ID,
        "salt": salt.hex(),
        "iv": iv.hex(),
        "ct": aes_ct.hex(),
    }
    raw_json = json.dumps(envelope, separators=(",", ":")).encode("utf-8")
    token = base64.b64encode(raw_json).decode("ascii")

    return {
        "vigenere_b64": vigenere_b64,
        "vigenere_hex": vigenere_hex,
        "salt_hex": salt.hex(),
        "iv_hex": iv.hex(),
        "aes_ciphertext_hex": aes_ct.hex(),
        "token": token,
    }


def super_encrypt(plaintext: str, vigenere_key: str, aes_passphrase: str) -> str:
    """Execute cascade encryption pipeline returning the self-contained Base64 token."""
    res = super_encrypt_detailed(plaintext, vigenere_key, aes_passphrase)
    return res["token"]


def super_decrypt_detailed(token: str, vigenere_key: str, aes_passphrase: str) -> dict[str, Any]:
    """
    Execute cascade decryption pipeline with intermediate telemetry:
      Token -> [Step 1: AES-256-CBC Unseal] -> [Step 2: Reverse Vigenère] -> Plaintext
    """
    if not token:
        raise ValueError("Ciphertext token cannot be empty.")
    if not vigenere_key:
        raise ValueError("Vigenère key cannot be empty.")
    if not aes_passphrase:
        raise ValueError("AES-256 passphrase cannot be empty.")

    try:
        raw_json = base64.b64decode(token.strip().encode("ascii")).decode("utf-8")
        envelope = json.loads(raw_json)
        salt = bytes.fromhex(envelope["salt"])
        iv = bytes.fromhex(envelope["iv"])
        aes_ct = bytes.fromhex(envelope["ct"])
    except Exception as exc:
        raise ValueError(f"Malformed super-encryption token envelope: {exc}") from exc

    aes_key = PBKDF2(
        aes_passphrase,
        salt,
        dkLen=32,
        count=KDF_ITERATIONS,
        hmac_hash_module=SHA256,
    )
    cipher = AES.new(aes_key, AES.MODE_CBC, iv=iv)
    try:
        padded = cipher.decrypt(aes_ct)
        v_bytes = unpad(padded, AES.block_size, style="pkcs7")
    except (ValueError, KeyError) as exc:
        raise ValueError("AES-256-CBC decryption failed: incorrect passphrase or corrupted ciphertext.") from exc

    plain_bytes = _vigenere_core_bytes(v_bytes, vigenere_key.encode("utf-8"), encrypt=False)
    plaintext = plain_bytes.decode("utf-8", errors="replace")

    return {
        "vigenere_b64": base64.b64encode(v_bytes).decode("ascii"),
        "vigenere_hex": v_bytes.hex(),
        "plaintext": plaintext,
    }


def super_decrypt(token: str, vigenere_key: str, aes_passphrase: str) -> str:
    """Execute cascade decryption pipeline returning the verified UTF-8 plaintext."""
    res = super_decrypt_detailed(token, vigenere_key, aes_passphrase)
    return res["plaintext"]
