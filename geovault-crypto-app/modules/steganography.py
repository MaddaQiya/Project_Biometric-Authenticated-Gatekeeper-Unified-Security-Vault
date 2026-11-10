"""
B.A.G.U.S. Vault - LSB PNG Image Steganography
==============================================

Spatial-domain Least Significant Bit (LSB) steganography on lossless PNG images (PIL):
  1. Each RGB pixel contributes 3 carrier bits (1 bit per R, G, B channel LSB):
       C'_ch = (C_ch & 0xFE) | b_k
  2. Embeds secret forensic payloads with terminal delimiter `<<<END>>>`.
  3. Optionally encrypts the secret message with a passphrase prior to LSB embedding.
  4. Encodes strictly as lossless PNG to guarantee pixel-exact extraction.
"""

from __future__ import annotations

import io
from typing import Optional

from Crypto.Cipher import ChaCha20
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from PIL import Image

DELIMITER: bytes = b"<<<END>>>"
RAW_PREFIX: bytes = b"RAW:"
ENC_PREFIX: bytes = b"ENC:"
KDF_ITERATIONS: int = 100_000
SALT_LEN: int = 16
NONCE_LEN: int = 12


AUTH_TAG: bytes = b"BAGUS_STEGO_OK::"


def _encrypt_payload(plaintext_bytes: bytes, passphrase: str) -> bytes:
    salt = get_random_bytes(SALT_LEN)
    nonce = get_random_bytes(NONCE_LEN)
    key = PBKDF2(passphrase, salt, dkLen=32, count=KDF_ITERATIONS, hmac_hash_module=SHA256)
    cipher = ChaCha20.new(key=key, nonce=nonce)
    ct = cipher.encrypt(AUTH_TAG + plaintext_bytes)
    return ENC_PREFIX + salt + nonce + ct


def _decrypt_payload(encrypted_body: bytes, passphrase: str) -> bytes:
    if len(encrypted_body) < SALT_LEN + NONCE_LEN:
        raise ValueError("Corrupted encrypted steganography payload: header too short.")
    salt = encrypted_body[:SALT_LEN]
    nonce = encrypted_body[SALT_LEN:SALT_LEN + NONCE_LEN]
    ct = encrypted_body[SALT_LEN + NONCE_LEN:]

    key = PBKDF2(passphrase, salt, dkLen=32, count=KDF_ITERATIONS, hmac_hash_module=SHA256)
    cipher = ChaCha20.new(key=key, nonce=nonce)
    plain = cipher.decrypt(ct)
    if not plain.startswith(AUTH_TAG):
        raise ValueError("Incorrect steganography passphrase or corrupted payload.")
    return plain[len(AUTH_TAG):]


def calculate_capacity(image_bytes: bytes) -> int:
    """
    Compute maximum UTF-8 payload size (in bytes) supported by ``image_bytes``.
    Formula: ``((width * height * 3) // 8) - delimiter_and_header_overhead``.
    """
    with Image.open(io.BytesIO(image_bytes)) as img:
        width, height = img.size
    total_carrier_bits = width * height * 3
    total_carrier_bytes = total_carrier_bits // 8
    overhead = len(DELIMITER) + len(ENC_PREFIX) + SALT_LEN + NONCE_LEN + 16
    return max(0, total_carrier_bytes - overhead)


def embed_message_lsb(
    cover_image_bytes: bytes,
    secret_message: str,
    passphrase: Optional[str] = None,
) -> bytes:
    """
    Embed ``secret_message`` into RGB least significant bits of ``cover_image_bytes``.
    Appends delimiter ``<<<END>>>`` and returns lossless PNG image bytes.
    """
    if not secret_message:
        raise ValueError("Secret message cannot be empty.")

    plain_bytes = secret_message.encode("utf-8")
    if passphrase and passphrase.strip():
        payload = _encrypt_payload(plain_bytes, passphrase.strip())
    else:
        payload = RAW_PREFIX + plain_bytes

    full_payload = payload + DELIMITER
    required_bits = len(full_payload) * 8

    # Open cover image and convert strictly to 24-bit RGB
    with Image.open(io.BytesIO(cover_image_bytes)) as raw_img:
        img = raw_img.convert("RGB")
        width, height = img.size

    total_carrier_bits = width * height * 3
    if required_bits > total_carrier_bits:
        raise ValueError(
            f"Payload exceeds image capacity! Required: {required_bits} bits "
            f"({len(full_payload)} bytes), but image can hold {total_carrier_bits} bits "
            f"({total_carrier_bits // 8} bytes). Use a larger cover image."
        )

    # Flatten bytes to bit stream
    bit_stream: list[int] = []
    for byte in full_payload:
        for i in range(7, -1, -1):
            bit_stream.append((byte >> i) & 1)

    pixels = list(img.getdata())
    new_pixels: list[tuple[int, int, int]] = []
    bit_idx = 0
    total_bits = len(bit_stream)

    for r, g, b in pixels:
        if bit_idx < total_bits:
            r = (r & 0xFE) | bit_stream[bit_idx]
            bit_idx += 1
        if bit_idx < total_bits:
            g = (g & 0xFE) | bit_stream[bit_idx]
            bit_idx += 1
        if bit_idx < total_bits:
            b = (b & 0xFE) | bit_stream[bit_idx]
            bit_idx += 1
        new_pixels.append((r, g, b))

    stego_img = Image.new("RGB", (width, height))
    stego_img.putdata(new_pixels)

    out_io = io.BytesIO()
    stego_img.save(out_io, format="PNG", optimize=False)
    return out_io.getvalue()


def extract_message_lsb(
    stego_image_bytes: bytes,
    passphrase: Optional[str] = None,
) -> str:
    """
    Extract and decode hidden payload from RGB LSBs until delimiter ``<<<END>>>``.
    """
    with Image.open(io.BytesIO(stego_image_bytes)) as raw_img:
        img = raw_img.convert("RGB")

    pixels = img.getdata()
    delim_len = len(DELIMITER)
    extracted_bytes = bytearray()
    curr_byte = 0
    bit_count = 0

    found_delim = False
    for r, g, b in pixels:
        for channel in (r, g, b):
            curr_byte = (curr_byte << 1) | (channel & 1)
            bit_count += 1
            if bit_count == 8:
                extracted_bytes.append(curr_byte)
                curr_byte = 0
                bit_count = 0
                if len(extracted_bytes) >= delim_len and extracted_bytes[-delim_len:] == DELIMITER:
                    found_delim = True
                    break
        if found_delim:
            break

    if not found_delim:
        raise ValueError(
            "No valid B.A.G.U.S. Vault steganographic payload detected (delimiter '<<<END>>>' not found)."
        )

    payload_body = bytes(extracted_bytes[:-delim_len])

    if payload_body.startswith(RAW_PREFIX):
        return payload_body[len(RAW_PREFIX):].decode("utf-8", errors="replace")

    if payload_body.startswith(ENC_PREFIX):
        if not passphrase or not passphrase.strip():
            raise ValueError("Steganography payload is password-protected. Provide decryption passphrase.")
        try:
            plain = _decrypt_payload(payload_body[len(ENC_PREFIX):], passphrase.strip())
            return plain.decode("utf-8", errors="replace")
        except Exception as exc:
            raise ValueError(f"Failed to decrypt hidden stego payload: {exc}") from exc

    # Fallback for plain un-prefixed payloads
    return payload_body.decode("utf-8", errors="replace")
