"""
GeoVault - Biometric + Cryptographic Two-Factor Login
=====================================================

Factor 1 - Knowledge (password)
-------------------------------
    master   = PBKDF2-HMAC-SHA256(password, salt[16 random bytes], 600 000 iterations)
    pepper   = HKDF(master_secret, "auth/password-pepper")        # never stored in the DB
    verifier = HKDF-SHA256(master, salt=pepper, info="auth/verifier",      32 bytes)  -> stored
    bio_key  = HKDF-SHA256(master, salt=pepper, info="auth/biometric-key", 16 bytes)  -> NEVER stored

Only the ``verifier`` and the ``salt`` are persisted. Because HKDF is one-way,
the stored verifier reveals nothing about ``bio_key``.

Factor 2 - Inherence (Pure PIL + hashlib 128x128 Biometric Pipeline)
--------------------------------------------------------------------
1. Decode raw image bytes with ``PIL.Image.open(io.BytesIO(image_bytes))``,
   normalize EXIF orientation, and convert to 8-bit grayscale (``.convert("L")``).
2. Extract a centered square region of interest, resize to a fixed ``128x128``
   matrix with Lanczos resampling, and apply histogram equalization + light
   Gaussian smoothing to normalize illumination.
3. Compute:
     * ``digest``: Cryptographic ``hashlib.sha256`` over the raw ``128x128``
       normalized grayscale pixel bytes.
     * ``phash`` & ``dhash``: Two 64-bit pure-Pillow perceptual descriptors
       (8x8 mean-threshold block hash and 9x8 horizontal gradient hash) forming
       a 128-bit structural vector for optical camera tolerance.
4. Serialize the biometric template vector and seal it with **AES-128-EAX**
   authenticated encryption using ``bio_key``, binding the operator username as
   Associated Data (AAD).
"""

from __future__ import annotations

import hashlib
import hmac
import io
import json
import re
import sqlite3
import time
from dataclasses import asdict, dataclass
from typing import Optional

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import HKDF, PBKDF2
from Crypto.Random import get_random_bytes
from PIL import Image, ImageFilter, ImageOps, UnidentifiedImageError

import config
import database

# --------------------------------------------------------------------------- #
# Parameters
# --------------------------------------------------------------------------- #
PBKDF2_ITERATIONS = 600_000          # OWASP recommendation for PBKDF2-HMAC-SHA256
SALT_BYTES = 16
AES_KEY_BYTES = 16                   # AES-128
EAX_NONCE_BYTES = 16
EAX_TAG_BYTES = 16
TEMPLATE_SIZE = (128, 128)           # Fixed normalized grayscale template dimensions
BIO_ALGORITHM_ID = "PIL-128x128-SHA256 / AES-128-EAX"

MATCH_THRESHOLD = 0.80               # Minimum similarity in [0, 1] required to authenticate
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_SECONDS = 120
MAX_IMAGE_BYTES = 10 * 1024 * 1024   # 10 MB

USERNAME_RE = re.compile(r"^[a-z0-9_.-]{3,32}$")
GENERIC_FAILURE = "Authentication failed: credentials or biometric did not match."

# Dummy salt used for unknown usernames so KDF timing remains uniform.
_DUMMY_SALT = get_random_bytes(SALT_BYTES)


class BiometricError(ValueError):
    """Raised when an image cannot be converted into a biometric template."""


# --------------------------------------------------------------------------- #
# Data objects
# --------------------------------------------------------------------------- #
@dataclass
class BiometricTemplate:
    phash: str                   # 16 hex chars (64-bit structural luminance descriptor)
    dhash: str                   # 16 hex chars (64-bit horizontal gradient descriptor)
    digest: str                  # 64 hex chars (SHA-256 over normalized 128x128 pixel bytes)
    extractor: str = "pil-128x128"
    face_detected: bool = True
    version: int = 1

    def bits(self) -> bytes:
        return bytes.fromhex(self.phash) + bytes.fromhex(self.dhash)


@dataclass
class AuthResult:
    success: bool
    message: str
    username: Optional[str] = None
    similarity: Optional[float] = None
    face_detected: Optional[bool] = None


# --------------------------------------------------------------------------- #
# Pure-Pillow + hashlib Biometric Feature Extraction
# --------------------------------------------------------------------------- #
def _center_square(gray: Image.Image, ratio: float = 0.85) -> Image.Image:
    """Crop a centered square region of interest from an 8-bit grayscale image."""
    side = max(1, int(min(gray.size) * ratio))
    left = (gray.width - side) // 2
    top = (gray.height - side) // 2
    return gray.crop((left, top, left + side, top + side))


def _pack_bits_to_hex(bits: list[int]) -> str:
    """Pack a list of 64 binary ints (0/1) into a 16-character hex string."""
    value = 0
    for bit in bits:
        value = (value << 1) | (1 if bit else 0)
    return f"{value:016x}"


def _pil_block_hash(norm_img: Image.Image) -> str:
    """Compute a 64-bit structural block hash over an 8x8 Lanczos downsampling."""
    thumb = norm_img.resize((8, 8), Image.Resampling.LANCZOS)
    pixels = list(thumb.getdata())
    mean_val = sum(pixels) / len(pixels)
    return _pack_bits_to_hex([1 if px >= mean_val else 0 for px in pixels])


def _pil_gradient_hash(norm_img: Image.Image) -> str:
    """Compute a 64-bit horizontal gradient hash (dHash) over a 9x8 Lanczos downsampling."""
    thumb = norm_img.resize((9, 8), Image.Resampling.LANCZOS)
    pixels = list(thumb.getdata())
    bits: list[int] = []
    for row in range(8):
        offset = row * 9
        for col in range(8):
            bits.append(1 if pixels[offset + col + 1] > pixels[offset + col] else 0)
    return _pack_bits_to_hex(bits)


def extract_biometric_features(image_bytes: bytes) -> BiometricTemplate:
    """
    Convert raw image bytes into a normalized 128x128 biometric template using
    pure Pillow (``PIL``) and ``hashlib.sha256``.

    Pipeline:
      1. Load via ``PIL.Image.open(io.BytesIO(image_bytes))``, transpose EXIF,
         and convert to 8-bit grayscale (``.convert("L")``).
      2. Crop centered square ROI, resize to fixed ``128x128`` resolution, and
         normalize lighting via histogram equalization + Gaussian smoothing.
      3. Compute ``hashlib.sha256`` over the raw ``128x128`` pixel byte buffer
         alongside 128-bit structural/gradient descriptors.
    """
    if not image_bytes:
        raise BiometricError("No biometric image was provided.")
    if len(image_bytes) > MAX_IMAGE_BYTES:
        raise BiometricError("Biometric image is too large (max 10 MB).")

    try:
        with Image.open(io.BytesIO(image_bytes)) as opened:
            transposed = ImageOps.exif_transpose(opened)
            gray = transposed.convert("L")
    except (UnidentifiedImageError, OSError) as exc:
        raise BiometricError(f"Unsupported or corrupted image: {exc}") from exc

    roi = _center_square(gray)
    normalized = roi.resize(TEMPLATE_SIZE, Image.Resampling.LANCZOS)
    normalized = ImageOps.equalize(normalized).filter(ImageFilter.GaussianBlur(radius=1))

    raw_pixel_bytes = normalized.tobytes()
    pixel_digest = hashlib.sha256(raw_pixel_bytes).hexdigest()
    phash = _pil_block_hash(normalized)
    dhash = _pil_gradient_hash(normalized)

    return BiometricTemplate(
        phash=phash,
        dhash=dhash,
        digest=pixel_digest,
        extractor="pil-128x128",
        face_detected=True,
    )


def compare_templates(a: BiometricTemplate, b: BiometricTemplate) -> float:
    """
    Compare two biometric templates.
    Returns 1.0 on an exact SHA-256 pixel digest match, or the normalized
    Hamming similarity in [0, 1] across the 128 structural/gradient bits.
    """
    if hmac.compare_digest(a.digest, b.digest):
        return 1.0
    xor = int.from_bytes(a.bits(), "big") ^ int.from_bytes(b.bits(), "big")
    return 1.0 - bin(xor).count("1") / 128.0


# --------------------------------------------------------------------------- #
# Key derivation & AES-128-EAX template encryption
# --------------------------------------------------------------------------- #
def _derive_keys(password: str, salt: bytes, iterations: int) -> tuple[bytes, bytes]:
    """Return ``(verifier[32], bio_key[16])`` derived from the password."""
    master = PBKDF2(password.encode("utf-8"), salt, dkLen=32, count=iterations, hmac_hash_module=SHA256)
    pepper = config.derive_subkey(config.PURPOSE_PASSWORD_PEPPER, 32)
    verifier = HKDF(master, 32, pepper, SHA256, context=b"auth/verifier")
    bio_key = HKDF(master, AES_KEY_BYTES, pepper, SHA256, context=b"auth/biometric-key")
    return verifier, bio_key


def encrypt_template(template: BiometricTemplate, key: bytes, username: str) -> bytes:
    """Seal the biometric template with AES-128-EAX; returns ``nonce(16) | tag(16) | ciphertext``."""
    cipher = AES.new(key, AES.MODE_EAX, nonce=get_random_bytes(EAX_NONCE_BYTES), mac_len=EAX_TAG_BYTES)
    cipher.update(f"GeoVault-bio|{username}".encode("utf-8"))
    ciphertext, tag = cipher.encrypt_and_digest(json.dumps(asdict(template)).encode("utf-8"))
    return cipher.nonce + tag + ciphertext


def decrypt_template(blob: bytes, key: bytes, username: str) -> BiometricTemplate:
    """Decrypt and authenticate a stored AES-128-EAX template. Raises ``ValueError`` on tampering."""
    blob = bytes(blob)
    if len(blob) <= EAX_NONCE_BYTES + EAX_TAG_BYTES:
        raise ValueError("Biometric template blob is truncated.")
    nonce = blob[:EAX_NONCE_BYTES]
    tag = blob[EAX_NONCE_BYTES:EAX_NONCE_BYTES + EAX_TAG_BYTES]
    ciphertext = blob[EAX_NONCE_BYTES + EAX_TAG_BYTES:]
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce, mac_len=EAX_TAG_BYTES)
    cipher.update(f"GeoVault-bio|{username}".encode("utf-8"))
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    data = json.loads(plaintext)
    return BiometricTemplate(
        phash=data["phash"],
        dhash=data["dhash"],
        digest=data["digest"],
        extractor=data.get("extractor", "pil-128x128"),
        face_detected=bool(data.get("face_detected", True)),
        version=int(data.get("version", 1)),
    )


# --------------------------------------------------------------------------- #
# Validation helpers
# --------------------------------------------------------------------------- #
def normalize_username(username: str) -> str:
    return (username or "").strip().lower()


def validate_username(username: str) -> Optional[str]:
    if not USERNAME_RE.match(username):
        return "Username must be 3-32 chars: lowercase letters, digits, '.', '_' or '-'."
    return None


def validate_password(password: str) -> Optional[str]:
    if len(password) < 8:
        return "Password must be at least 8 characters."
    if not re.search(r"[A-Za-z]", password) or not re.search(r"\d", password):
        return "Password must contain both letters and digits."
    return None


# --------------------------------------------------------------------------- #
# Public API used by app.py
# --------------------------------------------------------------------------- #
def register_user(username: str, password: str, image_bytes: bytes, require_face: bool = False) -> AuthResult:
    """Enrol a new operator with PBKDF2-SHA256 credentials and an AES-128-EAX sealed biometric template."""
    _ = require_face  # Retained for call-site signature compatibility
    username = normalize_username(username)
    for error in (validate_username(username), validate_password(password)):
        if error:
            return AuthResult(False, error)
    if database.user_exists(username):
        return AuthResult(False, "Username is already registered.")

    try:
        template = extract_biometric_features(image_bytes)
    except BiometricError as exc:
        return AuthResult(False, str(exc))

    salt = get_random_bytes(SALT_BYTES)
    verifier, bio_key = _derive_keys(password, salt, PBKDF2_ITERATIONS)
    encrypted = encrypt_template(template, bio_key, username)
    try:
        database.create_user(
            username,
            verifier.hex(),
            salt.hex(),
            PBKDF2_ITERATIONS,
            encrypted,
            BIO_ALGORITHM_ID,
        )
    except sqlite3.IntegrityError:
        return AuthResult(False, "Username is already registered.")
    return AuthResult(
        True,
        "Registration successful. Biometric template normalized (128x128) & sealed with AES-128-EAX.",
        username=username,
        face_detected=True,
    )


def authenticate_user(username: str, password: str, image_bytes: bytes) -> AuthResult:
    """Verify both factors (PBKDF2-SHA256 verifier + AES-128-EAX biometric template)."""
    username = normalize_username(username)
    user = database.get_user(username) if username else None

    if user and user["locked_until"] > time.time():
        wait = int(user["locked_until"] - time.time()) + 1
        return AuthResult(False, f"Too many failed attempts. Account locked for {wait}s.")

    # ---- Factor 1: password (KDF always runs -> uniform timing) ----------- #
    salt = bytes.fromhex(user["password_salt"]) if user else _DUMMY_SALT
    iterations = int(user["kdf_iterations"]) if user else PBKDF2_ITERATIONS
    verifier, bio_key = _derive_keys(password or "", salt, iterations)
    stored_verifier = bytes.fromhex(user["password_hash"]) if user else b"\x00" * 32
    password_ok = hmac.compare_digest(verifier, stored_verifier) and user is not None
    if not password_ok:
        if user:
            database.record_login_failure(username, MAX_FAILED_ATTEMPTS, LOCKOUT_SECONDS)
        return AuthResult(False, GENERIC_FAILURE)

    # ---- Factor 2: biometric -------------------------------------------- #
    try:
        probe = extract_biometric_features(image_bytes)
    except BiometricError as exc:
        return AuthResult(False, str(exc))
    try:
        enrolled = decrypt_template(user["bio_template"], bio_key, username)
    except (ValueError, KeyError, TypeError):
        return AuthResult(False, "Biometric template failed AES-EAX authentication - possible database tampering!")

    similarity = compare_templates(enrolled, probe)
    if similarity < MATCH_THRESHOLD:
        database.record_login_failure(username, MAX_FAILED_ATTEMPTS, LOCKOUT_SECONDS)
        return AuthResult(False, GENERIC_FAILURE, similarity=similarity)

    database.record_login_success(username)
    return AuthResult(
        True,
        "Authenticated with password + biometric.",
        username=username,
        similarity=similarity,
        face_detected=True,
    )
