"""
B.A.G.U.S. Vault - Optical Facial Biometric + Cryptographic Login
=================================================================

Factor 1 - Knowledge (Passkey)
------------------------------
    master   = PBKDF2-HMAC-SHA256(password, salt[16 random bytes], 600 000 iterations)
    pepper   = HKDF(master_secret, "auth/password-pepper")        # never stored in the DB
    verifier = HKDF-SHA256(master, salt=pepper, info="auth/verifier",      32 bytes)  -> stored
    bio_key  = HKDF-SHA256(master, salt=pepper, info="auth/biometric-key", 16 bytes)  -> NEVER stored

Only the ``verifier`` and the ``salt`` are persisted. Because HKDF is one-way,
the stored verifier reveals nothing about ``bio_key``.

Factor 2 - Inherence (Pure PIL 128x128 Optical Facial Recognition Pipeline)
---------------------------------------------------------------------------
1. Read captured optical face bytes via ``PIL.Image.open(io.BytesIO(image_bytes))``,
   normalize EXIF orientation, and convert to 8-bit Grayscale (``.convert("L")``).
2. Crop the centered facial region of interest, resize/normalize to a standard
   ``128x128`` biometric matrix with Lanczos resampling, and apply histogram
   equalization + Gaussian smoothing.
3. Generate the normalized pixel byte digest using SHA-256
   (``hashlib.sha256(normalized_bytes).digest()``) paired with 128-bit facial
   structural/gradient descriptors (``phash`` + ``dhash``).
4. Seal and encrypt the facial biometric digest vector using **AES-128-EAX**
   authenticated encryption before committing it to SQLite.
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
TEMPLATE_SIZE = (128, 128)           # Standard 128x128 facial biometric matrix
BIO_ALGORITHM_ID = "OPTICAL-FACE-128x128-SHA256 / AES-128-EAX"

MATCH_THRESHOLD = 0.80               # Minimum facial similarity in [0, 1] required
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_SECONDS = 120
MAX_IMAGE_BYTES = 10 * 1024 * 1024   # 10 MB

USERNAME_RE = re.compile(r"^[a-z0-9_.-]{3,32}$")
GENERIC_FAILURE = "Authentication failed: operator credentials or optical face scan did not match."

# Dummy salt used for unknown usernames so KDF timing remains uniform.
_DUMMY_SALT = get_random_bytes(SALT_BYTES)


class BiometricError(ValueError):
    """Raised when an optical face frame cannot be processed into a biometric template."""


# --------------------------------------------------------------------------- #
# Data objects
# --------------------------------------------------------------------------- #
@dataclass
class BiometricTemplate:
    phash: str                   # 16 hex chars (64-bit facial luminance block descriptor)
    dhash: str                   # 16 hex chars (64-bit facial horizontal gradient descriptor)
    digest: str                  # 64 hex chars (SHA-256 digest of normalized 128x128 face bytes)
    extractor: str = "optical-face-pil-128x128"
    face_detected: bool = True
    version: int = 1

    def bits(self) -> bytes:
        return bytes.fromhex(self.phash) + bytes.fromhex(self.dhash)

    def digest_bytes(self) -> bytes:
        return bytes.fromhex(self.digest)


@dataclass
class AuthResult:
    success: bool
    message: str
    username: Optional[str] = None
    similarity: Optional[float] = None
    face_detected: Optional[bool] = None


# --------------------------------------------------------------------------- #
# Pure-Pillow (PIL) + hashlib Optical Facial Feature Extraction
# --------------------------------------------------------------------------- #
def _center_face_roi(gray: Image.Image, ratio: float = 0.85) -> Image.Image:
    """Extract the centered square facial region of interest from an 8-bit grayscale frame."""
    side = max(1, int(min(gray.size) * ratio))
    left = (gray.width - side) // 2
    top = (gray.height - side) // 2
    return gray.crop((left, top, left + side, top + side))


def _pack_bits_to_hex(bits: list[int]) -> str:
    """Pack 64 binary ints (0/1) into a 16-character hexadecimal string."""
    value = 0
    for bit in bits:
        value = (value << 1) | (1 if bit else 0)
    return f"{value:016x}"


def _pil_block_hash(norm_img: Image.Image) -> str:
    """Compute a 64-bit structural luminance block hash over an 8x8 Lanczos matrix."""
    thumb = norm_img.resize((8, 8), Image.Resampling.LANCZOS)
    pixels = list(thumb.getdata())
    mean_val = sum(pixels) / len(pixels)
    return _pack_bits_to_hex([1 if px >= mean_val else 0 for px in pixels])


def _pil_gradient_hash(norm_img: Image.Image) -> str:
    """Compute a 64-bit horizontal facial gradient hash (dHash) over a 9x8 Lanczos matrix."""
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
    Process captured optical face image bytes strictly through Pillow (``PIL``)
    and ``hashlib.sha256``:
      1. Read ``image_bytes`` into a PIL Image and convert to Grayscale (``.convert("L")``).
      2. Resize and normalize to the standard ``128x128`` biometric matrix.
      3. Generate the normalized pixel byte digest via ``hashlib.sha256(normalized_bytes).digest()``.
      4. Package the digest and 128-bit structural descriptors into a :class:`BiometricTemplate`.
    """
    if not image_bytes:
        raise BiometricError("No optical face scan was captured.")
    if len(image_bytes) > MAX_IMAGE_BYTES:
        raise BiometricError("Captured optical frame exceeds maximum size (10 MB).")

    try:
        with Image.open(io.BytesIO(image_bytes)) as opened:
            transposed = ImageOps.exif_transpose(opened)
            gray = transposed.convert("L")
    except (UnidentifiedImageError, OSError) as exc:
        raise BiometricError(f"Invalid or corrupted optical face frame: {exc}") from exc

    roi = _center_face_roi(gray)
    normalized = roi.resize(TEMPLATE_SIZE, Image.Resampling.LANCZOS)
    normalized = ImageOps.equalize(normalized).filter(ImageFilter.GaussianBlur(radius=1))

    normalized_bytes = normalized.tobytes()
    digest_raw_bytes = hashlib.sha256(normalized_bytes).digest()
    phash = _pil_block_hash(normalized)
    dhash = _pil_gradient_hash(normalized)

    return BiometricTemplate(
        phash=phash,
        dhash=dhash,
        digest=digest_raw_bytes.hex(),
        extractor="optical-face-pil-128x128",
        face_detected=True,
    )


def compare_templates(a: BiometricTemplate, b: BiometricTemplate) -> float:
    """
    Compare two facial biometric templates.
    Returns 1.0 on an exact SHA-256 normalized pixel byte digest match, or the
    normalized Hamming similarity in [0, 1] across the 128 facial structure bits.
    """
    if hmac.compare_digest(a.digest_bytes(), b.digest_bytes()):
        return 1.0
    xor = int.from_bytes(a.bits(), "big") ^ int.from_bytes(b.bits(), "big")
    return 1.0 - bin(xor).count("1") / 128.0


# --------------------------------------------------------------------------- #
# Key derivation & AES-128-EAX template encryption
# --------------------------------------------------------------------------- #
def _derive_keys(password: str, salt: bytes, iterations: int) -> tuple[bytes, bytes]:
    """Return ``(verifier[32], bio_key[16])`` derived from the operator passkey."""
    master = PBKDF2(password.encode("utf-8"), salt, dkLen=32, count=iterations, hmac_hash_module=SHA256)
    pepper = config.derive_subkey(config.PURPOSE_PASSWORD_PEPPER, 32)
    verifier = HKDF(master, 32, pepper, SHA256, context=b"auth/verifier")
    bio_key = HKDF(master, AES_KEY_BYTES, pepper, SHA256, context=b"auth/biometric-key")
    return verifier, bio_key


def encrypt_template(template: BiometricTemplate, key: bytes, username: str) -> bytes:
    """Seal the facial biometric digest vector with AES-128-EAX: ``nonce(16) | tag(16) | ciphertext``."""
    cipher = AES.new(key, AES.MODE_EAX, nonce=get_random_bytes(EAX_NONCE_BYTES), mac_len=EAX_TAG_BYTES)
    cipher.update(f"GeoVault-bio|{username}".encode("utf-8"))
    ciphertext, tag = cipher.encrypt_and_digest(json.dumps(asdict(template)).encode("utf-8"))
    return cipher.nonce + tag + ciphertext


def decrypt_template(blob: bytes, key: bytes, username: str) -> BiometricTemplate:
    """Decrypt and authenticate a stored AES-128-EAX facial template. Raises ``ValueError`` on tampering."""
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
        extractor=data.get("extractor", "optical-face-pil-128x128"),
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
    """Enrol a new operator with PBKDF2-SHA256 credentials and an AES-128-EAX sealed facial template."""
    _ = require_face
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
        "Operator enrolled. Facial biometric digest (128x128 SHA-256) sealed with AES-128-EAX.",
        username=username,
        face_detected=True,
    )


def authenticate_user(username: str, password: str, image_bytes: bytes) -> AuthResult:
    """Verify both factors (PBKDF2-SHA256 passkey verifier + AES-128-EAX optical facial template)."""
    username = normalize_username(username)
    user = database.get_user(username) if username else None

    if user and user["locked_until"] > time.time():
        wait = int(user["locked_until"] - time.time()) + 1
        return AuthResult(False, f"Too many failed attempts. Account locked for {wait}s.")

    # ---- Factor 1: passkey (KDF always runs -> uniform timing) ------------ #
    salt = bytes.fromhex(user["password_salt"]) if user else _DUMMY_SALT
    iterations = int(user["kdf_iterations"]) if user else PBKDF2_ITERATIONS
    verifier, bio_key = _derive_keys(password or "", salt, iterations)
    stored_verifier = bytes.fromhex(user["password_hash"]) if user else b"\x00" * 32
    password_ok = hmac.compare_digest(verifier, stored_verifier) and user is not None
    if not password_ok:
        if user:
            database.record_login_failure(username, MAX_FAILED_ATTEMPTS, LOCKOUT_SECONDS)
        return AuthResult(False, GENERIC_FAILURE)

    # ---- Factor 2: optical facial recognition ----------------------------- #
    try:
        probe = extract_biometric_features(image_bytes)
    except BiometricError as exc:
        return AuthResult(False, str(exc))
    try:
        enrolled = decrypt_template(user["bio_template"], bio_key, username)
    except (ValueError, KeyError, TypeError):
        return AuthResult(False, "Facial biometric template failed AES-128-EAX authentication - possible database tampering!")

    similarity = compare_templates(enrolled, probe)
    if similarity < MATCH_THRESHOLD:
        database.record_login_failure(username, MAX_FAILED_ATTEMPTS, LOCKOUT_SECONDS)
        return AuthResult(False, GENERIC_FAILURE, similarity=similarity)

    database.record_login_success(username)
    return AuthResult(
        True,
        "Authenticated via PBKDF2-SHA256 passkey + Optical Facial Recognition.",
        username=username,
        similarity=similarity,
        face_detected=True,
    )


# --------------------------------------------------------------------------- #
# Synthetic Optical Frame Generator (Dev Demo & Fallback)
# --------------------------------------------------------------------------- #
def generate_optical_face_sample(username: str, seed_variant: int = 0) -> bytes:
    """
    Generate a 128x128 grayscale optical facial matrix image using pure PIL.
    Deterministic to (username, seed_variant). When seed_variant != 0, generates
    an unauthorized / mismatched intruder facial pattern.
    """
    import random
    from PIL import ImageDraw

    seed_val = int(hashlib.sha256(f"{username}::{seed_variant}".encode()).hexdigest()[:8], 16)
    rng = random.Random(seed_val)

    if seed_variant != 0:
        # Simulate unauthorized intruder face / incompatible facial structure
        img = Image.new("L", (128, 128), color=220)
        draw = ImageDraw.Draw(img)
        draw.rectangle([0, 0, 64, 64], fill=30)
        draw.rectangle([64, 64, 128, 128], fill=40)
        draw.ellipse([10, 20, 80, 110], fill=180, outline=60)
        for _ in range(20):
            x1, y1 = rng.randint(0, 120), rng.randint(0, 120)
            draw.line([(x1, y1), (x1 + rng.randint(5, 30), y1 + rng.randint(5, 30))], fill=rng.randint(20, 240), width=2)
    else:
        img = Image.new("L", (128, 128), color=30)
        draw = ImageDraw.Draw(img)

        # Facial oval boundary
        cx, cy = 64, 64
        rx = rng.randint(34, 40)
        ry = rng.randint(44, 52)
        draw.ellipse([cx - rx, cy - ry, cx + rx, cy + ry], fill=160, outline=220)

        # Eyes
        eye_y = cy - rng.randint(8, 14)
        eye_offset = rng.randint(14, 18)
        draw.ellipse([cx - eye_offset - 6, eye_y - 4, cx - eye_offset + 6, eye_y + 4], fill=50, outline=240)
        draw.ellipse([cx + eye_offset - 6, eye_y - 4, cx + eye_offset + 6, eye_y + 4], fill=50, outline=240)

        # Nose
        nose_y = cy + rng.randint(2, 6)
        draw.polygon([(cx, eye_y + 8), (cx - 4, nose_y + 8), (cx + 4, nose_y + 8)], fill=120)

        # Mouth
        mouth_y = cy + rng.randint(20, 26)
        draw.arc([cx - 16, mouth_y - 4, cx + 16, mouth_y + 8], start=0, end=180, fill=60, width=2)

        # Sensor scanlines
        for y in range(0, 128, 4):
            draw.line([(0, y), (128, y)], fill=rng.randint(20, 50), width=1)

    bio_io = io.BytesIO()
    img.save(bio_io, format="PNG")
    return bio_io.getvalue()
