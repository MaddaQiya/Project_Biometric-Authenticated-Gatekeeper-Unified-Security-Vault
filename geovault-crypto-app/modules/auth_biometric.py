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

Factor 2 - Inherence (face / fingerprint image)
-----------------------------------------------
1. Decode the image (Pillow), honour EXIF orientation, convert to grayscale.
2. Locate the face with OpenCV's Haar cascade (if OpenCV is installed);
   otherwise use a centred square crop (also used for fingerprint uploads).
3. Histogram-equalise + light Gaussian blur to normalise lighting/noise.
4. Compute two 64-bit perceptual hashes -> a 128-bit biometric template:
     * pHash - DCT-II of a 32x32 thumbnail, low-frequency 8x8 block vs. median
     * dHash - horizontal gradient signs of a 9x8 thumbnail
5. A SHA-256 cryptographic digest of the template bytes is kept inside the
   payload as a fingerprint of the enrolment.

The template is serialised to JSON and encrypted with **AES-128 in EAX mode**
(authenticated encryption) using ``bio_key``; the username is bound as
associated data, so swapping templates between rows is detected.

Camera captures are never bit-identical, so matching uses the normalised
Hamming similarity of the perceptual hashes against ``MATCH_THRESHOLD``.

.. note::
   Perceptual hashing is a lightweight, explainable stand-in for a real face
   recognition model (e.g. FaceNet embeddings). It is adequate for an academic
   demo but is *not* liveness-proof or spoof-resistant.
"""

from __future__ import annotations

import hmac
import io
import json
import re
import sqlite3
import time
from dataclasses import asdict, dataclass
from typing import Optional

import numpy as np
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import HKDF, PBKDF2
from Crypto.Random import get_random_bytes
from PIL import Image, ImageFilter, ImageOps, UnidentifiedImageError

import config
import database

try:  # OpenCV is optional: we degrade gracefully to a Pillow-only pipeline.
    import cv2  # type: ignore

    OPENCV_AVAILABLE = True
except ImportError:  # pragma: no cover
    cv2 = None  # type: ignore
    OPENCV_AVAILABLE = False

# --------------------------------------------------------------------------- #
# Parameters
# --------------------------------------------------------------------------- #
PBKDF2_ITERATIONS = 600_000          # OWASP 2023 recommendation for PBKDF2-HMAC-SHA256
SALT_BYTES = 16
AES_KEY_BYTES = 16                   # AES-128
EAX_NONCE_BYTES = 16
EAX_TAG_BYTES = 16
BIO_ALGORITHM_ID = "pHash+dHash-128 / AES-128-EAX"

MATCH_THRESHOLD = 0.80               # min. similarity (1 - hamming/128) to accept
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_SECONDS = 120
MAX_IMAGE_BYTES = 10 * 1024 * 1024   # 10 MB

USERNAME_RE = re.compile(r"^[a-z0-9_.-]{3,32}$")
GENERIC_FAILURE = "Authentication failed: credentials or biometric did not match."

# Dummy salt used for unknown usernames so the response time does not reveal
# whether an account exists (user-enumeration hardening).
_DUMMY_SALT = get_random_bytes(SALT_BYTES)


class BiometricError(ValueError):
    """Raised when an image cannot be turned into a biometric template."""


# --------------------------------------------------------------------------- #
# Data objects
# --------------------------------------------------------------------------- #
@dataclass
class BiometricTemplate:
    phash: str            # 16 hex chars (64 bits)
    dhash: str            # 16 hex chars (64 bits)
    face_detected: bool
    extractor: str        # "opencv-haar" | "center-crop"
    digest: str           # SHA-256 of the raw template bytes
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
# Image -> biometric template
# --------------------------------------------------------------------------- #
_CASCADE = None


def _get_face_cascade():
    """Lazily load OpenCV's bundled frontal-face Haar cascade."""
    global _CASCADE
    if not OPENCV_AVAILABLE:
        return None
    if _CASCADE is None:
        path = cv2.data.haarcascades + "haarcascade_frontalface_default.xml"
        cascade = cv2.CascadeClassifier(path)
        _CASCADE = cascade if not cascade.empty() else False
    return _CASCADE or None


def _load_grayscale(image_bytes: bytes) -> Image.Image:
    if not image_bytes:
        raise BiometricError("No biometric image was provided.")
    if len(image_bytes) > MAX_IMAGE_BYTES:
        raise BiometricError("Biometric image is too large (max 10 MB).")
    try:
        img = Image.open(io.BytesIO(image_bytes))
        img = ImageOps.exif_transpose(img)
        return img.convert("L")
    except (UnidentifiedImageError, OSError) as exc:
        raise BiometricError(f"Unsupported or corrupted image: {exc}") from exc


def _detect_face_box(gray: Image.Image) -> Optional[tuple[int, int, int, int]]:
    """Return (left, top, right, bottom) of the largest detected face, or None."""
    cascade = _get_face_cascade()
    if cascade is None:
        return None
    arr = np.asarray(gray, dtype=np.uint8)
    min_side = max(60, min(arr.shape) // 6)
    faces = cascade.detectMultiScale(arr, scaleFactor=1.1, minNeighbors=5, minSize=(min_side, min_side))
    if len(faces) == 0:
        return None
    x, y, w, h = max(faces, key=lambda f: int(f[2]) * int(f[3]))
    margin = int(0.10 * w)
    return (max(0, x - margin), max(0, y - margin),
            min(gray.width, x + w + margin), min(gray.height, y + h + margin))


def _center_square(gray: Image.Image, ratio: float = 0.8) -> Image.Image:
    side = int(min(gray.size) * ratio)
    left = (gray.width - side) // 2
    top = (gray.height - side) // 2
    return gray.crop((left, top, left + side, top + side))


def _dct_matrix(n: int) -> np.ndarray:
    """Orthonormal DCT-II basis matrix (pure numpy, no SciPy dependency)."""
    k = np.arange(n).reshape(-1, 1)
    i = np.arange(n).reshape(1, -1)
    mat = np.sqrt(2.0 / n) * np.cos(np.pi * (2 * i + 1) * k / (2 * n))
    mat[0, :] = np.sqrt(1.0 / n)
    return mat


_DCT32 = _dct_matrix(32)


def _bits_to_hex(bits: np.ndarray) -> str:
    return np.packbits(bits.astype(np.uint8).flatten()).tobytes().hex()


def _phash(roi: Image.Image) -> str:
    pixels = np.asarray(roi.resize((32, 32), Image.Resampling.LANCZOS), dtype=np.float64)
    dct = _DCT32 @ pixels @ _DCT32.T
    low = dct[:8, :8].flatten()
    median = np.median(low[1:])  # exclude the DC term (overall brightness)
    return _bits_to_hex(low > median)


def _dhash(roi: Image.Image) -> str:
    pixels = np.asarray(roi.resize((9, 8), Image.Resampling.LANCZOS), dtype=np.int16)
    return _bits_to_hex(pixels[:, 1:] > pixels[:, :-1])


def extract_biometric_features(image_bytes: bytes) -> BiometricTemplate:
    """Convert a raw face/fingerprint image into a 128-bit perceptual template."""
    gray = _load_grayscale(image_bytes)
    box = _detect_face_box(gray)
    if box is not None:
        roi, extractor, face = gray.crop(box), "opencv-haar", True
    else:
        roi, extractor, face = _center_square(gray), "center-crop", False

    roi = ImageOps.equalize(roi).filter(ImageFilter.GaussianBlur(radius=1))
    phash, dhash = _phash(roi), _dhash(roi)
    digest = SHA256.new(bytes.fromhex(phash) + bytes.fromhex(dhash)).hexdigest()
    return BiometricTemplate(phash=phash, dhash=dhash, face_detected=face,
                             extractor=extractor, digest=digest)


def compare_templates(a: BiometricTemplate, b: BiometricTemplate) -> float:
    """Normalised Hamming similarity in [0, 1] across the 128 template bits."""
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
    """AES-128-EAX encrypt; returns ``nonce(16) | tag(16) | ciphertext``."""
    cipher = AES.new(key, AES.MODE_EAX, nonce=get_random_bytes(EAX_NONCE_BYTES), mac_len=EAX_TAG_BYTES)
    cipher.update(f"GeoVault-bio|{username}".encode("utf-8"))  # associated data
    ciphertext, tag = cipher.encrypt_and_digest(json.dumps(asdict(template)).encode("utf-8"))
    return cipher.nonce + tag + ciphertext


def decrypt_template(blob: bytes, key: bytes, username: str) -> BiometricTemplate:
    """Decrypt and authenticate a stored template. Raises ``ValueError`` on tampering."""
    blob = bytes(blob)
    if len(blob) <= EAX_NONCE_BYTES + EAX_TAG_BYTES:
        raise ValueError("Biometric template blob is truncated.")
    nonce = blob[:EAX_NONCE_BYTES]
    tag = blob[EAX_NONCE_BYTES:EAX_NONCE_BYTES + EAX_TAG_BYTES]
    ciphertext = blob[EAX_NONCE_BYTES + EAX_TAG_BYTES:]
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce, mac_len=EAX_TAG_BYTES)
    cipher.update(f"GeoVault-bio|{username}".encode("utf-8"))
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)  # raises ValueError if MAC fails
    return BiometricTemplate(**json.loads(plaintext))


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
    """
    Enrol a new user with password + biometric template.

    :param require_face: Reject the enrolment if no face is detected
                         (only enforced when OpenCV is available).
    """
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
    if require_face and OPENCV_AVAILABLE and not template.face_detected:
        return AuthResult(False, "No face detected. Face the camera directly with good lighting and retry.")

    salt = get_random_bytes(SALT_BYTES)
    verifier, bio_key = _derive_keys(password, salt, PBKDF2_ITERATIONS)
    encrypted = encrypt_template(template, bio_key, username)
    try:
        database.create_user(username, verifier.hex(), salt.hex(), PBKDF2_ITERATIONS,
                             encrypted, BIO_ALGORITHM_ID)
    except sqlite3.IntegrityError:
        return AuthResult(False, "Username is already registered.")
    return AuthResult(True, "Registration successful. You can now log in.", username=username,
                      face_detected=template.face_detected)


def authenticate_user(username: str, password: str, image_bytes: bytes) -> AuthResult:
    """Verify both factors. All credential failures return the same generic message."""
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
    # Constant-time comparison (no early exit on the first differing byte).
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
    if enrolled.face_detected and OPENCV_AVAILABLE and not probe.face_detected:
        database.record_login_failure(username, MAX_FAILED_ATTEMPTS, LOCKOUT_SECONDS)
        return AuthResult(False, "No face detected in the biometric scan.", similarity=similarity)
    if similarity < MATCH_THRESHOLD:
        database.record_login_failure(username, MAX_FAILED_ATTEMPTS, LOCKOUT_SECONDS)
        return AuthResult(False, GENERIC_FAILURE, similarity=similarity)

    database.record_login_success(username)
    return AuthResult(True, "Authenticated with password + biometric.", username=username,
                      similarity=similarity, face_detected=probe.face_detected)
