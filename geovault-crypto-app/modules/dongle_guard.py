"""
B.A.G.U.S. Vault - Hardware / USB Dongle Guard
==============================================

The application stays locked until a *valid* dongle token is found on a
mounted removable drive (or on a configured fallback path for testing).

Dongle token format (``.geovault_dongle`` / ``.cyberdeck_dongle`` - UTF-8 JSON)
-------------------------------------------------------------------------------
{
  "version": 1,
  "product": "B.A.G.U.S. Vault",
  "dongle_id": "<uuid4 hex>",
  "label": "Operator Hardware Key",
  "issued_at": "2026-11-10T12:00:00+00:00",
  "expires_at": null | "<ISO-8601>",
  "volume_serial": null | "1A2B3C4D",      # Windows volume binding (anti-cloning)
  "nonce": "<16 random bytes hex>",
  "signature": "<HMAC-SHA256 hex>"
}

``signature = HMAC-SHA256(K_dongle, canonical_json(token without "signature"))``
where ``K_dongle = HKDF(master_secret, "dongle/hmac-sha256")``.
"""

from __future__ import annotations

import ctypes
import json
import os
import secrets
import sys
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable, Optional

import psutil
from Crypto.Hash import HMAC, SHA256

import config

DONGLE_VERSION = 1
PRODUCT_NAME = "B.A.G.U.S. Vault"
ACCEPTED_PRODUCTS = ("B.A.G.U.S. Vault", "GeoVault", "BAGUS_OS")
SUPPORTED_FILENAMES = (config.DONGLE_FILENAME, ".cyberdeck_dongle")
MAX_TOKEN_BYTES = 4096  # refuse to parse oversized files (DoS hardening)
REQUIRED_FIELDS = ("version", "product", "dongle_id", "label", "issued_at",
                   "expires_at", "volume_serial", "nonce", "signature")

_FILE_ATTRIBUTE_HIDDEN = 0x02


# --------------------------------------------------------------------------- #
# Result object
# --------------------------------------------------------------------------- #
@dataclass
class DongleStatus:
    """Outcome of a dongle check / scan."""

    valid: bool
    message: str
    path: Optional[str] = None             # directory that holds the dongle file
    dongle_id: Optional[str] = None
    label: Optional[str] = None
    issued_at: Optional[str] = None
    expires_at: Optional[str] = None
    volume_serial: Optional[str] = None
    scanned_locations: list[str] = field(default_factory=list)
    failures: dict[str, str] = field(default_factory=dict)  # location -> reason


# --------------------------------------------------------------------------- #
# HMAC helpers
# --------------------------------------------------------------------------- #
def _hmac_key() -> bytes:
    return config.derive_subkey(config.PURPOSE_DONGLE_HMAC, 32)


def _canonical_payload(token: dict) -> bytes:
    """Deterministic serialisation of every field except the signature."""
    payload = {k: v for k, v in token.items() if k != "signature"}
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def compute_signature(token: dict) -> str:
    """Return the hex HMAC-SHA256 tag for a token."""
    mac = HMAC.new(_hmac_key(), digestmod=SHA256)
    mac.update(_canonical_payload(token))
    return mac.hexdigest()


# --------------------------------------------------------------------------- #
# Platform helpers
# --------------------------------------------------------------------------- #
def get_volume_serial(path: str | os.PathLike) -> Optional[str]:
    """
    Return the volume serial number of the drive holding ``path`` (Windows only).
    Returns ``None`` on other platforms or when the serial cannot be read.
    """
    if os.name != "nt":
        return None
    drive, _ = os.path.splitdrive(os.path.abspath(os.fspath(path)))
    if not drive or drive.startswith("\\\\"):  # UNC/network paths are not bound
        return None
    serial = ctypes.c_uint32(0)
    ok = ctypes.windll.kernel32.GetVolumeInformationW(  # type: ignore[attr-defined]
        ctypes.c_wchar_p(drive + "\\"), None, 0, ctypes.byref(serial), None, None, None, 0
    )
    return f"{serial.value:08X}" if ok else None


def _set_hidden(path: Path) -> None:
    """Mark a file as hidden. On POSIX the leading dot already hides it."""
    if os.name == "nt":
        try:
            ctypes.windll.kernel32.SetFileAttributesW(str(path), _FILE_ATTRIBUTE_HIDDEN)  # type: ignore[attr-defined]
        except Exception:
            pass


def _is_linux_removable(device: str) -> bool:
    """Check /sys/block/<dev>/removable for a /dev/sdXN style device."""
    try:
        name = os.path.basename(device)
        base = name.rstrip("0123456789")
        if base.startswith("nvme") or base.startswith("mmcblk"):
            base = name.split("p")[0]
        flag = Path(f"/sys/block/{base}/removable")
        return flag.exists() and flag.read_text().strip() == "1"
    except OSError:
        return False


def list_removable_mountpoints() -> list[str]:
    """Enumerate mount points of removable drives (USB flash disks, SD cards...)."""
    mounts: list[str] = []
    try:
        partitions = psutil.disk_partitions(all=False)
    except Exception:
        return mounts

    for part in partitions:
        opts = (part.opts or "").lower()
        mount = part.mountpoint
        if sys.platform.startswith("win"):
            if "removable" in opts:
                mounts.append(mount)
        elif sys.platform == "darwin":
            if mount.startswith("/Volumes/"):
                mounts.append(mount)
        else:
            if (_is_linux_removable(part.device)
                    or mount.startswith(("/media/", "/run/media/", "/mnt/"))):
                mounts.append(mount)
    return sorted(set(mounts))


def _env_fallback_paths() -> list[str]:
    raw = os.environ.get(config.DONGLE_PATH_ENV, "")
    paths = [p.strip() for p in raw.split(os.pathsep) if p.strip()]
    if config.DEFAULT_FALLBACK_DONGLE_DIR.is_dir():
        paths.append(str(config.DEFAULT_FALLBACK_DONGLE_DIR))
    return paths


def candidate_locations(extra_paths: Optional[Iterable[str]] = None) -> list[str]:
    """Removable drives + env fallback paths + caller-supplied paths (deduplicated, ordered)."""
    ordered: list[str] = []
    for loc in [*list_removable_mountpoints(), *_env_fallback_paths(), *(extra_paths or [])]:
        if loc and loc not in ordered:
            ordered.append(loc)
    return ordered


# --------------------------------------------------------------------------- #
# Token creation & verification
# --------------------------------------------------------------------------- #
def build_dongle_token(
    label: str,
    volume_serial: Optional[str] = None,
    valid_days: Optional[int] = None,
) -> dict:
    """Create and sign a new dongle token (not yet written to disk)."""
    issued = datetime.now(timezone.utc).replace(microsecond=0)
    token = {
        "version": DONGLE_VERSION,
        "product": PRODUCT_NAME,
        "dongle_id": uuid.uuid4().hex,
        "label": (label or "B.A.G.U.S. Vault Dongle").strip()[:64],
        "issued_at": issued.isoformat(),
        "expires_at": (issued + timedelta(days=valid_days)).isoformat() if valid_days else None,
        "volume_serial": volume_serial,
        "nonce": secrets.token_hex(16),
    }
    token["signature"] = compute_signature(token)
    return token


def verify_dongle_token(token: dict, location: Optional[str] = None) -> tuple[bool, str]:
    """Validate a parsed token against HMAC-SHA256 signature, expiry, and volume serial."""
    if not isinstance(token, dict):
        return False, "Malformed dongle token (not a JSON object)."
    missing = [f for f in REQUIRED_FIELDS if f not in token]
    if missing:
        return False, f"Malformed dongle token (missing: {', '.join(missing)})."
    if token.get("product") not in ACCEPTED_PRODUCTS or token.get("version") != DONGLE_VERSION:
        return False, f"Dongle issued for unexpected product '{token.get('product')}'."

    # 1) Integrity + authenticity: constant-time HMAC-SHA256 comparison.
    mac = HMAC.new(_hmac_key(), digestmod=SHA256)
    mac.update(_canonical_payload(token))
    try:
        mac.hexverify(str(token["signature"]))
    except ValueError:
        return False, "HMAC-SHA256 signature mismatch - token is forged or was modified."

    # 2) Expiry check.
    if token.get("expires_at"):
        try:
            expires = datetime.fromisoformat(token["expires_at"])
        except ValueError:
            return False, "Invalid expiry timestamp."
        if datetime.now(timezone.utc) > expires:
            return False, f"Dongle expired on {token['expires_at']}."

    # 3) Volume binding (anti-cloning).
    if token.get("volume_serial") and location:
        current = get_volume_serial(location)
        if current is not None and current != token["volume_serial"]:
            return False, (
                f"Dongle bound to different drive "
                f"(expected volume {token['volume_serial']}, found {current}) - cloned token?"
            )

    return True, "Dongle verified (HMAC-SHA256 OK)."


def _find_token_file(location: str | os.PathLike) -> Optional[Path]:
    """Locate either .geovault_dongle or .cyberdeck_dongle inside location."""
    path = Path(location)
    if path.is_file() and path.name in SUPPORTED_FILENAMES:
        return path
    for name in SUPPORTED_FILENAMES:
        cand = path / name
        if cand.is_file():
            return cand
    return None


def check_dongle_at(location: Optional[str]) -> DongleStatus:
    """Validate the dongle token stored in ``location``."""
    if not location:
        return DongleStatus(False, "No dongle location provided.")
    token_file = _find_token_file(location)
    directory = str(Path(location) if Path(location).is_dir() else Path(location).parent)

    if not token_file:
        return DongleStatus(False, f"No authorization dongle token found in {directory}.", path=directory)

    try:
        if token_file.stat().st_size > MAX_TOKEN_BYTES:
            return DongleStatus(False, "Dongle token file exceeds maximum size limit.", path=directory)
        token = json.loads(token_file.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        return DongleStatus(False, f"Unreadable dongle token: {exc}", path=directory)

    ok, reason = verify_dongle_token(token, directory)
    if not ok:
        return DongleStatus(False, reason, path=directory)
    return DongleStatus(
        valid=True,
        message=reason,
        path=directory,
        dongle_id=token["dongle_id"],
        label=token["label"],
        issued_at=token["issued_at"],
        expires_at=token["expires_at"],
        volume_serial=token["volume_serial"],
    )


def scan_for_dongle(extra_paths: Optional[Iterable[str]] = None) -> DongleStatus:
    """Scan candidate locations and return the first valid dongle."""
    locations = candidate_locations(extra_paths)
    failures: dict[str, str] = {}
    for loc in locations:
        status = check_dongle_at(loc)
        if status.valid:
            status.scanned_locations = locations
            return status
        if _find_token_file(loc) is not None:
            failures[loc] = status.message

    if failures:
        message = "Dongle token found but validation FAILED: " + "; ".join(
            f"[{loc}] {why}" for loc, why in failures.items()
        )
    elif locations:
        message = f"No valid dongle detected across {len(locations)} scanned path(s). Connect USB hardware key."
    else:
        message = "No removable drive detected. Connect USB authorization dongle or mount virtual key."
    return DongleStatus(False, message, scanned_locations=locations, failures=failures)


def provision_dongle(
    target: str | os.PathLike,
    label: str = "B.A.G.U.S. Vault Dongle",
    valid_days: Optional[int] = None,
    bind_to_volume: bool = True,
    overwrite: bool = False,
) -> DongleStatus:
    """Write a freshly signed dongle file to ``target``."""
    target_dir = Path(target)
    if not target_dir.is_dir():
        raise FileNotFoundError(f"Target directory does not exist: {target_dir}")
    token_file = target_dir / config.DONGLE_FILENAME
    if token_file.exists():
        if not overwrite:
            raise FileExistsError(f"A dongle already exists at {token_file}.")
        try:
            token_file.unlink()
        except OSError:
            pass

    serial = get_volume_serial(target_dir) if bind_to_volume else None
    token = build_dongle_token(label=label, volume_serial=serial, valid_days=valid_days)
    token_file.write_text(json.dumps(token, indent=2), encoding="utf-8")
    _set_hidden(token_file)
    return check_dongle_at(str(target_dir))


# --------------------------------------------------------------------------- #
# Lockscreen Telemetry & Dev Demo Virtual Mount
# --------------------------------------------------------------------------- #
def get_usb_diagnostics() -> list[dict]:
    """Inspect all system disk partitions and report live dongle/HMAC status for the Lockscreen."""
    diagnostics: list[dict] = []
    try:
        partitions = psutil.disk_partitions(all=False)
    except Exception:
        partitions = []

    for part in partitions:
        mount = part.mountpoint
        opts = part.opts or ""
        vol_serial = get_volume_serial(mount) or "UNBOUND"
        token_path = _find_token_file(mount)
        token_name = token_path.name if token_path else "NOT_FOUND"

        status = check_dongle_at(mount) if token_path else None
        if status and status.valid:
            challenge_str = "AUTHENTICATED // HMAC-SHA256 VERIFIED"
            state_color = "#00FF66"
        elif token_path:
            challenge_str = f"TAMPER_DETECTED // {status.message if status else 'INVALID'}"
            state_color = "#FF003C"
        else:
            challenge_str = "AWAITING_DEVICE // NO_KEY_TOKEN"
            state_color = "#7C8DA6"

        diagnostics.append({
            "mount": mount,
            "device": part.device,
            "fstype": part.fstype or "RAW",
            "type": "REMOVABLE_USB" if "removable" in opts.lower() else "FIXED_DRIVE",
            "volume_serial": vol_serial,
            "token_file": token_name,
            "hmac_challenge": challenge_str,
            "status_color": state_color,
            "is_valid": bool(status and status.valid),
        })

    # Always report virtual fallback path state
    v_dir = config.DEFAULT_FALLBACK_DONGLE_DIR
    v_token = _find_token_file(v_dir) if v_dir.is_dir() else None
    v_status = check_dongle_at(str(v_dir)) if v_token else None
    diagnostics.append({
        "mount": str(v_dir),
        "device": "[VIRTUAL_LOOPBACK]",
        "fstype": "NTFS/POSIX",
        "type": "VIRTUAL_DONGLE",
        "volume_serial": "VIRTUAL_KEY",
        "token_file": v_token.name if v_token else "NOT_MOUNTED",
        "hmac_challenge": (
            "AUTHENTICATED // HMAC-SHA256 VERIFIED"
            if (v_status and v_status.valid)
            else "VIRTUAL_TOKEN_DISCONNECTED"
        ),
        "status_color": "#00FF66" if (v_status and v_status.valid) else "#FF003C",
        "is_valid": bool(v_status and v_status.valid),
    })

    return diagnostics


def mount_virtual_dongle(label: str = "Virtual Forensic Key") -> DongleStatus:
    """Mount a valid virtual dongle token inside ./virtual_usb (for live classroom demos)."""
    target = config.DEFAULT_FALLBACK_DONGLE_DIR
    target.mkdir(parents=True, exist_ok=True)
    return provision_dongle(target, label=label, bind_to_volume=False, overwrite=True)


def unmount_virtual_dongle() -> bool:
    """Unmount (delete) virtual dongle tokens to simulate live USB unplugging."""
    target = config.DEFAULT_FALLBACK_DONGLE_DIR
    removed = False
    for fn in SUPPORTED_FILENAMES:
        tf = target / fn
        if tf.exists():
            try:
                tf.unlink()
                removed = True
            except OSError:
                pass
    return removed


def is_virtual_dongle_mounted() -> bool:
    """Return True if a valid token is currently present in the virtual dongle path."""
    target = config.DEFAULT_FALLBACK_DONGLE_DIR
    return _find_token_file(target) is not None
