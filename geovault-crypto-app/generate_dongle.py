"""
GeoVault - USB / Local Dongle Provisioning Utility
==================================================

Can be used either as a **CLI script** OR as a **Streamlit UI**:

1) CLI usage:
     # Provision a local virtual USB folder for testing without hardware USB:
     python generate_dongle.py --local --overwrite

     # Provision a physical USB flash drive (e.g. E:\\ on Windows):
     python generate_dongle.py --target E:\\ --label "Operator Key #1" --overwrite

     # List detected removable USB drives:
     python generate_dongle.py --list

2) Streamlit UI usage:
     streamlit run generate_dongle.py
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Optional

import config
from modules import dongle_guard


# --------------------------------------------------------------------------- #
# CLI Mode
# --------------------------------------------------------------------------- #
def run_cli(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Provision or verify a GeoVault HMAC-SHA256 hardware/USB dongle (.geovault_dongle)."
    )
    parser.add_argument(
        "--target", "-t",
        help="Target USB mount point or folder path (e.g. E:\\ or ./virtual_usb).",
    )
    parser.add_argument(
        "--local", action="store_true",
        help=f"Create and provision the default local test folder ({config.DEFAULT_FALLBACK_DONGLE_DIR}).",
    )
    parser.add_argument(
        "--label", "-l", default="GeoVault Operator Dongle",
        help="Human-readable owner/device label embedded in the signed token.",
    )
    parser.add_argument(
        "--days", "-d", type=int, default=None,
        help="Optional validity period in days (omit for non-expiring token).",
    )
    parser.add_argument(
        "--no-volume-bind", action="store_true",
        help="Disable Windows volume serial number anti-cloning binding.",
    )
    parser.add_argument(
        "--overwrite", "-f", action="store_true",
        help="Overwrite an existing .geovault_dongle file if present.",
    )
    parser.add_argument(
        "--list", action="store_true",
        help="List currently mounted removable USB drives and exit.",
    )
    parser.add_argument(
        "--verify", "-v",
        help="Verify an existing dongle directory/file instead of creating one.",
    )
    parser.add_argument(
        "--revoke",
        help="Delete .geovault_dongle from the specified directory (locks GeoVault).",
    )

    args = parser.parse_args(argv)

    if args.list:
        mounts = dongle_guard.list_removable_mountpoints()
        if not mounts:
            print("No removable USB drives currently detected.")
        else:
            print("Detected removable drives:")
            for m in mounts:
                serial = dongle_guard.get_volume_serial(m) or "N/A"
                print(f"  - {m}  (Volume Serial: {serial})")
        return 0

    if args.verify:
        status = dongle_guard.check_dongle_at(args.verify)
        print(f"[{'VALID' if status.valid else 'INVALID'}] {status.message}")
        if status.valid:
            print(f"  Path         : {status.path}")
            print(f"  Dongle ID    : {status.dongle_id}")
            print(f"  Label        : {status.label}")
            print(f"  Issued At    : {status.issued_at}")
            print(f"  Expires At   : {status.expires_at or 'Never'}")
            print(f"  Volume Serial: {status.volume_serial or 'Unbound'}")
        return 0 if status.valid else 1

    if args.revoke:
        token_file = Path(args.revoke) / config.DONGLE_FILENAME
        if token_file.exists():
            token_file.unlink()
            print(f"[REVOKED] Removed {token_file}")
            return 0
        print(f"No {config.DONGLE_FILENAME} found in {args.revoke}")
        return 1

    target_path: Optional[Path] = None
    if args.local:
        target_path = config.DEFAULT_FALLBACK_DONGLE_DIR
        target_path.mkdir(parents=True, exist_ok=True)
    elif args.target:
        target_path = Path(args.target)
    else:
        mounts = dongle_guard.list_removable_mountpoints()
        if len(mounts) == 1:
            target_path = Path(mounts[0])
            print(f"Auto-selected removable USB drive: {target_path}")
        else:
            parser.print_help()
            print("\nTip: Use `python generate_dongle.py --local --overwrite` to create a local virtual USB dongle.")
            return 1

    try:
        status = dongle_guard.provision_dongle(
            target=target_path,
            label=args.label,
            valid_days=args.days,
            bind_to_volume=not args.no_volume_bind,
            overwrite=args.overwrite,
        )
    except (FileNotFoundError, FileExistsError) as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1

    if status.valid:
        print(f"[SUCCESS] Provisioned HMAC-SHA256 dongle in: {status.path}")
        print(f"  Token File   : {Path(status.path) / config.DONGLE_FILENAME} (hidden)")
        print(f"  Dongle ID    : {status.dongle_id}")
        print(f"  Label        : {status.label}")
        print(f"  Volume Serial: {status.volume_serial or 'Unbound'}")
        print(f"  Expires At   : {status.expires_at or 'Never'}")
        return 0

    print(f"[FAILED] {status.message}", file=sys.stderr)
    return 1


# --------------------------------------------------------------------------- #
# Streamlit UI Mode  (`streamlit run generate_dongle.py`)
# --------------------------------------------------------------------------- #
def run_streamlit_ui() -> None:
    import streamlit as st

    st.set_page_config(page_title="GeoVault Dongle Provisioner", page_icon="🔑", layout="centered")
    st.title("🔑 GeoVault Dongle Provisioning Studio")
    st.caption("Utility to sign & write a `.geovault_dongle` HMAC-SHA256 hardware token.")

    mounts = dongle_guard.list_removable_mountpoints()
    st.subheader("1. Choose Target Drive / Directory")
    mode = st.radio(
        "Target Type",
        ["Removable USB Flash Drive", f"Local Virtual USB (`{config.DEFAULT_FALLBACK_DONGLE_DIR.name}/`)", "Custom Folder Path"],
        index=0 if mounts else 1,
    )

    target_str = ""
    if mode == "Removable USB Flash Drive":
        if mounts:
            target_str = st.selectbox("Detected USB Drives", mounts)
        else:
            st.warning("No removable USB drive detected. Plug in a USB drive or choose **Local Virtual USB**.")
    elif mode.startswith("Local Virtual USB"):
        target_str = str(config.DEFAULT_FALLBACK_DONGLE_DIR)
        st.info(f"Token will be written to `{target_str}` (automatically scanned by GeoVault for local testing).")
    else:
        target_str = st.text_input("Custom Directory Path", value=str(config.DEFAULT_FALLBACK_DONGLE_DIR))

    st.subheader("2. Token Parameters")
    col1, col2 = st.columns(2)
    with col1:
        label = st.text_input("Key Label / Owner", value="GeoVault Operator Key")
        bind_vol = st.checkbox("Bind to Windows Volume Serial (Anti-Cloning)", value=True)
    with col2:
        use_expiry = st.checkbox("Set Expiration", value=False)
        valid_days = st.number_input("Valid Days", min_value=1, max_value=3650, value=365) if use_expiry else None
        overwrite = st.checkbox("Overwrite existing dongle", value=True)

    col_btn1, col_btn2 = st.columns(2)
    with col_btn1:
        if st.button("✨ Provision `.geovault_dongle` Now", type="primary", use_container_width=True, disabled=not target_str):
            try:
                if mode.startswith("Local Virtual USB"):
                    Path(target_str).mkdir(parents=True, exist_ok=True)
                status = dongle_guard.provision_dongle(
                    target=target_str,
                    label=label,
                    valid_days=int(valid_days) if valid_days else None,
                    bind_to_volume=bind_vol,
                    overwrite=overwrite,
                )
                if status.valid:
                    st.success(f"Dongle provisioned & verified at `{status.path}`!")
                    st.json({
                        "dongle_id": status.dongle_id,
                        "label": status.label,
                        "issued_at": status.issued_at,
                        "expires_at": status.expires_at,
                        "volume_serial": status.volume_serial,
                    })
                else:
                    st.error(status.message)
            except Exception as exc:
                st.error(str(exc))

    with col_btn2:
        if st.button("🗑️ Revoke / Remove Dongle", use_container_width=True, disabled=not target_str):
            token_path = Path(target_str) / config.DONGLE_FILENAME
            if token_path.exists():
                token_path.unlink()
                st.warning(f"Removed `{token_path}`. GeoVault is now locked.")
            else:
                st.info("No dongle file present at target.")

    st.divider()
    st.subheader("Live Scan Status")
    scan = dongle_guard.scan_for_dongle()
    if scan.valid:
        st.success(f"Active valid dongle detected at `{scan.path}` — ID `{scan.dongle_id}` ({scan.label})")
    else:
        st.error(scan.message)


def _running_in_streamlit() -> bool:
    try:
        from streamlit.runtime.scriptrunner import get_script_run_ctx

        return get_script_run_ctx() is not None
    except Exception:
        return False


if __name__ == "__main__":
    if _running_in_streamlit():
        run_streamlit_ui()
    else:
        raise SystemExit(run_cli())
