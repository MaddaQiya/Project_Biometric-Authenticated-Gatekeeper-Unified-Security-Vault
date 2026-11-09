"""
BAGUS_OS // TERMINAL v2.6 — GeoVault Spatial & Secret Document Digital Vault
============================================================================

Main Streamlit application refactored with a full Cyberpunk 2077 / Netrunner CLI
aesthetic while preserving the 3-stage security gatekeeper and all 7 backend modules:
  [Step 1: Hardware/USB Dongle Check (HMAC-SHA256)]
      -> [Step 2: Password (PBKDF2-SHA256) + Biometric (AES-128-EAX) Login]
          -> [Step 3: Main Vault Dashboard & PoW Blockchain Ledger]
"""

from __future__ import annotations

import secrets
from typing import Optional

import streamlit as st

import config
import database
import ui_cyberpunk
from modules import (
    auth_biometric,
    blockchain,
    dongle_guard,
    file_crypto,
    steganography,
    super_encryption,
)

# --------------------------------------------------------------------------- #
# Bootstrap, Cyberpunk CSS & Session State
# --------------------------------------------------------------------------- #
st.set_page_config(
    page_title="BAGUS_OS // TERMINAL v2.6 | GeoVault Netrunner CLI",
    page_icon="⚡",
    layout="wide",
    initial_sidebar_state="expanded",
)

ui_cyberpunk.inject_cyberpunk_css()
ui_cyberpunk.init_cli_logs()
database.init_db()

if "authenticated_user" not in st.session_state:
    st.session_state.authenticated_user = None
if "auth_similarity" not in st.session_state:
    st.session_state.auth_similarity = None
if "custom_dongle_path" not in st.session_state:
    st.session_state.custom_dongle_path = ""
if "last_logged_dongle_state" not in st.session_state:
    st.session_state.last_logged_dongle_state = None


def _read_biometric_input(prefix: str) -> Optional[bytes]:
    """Render Streamlit camera capture + fallback image uploader and return raw image bytes."""
    mode = st.radio(
        "BIOMETRIC_CAPTURE_CHANNEL // METODE INPUT",
        ["Kamera Langsung (Scan Wajah)", "Upload File Citra Wajah / Sidik Jari (Fallback)"],
        horizontal=True,
        key=f"{prefix}_bio_mode",
    )
    if mode.startswith("Kamera"):
        cam = st.camera_input("Scan Wajah Biometrik", key=f"{prefix}_cam")
        return cam.getvalue() if cam is not None else None

    upload = st.file_uploader(
        "Upload Citra Wajah atau Sidik Jari (PNG / JPG / WEBP)",
        type=["png", "jpg", "jpeg", "webp", "bmp"],
        key=f"{prefix}_upload",
    )
    if upload is not None:
        st.image(upload, caption="BIO_SENSOR_FRAME // PREVIEW", width=220)
        return upload.getvalue()
    return None


# --------------------------------------------------------------------------- #
# STEP 1: Hardware / USB Dongle Gatekeeper (Breach Alert Screen)
# --------------------------------------------------------------------------- #
def render_dongle_lock_screen(status: dongle_guard.DongleStatus) -> None:
    ui_cyberpunk.render_ascii_hud(current_step=1, operator=None, dongle_label=None)
    ui_cyberpunk.render_dongle_breach_banner(
        reason=status.message,
        has_tamper_failure=bool(status.failures),
    )

    col_a, col_b = st.columns([1, 1])
    with col_a:
        if st.button("⚡ RESCAN_USB_BUS // VALIDATE HMAC-SHA256 DONGLE", type="primary", use_container_width=True):
            ui_cyberpunk.log_cli(
                "DONGLE_GUARD",
                "Manual USB bus rescan triggered — probing removable mounts for .geovault_dongle",
                digest=ui_cyberpunk.sha256_hex(str(status.scanned_locations)),
                level="WARN",
            )
            st.session_state.last_logged_dongle_state = None
            st.rerun()

    with col_b:
        with st.expander("⚙️ NETRUNNER_OVERRIDE // FALLBACK DONGLE PATH CONFIG"):
            custom = st.text_input(
                "Custom Drive / Folder Path",
                value=st.session_state.custom_dongle_path,
                placeholder=str(config.DEFAULT_FALLBACK_DONGLE_DIR),
            )
            if st.button("MOUNT_FALLBACK_PATH // TEST"):
                st.session_state.custom_dongle_path = custom.strip()
                ui_cyberpunk.log_cli(
                    "DONGLE_GUARD",
                    f"Mounted custom dongle search path: {st.session_state.custom_dongle_path or 'DEFAULT'}",
                    digest=ui_cyberpunk.sha256_hex(st.session_state.custom_dongle_path or "DEFAULT"),
                    level="INFO",
                )
                st.session_state.last_logged_dongle_state = None
                st.rerun()
            st.caption(
                "Provision `.geovault_dongle` via CLI or Streamlit Studio:\n"
                "```bash\n"
                "python generate_dongle.py --local --overwrite\n"
                "streamlit run generate_dongle.py\n"
                "```"
            )

    with st.expander("📡 USB_BUS_TELEMETRY // SCANNED MOUNT POINTS"):
        if status.scanned_locations:
            for loc in status.scanned_locations:
                st.code(loc)
        else:
            st.write("NO_REMOVABLE_DRIVES_DETECTED // INSERT USB TOKEN OR PROVISION ./virtual_usb")

    ui_cyberpunk.render_cli_console("GATE_01 // HARDWARE DONGLE INTERCEPT LOG")


# --------------------------------------------------------------------------- #
# STEP 2: Biometric + Cryptographic Login / Registration
# --------------------------------------------------------------------------- #
def render_auth_screen(dongle: dongle_guard.DongleStatus) -> None:
    ui_cyberpunk.render_ascii_hud(current_step=2, operator=None, dongle_label=dongle.label)
    st.markdown(
        f"### 🧬 GATE_02 // BIOMETRIC + CRYPTOGRAPHIC NEURAL HANDSHAKE\n"
        f"`DONGLE_ID: {dongle.dongle_id}` · `MOUNT: {dongle.path}` · "
        f"`OPENCV_HAAR: {'ONLINE' if auth_biometric.OPENCV_AVAILABLE else 'CENTER_CROP_FALLBACK'}`"
    )

    tab_login, tab_register = st.tabs([
        "🔑 [01] AUTHENTICATE_OPERATOR",
        "📝 [02] ENROLL_NEW_IDENTITY",
    ])

    with tab_login:
        col_form, col_bio = st.columns([1, 1])
        with col_form:
            st.subheader("FACTOR_01 // PBKDF2-HMAC-SHA256 CREDENTIALS")
            login_user = st.text_input("Operator Handle (Username)", key="login_username", placeholder="operator_01")
            login_pw = st.text_input("Passkey", type="password", key="login_password")
            st.caption(
                "Derived via **PBKDF2-HMAC-SHA256 (600,000 iterations)** + 16-byte CSPRNG salt + "
                "**HKDF-SHA256** domain separation (`auth/verifier` & `auth/biometric-key`)."
            )
        with col_bio:
            st.subheader("FACTOR_02 // AES-128-EAX BIOMETRIC PROBE")
            login_img = _read_biometric_input("login")

        if st.button("🔓 EXECUTE_2FA_HANDSHAKE // UNLOCK VAULT", type="primary", use_container_width=True):
            if not login_user or not login_pw or not login_img:
                st.warning("Lengkapi Operator Handle, Passkey, dan Biometric Scan/Upload.")
            else:
                img_digest = ui_cyberpunk.sha256_hex(login_img)
                ui_cyberpunk.log_cli(
                    "BIO_AUTH",
                    f"Initiating PBKDF2-SHA256 (600k iter) + AES-128-EAX template unseal for '{login_user.strip().lower()}'",
                    digest=img_digest,
                    level="INFO",
                )
                with st.spinner("RUNNING PBKDF2-SHA256 & DECRYPTING AES-128-EAX BIOMETRIC TEMPLATE..."):
                    res = auth_biometric.authenticate_user(login_user, login_pw, login_img)
                if res.success:
                    ui_cyberpunk.log_cli(
                        "BIO_AUTH",
                        f"2FA handshake GRANTED for '{res.username}' — Hamming similarity={res.similarity:.1%}",
                        digest=img_digest,
                        level="OK",
                    )
                    st.session_state.authenticated_user = res.username
                    st.session_state.auth_similarity = res.similarity
                    st.rerun()
                else:
                    sim_info = f" (Similarity: {res.similarity:.1%})" if res.similarity is not None else ""
                    ui_cyberpunk.log_cli(
                        "BIO_AUTH",
                        f"2FA handshake REJECTED for '{login_user.strip().lower()}': {res.message}{sim_info}",
                        digest=img_digest,
                        level="CRIT",
                    )
                    st.error(f"{res.message}{sim_info}")

    with tab_register:
        col_r1, col_r2 = st.columns([1, 1])
        with col_r1:
            st.subheader("STEP_A // CREDENTIAL INITIALIZATION")
            reg_user = st.text_input(
                "New Operator Handle (3-32 chars, a-z0-9_.-)",
                key="reg_username",
                placeholder="operator_01",
            )
            reg_pw = st.text_input("Passkey (min. 8 chars, letters & digits)", type="password", key="reg_pw")
            reg_pw2 = st.text_input("Confirm Passkey", type="password", key="reg_pw2")
            require_face = st.checkbox(
                "Enforce strict OpenCV frontal-face detection (disable for fingerprint images)",
                value=False,
            )
        with col_r2:
            st.subheader("STEP_B // BIOMETRIC TEMPLATE CAPTURE")
            reg_img = _read_biometric_input("register")
            st.caption(
                "Extracts a 128-bit perceptual vector (`pHash 64-bit + dHash 64-bit`) and seals it "
                "inside SQLite using **AES-128-EAX** authenticated encryption."
            )

        if st.button("✨ ENROLL_OPERATOR // SEAL AES-128-EAX TEMPLATE", type="primary", use_container_width=True):
            if reg_pw != reg_pw2:
                st.error("Passkey confirmation mismatch.")
            elif not reg_img:
                st.warning("Capture or upload a biometric image first.")
            else:
                img_digest = ui_cyberpunk.sha256_hex(reg_img)
                with st.spinner("EXTRACTING 128-BIT BIOMETRIC VECTOR & SEALING WITH AES-128-EAX..."):
                    res = auth_biometric.register_user(reg_user, reg_pw, reg_img, require_face=require_face)
                if res.success:
                    ui_cyberpunk.log_cli(
                        "BIO_AUTH",
                        f"Enrolled operator '{res.username}' — template sealed with AES-128-EAX (face={res.face_detected})",
                        digest=img_digest,
                        level="OK",
                    )
                    st.success(
                        f"{res.message} (OpenCV Face ROI: {'DETECTED' if res.face_detected else 'CENTER_CROP'})"
                    )
                else:
                    ui_cyberpunk.log_cli(
                        "BIO_AUTH",
                        f"Enrollment failed for '{reg_user}': {res.message}",
                        digest=img_digest,
                        level="WARN",
                    )
                    st.error(res.message)

    ui_cyberpunk.render_cli_console("GATE_02 // BIOMETRIC & PBKDF2-SHA256 AUTH STREAM")


# --------------------------------------------------------------------------- #
# STEP 3: Main Vault Dashboard Pages
# --------------------------------------------------------------------------- #
def render_overview_tab(username: str, dongle: dongle_guard.DongleStatus) -> None:
    blockchain.ensure_genesis()
    stats = database.get_user_stats(username)
    report = blockchain.verify_chain()

    st.subheader("📡 NETRUNNER_CORE // TELEMETRY & CRYPTOGRAPHIC MATRIX")
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("POW_LEDGER_BLOCKS", stats["ledger_blocks"])
    m2.metric("CHAIN_INTEGRITY", "VALID_OK" if report.valid else "BREACHED!")
    m3.metric("SUPER_ENC_MESSAGES", stats["secret_messages"])
    m4.metric("CHACHA20_VAULT_FILES", stats["encrypted_files"])

    if not report.valid:
        st.error(
            f"🚨 [CHAIN_INTEGRITY_BREACH] {len(report.issues)} anomaly(s) detected in SQLite ledger! "
            "Open **⛓️ POW_BLOCKCHAIN_LEDGER** to inspect tampered blocks."
        )

    c1, c2 = st.columns(2)
    with c1:
        st.markdown("#### 🔑 HARDWARE_DONGLE // HMAC-SHA256 TOKEN")
        st.json({
            "label": dongle.label,
            "dongle_id": dongle.dongle_id,
            "mount_path": dongle.path,
            "volume_serial": dongle.volume_serial or "UNBOUND",
            "expires_at": dongle.expires_at or "NEVER",
            "mac_algorithm": "HMAC-SHA256 (HKDF domain: dongle/hmac-sha256)",
        })
    with c2:
        st.markdown("#### 🛡️ BAGUS_OS // ACTIVE CIPHER SUITES")
        st.markdown(
            "- **[MOD-01] Dongle Gatekeeper**: `.geovault_dongle` + `HMAC-SHA256` + Volume Serial Lock\n"
            "- **[MOD-02] Neural 2FA Auth**: `PBKDF2-HMAC-SHA256` (600k iter) + `pHash/dHash` + `AES-128-EAX`\n"
            "- **[MOD-03] Critical Asset Chain**: `SHA-256` PoW (`00`) + `AES-256-GCM` + `HMAC Tip Anchor`\n"
            "- **[MOD-04] Super Encryption**: `Vigenère Cipher` + `AES-256-CBC` (PKCS#7)\n"
            "- **[MOD-05] Stream File Vault**: `ChaCha20` + `SHA-256` integrity check\n"
            "- **[MOD-06] Pixel Steganography**: Lossless `PNG LSB` bit-plane embedding"
        )


def render_blockchain_tab(username: str) -> None:
    blockchain.ensure_genesis()
    st.subheader("⛓️ POW_BLOCKCHAIN_LEDGER // CRITICAL SPATIAL & SECRET ASSETS")
    st.caption(
        "Each critical asset is sealed with **AES-256-GCM** and mined into a **SHA-256 Proof-of-Work** "
        "block (`difficulty=\"00\"`) anchored by an **HMAC-SHA256** chain-tip signature."
    )

    col_verify, col_export = st.columns([2, 1])
    with col_verify:
        if st.button("🔍 VERIFY_BLOCKCHAIN_INTEGRITY // FULL HASH AUDIT", type="primary", use_container_width=True):
            rep = blockchain.verify_chain()
            st.session_state["last_verification"] = rep
            tip_hash = blockchain.get_chain()[-1].current_hash if blockchain.get_chain() else "NONE"
            ui_cyberpunk.log_cli(
                "POW_LEDGER",
                f"Chain audit complete: valid={rep.valid} | blocks={rep.blocks_checked} | "
                f"issues={len(rep.issues)} | elapsed={rep.elapsed_ms:.2f}ms",
                digest=tip_hash,
                level="OK" if rep.valid else "CRIT",
            )
    with col_export:
        st.download_button(
            "⬇️ EXPORT_LEDGER.JSON",
            data=blockchain.export_chain_json(),
            file_name="bagus_os_blockchain_ledger.json",
            mime="application/json",
            use_container_width=True,
        )

    report: blockchain.VerificationReport = st.session_state.get("last_verification") or blockchain.verify_chain()
    if report.valid:
        st.success(
            f"✅ **[CHAIN_INTEGRITY_VERIFIED]** All {report.blocks_checked} blocks passed SHA-256 recomputation, "
            f"PoW prefix `{blockchain.HASH_PREFIX}`, `previous_hash` linkage, AES-256-GCM tag, and HMAC tip anchor "
            f"({report.elapsed_ms:.2f} ms)."
        )
    else:
        st.error(
            f"🚨 **[CRITICAL_LEDGER_TAMPER_DETECTED]** Found {len(report.issues)} integrity violation(s):"
        )
        for issue in report.issues:
            st.warning(f"- **BLOCK #{issue.index}** [`{issue.kind}`]: {issue.detail}")

    sub_add, sub_explore, sub_tamper = st.tabs([
        "⛏️ [01] MINE_NEW_ASSET_BLOCK",
        "📦 [02] BLOCK_EXPLORER_&_GCM_DECRYPT",
        "🧪 [03] TAMPER_SIMULATION_LAB",
    ])

    with sub_add:
        asset_type = st.selectbox("Asset Classification", blockchain.ASSET_TYPES)
        asset_name = st.text_input("Asset Codename / Identifier", placeholder="SECTOR_7_BUNKER_COORDS")

        metadata: dict = {}
        if asset_type == "Secret Coordinates":
            c1, c2, c3 = st.columns(3)
            lat = c1.number_input("Latitude", min_value=-90.0, max_value=90.0, value=-6.200000, format="%.6f")
            lon = c2.number_input("Longitude", min_value=-180.0, max_value=180.0, value=106.816666, format="%.6f")
            elev = c3.number_input("Elevation (m)", value=45.0, format="%.1f")
            zone_note = st.text_area("Geospatial Extraction Protocol / Field Notes")
            metadata = {"latitude": lat, "longitude": lon, "elevation_m": elev, "notes": zone_note}
        elif asset_type == "Digital Certificate":
            c1, c2 = st.columns(2)
            issuer = c1.text_input("Issuing Authority (CA)", placeholder="BAGUS_OS Root CA")
            serial_no = c2.text_input("Certificate Serial", placeholder="SN-2077-AX-991")
            fingerprint = st.text_input("Public Key / SHA-256 Fingerprint")
            cert_note = st.text_area("Certificate Claims / Policy Payload")
            metadata = {"issuer": issuer, "serial_number": serial_no, "fingerprint": fingerprint, "claims": cert_note}
        else:
            classification = st.selectbox("Clearance Level", ["BLACK_ICE // TOP SECRET", "NETWATCH // SECRET", "RESTRICTED"])
            ref_id = st.text_input("Document Reference ID", placeholder="DOC-HV-2077")
            record_body = st.text_area("Encrypted Record Payload")
            metadata = {"classification": classification, "reference_id": ref_id, "content": record_body}

        if st.button("⛏️ SEAL_AES256_GCM & MINE_POW_BLOCK", type="primary"):
            if not asset_name.strip():
                st.warning("Asset Codename is required.")
            else:
                try:
                    mined = blockchain.add_asset(asset_name, asset_type, metadata, owner=username)
                    st.session_state["last_verification"] = blockchain.verify_chain()
                    ui_cyberpunk.log_cli(
                        "POW_LEDGER",
                        f"Mined Block #{mined.block.index} ('{mined.block.asset_name}') — "
                        f"nonce={mined.block.nonce} ({mined.attempts} hashes in {mined.elapsed_ms:.2f}ms)",
                        digest=mined.block.current_hash,
                        level="OK",
                    )
                    st.success(
                        f"Block **#{mined.block.index}** committed! "
                        f"SHA-256: `{mined.block.current_hash}` | Nonce: `{mined.block.nonce}` "
                        f"({mined.attempts} attempts, {mined.elapsed_ms:.2f} ms)."
                    )
                except Exception as exc:
                    ui_cyberpunk.log_cli("POW_LEDGER", f"Mining failed: {exc}", level="CRIT")
                    st.error(str(exc))

    with sub_explore:
        chain = blockchain.get_chain()
        for blk in reversed(chain):
            state_badge = "🟢 [VALID]" if report.block_status.get(blk.index) == "OK" else "🔴 [TAMPERED]"
            with st.expander(
                f"{state_badge} BLOCK #{blk.index:03d} // {blk.asset_name} // {blk.timestamp}",
                expanded=(blk.index == len(chain) - 1),
            ):
                st.markdown(
                    f"- **`CURRENT_HASH (SHA-256)`**: `{blk.current_hash}`\n"
                    f"- **`PREVIOUS_HASH`**: `{blk.previous_hash}`\n"
                    f"- **`POW_NONCE`**: `{blk.nonce}`\n"
                    f"- **`AES_256_GCM_CIPHERTEXT`**: `{blk.encrypted_asset_metadata[:72]}...`"
                )
                if st.button(f"🔓 UNSEAL_AES256_GCM // BLOCK #{blk.index}", key=f"dec_blk_{blk.index}"):
                    try:
                        decrypted = blockchain.decrypt_metadata(blk)
                        ui_cyberpunk.log_cli(
                            "POW_LEDGER",
                            f"AES-256-GCM tag verified & metadata unsealed for Block #{blk.index}",
                            digest=blk.current_hash,
                            level="OK",
                        )
                        st.json(decrypted)
                    except Exception as exc:
                        ui_cyberpunk.log_cli(
                            "POW_LEDGER",
                            f"AES-256-GCM authentication FAILED on Block #{blk.index}: {exc}",
                            digest=blk.current_hash,
                            level="CRIT",
                        )
                        st.error(f"AES-256-GCM Decryption/Authentication Failed: {exc}")

    with sub_tamper:
        st.info(
            "Simulate direct SQLite adversary attacks against `blockchain_ledger`, then run "
            "**VERIFY_BLOCKCHAIN_INTEGRITY** above to observe live tamper detection."
        )
        chain = blockchain.get_chain()
        col_t1, col_t2 = st.columns(2)
        target_idx = col_t1.selectbox("Target Block Index", [b.index for b in chain])
        mode_key = col_t2.selectbox(
            "Attack Vector",
            list(blockchain.TAMPER_MODES.keys()),
            format_func=lambda k: blockchain.TAMPER_MODES[k],
        )
        b1, b2 = st.columns(2)
        if b1.button("💥 INJECT_SQLITE_TAMPER_PAYLOAD", use_container_width=True):
            msg = blockchain.simulate_tampering(int(target_idx), mode_key)
            st.session_state["last_verification"] = blockchain.verify_chain()
            ui_cyberpunk.log_cli(
                "POW_LEDGER",
                f"Adversary simulation executed ({mode_key}) on Block #{target_idx}: {msg}",
                digest=ui_cyberpunk.sha256_hex(msg),
                level="CRIT",
            )
            st.rerun()
        if b2.button("♻️ PURGE_&_REBUILD_GENESIS_CHAIN", use_container_width=True):
            blockchain.reset_ledger()
            st.session_state["last_verification"] = blockchain.verify_chain()
            gen_hash = blockchain.get_chain()[0].current_hash
            ui_cyberpunk.log_cli(
                "POW_LEDGER",
                "Ledger purged and fresh Genesis Block #0 mined",
                digest=gen_hash,
                level="WARN",
            )
            st.rerun()


# --------------------------------------------------------------------------- #
# CRYPTOGRAPHIC VAULT SUBSYSTEM TABS (Super Encryption, ChaCha20, LSB Stego)
# --------------------------------------------------------------------------- #
def render_super_encryption_tab(username: str) -> None:
    st.subheader("📝 SUPER_ENCRYPTION // VIGENÈRE + AES-256-CBC CIPHER PIPELINE")
    st.caption("Two-layer cascade encryption (`modules/super_encryption.py`) — persists to `secret_messages`.")

    with st.form("super_enc_form"):
        title = st.text_input("Dispatch Title / Codename")
        plaintext = st.text_area("Classified Plaintext / Spatial Coordinates")
        c1, c2 = st.columns(2)
        vig_key = c1.text_input("Layer 1: Vigenère Classical Key", type="password")
        aes_key = c2.text_input("Layer 2: AES-256-CBC Passphrase", type="password")
        submitted = st.form_submit_button("🔒 EXECUTE_SUPER_ENCRYPT // VIGENERE -> AES-256-CBC", type="primary")

    if submitted:
        if not (title and plaintext and vig_key and aes_key):
            st.warning("All fields and both cryptographic keys are required.")
        else:
            pt_digest = ui_cyberpunk.sha256_hex(plaintext)
            try:
                token = super_encryption.super_encrypt(plaintext, vig_key, aes_key)
                database.insert_secret_message(username, title, token, super_encryption.ALGORITHM_ID)
                ui_cyberpunk.log_cli(
                    "SUPER_ENC",
                    f"Encrypted dispatch '{title}' via Vigenère + AES-256-CBC ({len(token)} chars)",
                    digest=ui_cyberpunk.sha256_hex(token),
                    level="OK",
                )
                st.success("Super-encrypted dispatch stored in SQLite vault.")
            except NotImplementedError as exc:
                ui_cyberpunk.log_cli(
                    "SUPER_ENC",
                    f"Pipeline handler uninitialized for '{title}': {exc}",
                    digest=pt_digest,
                    level="WARN",
                )
                st.info(f"⚙️ **[SUBSYSTEM_STANDBY]** `{exc}`")
            except Exception as exc:
                ui_cyberpunk.log_cli("SUPER_ENC", f"Encryption error: {exc}", digest=pt_digest, level="CRIT")
                st.error(str(exc))

    rows = database.list_secret_messages(username)
    if rows:
        st.divider()
        for row in rows:
            with st.expander(f"📄 [{row['id']:03d}] {row['title']} // {row['created_at']}"):
                st.code(row["ciphertext"])
                d1, d2 = st.columns(2)
                vk = d1.text_input("Vigenère Key", type="password", key=f"vk_{row['id']}")
                ak = d2.text_input("AES-256 Passphrase", type="password", key=f"ak_{row['id']}")
                if st.button("🔓 DECRYPT_DISPATCH", key=f"dec_msg_{row['id']}"):
                    ct_digest = ui_cyberpunk.sha256_hex(row["ciphertext"])
                    try:
                        plain = super_encryption.super_decrypt(row["ciphertext"], vk, ak)
                        ui_cyberpunk.log_cli(
                            "SUPER_ENC",
                            f"Decrypted dispatch #{row['id']} ('{row['title']}')",
                            digest=ct_digest,
                            level="OK",
                        )
                        st.success(plain)
                    except NotImplementedError as exc:
                        ui_cyberpunk.log_cli("SUPER_ENC", str(exc), digest=ct_digest, level="WARN")
                        st.info(f"⚙️ {exc}")
                    except Exception as exc:
                        ui_cyberpunk.log_cli("SUPER_ENC", f"Decryption failed: {exc}", digest=ct_digest, level="CRIT")
                        st.error(str(exc))


def render_file_crypto_tab(username: str) -> None:
    st.subheader("📁 CHACHA20_STREAM_VAULT // BINARY DOCUMENT ENCRYPTION")
    st.caption("Symmetric stream cipher subsystem (`modules/file_crypto.py`) — persists to `encrypted_files` & `storage/files/`.")

    uploaded = st.file_uploader("Select Classified Binary (PDF, GeoJSON, KML, ZIP, DOCX)")
    passphrase = st.text_input("ChaCha20 Stream Passphrase", type="password", key="file_enc_pass")
    if st.button("🔐 ENCRYPT_STREAM // CHACHA20", type="primary", disabled=uploaded is None):
        if not passphrase:
            st.warning("Supply a passphrase before encrypting.")
        else:
            raw_bytes = uploaded.getvalue()
            raw_digest = ui_cyberpunk.sha256_hex(raw_bytes)
            try:
                bundle = file_crypto.encrypt_file_bytes(raw_bytes, passphrase)
                stored_name = f"{secrets.token_hex(16)}.enc"
                config.ensure_storage()
                (config.FILES_DIR / stored_name).write_bytes(bundle.ciphertext)
                database.insert_encrypted_file(
                    owner=username,
                    original_name=uploaded.name,
                    stored_name=stored_name,
                    mime_type=uploaded.type,
                    size_bytes=uploaded.size,
                    sha256_plain=bundle.sha256_plain,
                    kdf_salt=bundle.kdf_salt,
                    nonce=bundle.nonce,
                    algorithm=bundle.algorithm,
                )
                ui_cyberpunk.log_cli(
                    "CHACHA20",
                    f"Encrypted '{uploaded.name}' ({uploaded.size} B) -> {stored_name} | nonce={bundle.nonce}",
                    digest=bundle.sha256_plain,
                    level="OK",
                )
                st.success(f"Encrypted `{uploaded.name}` -> `{stored_name}`!")
            except NotImplementedError as exc:
                ui_cyberpunk.log_cli(
                    "CHACHA20",
                    f"Stream cipher handler uninitialized on '{uploaded.name}' ({uploaded.size} B)",
                    digest=raw_digest,
                    level="WARN",
                )
                st.info(f"⚙️ **[SUBSYSTEM_STANDBY]** `{exc}`")
            except Exception as exc:
                ui_cyberpunk.log_cli("CHACHA20", f"File encryption error: {exc}", digest=raw_digest, level="CRIT")
                st.error(str(exc))

    files = database.list_encrypted_files(username)
    if files:
        st.divider()
        for f in files:
            with st.expander(f"📦 {f['original_name']} ({f['size_bytes']} B // {f['created_at']})"):
                st.caption(f"SHA-256 Plaintext: `{f['sha256_plain']}` | Nonce: `{f['nonce']}`")
                dec_pw = st.text_input("Decryption Passphrase", type="password", key=f"fdec_{f['id']}")
                if st.button("🔓 DECRYPT_CHACHA20_STREAM", key=f"fbtn_{f['id']}"):
                    try:
                        cipher_bytes = (config.FILES_DIR / f["stored_name"]).read_bytes()
                        plain = file_crypto.decrypt_file_bytes(
                            cipher_bytes, dec_pw, f["kdf_salt"], f["nonce"], f["sha256_plain"]
                        )
                        ui_cyberpunk.log_cli(
                            "CHACHA20",
                            f"Decrypted & verified SHA-256 for '{f['original_name']}'",
                            digest=f["sha256_plain"],
                            level="OK",
                        )
                        st.download_button(
                            f"⬇️ DOWNLOAD {f['original_name']}",
                            data=plain,
                            file_name=f["original_name"],
                            mime=f["mime_type"] or "application/octet-stream",
                            key=f"dl_{f['id']}",
                        )
                    except NotImplementedError as exc:
                        ui_cyberpunk.log_cli("CHACHA20", str(exc), digest=f["sha256_plain"], level="WARN")
                        st.info(f"⚙️ {exc}")
                    except Exception as exc:
                        ui_cyberpunk.log_cli("CHACHA20", f"File decryption failed: {exc}", digest=f["sha256_plain"], level="CRIT")
                        st.error(str(exc))


def render_steganography_tab() -> None:
    st.subheader("🖼️ LSB_STEGANOGRAPHY // LOSSLESS PNG BIT-PLANE INJECTION")
    st.caption("Spatial-domain carrier subsystem (`modules/steganography.py`) — embeds payloads inside RGB LSBs.")

    tab_embed, tab_extract = st.tabs(["📥 [01] EMBED_PAYLOAD_LSB", "📤 [02] EXTRACT_PAYLOAD_LSB"])
    with tab_embed:
        cover = st.file_uploader("Upload Cover Image (PNG / BMP)", type=["png", "bmp"], key="stego_cover")
        secret_msg = st.text_area("Hidden Payload / Coordinates")
        stego_pw = st.text_input("Optional Stego Passphrase", type="password", key="stego_pw_in")
        if st.button("✨ INJECT_LSB_BITS // GENERATE STEGO PNG", type="primary", disabled=cover is None):
            cover_bytes = cover.getvalue()
            cover_digest = ui_cyberpunk.sha256_hex(cover_bytes)
            try:
                out_png = steganography.embed_message_lsb(cover_bytes, secret_msg, stego_pw or None)
                out_digest = ui_cyberpunk.sha256_hex(out_png)
                ui_cyberpunk.log_cli(
                    "LSB_STEGO",
                    f"Embedded {len(secret_msg.encode('utf-8'))} B into '{cover.name}'",
                    digest=out_digest,
                    level="OK",
                )
                st.success("Payload embedded into lossless PNG bit-plane!")
                st.download_button("⬇️ DOWNLOAD_STEGO.PNG", data=out_png, file_name="bagus_os_stego.png", mime="image/png")
            except NotImplementedError as exc:
                ui_cyberpunk.log_cli(
                    "LSB_STEGO",
                    f"LSB carrier handler uninitialized on '{cover.name}' ({len(cover_bytes)} B)",
                    digest=cover_digest,
                    level="WARN",
                )
                st.info(f"⚙️ **[SUBSYSTEM_STANDBY]** `{exc}`")
            except Exception as exc:
                ui_cyberpunk.log_cli("LSB_STEGO", f"Stego embed error: {exc}", digest=cover_digest, level="CRIT")
                st.error(str(exc))

    with tab_extract:
        stego_img = st.file_uploader("Upload Stego PNG Image", type=["png"], key="stego_in")
        stego_pw_out = st.text_input("Optional Stego Passphrase", type="password", key="stego_pw_out")
        if st.button("🔍 EXTRACT_LSB_PAYLOAD", type="primary", disabled=stego_img is None):
            stego_bytes = stego_img.getvalue()
            stego_digest = ui_cyberpunk.sha256_hex(stego_bytes)
            try:
                msg = steganography.extract_message_lsb(stego_bytes, stego_pw_out or None)
                ui_cyberpunk.log_cli(
                    "LSB_STEGO",
                    f"Extracted {len(msg)} chars from '{stego_img.name}'",
                    digest=stego_digest,
                    level="OK",
                )
                st.success("Decoded hidden payload:")
                st.code(msg)
            except NotImplementedError as exc:
                ui_cyberpunk.log_cli(
                    "LSB_STEGO",
                    f"LSB extract handler uninitialized on '{stego_img.name}'",
                    digest=stego_digest,
                    level="WARN",
                )
                st.info(f"⚙️ **[SUBSYSTEM_STANDBY]** `{exc}`")
            except Exception as exc:
                ui_cyberpunk.log_cli("LSB_STEGO", f"Stego extract error: {exc}", digest=stego_digest, level="CRIT")
                st.error(str(exc))


# --------------------------------------------------------------------------- #
# Main Gatekeeper Router
# --------------------------------------------------------------------------- #
def main() -> None:
    extra = [st.session_state.custom_dongle_path] if st.session_state.custom_dongle_path else None
    dongle_status = dongle_guard.scan_for_dongle(extra_paths=extra)

    # Log dongle transitions once per state change to avoid flooding on every widget click.
    dongle_state_sig = (dongle_status.valid, dongle_status.dongle_id, dongle_status.message)
    if st.session_state.last_logged_dongle_state != dongle_state_sig:
        st.session_state.last_logged_dongle_state = dongle_state_sig
        if dongle_status.valid:
            ui_cyberpunk.log_cli(
                "DONGLE_GUARD",
                f"HMAC-SHA256 hardware token verified at '{dongle_status.path}' "
                f"(label='{dongle_status.label}', vol='{dongle_status.volume_serial or 'UNBOUND'}')",
                digest=dongle_status.dongle_id,
                level="OK",
            )
        else:
            ui_cyberpunk.log_cli(
                "DONGLE_GUARD",
                f"CRITICAL_SYSTEM_HALT — {dongle_status.message}",
                digest=ui_cyberpunk.sha256_hex(dongle_status.message),
                level="CRIT",
            )

    # Gate 1: Hardware Dongle Check
    if not dongle_status.valid:
        st.session_state.authenticated_user = None
        render_dongle_lock_screen(dongle_status)
        return

    # Gate 2: Biometric + Cryptographic Login
    if not st.session_state.authenticated_user:
        render_auth_screen(dongle_status)
        return

    # Gate 3: Authenticated Netrunner Vault Dashboard
    username = st.session_state.authenticated_user
    with st.sidebar:
        st.markdown("## ⚡ BAGUS_OS // v2.6")
        st.caption("NETRUNNER CRYPTOGRAPHIC CLI")
        st.success(f"👤 OP_HANDLE: **{username.upper()}**")
        if st.session_state.auth_similarity is not None:
            st.caption(f"🧬 BIO_MATCH: **{st.session_state.auth_similarity:.1%}** (`AES-128-EAX`)")
        st.caption(f"🔑 DONGLE: **{dongle_status.label}**")
        st.divider()
        menu = st.radio(
            "SUBSYSTEM_ROUTER",
            [
                "📡 [00] NETRUNNER_OVERVIEW",
                "⛓️ [01] POW_BLOCKCHAIN_LEDGER",
                "📝 [02] SUPER_ENCRYPTION_ENGINE",
                "📁 [03] CHACHA20_FILE_VAULT",
                "🖼️ [04] LSB_STEGANOGRAPHY",
            ],
        )
        st.divider()
        c_s1, c_s2 = st.columns(2)
        with c_s1:
            if st.button("🧹 CLEAR_TTY", use_container_width=True):
                st.session_state.cli_logs = []
                ui_cyberpunk.log_cli("KERNEL", "TTY console buffer flushed by operator", level="INFO")
                st.rerun()
        with c_s2:
            if st.button("🚪 JACK_OUT", use_container_width=True):
                ui_cyberpunk.log_cli("KERNEL", f"Operator '{username}' jacked out — session locked", level="WARN")
                st.session_state.authenticated_user = None
                st.session_state.auth_similarity = None
                st.rerun()

    ui_cyberpunk.render_ascii_hud(
        current_step=3,
        operator=username,
        dongle_label=dongle_status.label,
    )

    if menu.startswith("📡"):
        render_overview_tab(username, dongle_status)
    elif menu.startswith("⛓️"):
        render_blockchain_tab(username)
    elif menu.startswith("📝"):
        render_super_encryption_tab(username)
    elif menu.startswith("📁"):
        render_file_crypto_tab(username)
    elif menu.startswith("🖼️"):
        render_steganography_tab()

    ui_cyberpunk.render_cli_console("GATE_03 // LIVE NETRUNNER CRYPTOGRAPHIC EXECUTION LOG")


if __name__ == "__main__":
    main()
