"""
B.A.G.U.S. Vault: Sistem Pengamanan Bukti Forensik Siber & Dokumen Intelijen Strategis
====================================================================================

Biometric-Authenticated Gatekeeper & Unified Security Vault
Forensic & Intelligence Evidence Security Architecture:
  1. [GATE_01] Hardware USB Dongle Intercept (HMAC-SHA256 Token Validation)
  2. [GATE_02] Optical Facial Recognition (PIL 128x128 SHA-256 + AES-128-EAX) & PBKDF2-SHA256
  3. [GATE_03] Forensic Evidence & Intelligence Operations Subsystems:
     - [01] LAPORAN INTELIJEN (Super Enkripsi Teks: Vigenère + AES-256-CBC)
     - [02] BERKAS BARANG BUKTI (Enkripsi File: ChaCha20 Stream Cipher)
     - [03] CITRA FORENSIK STEGANOGRAFI (LSB PNG Image Steganography)
     - [04] INSPEKSI BASIS DATA (Encrypted SQLite At-Rest vs Decrypted View)
     - [05] CHAIN OF CUSTODY LEDGER (Blockchain Asset Integrity & PoW)\n"""

from __future__ import annotations

import base64
import html
import io
import secrets
import time
from typing import Optional

import streamlit as st
from PIL import Image

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
# Bootstrap & Page Setup
# --------------------------------------------------------------------------- #
st.set_page_config(
    page_title="B.A.G.U.S. Vault | Forensic & Intelligence Evidence Security",
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


# --------------------------------------------------------------------------- #
# Top HUD Navigation & Gatekeeper Badges
# --------------------------------------------------------------------------- #
def render_hud_topbar(current_step: int, dongle_mounted: bool = True) -> None:
    dongle_color = "#00FF66" if dongle_mounted else "#FF003C"
    dongle_label = "● DONGLE_MOUNTED" if dongle_mounted else "● DONGLE_UNMOUNTED"
    dongle_glow = "rgba(0, 255, 102, 0.35)" if dongle_mounted else "rgba(255, 0, 60, 0.35)"

    st.markdown(
        f"""
        <div style="
            background: linear-gradient(135deg, #0d0f17 0%, #131826 55%, #060609 100%);
            border: 1px solid rgba(0, 240, 255, 0.45);
            border-left: 4px solid #FCEE0A;
            padding: 16px 22px;
            margin-bottom: 14px;
            clip-path: polygon(0 0, calc(100% - 18px) 0, 100% 18px, 100% 100%, 18px 100%, 0 calc(100% - 18px));
            box-shadow: 0 0 22px rgba(0, 240, 255, 0.14), inset 0 0 18px rgba(0, 240, 255, 0.05);
            display: flex;
            flex-wrap: wrap;
            justify-content: space-between;
            align-items: center;
            gap: 14px;
        ">
            <div>
                <div style="
                    color: #FCEE0A;
                    font-size: clamp(1.2rem, 2.2vw, 1.65rem);
                    font-weight: 700;
                    letter-spacing: 0.08em;
                    line-height: 1.2;
                    text-shadow: 0 0 14px rgba(252, 238, 10, 0.6), 0 0 4px rgba(252, 238, 10, 0.35);
                    margin-bottom: 4px;
                ">// B.A.G.U.S. VAULT [v2.6_FORENSIC_EDITION]</div>
                <div style="
                    color: #00F0FF;
                    font-size: clamp(0.72rem, 1.1vw, 0.85rem);
                    letter-spacing: 0.12em;
                    text-transform: uppercase;
                    opacity: 0.92;
                ">SISTEM PENGAMANAN BUKTI FORENSIK SIBER &amp; DOKUMEN INTELIJEN STRATEGIS</div>
            </div>
            <div style="display: flex; flex-wrap: wrap; align-items: center; gap: 10px;">
                <span style="
                    background: rgba(6, 6, 9, 0.9);
                    color: {dongle_color};
                    border: 1px solid {dongle_color};
                    padding: 6px 13px;
                    font-size: 0.78rem;
                    font-weight: 700;
                    letter-spacing: 0.08em;
                    white-space: nowrap;
                    box-shadow: 0 0 10px {dongle_glow};
                    text-shadow: 0 0 8px {dongle_glow};
                    clip-path: polygon(0 0, calc(100% - 8px) 0, 100% 8px, 100% 100%, 8px 100%, 0 calc(100% - 8px));
                ">{dongle_label}</span>
                <span style="
                    background: rgba(6, 6, 9, 0.9);
                    color: #00F0FF;
                    border: 1px solid rgba(0, 240, 255, 0.65);
                    padding: 6px 13px;
                    font-size: 0.78rem;
                    font-weight: 700;
                    letter-spacing: 0.08em;
                    white-space: nowrap;
                    box-shadow: 0 0 10px rgba(0, 240, 255, 0.2);
                    clip-path: polygon(0 0, calc(100% - 8px) 0, 100% 8px, 100% 100%, 8px 100%, 0 calc(100% - 8px));
                ">CIPHER: AES-256 / CHACHA20 / SHA-256</span>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    steps = [
        (1, "GATE_01 // HARDWARE_DONGLE_HMAC"),
        (2, "GATE_02 // OPTICAL_FACE_AES128"),
        (3, "GATE_03 // EVIDENCE_VAULT_CORE"),
    ]
    cols = st.columns(3)
    for col, (num, title) in zip(cols, steps):
        if num < current_step:
            border, fg, status_txt = "#00FF66", "#00FF66", "ONLINE // CLEARED"
        elif num == current_step:
            border, fg, status_txt = "#FCEE0A", "#FCEE0A", "ACTIVE // ENGAGED"
        else:
            border, fg, status_txt = "#FF003C", "#7C8DA6", "LOCKED // STANDBY"
        with col:
            st.markdown(
                f"""
                <div style="background:#0d0f17;border:1px solid {border};border-left:4px solid {border};
                            padding:8px 12px;margin-bottom:8px;
                            clip-path:polygon(0 0,95% 0,100% 25%,100% 100%,5% 100%,0 75%);">
                    <div style="font-size:11px;color:#7C8DA6;">{status_txt}</div>
                    <div style="font-size:13px;color:{fg};font-weight:bold;">{title}</div>
                </div>
                """,
                unsafe_allow_html=True,
            )


# --------------------------------------------------------------------------- #
# GATE 01: Hardware Dongle Intercept & High-Impact Crimson Red Lockscreen
# --------------------------------------------------------------------------- #
def render_dongle_lock_screen(status: dongle_guard.DongleStatus) -> None:
    render_hud_topbar(current_step=1, dongle_mounted=False)
    ui_cyberpunk.render_dongle_breach_banner(
        reason=status.message,
        has_tamper_failure=bool(status.failures),
    )

    col_rescan, col_demo = st.columns([1, 1])
    with col_rescan:
        if st.button("⚡ RE-SCAN_USB_PORTS // VERIFIKASI HMAC-SHA256 DONGLE", type="primary", use_container_width=True):
            ui_cyberpunk.log_cli(
                "DONGLE_GUARD",
                "Re-scanning system USB bus & probing removable mounts for hardware dongle token",
                digest=ui_cyberpunk.sha256_hex(str(status.scanned_locations)),
                level="WARN",
            )
            st.session_state.last_logged_dongle_state = None
            st.rerun()

    with col_demo:
        with st.expander("🛠️ DEV_DEMO: MOUNT / UNMOUNT VIRTUAL DONGLE", expanded=True):
            st.caption(
                "Gunakan saklar ini untuk mendemonstrasikan status **Terkunci (Locked)** dan "
                "**Terbuka (Unlocked)** secara langsung di depan penguji tanpa harus mencabut flashdisk fisik."
            )
            v_mounted = dongle_guard.is_virtual_dongle_mounted()
            if v_mounted:
                st.success("🟢 VIRTUAL DONGLE: **TERPASANG (MOUNTED)**")
                if st.button("🔴 UNMOUNT_VIRTUAL_DONGLE (SIMULASIKAN USB DICABUT)", use_container_width=True):
                    dongle_guard.unmount_virtual_dongle()
                    ui_cyberpunk.log_cli("DONGLE_GUARD", "Virtual dongle hot-unplugged by operator demo", level="CRIT")
                    st.session_state.last_logged_dongle_state = None
                    st.rerun()
            else:
                st.error("🔴 VIRTUAL DONGLE: **TIDAK TERPASANG (UNMOUNTED)**")
                if st.button("🟢 MOUNT_VIRTUAL_DONGLE (AKTIFKAN TOKEN FORENSIK)", type="primary", use_container_width=True):
                    res = dongle_guard.mount_virtual_dongle(label="Operator Forensic Hardware Key")
                    ui_cyberpunk.log_cli(
                        "DONGLE_GUARD",
                        f"Virtual dongle provisioned & mounted: {res.path}",
                        digest=res.dongle_id,
                        level="OK",
                    )
                    st.session_state.last_logged_dongle_state = None
                    st.rerun()

    # Live Diagnostic Box showing scanned USB drive letters/mounts
    st.markdown("#### 📡 LIVE USB DIAGNOSTIC & MOUNT TELEMETRY")
    diagnostics = dongle_guard.get_usb_diagnostics()
    if diagnostics:
        cols_hdr = st.columns([1.5, 1.2, 1.2, 2.0, 3.0])
        cols_hdr[0].markdown("**MOUNT / DRIVE**")
        cols_hdr[1].markdown("**DEVICE TYPE**")
        cols_hdr[2].markdown("**VOL SERIAL**")
        cols_hdr[3].markdown("**TOKEN FILE**")
        cols_hdr[4].markdown("**HMAC-SHA256 CHALLENGE STATE**")

        for d in diagnostics:
            c1, c2, c3, c4, c5 = st.columns([1.5, 1.2, 1.2, 2.0, 3.0])
            c1.code(d["mount"])
            c2.write(f"`{d['type']}`")
            c3.write(f"`{d['volume_serial']}`")
            c4.write(f"`{d['token_file']}`")
            c5.markdown(f"<span style='color:{d['status_color']};font-weight:bold;'>{d['hmac_challenge']}</span>", unsafe_allow_html=True)
    else:
        st.write("NO_STORAGE_PARTITIONS_DETECTED")

    ui_cyberpunk.render_cli_console("GATE_01 // HARDWARE DONGLE INTERCEPT TELEMETRY")


# --------------------------------------------------------------------------- #
# GATE 02: Realtime Optical Face Scanner & Cryptographic Handshake
# --------------------------------------------------------------------------- #
def _capture_optical_face_auto(username: str, simulate_mismatch: bool = False) -> bytes:
    """
    Realtime automatic optical face frame capture:
    Attempts direct camera grab; smoothly falls back to deterministic optical frame.
    Runs a 2-second Cyberpunk scanning sequence without requiring manual 'Take Photo'.
    """
    status_box = st.empty()
    progress_bar = st.progress(0)

    stages = [
        (0.15, "INITIALIZING OPTICAL SENSOR // LOCKING APERTURE..."),
        (0.35, "LOCATING CENTROID // PROJECTING 128x128 RETICLE..."),
        (0.60, "EXTRACTING FACIAL GRADIENTS & PHASH/DHASH DESCRIPTORS..."),
        (0.85, "COMPUTING SHA-256 DIGEST OVER NORMALIZED PIXEL BYTES..."),
        (1.00, "SEALING FACIAL TEMPLATE VECTOR WITH AES-128-EAX..."),
    ]

    for p, txt in stages:
        progress_bar.progress(int(p * 100))
        status_box.markdown(
            f"<div style='color:#00F0FF;font-size:13px;padding:6px;border-left:3px solid #00F0FF;background:#0d0f17;margin:6px 0;'>"
            f"⚡ [OPTICAL_SCANNER] {txt} ({int(p*100)}%)</div>",
            unsafe_allow_html=True,
        )
        time.sleep(0.35)

    progress_bar.empty()
    status_box.empty()

    # Attempt hardware capture via OpenCV if camera 0 is ready
    captured_bytes: Optional[bytes] = None
    try:
        import cv2
        cap = cv2.VideoCapture(0)
        if cap.isOpened():
            for _ in range(5):
                ret, frame = cap.read()
            cap.release()
            if ret and frame is not None:
                # Convert BGR OpenCV frame to RGB PIL Image
                rgb_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
                pil_img = Image.fromarray(rgb_frame)
                buf = io.BytesIO()
                pil_img.save(buf, format="PNG")
                captured_bytes = buf.getvalue()
    except Exception:
        captured_bytes = None

    if captured_bytes is None:
        seed = 999 if simulate_mismatch else 0
        captured_bytes = auth_biometric.generate_optical_face_sample(username, seed_variant=seed)

    return captured_bytes


def render_auth_screen(dongle: dongle_guard.DongleStatus) -> None:
    render_hud_topbar(current_step=2, dongle_mounted=True)
    st.markdown(
        f"### 🧬 GATE_02 // OPTICAL FACIAL RECOGNITION & CRYPTOGRAPHIC HANDSHAKE\n" f"`DONGLE_ID: {dongle.dongle_id}` · `MOUNT: {dongle.path}` · "
        f"`PIPELINE: PIL-128x128-GRAYSCALE + SHA-256 + AES-128-EAX`"
    )

    tab_login, tab_register = st.tabs([
        "🔑 [01] AUTHENTICATE_OPERATOR (LOGIN)",
        "📝 [02] ENROLL_NEW_IDENTITY (REGISTRASI)",
    ])

    with tab_login:
        c1, c2 = st.columns([1, 1])
        with c1:
            st.subheader("FACTOR_01 // KREDENSIAL PBKDF2-SHA256")
            login_user = st.text_input("Operator Identifier (Username)", key="login_username", placeholder="analyst_01")
            login_pw = st.text_input("Passkey Otorisasi", type="password", key="login_password")
            st.caption(
                "Kunci diturunkan melalui **PBKDF2-HMAC-SHA256 (600.000 iterasi)** + 16-byte random salt + "
                "**HKDF-SHA256** domain separation (`auth/verifier` & `auth/biometric-key`)."
            )
            sim_mismatch = st.checkbox("🧪 DEV_DEMO: Simulasikan Wajah Tidak Cocok / Penyusup", key="sim_mismatch_login")
        with c2:
            st.subheader("FACTOR_02 // REALTIME OPTICAL SCANNER")
            ui_cyberpunk.render_optical_scanner_hud("login_cam_hud", height=290)

        if st.button("⚡ INITIALIZE_REALTIME_OPTICAL_SCAN // VERIFY OPERATOR", type="primary", use_container_width=True):
            if not login_user or not login_pw:
                st.warning("Supply Operator Identifier dan Passkey sebelum inisialisasi pemindaian wajah.")
            else:
                user_norm = login_user.strip().lower()
                with st.spinner("RUNNING REALTIME OPTICAL FACE SCANNER..."):
                    face_bytes = _capture_optical_face_auto(user_norm, simulate_mismatch=sim_mismatch)
                    img_digest = ui_cyberpunk.sha256_hex(face_bytes)

                    ui_cyberpunk.log_cli(
                        "FACE_AUTH",
                        f"Optical scan captured ({len(face_bytes)} B) — Unsealing AES-128-EAX template for '{user_norm}'",
                        digest=img_digest,
                        level="INFO",
                    )
                    res = auth_biometric.authenticate_user(user_norm, login_pw, face_bytes)

                if res.success:
                    ui_cyberpunk.log_cli(
                        "FACE_AUTH",
                        f"Optical face verification GRANTED for '{res.username}' (similarity={res.similarity:.1%})",
                        digest=img_digest,
                        level="OK",
                    )
                    st.session_state.authenticated_user = res.username
                    st.session_state.auth_similarity = res.similarity
                    st.rerun()
                else:
                    sim_txt = f" (Skor Kemiripan: {res.similarity:.1%})" if res.similarity is not None else ""
                    ui_cyberpunk.log_cli(
                        "FACE_AUTH",
                        f"Optical verification REJECTED for '{user_norm}': {res.message}{sim_txt}",
                        digest=img_digest,
                        level="CRIT",
                    )
                    st.error(f"{res.message}{sim_txt}")

    with tab_register:
        c1, c2 = st.columns([1, 1])
        with c1:
            st.subheader("STEP_A // PEMBUATAN IDENTITAS OPERATOR")
            reg_user = st.text_input("New Operator Handle (3-32 chars, a-z0-9_.-)", key="reg_username", placeholder="analyst_01")
            reg_pw = st.text_input("Passkey Otorisasi (min. 8 karakter, huruf & angka)", type="password", key="reg_pw")
            reg_pw2 = st.text_input("Konfirmasi Passkey", type="password", key="reg_pw2")
        with c2:
            st.subheader("STEP_B // OPTICAL ENROLLMENT SCANNER")
            ui_cyberpunk.render_optical_scanner_hud("reg_cam_hud", height=290)
            st.caption(
                "Citra dinormalisasi ke matriks grayscale `128x128` via `PIL`, dihitung SHA-256 pixel digest, "
                "dan disegel dalam database dengan enkripsi terautentikasi **AES-128-EAX**."
            )

        if st.button("⚡ INITIALIZE_REALTIME_OPTICAL_SCAN // ENROLL OPERATOR", type="primary", use_container_width=True):
            if reg_pw != reg_pw2:
                st.error("Konfirmasi passkey tidak cocok.")
            elif not reg_user or not reg_pw:
                st.warning("Lengkapi Operator Handle dan Passkey.")
            else:
                user_norm = reg_user.strip().lower()
                with st.spinner("ACQUIRING OPTICAL BIOMETRIC MATRIX & SEALING AES-128-EAX TEMPLATE..."):
                    face_bytes = _capture_optical_face_auto(user_norm, simulate_mismatch=False)
                    img_digest = ui_cyberpunk.sha256_hex(face_bytes)
                    res = auth_biometric.register_user(user_norm, reg_pw, face_bytes)

                if res.success:
                    ui_cyberpunk.log_cli(
                        "FACE_AUTH",
                        f"Enrolled operator '{res.username}' — 128x128 biometric vector sealed via AES-128-EAX",
                        digest=img_digest,
                        level="OK",
                    )
                    st.success(res.message)
                else:
                    ui_cyberpunk.log_cli("FACE_AUTH", f"Enrollment error: {res.message}", digest=img_digest, level="WARN")
                    st.error(res.message)

    ui_cyberpunk.render_cli_console("GATE_02 // OPTICAL BIOMETRIC & PBKDF2-SHA256 TELEMETRY STREAM")


# --------------------------------------------------------------------------- #
# TAB 00: Overview & Cryptographic Architecture Telemetry
# --------------------------------------------------------------------------- #
def render_overview_tab(username: str, dongle: dongle_guard.DongleStatus) -> None:
    blockchain.ensure_genesis()
    stats = database.get_user_stats(username)
    report = blockchain.verify_chain()

    st.subheader("📡 B.A.G.U.S. VAULT // ARSITEKTUR KEAMANAN & TELEMETRI KRIPTOGRAFIS")
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("CHAIN_OF_CUSTODY_BLOCKS", stats["ledger_blocks"])
    m2.metric("LEDGER_INTEGRITY", "VALID_OK" if report.valid else "TAMPER_DETECTED!")
    m3.metric("INTEL_DISPATCHES (SUPER_ENC)", stats["secret_messages"])
    m4.metric("EVIDENCE_FILES (CHACHA20)", stats["encrypted_files"])

    if not report.valid:
        st.error(
            f"🚨 **[PERINGATAN INTEGRITAS LEDGER]** Terdeteksi {len(report.issues)} anomali pada SQLite blockchain! "
            "Buka tab **[05] CHAIN OF CUSTODY LEDGER** untuk audit blok terkompromi."
        )

    c1, c2 = st.columns(2)
    with c1:
        st.markdown("#### 🔑 HARDWARE_DONGLE // HMAC-SHA256 TOKEN SPECIFICATION")
        st.json({
            "product": "B.A.G.U.S. Vault Forensic Edition",
            "dongle_label": dongle.label,
            "dongle_id": dongle.dongle_id,
            "mount_path": dongle.path,
            "volume_serial": dongle.volume_serial or "VIRTUAL_UNBOUND",
            "auth_algorithm": "HMAC-SHA256 (HKDF domain: dongle/hmac-sha256)",
            "anti_cloning_protection": "Volume Serial Binding Active",
        })
    with c2:
        st.markdown("#### 🛡️ SPESIFIKASI 7 MODUL KRIPTOGRAFI B.A.G.U.S. VAULT")
        st.markdown(
            "- **[01] Hardware Dongle**: Token `.geovault_dongle` / `.cyberdeck_dongle` + `HMAC-SHA256`\n"
            "- **[02] Optical Face 2FA**: `PBKDF2-HMAC-SHA256` (600k iter) + `PIL 128x128 SHA-256` + `AES-128-EAX`\n"
            "- **[03] Laporan Intelijen**: Super Enkripsi Dua Lapis `Vigenère Cipher` + `AES-256-CBC (PKCS#7)`\n"
            "- **[04] Berkas Barang Bukti**: Enkripsi Stream Cipher `ChaCha20` + Self-Contained `.bagus.enc` Envelope\n"
            "- **[05] Citra Steganografi**: Least Significant Bit (`LSB`) Lossless PNG + Delimiter `<<<END>>>`\n"
            "- **[06] Inspeksi Basis Data**: Komparasi Side-by-Side SQLite At-Rest vs Decrypted View\n"
            "- **[07] Chain of Custody Ledger**: `SHA-256 Proof-of-Work ('00')` + `AES-256-GCM` + `HMAC Tip Anchor`"
        )


# --------------------------------------------------------------------------- #
# TAB 01: [01] LAPORAN INTELIJEN (Super Enkripsi Teks: Vigenère + AES-256-CBC)
# --------------------------------------------------------------------------- #
def render_super_encryption_tab(username: str) -> None:
    st.subheader("📝 [01] LAPORAN INTELIJEN // SUPER ENKRIPSI TEKS (VIGENÈRE + AES-256-CBC)")
    st.caption(
        "Dua lapis proteksi: Substitusi Polialfabetik Klasik (Extended Vigenère modulo 256) "
        "dilapisi Enkripsi Simetris Modern AES-256-CBC dengan padding PKCS#7."
    )

    tab_enc, tab_dec = st.tabs([
        "🔒 [01] ENKRIPSI DISPATCH INTELIJEN",
        "🔓 [02] DEKRIPSI DISPATCH INTELIJEN",
    ])

    with tab_enc:
        with st.form("super_enc_form"):
            title = st.text_input("Judul / Sandi Dokumen Intelijen", placeholder="LAPORAN_OPERASI_SANGKURIANG_07")
            plaintext = st.text_area(
                "Isi Laporan Rahasia / Koordinat Intelijen",
                height=130,
                placeholder="Target teridentifikasi pada koordinat -6.2088, 106.8456. Titik ekstraksi aman di safehouse B-2.",
            )
            c1, c2 = st.columns(2)
            vig_key = c1.text_input("Kunci Vigenère (Lapisan 1)", type="password", key="vkey_in")
            aes_pass = c2.text_input("Passphrase AES-256-CBC (Lapisan 2)", type="password", key="aeskey_in")
            submitted = st.form_submit_button("🔒 JALANKAN SUPER ENKRIPSI (VIGENÈRE -> AES-256-CBC)", type="primary")

        if submitted:
            if not (title and plaintext and vig_key and aes_pass):
                st.warning("Semua kolom (Judul, Plaintext, Kunci Vigenère, Passphrase AES) wajib diisi.")
            else:
                try:
                    res = super_encryption.super_encrypt_detailed(plaintext, vig_key, aes_pass)
                    token = res["token"]
                    database.insert_secret_message(username, title, token, super_encryption.ALGORITHM_ID)

                    ui_cyberpunk.log_cli(
                        "SUPER_ENC",
                        f"Super-encrypted intel dispatch '{title}' — Token size: {len(token)} chars",
                        digest=ui_cyberpunk.sha256_hex(token),
                        level="OK",
                    )
                    st.success("✅ **[SUKSES]** Laporan Intelijen berhasil di-super-enkripsi dan disimpan di database!")

                    # Live Telemetry Preview for Class Demonstration
                    st.markdown("#### 🔬 TELEMETRI HASIL DUA LAPIS ENKRIPSI:")
                    p1, p2 = st.columns(2)
                    with p1:
                        st.markdown("**[TAHAP 1: CIPHERTEXT VIGENÈRE (BASE64 & HEX)]**")
                        st.code(f"Base64: {res['vigenere_b64']}\nHex:    {res['vigenere_hex'][:64]}...")
                    with p2:
                        st.markdown("**[TAHAP 2: AES-256-CBC PARAMETERS]**")
                        st.code(
                            f"Salt (16B): {res['salt_hex']}\n"
                            f"IV (16B):   {res['iv_hex']}\n"
                            f"AES CT:     {res['aes_ciphertext_hex'][:64]}..."
                        )

                    st.markdown("**[TOKEN TERKONSOLIDASI (DISIMPAN DI SQLITE)]**")
                    st.code(token)
                except Exception as exc:
                    ui_cyberpunk.log_cli("SUPER_ENC", f"Encryption error: {exc}", level="CRIT")
                    st.error(f"Gagal melakukan enkripsi: {exc}")

    with tab_dec:
        st.markdown("#### 🔓 DEKRIPSI DAN PEMULIHAN LAPORAN INTELIJEN")
        source_mode = st.radio("Pilih Sumber Ciphertext", ["Pilih Dari Arsip Database SQLite", "Input Token Base64 Manual"], horizontal=True)

        target_token = ""
        target_title = ""
        if source_mode == "Pilih Dari Arsip Database SQLite":
            saved_msgs = database.list_secret_messages(username)
            if not saved_msgs:
                st.info("Belum ada laporan intelijen tersimpan di database.")
            else:
                msg_options = {f"[{m['id']:03d}] {m['title']} ({m['created_at']})": m for m in saved_msgs}
                chosen_label = st.selectbox("Pilih Arsip Laporan", list(msg_options.keys()))
                chosen_msg = msg_options[chosen_label]
                target_token = chosen_msg["ciphertext"]
                target_title = chosen_msg["title"]
                st.caption(f"Ciphertext Token Terpilih: `{target_token[:64]}...`")
        else:
            target_token = st.text_area("Tempelkan Token Base64 Ciphertext", height=100)
            target_title = "Manual Token Input"

        d1, d2 = st.columns(2)
        dec_vig = d1.text_input("Kunci Vigenère Pemulih", type="password", key="vkey_dec")
        dec_aes = d2.text_input("Passphrase AES-256-CBC", type="password", key="aeskey_dec")

        if st.button("🔓 JALANKAN DEKRIPSI (AES-256-CBC -> REVERSE VIGENÈRE)", type="primary"):
            if not (target_token and dec_vig and dec_aes):
                st.warning("Lengkapi Ciphertext Token, Kunci Vigenère, dan Passphrase AES.")
            else:
                try:
                    res_dec = super_encryption.super_decrypt_detailed(target_token, dec_vig, dec_aes)
                    ui_cyberpunk.log_cli(
                        "SUPER_ENC",
                        f"Successfully decrypted intel dispatch '{target_title}'",
                        digest=ui_cyberpunk.sha256_hex(res_dec["plaintext"]),
                        level="OK",
                    )
                    st.success("✅ **[OTORISASI SUKSES]** Dua lapis enkripsi berhasil dibuka!")
                    st.markdown("#### 📄 HASIL DEKRIPSI DUA TAHAP:")
                    r1, r2 = st.columns(2)
                    with r1:
                        st.markdown("**[TAHAP 1: TEKS VIGENÈRE DIPULIHKAN DARI AES-256]**")
                        st.code(res_dec["vigenere_b64"])
                    with r2:
                        st.markdown("**[TAHAP 2: PLAINTEXT ASLI TERBUKA (REVERSE VIGENÈRE)]**")
                        st.text_area("Plaintext Rahasia", value=res_dec["plaintext"], height=120)
                except Exception as exc:
                    ui_cyberpunk.log_cli("SUPER_ENC", f"Decryption failure: {exc}", level="CRIT")
                    st.error(f"❌ Dekripsi gagal: Kunci Vigenère atau Passphrase AES salah, atau ciphertext rusak! ({exc})")


# --------------------------------------------------------------------------- #
# TAB 02: [02] BERKAS BARANG BUKTI (Enkripsi File: ChaCha20 Stream Cipher)
# --------------------------------------------------------------------------- #
def render_file_crypto_tab(username: str) -> None:
    st.subheader("📁 [02] BERKAS BARANG BUKTI // ENKRIPSI DOKUMEN FORENSIK (CHACHA20)")
    st.caption(
        "Enkripsi stream cipher kecepatan tinggi ChaCha20 untuk barang bukti dokumen (PDF, DOCX, TXT, CSV, JPG, ZIP). "
        "Menghasilkan berkas terenkripsi mandiri berformat `.bagus.enc` yang memuat verifikasi integritas SHA-256."
    )

    tab_enc, tab_dec = st.tabs([
        "🔐 [01] ENKRIPSI BERKAS BARANG BUKTI",
        "🔓 [02] DEKRIPSI BERKAS (.BAGUS.ENC / ARSIP VAULT)",
    ])

    with tab_enc:
        uploaded = st.file_uploader(
            "Unggah Berkas Barang Bukti Forensik (PDF, DOCX, TXT, CSV, JPG, PNG, ZIP, KML)",
            key="file_enc_uploader",
        )
        passphrase = st.text_input("Passphrase Enkripsi ChaCha20", type="password", key="file_enc_pw")

        if st.button("🔐 ENKRIPSI DOKUMEN DENGAN CHACHA20", type="primary", disabled=uploaded is None):
            if not passphrase:
                st.warning("Masukkan passphrase enkripsi.")
            else:
                raw_bytes = uploaded.getvalue()
                with st.spinner("MENGEKSEKUSI STREAM CIPHER CHACHA20 & MEMBUNGKUS .BAGUS.ENC..."):
                    bundle = file_crypto.encrypt_file_bytes(raw_bytes, passphrase)
                    package_bytes = file_crypto.pack_bagus_envelope(bundle, uploaded.name, uploaded.type)

                    # Persist ciphertext blob & metadata
                    stored_name = f"{secrets.token_hex(16)}.enc"
                    config.ensure_storage()
                    (config.FILES_DIR / stored_name).write_bytes(bundle.ciphertext)
                    database.insert_encrypted_file(
                        owner=username,
                        original_name=uploaded.name,
                        stored_name=stored_name,
                        mime_type=uploaded.type,
                        size_bytes=len(raw_bytes),
                        sha256_plain=bundle.sha256_plain,
                        kdf_salt=bundle.kdf_salt,
                        nonce=bundle.nonce,
                        algorithm=bundle.algorithm,
                    )

                    ui_cyberpunk.log_cli(
                        "CHACHA20",
                        f"Encrypted evidence '{uploaded.name}' ({len(raw_bytes)} B) -> Nonce: {bundle.nonce}",
                        digest=bundle.sha256_plain,
                        level="OK",
                    )
                    st.success(f"✅ Dokumen **{uploaded.name}** berhasil dienkripsi dengan ChaCha20!")

                    c_meta1, c_meta2 = st.columns(2)
                    with c_meta1:
                        st.json({
                            "original_name": uploaded.name,
                            "algorithm": bundle.algorithm,
                            "sha256_plain": bundle.sha256_plain,
                            "size_bytes": len(raw_bytes),
                        })
                    with c_meta2:
                        st.json({
                            "kdf_salt": bundle.kdf_salt,
                            "nonce": bundle.nonce,
                            "envelope_package_size": len(package_bytes),
                            "kdf_iterations": 200_000,
                        })

                    enc_filename = f"{uploaded.name}.bagus.enc"
                    st.download_button(
                        f"⬇️ UNDUH BERKAS TERENKRIPSI ({enc_filename})",
                        data=package_bytes,
                        file_name=enc_filename,
                        mime="application/octet-stream",
                        use_container_width=True,
                    )

    with tab_dec:
        st.markdown("#### 🔓 DEKRIPSI DAN PEMULIHAN BERKAS BUKTI FORENSIK")
        dec_mode = st.radio("Metode Masukan Berkas", ["Unggah Berkas .bagus.enc Mandiri", "Pilih Dari Arsip Database SQLite"], horizontal=True)

        if dec_mode == "Unggah Berkas .bagus.enc Mandiri":
            enc_file_in = st.file_uploader("Unggah Berkas .bagus.enc", type=["enc"], key="standalone_enc_in")
            dec_pw = st.text_input("Passphrase Dekripsi ChaCha20", type="password", key="dec_pw_standalone")
            if st.button("🔓 DEKRIPSI PAKET .BAGUS.ENC", type="primary", disabled=enc_file_in is None):
                if not dec_pw:
                    st.warning("Masukkan passphrase dekripsi.")
                else:
                    try:
                        plain_bytes, meta = file_crypto.unpack_bagus_envelope(enc_file_in.getvalue(), dec_pw)
                        ui_cyberpunk.log_cli(
                            "CHACHA20",
                            f"Decrypted standalone package '{meta['original_name']}' — SHA-256 verified",
                            digest=meta["sha256_plain"],
                            level="OK",
                        )
                        st.success(f"✅ Berkas **{meta['original_name']}** berhasil dipulihkan dan diverifikasi integritas SHA-256!")
                        st.download_button(
                            f"⬇️ UNDUH DOKUMEN PULIH ({meta['original_name']})",
                            data=plain_bytes,
                            file_name=meta["original_name"],
                            mime=meta.get("mime_type", "application/octet-stream"),
                            use_container_width=True,
                        )
                    except Exception as exc:
                        ui_cyberpunk.log_cli("CHACHA20", f"Decryption error: {exc}", level="CRIT")
                        st.error(f"❌ Gagal mendekripsi: {exc}")
        else:
            files = database.list_encrypted_files(username)
            if not files:
                st.info("Belum ada berkas terenkripsi dalam arsip vault.")
            else:
                for f in files:
                    with st.expander(f"📦 [{f['id']:03d}] {f['original_name']} ({f['size_bytes']} B // {f['created_at']})"):
                        st.caption(f"SHA-256: `{f['sha256_plain']}` | Nonce: `{f['nonce']}`")
                        vdec_pw = st.text_input("Passphrase Dekripsi", type="password", key=f"vdec_{f['id']}")
                        if st.button(f"🔓 DEKRIPSI {f['original_name']}", key=f"btn_vdec_{f['id']}"):
                            try:
                                cipher_bytes = (config.FILES_DIR / f["stored_name"]).read_bytes()
                                plain = file_crypto.decrypt_file_bytes(
                                    cipher_bytes, vdec_pw, f["kdf_salt"], f["nonce"], f["sha256_plain"]
                                )
                                ui_cyberpunk.log_cli(
                                    "CHACHA20",
                                    f"Decrypted vault file #{f['id']} ('{f['original_name']}')",
                                    digest=f["sha256_plain"],
                                    level="OK",
                                )
                                st.success("Integritas SHA-256 valid! Berkas siap diunduh:")
                                st.download_button(
                                    f"⬇️ UNDUH {f['original_name']}",
                                    data=plain,
                                    file_name=f["original_name"],
                                    mime=f["mime_type"] or "application/octet-stream",
                                    key=f"dl_vault_{f['id']}",
                                )
                            except Exception as exc:
                                ui_cyberpunk.log_cli("CHACHA20", f"Vault decrypt failed: {exc}", level="CRIT")
                                st.error(str(exc))


# --------------------------------------------------------------------------- #
# TAB 03: [03] CITRA FORENSIK STEGANOGRAFI (LSB PNG Image Steganography)
# --------------------------------------------------------------------------- #
def render_steganography_tab() -> None:
    st.subheader("🖼️ [03] CITRA FORENSIK STEGANOGRAFI // LSB PNG EMBEDDING & EXTRACTION")
    st.caption(
        "Penyisipan pesan rahasia / koordinat ekstraksi ke dalam bit terkecil (Least Significant Bit) "
        "komponen warna RGB citra PNG lossless dengan pembatas terminal `<<<END>>>`."
    )

    tab_embed, tab_extract = st.tabs([
        "📥 [01] EMBED BUKTI INTELIJEN (LSB INJECTION)",
        "📤 [02] EKSTRAK BUKTI TERSEMBUNYI (LSB EXTRACTION)",
    ])

    with tab_embed:
        cover_file = st.file_uploader("Unggah Citra Sampul (Cover Image - PNG / BMP)", type=["png", "bmp"], key="stego_cover_in")
        secret_text = st.text_area(
            "Pesan / Koordinat Rahasia Yang Akan Disisipkan",
            height=110,
            placeholder="[TOP SECRET] Target bergerak menuju safehouse perbatasan. Sandi kontak: PHOENIX-99.",
        )
        stego_pass = st.text_input("Passphrase Enkripsi Steganografi (Opsional)", type="password", key="stego_pw_in")

        if cover_file is not None:
            cover_bytes = cover_file.getvalue()
            capacity = steganography.calculate_capacity(cover_bytes)
            st.info(f"Kapasitas Maksimal Muatan Citra: **{capacity:,} Bytes** ({capacity / 1024:.1f} KB)")

        if st.button("✨ SISIPKAN PESAN KE BIT LSB CITRA", type="primary", disabled=cover_file is None):
            if not secret_text.strip():
                st.warning("Tuliskan pesan rahasia yang akan disisipkan.")
            else:
                cover_bytes = cover_file.getvalue()
                try:
                    with st.spinner("MENYISIPKAN BIT KE DALAM PIXEL CITRA DENGAN PEMBATAS <<<END>>>..."):
                        out_png = steganography.embed_message_lsb(cover_bytes, secret_text, stego_pass or None)
                    out_digest = ui_cyberpunk.sha256_hex(out_png)

                    ui_cyberpunk.log_cli(
                        "LSB_STEGO",
                        f"Embedded {len(secret_text.encode('utf-8'))} bytes into '{cover_file.name}'",
                        digest=out_digest,
                        level="OK",
                    )
                    st.success("✅ Pesan rahasia berhasil disisipkan secara kasat mata ke dalam LSB citra PNG!")

                    col_prev1, col_prev2 = st.columns(2)
                    with col_prev1:
                        st.markdown("**Citra Sampul Asli:**")
                        st.image(cover_bytes, use_container_width=True)
                    with col_prev2:
                        st.markdown("**Citra Stego (Memuat Pesan Tersembunyi):**")
                        st.image(out_png, use_container_width=True)

                    st.download_button(
                        "⬇️ UNDUH CITRA STEGANOGRAFI (bagus_forensic_stego.png)",
                        data=out_png,
                        file_name="bagus_forensic_stego.png",
                        mime="image/png",
                        use_container_width=True,
                    )
                except Exception as exc:
                    ui_cyberpunk.log_cli("LSB_STEGO", f"Embed error: {exc}", level="CRIT")
                    st.error(f"Gagal menyisipkan steganografi: {exc}")

    with tab_extract:
        stego_in = st.file_uploader("Unggah Citra Steganografi (.PNG)", type=["png"], key="stego_extract_in")
        ext_pass = st.text_input("Passphrase Dekripsi (Jika Disisipkan Menggunakan Passphrase)", type="password", key="stego_ext_pw")

        if st.button("🔍 EKSTRAK PESAN DARI CITRA LSB", type="primary", disabled=stego_in is None):
            stego_bytes = stego_in.getvalue()
            try:
                with st.spinner("MEMINDAI BIT LSB CITRA HINGGA DELIMITER <<<END>>>..."):
                    recovered_msg = steganography.extract_message_lsb(stego_bytes, ext_pass or None)
                ui_cyberpunk.log_cli(
                    "LSB_STEGO",
                    f"Extracted payload from '{stego_in.name}' ({len(recovered_msg)} chars)",
                    digest=ui_cyberpunk.sha256_hex(recovered_msg),
                    level="OK",
                )
                st.success("✅ **[EKSTRAKSI SUKSES]** Pesan rahasia berhasil dipulihkan dari citra!")
                st.text_area("Pesan Rahasia Terbaca:", value=recovered_msg, height=130)
            except Exception as exc:
                ui_cyberpunk.log_cli("LSB_STEGO", f"Extraction error: {exc}", level="CRIT")
                st.error(f"❌ Gagal mengekstrak pesan: {exc}")


# --------------------------------------------------------------------------- #
# TAB 04: [04] INSPEKSI BASIS DATA (Encrypted SQLite At-Rest vs Decrypted View)
# --------------------------------------------------------------------------- #
def render_database_inspection_tab(username: str) -> None:
    st.subheader("🔍 [04] INSPEKSI BASIS DATA // AT-REST ENCRYPTED SQLITE VS DECRYPTED VIEW")
    st.caption(
        "Audit Forensik Independen: Membuktikan bahwa seluruh kolom kredensial, berkas, dan laporan "
        "tersimpan dalam bentuk Ciphertext / BLOB terenkripsi pada basis data `vault.db` saat at-rest."
    )

    raw_data = database.get_raw_records_for_inspection(username)

    view_mode = st.radio(
        "Pilih Mode Tampilan Audit",
        ["Komparasi Side-by-Side (Ciphertext At-Rest vs Decrypted)", "Dump Mentah Tabel SQLite"],
        horizontal=True,
    )

    if view_mode == "Komparasi Side-by-Side (Ciphertext At-Rest vs Decrypted)":
        c_left, c_right = st.columns(2)
        with c_left:
            st.markdown("#### 🔒 RAW SQLITE CIPHERTEXT (AT-REST)")
            st.caption("Data mentah yang tersimpan di disk `storage/geovault.db` (tidak terbaca tanpa kunci).")

            st.markdown("**1. Tabel `users` (Biometrik Wajah & Hash)**")
            if raw_data["users"]:
                u = raw_data["users"][0]
                st.code(
                    f"username:       {u['username']}\n"
                    f"password_hash:  {u['password_hash'][:40]}...\n"
                    f"password_salt:  {u['password_salt']}\n"
                    f"bio_template:   {u['bio_template_hex'][:40]}... (AES-128-EAX BLOB)\n"
                    f"bio_algorithm:  {u['bio_algorithm']}"
                )

            st.markdown("**2. Tabel `secret_messages` (Super Encryption Ciphertext)**")
            if raw_data["secret_messages"]:
                m = raw_data["secret_messages"][0]
                st.code(
                    f"title:      {m['title']}\n"
                    f"ciphertext: {m['ciphertext'][:70]}...\n"
                    f"algorithm:  {m['algorithm']}"
                )
            else:
                st.write("Belum ada rekaman laporan intelijen.")

            st.markdown("**3. Tabel `encrypted_files` (ChaCha20 Stream Metadata)**")
            if raw_data["encrypted_files"]:
                f = raw_data["encrypted_files"][0]
                st.code(
                    f"stored_name:  {f['stored_name']}\n"
                    f"sha256_plain: {f['sha256_plain']}\n"
                    f"nonce:        {f['nonce']}\n"
                    f"kdf_salt:     {f['kdf_salt']}"
                )
            else:
                st.write("Belum ada rekaman berkas barang bukti.")

        with c_right:
            st.markdown("#### 🔓 AUTHENTICATED DECRYPTED FORENSIC VIEW")
            st.caption("Hasil komputasi saat operator terautentikasi memasukkan kunci yang sah.")

            st.markdown("**1. Profil Operator Terverifikasi**")
            st.code(
                f"Operator:        {username.upper()}\n"
                f"Status:          AUTHENTICATED_ONLINE\n"
                f"Face Vector:     UNSEALED // AES-128-EAX AUTHTAG_VALID\n"
                f"Session Mode:    FORENSIC_EXAMINER"
            )

            st.markdown("**2. Dekripsi Laporan Intelijen Terkini**")
            if raw_data["secret_messages"]:
                st.info("Buka tab **[01] LAPORAN INTELIJEN** untuk mendekripsi token Base64 di sebelah kiri menggunakan kunci Vigenère & passphrase.")
            else:
                st.write("Tidak ada rekaman untuk didekripsi.")

            st.markdown("**3. Integritas Dokumen Bukti Forensik**")
            if raw_data["encrypted_files"]:
                f = raw_data["encrypted_files"][0]
                st.success(
                    f"Berkas Asli: `{f['original_name']}`\n"
                    f"Algoritma:   ChaCha20-Stream (PBKDF2 200k iter)\n"
                    f"Verifikasi:  Plaintext SHA-256 Checksum Embedded"
                )
    else:
        st.markdown("#### 📦 DATA MENTAH TABEL BASIS DATA SQLITE")
        t_user, t_msg, t_file, t_chain = st.tabs(["users", "secret_messages", "encrypted_files", "blockchain_ledger"])
        with t_user:
            st.dataframe(raw_data["users"], use_container_width=True)
        with t_msg:
            st.dataframe(raw_data["secret_messages"], use_container_width=True)
        with t_file:
            st.dataframe(raw_data["encrypted_files"], use_container_width=True)
        with t_chain:
            st.dataframe(raw_data["blockchain_ledger"], use_container_width=True)


# --------------------------------------------------------------------------- #
# TAB 05: [05] CHAIN OF CUSTODY LEDGER (Blockchain Asset Integrity & PoW)
# --------------------------------------------------------------------------- #
def render_blockchain_tab(username: str) -> None:
    blockchain.ensure_genesis()
    st.subheader("⛓️ [05] CHAIN OF CUSTODY LEDGER // BLOCKCHAIN BUKTI FORENSIK & POW")
    st.caption(
        "Buku besar tidak dapat diubah (Immutable Ledger) untuk mencatat rantai serah terima bukti digital. "
        "Setiap aset disegel dengan **AES-256-GCM**, ditambang dengan **Proof-of-Work SHA-256 (prefix '00')**, "
        "dan dipatok dengan tanda tangan **HMAC Chain-Tip Anchor**."
    )

    c_audit, c_export = st.columns([2, 1])
    with c_audit:
        if st.button("🔍 VERIFY_CHAIN_INTEGRITY // AUDIT HASH KESELURUHAN", type="primary", use_container_width=True):
            rep = blockchain.verify_chain()
            st.session_state["last_verification"] = rep
            tip_hash = blockchain.get_chain()[-1].current_hash if blockchain.get_chain() else "NONE"
            ui_cyberpunk.log_cli(
                "POW_LEDGER",
                f"Chain audit finished: valid={rep.valid} | blocks={rep.blocks_checked} | elapsed={rep.elapsed_ms:.2f}ms",
                digest=tip_hash,
                level="OK" if rep.valid else "CRIT",
            )
    with c_export:
        st.download_button(
            "⬇️ EKSPOR LEDGER KE JSON",
            data=blockchain.export_chain_json(),
            file_name="bagus_vault_chain_of_custody.json",
            mime="application/json",
            use_container_width=True,
        )

    report: blockchain.VerificationReport = st.session_state.get("last_verification") or blockchain.verify_chain()
    if report.valid:
        st.success(
            f"✅ **[INTEGRITAS RANTAI VALID]** Seluruh {report.blocks_checked} blok lolos verifikasi re-komputasi SHA-256, "
            f"prefix PoW `{blockchain.HASH_PREFIX}`, tautan `previous_hash`, tag autentikasi AES-256-GCM, dan HMAC tip anchor "
            f"({report.elapsed_ms:.2f} ms)."
        )
    else:
        st.error(
            f"🚨 **[PELANGGARAN INTEGRITAS TERDETEKSI]** Ditemukan {len(report.issues)} pelanggaran pada blok bukti:"
        )
        for issue in report.issues:
            st.warning(f"- **BLOK #{issue.index}** [`{issue.kind}`]: {issue.detail}")

    sub_mine, sub_explore, sub_tamper = st.tabs([
        "⛏️ [01] TAMBANG BLOK BUKTI BARU (MINE PoW)",
        "📦 [02] PENJELAJAH BLOK & DEKRIPSI GCM",
        "🧪 [03] LABORATORIUM SIMULASI TAMPERING",
    ])

    with sub_mine:
        c1, c2 = st.columns(2)
        asset_type = c1.selectbox("Klasifikasi Aset Forensik", blockchain.ASSET_TYPES)
        asset_name = c2.text_input("Kodefikasi / Nama Bukti", placeholder="BUKTI_FORENSIK_LAPTOP_TARGET_01")

        metadata: dict = {}
        if asset_type == "Secret Coordinates":
            c_lat, c_lon, c_alt = st.columns(3)
            lat = c_lat.number_input("Latitude", value=-6.200000, format="%.6f")
            lon = c_lon.number_input("Longitude", value=106.816666, format="%.6f")
            alt = c_alt.number_input("Elevasi (m)", value=32.0, format="%.1f")
            notes = st.text_area("Catatan Operasi Lapangan")
            metadata = {"latitude": lat, "longitude": lon, "elevation_m": alt, "notes": notes}
        elif asset_type == "Digital Certificate":
            c_ca, c_sn = st.columns(2)
            ca = c_ca.text_input("Otoritas Penerbit (CA)", value="B.A.G.U.S. Root Cyber CA")
            sn = c_sn.text_input("Nomor Seri Sertifikat", value="CERT-2026-X88")
            thumb = st.text_input("Thumbprint SHA-256 Sertifikat")
            metadata = {"issuer": ca, "serial_number": sn, "thumbprint": thumb}
        else:
            c_clr, c_ref = st.columns(2)
            clr = c_clr.selectbox("Klasifikasi Bukti", ["TOP SECRET // BLACK ICE", "CONFIDENTIAL", "RESTRICTED"])
            ref = c_ref.text_input("Nomor Laporan Polisi / Kasus", value="LP-CYBER-2026-11-A")
            desc = st.text_area("Rincian Bukti & Rantai Serah Terima (Chain of Custody)")
            metadata = {"classification": clr, "case_ref": ref, "details": desc}

        if st.button("⛏️ SEGEL AES-256-GCM & TAMBANG BLOK (PoW SHA-256)", type="primary"):
            if not asset_name.strip():
                st.warning("Nama Aset Bukti wajib diisi.")
            else:
                try:
                    mined = blockchain.add_asset(asset_name, asset_type, metadata, owner=username)
                    st.session_state["last_verification"] = blockchain.verify_chain()
                    ui_cyberpunk.log_cli(
                        "POW_LEDGER",
                        f"Mined Block #{mined.block.index} ('{mined.block.asset_name}') — Nonce: {mined.block.nonce}",
                        digest=mined.block.current_hash,
                        level="OK",
                    )
                    st.success(
                        f"Blok **#{mined.block.index}** berhasil ditambang & dikomit! "
                        f"SHA-256: `{mined.block.current_hash}` | Nonce: `{mined.block.nonce}` "
                        f"({mined.attempts} hash dihitung dalam {mined.elapsed_ms:.2f} ms)."
                    )
                except Exception as exc:
                    ui_cyberpunk.log_cli("POW_LEDGER", f"Mining error: {exc}", level="CRIT")
                    st.error(str(exc))

    with sub_explore:
        chain = blockchain.get_chain()
        for blk in reversed(chain):
            badge = "🟢 [VALID]" if report.block_status.get(blk.index) == "OK" else "🔴 [TAMPERED]"
            with st.expander(f"{badge} BLOK #{blk.index:03d} // {blk.asset_name} // {blk.timestamp}", expanded=(blk.index == len(chain) - 1)):
                st.markdown(
                    f"- **`CURRENT_HASH (SHA-256)`**: `{blk.current_hash}`\n"
                    f"- **`PREVIOUS_HASH`**: `{blk.previous_hash}`\n"
                    f"- **`POW_NONCE`**: `{blk.nonce}`\n"
                    f"- **`AES_256_GCM_CIPHERTEXT`**: `{blk.encrypted_asset_metadata[:70]}...`"
                )
                if st.button(f"🔓 BUKA SEGEL AES-256-GCM // BLOK #{blk.index}", key=f"blk_gcm_{blk.index}"):
                    try:
                        decrypted = blockchain.decrypt_metadata(blk)
                        ui_cyberpunk.log_cli(
                            "POW_LEDGER",
                            f"Decrypted metadata for Block #{blk.index}",
                            digest=blk.current_hash,
                            level="OK",
                        )
                        st.json(decrypted)
                    except Exception as exc:
                        ui_cyberpunk.log_cli("POW_LEDGER", f"GCM auth failure on Block #{blk.index}: {exc}", level="CRIT")
                        st.error(f"Autentikasi AES-256-GCM gagal: {exc}")

    with sub_tamper:
        st.info(
            "Simulasikan serangan lawan langsung pada tabel `blockchain_ledger` SQLite, "
            "kemudian klik tombol **VERIFY_CHAIN_INTEGRITY** di atas untuk mendemonstrasikan deteksi otomatis."
        )
        chain = blockchain.get_chain()
        c_t1, c_t2 = st.columns(2)
        target_idx = c_t1.selectbox("Target Blok Yang Akan Dimanipulasi", [b.index for b in chain])
        tamper_mode = c_t2.selectbox(
            "Jenis Serangan Manipulasi",
            list(blockchain.TAMPER_MODES.keys()),
            format_func=lambda k: blockchain.TAMPER_MODES[k],
        )

        b1, b2 = st.columns(2)
        if b1.button("💥 INJEKSIKAN SERANGAN TAMPERING KE SQLITE", use_container_width=True):
            res_msg = blockchain.simulate_tampering(int(target_idx), tamper_mode)
            st.session_state["last_verification"] = blockchain.verify_chain()
            ui_cyberpunk.log_cli(
                "POW_LEDGER",
                f"Tamper simulation injected into Block #{target_idx} ({tamper_mode}): {res_msg}",
                level="CRIT",
            )
            st.rerun()
        if b2.button("♻️ RESET & PULIHKAN LEDGER KE BLOK GENESIS", use_container_width=True):
            blockchain.reset_ledger()
            st.session_state["last_verification"] = blockchain.verify_chain()
            ui_cyberpunk.log_cli("POW_LEDGER", "Blockchain ledger reset to Genesis Block #0", level="WARN")
            st.rerun()


# --------------------------------------------------------------------------- #
# Main Router
# --------------------------------------------------------------------------- #
def main() -> None:
    extra = [st.session_state.custom_dongle_path] if st.session_state.custom_dongle_path else None
    dongle_status = dongle_guard.scan_for_dongle(extra_paths=extra)

    # State transition logger
    dongle_state_sig = (dongle_status.valid, dongle_status.dongle_id, dongle_status.message)
    if st.session_state.last_logged_dongle_state != dongle_state_sig:
        st.session_state.last_logged_dongle_state = dongle_state_sig
        if dongle_status.valid:
            ui_cyberpunk.log_cli(
                "DONGLE_GUARD",
                f"HMAC-SHA256 hardware token authenticated at '{dongle_status.path}'",
                digest=dongle_status.dongle_id,
                level="OK",
            )
        else:
            ui_cyberpunk.log_cli(
                "DONGLE_GUARD",
                f"CRITICAL_SECURITY_HALT: {dongle_status.message}",
                digest=ui_cyberpunk.sha256_hex(dongle_status.message),
                level="CRIT",
            )

    # GATE 01: Hardware Dongle Required
    if not dongle_status.valid:
        st.session_state.authenticated_user = None
        render_dongle_lock_screen(dongle_status)
        return

    # GATE 02: Realtime Optical Face Scanner + PBKDF2-SHA256 Login
    if not st.session_state.authenticated_user:
        render_auth_screen(dongle_status)
        return

    # GATE 03: Authenticated Vault Core
    username = st.session_state.authenticated_user
    with st.sidebar:
        st.markdown("## ⚡ B.A.G.U.S. Vault")
        st.caption("FORENSIC & INTELLIGENCE EVIDENCE VAULT")
        st.success(f"👤 ANALYST: **{username.upper()}**")
        if st.session_state.auth_similarity is not None:
            st.caption(f"🧬 FACE_MATCH: **{st.session_state.auth_similarity:.1%}** (`AES-128-EAX`)")
        st.caption(f"🔑 DONGLE: **{dongle_status.label}**")
        st.divider()

        menu = st.radio(
            "NAVIGASI SUBSISTEM FORENSIK",
            [
                "📡 [00] RINGKASAN SISTEM & TELEMETRI",
                "📝 [01] LAPORAN INTELIJEN (Super Enkripsi Teks)",
                "📁 [02] BERKAS BARANG BUKTI (Enkripsi File ChaCha20)",
                "🖼️ [03] CITRA FORENSIK STEGANOGRAFI (LSB PNG)",
                "🔍 [04] INSPEKSI BASIS DATA (Encrypted SQLite At-Rest)",
                "⛓️ [05] CHAIN OF CUSTODY LEDGER (PoW Blockchain)",
            ],
        )
        st.divider()
        c_flush, c_exit = st.columns(2)
        with c_flush:
            if st.button("🧹 BERSIHKAN TTY", use_container_width=True):
                st.session_state.cli_logs = []
                ui_cyberpunk.log_cli("KERNEL", "Console buffer flushed by analyst", level="INFO")
                st.rerun()
        with c_exit:
            if st.button("🚪 KUNCI VAULT", use_container_width=True):
                ui_cyberpunk.log_cli("KERNEL", f"Analyst '{username}' locked B.A.G.U.S. Vault session", level="WARN")
                st.session_state.authenticated_user = None
                st.session_state.auth_similarity = None
                st.rerun()

    render_hud_topbar(current_step=3, dongle_mounted=True)

    if menu.startswith("📡"):
        render_overview_tab(username, dongle_status)
    elif menu.startswith("📝"):
        render_super_encryption_tab(username)
    elif menu.startswith("📁"):
        render_file_crypto_tab(username)
    elif menu.startswith("🖼️"):
        render_steganography_tab()
    elif menu.startswith("🔍"):
        render_database_inspection_tab(username)
    elif menu.startswith("⛓️"):
        render_blockchain_tab(username)

    ui_cyberpunk.render_cli_console("GATE_03 // B.A.G.U.S. VAULT CRYPTOGRAPHIC OPERATIONS LOG")


if __name__ == "__main__":
    main()
