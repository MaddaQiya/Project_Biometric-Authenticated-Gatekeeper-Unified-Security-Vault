"""
GeoVault: Spatial & Secret Document Digital Vault
=================================================

Main Streamlit application implementing the strict 3-stage security gatekeeper:
  [Step 1: Hardware/USB Dongle Check (HMAC-SHA256)]
      -> [Step 2: Password (PBKDF2-SHA256) + Biometric (AES-128-EAX) Login]
          -> [Step 3: Main Vault Dashboard & PoW Blockchain Ledger]
"""

from __future__ import annotations

import secrets
from pathlib import Path
from typing import Optional

import streamlit as st

import config
import database
from modules import (
    auth_biometric,
    blockchain,
    dongle_guard,
    file_crypto,
    steganography,
    super_encryption,
)

# --------------------------------------------------------------------------- #
# Bootstrap & Session State
# --------------------------------------------------------------------------- #
st.set_page_config(
    page_title="GeoVault | Spatial & Secret Digital Vault",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

database.init_db()

if "authenticated_user" not in st.session_state:
    st.session_state.authenticated_user = None
if "auth_similarity" not in st.session_state:
    st.session_state.auth_similarity = None
if "custom_dongle_path" not in st.session_state:
    st.session_state.custom_dongle_path = ""


def _read_biometric_input(prefix: str) -> Optional[bytes]:
    """Render Streamlit camera capture + fallback image uploader and return raw image bytes."""
    mode = st.radio(
        "Metode Input Biometrik",
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
        st.image(upload, caption="Pratinjau Citra Biometrik", width=220)
        return upload.getvalue()
    return None


def _render_stepper(current_step: int) -> None:
    steps = [
        (1, "Step 1: USB Dongle Check"),
        (2, "Step 2: Biometric + Crypto Login"),
        (3, "Step 3: Main Vault Dashboard"),
    ]
    cols = st.columns(3)
    for col, (num, title) in zip(cols, steps):
        with col:
            if num < current_step:
                st.success(f"✅ **{title}**")
            elif num == current_step:
                st.info(f"🔐 **{title}** *(Active)*")
            else:
                st.caption(f"🔒 {title}")


# --------------------------------------------------------------------------- #
# STEP 1: Hardware / USB Dongle Gatekeeper
# --------------------------------------------------------------------------- #
def render_dongle_lock_screen(status: dongle_guard.DongleStatus) -> None:
    _render_stepper(1)
    st.divider()
    st.title("🔒 GeoVault Terkunci — Hardware Dongle Diperlukan")
    st.markdown(
        "Aplikasi ini dilindungi oleh **Hardware/USB Dongle Gatekeeper**. "
        "Masukkan flashdisk USB yang memiliki token tersembunyi `.geovault_dongle` "
        "dengan tanda tangan **HMAC-SHA256** yang valid untuk melanjutkan."
    )

    if status.failures:
        st.error(f"🚨 **Peringatan Integritas Dongle:** {status.message}")
    else:
        st.warning(status.message)

    col_a, col_b = st.columns([1, 1])
    with col_a:
        if st.button("🔄 Scan Ulang USB Dongle", type="primary", use_container_width=True):
            st.rerun()

    with col_b:
        with st.expander("⚙️ Konfigurasi Path Fallback / Testing Tanpa USB Fisik"):
            custom = st.text_input(
                "Custom Drive / Folder Path",
                value=st.session_state.custom_dongle_path,
                placeholder=str(config.DEFAULT_FALLBACK_DONGLE_DIR),
            )
            if st.button("Simpan & Cek Path"):
                st.session_state.custom_dongle_path = custom.strip()
                st.rerun()
            st.caption(
                "Untuk membuat token `.geovault_dongle` pada USB atau folder virtual lokal, jalankan:\n"
                "```bash\n"
                "python generate_dongle.py --local --overwrite\n"
                "# atau buka UI Provisioning:\n"
                "streamlit run generate_dongle.py\n"
                "```"
            )

    with st.expander("📋 Detail Lokasi yang Dipindai"):
        if status.scanned_locations:
            for loc in status.scanned_locations:
                st.code(loc)
        else:
            st.write("Belum ada removable USB drive atau folder fallback aktif yang terdeteksi.")


# --------------------------------------------------------------------------- #
# STEP 2: Biometric + Cryptographic Login / Registration
# --------------------------------------------------------------------------- #
def render_auth_screen(dongle: dongle_guard.DongleStatus) -> None:
    _render_stepper(2)
    st.divider()
    st.title("🧬 Otentikasi Dua Faktor: Kriptografi + Biometrik")
    st.caption(
        f"Dongle Aktif: **{dongle.label}** (`{dongle.path}`) | "
        f"OpenCV Haar Cascade: **{'Aktif' if auth_biometric.OPENCV_AVAILABLE else 'Mode Fallback Center-Crop'}**"
    )

    tab_login, tab_register = st.tabs(["🔑 Login ke Vault", "📝 Registrasi Pengguna Baru"])

    with tab_login:
        col_form, col_bio = st.columns([1, 1])
        with col_form:
            st.subheader("Faktor 1: Kredensial Kriptografi")
            login_user = st.text_input("Username", key="login_username", placeholder="contoh: operator_01")
            login_pw = st.text_input("Password", type="password", key="login_password")
            st.caption(
                "Password diverifikasi menggunakan **PBKDF2-HMAC-SHA256 (600.000 iterasi)** + random 16-byte salt "
                "& HKDF domain separation."
            )
        with col_bio:
            st.subheader("Faktor 2: Verifikasi Biometrik")
            login_img = _read_biometric_input("login")

        if st.button("🔓 Verifikasi & Buka GeoVault", type="primary", use_container_width=True):
            if not login_user or not login_pw or not login_img:
                st.warning("Harap lengkapi Username, Password, dan Scan/Upload Biometrik.")
            else:
                with st.spinner("Menjalankan PBKDF2-SHA256 & mendekripsi template biometrik AES-128-EAX..."):
                    res = auth_biometric.authenticate_user(login_user, login_pw, login_img)
                if res.success:
                    st.session_state.authenticated_user = res.username
                    st.session_state.auth_similarity = res.similarity
                    st.rerun()
                else:
                    sim_info = f" (Skor kemiripan biometrik: {res.similarity:.1%})" if res.similarity is not None else ""
                    st.error(f"{res.message}{sim_info}")

    with tab_register:
        col_r1, col_r2 = st.columns([1, 1])
        with col_r1:
            st.subheader("1. Buat Kredensial")
            reg_user = st.text_input(
                "Username Baru (huruf kecil/angka, 3-32 karakter)",
                key="reg_username",
                placeholder="operator_01",
            )
            reg_pw = st.text_input("Password (min. 8 karakter, huruf & angka)", type="password", key="reg_pw")
            reg_pw2 = st.text_input("Konfirmasi Password", type="password", key="reg_pw2")
            require_face = st.checkbox(
                "Wajib deteksi wajah OpenCV (nonaktifkan jika memakai citra sidik jari)",
                value=False,
            )
        with col_r2:
            st.subheader("2. Pendaftaran Template Biometrik")
            reg_img = _read_biometric_input("register")
            st.caption(
                "Fitur biometrik (`pHash + dHash` 128-bit + digest SHA-256) dienkripsi menggunakan "
                "**AES-128-EAX** dengan kunci turunan password sebelum disimpan ke SQLite."
            )

        if st.button("✨ Daftarkan Akun & Enkripsi Biometrik", type="primary", use_container_width=True):
            if reg_pw != reg_pw2:
                st.error("Konfirmasi password tidak cocok.")
            elif not reg_img:
                st.warning("Harap ambil foto wajah atau upload citra biometrik terlebih dahulu.")
            else:
                with st.spinner("Mengekstrak fitur biometrik & mengenkripsi template dengan AES-128-EAX..."):
                    res = auth_biometric.register_user(reg_user, reg_pw, reg_img, require_face=require_face)
                if res.success:
                    st.success(
                        f"{res.message} (Deteksi wajah OpenCV: {'Ya' if res.face_detected else 'Center-Crop ROI'})"
                    )
                else:
                    st.error(res.message)


# --------------------------------------------------------------------------- #
# STEP 3: Main Vault Dashboard Pages
# --------------------------------------------------------------------------- #
def render_overview_tab(username: str, dongle: dongle_guard.DongleStatus) -> None:
    blockchain.ensure_genesis()
    stats = database.get_user_stats(username)
    report = blockchain.verify_chain()

    st.subheader("📊 Ringkasan Keamanan GeoVault")
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Blok Ledger Aset Kritis", stats["ledger_blocks"])
    m2.metric("Integritas Blockchain", "VALID" if report.valid else "TAMPERED!")
    m3.metric("Pesan Super-Enkripsi", stats["secret_messages"])
    m4.metric("Dokumen Terenkripsi ChaCha20", stats["encrypted_files"])

    if not report.valid:
        st.error(
            f"🚨 Terdeteksi {len(report.issues)} pelanggaran integritas pada Blockchain Ledger! "
            "Buka menu **Blockchain Critical Assets** untuk menginspeksi blok yang dimanipulasi."
        )

    c1, c2 = st.columns(2)
    with c1:
        st.markdown("#### 🔑 Status Hardware Dongle")
        st.json({
            "label": dongle.label,
            "dongle_id": dongle.dongle_id,
            "mount_path": dongle.path,
            "volume_serial": dongle.volume_serial or "Unbound",
            "expires_at": dongle.expires_at or "Never",
            "mac_algorithm": "HMAC-SHA256",
        })
    with c2:
        st.markdown("#### 🛡️ Arsitektur Kriptografi Aktif")
        st.markdown(
            "- **Gatekeeper**: Hardware/USB Token + `HMAC-SHA256`\n"
            "- **Otentikasi User**: `PBKDF2-HMAC-SHA256` (600k iterasi) + `HKDF`\n"
            "- **Proteksi Biometrik**: `pHash+dHash 128-bit` dienkripsi `AES-128-EAX`\n"
            "- **Critical Asset Ledger**: `SHA-256` Proof-of-Work (`00`) + `AES-256-GCM` + `HMAC Tip Anchor`\n"
            "- **Modul Dev 2 (Siap Integrasi)**: `Vigenère + AES-256-CBC`, `ChaCha20`, `LSB PNG Stego`"
        )


def render_blockchain_tab(username: str) -> None:
    blockchain.ensure_genesis()
    st.subheader("⛓️ Local Blockchain Ledger — Critical Spatial & Secret Assets")
    st.caption(
        "Setiap aset kritis dienkripsi dengan **AES-256-GCM** dan ditambang ke dalam blok berantai "
        "**SHA-256 Proof-of-Work** (difficulty prefix `\"00\"`) serta dikunci dengan **HMAC-SHA256 Tip Anchor**."
    )

    col_verify, col_export = st.columns([2, 1])
    with col_verify:
        if st.button("🔍 Verify Blockchain Integrity", type="primary", use_container_width=True):
            st.session_state["last_verification"] = blockchain.verify_chain()
    with col_export:
        st.download_button(
            "⬇️ Export Ledger JSON",
            data=blockchain.export_chain_json(),
            file_name="geovault_blockchain_ledger.json",
            mime="application/json",
            use_container_width=True,
        )

    report: blockchain.VerificationReport = st.session_state.get("last_verification") or blockchain.verify_chain()
    if report.valid:
        st.success(
            f"✅ **Integritas Rantai Terverifikasi:** Seluruh {report.blocks_checked} blok valid "
            f"(SHA-256 hash cocok, PoW `{blockchain.HASH_PREFIX}` terpenuhi, tautan `previous_hash` utuh, "
            f"tag AES-256-GCM & HMAC Anchor otentik — dicek dalam {report.elapsed_ms:.2f} ms)."
        )
    else:
        st.error(
            f"🚨 **PERINGATAN MANIPULASI DATABASE / LEDGER!** Ditemukan {len(report.issues)} masalah integritas:"
        )
        for issue in report.issues:
            st.warning(f"- **Blok #{issue.index}** [`{issue.kind}`]: {issue.detail}")

    sub_add, sub_explore, sub_tamper = st.tabs([
        "➕ Tambah & Mining Aset Kritis",
        "📦 Jelajahi Blok & Dekripsi Metadata",
        "🧪 Tamper Simulation Lab (Demo Pengujian)",
    ])

    with sub_add:
        asset_type = st.selectbox("Kategori Aset Kritis", blockchain.ASSET_TYPES)
        asset_name = st.text_input("Nama Aset / Kode Dokumen", placeholder="Contoh: Koordinat Bunker Logistik Sektor-7")

        metadata: dict = {}
        if asset_type == "Secret Coordinates":
            c1, c2, c3 = st.columns(3)
            lat = c1.number_input("Latitude", min_value=-90.0, max_value=90.0, value=-6.200000, format="%.6f")
            lon = c2.number_input("Longitude", min_value=-180.0, max_value=180.0, value=106.816666, format="%.6f")
            elev = c3.number_input("Elevasi (m)", value=45.0, format="%.1f")
            zone_note = st.text_area("Catatan Geospasial Rahasia", placeholder="Detail akses, radius aman, kode otorisasi...")
            metadata = {"latitude": lat, "longitude": lon, "elevation_m": elev, "notes": zone_note}
        elif asset_type == "Digital Certificate":
            c1, c2 = st.columns(2)
            issuer = c1.text_input("Otoritas Penerbit (CA)", placeholder="GeoVault Root Authority")
            serial_no = c2.text_input("Nomor Seri Sertifikat", placeholder="SN-2026-9981-AX")
            fingerprint = st.text_input("SHA-256 Fingerprint / Public Key Reference")
            cert_note = st.text_area("Payload / Klaim Sertifikat")
            metadata = {"issuer": issuer, "serial_number": serial_no, "fingerprint": fingerprint, "claims": cert_note}
        else:
            classification = st.selectbox("Tingkat Klasifikasi", ["TOP SECRET", "SECRET", "CONFIDENTIAL"])
            ref_id = st.text_input("ID Referensi Dokumen", placeholder="DOC-HV-0042")
            record_body = st.text_area("Isi Rekor Bernilai Tinggi")
            metadata = {"classification": classification, "reference_id": ref_id, "content": record_body}

        if st.button("⛏️ Enkripsi & Tambang Blok Baru (PoW SHA-256)", type="primary"):
            if not asset_name.strip():
                st.warning("Nama aset tidak boleh kosong.")
            else:
                try:
                    mined = blockchain.add_asset(asset_name, asset_type, metadata, owner=username)
                    st.session_state["last_verification"] = blockchain.verify_chain()
                    st.success(
                        f"Blok **#{mined.block.index}** berhasil ditambang! "
                        f"Hash: `{mined.block.current_hash}` | Nonce: `{mined.block.nonce}` "
                        f"({mined.attempts} percobaan dalam {mined.elapsed_ms:.2f} ms)."
                    )
                except Exception as exc:
                    st.error(str(exc))

    with sub_explore:
        chain = blockchain.get_chain()
        for blk in reversed(chain):
            state_badge = "🟢 VALID" if report.block_status.get(blk.index) == "OK" else "🔴 TAMPERED"
            with st.expander(
                f"{state_badge} | Block #{blk.index} — {blk.asset_name} ({blk.timestamp})",
                expanded=(blk.index == len(chain) - 1),
            ):
                st.markdown(
                    f"- **Current Hash (`SHA-256`)**: `{blk.current_hash}`\n"
                    f"- **Previous Hash**: `{blk.previous_hash}`\n"
                    f"- **Nonce (PoW)**: `{blk.nonce}`\n"
                    f"- **Encrypted Asset Metadata (`AES-256-GCM`)**: `{blk.encrypted_asset_metadata[:72]}...`"
                )
                if st.button(f"🔓 Dekripsi Metadata Blok #{blk.index}", key=f"dec_blk_{blk.index}"):
                    try:
                        st.json(blockchain.decrypt_metadata(blk))
                    except Exception as exc:
                        st.error(f"Gagal mendekripsi metadata (data rusak/dimanipulasi): {exc}")

    with sub_tamper:
        st.info(
            "Gunakan panel ini saat demo proyek untuk mensimulasikan penyerang yang mengubah tabel SQLite "
            "`blockchain_ledger` secara langsung, lalu klik **Verify Blockchain Integrity** di atas."
        )
        chain = blockchain.get_chain()
        col_t1, col_t2 = st.columns(2)
        target_idx = col_t1.selectbox("Pilih Blok Target", [b.index for b in chain])
        mode_key = col_t2.selectbox(
            "Jenis Serangan",
            list(blockchain.TAMPER_MODES.keys()),
            format_func=lambda k: blockchain.TAMPER_MODES[k],
        )
        b1, b2 = st.columns(2)
        if b1.button("💥 Simulasikan Manipulasi Database", use_container_width=True):
            msg = blockchain.simulate_tampering(int(target_idx), mode_key)
            st.session_state["last_verification"] = blockchain.verify_chain()
            st.warning(msg)
            st.rerun()
        if b2.button("♻️ Reset Ledger ke Genesis Baru", use_container_width=True):
            blockchain.reset_ledger()
            st.session_state["last_verification"] = blockchain.verify_chain()
            st.success("Ledger berhasil di-reset ke kondisi bersih.")
            st.rerun()


# --------------------------------------------------------------------------- #
# DEVELOPER 2 MODULE TABS (Cleanly decoupled via stub interfaces)
# --------------------------------------------------------------------------- #
def render_super_encryption_tab(username: str) -> None:
    st.subheader("📝 Secret Spatial Notes — Super Encryption (Vigenère + AES-256-CBC)")
    st.caption("Modul Developer 2 (`modules/super_encryption.py`) — terhubung ke tabel `secret_messages`.")

    with st.form("super_enc_form"):
        title = st.text_input("Judul Catatan Rahasia")
        plaintext = st.text_area("Isi Pesan / Koordinat Rahasia")
        c1, c2 = st.columns(2)
        vig_key = c1.text_input("Kunci Vigenère (Klasik)", type="password")
        aes_key = c2.text_input("Passphrase AES-256-CBC (Modern)", type="password")
        submitted = st.form_submit_button("🔒 Super-Encrypt & Simpan", type="primary")

    if submitted:
        if not (title and plaintext and vig_key and aes_key):
            st.warning("Semua kolom wajib diisi.")
        else:
            try:
                token = super_encryption.super_encrypt(plaintext, vig_key, aes_key)
                database.insert_secret_message(username, title, token, super_encryption.ALGORITHM_ID)
                st.success("Pesan terenkripsi ganda berhasil disimpan!")
            except NotImplementedError as exc:
                st.info(f"🚧 **Menunggu Implementasi Developer 2:** `{exc}`")
            except Exception as exc:
                st.error(str(exc))

    rows = database.list_secret_messages(username)
    if rows:
        st.divider()
        for row in rows:
            with st.expander(f"📄 {row['title']} ({row['created_at']})"):
                st.code(row["ciphertext"])
                d1, d2 = st.columns(2)
                vk = d1.text_input("Vigenère Key", type="password", key=f"vk_{row['id']}")
                ak = d2.text_input("AES Passphrase", type="password", key=f"ak_{row['id']}")
                if st.button("🔓 Dekripsi", key=f"dec_msg_{row['id']}"):
                    try:
                        st.success(super_encryption.super_decrypt(row["ciphertext"], vk, ak))
                    except NotImplementedError as exc:
                        st.info(f"🚧 {exc}")
                    except Exception as exc:
                        st.error(str(exc))


def render_file_crypto_tab(username: str) -> None:
    st.subheader("📁 Secret Document Vault — ChaCha20 Stream Cipher")
    st.caption("Modul Developer 2 (`modules/file_crypto.py`) — terhubung ke tabel `encrypted_files` & `storage/files/`.")

    uploaded = st.file_uploader("Pilih Dokumen Rahasia (PDF, GeoJSON, KML, ZIP, DOCX, dll.)")
    passphrase = st.text_input("Passphrase Enkripsi File", type="password", key="file_enc_pass")
    if st.button("🔐 Enkripsi Dokumen dengan ChaCha20", type="primary", disabled=uploaded is None):
        if not passphrase:
            st.warning("Masukkan passphrase enkripsi terlebih dahulu.")
        else:
            try:
                bundle = file_crypto.encrypt_file_bytes(uploaded.getvalue(), passphrase)
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
                st.success(f"Dokumen `{uploaded.name}` berhasil dienkripsi ke `{stored_name}`!")
            except NotImplementedError as exc:
                st.info(f"🚧 **Menunggu Implementasi Developer 2:** `{exc}`")
            except Exception as exc:
                st.error(str(exc))

    files = database.list_encrypted_files(username)
    if files:
        st.divider()
        for f in files:
            with st.expander(f"📦 {f['original_name']} ({f['size_bytes']} bytes — {f['created_at']})"):
                st.caption(f"SHA-256 Plaintext: `{f['sha256_plain']}` | Nonce: `{f['nonce']}`")
                dec_pw = st.text_input("Passphrase Dekripsi", type="password", key=f"fdec_{f['id']}")
                if st.button("🔓 Dekripsi & Siapkan Unduhan", key=f"fbtn_{f['id']}"):
                    try:
                        cipher_bytes = (config.FILES_DIR / f["stored_name"]).read_bytes()
                        plain = file_crypto.decrypt_file_bytes(
                            cipher_bytes, dec_pw, f["kdf_salt"], f["nonce"], f["sha256_plain"]
                        )
                        st.download_button(
                            f"⬇️ Download {f['original_name']}",
                            data=plain,
                            file_name=f["original_name"],
                            mime=f["mime_type"] or "application/octet-stream",
                            key=f"dl_{f['id']}",
                        )
                    except NotImplementedError as exc:
                        st.info(f"🚧 {exc}")
                    except Exception as exc:
                        st.error(str(exc))


def render_steganography_tab() -> None:
    st.subheader("🖼️ Spatial Map / Image Steganography — LSB PNG")
    st.caption("Modul Developer 2 (`modules/steganography.py`) — penyisipan pesan rahasia pada piksel citra PNG.")

    tab_embed, tab_extract = st.tabs(["📥 Sisipkan Pesan (Embed LSB)", "📤 Ekstrak Pesan (Extract LSB)"])
    with tab_embed:
        cover = st.file_uploader("Upload Cover Image (PNG / BMP)", type=["png", "bmp"], key="stego_cover")
        secret_msg = st.text_area("Pesan / Koordinat Rahasia yang Disembunyikan")
        stego_pw = st.text_input("Passphrase Opsional", type="password", key="stego_pw_in")
        if st.button("✨ Sisipkan ke LSB PNG", type="primary", disabled=cover is None):
            try:
                out_png = steganography.embed_message_lsb(cover.getvalue(), secret_msg, stego_pw or None)
                st.success("Pesan berhasil disisipkan!")
                st.download_button("⬇️ Download Stego PNG", data=out_png, file_name="geovault_stego.png", mime="image/png")
            except NotImplementedError as exc:
                st.info(f"🚧 **Menunggu Implementasi Developer 2:** `{exc}`")
            except Exception as exc:
                st.error(str(exc))

    with tab_extract:
        stego_img = st.file_uploader("Upload Stego PNG Image", type=["png"], key="stego_in")
        stego_pw_out = st.text_input("Passphrase Opsional", type="password", key="stego_pw_out")
        if st.button("🔍 Ekstrak Pesan Tersembunyi", type="primary", disabled=stego_img is None):
            try:
                msg = steganography.extract_message_lsb(stego_img.getvalue(), stego_pw_out or None)
                st.success("Pesan ditemukan:")
                st.code(msg)
            except NotImplementedError as exc:
                st.info(f"🚧 **Menunggu Implementasi Developer 2:** `{exc}`")
            except Exception as exc:
                st.error(str(exc))


# --------------------------------------------------------------------------- #
# Main Gatekeeper Router
# --------------------------------------------------------------------------- #
def main() -> None:
    extra = [st.session_state.custom_dongle_path] if st.session_state.custom_dongle_path else None
    dongle_status = dongle_guard.scan_for_dongle(extra_paths=extra)

    # Gate 1: If dongle is missing or invalid, immediately revoke active session & lock UI.
    if not dongle_status.valid:
        st.session_state.authenticated_user = None
        render_dongle_lock_screen(dongle_status)
        return

    # Gate 2: Require Password + Biometric authentication.
    if not st.session_state.authenticated_user:
        render_auth_screen(dongle_status)
        return

    # Gate 3: Main Vault Dashboard.
    username = st.session_state.authenticated_user
    with st.sidebar:
        st.title("🛡️ GeoVault")
        st.caption("Spatial & Secret Document Digital Vault")
        st.success(f"👤 Operator: **{username}**")
        if st.session_state.auth_similarity is not None:
            st.caption(f"🧬 Biometric Match: **{st.session_state.auth_similarity:.1%}**")
        st.caption(f"🔑 Dongle: **{dongle_status.label}**")
        st.divider()
        menu = st.radio(
            "Navigasi Vault",
            [
                "🏠 Dashboard Utama",
                "⛓️ Blockchain Critical Assets",
                "📝 Super-Encrypted Notes (Dev 2)",
                "📁 ChaCha20 File Vault (Dev 2)",
                "🖼️ LSB Steganography (Dev 2)",
            ],
        )
        st.divider()
        if st.button("🚪 Kunci Vault & Logout", use_container_width=True):
            st.session_state.authenticated_user = None
            st.session_state.auth_similarity = None
            st.rerun()

    _render_stepper(3)
    st.divider()

    if menu == "🏠 Dashboard Utama":
        render_overview_tab(username, dongle_status)
    elif menu == "⛓️ Blockchain Critical Assets":
        render_blockchain_tab(username)
    elif menu == "📝 Super-Encrypted Notes (Dev 2)":
        render_super_encryption_tab(username)
    elif menu == "📁 ChaCha20 File Vault (Dev 2)":
        render_file_crypto_tab(username)
    elif menu == "🖼️ LSB Steganography (Dev 2)":
        render_steganography_tab()


if __name__ == "__main__":
    main()
