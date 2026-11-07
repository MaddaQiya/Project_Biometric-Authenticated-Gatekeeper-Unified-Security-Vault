# 🛡️ GeoVault: Spatial & Secret Document Digital Vault

Aplikasi **Cryptography Final Project** berbasis **Python & Streamlit** untuk penyimpanan dokumen rahasia dan aset geospasial kritis dengan arsitektur pertahanan berlapis (*Defense-in-Depth*).

---

## 👥 Pembagian Kerja Tim (50-50 Tanpa Merge Conflict)

| Developer | Modul | Status | Algoritma Kriptografi |
| :--- | :--- | :--- | :--- |
| **Developer 1** | `modules/dongle_guard.py`, `generate_dongle.py` | ✅ Selesai | Hardware/USB Token `.geovault_dongle` + **HMAC-SHA256** + Volume Serial Binding |
| **Developer 1** | `modules/auth_biometric.py` | ✅ Selesai | **PBKDF2-HMAC-SHA256** (Salt 16B) + Perceptual Biometric Hash + **AES-128-EAX** |
| **Developer 1** | `modules/blockchain.py` | ✅ Selesai | **SHA-256 Proof-of-Work** (`"00"`) + **AES-256-GCM** Metadata + **HMAC Tip Anchor** |
| **Developer 1** | `app.py`, `database.py`, `config.py` | ✅ Selesai | 3-Step Gatekeeper UI, SQLite Schema & Parameterized CRUD |
| **Developer 2** | `modules/super_encryption.py` | 🧩 Stub Siap | **Vigenère Cipher + AES-256-CBC** Text Super Encryption |
| **Developer 2** | `modules/file_crypto.py` | 🧩 Stub Siap | **ChaCha20** Byte-Stream File Encryption & Decryption |
| **Developer 2** | `modules/steganography.py` | 🧩 Stub Siap | **LSB (Least Significant Bit)** Lossless PNG Steganography |

> **Catatan Kolaborasi GitHub:** Developer 2 cukup mengimplementasikan fungsi-fungsi di `modules/super_encryption.py`, `modules/file_crypto.py`, dan `modules/steganography.py` sesuai *type signature* dan *docstring* tanpa perlu mengubah `app.py` maupun `database.py`.

---

## 🚀 Cara Menjalankan & Preview Aplikasi

### 1. Masuk ke Direktori Proyek & Install Dependensi
```powershell
cd geovault-crypto-app
pip install -r requirements.txt
```

### 2. Jalankan Aplikasi Utama (Akan Muncul dalam Kondisi Terkunci / Gate 1)
```powershell
streamlit run app.py
```
Secara bawaan, saat pertama kali dibuka, aplikasi **terkunci penuh** di **Step 1: USB Dongle Check** karena belum ada token `.geovault_dongle`.

### 3. Buat / Provision Token `.geovault_dongle` (Untuk Membuka Gate 1)
Anda bisa menggunakan **salah satu** dari dua cara berikut:

- **Opsi A — Lewat CLI (Cepat, untuk USB fisik atau folder virtual lokal tanpa flashdisk):**
  ```powershell
  # Tanpa flashdisk fisik (membuat folder lokal ./virtual_usb/.geovault_dongle):
  python generate_dongle.py --local --overwrite

  # Atau ke flashdisk USB fisik (misal drive E:\):
  python generate_dongle.py --target E:\ --label "Admin USB" --overwrite
  ```
- **Opsi B — Lewat UI Streamlit Dongle Provisioner:**
  ```powershell
  streamlit run generate_dongle.py --server.port 8502
  ```
  Klik tombol **Provision `.geovault_dongle` Now**, lalu kembali ke tab GeoVault (`http://localhost:8501`) dan klik **Scan Ulang USB Dongle**.
