"""
GeoVault Cryptographic Modules
==============================

Developer 1 (Implemented):
  - ``dongle_guard``    : Hardware/USB Dongle check via HMAC-SHA256
  - ``auth_biometric``  : Salted PBKDF2-SHA256 + Biometric template & AES-128-EAX
  - ``blockchain``      : Local SHA-256 PoW Blockchain ledger & integrity verifier

Developer 2 (Interfaces / Stubs):
  - ``super_encryption``: Vigenere Cipher + AES-256-CBC text super encryption
  - ``file_crypto``     : ChaCha20 byte-stream file encryption & decryption
  - ``steganography``   : LSB (Least Significant Bit) PNG image steganography
"""
