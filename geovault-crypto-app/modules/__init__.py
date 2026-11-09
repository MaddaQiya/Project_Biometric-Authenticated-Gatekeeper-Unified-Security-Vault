"""
GeoVault Cryptographic Subsystems
=================================

  - ``dongle_guard``    : Hardware/USB Dongle verification via HMAC-SHA256
  - ``auth_biometric``  : Salted PBKDF2-SHA256 + Biometric template & AES-128-EAX
  - ``blockchain``      : Local SHA-256 PoW Blockchain ledger & integrity verifier
  - ``super_encryption``: Vigenere Cipher + AES-256-CBC text super encryption
  - ``file_crypto``     : ChaCha20 byte-stream file encryption & decryption
  - ``steganography``   : LSB (Least Significant Bit) PNG image steganography
"""
