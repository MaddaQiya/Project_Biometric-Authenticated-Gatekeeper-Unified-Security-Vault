"""
GeoVault - LSB PNG Image Steganography
======================================

Spatial-domain Least Significant Bit (LSB) steganography on lossless 24-bit/32-bit
**PNG** images (`PIL.Image`):
  1. Each RGB pixel contributes 3 carrier bits (1 bit per R, G, B channel LSB):
       C'_ch = (C_ch & 0xFE) | b_k
  2. A deterministic length header precedes the UTF-8 payload bits so extraction
     recovers the exact byte boundary without trailing carrier noise.
  3. Output is encoded strictly as lossless PNG so DCT quantization never destroys
     the least significant bit-plane.
"""

from __future__ import annotations

from typing import Optional


class SteganographyNotImplementedError(NotImplementedError):
    """Raised when an LSB steganography routine has not been bound yet."""


def calculate_capacity(image_bytes: bytes) -> int:
    """
    Compute the maximum UTF-8 payload size (in bytes) supported by ``image_bytes``.

    :param image_bytes: Raw bytes of the cover image.
    :returns:           Maximum embeddable payload bytes (`(width * height * 3) // 8 - header_bytes`).
    """
    raise SteganographyNotImplementedError(
        "calculate_capacity() is not yet bound in modules/steganography.py"
    )


def embed_message_lsb(
    cover_image_bytes: bytes,
    secret_message: str,
    passphrase: Optional[str] = None,
) -> bytes:
    """
    Embed ``secret_message`` into the RGB least significant bits of ``cover_image_bytes``.

    :param cover_image_bytes: Uploaded lossless cover image bytes (PNG/BMP).
    :param secret_message:    Secret text or spatial coordinates to hide.
    :param passphrase:        Optional passphrase to key/authenticate the embedded payload.
    :returns:                 Lossless PNG image bytes carrying the hidden payload.
    :raises ValueError:       If the payload bit length exceeds the cover image capacity.
    """
    raise SteganographyNotImplementedError(
        "embed_message_lsb() is not yet bound in modules/steganography.py"
    )


def extract_message_lsb(
    stego_image_bytes: bytes,
    passphrase: Optional[str] = None,
) -> str:
    """
    Extract and decode a hidden UTF-8 payload from the RGB LSBs of a stego PNG image.

    :param stego_image_bytes: PNG bytes containing an LSB-embedded payload.
    :param passphrase:        Optional passphrase used during embedding.
    :returns:                 Recovered UTF-8 plaintext message.
    :raises ValueError:       If no valid payload header is present or authentication fails.
    """
    raise SteganographyNotImplementedError(
        "extract_message_lsb() is not yet bound in modules/steganography.py"
    )
