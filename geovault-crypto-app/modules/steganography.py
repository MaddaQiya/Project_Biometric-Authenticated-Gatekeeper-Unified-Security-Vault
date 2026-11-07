"""
GeoVault - LSB PNG Image Steganography                       [DEVELOPER 2 STUB]
===============================================================================

Contract for Developer 2
------------------------
Implement Least Significant Bit (LSB) steganography on lossless **PNG** images
using ``Pillow`` (``PIL.Image``):
  1. Convert cover image to RGB/RGBA, compute pixel bit capacity via :func:`calculate_capacity`.
  2. Prepend a length header or sentinel delimiter (and optionally encrypt or MAC-protect
     the payload with ``passphrase`` if provided) before embedding bits into the R, G, B
     channel LSBs.
  3. Save the stego image strictly as lossless **PNG** bytes (never JPEG, which destroys LSBs).

Do NOT modify ``app.py`` signatures—only implement the functions below.
"""

from __future__ import annotations

from typing import Optional


class SteganographyNotImplementedError(NotImplementedError):
    """Raised while Developer 2's steganography module is still a stub."""


def calculate_capacity(image_bytes: bytes) -> int:
    """
    Calculate the maximum UTF-8 payload size (in bytes) that fits inside ``image_bytes``.

    :param image_bytes: Raw bytes of the cover image.
    :returns:           Maximum embeddable message bytes (excluding header overhead).
    """
    raise SteganographyNotImplementedError(
        "Developer 2: implement calculate_capacity() in modules/steganography.py"
    )


def embed_message_lsb(
    cover_image_bytes: bytes,
    secret_message: str,
    passphrase: Optional[str] = None,
) -> bytes:
    """
    Hide ``secret_message`` inside the LSBs of ``cover_image_bytes`` and return PNG bytes.

    :param cover_image_bytes: Uploaded cover image bytes (PNG/BMP).
    :param secret_message:    Secret text or coordinates to embed.
    :param passphrase:        Optional passphrase to encrypt/seed bit placement.
    :returns:                 Lossless PNG image bytes containing the hidden payload.
    :raises ValueError:       If the secret message exceeds cover image capacity.
    """
    raise SteganographyNotImplementedError(
        "Developer 2: implement embed_message_lsb() in modules/steganography.py"
    )


def extract_message_lsb(
    stego_image_bytes: bytes,
    passphrase: Optional[str] = None,
) -> str:
    """
    Extract a hidden UTF-8 message from a stego PNG image.

    :param stego_image_bytes: PNG bytes containing an LSB-embedded payload.
    :param passphrase:        Optional passphrase used during embedding.
    :returns:                 Extracted plaintext message.
    :raises ValueError:       If no valid GeoVault stego header/payload is found or passphrase fails.
    """
    raise SteganographyNotImplementedError(
        "Developer 2: implement extract_message_lsb() in modules/steganography.py"
    )
