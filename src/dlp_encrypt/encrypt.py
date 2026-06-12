from __future__ import annotations

import base64
import os
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


@dataclass(frozen=True)
class EncryptResult:
    """Result of a successful encryption."""

    payload: bytes
    nonce: bytes
    ciphertext: bytes
    filename: str
    mime_type: str | None
    output_path: Path | None


class EncryptionError(Exception):
    """Raised when encryption fails."""


def encrypt_aes_gcm(
    *,
    plaintext: bytes,
    key: bytes,
    nonce: bytes | None = None,
    associated_data: bytes | None = None,
    embed_nonce: bool = True,
    filename: str = "encrypted.bin",
    mime_type: str | None = None,
    output_path: Path | None = None,
) -> EncryptResult:
    """
    Encrypt data with AES-GCM for use with dlp-mcp.

    Default file format:
      [12-byte nonce][ciphertext + 16-byte auth tag]

    Set embed_nonce=False to return ciphertext without a leading nonce.
    """
    if len(key) not in (16, 24, 32):
        raise EncryptionError("AES key must be 16, 24, or 32 bytes")

    nonce = nonce or os.urandom(12)
    if len(nonce) != 12:
        raise EncryptionError("AES-GCM nonce must be 12 bytes")

    try:
        ciphertext = AESGCM(key).encrypt(nonce, plaintext, associated_data)
    except Exception as exc:
        raise EncryptionError("Encryption failed") from exc

    payload = (nonce + ciphertext) if embed_nonce else ciphertext

    if output_path is not None:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_bytes(payload)

    return EncryptResult(
        payload=payload,
        nonce=nonce,
        ciphertext=ciphertext,
        filename=Path(filename).name or "encrypted.bin",
        mime_type=mime_type,
        output_path=output_path,
    )


def encrypt_file(
    input_path: Path,
    *,
    key: bytes,
    output_path: Path | None = None,
    mime_type: str | None = None,
    associated_data: bytes | None = None,
    embed_nonce: bool = True,
) -> EncryptResult:
    """Encrypt a file from disk."""
    if not input_path.is_file():
        raise EncryptionError(f"Input file not found: {input_path}")

    plaintext = input_path.read_bytes()
    if output_path is None:
        output_path = input_path.with_suffix(input_path.suffix + ".enc")

    return encrypt_aes_gcm(
        plaintext=plaintext,
        key=key,
        associated_data=associated_data,
        embed_nonce=embed_nonce,
        filename=input_path.name,
        mime_type=mime_type,
        output_path=output_path,
    )


def encode_base64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")
