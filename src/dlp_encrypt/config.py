from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    """Runtime configuration loaded from environment variables."""

    encryption_key: bytes

    @classmethod
    def from_env(cls) -> Settings:
        key_hex = (
            os.environ.get("ENCRYPTION_KEY_HEX", "").strip()
            or os.environ.get("DECRYPTION_KEY_HEX", "").strip()
        )
        if not key_hex:
            raise ValueError(
                "ENCRYPTION_KEY_HEX (or DECRYPTION_KEY_HEX) environment variable is required"
            )

        try:
            key = bytes.fromhex(key_hex)
        except ValueError as exc:
            raise ValueError("Encryption key must be a valid hex string") from exc

        if len(key) not in (16, 24, 32):
            raise ValueError("Encryption key must decode to 16, 24, or 32 bytes (AES key)")

        return cls(encryption_key=key)
