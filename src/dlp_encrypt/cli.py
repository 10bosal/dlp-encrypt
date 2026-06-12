from __future__ import annotations

import argparse
import sys
from pathlib import Path

from dlp_encrypt.config import Settings
from dlp_encrypt.encrypt import EncryptionError, encode_base64, encrypt_file


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Encrypt a document with AES-GCM for DLP MCP",
    )
    parser.add_argument("input", type=Path, help="Path to plaintext file")
    parser.add_argument("-o", "--output", type=Path, help="Output path (default: input.ext.enc)")
    parser.add_argument(
        "--key-hex",
        help="AES key as hex (default: ENCRYPTION_KEY_HEX or DECRYPTION_KEY_HEX env var)",
    )
    parser.add_argument("--mime-type", help="MIME type hint for decryption (e.g. text/plain)")
    parser.add_argument(
        "--no-embed-nonce",
        action="store_true",
        help="Do not prepend nonce to output (pass nonce separately to dlp-mcp)",
    )
    parser.add_argument(
        "--print-b64",
        action="store_true",
        help="Print base64-encoded payload for MCP tool input",
    )
    args = parser.parse_args()

    if args.key_hex:
        try:
            key = bytes.fromhex(args.key_hex)
        except ValueError:
            print("Error: --key-hex must be a valid hex string", file=sys.stderr)
            return 1
        if len(key) not in (16, 24, 32):
            print("Error: key must decode to 16, 24, or 32 bytes", file=sys.stderr)
            return 1
    else:
        try:
            key = Settings.from_env().encryption_key
        except ValueError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return 1

    try:
        result = encrypt_file(
            args.input,
            key=key,
            output_path=args.output,
            mime_type=args.mime_type,
            embed_nonce=not args.no_embed_nonce,
        )
    except EncryptionError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    output = result.output_path or args.output or args.input.with_suffix(args.input.suffix + ".enc")
    print(f"Encrypted -> {output}")
    print(f"Size: {len(result.payload)} bytes")

    if args.print_b64:
        print(f"Base64 (for MCP tool input):\n{encode_base64(result.payload)}")

    if not args.no_embed_nonce:
        return 0

    print(f"Nonce (base64): {encode_base64(result.nonce)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
