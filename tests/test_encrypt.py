import base64
import os

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from dlp_encrypt.encrypt import encrypt_aes_gcm, encrypt_file, encode_base64


@pytest.fixture
def aes_key() -> bytes:
    return os.urandom(32)


def _decrypt(key: bytes, payload: bytes, *, nonce: bytes | None = None) -> bytes:
    if nonce is None:
        nonce = payload[:12]
        payload = payload[12:]
    return AESGCM(key).decrypt(nonce, payload, None)


def test_encrypt_embedded_nonce(aes_key):
    plaintext = b"hello dlp-encrypt"
    result = encrypt_aes_gcm(plaintext=plaintext, key=aes_key, filename="test.txt")

    assert _decrypt(aes_key, result.payload) == plaintext
    assert result.nonce == result.payload[:12]


def test_encrypt_external_nonce(aes_key):
    plaintext = b"external nonce"
    nonce = os.urandom(12)
    result = encrypt_aes_gcm(
        plaintext=plaintext,
        key=aes_key,
        nonce=nonce,
        embed_nonce=False,
    )

    assert _decrypt(aes_key, result.ciphertext, nonce=nonce) == plaintext
    assert result.payload == result.ciphertext


def test_encrypt_file(tmp_path, aes_key):
    input_path = tmp_path / "sample.txt"
    input_path.write_text("document body", encoding="utf-8")

    result = encrypt_file(input_path, key=aes_key)

    assert result.output_path is not None
    assert result.output_path.exists()
    assert _decrypt(aes_key, result.output_path.read_bytes()) == b"document body"


def test_roundtrip_base64(aes_key):
    plaintext = b"base64 roundtrip"
    result = encrypt_aes_gcm(plaintext=plaintext, key=aes_key)
    encoded = encode_base64(result.payload)
    assert base64.b64decode(encoded) == result.payload
