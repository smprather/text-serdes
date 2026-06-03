from __future__ import annotations

import subprocess
import sys
import zlib
from datetime import date
from pathlib import Path

import base91
import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from text_serdes import shoco
from text_serdes.codec import CodecError, date_key, decrypt_text, encrypt_bytes


TODAY = date(2026, 6, 1)
YESTERDAY = date(2026, 5, 31)


def test_round_trip_with_fixed_date() -> None:
    plaintext = b"alpha\nbeta\n\x00\xff"

    encoded = encrypt_bytes(plaintext, TODAY)

    assert "\n" not in encoded
    assert decrypt_text(encoded, TODAY) == plaintext


def test_encrypt_uses_zlib_format() -> None:
    encoded = encrypt_bytes(b"TypeError: invalid literal", TODAY)

    payload = bytes(base91.decode(encoded))

    assert payload.startswith(b"DC1")


def test_zlib_payload_contains_compressed_bytes() -> None:
    plaintext = b"TypeError: invalid literal"
    encoded = encrypt_bytes(b"TypeError: invalid literal", TODAY)

    compressed = _decrypt_zlib_payload(encoded)

    assert zlib.decompress(compressed) == plaintext


def test_shoco_round_trips_binary_bytes() -> None:
    plaintext = b"\x00TypeError: caf\xc3\xa9 value\xff\n"

    compressed = shoco.compress(plaintext)

    assert shoco.decompress(compressed) == plaintext


def test_legacy_zlib_payload_still_decodes() -> None:
    nonce = b"\x01" * 12
    ciphertext = AESGCM(date_key(TODAY)).encrypt(nonce, zlib.compress(b"legacy bytes"), None)
    encoded = base91.encode(b"DC1" + nonce + ciphertext)

    assert decrypt_text(encoded, TODAY) == b"legacy bytes"


def test_legacy_shoco_payload_still_decodes() -> None:
    nonce = b"\x02" * 12
    ciphertext = AESGCM(date_key(TODAY)).encrypt(nonce, shoco.compress(b"legacy shoco"), None)
    encoded = base91.encode(b"DC2" + nonce + ciphertext)

    assert decrypt_text(encoded, TODAY) == b"legacy shoco"


def test_legacy_hybrid_zlib_payload_still_decodes() -> None:
    nonce = b"\x03" * 12
    compressed = b"Z" + zlib.compress(b"legacy hybrid zlib")
    ciphertext = AESGCM(date_key(TODAY)).encrypt(nonce, compressed, None)
    encoded = base91.encode(b"DC3" + nonce + ciphertext)

    assert decrypt_text(encoded, TODAY) == b"legacy hybrid zlib"


def test_legacy_hybrid_shoco_payload_still_decodes() -> None:
    nonce = b"\x04" * 12
    compressed = b"S" + shoco.compress(b"legacy hybrid shoco")
    ciphertext = AESGCM(date_key(TODAY)).encrypt(nonce, compressed, None)
    encoded = base91.encode(b"DC3" + nonce + ciphertext)

    assert decrypt_text(encoded, TODAY) == b"legacy hybrid shoco"


def test_wrong_date_fails() -> None:
    encoded = encrypt_bytes(b"secret", TODAY)

    with pytest.raises(CodecError):
        decrypt_text(encoded, YESTERDAY)


def test_malformed_input_fails() -> None:
    with pytest.raises(CodecError):
        decrypt_text("not valid for this tool", TODAY)


def test_cli_round_trip_from_stdin() -> None:
    plaintext = b"from stdin\nwith newline\n"
    encoded = subprocess.run(
        [sys.executable, "-m", "text_serdes.cli"],
        input=plaintext,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    ).stdout

    assert encoded.endswith(b"\n")
    assert b"\n" not in encoded[:-1]

    decoded = subprocess.run(
        ["uv", "run", "dec"],
        input=encoded,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    ).stdout

    assert decoded == plaintext


def test_cli_file_input(tmp_path: Path) -> None:
    input_file = tmp_path / "message.txt"
    input_file.write_bytes(b"file bytes\n")

    encoded = subprocess.run(
        ["uv", "run", "enc", str(input_file)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    ).stdout

    decoded = subprocess.run(
        ["uv", "run", "dec"],
        input=encoded,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    ).stdout

    assert decoded == b"file bytes\n"


def _decrypt_zlib_payload(encoded: str) -> bytes:
    payload = bytes(base91.decode(encoded))
    assert payload.startswith(b"DC1")
    body = payload[3:]
    nonce = body[:12]
    ciphertext = body[12:]
    return AESGCM(date_key(TODAY)).decrypt(nonce, ciphertext, None)
