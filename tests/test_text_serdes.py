from __future__ import annotations

import subprocess
import sys
import zlib
from datetime import date
from pathlib import Path

import base91
import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from text_serdes.codec import CodecError, date_key, decrypt_payload, decrypt_text, encrypt_bytes


TODAY = date(2026, 6, 1)
YESTERDAY = date(2026, 5, 31)


def test_round_trip_with_fixed_date() -> None:
    plaintext = b"alpha\nbeta\n\x00\xff"

    encoded = encrypt_bytes(plaintext, TODAY)

    assert "\n" not in encoded
    assert decrypt_text(encoded, TODAY) == plaintext


def test_short_stdin_payload_uses_raw_format() -> None:
    encoded = encrypt_bytes(b"TypeError: invalid literal", TODAY)

    payload = bytes(base91.decode(encoded))

    assert payload.startswith(b"DR1")


def test_short_stdin_payload_contains_raw_bytes() -> None:
    plaintext = b"TypeError: invalid literal"
    encoded = encrypt_bytes(b"TypeError: invalid literal", TODAY)

    payload = _decrypt_payload_bytes(encoded)

    assert payload == plaintext


def test_repeated_stdin_payload_uses_zlib_format() -> None:
    plaintext = b"TypeError: invalid literal\n" * 50
    encoded = encrypt_bytes(plaintext, TODAY)
    payload = bytes(base91.decode(encoded))

    assert payload.startswith(b"DZ1")
    assert zlib.decompress(_decrypt_payload_bytes(encoded)) == plaintext


def test_file_payload_embeds_basename() -> None:
    encoded = encrypt_bytes(b"file bytes\n", TODAY, filename="message.txt")

    payload = decrypt_payload(encoded, TODAY)

    assert payload.filename == "message.txt"
    assert payload.data == b"file bytes\n"


def test_file_payload_uses_file_format() -> None:
    encoded = encrypt_bytes(b"file bytes\n", TODAY, filename="message.txt")
    payload = bytes(base91.decode(encoded))

    assert payload.startswith(b"FR1")


def test_wrong_date_fails() -> None:
    encoded = encrypt_bytes(b"secret", TODAY)

    with pytest.raises(CodecError):
        decrypt_text(encoded, YESTERDAY)


def test_malformed_input_fails() -> None:
    with pytest.raises(CodecError):
        decrypt_text("not valid for this tool", TODAY)


def test_terminal_paste_sequences_are_ignored() -> None:
    encoded = encrypt_bytes(b"pasted through terminal", TODAY)

    assert decrypt_text(f"\x1b[200~{encoded}\x1b[201~", TODAY) == b"pasted through terminal"


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

    input_file.write_bytes(b"will be overwritten\n")
    decoded = subprocess.run(
        [str(Path(sys.executable).parent / "dec")],
        input=encoded,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
        cwd=tmp_path,
    ).stdout

    assert decoded == b""
    assert input_file.read_bytes() == b"file bytes\n"


def _decrypt_payload_bytes(encoded: str) -> bytes:
    payload = bytes(base91.decode(encoded))
    magic = payload[:3]
    body = payload[3:]
    nonce = body[:12]
    ciphertext = body[12:]
    return AESGCM(date_key(TODAY)).decrypt(nonce, ciphertext, magic)
