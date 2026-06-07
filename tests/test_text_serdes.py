from __future__ import annotations

import subprocess
import sys
import zlib
from pathlib import Path

import base91
import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from text_serdes.codec import (
    CodecError,
    _part,
    _seal,
    decrypt_payload,
    decrypt_text,
    encrypt_bytes,
)


def _core_and_token(encoded: str) -> tuple[bytes, str]:
    core, token = _part(encoded)
    return bytes(base91.decode(core)), token


def _decrypt_payload_bytes(encoded: str) -> bytes:
    payload, token = _core_and_token(encoded)
    magic = payload[:3]
    body = payload[3:]
    nonce = body[:12]
    ciphertext = body[12:]
    return AESGCM(_seal(token)).decrypt(nonce, ciphertext, magic)


def test_round_trip() -> None:
    plaintext = b"alpha\nbeta\n\x00\xff"

    encoded = encrypt_bytes(plaintext)

    assert "\n" not in encoded
    assert decrypt_text(encoded) == plaintext


def test_self_contained_round_trip_is_date_independent() -> None:
    # the key now rides inside the line, so decode no longer depends on a date
    encoded = encrypt_bytes(b"self contained")

    assert decrypt_text(encoded) == b"self contained"


def test_short_stdin_payload_uses_raw_format() -> None:
    encoded = encrypt_bytes(b"TypeError: invalid literal")

    payload, _ = _core_and_token(encoded)

    assert payload.startswith(b"DR1")


def test_short_stdin_payload_contains_raw_bytes() -> None:
    plaintext = b"TypeError: invalid literal"
    encoded = encrypt_bytes(plaintext)

    payload = _decrypt_payload_bytes(encoded)

    assert payload == plaintext


def test_repeated_stdin_payload_uses_zlib_format() -> None:
    plaintext = b"TypeError: invalid literal\n" * 50
    encoded = encrypt_bytes(plaintext)
    payload, _ = _core_and_token(encoded)

    assert payload.startswith(b"DZ1")
    assert zlib.decompress(_decrypt_payload_bytes(encoded)) == plaintext


def test_file_payload_embeds_basename() -> None:
    encoded = encrypt_bytes(b"file bytes\n", filename="message.txt")

    payload = decrypt_payload(encoded)

    assert payload.filename == "message.txt"
    assert payload.data == b"file bytes\n"


def test_file_payload_uses_file_format() -> None:
    encoded = encrypt_bytes(b"file bytes\n", filename="message.txt")
    payload, _ = _core_and_token(encoded)

    assert payload.startswith(b"FR1")


def test_tampered_token_fails() -> None:
    encoded = encrypt_bytes(b"secret")

    mid = len(encoded) // 2
    swap = "A" if encoded[mid] != "A" else "B"
    broken = encoded[:mid] + swap + encoded[mid + 1 :]

    with pytest.raises(CodecError):
        decrypt_text(broken)


def test_ts_key_passphrase_must_match(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TS_KEY", "hunter2")
    encoded = encrypt_bytes(b"with passphrase")

    assert decrypt_text(encoded) == b"with passphrase"

    monkeypatch.setenv("TS_KEY", "wrong")
    with pytest.raises(CodecError):
        decrypt_text(encoded)

    monkeypatch.delenv("TS_KEY")
    with pytest.raises(CodecError):
        decrypt_text(encoded)


def test_malformed_input_fails() -> None:
    with pytest.raises(CodecError):
        decrypt_text("not valid for this tool")


def test_terminal_paste_sequences_are_ignored() -> None:
    encoded = encrypt_bytes(b"pasted through terminal")

    assert decrypt_text(f"\x1b[200~{encoded}\x1b[201~") == b"pasted through terminal"


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
