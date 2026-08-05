from __future__ import annotations

import json
import os
import subprocess
import sys
import zlib
from hashlib import sha256
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


def test_whitespace_damage_is_ignored() -> None:
    encoded = encrypt_bytes(b"wrapped paste survives")
    damaged = f"  {encoded[:7]}\n{encoded[7:21]}\r\n{encoded[21:]}\t "

    assert decrypt_text(damaged) == b"wrapped paste survives"


def test_noisy_paste_can_still_be_decoded() -> None:
    encoded = encrypt_bytes(b"noise around the payload")
    noisy = (
        "❯ uv run text-serdes-enc\n"
        " some transcript before\n"
        f"  {encoded[:18]}\n"
        f"{encoded[18:52]}\n"
        f"{encoded[52:]}\n"
        " transcript after\n"
    )

    assert decrypt_text(noisy) == b"noise around the payload"


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
        ["uv", "run", "text-serdes-dec"],
        input=encoded,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    ).stdout

    assert decoded == plaintext


def test_cli_wraps_long_encoded_output() -> None:
    plaintext = b"".join(sha256(i.to_bytes(2, "big")).digest() for i in range(128))

    encoded = subprocess.run(
        ["uv", "run", "text-serdes-enc"],
        input=plaintext,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    ).stdout

    lines = encoded.rstrip(b"\n").splitlines()
    assert len(lines) > 1
    assert max(len(line) for line in lines) <= 100

    decoded = subprocess.run(
        ["uv", "run", "text-serdes-dec"],
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
        ["uv", "run", "text-serdes-enc", str(input_file)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    ).stdout

    input_file.write_bytes(b"will be overwritten\n")
    decoded = subprocess.run(
        [str(Path(sys.executable).parent / "text-serdes-dec")],
        input=encoded,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
        cwd=tmp_path,
    ).stdout

    assert decoded == b""
    assert input_file.read_bytes() == b"file bytes\n"


def test_cli_output_file_overrides_embedded_filename(tmp_path: Path) -> None:
    input_file = tmp_path / "embedded.txt"
    input_file.write_bytes(b"payload with file name")

    encoded = subprocess.run(
        ["uv", "run", "text-serdes-enc", str(input_file)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    ).stdout

    output_file = tmp_path / "forced.txt"
    subprocess.run(
        ["uv", "run", "text-serdes-dec", "--output", str(output_file)],
        input=encoded,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    )

    assert output_file.read_bytes() == b"payload with file name"


def test_cli_output_directory_requires_embedded_filename(tmp_path: Path) -> None:
    encoded = subprocess.run(
        [str(Path(sys.executable).parent / "text-serdes-enc")],
        input=b"plain stdin payload",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    ).stdout

    result = subprocess.run(
        ["uv", "run", "text-serdes-dec", "--output", str(tmp_path)],
        input=encoded,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )

    assert result.returncode != 0
    assert b"embedded filename" in result.stderr


def test_cli_output_directory_uses_embedded_filename(tmp_path: Path) -> None:
    input_file = tmp_path / "source.txt"
    input_file.write_bytes(b"directory target")

    encoded = subprocess.run(
        ["uv", "run", "text-serdes-enc", str(input_file)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    ).stdout

    output_dir = tmp_path / "out"
    output_dir.mkdir()
    subprocess.run(
        ["uv", "run", "text-serdes-dec", "--output", str(output_dir)],
        input=encoded,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    )

    assert (output_dir / "source.txt").read_bytes() == b"directory target"


def test_cli_dev_logs_encode_and_decode(tmp_path: Path) -> None:
    dev_dir = tmp_path / "dev-logs"
    env = {**os.environ, "TEXT_SERDES_DEV_DIR": str(dev_dir)}
    input_file = tmp_path / "source.txt"
    input_file.write_bytes(b"dev log payload")

    encoded = subprocess.run(
        ["uv", "run", "text-serdes-enc", "--dev", str(input_file)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
        env=env,
    ).stdout

    enc_log = json.loads((dev_dir / "enc-latest.json").read_text())
    encoded_text = "".join(encoded.decode("ascii").split())
    assert enc_log["result"]["ok"] is True
    assert enc_log["input"]["bytes"] == len(b"dev log payload")
    assert enc_log["input"]["filename_embedded"] == "source.txt"
    assert enc_log["output"]["chars"] == len(encoded_text)
    assert enc_log["output"]["sha256"] == sha256(encoded_text.encode("ascii")).hexdigest()
    assert enc_log["output"]["wrap_columns"] == 100

    output_dir = tmp_path / "out"
    output_dir.mkdir()
    subprocess.run(
        ["uv", "run", "text-serdes-dec", "--dev", "--output", str(output_dir)],
        input=encoded,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
        env=env,
    )

    dec_log = json.loads((dev_dir / "dec-latest.json").read_text())
    assert dec_log["result"]["ok"] is True
    assert dec_log["input"]["bytes"] == len(encoded)
    assert dec_log["encoded_text"]["non_whitespace_chars"] == len(encoded_text)
    assert dec_log["decode"]["attempts"][0]["candidate_chars"] == len(encoded_text)
    assert dec_log["output"]["target"] == str(output_dir / "source.txt")


def test_cli_dev_logs_decode_failure(tmp_path: Path) -> None:
    dev_dir = tmp_path / "dev-logs"
    env = {**os.environ, "TEXT_SERDES_DEV_DIR": str(dev_dir)}
    encoded = encrypt_bytes(b"will be truncated").encode("ascii")

    result = subprocess.run(
        ["uv", "run", "text-serdes-dec", "--dev"],
        input=encoded[:-8] + b"\n",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        env=env,
    )

    dec_log = json.loads((dev_dir / "dec-latest.json").read_text())
    assert result.returncode != 0
    assert dec_log["result"]["ok"] is False
    assert dec_log["input"]["bytes"] == len(encoded[:-8]) + 1
    assert dec_log["decode"]["attempts"][0]["candidate_chars"] == len(encoded[:-8])
