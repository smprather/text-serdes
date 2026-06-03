from __future__ import annotations

import base91
import zlib
from dataclasses import dataclass
from datetime import date
from hashlib import sha256
from os import urandom

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b"DC1"
ENVELOPE_MAGIC = b"TS1"
STDIN_FLAG = 0
FILE_FLAG = 1
MAX_FILENAME_SIZE = 4096
NONCE_SIZE = 12


class CodecError(ValueError):
    """Raised when encoded input cannot be decoded with today's key."""


@dataclass(frozen=True)
class DecodedPayload:
    data: bytes
    filename: str | None = None


def date_key(day: date | None = None) -> bytes:
    """Derive the AES-256 key from a local calendar date."""
    current_day = day or date.today()
    return sha256(current_day.isoformat().encode("ascii")).digest()


def encrypt_bytes(data: bytes, day: date | None = None, filename: str | None = None) -> str:
    compressed = zlib.compress(_pack_payload(data, filename))
    nonce = urandom(NONCE_SIZE)
    ciphertext = AESGCM(date_key(day)).encrypt(nonce, compressed, None)
    return base91.encode(MAGIC + nonce + ciphertext)


def decrypt_text(encoded: str, day: date | None = None) -> bytes:
    return decrypt_payload(encoded, day).data


def decrypt_payload(encoded: str, day: date | None = None) -> DecodedPayload:
    try:
        payload = bytes(base91.decode(encoded.strip()))
    except Exception as exc:
        raise CodecError("input is not valid Base91") from exc

    if not payload.startswith(MAGIC):
        raise CodecError("input has an unsupported format")

    body = payload[len(MAGIC) :]
    if len(body) <= NONCE_SIZE:
        raise CodecError("input is too short")

    nonce = body[:NONCE_SIZE]
    ciphertext = body[NONCE_SIZE:]
    try:
        compressed = AESGCM(date_key(day)).decrypt(nonce, ciphertext, None)
    except InvalidTag as exc:
        raise CodecError("decrypt failed; wrong date or corrupt input") from exc

    return _unpack_payload(_decompress_zlib(compressed))


def _decompress_zlib(compressed: bytes) -> bytes:
    try:
        return zlib.decompress(compressed)
    except zlib.error as exc:
        raise CodecError("decompressed payload is invalid") from exc


def _pack_payload(data: bytes, filename: str | None) -> bytes:
    if filename is None:
        return ENVELOPE_MAGIC + bytes([STDIN_FLAG]) + data

    filename_bytes = filename.encode("utf-8")
    if not filename_bytes or len(filename_bytes) > MAX_FILENAME_SIZE:
        raise CodecError("filename is empty or too long")

    return ENVELOPE_MAGIC + bytes([FILE_FLAG]) + len(filename_bytes).to_bytes(2, "big") + filename_bytes + data


def _unpack_payload(payload: bytes) -> DecodedPayload:
    if not payload.startswith(ENVELOPE_MAGIC):
        raise CodecError("decompressed payload has an unsupported envelope")

    body = payload[len(ENVELOPE_MAGIC) :]
    if not body:
        raise CodecError("decompressed payload is missing an envelope flag")

    flag = body[0]
    body = body[1:]
    if flag == STDIN_FLAG:
        return DecodedPayload(body)

    if flag != FILE_FLAG:
        raise CodecError("decompressed payload has an unknown envelope flag")
    if len(body) < 2:
        raise CodecError("decompressed payload is missing a filename length")

    filename_size = int.from_bytes(body[:2], "big")
    body = body[2:]
    if filename_size == 0 or filename_size > MAX_FILENAME_SIZE or len(body) < filename_size:
        raise CodecError("decompressed payload has an invalid filename")

    try:
        filename = body[:filename_size].decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CodecError("decompressed payload has an invalid filename") from exc

    return DecodedPayload(body[filename_size:], filename)
