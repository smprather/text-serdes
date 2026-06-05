from __future__ import annotations

import base91
import zlib
from dataclasses import dataclass
from datetime import date
from hashlib import sha256
from os import urandom

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

RAW_STDIN_MAGIC = b"DR1"
ZLIB_STDIN_MAGIC = b"DZ1"
RAW_FILE_MAGIC = b"FR1"
ZLIB_FILE_MAGIC = b"FZ1"
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
    payload = _pack_file_payload(data, filename) if filename is not None else data
    compressed = zlib.compress(payload)
    should_compress = len(compressed) < len(payload)
    magic = _magic_for(filename is not None, should_compress)
    encrypted_payload = compressed if should_compress else payload
    nonce = urandom(NONCE_SIZE)
    ciphertext = AESGCM(date_key(day)).encrypt(nonce, encrypted_payload, magic)
    return base91.encode(magic + nonce + ciphertext)


def decrypt_text(encoded: str, day: date | None = None) -> bytes:
    return decrypt_payload(encoded, day).data


def decrypt_payload(encoded: str, day: date | None = None) -> DecodedPayload:
    try:
        payload = bytes(base91.decode(encoded.strip()))
    except Exception as exc:
        raise CodecError("input is not valid Base91") from exc

    magic = payload[:3]
    if magic not in {RAW_STDIN_MAGIC, ZLIB_STDIN_MAGIC, RAW_FILE_MAGIC, ZLIB_FILE_MAGIC}:
        raise CodecError("input has an unsupported format")

    body = payload[len(magic) :]
    if len(body) <= NONCE_SIZE:
        raise CodecError("input is too short")

    nonce = body[:NONCE_SIZE]
    ciphertext = body[NONCE_SIZE:]
    try:
        decrypted = AESGCM(date_key(day)).decrypt(nonce, ciphertext, magic)
    except InvalidTag as exc:
        raise CodecError("decrypt failed; wrong date or corrupt input") from exc

    payload_bytes = _decompress_zlib(decrypted) if magic in {ZLIB_STDIN_MAGIC, ZLIB_FILE_MAGIC} else decrypted
    if magic in {RAW_FILE_MAGIC, ZLIB_FILE_MAGIC}:
        return _unpack_file_payload(payload_bytes)
    return DecodedPayload(payload_bytes)


def _decompress_zlib(compressed: bytes) -> bytes:
    try:
        return zlib.decompress(compressed)
    except zlib.error as exc:
        raise CodecError("decompressed payload is invalid") from exc


def _magic_for(has_filename: bool, compressed: bool) -> bytes:
    if has_filename:
        return ZLIB_FILE_MAGIC if compressed else RAW_FILE_MAGIC
    return ZLIB_STDIN_MAGIC if compressed else RAW_STDIN_MAGIC


def _pack_file_payload(data: bytes, filename: str) -> bytes:
    filename_bytes = filename.encode("utf-8")
    if not filename_bytes or len(filename_bytes) > MAX_FILENAME_SIZE:
        raise CodecError("filename is empty or too long")

    return len(filename_bytes).to_bytes(2, "big") + filename_bytes + data


def _unpack_file_payload(payload: bytes) -> DecodedPayload:
    if len(payload) < 2:
        raise CodecError("decompressed payload is missing a filename length")

    filename_size = int.from_bytes(payload[:2], "big")
    body = payload[2:]
    if filename_size == 0 or filename_size > MAX_FILENAME_SIZE or len(body) < filename_size:
        raise CodecError("decompressed payload has an invalid filename")

    try:
        filename = body[:filename_size].decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CodecError("decompressed payload has an invalid filename") from exc

    return DecodedPayload(body[filename_size:], filename)
