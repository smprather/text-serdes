from __future__ import annotations

import base91
import zlib
from datetime import date
from hashlib import sha256
from os import urandom

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import shoco

MAGIC = b"DC3"
LEGACY_SHOCO_MAGIC = b"DC2"
LEGACY_ZLIB_MAGIC = b"DC1"
NONCE_SIZE = 12
SHOCO_METHOD = b"S"
ZLIB_METHOD = b"Z"


class CodecError(ValueError):
    """Raised when encoded input cannot be decoded with today's key."""


def date_key(day: date | None = None) -> bytes:
    """Derive the AES-256 key from a local calendar date."""
    current_day = day or date.today()
    return sha256(current_day.isoformat().encode("ascii")).digest()


def encrypt_bytes(data: bytes, day: date | None = None) -> str:
    method, compressed = _compress_best(data)
    nonce = urandom(NONCE_SIZE)
    ciphertext = AESGCM(date_key(day)).encrypt(nonce, method + compressed, None)
    return base91.encode(MAGIC + nonce + ciphertext)


def _compress_best(data: bytes) -> tuple[bytes, bytes]:
    shoco_data = shoco.compress(data)
    zlib_data = zlib.compress(data)
    if len(zlib_data) < len(shoco_data):
        return ZLIB_METHOD, zlib_data
    return SHOCO_METHOD, shoco_data


def decrypt_text(encoded: str, day: date | None = None) -> bytes:
    try:
        payload = bytes(base91.decode(encoded.strip()))
    except Exception as exc:
        raise CodecError("input is not valid Base91") from exc

    if payload.startswith(MAGIC):
        magic = MAGIC
    elif payload.startswith(LEGACY_SHOCO_MAGIC):
        magic = LEGACY_SHOCO_MAGIC
    elif payload.startswith(LEGACY_ZLIB_MAGIC):
        magic = LEGACY_ZLIB_MAGIC
    else:
        raise CodecError("input has an unsupported format")

    body = payload[len(magic) :]
    if len(body) <= NONCE_SIZE:
        raise CodecError("input is too short")

    nonce = body[:NONCE_SIZE]
    ciphertext = body[NONCE_SIZE:]
    try:
        compressed = AESGCM(date_key(day)).decrypt(nonce, ciphertext, None)
    except InvalidTag as exc:
        raise CodecError("decrypt failed; wrong date or corrupt input") from exc

    if magic == MAGIC:
        if not compressed:
            raise CodecError("compressed payload is missing a method")
        method = compressed[:1]
        compressed = compressed[1:]
        if method == SHOCO_METHOD:
            return _decompress_shoco(compressed)
        if method == ZLIB_METHOD:
            return _decompress_zlib(compressed)
        raise CodecError("compressed payload has an unknown method")

    if magic == LEGACY_ZLIB_MAGIC:
        return _decompress_zlib(compressed)
    return _decompress_shoco(compressed)


def _decompress_zlib(compressed: bytes) -> bytes:
    try:
        return zlib.decompress(compressed)
    except zlib.error as exc:
        raise CodecError("decompressed payload is invalid") from exc


def _decompress_shoco(compressed: bytes) -> bytes:
    try:
        return shoco.decompress(compressed)
    except ValueError as exc:
        raise CodecError("decompressed payload is invalid") from exc
