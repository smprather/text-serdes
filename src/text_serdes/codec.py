from __future__ import annotations

import base91
import zlib
from datetime import date
from hashlib import sha256
from os import urandom

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b"DC1"
NONCE_SIZE = 12


class CodecError(ValueError):
    """Raised when encoded input cannot be decoded with today's key."""


def date_key(day: date | None = None) -> bytes:
    """Derive the AES-256 key from a local calendar date."""
    current_day = day or date.today()
    return sha256(current_day.isoformat().encode("ascii")).digest()


def encrypt_bytes(data: bytes, day: date | None = None) -> str:
    compressed = zlib.compress(data)
    nonce = urandom(NONCE_SIZE)
    ciphertext = AESGCM(date_key(day)).encrypt(nonce, compressed, None)
    return base91.encode(MAGIC + nonce + ciphertext)


def decrypt_text(encoded: str, day: date | None = None) -> bytes:
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

    return _decompress_zlib(compressed)


def _decompress_zlib(compressed: bytes) -> bytes:
    try:
        return zlib.decompress(compressed)
    except zlib.error as exc:
        raise CodecError("decompressed payload is invalid") from exc
