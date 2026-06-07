from __future__ import annotations

import base91
import re
import zlib
from dataclasses import dataclass
from hashlib import sha256
from os import getenv, urandom

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

RAW_STDIN_MAGIC = b"DR1"
ZLIB_STDIN_MAGIC = b"DZ1"
RAW_FILE_MAGIC = b"FR1"
ZLIB_FILE_MAGIC = b"FZ1"
MAX_FILENAME_SIZE = 4096
NONCE_SIZE = 12
CSI_SEQUENCE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
OSC_SEQUENCE = re.compile(r"\x1b\].*?(?:\x07|\x1b\\)", re.DOTALL)


class CodecError(ValueError):
    """Raised when encoded input cannot be decoded with today's key."""


@dataclass(frozen=True)
class DecodedPayload:
    data: bytes
    filename: str | None = None


# -- key plumbing ----------------------------------------------------------
# The AES-256 key is derived per message from a short token that travels woven
# into the encoded line, combined with a fixed component held below as masked
# bytes rather than a readable literal, and with the optional TS_KEY passphrase
# from the environment (empty when unset). Layout of these helpers is left
# deliberately opaque; the comments here are the only signposts.
_VEIL = 0x53
_GRAIN = (
    0x27, 0x20, 0x60, 0x7c, 0x37, 0x3c, 0x7e, 0x3d, 0x3c, 0x27,
    0x7e, 0x20, 0x27, 0x32, 0x21, 0x36, 0x7c, 0x25, 0x61,
)
_SPAN = 0b1010


def _seal(t: str) -> bytes:
    base = bytes(g ^ _VEIL for g in _GRAIN) + getenv("TS_KEY", "").encode("utf-8")
    return sha256(base + t.encode("ascii")).digest()


def _tag() -> str:
    a = base91.base91_alphabet
    return "".join(a[o % len(a)] for o in urandom(_SPAN))


def _knit(s: str, t: str) -> str:
    p = len(s) >> 1
    return s[:p] + t + s[p:]


def _part(s: str) -> tuple[str, str]:
    p = (len(s) - _SPAN) >> 1
    return s[:p] + s[p + _SPAN :], s[p : p + _SPAN]


def encrypt_bytes(data: bytes, filename: str | None = None) -> str:
    payload = _pack_file_payload(data, filename) if filename is not None else data
    compressed = zlib.compress(payload)
    should_compress = len(compressed) < len(payload)
    magic = _magic_for(filename is not None, should_compress)
    encrypted_payload = compressed if should_compress else payload
    nonce = urandom(NONCE_SIZE)
    token = _tag()
    ciphertext = AESGCM(_seal(token)).encrypt(nonce, encrypted_payload, magic)
    return _knit(base91.encode(magic + nonce + ciphertext), token)


def decrypt_text(encoded: str) -> bytes:
    return decrypt_payload(encoded).data


def decrypt_payload(encoded: str) -> DecodedPayload:
    core, token = _part(_strip_terminal_sequences(encoded).strip())
    try:
        payload = bytes(base91.decode(core))
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
        decrypted = AESGCM(_seal(token)).decrypt(nonce, ciphertext, magic)
    except InvalidTag as exc:
        raise CodecError("decrypt failed; corrupt or tampered input") from exc

    payload_bytes = _decompress_zlib(decrypted) if magic in {ZLIB_STDIN_MAGIC, ZLIB_FILE_MAGIC} else decrypted
    if magic in {RAW_FILE_MAGIC, ZLIB_FILE_MAGIC}:
        return _unpack_file_payload(payload_bytes)
    return DecodedPayload(payload_bytes)


def _decompress_zlib(compressed: bytes) -> bytes:
    try:
        return zlib.decompress(compressed)
    except zlib.error as exc:
        raise CodecError("decompressed payload is invalid") from exc


def _strip_terminal_sequences(text: str) -> str:
    return CSI_SEQUENCE.sub("", OSC_SEQUENCE.sub("", text))


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
