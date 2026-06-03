from __future__ import annotations

from dataclasses import dataclass

MIN_CHR = 39
MAX_SUCCESSOR_N = 7

CHRS_BY_CHR_ID = b"eaiothnrslucwmdbpfgvyk-HMT'BxIWL"
CHR_IDS_BY_BYTE = {char: index for index, char in enumerate(CHRS_BY_CHR_ID)}

SUCCESSOR_IDS = (
    (7, 4, 12, -1, 6, -1, 1, 0, 3, 5, -1, 9, -1, 8, 2, -1, 15, 14, -1, 10, 11, -1, -1, -1, -1, -1, -1, -1, 13, -1, -1, -1),
    (-1, -1, 6, -1, 1, -1, 0, 3, 2, 4, 15, 11, -1, 9, 5, 10, 13, -1, 12, 8, 7, 14, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1),
    (9, 11, -1, 4, 2, -1, 0, 8, 1, 5, -1, 6, -1, 3, 7, 15, -1, 12, 10, 13, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1),
    (-1, -1, 14, 7, 5, -1, 1, 2, 8, 9, 0, 15, 6, 4, 11, -1, 12, 3, -1, 10, -1, 13, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1),
    (2, 4, 3, 1, 5, 0, -1, 6, 10, 9, 7, 12, 11, -1, -1, -1, -1, 13, -1, -1, 8, -1, 15, -1, -1, -1, 14, -1, -1, -1, -1, -1),
    (0, 1, 2, 3, 4, -1, -1, 5, 9, 10, 6, -1, -1, 8, 15, 11, -1, 14, -1, -1, 7, -1, 13, -1, -1, -1, 12, -1, -1, -1, -1, -1),
    (2, 8, 7, 4, 3, -1, 9, -1, 6, 11, -1, 5, -1, -1, 0, -1, -1, 14, 1, 15, 10, 12, -1, -1, -1, -1, 13, -1, -1, -1, -1, -1),
    (0, 3, 1, 2, 6, -1, 9, 8, 4, 12, 13, 10, -1, 11, 7, -1, -1, 15, 14, -1, 5, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1),
    (0, 6, 3, 4, 1, 2, -1, -1, 5, 10, 7, 9, 11, 12, -1, -1, 8, 14, -1, -1, 15, 13, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1),
    (0, 6, 2, 5, 9, -1, -1, -1, 10, 1, 8, -1, 12, 14, 4, -1, 15, 7, -1, 13, 3, 11, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1),
    (8, 10, 9, 15, 1, -1, 4, 0, 3, 2, -1, 6, -1, 12, 11, 13, 7, 14, 5, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1),
    (1, 3, 6, 0, 4, 2, -1, 7, 13, 8, 9, 11, -1, -1, 15, -1, -1, -1, -1, -1, 10, 5, 14, -1, -1, -1, -1, -1, -1, -1, -1, -1),
    (3, 0, 1, 4, -1, 2, 5, 6, 7, 8, -1, 14, -1, -1, 9, 15, -1, 12, -1, -1, -1, 10, 11, -1, -1, -1, 13, -1, -1, -1, -1, -1),
    (0, 1, 3, 2, 15, -1, 12, -1, 7, 14, 4, -1, -1, 9, -1, 8, 5, 10, -1, -1, 6, -1, 13, -1, -1, -1, 11, -1, -1, -1, -1, -1),
    (0, 3, 1, 2, -1, -1, 12, 6, 4, 9, 7, -1, -1, 14, 8, -1, -1, 15, 11, 13, 5, -1, 10, -1, -1, -1, -1, -1, -1, -1, -1, -1),
    (0, 5, 7, 2, 10, 13, -1, 6, 8, 1, 3, -1, -1, 14, 15, 11, -1, -1, -1, 12, 4, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1),
    (0, 2, 6, 3, 7, 10, -1, 1, 9, 4, 8, -1, -1, 15, -1, 12, 5, -1, -1, -1, 11, -1, 13, -1, -1, -1, 14, -1, -1, -1, -1, -1),
    (1, 3, 4, 0, 7, -1, 12, 2, 11, 8, 6, 13, -1, -1, -1, -1, -1, 5, -1, -1, 10, 15, 9, -1, -1, -1, 14, -1, -1, -1, -1, -1),
    (1, 3, 5, 2, 13, 0, 9, 4, 7, 6, 8, -1, -1, 15, -1, 11, -1, -1, 10, -1, 14, -1, 12, -1, -1, -1, -1, -1, -1, -1, -1, -1),
    (0, 2, 1, 3, -1, -1, -1, 6, -1, -1, 5, -1, -1, -1, -1, -1, -1, -1, -1, -1, 4, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1),
    (1, 11, 4, 0, 3, -1, 13, 12, 2, 7, -1, -1, 15, 10, 5, 8, 14, -1, -1, -1, -1, -1, 9, -1, -1, -1, 6, -1, -1, -1, -1, -1),
    (0, 9, 2, 14, 15, 4, 1, 13, 3, 5, -1, -1, 10, -1, -1, -1, -1, 6, 12, -1, 7, -1, 8, -1, -1, -1, 11, -1, -1, -1, -1, -1),
    (-1, 2, 14, -1, 1, 5, 8, 7, 4, 12, -1, 6, 9, 11, 13, 3, 10, 15, -1, -1, -1, -1, 0, -1, -1, -1, -1, -1, -1, -1, -1, -1),
    (0, 1, 3, 2, -1, -1, -1, -1, -1, -1, 4, -1, -1, -1, -1, -1, -1, -1, -1, -1, 6, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1),
    (4, 3, 1, 5, -1, -1, -1, 0, -1, -1, 6, -1, -1, -1, -1, -1, -1, -1, -1, -1, 2, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1),
    (2, 8, 4, 1, -1, 0, -1, 6, -1, -1, 5, -1, 7, -1, -1, -1, -1, -1, -1, -1, 10, -1, -1, 9, -1, -1, -1, -1, -1, -1, -1, -1),
    (12, 5, -1, -1, 1, -1, -1, 7, 0, 3, -1, 2, -1, 4, 6, -1, -1, -1, -1, 8, -1, -1, 15, -1, 13, 9, -1, -1, -1, -1, -1, 11),
    (1, 3, 2, 4, -1, -1, -1, 5, -1, 7, 0, -1, -1, -1, -1, -1, -1, -1, -1, -1, 6, -1, -1, -1, -1, -1, -1, -1, -1, 8, -1, -1),
    (5, 3, 4, 12, 1, 6, -1, -1, -1, -1, 8, 2, -1, -1, -1, -1, 0, 9, -1, -1, 11, -1, 10, -1, -1, -1, -1, -1, -1, -1, -1, -1),
    (-1, -1, -1, -1, 0, -1, 1, 12, 3, -1, -1, -1, -1, 5, -1, -1, -1, 2, -1, -1, -1, -1, -1, -1, -1, -1, 4, -1, -1, 6, -1, 10),
    (2, 3, 1, 4, -1, 0, -1, 5, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 7, -1, -1, -1, -1, -1, -1, -1, -1, 6, -1, -1),
    (5, 1, 3, 0, -1, -1, -1, -1, -1, -1, 4, -1, -1, -1, -1, -1, -1, -1, -1, -1, 2, -1, -1, -1, -1, -1, 9, -1, -1, 6, -1, 7),
)


@dataclass(frozen=True)
class Pack:
    word: int
    bytes_packed: int
    bytes_unpacked: int
    offsets: tuple[int, ...]
    masks: tuple[int, ...]


PACKS = (
    Pack(0x80000000, 1, 2, (26, 24), (15, 3)),
    Pack(0xC0000000, 2, 4, (25, 22, 19, 16), (15, 7, 7, 7)),
    Pack(0xE0000000, 4, 8, (23, 19, 15, 11, 8, 5, 2, 0), (31, 15, 15, 15, 7, 7, 7, 3)),
)


def _successor_bytes() -> tuple[tuple[int, ...], ...]:
    rows: list[tuple[int, ...]] = []
    for successors in SUCCESSOR_IDS:
        row = [0] * 16
        for chr_id, successor_id in enumerate(successors):
            if successor_id >= 0:
                row[successor_id] = CHRS_BY_CHR_ID[chr_id]
        rows.append(tuple(row))
    return tuple(rows)


SUCCESSOR_BYTES = _successor_bytes()


def _decode_header(value: int) -> int:
    index = -1
    while value & 0x80:
        value = (value << 1) & 0xFF
        index += 1
    return index


def _find_best_encoding(indices: list[int]) -> Pack | None:
    for pack in reversed(PACKS):
        if len(indices) >= pack.bytes_unpacked and all(
            index <= mask for index, mask in zip(indices[: pack.bytes_unpacked], pack.masks, strict=True)
        ):
            return pack
    return None


def compress(data: bytes) -> bytes:
    out = bytearray()
    position = 0
    data_len = len(data)

    while position < data_len:
        first_id = CHR_IDS_BY_BYTE.get(data[position], -1)
        if first_id < 0:
            _append_literal(out, data[position])
            position += 1
            continue

        indices = [first_id]
        last_id = first_id
        while len(indices) <= MAX_SUCCESSOR_N and position + len(indices) < data_len:
            current_id = CHR_IDS_BY_BYTE.get(data[position + len(indices)], -1)
            if current_id < 0:
                break
            successor_id = SUCCESSOR_IDS[last_id][current_id]
            if successor_id < 0:
                break
            indices.append(successor_id)
            last_id = current_id

        if len(indices) < 2:
            _append_literal(out, data[position])
            position += 1
            continue

        pack = _find_best_encoding(indices)
        if pack is None:
            _append_literal(out, data[position])
            position += 1
            continue

        code = pack.word
        for index, offset in zip(indices[: pack.bytes_unpacked], pack.offsets, strict=True):
            code |= index << offset
        out.extend(code.to_bytes(4, "big")[: pack.bytes_packed])
        position += pack.bytes_unpacked

    return bytes(out)


def _append_literal(out: bytearray, value: int) -> None:
    if value == 0 or value & 0x80:
        out.append(0)
    out.append(value)


def decompress(data: bytes) -> bytes:
    out = bytearray()
    position = 0
    data_len = len(data)

    while position < data_len:
        mark = _decode_header(data[position])
        if mark < 0:
            if data[position] == 0:
                position += 1
                if position >= data_len:
                    raise ValueError("truncated non-ascii sentinel")
            out.append(data[position])
            position += 1
            continue

        if mark >= len(PACKS):
            raise ValueError("invalid shoco header")
        pack = PACKS[mark]
        chunk = data[position : position + pack.bytes_packed]
        if len(chunk) != pack.bytes_packed:
            raise ValueError("truncated shoco pack")

        code = int.from_bytes(chunk.ljust(4, b"\x00"), "big")
        first_id = (code >> pack.offsets[0]) & pack.masks[0]
        if first_id >= len(CHRS_BY_CHR_ID):
            raise ValueError("invalid shoco leading character")
        last_byte = CHRS_BY_CHR_ID[first_id]
        out.append(last_byte)

        for offset, mask in zip(pack.offsets[1:], pack.masks[1:], strict=True):
            last_id = CHR_IDS_BY_BYTE[last_byte]
            successor_id = (code >> offset) & mask
            last_byte = SUCCESSOR_BYTES[last_id][successor_id]
            if last_byte == 0:
                raise ValueError("invalid shoco successor")
            out.append(last_byte)

        position += pack.bytes_packed

    return bytes(out)
