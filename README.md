# text-serdes

Tiny daily-key text transport for copy/paste workflows.

`text-serdes` takes bytes from a file or stdin, compresses them with a pure-Python shoco port, encrypts them with an AES-GCM key derived from today's local date, Base91-encodes the result, and prints one copyable line.

It is built for short-lived engineering text: Python error messages, logs, paths, JSON/YAML/TOML fragments, shell commands, tracebacks, and other structured text that does not behave like long prose.

## Install

```bash
uv sync
```

## Use

Encode stdin:

```bash
printf 'TypeError: invalid literal for int()' | uv run enc
```

Decode stdin:

```bash
uv run enc message.txt | uv run dec
```

Encode a file:

```bash
uv run enc message.txt
```

Decode a file containing encoded text:

```bash
uv run dec encoded.txt
```

Both commands use one optional positional file. With no file, they read stdin until EOF. `enc` writes a newline-terminated encoded string. `dec` writes the original bytes to stdout.

## Format

Current payloads use:

- `DC2` magic
- random 12-byte AES-GCM nonce
- shoco-compressed plaintext
- AES-GCM authentication tag
- Base91 outer encoding

Older `DC1` zlib payloads still decode, so same-day strings produced before the shoco switch are not stranded.

## Security Model

This is not long-term secure storage.

The encryption key is:

```text
sha256(local-date-as-YYYY-MM-DD)
```

That means encoded output is intended to be decoded on the same local date. Anyone who knows the date can derive the key. Use this for short-lived transport convenience, not secrets that need real key management.

## Compression

The compressor is a pure-Python port of shoco, a small-string compressor originally written in C. In the local benchmark corpus, shoco beat zlib on 27 of 28 engineering-style samples:

```text
totals: raw=1696 zlib=1818 gzip=2154 shoco=1379
total ratios: zlib=1.07x gzip=1.27x shoco=0.81x
median ratios: zlib=1.10x shoco=0.80x
wins vs current zlib: shoco=27 zlib=1 ties=0
```

Representative rows:

| sample kind | raw | zlib | gzip | shoco |
| --- | ---: | ---: | ---: | ---: |
| `TypeError: 'NoneType' object...` | 49 | 55 | 67 | 44 |
| `ModuleNotFoundError: No module...` | 49 | 54 | 66 | 36 |
| `ValueError: invalid literal...` | 57 | 64 | 76 | 44 |
| traceback path | 80 | 76 | 88 | 59 |
| JSON event | 85 | 81 | 93 | 69 |
| YAML deployment fragment | 67 | 73 | 85 | 51 |
| INI settings | 41 | 49 | 61 | 31 |
| source path | 53 | 49 | 61 | 36 |
| URL with query string | 73 | 76 | 88 | 55 |
| shell command | 55 | 63 | 75 | 46 |
| structured log line | 78 | 81 | 93 | 61 |
| UUID | 36 | 43 | 55 | 36 |
| SHA-256 digest | 71 | 65 | 77 | 70 |

Run the comparison:

```bash
python scripts/compare_shoco.py
```

## Develop

```bash
uv run pytest -q
```

Useful files:

- `text_serdes/cli.py`: CLI entry points.
- `text_serdes/codec.py`: encode/decode pipeline.
- `text_serdes/shoco.py`: pure-Python shoco implementation.
- `scripts/compare_shoco.py`: compression comparison corpus.
- `docs/pure-python-shoco-notes.md`: notes for publishing the shoco port as a standalone PyPI package.
