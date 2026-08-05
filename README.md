# text-serdes

Tiny self-contained text transport for copy/paste sites, like PasteBin and Cl1p.net.

`text-serdes` takes bytes from a file or stdin, compresses them, but only if it helps, encrypts, encodes with Base91, and prints copyable wrapped text.

## Install

```bash
uv sync
```

Or install it as a `uv` tool from this checkout:

```bash
uv tool install .
```

## Use

Encode stdin:

```bash
printf 'TypeError: invalid literal for int()' | uv run text-serdes-enc
```

Decode stdin:

```bash
uv run text-serdes-enc message.txt | uv run text-serdes-dec
```

Encode a file:

```bash
uv run text-serdes-enc message.txt
```

Decode a file containing encoded text:

```bash
uv run text-serdes-dec encoded.txt
```

Both commands use one optional positional file. With no file, they read stdin until EOF. `text-serdes-enc` writes one logical encoded payload wrapped across short physical lines for terminal paste. `text-serdes-dec` ignores whitespace in encoded input and writes the original bytes to stdout.

When `text-serdes-enc` receives a filename, it embeds only that file's basename. When `text-serdes-dec` sees an embedded filename, it writes the decoded bytes back to that basename in the current directory, overwriting any existing file.

## Format

Current payloads use:

- a small marker for stdin/file and raw/zlib
- a random 12-byte value needed for encryption
- encrypted raw or zlib-compressed bytes
- optional basename metadata when encoding a file
- Base91 text output

![text-serdes encode and decode flow](docs/codec-flow.svg)

## Security Model

This is not secure storage, and it is not trying to be.

By default each encoded payload is self-contained: the key material needed to decode it is carried inside the payload itself, in an obfuscated form, combined with a fixed component baked into this tool. There is no date window — any copy of `text-serdes` can decode any payload it produced. (The optional passphrase below changes this.)

The only thing this buys you is that the output does not read as plaintext to casual eyes glancing at a terminal, a chat log, or a paste. Anyone willing to read this source, or to point a capable tool at the encoded line, can recover the contents. Use it for short-lived transport convenience, not for anything that needs real key management.

### Optional passphrase

Set the `TS_KEY` environment variable to fold a passphrase into the key. When set, it must match on both `text-serdes-enc` and `text-serdes-dec`:

```bash
TS_KEY=swordfish uv run text-serdes-enc message.txt | TS_KEY=swordfish uv run text-serdes-dec
```

This moves a secret out of the source entirely, so the encoded payload cannot be decoded without it. `TS_KEY` is optional: leave it unset and the tool behaves as above (self-contained, obfuscation only). Payloads encoded with a given `TS_KEY` only decode with that same value.

## Compression

The encoder tries `zlib.compress()`. If zlib makes the payload smaller, it stores compressed bytes. If zlib would make the payload longer, it encrypts the raw bytes instead.

## Develop

```bash
uv run pytest -q
```

Useful files:

- `src/text_serdes/cli.py`: CLI entry points.
- `src/text_serdes/codec.py`: encode/decode pipeline.
