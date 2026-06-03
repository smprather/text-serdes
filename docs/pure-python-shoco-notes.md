# Pure Python Shoco Notes

Goal: publish a pure-Python shoco implementation on PyPI as the next project.

## What shoco is

Shoco is a small-string compressor originally written in C:

- Upstream docs: https://ed-von-schleck.github.io/shoco/
- Upstream repo: https://github.com/Ed-von-Schleck/shoco
- Upstream license: MIT, copyright Christian Schramm, 2014.
- Existing PyPI wrapper: `pyshoco`, last seen as an old C wrapper, not a pure-Python package.

Shoco is optimized for short strings. Its default model is English-like, but it also works well on many "engineering stuff" strings because those strings still contain many common letter pairs and repeated fragments:

- Python exceptions
- Tracebacks
- JSON, YAML, TOML, INI, CSV
- Paths, URLs, shell commands
- Logs, HTTP headers, SQL

It is not a general-purpose replacement for zlib on large or binary-heavy data. It is a small-string compressor with tiny overhead.

## Measured result in this repo

Script: `scripts/compare_shoco.py`

Corpus size: 28 hand-picked engineering-ish samples.

Result:

```text
totals: raw=1696 zlib=1818 gzip=2154 shoco=1379
total ratios: zlib=1.07x gzip=1.27x shoco=0.81x
median ratios: zlib=1.10x shoco=0.80x
wins vs current zlib: shoco=27 zlib=1 ties=0
```

Meaning:

- Current `zlib.compress()` often expands short strings because it has format overhead.
- `gzip.compress()` expands even more because gzip has larger headers/trailers.
- Shoco usually shrinks these short strings.
- The one zlib win was a hash-like string where repeated hex helped zlib more than shoco's language model.

## Current pure-Python port

File in this repo: `text_serdes/shoco.py`

Public API:

```python
from text_serdes import shoco

compressed = shoco.compress(data)
plain = shoco.decompress(compressed)
```

Current type contract:

- Input: `bytes`
- Output: `bytes`
- No dependencies
- No C extension
- Round-trips arbitrary bytes, including `0x00` and high-bit bytes.

This differs usefully from upstream C shoco. Upstream compression stops at a C string terminator in practice, so embedded `NUL` is not handled as ordinary data. The Python port escapes `0x00`, so it can be a real bytes codec.

## Algorithm notes

The default model has:

- A 32-byte primary alphabet: `eaiothnrslucwmdbpfgvyk-HMT'BxIWL`
- A 32x32 successor-id table.
- Three pack formats:
  - 1 packed byte -> 2 unpacked bytes
  - 2 packed bytes -> 4 unpacked bytes
  - 4 packed bytes -> 8 unpacked bytes

Compression loop:

1. Look up the current byte in the 32-byte model alphabet.
2. If unknown, write a literal byte.
3. If high-bit or `NUL`, write sentinel `0x00` then the literal byte.
4. Walk known successor pairs until the chain ends or reaches 8 bytes.
5. Choose the largest pack whose masks fit the collected indices.
6. Build the packed integer using the pack header, offsets, and masks.
7. Write the high-order packed bytes.

Decompression loop:

1. Inspect high bits of current byte to identify pack marker.
2. If no marker, read literal.
3. If literal is `0x00`, consume next byte as escaped `NUL` or high-bit literal.
4. For packed data, unpack leading model character.
5. Reconstruct successor bytes by indexing the successor table.
6. Reject truncated packs, invalid headers, and impossible successor ids.

## Codec integration in this repo

`text_serdes.codec` now writes:

- `DC2`: shoco-compressed payload, then AES-GCM, then Base91.

It still reads:

- `DC2`: shoco path.
- `DC1`: legacy zlib path.

Backward read support matters because existing same-day encoded strings would otherwise become undecodable after swapping compressors.

## Tests already added

Current repo tests cover:

- Fixed-date round trip.
- Binary bytes with `NUL` and `0xff`.
- Shoco direct round trip.
- New payload magic starts with `DC2`.
- Old `DC1` zlib payload still decodes.
- Wrong-date failure.
- Malformed input failure.
- CLI stdin and file input.

Additional tests recommended for standalone package:

- Empty bytes.
- Single byte literals.
- Every byte value `0..255`.
- Random bytes, many seeds.
- Known upstream vectors from C shoco.
- Cross-check pure Python compressed output against C output for inputs without `NUL`.
- Corrupt compressed data should raise `ValueError`.
- Truncated sentinel should raise `ValueError`.
- Truncated pack should raise `ValueError`.
- Large-ish input smoke test, even though this is not the target workload.
- Hypothesis property test if we allow a test dependency.

## Packaging plan for PyPI

Recommended package shape:

```text
pure-python-shoco/
  pyproject.toml
  README.md
  LICENSE
  src/
    shoco/
      __init__.py
      _model.py
      _codec.py
      py.typed
  tests/
    test_codec.py
    test_vectors.py
```

Possible package names:

- Distribution name: `pure-python-shoco` or `shoco-py`
- Import name: `shoco`

Need verify final PyPI name before publishing. I saw an old `pyshoco` package, so avoid that name.

Suggested public API:

```python
def compress(data: bytes | str, /, *, encoding: str = "utf-8") -> bytes: ...
def decompress(data: bytes, /) -> bytes: ...
def compress_text(text: str, /, *, encoding: str = "utf-8") -> bytes: ...
def decompress_text(data: bytes, /, *, encoding: str = "utf-8", errors: str = "strict") -> str: ...
```

Keep the core bytes API simple. Text helpers can exist, but bytes should be first-class because the implementation can round-trip arbitrary bytes.

Suggested metadata:

- `requires-python = ">=3.9"` or `>=3.10`.
- No runtime dependencies.
- License: MIT.
- Include upstream MIT license notice and attribution.
- Classifiers:
  - `Development Status :: 3 - Alpha` for first release.
  - `License :: OSI Approved :: MIT License`
  - `Programming Language :: Python :: 3`
  - `Programming Language :: Python :: 3 :: Only`
  - `Programming Language :: Python :: Implementation :: CPython`
  - `Programming Language :: Python :: Implementation :: PyPy`
  - `Topic :: System :: Archiving :: Compression`

Build backend:

- `hatchling` is fine.
- Use `src/` layout to avoid accidental local import success.
- Build both wheel and sdist.

Current PyPA packaging docs recommend modern `pyproject.toml` packaging, building distributions, testing on TestPyPI if desired, and publishing with Twine or Trusted Publishing:

- Packaging guide: https://packaging.python.org/en/latest/guides/section-build-and-publish/
- Tutorial: https://packaging.python.org/tutorials/packaging-projects/
- PyPI Trusted Publishing: https://docs.pypi.org/trusted-publishers/

For a new project, GitHub Actions plus Trusted Publishing is the cleaner long-term release path because it avoids long-lived PyPI API tokens.

## Release checklist

1. Create separate repo.
2. Move pure Python implementation out of `text_serdes`.
3. Split large model tables into `_model.py`.
4. Keep codec logic in `_codec.py`.
5. Add `README.md` with examples and limitations.
6. Add upstream attribution in `LICENSE` or `NOTICE`.
7. Add tests and C cross-check script.
8. Add benchmark script with engineering-string corpus.
9. Add GitHub Actions:
   - pytest on CPython and PyPy.
   - build wheel/sdist.
   - optional publish-on-tag workflow using PyPI Trusted Publishing.
10. Build locally:
   - `python -m build`
   - `python -m twine check dist/*`
11. Upload to TestPyPI only if desired.
12. Publish real release to PyPI.
13. Replace vendored `text_serdes.shoco` with dependency after package exists.

## Open risks

- Performance: pure Python will be slower than C. Need benchmark throughput, not only size.
- Model ownership: we copied/generated tables from upstream. MIT allows this, but attribution must be preserved.
- API naming: `shoco` import name may conflict with existing packages or expectations. Verify.
- Compatibility: If users expect exact C behavior around `NUL`, our bytes-safe behavior differs. Document this clearly.
- Malformed data: standalone package should define exact exception behavior.
- Compression ratio: default model is not perfect for all engineering strings. Custom model generation could become a later feature, but first release should stay narrow.

## Good first release scope

Ship:

- Pure Python default-model shoco.
- Bytes API.
- Text helper API.
- Tests.
- Benchmark.
- MIT license and attribution.
- Python 3.9+ or 3.10+.

Do not ship yet:

- Custom model generator.
- Streaming API.
- C extension.
- Format versioning.
- CLI, unless very small and useful.

Keep first package small and boring. Main value: installable, no compiler, no dependencies, good enough short-string compression.
