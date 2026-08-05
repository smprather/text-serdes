# Repository Guidelines

## Project Structure & Module Organization

This is a small Python CLI project. Runtime code lives in `src/text_serdes/`, with command entry points in `src/text_serdes/cli.py` and encode/decode logic in `src/text_serdes/codec.py`. Tests live in `tests/`. Package metadata, dependencies, console scripts, and pytest discovery settings are in `pyproject.toml`.

## Build, Test, and Development Commands

- `uv sync`: create or update the local virtual environment.
- `uv run text-serdes-enc [input_file]`: compress, encrypt with today's date key, Base91 encode, and print to stdout.
- `uv run text-serdes-dec [input_file]`: Base91 decode, decrypt with today's date key, decompress, and print plaintext.
- `uv run pytest -q`: run the root test suite.

Commands should be run from the repository root, `/home/mylesp/text-serdes`.

## Coding Style & Naming Conventions

Target Python >=3.12. Use 4-space indentation, type hints for public functions, and `snake_case` for modules, functions, and variables. Keep CLI behavior small and predictable: one optional positional input file, otherwise read stdin until EOF. Keep generated files such as `__pycache__/`, build artifacts, and virtual environments out of git.

## Testing Guidelines

Use `pytest`. Test files should be named `test_*.py`, and tests should cover both library functions and CLI behavior. For codec changes, include round-trip tests, malformed input tests, and date-key failure tests. For CLI changes, verify file input, stdin input, stdout formatting, stderr errors, and exit codes.

## Commit & Pull Request Guidelines

Use short imperative commit subjects such as `Add daily codec CLI` or `Handle malformed Base91 input`. Keep commits focused. Pull requests should describe behavior changes, list verification commands, link related issues when relevant, and call out any CLI compatibility changes.

## Security & Configuration Tips

The key is derived only from the local date (`YYYY-MM-DD`), so this tool is for simple short-lived transport, not high-security storage. Encoded output is only decryptable on the same local date unless the implementation later adds an explicit date option.
