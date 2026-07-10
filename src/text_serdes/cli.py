from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path

import rich_click as click

from .codec import CodecError, decrypt_payload, encrypt_bytes

OUTPUT_WRAP_COLUMNS = 100


def read_input(path: str | None) -> bytes:
    stdin = click.get_binary_stream("stdin")
    if path is None:
        return stdin.read()

    with open(path, "rb") as handle:
        return handle.read()


def write_output(payload: bytes, output_file: Path | None) -> None:
    if output_file is None:
        stdout = click.get_binary_stream("stdout")
        stdout.write(payload)
        return

    with open(output_file, "wb") as handle:
        handle.write(payload)


def _dev_log_path(command: str) -> Path:
    return Path(os.getenv("TEXT_SERDES_DEV_DIR", "/tmp/text-serdes-dev")) / f"{command}-latest.json"


def _write_dev_log(command: str, log: dict[str, object]) -> None:
    path = _dev_log_path(command)
    path.parent.mkdir(parents=True, exist_ok=True)
    log["log_path"] = str(path)
    path.write_text(json.dumps(log, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _base_dev_log(command: str) -> dict[str, object]:
    return {
        "command": command,
        "cwd": str(Path.cwd()),
        "pid": os.getpid(),
        "argv": sys.argv,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "streams": {
            "stdin_isatty": sys.stdin.isatty(),
            "stdout_isatty": sys.stdout.isatty(),
            "stderr_isatty": sys.stderr.isatty(),
        },
        "environment": {
            "ts_key_set": os.getenv("TS_KEY") is not None,
        },
    }


def _bytes_summary(data: bytes) -> dict[str, object]:
    return {
        "bytes": len(data),
        "sha256": sha256(data).hexdigest(),
        "prefix_hex": data[:40].hex(),
        "suffix_hex": data[-40:].hex(),
    }


def _text_summary(text: str) -> dict[str, object]:
    encoded = text.encode("ascii")
    return {
        "chars": len(text),
        "sha256": sha256(encoded).hexdigest(),
        "prefix": text[:80],
        "suffix": text[-80:],
        "contains_newline": "\n" in text,
        "contains_carriage_return": "\r" in text,
    }


def _wrap_encoded_output(text: str) -> str:
    return "\n".join(text[i : i + OUTPUT_WRAP_COLUMNS] for i in range(0, len(text), OUTPUT_WRAP_COLUMNS))


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.argument("input_file", required=False, type=click.Path(dir_okay=False))
@click.option("--dev", is_flag=True, help="Write detailed debug info to /tmp/text-serdes-dev/enc-latest.json.")
def enc_main(input_file: str | None = None, dev: bool = False) -> None:
    """Compress, encrypt, and encode INPUT_FILE or stdin when omitted."""
    log = _base_dev_log("enc") if dev else {}
    try:
        data = read_input(input_file)
        filename = Path(input_file).name if input_file is not None else None
        output = encrypt_bytes(data, filename=filename)
        wrapped_output = _wrap_encoded_output(output)
        if dev:
            wrapped_lines = wrapped_output.splitlines()
            log["input"] = {
                "source": input_file if input_file is not None else "stdin",
                "filename_embedded": filename,
                **_bytes_summary(data),
            }
            log["output"] = {
                **_text_summary(output),
                "wrap_columns": OUTPUT_WRAP_COLUMNS,
                "wrapped_line_count": len(wrapped_lines),
                "wrapped_max_line_chars": max((len(line) for line in wrapped_lines), default=0),
                "stdout_bytes_with_trailing_newline": len(wrapped_output.encode("ascii")) + 1,
            }
            log["result"] = {"ok": True}
    except (OSError, CodecError) as exc:
        if dev:
            log["result"] = {"ok": False, "error_type": type(exc).__name__, "error": str(exc)}
        raise click.ClickException(str(exc)) from exc
    finally:
        if dev:
            _write_dev_log("enc", log)

    click.echo(wrapped_output)


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.argument("input_file", required=False, type=click.Path(dir_okay=False))
@click.option("--dev", is_flag=True, help="Write detailed debug info to /tmp/text-serdes-dev/dec-latest.json.")
@click.option(
    "--output",
    type=click.Path(path_type=Path, dir_okay=True, file_okay=True, writable=True),
)
def dec_main(input_file: str | None = None, dev: bool = False, output: Path | None = None) -> None:
    """Decode, decrypt, and decompress INPUT_FILE or stdin when omitted."""
    log = _base_dev_log("dec") if dev else {}
    try:
        raw_input = read_input(input_file)
        if dev:
            log["input"] = {
                "source": input_file if input_file is not None else "stdin",
                **_bytes_summary(raw_input),
            }
        encoded = raw_input.decode("ascii")
        decode_debug: dict[str, object] = {}
        if dev:
            normalized = "".join(encoded.split())
            log["encoded_text"] = {
                **_text_summary(encoded),
                "non_whitespace_chars": len(normalized),
                "non_whitespace_sha256": sha256(normalized.encode("ascii")).hexdigest(),
            }
            log["decode"] = decode_debug
        payload = decrypt_payload(encoded, debug=decode_debug if dev else None)
    except (OSError, UnicodeDecodeError, CodecError) as exc:
        if dev:
            log["result"] = {"ok": False, "error_type": type(exc).__name__, "error": str(exc)}
            _write_dev_log("dec", log)
        raise click.ClickException(str(exc)) from exc

    if output is not None:
        if output.exists() and output.is_dir():
            if payload.filename is None:
                exc = CodecError("--output is a directory, but the encoded input has no embedded filename")
                if dev:
                    log["result"] = {"ok": False, "error_type": type(exc).__name__, "error": str(exc)}
                    _write_dev_log("dec", log)
                raise click.ClickException(str(exc)) from exc
            output_path = output / Path(payload.filename).name
        else:
            output_path = output

        try:
            write_output(payload.data, output_path)
        except OSError as exc:
            if dev:
                log["result"] = {"ok": False, "error_type": type(exc).__name__, "error": str(exc)}
                _write_dev_log("dec", log)
            raise click.ClickException(str(exc)) from exc
        if dev:
            log["output"] = {
                "target": str(output_path),
                "embedded_filename": payload.filename,
                "payload_bytes": len(payload.data),
            }
            log["result"] = {"ok": True}
            _write_dev_log("dec", log)
        return

    if payload.filename is not None:
        try:
            write_output(payload.data, Path(payload.filename).name)
        except OSError as exc:
            if dev:
                log["result"] = {"ok": False, "error_type": type(exc).__name__, "error": str(exc)}
                _write_dev_log("dec", log)
            raise click.ClickException(str(exc)) from exc
        if dev:
            log["output"] = {
                "target": Path(payload.filename).name,
                "embedded_filename": payload.filename,
                "payload_bytes": len(payload.data),
            }
            log["result"] = {"ok": True}
            _write_dev_log("dec", log)
        return

    write_output(payload.data, None)
    if dev:
        log["output"] = {
            "target": "stdout",
            "embedded_filename": payload.filename,
            "payload_bytes": len(payload.data),
        }
        log["result"] = {"ok": True}
        _write_dev_log("dec", log)


if __name__ == "__main__":
    enc_main()
