from __future__ import annotations

import rich_click as click

from .codec import CodecError, decrypt_text, encrypt_bytes


def read_input(path: str | None) -> bytes:
    stdin = click.get_binary_stream("stdin")
    if path is None:
        return stdin.read()

    with open(path, "rb") as handle:
        return handle.read()


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.argument("input_file", required=False, type=click.Path(dir_okay=False))
def enc_main(input_file: str | None = None) -> None:
    """Compress, encrypt, and encode INPUT_FILE or stdin when omitted."""
    try:
        output = encrypt_bytes(read_input(input_file))
    except OSError as exc:
        raise click.ClickException(str(exc)) from exc

    click.echo(output)


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.argument("input_file", required=False, type=click.Path(dir_okay=False))
def dec_main(input_file: str | None = None) -> None:
    """Decode, decrypt, and decompress INPUT_FILE or stdin when omitted."""
    try:
        encoded = read_input(input_file).decode("ascii")
        output = decrypt_text(encoded)
    except (OSError, UnicodeDecodeError, CodecError) as exc:
        raise click.ClickException(str(exc)) from exc

    stdout = click.get_binary_stream("stdout")
    stdout.write(output)


if __name__ == "__main__":
    enc_main()
