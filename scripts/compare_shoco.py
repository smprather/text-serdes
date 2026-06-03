from __future__ import annotations

import argparse
import gzip
import sys
import statistics
import zlib
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from text_serdes import shoco


@dataclass(frozen=True)
class Sample:
    group: str
    text: str


SAMPLES = [
    Sample("python-error", "TypeError: 'NoneType' object is not subscriptable"),
    Sample("python-error", "ModuleNotFoundError: No module named 'rich_click'"),
    Sample("python-error", "ValueError: invalid literal for int() with base 10: 'abc'"),
    Sample("python-error", "KeyError: 'DATABASE_URL'"),
    Sample("python-error", "FileNotFoundError: [Errno 2] No such file or directory: '/tmp/input.json'"),
    Sample("python-error", "UnicodeDecodeError: 'utf-8' codec can't decode byte 0xff in position 0"),
    Sample("traceback", '  File "/home/mylesp/text-serdes/src/text_serdes/codec.py", line 35, in decrypt_text'),
    Sample("traceback", '  File "/usr/lib/python3.12/subprocess.py", line 571, in run'),
    Sample("json", '{"event":"deploy","status":"failed","attempt":3,"service":"api","region":"us-east-1"}'),
    Sample("json", '{"path":"/var/log/app.log","offset":184467,"level":"ERROR","message":"connection refused"}'),
    Sample("yaml", "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: text-serdes\n"),
    Sample("toml", '[project]\nname = "text-serdes"\nrequires-python = ">=3.12"\n'),
    Sample("ini", "timeout=30\nretry_count=5\nlog_level=debug\n"),
    Sample("csv", "timestamp,level,service,message\n2026-06-03T03:21:11Z,error,worker,timeout\n"),
    Sample("path", "/home/mylesp/text-serdes/tests/test_text_serdes.py:34"),
    Sample("path", "s3://company-prod-artifacts/builds/2026/06/03/text-serdes.tar.gz"),
    Sample("url", "https://api.example.com/v1/users?limit=100&sort=created_at&direction=desc"),
    Sample("sql", "SELECT id, email FROM users WHERE deleted_at IS NULL ORDER BY created_at DESC LIMIT 50;"),
    Sample("shell", "UV_CACHE_DIR=/tmp/text-serdes-uv-cache uv run pytest -q"),
    Sample("shell", "git push -u origin codex/rename-dailycrypt-package"),
    Sample("log", "2026-06-03T03:24:01.883Z ERROR api request_id=ab12 status=500 latency_ms=238"),
    Sample("log", "level=warning msg=\"retrying request\" attempt=2 backoff_ms=400 host=db.internal"),
    Sample("http", "HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\nX-Request-ID: abc123\r\n"),
    Sample("uuid", "550e8400-e29b-41d4-a716-446655440000"),
    Sample("hash", "sha256:2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae"),
    Sample("english", "hello world"),
    Sample("english", "compress and encrypt with today's date key"),
    Sample("unicode", "error: café value contains smart quote “bad”"),
]


def _long_samples() -> list[Sample]:
    traceback_lines = [
        '  File "/home/mylesp/text-serdes/src/text_serdes/codec.py", line 35, in decrypt_text',
        '  File "/home/mylesp/text-serdes/src/text_serdes/cli.py", line 34, in dec_main',
        '  File "/usr/lib/python3.12/subprocess.py", line 571, in run',
        "ValueError: invalid literal for int() with base 10: 'abc'",
    ]
    log_lines = [
        "2026-06-03T03:24:01.883Z ERROR api request_id=ab12 status=500 latency_ms=238 path=/v1/users",
        "2026-06-03T03:24:02.117Z WARN worker job=sync-users attempt=2 backoff_ms=400 host=db.internal",
        "2026-06-03T03:24:02.803Z INFO cache op=set key=user:42 ttl=3600 size_bytes=184",
        "2026-06-03T03:24:03.042Z ERROR db message=\"connection refused\" retryable=true port=5432",
    ]
    json_lines = [
        '{"event":"deploy","status":"failed","attempt":3,"service":"api","region":"us-east-1"}',
        '{"path":"/var/log/app.log","offset":184467,"level":"ERROR","message":"connection refused"}',
        '{"query":"SELECT id, email FROM users WHERE deleted_at IS NULL","limit":50,"duration_ms":18}',
        '{"headers":{"content-type":"application/json","x-request-id":"abc123"},"status":502}',
    ]
    yaml_doc = """apiVersion: apps/v1
kind: Deployment
metadata:
  name: text-serdes
  namespace: tools
spec:
  replicas: 3
  selector:
    matchLabels:
      app: text-serdes
  template:
    metadata:
      labels:
        app: text-serdes
    spec:
      containers:
        - name: api
          image: ghcr.io/example/text-serdes:0.1.0
          env:
            - name: LOG_LEVEL
              value: debug
"""
    return [
        Sample("long-trace", "\n".join(traceback_lines * 4)),
        Sample("long-log", "\n".join(log_lines * 5)),
        Sample("long-json", "[" + ",".join(json_lines * 5) + "]"),
        Sample("long-yaml", yaml_doc * 4),
    ]


SAMPLES.extend(_long_samples())


def ratio(size: int, original: int) -> str:
    return f"{size / original:5.2f}x" if original else "  n/a"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.parse_args()
    rows: list[tuple[str, int, int, int, int, int]] = []

    print("group          raw  zlib gzip shoco best  zlib  gzip shoco  best  text")
    print("------------- ---- ----- ---- ----- ---- ------ ----- ------ -----  ------------------------------")
    for sample in SAMPLES:
        data = sample.text.encode("utf-8")
        zlib_data = zlib.compress(data)
        gzip_data = gzip.compress(data)
        shoco_data = shoco.compress(data)
        decoded = shoco.decompress(shoco_data)
        if decoded != data:
            raise RuntimeError(f"shoco round trip failed for {sample.text!r}: {decoded!r}")
        best_size = min(len(zlib_data), len(shoco_data))
        rows.append((sample.group, len(data), len(zlib_data), len(gzip_data), len(shoco_data), best_size))
        preview = sample.text.replace("\n", "\\n").replace("\r", "\\r")[:30]
        print(
            f"{sample.group:<13} {len(data):4d} {len(zlib_data):5d} {len(gzip_data):4d}"
            f" {len(shoco_data):5d} {best_size:4d} {ratio(len(zlib_data), len(data))}"
            f" {ratio(len(gzip_data), len(data))} {ratio(len(shoco_data), len(data))}"
            f" {ratio(best_size, len(data))}  {preview}"
        )

    raw_total = sum(row[1] for row in rows)
    zlib_total = sum(row[2] for row in rows)
    gzip_total = sum(row[3] for row in rows)
    shoco_total = sum(row[4] for row in rows)
    best_total = sum(row[5] for row in rows)
    shoco_wins = sum(row[4] < row[2] for row in rows)
    zlib_wins = sum(row[2] < row[4] for row in rows)
    ties = len(rows) - shoco_wins - zlib_wins
    med_zlib = statistics.median(row[2] / row[1] for row in rows)
    med_shoco = statistics.median(row[4] / row[1] for row in rows)
    med_best = statistics.median(row[5] / row[1] for row in rows)

    print()
    print(f"samples: {len(rows)}")
    print(f"totals: raw={raw_total} zlib={zlib_total} gzip={gzip_total} shoco={shoco_total} best={best_total}")
    print(
        f"total ratios: zlib={zlib_total / raw_total:.2f}x gzip={gzip_total / raw_total:.2f}x"
        f" shoco={shoco_total / raw_total:.2f}x best={best_total / raw_total:.2f}x"
    )
    print(f"median ratios: zlib={med_zlib:.2f}x shoco={med_shoco:.2f}x best={med_best:.2f}x")
    print(f"wins vs current zlib: shoco={shoco_wins} zlib={zlib_wins} ties={ties}")


if __name__ == "__main__":
    main()
