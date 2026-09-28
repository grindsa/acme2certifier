#!/usr/bin/env python3
"""Minimal UDP syslog sink for CI smoke tests.

Listens for classic UDP syslog datagrams and appends each payload as a line
to an output file. Used by .github/workflows/feature-prefix.yml to verify
Helper.syslog_address remote forwarding.
"""

from __future__ import annotations

import argparse
import os
import socket
import sys


def _allowed_bases() -> list[str]:
    bases = [os.path.realpath(os.getcwd()), os.path.realpath("/tmp"), os.path.realpath("/out")]
    workspace = os.environ.get("GITHUB_WORKSPACE")
    if workspace:
        bases.append(os.path.realpath(workspace))
    return bases


def _safe_path(path: str, *, must_exist: bool = False) -> str:
    """Resolve *path* and require it under an allowlisted base directory."""
    if not path or "\x00" in path:
        raise SystemExit(f"invalid path: {path!r}")
    resolved = os.path.realpath(path)
    if not any(
        resolved == base or resolved.startswith(base + os.sep) for base in _allowed_bases()
    ):
        raise SystemExit(f"path outside allowed directories: {path}")
    if must_exist and not os.path.isfile(resolved):
        raise SystemExit(f"file not found: {path}")
    parent = os.path.dirname(resolved)
    if not os.path.isdir(parent):
        raise SystemExit(f"parent directory missing: {path}")
    return resolved


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bind", default="0.0.0.0", help="Bind address")
    parser.add_argument("--port", type=int, default=5514, help="UDP port")
    parser.add_argument(
        "--output", required=True, help="Append received datagrams here"
    )
    parser.add_argument(
        "--ready",
        default=None,
        help="Create this empty file once the socket is listening",
    )
    args = parser.parse_args()

    output_path = _safe_path(args.output)
    ready_path = _safe_path(args.ready) if args.ready else None

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((args.bind, args.port))

    if ready_path:
        # Empty sentinel so CI can wait until the socket is bound.
        with open(ready_path, "w", encoding="utf-8") as ready_file:
            ready_file.write("")

    print(
        f"udp syslog sink listening on {args.bind}:{args.port} -> {output_path}",
        flush=True,
    )

    with open(output_path, "ab") as out:
        while True:
            data, _addr = sock.recvfrom(65535)
            out.write(data + b"\n")
            out.flush()


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit(0)
