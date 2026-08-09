#!/usr/bin/env python3
"""Minimal UDP syslog sink for CI smoke tests.

Listens for classic UDP syslog datagrams and appends each payload as a line
to an output file. Used by .github/workflows/deployment-wsgi.yml to verify
Helper.syslog_address remote forwarding.
"""

from __future__ import annotations

import argparse
import socket
import sys


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

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((args.bind, args.port))

    if args.ready:
        with open(args.ready, "w", encoding="utf-8"):
            pass

    print(
        f"udp syslog sink listening on {args.bind}:{args.port} -> {args.output}",
        flush=True,
    )

    with open(args.output, "ab") as out:
        while True:
            data, _addr = sock.recvfrom(65535)
            out.write(data + b"\n")
            out.flush()


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit(0)
