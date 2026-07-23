#!/usr/bin/env python3
"""Strip pip venv python-home from Apache vhosts for Debian packages."""

import re
import sys
from pathlib import Path


def patch_file(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    # Multi-line WSGIDaemonProcess with python-home + python-path
    text = re.sub(
        r"WSGIDaemonProcess\s+(\S+)\s*\\\s*\n\s*"
        r"python-home=/var/www/acme2certifier/venv\s*\\\s*\n\s*"
        r"python-path=",
        r"WSGIDaemonProcess \1 python-path=",
        text,
    )
    # Single-line python-home=.../venv
    text = text.replace(" python-home=/var/www/acme2certifier/venv", "")
    path.write_text(text, encoding="utf-8")


def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} <apache2-share-dir>", file=sys.stderr)
        return 2
    apache_dir = Path(sys.argv[1])
    if not apache_dir.is_dir():
        print(f"missing directory: {apache_dir}", file=sys.stderr)
        return 1
    for conf in sorted(apache_dir.glob("apache_*.conf")):
        patch_file(conf)
        if "python-home=/var/www/acme2certifier/venv" in conf.read_text(
            encoding="utf-8"
        ):
            print(f"ERROR: python-home still present in {conf}", file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
