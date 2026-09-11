#!/usr/bin/env python3
"""Inject Django DATABASES TLS OPTIONS for CI MariaDB/PostgreSQL settings files."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


def _patch_mariadb(text: str, ca_runtime_path: str) -> str:
    ssl_snippet = f'"ssl": {{"ca": "{ca_runtime_path}"}}'
    if ssl_snippet in text:
        return text
    needle = '"use_unicode": True,'
    if needle not in text:
        raise SystemExit("MariaDB settings: expected OPTIONS use_unicode key")
    return text.replace(
        needle,
        needle + f"\n            {ssl_snippet},",
        1,
    )


def _patch_psql(text: str, ca_runtime_path: str) -> str:
    if '"sslmode"' in text and "sslrootcert" in text:
        return text
    options = (
        '        "OPTIONS": {\n'
        '            "sslmode": "verify-ca",\n'
        f'            "sslrootcert": "{ca_runtime_path}",\n'
        "        },\n"
    )
    needle = '"PORT": "",\n'
    if needle in text:
        return text.replace(needle, needle + options, 1)
    needle_alt = '"PORT": "",'
    if needle_alt in text:
        return text.replace(needle_alt, needle_alt + "\n" + options.rstrip("\n"), 1)
    raise SystemExit("PostgreSQL settings: expected PORT key to inject OPTIONS")


def patch_file(path: Path, django_db: str, ca_runtime_path: str) -> None:
    text = path.read_text(encoding="utf-8")
    if django_db == "mariadb":
        updated = _patch_mariadb(text, ca_runtime_path)
    elif django_db == "psql":
        updated = _patch_psql(text, ca_runtime_path)
    else:
        raise SystemExit(f"unsupported DJANGO_DB={django_db} (expected mariadb|psql)")
    if updated == text:
        print(f"already patched: {path}")
        return
    path.write_text(updated, encoding="utf-8")
    print(f"patched TLS OPTIONS: {path}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--django-db",
        required=True,
        choices=("mariadb", "psql"),
    )
    parser.add_argument(
        "--ca-runtime-path",
        required=True,
        help="Path Django opens at runtime (inside the a2c container/host)",
    )
    parser.add_argument(
        "settings_files",
        nargs="+",
        type=Path,
        help="settings.py file(s) to patch",
    )
    args = parser.parse_args()
    for settings in args.settings_files:
        if not settings.is_file():
            raise SystemExit(f"settings file not found: {settings}")
        patch_file(settings, args.django_db, args.ca_runtime_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
