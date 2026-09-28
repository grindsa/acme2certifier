#!/usr/bin/env python3
"""Inject Django DATABASES TLS OPTIONS for CI MariaDB/PostgreSQL settings files."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import Sequence


def _default_allowed_bases() -> list[Path]:
    """Directories under which settings files may be patched."""
    bases = [Path.cwd()]
    workspace = os.environ.get("GITHUB_WORKSPACE")
    if workspace:
        bases.append(Path(workspace))
    return bases


def _safe_settings_path(path: Path, allowed_bases: Sequence[Path]) -> Path:
    """Resolve *path* and require it to remain under one of *allowed_bases*.

    Blocks path-traversal via ``..`` / symlink escapes from CLI arguments
    (Sonar pythonsecurity:S2083 / S8707).
    """
    raw = os.fspath(path)
    if not raw or "\x00" in raw:
        raise SystemExit(f"invalid settings path: {path!r}")

    resolved = os.path.realpath(raw)
    for base in allowed_bases:
        real_base = os.path.realpath(os.fspath(base))
        try:
            if os.path.commonpath([resolved, real_base]) != real_base:
                continue
        except ValueError:
            continue
        target = Path(resolved)
        if not target.is_file():
            raise SystemExit(f"settings file not found: {path}")
        return target
    raise SystemExit(
        f"settings path outside allowed directories: {path} (resolved={resolved})"
    )


def _client_material_paths(ca_runtime_path: str) -> tuple[str, str]:
    parent = Path(ca_runtime_path).parent
    return str(parent / "db-client-cert.pem"), str(parent / "db-client-key.pem")


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
    sslcert, sslkey = _client_material_paths(ca_runtime_path)
    options = (
        '        "OPTIONS": {\n'
        '            "sslmode": "verify-ca",\n'
        f'            "sslrootcert": "{ca_runtime_path}",\n'
        f'            "sslcert": "{sslcert}",\n'
        f'            "sslkey": "{sslkey}",\n'
        "        },\n"
    )
    needle = '"PORT": "",\n'
    if needle in text:
        return text.replace(needle, needle + options, 1)
    if '"PORT": "",' in text:
        return text.replace('"PORT": "",', '"PORT": "",\n' + options.rstrip("\n"), 1)
    raise SystemExit("PostgreSQL settings: expected PORT key to inject OPTIONS")


def patch_file(
    path: Path,
    django_db: str,
    ca_runtime_path: str,
    *,
    allowed_bases: Sequence[Path] | None = None,
) -> None:
    """Patch *path* after verifying it stays under *allowed_bases*."""
    bases = list(allowed_bases) if allowed_bases is not None else _default_allowed_bases()
    target = _safe_settings_path(path, bases)
    text = target.read_text(encoding="utf-8")
    if django_db == "mariadb":
        updated = _patch_mariadb(text, ca_runtime_path)
    elif django_db == "psql":
        updated = _patch_psql(text, ca_runtime_path)
    else:
        raise SystemExit(f"unsupported DJANGO_DB={django_db} (expected mariadb|psql)")
    if updated == text:
        print(f"already patched: {target}")
        return
    target.write_text(updated, encoding="utf-8")
    print(f"patched TLS OPTIONS: {target}")


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
    bases = _default_allowed_bases()
    for settings in args.settings_files:
        patch_file(settings, args.django_db, args.ca_runtime_path, allowed_bases=bases)
    return 0


if __name__ == "__main__":
    sys.exit(main())
