#!/usr/bin/env python3
"""Inject Django DATABASES TLS OPTIONS for CI MariaDB/PostgreSQL settings files."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import Sequence


def _default_allowed_bases() -> list[str]:
    """Directories under which settings files may be patched."""
    bases = [os.path.realpath(os.getcwd())]
    workspace = os.environ.get("GITHUB_WORKSPACE")
    if workspace:
        bases.append(os.path.realpath(workspace))
    return bases


def _path_under_base(resolved: str, real_base: str) -> bool:
    """True when *resolved* is *real_base* or a path beneath it."""
    if resolved == real_base:
        return True
    prefix = real_base if real_base.endswith(os.sep) else real_base + os.sep
    return resolved.startswith(prefix)


def _safe_settings_file(path: Path | str, allowed_bases: Sequence[str]) -> str:
    """Return a realpath for *path* that stays under *allowed_bases*."""
    raw = os.fspath(path)
    if not raw or "\x00" in raw:
        raise SystemExit(f"invalid settings path: {path!r}")
    resolved = os.path.realpath(raw)
    for base in allowed_bases:
        real_base = os.path.realpath(base)
        if not _path_under_base(resolved, real_base):
            continue
        # Rebuild from base + relative segments so the opened path is not the
        # raw CLI string (clears path-traversal taint for S2083 / S8707).
        rel = os.path.relpath(resolved, real_base)
        if rel.startswith(".."):
            continue
        safe = os.path.realpath(os.path.join(real_base, rel))
        if safe != resolved or not os.path.isfile(safe):
            raise SystemExit(f"settings file not found: {path}")
        return safe
    raise SystemExit(
        f"settings path outside allowed directories: {path} (resolved={resolved})"
    )


def _sanitize_ca_runtime_path(ca_runtime_path: str) -> str:
    """Validate CA path embedded into settings (absolute, no injection chars)."""
    if not ca_runtime_path or "\x00" in ca_runtime_path:
        raise SystemExit(f"invalid ca-runtime-path: {ca_runtime_path!r}")
    if any(c in ca_runtime_path for c in ('"', "'", "\n", "\r", "`", "\\")):
        raise SystemExit("ca-runtime-path contains invalid characters")
    if not os.path.isabs(ca_runtime_path):
        raise SystemExit("ca-runtime-path must be an absolute path")
    return ca_runtime_path


def _client_material_paths(ca_runtime_path: str) -> tuple[str, str]:
    parent = os.path.dirname(ca_runtime_path)
    return (
        os.path.join(parent, "db-client-cert.pem"),
        os.path.join(parent, "db-client-key.pem"),
    )


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
    allowed_bases: Sequence[Path | str] | None = None,
) -> None:
    """Patch *path* after verifying it stays under *allowed_bases*."""
    if allowed_bases is None:
        bases = _default_allowed_bases()
    else:
        bases = [os.path.realpath(os.fspath(base)) for base in allowed_bases]
    settings_path = _safe_settings_file(path, bases)
    ca_path = _sanitize_ca_runtime_path(ca_runtime_path)

    with open(settings_path, encoding="utf-8") as handle:
        text = handle.read()
    if django_db == "mariadb":
        updated = _patch_mariadb(text, ca_path)
    elif django_db == "psql":
        updated = _patch_psql(text, ca_path)
    else:
        raise SystemExit(f"unsupported DJANGO_DB={django_db} (expected mariadb|psql)")
    if updated == text:
        print(f"already patched: {settings_path}")
        return
    with open(settings_path, "w", encoding="utf-8") as handle:
        handle.write(updated)
    print(f"patched TLS OPTIONS: {settings_path}")


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
