#!/usr/bin/env python3
"""Append Django DB TLS query params to ACME2CERTIFIER_DATABASE_URL in a CI env file."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import Dict, List, Sequence
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse


def _default_allowed_bases() -> list[str]:
    bases = [os.path.realpath(os.getcwd())]
    workspace = os.environ.get("GITHUB_WORKSPACE")
    if workspace:
        bases.append(os.path.realpath(workspace))
    return bases


def _path_under_base(resolved: str, real_base: str) -> bool:
    if resolved == real_base:
        return True
    prefix = real_base if real_base.endswith(os.sep) else real_base + os.sep
    return resolved.startswith(prefix)


def _safe_env_file(path: Path | str, allowed_bases: Sequence[str]) -> str:
    raw = os.fspath(path)
    if not raw or "\x00" in raw:
        raise SystemExit(f"invalid env file path: {path!r}")
    resolved = os.path.realpath(raw)
    for base in allowed_bases:
        real_base = os.path.realpath(base)
        if not _path_under_base(resolved, real_base):
            continue
        rel = os.path.relpath(resolved, real_base)
        if rel.startswith(".."):
            continue
        safe = os.path.realpath(os.path.join(real_base, rel))
        if safe != resolved or not os.path.isfile(safe):
            raise SystemExit(f"env file not found: {path}")
        return safe
    raise SystemExit(
        f"env file path outside allowed directories: {path} (resolved={resolved})"
    )


def _sanitize_ca_runtime_path(ca_runtime_path: str) -> str:
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


def _read_env_file(path: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or "=" not in stripped:
                continue
            key, val = stripped.split("=", 1)
            out[key] = val
    return out


def _write_env_file(path: str, values: Dict[str, str], order: List[str]) -> None:
    lines = []
    seen = set()
    for key in order:
        if key in values:
            lines.append(f"{key}={values[key]}\n")
            seen.add(key)
    for key, val in values.items():
        if key not in seen:
            lines.append(f"{key}={val}\n")
    with open(path, "w", encoding="utf-8") as handle:
        handle.writelines(lines)


def _append_query(url: str, extra: Dict[str, str]) -> str:
    parsed = urlparse(url)
    query = dict(parse_qsl(parsed.query, keep_blank_values=True))
    for key, val in extra.items():
        query.setdefault(key, val)
    return urlunparse(parsed._replace(query=urlencode(query, safe="/")))


def tls_query_params(django_db: str, ca_runtime_path: str) -> Dict[str, str]:
    if django_db == "mariadb":
        return {"ca": ca_runtime_path}
    if django_db == "psql":
        sslcert, sslkey = _client_material_paths(ca_runtime_path)
        return {
            "sslmode": "verify-ca",
            "sslrootcert": ca_runtime_path,
            "sslcert": sslcert,
            "sslkey": sslkey,
        }
    raise SystemExit(f"unsupported DJANGO_DB={django_db} (expected mariadb|psql)")


def patch_env_file(
    path: Path | str,
    django_db: str,
    ca_runtime_path: str,
    *,
    allowed_bases: Sequence[Path | str] | None = None,
) -> str:
    """Append TLS query params to ACME2CERTIFIER_DATABASE_URL; return new URL."""
    if allowed_bases is None:
        bases = _default_allowed_bases()
    else:
        bases = [os.path.realpath(os.fspath(base)) for base in allowed_bases]
    env_path = _safe_env_file(path, bases)
    ca_path = _sanitize_ca_runtime_path(ca_runtime_path)
    values = _read_env_file(env_path)
    url = values.get("ACME2CERTIFIER_DATABASE_URL", "").strip()
    if not url:
        raise SystemExit(f"ACME2CERTIFIER_DATABASE_URL missing in {env_path}")
    updated = _append_query(url, tls_query_params(django_db, ca_path))
    if updated == url:
        print(f"already TLS-patched: {env_path}")
        return url
    values["ACME2CERTIFIER_DATABASE_URL"] = updated
    order = [
        "ACME2CERTIFIER_SECRET_KEY",
        "ACME2CERTIFIER_ALLOWED_HOSTS",
        "ACME2CERTIFIER_DATABASE_URL",
    ]
    _write_env_file(env_path, values, order)
    print(f"patched TLS into DATABASE_URL: {env_path}")
    return updated


# Back-compat alias used by older tests / imports.
patch_file = patch_env_file


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
        help="Path Django opens at runtime for the CA PEM",
    )
    parser.add_argument(
        "env_files",
        nargs="+",
        type=Path,
        help="django.env file(s) containing ACME2CERTIFIER_DATABASE_URL",
    )
    args = parser.parse_args()
    bases = _default_allowed_bases()
    last_url = ""
    for env_file in args.env_files:
        last_url = patch_env_file(
            env_file, args.django_db, args.ca_runtime_path, allowed_bases=bases
        )
    if os.environ.get("GITHUB_ENV") and last_url:
        with open(os.environ["GITHUB_ENV"], "a", encoding="utf-8") as handle:
            handle.write(f"ACME2CERTIFIER_DATABASE_URL={last_url}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
