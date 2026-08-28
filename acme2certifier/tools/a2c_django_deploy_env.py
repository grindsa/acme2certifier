#!/usr/bin/python3
"""Load ACME2CERTIFIER_* from uWSGI ini / Apache envvars when unset in os.environ."""

from __future__ import annotations

import os
import re
import shlex
import socket
from pathlib import Path
from typing import Dict, Optional

_UWSGI_ENV_RE = re.compile(r"^env\s*=\s*(ACME2CERTIFIER_[A-Z_]+)=(.*)$")
_APACHE_EXPORT_PREFIX = "export ACME2CERTIFIER_"
_DEPLOY_KEYS = (
    "ACME2CERTIFIER_SECRET_KEY",
    "ACME2CERTIFIER_ALLOWED_HOSTS",
    "ACME2CERTIFIER_DEBUG",
)


def _unquote_uwsgi_value(raw: str) -> str:
    val = raw.strip()
    if len(val) >= 2 and val[0] == val[-1] == '"':
        return val[1:-1].replace("$$", "$")
    return val


def _read_uwsgi_env(ini_path: Path) -> Dict[str, str]:
    out: Dict[str, str] = {}
    if not ini_path.is_file():
        return out
    for line in ini_path.read_text(encoding="utf-8").splitlines():
        match = _UWSGI_ENV_RE.match(line.strip())
        if match:
            out[match.group(1)] = _unquote_uwsgi_value(match.group(2))
    return out


def _parse_apache_export(line: str) -> Optional[tuple[str, str]]:
    stripped = line.strip()
    if not stripped.startswith(_APACHE_EXPORT_PREFIX):
        return None
    try:
        tokens = shlex.split(stripped, posix=True)
    except ValueError:
        return None
    if len(tokens) != 2 or "=" not in tokens[1]:
        return None
    key, val = tokens[1].split("=", 1)
    if not key.startswith("ACME2CERTIFIER_"):
        return None
    return key, val


def _read_apache_envvars(envvars_path: Path) -> Dict[str, str]:
    out: Dict[str, str] = {}
    if not envvars_path.is_file():
        return out
    for line in envvars_path.read_text(encoding="utf-8").splitlines():
        parsed = _parse_apache_export(line)
        if parsed:
            out[parsed[0]] = parsed[1]
    return out


def load_deploy_env(base_dir: Optional[str] = None) -> None:
    """Populate ACME2CERTIFIER_* in os.environ from deployment files when unset."""
    base = Path(
        base_dir or os.environ.get("ACME2CERTIFIER_BASE_DIR", "/var/www/acme2certifier")
    )
    for source in (
        _read_uwsgi_env(base / "acme2certifier.ini"),
        _read_apache_envvars(Path("/etc/apache2/envvars")),
    ):
        for key, val in source.items():
            if key in _DEPLOY_KEYS and not os.environ.get(key):
                os.environ[key] = val

    if not os.environ.get("ACME2CERTIFIER_SECRET_KEY"):
        # pylint: disable=E0401
        from django.core.management.utils import get_random_secret_key

        os.environ["ACME2CERTIFIER_SECRET_KEY"] = get_random_secret_key()

    if not os.environ.get("ACME2CERTIFIER_ALLOWED_HOSTS"):
        host = socket.gethostname()
        os.environ["ACME2CERTIFIER_ALLOWED_HOSTS"] = f"127.0.0.1,localhost,{host}"


def main() -> None:
    load_deploy_env()
    for key in _DEPLOY_KEYS:
        if os.environ.get(key):
            print(f"{key} is set")


if __name__ == "__main__":
    main()
