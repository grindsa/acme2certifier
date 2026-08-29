#!/usr/bin/python3
"""Load ACME2CERTIFIER_* from uWSGI ini / Apache envvars when unset in os.environ."""

import configparser
import os
import re
import shlex
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

_UWSGI_ENV_RE = re.compile(r"^env\s*=\s*(ACME2CERTIFIER_[A-Z_]+)=(.*)$")
_APACHE_EXPORT_PREFIX = "export ACME2CERTIFIER_"
_DEPLOY_KEYS = (
    "ACME2CERTIFIER_SECRET_KEY",
    "ACME2CERTIFIER_ALLOWED_HOSTS",
    "ACME2CERTIFIER_DEBUG",
)
_DEFAULT_DEPLOY_HOST = "acme-srv"


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


def _parse_apache_export(line: str) -> Optional[Tuple[str, str]]:
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


def _host_from_server_name(server_name: str) -> Optional[str]:
    """Extract a Host header value from cfg server_name (FQDN or URL)."""
    value = server_name.strip()
    if not value:
        return None
    if "://" in value:
        host = urlparse(value).hostname
    else:
        host = value.split("/", 1)[0].strip()
        if "@" in host:
            host = host.rsplit("@", 1)[-1]
        if host.startswith("[") and "]" in host:
            host = host[1 : host.index("]")]
        elif ":" in host:
            host = host.rsplit(":", 1)[0]
    host = (host or "").strip()
    return host or None


def _acme_srv_cfg_path(base: Path) -> Path:
    return Path(os.environ.get("ACME_SRV_CONFIGFILE", str(base / "acme_srv.cfg")))


def _server_name_host_from_cfg(base: Path) -> Optional[str]:
    """Return server_name from acme_srv.cfg as an ALLOWED_HOSTS entry."""
    cfg_path = _acme_srv_cfg_path(base)
    if not cfg_path.is_file():
        return None
    parser = configparser.ConfigParser(interpolation=None)
    parser.optionxform = str
    try:
        parser.read(cfg_path, encoding="utf-8-sig")
    except (OSError, configparser.Error):
        return None
    for section in ("DEFAULT", "Directory"):
        if not parser.has_option(section, "server_name"):
            continue
        raw = parser.get(section, "server_name", fallback="").strip()
        host = _host_from_server_name(raw)
        if host:
            return host
    return None


def _ensure_allowed_hosts(base: Optional[Path] = None) -> None:
    """127.0.0.1 and localhost are always allowed; merge configured hosts or acme-srv."""
    raw = os.environ.get("ACME2CERTIFIER_ALLOWED_HOSTS", "").strip()
    if raw:
        extras = [h.strip() for h in raw.split(",") if h.strip()]
    else:
        extras = [_DEFAULT_DEPLOY_HOST]
    if base is not None:
        cfg_host = _server_name_host_from_cfg(base)
        if cfg_host and cfg_host not in extras:
            extras.append(cfg_host)
    hosts: List[str] = []
    for host in ("127.0.0.1", "localhost", *extras):
        if host not in hosts:
            hosts.append(host)
    os.environ["ACME2CERTIFIER_ALLOWED_HOSTS"] = ",".join(hosts)


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

    _ensure_allowed_hosts(base)


def main() -> None:
    load_deploy_env()
    for key in _DEPLOY_KEYS:
        if os.environ.get(key):
            print(f"{key} is set")


if __name__ == "__main__":
    main()
