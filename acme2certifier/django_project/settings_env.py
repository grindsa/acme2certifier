"""Parse ACME2CERTIFIER_* for Django settings via django-environ."""

import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from django.core.exceptions import ImproperlyConfigured

from acme2certifier.acme_srv.helpers.logging_utils import env_debug_get

_DEFAULT_BASE = "/var/www/acme2certifier"
INSECURE_SECRET_KEY = "django-insecure-change-me-run-a2c-django-secret-keygen"
_MYSQL_OPTIONS: Dict[str, Any] = {
    "init_command": "SET sql_mode='STRICT_TRANS_TABLES', innodb_strict_mode=1",
    "charset": "utf8mb4",
    "use_unicode": True,
}
_MSSQL_DEFAULT_DRIVER = "ODBC Driver 18 for SQL Server"
_MYSQL_CA_KEYS = ("ca", "ssl-ca", "ssl_ca")

try:
    import environ
except ImportError as exc:  # pragma: no cover - patched in tests
    environ = None  # type: ignore[assignment]
    _ENVIRON_IMPORT_ERROR: Optional[BaseException] = exc
else:
    _ENVIRON_IMPORT_ERROR = None


def _require_environ() -> Any:
    if environ is None:
        raise ImproperlyConfigured(
            "django-environ is required for Django settings. "
            "Install with: pip install 'acme2certifier[django]' "
            "or the distro package python3-django-environ."
        ) from _ENVIRON_IMPORT_ERROR
    return environ


def sqlite_options(timeout: int) -> Dict[str, Any]:
    """SQLite OPTIONS: busy timeout and IMMEDIATE transactions on Django 5.1+."""
    import django

    options: Dict[str, Any] = {"timeout": timeout}
    if django.VERSION >= (5, 1):
        options["transaction_mode"] = "IMMEDIATE"
    return options


def _allowed_hosts(raw: str) -> List[str]:
    return [h.strip() for h in raw.split(",") if h.strip()]


def _options_dict(db: Dict[str, Any]) -> Dict[str, Any]:
    options = db.get("OPTIONS")
    if not isinstance(options, dict):
        options = {}
        db["OPTIONS"] = options
    return options


def _merge_mysql_ssl(options: Dict[str, Any]) -> None:
    """Nest URL query ca / ssl-ca / ssl_ca into OPTIONS['ssl']['ca']."""
    ca: Optional[Any] = None
    for key in _MYSQL_CA_KEYS:
        if key in options:
            ca = options.pop(key)
            break
    if not ca:
        return
    ssl_opt = options.get("ssl")
    if not isinstance(ssl_opt, dict):
        ssl_opt = {}
        options["ssl"] = ssl_opt
    ssl_opt.setdefault("ca", ca)


def apply_engine_options(db: Dict[str, Any], timeout: int) -> None:
    """Merge engine defaults without overwriting URL-provided OPTIONS."""
    engine = str(db.get("ENGINE") or "")
    options = _options_dict(db)

    if engine.endswith("sqlite3"):
        for key, value in sqlite_options(timeout).items():
            options.setdefault(key, value)
        return

    if "mysql" in engine:
        for key, value in _MYSQL_OPTIONS.items():
            options.setdefault(key, value)
        _merge_mysql_ssl(options)
        return

    if engine in ("mssql", "sql_server.pyodbc") or engine.endswith("mssql"):
        db["ENGINE"] = "mssql"
        options.setdefault("driver", _MSSQL_DEFAULT_DRIVER)


def database_from_url() -> Optional[Dict[str, Any]]:
    """Parse ACME2CERTIFIER_DATABASE_URL, or None when unset."""
    raw = os.environ.get("ACME2CERTIFIER_DATABASE_URL", "").strip()
    if not raw:
        return None
    env_mod = _require_environ()
    env = env_mod.Env()
    db = env.db("ACME2CERTIFIER_DATABASE_URL")
    timeout = int(os.environ.get("ACME2CERTIFIER_SQLITE_TIMEOUT", "30"))
    apply_engine_options(db, timeout)
    return db


def load_settings_env() -> Dict[str, Any]:
    """Return BASE_DIR, SECRET_KEY, DEBUG, ALLOWED_HOSTS, DATABASES."""
    env_mod = _require_environ()
    env = env_mod.Env(
        ACME2CERTIFIER_SQLITE_TIMEOUT=(int, 30),
    )

    default_base = _DEFAULT_BASE if os.path.isdir(_DEFAULT_BASE) else os.getcwd()
    base_dir = str(env("ACME2CERTIFIER_BASE_DIR", default=default_base))

    dotenv = Path(base_dir) / ".env"
    if dotenv.is_file():
        env.read_env(str(dotenv), overwrite=False)
        base_dir = str(env("ACME2CERTIFIER_BASE_DIR", default=default_base))

    secret_key = str(env("ACME2CERTIFIER_SECRET_KEY", default=INSECURE_SECRET_KEY))
    debug = env_debug_get()
    default_hosts = "127.0.0.1,*" if debug else "127.0.0.1,localhost"
    allowed_hosts = _allowed_hosts(
        str(env("ACME2CERTIFIER_ALLOWED_HOSTS", default=default_hosts))
    )
    timeout = int(env("ACME2CERTIFIER_SQLITE_TIMEOUT"))

    db = database_from_url()
    if db is None:
        db = {
            "ENGINE": "django.db.backends.sqlite3",
            "NAME": os.path.join(base_dir, "db.sqlite3"),
            "OPTIONS": {},
        }
        apply_engine_options(db, timeout)

    return {
        "BASE_DIR": base_dir,
        "SECRET_KEY": secret_key,
        "DEBUG": debug,
        "ALLOWED_HOSTS": allowed_hosts,
        "DATABASES": {"default": db},
    }
