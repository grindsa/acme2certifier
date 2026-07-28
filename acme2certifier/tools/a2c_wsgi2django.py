#!/usr/bin/python3
"""Migrate ACME data from WSGI SQLite to Django ORM via a portable JSON dump."""

import argparse
import json
import os
import re
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

_VERBOSE = False

from acme2certifier.acme_srv.version import __dbversion__, __version__

SCHEMA_VERSION = 1
TOOL_VERSION = "0.1.0"
DEFAULT_DJANGO_SETTINGS = "acme2certifier.django_project.settings"

# Dump keys use WSGI table names (orders, not order).
DUMP_TABLES: Tuple[str, ...] = (
    "status",
    "account",
    "orders",
    "authorization",
    "challenge",
    "certificate",
    "cliaccount",
    "cahandler",
    "housekeeping",
    "nonce",
)

EXPECTED_STATUS: Dict[int, str] = {
    1: "invalid",
    2: "pending",
    3: "ready",
    4: "processing",
    5: "valid",
    6: "expired",
    7: "deactivated",
    8: "revoked",
}

# Dump table → Django model class name (django_app.models).
TABLE_MODEL_MAP: Dict[str, str] = {
    "account": "Account",
    "cliaccount": "Cliaccount",
    "challenge": "Challenge",
    "housekeeping": "Housekeeping",
    "cahandler": "Cahandler",
}

# Columns checked for Django max_length overflow (dump/WSGI names == model fields).
LENGTH_CHECK_FIELDS: Dict[str, Tuple[str, ...]] = {
    "account": ("contact", "eab_kid"),
    "cliaccount": ("contact",),
    "challenge": ("keyauthorization", "source"),
    "housekeeping": ("value",),
    "cahandler": ("value1", "value2"),
}

# Used only when Django models cannot be imported (WSGI-only host).
FALLBACK_LENGTH_LIMITS: Dict[str, Dict[str, int]] = {
    "account": {"contact": 255, "eab_kid": 255},
    "cliaccount": {"contact": 255},
    "challenge": {"keyauthorization": 128, "source": 128},
    "housekeeping": {"value": 30},
    "cahandler": {"value1": 250, "value2": 250},
}

# child_table -> (fk_column, parent_table)
FK_SPECS: Tuple[Tuple[str, str, str], ...] = (
    ("account", "status_id", "status"),
    ("orders", "account_id", "account"),
    ("orders", "status_id", "status"),
    ("authorization", "order_id", "orders"),
    ("authorization", "status_id", "status"),
    ("challenge", "authorization_id", "authorization"),
    ("challenge", "status_id", "status"),
    ("certificate", "order_id", "orders"),
)

SUMMARY_KEYS: Tuple[Tuple[str, str], ...] = (
    ("account", "accounts"),
    ("orders", "orders"),
    ("authorization", "authorizations"),
    ("challenge", "challenges"),
    ("certificate", "certificates"),
    ("cliaccount", "cliaccounts"),
    ("cahandler", "cahandler"),
    ("housekeeping", "housekeeping"),
    ("nonce", "nonces"),
    ("status", "status"),
)

# Wipe order (children before parents). Status is never wiped.
WIPE_MODEL_NAMES: Tuple[str, ...] = (
    "Challenge",
    "Authorization",
    "Certificate",
    "Order",
    "Account",
    "Cliaccount",
    "Cahandler",
    "Nonce",
)

# Import order (FK-safe). Status is verify-only (never written).
IMPORT_TABLE_ORDER: Tuple[str, ...] = (
    "account",
    "orders",
    "authorization",
    "challenge",
    "certificate",
    "cliaccount",
    "cahandler",
    "housekeeping",
    "nonce",
)

CHECK_EXIT_OK = 0
CHECK_EXIT_MISMATCH = 1
CHECK_EXIT_ERROR = 2

CHECK_FIELDS: Dict[str, Tuple[str, ...]] = {
    "status": ("id", "name"),
    "account": ("id", "name", "status_id", "alg", "jwk", "contact", "eab_kid"),
    "orders": (
        "id",
        "name",
        "account_id",
        "status_id",
        "notbefore",
        "notafter",
        "identifiers",
        "profile",
        "expires",
    ),
    "authorization": (
        "id",
        "name",
        "order_id",
        "status_id",
        "type",
        "value",
        "token",
        "expires",
    ),
    "challenge": (
        "id",
        "name",
        "authorization_id",
        "status_id",
        "type",
        "token",
        "keyauthorization",
        "source",
        "validated",
        "validation_error",
        "expires",
    ),
    "certificate": (
        "id",
        "name",
        "order_id",
        "csr",
        "cert",
        "cert_raw",
        "error",
        "poll_identifier",
        "header_info",
        "renewal_info",
        "aki",
        "serial",
        "issue_uts",
        "expire_uts",
        "replaced",
    ),
    "cliaccount": (
        "id",
        "name",
        "jwk",
        "contact",
        "cliadmin",
        "reportadmin",
        "certificateadmin",
    ),
    "cahandler": ("id", "name", "value1", "value2"),
    "housekeeping": ("id", "name", "value"),
    "nonce": ("id", "nonce"),
}

CHECK_MODEL_MAP: Dict[str, str] = {
    "status": "Status",
    "account": "Account",
    "orders": "Order",
    "authorization": "Authorization",
    "challenge": "Challenge",
    "certificate": "Certificate",
    "cliaccount": "Cliaccount",
    "cahandler": "Cahandler",
    "housekeeping": "Housekeeping",
    "nonce": "Nonce",
}

BOOL_CHECK_FIELDS: Dict[str, Tuple[str, ...]] = {
    "cliaccount": ("cliadmin", "reportadmin", "certificateadmin"),
    "certificate": ("replaced",),
}

INT_CHECK_FIELDS: Dict[str, Tuple[str, ...]] = {
    "status": ("id",),
    "account": ("id", "status_id"),
    "orders": ("id", "account_id", "status_id", "notbefore", "notafter", "expires"),
    "authorization": ("id", "order_id", "status_id", "expires"),
    "challenge": ("id", "authorization_id", "status_id", "validated", "expires"),
    "certificate": ("id", "order_id", "issue_uts", "expire_uts"),
    "cliaccount": ("id",),
    "cahandler": ("id",),
    "housekeeping": ("id",),
    "nonce": ("id",),
}

EMPTY_EQ_NONE_FIELDS: Dict[str, Tuple[str, ...]] = {
    "account": ("name", "alg", "jwk", "contact", "eab_kid"),
    "orders": ("name", "identifiers", "profile"),
    "authorization": ("name", "type", "value", "token"),
    "challenge": (
        "name",
        "token",
        "type",
        "keyauthorization",
        "source",
        "validation_error",
    ),
    "cliaccount": ("name", "jwk", "contact"),
    "cahandler": ("name", "value1", "value2"),
    "housekeeping": ("name", "value"),
    "nonce": ("nonce",),
}

NONE_EQ_ZERO_FIELDS: Dict[str, Tuple[str, ...]] = {
    "authorization": ("expires",),
    "orders": ("notbefore", "notafter", "expires"),
    "challenge": ("expires", "validated"),
    "certificate": ("issue_uts", "expire_uts"),
}


class ExportError(Exception):
    """Raised when WSGI export validation fails."""


class MigrationError(Exception):
    """Raised when wipe/import validation or ORM operations fail."""


def set_verbose(enabled: bool) -> None:
    """Enable or disable verbose progress logging to stderr."""
    global _VERBOSE
    _VERBOSE = enabled


def _vlog(message: str) -> None:
    """Print a progress line when verbose mode is enabled."""
    if _VERBOSE:
        print(message, file=sys.stderr)


def _ensure_django_models() -> bool:
    """Configure Django just enough to read model field metadata.

    Returns False when Django is not installed or setup fails. Does not open
    a database connection; export remains usable on WSGI-only hosts via
    FALLBACK_LENGTH_LIMITS.
    """
    try:
        import django
        from django.apps import apps
        from django.conf import settings
    except ImportError:
        return False

    try:
        if apps.ready:
            return True
        if not settings.configured:
            settings.configure(
                INSTALLED_APPS=["acme2certifier.django_app"],
                DATABASES={
                    "default": {
                        "ENGINE": "django.db.backends.sqlite3",
                        "NAME": ":memory:",
                    }
                },
                USE_TZ=True,
            )
        django.setup()
        return True
    except Exception as exc:  # noqa: BLE001 — optional path; fall back
        print(
            f"warning: Django model introspection unavailable ({exc}); "
            "using fallback length limits",
            file=sys.stderr,
        )
        return False


def length_limits_from_django() -> Optional[Dict[str, Dict[str, int]]]:
    """Read max_length for length-checked fields from django_app.models.

    Fields without max_length (e.g. unlimited TextField) are omitted — no
    overflow check for that column.
    """
    if not _ensure_django_models():
        return None

    from acme2certifier.django_app import models as dj_models

    limits: Dict[str, Dict[str, int]] = {}
    for table, field_names in LENGTH_CHECK_FIELDS.items():
        model = getattr(dj_models, TABLE_MODEL_MAP[table])
        field_limits: Dict[str, int] = {}
        for field_name in field_names:
            field = model._meta.get_field(field_name)
            max_len = getattr(field, "max_length", None)
            if max_len is not None:
                field_limits[field_name] = int(max_len)
        if field_limits:
            limits[table] = field_limits
    return limits


def resolve_length_limits() -> Dict[str, Dict[str, int]]:
    """Prefer live Django model limits; else frozen FALLBACK_LENGTH_LIMITS."""
    live = length_limits_from_django()
    if live is not None:
        return live
    return {table: dict(cols) for table, cols in FALLBACK_LENGTH_LIMITS.items()}


def _row_to_dict(row: sqlite3.Row) -> Dict[str, Any]:
    """Convert sqlite3.Row to a plain dict preserving column names."""
    return {key: row[key] for key in row.keys()}


def _table_exists(conn: sqlite3.Connection, table: str) -> bool:
    """Return True if *table* exists in the SQLite database."""
    cur = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=? LIMIT 1",
        (table,),
    )
    return cur.fetchone() is not None


def _fetch_table(conn: sqlite3.Connection, table: str) -> List[Dict[str, Any]]:
    """Fetch all rows from *table* as dicts ordered by id when present."""
    if not _table_exists(conn, table):
        return []
    cur = conn.execute(f'SELECT * FROM "{table}"')
    rows = [_row_to_dict(row) for row in cur.fetchall()]
    if rows and "id" in rows[0]:
        rows.sort(key=lambda r: int(r["id"]))
    return rows


def _read_dbversion(conn: sqlite3.Connection) -> Optional[str]:
    """Read housekeeping.dbversion value, or None if missing."""
    if not _table_exists(conn, "housekeeping"):
        return None
    cur = conn.execute(
        'SELECT value FROM housekeeping WHERE name = ? LIMIT 1',
        ("dbversion",),
    )
    row = cur.fetchone()
    if row is None:
        return None
    value = row[0]
    return None if value is None else str(value)


def _validate_dbversion(dbversion: Optional[str]) -> None:
    """Refuse export when source dbversion != tool __dbversion__."""
    if dbversion is None:
        raise ExportError(
            "source database has no housekeeping.dbversion row; "
            f"expected {__dbversion__}"
        )
    if dbversion != __dbversion__:
        raise ExportError(
            f"source dbversion {dbversion!r} != tool __dbversion__ {__dbversion__!r}; "
            "refuse export (upgrade WSGI DB with a2c-db-update first)"
        )


def _validate_status(rows: Sequence[Mapping[str, Any]]) -> None:
    """Validate status PK ↔ name map when status rows are present."""
    if not rows:
        return
    by_id = {int(row["id"]): str(row["name"]) for row in rows}
    for pk, name in EXPECTED_STATUS.items():
        if pk not in by_id:
            raise ExportError(f"status PK {pk} missing (expected name={name!r})")
        if by_id[pk] != name:
            raise ExportError(
                f"status PK {pk} name mismatch: got {by_id[pk]!r}, expected {name!r}"
            )


def _validate_lengths(
    tables: Mapping[str, Sequence[Mapping[str, Any]]],
    limits: Optional[Mapping[str, Mapping[str, int]]] = None,
) -> None:
    """Fail when any field exceeds Django target max_length."""
    resolved = limits if limits is not None else resolve_length_limits()
    for table, cols in resolved.items():
        for row in tables.get(table, []):
            row_id = row.get("id")
            for column, max_len in cols.items():
                value = row.get(column)
                if value is None:
                    continue
                text = str(value)
                if len(text) > max_len:
                    raise ExportError(
                        f"{table}.id={row_id} {column} length {len(text)} "
                        f"exceeds Django limit {max_len}"
                    )


def _ids(rows: Iterable[Mapping[str, Any]]) -> set:
    """Collect integer id values from rows."""
    return {int(row["id"]) for row in rows if row.get("id") is not None}


def _drop_orphan_rows(
    tables: Dict[str, List[Dict[str, Any]]],
    stream: Any = None,
) -> None:
    """Remove rows with NULL/dangling FKs; warn on stderr (do not fail).

    Processes child tables in FK dependency order so dropping a parent row
    also drops dependent children on a later pass.
    """
    if stream is None:
        stream = sys.stderr

    child_order: List[str] = []
    seen = set()
    for child, _fk_col, _parent in FK_SPECS:
        if child not in seen:
            child_order.append(child)
            seen.add(child)

    for child in child_order:
        specs = [(fk, parent) for c, fk, parent in FK_SPECS if c == child]
        id_sets = {name: _ids(rows) for name, rows in tables.items()}
        kept: List[Dict[str, Any]] = []
        for row in tables.get(child, []):
            reason: Optional[str] = None
            for fk_col, parent in specs:
                fk_val = row.get(fk_col)
                if fk_val is None:
                    reason = f"NULL {fk_col} (required FK to {parent})"
                    break
                if int(fk_val) not in id_sets.get(parent, set()):
                    reason = (
                        f"dangling {fk_col}={fk_val} (missing {parent}.id)"
                    )
                    break
            if reason is not None:
                print(
                    f"warning: skipping orphan {child}.id={row.get('id')}: {reason}",
                    file=stream,
                )
                continue
            kept.append(row)
        tables[child] = kept


def _validate_required(tables: Mapping[str, Sequence[Mapping[str, Any]]]) -> None:
    """Fail when required NOT NULL fields are missing/empty in dump rows."""
    for row in tables.get("account", []):
        if not row.get("jwk"):
            raise ExportError(f"account.id={row.get('id')} missing required jwk")
        if row.get("contact") is None:
            raise ExportError(f"account.id={row.get('id')} missing required contact")
    for row in tables.get("certificate", []):
        if row.get("csr") is None:
            raise ExportError(f"certificate.id={row.get('id')} missing required csr")
        if row.get("order_id") is None:
            raise ExportError(
                f"certificate.id={row.get('id')} missing required order_id"
            )


def build_dump(
    db_path: Path,
    *,
    include_nonces: bool = False,
) -> Dict[str, Any]:
    """Read WSGI SQLite and build a dump dict (schema v1)."""
    if not db_path.is_file():
        raise ExportError(f"WSGI database not found: {db_path}")

    _vlog(f"export: reading WSGI database {db_path.resolve()}")
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    try:
        dbversion = _read_dbversion(conn)
        _vlog(f"export: source dbversion={dbversion!r}")
        _validate_dbversion(dbversion)

        tables: Dict[str, List[Dict[str, Any]]] = {}
        for name in DUMP_TABLES:
            if name == "nonce" and not include_nonces:
                tables[name] = []
                continue
            tables[name] = _fetch_table(conn, name)
            _vlog(f"export: table {name}: {len(tables[name])} row(s)")

        _validate_status(tables["status"])
        _vlog("export: status fixture validated")
        _drop_orphan_rows(tables)
        _validate_lengths(tables)
        _validate_required(tables)
        _vlog("export: validation complete")

        dump: Dict[str, Any] = {
            "meta": {
                "schema_version": SCHEMA_VERSION,
                "tool_version": TOOL_VERSION,
                "a2c_version": __version__,
                "dbversion": dbversion,
                "source": "wsgi-sqlite",
                "source_path": str(db_path.resolve()),
                "created_at": datetime.now(timezone.utc)
                .replace(microsecond=0)
                .isoformat()
                .replace("+00:00", "Z"),
                "include_nonces": include_nonces,
            },
            "tables": tables,
        }
        return dump
    finally:
        conn.close()


def summary_counts(tables: Mapping[str, Sequence[Any]]) -> Dict[str, int]:
    """Return human-oriented counts for export/import summary output."""
    return {label: len(tables.get(key, [])) for key, label in SUMMARY_KEYS}


def print_summary(
    tables: Mapping[str, Sequence[Any]],
    stream: Any = None,
    *,
    prefix: str = "export summary",
) -> None:
    """Print entity counts to stdout (or *stream*)."""
    if stream is None:
        stream = sys.stdout
    counts = summary_counts(tables)
    labels = (
        "accounts",
        "orders",
        "authorizations",
        "challenges",
        "certificates",
        "cliaccounts",
        "cahandler",
        "housekeeping",
        "status",
    )
    parts = [f"{name}={counts[name]}" for name in labels]
    if counts.get("nonces", 0):
        parts.append(f"nonces={counts['nonces']}")
    print(f"{prefix}: " + ", ".join(parts), file=stream)


def write_dump(dump: Mapping[str, Any], out_path: Path) -> None:
    """Write dump JSON to *out_path* (UTF-8, indented)."""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as handle:
        json.dump(dump, handle, indent=2, ensure_ascii=False, sort_keys=False)
        handle.write("\n")


def load_dump(dump_path: Path) -> Dict[str, Any]:
    """Load and minimally validate a dump JSON file."""
    if not dump_path.is_file():
        raise MigrationError(f"dump not found: {dump_path}")
    try:
        with dump_path.open("r", encoding="utf-8") as handle:
            dump = json.load(handle)
    except json.JSONDecodeError as exc:
        raise MigrationError(f"invalid dump JSON: {exc}") from exc
    if not isinstance(dump, dict):
        raise MigrationError("dump root must be a JSON object")
    meta = dump.get("meta")
    tables = dump.get("tables")
    if not isinstance(meta, dict) or not isinstance(tables, dict):
        raise MigrationError("dump must contain meta and tables objects")
    return dump


def setup_django_orm() -> None:
    """Bootstrap Django for ORM wipe/import (same pattern as a2c-django-update)."""
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", DEFAULT_DJANGO_SETTINGS)
    try:
        import django
        from django.apps import apps
        from django.conf import settings
    except ImportError as exc:
        raise MigrationError(
            f"Django is required for wipe/import: {exc}"
        ) from exc

    if apps.ready:
        return
    try:
        if not settings.configured and not os.environ.get("DJANGO_SETTINGS_MODULE"):
            raise MigrationError(
                "Django settings are not configured; set DJANGO_SETTINGS_MODULE"
            )
        django.setup()
    except MigrationError:
        raise
    except Exception as exc:  # noqa: BLE001 — surface setup failures to CLI
        raise MigrationError(f"Django setup failed: {exc}") from exc


def _django_models() -> Any:
    """Return django_app.models after ORM setup."""
    setup_django_orm()
    from acme2certifier.django_app import models as dj_models

    return dj_models


def _status_mismatches(models: Any) -> List[str]:
    """Return status fixture mismatches as human-readable strings."""
    by_id = {int(row.pk): str(row.name) for row in models.Status.objects.all()}
    mismatches: List[str] = []
    for pk, name in EXPECTED_STATUS.items():
        if pk not in by_id:
            mismatches.append(f"PK {pk} missing (expected name={name!r})")
            continue
        if by_id[pk] != name:
            mismatches.append(
                f"PK {pk} name mismatch: got {by_id[pk]!r}, expected {name!r}"
            )
    return mismatches


def assert_django_status_fixture(*, auto_seed: bool = True) -> None:
    """Ensure Django Status PKs 1-8 match fixture, optionally auto-seeding."""
    models = _django_models()
    mismatches = _status_mismatches(models)
    if not mismatches and not auto_seed:
        return
    if not mismatches:
        return

    if auto_seed:
        from django.core.management import call_command

        print(
            "warning: edge-case detected: Django Status fixture is missing/invalid; importing fixture via loaddata status",
            file=sys.stderr,
        )
        call_command("loaddata", "status", verbosity=0)
        mismatches = _status_mismatches(models)
        if not mismatches:
            return

    if not auto_seed:
        raise MigrationError(
            "Django Status fixture invalid during dry-run (no DB writes allowed): "
            + "; ".join(mismatches)
            + ". Seed Status first (a2c-django-update / loaddata status), "
            + "or run import without --dry-run to allow auto-seeding"
        )

    raise MigrationError(
        "Django Status fixture invalid: "
        + "; ".join(mismatches)
        + ". Run a2c-django-update / loaddata status"
    )


def _validate_dump_for_import(dump: Mapping[str, Any]) -> None:
    """Validate dump meta/tables before ORM import."""
    meta = dump["meta"]
    tables = dump["tables"]
    schema_version = meta.get("schema_version")
    if schema_version != SCHEMA_VERSION:
        raise MigrationError(
            f"dump schema_version {schema_version!r} != {SCHEMA_VERSION}"
        )
    dbversion = meta.get("dbversion")
    if dbversion != __dbversion__:
        raise MigrationError(
            f"dump dbversion {dbversion!r} != tool __dbversion__ {__dbversion__!r}"
        )
    try:
        _validate_status(tables.get("status", []))
        _validate_lengths(tables)
        _validate_required(tables)
    except ExportError as exc:
        raise MigrationError(str(exc)) from exc


def target_acme_row_counts() -> Dict[str, int]:
    """Count migratable ACME rows in the Django DB (Status excluded)."""
    models = _django_models()
    return {
        "account": models.Account.objects.count(),
        "orders": models.Order.objects.count(),
        "authorization": models.Authorization.objects.count(),
        "challenge": models.Challenge.objects.count(),
        "certificate": models.Certificate.objects.count(),
        "cliaccount": models.Cliaccount.objects.count(),
        "cahandler": models.Cahandler.objects.count(),
        "nonce": models.Nonce.objects.count(),
        "housekeeping": models.Housekeeping.objects.exclude(name="dbversion").count(),
    }


def target_is_nonempty() -> bool:
    """True when any migratable ACME data exists (ignores Status + dbversion)."""
    return any(count > 0 for count in target_acme_row_counts().values())


def wipe_acme_data(*, dry_run: bool = False) -> Dict[str, int]:
    """Delete ACME app rows in FK-safe order; never delete Status.

    Preserves Housekeeping ``dbversion`` so Django's post-migrate value remains.
    """
    from django.db import transaction

    models = _django_models()
    deleted: Dict[str, int] = {}

    def _delete(label: str, queryset: Any) -> None:
        count = queryset.count()
        deleted[label] = count
        if not dry_run and count:
            queryset.delete()

    with transaction.atomic():
        for name in WIPE_MODEL_NAMES:
            model = getattr(models, name)
            count = model.objects.count()
            _vlog(f"wipe: {name.lower()}: {count} row(s)")
            _delete(name.lower(), model.objects.all())
        hk_qs = models.Housekeeping.objects.exclude(name="dbversion")
        hk_count = hk_qs.count()
        _vlog(f"wipe: housekeeping: {hk_count} row(s) (dbversion preserved)")
        _delete("housekeeping", hk_qs)
        # Status intentionally untouched.
        deleted["status"] = 0
    return deleted


def print_wipe_summary(deleted: Mapping[str, int], stream: Any = None) -> None:
    """Print wipe deletion counts."""
    if stream is None:
        stream = sys.stdout
    order = (
        "challenge",
        "authorization",
        "certificate",
        "order",
        "account",
        "cliaccount",
        "cahandler",
        "nonce",
        "housekeeping",
    )
    parts = [f"{key}={deleted.get(key, 0)}" for key in order]
    print("wipe summary: " + ", ".join(parts), file=stream)


def _as_bool(value: Any) -> bool:
    """Coerce dump INT/NULL/bool to Django BooleanField."""
    if value is None:
        return False
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(int(value))
    text = str(value).strip().lower()
    if text in ("", "0", "false", "no", "n"):
        return False
    if text in ("1", "true", "yes", "y"):
        return True
    return bool(value)


def _as_int(value: Any, default: int = 0) -> int:
    """Coerce NULL int fields to *default*."""
    if value is None or value == "":
        return default
    return int(value)


def _as_str(value: Any, default: str = "") -> str:
    """Coerce NULL strings to *default* when blankable."""
    if value is None:
        return default
    return str(value)


def _parse_iso_datetime(text: str) -> datetime:
    """Parse ISO-like timestamps without datetime.fromisoformat (Python 3.6)."""
    normalized = str(text).strip()
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+0000"
    tz_match = re.match(r"^(.*)([+-]\d{2}):(\d{2})$", normalized)
    if tz_match:
        normalized = tz_match.group(1) + tz_match.group(2) + tz_match.group(3)

    formats = (
        "%Y-%m-%dT%H:%M:%S.%f%z",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S",
    )
    for fmt in formats:
        try:
            return datetime.strptime(normalized, fmt)
        except ValueError:
            continue
    raise ValueError("unparseable timestamp: {!r}".format(normalized))


def _parse_datetime(value: Any) -> Optional[datetime]:
    """Parse dump timestamp into a datetime; make aware when USE_TZ=True."""
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        dt = value
    else:
        text = str(value).strip()
        try:
            dt = _parse_iso_datetime(text)
        except ValueError:
            for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M:%S.%f"):
                try:
                    dt = datetime.strptime(text, fmt)
                    break
                except ValueError:
                    continue
            else:
                raise MigrationError("unparseable timestamp: {!r}".format(value))

    from django.conf import settings
    from django.utils import timezone as dj_tz

    if getattr(settings, "USE_TZ", False):
        if dj_tz.is_naive(dt):
            dt = dj_tz.make_aware(dt, dj_tz.get_default_timezone())
    return dt


def _save_with_timestamps(
    model: Any,
    fields: Dict[str, Any],
    timestamps: Mapping[str, Any],
) -> None:
    """Create a row with explicit pk, then set auto_now(_add) timestamps via update."""
    obj = model(**fields)
    obj.save()
    updates = {
        key: value for key, value in timestamps.items() if value is not None
    }
    if updates:
        model.objects.filter(pk=obj.pk).update(**updates)


def _import_account(row: Mapping[str, Any], models: Any) -> None:
    """Insert Account preserving pk and FKs."""
    created_at = _parse_datetime(row.get("created_at"))
    _save_with_timestamps(
        models.Account,
        {
            "id": int(row["id"]),
            "name": _as_str(row.get("name")),
            "alg": _as_str(row.get("alg")),
            "jwk": _as_str(row.get("jwk")),
            "contact": _as_str(row.get("contact")),
            "eab_kid": _as_str(row.get("eab_kid")),
            "status_id": int(row["status_id"]),
        },
        {"created_at": created_at},
    )


def _import_order(row: Mapping[str, Any], models: Any) -> None:
    """Insert Order from dump ``orders`` row."""
    created_at = _parse_datetime(row.get("created_at"))
    _save_with_timestamps(
        models.Order,
        {
            "id": int(row["id"]),
            "name": _as_str(row.get("name")),
            "notbefore": _as_int(row.get("notbefore")),
            "notafter": _as_int(row.get("notafter")),
            "identifiers": _as_str(row.get("identifiers")),
            "account_id": int(row["account_id"]),
            "profile": _as_str(row.get("profile")),
            "status_id": int(row["status_id"]),
            "expires": _as_int(row.get("expires")),
        },
        {"created_at": created_at},
    )


def _import_authorization(row: Mapping[str, Any], models: Any) -> None:
    """Insert Authorization preserving stored status_id."""
    created_at = _parse_datetime(row.get("created_at"))
    _save_with_timestamps(
        models.Authorization,
        {
            "id": int(row["id"]),
            "name": _as_str(row.get("name")),
            "order_id": int(row["order_id"]),
            "type": _as_str(row.get("type")),
            "value": _as_str(row.get("value")),
            "expires": _as_int(row.get("expires")),
            "token": _as_str(row.get("token")),
            "status_id": int(row["status_id"]),
        },
        {"created_at": created_at},
    )


def _import_challenge(row: Mapping[str, Any], models: Any) -> None:
    """Insert Challenge; NULL token becomes empty string."""
    created_at = _parse_datetime(row.get("created_at"))
    token = row.get("token")
    if token is None:
        print(
            f"warning: challenge.id={row.get('id')} token is NULL; using empty string",
            file=sys.stderr,
        )
        token = ""
    _save_with_timestamps(
        models.Challenge,
        {
            "id": int(row["id"]),
            "name": _as_str(row.get("name")),
            "token": _as_str(token),
            "authorization_id": int(row["authorization_id"]),
            "expires": _as_int(row.get("expires")),
            "type": _as_str(row.get("type")),
            "keyauthorization": _as_str(row.get("keyauthorization")),
            "source": _as_str(row.get("source")),
            "status_id": int(row["status_id"]),
            "validated": _as_int(row.get("validated")),
            "validation_error": _as_str(row.get("validation_error")),
        },
        {"created_at": created_at},
    )


def _import_certificate(row: Mapping[str, Any], models: Any) -> None:
    """Insert Certificate preserving pk and order_id."""
    created_at = _parse_datetime(row.get("created_at"))
    _save_with_timestamps(
        models.Certificate,
        {
            "id": int(row["id"]),
            "name": _as_str(row.get("name")),
            "cert": row.get("cert"),
            "cert_raw": row.get("cert_raw"),
            "error": row.get("error"),
            "order_id": int(row["order_id"]),
            "csr": row.get("csr"),
            "poll_identifier": row.get("poll_identifier"),
            "header_info": row.get("header_info"),
            "renewal_info": row.get("renewal_info"),
            "aki": row.get("aki"),
            "serial": row.get("serial"),
            "issue_uts": _as_int(row.get("issue_uts")),
            "expire_uts": _as_int(row.get("expire_uts")),
            "replaced": _as_bool(row.get("replaced")),
        },
        {"created_at": created_at},
    )


def _import_cliaccount(row: Mapping[str, Any], models: Any) -> None:
    """Insert Cliaccount via model (handler has no cliaccount_add)."""
    created_at = _parse_datetime(row.get("created_at"))
    _save_with_timestamps(
        models.Cliaccount,
        {
            "id": int(row["id"]),
            "name": _as_str(row.get("name")),
            "jwk": _as_str(row.get("jwk")),
            "contact": _as_str(row.get("contact")),
            "cliadmin": _as_bool(row.get("cliadmin")),
            "reportadmin": _as_bool(row.get("reportadmin")),
            "certificateadmin": _as_bool(row.get("certificateadmin")),
        },
        {"created_at": created_at},
    )


def _import_cahandler(row: Mapping[str, Any], models: Any) -> None:
    """Insert Cahandler preserving pk."""
    created_at = _parse_datetime(row.get("created_at"))
    _save_with_timestamps(
        models.Cahandler,
        {
            "id": int(row["id"]),
            "name": _as_str(row.get("name")),
            "value1": _as_str(row.get("value1")),
            "value2": _as_str(row.get("value2")),
        },
        {"created_at": created_at},
    )


def _import_housekeeping_row(row: Mapping[str, Any], models: Any) -> None:
    """Insert/merge Housekeeping; never silently overwrite dbversion."""
    name = _as_str(row.get("name"))
    value = _as_str(row.get("value"))
    modified_at = _parse_datetime(row.get("modified_at"))
    row_id = int(row["id"])

    if name == "dbversion":
        if value != __dbversion__:
            raise MigrationError(
                f"housekeeping dbversion {value!r} != __dbversion__ {__dbversion__!r}; "
                "refuse import (never downgrade silently)"
            )
        existing = models.Housekeeping.objects.filter(name="dbversion").first()
        if existing is not None:
            if existing.value == __dbversion__:
                return
            # Django drifted; dump matches tool version — repair via ORM.
            models.Housekeeping.objects.filter(pk=existing.pk).update(
                value=value,
                **({"modified_at": modified_at} if modified_at is not None else {}),
            )
            return
        _save_with_timestamps(
            models.Housekeeping,
            {"id": row_id, "name": name, "value": value},
            {"modified_at": modified_at},
        )
        return

    _save_with_timestamps(
        models.Housekeeping,
        {"id": row_id, "name": name, "value": value},
        {"modified_at": modified_at},
    )


def _import_nonce(row: Mapping[str, Any], models: Any) -> None:
    """Insert optional Nonce row."""
    created_at = _parse_datetime(row.get("created_at"))
    _save_with_timestamps(
        models.Nonce,
        {"id": int(row["id"]), "nonce": _as_str(row.get("nonce"))},
        {"created_at": created_at},
    )


_IMPORT_HANDLERS = {
    "account": _import_account,
    "orders": _import_order,
    "authorization": _import_authorization,
    "challenge": _import_challenge,
    "certificate": _import_certificate,
    "cliaccount": _import_cliaccount,
    "cahandler": _import_cahandler,
    "housekeeping": _import_housekeeping_row,
    "nonce": _import_nonce,
}


def import_dump(
    dump: Mapping[str, Any],
    *,
    wipe: bool = False,
    dry_run: bool = False,
) -> Dict[str, int]:
    """Import dump tables into Django via ORM. Returns imported counts per dump key."""
    from django.db import transaction

    setup_django_orm()
    _vlog(
        "import: validating dump "
        f"(schema_version={dump.get('meta', {}).get('schema_version')!r}, "
        f"dbversion={dump.get('meta', {}).get('dbversion')!r})"
    )
    _validate_dump_for_import(dump)
    assert_django_status_fixture(auto_seed=not dry_run)
    _vlog("import: Django Status fixture validated")

    tables = dump["tables"]
    include_nonces = bool(dump.get("meta", {}).get("include_nonces"))

    if target_is_nonempty():
        if not wipe:
            raise MigrationError(
                "target ACME tables are not empty; re-run with --wipe or wipe first"
            )
        _vlog("import: wiping non-empty target ACME tables")
        wipe_acme_data(dry_run=dry_run)

    imported: Dict[str, int] = {key: 0 for key in IMPORT_TABLE_ORDER}
    # status is never imported
    imported["status"] = 0

    if dry_run:
        for key in IMPORT_TABLE_ORDER:
            if key == "nonce" and not include_nonces:
                imported[key] = 0
                continue
            imported[key] = len(tables.get(key, []))
            _vlog(f"import dry-run: would import {key}: {imported[key]} row(s)")
        return imported

    models = _django_models()
    try:
        with transaction.atomic():
            for key in IMPORT_TABLE_ORDER:
                if key == "nonce" and not include_nonces:
                    continue
                handler = _IMPORT_HANDLERS[key]
                rows = tables.get(key, [])
                _vlog(f"import: writing {key}: {len(rows)} row(s)")
                for row in rows:
                    handler(row, models)
                    imported[key] += 1
    except MigrationError:
        raise
    except Exception as exc:  # noqa: BLE001 — map ORM/integrity errors
        raise MigrationError(f"import failed: {exc}") from exc

    return imported


def cmd_export(args: argparse.Namespace) -> int:
    """Handle ``export`` subcommand. Returns process exit code."""
    db_path = Path(args.db)
    out_path = Path(args.out)
    try:
        _vlog(f"export: include_nonces={bool(args.include_nonces)}")
        dump = build_dump(db_path, include_nonces=bool(args.include_nonces))
        write_dump(dump, out_path)
        _vlog(f"export: wrote {out_path.resolve()}")
        print_summary(dump["tables"], prefix="export summary")
        print(f"wrote dump: {out_path.resolve()}")
        return 0
    except ExportError as exc:
        print(f"export failed: {exc}", file=sys.stderr)
        return 1
    except sqlite3.Error as exc:
        print(f"export failed: sqlite error: {exc}", file=sys.stderr)
        return 1


def cmd_wipe(args: argparse.Namespace) -> int:
    """Handle ``wipe`` subcommand. Returns process exit code."""
    if not args.yes:
        print(
            "wipe failed: refusing to wipe without --yes",
            file=sys.stderr,
        )
        return 1
    try:
        setup_django_orm()
        deleted = wipe_acme_data(dry_run=False)
        print_wipe_summary(deleted)
        return 0
    except MigrationError as exc:
        print(f"wipe failed: {exc}", file=sys.stderr)
        return 1


def cmd_import(args: argparse.Namespace) -> int:
    """Handle ``import`` subcommand. Returns process exit code."""
    dump_path = Path(args.dump)
    try:
        setup_django_orm()
        dump = load_dump(dump_path)
        _vlog(
            f"import: dump={dump_path.resolve()} "
            f"wipe={bool(args.wipe)} dry_run={bool(args.dry_run)}"
        )
        imported = import_dump(
            dump,
            wipe=bool(args.wipe),
            dry_run=bool(args.dry_run),
        )
        # Re-shape counts for print_summary (dump-key → label map).
        tables_for_summary = {
            key: [None] * imported.get(key, 0) for key, _label in SUMMARY_KEYS
        }
        prefix = "import dry-run summary" if args.dry_run else "import summary"
        print_summary(tables_for_summary, prefix=prefix)
        if args.dry_run:
            print("dry-run: no changes written")
        else:
            print(f"imported dump: {dump_path.resolve()}")
        return 0
    except MigrationError as exc:
        print(f"import failed: {exc}", file=sys.stderr)
        return 1


def _normalize_check_value(table: str, field: str, value: Any) -> Any:
    """Normalize values for deterministic dump/source/Django comparisons."""
    if field in NONE_EQ_ZERO_FIELDS.get(table, ()):
        if value is None or value == "":
            return 0
        if isinstance(value, str) and value.strip().lower() == "none":
            return 0
    if field in EMPTY_EQ_NONE_FIELDS.get(table, ()) and value is None:
        return ""
    if field in BOOL_CHECK_FIELDS.get(table, ()):
        return _as_bool(value)
    if field in INT_CHECK_FIELDS.get(table, ()):
        if value is None or value == "":
            return None
        return int(value)
    return value


def _canonicalize_rows(
    table: str, rows: Sequence[Mapping[str, Any]]
) -> Dict[int, Dict[str, Any]]:
    """Index table rows by id with normalized compare fields."""
    canonical: Dict[int, Dict[str, Any]] = {}
    fields = CHECK_FIELDS[table]
    for row in rows:
        if "id" not in row or row["id"] is None:
            raise MigrationError(f"{table} row missing required id for check")
        row_id = int(row["id"])
        entry: Dict[str, Any] = {}
        for field in fields:
            entry[field] = _normalize_check_value(table, field, row.get(field))
        canonical[row_id] = entry
    return canonical


def _diff_rows(
    table: str,
    left_rows: Sequence[Mapping[str, Any]],
    right_rows: Sequence[Mapping[str, Any]],
    *,
    left_label: str,
    right_label: str,
) -> List[str]:
    """Return mismatch lines between two row collections for a table."""
    mismatches: List[str] = []
    left = _canonicalize_rows(table, left_rows)
    right = _canonicalize_rows(table, right_rows)

    if len(left) != len(right):
        mismatches.append(
            f"{table}: count mismatch ({left_label}={len(left)} != {right_label}={len(right)})"
        )

    left_ids = set(left.keys())
    right_ids = set(right.keys())
    missing = sorted(left_ids - right_ids)
    extra = sorted(right_ids - left_ids)
    if missing:
        mismatches.append(
            f"{table}: ids missing in {right_label}: {missing[:5]}"
        )
    if extra:
        mismatches.append(
            f"{table}: ids unexpected in {right_label}: {extra[:5]}"
        )

    for row_id in sorted(left_ids & right_ids):
        left_row = left[row_id]
        right_row = right[row_id]
        for field in CHECK_FIELDS[table]:
            if left_row.get(field) != right_row.get(field):
                mismatches.append(
                    f"{table}.id={row_id} field {field}: "
                    f"{left_label}={left_row.get(field)!r} != {right_label}={right_row.get(field)!r}"
                )
                break
    return mismatches


def _source_only_certificate_diagnostics(
    dump_rows: Sequence[Mapping[str, Any]],
    source_rows: Sequence[Mapping[str, Any]],
    source_order_rows: Sequence[Mapping[str, Any]],
) -> List[str]:
    """Explain why certificate ids exist in source-db but not in dump."""
    diagnostics: List[str] = []
    dump_ids = set(_canonicalize_rows("certificate", dump_rows).keys())
    source_ids = set(_canonicalize_rows("certificate", source_rows).keys())
    extra_ids = sorted(source_ids - dump_ids)
    if not extra_ids:
        return diagnostics

    source_by_id = {int(row["id"]): row for row in source_rows if row.get("id") is not None}
    source_order_ids = {int(row["id"]) for row in source_order_rows if row.get("id") is not None}

    for cert_id in extra_ids[:10]:
        row = source_by_id.get(cert_id, {})
        order_id = row.get("order_id")
        if order_id is None:
            diagnostics.append(
                f"dump-vs-source-db detail: certificate.id={cert_id} excluded from dump: NULL order_id"
            )
            continue
        try:
            parsed_order_id = int(order_id)
        except (TypeError, ValueError):
            diagnostics.append(
                f"dump-vs-source-db detail: certificate.id={cert_id} excluded from dump: invalid order_id={order_id!r}"
            )
            continue
        if parsed_order_id not in source_order_ids:
            diagnostics.append(
                f"dump-vs-source-db detail: certificate.id={cert_id} excluded from dump: dangling order_id={parsed_order_id}"
            )
            continue
        diagnostics.append(
            f"dump-vs-source-db detail: certificate.id={cert_id} present in source-db but not in dump"
        )
    return diagnostics


def _tables_for_check(dump: Mapping[str, Any], *, include_nonces: bool) -> Tuple[str, ...]:
    """Check table set derived from dump settings."""
    base = (
        "status",
        "account",
        "orders",
        "authorization",
        "challenge",
        "certificate",
        "cliaccount",
        "cahandler",
        "housekeeping",
    )
    if include_nonces:
        return base + ("nonce",)
    return base


def _django_rows_for_table(table: str) -> List[Dict[str, Any]]:
    """Fetch table rows from Django models for comparison."""
    models = _django_models()
    model = getattr(models, CHECK_MODEL_MAP[table])
    rows = list(model.objects.values(*CHECK_FIELDS[table]))
    if rows and "id" in rows[0]:
        rows.sort(key=lambda row: int(row["id"]))
    return rows


def _source_rows_for_table(db_path: Path, table: str) -> List[Dict[str, Any]]:
    """Fetch table rows from a source WSGI SQLite DB."""
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    try:
        return _fetch_table(conn, table)
    finally:
        conn.close()


def run_check(
    dump: Mapping[str, Any], *, source_db: Optional[Path] = None
) -> List[str]:
    """Compare dump rows against Django and optional source SQLite."""
    _validate_dump_for_import(dump)
    assert_django_status_fixture(auto_seed=False)
    tables = dump["tables"]
    include_nonces = bool(dump.get("meta", {}).get("include_nonces"))
    check_tables = _tables_for_check(dump, include_nonces=include_nonces)
    mismatches: List[str] = []

    for table in check_tables:
        dump_rows = tables.get(table, [])
        django_rows = _django_rows_for_table(table)
        _vlog(
            f"check: comparing {table}: dump={len(dump_rows)} django={len(django_rows)}"
        )
        for mismatch in _diff_rows(
            table,
            dump_rows,
            django_rows,
            left_label="dump",
            right_label="django",
        ):
            mismatches.append(f"dump-vs-django: {mismatch}")

    if source_db is not None:
        _vlog(f"check: comparing dump against source-db {source_db.resolve()}")
        for table in check_tables:
            dump_rows = tables.get(table, [])
            source_rows = _source_rows_for_table(source_db, table)
            _vlog(
                f"check: comparing {table}: dump={len(dump_rows)} source-db={len(source_rows)}"
            )
            for mismatch in _diff_rows(
                table,
                dump_rows,
                source_rows,
                left_label="dump",
                right_label="source-db",
            ):
                mismatches.append(f"dump-vs-source-db: {mismatch}")
            if table == "certificate":
                source_order_rows = _source_rows_for_table(source_db, "orders")
                mismatches.extend(
                    _source_only_certificate_diagnostics(
                        dump_rows, source_rows, source_order_rows
                    )
                )

    return mismatches


def cmd_check(args: argparse.Namespace) -> int:
    """Handle ``check`` subcommand. Returns CI-friendly exit codes."""
    dump_path = Path(args.dump)
    source_db = Path(args.source_db) if args.source_db else None
    try:
        setup_django_orm()
        dump = load_dump(dump_path)
        mismatches = run_check(dump, source_db=source_db)
        if mismatches:
            for line in mismatches:
                print(f"check mismatch: {line}", file=sys.stderr)
            return CHECK_EXIT_MISMATCH
        if source_db is not None:
            print(
                "check passed: dump matches Django and source-db"
            )
        else:
            print("check passed: dump matches Django")
        return CHECK_EXIT_OK
    except (MigrationError, sqlite3.Error, OSError) as exc:
        print(f"check failed: {exc}", file=sys.stderr)
        return CHECK_EXIT_ERROR


def build_parser() -> argparse.ArgumentParser:
    """Build CLI argument parser (export / wipe / import / check)."""
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        default=False,
        help="Verbose progress logging to stderr",
    )

    parser = argparse.ArgumentParser(
        prog="a2c-wsgi2django",
        description="Migrate ACME data from WSGI SQLite to Django (JSON dump).",
        parents=[common],
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"a2c-wsgi2django {TOOL_VERSION} (a2c {__version__})",
    )
    sub = parser.add_subparsers(dest="command")

    export_p = sub.add_parser(
        "export",
        parents=[common],
        help="Export WSGI acme_srv.db to a portable JSON dump",
    )
    export_p.add_argument(
        "--db",
        required=True,
        help="Path to WSGI SQLite database (acme_srv.db)",
    )
    export_p.add_argument(
        "--out",
        required=True,
        help="Output JSON dump path",
    )
    export_p.add_argument(
        "--cfg",
        default=None,
        help="Optional acme_srv.cfg (unused for export; reserved)",
    )
    export_p.add_argument(
        "--include-nonces",
        action="store_true",
        default=False,
        help="Include ephemeral nonce rows in the dump",
    )
    export_p.set_defaults(func=cmd_export)

    wipe_p = sub.add_parser(
        "wipe",
        parents=[common],
        help="Delete ACME Django model rows (keeps Status and dbversion)",
    )
    wipe_p.add_argument(
        "--yes",
        action="store_true",
        default=False,
        help="Confirm wipe (required)",
    )
    wipe_p.set_defaults(func=cmd_wipe)

    import_p = sub.add_parser(
        "import",
        parents=[common],
        help="Import a JSON dump into Django via the ORM",
    )
    import_p.add_argument(
        "--dump",
        required=True,
        help="Path to a2c-wsgi dump JSON",
    )
    import_p.add_argument(
        "--wipe",
        action="store_true",
        default=False,
        help="Wipe migratable ACME rows before import",
    )
    import_p.add_argument(
        "--dry-run",
        action="store_true",
        default=False,
        help="Validate and report counts without writing",
    )
    import_p.set_defaults(func=cmd_import)

    check_p = sub.add_parser(
        "check",
        parents=[common],
        help="Compare dump with Django data and optional source WSGI SQLite",
    )
    check_p.add_argument(
        "--dump",
        required=True,
        help="Path to a2c-wsgi dump JSON",
    )
    check_p.add_argument(
        "--source-db",
        default=None,
        help="Optional path to source WSGI SQLite (acme_srv.db) for extra checks",
    )
    check_p.set_defaults(func=cmd_check)
    return parser


def _extract_verbose(argv: Sequence[str]) -> Tuple[List[str], bool]:
    """Strip global -v/--verbose flags (argparse subparsers miss pre-command opts)."""
    verbose = False
    filtered: List[str] = []
    for arg in argv:
        if arg in ("-v", "--verbose"):
            verbose = True
        else:
            filtered.append(arg)
    return filtered, verbose


def main(argv: Optional[Sequence[str]] = None) -> int:
    """CLI entry point."""
    parser = build_parser()
    raw_argv = list(argv) if argv is not None else sys.argv[1:]
    parsed_argv, pre_verbose = _extract_verbose(raw_argv)
    args = parser.parse_args(parsed_argv)
    if not getattr(args, "command", None):
        parser.error("command required (export, wipe, import, check)")
    set_verbose(pre_verbose or bool(getattr(args, "verbose", False)))
    return int(args.func(args))


if __name__ == "__main__":
    sys.exit(main())
