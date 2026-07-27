#!/usr/bin/python3
"""Migrate ACME data from WSGI SQLite to Django ORM via a portable JSON dump."""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from acme2certifier.acme_srv.version import __dbversion__, __version__

SCHEMA_VERSION = 1
TOOL_VERSION = "0.1.0"

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


class ExportError(Exception):
    """Raised when WSGI export validation fails."""


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

    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    try:
        dbversion = _read_dbversion(conn)
        _validate_dbversion(dbversion)

        tables: Dict[str, List[Dict[str, Any]]] = {}
        for name in DUMP_TABLES:
            if name == "nonce" and not include_nonces:
                tables[name] = []
                continue
            tables[name] = _fetch_table(conn, name)

        _validate_status(tables["status"])
        _drop_orphan_rows(tables)
        _validate_lengths(tables)
        _validate_required(tables)

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


def print_summary(tables: Mapping[str, Sequence[Any]], stream: Any = None) -> None:
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
    print("export summary: " + ", ".join(parts), file=stream)


def write_dump(dump: Mapping[str, Any], out_path: Path) -> None:
    """Write dump JSON to *out_path* (UTF-8, indented)."""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as handle:
        json.dump(dump, handle, indent=2, ensure_ascii=False, sort_keys=False)
        handle.write("\n")


def cmd_export(args: argparse.Namespace) -> int:
    """Handle ``export`` subcommand. Returns process exit code."""
    db_path = Path(args.db)
    out_path = Path(args.out)
    try:
        dump = build_dump(db_path, include_nonces=bool(args.include_nonces))
        write_dump(dump, out_path)
        print_summary(dump["tables"])
        print(f"wrote dump: {out_path.resolve()}")
        return 0
    except ExportError as exc:
        print(f"export failed: {exc}", file=sys.stderr)
        return 1
    except sqlite3.Error as exc:
        print(f"export failed: sqlite error: {exc}", file=sys.stderr)
        return 1


def build_parser() -> argparse.ArgumentParser:
    """Build CLI argument parser (export only in Phase 1)."""
    parser = argparse.ArgumentParser(
        prog="a2c-wsgi2django",
        description="Migrate ACME data from WSGI SQLite to Django (JSON dump).",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"a2c-wsgi2django {TOOL_VERSION} (a2c {__version__})",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    export_p = sub.add_parser(
        "export",
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
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    """CLI entry point."""
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    return int(args.func(args))


if __name__ == "__main__":
    sys.exit(main())
