#!/usr/bin/env python3
"""Dump an XCA SQLite database as MariaDB- or PostgreSQL-compatible SQL.

GitHub-hosted sqlite3 is often 3.45.x: `.dump` emits `unistr()` / `char(10)` and
has no `--escape off`. Neither MariaDB nor PostgreSQL accept that dump as-is.
"""

from __future__ import annotations

import argparse
import sqlite3
import sys
from typing import Any, Optional, TextIO


def sql_literal(value: Any, dialect: str = "mysql") -> str:
    """Render a Python value as an SQL literal (UTF-8 strings, hex blobs)."""
    if value is None:
        return "NULL"
    if isinstance(value, bytes):
        if dialect == "postgresql":
            return r"'\x" + value.hex() + "'"
        return "X'" + value.hex() + "'"
    if isinstance(value, bool):
        return "1" if value else "0"
    if isinstance(value, (int, float)):
        return str(value)
    return "'" + str(value).replace("'", "''") + "'"


def quote_ident(name: str, dialect: str) -> str:
    """Quote an identifier for *dialect*.

    PostgreSQL folds unquoted CREATE TABLE names to lowercase, but quoted
    identifiers are case-sensitive. Quote the folded name so INSERTs match
    sqlite_master DDL and reserved words such as ``public`` stay valid.
    """
    ident = name.replace('"', '""')
    if dialect == "postgresql":
        ident = ident.lower()
    return f'"{ident}"'


def dump_xca_sqlite(xdb_path: str, dialect: str, out: TextIO) -> None:
    """Write CREATE/INSERT/VIEW/INDEX statements for *xdb_path* to *out*."""
    if dialect not in ("mysql", "postgresql"):
        raise ValueError(f"unsupported dialect {dialect}")

    con = sqlite3.connect(f"file:{xdb_path}?mode=ro", uri=True)
    con.row_factory = sqlite3.Row
    try:
        if dialect == "mysql":
            out.write("SET SESSION SQL_MODE='ANSI';\n")
            out.write("SET NAMES utf8mb4;\n")
            out.write("SET FOREIGN_KEY_CHECKS=0;\n")

        objects = con.execute(
            "SELECT type, name, sql FROM sqlite_master "
            "WHERE sql IS NOT NULL AND name NOT LIKE 'sqlite_%' "
            "ORDER BY rowid"
        ).fetchall()
        for type_, name, sql in objects:
            statement = sql.rstrip().rstrip(";") + ";\n"
            out.write(statement)
            if type_ != "table":
                continue
            col_info = con.execute(f'PRAGMA table_info("{name}")').fetchall()
            columns = [row["name"] for row in col_info]
            quoted_cols = ", ".join(quote_ident(col, dialect) for col in columns)
            table_ident = quote_ident(name, dialect)
            for row in con.execute(f'SELECT * FROM "{name}"'):
                values = ", ".join(sql_literal(row[col], dialect) for col in columns)
                out.write(
                    f"INSERT INTO {table_ident} ({quoted_cols}) VALUES ({values});\n"
                )

        if dialect == "mysql":
            out.write("SET FOREIGN_KEY_CHECKS=1;\n")
    finally:
        con.close()


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("xdb", help="Path to the XCA SQLite database")
    parser.add_argument(
        "--dialect",
        choices=("mysql", "postgresql"),
        required=True,
        help="Target SQL dialect",
    )
    parser.add_argument(
        "-o",
        "--output",
        default="-",
        help="Output file (default: stdout)",
    )
    args = parser.parse_args(argv)

    if args.output == "-":
        dump_xca_sqlite(args.xdb, args.dialect, sys.stdout)
        return 0
    with open(args.output, "w", encoding="utf-8", newline="\n") as handle:
        dump_xca_sqlite(args.xdb, args.dialect, handle)
    return 0


if __name__ == "__main__":
    sys.exit(main())
