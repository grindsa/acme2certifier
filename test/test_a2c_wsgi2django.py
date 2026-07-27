#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""pytest for a2c-wsgi2django export (Phase 1; no Django)."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Tuple

import pytest

from acme2certifier.acme_srv.version import __dbversion__, __version__
from acme2certifier.tools import a2c_wsgi2django as migrator


STATUS_ROWS: List[Tuple[int, str]] = [
    (1, "invalid"),
    (2, "pending"),
    (3, "ready"),
    (4, "processing"),
    (5, "valid"),
    (6, "expired"),
    (7, "deactivated"),
    (8, "revoked"),
]


def _create_wsgi_schema(conn: sqlite3.Connection) -> None:
    """Create a minimal current-schema WSGI SQLite DB."""
    cur = conn.cursor()
    cur.execute(
        'CREATE TABLE "status" ('
        '"id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, '
        '"name" varchar(15) UNIQUE NOT NULL)'
    )
    cur.executemany(
        "INSERT INTO status(id, name) VALUES(?, ?)",
        STATUS_ROWS,
    )
    cur.execute(
        'CREATE TABLE "nonce" ('
        '"id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, '
        '"nonce" varchar(30) NOT NULL, '
        '"created_at" TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL)'
    )
    cur.execute(
        'CREATE TABLE "account" ('
        '"id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, '
        '"name" varchar(15) NOT NULL UNIQUE, '
        '"alg" varchar(10) NOT NULL, '
        '"jwk" TEXT UNIQUE NOT NULL, '
        '"contact" TEXT NOT NULL, '
        '"eab_kid" varchar(255) DEFAULT \'\', '
        '"status_id" integer NOT NULL REFERENCES "status" ("id") DEFAULT 5, '
        '"created_at" TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL)'
    )
    cur.execute(
        'CREATE TABLE "cliaccount" ('
        '"id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, '
        '"name" varchar(15) NOT NULL UNIQUE, '
        '"jwk" TEXT UNIQUE NOT NULL, '
        '"contact" TEXT NOT NULL, '
        '"cliadmin" INT, '
        '"reportadmin" INT, '
        '"certificateadmin" INT, '
        '"created_at" TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL)'
    )
    cur.execute(
        'CREATE TABLE "orders" ('
        '"id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, '
        '"name" varchar(15) UNIQUE NOT NULL, '
        '"notbefore" integer DEFAULT 0, '
        '"notafter" integer DEFAULT 0, '
        '"identifiers" text NOT NULL, '
        '"account_id" integer NOT NULL REFERENCES "account" ("id"), '
        '"profile" varchar(64), '
        '"status_id" integer NOT NULL REFERENCES "status" ("id") DEFAULT 2, '
        '"expires" integer NOT NULL, '
        '"created_at" TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL)'
    )
    cur.execute(
        'CREATE TABLE "authorization" ('
        '"id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, '
        '"name" varchar(15) NOT NULL UNIQUE, '
        '"order_id" integer NOT NULL REFERENCES "orders" ("id"), '
        '"type" varchar(5) NOT NULL, '
        '"value" text NOT NULL, '
        '"expires" integer, '
        '"token" varchar(64), '
        '"status_id" integer NOT NULL REFERENCES "status" ("id") DEFAULT 2, '
        '"created_at" TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL)'
    )
    cur.execute(
        'CREATE TABLE "challenge" ('
        '"id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, '
        '"name" varchar(15) NOT NULL UNIQUE, '
        '"token" varchar(64), '
        '"authorization_id" integer NOT NULL REFERENCES "authorization" ("id"), '
        '"expires" integer, '
        '"type" varchar(15) NOT NULL, '
        '"keyauthorization" varchar(128), '
        '"source" varchar(128), '
        '"status_id" integer NOT NULL REFERENCES "status" ("id"), '
        '"validated" integer DEFAULT 0, '
        '"validation_error" text, '
        '"created_at" TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL)'
    )
    cur.execute(
        'CREATE TABLE "certificate" ('
        '"id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, '
        '"name" varchar(15) NOT NULL UNIQUE, '
        '"cert" text, '
        '"cert_raw" text, '
        '"error" text, '
        '"order_id" integer NOT NULL REFERENCES "orders" ("id"), '
        '"csr" text NOT NULL, '
        '"poll_identifier" text, '
        '"header_info" text, '
        '"created_at" TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL, '
        '"renewal_info" text, '
        '"aki" text, '
        '"serial" text, '
        '"issue_uts" integer DEFAULT 0, '
        '"expire_uts" integer DEFAULT 0, '
        '"replaced" integer DEFAULT 0)'
    )
    cur.execute(
        'CREATE TABLE "housekeeping" ('
        '"id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, '
        '"name" varchar(30) NOT NULL UNIQUE, '
        '"value" text, '
        '"modified_at" TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL)'
    )
    cur.execute(
        'CREATE TABLE "cahandler" ('
        '"id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, '
        '"name" varchar(15) NOT NULL UNIQUE, '
        '"value1" text, '
        '"value2" text, '
        '"created_at" TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL)'
    )
    cur.execute(
        "INSERT INTO housekeeping (name, value) VALUES (?, ?)",
        ("dbversion", __dbversion__),
    )
    conn.commit()


def _seed_fixture_data(conn: sqlite3.Connection) -> None:
    """Insert a minimal connected ACME graph for export assertions."""
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO account (id, name, alg, jwk, contact, eab_kid, status_id, created_at) "
        "VALUES (1, 'acctAAAA', 'ES256', '{\"kty\":\"EC\"}', 'mailto:a@example.com', "
        "'eab-1', 5, '2024-01-01 00:00:00')"
    )
    cur.execute(
        "INSERT INTO orders (id, name, notbefore, notafter, identifiers, account_id, "
        "profile, status_id, expires, created_at) "
        "VALUES (10, 'ordBBBBB', 0, 0, '[{\"type\":\"dns\",\"value\":\"ex.com\"}]', "
        "1, 'default', 5, 1700000000, '2024-01-02 00:00:00')"
    )
    cur.execute(
        "INSERT INTO authorization (id, name, order_id, type, value, expires, token, "
        "status_id, created_at) "
        "VALUES (20, 'authCCCC', 10, 'dns', 'ex.com', 1700000000, 'tok-auth', 5, "
        "'2024-01-03 00:00:00')"
    )
    cur.execute(
        "INSERT INTO challenge (id, name, token, authorization_id, expires, type, "
        "keyauthorization, source, status_id, validated, validation_error, created_at) "
        "VALUES (30, 'chalDDDD', 'tok-chal', 20, 1700000000, 'http-01', "
        "'keyauth-value', '1.2.3.4', 5, 1, NULL, '2024-01-04 00:00:00')"
    )
    cur.execute(
        "INSERT INTO certificate (id, name, cert, cert_raw, error, order_id, csr, "
        "poll_identifier, header_info, created_at, renewal_info, aki, serial, "
        "issue_uts, expire_uts, replaced) "
        "VALUES (40, 'certEEEE', '-----BEGIN CERT-----', 'rawcert', NULL, 10, "
        "'-----BEGIN CSR-----', 'poll-1', '{}', '2024-01-05 00:00:00', NULL, "
        "'aki-1', 'serial-1', 1700000100, 1700000200, 0)"
    )
    cur.execute(
        "INSERT INTO cliaccount (id, name, jwk, contact, cliadmin, reportadmin, "
        "certificateadmin, created_at) "
        "VALUES (50, 'cliFFFFF', '{\"kty\":\"RSA\"}', 'mailto:cli@example.com', "
        "1, 0, 1, '2024-01-06 00:00:00')"
    )
    cur.execute(
        "INSERT INTO cahandler (id, name, value1, value2, created_at) "
        "VALUES (60, 'cahandler1', 'v1', 'v2', '2024-01-07 00:00:00')"
    )
    cur.execute(
        "INSERT INTO nonce (id, nonce, created_at) "
        "VALUES (70, 'nonce-abc', '2024-01-08 00:00:00')"
    )
    conn.commit()


@pytest.fixture
def wsgi_db(tmp_path: Path) -> Path:
    """Build a fixture WSGI acme_srv.db under tmp_path."""
    db_path = tmp_path / "acme_srv.db"
    conn = sqlite3.connect(str(db_path))
    try:
        _create_wsgi_schema(conn)
        _seed_fixture_data(conn)
    finally:
        conn.close()
    return db_path


def test_export_builds_schema_v1_dump(wsgi_db: Path, tmp_path: Path) -> None:
    """Export produces meta + tables with expected counts and preserved PKs."""
    out = tmp_path / "dump.json"
    dump = migrator.build_dump(wsgi_db, include_nonces=False)
    migrator.write_dump(dump, out)

    loaded: Dict[str, Any] = json.loads(out.read_text(encoding="utf-8"))
    meta = loaded["meta"]
    tables = loaded["tables"]

    assert meta["schema_version"] == 1
    assert meta["tool_version"] == migrator.TOOL_VERSION
    assert meta["a2c_version"] == __version__
    assert meta["dbversion"] == __dbversion__
    assert meta["source"] == "wsgi-sqlite"
    assert meta["include_nonces"] is False
    assert Path(meta["source_path"]).resolve() == wsgi_db.resolve()
    assert meta["created_at"].endswith("Z")

    assert set(tables.keys()) == set(migrator.DUMP_TABLES)
    assert len(tables["status"]) == 8
    assert len(tables["account"]) == 1
    assert len(tables["orders"]) == 1
    assert len(tables["authorization"]) == 1
    assert len(tables["challenge"]) == 1
    assert len(tables["certificate"]) == 1
    assert len(tables["cliaccount"]) == 1
    assert len(tables["cahandler"]) == 1
    assert len(tables["housekeeping"]) == 1
    assert tables["nonce"] == []

    assert tables["account"][0]["id"] == 1
    assert tables["account"][0]["name"] == "acctAAAA"
    assert tables["orders"][0]["id"] == 10
    assert tables["orders"][0]["account_id"] == 1
    assert tables["authorization"][0]["order_id"] == 10
    assert tables["challenge"][0]["authorization_id"] == 20
    assert tables["certificate"][0]["order_id"] == 10
    assert tables["certificate"][0]["serial"] == "serial-1"
    assert tables["cliaccount"][0]["cliadmin"] == 1
    assert tables["housekeeping"][0]["name"] == "dbversion"
    assert tables["housekeeping"][0]["value"] == __dbversion__


def test_export_fk_integrity(wsgi_db: Path) -> None:
    """Dump FK ids resolve within exported parent tables."""
    dump = migrator.build_dump(wsgi_db)
    tables = dump["tables"]
    status_ids = {row["id"] for row in tables["status"]}
    account_ids = {row["id"] for row in tables["account"]}
    order_ids = {row["id"] for row in tables["orders"]}
    authz_ids = {row["id"] for row in tables["authorization"]}

    for row in tables["account"]:
        assert row["status_id"] in status_ids
    for row in tables["orders"]:
        assert row["account_id"] in account_ids
        assert row["status_id"] in status_ids
    for row in tables["authorization"]:
        assert row["order_id"] in order_ids
        assert row["status_id"] in status_ids
    for row in tables["challenge"]:
        assert row["authorization_id"] in authz_ids
        assert row["status_id"] in status_ids
    for row in tables["certificate"]:
        assert row["order_id"] in order_ids


def test_export_include_nonces(wsgi_db: Path) -> None:
    """--include-nonces populates tables.nonce and meta.include_nonces."""
    dump = migrator.build_dump(wsgi_db, include_nonces=True)
    assert dump["meta"]["include_nonces"] is True
    assert len(dump["tables"]["nonce"]) == 1
    assert dump["tables"]["nonce"][0]["nonce"] == "nonce-abc"


def test_export_cli_writes_file(wsgi_db: Path, tmp_path: Path, capsys: Any) -> None:
    """CLI export subcommand writes dump and prints summary."""
    out = tmp_path / "out" / "dump.json"
    rc = migrator.main(
        ["export", "--db", str(wsgi_db), "--out", str(out)]
    )
    assert rc == 0
    assert out.is_file()
    captured = capsys.readouterr()
    assert "export summary:" in captured.out
    assert "accounts=1" in captured.out
    assert "orders=1" in captured.out
    assert "wrote dump:" in captured.out


def test_export_fails_wrong_dbversion(tmp_path: Path) -> None:
    """Refuse export when housekeeping.dbversion mismatches __dbversion__."""
    db_path = tmp_path / "bad_version.db"
    conn = sqlite3.connect(str(db_path))
    try:
        _create_wsgi_schema(conn)
        conn.execute(
            "UPDATE housekeeping SET value = ? WHERE name = ?",
            ("0.00", "dbversion"),
        )
        conn.commit()
    finally:
        conn.close()

    with pytest.raises(migrator.ExportError, match="dbversion"):
        migrator.build_dump(db_path)

    rc = migrator.main(
        ["export", "--db", str(db_path), "--out", str(tmp_path / "x.json")]
    )
    assert rc == 1


def test_export_fails_contact_overflow(wsgi_db: Path) -> None:
    """Refuse export when Account.contact exceeds Django CharField(255)."""
    conn = sqlite3.connect(str(wsgi_db))
    try:
        conn.execute(
            "UPDATE account SET contact = ? WHERE id = 1",
            ("x" * 256,),
        )
        conn.commit()
    finally:
        conn.close()

    with pytest.raises(migrator.ExportError, match="contact length"):
        migrator.build_dump(wsgi_db)


def test_export_skips_dangling_fk_with_warning(
    wsgi_db: Path, capsys: Any
) -> None:
    """Orphan FK rows are skipped with a warning; export still succeeds."""
    conn = sqlite3.connect(str(wsgi_db))
    try:
        conn.execute("PRAGMA foreign_keys = OFF")
        conn.execute("UPDATE orders SET account_id = 999 WHERE id = 10")
        conn.commit()
    finally:
        conn.close()

    dump = migrator.build_dump(wsgi_db)
    captured = capsys.readouterr()
    assert "warning: skipping orphan orders.id=10" in captured.err
    assert "dangling account_id=999" in captured.err
    # Dependent children of the skipped order are also dropped.
    assert dump["tables"]["orders"] == []
    assert dump["tables"]["authorization"] == []
    assert dump["tables"]["challenge"] == []
    assert dump["tables"]["certificate"] == []
    assert len(dump["tables"]["account"]) == 1


def test_export_skips_certificate_with_order_id_zero(
    wsgi_db: Path, capsys: Any
) -> None:
    """certificate.order_id=0 (no matching order) is skipped, not fatal."""
    conn = sqlite3.connect(str(wsgi_db))
    try:
        conn.execute("PRAGMA foreign_keys = OFF")
        conn.execute(
            "INSERT INTO certificate (id, name, order_id, csr) "
            "VALUES (77, 'orphan-cert', 0, '')"
        )
        conn.commit()
    finally:
        conn.close()

    dump = migrator.build_dump(wsgi_db)
    captured = capsys.readouterr()
    assert "warning: skipping orphan certificate.id=77" in captured.err
    assert "dangling order_id=0" in captured.err
    cert_ids = {row["id"] for row in dump["tables"]["certificate"]}
    assert 77 not in cert_ids
    assert 40 in cert_ids


def test_export_fails_status_name_mismatch(wsgi_db: Path) -> None:
    """Refuse export when status PK/name map drifts from fixture."""
    conn = sqlite3.connect(str(wsgi_db))
    try:
        conn.execute("UPDATE status SET name = ? WHERE id = 1", ("bogus",))
        conn.commit()
    finally:
        conn.close()

    with pytest.raises(migrator.ExportError, match="status PK 1"):
        migrator.build_dump(wsgi_db)


def test_summary_counts(wsgi_db: Path) -> None:
    """summary_counts maps dump keys to operator-facing labels."""
    dump = migrator.build_dump(wsgi_db)
    counts = migrator.summary_counts(dump["tables"])
    assert counts["accounts"] == 1
    assert counts["orders"] == 1
    assert counts["authorizations"] == 1
    assert counts["challenges"] == 1
    assert counts["certificates"] == 1
    assert counts["cliaccounts"] == 1
    assert counts["nonces"] == 0


def test_resolve_length_limits_prefers_django_when_available() -> None:
    """Live model max_length wins over FALLBACK_LENGTH_LIMITS."""
    live = {"housekeeping": {"value": 300}, "account": {"contact": 255}}
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(migrator, "length_limits_from_django", lambda: live)
        assert migrator.resolve_length_limits() == live


def test_resolve_length_limits_fallback_without_django() -> None:
    """Without Django models, frozen fallback limits are used."""
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(migrator, "length_limits_from_django", lambda: None)
        limits = migrator.resolve_length_limits()
        assert limits == migrator.FALLBACK_LENGTH_LIMITS
        assert limits["housekeeping"]["value"] == 30


def test_export_respects_resolved_housekeeping_limit(wsgi_db: Path) -> None:
    """Long housekeeping.value exports when model limit allows it."""
    long_value = "x" * 299
    conn = sqlite3.connect(str(wsgi_db))
    try:
        conn.execute(
            "INSERT INTO housekeeping (name, value) VALUES (?, ?)",
            ("profiles", long_value),
        )
        conn.commit()
    finally:
        conn.close()

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(
            migrator,
            "resolve_length_limits",
            lambda: {
                **migrator.FALLBACK_LENGTH_LIMITS,
                "housekeeping": {"value": 300},
            },
        )
        dump = migrator.build_dump(wsgi_db)

    names = {row["name"]: row["value"] for row in dump["tables"]["housekeeping"]}
    assert names["profiles"] == long_value
