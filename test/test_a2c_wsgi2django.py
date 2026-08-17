#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""pytest for a2c-wsgi2django export / wipe / import."""

from __future__ import annotations

import json
import sqlite3
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Mapping, Sequence, Tuple

import pytest

# Configure Django before migrator length introspection can lock :memory: settings.
_TEST_DJANGO_DB = Path(tempfile.mkstemp(suffix="-a2c-wsgi2django.sqlite3")[1])


def _bootstrap_django() -> None:
    """Configure Django sqlite test DB once for this module."""
    import django
    from django.conf import settings

    if settings.configured:
        return
    settings.configure(
        INSTALLED_APPS=[
            "django.contrib.contenttypes",
            "django.contrib.auth",
            "acme2certifier.django_app.apps.AcmeSrvConfig",
        ],
        DATABASES={
            "default": {
                "ENGINE": "django.db.backends.sqlite3",
                "NAME": str(_TEST_DJANGO_DB),
            }
        },
        USE_TZ=True,
        SECRET_KEY="test-a2c-wsgi2django",
        DEFAULT_AUTO_FIELD="django.db.models.AutoField",
        TIME_ZONE="UTC",
    )
    django.setup()


_bootstrap_django()

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


def test_001_parse_iso_datetime_python36_compatible() -> None:
    """ISO parsing must not rely on datetime.fromisoformat (added in 3.7)."""
    from datetime import datetime

    assert migrator._parse_iso_datetime("2024-01-15T10:20:30") == datetime(
        2024, 1, 15, 10, 20, 30
    )
    assert migrator._parse_iso_datetime("2024-01-15T10:20:30.123456") == datetime(
        2024, 1, 15, 10, 20, 30, 123456
    )
    assert migrator._parse_iso_datetime("2024-01-15T10:20:30Z").utcoffset() is not None
    assert (
        migrator._parse_iso_datetime("2024-01-15T10:20:30+00:00").utcoffset()
        is not None
    )


def test_002_main_requires_subcommand_python36_compatible() -> None:
    """argparse subparsers(required=...) needs Python 3.7+; enforce manually."""
    with pytest.raises(SystemExit):
        migrator.main([])


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
        "\"eab_kid\" varchar(255) DEFAULT '', "
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
        'VALUES (10, \'ordBBBBB\', 0, 0, \'[{"type":"dns","value":"ex.com"}]\', '
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


@pytest.fixture(scope="module", autouse=True)
def _migrate_django_db() -> None:
    """Apply migrations and load Status (+ dbversion) fixture once."""
    from django.core.management import call_command

    call_command("migrate", interactive=False, verbosity=0, run_syncdb=True)
    call_command("loaddata", "status", verbosity=0)


@pytest.fixture
def clean_django_db() -> None:
    """Wipe migratable ACME rows; keep Status and housekeeping.dbversion."""
    from django.core.management import call_command

    migrator.wipe_acme_data(dry_run=False)
    from acme2certifier.django_app.models import Housekeeping, Status

    if Status.objects.count() != 8:
        call_command("loaddata", "status", verbosity=0)
    assert Status.objects.count() == 8
    assert Housekeeping.objects.filter(name="dbversion").exists()


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


@pytest.fixture
def sample_dump(wsgi_db: Path) -> Dict[str, Any]:
    """Export fixture WSGI DB to an in-memory dump dict."""
    return migrator.build_dump(wsgi_db, include_nonces=False)


def test_003_export_builds_schema_v1_dump(wsgi_db: Path, tmp_path: Path) -> None:
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


def test_004_export_fk_integrity(wsgi_db: Path) -> None:
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


def test_005_export_include_nonces(wsgi_db: Path) -> None:
    """--include-nonces populates tables.nonce and meta.include_nonces."""
    dump = migrator.build_dump(wsgi_db, include_nonces=True)
    assert dump["meta"]["include_nonces"] is True
    assert len(dump["tables"]["nonce"]) == 1
    assert dump["tables"]["nonce"][0]["nonce"] == "nonce-abc"


def test_006_export_cli_writes_file(wsgi_db: Path, tmp_path: Path, capsys: Any) -> None:
    """CLI export subcommand writes dump and prints summary."""
    out = tmp_path / "out" / "dump.json"
    rc = migrator.main(["export", "--db", str(wsgi_db), "--out", str(out)])
    assert rc == 0
    assert out.is_file()
    captured = capsys.readouterr()
    assert "export summary:" in captured.out
    assert "accounts=1" in captured.out
    assert "orders=1" in captured.out
    assert "wrote dump:" in captured.out


def test_007_export_fails_wrong_dbversion(tmp_path: Path) -> None:
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


def test_008_export_fails_contact_overflow(wsgi_db: Path) -> None:
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


def test_009_export_skips_dangling_fk_with_warning(wsgi_db: Path, capsys: Any) -> None:
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


def test_010_export_skips_certificate_with_order_id_zero(
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


def test_011_export_fails_status_name_mismatch(wsgi_db: Path) -> None:
    """Refuse export when status PK/name map drifts from fixture."""
    conn = sqlite3.connect(str(wsgi_db))
    try:
        conn.execute("UPDATE status SET name = ? WHERE id = 1", ("bogus",))
        conn.commit()
    finally:
        conn.close()

    with pytest.raises(migrator.ExportError, match="status PK 1"):
        migrator.build_dump(wsgi_db)


def test_012_summary_counts(wsgi_db: Path) -> None:
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


def test_013_resolve_length_limits_prefers_django_when_available() -> None:
    """Live model max_length wins over FALLBACK_LENGTH_LIMITS."""
    live = {"housekeeping": {"value": 300}, "account": {"contact": 255}}
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(migrator, "length_limits_from_django", lambda: live)
        assert migrator.resolve_length_limits() == live


def test_014_resolve_length_limits_fallback_without_django() -> None:
    """Without Django models, frozen fallback limits are used."""
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(migrator, "length_limits_from_django", lambda: None)
        limits = migrator.resolve_length_limits()
        assert limits == migrator.FALLBACK_LENGTH_LIMITS
        assert limits["housekeeping"]["value"] == 30


def test_015_export_respects_resolved_housekeeping_limit(wsgi_db: Path) -> None:
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


def test_016_wipe_requires_yes(capsys: Any) -> None:
    """CLI wipe without --yes refuses and exits 1."""
    rc = migrator.main(["wipe"])
    assert rc == 1
    assert "refusing to wipe without --yes" in capsys.readouterr().err


def test_017_wipe_keeps_status_and_dbversion(clean_django_db: None) -> None:
    """Wipe deletes ACME rows but leaves Status fixture and dbversion."""
    from acme2certifier.django_app.models import Account, Housekeeping, Status

    Account.objects.create(
        id=99,
        name="tmpacct",
        alg="ES256",
        jwk="{}",
        contact="mailto:t@example.com",
        status_id=5,
    )
    Housekeeping.objects.create(name="profiles", value="[]")
    assert Account.objects.count() == 1

    deleted = migrator.wipe_acme_data(dry_run=False)
    assert deleted["account"] == 1
    assert deleted["housekeeping"] == 1
    assert Account.objects.count() == 0
    assert Status.objects.count() == 8
    assert list(Status.objects.order_by("pk").values_list("pk", "name")) == [
        (pk, name) for pk, name in STATUS_ROWS
    ]
    hk = Housekeeping.objects.get(name="dbversion")
    assert hk.value == __dbversion__
    assert not Housekeeping.objects.filter(name="profiles").exists()


def test_018_import_preserves_pks_and_fks(
    clean_django_db: None, sample_dump: Dict[str, Any]
) -> None:
    """Import writes ORM rows with dump PKs and FK ids."""
    from acme2certifier.django_app.models import (
        Account,
        Authorization,
        Cahandler,
        Certificate,
        Challenge,
        Cliaccount,
        Housekeeping,
        Order,
    )

    imported = migrator.import_dump(sample_dump, wipe=False, dry_run=False)
    assert imported["account"] == 1
    assert imported["orders"] == 1
    assert imported["authorization"] == 1
    assert imported["challenge"] == 1
    assert imported["certificate"] == 1
    assert imported["cliaccount"] == 1
    assert imported["cahandler"] == 1

    acct = Account.objects.get(pk=1)
    assert acct.name == "acctAAAA"
    assert acct.status_id == 5
    assert acct.contact == "mailto:a@example.com"

    order = Order.objects.get(pk=10)
    assert order.account_id == 1
    assert order.status_id == 5

    authz = Authorization.objects.get(pk=20)
    assert authz.order_id == 10

    chal = Challenge.objects.get(pk=30)
    assert chal.authorization_id == 20
    assert chal.token == "tok-chal"

    cert = Certificate.objects.get(pk=40)
    assert cert.order_id == 10
    assert cert.serial == "serial-1"
    assert cert.replaced is False

    cli = Cliaccount.objects.get(pk=50)
    assert cli.cliadmin is True
    assert cli.reportadmin is False
    assert cli.certificateadmin is True

    ca = Cahandler.objects.get(pk=60)
    assert ca.value1 == "v1"

    assert Housekeeping.objects.get(name="dbversion").value == __dbversion__


def test_019_import_refuses_nonempty_without_wipe(
    clean_django_db: None, sample_dump: Dict[str, Any]
) -> None:
    """Non-empty target without --wipe fails."""
    migrator.import_dump(sample_dump, wipe=False, dry_run=False)
    with pytest.raises(migrator.MigrationError, match="not empty"):
        migrator.import_dump(sample_dump, wipe=False, dry_run=False)


def test_020_import_wipe_flag_replaces_data(
    clean_django_db: None, sample_dump: Dict[str, Any]
) -> None:
    """--wipe clears prior ACME rows then imports."""
    from acme2certifier.django_app.models import Account

    migrator.import_dump(sample_dump, wipe=False, dry_run=False)
    assert Account.objects.filter(pk=1).exists()
    imported = migrator.import_dump(sample_dump, wipe=True, dry_run=False)
    assert imported["account"] == 1
    assert Account.objects.count() == 1
    assert Account.objects.get(pk=1).name == "acctAAAA"


def test_021_import_dry_run_writes_nothing(
    clean_django_db: None, sample_dump: Dict[str, Any]
) -> None:
    """--dry-run validates and reports counts without ORM writes."""
    from acme2certifier.django_app.models import Account

    imported = migrator.import_dump(sample_dump, wipe=False, dry_run=True)
    assert imported["account"] == 1
    assert imported["orders"] == 1
    assert Account.objects.count() == 0


def test_022_import_dry_run_does_not_seed_status_fixture(
    clean_django_db: None, sample_dump: Dict[str, Any]
) -> None:
    """Dry-run must not mutate DB; missing Status rows should fail."""
    from acme2certifier.django_app.models import Status

    Status.objects.all().delete()
    assert Status.objects.count() == 0

    with pytest.raises(migrator.MigrationError, match="dry-run"):
        migrator.import_dump(sample_dump, wipe=True, dry_run=True)
    assert Status.objects.count() == 0


def test_023_import_cli(
    clean_django_db: None,
    sample_dump: Dict[str, Any],
    tmp_path: Path,
    capsys: Any,
) -> None:
    """CLI import --wipe writes rows and prints import summary."""
    dump_path = tmp_path / "dump.json"
    migrator.write_dump(sample_dump, dump_path)
    rc = migrator.main(["import", "--dump", str(dump_path), "--wipe"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "import summary:" in out
    assert "accounts=1" in out
    from acme2certifier.django_app.models import Account

    assert Account.objects.filter(pk=1).exists()


def test_024_import_cli_dry_run(
    clean_django_db: None,
    sample_dump: Dict[str, Any],
    tmp_path: Path,
    capsys: Any,
) -> None:
    """CLI import --dry-run does not write."""
    dump_path = tmp_path / "dump.json"
    migrator.write_dump(sample_dump, dump_path)
    rc = migrator.main(["import", "--dump", str(dump_path), "--dry-run"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "import dry-run summary:" in out
    assert "dry-run: no changes written" in out
    from acme2certifier.django_app.models import Account

    assert Account.objects.count() == 0


def test_025_import_fails_bad_schema_version(
    clean_django_db: None, sample_dump: Dict[str, Any]
) -> None:
    """Refuse import when dump schema_version is not 1."""
    sample_dump["meta"]["schema_version"] = 99
    with pytest.raises(migrator.MigrationError, match="schema_version"):
        migrator.import_dump(sample_dump)


def test_026_import_fails_contact_overflow(
    clean_django_db: None, sample_dump: Dict[str, Any]
) -> None:
    """Refuse import when Account.contact exceeds model max_length."""
    sample_dump["tables"]["account"][0]["contact"] = "x" * 256
    with pytest.raises(migrator.MigrationError, match="contact length"):
        migrator.import_dump(sample_dump)


def test_027_import_fails_status_pk_mismatch(
    clean_django_db: None, sample_dump: Dict[str, Any]
) -> None:
    """Refuse import when dump status PK/name map drifts from fixture."""
    for row in sample_dump["tables"]["status"]:
        if int(row["id"]) == 1:
            row["name"] = "bogus"
            break
    with pytest.raises(migrator.MigrationError, match="status PK 1"):
        migrator.import_dump(sample_dump)


def test_028_import_fails_housekeeping_overflow(
    clean_django_db: None, sample_dump: Dict[str, Any]
) -> None:
    """Refuse import when housekeeping.value exceeds model max_length."""
    sample_dump["tables"]["housekeeping"].append(
        {"id": 99, "name": "profiles", "value": "x" * 301}
    )
    with pytest.raises(migrator.MigrationError, match="value length"):
        migrator.import_dump(sample_dump)


def test_029_export_fails_housekeeping_overflow(wsgi_db: Path) -> None:
    """Refuse export when housekeeping.value exceeds Django limit."""
    conn = sqlite3.connect(str(wsgi_db))
    try:
        conn.execute(
            "INSERT INTO housekeeping (name, value) VALUES (?, ?)",
            ("profiles", "x" * 301),
        )
        conn.commit()
    finally:
        conn.close()

    with pytest.raises(migrator.ExportError, match="value length"):
        migrator.build_dump(wsgi_db)


def test_030_verbose_export_logs_progress(
    wsgi_db: Path, tmp_path: Path, capsys: Any
) -> None:
    """CLI -v prints export progress to stderr."""
    out = tmp_path / "dump.json"
    rc = migrator.main(["-v", "export", "--db", str(wsgi_db), "--out", str(out)])
    assert rc == 0
    err = capsys.readouterr().err
    assert "export: reading WSGI database" in err
    assert "export: status fixture validated" in err
    assert "export: validation complete" in err


def test_031_import_challenge_null_token_warns(
    clean_django_db: None, sample_dump: Dict[str, Any], capsys: Any
) -> None:
    """NULL challenge.token becomes empty string with a warning."""
    sample_dump["tables"]["challenge"][0]["token"] = None
    migrator.import_dump(sample_dump)
    err = capsys.readouterr().err
    assert "token is NULL" in err
    from acme2certifier.django_app.models import Challenge

    assert Challenge.objects.get(pk=30).token == ""


def test_032_wipe_cli(
    clean_django_db: None, sample_dump: Dict[str, Any], capsys: Any
) -> None:
    """CLI wipe --yes clears imported rows and prints summary."""
    migrator.import_dump(sample_dump)
    rc = migrator.main(["wipe", "--yes"])
    assert rc == 0
    assert "wipe summary:" in capsys.readouterr().out
    from acme2certifier.django_app.models import Account, Status

    assert Account.objects.count() == 0
    assert Status.objects.count() == 8


def test_033_check_cli_passes_for_matching_dump_and_django(
    clean_django_db: None,
    sample_dump: Dict[str, Any],
    tmp_path: Path,
    capsys: Any,
) -> None:
    """check returns 0 when dump matches imported Django rows."""
    dump_path = tmp_path / "dump.json"
    migrator.write_dump(sample_dump, dump_path)
    migrator.import_dump(sample_dump)

    rc = migrator.main(["check", "--dump", str(dump_path)])
    assert rc == migrator.CHECK_EXIT_OK
    assert "check passed: dump matches Django" in capsys.readouterr().out


def test_034_check_cli_reports_django_mismatch(
    clean_django_db: None,
    sample_dump: Dict[str, Any],
    tmp_path: Path,
    capsys: Any,
) -> None:
    """check returns mismatch exit code when Django drifted from dump."""
    from acme2certifier.django_app.models import Account

    dump_path = tmp_path / "dump.json"
    migrator.write_dump(sample_dump, dump_path)
    migrator.import_dump(sample_dump)
    Account.objects.filter(pk=1).update(contact="mailto:drift@example.com")

    rc = migrator.main(["check", "--dump", str(dump_path)])
    assert rc == migrator.CHECK_EXIT_MISMATCH
    err = capsys.readouterr().err
    assert "check mismatch: dump-vs-django" in err
    assert "account.id=1 field contact" in err


def test_035_check_cli_passes_with_source_db(
    clean_django_db: None,
    sample_dump: Dict[str, Any],
    wsgi_db: Path,
    tmp_path: Path,
    capsys: Any,
) -> None:
    """check --source-db validates dump against Django and source SQLite."""
    dump_path = tmp_path / "dump.json"
    migrator.write_dump(sample_dump, dump_path)
    migrator.import_dump(sample_dump)

    rc = migrator.main(["check", "--dump", str(dump_path), "--source-db", str(wsgi_db)])
    assert rc == migrator.CHECK_EXIT_OK
    assert "check passed: dump matches Django and source-db" in capsys.readouterr().out


def test_036_check_cli_reports_source_db_mismatch(
    clean_django_db: None,
    sample_dump: Dict[str, Any],
    wsgi_db: Path,
    tmp_path: Path,
    capsys: Any,
) -> None:
    """check returns mismatch exit code when source DB differs from dump."""
    dump_path = tmp_path / "dump.json"
    migrator.write_dump(sample_dump, dump_path)
    migrator.import_dump(sample_dump)

    conn = sqlite3.connect(str(wsgi_db))
    try:
        conn.execute(
            "UPDATE account SET contact = ? WHERE id = 1",
            ("mailto:source-drift@example.com",),
        )
        conn.commit()
    finally:
        conn.close()

    rc = migrator.main(["check", "--dump", str(dump_path), "--source-db", str(wsgi_db)])
    assert rc == migrator.CHECK_EXIT_MISMATCH
    err = capsys.readouterr().err
    assert "check mismatch: dump-vs-source-db" in err
    assert "account.id=1 field contact" in err


def test_037_check_cli_uses_error_exit_for_runtime_failures(
    clean_django_db: None,
    sample_dump: Dict[str, Any],
    tmp_path: Path,
    capsys: Any,
) -> None:
    """check returns execution-error exit code for invalid source path."""
    dump_path = tmp_path / "dump.json"
    migrator.write_dump(sample_dump, dump_path)
    migrator.import_dump(sample_dump)

    missing_source = tmp_path / "missing.db"
    rc = migrator.main(
        ["check", "--dump", str(dump_path), "--source-db", str(missing_source)]
    )
    assert rc == migrator.CHECK_EXIT_ERROR
    assert "check failed:" in capsys.readouterr().err


def test_038_check_treats_nullable_blank_challenge_fields_as_equal(
    clean_django_db: None,
    sample_dump: Dict[str, Any],
    tmp_path: Path,
) -> None:
    """NULL dump values match Django blank strings for challenge text fields."""
    dump_path = tmp_path / "dump.json"
    sample_dump["tables"]["challenge"][0]["keyauthorization"] = None
    sample_dump["tables"]["challenge"][0]["source"] = None
    sample_dump["tables"]["challenge"][0]["validation_error"] = None
    migrator.write_dump(sample_dump, dump_path)
    migrator.import_dump(sample_dump)

    rc = migrator.main(["check", "--dump", str(dump_path)])
    assert rc == migrator.CHECK_EXIT_OK


def test_039_check_treats_nullable_blank_authorization_token_as_equal(
    clean_django_db: None,
    sample_dump: Dict[str, Any],
    tmp_path: Path,
) -> None:
    """NULL dump token matches Django blank string for authorization.token."""
    dump_path = tmp_path / "dump.json"
    sample_dump["tables"]["authorization"][0]["token"] = None
    migrator.write_dump(sample_dump, dump_path)
    migrator.import_dump(sample_dump)

    rc = migrator.main(["check", "--dump", str(dump_path)])
    assert rc == migrator.CHECK_EXIT_OK


def test_040_check_treats_nullable_authorization_expires_as_zero(
    clean_django_db: None,
    sample_dump: Dict[str, Any],
    tmp_path: Path,
) -> None:
    """NULL dump expires matches Django default 0 for authorization.expires."""
    dump_path = tmp_path / "dump.json"
    sample_dump["tables"]["authorization"][0]["expires"] = None
    migrator.write_dump(sample_dump, dump_path)
    migrator.import_dump(sample_dump)

    rc = migrator.main(["check", "--dump", str(dump_path)])
    assert rc == migrator.CHECK_EXIT_OK


def test_041_check_treats_nullable_order_notbefore_as_zero(
    clean_django_db: None,
    sample_dump: Dict[str, Any],
    tmp_path: Path,
) -> None:
    """NULL dump notbefore matches Django default 0 for orders.notbefore."""
    dump_path = tmp_path / "dump.json"
    sample_dump["tables"]["orders"][0]["notbefore"] = None
    migrator.write_dump(sample_dump, dump_path)
    migrator.import_dump(sample_dump)

    rc = migrator.main(["check", "--dump", str(dump_path)])
    assert rc == migrator.CHECK_EXIT_OK


def test_042_check_treats_nullable_account_eab_kid_as_blank(
    clean_django_db: None,
    sample_dump: Dict[str, Any],
    tmp_path: Path,
) -> None:
    """NULL dump eab_kid matches Django blank string."""
    dump_path = tmp_path / "dump.json"
    sample_dump["tables"]["account"][0]["eab_kid"] = None
    migrator.write_dump(sample_dump, dump_path)
    migrator.import_dump(sample_dump)

    rc = migrator.main(["check", "--dump", str(dump_path)])
    assert rc == migrator.CHECK_EXIT_OK


def test_043_check_treats_blank_order_notbefore_as_zero(
    clean_django_db: None,
    sample_dump: Dict[str, Any],
    tmp_path: Path,
) -> None:
    """Blank-string dump notbefore matches Django default 0."""
    dump_path = tmp_path / "dump.json"
    sample_dump["tables"]["orders"][0]["notbefore"] = ""
    migrator.write_dump(sample_dump, dump_path)
    migrator.import_dump(sample_dump)

    rc = migrator.main(["check", "--dump", str(dump_path)])
    assert rc == migrator.CHECK_EXIT_OK


def test_044_check_source_db_certificate_extra_id_has_diagnostic(
    clean_django_db: None,
    sample_dump: Dict[str, Any],
    wsgi_db: Path,
    tmp_path: Path,
    capsys: Any,
) -> None:
    """Source-only certificate ids include exclusion reason details."""
    dump_path = tmp_path / "dump.json"
    migrator.write_dump(sample_dump, dump_path)
    migrator.import_dump(sample_dump)

    conn = sqlite3.connect(str(wsgi_db))
    try:
        conn.execute("PRAGMA foreign_keys = OFF")
        conn.execute(
            "INSERT INTO certificate (id, name, order_id, csr) "
            "VALUES (77, 'orphan-cert-diag', 0, '')"
        )
        conn.commit()
    finally:
        conn.close()

    rc = migrator.main(["check", "--dump", str(dump_path), "--source-db", str(wsgi_db)])
    assert rc == migrator.CHECK_EXIT_MISMATCH
    err = capsys.readouterr().err
    assert "dump-vs-source-db: certificate: ids unexpected in source-db: [77]" in err
    assert (
        "dump-vs-source-db detail: certificate.id=77 excluded from dump: dangling order_id=0"
        in err
    )


def test_045_orphan_reason_null_and_dangling() -> None:
    """_orphan_reason reports NULL and dangling FK cases."""
    specs = [("order_id", "orders"), ("status_id", "status")]
    id_sets = {"orders": {1}, "status": {2}}
    assert (
        migrator._orphan_reason({"order_id": None, "status_id": 2}, specs, id_sets)
        == "NULL order_id (required FK to orders)"
    )
    assert (
        migrator._orphan_reason({"order_id": 99, "status_id": 2}, specs, id_sets)
        == "dangling order_id=99 (missing orders.id)"
    )
    assert (
        migrator._orphan_reason({"order_id": 1, "status_id": 2}, specs, id_sets) is None
    )


def test_046_fk_child_order_unique() -> None:
    """FK child order lists each child table once in FK_SPECS order."""
    order = migrator._fk_child_order()
    assert order == ["account", "orders", "authorization", "challenge", "certificate"]
    assert len(order) == len(set(order))


def test_047_parse_datetime_none_blank_and_fallback() -> None:
    """_parse_datetime handles empty values and space-separated timestamps."""
    from datetime import datetime

    assert migrator._parse_datetime(None) is None
    assert migrator._parse_datetime("") is None
    dt = migrator._parse_datetime("2024-01-15 10:20:30")
    assert dt is not None
    assert dt.replace(tzinfo=None) == datetime(2024, 1, 15, 10, 20, 30)
    with pytest.raises(migrator.MigrationError, match="unparseable timestamp"):
        migrator._parse_datetime("not-a-timestamp")


def test_048_imported_counts_init_and_dry_run_skips_nonce() -> None:
    """Import counters zero-init; dry-run skips nonce unless included."""
    counts = migrator._imported_counts_init()
    assert counts["status"] == 0
    assert counts["account"] == 0
    assert set(migrator.IMPORT_TABLE_ORDER).issubset(counts)

    tables = {"account": [{"id": 1}], "nonce": [{"id": 1}, {"id": 2}]}
    dry = migrator._dry_run_import_counts(tables, include_nonces=False)
    assert dry["account"] == 1
    assert dry["nonce"] == 0
    dry_with = migrator._dry_run_import_counts(tables, include_nonces=True)
    assert dry_with["nonce"] == 2


def test_049_as_bool_coercion_matrix() -> None:
    """_as_bool accepts None/bool/int/string truthy and falsy forms."""
    assert migrator._as_bool(None) is False
    assert migrator._as_bool(True) is True
    assert migrator._as_bool(False) is False
    assert migrator._as_bool(0) is False
    assert migrator._as_bool(1) is True
    assert migrator._as_bool("") is False
    assert migrator._as_bool("0") is False
    assert migrator._as_bool("false") is False
    assert migrator._as_bool("NO") is False
    assert migrator._as_bool("n") is False
    assert migrator._as_bool("1") is True
    assert migrator._as_bool("TRUE") is True
    assert migrator._as_bool("yes") is True
    assert migrator._as_bool("y") is True
    assert migrator._as_bool("other") is True


def test_050_parse_datetime_instance_and_aware_passthrough() -> None:
    """datetime instances are accepted; already-aware values stay aware."""
    from datetime import datetime, timezone

    naive = datetime(2024, 6, 1, 12, 0, 0)
    aware_in = datetime(2024, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
    out_naive = migrator._parse_datetime(naive)
    assert out_naive is not None
    assert out_naive.tzinfo is not None
    out_aware = migrator._parse_datetime(aware_in)
    assert out_aware is aware_in or out_aware.utcoffset() == aware_in.utcoffset()


def test_051_parse_iso_datetime_offset_and_valueerror() -> None:
    """ISO parser accepts +HH:MM offsets and raises on garbage."""
    dt = migrator._parse_iso_datetime("2024-01-15T10:20:30+01:00")
    assert dt.utcoffset() is not None
    assert dt.utcoffset().total_seconds() == 3600
    with pytest.raises(ValueError, match="unparseable timestamp"):
        migrator._parse_iso_datetime("not-a-date")


def test_052_load_dump_error_matrix(tmp_path: Path) -> None:
    """load_dump rejects missing/invalid/non-object/incomplete JSON."""
    missing = tmp_path / "missing.json"
    with pytest.raises(migrator.MigrationError, match="dump not found"):
        migrator.load_dump(missing)

    bad = tmp_path / "bad.json"
    bad.write_text("{not-json", encoding="utf-8")
    with pytest.raises(migrator.MigrationError, match="invalid dump JSON"):
        migrator.load_dump(bad)

    arr = tmp_path / "arr.json"
    arr.write_text("[1, 2]", encoding="utf-8")
    with pytest.raises(migrator.MigrationError, match="JSON object"):
        migrator.load_dump(arr)

    incomplete = tmp_path / "incomplete.json"
    incomplete.write_text('{"meta": {}}', encoding="utf-8")
    with pytest.raises(migrator.MigrationError, match="meta and tables"):
        migrator.load_dump(incomplete)


def test_053_build_dump_missing_db_and_missing_dbversion(tmp_path: Path) -> None:
    """Export fails for missing DB file and missing housekeeping.dbversion."""
    with pytest.raises(migrator.ExportError, match="WSGI database not found"):
        migrator.build_dump(tmp_path / "nope.db")

    db_path = tmp_path / "nodbv.db"
    conn = sqlite3.connect(str(db_path))
    try:
        _create_wsgi_schema(conn)
        conn.execute("DELETE FROM housekeeping WHERE name = 'dbversion'")
        conn.commit()
    finally:
        conn.close()
    with pytest.raises(migrator.ExportError, match="no housekeeping.dbversion"):
        migrator.build_dump(db_path)


def test_054_validate_required_account_and_certificate() -> None:
    """_validate_required enforces jwk/contact/csr/order_id."""
    with pytest.raises(migrator.ExportError, match="missing required jwk"):
        migrator._validate_required(
            {"account": [{"id": 1, "jwk": "", "contact": "x"}], "certificate": []}
        )
    with pytest.raises(migrator.ExportError, match="missing required contact"):
        migrator._validate_required(
            {"account": [{"id": 1, "jwk": "{}", "contact": None}], "certificate": []}
        )
    with pytest.raises(migrator.ExportError, match="missing required csr"):
        migrator._validate_required(
            {
                "account": [],
                "certificate": [{"id": 2, "csr": None, "order_id": 1}],
            }
        )
    with pytest.raises(migrator.ExportError, match="missing required order_id"):
        migrator._validate_required(
            {
                "account": [],
                "certificate": [{"id": 2, "csr": "csr", "order_id": None}],
            }
        )


def test_055_validate_status_empty_and_missing_pk() -> None:
    """Empty status is accepted; missing expected PK fails."""
    migrator._validate_status([])
    with pytest.raises(migrator.ExportError, match="status PK 1 missing"):
        migrator._validate_status([{"id": 2, "name": "pending"}])


def test_056_fetch_table_missing_and_read_dbversion_edges(tmp_path: Path) -> None:
    """Missing tables return []; housekeeping absent/empty yields None."""
    db_path = tmp_path / "emptyish.db"
    conn = sqlite3.connect(str(db_path))
    try:
        conn.row_factory = sqlite3.Row
        assert migrator._fetch_table(conn, "nonce") == []
        assert migrator._read_dbversion(conn) is None
        conn.execute(
            'CREATE TABLE "housekeeping" ('
            '"id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, '
            '"name" varchar(30) NOT NULL UNIQUE, '
            '"value" text)'
        )
        assert migrator._read_dbversion(conn) is None
        conn.execute(
            "INSERT INTO housekeeping (name, value) VALUES ('dbversion', NULL)"
        )
        conn.commit()
        assert migrator._read_dbversion(conn) is None
    finally:
        conn.close()


def test_057_print_summary_includes_nonces(capsys: Any) -> None:
    """Summary prints nonces=N when nonce count is non-zero."""
    tables = {key: [] for key, _label in migrator.SUMMARY_KEYS}
    tables["nonce"] = [{"id": 1}, {"id": 2}]
    migrator.print_summary(tables, prefix="export summary")
    out = capsys.readouterr().out
    assert "nonces=2" in out


def test_058_wipe_dry_run_does_not_delete(clean_django_db: None) -> None:
    """wipe_acme_data(dry_run=True) reports counts but leaves rows."""
    from acme2certifier.django_app.models import Account

    Account.objects.create(
        id=98,
        name="drywipe",
        alg="ES256",
        jwk="{}",
        contact="mailto:d@example.com",
        status_id=5,
    )
    deleted = migrator.wipe_acme_data(dry_run=True)
    assert deleted["account"] == 1
    assert Account.objects.filter(pk=98).exists()


def test_059_import_nonces_end_to_end(clean_django_db: None, wsgi_db: Path) -> None:
    """include_nonces dump imports Nonce rows and check includes nonce table."""
    from acme2certifier.django_app.models import Nonce

    dump = migrator.build_dump(wsgi_db, include_nonces=True)
    assert len(dump["tables"]["nonce"]) == 1
    imported = migrator.import_dump(dump, wipe=False, dry_run=False)
    assert imported["nonce"] == 1
    assert Nonce.objects.get(pk=70).nonce == "nonce-abc"

    dump_path = wsgi_db.parent / "with-nonces.json"
    migrator.write_dump(dump, dump_path)
    rc = migrator.main(["check", "--dump", str(dump_path)])
    assert rc == migrator.CHECK_EXIT_OK
    assert "nonce" in migrator._tables_for_check(dump, include_nonces=True)


def test_060_import_dump_dbversion_mismatch(
    clean_django_db: None, sample_dump: Dict[str, Any]
) -> None:
    """Refuse import when dump meta.dbversion != tool __dbversion__."""
    sample_dump["meta"]["dbversion"] = "0.0.0-not-real"
    with pytest.raises(migrator.MigrationError, match="dump dbversion"):
        migrator.import_dump(sample_dump)


def test_061_housekeeping_dbversion_refuse_wrong_value(
    clean_django_db: None,
) -> None:
    """Refuse importing a housekeeping dbversion that differs from the tool."""
    models = migrator._django_models()
    with pytest.raises(migrator.MigrationError, match="refuse import"):
        migrator._import_housekeeping_row(
            {"id": 999, "name": "dbversion", "value": "9.9.9", "modified_at": None},
            models,
        )


def test_062_housekeeping_dbversion_repair_and_insert(
    clean_django_db: None,
) -> None:
    """Repair drifted Django dbversion; insert when row is absent."""
    from acme2certifier.django_app.models import Housekeeping

    models = migrator._django_models()
    existing = Housekeeping.objects.get(name="dbversion")
    original_pk = int(existing.pk)
    Housekeeping.objects.filter(pk=existing.pk).update(value="drifted")
    migrator._import_housekeeping_row(
        {
            "id": original_pk,
            "name": "dbversion",
            "value": __dbversion__,
            "modified_at": "2024-02-01 00:00:00",
        },
        models,
    )
    assert Housekeeping.objects.get(name="dbversion").value == __dbversion__

    Housekeeping.objects.filter(name="dbversion").delete()
    migrator._import_housekeeping_row(
        {
            "id": original_pk,
            "name": "dbversion",
            "value": __dbversion__,
            "modified_at": None,
        },
        models,
    )
    restored = Housekeeping.objects.get(name="dbversion")
    assert restored.value == __dbversion__
    assert int(restored.pk) == original_pk


def test_063_import_failed_wraps_orm_errors(
    clean_django_db: None, sample_dump: Dict[str, Any]
) -> None:
    """Generic ORM/handler exceptions become MigrationError('import failed: ...')."""

    def _boom(_row: Any, _models: Any) -> None:
        raise RuntimeError("simulated orm failure")

    with pytest.MonkeyPatch.context() as mp:
        mp.setitem(migrator._IMPORT_HANDLERS, "account", _boom)
        with pytest.raises(migrator.MigrationError, match="import failed:"):
            migrator.import_dump(sample_dump, wipe=False, dry_run=False)


def test_064_cmd_export_sqlite_error(tmp_path: Path, capsys: Any) -> None:
    """cmd_export maps unexpected sqlite3.Error to exit 1."""
    db_path = tmp_path / "acme_srv.db"
    db_path.write_text("not-a-sqlite-db", encoding="utf-8")
    args = type(
        "Args",
        (),
        {
            "db": str(db_path),
            "out": str(tmp_path / "out.json"),
            "include_nonces": False,
        },
    )()
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(
            migrator,
            "build_dump",
            lambda *_a, **_k: (_ for _ in ()).throw(sqlite3.Error("boom")),
        )
        rc = migrator.cmd_export(args)
    assert rc == 1
    assert "sqlite error" in capsys.readouterr().err


def test_065_cmd_wipe_migration_error(capsys: Any) -> None:
    """cmd_wipe prints wipe failed on MigrationError."""
    args = type("Args", (), {"yes": True})()
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(
            migrator,
            "setup_django_orm",
            lambda: (_ for _ in ()).throw(migrator.MigrationError("no django")),
        )
        rc = migrator.cmd_wipe(args)
    assert rc == 1
    assert "wipe failed: no django" in capsys.readouterr().err


def test_066_ensure_django_models_importerror() -> None:
    """_ensure_django_models returns False when Django import fails."""
    import builtins

    real_import = builtins.__import__

    def _fake_import(name: str, *args: Any, **kwargs: Any) -> Any:
        if name == "django" or name.startswith("django."):
            raise ImportError("simulated")
        return real_import(name, *args, **kwargs)

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(builtins, "__import__", _fake_import)
        assert migrator._ensure_django_models() is False
        assert migrator.length_limits_from_django() is None


def test_067_setup_django_orm_importerror() -> None:
    """setup_django_orm raises MigrationError when Django is unavailable."""
    import builtins

    real_import = builtins.__import__

    def _fake_import(name: str, *args: Any, **kwargs: Any) -> Any:
        if name == "django" or name.startswith("django."):
            raise ImportError("simulated")
        return real_import(name, *args, **kwargs)

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(builtins, "__import__", _fake_import)
        with pytest.raises(migrator.MigrationError, match="Django is required"):
            migrator.setup_django_orm()


def test_068_status_mismatches_name_drift(clean_django_db: None) -> None:
    """_status_mismatches reports PK name mismatches."""
    from acme2certifier.django_app.models import Status

    models = migrator._django_models()
    Status.objects.filter(pk=1).update(name="bogus")
    mismatches = migrator._status_mismatches(models)
    assert any("name mismatch" in m for m in mismatches)
    Status.objects.filter(pk=1).update(name="invalid")


def test_069_assert_status_fixture_auto_seed(clean_django_db: None) -> None:
    """auto_seed repairs missing Status rows via loaddata path."""
    from acme2certifier.django_app.models import Status

    Status.objects.all().delete()
    assert Status.objects.count() == 0

    def _seed_status(cmd: str, *args: Any, **kwargs: Any) -> None:
        if cmd != "loaddata":
            return
        for pk, name in STATUS_ROWS:
            Status.objects.update_or_create(pk=pk, defaults={"name": name})

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr("django.core.management.call_command", _seed_status)
        migrator.assert_django_status_fixture(auto_seed=True)
    assert Status.objects.count() == 8


def test_070_assert_status_fixture_still_invalid_after_seed(
    clean_django_db: None,
) -> None:
    """If auto-seed leaves mismatches, raise MigrationError."""
    from acme2certifier.django_app.models import Housekeeping, Status

    Status.objects.all().delete()

    def _noop_loaddata(*_a: Any, **_k: Any) -> None:
        return None

    try:
        with pytest.MonkeyPatch.context() as mp:
            mp.setattr("django.core.management.call_command", _noop_loaddata)
            with pytest.raises(migrator.MigrationError, match="Status fixture invalid"):
                migrator.assert_django_status_fixture(auto_seed=True)
    finally:
        for pk, name in STATUS_ROWS:
            Status.objects.update_or_create(pk=pk, defaults={"name": name})
        Housekeeping.objects.update_or_create(
            name="dbversion", defaults={"value": __dbversion__}
        )


def test_071_normalize_check_value_edges() -> None:
    """NONE_EQ_ZERO / INT_CHECK / EMPTY_EQ_NONE edge coercions."""
    assert migrator._normalize_check_value("certificate", "issue_uts", "none") == 0
    assert migrator._normalize_check_value("challenge", "validated", None) == 0
    assert migrator._normalize_check_value("account", "status_id", "") is None
    assert migrator._normalize_check_value("account", "status_id", "5") == 5
    assert migrator._normalize_check_value("account", "eab_kid", None) == ""


def test_072_canonicalize_rows_requires_id() -> None:
    """Check comparison requires each row to have an id."""
    with pytest.raises(migrator.MigrationError, match="missing required id"):
        migrator._canonicalize_rows("status", [{"name": "invalid"}])


def test_073_diff_rows_missing_ids_in_right() -> None:
    """_diff_rows reports ids missing on the right side."""
    left = [{"id": 1, "name": "invalid"}, {"id": 2, "name": "pending"}]
    right = [{"id": 1, "name": "invalid"}]
    msgs = migrator._diff_rows(
        "status", left, right, left_label="dump", right_label="django"
    )
    assert any("ids missing in django" in m for m in msgs)
    assert any("count mismatch" in m for m in msgs)


def test_074_certificate_diagnostics_null_invalid_and_present() -> None:
    """Source-only certificate diagnostics cover NULL/invalid/present cases."""

    def _cert(cid: int, order_id: Any) -> Dict[str, Any]:
        return {
            "id": cid,
            "name": f"c{cid}",
            "order_id": order_id,
            "csr": "csr",
            "cert": None,
            "cert_raw": None,
            "error": None,
            "poll_identifier": None,
            "header_info": None,
            "renewal_info": None,
            "aki": None,
            "serial": None,
            "issue_uts": 0,
            "expire_uts": 0,
            "replaced": 0,
        }

    dump_rows = [_cert(1, 10)]
    source_rows = [
        _cert(1, 10),
        _cert(2, None),
        _cert(3, "bad"),
        _cert(4, 10),
    ]
    order_rows = [{"id": 10}]

    # Canonicalize rejects non-int order_id; stub ids so diagnostic branches run.
    def _ids_only(
        _table: str, rows: Sequence[Mapping[str, Any]]
    ) -> Dict[int, Dict[str, Any]]:
        return {int(row["id"]): {} for row in rows if row.get("id") is not None}

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(migrator, "_canonicalize_rows", _ids_only)
        diags = migrator._source_only_certificate_diagnostics(
            dump_rows, source_rows, order_rows
        )
    assert any("NULL order_id" in d for d in diags)
    assert any("invalid order_id" in d for d in diags)
    assert any("present in source-db but not in dump" in d for d in diags)


def test_075_extract_verbose_strips_flags() -> None:
    """_extract_verbose removes -v/--verbose anywhere in argv."""
    filtered, verbose = migrator._extract_verbose(
        ["-v", "import", "--dump", "x.json", "--verbose"]
    )
    assert verbose is True
    assert filtered == ["import", "--dump", "x.json"]


def test_076_verbose_import_and_check_cli(
    clean_django_db: None,
    sample_dump: Dict[str, Any],
    tmp_path: Path,
    capsys: Any,
) -> None:
    """Trailing --verbose enables progress logs for import and check."""
    dump_path = tmp_path / "dump.json"
    migrator.write_dump(sample_dump, dump_path)
    rc = migrator.main(["import", "--dump", str(dump_path), "--verbose"])
    assert rc == 0
    err = capsys.readouterr().err
    assert "import:" in err

    rc = migrator.main(["check", "--dump", str(dump_path), "-v"])
    assert rc == migrator.CHECK_EXIT_OK


def test_077_import_wipe_dry_run_on_nonempty(
    clean_django_db: None, sample_dump: Dict[str, Any]
) -> None:
    """Non-empty target with wipe+dry_run reports counts without writing."""
    from acme2certifier.django_app.models import Account

    migrator.import_dump(sample_dump, wipe=False, dry_run=False)
    before = Account.objects.count()
    counts = migrator.import_dump(sample_dump, wipe=True, dry_run=True)
    assert counts["account"] == 1
    assert Account.objects.count() == before


def test_078_ensure_django_models_setup_exception(capsys: Any) -> None:
    """_ensure_django_models warns and returns False when setup raises."""
    from django.apps import apps

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(apps, "ready", False)

        def _boom_setup() -> None:
            raise RuntimeError("setup exploded")

        mp.setattr("django.setup", _boom_setup)
        assert migrator._ensure_django_models() is False
    assert "Django model introspection unavailable" in capsys.readouterr().err


def test_079_setup_django_orm_setup_failure() -> None:
    """setup_django_orm wraps unexpected setup exceptions as MigrationError."""
    from django.apps import apps

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(apps, "ready", False)

        def _boom_setup() -> None:
            raise RuntimeError("broken settings")

        mp.setattr("django.setup", _boom_setup)
        with pytest.raises(migrator.MigrationError, match="Django setup failed"):
            migrator.setup_django_orm()


def test_080_import_non_dbversion_housekeeping(
    clean_django_db: None,
) -> None:
    """Non-dbversion housekeeping rows are inserted via the generic path."""
    from acme2certifier.django_app.models import Housekeeping

    models = migrator._django_models()
    migrator._import_housekeeping_row(
        {
            "id": 777,
            "name": "profiles",
            "value": "[]",
            "modified_at": "2024-03-01 00:00:00",
        },
        models,
    )
    assert Housekeeping.objects.get(pk=777).name == "profiles"
    assert Housekeeping.objects.get(pk=777).value == "[]"


def test_081_import_dump_reraises_migration_error(
    clean_django_db: None, sample_dump: Dict[str, Any]
) -> None:
    """MigrationError raised inside the import transaction is not wrapped."""

    def _boom(_row: Any, _models: Any) -> None:
        raise migrator.MigrationError("explicit import abort")

    with pytest.MonkeyPatch.context() as mp:
        mp.setitem(migrator._IMPORT_HANDLERS, "account", _boom)
        with pytest.raises(migrator.MigrationError, match="explicit import abort"):
            migrator.import_dump(sample_dump, wipe=False, dry_run=False)


def test_082_cmd_import_migration_error(tmp_path: Path, capsys: Any) -> None:
    """cmd_import prints import failed on MigrationError."""
    dump_path = tmp_path / "missing.json"
    args = type(
        "Args",
        (),
        {"dump": str(dump_path), "wipe": False, "dry_run": False},
    )()
    rc = migrator.cmd_import(args)
    assert rc == 1
    assert "import failed:" in capsys.readouterr().err


def test_083_module_main_entrypoint(monkeypatch: pytest.MonkeyPatch) -> None:
    """``__main__`` guard forwards main()'s exit code via sys.exit."""
    import runpy
    import sys

    monkeypatch.setattr(sys, "argv", ["a2c-wsgi2django", "wipe"])
    sys.modules.pop("acme2certifier.tools.a2c_wsgi2django", None)
    with pytest.raises(SystemExit) as exc:
        runpy.run_module(
            "acme2certifier.tools.a2c_wsgi2django",
            run_name="__main__",
            alter_sys=True,
        )
    assert exc.value.code == 1


def test_084_ensure_django_models_configure_and_setup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """_ensure_django_models configures settings then setup when not ready."""
    from unittest.mock import MagicMock, PropertyMock, patch

    mock_django = MagicMock()
    mock_apps = MagicMock()
    mock_apps.ready = False
    mock_settings = MagicMock()
    type(mock_settings).configured = PropertyMock(return_value=False)

    mock_django_conf = MagicMock(settings=mock_settings)
    mock_django_apps = MagicMock(apps=mock_apps)

    with patch.dict(
        "sys.modules",
        {
            "django": mock_django,
            "django.apps": mock_django_apps,
            "django.conf": mock_django_conf,
        },
    ):
        assert migrator._ensure_django_models() is True
    mock_settings.configure.assert_called_once()
    mock_django.setup.assert_called_once()


def test_085_setup_django_orm_missing_settings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """setup_django_orm raises MigrationError when settings env is empty."""
    from unittest.mock import MagicMock, PropertyMock, patch

    monkeypatch.setenv("DJANGO_SETTINGS_MODULE", "")
    mock_django = MagicMock()
    mock_apps = MagicMock()
    mock_apps.ready = False
    mock_settings = MagicMock()
    type(mock_settings).configured = PropertyMock(return_value=False)

    with patch.dict(
        "sys.modules",
        {
            "django": mock_django,
            "django.apps": MagicMock(apps=mock_apps),
            "django.conf": MagicMock(settings=mock_settings),
        },
    ):
        with pytest.raises(
            migrator.MigrationError, match="Django settings are not configured"
        ):
            migrator.setup_django_orm()
