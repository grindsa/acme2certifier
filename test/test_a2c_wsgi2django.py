#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""pytest for a2c-wsgi2django export / wipe / import."""

from __future__ import annotations

import json
import sqlite3
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Tuple

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


def test_parse_iso_datetime_python36_compatible() -> None:
    """ISO parsing must not rely on datetime.fromisoformat (added in 3.7)."""
    from datetime import datetime

    assert migrator._parse_iso_datetime("2024-01-15T10:20:30") == datetime(
        2024, 1, 15, 10, 20, 30
    )
    assert migrator._parse_iso_datetime("2024-01-15T10:20:30.123456") == datetime(
        2024, 1, 15, 10, 20, 30, 123456
    )
    assert migrator._parse_iso_datetime("2024-01-15T10:20:30Z").utcoffset() is not None
    assert migrator._parse_iso_datetime("2024-01-15T10:20:30+00:00").utcoffset() is not None


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


def test_001_export_builds_schema_v1_dump(wsgi_db: Path, tmp_path: Path) -> None:
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


def test_002_export_fk_integrity(wsgi_db: Path) -> None:
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


def test_003_export_include_nonces(wsgi_db: Path) -> None:
    """--include-nonces populates tables.nonce and meta.include_nonces."""
    dump = migrator.build_dump(wsgi_db, include_nonces=True)
    assert dump["meta"]["include_nonces"] is True
    assert len(dump["tables"]["nonce"]) == 1
    assert dump["tables"]["nonce"][0]["nonce"] == "nonce-abc"


def test_004_export_cli_writes_file(wsgi_db: Path, tmp_path: Path, capsys: Any) -> None:
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


def test_005_export_fails_wrong_dbversion(tmp_path: Path) -> None:
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


def test_006_export_fails_contact_overflow(wsgi_db: Path) -> None:
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


def test_007_export_skips_dangling_fk_with_warning(
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


def test_008_export_skips_certificate_with_order_id_zero(
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


def test_009_export_fails_status_name_mismatch(wsgi_db: Path) -> None:
    """Refuse export when status PK/name map drifts from fixture."""
    conn = sqlite3.connect(str(wsgi_db))
    try:
        conn.execute("UPDATE status SET name = ? WHERE id = 1", ("bogus",))
        conn.commit()
    finally:
        conn.close()

    with pytest.raises(migrator.ExportError, match="status PK 1"):
        migrator.build_dump(wsgi_db)


def test_010_summary_counts(wsgi_db: Path) -> None:
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


def test_011_resolve_length_limits_prefers_django_when_available() -> None:
    """Live model max_length wins over FALLBACK_LENGTH_LIMITS."""
    live = {"housekeeping": {"value": 300}, "account": {"contact": 255}}
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(migrator, "length_limits_from_django", lambda: live)
        assert migrator.resolve_length_limits() == live


def test_012_resolve_length_limits_fallback_without_django() -> None:
    """Without Django models, frozen fallback limits are used."""
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(migrator, "length_limits_from_django", lambda: None)
        limits = migrator.resolve_length_limits()
        assert limits == migrator.FALLBACK_LENGTH_LIMITS
        assert limits["housekeeping"]["value"] == 30


def test_013_export_respects_resolved_housekeeping_limit(wsgi_db: Path) -> None:
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


def test_014_wipe_requires_yes(capsys: Any) -> None:
    """CLI wipe without --yes refuses and exits 1."""
    rc = migrator.main(["wipe"])
    assert rc == 1
    assert "refusing to wipe without --yes" in capsys.readouterr().err


def test_015_wipe_keeps_status_and_dbversion(clean_django_db: None) -> None:
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


def test_016_import_preserves_pks_and_fks(
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


def test_017_import_refuses_nonempty_without_wipe(
    clean_django_db: None, sample_dump: Dict[str, Any]
) -> None:
    """Non-empty target without --wipe fails."""
    migrator.import_dump(sample_dump, wipe=False, dry_run=False)
    with pytest.raises(migrator.MigrationError, match="not empty"):
        migrator.import_dump(sample_dump, wipe=False, dry_run=False)


def test_018_import_wipe_flag_replaces_data(
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


def test_019_import_dry_run_writes_nothing(
    clean_django_db: None, sample_dump: Dict[str, Any]
) -> None:
    """--dry-run validates and reports counts without ORM writes."""
    from acme2certifier.django_app.models import Account

    imported = migrator.import_dump(sample_dump, wipe=False, dry_run=True)
    assert imported["account"] == 1
    assert imported["orders"] == 1
    assert Account.objects.count() == 0


def test_020_import_dry_run_does_not_seed_status_fixture(
    clean_django_db: None, sample_dump: Dict[str, Any]
) -> None:
    """Dry-run must not mutate DB; missing Status rows should fail."""
    from acme2certifier.django_app.models import Status

    Status.objects.all().delete()
    assert Status.objects.count() == 0

    with pytest.raises(migrator.MigrationError, match="dry-run"):
        migrator.import_dump(sample_dump, wipe=True, dry_run=True)
    assert Status.objects.count() == 0


def test_021_import_cli(
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


def test_022_import_cli_dry_run(
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


def test_023_import_fails_bad_schema_version(
    clean_django_db: None, sample_dump: Dict[str, Any]
) -> None:
    """Refuse import when dump schema_version is not 1."""
    sample_dump["meta"]["schema_version"] = 99
    with pytest.raises(migrator.MigrationError, match="schema_version"):
        migrator.import_dump(sample_dump)


def test_024_import_fails_contact_overflow(
    clean_django_db: None, sample_dump: Dict[str, Any]
) -> None:
    """Refuse import when Account.contact exceeds model max_length."""
    sample_dump["tables"]["account"][0]["contact"] = "x" * 256
    with pytest.raises(migrator.MigrationError, match="contact length"):
        migrator.import_dump(sample_dump)


def test_025_import_challenge_null_token_warns(
    clean_django_db: None, sample_dump: Dict[str, Any], capsys: Any
) -> None:
    """NULL challenge.token becomes empty string with a warning."""
    sample_dump["tables"]["challenge"][0]["token"] = None
    migrator.import_dump(sample_dump)
    err = capsys.readouterr().err
    assert "token is NULL" in err
    from acme2certifier.django_app.models import Challenge

    assert Challenge.objects.get(pk=30).token == ""


def test_026_wipe_cli(clean_django_db: None, sample_dump: Dict[str, Any], capsys: Any) -> None:
    """CLI wipe --yes clears imported rows and prints summary."""
    migrator.import_dump(sample_dump)
    rc = migrator.main(["wipe", "--yes"])
    assert rc == 0
    assert "wipe summary:" in capsys.readouterr().out
    from acme2certifier.django_app.models import Account, Status

    assert Account.objects.count() == 0
    assert Status.objects.count() == 8


def test_027_check_cli_passes_for_matching_dump_and_django(
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


def test_028_check_cli_reports_django_mismatch(
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


def test_029_check_cli_passes_with_source_db(
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

    rc = migrator.main(
        ["check", "--dump", str(dump_path), "--source-db", str(wsgi_db)]
    )
    assert rc == migrator.CHECK_EXIT_OK
    assert (
        "check passed: dump matches Django and source-db"
        in capsys.readouterr().out
    )


def test_030_check_cli_reports_source_db_mismatch(
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

    rc = migrator.main(
        ["check", "--dump", str(dump_path), "--source-db", str(wsgi_db)]
    )
    assert rc == migrator.CHECK_EXIT_MISMATCH
    err = capsys.readouterr().err
    assert "check mismatch: dump-vs-source-db" in err
    assert "account.id=1 field contact" in err


def test_031_check_cli_uses_error_exit_for_runtime_failures(
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


def test_032_check_treats_nullable_blank_challenge_fields_as_equal(
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


def test_033_check_treats_nullable_blank_authorization_token_as_equal(
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


def test_034_check_treats_nullable_authorization_expires_as_zero(
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


def test_035_check_treats_nullable_order_notbefore_as_zero(
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


def test_036_check_treats_nullable_account_eab_kid_as_blank(
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


def test_037_check_treats_blank_order_notbefore_as_zero(
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


def test_038_check_source_db_certificate_extra_id_has_diagnostic(
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

    rc = migrator.main(
        ["check", "--dump", str(dump_path), "--source-db", str(wsgi_db)]
    )
    assert rc == migrator.CHECK_EXIT_MISMATCH
    err = capsys.readouterr().err
    assert "dump-vs-source-db: certificate: ids unexpected in source-db: [77]" in err
    assert (
        "dump-vs-source-db detail: certificate.id=77 excluded from dump: dangling order_id=0"
        in err
    )
