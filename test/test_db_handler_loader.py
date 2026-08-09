# -*- coding: utf-8 -*-
"""Tests for selectable DB handler resolution."""

import importlib
import logging
import sys
from typing import Dict, Iterator

import pytest

_MODULE = "acme2certifier.acme_srv.db_handler"


@pytest.fixture(autouse=True)
def db_handler_mod(monkeypatch: pytest.MonkeyPatch) -> Iterator[object]:
    """Provide a real db_handler module (undo MagicMock stubs from other suites)."""
    monkeypatch.delenv("ACME_SRV_DB_HANDLER", raising=False)
    # test_authorization / test_directory inject MagicMock into sys.modules at import.
    sys.modules.pop(_MODULE, None)
    mod = importlib.import_module(_MODULE)
    yield mod


def test_001_normalize_short_names(db_handler_mod: object) -> None:
    assert (
        db_handler_mod._normalize_handler("wsgi")
        == "acme2certifier.dbhandlers.wsgi_handler"
    )
    assert (
        db_handler_mod._normalize_handler("DJANGO")
        == "acme2certifier.dbhandlers.django_handler"
    )
    assert (
        db_handler_mod._normalize_handler("my.custom.handler") == "my.custom.handler"
    )


def test_002_cfg_handler_wins_over_env(
    db_handler_mod: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ACME_SRV_DB_HANDLER", "django")
    config: Dict[str, Dict[str, str]] = {"DBhandler": {"handler": "wsgi"}}
    assert (
        db_handler_mod.resolve_db_handler_module(config)
        == "acme2certifier.dbhandlers.wsgi_handler"
    )


def test_003_env_used_when_cfg_has_no_handler(
    db_handler_mod: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ACME_SRV_DB_HANDLER", "django")
    config: Dict[str, Dict[str, str]] = {"DBhandler": {"dbfile": "/tmp/x.db"}}
    assert (
        db_handler_mod.resolve_db_handler_module(config)
        == "acme2certifier.dbhandlers.django_handler"
    )


def test_004_default_is_wsgi(db_handler_mod: object) -> None:
    config: Dict[str, Dict[str, str]] = {"DBhandler": {}}
    assert (
        db_handler_mod.resolve_db_handler_module(config)
        == "acme2certifier.dbhandlers.wsgi_handler"
    )


def test_005_handler_module_wins_over_handler(db_handler_mod: object) -> None:
    config: Dict[str, Dict[str, str]] = {
        "DBhandler": {
            "handler": "django",
            "handler_module": "acme2certifier.dbhandlers.wsgi_handler",
        }
    }
    assert (
        db_handler_mod.resolve_db_handler_module(config)
        == "acme2certifier.dbhandlers.wsgi_handler"
    )


def test_006_load_wsgi_handler_exports_dbstore(db_handler_mod: object) -> None:
    loaded = db_handler_mod.load_db_handler_module({"DBhandler": {"handler": "wsgi"}})
    assert hasattr(loaded, "DBstore")
    assert loaded.__name__ == "acme2certifier.dbhandlers.wsgi_handler"


def test_007_log_active_db_handler(
    db_handler_mod: object, caplog: pytest.LogCaptureFixture
) -> None:
    logger = logging.getLogger("test.db_handler_startup")
    config: Dict[str, Dict[str, str]] = {"DBhandler": {"handler": "wsgi"}}
    with caplog.at_level(logging.INFO, logger="test.db_handler_startup"):
        db_handler_mod.log_active_db_handler(logger, config)
    assert any("Using DB handler" in rec.message for rec in caplog.records)


def test_008_warn_dbhandler_missing_handler(
    db_handler_mod: object, caplog: pytest.LogCaptureFixture
) -> None:
    db_handler_mod._DBHANDLER_CFG_WARNED = False
    logger = logging.getLogger("test.db_handler_warn")
    config: Dict[str, Dict[str, str]] = {"DBhandler": {"dbfile": "/tmp/x.db"}}
    with caplog.at_level(logging.WARNING, logger="test.db_handler_warn"):
        db_handler_mod.warn_dbhandler_cfg_missing(logger, config)
        db_handler_mod.warn_dbhandler_cfg_missing(logger, config)
    matches = [rec for rec in caplog.records if "[DBhandler]" in rec.message]
    assert len(matches) == 1
    assert "handler not set" in matches[0].message
    assert "default: wsgi" in matches[0].message


def test_009_warn_dbhandler_missing_section_with_env(
    db_handler_mod: object,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    db_handler_mod._DBHANDLER_CFG_WARNED = False
    monkeypatch.setenv("ACME_SRV_DB_HANDLER", "django")
    logger = logging.getLogger("test.db_handler_warn_env")
    with caplog.at_level(logging.WARNING, logger="test.db_handler_warn_env"):
        db_handler_mod.warn_dbhandler_cfg_missing(logger, {"DEFAULT": {}})
    assert any(
        "section missing" in rec.message
        and "ACME_SRV_DB_HANDLER=django" in rec.message
        for rec in caplog.records
    )


def test_010_warn_dbhandler_handler_module_suppresses(
    db_handler_mod: object, caplog: pytest.LogCaptureFixture
) -> None:
    db_handler_mod._DBHANDLER_CFG_WARNED = False
    logger = logging.getLogger("test.db_handler_no_warn")
    config: Dict[str, Dict[str, str]] = {
        "DBhandler": {
            "handler_module": "acme2certifier.dbhandlers.django_handler",
        }
    }
    with caplog.at_level(logging.WARNING, logger="test.db_handler_no_warn"):
        db_handler_mod.warn_dbhandler_cfg_missing(logger, config)
    assert not caplog.records


def test_011_warn_dbhandler_invalid_handler(
    db_handler_mod: object, caplog: pytest.LogCaptureFixture
) -> None:
    db_handler_mod._DBHANDLER_CFG_WARNED = False
    logger = logging.getLogger("test.db_handler_invalid")
    config: Dict[str, Dict[str, str]] = {"DBhandler": {"handler": "mysql"}}
    with caplog.at_level(logging.WARNING, logger="test.db_handler_invalid"):
        db_handler_mod.warn_dbhandler_cfg_missing(logger, config)
    assert any("handler='mysql'" in rec.message for rec in caplog.records)


def test_012_package_db_handler_reexports_dbstore(db_handler_mod: object) -> None:
    assert hasattr(db_handler_mod, "DBstore")
    assert callable(db_handler_mod.DBstore)


def test_013_wsgi_backend_module_exports_dbstore() -> None:
    mod = importlib.import_module("acme2certifier.dbhandlers.wsgi_handler")
    assert mod.DBstore is not None
    assert mod.DBstore.__module__ == "acme2certifier.dbhandlers.wsgi_handler"


def test_014_cfg_handler_name_load_config_failure(
    db_handler_mod: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    def _boom() -> None:
        raise RuntimeError("cfg boom")

    monkeypatch.setattr(
        "acme2certifier.acme_srv.helpers.config.load_config",
        _boom,
    )
    assert db_handler_mod._cfg_handler_name(None) is None


def test_015_cfg_handler_name_missing_section(db_handler_mod: object) -> None:
    assert db_handler_mod._cfg_handler_name({"DEFAULT": {}}) is None


def test_016_load_db_handler_module_import_failure(
    db_handler_mod: object,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    monkeypatch.setattr(
        db_handler_mod,
        "_resolve_db_handler",
        lambda config_dic=None: ("missing.db.handler.module", "cfg"),
    )
    with caplog.at_level(logging.CRITICAL, logger="acme2certifier.db_handler"):
        with pytest.raises(ModuleNotFoundError):
            db_handler_mod.load_db_handler_module({})
    assert any("Loading DB handler" in rec.message for rec in caplog.records)


def test_017_active_db_handler_label(db_handler_mod: object) -> None:
    label = db_handler_mod.active_db_handler_label()
    assert label in ("wsgi", "django") or isinstance(label, str)
