# -*- coding: utf-8 -*-
"""Tests for selectable DB handler loader (``acme_srv.db_handler``)."""

import importlib
import logging
import sys
from typing import Dict, Iterator

import pytest

from acme2certifier.acme_srv.helpers import db_handler_select

_MODULE = "acme2certifier.acme_srv.db_handler"


@pytest.fixture(autouse=True)
def db_handler_mod(monkeypatch: pytest.MonkeyPatch) -> Iterator[object]:
    """Provide a real db_handler module (undo MagicMock stubs from other suites)."""
    monkeypatch.delenv("ACME_SRV_DB_HANDLER", raising=False)
    # test_authorization / test_directory inject MagicMock into sys.modules at import.
    sys.modules.pop(_MODULE, None)
    mod = importlib.import_module(_MODULE)
    yield mod


def test_001_load_wsgi_handler_exports_dbstore(db_handler_mod: object) -> None:
    loaded = db_handler_mod.load_db_handler_module({"DBhandler": {"handler": "wsgi"}})
    assert hasattr(loaded, "DBstore")
    assert loaded.__name__ == "acme2certifier.dbhandlers.wsgi_handler"


def test_002_log_active_db_handler(
    db_handler_mod: object, caplog: pytest.LogCaptureFixture
) -> None:
    db_handler_select._DBHANDLER_CFG_WARNED = False
    logger = logging.getLogger("test.db_handler_startup")
    config: Dict[str, Dict[str, str]] = {"DBhandler": {"handler": "wsgi"}}
    with caplog.at_level(logging.INFO, logger="test.db_handler_startup"):
        db_handler_mod.log_active_db_handler(logger, config)
    assert any("Using DB handler" in rec.message for rec in caplog.records)


def test_003_warn_via_log_active_when_handler_missing(
    db_handler_mod: object, caplog: pytest.LogCaptureFixture
) -> None:
    """log_active_db_handler delegates cfg warnings to the helper."""
    db_handler_select._DBHANDLER_CFG_WARNED = False
    logger = logging.getLogger("test.db_handler_warn")
    config: Dict[str, Dict[str, str]] = {"DBhandler": {"dbfile": "/tmp/x.db"}}
    with caplog.at_level(logging.WARNING, logger="test.db_handler_warn"):
        db_handler_mod.log_active_db_handler(logger, config)
        db_handler_mod.log_active_db_handler(logger, config)
    matches = [rec for rec in caplog.records if "[DBhandler]" in rec.message]
    assert len(matches) == 1
    assert "handler not set" in matches[0].message


def test_004_package_db_handler_reexports_dbstore(db_handler_mod: object) -> None:
    assert hasattr(db_handler_mod, "DBstore")
    assert callable(db_handler_mod.DBstore)


def test_005_wsgi_backend_module_exports_dbstore() -> None:
    mod = importlib.import_module("acme2certifier.dbhandlers.wsgi_handler")
    assert mod.DBstore is not None
    assert mod.DBstore.__module__ == "acme2certifier.dbhandlers.wsgi_handler"


def test_006_load_db_handler_module_import_failure(
    db_handler_mod: object,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    monkeypatch.setattr(
        "acme2certifier.acme_srv.db_handler.resolve_db_handler",
        lambda config_dic=None: ("missing.db.handler.module", "cfg"),
    )
    with caplog.at_level(logging.CRITICAL, logger="acme2certifier.db_handler"):
        with pytest.raises(ModuleNotFoundError):
            db_handler_mod.load_db_handler_module({})
    assert any("Loading DB handler" in rec.message for rec in caplog.records)


def test_007_active_db_handler_label(db_handler_mod: object) -> None:
    label = db_handler_mod.active_db_handler_label()
    assert label in ("wsgi", "django") or isinstance(label, str)
