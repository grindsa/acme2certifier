# -*- coding: utf-8 -*-
"""Tests for selectable DB handler resolution."""

from __future__ import annotations

import importlib
import logging
import os
from typing import Dict

import pytest

from acme2certifier.acme_srv import db_handler as db_handler_mod


@pytest.fixture(autouse=True)
def _clear_db_handler_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ACME_SRV_DB_HANDLER", raising=False)


def test_normalize_short_names() -> None:
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


def test_cfg_handler_wins_over_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ACME_SRV_DB_HANDLER", "django")
    config: Dict[str, Dict[str, str]] = {"DBhandler": {"handler": "wsgi"}}
    assert (
        db_handler_mod.resolve_db_handler_module(config)
        == "acme2certifier.dbhandlers.wsgi_handler"
    )


def test_env_used_when_cfg_has_no_handler(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ACME_SRV_DB_HANDLER", "django")
    config: Dict[str, Dict[str, str]] = {"DBhandler": {"dbfile": "/tmp/x.db"}}
    assert (
        db_handler_mod.resolve_db_handler_module(config)
        == "acme2certifier.dbhandlers.django_handler"
    )


def test_default_is_wsgi() -> None:
    config: Dict[str, Dict[str, str]] = {"DBhandler": {}}
    assert (
        db_handler_mod.resolve_db_handler_module(config)
        == "acme2certifier.dbhandlers.wsgi_handler"
    )


def test_handler_module_wins_over_handler() -> None:
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


def test_load_wsgi_handler_exports_dbstore() -> None:
    loaded = db_handler_mod.load_db_handler_module({"DBhandler": {"handler": "wsgi"}})
    assert hasattr(loaded, "DBstore")
    assert loaded.__name__ == "acme2certifier.dbhandlers.wsgi_handler"


def test_log_active_db_handler(caplog: pytest.LogCaptureFixture) -> None:
    logger = logging.getLogger("test.db_handler_startup")
    with caplog.at_level(logging.INFO, logger="test.db_handler_startup"):
        db_handler_mod.log_active_db_handler(logger)
    assert any("Using DB handler" in rec.message for rec in caplog.records)


def test_package_db_handler_reexports_dbstore() -> None:
    # Module already imported at collection time with default wsgi backend.
    assert hasattr(db_handler_mod, "DBstore")
    assert callable(db_handler_mod.DBstore)


def test_wsgi_backend_module_exports_dbstore() -> None:
    mod = importlib.import_module("acme2certifier.dbhandlers.wsgi_handler")
    assert mod.DBstore is not None
    assert mod.DBstore.__module__ == "acme2certifier.dbhandlers.wsgi_handler"
