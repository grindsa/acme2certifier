# -*- coding: utf-8 -*-
"""Tests for CAHandlerRegistry (Phase A — classical mode foundation)."""

from __future__ import annotations

import configparser
import logging
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from acme2certifier.acme_srv.helpers.cahandler_registry import (
    BoundCAHandler,
    CAHandlerRegistry,
)
from acme2certifier.acme_srv.helpers.config import (
    cahandler_config_section_set,
    cahandler_config_section_reset,
    load_config,
    load_config_section,
)


class _DummyHandler:
    config_section = "CAhandler"

    def __init__(self, debug: bool = False, logger=None):
        self.debug = debug
        self.logger = logger

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def _config_load(self):
        config_dic = load_config(self.logger, "CAhandler")
        self.api_host = config_dic.get("CAhandler", "api_host", fallback=None)


@pytest.fixture(name="logger")
def fixture_logger() -> logging.Logger:
    return logging.getLogger("test_cahandler_registry")


def _cfg(sections: dict) -> configparser.ConfigParser:
    config = configparser.ConfigParser()
    for section, options in sections.items():
        if not config.has_section(section):
            config.add_section(section)
        for key, value in options.items():
            config.set(section, key, value)
    return config


@patch("acme2certifier.acme_srv.helpers.cahandler_registry.ca_handler_load_from_section")
def test_classical_mode_single_handler(mock_load, logger: logging.Logger) -> None:
    module = SimpleNamespace(CAhandler=_DummyHandler)
    mock_load.return_value = module
    config = _cfg({"CAhandler": {"handler_module": "acme2certifier.cahandlers.openssl_ca_handler"}})

    registry = CAHandlerRegistry(logger).load(config)

    assert registry.multi_handler is False
    bound = registry.resolve()
    assert bound is not None
    assert bound.name == "default"
    with bound(False, logger) as inst:
        assert inst.config_section == "CAhandler"


@patch("acme2certifier.acme_srv.helpers.cahandler_registry.ca_handler_load_from_section")
def test_multi_handler_config_parse(mock_load, logger: logging.Logger) -> None:
    module = SimpleNamespace(CAhandler=_DummyHandler)
    mock_load.return_value = module
    config = _cfg(
        {
            "CAhandler": {
                "multi_handler": "True",
                "default_handler": "openssl",
            },
            "CAhandler:openssl": {
                "handler_module": "acme2certifier.cahandlers.openssl_ca_handler",
            },
            "Order": {
                "profile_cahandler": '{"long": "ejbca"}',
            },
        }
    )

    registry = CAHandlerRegistry(logger).load(config)

    assert registry.multi_handler is True
    assert registry.default_name == "openssl"
    assert "openssl" in registry.handlers
    assert registry.profile_cahandler == {"long": "ejbca"}


def test_load_config_honors_bound_section_via_context(logger: logging.Logger) -> None:
    config = _cfg(
        {
            "CAhandler": {"shared_flag": "yes"},
            "CAhandler:ejbca": {"api_host": "https://ejbca.example"},
        }
    )

    with patch(
        "acme2certifier.acme_srv.helpers.config._read_config_file",
        return_value="",
    ), patch(
        "acme2certifier.acme_srv.helpers.config._parse_config_content",
        return_value=(config, "ini"),
    ):
        token = cahandler_config_section_set("CAhandler:ejbca")
        try:
            merged = load_config(logger)
        finally:
            cahandler_config_section_reset(token)

    assert merged.get("CAhandler", "api_host") == "https://ejbca.example"
    assert merged.get("CAhandler", "shared_flag") == "yes"


def test_load_config_section_aliases_named_section(logger: logging.Logger) -> None:
    config = _cfg(
        {
            "CAhandler": {"shared_flag": "yes"},
            "CAhandler:ejbca": {"api_host": "https://ejbca.example"},
        }
    )

    with patch(
        "acme2certifier.acme_srv.helpers.config._read_config_file",
        return_value="",
    ), patch(
        "acme2certifier.acme_srv.helpers.config._parse_config_content",
        return_value=(config, "ini"),
    ):
        merged = load_config_section(logger, "CAhandler:ejbca")

    assert merged.get("CAhandler", "api_host") == "https://ejbca.example"
    assert merged.get("CAhandler", "shared_flag") == "yes"


def test_bound_cahandler_load_config_in_context(logger: logging.Logger) -> None:
    config = _cfg(
        {
            "CAhandler": {"shared_flag": "yes"},
            "CAhandler:ejbca": {"api_host": "https://ejbca.example"},
        }
    )
    bound = BoundCAHandler(_DummyHandler, "CAhandler:ejbca", "ejbca")

    with patch(
        "acme2certifier.acme_srv.helpers.config._read_config_file",
        return_value="",
    ), patch(
        "acme2certifier.acme_srv.helpers.config._parse_config_content",
        return_value=(config, "ini"),
    ):
        with bound(False, logger) as handler:
            handler._config_load()

    assert handler.api_host == "https://ejbca.example"
