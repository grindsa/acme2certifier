# -*- coding: utf-8 -*-
"""Tests for acme_srv.helpers.config."""

from __future__ import annotations

import configparser
import logging
import os
import warnings
from collections.abc import Callable
from contextlib import AbstractContextManager
from typing import Any
from unittest.mock import MagicMock, Mock, patch

import pytest

from acme2certifier.acme_srv.helpers.config import (
    client_parameter_validate,
    config_allowed_domainlist_load,
    config_allowed_iplist_load,
    config_async_mode_load,
    config_check,
    config_dns_server_list_load,
    config_dryrun_load,
    config_eab_profile_load,
    config_enroll_config_log_load,
    config_headerinfo_load,
    config_profile_load,
    config_proxy_load,
    header_info_lookup,
    load_config,
    profile_lookup,
)

pytestmark = pytest.mark.usefixtures("clear_config_cache", "_silence_logging")


def test_126_helper_config_dns_server_list_load_defaults(
    logger: logging.Logger,
) -> None:
    """config_dns_server_list_load returns defaults when no settings are present."""
    config_dic = {}
    dns_server_list, dns_validation_pause_timer = config_dns_server_list_load(
        logger, config_dic
    )
    assert [] == dns_server_list
    assert 0.5 == dns_validation_pause_timer


def test_127_helper_config_dns_server_list_load_default_section(
    logger: logging.Logger,
) -> None:
    """config_dns_server_list_load loads dns_server_list from DEFAULT section."""
    config_dic = {"DEFAULT": {"dns_server_list": '["1.1.1.1", "8.8.8.8"]'}}
    dns_server_list, dns_validation_pause_timer = config_dns_server_list_load(
        logger, config_dic
    )
    assert ["1.1.1.1", "8.8.8.8"] == dns_server_list
    assert 0.5 == dns_validation_pause_timer


def test_128_helper_config_dns_server_list_load_default_section_parse_error(
    logger: logging.Logger, capture_logs: Callable[..., AbstractContextManager[Any]]
) -> None:
    """config_dns_server_list_load logs warning on invalid DEFAULT dns_server_list."""
    config_dic = {"DEFAULT": {"dns_server_list": "not-json"}}
    with capture_logs("test_a2c", level="DEBUG") as log_context:
        dns_server_list, dns_validation_pause_timer = config_dns_server_list_load(
            logger, config_dic
        )
    assert [] == dns_server_list
    assert 0.5 == dns_validation_pause_timer
    assert any(
        (
            "Failed to load dns_server_list from configuration" in record.message
            for record in log_context.records
            if record.levelname == "WARNING"
        )
    )


def test_129_helper_config_dns_server_list_load_challenge_section_and_timer(
    logger: logging.Logger, capture_logs: Callable[..., AbstractContextManager[Any]]
) -> None:
    """config_dns_server_list_load handles deprecated Challenge section and timer."""
    config_dic = {
        "Challenge": {
            "dns_server_list": '["9.9.9.9"]',
            "dns_validation_pause_timer": "7",
        }
    }
    with capture_logs("test_a2c", level="DEBUG") as log_context:
        dns_server_list, dns_validation_pause_timer = config_dns_server_list_load(
            logger, config_dic
        )
    assert ["9.9.9.9"] == dns_server_list
    assert 7 == dns_validation_pause_timer
    assert any(
        (
            "dns_server_list parameter found in Challenge section - this is deprecated"
            in record.message
            for record in log_context.records
            if record.levelname == "WARNING"
        )
    )


def test_130_helper_config_dns_server_list_load_challenge_section_parse_errors(
    logger: logging.Logger, capture_logs: Callable[..., AbstractContextManager[Any]]
) -> None:
    """config_dns_server_list_load logs warnings on invalid Challenge values."""
    config_dic = {
        "Challenge": {
            "dns_server_list": "bad-json",
            "dns_validation_pause_timer": "NaN",
        }
    }
    with capture_logs("test_a2c", level="DEBUG") as log_context:
        dns_server_list, dns_validation_pause_timer = config_dns_server_list_load(
            logger, config_dic
        )
    assert [] == dns_server_list
    assert 0.5 == dns_validation_pause_timer
    assert any(
        (
            "Failed to load dns_server_list from configuration" in record.message
            for record in log_context.records
            if record.levelname == "WARNING"
        )
    )
    assert any(
        (
            "Failed to parse dns_validation_pause_timer from configuration"
            in record.message
            for record in log_context.records
            if record.levelname == "WARNING"
        )
    )


@patch("configparser.RawConfigParser")
def test_225_load_config(mock_parser: MagicMock) -> None:
    """load config"""
    assert load_config(None, None, None)


@patch("configparser.RawConfigParser")
def test_226_load_config(mock_parser: MagicMock, logger: logging.Logger) -> None:
    """load config"""
    assert load_config(logger, None, None)


@patch.dict("os.environ", {"ACME_SRV_CONFIGFILE": "ACME_SRV_CONFIGFILE"})
@patch("configparser.RawConfigParser")
def test_227_load_config(mock_parser: MagicMock) -> None:
    """load config"""
    assert load_config(None, None, None)


def test_228_load_config_logs_path_and_source_once(
    logger: logging.Logger, capture_logs: Callable[..., AbstractContextManager[Any]]
) -> None:
    """successful load emits Loaded acme_srv.cfg INFO once per path"""
    import tempfile
    from acme2certifier.acme_srv.helpers import config as config_mod

    config_mod._ACME_SRV_CFG_LOADED.clear()
    config_mod._LAST_LOADED_CFG = None
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".cfg", delete=False, encoding="utf8"
    ) as handle:
        handle.write("[DEFAULT]\ndebug: False\n")
        cfg_path = handle.name
    try:
        abs_path = os.path.abspath(cfg_path)
        with capture_logs("test_a2c", level="INFO") as lcm1:
            load_config(logger, None, cfg_path)
        assert (
            f"INFO:test_a2c:Loaded acme_srv.cfg {abs_path} (explicit, ini)"
            in lcm1.output
        )
        with capture_logs("test_a2c", level="DEBUG") as lcm2:
            load_config(logger, None, cfg_path)
        assert not any(
            (
                line.startswith("INFO:test_a2c:Loaded acme_srv.cfg")
                for line in lcm2.output
            )
        )
        assert any(
            (
                f"DEBUG:test_a2c:Loaded acme_srv.cfg {abs_path} (explicit, ini)" in line
                for line in lcm2.output
            )
        )
    finally:
        os.unlink(cfg_path)
        config_mod._ACME_SRV_CFG_LOADED.clear()
        config_mod._LAST_LOADED_CFG = None
        config_mod.load_config_cache_clear()


def test_229_load_config_logs_env_source(
    logger: logging.Logger, capture_logs: Callable[..., AbstractContextManager[Any]]
) -> None:
    """ACME_SRV_CONFIGFILE source is reflected in the once-INFO line"""
    import tempfile
    from acme2certifier.acme_srv.helpers import config as config_mod

    config_mod._ACME_SRV_CFG_LOADED.clear()
    config_mod._LAST_LOADED_CFG = None
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".cfg", delete=False, encoding="utf8"
    ) as handle:
        handle.write("[DEFAULT]\ndebug: False\n")
        cfg_path = handle.name
    try:
        abs_path = os.path.abspath(cfg_path)
        with patch.dict("os.environ", {"ACME_SRV_CONFIGFILE": cfg_path}):
            with capture_logs("test_a2c", level="INFO") as lcm:
                load_config(logger, None, None)
        assert (
            f"INFO:test_a2c:Loaded acme_srv.cfg {abs_path} (ACME_SRV_CONFIGFILE, ini)"
            in lcm.output
        )
    finally:
        os.unlink(cfg_path)
        config_mod._ACME_SRV_CFG_LOADED.clear()
        config_mod._LAST_LOADED_CFG = None
        config_mod.load_config_cache_clear()


def test_230_load_config_cache_reuses_parser(logger: logging.Logger) -> None:
    """second load_config() for the same path does not re-read the file"""
    import tempfile
    from acme2certifier.acme_srv.helpers import config as config_mod

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".cfg", delete=False, encoding="utf8"
    ) as handle:
        handle.write("[DEFAULT]\ndebug: False\n[CAhandler]\nshared: 1\n")
        cfg_path = handle.name
    try:
        first = load_config(logger, None, cfg_path)
        with patch.object(
            config_mod, "_read_config_file", side_effect=AssertionError("re-read")
        ):
            second = load_config(logger, None, cfg_path)
        assert first is second
        assert first.get("CAhandler", "shared") == "1"
    finally:
        os.unlink(cfg_path)
        config_mod.load_config_cache_clear()


def test_231_load_config_cache_clear_rereads(logger: logging.Logger) -> None:
    """load_config_cache_clear() forces a re-read of the same path"""
    import tempfile
    from acme2certifier.acme_srv.helpers import config as config_mod

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".cfg", delete=False, encoding="utf8"
    ) as handle:
        handle.write("[DEFAULT]\nvalue: a\n")
        cfg_path = handle.name
    try:
        first = load_config(logger, None, cfg_path)
        assert first.get("DEFAULT", "value") == "a"
        with open(cfg_path, "w", encoding="utf8") as handle:
            handle.write("[DEFAULT]\nvalue: b\n")
        stale = load_config(logger, None, cfg_path)
        assert stale.get("DEFAULT", "value") == "a"
        config_mod.load_config_cache_clear()
        refreshed = load_config(logger, None, cfg_path)
        assert refreshed.get("DEFAULT", "value") == "b"
    finally:
        os.unlink(cfg_path)
        config_mod.load_config_cache_clear()


def test_232_load_config_missing_file_not_cached(logger: logging.Logger) -> None:
    """OSError / missing file is not cached"""
    import tempfile
    from acme2certifier.acme_srv.helpers import config as config_mod

    cfg_path = tempfile.mktemp(suffix=".cfg")
    empty = load_config(logger, None, cfg_path)
    assert list(empty.sections()) == []
    with open(cfg_path, "w", encoding="utf8") as handle:
        handle.write("[DEFAULT]\nvalue: later\n")
    try:
        loaded = load_config(logger, None, cfg_path)
        assert loaded.get("DEFAULT", "value") == "later"
    finally:
        os.unlink(cfg_path)
        config_mod.load_config_cache_clear()


def test_233_load_config_merge_after_cache_hit(logger: logging.Logger) -> None:
    """Bound-section overlay still runs on a cache hit and does not store the merge"""
    import tempfile
    from acme2certifier.acme_srv.helpers import config as config_mod
    from acme2certifier.acme_srv.helpers.config import (
        cahandler_config_section_reset,
        cahandler_config_section_set,
    )

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".cfg", delete=False, encoding="utf8"
    ) as handle:
        handle.write(
            "[CAhandler]\nshared: yes\n[CAhandler:ejbca]\napi_host: https://ejbca.example\n"
        )
        cfg_path = handle.name
    token = None
    try:
        with patch.dict("os.environ", {"ACME_SRV_CONFIGFILE": cfg_path}):
            cached = load_config(logger, None, None)
            assert not cached.has_option("CAhandler", "api_host")
            token = cahandler_config_section_set("CAhandler:ejbca")
            merged = load_config(logger, None, None)
            assert merged.get("CAhandler", "api_host") == "https://ejbca.example"
            assert merged.get("CAhandler", "shared") == "yes"
            cahandler_config_section_reset(token)
            token = None
            after = load_config(logger, None, None)
            assert not after.has_option("CAhandler", "api_host")
            assert after.has_section("CAhandler:ejbca")
    finally:
        if token is not None:
            cahandler_config_section_reset(token)
        os.unlink(cfg_path)
        config_mod.load_config_cache_clear()


def test_236_log_loaded_acme_srv_cfg_after_deferred_load(
    logger: logging.Logger, capture_logs: Callable[..., AbstractContextManager[Any]]
) -> None:
    """load_config() without logger defers INFO until log_loaded_acme_srv_cfg"""
    import tempfile
    from acme2certifier.acme_srv.helpers import config as config_mod

    config_mod._ACME_SRV_CFG_LOADED.clear()
    config_mod._LAST_LOADED_CFG = None
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".cfg", delete=False, encoding="utf8"
    ) as handle:
        handle.write("[DEFAULT]\ndebug: False\n")
        cfg_path = handle.name
    try:
        abs_path = os.path.abspath(cfg_path)
        load_config(None, None, cfg_path)
        assert config_mod._LAST_LOADED_CFG == (abs_path, "explicit", "ini")
        assert abs_path not in config_mod._ACME_SRV_CFG_LOADED
        with capture_logs("test_a2c", level="INFO") as lcm:
            config_mod.log_loaded_acme_srv_cfg(logger)
        assert (
            f"INFO:test_a2c:Loaded acme_srv.cfg {abs_path} (explicit, ini)"
            in lcm.output
        )
    finally:
        os.unlink(cfg_path)
        config_mod._ACME_SRV_CFG_LOADED.clear()
        config_mod._LAST_LOADED_CFG = None
        config_mod.load_config_cache_clear()


def test_335_config_check(
    logger: logging.Logger, capture_logs: Callable[..., AbstractContextManager[Any]]
) -> None:
    """test config check"""
    config_dic = {"foo": {"bar": '"foobar"'}}
    with capture_logs("test_a2c", level="INFO") as lcm:
        config_check(logger, config_dic)
    assert (
        'WARNING:test_a2c:Section foo option: bar contains " characters. Please check if this is required!'
        in lcm.output
    )


@patch("acme2certifier.acme_srv.helpers.config.profile_lookup")
@patch("acme2certifier.acme_srv.helpers.config.header_info_lookup")
def test_389_client_parameter_validate(
    mock_lookup: MagicMock,
    mock_profile: MagicMock,
    logger: logging.Logger,
    FakeDBStore: type[Any],
) -> None:
    """test client_parameter_validate"""
    mock_lookup.return_value = "value2"
    mock_profile.return_value = "value1"
    cahandler = FakeDBStore()
    cahandler.profiles = {"foo": "bar"}
    assert ("value1", None) == client_parameter_validate(
        logger, "csr", cahandler, "key", ["value0", "value1", "value2"]
    )
    assert not mock_lookup.called
    assert mock_profile.called


@patch("acme2certifier.acme_srv.helpers.config.profile_lookup")
@patch("acme2certifier.acme_srv.helpers.config.header_info_lookup")
def test_390_client_parameter_validate(
    mock_lookup: MagicMock,
    mock_profile: MagicMock,
    logger: logging.Logger,
    FakeDBStore: type[Any],
) -> None:
    """test client_parameter_validate"""
    mock_lookup.return_value = "value2"
    cahandler = FakeDBStore()
    assert ("value2", None) == client_parameter_validate(
        logger, "csr", cahandler, "key", ["value0", "value2"]
    )
    assert mock_lookup.called
    assert not mock_profile.called


@patch("acme2certifier.acme_srv.helpers.config.profile_lookup")
@patch("acme2certifier.acme_srv.helpers.config.header_info_lookup")
def test_391_client_parameter_validate(
    mock_lookup: MagicMock,
    mock_profile: MagicMock,
    logger: logging.Logger,
    FakeDBStore: type[Any],
) -> None:
    """test client_parameter_validate"""
    mock_lookup.return_value = "unk_value"
    cahandler = FakeDBStore()
    assert (None, 'parameter "unk_value" is not allowed') == client_parameter_validate(
        logger, "csr", cahandler, "parameter", ["value0", "value2"]
    )
    assert mock_lookup.called
    assert not mock_profile.called


@patch("acme2certifier.acme_srv.helpers.config.profile_lookup")
@patch("acme2certifier.acme_srv.helpers.config.header_info_lookup")
def test_392_client_parameter_validate(
    mock_lookup: MagicMock,
    mock_profile: MagicMock,
    logger: logging.Logger,
    FakeDBStore: type[Any],
) -> None:
    """test client_parameter_validate"""
    mock_lookup.return_value = None
    cahandler = FakeDBStore()
    assert ("value0", None) == client_parameter_validate(
        logger, "csr", cahandler, "parameter", ["value0", "value2"]
    )
    assert mock_lookup.called
    assert not mock_profile.called


@patch("acme2certifier.acme_srv.helpers.network.header_info_get")
def test_393_header_info_lookup(mock_info: MagicMock, logger: logging.Logger) -> None:
    """test header_info_lookup"""
    mock_info.return_value = [
        {"header_info": '{"header_info_field": "foo1=value1 foo2=value2"}'}
    ]
    assert "value1" == header_info_lookup(logger, "csr", "header_info_field", "foo1")


@patch("acme2certifier.acme_srv.helpers.network.header_info_get")
def test_394_header_info_lookup(mock_info: MagicMock, logger: logging.Logger) -> None:
    """test header_info_lookup"""
    mock_info.return_value = [
        {"header_info": '{"header_info_field": "foo1=value1=foo foo2=value2=foo"}'}
    ]
    assert "value1=foo" == header_info_lookup(
        logger, "csr", "header_info_field", "foo1"
    )


@patch("acme2certifier.acme_srv.helpers.network.header_info_get")
def test_395_header_info_lookup(mock_info: MagicMock, logger: logging.Logger) -> None:
    """test header_info_lookup"""
    mock_info.return_value = None
    assert not header_info_lookup(logger, "csr", "header_info_field", "foo1")


@patch("acme2certifier.acme_srv.helpers.network.header_info_get")
def test_396_header_info_lookup(
    mock_info: MagicMock,
    logger: logging.Logger,
    capture_logs: Callable[..., AbstractContextManager[Any]],
) -> None:
    """test header_info_lookup"""
    mock_info.return_value = [
        {"foo": '{"header_info_field": "foo1=value1 foo2=value2"}'}
    ]
    with capture_logs("test_a2c", level="INFO") as lcm:
        assert not header_info_lookup(logger, "csr", "header_info_field", "foo1")
    assert (
        "WARNING:test_a2c:Header_info_field not found in header info: header_info_field"
        in lcm.output
    )


@patch("acme2certifier.acme_srv.helpers.network.header_info_get")
def test_397_header_info_lookup(
    mock_info: MagicMock,
    logger: logging.Logger,
    capture_logs: Callable[..., AbstractContextManager[Any]],
) -> None:
    """test header_info_lookup"""
    mock_info.return_value = [{"header_info": '{"foo": "foo1=value1 foo2=value2"}'}]
    with capture_logs("test_a2c", level="INFO") as lcm:
        assert not header_info_lookup(logger, "csr", "header_info_field", "foo1")
    assert (
        "WARNING:test_a2c:Header_info_field not found in header info: header_info_field"
        in lcm.output
    )


@patch("acme2certifier.acme_srv.helpers.network.header_info_get")
def test_398_header_info_lookup(
    mock_info: MagicMock,
    logger: logging.Logger,
    capture_logs: Callable[..., AbstractContextManager[Any]],
) -> None:
    """test header_info_lookup"""
    mock_info.return_value = "bump"
    with capture_logs("test_a2c", level="INFO") as lcm:
        assert not header_info_lookup(logger, "csr", "header_info_field", "foo1")
    assert (
        "WARNING:test_a2c:Header_info_field not found in header info: header_info_field"
        in lcm.output
    )


@patch("acme2certifier.acme_srv.helpers.config.json.loads")
@patch("acme2certifier.acme_srv.helpers.network.header_info_get")
def test_399_header_info_lookup(
    mock_info: MagicMock,
    mock_json: MagicMock,
    logger: logging.Logger,
    capture_logs: Callable[..., AbstractContextManager[Any]],
) -> None:
    """test header_info_lookup"""
    mock_info.return_value = [{"header_info": "foo1=value1 foo2=value2"}]
    mock_json.side_effect = Exception("mock_json")
    with capture_logs("test_a2c", level="INFO") as lcm:
        assert not header_info_lookup(logger, "csr", "header_info_field", "foo1")
    assert "ERROR:test_a2c:Could not parse header_info_field: mock_json" in lcm.output


def test_400_config_headerinfo_load(logger: logging.Logger) -> None:
    """test config_headerinfo_load()"""
    config_dic = {"Order": {"header_info_list": '["foo", "bar", "foobar"]'}}
    assert "foo" == config_headerinfo_load(logger, config_dic)


def test_401_config_headerinfo_load(logger: logging.Logger) -> None:
    """test config_headerinfo_load()"""
    config_dic = {"Order": {"header_info_list": '["foo"]'}}
    assert "foo" == config_headerinfo_load(logger, config_dic)


def test_402_config_headerinfo_load(
    logger: logging.Logger, capture_logs: Callable[..., AbstractContextManager[Any]]
) -> None:
    """test config_headerinfo_load()"""
    config_dic = {"Order": {"header_info_list": "foo"}}
    with capture_logs("test_a2c", level="INFO") as lcm:
        assert not config_headerinfo_load(logger, config_dic)
    assert (
        "WARNING:test_a2c:Failed to parse header_info_list from configuration: Expecting value: line 1 column 1 (char 0)"
        in lcm.output
    )


@patch("acme2certifier.acme_srv.helpers.config.eab_handler_load")
def test_403_config_eab_profile_load(
    mock_eabload: MagicMock, logger: logging.Logger
) -> None:
    """test config_eab_profiling()"""
    config_dic = configparser.ConfigParser()
    config_dic["EABhandler"] = {
        "eab_profiling": True,
        "eab_handler_file": "eab_handler_file",
    }
    eabl = Mock()
    eabl.EABhandler = "bar"
    mock_eabload.return_value = eabl
    assert (True, "bar") == config_eab_profile_load(logger, config_dic)
    assert mock_eabload.called


@patch("acme2certifier.acme_srv.helpers.config.eab_handler_load")
def test_404_config_eab_profile_load(
    mock_eabload: MagicMock,
    logger: logging.Logger,
    capture_logs: Callable[..., AbstractContextManager[Any]],
) -> None:
    """test config_eab_profiling()"""
    config_dic = configparser.ConfigParser()
    config_dic["CAhandler"] = {"eab_profiling": True}
    config_dic["EABhandler"] = {"eab_handler_file": "eab_handler_file"}
    eabl = Mock()
    eabl.EABhandler = "bar"
    mock_eabload.return_value = eabl
    with capture_logs("test_a2c", level="INFO") as lcm:
        assert (True, "bar") == config_eab_profile_load(logger, config_dic)
    assert mock_eabload.called
    assert (
        "WARNING:test_a2c:eab_profiling found in CAhandler section - this is deprecated, please use EABhandler section"
        in lcm.output
    )


@patch("acme2certifier.acme_srv.helpers.config.eab_handler_load")
def test_405_config_eab_profile_load(
    mock_eabload: MagicMock,
    logger: logging.Logger,
    capture_logs: Callable[..., AbstractContextManager[Any]],
) -> None:
    """test config_eab_profiling()"""
    config_dic = configparser.ConfigParser()
    config_dic["CAhandler"] = {"eab_profiling": "aa"}
    config_dic["EABhandler"] = {"eab_handler_file": "eab_handler_file"}
    eabl = Mock()
    eabl.EABhandler = "bar"
    mock_eabload.return_value = eabl
    with capture_logs("test_a2c", level="INFO") as lcm:
        assert (False, None) == config_eab_profile_load(logger, config_dic)
    assert not mock_eabload.called
    assert (
        "WARNING:test_a2c:eab_profiling found in CAhandler section - this is deprecated, please use EABhandler section"
        in lcm.output
    )
    assert (
        "ERROR:test_a2c:Failed to load eabprofile from configuration: Not a boolean: aa"
        in lcm.output
    )


@patch("acme2certifier.acme_srv.helpers.config.eab_handler_load")
def test_406_config_eab_profile_load(
    mock_eabload: MagicMock,
    logger: logging.Logger,
    capture_logs: Callable[..., AbstractContextManager[Any]],
) -> None:
    """test config_eab_profiling()"""
    config_dic = configparser.ConfigParser()
    config_dic["EABhandler"] = {"eab_profiling": True}
    eabl = Mock()
    eabl.EABhandler = "bar"
    mock_eabload.return_value = eabl
    with capture_logs("test_a2c", level="INFO") as lcm:
        assert (True, None) == config_eab_profile_load(logger, config_dic)
    assert not mock_eabload.called
    assert "CRITICAL:test_a2c:Configuration error: EABHandler incomplete" in lcm.output
    assert not mock_eabload.called


@patch("acme2certifier.acme_srv.helpers.config.eab_handler_load")
def test_407_config_eab_profile_load(
    mock_eabload: MagicMock,
    logger: logging.Logger,
    capture_logs: Callable[..., AbstractContextManager[Any]],
) -> None:
    """test config_eab_profiling()"""
    config_dic = configparser.ConfigParser()
    config_dic["EABhandler"] = {
        "eab_profiling": True,
        "eab_handler_file": "eab_handler_file",
    }
    mock_eabload.return_value = None
    with capture_logs("test_a2c", level="INFO") as lcm:
        assert (True, None) == config_eab_profile_load(logger, config_dic)
    assert mock_eabload.called
    assert "CRITICAL:test_a2c:EABHandler could not get loaded" in lcm.output


@patch("acme2certifier.acme_srv.helpers.config.eab_handler_load")
def test_408_config_eab_profile_load(
    mock_eabload: MagicMock, logger: logging.Logger
) -> None:
    """test config_eab_profiling()"""
    config_dic = configparser.ConfigParser()
    config_dic["EABhandler"] = {
        "eab_profiling": False,
        "eab_handler_file": "eab_handler_file",
    }
    assert (False, None) == config_eab_profile_load(logger, config_dic)
    assert not mock_eabload.called


@patch("acme2certifier.acme_srv.helpers.config.eab_handler_load")
def test_409_config_eab_profile_load(
    mock_eabload: MagicMock, logger: logging.Logger
) -> None:
    """test config_eab_profiling()"""
    config_dic = configparser.ConfigParser()
    config_dic["EABhandler"] = {
        "eab_profiling": "aa",
        "eab_handler_file": "eab_handler_file",
    }
    assert (False, None) == config_eab_profile_load(logger, config_dic)
    assert not mock_eabload.called


def test_479_config_enroll_config_log_load(logger: logging.Logger) -> None:
    """test config_enroll_config_log_load()"""
    config_dic = configparser.ConfigParser()
    config_dic["CAhandler"] = {"enrollment_config_log": "True"}
    assert (True, []) == config_enroll_config_log_load(logger, config_dic)


def test_480_config_enroll_config_log_load(logger: logging.Logger) -> None:
    """test config_enroll_config_log_load()"""
    config_dic = configparser.ConfigParser()
    config_dic["CAhandler"] = {"enrollment_config_log": "False"}
    assert (False, []) == config_enroll_config_log_load(logger, config_dic)


def test_481_config_enroll_config_log_load(
    logger: logging.Logger, capture_logs: Callable[..., AbstractContextManager[Any]]
) -> None:
    """test config_enroll_config_log_load()"""
    config_dic = configparser.ConfigParser()
    config_dic["CAhandler"] = {"enrollment_config_log": "aaa"}
    with capture_logs("test_a2c", level="INFO") as lcm:
        assert (False, []) == config_enroll_config_log_load(logger, config_dic)
    assert (
        "WARNING:test_a2c:Failed to load enrollment_config_log from configuration: Not a boolean: aaa"
        in lcm.output
    )


def test_482_config_enroll_config_log_load(logger: logging.Logger) -> None:
    """test config_enroll_config_log_load()"""
    config_dic = configparser.ConfigParser()
    config_dic["CAhandler"] = {
        "enrollment_config_log": "True",
        "enrollment_config_log_skip_list": '["foo", "bar"]',
    }
    assert (True, ["foo", "bar"]) == config_enroll_config_log_load(logger, config_dic)


def test_483_config_enroll_config_log_load(
    logger: logging.Logger, capture_logs: Callable[..., AbstractContextManager[Any]]
) -> None:
    """test config_enroll_config_log_load()"""
    config_dic = configparser.ConfigParser()
    config_dic["CAhandler"] = {
        "enrollment_config_log": "True",
        "enrollment_config_log_skip_list": '"foo",',
    }
    with capture_logs("test_a2c", level="INFO") as lcm:
        assert (True, "failed to parse") == config_enroll_config_log_load(
            logger, config_dic
        )
    assert (
        "WARNING:test_a2c:Failed to parse enrollment_config_log_skip_list from configuration: Extra data: line 1 column 6 (char 5)"
        in lcm.output
    )


def test_484_config_allowed_domainlist_load(logger: logging.Logger) -> None:
    """test config_allowed_domainlist_load()"""
    config_dic = {"CAhandler": {"allowed_domainlist": '["foo", "bar", "foobar"]'}}
    assert ["foo", "bar", "foobar"] == config_allowed_domainlist_load(
        logger, config_dic
    )


def test_485_config_allowed_domainlist_load(logger: logging.Logger) -> None:
    """test config_allowed_domainlist_load()"""
    config_dic = {"CAhandler": {"allowed_domainlist": '["foo"]'}}
    assert ["foo"] == config_allowed_domainlist_load(logger, config_dic)


def test_486_config_allowed_domainlist_load(
    logger: logging.Logger, capture_logs: Callable[..., AbstractContextManager[Any]]
) -> None:
    """test config_allowed_domainlist_load()"""
    config_dic = {"CAhandler": {"allowed_domainlist": "foo"}}
    with capture_logs("test_a2c", level="INFO") as lcm:
        assert "failed to parse" == config_allowed_domainlist_load(logger, config_dic)
    assert (
        "WARNING:test_a2c:Failed to load allowed_domainlist from configuration: Expecting value: line 1 column 1 (char 0)"
        in lcm.output
    )


def test_513_config_profile_load(logger: logging.Logger) -> None:
    """test _config_load with unknown values config"""
    parser = configparser.ConfigParser()
    parser["Order"] = {"profiles": '{"foo": "bar", "bar": "foo"}'}
    assert {"foo": "bar", "bar": "foo"} == config_profile_load(logger, parser)


def test_514_config_profile_load(
    logger: logging.Logger, capture_logs: Callable[..., AbstractContextManager[Any]]
) -> None:
    """test _config_load with unknown values config"""
    parser = configparser.ConfigParser()
    parser["Order"] = {"profiles": "foo"}
    with capture_logs("test_a2c", level="INFO") as lcm:
        assert not config_profile_load(logger, parser)
    assert (
        "WARNING:test_a2c:Failed to load profiles from configuration: Expecting value: line 1 column 1 (char 0)"
        in lcm.output
    )


def test_515_profile_lookup(logger: logging.Logger) -> None:
    """profile_lookup ()"""
    models_mock = MagicMock()
    models_mock.DBstore().certificates_search.return_value = [
        {"foo": "bar", "order__profile": "order_profile"}
    ]
    modules = {"acme2certifier.acme_srv.db_handler": models_mock}
    patch.dict("sys.modules", modules).start()
    assert "order_profile" == profile_lookup(logger, "csr")


def test_516_profile_lookup(logger: logging.Logger) -> None:
    """profile_lookup ()"""
    models_mock = MagicMock()
    models_mock.DBstore().certificates_search.return_value = None
    modules = {"acme2certifier.acme_srv.db_handler": models_mock}
    patch.dict("sys.modules", modules).start()
    assert not profile_lookup(logger, "csr")


def test_517_profile_lookup(logger: logging.Logger) -> None:
    """profile_lookup ()"""
    models_mock = MagicMock()
    models_mock.DBstore().certificates_search.return_value = [{"foo": "bar"}]
    modules = {"acme2certifier.acme_srv.db_handler": models_mock}
    patch.dict("sys.modules", modules).start()
    assert not profile_lookup(logger, "csr")


def test_518_profile_lookup(
    logger: logging.Logger, capture_logs: Callable[..., AbstractContextManager[Any]]
) -> None:
    """profile_lookup ()"""
    models_mock = MagicMock()
    models_mock.DBstore().certificates_search.side_effect = Exception("mock_search")
    modules = {"acme2certifier.acme_srv.db_handler": models_mock}
    patch.dict("sys.modules", modules).start()
    with capture_logs("test_a2c", level="INFO") as lcm:
        assert not profile_lookup(logger, "csr")
    assert "WARNING:test_a2c:Profile lookup failed with: mock_search" in lcm.output


@patch("acme2certifier.acme_srv.helpers.network.proxy_check")
@patch("acme2certifier.acme_srv.helpers.network.parse_url")
def test_530_config_proxy_load_valid_config(
    mock_parse_url: MagicMock, mock_proxy_check: MagicMock, logger: logging.Logger
) -> None:
    """test config_proxy_load() with valid configuration"""
    config_dic = {
        "DEFAULT": {
            "proxy_server_list": '{"example.com": "proxy.example.com:8080", "*.test.com": "proxy.test.com:3128"}'
        }
    }
    host_name = "https://api.example.com:443/test"
    mock_parse_url.return_value = {"host": "api.example.com:443"}
    mock_proxy_check.return_value = "proxy.example.com:8080"
    result = config_proxy_load(logger, config_dic, host_name)
    expected = {"http": "proxy.example.com:8080", "https": "proxy.example.com:8080"}
    assert result == expected
    mock_parse_url.assert_called_once_with(logger, host_name)
    mock_proxy_check.assert_called_once_with(
        logger,
        "api.example.com",
        {"example.com": "proxy.example.com:8080", "*.test.com": "proxy.test.com:3128"},
    )


@patch("acme2certifier.acme_srv.helpers.network.proxy_check")
@patch("acme2certifier.acme_srv.helpers.network.parse_url")
def test_531_config_proxy_load_redacts_userinfo(
    mock_parse_url: MagicMock,
    mock_proxy_check: MagicMock,
    logger: logging.Logger,
    capture_logs: Callable[..., AbstractContextManager[Any]],
) -> None:
    """debug log of the selected proxy must not include userinfo"""
    config_dic = {
        "DEFAULT": {"proxy_server_list": '{"example.com": "http://proxy:8080"}'}
    }
    secret = "s3cret-pass"
    mock_parse_url.return_value = {"host": "api.example.com"}
    mock_proxy_check.return_value = f"http://alice:{secret}@proxy.example:8080"
    with capture_logs("test_a2c", level="DEBUG") as lcm:
        result = config_proxy_load(logger, config_dic, "https://api.example.com/test")
    assert result["http"] == f"http://alice:{secret}@proxy.example:8080"
    joined = "\n".join(lcm.output)
    assert secret not in joined
    assert "alice" not in joined
    assert "http://***@proxy.example:8080" in joined


def test_532_config_proxy_load_no_default_section(logger: logging.Logger) -> None:
    """test config_proxy_load() with no DEFAULT section"""
    config_dic = {"OTHER": {"some_setting": "value"}}
    host_name = "https://api.example.com:443/test"
    result = config_proxy_load(logger, config_dic, host_name)
    assert result == {}


def test_533_config_proxy_load_no_proxy_server_list(logger: logging.Logger) -> None:
    """test config_proxy_load() with no proxy_server_list in DEFAULT section"""
    config_dic = {"DEFAULT": {"other_setting": "value"}}
    host_name = "https://api.example.com:443/test"
    result = config_proxy_load(logger, config_dic, host_name)
    assert result == {}


def test_534_config_proxy_load_invalid_json(
    logger: logging.Logger, capture_logs: Callable[..., AbstractContextManager[Any]]
) -> None:
    """test config_proxy_load() with invalid JSON in proxy_server_list"""
    config_dic = {"DEFAULT": {"proxy_server_list": "invalid json string"}}
    host_name = "https://api.example.com:443/test"
    with capture_logs("test_a2c", level="INFO") as lcm:
        result = config_proxy_load(logger, config_dic, host_name)
    assert result == {}
    assert any(
        (
            "Failed to parse proxy_server_list from configuration:" in log
            for log in lcm.output
        )
    )


@patch("acme2certifier.acme_srv.helpers.network.parse_url")
def test_535_config_proxy_load_no_host_in_url(
    mock_parse_url: MagicMock, logger: logging.Logger
) -> None:
    """test config_proxy_load() with parsed URL missing host information"""
    config_dic = {
        "DEFAULT": {"proxy_server_list": '{"example.com": "proxy.example.com:8080"}'}
    }
    host_name = "invalid-url"
    mock_parse_url.return_value = {}
    result = config_proxy_load(logger, config_dic, host_name)
    assert result == {}
    mock_parse_url.assert_called_once_with(logger, host_name)


@patch("acme2certifier.acme_srv.helpers.network.proxy_check")
@patch("acme2certifier.acme_srv.helpers.network.parse_url")
def test_536_config_proxy_load_proxy_check_returns_none(
    mock_parse_url: MagicMock, mock_proxy_check: MagicMock, logger: logging.Logger
) -> None:
    """test config_proxy_load() when proxy_check returns None"""
    config_dic = {
        "DEFAULT": {"proxy_server_list": '{"other.com": "proxy.other.com:8080"}'}
    }
    host_name = "https://api.example.com:443/test"
    mock_parse_url.return_value = {"host": "api.example.com:443"}
    mock_proxy_check.return_value = None
    result = config_proxy_load(logger, config_dic, host_name)
    expected = {"http": None, "https": None}
    assert result == expected


@patch("acme2certifier.acme_srv.helpers.network.parse_url")
def test_537_config_proxy_load_parse_url_exception(
    mock_parse_url: MagicMock,
    logger: logging.Logger,
    capture_logs: Callable[..., AbstractContextManager[Any]],
) -> None:
    """test config_proxy_load() when parse_url raises exception"""
    config_dic = {
        "DEFAULT": {"proxy_server_list": '{"example.com": "proxy.example.com:8080"}'}
    }
    host_name = "https://api.example.com:443/test"
    mock_parse_url.side_effect = Exception("URL parsing error")
    with capture_logs("test_a2c", level="INFO") as lcm:
        result = config_proxy_load(logger, config_dic, host_name)
    assert result == {}
    assert any(
        (
            "Failed to parse proxy_server_list from configuration: URL parsing error"
            in log
            for log in lcm.output
        )
    )


@patch("acme2certifier.acme_srv.helpers.network.proxy_check")
@patch("acme2certifier.acme_srv.helpers.network.parse_url")
def test_538_config_proxy_load_host_without_port(
    mock_parse_url: MagicMock, mock_proxy_check: MagicMock, logger: logging.Logger
) -> None:
    """test config_proxy_load() with host that doesn't contain port"""
    config_dic = {
        "DEFAULT": {"proxy_server_list": '{"example.com": "proxy.example.com:8080"}'}
    }
    host_name = "https://api.example.com/test"
    mock_parse_url.return_value = {"host": "api.example.com"}
    mock_proxy_check.return_value = "proxy.example.com:8080"
    result = config_proxy_load(logger, config_dic, host_name)
    expected = {"http": "proxy.example.com:8080", "https": "proxy.example.com:8080"}
    assert result == expected
    mock_proxy_check.assert_called_once_with(
        logger, "api.example.com", {"example.com": "proxy.example.com:8080"}
    )


@patch("acme2certifier.acme_srv.helpers.network.proxy_check")
@patch("acme2certifier.acme_srv.helpers.network.parse_url")
def test_539_config_proxy_load_empty_proxy_list(
    mock_parse_url: MagicMock, mock_proxy_check: MagicMock, logger: logging.Logger
) -> None:
    """test config_proxy_load() with empty proxy_server_list"""
    config_dic = {"DEFAULT": {"proxy_server_list": "{}"}}
    host_name = "https://api.example.com:443/test"
    mock_parse_url.return_value = {"host": "api.example.com:443"}
    mock_proxy_check.return_value = None
    result = config_proxy_load(logger, config_dic, host_name)
    expected = {"http": None, "https": None}
    assert result == expected
    mock_parse_url.assert_called_once_with(logger, host_name)
    mock_proxy_check.assert_called_once_with(logger, "api.example.com", {})


def test_540_config_async_mode_load_true_with_django(logger: logging.Logger) -> None:
    """test config_async_mode_load() with async_mode True and django db"""
    config_dic = configparser.ConfigParser()
    config_dic["DEFAULT"] = {"async_mode": "True"}
    db_type = "django"
    result = config_async_mode_load(logger, config_dic, db_type)
    assert result


def test_541_config_async_mode_load_true_non_django(
    logger: logging.Logger, capture_logs: Callable[..., AbstractContextManager[Any]]
) -> None:
    """test config_async_mode_load() with async_mode True and non-django db"""
    config_dic = configparser.ConfigParser()
    config_dic["DEFAULT"] = {"async_mode": "True"}
    db_type = "sqlite"
    with capture_logs(logger, level="INFO") as log:
        result = config_async_mode_load(logger, config_dic, db_type)
    assert not result
    assert "asynchronous Challenge validation disabled" in log.output[0]


def test_542_config_async_mode_load_false_with_django(logger: logging.Logger) -> None:
    """test config_async_mode_load() with async_mode False and django db"""
    config_dic = configparser.ConfigParser()
    config_dic["DEFAULT"] = {"async_mode": "False"}
    db_type = "django"
    assert not config_async_mode_load(logger, config_dic, db_type)


def test_543_config_async_mode_load_default_fallback(logger: logging.Logger) -> None:
    """test config_async_mode_load() with no async_mode setting (fallback)"""
    config_dic = configparser.ConfigParser()
    config_dic["DEFAULT"] = {}
    db_type = "django"
    assert not config_async_mode_load(logger, config_dic, db_type)


def test_544_config_async_mode_load_no_default_section(logger: logging.Logger) -> None:
    """test config_async_mode_load() with no DEFAULT section"""
    config_dic = configparser.ConfigParser()
    db_type = "django"
    assert not config_async_mode_load(logger, config_dic, db_type)


def test_545_config_async_mode_load_invalid_boolean(logger: logging.Logger) -> None:
    """test config_async_mode_load() with invalid boolean value"""
    config_dic = configparser.ConfigParser()
    config_dic["DEFAULT"] = {"async_mode": "invalid"}
    db_type = "django"
    with pytest.raises(ValueError) as context:
        config_async_mode_load(logger, config_dic, db_type)
    assert "Not a boolean: invalid" in str(context.value)


def test_546_config_async_mode_load_case_insensitive_true(
    logger: logging.Logger,
) -> None:
    """test config_async_mode_load() with case insensitive True values"""
    test_cases = ["true", "TRUE", "True", "1", "yes", "on"]
    for value in test_cases:
        config_dic = configparser.ConfigParser()
        config_dic["DEFAULT"] = {"async_mode": value}
        db_type = "django"
        result = config_async_mode_load(logger, config_dic, db_type)
        assert result


def test_547_config_async_mode_load_case_insensitive_false(
    logger: logging.Logger,
) -> None:
    """test config_async_mode_load() with case insensitive False values"""
    test_cases = ["false", "FALSE", "False", "0", "no", "off"]
    for value in test_cases:
        config_dic = configparser.ConfigParser()
        config_dic["DEFAULT"] = {"async_mode": value}
        db_type = "django"
        assert not config_async_mode_load(logger, config_dic, db_type)


def test_548_config_async_mode_load_different_db_types(
    logger: logging.Logger, capture_logs: Callable[..., AbstractContextManager[Any]]
) -> None:
    """test config_async_mode_load() with various non-django db types"""
    config_dic = configparser.ConfigParser()
    config_dic["DEFAULT"] = {"async_mode": "True"}
    db_types = ["sqlite", "mysql", "postgresql", "oracle", "wsgi", ""]
    for db_type in db_types:
        with capture_logs(logger, level="INFO") as log:
            result = config_async_mode_load(logger, config_dic, db_type)
        assert not result
        assert "asynchronous Challenge validation disabled" in log.output[0]


def test_583_config_allowed_domainlist_load_deprecated_section(
    logger: logging.Logger, capture_logs: Callable[..., AbstractContextManager[Any]]
) -> None:
    """Test config_allowed_domainlist_load loads from deprecated CAhandler section and logs warning."""
    from acme2certifier.acme_srv.helpers import config

    cfg = {"CAhandler": {"allowed_domainlist": "example.com,example.org"}}
    with capture_logs(logger, level="WARNING") as log_context:
        result = config.config_allowed_domainlist_load(logger, cfg)
    from acme2certifier.acme_srv.helpers.global_variables import PARSING_ERR_MSG

    assert result == PARSING_ERR_MSG
    assert any(("deprecated" in msg.lower() for msg in log_context.output))


def test_584_config_allowed_domainlist_load_invalid_json(
    logger: logging.Logger, capture_logs: Callable[..., AbstractContextManager[Any]]
) -> None:
    """Test config_allowed_domainlist_load handles invalid JSON and logs warning."""
    from acme2certifier.acme_srv.helpers import config

    cfg = {"Order": {"allowed_domainlist": "not-a-json-list"}}
    with capture_logs(logger, level="WARNING") as log_context:
        from acme2certifier.acme_srv.helpers.global_variables import PARSING_ERR_MSG

        result = config.config_allowed_domainlist_load(logger, cfg)
    assert result == PARSING_ERR_MSG
    assert any(
        (
            "failed to load allowed_domainlist" in msg.lower()
            for msg in log_context.output
        )
    )


def test_592_config_dryrun_load_not_set() -> None:
    """Test config_dryrun_load with valid 'true' value."""


def test_593_config_dryrun_load_not_set(logger: logging.Logger) -> None:
    """Test config_dryrun_load when dryrun is not set."""
    config_dic = configparser.ConfigParser()
    config_dic["DEFAULT"] = {"foo": "bar"}
    assert (False, None) == config_dryrun_load(logger, config_dic)


def test_594_config_dryrun_load_true(logger: logging.Logger) -> None:
    """Test config_dryrun_load with valid 'true' value."""
    config_dic = configparser.ConfigParser()
    config_dic["DEFAULT"] = {"dryrun": "True"}
    true_list = ["true", "True", "TRUE"]
    for val in true_list:
        config_dic["DEFAULT"]["dryrun"] = val
        assert (True, None) == config_dryrun_load(logger, config_dic)


def test_595_config_dryrun_load_false(logger: logging.Logger) -> None:
    """Test config_dryrun_load with valid 'false' value."""
    config_dic = configparser.ConfigParser()
    config_dic["DEFAULT"] = {"dryrun": "False"}
    false_list = ["false", "False", "FALSE"]
    for val in false_list:
        config_dic["DEFAULT"]["dryrun"] = val
        assert (False, None) == config_dryrun_load(logger, config_dic)


def test_596_config_dryrun_load_profile(logger: logging.Logger) -> None:
    """Test config_dryrun_load with invalid value."""
    config_dic = configparser.ConfigParser()
    profile_list = ["profile", "Profile", "PROFILE"]
    for val in profile_list:
        config_dic["DEFAULT"]["dryrun"] = val
        config_dic["DEFAULT"]["dryrun_profile"] = "custom_dryrun_profile"
        assert (False, "custom_dryrun_profile") == config_dryrun_load(
            logger, config_dic
        )


def test_597_config_dryrun_load_profile_no_profilename(
    logger: logging.Logger, capture_logs: Callable[..., AbstractContextManager[Any]]
) -> None:
    """Test config_dryrun_load with invalid value and no dryrun_profile set."""
    config_dic = configparser.ConfigParser()
    config_dic["DEFAULT"]["dryrun"] = "profile"
    with capture_logs(logger, level="WARNING") as lcm:
        assert (False, None) == config_dryrun_load(logger, config_dic)
        assert (
            "WARNING:test_a2c:Dryrun profile name not set in configuration, please set dryrun_profile parameter"
            in lcm.output[0]
        )


def test_607_config_allowed_iplist_load(logger: logging.Logger) -> None:
    """test config_allowed_iplist_load()"""
    config_dic = {"Order": {"allowed_iplist": '["foo", "bar", "foobar"]'}}
    assert ["foo", "bar", "foobar"] == config_allowed_iplist_load(logger, config_dic)


def test_608_config_allowed_iplist_load(logger: logging.Logger) -> None:
    """test config_allowed_iplist_load()"""
    config_dic = {"Order": {"allowed_iplist": '["foo"]'}}
    assert ["foo"] == config_allowed_iplist_load(logger, config_dic)


def test_609_config_allowed_iplist_load(
    logger: logging.Logger, capture_logs: Callable[..., AbstractContextManager[Any]]
) -> None:
    """test config_allowed_iplist_load()"""
    config_dic = {"Order": {"allowed_iplist": "foo"}}
    with capture_logs("test_a2c", level="INFO") as lcm:
        assert "failed to parse" == config_allowed_iplist_load(logger, config_dic)
    assert (
        "WARNING:test_a2c:Failed to load allowed_iplist from configuration: Expecting value: line 1 column 1 (char 0)"
        in lcm.output
    )


def test_624_default_deploy_base_dir_and_resolve_config_path() -> None:
    """default_deploy_base_dir and resolve_config_path cover env/dir/empty paths"""
    from acme2certifier.acme_srv.helpers import config as config_mod

    with patch.dict(
        os.environ, {"ACME2CERTIFIER_BASE_DIR": "/custom/base"}, clear=False
    ):
        assert config_mod.default_deploy_base_dir() == "/custom/base"
        assert config_mod.resolve_config_path("rel/path.cfg") == os.path.normpath(
            "/custom/base/rel/path.cfg"
        )
    env = os.environ.copy()
    env.pop("ACME2CERTIFIER_BASE_DIR", None)
    with patch.dict(os.environ, env, clear=True):
        with patch(
            "os.path.isdir", side_effect=lambda p: p == "/var/www/acme2certifier"
        ):
            assert config_mod.default_deploy_base_dir() == "/var/www/acme2certifier"
        with patch("os.path.isdir", side_effect=lambda p: p == "/opt/acme2certifier"):
            assert config_mod.default_deploy_base_dir() == "/opt/acme2certifier"
        with patch("os.path.isdir", return_value=False):
            assert config_mod.default_deploy_base_dir() == "/var/www/acme2certifier"
        assert config_mod.resolve_config_path(None) is None
        assert config_mod.resolve_config_path("") == ""
        assert config_mod.resolve_config_path("/abs/path.cfg") == "/abs/path.cfg"
        assert config_mod.resolve_config_path("rel.cfg") == "rel.cfg"


def test_625_warn_acme_srv_cfg_path_once(
    logger: logging.Logger, capture_logs: Callable[..., AbstractContextManager[Any]]
) -> None:
    """_warn_acme_srv_cfg_path warns once per path"""
    from acme2certifier.acme_srv.helpers import config as config_mod

    config_mod._ACME_SRV_CFG_PATH_WARNED.clear()
    with (
        capture_logs("test_a2c", level="WARNING") as lcm,
        warnings.catch_warnings(record=True) as caught,
    ):
        warnings.simplefilter("always")
        config_mod._warn_acme_srv_cfg_path(
            "/legacy/acme_srv.cfg", "/preferred/acme_srv.cfg", logger
        )
        config_mod._warn_acme_srv_cfg_path(
            "/legacy/acme_srv.cfg", "/preferred/acme_srv.cfg", logger
        )
    assert 1 == sum((1 for line in lcm.output if "Loading acme_srv.cfg from" in line))
    assert any((issubclass(w.category, DeprecationWarning) for w in caught))


def test_626_default_acme_srv_cfg_file_path_priority(
    logger: logging.Logger, capture_logs: Callable[..., AbstractContextManager[Any]]
) -> None:
    """_default_acme_srv_cfg_file covers nested/packaged/legacy/fallback"""
    from acme2certifier.acme_srv.helpers import config as config_mod

    config_mod._ACME_SRV_CFG_PATH_WARNED.clear()

    def _isfile_for(path_set):
        return lambda p: p in path_set

    with (
        patch(
            "os.path.isfile",
            side_effect=_isfile_for({"/var/www/acme2certifier/acme_srv/acme_srv.cfg"}),
        ),
        capture_logs("test_a2c", level="WARNING") as lcm,
    ):
        result = config_mod._default_acme_srv_cfg_file(logger)
    assert result == "/var/www/acme2certifier/acme_srv/acme_srv.cfg"
    assert any(("Loading acme_srv.cfg from" in line for line in lcm.output))
    helpers_dir = os.path.dirname(os.path.abspath(config_mod.__file__))
    pkg_dir = os.path.dirname(helpers_dir)
    packaged = os.path.join(pkg_dir, "acme_srv.cfg")
    with patch("os.path.isfile", side_effect=_isfile_for({packaged})):
        assert config_mod._default_acme_srv_cfg_file(logger) == packaged
    install_or_repo_root = os.path.dirname(os.path.dirname(pkg_dir))
    legacy = os.path.join(install_or_repo_root, "acme_srv", "acme_srv.cfg")
    config_mod._ACME_SRV_CFG_PATH_WARNED.clear()
    with (
        patch("os.path.isfile", side_effect=_isfile_for({legacy})),
        capture_logs("test_a2c", level="WARNING"),
    ):
        assert config_mod._default_acme_srv_cfg_file(logger) == legacy
    with patch("os.path.isfile", return_value=False):
        assert (
            config_mod._default_acme_srv_cfg_file(logger)
            == "/var/www/acme2certifier/acme_srv.cfg"
        )


def test_634_legacy_acme_get_load_default_false(logger: logging.Logger) -> None:
    """legacy_acme_get defaults to False"""
    from configparser import ConfigParser
    from acme2certifier.acme_srv.helpers.config import legacy_acme_get_load

    config_dic = ConfigParser()
    assert not legacy_acme_get_load(logger, config_dic)


def test_635_legacy_acme_get_load_true_warns(
    logger: logging.Logger, capture_logs: Callable[..., AbstractContextManager[Any]]
) -> None:
    """legacy_acme_get True logs a warning"""
    from configparser import ConfigParser
    from acme2certifier.acme_srv.helpers.config import (
        legacy_acme_get_load,
        acme_get_method_not_allowed_problem,
    )

    config_dic = ConfigParser()
    config_dic["DEFAULT"] = {"legacy_acme_get": "True"}
    with capture_logs("test_a2c", level="WARNING") as lcm:
        assert legacy_acme_get_load(logger, config_dic)
    assert any(("legacy_acme_get is enabled" in line for line in lcm.output))
    problem = acme_get_method_not_allowed_problem()
    assert 405 == problem["status"]
    assert "malformed" in problem["type"]


def test_648_tnauthlist_configuration_validate_disabled(logger: logging.Logger) -> None:
    """no message when tnauthlist_support is off"""
    from configparser import ConfigParser
    from acme2certifier.acme_srv.helpers.config import tnauthlist_configuration_validate

    config_dic = ConfigParser()
    config_dic["Order"] = {"tnauthlist_support": "False"}
    with patch.object(logger, "error") as error_mock:
        with patch.object(logger, "critical") as critical_mock:
            tnauthlist_configuration_validate(logger, config_dic)
    error_mock.assert_not_called()
    critical_mock.assert_not_called()


def test_649_tnauthlist_configuration_validate_enabled_not_acknowledged(
    logger: logging.Logger, capture_logs: Callable[..., AbstractContextManager[Any]]
) -> None:
    """tnauthlist_support without acknowledgement logs an error"""
    from configparser import ConfigParser
    from acme2certifier.acme_srv.helpers.config import tnauthlist_configuration_validate
    from acme2certifier.acme_srv.helpers.security_gate import SECURITY_DISABLE_ACK_ENV

    config_dic = ConfigParser()
    config_dic["Order"] = {"tnauthlist_support": "True"}
    with patch.dict("os.environ", {SECURITY_DISABLE_ACK_ENV: ""}, clear=False):
        with capture_logs("test_a2c", level="ERROR") as lcm:
            tnauthlist_configuration_validate(logger, config_dic)
    assert any(
        (
            "tkauth-01 validation is not implemented" in line
            and SECURITY_DISABLE_ACK_ENV in line
            for line in lcm.output
        )
    )


def test_650_tnauthlist_configuration_validate_enabled_acknowledged(
    logger: logging.Logger, capture_logs: Callable[..., AbstractContextManager[Any]]
) -> None:
    """tnauthlist_support with acknowledgement logs a critical message"""
    from configparser import ConfigParser
    from acme2certifier.acme_srv.helpers.config import tnauthlist_configuration_validate
    from acme2certifier.acme_srv.helpers.security_gate import SECURITY_DISABLE_ACK_ENV

    config_dic = ConfigParser()
    config_dic["Order"] = {"tnauthlist_support": "True"}
    with patch.dict("os.environ", {SECURITY_DISABLE_ACK_ENV: "1"}, clear=False):
        with capture_logs("test_a2c", level="CRITICAL") as lcm:
            tnauthlist_configuration_validate(logger, config_dic)
    assert any(("SECURITY DISABLE ACKNOWLEDGED" in line for line in lcm.output))


def test_651_tnauthlist_configuration_validate_empty_config(
    logger: logging.Logger,
) -> None:
    """tnauthlist_configuration_validate returns early when config_dic is falsy"""
    from acme2certifier.acme_srv.helpers.config import tnauthlist_configuration_validate

    with patch.object(logger, "error") as error_mock:
        with patch.object(logger, "critical") as critical_mock:
            tnauthlist_configuration_validate(logger, None)
    error_mock.assert_not_called()
    critical_mock.assert_not_called()


def test_652_challenge_type_configuration_validate_all_disabled(
    logger: logging.Logger,
) -> None:
    """challenge_type_configuration_validate warns when all std types are off."""
    from configparser import ConfigParser
    from acme2certifier.acme_srv.helpers.config import (
        challenge_type_configuration_validate,
    )

    config_dic = ConfigParser()
    config_dic.add_section("Challenge")
    config_dic.set("Challenge", "http_01_support", "False")
    config_dic.set("Challenge", "dns_01_support", "False")
    config_dic.set("Challenge", "tls_alpn_01_support", "False")
    with patch.object(logger, "warning") as warning_mock:
        challenge_type_configuration_validate(logger, config_dic)
    warning_mock.assert_called_once()
    assert "All RFC 8555 challenge types are disabled" in warning_mock.call_args[0][0]


def test_653_challenge_type_configuration_validate_dns_persist_enabled(
    logger: logging.Logger,
) -> None:
    """No warning when dns_persist_01_support is enabled."""
    from configparser import ConfigParser
    from acme2certifier.acme_srv.helpers.config import (
        challenge_type_configuration_validate,
    )

    config_dic = ConfigParser()
    config_dic.add_section("Challenge")
    config_dic.set("Challenge", "http_01_support", "False")
    config_dic.set("Challenge", "dns_01_support", "False")
    config_dic.set("Challenge", "tls_alpn_01_support", "False")
    config_dic.set("Challenge", "dns_persist_01_support", "True")
    with patch.object(logger, "warning") as warning_mock:
        challenge_type_configuration_validate(logger, config_dic)
    warning_mock.assert_not_called()


def test_654_challenge_type_configuration_validate_default_enabled(
    logger: logging.Logger,
) -> None:
    """No warning when standard challenge types use default (enabled)."""
    from configparser import ConfigParser
    from acme2certifier.acme_srv.helpers.config import (
        challenge_type_configuration_validate,
    )

    config_dic = ConfigParser()
    config_dic.add_section("Challenge")
    with patch.object(logger, "warning") as warning_mock:
        challenge_type_configuration_validate(logger, config_dic)
    warning_mock.assert_not_called()


def test_655_default_wsgi_dbfile() -> None:
    """default_wsgi_dbfile joins deploy base dir with acme_srv.db"""
    from acme2certifier.acme_srv.helpers import config as config_mod

    with patch.object(
        config_mod, "default_deploy_base_dir", return_value="/custom/base"
    ):
        assert config_mod.default_wsgi_dbfile() == os.path.join(
            "/custom/base", "acme_srv.db"
        )


def test_656_default_acme_srv_cfg_file_preferred_deploy(logger: logging.Logger) -> None:
    """_default_acme_srv_cfg_file returns first existing preferred deploy path"""
    from acme2certifier.acme_srv.helpers import config as config_mod

    preferred = "/var/www/acme2certifier/acme_srv.cfg"
    with patch("os.path.isfile", side_effect=lambda p: p == preferred):
        assert config_mod._default_acme_srv_cfg_file(logger) == preferred


def test_665_unique_key_loader_duplicate_and_mapping() -> None:
    """_UniqueKeyLoader rejects duplicate keys and loads mappings"""
    import yaml
    from acme2certifier.acme_srv.helpers.config import _UniqueKeyLoader

    ok = yaml.load("a: 1\nb: 2\n", Loader=_UniqueKeyLoader)
    assert {"a": 1, "b": 2} == ok
    with pytest.raises(yaml.constructor.ConstructorError):
        yaml.load("a: 1\na: 2\n", Loader=_UniqueKeyLoader)
    assert [1, 2] == yaml.load("- 1\n- 2\n", Loader=_UniqueKeyLoader)
    loader = _UniqueKeyLoader("")
    scalar = yaml.ScalarNode("tag:yaml.org,2002:str", "hello")
    with pytest.raises(yaml.constructor.ConstructorError):
        loader.construct_mapping(scalar)


def test_666_set_yaml_option_null_and_new_section(
    logger: logging.Logger, capture_logs: Callable[..., AbstractContextManager[Any]]
) -> None:
    """_set_yaml_option skips null and creates non-DEFAULT sections"""
    from acme2certifier.acme_srv.helpers.config import _set_yaml_option
    import configparser

    config = configparser.ConfigParser()
    with capture_logs("test_a2c", level="WARNING"):
        _set_yaml_option(config, "Sec", "opt", None, logger)
    assert not config.has_section("Sec")
    _set_yaml_option(config, "Sec", "opt", "val", logger)
    assert "val" == config.get("Sec", "opt")


def test_667_log_loaded_acme_srv_cfg_flushes_last(
    logger: logging.Logger, capture_logs: Callable[..., AbstractContextManager[Any]]
) -> None:
    """log_loaded_acme_srv_cfg emits pending load info"""
    import acme2certifier.acme_srv.helpers.config as cfgmod

    prev = cfgmod._LAST_LOADED_CFG
    cfgmod._LAST_LOADED_CFG = ("/tmp/acme_srv.cfg", "test", "ini")
    cfgmod._ACME_SRV_CFG_LOADED.discard(os.path.abspath("/tmp/acme_srv.cfg"))
    try:
        with capture_logs("test_a2c", level="INFO") as lcm:
            cfgmod.log_loaded_acme_srv_cfg(logger)
        assert any(("Loaded acme_srv.cfg" in x for x in lcm.output))
    finally:
        cfgmod._LAST_LOADED_CFG = prev


def test_668_detect_config_format_variants() -> None:
    """_detect_config_format covers empty, comments, ini, yaml markers, ext"""
    from acme2certifier.acme_srv.helpers.config import _detect_config_format

    assert "ini" == _detect_config_format("", "x.cfg")
    assert "ini" == _detect_config_format("# only\n; c\n", "x.cfg")
    assert "ini" == _detect_config_format("[DEFAULT]\na: 1\n", "x.cfg")
    assert "yaml" == _detect_config_format("---\na: 1\n", "x.cfg")
    assert "yaml" == _detect_config_format("- item\n", "x.cfg")
    assert "yaml" == _detect_config_format("{a: 1}\n", "x.cfg")
    assert "yaml" == _detect_config_format("DEFAULT:\n  a: 1\n", "x.cfg")
    assert "yaml" == _detect_config_format("weird\n", "x.yaml")
    assert "ini" == _detect_config_format("weird\n", "x.cfg")


def test_669_yaml_value_and_parse_yaml(
    logger: logging.Logger, capture_logs: Callable[..., AbstractContextManager[Any]]
) -> None:
    """YAML value normalization and _parse_yaml edge cases"""
    from acme2certifier.acme_srv.helpers.config import (
        _yaml_value_to_option,
        _parse_yaml,
        _set_yaml_option,
        _parse_config_content,
    )
    import configparser

    with capture_logs("test_a2c", level="WARNING") as lcm:
        assert _yaml_value_to_option(None, logger, "S", "o") is None
    assert any(("Ignoring null YAML option" in x for x in lcm.output))
    assert "True" == _yaml_value_to_option(True, logger, "S", "o")
    assert "False" == _yaml_value_to_option(False, logger, "S", "o")
    assert "3" == _yaml_value_to_option(3, logger, "S", "o")
    assert "hi" == _yaml_value_to_option("hi", logger, "S", "o")
    assert "[1]" == _yaml_value_to_option([1], logger, "S", "o")
    with pytest.raises(ValueError):
        _yaml_value_to_option(object(), logger, "S", "o")
    cfg = _parse_yaml("", logger)
    assert isinstance(cfg, configparser.ConfigParser)
    with pytest.raises(ValueError):
        _parse_yaml("- just a list\n", logger)
    with pytest.raises(ValueError):
        _parse_yaml("1: foo\n", logger)
    config = configparser.ConfigParser()
    with pytest.raises(ValueError):
        _set_yaml_option(config, "S", 123, "v", logger)
    parsed = _parse_yaml(
        "DEFAULT:\n  debug: true\nOrder:\n  validity: 10\n  tags: [a, b]\nroot_scalar: hello\n",
        logger,
    )
    assert "True" == parsed.get("DEFAULT", "debug")
    assert "10" == parsed.get("Order", "validity")
    assert "a" in parsed.get("Order", "tags")
    assert "hello" == parsed.get("DEFAULT", "root_scalar")
    cfg2, fmt = _parse_config_content(
        "Order:\n  validity: 5\n", "acme_srv.yaml", logger
    )
    assert "yaml" == fmt
    assert "5" == cfg2.get("Order", "validity")
    with (
        patch(
            "acme2certifier.acme_srv.helpers.config._detect_config_format",
            return_value="ini",
        ),
        patch(
            "acme2certifier.acme_srv.helpers.config._parse_ini",
            side_effect=configparser.Error("bad"),
        ),
    ):
        cfg4, fmt4 = _parse_config_content("Order:\n  validity: 7\n", "x.cfg", logger)
        assert "yaml" == fmt4
        assert "7" == cfg4.get("Order", "validity")


def test_670_config_allowed_header_values_load(
    logger: logging.Logger, capture_logs: Callable[..., AbstractContextManager[Any]]
) -> None:
    """config_allowed_header_values_load covers missing, valid, invalid, non-list"""
    from acme2certifier.acme_srv.helpers.config import config_allowed_header_values_load
    import configparser

    empty = configparser.ConfigParser()
    assert [] == config_allowed_header_values_load(logger, empty)
    parser = configparser.ConfigParser()
    parser["Order"] = {"allowed_header_values": '["a", "b"]'}
    assert ["a", "b"] == config_allowed_header_values_load(logger, parser)
    parser_bad = configparser.ConfigParser()
    parser_bad["Order"] = {"allowed_header_values": "not-json"}
    with capture_logs("test_a2c", level="WARNING") as lcm:
        assert [] == config_allowed_header_values_load(logger, parser_bad)
    assert any(("Failed to parse allowed_header_values" in msg for msg in lcm.output))
    parser_obj = configparser.ConfigParser()
    parser_obj["Order"] = {"allowed_header_values": '{"a": true}'}
    with capture_logs("test_a2c", level="WARNING") as lcm2:
        assert [] == config_allowed_header_values_load(logger, parser_obj)
    assert any(("Failed to parse allowed_header_values" in msg for msg in lcm2.output))
    parser_blank = configparser.ConfigParser()
    parser_blank["Order"] = {"allowed_header_values": ""}
    assert [] == config_allowed_header_values_load(logger, parser_blank)


def test_671_config_allowed_templates_load(
    logger: logging.Logger, capture_logs: Callable[..., AbstractContextManager[Any]]
) -> None:
    """config_allowed_templates_load prefers Order, falls back to CAhandler"""
    from acme2certifier.acme_srv.helpers.config import config_allowed_templates_load
    import configparser

    empty = configparser.ConfigParser()
    with capture_logs("test_a2c", level="WARNING") as lcm_empty:
        assert [] == config_allowed_templates_load(logger, empty)
    assert any("No [Order] allowed_header_values" in msg for msg in lcm_empty.output)

    parser_order = configparser.ConfigParser()
    parser_order["Order"] = {"allowed_header_values": '["FromOrder"]'}
    parser_order["CAhandler"] = {"allowed_templates": '["FromCA"]'}
    assert ["FromOrder"] == config_allowed_templates_load(logger, parser_order)

    parser_ca = configparser.ConfigParser()
    parser_ca["CAhandler"] = {"allowed_templates": '["WebServer", "User"]'}
    with capture_logs("test_a2c", level="WARNING") as lcm_depr:
        assert ["WebServer", "User"] == config_allowed_templates_load(logger, parser_ca)
    assert any("allowed_templates is deprecated" in msg for msg in lcm_depr.output)

    parser_bad = configparser.ConfigParser()
    parser_bad["CAhandler"] = {"allowed_templates": "not-json"}
    with capture_logs("test_a2c", level="WARNING") as lcm_bad:
        assert [] == config_allowed_templates_load(logger, parser_bad)
    assert any("Failed to parse allowed_templates" in msg for msg in lcm_bad.output)

    parser_obj = configparser.ConfigParser()
    parser_obj["CAhandler"] = {"allowed_templates": '{"WebServer": true}'}
    with capture_logs("test_a2c", level="WARNING") as lcm_obj:
        assert [] == config_allowed_templates_load(logger, parser_obj)
    assert any("Failed to parse allowed_templates" in msg for msg in lcm_obj.output)

    parser_empty_list = configparser.ConfigParser()
    parser_empty_list["CAhandler"] = {"allowed_templates": "[]"}
    with capture_logs("test_a2c", level="WARNING") as lcm_empty_list:
        assert [] == config_allowed_templates_load(logger, parser_empty_list)
    assert any("allowed_templates is empty" in msg for msg in lcm_empty_list.output)


def test_672_challenge_type_configuration_validate_empty_config(
    logger: logging.Logger,
) -> None:
    """challenge_type_configuration_validate returns early when config_dic is falsy"""
    from acme2certifier.acme_srv.helpers.config import (
        challenge_type_configuration_validate,
    )

    with patch.object(logger, "warning") as warning_mock:
        challenge_type_configuration_validate(logger, None)
    warning_mock.assert_not_called()


def test_673_config_kerberos_options_load(
    logger: logging.Logger, monkeypatch: Any
) -> None:
    """config_kerberos_options_load assigns krb5_* via config_option_load"""
    from acme2certifier.acme_srv.helpers.config import config_kerberos_options_load
    import configparser
    from types import SimpleNamespace

    target = SimpleNamespace(
        krb5_principal=None,
        krb5_keytab=None,
        krb5_cache=None,
        krb5_config=None,
        krb5_kinit_path="/usr/bin/kinit",
    )
    parser = configparser.ConfigParser()
    parser["CAhandler"] = {
        "krb5_principal": "svc@EXAMPLE.COM",
        "krb5_keytab": "/tmp/svc.keytab",
        "krb5_cache": "/tmp/ccache",
        "krb5_config": "/tmp/krb5.conf",
        "krb5_kinit_path": "/usr/local/bin/kinit",
    }
    config_kerberos_options_load(logger, parser, target)
    assert "svc@EXAMPLE.COM" == target.krb5_principal
    assert "/tmp/svc.keytab" == target.krb5_keytab
    assert "/tmp/ccache" == target.krb5_cache
    assert "/tmp/krb5.conf" == target.krb5_config
    assert "/usr/local/bin/kinit" == target.krb5_kinit_path

    env_target = SimpleNamespace(
        krb5_principal=None,
        krb5_keytab=None,
        krb5_cache=None,
        krb5_config=None,
        krb5_kinit_path="/usr/bin/kinit",
    )
    env_parser = configparser.ConfigParser()
    env_parser["CAhandler"] = {"krb5_principal_variable": "KRB5_PRINCIPAL_TEST"}
    monkeypatch.setenv("KRB5_PRINCIPAL_TEST", "from-env@EXAMPLE.COM")
    config_kerberos_options_load(logger, env_parser, env_target)
    assert "from-env@EXAMPLE.COM" == env_target.krb5_principal
    assert "/usr/bin/kinit" == env_target.krb5_kinit_path


def test_674_config_number_load(
    logger: logging.Logger, capture_logs: Callable[..., AbstractContextManager[Any]]
) -> None:
    """config_number_load parses int/float and keeps current on failure"""
    from acme2certifier.acme_srv.helpers.config import config_number_load
    import configparser

    empty = configparser.ConfigParser()
    assert 10 == config_number_load(
        logger, empty, "request_timeout", cast=int, current=10
    )

    parser = configparser.ConfigParser()
    parser["CAhandler"] = {
        "request_timeout": "15",
        "request_retry_backoff": "1.5",
        "request_retries": "bad",
    }
    assert 15 == config_number_load(
        logger, parser, "request_timeout", cast=int, current=10
    )
    assert 1.5 == config_number_load(
        logger, parser, "request_retry_backoff", cast=float, current=2.0
    )
    with capture_logs("test_a2c", level="ERROR") as lcm:
        assert 3 == config_number_load(
            logger, parser, "request_retries", cast=int, current=3
        )
    assert any(
        "Failed to parse request_retries parameter:" in msg for msg in lcm.output
    )
    assert 10 == config_number_load(
        logger, parser, "missing_option", cast=int, current=10
    )
    assert 12 == config_number_load(
        logger,
        {"CAhandler": {"request_timeout": "12"}},
        "request_timeout",
        cast=int,
        current=10,
    )


def test_675_cahandler_section_merged_config_passthrough(
    logger: logging.Logger,
) -> None:
    """Named section CAhandler is returned unchanged"""
    from acme2certifier.acme_srv.helpers.config import _cahandler_section_merged_config

    parser = configparser.ConfigParser(interpolation=None)
    parser.optionxform = str
    parser.add_section("CAhandler")
    parser.set("CAhandler", "api_host", "https://ca")
    assert _cahandler_section_merged_config(parser, "CAhandler", logger) is parser


def test_676_cahandler_section_merged_config_missing_section(
    logger: logging.Logger,
) -> None:
    """Missing named overlay section leaves the parser unchanged"""
    from acme2certifier.acme_srv.helpers.config import _cahandler_section_merged_config

    parser = configparser.ConfigParser(interpolation=None)
    parser.optionxform = str
    parser.add_section("CAhandler")
    result = _cahandler_section_merged_config(parser, "CAhandler:missing", logger)
    assert result is parser


def test_677_cahandler_section_merged_config_no_base_section(
    logger: logging.Logger,
) -> None:
    """Named overlay creates [CAhandler] when the base section is absent"""
    from acme2certifier.acme_srv.helpers.config import _cahandler_section_merged_config

    parser = configparser.ConfigParser(interpolation=None)
    parser.optionxform = str
    parser.add_section("CAhandler:ejbca")
    parser.set("CAhandler:ejbca", "api_host", "https://ejbca")
    merged = _cahandler_section_merged_config(parser, "CAhandler:ejbca", logger)
    assert merged.get("CAhandler", "api_host") == "https://ejbca"


def test_678_cahandler_section_merged_config_defensive_copy(
    logger: logging.Logger,
) -> None:
    """Defensive CAhandler copy when sections() omits a present CAhandler"""
    from acme2certifier.acme_srv.helpers.config import _cahandler_section_merged_config

    config = MagicMock()
    config.has_section.side_effect = lambda section: section in {
        "CAhandler",
        "CAhandler:ejbca",
    }
    config.sections.return_value = []
    config.items.return_value = [("api_host", "https://ca")]
    merged = _cahandler_section_merged_config(config, "CAhandler:ejbca", logger)
    assert merged.get("CAhandler", "api_host") == "https://ca"


def test_679_resolve_config_injected_and_load(logger: logging.Logger) -> None:
    """resolve_config returns the injected parser or delegates to load_config"""
    from acme2certifier.acme_srv.helpers.config import resolve_config

    parser = configparser.ConfigParser()
    assert resolve_config(parser) is parser
    with patch(
        "acme2certifier.acme_srv.helpers.config.load_config", return_value="loaded"
    ) as mock_load:
        assert resolve_config(None, logger, "flt", "cfg") == "loaded"
    mock_load.assert_called_once_with(logger, "flt", "cfg")


def test_680_load_config_cache_hit_without_logger() -> None:
    """Cache hit without an app logger uses debug logging only"""
    import tempfile
    from acme2certifier.acme_srv.helpers import config as config_mod

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".cfg", delete=False, encoding="utf8"
    ) as handle:
        handle.write("[CAhandler]\nshared: 1\n")
        cfg_path = handle.name
    try:
        first = load_config(None, None, cfg_path)
        with patch.object(
            config_mod, "_read_config_file", side_effect=AssertionError("re-read")
        ):
            second = load_config(None, None, cfg_path)
        assert first is second
    finally:
        os.unlink(cfg_path)
        config_mod.load_config_cache_clear()


def test_681_load_config_section_default_cahandler(logger: logging.Logger) -> None:
    """load_config_section('CAhandler') does not bind a named overlay"""
    from acme2certifier.acme_srv.helpers.config import load_config_section

    with patch(
        "acme2certifier.acme_srv.helpers.config.load_config", return_value="cfg"
    ) as mock_load:
        assert load_config_section(logger, "CAhandler") == "cfg"
    mock_load.assert_called_once()


def test_682_load_cahandler_config_from_handler_attrs(logger: logging.Logger) -> None:
    """load_cahandler_config reads config_section, CONFIG_SECTION, or default"""
    from types import SimpleNamespace
    from acme2certifier.acme_srv.helpers.config import load_cahandler_config

    with patch(
        "acme2certifier.acme_srv.helpers.config.load_config_section", return_value="cfg"
    ) as mock_lcs:
        handler = SimpleNamespace(config_section="CAhandler:ejbca")
        assert load_cahandler_config(logger, handler) == "cfg"
        mock_lcs.assert_called_with(logger, "CAhandler:ejbca")
        handler = SimpleNamespace(CONFIG_SECTION="CAhandler:xca")
        assert load_cahandler_config(logger, handler) == "cfg"
        mock_lcs.assert_called_with(logger, "CAhandler:xca")
        assert load_cahandler_config(logger) == "cfg"
        mock_lcs.assert_called_with(logger, "CAhandler")


def test_683_cahandler_lookup_no_input(logger: logging.Logger) -> None:
    """cahandler_lookup returns None when neither csr nor cert_raw is given"""
    from acme2certifier.acme_srv.helpers.config import cahandler_lookup

    models_mock = MagicMock()
    with patch.dict("sys.modules", {"acme2certifier.acme_srv.db_handler": models_mock}):
        assert cahandler_lookup(logger) is None
    models_mock.DBstore.assert_called_once()
    models_mock.DBstore.return_value.certificates_search.assert_not_called()


def test_684_cahandler_lookup_db_error(
    logger: logging.Logger, capture_logs: Callable[..., AbstractContextManager[Any]]
) -> None:
    """cahandler_lookup logs a warning when certificates_search fails"""
    from acme2certifier.acme_srv.helpers.config import cahandler_lookup

    models_mock = MagicMock()
    models_mock.DBstore.return_value.certificates_search.side_effect = Exception(
        "db fail"
    )
    with patch.dict("sys.modules", {"acme2certifier.acme_srv.db_handler": models_mock}):
        with capture_logs("test_a2c", level="WARNING") as lcm:
            assert cahandler_lookup(logger, csr="csr") is None
    assert "WARNING:test_a2c:CAhandler lookup failed with: db fail" in lcm.output


@patch("acme2certifier.acme_srv.helpers.config.load_config")
def test_685_header_value_allowlist_resolve(
    mock_load_cfg: MagicMock, logger: logging.Logger, FakeDBStore: type[Any]
) -> None:
    """header_value_allowlist_resolve prefers Order then allowed_templates"""
    from acme2certifier.acme_srv.helpers.config import header_value_allowlist_resolve
    import configparser

    parser_order = configparser.ConfigParser()
    parser_order["Order"] = {"allowed_header_values": '["from-order"]'}
    mock_load_cfg.return_value = parser_order
    cahandler = FakeDBStore()
    cahandler.allowed_templates = ["from-templates"]
    assert ["from-order"] == header_value_allowlist_resolve(logger, cahandler)
    parser_empty = configparser.ConfigParser()
    mock_load_cfg.return_value = parser_empty
    cahandler.allowed_templates = ["from-templates"]
    assert ["from-templates"] == header_value_allowlist_resolve(logger, cahandler)
    cahandler_empty = FakeDBStore()
    assert [] == header_value_allowlist_resolve(logger, cahandler_empty)
