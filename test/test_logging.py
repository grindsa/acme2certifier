# -*- coding: utf-8 -*-
"""Tests for acme_srv.helpers.logging_utils."""

from __future__ import annotations

import configparser
import logging
import os
from collections.abc import Callable
from contextlib import AbstractContextManager
from typing import Any
from unittest.mock import MagicMock, Mock, patch

import pytest

from acme2certifier.acme_srv.helpers.logging_utils import (
    _logger_certificate_modify,
    _logger_challenges_modify,
    _logger_nonce_modify,
    _logger_token_modify,
    handle_exception,
    log_response,
    logger_setup,
    print_debug,
)

pytestmark = pytest.mark.usefixtures("clear_config_cache", "_silence_logging")


def test_216_logger_setup() -> None:
    """logger setup"""
    assert logger_setup(False)


def test_217_logger_setup() -> None:
    """logger setup"""
    assert logger_setup(True)


def test_218_logger_setup_false_quiets_http_loggers() -> None:
    """debug=False must not leave urllib3/requests at DEBUG"""
    import logging

    logging.getLogger().setLevel(logging.DEBUG)
    logging.getLogger("urllib3").setLevel(logging.DEBUG)
    logging.getLogger("requests").setLevel(logging.DEBUG)
    logger_setup(False)
    assert logging.getLogger().level >= logging.INFO
    assert logging.getLogger("urllib3").level >= logging.WARNING
    assert logging.getLogger("requests").level >= logging.WARNING


@patch("acme2certifier.acme_srv.helpers.logging_utils.load_config")
def test_219_logger_setup(mock_load_cfg: MagicMock) -> None:
    """logger setup"""
    mock_load_cfg.return_value = {
        "Helper": {
            "log_format": "%(asctime)s - acme2certifier - %(levelname)s - %(message)s"
        }
    }
    assert logger_setup(True)


@patch("acme2certifier.acme_srv.helpers.logging_utils.logging.handlers.SysLogHandler")
@patch("acme2certifier.acme_srv.helpers.logging_utils.load_config")
def test_220_logger_setup_syslog(
    mock_load_cfg: MagicMock, mock_syslog: MagicMock
) -> None:
    """logger setup attaches SysLogHandler when Helper.syslog_address is set"""
    from acme2certifier.acme_srv.helpers.logging_utils import _SYSLOG_FACILITY_MAP

    mock_cfg = configparser.RawConfigParser()
    mock_cfg["Helper"] = {
        "syslog_address": "/dev/log",
        "syslog_facility": "daemon",
        "log_format": "%(message)s",
    }
    mock_load_cfg.return_value = mock_cfg
    mock_handler = MagicMock()
    mock_syslog.return_value = mock_handler
    logger = logger_setup(False)
    mock_syslog.assert_called_once()
    call_kwargs = mock_syslog.call_args.kwargs
    assert call_kwargs["address"] == "/dev/log"
    assert call_kwargs["facility"] == _SYSLOG_FACILITY_MAP["daemon"]
    assert mock_handler in logger.handlers
    logger.removeHandler(mock_handler)


@patch("acme2certifier.acme_srv.helpers.logging_utils.logging.handlers.SysLogHandler")
@patch("acme2certifier.acme_srv.helpers.logging_utils.load_config")
def test_221_logger_setup_syslog_disabled_without_address(
    mock_load_cfg: MagicMock, mock_syslog: MagicMock
) -> None:
    """SysLogHandler is not attached when syslog_address is absent"""
    mock_cfg = configparser.RawConfigParser()
    mock_cfg["Helper"] = {"log_format": "%(message)s"}
    mock_load_cfg.return_value = mock_cfg
    logger_setup(False)
    mock_syslog.assert_not_called()


@patch("acme2certifier.acme_srv.helpers.logging_utils.logging.FileHandler")
@patch("acme2certifier.acme_srv.helpers.logging_utils.load_config")
def test_222_logger_setup_log_file(
    mock_load_cfg: MagicMock, mock_file_handler: MagicMock
) -> None:
    """logger setup attaches FileHandler when Helper.log_file is set"""
    mock_cfg = configparser.RawConfigParser()
    mock_cfg["Helper"] = {
        "log_file": "/var/log/acme2certifier/acme2certifier.log",
        "log_format": "%(message)s",
    }
    mock_load_cfg.return_value = mock_cfg
    mock_handler = MagicMock()
    mock_file_handler.return_value = mock_handler
    logger = logger_setup(False)
    mock_file_handler.assert_called_once_with(
        "/var/log/acme2certifier/acme2certifier.log"
    )
    assert mock_handler in logger.handlers
    logger.removeHandler(mock_handler)


@patch("acme2certifier.acme_srv.helpers.logging_utils.logging.FileHandler")
@patch("acme2certifier.acme_srv.helpers.logging_utils.load_config")
def test_223_logger_setup_log_file_disabled_without_path(
    mock_load_cfg: MagicMock, mock_file_handler: MagicMock
) -> None:
    """FileHandler is not attached when log_file is absent"""
    mock_cfg = configparser.RawConfigParser()
    mock_cfg["Helper"] = {"log_format": "%(message)s"}
    mock_load_cfg.return_value = mock_cfg
    logger_setup(False)
    mock_file_handler.assert_not_called()


@patch("acme2certifier.acme_srv.helpers.logging_utils.logging.FileHandler")
@patch("acme2certifier.acme_srv.helpers.logging_utils.load_config")
def test_224_logger_setup_log_file_open_failure(
    mock_load_cfg: MagicMock, mock_file_handler: MagicMock
) -> None:
    """FileHandler open failure is logged and does not raise"""
    mock_cfg = configparser.RawConfigParser()
    mock_cfg["Helper"] = {
        "log_file": "/no/such/dir/acme2certifier.log",
        "log_format": "%(message)s",
    }
    mock_load_cfg.return_value = mock_cfg
    mock_file_handler.side_effect = OSError("Permission denied")
    logger = logger_setup(False)
    assert logger
    mock_file_handler.assert_called_once()


def test_237_log_response(
    logger: logging.Logger, capture_logs: Callable[..., AbstractContextManager[Any]]
) -> None:
    """log_response success dump at INFO"""
    addr = "addr"
    url = "url"
    data_dic = {"foo": "bar"}
    with capture_logs("test_a2c", level="INFO") as lcm:
        log_response(logger, addr, url, data_dic)
    assert "INFO:test_a2c:addr url {'foo': 'bar'}" in lcm.output


def test_238_log_response(
    logger: logging.Logger, capture_logs: Callable[..., AbstractContextManager[Any]]
) -> None:
    """log_response redacts Nonce in header"""
    addr = "addr"
    url = "url"
    data_dic = {"foo": "bar", "header": {"Replay-Nonce": "Replay-Nonce"}}
    with capture_logs("test_a2c", level="INFO") as lcm:
        log_response(logger, addr, url, data_dic)
    assert (
        "INFO:test_a2c:addr url {'foo': 'bar', 'header': {'Replay-Nonce': '- modified -'}}"
        in lcm.output
    )


def test_239_log_response(
    logger: logging.Logger, capture_logs: Callable[..., AbstractContextManager[Any]]
) -> None:
    """log_response redacts cert body (dict data on /acme/cert path)"""
    addr = "addr"
    url = "/acme/cert/secret"
    data_dic = {"foo": "bar", "data": {"Replay-Nonce": "Replay-Nonce"}}
    with capture_logs("test_a2c", level="INFO") as lcm:
        log_response(logger, addr, url, data_dic)
    assert (
        "INFO:test_a2c:addr /acme/cert/secret {'foo': 'bar', 'data': ' - certificate - '}"
        in lcm.output
    )


def test_240_log_response_redacts_pem_chain(
    logger: logging.Logger, capture_logs: Callable[..., AbstractContextManager[Any]]
) -> None:
    """log_response redacts PEM certificate chain string on download"""
    addr = "addr"
    url = "/acme/cert/secret"
    pem_chain = "-----BEGIN CERTIFICATE-----\nMIIBleaf\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nMIIBca\n-----END CERTIFICATE-----"
    data_dic = {"code": 200, "data": pem_chain}
    with capture_logs("test_a2c", level="INFO") as lcm:
        log_response(logger, addr, url, data_dic)
    assert (
        "INFO:test_a2c:addr /acme/cert/secret {'code': 200, 'data': ' - certificate - '}"
        in lcm.output
    )
    assert all(("BEGIN CERTIFICATE" not in line for line in lcm.output))


def test_241_log_response_redacts_pem_on_custom_path(
    logger: logging.Logger, capture_logs: Callable[..., AbstractContextManager[Any]]
) -> None:
    """log_response redacts PEM body even when locator is a custom cert path"""
    addr = "addr"
    url = "/certificate/abc123"
    pem = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----"
    data_dic = {"code": 200, "data": pem}
    with capture_logs("test_a2c", level="INFO") as lcm:
        log_response(logger, addr, url, data_dic)
    assert (
        "INFO:test_a2c:addr /certificate/abc123 {'code': 200, 'data': ' - certificate - '}"
        in lcm.output
    )


@patch("acme2certifier.acme_srv.helpers.logging_utils.load_config")
def test_242_log_response_keeps_pem_when_log_cert_content(
    mock_load_config: MagicMock,
    logger: logging.Logger,
    capture_logs: Callable[..., AbstractContextManager[Any]],
) -> None:
    """log_response keeps PEM body when Helper.log_cert_content is True"""
    from configparser import ConfigParser

    cfg = ConfigParser()
    cfg.add_section("Helper")
    cfg.set("Helper", "log_cert_content", "True")
    mock_load_config.return_value = cfg
    addr = "addr"
    url = "/acme/cert/secret"
    pem = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----"
    data_dic = {"code": 200, "data": pem}
    with capture_logs("test_a2c", level="INFO") as lcm:
        log_response(logger, addr, url, data_dic)
    assert "BEGIN CERTIFICATE" in lcm.output[0]
    assert " - certificate - " not in lcm.output[0]


def test_243_log_response(
    logger: logging.Logger, capture_logs: Callable[..., AbstractContextManager[Any]]
) -> None:
    """log_response redacts token"""
    addr = "addr"
    url = "url"
    data_dic = {"foo": "bar", "data": {"token": "token"}}
    with capture_logs("test_a2c", level="INFO") as lcm:
        log_response(logger, addr, url, data_dic)
    assert (
        "INFO:test_a2c:addr url {'foo': 'bar', 'data': {'token': '- modified -'}}"
        in lcm.output
    )


def test_244_log_response(
    logger: logging.Logger, capture_logs: Callable[..., AbstractContextManager[Any]]
) -> None:
    """log_response redacts single token in challenges"""
    addr = "addr"
    url = "url"
    data_dic = {
        "foo": "bar",
        "data": {"challenges": [{"foo1": "bar1", "token": "token1"}]},
    }
    with capture_logs("test_a2c", level="INFO") as lcm:
        log_response(logger, addr, url, data_dic)
    assert (
        "INFO:test_a2c:addr url {'foo': 'bar', 'data': {'challenges': [{'foo1': 'bar1', 'token': '- modified - '}]}}"
        in lcm.output
    )


def test_245_log_response(
    logger: logging.Logger, capture_logs: Callable[..., AbstractContextManager[Any]]
) -> None:
    """log_response redacts two tokens in challenges"""
    addr = "addr"
    url = "url"
    data_dic = {
        "foo": "bar",
        "data": {
            "challenges": [
                {"foo1": "bar1", "token": "token1"},
                {"foo2": "bar2", "token": "token1"},
            ]
        },
    }
    with capture_logs("test_a2c", level="INFO") as lcm:
        log_response(logger, addr, url, data_dic)
    assert (
        "INFO:test_a2c:addr url {'foo': 'bar', 'data': {'challenges': [{'foo1': 'bar1', 'token': '- modified - '}, {'foo2': 'bar2', 'token': '- modified - '}]}}"
        in lcm.output
    )


def test_246_log_response_debug_dump_on_4xx(
    logger: logging.Logger, capture_logs: Callable[..., AbstractContextManager[Any]]
) -> None:
    """ACME 4xx responses: edge log_response only dumps at DEBUG"""
    addr = "addr"
    url = "/acme/newaccount"
    data_dic = {
        "code": 403,
        "data": {
            "status": 403,
            "type": "urn:ietf:params:acme:error:unauthorized",
            "detail": "invalid eab credentials",
        },
    }
    with capture_logs("test_a2c", level="DEBUG") as lcm:
        log_response(logger, addr, url, data_dic)
    assert any(
        (
            line.startswith("DEBUG:test_a2c:addr /acme/newaccount")
            and "invalid eab credentials" in line
            for line in lcm.output
        )
    )
    assert not any(
        (
            line.startswith("WARNING:") or line.startswith("ERROR:")
            for line in lcm.output
        )
    )


def test_247_log_response_debug_dump_on_5xx(
    logger: logging.Logger, capture_logs: Callable[..., AbstractContextManager[Any]]
) -> None:
    """ACME 5xx responses: edge log_response only dumps at DEBUG"""
    addr = "addr"
    url = "/acme/order"
    data_dic = {
        "code": 500,
        "header": {"Replay-Nonce": "secret-nonce"},
        "data": {
            "status": 500,
            "type": "urn:ietf:params:acme:error:serverInternal",
            "detail": "Database error",
        },
    }
    with capture_logs("test_a2c", level="DEBUG") as lcm:
        log_response(logger, addr, url, data_dic)
    assert any(
        (
            line.startswith("DEBUG:test_a2c:addr /acme/order")
            and "- modified -" in line
            for line in lcm.output
        )
    )
    assert not any(
        (
            line.startswith("WARNING:") or line.startswith("ERROR:")
            for line in lcm.output
        )
    )


@patch("builtins.print")
def test_248_print_debug(mock_print: MagicMock) -> None:
    """test print_debug"""
    print_debug(False, "test")
    assert not mock_print.called


@patch("builtins.print")
def test_249_print_debug(mock_print: MagicMock) -> None:
    """test print_debug"""
    print_debug(True, "test")
    assert mock_print.called


@patch("sys.__excepthook__")
def test_283_handle_exception_keyboard_interrupt(mock_excepthook: MagicMock) -> None:
    """test handle_exception with KeyboardInterrupt - should call sys.__excepthook__"""
    exc_type = KeyboardInterrupt
    exc_value = KeyboardInterrupt("Test keyboard interrupt")
    exc_traceback = Mock()
    result = handle_exception(exc_type, exc_value, exc_traceback)
    mock_excepthook.assert_called_once_with(exc_type, exc_value, exc_traceback)
    assert result is None


@patch("logging.exception")
def test_284_handle_exception_regular_exception(
    mock_logging_exception: MagicMock,
) -> None:
    """test handle_exception with regular exception - should call logging.exception"""
    exc_type = ValueError
    exc_value = ValueError("Test value error")
    exc_traceback = Mock()
    result = handle_exception(exc_type, exc_value, exc_traceback)
    mock_logging_exception.assert_called_once_with(
        "Uncaught exception", exc_info=(exc_type, exc_value, exc_traceback)
    )
    assert result is None


@patch("logging.exception")
def test_285_handle_exception_runtime_error(mock_logging_exception: MagicMock) -> None:
    """test handle_exception with RuntimeError - should call logging.exception"""
    exc_type = RuntimeError
    exc_value = RuntimeError("Test runtime error")
    exc_traceback = Mock()
    result = handle_exception(exc_type, exc_value, exc_traceback)
    mock_logging_exception.assert_called_once_with(
        "Uncaught exception", exc_info=(exc_type, exc_value, exc_traceback)
    )
    assert result is None


@patch("logging.exception")
def test_286_handle_exception_type_error(mock_logging_exception: MagicMock) -> None:
    """test handle_exception with TypeError - should call logging.exception"""
    exc_type = TypeError
    exc_value = TypeError("Test type error")
    exc_traceback = Mock()
    result = handle_exception(exc_type, exc_value, exc_traceback)
    mock_logging_exception.assert_called_once_with(
        "Uncaught exception", exc_info=(exc_type, exc_value, exc_traceback)
    )
    assert result is None


@patch("sys.__excepthook__")
@patch("logging.exception")
def test_287_handle_exception_keyboard_interrupt_subclass(
    mock_logging_exception: MagicMock, mock_excepthook: MagicMock
) -> None:
    """test handle_exception with KeyboardInterrupt subclass - should call sys.__excepthook__"""

    class CustomKeyboardInterrupt(KeyboardInterrupt):
        pass

    exc_type = CustomKeyboardInterrupt
    exc_value = CustomKeyboardInterrupt("Custom keyboard interrupt")
    exc_traceback = Mock()
    result = handle_exception(exc_type, exc_value, exc_traceback)
    mock_excepthook.assert_called_once_with(exc_type, exc_value, exc_traceback)
    mock_logging_exception.assert_not_called()
    assert result is None


@patch("logging.exception")
def test_288_handle_exception_system_exit(mock_logging_exception: MagicMock) -> None:
    """test handle_exception with SystemExit - should call logging.exception"""
    exc_type = SystemExit
    exc_value = SystemExit(1)
    exc_traceback = Mock()
    result = handle_exception(exc_type, exc_value, exc_traceback)
    mock_logging_exception.assert_called_once_with(
        "Uncaught exception", exc_info=(exc_type, exc_value, exc_traceback)
    )
    assert result is None


@patch("logging.exception")
def test_289_handle_exception_custom_exception(
    mock_logging_exception: MagicMock,
) -> None:
    """test handle_exception with custom exception - should call logging.exception"""

    class CustomException(Exception):
        pass

    exc_type = CustomException
    exc_value = CustomException("Custom exception message")
    exc_traceback = Mock()
    result = handle_exception(exc_type, exc_value, exc_traceback)
    mock_logging_exception.assert_called_once_with(
        "Uncaught exception", exc_info=(exc_type, exc_value, exc_traceback)
    )
    assert result is None


def test_324_logger_nonce_modify() -> None:
    """test _logger_nonce_modify()"""
    data_dic = {"foo": "bar"}
    assert {"foo": "bar"} == _logger_nonce_modify(data_dic)


def test_325_logger_nonce_modify() -> None:
    """test _logger_nonce_modify()"""
    data_dic = {"foo": "bar", "header": {"foo": "bar"}}
    assert {"foo": "bar", "header": {"foo": "bar"}} == _logger_nonce_modify(data_dic)


def test_326_logger_nonce_modify() -> None:
    """test _logger_nonce_modify()"""
    data_dic = {"foo": "bar", "header": {"Replay-Nonce": "bar"}}
    assert {
        "foo": "bar",
        "header": {"Replay-Nonce": "- modified -"},
    } == _logger_nonce_modify(data_dic)


def test_327_logger_certificate_modify() -> None:
    """test _logger_certificate_modify()"""
    data_dic = {"data": "bar"}
    assert {"data": "bar"} == _logger_certificate_modify(data_dic, "locator")


def test_328_logger_certificate_modify() -> None:
    """test _logger_certificate_modify()"""
    data_dic = {"data": "bar"}
    assert {"data": " - certificate - "} == _logger_certificate_modify(
        data_dic, "foo/acme/cert"
    )


def test_329_logger_certificate_modify_pem_content() -> None:
    """test _logger_certificate_modify() redacts PEM without /acme/cert path"""
    data_dic = {"data": "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----"}
    assert {"data": " - certificate - "} == _logger_certificate_modify(
        data_dic, "/custom/cert/path"
    )


def test_330_logger_token_modify() -> None:
    """test _logger_token_modify()"""
    data_dic = {"data": "bar"}
    assert {"data": "bar"} == _logger_token_modify(data_dic)


def test_331_logger_token_modify() -> None:
    """test _logger_token_modify()"""
    data_dic = {"data": {"token": "token"}}
    assert {"data": {"token": "- modified -"}} == _logger_token_modify(data_dic)


def test_332_logger_challenges_modify() -> None:
    """test _logger_challenges_modify()"""
    data_dic = {"data": "bar"}
    assert {"data": "bar"} == _logger_challenges_modify(data_dic)


def test_333_logger_challenges_modify() -> None:
    """test _logger_challenges_modify()"""
    data_dic = {"data": {"challenges": [{"token": "token1"}]}}
    assert {
        "data": {"challenges": [{"token": "- modified - "}]}
    } == _logger_challenges_modify(data_dic)


def test_334_logger_challenges_modify() -> None:
    """test _logger_challenges_modify()"""
    data_dic = {"data": {"challenges": [{"token": "token1"}, {"token": "token2"}]}}
    assert {
        "data": {"challenges": [{"token": "- modified - "}, {"token": "- modified - "}]}
    } == _logger_challenges_modify(data_dic)


def test_636_response_http_code_non_dict() -> None:
    """_response_http_code returns None for non-dict payloads"""
    from acme2certifier.acme_srv.helpers.logging_utils import _response_http_code

    assert _response_http_code("not-a-dict") is None
    assert _response_http_code(None) is None


def test_637_response_http_code_invalid_code() -> None:
    """_response_http_code returns None when code cannot be converted to int"""
    from acme2certifier.acme_srv.helpers.logging_utils import _response_http_code

    assert _response_http_code({"code": "not-an-int"}) is None
    assert _response_http_code({"code": object()}) is None


def test_638_log_response_success_with_code_200(
    logger: logging.Logger, capture_logs: Callable[..., AbstractContextManager[Any]]
) -> None:
    """log_response INFO path for successful HTTP codes (< 400)"""
    with capture_logs("test_a2c", level="INFO") as lcm:
        log_response(logger, "addr", "/acme/directory", {"code": 200, "data": "ok"})
    assert (
        "INFO:test_a2c:addr /acme/directory {'code': 200, 'data': 'ok'}" in lcm.output
    )


def test_639_syslog_address_host_port_and_fallbacks() -> None:
    """_syslog_address parses host:port and falls back for invalid forms"""
    from acme2certifier.acme_srv.helpers.logging_utils import _syslog_address

    assert ("localhost", 514) == _syslog_address("localhost:514")
    assert "host:bad" == _syslog_address("host:bad")
    assert "udp-host" == _syslog_address("udp-host")


@patch("acme2certifier.acme_srv.helpers.logging_utils.logging.handlers.SysLogHandler")
@patch("acme2certifier.acme_srv.helpers.logging_utils.load_config")
def test_640_logger_setup_syslog_empty_address(
    mock_load_cfg: MagicMock, mock_syslog: MagicMock
) -> None:
    """empty syslog_address does not attach SysLogHandler"""
    mock_cfg = configparser.RawConfigParser()
    mock_cfg["Helper"] = {"syslog_address": "   ", "log_format": "%(message)s"}
    mock_load_cfg.return_value = mock_cfg
    logger_setup(False)
    mock_syslog.assert_not_called()


def test_641_logger_setup_syslog_already_attached() -> None:
    """existing SysLogHandler is not duplicated"""
    import logging as logging_mod
    from acme2certifier.acme_srv.helpers.logging_utils import _attach_syslog_handler

    class DummySyslog(logging_mod.handlers.SysLogHandler):

        def __init__(self):
            logging_mod.Handler.__init__(self)

    logger = logging_mod.getLogger("test_a2c_syslog_dup")
    logger.handlers.clear()
    existing = DummySyslog()
    logger.addHandler(existing)
    cfg = configparser.RawConfigParser()
    cfg["Helper"] = {"syslog_address": "/dev/log"}
    try:
        _attach_syslog_handler(logger, cfg, logging_mod.Formatter("%(message)s"))
        assert [existing] == logger.handlers
    finally:
        logger.handlers.clear()


def test_642_logger_setup_syslog_oserror(
    logger: logging.Logger, capture_logs: Callable[..., AbstractContextManager[Any]]
) -> None:
    """SysLogHandler OSError is logged and does not raise"""
    import logging as logging_mod
    from acme2certifier.acme_srv.helpers.logging_utils import _attach_syslog_handler

    class RaisingSyslog(logging_mod.handlers.SysLogHandler):

        def __init__(self, *args, **kwargs):
            raise OSError("syslog unavailable")

    cfg = configparser.RawConfigParser()
    cfg["Helper"] = {"syslog_address": "/dev/log"}
    with patch(
        "acme2certifier.acme_srv.helpers.logging_utils.logging.handlers.SysLogHandler",
        RaisingSyslog,
    ):
        with capture_logs("test_a2c", level="ERROR") as lcm:
            _attach_syslog_handler(logger, cfg, logging_mod.Formatter("%(message)s"))
    assert any(("Failed to attach SysLogHandler" in line for line in lcm.output))


@patch("acme2certifier.acme_srv.helpers.logging_utils.logging.FileHandler")
@patch("acme2certifier.acme_srv.helpers.logging_utils.load_config")
def test_643_logger_setup_log_file_empty_path(
    mock_load_cfg: MagicMock, mock_file_handler: MagicMock
) -> None:
    """empty log_file does not attach FileHandler"""
    mock_cfg = configparser.RawConfigParser()
    mock_cfg["Helper"] = {"log_file": "  ", "log_format": "%(message)s"}
    mock_load_cfg.return_value = mock_cfg
    logger_setup(False)
    mock_file_handler.assert_not_called()


def test_644_logger_setup_log_file_already_attached() -> None:
    """existing FileHandler for same path is not duplicated"""
    import logging as logging_mod
    import os
    from acme2certifier.acme_srv.helpers.logging_utils import _attach_file_handler

    class DummyFileHandler(logging_mod.FileHandler):

        def __init__(self, filename):
            logging_mod.Handler.__init__(self)
            self.baseFilename = os.path.abspath(filename)

    log_path = "/tmp/a2c_logging_utils_coverage.log"
    logger = logging_mod.getLogger("test_a2c_file_dup")
    logger.handlers.clear()
    existing = DummyFileHandler(log_path)
    logger.addHandler(existing)
    cfg = configparser.RawConfigParser()
    cfg["Helper"] = {"log_file": log_path}
    try:
        _attach_file_handler(logger, cfg, logging_mod.Formatter("%(message)s"))
        assert [existing] == logger.handlers
    finally:
        logger.handlers.clear()


@patch("acme2certifier.acme_srv.helpers.logging_utils.load_config")
def test_645_log_cert_content_enabled_missing_helper_section(
    mock_load_config: MagicMock,
) -> None:
    """_log_cert_content_enabled returns False when Helper section is absent"""
    from configparser import ConfigParser
    from acme2certifier.acme_srv.helpers.logging_utils import _log_cert_content_enabled

    mock_load_config.return_value = ConfigParser()
    assert not _log_cert_content_enabled()


@patch("acme2certifier.acme_srv.helpers.logging_utils.load_config")
def test_646_log_cert_content_enabled_invalid_boolean(
    mock_load_config: MagicMock,
) -> None:
    """_log_cert_content_enabled returns False when log_cert_content is not a bool"""
    from configparser import ConfigParser
    from acme2certifier.acme_srv.helpers.logging_utils import _log_cert_content_enabled

    cfg = ConfigParser()
    cfg.add_section("Helper")
    cfg.set("Helper", "log_cert_content", "not-a-bool")
    mock_load_config.return_value = cfg
    assert not _log_cert_content_enabled()


def test_692_config_debug_get_cfg_overrides_env() -> None:
    """DEFAULT.debug overrides ACME2CERTIFIER_DEBUG when set"""
    from acme2certifier.acme_srv.helpers.logging_utils import (
        config_debug_get,
        env_debug_get,
    )

    empty = configparser.ConfigParser()
    with patch.dict(os.environ, {"ACME2CERTIFIER_DEBUG": "1"}):
        assert env_debug_get()
        assert config_debug_get(empty)
        cfg_off = configparser.ConfigParser()
        cfg_off.set("DEFAULT", "debug", "False")
        assert not config_debug_get(cfg_off)
    cfg_on = configparser.ConfigParser()
    cfg_on.set("DEFAULT", "debug", "True")
    with patch.dict(os.environ, {"ACME2CERTIFIER_DEBUG": "0"}):
        assert not env_debug_get()
        assert config_debug_get(cfg_on)
        assert not config_debug_get(empty)
    cfg_bad = configparser.ConfigParser()
    cfg_bad.set("DEFAULT", "debug", "not-a-bool")
    with patch.dict(os.environ, {"ACME2CERTIFIER_DEBUG": "1"}):
        assert config_debug_get(cfg_bad)
        assert config_debug_get({"DEFAULT": {"debug": True}})
        assert not config_debug_get({"DEFAULT": {"debug": "False"}})
        assert config_debug_get({"DEFAULT": {"debug": "yes"}})
        assert config_debug_get(object())
    with patch(
        "acme2certifier.acme_srv.helpers.logging_utils.load_config", return_value=cfg_on
    ):
        assert config_debug_get(None)


def test_693_logger_setup_false_filters_load_config_debug(
    capture_logs: Callable[..., AbstractContextManager[Any]],
) -> None:
    """logger_setup(False) applies INFO before load_config DEBUG"""
    import logging

    cfg = configparser.RawConfigParser()
    cfg["Helper"] = {"log_format": "%(message)s"}

    def _load():
        logging.getLogger("acme2certifier").debug("Helper.load_config() start")
        return cfg

    with patch(
        "acme2certifier.acme_srv.helpers.logging_utils.load_config", side_effect=_load
    ):
        with capture_logs("acme2certifier", level="DEBUG") as lcm:
            logging.getLogger("acme2certifier").info("marker")
            logger_setup(False)
    assert any(("marker" in msg for msg in lcm.output))
    assert not any(("Helper.load_config" in msg for msg in lcm.output))


def test_694_apply_log_levels_and_dict_debug_invalid() -> None:
    """apply_log_levels and non-ConfigParser DEFAULT.debug parsing"""
    import logging
    from acme2certifier.acme_srv.helpers.logging_utils import (
        apply_log_levels,
        config_debug_get,
        _explicit_default_debug,
    )

    logging.getLogger().setLevel(logging.DEBUG)
    logging.getLogger("urllib3").setLevel(logging.DEBUG)
    apply_log_levels(False)
    assert logging.getLogger().level >= logging.INFO
    assert logging.getLogger("urllib3").level >= logging.WARNING
    with patch.dict(os.environ, {"ACME2CERTIFIER_DEBUG": "0"}):
        assert not config_debug_get({"DEFAULT": {"debug": "maybe"}})
        assert not config_debug_get({"DEFAULT": {}})
        assert not config_debug_get({"Helper": {}})
        assert _explicit_default_debug(None) is None
        assert _explicit_default_debug({"DEFAULT": {"debug": "maybe"}}) is None
        assert not _explicit_default_debug({"DEFAULT": {"debug": False}})
