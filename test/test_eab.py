# -*- coding: utf-8 -*-
"""Tests for acme_srv.helpers.eab."""

from __future__ import annotations

import logging
import os
from collections.abc import Callable
from contextlib import AbstractContextManager
from typing import Any
from unittest.mock import MagicMock, Mock, patch

import pytest

from acme2certifier.acme_srv.helpers.eab import (
    eab_profile_as_bool,
    eab_profile_check,
    eab_profile_header_info_check,
    eab_profile_list_check,
    eab_profile_revocation_check,
    eab_profile_string_check,
    eab_profile_subject_check,
    eab_profile_subject_string_check,
)

pytestmark = pytest.mark.usefixtures("clear_config_cache", "_silence_logging")


def test_410_eab_profile_string_check(
    logger: logging.Logger, FakeDBStore: type[Any]
) -> None:
    """test _eab_profile_string_check()"""
    cahandler = FakeDBStore()
    cahandler.foo = "foo"
    eab_profile_string_check(logger, cahandler, "foo", "bar")
    assert "bar" == cahandler.foo


def test_411_eab_profile_string_check_redacts_credential(
    logger: logging.Logger,
    capture_logs: Callable[..., AbstractContextManager[Any]],
    FakeDBStore: type[Any],
) -> None:
    """credential-like profile values are applied but not logged"""
    cahandler = FakeDBStore()
    cahandler.api_password = "old"
    secret = "s3cret-value"
    with capture_logs("test_a2c", level="DEBUG") as lcm:
        eab_profile_string_check(logger, cahandler, "api_password", secret)
    assert secret == cahandler.api_password
    joined = "\n".join(lcm.output)
    assert secret not in joined
    assert "<redacted>" in joined


def test_412_eab_profile_string_check_logs_non_credential(
    logger: logging.Logger,
    capture_logs: Callable[..., AbstractContextManager[Any]],
    FakeDBStore: type[Any],
) -> None:
    """non-credential profile values remain in debug logs"""
    cahandler = FakeDBStore()
    cahandler.foo = "old"
    with capture_logs("test_a2c", level="DEBUG") as lcm:
        eab_profile_string_check(logger, cahandler, "foo", "bar")
    assert "value: bar" in "\n".join(lcm.output)


def test_413_eab_profile_string_check(
    logger: logging.Logger,
    capture_logs: Callable[..., AbstractContextManager[Any]],
    FakeDBStore: type[Any],
) -> None:
    """test _eab_profile_string_check()"""
    cahandler = FakeDBStore()
    cahandler.foo = "foo"
    with capture_logs("test_a2c", level="INFO") as lcm:
        eab_profile_string_check(logger, cahandler, "foobar", "bar")
    assert "foo" == cahandler.foo
    assert (
        "WARNING:test_a2c:EAB profile string checking: ignoring unrecognized string attribute: key: foobar"
        in lcm.output
    )


def test_414_eab_profile_as_bool() -> None:
    """test eab_profile_as_bool() normalization"""
    assert eab_profile_as_bool(True)
    assert not eab_profile_as_bool(False)
    assert eab_profile_as_bool("True")
    assert not eab_profile_as_bool("False")
    assert eab_profile_as_bool("true")
    assert not eab_profile_as_bool("false")
    assert eab_profile_as_bool("1")
    assert not eab_profile_as_bool("0")
    assert eab_profile_as_bool(None, default=True)
    assert not eab_profile_as_bool(None, default=False)
    assert eab_profile_as_bool("invalid", default=True)
    assert not eab_profile_as_bool("invalid", default=False)


def test_415_eab_profile_list_check(
    logger: logging.Logger,
    capture_logs: Callable[..., AbstractContextManager[Any]],
    FakeDBStore: type[Any],
) -> None:
    """test _eab_profile_list_check()"""
    cahandler = FakeDBStore()
    cahandler.foo = "foo"
    eabhandler = Mock()
    with capture_logs("test_a2c", level="INFO") as lcm:
        eab_profile_list_check(logger, cahandler, eabhandler, "csr", "foobar", "bar")
    assert "foo" == cahandler.foo
    assert (
        "WARNING:test_a2c:EAP profile list checking: ignoring unrecognized list attribute: key: foobar"
        in lcm.output
    )


@patch("acme2certifier.acme_srv.helpers.eab.allowed_domainlist_check")
def test_416_eab_profile_list_check(
    mock_chk: MagicMock, logger: logging.Logger, FakeDBStore: type[Any]
) -> None:
    """test _eab_profile_list_check()"""
    cahandler = FakeDBStore()
    eabhandler = Mock()
    mock_chk.return_value = False
    cahandler.foo = "foo"
    eab_profile_list_check(
        logger, cahandler, eabhandler, "csr", "allowed_domainlist", "bar"
    )
    assert "foo" == cahandler.foo


@patch("acme2certifier.acme_srv.helpers.eab.allowed_domainlist_check")
def test_417_eab_profile_list_check(
    mock_chk: MagicMock, logger: logging.Logger, FakeDBStore: type[Any]
) -> None:
    """test _eab_profile_list_check()"""
    cahandler = FakeDBStore()
    mock_chk.return_value = "error"
    cahandler.foo = "foo"
    eabhandler = Mock()
    assert "error" == eab_profile_list_check(
        logger, cahandler, eabhandler, "csr", "allowed_domainlist", "bar"
    )
    assert "foo" == cahandler.foo


@patch("acme2certifier.acme_srv.helpers.eab.allowed_domainlist_check")
@patch("acme2certifier.acme_srv.helpers.eab.client_parameter_validate")
def test_418_eab_profile_list_check(
    mock_hifv: MagicMock,
    mock_chk: MagicMock,
    logger: logging.Logger,
    FakeDBStore: type[Any],
) -> None:
    """test _eab_profile_list_check()"""
    cahandler = FakeDBStore()
    cahandler.foo = "foo"
    cahandler.header_info_field = "header_info_field"
    mock_chk.return_value = "error"
    cahandler.foo = "foo"
    eabhandler = Mock()
    mock_hifv.return_value = ("mock_hifv", None)
    assert not eab_profile_list_check(
        logger, cahandler, eabhandler, "csr", "foo", "bar"
    )
    assert "mock_hifv" == cahandler.foo


@patch("acme2certifier.acme_srv.helpers.eab.allowed_domainlist_check")
@patch("acme2certifier.acme_srv.helpers.eab.client_parameter_validate")
def test_419_eab_profile_list_check(
    mock_hifv: MagicMock,
    mock_chk: MagicMock,
    logger: logging.Logger,
    FakeDBStore: type[Any],
) -> None:
    """test _eab_profile_list_check()"""
    cahandler = FakeDBStore()
    cahandler.foo = "foo"
    cahandler.header_info_field = "header_info_field"
    mock_chk.return_value = "error"
    cahandler.foo = "foo"
    eabhandler = Mock()
    mock_hifv.return_value = (None, "error")
    assert "error" == eab_profile_list_check(
        logger, cahandler, eabhandler, "csr", "foo", "bar"
    )
    assert "foo" == cahandler.foo


@patch("acme2certifier.acme_srv.helpers.eab.allowed_domainlist_check")
def test_420_eab_profile_list_check(
    mock_chk: MagicMock, logger: logging.Logger, FakeDBStore: type[Any]
) -> None:
    """test _eab_profile_list_check() test allowed domain check if cahander contains attribute"""
    cahandler = FakeDBStore()
    mock_chk.return_value = False
    cahandler.allowed_domainlist = ["foo", "foobar"]
    cahandler.foo = "foo"
    cahandler.header_info_field = None
    eabhandler = Mock()
    assert not eab_profile_list_check(
        logger, cahandler, eabhandler, "csr", "allowed_domainlist", ["bar"]
    )
    assert "foo" == cahandler.foo
    assert ["foo", "foobar"] == cahandler.allowed_domainlist
    assert mock_chk.called


@patch("acme2certifier.acme_srv.helpers.eab.allowed_domainlist_check")
def test_421_eab_profile_list_check(
    mock_chk: MagicMock,
    logger: logging.Logger,
    capture_logs: Callable[..., AbstractContextManager[Any]],
    FakeDBStore: type[Any],
) -> None:
    """test _eab_profile_list_check() test allowed domain check if eabhandler contains attribute"""
    cahandler = FakeDBStore()
    mock_chk.return_value = False
    cahandler.allowed_domainlist = ["foo", "foobar"]
    cahandler.foo = "foo"
    cahandler.header_info_field = None
    eabhandler = Mock()
    eabhandler.allowed_domains_check.return_value = False
    with capture_logs("test_a2c", level="INFO") as lcm:
        assert not eab_profile_list_check(
            logger, cahandler, eabhandler, "csr", "allowed_domainlist", ["bar"]
        )
    assert (
        "INFO:test_a2c:Execute allowed_domains_check() from eab handler" in lcm.output
    )
    assert "foo" == cahandler.foo
    assert ["foo", "foobar"] == cahandler.allowed_domainlist
    assert not mock_chk.called


@patch("acme2certifier.acme_srv.helpers.eab.allowed_domainlist_check")
def test_422_eab_profile_list_check(
    mock_chk: MagicMock,
    logger: logging.Logger,
    capture_logs: Callable[..., AbstractContextManager[Any]],
    FakeDBStore: type[Any],
) -> None:
    """test _eab_profile_list_check() test allowed domain check if eabhandler contains attribute"""
    cahandler = FakeDBStore()
    mock_chk.return_value = False
    cahandler.allowed_domainlist = ["foo", "foobar"]
    cahandler.foo = "foo"
    cahandler.header_info_field = None
    eabhandler = Mock()
    eabhandler.allowed_domains_check.return_value = "eab_error"
    with capture_logs("test_a2c", level="INFO") as lcm:
        assert "eab_error" == eab_profile_list_check(
            logger, cahandler, eabhandler, "csr", "allowed_domainlist", ["bar"]
        )
    assert (
        "INFO:test_a2c:Execute allowed_domains_check() from eab handler" in lcm.output
    )
    assert "foo" == cahandler.foo
    assert ["foo", "foobar"] == cahandler.allowed_domainlist
    assert not mock_chk.called


@patch("acme2certifier.acme_srv.helpers.eab.profile_lookup")
@patch("acme2certifier.acme_srv.helpers.eab.eab_profile_check")
@patch("acme2certifier.acme_srv.helpers.eab.header_info_lookup")
def test_423_eab_profile_header_info_check(
    mock_lookup: MagicMock,
    mock_eab: MagicMock,
    mock_profile: MagicMock,
    logger: logging.Logger,
    FakeDBStore: type[Any],
) -> None:
    """test eab_profile_header_info_check()"""
    cahandler = FakeDBStore()
    cahandler.eab_profiling = False
    cahandler.header_info_field = None
    assert not eab_profile_header_info_check(
        logger, cahandler, "csr", "handler_hifield"
    )
    assert not mock_lookup.called
    assert not mock_eab.called
    assert not mock_profile.called


@patch("acme2certifier.acme_srv.helpers.eab.profile_lookup")
@patch("acme2certifier.acme_srv.helpers.eab.eab_profile_check")
@patch("acme2certifier.acme_srv.helpers.eab.header_info_lookup")
def test_424_eab_profile_header_info_check(
    mock_lookup: MagicMock,
    mock_eab: MagicMock,
    mock_profile: MagicMock,
    logger: logging.Logger,
    FakeDBStore: type[Any],
) -> None:
    """test eab_profile_header_info_check()"""
    cahandler = FakeDBStore()
    cahandler.eab_profiling = False
    cahandler.header_info_field = None
    cahandler.profiles = {"profile": "profile"}
    mock_profile.return_value = "profile_value"
    assert not eab_profile_header_info_check(
        logger, cahandler, "csr", "handler_hifield"
    )
    assert not mock_lookup.called
    assert not mock_eab.called
    assert mock_profile.called
    assert "profile_value" == cahandler.handler_hifield


@patch("acme2certifier.acme_srv.helpers.eab.profile_lookup")
@patch("acme2certifier.acme_srv.helpers.eab.eab_profile_check")
@patch("acme2certifier.acme_srv.helpers.eab.header_info_lookup")
def test_425_eab_profile_header_info_check(
    mock_lookup: MagicMock,
    mock_eab: MagicMock,
    mock_profile: MagicMock,
    logger: logging.Logger,
    FakeDBStore: type[Any],
) -> None:
    """test eab_profile_header_info_check()"""
    cahandler = FakeDBStore()
    cahandler.eab_profiling = False
    cahandler.header_info_field = None
    cahandler.handler_hifield = "old_value"
    cahandler.profiles = {"profile": "profile"}
    mock_profile.return_value = None
    assert not eab_profile_header_info_check(
        logger, cahandler, "csr", "handler_hifield"
    )
    assert not mock_lookup.called
    assert not mock_eab.called
    assert mock_profile.called
    assert "old_value" == cahandler.handler_hifield


@patch("acme2certifier.acme_srv.helpers.eab.profile_lookup")
@patch("acme2certifier.acme_srv.helpers.eab.eab_profile_check")
@patch("acme2certifier.acme_srv.helpers.eab.header_info_lookup")
def test_426_eab_profile_header_info_check_skip_handler_routing_name(
    mock_lookup: MagicMock,
    mock_eab: MagicMock,
    mock_profile: MagicMock,
    logger: logging.Logger,
    FakeDBStore: type[Any],
) -> None:
    """ACME profile matching cahandler_registry_name is routing-only."""
    cahandler = FakeDBStore()
    cahandler.eab_profiling = False
    cahandler.header_info_field = None
    cahandler.handler_hifield = "OV"
    cahandler.cahandler_registry_name = "harica"
    cahandler.profiles = {"harica": "http://example/harica"}
    mock_profile.return_value = "harica"
    assert not eab_profile_header_info_check(
        logger, cahandler, "csr", "handler_hifield"
    )
    assert not mock_lookup.called
    assert not mock_eab.called
    assert mock_profile.called
    assert "OV" == cahandler.handler_hifield


@patch("acme2certifier.acme_srv.helpers.eab.profile_lookup")
@patch("acme2certifier.acme_srv.helpers.eab.eab_profile_check")
@patch("acme2certifier.acme_srv.helpers.eab.header_value_allowlist_resolve")
@patch("acme2certifier.acme_srv.helpers.eab.header_info_lookup")
def test_427_eab_profile_header_info_check(
    mock_lookup: MagicMock,
    mock_allowlist: MagicMock,
    mock_eab: MagicMock,
    mock_profile: MagicMock,
    logger: logging.Logger,
    capture_logs: Callable[..., AbstractContextManager[Any]],
    FakeDBStore: type[Any],
) -> None:
    """header value ignored when allowlist empty and risk gate unset"""
    from acme2certifier.acme_srv.helpers.security_gate import SECURITY_DISABLE_ACK_ENV

    cahandler = FakeDBStore()
    cahandler.eab_profiling = False
    cahandler.header_info_field = "hi_field"
    mock_allowlist.return_value = []
    mock_lookup.return_value = "hi_value"
    cahandler.hi_field = "pre_hi_field"
    with patch.dict(os.environ, {SECURITY_DISABLE_ACK_ENV: ""}, clear=False):
        with capture_logs("test_a2c", level="WARNING") as lcm:
            assert not eab_profile_header_info_check(
                logger, cahandler, "csr", "hi_field"
            )
    assert any(
        ("Ignoring client-selected hi_field=hi_value" in msg for msg in lcm.output)
    )
    assert "pre_hi_field" == cahandler.hi_field
    assert mock_lookup.called
    assert not mock_eab.called
    assert not mock_profile.called


@patch("acme2certifier.acme_srv.helpers.eab.eab_profile_check")
@patch("acme2certifier.acme_srv.helpers.eab.header_value_allowlist_resolve")
@patch("acme2certifier.acme_srv.helpers.eab.header_info_lookup")
def test_428_eab_profile_header_info_check(
    mock_lookup: MagicMock,
    mock_allowlist: MagicMock,
    mock_eab: MagicMock,
    logger: logging.Logger,
    capture_logs: Callable[..., AbstractContextManager[Any]],
    FakeDBStore: type[Any],
) -> None:
    """default profile_name kept when allowlist empty and risk gate unset"""
    from acme2certifier.acme_srv.helpers.security_gate import SECURITY_DISABLE_ACK_ENV

    cahandler = FakeDBStore()
    cahandler.eab_profiling = False
    cahandler.header_info_field = "hi_field"
    mock_allowlist.return_value = []
    mock_lookup.return_value = "hi_value"
    cahandler.hi_field = "pre_hi_field"
    cahandler.profile_name = "profile_name"
    with patch.dict(os.environ, {SECURITY_DISABLE_ACK_ENV: ""}, clear=False):
        with capture_logs("test_a2c", level="WARNING") as lcm:
            assert not eab_profile_header_info_check(logger, cahandler, "csr")
    assert any(
        ("Ignoring client-selected profile_name=hi_value" in msg for msg in lcm.output)
    )
    assert "pre_hi_field" == cahandler.hi_field
    assert "profile_name" == cahandler.profile_name
    assert mock_lookup.called
    assert not mock_eab.called


@patch("acme2certifier.acme_srv.helpers.eab.header_value_allowlist_resolve")
@patch("acme2certifier.acme_srv.helpers.eab.eab_profile_check")
@patch("acme2certifier.acme_srv.helpers.eab.header_info_lookup")
def test_429_eab_profile_header_info_check_allowlist(
    mock_lookup: MagicMock,
    mock_eab: MagicMock,
    mock_allowlist: MagicMock,
    logger: logging.Logger,
    capture_logs: Callable[..., AbstractContextManager[Any]],
    FakeDBStore: type[Any],
) -> None:
    """header value applied when allowlist is non-empty and contains value"""
    cahandler = FakeDBStore()
    cahandler.eab_profiling = False
    cahandler.header_info_field = "hi_field"
    mock_allowlist.return_value = ["hi_value", "other"]
    mock_lookup.return_value = "hi_value"
    cahandler.hi_field = "pre_hi_field"
    with capture_logs("test_a2c", level="INFO") as lcm:
        assert not eab_profile_header_info_check(logger, cahandler, "csr", "hi_field")
    assert (
        "INFO:test_a2c:Received enrollment parameter: hi_field value: hi_value via headerinfo field"
        in lcm.output
    )
    assert "hi_value" == cahandler.hi_field
    assert mock_lookup.called
    assert not mock_eab.called


@patch("acme2certifier.acme_srv.helpers.eab.header_value_allowlist_resolve")
@patch("acme2certifier.acme_srv.helpers.eab.eab_profile_check")
@patch("acme2certifier.acme_srv.helpers.eab.header_info_lookup")
def test_430_eab_profile_header_info_check_risk_gate(
    mock_lookup: MagicMock,
    mock_eab: MagicMock,
    mock_allowlist: MagicMock,
    logger: logging.Logger,
    capture_logs: Callable[..., AbstractContextManager[Any]],
    FakeDBStore: type[Any],
) -> None:
    """header value applied with empty allowlist when risk gate is set"""
    from acme2certifier.acme_srv.helpers.security_gate import SECURITY_DISABLE_ACK_ENV

    cahandler = FakeDBStore()
    cahandler.eab_profiling = False
    cahandler.header_info_field = "hi_field"
    mock_allowlist.return_value = []
    mock_lookup.return_value = "hi_value"
    cahandler.hi_field = "pre_hi_field"
    with patch.dict(os.environ, {SECURITY_DISABLE_ACK_ENV: "1"}, clear=False):
        with capture_logs("test_a2c", level="INFO") as lcm:
            assert not eab_profile_header_info_check(
                logger, cahandler, "csr", "hi_field"
            )
    assert any(
        (
            "Client-selected hi_field=hi_value permitted with empty allowlist" in msg
            for msg in lcm.output
        )
    )
    assert (
        "INFO:test_a2c:Received enrollment parameter: hi_field value: hi_value via headerinfo field"
        in lcm.output
    )
    assert "hi_value" == cahandler.hi_field
    assert mock_lookup.called
    assert not mock_eab.called


@patch("acme2certifier.acme_srv.helpers.eab.header_value_allowlist_resolve")
@patch("acme2certifier.acme_srv.helpers.eab.eab_profile_check")
@patch("acme2certifier.acme_srv.helpers.eab.header_info_lookup")
def test_431_eab_profile_header_info_check_not_in_allowlist(
    mock_lookup: MagicMock,
    mock_eab: MagicMock,
    mock_allowlist: MagicMock,
    logger: logging.Logger,
    capture_logs: Callable[..., AbstractContextManager[Any]],
    FakeDBStore: type[Any],
) -> None:
    """header value ignored when not present in allowlist"""
    cahandler = FakeDBStore()
    cahandler.eab_profiling = False
    cahandler.header_info_field = "hi_field"
    mock_allowlist.return_value = ["allowed"]
    mock_lookup.return_value = "hi_value"
    cahandler.hi_field = "pre_hi_field"
    with capture_logs("test_a2c", level="WARNING") as lcm:
        assert not eab_profile_header_info_check(logger, cahandler, "csr", "hi_field")
    assert any(
        (
            "Ignoring client-selected hi_field=hi_value; value is not in the allowlist"
            in msg
            for msg in lcm.output
        )
    )
    assert "pre_hi_field" == cahandler.hi_field
    assert mock_lookup.called
    assert not mock_eab.called


@patch("acme2certifier.acme_srv.helpers.eab.eab_profile_check")
@patch("acme2certifier.acme_srv.helpers.eab.header_info_lookup")
def test_432_eab_profile_header_info_check(
    mock_lookup: MagicMock,
    mock_eab: MagicMock,
    logger: logging.Logger,
    FakeDBStore: type[Any],
) -> None:
    """test eab_profile_header_info_check()"""
    cahandler = FakeDBStore()
    cahandler.eab_profiling = False
    cahandler.header_info_field = "hi_field"
    mock_lookup.return_value = None
    cahandler.hi_field = "pre_hi_field"
    cahandler.profile_name = "profile_name"
    assert not eab_profile_header_info_check(logger, cahandler, "csr")
    assert "pre_hi_field" == cahandler.hi_field
    assert "profile_name" == cahandler.profile_name
    assert not mock_eab.called


@patch("acme2certifier.acme_srv.helpers.eab.eab_profile_check")
@patch("acme2certifier.acme_srv.helpers.eab.header_info_lookup")
def test_433_eab_profile_header_info_check(
    mock_lookup: MagicMock,
    mock_eab: MagicMock,
    logger: logging.Logger,
    capture_logs: Callable[..., AbstractContextManager[Any]],
    FakeDBStore: type[Any],
) -> None:
    """test eab_profile_header_info_check()"""
    cahandler = FakeDBStore()
    cahandler.eab_profiling = True
    cahandler.eab_handler = None
    cahandler.header_info_field = "hi_field"
    mock_lookup.return_value = "hi_value"
    cahandler.hi_field = "pre_hi_field"
    with capture_logs("test_a2c", level="INFO") as lcm:
        assert (
            "Eab_profiling enabled but no handler defined"
            == eab_profile_header_info_check(logger, cahandler, "csr", "hi_field")
        )
    assert "ERROR:test_a2c:EAB profiling enabled but no handler defined" in lcm.output
    assert "pre_hi_field" == cahandler.hi_field
    assert not mock_eab.called
    assert not mock_lookup.called


@patch("acme2certifier.acme_srv.helpers.eab.eab_profile_check")
@patch("acme2certifier.acme_srv.helpers.eab.header_info_lookup")
def test_434_eab_profile_header_info_check(
    mock_lookup: MagicMock,
    mock_eab: MagicMock,
    logger: logging.Logger,
    FakeDBStore: type[Any],
) -> None:
    """test eab_profile_header_info_check()"""
    cahandler = FakeDBStore()
    cahandler.eab_profiling = True
    cahandler.eab_handler = "eab_handler"
    cahandler.header_info_field = "hi_field"
    mock_lookup.return_value = "hi_value"
    mock_eab.return_value = "mock_eab"
    cahandler.hi_field = "pre_hi_field"
    assert "mock_eab" == eab_profile_header_info_check(
        logger, cahandler, "csr", "hi_field"
    )
    assert "pre_hi_field" == cahandler.hi_field
    assert not mock_lookup.called
    assert mock_eab.called


@patch("acme2certifier.acme_srv.helpers.eab.eab_profile_list_check")
@patch("acme2certifier.acme_srv.helpers.eab.eab_profile_string_check")
def test_435_eab_profile_check(
    mock_string: MagicMock, mock_list: MagicMock, logger: logging.Logger
) -> None:
    """test _eab_profile_check()"""
    cahandler = MagicMock()
    csr = "testCSR"
    handler_hifield = "testField"
    cahandler.eab_handler.return_value.__enter__.return_value.eab_profile_get.return_value = {
        "testField": "stringValue"
    }
    assert eab_profile_check(logger, cahandler, csr, handler_hifield) is None
    assert mock_string.called
    assert not mock_list.called


@patch("acme2certifier.acme_srv.helpers.eab.eab_profile_list_check")
@patch("acme2certifier.acme_srv.helpers.eab.eab_profile_string_check")
def test_436_eab_profile_check(
    mock_string: MagicMock, mock_list: MagicMock, logger: logging.Logger
) -> None:
    cahandler = MagicMock()
    csr = "testCSR"
    handler_hifield = "testField"
    cahandler.eab_handler.return_value.__enter__.return_value.eab_profile_get.return_value = {
        "testField": ["listValue"]
    }
    mock_list.return_value = None
    assert eab_profile_check(logger, cahandler, csr, handler_hifield) is None
    assert not mock_string.called
    assert mock_list.called


@patch("acme2certifier.acme_srv.helpers.eab.header_info_lookup")
@patch("acme2certifier.acme_srv.helpers.eab.eab_profile_list_check")
@patch("acme2certifier.acme_srv.helpers.eab.eab_profile_string_check")
def test_437_eab_profile_check(
    mock_string: MagicMock,
    mock_list: MagicMock,
    mock_hil: MagicMock,
    logger: logging.Logger,
) -> None:
    cahandler = MagicMock()
    csr = "testCSR"
    handler_hifield = "testField"
    cahandler.eab_handler.return_value.__enter__.return_value.eab_profile_get.return_value = {
        "testField": ["listValue"]
    }
    mock_list.return_value = "mock_list"
    assert "mock_list" == eab_profile_check(logger, cahandler, csr, handler_hifield)
    assert not mock_string.called
    assert mock_list.called
    assert not mock_hil.called


@patch("acme2certifier.acme_srv.helpers.eab.header_info_lookup")
@patch("acme2certifier.acme_srv.helpers.eab.eab_profile_list_check")
@patch("acme2certifier.acme_srv.helpers.eab.eab_profile_string_check")
def test_438_eab_profile_check(
    mock_string: MagicMock,
    mock_list: MagicMock,
    mock_hil: MagicMock,
    logger: logging.Logger,
) -> None:
    cahandler = MagicMock()
    csr = "testCSR"
    handler_hifield = "testField"
    cahandler.eab_handler.return_value.__enter__.return_value.eab_profile_get.return_value = {
        "testField1": ["listValue"]
    }
    mock_list.return_value = "mock_list"
    assert (
        'header_info field "testField" is not allowed by profile'
        == eab_profile_check(logger, cahandler, csr, handler_hifield)
    )
    assert not mock_string.called
    assert mock_list.called
    assert mock_hil.called


@patch("acme2certifier.acme_srv.helpers.eab.eab_profile_list_check")
@patch("acme2certifier.acme_srv.helpers.eab.eab_profile_string_check")
def test_439_eab_profile_check(
    mock_string: MagicMock, mock_list: MagicMock, logger: logging.Logger
) -> None:
    cahandler = MagicMock()
    csr = "testCSR"
    handler_hifield = "testField"
    cahandler.eab_handler.return_value.__enter__.return_value.eab_profile_get.return_value = {
        "testField": ["listValue"]
    }
    cahandler.eab_profile_list_check.return_value = "eab_list_check"
    mock_list.return_value = None
    assert "eab_list_check" == eab_profile_check(
        logger, cahandler, csr, handler_hifield
    )
    assert not mock_string.called
    assert not mock_list.called


@patch("acme2certifier.acme_srv.helpers.eab.eab_profile_subject_check")
@patch("acme2certifier.acme_srv.helpers.eab.eab_profile_list_check")
@patch("acme2certifier.acme_srv.helpers.eab.eab_profile_string_check")
def test_440_eab_profile_check(
    mock_string: MagicMock,
    mock_list: MagicMock,
    mock_subject: MagicMock,
    logger: logging.Logger,
) -> None:
    cahandler = MagicMock()
    csr = "testCSR"
    handler_hifield = None
    mock_subject.return_value = "mock_subject"
    cahandler.eab_handler.return_value.__enter__.return_value.eab_profile_get.return_value = {
        "subject": ["listValue"]
    }
    cahandler.eab_profile_list_check.return_value = "eab_list_check"
    mock_list.return_value = None
    assert "mock_subject" == eab_profile_check(logger, cahandler, csr, handler_hifield)
    assert not mock_string.called
    assert not mock_list.called
    assert mock_subject.called


@patch("acme2certifier.acme_srv.helpers.eab.cn_validate")
def test_448_eab_profile_subjet_string_check(
    mock_validate: MagicMock, logger: logging.Logger
) -> None:
    """test eab_profile_subject_string_check()"""
    profile_dic = {"foo": "bar1"}
    assert "Profile subject check failed for foo" == eab_profile_subject_string_check(
        logger, profile_dic, "foo", "bar"
    )
    assert not mock_validate.called


@patch("acme2certifier.acme_srv.helpers.eab.cn_validate")
def test_449_eab_profile_subjet_string_check(
    mock_validate: MagicMock, logger: logging.Logger
) -> None:
    """test eab_profile_subject_string_check()"""
    profile_dic = {"foo": "*"}
    assert not eab_profile_subject_string_check(logger, profile_dic, "foo", "bar")
    assert not mock_validate.called


@patch("acme2certifier.acme_srv.helpers.eab.cn_validate")
def test_450_eab_profile_subjet_string_check(
    mock_validate: MagicMock, logger: logging.Logger
) -> None:
    """test eab_profile_subject_string_check()"""
    profile_dic = {"foo": "bar"}
    assert not eab_profile_subject_string_check(logger, profile_dic, "foo", "bar")
    assert not mock_validate.called


@patch("acme2certifier.acme_srv.helpers.eab.cn_validate")
def test_451_eab_profile_subjet_string_check(
    mock_validate: MagicMock, logger: logging.Logger
) -> None:
    """test eab_profile_subject_string_check()"""
    profile_dic = {"foo": ["bar1", "bar2", "bar3"]}
    assert "Profile subject check failed for foo" == eab_profile_subject_string_check(
        logger, profile_dic, "foo", "bar"
    )
    assert not mock_validate.called


@patch("acme2certifier.acme_srv.helpers.eab.cn_validate")
def test_452_eab_profile_subjet_string_check(
    mock_validate: MagicMock, logger: logging.Logger
) -> None:
    """test eab_profile_subject_string_check()"""
    profile_dic = {"foo": ["bar1", "bar2", "bar3"]}
    assert not eab_profile_subject_string_check(logger, profile_dic, "foo", "bar2")
    assert not mock_validate.called


@patch("acme2certifier.acme_srv.helpers.eab.cn_validate")
def test_453_eab_profile_subjet_string_check(
    mock_validate: MagicMock, logger: logging.Logger
) -> None:
    """test eab_profile_subject_string_check()"""
    profile_dic = {"foo": ["bar1", "bar2", "bar3"]}
    mock_validate.return_value = "error"
    assert "error" == eab_profile_subject_string_check(
        logger, profile_dic, "commonName", "bar"
    )
    assert mock_validate.called


@patch("acme2certifier.acme_srv.helpers.eab.cn_validate")
def test_454_eab_profile_subjet_string_check(
    mock_validate: MagicMock, logger: logging.Logger
) -> None:
    """test eab_profile_subject_string_check()"""
    profile_dic = {"foo": ["bar1", "bar2", "bar3"]}
    mock_validate.return_value = "error"
    assert "Profile subject check failed for bar" == eab_profile_subject_string_check(
        logger, profile_dic, "bar", "bar"
    )
    assert not mock_validate.called


@patch("acme2certifier.acme_srv.helpers.eab.eab_profile_subject_string_check")
@patch("acme2certifier.acme_srv.helpers.eab.csr_subject_get")
def test_455_eab_profile_subject_check(
    mock_cn: MagicMock, mock_strchk: MagicMock, logger: logging.Logger
) -> None:
    """test eab_profile_subject_check()"""
    profile_dic = {"foo": "bar"}
    mock_cn.return_value = {"o": "o", "ou": "ou", "cn": "cn"}
    mock_strchk.side_effect = ["o", "ou", "cn"]
    assert "o" == eab_profile_subject_check(logger, "csr", profile_dic)


@patch("acme2certifier.acme_srv.helpers.eab.eab_profile_subject_string_check")
@patch("acme2certifier.acme_srv.helpers.eab.csr_subject_get")
def test_456_eab_profile_subject_check(
    mock_cn: MagicMock, mock_strchk: MagicMock, logger: logging.Logger
) -> None:
    """test eab_profile_subject_check()"""
    profile_dic = {"foo": "bar"}
    mock_cn.return_value = {"o": "o", "ou": "ou", "cn": "cn"}
    mock_strchk.side_effect = [False, "ou", "cn"]
    assert "ou" == eab_profile_subject_check(logger, "csr", profile_dic)


@patch("acme2certifier.acme_srv.helpers.eab.eab_profile_subject_string_check")
@patch("acme2certifier.acme_srv.helpers.eab.csr_subject_get")
def test_457_eab_profile_subject_check(
    mock_cn: MagicMock, mock_strchk: MagicMock, logger: logging.Logger
) -> None:
    """test eab_profile_subject_check()"""
    profile_dic = {"foo": "bar"}
    mock_cn.return_value = {"o": "o", "ou": "ou", "cn": "cn"}
    mock_strchk.side_effect = [False, False, "cn"]
    assert "cn" == eab_profile_subject_check(logger, "csr", profile_dic)


@patch("acme2certifier.acme_srv.helpers.eab.eab_profile_subject_string_check")
@patch("acme2certifier.acme_srv.helpers.eab.csr_subject_get")
def test_458_eab_profile_subject_check(
    mock_cn: MagicMock, mock_strchk: MagicMock, logger: logging.Logger
) -> None:
    """test eab_profile_subject_check()"""
    profile_dic = {"foo": "bar"}
    mock_cn.return_value = {"o": "o", "ou": "ou", "cn": "cn"}
    mock_strchk.side_effect = [False, False, False]
    assert "Profile subject check failed" == eab_profile_subject_check(
        logger, "csr", profile_dic
    )


@patch(
    "acme2certifier.acme_srv.helpers.encoding.b64_url_recode",
    return_value="encoded_cert",
)
def test_523_eab_profile_revocation_check_str_value(
    mock_b64_url_recode: MagicMock, logger: logging.Logger
) -> None:
    """eab_profile_dic with a string value"""
    cahandler = MagicMock()
    cahandler.eab_handler.return_value.__enter__.return_value = MagicMock()
    certificate_raw = "dummy_cert"
    eab_handler = cahandler.eab_handler.return_value.__enter__.return_value
    eab_handler.eab_profile_get.return_value = {"profile": "value"}
    with patch(
        "acme2certifier.acme_srv.helpers.eab.eab_profile_string_check"
    ) as mock_string_check:
        eab_profile_revocation_check(logger, cahandler, certificate_raw)
        mock_string_check.assert_called_once_with(logger, cahandler, "profile", "value")
        assert not mock_b64_url_recode.called


@patch(
    "acme2certifier.acme_srv.helpers.encoding.b64_url_recode",
    return_value="encoded_cert",
)
def test_524_eab_profile_revocation_check_str_and_ignore_value(
    mock_b64_url_recode: MagicMock, logger: logging.Logger
) -> None:
    """eab_profile_dic with a string value"""
    cahandler = MagicMock()
    cahandler.eab_handler.return_value.__enter__.return_value = MagicMock()
    certificate_raw = "dummy_cert"
    eab_handler = cahandler.eab_handler.return_value.__enter__.return_value
    eab_handler.eab_profile_get.return_value = {"profile": "value", "subject": "value2"}
    with patch(
        "acme2certifier.acme_srv.helpers.eab.eab_profile_string_check"
    ) as mock_string_check:
        eab_profile_revocation_check(logger, cahandler, certificate_raw)
        mock_string_check.assert_called_once_with(logger, cahandler, "profile", "value")
        assert not mock_b64_url_recode.called


@patch(
    "acme2certifier.acme_srv.helpers.encoding.b64_url_recode",
    return_value="encoded_cert",
)
def test_525_eab_profile_revocation_check_list_value(
    mock_b64_url_recode: MagicMock, logger: logging.Logger
) -> None:
    """eab_profile_dic with a list value"""
    cahandler = MagicMock()
    cahandler.eab_handler.return_value.__enter__.return_value = MagicMock()
    certificate_raw = "dummy_cert"
    eab_handler = cahandler.eab_handler.return_value.__enter__.return_value
    eab_handler.eab_profile_get.return_value = {"profile": ["v1", "v2"]}
    cahandler.eab_profile_list_check = MagicMock()
    eab_profile_revocation_check(logger, cahandler, certificate_raw)
    cahandler.eab_profile_list_check.assert_called_once()
    assert not mock_b64_url_recode.called


@patch(
    "acme2certifier.acme_srv.helpers.encoding.b64_url_recode",
    return_value="encoded_cert",
)
def test_526_eab_profile_revocation_check_list_value_fallback(
    mock_b64_url_recode: MagicMock, logger: logging.Logger
) -> None:
    """eab_profile_dic with a list value, fallback to global function"""
    cahandler = MagicMock()
    cahandler.eab_handler.return_value.__enter__.return_value = MagicMock()
    certificate_raw = "dummy_cert"
    eab_handler = cahandler.eab_handler.return_value.__enter__.return_value
    eab_handler.eab_profile_get.return_value = {"profile": ["v1", "v2"]}
    if hasattr(cahandler, "eab_profile_list_check"):
        delattr(cahandler, "eab_profile_list_check")
    with patch(
        "acme2certifier.acme_srv.helpers.eab.eab_profile_list_check"
    ) as mock_list_check:
        eab_profile_revocation_check(logger, cahandler, certificate_raw)
        mock_list_check.assert_called_once()


def test_675_eab_profile_check_skips_cahandler_name(logger: logging.Logger) -> None:
    """eab_profile_check skips routing-only cahandler_name keys"""
    cahandler = MagicMock()
    eab_handler = MagicMock()
    cahandler.eab_handler.return_value.__enter__.return_value = eab_handler
    eab_handler.eab_profile_get.return_value = {"cahandler_name": "openssl"}
    with patch(
        "acme2certifier.acme_srv.helpers.eab.eab_profile_string_check"
    ) as mock_string:
        assert eab_profile_check(logger, cahandler, "csr", "field") is None
    mock_string.assert_not_called()


def test_676_eab_profile_string_check_skips_cahandler_name(
    logger: logging.Logger, FakeDBStore: type[Any]
) -> None:
    """eab_profile_string_check does not apply cahandler_name to the handler"""
    cahandler = FakeDBStore()
    cahandler.cahandler_name = "old"
    eab_profile_string_check(logger, cahandler, "cahandler_name", "openssl")
    assert "old" == cahandler.cahandler_name


def test_695_eab_profile_check_non_str_non_list_value(logger: logging.Logger) -> None:
    """Non-string, non-list profile values are ignored."""
    cahandler = MagicMock()
    cahandler.header_info_field = False
    cahandler.eab_handler.return_value.__enter__.return_value.eab_profile_get.return_value = {
        "boolFlag": True,
        "nested": {"foo": 1},
    }
    assert eab_profile_check(logger, cahandler, "csr", "boolFlag") is None


def test_696_eab_profile_check_cert_chain_skip_list(
    logger: logging.Logger, FakeDBStore: type[Any]
) -> None:
    """cert_chain_skip_list is validated and not setattr'd onto the handler"""
    cahandler = FakeDBStore()
    cahandler.header_info_field = None
    eab_handler = MagicMock()
    cahandler.eab_handler = MagicMock()
    cahandler.eab_handler.return_value.__enter__.return_value = eab_handler
    eab_handler.eab_profile_get.return_value = {"cert_chain_skip_list": ["aabbccdd"]}
    with (
        patch(
            "acme2certifier.acme_srv.helpers.eab.eab_profile_string_check"
        ) as mock_string,
        patch(
            "acme2certifier.acme_srv.helpers.eab.eab_profile_list_check"
        ) as mock_list,
    ):
        assert eab_profile_check(logger, cahandler, "csr", "field") is None
    mock_string.assert_not_called()
    mock_list.assert_not_called()
    assert not hasattr(cahandler, "cert_chain_skip_list")


def test_697_eab_profile_check_cert_chain_skip_list_invalid(
    logger: logging.Logger, FakeDBStore: type[Any]
) -> None:
    """invalid kid skip-list fails eab_profile_check"""
    cahandler = FakeDBStore()
    cahandler.header_info_field = None
    eab_handler = MagicMock()
    cahandler.eab_handler = MagicMock()
    cahandler.eab_handler.return_value.__enter__.return_value = eab_handler
    eab_handler.eab_profile_get.return_value = {"cert_chain_skip_list": "nope"}
    assert (
        "Configuration error: Failed to parse cert_chain_skip_list"
        == eab_profile_check(logger, cahandler, "csr", "field")
    )
    assert not hasattr(cahandler, "cert_chain_skip_list")


def test_698_eab_profile_check_cert_chain_append_missing_file(
    logger: logging.Logger, FakeDBStore: type[Any]
) -> None:
    """missing kid append PEM fails eab_profile_check"""
    cahandler = FakeDBStore()
    cahandler.header_info_field = None
    eab_handler = MagicMock()
    cahandler.eab_handler = MagicMock()
    cahandler.eab_handler.return_value.__enter__.return_value = eab_handler
    eab_handler.eab_profile_get.return_value = {
        "cert_chain_append": ["/no/such/file.pem"]
    }
    result = eab_profile_check(logger, cahandler, "csr", "field")
    assert result.startswith(
        "Configuration error: Failed to read cert_chain_append file"
    )
    assert not hasattr(cahandler, "cert_chain_append")
