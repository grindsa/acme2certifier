# -*- coding: utf-8 -*-
"""Tests for acme_srv.helpers.domain_utils."""

from __future__ import annotations

import logging
from collections.abc import Callable
from contextlib import AbstractContextManager
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from acme2certifier.acme_srv.helpers.domain_utils import (
    allowed_domainlist_check,
    is_domain_whitelisted,
    is_ip_whitelisted,
)

pytestmark = pytest.mark.usefixtures("clear_config_cache", "_silence_logging")


def test_487_domainlist_check(logger: logging.Logger) -> None:
    """domainlist_check failed check as empty entry"""
    list_ = ["bar.foo", "foo.bar"]
    entry = None
    assert not is_domain_whitelisted(logger, entry, list_)


def test_488_is_domain_whitelisted(logger: logging.Logger) -> None:
    """is_domain_whitelisted failed check as empty entry"""
    list_ = ["bar.foo$", "foo.bar$"]
    entry = None
    assert not is_domain_whitelisted(logger, entry, list_)


def test_489_is_domain_whitelisted(logger: logging.Logger) -> None:
    """is_domain_whitelisted check against empty list"""
    list_ = []
    entry = "host.bar.foo"
    assert not is_domain_whitelisted(logger, entry, list_)


def test_490_is_domain_whitelisted(logger: logging.Logger) -> None:
    """is_domain_whitelisted successful check against 1st element of a list"""
    list_ = ["*.bar.foo", "*.foo.bar"]
    entry = "host.bar.foo"
    assert is_domain_whitelisted(logger, entry, list_)


def test_491_is_domain_whitelisted(logger: logging.Logger) -> None:
    """is_domain_whitelisted unsuccessful as endcheck failed"""
    list_ = ["bar.foo", "foo.bar"]
    entry = "host.bar.foo.bar1"
    assert not is_domain_whitelisted(logger, entry, list_)


def test_492_is_domain_whitelisted(logger: logging.Logger) -> None:
    """is_domain_whitelisted wildcard check"""
    list_ = ["*.bar.foo", "foo.bar"]
    entry = "*.bar.foo"
    assert is_domain_whitelisted(logger, entry, list_)


def test_493_is_domain_whitelisted(logger: logging.Logger) -> None:
    """is_domain_whitelisted failed wildcard check"""
    list_ = ["bar.foo$", "foo.bar$"]
    entry = "*.bar.foo_"
    assert not is_domain_whitelisted(logger, entry, list_)


def test_494_is_domain_whitelisted(logger: logging.Logger) -> None:
    """is_domain_whitelisted not end check"""
    list_ = ["bar.foo$", "foo.bar$"]
    entry = "bar.foo gna"
    assert not is_domain_whitelisted(logger, entry, list_)


def test_495_is_domain_whitelisted(logger: logging.Logger) -> None:
    """is_domain_whitelisted $ at the end"""
    list_ = ["bar.foo$", "foo.bar$"]
    entry = "bar.foo$"
    assert not is_domain_whitelisted(logger, entry, list_)


def test_496_is_domain_whitelisted(logger: logging.Logger) -> None:
    """is_domain_whitelisted unsuccessful whildcard check"""
    list_ = ["foo.bar$", "\\*.bar.foo"]
    entry = "host.bar.foo"
    assert not is_domain_whitelisted(logger, entry, list_)


def test_497_is_domain_whitelisted(logger: logging.Logger) -> None:
    """is_domain_whitelisted successful whildcard check"""
    list_ = ["foo.bar$", "*.bar.foo"]
    entry = "*.bar.foo"
    assert is_domain_whitelisted(logger, entry, list_)


def test_498_is_domain_whitelisted(logger: logging.Logger) -> None:
    """is_domain_whitelisted successful whildcard in list but not in string"""
    list_ = ["foo.bar$", "*.bar.foo"]
    entry = "foo.bar.foo"
    assert is_domain_whitelisted(logger, entry, list_)


def test_499_is_domain_whitelisted(
    logger: logging.Logger, capture_logs: Callable[..., AbstractContextManager[Any]]
) -> None:
    """ip address check NOne in whitelist"""
    list_ = [None, "*.bar.foo"]
    entry = "foo.bar.foo"
    with capture_logs("test_a2c", level="INFO") as lcm:
        assert is_domain_whitelisted(logger, entry, list_)
    assert (
        "ERROR:test_a2c:Invalid pattern configured in allowed_domainlist: empty string"
        in lcm.output
    )


@patch("idna.encode")
def test_500_is_domain_whitelisted(
    mock_idna: MagicMock,
    logger: logging.Logger,
    capture_logs: Callable[..., AbstractContextManager[Any]],
) -> None:
    """exception"""
    list_ = ["example.com", "*.bar.foo"]
    entry = "foo.bar.foo"
    mock_idna.side_effect = Exception("idna error")
    with capture_logs("test_a2c", level="INFO") as lcm:
        assert not is_domain_whitelisted(logger, entry, list_)
    assert "ERROR:test_a2c:Invalid domain format in csr: idna error" in lcm.output


def test_501_is_domain_whitelisted(logger: logging.Logger) -> None:
    """whitelist"""
    list_ = ["example.com", "bar.foo"]
    entry = "*.bar.foo"
    assert not is_domain_whitelisted(logger, entry, list_)


def test_502_is_domain_whitelisted(logger: logging.Logger) -> None:
    """exact domain name"""
    list_ = ["example.com", "bar.foo"]
    entry = "bar.foo"
    assert is_domain_whitelisted(logger, entry, list_)


def test_503_is_domain_whitelisted(logger: logging.Logger) -> None:
    """wildcard domain name"""
    list_ = ["*.example.com", "*.bar.foo"]
    entry = "*.example.com"
    assert is_domain_whitelisted(logger, entry, list_)


@patch("idna.encode")
def test_504_is_domain_whitelisted(
    mock_idna: MagicMock,
    logger: logging.Logger,
    capture_logs: Callable[..., AbstractContextManager[Any]],
) -> None:
    """exception"""
    list_ = ["example.com", "*.bar.foo"]
    entry = "foo.bar.foo"
    mock_idna.side_effect = [Exception("idna error"), "bar"]
    with capture_logs("test_a2c", level="INFO") as lcm:
        assert not is_domain_whitelisted(logger, entry, list_)
    assert (
        "ERROR:test_a2c:Invalid pattern configured in allowed_domainlist: *.bar.foo"
        in lcm.output
    )


@patch("acme2certifier.acme_srv.helpers.domain_utils.csr_cn_get")
@patch("acme2certifier.acme_srv.helpers.domain_utils.csr_san_get")
def test_505_allowed_domainlist_check(
    mock_san: MagicMock, mock_cn: MagicMock, logger: logging.Logger
) -> None:
    """CAhandler._check_csr with empty allowed_domainlist"""
    allowed_domainlist = []
    mock_san.return_value = ["DNS:host.foo.bar"]
    mock_cn.return_value = "host2.foo.bar"
    csr = "csr"
    assert not allowed_domainlist_check(logger, csr, allowed_domainlist)


@patch("acme2certifier.acme_srv.helpers.domain_utils.csr_cn_get")
@patch("acme2certifier.acme_srv.helpers.domain_utils.csr_san_get")
def test_506_allowed_domainlist_check(
    mock_san: MagicMock, mock_cn: MagicMock, logger: logging.Logger
) -> None:
    """CAhandler._check_csr with empty allowed_domainlist"""
    allowed_domainlist = ["*.foo.bar"]
    mock_san.return_value = ["DNS:host.foo.bar"]
    mock_cn.return_value = "host2.foo.bar"
    csr = "csr"
    assert not allowed_domainlist_check(logger, csr, allowed_domainlist)


@patch("acme2certifier.acme_srv.helpers.domain_utils.csr_cn_get")
@patch("acme2certifier.acme_srv.helpers.domain_utils.csr_san_get")
def test_507_allowed_domainlist_check(
    mock_san: MagicMock, mock_cn: MagicMock, logger: logging.Logger
) -> None:
    """CAhandler._check_csr with allowd allowed_domainlist"""
    allowed_domainlist = ["*.bar.bar"]
    mock_san.return_value = ["DNS:host.foo.bar"]
    mock_cn.return_value = "host2.foo.bar"
    csr = "csr"
    assert (
        "Either CN or SANs are not allowed by configuration"
        == allowed_domainlist_check(logger, csr, allowed_domainlist)
    )


@patch("acme2certifier.acme_srv.helpers.domain_utils.csr_cn_get")
@patch("acme2certifier.acme_srv.helpers.domain_utils.csr_san_get")
def test_508_allowed_domainlist_check(
    mock_san: MagicMock, mock_cn: MagicMock, logger: logging.Logger
) -> None:
    """CAhandler._check_csr with allowed allowed_domainlist"""
    allowed_domainlist = ["*.foo.bar"]
    mock_san.return_value = ["invalidhostname"]
    mock_cn.return_value = "host2.foo.bar"
    csr = "csr"
    assert "SAN list parsing failed ['invalidhostname']" == allowed_domainlist_check(
        logger, csr, allowed_domainlist
    )


@patch("acme2certifier.acme_srv.helpers.domain_utils.csr_cn_get")
@patch("acme2certifier.acme_srv.helpers.domain_utils.csr_san_get")
def test_509_allowed_domainlist_check(
    mock_san: MagicMock, mock_cn: MagicMock, logger: logging.Logger
) -> None:
    """CAhandler._check_csr with empty allowed_domainlist"""
    allowed_domainlist = ["*.foo.bar"]
    mock_san.return_value = ["email:user@bar.foo.bar"]
    mock_cn.return_value = "host2.foo.bar"
    csr = "csr"
    assert not allowed_domainlist_check(logger, csr, allowed_domainlist)


def test_598_is_ip_whitelisted_empty(logger: logging.Logger) -> None:
    """Test is_ip_whitelisted with empty IP list."""
    assert not is_ip_whitelisted(logger, "1.2.3.4", [])


def test_599_is_ip_whitelisted_noip(logger: logging.Logger) -> None:
    """Test is_ip_whitelisted with no IP provided."""
    assert not is_ip_whitelisted(
        logger, "", ["10.0.0.1/8", "172.16.0.1/32", "192.168.123.1"]
    )


def test_600_is_ip_whitelisted_invalid(logger: logging.Logger) -> None:
    """Test is_ip_whitelisted with invalid IP list."""
    assert not is_ip_whitelisted(
        logger, "10.0.aa.0", ["10.0.0.1/8", "172.16.0.1/32", "192.168.123.1"]
    )


def test_601_is_ip_whitelisted_invalid(logger: logging.Logger) -> None:
    """Test is_ip_whitelisted with invalid IP list."""
    assert not is_ip_whitelisted(
        logger, "10.0.0.300", ["10.0.0.1/8", "172.16.0.1/32", "192.168.123.1"]
    )


def test_602_is_ip_whitelisted_no_match(logger: logging.Logger) -> None:
    """Test is_ip_whitelisted with no matching IP."""
    assert not is_ip_whitelisted(
        logger, "10.1.0.1", ["10.0.0.1/16", "172.16.0.1/32", "192.168.123.1"]
    )


def test_603_is_ip_whitelisted_exact_match(logger: logging.Logger) -> None:
    """Test is_ip_whitelisted with exact matching IP."""
    assert is_ip_whitelisted(
        logger, "192.168.123.1", ["10.0.0.1/8", "172.16.0.1/32", "192.168.123.1"]
    )


def test_604_is_ip_whitelisted_cidr_match(logger: logging.Logger) -> None:
    """Test is_ip_whitelisted with CIDR matching IP."""
    assert is_ip_whitelisted(
        logger, "10.0.20.1", ["10.0.0.1/8", "172.16.0.1/32", "192.168.123.1"]
    )


def test_605_is_ip_whitelisted_cidr_32match(logger: logging.Logger) -> None:
    """Test is_ip_whitelisted with CIDR /32 matching IP."""
    assert is_ip_whitelisted(
        logger, "172.16.0.1", ["10.0.0.1/8", "172.16.0.1/32", "192.168.123.1"]
    )


def test_606_is_ip_whitelisted_invalid_network(
    logger: logging.Logger, capture_logs: Callable[..., AbstractContextManager[Any]]
) -> None:
    """Test is_ip_whitelisted with invalid network."""
    with capture_logs(logger, level="ERROR") as lcm:
        assert is_ip_whitelisted(
            logger, "172.16.0.1", ["10.300.0.0/8", "172.16.0.1/32", "192.168.123.1"]
        )
    assert (
        "ERROR:test_a2c:Invalid network entry in allowed_iplist: 10.300.0.0/8"
        in lcm.output[0]
    )


def test_610_is_email_whitelisted_exact_match(logger: logging.Logger) -> None:
    """Test is_email_whitelisted with exact match"""
    from acme2certifier.acme_srv.helpers.domain_utils import is_email_whitelisted

    email_list = ["user@example.com", "admin@domain.com"]
    assert is_email_whitelisted(logger, "user@example.com", email_list)
    assert is_email_whitelisted(logger, "admin@domain.com", email_list)


def test_611_is_email_whitelisted_case_insensitive(logger: logging.Logger) -> None:
    """Test is_email_whitelisted is case-insensitive"""
    from acme2certifier.acme_srv.helpers.domain_utils import is_email_whitelisted

    email_list = ["User@Example.com", "Admin@Domain.com"]
    assert is_email_whitelisted(logger, "user@example.com", email_list)
    assert is_email_whitelisted(logger, "ADMIN@DOMAIN.COM", email_list)


def test_612_is_email_whitelisted_not_in_list() -> None:
    """Test is_email_whitelisted returns False for non-matching email"""
    from acme2certifier.acme_srv.helpers.domain_utils import is_email_whitelisted

    email_list = ["user@example.com", "admin@domain.com"]


def test_613_is_email_whitelisted_with_whitespace(logger: logging.Logger) -> None:
    """Test is_email_whitelisted trims whitespace"""
    from acme2certifier.acme_srv.helpers.domain_utils import is_email_whitelisted

    email_list = [" user@example.com ", "admin@domain.com "]
    assert is_email_whitelisted(logger, "user@example.com", email_list)
    assert is_email_whitelisted(logger, "admin@domain.com", email_list)


def test_614_email_whitelisted_empty_list(logger: logging.Logger) -> None:
    """Test is_email_whitelisted with empty list returns False"""
    from acme2certifier.acme_srv.helpers.domain_utils import is_email_whitelisted

    email_list = []
    assert not is_email_whitelisted(logger, "user@example.com", email_list)


def test_615_is_email_whitelisted_exact_match(logger: logging.Logger) -> None:
    """Test is_email_whitelisted returns True for exact match."""
    from acme2certifier.acme_srv.helpers.domain_utils import is_email_whitelisted

    email_list = ["user@example.com", "admin@foo.com"]
    assert is_email_whitelisted(logger, "user@example.com", email_list)
    assert is_email_whitelisted(logger, "admin@foo.com", email_list)
    assert not is_email_whitelisted(logger, "other@example.com", email_list)


def test_616_is_email_whitelisted_wildcard(logger: logging.Logger) -> None:
    """Test is_email_whitelisted returns True for wildcard *@example.com."""
    from acme2certifier.acme_srv.helpers.domain_utils import is_email_whitelisted

    email_list = ["*@example.com"]
    assert is_email_whitelisted(logger, "user@example.com", email_list)
    assert is_email_whitelisted(logger, "admin@example.com", email_list)
    assert not is_email_whitelisted(logger, "user@other.com", email_list)


def test_617_is_email_whitelisted_mixed_patterns(logger: logging.Logger) -> None:
    """Test is_email_whitelisted with mixed exact and wildcard patterns."""
    from acme2certifier.acme_srv.helpers.domain_utils import is_email_whitelisted

    email_list = ["*@example.com", "special@foo.com"]
    assert is_email_whitelisted(logger, "user@example.com", email_list)
    assert is_email_whitelisted(logger, "special@foo.com", email_list)
    assert not is_email_whitelisted(logger, "nobody@bar.com", email_list)


def test_618_is_email_whitelisted_strip_and_case(logger: logging.Logger) -> None:
    """Test is_email_whitelisted is case and whitespace insensitive."""
    from acme2certifier.acme_srv.helpers.domain_utils import is_email_whitelisted

    email_list = ["  User@Example.com  ", "*@foo.com"]
    assert is_email_whitelisted(logger, " user@example.com ", email_list)
    assert is_email_whitelisted(logger, "ADMIN@FOO.COM", email_list)
