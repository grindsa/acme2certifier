# -*- coding: utf-8 -*-
"""Tests for acme_srv.helpers.validation."""

from __future__ import annotations

import logging
from collections.abc import Callable
from contextlib import AbstractContextManager
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from acme2certifier.acme_srv.helpers.validation import (
    cn_validate,
    dkeys_lower,
    fqdn_in_san_check,
    ip_validate,
    ipv6_chk,
    normalize_email_address,
    validate_csr,
    validate_email,
    validate_fqdn,
    validate_identifier,
    validate_ip,
)

pytestmark = pytest.mark.usefixtures("clear_config_cache", "_silence_logging")


def test_006_helper_validate_email(logger: logging.Logger) -> None:
    """validate normal email"""
    assert validate_email(logger, "foo@example.com")


def test_007_helper_validate_email(logger: logging.Logger) -> None:
    """validate normal email"""
    assert validate_email(logger, "mailto:foo@example.com")


def test_008_helper_validate_email(logger: logging.Logger) -> None:
    """validate normal email"""
    assert validate_email(logger, "mailto: foo@example.com")


def test_009_helper_validate_email(logger: logging.Logger) -> None:
    """validate normal email"""
    assert validate_email(
        logger, ["mailto: foo@example.com", "mailto: bar@example.com"]
    )


def test_010_helper_validate_email(logger: logging.Logger) -> None:
    """validate normal email"""
    assert not validate_email(logger, "example.com")


def test_011_helper_validate_email(logger: logging.Logger) -> None:
    """validate normal email"""
    assert not validate_email(logger, "me@exam,ple.com")


def test_012_helper_validate_email(logger: logging.Logger) -> None:
    """validate normal email"""
    assert not validate_email(
        logger, ["mailto: foo@exa,mple.com", "mailto: bar@example.com"]
    )


def test_013_helper_validate_email(logger: logging.Logger) -> None:
    """validate normal email"""
    assert not validate_email(
        logger, ["mailto: foo@example.com", "mailto: bar@exa,mple.com"]
    )


def test_014_helper_normalize_email_address_ascii(logger: logging.Logger) -> None:
    """normalize ASCII email addresses for comparison"""
    assert normalize_email_address(logger, "User@Example.COM") == "user@example.com"
    assert (
        normalize_email_address(logger, '"Display Name" <user@example.com>')
        == "user@example.com"
    )


def test_015_helper_normalize_email_address_punycode(logger: logging.Logger) -> None:
    """normalize U-label and A-label domains to the same form"""
    u_label = "user@münchen.de"
    a_label = "user@xn--mnchen-3ya.de"
    normalized_u = normalize_email_address(logger, u_label)
    normalized_a = normalize_email_address(logger, a_label)
    assert normalized_u == normalized_a
    assert normalized_u == "user@xn--mnchen-3ya.de"


def test_016_helper_normalize_email_address_invalid(logger: logging.Logger) -> None:
    """normalize_email_address returns None for invalid input"""
    assert normalize_email_address(logger, "") is None
    assert normalize_email_address(logger, "not-an-email") is None


def test_077_helper_dkeys_lower() -> None:
    """dkeys_lower with a simple string"""
    tree = "fOo"
    assert "fOo" == dkeys_lower(tree)


def test_078_helper_dkeys_lower() -> None:
    """dkeys_lower with a simple list"""
    tree = ["fOo", "bAr"]
    assert ["fOo", "bAr"] == dkeys_lower(tree)


def test_079_helper_dkeys_lower() -> None:
    """dkeys_lower with a simple dictionary"""
    tree = {"kEy": "vAlUe"}
    assert {"key": "vAlUe"} == dkeys_lower(tree)


def test_080_helper_dkeys_lower() -> None:
    """dkeys_lower with a nested dictionary containg strings, list and dictionaries"""
    tree = {
        "kEy1": "vAlUe2",
        "keys2": ["lIsT2", {"kEyS3": "vAlUe3", "kEyS4": "vAlUe3"}],
        "keys4": {"kEyS4": "vAluE5", "kEyS5": "vAlUE6"},
    }
    assert {
        "key1": "vAlUe2",
        "keys2": ["lIsT2", {"keys3": "vAlUe3", "keys4": "vAlUe3"}],
        "keys4": {"keys5": "vAlUE6", "keys4": "vAluE5"},
    } == dkeys_lower(tree)


def test_150_helper_validate_email(logger: logging.Logger) -> None:
    """validate email containing "-" in domain"""
    assert validate_email(logger, "foo@example-example.com")


def test_151_helper_validate_email(logger: logging.Logger) -> None:
    """validate email containing "-" in user"""
    assert validate_email(logger, "foo-foo@example.com")


def test_158_helper_validate_email(logger: logging.Logger) -> None:
    """validate email containing first letter of domain cannot be a number"""
    assert not validate_email(logger, "foo@1example.com")


def test_159_helper_validate_email(logger: logging.Logger) -> None:
    """validate email containing last letter of domain cannot -"""
    assert not validate_email(logger, "foo@example-.com")


def test_160_helper_validate_email_double_dot(logger: logging.Logger) -> None:
    """validate email rejecting consecutive dots in domain"""
    assert not validate_email(logger, "foo@example..com")


def test_161_helper_validate_email_multi_tld(logger: logging.Logger) -> None:
    """validate email with multi-label TLD"""
    assert validate_email(logger, "foo@example.co.uk")


def test_195_fqdn_in_san_check(logger: logging.Logger) -> None:
    """successful check one entry one match"""
    fqdn = "foo.bar.local"
    san_list = ["DNS:foo.bar.local"]
    assert fqdn_in_san_check(logger, san_list, fqdn)


def test_196_fqdn_in_san_check(logger: logging.Logger) -> None:
    """successful check two entries one match"""
    fqdn = "foo.bar.local"
    san_list = ["DNS:foo1.bar.local", "DNS:foo.bar.local"]
    assert fqdn_in_san_check(logger, san_list, fqdn)


def test_197_fqdn_in_san_check(logger: logging.Logger) -> None:
    """successful check two entries no DNS one match"""
    fqdn = "foo.bar.local"
    san_list = ["IP: 10.0.0.l", "DNS:foo.bar.local"]
    assert fqdn_in_san_check(logger, san_list, fqdn)


def test_198_fqdn_in_san_check(logger: logging.Logger) -> None:
    """successful check no fqdn"""
    fqdn = None
    san_list = ["IP: 10.0.0.l", "DNS:foo.bar.local"]
    assert not fqdn_in_san_check(logger, san_list, fqdn)


def test_199_fqdn_in_san_check(logger: logging.Logger) -> None:
    """successful check no fqdn"""
    fqdn = ""
    san_list = ["IP: 10.0.0.l", "DNS:foo.bar.local"]
    assert not fqdn_in_san_check(logger, san_list, fqdn)


def test_200_fqdn_in_san_check(logger: logging.Logger) -> None:
    """successful check blank fqdn"""
    fqdn = " "
    san_list = ["IP: 10.0.0.l", "DNS:foo.bar.local"]
    assert not fqdn_in_san_check(logger, san_list, fqdn)


def test_201_fqdn_in_san_check(logger: logging.Logger) -> None:
    """successful check empty san_list"""
    fqdn = "foo.bar.local"
    san_list = []
    assert not fqdn_in_san_check(logger, san_list, fqdn)


def test_202_fqdn_in_san_check(logger: logging.Logger) -> None:
    """successful check two entries one match"""
    fqdn = "foo.bar.local"
    san_list = ["foo1.bar.local", "DNS:foo.bar.local"]
    assert fqdn_in_san_check(logger, san_list, fqdn)


def test_203_fqdn_in_san_check(
    logger: logging.Logger, capture_logs: Callable[..., AbstractContextManager[Any]]
) -> None:
    """successful check two entries one match"""
    fqdn = "foo.bar.local"
    san_list = ["foo1.bar.local"]
    with capture_logs("test_a2c", level="INFO") as lcm:
        assert not fqdn_in_san_check(logger, san_list, fqdn)
    assert (
        "ERROR:test_a2c:Error during SAN check. SAN split failed: foo1.bar.local"
        in lcm.output
    )


def test_254_validate_csr(logger: logging.Logger) -> None:
    """patched_create_connection"""
    assert validate_csr(logger, "oder_dic", "csr")


def test_353_ipv6_chk(logger: logging.Logger) -> None:
    """test ipv6_chk()"""
    addr_obj = "fe80::215:5dff:fec0:102"
    assert ipv6_chk(logger, addr_obj)


def test_354_ipv6_chk(logger: logging.Logger) -> None:
    """test ipv6_chk()"""
    addr_obj = "foo.bar.local"
    assert not ipv6_chk(logger, addr_obj)


def test_355_ipv6_chk(logger: logging.Logger) -> None:
    """test ipv6_chk()"""
    addr_obj = "192.168.123.10"
    assert not ipv6_chk(logger, addr_obj)


def test_356_ipv6_chk(logger: logging.Logger) -> None:
    """test ipv6_chk()"""
    addr_obj = None
    assert not ipv6_chk(logger, addr_obj)


def test_363_ip_validate(logger: logging.Logger) -> None:
    """test ip validate"""
    assert ("1.0.0.10.in-addr.arpa", False) == ip_validate(logger, "10.0.0.1")


def test_364_ip_validate(logger: logging.Logger) -> None:
    """test ip validate"""
    assert (None, True) == ip_validate(logger, "1000.0.0.1")


def test_369_validate_fqdn(logger: logging.Logger) -> None:
    """test validate_fqdn()"""
    assert validate_fqdn(logger, "foo.bar.com")


def test_370_validate_fqdn(logger: logging.Logger) -> None:
    """test validate_fqdn()"""
    assert not validate_fqdn(logger, "-foo.bar.com")


def test_371_validate_fqdn(logger: logging.Logger) -> None:
    """test validate_fqdn()"""
    assert not validate_fqdn(logger, "foo.bar.com/foo")


def test_372_validate_fqdn(logger: logging.Logger) -> None:
    """test validate_fqdn()"""
    assert not validate_fqdn(logger, "foo.bar.com#foo")


def test_373_validate_fqdn(logger: logging.Logger) -> None:
    """test validate_fqdn()"""
    assert not validate_fqdn(logger, "foo.bar.com?foo=foo")


def test_374_validate_fqdn(logger: logging.Logger) -> None:
    """test validate_fqdn()"""
    assert not validate_fqdn(logger, "2a01:c22:b0cf:600:74be:80a7:4feb:bfe8")


def test_375_validate_fqdn(logger: logging.Logger) -> None:
    """test validate_fqdn()"""
    assert not validate_fqdn(logger, "foo.bar.com:8080")


def test_376_validate_fqdn(logger: logging.Logger) -> None:
    """test validate_fqdn()"""
    assert not validate_fqdn(logger, "foo@bar.local")


def test_377_validate_fqdn(logger: logging.Logger) -> None:
    """test validate_fqdn()"""
    assert validate_fqdn(logger, "*.bar.local")


def test_378_validate_ip(logger: logging.Logger) -> None:
    """test validate_ip()"""
    assert validate_ip(logger, "10.0.0.1")


def test_379_validate_ip(logger: logging.Logger) -> None:
    """test validate_ip()"""
    assert validate_ip(logger, "2a01:c22:b0cf:600:74be:80a7:4feb:bfe8")


def test_380_validate_ip(logger: logging.Logger) -> None:
    """test validate_ip()"""
    assert not validate_ip(logger, "foo.bar.local")


def test_381_validate_ip(logger: logging.Logger) -> None:
    """test validate_ip()"""
    assert not validate_ip(logger, "foo@bar.local")


def test_382_validate_ip(logger: logging.Logger) -> None:
    """test validate_ip()"""
    assert not validate_ip(logger, "301.0.0.1")


@patch("acme2certifier.acme_srv.helpers.validation.validate_email")
@patch("acme2certifier.acme_srv.helpers.validation.validate_fqdn")
@patch("acme2certifier.acme_srv.helpers.validation.validate_ip")
def test_383_validate_identifier(
    mock_ip: MagicMock,
    mock_fqdn: MagicMock,
    mock_email: MagicMock,
    logger: logging.Logger,
) -> None:
    """test validate_identifier"""
    mock_fqdn.return_value = "dns"
    mock_ip.return_value = "ip"
    assert "dns" == validate_identifier(logger, "dns", "foo.bar.com")
    assert mock_fqdn.called
    assert not mock_ip.called
    assert not mock_email.called


@patch("acme2certifier.acme_srv.helpers.validation.validate_email")
@patch("acme2certifier.acme_srv.helpers.validation.validate_fqdn")
@patch("acme2certifier.acme_srv.helpers.validation.validate_ip")
def test_384_validate_identifier(
    mock_ip: MagicMock,
    mock_fqdn: MagicMock,
    mock_email: MagicMock,
    logger: logging.Logger,
) -> None:
    """test validate_identifier"""
    mock_fqdn.return_value = "dns"
    mock_ip.return_value = "ip"
    assert "ip" == validate_identifier(logger, "ip", "ip")
    assert not mock_fqdn.called
    assert mock_ip.called
    assert not mock_email.called


@patch("acme2certifier.acme_srv.helpers.validation.validate_email")
@patch("acme2certifier.acme_srv.helpers.validation.validate_fqdn")
@patch("acme2certifier.acme_srv.helpers.validation.validate_ip")
def test_385_validate_identifier(
    mock_ip: MagicMock,
    mock_fqdn: MagicMock,
    mock_email: MagicMock,
    logger: logging.Logger,
) -> None:
    """test validate_identifier"""
    mock_fqdn.return_value = "dns"
    mock_ip.return_value = "ip"
    assert not validate_identifier(logger, "unk", "ip")
    assert not mock_fqdn.called
    assert not mock_ip.called
    assert not mock_email.called


@patch("acme2certifier.acme_srv.helpers.validation.validate_email")
@patch("acme2certifier.acme_srv.helpers.validation.validate_fqdn")
@patch("acme2certifier.acme_srv.helpers.validation.validate_ip")
def test_386_validate_identifier(
    mock_ip: MagicMock,
    mock_fqdn: MagicMock,
    mock_email: MagicMock,
    logger: logging.Logger,
) -> None:
    """test validate_identifier"""
    mock_fqdn.return_value = "dns"
    mock_ip.return_value = "ip"
    assert not validate_identifier(logger, "tnauthlist", "ip")
    assert not mock_fqdn.called
    assert not mock_ip.called
    assert not mock_email.called


@patch("acme2certifier.acme_srv.helpers.validation.validate_email")
@patch("acme2certifier.acme_srv.helpers.validation.validate_fqdn")
@patch("acme2certifier.acme_srv.helpers.validation.validate_ip")
def test_387_validate_identifier(
    mock_ip: MagicMock,
    mock_fqdn: MagicMock,
    mock_email: MagicMock,
    logger: logging.Logger,
) -> None:
    """test validate_identifier"""
    mock_fqdn.return_value = "dns"
    mock_ip.return_value = "ip"
    assert validate_identifier(logger, "tnauthlist", "ip", True)
    assert not mock_fqdn.called
    assert not mock_ip.called
    assert not mock_email.called


@patch("acme2certifier.acme_srv.helpers.validation.validate_email")
@patch("acme2certifier.acme_srv.helpers.validation.validate_fqdn")
@patch("acme2certifier.acme_srv.helpers.validation.validate_ip")
def test_388_validate_identifier(
    mock_ip: MagicMock,
    mock_fqdn: MagicMock,
    mock_email: MagicMock,
    logger: logging.Logger,
) -> None:
    """test validate_identifier"""
    mock_fqdn.return_value = "dns"
    mock_ip.return_value = "ip"
    assert validate_identifier(logger, "email", "email", True)
    assert not mock_fqdn.called
    assert not mock_ip.called
    assert mock_email.called


@patch("acme2certifier.acme_srv.helpers.validation.validate_fqdn")
@patch("acme2certifier.acme_srv.helpers.validation.validate_ip")
def test_441_cn_validate(
    mock_ip: MagicMock, mock_fqdn: MagicMock, logger: logging.Logger
) -> None:
    """test cn_validate()"""
    mock_ip.return_value = True
    mock_fqdn.return_value = True
    assert not cn_validate(logger, "foo.bar.com")
    assert not mock_fqdn.called


@patch("acme2certifier.acme_srv.helpers.validation.validate_fqdn")
@patch("acme2certifier.acme_srv.helpers.validation.validate_ip")
def test_442_cn_validate(
    mock_ip: MagicMock, mock_fqdn: MagicMock, logger: logging.Logger
) -> None:
    """test cn_validate()"""
    mock_ip.return_value = False
    mock_fqdn.return_value = True
    assert not cn_validate(logger, "foo.bar.com")
    assert mock_fqdn.called


@patch("acme2certifier.acme_srv.helpers.validation.validate_fqdn")
@patch("acme2certifier.acme_srv.helpers.validation.validate_ip")
def test_443_cn_validate(
    mock_ip: MagicMock, mock_fqdn: MagicMock, logger: logging.Logger
) -> None:
    """test cn_validate()"""
    mock_ip.return_value = False
    mock_fqdn.return_value = False
    assert "Profile subject check failed: CN validation failed" == cn_validate(
        logger, "foo.bar.com"
    )
    assert mock_fqdn.called


@patch("acme2certifier.acme_srv.helpers.validation.validate_fqdn")
@patch("acme2certifier.acme_srv.helpers.validation.validate_ip")
def test_444_cn_validate(
    mock_ip: MagicMock, mock_fqdn: MagicMock, logger: logging.Logger
) -> None:
    """test cn_validate()"""
    mock_ip.return_value = False
    mock_fqdn.return_value = False
    assert "Profile subject check failed: commonName missing" == cn_validate(
        logger, None
    )
    assert not mock_fqdn.called


def test_673_normalize_email_address_empty_local_or_domain(
    logger: logging.Logger,
) -> None:
    """normalize_email_address returns None when local or domain is empty"""
    assert normalize_email_address(logger, "@example.com") is None
    assert normalize_email_address(logger, "user@") is None


def test_674_normalize_email_address_idna_error(logger: logging.Logger) -> None:
    """normalize_email_address returns None when IDNA encoding fails"""
    import idna

    with patch(
        "acme2certifier.acme_srv.helpers.validation.idna.encode",
        side_effect=idna.IDNAError("bad domain"),
    ):
        assert normalize_email_address(logger, "user@example.com") is None
