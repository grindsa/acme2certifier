# -*- coding: utf-8 -*-
"""Unit tests for allow_shortname_from_fqdn helpers (Phase 1)."""

import logging
from unittest.mock import patch

import pytest

from acme2certifier.acme_srv.helpers.config import (
    config_shortname_denylist_load,
    warn_shortname_without_domainlist,
)
from acme2certifier.acme_srv.helpers.domain_utils import (
    allowed_domainlist_check,
    is_shortname_denied,
    is_single_label_name,
    shortname_covered_by_siblings,
)


@pytest.fixture
def logger():
    return logging.getLogger("test_a2c")


def test_is_single_label_name_true(logger):
    assert is_single_label_name(logger, "host")
    assert is_single_label_name(logger, "HOST")
    assert is_single_label_name(logger, "  host  ")


def test_is_single_label_name_false(logger):
    assert not is_single_label_name(logger, "")
    assert not is_single_label_name(logger, None)
    assert not is_single_label_name(logger, "host.example.com")
    assert not is_single_label_name(logger, "*.example.com")
    assert not is_single_label_name(logger, "*")
    assert not is_single_label_name(logger, "host*")


def test_is_shortname_denied(logger):
    assert not is_shortname_denied(logger, "mail", [])
    assert not is_shortname_denied(logger, "mail", None)
    assert not is_shortname_denied(logger, "web", ["mail", "vpn"])
    assert is_shortname_denied(logger, "mail", ["mail", "vpn"])
    assert is_shortname_denied(logger, "MAIL", ["mail"])
    assert is_shortname_denied(logger, "  Vpn  ", ["vpn"])


def test_shortname_covered_matching_sibling(logger):
    siblings = ["host.intra.net", "host"]
    allowlist = ["*.intra.net"]
    assert shortname_covered_by_siblings(logger, "host", siblings, allowlist)


def test_shortname_covered_case_insensitive(logger):
    siblings = ["Host.Intra.Net"]
    allowlist = ["*.intra.net"]
    assert shortname_covered_by_siblings(logger, "HOST", siblings, allowlist)


def test_shortname_covered_missing_sibling(logger):
    siblings = ["host"]
    allowlist = ["*.intra.net"]
    assert not shortname_covered_by_siblings(logger, "host", siblings, allowlist)


def test_shortname_covered_wrong_first_label(logger):
    siblings = ["other.intra.net", "host"]
    allowlist = ["*.intra.net"]
    assert not shortname_covered_by_siblings(logger, "host", siblings, allowlist)


def test_shortname_covered_wildcard_sibling_rejected(logger):
    siblings = ["*.intra.net", "host"]
    allowlist = ["*.intra.net"]
    assert not shortname_covered_by_siblings(logger, "host", siblings, allowlist)


def test_shortname_covered_sibling_not_on_allowlist(logger):
    siblings = ["host.other.net", "host"]
    allowlist = ["*.intra.net"]
    assert not shortname_covered_by_siblings(logger, "host", siblings, allowlist)


def test_shortname_covered_rejects_non_single_label(logger):
    siblings = ["host.intra.net"]
    allowlist = ["*.intra.net"]
    assert not shortname_covered_by_siblings(
        logger, "host.intra.net", siblings, allowlist
    )


def test_shortname_covered_ignores_ip_sibling(logger):
    siblings = ["10.0.0.1", "host"]
    allowlist = ["10.0.0.1", "*.intra.net"]
    assert not shortname_covered_by_siblings(logger, "10", siblings, allowlist)


def test_config_shortname_denylist_load_valid(logger):
    config_dic = {"Order": {"shortname_denylist": '["mail", "vpn"]'}}
    assert config_shortname_denylist_load(logger, config_dic) == ["mail", "vpn"]


def test_config_shortname_denylist_load_empty(logger):
    assert config_shortname_denylist_load(logger, {}) == []
    assert config_shortname_denylist_load(logger, {"Order": {}}) == []


def test_config_shortname_denylist_load_parse_error(logger, caplog):
    config_dic = {"Order": {"shortname_denylist": "not-json"}}
    with caplog.at_level(logging.INFO, logger="test_a2c"):
        assert config_shortname_denylist_load(logger, config_dic) == "failed to parse"
    assert any("Failed to load shortname_denylist" in r.message for r in caplog.records)


def test_warn_shortname_without_domainlist_warns(logger, caplog):
    with caplog.at_level(logging.WARNING, logger="test_a2c"):
        warn_shortname_without_domainlist(logger, True, [])
    assert any(
        "allow_shortname_from_fqdn is enabled but allowed_domainlist is empty"
        in r.message
        for r in caplog.records
    )


def test_warn_shortname_without_domainlist_silent_when_consistent(logger, caplog):
    with caplog.at_level(logging.WARNING, logger="test_a2c"):
        warn_shortname_without_domainlist(logger, True, ["*.intra.net"])
        warn_shortname_without_domainlist(logger, False, [])
    assert not any("allow_shortname_from_fqdn is enabled" in r.message for r in caplog.records)


@patch("acme2certifier.acme_srv.helpers.domain_utils.csr_cn_get")
@patch("acme2certifier.acme_srv.helpers.domain_utils.csr_san_get")
def test_allowed_domainlist_check_flag_off_rejects_shortname(
    mock_san, mock_cn, logger
):
    mock_san.return_value = ["DNS:host.intra.net", "DNS:host"]
    mock_cn.return_value = None
    error = allowed_domainlist_check(
        logger, "csr", ["*.intra.net"], allow_shortname_from_fqdn=False
    )
    assert error == "Either CN or SANs are not allowed by configuration"


@patch("acme2certifier.acme_srv.helpers.domain_utils.csr_cn_get")
@patch("acme2certifier.acme_srv.helpers.domain_utils.csr_san_get")
def test_allowed_domainlist_check_flag_on_accepts_shortname(mock_san, mock_cn, logger):
    mock_san.return_value = ["DNS:host.intra.net", "DNS:host"]
    mock_cn.return_value = None
    error = allowed_domainlist_check(
        logger, "csr", ["*.intra.net"], allow_shortname_from_fqdn=True
    )
    assert not error


@patch("acme2certifier.acme_srv.helpers.domain_utils.csr_cn_get")
@patch("acme2certifier.acme_srv.helpers.domain_utils.csr_san_get")
def test_allowed_domainlist_check_denylist_rejects(mock_san, mock_cn, logger):
    mock_san.return_value = ["DNS:mail.intra.net", "DNS:mail"]
    mock_cn.return_value = None
    error = allowed_domainlist_check(
        logger,
        "csr",
        ["*.intra.net"],
        allow_shortname_from_fqdn=True,
        shortname_denylist=["mail"],
    )
    assert error == "Either CN or SANs are not allowed by configuration"


@patch("acme2certifier.acme_srv.helpers.domain_utils.csr_cn_get")
@patch("acme2certifier.acme_srv.helpers.domain_utils.csr_san_get")
def test_allowed_domainlist_check_shortname_only_rejected(mock_san, mock_cn, logger):
    mock_san.return_value = ["DNS:host"]
    mock_cn.return_value = None
    error = allowed_domainlist_check(
        logger, "csr", ["*.intra.net"], allow_shortname_from_fqdn=True
    )
    assert error == "Either CN or SANs are not allowed by configuration"


@patch("acme2certifier.acme_srv.helpers.domain_utils.csr_cn_get")
@patch("acme2certifier.acme_srv.helpers.domain_utils.csr_san_get")
def test_allowed_domainlist_check_explicit_allowlist_still_works(
    mock_san, mock_cn, logger
):
    """Denylist only gates the shortname shortcut; explicit allowlist entry wins."""
    mock_san.return_value = ["DNS:mail"]
    mock_cn.return_value = None
    error = allowed_domainlist_check(
        logger,
        "csr",
        ["mail"],
        allow_shortname_from_fqdn=True,
        shortname_denylist=["mail"],
    )
    assert not error


@patch("acme2certifier.acme_srv.helpers.eab.allowed_domainlist_check")
def test_eab_profile_list_passes_shortname_settings(mock_chk, logger):
    """EAB allowed_domainlist check forwards cahandler shortname settings."""
    from acme2certifier.acme_srv.helpers.eab import eab_profile_list_check

    mock_chk.return_value = None
    cahandler = type(
        "CA",
        (),
        {
            "allow_shortname_from_fqdn": True,
            "shortname_denylist": ["mail"],
        },
    )()
    eabhandler = type("EAB", (), {})()
    eab_profile_list_check(
        logger, cahandler, eabhandler, "csr", "allowed_domainlist", ["*.intra.net"]
    )
    mock_chk.assert_called_once_with(
        logger,
        "csr",
        ["*.intra.net"],
        allow_shortname_from_fqdn=True,
        shortname_denylist=["mail"],
    )


def test_eab_profile_list_sets_shortname_denylist(logger):
    from acme2certifier.acme_srv.helpers.eab import eab_profile_list_check

    cahandler = type("CA", (), {"shortname_denylist": []})()
    eabhandler = type("EAB", (), {})()
    eab_profile_list_check(
        logger, cahandler, eabhandler, "csr", "shortname_denylist", ["vpn", "mail"]
    )
    assert cahandler.shortname_denylist == ["vpn", "mail"]


def test_eab_profile_entry_sets_bool_attr(logger):
    from acme2certifier.acme_srv.helpers.eab import _eab_profile_entry_check

    cahandler = type("CA", (), {"allow_shortname_from_fqdn": False})()
    eabhandler = type("EAB", (), {})()
    result = _eab_profile_entry_check(
        logger,
        cahandler,
        eabhandler,
        "csr",
        "allow_shortname_from_fqdn",
        True,
    )
    assert result is None
    assert cahandler.allow_shortname_from_fqdn is True
