# -*- coding: utf-8 -*-
"""Tests for acme_srv.helpers.network."""

from __future__ import annotations

import configparser
import logging
from collections.abc import Callable
from contextlib import AbstractContextManager
from typing import Any
from unittest.mock import MagicMock, Mock, patch

import dns.resolver
import requests

import pytest

from acme2certifier.acme_srv.helpers.network import (
    allowed_gai_family,
    dns_server_list_load,
    encode_url,
    fqdn_resolve,
    get_url,
    header_info_get,
    proxy_check,
    proxystring_convert,
    request_operation,
    server_name_configuration_validate,
    servercert_get,
    txt_get,
    url_get,
    url_get_with_own_dns,
    v6_adjust,
)

pytestmark = pytest.mark.usefixtures("clear_config_cache", "_silence_logging")


@patch(
    "acme2certifier.acme_srv.helpers.network.load_config",
    return_value=configparser.ConfigParser(),
)
def test_100_helper_get_url(_mock_load_config: MagicMock) -> None:
    """get_url https"""
    data_dic = {
        "HTTP_HOST": "http_host",
        "SERVER_PORT": "443",
        "PATH_INFO": "path_info",
    }
    assert "https://http_host" == get_url(data_dic, False)


@patch(
    "acme2certifier.acme_srv.helpers.network.load_config",
    return_value=configparser.ConfigParser(),
)
def test_101_helper_get_url(_mock_load_config: MagicMock) -> None:
    """get_url http"""
    data_dic = {"HTTP_HOST": "http_host", "SERVER_PORT": "80", "PATH_INFO": "path_info"}
    assert "http://http_host" == get_url(data_dic, False)


@patch(
    "acme2certifier.acme_srv.helpers.network.load_config",
    return_value=configparser.ConfigParser(),
)
def test_102_helper_get_url(_mock_load_config: MagicMock) -> None:
    """get_url http wsgi.scheme"""
    data_dic = {
        "HTTP_HOST": "http_host",
        "SERVER_PORT": "80",
        "PATH_INFO": "path_info",
        "wsgi.url_scheme": "wsgi.url_scheme",
    }
    assert "wsgi.url_scheme://http_host" == get_url(data_dic, False)


@patch(
    "acme2certifier.acme_srv.helpers.network.load_config",
    return_value=configparser.ConfigParser(),
)
def test_103_helper_get_url(_mock_load_config: MagicMock) -> None:
    """get_url https include_path true bot no pathinfo"""
    data_dic = {"HTTP_HOST": "http_host", "SERVER_PORT": "443"}
    assert "https://http_host" == get_url(data_dic, True)


@patch(
    "acme2certifier.acme_srv.helpers.network.load_config",
    return_value=configparser.ConfigParser(),
)
def test_104_helper_get_url(_mock_load_config: MagicMock) -> None:
    """get_url https and path info"""
    data_dic = {
        "HTTP_HOST": "http_host",
        "SERVER_PORT": "443",
        "PATH_INFO": "path_info",
    }
    assert "https://http_hostpath_info" == get_url(data_dic, True)


@patch(
    "acme2certifier.acme_srv.helpers.network.load_config",
    return_value=configparser.ConfigParser(),
)
def test_105_helper_get_url(_mock_load_config: MagicMock) -> None:
    """get_url wsgi.url and pathinfo"""
    data_dic = {
        "HTTP_HOST": "http_host",
        "SERVER_PORT": "80",
        "PATH_INFO": "path_info",
        "wsgi.url_scheme": "wsgi.url_scheme",
    }
    assert "wsgi.url_scheme://http_hostpath_info" == get_url(data_dic, True)


@patch(
    "acme2certifier.acme_srv.helpers.network.load_config",
    return_value=configparser.ConfigParser(),
)
def test_106_helper_get_url(_mock_load_config: MagicMock) -> None:
    """get_url http and pathinfo"""
    data_dic = {"HTTP_HOST": "http_host", "SERVER_PORT": "80", "PATH_INFO": "path_info"}
    assert "http://http_hostpath_info" == get_url(data_dic, True)


@patch(
    "acme2certifier.acme_srv.helpers.network.load_config",
    return_value=configparser.ConfigParser(),
)
def test_107_helper_get_url(_mock_load_config: MagicMock) -> None:
    """get_url without hostinfo"""
    data_dic = {"SERVER_PORT": "80", "PATH_INFO": "path_info"}
    assert "http://localhost" == get_url(data_dic, False)


@patch(
    "acme2certifier.acme_srv.helpers.network.load_config",
    return_value=configparser.ConfigParser(),
)
def test_108_helper_get_url(_mock_load_config: MagicMock) -> None:
    """get_url without SERVER_PORT"""
    data_dic = {"HTTP_HOST": "http_host"}
    assert "http://http_host" == get_url(data_dic, True)


@patch("acme2certifier.acme_srv.helpers.network.requests.get")
def test_109_helper_url_get(mock_request: MagicMock, logger: logging.Logger) -> None:
    """successful url get without dns servers"""
    mock_request.return_value.text = "foo"
    mock_request.return_value.status_code = 200
    result, status_code, error_msg = url_get(logger, "url")
    assert "foo" == result
    assert 200 == status_code
    assert None == error_msg


@patch("acme2certifier.acme_srv.helpers.network.requests.get")
def test_110_helper_url_get(mock_request: MagicMock, logger: logging.Logger) -> None:
    """successful url get without dns servers"""
    mock_request.return_value.text = "foo"
    mock_request.return_value.status_code = 200
    result, status_code, error_msg = url_get(logger, "url", "dns", "proxy")
    assert "foo" == result
    assert 200 == status_code
    assert None == error_msg


@patch("acme2certifier.acme_srv.helpers.network.requests.get")
def test_111_helper_url_get(mock_request: MagicMock, logger: logging.Logger) -> None:
    """unsuccessful url get without dns servers"""
    mock_request.return_value = {"foo": "foo"}
    result, status_code, error_msg = url_get(logger, "url")
    assert None == result
    assert 500 == status_code
    assert "Could not fetch URL" in error_msg


@patch("acme2certifier.acme_srv.helpers.network.url_get_with_own_dns")
def test_112_helper_url_get(mock_request: MagicMock, logger: logging.Logger) -> None:
    """successful url get with dns servers"""
    mock_request.return_value = ("foo", 200, None)
    result, status_code, error_msg = url_get(logger, "url", "dns")
    assert "foo" == result
    assert 200 == status_code
    assert None == error_msg


@patch(
    "acme2certifier.acme_srv.helpers.network.requests.get",
    side_effect=Mock(side_effect=Exception("foo")),
)
def test_113_helper_url_get(
    mock_request: MagicMock,
    logger: logging.Logger,
    capture_logs: Callable[..., AbstractContextManager[Any]],
) -> None:
    """unsuccessful url_get"""
    with capture_logs("test_a2c", level="INFO") as lcm:
        result, status_code, error_msg = url_get(logger, "url")
        assert None == result
        assert 500 == status_code
        assert "Could not fetch URL" in error_msg
    assert "ERROR:test_a2c:foo" in lcm.output


@patch("acme2certifier.acme_srv.helpers.network.requests.get")
def test_114_helper_url_get(mock_request: MagicMock, logger: logging.Logger) -> None:
    """unsuccessful url_get fallback to v4"""
    object = Mock()
    object.text = "foo"
    object.status_code = 200
    mock_request.side_effect = [Exception("foo"), object]
    result, status_code, error_msg = url_get(logger, "url")
    assert "foo" == result
    assert 200 == status_code
    assert None == error_msg


@patch("acme2certifier.acme_srv.helpers.network.requests.get")
def test_115_helper_url_get_with_own_dns(
    mock_request: MagicMock, logger: logging.Logger
) -> None:
    """successful url_get_with_own_dns get with dns servers"""
    mock_request.return_value.text = "foo"
    mock_request.return_value.status_code = 200
    result, status_code, error_msg = url_get_with_own_dns(logger, "url")
    assert "foo" == result
    assert 200 == status_code
    assert None == error_msg


@patch("acme2certifier.acme_srv.helpers.network.requests.get")
def test_116_helper_url_get_with_own_dns(
    mock_request: MagicMock, logger: logging.Logger
) -> None:
    """successful url_get_with_own_dns get with dns servers"""
    mock_request.return_value = {"foo": "foo"}
    result, status_code, error_msg = url_get_with_own_dns(logger, "url")
    assert None == result
    assert 500 == status_code
    assert "Could not get URL by using the configured DNS servers" in error_msg


@patch("acme2certifier.acme_srv.helpers.network.requests.get")
def test_117_helper_url_get_with_own_dns_non_200(
    mock_request: MagicMock, logger: logging.Logger
) -> None:
    """url_get_with_own_dns with non-200 status code"""
    mock_request.return_value.text = "Not Found"
    mock_request.return_value.status_code = 404
    mock_request.return_value.reason = "Not Found"
    result, status_code, error_msg = url_get_with_own_dns(
        logger, "http://example.com/test"
    )
    assert "Not Found" == result
    assert 404 == status_code
    assert "http://example.com/test Not Found" == error_msg


@patch("acme2certifier.acme_srv.helpers.network.requests.get")
def test_118_helper_url_get_with_own_dns_verify_false(
    mock_request: MagicMock, logger: logging.Logger
) -> None:
    """url_get_with_own_dns with verify=False parameter"""
    mock_request.return_value.text = "secure content"
    mock_request.return_value.status_code = 200
    result, status_code, error_msg = url_get_with_own_dns(
        logger, "https://secure.example.com", verify=False
    )
    assert "secure content" == result
    assert 200 == status_code
    assert None == error_msg
    mock_request.assert_called_once()
    call_args = mock_request.call_args
    assert call_args[1]["verify"] == False


@patch("acme2certifier.acme_srv.helpers.network.requests.get")
def test_119_helper_url_get_with_own_dns_connection_cleanup(
    mock_request: MagicMock, logger: logging.Logger
) -> None:
    """url_get_with_own_dns clears thread-local custom DNS after exception"""
    mock_request.side_effect = requests.exceptions.ConnectionError("Connection failed")
    from acme2certifier.acme_srv.helpers import network as network_mod

    result, status_code, error_msg = url_get_with_own_dns(logger, "http://example.com")
    assert None == result
    assert 500 == status_code
    assert "Could not get URL by using the configured DNS servers" in error_msg
    assert not getattr(network_mod._dns_connect_tls, "use_custom_dns", False)


@patch("acme2certifier.acme_srv.helpers.network.requests.get")
def test_120_helper_url_get_with_own_dns_server_error(
    mock_request: MagicMock, logger: logging.Logger
) -> None:
    """url_get_with_own_dns with server error status code"""
    mock_request.return_value.text = "Internal Server Error"
    mock_request.return_value.status_code = 500
    mock_request.return_value.reason = "Internal Server Error"
    result, status_code, error_msg = url_get_with_own_dns(
        logger, "http://api.example.com/endpoint"
    )
    assert "Internal Server Error" == result
    assert 500 == status_code
    assert "http://api.example.com/endpoint Internal Server Error" == error_msg


@patch("acme2certifier.acme_srv.helpers.network.load_config")
def test_121_helper_dns_server_list_load(mock_load_config: MagicMock) -> None:
    """successful dns_server_list_load with empty config file"""
    mock_load_config.return_value = {}
    assert ["9.9.9.9", "8.8.8.8"] == dns_server_list_load()


@patch("acme2certifier.acme_srv.helpers.network.load_config")
def test_122_helper_dns_server_list_load(mock_load_config: MagicMock) -> None:
    """successful dns_server_list_load with empty Challenge section"""
    mock_load_config.return_value = {"Challenge": {}}
    assert ["9.9.9.9", "8.8.8.8"] == dns_server_list_load()


@patch("acme2certifier.acme_srv.helpers.network.load_config")
def test_123_helper_dns_server_list_load(mock_load_config: MagicMock) -> None:
    """successful dns_server_list_load with wrong Challenge section"""
    mock_load_config.return_value = {"Challenge": {"foo": "bar"}}
    assert ["9.9.9.9", "8.8.8.8"] == dns_server_list_load()


@patch("acme2certifier.acme_srv.helpers.network.load_config")
def test_124_helper_dns_server_list_load(mock_load_config: MagicMock) -> None:
    """successful dns_server_list_load with wrong json format"""
    mock_load_config.return_value = {"Challenge": {"dns_server_list": "bar"}}
    assert ["9.9.9.9", "8.8.8.8"] == dns_server_list_load()


@patch("acme2certifier.acme_srv.helpers.network.load_config")
def test_125_helper_dns_server_list_load(mock_load_config: MagicMock) -> None:
    """successful dns_server_list_load with wrong json format"""
    mock_load_config.return_value = {"Challenge": {"dns_server_list": '["foo", "bar"]'}}
    assert ["foo", "bar"] == dns_server_list_load()


@patch(
    "acme2certifier.acme_srv.helpers.network.load_config",
    return_value=configparser.ConfigParser(),
)
def test_152_helper_get_url(_mock_load_config: MagicMock) -> None:
    """get_url with xforwarded https"""
    data_dic = {
        "HTTP_X_FORWARDED_PROTO": "https",
        "HTTP_HOST": "http_host",
        "SERVER_PORT": "443",
        "PATH_INFO": "path_info",
    }
    assert "https://http_host" == get_url(data_dic, False)


@patch(
    "acme2certifier.acme_srv.helpers.network.load_config",
    return_value=configparser.ConfigParser(),
)
def test_153_helper_get_url(_mock_load_config: MagicMock) -> None:
    """get_url with xforwarded http"""
    data_dic = {
        "HTTP_X_FORWARDED_PROTO": "http",
        "HTTP_HOST": "http_host",
        "SERVER_PORT": "443",
        "PATH_INFO": "path_info",
    }
    assert "http://http_host" == get_url(data_dic, False)


@patch("acme2certifier.acme_srv.helpers.network.load_config")
def test_154_helper_get_url_server_name_override(mock_load_cfg: MagicMock) -> None:
    """get_url uses configured DEFAULT.server_name instead of Host header"""
    cfg = configparser.ConfigParser()
    cfg["DEFAULT"] = {"server_name": "acme.example.com"}
    mock_load_cfg.return_value = cfg
    data_dic = {
        "HTTP_HOST": "attacker.example.net",
        "HTTP_X_FORWARDED_PROTO": "https",
        "SERVER_PORT": "443",
        "PATH_INFO": "/acme/directory",
    }
    assert "https://acme.example.com" == get_url(data_dic, False)
    assert "https://acme.example.com/acme/directory" == get_url(data_dic, True)


def test_155_server_name_configuration_fallback_warning(
    logger: logging.Logger, capture_logs: Callable[..., AbstractContextManager[Any]]
) -> None:
    """startup warning when DEFAULT.server_name is not configured"""
    cfg = configparser.ConfigParser()
    cfg["Directory"] = {"caaidentities": '["acme.example.com"]'}
    with capture_logs("test_a2c", level="WARNING") as lcm:
        server_name_configuration_validate(logger, cfg)
    assert any(("No [DEFAULT] server_name configured" in line for line in lcm.output))


def test_156_server_name_caa_mismatch_warning(
    logger: logging.Logger, capture_logs: Callable[..., AbstractContextManager[Any]]
) -> None:
    """startup warning when server_name is not part of caaidentities"""
    cfg = configparser.ConfigParser()
    cfg["DEFAULT"] = {"server_name": "acme.example.com"}
    cfg["Directory"] = {"caaidentities": '["issuer.example.com"]'}
    with capture_logs("test_a2c", level="WARNING") as lcm:
        server_name_configuration_validate(logger, cfg)
    assert any(
        ("is not listed in Directory.caaidentities" in line for line in lcm.output)
    )


def test_157_server_name_caa_match_no_warning(
    logger: logging.Logger, capture_no_logs: Callable[..., AbstractContextManager[Any]]
) -> None:
    """no warning when server_name matches caaidentities"""
    cfg = configparser.ConfigParser()
    cfg["DEFAULT"] = {"server_name": "acme.example.com"}
    cfg["Directory"] = {"caaidentities": '["acme.example.com"]'}
    with capture_no_logs("test_a2c", level="WARNING"):
        server_name_configuration_validate(logger, cfg)


@patch("dns.resolver.Resolver")
def test_168_helper_fqdn_resolve(
    mock_resolve: MagicMock, logger: logging.Logger
) -> None:
    """successful dns-query for short hostname with custom nameserver"""
    mock_resolve.return_value.resolve.return_value = ["10.0.0.2"]
    assert ("10.0.0.2", False, None) == fqdn_resolve(logger, "foo", dnssrv="10.0.0.1")


@patch("dns.resolver.Resolver")
def test_169_helper_fqdn_resolve(
    mock_resolve: MagicMock, logger: logging.Logger
) -> None:
    """successful dns-query returning covering github"""
    mock_resolve.return_value.resolve.return_value = ["foo"]
    assert ("foo", False, None) == fqdn_resolve(
        logger, "foo.bar.local", dnssrv="10.0.0.1"
    )


@patch("dns.resolver.Resolver")
def test_170_helper_fqdn_resolve(
    mock_resolve: MagicMock, logger: logging.Logger
) -> None:
    """successful dns-query for short hostname returning a single entry"""
    mock_resolve.return_value.resolve.return_value = ["10.0.0.2"]
    assert ("10.0.0.2", False, None) == fqdn_resolve(logger, "foo")


@patch("dns.resolver.Resolver")
def test_171_helper_fqdn_resolve(
    mock_resolve: MagicMock, logger: logging.Logger
) -> None:
    """successful dns-query returning two entries but catch singles"""
    mock_resolve.return_value.resolve.side_effect = [["v41", "v42"], ["v61", "v62"]]
    assert ("v41", False, None) == fqdn_resolve(
        logger, "foo.bar.local", dnssrv="10.0.0.1"
    )


@patch("dns.resolver.Resolver")
def test_172_helper_fqdn_resolve(
    mock_resolve: MagicMock, logger: logging.Logger
) -> None:
    """successful dns-query returning only ipv6 and catchsingle"""
    mock_resolve.return_value.resolve.side_effect = [[], ["v61", "v62"]]
    assert ("v61", False, None) == fqdn_resolve(
        logger, "foo.bar.local", dnssrv="10.0.0.1"
    )


@patch("dns.resolver.Resolver")
def test_173_helper_fqdn_resolve(
    mock_resolve: MagicMock, logger: logging.Logger
) -> None:
    """successful dns-query returning list and catch_all"""
    mock_resolve.return_value.resolve.side_effect = [["v41", "v42"], ["v61", "v62"]]
    assert (["v41", "v42", "v61", "v62"], False, None) == fqdn_resolve(
        logger, "foo.bar.local", dnssrv="10.0.0.1", catch_all=True
    )


@patch("dns.resolver.Resolver")
def test_174_helper_fqdn_resolve(
    mock_resolve: MagicMock, logger: logging.Logger
) -> None:
    """successful dns-query returning covering list but no v4 and catch_all"""
    mock_resolve.return_value.resolve.side_effect = [[], ["v61", "v62"]]
    assert (["v61", "v62"], False, None) == fqdn_resolve(
        logger, "foo.bar.local", dnssrv="10.0.0.1", catch_all=True
    )


@patch("dns.resolver.Resolver")
def test_175_helper_fqdn_resolve(
    mock_resolve: MagicMock, logger: logging.Logger
) -> None:
    """successful dns-query returning list v6 only and catch_all"""
    mock_resolve.return_value.resolve.side_effect = [["v41", "v42"], []]
    assert (["v41", "v42"], False, None) == fqdn_resolve(
        logger, "foo.bar.local", dnssrv="10.0.0.1", catch_all=True
    )


@patch("dns.resolver.Resolver")
def test_176_helper_fqdn_resolve(
    mock_resolve: MagicMock, logger: logging.Logger
) -> None:
    """successful dns-query returning covering list but no v4 and catch_all"""
    mock_resolve.return_value.resolve.side_effect = [Exception("foo"), ["v61", "v62"]]
    assert (["v61", "v62"], False, None) == fqdn_resolve(
        logger, "foo.bar.local", dnssrv="10.0.0.1", catch_all=True
    )


@patch("dns.resolver.Resolver")
def test_177_helper_fqdn_resolve(
    mock_resolve: MagicMock, logger: logging.Logger
) -> None:
    """successful dns-query returning list v6 only and catch_all"""
    mock_resolve.return_value.resolve.side_effect = [["v41", "v42"], Exception("foo")]
    assert (["v41", "v42"], False, None) == fqdn_resolve(
        logger, "foo.bar.local", dnssrv="10.0.0.1", catch_all=True
    )


@patch("dns.resolver.Resolver")
def test_178_helper_fqdn_resolve(
    mock_resolve: MagicMock, logger: logging.Logger
) -> None:
    """successful dns-query returning covering list but no v4 and catch_all"""
    mock_resolve.return_value.resolve.side_effect = Mock(
        side_effect=[dns.resolver.NXDOMAIN, ["v61", "v62"]]
    )
    assert (["v61", "v62"], False, None) == fqdn_resolve(
        logger, "foo.bar.local", dnssrv=["10.0.0.1"], catch_all=True
    )


@patch("dns.resolver.Resolver")
def test_179_helper_fqdn_resolve(
    mock_resolve: MagicMock, logger: logging.Logger
) -> None:
    """successful dns-query returning list v6 only and catch_all"""
    mock_resolve.return_value.resolve.side_effect = Mock(
        side_effect=[["v41", "v42"], dns.resolver.NXDOMAIN]
    )
    assert (["v41", "v42"], False, None) == fqdn_resolve(
        logger, "foo.bar.local", dnssrv=["10.0.0.1"], catch_all=True
    )


@patch("dns.resolver.Resolver")
def test_180_helper_fqdn_resolve(
    mock_resolve: MagicMock, logger: logging.Logger
) -> None:
    """successful dns-query returning covering list but no v4 and catch_all"""
    mock_resolve.return_value.resolve.side_effect = Mock(
        side_effect=dns.resolver.NXDOMAIN
    )
    err_msg = "A: NXDOMAIN: foo.bar.local does not exist; AAAA: NXDOMAIN: foo.bar.local does not exist"
    assert ([], True, err_msg) == fqdn_resolve(
        logger, "foo.bar.local", dnssrv=["10.0.0.1"], catch_all=True
    )


@patch("dns.resolver.Resolver")
def test_181_helper_fqdn_resolve(
    mock_resolve: MagicMock, logger: logging.Logger
) -> None:
    """successful dns-query returning one value"""
    mock_resolve.return_value.resolve.return_value = ["foo"]
    assert ("foo", False, None) == fqdn_resolve(logger, "foo.bar.local")


@patch("dns.resolver.Resolver")
def test_182_helper_fqdn_resolve(
    mock_resolve: MagicMock, logger: logging.Logger
) -> None:
    """successful dns-query returning two values"""
    mock_resolve.return_value.resolve.return_value = ["bar", "foo"]
    assert ("bar", False, None) == fqdn_resolve(logger, "foo.bar.local")


@patch("dns.resolver.Resolver")
def test_183_helper_fqdn_resolve(
    mock_resolve: MagicMock, logger: logging.Logger
) -> None:
    """catch NXDOMAIN"""
    mock_resolve.return_value.resolve.side_effect = Mock(
        side_effect=dns.resolver.NXDOMAIN
    )
    assert (
        None,
        True,
        "A: NXDOMAIN: foo.bar.local does not exist; AAAA: NXDOMAIN: foo.bar.local does not exist",
    ) == fqdn_resolve(logger, "foo.bar.local")


@patch("dns.resolver.Resolver")
def test_184_helper_fqdn_resolve(
    mock_resolve: MagicMock, logger: logging.Logger
) -> None:
    """catch NoAnswer"""
    mock_resolve.return_value.resolve.side_effect = Mock(
        side_effect=dns.resolver.NoAnswer
    )
    err_msg = "A: No A record found for foo.bar.local; AAAA: No AAAA record found for foo.bar.local"
    assert (None, True, err_msg) == fqdn_resolve(logger, "foo.bar.local")


@patch("dns.resolver.Resolver")
def test_185_helper_fqdn_resolve(
    mock_resolve: MagicMock, logger: logging.Logger
) -> None:
    """catch other dns related execption"""
    mock_resolve.return_value.resolve.side_effect = Mock(
        side_effect=dns.resolver.NoNameservers
    )
    err_msg = "A: DNS resolution error: All nameservers failed to answer the query.; AAAA: DNS resolution error: All nameservers failed to answer the query."
    assert (None, True, err_msg) == fqdn_resolve(logger, "foo.bar.local")


@patch("dns.resolver.Resolver")
def test_186_helper_fqdn_resolve(
    mock_resolve: MagicMock, logger: logging.Logger
) -> None:
    """catch other execption"""
    mock_resolve.return_value.resolve.side_effect = Mock(side_effect=Exception("foo"))
    assert (
        None,
        True,
        "A: DNS resolution error: foo; AAAA: DNS resolution error: foo",
    ) == fqdn_resolve(logger, "foo.bar.local")


@patch("dns.resolver.Resolver")
def test_187_helper_fqdn_resolve(
    mock_resolve: MagicMock, logger: logging.Logger
) -> None:
    """catch NXDOMAIN on v4 and fine in v6"""
    mock_resolve.return_value.resolve.side_effect = (
        Mock(side_effect=dns.resolver.NXDOMAIN),
        ["foo"],
    )
    assert ("foo", False, None) == fqdn_resolve(logger, "foo.bar.local")


@patch("dns.resolver.Resolver")
def test_188_helper_fqdn_resolve(
    mock_resolve: MagicMock, logger: logging.Logger
) -> None:
    """catch NoAnswer on v4 and fine in v6"""
    mock_resolve.return_value.resolve.side_effect = (
        Mock(side_effect=dns.resolver.NoAnswer),
        ["foo"],
    )
    assert ("foo", False, None) == fqdn_resolve(logger, "foo.bar.local")


@patch("dns.resolver.Resolver")
def test_189_helper_fqdn_resolve(
    mock_resolve: MagicMock, logger: logging.Logger
) -> None:
    """catch other dns related execption on v4 and fine in v6"""
    mock_resolve.return_value.resolve.side_effect = ([Exception("foo"), ["foo"]],)
    assert ("foo", False, None) == fqdn_resolve(logger, "foo.bar.local")


@patch("dns.resolver.Resolver")
def test_190_helper_fqdn_resolve(
    mock_resolve: MagicMock, logger: logging.Logger
) -> None:
    """catch other execption when resolving v4 but fine in v6"""
    mock_resolve.return_value.resolve.side_effect = ([Exception("foo"), ["foo"]],)
    assert ("foo", False, None) == fqdn_resolve(logger, "foo.bar.local")


@patch("socket.AF_INET")
def test_253_allowed_gai_family(mock_sock: MagicMock) -> None:
    """test allowed_gai_family"""
    assert allowed_gai_family()


@patch("acme2certifier.acme_srv.helpers.network.proxystring_convert")
@patch("ssl.DER_cert_to_PEM_cert")
@patch("ssl.SSLContext.wrap_socket")
@patch("socks.socksocket")
def test_255_servercert_get(
    mock_sock: MagicMock,
    mock_context: MagicMock,
    mock_cert: MagicMock,
    mock_convert: MagicMock,
    logger: logging.Logger,
) -> None:
    """test servercert get"""
    mock_convert.return_value = ("proxy_proto", "proxy_addr", "proxy_port")
    mock_sock = Mock()
    mock_context = Mock()
    mock_cert.return_value = "foo"
    pem, _alpn = servercert_get(logger, "hostname")
    assert "foo" == pem
    assert not mock_convert.called


@patch("acme2certifier.acme_srv.helpers.network.ipv6_chk")
@patch("acme2certifier.acme_srv.helpers.network.proxystring_convert")
@patch("ssl.DER_cert_to_PEM_cert")
@patch("ssl.SSLContext.wrap_socket")
@patch("socket.socket")
@patch("socks.socksocket")
def test_256_servercert_get(
    mock_sock: MagicMock,
    mock_ssock: MagicMock,
    mock_context: MagicMock,
    mock_cert: MagicMock,
    mock_convert: MagicMock,
    mock_ipchk: MagicMock,
    logger: logging.Logger,
) -> None:
    """test servercert get ippv6"""
    mock_convert.return_value = ("proxy_proto", "proxy_addr", "proxy_port")
    mock_ipchk.return_value = True
    mock_context = Mock()
    mock_cert.return_value = "foo"
    pem, _alpn = servercert_get(logger, "hostname")
    assert "foo" == pem
    assert mock_ssock.called
    assert not mock_sock.called


@patch("acme2certifier.acme_srv.helpers.network.proxystring_convert")
@patch("ssl.DER_cert_to_PEM_cert")
@patch("ssl.SSLContext.wrap_socket")
@patch("socket.socket")
@patch("socks.socksocket")
def test_257_servercert_get(
    mock_sock: MagicMock,
    mock_ssock: MagicMock,
    mock_context: MagicMock,
    mock_cert: MagicMock,
    mock_convert: MagicMock,
    logger: logging.Logger,
) -> None:
    """test servercert get with proxy"""
    mock_convert.return_value = ("proxy_proto", "proxy_addr", "proxy_port")
    mock_context = Mock()
    mock_cert.return_value = "foo"
    pem, _alpn = servercert_get(logger, "hostname", 443, "proxy")
    assert "foo" == pem
    assert mock_convert.called
    assert not mock_ssock.called


@patch("ssl.DER_cert_to_PEM_cert")
@patch("ssl.SSLContext.wrap_socket")
@patch("socks.socksocket")
def test_258_servercert_get(
    mock_sock: MagicMock,
    mock_context: MagicMock,
    mock_cert: MagicMock,
    logger: logging.Logger,
    capture_logs: Callable[..., AbstractContextManager[Any]],
) -> None:
    """test servercert exception"""
    mock_sock = Mock()
    mock_context.side_effect = Exception("exc_warp_sock")
    mock_cert.return_value = "foo"
    with capture_logs("test_a2c", level="INFO") as lcm:
        assert (None, None) == servercert_get(logger, "hostname", 443)
    assert not mock_cert.called
    assert (
        "ERROR:test_a2c:Could not get peer certificate. Error: exc_warp_sock"
        in lcm.output
    )


@patch("ssl.TLSVersion")
@patch("acme2certifier.acme_srv.helpers.network.proxystring_convert")
@patch("ssl.DER_cert_to_PEM_cert")
@patch("ssl.SSLContext.wrap_socket")
@patch("socks.socksocket")
def test_259_servercert_get(
    mock_sock: MagicMock,
    mock_context: MagicMock,
    mock_cert: MagicMock,
    mock_convert: MagicMock,
    map_min_version: MagicMock,
    logger: logging.Logger,
    capture_logs: Callable[..., AbstractContextManager[Any]],
) -> None:
    """test servercert get"""
    mock_convert.return_value = ("proxy_proto", "proxy_addr", "proxy_port")
    mock_sock = Mock()
    mock_context = Mock()
    mock_cert.return_value = "foo"
    with capture_logs("test_a2c", level="INFO") as lcm:
        pem, _alpn = servercert_get(logger, "hostname")
        assert "foo" == pem
    assert (
        "ERROR:test_a2c:Error while getting the peer certifiate: minimum tls version not supported"
        in lcm.output
    )
    assert not mock_convert.called


@patch("dns.resolver.Resolver")
@patch("dns.resolver.resolve")
def test_260_txt_get(
    mock_resolve: MagicMock, mock_res: MagicMock, logger: logging.Logger
) -> None:
    """successful dns-query returning one txt record"""
    resp_obj = Mock()
    resp_obj.strings = ["foo", "bar"]
    mock_resolve.return_value = [resp_obj]
    assert ["foo"] == txt_get(logger, "foo", "10.0.0.1")
    assert mock_res.called


@patch("dns.resolver.resolve")
def test_261_txt_get(mock_resolve: MagicMock, logger: logging.Logger) -> None:
    """successful dns-query returning one txt record"""
    resp_obj = Mock()
    resp_obj.strings = ["foo", "bar"]
    mock_resolve.return_value = [resp_obj]
    assert ["foo"] == txt_get(logger, "foo")


@patch("dns.resolver.resolve")
def test_262_txt_get(mock_resolve: MagicMock, logger: logging.Logger) -> None:
    """successful dns-query returning one txt record"""
    resp_obj1 = Mock()
    resp_obj1.strings = ["foo1", "bar1"]
    resp_obj2 = Mock()
    resp_obj2.strings = ["foo2", "bar2"]
    mock_resolve.return_value = [resp_obj1, resp_obj2]
    assert ["foo1", "foo2"] == txt_get(logger, "foo")


@patch("dns.resolver.resolve")
def test_263_txt_get(
    mock_resolve: MagicMock,
    logger: logging.Logger,
    capture_logs: Callable[..., AbstractContextManager[Any]],
) -> None:
    """successful dns-query returning one txt record"""
    mock_resolve.side_effect = Exception("mock_resolve")
    with capture_logs("test_a2c", level="INFO") as lcm:
        assert not txt_get(logger, "foo")
    assert "ERROR:test_a2c:Could not get TXT record: mock_resolve" in lcm.output


def test_264_proxystring_convert(logger: logging.Logger) -> None:
    """convert proxy_string http"""
    assert (3, "proxy", 8080) == proxystring_convert(logger, "http://proxy:8080")


def test_265_proxystring_convert(logger: logging.Logger) -> None:
    """convert proxy_string socks4"""
    assert (1, "proxy", 8080) == proxystring_convert(logger, "socks4://proxy:8080")


def test_266_proxystring_convert(logger: logging.Logger) -> None:
    """convert proxy_string socks5"""
    assert (2, "proxy", 8080) == proxystring_convert(logger, "socks5://proxy:8080")


def test_267_proxystring_convert(
    logger: logging.Logger, capture_logs: Callable[..., AbstractContextManager[Any]]
) -> None:
    """convert proxy_string unknown protocol"""
    with capture_logs("test_a2c", level="INFO") as lcm:
        assert (None, "proxy", 8080) == proxystring_convert(logger, "unk://proxy:8080")
    assert "ERROR:test_a2c:Unknown proxy protocol: unk" in lcm.output


def test_268_proxystring_convert(
    logger: logging.Logger, capture_logs: Callable[..., AbstractContextManager[Any]]
) -> None:
    """convert proxy_string unknown protocol"""
    with capture_logs("test_a2c", level="INFO") as lcm:
        assert (3, "proxy", None) == proxystring_convert(logger, "http://proxy:ftp")
    assert "ERROR:test_a2c:Unknown proxy port" in lcm.output
    assert "ftp" not in "\n".join(lcm.output)


def test_269_proxystring_convert(
    logger: logging.Logger, capture_logs: Callable[..., AbstractContextManager[Any]]
) -> None:
    """convert proxy_string porxy sting without protocol"""
    with capture_logs("test_a2c", level="INFO") as lcm:
        assert (None, None, None) == proxystring_convert(logger, "proxy")
    assert "ERROR:test_a2c:Error while splitting proxy_server string" in lcm.output
    assert "ERROR:test_a2c:Proxy protocol, address, or port is missing" in lcm.output


def test_270_proxystring_convert(
    logger: logging.Logger, capture_logs: Callable[..., AbstractContextManager[Any]]
) -> None:
    """convert proxy_string porxy sting without port"""
    with capture_logs("test_a2c", level="INFO") as lcm:
        assert (None, None, None) == proxystring_convert(logger, "http://proxy")
    assert "ERROR:test_a2c:Error while splitting proxy into host/port" in lcm.output
    assert "ERROR:test_a2c:Proxy protocol, address, or port is missing" in lcm.output
    assert "http://proxy" not in "\n".join(lcm.output)


def test_271_proxystring_convert_redacts_userinfo(
    logger: logging.Logger, capture_logs: Callable[..., AbstractContextManager[Any]]
) -> None:
    """proxy userinfo must not appear in debug or error logs"""
    secret = "s3cret-pass"
    proxy = f"http://alice:{secret}@proxy.example"
    with capture_logs("test_a2c", level="DEBUG") as lcm:
        proxystring_convert(logger, proxy)
    joined = "\n".join(lcm.output)
    assert secret not in joined
    assert "alice" not in joined
    assert "http://***@proxy.example" in joined


def test_272_proxy_check(logger: logging.Logger) -> None:
    """check proxy for empty list"""
    fqdn = "foo.bar.local"
    proxy_list = {}
    assert not proxy_check(logger, fqdn, proxy_list)


def test_273_proxy_check(logger: logging.Logger) -> None:
    """check proxy - no match"""
    fqdn = "foo.bar.local"
    proxy_list = {"foo1.bar.local": "proxy_match"}
    assert not proxy_check(logger, fqdn, proxy_list)


def test_274_proxy_check(logger: logging.Logger) -> None:
    """check proxy - single entry"""
    fqdn = "foo.bar.local"
    proxy_list = {"foo.bar.local": "proxy_match"}
    assert "proxy_match" == proxy_check(logger, fqdn, proxy_list)


def test_275_proxy_check(logger: logging.Logger) -> None:
    """check proxy  - multiple entry"""
    fqdn = "foo.bar.local"
    proxy_list = {"bar.bar.local": "proxy_nomatch", "foo.bar.local": "proxy_match"}
    assert "proxy_match" == proxy_check(logger, fqdn, proxy_list)


def test_276_proxy_check(logger: logging.Logger) -> None:
    """check proxy  -  multiple entrie domain match"""
    fqdn = "foo.bar.local"
    proxy_list = {"bar.bar.local": "proxy_nomatch", "bar.local$": "proxy_match"}
    assert "proxy_match" == proxy_check(logger, fqdn, proxy_list)


def test_277_proxy_check(logger: logging.Logger) -> None:
    """check proxy for empty list  multiple entrie domain match"""
    fqdn = "foo.bar.local"
    proxy_list = {"bar.local$": "proxy_nomatch", "foo.bar.local$": "proxy_match"}
    assert "proxy_match" == proxy_check(logger, fqdn, proxy_list)


def test_278_proxy_check(logger: logging.Logger) -> None:
    """check proxy - multiple entrie domain match"""
    fqdn = "foo.bar.local"
    proxy_list = {"bar.local$": "proxy_match", "foo1.bar.local$": "proxy_nomatch"}
    assert "proxy_match" == proxy_check(logger, fqdn, proxy_list)


def test_279_proxy_check(logger: logging.Logger) -> None:
    """check proxy - wildcard"""
    fqdn = "foo.bar.local"
    proxy_list = {"foo1.bar.local$": "proxy_nomatch", "*.bar.local$": "proxy_match"}
    assert "proxy_match" == proxy_check(logger, fqdn, proxy_list)


def test_280_proxy_check(logger: logging.Logger) -> None:
    """check proxy - wildcard"""
    fqdn = "foo.bar.local"
    proxy_list = {".local$": "proxy_nomatch", "*.bar.local$": "proxy_match"}
    assert "proxy_match" == proxy_check(logger, fqdn, proxy_list)


def test_281_proxy_check(logger: logging.Logger) -> None:
    """check proxy - wildcard"""
    fqdn = "local"
    proxy_list = {"local$": "proxy_match", "*.bar.local$": "proxy_no_match"}
    assert "proxy_match" == proxy_check(logger, fqdn, proxy_list)


def test_282_proxy_check(logger: logging.Logger) -> None:
    """check proxy - wildcard"""
    fqdn = "foo.bar.local"
    proxy_list = {
        "*": "wildcard",
        "notlocal$": "proxy_no_match",
        "*.notbar.local$": "proxy_no_match",
    }
    assert "wildcard" == proxy_check(logger, fqdn, proxy_list)


def test_290_proxy_check(logger: logging.Logger) -> None:
    """check proxy - wildcard"""
    fqdn = "foo.bar.local"
    proxy_list = {"*.bar.local$": "proxy_match"}
    assert "proxy_match" == proxy_check(logger, fqdn, proxy_list)


@patch("acme2certifier.acme_srv.helpers.network.USER_AGENT", "FOOBAR")
def test_350_v6_adjust(logger: logging.Logger) -> None:
    """test v6_adjust()"""
    url = "http://www.foo.bar"
    assert (
        {"Connection": "close", "Accept-Encoding": "gzip", "User-Agent": "FOOBAR"},
        "http://www.foo.bar",
    ) == v6_adjust(logger, url)


@patch("acme2certifier.acme_srv.helpers.network.USER_AGENT", "FOOBAR")
def test_351_v6_adjust(logger: logging.Logger) -> None:
    """test v6_adjust()"""
    url = "http://192.168.123.10"
    assert (
        {"Connection": "close", "Accept-Encoding": "gzip", "User-Agent": "FOOBAR"},
        "http://192.168.123.10",
    ) == v6_adjust(logger, url)


@patch("acme2certifier.acme_srv.helpers.network.USER_AGENT", "FOOBAR")
def test_352_v6_adjust(logger: logging.Logger) -> None:
    """test v6_adjust()"""
    url = "http://fe80::215:5dff:fec0:102"
    assert (
        {
            "Connection": "close",
            "Accept-Encoding": "gzip",
            "User-Agent": "FOOBAR",
            "Host": "fe80::215:5dff:fec0:102",
        },
        "http://[fe80::215:5dff:fec0:102]/",
    ) == v6_adjust(logger, url)


def test_357_header_info_get(logger: logging.Logger) -> None:
    """header_info_get ()"""
    models_mock = MagicMock()
    models_mock.DBstore().certificates_search.return_value = ("foo", "bar")
    modules = {"acme2certifier.acme_srv.db_handler": models_mock}
    patch.dict("sys.modules", modules).start()
    assert ["foo", "bar"] == header_info_get(logger, "csr")


def test_358_header_info_get(
    logger: logging.Logger, capture_logs: Callable[..., AbstractContextManager[Any]]
) -> None:
    """header_info_get ()"""
    models_mock = MagicMock()
    models_mock.DBstore().certificates_search.side_effect = Exception("mock_search")
    modules = {"acme2certifier.acme_srv.db_handler": models_mock}
    patch.dict("sys.modules", modules).start()
    with capture_logs("test_a2c", level="INFO") as lcm:
        assert not header_info_get(logger, "csr")
    assert (
        "ERROR:test_a2c:Error while getting header_info from database: mock_search"
        in lcm.output
    )


def test_359_encode_url(logger: logging.Logger) -> None:
    url = "www.example.com"
    assert url == encode_url(logger, url)


def test_360_encode_url(logger: logging.Logger) -> None:
    url = "www.example.com/hello world"
    assert "www.example.com/hello%20world" == encode_url(logger, url)


def test_361_encode_url(logger: logging.Logger) -> None:
    url = "www.example.com/hello@world?foo=bar&bar=foo"
    assert "www.example.com/hello%40world%3Ffoo%3Dbar%26bar%3Dfoo" == encode_url(
        logger, url
    )


@patch("acme2certifier.acme_srv.helpers.network.requests.put")
@patch("acme2certifier.acme_srv.helpers.network.requests.post")
@patch("acme2certifier.acme_srv.helpers.network.requests.get")
def test_463_request_operation(
    mock_get: MagicMock,
    mock_post: MagicMock,
    mock_put: MagicMock,
    logger: logging.Logger,
) -> None:
    """test request_operation()"""
    mockresponse_get = Mock()
    mockresponse_get.status_code = "status_code"
    mockresponse_get.json = lambda: {"get": "get"}
    mock_get.return_value = mockresponse_get
    mockresponse_post = Mock()
    mockresponse_post.status_code = "status_code"
    mockresponse_post.json = lambda: {"post": "post"}
    mock_post.return_value = mockresponse_post
    mockresponse_put = Mock()
    mockresponse_put.status_code = "status_code"
    mockresponse_put.json = lambda: {"put": "put"}
    mock_put.return_value = mockresponse_put
    assert ("status_code", {"get": "get"}) == request_operation(
        logger=logger, url="foo", method="get"
    )
    assert mock_get.called
    assert not mock_post.called
    assert not mock_put.called


@patch("acme2certifier.acme_srv.helpers.network.requests.put")
@patch("acme2certifier.acme_srv.helpers.network.requests.post")
@patch("acme2certifier.acme_srv.helpers.network.requests.get")
def test_464_request_operation(
    mock_get: MagicMock,
    mock_post: MagicMock,
    mock_put: MagicMock,
    logger: logging.Logger,
) -> None:
    """test request_operation()"""
    mockresponse_get = Mock()
    mockresponse_get.status_code = "status_code"
    mockresponse_get.json = lambda: {"get": "get"}
    mock_get.return_value = mockresponse_get
    mockresponse_post = Mock()
    mockresponse_post.status_code = "status_code"
    mockresponse_post.json = lambda: {"post": "post"}
    mock_post.return_value = mockresponse_post
    mockresponse_put = Mock()
    mockresponse_put.status_code = "status_code"
    mockresponse_put.json = lambda: {"put": "put"}
    mock_put.return_value = mockresponse_put
    assert ("status_code", {"post": "post"}) == request_operation(
        logger=logger, url="foo", method="post"
    )
    assert not mock_get.called
    assert mock_post.called
    assert not mock_put.called


@patch("acme2certifier.acme_srv.helpers.network.requests.put")
@patch("acme2certifier.acme_srv.helpers.network.requests.post")
@patch("acme2certifier.acme_srv.helpers.network.requests.get")
def test_465_request_operation(
    mock_get: MagicMock,
    mock_post: MagicMock,
    mock_put: MagicMock,
    logger: logging.Logger,
) -> None:
    """test request_operation()"""
    mockresponse_get = Mock()
    mockresponse_get.status_code = "status_code"
    mockresponse_get.json = lambda: {"get": "get"}
    mock_get.return_value = mockresponse_get
    mockresponse_post = Mock()
    mockresponse_post.status_code = "status_code"
    mockresponse_post.json = lambda: {"post": "post"}
    mock_post.return_value = mockresponse_post
    mockresponse_put = Mock()
    mockresponse_put.status_code = "status_code"
    mockresponse_put.json = lambda: {"put": "put"}
    mock_put.return_value = mockresponse_put
    assert ("status_code", {"put": "put"}) == request_operation(
        logger=logger, url="foo", method="put"
    )
    assert not mock_get.called
    assert not mock_post.called
    assert mock_put.called


@patch("acme2certifier.acme_srv.helpers.network.requests.put")
@patch("acme2certifier.acme_srv.helpers.network.requests.post")
@patch("acme2certifier.acme_srv.helpers.network.requests.get")
def test_466_request_operation(
    mock_get: MagicMock,
    mock_post: MagicMock,
    mock_put: MagicMock,
    logger: logging.Logger,
) -> None:
    """test request_operation()"""
    mockresponse_get = Mock()
    mockresponse_get.status_code = "status_code"
    mockresponse_get.json = "string"
    mock_get.return_value = mockresponse_get
    assert ("status_code", "'str' object is not callable") == request_operation(
        logger=logger, url="foo", method="get"
    )
    assert mock_get.called
    assert not mock_post.called
    assert not mock_put.called


@patch("acme2certifier.acme_srv.helpers.network.requests.put")
@patch("acme2certifier.acme_srv.helpers.network.requests.post")
@patch("acme2certifier.acme_srv.helpers.network.requests.get")
def test_467_request_operation(
    mock_get: MagicMock,
    mock_post: MagicMock,
    mock_put: MagicMock,
    logger: logging.Logger,
) -> None:
    """test request_operation()"""
    mockresponse_get = Mock()
    mockresponse_get.status_code = "status_code"
    mockresponse_get.json = "string"
    mockresponse_get.text = None
    mock_get.return_value = mockresponse_get
    assert ("status_code", None) == request_operation(
        logger=logger, url="foo", method="get"
    )
    assert mock_get.called
    assert not mock_post.called
    assert not mock_put.called


@patch("acme2certifier.acme_srv.helpers.network.requests.put")
@patch("acme2certifier.acme_srv.helpers.network.requests.post")
@patch("acme2certifier.acme_srv.helpers.network.requests.get")
def test_468_request_operation(
    mock_get: MagicMock,
    mock_post: MagicMock,
    mock_put: MagicMock,
    logger: logging.Logger,
    capture_logs: Callable[..., AbstractContextManager[Any]],
) -> None:
    """test request_operation()"""
    mockresponse_get = Mock()
    mockresponse_get.status_code = "status_code"
    mockresponse_get.json = "string"
    mockresponse_get.text = None
    mock_get.return_value = mockresponse_get
    with capture_logs("test_a2c", level="INFO") as lcm:
        assert (500, "Unknown request method") == request_operation(
            logger=logger, url="foo", method="unknown"
        )
    assert "ERROR:test_a2c:Unknown request method: unknown" in lcm.output
    assert not mock_get.called
    assert not mock_post.called
    assert not mock_put.called


def test_549_fqdn_resolve_successful_a_record_no_catch_all(
    logger: logging.Logger,
) -> None:
    """Test successful A record resolution without catch_all"""
    from acme2certifier.acme_srv.helpers.network import _fqdn_resolve

    mock_resolver = Mock()
    mock_answer = [Mock(__str__=Mock(return_value="192.168.1.1"))]
    mock_resolver.resolve.return_value = mock_answer
    result, invalid, error_msg = _fqdn_resolve(
        logger, mock_resolver, "example.com", catch_all=False
    )
    assert result == "192.168.1.1"
    assert not invalid
    assert error_msg is None
    mock_resolver.resolve.assert_called_once_with("example.com", "A")


def test_550_fqdn_resolve_successful_aaaa_record_no_catch_all(
    logger: logging.Logger,
) -> None:
    """Test successful AAAA record resolution when A record fails"""
    from acme2certifier.acme_srv.helpers.network import _fqdn_resolve

    mock_resolver = Mock()
    mock_aaaa_answer = [Mock(__str__=Mock(return_value="2001:db8::1"))]
    mock_resolver.resolve.side_effect = [dns.resolver.NXDOMAIN(), mock_aaaa_answer]
    result, invalid, error_msg = _fqdn_resolve(
        logger, mock_resolver, "example.com", catch_all=False
    )
    assert result == "2001:db8::1"
    assert not invalid
    assert error_msg is None


def test_551_fqdn_resolve_successful_catch_all_both_records(
    logger: logging.Logger,
) -> None:
    """Test successful resolution with catch_all returning both A and AAAA"""
    from acme2certifier.acme_srv.helpers.network import _fqdn_resolve

    mock_resolver = Mock()
    mock_a_answer = [
        Mock(__str__=Mock(return_value="192.168.1.1")),
        Mock(__str__=Mock(return_value="192.168.1.2")),
    ]
    mock_aaaa_answer = [Mock(__str__=Mock(return_value="2001:db8::1"))]
    mock_resolver.resolve.side_effect = [mock_a_answer, mock_aaaa_answer]
    result, invalid, error_msg = _fqdn_resolve(
        logger, mock_resolver, "example.com", catch_all=True
    )
    assert result == ["192.168.1.1", "192.168.1.2", "2001:db8::1"]
    assert not invalid
    assert error_msg is None


def test_552_fqdn_resolve_nxdomain_error(logger: logging.Logger) -> None:
    """Test NXDOMAIN error handling"""
    from acme2certifier.acme_srv.helpers.network import _fqdn_resolve

    mock_resolver = Mock()
    mock_resolver.resolve.side_effect = dns.resolver.NXDOMAIN()
    result, invalid, error_msg = _fqdn_resolve(
        logger, mock_resolver, "nonexistent.com", catch_all=False
    )
    expected_result = None
    assert result == expected_result
    assert invalid
    assert "NXDOMAIN: nonexistent.com does not exist" in error_msg


def test_553_fqdn_resolve_no_answer_error(logger: logging.Logger) -> None:
    """Test NoAnswer error handling"""
    from acme2certifier.acme_srv.helpers.network import _fqdn_resolve

    mock_resolver = Mock()
    mock_resolver.resolve.side_effect = dns.resolver.NoAnswer()
    result, invalid, error_msg = _fqdn_resolve(
        logger, mock_resolver, "example.com", catch_all=False
    )
    expected_result = None
    assert result == expected_result
    assert invalid
    assert "No A record found for example.com" in error_msg


def test_554_fqdn_resolve_timeout_error(logger: logging.Logger) -> None:
    """Test timeout error handling"""
    from acme2certifier.acme_srv.helpers.network import _fqdn_resolve

    mock_resolver = Mock()
    mock_resolver.resolve.side_effect = dns.resolver.Timeout()
    result, invalid, error_msg = _fqdn_resolve(
        logger, mock_resolver, "example.com", catch_all=False
    )
    expected_result = None
    assert result == expected_result
    assert invalid
    assert "DNS query timeout for example.com" in error_msg


def test_555_fqdn_resolve_generic_error(logger: logging.Logger) -> None:
    """Test generic exception handling"""
    from acme2certifier.acme_srv.helpers.network import _fqdn_resolve

    mock_resolver = Mock()
    mock_resolver.resolve.side_effect = Exception("Connection refused")
    result, invalid, error_msg = _fqdn_resolve(
        logger, mock_resolver, "example.com", catch_all=False
    )
    expected_result = None
    assert result == expected_result
    assert invalid
    assert "DNS resolution error: Connection refused" in error_msg


def test_556_fqdn_resolve_mixed_errors_catch_all(logger: logging.Logger) -> None:
    """Test mixed errors across record types with catch_all"""
    from acme2certifier.acme_srv.helpers.network import _fqdn_resolve

    mock_resolver = Mock()
    mock_resolver.resolve.side_effect = [
        dns.resolver.NXDOMAIN(),
        dns.resolver.Timeout(),
    ]
    result, invalid, error_msg = _fqdn_resolve(
        logger, mock_resolver, "example.com", catch_all=True
    )
    expected_result = []
    assert result == expected_result
    assert invalid
    assert "A: NXDOMAIN: example.com does not exist" in error_msg
    assert "AAAA: DNS query timeout for example.com" in error_msg


def test_557_fqdn_resolve_empty_answers_no_catch_all(logger: logging.Logger) -> None:
    """Test empty answers without catch_all"""
    from acme2certifier.acme_srv.helpers.network import _fqdn_resolve

    mock_resolver = Mock()
    mock_answer = []
    mock_resolver.resolve.return_value = mock_answer
    result, invalid, error_msg = _fqdn_resolve(
        logger, mock_resolver, "example.com", catch_all=False
    )
    expected_result = None
    assert result == expected_result
    assert invalid
    assert error_msg is None


def test_558_fqdn_resolve_empty_answers_catch_all(logger: logging.Logger) -> None:
    """Test empty answers with catch_all"""
    from acme2certifier.acme_srv.helpers.network import _fqdn_resolve

    mock_resolver = Mock()
    mock_answer = []
    mock_resolver.resolve.return_value = mock_answer
    result, invalid, error_msg = _fqdn_resolve(
        logger, mock_resolver, "example.com", catch_all=True
    )
    expected_result = []
    assert result == expected_result
    assert invalid
    assert error_msg is None


def test_559_fqdn_resolve_partial_success_catch_all(logger: logging.Logger) -> None:
    """Test partial success with catch_all (A succeeds, AAAA fails)"""
    from acme2certifier.acme_srv.helpers.network import _fqdn_resolve

    mock_resolver = Mock()
    mock_a_answer = [Mock(__str__=Mock(return_value="192.168.1.1"))]
    mock_resolver.resolve.side_effect = [mock_a_answer, dns.resolver.NoAnswer()]
    result, invalid, error_msg = _fqdn_resolve(
        logger, mock_resolver, "example.com", catch_all=True
    )
    assert result == ["192.168.1.1"]
    assert not invalid
    assert error_msg is None


def test_560_fqdn_resolve_multiple_a_records_no_catch_all(
    logger: logging.Logger,
) -> None:
    """Test multiple A records without catch_all (should return first)"""
    from acme2certifier.acme_srv.helpers.network import _fqdn_resolve

    mock_resolver = Mock()
    mock_answer = [
        Mock(__str__=Mock(return_value="192.168.1.1")),
        Mock(__str__=Mock(return_value="192.168.1.2")),
        Mock(__str__=Mock(return_value="192.168.1.3")),
    ]
    mock_resolver.resolve.return_value = mock_answer
    result, invalid, error_msg = _fqdn_resolve(
        logger, mock_resolver, "example.com", catch_all=False
    )
    assert result == "192.168.1.1"
    assert not invalid
    assert error_msg is None
    mock_resolver.resolve.assert_called_once_with("example.com", "A")


def test_561_fqdn_resolve_a_fails_aaaa_succeeds_no_catch_all(
    logger: logging.Logger,
) -> None:
    """Test A record failure but AAAA success without catch_all"""
    from acme2certifier.acme_srv.helpers.network import _fqdn_resolve

    mock_resolver = Mock()
    mock_aaaa_answer = [Mock(__str__=Mock(return_value="2001:db8::1"))]
    mock_resolver.resolve.side_effect = [dns.resolver.NoAnswer(), mock_aaaa_answer]
    result, invalid, error_msg = _fqdn_resolve(
        logger, mock_resolver, "example.com", catch_all=False
    )
    assert result == "2001:db8::1"
    assert not invalid
    assert error_msg is None


def test_562_fqdn_resolve_logging_verification(
    logger: logging.Logger, capture_logs: Callable[..., AbstractContextManager[Any]]
) -> None:
    """Test that appropriate logging occurs"""
    from acme2certifier.acme_srv.helpers.network import _fqdn_resolve

    mock_resolver = Mock()
    mock_answer = [Mock(__str__=Mock(return_value="192.168.1.1"))]
    mock_resolver.resolve.return_value = mock_answer
    with capture_logs(logger, level="DEBUG") as log_context:
        result, invalid, error_msg = _fqdn_resolve(
            logger, mock_resolver, "example.com", catch_all=False
        )
    assert result == "192.168.1.1"
    assert not invalid
    assert error_msg is None
    assert any(
        (
            "Helper._fqdn_resolve(example.com:False)" in record.message
            for record in log_context.records
        )
    )
    assert any(
        (
            "Helper._fqdn_resolve() got answer:" in record.message
            for record in log_context.records
        )
    )
    assert any(
        (
            "Helper._fqdn_resolve(example.com) ended with:" in record.message
            for record in log_context.records
        )
    )


def test_563_ptr_resolve_successful_resolution(logger: logging.Logger) -> None:
    """Test successful PTR record resolution"""
    from acme2certifier.acme_srv.helpers.network import ptr_resolve

    with patch("dns.resolver.Resolver") as mock_resolver_class:
        mock_resolver = Mock()
        mock_resolver_class.return_value = mock_resolver
        mock_ptr_answer = [Mock(__str__=Mock(return_value="example.com."))]
        mock_resolver.resolve.return_value = mock_ptr_answer
        with patch("dns.reversename.from_address") as mock_reverse:
            mock_reverse.return_value = "reversed_ip"
            result, invalid = ptr_resolve(logger, "192.168.1.1")
            assert result == "example.com"
            assert not invalid
            mock_reverse.assert_called_once_with("192.168.1.1")
            mock_resolver.resolve.assert_called_once_with("reversed_ip", "PTR")


def test_564_ptr_resolve_successful_with_dns_servers(logger: logging.Logger) -> None:
    """Test successful PTR resolution with custom DNS servers"""
    from acme2certifier.acme_srv.helpers.network import ptr_resolve

    with patch("dns.resolver.Resolver") as mock_resolver_class:
        mock_resolver = Mock()
        mock_resolver_class.return_value = mock_resolver
        mock_ptr_answer = [Mock(__str__=Mock(return_value="mail.example.com."))]
        mock_resolver.resolve.return_value = mock_ptr_answer
        with patch("dns.reversename.from_address") as mock_reverse:
            mock_reverse.return_value = "reversed_ip"
            dns_servers = ["8.8.8.8", "1.1.1.1"]
            result, invalid = ptr_resolve(logger, "203.0.113.5", dns_servers)
            assert result == "mail.example.com"
            assert not invalid
            assert mock_resolver.nameservers == dns_servers


def test_565_ptr_resolve_exception_handling(logger: logging.Logger) -> None:
    """Test PTR resolution exception handling"""
    from acme2certifier.acme_srv.helpers.network import ptr_resolve

    with patch("dns.resolver.Resolver") as mock_resolver_class:
        mock_resolver = Mock()
        mock_resolver_class.return_value = mock_resolver
        mock_resolver.resolve.side_effect = Exception("DNS resolution failed")
        with patch("dns.reversename.from_address") as mock_reverse:
            mock_reverse.return_value = "reversed_ip"
            result, invalid = ptr_resolve(logger, "invalid.ip")
            assert result is None
            assert invalid


def test_566_ptr_resolve_nxdomain_error(logger: logging.Logger) -> None:
    """Test PTR resolution with NXDOMAIN error"""
    from acme2certifier.acme_srv.helpers.network import ptr_resolve

    with patch("dns.resolver.Resolver") as mock_resolver_class:
        mock_resolver = Mock()
        mock_resolver_class.return_value = mock_resolver
        mock_resolver.resolve.side_effect = dns.resolver.NXDOMAIN()
        with patch("dns.reversename.from_address") as mock_reverse:
            mock_reverse.return_value = "reversed_ip"
            result, invalid = ptr_resolve(logger, "10.0.0.1")
            assert result is None
            assert invalid


def test_567_ptr_resolve_timeout_error(logger: logging.Logger) -> None:
    """Test PTR resolution with timeout error"""
    from acme2certifier.acme_srv.helpers.network import ptr_resolve

    with patch("dns.resolver.Resolver") as mock_resolver_class:
        mock_resolver = Mock()
        mock_resolver_class.return_value = mock_resolver
        mock_resolver.resolve.side_effect = dns.resolver.Timeout()
        with patch("dns.reversename.from_address") as mock_reverse:
            mock_reverse.return_value = "reversed_ip"
            result, invalid = ptr_resolve(logger, "172.16.0.1")
            assert result is None
            assert invalid


def test_568_ptr_resolve_invalid_address_format(logger: logging.Logger) -> None:
    """Test PTR resolution with invalid IP address format"""
    from acme2certifier.acme_srv.helpers.network import ptr_resolve

    with patch("dns.resolver.Resolver") as mock_resolver_class:
        mock_resolver = Mock()
        mock_resolver_class.return_value = mock_resolver
        with patch("dns.reversename.from_address") as mock_reverse:
            mock_reverse.side_effect = Exception("Invalid IP address format")
            result, invalid = ptr_resolve(logger, "not.an.ip.address")
            assert result is None
            assert invalid


def test_569_ptr_resolve_empty_response(logger: logging.Logger) -> None:
    """Test PTR resolution with empty response"""
    from acme2certifier.acme_srv.helpers.network import ptr_resolve

    with patch("dns.resolver.Resolver") as mock_resolver_class:
        mock_resolver = Mock()
        mock_resolver_class.return_value = mock_resolver
        mock_resolver.resolve.side_effect = IndexError("list index out of range")
        with patch("dns.reversename.from_address") as mock_reverse:
            mock_reverse.return_value = "reversed_ip"
            result, invalid = ptr_resolve(logger, "198.51.100.1")
            assert result is None
            assert invalid


def test_570_ptr_resolve_logging_verification(
    logger: logging.Logger, capture_logs: Callable[..., AbstractContextManager[Any]]
) -> None:
    """Test PTR resolution logging behavior"""
    from acme2certifier.acme_srv.helpers.network import ptr_resolve

    with patch("dns.resolver.Resolver") as mock_resolver_class:
        mock_resolver = Mock()
        mock_resolver_class.return_value = mock_resolver
        mock_ptr_answer = [Mock(__str__=Mock(return_value="test.example.org."))]
        mock_resolver.resolve.return_value = mock_ptr_answer
        with patch("dns.reversename.from_address") as mock_reverse:
            mock_reverse.return_value = "reversed_ip"
            with capture_logs(logger, level="DEBUG") as log_context:
                result, invalid = ptr_resolve(logger, "93.184.216.34")
            assert result == "test.example.org"
            assert not invalid
            assert any(
                (
                    "Helper.ptr_resolve(93.184.216.34)" in record.message
                    for record in log_context.records
                )
            )
            assert any(
                (
                    "Helper.ptr_resolve(93.184.216.34) ended with:" in record.message
                    for record in log_context.records
                )
            )


def test_571_ptr_resolve_error_logging_verification(
    logger: logging.Logger, capture_logs: Callable[..., AbstractContextManager[Any]]
) -> None:
    """Test PTR resolution error logging behavior"""
    from acme2certifier.acme_srv.helpers.network import ptr_resolve

    with patch("dns.resolver.Resolver") as mock_resolver_class:
        mock_resolver = Mock()
        mock_resolver_class.return_value = mock_resolver
        mock_resolver.resolve.side_effect = Exception("Connection timeout")
        with patch("dns.reversename.from_address") as mock_reverse:
            mock_reverse.return_value = "reversed_ip"
            with capture_logs(logger, level="DEBUG") as log_context:
                result, invalid = ptr_resolve(logger, "127.0.0.1")
            assert result is None
            assert invalid
            assert any(
                (
                    "Error while resolving 127.0.0.1: Connection timeout"
                    in record.message
                    for record in log_context.records
                )
            )


def test_572_ptr_resolve_ipv6_address(logger: logging.Logger) -> None:
    """Test PTR resolution with IPv6 address"""
    from acme2certifier.acme_srv.helpers.network import ptr_resolve

    with patch("dns.resolver.Resolver") as mock_resolver_class:
        mock_resolver = Mock()
        mock_resolver_class.return_value = mock_resolver
        mock_ptr_answer = [Mock(__str__=Mock(return_value="ipv6.example.com."))]
        mock_resolver.resolve.return_value = mock_ptr_answer
        with patch("dns.reversename.from_address") as mock_reverse:
            mock_reverse.return_value = "ipv6_reversed"
            result, invalid = ptr_resolve(logger, "2001:db8::1")
            assert result == "ipv6.example.com"
            assert not invalid
            mock_reverse.assert_called_once_with("2001:db8::1")
            mock_resolver.resolve.assert_called_once_with("ipv6_reversed", "PTR")


def test_573_url_get_with_default_dns_successful_200(logger: logging.Logger) -> None:
    """Test successful HTTP request with 200 status code"""
    from acme2certifier.acme_srv.helpers.network import url_get_with_default_dns

    with patch("acme2certifier.acme_srv.helpers.network.v6_adjust") as mock_v6_adjust:
        mock_v6_adjust.return_value = ({"User-Agent": "test"}, "http://example.com")
        with patch("requests.get") as mock_get:
            mock_response = Mock()
            mock_response.text = "Success response"
            mock_response.status_code = 200
            mock_get.return_value = mock_response
            result, status_code, error_msg = url_get_with_default_dns(
                logger, "http://example.com", {}, True, 30
            )
            assert result == "Success response"
            assert status_code == 200
            assert error_msg is None
            mock_get.assert_called_once_with(
                "http://example.com",
                verify=True,
                timeout=30,
                headers={"User-Agent": "test"},
                proxies={},
            )


def test_574_url_get_with_default_dns_successful_non_200(
    logger: logging.Logger,
) -> None:
    """Test successful HTTP request with non-200 status code"""
    from acme2certifier.acme_srv.helpers.network import url_get_with_default_dns

    with patch("acme2certifier.acme_srv.helpers.network.v6_adjust") as mock_v6_adjust:
        mock_v6_adjust.return_value = ({"User-Agent": "test"}, "http://example.com")
        with patch("requests.get") as mock_get:
            mock_response = Mock()
            mock_response.text = "Not found"
            mock_response.status_code = 404
            mock_response.reason = "Not Found"
            mock_get.return_value = mock_response
            result, status_code, error_msg = url_get_with_default_dns(
                logger, "http://example.com", {}, True, 30
            )
            assert result == "Not found"
            assert status_code == 404
            assert error_msg == "http://example.com Not Found"


def test_575_url_get_with_default_dns_exception_fallback_success(
    logger: logging.Logger,
) -> None:
    """Test exception in first request triggers IPv4 fallback - success"""
    from acme2certifier.acme_srv.helpers.network import url_get_with_default_dns

    with patch("acme2certifier.acme_srv.helpers.network.v6_adjust") as mock_v6_adjust:
        mock_v6_adjust.return_value = ({"User-Agent": "test"}, "http://example.com")
        with patch("requests.get") as mock_get:
            mock_response = Mock()
            mock_response.text = "Fallback success"
            mock_response.status_code = 200
            mock_get.side_effect = [Exception("Initial request failed"), mock_response]
            with patch(
                "acme2certifier.acme_srv.helpers.network.urllib3_cn"
            ) as mock_urllib3:
                old_gai_family = Mock()
                mock_urllib3.allowed_gai_family = old_gai_family
                result, status_code, error_msg = url_get_with_default_dns(
                    logger, "http://example.com", {"http": "proxy:8080"}, True, 30
                )
                assert result == "Fallback success"
                assert status_code == 200
                assert error_msg is None
                assert mock_get.call_count == 2
                assert mock_urllib3.allowed_gai_family == old_gai_family


def test_576_url_get_with_default_dns_fallback_read_timeout(
    logger: logging.Logger,
) -> None:
    """Test ReadTimeout exception in IPv4 fallback"""
    from acme2certifier.acme_srv.helpers.network import url_get_with_default_dns

    with patch("acme2certifier.acme_srv.helpers.network.v6_adjust") as mock_v6_adjust:
        mock_v6_adjust.return_value = ({"User-Agent": "test"}, "http://example.com")
        with patch("requests.get") as mock_get:
            mock_get.side_effect = [
                Exception("Initial request failed"),
                requests.exceptions.ReadTimeout("Read timeout"),
            ]
            with patch(
                "acme2certifier.acme_srv.helpers.network.urllib3_cn"
            ) as mock_urllib3:
                old_gai_family = Mock()
                mock_urllib3.allowed_gai_family = old_gai_family
                result, status_code, error_msg = url_get_with_default_dns(
                    logger, "http://example.com", {}, False, 10
                )
                assert result is None
                assert status_code == 500
                assert (
                    error_msg
                    == "Could not fetch URL: http://example.com - Read timeout."
                )
                assert mock_urllib3.allowed_gai_family == old_gai_family


def test_577_url_get_with_default_dns_fallback_connection_error(
    logger: logging.Logger,
) -> None:
    """Test ConnectionError exception in IPv4 fallback"""
    from acme2certifier.acme_srv.helpers.network import url_get_with_default_dns

    with patch("acme2certifier.acme_srv.helpers.network.v6_adjust") as mock_v6_adjust:
        mock_v6_adjust.return_value = ({"User-Agent": "test"}, "http://example.com")
        with patch("requests.get") as mock_get:
            mock_get.side_effect = [
                Exception("Initial request failed"),
                requests.exceptions.ConnectionError("Connection failed"),
            ]
            with patch(
                "acme2certifier.acme_srv.helpers.network.urllib3_cn"
            ) as mock_urllib3:
                old_gai_family = Mock()
                mock_urllib3.allowed_gai_family = old_gai_family
                result, status_code, error_msg = url_get_with_default_dns(
                    logger, "http://example.com", {}, True, 20
                )
                assert result is None
                assert status_code == 500
                assert (
                    error_msg
                    == "Could not fetch URL: http://example.com - Connection error."
                )
                assert mock_urllib3.allowed_gai_family == old_gai_family


def test_578_url_get_with_default_dns_fallback_generic_exception(
    logger: logging.Logger,
) -> None:
    """Test generic exception in IPv4 fallback"""
    from acme2certifier.acme_srv.helpers.network import url_get_with_default_dns

    with patch("acme2certifier.acme_srv.helpers.network.v6_adjust") as mock_v6_adjust:
        mock_v6_adjust.return_value = ({"User-Agent": "test"}, "http://example.com")
        with patch("requests.get") as mock_get:
            mock_get.side_effect = [
                Exception("Initial request failed"),
                RuntimeError("Unexpected error"),
            ]
            with patch(
                "acme2certifier.acme_srv.helpers.network.urllib3_cn"
            ) as mock_urllib3:
                old_gai_family = Mock()
                mock_urllib3.allowed_gai_family = old_gai_family
                result, status_code, error_msg = url_get_with_default_dns(
                    logger, "http://example.com", {}, True, 15
                )
                assert result is None
                assert status_code == 500
                assert error_msg == "Could not fetch URL: http://example.com"
                assert mock_urllib3.allowed_gai_family == old_gai_family


def test_579_url_get_with_default_dns_fallback_non_200(logger: logging.Logger) -> None:
    """Test non-200 status in IPv4 fallback"""
    from acme2certifier.acme_srv.helpers.network import url_get_with_default_dns

    with patch("acme2certifier.acme_srv.helpers.network.v6_adjust") as mock_v6_adjust:
        mock_v6_adjust.return_value = ({"User-Agent": "test"}, "http://example.com")
        with patch("requests.get") as mock_get:
            mock_response = Mock()
            mock_response.text = "Server Error"
            mock_response.status_code = 500
            mock_response.reason = "Internal Server Error"
            mock_get.side_effect = [Exception("Initial request failed"), mock_response]
            with patch(
                "acme2certifier.acme_srv.helpers.network.urllib3_cn"
            ) as mock_urllib3:
                old_gai_family = Mock()
                mock_urllib3.allowed_gai_family = old_gai_family
                result, status_code, error_msg = url_get_with_default_dns(
                    logger, "http://example.com", {}, True, 25
                )
                assert result == "Server Error"
                assert status_code == 500
                assert error_msg == "http://example.com Internal Server Error"
                assert mock_urllib3.allowed_gai_family == old_gai_family


def test_580_url_get_with_default_dns_with_proxy_config(logger: logging.Logger) -> None:
    """Test request with proxy configuration"""
    from acme2certifier.acme_srv.helpers.network import url_get_with_default_dns

    with patch("acme2certifier.acme_srv.helpers.network.v6_adjust") as mock_v6_adjust:
        mock_v6_adjust.return_value = ({"User-Agent": "test"}, "http://example.com")
        with patch("requests.get") as mock_get:
            mock_response = Mock()
            mock_response.text = "Proxy response"
            mock_response.status_code = 200
            mock_get.return_value = mock_response
            proxy_config = {
                "http": "proxy.example.com:8080",
                "https": "proxy.example.com:8080",
            }
            result, status_code, error_msg = url_get_with_default_dns(
                logger, "http://example.com", proxy_config, False, 30
            )
            assert result == "Proxy response"
            assert status_code == 200
            assert error_msg is None
            mock_get.assert_called_once_with(
                "http://example.com",
                verify=False,
                timeout=30,
                headers={"User-Agent": "test"},
                proxies=proxy_config,
            )


def test_581_url_get_with_default_dns_logging_verification(
    logger: logging.Logger, capture_logs: Callable[..., AbstractContextManager[Any]]
) -> None:
    """Test logging behavior in url_get_with_default_dns"""
    from acme2certifier.acme_srv.helpers.network import url_get_with_default_dns

    with patch("acme2certifier.acme_srv.helpers.network.v6_adjust") as mock_v6_adjust:
        mock_v6_adjust.return_value = ({"User-Agent": "test"}, "http://example.com")
        with patch("requests.get") as mock_get:
            mock_get.side_effect = [
                Exception("Initial request failed"),
                requests.exceptions.ReadTimeout("Read timeout"),
            ]
            with patch("acme2certifier.acme_srv.helpers.network.urllib3_cn"):
                with capture_logs(logger, level="DEBUG") as log_context:
                    result, status_code, error_msg = url_get_with_default_dns(
                        logger, "http://example.com", {}, True, 20
                    )
                assert result is None
                assert status_code == 500
                assert any(
                    (
                        "Helper.url_get_with_default_dns(http://example.com) vrf=True, timout:20"
                        in record.message
                        for record in log_context.records
                    )
                )
                assert any(
                    (
                        "Helper.url_get_with_default_dns(Initial request failed): error"
                        in record.message
                        for record in log_context.records
                    )
                )
                assert any(
                    (
                        "Helper.url_get_with_default_dns(http://example.com): fallback to v4"
                        in record.message
                        for record in log_context.records
                    )
                )
                assert any(
                    (
                        "Helper.url_get_with_default_dns(http://example.com): read timeout"
                        in record.message
                        for record in log_context.records
                    )
                )


def test_582_allowed_gai_family() -> None:
    """Test allowed_gai_family function returns IPv4"""
    from acme2certifier.acme_srv.helpers.network import allowed_gai_family
    import socket

    result = allowed_gai_family()
    assert result == socket.AF_INET


def test_629_normalize_resolved_ips() -> None:
    """normalize_resolved_ips handles str/list/None"""
    from acme2certifier.acme_srv.helpers.network import normalize_resolved_ips

    assert [] == normalize_resolved_ips(None)
    assert [] == normalize_resolved_ips("")
    assert ["1.2.3.4"] == normalize_resolved_ips("1.2.3.4")
    assert ["1.2.3.4", "2001:db8::1"] == normalize_resolved_ips(
        ["1.2.3.4", "2001:db8::1", ""]
    )


def test_630_filter_http01_target_ips_permissive(logger: logging.Logger) -> None:
    """Default filter keeps private and public addresses"""
    from acme2certifier.acme_srv.helpers.network import filter_http01_target_ips

    allowed, err = filter_http01_target_ips(
        logger, ["10.0.0.1", "127.0.0.1", "8.8.8.8", "not-an-ip"], block_private=False
    )
    assert err is None
    assert ["10.0.0.1", "127.0.0.1", "8.8.8.8"] == allowed


def test_631_filter_http01_target_ips_strict(logger: logging.Logger) -> None:
    """Strict filter keeps only global addresses and prefers IPv4"""
    from acme2certifier.acme_srv.helpers.network import filter_http01_target_ips

    allowed, err = filter_http01_target_ips(
        logger,
        [
            "10.0.0.1",
            "169.254.169.254",
            "127.0.0.1",
            "2001:db8::1",
            "2606:4700:4700::1111",
            "8.8.8.8",
        ],
        block_private=True,
    )
    assert err is None
    assert ["8.8.8.8", "2606:4700:4700::1111"] == allowed
    allowed, err = filter_http01_target_ips(
        logger, ["10.0.0.1", "127.0.0.1"], block_private=True
    )
    assert [] == allowed
    assert "No allowed address for HTTP-01 validation" == err


@patch("acme2certifier.acme_srv.helpers.network.requests.get")
def test_632_url_get_dns_pinned_success(
    mock_get: MagicMock, logger: logging.Logger
) -> None:
    """url_get_dns_pinned dials pinned IP URL with logical Host header"""
    from acme2certifier.acme_srv.helpers.network import url_get_dns_pinned

    mock_resp = Mock()
    mock_resp.text = "token.thumb"
    mock_resp.status_code = 200
    mock_resp.reason = "OK"
    mock_get.return_value = mock_resp
    result, status, err = url_get_dns_pinned(
        logger,
        host="example.com",
        path="/.well-known/acme-challenge/tok",
        pinned_ips=["8.8.8.8"],
        verify=False,
        timeout=5,
    )
    assert "token.thumb" == result
    assert 200 == status
    assert err is None
    args, kwargs = mock_get.call_args
    assert "http://8.8.8.8/.well-known/acme-challenge/tok" == args[0]
    assert "example.com" == kwargs["headers"]["Host"]
    assert {} == kwargs["proxies"]


@patch("acme2certifier.acme_srv.helpers.network.requests.get")
def test_633_url_get_dns_pinned_ipv6_host_and_peer(
    mock_get: MagicMock, logger: logging.Logger
) -> None:
    """IPv6 pin and identifier are bracketed in URL and Host"""
    from acme2certifier.acme_srv.helpers.network import url_get_dns_pinned

    mock_resp = Mock()
    mock_resp.text = "ok"
    mock_resp.status_code = 200
    mock_resp.reason = "OK"
    mock_get.return_value = mock_resp
    url_get_dns_pinned(
        logger, host="example.com", path="/path", pinned_ips=["2606:4700:4700::1111"]
    )
    args, kwargs = mock_get.call_args
    assert "http://[2606:4700:4700::1111]/path" == args[0]
    assert "example.com" == kwargs["headers"]["Host"]
    url_get_dns_pinned(
        logger,
        host="2606:4700:4700::1111",
        path="/path",
        pinned_ips=["2606:4700:4700::1111"],
    )
    args, kwargs = mock_get.call_args
    assert "http://[2606:4700:4700::1111]/path" == args[0]
    assert "[2606:4700:4700::1111]" == kwargs["headers"]["Host"]


def test_699_proxy_url_for_log_userinfo_without_scheme() -> None:
    """userinfo is stripped when a proxy string has no scheme"""
    from acme2certifier.acme_srv.helpers.network import proxy_url_for_log

    assert (
        proxy_url_for_log("alice:s3cret@proxy.example:8080") == "***@proxy.example:8080"
    )
    assert proxy_url_for_log(None) is None
