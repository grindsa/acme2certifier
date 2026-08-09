"""Coverage-focused edge case tests for acme_srv helpers."""

from __future__ import annotations

import configparser
import logging
from unittest.mock import Mock, patch

import requests

from acme2certifier.acme_srv.helpers.network import (
    _caaidentities_parse,
    configured_server_name_get,
    request_operation,
    url_get_dns_pinned,
)


def _logger() -> logging.Logger:
    return logging.getLogger("test_a2c_coverage_edges")


def test_001_network_caaidentities_parse_empty_and_fallback_csv() -> None:
    assert _caaidentities_parse("") == []
    assert _caaidentities_parse("not-json,still-valid") == ["not-json", "still-valid"]


def test_002_network_configured_server_name_directory_fallback() -> None:
    parser = configparser.ConfigParser()
    parser["Directory"] = {"server_name": "directory.example"}
    assert configured_server_name_get(parser) == "directory.example"


@patch("acme2certifier.acme_srv.helpers.network.requests.get")
def test_003_url_get_dns_pinned_invalid_ip_then_non_200_and_path_normalization(
    mock_get: Mock,
) -> None:
    response = Mock()
    response.text = "body"
    response.status_code = 404
    response.reason = "Not Found"
    mock_get.return_value = response

    body, code, error = url_get_dns_pinned(
        _logger(),
        "example.org",
        "token-path",
        ["bad-ip", "203.0.113.10"],
        verify=False,
    )

    assert body == "body"
    assert code == 404
    assert error == "http://example.org/token-path Not Found"
    assert mock_get.call_args.args[0] == "http://example.org/token-path"


@patch("acme2certifier.acme_srv.helpers.network.requests.get")
def test_004_url_get_dns_pinned_read_timeout_returns_last_error(mock_get: Mock) -> None:
    mock_get.side_effect = requests.exceptions.ReadTimeout()
    body, code, error = url_get_dns_pinned(
        _logger(), "example.org", "/token", ["203.0.113.11"], verify=False
    )
    assert body is None
    assert code == 500
    assert "Read timeout" in str(error)


@patch("acme2certifier.acme_srv.helpers.network.requests.get")
def test_005_url_get_dns_pinned_connection_and_generic_exception_paths(
    mock_get: Mock,
) -> None:
    mock_get.side_effect = [
        requests.exceptions.ConnectionError(),
        RuntimeError("generic failure"),
    ]
    body, code, error = url_get_dns_pinned(
        _logger(),
        "example.org",
        "/token",
        ["203.0.113.12", "203.0.113.13"],
        verify=False,
    )
    assert body is None
    assert code == 500
    assert "generic failure" in str(error)


def test_006_request_operation_retries_retryable_status_then_success() -> None:
    response_500 = Mock(status_code=500, text="")
    response_200 = Mock(status_code=200, text="ok")
    response_200.json.return_value = {"ok": True}
    session = Mock(get=Mock(side_effect=[response_500, response_200]))

    with patch("acme2certifier.acme_srv.helpers.network.time.sleep") as mock_sleep:
        code, content = request_operation(
            _logger(),
            session=session,
            url="http://example.org",
            method="GET",
            retries=1,
            retry_backoff=0.5,
        )

    assert code == 200
    assert content == {"ok": True}
    mock_sleep.assert_called_once_with(0.5)


def test_007_request_operation_retries_exception_then_success() -> None:
    response_200 = Mock(status_code=200, text="")
    session = Mock(get=Mock(side_effect=[RuntimeError("boom"), response_200]))

    with patch("acme2certifier.acme_srv.helpers.network.time.sleep") as mock_sleep:
        code, content = request_operation(
            _logger(),
            session=session,
            url="http://example.org",
            method="GET",
            retries=1,
            retry_backoff=0.25,
        )

    assert code == 200
    assert content is None
    mock_sleep.assert_called_once_with(0.25)


def test_008_request_operation_unexpected_retry_loop_exit_guard() -> None:
    session = Mock(get=Mock())
    with patch("builtins.range", return_value=[]):
        assert request_operation(_logger(), session=session) == (
            500,
            "Unexpected retry loop exit",
        )
