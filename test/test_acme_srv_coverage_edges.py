#!/usr/bin/python
# -*- coding: utf-8 -*-
"""Coverage-focused edge case tests for acme_srv helpers."""

import configparser
import logging
import unittest
from unittest.mock import Mock, patch

import requests

from acme2certifier.acme_srv.helpers.network import (
    _caaidentities_parse,
    configured_server_name_get,
    request_operation,
    server_name_allowed_host,
    url_get_dns_pinned,
)


class TestAcmeSrvCoverageEdges(unittest.TestCase):
    """Edge cases for network helper coverage."""

    def setUp(self) -> None:
        logging.basicConfig(level=logging.CRITICAL)
        self.logger = logging.getLogger("test_a2c_coverage_edges")

    def test_001_network_caaidentities_parse_empty_and_fallback_csv(self) -> None:
        """parse empty caaidentities and comma-separated fallback"""
        self.assertEqual(_caaidentities_parse(self.logger, ""), [])
        self.assertEqual(
            _caaidentities_parse(self.logger, "not-json,still-valid"),
            ["not-json", "still-valid"],
        )

    def test_002_network_configured_server_name_directory_fallback(self) -> None:
        """configured_server_name_get falls back to Directory section"""
        parser = configparser.ConfigParser()
        parser["Directory"] = {"server_name": "directory.example"}
        self.assertEqual(configured_server_name_get(parser), "directory.example")

    def test_003_network_server_name_allowed_host(self) -> None:
        """server_name_allowed_host normalizes FQDN and URL-shaped values"""
        self.assertIsNone(server_name_allowed_host(""))
        self.assertIsNone(server_name_allowed_host("  "))
        self.assertEqual(
            server_name_allowed_host("acme.example.com"), "acme.example.com"
        )
        self.assertEqual(
            server_name_allowed_host("https://acme.example.com:8443"),
            "acme.example.com:8443",
        )
        self.assertEqual(
            server_name_allowed_host("acme.example.com/acme/directory"),
            "acme.example.com",
        )

    @patch("acme2certifier.acme_srv.helpers.network.requests.get")
    def test_004_url_get_dns_pinned_invalid_ip_then_non_200_and_path_normalization(
        self, mock_get: Mock
    ) -> None:
        """url_get_dns_pinned skips bad IP and normalizes token path"""
        response = Mock()
        response.text = "body"
        response.status_code = 404
        response.reason = "Not Found"
        mock_get.return_value = response

        body, code, error = url_get_dns_pinned(
            self.logger,
            "example.org",
            "token-path",
            ["bad-ip", "203.0.113.10"],
            verify=False,
        )

        self.assertEqual(body, "body")
        self.assertEqual(code, 404)
        self.assertEqual(error, "http://example.org/token-path Not Found")
        self.assertEqual(mock_get.call_args.args[0], "http://example.org/token-path")

    @patch("acme2certifier.acme_srv.helpers.network.requests.get")
    def test_005_url_get_dns_pinned_read_timeout_returns_last_error(
        self, mock_get: Mock
    ) -> None:
        """url_get_dns_pinned returns last error on read timeout"""
        mock_get.side_effect = requests.exceptions.ReadTimeout()
        body, code, error = url_get_dns_pinned(
            self.logger, "example.org", "/token", ["203.0.113.11"], verify=False
        )
        self.assertIsNone(body)
        self.assertEqual(code, 500)
        self.assertIn("Read timeout", str(error))

    @patch("acme2certifier.acme_srv.helpers.network.requests.get")
    def test_006_url_get_dns_pinned_connection_and_generic_exception_paths(
        self, mock_get: Mock
    ) -> None:
        """url_get_dns_pinned surfaces connection and generic errors"""
        mock_get.side_effect = [
            requests.exceptions.ConnectionError(),
            RuntimeError("generic failure"),
        ]
        body, code, error = url_get_dns_pinned(
            self.logger,
            "example.org",
            "/token",
            ["203.0.113.12", "203.0.113.13"],
            verify=False,
        )
        self.assertIsNone(body)
        self.assertEqual(code, 500)
        self.assertIn("generic failure", str(error))

    def test_007_request_operation_retries_retryable_status_then_success(self) -> None:
        """request_operation retries retryable HTTP status then succeeds"""
        response_500 = Mock(status_code=500, text="")
        response_200 = Mock(status_code=200, text="ok")
        response_200.json.return_value = {"ok": True}
        session = Mock(get=Mock(side_effect=[response_500, response_200]))

        with patch("acme2certifier.acme_srv.helpers.network.time.sleep") as mock_sleep:
            code, content = request_operation(
                self.logger,
                session=session,
                url="http://example.org",
                method="GET",
                retries=1,
                retry_backoff=0.5,
            )

        self.assertEqual(code, 200)
        self.assertEqual(content, {"ok": True})
        mock_sleep.assert_called_once_with(0.5)

    def test_008_request_operation_retries_exception_then_success(self) -> None:
        """request_operation retries after exception then succeeds"""
        response_200 = Mock(status_code=200, text="")
        session = Mock(get=Mock(side_effect=[RuntimeError("boom"), response_200]))

        with patch("acme2certifier.acme_srv.helpers.network.time.sleep") as mock_sleep:
            code, content = request_operation(
                self.logger,
                session=session,
                url="http://example.org",
                method="GET",
                retries=1,
                retry_backoff=0.25,
            )

        self.assertEqual(code, 200)
        self.assertIsNone(content)
        mock_sleep.assert_called_once_with(0.25)

    def test_009_request_operation_unexpected_retry_loop_exit_guard(self) -> None:
        """request_operation guard when retry loop exits unexpectedly"""
        session = Mock(get=Mock())
        with patch("builtins.range", return_value=[]):
            self.assertEqual(
                request_operation(self.logger, session=session),
                (500, "Unexpected retry loop exit"),
            )


if __name__ == "__main__":
    unittest.main()
