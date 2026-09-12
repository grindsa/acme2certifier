#!/usr/bin/python
# -*- coding: utf-8 -*-
"""Coverage-focused edge case tests for acme_srv helpers."""

import configparser
import logging
import os
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, Mock, patch

import requests

from acme2certifier.acme_srv.helpers.network import (
    _caaidentities_parse,
    ca_api_request,
    client_session_apply,
    configured_server_name_get,
    request_operation,
    server_name_allowed_host,
    url_get_dns_pinned,
)
from acme2certifier.acme_srv.helpers.config import config_ca_bundle_load


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

    def test_010_request_operation_passes_auth(self) -> None:
        """request_operation forwards HTTP auth to the session call"""
        response = Mock(status_code=200, text="")
        session = Mock(get=Mock(return_value=response))
        auth = Mock()
        code, _content = request_operation(
            self.logger,
            session=session,
            url="http://example.org",
            method="GET",
            auth=auth,
        )
        self.assertEqual(code, 200)
        session.get.assert_called_once()
        self.assertIs(session.get.call_args.kwargs["auth"], auth)

    def test_011_config_ca_bundle_load_boolean_and_path(self) -> None:
        """config_ca_bundle_load parses booleans and keeps path strings"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"ca_bundle": "False"}
        self.assertFalse(config_ca_bundle_load(self.logger, parser, current=True))
        parser["CAhandler"] = {"ca_bundle": "/etc/ssl/certs/ca.pem"}
        self.assertEqual(
            config_ca_bundle_load(self.logger, parser, current=True),
            "/etc/ssl/certs/ca.pem",
        )
        self.assertTrue(
            config_ca_bundle_load(self.logger, {"DEFAULT": {}}, current=True)
        )
        self.assertFalse(
            config_ca_bundle_load(
                self.logger, {"CAhandler": {"ca_bundle": "False"}}, current=True
            )
        )
        mock_cfg = Mock()
        mock_cfg.get.return_value = "notaboolean"
        mock_cfg.getboolean.return_value = False
        self.assertEqual(
            config_ca_bundle_load(self.logger, mock_cfg, current=True),
            "notaboolean",
        )

    def test_012_client_session_apply_pem_and_pkcs12(self) -> None:
        """client_session_apply sets PEM certs or mounts a PKCS12 adapter"""
        session = Mock()
        client_session_apply(session, pem_cert="cert.pem", pem_key="key.pem")
        self.assertEqual(session.cert, ("cert.pem", "key.pem"))

        session = Mock()
        adapter_cls = Mock(return_value="adapter")
        client_session_apply(
            session,
            pkcs12_filename="client.p12",
            pkcs12_password="secret",
            mount_url="https://ca.example",
            pkcs12_adapter_cls=adapter_cls,
        )
        adapter_cls.assert_called_once_with(
            pkcs12_filename="client.p12", pkcs12_password="secret"
        )
        session.mount.assert_called_once_with("https://ca.example", "adapter")

        session = Mock()
        adapter_cls = Mock(return_value="adapter")
        client_session_apply(
            session,
            pkcs12_filename="client.p12",
            pkcs12_password="secret",
            pkcs12_adapter_cls=adapter_cls,
        )
        adapter_cls.assert_called_once_with(
            pkcs12_filename="client.p12", pkcs12_password="secret"
        )
        session.mount.assert_called_once_with(None, "adapter")

    def test_013_ca_api_request_wraps_request_operation(self) -> None:
        """ca_api_request delegates to request_operation"""
        with patch(
            "acme2certifier.acme_srv.helpers.network.request_operation",
            return_value=(201, {"ok": True}),
        ) as mock_req:
            code, content = ca_api_request(
                self.logger, "post", "http://example.org", payload={"a": 1}
            )
        self.assertEqual((code, content), (201, {"ok": True}))
        mock_req.assert_called_once()

    def test_014_kerberos_ccache_path_and_username(self) -> None:
        """KerberosAuthMixin normalizes FILE: ccaches and principal usernames"""
        from acme2certifier.acme_srv.helpers.kerberos_auth import KerberosAuthMixin

        self.assertEqual(
            "/tmp/cc", KerberosAuthMixin._kerberos_ccache_path("FILE:/tmp/cc")
        )
        self.assertEqual("/tmp/cc", KerberosAuthMixin._kerberos_ccache_path("/tmp/cc"))
        self.assertIsNone(KerberosAuthMixin._kerberos_ccache_path(None))
        self.assertIsNone(KerberosAuthMixin._kerberos_ccache_path(""))

        mixin = KerberosAuthMixin()
        mixin.logger = self.logger
        self.assertEqual(
            "svc", mixin._kerberos_username_from_principal("svc@EXAMPLE.COM")
        )

    def test_015_acme_response_content_type(self) -> None:
        """JSON for success; problem+json for ACME error status codes"""
        from acme2certifier.acme_srv.helpers.acme_http_boot import (
            CONTENT_TYPE_JSON,
            CONTENT_TYPE_PROBLEM_JSON,
            acme_response_content_type,
        )

        self.assertEqual(CONTENT_TYPE_JSON, acme_response_content_type())
        self.assertEqual(CONTENT_TYPE_JSON, acme_response_content_type(201))
        self.assertEqual(CONTENT_TYPE_PROBLEM_JSON, acme_response_content_type(400))
        self.assertEqual(CONTENT_TYPE_JSON, acme_response_content_type("nope"))

    def test_016_configure_django_settings_module(self) -> None:
        """setdefault DJANGO_SETTINGS_MODULE and leave an existing value alone"""
        from acme2certifier.acme_srv.helpers.django_boot import (
            DEFAULT_DJANGO_SETTINGS,
            configure_django_settings_module,
        )

        with patch.dict(os.environ, {"DJANGO_SETTINGS_MODULE": "custom.settings"}):
            self.assertEqual(
                "custom.settings", configure_django_settings_module("ignored.settings")
            )
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("DJANGO_SETTINGS_MODULE", None)
            self.assertEqual(
                DEFAULT_DJANGO_SETTINGS, configure_django_settings_module()
            )

    def test_017_prepend_sys_path_if_dir(self) -> None:
        """prepend an existing directory once; skip missing and duplicate paths"""
        from acme2certifier.acme_srv.helpers.django_boot import prepend_sys_path_if_dir

        prepend_sys_path_if_dir(None)
        prepend_sys_path_if_dir("/nonexistent/a2c/django-boot-xyz")
        self.assertNotIn("/nonexistent/a2c/django-boot-xyz", sys.path)
        with tempfile.TemporaryDirectory() as tmp:
            saved = list(sys.path)
            try:
                if tmp in sys.path:
                    sys.path.remove(tmp)
                prepend_sys_path_if_dir(tmp)
                self.assertEqual(tmp, sys.path[0])
                prepend_sys_path_if_dir(tmp)
                self.assertEqual(1, sys.path.count(tmp))
            finally:
                sys.path[:] = saved

    def test_018_boot_acme_http_stack(self) -> None:
        """HTTP adapter boot loads config, validates, and runs housekeeping"""
        from acme2certifier.acme_srv.helpers.acme_http_boot import boot_acme_http_stack

        mock_hk = MagicMock()
        mock_cm = MagicMock()
        mock_cm.__enter__.return_value = mock_hk
        mock_cm.__exit__.return_value = False
        logger = logging.getLogger("test_a2c_boot_stack")
        with (
            patch("acme2certifier.acme_srv.helper.apply_log_levels"),
            patch(
                "acme2certifier.acme_srv.helper.load_config", return_value={"cfg": True}
            ),
            patch("acme2certifier.acme_srv.helper.config_debug_get", return_value=True),
            patch("acme2certifier.acme_srv.helper.logger_setup", return_value=logger),
            patch("acme2certifier.acme_srv.helper.log_loaded_acme_srv_cfg"),
            patch("acme2certifier.acme_srv.db_handler.log_active_db_handler"),
            patch("acme2certifier.acme_srv.helper.config_check"),
            patch("acme2certifier.acme_srv.helper.server_name_configuration_validate"),
            patch("acme2certifier.acme_srv.helper.tnauthlist_configuration_validate"),
            patch(
                "acme2certifier.acme_srv.helper.challenge_type_configuration_validate"
            ),
            patch(
                "acme2certifier.acme_srv.helper.legacy_acme_get_load", return_value=True
            ),
            patch(
                "acme2certifier.acme_srv.trigger.resolve_trigger_endpoint",
                return_value=False,
            ),
            patch(
                "acme2certifier.acme_srv.housekeeping.resolve_housekeeping_cli_endpoint",
                return_value=False,
            ),
            patch(
                "acme2certifier.acme_srv.housekeeping.Housekeeping",
                return_value=mock_cm,
            ),
        ):
            stack = boot_acme_http_stack(log_startup_version=True)
        self.assertEqual({"cfg": True}, stack.config)
        self.assertTrue(stack.debug)
        self.assertIs(logger, stack.logger)
        self.assertTrue(stack.legacy_acme_get)
        self.assertFalse(stack.trigger_endpoint_enabled)
        self.assertFalse(stack.housekeeping_cli_enabled)
        mock_hk.dbversion_check.assert_called_once()
        mock_hk.nonce_cleanup.assert_called_once()


if __name__ == "__main__":
    unittest.main()
