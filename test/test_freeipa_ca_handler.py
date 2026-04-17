import unittest
from unittest.mock import MagicMock, patch
import sys

sys.path.insert(0, ".")
sys.path.insert(1, "..")
from acme_srv.helper import (
    load_config,
    csr_cn_get,
    csr_san_get,
    build_pem_file,
    b64_decode,
    cert_der2pem,
    cert_serial_get,
    handler_config_check,
    eab_profile_header_info_check,
)
import requests


class TestCAhandler(unittest.TestCase):
    def setUp(self):
        self.logger = MagicMock()
        from examples.ca_handler.freeipa_ca_handler import CAhandler

        self.handler = CAhandler(logger=self.logger)
        self.handler.api_host = "https://ipa.example.com"
        self.handler.api_user = "admin"
        self.handler.api_password = "secret"
        self.handler.api_version = "2.257"
        self.handler.fqdn = "ipa.example.com"
        self.handler.realm = "EXAMPLE.COM"
        self.handler.profile_id = "testprofile"
        self.handler.session = MagicMock()
        self.handler.ca_bundle = True
        self.handler.proxy = None
        self.handler.request_timeout = 30

    @patch("examples.ca_handler.freeipa_ca_handler.load_config")
    def test_001_config_load_testcase(self, mock_load_config):
        config = MagicMock()
        config.get.side_effect = lambda section, key, fallback=None: "value"
        config.getboolean.return_value = True
        mock_load_config.return_value = config
        self.handler._config_load()
        self.assertEqual(self.handler.api_host, "value")
        self.assertEqual(self.handler.api_user, "value")
        self.assertTrue(self.handler.ca_bundle)

    @patch("examples.ca_handler.freeipa_ca_handler.load_config")
    def test_002_config_load_fqdn_fallback(self, mock_load_config):
        # Simulate missing fqdn in DEFAULT section, should log and fallback to CONFIG_SECTION
        config = MagicMock()

        def get_side_effect(section, key, fallback=None):
            if section == self.handler.CONFIG_DEFAULT_SECTION and key == "fqdn":
                return ""
            if section == self.handler.CONFIG_SECTION and key == "fqdn":
                return "fqdn-from-section"
            return fallback or "other-value"

        config.get.side_effect = get_side_effect
        config.getboolean.return_value = True
        mock_load_config.return_value = config
        self.handler.fqdn = ""
        with patch.object(self.handler, "logger") as mock_logger:
            self.handler._config_load()
            mock_logger.debug.assert_any_call("FQDN not configured in DEFAULT section")
        self.assertEqual(self.handler.fqdn, "fqdn-from-section")

    def test_003_config_load_fqdn_fallback(self):
        # Simulate missing fqdn in DEFAULT section, should log and fallback to CONFIG_SECTION
        with patch(
            "examples.ca_handler.freeipa_ca_handler.load_config"
        ) as mock_load_config:
            config = MagicMock()

            def get_side_effect(section, key, fallback=None):
                if section == self.handler.CONFIG_DEFAULT_SECTION and key == "fqdn":
                    return ""
                if section == self.handler.CONFIG_SECTION and key == "fqdn":
                    return "fqdn-from-section"
                return fallback or "other-value"

            config.get.side_effect = get_side_effect
            config.getboolean.return_value = True
            mock_load_config.return_value = config
            self.handler.fqdn = ""
            with patch.object(self.handler, "logger") as mock_logger:
                self.handler._config_load()
                mock_logger.debug.assert_any_call(
                    "FQDN not configured in DEFAULT section"
                )
            self.assertEqual(self.handler.fqdn, "fqdn-from-section")

    def test_004_config_load_ca_bundle_boolean_true(self):
        # Simulate ca_bundle as string "true", should convert to boolean True
        with patch(
            "examples.ca_handler.freeipa_ca_handler.load_config"
        ) as mock_load_config:
            config = MagicMock()
            config.get.side_effect = lambda section, key, fallback=None: "true"
            config.getboolean.return_value = True
            mock_load_config.return_value = config
            self.handler.ca_bundle = False  # Set default to False
            self.handler._config_load()
            self.assertTrue(self.handler.ca_bundle)

    def test_005_config_load_ca_bundle_boolean_false(self):
        # Simulate ca_bundle as string "false", should convert to boolean False
        with patch(
            "examples.ca_handler.freeipa_ca_handler.load_config"
        ) as mock_load_config:
            config = MagicMock()
            config.get.side_effect = lambda section, key, fallback=None: "false"
            config.getboolean.return_value = False
            mock_load_config.return_value = config
            self.handler.ca_bundle = True  # Set default to True
            self.handler._config_load()
            self.assertFalse(self.handler.ca_bundle)

    def test_006_config_load_ca_bundle_not_boolean(self):
        # Simulate ca_bundle as string "notaboolean", should fallback to default
        with patch(
            "examples.ca_handler.freeipa_ca_handler.load_config"
        ) as mock_load_config:
            config = MagicMock()
            config.get.side_effect = lambda section, key, fallback=None: "notaboolean"
            config.getboolean.return_value = False
            mock_load_config.return_value = config
            self.handler.ca_bundle = True  # Set default to True
            self.handler._config_load()
            self.assertEqual("notaboolean", self.handler.ca_bundle)

    def test_007_login_success_testcase(self):
        # Test successful login
        self.handler.session = MagicMock()
        mock_post = self.handler.session.post
        mock_post.return_value.raise_for_status.return_value = None
        self.handler.api_host = "https://ipa.example.com"
        self.handler.api_user = "admin"
        self.handler.api_password = "secret"
        self.handler.ca_bundle = True
        self.handler.prefix = "/ipa"
        self.handler.LOGIN_URL = "/session/login_password"
        result = self.handler._login()
        mock_post.assert_called_once()
        self.logger.debug.assert_any_call("CAhandler._login()")
        self.assertIsNone(result)

    @patch("examples.ca_handler.freeipa_ca_handler.requests.Session")
    def test_008_login_creates_session_if_none(self, mock_session):
        # Cover the branch where self.session is None and a new Session is created
        self.handler.session = None
        self.handler.api_host = "https://ipa.example.com"
        self.handler.api_user = "admin"
        self.handler.api_password = "secret"
        self.handler.ca_bundle = True
        self.handler.prefix = "/ipa"
        self.handler.LOGIN_URL = "/session/login_password"
        mock_post = MagicMock()
        mock_session.return_value = MagicMock(post=mock_post, headers={})
        # Patch post to raise early to avoid real HTTP call
        mock_post.side_effect = Exception("stop")
        with self.assertRaises(Exception):
            self.handler._login()
        mock_session.assert_called_once()

    def test_009_login_http_error_testcase(self):
        # Test HTTPError during login
        self.handler.session = MagicMock()
        self.handler.session.post.return_value.raise_for_status.side_effect = (
            requests.exceptions.HTTPError("HTTP error")
        )
        self.handler.api_host = "https://ipa.example.com"
        self.handler.api_user = "admin"
        self.handler.api_password = "secret"
        self.handler.ca_bundle = True
        self.handler.prefix = "/ipa"
        self.handler.LOGIN_URL = "/session/login_password"
        result = self.handler._login()
        self.logger.error.assert_called()
        self.assertIsInstance(result, dict)
        self.assertIn("HTTP error during login", result["error"])

    def test_010_login_connection_error_testcase(self):
        # Test ConnectionError during login
        self.handler.session = MagicMock()
        self.handler.session.post.return_value.raise_for_status.side_effect = (
            requests.exceptions.ConnectionError("Connection error")
        )
        self.handler.api_host = "https://ipa.example.com"
        self.handler.api_user = "admin"
        self.handler.api_password = "secret"
        self.handler.ca_bundle = True
        self.handler.prefix = "/ipa"
        self.handler.LOGIN_URL = "/session/login_password"
        result = self.handler._login()
        self.logger.error.assert_called()
        self.assertIsInstance(result, dict)
        self.assertIn("Connection error during login", result["error"])

    def test_011_login_timeout_error_testcase(self):
        # Test Timeout during login
        self.handler.session = MagicMock()
        self.handler.session.post.return_value.raise_for_status.side_effect = (
            requests.exceptions.Timeout("Timeout error")
        )
        self.handler.api_host = "https://ipa.example.com"
        self.handler.api_user = "admin"
        self.handler.api_password = "secret"
        self.handler.ca_bundle = True
        self.handler.prefix = "/ipa"
        self.handler.LOGIN_URL = "/session/login_password"
        result = self.handler._login()
        self.logger.error.assert_called()
        self.assertIsInstance(result, dict)
        self.assertIn("Timeout during login", result["error"])

    def test_012_login_request_exception_testcase(self):
        # Test generic RequestException during login
        self.handler.session = MagicMock()
        self.handler.session.post.return_value.raise_for_status.side_effect = (
            requests.exceptions.RequestException("Request exception")
        )
        self.handler.api_host = "https://ipa.example.com"
        self.handler.api_user = "admin"
        self.handler.api_password = "secret"
        self.handler.ca_bundle = True
        self.handler.prefix = "/ipa"
        self.handler.LOGIN_URL = "/session/login_password"
        result = self.handler._login()
        self.logger.error.assert_called()
        self.assertIsInstance(result, dict)
        self.assertIn("Unexpected request exception during login", result["error"])

    def test_013_ipa_ping_testcase(self):
        self.handler._rpc_post = MagicMock(return_value={"result": "pong"})
        result = self.handler._ipa_ping()
        self.assertEqual(result, {"result": "pong"})

    def test_014_host_add_and_error_testcase(self):
        self.handler._rpc_post = MagicMock(return_value={"error": "fail"})
        self.handler._host_add("host1")
        self.logger.error.assert_called()

    def test_015_host_add_principal_and_error_testcase(self):
        self.handler._rpc_post = MagicMock(return_value={"error": "fail"})
        self.handler._host_add_principal("host1", "fqdn1")
        self.logger.error.assert_called()

    def test_016_host_add_principal_success_logs_debug(self):
        # Should log debug when host principal is added successfully (no error in content)
        with patch.object(self.handler, "_rpc_post", return_value={}), patch.object(
            self.handler, "logger"
        ) as mock_logger:
            self.handler._host_add_principal("host1", "fqdn1")
            mock_logger.debug.assert_called_with(
                "Host principal %s added to host %s successfully", "fqdn1", "host1"
            )

    def test_017_host_add_success_logs_info(self):
        # Should log info when host is added successfully (no error in content)
        with patch.object(self.handler, "_rpc_post", return_value={}), patch.object(
            self.handler, "logger"
        ) as mock_logger:
            self.handler._host_add("host1")
            mock_logger.info.assert_called_with(
                "Host %s added successfully to freeIPA", "host1"
            )

    def test_018_host_add_invalid_hostname(self):
        # Should log error and return for invalid hostname (None)
        with patch.object(self.handler, "logger") as mock_logger:
            self.handler._host_add(None)
            mock_logger.error.assert_called_with(
                "Invalid hostname provided to _host_add: %s", None
            )
        # Should log error and return for invalid hostname (not a string)
        with patch.object(self.handler, "logger") as mock_logger:
            self.handler._host_add(12345)
            mock_logger.error.assert_called_with(
                "Invalid hostname provided to _host_add: %s", 12345
            )

    def test_019_host_add_principal_invalid_fqdn(self):
        # Should log error and return for invalid fqdn
        with patch.object(self.handler, "logger") as mock_logger:
            self.handler._host_add_principal("host", None)
            mock_logger.error.assert_called_with(
                "Invalid fqdn provided to _host_add_principal: %s", None
            )
        with patch.object(self.handler, "logger") as mock_logger:
            self.handler._host_add_principal(None, "fqdn")
            mock_logger.error.assert_called_with(
                "Invalid hostname provided to _host_add_principal: %s", None
            )
        with patch.object(self.handler, "logger") as mock_logger:
            self.handler._host_add_principal("host", 12345)
            mock_logger.error.assert_called_with(
                "Invalid fqdn provided to _host_add_principal: %s", 12345
            )

    def test_020_host_add_principal_error_and_success(self):
        # Should log error if _rpc_post returns error, else log success
        self.handler.api_version = "2.257"
        with patch.object(
            self.handler, "_rpc_post", return_value={"error": "fail"}
        ), patch.object(self.handler, "logger") as mock_logger:
            self.handler._host_add_principal("host", "fqdn")
            mock_logger.error.assert_called_with(
                "Failed to add host principal %s for host %s: %s",
                "fqdn",
                "host",
                "fail",
            )
        with patch.object(self.handler, "_rpc_post", return_value={}), patch.object(
            self.handler, "logger"
        ) as mock_logger:
            self.handler._host_add_principal("host", "fqdn")
            mock_logger.debug.assert_called_with(
                "Host principal %s added to host %s successfully", "fqdn", "host"
            )

    def test_021_host_search_testcase(self):
        self.handler._rpc_post = MagicMock(return_value={"result": {"foo": "bar"}})
        result = self.handler._host_search("host1")
        self.assertEqual(result, {"result": {"foo": "bar"}})

    def test_022_host_search_invalid_hostname(self):
        # Should log error and return {} for invalid hostname input
        with patch.object(self.handler, "logger") as mock_logger:
            result = self.handler._host_search(None)
            self.assertEqual(result, {})
            mock_logger.error.assert_called_with(
                "Invalid hostname provided to _host_search: %s", None
            )
        with patch.object(self.handler, "logger") as mock_logger:
            result = self.handler._host_search(12345)
            self.assertEqual(result, {})
            mock_logger.error.assert_called_with(
                "Invalid hostname provided to _host_search: %s", 12345
            )

    def test_023_parse_csr_valid_testcase(self):
        with patch(
            "examples.ca_handler.freeipa_ca_handler.csr_cn_get", return_value="cn"
        ), patch(
            "examples.ca_handler.freeipa_ca_handler.csr_san_get",
            return_value=["DNS:foo", "DNS:bar"],
        ):
            cn, san_list = self.handler._parse_csr("dummycsr")
            self.assertEqual(cn, "cn")
            self.assertEqual(san_list, ["foo", "bar"])

    def test_024_parse_csr_no_cn_testcase(self):
        with patch(
            "examples.ca_handler.freeipa_ca_handler.csr_cn_get", return_value=None
        ), patch(
            "examples.ca_handler.freeipa_ca_handler.csr_san_get",
            return_value=["DNS:foo"],
        ):
            cn, san_list = self.handler._parse_csr("dummycsr")
            self.assertEqual(cn, "foo")
            self.assertEqual(san_list, [])

    def test_025_parse_csr_invalid_input(self):
        # Should log error and return (None, []) for invalid CSR input
        with patch.object(self.handler, "logger") as mock_logger:
            result = self.handler._parse_csr(None)
            self.assertEqual(result, (None, []))
            mock_logger.error.assert_called_with(
                "Invalid CSR provided to _parse_csr: %s", None
            )
        with patch.object(self.handler, "logger") as mock_logger:
            result = self.handler._parse_csr(12345)
            self.assertEqual(result, (None, []))
            mock_logger.error.assert_called_with(
                "Invalid CSR provided to _parse_csr: %s", 12345
            )

    def test_026_rpc_post_success_testcase(self):
        mock_response = MagicMock()
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = {"result": "ok"}
        self.handler.session.post.return_value = mock_response
        result = self.handler._rpc_post({"foo": "bar"})
        self.assertEqual(result, {"result": "ok"})

    def test_027_rpc_post_http_error_testcase(self):
        self.handler.session.post.side_effect = Exception("HTTP error")
        with self.assertRaises(Exception):
            self.handler._rpc_post({"foo": "bar"})

    def test_028_rpc_post_http_error(self):
        # Simulate HTTPError
        self.handler.session.post.side_effect = requests.exceptions.HTTPError("fail")
        result = self.handler._rpc_post({"foo": "bar"})
        self.assertIn("error", result)
        self.assertIn("HTTP error", result["error"])

    def test_029_rpc_post_connection_error(self):
        # Simulate ConnectionError
        self.handler.session.post.side_effect = requests.exceptions.ConnectionError(
            "fail"
        )
        result = self.handler._rpc_post({"foo": "bar"})
        self.assertIn("error", result)
        self.assertIn("Connection error", result["error"])

    def test_030_rpc_post_timeout_error(self):
        # Simulate Timeout
        self.handler.session.post.side_effect = requests.exceptions.Timeout("fail")
        result = self.handler._rpc_post({"foo": "bar"})
        self.assertIn("error", result)
        self.assertIn("Timeout error", result["error"])

    def test_031_rpc_post_request_exception(self):
        # Simulate generic RequestException
        self.handler.session.post.side_effect = requests.exceptions.RequestException(
            "fail"
        )
        result = self.handler._rpc_post({"foo": "bar"})
        self.assertIn("error", result)
        self.assertIn("Request exception", result["error"])

    def test_032_rpc_post_json_decode_error(self):
        # Simulate ValueError on resp.json()
        mock_resp = MagicMock()
        mock_resp.raise_for_status.return_value = None
        mock_resp.json.side_effect = ValueError("fail")
        self.handler.session.post.return_value = mock_resp
        result = self.handler._rpc_post({"foo": "bar"})
        self.assertIn("error", result)
        self.assertIn("JSON decode error", result["error"])

    def test_033_extract_api_version_testcase(self):
        self.handler._ipa_ping = MagicMock(
            return_value={"result": {"summary": "API version 2.257"}}
        )
        self.handler._extract_api_version()
        self.assertEqual(self.handler.api_version, "2.257")

    def test_034_cert_chain_to_pem_testcase(self):
        with patch(
            "examples.ca_handler.freeipa_ca_handler.b64_decode", return_value=b"bytes"
        ), patch(
            "examples.ca_handler.freeipa_ca_handler.cert_der2pem", return_value=b"PEM"
        ):
            pem = self.handler._cert_chain_to_pem([{"__base64__": "abc"}])
            self.assertIn("PEM", pem)

    def test_035_enroll_error_testcase(self):
        self.handler._rpc_post = MagicMock(return_value={"error": "fail"})
        error, cert_bundle, cert_raw = self.handler._enroll("host", "csr")
        self.assertEqual(error, "fail")
        self.assertIsNone(cert_bundle)
        self.assertIsNone(cert_raw)

    def test_036_enroll_success_testcase(self):
        self.handler._rpc_post = MagicMock(
            return_value={
                "result": {"result": {"certificate": "cert", "certificate_chain": []}}
            }
        )
        with patch.object(self.handler, "_cert_chain_to_pem", return_value="pem"):
            error, cert_bundle, cert_raw = self.handler._enroll("host", "csr")
            self.assertIsNone(error)
            self.assertEqual(cert_bundle, "pem")
            self.assertEqual(cert_raw, "cert")

    def test_037_enroll_unexpected_result_structure(self):
        # _rpc_post returns a result with unexpected structure (not a dict)
        self.handler._rpc_post = MagicMock(
            return_value={"result": {"result": "notadict"}}
        )
        with patch.object(self.handler, "logger") as mock_logger:
            error, cert_bundle, cert_raw = self.handler._enroll("host", "csr")
            self.assertIn("Unexpected structure for", error)
            self.assertIsNone(cert_bundle)
            self.assertIsNone(cert_raw)
            mock_logger.error.assert_called()

    def test_038_enroll_exception_in_result_extraction(self):
        # _rpc_post returns a result that triggers an exception in extraction
        self.handler._rpc_post = MagicMock(
            return_value={
                "result": {"result": {"certificate": "cert", "certificate_chain": None}}
            }
        )
        with patch.object(
            self.handler, "_cert_chain_to_pem", side_effect=Exception("fail")
        ), patch.object(self.handler, "logger") as mock_logger:
            error, cert_bundle, cert_raw = self.handler._enroll("host", "csr")
            self.assertIn("Error extracting certificate or chain", error)
            self.assertIsNone(cert_bundle)
            self.assertIsNone(cert_raw)
            mock_logger.error.assert_called()

    def test_039_enroll_no_result_key(self):
        # _rpc_post returns no 'result' key
        self.handler._rpc_post = MagicMock(return_value={})
        with patch.object(self.handler, "logger") as mock_logger:
            error, cert_bundle, cert_raw = self.handler._enroll("host", "csr")
            self.assertEqual(error, "Certificate chain not found in response")
            self.assertIsNone(cert_bundle)
            self.assertIsNone(cert_raw)
            mock_logger.error.assert_called()

    def test_040_revoke_error_testcase(self):
        self.handler._rpc_post = MagicMock(return_value={"error": "fail"})
        code, message, detail = self.handler._revoke("serial")
        self.assertEqual(code, 500)
        self.assertEqual(message, "fail")
        self.assertIsNone(detail)

    def test_041_revoke_success_testcase(self):
        self.handler._rpc_post = MagicMock(return_value={})
        code, message, detail = self.handler._revoke("serial")
        self.assertEqual(code, 200)
        self.assertEqual(message, "Certificate revoked successfully")
        self.assertIsNone(detail)

    def test_042_handler_check_testcase(self):
        with patch(
            "examples.ca_handler.freeipa_ca_handler.handler_config_check",
            return_value=None,
        ):
            error = self.handler.handler_check()
            self.assertIsNone(error)

    def test_043_poll_testcase(self):
        error, cert_bundle, cert_raw, poll_identifier, rejected = self.handler.poll(
            "cert", "pollid", "csr"
        )
        self.assertIsNone(error)
        self.assertIsNone(cert_bundle)
        self.assertIsNone(cert_raw)
        self.assertEqual(poll_identifier, "pollid")
        self.assertFalse(rejected)

    def test_044_trigger_testcase(self):
        error, cert_bundle, cert_raw = self.handler.trigger("payload")
        self.assertIsNone(error)
        self.assertIsNone(cert_bundle)
        self.assertIsNone(cert_raw)

    def test_045_ensure_host_and_principals_success_testcase(self):
        # Host exists, no error
        self.handler._host_search = MagicMock(return_value={"result": {"foo": "bar"}})
        self.handler._host_add = MagicMock()
        self.handler._host_add_managedby = MagicMock()
        self.handler._host_add_principal = MagicMock()
        error = self.handler._ensure_host_and_principals("host1", ["fqdn1", "fqdn2"])
        self.assertIsNone(error)
        self.handler._host_add.assert_not_called()  # Should not add host if exists
        self.handler._host_add_managedby.assert_called_once_with("host1")
        self.handler._host_add_principal.assert_any_call("host1", "fqdn1")
        self.handler._host_add_principal.assert_any_call("host1", "fqdn2")

    def test_046_ensure_host_and_principals_create_host_testcase(self):
        # Host does not exist, should add
        self.handler._host_search = MagicMock(return_value={"result": {}})
        self.handler._host_add = MagicMock()
        self.handler._host_add_managedby = MagicMock()
        self.handler._host_add_principal = MagicMock()
        error = self.handler._ensure_host_and_principals("host2", ["fqdn3"])
        self.assertIsNone(error)
        self.handler._host_add.assert_called_once_with("host2")
        self.handler._host_add_managedby.assert_called_once_with("host2")
        self.handler._host_add_principal.assert_called_once_with("host2", "fqdn3")

    def test_047_ensure_host_and_principals_error_testcase(self):
        # Host search fails
        self.handler._host_search = MagicMock(return_value={"error": "fail"})
        self.handler._host_add = MagicMock()
        self.handler._host_add_managedby = MagicMock()
        self.handler._host_add_principal = MagicMock()
        error = self.handler._ensure_host_and_principals("host3", ["fqdn4"])
        self.assertEqual(error, "Malformed host search response")
        self.handler._host_add.assert_not_called()
        self.handler._host_add_managedby.assert_not_called()
        self.handler._host_add_principal.assert_not_called()
        self.logger.error.assert_called()

    def test_048_host_add_managedby_success_testcase(self):
        # Test successful managedby addition
        self.handler._rpc_post = MagicMock(return_value={})
        self.handler.fqdn = "ipa.example.com"
        self.handler.api_version = "2.257"
        self.logger.reset_mock()
        self.handler._host_add_managedby("host1")
        self.handler._rpc_post.assert_called_once()
        self.logger.debug.assert_any_call("CAhandler._host_add_managedby()")
        self.logger.debug.assert_any_call(
            "Host %s added managed by %s successfully", "host1", "ipa.example.com"
        )

    def test_049_host_add_managedby_error_testcase(self):
        # Test error during managedby addition
        self.handler._rpc_post = MagicMock(return_value={"error": "fail"})
        self.handler.fqdn = "ipa.example.com"
        self.handler.api_version = "2.257"
        self.logger.reset_mock()
        self.handler._host_add_managedby("host2")
        self.handler._rpc_post.assert_called_once()
        self.logger.debug.assert_any_call("CAhandler._host_add_managedby()")
        self.logger.error.assert_any_call("Failed to add host %s: %s", "host2", "fail")

    def test_050_enter_with_config_load_and_login_testcase(self):
        # Test __enter__ triggers config load, login, and API version extraction if api_host is not set
        self.handler.api_host = None
        self.handler._config_load = MagicMock()
        self.handler._login = MagicMock()
        self.handler._extract_api_version = MagicMock()
        result = self.handler.__enter__()
        self.handler._config_load.assert_called_once()
        self.handler._login.assert_called_once()
        self.handler._extract_api_version.assert_called_once()
        self.assertIs(result, self.handler)

    def test_051_enter_with_api_host_set_testcase(self):
        # Test __enter__ does not call config load, login, or API version extraction if api_host is set
        self.handler.api_host = "https://ipa.example.com"
        self.handler._config_load = MagicMock()
        self.handler._login = MagicMock()
        self.handler._extract_api_version = MagicMock()
        result = self.handler.__enter__()
        self.handler._config_load.assert_not_called()
        self.handler._login.assert_not_called()
        self.handler._extract_api_version.assert_not_called()
        self.assertIs(result, self.handler)

    def test_052_exit_with_session_testcase(self):
        # Test __exit__ closes and clears session if present
        mock_session = MagicMock()
        self.handler.session = mock_session
        self.handler.__exit__(None, None, None)
        mock_session.close.assert_called_once()
        self.assertIsNone(self.handler.session)

    def test_053_exit_without_session_testcase(self):
        # Test __exit__ does nothing if session is None
        self.handler.session = None
        # Should not raise
        self.handler.__exit__(None, None, None)
        self.assertIsNone(self.handler.session)

    def test_054_revoke_public_error(self):
        # Simulate cert_serial_get returns a serial, _revoke returns error
        with patch(
            "examples.ca_handler.freeipa_ca_handler.cert_serial_get",
            return_value="serial",
        ):
            self.handler._revoke = MagicMock(return_value=(1, "fail", None))
            code, message, detail = self.handler.revoke("dummycert")
            self.handler._revoke.assert_called_once_with("serial")
            self.assertEqual(code, 1)
            self.assertEqual(message, "fail")
            self.assertIsNone(detail)

    def test_055_revoke_public_success(self):
        # Simulate cert_serial_get returns a serial, _revoke returns success
        with patch(
            "examples.ca_handler.freeipa_ca_handler.cert_serial_get",
            return_value="serial",
        ):
            self.handler._revoke = MagicMock(
                return_value=(0, "Certificate revoked successfully", None)
            )
            code, message, detail = self.handler.revoke("dummycert")
            self.handler._revoke.assert_called_once_with("serial")
            self.assertEqual(code, 0)
            self.assertEqual(message, "Certificate revoked successfully")
            self.assertIsNone(detail)

    def test_056_revoke_no_serial(self):
        # Simulate cert_serial_get returns None, _revoke should not be called
        with patch(
            "examples.ca_handler.freeipa_ca_handler.cert_serial_get", return_value=None
        ):
            self.handler._revoke = MagicMock()
            code, message, detail = self.handler.revoke("dummycert")
            self.handler._revoke.assert_not_called()
            self.assertEqual(code, 400)
            self.assertEqual(message, "urn:ietf:params:acme:error:malformed")
            self.assertEqual(
                detail, "Invalid certificate format or missing serial number"
            )

    def test_057_revoke_no_cert(self):
        # Simulate cert_serial_get returns None, _revoke should not be called
        with patch(
            "examples.ca_handler.freeipa_ca_handler.cert_serial_get", return_value=None
        ):
            self.handler._revoke = MagicMock()
            code, message, detail = self.handler.revoke(None)
            self.handler._revoke.assert_not_called()
            self.assertEqual(code, 400)
            self.assertEqual(message, "urn:ietf:params:acme:error:malformed")
            self.assertEqual(detail, "Certificate data is required for revocation")

    def test_058_enroll_eab_profile_error(self):
        # Simulate eab_profile_header_info_check returns error
        with patch(
            "examples.ca_handler.freeipa_ca_handler.eab_profile_header_info_check",
            return_value="eab_error",
        ):
            result = self.handler.enroll("dummycsr")
            self.assertEqual(result, ("eab_error", None, None, None))

    def test_059_enroll_ensure_host_error(self):
        # Simulate eab_profile_header_info_check ok, _parse_csr returns host/alias, _ensure_host_and_principals returns error
        with patch(
            "examples.ca_handler.freeipa_ca_handler.eab_profile_header_info_check",
            return_value=None,
        ), patch.object(
            self.handler, "_parse_csr", return_value=("host", ["alias1", "alias2"])
        ), patch.object(
            self.handler, "_ensure_host_and_principals", return_value="host_error"
        ):
            result = self.handler.enroll("dummycsr")
            self.assertEqual(result, ("host_error", None, None, None))

    def test_060_enroll_enroll_error(self):
        # Simulate all ok until _enroll, which returns error
        with patch(
            "examples.ca_handler.freeipa_ca_handler.eab_profile_header_info_check",
            return_value=None,
        ), patch.object(
            self.handler, "_parse_csr", return_value=("host", ["alias1", "alias2"])
        ), patch.object(
            self.handler, "_ensure_host_and_principals", return_value=None
        ), patch(
            "examples.ca_handler.freeipa_ca_handler.build_pem_file",
            return_value="pemcsr",
        ), patch.object(
            self.handler, "_enroll", return_value=("enroll_error", None, None)
        ):
            result = self.handler.enroll("dummycsr")
            self.assertEqual(result, ("enroll_error", None, None, None))

    def test_061_enroll_success(self):
        # Simulate full success path
        with patch(
            "examples.ca_handler.freeipa_ca_handler.eab_profile_header_info_check",
            return_value=None,
        ), patch.object(
            self.handler, "_parse_csr", return_value=("host", ["alias1", "alias2"])
        ), patch.object(
            self.handler, "_ensure_host_and_principals", return_value=None
        ), patch(
            "examples.ca_handler.freeipa_ca_handler.build_pem_file",
            return_value="pemcsr",
        ), patch.object(
            self.handler, "_enroll", return_value=(None, "bundle", "raw")
        ):
            result = self.handler.enroll("dummycsr")
            self.assertEqual(result, (None, "bundle", "raw", None))

    def test_062_cert_chain_to_pem_skips_missing_base64(self):
        # Should skip certs without '__base64__' key or with falsy value
        certs = [
            {},  # no __base64__ key
            {"__base64__": None},  # falsy value
            {"__base64__": ""},  # empty string
        ]
        with patch(
            "examples.ca_handler.freeipa_ca_handler.b64_decode"
        ) as mock_b64_decode, patch(
            "examples.ca_handler.freeipa_ca_handler.cert_der2pem"
        ) as mock_cert_der2pem:
            result = self.handler._cert_chain_to_pem(certs)
            self.assertEqual(result, "")
            mock_b64_decode.assert_not_called()
            mock_cert_der2pem.assert_not_called()

    def test_063_enroll_calls_enrollment_config_log(self):
        # Cover lines 451-454: enrollment_config_log is called if self.enrollment_config_log is True
        self.handler.enrollment_config_log = True
        self.handler.enrollment_config_log_skip_list = ["skip1", "skip2"]
        with patch("examples.ca_handler.freeipa_ca_handler.enrollment_config_log") as mock_enroll_log, \
             patch.object(self.handler, "_rpc_post", return_value={"error": "fail"}):
            self.handler._enroll("host", "csr")
            mock_enroll_log.assert_called_once_with(self.logger, self.handler, ["skip1", "skip2"])


if __name__ == "__main__":
    unittest.main()
