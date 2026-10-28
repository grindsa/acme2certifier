# -*- coding: utf-8 -*-
"""unittests for google_cas_ca_handler"""

# pylint: disable=C0415, R0904, W0212
from __future__ import annotations

import base64
import configparser
import logging
import os
import socket
import sys
import threading
import time
import unittest
from unittest.mock import MagicMock, patch

import requests

sys.path.insert(0, ".")
sys.path.insert(1, "..")

MOCK_DIR = os.path.abspath(
    os.path.join(
        os.path.dirname(__file__),
        "..",
        "examples",
        "Docker",
        "google_privateca",
    )
)


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class TestGoogleCASHandler(unittest.TestCase):
    """unit tests for Google Private CAS REST handler"""

    def setUp(self):
        from acme2certifier.cahandlers.google_cas_ca_handler import CAhandler

        logging.basicConfig(level=logging.CRITICAL)
        self.logger = logging.getLogger("test_a2c")
        self.cahandler = CAhandler(False, self.logger)

    def _ready(self, endpoint: str = "http://127.0.0.1:9"):
        self.cahandler.project = "demo"
        self.cahandler.location = "europe-west1"
        self.cahandler.ca_pool = "demo-pool"
        self.cahandler.endpoint_url = endpoint
        self.cahandler.access_token = "unit-test-token"
        self.cahandler.issuing_certificate_authority_id = "mock-issuing-ca"

    def test_001_trigger_not_implemented(self):
        error, cert_bundle, cert_raw = self.cahandler.trigger("payload")
        self.assertEqual(error, "Method not implemented.")
        self.assertIsNone(cert_bundle)
        self.assertIsNone(cert_raw)

    def test_002_config_check_missing_params(self):
        err = self.cahandler._config_check()
        self.assertTrue(err)
        self.assertTrue(
            "project" in err or "ca_pool" in err or "required" in err.lower()
        )

    def test_003_config_check_ok_with_endpoint_placeholder(self):
        self.cahandler.project = "demo"
        self.cahandler.location = "europe-west1"
        self.cahandler.ca_pool = "demo-pool"
        self.cahandler.endpoint_url = "http://127.0.0.1:8080"
        self.assertIsNone(self.cahandler._config_check())
        self.assertEqual(self.cahandler._credentials_resolve(), "mock-token")

    def test_004_config_check_full_pool_name(self):
        self.cahandler.ca_pool = (
            "projects/demo/locations/europe-west1/caPools/demo-pool"
        )
        self.cahandler.endpoint_url = "http://127.0.0.1:8080"
        self.assertTrue(
            self.cahandler._parent_resource().endswith("/caPools/demo-pool")
        )
        self.assertIsNone(self.cahandler._config_check())

    def test_005_revocation_reason_mapping(self):
        self.assertEqual(
            self.cahandler._revocation_reason("keyCompromise"), "KEY_COMPROMISE"
        )
        self.assertEqual(
            self.cahandler._revocation_reason("unspecified"),
            "REVOCATION_REASON_UNSPECIFIED",
        )

    def test_006_lifetime_duration(self):
        self.cahandler.lifetime_days = 30
        self.assertEqual(self.cahandler._lifetime_duration(), "2592000s")

    def test_007_service_url(self):
        self.assertEqual(
            self.cahandler._service_url(), "https://privateca.googleapis.com"
        )
        self.cahandler.endpoint_url = "http://localhost:8080/"
        self.assertEqual(self.cahandler._service_url(), "http://localhost:8080")

    def test_008_access_token_precedence(self):
        self._ready()
        self.cahandler.credentials_file = "/nonexistent.json"
        self.assertEqual(self.cahandler._credentials_resolve(), "unit-test-token")

    @patch("acme2certifier.cahandlers.google_cas_ca_handler.requests.request")
    def test_009_api_call_sends_bearer(self, mock_request):
        self._ready()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = '{"ok":true}'
        mock_resp.json.return_value = {"ok": True}
        mock_request.return_value = mock_resp

        out = self.cahandler._api_call(
            "GET",
            "v1/projects/demo/locations/europe-west1/caPools/demo-pool/certificates",
        )
        self.assertEqual(out, {"ok": True})
        headers = mock_request.call_args.kwargs["headers"]
        self.assertEqual(headers["Authorization"], "Bearer unit-test-token")
        self.assertTrue(mock_request.call_args.kwargs["verify"])

    @patch("acme2certifier.cahandlers.google_cas_ca_handler.requests.request")
    def test_010_api_call_error(self, mock_request):
        self._ready()
        mock_resp = MagicMock()
        mock_resp.status_code = 400
        mock_resp.text = '{"error":{"status":"INVALID_ARGUMENT","message":"bad"}}'
        mock_resp.json.return_value = {
            "error": {"status": "INVALID_ARGUMENT", "message": "bad"}
        }
        mock_request.return_value = mock_resp
        with self.assertRaises(RuntimeError) as ctx:
            self.cahandler._api_call("POST", "v1/x/certificates", payload={})
        self.assertIn("INVALID_ARGUMENT", str(ctx.exception))

    @patch("acme2certifier.cahandlers.google_cas_ca_handler.CAhandler._api_call")
    def test_011_enroll(self, mock_api):
        self._ready()
        leaf = "-----BEGIN CERTIFICATE-----\nLEAF\n-----END CERTIFICATE-----"
        ica = "-----BEGIN CERTIFICATE-----\nICA\n-----END CERTIFICATE-----"
        root = "-----BEGIN CERTIFICATE-----\nROOT\n-----END CERTIFICATE-----"
        mock_api.return_value = {
            "name": (
                "projects/demo/locations/europe-west1/caPools/demo-pool/certificates/c1"
            ),
            "pemCertificate": leaf,
            "pemCertificateChain": [ica, root],
        }

        with (
            patch(
                "acme2certifier.cahandlers.google_cas_ca_handler.build_pem_file",
                return_value=(
                    "-----BEGIN CERTIFICATE REQUEST-----\n"
                    "MIIB\n-----END CERTIFICATE REQUEST-----\n"
                ),
            ),
            patch(
                "acme2certifier.cahandlers.google_cas_ca_handler.b64_url_recode",
                return_value="csr",
            ),
            patch(
                "acme2certifier.cahandlers.google_cas_ca_handler.cert_pem2der",
                return_value=b"der",
            ),
            patch(
                "acme2certifier.cahandlers.google_cas_ca_handler.b64_encode",
                return_value="Y2VydA==",
            ),
            patch(
                "acme2certifier.cahandlers.google_cas_ca_handler.eab_profile_header_info_check",
                return_value=None,
            ),
        ):
            error, bundle, cert_raw, poll_id = self.cahandler.enroll("csr-b64")

        self.assertIsNone(error)
        self.assertIn("LEAF", bundle)
        self.assertIn("ICA", bundle)
        self.assertEqual(cert_raw, "Y2VydA==")
        self.assertTrue(poll_id.endswith("/certificates/c1"))
        self.assertEqual(mock_api.call_args[0][0], "POST")
        self.assertIn("pemCsr", mock_api.call_args.kwargs["payload"])

    @patch("acme2certifier.cahandlers.google_cas_ca_handler.CAhandler._api_call")
    def test_012_handler_check(self, mock_api):
        self._ready()
        mock_api.return_value = {"name": "…/certificateAuthorities/mock-issuing-ca"}
        self.assertIsNone(self.cahandler.handler_check())
        self.assertEqual(mock_api.call_args[0][0], "GET")
        self.assertIn(
            "certificateAuthorities/mock-issuing-ca", mock_api.call_args[0][1]
        )

    @patch("acme2certifier.cahandlers.google_cas_ca_handler.CAhandler._api_call")
    @patch("acme2certifier.cahandlers.google_cas_ca_handler.cert_serial_get")
    def test_013_revoke(self, mock_serial, mock_api):
        self._ready()
        mock_serial.return_value = "abcd"
        name = "projects/demo/locations/europe-west1/caPools/demo-pool/certificates/c1"
        mock_api.side_effect = [
            {"certificates": [{"name": name}]},
            {"name": name, "revocationDetails": {"revocationState": "REVOKED"}},
        ]
        code, message, detail = self.cahandler.revoke("certraw", "keyCompromise")
        self.assertEqual(code, 200)
        self.assertIsNone(message)
        self.assertIsNone(detail)
        self.assertEqual(mock_api.call_args_list[0][0][0], "GET")
        self.assertEqual(mock_api.call_args_list[1][0][0], "POST")
        self.assertTrue(mock_api.call_args_list[1][0][1].endswith(":revoke"))
        self.assertEqual(
            mock_api.call_args_list[1][1]["payload"]["reason"], "KEY_COMPROMISE"
        )

    @patch("acme2certifier.cahandlers.google_cas_ca_handler.CAhandler._api_call")
    def test_014_poll(self, mock_api):
        self._ready()
        name = "projects/demo/locations/europe-west1/caPools/demo-pool/certificates/c1"
        leaf = "-----BEGIN CERTIFICATE-----\nLEAF\n-----END CERTIFICATE-----"
        mock_api.return_value = {
            "name": name,
            "pemCertificate": leaf,
            "pemCertificateChain": [],
        }
        with (
            patch(
                "acme2certifier.cahandlers.google_cas_ca_handler.cert_pem2der",
                return_value=b"der",
            ),
            patch(
                "acme2certifier.cahandlers.google_cas_ca_handler.b64_encode",
                return_value="Y2VydA==",
            ),
        ):
            error, bundle, cert_raw, poll_id, rejected = self.cahandler.poll(
                "n", name, "csr"
            )
        self.assertIsNone(error)
        self.assertIn("LEAF", bundle)
        self.assertEqual(cert_raw, "Y2VydA==")
        self.assertEqual(poll_id, name)
        self.assertFalse(rejected)

    def test_015_missing_google_auth_on_real_endpoint(self):
        self.cahandler.project = "demo"
        self.cahandler.location = "europe-west1"
        self.cahandler.ca_pool = "demo-pool"
        self.cahandler.endpoint_url = None
        self.cahandler.access_token = None
        self.cahandler.credentials_file = None
        with patch(
            "acme2certifier.cahandlers.google_cas_ca_handler.CAhandler._google_auth_import",
            side_effect=RuntimeError(
                "google-auth is required for Google Private CAS authentication"
            ),
        ):
            with self.assertRaises(RuntimeError) as ctx:
                self.cahandler._credentials_resolve()
            self.assertIn("google-auth", str(ctx.exception))

    def test_016_tls_verify_options(self):
        self.cahandler.verify = False
        self.assertFalse(self.cahandler._tls_verify())
        self.cahandler.verify = True
        self.cahandler.ca_bundle = "/tmp/trust.pem"
        self.assertEqual(self.cahandler._tls_verify(), "/tmp/trust.pem")

    @patch("acme2certifier.cahandlers.google_cas_ca_handler.CAhandler._config_load")
    def test_017_enter_loads_config_when_unset(self, mock_load):
        """__enter__ loads config when project and ca_pool are unset"""
        with self.cahandler as handler:
            self.assertIs(handler, self.cahandler)
        mock_load.assert_called_once_with()

    def test_018_enter_skips_load_when_ready(self):
        """__enter__ skips config load when project or ca_pool is set"""
        self.cahandler.project = "demo"
        with patch.object(self.cahandler, "_config_load") as mock_load:
            with self.cahandler:
                pass
            mock_load.assert_not_called()

    def test_019_credentials_from_file(self):
        """credentials_file path calls _token_from_credentials_file"""
        self.cahandler.credentials_file = "/tmp/sa.json"
        with patch.object(
            self.cahandler, "_token_from_credentials_file", return_value="file-token"
        ) as mock_tok:
            self.assertEqual(self.cahandler._credentials_resolve(), "file-token")
            mock_tok.assert_called_once_with("/tmp/sa.json")

    def test_020_google_auth_import_missing(self):
        """_google_auth_import raises when google-auth is not installed"""
        import builtins

        real_import = builtins.__import__

        def _fake_import(name, *args, **kwargs):
            if name.startswith("google"):
                raise ImportError("no google")
            return real_import(name, *args, **kwargs)

        with patch("builtins.__import__", side_effect=_fake_import):
            with self.assertRaises(RuntimeError) as ctx:
                self.cahandler._google_auth_import()
            self.assertIn("google-auth is required", str(ctx.exception))

    def test_021_token_from_credentials_file_ok(self):
        """_token_from_credentials_file refreshes SA credentials"""
        mock_sa = MagicMock()
        mock_transport = MagicMock()
        mock_creds = MagicMock()
        mock_creds.token = "sa-token"
        mock_sa.Credentials.from_service_account_file.return_value = mock_creds
        with patch.object(
            self.cahandler,
            "_google_auth_import",
            return_value=(MagicMock(), mock_transport, mock_sa),
        ):
            token = self.cahandler._token_from_credentials_file("/tmp/sa.json")
        self.assertEqual(token, "sa-token")
        mock_creds.refresh.assert_called_once()

    def test_022_token_from_credentials_file_empty_token(self):
        """_token_from_credentials_file errors when refresh yields no token"""
        mock_sa = MagicMock()
        mock_transport = MagicMock()
        mock_creds = MagicMock()
        mock_creds.token = None
        mock_sa.Credentials.from_service_account_file.return_value = mock_creds
        with patch.object(
            self.cahandler,
            "_google_auth_import",
            return_value=(MagicMock(), mock_transport, mock_sa),
        ):
            with self.assertRaises(RuntimeError) as ctx:
                self.cahandler._token_from_credentials_file("/tmp/sa.json")
            self.assertIn("credentials_file", str(ctx.exception))

    def test_023_token_from_adc_refresh(self):
        """_token_from_adc refreshes invalid credentials"""
        mock_auth = MagicMock()
        mock_transport = MagicMock()
        mock_creds = MagicMock()
        mock_creds.valid = False
        mock_creds.token = None
        mock_auth.default.return_value = (mock_creds, "proj")

        def _refresh(_req):
            mock_creds.token = "adc-token"
            mock_creds.valid = True

        mock_creds.refresh.side_effect = _refresh
        with patch.object(
            self.cahandler,
            "_google_auth_import",
            return_value=(mock_auth, mock_transport, MagicMock()),
        ):
            token = self.cahandler._token_from_adc()
        self.assertEqual(token, "adc-token")

    def test_024_token_from_adc_empty_token(self):
        """_token_from_adc errors when ADC yields no token"""
        mock_auth = MagicMock()
        mock_transport = MagicMock()
        mock_creds = MagicMock()
        mock_creds.valid = True
        mock_creds.token = None
        mock_auth.default.return_value = (mock_creds, "proj")
        with patch.object(
            self.cahandler,
            "_google_auth_import",
            return_value=(mock_auth, mock_transport, MagicMock()),
        ):
            with self.assertRaises(RuntimeError) as ctx:
                self.cahandler._token_from_adc()
            self.assertIn("ADC", str(ctx.exception))

    def test_025_config_check_credentials_error(self):
        """_config_check surfaces credential resolution failures"""
        self.cahandler.project = "demo"
        self.cahandler.location = "europe-west1"
        self.cahandler.ca_pool = "demo-pool"
        self.cahandler.endpoint_url = None
        with patch.object(
            self.cahandler,
            "_credentials_resolve",
            side_effect=RuntimeError("no creds"),
        ):
            with self.assertLogs("test_a2c", level="ERROR") as lcm:
                err = self.cahandler._config_check()
        self.assertEqual(err, "no creds")
        self.assertTrue(any("no creds" in line for line in lcm.output))

    @patch(
        "acme2certifier.cahandlers.google_cas_ca_handler.config_proxy_load",
        return_value={},
    )
    @patch(
        "acme2certifier.cahandlers.google_cas_ca_handler.config_enroll_config_log_load",
        return_value=(False, []),
    )
    @patch(
        "acme2certifier.cahandlers.google_cas_ca_handler.config_headerinfo_load",
        return_value=False,
    )
    @patch(
        "acme2certifier.cahandlers.google_cas_ca_handler.config_profile_load",
        return_value={},
    )
    @patch(
        "acme2certifier.cahandlers.google_cas_ca_handler.config_eab_profile_load",
        return_value=(False, None),
    )
    @patch("acme2certifier.cahandlers.google_cas_ca_handler.config_ca_bundle_load")
    @patch("acme2certifier.cahandlers.google_cas_ca_handler.config_option_load")
    @patch("acme2certifier.cahandlers.google_cas_ca_handler.load_config")
    def test_026_config_load_full(
        self,
        mock_load_cfg,
        mock_option,
        mock_ca_bundle,
        _mock_eab,
        _mock_profiles,
        _mock_header,
        _mock_enroll,
        _mock_proxy,
    ):
        """_config_load applies CAhandler options"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {
            "project": "p1",
            "location": "europe-west1",
            "ca_pool": "pool1",
            "issuing_certificate_authority_id": "ca1",
            "certificate_template": "projects/p1/locations/europe-west1/certificateTemplates/t1",
            "endpoint_url": "http://localhost:8080",
            "lifetime_days": "30",
            "request_timeout": "15",
            "request_retries": "2",
            "verify": "True",
        }
        mock_load_cfg.return_value = parser
        mock_option.side_effect = ["/tmp/sa.json", "tok"]
        mock_ca_bundle.return_value = True
        self.cahandler._config_load()
        self.assertEqual(self.cahandler.project, "p1")
        self.assertEqual(self.cahandler.location, "europe-west1")
        self.assertEqual(self.cahandler.ca_pool, "pool1")
        self.assertEqual(self.cahandler.issuing_certificate_authority_id, "ca1")
        self.assertIn("certificateTemplates/t1", self.cahandler.certificate_template)
        self.assertEqual(self.cahandler.endpoint_url, "http://localhost:8080")
        self.assertEqual(self.cahandler.credentials_file, "/tmp/sa.json")
        self.assertEqual(self.cahandler.access_token, "tok")
        self.assertEqual(self.cahandler.lifetime_days, 30)
        self.assertEqual(self.cahandler.request_timeout, 15)
        self.assertEqual(self.cahandler.request_retries, 2)

    @patch(
        "acme2certifier.cahandlers.google_cas_ca_handler.config_proxy_load",
        return_value={},
    )
    @patch(
        "acme2certifier.cahandlers.google_cas_ca_handler.config_enroll_config_log_load",
        return_value=(False, []),
    )
    @patch(
        "acme2certifier.cahandlers.google_cas_ca_handler.config_headerinfo_load",
        return_value=False,
    )
    @patch(
        "acme2certifier.cahandlers.google_cas_ca_handler.config_profile_load",
        return_value={},
    )
    @patch(
        "acme2certifier.cahandlers.google_cas_ca_handler.config_eab_profile_load",
        return_value=(False, None),
    )
    @patch(
        "acme2certifier.cahandlers.google_cas_ca_handler.config_option_load",
        return_value=None,
    )
    @patch("acme2certifier.cahandlers.google_cas_ca_handler.load_config")
    def test_027_config_load_env_and_tls_warning(
        self,
        mock_load_cfg,
        _mock_option,
        _mock_eab,
        _mock_profiles,
        _mock_header,
        _mock_enroll,
        _mock_proxy,
    ):
        """env fills credentials; verify=False logs WARNING"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {
            "project": "p1",
            "location": "europe-west1",
            "ca_pool": "pool1",
            "verify": "False",
        }
        mock_load_cfg.return_value = parser
        with (
            patch.dict(
                "os.environ",
                {
                    "GOOGLE_APPLICATION_CREDENTIALS": "/env/sa.json",
                    "GOOGLE_CAS_ACCESS_TOKEN": "env-tok",
                },
                clear=False,
            ),
            patch(
                "acme2certifier.cahandlers.google_cas_ca_handler.config_ca_bundle_load",
                return_value=False,
            ),
            self.assertLogs("test_a2c", level="WARNING") as lcm,
        ):
            self.cahandler._config_load()
        self.assertEqual(self.cahandler.credentials_file, "/env/sa.json")
        self.assertEqual(self.cahandler.access_token, "env-tok")
        self.assertFalse(self.cahandler.verify)
        self.assertTrue(
            any(
                "TLS certificate verification is disabled" in line
                for line in lcm.output
            )
        )

    @patch(
        "acme2certifier.cahandlers.google_cas_ca_handler.config_proxy_load",
        return_value={},
    )
    @patch(
        "acme2certifier.cahandlers.google_cas_ca_handler.config_enroll_config_log_load",
        return_value=(False, []),
    )
    @patch(
        "acme2certifier.cahandlers.google_cas_ca_handler.config_headerinfo_load",
        return_value=False,
    )
    @patch(
        "acme2certifier.cahandlers.google_cas_ca_handler.config_profile_load",
        return_value={},
    )
    @patch(
        "acme2certifier.cahandlers.google_cas_ca_handler.config_eab_profile_load",
        return_value=(False, None),
    )
    @patch("acme2certifier.cahandlers.google_cas_ca_handler.load_config")
    def test_028_config_load_without_cahandler_section(
        self,
        mock_load_cfg,
        _mock_eab,
        _mock_profiles,
        _mock_header,
        _mock_enroll,
        _mock_proxy,
    ):
        """_config_load tolerates missing CAhandler section"""
        mock_load_cfg.return_value = configparser.ConfigParser()
        self.cahandler._config_load()
        self.assertIsNone(self.cahandler.project)

    def test_029_api_error_message_variants(self):
        """_api_error_message covers Google error shapes"""
        self.assertEqual(
            self.cahandler._api_error_message(
                400, {"error": {"status": "FAILED", "message": "x"}}
            ),
            "FAILED: x",
        )
        self.assertEqual(
            self.cahandler._api_error_message(400, {"message": "plain"}),
            "plain",
        )
        self.assertEqual(
            self.cahandler._api_error_message(500, "raw"),
            "HTTP 500: raw",
        )

    def test_030_response_content_and_backoff(self):
        """_response_content falls back to text; _api_backoff sleeps"""
        mock_resp = MagicMock()
        mock_resp.text = "not-json"
        mock_resp.json.side_effect = ValueError("bad")
        self.assertEqual(self.cahandler._response_content(mock_resp), "not-json")
        mock_resp.text = ""
        mock_resp.json.side_effect = None
        self.assertEqual(self.cahandler._response_content(mock_resp), {})
        with patch(
            "acme2certifier.cahandlers.google_cas_ca_handler.time.sleep"
        ) as mock_sleep:
            self.cahandler._api_backoff(3)
            mock_sleep.assert_called_once()

    def test_031_api_response_process_branches(self):
        """_api_response_process success, retry, and hard failure"""
        ok = MagicMock()
        ok.status_code = 200
        ok.text = '{"a":1}'
        ok.json.return_value = {"a": 1}
        self.assertEqual(self.cahandler._api_response_process(ok, 1, 1), {"a": 1})

        bad_type = MagicMock()
        bad_type.status_code = 200
        bad_type.text = "x"
        bad_type.json.return_value = "x"
        with patch.object(self.cahandler, "_response_content", return_value="x"):
            with self.assertRaises(RuntimeError):
                self.cahandler._api_response_process(bad_type, 1, 1)

        retry = MagicMock()
        retry.status_code = 503
        with patch.object(
            self.cahandler,
            "_response_content",
            return_value={"error": {"message": "busy"}},
        ):
            self.assertIsNone(self.cahandler._api_response_process(retry, 1, 3))
            with self.assertRaises(RuntimeError):
                self.cahandler._api_response_process(retry, 3, 3)

    @patch("acme2certifier.cahandlers.google_cas_ca_handler.requests.request")
    def test_032_api_call_retries_and_request_exception(self, mock_request):
        """_api_call retries on 503 then succeeds; RequestException exhausts"""
        self._ready()
        self.cahandler.request_retries = 1
        fail = MagicMock()
        fail.status_code = 503
        fail.text = '{"error":{"message":"busy"}}'
        fail.json.return_value = {"error": {"message": "busy"}}
        ok = MagicMock()
        ok.status_code = 200
        ok.text = '{"ok":true}'
        ok.json.return_value = {"ok": True}
        mock_request.side_effect = [fail, ok]
        with patch("acme2certifier.cahandlers.google_cas_ca_handler.time.sleep"):
            self.assertEqual(
                self.cahandler._api_call("GET", "v1/x", query={"a": "b"}),
                {"ok": True},
            )

        mock_request.side_effect = requests.RequestException("down")
        with patch("acme2certifier.cahandlers.google_cas_ca_handler.time.sleep"):
            with self.assertRaises(RuntimeError) as ctx:
                self.cahandler._api_call("GET", "v1/x")
            self.assertIn("down", str(ctx.exception))

    @patch("acme2certifier.cahandlers.google_cas_ca_handler.CAhandler._api_call")
    def test_033_create_certificate_with_template(self, mock_api):
        """_create_certificate includes certificateTemplate when set"""
        self._ready()
        self.cahandler.certificate_template = (
            "projects/p/locations/l/certificateTemplates/t"
        )
        mock_api.return_value = {"name": "n"}
        self.cahandler._create_certificate("CSR")
        self.assertEqual(
            mock_api.call_args.kwargs["payload"]["certificateTemplate"],
            self.cahandler.certificate_template,
        )

    @patch("acme2certifier.cahandlers.google_cas_ca_handler.CAhandler._api_call")
    def test_034_list_certificates_non_list(self, mock_api):
        """_list_certificates_by_serial returns [] when certificates is not a list"""
        self._ready()
        mock_api.return_value = {"certificates": {"unexpected": True}}
        self.assertEqual(self.cahandler._list_certificates_by_serial("ab"), [])

    def test_035_bundle_from_certificate_errors_and_string_chain(self):
        """_bundle_from_certificate missing PEM and string chain"""
        with self.assertRaises(RuntimeError):
            self.cahandler._bundle_from_certificate({})
        leaf = "-----BEGIN CERTIFICATE-----\nL\n-----END CERTIFICATE-----"
        with (
            patch(
                "acme2certifier.cahandlers.google_cas_ca_handler.cert_pem2der",
                return_value=b"der",
            ),
            patch(
                "acme2certifier.cahandlers.google_cas_ca_handler.b64_encode",
                return_value="Yw==",
            ),
        ):
            bundle, raw, name = self.cahandler._bundle_from_certificate(
                {
                    "pemCertificate": leaf,
                    "pemCertificateChain": "-----BEGIN CERTIFICATE-----\nC\n-----END CERTIFICATE-----",
                    "name": "n1",
                }
            )
        self.assertIn("L", bundle)
        self.assertIn("C", bundle)
        self.assertEqual(raw, "Yw==")
        self.assertEqual(name, "n1")

    @patch("acme2certifier.cahandlers.google_cas_ca_handler.CAhandler._api_call")
    @patch("acme2certifier.cahandlers.google_cas_ca_handler.enrollment_config_log")
    def test_036_enroll_config_log_and_failure(self, mock_enroll_log, mock_api):
        """enroll logs config when enabled and catches create failures"""
        self._ready()
        self.cahandler.enrollment_config_log = True
        mock_api.side_effect = RuntimeError("create failed")
        with (
            patch(
                "acme2certifier.cahandlers.google_cas_ca_handler.build_pem_file",
                return_value="CSR",
            ),
            patch(
                "acme2certifier.cahandlers.google_cas_ca_handler.b64_url_recode",
                return_value="x",
            ),
            patch(
                "acme2certifier.cahandlers.google_cas_ca_handler.eab_profile_header_info_check",
                return_value=None,
            ),
            self.assertLogs("test_a2c", level="ERROR") as lcm,
        ):
            error, bundle, cert_raw, poll_id = self.cahandler.enroll("csr")
        self.assertEqual(error, "create failed")
        self.assertIsNone(bundle)
        mock_enroll_log.assert_called_once()
        self.assertTrue(any("create failed" in line for line in lcm.output))

    @patch("acme2certifier.cahandlers.google_cas_ca_handler.CAhandler._api_call")
    def test_037_handler_check_without_issuing_ca(self, mock_api):
        """handler_check lists certificates when issuing CA id is unset"""
        self._ready()
        self.cahandler.issuing_certificate_authority_id = None
        mock_api.return_value = {"certificates": []}
        self.assertIsNone(self.cahandler.handler_check())
        self.assertTrue(mock_api.call_args[0][1].endswith("/certificates"))

    @patch("acme2certifier.cahandlers.google_cas_ca_handler.CAhandler._api_call")
    def test_038_handler_check_api_error(self, mock_api):
        """handler_check returns API errors"""
        self._ready()
        mock_api.side_effect = RuntimeError("unreachable")
        with self.assertLogs("test_a2c", level="ERROR") as lcm:
            err = self.cahandler.handler_check()
        self.assertEqual(err, "unreachable")
        self.assertTrue(any("handler_check failed" in line for line in lcm.output))

    def test_039_poll_missing_identifier(self):
        """poll errors when poll_identifier is empty"""
        error, bundle, cert_raw, poll_id, rejected = self.cahandler.poll("n", "", "csr")
        self.assertIn("Missing poll_identifier", error)
        self.assertIsNone(bundle)
        self.assertEqual(poll_id, "")
        self.assertFalse(rejected)

    @patch("acme2certifier.cahandlers.google_cas_ca_handler.CAhandler._api_call")
    def test_040_poll_failure(self, mock_api):
        """poll surfaces get failures"""
        mock_api.side_effect = RuntimeError("gone")
        with self.assertLogs("test_a2c", level="ERROR") as lcm:
            error, _b, _r, poll_id, _rej = self.cahandler.poll("n", "projects/x", "csr")
        self.assertEqual(error, "gone")
        self.assertEqual(poll_id, "projects/x")
        self.assertTrue(any("Failed to poll" in line for line in lcm.output))

    def test_041_revoke_config_error(self):
        """revoke returns 500 when config is incomplete"""
        code, message, detail = self.cahandler.revoke("certraw")
        self.assertEqual(code, 500)
        self.assertEqual(message, "urn:ietf:params:acme:error:serverInternal")
        self.assertTrue(detail)

    @patch("acme2certifier.cahandlers.google_cas_ca_handler.cert_serial_get")
    def test_042_revoke_missing_serial(self, mock_serial):
        """revoke returns 500 when serial cannot be parsed"""
        self._ready()
        mock_serial.return_value = None
        with self.assertLogs("test_a2c", level="ERROR") as lcm:
            code, message, detail = self.cahandler.revoke("certraw")
        self.assertEqual(code, 500)
        self.assertIn("serial", detail.lower())
        self.assertTrue(any("serial" in line.lower() for line in lcm.output))

    @patch("acme2certifier.cahandlers.google_cas_ca_handler.CAhandler._api_call")
    @patch("acme2certifier.cahandlers.google_cas_ca_handler.cert_serial_get")
    @patch(
        "acme2certifier.cahandlers.google_cas_ca_handler.eab_profile_revocation_check"
    )
    def test_043_revoke_eab_and_no_match(self, mock_eab_rev, mock_serial, mock_api):
        """revoke runs EAB check and errors when list is empty"""
        self._ready()
        self.cahandler.eab_profiling = True
        mock_serial.return_value = "abcd"
        mock_api.return_value = {"certificates": []}
        with self.assertLogs("test_a2c", level="ERROR") as lcm:
            code, message, detail = self.cahandler.revoke("certraw")
        mock_eab_rev.assert_called_once()
        self.assertEqual(code, 500)
        self.assertIn("No Private CAS certificate found", detail)
        self.assertTrue(any("Failed to revoke" in line for line in lcm.output))

    @patch("acme2certifier.cahandlers.google_cas_ca_handler.CAhandler._api_call")
    @patch("acme2certifier.cahandlers.google_cas_ca_handler.cert_serial_get")
    def test_044_revoke_missing_name(self, mock_serial, mock_api):
        """revoke errors when listed certificate has no name"""
        self._ready()
        mock_serial.return_value = "abcd"
        mock_api.return_value = {"certificates": [{"name": ""}]}
        code, message, detail = self.cahandler.revoke("certraw")
        self.assertEqual(code, 500)
        self.assertIn("missing name", detail)

    def test_045_google_auth_import_ok(self):
        """_google_auth_import returns modules when google-auth is available"""
        import types

        mock_auth = types.ModuleType("google.auth")
        mock_transport_pkg = types.ModuleType("google.auth.transport")
        mock_requests_mod = types.ModuleType("google.auth.transport.requests")
        mock_oauth2 = types.ModuleType("google.oauth2")
        mock_sa_mod = types.ModuleType("google.oauth2.service_account")
        google_pkg = types.ModuleType("google")
        mock_auth.transport = mock_transport_pkg
        mock_transport_pkg.requests = mock_requests_mod
        google_pkg.auth = mock_auth
        google_pkg.oauth2 = mock_oauth2
        mock_oauth2.service_account = mock_sa_mod
        modules = {
            "google": google_pkg,
            "google.auth": mock_auth,
            "google.auth.transport": mock_transport_pkg,
            "google.auth.transport.requests": mock_requests_mod,
            "google.oauth2": mock_oauth2,
            "google.oauth2.service_account": mock_sa_mod,
        }
        with patch.dict("sys.modules", modules):
            auth, transport, sa = self.cahandler._google_auth_import()
        self.assertIs(auth, mock_auth)
        self.assertIs(transport, mock_requests_mod)
        self.assertIs(sa, mock_sa_mod)

    @patch("acme2certifier.cahandlers.google_cas_ca_handler.requests.request")
    def test_046_api_call_exhausted_null_responses(self, mock_request):
        """_api_call raises when every attempt yields a retryable null body"""
        self._ready()
        self.cahandler.request_retries = 0
        mock_request.return_value = MagicMock()
        with (
            patch.object(self.cahandler, "_api_response_process", return_value=None),
            patch("acme2certifier.cahandlers.google_cas_ca_handler.time.sleep"),
        ):
            with self.assertRaises(RuntimeError) as ctx:
                self.cahandler._api_call("GET", "v1/x")
            self.assertIn("Private CAS request failed", str(ctx.exception))


class TestGoogleCASHandlerMockServer(unittest.TestCase):
    """smoke tests against the in-repo Private CAS REST mock"""

    httpd = None
    endpoint = None

    @classmethod
    def setUpClass(cls):
        if not os.path.isdir(MOCK_DIR):
            raise unittest.SkipTest("google_privateca mock not present")

        sys.path.insert(0, MOCK_DIR)
        from pki import create_hierarchy
        from server import MockPrivateCaApp
        from wsgiref.simple_server import make_server

        port = _free_port()
        material = create_hierarchy(issuing_ca_id="mock-issuing-ca")
        app = MockPrivateCaApp(
            material=material,
            project="demo",
            location="europe-west1",
            pool="demo-pool",
            require_bearer=True,
        )
        cls.httpd = make_server("127.0.0.1", port, app)
        thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        thread.start()
        deadline = time.time() + 5
        while time.time() < deadline:
            try:
                requests.get(f"http://127.0.0.1:{port}/healthz", timeout=0.5)
                break
            except requests.RequestException:
                time.sleep(0.05)
        else:
            cls.httpd.shutdown()
            raise unittest.SkipTest("mock Private CAS server did not start")
        cls.endpoint = f"http://127.0.0.1:{port}"

    @classmethod
    def tearDownClass(cls):
        if cls.httpd is not None:
            cls.httpd.shutdown()
            cls.httpd = None

    def setUp(self):
        from acme2certifier.cahandlers.google_cas_ca_handler import CAhandler

        logging.basicConfig(level=logging.CRITICAL)
        self.logger = logging.getLogger("test_a2c")
        self.cahandler = CAhandler(False, self.logger)
        self.cahandler.project = "demo"
        self.cahandler.location = "europe-west1"
        self.cahandler.ca_pool = "demo-pool"
        self.cahandler.endpoint_url = self.endpoint
        self.cahandler.access_token = "unit-test-token"
        self.cahandler.issuing_certificate_authority_id = "mock-issuing-ca"

    def test_001_mock_server_rejects_missing_bearer(self):
        url = (
            f"{self.endpoint}/v1/projects/demo/locations/europe-west1/"
            "caPools/demo-pool/certificates"
        )
        resp = requests.get(url, timeout=5)
        self.assertEqual(resp.status_code, 401)

    def test_002_mock_server_enroll_and_revoke(self):
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(
                x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "smoke.acme")])
            )
            .sign(key, hashes.SHA256())
        )
        csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode("ascii")

        with (
            patch(
                "acme2certifier.cahandlers.google_cas_ca_handler.build_pem_file",
                return_value=csr_pem,
            ),
            patch(
                "acme2certifier.cahandlers.google_cas_ca_handler.b64_url_recode",
                return_value="ignored",
            ),
            patch(
                "acme2certifier.cahandlers.google_cas_ca_handler.eab_profile_header_info_check",
                return_value=None,
            ),
        ):
            error, bundle, cert_raw, poll_id = self.cahandler.enroll("dummy")

        self.assertIsNone(error, error)
        self.assertIn("BEGIN CERTIFICATE", bundle)
        self.assertTrue(cert_raw)
        self.assertIn("/certificates/", poll_id)

        leaf_pem = (
            bundle.split("-----END CERTIFICATE-----")[0] + "-----END CERTIFICATE-----"
        )
        leaf_der = x509.load_pem_x509_certificate(
            leaf_pem.encode("ascii")
        ).public_bytes(serialization.Encoding.DER)
        cert_b64 = base64.b64encode(leaf_der).decode("ascii")
        code, message, detail = self.cahandler.revoke(cert_b64, "keyCompromise")
        self.assertEqual(code, 200, (message, detail))


if __name__ == "__main__":
    unittest.main()
