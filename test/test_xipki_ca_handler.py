#!/usr/bin/python
# -*- coding: utf-8 -*-
"""unittests for xipki_ca_handler"""

# pylint: disable=C0415, R0904, W0212
import base64
import configparser
import datetime
import logging
import os
import sys
import unittest
from unittest.mock import Mock, patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

sys.path.insert(0, ".")
sys.path.insert(1, "..")


def _make_ca_and_leaf():
    """build a self-signed CA, leaf cert, and CSR for tests"""
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test CA")])
    now = datetime.datetime.now(datetime.timezone.utc)
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(issuer)
        .issuer_name(issuer)
        .public_key(ca_key.public_key())
        .serial_number(0xABCD)
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .sign(ca_key, hashes.SHA256())
    )
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf = (
        x509.CertificateBuilder()
        .subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "leaf.example")])
        )
        .issuer_name(issuer)
        .public_key(leaf_key.public_key())
        .serial_number(0x1234)
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=30))
        .sign(ca_key, hashes.SHA256())
    )
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "leaf.example")])
        )
        .sign(leaf_key, hashes.SHA256())
    )
    return ca_cert, leaf, csr


class TestACMEHandler(unittest.TestCase):
    """test class for xipki_ca_handler"""

    @classmethod
    def setUpClass(cls):
        ca_cert, leaf, csr = _make_ca_and_leaf()
        cls.ca_der = ca_cert.public_bytes(serialization.Encoding.DER)
        cls.ca_pem = ca_cert.public_bytes(serialization.Encoding.PEM).decode()
        cls.ca_sha1 = ca_cert.fingerprint(hashes.SHA1()).hex()
        cls.leaf_der = leaf.public_bytes(serialization.Encoding.DER)
        cls.leaf_b64url = (
            base64.urlsafe_b64encode(leaf.public_bytes(serialization.Encoding.DER))
            .decode()
            .rstrip("=")
        )
        cls.csr_b64url = (
            base64.urlsafe_b64encode(csr.public_bytes(serialization.Encoding.DER))
            .decode()
            .rstrip("=")
        )

    def setUp(self):
        """setup unittest"""
        from acme2certifier.cahandlers.xipki_ca_handler import CAhandler

        logging.basicConfig(level=logging.CRITICAL)
        self.logger = logging.getLogger("test_a2c")
        self.cahandler = CAhandler(False, self.logger)
        self.dir_path = os.path.dirname(os.path.realpath(__file__))

    def test_001_default(self):
        """default test which always passes"""
        self.assertEqual("foo", "foo")

    @patch("acme2certifier.cahandlers.xipki_ca_handler.CAhandler._config_load")
    def test_002_enter_loads_config(self, mock_cfg):
        """__enter__ loads config when api_host unset"""
        mock_cfg.return_value = None
        with patch.object(self.cahandler, "_auth_set") as mock_auth:
            self.cahandler.__enter__()
        self.assertTrue(mock_cfg.called)
        self.assertTrue(mock_auth.called)

    @patch("acme2certifier.cahandlers.xipki_ca_handler.CAhandler._config_load")
    def test_003_enter_skips_when_configured(self, mock_cfg):
        """__enter__ skips config when api_host set"""
        self.cahandler.api_host = "https://xipki.example/gw/rest/ca"
        with patch.object(self.cahandler, "_auth_set") as mock_auth:
            self.cahandler.__enter__()
        self.assertFalse(mock_cfg.called)
        self.assertFalse(mock_auth.called)

    def test_004_poll_stub(self):
        """poll is not implemented"""
        self.assertEqual(
            ("Method not implemented.", None, None, "poll_id", False),
            self.cahandler.poll("cert", "poll_id", "csr"),
        )

    def test_005_trigger_stub(self):
        """trigger is not implemented"""
        self.assertEqual(
            ("Method not implemented.", None, None),
            self.cahandler.trigger("payload"),
        )

    def test_006_reason_normalize(self):
        """revocation reason normalization"""
        self.assertEqual("UNSPECIFIED", self.cahandler._reason_normalize(None))
        self.assertEqual("UNSPECIFIED", self.cahandler._reason_normalize(""))
        self.assertEqual(
            "KEY_COMPROMISE", self.cahandler._reason_normalize("keyCompromise")
        )
        self.assertEqual(
            "KEY_COMPROMISE", self.cahandler._reason_normalize("KEY_COMPROMISE")
        )
        self.assertEqual(
            "CESSATION_OF_OPERATION",
            self.cahandler._reason_normalize("cessationOfOperation"),
        )

    @patch("acme2certifier.cahandlers.xipki_ca_handler.load_config")
    def test_007_config_load_required(self, mock_load_cfg):
        """_config_load sets required fields"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {
            "api_host": "https://xipki.example/gw/rest/ca",
            "api_user": "user",
            "api_password": "secret",
            "profile": "tls",
            "request_timeout": "15",
        }
        mock_load_cfg.return_value = parser
        with patch(
            "acme2certifier.cahandlers.xipki_ca_handler.config_option_load",
            side_effect=lambda _l, _c, option, current=None: {
                "api_user": "user",
                "api_password": "secret",
            }.get(option, current),
        ):
            with patch(
                "acme2certifier.cahandlers.xipki_ca_handler.config_ca_bundle_load",
                return_value=True,
            ):
                with patch(
                    "acme2certifier.cahandlers.xipki_ca_handler.config_proxy_load",
                    return_value={},
                ):
                    with patch(
                        "acme2certifier.cahandlers.xipki_ca_handler.config_eab_profile_load",
                        return_value=(False, None),
                    ):
                        with patch(
                            "acme2certifier.cahandlers.xipki_ca_handler.config_profile_load",
                            return_value={},
                        ):
                            with patch(
                                "acme2certifier.cahandlers.xipki_ca_handler.config_headerinfo_load",
                                return_value=False,
                            ):
                                with patch(
                                    "acme2certifier.cahandlers.xipki_ca_handler.config_enroll_config_log_load",
                                    return_value=(False, []),
                                ):
                                    self.cahandler._config_load()
        self.assertEqual("https://xipki.example/gw/rest/ca", self.cahandler.api_host)
        self.assertEqual("user", self.cahandler.api_user)
        self.assertEqual("secret", self.cahandler.api_password)
        self.assertEqual("tls", self.cahandler.profile)
        self.assertEqual(15, self.cahandler.request_timeout)

    @patch("acme2certifier.cahandlers.xipki_ca_handler.load_config")
    def test_008_config_load_missing_logs(self, mock_load_cfg):
        """_config_load logs missing parameters"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {}
        mock_load_cfg.return_value = parser
        with patch(
            "acme2certifier.cahandlers.xipki_ca_handler.config_option_load",
            return_value=None,
        ):
            with patch(
                "acme2certifier.cahandlers.xipki_ca_handler.config_ca_bundle_load",
                return_value=True,
            ):
                with patch(
                    "acme2certifier.cahandlers.xipki_ca_handler.config_proxy_load",
                    return_value={},
                ):
                    with patch(
                        "acme2certifier.cahandlers.xipki_ca_handler.config_eab_profile_load",
                        return_value=(False, None),
                    ):
                        with patch(
                            "acme2certifier.cahandlers.xipki_ca_handler.config_profile_load",
                            return_value={},
                        ):
                            with patch(
                                "acme2certifier.cahandlers.xipki_ca_handler.config_headerinfo_load",
                                return_value=False,
                            ):
                                with patch(
                                    "acme2certifier.cahandlers.xipki_ca_handler.config_enroll_config_log_load",
                                    return_value=(False, []),
                                ):
                                    with self.assertLogs(
                                        "test_a2c", level="ERROR"
                                    ) as lcm:
                                        self.cahandler._config_load()
        self.assertTrue(any("api_host" in line for line in lcm.output))

    def test_009_auth_set(self):
        """_auth_set configures BasicAuth"""
        self.cahandler.api_user = "user"
        self.cahandler.api_password = "pass"
        self.cahandler._auth_set()
        self.assertIsNotNone(self.cahandler.session)
        self.assertIsNotNone(self.cahandler.session.auth)

    def test_010_handler_check(self):
        """handler_check reports missing config"""
        error = self.cahandler.handler_check()
        self.assertTrue(error)

    def test_011_handler_check_ok(self):
        """handler_check succeeds when configured"""
        self.cahandler.api_host = "https://xipki.example/gw/rest/ca"
        self.cahandler.api_user = "user"
        self.cahandler.api_password = "pass"
        self.cahandler.profile = "tls"
        self.assertIsNone(self.cahandler.handler_check())

    @patch("acme2certifier.cahandlers.xipki_ca_handler.CAhandler._http_request")
    def test_012_cacert_cache(self, mock_http):
        """_cacert_cache loads cacerts and cacert"""
        self.cahandler.api_host = "https://xipki.example/gw/rest/ca/"
        mock_http.side_effect = [
            (200, self.ca_pem.encode(), self.ca_pem),
            (200, self.ca_der, "ok"),
        ]
        error, pem = self.cahandler._cacert_cache()
        self.assertIsNone(error)
        self.assertIn("BEGIN CERTIFICATE", pem)
        self.assertEqual(self.ca_sha1, self.cahandler._ca_sha1)
        # second call uses cache
        mock_http.reset_mock()
        error2, pem2 = self.cahandler._cacert_cache()
        self.assertIsNone(error2)
        self.assertEqual(pem, pem2)
        self.assertFalse(mock_http.called)

    @patch("acme2certifier.cahandlers.xipki_ca_handler.CAhandler._http_request")
    def test_013_cacert_cache_fail(self, mock_http):
        """_cacert_cache fails on HTTP error"""
        self.cahandler.api_host = "https://xipki.example/gw/rest/ca"
        mock_http.return_value = (500, b"", "boom")
        error, pem = self.cahandler._cacert_cache()
        self.assertIn("cacerts", error)
        self.assertIsNone(pem)

    @patch(
        "acme2certifier.cahandlers.xipki_ca_handler.eab_profile_header_info_check",
        return_value=None,
    )
    @patch("acme2certifier.cahandlers.xipki_ca_handler.CAhandler._cacert_cache")
    @patch("acme2certifier.cahandlers.xipki_ca_handler.CAhandler._enroll_post")
    def test_014_enroll_success(self, mock_enroll, mock_cache, _mock_eab):
        """enroll builds PEM bundle"""
        self.cahandler.api_host = "https://xipki.example/gw/rest/ca"
        self.cahandler.profile = "tls"
        mock_cache.return_value = (None, self.ca_pem)
        mock_enroll.return_value = (None, self.leaf_der)
        error, bundle, cert_raw, poll = self.cahandler.enroll(self.csr_b64url)
        self.assertIsNone(error)
        self.assertIn("BEGIN CERTIFICATE", bundle)
        self.assertIsNotNone(cert_raw)
        self.assertIsNone(poll)

    @patch(
        "acme2certifier.cahandlers.xipki_ca_handler.eab_profile_header_info_check",
        return_value="profile denied",
    )
    def test_015_enroll_eab_reject(self, _mock_eab):
        """enroll stops on EAB/header check failure"""
        error, bundle, cert_raw, _poll = self.cahandler.enroll(self.csr_b64url)
        self.assertEqual("profile denied", error)
        self.assertIsNone(bundle)
        self.assertIsNone(cert_raw)

    @patch(
        "acme2certifier.cahandlers.xipki_ca_handler.eab_profile_header_info_check",
        return_value=None,
    )
    @patch("acme2certifier.cahandlers.xipki_ca_handler.CAhandler._cacert_cache")
    @patch("acme2certifier.cahandlers.xipki_ca_handler.CAhandler._enroll_post")
    def test_016_enroll_http_error(self, mock_enroll, mock_cache, _mock_eab):
        """enroll surfaces enrollment HTTP failure"""
        mock_cache.return_value = (None, self.ca_pem)
        mock_enroll.return_value = ("Enrollment failed: HTTP 401", None)
        error, bundle, cert_raw, _poll = self.cahandler.enroll(self.csr_b64url)
        self.assertIn("401", error)
        self.assertIsNone(bundle)
        self.assertIsNone(cert_raw)

    @patch("acme2certifier.cahandlers.xipki_ca_handler.CAhandler._http_request")
    def test_017_enroll_post(self, mock_http):
        """_enroll_post posts PKCS#10"""
        self.cahandler.api_host = "https://xipki.example/gw/rest/ca"
        self.cahandler.profile = "tls"
        mock_http.return_value = (200, self.leaf_der, "ok")
        error, leaf = self.cahandler._enroll_post(b"csr-der")
        self.assertIsNone(error)
        self.assertEqual(self.leaf_der, leaf)
        args, kwargs = mock_http.call_args
        self.assertEqual("POST", args[0])
        self.assertIn("enroll-cert?profile=tls", args[1])
        self.assertEqual(b"csr-der", kwargs.get("data") or args[2])

    @patch("acme2certifier.cahandlers.xipki_ca_handler.CAhandler._cacert_cache")
    @patch("acme2certifier.cahandlers.xipki_ca_handler.CAhandler._http_request")
    def test_018_revoke_success(self, mock_http, mock_cache):
        """revoke succeeds"""
        self.cahandler.api_host = "https://xipki.example/gw/rest/ca"
        self.cahandler._ca_sha1 = self.ca_sha1
        mock_cache.return_value = (None, self.ca_pem)
        mock_http.return_value = (200, b"", "")
        code, message, detail = self.cahandler.revoke(self.leaf_b64url, "keyCompromise")
        self.assertEqual(200, code)
        self.assertIsNone(message)
        self.assertIsNone(detail)
        _args, _kwargs = mock_http.call_args
        url = _args[1]
        self.assertIn("revoke-cert?", url)
        self.assertIn(f"ca-sha1={self.ca_sha1}", url)
        self.assertIn("serial-number=0x1234", url)
        self.assertIn("reason=KEY_COMPROMISE", url)

    @patch("acme2certifier.cahandlers.xipki_ca_handler.CAhandler._cacert_cache")
    @patch("acme2certifier.cahandlers.xipki_ca_handler.CAhandler._http_request")
    def test_019_revoke_http_error(self, mock_http, mock_cache):
        """revoke fails on non-200"""
        self.cahandler.api_host = "https://xipki.example/gw/rest/ca"
        self.cahandler._ca_sha1 = self.ca_sha1
        mock_cache.return_value = (None, self.ca_pem)
        mock_http.return_value = (400, b"", "bad request")
        code, message, detail = self.cahandler.revoke(self.leaf_b64url)
        self.assertEqual(400, code)
        self.assertTrue(message)
        self.assertEqual("bad request", detail)

    def test_020_revoke_missing_host(self):
        """revoke without api_host"""
        code, message, detail = self.cahandler.revoke(self.leaf_b64url)
        self.assertEqual(400, code)
        self.assertTrue(message)
        self.assertIn("api_host", detail)

    def test_021_http_request_exception(self):
        """_http_request returns 500 on connection errors"""
        self.cahandler.session = Mock()
        self.cahandler.session.request.side_effect = Exception("conn fail")
        self.cahandler.ca_bundle = True
        self.cahandler.proxy = None
        self.cahandler.request_timeout = 5
        code, content, text = self.cahandler._http_request("GET", "https://example")
        self.assertEqual(500, code)
        self.assertEqual(b"", content)
        self.assertIn("conn fail", text)

    def test_022_auth_set_incomplete(self):
        """_auth_set logs when user or password is missing."""
        self.cahandler.api_user = "user"
        self.cahandler.api_password = None
        with self.assertLogs("test_a2c", level="ERROR") as lcm:
            self.cahandler._auth_set()
        self.assertIn(
            'Auth incomplete. Either "api_user" or "api_password" is missing',
            lcm.output[0],
        )
        self.assertIsNone(self.cahandler.session.auth)

    @patch("acme2certifier.cahandlers.xipki_ca_handler.load_config")
    def test_023_config_load_bad_timeout(self, mock_load_cfg):
        """Invalid request_timeout falls back to 20 and is logged."""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {
            "api_host": "https://xipki.example/gw/rest/ca",
            "api_user": "user",
            "api_password": "secret",
            "profile": "tls",
            "request_timeout": "nope",
        }
        mock_load_cfg.return_value = parser
        with patch(
            "acme2certifier.cahandlers.xipki_ca_handler.config_option_load",
            side_effect=lambda _l, _c, option, current=None: {
                "api_user": "user",
                "api_password": "secret",
            }.get(option, current),
        ):
            with patch(
                "acme2certifier.cahandlers.xipki_ca_handler.config_ca_bundle_load",
                return_value=True,
            ):
                with patch(
                    "acme2certifier.cahandlers.xipki_ca_handler.config_proxy_load",
                    return_value={},
                ):
                    with patch(
                        "acme2certifier.cahandlers.xipki_ca_handler.config_eab_profile_load",
                        return_value=(False, None),
                    ):
                        with patch(
                            "acme2certifier.cahandlers.xipki_ca_handler.config_profile_load",
                            return_value={},
                        ):
                            with patch(
                                "acme2certifier.cahandlers.xipki_ca_handler.config_headerinfo_load",
                                return_value=False,
                            ):
                                with patch(
                                    "acme2certifier.cahandlers.xipki_ca_handler.config_enroll_config_log_load",
                                    return_value=(False, []),
                                ):
                                    with self.assertLogs(
                                        "test_a2c", level="ERROR"
                                    ) as lcm:
                                        self.cahandler._config_load()
        self.assertEqual(20, self.cahandler.request_timeout)
        self.assertTrue(any("request_timeout" in line for line in lcm.output))

    def test_024_http_request_success(self):
        """_http_request returns status, body, and text from the session."""
        response = Mock()
        response.status_code = 204
        response.content = b"body"
        response.text = "body"
        self.cahandler.session = Mock()
        self.cahandler.session.request.return_value = response
        self.cahandler.ca_bundle = True
        self.cahandler.proxy = None
        self.cahandler.request_timeout = 5
        code, content, text = self.cahandler._http_request("GET", "https://example")
        self.assertEqual(204, code)
        self.assertEqual(b"body", content)
        self.assertEqual("body", text)

    def test_025_reason_normalize_blank(self):
        """Whitespace revocation reasons map to UNSPECIFIED."""
        self.assertEqual("UNSPECIFIED", self.cahandler._reason_normalize("   "))

    def test_026_cacert_cache_missing_host(self):
        """_cacert_cache fails when api_host is unset."""
        error, pem = self.cahandler._cacert_cache()
        self.assertIn("api_host", error)
        self.assertIsNone(pem)

    @patch("acme2certifier.cahandlers.xipki_ca_handler.CAhandler._http_request")
    def test_027_cacert_cache_appends_newline_and_parse_error(self, mock_http):
        """PEM without a trailing newline is normalized; bad /cacert is an error."""
        self.cahandler.api_host = "https://xipki.example/gw/rest/ca"
        mock_http.side_effect = [
            (200, b"CERTDATA", "CERTDATA"),
            (200, b"not-a-cert", "not-a-cert"),
        ]
        with self.assertLogs("test_a2c", level="ERROR") as lcm:
            error, pem = self.cahandler._cacert_cache()
        self.assertIn("Could not parse /cacert", error)
        self.assertIsNone(pem)
        self.assertTrue(self.cahandler._cacerts_pem.endswith("\n"))
        self.assertTrue(any("Could not parse /cacert" in line for line in lcm.output))

    @patch("acme2certifier.cahandlers.xipki_ca_handler.CAhandler._http_request")
    def test_028_cacert_cache_cacert_http_error(self, mock_http):
        """_cacert_cache reports a failed /cacert fetch."""
        self.cahandler.api_host = "https://xipki.example/gw/rest/ca"
        mock_http.side_effect = [
            (200, self.ca_pem.encode(), self.ca_pem),
            (404, b"", "missing"),
        ]
        with self.assertLogs("test_a2c", level="ERROR") as lcm:
            error, pem = self.cahandler._cacert_cache()
        self.assertIn("Could not fetch /cacert: HTTP 404", error)
        self.assertIn("missing", error)
        self.assertIsNone(pem)
        self.assertTrue(any("Could not fetch /cacert" in line for line in lcm.output))

    def test_029_enroll_post_missing_host(self):
        """_enroll_post fails when api_host is unset."""
        error, leaf = self.cahandler._enroll_post(b"csr-der")
        self.assertIn("api_host", error)
        self.assertIsNone(leaf)

    def test_030_enroll_post_missing_profile(self):
        """_enroll_post fails when profile is unset."""
        self.cahandler.api_host = "https://xipki.example/gw/rest/ca"
        error, leaf = self.cahandler._enroll_post(b"csr-der")
        self.assertIn("profile", error)
        self.assertIsNone(leaf)

    @patch("acme2certifier.cahandlers.xipki_ca_handler.enrollment_config_log")
    @patch("acme2certifier.cahandlers.xipki_ca_handler.CAhandler._http_request")
    def test_031_enroll_post_logs_config(self, mock_http, mock_log):
        """enrollment_config_log is emitted before the enroll POST."""
        self.cahandler.api_host = "https://xipki.example/gw/rest/ca"
        self.cahandler.profile = "tls"
        self.cahandler.enrollment_config_log = True
        self.cahandler.enrollment_config_log_skip_list = ["api_password"]
        mock_http.return_value = (200, self.leaf_der, "ok")
        error, leaf = self.cahandler._enroll_post(b"csr-der")
        self.assertIsNone(error)
        self.assertEqual(self.leaf_der, leaf)
        self.assertTrue(mock_log.called)

    @patch("acme2certifier.cahandlers.xipki_ca_handler.CAhandler._http_request")
    def test_032_enroll_post_http_error(self, mock_http):
        """_enroll_post includes the response text in the error."""
        self.cahandler.api_host = "https://xipki.example/gw/rest/ca"
        self.cahandler.profile = "tls"
        mock_http.return_value = (401, b"", "denied")
        with self.assertLogs("test_a2c", level="ERROR") as lcm:
            error, leaf = self.cahandler._enroll_post(b"csr-der")
        self.assertEqual("Enrollment failed: HTTP 401 - denied", error)
        self.assertIsNone(leaf)
        self.assertIn("ERROR:test_a2c:Enrollment failed: HTTP 401 - denied", lcm.output)

    def test_033_bundle_create_bad_der(self):
        """_bundle_create reports a certificate that cannot be parsed."""
        with self.assertLogs("test_a2c", level="ERROR") as lcm:
            error, bundle, raw = self.cahandler._bundle_create(b"not-der", self.ca_pem)
        self.assertIn("Certificate parse failed", error)
        self.assertIsNone(bundle)
        self.assertIsNone(raw)
        self.assertTrue(any("Certificate parse failed" in line for line in lcm.output))

    @patch(
        "acme2certifier.cahandlers.xipki_ca_handler.eab_profile_header_info_check",
        return_value=None,
    )
    @patch("acme2certifier.cahandlers.xipki_ca_handler.CAhandler._cacert_cache")
    def test_034_enroll_invalid_csr(self, mock_cache, _mock_eab):
        """enroll rejects a CSR that is not valid base64."""
        mock_cache.return_value = (None, self.ca_pem)
        with self.assertLogs("test_a2c", level="ERROR") as lcm:
            error, bundle, cert_raw, _poll = self.cahandler.enroll("abc$")
        self.assertIn("Invalid CSR", error)
        self.assertIsNone(bundle)
        self.assertIsNone(cert_raw)
        self.assertTrue(any("Invalid CSR" in line for line in lcm.output))

    @patch("acme2certifier.cahandlers.xipki_ca_handler.eab_profile_revocation_check")
    def test_035_revoke_runs_eab_revocation_check(self, mock_check):
        """eab profiling runs the revocation profile check."""
        self.cahandler.eab_profiling = True
        code, _message, detail = self.cahandler.revoke(self.leaf_b64url)
        self.assertEqual(400, code)
        self.assertIn("api_host", detail)
        mock_check.assert_called_once()

    @patch("acme2certifier.cahandlers.xipki_ca_handler.CAhandler._cacert_cache")
    def test_036_revoke_cache_error(self, mock_cache):
        """revoke stops when the CA certificate cache fails."""
        self.cahandler.api_host = "https://xipki.example/gw/rest/ca"
        mock_cache.return_value = ("Could not fetch /cacerts: HTTP 500", None)
        code, _message, detail = self.cahandler.revoke(self.leaf_b64url)
        self.assertEqual(400, code)
        self.assertEqual("Could not fetch /cacerts: HTTP 500", detail)

    @patch("acme2certifier.cahandlers.xipki_ca_handler.CAhandler._cacert_cache")
    def test_037_revoke_bad_certificate(self, mock_cache):
        """revoke rejects a certificate whose serial cannot be parsed."""
        self.cahandler.api_host = "https://xipki.example/gw/rest/ca"
        self.cahandler._ca_sha1 = self.ca_sha1
        mock_cache.return_value = (None, self.ca_pem)
        with self.assertLogs("test_a2c", level="ERROR") as lcm:
            code, _message, detail = self.cahandler.revoke("%%%")
        self.assertEqual(400, code)
        self.assertIn("Invalid certificate", detail)
        self.assertTrue(
            any("Could not parse certificate serial" in line for line in lcm.output)
        )


if __name__ == "__main__":
    unittest.main()
