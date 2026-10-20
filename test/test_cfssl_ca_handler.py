#!/usr/bin/python
# -*- coding: utf-8 -*-
"""unittests for cfssl_ca_handler"""

# pylint: disable=C0415, R0904, W0212
import base64
import configparser
import datetime
import hashlib
import hmac
import json
import logging
import os
import sys
import unittest
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

sys.path.insert(0, ".")
sys.path.insert(1, "..")


def _make_ca_and_leaf():
    """Build a CA, a leaf with AKI, and a CSR."""
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "CFSSL Test CA")])
    now = datetime.datetime.now(datetime.timezone.utc)
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(issuer)
        .issuer_name(issuer)
        .public_key(ca_key.public_key())
        .serial_number(0xABCD)
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),
            critical=False,
        )
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
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
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


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _ok(result):
    return 200, {"success": True, "result": result, "errors": [], "messages": []}


class TestCFSSLHandler(unittest.TestCase):
    """test class for cfssl_ca_handler"""

    @classmethod
    def setUpClass(cls):
        ca_cert, leaf, csr = _make_ca_and_leaf()
        cls.ca_pem = ca_cert.public_bytes(serialization.Encoding.PEM).decode()
        cls.leaf_pem = leaf.public_bytes(serialization.Encoding.PEM).decode()
        cls.leaf_b64url = _b64url(leaf.public_bytes(serialization.Encoding.DER))
        cls.csr_b64url = _b64url(csr.public_bytes(serialization.Encoding.DER))
        cls.aki = leaf.extensions.get_extension_for_class(
            x509.AuthorityKeyIdentifier
        ).value.key_identifier.hex()

    def setUp(self):
        """setup unittest"""
        from acme2certifier.cahandlers.cfssl_ca_handler import CAhandler

        logging.basicConfig(level=logging.CRITICAL)
        self.logger = logging.getLogger("test_a2c")
        self.cahandler = CAhandler(False, self.logger)
        self.cahandler.cfssl_url = "http://cfssl:8888"

    def _config_parser(self, section=None):
        parser = configparser.ConfigParser()
        parser["CAhandler"] = section or {}
        return parser

    def _patch_loaders(
        self, parser, eab=(False, None), profiles=None, header=False, enroll=(False, [])
    ):
        stack = [
            patch(
                "acme2certifier.cahandlers.cfssl_ca_handler.load_config",
                return_value=parser,
            ),
            patch(
                "acme2certifier.cahandlers.cfssl_ca_handler.config_ca_bundle_load",
                return_value=True,
            ),
            patch(
                "acme2certifier.cahandlers.cfssl_ca_handler.config_proxy_load",
                return_value={},
            ),
            patch(
                "acme2certifier.cahandlers.cfssl_ca_handler.config_eab_profile_load",
                return_value=eab,
            ),
            patch(
                "acme2certifier.cahandlers.cfssl_ca_handler.config_profile_load",
                return_value={} if profiles is None else profiles,
            ),
            patch(
                "acme2certifier.cahandlers.cfssl_ca_handler.config_headerinfo_load",
                return_value=header,
            ),
            patch(
                "acme2certifier.cahandlers.cfssl_ca_handler.config_enroll_config_log_load",
                return_value=enroll,
            ),
        ]
        for item in stack:
            item.start()
            self.addCleanup(item.stop)

    @patch("acme2certifier.cahandlers.cfssl_ca_handler.CAhandler._config_load")
    def test_enter_loads_config(self, mock_cfg):
        """__enter__ loads config when cfssl_url is unset"""
        self.cahandler.cfssl_url = None
        with self.cahandler:
            self.assertTrue(mock_cfg.called)

    @patch("acme2certifier.cahandlers.cfssl_ca_handler.CAhandler._config_load")
    def test_enter_skips_when_configured(self, mock_cfg):
        """__enter__ skips config when cfssl_url is set"""
        with self.cahandler:
            self.assertFalse(mock_cfg.called)

    def test_poll_and_trigger(self):
        """poll and trigger are not implemented"""
        self.assertEqual(
            ("Method not implemented.", None, None, "poll_id", False),
            self.cahandler.poll("cert", "poll_id", "csr"),
        )
        self.assertEqual(
            ("Method not implemented.", None, None),
            self.cahandler.trigger("payload"),
        )

    def test_handler_check(self):
        """handler_check requires cfssl_url"""
        self.assertIsNone(self.cahandler.handler_check())
        self.cahandler.cfssl_url = None
        self.assertTrue(self.cahandler.handler_check())

    def test_config_load(self):
        """_config_load sets url, profile, label, auth key, and timeouts"""
        parser = self._config_parser(
            {
                "cfssl_url": "http://cfssl:8888/",
                "profile": "server",
                "label": "primary",
                "auth_key": "abcd",
                "chain_file": "/tmp/chain.pem",
                "request_timeout": "15",
                "request_retries": "4",
                "request_retry_backoff": "1.5",
            }
        )
        self._patch_loaders(parser)
        self.cahandler.cfssl_url = None
        self.cahandler._config_load()
        self.assertEqual("http://cfssl:8888/", self.cahandler.cfssl_url)
        self.assertEqual("server", self.cahandler.profile)
        self.assertEqual("primary", self.cahandler.label)
        self.assertEqual("abcd", self.cahandler.auth_key)
        self.assertEqual("/tmp/chain.pem", self.cahandler.chain_file)
        self.assertEqual(15, self.cahandler.request_timeout)
        self.assertEqual(4, self.cahandler.request_retries)
        self.assertEqual(1.5, self.cahandler.request_retry_backoff)

    def test_config_load_bad_numbers_and_missing_url(self):
        """bad numeric options are logged and cfssl_url is required"""
        parser = self._config_parser(
            {
                "request_timeout": "nope",
                "request_retries": "nope",
                "request_retry_backoff": "nope",
            }
        )
        self._patch_loaders(parser)
        self.cahandler.cfssl_url = None
        with self.assertLogs("test_a2c", level="ERROR") as logs:
            self.cahandler._config_load()
        self.assertEqual(20, self.cahandler.request_timeout)
        self.assertEqual(3, self.cahandler.request_retries)
        self.assertEqual(2.0, self.cahandler.request_retry_backoff)
        self.assertTrue(any("cfssl_url" in line for line in logs.output))

    def test_config_load_missing_section(self):
        """a config without CAhandler still reports the missing url"""
        parser = configparser.ConfigParser()
        self._patch_loaders(parser)
        self.cahandler.cfssl_url = None
        with self.assertLogs("test_a2c", level="ERROR") as logs:
            self.cahandler._config_load()
        self.assertIsNone(self.cahandler.cfssl_url)
        self.assertTrue(any("cfssl_url" in line for line in logs.output))

    def test_sign_body_and_auth_wrap(self):
        """profile and label are optional; authsign HMAC covers the raw JSON"""
        body = self.cahandler._sign_body("CSR")
        self.assertEqual({"certificate_request": "CSR"}, body)
        self.cahandler.profile = "server"
        self.cahandler.label = "primary"
        body = self.cahandler._sign_body("CSR")
        self.assertEqual("server", body["profile"])
        self.assertEqual("primary", body["label"])

        self.cahandler.auth_key = "000102030405060708090a0b0c0d0e0f"
        error, wrapped = self.cahandler._auth_wrap(body)
        self.assertIsNone(error)
        raw = json.dumps(body, separators=(",", ":")).encode("utf-8")
        digest = hmac.new(
            bytes.fromhex(self.cahandler.auth_key), raw, hashlib.sha256
        ).digest()
        self.assertEqual(base64.b64encode(digest).decode("ascii"), wrapped["token"])
        self.assertEqual(base64.b64encode(raw).decode("ascii"), wrapped["request"])

        self.cahandler.auth_key = "zz"
        error, wrapped = self.cahandler._auth_wrap(body)
        self.assertIn("auth_key", error)
        self.assertIsNone(wrapped)

    def test_result_get(self):
        """CFSSL envelopes: HTTP errors, success false, and a missing field"""
        error, result = self.cahandler._result_get(500, "boom")
        self.assertIn("boom", error)
        self.assertIsNone(result)
        error, result = self.cahandler._result_get(500, {"success": False})
        self.assertIn("500", error)
        error, result = self.cahandler._result_get(
            200, {"success": False, "errors": [{"message": "no"}]}
        )
        self.assertIn("no", error)
        error, result = self.cahandler._result_get(200, {"success": True, "result": []})
        self.assertIn("missing result", error)
        error, result = self.cahandler._result_get(
            200, {"success": True, "result": {}}, required="certificate"
        )
        self.assertIn("certificate", error)
        error, result = self.cahandler._result_get(200, {"success": True, "result": {}})
        self.assertIsNone(error)
        self.assertEqual({}, result)

    def test_chain_extra(self):
        """chain_file is optional, appended, and reported when unreadable"""
        error, extra = self.cahandler._chain_extra()
        self.assertIsNone(error)
        self.assertEqual("", extra)

        path = os.path.join(self._tmp(), "chain.pem")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(self.ca_pem.strip())
        self.cahandler.chain_file = path
        error, extra = self.cahandler._chain_extra()
        self.assertIsNone(error)
        self.assertTrue(extra.endswith("\n"))
        self.assertIn("BEGIN CERTIFICATE", extra)

        self.cahandler.chain_file = os.path.join(self._tmp(), "missing.pem")
        error, extra = self.cahandler._chain_extra()
        self.assertIn("chain_file", error)
        self.assertEqual("", extra)

        empty = os.path.join(self._tmp(), "empty.pem")
        with open(empty, "w", encoding="utf-8") as handle:
            handle.write("   \n")
        self.cahandler.chain_file = empty
        error, extra = self.cahandler._chain_extra()
        self.assertIsNone(error)
        self.assertEqual("", extra)

    def _tmp(self):
        import tempfile

        path = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(path, ignore_errors=True))
        return path

    @patch("acme2certifier.cahandlers.cfssl_ca_handler.ca_api_request")
    @patch(
        "acme2certifier.cahandlers.cfssl_ca_handler.eab_profile_header_info_check",
        return_value=None,
    )
    def test_enroll_success(self, _eab, mock_api):
        """enroll returns the leaf plus the signer from /info"""
        mock_api.side_effect = [
            _ok({"certificate": self.leaf_pem.strip()}),
            _ok({"certificate": self.ca_pem}),
        ]
        error, bundle, raw, poll_id = self.cahandler.enroll(self.csr_b64url)
        self.assertIsNone(error)
        self.assertIsNone(poll_id)
        self.assertIn("BEGIN CERTIFICATE", bundle)
        self.assertEqual(bundle.count("BEGIN CERTIFICATE"), 2)
        self.assertEqual(
            base64.b64decode(raw),
            base64.b64decode(self.leaf_pem.split("-----")[2].replace("\n", "")),
        )
        sign_payload = mock_api.call_args_list[0].kwargs["payload"]
        self.assertIn("BEGIN CERTIFICATE REQUEST", sign_payload["certificate_request"])
        self.assertNotIn("profile", sign_payload)

        mock_api.reset_mock()
        mock_api.side_effect = [_ok({"certificate": self.leaf_pem})]
        error, bundle, _raw, _poll = self.cahandler.enroll(self.csr_b64url)
        self.assertIsNone(error)
        self.assertEqual(mock_api.call_count, 1)

    @patch("acme2certifier.cahandlers.cfssl_ca_handler.enrollment_config_log")
    @patch("acme2certifier.cahandlers.cfssl_ca_handler.ca_api_request")
    @patch(
        "acme2certifier.cahandlers.cfssl_ca_handler.eab_profile_header_info_check",
        return_value=None,
    )
    def test_enroll_authsign_profile_label_and_chain(self, _eab, mock_api, mock_log):
        """authsign, profile, label, chain_file, and enrollment logging"""
        self.cahandler.profile = "server"
        self.cahandler.label = "primary"
        self.cahandler.auth_key = "0f0e0d0c0b0a09080706050403020100"
        self.cahandler.enrollment_config_log = True
        self.cahandler.enrollment_config_log_skip_list = "not-a-list"
        path = os.path.join(self._tmp(), "root.pem")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(self.ca_pem)
        self.cahandler.chain_file = path
        mock_api.side_effect = [
            _ok({"certificate": self.leaf_pem}),
            _ok({"certificate": "  " + self.ca_pem + "  "}),
        ]
        error, bundle, _raw, _poll = self.cahandler.enroll(self.csr_b64url)
        self.assertIsNone(error)
        self.assertEqual(bundle.count("BEGIN CERTIFICATE"), 3)
        self.assertEqual(
            mock_api.call_args_list[0].args[2].rsplit("/", 1)[-1], "authsign"
        )
        wrapped = mock_api.call_args_list[0].kwargs["payload"]
        inner = json.loads(base64.b64decode(wrapped["request"]))
        self.assertEqual("server", inner["profile"])
        self.assertEqual("primary", inner["label"])
        self.assertTrue(mock_log.called)
        self.assertIn("auth_key", mock_log.call_args.args[2])

    @patch(
        "acme2certifier.cahandlers.cfssl_ca_handler.eab_profile_header_info_check",
        return_value="bad csr",
    )
    def test_enroll_eab_error(self, _eab):
        """profiling failures are returned as the enroll error"""
        error, bundle, raw, poll_id = self.cahandler.enroll(self.csr_b64url)
        self.assertEqual("bad csr", error)
        self.assertIsNone(bundle)
        self.assertIsNone(raw)
        self.assertIsNone(poll_id)

    @patch(
        "acme2certifier.cahandlers.cfssl_ca_handler.eab_profile_header_info_check",
        return_value=None,
    )
    def test_enroll_missing_url_and_bad_csr(self, _eab):
        """missing url and a CSR that cannot be recoded fail before HTTP"""
        self.cahandler.cfssl_url = None
        error, *_rest = self.cahandler.enroll(self.csr_b64url)
        self.assertIn("cfssl_url", error)

        self.cahandler.cfssl_url = "http://cfssl:8888"
        with patch(
            "acme2certifier.cahandlers.cfssl_ca_handler.build_pem_file",
            side_effect=ValueError("nope"),
        ):
            error, *_rest = self.cahandler.enroll(self.csr_b64url)
        self.assertIn("Invalid CSR", error)

    @patch("acme2certifier.cahandlers.cfssl_ca_handler.ca_api_request")
    @patch(
        "acme2certifier.cahandlers.cfssl_ca_handler.eab_profile_header_info_check",
        return_value=None,
    )
    def test_enroll_http_and_parse_failures(self, _eab, mock_api):
        """sign, info, parse, auth, and chain failures stop enrollment"""
        mock_api.return_value = (500, "down")
        error, *_rest = self.cahandler.enroll(self.csr_b64url)
        self.assertIn("down", error)

        mock_api.return_value = _ok({"certificate": "not-a-certificate"})
        error, *_rest = self.cahandler.enroll(self.csr_b64url)
        self.assertIn("Certificate parse failed", error)

        mock_api.side_effect = [
            _ok({"certificate": self.leaf_pem}),
            (500, "info down"),
        ]
        error, bundle, raw, _poll = self.cahandler.enroll(self.csr_b64url)
        self.assertIn("info down", error)
        self.assertIsNone(bundle)
        self.assertIsNone(raw)

        self.cahandler.auth_key = "zz"
        error, *_rest = self.cahandler.enroll(self.csr_b64url)
        self.assertIn("auth_key", error)

        self.cahandler.auth_key = None
        self.cahandler._signer_pem = None
        self.cahandler.chain_file = os.path.join(self._tmp(), "nope.pem")
        mock_api.side_effect = [
            _ok({"certificate": self.leaf_pem}),
            _ok({"certificate": self.ca_pem}),
        ]
        error, bundle, raw, _poll = self.cahandler.enroll(self.csr_b64url)
        self.assertIn("chain_file", error)
        self.assertIsNone(bundle)
        self.assertIsNone(raw)

    @patch("acme2certifier.cahandlers.cfssl_ca_handler.eab_profile_revocation_check")
    @patch("acme2certifier.cahandlers.cfssl_ca_handler.ca_api_request")
    def test_revoke_success(self, mock_api, mock_eab):
        """revoke posts decimal serial, lowercase AKI, and the reason"""
        self.cahandler.eab_profiling = True
        mock_api.return_value = _ok({})
        code, message, detail = self.cahandler.revoke(
            self.leaf_b64url, "keyCompromise", "20200101120000Z"
        )
        self.assertEqual(200, code)
        self.assertIsNone(message)
        self.assertIsNone(detail)
        payload = mock_api.call_args.kwargs["payload"]
        self.assertEqual("4660", payload["serial"])
        self.assertEqual(self.aki, payload["authority_key_id"])
        self.assertEqual("keyCompromise", payload["reason"])
        self.assertTrue(mock_eab.called)

        code, _message, _detail = self.cahandler.revoke(self.leaf_b64url, None, None)
        self.assertEqual("unspecified", mock_api.call_args.kwargs["payload"]["reason"])
        self.assertEqual(200, code)

    @patch("acme2certifier.cahandlers.cfssl_ca_handler.ca_api_request")
    def test_revoke_failures(self, mock_api):
        """missing url, unparsable cert, missing AKI, and API errors"""
        self.cahandler.cfssl_url = None
        code, _message, detail = self.cahandler.revoke(self.leaf_b64url)
        self.assertEqual(400, code)
        self.assertIn("cfssl_url", detail)

        self.cahandler.cfssl_url = "http://cfssl:8888"
        code, _message, detail = self.cahandler.revoke("%%%")
        self.assertEqual(400, code)
        self.assertIn("Invalid certificate", detail)

        with patch(
            "acme2certifier.cahandlers.cfssl_ca_handler.cert_aki_get",
            return_value=None,
        ):
            code, _message, detail = self.cahandler.revoke(self.leaf_b64url)
        self.assertEqual(400, code)
        self.assertIn("authority key identifier", detail)

        mock_api.return_value = (
            200,
            {"success": False, "errors": [{"message": "no row"}]},
        )
        code, _message, detail = self.cahandler.revoke(self.leaf_b64url)
        self.assertEqual(400, code)
        self.assertIn("no row", detail)

    @patch("acme2certifier.cahandlers.cfssl_ca_handler.enrollment_config_log")
    def test_enroll_log_skip_list(self, mock_log):
        """a list skip-list is extended with auth_key"""
        self.cahandler.enrollment_config_log = True
        self.cahandler.enrollment_config_log_skip_list = ["cfssl_url"]
        self.cahandler._enroll_log()
        self.assertEqual(["cfssl_url", "auth_key"], mock_log.call_args.args[2])
        self.cahandler.enrollment_config_log = False
        mock_log.reset_mock()
        self.cahandler._enroll_log()
        self.assertFalse(mock_log.called)
