#!/usr/bin/python
# -*- coding: utf-8 -*-
"""unittests for mscepces_ca_handler"""

# pylint: disable=C0415, R0904, W0212
import configparser
import os
import sys
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, ".")
sys.path.insert(1, "..")

FIXTURE_DIR = os.path.join(os.path.dirname(__file__), "fixtures", "mscepces")
TEST_CSR_B64 = (
    "MIICWzCCAUMCAQAwFjEUMBIGA1UEAwwLY3NyLmV4YW1wbGUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDZc7ufN9Qocu_"
    "NveBvh_utfiviR-WhcaodKwLztOnC8ze_fZq2klfoiRreq5px9Vt0_VhnNeyjAShPAiCvTkosQACgV77PPPSFlEC7R6cJSeKLBC-W9"
    "Mdu9C5tsuhT1IJl62AM4e4xoYGhYpcQY-HxsLKr9H5J1OfT4uwau62JiAhs1Ff3pG4A7wIeaZjSIuUsv6ErohSkvM8PuifW-tipWjt"
    "Hnb0zdbhRkmJqfFOvJ8QrVZn18RweZdNgrHQSxDljJgp5GSiSsw3M7qrao812xBZzFekPvbKb1fJ6xHiGiZbE6E1OfhqJk6Q3vGXCm"
    "6tu8zB14EGUkpfiNCc1JnPpAgMBAAGgADANBgkqhkiG9w0BAQsFAAOCAQEAKQjNrkw3lE0EcskB6_tGZl5k1PQK0buJGwXoa8A_8XVb"
    "HxuSCDbVGUXwQjHDccPOiYdWPGzwqX0l5WmLheDXWDdCGNrwh2unBxn9Ro5T33LlEKWHUOvk1ypBtlB8yBeaV6Ny7aLSm9RZeQ-TMge"
    "Lv8Yk9Zs1uV7_I32vaPbA4ryYTkIkl_OL467MkUh3r3c2BLQxe1KYUmNhL9AyYGG6W9zk2qbQ5v8QZ-v5PLFnOsLyY10usvx6ApQGnn"
    "_PxQQbpT4OFYQZRyNqwnMrwT6_lEpiB4wg0t6VTG_kXroCFXV9Ok-lOW9lTVdn2GrZzwk_K6xJ64lmxsZjzmBNOBJvCg"
)


def _fixture(name: str) -> str:
    with open(os.path.join(FIXTURE_DIR, name), encoding="utf-8") as handle:
        return handle.read()


class TestMscepcesCaHandler(unittest.TestCase):
    """test class for mscepces_ca_handler"""

    def setUp(self):
        """setup unittest"""
        import logging
        from acme2certifier.cahandlers.mscepces_ca_handler import CAhandler

        logging.basicConfig(level=logging.CRITICAL)
        self.logger = logging.getLogger("test_a2c")
        self.cahandler = CAhandler(False, self.logger)

    def test_001_default(self):
        """default smoke test"""
        self.assertEqual("foo", "foo")

    def test_002_parse_xcep_get_policies(self):
        """parse GetPoliciesResponse templates and CES URIs"""
        from acme2certifier.cahandlers.mscepces_ca_handler import (
            _parse_xcep_get_policies,
        )

        result = _parse_xcep_get_policies(_fixture("xcep_get_policies_response.xml"))
        self.assertIn("WebServer", result["templates"])
        self.assertIn("User", result["templates"])
        self.assertTrue(result["ces_uris"][0].endswith("/CES"))
        self.assertEqual(1, len(result["ca_certificates"]))
        self.assertIn("BEGIN CERTIFICATE", result["ca_certificates"][0])

    def test_003_parse_wstep_issued(self):
        """parse issued WSTEP response"""
        from acme2certifier.cahandlers.mscepces_ca_handler import _parse_wstep_response

        result = _parse_wstep_response(_fixture("wstep_issue_issued.xml"))
        self.assertEqual("issued", result["status"])
        self.assertEqual("42", result["request_id"])
        self.assertTrue(result["token"])

    def test_004_parse_wstep_pending(self):
        """parse pending WSTEP response"""
        from acme2certifier.cahandlers.mscepces_ca_handler import _parse_wstep_response

        result = _parse_wstep_response(_fixture("wstep_issue_pending.xml"))
        self.assertEqual("pending", result["status"])
        self.assertEqual("111", result["request_id"])
        self.assertIn("service.svc/CES", result["reference"])

    def test_005_parse_wstep_denied(self):
        """parse denied WSTEP response"""
        from acme2certifier.cahandlers.mscepces_ca_handler import _parse_wstep_response

        result = _parse_wstep_response(_fixture("wstep_issue_denied.xml"))
        self.assertEqual("denied", result["status"])

    def test_006_parse_soap_fault(self):
        """SOAP Fault raises RuntimeError"""
        from acme2certifier.cahandlers.mscepces_ca_handler import _parse_wstep_response

        with self.assertRaises(RuntimeError) as ctx:
            _parse_wstep_response(_fixture("soap_fault.xml"))
        self.assertIn("Authentication failed", str(ctx.exception))

    def test_007_wstep_issue_body_contains_template(self):
        """Issue body includes AdditionalContext CertificateTemplate"""
        from acme2certifier.cahandlers.mscepces_ca_handler import _wstep_issue_body
        from xml.etree import ElementTree as ET

        body = _wstep_issue_body("AAAA", "WebServer")
        xml = ET.tostring(body, encoding="unicode")
        self.assertIn("CertificateTemplate", xml)
        self.assertIn("WebServer", xml)
        self.assertIn("AAAA", xml)

    def test_008_poll_identifier_roundtrip(self):
        """poll identifier encode/decode"""
        from acme2certifier.cahandlers.mscepces_ca_handler import (
            _poll_identifier_decode,
            _poll_identifier_encode,
        )

        encoded = _poll_identifier_encode(
            "111", "https://ces.example.com/TestCA_CES_Kerberos/service.svc/CES"
        )
        request_id, reference = _poll_identifier_decode(encoded)
        self.assertEqual("111", request_id)
        self.assertTrue(reference.endswith("/CES"))

    @patch("acme2certifier.cahandlers.mscepces_ca_handler.load_config")
    def test_009_config_load(self, mock_load_cfg):
        """load ces_url/template/auth_method"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {
            "ces_url": "https://ces.example.com/CA_CES_Kerberos/service.svc/CES",
            "cep_url": "https://cep.example.com/ADPolicyProvider_CEP_Kerberos/service.svc/CEP",
            "template": "WebServer",
            "auth_method": "username_password",
            "ces_username": "user",
            "ces_password": "pass",
        }
        mock_load_cfg.return_value = parser
        self.cahandler._config_load()
        self.assertTrue(self.cahandler.ces_url.startswith("https://ces."))
        self.assertEqual("WebServer", self.cahandler.template)
        self.assertEqual("username_password", self.cahandler.auth_method)
        self.assertEqual("user", self.cahandler.ces_username)
        self.assertEqual("user", self.cahandler.user)

    @patch("acme2certifier.cahandlers.mscepces_ca_handler.load_config")
    def test_010_handler_check_missing_ces_url(self, mock_load_cfg):
        """handler_check fails without ces_url"""
        mock_load_cfg.return_value = configparser.ConfigParser()
        self.cahandler._config_load()
        error = self.cahandler.handler_check()
        self.assertIn("ces_url", error)

    @patch("acme2certifier.cahandlers.mscepces_ca_handler.CAhandler._soap_post")
    @patch("acme2certifier.cahandlers.mscepces_ca_handler.load_config")
    def test_011_enroll_issued(self, mock_load_cfg, mock_soap):
        """enroll returns certificate for Issued disposition"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {
            "ces_url": "https://ces.example.com/CA_CES_Kerberos/service.svc/CES",
            "template": "WebServer",
            "auth_method": "username_password",
            "ces_username": "user",
            "ces_password": "pass",
            "ca_templates_check": "off",
        }
        mock_load_cfg.return_value = parser
        mock_soap.return_value = _fixture("wstep_issue_issued.xml")
        self.cahandler._config_load()
        error, cert_bundle, cert_raw, poll_id = self.cahandler.enroll(TEST_CSR_B64)
        self.assertIsNone(error)
        self.assertIsNone(poll_id)
        self.assertTrue(cert_raw)
        self.assertIn("BEGIN CERTIFICATE", cert_bundle)

    @patch("acme2certifier.cahandlers.mscepces_ca_handler.CAhandler._soap_post")
    @patch("acme2certifier.cahandlers.mscepces_ca_handler.load_config")
    def test_012_enroll_pending(self, mock_load_cfg, mock_soap):
        """enroll returns poll identifier for Pending disposition"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {
            "ces_url": "https://ces.example.com/CA_CES_Kerberos/service.svc/CES",
            "template": "WebServer",
            "auth_method": "username_password",
            "ces_username": "user",
            "ces_password": "pass",
            "ca_templates_check": "off",
        }
        mock_load_cfg.return_value = parser
        mock_soap.return_value = _fixture("wstep_issue_pending.xml")
        self.cahandler._config_load()
        error, cert_bundle, cert_raw, poll_id = self.cahandler.enroll(TEST_CSR_B64)
        self.assertIsNone(error)
        self.assertIsNone(cert_bundle)
        self.assertIsNone(cert_raw)
        self.assertTrue(poll_id.startswith("111@@"))

    @patch("acme2certifier.cahandlers.mscepces_ca_handler.CAhandler._soap_post")
    @patch("acme2certifier.cahandlers.mscepces_ca_handler.load_config")
    def test_013_enroll_denied(self, mock_load_cfg, mock_soap):
        """enroll returns error for Denied disposition"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {
            "ces_url": "https://ces.example.com/CA_CES_Kerberos/service.svc/CES",
            "template": "WebServer",
            "auth_method": "username_password",
            "ces_username": "user",
            "ces_password": "pass",
            "ca_templates_check": "off",
        }
        mock_load_cfg.return_value = parser
        mock_soap.return_value = _fixture("wstep_issue_denied.xml")
        self.cahandler._config_load()
        error, cert_bundle, cert_raw, poll_id = self.cahandler.enroll(TEST_CSR_B64)
        self.assertIn("denied", error.lower())
        self.assertIsNone(cert_bundle)
        self.assertIsNone(cert_raw)
        self.assertIsNone(poll_id)

    @patch("acme2certifier.cahandlers.mscepces_ca_handler.CAhandler._soap_post")
    @patch("acme2certifier.cahandlers.mscepces_ca_handler.load_config")
    def test_014_poll_issued(self, mock_load_cfg, mock_soap):
        """poll returns certificate when pending request is issued"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {
            "ces_url": "https://ces.example.com/CA_CES_Kerberos/service.svc/CES",
            "template": "WebServer",
            "auth_method": "username_password",
            "ces_username": "user",
            "ces_password": "pass",
        }
        mock_load_cfg.return_value = parser
        mock_soap.return_value = _fixture("wstep_poll_issued.xml")
        self.cahandler._config_load()
        error, cert_bundle, cert_raw, poll_id, rejected = self.cahandler.poll(
            "cert",
            "111@@https://ces.example.com/CA_CES_Kerberos/service.svc/CES",
            TEST_CSR_B64,
        )
        self.assertIsNone(error)
        self.assertFalse(rejected)
        self.assertTrue(cert_raw)
        self.assertIn("BEGIN CERTIFICATE", cert_bundle)

    def test_015_revoke_not_supported(self):
        """revoke is stubbed"""
        code, message, detail = self.cahandler.revoke("cert", "unspecified", None)
        self.assertEqual(500, code)
        self.assertIn("serverInternal", message)
        self.assertEqual("Revocation is not supported.", detail)

    def test_016_https_required(self):
        """cleartext ces_url rejected"""
        self.cahandler.ces_url = "http://ces.example.com/CES"
        self.cahandler.template = "WebServer"
        self.cahandler.auth_method = "username_password"
        self.cahandler.ces_username = "user"
        self.cahandler.ces_password = "pass"
        self.cahandler.user = "user"
        self.cahandler.password = "pass"
        error, _, _, _ = self.cahandler.enroll(TEST_CSR_B64)
        self.assertIn("HTTPS", error)

    @patch("acme2certifier.cahandlers.mscepces_ca_handler.CAhandler._soap_post")
    def test_017_soap_post_action_for_issue(self, mock_soap):
        """Issue uses WSTEP RST action"""
        from acme2certifier.cahandlers.mscepces_ca_handler import ACTION_WSTEP_RST

        mock_soap.return_value = _fixture("wstep_issue_issued.xml")
        self.cahandler.ces_url = "https://ces.example.com/CES"
        self.cahandler.template = "WebServer"
        self.cahandler.auth_method = "username_password"
        self.cahandler.ces_username = "u"
        self.cahandler.ces_password = "p"
        self.cahandler.user = "u"
        self.cahandler.password = "p"
        self.cahandler.ca_templates_check = "off"
        self.cahandler._enroll(TEST_CSR_B64)
        args, _kwargs = mock_soap.call_args
        self.assertEqual(ACTION_WSTEP_RST, args[1])

    @patch("acme2certifier.cahandlers.mscepces_ca_handler.CAhandler._soap_post")
    @patch("acme2certifier.cahandlers.mscepces_ca_handler.load_config")
    def test_018_enroll_appends_cep_ca(self, mock_load_cfg, mock_soap):
        """issued leaf is bundled with CA cert from CEP GetPolicies"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {
            "ces_url": "https://ces.example.com/CA_CES_Kerberos/service.svc/CES",
            "cep_url": "https://cep.example.com/ADPolicyProvider_CEP_Kerberos/service.svc/CEP",
            "template": "WebServer",
            "auth_method": "username_password",
            "ces_username": "user",
            "ces_password": "pass",
            "ca_templates_check": "off",
        }
        mock_load_cfg.return_value = parser
        mock_soap.side_effect = [
            _fixture("wstep_issue_issued.xml"),
            _fixture("xcep_get_policies_response.xml"),
        ]
        self.cahandler._config_load()
        error, cert_bundle, cert_raw, poll_id = self.cahandler.enroll(TEST_CSR_B64)
        self.assertIsNone(error)
        self.assertIsNone(poll_id)
        self.assertTrue(cert_raw)
        self.assertEqual(2, cert_bundle.count("BEGIN CERTIFICATE"))
        # issuing CA from CEP fixture (CN=mscepces-test-ca) is second PEM block
        second = cert_bundle.split("-----END CERTIFICATE-----")[1]
        self.assertIn("MIICrzCCAZegAwIBAgIBAT", second)


if __name__ == "__main__":
    unittest.main()
