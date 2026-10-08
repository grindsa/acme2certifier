#!/usr/bin/python
# -*- coding: utf-8 -*-
"""unittests for mscepces_ca_handler"""

# pylint: disable=C0415, R0904, W0212
import configparser
import os
import sys
import tempfile
import types
import unittest
from unittest.mock import MagicMock, mock_open, patch

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


def _fake_requests_gssapi(auth_cls):
    """Build a fake requests_gssapi module exposing HTTPSPNEGOAuth."""
    fake_mod = types.ModuleType("requests_gssapi")
    fake_mod.HTTPSPNEGOAuth = auth_cls
    return fake_mod


def _issued_token_b64() -> str:
    """Extract issued cert token from WSTEP fixture."""
    from acme2certifier.cahandlers.mscepces_ca_handler import _parse_wstep_response

    return _parse_wstep_response(_fixture("wstep_issue_issued.xml"))["token"]


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

    @patch("acme2certifier.cahandlers.mscepces_ca_handler.CAhandler._xcep_get_policies")
    @patch("acme2certifier.cahandlers.mscepces_ca_handler.load_config")
    def test_011_handler_check_skips_cep_contact(
        self, mock_load_cfg, mock_get_policies
    ):
        """handler_check is config-only; does not call CEP GetPolicies"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {
            "cep_url": "https://cep.example.com/CEP",
            "ces_url": "https://ces.example.com/CES",
            "template": "WebServer",
            "auth_method": "gssapi",
            "krb5_principal": "a2c-keytab@EXAMPLE.COM",
            "krb5_keytab": "/tmp/krb5.keytab",
            "ca_templates_check": "warn",
        }
        mock_load_cfg.return_value = parser
        self.cahandler._config_load()
        error = self.cahandler.handler_check()
        self.assertIsNone(error)
        mock_get_policies.assert_not_called()

    @patch("acme2certifier.cahandlers.mscepces_ca_handler.CAhandler._soap_post")
    @patch("acme2certifier.cahandlers.mscepces_ca_handler.load_config")
    def test_012_enroll_issued(self, mock_load_cfg, mock_soap):
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
    def test_013_enroll_pending(self, mock_load_cfg, mock_soap):
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
    def test_014_enroll_denied(self, mock_load_cfg, mock_soap):
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
    def test_015_poll_issued(self, mock_load_cfg, mock_soap):
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

    def test_016_revoke_not_supported(self):
        """revoke is stubbed"""
        code, message, detail = self.cahandler.revoke("cert", "unspecified", None)
        self.assertEqual(500, code)
        self.assertIn("serverInternal", message)
        self.assertEqual("Revocation is not supported.", detail)

    def test_017_https_required(self):
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
    def test_018_soap_post_action_for_issue(self, mock_soap):
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
    def test_019_enroll_appends_cep_ca(self, mock_load_cfg, mock_soap):
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

    def test_020_soap_envelope_with_username_token(self):
        """_soap_envelope includes WS-Security UsernameToken when provided"""
        from acme2certifier.cahandlers.mscepces_ca_handler import (
            _soap_envelope,
            _username_token_fields,
            _xcep_get_policies_body,
        )
        from xml.etree import ElementTree as ET

        token = _username_token_fields("user", "pass")
        data = _soap_envelope(
            "http://action", "https://ces.example/CES", _xcep_get_policies_body(), token
        )
        root = ET.fromstring(data)
        self.assertIsNotNone(
            next(
                el
                for el in root.iter()
                if el.tag.endswith("Username") and el.text == "user"
            )
        )

    def test_021_soap_envelope_without_username_token(self):
        """_soap_envelope omits Security header without token"""
        from acme2certifier.cahandlers.mscepces_ca_handler import (
            _soap_envelope,
            _xcep_get_policies_body,
        )
        from xml.etree import ElementTree as ET

        data = _soap_envelope(
            "http://action", "https://ces.example/CES", _xcep_get_policies_body()
        )
        root = ET.fromstring(data)
        security = [el for el in root.iter() if el.tag.endswith("Security")]
        self.assertEqual([], security)

    def test_022_parse_xcep_get_policies_fault(self):
        """XCEP SOAP Fault raises RuntimeError"""
        from acme2certifier.cahandlers.mscepces_ca_handler import (
            _parse_xcep_get_policies,
        )

        with self.assertRaises(RuntimeError) as ctx:
            _parse_xcep_get_policies(_fixture("soap_fault.xml"))
        self.assertIn("XCEP SOAP Fault", str(ctx.exception))

    def test_023_certificate_element_to_pem_empty_invalid(self):
        """_certificate_element_to_pem handles empty and invalid input"""
        from acme2certifier.cahandlers.mscepces_ca_handler import (
            _certificate_element_to_pem,
        )

        self.assertIsNone(_certificate_element_to_pem(None))
        self.assertIsNone(_certificate_element_to_pem("not-valid-base64!!!"))

    def test_024_cert_bundle_with_ca_skips_duplicate(self):
        """_cert_bundle_with_ca skips CA PEM already in leaf bundle"""
        from acme2certifier.cahandlers.mscepces_ca_handler import (
            _cert_bundle_with_ca,
            _parse_xcep_get_policies,
            _token_to_pem_bundle,
        )

        ca_pem = _parse_xcep_get_policies(_fixture("xcep_get_policies_response.xml"))[
            "ca_certificates"
        ][0]
        leaf, _ = _token_to_pem_bundle(self.logger, _issued_token_b64())
        bundle = _cert_bundle_with_ca(leaf, [leaf, ca_pem])
        self.assertEqual(2, bundle.count("BEGIN CERTIFICATE"))

    def test_025_parse_wstep_missing_response(self):
        """missing RequestSecurityTokenResponse raises"""
        from acme2certifier.cahandlers.mscepces_ca_handler import _parse_wstep_response

        xml = (
            '<?xml version="1.0"?>'
            '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">'
            "<s:Body></s:Body></s:Envelope>"
        )
        with self.assertRaises(RuntimeError) as ctx:
            _parse_wstep_response(xml)
        self.assertIn("missing RequestSecurityTokenResponse", str(ctx.exception))

    def test_026_parse_wstep_unknown_disposition(self):
        """unknown WSTEP disposition maps to unknown status"""
        from acme2certifier.cahandlers.mscepces_ca_handler import _parse_wstep_response

        xml = (
            '<?xml version="1.0"?>'
            '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">'
            "<s:Body><wst:RequestSecurityTokenResponse "
            'xmlns:wst="http://docs.oasis-open.org/ws-sx/ws-trust/200512">'
            "<wst:DispositionMessage>Weird</wst:DispositionMessage>"
            "</wst:RequestSecurityTokenResponse></s:Body></s:Envelope>"
        )
        self.assertEqual("unknown", _parse_wstep_response(xml)["status"])

    def test_027_csr_to_pkcs10_b64_pem_input(self):
        """_csr_to_pkcs10_b64 accepts PEM CSR"""
        from acme2certifier.acme_srv.helper import b64_url_recode, build_pem_file
        from acme2certifier.cahandlers.mscepces_ca_handler import _csr_to_pkcs10_b64

        pem = build_pem_file(
            self.logger, None, b64_url_recode(self.logger, TEST_CSR_B64), True, True
        )
        b64_der = _csr_to_pkcs10_b64(self.logger, pem)
        self.assertTrue(b64_der)
        self.assertNotIn("BEGIN", b64_der)

    def test_028_token_to_pem_bundle_der_token(self):
        """_token_to_pem_bundle decodes DER X509 token"""
        from acme2certifier.cahandlers.mscepces_ca_handler import _token_to_pem_bundle

        bundle, raw = _token_to_pem_bundle(self.logger, _issued_token_b64())
        self.assertIn("BEGIN CERTIFICATE", bundle)
        self.assertTrue(raw)

    def test_029_token_to_pem_bundle_pem_token(self):
        """_token_to_pem_bundle accepts inline PEM"""
        from acme2certifier.cahandlers.mscepces_ca_handler import (
            _token_to_pem_bundle,
            _parse_wstep_response,
        )

        bundle, raw = _token_to_pem_bundle(self.logger, _issued_token_b64())
        _, raw_der = _token_to_pem_bundle(self.logger, bundle)
        self.assertTrue(raw_der)
        issued = _parse_wstep_response(_fixture("wstep_issue_issued.xml"))
        self.assertEqual("issued", issued["status"])

    @patch("acme2certifier.cahandlers.mscepces_ca_handler.pkcs7_to_pem")
    def test_030_token_to_pem_bundle_pkcs7_fail_pem_fallback(self, mock_p7):
        """pkcs7_to_pem failure falls back to PEM parse"""
        from acme2certifier.cahandlers.mscepces_ca_handler import _token_to_pem_bundle

        mock_p7.side_effect = ValueError("bad pkcs7")
        bundle, _ = _token_to_pem_bundle(self.logger, _issued_token_b64())
        pem = bundle if "BEGIN" in bundle else _issued_token_b64()
        bundle2, raw2 = _token_to_pem_bundle(
            self.logger,
            (
                "-----BEGIN CERTIFICATE-----\n"
                + pem.split("BEGIN CERTIFICATE-----")[-1]
                if "BEGIN" in pem
                else pem
            ),
        )
        if "BEGIN" in pem:
            bundle2, raw2 = _token_to_pem_bundle(self.logger, bundle)
        self.assertTrue(raw2 or bundle2)

    def test_031_token_to_pem_bundle_total_failure(self):
        """unparseable token returns None tuple"""
        from acme2certifier.cahandlers.mscepces_ca_handler import _token_to_pem_bundle

        self.assertEqual(
            (None, None), _token_to_pem_bundle(self.logger, "garbage-token")
        )

    def test_032_leaf_pem_from_bundle_no_match(self):
        """_leaf_pem_from_bundle returns input when no PEM found"""
        from acme2certifier.cahandlers.mscepces_ca_handler import _leaf_pem_from_bundle

        self.assertEqual("not-a-pem", _leaf_pem_from_bundle("not-a-pem"))

    def test_033_poll_identifier_decode_edge_cases(self):
        """_poll_identifier_decode without separator"""
        from acme2certifier.cahandlers.mscepces_ca_handler import (
            _poll_identifier_decode,
        )

        self.assertEqual((None, None), _poll_identifier_decode(""))
        self.assertEqual(("nosep", None), _poll_identifier_decode("nosep"))

    def test_034_username_token_fields(self):
        """_username_token_fields builds nonce and created"""
        from acme2certifier.cahandlers.mscepces_ca_handler import _username_token_fields

        fields = _username_token_fields("u", "p")
        self.assertEqual("u", fields["username"])
        self.assertEqual("p", fields["password"])
        self.assertTrue(fields["nonce"])
        self.assertTrue(fields["created"].endswith("Z"))

    def test_035_gssapi_channel_bindings_supported_true(self):
        """gssapi_channel_bindings_supported True when param exists"""
        from acme2certifier.cahandlers.mscepces_ca_handler import (
            gssapi_channel_bindings_supported,
        )

        class FakeAuth:
            def __init__(self, channel_bindings=None, **_kwargs):
                self.channel_bindings = channel_bindings

        with patch.dict(
            "sys.modules", {"requests_gssapi": _fake_requests_gssapi(FakeAuth)}
        ):
            self.assertTrue(gssapi_channel_bindings_supported())

    def test_036_gssapi_channel_bindings_supported_false(self):
        """gssapi_channel_bindings_supported False without param"""
        from acme2certifier.cahandlers.mscepces_ca_handler import (
            gssapi_channel_bindings_supported,
        )

        class FakeAuth:
            def __init__(self, **_kwargs):
                pass

        with patch.dict(
            "sys.modules", {"requests_gssapi": _fake_requests_gssapi(FakeAuth)}
        ):
            self.assertFalse(gssapi_channel_bindings_supported())

    def test_037_gssapi_channel_bindings_supported_import_error(self):
        """gssapi_channel_bindings_supported False on import failure"""
        from acme2certifier.cahandlers.mscepces_ca_handler import (
            gssapi_channel_bindings_supported,
        )

        with patch(
            "acme2certifier.cahandlers.mscepces_ca_handler.importlib.import_module",
            side_effect=ImportError("missing"),
        ):
            self.assertFalse(gssapi_channel_bindings_supported())

    def test_038_gssapi_channel_bindings_supported_no_auth_cls(self):
        """gssapi_channel_bindings_supported False when HTTPSPNEGOAuth missing"""
        from acme2certifier.cahandlers.mscepces_ca_handler import (
            gssapi_channel_bindings_supported,
        )

        fake_mod = types.ModuleType("requests_gssapi")
        with patch.dict("sys.modules", {"requests_gssapi": fake_mod}):
            self.assertFalse(gssapi_channel_bindings_supported())

    def test_039_gssapi_channel_bindings_supported_inspect_error(self):
        """gssapi_channel_bindings_supported False when inspect fails"""
        from acme2certifier.cahandlers.mscepces_ca_handler import (
            gssapi_channel_bindings_supported,
        )

        class FakeAuth:
            pass

        fake_mod = _fake_requests_gssapi(FakeAuth)
        with (
            patch.dict("sys.modules", {"requests_gssapi": fake_mod}),
            patch("inspect.signature", side_effect=TypeError("bad")),
        ):
            self.assertFalse(gssapi_channel_bindings_supported())

    @patch("acme2certifier.cahandlers.mscepces_ca_handler.load_config")
    def test_040_context_manager_loads_config(self, mock_load_cfg):
        """__enter__ loads config when ces_url unset"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {
            "ces_url": "https://ces.example.com/CES",
            "template": "WebServer",
        }
        mock_load_cfg.return_value = parser
        self.cahandler.ces_url = None
        with self.cahandler as handler:
            self.assertTrue(handler.ces_url.startswith("https://"))

    @patch("acme2certifier.cahandlers.mscepces_ca_handler.load_config")
    def test_041_config_auth_and_channel_bindings_warnings(self, mock_load_cfg):
        """unknown auth_method and invalid channel_bindings log warnings"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {
            "auth_method": "bogus",
            "gssapi_channel_bindings": "maybe",
        }
        mock_load_cfg.return_value = parser
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.cahandler._config_load()
        self.assertEqual("gssapi", self.cahandler.auth_method)
        self.assertEqual("auto", self.cahandler.gssapi_channel_bindings)
        self.assertIn("Unknown auth_method", lcm.output[0])
        self.assertTrue(
            any("Invalid gssapi_channel_bindings" in msg for msg in lcm.output)
        )

    @patch("acme2certifier.cahandlers.mscepces_ca_handler.load_config")
    def test_042_config_verify_false_warning(self, mock_load_cfg):
        """verify=False logs security warning"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"verify": "False"}
        mock_load_cfg.return_value = parser
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.cahandler._config_load()
        self.assertFalse(self.cahandler.verify)
        self.assertIn("TLS certificate verification is disabled", lcm.output[0])

    def test_043_config_headerinfo_load(self):
        """header_info_list first element loads; bad JSON warns"""
        config_ok = {"Order": {"header_info_list": '["first", "second"]'}}
        self.cahandler._config_headerinfo_load(config_ok)
        self.assertEqual("first", self.cahandler.header_info_field)
        handler2 = type(self.cahandler)(False, self.logger)
        config_bad = {"Order": {"header_info_list": "not-json"}}
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            handler2._config_headerinfo_load(config_bad)
        self.assertFalse(handler2.header_info_field)
        self.assertIn("Failed to parse header_info_list", lcm.output[0])

    @patch("acme2certifier.cahandlers.mscepces_ca_handler.load_config")
    def test_044_config_allowed_templates_order_precedence(self, mock_load_cfg):
        """Order allowed_header_values overrides CAhandler allowed_templates"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"allowed_templates": '["FromCA"]'}
        parser["Order"] = {"allowed_header_values": '["FromOrder"]'}
        mock_load_cfg.return_value = parser
        self.cahandler._config_load()
        self.assertEqual(["FromOrder"], self.cahandler.allowed_templates)

    @patch("acme2certifier.cahandlers.mscepces_ca_handler.load_config")
    def test_045_config_allowed_templates_deprecated(self, mock_load_cfg):
        """deprecated allowed_templates loads with warning"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"allowed_templates": '["WebServer"]'}
        mock_load_cfg.return_value = parser
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.cahandler._config_load()
        self.assertEqual(["WebServer"], self.cahandler.allowed_templates)
        self.assertIn("allowed_templates is deprecated", lcm.output[0])

    @patch("acme2certifier.cahandlers.mscepces_ca_handler.load_config")
    def test_046_config_allowed_templates_invalid(self, mock_load_cfg):
        """invalid allowed_templates JSON yields empty list"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"allowed_templates": "not-json"}
        mock_load_cfg.return_value = parser
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.cahandler._config_load()
        self.assertEqual([], self.cahandler.allowed_templates)
        self.assertTrue(
            any("Failed to parse allowed_templates" in msg for msg in lcm.output)
        )

    @patch(
        "acme2certifier.cahandlers.mscepces_ca_handler.os.path.isfile",
        return_value=True,
    )
    def test_047_credentials_configured_keytab(self, _mock_isfile):
        """gssapi keytab satisfies _credentials_are_configured"""
        self.cahandler.auth_method = "gssapi"
        self.cahandler.krb5_principal = "svc@EXAMPLE.COM"
        self.cahandler.krb5_keytab = "/tmp/svc.keytab"
        self.assertTrue(self.cahandler._credentials_are_configured())

    def test_048_allowed_templates_check(self):
        """allowlist reject and allow paths"""
        self.cahandler.template = "Other"
        self.cahandler.allowed_templates = ["WebServer"]
        self.assertIn(
            "not in allowed_templates", self.cahandler._allowed_templates_check()
        )
        self.cahandler.template = "WebServer"
        self.assertIsNone(self.cahandler._allowed_templates_check())

    def test_049_tls_verify_modes(self):
        """_tls_verify returns False, path, or True"""
        self.cahandler.verify = False
        self.assertFalse(self.cahandler._tls_verify())
        self.cahandler.verify = True
        self.cahandler.ca_bundle = "/tmp/ca.pem"
        self.assertEqual("/tmp/ca.pem", self.cahandler._tls_verify())
        self.cahandler.ca_bundle = True
        self.assertTrue(self.cahandler._tls_verify())

    @patch("acme2certifier.cahandlers.mscepces_ca_handler.importlib.import_module")
    def test_050_gssapi_creds_from_password_paths(self, mock_import):
        """password GSSAPI acquire success and failure paths"""
        mock_gssapi = MagicMock()
        mock_import.return_value = mock_gssapi
        creds = MagicMock()
        creds.creds = "raw-creds"
        mock_gssapi.raw.acquire_cred_with_password.return_value = creds
        self.cahandler.user = "user@REALM"
        self.cahandler.password = "secret"
        self.assertEqual("raw-creds", self.cahandler._gssapi_creds_from_password())
        self.cahandler.user = None
        with self.assertRaises(RuntimeError):
            self.cahandler._gssapi_creds_from_password()
        mock_import.side_effect = ImportError("no gssapi")
        with self.assertRaises(RuntimeError):
            self.cahandler._gssapi_creds_from_password()
        mock_import.side_effect = None
        mock_import.return_value = mock_gssapi
        mock_gssapi.raw.acquire_cred_with_password.side_effect = Exception("fail")
        self.cahandler.user = "user@REALM"
        self.cahandler.password = "secret"
        with self.assertRaises(RuntimeError):
            self.cahandler._gssapi_creds_from_password()

    def test_051_session_auth_non_gssapi(self):
        """_session_auth returns None for username_password"""
        self.cahandler.auth_method = "username_password"
        self.assertIsNone(self.cahandler._session_auth())

    @patch(
        "acme2certifier.cahandlers.mscepces_ca_handler.CAhandler._gssapi_creds_from_password"
    )
    def test_052_session_auth_with_creds_and_bindings(self, mock_pw_creds):
        """_session_auth builds HTTPSPNEGOAuth with creds and bindings"""
        calls = []

        class FakeAuth:
            def __init__(self, **kwargs):
                calls.append(kwargs)

        mock_pw_creds.return_value = "pw-creds"
        self.cahandler.auth_method = "gssapi"
        self.cahandler.user = "u@R"
        self.cahandler.password = "p"
        self.cahandler.gssapi_channel_bindings = "on"
        with patch.dict(
            "sys.modules", {"requests_gssapi": _fake_requests_gssapi(FakeAuth)}
        ):
            with patch(
                "acme2certifier.cahandlers.mscepces_ca_handler.gssapi_channel_bindings_supported",
                return_value=True,
            ):
                auth = self.cahandler._session_auth()
        self.assertIsInstance(auth, FakeAuth)
        self.assertEqual("pw-creds", calls[0]["creds"])
        self.assertEqual("tls-server-end-point", calls[0]["channel_bindings"])

    def test_053_session_auth_errors(self):
        """_session_auth import fail, channel error, no creds"""
        self.cahandler.auth_method = "gssapi"
        with patch(
            "acme2certifier.cahandlers.mscepces_ca_handler.importlib.import_module",
            side_effect=ImportError("no mod"),
        ):
            with self.assertRaises(RuntimeError):
                self.cahandler._session_auth()
        with patch.dict(
            "sys.modules",
            {"requests_gssapi": _fake_requests_gssapi(MagicMock)},
        ):
            self.cahandler.gssapi_channel_bindings = "on"
            with patch(
                "acme2certifier.cahandlers.mscepces_ca_handler.gssapi_channel_bindings_supported",
                return_value=False,
            ):
                with self.assertRaises(RuntimeError):
                    self.cahandler._session_auth()
            self.cahandler.gssapi_channel_bindings = "auto"
            self.cahandler.user = None
            self.cahandler.password = None
            with self.assertRaises(RuntimeError):
                self.cahandler._session_auth()

    def test_054_gssapi_channel_bindings_resolve(self):
        """resolve off, on unsupported, auto supported and unsupported"""
        self.cahandler.auth_method = "username_password"
        self.assertEqual(
            (None, None), self.cahandler._gssapi_channel_bindings_resolve()
        )
        self.cahandler.auth_method = "gssapi"
        self.cahandler.gssapi_channel_bindings = "off"
        self.assertEqual(
            (None, None), self.cahandler._gssapi_channel_bindings_resolve()
        )
        self.cahandler.gssapi_channel_bindings = "on"
        with patch(
            "acme2certifier.cahandlers.mscepces_ca_handler.gssapi_channel_bindings_supported",
            return_value=False,
        ):
            bindings, err = self.cahandler._gssapi_channel_bindings_resolve()
        self.assertIsNone(bindings)
        self.assertIn("channel_bindings=on", err)
        self.cahandler.gssapi_channel_bindings = "auto"
        with patch(
            "acme2certifier.cahandlers.mscepces_ca_handler.gssapi_channel_bindings_supported",
            return_value=True,
        ):
            bindings, err = self.cahandler._gssapi_channel_bindings_resolve()
        self.assertEqual("tls-server-end-point", bindings)
        self.assertIsNone(err)
        with patch(
            "acme2certifier.cahandlers.mscepces_ca_handler.gssapi_channel_bindings_supported",
            return_value=False,
        ):
            with self.assertLogs("test_a2c", level="INFO") as lcm:
                bindings, err = self.cahandler._gssapi_channel_bindings_resolve()
        self.assertIsNone(bindings)
        self.assertIsNone(err)
        self.assertIn("does not support channel_bindings", lcm.output[0])

    def test_055_username_token(self):
        """_username_token for username_password auth"""
        self.cahandler.auth_method = "gssapi"
        self.assertIsNone(self.cahandler._username_token())
        self.cahandler.auth_method = "username_password"
        self.cahandler.ces_username = None
        with self.assertRaises(RuntimeError):
            self.cahandler._username_token()
        self.cahandler.ces_username = "u"
        self.cahandler.ces_password = "p"
        token = self.cahandler._username_token()
        self.assertEqual("u", token["username"])

    @patch("acme2certifier.cahandlers.mscepces_ca_handler.requests.post")
    def test_056_soap_post_http500_and_raise(self, mock_post):
        """_soap_post returns SOAP body on HTTP 500; raises on other errors"""
        from acme2certifier.cahandlers.mscepces_ca_handler import (
            _xcep_get_policies_body,
        )

        resp500 = MagicMock(status_code=500, text="<fault/>")
        mock_post.return_value = resp500
        self.cahandler.auth_method = "username_password"
        self.cahandler.ces_username = "u"
        self.cahandler.ces_password = "p"
        text = self.cahandler._soap_post(
            "https://ces.example/CES", "action", _xcep_get_policies_body()
        )
        self.assertEqual("<fault/>", text)
        resp400 = MagicMock(status_code=400, text="bad")
        resp400.raise_for_status.side_effect = Exception("HTTP 400")
        mock_post.return_value = resp400
        with self.assertRaises(Exception):
            self.cahandler._soap_post(
                "https://ces.example/CES", "action", _xcep_get_policies_body()
            )

    @patch(
        "acme2certifier.cahandlers.mscepces_ca_handler.CAhandler._kerberos_config_path_resolve"
    )
    def test_057_kerberos_runtime_environment(self, mock_resolve):
        """_kerberos_runtime_environment sets and restores KRB5_CONFIG"""
        mock_resolve.return_value = "/tmp/krb5.conf"
        clean_env = {k: v for k, v in os.environ.items() if k != "KRB5_CONFIG"}
        with patch.dict(os.environ, clean_env, clear=True):
            with self.cahandler._kerberos_runtime_environment():
                self.assertEqual("/tmp/krb5.conf", os.environ.get("KRB5_CONFIG"))
            self.assertIsNone(os.environ.get("KRB5_CONFIG"))
            os.environ["KRB5_CONFIG"] = "/existing"
            with self.cahandler._kerberos_runtime_environment():
                self.assertEqual("/tmp/krb5.conf", os.environ["KRB5_CONFIG"])
            self.assertEqual("/existing", os.environ["KRB5_CONFIG"])

    def test_058_kerberos_gssapi_creds_from_cache(self):
        """ccache load paths for gssapi credentials"""
        self.cahandler.auth_method = "username_password"
        self.assertEqual(
            (None, None), self.cahandler._kerberos_gssapi_creds_from_cache()
        )
        self.cahandler.auth_method = "gssapi"
        self.cahandler.krb5_cache = None
        self.cahandler.krb5_keytab = None
        self.cahandler.krb5_principal = None
        self.assertEqual(
            (None, None), self.cahandler._kerberos_gssapi_creds_from_cache()
        )
        self.cahandler.krb5_cache = None
        self.cahandler.krb5_principal = "svc@EXAMPLE.COM"
        with patch(
            "acme2certifier.cahandlers.mscepces_ca_handler.os.path.isfile",
            return_value=True,
        ):
            self.cahandler.krb5_keytab = "/tmp/k.keytab"
            creds, err = self.cahandler._kerberos_gssapi_creds_from_cache()
        self.assertIsNone(creds)
        self.assertIn("ccache is not available", err)
        with patch(
            "acme2certifier.cahandlers.mscepces_ca_handler.importlib.import_module",
            side_effect=ImportError("no gssapi"),
        ):
            self.cahandler.krb5_cache = "FILE:/tmp/cc"
            creds, err = self.cahandler._kerberos_gssapi_creds_from_cache()
        self.assertIn("gssapi module is required", err)
        mock_gssapi = MagicMock()
        mock_gssapi.Credentials = None
        with patch(
            "acme2certifier.cahandlers.mscepces_ca_handler.importlib.import_module",
            return_value=mock_gssapi,
        ):
            creds, err = self.cahandler._kerberos_gssapi_creds_from_cache()
        self.assertIn("Credentials is required", err)

    @patch(
        "acme2certifier.cahandlers.mscepces_ca_handler.CAhandler._kerberos_cleanup_temporary_ccache"
    )
    @patch(
        "acme2certifier.cahandlers.mscepces_ca_handler.CAhandler._kerberos_keytab_is_configured"
    )
    @patch(
        "acme2certifier.cahandlers.mscepces_ca_handler.CAhandler._kerberos_gssapi_creds_from_cache"
    )
    def test_059_kerberos_bind_gssapi_creds_success(
        self, mock_cache, mock_keytab, mock_cleanup
    ):
        """_kerberos_bind_gssapi_creds returns cache creds"""
        mock_cache.return_value = ("creds", None)
        creds, err = self.cahandler._kerberos_bind_gssapi_creds()
        self.assertEqual("creds", creds)
        self.assertIsNone(err)

    @patch(
        "acme2certifier.cahandlers.mscepces_ca_handler.CAhandler._kerberos_cleanup_temporary_ccache"
    )
    @patch(
        "acme2certifier.cahandlers.mscepces_ca_handler.CAhandler._kerberos_keytab_is_configured",
        return_value=True,
    )
    @patch(
        "acme2certifier.cahandlers.mscepces_ca_handler.CAhandler._kerberos_gssapi_creds_from_cache",
        return_value=(None, "load failed"),
    )
    def test_060_kerberos_bind_gssapi_creds_keytab_error(
        self, _mock_cache, _mock_keytab, _mock_cleanup
    ):
        """keytab mode returns error when ccache load fails"""
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            creds, err = self.cahandler._kerberos_bind_gssapi_creds()
        self.assertIsNone(creds)
        self.assertEqual("load failed", err)
        self.assertIn("Kerberos credential load failed", lcm.output[0])

    @patch(
        "acme2certifier.cahandlers.mscepces_ca_handler.CAhandler._kerberos_cleanup_temporary_ccache"
    )
    @patch(
        "acme2certifier.cahandlers.mscepces_ca_handler.CAhandler._kerberos_keytab_is_configured",
        return_value=False,
    )
    @patch(
        "acme2certifier.cahandlers.mscepces_ca_handler.CAhandler._kerberos_gssapi_creds_from_cache",
        return_value=(None, "load failed"),
    )
    def test_061_kerberos_bind_gssapi_creds_password_fallback(
        self, _mock_cache, _mock_keytab, _mock_cleanup
    ):
        """password mode falls back when ccache unreadable"""
        self.cahandler.krb5_principal = None
        self.cahandler.krb5_keytab = None
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            creds, err = self.cahandler._kerberos_bind_gssapi_creds()
        self.assertIsNone(creds)
        self.assertIsNone(err)
        self.assertTrue(any("falling back to in-process" in msg for msg in lcm.output))

    @patch(
        "acme2certifier.cahandlers.mscepces_ca_handler.CAhandler._kerberos_acquire_with_kinit_password"
    )
    @patch(
        "acme2certifier.cahandlers.mscepces_ca_handler.CAhandler._kerberos_ccache_prepare"
    )
    def test_062_kerberos_prepare_gssapi_password_backend(
        self, mock_ccache, mock_kinit_pw
    ):
        """password backend kinit success and fallback warning"""
        self.cahandler.user = None
        self.assertIsNone(self.cahandler._kerberos_prepare_gssapi_password_backend())
        self.cahandler.user = "u@R"
        self.cahandler.password = "p"
        self.cahandler.krb5_config = "/missing/krb5.conf"
        with patch(
            "acme2certifier.cahandlers.mscepces_ca_handler.CAhandler._kerberos_config_path_resolve",
            return_value=None,
        ):
            self.assertEqual(
                "Configured krb5_config does not exist.",
                self.cahandler._kerberos_prepare_gssapi_password_backend(),
            )
        self.cahandler.krb5_config = None
        mock_ccache.return_value = "/tmp/cc"
        mock_kinit_pw.return_value = True
        self.assertIsNone(self.cahandler._kerberos_prepare_gssapi_password_backend())
        mock_kinit_pw.return_value = False
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.assertIsNone(
                self.cahandler._kerberos_prepare_gssapi_password_backend()
            )
        self.assertIn("Password kinit unavailable", lcm.output[0])

    @patch(
        "acme2certifier.cahandlers.mscepces_ca_handler.CAhandler._kerberos_acquire_keytab_credentials"
    )
    @patch(
        "acme2certifier.cahandlers.mscepces_ca_handler.CAhandler._kerberos_prepare_gssapi_password_backend"
    )
    @patch(
        "acme2certifier.cahandlers.mscepces_ca_handler.CAhandler._kerberos_keytab_is_configured"
    )
    def test_063_kerberos_prepare_gssapi_backend(
        self, mock_keytab, mock_pw_backend, mock_keytab_acquire
    ):
        """_kerberos_prepare_gssapi_backend dispatches by auth and keytab"""
        self.cahandler.auth_method = "username_password"
        self.assertIsNone(self.cahandler._kerberos_prepare_gssapi_backend())
        self.cahandler.auth_method = "gssapi"
        mock_keytab.return_value = False
        mock_pw_backend.return_value = "pw-err"
        self.assertEqual("pw-err", self.cahandler._kerberos_prepare_gssapi_backend())
        mock_keytab.return_value = True
        mock_keytab_acquire.return_value = None
        self.assertIsNone(self.cahandler._kerberos_prepare_gssapi_backend())

    @patch("acme2certifier.cahandlers.mscepces_ca_handler.CAhandler._soap_post")
    def test_064_xcep_get_policies_cache_and_missing_cep(self, mock_soap):
        """GetPolicies cache hit; missing cep_url raises"""
        self.cahandler.cep_url = None
        with self.assertRaises(RuntimeError):
            self.cahandler._xcep_get_policies()
        self.cahandler.cep_url = "https://cep.example/CEP"
        mock_soap.return_value = _fixture("xcep_get_policies_response.xml")
        first = self.cahandler._xcep_get_policies()
        second = self.cahandler._xcep_get_policies()
        self.assertEqual(first, second)
        mock_soap.assert_called_once()

    @patch("acme2certifier.cahandlers.mscepces_ca_handler.os.path.exists")
    def test_065_ca_certificates_from_file(self, mock_exists):
        """ca_certificates file missing, read error, success"""
        self.cahandler.ca_certificates = None
        self.assertEqual([], self.cahandler._ca_certificates_from_file())
        self.cahandler.ca_certificates = "/no/file.pem"
        mock_exists.return_value = False
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.assertEqual([], self.cahandler._ca_certificates_from_file())
        self.assertIn("does not exist", lcm.output[0])
        mock_exists.return_value = True
        pem = _parse_xcep_fixture_ca_pem()
        with patch("builtins.open", mock_open(read_data=pem)):
            loaded = self.cahandler._ca_certificates_from_file()
        self.assertEqual(1, len(loaded))
        with patch("builtins.open", side_effect=OSError("denied")):
            with self.assertLogs("test_a2c", level="INFO") as lcm2:
                self.assertEqual([], self.cahandler._ca_certificates_from_file())
        self.assertIn("Failed to read ca_certificates", lcm2.output[0])

    @patch("acme2certifier.cahandlers.mscepces_ca_handler.CAhandler._xcep_get_policies")
    def test_066_ca_certificates_from_cep_exception(self, mock_policies):
        """CEP fetch failure returns empty CA list"""
        self.cahandler.cep_url = "https://cep.example/CEP"
        mock_policies.side_effect = RuntimeError("cep down")
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.assertEqual([], self.cahandler._ca_certificates_from_cep())
        self.assertIn("Failed to fetch CA certificates from CEP", lcm.output[0])
        self.cahandler.cep_url = None
        self.assertEqual([], self.cahandler._ca_certificates_from_cep())

    @patch("acme2certifier.cahandlers.mscepces_ca_handler.CAhandler._xcep_get_policies")
    def test_067_ca_templates_membership_check(self, mock_policies):
        """ca_templates_check off/warn/on paths"""
        self.cahandler.ca_templates_check = "off"
        self.assertIsNone(self.cahandler._ca_templates_membership_check())
        self.cahandler.ca_templates_check = "on"
        self.cahandler.cep_url = "https://cep/CEP"
        self.cahandler.template = "WebServer"
        mock_policies.side_effect = RuntimeError("fail")
        self.assertIn(
            "CEP GetPolicies failed", self.cahandler._ca_templates_membership_check()
        )
        mock_policies.side_effect = None
        mock_policies.return_value = {"templates": ["User"]}
        self.assertIn("was not found", self.cahandler._ca_templates_membership_check())
        self.cahandler.ca_templates_check = "warn"
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.assertIsNone(self.cahandler._ca_templates_membership_check())
        self.assertIn("was not found", lcm.output[0])
        mock_policies.return_value = {"templates": ["WebServer"]}
        self.assertIsNone(self.cahandler._ca_templates_membership_check())

    def test_068_result_from_wstep_branches(self):
        """_result_from_wstep issued/pending/denied/unknown edge cases"""
        err, bundle, raw, poll = self.cahandler._result_from_wstep(
            {"status": "issued", "token": None}
        )
        self.assertEqual(self.cahandler.CERT_FETCH_ERROR, err)
        err, bundle, raw, poll = self.cahandler._result_from_wstep(
            {"status": "issued", "token": "garbage-token"}
        )
        self.assertIn("Failed to parse certificate", err)
        self.cahandler.cep_url = None
        self.cahandler.ca_certificates = None
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            err, bundle, raw, poll = self.cahandler._result_from_wstep(
                {"status": "issued", "token": _issued_token_b64()}
            )
        self.assertIsNone(err)
        self.assertIn("No CA chain appended", lcm.output[0])
        err, _, _, poll = self.cahandler._result_from_wstep({"status": "pending"})
        self.assertIn("missing RequestID", err)
        err, _, _, poll = self.cahandler._result_from_wstep(
            {
                "status": "pending",
                "request_id": "9",
                "reference": "https://ces/CES",
            }
        )
        self.assertIsNone(err)
        self.assertTrue(poll.startswith("9@@"))
        err, _, _, _ = self.cahandler._result_from_wstep(
            {"status": "denied", "disposition": "Nope"}
        )
        self.assertIn("denied", err.lower())
        err, _, _, _ = self.cahandler._result_from_wstep(
            {"status": "unknown", "disposition": "???"}
        )
        self.assertIn("Unexpected WSTEP disposition", err)

    @patch("acme2certifier.cahandlers.mscepces_ca_handler.enrollment_config_log")
    @patch("acme2certifier.cahandlers.mscepces_ca_handler.CAhandler._wstep_issue")
    def test_069_enroll_internal_paths(self, mock_issue, mock_ecl):
        """_enroll logs config, template error, exception"""
        self.cahandler.enrollment_config_log = True
        mock_issue.return_value = {"status": "issued", "token": _issued_token_b64()}
        self.cahandler._enroll(TEST_CSR_B64)
        mock_ecl.assert_called_once()
        with patch.object(
            self.cahandler,
            "_ca_templates_membership_check",
            return_value="template bad",
        ):
            err, _, _, _ = self.cahandler._enroll(TEST_CSR_B64)
        self.assertEqual("template bad", err)
        mock_issue.side_effect = RuntimeError("boom")
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            err, _, _, _ = self.cahandler._enroll(TEST_CSR_B64)
        self.assertEqual(self.cahandler.CERT_FETCH_ERROR, err)
        self.assertIn("Failed to enroll certificate", lcm.output[0])

    @patch("acme2certifier.cahandlers.mscepces_ca_handler.load_config")
    def test_070_handler_check_requires_password_without_keytab(self, mock_load_cfg):
        """handler_check requires ces_username/password when no keytab"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {
            "ces_url": "https://ces.example/CES",
            "template": "WebServer",
            "auth_method": "gssapi",
        }
        mock_load_cfg.return_value = parser
        self.cahandler._config_load()
        error = self.cahandler.handler_check()
        self.assertIsNotNone(error)

    @patch(
        "acme2certifier.cahandlers.mscepces_ca_handler.CAhandler._kerberos_bind_gssapi_creds",
        return_value=(None, None),
    )
    @patch(
        "acme2certifier.cahandlers.mscepces_ca_handler.CAhandler._kerberos_prepare_gssapi_backend",
        return_value=None,
    )
    @patch("acme2certifier.cahandlers.mscepces_ca_handler.load_config")
    def test_071_enroll_config_and_https_errors(
        self, mock_load_cfg, _mock_kerb, _mock_bind
    ):
        """enroll configuration and HTTPS validation errors"""
        mock_load_cfg.return_value = configparser.ConfigParser()
        self.cahandler._config_load()
        error, _, _, _ = self.cahandler.enroll(TEST_CSR_B64)
        self.assertIsNotNone(error)
        self.cahandler.ces_url = "https://ces.example/CES"
        self.cahandler.template = "WebServer"
        self.cahandler.auth_method = "username_password"
        self.cahandler.ces_username = "u"
        self.cahandler.ces_password = "p"
        self.cahandler.user = "u"
        self.cahandler.password = "p"
        self.cahandler.cep_url = "http://cep.example/CEP"
        error, _, _, _ = self.cahandler.enroll(TEST_CSR_B64)
        self.assertIn("cep_url", error)

    @patch(
        "acme2certifier.cahandlers.mscepces_ca_handler.CAhandler._kerberos_cleanup_temporary_ccache"
    )
    @patch(
        "acme2certifier.cahandlers.mscepces_ca_handler.CAhandler._kerberos_bind_gssapi_creds",
        return_value=(None, None),
    )
    @patch(
        "acme2certifier.cahandlers.mscepces_ca_handler.CAhandler._kerberos_prepare_gssapi_backend",
        return_value="kerb err",
    )
    def test_072_enroll_kerberos_prepare_error(
        self, _mock_prepare, _mock_bind, mock_cleanup
    ):
        """enroll returns kerberos prepare error"""
        self._set_enroll_ready()
        error, _, _, _ = self.cahandler.enroll(TEST_CSR_B64)
        self.assertEqual("kerb err", error)
        self.assertTrue(mock_cleanup.called)

    @patch(
        "acme2certifier.cahandlers.mscepces_ca_handler.CAhandler._kerberos_cleanup_temporary_ccache"
    )
    @patch(
        "acme2certifier.cahandlers.mscepces_ca_handler.CAhandler._kerberos_bind_gssapi_creds",
        return_value=(None, "bind err"),
    )
    @patch(
        "acme2certifier.cahandlers.mscepces_ca_handler.CAhandler._kerberos_prepare_gssapi_backend",
        return_value=None,
    )
    def test_073_enroll_kerberos_bind_error(
        self, _mock_prepare, _mock_bind, _mock_cleanup
    ):
        """enroll returns kerberos bind error"""
        self._set_enroll_ready()
        error, _, _, _ = self.cahandler.enroll(TEST_CSR_B64)
        self.assertEqual("bind err", error)

    @patch(
        "acme2certifier.cahandlers.mscepces_ca_handler.CAhandler._kerberos_cleanup_temporary_ccache"
    )
    @patch(
        "acme2certifier.cahandlers.mscepces_ca_handler.CAhandler._kerberos_bind_gssapi_creds",
        return_value=(None, None),
    )
    @patch(
        "acme2certifier.cahandlers.mscepces_ca_handler.CAhandler._kerberos_prepare_gssapi_backend",
        return_value=None,
    )
    @patch(
        "acme2certifier.cahandlers.mscepces_ca_handler.eab_profile_header_info_check",
        return_value="eab bad",
    )
    def test_074_enroll_eab_error(
        self, _mock_eab, _mock_prepare, _mock_bind, mock_cleanup
    ):
        """enroll returns eab profile error"""
        self._set_enroll_ready()
        error, _, _, _ = self.cahandler.enroll(TEST_CSR_B64)
        self.assertEqual("eab bad", error)
        self.assertTrue(mock_cleanup.called)

    @patch(
        "acme2certifier.cahandlers.mscepces_ca_handler.CAhandler._kerberos_cleanup_temporary_ccache"
    )
    @patch(
        "acme2certifier.cahandlers.mscepces_ca_handler.CAhandler._kerberos_bind_gssapi_creds",
        return_value=(None, None),
    )
    @patch(
        "acme2certifier.cahandlers.mscepces_ca_handler.CAhandler._kerberos_prepare_gssapi_backend",
        return_value=None,
    )
    @patch(
        "acme2certifier.cahandlers.mscepces_ca_handler.eab_profile_header_info_check",
        return_value=None,
    )
    def test_075_enroll_allowed_templates_error(
        self, _mock_eab, _mock_prepare, _mock_bind, mock_cleanup
    ):
        """enroll rejects disallowed template"""
        self._set_enroll_ready()
        self.cahandler.allowed_templates = ["Other"]
        error, _, _, _ = self.cahandler.enroll(TEST_CSR_B64)
        self.assertIn("not in allowed_templates", error)
        self.assertTrue(mock_cleanup.called)

    def test_076_poll_invalid_and_missing_ces(self):
        """poll invalid identifier and missing CES URL"""
        error, _, _, _, _ = self.cahandler.poll("c", "", TEST_CSR_B64)
        self.assertEqual("Invalid poll identifier", error)
        error, _, _, _, _ = self.cahandler.poll("c", "onlyid", TEST_CSR_B64)
        self.assertEqual("CES URL missing for poll", error)

    @patch(
        "acme2certifier.cahandlers.mscepces_ca_handler.CAhandler._kerberos_bind_gssapi_creds",
        return_value=(None, None),
    )
    @patch(
        "acme2certifier.cahandlers.mscepces_ca_handler.CAhandler._kerberos_prepare_gssapi_backend",
        return_value=None,
    )
    def test_077_poll_https_kerberos_and_bind(self, mock_prepare, _mock_bind):
        """poll HTTPS check and kerberos errors"""
        self.cahandler.ces_url = "http://ces/CES"
        error, _, _, _, _ = self.cahandler.poll("c", "111", TEST_CSR_B64)
        self.assertIn("HTTPS", error)
        self._set_enroll_ready()
        mock_prepare.return_value = "kerb err"
        error, _, _, _, _ = self.cahandler.poll(
            "c", "1@@https://ces.example/CES", TEST_CSR_B64
        )
        self.assertEqual("kerb err", error)
        mock_prepare.return_value = None
        with patch.object(
            self.cahandler,
            "_kerberos_bind_gssapi_creds",
            return_value=(None, "bind err"),
        ):
            error, _, _, _, _ = self.cahandler.poll(
                "c", "1@@https://ces.example/CES", TEST_CSR_B64
            )
        self.assertEqual("bind err", error)

    @patch(
        "acme2certifier.cahandlers.mscepces_ca_handler.CAhandler._session_auth",
        return_value=None,
    )
    @patch(
        "acme2certifier.cahandlers.mscepces_ca_handler.CAhandler._kerberos_bind_gssapi_creds",
        return_value=(None, None),
    )
    @patch(
        "acme2certifier.cahandlers.mscepces_ca_handler.CAhandler._kerberos_prepare_gssapi_backend",
        return_value=None,
    )
    def test_078_poll_denied_pending_exception(
        self, _mock_prepare, _mock_bind, _mock_auth
    ):
        """poll denied, pending poll id refresh, and exception"""
        self._set_enroll_ready()
        with patch.object(
            self.cahandler,
            "_wstep_poll",
            return_value={"status": "denied", "disposition": "no"},
        ):
            _, _, _, _, rejected = self.cahandler.poll(
                "c", "1@@https://ces.example/CES", TEST_CSR_B64
            )
        self.assertTrue(rejected)
        with patch.object(
            self.cahandler,
            "_wstep_poll",
            return_value={
                "status": "pending",
                "request_id": "22",
                "reference": "https://ces.example/CES",
            },
        ):
            _, _, _, poll_id, _ = self.cahandler.poll(
                "c", "1@@https://ces.example/CES", TEST_CSR_B64
            )
        self.assertTrue(poll_id.startswith("22@@"))
        with patch.object(self.cahandler, "_wstep_poll", side_effect=RuntimeError("x")):
            with self.assertLogs("test_a2c", level="INFO") as lcm:
                error, _, _, _, _ = self.cahandler.poll(
                    "c", "1@@https://ces.example/CES", TEST_CSR_B64
                )
        self.assertEqual(self.cahandler.CERT_FETCH_ERROR, error)
        self.assertIn("Failed to poll certificate", lcm.output[0])

    def test_079_token_to_pem_bundle_pkcs7_text_success(self):
        """_token_to_pem_bundle uses pkcs7_to_pem for PEM-shaped token text"""
        from acme2certifier.cahandlers.mscepces_ca_handler import _token_to_pem_bundle

        pem = _token_to_pem_bundle(self.logger, _issued_token_b64())[0]
        with patch(
            "acme2certifier.cahandlers.mscepces_ca_handler.pkcs7_to_pem",
            return_value=pem,
        ) as mock_p7:
            bundle, raw = _token_to_pem_bundle(self.logger, pem)
        mock_p7.assert_called_once()
        self.assertTrue(raw)

    def test_080_token_to_pem_bundle_pem_parse_fallback_fail(self):
        """invalid PEM text falls through when pkcs7 and x509 parse fail"""
        from acme2certifier.cahandlers.mscepces_ca_handler import _token_to_pem_bundle

        bad_pem = "-----BEGIN CERTIFICATE-----\n" "QkFE\n" "-----END CERTIFICATE-----"
        with patch(
            "acme2certifier.cahandlers.mscepces_ca_handler.pkcs7_to_pem",
            side_effect=ValueError("bad pkcs7"),
        ):
            bundle, raw = _token_to_pem_bundle(self.logger, bad_pem)
        self.assertIsNone(bundle)
        self.assertIsNone(raw)

    @patch("acme2certifier.cahandlers.mscepces_ca_handler.base64.b64decode")
    def test_081_token_to_pem_bundle_str_raw(self, mock_b64):
        """_token_to_pem_bundle handles str raw from failed base64 decode"""
        from acme2certifier.cahandlers.mscepces_ca_handler import _token_to_pem_bundle

        mock_b64.side_effect = ValueError("bad b64")
        with patch(
            "acme2certifier.cahandlers.mscepces_ca_handler.convert_string_to_byte",
            return_value="not-pem-bytes",
        ):
            bundle, raw = _token_to_pem_bundle(self.logger, "%%%")
        self.assertIsNone(raw)

    @patch("acme2certifier.cahandlers.mscepces_ca_handler.pkcs7_to_pem")
    def test_082_token_to_pem_bundle_der_pkcs7(self, mock_p7):
        """_token_to_pem_bundle falls back to pkcs7 on DER failure"""
        from acme2certifier.cahandlers.mscepces_ca_handler import _token_to_pem_bundle

        mock_p7.return_value = _token_to_pem_bundle(self.logger, _issued_token_b64())[0]
        bundle, raw = _token_to_pem_bundle(self.logger, "AA==")
        self.assertTrue(raw)

    def test_083_session_auth_uses_bound_gssapi_creds(self):
        """_session_auth passes pre-bound _gssapi_creds"""
        calls = []

        class FakeAuth:
            def __init__(self, **kwargs):
                calls.append(kwargs)

        self.cahandler.auth_method = "gssapi"
        self.cahandler._gssapi_creds = MagicMock(creds="bound")
        self.cahandler.gssapi_channel_bindings = "off"
        with patch.dict(
            "sys.modules", {"requests_gssapi": _fake_requests_gssapi(FakeAuth)}
        ):
            self.cahandler._session_auth()
        self.assertEqual("bound", calls[0]["creds"])

    @patch("acme2certifier.cahandlers.mscepces_ca_handler.requests.post")
    def test_084_soap_post_success_200(self, mock_post):
        """_soap_post returns body on HTTP 200"""
        from acme2certifier.cahandlers.mscepces_ca_handler import (
            _xcep_get_policies_body,
        )

        mock_post.return_value = MagicMock(status_code=200, text="<ok/>")
        self.cahandler.auth_method = "username_password"
        self.cahandler.ces_username = "u"
        self.cahandler.ces_password = "p"
        text = self.cahandler._soap_post(
            "https://ces.example/CES", "act", _xcep_get_policies_body()
        )
        self.assertEqual("<ok/>", text)

    @patch(
        "acme2certifier.cahandlers.mscepces_ca_handler.CAhandler._kerberos_ccache_path",
        return_value="/tmp/cc",
    )
    @patch("acme2certifier.cahandlers.mscepces_ca_handler.importlib.import_module")
    def test_085_kerberos_gssapi_creds_from_cache_success(
        self, mock_import, _mock_ccache
    ):
        """successful GSSAPI credential load from ccache"""
        self.cahandler.auth_method = "gssapi"
        self.cahandler.krb5_cache = "FILE:/tmp/cc"
        mock_gssapi = MagicMock()
        mock_gssapi.Credentials.return_value = "loaded"
        mock_import.return_value = mock_gssapi
        creds, err = self.cahandler._kerberos_gssapi_creds_from_cache()
        self.assertEqual("loaded", creds)
        self.assertIsNone(err)

    @patch(
        "acme2certifier.cahandlers.mscepces_ca_handler.CAhandler._kerberos_ccache_path",
        return_value="/tmp/cc",
    )
    @patch("acme2certifier.cahandlers.mscepces_ca_handler.importlib.import_module")
    def test_086_kerberos_gssapi_creds_from_cache_load_error(
        self, mock_import, _mock_ccache
    ):
        """Credentials load failure returns error string"""
        self.cahandler.auth_method = "gssapi"
        self.cahandler.krb5_cache = "FILE:/tmp/cc"
        mock_gssapi = MagicMock()
        mock_gssapi.Credentials.side_effect = Exception("bad cache")
        mock_import.return_value = mock_gssapi
        creds, err = self.cahandler._kerberos_gssapi_creds_from_cache()
        self.assertIsNone(creds)
        self.assertIn("Failed to load GSSAPI credentials", err)

    @patch("acme2certifier.cahandlers.mscepces_ca_handler.CAhandler._xcep_get_policies")
    def test_087_ca_templates_membership_cep_warn(self, mock_policies):
        """ca_templates_check=warn logs CEP GetPolicies failure"""
        self.cahandler.ca_templates_check = "warn"
        self.cahandler.cep_url = "https://cep/CEP"
        self.cahandler.template = "WebServer"
        mock_policies.side_effect = RuntimeError("down")
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.assertIsNone(self.cahandler._ca_templates_membership_check())
        self.assertIn("CEP GetPolicies failed", lcm.output[0])

    def test_088_trigger_not_implemented(self):
        """trigger returns not implemented"""
        result = self.cahandler.trigger("payload")
        self.assertEqual(("Method not implemented.", None, None), result)

    def _set_enroll_ready(self):
        """Set minimal fields for enroll/poll gssapi/username paths."""
        self.cahandler.ces_url = "https://ces.example.com/CES"
        self.cahandler.template = "WebServer"
        self.cahandler.auth_method = "username_password"
        self.cahandler.ces_username = "u"
        self.cahandler.ces_password = "p"
        self.cahandler.user = "u"
        self.cahandler.password = "p"
        self.cahandler.ca_templates_check = "off"


def _parse_xcep_fixture_ca_pem() -> str:
    from acme2certifier.cahandlers.mscepces_ca_handler import _parse_xcep_get_policies

    return _parse_xcep_get_policies(
        open(
            os.path.join(FIXTURE_DIR, "xcep_get_policies_response.xml"),
            encoding="utf-8",
        ).read()
    )["ca_certificates"][0]


if __name__ == "__main__":
    unittest.main()
