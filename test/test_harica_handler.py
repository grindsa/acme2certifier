# -*- coding: utf-8 -*-
"""unittests for harica_ca_handler"""

# pylint: disable=C0415, R0904, W0212
import configparser
import sys
import unittest
from unittest.mock import MagicMock, Mock, patch

sys.path.insert(0, ".")
sys.path.insert(1, "..")


class TestHaricaCAhandler(unittest.TestCase):
    """test class for harica_ca_handler"""

    def setUp(self):
        import logging
        from acme2certifier.cahandlers.harica_ca_handler import CAhandler

        logging.basicConfig(level=logging.CRITICAL)
        self.logger = logging.getLogger("test_a2c")
        self.cahandler = CAhandler(False, self.logger)
        self.cahandler.api_url = "https://cm-stg.harica.gr"
        self.cahandler.email = "user@example.com"
        self.cahandler.password = "secret"

    def test_001_totp_generate(self):
        from acme2certifier.cahandlers import harica_ca_handler

        with patch(
            "acme2certifier.cahandlers.harica_ca_handler.time.time", return_value=1234567890
        ):
            code = harica_ca_handler._totp_generate("JBSWY3DPEHPK3PXP")
        self.assertEqual(len(code), 6)
        self.assertTrue(code.isdigit())

    def test_002_config_check_missing_params(self):
        self.cahandler.email = None
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            error = self.cahandler._config_check()
        self.assertEqual("email parameter is missing in config file", error)
        self.assertIn("email parameter is missing", lcm.output[0])

    def test_003_config_check_auto_approve_requires_approver(self):
        self.cahandler.auto_approve = True
        error = self.cahandler._config_check()
        self.assertIn("approver_email", error)

    def test_004_config_check_ok(self):
        error = self.cahandler._config_check()
        self.assertIsNone(error)

    @patch("acme2certifier.cahandlers.harica_ca_handler.load_config")
    def test_005_config_load(self, mock_load_cfg):
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {
            "api_url": "https://cm-stg.harica.gr",
            "email": "a@b.c",
            "password": "pw",
            "totp_seed": "JBSWY3DPEHPK3PXP",
            "transaction_type": "EV",
            "consent_same_key": "False",
            "auto_approve": "True",
            "approver_email": "approver@example.com",
            "approver_password": "apw",
            "request_timeout": "30",
        }
        mock_load_cfg.return_value = parser
        self.cahandler._config_load()
        self.assertEqual(self.cahandler.api_url, "https://cm-stg.harica.gr")
        self.assertEqual(self.cahandler.email, "a@b.c")
        self.assertEqual(self.cahandler.transaction_type, "EV")
        self.assertFalse(self.cahandler.consent_same_key)
        self.assertTrue(self.cahandler.auto_approve)
        self.assertEqual(self.cahandler.approver_email, "approver@example.com")
        self.assertEqual(self.cahandler.request_timeout, 30)

    def test_006_domains_build(self):
        domains = self.cahandler._domains_build(["example.com", "www.example.com"])
        self.assertEqual(len(domains), 1)
        self.assertEqual(domains[0]["domain"], "example.com")
        self.assertTrue(domains[0]["includeWWW"])

    def test_007_organization_dn_build(self):
        org = {
            "id": "org-1",
            "country": "GR",
            "state": "Attica",
            "locality": "Athens",
            "organizationName": "Example Org",
        }
        org_dn = self.cahandler._organization_dn_build(org)
        self.assertIn("OrganizationId:org-1", org_dn)
        self.assertIn("&C:GR", org_dn)
        self.assertIn("&O:Example Org", org_dn)

    def test_008_fetch_rv_token(self):
        mock_response = Mock()
        mock_response.text = (
            '<input name="__RequestVerificationToken" type="hidden" value="token123" />'
        )
        mock_response.raise_for_status = Mock()
        self.cahandler._session.get = Mock(return_value=mock_response)
        self.cahandler._fetch_rv_token()
        self.assertEqual(self.cahandler._rv_token, "token123")

    def test_009_certificate_parse(self):
        cert_data = {
            "certificate": "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
            "intermediateCertificate": "-----BEGIN CERTIFICATE-----\nMIIC\n-----END CERTIFICATE-----\n",
        }
        with patch(
            "acme2certifier.cahandlers.harica_ca_handler.cert_pem2der",
            return_value=b"der",
        ):
            with patch(
                "acme2certifier.cahandlers.harica_ca_handler.b64_encode",
                return_value="rawb64",
            ):
                bundle, cert_raw = self.cahandler._certificate_parse(cert_data)
        self.assertIn("MIIB", bundle)
        self.assertIn("MIIC", bundle)
        self.assertEqual(cert_raw, "rawb64")

    @patch(
        "acme2certifier.cahandlers.harica_ca_handler.CAhandler._config_check",
        return_value=None,
    )
    @patch(
        "acme2certifier.cahandlers.harica_ca_handler.CAhandler._csr_check",
        return_value=None,
    )
    @patch(
        "acme2certifier.cahandlers.harica_ca_handler.csr_san_get",
        return_value=["example.com"],
    )
    @patch(
        "acme2certifier.cahandlers.harica_ca_handler.csr_cn_lookup",
        return_value="example.com",
    )
    @patch(
        "acme2certifier.cahandlers.harica_ca_handler.CAhandler._csr_pem_get",
        return_value="pem-csr",
    )
    @patch("acme2certifier.cahandlers.harica_ca_handler.CAhandler._login")
    @patch(
        "acme2certifier.cahandlers.harica_ca_handler.CAhandler._organization_lookup",
        return_value={"id": "org-1", "organizationName": "Org"},
    )
    @patch(
        "acme2certifier.cahandlers.harica_ca_handler.CAhandler._certificate_request",
        return_value="txn-123",
    )
    @patch(
        "acme2certifier.cahandlers.harica_ca_handler.CAhandler._certificate_fetch",
        return_value=None,
    )
    def test_010_enroll_pending(
        self,
        mock_fetch,
        mock_request,
        mock_org,
        mock_login,
        mock_pem,
        mock_cn,
        mock_san,
        mock_csr,
        mock_cfg,
    ):
        error, cert_bundle, cert_raw, poll_identifier = self.cahandler.enroll("csr")
        self.assertIsNone(error)
        self.assertIsNone(cert_bundle)
        self.assertIsNone(cert_raw)
        self.assertEqual(poll_identifier, "txn-123")

    @patch(
        "acme2certifier.cahandlers.harica_ca_handler.CAhandler._config_check",
        return_value=None,
    )
    @patch(
        "acme2certifier.cahandlers.harica_ca_handler.CAhandler._csr_check",
        return_value=None,
    )
    @patch(
        "acme2certifier.cahandlers.harica_ca_handler.csr_san_get",
        return_value=["example.com"],
    )
    @patch(
        "acme2certifier.cahandlers.harica_ca_handler.csr_cn_lookup",
        return_value="example.com",
    )
    @patch(
        "acme2certifier.cahandlers.harica_ca_handler.CAhandler._csr_pem_get",
        return_value="pem-csr",
    )
    @patch("acme2certifier.cahandlers.harica_ca_handler.CAhandler._login")
    @patch(
        "acme2certifier.cahandlers.harica_ca_handler.CAhandler._organization_lookup",
        return_value={"id": "org-1"},
    )
    @patch(
        "acme2certifier.cahandlers.harica_ca_handler.CAhandler._certificate_request",
        return_value="txn-456",
    )
    @patch(
        "acme2certifier.cahandlers.harica_ca_handler.CAhandler._certificate_fetch",
        return_value={
            "transactionStatus": "Completed",
            "certificate": "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
        },
    )
    @patch(
        "acme2certifier.cahandlers.harica_ca_handler.CAhandler._certificate_parse",
        return_value=("bundle", "raw"),
    )
    def test_011_enroll_immediate(
        self,
        mock_parse,
        mock_fetch,
        mock_request,
        mock_org,
        mock_login,
        mock_pem,
        mock_cn,
        mock_san,
        mock_csr,
        mock_cfg,
    ):
        error, cert_bundle, cert_raw, poll_identifier = self.cahandler.enroll("csr")
        self.assertIsNone(error)
        self.assertEqual(cert_bundle, "bundle")
        self.assertEqual(cert_raw, "raw")
        self.assertIsNone(poll_identifier)

    @patch("acme2certifier.cahandlers.harica_ca_handler.CAhandler._login")
    @patch(
        "acme2certifier.cahandlers.harica_ca_handler.CAhandler._certificate_fetch",
        return_value={
            "transactionStatus": "Completed",
            "certificate": "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
        },
    )
    @patch(
        "acme2certifier.cahandlers.harica_ca_handler.CAhandler._certificate_parse",
        return_value=("bundle", "raw"),
    )
    def test_012_poll_success(self, mock_parse, mock_fetch, mock_login):
        error, cert_bundle, cert_raw, poll_id, rejected = self.cahandler.poll(
            "cert", "txn-1", "csr"
        )
        self.assertIsNone(error)
        self.assertEqual(cert_bundle, "bundle")
        self.assertEqual(cert_raw, "raw")
        self.assertFalse(rejected)

    @patch("acme2certifier.cahandlers.harica_ca_handler.CAhandler._login")
    @patch(
        "acme2certifier.cahandlers.harica_ca_handler.CAhandler._certificate_fetch",
        return_value={"transactionStatus": "Pending"},
    )
    def test_013_poll_still_pending(self, mock_fetch, mock_login):
        error, cert_bundle, cert_raw, poll_id, rejected = self.cahandler.poll(
            "cert", "txn-1", "csr"
        )
        self.assertIsNone(error)
        self.assertIsNone(cert_bundle)
        self.assertFalse(rejected)
        self.assertEqual(poll_id, "txn-1")

    @patch("acme2certifier.cahandlers.harica_ca_handler.CAhandler._login")
    @patch(
        "acme2certifier.cahandlers.harica_ca_handler.CAhandler._certificate_fetch",
        return_value={"transactionStatus": "Cancelled"},
    )
    def test_014_poll_rejected(self, mock_fetch, mock_login):
        error, cert_bundle, cert_raw, poll_id, rejected = self.cahandler.poll(
            "cert", "txn-1", "csr"
        )
        self.assertTrue(rejected)

    @patch(
        "acme2certifier.cahandlers.harica_ca_handler.cert_serial_get",
        return_value="01AB",
    )
    @patch(
        "acme2certifier.cahandlers.harica_ca_handler.CAhandler._config_check",
        return_value=None,
    )
    @patch("acme2certifier.cahandlers.harica_ca_handler.CAhandler._login")
    @patch(
        "acme2certifier.cahandlers.harica_ca_handler.CAhandler._transaction_id_by_serial",
        return_value="txn-rev",
    )
    @patch(
        "acme2certifier.cahandlers.harica_ca_handler.CAhandler._api_post_json",
        return_value=(200, {}),
    )
    def test_015_revoke_success(
        self, mock_api, mock_txn, mock_login, mock_cfg, mock_serial
    ):
        code, message, detail = self.cahandler.revoke("cert-raw")
        self.assertEqual(code, 200)
        self.assertIsNone(message)

    def test_016_trigger_not_implemented(self):
        error, cert_bundle, cert_raw = self.cahandler.trigger("payload")
        self.assertEqual(error, "Method not implemented.")

    @patch("acme2certifier.cahandlers.harica_ca_handler.CAhandler._config_load")
    def test_017_enter(self, mock_cfg):
        mock_cfg.return_value = None
        self.cahandler.email = None
        with self.cahandler.__enter__():
            pass
        self.assertTrue(mock_cfg.called)

    @patch("acme2certifier.cahandlers.harica_ca_handler.CAhandler._config_load")
    def test_018_enter_skips_load(self, mock_cfg):
        self.cahandler.email = "loaded@example.com"
        with self.cahandler.__enter__():
            pass
        self.assertFalse(mock_cfg.called)


if __name__ == "__main__":
    unittest.main()
