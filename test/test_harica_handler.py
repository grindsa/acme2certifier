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
        self.cahandler.requester_email = "user@example.com"
        self.cahandler.requester_password = "secret"

    def test_001_totp_generate(self):
        from acme2certifier.cahandlers import harica_ca_handler

        with patch(
            "acme2certifier.cahandlers.harica_ca_handler.time.time",
            return_value=1234567890,
        ):
            code = harica_ca_handler.totp_generate("JBSWY3DPEHPK3PXP")
        self.assertEqual(len(code), 6)
        self.assertTrue(code.isdigit())

    def test_002_config_check_missing_params(self):
        self.cahandler.requester_email = None
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            error = self.cahandler._config_check()
        self.assertEqual("requester_email parameter is missing in config file", error)
        self.assertIn("requester_email parameter is missing", lcm.output[0])

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
            "requester_email": "a@b.c",
            "requester_password": "pw",
            "requester_totp_seed": "JBSWY3DPEHPK3PXP",
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
        self.assertEqual(self.cahandler.requester_email, "a@b.c")
        self.assertEqual(self.cahandler.transaction_type, "EV")
        self.assertFalse(self.cahandler.consent_same_key)
        self.assertTrue(self.cahandler.auto_approve)
        self.assertEqual(self.cahandler.approver_email, "approver@example.com")
        self.assertEqual(self.cahandler.request_timeout, 30)

    @patch("acme2certifier.cahandlers.harica_ca_handler.load_config")
    @patch.dict(
        "os.environ",
        {
            "HARICA_REQUESTER_EMAIL": "env@example.com",
            "HARICA_REQUESTER_PASSWORD": "env_pw",
            "HARICA_REQUESTER_TOTP": "JBSWY3DPEHPK3PXP",
            "HARICA_APPROVER_EMAIL": "appr@example.com",
            "HARICA_APPROVER_PASSWORD": "appr_pw",
            "HARICA_APPROVER_TOTP": "KRSXG5CTMVRXEZLU",
        },
        clear=False,
    )
    def test_006_config_load_from_variables(self, mock_load_cfg):
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {
            "api_url": "https://cm-stg.harica.gr",
            "requester_email_variable": "HARICA_REQUESTER_EMAIL",
            "requester_password_variable": "HARICA_REQUESTER_PASSWORD",
            "requester_totp_seed_variable": "HARICA_REQUESTER_TOTP",
            "auto_approve": "True",
            "approver_email_variable": "HARICA_APPROVER_EMAIL",
            "approver_password_variable": "HARICA_APPROVER_PASSWORD",
            "approver_totp_seed_variable": "HARICA_APPROVER_TOTP",
        }
        mock_load_cfg.return_value = parser
        self.cahandler.requester_email = None
        self.cahandler.requester_password = None
        self.cahandler._config_load()
        self.assertEqual(self.cahandler.requester_email, "env@example.com")
        self.assertEqual(self.cahandler.requester_password, "env_pw")
        self.assertEqual(self.cahandler.requester_totp_seed, "JBSWY3DPEHPK3PXP")
        self.assertEqual(self.cahandler.approver_email, "appr@example.com")
        self.assertEqual(self.cahandler.approver_password, "appr_pw")
        self.assertEqual(self.cahandler.approver_totp_seed, "KRSXG5CTMVRXEZLU")

    @patch("acme2certifier.cahandlers.harica_ca_handler.load_config")
    @patch.dict(
        "os.environ",
        {"HARICA_REQUESTER_PASSWORD": "env_pw"},
        clear=False,
    )
    def test_007_config_load_direct_overwrites_variable(self, mock_load_cfg):
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {
            "api_url": "https://cm-stg.harica.gr",
            "requester_email": "a@b.c",
            "requester_password_variable": "HARICA_REQUESTER_PASSWORD",
            "requester_password": "cfg_pw",
        }
        mock_load_cfg.return_value = parser
        self.cahandler.requester_password = None
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.cahandler._config_load()
        self.assertEqual(self.cahandler.requester_password, "cfg_pw")
        self.assertTrue(
            any("Overwrite requester_password" in line for line in lcm.output)
        )

    @patch("acme2certifier.cahandlers.harica_ca_handler.load_config")
    def test_008_config_load_missing_env_variable(self, mock_load_cfg):
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {
            "api_url": "https://cm-stg.harica.gr",
            "requester_email": "a@b.c",
            "requester_password_variable": "HARICA_MISSING_PASSWORD",
        }
        mock_load_cfg.return_value = parser
        self.cahandler.requester_password = None
        with self.assertLogs("test_a2c", level="ERROR") as lcm:
            self.cahandler._config_load()
        self.assertIsNone(self.cahandler.requester_password)
        self.assertIn("Could not load requester_password_variable", lcm.output[0])

    def test_009_domains_build(self):
        domains = self.cahandler._domains_build(["example.com", "www.example.com"])
        self.assertEqual(len(domains), 1)
        self.assertEqual(domains[0]["domain"], "example.com")
        self.assertTrue(domains[0]["includeWWW"])

    def test_010_domains_collect_strips_dns_prefix(self):
        with patch(
            "acme2certifier.cahandlers.harica_ca_handler.csr_san_get",
            return_value=["DNS:acme-client.example.com"],
        ):
            with patch(
                "acme2certifier.cahandlers.harica_ca_handler.csr_cn_lookup",
                return_value="acme-client.example.com",
            ):
                domains = self.cahandler._domains_collect("csr")
        self.assertEqual(domains, ["acme-client.example.com"])

    def test_011_domain_is_allowed(self):
        allowed = ["dynamop.de", "*.example.org"]
        self.assertTrue(self.cahandler._domain_is_allowed("dynamop.de", allowed))
        self.assertTrue(
            self.cahandler._domain_is_allowed("acme-client.dynamop.de", allowed)
        )
        self.assertTrue(self.cahandler._domain_is_allowed("foo.example.org", allowed))
        self.assertFalse(self.cahandler._domain_is_allowed("other.com", allowed))

    def test_012_domains_allowed_check_rejects(self):
        with patch.object(
            self.cahandler,
            "_domains_list_allowed",
            return_value=(["dynamop.de"], {}),
        ):
            with self.assertRaises(ValueError) as cm:
                self.cahandler._domains_allowed_check(
                    ["evil.example.com"], {"id": "org-1"}
                )
        self.assertIn("not allowed", str(cm.exception))
        self.assertIn("evil.example.com", str(cm.exception))

    def test_013_domains_allowed_check_expired(self):
        with patch.object(
            self.cahandler,
            "_domains_list_allowed",
            return_value=([], {"dynamop.de": "2026-06-17T10:15:05"}),
        ):
            with self.assertRaises(ValueError) as cm:
                self.cahandler._domains_allowed_check(
                    ["acme-client.dynamop.de"], {"id": "org-1"}
                )
        self.assertIn("expired", str(cm.exception).lower())
        self.assertIn("dynamop.de", str(cm.exception))

    def test_014_domain_validity_still_valid(self):
        self.assertIs(self.cahandler._domain_validity_still_valid(None), None)
        self.assertFalse(
            self.cahandler._domain_validity_still_valid("2020-01-01T00:00:00")
        )
        self.assertTrue(
            self.cahandler._domain_validity_still_valid("2099-01-01T00:00:00")
        )

    def test_015_organization_dn_build(self):
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

    def test_016_fetch_rv_token(self):
        mock_response = Mock()
        mock_response.text = (
            '<input name="__RequestVerificationToken" type="hidden" value="token123" />'
        )
        mock_response.raise_for_status = Mock()
        self.cahandler._session.get = Mock(return_value=mock_response)
        self.cahandler._fetch_rv_token()
        self.assertEqual(self.cahandler._rv_token, "token123")

    def test_017_certificate_parse(self):
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

    def test_018_certificate_parse_pembundle(self):
        cert_data = {
            "pemBundle": (
                "-----BEGIN CERTIFICATE-----\nLEAF\n-----END CERTIFICATE-----\n"
                "-----BEGIN CERTIFICATE-----\nCHAIN\n-----END CERTIFICATE-----\n"
            )
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
        self.assertIn("LEAF", bundle)
        self.assertIn("CHAIN", bundle)
        self.assertEqual(cert_raw, "rawb64")

    def test_019_pem_bundle_clean_strips_subject_issuer(self):
        dirty = (
            "subject=CN=acme-client-11431.dynamop.de, O=Test Organization, "
            "S=Test City, C=DE\n"
            "issuer=CN=GEANT TLS RSA 1 - STG, O=Hellenic Academic and Research "
            "Institutions CA, C=GR\n"
            "-----BEGIN CERTIFICATE-----\n"
            "LEAFBASE64\n"
            "-----END CERTIFICATE-----\n"
            "subject=CN=GEANT TLS RSA 1 - STG, O=Hellenic Academic and Research "
            "Institutions CA, C=GR\n"
            "issuer=CN=HARICA Root CA 2015, O=Hellenic Academic and Research "
            "Institutions CA, C=GR\n"
            "-----BEGIN CERTIFICATE-----\n"
            "CHAINBASE64\n"
            "-----END CERTIFICATE-----\n"
        )
        cleaned = self.cahandler._pem_bundle_clean(dirty)
        self.assertNotIn("subject=", cleaned)
        self.assertNotIn("issuer=", cleaned)
        self.assertNotIn("Test Organization", cleaned)
        self.assertIn(
            "-----BEGIN CERTIFICATE-----\nLEAFBASE64\n-----END CERTIFICATE-----",
            cleaned,
        )
        self.assertIn(
            "-----BEGIN CERTIFICATE-----\nCHAINBASE64\n-----END CERTIFICATE-----",
            cleaned,
        )
        self.assertEqual(cleaned.count("BEGIN CERTIFICATE"), 2)

    def test_020_certificate_parse_strips_harica_comments(self):
        cert_data = {
            "pemBundle": (
                "subject=CN=leaf.example.com, O=Org, C=DE\n"
                "issuer=CN=Issuer CA, O=CA, C=GR\n"
                "-----BEGIN CERTIFICATE-----\nLEAF\n-----END CERTIFICATE-----\n"
                "subject=CN=Issuer CA, O=CA, C=GR\n"
                "issuer=CN=Root CA, O=CA, C=GR\n"
                "-----BEGIN CERTIFICATE-----\nCHAIN\n-----END CERTIFICATE-----\n"
            )
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
        self.assertIsNotNone(bundle)
        self.assertNotIn("subject=", bundle)
        self.assertNotIn("issuer=", bundle)
        self.assertIn("LEAF", bundle)
        self.assertIn("CHAIN", bundle)
        self.assertEqual(cert_raw, "rawb64")

    def test_021_pem_bundle_clean_empty(self):
        self.assertEqual(self.cahandler._pem_bundle_clean(""), "")
        self.assertEqual(self.cahandler._pem_bundle_clean("subject=CN=foo"), "")
        self.assertEqual(self.cahandler._pem_bundle_clean(None), "")

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
    def test_022_enroll_pending(
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
    def test_023_enroll_immediate(
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
    def test_024_poll_success(self, mock_parse, mock_fetch, mock_login):
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
    def test_025_poll_still_pending(self, mock_fetch, mock_login):
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
    def test_026_poll_rejected(self, mock_fetch, mock_login):
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
    def test_027_revoke_success(
        self, mock_api, mock_txn, mock_login, mock_cfg, mock_serial
    ):
        code, message, detail = self.cahandler.revoke("cert-raw")
        self.assertEqual(code, 200)
        self.assertIsNone(message)
        mock_api.assert_called_once()
        self.assertEqual(mock_api.call_args[0][0], "/api/Certificate/RevokeCertificate")

    def test_028_trigger_not_implemented(self):
        error, cert_bundle, cert_raw = self.cahandler.trigger("payload")
        self.assertEqual(error, "Method not implemented.")

    @patch("acme2certifier.cahandlers.harica_ca_handler.CAhandler._config_load")
    def test_029_enter(self, mock_cfg):
        mock_cfg.return_value = None
        self.cahandler.requester_email = None
        with self.cahandler.__enter__():
            pass
        self.assertTrue(mock_cfg.called)

    @patch("acme2certifier.cahandlers.harica_ca_handler.CAhandler._config_load")
    def test_030_enter_skips_load(self, mock_cfg):
        self.cahandler.requester_email = "loaded@example.com"
        with self.cahandler.__enter__():
            pass
        self.assertFalse(mock_cfg.called)

    def test_031_exit(self):
        self.assertIsNone(self.cahandler.__exit__(None, None, None))

    @patch("acme2certifier.cahandlers.harica_ca_handler.proxy_check")
    @patch("acme2certifier.cahandlers.harica_ca_handler.parse_url")
    def test_032_config_proxy_load_success(self, mock_url, mock_chk):
        parser = configparser.ConfigParser()
        parser["DEFAULT"] = {
            "proxy_server_list": '[["cm-stg.harica.gr", "http://proxy:8080"]]'
        }
        mock_url.return_value = {"host": "cm-stg.harica.gr"}
        mock_chk.return_value = "http://proxy:8080"
        self.cahandler._config_proxy_load(parser)
        self.assertEqual(
            {"http": "http://proxy:8080", "https": "http://proxy:8080"},
            self.cahandler.proxy,
        )

    def test_033_config_proxy_load_parse_fail(self):
        parser = configparser.ConfigParser()
        parser["DEFAULT"] = {"proxy_server_list": "not-json"}
        with self.assertLogs("test_a2c", level="WARNING") as lcm:
            self.cahandler._config_proxy_load(parser)
        self.assertIn("Failed to parse proxy_server_list", lcm.output[0])

    @patch("acme2certifier.cahandlers.harica_ca_handler.config_enroll_config_log_load")
    @patch("acme2certifier.cahandlers.harica_ca_handler.config_headerinfo_load")
    @patch("acme2certifier.cahandlers.harica_ca_handler.config_profile_load")
    @patch("acme2certifier.cahandlers.harica_ca_handler.config_eab_profile_load")
    @patch("acme2certifier.cahandlers.harica_ca_handler.load_config")
    def test_034_config_load_edge_cases(
        self, mock_load, mock_eab, mock_prof, mock_hdr, mock_enroll
    ):
        mock_eab.return_value = (False, None)
        mock_prof.return_value = {}
        mock_hdr.return_value = False
        mock_enroll.return_value = (True, ["password"])
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {
            "api_url": "https://cm-stg.harica.gr/",
            "requester_email": "a@b.c",
            "requester_password": "pw",
            "consent_same_key": "maybe",
            "auto_approve": "notabool",
            "organization_id": '""',
            "request_timeout": "bad",
            "request_retries": "bad",
            "request_retry_backoff": "bad",
            "ca_bundle": "/etc/ssl/certs/ca.pem",
        }
        mock_load.return_value = parser
        self.cahandler._config_load()
        self.assertFalse(self.cahandler.consent_same_key)
        self.assertFalse(self.cahandler.auto_approve)
        self.assertIsNone(self.cahandler.organization_id)
        self.assertEqual(self.cahandler.request_timeout, 60)
        self.assertEqual(self.cahandler.request_retries, 3)
        self.assertEqual(self.cahandler.request_retry_backoff, 2.0)
        self.assertEqual(self.cahandler.ca_bundle, "/etc/ssl/certs/ca.pem")
        self.assertTrue(self.cahandler.enrollment_config_log)
        self.assertEqual(self.cahandler.enrollment_config_log_skip_list, ["password"])

    @patch("acme2certifier.cahandlers.harica_ca_handler.config_enroll_config_log_load")
    @patch("acme2certifier.cahandlers.harica_ca_handler.config_headerinfo_load")
    @patch("acme2certifier.cahandlers.harica_ca_handler.config_profile_load")
    @patch("acme2certifier.cahandlers.harica_ca_handler.config_eab_profile_load")
    @patch("acme2certifier.cahandlers.harica_ca_handler.load_config")
    def test_035_config_load_org_id_strip_and_ca_bundle_bool(
        self, mock_load, mock_eab, mock_prof, mock_hdr, mock_enroll
    ):
        mock_eab.return_value = (False, None)
        mock_prof.return_value = {}
        mock_hdr.return_value = False
        mock_enroll.return_value = (False, [])
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {
            "api_url": "https://cm-stg.harica.gr",
            "requester_email": "a@b.c",
            "requester_password": "pw",
            "organization_id": "  org-99  ",
            "consent_same_key": "yes",
            "ca_bundle": "False",
        }
        mock_load.return_value = parser
        self.cahandler._config_load()
        self.assertEqual(self.cahandler.organization_id, "org-99")
        self.assertTrue(self.cahandler.consent_same_key)
        self.assertFalse(self.cahandler.ca_bundle)

    @patch(
        "acme2certifier.cahandlers.harica_ca_handler.eab_profile_header_info_check",
        return_value="profile error",
    )
    def test_036_csr_check(self, mock_eab):
        self.assertEqual(self.cahandler._csr_check("csr"), "profile error")
        mock_eab.assert_called_once()

    def test_037_fetch_rv_token_with_jwt_and_missing(self):
        self.cahandler._jwt_token = "jwt-token"
        mock_ok = Mock()
        mock_ok.text = '<input name="__RequestVerificationToken" value="tok-jwt" />'
        mock_ok.raise_for_status = Mock()
        self.cahandler._session.get = Mock(return_value=mock_ok)
        self.cahandler._fetch_rv_token()
        self.assertEqual(self.cahandler._rv_token, "tok-jwt")
        headers = self.cahandler._session.get.call_args[1]["headers"]
        self.assertEqual(headers["Authorization"], "jwt-token")

        mock_bad = Mock()
        mock_bad.text = "<html>no token</html>"
        mock_bad.raise_for_status = Mock()
        self.cahandler._session.get = Mock(return_value=mock_bad)
        with self.assertRaises(ValueError) as cm:
            self.cahandler._fetch_rv_token()
        self.assertIn("RequestVerificationToken not found", str(cm.exception))

    def test_038_auth_headers(self):
        self.cahandler._jwt_token = "jwt"
        self.cahandler._rv_token = "rv"
        with_ct = self.cahandler._auth_headers("application/json")
        self.assertEqual(with_ct["Content-Type"], "application/json")
        self.assertEqual(with_ct["Authorization"], "jwt")
        without_ct = self.cahandler._auth_headers(None)
        self.assertNotIn("Content-Type", without_ct)

    def test_039_parse_api_response_paths(self):
        redirect = Mock()
        redirect.status_code = 302
        redirect.url = "https://cm-stg.harica.gr/Login"
        redirect.text = ""
        with self.assertRaises(PermissionError):
            self.cahandler._parse_api_response(redirect)

        login_html = Mock()
        login_html.status_code = 200
        login_html.url = "https://cm-stg.harica.gr/api/foo"
        login_html.text = "<!DOCTYPE html><title>Login</title>"
        with self.assertRaises(PermissionError):
            self.cahandler._parse_api_response(login_html)

        empty = Mock()
        empty.status_code = 204
        empty.url = "https://cm-stg.harica.gr/api/foo"
        empty.text = ""
        self.assertEqual(self.cahandler._parse_api_response(empty), (204, None))

        ok = Mock()
        ok.status_code = 200
        ok.url = "https://cm-stg.harica.gr/api/foo"
        ok.text = '{"a": 1}'
        ok.json = Mock(return_value={"a": 1})
        self.assertEqual(self.cahandler._parse_api_response(ok), (200, {"a": 1}))

        plain = Mock()
        plain.status_code = 200
        plain.url = "https://cm-stg.harica.gr/api/foo"
        plain.text = "not-json"
        plain.json = Mock(side_effect=ValueError("no json"))
        self.assertEqual(self.cahandler._parse_api_response(plain), (200, "not-json"))

    @patch(
        "acme2certifier.cahandlers.harica_ca_handler.totp_generate",
        return_value="123456",
    )
    @patch("acme2certifier.cahandlers.harica_ca_handler.CAhandler._fetch_rv_token")
    def test_040_login_with_totp_success(self, mock_fetch, mock_totp):
        self.cahandler._rv_token = "rv"
        mock_resp = Mock()
        mock_resp.status_code = 200
        mock_resp.text = '"jwt-value"'
        self.cahandler._session.post = Mock(return_value=mock_resp)
        self.cahandler._login("user@ex.com", "pw", "SEED")
        self.assertEqual(self.cahandler._jwt_token, "jwt-value")
        self.assertEqual(mock_fetch.call_count, 2)
        endpoint = self.cahandler._session.post.call_args[0][0]
        self.assertIn("Login2FA", endpoint)
        mock_totp.assert_called_once_with("SEED")

    @patch("acme2certifier.cahandlers.harica_ca_handler.CAhandler._fetch_rv_token")
    def test_041_login_fail_and_empty_token(self, mock_fetch):
        self.cahandler._rv_token = "rv"
        fail = Mock()
        fail.status_code = 401
        fail.text = "denied"
        self.cahandler._session.post = Mock(return_value=fail)
        with self.assertRaises(PermissionError) as cm:
            self.cahandler._login("u", "p", None)
        self.assertIn("login failed", str(cm.exception))

        empty = Mock()
        empty.status_code = 200
        empty.text = '""'
        self.cahandler._session.post = Mock(return_value=empty)
        with self.assertRaises(PermissionError) as cm2:
            self.cahandler._login("u", "p", None)
        self.assertIn("empty JWT", str(cm2.exception))

    def test_042_api_post_json_not_logged_in_and_success(self):
        self.cahandler._jwt_token = None
        self.cahandler._rv_token = None
        with self.assertRaises(PermissionError):
            self.cahandler._api_post_json("/api/x", {})

        self.cahandler._jwt_token = "jwt"
        self.cahandler._rv_token = "rv"
        mock_resp = Mock()
        mock_resp.status_code = 200
        mock_resp.url = "https://cm-stg.harica.gr/api/x"
        mock_resp.text = "{}"
        mock_resp.json = Mock(return_value={})
        self.cahandler._session.post = Mock(return_value=mock_resp)
        code, content = self.cahandler._api_post_json("/api/x", {"a": 1})
        self.assertEqual(code, 200)
        self.assertEqual(content, {})

    def test_043_api_post_multipart(self):
        self.cahandler._jwt_token = None
        with self.assertRaises(PermissionError):
            self.cahandler._api_post_multipart("/api/x", {"f": (None, "v")})

        self.cahandler._jwt_token = "jwt"
        self.cahandler._rv_token = "rv"
        mock_resp = Mock()
        mock_resp.status_code = 201
        mock_resp.url = "https://cm-stg.harica.gr/api/x"
        mock_resp.text = '{"id": "1"}'
        mock_resp.json = Mock(return_value={"id": "1"})
        self.cahandler._session.post = Mock(return_value=mock_resp)
        code, content = self.cahandler._api_post_multipart("/api/x", {"f": (None, "v")})
        self.assertEqual(code, 201)
        self.assertEqual(content, {"id": "1"})
        headers = self.cahandler._session.post.call_args[1]["headers"]
        self.assertNotIn("Content-Type", headers)

    def test_044_domains_build_wildcard_skip(self):
        domains = self.cahandler._domains_build(
            ["*.example.com", "www.example.com", "example.com"]
        )
        self.assertEqual(len(domains), 1)
        self.assertTrue(domains[0]["isWildcard"])
        self.assertEqual(domains[0]["domain"], "*.example.com")

    def test_045_organization_dn_build_ou(self):
        org = {
            "id": "org-1",
            "organizationUnitName": "IT",
        }
        org_dn = self.cahandler._organization_dn_build(org)
        self.assertIn("&OU:IT", org_dn)

    def test_046_domains_collect_edge_cases(self):
        with patch(
            "acme2certifier.cahandlers.harica_ca_handler.csr_san_get",
            return_value=[123, "IP:1.2.3.4", "EMAIL:a@b.c", "bare.example.com"],
        ):
            with patch(
                "acme2certifier.cahandlers.harica_ca_handler.csr_cn_lookup",
                return_value="DNS:cn.example.com",
            ):
                with self.assertLogs("test_a2c", level="WARNING") as lcm:
                    domains = self.cahandler._domains_collect("csr")
        self.assertEqual(domains, ["cn.example.com", "bare.example.com"])
        self.assertTrue(any("Skipping non-DNS SAN" in line for line in lcm.output))

    def test_047_domain_validity_z_suffix_and_parse_fail(self):
        self.assertTrue(
            self.cahandler._domain_validity_still_valid("2099-01-01T00:00:00Z")
        )
        self.assertTrue(
            self.cahandler._domain_validity_still_valid("2099-01-01T00:00:00.1234567")
        )
        with self.assertLogs("test_a2c", level="WARNING") as lcm:
            self.assertIsNone(self.cahandler._domain_validity_still_valid("not-a-date"))
        self.assertIn("Could not parse HARICA domain validity", lcm.output[0])

    def test_048_domains_rows_collect(self):
        rows = [
            "skip",
            {"domain": ""},
            {"fqdn": "valid.example.com", "validity": "2099-01-01T00:00:00"},
            {"name": "old.example.com", "validity": "2020-01-01T00:00:00"},
        ]
        with self.assertLogs("test_a2c", level="WARNING") as lcm:
            valid, expired = self.cahandler._domains_rows_collect(rows)
        self.assertEqual(valid, ["valid.example.com"])
        self.assertIn("old.example.com", expired)
        self.assertIn("validation expired", lcm.output[0])

    @patch(
        "acme2certifier.cahandlers.harica_ca_handler.CAhandler._api_post_json",
        return_value=(500, None),
    )
    def test_049_domains_list_allowed_search_groups_fail(self, mock_api):
        allowed, expired = self.cahandler._domains_list_allowed({"id": "org-1"})
        self.assertEqual(allowed, [])
        self.assertEqual(expired, {})

    @patch("acme2certifier.cahandlers.harica_ca_handler.CAhandler._api_post_json")
    def test_050_domains_list_allowed_group_filter_and_validity(self, mock_api):
        mock_api.side_effect = [
            (
                200,
                [
                    {"id": None},
                    {"id": "g-other", "organizationId": "other"},
                    {"id": "g-match", "organizationId": "org-1"},
                ],
            ),
            (
                200,
                [
                    {
                        "domain": "allowed.example.com",
                        "validity": "2099-01-01T00:00:00",
                    },
                    {
                        "domain": "expired.example.com",
                        "validity": "2020-01-01T00:00:00",
                    },
                ],
            ),
        ]
        with self.assertLogs("test_a2c", level="WARNING"):
            allowed, expired = self.cahandler._domains_list_allowed({"id": "org-1"})
        self.assertEqual(allowed, ["allowed.example.com"])
        self.assertIn("expired.example.com", expired)

    @patch("acme2certifier.cahandlers.harica_ca_handler.CAhandler._api_post_json")
    def test_051_domains_list_allowed_fallback_first_group(self, mock_api):
        # org filter skips g1 in the loop; fallback re-queries groups[0]
        mock_api.side_effect = [
            (200, [{"id": "g1", "organizationId": "other"}]),
            (
                200,
                [{"domain": "fallback.example.com", "validity": None}],
            ),
        ]
        allowed, expired = self.cahandler._domains_list_allowed({"id": "org-1"})
        self.assertEqual(allowed, ["fallback.example.com"])
        self.assertEqual(expired, {})

    @patch("acme2certifier.cahandlers.harica_ca_handler.CAhandler._api_post_json")
    def test_052_domains_list_allowed_group_domains_fallback(self, mock_api):
        # loop + fallback GetDomainsValidity both fail → use group["domains"]
        mock_api.side_effect = [
            (200, [{"id": "g1", "domains": ["Group.Example.com", "", None]}]),
            (400, None),
            (400, None),
        ]
        allowed, expired = self.cahandler._domains_list_allowed({"id": "org-1"})
        self.assertEqual(allowed, ["group.example.com"])
        self.assertEqual(expired, {})

    @patch(
        "acme2certifier.cahandlers.harica_ca_handler.CAhandler._api_post_json",
        side_effect=RuntimeError("boom"),
    )
    def test_053_domains_list_allowed_exception(self, mock_api):
        with self.assertLogs("test_a2c", level="WARNING") as lcm:
            allowed, expired = self.cahandler._domains_list_allowed({"id": "org-1"})
        self.assertEqual(allowed, [])
        self.assertEqual(expired, {})
        self.assertIn("Could not list HARICA allowed domains", lcm.output[0])

    def test_054_domains_allowed_check_skip_when_empty(self):
        with patch.object(
            self.cahandler, "_domains_list_allowed", return_value=([], {})
        ):
            self.cahandler._domains_allowed_check(
                ["anything.example.com"], {"id": "org-1"}
            )

    def test_055_domains_allowed_check_ok(self):
        with patch.object(
            self.cahandler,
            "_domains_list_allowed",
            return_value=(["example.com"], {}),
        ):
            self.cahandler._domains_allowed_check(["www.example.com"], {"id": "org-1"})

    @patch(
        "acme2certifier.cahandlers.harica_ca_handler.CAhandler._api_post_json",
        return_value=(500, "err"),
    )
    def test_056_organization_lookup_fail(self, mock_api):
        with self.assertRaises(ValueError) as cm:
            self.cahandler._organization_lookup(["example.com"])
        self.assertIn("Organization lookup failed", str(cm.exception))

    @patch("acme2certifier.cahandlers.harica_ca_handler.CAhandler._api_post_json")
    def test_057_organization_lookup_filter_and_multi(self, mock_api):
        mock_api.return_value = (
            200,
            [{"id": "org-a"}, {"id": "org-b"}],
        )
        self.cahandler.organization_id = "org-a"
        org = self.cahandler._organization_lookup(["example.com"])
        self.assertEqual(org["id"], "org-a")

        self.cahandler.organization_id = "missing"
        with self.assertRaises(ValueError) as cm:
            self.cahandler._organization_lookup(["example.com"])
        self.assertIn("No matching HARICA organization", str(cm.exception))

        self.cahandler.organization_id = None
        with self.assertRaises(ValueError) as cm2:
            self.cahandler._organization_lookup(["example.com"])
        self.assertIn("Multiple HARICA organizations", str(cm2.exception))

    @patch(
        "acme2certifier.cahandlers.harica_ca_handler.build_pem_file",
        return_value="-----BEGIN CERTIFICATE REQUEST-----\nX\n-----END CERTIFICATE REQUEST-----\n",
    )
    @patch(
        "acme2certifier.cahandlers.harica_ca_handler.b64_url_recode",
        return_value="recode",
    )
    def test_058_csr_pem_get(self, mock_recode, mock_pem):
        pem = self.cahandler._csr_pem_get("csr")
        self.assertIn("BEGIN CERTIFICATE REQUEST", pem)
        mock_recode.assert_called_once()
        mock_pem.assert_called_once()

    @patch(
        "acme2certifier.cahandlers.harica_ca_handler.CAhandler._api_post_multipart",
        return_value=(200, {"id": "txn-ov"}),
    )
    def test_059_certificate_request_ov(self, mock_mp):
        self.cahandler.transaction_type = "OV"
        self.cahandler.consent_same_key = False
        txn = self.cahandler._certificate_request(
            "pem",
            ["example.com"],
            {
                "id": "org-1",
                "country": "GR",
                "organizationName": "Org",
            },
        )
        self.assertEqual(txn, "txn-ov")
        form = mock_mp.call_args[0][1]
        self.assertIn("organizationDN", form)
        self.assertEqual(form["consentSameKey"][1], "false")

    @patch(
        "acme2certifier.cahandlers.harica_ca_handler.CAhandler._api_post_multipart",
        return_value=(400, "bad"),
    )
    def test_060_certificate_request_fail(self, mock_mp):
        self.cahandler.transaction_type = "DV"
        with self.assertRaises(ValueError) as cm:
            self.cahandler._certificate_request("pem", ["example.com"], {"id": "o"})
        self.assertIn("Certificate request failed", str(cm.exception))
        form = mock_mp.call_args[0][1]
        self.assertNotIn("organizationDN", form)

    @patch("acme2certifier.cahandlers.harica_ca_handler.CAhandler._api_post_json")
    def test_061_certificate_fetch_paths(self, mock_api):
        mock_api.return_value = (404, None)
        self.assertIsNone(self.cahandler._certificate_fetch("txn"))

        mock_api.return_value = (500, "err")
        with self.assertRaises(ValueError) as cm:
            self.cahandler._certificate_fetch("txn")
        self.assertIn("GetCertificate failed", str(cm.exception))

        mock_api.return_value = (200, {"certificate": "pem"})
        self.assertEqual(
            self.cahandler._certificate_fetch("txn"), {"certificate": "pem"}
        )

        mock_api.return_value = (200, "not-a-dict")
        self.assertIsNone(self.cahandler._certificate_fetch("txn"))

    def test_062_transaction_status_get_alt_keys(self):
        self.assertEqual(
            self.cahandler._transaction_status_get({"status": "Ready"}), "Ready"
        )
        self.assertEqual(
            self.cahandler._transaction_status_get(
                {"transaction_status": "Processing"}
            ),
            "Processing",
        )
        self.assertIsNone(self.cahandler._transaction_status_get({}))

    def test_063_pem_bundle_clean_incomplete_block(self):
        self.assertEqual(
            self.cahandler._pem_bundle_clean("-----BEGIN CERTIFICATE-----"),
            "",
        )

    def test_064_certificate_parse_edge_paths(self):
        with patch(
            "acme2certifier.cahandlers.harica_ca_handler.cert_pem2der",
            return_value=b"der",
        ):
            with patch(
                "acme2certifier.cahandlers.harica_ca_handler.b64_encode",
                return_value="raw",
            ):
                bundle, raw = self.cahandler._certificate_parse(
                    {
                        "pemBundle": (
                            "-----BEGIN CERTIFICATE-----\nLEAF\n"
                            "-----END CERTIFICATE-----\n"
                        ),
                        "certificate": (
                            "-----BEGIN CERTIFICATE-----\nLEAF\n"
                            "-----END CERTIFICATE-----\n"
                        ),
                    }
                )
        self.assertIn("LEAF", bundle)
        self.assertEqual(raw, "raw")

        self.assertEqual(self.cahandler._certificate_parse({}), (None, None))
        self.assertEqual(
            self.cahandler._certificate_parse(
                {"pemBundle": "-----BEGIN CERTIFICATE-----"}
            ),
            (None, None),
        )

    @patch("acme2certifier.cahandlers.harica_ca_handler.CAhandler._api_post_multipart")
    @patch("acme2certifier.cahandlers.harica_ca_handler.CAhandler._api_post_json")
    def test_065_approve_transaction_success(self, mock_json, mock_mp):
        mock_json.return_value = (
            200,
            [
                {
                    "transactionId": "txn-1",
                    "reviewGetDTOs": [
                        {
                            "isReviewed": False,
                            "reviewId": "r1",
                            "reviewValue": "v1",
                        },
                        {"isReviewed": True, "reviewId": "r2", "reviewValue": "v2"},
                    ],
                },
                {"transactionId": "other"},
            ],
        )
        mock_mp.return_value = (200, {})
        self.cahandler._approve_transaction("txn-1")
        self.assertTrue(mock_mp.called)

    @patch(
        "acme2certifier.cahandlers.harica_ca_handler.CAhandler._api_post_json",
        return_value=(500, None),
    )
    def test_066_approve_transaction_list_fail(self, mock_json):
        with self.assertRaises(ValueError) as cm:
            self.cahandler._approve_transaction("txn-1")
        self.assertIn("GetSSLReviewableTransactions failed", str(cm.exception))

    @patch(
        "acme2certifier.cahandlers.harica_ca_handler.CAhandler._api_post_json",
        return_value=(200, [{"transactionId": "txn-1", "reviewGetDTOs": []}]),
    )
    def test_067_approve_transaction_no_reviews(self, mock_json):
        with self.assertLogs("test_a2c", level="WARNING") as lcm:
            self.cahandler._approve_transaction("txn-1")
        self.assertIn("No pending reviews found", lcm.output[0])

    @patch(
        "acme2certifier.cahandlers.harica_ca_handler.CAhandler._api_post_multipart",
        return_value=(400, "nope"),
    )
    @patch("acme2certifier.cahandlers.harica_ca_handler.CAhandler._api_post_json")
    def test_068_approve_transaction_update_fail(self, mock_json, mock_mp):
        mock_json.return_value = (
            200,
            [
                {
                    "transactionId": "txn-1",
                    "reviewGetDTOs": [
                        {
                            "isReviewed": False,
                            "reviewId": "r1",
                            "reviewValue": "v1",
                        }
                    ],
                }
            ],
        )
        with self.assertRaises(ValueError) as cm:
            self.cahandler._approve_transaction("txn-1")
        self.assertIn("UpdateReviews failed", str(cm.exception))

    @patch("acme2certifier.cahandlers.harica_ca_handler.CAhandler._certificate_fetch")
    @patch("acme2certifier.cahandlers.harica_ca_handler.CAhandler._api_post_json")
    def test_069_transaction_id_by_serial_direct(self, mock_api, mock_fetch):
        mock_api.return_value = (
            200,
            [{"serialNumber": "01:AB", "transactionId": "txn-a"}],
        )
        self.assertEqual(self.cahandler._transaction_id_by_serial("01ab"), "txn-a")
        self.assertFalse(mock_fetch.called)
        mock_api.assert_called_once_with("/api/ServerCertificate/GetMyTransactions", {})

    @patch("acme2certifier.cahandlers.harica_ca_handler.CAhandler._certificate_fetch")
    @patch("acme2certifier.cahandlers.harica_ca_handler.CAhandler._api_post_json")
    def test_070_transaction_id_by_serial_via_fetch(self, mock_api, mock_fetch):
        mock_api.side_effect = [
            (200, [{"id": "txn-b"}]),
            (200, []),
        ]
        mock_fetch.return_value = {"serialNumber": "cdef"}
        self.assertEqual(self.cahandler._transaction_id_by_serial("cdef"), "txn-b")

    @patch("acme2certifier.cahandlers.harica_ca_handler.CAhandler._certificate_fetch")
    @patch("acme2certifier.cahandlers.harica_ca_handler.CAhandler._api_post_json")
    def test_071_transaction_id_by_serial_validator_fallback(
        self, mock_api, mock_fetch
    ):
        mock_api.side_effect = [
            (200, []),
            (
                200,
                [
                    {"id": None},
                    {"transactionId": "txn-skip"},
                    {"transactionId": "txn-c", "serialNumber": "99"},
                ],
            ),
        ]
        self.assertEqual(self.cahandler._transaction_id_by_serial("99"), "txn-c")
        self.assertEqual(mock_api.call_count, 2)
        self.assertEqual(
            mock_api.call_args_list[1][0][0],
            "/api/OrganizationValidatorSSL/GetSSLTransactions",
        )

    @patch("acme2certifier.cahandlers.harica_ca_handler.CAhandler._certificate_fetch")
    @patch("acme2certifier.cahandlers.harica_ca_handler.CAhandler._api_post_json")
    def test_072_transaction_id_by_serial_not_found(self, mock_api, mock_fetch):
        mock_api.side_effect = [
            (200, [{"id": "txn-x"}, {"id": "txn-y"}]),
            (200, []),
        ]
        mock_fetch.side_effect = [None, {"serial": "nope"}]
        self.assertIsNone(self.cahandler._transaction_id_by_serial("dead"))

    @patch("acme2certifier.cahandlers.harica_ca_handler.CAhandler._certificate_fetch")
    @patch("acme2certifier.cahandlers.harica_ca_handler.CAhandler._api_post_json")
    def test_073_transaction_id_skips_validator_302(self, mock_api, mock_fetch):
        mock_api.side_effect = [
            (200, []),
            PermissionError("HARICA API redirected to login"),
        ]
        self.assertIsNone(self.cahandler._transaction_id_by_serial("dead"))
        self.assertEqual(mock_api.call_count, 2)

    @patch(
        "acme2certifier.cahandlers.harica_ca_handler.CAhandler._config_check",
        return_value="cfg error",
    )
    def test_074_enroll_config_error(self, mock_cfg):
        error, *_ = self.cahandler.enroll("csr")
        self.assertEqual(error, "cfg error")

    @patch(
        "acme2certifier.cahandlers.harica_ca_handler.CAhandler._config_check",
        return_value=None,
    )
    @patch(
        "acme2certifier.cahandlers.harica_ca_handler.CAhandler._csr_check",
        return_value="csr error",
    )
    def test_075_enroll_csr_error(self, mock_csr, mock_cfg):
        error, *_ = self.cahandler.enroll("csr")
        self.assertEqual(error, "csr error")

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
        return_value=[],
    )
    @patch(
        "acme2certifier.cahandlers.harica_ca_handler.csr_cn_lookup",
        return_value=None,
    )
    @patch("acme2certifier.cahandlers.harica_ca_handler.enrollment_config_log")
    def test_076_enroll_no_domains(
        self, mock_log, mock_cn, mock_san, mock_csr, mock_cfg
    ):
        self.cahandler.enrollment_config_log = True
        with self.assertLogs("test_a2c", level="ERROR") as lcm:
            error, *_ = self.cahandler.enroll("csr")
        self.assertIn("no CN or SAN", error)
        self.assertTrue(mock_log.called)
        self.assertIn("Certificate enrollment failed", lcm.output[0])

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
        return_value="pem",
    )
    @patch("acme2certifier.cahandlers.harica_ca_handler.CAhandler._login")
    @patch(
        "acme2certifier.cahandlers.harica_ca_handler.CAhandler._organization_lookup",
        return_value={"id": "org-1"},
    )
    @patch(
        "acme2certifier.cahandlers.harica_ca_handler.CAhandler._domains_allowed_check"
    )
    @patch(
        "acme2certifier.cahandlers.harica_ca_handler.CAhandler._certificate_request",
        return_value="txn-aa",
    )
    @patch("acme2certifier.cahandlers.harica_ca_handler.CAhandler._approve_transaction")
    @patch(
        "acme2certifier.cahandlers.harica_ca_handler.CAhandler._certificate_fetch",
        return_value={"transactionStatus": "Rejected"},
    )
    def test_077_enroll_auto_approve_rejected(
        self,
        mock_fetch,
        mock_approve,
        mock_req,
        mock_allow,
        mock_org,
        mock_login,
        mock_pem,
        mock_cn,
        mock_san,
        mock_csr,
        mock_cfg,
    ):
        self.cahandler.auto_approve = True
        self.cahandler.approver_email = "a@b.c"
        self.cahandler.approver_password = "apw"
        error, bundle, raw, poll = self.cahandler.enroll("csr")
        self.assertIn("rejected", error.lower())
        self.assertIsNone(poll)
        self.assertEqual(mock_login.call_count, 3)
        self.assertTrue(mock_approve.called)

    def test_078_poll_missing_identifier(self):
        error, bundle, raw, poll_id, rejected = self.cahandler.poll("c", None, "csr")
        self.assertEqual(error, "Missing poll_identifier")
        self.assertFalse(rejected)

    @patch("acme2certifier.cahandlers.harica_ca_handler.CAhandler._login")
    @patch(
        "acme2certifier.cahandlers.harica_ca_handler.CAhandler._certificate_fetch",
        return_value=None,
    )
    def test_079_poll_fetch_none(self, mock_fetch, mock_login):
        error, bundle, raw, poll_id, rejected = self.cahandler.poll("c", "txn", "csr")
        self.assertIsNone(error)
        self.assertIsNone(bundle)
        self.assertFalse(rejected)

    @patch("acme2certifier.cahandlers.harica_ca_handler.CAhandler._login")
    @patch(
        "acme2certifier.cahandlers.harica_ca_handler.CAhandler._certificate_fetch",
        return_value={
            "transactionStatus": "Completed",
            "certificate": "-----BEGIN CERTIFICATE-----\nX\n-----END CERTIFICATE-----\n",
        },
    )
    @patch(
        "acme2certifier.cahandlers.harica_ca_handler.CAhandler._certificate_parse",
        return_value=(None, None),
    )
    def test_080_poll_parse_fail(self, mock_parse, mock_fetch, mock_login):
        error, bundle, raw, poll_id, rejected = self.cahandler.poll("c", "txn", "csr")
        self.assertEqual(error, "Certificate response did not contain PEM data")

    @patch(
        "acme2certifier.cahandlers.harica_ca_handler.CAhandler._login",
        side_effect=RuntimeError("poll boom"),
    )
    def test_081_poll_exception(self, mock_login):
        with self.assertLogs("test_a2c", level="ERROR") as lcm:
            error, *_ = self.cahandler.poll("c", "txn", "csr")
        self.assertEqual(error, "poll boom")
        self.assertIn("Certificate poll failed", lcm.output[0])

    @patch(
        "acme2certifier.cahandlers.harica_ca_handler.cert_serial_get",
        return_value=None,
    )
    def test_082_revoke_no_serial(self, mock_serial):
        with self.assertLogs("test_a2c", level="WARNING") as lcm:
            code, message, detail = self.cahandler.revoke("cert")
        self.assertEqual(code, 400)
        self.assertIn("serial", detail.lower())
        self.assertIn("Certificate revoke failed", lcm.output[0])

    @patch(
        "acme2certifier.cahandlers.harica_ca_handler.cert_serial_get",
        return_value="01ab",
    )
    @patch(
        "acme2certifier.cahandlers.harica_ca_handler.CAhandler._config_check",
        return_value="bad cfg",
    )
    def test_083_revoke_config_error(self, mock_cfg, mock_serial):
        code, message, detail = self.cahandler.revoke("cert")
        self.assertEqual(code, 500)
        self.assertEqual(detail, "bad cfg")

    @patch(
        "acme2certifier.cahandlers.harica_ca_handler.cert_serial_get",
        return_value="01ab",
    )
    @patch(
        "acme2certifier.cahandlers.harica_ca_handler.CAhandler._config_check",
        return_value=None,
    )
    @patch("acme2certifier.cahandlers.harica_ca_handler.CAhandler._login")
    @patch(
        "acme2certifier.cahandlers.harica_ca_handler.CAhandler._transaction_id_by_serial",
        return_value=None,
    )
    def test_084_revoke_txn_not_found(
        self, mock_txn, mock_login, mock_cfg, mock_serial
    ):
        code, message, detail = self.cahandler.revoke("cert")
        self.assertEqual(code, 404)
        self.assertIn("No HARICA transaction found", detail)

    @patch(
        "acme2certifier.cahandlers.harica_ca_handler.cert_serial_get",
        return_value="01ab",
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
        return_value=(400, "denied"),
    )
    def test_085_revoke_api_fail(
        self, mock_api, mock_txn, mock_login, mock_cfg, mock_serial
    ):
        code, message, detail = self.cahandler.revoke("cert")
        self.assertEqual(code, 500)
        self.assertIn("Revoke failed", detail)

    @patch(
        "acme2certifier.cahandlers.harica_ca_handler.cert_serial_get",
        return_value="01ab",
    )
    @patch(
        "acme2certifier.cahandlers.harica_ca_handler.CAhandler._config_check",
        return_value=None,
    )
    @patch(
        "acme2certifier.cahandlers.harica_ca_handler.CAhandler._login",
        side_effect=RuntimeError("rev boom"),
    )
    def test_086_revoke_exception(self, mock_login, mock_cfg, mock_serial):
        with self.assertLogs("test_a2c", level="ERROR") as lcm:
            code, message, detail = self.cahandler.revoke("cert")
        self.assertEqual(code, 500)
        self.assertEqual(detail, "rev boom")
        self.assertIn("Certificate revoke failed", lcm.output[0])

    def test_087_handler_check(self):
        with patch.object(
            self.cahandler, "_config_check", return_value="missing requester_email"
        ) as mock_chk:
            self.assertEqual(self.cahandler.handler_check(), "missing requester_email")
            mock_chk.assert_called_once()

    def test_088_domains_rows_from_groups_empty_ids(self):
        """groups without ids hit the empty fallback return."""
        self.assertEqual(self.cahandler._domains_rows_from_groups([{}], "org-1"), [])

    def test_089_transaction_id_from_list_skips_non_dict(self):
        found = self.cahandler._transaction_id_from_list(
            ["skip-me", {"id": "txn-x", "serialNumber": "aa"}],
            "aa",
            check_item_serial=True,
        )
        self.assertEqual(found, "txn-x")

    @patch(
        "acme2certifier.cahandlers.harica_ca_handler.CAhandler._certificate_fetch",
        return_value={"transactionStatus": "Completed", "certificate": True},
    )
    @patch(
        "acme2certifier.cahandlers.harica_ca_handler.CAhandler._certificate_parse",
        return_value=(None, None),
    )
    def test_090_enroll_issued_get_keeps_poll_when_no_pem(self, mock_parse, mock_fetch):
        error, bundle, raw, poll = self.cahandler._enroll_issued_get("txn-keep")
        self.assertIsNone(error)
        self.assertIsNone(bundle)
        self.assertEqual(poll, "txn-keep")


if __name__ == "__main__":
    unittest.main()
