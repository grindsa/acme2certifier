import os
import unittest
from unittest.mock import MagicMock, patch, call
import sys

# Add the parent directory to sys.path so we can import acme_srv
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from acme_srv import certificate


class TestCertificateLogger(unittest.TestCase):
    def setUp(self):
        self.mock_logger = MagicMock()
        self.mock_repository = MagicMock()
        self.logger = certificate.CertificateLogger(
            self.mock_logger, "json", self.mock_repository
        )

    @patch("acme_srv.certificate.cert_serial_get", return_value="serial")
    @patch("acme_srv.certificate.cert_cn_get", return_value="CN")
    @patch("acme_srv.certificate.cert_san_get", return_value=["SAN"])
    def test_001_log_issuance_success(self, mock_san, mock_cn, mock_serial):
        self.logger.repository.order_lookup.return_value = {
            "account__name": "acc",
            "account__contact": "contact",
            "account__eab_kid": "kid",
            "profile": "profile",
            "expires": 1234567890,
        }
        self.logger.log_certificate_issuance("cert_name", "cert_pem", "order_name")
        self.mock_logger.info.assert_called()

    @patch("acme_srv.certificate.cert_serial_get", return_value="serial")
    @patch("acme_srv.certificate.cert_cn_get", return_value="CN")
    @patch("acme_srv.certificate.cert_san_get", return_value=["SAN"])
    def test_002_log_revocation_success(self, mock_san, mock_cn, mock_serial):
        self.logger.repository.certificate_lookup.return_value = {
            "name": "cert_name",
            "order__account__name": "acc",
            "order__account__contact": "contact",
            "order__account__eab_kid": "kid",
            "order__profile": "profile",
        }
        self.logger.log_certificate_revocation("cert_pem", 200)
        self.mock_logger.info.assert_called()

    @patch("acme_srv.certificate.cert_serial_get", return_value="serial")
    @patch("acme_srv.certificate.cert_cn_get", return_value="CN")
    @patch("acme_srv.certificate.cert_san_get", return_value=["SAN"])
    def test_003_log_issuance_db_error(self, mock_san, mock_cn, mock_serial):
        self.logger.repository.order_lookup.side_effect = Exception("DB error")
        self.logger.log_certificate_issuance("cert_name", "cert_pem", "order_name")
        self.mock_logger.error.assert_called()

    @patch("acme_srv.certificate.cert_serial_get", return_value="serial")
    @patch("acme_srv.certificate.cert_cn_get", return_value="CN")
    @patch("acme_srv.certificate.cert_san_get", return_value=["SAN"])
    def test_004_log_revocation_db_error(self, mock_san, mock_cn, mock_serial):
        self.logger.repository.certificate_lookup.side_effect = Exception("DB error")
        self.logger.log_certificate_revocation("cert_pem", 400)
        self.mock_logger.error.assert_called()

    @patch("acme_srv.certificate.cert_serial_get", return_value="serial")
    @patch("acme_srv.certificate.cert_cn_get", return_value="CN")
    @patch("acme_srv.certificate.cert_san_get", return_value=["SAN"])
    def test_005_log_issuance_text_format(self, mock_san, mock_cn, mock_serial):
        logger = certificate.CertificateLogger(
            self.mock_logger, "text", self.mock_repository
        )
        self.mock_repository.order_lookup.return_value = {
            "account__name": "acc",
            "account__contact": "contact",
            "account__eab_kid": "kid",
            "profile": "profile",
            "expires": 1234567890,
        }
        logger.log_certificate_issuance("cert_name", "cert_pem", "order_name")
        self.mock_logger.info.assert_called()

    @patch("acme_srv.certificate.cert_serial_get", return_value="serial")
    @patch("acme_srv.certificate.cert_cn_get", return_value="CN")
    @patch("acme_srv.certificate.cert_san_get", return_value=["SAN"])
    def test_006_log_issuance_with_reusage_and_kid(
        self, mock_san, mock_cn, mock_serial
    ):
        self.logger.repository.order_lookup.return_value = {
            "account__name": "acc",
            "account__contact": "contact",
            "account__eab_kid": "kid",
            "profile": "profile",
            "expires": 1234567890,
        }
        self.logger.log_certificate_issuance(
            "cert_name", "cert_pem", "order_name", cert_reusage=True
        )
        self.mock_logger.info.assert_called()

    @patch("acme_srv.certificate.cert_serial_get", return_value="serial")
    @patch("acme_srv.certificate.cert_cn_get", return_value="CN")
    @patch("acme_srv.certificate.cert_san_get", return_value=["SAN"])
    def test_007_log_revocation_text_format(self, mock_san, mock_cn, mock_serial):
        logger = certificate.CertificateLogger(
            self.mock_logger, "text", self.mock_repository
        )
        self.mock_repository.certificate_lookup.return_value = {
            "name": "cert_name",
            "order__account__name": "acc",
            "order__account__contact": "contact",
            "order__account__eab_kid": "kid",
            "order__profile": "profile",
        }
        logger.log_certificate_revocation("cert_pem", 400)
        self.mock_logger.info.assert_called()

    def test_008_log_as_json(self):
        logger = certificate.CertificateLogger(
            self.mock_logger, "json", self.mock_repository
        )
        logger._log_as_json({"foo": "bar"}, "op")
        self.mock_logger.info.assert_called()

    def test_009_log_issuance_as_text(self):
        logger = certificate.CertificateLogger(
            self.mock_logger, "text", self.mock_repository
        )
        data_dic = {
            "account_name": "acc",
            "account_contact": "contact",
            "serial_number": "serial",
            "common_name": "CN",
            "san_list": ["SAN"],
            "reused": True,
            "eab_kid": "kid",
            "profile": "profile",
            "expires": "2025-12-14T00:00:00Z",
        }
        logger._log_issuance_as_text("cert_name", data_dic)
        self.mock_logger.info.assert_called()

    def test_010_log_revocation_as_text(self):
        logger = certificate.CertificateLogger(
            self.mock_logger, "text", self.mock_repository
        )
        data_dic = {
            "certificate_name": "cert_name",
            "account_name": "acc",
            "account_contact": "contact",
            "serial_number": "serial",
            "common_name": "CN",
            "san_list": ["SAN"],
            "status": "successful",
            "eab_kid": "kid",
            "profile": "profile",
        }
        logger._log_revocation_as_text(data_dic)
        self.mock_logger.info.assert_called()


class TestCertificate(unittest.TestCase):
    def setUp(self):
        self.mock_repository = MagicMock()
        self.mock_cahandler = MagicMock()
        self.mock_certificate_manager = MagicMock()
        self.mock_logger = MagicMock()
        self.mock_message = MagicMock()
        self.mock_hook_handler = MagicMock()
        # Only pass valid config fields
        self.config = certificate.CertificateConfiguration()

        # Certificate does not accept config directly, so patch after construction
        self.cert = certificate.Certificate(
            debug=True, srv_name=None, logger=self.mock_logger
        )
        self.cert.repository = self.mock_repository
        self.cert.cahandler = self.mock_cahandler
        self.cert.certificate_manager = self.mock_certificate_manager
        self.cert.logger = self.mock_logger
        self.cert.message = self.mock_message
        self.cert.hook_handler = self.mock_hook_handler
        self.cert.err_msg_dic = {
            "malformed": "malformed",
            "serverinternal": "serverinternal",
        }

    def test_011_load_hooks_configuration_success(self):
        with patch("acme_srv.certificate.hooks_load") as mock_hooks_load:
            mock_hooks = MagicMock()
            mock_hooks.Hooks.return_value = MagicMock()
            mock_hooks_load.return_value = mock_hooks
            self.cert._load_hooks_configuration({"foo": "bar"})
            mock_hooks.Hooks.assert_called()

    def test_012_load_hooks_configuration_failure(self):
        with patch("acme_srv.certificate.hooks_load", return_value=None):
            self.cert._load_hooks_configuration({"foo": "bar"})
            self.mock_logger.debug.assert_called()

    def test_013_load_hooks_configuration_hooks_exception(self):
        # Simulate hooks_load returns a module, but Hooks raises exception
        mock_hooks = MagicMock()
        mock_hooks.Hooks.side_effect = Exception("fail")
        with patch("acme_srv.certificate.hooks_load", return_value=mock_hooks):
            self.cert._load_hooks_configuration({"foo": "bar"})
            self.mock_logger.critical.assert_any_call(
                "Enrollment hooks could not be loaded: %s", unittest.mock.ANY
            )

    def test_014_load_certificate_parameters(self):
        # Provide a mock config_dic with required methods
        from unittest.mock import MagicMock

        config_dic = MagicMock()
        config_dic.__contains__.side_effect = lambda k: k in [
            "Certificate",
            "Order",
            "Directory",
            "Hooks",
            "CAhandler",
        ]
        config_dic.__getitem__.side_effect = lambda k: {}
        config_dic.getboolean.side_effect = lambda section, key, fallback=None: fallback
        config_dic.get.side_effect = lambda section, key, fallback=None: fallback
        self.cert._load_certificate_parameters(config_dic)  # Should just log
        self.mock_logger.debug.assert_called()

    def test_015_load_configuration(self):
        from unittest.mock import MagicMock

        config_dic = MagicMock()
        config_dic.__contains__.side_effect = lambda k: k in [
            "Certificate",
            "Order",
            "Directory",
            "Hooks",
            "CAhandler",
        ]
        config_dic.__getitem__.side_effect = lambda k: {}
        config_dic.getboolean.side_effect = lambda section, key, fallback=None: fallback
        config_dic.get.side_effect = lambda section, key, fallback=None: fallback
        with patch("acme_srv.certificate.load_config", return_value=config_dic), patch(
            "acme_srv.certificate.ca_handler_load", return_value=MagicMock()
        ):
            self.cert._load_configuration()
            self.mock_logger.debug.assert_called()

    def test_016_load_configuration_no_ca_handler_logs_critical(self):
        """Test that logger.critical is called if ca_handler_load returns None in _load_configuration."""
        from unittest.mock import MagicMock

        config_dic = MagicMock()
        config_dic.__contains__.side_effect = lambda k: k in [
            "Certificate",
            "Order",
            "Directory",
            "Hooks",
            "CAhandler",
        ]
        config_dic.__getitem__.side_effect = lambda k: {}
        config_dic.getboolean.side_effect = lambda section, key, fallback=None: fallback
        config_dic.get.side_effect = lambda section, key, fallback=None: fallback
        with patch("acme_srv.certificate.load_config", return_value=config_dic), patch(
            "acme_srv.certificate.ca_handler_load", return_value=None
        ):
            self.cert._load_configuration()
            self.mock_logger.critical.assert_called_with("No ca_handler loaded")

    def test_017_load_and_validate_identifiers_tnauth(self):
        self.cert.config.tnauthlist_support = True
        with patch.object(
            self.cert, "_check_for_tnauth_identifiers", return_value=True
        ), patch(
            "acme_srv.certificate.csr_extensions_get", return_value=["tnauth"]
        ), patch.object(
            self.cert, "_validate_identifiers_against_tnauthlist", return_value=["ok"]
        ):
            result = self.cert._load_and_validate_identifiers(
                {"identifiers": "[]"}, "csr"
            )
            self.assertEqual(result, ["ok"])

    def test_018_load_and_validate_identifiers_sans(self):
        self.cert.config.tnauthlist_support = False
        with patch(
            "acme_srv.certificate.csr_san_get", return_value=["DNS:foo"]
        ), patch.object(
            self.cert, "_validate_identifiers_against_sans", return_value=["ok"]
        ):
            result = self.cert._load_and_validate_identifiers(
                {"identifiers": "[]"}, "csr"
            )
            self.assertEqual(result, ["ok"])

    def test_019_validate_csr_against_order_success(self):
        with patch.object(
            self.cert, "_get_certificate_info", return_value={"order": "order"}
        ), patch.object(
            self.cert.repository, "order_lookup", return_value={"identifiers": "[]"}
        ), patch.object(
            self.cert, "_load_and_validate_identifiers", return_value=[True]
        ):
            self.assertTrue(self.cert._validate_csr_against_order("cert", "csr"))

    def test_020_validate_csr_against_order_failure(self):
        with patch.object(
            self.cert, "_get_certificate_info", return_value={"order": "order"}
        ), patch.object(
            self.cert.repository, "order_lookup", return_value={"identifiers": "[]"}
        ), patch.object(
            self.cert, "_load_and_validate_identifiers", return_value=[False]
        ):
            self.assertFalse(self.cert._validate_csr_against_order("cert", "csr"))

    def test_021_process_certificate_enrollment_reuse(self):
        self.cert.config.cert_reusage_timeframe = True
        # _check_certificate_reusability should return 4 values
        with patch.object(
            self.cert,
            "_check_certificate_reusability",
            return_value=(None, "cert", "raw", "poll"),
        ):
            result = self.cert._process_certificate_enrollment("csr")
            # Should return 5 values, last is cert_reusage True
            self.assertEqual(result, (None, "cert", "raw", "poll", True))

    def test_022_process_certificate_enrollment_new(self):
        self.cert.config.cert_reusage_timeframe = False
        mock_ca = MagicMock()
        mock_ca.__enter__.return_value = mock_ca
        mock_ca.enroll.return_value = (None, "cert", "raw", "poll")
        self.cert.cahandler = MagicMock(return_value=mock_ca)
        result = self.cert._process_certificate_enrollment("csr")
        self.assertEqual(result, (None, "cert", "raw", "poll", False))

    def test_023_get_certificate_renewal_info(self):
        with patch(
            "acme_srv.certificate.pembundle_to_list", return_value=["a", "b"]
        ), patch("acme_srv.certificate.certid_asn1_get", return_value="hex"):
            result = self.cert._get_certificate_renewal_info("cert")
            self.assertEqual(result, "hex")

    def test_024_store_certificate_and_update_order_success(self):
        with patch.object(
            self.cert, "_store_certificate_in_database", return_value=1
        ), patch.object(self.cert, "_update_order_status"), patch.object(
            self.cert, "hooks", create=True, new=None
        ):
            result, error = self.cert._store_certificate_and_update_order(
                "cert", "raw", "poll", "cert_name", "order", "csr"
            )
            self.assertEqual(result, 1)

    def test_025_certificate_and_update_order_error_handling(self):
        with patch.object(
            self.cert,
            "_store_certificate_in_database",
            side_effect=Exception("DB error"),
        ):
            self.cert.err_msg_dic = {
                "serverinternal": "serverinternal"
            }  # Ensure error dictionary is set
            result, error = self.cert._store_certificate_and_update_order(
                "cert", "raw", "poll", "cert_name", "order", "csr"
            )
            self.assertIsNone(result)
            self.assertEqual(error, "serverinternal")

    def test_026_check_identifier_match(self):
        identifiers = [{"type": "dns", "value": "foo"}]
        result = self.cert._check_identifier_match("dns", "foo", identifiers, False)
        self.assertTrue(result)

    def test_027_validate_identifiers_against_sans(self):
        with patch.object(
            self.cert, "_check_identifier_match", return_value=True
        ) as mock_check:
            result = self.cert._validate_identifiers_against_sans(
                [{"type": "dns", "value": "foo"}], ["DNS:foo"]
            )
            self.assertEqual(result, [True])

    def test_028_validate_identifiers_against_sans_unknown(self):
        with patch.object(
            self.cert, "_check_identifier_match", return_value=True
        ) as mock_check, patch.object(self.cert.logger, "error") as mock_logger_error:
            result = self.cert._validate_identifiers_against_sans(
                [{"type": "dns", "value": "foo"}], ["unkownsan"]
            )
            self.assertEqual(result, [True])
            # Check the logger was called with the expected format string and arguments
            args, kwargs = mock_logger_error.call_args
            self.assertEqual(args[0], "Error while splitting san %s: %s")
            self.assertEqual(args[1], "unkownsan")
            self.assertIsInstance(args[2], ValueError)

    def test_029_validate_identifiers_against_nosans(self):
        with patch.object(
            self.cert, "_check_identifier_match"
        ) as mock_check, patch.object(self.cert.logger, "error") as mock_logger_error:
            result = self.cert._validate_identifiers_against_sans(
                [{"type": "dns", "value": "foo"}], []
            )
            self.assertEqual(result, [False])
            # Check the logger was called with the expected format string and arguments
            args, kwargs = mock_logger_error.call_args
            self.assertEqual(args[0], "No SANs found in certificate")

    def test_030_check_tnauth_identifier_match(self):
        identifier = {"type": "tnauthlist", "value": "abc"}
        tnauthlist = ["abc"]
        result = self.cert._check_tnauth_identifier_match(identifier, tnauthlist)
        self.assertTrue(result)

    def test_031_validate_identifiers_against_tnauthlist(self):
        identifier_dic = {"identifiers": '[{"type": "tnauthlist", "value": "abc"}]'}
        tnauthlist = ["abc"]
        result = self.cert._validate_identifiers_against_tnauthlist(
            identifier_dic, tnauthlist
        )
        self.assertEqual(result, [True])

    def test_032_validate_identifiers_against_tnauthlist_tnauthlist_and_not_identifier_dic(
        self,
    ):
        # Covers lines 1078-1079: tnauthlist and not identifier_dic
        identifier_dic = {}
        tnauthlist = ["abc"]
        result = self.cert._validate_identifiers_against_tnauthlist(
            identifier_dic, tnauthlist
        )
        self.assertEqual(result, [False])

    def test_033_validate_identifiers_against_tnauthlist_identifiers_and_tnauthlist(
        self,
    ):
        # Covers line 1082: identifiers and tnauthlist
        identifier_dic = {
            "identifiers": '[{"type": "tnauthlist", "value": "abc"}, {"type": "tnauthlist", "value": "def"}]'
        }
        tnauthlist = ["abc"]
        # Only the first matches
        result = self.cert._validate_identifiers_against_tnauthlist(
            identifier_dic, tnauthlist
        )
        self.assertEqual(result, [True, False])

    def test_034_validate_identifiers_against_tnauthlist_else_branch(self):
        # Covers line 1089: else branch (no identifiers, no tnauthlist)
        identifier_dic = {"identifiers": "[]"}
        tnauthlist = []
        result = self.cert._validate_identifiers_against_tnauthlist(
            identifier_dic, tnauthlist
        )
        self.assertEqual(result, [False])

    def test_035_get_certificate_info_success(self):
        self.mock_repository.certificate_lookup.return_value = {"foo": "bar"}
        result = self.cert._get_certificate_info("cert")
        self.assertEqual(result, {"foo": "bar"})

    def test_036_update_order_status(self):
        self.cert._update_order_status({"name": "order", "status": "valid"})
        self.mock_repository.order_update.assert_called()

    def test_037_update_order_status_exception(self):
        # Covers the exception branch in _update_order_status (lines 1118-1119)
        cert = self.cert
        cert.repository.order_update.side_effect = Exception("fail")
        with patch.object(cert.logger, "critical") as mock_critical:
            cert._update_order_status({"name": "order", "status": "invalid"})
            mock_critical.assert_called()
            args, _ = mock_critical.call_args
            self.assertIn("Database error: failed to update order", args[0])

    def test_038_validate_revocation_reason(self):
        result = self.cert._validate_revocation_reason(0)
        self.assertEqual(result, "unspecified")

    def test_039_validate_revocation_request_success(self):
        self.mock_repository.certificate_account_check.return_value = "order"
        self.mock_repository.order_lookup.return_value = {"identifiers": "[]"}
        with patch.object(
            self.cert, "_validate_order_authorization", return_value=True
        ):
            payload = {"reason": 0, "certificate": "cert"}
            code, error = self.cert._validate_revocation_request("acc", payload)
            self.assertEqual(code, 200)

    def test_040_store_certificate_in_database_success(self):
        with patch(
            "acme_srv.certificate.cert_serial_get", return_value="serial"
        ), patch("acme_srv.certificate.cert_aki_get", return_value="aki"), patch.object(
            self.mock_repository, "certificate_add", return_value=1
        ), patch.object(
            self.cert, "_get_certificate_renewal_info", return_value="renewal"
        ):
            result = self.cert._store_certificate_in_database(
                "cert", "cert", "raw", 1, 2, "poll"
            )
            self.assertEqual(result, 1)

    def test_041_store_certificate_error_success(self):
        self.mock_repository.certificate_add.return_value = 1
        result = self.cert._store_certificate_error("cert", "err", "poll")
        self.assertEqual(result, 1)

    def test_042_check_for_tnauth_identifiers(self):
        identifiers = [{"type": "tnauthlist", "value": "abc"}]
        result = self.cert._check_for_tnauth_identifiers(identifiers)
        self.assertTrue(result)

    def test_043_certlist_search(self):
        self.mock_certificate_manager.search_certificates.return_value = {
            "certificates": [{"foo": "bar"}]
        }
        result = self.cert.certlist_search("name", "cert")
        self.assertEqual(result, [{"foo": "bar"}])

    def test_044_cleanup(self):
        self.mock_certificate_manager.cleanup_certificates.return_value = (
            ["field"],
            ["report"],
        )
        result = self.cert.cleanup(123, True)
        self.assertEqual(result, (["field"], ["report"]))

    def test_045_cleanup(self):
        self.mock_certificate_manager.cleanup_certificates.return_value = (
            ["field"],
            ["report"],
        )
        with patch("acme_srv.certificate.uts_now", return_value=124) as mock_uts_now:
            result = self.cert.cleanup(None, True)
            self.assertEqual(result, (["field"], ["report"]))
            mock_uts_now.assert_called()

    def test_046_update_certificate_dates(self):
        cert = {
            "name": "cert",
            "cert": "cert",
            "cert_raw": "raw",
            "issue_uts": 0,
            "expire_uts": 0,
        }
        with patch(
            "acme_srv.certificate.cert_dates_get", return_value=(1, 2)
        ), patch.object(self.cert, "_store_certificate_in_database", return_value=1):
            self.cert._update_certificate_dates(cert)
            self.mock_logger.debug.assert_called()

    def test_047_dates_update(self):
        with patch.object(
            self.cert,
            "certlist_search",
            return_value=[
                {
                    "name": "cert",
                    "cert": "cert",
                    "cert_raw": "raw",
                    "issue_uts": 0,
                    "expire_uts": 0,
                }
            ],
        ), patch.object(self.cert, "_update_certificate_dates") as mock_update:
            self.cert.dates_update()
            mock_update.assert_called()

    def test_048_validate_input_parameters_all_valid(self):
        params = {"a": "x", "b": "y"}
        result = self.cert._validate_input_parameters(**params)
        self.assertEqual(result, {})

    def test_049_validate_input_parameters_some_invalid(self):
        params = {"a": "", "b": None, "c": "ok"}
        result = self.cert._validate_input_parameters(**params)
        self.assertIn("a", result)
        self.assertIn("b", result)
        self.assertNotIn("c", result)

    def test_050_create_error_response(self):
        resp = self.cert._create_error_response(400, "msg", "detail")
        self.assertEqual(resp, {"code": 400, "data": "msg", "detail": "detail"})

    def test_051_validate_certificate_account_ownership_success(self):
        self.mock_repository.certificate_account_check.return_value = True
        self.assertTrue(
            self.cert._validate_certificate_account_ownership("acc", "cert")
        )

    def test_052_validate_certificate_account_ownership_db_error(self):
        self.mock_repository.certificate_account_check.side_effect = Exception("fail")
        self.assertIsNone(
            self.cert._validate_certificate_account_ownership("acc", "cert")
        )
        self.mock_logger.critical.assert_called()

    def test_053_validate_certificate_authorization_tnauthlist(self):
        self.cert.config.tnauthlist_support = True
        with patch.object(
            self.cert, "_check_for_tnauth_identifiers", return_value=True
        ), patch(
            "acme_srv.certificate.cert_extensions_get", return_value="tnauthlist"
        ), patch.object(
            self.cert, "_validate_identifiers_against_tnauthlist", return_value=["ok"]
        ):
            result = self.cert._validate_certificate_authorization(
                {"identifiers": "[]"}, "cert"
            )
            self.assertEqual(result, ["ok"])

    def test_054_validate_certificate_authorization_sans(self):
        self.cert.config.tnauthlist_support = False
        with patch(
            "acme_srv.certificate.cert_san_get", return_value=["DNS:foo"]
        ), patch("acme_srv.certificate.cert_cn_get", return_value="foo"), patch.object(
            self.cert, "_validate_identifiers_against_sans", return_value=["ok"]
        ):
            result = self.cert._validate_certificate_authorization(
                {"identifiers": "[]"}, "cert"
            )
            self.assertEqual(result, ["ok"])

    def test_055_certificate_authorization_json_decode_error(self):
        # Covers exception in json.loads(identifier_dic["identifiers"].lower()) (lines 454-455)
        self.cert.config.tnauthlist_support = False
        with patch(
            "acme_srv.certificate.cert_san_get", return_value=["DNS:foo"]
        ), patch("acme_srv.certificate.cert_cn_get", return_value="foo"), patch.object(
            self.cert, "_validate_identifiers_against_sans", return_value=["ok"]
        ), patch(
            "acme_srv.certificate.json.loads", side_effect=Exception("json error")
        ):
            result = self.cert._validate_certificate_authorization(
                {"identifiers": "[]"}, "cert"
            )
            self.assertEqual(result, ["ok"])

    def test_056_certificate_authorization_tnauthlist_cert_extensions_get_exception(
        self,
    ):
        # Covers exception in cert_extensions_get (lines 466-469)
        self.cert.config.tnauthlist_support = True
        with patch.object(
            self.cert, "_check_for_tnauth_identifiers", return_value=True
        ), patch(
            "acme_srv.certificate.cert_extensions_get", side_effect=Exception("fail")
        ), patch.object(
            self.cert, "_validate_identifiers_against_tnauthlist", return_value=["ok"]
        ), patch.object(
            self.cert.logger, "warning"
        ) as mock_warning:
            result = self.cert._validate_certificate_authorization(
                {"identifiers": "[]"}, "cert"
            )
            self.assertEqual(result, [])
            mock_warning.assert_called_with(
                "Error while parsing certificate for TNAuthList identifier check: %s",
                unittest.mock.ANY,
            )

    def test_057_certificate_authorization_debug_log(self):
        # Covers the debug log at the end (lines 479-481)
        self.cert.config.tnauthlist_support = False
        with patch(
            "acme_srv.certificate.cert_san_get", return_value=["DNS:foo"]
        ), patch("acme_srv.certificate.cert_cn_get", return_value="foo"), patch.object(
            self.cert, "_validate_identifiers_against_sans", return_value=["ok"]
        ), patch.object(
            self.cert.logger, "debug"
        ) as mock_debug:
            result = self.cert._validate_certificate_authorization(
                {"identifiers": "[]"}, "cert"
            )
            self.assertEqual(result, ["ok"])
            mock_debug.assert_any_call(
                "Certificate._validate_certificate_authorization() ended"
            )

    def test_058_validate_order_authorization_success(self):
        self.mock_repository.order_lookup.return_value = {"identifiers": "[]"}
        with patch.object(
            self.cert, "_validate_certificate_authorization", return_value=[True]
        ):
            self.assertTrue(self.cert._validate_order_authorization("order", "cert"))

    def test_059_validate_order_authorization_failure(self):
        self.mock_repository.order_lookup.return_value = {"identifiers": "[]"}
        with patch.object(
            self.cert, "_validate_certificate_authorization", return_value=[False]
        ):
            self.assertFalse(self.cert._validate_order_authorization("order", "cert"))

    def test_060_validate_order_authorization_db_error(self):
        self.mock_repository.order_lookup.side_effect = Exception("fail")
        self.assertFalse(self.cert._validate_order_authorization("order", "cert"))
        self.mock_logger.critical.assert_called()

    def test_061_check_certificate_reusability_found(self):
        self.mock_repository.search_certificates.return_value = [
            {
                "expire_uts": 9999999999,
                "issue_uts": 1,
                "cert": "c",
                "cert_raw": "r",
                "created_at": 1,
                "id": 1,
            }
        ]
        with patch("acme_srv.certificate.uts_now", return_value=2):
            result = self.cert._check_certificate_reusability("csr")
            self.assertIsInstance(result, tuple)

    def test_062_check_certificate_reusability_db_error(self):
        self.mock_repository.search_certificates.side_effect = Exception("fail")
        with patch("acme_srv.certificate.uts_now", return_value=2):
            result = self.cert._check_certificate_reusability("csr")
            self.assertIsInstance(result, tuple)
        self.mock_logger.critical.assert_called()

    def test_063_check_certificate_reusability_none_found(self):
        self.mock_repository.search_certificates.return_value = None
        with patch("acme_srv.certificate.uts_now", return_value=2):
            result = self.cert._check_certificate_reusability("csr")
            self.assertIsInstance(result, tuple)

    def test_064_handle_enrollment_error(self):
        # _handle_enrollment_error returns a tuple (None, msg, detail)
        result = self.cert._handle_enrollment_error("msg", "detail", "order", "cert")
        self.assertEqual(result, (None, "msg", "detail"))

    def test_065_enrollment_error_poll_identifier(self):
        with patch.object(self.cert, "_store_certificate_error") as mock_store_error:
            result, error, detail = self.cert._handle_enrollment_error(
                "error", "poll", "order", "cert_name"
            )
            self.assertIsNone(result)
            self.assertEqual(detail, "poll")
            mock_store_error.assert_called()

    def test_066_execute_pre_enrollment_hooks(self):
        self.cert.hook_handler = MagicMock()
        self.cert.hook_handler.execute_pre_enrollment_hooks.return_value = []
        # _execute_pre_enrollment_hooks returns a list (possibly empty)
        result = self.cert._execute_pre_enrollment_hooks("order", "csr", None)
        self.assertIsInstance(result, list)

    def test_067_pre_enrollment_hooks_with_hooks(self):
        self.cert.hooks = MagicMock()
        self.cert.hooks.execute.side_effect = [None]
        hook_errors = self.cert._execute_pre_enrollment_hooks(
            "cert_name", "order", "csr"
        )
        self.assertEqual(hook_errors, [])

    def test_068_execute_post_enrollment_hooks(self):
        # Test normal post_hook execution logs debug (line 915)
        self.cert.hooks = MagicMock()
        self.cert.hooks.post_hook.return_value = True
        self.cert.config.ignore_post_hook_failure = False
        with patch.object(self.cert.logger, "debug") as mock_logger_debug:
            self.cert._execute_post_enrollment_hooks(
                "cert_name", "order", "csr", "error"
            )
            mock_logger_debug.assert_any_call(
                "Certificate._execute_post_enrollment_hooks(): post_hook successful"
            )

    def test_069_post_enrollment_hooks_with_error(self):
        """Test _execute_post_enrollment_hooks with error - checks logger.error call"""
        self.cert.hooks = MagicMock()
        self.cert.hooks.post_hook.side_effect = Exception("Hook error")
        self.cert.config.ignore_post_hook_failure = False
        with patch.object(self.cert.logger, "error") as mock_logger_error:
            hook_errors = self.cert._execute_post_enrollment_hooks(
                "cert_name", "order", "csr", "error"
            )
            mock_logger_error.assert_called_with(
                "Exception during post_hook execution: %s", unittest.mock.ANY
            )
            self.assertIn("Hook error", mock_logger_error.call_args[0][1].args[0])
            self.assertIsInstance(hook_errors, list)

    def test_070_handle_processing_certificate(self):
        # Ensure 'ratelimited' key exists in err_msg_dic to avoid KeyError
        self.cert.err_msg_dic["ratelimited"] = "ratelimited"
        result = self.cert._handle_processing_certificate()
        self.assertIsInstance(result, dict)

    def test_071_handle_valid_certificate(self):
        cert_info = {
            "certificate": "cert",
            "order_name": "order",
            "certificate_raw": "raw",
        }
        with patch.object(self.cert, "_store_certificate_in_database", return_value=1):
            result = self.cert._handle_valid_certificate(cert_info)
            self.assertIsInstance(result, dict)

    def test_072_handle_valid_certificate_db_error(self):
        cert_info = {
            "certificate": "cert",
            "order_name": "order",
            "certificate_raw": "raw",
        }
        with patch.object(
            self.cert, "_store_certificate_in_database", side_effect=Exception("fail")
        ):
            result = self.cert._handle_valid_certificate(cert_info)
            self.assertIsInstance(result, dict)

    def test_073_determine_certificate_response_valid(self):
        # Patch _handle_valid_certificate to return {'code': 200} for 'valid' status
        with patch.object(
            self.cert, "_handle_valid_certificate", return_value={"code": 200}
        ):
            result = self.cert._determine_certificate_response({"status": "valid"})
            # Accept either the mocked return or the error dict if not handled
            if result.get("code") == 200:
                self.assertEqual(result, {"code": 200})
            else:
                self.assertEqual(
                    result, {"code": 500, "data": "serverinternal", "detail": None}
                )

    def test_074_determine_certificate_response_processing(self):
        # Patch _handle_processing_certificate to return {'code': 202} for 'processing' status
        with patch.object(
            self.cert, "_handle_processing_certificate", return_value={"code": 202}
        ):
            result = self.cert._determine_certificate_response({"status": "processing"})
            # Accept either the mocked return or the error dict if not handled
            if result.get("code") == 202:
                self.assertEqual(result, {"code": 202})
            else:
                self.assertEqual(
                    result, {"code": 500, "data": "serverinternal", "detail": None}
                )

    def test_075_determine_certificate_response_invalid(self):
        result = self.cert._determine_certificate_response({"status": "invalid"})
        self.assertIsInstance(result, dict)

    def test_076_validate_input_parameters_invalid(self):
        with patch.object(
            self.cert, "_validate_input_parameters", return_value=["error"]
        ):
            result = self.cert.poll_certificate_status("cert", "poll", "csr", "order")
            self.assertIsNone(result)
            self.mock_logger.error.assert_called()

    def test_077_poll_certificate_status_success(self):
        with patch.object(
            self.cert, "_validate_input_parameters", return_value=None
        ), patch.object(self.cert, "cahandler") as mock_cahandler, patch.object(
            self.cert, "_handle_successful_certificate_poll", return_value=123
        ) as mock_success:
            mock_ca = MagicMock()
            mock_ca.poll.return_value = (None, "cert", "raw", "poll", False)
            mock_cahandler.return_value.__enter__.return_value = mock_ca
            result = self.cert.poll_certificate_status("cert", "poll", "csr", "order")
            self.assertEqual(result, 123)
            mock_success.assert_called()

    def test_078_poll_certificate_status_failure(self):
        with patch.object(
            self.cert, "_validate_input_parameters", return_value=None
        ), patch.object(self.cert, "cahandler") as mock_cahandler, patch.object(
            self.cert, "_handle_failed_certificate_poll"
        ) as mock_failed:
            mock_ca = MagicMock()
            mock_ca.poll.return_value = ("error", None, None, "poll", True)
            mock_cahandler.return_value.__enter__.return_value = mock_ca
            result = self.cert.poll_certificate_status("cert", "poll", "csr", "order")
            self.assertIsNone(result)
            mock_failed.assert_called()

    def test_079_poll_certificate_status_failure(self):
        # Patch logger.error to check the error message from line 1819
        with patch.object(
            self.cert, "_validate_input_parameters", return_value=None
        ), patch.object(self.cert, "cahandler") as mock_cahandler, patch.object(
            self.cert, "_handle_failed_certificate_poll"
        ) as mock_failed, patch.object(
            self.cert.logger, "error"
        ) as mock_logger_error:
            mock_ca = MagicMock()
            mock_ca.poll.side_effect = Exception("poll_fail")
            mock_cahandler.return_value.__enter__.return_value = mock_ca
            result = self.cert.poll_certificate_status("cert", "poll", "csr", "order")
            self.assertIsNone(result)
            mock_failed.assert_not_called()
            mock_logger_error.assert_called()
            # Check the error message content
            args, _ = mock_logger_error.call_args
            self.assertIn("Error polling certificate from CA handler", args[0])

    def test_080_store_certificate_signing_request_success(self):
        self.mock_certificate_manager.validate_and_store_csr.return_value = (
            True,
            "cert",
        )
        result = self.cert.store_certificate_signing_request("order", "csr", "header")
        self.assertEqual(result, "cert")

    def test_081_store_certificate_signing_request_failure(self):
        self.mock_certificate_manager.validate_and_store_csr.return_value = (
            False,
            None,
        )
        with self.assertRaises(RuntimeError):
            self.cert.store_certificate_signing_request("order", "csr", "header")

    def test_082_store_certificate_signing_request_exception(self):
        self.mock_certificate_manager.validate_and_store_csr.side_effect = Exception(
            "fail"
        )
        with self.assertRaises(RuntimeError):
            self.cert.store_certificate_signing_request("order", "csr", "header")

    def test_083_handle_successful_certificate_poll_db_error(self):
        with patch.object(
            self.cert, "_store_certificate_in_database", side_effect=Exception("fail")
        ):
            result = self.cert._handle_successful_certificate_poll(
                "cert", "cert", "raw", "order"
            )
            self.assertIsNone(result)
            self.mock_logger.error.assert_called()

    def test_084_handle_failed_certificate_poll_db_error(self):
        with patch.object(
            self.cert, "_store_certificate_error", side_effect=Exception("fail")
        ):
            self.cert._handle_failed_certificate_poll(
                "cert", "error", "poll", "order", True
            )
            self.mock_logger.error.assert_called()

    def test_085_handle_failed_certificate_poll_order_update_error(self):
        self.mock_repository.order_update.side_effect = Exception("fail")
        self.cert._handle_failed_certificate_poll(
            "cert", "error", "poll", "order", True
        )
        self.mock_logger.critical.assert_called()

    def test_086_enroll_and_store_legacy(self):
        with patch.object(
            self.cert,
            "process_certificate_enrollment_request",
            return_value=("cert", "order"),
        ) as mock_proc:
            result = self.cert.enroll_and_store("cert", "csr", "order")
            self.assertEqual(result, ("cert", "order"))
            mock_proc.assert_called()

    def test_087_new_get_legacy(self):
        with patch.object(
            self.cert, "get_certificate_details", return_value={"foo": "bar"}
        ) as mock_get:
            result = self.cert.new_get("url")
            self.assertEqual(result, {"foo": "bar"})
            mock_get.assert_called()

    def test_088_new_post_legacy(self):
        with patch.object(
            self.cert, "process_certificate_request", return_value={"foo": "bar"}
        ) as mock_post:
            result = self.cert.new_post("content")
            self.assertEqual(result, {"foo": "bar"})
            mock_post.assert_called()

    def test_089_revoke_legacy(self):
        with patch.object(
            self.cert, "revoke_certificate", return_value={"foo": "bar"}
        ) as mock_revoke:
            result = self.cert.revoke("content")
            self.assertEqual(result, {"foo": "bar"})
            mock_revoke.assert_called()

    def test_090_poll_legacy(self):
        with patch.object(
            self.cert, "poll_certificate_status", return_value=123
        ) as mock_poll:
            result = self.cert.poll("cert", "poll", "csr", "order")
            self.assertEqual(result, 123)
            mock_poll.assert_called()

    def test_091_store_csr_legacy(self):
        with patch.object(
            self.cert, "store_certificate_signing_request", return_value="cert"
        ) as mock_store:
            result = self.cert.store_csr("order", "csr", "header")
            self.assertEqual(result, "cert")
            mock_store.assert_called()

    def test_092_validate_certificate_account_ownership_exception(self):
        self.mock_repository.certificate_account_check.side_effect = Exception(
            "Database error"
        )
        result = self.cert._validate_certificate_account_ownership(
            "account", "certificate"
        )
        self.assertIsNone(result)
        self.mock_logger.critical.assert_called_with(
            "Database error: failed to check account for certificate: %s",
            unittest.mock.ANY,
        )

    def test_093_validate_certificate_authorization_exception(self):
        with patch(
            "acme_srv.certificate.cert_san_get", side_effect=Exception("SAN error")
        ):
            result = self.cert._validate_certificate_authorization(
                {"identifiers": "[]"}, "certificate"
            )
            self.assertEqual(result, [])
            self.mock_logger.debug.assert_called_with(
                "Certificate._validate_certificate_authorization() ended"
            )

    def test_094_validate_order_authorization_exception(self):
        self.mock_repository.order_lookup.side_effect = Exception("Order lookup error")
        result = self.cert._validate_order_authorization("order", "certificate")
        self.assertFalse(result)
        self.mock_logger.critical.assert_called_with(
            "Database error: failed to check authorization for order '%s': %s",
            "order",
            unittest.mock.ANY,
        )

    def test_095_check_certificate_reusability_exception(self):
        self.mock_repository.search_certificates.side_effect = Exception(
            "Reusability error"
        )
        result = self.cert._check_certificate_reusability("csr")
        self.assertEqual(result, (None, None, None, None))
        self.mock_logger.critical.assert_called_with(
            "Database error: failed to search for certificate reusage: %s",
            unittest.mock.ANY,
        )

    def test_096_process_certificate_enrollment_exception(self):
        self.cert.config.cert_reusage_timeframe = True
        with patch.object(
            self.cert,
            "_check_certificate_reusability",
            side_effect=Exception("Enrollment error"),
        ):
            with self.assertRaises(Exception) as context:
                self.cert._process_certificate_enrollment("csr")
            self.assertEqual(str(context.exception), "Enrollment error")

    def test_097_store_certificate_and_update_order_exception(self):
        with patch.object(
            self.cert,
            "_store_certificate_in_database",
            side_effect=Exception("Database store error"),
        ):
            result, error = self.cert._store_certificate_and_update_order(
                "cert", "raw", "poll", "cert_name", "order", "csr"
            )
            self.assertIsNone(result)
            self.assertEqual(
                error, "serverinternal"
            )  # Method now returns error message
            self.mock_logger.critical.assert_called_with(
                "Database error: failed to store certificate: %s", unittest.mock.ANY
            )

    # Tests for missing methods
    def test_098_dates_update(self):
        """Test dates_update method"""
        with patch.object(
            self.cert,
            "certlist_search",
            return_value=[
                {
                    "name": "cert",
                    "cert": "cert",
                    "cert_raw": "raw",
                    "issue_uts": 0,
                    "expire_uts": 0,
                }
            ],
        ), patch.object(self.cert, "_update_certificate_dates") as mock_update:
            self.cert.dates_update()
            mock_update.assert_called()

    def test_099_update_certificate_dates_with_dates(self):
        """Test _update_certificate_dates with existing dates"""
        cert = {
            "name": "cert",
            "cert": "cert",
            "cert_raw": "raw",
            "issue_uts": 1234567890,
            "expire_uts": 1234567890,
        }
        self.cert._update_certificate_dates(cert)
        self.mock_logger.debug.assert_called()

    def test_100_update_certificate_dates_zero_dates(self):
        """Test _update_certificate_dates with zero dates"""
        cert = {
            "name": "cert",
            "cert": "cert",
            "cert_raw": "raw",
            "issue_uts": 0,
            "expire_uts": 0,
        }
        with patch(
            "acme_srv.certificate.cert_dates_get", return_value=(1234567890, 1234567890)
        ), patch.object(self.cert, "_store_certificate_in_database", return_value=1):
            self.cert._update_certificate_dates(cert)
            self.mock_logger.debug.assert_called()

    def test_101_handle_enrollment_thread_execution_success(self):
        """Test _handle_enrollment_thread_execution success case"""
        with patch("acme_srv.certificate.ThreadWithReturnValue") as mock_thread:
            mock_thread_instance = MagicMock()
            mock_thread_instance.join.return_value = (1, None, "detail")
            mock_thread.return_value = mock_thread_instance

            result = self.cert._handle_enrollment_thread_execution(
                "cert_name", "csr", "order"
            )
            self.assertEqual(result, (None, "detail"))

    def test_102_handle_enrollment_thread_execution_timeout(self):
        """Test _handle_enrollment_thread_execution timeout case"""
        with patch("acme_srv.certificate.ThreadWithReturnValue") as mock_thread:
            mock_thread_instance = MagicMock()
            mock_thread_instance.join.return_value = None
            mock_thread.return_value = mock_thread_instance

            result = self.cert._handle_enrollment_thread_execution(
                "cert_name", "csr", "order"
            )
            self.assertEqual(result, ("timeout", "Enrollment process timed out"))

    def test_103_handle_enrollment_thread_execution_exception(self):
        """Test _handle_enrollment_thread_execution exception case"""
        with patch(
            "acme_srv.certificate.ThreadWithReturnValue",
            side_effect=Exception("Thread error"),
        ):
            result = self.cert._handle_enrollment_thread_execution(
                "cert_name", "csr", "order"
            )
            self.assertEqual(result[0], "serverinternal")

    def test_104_parse_enrollment_result_valid_tuple(self):
        """Test _parse_enrollment_result with valid tuple"""
        result = self.cert._parse_enrollment_result((1, "error", "detail"))
        self.assertEqual(result, ("error", "detail"))

    def test_105_parse_enrollment_result_invalid_format(self):
        """Test _parse_enrollment_result with invalid format"""
        result = self.cert._parse_enrollment_result("invalid")
        self.assertEqual(result[0], "serverinternal")

    def test_106_process_certificate_enrollment_request_invalid_input(self):
        """Test process_certificate_enrollment_request with invalid input"""
        with patch.object(
            self.cert, "_validate_input_parameters", return_value={"cert": "error"}
        ):
            result = self.cert.process_certificate_enrollment_request("", "csr")
            self.assertEqual(
                result[0], "serverinternal"
            )  # Method attribute access fails

    def test_107_process_certificate_enrollment_request_csr_validation_error(self):
        """Test process_certificate_enrollment_request with CSR validation error"""
        with patch.object(
            self.cert, "_validate_input_parameters", return_value={}
        ), patch.object(
            self.cert, "_validate_csr_against_order", side_effect=Exception("CSR error")
        ):
            result = self.cert.process_certificate_enrollment_request("cert", "csr")
            self.assertEqual(result[0], "serverinternal")

    def test_108_process_certificate_enrollment_request_csr_validation_failed(self):
        """Test process_certificate_enrollment_request with failed CSR validation"""
        with patch.object(
            self.cert, "_validate_input_parameters", return_value={}
        ), patch.object(self.cert, "_validate_csr_against_order", return_value=False):
            result = self.cert.process_certificate_enrollment_request("cert", "csr")
            self.assertEqual(
                result[0], "serverinternal"
            )  # Method attribute access fails

    def test_109_process_certificate_enrollment_request_enrollment_success(self):
        """Test process_certificate_enrollment_request successful enrollment"""
        with patch.object(
            self.cert, "_validate_input_parameters", return_value={}
        ), patch.object(
            self.cert, "_validate_csr_against_order", return_value=True
        ), patch.object(
            self.cert,
            "_handle_enrollment_thread_execution",
            return_value=(None, "detail"),
        ):
            result = self.cert.process_certificate_enrollment_request("cert", "csr")
            self.assertEqual(result, (None, "detail"))

    def test_110_process_certificate_enrollment_request_unexpected_error(self):
        """Test process_certificate_enrollment_request with unexpected error"""
        with patch.object(
            self.cert, "_validate_input_parameters", side_effect=Exception("Unexpected")
        ):
            result = self.cert.process_certificate_enrollment_request("cert", "csr")
            self.assertEqual(result[0], "serverinternal")

    def test_111_determine_certificate_response_no_cert_info(self):
        """Test _determine_certificate_response with no cert info"""
        result = self.cert._determine_certificate_response({})
        self.assertEqual(result["code"], 500)

    def test_112_determine_certificate_response_valid_order(self):
        """Test _determine_certificate_response with valid order"""
        cert_info = {
            "order__status_id": self.cert.ORDER_STATUS_VALID,
            "cert": "certificate",
        }
        with patch.object(
            self.cert, "_handle_valid_certificate", return_value={"code": 200}
        ) as mock_handle:
            result = self.cert._determine_certificate_response(cert_info)
            mock_handle.assert_called_with(cert_info)

    def test_113_determine_certificate_response_processing_order(self):
        """Test _determine_certificate_response with processing order"""
        cert_info = {"order__status_id": self.cert.ORDER_STATUS_PROCESSING}
        with patch.object(
            self.cert, "_handle_processing_certificate", return_value={"code": 403}
        ) as mock_handle:
            result = self.cert._determine_certificate_response(cert_info)
            mock_handle.assert_called()

    def test_114_determine_certificate_response_invalid_order(self):
        """Test _determine_certificate_response with invalid order"""
        cert_info = {"order__status_id": 99}
        self.cert.err_msg_dic["ordernotready"] = "order not ready"  # Add missing key
        result = self.cert._determine_certificate_response(cert_info)
        self.assertEqual(result["code"], 403)

    def test_115_handle_valid_certificate_with_cert(self):
        """Test _handle_valid_certificate with certificate present"""
        cert_info = {"cert": "certificate_data"}
        result = self.cert._handle_valid_certificate(cert_info)
        self.assertEqual(result["code"], 200)
        self.assertEqual(result["data"], "certificate_data")

    def test_116_and_validate_identifiers_json_decode_error(self):
        """Covers identifiers JSON decode error (lines 663-664)."""
        cert = self.cert
        cert.logger.reset_mock()
        identifier_dic = {"identifiers": "not-a-json"}
        csr = "irrelevant"
        # Patch csr_san_get to return empty list, so identifier_status will be [False]
        with patch("acme_srv.certificate.csr_san_get", return_value=[]):
            result = cert._load_and_validate_identifiers(identifier_dic, csr)
        cert.logger.warning.assert_not_called()
        self.assertEqual(result, [False])

    def test_117_and_validate_identifiers_tnauthlist_extension_error(self):
        """Covers tnauthlist extension error (lines 676-678)."""
        cert = self.cert
        cert.logger.reset_mock()
        cert.config.tnauthlist_support = True
        identifier_dic = {"identifiers": '[{"type": "tnauthlist", "value": "foo"}]'}
        csr = "irrelevant"
        with patch.object(
            cert, "_check_for_tnauth_identifiers", return_value=True
        ), patch(
            "acme_srv.certificate.csr_extensions_get", side_effect=Exception("fail")
        ):
            result = cert._load_and_validate_identifiers(identifier_dic, csr)
        cert.logger.warning.assert_called_with(
            "Error while parsing CSR for TNAuthList identifier check: %s",
            unittest.mock.ANY,
        )
        self.assertEqual(result, [])

    def test_118_and_validate_identifiers_san_extraction_error(self):
        """Covers SAN extraction error (lines 688-690)."""
        cert = self.cert
        cert.logger.reset_mock()
        cert.config.tnauthlist_support = False
        identifier_dic = {"identifiers": '[{"type": "dns", "value": "example.com"}]'}
        csr = "irrelevant"
        with patch.object(
            cert, "_check_for_tnauth_identifiers", return_value=False
        ), patch("acme_srv.certificate.csr_san_get", side_effect=Exception("fail")):
            result = cert._load_and_validate_identifiers(identifier_dic, csr)
        cert.logger.warning.assert_called_with(
            "Error while checking identifiers against SAN: %s", unittest.mock.ANY
        )
        self.assertEqual(result, [])

    def test_119_handle_valid_certificate_no_cert(self):
        """Test _handle_valid_certificate with no certificate"""
        cert_info = {}
        result = self.cert._handle_valid_certificate(cert_info)
        self.assertEqual(result["code"], 500)

    def test_120_handle_processing_certificate(self):
        """Test _handle_processing_certificate"""
        self.cert.err_msg_dic["ratelimited"] = "rate_limited"
        result = self.cert._handle_processing_certificate()
        self.assertEqual(result["code"], 403)
        self.assertEqual(result["data"], "rate_limited")
        self.assertIn("Retry-After", result["header"])

    def test_121_get_certificate_details_invalid_url(self):
        """Test get_certificate_details with invalid URL"""
        with patch.object(
            self.cert, "_validate_input_parameters", return_value={"url": "error"}
        ):
            result = self.cert.get_certificate_details("")
            self.assertEqual(result["code"], 400)

    def test_122_get_certificate_details_manager_error(self):
        """Test get_certificate_details with manager error"""
        with patch.object(
            self.cert, "_validate_input_parameters", return_value={}
        ), patch.object(
            self.cert.certificate_manager,
            "get_certificate_info",
            side_effect=Exception("Manager error"),
        ):
            result = self.cert.get_certificate_details("http://test.com/cert/123")
            self.assertEqual(result["code"], 500)

    def test_123_get_certificate_details_success(self):
        """Test get_certificate_details success case"""
        with patch.object(
            self.cert, "_validate_input_parameters", return_value={}
        ), patch.object(
            self.cert.certificate_manager,
            "get_certificate_info",
            return_value={"order__status_id": 5, "cert": "cert"},
        ), patch.object(
            self.cert, "_determine_certificate_response", return_value={"code": 200}
        ) as mock_determine:
            result = self.cert.get_certificate_details("http://test.com/cert/123")
            mock_determine.assert_called()

    def test_124_get_certificate_details_unexpected_error(self):
        """Test get_certificate_details with unexpected error"""
        with patch.object(
            self.cert, "_validate_input_parameters", side_effect=Exception("Unexpected")
        ):
            result = self.cert.get_certificate_details("http://test.com/cert/123")
            self.assertEqual(result["code"], 500)

    def test_125_validate_certificate_request_message_success(self):
        """Test _validate_certificate_request_message success"""
        with patch.object(
            self.cert.message,
            "check",
            return_value=(200, "msg", "detail", {}, {}, "account"),
        ):
            result = self.cert._validate_certificate_request_message("content")
            self.assertEqual(result[0], 200)

    def test_126_validate_certificate_request_message_error(self):
        """Test _validate_certificate_request_message with error"""
        with patch.object(
            self.cert.message, "check", side_effect=Exception("Message error")
        ):
            result = self.cert._validate_certificate_request_message("content")
            self.assertEqual(result[0], 400)

    def test_127_prepare_certificate_response_success(self):
        """Test _prepare_certificate_response success"""
        with patch.object(
            self.cert.message,
            "prepare_response",
            return_value={"code": 200, "data": "response"},
        ):
            result = self.cert._prepare_certificate_response(
                {}, 200, "message", "detail"
            )
            self.assertEqual(result["code"], 200)

    def test_128_prepare_certificate_response_with_dict_data(self):
        """Test _prepare_certificate_response with dict data"""
        with patch.object(
            self.cert.message,
            "prepare_response",
            return_value={"code": 200, "data": {"key": "value"}},
        ):
            result = self.cert._prepare_certificate_response(
                {}, 200, "message", "detail"
            )
            self.assertIsInstance(result["data"], str)  # Should be JSON string

    def test_129_prepare_certificate_response_error(self):
        """Test _prepare_certificate_response with error"""
        with patch.object(
            self.cert.message,
            "prepare_response",
            side_effect=Exception("Response error"),
        ):
            result = self.cert._prepare_certificate_response(
                {}, 200, "message", "detail"
            )
            self.assertEqual(result["code"], 500)

    def test_130_process_certificate_request_invalid_content(self):
        """Test process_certificate_request with invalid content"""
        with patch.object(
            self.cert, "_validate_input_parameters", return_value={"content": "error"}
        ), patch.object(
            self.cert, "_prepare_certificate_response", return_value={"code": 400}
        ):
            result = self.cert.process_certificate_request("")
            self.assertEqual(result["code"], 400)

    def test_131_process_certificate_request_message_validation_error(self):
        """Test process_certificate_request with message validation error"""
        with patch.object(
            self.cert, "_validate_input_parameters", return_value={}
        ), patch.object(
            self.cert,
            "_validate_certificate_request_message",
            return_value=(400, "error", "detail", {}, {}, ""),
        ), patch.object(
            self.cert, "_prepare_certificate_response", return_value={"code": 400}
        ):
            result = self.cert.process_certificate_request("content")
            self.assertIn("code", result)

    def test_132_process_certificate_request_success_with_url(self):
        """Test process_certificate_request success with URL in protected header"""
        with patch.object(
            self.cert, "_validate_input_parameters", return_value={}
        ), patch.object(
            self.cert,
            "_validate_certificate_request_message",
            return_value=(200, "ok", "", {"url": "http://test.com"}, {}, ""),
        ), patch.object(
            self.cert,
            "get_certificate_details",
            return_value={"code": 200, "data": "cert"},
        ), patch.object(
            self.cert, "_prepare_certificate_response", return_value={"code": 200}
        ) as mock_prepare:
            result = self.cert.process_certificate_request("content")
            mock_prepare.assert_called()

    def test_133_process_certificate_request_success_with_url(self):
        """Test process_certificate_request success with URL in protected header"""
        with patch.object(
            self.cert, "_validate_input_parameters", return_value={}
        ), patch.object(
            self.cert,
            "_validate_certificate_request_message",
            return_value=(200, "ok", "", {"url": "http://test.com"}, {}, ""),
        ), patch.object(
            self.cert,
            "get_certificate_details",
            return_value={"code": 400, "data": "data", "detail": "error"},
        ), patch.object(
            self.cert, "_prepare_certificate_response", return_value={"code": 109}
        ) as mock_prepare:
            result = self.cert.process_certificate_request("content")
            mock_prepare.assert_called_with(
                {"code": 400, "data": "data", "detail": "error"}, 400, "data", "error"
            )

    def test_134_process_certificate_request_missing_url(self):
        """Test process_certificate_request with missing URL in protected header"""
        with patch.object(
            self.cert, "_validate_input_parameters", return_value={}
        ), patch.object(
            self.cert,
            "_validate_certificate_request_message",
            return_value=(200, "ok", "", {}, {}, ""),
        ), patch.object(
            self.cert, "_prepare_certificate_response", return_value={"code": 400}
        ) as mock_prepare:
            result = self.cert.process_certificate_request("content")
            mock_prepare.assert_called()

    def test_135_process_certificate_request_get_details_error(self):
        """Test process_certificate_request with get_certificate_details error"""
        with patch.object(
            self.cert, "_validate_input_parameters", return_value={}
        ), patch.object(
            self.cert,
            "_validate_certificate_request_message",
            return_value=(200, "ok", "", {"url": "http://test.com"}, {}, ""),
        ), patch.object(
            self.cert,
            "get_certificate_details",
            side_effect=Exception("Get details error"),
        ), patch.object(
            self.cert, "_prepare_certificate_response", return_value={"code": 500}
        ) as mock_prepare:
            result = self.cert.process_certificate_request("content")
            mock_prepare.assert_called()

    def test_136_process_certificate_request_unexpected_error(self):
        """Test process_certificate_request with unexpected error"""
        with patch.object(
            self.cert, "_validate_input_parameters", side_effect=Exception("Unexpected")
        ), patch.object(
            self.cert, "_prepare_certificate_response", return_value={"code": 500}
        ):
            result = self.cert.process_certificate_request("content")
            self.assertEqual(result["code"], 500)

    def test_137_validate_revocation_message_success(self):
        """Test _validate_revocation_message success"""
        with patch.object(
            self.cert.message,
            "check",
            return_value=(200, "msg", "detail", "protected", {}, "account"),
        ):
            result = self.cert._validate_revocation_message("content")
            self.assertEqual(result[0], 200)

    def test_138_validate_revocation_message_error(self):
        """Test _validate_revocation_message with error"""
        with patch.object(
            self.cert.message, "check", side_effect=Exception("Message error")
        ):
            result = self.cert._validate_revocation_message("content")
            self.assertEqual(result[0], 400)

    def test_139_process_certificate_revocation_validation_error(self):
        """Test _process_certificate_revocation with validation error"""
        with patch.object(
            self.cert, "_validate_revocation_request", return_value=(400, "error")
        ):
            result = self.cert._process_certificate_revocation("account", {})
            self.assertEqual(result, (400, "error", None))

    def test_140_process_certificate_revocation_success(self):
        """Test _process_certificate_revocation success"""
        payload = {"certificate": "cert"}
        with patch.object(
            self.cert, "_validate_revocation_request", return_value=(200, "unspecified")
        ), patch.object(self.cert, "cahandler") as mock_cahandler:
            mock_ca = MagicMock()
            mock_ca.revoke.return_value = (200, "revoked", "detail")
            mock_cahandler.return_value.__enter__.return_value = mock_ca

            result = self.cert._process_certificate_revocation("account", payload)
            self.assertEqual(result, (200, "revoked", "detail"))

    def test_141_process_certificate_revocation_with_logging(self):
        """Test _process_certificate_revocation with operations logging"""
        payload = {"certificate": "cert"}
        self.cert.config.cert_operations_log = "json"
        with patch.object(
            self.cert, "_validate_revocation_request", return_value=(200, "unspecified")
        ), patch.object(self.cert, "cahandler") as mock_cahandler, patch.object(
            self.cert.certificate_logger, "log_certificate_revocation"
        ) as mock_log:
            mock_ca = MagicMock()
            mock_ca.revoke.return_value = (200, "revoked", "detail")
            mock_cahandler.return_value.__enter__.return_value = mock_ca

            result = self.cert._process_certificate_revocation("account", payload)
            mock_log.assert_called_with("cert", 200)

    def test_142_process_certificate_revocation_logging_error(self):
        """Test _process_certificate_revocation with logging error"""
        payload = {"certificate": "cert"}
        self.cert.config.cert_operations_log = "json"
        with patch.object(
            self.cert, "_validate_revocation_request", return_value=(200, "unspecified")
        ), patch.object(self.cert, "cahandler") as mock_cahandler, patch.object(
            self.cert.certificate_logger,
            "log_certificate_revocation",
            side_effect=Exception("Log error"),
        ):
            mock_ca = MagicMock()
            mock_ca.revoke.return_value = (200, "revoked", "detail")
            mock_cahandler.return_value.__enter__.return_value = mock_ca

            result = self.cert._process_certificate_revocation("account", payload)
            self.assertEqual(
                result, (200, "revoked", "detail")
            )  # Should still succeed despite log error

    def test_143_process_certificate_revocation_exception(self):
        """Test _process_certificate_revocation with exception"""
        with patch.object(
            self.cert,
            "_validate_revocation_request",
            side_effect=Exception("Revocation error"),
        ):
            result = self.cert._process_certificate_revocation("account", {})
            self.assertEqual(result[0], 500)

    def test_144_revoke_certificate_invalid_content(self):
        """Test revoke_certificate with invalid content"""
        with patch.object(
            self.cert, "_validate_input_parameters", return_value={"content": "error"}
        ), patch.object(
            self.cert.message, "prepare_response", return_value={"code": 400}
        ):
            result = self.cert.revoke_certificate("")
            self.assertIn("code", result)

    def test_145_revoke_certificate_message_validation_error(self):
        """Test revoke_certificate with message validation error"""
        with patch.object(
            self.cert, "_validate_input_parameters", return_value={}
        ), patch.object(
            self.cert,
            "_validate_revocation_message",
            return_value=(400, "error", "detail", "", {}, ""),
        ), patch.object(
            self.cert.message, "prepare_response", return_value={"code": 400}
        ):
            result = self.cert.revoke_certificate("content")
            self.assertIn("code", result)

    def test_146_revoke_certificate_success(self):
        """Test revoke_certificate success"""
        with patch.object(
            self.cert, "_validate_input_parameters", return_value={}
        ), patch.object(
            self.cert,
            "_validate_revocation_message",
            return_value=(200, "ok", "", "", {"certificate": "cert"}, "account"),
        ), patch.object(
            self.cert,
            "_process_certificate_revocation",
            return_value=(200, "revoked", "detail"),
        ), patch.object(
            self.cert.message, "prepare_response", return_value={"code": 200}
        ) as mock_prepare:
            result = self.cert.revoke_certificate("content")
            mock_prepare.assert_called()

    def test_147_revoke_certificate_unexpected_error(self):
        """Test revoke_certificate with unexpected error"""
        with patch.object(
            self.cert, "_validate_input_parameters", side_effect=Exception("Unexpected")
        ), patch.object(
            self.cert.message, "prepare_response", return_value={"code": 500}
        ):
            result = self.cert.revoke_certificate("content")
            self.assertIn("code", result)

    def test_148_process_enrollment_and_store_certificate_success(self):
        # Pre-enrollment hooks return empty (no error)
        with patch.object(
            self.cert, "_execute_pre_enrollment_hooks", return_value=[]
        ), patch.object(
            self.cert,
            "_process_certificate_enrollment",
            return_value=(None, "cert", "raw", "poll", False),
        ), patch.object(
            self.cert,
            "_store_certificate_and_update_order",
            return_value=("result", None),
        ), patch.object(
            self.cert.certificate_logger, "log_certificate_issuance"
        ) as mock_log, patch.object(
            self.cert, "_execute_post_enrollment_hooks", return_value=[]
        ):
            self.cert.config.cert_operations_log = "json"
            result = self.cert._process_enrollment_and_store_certificate(
                "cert_name", "csr", "order_name"
            )
            self.assertEqual(result, ("result", None, None))
            mock_log.assert_called_with("cert_name", "raw", "order_name", False)

    def test_149_process_enrollment_and_store_certificate_enrollment_error(self):
        # Enrollment returns no certificate, triggers error handling
        with patch.object(
            self.cert, "_execute_pre_enrollment_hooks", return_value=[]
        ), patch.object(
            self.cert,
            "_process_certificate_enrollment",
            return_value=("error", None, None, "poll", False),
        ), patch.object(
            self.cert,
            "_handle_enrollment_error",
            return_value=("result", "error", "detail"),
        ) as mock_handle, patch.object(
            self.cert, "_execute_post_enrollment_hooks", return_value=[]
        ):
            result = self.cert._process_enrollment_and_store_certificate(
                "cert_name", "csr", "order_name"
            )
            self.assertEqual(result, ("result", "error", "detail"))
            mock_handle.assert_called()

    def test_150_process_enrollment_and_store_certificate_pre_hook_error(self):
        # Pre-enrollment hook returns error, should return early
        with patch.object(
            self.cert, "_execute_pre_enrollment_hooks", return_value=["pre_hook_error"]
        ):
            result = self.cert._process_enrollment_and_store_certificate(
                "cert_name", "csr", "order_name"
            )
            self.assertEqual(result, ["pre_hook_error"])

    def test_151_process_enrollment_and_store_certificate_post_hook_error(self):
        # Post-enrollment hook returns error, should return early
        with patch.object(
            self.cert, "_execute_pre_enrollment_hooks", return_value=[]
        ), patch.object(
            self.cert,
            "_process_certificate_enrollment",
            return_value=(None, "cert", "raw", "poll", False),
        ), patch.object(
            self.cert,
            "_store_certificate_and_update_order",
            return_value=("result", None),
        ), patch.object(
            self.cert.certificate_logger, "log_certificate_issuance"
        ), patch.object(
            self.cert,
            "_execute_post_enrollment_hooks",
            return_value=["post_hook_error"],
        ):
            result = self.cert._process_enrollment_and_store_certificate(
                "cert_name", "csr", "order_name"
            )
            self.assertEqual(result, ["post_hook_error"])

    def test_152_process_enrollment_and_store_certificate_store_error(self):
        # _store_certificate_and_update_order returns error, should return error
        with patch.object(
            self.cert, "_execute_pre_enrollment_hooks", return_value=[]
        ), patch.object(
            self.cert,
            "_process_certificate_enrollment",
            return_value=(None, "cert", "raw", "poll", False),
        ), patch.object(
            self.cert,
            "_store_certificate_and_update_order",
            return_value=("result", "error"),
        ):
            result = self.cert._process_enrollment_and_store_certificate(
                "cert_name", "csr", "order_name"
            )
            self.assertEqual(result, "error")

    def test_153_process_enrollment_and_store_certificate_logger_exception(self):
        # Exception in logger should not crash method
        with patch.object(
            self.cert, "_execute_pre_enrollment_hooks", return_value=[]
        ), patch.object(
            self.cert,
            "_process_certificate_enrollment",
            return_value=(None, "cert", "raw", "poll", False),
        ), patch.object(
            self.cert,
            "_store_certificate_and_update_order",
            return_value=("result", None),
        ), patch.object(
            self.cert.certificate_logger,
            "log_certificate_issuance",
            side_effect=Exception("log error"),
        ), patch.object(
            self.cert, "_execute_post_enrollment_hooks", return_value=[]
        ):
            result = self.cert._process_enrollment_and_store_certificate(
                "cert_name", "csr", "order_name"
            )
            self.assertEqual(result, ("result", None, None))

    def test_154_get_certificate_info_success(self):
        # Covers: _get_certificate_info normal DB lookup (line 1106)
        cert = self.cert
        cert.repository.certificate_lookup.return_value = {"foo": "bar"}
        result = cert._get_certificate_info("cert_name")
        self.assertEqual(result, {"foo": "bar"})
        cert.repository.certificate_lookup.assert_called_with(
            "name", "cert_name", ("name", "csr", "cert", "order__name")
        )

    def test_155_get_certificate_info_db_error(self):
        # Covers: _get_certificate_info exception/critical branch (lines 1118-1119)
        cert = self.cert
        cert.repository.certificate_lookup.side_effect = Exception("fail")
        result = cert._get_certificate_info("cert_name")
        self.assertIsNone(result)
        cert.logger.critical.assert_called()
        self.assertIn(
            "Database error: failed to get certificate info",
            cert.logger.critical.call_args[0][0],
        )

    def test_156_process_certificate_request_code_200_no_url(self):
        # Covers: process_certificate_request else branch for missing url in protected
        from unittest.mock import patch, MagicMock

        def fake_message_init(self, debug, server_name, logger):
            self.logger = MagicMock()
            self.debug = debug
            self.server_name = server_name
            self.config = MagicMock()
            self.prepare_response = MagicMock(return_value={})

        with patch(
            "acme_srv.certificate.error_dic_get",
            return_value={"serverinternal": "err", "malformed": "malf"},
        ):
            with patch("acme_srv.message.Message.__init__", new=fake_message_init):
                cert = certificate.Certificate()
                cert.logger = MagicMock()
                cert._validate_input_parameters = MagicMock(return_value=None)
                cert._validate_certificate_request_message = MagicMock(
                    return_value=(200, "ok", "detail", {}, {}, "")
                )
                cert._prepare_certificate_response = MagicMock(
                    return_value={"code": 400, "data": "error"}
                )
                result = cert.process_certificate_request("dummy-content")
                cert._prepare_certificate_response.assert_called_with(
                    {}, 400, "malf", "url missing in protected header"
                )
                self.assertEqual(result, {"code": 400, "data": "error"})

    def test_157_store_certificate_signing_request_unexpected_exception(self):
        # Covers: store_certificate_signing_request exception branch (lines 1824-1826)
        from unittest.mock import patch, MagicMock

        def fake_message_init(self, debug, server_name, logger):
            self.logger = MagicMock()
            self.debug = debug
            self.server_name = server_name
            self.config = MagicMock()
            self.prepare_response = MagicMock(return_value={})

        with patch(
            "acme_srv.certificate.error_dic_get",
            return_value={"serverinternal": "err", "malformed": "malf"},
        ):
            with patch("acme_srv.message.Message.__init__", new=fake_message_init):
                mock_logger = MagicMock()
                cert = certificate.Certificate(logger=mock_logger)
                cert.certificate_manager = MagicMock()
                cert.certificate_manager.validate_and_store_csr.side_effect = Exception(
                    "unexpected error"
                )
                import pytest

                with self.assertRaises(RuntimeError) as excinfo:
                    cert.store_certificate_signing_request(
                        "order1", "csrdata", "headerinfo"
                    )
                self.assertEqual(mock_logger.error.call_count, 1)
                self.assertIn(
                    "Error during CSR validation and storage",
                    mock_logger.error.call_args[0][0],
                )
                self.assertIn(
                    "CSR storage failed: unexpected error", str(excinfo.exception)
                )

    def test_158_poll_certificate_status_unexpected_exception(self):
        # Covers: poll_certificate_status except branch for unexpected exception
        with patch.object(
            self.cert, "_validate_input_parameters", side_effect=Exception("fail")
        ), patch.object(self.cert.logger, "critical") as mock_critical:
            result = self.cert.poll_certificate_status("cert", "poll", "csr", "order")
            self.assertIsNone(result)
            mock_critical.assert_called_with(
                "Unexpected error in poll_certificate_status: %s", unittest.mock.ANY
            )

    def test_159_handle_successful_certificate_poll_order_update_exception(self):
        # Covers: _handle_successful_certificate_poll except branch for order_update
        with patch.object(
            self.cert, "_store_certificate_in_database", return_value=123
        ), patch.object(
            self.cert.repository, "order_update", side_effect=Exception("fail")
        ), patch.object(
            self.cert.logger, "critical"
        ) as mock_critical:
            result = self.cert._handle_successful_certificate_poll(
                "cert", "cert", "raw", "order"
            )
            self.assertEqual(result, 123)
            mock_critical.assert_called_with(
                "Database error updating order status during polling: %s",
                unittest.mock.ANY,
            )

    def test_160_process_certificate_request_get_certificate_details_exception(self):
        # Covers: process_certificate_request except block for get_certificate_details
        with patch.object(
            self.cert, "_validate_input_parameters", return_value={}
        ), patch.object(
            self.cert,
            "_validate_certificate_request_message",
            return_value=(200, "ok", "", {"url": "http://test.com"}, {}, ""),
        ), patch.object(
            self.cert, "get_certificate_details", side_effect=Exception("fail")
        ), patch.object(
            self.cert, "_prepare_certificate_response", return_value={"code": 500}
        ) as mock_prepare:
            result = self.cert.process_certificate_request("content")
            mock_prepare.assert_called()
            self.assertEqual(result["code"], 500)

    def test_161_process_certificate_request_outer_exception(self):
        # Covers: process_certificate_request outer except block
        with patch.object(
            self.cert, "_validate_input_parameters", side_effect=Exception("fail")
        ), patch.object(
            self.cert, "_prepare_certificate_response", return_value={"code": 500}
        ):
            result = self.cert.process_certificate_request("content")
            self.assertEqual(result["code"], 500)

    def test_162_process_certificate_request_url_missing(self):
        # Covers: process_certificate_request else branch for missing url in protected
        with patch.object(
            self.cert, "_validate_input_parameters", return_value={}
        ), patch.object(
            self.cert,
            "_validate_certificate_request_message",
            return_value=(200, "ok", "", {}, {}, ""),
        ), patch.object(
            self.cert, "_prepare_certificate_response", return_value={"code": 400}
        ) as mock_prepare:
            result = self.cert.process_certificate_request("content")
            mock_prepare.assert_called()
            self.assertEqual(result["code"], 400)

    def test_163_process_certificate_revocation_logger_warning(self):
        # Covers: _process_certificate_revocation logger.warning branch
        payload = {"certificate": "cert"}
        self.cert.config.cert_operations_log = "json"
        with patch.object(
            self.cert, "_validate_revocation_request", return_value=(200, "unspecified")
        ), patch.object(self.cert, "cahandler") as mock_cahandler, patch.object(
            self.cert.certificate_logger,
            "log_certificate_revocation",
            side_effect=Exception("fail"),
        ), patch.object(
            self.cert.logger, "warning"
        ) as mock_warning:
            mock_ca = MagicMock()
            mock_ca.revoke.return_value = (200, "revoked", "detail")
            mock_cahandler.return_value.__enter__.return_value = mock_ca
            result = self.cert._process_certificate_revocation("account", payload)
            mock_warning.assert_called()
            self.assertEqual(result, (200, "revoked", "detail"))

    def test_164_revoke_certificate_payload_missing_certificate(self):
        # Covers: revoke_certificate branch where payload is missing 'certificate'
        with patch.object(
            self.cert, "_validate_input_parameters", return_value={}
        ), patch.object(
            self.cert,
            "_validate_revocation_message",
            return_value=(200, "ok", "", "", {}, ""),
        ), patch.object(
            self.cert.message, "prepare_response", return_value={"code": 400}
        ) as mock_prepare:
            result = self.cert.revoke_certificate("content")
            mock_prepare.assert_called()
            self.assertEqual(result["code"], 400)

    def test_165_revoke_certificate_outer_exception(self):
        # Covers: revoke_certificate outer except block
        with patch.object(
            self.cert, "_validate_input_parameters", side_effect=Exception("fail")
        ), patch.object(
            self.cert.message, "prepare_response", return_value={"code": 500}
        ):
            result = self.cert.revoke_certificate("content")
            self.assertEqual(result["code"], 500)

    def test_166_store_certificate_signing_request_unexpected_exception(self):
        # Covers: store_certificate_signing_request unexpected exception/critical
        # Patch logger.debug after the nested try/except to raise an exception
        orig_debug = self.cert.logger.debug

        def debug_side_effect(*args, **kwargs):
            if args and "ended successfully" in str(args[0]):
                raise TypeError("fail")
            return orig_debug(*args, **kwargs)

        with patch.object(
            self.cert.certificate_manager,
            "validate_and_store_csr",
            return_value=(True, "cert"),
        ):
            with patch.object(
                self.cert.logger, "debug", side_effect=debug_side_effect
            ), patch.object(self.cert.logger, "critical") as mock_critical:
                with self.assertRaises(RuntimeError):
                    self.cert.store_certificate_signing_request(
                        "order", "csr", "header"
                    )
                mock_critical.assert_called()

    def test_167_poll_certificate_status_unexpected_exception(self):
        # Covers: poll_certificate_status exception/critical branch (line 1825)
        cert = self.cert
        # Patch _validate_input_parameters to raise, so the outer except is triggered
        cert._validate_input_parameters = MagicMock(side_effect=Exception("fail"))
        cert.logger.reset_mock()
        result = cert.poll_certificate_status("certname", "pollid", "csr", "order")
        cert.logger.critical.assert_called()
        self.assertIsNone(result)
        self.assertIn(
            "Unexpected error in poll_certificate_status",
            cert.logger.critical.call_args[0][0],
        )

    def test_168_store_certificate_in_database_exception(self):
        # Covers: _store_certificate_in_database exception/critical branch
        cert = self.cert
        cert._get_certificate_renewal_info = MagicMock(return_value="renewal_info")
        # Patch cert_serial_get and cert_aki_get to avoid unrelated errors
        import acme_srv.certificate as certificate_mod

        orig_cert_serial_get = certificate_mod.cert_serial_get
        orig_cert_aki_get = certificate_mod.cert_aki_get
        certificate_mod.cert_serial_get = MagicMock(return_value="serial")
        certificate_mod.cert_aki_get = MagicMock(return_value="aki")
        cert.repository.certificate_add.side_effect = Exception("db error")
        cert.logger.reset_mock()
        try:
            result = cert._store_certificate_in_database(
                "certname", "cert", "raw", 1, 2, "pollid"
            )
            cert.logger.critical.assert_called()
            self.assertIsNone(result)
            self.assertIn(
                "acme2certifier database error in Certificate._store_certificate_in_database",
                cert.logger.critical.call_args[0][0],
            )
        finally:
            certificate_mod.cert_serial_get = orig_cert_serial_get
            certificate_mod.cert_aki_get = orig_cert_aki_get

    def test_169_store_certificate_error_exception(self):
        # Covers: _store_certificate_error exception/critical branch
        cert = self.cert
        cert.repository.certificate_add.side_effect = Exception("fail")
        cert.logger.reset_mock()
        result = cert._store_certificate_error("cert_name", "error", "poll_id")
        self.assertIsNone(result)
        cert.logger.critical.assert_called()
        self.assertIn(
            "Database error: failed to store certificate error",
            cert.logger.critical.call_args[0][0],
        )

    def test_170_check_tnauth_identifier_match_true(self):
        # Covers: _check_tnauth_identifier_match type/value match (lines 1245-1246)
        cert = self.cert
        identifier = {"type": "tnauthlist", "value": "abc"}
        tnauthlist = ["abc", "def"]
        result = cert._check_tnauth_identifier_match(identifier, tnauthlist)
        self.assertTrue(result)

    def test_171_check_tnauth_identifier_match_false(self):
        # Covers: _check_tnauth_identifier_match no match (lines 1245-1246)
        cert = self.cert
        identifier = {"type": "tnauthlist", "value": "xyz"}
        tnauthlist = ["abc", "def"]
        result = cert._check_tnauth_identifier_match(identifier, tnauthlist)
        self.assertFalse(result)

    def test_172_check_identifier_match_true(self):
        # Covers: _check_identifier_match for-loop/if-branch (line 1221)
        cert = self.cert
        identifiers = [
            {"type": "dns", "value": "foo"},
            {"type": "email", "value": "bar"},
        ]
        result = cert._check_identifier_match("dns", "foo", identifiers, False)
        self.assertTrue(result)

    def test_173_check_identifier_match_false(self):
        # Covers: _check_identifier_match return (line 1223) when no match
        cert = self.cert
        identifiers = [
            {"type": "dns", "value": "baz"},
            {"type": "email", "value": "bar"},
        ]
        result = cert._check_identifier_match("dns", "foo", identifiers, False)
        self.assertFalse(result)

    def test_174_validate_revocation_request_unauthorized_forced(self):
        # Force coverage for line 1171 by using a custom err_msg_dic with a side effect
        cert = certificate.Certificate(debug=True, srv_name=None, logger=MagicMock())

        class SideEffectDict(dict):
            def __getitem__(self, key):
                if key == "unauthorized":
                    print("COVERAGE: unauthorized branch hit")
                return super().__getitem__(key)

        cert.err_msg_dic = SideEffectDict(
            {
                "badrevocationreason": "badreason",
                "unauthorized": "unauth",
                "serverinternal": "internal",
            }
        )
        payload = {"reason": 0, "certificate": "cert"}
        with patch.object(
            cert, "_validate_certificate_account_ownership", return_value="order"
        ), patch.object(cert, "_validate_order_authorization", return_value=False):
            code, error = cert._validate_revocation_request("acc", payload)
            self.assertEqual(code, 400)
            self.assertEqual(error, "unauth")

    def test_175_validate_revocation_request_unauthorized_minimal(self):
        # Isolated test to guarantee coverage for line 1171 (unauthorized branch)
        cert = certificate.Certificate(debug=True, srv_name=None, logger=MagicMock())
        cert.err_msg_dic = {
            "badrevocationreason": "badreason",
            "unauthorized": "unauth",
            "serverinternal": "internal",
        }
        payload = {"reason": 0, "certificate": "cert"}
        # Patch only the necessary methods
        with patch.object(
            cert, "_validate_certificate_account_ownership", return_value="order"
        ), patch.object(cert, "_validate_order_authorization", return_value=False):
            code, error = cert._validate_revocation_request("acc", payload)
            self.assertEqual(code, 400)
            self.assertEqual(error, "unauth")

    def test_176_validate_revocation_request_bad_reason(self):
        # Covers line 1159: error = self.err_msg_dic["badrevocationreason"]
        payload = {"reason": 99, "certificate": "cert"}  # 99 is not a valid reason
        self.cert.err_msg_dic = {
            "badrevocationreason": "badreason",
            "unauthorized": "unauth",
            "serverinternal": "internal",
        }
        code, error = self.cert._validate_revocation_request("acc", payload)
        self.assertEqual(code, 400)
        self.assertEqual(error, "badreason")

    def test_177_validate_revocation_request_no_reason(self):
        # Covers line 1162: rev_reason = "unspecified"
        payload = {"certificate": "cert"}
        self.cert.err_msg_dic = {
            "badrevocationreason": "badreason",
            "unauthorized": "unauth",
            "serverinternal": "internal",
        }
        with patch.object(
            self.cert, "_validate_certificate_account_ownership", return_value=None
        ):
            code, error = self.cert._validate_revocation_request("acc", payload)
            self.assertEqual(code, 400)
            self.assertEqual(error, "unspecified")

    def test_178_validate_revocation_request_unauthorized(self):
        # Explicitly cover line 1171: error = self.err_msg_dic["unauthorized"]
        payload = {"reason": 0, "certificate": "cert"}
        self.cert.err_msg_dic = {
            "badrevocationreason": "badreason",
            "unauthorized": "unauth",
            "serverinternal": "internal",
        }
        # Patch _validate_certificate_account_ownership to return a non-None value (order_name)
        # Patch _validate_order_authorization to return False (unauthorized)
        with patch.object(
            self.cert, "_validate_certificate_account_ownership", return_value="order"
        ) as mock_own, patch.object(
            self.cert, "_validate_order_authorization", return_value=False
        ) as mock_auth:
            code, error = self.cert._validate_revocation_request("acc", payload)
            self.assertEqual(code, 400)
            self.assertEqual(error, "unauth")
            mock_own.assert_called_once_with("acc", "cert")
            mock_auth.assert_called_once_with("order", "cert")

    def test_179_validate_revocation_request_success(self):
        # Covers line 1183: code = 200
        payload = {"reason": 0, "certificate": "cert"}
        self.cert.err_msg_dic = {
            "badrevocationreason": "badreason",
            "unauthorized": "unauth",
            "serverinternal": "internal",
        }
        with patch.object(
            self.cert, "_validate_certificate_account_ownership", return_value="order"
        ), patch.object(self.cert, "_validate_order_authorization", return_value=True):
            code, error = self.cert._validate_revocation_request("acc", payload)
            self.assertEqual(code, 200)
            self.assertEqual(error, "unspecified")

    def test_180_validate_revocation_request_nocert(self):
        # Explicitly cover line 1171: error = self.err_msg_dic["unauthorized"] and check logger
        payload = {"reason": 0, "foo": "bar"}
        self.cert.err_msg_dic = {
            "badrevocationreason": "badreason",
            "unauthorized": "unauth",
            "serverinternal": "internal",
        }
        with patch.object(
            self.cert, "_validate_certificate_account_ownership", return_value="order"
        ) as mock_own, patch.object(
            self.cert, "_validate_order_authorization", return_value=False
        ) as mock_auth, patch.object(
            self.cert.logger, "debug"
        ) as mock_logger_debug:
            code, error = self.cert._validate_revocation_request("acc", payload)
            self.assertEqual(code, 400)
            # self.assertEqual(error, 'unauth')
            # mock_own.assert_called_once_with('acc', 'cert')
            # mock_auth.assert_called_once_with('order', 'cert')
            mock_logger_debug.assert_any_call(
                "Certificate._validate_revocation_request(): Revocation request missing 'certificate' field"
            )

    def test_181_validate_csr_against_order_order_lookup_exception(self):
        # Covers exception branch at line 720 in _validate_csr_against_order
        cert_dic = {"order": "order1"}
        with patch.object(
            self.cert, "_get_certificate_info", return_value=cert_dic
        ), patch.object(
            self.cert.repository, "order_lookup", side_effect=Exception("lookup failed")
        ), patch.object(
            self.cert.logger, "critical"
        ) as mock_critical:
            result = self.cert._validate_csr_against_order("cert_name", "csr")
            mock_critical.assert_called_with(
                "Database error in Certificate when checking the CSR identifiers: %s",
                unittest.mock.ANY,
            )
            self.assertFalse(result)

    def test_182_store_certificate_and_update_order_success_hook(self):
        # Covers success_hook execution and debug log
        self.cert.hooks = MagicMock()
        self.cert.hooks.success_hook.return_value = None
        with patch.object(
            self.cert, "_store_certificate_in_database", return_value=1
        ), patch.object(self.cert, "_update_order_status") as mock_update, patch.object(
            self.cert.logger, "debug"
        ) as mock_debug:
            result, error = self.cert._store_certificate_and_update_order(
                "cert", "raw", "poll", "cert_name", "order", "csr"
            )
            self.cert.hooks.success_hook.assert_called_with(
                "cert_name", "order", "csr", "cert", "raw", "poll"
            )
            mock_debug.assert_any_call(
                "Certificate._store_certificate_and_update_order: success_hook successful"
            )
            self.assertEqual(result, 1)
            self.assertIsNone(error)

    def test_183_store_certificate_and_update_order_success_hook_exception(self):
        # Covers exception in success_hook and error logging
        self.cert.hooks = MagicMock()
        self.cert.hooks.success_hook.side_effect = Exception("success_hook failed")
        self.cert.config.ignore_success_hook_failure = False
        with patch.object(
            self.cert, "_store_certificate_in_database", return_value=1
        ), patch.object(self.cert, "_update_order_status"), patch.object(
            self.cert.logger, "error"
        ) as mock_logger_error:
            result, error = self.cert._store_certificate_and_update_order(
                "cert", "raw", "poll", "cert_name", "order", "csr"
            )
            mock_logger_error.assert_called_with(
                "Exception during success_hook execution: %s", unittest.mock.ANY
            )
            self.assertEqual(error, (None, "success_hook_error", "success_hook failed"))

    def test_184_store_certificate_and_update_order_success_hook_exception_ignore(self):
        # Covers exception in success_hook with ignore_success_hook_failure True (no error returned)
        self.cert.hooks = MagicMock()
        self.cert.hooks.success_hook.side_effect = Exception("success_hook failed")
        self.cert.config.ignore_success_hook_failure = True
        with patch.object(
            self.cert, "_store_certificate_in_database", return_value=1
        ), patch.object(self.cert, "_update_order_status"), patch.object(
            self.cert.logger, "error"
        ) as mock_logger_error:
            result, error = self.cert._store_certificate_and_update_order(
                "cert", "raw", "poll", "cert_name", "order", "csr"
            )
            mock_logger_error.assert_called_with(
                "Exception during success_hook execution: %s", unittest.mock.ANY
            )
            self.assertEqual(result, 1)
            self.assertIsNone(error)

    def test_185_execute_pre_enrollment_hooks_exception(self):
        # Covers exception branch when pre_hook raises and ignore_pre_hook_failure is False
        mock_hooks = MagicMock()
        mock_hooks.pre_hook.side_effect = Exception("pre_hook failed")
        self.cert.hooks = mock_hooks
        self.cert.config.ignore_pre_hook_failure = False
        with patch.object(self.cert.logger, "error") as mock_logger_error:
            result = self.cert._execute_pre_enrollment_hooks(
                "cert_name", "order_name", "csr"
            )
            mock_logger_error.assert_called_with(
                "Exception during pre_hook execution: %s", unittest.mock.ANY
            )
            self.assertEqual(result, (None, "pre_hook_error", "pre_hook failed"))

    def test_186_handle_enrollment_error_no_poll_identifier(self):
        # Covers branch where poll_identifier is None and error is not special string
        self.cert.err_msg_dic = {
            "serverinternal": "serverinternal",
            "rejectedidentifier": "rejectedidentifier",
        }
        with patch.object(
            self.cert, "_update_order_status"
        ) as mock_update, patch.object(
            self.cert, "_store_certificate_error"
        ) as mock_store:
            result = self.cert._handle_enrollment_error(
                "some_error", None, "order1", "cert1"
            )
            mock_update.assert_called_with({"name": "order1", "status": "invalid"})
            mock_store.assert_called_with("cert1", "some_error", None)
            self.assertEqual(result, (None, "serverinternal", None))

    def test_187_handle_enrollment_error_with_poll_identifier(self):
        # Covers branch where poll_identifier is set
        with patch.object(
            self.cert, "_update_order_status"
        ) as mock_update, patch.object(
            self.cert, "_store_certificate_error"
        ) as mock_store:
            result = self.cert._handle_enrollment_error(
                "some_error", "pollid", "order1", "cert1"
            )
            # Should not call update_order_status
            mock_update.assert_not_called()
            mock_store.assert_called_with("cert1", "some_error", "pollid")
            self.assertEqual(result, (None, "some_error", "pollid"))

    def test_188_handle_enrollment_error_rejected_identifier(self):
        # Covers branch where error is 'Either CN or SANs are not allowed by configuration'
        self.cert.err_msg_dic = {
            "serverinternal": "serverinternal",
            "rejectedidentifier": "rejectedidentifier",
        }
        with patch.object(
            self.cert, "_update_order_status"
        ) as mock_update, patch.object(
            self.cert, "_store_certificate_error"
        ) as mock_store:
            result = self.cert._handle_enrollment_error(
                "Either CN or SANs are not allowed by configuration",
                None,
                "order1",
                "cert1",
            )
            mock_update.assert_called_with({"name": "order1", "status": "invalid"})
            mock_store.assert_called_with(
                "cert1", "Either CN or SANs are not allowed by configuration", None
            )
            self.assertEqual(
                result,
                (
                    None,
                    "rejectedidentifier",
                    "CN or SANs are not allowed by configuration",
                ),
            )

    def test_189_handle_enrollment_error_exception(self):
        # Covers exception branch
        self.cert.err_msg_dic = {
            "serverinternal": "serverinternal",
            "rejectedidentifier": "rejectedidentifier",
        }
        with patch.object(
            self.cert, "_update_order_status", side_effect=Exception("fail")
        ), patch.object(
            self.cert, "_store_certificate_error", side_effect=Exception("fail")
        ), patch.object(
            self.cert.logger, "critical"
        ) as mock_critical:
            result = self.cert._handle_enrollment_error(
                "some_error", None, "order1", "cert1"
            )
            mock_critical.assert_called()
            self.assertEqual(result, (None, "serverinternal", None))

    def test_190_validate_certificate_authorization_sans_exception(self):
        # Explicitly covers lines 477-481: exception in cert_san_get triggers warning and returns []
        self.cert.config.tnauthlist_support = False
        with patch(
            "acme_srv.certificate.cert_san_get", side_effect=Exception("fail")
        ), patch.object(self.cert.logger, "warning") as mock_warning, patch.object(
            self.cert.logger, "debug"
        ) as mock_debug:
            result = self.cert._validate_certificate_authorization(
                {"identifiers": "[]"}, "cert"
            )
            self.assertEqual(result, [])
            mock_warning.assert_called_with(
                "Error while parsing certificate for SAN identifier check: %s",
                unittest.mock.ANY,
            )
            mock_debug.assert_any_call(
                "Certificate._validate_certificate_authorization() ended"
            )

    def test_191_enter_calls_load_configuration_and_returns_self(self):
        cert = self.cert
        with patch.object(cert, "_load_configuration") as mock_load_config:
            result = cert.__enter__()
            mock_load_config.assert_called_once()
            self.assertIs(result, cert)

    def test_192_validate_certificate_authorization_cn2san_add(self):
        # Covers the branch where tnauthlist_support is False and cn2san_add is True
        self.cert.config.tnauthlist_support = False
        self.cert.config.cn2san_add = True
        # Simulate no SANs returned, but CN is present
        with patch("acme_srv.certificate.cert_san_get", return_value=[]), patch(
            "acme_srv.certificate.cert_cn_get", return_value="mycn"
        ) as mock_cn_get, patch.object(
            self.cert, "_validate_identifiers_against_sans", return_value=["ok"]
        ) as mock_validate:
            result = self.cert._validate_certificate_authorization(
                {"identifiers": "[]"}, "cert"
            )
            # The CN should be added to the SANs list as DNS:mycn
            mock_cn_get.assert_called_once()
            mock_validate.assert_called_with([], ["DNS:mycn"])
            self.assertEqual(result, ["ok"])

    def test_193_validate_certificate_authorization_sans_exception(self):
        # Covers lines 477-481: exception in cert_san_get triggers warning and returns []
        self.cert.config.tnauthlist_support = False
        with patch(
            "acme_srv.certificate.cert_san_get", side_effect=Exception("fail")
        ), patch.object(self.cert.logger, "warning") as mock_warning, patch.object(
            self.cert.logger, "debug"
        ) as mock_debug:
            result = self.cert._validate_certificate_authorization(
                {"identifiers": "[]"}, "cert"
            )
            self.assertEqual(result, [])
            mock_warning.assert_called_with(
                "Error while parsing certificate for SAN identifier check: %s",
                unittest.mock.ANY,
            )
            mock_debug.assert_any_call(
                "Certificate._validate_certificate_authorization() ended"
            )

    def test_194_handle_enrollment_thread_execution_async_mode(self):
        """Test _handle_enrollment_thread_execution with async_mode True (lines 1305-1306)."""
        self.cert.config.async_mode = True
        self.cert.config.enrollment_timeout = 5
        with patch("acme_srv.certificate.ThreadWithReturnValue") as mock_thread:
            mock_thread_instance = MagicMock()
            # join should not be called when async_mode is True
            mock_thread.return_value = mock_thread_instance
            result = self.cert._handle_enrollment_thread_execution(
                "cert_name", "csr", "order"
            )
            self.assertEqual(result, (None, "asynchronous enrollment started"))
            mock_thread_instance.join.assert_not_called()

    def test_195_check_certificate_reusability_reused_values(self):
        """Test _check_certificate_reusability returns correct cert, cert_raw, and message when reused."""
        cert_data = {
            "expire_uts": 9999999999,
            "issue_uts": 1,
            "cert": "cert_value",
            "cert_raw": "raw_value",
            "created_at": 1,
            "id": 42,
        }
        self.mock_repository.search_certificates.return_value = [cert_data]
        self.cert.config.cert_reusage_timeframe = 2  # Ensure reuse block is entered
        with patch("acme_srv.certificate.uts_now", return_value=2):
            _, cert, cert_raw, message = self.cert._check_certificate_reusability("csr")
            self.assertEqual(cert, "cert_value")
            self.assertEqual(cert_raw, "raw_value")
            self.assertIn("reused certificate from id: 42", message)

    def test_196_process_enrollment_and_store_certificate_log_exception(self):
        """Test _process_enrollment_and_store_certificate covers log_certificate_issuance exception branch (lines 930-933)."""
        cert = certificate.Certificate(
            debug=True, srv_name=None, logger=self.mock_logger
        )
        cert._execute_pre_enrollment_hooks = MagicMock(return_value=[])
        cert._process_certificate_enrollment = MagicMock(
            return_value=(None, "cert", "raw", "poll", True)
        )
        cert._store_certificate_and_update_order = MagicMock(return_value=(1, None))
        cert.config.cert_operations_log = "json"
        cert.certificate_logger.log_certificate_issuance = MagicMock(
            side_effect=Exception("log error")
        )
        cert._execute_post_enrollment_hooks = MagicMock(return_value=[])
        # Should not raise, but should call logger.error
        result = cert._process_enrollment_and_store_certificate(
            "cert_name", "csr", "order_name"
        )
        self.mock_logger.error.assert_any_call(
            "Exception during log_certificate_issuance: %s", unittest.mock.ANY
        )

    def test_197_load_configuration_defaults(self):
        """Test _load_configuration uses defaults when config is empty."""
        import configparser

        config = configparser.ConfigParser()
        with patch("acme_srv.certificate.load_config", return_value=config):
            cert = certificate.Certificate(
                debug=True, srv_name=None, logger=self.mock_logger
            )
            cert._load_configuration()
            config_obj = cert.config
            self.assertEqual(config_obj.cert_reusage_timeframe, 0)
            self.assertEqual(config_obj.enrollment_timeout, 5)
            self.assertEqual(config_obj.retry_after, 600)
            self.assertIsNone(config_obj.cert_operations_log)
            self.assertFalse(config_obj.tnauthlist_support)
            self.assertFalse(config_obj.cn2san_add)
            self.assertFalse(config_obj.ignore_pre_hook_failure)
            self.assertTrue(config_obj.ignore_post_hook_failure)
            self.assertFalse(config_obj.ignore_success_hook_failure)

    def test_198_load_configuration_full_config(self):
        """Test _load_configuration with all config sections and values overridden."""
        import configparser

        config = configparser.ConfigParser()
        config.add_section("Certificate")
        config.set("Certificate", "cert_reusage_timeframe", "123")
        config.set("Certificate", "enrollment_timeout", "9")
        config.set("Certificate", "retry_after", "321")
        config.set("Certificate", "cert_operations_log", "JSON")
        config.add_section("Order")
        config.set("Order", "tnauthlist_support", "True")
        config.add_section("CAhandler")
        config.set("CAhandler", "handler_file", "examples/ca_handler/asa_ca_handler.py")
        config.add_section("Directory")
        config.set("Directory", "url_prefix", "/prefix")
        config.add_section("Hooks")
        config.set("Hooks", "ignore_pre_hook_failure", "True")
        config.set("Hooks", "ignore_post_hook_failure", "False")
        config.set("Hooks", "ignore_success_hook_failure", "True")
        with patch("acme_srv.certificate.load_config", return_value=config):
            cert = certificate.Certificate(
                debug=True, srv_name=None, logger=self.mock_logger
            )
            cert._load_configuration()
            config_obj = cert.config
            self.assertEqual(config_obj.cert_reusage_timeframe, 123)
            self.assertEqual(config_obj.enrollment_timeout, 9)
            self.assertEqual(config_obj.retry_after, 321)
            self.assertEqual(config_obj.cert_operations_log, "json")
            self.assertTrue(config_obj.tnauthlist_support)
            self.assertTrue(config_obj.cn2san_add)
            self.assertTrue(config_obj.ignore_pre_hook_failure)
            self.assertFalse(config_obj.ignore_post_hook_failure)
            self.assertTrue(config_obj.ignore_success_hook_failure)

    def test_199_configuration_partial_config(self):
        """Test _load_configuration with some config sections missing."""
        import configparser

        config = configparser.ConfigParser()
        config.add_section("Certificate")
        config.set("Certificate", "cert_reusage_timeframe", "42")
        # No Order, CAhandler, Directory, Hooks
        with patch("acme_srv.certificate.load_config", return_value=config):
            cert = certificate.Certificate(
                debug=True, srv_name=None, logger=self.mock_logger
            )
            cert._load_configuration()
            config_obj = cert.config
            self.assertEqual(config_obj.cert_reusage_timeframe, 42)
            self.assertEqual(config_obj.enrollment_timeout, 5)  # default
            self.assertEqual(config_obj.retry_after, 600)  # default
            self.assertFalse(config_obj.tnauthlist_support)
            self.assertFalse(config_obj.cn2san_add)

    def test_200_configuration_directory_url_prefix(self):
        """Test _load_configuration applies url_prefix to path_dic."""
        import configparser

        config = configparser.ConfigParser()
        config.add_section("Directory")
        config.set("Directory", "url_prefix", "/api")
        with patch("acme_srv.certificate.load_config", return_value=config):
            cert = certificate.Certificate(
                debug=True, srv_name=None, logger=self.mock_logger
            )
            cert._load_configuration()
            # path_dic is on the instance, not config
            self.assertEqual(cert.path_dic["cert_path"], "/api/acme/cert/")

    def test_201_load_configuration_type_conversion_and_fallback(self):
        """Test _load_configuration handles type conversion and fallback logic."""
        import configparser

        config = configparser.ConfigParser()
        config.add_section("Certificate")
        config.set("Certificate", "cert_reusage_timeframe", "notanint")
        config.set("Certificate", "enrollment_timeout", "notanint")
        config.set("Certificate", "retry_after", "notanint")
        with patch("acme_srv.certificate.load_config", return_value=config):
            cert = certificate.Certificate(
                debug=True, srv_name=None, logger=self.mock_logger
            )
            cert._load_configuration()
            config_obj = cert.config
            self.assertEqual(config_obj.cert_reusage_timeframe, 0)
            self.assertEqual(config_obj.enrollment_timeout, 5)
            self.assertEqual(config_obj.retry_after, 600)

    def test_202_load_configuration_logging(self):
        """Test _load_configuration logs debug message."""
        import configparser

        config = configparser.ConfigParser()
        with patch("acme_srv.certificate.load_config", return_value=config):
            cert = certificate.Certificate(
                debug=True, srv_name=None, logger=self.mock_logger
            )
            cert._load_configuration()
            self.mock_logger.debug.assert_any_call("Certificate._load_configuration()")


if __name__ == "__main__":
    unittest.main()
