# -*- coding: utf-8 -*-
"""Unit tests for CertificateManager coordination layer"""
import os
import unittest
from unittest.mock import MagicMock, Mock, patch
import sys
# Add the parent directory to sys.path so we can import acme_srv
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from acme_srv.certificate_manager import CertificateManager


class TestCertificateManager(unittest.TestCase):
    def setUp(self):

        self.logger = MagicMock()
        self.err_msg_dic = {"serverinternal": "serverinternal"}

        # Repository mock with common methods
        self.repository = MagicMock()

        # Minimal config stub
        class Cfg:
            cert_operations_log = None
            tnauthlist_support = False
            cn2san_add = False
            cert_reusage_timeframe = 0

        self.config = Cfg()

        self.mgr = CertificateManager(
            debug=True,
            logger=self.logger,
            err_msg_dic=self.err_msg_dic,
            repository=self.repository,
            config=self.config,
        )

        # Replace business logic with a mock we control per test
        self.mgr.business_logic = MagicMock()

    # --- search_certificates ---
    def test_001_search_certificates_no_cert_field_skips_validation(self):
        self.repository.search_certificates.return_value = [
            {"name": "c1", "csr": "csr1"}
        ]

        result = self.mgr.search_certificates("name", "c1", ["name", "csr"])

        self.assertEqual(result["count"], 1)
        self.assertEqual(result["total_found"], 1)
        self.mgr.business_logic.validate_certificate_data.assert_not_called()

    def test_002_search_certificates_with_cert_filters_invalid(self):
        # two certs where first validates True and second False
        self.repository.search_certificates.return_value = [
            {"name": "c1", "cert": "pem1"},
            {"name": "c2", "cert": "pem2"},
        ]
        # Return True for pem1, False for pem2
        self.mgr.business_logic.validate_certificate_data.side_effect = [True, False]

        result = self.mgr.search_certificates("cert", "", ["name", "cert"])

        self.assertEqual(result["count"], 1)
        self.assertEqual(result["total_found"], 2)
        self.assertEqual(result["certificates"], [{"name": "c1", "cert": "pem1"}])

    def test_003_search_certificates_repo_returns_none_treated_as_error(self):
        self.repository.search_certificates.return_value = None
        result = self.mgr.search_certificates("name", "x")
        self.assertEqual(result["count"], 0)
        self.assertEqual(result["total_found"], 0)
        self.assertEqual(result["certificates"], None)
        self.assertIn("error", result)

    def test_004_search_certificates_repo_raises_exception(self):
        self.repository.search_certificates.side_effect = RuntimeError("boom")
        result = self.mgr.search_certificates("name", "x")
        self.assertEqual(result["count"], 0)
        self.assertEqual(result["total_found"], 0)
        self.assertEqual(result["certificates"], [])
        self.assertEqual(result["error"], "boom")

    # --- get_certificate_info ---
    def test_005_get_certificate_info_with_cert_enhances_info(self):
        self.mgr.business_logic.sanitize_certificate_name.return_value = "clean"
        self.repository.get_certificate_info.return_value = {
            "name": "clean",
            "cert": "pem",
            "cert_raw": "pemraw",
        }
        self.mgr.business_logic.extract_certificate_info.return_value = {
            "serial": "01",
            "cn": "example.com",
        }

        result = self.mgr.get_certificate_info(" dirty ")

        self.mgr.business_logic.sanitize_certificate_name.assert_called_once()
        self.mgr.business_logic.extract_certificate_info.assert_called_once_with("pemraw")
        self.assertEqual(result["serial"], "01")
        self.assertEqual(result["cn"], "example.com")

    def test_006_get_certificate_info_without_cert_no_enhancement(self):
        self.mgr.business_logic.sanitize_certificate_name.return_value = "clean"
        self.repository.get_certificate_info.return_value = {"name": "clean"}

        result = self.mgr.get_certificate_info("name")

        self.mgr.business_logic.extract_certificate_info.assert_not_called()
        self.assertEqual(result, {"name": "clean"})

    # --- store_certificate ---
    def test_007_store_certificate_only_csr_and_order(self):
        self.mgr.business_logic.sanitize_certificate_name.return_value = "n"
        self.repository.add_certificate.return_value = True

        ok, err = self.mgr.store_certificate("n", csr="csr1", order_name="ord1")

        self.assertTrue(ok)
        self.assertIsNone(err)
        self.repository.add_certificate.assert_called_once()
        stored = self.repository.add_certificate.call_args[0][0]
        self.assertEqual(stored["name"], "n")
        self.assertEqual(stored["csr"], "csr1")
        self.assertEqual(stored["order"], "ord1")

    def test_008_store_certificate_with_certificate_data_logs_when_enabled(self):
        # enable operations logging in config
        self.mgr.cert_operations_log = "json"
        self.mgr.business_logic.sanitize_certificate_name.return_value = "n"
        self.mgr.business_logic.calculate_certificate_dates.return_value = (1, 2)
        self.repository.add_certificate.return_value = True

        ok, err = self.mgr.store_certificate(
            "n", csr="csr1", order_name="ord1", certificate_data="pem"
        )

        self.assertTrue(ok)
        self.assertIsNone(err)
        stored = self.repository.add_certificate.call_args[0][0]
        self.assertEqual(stored["issue_uts"], 1)
        self.assertEqual(stored["expire_uts"], 2)
        self.repository.store_certificate_operation_log.assert_called_once_with(
            "n", "store", "success"
        )

    def test_009_store_certificate_failure_paths(self):
        self.mgr.business_logic.sanitize_certificate_name.return_value = "n"
        self.repository.add_certificate.return_value = False

        ok, err = self.mgr.store_certificate("n", csr="csr1")
        self.assertFalse(ok)
        self.assertEqual(err, "Database storage failed")

        self.repository.add_certificate.side_effect = RuntimeError("dberr")
        ok, err = self.mgr.store_certificate("n", csr="csr1")
        self.assertFalse(ok)
        self.assertEqual(err, "dberr")

    # --- update_certificate_dates ---
    def test_010_update_certificate_dates_specific_name_success(self):
        self.repository.get_certificate_info.return_value = {
            "name": "c1",
            "cert": "pem",
        }
        self.mgr.business_logic.calculate_certificate_dates.return_value = (10, 20)
        self.repository.update_certificate.return_value = True

        updated, errors = self.mgr.update_certificate_dates("c1")
        self.assertEqual((updated, errors), (1, 0))
        self.repository.update_certificate.assert_called_once()

    def test_011_update_certificate_dates_list_mixed_results(self):
        self.repository.search_certificates.return_value = [
            {"name": "a", "cert": "pemA"},
            {"name": "b", "cert": "pemB"},
            {"name": "c", "cert": None},
        ]
        # First update ok, second update fails
        self.mgr.business_logic.calculate_certificate_dates.side_effect = [
            (1, 2),
            (3, 4),
        ]
        self.repository.update_certificate.side_effect = [True, False]

        updated, errors = self.mgr.update_certificate_dates()
        self.assertEqual(updated, 1)
        self.assertEqual(errors, 1)  # one failed update, one skipped (no cert)

    def test_012_update_certificate_dates_calc_exception_counts_error(self):
        self.repository.search_certificates.return_value = [
            {"name": "a", "cert": "pemA"}
        ]
        self.mgr.business_logic.calculate_certificate_dates.side_effect = RuntimeError(
            "calc"
        )

        updated, errors = self.mgr.update_certificate_dates()
        self.assertEqual((updated, errors), (0, 1))

    def test_013_update_certificate_dates_top_level_exception(self):
        self.repository.search_certificates.side_effect = RuntimeError("boom")
        updated, errors = self.mgr.update_certificate_dates()
        self.assertEqual(updated, 0)
        self.assertEqual(errors, 1)

    def test_014_update_certificate_dates_no_certificates(self):
        self.repository.search_certificates.return_value = []
        updated, errors = self.mgr.update_certificate_dates()
        self.assertEqual((updated, errors), (0, 0))

    # --- cleanup_certificates ---
    @patch("acme_srv.certificate_manager.uts_now", return_value=1234)
    def test_015_cleanup_certificates_no_log(self, mock_now):
        self.repository.cleanup_certificates.return_value = (
            ["name", "expire_uts"],
            ["c1"],
        )
        fields, report = self.mgr.cleanup_certificates(timestamp=None, purge=False)
        self.assertEqual(fields, ["name", "expire_uts"])
        self.assertEqual(report, ["c1"])
        self.repository.store_certificate_operation_log.assert_not_called()

    def test_016_cleanup_certificates_logs_when_enabled(self):
        self.mgr.cert_operations_log = "text"
        self.repository.cleanup_certificates.return_value = (
            ["name"],
            ["c1", "c2"],
        )
        fields, report = self.mgr.cleanup_certificates(timestamp=999, purge=True)
        self.assertEqual((fields, report), (["name"], ["c1", "c2"]))
        self.repository.store_certificate_operation_log.assert_called_once_with(
            "batch_2", "purge", "processed_2_certificates"
        )

    def test_017_cleanup_certificates_exception_returns_empty(self):
        self.repository.cleanup_certificates.side_effect = RuntimeError("ops")
        fields, report = self.mgr.cleanup_certificates()
        self.assertEqual((fields, report), ([], []))

    # --- check_account_authorization ---
    @patch("acme_srv.certificate_manager.b64_url_recode", return_value="ENC")
    def test_018_check_account_authorization_authorized(self, mock_b64):
        self.repository.get_account_check_result.return_value = True
        res = self.mgr.check_account_authorization("acc", "cert")
        self.assertEqual(res["status"], "authorized")
        self.assertEqual(res["account"], "acc")
        self.repository.get_account_check_result.assert_called_once_with("acc", "ENC")

    @patch("acme_srv.certificate_manager.b64_url_recode", return_value="ENC")
    def test_019_check_account_authorization_unauthorized(self, mock_b64):
        self.repository.get_account_check_result.return_value = False
        res = self.mgr.check_account_authorization("acc", "cert")
        self.assertEqual(res["status"], "unauthorized")
        self.assertIn("error", res)

    @patch("acme_srv.certificate_manager.b64_url_recode", return_value="ENC")
    def test_020_check_account_authorization_error(self, mock_b64):
        self.repository.get_account_check_result.side_effect = RuntimeError("db")
        res = self.mgr.check_account_authorization("acc", "cert")
        self.assertEqual(res["status"], "error")
        self.assertEqual(res["error"], "db")

    # --- prepare_certificate_response ---
    def test_021_prepare_certificate_response_delegates_to_business_logic(self):
        self.mgr.business_logic.format_certificate_response.return_value = {
            "code": 200,
            "data": "pem",
        }
        res = self.mgr.prepare_certificate_response("pem", 200)
        self.mgr.business_logic.format_certificate_response.assert_called_once_with(
            "pem", 200
        )
        self.assertEqual(res["code"], 200)
        self.assertEqual(res["data"], "pem")

    # --- update_order_status ---
    def test_022_update_order_status_success_with_certificate(self):
        self.repository.update_order.return_value = True
        ok = self.mgr.update_order_status("o1", "valid", certificate_name="c1")
        self.assertTrue(ok)
        self.repository.update_order.assert_called_once_with(
            {"name": "o1", "status": "valid", "certificate": "c1"}
        )

    def test_023_update_order_status_failure_on_exception(self):
        self.repository.update_order.side_effect = RuntimeError("db")
        ok = self.mgr.update_order_status("o1", "processing")
        self.assertFalse(ok)

    # --- get_certificate_by_order ---
    def test_024_get_certificate_by_order_enhances_with_info(self):
        self.repository.get_certificate_by_order.return_value = {
            "cert": "pem",
        }
        self.mgr.business_logic.extract_certificate_info.return_value = {
            "serial": "01"
        }
        res = self.mgr.get_certificate_by_order("o1")
        self.mgr.business_logic.extract_certificate_info.assert_called_once_with("pem")
        self.assertEqual(res["serial"], "01")

    def test_025_get_certificate_by_order_exception_returns_empty(self):
        self.repository.get_certificate_by_order.side_effect = RuntimeError("db")
        res = self.mgr.get_certificate_by_order("o1")
        self.assertEqual(res, {})

    # --- validate_and_store_csr ---
    def test_026_validate_and_store_csr_validation_fails(self):
        self.mgr.business_logic.validate_csr.return_value = (400, "err", "detail")
        ok, cname = self.mgr.validate_and_store_csr("o1", "csr")
        self.assertFalse(ok)
        self.assertEqual(cname, "")

    def test_027_validate_and_store_csr_stores_and_returns_name(self):
        self.mgr.business_logic.validate_csr.return_value = (200, None, None)
        self.mgr.business_logic.generate_certificate_name.return_value = "cname"
        self.mgr.store_certificate = Mock(return_value=(True, None))

        ok, cname = self.mgr.validate_and_store_csr("o1", "csr")
        self.assertTrue(ok)
        self.assertEqual(cname, "cname")
        self.mgr.store_certificate.assert_called_once_with("cname", "csr", "o1")

    def test_028_validate_and_store_csr_store_fails_returns_name(self):
        self.mgr.business_logic.validate_csr.return_value = (200, None, None)
        self.mgr.business_logic.generate_certificate_name.return_value = "cname"
        self.mgr.store_certificate = Mock(return_value=(False, "dberr"))

        ok, cname = self.mgr.validate_and_store_csr("o1", "csr")
        self.assertFalse(ok)
        self.assertEqual(cname, "cname")

    def test_029_validate_and_store_csr_exception_returns_generated_name(self):
        self.mgr.business_logic.validate_csr.side_effect = RuntimeError("oops")
        self.mgr.business_logic.generate_certificate_name.return_value = "cname"

        ok, cname = self.mgr.validate_and_store_csr("o1", "csr")
        self.assertFalse(ok)
        self.assertEqual(cname, "cname")

    # --- __init__ defaults coverage (no config provided) ---
    def test_030_init_without_config_uses_defaults(self):
        repo = MagicMock()
        mgr = CertificateManager(
            debug=True, logger=self.logger, err_msg_dic=self.err_msg_dic, repository=repo, config=None
        )
        # When config is None, defaults should be applied
        self.assertIsNone(mgr.cert_operations_log)
        self.assertFalse(mgr.tnauthlist_support)
        # And business_logic should still be constructed
        self.assertIsNotNone(mgr.business_logic)


if __name__ == "__main__":
    unittest.main()
