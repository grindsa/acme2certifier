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
        self.mgr.business_logic.extract_certificate_info.assert_called_once_with(
            "pemraw"
        )
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

    def test_008_store_certificate_with_header_info(self):
        # Ensure header_info is stored and logger.debug is called
        self.mgr.business_logic.sanitize_certificate_name.return_value = "certname"
        self.repository.add_certificate.return_value = True
        header_info = "header details"
        ok, err = self.mgr.store_certificate(
            "certname", csr="csr1", header_info=header_info
        )
        self.assertTrue(ok)
        self.assertIsNone(err)
        stored = self.repository.add_certificate.call_args[0][0]
        self.assertEqual(stored["header_info"], header_info)
        self.logger.debug.assert_any_call(
            "CertificateManager.store_certificate(): store header_info with certificate"
        )

    def test_009_store_certificate_with_certificate_data_logs_when_enabled(self):
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

    def test_010_store_certificate_failure_paths(self):
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
    def test_011_update_certificate_dates_specific_name_success(self):
        self.repository.get_certificate_info.return_value = {
            "name": "c1",
            "cert": "pem",
        }
        self.mgr.business_logic.calculate_certificate_dates.return_value = (10, 20)
        self.repository.update_certificate.return_value = True

        updated, errors = self.mgr.update_certificate_dates("c1")
        self.assertEqual((updated, errors), (1, 0))
        self.repository.update_certificate.assert_called_once()

    def test_012_update_certificate_dates_list_mixed_results(self):
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

    def test_013_update_certificate_dates_calc_exception_counts_error(self):
        self.repository.search_certificates.return_value = [
            {"name": "a", "cert": "pemA"}
        ]
        self.mgr.business_logic.calculate_certificate_dates.side_effect = RuntimeError(
            "calc"
        )

        updated, errors = self.mgr.update_certificate_dates()
        self.assertEqual((updated, errors), (0, 1))

    def test_014_update_certificate_dates_top_level_exception(self):
        self.repository.search_certificates.side_effect = RuntimeError("boom")
        updated, errors = self.mgr.update_certificate_dates()
        self.assertEqual(updated, 0)
        self.assertEqual(errors, 1)

    def test_015_update_certificate_dates_no_certificates(self):
        self.repository.search_certificates.return_value = []
        updated, errors = self.mgr.update_certificate_dates()
        self.assertEqual((updated, errors), (0, 0))

    # --- cleanup_certificates ---

    def test_016_cleanup_certificates_exception_returns_empty(self):
        self.repository.search_expired_certificates.side_effect = RuntimeError("ops")
        fields, report = self.mgr.cleanup_certificates()
        self.assertEqual((fields, report), ([], []))

    # --- check_account_authorization ---
    @patch("acme_srv.certificate_manager.b64_url_recode", return_value="ENC")
    def test_017_check_account_authorization_authorized(self, mock_b64):
        self.repository.get_account_check_result.return_value = True
        res = self.mgr.check_account_authorization("acc", "cert")
        self.assertEqual(res["status"], "authorized")
        self.assertEqual(res["account"], "acc")
        self.repository.get_account_check_result.assert_called_once_with("acc", "ENC")

    @patch("acme_srv.certificate_manager.b64_url_recode", return_value="ENC")
    def test_018_check_account_authorization_unauthorized(self, mock_b64):
        self.repository.get_account_check_result.return_value = False
        res = self.mgr.check_account_authorization("acc", "cert")
        self.assertEqual(res["status"], "unauthorized")
        self.assertIn("error", res)

    @patch("acme_srv.certificate_manager.b64_url_recode", return_value="ENC")
    def test_019_check_account_authorization_error(self, mock_b64):
        self.repository.get_account_check_result.side_effect = RuntimeError("db")
        res = self.mgr.check_account_authorization("acc", "cert")
        self.assertEqual(res["status"], "error")
        self.assertEqual(res["error"], "db")

    # --- prepare_certificate_response ---
    def test_020_prepare_certificate_response_delegates_to_business_logic(self):
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
    def test_021_update_order_status_success_with_certificate(self):
        self.repository.update_order.return_value = True
        ok = self.mgr.update_order_status("o1", "valid", certificate_name="c1")
        self.assertTrue(ok)
        self.repository.update_order.assert_called_once_with(
            {"name": "o1", "status": "valid", "certificate": "c1"}
        )

    def test_022_update_order_status_failure_on_exception(self):
        self.repository.update_order.side_effect = RuntimeError("db")
        ok = self.mgr.update_order_status("o1", "processing")
        self.assertFalse(ok)

    # --- get_certificate_by_order ---
    def test_023_get_certificate_by_order_enhances_with_info(self):
        self.repository.get_certificate_by_order.return_value = {
            "cert": "pem",
        }
        self.mgr.business_logic.extract_certificate_info.return_value = {"serial": "01"}
        res = self.mgr.get_certificate_by_order("o1")
        self.mgr.business_logic.extract_certificate_info.assert_called_once_with("pem")
        self.assertEqual(res["serial"], "01")

    def test_024_get_certificate_by_order_exception_returns_empty(self):
        self.repository.get_certificate_by_order.side_effect = RuntimeError("db")
        res = self.mgr.get_certificate_by_order("o1")
        self.assertEqual(res, {})

    # --- validate_and_store_csr ---
    def test_025_validate_and_store_csr_validation_fails(self):
        self.mgr.business_logic.validate_csr.return_value = (400, "err", "detail")
        ok, cname = self.mgr.validate_and_store_csr("o1", "csr")
        self.assertFalse(ok)
        self.assertEqual(cname, "")

    def test_026_validate_and_store_csr_stores_and_returns_name(self):
        self.mgr.business_logic.validate_csr.return_value = (200, None, None)
        self.mgr.business_logic.generate_certificate_name.return_value = "cname"
        self.mgr.store_certificate = Mock(return_value=(True, None))

        ok, cname = self.mgr.validate_and_store_csr("o1", "csr")
        self.assertTrue(ok)
        self.assertEqual(cname, "cname")
        self.mgr.store_certificate.assert_called_once_with(
            "cname", "csr", "o1", header_info=None
        )

    def test_027_validate_and_store_csr_stores_with_headerinfo_and_returns_name(self):
        self.mgr.business_logic.validate_csr.return_value = (200, None, None)
        self.mgr.business_logic.generate_certificate_name.return_value = "cname"
        self.mgr.store_certificate = Mock(return_value=(True, None))

        ok, cname = self.mgr.validate_and_store_csr(
            "o1", "csr", header_info="headerdata"
        )
        self.assertTrue(ok)
        self.assertEqual(cname, "cname")
        self.mgr.store_certificate.assert_called_once_with(
            "cname", "csr", "o1", header_info="headerdata"
        )

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
            debug=True,
            logger=self.logger,
            err_msg_dic=self.err_msg_dic,
            repository=repo,
            config=None,
        )
        # When config is None, defaults should be applied
        self.assertIsNone(mgr.cert_operations_log)
        self.assertFalse(mgr.tnauthlist_support)
        # And business_logic should still be constructed
        self.assertIsNotNone(mgr.business_logic)

    # --- cleanup_certificates() ---
    def test_031_cleanup_certificates_purge_and_mark(self):
        from acme_srv.helper import uts_to_date_utc

        # Setup expired certificates
        certs = [
            {
                "name": "cert1",
                "expire_uts": 100,
                "issue_uts": 50,
                "cert": "valid",
                "cert_raw": "raw1",
            },
            {
                "name": "cert2",
                "expire_uts": 0,
                "issue_uts": 50,
                "cert": "valid",
                "cert_raw": "raw2",
                "csr": "csr",
                "created_at": "2020-01-01T00:00:00Z",
            },
            {
                "name": "cert3",
                "expire_uts": 0,
                "issue_uts": 50,
                "cert": "valid",
                "cert_raw": None,
                "csr": None,
            },
            {
                "name": "cert4",
                "expire_uts": 0,
                "issue_uts": 50,
                "cert": "removed by cleanup",
                "cert_raw": "raw4",
            },
        ]
        self.repository.search_expired_certificates.return_value = certs
        self.repository.delete_certificate = Mock()
        self.repository.add_certificate = Mock()
        # Purge mode
        _, report = self.mgr.cleanup_certificates(timestamp=200, purge=True)
        self.assertIn("cert1", report)
        self.assertIn("cert4", report)
        self.repository.delete_certificate.assert_any_call("cert1")
        self.repository.delete_certificate.assert_any_call("cert4")
        # Mark mode
        self.repository.delete_certificate.reset_mock()
        self.repository.add_certificate.reset_mock()
        ts = 200
        expected_cert = {
            "name": "cert1",
            "expire_uts": 100,
            "issue_uts": 50,
            "cert": f"removed by certificates.cleanup() on {uts_to_date_utc(ts)}",
            "cert_raw": "raw1",
        }
        _, report2 = self.mgr.cleanup_certificates(timestamp=ts, purge=False)
        self.assertIn("cert1", report2)
        self.repository.add_certificate.assert_any_call(expected_cert)

    # --- _check_invalidation() ---
    def test_032_check_invalidation_various_cases(self):
        # cert with 'removed by' in cert
        cert = {"name": "c1", "cert": "removed by cleanup", "expire_uts": 0}
        self.assertTrue(self.mgr._check_invalidation(cert, 100, purge=True))
        # cert with expire_uts and not removed
        cert2 = {"name": "c2", "cert": "valid", "expire_uts": 0, "cert_raw": "raw"}
        with patch.object(self.mgr, "_get_expiredate", return_value=True) as m:
            self.assertTrue(self.mgr._check_invalidation(cert2, 100, purge=False))
            m.assert_called_once()
        # cert with no expire_uts
        cert3 = {"name": "c3", "cert": "valid"}
        self.assertFalse(self.mgr._check_invalidation(cert3, 100, purge=False))
        # cert with no name
        cert4 = {"cert": "valid"}
        self.assertTrue(self.mgr._check_invalidation(cert4, 100, purge=False))

    # --- _assume_expirydate() ---
    def test_033_assume_expirydate_various_cases(self):
        # CSR present, created_at older than 2 weeks
        cert = {"csr": "csr", "created_at": "1970-01-01T00:00:00Z"}
        # timestamp = 200, so timestamp - (14*86400) = -1209600
        # Only values between 0 and -1209600 will set to_be_cleared True, which is impossible
        # So, test with a timestamp that makes the window positive
        # Let's use timestamp = 1210000, so window is 1210000 - 1209600 = 400
        # created_at_uts = 100, so 0 < 100 < 400 is True
        with patch("acme_srv.certificate_manager.date_to_uts_utc", return_value=100):
            self.assertTrue(self.mgr._assume_expirydate(cert, 1210000, False))
        # created_at_uts = 500, so 0 < 500 < 400 is False
        with patch("acme_srv.certificate_manager.date_to_uts_utc", return_value=500):
            self.assertFalse(self.mgr._assume_expirydate(cert, 1210000, False))
        # No CSR, no cert
        cert2 = {"csr": None}
        self.assertTrue(self.mgr._assume_expirydate(cert2, 200, False))

    # --- _get_expiredate() ---
    def test_034_get_expiredate_various_cases(self):
        # expire_uts == 0, cert_raw present, expire_uts < timestamp
        cert = {"expire_uts": 0, "cert_raw": "raw"}
        with patch(
            "acme_srv.certificate_manager.cert_dates_get", return_value=(10, 50)
        ):
            self.assertTrue(self.mgr._get_expiredate(cert, 100, False))
            self.assertEqual(cert["issue_uts"], 10)
            self.assertEqual(cert["expire_uts"], 50)
        # expire_uts == 0, cert_raw missing, fallback to _assume_expirydate
        cert2 = {"expire_uts": 0}
        with patch.object(self.mgr, "_assume_expirydate", return_value=True) as m:
            self.assertTrue(self.mgr._get_expiredate(cert2, 100, False))
            m.assert_called_once()
        # expire_uts != 0
        cert3 = {"expire_uts": 10}
        self.assertTrue(self.mgr._get_expiredate(cert3, 100, False))

    def test_035_assume_expirydate_csr_present_but_no_created_at(self):
        # Covers the branch where 'csr' is present but 'created_at' is missing
        cert = {"csr": "csr"}
        # to_be_cleared should remain False
        self.assertFalse(self.mgr._assume_expirydate(cert, 200, False))

    def test_036_cleanup_certificates_repository_exception(self):
        # Covers the exception branch when repository.search_expired_certificates raises
        self.repository.search_expired_certificates.side_effect = RuntimeError("fail")
        fields, report = self.mgr.cleanup_certificates(timestamp=123, purge=False)
        self.assertEqual(fields, [])
        self.assertEqual(report, [])

    def test_037_cleanup_certificates_loop_body_exception(self):
        # Covers the exception branch inside the for-loop
        # The first cert will cause an exception in _check_invalidation
        class DummyRepo:
            def search_expired_certificates(self, timestamp, field_list):
                return [{"name": "badcert"}]

        mgr = CertificateManager(
            debug=True,
            logger=self.logger,
            err_msg_dic=self.err_msg_dic,
            repository=DummyRepo(),
            config=self.config,
        )
        # Patch _check_invalidation to raise
        mgr._check_invalidation = Mock(side_effect=RuntimeError("badcert"))
        fields, report = mgr.cleanup_certificates(timestamp=123, purge=False)
        self.assertIn("name", fields)
        self.assertEqual(report, [])


if __name__ == "__main__":
    unittest.main()
