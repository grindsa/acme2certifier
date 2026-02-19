# -*- coding: utf-8 -*-
"""Unit tests for DatabaseCertificateRepository abstraction over DBstore"""

import os
import unittest
from unittest.mock import MagicMock
import sys

# Add the parent directory to sys.path so we can import acme_srv
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from acme_srv.certificate_repository import DatabaseCertificateRepository


class TestCertificateRepository(unittest.TestCase):
    def setUp(self):
        self.logger = MagicMock()
        self.db = MagicMock()
        self.repo = DatabaseCertificateRepository(self.db, self.logger)

    # --- search_certificates ---
    def test_001_search_no_vlist_success(self):
        self.db.certificates_search.return_value = [{"name": "c1"}]
        res = self.repo.search_certificates("name", "c1")
        self.db.certificates_search.assert_called_once_with("name", "c1")
        self.assertEqual(res, [{"name": "c1"}])

    def test_002_search_with_vlist_success(self):
        self.db.certificates_search.return_value = []
        res = self.repo.search_certificates("name", "c1", ["name", "csr"])
        self.db.certificates_search.assert_called_once_with(
            "name", "c1", ["name", "csr"]
        )
        self.assertEqual(res, [])

    def test_003_search_exception_returns_none(self):
        self.db.certificates_search.side_effect = RuntimeError("db")
        res = self.repo.search_certificates("name", "c1")
        self.assertIsNone(res)
        self.logger.critical.assert_called()

    # --- get_certificate_info ---
    def test_004_get_certificate_info_success(self):
        self.db.certificate_lookup.return_value = {"name": "c1", "cert": "pem"}
        res = self.repo.get_certificate_info("c1")
        self.db.certificate_lookup.assert_called_once()
        self.assertEqual(res["name"], "c1")

    def test_005_get_certificate_info_exception_returns_empty(self):
        self.db.certificate_lookup.side_effect = RuntimeError("db")
        res = self.repo.get_certificate_info("c1")
        self.assertEqual(res, {})

    def test_006_get_certificate_info_none_from_db_passes_through(self):
        self.db.certificate_lookup.side_effect = None
        self.db.certificate_lookup.return_value = None
        res = self.repo.get_certificate_info("c1")
        self.assertIsNone(res)

    # --- add / update / delete (name variant) ---
    def test_007_add_certificate_success(self):
        self.db.certificate_add.return_value = True
        ok = self.repo.add_certificate({"name": "c1"})
        self.assertTrue(ok)

    def test_008_add_certificate_exception_returns_false(self):
        self.db.certificate_add.side_effect = RuntimeError("db")
        ok = self.repo.add_certificate({"name": "c1"})
        self.assertFalse(ok)

    def test_009_delete_certificate_success(self):
        self.db.certificate_delete.return_value = True
        ok = self.repo.delete_certificate("c1")
        self.assertTrue(ok)

    def test_010_delete_certificate_exception_returns_false(self):
        self.db.certificate_delete.side_effect = RuntimeError("db")
        ok = self.repo.delete_certificate("c1")
        self.assertFalse(ok)

    # --- account check / update order (middle methods) ---
    def test_011_get_account_check_result_success(self):
        self.db.certificate_account_check.return_value = {"ok": True}
        res = self.repo.get_account_check_result("acc", "cert")
        self.assertEqual(res, {"ok": True})

    def test_012_get_account_check_result_exception_returns_none(self):
        self.db.certificate_account_check.side_effect = RuntimeError("db")
        res = self.repo.get_account_check_result("acc", "cert")
        self.assertIsNone(res)

    def test_013_update_order_success_true(self):
        self.db.order_update.return_value = (
            None  # method has no return, repo returns True
        )
        ok = self.repo.update_order({"name": "o1", "status": "valid"})
        self.assertTrue(ok)

    def test_014_update_order_exception_returns_false(self):
        self.db.order_update.side_effect = RuntimeError("db")
        ok = self.repo.update_order({"name": "o1", "status": "valid"})
        self.assertFalse(ok)

    # --- get_orders_by_account ---
    def test_015_get_orders_by_account_success_list(self):
        self.db.orders_search.return_value = [{"name": "o1"}]
        res = self.repo.get_orders_by_account("acc")
        self.assertEqual(res, [{"name": "o1"}])

    def test_016_get_orders_by_account_empty_to_list(self):
        self.db.orders_search.return_value = None
        res = self.repo.get_orders_by_account("acc")
        self.assertEqual(res, [])

    def test_017_get_orders_by_account_exception_returns_empty(self):
        self.db.orders_search.side_effect = RuntimeError("db")
        res = self.repo.get_orders_by_account("acc")
        self.assertEqual(res, [])

    # --- get_certificate_by_order ---
    def test_018_get_certificate_by_order_success(self):
        self.db.certificate_lookup.return_value = {"name": "c1"}
        res = self.repo.get_certificate_by_order("o1")
        self.assertEqual(res, {"name": "c1"})

    def test_019_get_certificate_by_order_exception_returns_empty(self):
        self.db.certificate_lookup.side_effect = RuntimeError("db")
        res = self.repo.get_certificate_by_order("o1")
        self.assertEqual(res, {})

    # --- store_certificate_operation_log ---
    def test_020_store_certificate_operation_log_success(self):
        self.db.cahandler_add.return_value = True
        ok = self.repo.store_certificate_operation_log("c1", "store", "success")
        self.assertTrue(ok)
        self.db.cahandler_add.assert_called_once()

    def test_021_store_certificate_operation_log_exception_returns_false(self):
        self.db.cahandler_add.side_effect = RuntimeError("db")
        ok = self.repo.store_certificate_operation_log("c1", "store", "success")
        self.assertFalse(ok)

    # --- bottom API (compatibility) ---
    def test_022_certificate_account_check_success(self):
        self.db.certificate_account_check.return_value = True
        res = self.repo.certificate_account_check("acc", "cert")
        self.assertTrue(res)

    def test_023_certificate_account_check_exception_returns_none(self):
        self.db.certificate_account_check.side_effect = RuntimeError("db")
        res = self.repo.certificate_account_check("acc", "cert")
        self.assertIsNone(res)

    def test_024_certificate_lookup_with_vlist_success(self):
        self.db.certificate_lookup.return_value = {"name": "c1"}
        res = self.repo.certificate_lookup("name", "c1", ["name"])
        self.db.certificate_lookup.assert_called_once_with("name", "c1", ["name"])
        self.assertEqual(res, {"name": "c1"})

    def test_025_certificate_lookup_without_vlist_success(self):
        self.db.certificate_lookup.reset_mock()
        self.db.certificate_lookup.return_value = {"name": "c2"}
        res = self.repo.certificate_lookup("name", "c2")
        self.db.certificate_lookup.assert_called_once_with("name", "c2")
        self.assertEqual(res, {"name": "c2"})

    def test_026_certificate_lookup_exception_returns_empty(self):
        self.db.certificate_lookup.side_effect = RuntimeError("db")
        res = self.repo.certificate_lookup("name", "c1")
        self.assertEqual(res, {})

    def test_027_certificate_add_success_returns_id(self):
        self.db.certificate_add.return_value = 123
        res = self.repo.certificate_add({"name": "c1"})
        self.assertEqual(res, 123)

    def test_028_certificate_add_exception_returns_none(self):
        self.db.certificate_add.side_effect = RuntimeError("db")
        res = self.repo.certificate_add({"name": "c1"})
        self.assertIsNone(res)

    def test_029_certificate_delete_success(self):
        self.db.certificate_delete.return_value = True
        ok = self.repo.certificate_delete("name", "c1")
        self.assertTrue(ok)

    def test_030_certificate_delete_exception_returns_false(self):
        self.db.certificate_delete.side_effect = RuntimeError("db")
        ok = self.repo.certificate_delete("name", "c1")
        self.assertFalse(ok)

    def test_031_order_lookup_with_vlist_success(self):
        self.db.order_lookup.return_value = {"name": "o1"}
        res = self.repo.order_lookup("name", "o1", ["name"])
        self.db.order_lookup.assert_called_once_with("name", "o1", ["name"])
        self.assertEqual(res, {"name": "o1"})

    def test_032_order_lookup_without_vlist_success(self):
        self.db.order_lookup.reset_mock()
        self.db.order_lookup.return_value = {"name": "o2"}
        res = self.repo.order_lookup("name", "o2")
        self.db.order_lookup.assert_called_once_with("name", "o2")
        self.assertEqual(res, {"name": "o2"})

    def test_033_order_lookup_exception_returns_empty(self):
        self.db.order_lookup.side_effect = RuntimeError("db")
        res = self.repo.order_lookup("name", "o1")
        self.assertEqual(res, {})

    def test_034_order_update_success(self):
        self.db.order_update.return_value = True
        ok = self.repo.order_update({"name": "o1"})
        self.assertTrue(ok)

    def test_035_order_update_exception_returns_false(self):
        self.db.order_update.side_effect = RuntimeError("db")
        ok = self.repo.order_update({"name": "o1"})
        self.assertFalse(ok)

    def test_036_search_expired_certificates_returns_results(self):
        # Simulate dbstore returning a list of expired certificates
        certs = [
            {"name": "expired1", "expire_uts": 100, "cert": "pem1"},
            {"name": "expired2", "expire_uts": 200, "cert": "pem2"},
        ]
        self.db.certificates_search.return_value = certs
        result = self.repo.search_expired_certificates(
            123456, ["name", "expire_uts", "cert"]
        )
        self.db.certificates_search.assert_called_once_with(
            "expire_uts", 123456, ["name", "expire_uts", "cert"], "<="
        )
        self.assertEqual(result, certs)

    def test_037_search_expired_certificates_returns_empty(self):
        # Simulate dbstore returning an empty list
        self.db.certificates_search.return_value = []
        result = self.repo.search_expired_certificates(
            123456, ["name", "expire_uts", "cert"]
        )
        self.db.certificates_search.assert_called_once()
        self.assertEqual(result, [])

    def test_038_search_expired_certificates_raises_exception(self):
        # Simulate dbstore raising an exception
        self.db.certificates_search.side_effect = RuntimeError("db error")
        result = self.repo.search_expired_certificates(
            123456, ["name", "expire_uts", "cert"]
        )
        self.assertEqual(result, [])
        self.logger.critical.assert_called()


if __name__ == "__main__":
    unittest.main()
