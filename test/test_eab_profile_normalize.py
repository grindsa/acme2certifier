#!/usr/bin/python
# -*- coding: utf-8 -*-
"""unittests for EAB profile section-key normalization"""

# pylint: disable=C0415
import sys
import unittest

sys.path.insert(0, ".")
sys.path.insert(1, "..")


class TestEabProfileNormalize(unittest.TestCase):
    """test eab_profile_entry_normalize / eab_profiles_normalize"""

    def setUp(self):
        from acme2certifier.acme_srv.helpers.eab_profile import (
            eab_profile_entry_normalize,
            eab_profile_kid_entry_get,
            eab_profiles_normalize,
        )

        self.normalize_entry = eab_profile_entry_normalize
        self.normalize_profiles = eab_profiles_normalize
        self.kid_entry_get = eab_profile_kid_entry_get

    def test_001_order_section_case(self):
        """Order section title is lowercased"""
        result = self.normalize_entry(
            {
                "hmac": "mac",
                "Order": {"allowed_domainlist": ["www.example.com"]},
            }
        )
        self.assertIn("order", result)
        self.assertNotIn("Order", result)
        self.assertEqual(result["order"]["allowed_domainlist"], ["www.example.com"])

    def test_002_cahandler_section_case(self):
        """Cahandler section title is lowercased"""
        result = self.normalize_entry({"HMAC": "mac", "Cahandler": {"ca_name": "pki"}})
        self.assertEqual(result["hmac"], "mac")
        self.assertEqual(result["cahandler"]["ca_name"], "pki")

    def test_003_nested_keys_unchanged(self):
        """Nested keys inside sections keep their case"""
        result = self.normalize_entry(
            {"hmac": "mac", "order": {"Allowed_Domainlist": ["a.com"]}}
        )
        self.assertIn("Allowed_Domainlist", result["order"])

    def test_004_profiles_map(self):
        """Kid ids stay as-is; entries are normalized"""
        result = self.normalize_profiles(
            {
                "keyid_01": {
                    "hmac": "mac",
                    "Order": {"allowed_domainlist": ["www.example.com"]},
                }
            }
        )
        self.assertIn("keyid_01", result)
        self.assertIn("order", result["keyid_01"])

    def test_005_json_string_entry(self):
        """JSON string profile entry is parsed and normalized"""
        result = self.normalize_entry(
            '{"hmac":"mac","Challenge":{"http_01_support":"False"}}'
        )
        self.assertEqual(result["hmac"], "mac")
        self.assertEqual(result["challenge"]["http_01_support"], "False")

    def test_006_kid_entry_get_on_apply(self):
        """Apply helper lowercases section titles for one kid"""
        profiles = {
            "keyid_01": {
                "hmac": "mac",
                "Order": {"allowed_domainlist": ["www.example.com"]},
            }
        }
        entry = self.kid_entry_get(profiles, "keyid_01")
        self.assertIn("order", entry)
        self.assertNotIn("Order", entry)
        self.assertEqual(self.kid_entry_get(profiles, "missing"), {})


if __name__ == "__main__":
    unittest.main()
