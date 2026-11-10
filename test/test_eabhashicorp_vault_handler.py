#!/usr/bin/python
# -*- coding: utf-8 -*-
"""unittests for hashicorp_vault_handler"""

# pylint: disable=C0415, W0212
import configparser
import os
import sys
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, ".")
sys.path.insert(1, "..")


class TestEABHashicorpVaultHandler(unittest.TestCase):
    """test class for hashicorp_vault_handler"""

    def setUp(self):
        """setup unit test"""
        import logging

        logging.basicConfig(level=logging.CRITICAL)
        self.logger = logging.getLogger("test_a2c")
        from acme2certifier.eabhandlers.hashicorp_vault_handler import EABhandler

        self.eabhandler = EABhandler(self.logger)
        self.dir_path = os.path.dirname(os.path.realpath(__file__))

    def test_001_default(self):
        """default test which always passes"""
        self.assertEqual("foo", "foo")

    @patch("acme2certifier.eabhandlers.hashicorp_vault_handler.EABhandler._config_load")
    def test_002_enter(self, mock_config_load):
        """test enter calls config load"""
        mock_config_load.return_value = None
        self.eabhandler.__enter__()
        self.assertTrue(mock_config_load.called)

    @patch("acme2certifier.eabhandlers.hashicorp_vault_handler.config_proxy_load")
    @patch("acme2certifier.eabhandlers.hashicorp_vault_handler.load_config")
    def test_003_config_load_empty(self, mock_load_config, mock_proxy):
        """test _config_load with empty config"""
        mock_load_config.return_value = configparser.ConfigParser()
        mock_proxy.return_value = {}
        self.eabhandler._config_load()
        self.assertIsNone(self.eabhandler.vault_url)
        self.assertIsNone(self.eabhandler.vault_token)
        self.assertEqual(self.eabhandler.vault_mount, "secret")
        self.assertEqual(self.eabhandler.vault_prefix, "acme/eab")
        self.assertEqual(self.eabhandler.vault_secret_key, "value")

    @patch("acme2certifier.eabhandlers.hashicorp_vault_handler.config_proxy_load")
    @patch("acme2certifier.eabhandlers.hashicorp_vault_handler.load_config")
    def test_004_config_load_values(self, mock_load_config, mock_proxy):
        """test _config_load with EABhandler values"""
        parser = configparser.ConfigParser()
        parser["EABhandler"] = {
            "vault_url": "http://vault:8200",
            "vault_mount": "kv",
            "vault_prefix": "acme/eab",
            "vault_token": "s.token",
            "vault_secret_key": "payload",
            "request_timeout": "30",
            "cache_ttl": "10",
        }
        mock_load_config.return_value = parser
        mock_proxy.return_value = {"http": "proxy"}
        self.eabhandler._config_load()
        self.assertEqual(self.eabhandler.vault_url, "http://vault:8200")
        self.assertEqual(self.eabhandler.vault_mount, "kv")
        self.assertEqual(self.eabhandler.vault_prefix, "acme/eab")
        self.assertEqual(self.eabhandler.vault_token, "s.token")
        self.assertEqual(self.eabhandler.vault_secret_key, "payload")
        self.assertEqual(self.eabhandler.request_timeout, 30)
        self.assertEqual(self.eabhandler.cache_ttl, 10)
        self.assertEqual(self.eabhandler.proxy, {"http": "proxy"})

    @patch.dict(os.environ, {"VAULT_TOKEN": "from-env"}, clear=False)
    @patch("acme2certifier.eabhandlers.hashicorp_vault_handler.config_proxy_load")
    @patch("acme2certifier.eabhandlers.hashicorp_vault_handler.load_config")
    def test_005_config_load_token_variable(self, mock_load_config, mock_proxy):
        """test vault_token_variable from environment"""
        parser = configparser.ConfigParser()
        parser["EABhandler"] = {
            "vault_url": "http://vault:8200",
            "vault_token_variable": "VAULT_TOKEN",
        }
        mock_load_config.return_value = parser
        mock_proxy.return_value = {}
        self.eabhandler._config_load()
        self.assertEqual(self.eabhandler.vault_token, "from-env")

    def test_006_secret_url(self):
        """test KV v2 data URL construction"""
        self.eabhandler.vault_url = "http://vault:8200/"
        self.eabhandler.vault_mount = "secret"
        self.eabhandler.vault_prefix = "/acme/eab/"
        self.assertEqual(
            self.eabhandler._secret_url("keyid_00"),
            "http://vault:8200/v1/secret/data/acme/eab/keyid_00",
        )

    def test_006b_secret_url_encodes_metacharacters(self):
        """L10: kid is one encoded segment (no / or .. traversal)"""
        self.eabhandler.vault_url = "http://vault:8200"
        self.eabhandler.vault_mount = "secret"
        self.eabhandler.vault_prefix = "acme/eab"
        url = self.eabhandler._secret_url("../sys")
        # Entire kid is one segment; dots and slash encoded
        self.assertEqual(
            url,
            "http://vault:8200/v1/secret/data/acme/eab/%2E%2E%2Fsys",
        )
        self.assertNotIn("/../", url)
        url_slash = self.eabhandler._secret_url("a/b")
        self.assertEqual(
            url_slash,
            "http://vault:8200/v1/secret/data/acme/eab/a%2Fb",
        )
        url_q = self.eabhandler._secret_url("a?x=1")
        self.assertIn("a%3Fx%3D1", url_q)
        self.assertNotIn("?", url_q.split("/v1/", 1)[1])

    def test_006c_kid_is_safe_allowlist(self):
        """L10: only base64url-like kids are accepted for Vault lookup"""
        self.assertTrue(self.eabhandler._kid_is_safe("keyid_00"))
        self.assertTrue(self.eabhandler._kid_is_safe("abc-DEF_012"))
        self.assertFalse(self.eabhandler._kid_is_safe(""))
        self.assertFalse(self.eabhandler._kid_is_safe("../secret"))
        self.assertFalse(self.eabhandler._kid_is_safe("a/b"))
        self.assertFalse(self.eabhandler._kid_is_safe("a?b"))
        self.assertFalse(self.eabhandler._kid_is_safe(None))

    @patch(
        "acme2certifier.eabhandlers.hashicorp_vault_handler.EABhandler._api_get"
    )
    def test_006d_kid_secret_get_rejects_unsafe_kid(self, mock_api):
        """L10: unsafe kid never hits Vault"""
        self.eabhandler.vault_url = "http://vault:8200"
        self.eabhandler.vault_token = "t"
        with self.assertLogs("test_a2c", level="WARNING") as lcm:
            self.assertIsNone(self.eabhandler._kid_secret_get("../sys"))
        mock_api.assert_not_called()
        self.assertTrue(
            any("Rejected unsafe EAB kid" in line for line in lcm.output)
        )

    def test_007_list_url(self):
        """test KV v2 metadata list URL construction"""
        self.eabhandler.vault_url = "http://vault:8200"
        self.eabhandler.vault_mount = "secret"
        self.eabhandler.vault_prefix = "acme/eab"
        self.assertEqual(
            self.eabhandler._list_url(),
            "http://vault:8200/v1/secret/metadata/acme/eab?list=true",
        )

    def test_008_payload_normalize_string(self):
        """string payload becomes hmac-only profile"""
        self.assertEqual(
            self.eabhandler._payload_normalize("bWFjXzAw"),
            {"hmac": "bWFjXzAw"},
        )

    def test_009_payload_normalize_profile_object(self):
        """object with hmac is kept as profile"""
        payload = {
            "hmac": "bWFj",
            "cahandler": {"allowed_domainlist": ["example.com"]},
        }
        self.assertEqual(self.eabhandler._payload_normalize(payload), payload)

    def test_010_payload_normalize_value_string(self):
        """value field with string is hmac-only"""
        self.assertEqual(
            self.eabhandler._payload_normalize({"value": "bWFjXzAw"}),
            {"hmac": "bWFjXzAw"},
        )

    def test_011_payload_normalize_value_json_string(self):
        """value field with JSON string becomes profile"""
        raw = '{"hmac": "bWFj", "cahandler": {"ca_name": "pki"}}'
        result = self.eabhandler._payload_normalize({"value": raw})
        self.assertEqual(result["hmac"], "bWFj")
        self.assertEqual(result["cahandler"]["ca_name"], "pki")

    def test_012_payload_normalize_value_nested_object(self):
        """value field with nested object becomes profile"""
        payload = {"value": {"hmac": "nested", "challenge": {"x": "1"}}}
        result = self.eabhandler._payload_normalize(payload)
        self.assertEqual(result["hmac"], "nested")
        self.assertEqual(result["challenge"]["x"], "1")

    def test_013_payload_normalize_keeps_section_case(self):
        """Payload parse keeps section casing; apply-paths lowercase separately"""
        payload = {
            "hmac": "mac",
            "Order": {"allowed_domainlist": ["www.example.com"]},
        }
        result = self.eabhandler._payload_normalize(payload)
        self.assertEqual(result["hmac"], "mac")
        self.assertIn("Order", result)

    def test_014_payload_normalize_single_string_field(self):
        """single string-valued field without value/hmac key"""
        self.assertEqual(
            self.eabhandler._payload_normalize({"mac": "only"}),
            {"hmac": "only"},
        )

    def test_015_payload_normalize_bad_json(self):
        """invalid JSON string returns None"""
        self.assertIsNone(self.eabhandler._payload_normalize("{not-json"))

    def test_016_payload_normalize_missing_hmac(self):
        """object without hmac or value returns None"""
        self.assertIsNone(self.eabhandler._payload_normalize({"cahandler": {"a": "b"}}))

    def test_017_mac_key_get_no_kid(self):
        """mac_key_get without kid"""
        with self.assertLogs("test_a2c", level="WARNING") as lcm:
            self.assertIsNone(self.eabhandler.mac_key_get(None))
        self.assertIn("WARNING:test_a2c:MAC key retrieval failed: kid=None", lcm.output)

    def test_018_mac_key_get_missing_config(self):
        """mac_key_get without vault_url/token"""
        with self.assertLogs("test_a2c", level="WARNING") as lcm:
            self.assertIsNone(self.eabhandler.mac_key_get("keyid_00"))
        self.assertTrue(any("MAC key retrieval failed" in line for line in lcm.output))

    @patch("acme2certifier.eabhandlers.hashicorp_vault_handler.ca_api_request")
    def test_019_mac_key_get_string_secret(self, mock_api):
        """mac_key_get with string HMAC in value field"""
        self.eabhandler.vault_url = "http://vault:8200"
        self.eabhandler.vault_token = "token"
        mock_api.return_value = (
            200,
            {"data": {"data": {"value": "bWFjXzAw"}}},
        )
        self.assertEqual(self.eabhandler.mac_key_get("keyid_00"), "bWFjXzAw")
        mock_api.assert_called_once()
        args = mock_api.call_args
        self.assertEqual(args[0][1], "get")
        self.assertIn("/v1/secret/data/acme/eab/keyid_00", args[0][2])

    @patch("acme2certifier.eabhandlers.hashicorp_vault_handler.ca_api_request")
    def test_020_mac_key_get_profile_object(self, mock_api):
        """mac_key_get with full profile object in value"""
        self.eabhandler.vault_url = "http://vault:8200"
        self.eabhandler.vault_token = "token"
        mock_api.return_value = (
            200,
            {
                "data": {
                    "data": {
                        "value": {
                            "hmac": "profile-hmac",
                            "cahandler": {"allowed_domainlist": ["a.com"]},
                        }
                    }
                }
            },
        )
        self.assertEqual(self.eabhandler.mac_key_get("keyid_01"), "profile-hmac")

    @patch("acme2certifier.eabhandlers.hashicorp_vault_handler.ca_api_request")
    def test_021_mac_key_get_top_level_hmac(self, mock_api):
        """mac_key_get when secret data is profile without value wrapper"""
        self.eabhandler.vault_url = "http://vault:8200"
        self.eabhandler.vault_token = "token"
        mock_api.return_value = (
            200,
            {"data": {"data": {"hmac": "top-hmac", "authorization": {}}}},
        )
        self.assertEqual(self.eabhandler.mac_key_get("keyid_02"), "top-hmac")

    @patch("acme2certifier.eabhandlers.hashicorp_vault_handler.ca_api_request")
    def test_022_mac_key_get_http_error(self, mock_api):
        """mac_key_get on non-200 response"""
        self.eabhandler.vault_url = "http://vault:8200"
        self.eabhandler.vault_token = "token"
        mock_api.return_value = (404, {"errors": ["not found"]})
        with self.assertLogs("test_a2c", level="WARNING") as lcm:
            self.assertIsNone(self.eabhandler.mac_key_get("missing"))
        self.assertTrue(any("http_code=404" in line for line in lcm.output))

    @patch("acme2certifier.eabhandlers.hashicorp_vault_handler.ca_api_request")
    def test_023_mac_key_get_uses_cache(self, mock_api):
        """second mac_key_get for same kid uses cache"""
        self.eabhandler.vault_url = "http://vault:8200"
        self.eabhandler.vault_token = "token"
        self.eabhandler.cache_ttl = 60
        mock_api.return_value = (
            200,
            {"data": {"data": {"value": "cached-hmac"}}},
        )
        self.assertEqual(self.eabhandler.mac_key_get("keyid_00"), "cached-hmac")
        self.assertEqual(self.eabhandler.mac_key_get("keyid_00"), "cached-hmac")
        self.assertEqual(mock_api.call_count, 1)

    @patch("acme2certifier.eabhandlers.hashicorp_vault_handler.ca_api_request")
    def test_024_key_file_load(self, mock_api):
        """key_file_load lists kids and loads profiles"""
        self.eabhandler.vault_url = "http://vault:8200"
        self.eabhandler.vault_token = "token"

        def _api_side_effect(_logger, _method, url, **_kwargs):
            if "metadata" in url:
                return 200, {"data": {"keys": ["keyid_00", "subdir/", "keyid_01"]}}
            if url.rstrip("/").endswith("keyid_00"):
                return 200, {"data": {"data": {"value": "hmac-00"}}}
            if url.rstrip("/").endswith("keyid_01"):
                return (
                    200,
                    {
                        "data": {
                            "data": {
                                "hmac": "hmac-01",
                                "cahandler": {"ca_name": "pki"},
                            }
                        }
                    },
                )
            return 404, {}

        mock_api.side_effect = _api_side_effect
        result = self.eabhandler.key_file_load()
        self.assertEqual(result["keyid_00"], {"hmac": "hmac-00"})
        self.assertEqual(result["keyid_01"]["hmac"], "hmac-01")
        self.assertEqual(result["keyid_01"]["cahandler"]["ca_name"], "pki")

    @patch(
        "acme2certifier.eabhandlers.hashicorp_vault_handler.EABhandler.key_file_load"
    )
    @patch("acme2certifier.eabhandlers.hashicorp_vault_handler.EABhandler.eab_kid_get")
    def test_025_eab_profile_get(self, mock_kid, mock_load):
        """eab_profile_get returns cahandler block for kid"""
        mock_kid.return_value = "keyid_01"
        mock_load.return_value = {
            "keyid_01": {
                "hmac": "x",
                "Cahandler": {"allowed_domainlist": ["a.com"]},
            }
        }
        self.assertEqual(
            self.eabhandler.eab_profile_get("csr"),
            {"allowed_domainlist": ["a.com"]},
        )

    @patch(
        "acme2certifier.eabhandlers.hashicorp_vault_handler.EABhandler.key_file_load"
    )
    @patch("acme2certifier.eabhandlers.hashicorp_vault_handler.EABhandler.eab_kid_get")
    def test_026_eab_profile_get_hmac_only(self, mock_kid, mock_load):
        """eab_profile_get returns empty for hmac-only kid"""
        mock_kid.return_value = "keyid_00"
        mock_load.return_value = {"keyid_00": {"hmac": "only"}}
        self.assertEqual(self.eabhandler.eab_profile_get("csr"), {})

    @patch(
        "acme2certifier.eabhandlers.hashicorp_vault_handler.EABhandler.key_file_load"
    )
    @patch("acme2certifier.eabhandlers.hashicorp_vault_handler.EABhandler.eab_kid_get")
    def test_027_cahandler_name_get(self, mock_kid, mock_load):
        """cahandler_name_get returns registry name"""
        mock_kid.return_value = "keyid_01"
        mock_load.return_value = {
            "keyid_01": {
                "hmac": "x",
                "cahandler_name": "vault_primary",
            }
        }
        self.assertEqual(self.eabhandler.cahandler_name_get("csr"), "vault_primary")

    def test_028_vault_kv_path_skips_none_and_empty_segments(self):
        """_vault_kv_path ignores None parts and empty slash segments"""
        from acme2certifier.eabhandlers.hashicorp_vault_handler import _vault_kv_path

        self.assertEqual(_vault_kv_path(None, "secret", "", "/acme/eab/"), "secret/acme/eab")

    def test_029_payload_normalize_none_and_unsupported(self):
        """None and non-dict/non-str payloads are rejected"""
        self.assertIsNone(self.eabhandler._payload_normalize(None))
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.assertIsNone(self.eabhandler._payload_normalize(["list"]))
        self.assertTrue(
            any("Unsupported secret payload type" in line for line in lcm.output)
        )

    def test_030_cache_get_expired_and_cache_set_disabled(self):
        """Expired cache entries are dropped; cache_ttl<=0 disables writes"""
        import time

        self.eabhandler._cache["kid"] = (time.time() - 1, {"hmac": "stale"})
        self.assertIsNone(self.eabhandler._cache_get("kid"))
        self.assertNotIn("kid", self.eabhandler._cache)

        self.eabhandler.cache_ttl = 0
        self.eabhandler._cache_set("kid", {"hmac": "x"})
        self.assertNotIn("kid", self.eabhandler._cache)

    @patch("acme2certifier.eabhandlers.hashicorp_vault_handler.EABhandler._api_get")
    def test_031_kid_secret_get_api_exception(self, mock_api):
        """API exceptions during kid fetch are logged and return None"""
        self.eabhandler.vault_url = "http://vault:8200"
        self.eabhandler.vault_token = "token"
        mock_api.side_effect = RuntimeError("boom")
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.assertIsNone(self.eabhandler._kid_secret_get("keyid_00"))
        self.assertTrue(any("Vault request failed for kid=keyid_00" in line for line in lcm.output))

    @patch(
        "acme2certifier.eabhandlers.hashicorp_vault_handler.EABhandler._payload_normalize",
        return_value=None,
    )
    @patch("acme2certifier.eabhandlers.hashicorp_vault_handler.EABhandler._api_get")
    def test_032_kid_secret_get_normalize_none(self, mock_api, _mock_norm):
        """Failed payload normalize logs WARNING and returns None"""
        self.eabhandler.vault_url = "http://vault:8200"
        self.eabhandler.vault_token = "token"
        mock_api.return_value = (200, {"data": {"data": {"value": "x"}}})
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.assertIsNone(self.eabhandler._kid_secret_get("keyid_00"))
        self.assertTrue(
            any("could not normalize payload" in line for line in lcm.output)
        )

    @patch(
        "acme2certifier.eabhandlers.hashicorp_vault_handler.EABhandler._payload_normalize",
        return_value={"cahandler": {}},
    )
    @patch("acme2certifier.eabhandlers.hashicorp_vault_handler.EABhandler._api_get")
    def test_033_kid_secret_get_missing_hmac(self, mock_api, _mock_norm):
        """Normalized profile without hmac is rejected"""
        self.eabhandler.vault_url = "http://vault:8200"
        self.eabhandler.vault_token = "token"
        mock_api.return_value = (200, {"data": {"data": {"value": "x"}}})
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.assertIsNone(self.eabhandler._kid_secret_get("keyid_00"))
        self.assertTrue(any("missing hmac in profile" in line for line in lcm.output))

    def test_034_kids_list_missing_credentials(self):
        """_kids_list returns empty without vault_url/token"""
        self.eabhandler.vault_url = None
        self.eabhandler.vault_token = None
        self.assertEqual(self.eabhandler._kids_list(), [])

    @patch("acme2certifier.eabhandlers.hashicorp_vault_handler.EABhandler._api_get")
    def test_035_kids_list_api_exception(self, mock_api):
        """List API exceptions are logged and return empty"""
        self.eabhandler.vault_url = "http://vault:8200"
        self.eabhandler.vault_token = "token"
        mock_api.side_effect = RuntimeError("list boom")
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.assertEqual(self.eabhandler._kids_list(), [])
        self.assertTrue(any("Vault list failed: list boom" in line for line in lcm.output))

    @patch("acme2certifier.eabhandlers.hashicorp_vault_handler.EABhandler._api_get")
    def test_036_kids_list_http_error(self, mock_api):
        """Non-200 list responses are logged and return empty"""
        self.eabhandler.vault_url = "http://vault:8200"
        self.eabhandler.vault_token = "token"
        mock_api.return_value = (500, {"errors": ["nope"]})
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.assertEqual(self.eabhandler._kids_list(), [])
        self.assertTrue(any("http_code=500" in line for line in lcm.output))

    @patch("acme2certifier.eabhandlers.hashicorp_vault_handler.EABhandler._api_get")
    def test_037_kids_list_skips_unsafe_kid(self, mock_api):
        """Unsafe kids from Vault list are skipped with WARNING"""
        self.eabhandler.vault_url = "http://vault:8200"
        self.eabhandler.vault_token = "token"
        mock_api.return_value = (
            200,
            {"data": {"keys": ["safe_kid", "../escape", "also.ok"]}},
        )
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            kids = self.eabhandler._kids_list()
        self.assertIn("safe_kid", kids)
        self.assertNotIn("../escape", kids)
        self.assertTrue(
            any("Skipping unsafe EAB kid from Vault list" in line for line in lcm.output)
        )


if __name__ == "__main__":
    unittest.main()
