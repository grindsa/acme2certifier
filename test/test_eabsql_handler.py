#!/usr/bin/python
# -*- coding: utf-8 -*-
"""unittests for acme2certifier"""
# pylint: disable= C0415, W0212
import unittest
import sys
import os
from unittest.mock import patch, MagicMock
import configparser

sys.path.insert(0, ".")
sys.path.insert(1, "..")


class TestEABHandler(unittest.TestCase):
    """test class for sql_handler"""

    def setUp(self):
        """setup unit test"""
        import sys
        import types
        sys.modules['psycopg2'] = types.ModuleType('psycopg2')
        sys.modules['psycopg2'].connect = MagicMock()
        mssql_mock = types.ModuleType('mssql_python')
        def dummy_connect(*args, **kwargs):
            return None
        mssql_mock.connect = dummy_connect
        sys.modules['mssql_python'] = mssql_mock
        import logging

        logging.basicConfig(level=logging.CRITICAL)
        self.logger = logging.getLogger("test_a2c")
        from examples.eab_handler.sql_handler import EABhandler

        self.eabhandler = EABhandler(self.logger)
        self.dir_path = os.path.dirname(os.path.realpath(__file__))


    def test_001_default(self):
        """default test which always passes"""
        self.assertEqual("foo", "foo")

    @patch("examples.eab_handler.sql_handler.EABhandler._config_load")
    def test_002__enter__(self, mock_config_load):
        """test enter called"""
        mock_config_load.return_value = True
        self.eabhandler.__enter__()
        self.assertTrue(mock_config_load.called)

    @patch("examples.eab_handler.sql_handler.load_config")
    def test_003_config_load(self, mock_config_load):
        """test _config_load - empty dictionary"""
        parser = configparser.ConfigParser()
        mock_config_load.return_value = parser
        self.eabhandler._config_load()
        self.assertFalse(self.eabhandler.db_system)
        self.assertFalse(self.eabhandler.db_host)
        self.assertFalse(self.eabhandler.db_name)
        self.assertFalse(self.eabhandler.db_user)
        self.assertFalse(self.eabhandler.db_password)

    @patch("examples.eab_handler.sql_handler.load_config")
    def test_004_config_load(self, mock_load_config_load):
        """test _config_load - bogus values"""
        parser = configparser.ConfigParser()
        parser["foo"] = {"foo": "bar"}
        mock_load_config_load.return_value = parser
        self.eabhandler._config_load()
        self.assertFalse(self.eabhandler.db_system)
        self.assertFalse(self.eabhandler.db_host)
        self.assertFalse(self.eabhandler.db_name)
        self.assertFalse(self.eabhandler.db_user)
        self.assertFalse(self.eabhandler.db_password)

    @patch("examples.eab_handler.sql_handler.load_config")
    def test_005_config_load(self, mock_config_load):
        """test _config_load - bogus values"""
        parser = configparser.ConfigParser()
        parser["EABhandler"] = {"foo": "bar"}
        mock_config_load.return_value = parser
        self.eabhandler._config_load()
        self.assertFalse(self.eabhandler.db_system)
        self.assertFalse(self.eabhandler.db_host)
        self.assertFalse(self.eabhandler.db_name)
        self.assertFalse(self.eabhandler.db_user)
        self.assertFalse(self.eabhandler.db_password)

    @patch("examples.eab_handler.sql_handler.load_config")
    def test_006_config_load(self, mock_config_load):
        """test _config_load - valid values"""
        parser = configparser.ConfigParser()
        parser["EABhandler"] = {"db_system": "db_system"}
        mock_config_load.return_value = parser
        self.eabhandler._config_load()
        self.assertEqual("db_system", self.eabhandler.db_system)
        self.assertFalse(self.eabhandler.db_host)
        self.assertFalse(self.eabhandler.db_name)
        self.assertFalse(self.eabhandler.db_user)
        self.assertFalse(self.eabhandler.db_password)

    @patch("examples.eab_handler.sql_handler.load_config")
    def test_007_config_load(self, mock_config_load):
        """test _config_load - valid values"""
        parser = configparser.ConfigParser()
        parser["EABhandler"] = {
            "db_system": "db_system",
            "db_host": "db_host",
            "db_name": "db_name",
            "db_user": "db_user",
            "db_password": "db_password"
        }
        mock_config_load.return_value = parser
        self.eabhandler._config_load()
        self.assertEqual("db_system", self.eabhandler.db_system)
        self.assertEqual("db_host", self.eabhandler.db_host)
        self.assertEqual("db_name", self.eabhandler.db_name)
        self.assertEqual("db_user", self.eabhandler.db_user)
        self.assertEqual("db_password", self.eabhandler.db_password)

    def test_008_mac_key_get(self):
        """test mac_key_get without db parameters specified"""
        self.assertFalse(self.eabhandler.mac_key_get(None))

    @patch("examples.eab_handler.sql_handler.EABhandler._wllist_check")
    @patch("examples.eab_handler.sql_handler.EABhandler._cn_add")
    @patch("examples.eab_handler.sql_handler.EABhandler._chk_san_lists_get")
    def test_009_allowed_domains_check(self, mock_san, mock_cn, mock_wlc):
        """test EABhanlder._allowed_domains_check()"""
        mock_san.return_value = (["foo"], [])
        mock_cn.return_value = ["foo", "bar"]
        mock_wlc.side_effect = [True, True]
        self.assertFalse(
            self.eabhandler._allowed_domains_check("csr", ["domain", "list"])
        )

    @patch("examples.eab_handler.sql_handler.EABhandler._wllist_check")
    @patch("examples.eab_handler.sql_handler.EABhandler._cn_add")
    @patch("examples.eab_handler.sql_handler.EABhandler._chk_san_lists_get")
    def test_010_allowed_domains_check(self, mock_san, mock_cn, mock_wlc):
        """test EABhanlder._allowed_domains_check()"""
        mock_san.return_value = (["foo"], [False])
        mock_cn.return_value = ["foo", "bar"]
        mock_wlc.side_effect = [True, True]
        self.assertEqual(
            "Either CN or SANs are not allowed by profile",
            self.eabhandler._allowed_domains_check("csr", ["domain", "list"]),
        )

    @patch("examples.eab_handler.sql_handler.EABhandler._wllist_check")
    @patch("examples.eab_handler.sql_handler.EABhandler._cn_add")
    @patch("examples.eab_handler.sql_handler.EABhandler._chk_san_lists_get")
    def test_011_allowed_domains_check(self, mock_san, mock_cn, mock_wlc):
        """test EABhanlder._allowed_domains_check()"""
        mock_san.return_value = (["foo"], [])
        mock_cn.return_value = ["foo", "bar"]
        mock_wlc.side_effect = [False, True]
        self.assertEqual(
            "Either CN or SANs are not allowed by profile",
            self.eabhandler._allowed_domains_check("csr", ["domain", "list"]),
        )

    @patch("examples.eab_handler.sql_handler.EABhandler.key_file_load")
    def test_012_eab_profile_get(self, mock_key_file_load):
        """test EABhandler._eab_profile_get()"""
        mock_key_file_load.return_value = {
            "eab_kid": {"cahandler": {"foo_parameter": "bar_parameter"}}
        }
        models_mock = MagicMock()
        models_mock.DBstore().certificate_lookup.return_value = {
            "foo": "bar",
            "order__account__eab_kid": "eab_kid",
        }
        modules = {"acme_srv.db_handler": models_mock}
        patch.dict("sys.modules", modules).start()
        self.assertEqual(
            {"foo_parameter": "bar_parameter"}, self.eabhandler.eab_profile_get("csr")
        )

    @patch("examples.eab_handler.sql_handler.EABhandler.key_file_load")
    def test_013_eab_profile_get(self, mock_key_file_load):
        """test EABhandler._eab_profile_get()"""
        mock_key_file_load.return_value = {
            "eab_kid": {"cahandler_invalid": {"foo_parameter": "bar_parameter"}}
        }
        models_mock = MagicMock()
        models_mock.DBstore().certificate_lookup.return_value = {
            "foo": "bar",
            "order__account__eab_kid": "eab_kid",
        }
        modules = {"acme_srv.db_handler": models_mock}
        patch.dict("sys.modules", modules).start()
        self.assertFalse(self.eabhandler.eab_profile_get("csr"))

    @patch("examples.eab_handler.sql_handler.EABhandler.key_file_load")
    def test_014_eab_profile_get(self, mock_key_file_load):
        """test EABhandler._eab_profile_get()"""
        mock_key_file_load.return_value = {
            "eab_kid": {"cahandler1": {"foo_parameter": "bar_parameter"}}
        }
        models_mock = MagicMock()
        models_mock.DBstore().certificate_lookup.return_value = {
            "foo": "bar",
            "1order__account__eab_kid": "eab_kid",
        }
        modules = {"acme_srv.db_handler": models_mock}
        patch.dict("sys.modules", modules).start()
        self.assertFalse(self.eabhandler.eab_profile_get("csr"))

    @patch("examples.eab_handler.sql_handler.EABhandler.key_file_load")
    def test_015_eab_profile_get(self, mock_key_file_load):
        """test EABhandler._eab_profile_get()"""
        mock_key_file_load.return_value = {
            "eab_kid": {"cahandler": {"foo_parameter": "bar_parameter"}}
        }
        models_mock = MagicMock()
        models_mock.DBstore().certificate_lookup.return_value = {
            "foo": "bar",
            "order__account__eab_kid": "eab_kid1",
        }
        modules = {"acme_srv.db_handler": models_mock}
        patch.dict("sys.modules", modules).start()
        self.assertFalse(self.eabhandler.eab_profile_get("csr"))

    @patch("examples.eab_handler.sql_handler.EABhandler.key_file_load")
    def test_016_eab_profile_get(self, mock_prof):
        """test EABhandler._eab_profile_get()"""
        mock_prof.return_value = {
            "eab_kid": {"cahandler": {"foo_parameter": "bar_parameter"}}
        }
        models_mock = MagicMock()
        models_mock.DBstore().certificate_lookup.side_effect = Exception("ex_db_lookup")
        modules = {"acme_srv.db_handler": models_mock}
        patch.dict("sys.modules", modules).start()
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.assertFalse(self.eabhandler.eab_profile_get("csr"))
        self.assertIn(
            "ERROR:test_a2c:Database error while retrieving eab_kid: ex_db_lookup",
            lcm.output,
        )

    def test_017_chk_san_lists_get_empty(self):
        # Should return empty lists for empty input
        result = self.eabhandler._chk_san_lists_get(None)
        self.assertEqual(result, ([], []))

    @patch("examples.eab_handler.sql_handler.csr_san_get")
    def test_018_chk_san_lists_get_value(self, mock_csr_san_get):
        # Should return empty lists for empty input
        mock_csr_san_get.return_value = ['dns:example.com', 'dns:example.org']
        result = self.eabhandler._chk_san_lists_get('csr')
        self.assertEqual(result, (['example.com', 'example.org'], []))

    @patch("examples.eab_handler.sql_handler.csr_san_get")
    def test_019_chk_san_lists_get_value(self, mock_csr_san_get):
        # Should return empty lists for empty input
        mock_csr_san_get.return_value = ['example.com', 'example.org']#
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.assertEqual([False, False], self.eabhandler._chk_san_lists_get('csr')[1])
        self.assertIn('INFO:test_a2c:SAN list parsing failed at entry: example.com', lcm.output)
        self.assertIn('INFO:test_a2c:SAN list parsing failed at entry: example.org', lcm.output)


    @patch("examples.eab_handler.sql_handler.csr_cn_get")
    def test_021_cn_add_cn_not_in_sans(self, mock_csr_cn_get):
        """CN present and not in SANs: should append CN"""
        mock_csr_cn_get.return_value = "example.com"
        result = self.eabhandler._cn_add("dummy_csr", ["test.com"])
        self.assertIn("example.com", result)
        self.assertIn("test.com", result)
        self.assertEqual(len(result), 2)

    @patch("examples.eab_handler.sql_handler.csr_cn_get")
    def test_022_cn_add_cn_already_in_sans(self, mock_csr_cn_get):
        """CN present and already in SANs: should not duplicate CN"""
        mock_csr_cn_get.return_value = "example.com"
        result = self.eabhandler._cn_add("dummy_csr", ["example.com", "test.com"])
        self.assertIn("example.com", result)
        self.assertIn("test.com", result)
        self.assertEqual(len(result), 2)

    @patch("examples.eab_handler.sql_handler.csr_cn_get")
    def test_023_cn_add_no_cn(self, mock_csr_cn_get):
        """No CN present: should not modify SANs"""
        mock_csr_cn_get.return_value = None
        result = self.eabhandler._cn_add("dummy_csr", ["test.com"])
        self.assertEqual(result, ["test.com"])

    def test_024_list_regex_check_match(self):
        """Entry matches regex: should return True"""
        result = self.eabhandler._list_regex_check("example.com", ["example\\.com"])
        self.assertTrue(result)

    def test_025_list_regex_check_no_match(self):
        """Entry does not match regex: should return False"""
        result = self.eabhandler._list_regex_check("example.com", ["test\\.com"])
        self.assertFalse(result)

    def test_026_list_regex_check_wildcard(self):
        """Entry matches wildcard regex: should return True"""
        result = self.eabhandler._list_regex_check("sub.example.com", ["*.example\\.com"])
        self.assertTrue(result)

    def test_027_wllist_check_match(self):
        """Entry matches list: should return True"""
        result = self.eabhandler._wllist_check("example.com", ["example\\.com"])
        self.assertTrue(result)

    def test_028_wllist_check_empty_list(self):
        """Empty list: should return True"""
        result = self.eabhandler._wllist_check("example.com", [])
        self.assertTrue(result)

    def test_029_wllist_check_toggle(self):
        """Toggle: should invert result"""
        result = self.eabhandler._wllist_check("example.com", ["example\\.com"], toggle=True)
        self.assertFalse(result)

    def test_030_wllist_check_no_match(self):
        """Entry does not match list: should return False"""
        result = self.eabhandler._wllist_check("example.com", ["test\\.com"])
        self.assertFalse(result)

    def test_031_key_file_load_no_db_params(self):
        """No DB params: should return empty dict"""
        self.eabhandler.db_host = None
        self.eabhandler.db_name = None
        self.eabhandler.db_user = None
        self.eabhandler.db_password = None
        result = self.eabhandler.key_file_load()
        self.assertEqual(result, {})

    @patch("examples.eab_handler.sql_handler.EABhandler._load_mssql_profiles")
    def test_032_key_file_load_mssql(self, mock_load_mssql):
        """MSSQL: should call _load_mssql_profiles and return its result"""
        self.eabhandler.db_host = "host"
        self.eabhandler.db_name = "name"
        self.eabhandler.db_user = "user"
        self.eabhandler.db_password = "pass"
        self.eabhandler.db_system = "mssql"
        mock_load_mssql.return_value = {"key": "profile"}
        result = self.eabhandler.key_file_load()
        self.assertEqual(result, {"key": "profile"})
        mock_load_mssql.assert_called_once()

    @patch("examples.eab_handler.sql_handler.EABhandler._load_postgres_profiles")
    def test_033_key_file_load_postgres(self, mock_load_postgres):
        """Postgres: should call _load_postgres_profiles and return its result"""
        self.eabhandler.db_host = "host"
        self.eabhandler.db_name = "name"
        self.eabhandler.db_user = "user"
        self.eabhandler.db_password = "pass"
        self.eabhandler.db_system = "postgres"
        mock_load_postgres.return_value = {"key": "profile"}
        result = self.eabhandler.key_file_load()
        self.assertEqual(result, {"key": "profile"})
        mock_load_postgres.assert_called_once()

    @patch("examples.eab_handler.sql_handler.EABhandler._load_mssql_profiles")
    @patch("examples.eab_handler.sql_handler.EABhandler._load_postgres_profiles")
    def test_034_key_file_load_error(self, mock_postgres, mock_mssql):
        """Invalid db_system: should return empty dict"""
        self.eabhandler.db_host = "host"
        self.eabhandler.db_name = "name"
        self.eabhandler.db_user = "user"
        self.eabhandler.db_password = "pass"
        self.eabhandler.db_system = "invalid"
        mock_postgres.return_value = {}
        mock_mssql.return_value = {}
        result = self.eabhandler.key_file_load()
        self.assertEqual(result, {})

    @patch("examples.eab_handler.sql_handler.connect")
    def test_035_load_mssql_profiles_success(self, mock_connect):
        """Successful fetch: should return dict with profiles"""
        self.eabhandler.db_host = "host"
        self.eabhandler.db_name = "name"
        self.eabhandler.db_user = "user"
        self.eabhandler.db_password = "pass"
        # Mock MSSQL connection and cursor
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value = mock_cursor
        mock_cursor.fetchall.return_value = [MagicMock(key_id="id1", profile="profile1"), MagicMock(key_id="id2", profile="profile2")]
        mock_connect.return_value = mock_conn
        result = self.eabhandler._load_mssql_profiles("SELECT ...")
        self.assertEqual(result, {"id1": "profile1", "id2": "profile2"})
        mock_conn.close.assert_called_once()

    @patch("examples.eab_handler.sql_handler.connect")
    def test_036_load_mssql_profiles_empty(self, mock_connect):
        """Empty result: should return empty dict"""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value = mock_cursor
        mock_cursor.fetchall.return_value = []
        mock_connect.return_value = mock_conn
        result = self.eabhandler._load_mssql_profiles("SELECT ...")
        self.assertEqual(result, {})

    @patch("examples.eab_handler.sql_handler.connect")
    def test_037_load_mssql_profiles_exception(self, mock_connect):
        """Exception: should log error and return empty dict"""
        mock_connect.side_effect = Exception("connection error")
        with self.assertLogs("test_a2c", level="ERROR") as lcm:
            result = self.eabhandler._load_mssql_profiles("SELECT ...")
        self.assertEqual(result, {})
        self.assertTrue(any("error" in msg.lower() for msg in lcm.output))

    @patch("examples.eab_handler.sql_handler.psycopg2.connect")
    def test_038_load_postgres_profiles_success(self, mock_connect):
        """Successful fetch: should return dict with profiles"""
        self.eabhandler.db_host = "host"
        self.eabhandler.db_name = "name"
        self.eabhandler.db_user = "user"
        self.eabhandler.db_password = "pass"
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value = mock_cursor
        mock_cursor.fetchall.return_value = [("id1", "profile1"), ("id2", "profile2")]
        mock_connect.return_value = mock_conn
        result = self.eabhandler._load_postgres_profiles("SELECT ...")
        self.assertEqual(result, {"id1": "profile1", "id2": "profile2"})
        mock_conn.close.assert_called_once()

    @patch("examples.eab_handler.sql_handler.psycopg2.connect")
    def test_039_load_postgres_profiles_empty(self, mock_connect):
        """Empty result: should return empty dict"""
        mock_conn = MagicMock()
        mock_conn.close = MagicMock()
        mock_conn.__bool__.return_value = True
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value = mock_cursor
        mock_cursor.fetchall.return_value = []
        mock_connect.return_value = mock_conn
        result = self.eabhandler._load_postgres_profiles("SELECT ...")
        self.assertEqual(result, {})
        self.assertTrue(mock_conn.close.called)

    @patch("examples.eab_handler.sql_handler.psycopg2.connect")
    def test_040_load_postgres_profiles_exception(self, mock_connect):
        """Exception: should log error and return empty dict"""
        mock_connect.side_effect = Exception("connection error")
        with self.assertLogs("test_a2c", level="ERROR") as lcm:
            result = self.eabhandler._load_postgres_profiles("SELECT ...")
        self.assertEqual(result, {})
        self.assertTrue(any("error" in msg.lower() for msg in lcm.output))

    @patch("examples.eab_handler.sql_handler.EABhandler.key_file_load")
    def test_041_mac_key_get_valid(self, mock_key_file_load):
        """Valid key: should return mac_key"""
        self.eabhandler.db_host = "host"
        self.eabhandler.db_name = "name"
        self.eabhandler.db_user = "user"
        self.eabhandler.db_password = "pass"
        mock_key_file_load.return_value = {"key1": "mac_value"}
        result = self.eabhandler.mac_key_get("key1")
        self.assertEqual(result, "mac_value")

    @patch("examples.eab_handler.sql_handler.EABhandler.key_file_load")
    def test_042_mac_key_get_missing_key(self, mock_key_file_load):
        """Missing key: should return None"""
        self.eabhandler.db_host = "host"
        self.eabhandler.db_name = "name"
        self.eabhandler.db_user = "user"
        self.eabhandler.db_password = "pass"
        mock_key_file_load.return_value = {"key1": "mac_value"}
        result = self.eabhandler.mac_key_get("key2")
        self.assertIsNone(result)

    def test_043_mac_key_get_missing_db_params(self):
        """Missing DB params: should return None and log error"""
        self.eabhandler.db_host = None
        self.eabhandler.db_name = None
        self.eabhandler.db_user = None
        self.eabhandler.db_password = None
        with self.assertLogs("test_a2c", level="ERROR") as lcm:
            result = self.eabhandler.mac_key_get("key1")
        self.assertIsNone(result)
        self.assertTrue(any("error" in msg.lower() for msg in lcm.output))

    @patch("examples.eab_handler.sql_handler.EABhandler.key_file_load")
    def test_044_mac_key_get_exception(self, mock_key_file_load):
        """Exception: should return None and log error"""
        self.eabhandler.db_host = "host"
        self.eabhandler.db_name = "name"
        self.eabhandler.db_user = "user"
        self.eabhandler.db_password = "pass"
        mock_key_file_load.side_effect = Exception("lookup error")
        with self.assertLogs("test_a2c", level="ERROR") as lcm:
            result = self.eabhandler.mac_key_get("key1")
        self.assertIsNone(result)
        self.assertTrue(any("error" in msg.lower() for msg in lcm.output))

    def test_045_eab_kid_get_exception(self):
        """Exception branch: should log error and return None"""
        self.eabhandler.db_host = "host"
        self.eabhandler.db_name = "name"
        self.eabhandler.db_user = "user"
        self.eabhandler.db_password = "pass"
        dbstore_mock = MagicMock()
        dbstore_mock.side_effect = Exception("db error")
        sys.modules['acme_srv.db_handler'] = MagicMock(DBstore=dbstore_mock)
        with self.assertLogs("test_a2c", level="ERROR") as lcm:
            result = self.eabhandler.eab_kid_get("csr")
        self.assertIsNone(result)
        self.assertTrue(any("Database error while retrieving eab_kid" in msg for msg in lcm.output))


if __name__ == "__main__":

    if os.path.exists("acme_test.db"):
        os.remove("acme_test.db")
    unittest.main()