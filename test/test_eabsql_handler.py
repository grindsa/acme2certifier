#!/usr/bin/python
# -*- coding: utf-8 -*-
"""unittests for acme2certifier"""

# pylint: disable= C0415, W0212
import configparser
import os
import sys
import unittest
from unittest.mock import patch, MagicMock

sys.path.insert(0, ".")
sys.path.insert(1, "..")


class TestEABHandler(unittest.TestCase):
    """test class for sql_handler"""

    def setUp(self):
        """setup unit test"""
        import logging

        logging.basicConfig(level=logging.CRITICAL)
        self.logger = logging.getLogger("test_a2c")
        from acme2certifier.eabhandlers.sql_handler import EABhandler

        self.eabhandler = EABhandler(self.logger)
        self.dir_path = os.path.dirname(os.path.realpath(__file__))

    def _mock_conn_with_rows(self, rows):
        """Build a mock DB connection returning rows from fetchall."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value = mock_cursor
        mock_cursor.fetchall.return_value = rows
        return mock_conn, mock_cursor

    def test_001_default(self):
        """default test which always passes"""
        self.assertEqual("foo", "foo")

    @patch("acme2certifier.eabhandlers.sql_handler.EABhandler._config_load")
    def test_002__enter__(self, mock_config_load):
        """test enter called"""
        mock_config_load.return_value = True
        self.eabhandler.__enter__()
        self.assertTrue(mock_config_load.called)

    @patch("acme2certifier.eabhandlers.sql_handler.load_config")
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

    @patch("acme2certifier.eabhandlers.sql_handler.load_config")
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

    @patch("acme2certifier.eabhandlers.sql_handler.load_config")
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

    @patch("acme2certifier.eabhandlers.sql_handler.load_config")
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

    @patch("acme2certifier.eabhandlers.sql_handler.load_config")
    def test_007_config_load(self, mock_config_load):
        """test _config_load - valid values"""
        parser = configparser.ConfigParser()
        parser["EABhandler"] = {
            "db_system": "db_system",
            "db_host": "db_host",
            "db_name": "db_name",
            "db_user": "db_user",
            "db_password": "db_password",
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

    @patch("acme2certifier.eabhandlers.sql_handler.EABhandler._wllist_check")
    @patch("acme2certifier.eabhandlers.sql_handler.EABhandler._cn_add")
    @patch("acme2certifier.eabhandlers.sql_handler.EABhandler._chk_san_lists_get")
    def test_009_allowed_domains_check(self, mock_san, mock_cn, mock_wlc):
        """test EABhanlder._allowed_domains_check()"""
        mock_san.return_value = (["foo"], [])
        mock_cn.return_value = ["foo", "bar"]
        mock_wlc.side_effect = [True, True]
        self.assertFalse(
            self.eabhandler._allowed_domains_check("csr", ["domain", "list"])
        )

    @patch("acme2certifier.eabhandlers.sql_handler.EABhandler._wllist_check")
    @patch("acme2certifier.eabhandlers.sql_handler.EABhandler._cn_add")
    @patch("acme2certifier.eabhandlers.sql_handler.EABhandler._chk_san_lists_get")
    def test_010_allowed_domains_check(self, mock_san, mock_cn, mock_wlc):
        """test EABhanlder._allowed_domains_check()"""
        mock_san.return_value = (["foo"], [False])
        mock_cn.return_value = ["foo", "bar"]
        mock_wlc.side_effect = [True, True]
        self.assertEqual(
            "Either CN or SANs are not allowed by profile",
            self.eabhandler._allowed_domains_check("csr", ["domain", "list"]),
        )

    @patch("acme2certifier.eabhandlers.sql_handler.EABhandler._wllist_check")
    @patch("acme2certifier.eabhandlers.sql_handler.EABhandler._cn_add")
    @patch("acme2certifier.eabhandlers.sql_handler.EABhandler._chk_san_lists_get")
    def test_011_allowed_domains_check(self, mock_san, mock_cn, mock_wlc):
        """test EABhanlder._allowed_domains_check()"""
        mock_san.return_value = (["foo"], [])
        mock_cn.return_value = ["foo", "bar"]
        mock_wlc.side_effect = [False, True]
        self.assertEqual(
            "Either CN or SANs are not allowed by profile",
            self.eabhandler._allowed_domains_check("csr", ["domain", "list"]),
        )

    @patch("acme2certifier.eabhandlers.sql_handler.EABhandler.key_file_load")
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
        modules = {"acme2certifier.acme_srv.db_handler": models_mock}
        patch.dict("sys.modules", modules).start()
        self.assertEqual(
            {"foo_parameter": "bar_parameter"}, self.eabhandler.eab_profile_get("csr")
        )

    @patch("acme2certifier.eabhandlers.sql_handler.EABhandler.key_file_load")
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
        modules = {"acme2certifier.acme_srv.db_handler": models_mock}
        patch.dict("sys.modules", modules).start()
        self.assertFalse(self.eabhandler.eab_profile_get("csr"))

    @patch("acme2certifier.eabhandlers.sql_handler.EABhandler.key_file_load")
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
        modules = {"acme2certifier.acme_srv.db_handler": models_mock}
        patch.dict("sys.modules", modules).start()
        self.assertFalse(self.eabhandler.eab_profile_get("csr"))

    @patch("acme2certifier.eabhandlers.sql_handler.EABhandler.key_file_load")
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
        modules = {"acme2certifier.acme_srv.db_handler": models_mock}
        patch.dict("sys.modules", modules).start()
        self.assertFalse(self.eabhandler.eab_profile_get("csr"))

    @patch("acme2certifier.eabhandlers.sql_handler.EABhandler.key_file_load")
    def test_016_eab_profile_get(self, mock_prof):
        """test EABhandler._eab_profile_get()"""
        mock_prof.return_value = {
            "eab_kid": {"cahandler": {"foo_parameter": "bar_parameter"}}
        }
        models_mock = MagicMock()
        models_mock.DBstore().certificate_lookup.side_effect = Exception("ex_db_lookup")
        modules = {"acme2certifier.acme_srv.db_handler": models_mock}
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

    @patch("acme2certifier.acme_srv.helpers.domain_utils.csr_san_get")
    def test_018_chk_san_lists_get_value(self, mock_csr_san_get):
        # Should return empty lists for empty input
        mock_csr_san_get.return_value = ["dns:example.com", "dns:example.org"]
        result = self.eabhandler._chk_san_lists_get("csr")
        self.assertEqual(result, (["example.com", "example.org"], []))

    @patch("acme2certifier.acme_srv.helpers.domain_utils.csr_san_get")
    def test_019_chk_san_lists_get_value(self, mock_csr_san_get):
        # Should return empty lists for empty input
        mock_csr_san_get.return_value = ["example.com", "example.org"]  #
        self.assertEqual([False, False], self.eabhandler._chk_san_lists_get("csr")[1])

    @patch("acme2certifier.acme_srv.helpers.eab_profile.csr_cn_get")
    def test_020_cn_add_cn_not_in_sans(self, mock_csr_cn_get):
        """CN present and not in SANs: should append CN"""
        mock_csr_cn_get.return_value = "example.com"
        result = self.eabhandler._cn_add("dummy_csr", ["test.com"])
        self.assertIn("example.com", result)
        self.assertIn("test.com", result)
        self.assertEqual(len(result), 2)

    @patch("acme2certifier.acme_srv.helpers.eab_profile.csr_cn_get")
    def test_021_cn_add_cn_already_in_sans(self, mock_csr_cn_get):
        """CN present and already in SANs: should not duplicate CN"""
        mock_csr_cn_get.return_value = "example.com"
        result = self.eabhandler._cn_add("dummy_csr", ["example.com", "test.com"])
        self.assertIn("example.com", result)
        self.assertIn("test.com", result)
        self.assertEqual(len(result), 2)

    @patch("acme2certifier.acme_srv.helpers.eab_profile.csr_cn_get")
    def test_022_cn_add_no_cn(self, mock_csr_cn_get):
        """No CN present: should not modify SANs"""
        mock_csr_cn_get.return_value = None
        result = self.eabhandler._cn_add("dummy_csr", ["test.com"])
        self.assertEqual(result, ["test.com"])

    def test_023_list_regex_check_match(self):
        """Entry matches regex: should return True"""
        result = self.eabhandler._list_regex_check("example.com", ["example\\.com"])
        self.assertTrue(result)

    def test_024_list_regex_check_no_match(self):
        """Entry does not match regex: should return False"""
        result = self.eabhandler._list_regex_check("example.com", ["test\\.com"])
        self.assertFalse(result)

    def test_025_list_regex_check_wildcard(self):
        """Entry matches wildcard regex: should return True"""
        result = self.eabhandler._list_regex_check(
            "sub.example.com", ["*.example\\.com"]
        )
        self.assertTrue(result)

    def test_026_wllist_check_match(self):
        """Entry matches list: should return True"""
        result = self.eabhandler._wllist_check("example.com", ["example\\.com"])
        self.assertTrue(result)

    def test_027_wllist_check_empty_list(self):
        """Empty list: should return True"""
        result = self.eabhandler._wllist_check("example.com", [])
        self.assertTrue(result)

    def test_028_wllist_check_toggle(self):
        """Toggle: should invert result"""
        result = self.eabhandler._wllist_check(
            "example.com", ["example\\.com"], toggle=True
        )
        self.assertFalse(result)

    def test_029_wllist_check_no_match(self):
        """Entry does not match list: should return False"""
        result = self.eabhandler._wllist_check("example.com", ["test\\.com"])
        self.assertFalse(result)

    def test_030_key_file_load_no_db_params(self):
        """No DB params: should return empty dict"""
        self.eabhandler.db_host = None
        self.eabhandler.db_name = None
        self.eabhandler.db_user = None
        self.eabhandler.db_password = None
        self.eabhandler.db_system = None
        result = self.eabhandler.key_file_load()
        self.assertEqual(result, {})

    @patch("acme2certifier.eabhandlers.sql_handler.EABhandler._load_mssql_profiles")
    def test_031_key_file_load_mssql(self, mock_load):
        """MSSQL: should call _load_mssql_profiles and return its result"""
        self.eabhandler.db_host = "host"
        self.eabhandler.db_name = "name"
        self.eabhandler.db_user = "user"
        self.eabhandler.db_password = "pass"
        self.eabhandler.db_system = "mssql"
        mock_load.return_value = {"key": "profile"}
        result = self.eabhandler.key_file_load()
        self.assertEqual(result, {"key": "profile"})
        mock_load.assert_called_once()

    @patch("acme2certifier.eabhandlers.sql_handler.EABhandler._load_postgres_profiles")
    def test_032_key_file_load_postgres(self, mock_load):
        """Postgres: should call _load_postgres_profiles and return its result"""
        self.eabhandler.db_host = "host"
        self.eabhandler.db_name = "name"
        self.eabhandler.db_user = "user"
        self.eabhandler.db_password = "pass"
        self.eabhandler.db_system = "postgres"
        mock_load.return_value = {"key": "profile"}
        result = self.eabhandler.key_file_load()
        self.assertEqual(result, {"key": "profile"})
        mock_load.assert_called_once()

    def test_033_key_file_load_invalid_system(self):
        """Invalid db_system: should return empty dict without calling loaders"""
        self.eabhandler.db_host = "host"
        self.eabhandler.db_name = "name"
        self.eabhandler.db_user = "user"
        self.eabhandler.db_password = "pass"
        self.eabhandler.db_system = "invalid"
        result = self.eabhandler.key_file_load()
        self.assertEqual(result, {})

    @patch("acme2certifier.eabhandlers.sql_handler.EABhandler._schema_ensure")
    @patch("acme2certifier.eabhandlers.sql_handler.EABhandler._mssql_connect")
    def test_034_load_mssql_profiles_success(self, mock_connect, mock_schema):
        """Successful fetch: should return dict with profiles"""
        self.eabhandler.db_host = "host"
        self.eabhandler.db_name = "name"
        self.eabhandler.db_user = "user"
        self.eabhandler.db_password = "pass"
        self.eabhandler.db_system = "mssql"
        mock_conn, _cursor = self._mock_conn_with_rows(
            [
                (
                    "keyid_01",
                    '{"hmac": "hmac_01", "order": {"allowed_domainlist": ["127.0.0.1"]}}',
                ),
                ("keyid_02", '{"hmac": "hmac_02"}'),
                (
                    "keyid_03",
                    '{"order": {"allowed_domainlist": ["127.0.0.1"]}, "hmac": "hmac_03"}',
                ),
            ]
        )
        mock_connect.return_value = mock_conn
        result = self.eabhandler._load_mssql_profiles()
        self.assertEqual(
            result,
            {
                "keyid_01": {
                    "hmac": "hmac_01",
                    "order": {"allowed_domainlist": ["127.0.0.1"]},
                },
                "keyid_02": {"hmac": "hmac_02"},
                "keyid_03": {
                    "order": {"allowed_domainlist": ["127.0.0.1"]},
                    "hmac": "hmac_03",
                },
            },
        )
        mock_schema.assert_called_once_with(mock_conn, "mssql")
        mock_conn.close.assert_called_once()

    @patch("acme2certifier.eabhandlers.sql_handler.EABhandler._schema_ensure")
    @patch("acme2certifier.eabhandlers.sql_handler.EABhandler._mssql_connect")
    def test_035_load_mssql_profiles_empty(self, mock_connect, _mock_schema):
        """Empty result: should return empty dict"""
        mock_conn, _cursor = self._mock_conn_with_rows([])
        mock_connect.return_value = mock_conn
        result = self.eabhandler._load_mssql_profiles()
        self.assertEqual(result, {})

    @patch("acme2certifier.eabhandlers.sql_handler.EABhandler._mssql_connect")
    def test_036_load_mssql_profiles_exception(self, mock_connect):
        """Exception: should log error and return empty dict"""
        mock_connect.side_effect = Exception("connection error")
        with self.assertLogs("test_a2c", level="ERROR") as lcm:
            result = self.eabhandler._load_mssql_profiles()
        self.assertEqual(result, {})
        self.assertTrue(any("error" in msg.lower() for msg in lcm.output))

    @patch("acme2certifier.eabhandlers.sql_handler.EABhandler._schema_ensure")
    @patch("acme2certifier.eabhandlers.sql_handler.EABhandler._postgres_connect")
    def test_037_load_postgres_profiles_success(self, mock_connect, mock_schema):
        """Successful fetch via psycopg2 path: parse JSON profiles"""
        self.eabhandler.db_host = "host"
        self.eabhandler.db_name = "name"
        self.eabhandler.db_user = "user"
        self.eabhandler.db_password = "pass"
        self.eabhandler.db_system = "postgres"
        mock_conn, _cursor = self._mock_conn_with_rows(
            [
                (
                    "keyid_01",
                    '{"hmac": "hmac_01", "order": {"allowed_domainlist": ["127.0.0.1"]}}',
                ),
                ("keyid_02", '{"hmac": "hmac_02"}'),
                (
                    "keyid_03",
                    {"order": {"allowed_domainlist": ["127.0.0.1"]}, "hmac": "hmac_03"},
                ),
            ]
        )
        mock_connect.return_value = mock_conn
        result = self.eabhandler._load_postgres_profiles()
        self.assertEqual(
            result,
            {
                "keyid_01": {
                    "hmac": "hmac_01",
                    "order": {"allowed_domainlist": ["127.0.0.1"]},
                },
                "keyid_02": {"hmac": "hmac_02"},
                "keyid_03": {
                    "order": {"allowed_domainlist": ["127.0.0.1"]},
                    "hmac": "hmac_03",
                },
            },
        )
        mock_schema.assert_called_once_with(mock_conn, "postgres")
        mock_conn.close.assert_called_once()

    @patch("acme2certifier.eabhandlers.sql_handler.EABhandler._schema_ensure")
    @patch("acme2certifier.eabhandlers.sql_handler.EABhandler._postgres_connect")
    def test_038_load_postgres_profiles_empty(self, mock_connect, _mock_schema):
        """Empty result: should return empty dict"""
        mock_conn, _cursor = self._mock_conn_with_rows([])
        mock_connect.return_value = mock_conn
        result = self.eabhandler._load_postgres_profiles()
        self.assertEqual(result, {})

    @patch("acme2certifier.eabhandlers.sql_handler.EABhandler._postgres_connect")
    def test_039_load_postgres_profiles_exception(self, mock_connect):
        """Exception: should log error and return empty dict"""
        mock_connect.side_effect = Exception("connection error")
        with self.assertLogs("test_a2c", level="ERROR") as lcm:
            result = self.eabhandler._load_postgres_profiles()
        self.assertEqual(result, {})
        self.assertTrue(any("error" in msg.lower() for msg in lcm.output))

    def test_039b_postgres_connect_kwargs(self):
        """_postgres_connect passes host/dbname/user/password to psycopg2"""
        self.eabhandler.db_host = "pg-host"
        self.eabhandler.db_name = "pg-db"
        self.eabhandler.db_user = "pg-user"
        self.eabhandler.db_password = "pg-pass"
        mock_psycopg2 = MagicMock()
        with patch.dict(sys.modules, {"psycopg2": mock_psycopg2}):
            self.eabhandler._postgres_connect()
        mock_psycopg2.connect.assert_called_once_with(
            host="pg-host",
            dbname="pg-db",
            user="pg-user",
            password="pg-pass",
        )

    def test_039c_mssql_connect_conn_string(self):
        """_mssql_connect uses ODBC Driver 18 and Encrypt flags"""
        self.eabhandler.db_host = "sql-host"
        self.eabhandler.db_name = "sql-db"
        self.eabhandler.db_user = "sql-user"
        self.eabhandler.db_password = "sql-pass"
        mock_pyodbc = MagicMock()
        with patch.dict(sys.modules, {"pyodbc": mock_pyodbc}):
            self.eabhandler._mssql_connect()
        conn_str = mock_pyodbc.connect.call_args[0][0]
        self.assertIn("DRIVER={ODBC Driver 18 for SQL Server}", conn_str)
        self.assertIn("SERVER=sql-host", conn_str)
        self.assertIn("Encrypt=yes", conn_str)
        self.assertIn("TrustServerCertificate=yes", conn_str)
        self.assertNotIn("PostgreSQL", conn_str)

    @patch("acme2certifier.eabhandlers.sql_handler.EABhandler.key_file_load")
    def test_040_mac_key_get_valid_mssql(self, mock_key_file_load):
        """Valid key: should return mac_key"""
        self.eabhandler.db_host = "host"
        self.eabhandler.db_name = "name"
        self.eabhandler.db_user = "user"
        self.eabhandler.db_password = "pass"
        self.eabhandler.db_system = "mssql"

        mock_key_file_load.return_value = {
            "keyid_01": {
                "hmac": "hmac_01",
                "order": {"allowed_domainlist": ["127.0.0.1"]},
            },
            "keyid_02": {"hmac": "hmac_02"},
            "keyid_03": {
                "order": {"allowed_domainlist": ["127.0.0.1"]},
                "hmac": "hmac_03",
            },
        }

        result = self.eabhandler.mac_key_get("keyid_01")
        self.assertEqual(result, "hmac_01")
        result = self.eabhandler.mac_key_get("keyid_02")
        self.assertEqual(result, "hmac_02")
        result = self.eabhandler.mac_key_get("keyid_03")
        self.assertEqual(result, "hmac_03")

    @patch("acme2certifier.eabhandlers.sql_handler.EABhandler.key_file_load")
    def test_041_mac_key_get_valid_postgres(self, mock_key_file_load):
        """Valid key: should return mac_key"""
        self.eabhandler.db_host = "host"
        self.eabhandler.db_name = "name"
        self.eabhandler.db_user = "user"
        self.eabhandler.db_password = "pass"
        self.eabhandler.db_system = "postgres"

        mock_key_file_load.return_value = {
            "keyid_01": {
                "hmac": "hmac_01",
                "order": {"allowed_domainlist": ["127.0.0.1"]},
            },
            "keyid_02": {"hmac": "hmac_02"},
            "keyid_03": {
                "order": {"allowed_domainlist": ["127.0.0.1"]},
                "hmac": "hmac_03",
            },
        }

        result = self.eabhandler.mac_key_get("keyid_01")
        self.assertEqual(result, "hmac_01")
        result = self.eabhandler.mac_key_get("keyid_02")
        self.assertEqual(result, "hmac_02")
        result = self.eabhandler.mac_key_get("keyid_03")
        self.assertEqual(result, "hmac_03")

    @patch("acme2certifier.eabhandlers.sql_handler.EABhandler.key_file_load")
    def test_042_mac_key_get_missing_key(self, mock_key_file_load):
        """Missing key: should return None"""
        self.eabhandler.db_host = "host"
        self.eabhandler.db_name = "name"
        self.eabhandler.db_user = "user"
        self.eabhandler.db_password = "pass"
        mock_key_file_load.return_value = {
            "keyid_01": {
                "hmac": "hmac_01",
            }
        }
        result = self.eabhandler.mac_key_get("keyid_02")
        self.assertIsNone(result)

    def test_043_mac_key_get_missing_db_params(self):
        """Missing DB params: should return None and log error"""
        self.eabhandler.db_host = None
        self.eabhandler.db_name = None
        self.eabhandler.db_user = None
        self.eabhandler.db_password = None
        self.eabhandler.db_system = None
        with self.assertLogs("test_a2c", level="ERROR") as lcm:
            result = self.eabhandler.mac_key_get("key1")
        self.assertIsNone(result)
        self.assertTrue(any("error" in msg.lower() for msg in lcm.output))

    @patch("acme2certifier.eabhandlers.sql_handler.EABhandler.key_file_load")
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
        sys.modules["acme2certifier.acme_srv.db_handler"] = MagicMock(
            DBstore=dbstore_mock
        )
        with self.assertLogs("test_a2c", level="ERROR") as lcm:
            result = self.eabhandler.eab_kid_get("csr")
        self.assertIsNone(result)
        self.assertTrue(
            any("Database error while retrieving eab_kid" in msg for msg in lcm.output)
        )

    def test_046_eab_kid_get_revocation(self):
        """test EABhandler.eab_kid_get() with revocation=True uses cert_raw"""
        models_mock = MagicMock()
        models_mock.DBstore().certificate_lookup.return_value = {
            "order__account__eab_kid": "kid_rev"
        }
        modules = {"acme2certifier.acme_srv.db_handler": models_mock}
        patch.dict("sys.modules", modules).start()
        result = self.eabhandler.eab_kid_get("cert_raw_data", revocation=True)
        self.assertEqual(result, "kid_rev")
        call_args = models_mock.DBstore().certificate_lookup.call_args
        self.assertEqual(call_args[0][0], "cert_raw")

    @patch("acme2certifier.eabhandlers.sql_handler.EABhandler.key_file_load")
    @patch("acme2certifier.eabhandlers.sql_handler.EABhandler.eab_kid_get")
    def test_047_cahandler_name_get_dict(self, mock_kid, mock_prof):
        """cahandler_name_get reads cahandler_name from a dict profile entry"""
        mock_prof.return_value = {"kid1": {"cahandler_name": "openssl"}}
        mock_kid.return_value = "kid1"
        self.assertEqual(self.eabhandler.cahandler_name_get("csr"), "openssl")

    @patch("acme2certifier.eabhandlers.sql_handler.EABhandler.key_file_load")
    @patch("acme2certifier.eabhandlers.sql_handler.EABhandler.eab_kid_get")
    def test_048_cahandler_name_get_json_string(self, mock_kid, mock_prof):
        """cahandler_name_get parses a JSON string profile entry"""
        mock_prof.return_value = {"kid1": '{"cahandler_name": "ejbca"}'}
        mock_kid.return_value = "kid1"
        self.assertEqual(self.eabhandler.cahandler_name_get("csr"), "ejbca")

    @patch("acme2certifier.eabhandlers.sql_handler.EABhandler.key_file_load")
    @patch("acme2certifier.eabhandlers.sql_handler.EABhandler.eab_kid_get")
    def test_049_cahandler_name_get_invalid_json(self, mock_kid, mock_prof):
        """cahandler_name_get treats invalid JSON profile entries as empty"""
        mock_prof.return_value = {"kid1": "not-json"}
        mock_kid.return_value = "kid1"
        self.assertIsNone(self.eabhandler.cahandler_name_get("csr"))

    @patch("acme2certifier.eabhandlers.sql_handler.EABhandler._schema_ensure")
    @patch("acme2certifier.eabhandlers.sql_handler.EABhandler._mssql_connect")
    def test_050_load_mssql_profiles_invalid_json(self, mock_connect, _mock_schema):
        """Invalid json: should log error and return empty dict"""
        mock_conn, mock_cursor = self._mock_conn_with_rows(
            [
                (
                    "keyid_01",
                    '"hmac": "hmac_01", "order": "allowed_domainlist": ["127.0.0.1"}}',
                )
            ]
        )
        mock_connect.return_value = mock_conn
        with self.assertLogs("test_a2c", level="ERROR") as lcm:
            result = self.eabhandler._load_mssql_profiles()
        self.assertEqual(result, {})
        self.assertTrue(
            any("_load_mssql_profiles() error" in msg for msg in lcm.output)
        )
        self.assertTrue(mock_cursor.execute.called)

    @patch("acme2certifier.eabhandlers.sql_handler.EABhandler._schema_ensure")
    @patch("acme2certifier.eabhandlers.sql_handler.EABhandler._postgres_connect")
    def test_051_load_postgres_profiles_invalid_json(self, mock_connect, _mock_schema):
        """Invalid json: should log error and return empty dict"""
        mock_conn, mock_cursor = self._mock_conn_with_rows(
            [
                (
                    "keyid_01",
                    '"hmac": "hmac_01", "order": "allowed_domainlist": ["127.0.0.1"}}',
                )
            ]
        )
        mock_connect.return_value = mock_conn
        with self.assertLogs("test_a2c", level="ERROR") as lcm:
            result = self.eabhandler._load_postgres_profiles()
        self.assertEqual(result, {})
        self.assertTrue(
            any("_load_postgres_profiles() error" in msg for msg in lcm.output)
        )
        self.assertTrue(mock_cursor.execute.called)

    @patch("acme2certifier.eabhandlers.sql_handler.EABhandler._column_exists")
    @patch("acme2certifier.eabhandlers.sql_handler.EABhandler._table_exists")
    def test_052_schema_ensure_migrates_legacy_postgres(
        self, mock_table_exists, mock_column_exists
    ):
        """Legacy credentials table triggers rename to acme_credential/enabled"""
        mock_table_exists.side_effect = lambda _c, _s, name: name == "credentials"
        mock_column_exists.side_effect = (
            lambda _c, _s, _t, col: col == "status"
        )
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value = mock_cursor
        with self.assertLogs("test_a2c", level="WARNING") as lcm:
            self.eabhandler._schema_ensure(mock_conn, "postgres")
        executed = [call.args[0] for call in mock_cursor.execute.call_args_list]
        self.assertIn("ALTER TABLE credentials RENAME TO acme_credential", executed)
        self.assertIn(
            "ALTER TABLE acme_credential RENAME COLUMN status TO enabled", executed
        )
        mock_conn.commit.assert_called_once()
        self.assertTrue(any("legacy table 'credentials'" in msg for msg in lcm.output))

    @patch("acme2certifier.eabhandlers.sql_handler.EABhandler._column_exists")
    @patch("acme2certifier.eabhandlers.sql_handler.EABhandler._table_exists")
    def test_053_schema_ensure_noop_when_new(
        self, mock_table_exists, mock_column_exists
    ):
        """New schema present: no ALTER statements"""
        mock_table_exists.side_effect = lambda _c, _s, name: name == "acme_credential"
        mock_column_exists.return_value = False
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value = mock_cursor
        self.eabhandler._schema_ensure(mock_conn, "postgres")
        mock_cursor.execute.assert_not_called()
        mock_conn.commit.assert_called_once()

    @patch("acme2certifier.eabhandlers.sql_handler.EABhandler._column_exists")
    @patch("acme2certifier.eabhandlers.sql_handler.EABhandler._table_exists")
    def test_054_schema_ensure_migrates_legacy_mssql(
        self, mock_table_exists, mock_column_exists
    ):
        """Legacy credentials table on MSSQL uses sp_rename"""
        mock_table_exists.side_effect = lambda _c, _s, name: name == "credentials"
        mock_column_exists.side_effect = (
            lambda _c, _s, _t, col: col == "status"
        )
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value = mock_cursor
        self.eabhandler._schema_ensure(mock_conn, "mssql")
        executed = [call.args[0] for call in mock_cursor.execute.call_args_list]
        self.assertIn("EXEC sp_rename 'credentials', 'acme_credential'", executed)
        self.assertIn(
            "EXEC sp_rename 'acme_credential.status', 'enabled', 'COLUMN'", executed
        )


if __name__ == "__main__":

    if os.path.exists("acme_test.db"):
        os.remove("acme_test.db")
    unittest.main()
