import unittest
from unittest.mock import MagicMock, patch
import os
import sys

# Add the parent directory to sys.path so we can import acme_srv
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from acme_srv.directory import Directory, DirectoryConfig, DirectoryRepository


class TestDirectory(unittest.TestCase):
    def setUp(self):
        self.mock_logger = MagicMock()
        self.mock_dbstore = MagicMock()
        self.mock_repository = DirectoryRepository(self.mock_dbstore, self.mock_logger)
        self.mock_config = DirectoryConfig()
        self.mock_cahandler = MagicMock()
        self.mock_cahandler_instance = MagicMock()
        self.mock_cahandler.return_value = self.mock_cahandler_instance
        self.mock_cahandler_instance.__enter__.return_value = (
            self.mock_cahandler_instance
        )
        self.mock_cahandler_instance.__exit__.return_value = None
        self.mock_cahandler_instance.handler_check.return_value = None
        self.directory = Directory(
            debug=None, srv_name="http://localhost", logger=self.mock_logger
        )
        self.directory.dbstore = self.mock_dbstore
        self.directory.repository = self.mock_repository
        self.directory.config = self.mock_config
        self.directory.cahandler = self.mock_cahandler

    def test_001_context_manager(self):
        with patch.object(self.directory, "_load_configuration") as mock_load_config:
            with self.directory as d:
                mock_load_config.assert_called_once()
                self.assertIs(d, self.directory)

    def test_002_load_configuration(self):
        with patch("acme_srv.directory.load_config", return_value={"Directory": {}}):
            with patch.object(
                self.directory, "_parse_directory_section"
            ) as mock_parse_dir, patch.object(
                self.directory, "_parse_booleans"
            ) as mock_parse_bool, patch.object(
                self.directory, "_parse_eab_and_profiles"
            ) as mock_parse_eab, patch.object(
                self.directory, "_load_ca_handler"
            ) as mock_load_ca:
                self.directory._load_configuration()
                mock_parse_dir.assert_called()
                mock_parse_bool.assert_called()
                mock_parse_eab.assert_called()
                mock_load_ca.assert_called()

    def test_003_parse_directory_section_sets_config(self):
        # Mock config_dic to behave like configparser.ConfigParser
        config_dic = MagicMock()
        config_dic.__contains__.side_effect = lambda k: k == "Directory"
        config_dic.__getitem__.side_effect = (
            lambda k: {"tos_url": "tos", "url_prefix": "/prefix", "home": "custom_home"}
            if k == "Directory"
            else None
        )
        config_dic.get.side_effect = lambda section, key, fallback=None: None
        self.directory._parse_directory_section(config_dic)
        self.assertEqual(self.directory.config.tos_url, "tos")
        self.assertEqual(self.directory.config.url_prefix, "/prefix")
        self.assertEqual(self.directory.config.home, "custom_home")

    def test_004_parse_caaidentities_json(self):
        value = '["id1", "id2"]'
        result = self.directory._parse_caaidentities(value)
        self.assertEqual(result, ["id1", "id2"])

    def test_005_parse_caaidentities_fallback(self):
        value = "id1"
        result = self.directory._parse_caaidentities(value)
        self.assertEqual(result, ["id1"])

    def test_006_parse_caaidentities_error(self):
        value = "[invalid_json]"
        with patch.object(self.mock_logger, "error") as mock_error:
            result = self.directory._parse_caaidentities(value)
            self.assertEqual(result, [])
            mock_error.assert_called()

    def test_007_parse_booleans(self):
        config_dic = MagicMock()
        config_dic.getboolean.side_effect = lambda section, key, fallback: True
        self.directory._parse_booleans(config_dic)
        self.assertTrue(self.directory.config.supress_version)
        self.assertTrue(self.directory.config.db_check)
        self.assertTrue(self.directory.config.suppress_product_information)

    def test_008_parse_booleans_error(self):
        config_dic = MagicMock()
        config_dic.getboolean.side_effect = Exception("fail")
        with patch.object(self.mock_logger, "error") as mock_error:
            self.directory._parse_booleans(config_dic)
            self.assertTrue(mock_error.called)

    def test_009_parse_eab_and_profiles(self):
        config_dic = {"EABhandler": {"eab_handler_file": "file"}}
        with patch(
            "acme_srv.directory.config_profile_load", return_value={"profile": "data"}
        ):
            self.directory._parse_eab_and_profiles(config_dic)
            self.assertTrue(self.directory.config.eab)
            self.assertEqual(self.directory.config.profiles, {"profile": "data"})

    def test_010_load_ca_handler_success(self):
        config_dic = {}
        ca_handler_module = MagicMock()
        ca_handler_module.CAhandler = MagicMock()
        with patch(
            "acme_srv.directory.ca_handler_load", return_value=ca_handler_module
        ):
            self.directory._load_ca_handler(config_dic)
            self.assertEqual(self.directory.cahandler, ca_handler_module.CAhandler)

    def test_011_load_ca_handler_failure(self):
        config_dic = {}
        with patch("acme_srv.directory.ca_handler_load", return_value=None):
            with patch.object(self.mock_logger, "critical") as mock_critical:
                self.directory._load_ca_handler(config_dic)
                mock_critical.assert_called()

    def test_012_build_meta_information(self):
        self.directory.config.suppress_product_information = False
        self.directory.config.supress_version = False
        self.directory.config.tos_url = "tos"
        self.directory.config.caaidentities = ["id1"]
        self.directory.config.profiles = {"profile": "data"}
        self.directory.config.eab = True
        meta = self.directory._build_meta_information()
        self.assertIn("home", meta)
        self.assertIn("author", meta)
        self.assertIn("name", meta)
        self.assertIn("version", meta)
        self.assertIn("termsOfService", meta)
        self.assertIn("caaIdentities", meta)
        self.assertIn("profiles", meta)
        self.assertIn("externalAccountRequired", meta)

    def test_013_build_meta_information_suppress(self):
        self.directory.config.suppress_product_information = True
        self.directory.config.home = "custom_home"
        meta = self.directory._build_meta_information()
        self.assertIn("home", meta)
        self.assertNotIn("author", meta)
        self.assertNotIn("name", meta)
        self.assertNotIn("version", meta)

    def test_014_build_directory_response_db_check_ok(self):
        self.directory.config.db_check = True
        self.directory.dbversion = "1.0"
        self.directory.repository = self.mock_repository
        with patch.object(
            self.mock_repository, "get_db_version", return_value=("1.0", "script")
        ):
            resp = self.directory._build_directory_response()
            self.assertEqual(resp["meta"]["db_check"], "OK")

    def test_015_build_directory_response_db_check_nok(self):
        self.directory.config.db_check = True
        self.directory.dbversion = "1.0"
        self.directory.repository = self.mock_repository
        with patch.object(
            self.mock_repository, "get_db_version", return_value=("2.0", "script")
        ):
            with patch.object(self.mock_logger, "error") as mock_error:
                resp = self.directory._build_directory_response()
                self.assertEqual(resp["meta"]["db_check"], "NOK")
                mock_error.assert_called()

    def test_016_build_directory_response_db_exception(self):
        self.directory.config.db_check = True
        self.directory.dbversion = "1.0"
        self.directory.repository = self.mock_repository
        with patch.object(
            self.mock_repository, "get_db_version", return_value=(None, None)
        ):
            with patch.object(self.mock_logger, "error") as mock_error:
                resp = self.directory._build_directory_response()
                self.assertEqual(resp["meta"]["db_check"], "NOK")
                mock_error.assert_called()

    def test_017_build_directory_response_random_key(self):
        resp = self.directory._build_directory_response()
        found_random = any(
            v
            == "https://community.letsencrypt.org/t/adding-random-entries-to-the-directory/33417"
            for v in resp.values()
        )
        self.assertTrue(found_random)

    def test_018_get_directory_response_success(self):
        self.directory.cahandler = self.mock_cahandler
        self.mock_cahandler_instance.handler_check.return_value = None
        resp = self.directory.get_directory_response()
        self.assertIn("newAuthz", resp)
        self.assertIn("meta", resp)

    def test_019_get_directory_response_error(self):
        self.directory.cahandler = self.mock_cahandler
        self.mock_cahandler_instance.handler_check.return_value = "error"
        resp = self.directory.get_directory_response()
        self.assertIn("error", resp)

    def test_020_get_directory_response_no_handler(self):
        self.directory.cahandler = None
        resp = self.directory.get_directory_response()
        self.assertIn("error", resp)

    def test_021_directory_get(self):
        with patch.object(
            self.directory, "get_directory_response", return_value={"key": "value"}
        ):
            resp = self.directory.directory_get()
            self.assertEqual(resp, {"key": "value"})

    def test_022_servername_get(self):
        self.directory.server_name = "test_server"
        self.assertEqual(self.directory.servername_get(), "test_server")

    def test_023_parse_directory_section_calls_parse_caaidentities(self):
        # Mock config_dic to behave like configparser.ConfigParser
        config_dic = MagicMock()
        config_dic.__contains__.side_effect = lambda k: k == "Directory"
        config_dic.__getitem__.side_effect = (
            lambda k: {"tos_url": "tos", "url_prefix": "/prefix", "home": "custom_home"}
            if k == "Directory"
            else None
        )
        # Return a non-None value for caaidentities
        config_dic.get.side_effect = (
            lambda section, key, fallback=None: '["id1", "id2"]'
            if key == "caaidentities"
            else None
        )
        with patch.object(
            self.directory,
            "_parse_caaidentities",
            wraps=self.directory._parse_caaidentities,
        ) as mock_parse_caaidentities:
            self.directory._parse_directory_section(config_dic)
            mock_parse_caaidentities.assert_called_once_with('["id1", "id2"]')

    def test_024_repository_get_db_version_success(self):
        mock_dbstore = MagicMock()
        mock_dbstore.dbversion_get.return_value = ("1.0", "script")
        repo = DirectoryRepository(mock_dbstore, self.mock_logger)
        result = repo.get_db_version()
        self.assertEqual(result, ("1.0", "script"))

    def test_025_repository_get_db_version_exception(self):
        mock_dbstore = MagicMock()
        mock_dbstore.dbversion_get.side_effect = Exception("fail")
        repo = DirectoryRepository(mock_dbstore, self.mock_logger)
        with patch.object(self.mock_logger, "critical") as mock_critical:
            result = repo.get_db_version()
            self.assertEqual(result, (None, None))
            mock_critical.assert_called()


if __name__ == "__main__":
    unittest.main()
