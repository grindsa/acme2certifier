import unittest
from unittest.mock import MagicMock, patch, ANY
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
        # Mock config_dic to behave like configparser.ConfigParser
        config_dic = MagicMock()
        config_dic.getboolean.return_value = False
        with patch("acme_srv.directory.load_config", return_value=config_dic):
            with patch("acme_srv.directory.config_async_mode_load", return_value=False) as mock_async_mode_load:
                with patch.object(
                    self.directory, "_parse_directory_section"
                ) as mock_parse_dir, patch.object(
                    self.directory, "_parse_booleans"
                ) as mock_parse_bool, patch.object(
                    self.directory, "_parse_eab_and_profiles"
                ) as mock_parse_eab, patch.object(
                    self.directory, "_load_ca_handler"
                ) as mock_load_ca, patch.object(
                    self.directory, "_parse_cahandler_section"
                ) as mock_parse_cahandler_section:
                    self.directory._load_configuration()
                    mock_parse_dir.assert_called()
                    mock_parse_bool.assert_called()
                    mock_parse_eab.assert_called()
                    mock_load_ca.assert_called()
                    mock_parse_cahandler_section.assert_called()
                    mock_async_mode_load.assert_called()

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

    def test_026_get_directory_response_profiles_sync_load_profiles(self):
        # Setup Directory with profiles_sync enabled and no error from handler_check
        self.directory.config.profiles_sync = True
        self.directory.config.acme_url = "https://acme.example.com"
        self.directory.config.profiles_sync_interval = 1234
        self.directory.config.async_mode = False
        self.directory.config.profiles = {}
        mock_cahandler_instance = MagicMock()
        mock_cahandler_instance.__enter__.return_value = mock_cahandler_instance
        mock_cahandler_instance.__exit__.return_value = None
        mock_cahandler_instance.handler_check.return_value = None
        mock_cahandler_instance.load_profiles.return_value = {"profile": "loaded"}
        self.directory.cahandler = MagicMock(return_value=mock_cahandler_instance)
        # Ensure hasattr returns True for load_profiles
        with patch.object(mock_cahandler_instance, "load_profiles", wraps=mock_cahandler_instance.load_profiles):
            resp = self.directory.get_directory_response()
            self.assertEqual(self.directory.config.profiles, {"profile": "loaded"})
            self.assertIn("newAuthz", resp)

    def test_027_get_directory_response_no_cahandler(self):
        self.directory.cahandler = None
        with patch.object(self.mock_logger, "critical") as mock_critical:
            resp = self.directory.get_directory_response()
            self.assertIn("error", resp)
            mock_critical.assert_called()

    def test_028_profile_list_get_success(self):
        mock_dbstore = MagicMock()
        profiles_json = None
        mock_dbstore.hkparameter_get.return_value = profiles_json
        repo = DirectoryRepository(mock_dbstore, self.mock_logger)
        self.assertFalse(repo.profile_list_get())

    def test_029_profile_list_get_success(self):
        mock_dbstore = MagicMock()
        profiles_json = '[{"name": "profile1"}, {"name": "profile2"}]'
        mock_dbstore.hkparameter_get.return_value = profiles_json
        repo = DirectoryRepository(mock_dbstore, self.mock_logger)
        result = repo.profile_list_get()
        self.assertEqual(result, [{"name": "profile1"}, {"name": "profile2"}])

    def test_030_profile_list_get_db_exception(self):
        mock_dbstore = MagicMock()
        mock_dbstore.hkparameter_get.side_effect = Exception("fail")
        repo = DirectoryRepository(mock_dbstore, self.mock_logger)
        with patch.object(self.mock_logger, "critical") as mock_critical:
            result = repo.profile_list_get()
            self.assertEqual(result, [])
            mock_critical.assert_called()

    def test_031_profile_list_get_json_error(self):
        mock_dbstore = MagicMock()
        # Use an invalid JSON string to ensure json.loads fails
        mock_dbstore.hkparameter_get.return_value = "{invalid_json: true]"
        repo = DirectoryRepository(mock_dbstore, self.mock_logger)
        with patch.object(self.mock_logger, "error") as mock_error:
            result = repo.profile_list_get()
            self.assertEqual(result, [])
            mock_error.assert_called()

    def test_032_profile_list_set_success(self):
        mock_dbstore = MagicMock()
        repo = DirectoryRepository(mock_dbstore, self.mock_logger)
        data_dic = {"profiles": ["profile1", "profile2"]}
        repo.profile_list_set(data_dic)
        mock_dbstore.hkparameter_add.assert_called_once_with(data_dic)

    def test_033_profile_list_set_db_exception(self):
        mock_dbstore = MagicMock()
        mock_dbstore.hkparameter_add.side_effect = Exception("fail")
        repo = DirectoryRepository(mock_dbstore, self.mock_logger)
        data_dic = {"profiles": ["profile1", "profile2"]}
        with patch.object(self.mock_logger, "critical") as mock_critical:
            repo.profile_list_set(data_dic)
            mock_critical.assert_called()

    def test_034_parse_cahandler_section_profiles_sync_exception(self):
        config_dic = MagicMock()
        config_dic.__contains__.side_effect = lambda k: k == "CAhandler"
        config_dic.__getitem__.side_effect = lambda k: {"acme_url": "https://acme.example.com"} if k == "CAhandler" else None
        config_dic.getboolean.side_effect = Exception("fail")
        with patch.object(self.mock_logger, "error") as mock_error:
            self.directory._parse_cahandler_section(config_dic)
            mock_error.assert_any_call("profiles_sync not set: %s", ANY)

    def test_035_parse_cahandler_section_sets_acme_url(self):
        config_dic = MagicMock()
        config_dic.__contains__.side_effect = lambda k: k == "CAhandler"
        config_dic.__getitem__.side_effect = lambda k: {"acme_url": "https://acme.example.com"} if k == "CAhandler" else None
        config_dic.getboolean.side_effect = lambda section, key, fallback=None: False
        self.directory._parse_cahandler_section(config_dic)
        self.assertEqual(self.directory.config.acme_url, "https://acme.example.com")

    def test_036_parse_cahandler_section_profiles_sync_disabled(self):
        config_dic = MagicMock()
        config_dic.__contains__.side_effect = lambda k: k == "CAhandler"
        config_dic.__getitem__.side_effect = lambda k: {"acme_url": "https://acme.example.com"} if k == "CAhandler" else None
        config_dic.getboolean.side_effect = lambda section, key, fallback=None: False
        self.directory.config.profiles = {}
        self.directory._parse_cahandler_section(config_dic)
        self.assertFalse(self.directory.config.profiles_sync)

    def test_037_parse_cahandler_section_profiles_sync_enabled_profiles_configured(self):
        config_dic = MagicMock()
        config_dic.__contains__.side_effect = lambda k: k == "CAhandler"
        config_dic.__getitem__.side_effect = lambda k: {"acme_url": "https://acme.example.com"} if k == "CAhandler" else None
        # First call to getboolean returns True for profiles_sync
        config_dic.getboolean.side_effect = lambda section, key, fallback=None: True if key == "profiles_sync" else False
        self.directory.config.profiles = {"profile": "data"}
        with patch.object(self.mock_logger, "error") as mock_error:
            self.directory._parse_cahandler_section(config_dic)
            self.assertFalse(self.directory.config.profiles_sync)
            mock_error.assert_any_call("Profiles are configured via acme_srv.cfg. Disabling profile sync.")

    def test_038_parse_cahandler_section_profiles_sync_enabled_no_acme_url(self):
        config_dic = MagicMock()
        config_dic.__contains__.side_effect = lambda k: k == "CAhandler"
        config_dic.__getitem__.side_effect = lambda k: {} if k == "CAhandler" else None
        config_dic.getboolean.side_effect = lambda section, key, fallback=None: True if key == "profiles_sync" else False
        self.directory.config.profiles = {}
        self.directory.config.acme_url = None
        with patch.object(self.mock_logger, "error") as mock_error:
            self.directory._parse_cahandler_section(config_dic)
            self.assertFalse(self.directory.config.profiles_sync)
            mock_error.assert_any_call("profiles_sync is set but no acme_url configured.")

    def test_039_parse_cahandler_section_profiles_sync_interval_set(self):
        config_dic = MagicMock()
        config_dic.__contains__.side_effect = lambda k: k == "CAhandler"
        config_dic.__getitem__.side_effect = lambda k: {"acme_url": "https://acme.example.com"} if k == "CAhandler" else None
        config_dic.getboolean.side_effect = lambda section, key, fallback=None: True if key == "profiles_sync" else False
        config_dic.getint.side_effect = lambda section, key, fallback=None: 1234 if key == "profiles_sync_interval" else fallback
        self.directory.config.profiles = {}
        self.directory.config.acme_url = "https://acme.example.com"
        self.directory.config.profiles_sync = False
        self.directory._parse_cahandler_section(config_dic)
        self.assertEqual(self.directory.config.profiles_sync_interval, 1234)

    def test_040_parse_cahandler_section_profiles_sync_interval_error(self):
        config_dic = MagicMock()
        config_dic.__contains__.side_effect = lambda k: k == "CAhandler"
        config_dic.__getitem__.side_effect = lambda k: {"acme_url": "https://acme.example.com"} if k == "CAhandler" else None
        config_dic.getboolean.side_effect = lambda section, key, fallback=None: True if key == "profiles_sync" else False
        config_dic.getint.side_effect = Exception("fail")
        self.directory.config.profiles = {}
        self.directory.config.acme_url = "https://acme.example.com"
        self.directory.config.profiles_sync = False
        with patch.object(self.mock_logger, "error") as mock_error:
            self.directory._parse_cahandler_section(config_dic)
            mock_error.assert_any_call("profiles_sync_interval not set: %s", ANY)


if __name__ == "__main__":
    unittest.main()
