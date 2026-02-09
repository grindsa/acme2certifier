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


class TestACMEHandler(unittest.TestCase):
    """test class for sql_handler"""

    def setUp(self):
        """setup unit test"""
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

