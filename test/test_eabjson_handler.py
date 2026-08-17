#!/usr/bin/python
# -*- coding: utf-8 -*-
"""unittests for acme2certifier"""

# pylint: disable= C0415, W0212
import unittest
import sys
import os
from OpenSSL import crypto
from unittest.mock import patch, Mock, MagicMock, mock_open
import requests
import configparser

sys.path.insert(0, ".")
sys.path.insert(1, "..")


class TestACMEHandler(unittest.TestCase):
    """test class for cgi_handler"""

    def setUp(self):
        """setup unittest"""
        import logging

        logging.basicConfig(level=logging.CRITICAL)
        self.logger = logging.getLogger("test_a2c")
        from acme2certifier.eabhandlers.json_handler import EABhandler

        self.eabhandler = EABhandler(self.logger)
        self.dir_path = os.path.dirname(os.path.realpath(__file__))

    def test_001_default(self):
        """default test which always passes"""
        self.assertEqual("foo", "foo")

    @patch("acme2certifier.eabhandlers.json_handler.EABhandler._config_load")
    def test_002__enter__(self, mock_cfg):
        """test enter  called"""
        mock_cfg.return_value = True
        self.eabhandler.__enter__()
        self.assertTrue(mock_cfg.called)

    @patch("acme2certifier.eabhandlers.json_handler.load_config")
    def test_003_config_load(self, mock_load_cfg):
        """test _config_load - empty dictionary"""
        parser = configparser.ConfigParser()
        mock_load_cfg.return_value = parser
        self.eabhandler._config_load()
        self.assertFalse(self.eabhandler.key_file)

    @patch("acme2certifier.eabhandlers.json_handler.load_config")
    def test_004_config_load(self, mock_load_cfg):
        """test _config_load - bogus values"""
        parser = configparser.ConfigParser()
        parser["foo"] = {"foo": "bar"}
        mock_load_cfg.return_value = parser
        self.eabhandler._config_load()
        self.assertFalse(self.eabhandler.key_file)

    @patch("acme2certifier.eabhandlers.json_handler.load_config")
    def test_005_config_load(self, mock_load_cfg):
        """test _config_load - bogus values"""
        parser = configparser.ConfigParser()
        parser["EABhandler"] = {"foo": "bar"}
        mock_load_cfg.return_value = parser
        self.eabhandler._config_load()
        self.assertFalse(self.eabhandler.key_file)

    @patch("acme2certifier.eabhandlers.json_handler.load_config")
    def test_006_config_load(self, mock_load_cfg):
        """test _config_load - bogus values"""
        parser = configparser.ConfigParser()
        parser["EABhandler"] = {"key_file": "key_file"}
        mock_load_cfg.return_value = parser
        self.eabhandler._config_load()
        self.assertEqual("key_file", self.eabhandler.key_file)

    def test_007_mac_key_get(self):
        """test mac_key_get without file specified and without kid"""
        with self.assertLogs("test_a2c", level="WARNING") as lcm:
            self.assertFalse(self.eabhandler.mac_key_get(None))
        self.assertIn("WARNING:test_a2c:MAC key retrieval failed: kid=None", lcm.output)

    def test_008_mac_key_get_missing_key_file(self):
        """test mac_key_get with kid but no key_file"""
        with self.assertLogs("test_a2c", level="WARNING") as lcm:
            self.assertFalse(self.eabhandler.mac_key_get("kid"))
        self.assertIn(
            "WARNING:test_a2c:MAC key retrieval failed: key_file is None",
            lcm.output,
        )

    @patch("builtins.open", mock_open(read_data="foo"), create=True)
    def test_009_mac_key_get(self):
        """test mac_key_get with file but no kid"""
        self.eabhandler.key_file = "file"
        with self.assertLogs("test_a2c", level="WARNING") as lcm:
            self.assertFalse(self.eabhandler.mac_key_get(None))
        self.assertIn("WARNING:test_a2c:MAC key retrieval failed: kid=None", lcm.output)

    @patch("json.load")
    @patch("builtins.open", mock_open(read_data="foo"), create=True)
    def test_010_mac_key_get(self, mock_json):
        """test mac_key_get json reader return bogus values"""
        self.eabhandler.key_file = "file"
        mock_json.return_value = {"foo", "bar"}
        with self.assertLogs("test_a2c", level="WARNING") as lcm:
            self.assertFalse(self.eabhandler.mac_key_get("kid"))
        self.assertIn(
            "WARNING:test_a2c:MAC key retrieval failed: kid=kid not found in key file",
            lcm.output,
        )

    @patch("json.load")
    @patch("builtins.open", mock_open(read_data="foo"), create=True)
    def test_011_mac_key_get(self, mock_json):
        """test mac_key_get json match"""
        self.eabhandler.key_file = "file"
        mock_json.return_value = {"kid": "mac"}
        self.assertEqual("mac", self.eabhandler.mac_key_get("kid"))

    @patch("json.load")
    @patch("builtins.open", mock_open(read_data="foo"), create=True)
    def test_012_mac_key_get(self, mock_json):
        """test mac_key_get json no match"""
        self.eabhandler.key_file = "file"
        mock_json.return_value = {"kid1": "mac"}
        with self.assertLogs("test_a2c", level="WARNING") as lcm:
            self.assertFalse(self.eabhandler.mac_key_get("kid"))
        self.assertIn(
            "WARNING:test_a2c:MAC key retrieval failed: kid=kid not found in key file",
            lcm.output,
        )

    @patch("json.load")
    @patch("builtins.open", mock_open(read_data="foo"), create=True)
    def test_013_mac_key_get(self, mock_json):
        """test mac_key_get json load exception"""
        self.eabhandler.key_file = "file"
        mock_json.side_effect = Exception("ex_json_load")
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.assertFalse(self.eabhandler.mac_key_get("kid"))
        self.assertIn(
            "ERROR:test_a2c:Failed to load EAB key file: ex_json_load", lcm.output
        )
        self.assertIn(
            "WARNING:test_a2c:MAC key retrieval failed: kid=kid not found in key file",
            lcm.output,
        )


if __name__ == "__main__":

    unittest.main()
