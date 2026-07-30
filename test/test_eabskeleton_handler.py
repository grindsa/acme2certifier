#!/usr/bin/python
# -*- coding: utf-8 -*-
"""unittests for acme2certifier"""

# pylint: disable=C0415, W0212
import unittest
import sys
import os
from unittest.mock import patch
import configparser

sys.path.insert(0, ".")
sys.path.insert(1, "..")


class TestACMEHandler(unittest.TestCase):
    """test class for skeleton_eab_handler"""

    def setUp(self):
        """setup unittest"""
        import logging

        logging.basicConfig(level=logging.CRITICAL)
        self.logger = logging.getLogger("test_a2c")
        from acme2certifier.eabhandlers.skeleton_eab_handler import EABhandler

        self.eabhandler = EABhandler(self.logger)
        self.dir_path = os.path.dirname(os.path.realpath(__file__))

    def test_001_default(self):
        """default test which always passes"""
        self.assertEqual("foo", "foo")

    @patch("acme2certifier.eabhandlers.skeleton_eab_handler.EABhandler._config_load")
    def test_002__enter__(self, mock_cfg):
        """test enter calls _config_load when key is unset"""
        mock_cfg.return_value = True
        self.eabhandler.__enter__()
        self.assertTrue(mock_cfg.called)

    @patch("acme2certifier.eabhandlers.skeleton_eab_handler.EABhandler._config_load")
    def test_003__enter__key_set(self, mock_cfg):
        """test enter skips _config_load when key is already set"""
        self.eabhandler.key = "existing"
        result = self.eabhandler.__enter__()
        self.assertFalse(mock_cfg.called)
        self.assertEqual(result, self.eabhandler)

    def test_004__exit__(self):
        """test exit is a no-op"""
        self.assertIsNone(self.eabhandler.__exit__(None, None, None))

    @patch("acme2certifier.eabhandlers.skeleton_eab_handler.load_config")
    def test_005_config_load(self, mock_load_cfg):
        """test _config_load - empty dictionary"""
        parser = configparser.ConfigParser()
        mock_load_cfg.return_value = parser
        self.eabhandler._config_load()
        self.assertIsNone(self.eabhandler.key)

    @patch("acme2certifier.eabhandlers.skeleton_eab_handler.load_config")
    def test_006_config_load(self, mock_load_cfg):
        """test _config_load - section without key"""
        parser = configparser.ConfigParser()
        parser["EABhandler"] = {"foo": "bar"}
        mock_load_cfg.return_value = parser
        self.eabhandler._config_load()
        self.assertIsNone(self.eabhandler.key)

    @patch("acme2certifier.eabhandlers.skeleton_eab_handler.load_config")
    def test_007_config_load(self, mock_load_cfg):
        """test _config_load - key present"""
        parser = configparser.ConfigParser()
        parser["EABhandler"] = {"key": "secret"}
        mock_load_cfg.return_value = parser
        self.eabhandler._config_load()
        self.assertEqual("secret", self.eabhandler.key)

    def test_008_allowed_domains_check(self):
        """test allowed_domains_check returns ERROR"""
        self.assertEqual("ERROR", self.eabhandler.allowed_domains_check("csr", "value"))

    def test_009_mac_key_get(self):
        """test mac_key_get returns stub mac_key"""
        self.assertEqual("mac_key", self.eabhandler.mac_key_get("kid"))


if __name__ == "__main__":

    unittest.main()
