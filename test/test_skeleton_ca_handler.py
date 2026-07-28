#!/usr/bin/python
# -*- coding: utf-8 -*-
"""unittests for skeleton_ca_handler"""

# pylint: disable=C0415, W0212
import sys
import unittest
from unittest.mock import patch
import configparser

sys.path.insert(0, ".")
sys.path.insert(1, "..")


class TestACMEHandler(unittest.TestCase):
    """test class for skeleton_ca_handler"""

    def setUp(self):
        """setup unittest"""
        import logging

        logging.basicConfig(level=logging.CRITICAL)
        self.logger = logging.getLogger("test_a2c")
        from acme2certifier.cahandlers.skeleton_ca_handler import CAhandler

        self.cahandler = CAhandler(False, self.logger)

    def test_001_default(self):
        """default test which always passes"""
        self.assertEqual("foo", "foo")

    @patch("acme2certifier.cahandlers.skeleton_ca_handler.CAhandler._config_load")
    def test_002__enter__(self, mock_cfg):
        """test enter calls _config_load when parameter is unset"""
        mock_cfg.return_value = True
        result = self.cahandler.__enter__()
        self.assertTrue(mock_cfg.called)
        self.assertEqual(result, self.cahandler)

    @patch("acme2certifier.cahandlers.skeleton_ca_handler.CAhandler._config_load")
    def test_003__enter__parameter_set(self, mock_cfg):
        """test enter skips _config_load when parameter is already set"""
        self.cahandler.parameter = "existing"
        result = self.cahandler.__enter__()
        self.assertFalse(mock_cfg.called)
        self.assertEqual(result, self.cahandler)

    def test_004__exit__(self):
        """test exit is a no-op"""
        self.assertIsNone(self.cahandler.__exit__(None, None, None))

    @patch("acme2certifier.cahandlers.skeleton_ca_handler.load_config")
    def test_005_config_load_without_parameter(self, mock_load_cfg):
        """test _config_load with empty CAhandler section"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"foo": "bar"}
        mock_load_cfg.return_value = parser
        self.cahandler._config_load()
        self.assertIsNone(self.cahandler.parameter)

    @patch("acme2certifier.cahandlers.skeleton_ca_handler.load_config")
    def test_006_config_load_with_parameter(self, mock_load_cfg):
        """test _config_load sets parameter from config"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"parameter": "value"}
        mock_load_cfg.return_value = parser
        self.cahandler._config_load()
        self.assertEqual("value", self.cahandler.parameter)

    def test_007_stub_func(self):
        """test _stub_func runs without error"""
        self.assertIsNone(self.cahandler._stub_func("payload"))

    @patch("acme2certifier.cahandlers.skeleton_ca_handler.header_info_get")
    @patch("acme2certifier.cahandlers.skeleton_ca_handler.CAhandler._stub_func")
    def test_008_enroll_without_header_info(self, mock_stub, mock_header):
        """test enroll with empty header info"""
        mock_header.return_value = []
        result = self.cahandler.enroll("csr")
        self.assertEqual((None, None, None, None), result)
        mock_stub.assert_called_once_with("csr")

    @patch("acme2certifier.cahandlers.skeleton_ca_handler.header_info_get")
    @patch("acme2certifier.cahandlers.skeleton_ca_handler.CAhandler._stub_func")
    def test_009_enroll_with_header_info(self, mock_stub, mock_header):
        """test enroll logs header info when present"""
        mock_header.return_value = [
            {"header_info": "first"},
            {"header_info": "last-header"},
        ]
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            result = self.cahandler.enroll("csr")
        self.assertEqual((None, None, None, None), result)
        self.assertIn("INFO:test_a2c:last-header", lcm.output)
        mock_stub.assert_called_once_with("csr")

    @patch("acme2certifier.cahandlers.skeleton_ca_handler.CAhandler._stub_func")
    def test_010_handler_check(self, mock_stub):
        """test handler_check calls stub and returns its result"""
        mock_stub.return_value = "stub-error"
        self.assertEqual("stub-error", self.cahandler.handler_check())
        mock_stub.assert_called_once_with("text")

    @patch("acme2certifier.cahandlers.skeleton_ca_handler.CAhandler._stub_func")
    def test_011_poll(self, mock_stub):
        """test poll returns pending stub response"""
        result = self.cahandler.poll("cert1", "poll-id", "csr")
        self.assertEqual((None, None, None, "poll-id", False), result)
        mock_stub.assert_called_once_with("cert1")

    def test_012_revoke(self):
        """test revoke returns not-supported serverInternal error"""
        self.assertEqual(
            (
                500,
                "urn:ietf:params:acme:error:serverInternal",
                "Revocation is not supported.",
            ),
            self.cahandler.revoke("cert", "keyCompromise", "2020-01-01"),
        )

    @patch("acme2certifier.cahandlers.skeleton_ca_handler.CAhandler._stub_func")
    def test_013_trigger(self, mock_stub):
        """test trigger returns stub response"""
        result = self.cahandler.trigger("payload")
        self.assertEqual((None, None, None), result)
        mock_stub.assert_called_once_with("payload")


if __name__ == "__main__":
    unittest.main()
