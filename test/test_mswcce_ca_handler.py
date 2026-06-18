#!/usr/bin/python
# -*- coding: utf-8 -*-
"""unittests for openssl_ca_handler"""

# pylint: disable=C0415, R0904, R0913, W0212
import os
import subprocess
import sys
import unittest
from unittest.mock import patch, mock_open, Mock
import configparser

sys.path.insert(0, ".")
sys.path.insert(1, "..")


class TestACMEHandler(unittest.TestCase):
    """test class for mswcce_ca_handler"""

    def setUp(self):
        """setup unittest"""
        import logging
        from examples.ca_handler.mswcce_ca_handler import CAhandler

        logging.basicConfig(level=logging.CRITICAL)
        self.logger = logging.getLogger("test_a2c")
        self.cahandler = CAhandler(False, self.logger)

    def tearDown(self):
        """teardown"""
        pass

    def test_001_default(self):
        """default test which always passes"""
        self.assertEqual("foo", "foo")

    @patch("examples.ca_handler.mswcce_ca_handler.load_config")
    def test_002_config_load(self, mock_load_cfg):
        """test _config_load no cahandler section"""
        parser = configparser.ConfigParser()
        self.cahandler._config_load()
        self.assertFalse(self.cahandler.host)
        self.assertFalse(self.cahandler.user)
        self.assertFalse(self.cahandler.password)
        self.assertFalse(self.cahandler.template)
        self.assertFalse(self.cahandler.proxy)
        self.assertFalse(self.cahandler.target_domain)
        self.assertFalse(self.cahandler.domain_controller)
        self.assertFalse(self.cahandler.ca_name)
        self.assertFalse(self.cahandler.ca_bundle)
        self.assertFalse(self.cahandler.use_kerberos)
        self.assertEqual(5, self.cahandler.timeout)

    @patch("examples.ca_handler.mswcce_ca_handler.load_config")
    def test_003_config_load(self, mock_load_cfg):
        """test _config_load wrongly configured cahandler section"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"foo": "bar"}
        mock_load_cfg.return_value = parser
        self.cahandler._config_load()
        self.assertFalse(self.cahandler.host)
        self.assertFalse(self.cahandler.user)
        self.assertFalse(self.cahandler.password)
        self.assertFalse(self.cahandler.template)
        self.assertFalse(self.cahandler.proxy)
        self.assertFalse(self.cahandler.target_domain)
        self.assertFalse(self.cahandler.domain_controller)
        self.assertFalse(self.cahandler.ca_name)
        self.assertFalse(self.cahandler.ca_bundle)
        self.assertFalse(self.cahandler.use_kerberos)
        self.assertEqual(5, self.cahandler.timeout)

    @patch.dict("os.environ", {"host_var": "host_var"})
    @patch("examples.ca_handler.mswcce_ca_handler.load_config")
    def test_004_config_load(self, mock_load_cfg):
        """test _config_load - load host from variable"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"host_variable": "host_var"}
        mock_load_cfg.return_value = parser
        self.cahandler._config_load()
        self.assertEqual("host_var", self.cahandler.host)
        self.assertFalse(self.cahandler.user)
        self.assertFalse(self.cahandler.password)
        self.assertFalse(self.cahandler.template)
        self.assertFalse(self.cahandler.proxy)
        self.assertFalse(self.cahandler.target_domain)
        self.assertFalse(self.cahandler.domain_controller)
        self.assertFalse(self.cahandler.ca_name)
        self.assertFalse(self.cahandler.ca_bundle)
        self.assertFalse(self.cahandler.use_kerberos)

    @patch.dict("os.environ", {"host_var": "host_var"})
    @patch("examples.ca_handler.mswcce_ca_handler.load_config")
    def test_005_config_load(self, mock_load_cfg):
        """test _config_load - load host from not_existing variable"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"host_variable": "unk"}
        mock_load_cfg.return_value = parser
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.cahandler._config_load()
        self.assertFalse(self.cahandler.host)
        self.assertFalse(self.cahandler.user)
        self.assertFalse(self.cahandler.password)
        self.assertFalse(self.cahandler.template)
        self.assertFalse(self.cahandler.proxy)
        self.assertFalse(self.cahandler.target_domain)
        self.assertFalse(self.cahandler.domain_controller)
        self.assertFalse(self.cahandler.ca_name)
        self.assertFalse(self.cahandler.ca_bundle)
        self.assertIn(
            "ERROR:test_a2c:Unable to load host variable from environment: 'unk'",
            lcm.output,
        )
        self.assertFalse(self.cahandler.use_kerberos)
        self.assertEqual(5, self.cahandler.timeout)

    @patch.dict("os.environ", {"host_var": "host_var"})
    @patch("examples.ca_handler.mswcce_ca_handler.load_config")
    def test_006_config_load(self, mock_load_cfg):
        """test _config_load - overwrite host variable"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"host_variable": "host_var", "host": "host_local"}
        mock_load_cfg.return_value = parser
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.cahandler._config_load()
        self.assertEqual("host_local", self.cahandler.host)
        self.assertFalse(self.cahandler.user)
        self.assertFalse(self.cahandler.password)
        self.assertFalse(self.cahandler.template)
        self.assertFalse(self.cahandler.proxy)
        self.assertFalse(self.cahandler.target_domain)
        self.assertFalse(self.cahandler.domain_controller)
        self.assertFalse(self.cahandler.ca_name)
        self.assertFalse(self.cahandler.ca_bundle)
        self.assertIn("INFO:test_a2c:Overwrite host", lcm.output)
        self.assertFalse(self.cahandler.use_kerberos)

    @patch("examples.ca_handler.mswcce_ca_handler.load_config")
    def test_007_config_load(self, mock_load_cfg):
        """test _config_load - load host from config file"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"host": "host_local"}
        mock_load_cfg.return_value = parser
        self.cahandler._config_load()
        self.assertEqual("host_local", self.cahandler.host)
        self.assertFalse(self.cahandler.user)
        self.assertFalse(self.cahandler.password)
        self.assertFalse(self.cahandler.template)
        self.assertFalse(self.cahandler.proxy)
        self.assertFalse(self.cahandler.target_domain)
        self.assertFalse(self.cahandler.domain_controller)
        self.assertFalse(self.cahandler.ca_name)
        self.assertFalse(self.cahandler.ca_bundle)
        self.assertFalse(self.cahandler.use_kerberos)

    @patch.dict("os.environ", {"user_var": "user_var"})
    @patch("examples.ca_handler.mswcce_ca_handler.load_config")
    def test_008_config_load(self, mock_load_cfg):
        """test _config_load - load user from variable"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"user_variable": "user_var"}
        mock_load_cfg.return_value = parser
        self.cahandler._config_load()
        self.assertFalse(self.cahandler.host)
        self.assertEqual("user_var", self.cahandler.user)
        self.assertFalse(self.cahandler.password)
        self.assertFalse(self.cahandler.template)
        self.assertFalse(self.cahandler.proxy)
        self.assertFalse(self.cahandler.target_domain)
        self.assertFalse(self.cahandler.domain_controller)
        self.assertFalse(self.cahandler.ca_name)
        self.assertFalse(self.cahandler.ca_bundle)
        self.assertFalse(self.cahandler.use_kerberos)

    @patch.dict("os.environ", {"user_var": "user_var"})
    @patch("examples.ca_handler.mswcce_ca_handler.load_config")
    def test_009_config_load(self, mock_load_cfg):
        """test _config_load - load user from not existing variable"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"user_variable": "unk"}
        mock_load_cfg.return_value = parser
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.cahandler._config_load()
        self.assertFalse(self.cahandler.host)
        self.assertFalse(self.cahandler.user)
        self.assertFalse(self.cahandler.password)
        self.assertFalse(self.cahandler.template)
        self.assertFalse(self.cahandler.proxy)
        self.assertFalse(self.cahandler.target_domain)
        self.assertFalse(self.cahandler.domain_controller)
        self.assertFalse(self.cahandler.ca_name)
        self.assertFalse(self.cahandler.ca_bundle)
        self.assertIn(
            "ERROR:test_a2c:Unable to load user variable from environment: 'unk'",
            lcm.output,
        )
        self.assertFalse(self.cahandler.use_kerberos)

    @patch.dict("os.environ", {"user_var": "user_var"})
    @patch("examples.ca_handler.mswcce_ca_handler.load_config")
    def test_010_config_load(self, mock_load_cfg):
        """test _config_load - overwrite user variable"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"user_variable": "user_var", "user": "user_local"}
        mock_load_cfg.return_value = parser
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.cahandler._config_load()
        self.assertFalse(self.cahandler.host)
        self.assertEqual("user_local", self.cahandler.user)
        self.assertFalse(self.cahandler.password)
        self.assertFalse(self.cahandler.template)
        self.assertFalse(self.cahandler.proxy)
        self.assertFalse(self.cahandler.target_domain)
        self.assertFalse(self.cahandler.domain_controller)
        self.assertFalse(self.cahandler.ca_name)
        self.assertFalse(self.cahandler.ca_bundle)
        self.assertIn("INFO:test_a2c:Overwrite user", lcm.output)
        self.assertFalse(self.cahandler.use_kerberos)

    @patch("examples.ca_handler.mswcce_ca_handler.load_config")
    def test_011_config_load(self, mock_load_cfg):
        """test _config_load - load user from config file"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"user": "user_local"}
        mock_load_cfg.return_value = parser
        self.cahandler._config_load()
        self.assertFalse(self.cahandler.host)
        self.assertEqual("user_local", self.cahandler.user)
        self.assertFalse(self.cahandler.password)
        self.assertFalse(self.cahandler.template)
        self.assertFalse(self.cahandler.proxy)
        self.assertFalse(self.cahandler.target_domain)
        self.assertFalse(self.cahandler.domain_controller)
        self.assertFalse(self.cahandler.ca_name)
        self.assertFalse(self.cahandler.ca_bundle)
        self.assertFalse(self.cahandler.use_kerberos)

    @patch.dict("os.environ", {"password_var": "password_var"})
    @patch("examples.ca_handler.mswcce_ca_handler.load_config")
    def test_012_config_load(self, mock_load_cfg):
        """test _config_load - load password from variable"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"password_variable": "password_var"}
        mock_load_cfg.return_value = parser
        self.cahandler._config_load()
        self.assertFalse(self.cahandler.host)
        self.assertFalse(self.cahandler.user)
        self.assertEqual("password_var", self.cahandler.password)
        self.assertFalse(self.cahandler.template)
        self.assertFalse(self.cahandler.proxy)
        self.assertFalse(self.cahandler.target_domain)
        self.assertFalse(self.cahandler.domain_controller)
        self.assertFalse(self.cahandler.ca_name)
        self.assertFalse(self.cahandler.ca_bundle)
        self.assertFalse(self.cahandler.use_kerberos)

    @patch.dict("os.environ", {"password_var": "password_var"})
    @patch("examples.ca_handler.mswcce_ca_handler.load_config")
    def test_013_config_load(self, mock_load_cfg):
        """test _config_load - load password from not existing variable"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"password_variable": "unk"}
        mock_load_cfg.return_value = parser
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.cahandler._config_load()
        self.assertFalse(self.cahandler.host)
        self.assertFalse(self.cahandler.user)
        self.assertFalse(self.cahandler.password)
        self.assertFalse(self.cahandler.template)
        self.assertFalse(self.cahandler.proxy)
        self.assertFalse(self.cahandler.target_domain)
        self.assertFalse(self.cahandler.domain_controller)
        self.assertFalse(self.cahandler.ca_name)
        self.assertFalse(self.cahandler.ca_bundle)
        self.assertIn(
            "ERROR:test_a2c:Unable to load password variable from environment: 'unk'",
            lcm.output,
        )
        self.assertFalse(self.cahandler.use_kerberos)

    @patch.dict("os.environ", {"password_var": "password_var"})
    @patch("examples.ca_handler.mswcce_ca_handler.load_config")
    def test_014_config_load(self, mock_load_cfg):
        """test _config_load - overwrite password variable"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {
            "password_variable": "password_var",
            "password": "password_local",
        }
        mock_load_cfg.return_value = parser
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.cahandler._config_load()
        self.assertFalse(self.cahandler.host)
        self.assertFalse(self.cahandler.user)
        self.assertEqual("password_local", self.cahandler.password)
        self.assertFalse(self.cahandler.template)
        self.assertFalse(self.cahandler.proxy)
        self.assertFalse(self.cahandler.target_domain)
        self.assertFalse(self.cahandler.domain_controller)
        self.assertFalse(self.cahandler.ca_name)
        self.assertFalse(self.cahandler.ca_bundle)
        self.assertIn("INFO:test_a2c:Overwrite password", lcm.output)
        self.assertFalse(self.cahandler.use_kerberos)

    @patch("examples.ca_handler.mswcce_ca_handler.load_config")
    def test_015_config_load(self, mock_load_cfg):
        """test _config_load - load password from config file"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"password": "password_local"}
        mock_load_cfg.return_value = parser
        self.cahandler._config_load()
        self.assertFalse(self.cahandler.host)
        self.assertFalse(self.cahandler.user)
        self.assertEqual("password_local", self.cahandler.password)
        self.assertFalse(self.cahandler.template)
        self.assertFalse(self.cahandler.proxy)
        self.assertFalse(self.cahandler.target_domain)
        self.assertFalse(self.cahandler.domain_controller)
        self.assertFalse(self.cahandler.ca_name)
        self.assertFalse(self.cahandler.ca_bundle)
        self.assertFalse(self.cahandler.use_kerberos)
        self.assertEqual(5, self.cahandler.timeout)

    @patch("examples.ca_handler.mswcce_ca_handler.load_config")
    def test_016_config_load(self, mock_load_cfg):
        """test _config_load - load target domain from config file"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"target_domain": "target_domain"}
        mock_load_cfg.return_value = parser
        self.cahandler._config_load()
        self.assertFalse(self.cahandler.host)
        self.assertFalse(self.cahandler.user)
        self.assertFalse(self.cahandler.password)
        self.assertEqual("target_domain", self.cahandler.target_domain)
        self.assertFalse(self.cahandler.template)
        self.assertFalse(self.cahandler.proxy)
        self.assertFalse(self.cahandler.domain_controller)
        self.assertFalse(self.cahandler.ca_name)
        self.assertFalse(self.cahandler.ca_bundle)
        self.assertFalse(self.cahandler.use_kerberos)
        self.assertEqual(5, self.cahandler.timeout)

    @patch("examples.ca_handler.mswcce_ca_handler.load_config")
    def test_017_config_load(self, mock_load_cfg):
        """test _config_load - load domain_controller from config file"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"domain_controller": "domain_controller"}
        mock_load_cfg.return_value = parser
        self.cahandler._config_load()
        self.assertFalse(self.cahandler.host)
        self.assertFalse(self.cahandler.user)
        self.assertFalse(self.cahandler.password)
        self.assertEqual("domain_controller", self.cahandler.domain_controller)
        self.assertFalse(self.cahandler.template)
        self.assertFalse(self.cahandler.proxy)
        self.assertFalse(self.cahandler.target_domain)
        self.assertFalse(self.cahandler.ca_name)
        self.assertFalse(self.cahandler.ca_bundle)
        self.assertFalse(self.cahandler.use_kerberos)

    @patch("examples.ca_handler.mswcce_ca_handler.load_config")
    def test_018_config_load(self, mock_load_cfg):
        """test _config_load - load domain_controller from config file"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"dns_server": "dns_server"}
        mock_load_cfg.return_value = parser
        self.cahandler._config_load()
        self.assertFalse(self.cahandler.host)
        self.assertFalse(self.cahandler.user)
        self.assertFalse(self.cahandler.password)
        self.assertEqual("dns_server", self.cahandler.domain_controller)
        self.assertFalse(self.cahandler.template)
        self.assertFalse(self.cahandler.proxy)
        self.assertFalse(self.cahandler.target_domain)
        self.assertFalse(self.cahandler.ca_name)
        self.assertFalse(self.cahandler.ca_bundle)
        self.assertFalse(self.cahandler.use_kerberos)

    @patch("examples.ca_handler.mswcce_ca_handler.load_config")
    def test_019_config_load(self, mock_load_cfg):
        """test _config_load - load ca_name from config file"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"ca_name": "ca_name"}
        mock_load_cfg.return_value = parser
        self.cahandler._config_load()
        self.assertFalse(self.cahandler.host)
        self.assertFalse(self.cahandler.user)
        self.assertFalse(self.cahandler.password)
        self.assertEqual("ca_name", self.cahandler.ca_name)
        self.assertFalse(self.cahandler.template)
        self.assertFalse(self.cahandler.proxy)
        self.assertFalse(self.cahandler.target_domain)
        self.assertFalse(self.cahandler.domain_controller)
        self.assertFalse(self.cahandler.ca_bundle)
        self.assertFalse(self.cahandler.use_kerberos)
        self.assertEqual(5, self.cahandler.timeout)

    @patch("examples.ca_handler.mswcce_ca_handler.load_config")
    def test_020_config_load(self, mock_load_cfg):
        """test _config_load - load ca_name from config file"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"ca_bundle": "ca_bundle"}
        mock_load_cfg.return_value = parser
        self.cahandler._config_load()
        self.assertFalse(self.cahandler.host)
        self.assertFalse(self.cahandler.user)
        self.assertFalse(self.cahandler.password)
        self.assertEqual("ca_bundle", self.cahandler.ca_bundle)
        self.assertFalse(self.cahandler.template)
        self.assertFalse(self.cahandler.proxy)
        self.assertFalse(self.cahandler.target_domain)
        self.assertFalse(self.cahandler.domain_controller)
        self.assertFalse(self.cahandler.ca_name)
        self.assertFalse(self.cahandler.use_kerberos)
        self.assertEqual(5, self.cahandler.timeout)

    @patch("examples.ca_handler.mswcce_ca_handler.load_config")
    def test_021_config_load(self, mock_load_cfg):
        """test _config_load - load template from config file"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"template": "template"}
        mock_load_cfg.return_value = parser
        self.cahandler._config_load()
        self.assertFalse(self.cahandler.host)
        self.assertFalse(self.cahandler.user)
        self.assertFalse(self.cahandler.password)
        self.assertEqual("template", self.cahandler.template)
        self.assertFalse(self.cahandler.ca_bundle)
        self.assertFalse(self.cahandler.proxy)
        self.assertFalse(self.cahandler.target_domain)
        self.assertFalse(self.cahandler.domain_controller)
        self.assertFalse(self.cahandler.ca_name)
        self.assertFalse(self.cahandler.use_kerberos)

    @patch("examples.ca_handler.mswcce_ca_handler.proxy_check")
    @patch("json.loads")
    @patch("examples.ca_handler.mswcce_ca_handler.load_config")
    def test_022_config_load(self, mock_load_cfg, mock_json, mock_chk):
        """test _config_load ca_handler configured load proxies"""
        mock_load_cfg.return_value = {"DEFAULT": {"proxy_server_list": "foo"}}
        mock_json.return_value = "foo.bar.local"
        mock_chk.return_value = "proxy.bar.local"
        self.cahandler._config_load()
        self.assertTrue(mock_json.called)
        self.assertTrue(mock_chk.called)
        self.assertEqual(
            {"http": "proxy.bar.local", "https": "proxy.bar.local"},
            self.cahandler.proxy,
        )
        self.assertFalse(self.cahandler.host)
        self.assertFalse(self.cahandler.user)
        self.assertFalse(self.cahandler.password)
        self.assertFalse(self.cahandler.template)
        self.assertFalse(self.cahandler.ca_bundle)
        self.assertFalse(self.cahandler.target_domain)
        self.assertFalse(self.cahandler.domain_controller)
        self.assertFalse(self.cahandler.ca_name)
        self.assertFalse(self.cahandler.use_kerberos)

    @patch("examples.ca_handler.mswcce_ca_handler.proxy_check")
    @patch("json.loads")
    @patch("examples.ca_handler.mswcce_ca_handler.load_config")
    def test_023_config_load(self, mock_load_cfg, mock_json, mock_chk):
        """test _config_load ca_handler configured load proxies failed with exception in json.load"""
        mock_load_cfg.return_value = {"DEFAULT": {"proxy_server_list": "foo"}}
        mock_json.side_effect = Exception("exc_load_config")
        mock_chk.side = "proxy.bar.local"
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.cahandler._config_load()
        self.assertTrue(mock_json.called)
        self.assertFalse(mock_chk.called)
        self.assertFalse(self.cahandler.proxy)
        self.assertFalse(self.cahandler.host)
        self.assertFalse(self.cahandler.user)
        self.assertFalse(self.cahandler.password)
        self.assertFalse(self.cahandler.template)
        self.assertFalse(self.cahandler.ca_bundle)
        self.assertFalse(self.cahandler.target_domain)
        self.assertFalse(self.cahandler.domain_controller)
        self.assertFalse(self.cahandler.ca_name)
        self.assertIn(
            "WARNING:test_a2c:Failed to load proxy_server_list from configuration: exc_load_config",
            lcm.output,
        )
        self.assertFalse(self.cahandler.use_kerberos)

    @patch("examples.ca_handler.mswcce_ca_handler.load_config")
    def test_024_config_load(self, mock_load_cfg):
        """test _config_load - load template from config file"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"use_kerberos": "True"}
        mock_load_cfg.return_value = parser
        self.cahandler._config_load()
        self.assertFalse(self.cahandler.host)
        self.assertFalse(self.cahandler.user)
        self.assertFalse(self.cahandler.password)
        self.assertFalse(self.cahandler.template)
        self.assertFalse(self.cahandler.ca_bundle)
        self.assertFalse(self.cahandler.proxy)
        self.assertFalse(self.cahandler.target_domain)
        self.assertFalse(self.cahandler.domain_controller)
        self.assertFalse(self.cahandler.ca_name)
        self.assertTrue(self.cahandler.use_kerberos)

    @patch("examples.ca_handler.mswcce_ca_handler.load_config")
    def test_025_config_load(self, mock_load_cfg):
        """test _config_load - load template from config file"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"use_kerberos": True}
        mock_load_cfg.return_value = parser
        self.cahandler._config_load()
        self.assertFalse(self.cahandler.host)
        self.assertFalse(self.cahandler.user)
        self.assertFalse(self.cahandler.password)
        self.assertFalse(self.cahandler.template)
        self.assertFalse(self.cahandler.ca_bundle)
        self.assertFalse(self.cahandler.proxy)
        self.assertFalse(self.cahandler.target_domain)
        self.assertFalse(self.cahandler.domain_controller)
        self.assertFalse(self.cahandler.ca_name)
        self.assertTrue(self.cahandler.use_kerberos)

    @patch("examples.ca_handler.mswcce_ca_handler.load_config")
    def test_026_config_load(self, mock_load_cfg):
        """test _config_load - load template from config file"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"use_kerberos": False}
        mock_load_cfg.return_value = parser
        self.cahandler._config_load()
        self.assertFalse(self.cahandler.host)
        self.assertFalse(self.cahandler.user)
        self.assertFalse(self.cahandler.password)
        self.assertFalse(self.cahandler.template)
        self.assertFalse(self.cahandler.ca_bundle)
        self.assertFalse(self.cahandler.proxy)
        self.assertFalse(self.cahandler.target_domain)
        self.assertFalse(self.cahandler.domain_controller)
        self.assertFalse(self.cahandler.ca_name)
        self.assertFalse(self.cahandler.use_kerberos)

    @patch("examples.ca_handler.mswcce_ca_handler.load_config")
    def test_027_config_load(self, mock_load_cfg):
        """test _config_load - load template from config file"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"use_kerberos": "False"}
        mock_load_cfg.return_value = parser
        self.cahandler._config_load()
        self.assertFalse(self.cahandler.host)
        self.assertFalse(self.cahandler.user)
        self.assertFalse(self.cahandler.password)
        self.assertFalse(self.cahandler.template)
        self.assertFalse(self.cahandler.ca_bundle)
        self.assertFalse(self.cahandler.proxy)
        self.assertFalse(self.cahandler.target_domain)
        self.assertFalse(self.cahandler.domain_controller)
        self.assertFalse(self.cahandler.ca_name)
        self.assertFalse(self.cahandler.use_kerberos)

    @patch("examples.ca_handler.mswcce_ca_handler.load_config")
    def test_028_config_load(self, mock_load_cfg):
        """test _config_load - load template from config file"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"use_kerberos": "aaaa"}
        mock_load_cfg.return_value = parser
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.cahandler._config_load()
        self.assertFalse(self.cahandler.host)
        self.assertFalse(self.cahandler.user)
        self.assertFalse(self.cahandler.password)
        self.assertFalse(self.cahandler.template)
        self.assertFalse(self.cahandler.ca_bundle)
        self.assertFalse(self.cahandler.proxy)
        self.assertFalse(self.cahandler.target_domain)
        self.assertFalse(self.cahandler.domain_controller)
        self.assertFalse(self.cahandler.ca_name)
        self.assertFalse(self.cahandler.use_kerberos)
        self.assertIn(
            "WARNING:test_a2c:Failed to parse 'use_kerberos' from configuration. Using default value False. Error: Not a boolean: aaaa",
            lcm.output,
        )

    @patch("examples.ca_handler.mswcce_ca_handler.load_config")
    def test_029_config_load(self, mock_load_cfg):
        """test _config_load - load template from config file"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"allowed_domainlist": '["allowed_domainlist"]'}
        mock_load_cfg.return_value = parser
        self.cahandler._config_load()
        self.assertFalse(self.cahandler.host)
        self.assertFalse(self.cahandler.user)
        self.assertFalse(self.cahandler.password)
        self.assertFalse(self.cahandler.template)
        self.assertFalse(self.cahandler.ca_bundle)
        self.assertFalse(self.cahandler.proxy)
        self.assertFalse(self.cahandler.target_domain)
        self.assertFalse(self.cahandler.domain_controller)
        self.assertFalse(self.cahandler.ca_name)
        self.assertFalse(self.cahandler.use_kerberos)

    @patch("examples.ca_handler.mswcce_ca_handler.load_config")
    def test_030_config_load(self, mock_load_cfg):
        """test _config_load - load template from config file"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"allowed_domainlist": "wrongstring"}
        mock_load_cfg.return_value = parser
        self.cahandler._config_load()
        self.assertFalse(self.cahandler.host)
        self.assertFalse(self.cahandler.user)
        self.assertFalse(self.cahandler.password)
        self.assertFalse(self.cahandler.template)
        self.assertFalse(self.cahandler.ca_bundle)
        self.assertFalse(self.cahandler.proxy)
        self.assertFalse(self.cahandler.target_domain)
        self.assertFalse(self.cahandler.domain_controller)
        self.assertFalse(self.cahandler.ca_name)
        self.assertFalse(self.cahandler.use_kerberos)

    @patch("examples.ca_handler.mswcce_ca_handler.load_config")
    def test_031_config_load(self, mock_load_cfg):
        """test _config_load - load template from config file"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"timeout": 20}
        mock_load_cfg.return_value = parser
        self.cahandler._config_load()
        self.assertFalse(self.cahandler.host)
        self.assertFalse(self.cahandler.user)
        self.assertFalse(self.cahandler.password)
        self.assertFalse(self.cahandler.template)
        self.assertFalse(self.cahandler.ca_bundle)
        self.assertFalse(self.cahandler.proxy)
        self.assertFalse(self.cahandler.target_domain)
        self.assertFalse(self.cahandler.domain_controller)
        self.assertFalse(self.cahandler.ca_name)
        self.assertFalse(self.cahandler.use_kerberos)
        self.assertEqual(20, self.cahandler.timeout)

    @patch("examples.ca_handler.mswcce_ca_handler.load_config")
    def test_032_config_load(self, mock_load_cfg):
        """test _config_load - load template from config file"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"timeout": "20"}
        mock_load_cfg.return_value = parser
        self.cahandler._config_load()
        self.assertFalse(self.cahandler.host)
        self.assertFalse(self.cahandler.user)
        self.assertFalse(self.cahandler.password)
        self.assertFalse(self.cahandler.template)
        self.assertFalse(self.cahandler.ca_bundle)
        self.assertFalse(self.cahandler.proxy)
        self.assertFalse(self.cahandler.target_domain)
        self.assertFalse(self.cahandler.domain_controller)
        self.assertFalse(self.cahandler.ca_name)
        self.assertFalse(self.cahandler.use_kerberos)
        self.assertEqual(20, self.cahandler.timeout)

    @patch("examples.ca_handler.mswcce_ca_handler.load_config")
    def test_033_config_load(self, mock_load_cfg):
        """test _config_load - load template from config file"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"timeout": "aaaa"}
        mock_load_cfg.return_value = parser
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.cahandler._config_load()
        self.assertFalse(self.cahandler.host)
        self.assertFalse(self.cahandler.user)
        self.assertFalse(self.cahandler.password)
        self.assertFalse(self.cahandler.template)
        self.assertFalse(self.cahandler.ca_bundle)
        self.assertFalse(self.cahandler.proxy)
        self.assertFalse(self.cahandler.target_domain)
        self.assertFalse(self.cahandler.domain_controller)
        self.assertFalse(self.cahandler.ca_name)
        self.assertFalse(self.cahandler.use_kerberos)
        self.assertIn(
            "WARNING:test_a2c:Failed to parse 'timeout' from configuration. Using default value 5. Error: invalid literal for int() with base 10: 'aaaa'",
            lcm.output,
        )
        self.assertEqual(5, self.cahandler.timeout)

    @patch("examples.ca_handler.mswcce_ca_handler.load_config")
    def test_034_config_load(self, mock_load_cfg):
        """test _config_load - load template from config file"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"enrollment_config_log": True}
        mock_load_cfg.return_value = parser
        self.cahandler._config_load()
        self.assertFalse(self.cahandler.host)
        self.assertFalse(self.cahandler.user)
        self.assertFalse(self.cahandler.password)
        self.assertFalse(self.cahandler.template)
        self.assertFalse(self.cahandler.ca_bundle)
        self.assertFalse(self.cahandler.proxy)
        self.assertFalse(self.cahandler.target_domain)
        self.assertFalse(self.cahandler.domain_controller)
        self.assertFalse(self.cahandler.ca_name)
        self.assertFalse(self.cahandler.use_kerberos)
        self.assertTrue(self.cahandler.enrollment_config_log)

    @patch("examples.ca_handler.mswcce_ca_handler.load_config")
    def test_035_config_load(self, mock_load_cfg):
        """test _config_load - load template from config file"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"enrollment_config_log": False}
        mock_load_cfg.return_value = parser
        self.cahandler._config_load()
        self.assertFalse(self.cahandler.host)
        self.assertFalse(self.cahandler.user)
        self.assertFalse(self.cahandler.password)
        self.assertFalse(self.cahandler.template)
        self.assertFalse(self.cahandler.ca_bundle)
        self.assertFalse(self.cahandler.proxy)
        self.assertFalse(self.cahandler.target_domain)
        self.assertFalse(self.cahandler.domain_controller)
        self.assertFalse(self.cahandler.ca_name)
        self.assertFalse(self.cahandler.use_kerberos)
        self.assertFalse(self.cahandler.enrollment_config_log)

    @patch("examples.ca_handler.mswcce_ca_handler.load_config")
    def test_036_config_load(self, mock_load_cfg):
        """test _config_load - load template from config file"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"enrollment_config_log": "False"}
        mock_load_cfg.return_value = parser
        self.cahandler._config_load()
        self.assertFalse(self.cahandler.host)
        self.assertFalse(self.cahandler.user)
        self.assertFalse(self.cahandler.password)
        self.assertFalse(self.cahandler.template)
        self.assertFalse(self.cahandler.ca_bundle)
        self.assertFalse(self.cahandler.proxy)
        self.assertFalse(self.cahandler.target_domain)
        self.assertFalse(self.cahandler.domain_controller)
        self.assertFalse(self.cahandler.ca_name)
        self.assertFalse(self.cahandler.use_kerberos)
        self.assertFalse(self.cahandler.enrollment_config_log)

    @patch("examples.ca_handler.mswcce_ca_handler.load_config")
    def test_037_config_load(self, mock_load_cfg):
        """test _config_load - load template from config file"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"enrollment_config_log": "aaaa"}
        mock_load_cfg.return_value = parser
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.cahandler._config_load()
        self.assertFalse(self.cahandler.host)
        self.assertFalse(self.cahandler.user)
        self.assertFalse(self.cahandler.password)
        self.assertFalse(self.cahandler.template)
        self.assertFalse(self.cahandler.ca_bundle)
        self.assertFalse(self.cahandler.proxy)
        self.assertFalse(self.cahandler.target_domain)
        self.assertFalse(self.cahandler.domain_controller)
        self.assertFalse(self.cahandler.ca_name)
        self.assertFalse(self.cahandler.use_kerberos)
        self.assertIn(
            "WARNING:test_a2c:Failed to load enrollment_config_log from configuration: Not a boolean: aaaa",
            lcm.output,
        )
        self.assertFalse(self.cahandler.enrollment_config_log)

    @patch("builtins.open", mock_open(read_data="foo"), create=True)
    def test_038__file_load(self):
        """test _load file()"""
        self.assertEqual("foo", self.cahandler._file_load("filename"))

    @patch("builtins.open")
    def test_039__file_load(self, mock_op):
        """test _load file()"""
        mock_op.side_effect = Exception("ex_mock_open")
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.assertFalse(self.cahandler._file_load("filename"))
        self.assertIn(
            "ERROR:test_a2c:Could not load file 'filename'. Error: ex_mock_open",
            lcm.output,
        )

    def test_040_revoke(self):
        """test revocation"""
        self.assertEqual(
            (
                500,
                "urn:ietf:params:acme:error:serverInternal",
                "Revocation is not supported.",
            ),
            self.cahandler.revoke("cert", "rev_reason", "rev_date"),
        )

    def test_041_poll(self):
        """test polling"""
        self.assertEqual(
            ("Method not implemented.", None, None, "poll_identifier", False),
            self.cahandler.poll("cert_name", "poll_identifier", "csr"),
        )

    def test_042_trigger(self):
        """test trigger"""
        self.assertEqual(
            ("Method not implemented.", None, None), self.cahandler.trigger("payload")
        )

    @patch("examples.ca_handler.mswcce_ca_handler.CAhandler.request_create")
    def test_043_enroll(self, mock_rcr):
        """test enrollment - unconfigured"""
        self.assertEqual(
            (
                "Configuration incomplete: host, user, password, or template is missing.",
                None,
                None,
                None,
            ),
            self.cahandler.enroll("csr"),
        )
        self.assertFalse(mock_rcr.called)

    @patch("examples.ca_handler.mswcce_ca_handler.CAhandler.request_create")
    def test_044_enroll(self, mock_rcr):
        """test enrollment - host unconfigured"""
        self.cahandler.host = None
        self.cahandler.user = "user"
        self.cahandler.password = "password"
        self.cahandler.template = "template"
        self.assertEqual(
            (
                "Configuration incomplete: host, user, password, or template is missing.",
                None,
                None,
                None,
            ),
            self.cahandler.enroll("csr"),
        )
        self.assertFalse(mock_rcr.called)

    @patch("examples.ca_handler.mswcce_ca_handler.CAhandler.request_create")
    def test_045_enroll(self, mock_rcr):
        """test enrollment - user unconfigured"""
        self.cahandler.host = "host"
        self.cahandler.user = None
        self.cahandler.password = "password"
        self.cahandler.template = "template"
        self.assertEqual(
            (
                "Configuration incomplete: host, user, password, or template is missing.",
                None,
                None,
                None,
            ),
            self.cahandler.enroll("csr"),
        )
        self.assertFalse(mock_rcr.called)

    @patch("examples.ca_handler.mswcce_ca_handler.CAhandler.request_create")
    def test_046_enroll(self, mock_rcr):
        """test enrollment - password unconfigured"""
        self.cahandler.host = "host"
        self.cahandler.user = "user"
        self.cahandler.password = None
        self.cahandler.template = "template"
        self.assertEqual(
            (
                "Configuration incomplete: host, user, password, or template is missing.",
                None,
                None,
                None,
            ),
            self.cahandler.enroll("csr"),
        )
        self.assertFalse(mock_rcr.called)

    @patch("examples.ca_handler.mswcce_ca_handler.CAhandler.request_create")
    def test_047_enroll(self, mock_rcr):
        """test enrollment - template unconfigured"""
        self.cahandler.host = "host"
        self.cahandler.user = "user"
        self.cahandler.password = "password"
        self.cahandler.template = None
        self.assertEqual(
            (
                "Configuration incomplete: host, user, password, or template is missing.",
                None,
                None,
                None,
            ),
            self.cahandler.enroll("csr"),
        )
        self.assertFalse(mock_rcr.called)

    @patch("examples.ca_handler.mswcce_ca_handler.CAhandler.request_create")
    @patch("examples.ca_handler.mswcce_ca_handler.convert_string_to_byte")
    @patch("examples.ca_handler.mswcce_ca_handler.convert_byte_to_string")
    @patch("examples.ca_handler.mswcce_ca_handler.CAhandler._file_load")
    @patch("examples.ca_handler.mswcce_ca_handler.build_pem_file")
    def test_048_enroll(self, mock_pem, mock_file, mock_b2s, mock_s2b, mock_rcr):
        """test enrollment - ca_server.get_cert() triggers exception"""
        self.cahandler.host = "host"
        self.cahandler.user = "user"
        self.cahandler.password = "password"
        self.cahandler.template = "template"
        mock_rcr.return_value = Mock(return_value="raw_data")
        mock_file.return_value = "file_load"
        mock_s2b.return_value = "s2b"
        mock_b2s.side_effect = Exception("ex_b2s")
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.assertEqual(
                (
                    "Certificate bundling failed: CA certificate or issued certificate is missing.",
                    None,
                    None,
                    None,
                ),
                self.cahandler.enroll("csr"),
            )
        self.assertIn("ERROR:test_a2c:Enrollment failed with error: ex_b2s", lcm.output)
        self.assertIn(
            "ERROR:test_a2c:Certificate bundling failed: CA certificate or issued certificate is missing.",
            lcm.output,
        )
        self.assertTrue(mock_rcr.called)

    @patch("examples.ca_handler.mswcce_ca_handler.CAhandler.request_create")
    @patch("examples.ca_handler.mswcce_ca_handler.convert_string_to_byte")
    @patch("examples.ca_handler.mswcce_ca_handler.convert_byte_to_string")
    @patch("examples.ca_handler.mswcce_ca_handler.CAhandler._file_load")
    @patch("examples.ca_handler.mswcce_ca_handler.build_pem_file")
    def test_049_enroll(self, mock_pem, mock_file, mock_b2s, mock_s2b, mock_rcr):
        """test enrollment - no certificate returned by ca_server.get_cert()"""
        self.cahandler.host = "host"
        self.cahandler.user = "user"
        self.cahandler.password = "password"
        self.cahandler.template = "template"
        mock_rcr.return_value = Mock(return_value="raw_data")
        mock_file.return_value = "file_load"
        mock_s2b.return_value = "s2b"
        mock_b2s.return_value = None
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.assertEqual(
                (
                    "Certificate bundling failed: CA certificate or issued certificate is missing.",
                    None,
                    None,
                    None,
                ),
                self.cahandler.enroll("csr"),
            )
        self.assertIn(
            "ERROR:test_a2c:Certificate bundling failed: CA certificate or issued certificate is missing.",
            lcm.output,
        )
        self.assertTrue(mock_rcr.called)

    @patch("examples.ca_handler.mswcce_ca_handler.CAhandler.request_create")
    @patch("examples.ca_handler.mswcce_ca_handler.convert_string_to_byte")
    @patch("examples.ca_handler.mswcce_ca_handler.convert_byte_to_string")
    @patch("examples.ca_handler.mswcce_ca_handler.CAhandler._file_load")
    @patch("examples.ca_handler.mswcce_ca_handler.build_pem_file")
    def test_050_enroll(self, mock_pem, mock_file, mock_b2s, mock_s2b, mock_rcr):
        """test enrollment - certificate and bundling successful"""
        self.cahandler.host = "host"
        self.cahandler.user = "user"
        self.cahandler.password = "password"
        self.cahandler.template = "template"
        mock_rcr.return_value = Mock(return_value="raw_data")
        mock_file.return_value = "file_load"
        mock_s2b.return_value = "s2b"
        mock_b2s.return_value = "b2s"
        self.assertEqual(
            (None, "b2sfile_load", "b2s", None), self.cahandler.enroll("csr")
        )
        self.assertTrue(mock_rcr.called)

    @patch("examples.ca_handler.mswcce_ca_handler.CAhandler.request_create")
    @patch("examples.ca_handler.mswcce_ca_handler.convert_string_to_byte")
    @patch("examples.ca_handler.mswcce_ca_handler.convert_byte_to_string")
    @patch("examples.ca_handler.mswcce_ca_handler.CAhandler._file_load")
    @patch("examples.ca_handler.mswcce_ca_handler.build_pem_file")
    def test_051_enroll(self, mock_pem, mock_file, mock_b2s, mock_s2b, mock_rcr):
        """test enrollment - certificate and bundling successful"""
        self.cahandler.host = "host"
        self.cahandler.user = "user"
        self.cahandler.password = "password"
        self.cahandler.template = "template"
        mock_rcr.return_value = Mock(return_value="raw_data")
        mock_file.return_value = "file_load"
        mock_s2b.return_value = "s2b"
        mock_b2s.return_value = "b2s"
        self.assertEqual(
            (None, "b2sfile_load", "b2s", None), self.cahandler.enroll("csr")
        )
        self.assertTrue(mock_rcr.called)

    @patch("examples.ca_handler.mswcce_ca_handler.CAhandler.request_create")
    @patch("examples.ca_handler.mswcce_ca_handler.convert_string_to_byte")
    @patch("examples.ca_handler.mswcce_ca_handler.convert_byte_to_string")
    @patch("examples.ca_handler.mswcce_ca_handler.CAhandler._file_load")
    @patch("examples.ca_handler.mswcce_ca_handler.build_pem_file")
    def test_052_enroll(self, mock_pem, mock_file, mock_b2s, mock_s2b, mock_rcr):
        """test enrollment - certificate and bundling successful replacement test"""
        self.cahandler.host = "host"
        self.cahandler.user = "user"
        self.cahandler.password = "password"
        self.cahandler.template = "template"
        mock_rcr.return_value = Mock(return_value="raw_data")
        mock_file.return_value = "file_load"
        mock_s2b.return_value = "s2b"
        mock_b2s.return_value = (
            "-----BEGIN CERTIFICATE-----\nb2s_replacement\n-----END CERTIFICATE-----\n"
        )
        self.assertEqual(
            (
                None,
                "-----BEGIN CERTIFICATE-----\nb2s_replacement\n-----END CERTIFICATE-----\nfile_load",
                "b2s_replacement",
                None,
            ),
            self.cahandler.enroll("csr"),
        )
        self.assertTrue(mock_rcr.called)

    @patch("examples.ca_handler.mswcce_ca_handler.eab_profile_header_info_check")
    @patch("examples.ca_handler.mswcce_ca_handler.CAhandler.request_create")
    @patch("examples.ca_handler.mswcce_ca_handler.convert_string_to_byte")
    @patch("examples.ca_handler.mswcce_ca_handler.convert_byte_to_string")
    @patch("examples.ca_handler.mswcce_ca_handler.CAhandler._file_load")
    @patch("examples.ca_handler.mswcce_ca_handler.build_pem_file")
    def test_053_enroll(
        self, mock_pem, mock_file, mock_b2s, mock_s2b, mock_rcr, mock_eab
    ):
        """test enrollment - certificate and bundling successful replacement test"""
        self.cahandler.host = "host"
        self.cahandler.user = "user"
        self.cahandler.password = "password"
        self.cahandler.template = "template"
        mock_rcr.return_value = Mock(return_value="raw_data")
        mock_file.return_value = None
        mock_s2b.return_value = "s2b"
        mock_eab.return_value = None
        mock_b2s.return_value = (
            "-----BEGIN CERTIFICATE-----\nb2s_replacement\n-----END CERTIFICATE-----\n"
        )
        self.assertEqual(
            (
                None,
                "-----BEGIN CERTIFICATE-----\nb2s_replacement\n-----END CERTIFICATE-----\n",
                "b2s_replacement",
                None,
            ),
            self.cahandler.enroll("csr"),
        )
        self.assertTrue(mock_rcr.called)
        self.assertTrue(mock_eab.called)

    @patch("examples.ca_handler.mswcce_ca_handler.eab_profile_header_info_check")
    @patch("examples.ca_handler.mswcce_ca_handler.CAhandler.request_create")
    @patch("examples.ca_handler.mswcce_ca_handler.convert_string_to_byte")
    @patch("examples.ca_handler.mswcce_ca_handler.convert_byte_to_string")
    @patch("examples.ca_handler.mswcce_ca_handler.CAhandler._file_load")
    @patch("examples.ca_handler.mswcce_ca_handler.build_pem_file")
    def test_054_enroll(
        self, mock_pem, mock_file, mock_b2s, mock_s2b, mock_rcr, mock_eab
    ):
        """test enrollment - certificate and bundling successful replacement test"""
        self.cahandler.host = "host"
        self.cahandler.user = "user"
        self.cahandler.password = "password"
        self.cahandler.template = "template"
        self.cahandler.header_info_field = "header_info"
        mock_rcr.return_value = Mock(return_value="raw_data")
        mock_file.return_value = None
        mock_s2b.return_value = "s2b"
        mock_b2s.return_value = (
            "-----BEGIN CERTIFICATE-----\nb2s_replacement\n-----END CERTIFICATE-----\n"
        )
        mock_eab.return_value = "error"
        self.assertEqual(("error", None, None, None), self.cahandler.enroll("csr"))
        self.assertFalse(mock_rcr.called)
        self.assertEqual("template", self.cahandler.template)

    @patch("examples.ca_handler.mswcce_ca_handler.eab_profile_header_info_check")
    @patch("examples.ca_handler.mswcce_ca_handler.CAhandler.request_create")
    @patch("examples.ca_handler.mswcce_ca_handler.convert_string_to_byte")
    @patch("examples.ca_handler.mswcce_ca_handler.convert_byte_to_string")
    @patch("examples.ca_handler.mswcce_ca_handler.CAhandler._file_load")
    @patch("examples.ca_handler.mswcce_ca_handler.build_pem_file")
    def test_055_enroll(
        self, mock_pem, mock_file, mock_b2s, mock_s2b, mock_rcr, mock_eab
    ):
        """test enrollment - certificate and bundling successful replacement test"""
        self.cahandler.host = "host"
        self.cahandler.user = "user"
        self.cahandler.password = "password"
        self.cahandler.template = "template"
        self.cahandler.header_info_field = "header_info"
        mock_rcr.return_value = Mock(return_value="raw_data")
        mock_file.return_value = None
        mock_s2b.return_value = "s2b"
        mock_b2s.return_value = (
            "-----BEGIN CERTIFICATE-----\nb2s_replacement\n-----END CERTIFICATE-----\n"
        )
        mock_eab.return_value = None
        self.assertEqual(
            (
                None,
                "-----BEGIN CERTIFICATE-----\nb2s_replacement\n-----END CERTIFICATE-----\n",
                "b2s_replacement",
                None,
            ),
            self.cahandler.enroll("csr"),
        )
        self.assertTrue(mock_rcr.called)
        self.assertEqual("template", self.cahandler.template)

    @patch("examples.ca_handler.mswcce_ca_handler.enrollment_config_log")
    @patch("examples.ca_handler.mswcce_ca_handler.Request")
    @patch("examples.ca_handler.mswcce_ca_handler.Target")
    def test_056_request_create(self, mock_target, mock_request, mock_ecl):
        """test request create"""
        mock_target.return_value = True
        mock_request.return_value = "foo"
        self.assertEqual("foo", self.cahandler.request_create())
        self.assertFalse(mock_ecl.called)

    @patch("examples.ca_handler.mswcce_ca_handler.enrollment_config_log")
    @patch("examples.ca_handler.mswcce_ca_handler.Request")
    @patch("examples.ca_handler.mswcce_ca_handler.Target")
    def test_057_request_create(self, mock_target, mock_request, mock_ecl):
        """test request create"""
        mock_target.return_value = True
        mock_request.return_value = "foo"
        self.cahandler.enrollment_config_log = True
        self.assertEqual("foo", self.cahandler.request_create())
        self.assertTrue(mock_ecl.called)

    @patch("examples.ca_handler.mswcce_ca_handler.CAhandler._config_load")
    def test_058__enter(self, mock_cfgload):
        """CAhandler._enter() with config load"""
        self.cahandler.host = "host"
        self.cahandler.__enter__()
        self.assertFalse(mock_cfgload.called)

    @patch("examples.ca_handler.mswcce_ca_handler.CAhandler._config_load")
    def test_059__enter(self, mock_cfgload):
        """CAhandler._enter() with config load"""
        self.cahandler.host = None
        self.cahandler.__enter__()
        self.assertTrue(mock_cfgload.called)

    @patch("examples.ca_handler.mswcce_ca_handler.header_info_get")
    def test_060_template_name_get(self, mock_header):
        """test _template_name_get()"""
        mock_header.return_value = [
            {
                "header_info": '{"header_field": "template=foo lego-cli/4.14.2 xenolf-acme/4.14.2 (release; linux; amd64)"}'
            }
        ]
        self.cahandler.header_info_field = "header_field"
        self.assertEqual("foo", self.cahandler._template_name_get("csr"))

    @patch("examples.ca_handler.mswcce_ca_handler.header_info_get")
    def test_061_template_name_get(self, mock_header):
        """test _template_name_get()"""
        mock_header.return_value = [
            {
                "header_info": '{"header_field": "Template=foo lego-cli/4.14.2 xenolf-acme/4.14.2 (release; linux; amd64)"}'
            }
        ]
        self.cahandler.header_info_field = "header_field"
        self.assertEqual("foo", self.cahandler._template_name_get("csr"))

    @patch("examples.ca_handler.mswcce_ca_handler.header_info_get")
    def test_062_template_name_get(self, mock_header):
        """test _template_name_get()"""
        mock_header.return_value = [{"header_info": "header_info"}]
        self.cahandler.header_info_field = "header_field"
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.assertFalse(self.cahandler._template_name_get("csr"))
        self.assertIn(
            "ERROR:test_a2c:Failed to parse template from header info: Expecting value: line 1 column 1 (char 0)",
            lcm.output,
        )

    def test_063_config_headerinfo_load(self):
        """test config_headerinfo_load()"""
        config_dic = {"Order": {"header_info_list": '["foo", "bar", "foobar"]'}}
        self.cahandler._config_headerinfo_load(config_dic)
        self.assertEqual("foo", self.cahandler.header_info_field)

    def test_064_config_headerinfo_load(self):
        """test config_headerinfo_load()"""
        config_dic = {"Order": {"header_info_list": '["foo"]'}}
        self.cahandler._config_headerinfo_load(config_dic)
        self.assertEqual("foo", self.cahandler.header_info_field)

    def test_065_config_headerinfo_load(self):
        """test config_headerinfo_load()"""
        config_dic = {"Order": {"header_info_list": "foo"}}
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.cahandler._config_headerinfo_load(config_dic)
        self.assertFalse(self.cahandler.header_info_field)
        self.assertIn(
            "WARNING:test_a2c:Failed to parse header_info_list from configuration: Expecting value: line 1 column 1 (char 0)",
            lcm.output,
        )

    @patch("examples.ca_handler.mswcce_ca_handler.handler_config_check")
    def test_066_handler_check(self, mock_handler_check):
        """test handler_check"""
        mock_handler_check.return_value = "mock_handler_check"
        self.assertEqual("mock_handler_check", self.cahandler.handler_check())

    @patch("examples.ca_handler.mswcce_ca_handler.load_config")
    def test_067_config_load_python_kerberos_backend(self, mock_load_cfg):
        """test _config_load with python kerberos backend options"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {
            "use_kerberos": "True",
            "krb5_auth_backend": "python",
            "krb5_principal": "svc-a2c-enroll@EXAMPLE.COM",
            "krb5_keytab": "/tmp/svc.keytab",
            "krb5_cache": "/tmp/krb5cc_svc",
            "krb5_config": "/tmp/krb5.conf",
        }
        mock_load_cfg.return_value = parser
        self.cahandler._config_load()
        self.assertTrue(self.cahandler.use_kerberos)
        self.assertEqual("python", self.cahandler.krb5_auth_backend)
        self.assertEqual(
            "svc-a2c-enroll@EXAMPLE.COM",
            self.cahandler.krb5_principal,
        )
        self.assertEqual("/tmp/svc.keytab", self.cahandler.krb5_keytab)
        self.assertEqual("/tmp/krb5cc_svc", self.cahandler.krb5_cache)
        self.assertEqual("/tmp/krb5.conf", self.cahandler.krb5_config)

    @patch("examples.ca_handler.mswcce_ca_handler.load_config")
    def test_067a_config_load_autoselect_python_backend(self, mock_load_cfg):
        """test backend autoselection to python for keytab-based kerberos config"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {
            "use_kerberos": "True",
            "krb5_principal": "svc-a2c-enroll@EXAMPLE.COM",
            "krb5_keytab": "/tmp/svc.keytab",
        }
        mock_load_cfg.return_value = parser

        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.cahandler._config_load()

        self.assertEqual("python", self.cahandler.krb5_auth_backend)
        self.assertIn(
            "INFO:test_a2c:Auto-selected krb5_auth_backend='python' because krb5_principal and krb5_keytab are configured.",
            lcm.output,
        )

    @patch("examples.ca_handler.mswcce_ca_handler.load_config")
    def test_067b_config_load_keep_explicit_backend(self, mock_load_cfg):
        """test explicit backend is preserved even in keytab mode"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {
            "use_kerberos": "True",
            "krb5_auth_backend": "impacket",
            "krb5_principal": "svc-a2c-enroll@EXAMPLE.COM",
            "krb5_keytab": "/tmp/svc.keytab",
            "krb5_cache": "/tmp/krb5cc_svc",
        }
        mock_load_cfg.return_value = parser

        self.cahandler._config_load()

        self.assertEqual("impacket", self.cahandler.krb5_auth_backend)

    def test_068_config_is_complete_krb5_keytab(self):
        """test config completeness in kerberos keytab mode"""
        self.cahandler.host = "host"
        self.cahandler.template = "template"
        self.cahandler.use_kerberos = True
        self.cahandler.krb5_auth_backend = "python"
        self.cahandler.krb5_principal = "svc-a2c-enroll@EXAMPLE.COM"
        self.cahandler.krb5_keytab = "/tmp/svc.keytab"

        result, error = self.cahandler._config_is_complete()
        self.assertTrue(result)
        self.assertFalse(error)

    def test_069_config_is_complete_kerberos_incomplete(self):
        """test config completeness in incomplete kerberos mode"""
        self.cahandler.host = "host"
        self.cahandler.template = "template"
        self.cahandler.use_kerberos = True

        result, error = self.cahandler._config_is_complete()
        self.assertFalse(result)
        self.assertIn("kerberos is enabled", error)

    @patch(
        "examples.ca_handler.mswcce_ca_handler.CAhandler._kerberos_prepare_python_backend"
    )
    def test_070_enroll_python_backend_error(self, mock_krb_prepare):
        """test enroll returns python backend setup errors"""
        mock_krb_prepare.return_value = "backend error"
        self.cahandler.host = "host"
        self.cahandler.template = "template"
        self.cahandler.use_kerberos = True
        self.cahandler.krb5_auth_backend = "python"
        self.cahandler.krb5_principal = "svc-a2c-enroll@EXAMPLE.COM"
        self.cahandler.krb5_keytab = "/tmp/svc.keytab"

        error, cert_bundle, cert_raw, _ = self.cahandler.enroll("csr")
        self.assertEqual("backend error", error)
        self.assertFalse(cert_bundle)
        self.assertFalse(cert_raw)

    @patch("examples.ca_handler.mswcce_ca_handler.importlib.import_module")
    @patch("examples.ca_handler.mswcce_ca_handler.os.path.isfile")
    def test_071_kerberos_prepare_python_backend_fallback_kinit(
        self,
        mock_isfile,
        mock_import_module,
    ):
        """fallback to gssapi high-level acquire if raw API is unavailable"""
        self.cahandler.use_kerberos = True
        self.cahandler.krb5_auth_backend = "python"
        self.cahandler.krb5_principal = "svc-a2c-enroll@EXAMPLE.COM"
        self.cahandler.krb5_keytab = "/tmp/svc.keytab"
        self.cahandler.krb5_cache = "/tmp/krb5cc_svc"

        mock_isfile.return_value = True

        mock_gssapi = Mock()
        mock_gssapi.NameType.krb5_principal = "krb5_principal"
        mock_gssapi.Name.return_value = "principal"
        mock_gssapi.raw = object()
        mock_gssapi.Credentials = Mock()
        mock_gssapi.Credentials.acquire = Mock(return_value=(None, None, None))
        mock_import_module.return_value = mock_gssapi

        error = self.cahandler._kerberos_prepare_python_backend()

        self.assertFalse(error)
        self.assertTrue(mock_gssapi.Credentials.acquire.called)
        self.assertEqual(
            "/tmp/krb5cc_svc",
            self.cahandler.krb5_cache,
        )

    @patch("examples.ca_handler.mswcce_ca_handler.subprocess.run")
    @patch("examples.ca_handler.mswcce_ca_handler.os.path.isfile")
    def test_072_kerberos_acquire_with_kinit_with_krb5_config(
        self,
        mock_isfile,
        mock_subprocess_run,
    ):
        """test kinit fallback uses optional KRB5_CONFIG when configured"""
        self.cahandler.krb5_keytab = "/tmp/svc.keytab"
        self.cahandler.krb5_principal = "svc-a2c-enroll@EXAMPLE.COM"
        self.cahandler.krb5_config = "/tmp/krb5.conf"

        def _isfile_side_effect(path):
            return path == "/tmp/krb5.conf"

        mock_isfile.side_effect = _isfile_side_effect

        result = self.cahandler._kerberos_acquire_with_kinit("/tmp/krb5cc_svc")

        self.assertTrue(result)
        self.assertTrue(mock_subprocess_run.called)
        _, run_kwargs = mock_subprocess_run.call_args
        self.assertEqual("/tmp/krb5cc_svc", run_kwargs["env"]["KRB5CCNAME"])
        self.assertEqual("/tmp/krb5.conf", run_kwargs["env"]["KRB5_CONFIG"])

    def test_073_kerberos_username_from_principal(self):
        """test kerberos username extraction from principal"""
        username = self.cahandler._kerberos_username_from_principal(
            "svc-a2c-enroll@EXAMPLE.COM"
        )
        self.assertEqual("svc-a2c-enroll", username)

    def test_074_kerberos_username_from_principal_missing_principal(self):
        """test kerberos username extraction when principal is missing"""
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            username = self.cahandler._kerberos_username_from_principal("")

        self.assertFalse(username)
        self.assertIn(
            "ERROR:test_a2c:Kerberos principal is not configured, cannot extract username.",
            lcm.output,
        )

    def test_075_kerberos_prepare_python_backend_skips_when_disabled(self):
        """test kerberos python backend is skipped when disabled"""
        self.cahandler.use_kerberos = False
        self.cahandler.krb5_auth_backend = "python"
        self.assertFalse(self.cahandler._kerberos_prepare_python_backend())

        self.cahandler.use_kerberos = True
        self.cahandler.krb5_auth_backend = "impacket"
        self.assertFalse(self.cahandler._kerberos_prepare_python_backend())

    def test_076_kerberos_prepare_python_backend_skips_without_keytab_config(self):
        """test kerberos python backend is skipped without keytab config"""
        self.cahandler.use_kerberos = True
        self.cahandler.krb5_auth_backend = "python"
        self.cahandler.krb5_principal = None
        self.cahandler.krb5_keytab = "/tmp/svc.keytab"

        self.assertFalse(self.cahandler._kerberos_prepare_python_backend())

    @patch("examples.ca_handler.mswcce_ca_handler.os.path.isfile")
    def test_077_kerberos_prepare_python_backend_missing_keytab_file(self, mock_isfile):
        """test kerberos python backend errors when keytab file is missing"""
        self.cahandler.use_kerberos = True
        self.cahandler.krb5_auth_backend = "python"
        self.cahandler.krb5_principal = "svc-a2c-enroll@EXAMPLE.COM"
        self.cahandler.krb5_keytab = "/tmp/svc.keytab"
        mock_isfile.return_value = False

        self.assertEqual(
            "Kerberos keytab file does not exist.",
            self.cahandler._kerberos_prepare_python_backend(),
        )

    @patch("examples.ca_handler.mswcce_ca_handler.importlib.import_module")
    @patch("examples.ca_handler.mswcce_ca_handler.os.path.isfile")
    def test_078_kerberos_prepare_python_backend_missing_gssapi(
        self,
        mock_isfile,
        mock_import_module,
    ):
        """test kerberos python backend errors if gssapi is unavailable"""
        self.cahandler.use_kerberos = True
        self.cahandler.krb5_auth_backend = "python"
        self.cahandler.krb5_principal = "svc-a2c-enroll@EXAMPLE.COM"
        self.cahandler.krb5_keytab = "/tmp/svc.keytab"
        self.cahandler.krb5_cache = "/tmp/krb5cc_svc"
        mock_isfile.return_value = True
        mock_import_module.side_effect = Exception("gssapi import error")

        self.assertEqual(
            "gssapi module is required for krb5_auth_backend=python.",
            self.cahandler._kerberos_prepare_python_backend(),
        )

    @patch.dict("os.environ", {}, clear=True)
    @patch("examples.ca_handler.mswcce_ca_handler.importlib.import_module")
    @patch("examples.ca_handler.mswcce_ca_handler.os.path.exists")
    @patch("examples.ca_handler.mswcce_ca_handler.os.path.isfile")
    @patch(
        "examples.ca_handler.mswcce_ca_handler.CAhandler._kerberos_acquire_with_kinit"
    )
    @patch(
        "examples.ca_handler.mswcce_ca_handler.CAhandler._kerberos_acquire_with_gssapi_highlevel"
    )
    @patch(
        "examples.ca_handler.mswcce_ca_handler.CAhandler._kerberos_acquire_with_gssapi_raw"
    )
    def test_079_kerberos_prepare_python_backend_success_with_raw_acquire(
        self,
        mock_raw_acquire,
        mock_high_acquire,
        mock_kinit_acquire,
        mock_isfile,
        mock_exists,
        mock_import_module,
    ):
        """test kerberos python backend success with raw gssapi acquire"""
        self.cahandler.use_kerberos = True
        self.cahandler.krb5_auth_backend = "python"
        self.cahandler.krb5_principal = "svc-a2c-enroll@EXAMPLE.COM"
        self.cahandler.krb5_keytab = "/tmp/svc.keytab"
        self.cahandler.krb5_cache = "FILE:/tmp/krb5cc_svc"

        mock_isfile.return_value = True
        mock_exists.return_value = True
        mock_raw_acquire.return_value = True

        mock_gssapi = Mock()
        mock_gssapi.NameType.kerberos_principal = "kerberos_principal"
        mock_gssapi.Name.return_value = "principal"
        mock_import_module.return_value = mock_gssapi

        error = self.cahandler._kerberos_prepare_python_backend()

        self.assertFalse(error)
        self.assertEqual("/tmp/krb5cc_svc", self.cahandler.krb5_cache)
        self.assertEqual("/tmp/krb5cc_svc", os.environ["KRB5CCNAME"])
        self.assertTrue(mock_raw_acquire.called)
        self.assertFalse(mock_high_acquire.called)
        self.assertFalse(mock_kinit_acquire.called)

    @patch("examples.ca_handler.mswcce_ca_handler.importlib.import_module")
    @patch("examples.ca_handler.mswcce_ca_handler.os.path.exists")
    @patch("examples.ca_handler.mswcce_ca_handler.os.path.isfile")
    @patch(
        "examples.ca_handler.mswcce_ca_handler.CAhandler._kerberos_acquire_with_kinit"
    )
    @patch(
        "examples.ca_handler.mswcce_ca_handler.CAhandler._kerberos_acquire_with_gssapi_highlevel"
    )
    @patch(
        "examples.ca_handler.mswcce_ca_handler.CAhandler._kerberos_acquire_with_gssapi_raw"
    )
    @patch("builtins.open", new_callable=mock_open)
    def test_080_kerberos_prepare_python_backend_creates_temp_ccache(
        self,
        mock_file_open,
        mock_raw_acquire,
        mock_high_acquire,
        mock_kinit_acquire,
        mock_isfile,
        mock_exists,
        mock_import_module,
    ):
        """test kerberos python backend creates ccache file when not configured"""
        self.cahandler.use_kerberos = True
        self.cahandler.krb5_auth_backend = "python"
        self.cahandler.krb5_principal = "svc-a2c-enroll@EXAMPLE.COM"
        self.cahandler.krb5_keytab = "/tmp/svc.keytab"
        self.cahandler.krb5_cache = None

        mock_isfile.return_value = True
        mock_exists.return_value = False
        mock_raw_acquire.return_value = False
        mock_high_acquire.return_value = False
        mock_kinit_acquire.return_value = True

        mock_gssapi = Mock()
        mock_gssapi.NameType.kerberos_principal = "kerberos_principal"
        mock_gssapi.Name.return_value = "principal"
        mock_import_module.return_value = mock_gssapi

        error = self.cahandler._kerberos_prepare_python_backend()

        self.assertFalse(error)
        self.assertTrue(self.cahandler.krb5_cache)
        mock_file_open.assert_called_once_with(
            self.cahandler.krb5_cache, "a", encoding="utf-8"
        )
        self.assertTrue(mock_kinit_acquire.called)

    @patch(
        "examples.ca_handler.mswcce_ca_handler.CAhandler._kerberos_acquire_with_kinit"
    )
    @patch(
        "examples.ca_handler.mswcce_ca_handler.CAhandler._kerberos_acquire_with_gssapi_highlevel"
    )
    @patch(
        "examples.ca_handler.mswcce_ca_handler.CAhandler._kerberos_acquire_with_gssapi_raw"
    )
    @patch("examples.ca_handler.mswcce_ca_handler.importlib.import_module")
    @patch("examples.ca_handler.mswcce_ca_handler.os.path.exists")
    @patch("examples.ca_handler.mswcce_ca_handler.os.path.isfile")
    def test_081_kerberos_prepare_python_backend_principal_build_failed(
        self,
        mock_isfile,
        mock_exists,
        mock_import_module,
        mock_raw_acquire,
        mock_high_acquire,
        mock_kinit_acquire,
    ):
        """test kerberos python backend errors when gssapi principal creation fails"""
        self.cahandler.use_kerberos = True
        self.cahandler.krb5_auth_backend = "python"
        self.cahandler.krb5_principal = "svc-a2c-enroll@EXAMPLE.COM"
        self.cahandler.krb5_keytab = "/tmp/svc.keytab"
        self.cahandler.krb5_cache = "/tmp/krb5cc_svc"

        mock_isfile.return_value = True
        mock_exists.return_value = True

        mock_gssapi = Mock()
        mock_gssapi.NameType.kerberos_principal = "kerberos_principal"
        mock_gssapi.Name.side_effect = Exception("invalid principal")
        mock_import_module.return_value = mock_gssapi

        error = self.cahandler._kerberos_prepare_python_backend()

        self.assertEqual(
            "Failed to build kerberos principal for kerberos keytab authentication.",
            error,
        )
        self.assertFalse(mock_raw_acquire.called)
        self.assertFalse(mock_high_acquire.called)
        self.assertFalse(mock_kinit_acquire.called)

    @patch("examples.ca_handler.mswcce_ca_handler.importlib.import_module")
    @patch("examples.ca_handler.mswcce_ca_handler.os.path.exists")
    @patch("examples.ca_handler.mswcce_ca_handler.os.path.isfile")
    def test_082_kerberos_prepare_python_backend_all_acquire_methods_failed(
        self,
        mock_isfile,
        mock_exists,
        mock_import_module,
    ):
        """test kerberos python backend returns terminal error after all acquire methods fail"""
        self.cahandler.use_kerberos = True
        self.cahandler.krb5_auth_backend = "python"
        self.cahandler.krb5_principal = "svc-a2c-enroll@EXAMPLE.COM"
        self.cahandler.krb5_keytab = "/tmp/svc.keytab"
        self.cahandler.krb5_cache = "/tmp/krb5cc_svc"

        mock_isfile.return_value = True
        mock_exists.return_value = True

        mock_gssapi = Mock()
        mock_gssapi.NameType.kerberos_principal = "kerberos_principal"
        mock_gssapi.Name.return_value = "principal"
        mock_import_module.return_value = mock_gssapi

        self.cahandler._kerberos_acquire_with_gssapi_raw = Mock(return_value=False)
        self.cahandler._kerberos_acquire_with_gssapi_highlevel = Mock(
            return_value=False
        )
        self.cahandler._kerberos_acquire_with_kinit = Mock(return_value=False)

        error = self.cahandler._kerberos_prepare_python_backend()

        self.assertEqual(
            "Failed to acquire kerberos credentials via gssapi/keytab.",
            error,
        )
        self.assertTrue(self.cahandler._kerberos_acquire_with_gssapi_raw.called)
        self.assertTrue(self.cahandler._kerberos_acquire_with_gssapi_highlevel.called)
        self.assertTrue(self.cahandler._kerberos_acquire_with_kinit.called)

    def test_083_kerberos_acquire_with_gssapi_raw_success(self):
        """test kerberos raw gssapi acquire success path"""
        self.cahandler.krb5_keytab = "/tmp/svc.keytab"

        mock_raw_acquire = Mock()
        mock_gssapi = Mock()
        mock_gssapi.raw = Mock()
        mock_gssapi.raw.acquire_cred_from = mock_raw_acquire

        result = self.cahandler._kerberos_acquire_with_gssapi_raw(
            mock_gssapi,
            "principal_obj",
            "/tmp/krb5cc_svc",
        )

        self.assertTrue(result)
        self.assertTrue(mock_raw_acquire.called)
        _, call_kwargs = mock_raw_acquire.call_args
        self.assertEqual(
            {
                b"client_keytab": b"/tmp/svc.keytab",
                b"ccache": b"/tmp/krb5cc_svc",
            },
            call_kwargs["store"],
        )
        self.assertEqual("principal_obj", call_kwargs["desired_name"])
        self.assertEqual("initiate", call_kwargs["cred_usage"])

    def test_084_kerberos_acquire_with_gssapi_raw_exception(self):
        """test kerberos raw gssapi acquire exception path"""
        self.cahandler.krb5_keytab = "/tmp/svc.keytab"

        mock_gssapi = Mock()
        mock_gssapi.raw = Mock()
        mock_gssapi.raw.acquire_cred_from = Mock(
            side_effect=Exception("acquire_failed")
        )

        with self.assertLogs("test_a2c", level="INFO") as lcm:
            result = self.cahandler._kerberos_acquire_with_gssapi_raw(
                mock_gssapi,
                "principal_obj",
                "/tmp/krb5cc_svc",
            )

        self.assertFalse(result)
        self.assertIn(
            "WARNING:test_a2c:Failed to acquire kerberos credentials via gssapi.raw.acquire_cred_from: acquire_failed",
            lcm.output,
        )

    def test_085_kerberos_acquire_with_gssapi_highlevel_acquire_unavailable(self):
        """test kerberos high-level gssapi acquire returns False if API is unavailable"""
        self.cahandler.krb5_keytab = "/tmp/svc.keytab"

        mock_gssapi = Mock()
        mock_gssapi.Credentials = object()

        result = self.cahandler._kerberos_acquire_with_gssapi_highlevel(
            mock_gssapi,
            "principal_obj",
            "/tmp/krb5cc_svc",
        )

        self.assertFalse(result)

    def test_086_kerberos_acquire_with_gssapi_highlevel_exception(self):
        """test kerberos high-level gssapi acquire exception path"""
        self.cahandler.krb5_keytab = "/tmp/svc.keytab"

        mock_credentials = Mock()
        mock_credentials.acquire = Mock(side_effect=Exception("highlevel_failed"))
        mock_gssapi = Mock()
        mock_gssapi.Credentials = mock_credentials

        with self.assertLogs("test_a2c", level="INFO") as lcm:
            result = self.cahandler._kerberos_acquire_with_gssapi_highlevel(
                mock_gssapi,
                "principal_obj",
                "/tmp/krb5cc_svc",
            )

        self.assertFalse(result)
        self.assertIn(
            "WARNING:test_a2c:Failed to acquire kerberos credentials via gssapi.Credentials.acquire: highlevel_failed",
            lcm.output,
        )

    @patch("examples.ca_handler.mswcce_ca_handler.subprocess.run")
    @patch("examples.ca_handler.mswcce_ca_handler.os.path.isfile")
    def test_087_kerberos_acquire_with_kinit_missing_krb5_config(
        self,
        mock_isfile,
        mock_subprocess_run,
    ):
        """test kinit fallback warns when configured krb5_config does not exist"""
        self.cahandler.krb5_keytab = "/tmp/svc.keytab"
        self.cahandler.krb5_principal = "svc-a2c-enroll@EXAMPLE.COM"
        self.cahandler.krb5_config = "/tmp/does-not-exist-krb5.conf"

        mock_isfile.return_value = False

        with self.assertLogs("test_a2c", level="INFO") as lcm:
            result = self.cahandler._kerberos_acquire_with_kinit("/tmp/krb5cc_svc")

        self.assertTrue(result)
        self.assertTrue(mock_subprocess_run.called)
        _, run_kwargs = mock_subprocess_run.call_args
        self.assertEqual("/tmp/krb5cc_svc", run_kwargs["env"]["KRB5CCNAME"])
        self.assertNotIn("KRB5_CONFIG", run_kwargs["env"])
        self.assertIn(
            "WARNING:test_a2c:Configured krb5_config does not exist: /tmp/does-not-exist-krb5.conf. Ignoring for kinit fallback.",
            lcm.output,
        )

    @patch("examples.ca_handler.mswcce_ca_handler.subprocess.run")
    def test_088_kerberos_acquire_with_kinit_exception_with_stderr(
        self,
        mock_subprocess_run,
    ):
        """test kinit fallback logs stderr content on command failure"""
        self.cahandler.krb5_keytab = "/tmp/svc.keytab"
        self.cahandler.krb5_principal = "svc-a2c-enroll@EXAMPLE.COM"

        mock_subprocess_run.side_effect = subprocess.CalledProcessError(
            returncode=1,
            cmd=["kinit"],
            stderr=b"kinit failed",
        )

        with self.assertLogs("test_a2c", level="INFO") as lcm:
            result = self.cahandler._kerberos_acquire_with_kinit("/tmp/krb5cc_svc")

        self.assertFalse(result)
        self.assertIn(
            "ERROR:test_a2c:Failed to acquire kerberos credentials via kinit: kinit failed",
            lcm.output,
        )

    @patch("examples.ca_handler.mswcce_ca_handler.subprocess.run")
    def test_089_kerberos_acquire_with_kinit_exception_without_stderr(
        self,
        mock_subprocess_run,
    ):
        """test kinit fallback logs exception object when stderr is unavailable"""
        self.cahandler.krb5_keytab = "/tmp/svc.keytab"
        self.cahandler.krb5_principal = "svc-a2c-enroll@EXAMPLE.COM"

        mock_subprocess_run.side_effect = Exception("kinit runtime failure")

        with self.assertLogs("test_a2c", level="INFO") as lcm:
            result = self.cahandler._kerberos_acquire_with_kinit("/tmp/krb5cc_svc")

        self.assertFalse(result)
        self.assertIn(
            "ERROR:test_a2c:Failed to acquire kerberos credentials via kinit: kinit runtime failure",
            lcm.output,
        )

    @patch("examples.ca_handler.mswcce_ca_handler.subprocess.run")
    def test_090_kerberos_acquire_with_kinit_command_not_found(
        self,
        mock_subprocess_run,
    ):
        """test kinit fallback handles missing kinit command"""
        self.cahandler.krb5_keytab = "/tmp/svc.keytab"
        self.cahandler.krb5_principal = "svc-a2c-enroll@EXAMPLE.COM"

        mock_subprocess_run.side_effect = FileNotFoundError("kinit")

        with self.assertLogs("test_a2c", level="INFO") as lcm:
            result = self.cahandler._kerberos_acquire_with_kinit("/tmp/krb5cc_svc")

        self.assertFalse(result)
        self.assertIn(
            "ERROR:test_a2c:kinit command not found: kinit",
            lcm.output,
        )

    def test_091_config_is_complete_kerberos_keytab_impacket_missing_cache(self):
        """test _config_is_complete fails for keytab+impacket when krb5_cache is missing"""
        self.cahandler.host = "host"
        self.cahandler.template = "template"
        self.cahandler.use_kerberos = True
        self.cahandler.krb5_auth_backend = "impacket"
        self.cahandler.krb5_principal = "svc-a2c-enroll@EXAMPLE.COM"
        self.cahandler.krb5_keytab = "/tmp/svc.keytab"
        self.cahandler.krb5_cache = None

        result, error = self.cahandler._config_is_complete()

        self.assertFalse(result)
        self.assertEqual(
            "Configuration incomplete: kerberos keytab with krb5_auth_backend=impacket requires krb5_cache.",
            error,
        )

    def test_092_config_is_complete_kerberos_user_password_fallback(self):
        """test _config_is_complete accepts kerberos user/password fallback without keytab"""
        self.cahandler.host = "host"
        self.cahandler.template = "template"
        self.cahandler.use_kerberos = True
        self.cahandler.krb5_principal = None
        self.cahandler.krb5_keytab = None
        self.cahandler.user = "user"
        self.cahandler.password = "password"

        result, error = self.cahandler._config_is_complete()

        self.assertTrue(result)
        self.assertFalse(error)

    @patch("examples.ca_handler.mswcce_ca_handler.Request")
    @patch("examples.ca_handler.mswcce_ca_handler.Target")
    @patch(
        "examples.ca_handler.mswcce_ca_handler.CAhandler._kerberos_username_from_principal"
    )
    def test_093_request_create_kerberos_keytab_mode(
        self,
        mock_username_from_principal,
        mock_target,
        mock_request,
    ):
        """test request_create uses keytab-derived username and no password in kerberos keytab mode"""
        self.cahandler.use_kerberos = True
        self.cahandler.krb5_principal = "svc-a2c-enroll@EXAMPLE.COM"
        self.cahandler.krb5_keytab = "/tmp/svc.keytab"
        self.cahandler.user = "legacy_user"
        self.cahandler.password = "legacy_password"
        self.cahandler.target_domain = "example.local"
        self.cahandler.host = "dc01.example.local"
        self.cahandler.domain_controller = "10.0.0.10"
        self.cahandler.timeout = 30
        self.cahandler.ca_name = "CA01"
        self.cahandler.template = "UserTemplate"

        mock_username_from_principal.return_value = "svc-a2c-enroll"
        mock_target.return_value = "target_obj"
        mock_request.return_value = "request_obj"

        result = self.cahandler.request_create()

        self.assertEqual("request_obj", result)
        mock_username_from_principal.assert_called_once_with(
            "svc-a2c-enroll@EXAMPLE.COM"
        )
        _, target_kwargs = mock_target.call_args
        self.assertEqual("svc-a2c-enroll", target_kwargs["username"])
        self.assertEqual("", target_kwargs["password"])
        self.assertTrue(target_kwargs["no_pass"])
        _, request_kwargs = mock_request.call_args
        self.assertEqual("target_obj", request_kwargs["target"])
        self.assertTrue(request_kwargs["do_kerberos"])

    @patch("examples.ca_handler.mswcce_ca_handler.handler_config_check")
    def test_094_handler_check_kerberos_keytab_required_fields(
        self, mock_handler_check
    ):
        """test handler_check uses reduced required fields in kerberos keytab mode"""
        mock_handler_check.return_value = "ok"
        self.cahandler.use_kerberos = True
        self.cahandler.krb5_principal = "svc-a2c-enroll@EXAMPLE.COM"
        self.cahandler.krb5_keytab = "/tmp/svc.keytab"

        result = self.cahandler.handler_check()

        self.assertEqual("ok", result)
        _, call_args = mock_handler_check.call_args
        self.assertEqual(
            ["host", "template", "ca_name", "target_domain"],
            (
                call_args["required_fields"]
                if "required_fields" in call_args
                else mock_handler_check.call_args[0][2]
            ),
        )

    @patch("examples.ca_handler.mswcce_ca_handler.load_config")
    def test_095_config_load_unknown_krb5_auth_backend_fallback(self, mock_load_cfg):
        """test _config_parameters_load falls back to impacket for unknown krb5_auth_backend"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {
            "use_kerberos": "True",
            "krb5_auth_backend": "unknown_backend",
        }
        mock_load_cfg.return_value = parser

        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.cahandler._config_load()

        self.assertEqual("impacket", self.cahandler.krb5_auth_backend)
        self.assertIn(
            "WARNING:test_a2c:Unknown krb5_auth_backend 'unknown_backend'. Falling back to 'impacket'.",
            lcm.output,
        )


if __name__ == "__main__":

    unittest.main()
