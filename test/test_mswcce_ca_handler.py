#!/usr/bin/python
# -*- coding: utf-8 -*-
"""unittests for openssl_ca_handler"""
# pylint: disable=C0415, R0904, R0913, W0212
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
        self.assertFalse(self.cahandler.allowed_domainlist)
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
        self.assertFalse(self.cahandler.allowed_domainlist)

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
        self.assertFalse(self.cahandler.allowed_domainlist)
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
        self.assertFalse(self.cahandler.allowed_domainlist)

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
        self.assertFalse(self.cahandler.allowed_domainlist)

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
        self.assertFalse(self.cahandler.allowed_domainlist)

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
        self.assertFalse(self.cahandler.allowed_domainlist)

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
        self.assertFalse(self.cahandler.allowed_domainlist)

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
        self.assertFalse(self.cahandler.allowed_domainlist)

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
        self.assertFalse(self.cahandler.allowed_domainlist)

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
        self.assertFalse(self.cahandler.allowed_domainlist)

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
        self.assertFalse(self.cahandler.allowed_domainlist)

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
        self.assertFalse(self.cahandler.allowed_domainlist)
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
        self.assertFalse(self.cahandler.allowed_domainlist)
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
        self.assertFalse(self.cahandler.allowed_domainlist)

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
        self.assertFalse(self.cahandler.allowed_domainlist)

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
        self.assertFalse(self.cahandler.allowed_domainlist)
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
        self.assertFalse(self.cahandler.allowed_domainlist)
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
        self.assertFalse(self.cahandler.allowed_domainlist)

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
        self.assertFalse(self.cahandler.allowed_domainlist)

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
        self.assertFalse(self.cahandler.allowed_domainlist)

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
        self.assertFalse(self.cahandler.allowed_domainlist)

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
        self.assertFalse(self.cahandler.allowed_domainlist)

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
        self.assertFalse(self.cahandler.allowed_domainlist)

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
        self.assertFalse(self.cahandler.allowed_domainlist)

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
        self.assertFalse(self.cahandler.allowed_domainlist)

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
        self.assertEqual(["allowed_domainlist"], self.cahandler.allowed_domainlist)

    @patch("examples.ca_handler.mswcce_ca_handler.load_config")
    def test_030_config_load(self, mock_load_cfg):
        """test _config_load - load template from config file"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"allowed_domainlist": "wrongstring"}
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
        self.assertEqual("failed to parse", self.cahandler.allowed_domainlist)
        self.assertIn(
            "WARNING:test_a2c:Failed to load allowed_domainlist from configuration: Expecting value: line 1 column 1 (char 0)",
            lcm.output,
        )

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
        self.assertFalse(self.cahandler.allowed_domainlist)
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
        self.assertFalse(self.cahandler.allowed_domainlist)
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
        self.assertFalse(self.cahandler.allowed_domainlist)
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
        self.assertFalse(self.cahandler.allowed_domainlist)
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
        self.assertFalse(self.cahandler.allowed_domainlist)
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
        self.assertFalse(self.cahandler.allowed_domainlist)
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
        self.assertFalse(self.cahandler.allowed_domainlist)
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

    @patch("examples.ca_handler.mswcce_ca_handler.allowed_domainlist_check")
    @patch("examples.ca_handler.mswcce_ca_handler.CAhandler.request_create")
    @patch("examples.ca_handler.mswcce_ca_handler.convert_string_to_byte")
    @patch("examples.ca_handler.mswcce_ca_handler.convert_byte_to_string")
    @patch("examples.ca_handler.mswcce_ca_handler.CAhandler._file_load")
    @patch("examples.ca_handler.mswcce_ca_handler.build_pem_file")
    def test_050_enroll(
        self, mock_pem, mock_file, mock_b2s, mock_s2b, mock_rcr, mock_dlchk
    ):
        """test enrollment - certificate and bundling successful"""
        self.cahandler.host = "host"
        self.cahandler.user = "user"
        self.cahandler.password = "password"
        self.cahandler.template = "template"
        mock_dlchk.return_value = False
        mock_rcr.return_value = Mock(return_value="raw_data")
        mock_file.return_value = "file_load"
        mock_s2b.return_value = "s2b"
        mock_b2s.return_value = "b2s"
        self.assertEqual(
            (None, "b2sfile_load", "b2s", None), self.cahandler.enroll("csr")
        )
        self.assertTrue(mock_rcr.called)
        self.assertTrue(mock_dlchk.called)

    @patch("examples.ca_handler.mswcce_ca_handler.allowed_domainlist_check")
    @patch("examples.ca_handler.mswcce_ca_handler.CAhandler.request_create")
    @patch("examples.ca_handler.mswcce_ca_handler.convert_string_to_byte")
    @patch("examples.ca_handler.mswcce_ca_handler.convert_byte_to_string")
    @patch("examples.ca_handler.mswcce_ca_handler.CAhandler._file_load")
    @patch("examples.ca_handler.mswcce_ca_handler.build_pem_file")
    def test_051_enroll(
        self, mock_pem, mock_file, mock_b2s, mock_s2b, mock_rcr, mock_dlchk
    ):
        """test enrollment - certificate and bundling successful"""
        self.cahandler.host = "host"
        self.cahandler.user = "user"
        self.cahandler.password = "password"
        self.cahandler.template = "template"
        self.cahandler.allowed_domainlist = ["allowed_domainlist"]
        mock_dlchk.return_value = False
        mock_rcr.return_value = Mock(return_value="raw_data")
        mock_file.return_value = "file_load"
        mock_s2b.return_value = "s2b"
        mock_b2s.return_value = "b2s"
        self.assertEqual(
            (None, "b2sfile_load", "b2s", None), self.cahandler.enroll("csr")
        )
        self.assertTrue(mock_rcr.called)
        self.assertTrue(mock_dlchk.called)

    @patch("examples.ca_handler.mswcce_ca_handler.allowed_domainlist_check")
    @patch("examples.ca_handler.mswcce_ca_handler.CAhandler.request_create")
    @patch("examples.ca_handler.mswcce_ca_handler.convert_string_to_byte")
    @patch("examples.ca_handler.mswcce_ca_handler.convert_byte_to_string")
    @patch("examples.ca_handler.mswcce_ca_handler.CAhandler._file_load")
    @patch("examples.ca_handler.mswcce_ca_handler.build_pem_file")
    def test_052_enroll(
        self, mock_pem, mock_file, mock_b2s, mock_s2b, mock_rcr, mock_dlchk
    ):
        """test enrollment - certificate and bundling successful"""
        self.cahandler.host = "host"
        self.cahandler.user = "user"
        self.cahandler.password = "password"
        self.cahandler.template = "template"
        self.cahandler.allowed_domainlist = ["allowed_domainlist"]
        mock_dlchk.return_value = "error"
        mock_rcr.return_value = Mock(return_value="raw_data")
        mock_file.return_value = "file_load"
        mock_s2b.return_value = "s2b"
        mock_b2s.return_value = "b2s"
        self.assertEqual(("error", None, None, None), self.cahandler.enroll("csr"))
        self.assertFalse(mock_rcr.called)
        self.assertTrue(mock_dlchk.called)

    @patch("examples.ca_handler.mswcce_ca_handler.allowed_domainlist_check")
    @patch("examples.ca_handler.mswcce_ca_handler.CAhandler.request_create")
    @patch("examples.ca_handler.mswcce_ca_handler.convert_string_to_byte")
    @patch("examples.ca_handler.mswcce_ca_handler.convert_byte_to_string")
    @patch("examples.ca_handler.mswcce_ca_handler.CAhandler._file_load")
    @patch("examples.ca_handler.mswcce_ca_handler.build_pem_file")
    def test_053_enroll(
        self, mock_pem, mock_file, mock_b2s, mock_s2b, mock_rcr, mock_dlchk
    ):
        """test enrollment - certificate and bundling successful"""
        self.cahandler.host = "host"
        self.cahandler.user = "user"
        self.cahandler.password = "password"
        self.cahandler.template = "template"
        self.cahandler.allowed_domainlist = "ADLFAILURE"
        mock_dlchk.return_value = "error"
        mock_rcr.return_value = Mock(return_value="raw_data")
        mock_file.return_value = "file_load"
        mock_s2b.return_value = "s2b"
        mock_b2s.return_value = "b2s"
        self.assertEqual(("error", None, None, None), self.cahandler.enroll("csr"))
        self.assertFalse(mock_rcr.called)
        self.assertTrue(mock_dlchk.called)

    @patch("examples.ca_handler.mswcce_ca_handler.CAhandler.request_create")
    @patch("examples.ca_handler.mswcce_ca_handler.convert_string_to_byte")
    @patch("examples.ca_handler.mswcce_ca_handler.convert_byte_to_string")
    @patch("examples.ca_handler.mswcce_ca_handler.CAhandler._file_load")
    @patch("examples.ca_handler.mswcce_ca_handler.build_pem_file")
    def test_054_enroll(self, mock_pem, mock_file, mock_b2s, mock_s2b, mock_rcr):
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
    def test_055_enroll(
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
    def test_056_enroll(
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
    def test_057_enroll(
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
    def test_058_request_create(self, mock_target, mock_request, mock_ecl):
        """test request create"""
        mock_target.return_value = True
        mock_request.return_value = "foo"
        self.assertEqual("foo", self.cahandler.request_create())
        self.assertFalse(mock_ecl.called)

    @patch("examples.ca_handler.mswcce_ca_handler.enrollment_config_log")
    @patch("examples.ca_handler.mswcce_ca_handler.Request")
    @patch("examples.ca_handler.mswcce_ca_handler.Target")
    def test_059_request_create(self, mock_target, mock_request, mock_ecl):
        """test request create"""
        mock_target.return_value = True
        mock_request.return_value = "foo"
        self.cahandler.enrollment_config_log = True
        self.assertEqual("foo", self.cahandler.request_create())
        self.assertTrue(mock_ecl.called)

    @patch("examples.ca_handler.mswcce_ca_handler.CAhandler._config_load")
    def test_060__enter(self, mock_cfgload):
        """CAhandler._enter() with config load"""
        self.cahandler.host = "host"
        self.cahandler.__enter__()
        self.assertFalse(mock_cfgload.called)

    @patch("examples.ca_handler.mswcce_ca_handler.CAhandler._config_load")
    def test_061__enter(self, mock_cfgload):
        """CAhandler._enter() with config load"""
        self.cahandler.host = None
        self.cahandler.__enter__()
        self.assertTrue(mock_cfgload.called)

    @patch("examples.ca_handler.mswcce_ca_handler.header_info_get")
    def test_062_template_name_get(self, mock_header):
        """test _template_name_get()"""
        mock_header.return_value = [
            {
                "header_info": '{"header_field": "template=foo lego-cli/4.14.2 xenolf-acme/4.14.2 (release; linux; amd64)"}'
            }
        ]
        self.cahandler.header_info_field = "header_field"
        self.assertEqual("foo", self.cahandler._template_name_get("csr"))

    @patch("examples.ca_handler.mswcce_ca_handler.header_info_get")
    def test_063_template_name_get(self, mock_header):
        """test _template_name_get()"""
        mock_header.return_value = [
            {
                "header_info": '{"header_field": "Template=foo lego-cli/4.14.2 xenolf-acme/4.14.2 (release; linux; amd64)"}'
            }
        ]
        self.cahandler.header_info_field = "header_field"
        self.assertEqual("foo", self.cahandler._template_name_get("csr"))

    @patch("examples.ca_handler.mswcce_ca_handler.header_info_get")
    def test_064_template_name_get(self, mock_header):
        """test _template_name_get()"""
        mock_header.return_value = [{"header_info": "header_info"}]
        self.cahandler.header_info_field = "header_field"
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.assertFalse(self.cahandler._template_name_get("csr"))
        self.assertIn(
            "ERROR:test_a2c:Failed to parse template from header info: Expecting value: line 1 column 1 (char 0)",
            lcm.output,
        )

    def test_065_config_headerinfo_load(self):
        """test config_headerinfo_load()"""
        config_dic = {"Order": {"header_info_list": '["foo", "bar", "foobar"]'}}
        self.cahandler._config_headerinfo_load(config_dic)
        self.assertEqual("foo", self.cahandler.header_info_field)

    def test_066_config_headerinfo_load(self):
        """test config_headerinfo_load()"""
        config_dic = {"Order": {"header_info_list": '["foo"]'}}
        self.cahandler._config_headerinfo_load(config_dic)
        self.assertEqual("foo", self.cahandler.header_info_field)

    def test_067_config_headerinfo_load(self):
        """test config_headerinfo_load()"""
        config_dic = {"Order": {"header_info_list": "foo"}}
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.cahandler._config_headerinfo_load(config_dic)
        self.assertFalse(self.cahandler.header_info_field)
        self.assertIn(
            "WARNING:test_a2c:Failed to parse header_info_list from configuration: Expecting value: line 1 column 1 (char 0)",
            lcm.output,
        )


if __name__ == "__main__":

    unittest.main()
