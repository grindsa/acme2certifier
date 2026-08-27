#!/usr/bin/python
# -*- coding: utf-8 -*-
"""unittests for openssl_ca_handler"""

# pylint: disable=C0415, R0904, R0913, W0212
import os
import subprocess
import sys
import unittest
from unittest.mock import patch, mock_open, Mock, MagicMock
import configparser

sys.path.insert(0, ".")
sys.path.insert(1, "..")


class TestACMEHandler(unittest.TestCase):
    """test class for msicpr_ca_handler"""

    def setUp(self):
        """setup unittest"""
        import logging
        from acme2certifier.cahandlers.msicpr_ca_handler import CAhandler

        logging.basicConfig(level=logging.CRITICAL)
        self.logger = logging.getLogger("test_a2c")
        self.cahandler = CAhandler(False, self.logger)

    def tearDown(self):
        """teardown"""
        pass

    def test_001_default(self):
        """default test which always passes"""
        self.assertEqual("foo", "foo")

    @patch("acme2certifier.cahandlers.msicpr_ca_handler.load_config")
    def test_002_config_load(self, mock_load_cfg):
        """test _config_load no cahandler section"""
        parser = configparser.ConfigParser()
        self.cahandler._config_load()
        self.assertFalse(self.cahandler.host)
        self.assertFalse(self.cahandler.user)
        self.assertFalse(self.cahandler.password)
        self.assertFalse(self.cahandler.template)
        self.assertFalse(self.cahandler.target_domain)
        self.assertFalse(self.cahandler.domain_controller)
        self.assertFalse(self.cahandler.ca_name)
        self.assertFalse(self.cahandler.ca_bundle)
        self.assertFalse(self.cahandler.use_kerberos)
        self.assertEqual(5, self.cahandler.timeout)

    @patch("acme2certifier.cahandlers.msicpr_ca_handler.load_config")
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
        self.assertFalse(self.cahandler.target_domain)
        self.assertFalse(self.cahandler.domain_controller)
        self.assertFalse(self.cahandler.ca_name)
        self.assertFalse(self.cahandler.ca_bundle)
        self.assertFalse(self.cahandler.use_kerberos)
        self.assertEqual(5, self.cahandler.timeout)

    @patch.dict("os.environ", {"host_var": "host_var"})
    @patch("acme2certifier.cahandlers.msicpr_ca_handler.load_config")
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
        self.assertFalse(self.cahandler.target_domain)
        self.assertFalse(self.cahandler.domain_controller)
        self.assertFalse(self.cahandler.ca_name)
        self.assertFalse(self.cahandler.ca_bundle)
        self.assertFalse(self.cahandler.use_kerberos)

    @patch.dict("os.environ", {"host_var": "host_var"})
    @patch("acme2certifier.cahandlers.msicpr_ca_handler.load_config")
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
    @patch("acme2certifier.cahandlers.msicpr_ca_handler.load_config")
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
        self.assertFalse(self.cahandler.target_domain)
        self.assertFalse(self.cahandler.domain_controller)
        self.assertFalse(self.cahandler.ca_name)
        self.assertFalse(self.cahandler.ca_bundle)
        self.assertIn("INFO:test_a2c:Overwrite host", lcm.output)
        self.assertFalse(self.cahandler.use_kerberos)

    @patch("acme2certifier.cahandlers.msicpr_ca_handler.load_config")
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
        self.assertFalse(self.cahandler.target_domain)
        self.assertFalse(self.cahandler.domain_controller)
        self.assertFalse(self.cahandler.ca_name)
        self.assertFalse(self.cahandler.ca_bundle)
        self.assertFalse(self.cahandler.use_kerberos)

    @patch.dict("os.environ", {"user_var": "user_var"})
    @patch("acme2certifier.cahandlers.msicpr_ca_handler.load_config")
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
        self.assertFalse(self.cahandler.target_domain)
        self.assertFalse(self.cahandler.domain_controller)
        self.assertFalse(self.cahandler.ca_name)
        self.assertFalse(self.cahandler.ca_bundle)
        self.assertFalse(self.cahandler.use_kerberos)

    @patch.dict("os.environ", {"user_var": "user_var"})
    @patch("acme2certifier.cahandlers.msicpr_ca_handler.load_config")
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
    @patch("acme2certifier.cahandlers.msicpr_ca_handler.load_config")
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
        self.assertFalse(self.cahandler.target_domain)
        self.assertFalse(self.cahandler.domain_controller)
        self.assertFalse(self.cahandler.ca_name)
        self.assertFalse(self.cahandler.ca_bundle)
        self.assertIn("INFO:test_a2c:Overwrite user", lcm.output)
        self.assertFalse(self.cahandler.use_kerberos)

    @patch("acme2certifier.cahandlers.msicpr_ca_handler.load_config")
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
        self.assertFalse(self.cahandler.target_domain)
        self.assertFalse(self.cahandler.domain_controller)
        self.assertFalse(self.cahandler.ca_name)
        self.assertFalse(self.cahandler.ca_bundle)
        self.assertFalse(self.cahandler.use_kerberos)

    @patch.dict("os.environ", {"password_var": "password_var"})
    @patch("acme2certifier.cahandlers.msicpr_ca_handler.load_config")
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
        self.assertFalse(self.cahandler.target_domain)
        self.assertFalse(self.cahandler.domain_controller)
        self.assertFalse(self.cahandler.ca_name)
        self.assertFalse(self.cahandler.ca_bundle)
        self.assertFalse(self.cahandler.use_kerberos)

    @patch.dict("os.environ", {"password_var": "password_var"})
    @patch("acme2certifier.cahandlers.msicpr_ca_handler.load_config")
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
    @patch("acme2certifier.cahandlers.msicpr_ca_handler.load_config")
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
        self.assertFalse(self.cahandler.target_domain)
        self.assertFalse(self.cahandler.domain_controller)
        self.assertFalse(self.cahandler.ca_name)
        self.assertFalse(self.cahandler.ca_bundle)
        self.assertIn("INFO:test_a2c:Overwrite password", lcm.output)
        self.assertFalse(self.cahandler.use_kerberos)

    @patch("acme2certifier.cahandlers.msicpr_ca_handler.load_config")
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
        self.assertFalse(self.cahandler.target_domain)
        self.assertFalse(self.cahandler.domain_controller)
        self.assertFalse(self.cahandler.ca_name)
        self.assertFalse(self.cahandler.ca_bundle)
        self.assertFalse(self.cahandler.use_kerberos)
        self.assertEqual(5, self.cahandler.timeout)

    @patch("acme2certifier.cahandlers.msicpr_ca_handler.load_config")
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
        self.assertFalse(self.cahandler.domain_controller)
        self.assertFalse(self.cahandler.ca_name)
        self.assertFalse(self.cahandler.ca_bundle)
        self.assertFalse(self.cahandler.use_kerberos)
        self.assertEqual(5, self.cahandler.timeout)

    @patch("acme2certifier.cahandlers.msicpr_ca_handler.load_config")
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
        self.assertFalse(self.cahandler.target_domain)
        self.assertFalse(self.cahandler.ca_name)
        self.assertFalse(self.cahandler.ca_bundle)
        self.assertFalse(self.cahandler.use_kerberos)

    @patch("acme2certifier.cahandlers.msicpr_ca_handler.load_config")
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
        self.assertFalse(self.cahandler.target_domain)
        self.assertFalse(self.cahandler.ca_name)
        self.assertFalse(self.cahandler.ca_bundle)
        self.assertFalse(self.cahandler.use_kerberos)

    @patch("acme2certifier.cahandlers.msicpr_ca_handler.load_config")
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
        self.assertFalse(self.cahandler.target_domain)
        self.assertFalse(self.cahandler.domain_controller)
        self.assertFalse(self.cahandler.ca_bundle)
        self.assertFalse(self.cahandler.use_kerberos)
        self.assertEqual(5, self.cahandler.timeout)

    @patch("acme2certifier.cahandlers.msicpr_ca_handler.load_config")
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
        self.assertFalse(self.cahandler.target_domain)
        self.assertFalse(self.cahandler.domain_controller)
        self.assertFalse(self.cahandler.ca_name)
        self.assertFalse(self.cahandler.use_kerberos)
        self.assertEqual(5, self.cahandler.timeout)

    @patch("acme2certifier.cahandlers.msicpr_ca_handler.load_config")
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
        self.assertFalse(self.cahandler.target_domain)
        self.assertFalse(self.cahandler.domain_controller)
        self.assertFalse(self.cahandler.ca_name)
        self.assertFalse(self.cahandler.use_kerberos)

    @patch("acme2certifier.cahandlers.msicpr_ca_handler.load_config")
    def test_022_config_load_security_warnings_ntlm(self, mock_load_cfg):
        """test _config_load emits NTLM and ca_bundle security warnings"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"host": "ca.example"}
        mock_load_cfg.return_value = parser
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.cahandler._config_load()
        self.assertIn(
            "WARNING:test_a2c:Kerberos is disabled; MS-ICPR authentication uses NTLM. "
            "Prefer use_kerberos=True (see Microsoft guidance on NTLM).",
            lcm.output,
        )
        self.assertIn(
            "WARNING:test_a2c:MS-ICPR enrolls over SMB/DCE-RPC. Certificate packaging uses the CMS "
            "chain from the enrollment response when available; ca_bundle is an "
            "optional local PEM fallback and does not authenticate the CA endpoint.",
            lcm.output,
        )

    @patch("acme2certifier.cahandlers.msicpr_ca_handler.load_config")
    def test_023_config_load_security_warnings_kerberos_skips_ntlm(self, mock_load_cfg):
        """test _config_load skips NTLM warning when Kerberos is enabled"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"host": "ca.example", "use_kerberos": "True"}
        mock_load_cfg.return_value = parser
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.cahandler._config_load()
        self.assertTrue(self.cahandler.use_kerberos)
        self.assertFalse(any("authentication uses NTLM" in msg for msg in lcm.output))
        self.assertTrue(
            any(
                "Certificate packaging uses the CMS" in msg
                or "ca_bundle is an optional local PEM fallback" in msg
                for msg in lcm.output
            )
        )

    @patch("acme2certifier.cahandlers.msicpr_ca_handler.load_config")
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
        self.assertFalse(self.cahandler.target_domain)
        self.assertFalse(self.cahandler.domain_controller)
        self.assertFalse(self.cahandler.ca_name)
        self.assertTrue(self.cahandler.use_kerberos)

    @patch("acme2certifier.cahandlers.msicpr_ca_handler.load_config")
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
        self.assertFalse(self.cahandler.target_domain)
        self.assertFalse(self.cahandler.domain_controller)
        self.assertFalse(self.cahandler.ca_name)
        self.assertTrue(self.cahandler.use_kerberos)

    @patch("acme2certifier.cahandlers.msicpr_ca_handler.load_config")
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
        self.assertFalse(self.cahandler.target_domain)
        self.assertFalse(self.cahandler.domain_controller)
        self.assertFalse(self.cahandler.ca_name)
        self.assertFalse(self.cahandler.use_kerberos)

    @patch("acme2certifier.cahandlers.msicpr_ca_handler.load_config")
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
        self.assertFalse(self.cahandler.target_domain)
        self.assertFalse(self.cahandler.domain_controller)
        self.assertFalse(self.cahandler.ca_name)
        self.assertFalse(self.cahandler.use_kerberos)

    @patch("acme2certifier.cahandlers.msicpr_ca_handler.load_config")
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
        self.assertFalse(self.cahandler.target_domain)
        self.assertFalse(self.cahandler.domain_controller)
        self.assertFalse(self.cahandler.ca_name)
        self.assertFalse(self.cahandler.use_kerberos)
        self.assertIn(
            "WARNING:test_a2c:Failed to parse 'use_kerberos' from configuration. Using default value False. Error: Not a boolean: aaaa",
            lcm.output,
        )

    @patch("acme2certifier.cahandlers.msicpr_ca_handler.load_config")
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
        self.assertFalse(self.cahandler.target_domain)
        self.assertFalse(self.cahandler.domain_controller)
        self.assertFalse(self.cahandler.ca_name)
        self.assertFalse(self.cahandler.use_kerberos)

    @patch("acme2certifier.cahandlers.msicpr_ca_handler.load_config")
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
        self.assertFalse(self.cahandler.target_domain)
        self.assertFalse(self.cahandler.domain_controller)
        self.assertFalse(self.cahandler.ca_name)
        self.assertFalse(self.cahandler.use_kerberos)

    @patch("acme2certifier.cahandlers.msicpr_ca_handler.load_config")
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
        self.assertFalse(self.cahandler.target_domain)
        self.assertFalse(self.cahandler.domain_controller)
        self.assertFalse(self.cahandler.ca_name)
        self.assertFalse(self.cahandler.use_kerberos)
        self.assertEqual(20, self.cahandler.timeout)

    @patch("acme2certifier.cahandlers.msicpr_ca_handler.load_config")
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
        self.assertFalse(self.cahandler.target_domain)
        self.assertFalse(self.cahandler.domain_controller)
        self.assertFalse(self.cahandler.ca_name)
        self.assertFalse(self.cahandler.use_kerberos)
        self.assertEqual(20, self.cahandler.timeout)

    @patch("acme2certifier.cahandlers.msicpr_ca_handler.load_config")
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
        self.assertFalse(self.cahandler.target_domain)
        self.assertFalse(self.cahandler.domain_controller)
        self.assertFalse(self.cahandler.ca_name)
        self.assertFalse(self.cahandler.use_kerberos)
        self.assertIn(
            "WARNING:test_a2c:Failed to parse 'timeout' from configuration. Using default value 5. Error: invalid literal for int() with base 10: 'aaaa'",
            lcm.output,
        )
        self.assertEqual(5, self.cahandler.timeout)

    @patch("acme2certifier.cahandlers.msicpr_ca_handler.load_config")
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
        self.assertFalse(self.cahandler.target_domain)
        self.assertFalse(self.cahandler.domain_controller)
        self.assertFalse(self.cahandler.ca_name)
        self.assertFalse(self.cahandler.use_kerberos)
        self.assertTrue(self.cahandler.enrollment_config_log)

    @patch("acme2certifier.cahandlers.msicpr_ca_handler.load_config")
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
        self.assertFalse(self.cahandler.target_domain)
        self.assertFalse(self.cahandler.domain_controller)
        self.assertFalse(self.cahandler.ca_name)
        self.assertFalse(self.cahandler.use_kerberos)
        self.assertFalse(self.cahandler.enrollment_config_log)

    @patch("acme2certifier.cahandlers.msicpr_ca_handler.load_config")
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
        self.assertFalse(self.cahandler.target_domain)
        self.assertFalse(self.cahandler.domain_controller)
        self.assertFalse(self.cahandler.ca_name)
        self.assertFalse(self.cahandler.use_kerberos)
        self.assertFalse(self.cahandler.enrollment_config_log)

    @patch("acme2certifier.cahandlers.msicpr_ca_handler.load_config")
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

    @patch("acme2certifier.cahandlers.msicpr_ca_handler.CAhandler.request_create")
    def test_043_enroll(self, mock_rcr):
        """test enrollment - unconfigured"""
        self.assertEqual(
            (
                "Configuration error: host, user, password, or template is missing",
                None,
                None,
                None,
            ),
            self.cahandler.enroll("csr"),
        )
        self.assertFalse(mock_rcr.called)

    @patch("acme2certifier.cahandlers.msicpr_ca_handler.CAhandler.request_create")
    def test_044_enroll(self, mock_rcr):
        """test enrollment - host unconfigured"""
        self.cahandler.host = None
        self.cahandler.user = "user"
        self.cahandler.password = "password"
        self.cahandler.template = "template"
        self.assertEqual(
            (
                "Configuration error: host, user, password, or template is missing",
                None,
                None,
                None,
            ),
            self.cahandler.enroll("csr"),
        )
        self.assertFalse(mock_rcr.called)

    @patch("acme2certifier.cahandlers.msicpr_ca_handler.CAhandler.request_create")
    def test_045_enroll(self, mock_rcr):
        """test enrollment - user unconfigured"""
        self.cahandler.host = "host"
        self.cahandler.user = None
        self.cahandler.password = "password"
        self.cahandler.template = "template"
        self.assertEqual(
            (
                "Configuration error: host, user, password, or template is missing",
                None,
                None,
                None,
            ),
            self.cahandler.enroll("csr"),
        )
        self.assertFalse(mock_rcr.called)

    @patch("acme2certifier.cahandlers.msicpr_ca_handler.CAhandler.request_create")
    def test_046_enroll(self, mock_rcr):
        """test enrollment - password unconfigured"""
        self.cahandler.host = "host"
        self.cahandler.user = "user"
        self.cahandler.password = None
        self.cahandler.template = "template"
        self.assertEqual(
            (
                "Configuration error: host, user, password, or template is missing",
                None,
                None,
                None,
            ),
            self.cahandler.enroll("csr"),
        )
        self.assertFalse(mock_rcr.called)

    @patch("acme2certifier.cahandlers.msicpr_ca_handler.CAhandler.request_create")
    def test_047_enroll(self, mock_rcr):
        """test enrollment - template unconfigured"""
        self.cahandler.host = "host"
        self.cahandler.user = "user"
        self.cahandler.password = "password"
        self.cahandler.template = None
        self.assertEqual(
            (
                "Configuration error: host, user, password, or template is missing",
                None,
                None,
                None,
            ),
            self.cahandler.enroll("csr"),
        )
        self.assertFalse(mock_rcr.called)

    @patch("acme2certifier.cahandlers.msicpr_ca_handler.CAhandler.request_create")
    @patch("acme2certifier.cahandlers.msicpr_ca_handler.convert_string_to_byte")
    @patch("acme2certifier.cahandlers.msicpr_ca_handler.convert_byte_to_string")
    @patch("acme2certifier.cahandlers.msicpr_ca_handler.CAhandler._file_load")
    @patch("acme2certifier.cahandlers.msicpr_ca_handler.build_pem_file")
    def test_048_enroll(self, mock_pem, mock_file, mock_b2s, mock_s2b, mock_rcr):
        """test enrollment - ca_server.get_cert() triggers exception"""
        self.cahandler.host = "host"
        self.cahandler.user = "user"
        self.cahandler.password = "password"
        self.cahandler.template = "template"
        mock_request = Mock()
        mock_request.get_cert.return_value = {
            "request_id": 1,
            "disposition": 3,
            "disposition_message": None,
            "certificate": "raw_data",
        }
        mock_rcr.return_value = mock_request
        mock_file.return_value = "file_load"
        mock_s2b.return_value = "s2b"
        mock_b2s.side_effect = Exception("ex_b2s")
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.assertEqual(
                (
                    "Could not get certificate from CA server",
                    None,
                    None,
                    None,
                ),
                self.cahandler.enroll("csr"),
            )
        self.assertIn("ERROR:test_a2c:Enrollment failed with error: ex_b2s", lcm.output)
        self.assertTrue(mock_rcr.called)

    @patch("acme2certifier.cahandlers.msicpr_ca_handler.CAhandler.request_create")
    @patch("acme2certifier.cahandlers.msicpr_ca_handler.convert_string_to_byte")
    @patch("acme2certifier.cahandlers.msicpr_ca_handler.convert_byte_to_string")
    @patch("acme2certifier.cahandlers.msicpr_ca_handler.CAhandler._file_load")
    @patch("acme2certifier.cahandlers.msicpr_ca_handler.build_pem_file")
    def test_049_enroll(self, mock_pem, mock_file, mock_b2s, mock_s2b, mock_rcr):
        """test enrollment - no certificate returned by ca_server.get_cert()"""
        self.cahandler.host = "host"
        self.cahandler.user = "user"
        self.cahandler.password = "password"
        self.cahandler.template = "template"
        mock_request = Mock()
        mock_request.get_cert.return_value = {
            "request_id": 1,
            "disposition": 3,
            "disposition_message": None,
            "certificate": "raw_data",
        }
        mock_rcr.return_value = mock_request
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

    @patch("acme2certifier.cahandlers.msicpr_ca_handler.CAhandler.request_create")
    @patch("acme2certifier.cahandlers.msicpr_ca_handler.convert_string_to_byte")
    @patch("acme2certifier.cahandlers.msicpr_ca_handler.convert_byte_to_string")
    @patch("acme2certifier.cahandlers.msicpr_ca_handler.CAhandler._file_load")
    @patch("acme2certifier.cahandlers.msicpr_ca_handler.build_pem_file")
    def test_050_enroll(self, mock_pem, mock_file, mock_b2s, mock_s2b, mock_rcr):
        """test enrollment - certificate and bundling successful"""
        self.cahandler.host = "host"
        self.cahandler.user = "user"
        self.cahandler.password = "password"
        self.cahandler.template = "template"
        self.cahandler.ca_bundle = "ca_bundle"
        mock_request = Mock()
        mock_request.get_cert.return_value = {
            "request_id": 1,
            "disposition": 3,
            "disposition_message": None,
            "certificate": "raw_data",
        }
        mock_rcr.return_value = mock_request
        mock_file.return_value = "file_load"
        mock_s2b.return_value = "s2b"
        mock_b2s.return_value = "b2s"
        self.assertEqual(
            (None, "b2sfile_load", "b2s", None), self.cahandler.enroll("csr")
        )
        self.assertTrue(mock_rcr.called)

    @patch("acme2certifier.cahandlers.msicpr_ca_handler.CAhandler.request_create")
    @patch("acme2certifier.cahandlers.msicpr_ca_handler.convert_string_to_byte")
    @patch("acme2certifier.cahandlers.msicpr_ca_handler.convert_byte_to_string")
    @patch("acme2certifier.cahandlers.msicpr_ca_handler.CAhandler._file_load")
    @patch("acme2certifier.cahandlers.msicpr_ca_handler.build_pem_file")
    def test_051_enroll(self, mock_pem, mock_file, mock_b2s, mock_s2b, mock_rcr):
        """test enrollment - certificate and bundling successful"""
        self.cahandler.host = "host"
        self.cahandler.user = "user"
        self.cahandler.password = "password"
        self.cahandler.template = "template"
        self.cahandler.ca_bundle = "ca_bundle"
        mock_request = Mock()
        mock_request.get_cert.return_value = {
            "request_id": 1,
            "disposition": 3,
            "disposition_message": None,
            "certificate": "raw_data",
        }
        mock_rcr.return_value = mock_request
        mock_file.return_value = "file_load"
        mock_s2b.return_value = "s2b"
        mock_b2s.return_value = "b2s"
        self.assertEqual(
            (None, "b2sfile_load", "b2s", None), self.cahandler.enroll("csr")
        )
        self.assertTrue(mock_rcr.called)

    @patch("acme2certifier.cahandlers.msicpr_ca_handler.CAhandler.request_create")
    @patch("acme2certifier.cahandlers.msicpr_ca_handler.convert_string_to_byte")
    @patch("acme2certifier.cahandlers.msicpr_ca_handler.convert_byte_to_string")
    @patch("acme2certifier.cahandlers.msicpr_ca_handler.CAhandler._file_load")
    @patch("acme2certifier.cahandlers.msicpr_ca_handler.build_pem_file")
    def test_052_enroll(self, mock_pem, mock_file, mock_b2s, mock_s2b, mock_rcr):
        """test enrollment - certificate and bundling successful replacement test"""
        self.cahandler.host = "host"
        self.cahandler.user = "user"
        self.cahandler.password = "password"
        self.cahandler.template = "template"
        self.cahandler.ca_bundle = "ca_bundle"
        mock_request = Mock()
        mock_request.get_cert.return_value = {
            "request_id": 1,
            "disposition": 3,
            "disposition_message": None,
            "certificate": "raw_data",
        }
        mock_rcr.return_value = mock_request
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

    @patch("acme2certifier.cahandlers.msicpr_ca_handler.eab_profile_header_info_check")
    @patch("acme2certifier.cahandlers.msicpr_ca_handler.CAhandler.request_create")
    @patch("acme2certifier.cahandlers.msicpr_ca_handler.convert_string_to_byte")
    @patch("acme2certifier.cahandlers.msicpr_ca_handler.convert_byte_to_string")
    @patch("acme2certifier.cahandlers.msicpr_ca_handler.CAhandler._file_load")
    @patch("acme2certifier.cahandlers.msicpr_ca_handler.build_pem_file")
    def test_053_enroll(
        self, mock_pem, mock_file, mock_b2s, mock_s2b, mock_rcr, mock_eab
    ):
        """test enrollment - certificate and bundling successful replacement test"""
        self.cahandler.host = "host"
        self.cahandler.user = "user"
        self.cahandler.password = "password"
        self.cahandler.template = "template"
        mock_request = Mock()
        mock_request.get_cert.return_value = {
            "request_id": 1,
            "disposition": 3,
            "disposition_message": None,
            "certificate": "raw_data",
        }
        mock_rcr.return_value = mock_request
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

    @patch("acme2certifier.cahandlers.msicpr_ca_handler.eab_profile_header_info_check")
    @patch("acme2certifier.cahandlers.msicpr_ca_handler.CAhandler.request_create")
    @patch("acme2certifier.cahandlers.msicpr_ca_handler.convert_string_to_byte")
    @patch("acme2certifier.cahandlers.msicpr_ca_handler.convert_byte_to_string")
    @patch("acme2certifier.cahandlers.msicpr_ca_handler.CAhandler._file_load")
    @patch("acme2certifier.cahandlers.msicpr_ca_handler.build_pem_file")
    def test_054_enroll(
        self, mock_pem, mock_file, mock_b2s, mock_s2b, mock_rcr, mock_eab
    ):
        """test enrollment - certificate and bundling successful replacement test"""
        self.cahandler.host = "host"
        self.cahandler.user = "user"
        self.cahandler.password = "password"
        self.cahandler.template = "template"
        self.cahandler.header_info_field = "header_info"
        mock_request = Mock()
        mock_request.get_cert.return_value = {
            "request_id": 1,
            "disposition": 3,
            "disposition_message": None,
            "certificate": "raw_data",
        }
        mock_rcr.return_value = mock_request
        mock_file.return_value = None
        mock_s2b.return_value = "s2b"
        mock_b2s.return_value = (
            "-----BEGIN CERTIFICATE-----\nb2s_replacement\n-----END CERTIFICATE-----\n"
        )
        mock_eab.return_value = "error"
        self.assertEqual(("error", None, None, None), self.cahandler.enroll("csr"))
        self.assertFalse(mock_rcr.called)
        self.assertEqual("template", self.cahandler.template)

    @patch("acme2certifier.cahandlers.msicpr_ca_handler.eab_profile_header_info_check")
    @patch("acme2certifier.cahandlers.msicpr_ca_handler.CAhandler.request_create")
    @patch("acme2certifier.cahandlers.msicpr_ca_handler.convert_string_to_byte")
    @patch("acme2certifier.cahandlers.msicpr_ca_handler.convert_byte_to_string")
    @patch("acme2certifier.cahandlers.msicpr_ca_handler.CAhandler._file_load")
    @patch("acme2certifier.cahandlers.msicpr_ca_handler.build_pem_file")
    def test_055_enroll(
        self, mock_pem, mock_file, mock_b2s, mock_s2b, mock_rcr, mock_eab
    ):
        """test enrollment - certificate and bundling successful replacement test"""
        self.cahandler.host = "host"
        self.cahandler.user = "user"
        self.cahandler.password = "password"
        self.cahandler.template = "template"
        self.cahandler.header_info_field = "header_info"
        mock_request = Mock()
        mock_request.get_cert.return_value = {
            "request_id": 1,
            "disposition": 3,
            "disposition_message": None,
            "certificate": "raw_data",
        }
        mock_rcr.return_value = mock_request
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

    @patch("acme2certifier.cahandlers.msicpr_ca_handler.enrollment_config_log")
    @patch("acme2certifier.cahandlers.msicpr_ca_handler.Request")
    @patch("acme2certifier.cahandlers.msicpr_ca_handler.Target")
    def test_056_request_create(self, mock_target, mock_request, mock_ecl):
        """test request create"""
        mock_target.return_value = True
        mock_request.return_value = "foo"
        self.assertEqual("foo", self.cahandler.request_create())
        self.assertFalse(mock_ecl.called)

    @patch("acme2certifier.cahandlers.msicpr_ca_handler.enrollment_config_log")
    @patch("acme2certifier.cahandlers.msicpr_ca_handler.Request")
    @patch("acme2certifier.cahandlers.msicpr_ca_handler.Target")
    def test_057_request_create(self, mock_target, mock_request, mock_ecl):
        """test request create"""
        mock_target.return_value = True
        mock_request.return_value = "foo"
        self.cahandler.enrollment_config_log = True
        self.assertEqual("foo", self.cahandler.request_create())
        self.assertTrue(mock_ecl.called)
        skiplist = mock_ecl.call_args[0][2]
        for key in (
            "password",
            "krb5_keytab",
            "krb5_cache",
            "krb5_config",
            "krb5_kinit_path",
            "_kerberos_tgt",
        ):
            self.assertIn(key, skiplist)

    @patch("acme2certifier.cahandlers.msicpr_ca_handler.Request")
    @patch("acme2certifier.cahandlers.msicpr_ca_handler.Target")
    def test_058_request_create_noninteractive_no_pass(self, mock_target, mock_request):
        """test request_create enforces no_pass=True to avoid interactive password prompts"""
        mock_target.return_value = True
        mock_request.return_value = "foo"
        self.cahandler.use_kerberos = False
        self.cahandler.user = "user"
        self.cahandler.password = ""

        self.assertEqual("foo", self.cahandler.request_create())
        _, target_kwargs = mock_target.call_args
        self.assertTrue(target_kwargs["no_pass"])

    @patch("acme2certifier.cahandlers.msicpr_ca_handler.CAhandler._config_load")
    def test_059__enter(self, mock_cfgload):
        """CAhandler._enter() with config load"""
        self.cahandler.host = "host"
        self.cahandler.__enter__()
        self.assertFalse(mock_cfgload.called)

    @patch("acme2certifier.cahandlers.msicpr_ca_handler.CAhandler._config_load")
    def test_060__enter(self, mock_cfgload):
        """CAhandler._enter() with config load"""
        self.cahandler.host = None
        self.cahandler.__enter__()
        self.assertTrue(mock_cfgload.called)

    def test_061_config_headerinfo_load(self):
        """test config_headerinfo_load()"""
        config_dic = {"Order": {"header_info_list": '["foo", "bar", "foobar"]'}}
        self.cahandler._config_headerinfo_load(config_dic)
        self.assertEqual("foo", self.cahandler.header_info_field)

    def test_062_config_headerinfo_load(self):
        """test config_headerinfo_load()"""
        config_dic = {"Order": {"header_info_list": '["foo"]'}}
        self.cahandler._config_headerinfo_load(config_dic)
        self.assertEqual("foo", self.cahandler.header_info_field)

    def test_063_config_headerinfo_load(self):
        """test config_headerinfo_load()"""
        config_dic = {"Order": {"header_info_list": "foo"}}
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.cahandler._config_headerinfo_load(config_dic)
        self.assertFalse(self.cahandler.header_info_field)
        self.assertIn(
            "WARNING:test_a2c:Failed to parse header_info_list from configuration: Expecting value: line 1 column 1 (char 0)",
            lcm.output,
        )

    @patch("acme2certifier.cahandlers.msicpr_ca_handler.handler_config_check")
    def test_064_handler_check(self, mock_handler_check):
        """test handler_check"""
        mock_handler_check.return_value = "mock_handler_check"
        self.assertEqual("mock_handler_check", self.cahandler.handler_check())

    @patch("acme2certifier.cahandlers.msicpr_ca_handler.handler_config_check")
    def test_065_handler_check_rejects_invalid_kinit_path(self, mock_handler_check):
        """handler_check rejects unsafe krb5_kinit_path"""
        mock_handler_check.return_value = None
        self.cahandler.krb5_kinit_path = "/tmp/evil.sh"
        with self.assertLogs("test_a2c", level="ERROR") as lcm:
            error = self.cahandler.handler_check()
        self.assertEqual("krb5_kinit_path is invalid", error)
        self.assertTrue(any("Rejected krb5_kinit_path" in msg for msg in lcm.output))

    @patch("acme2certifier.cahandlers.msicpr_ca_handler.load_config")
    def test_066_config_load_python_kerberos_backend(self, mock_load_cfg):
        """test _config_load with python kerberos backend options"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {
            "use_kerberos": "True",
            "krb5_auth_backend": "python",
            "krb5_principal": "svc-a2c-enroll@EXAMPLE.COM",
            "krb5_keytab": "/tmp/svc.keytab",
            "krb5_cache": "/tmp/krb5cc_svc",
            "krb5_config": "/tmp/krb5.conf",
            "krb5_kinit_path": "/usr/local/bin/kinit",
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
        self.assertEqual("/usr/local/bin/kinit", self.cahandler.krb5_kinit_path)

    @patch("acme2certifier.cahandlers.msicpr_ca_handler.load_config")
    def test_067_config_load_autoselect_python_backend(self, mock_load_cfg):
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

    @patch("acme2certifier.cahandlers.msicpr_ca_handler.load_config")
    def test_068_config_load_keep_explicit_backend(self, mock_load_cfg):
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

    def test_069_config_is_complete_krb5_keytab(self):
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

    def test_070_config_is_complete_kerberos_incomplete(self):
        """test config completeness in incomplete kerberos mode"""
        self.cahandler.host = "host"
        self.cahandler.template = "template"
        self.cahandler.use_kerberos = True

        result, error = self.cahandler._config_is_complete()
        self.assertFalse(result)
        self.assertIn("kerberos is enabled", error)

    @patch(
        "acme2certifier.cahandlers.msicpr_ca_handler.CAhandler._kerberos_prepare_python_backend"
    )
    def test_071_enroll_python_backend_error(self, mock_krb_prepare):
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

    @patch(
        "acme2certifier.cahandlers.msicpr_ca_handler.CAhandler._kerberos_cleanup_temporary_ccache"
    )
    @patch(
        "acme2certifier.cahandlers.msicpr_ca_handler.CAhandler._kerberos_prepare_python_backend"
    )
    def test_072_enroll_cleans_temporary_ccache_on_prepare_failure(
        self, mock_krb_prepare, mock_cleanup
    ):
        """prepare failure after temp ccache creation still runs cleanup"""

        def _prepare_with_temp_ccache():
            self.cahandler.krb5_cache = "/tmp/acme2certifier_krb5cc_prepare_fail"
            self.cahandler._krb5_cache_is_temporary = True
            return "Failed to acquire kerberos credentials via gssapi/keytab."

        mock_krb_prepare.side_effect = _prepare_with_temp_ccache
        self.cahandler.host = "host"
        self.cahandler.user = "user"
        self.cahandler.password = "password"
        self.cahandler.template = "template"
        self.cahandler.ca_name = "ca"
        self.cahandler.target_domain = "EXAMPLE.COM"
        self.cahandler.use_kerberos = True
        self.cahandler.krb5_auth_backend = "python"
        self.cahandler.krb5_principal = "svc-a2c-enroll@EXAMPLE.COM"
        self.cahandler.krb5_keytab = "/tmp/svc.keytab"

        error, cert_bundle, cert_raw, _ = self.cahandler.enroll("csr")
        self.assertEqual(
            "Failed to acquire kerberos credentials via gssapi/keytab.",
            error,
        )
        self.assertFalse(cert_bundle)
        self.assertFalse(cert_raw)
        mock_cleanup.assert_called_once()

    @patch("acme2certifier.cahandlers.msicpr_ca_handler.importlib.import_module")
    @patch("acme2certifier.cahandlers.msicpr_ca_handler.os.path.isfile")
    def test_073_kerberos_prepare_python_backend_fallback_kinit(
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

    @patch("acme2certifier.cahandlers.msicpr_ca_handler.subprocess.run")
    @patch("acme2certifier.cahandlers.msicpr_ca_handler.os.path.isfile")
    def test_074_kerberos_acquire_with_kinit_with_krb5_config(
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
        run_args, run_kwargs = mock_subprocess_run.call_args
        self.assertEqual("kinit", run_args[0][0])
        self.assertEqual("/tmp/krb5cc_svc", run_kwargs["env"]["KRB5CCNAME"])
        self.assertEqual("/tmp/krb5.conf", run_kwargs["env"]["KRB5_CONFIG"])
        self.assertEqual(self.cahandler.KINIT_TIMEOUT_SECONDS, run_kwargs["timeout"])

    @patch("acme2certifier.cahandlers.msicpr_ca_handler.subprocess.run")
    def test_075_kerberos_acquire_with_kinit_custom_binary_path(
        self,
        mock_subprocess_run,
    ):
        """test kinit fallback uses configured kinit binary path"""
        self.cahandler.krb5_keytab = "/tmp/svc.keytab"
        self.cahandler.krb5_principal = "svc-a2c-enroll@EXAMPLE.COM"
        self.cahandler.krb5_kinit_path = "/usr/local/bin/kinit"

        result = self.cahandler._kerberos_acquire_with_kinit("/tmp/krb5cc_svc")

        self.assertTrue(result)
        run_args, _run_kwargs = mock_subprocess_run.call_args
        self.assertEqual(os.path.realpath("/usr/local/bin/kinit"), run_args[0][0])

    @patch("acme2certifier.cahandlers.msicpr_ca_handler.subprocess.run")
    def test_076_kerberos_acquire_with_kinit_rejects_unsafe_path(
        self, mock_subprocess_run
    ):
        """unsafe krb5_kinit_path is rejected before subprocess"""
        self.cahandler.krb5_keytab = "/tmp/svc.keytab"
        self.cahandler.krb5_principal = "svc-a2c-enroll@EXAMPLE.COM"
        self.cahandler.krb5_kinit_path = "/tmp/evil.sh"
        with self.assertLogs("test_a2c", level="ERROR") as lcm:
            result = self.cahandler._kerberos_acquire_with_kinit("/tmp/krb5cc_svc")
        self.assertFalse(result)
        self.assertFalse(mock_subprocess_run.called)
        self.assertTrue(any("Rejected krb5_kinit_path" in msg for msg in lcm.output))

    def test_077_kerberos_username_from_principal(self):
        """test kerberos username extraction from principal"""
        username = self.cahandler._kerberos_username_from_principal(
            "svc-a2c-enroll@EXAMPLE.COM"
        )
        self.assertEqual("svc-a2c-enroll", username)

    def test_078_kerberos_username_from_principal_missing_principal(self):
        """test kerberos username extraction when principal is missing"""
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            username = self.cahandler._kerberos_username_from_principal("")

        self.assertFalse(username)
        self.assertIn(
            "ERROR:test_a2c:Kerberos principal is not configured, cannot extract username.",
            lcm.output,
        )

    def test_079_kerberos_prepare_python_backend_skips_when_disabled(self):
        """test kerberos python backend is skipped when disabled"""
        self.cahandler.use_kerberos = False
        self.cahandler.krb5_auth_backend = "python"
        self.assertFalse(self.cahandler._kerberos_prepare_python_backend())

        self.cahandler.use_kerberos = True
        self.cahandler.krb5_auth_backend = "impacket"
        self.assertFalse(self.cahandler._kerberos_prepare_python_backend())

    def test_080_kerberos_prepare_python_backend_skips_without_keytab_config(self):
        """test kerberos python backend is skipped without keytab config"""
        self.cahandler.use_kerberos = True
        self.cahandler.krb5_auth_backend = "python"
        self.cahandler.krb5_principal = None
        self.cahandler.krb5_keytab = "/tmp/svc.keytab"

        self.assertFalse(self.cahandler._kerberos_prepare_python_backend())

    @patch("acme2certifier.cahandlers.msicpr_ca_handler.os.path.isfile")
    def test_081_kerberos_prepare_python_backend_missing_keytab_file(self, mock_isfile):
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

    @patch("acme2certifier.cahandlers.msicpr_ca_handler.importlib.import_module")
    @patch("acme2certifier.cahandlers.msicpr_ca_handler.os.path.isfile")
    def test_082_kerberos_prepare_python_backend_missing_gssapi(
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
    @patch("acme2certifier.cahandlers.msicpr_ca_handler.importlib.import_module")
    @patch("acme2certifier.cahandlers.msicpr_ca_handler.os.path.exists")
    @patch("acme2certifier.cahandlers.msicpr_ca_handler.os.path.isfile")
    @patch(
        "acme2certifier.cahandlers.msicpr_ca_handler.CAhandler._kerberos_acquire_with_kinit"
    )
    @patch(
        "acme2certifier.cahandlers.msicpr_ca_handler.CAhandler._kerberos_acquire_with_gssapi_highlevel"
    )
    @patch(
        "acme2certifier.cahandlers.msicpr_ca_handler.CAhandler._kerberos_acquire_with_gssapi_raw"
    )
    def test_083_kerberos_prepare_python_backend_success_with_raw_acquire(
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
        self.assertNotIn("KRB5CCNAME", os.environ)
        self.assertTrue(mock_raw_acquire.called)
        self.assertFalse(mock_high_acquire.called)
        self.assertFalse(mock_kinit_acquire.called)

    @patch("acme2certifier.cahandlers.msicpr_ca_handler.importlib.import_module")
    @patch("acme2certifier.cahandlers.msicpr_ca_handler.os.path.exists")
    @patch("acme2certifier.cahandlers.msicpr_ca_handler.os.path.isfile")
    @patch(
        "acme2certifier.cahandlers.msicpr_ca_handler.CAhandler._kerberos_acquire_with_kinit"
    )
    @patch(
        "acme2certifier.cahandlers.msicpr_ca_handler.CAhandler._kerberos_acquire_with_gssapi_highlevel"
    )
    @patch(
        "acme2certifier.cahandlers.msicpr_ca_handler.CAhandler._kerberos_acquire_with_gssapi_raw"
    )
    @patch("builtins.open", new_callable=mock_open)
    def test_084_kerberos_prepare_python_backend_creates_temp_ccache(
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
        "acme2certifier.cahandlers.msicpr_ca_handler.CAhandler._kerberos_acquire_with_kinit"
    )
    @patch(
        "acme2certifier.cahandlers.msicpr_ca_handler.CAhandler._kerberos_acquire_with_gssapi_highlevel"
    )
    @patch(
        "acme2certifier.cahandlers.msicpr_ca_handler.CAhandler._kerberos_acquire_with_gssapi_raw"
    )
    @patch("acme2certifier.cahandlers.msicpr_ca_handler.importlib.import_module")
    @patch("acme2certifier.cahandlers.msicpr_ca_handler.os.path.exists")
    @patch("acme2certifier.cahandlers.msicpr_ca_handler.os.path.isfile")
    def test_085_kerberos_prepare_python_backend_principal_build_failed(
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

    @patch("acme2certifier.cahandlers.msicpr_ca_handler.importlib.import_module")
    @patch("acme2certifier.cahandlers.msicpr_ca_handler.os.path.exists")
    @patch("acme2certifier.cahandlers.msicpr_ca_handler.os.path.isfile")
    def test_086_kerberos_prepare_python_backend_all_acquire_methods_failed(
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

    def test_087_kerberos_acquire_with_gssapi_raw_success(self):
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

    def test_088_kerberos_acquire_with_gssapi_raw_exception(self):
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

    def test_089_kerberos_acquire_with_gssapi_highlevel_acquire_unavailable(self):
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

    def test_090_kerberos_acquire_with_gssapi_highlevel_exception(self):
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

    @patch("acme2certifier.cahandlers.msicpr_ca_handler.subprocess.run")
    @patch("acme2certifier.cahandlers.msicpr_ca_handler.os.path.isfile")
    def test_091_kerberos_acquire_with_kinit_missing_krb5_config(
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

    @patch("acme2certifier.cahandlers.msicpr_ca_handler.subprocess.run")
    def test_092_kerberos_acquire_with_kinit_exception_with_stderr(
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

    @patch("acme2certifier.cahandlers.msicpr_ca_handler.subprocess.run")
    def test_093_kerberos_acquire_with_kinit_exception_without_stderr(
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

    @patch("acme2certifier.cahandlers.msicpr_ca_handler.subprocess.run")
    def test_094_kerberos_acquire_with_kinit_command_not_found(
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

    @patch("acme2certifier.cahandlers.msicpr_ca_handler.subprocess.run")
    def test_095_kerberos_acquire_with_kinit_timeout(
        self,
        mock_subprocess_run,
    ):
        """test kinit fallback handles subprocess timeout"""
        self.cahandler.krb5_keytab = "/tmp/svc.keytab"
        self.cahandler.krb5_principal = "svc-a2c-enroll@EXAMPLE.COM"

        mock_subprocess_run.side_effect = subprocess.TimeoutExpired(
            cmd=["kinit"], timeout=self.cahandler.KINIT_TIMEOUT_SECONDS
        )

        with self.assertLogs("test_a2c", level="INFO") as lcm:
            result = self.cahandler._kerberos_acquire_with_kinit("/tmp/krb5cc_svc")

        self.assertFalse(result)
        self.assertIn(
            f"ERROR:test_a2c:kinit timed out after {self.cahandler.KINIT_TIMEOUT_SECONDS} seconds while acquiring kerberos credentials",
            lcm.output,
        )

    def test_096_config_is_complete_kerberos_keytab_impacket_missing_cache(self):
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
            "Configuration error: kerberos keytab with krb5_auth_backend=impacket requires krb5_cache",
            error,
        )

    def test_097_config_is_complete_kerberos_user_password_fallback(self):
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

    @patch("acme2certifier.cahandlers.msicpr_ca_handler.Request")
    @patch("acme2certifier.cahandlers.msicpr_ca_handler.Target")
    @patch(
        "acme2certifier.cahandlers.msicpr_ca_handler.CAhandler._kerberos_username_from_principal"
    )
    def test_098_request_create_kerberos_keytab_mode(
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
        self.assertIsNone(target_kwargs.get("tgt"))
        _, request_kwargs = mock_request.call_args
        self.assertEqual("target_obj", request_kwargs["target"])
        self.assertTrue(request_kwargs["do_kerberos"])

    @patch("acme2certifier.cahandlers.msicpr_ca_handler.handler_config_check")
    def test_099_handler_check_kerberos_keytab_required_fields(
        self, mock_handler_check
    ):
        """test handler_check uses reduced required fields in kerberos keytab mode"""
        mock_handler_check.return_value = "ok"
        self.cahandler.use_kerberos = True
        self.cahandler.krb5_auth_backend = "python"
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

    @patch("acme2certifier.cahandlers.msicpr_ca_handler.handler_config_check")
    def test_100_handler_check_kerberos_keytab_impacket_requires_cache(
        self, mock_handler_check
    ):
        """test handler_check requires krb5_cache in kerberos keytab impacket mode"""
        mock_handler_check.return_value = "ok"
        self.cahandler.use_kerberos = True
        self.cahandler.krb5_auth_backend = "impacket"
        self.cahandler.krb5_principal = "svc-a2c-enroll@EXAMPLE.COM"
        self.cahandler.krb5_keytab = "/tmp/svc.keytab"

        result = self.cahandler.handler_check()

        self.assertEqual("ok", result)
        _, call_args = mock_handler_check.call_args
        self.assertEqual(
            ["host", "template", "ca_name", "target_domain", "krb5_cache"],
            (
                call_args["required_fields"]
                if "required_fields" in call_args
                else mock_handler_check.call_args[0][2]
            ),
        )

    @patch("acme2certifier.cahandlers.msicpr_ca_handler.load_config")
    def test_101_config_load_unknown_krb5_auth_backend_fallback(self, mock_load_cfg):
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

    @patch("acme2certifier.cahandlers.msicpr_ca_handler.fqdn_resolve")
    @patch("acme2certifier.cahandlers.msicpr_ca_handler.ip_validate")
    @patch("acme2certifier.cahandlers.msicpr_ca_handler.load_config")
    def test_102_config_load_domain_controller_fqdn_resolution(
        self,
        mock_load_cfg,
        mock_ip_validate,
        mock_fqdn_resolve,
    ):
        """test _config_parameters_load resolves domain_controller FQDN to first IP"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"domain_controller": "dc01.example.local"}
        mock_load_cfg.return_value = parser
        mock_ip_validate.return_value = (None, True)
        mock_fqdn_resolve.return_value = ("10.0.0.10", False, None)

        self.cahandler._config_load()

        self.assertEqual("10.0.0.10", self.cahandler.domain_controller)
        mock_ip_validate.assert_called_once_with(self.logger, "dc01.example.local")
        mock_fqdn_resolve.assert_called_once_with(self.logger, "dc01.example.local")

    @patch("acme2certifier.cahandlers.msicpr_ca_handler.fqdn_resolve")
    @patch("acme2certifier.cahandlers.msicpr_ca_handler.ip_validate")
    @patch("acme2certifier.cahandlers.msicpr_ca_handler.load_config")
    def test_103_config_load_domain_controller_ip_passthrough(
        self,
        mock_load_cfg,
        mock_ip_validate,
        mock_fqdn_resolve,
    ):
        """test _config_parameters_load keeps literal domain_controller IP without DNS lookup"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"domain_controller": "10.0.0.12"}
        mock_load_cfg.return_value = parser
        mock_ip_validate.return_value = ("12.0.0.10.in-addr.arpa", False)

        self.cahandler._config_load()

        self.assertEqual("10.0.0.12", self.cahandler.domain_controller)
        mock_ip_validate.assert_called_once_with(self.logger, "10.0.0.12")
        self.assertFalse(mock_fqdn_resolve.called)

    @patch("acme2certifier.cahandlers.msicpr_ca_handler.fqdn_resolve")
    @patch("acme2certifier.cahandlers.msicpr_ca_handler.ip_validate")
    @patch("acme2certifier.cahandlers.msicpr_ca_handler.load_config")
    def test_104_config_load_domain_controller_fqdn_resolution_list_first_ip(
        self,
        mock_load_cfg,
        mock_ip_validate,
        mock_fqdn_resolve,
    ):
        """test _config_parameters_load picks first IP when fqdn_resolve returns a list"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"domain_controller": "dc-list.example.local"}
        mock_load_cfg.return_value = parser
        mock_ip_validate.return_value = (None, True)
        mock_fqdn_resolve.return_value = (["10.0.0.20", "10.0.0.21"], False, None)

        self.cahandler._config_load()

        self.assertEqual("10.0.0.20", self.cahandler.domain_controller)
        mock_ip_validate.assert_called_once_with(self.logger, "dc-list.example.local")
        mock_fqdn_resolve.assert_called_once_with(
            self.logger,
            "dc-list.example.local",
        )

    @patch("acme2certifier.cahandlers.msicpr_ca_handler.fqdn_resolve")
    @patch("acme2certifier.cahandlers.msicpr_ca_handler.ip_validate")
    @patch("acme2certifier.cahandlers.msicpr_ca_handler.load_config")
    def test_105_config_load_domain_controller_fqdn_resolution_failure_warning(
        self,
        mock_load_cfg,
        mock_ip_validate,
        mock_fqdn_resolve,
    ):
        """test _config_parameters_load logs warning and keeps fqdn on failed resolution"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"domain_controller": "dc-fail.example.local"}
        mock_load_cfg.return_value = parser
        mock_ip_validate.return_value = (None, True)
        mock_fqdn_resolve.return_value = (None, True, "NXDOMAIN")

        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.cahandler._config_load()

        self.assertEqual("dc-fail.example.local", self.cahandler.domain_controller)
        mock_ip_validate.assert_called_once_with(self.logger, "dc-fail.example.local")
        mock_fqdn_resolve.assert_called_once_with(
            self.logger,
            "dc-fail.example.local",
        )
        self.assertIn(
            "WARNING:test_a2c:Failed to resolve domain controller 'dc-fail.example.local': NXDOMAIN",
            lcm.output,
        )

    @patch.dict(
        "os.environ",
        {"KRB5CCNAME": "existing_ccache", "KRB5_CONFIG": "existing_krb5_config"},
        clear=True,
    )
    @patch("acme2certifier.cahandlers.msicpr_ca_handler.os.path.isfile")
    def test_106_kerberos_runtime_environment_is_noop(self, mock_isfile):
        """kerberos runtime env context no longer mutates process env"""
        self.cahandler.krb5_cache = "/tmp/runtime_ccache"
        self.cahandler.krb5_config = "/tmp/runtime_krb5.conf"
        mock_isfile.return_value = True

        with self.cahandler._kerberos_runtime_environment():
            self.assertEqual("existing_ccache", os.environ.get("KRB5CCNAME"))
            self.assertEqual("existing_krb5_config", os.environ.get("KRB5_CONFIG"))

        self.assertEqual("existing_ccache", os.environ.get("KRB5CCNAME"))
        self.assertEqual("existing_krb5_config", os.environ.get("KRB5_CONFIG"))

    @patch("acme2certifier.cahandlers.msicpr_ca_handler.os.unlink")
    def test_107_kerberos_cleanup_temporary_ccache(self, mock_unlink):
        """test temporary ccache cleanup removes file and resets handler state"""
        self.cahandler.krb5_cache = "/tmp/runtime_ccache"
        self.cahandler._krb5_cache_is_temporary = True

        self.cahandler._kerberos_cleanup_temporary_ccache()

        mock_unlink.assert_called_once_with("/tmp/runtime_ccache")
        self.assertFalse(self.cahandler._krb5_cache_is_temporary)
        self.assertIsNone(self.cahandler.krb5_cache)

    @patch("acme2certifier.cahandlers.msicpr_ca_handler.CAhandler.request_create")
    @patch("acme2certifier.cahandlers.msicpr_ca_handler.convert_string_to_byte")
    @patch("acme2certifier.cahandlers.msicpr_ca_handler.CAhandler._file_load")
    @patch("acme2certifier.cahandlers.msicpr_ca_handler.build_pem_file")
    def test_108_enroll_pending_disposition(
        self,
        _mock_pem,
        mock_file,
        mock_s2b,
        mock_rcr,
    ):
        """test enrollment returns explicit error for pending disposition"""
        self.cahandler.host = "host"
        self.cahandler.user = "user"
        self.cahandler.password = "password"
        self.cahandler.template = "template"

        mock_request = Mock()
        mock_request.get_cert.return_value = {
            "request_id": 55,
            "disposition": 5,
            "disposition_message": "pending",
            "certificate": None,
        }
        mock_rcr.return_value = mock_request
        mock_file.return_value = "file_load"
        mock_s2b.return_value = "s2b"

        self.assertEqual(
            ("Certificate request is pending approval.", None, None, "55"),
            self.cahandler.enroll("csr"),
        )

    @patch("acme2certifier.cahandlers.msicpr_ca_handler.CAhandler.request_create")
    @patch("acme2certifier.cahandlers.msicpr_ca_handler.convert_string_to_byte")
    @patch("acme2certifier.cahandlers.msicpr_ca_handler.CAhandler._file_load")
    @patch("acme2certifier.cahandlers.msicpr_ca_handler.build_pem_file")
    def test_109_enroll_nonissued_disposition(
        self,
        _mock_pem,
        mock_file,
        mock_s2b,
        mock_rcr,
    ):
        """test enrollment returns generic error for non-issued non-pending disposition"""
        self.cahandler.host = "host"
        self.cahandler.user = "user"
        self.cahandler.password = "password"
        self.cahandler.template = "template"

        mock_request = Mock()
        mock_request.get_cert.return_value = {
            "request_id": 99,
            "disposition": 2,
            "disposition_message": "access denied",
            "certificate": None,
        }
        mock_rcr.return_value = mock_request
        mock_file.return_value = "file_load"
        mock_s2b.return_value = "s2b"

        self.assertEqual(
            ("Could not get certificate from CA server", None, None, None),
            self.cahandler.enroll("csr"),
        )

    @patch.dict("os.environ", {}, clear=True)
    @patch("acme2certifier.cahandlers.msicpr_ca_handler.os.path.isfile")
    def test_110_kerberos_runtime_environment_leaves_env_unset(self, mock_isfile):
        """runtime env no-op does not introduce KRB5* vars"""
        self.cahandler.krb5_cache = "/tmp/runtime_ccache"
        self.cahandler.krb5_config = "/tmp/runtime_krb5.conf"
        mock_isfile.return_value = True

        with self.cahandler._kerberos_runtime_environment():
            self.assertNotIn("KRB5CCNAME", os.environ)
            self.assertNotIn("KRB5_CONFIG", os.environ)

        self.assertNotIn("KRB5CCNAME", os.environ)
        self.assertNotIn("KRB5_CONFIG", os.environ)

    def test_111_kerberos_cleanup_temporary_ccache_noop(self):
        """cleanup returns early when ccache is not temporary"""
        self.cahandler.krb5_cache = "/tmp/runtime_ccache"
        self.cahandler._krb5_cache_is_temporary = False
        self.cahandler._kerberos_cleanup_temporary_ccache()
        self.assertEqual("/tmp/runtime_ccache", self.cahandler.krb5_cache)

    @patch(
        "acme2certifier.cahandlers.msicpr_ca_handler.os.unlink",
        side_effect=FileNotFoundError(),
    )
    def test_112_kerberos_cleanup_temporary_ccache_missing(self, mock_unlink):
        """cleanup handles already-removed temporary ccache"""
        self.cahandler.krb5_cache = "/tmp/runtime_ccache"
        self.cahandler._krb5_cache_is_temporary = True
        self.cahandler._kerberos_cleanup_temporary_ccache()
        mock_unlink.assert_called_once_with("/tmp/runtime_ccache")
        self.assertFalse(self.cahandler._krb5_cache_is_temporary)
        self.assertIsNone(self.cahandler.krb5_cache)

    @patch(
        "acme2certifier.cahandlers.msicpr_ca_handler.os.unlink",
        side_effect=PermissionError("denied"),
    )
    def test_113_kerberos_cleanup_temporary_ccache_error(self, mock_unlink):
        """cleanup logs warning when unlink fails"""
        self.cahandler.krb5_cache = "/tmp/runtime_ccache"
        self.cahandler._krb5_cache_is_temporary = True
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.cahandler._kerberos_cleanup_temporary_ccache()
        mock_unlink.assert_called_once_with("/tmp/runtime_ccache")
        self.assertIn(
            "WARNING:test_a2c:Failed to remove temporary kerberos ccache file '/tmp/runtime_ccache': denied",
            lcm.output,
        )
        self.assertFalse(self.cahandler._krb5_cache_is_temporary)
        self.assertIsNone(self.cahandler.krb5_cache)

    @patch("acme2certifier.cahandlers.msicpr_ca_handler.CAhandler.request_create")
    @patch("acme2certifier.cahandlers.msicpr_ca_handler.convert_string_to_byte")
    def test_114_certificate_request_send(self, mock_s2b, mock_rcr):
        """_certificate_request_send submits CSR without process env mutation"""
        mock_request = Mock()
        mock_request.get_cert.return_value = {"disposition": 3}
        mock_rcr.return_value = mock_request
        mock_s2b.return_value = b"csr"
        self.assertEqual(
            {"disposition": 3},
            self.cahandler._certificate_request_send("csr"),
        )
        mock_request.get_cert.assert_called_once_with(b"csr")
        mock_request.close.assert_called_once_with()

    @patch("acme2certifier.cahandlers.msicpr_ca_handler.CAhandler.request_create")
    @patch("acme2certifier.cahandlers.msicpr_ca_handler.convert_string_to_byte")
    def test_115_certificate_request_send_closes_on_error(self, mock_s2b, mock_rcr):
        """_certificate_request_send closes DCE even when get_cert raises"""
        mock_request = Mock()
        mock_request.get_cert.side_effect = ConnectionError(
            "DCE/RPC connection to CA server is not available"
        )
        mock_rcr.return_value = mock_request
        mock_s2b.return_value = b"csr"
        with self.assertRaises(ConnectionError):
            self.cahandler._certificate_request_send("csr")
        mock_request.close.assert_called_once_with()

    def test_116_certificate_response_process_issued_without_bytes(self):
        """issued disposition without certificate bytes returns fetch error"""
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            error, cert_raw, poll_identifier, ca_chain = (
                self.cahandler._certificate_response_process(
                    {
                        "request_id": 7,
                        "disposition": 3,
                        "disposition_message": "issued",
                        "certificate": None,
                    }
                )
            )
        self.assertEqual("Could not get certificate from CA server", error)
        self.assertIsNone(cert_raw)
        self.assertIsNone(poll_identifier)
        self.assertIsNone(ca_chain)
        self.assertIn(
            "ERROR:test_a2c:Enrollment response has issued disposition but no certificate bytes. request_id=7",
            lcm.output,
        )

    def test_117_certificate_response_process_pending_returns_poll_identifier(self):
        """pending disposition returns CA request_id as poll identifier"""
        with self.assertLogs("test_a2c", level="INFO"):
            error, cert_raw, poll_identifier, ca_chain = (
                self.cahandler._certificate_response_process(
                    {
                        "request_id": 55,
                        "disposition": 5,
                        "disposition_message": "pending",
                        "certificate": None,
                    }
                )
            )
        self.assertEqual("Certificate request is pending approval.", error)
        self.assertIsNone(cert_raw)
        self.assertEqual("55", poll_identifier)
        self.assertIsNone(ca_chain)

    @patch(
        "acme2certifier.cahandlers.msicpr_ca_handler.CAhandler._kerberos_cleanup_temporary_ccache"
    )
    @patch(
        "acme2certifier.cahandlers.msicpr_ca_handler.CAhandler._kerberos_tgt_from_ccache",
        return_value=("fake-tgt", None),
    )
    @patch(
        "acme2certifier.cahandlers.msicpr_ca_handler.CAhandler._kerberos_prepare_python_backend"
    )
    @patch(
        "acme2certifier.cahandlers.msicpr_ca_handler.CAhandler._kerberos_keytab_is_configured"
    )
    @patch(
        "acme2certifier.cahandlers.msicpr_ca_handler.CAhandler._certificate_request_send"
    )
    @patch("acme2certifier.cahandlers.msicpr_ca_handler.convert_byte_to_string")
    @patch("acme2certifier.cahandlers.msicpr_ca_handler.CAhandler._file_load")
    @patch("acme2certifier.cahandlers.msicpr_ca_handler.build_pem_file")
    def test_118_enroll_cleans_temporary_ccache_on_kerberos_scope(
        self,
        mock_pem,
        mock_file,
        mock_b2s,
        mock_send,
        mock_keytab,
        mock_prepare,
        mock_tgt,
        mock_cleanup,
    ):
        """enroll cleans temporary ccache when python kerberos scope is active"""
        self.cahandler.host = "host"
        self.cahandler.user = "user"
        self.cahandler.password = "password"
        self.cahandler.template = "template"
        self.cahandler.use_kerberos = True
        self.cahandler.krb5_auth_backend = "python"
        self.cahandler.ca_bundle = "ca_bundle"
        mock_keytab.return_value = True
        mock_prepare.return_value = None
        mock_pem.return_value = "csr_pem"
        mock_file.return_value = "ca_pem"
        mock_b2s.return_value = (
            "-----BEGIN CERTIFICATE-----\ncert\n-----END CERTIFICATE-----\n"
        )
        mock_send.return_value = {
            "request_id": 1,
            "disposition": 3,
            "disposition_message": "issued",
            "certificate": b"cert",
        }
        error, cert_bundle, cert_raw, poll_id = self.cahandler.enroll("csr")
        self.assertIsNone(error)
        self.assertTrue(mock_tgt.called)
        self.assertTrue(mock_cleanup.called)
        self.assertEqual(
            "-----BEGIN CERTIFICATE-----\ncert\n-----END CERTIFICATE-----\nca_pem",
            cert_bundle,
        )
        self.assertEqual("cert", cert_raw)
        self.assertIsNone(poll_id)

    @patch("acme2certifier.cahandlers.msicpr_ca_handler.load_config")
    def test_119_templates_config_load(self, mock_load_cfg):
        """allowed_templates loads from JSON list"""
        import configparser

        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"allowed_templates": '["WebServer", "User"]'}
        mock_load_cfg.return_value = parser
        self.cahandler._config_load()
        self.assertEqual(["WebServer", "User"], self.cahandler.allowed_templates)

    def test_120_templates_check_reject(self):
        """non-empty allowlist rejects unknown template"""
        self.cahandler.template = "Other"
        self.cahandler.allowed_templates = ["WebServer"]
        self.assertEqual(
            "Template 'Other' is not allowed",
            self.cahandler._allowed_templates_check(),
        )

    @patch(
        "acme2certifier.cahandlers.msicpr_ca_handler.eab_profile_header_info_check",
        return_value=None,
    )
    @patch(
        "acme2certifier.cahandlers.msicpr_ca_handler.CAhandler._config_is_complete",
        return_value=(True, None),
    )
    def test_121_rejects_disallowed_template(self, _mock_complete, _mock_eab):
        """enroll rejects template not in allowed_templates"""
        self.cahandler.host = "host"
        self.cahandler.user = "user"
        self.cahandler.password = "password"
        self.cahandler.template = "BadTemplate"
        self.cahandler.allowed_templates = ["WebServer"]
        error, cert_bundle, cert_raw, poll_id = self.cahandler.enroll("csr")
        self.assertEqual("Template 'BadTemplate' is not allowed", error)
        self.assertIsNone(cert_bundle)
        self.assertIsNone(cert_raw)
        self.assertIsNone(poll_id)

    @patch("acme2certifier.cahandlers.msicpr_ca_handler.CAhandler.request_create")
    @patch("acme2certifier.cahandlers.msicpr_ca_handler.convert_string_to_byte")
    @patch("acme2certifier.cahandlers.msicpr_ca_handler.CAhandler._file_load")
    @patch("acme2certifier.cahandlers.msicpr_ca_handler.build_pem_file")
    def test_122_prefers_rpc_certificate_chain(
        self, mock_pem, mock_file, mock_s2b, mock_rcr
    ):
        """enrollment prefers CMS chain from response over local ca_bundle"""
        self.cahandler.host = "host"
        self.cahandler.user = "user"
        self.cahandler.password = "password"
        self.cahandler.template = "template"
        self.cahandler.ca_bundle = "ca_bundle"
        mock_request = Mock()
        mock_request.get_cert.return_value = {
            "request_id": 1,
            "disposition": 3,
            "disposition_message": None,
            "certificate": (
                b"-----BEGIN CERTIFICATE-----\nleaf\n-----END CERTIFICATE-----\n"
            ),
            "certificate_chain": (
                b"-----BEGIN CERTIFICATE-----\nca\n-----END CERTIFICATE-----\n"
            ),
        }
        mock_rcr.return_value = mock_request
        mock_file.return_value = "file_load"
        mock_s2b.return_value = b"csr"
        mock_pem.return_value = "csr"

        error, cert_bundle, cert_raw, poll_id = self.cahandler.enroll("csr")
        self.assertIsNone(error)
        self.assertEqual(
            "-----BEGIN CERTIFICATE-----\nleaf\n-----END CERTIFICATE-----\n"
            "-----BEGIN CERTIFICATE-----\nca\n-----END CERTIFICATE-----\n",
            cert_bundle,
        )
        self.assertEqual("leaf", cert_raw)
        self.assertIsNone(poll_id)
        self.assertFalse(mock_file.called)

    @patch("acme2certifier.cahandlers.msicpr_ca_handler.load_config")
    def test_123_config_allowed_templates_non_list_json(self, mock_load_cfg):
        """JSON object for allowed_templates is treated as empty allowlist"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"allowed_templates": '{"WebServer": true}'}
        mock_load_cfg.return_value = parser
        with self.assertLogs("test_a2c", level="WARNING") as lcm:
            self.cahandler._config_load()
        self.assertEqual([], self.cahandler.allowed_templates)
        self.assertTrue(
            any("Failed to parse allowed_templates" in msg for msg in lcm.output)
        )

    @patch("acme2certifier.cahandlers.msicpr_ca_handler.load_config")
    def test_124_config_allowed_templates_empty_list_warns(self, mock_load_cfg):
        """empty JSON list for allowed_templates logs empty-allowlist warning"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"allowed_templates": "[]"}
        mock_load_cfg.return_value = parser
        with self.assertLogs("test_a2c", level="WARNING") as lcm:
            self.cahandler._config_load()
        self.assertEqual([], self.cahandler.allowed_templates)
        self.assertTrue(any("allowed_templates is empty" in msg for msg in lcm.output))

    def test_125_allowed_templates_check_allow(self):
        """non-empty allowlist accepts listed template"""
        self.cahandler.template = "WebServer"
        self.cahandler.allowed_templates = ["WebServer"]
        self.assertIsNone(self.cahandler._allowed_templates_check())

    def test_126_kerberos_ccache_path_normalizes_file_prefix(self):
        """_kerberos_ccache_path strips FILE: prefix and handles empty values"""
        self.assertEqual(
            "/tmp/cc",
            self.cahandler._kerberos_ccache_path("FILE:/tmp/cc"),
        )
        self.assertEqual("/tmp/cc", self.cahandler._kerberos_ccache_path("/tmp/cc"))
        self.assertIsNone(self.cahandler._kerberos_ccache_path(None))
        self.assertIsNone(self.cahandler._kerberos_ccache_path(""))

    def test_127_kerberos_tgt_from_ccache_noop_without_python_keytab(self):
        """_kerberos_tgt_from_ccache is a no-op outside python keytab mode"""
        self.cahandler.use_kerberos = False
        self.assertEqual((None, None), self.cahandler._kerberos_tgt_from_ccache())

    def test_128_kerberos_tgt_from_ccache_missing_ccache(self):
        """missing ccache path returns an explicit error"""
        self.cahandler.use_kerberos = True
        self.cahandler.krb5_auth_backend = "python"
        self.cahandler.krb5_principal = "svc@EXAMPLE.COM"
        self.cahandler.krb5_keytab = "/tmp/svc.keytab"
        self.cahandler.krb5_cache = None
        creds, error = self.cahandler._kerberos_tgt_from_ccache()
        self.assertIsNone(creds)
        self.assertIn("Kerberos ccache is not available", error)

    def test_129_kerberos_tgt_from_ccache_import_error(self):
        """impacket CCache import failure is reported"""
        self.cahandler.use_kerberos = True
        self.cahandler.krb5_auth_backend = "python"
        self.cahandler.krb5_principal = "svc@EXAMPLE.COM"
        self.cahandler.krb5_keytab = "/tmp/svc.keytab"
        self.cahandler.krb5_cache = "/tmp/cc"
        with patch.dict(
            "sys.modules",
            {
                "impacket": None,
                "impacket.krb5": None,
                "impacket.krb5.ccache": None,
            },
        ):
            with self.assertLogs("test_a2c", level="ERROR") as lcm:
                creds, error = self.cahandler._kerberos_tgt_from_ccache()
        self.assertIsNone(creds)
        self.assertIn("impacket is required", error)
        self.assertTrue(
            any("Failed to import impacket CCache" in msg for msg in lcm.output)
        )

    def test_130_kerberos_tgt_from_ccache_load_none(self):
        """CCache.loadFile returning None is reported"""
        self.cahandler.use_kerberos = True
        self.cahandler.krb5_auth_backend = "python"
        self.cahandler.krb5_principal = "svc@EXAMPLE.COM"
        self.cahandler.krb5_keytab = "/tmp/svc.keytab"
        self.cahandler.krb5_cache = "/tmp/cc"
        mock_ccache_mod = MagicMock()
        mock_ccache_mod.CCache.loadFile.return_value = None
        with patch.dict(
            "sys.modules",
            {
                "impacket": MagicMock(),
                "impacket.krb5": MagicMock(),
                "impacket.krb5.ccache": mock_ccache_mod,
            },
        ):
            creds, error = self.cahandler._kerberos_tgt_from_ccache()
        self.assertIsNone(creds)
        self.assertIn("Failed to load Kerberos ccache file", error)

    def test_131_kerberos_tgt_from_ccache_missing_tgt(self):
        """missing TGT credential in ccache is reported"""
        self.cahandler.use_kerberos = True
        self.cahandler.krb5_auth_backend = "python"
        self.cahandler.krb5_principal = "svc@EXAMPLE.COM"
        self.cahandler.krb5_keytab = "/tmp/svc.keytab"
        self.cahandler.krb5_cache = "/tmp/cc"
        mock_ccache = MagicMock()
        mock_ccache.principal.realm = {"data": b"EXAMPLE.COM"}
        mock_ccache.getCredential.return_value = None
        mock_ccache_mod = MagicMock()
        mock_ccache_mod.CCache.loadFile.return_value = mock_ccache
        with patch.dict(
            "sys.modules",
            {
                "impacket": MagicMock(),
                "impacket.krb5": MagicMock(),
                "impacket.krb5.ccache": mock_ccache_mod,
            },
        ):
            creds, error = self.cahandler._kerberos_tgt_from_ccache()
        self.assertIsNone(creds)
        self.assertIn("No TGT found in Kerberos ccache", error)

    def test_132_kerberos_tgt_from_ccache_success(self):
        """successful TGT extraction from ccache"""
        self.cahandler.use_kerberos = True
        self.cahandler.krb5_auth_backend = "python"
        self.cahandler.krb5_principal = "svc@EXAMPLE.COM"
        self.cahandler.krb5_keytab = "/tmp/svc.keytab"
        self.cahandler.krb5_cache = "FILE:/tmp/cc"
        mock_creds = MagicMock()
        mock_creds.toTGT.return_value = "fake-tgt"
        mock_ccache = MagicMock()
        mock_ccache.principal.realm = {"data": b"EXAMPLE.COM"}
        mock_ccache.getCredential.return_value = mock_creds
        mock_ccache_mod = MagicMock()
        mock_ccache_mod.CCache.loadFile.return_value = mock_ccache
        with patch.dict(
            "sys.modules",
            {
                "impacket": MagicMock(),
                "impacket.krb5": MagicMock(),
                "impacket.krb5.ccache": mock_ccache_mod,
            },
        ):
            tgt, error = self.cahandler._kerberos_tgt_from_ccache()
        self.assertEqual("fake-tgt", tgt)
        self.assertIsNone(error)
        mock_ccache_mod.CCache.loadFile.assert_called_once_with("/tmp/cc")

    def test_133_kerberos_tgt_from_ccache_extract_error(self):
        """unexpected extraction failures are reported"""
        self.cahandler.use_kerberos = True
        self.cahandler.krb5_auth_backend = "python"
        self.cahandler.krb5_principal = "svc@EXAMPLE.COM"
        self.cahandler.krb5_keytab = "/tmp/svc.keytab"
        self.cahandler.krb5_cache = "/tmp/cc"
        mock_ccache_mod = MagicMock()
        mock_ccache_mod.CCache.loadFile.side_effect = RuntimeError("corrupt")
        with patch.dict(
            "sys.modules",
            {
                "impacket": MagicMock(),
                "impacket.krb5": MagicMock(),
                "impacket.krb5.ccache": mock_ccache_mod,
            },
        ):
            with self.assertLogs("test_a2c", level="ERROR") as lcm:
                creds, error = self.cahandler._kerberos_tgt_from_ccache()
        self.assertIsNone(creds)
        self.assertIn("Failed to extract Kerberos TGT from ccache", error)
        self.assertTrue(
            any("Failed to extract TGT from ccache" in msg for msg in lcm.output)
        )

    @patch(
        "acme2certifier.cahandlers.msicpr_ca_handler.CAhandler._kerberos_cleanup_temporary_ccache"
    )
    @patch(
        "acme2certifier.cahandlers.msicpr_ca_handler.CAhandler._kerberos_tgt_from_ccache",
        return_value=(None, "tgt load failed"),
    )
    @patch(
        "acme2certifier.cahandlers.msicpr_ca_handler.CAhandler._kerberos_prepare_python_backend",
        return_value=None,
    )
    @patch(
        "acme2certifier.cahandlers.msicpr_ca_handler.CAhandler._kerberos_keytab_is_configured",
        return_value=True,
    )
    def test_134_enroll_returns_tgt_error(
        self, _mock_keytab, _mock_prepare, mock_tgt, mock_cleanup
    ):
        """enroll aborts when TGT cannot be loaded from ccache"""
        self.cahandler.host = "host"
        self.cahandler.user = "user"
        self.cahandler.password = "password"
        self.cahandler.template = "template"
        self.cahandler.use_kerberos = True
        self.cahandler.krb5_auth_backend = "python"
        with self.assertLogs("test_a2c", level="ERROR") as lcm:
            error, cert_bundle, cert_raw, poll_id = self.cahandler.enroll("csr")
        self.assertEqual("tgt load failed", error)
        self.assertIsNone(cert_bundle)
        self.assertIsNone(cert_raw)
        self.assertIsNone(poll_id)
        self.assertTrue(mock_tgt.called)
        self.assertTrue(mock_cleanup.called)
        self.assertTrue(any("Kerberos TGT load failed" in msg for msg in lcm.output))

    @patch("acme2certifier.cahandlers.msicpr_ca_handler.load_config")
    def test_135_config_load_prefers_order_allowed_header_values(self, mock_load_cfg):
        """Order.allowed_header_values takes precedence over CAhandler.allowed_templates"""
        parser = configparser.ConfigParser()
        parser["Order"] = {"allowed_header_values": '["FromOrder", "AlsoOrder"]'}
        parser["CAhandler"] = {"allowed_templates": '["FromCA"]'}
        mock_load_cfg.return_value = parser
        self.cahandler._config_load()
        self.assertEqual(["FromOrder", "AlsoOrder"], self.cahandler.allowed_templates)

    @patch("acme2certifier.cahandlers.msicpr_ca_handler.load_config")
    def test_136_config_load_allowed_templates_deprecation_warning(self, mock_load_cfg):
        """reading CAhandler allowed_templates logs migration warning"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"allowed_templates": '["WebServer"]'}
        mock_load_cfg.return_value = parser
        with self.assertLogs("test_a2c", level="WARNING") as lcm:
            self.cahandler._config_load()
        self.assertEqual(["WebServer"], self.cahandler.allowed_templates)
        self.assertTrue(
            any(
                "allowed_templates is deprecated for header allowlisting" in msg
                for msg in lcm.output
            )
        )


if __name__ == "__main__":

    unittest.main()
