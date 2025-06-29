#!/usr/bin/python
# -*- coding: utf-8 -*-
"""unittests for openssl_ca_handler"""
# pylint: disable=C0415, R0904, W0212
import sys
import os
import unittest
from unittest.mock import patch, Mock
import requests
import base64
import configparser

sys.path.insert(0, ".")
sys.path.insert(1, "..")


class FakeDBStore(object):
    """face DBStore class needed for mocking"""

    # pylint: disable=W0107, R0903
    def mount():
        return True

    pass


class TestACMEHandler(unittest.TestCase):
    """test class for cgi_handler"""

    def setUp(self):
        """setup unittest"""
        import logging
        from examples.ca_handler.est_ca_handler import CAhandler

        logging.basicConfig(level=logging.CRITICAL)
        self.logger = logging.getLogger("test_a2c")
        self.cahandler = CAhandler(False, self.logger)
        self.dir_path = os.path.dirname(os.path.realpath(__file__))

    def test_001_default(self):
        """default test which always passes"""
        self.assertEqual("foo", "foo")

    @patch("examples.ca_handler.est_ca_handler.CAhandler._config_proxy_load")
    @patch("examples.ca_handler.est_ca_handler.CAhandler._config_parameters_load")
    @patch("examples.ca_handler.est_ca_handler.CAhandler._config_password_load")
    @patch("examples.ca_handler.est_ca_handler.CAhandler._config_userauth_load")
    @patch("examples.ca_handler.est_ca_handler.CAhandler._config_clientauth_load")
    @patch("examples.ca_handler.est_ca_handler.CAhandler._config_host_load")
    @patch("examples.ca_handler.est_ca_handler.load_config")
    def test_002_config_load(
        self,
        mock_load_cfg,
        mock_host,
        mock_cla,
        mock_usa,
        mock_pass,
        mock_para,
        mock_proxy,
    ):
        """test _config_load - est host configured"""
        parser = configparser.ConfigParser()
        # parser['CAhandler'] = {'api_host': 'api_host', 'foo': 'bar'}
        mock_load_cfg.return_value = parser
        self.cahandler._config_load()
        self.assertTrue(mock_load_cfg.called)
        self.assertFalse(mock_host.called)
        self.assertFalse(mock_cla.called)
        self.assertFalse(mock_usa.called)
        self.assertFalse(mock_pass.called)
        self.assertFalse(mock_para.called)
        self.assertTrue(mock_proxy.called)

    @patch("examples.ca_handler.est_ca_handler.CAhandler._config_proxy_load")
    @patch("examples.ca_handler.est_ca_handler.CAhandler._config_parameters_load")
    @patch("examples.ca_handler.est_ca_handler.CAhandler._config_password_load")
    @patch("examples.ca_handler.est_ca_handler.CAhandler._config_userauth_load")
    @patch("examples.ca_handler.est_ca_handler.CAhandler._config_clientauth_load")
    @patch("examples.ca_handler.est_ca_handler.CAhandler._config_host_load")
    @patch("examples.ca_handler.est_ca_handler.load_config")
    def test_003_config_load(
        self,
        mock_load_cfg,
        mock_host,
        mock_cla,
        mock_usa,
        mock_pass,
        mock_para,
        mock_proxy,
    ):
        """test _config_load - est host configured"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"est_host": "foo_host"}
        mock_load_cfg.return_value = parser
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.cahandler._config_load()
        self.assertIn(
            "ERROR:test_a2c:Configuration incomplete: either user or client authentication must be configured.",
            lcm.output,
        )
        self.assertTrue(mock_load_cfg.called)
        self.assertTrue(mock_host.called)
        self.assertTrue(mock_cla.called)
        self.assertTrue(mock_usa.called)
        self.assertTrue(mock_pass.called)
        self.assertTrue(mock_para.called)
        self.assertTrue(mock_proxy.called)

    @patch("examples.ca_handler.est_ca_handler.CAhandler._config_proxy_load")
    @patch("examples.ca_handler.est_ca_handler.CAhandler._config_parameters_load")
    @patch("examples.ca_handler.est_ca_handler.CAhandler._config_password_load")
    @patch("examples.ca_handler.est_ca_handler.CAhandler._config_userauth_load")
    @patch("examples.ca_handler.est_ca_handler.CAhandler._config_clientauth_load")
    @patch("examples.ca_handler.est_ca_handler.CAhandler._config_host_load")
    @patch("examples.ca_handler.est_ca_handler.load_config")
    def test_004_config_load(
        self,
        mock_load_cfg,
        mock_host,
        mock_cla,
        mock_usa,
        mock_pass,
        mock_para,
        mock_proxy,
    ):
        """test _config_load - est host configured"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"est_host": "foo_host"}
        mock_load_cfg.return_value = parser
        self.cahandler.est_client_cert = "est_client_cert"
        self.cahandler.est_user = "est_user"
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.cahandler._config_load()
        self.assertIn(
            "ERROR:test_a2c:Configuration error: user and client authentication cannot be configured together.",
            lcm.output,
        )
        self.assertTrue(mock_load_cfg.called)
        self.assertTrue(mock_host.called)
        self.assertTrue(mock_cla.called)
        self.assertTrue(mock_usa.called)
        self.assertTrue(mock_pass.called)
        self.assertTrue(mock_para.called)
        self.assertTrue(mock_proxy.called)

    def test_005_config_host_load(self):
        """test _config_load - est host configured"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"est_host": "foo_host"}
        self.cahandler._config_host_load(parser)
        self.assertEqual("foo_host/.well-known/est", self.cahandler.est_host)
        self.assertEqual(20, self.cahandler.request_timeout)

    @patch.dict("os.environ", {"est_host_var": "foo_host"})
    def test_006_config_host_load(self):
        """test _config_load - est host configured via environment variable"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"est_host_variable": "est_host_var"}
        self.cahandler._config_host_load(parser)
        self.assertEqual("foo_host/.well-known/est", self.cahandler.est_host)
        self.assertEqual(20, self.cahandler.request_timeout)

    @patch.dict("os.environ", {"est_host_var": "foo_host"})
    def test_007_config_host_load(self):
        """test _config_load - est host configured  via not existing environment variable"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"est_host_variable": "does_not_exist"}
        self.cahandler._config_host_load(parser)
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.cahandler._config_host_load(parser)
        self.assertFalse(self.cahandler.est_host)
        self.assertIn(
            "ERROR:test_a2c:Could not load est_host_variable:'does_not_exist'",
            lcm.output,
        )
        self.assertEqual(20, self.cahandler.request_timeout)

    @patch.dict("os.environ", {"est_host_var": "foo_host"})
    def test_008_config_host_load(self):
        """test _config_load - est host configured as variable and in cfg"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {
            "est_host_variable": "est_host_var",
            "est_host": "foo_host_loc",
        }
        self.cahandler._config_host_load(parser)
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.cahandler._config_host_load(parser)
        self.assertEqual("foo_host_loc/.well-known/est", self.cahandler.est_host)
        self.assertIn("INFO:test_a2c:Overwrite est_host", lcm.output)
        self.assertEqual(20, self.cahandler.request_timeout)

    def test_009_config_host_load(self):
        """test _config_load - no est host configured"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"foo": "bar"}
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.cahandler._config_host_load(parser)
        self.assertIn(
            'ERROR:test_a2c:Missing "est_host" parameter',
            lcm.output,
        )
        self.assertEqual(20, self.cahandler.request_timeout)

    @patch("examples.ca_handler.est_ca_handler.load_config")
    def test_010_config_host_load(self, mock_cfg):
        """test _config_load - client auth configured but no ca_bundle"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {
            "est_host": "foo_host",
            "est_client_key": "est_client_key",
            "est_client_cert": "est_client_cert",
            "ca_bundle": False,
        }
        mock_cfg.return_value = parser
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.cahandler._config_load()
        self.assertIn(
            "ERROR:test_a2c:Configuration error: client authentication requires a ca_bundle.",
            lcm.output,
        )
        self.assertEqual("foo_host/.well-known/est", self.cahandler.est_host)
        self.assertEqual(20, self.cahandler.request_timeout)
        self.assertTrue(self.cahandler.est_client_cert)
        self.assertFalse(self.cahandler.ca_bundle)

    def test_011_config_clientauth_load(self):
        """test _config_load - client certificate configured but no key"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"est_host": "foo", "est_client_cert": "est_client_cert"}
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.cahandler._config_clientauth_load(parser)
        self.assertFalse(self.cahandler.est_client_cert)
        self.assertIn(
            'ERROR:test_a2c:Clientauth configuration incomplete: either "est_client_key or "cert_passphrase" parameter is missing in config file',
            lcm.output,
        )
        self.assertEqual(20, self.cahandler.request_timeout)
        self.assertFalse(self.cahandler.est_client_cert)

    def test_012_config_clientauth_load(self):
        """test _config_load - client certificate configured but no key"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {
            "est_client_key": "est_client_key",
            "est_client_cert": "est_client_cert",
        }
        self.cahandler.session = Mock()
        self.cahandler._config_clientauth_load(parser)
        self.assertTrue(self.cahandler.est_client_cert)
        self.assertEqual(20, self.cahandler.request_timeout)
        self.assertEqual(
            ("est_client_cert", "est_client_key"), self.cahandler.session.cert
        )

    @patch("examples.ca_handler.est_ca_handler.CAhandler._cert_passphrase_load")
    @patch("examples.ca_handler.est_ca_handler.Pkcs12Adapter")
    def test_013_config_clientauth_load(self, mock_pkcs12, mock_load):
        """test _config_load - client certificate configured but no key"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {
            "cert_passphrase": "cert_passphrase",
            "est_client_cert": "est_client_cert",
        }
        self.cahandler.session = Mock()
        self.cahandler._config_clientauth_load(parser)
        self.assertTrue(self.cahandler.est_client_cert)
        self.assertTrue(mock_pkcs12.called)
        self.assertTrue(mock_load.called)

    def test_014_cert_passphrase_load(self):
        """_cert_passphrase_load()"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"cert_passphrase": "cert_passphrase"}
        self.cahandler._cert_passphrase_load(parser)
        self.assertEqual("cert_passphrase", self.cahandler.cert_passphrase)

    @patch.dict("os.environ", {"cert_passphrase_variable": "cert_passphrase_variable"})
    def test_015_cert_passphrase_load(self):
        """_cert_passphrase_load()"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"cert_passphrase_variable": "cert_passphrase_variable"}
        self.cahandler._cert_passphrase_load(parser)
        self.assertEqual("cert_passphrase_variable", self.cahandler.cert_passphrase)

    @patch.dict("os.environ", {"cert_passphrase_variable": "cert_passphrase_variable"})
    def test_016_cert_passphrase_load(self):
        """_cert_passphrase_load()"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {
            "cert_passphrase_variable": "cert_passphrase_variable",
            "cert_passphrase": "cert_passphrase",
        }
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.cahandler._cert_passphrase_load(parser)
        self.assertIn(
            "INFO:test_a2c:Overwrite cert_passphrase",
            lcm.output,
        )
        self.assertEqual("cert_passphrase", self.cahandler.cert_passphrase)

    @patch.dict("os.environ", {"foo": "bar"})
    def test_017_cert_passphrase_load(self):
        """_cert_passphrase_load()"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"cert_passphrase_variable": "cert_passphrase_variable"}
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.cahandler._cert_passphrase_load(parser)
        self.assertIn(
            "ERROR:test_a2c:Could not load cert_passphrase_variable:'cert_passphrase_variable'",
            lcm.output,
        )
        self.assertFalse(self.cahandler.cert_passphrase)

    def test_018_config_userauth_load(self):
        """test _config_userauth_load()"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"est_user": "est_user"}
        self.cahandler._config_userauth_load(parser)
        self.assertEqual("est_user", self.cahandler.est_user)

    @patch.dict("os.environ", {"est_user_var": "estuser"})
    def test_019_config_userauth_load(self):
        """test _config_userauth_load()"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"est_user_variable": "est_user_var"}
        self.cahandler._config_userauth_load(parser)
        self.assertEqual("estuser", self.cahandler.est_user)

    @patch.dict("os.environ", {"foo": "foo"})
    def test_020_config_userauth_load(self):
        """test _config_userauth_load()"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"est_user_variable": "est_user_var"}
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.cahandler._config_userauth_load(parser)
        self.assertIn(
            "ERROR:test_a2c:Could not load est_user_variable:'est_user_var'",
            lcm.output,
        )
        self.assertFalse(self.cahandler.est_user)

    @patch.dict("os.environ", {"est_user_var": "est_user_var"})
    def test_021_config_userauth_load(self):
        """test _config_userauth_load()"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {
            "est_user_variable": "est_user_var",
            "est_user": "est_user",
        }
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.cahandler._config_userauth_load(parser)
        self.assertIn(
            "INFO:test_a2c:CAhandler._config_load() overwrite est_user", lcm.output
        )
        self.assertEqual("est_user", self.cahandler.est_user)

    def test_022_config_password_load(self):
        """test _config_password_load()"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"est_password": "est_password"}
        self.cahandler._config_password_load(parser)
        self.assertEqual("est_password", self.cahandler.est_password)

    @patch.dict("os.environ", {"est_password_var": "est_password_var"})
    def test_023_config_password_load(self):
        """test _config_password_load()"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"est_password_variable": "est_password_var"}
        self.cahandler._config_password_load(parser)
        self.assertEqual("est_password_var", self.cahandler.est_password)

    @patch.dict("os.environ", {"var": "est_password_var"})
    def test_024_config_password_load(self):
        """test _config_password_load()"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"est_password_variable": "est_password_var"}
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.cahandler._config_password_load(parser)
        self.assertIn(
            "ERROR:test_a2c:Could not load est_password:'est_password_var'",
            lcm.output,
        )
        self.assertFalse(self.cahandler.est_password)

    @patch.dict("os.environ", {"est_password_var": "est_password_var"})
    def test_025_config_password_load(self):
        """test _config_password_load()"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {
            "est_password_variable": "est_password_var",
            "est_password": "est_password",
        }
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.cahandler._config_password_load(parser)
        self.assertIn("INFO:test_a2c:Overwrite est_password", lcm.output)
        self.assertEqual("est_password", self.cahandler.est_password)

    def test_026_config_password_load(self):
        """test _config_password_load()"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"foo": "bar"}
        self.cahandler.est_user = "foo"
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.cahandler._config_password_load(parser)
        self.assertIn(
            'ERROR:test_a2c:Configuration incomplete: either "est_user" or "est_password" parameter is missing in config file',
            lcm.output,
        )

    def test_027_config_password_load(self):
        """test _config_password_load()"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"foo": "bar"}
        self.cahandler.est_password = "foo"
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.cahandler._config_password_load(parser)
        self.assertIn(
            'ERROR:test_a2c:Configuration incomplete: either "est_user" or "est_password" parameter is missing in config file',
            lcm.output,
        )

    def test_028_config_parameters_load(self):
        """test _config_load - ca bundle"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"ca_bundle": True}
        self.cahandler._config_parameters_load(parser)
        self.assertTrue(self.cahandler.ca_bundle)
        self.assertEqual(20, self.cahandler.request_timeout)

    def test_029_config_parameters_load(self):
        """test _config_load - ca bundle"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"ca_bundle": False}
        self.cahandler._config_parameters_load(parser)
        self.assertFalse(self.cahandler.ca_bundle)
        self.assertEqual(20, self.cahandler.request_timeout)

    def test_030_config_parameters_load(self):
        """test _config_load - ca bundle"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"ca_bundle": "ca_bundle"}
        self.cahandler._config_parameters_load(parser)
        self.assertEqual("ca_bundle", self.cahandler.ca_bundle)
        self.assertEqual(20, self.cahandler.request_timeout)

    def test_031_config_parameters_load(self):
        """test _config_load - ca bundle"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"request_timeout": 10}
        self.cahandler._config_parameters_load(parser)
        self.assertTrue(self.cahandler.ca_bundle)
        self.assertEqual(10, self.cahandler.request_timeout)

    def test_032_config_parameters_load(self):
        """test _config_load - ca bundle"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"request_timeout": "10"}
        self.cahandler._config_parameters_load(parser)
        self.assertTrue(self.cahandler.ca_bundle)
        self.assertEqual(10, self.cahandler.request_timeout)

    def test_033_config_parameters_load(self):
        """test _config_load - ca bundle"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"request_timeout": "aa"}
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.cahandler._config_parameters_load(parser)
        self.assertIn(
            "ERROR:test_a2c:Could not load request_timeout:aa",
            lcm.output,
        )
        self.assertTrue(self.cahandler.ca_bundle)
        self.assertEqual(20, self.cahandler.request_timeout)

    @patch("examples.ca_handler.est_ca_handler.parse_url")
    @patch("json.loads")
    def test_034_config_proxy_load(self, mock_json, mock_url):
        """test _config_load ca_handler configured load proxies"""
        parser = configparser.ConfigParser()
        parser["DEFAULT"] = {"proxy_server_list": "foo"}
        mock_url.return_value = {"foo": "bar"}
        mock_json.return_value = "foo"
        self.cahandler._config_proxy_load(parser)
        self.assertTrue(mock_json.called)
        self.assertTrue(mock_url.called)
        self.assertEqual(20, self.cahandler.request_timeout)

    @patch("examples.ca_handler.est_ca_handler.proxy_check")
    @patch("examples.ca_handler.est_ca_handler.parse_url")
    @patch("json.loads")
    def test_035_config_proxy_load(self, mock_json, mock_url, mock_chk):
        """test _config_load ca_handler configured load proxies"""
        parser = configparser.ConfigParser()
        parser["DEFAULT"] = {"proxy_server_list": "foo"}
        mock_url.return_value = {"host": "bar:8888"}
        mock_json.return_value = "foo.bar.local"
        mock_chk.return_value = "proxy.bar.local"
        self.cahandler._config_proxy_load(parser)
        self.assertTrue(mock_json.called)
        self.assertTrue(mock_url.called)
        self.assertTrue(mock_chk.called)
        self.assertEqual(
            {"http": "proxy.bar.local", "https": "proxy.bar.local"},
            self.cahandler.proxy,
        )
        self.assertEqual(20, self.cahandler.request_timeout)

    @patch("examples.ca_handler.est_ca_handler.proxy_check")
    @patch("examples.ca_handler.est_ca_handler.parse_url")
    @patch("json.loads")
    def test_036_config_proxy_load(self, mock_json, mock_url, mock_chk):
        """test _config_load ca_handler configured load proxies"""
        parser = configparser.ConfigParser()
        parser["DEFAULT"] = {"proxy_server_list": "foo"}
        mock_url.return_value = {"host": "bar"}
        mock_json.return_value = "foo.bar.local"
        mock_chk.return_value = "proxy.bar.local"
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.cahandler._config_proxy_load(parser)
        self.assertTrue(mock_json.called)
        self.assertTrue(mock_url.called)
        self.assertFalse(mock_chk.called)
        self.assertFalse(self.cahandler.proxy)
        self.assertIn(
            "WARNING:test_a2c:Challenge._config_load() proxy_server_list failed with error: not enough values to unpack (expected 2, got 1)",
            lcm.output,
        )
        self.assertEqual(20, self.cahandler.request_timeout)

    def test_037_revoke(self):
        """test revocation"""
        self.assertEqual(
            (
                500,
                "urn:ietf:params:acme:error:serverInternal",
                "Revocation is not supported.",
            ),
            self.cahandler.revoke("cert", "rev_reason", "rev_date"),
        )

    def test_038_poll(self):
        """test polling"""
        self.assertEqual(
            ("Method not implemented.", None, None, "poll_identifier", False),
            self.cahandler.poll("cert_name", "poll_identifier", "csr"),
        )

    def test_039_trigger(self):
        """test polling"""
        self.assertEqual(
            ("Method not implemented.", None, None), self.cahandler.trigger("payload")
        )

    @patch("examples.ca_handler.est_ca_handler.b64_decode")
    @patch("examples.ca_handler.est_ca_handler.CAhandler._pkcs7_to_pem")
    @patch.object(requests, "get")
    def test_040__cacerts_get(self, mock_req, mock_to_pem, _mock_b64):
        """test _cacerts_get() successful run by using client certs"""
        self.cahandler.session = Mock()
        mockresponse = Mock()
        mock_req.return_value = mockresponse
        mockresponse.text = "mock return"
        mock_to_pem.return_value = "pem"
        self.cahandler.est_host = "foo"
        self.cahandler.ca_bundle = ["foo_bundle"]
        self.cahandler.est_client_cert = "est_client_cert"
        self.assertEqual((None, "pem"), self.cahandler._cacerts_get())

    @patch("examples.ca_handler.est_ca_handler.b64_decode")
    @patch("examples.ca_handler.est_ca_handler.CAhandler._pkcs7_to_pem")
    @patch.object(requests, "get")
    def test_041__cacerts_get(self, mock_req, mock_to_pem, _mock_b64):
        """test _cacerts_get() successful run by using client certs"""
        self.cahandler.session = Mock()
        mockresponse = Mock()
        mock_req.return_value = mockresponse
        mockresponse.text = "mock return"
        mock_to_pem.return_value = "pem"
        self.cahandler.est_host = "foo"
        self.cahandler.ca_bundle = ["foo_bundle"]
        self.cahandler.est_user = "est_user"
        self.cahandler.est_password = "est_password"
        self.assertEqual((None, "pem"), self.cahandler._cacerts_get())

    @patch("examples.ca_handler.est_ca_handler.b64_decode")
    @patch("examples.ca_handler.est_ca_handler.CAhandler._pkcs7_to_pem")
    @patch.object(requests, "get")
    def test_042__cacerts_get(self, mock_req, mock_to_pem, _mock_b64):
        """test _cacerts_get() no est_host parameter"""
        mockresponse = Mock()
        mock_req.return_value = mockresponse
        mockresponse.text = "mock return"
        mock_to_pem.return_value = "pem"
        self.cahandler.ca_bundle = ["foo_bundle"]
        self.cahandler.est_client_cert = "est_client_cert"
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.assertEqual((None, None), self.cahandler._cacerts_get())
        self.assertIn(
            'ERROR:test_a2c:Configuration incomplete: "est_host" parameter is missing',
            lcm.output,
        )

    @patch("examples.ca_handler.est_ca_handler.b64_decode")
    @patch("examples.ca_handler.est_ca_handler.CAhandler._pkcs7_to_pem")
    def test_043__cacerts_get(self, mock_to_pem, _mock_b64):
        """test _cacerts_get() request.get triggers exception"""
        self.cahandler.session = Mock()
        mock_to_pem.side_effect = Exception("exc_cacerts_get")
        self.cahandler.est_host = "foo"
        self.cahandler.ca_bundle = ["foo_bundle"]
        self.cahandler.est_client_cert = "est_client_cert"
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.cahandler._cacerts_get()
        self.assertIn(
            "ERROR:test_a2c:Error while getting the CA certificates: exc_cacerts_get",
            lcm.output,
        )

    @patch("examples.ca_handler.est_ca_handler.b64_decode")
    @patch("examples.ca_handler.est_ca_handler.CAhandler._pkcs7_to_pem")
    def test_044__simpleenroll(self, mock_to_pem, _mock_b64):
        """test _cacerts_get() successful run"""
        mockresponse = Mock()
        self.cahandler.session = Mock()
        mockresponse.text = "mock return"
        mock_to_pem.return_value = "pem"
        self.cahandler.est_host = "foo"
        self.cahandler.ca_bundle = ["foo_bundle"]
        self.cahandler.est_client_cert = "est_client_cert"
        self.assertEqual((None, "pem"), self.cahandler._simpleenroll("csr"))

    @patch("examples.ca_handler.est_ca_handler.b64_decode")
    @patch("examples.ca_handler.est_ca_handler.CAhandler._pkcs7_to_pem")
    def test_045__simpleenroll(self, mock_to_pem, mock_b64):
        """test _cacerts_get() successful run"""
        self.cahandler.session = Mock()
        mock_b64.side_effect = Exception("exc_simple_enroll")
        mock_to_pem.return_value = "pem"
        self.cahandler.est_host = "foo"
        self.cahandler.ca_bundle = ["foo_bundle"]
        self.cahandler.est_client_cert = "est_client_cert"
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.assertEqual(
                ("exc_simple_enroll", None), self.cahandler._simpleenroll("csr")
            )
        self.assertIn(
            "ERROR:test_a2c:Enrollment error: exc_simple_enroll",
            lcm.output,
        )

    @patch("examples.ca_handler.est_ca_handler.b64_decode")
    @patch("examples.ca_handler.est_ca_handler.CAhandler._pkcs7_to_pem")
    def test_046__simpleenroll(self, mock_to_pem, mock_b64):
        """test _cacerts_get() successful run"""
        self.cahandler.session = Mock()
        mock_b64.side_effect = Exception("exc_simple_enroll")
        mock_to_pem.return_value = "pem"
        self.cahandler.est_host = "foo"
        self.cahandler.ca_bundle = ["foo_bundle"]
        self.cahandler.est_user = "est_user"
        self.cahandler.est_password = "est_password"
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.assertEqual(
                ("exc_simple_enroll", None), self.cahandler._simpleenroll("csr")
            )
        self.assertIn(
            "ERROR:test_a2c:Enrollment error: exc_simple_enroll",
            lcm.output,
        )

    @patch("examples.ca_handler.est_ca_handler.CAhandler._cacerts_get")
    def test_047_enroll(self, mock_ca):
        """test certificate enrollment _cacert_get returns error"""
        mock_ca.return_value = ("Error", None)
        self.cahandler.est_host = "foo"
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.assertEqual(("Error", None, None, None), self.cahandler.enroll("csr"))
        self.assertIn(
            "ERROR:test_a2c:Error while fetching the CA certificates: Error", lcm.output
        )

    @patch("examples.ca_handler.est_ca_handler.CAhandler._cacerts_get")
    def test_048_enroll(self, mock_ca):
        """test certificate enrollment no error but now ca_certs"""
        mock_ca.return_value = (None, None)
        self.cahandler.est_host = "foo"
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.assertEqual(
                ("no CA certificates found", None, None, None),
                self.cahandler.enroll("csr"),
            )
        self.assertIn("ERROR:test_a2c:No CA certificates found", lcm.output)

    @patch("examples.ca_handler.est_ca_handler.CAhandler._simpleenroll")
    @patch("examples.ca_handler.est_ca_handler.CAhandler._cacerts_get")
    def test_049_enroll(self, mock_ca, mock_enroll):
        """test certificate enrollment _simpleenroll returns error"""
        mock_ca.return_value = (None, "ca_pem")
        mock_enroll.return_value = ("Error", None)
        self.cahandler.est_host = "foo"
        self.cahandler.est_user = "est_usr"
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.assertEqual(("Error", None, None, None), self.cahandler.enroll("csr"))
        self.assertIn("ERROR:test_a2c:Simpleenroll error: Error", lcm.output)

    @patch("examples.ca_handler.est_ca_handler.allowed_domainlist_check")
    @patch("examples.ca_handler.est_ca_handler.CAhandler._simpleenroll")
    @patch("examples.ca_handler.est_ca_handler.CAhandler._cacerts_get")
    def test_050_enroll(self, mock_ca, mock_enroll, mock_adl):
        """test certificate enrollment _simpleenroll returns certificate"""
        mock_ca.return_value = (None, "ca_pem")
        mock_enroll.return_value = (None, "cert")
        mock_adl.return_value = None
        self.cahandler.est_host = "foo"
        self.cahandler.est_user = "est_usr"
        self.assertEqual(
            (None, "certca_pem", "cert", None), self.cahandler.enroll("csr")
        )
        self.assertTrue(mock_adl.called)

    @patch("examples.ca_handler.est_ca_handler.allowed_domainlist_check")
    @patch("examples.ca_handler.est_ca_handler.CAhandler._simpleenroll")
    @patch("examples.ca_handler.est_ca_handler.CAhandler._cacerts_get")
    def test_051_enroll(self, mock_ca, mock_enroll, mock_adl):
        """test certificate enrollment _simpleenroll returns certificate"""
        mock_ca.return_value = (None, "ca_pem")
        mock_enroll.return_value = (None, "cert")
        mock_adl.return_value = "adl_error"
        self.cahandler.est_host = "foo"
        self.cahandler.est_user = "est_usr"
        self.assertEqual(("adl_error", None, None, None), self.cahandler.enroll("csr"))
        self.assertTrue(mock_adl.called)
        self.assertFalse(mock_enroll.called)

    @patch("examples.ca_handler.est_ca_handler.CAhandler._simpleenroll")
    @patch("examples.ca_handler.est_ca_handler.CAhandler._cacerts_get")
    def test_052_enroll(self, mock_ca, mock_enroll):
        """test certificate enrollment replace CERT BEGIN"""
        mock_ca.return_value = (None, "ca_pem")
        mock_enroll.return_value = (None, "-----BEGIN CERTIFICATE-----\ncert")
        self.cahandler.est_host = "foo"
        self.cahandler.est_user = "est_usr"
        self.assertEqual(
            (None, "-----BEGIN CERTIFICATE-----\ncertca_pem", "cert", None),
            self.cahandler.enroll("csr"),
        )

    @patch("examples.ca_handler.est_ca_handler.CAhandler._simpleenroll")
    @patch("examples.ca_handler.est_ca_handler.CAhandler._cacerts_get")
    def test_053_enroll(self, mock_ca, mock_enroll):
        """test certificate enrollment replace CERT END"""
        mock_ca.return_value = (None, "ca_pem")
        mock_enroll.return_value = (None, "cert-----END CERTIFICATE-----\n")
        self.cahandler.est_host = "foo"
        self.cahandler.est_user = "est_usr"
        self.assertEqual(
            (None, "cert-----END CERTIFICATE-----\nca_pem", "cert", None),
            self.cahandler.enroll("csr"),
        )

    @patch("examples.ca_handler.est_ca_handler.CAhandler._simpleenroll")
    @patch("examples.ca_handler.est_ca_handler.CAhandler._cacerts_get")
    def test_054_enroll(self, mock_ca, mock_enroll):
        """test certificate enrollment replace CERT BEGIN AND END"""
        mock_ca.return_value = (None, "ca_pem")
        mock_enroll.return_value = (
            None,
            "-----BEGIN CERTIFICATE-----\ncert-----END CERTIFICATE-----\n",
        )
        self.cahandler.est_host = "foo"
        self.cahandler.est_user = "est_usr"
        self.assertEqual(
            (
                None,
                "-----BEGIN CERTIFICATE-----\ncert-----END CERTIFICATE-----\nca_pem",
                "cert",
                None,
            ),
            self.cahandler.enroll("csr"),
        )

    @patch("examples.ca_handler.est_ca_handler.CAhandler._simpleenroll")
    @patch("examples.ca_handler.est_ca_handler.CAhandler._cacerts_get")
    def test_055_enroll(self, mock_ca, mock_enroll):
        """test certificate enrollment replace CERT BEGIN AND END and \n"""
        mock_ca.return_value = (None, "ca_pem")
        mock_enroll.return_value = (
            None,
            "-----BEGIN CERTIFICATE-----\ncert\n-----END CERTIFICATE-----\n\n",
        )
        self.cahandler.est_host = "foo"
        self.cahandler.est_user = "est_usr"
        self.assertEqual(
            (
                None,
                "-----BEGIN CERTIFICATE-----\ncert\n-----END CERTIFICATE-----\n\nca_pem",
                "cert",
                None,
            ),
            self.cahandler.enroll("csr"),
        )

    @patch("examples.ca_handler.est_ca_handler.CAhandler._config_load")
    def test_056__enter__(self, mock_cfg):
        """test enter  called"""
        mock_cfg.return_value = True
        self.cahandler.__enter__()
        self.assertTrue(mock_cfg.called)

    @patch("examples.ca_handler.est_ca_handler.CAhandler._config_load")
    def test_057__enter__(self, mock_cfg):
        """test enter api hosts defined"""
        mock_cfg.return_value = True
        self.cahandler.est_host = "api_host"
        self.cahandler.__enter__()
        self.assertFalse(mock_cfg.called)

    def test_058__pkcs7_to_pem(self):
        """test pkcs7 to pem default output"""
        with open(self.dir_path + "/ca/certs.p7b", "r") as fso:
            file_content = fso.read()
        with open(self.dir_path + "/ca/certs.pem", "r") as fso:
            result = fso.read()
        self.assertEqual(result, self.cahandler._pkcs7_to_pem(file_content))

    def test_059__pkcs7_to_pem(self):
        """test pkcs7 to pem output string"""
        with open(self.dir_path + "/ca/certs.p7b", "r") as fso:
            file_content = fso.read()
        with open(self.dir_path + "/ca/certs.pem", "r") as fso:
            result = fso.read()
        self.assertEqual(result, self.cahandler._pkcs7_to_pem(file_content, "string"))

    def test_060__pkcs7_to_pem(self):
        """test pkcs7 to pem output list"""
        with open(self.dir_path + "/ca/certs.p7b", "r") as fso:
            file_content = fso.read()
        result = [
            "-----BEGIN CERTIFICATE-----\nMIIFTzCCAzegAwIBAgIIAzHyhSyrXfMwDQYJKoZIhvcNAQELBQAwKzEXMBUGA1UE\nCxMOYWNtZTJjZXJ0aWZpZXIxEDAOBgNVBAMTB3Jvb3QtY2EwHhcNMjAwNTI3MTM1\nNDAwWhcNMzAwNTI2MjM1OTAwWjAqMRcwFQYDVQQLEw5hY21lMmNlcnRpZmllcjEP\nMA0GA1UEAxMGc3ViLWNhMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA\nxXHaGZsolXe+PBdUryngHP9VbBC1mehqeTtYI+hqsqGNH7q9a7bSrxMwFuF1kYL8\njqqxkJdtl0L94xcxJg/ZdMx7Nt0vGI+BaAuTpEpUEHeN4tqS6NhB/m/0LGkAELc/\nqkzmoO4B1FDwEEj/3IXtZcupqG80oDt7jWSGXdtF7NTjzcumznMeRXidCdhxRxT/\n/WrsChaytXo0xWZ56oeNwd6x6Dr8/39PBOWtj4fldyDcg+Q+alci2tx9pxmu2bCV\nXcB9ftCLKhDk2WEHE88bgKSp7fV2RCmq9po+Tx8JJ7qecLunUsK/F0XN4kpoQLm9\nhcymqchnMSncSiyin1dQHGHWgXDtBDdq6A2Z6rx26Qk5H9HTYvcNSe1YwFEDoGLB\nZQjbCPWiaqoaH4agBQTclPvrrSCRaVmhUSO+pBtSXDkmN4t3MDZxfgRkp8ixwkB1\n5Y5f0LTpCyAJsdQDw8+Ea0aDqO30eskh4CErnm9+Fejd9Ew2cwpdwfBXzVSbYilM\nGueQihZHvJmVRxAwU69aO2Qs8B0tQ60CfWKVlmWPiakrvYYlPp0FBsM61G6LZEN8\nhH2CKnS8hHv5IWEXZvp0Pk8V3P5h6bWN0Tl+x/V1Prt7Wp8NoiPETE8XyDDxe6dm\nKxztWBH/mTsJyMGb6ZiUoXdPU9TFUKqHxTRLHaxfsPsCAwEAAaN4MHYwEgYDVR0T\nAQH/BAgwBgEB/wIBATAdBgNVHQ4EFgQUv96OjgYiIqutQ8jd1E+oq0hBPtUwDgYD\nVR0PAQH/BAQDAgGGMBEGCWCGSAGG+EIBAQQEAwIABzAeBglghkgBhvhCAQ0EERYP\neGNhIGNlcnRpZmljYXRlMA0GCSqGSIb3DQEBCwUAA4ICAQBbHLEVyg4f9uEujroc\n31UVyDRLMdPgEPLjOenSBCBmH0N81whDmxNI/7JAAB6J14WMX8OLF0HkZnb7G77W\nvDhy1aFvQFbXHBz3/zUO9Mw9J4L2XEW6ond3Nsh1m2oXeBde3R3ANxuIzHqZDlP9\n6YrRcHjnf4+1/5AKDJAvJD+gFb5YnYUKH2iSvHUvG17xcZx98Rf2eo8LealG4JqH\nJh4sKRy0VjDQD7jXSCbweTHEb8wz+6OfNGrIo+BhTFP5vPcwE4nlJwYBoaOJ5cVa\n7gdQJ7WkLSxvwHxuxzvSVK73u3jl3I9SqTrbMLG/jeJyV0P8EvdljOaGnCtQVRwC\nzM4ptXUvKhKOHy7/nyTF/Bc35ZwwL/2xWvNK1+NibgE/6CFxupwWpdmxQbVVuoQ3\n2tUil9ty0yC6m5GKE8+t1lrZuxyA+b/TBnYNO5xo8UEMbkpxaNYSwmw+f/loxXP/\nM7sIBcLvy2ugHEBxwd9o/kLXeXT2DaRvxPjp4yk8MpJRpNmz3aB5HJwaUnaRLVo5\nZ3XWWXmjMGZ6/m0AAoDbDz/pXtOoJZT8BJdD1DuDdszVsQnLVn4B/LtIXL6FbXsF\nzfv6ERP9a5gpKUZ+4NjgrnlGtdccNZpwyWF0IXcvaq3b8hXIRO4hMjzHeHfzJN4t\njX1vlY35Ofonc4+6dRVamBiF9A==\n-----END CERTIFICATE-----\n",
            "-----BEGIN CERTIFICATE-----\nMIIFcDCCA1igAwIBAgIIevLTTxOMoZgwDQYJKoZIhvcNAQELBQAwKzEXMBUGA1UE\nCxMOYWNtZTJjZXJ0aWZpZXIxEDAOBgNVBAMTB3Jvb3QtY2EwHhcNMjAwNTI3MDAw\nMDAwWhcNMzAwNTI2MjM1OTU5WjArMRcwFQYDVQQLEw5hY21lMmNlcnRpZmllcjEQ\nMA4GA1UEAxMHcm9vdC1jYTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIB\nAJy4UZHdZgYt64k/rFamoC676tYvtabeuiqVw1c6oVZI897cFLG6BYwyr2Eaj7tF\nrqTJDeMN4vZSudLsmLDq6m8KwX/riPzUTIlcjM5aIMANZr9rLEs3NWtcivolB5aQ\n1slhdVitUPLuxsFnYeQTyxFyP7lng9M/Z403KLG8phdmKjM0vJkaj4OuKOXf3UsW\nqWQYyRl/ms07xVj02uq08LkoeO+jtQisvyVXURdaCceZtyK/ZBQ7NFCsbK112cVR\n1e2aJol7NJAA6Wm6iBzAdkAA2l3kh40SLoEbaiaVMixLN2vilIZOOAoDXX4+T6ir\n+KnDVSJ2yu5c/OJMwuXwHrh7Lgg1vsFR5TNehknhjUuWOUO+0TkKPg2A7KTg72OZ\n2mOcLZIbxzr1P5RRvdmLQLPrTF2EJvpQPNmbXqN3ZVWEvfHTjkkTFY/dsOTvFTgS\nri15zYKch8votcU7z+BQhgmMtwO2JhPMmZ6ABd9skI7ijWpwOltAhxtdoBO6T6CB\nCrE2yXc6V/PyyAKcFglNmIght5oXsnE+ub/dtx8f9Iea/xNPdo5aGy8fdaitolDK\n16kd3Kb7OE4HMHIwOxxF1BEAqerxxhbLMRBr8hRSZI5cvLzWLvpAQ5zuhjD6V3b9\nBYFd4ujAu3zl3mbzdbYjFoGOX6aBZaGDxlc4O2W7HxntAgMBAAGjgZcwgZQwDwYD\nVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUDGVvuTFYZtEAkz3af9wRKDDvAswwHwYD\nVR0jBBgwFoAUDGVvuTFYZtEAkz3af9wRKDDvAswwDgYDVR0PAQH/BAQDAgGGMBEG\nCWCGSAGG+EIBAQQEAwIABzAeBglghkgBhvhCAQ0EERYPeGNhIGNlcnRpZmljYXRl\nMA0GCSqGSIb3DQEBCwUAA4ICAQAjko7dX+iCgT+m3Iy1Vg6j7MRevPAzq1lqHRRN\nNdt2ct530pIut7Fv5V2xYk35ka+i/G+XyOvTXa9vAUKiBtiRnUPsXu4UcS7CcrCX\nEzHx4eOtHnp5wDhO0Fx5/OUZTaP+L7Pd1GD/j953ibx5bMa/M9Rj+S486nst57tu\nDRmEAavFDiMd6L3jH4YSckjmIH2uSeDIaRa9k6ag077XmWhvVYQ9tuR7RGbSuuV3\nFc6pqcFbbWpoLhNRcFc+hbUKOsKl2cP+QEKP/H2s3WMllqgAKKZeO+1KOsGo1CDs\n475bIXyCBpFbH2HOPatmu3yZRQ9fj9ta9EW46n33DFRNLinFWa4WJs4yLVP1juge\n2TCOyA1t61iy++RRXSG3e7NFYrEZuCht1EdDAdzIUY89m9NCPwoDYS4CahgnfkkO\n7YQe6f6yqK6isyf8ZFcp1uF58eERDiF/FDqS8nLmCdURuI56DDoNvDpig5J/9RNW\nG8vEvt2p7QrjeZ3EAatx5JuYty/NKTHZwJWk51CgzEgzDwzE2JIiqeldtL5d0Sl6\neVuv0G04BEyuXxEWpgVVzBS4qEFIBSnTJzgu1PXmId3yLvg2Nr8NKvwyZmN5xKFp\n0A9BWo15zW1PXDaD+l39oTYD7agjXkzTAjYIcfNJ7ATIYFD0xAvNAOf70s7aNupF\nfvkG2Q==\n-----END CERTIFICATE-----\n",
        ]
        self.assertEqual(result, self.cahandler._pkcs7_to_pem(file_content, "list"))

    def test_061__pkcs7_to_pem(self):
        """test pkcs7 to pem output list"""
        with open(self.dir_path + "/ca/certs.p7b", "r") as fso:
            file_content = fso.read()
        result = None
        self.assertEqual(result, self.cahandler._pkcs7_to_pem(file_content, "unknown"))

    def test_062__pkcs7_to_pem(self):
        """test pkcs7 to pem output list"""

        file_content = base64.b64decode(
            "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"
        )
        result = [
            "-----BEGIN CERTIFICATE-----\nMIIFTzCCAzegAwIBAgIIAzHyhSyrXfMwDQYJKoZIhvcNAQELBQAwKzEXMBUGA1UE\nCxMOYWNtZTJjZXJ0aWZpZXIxEDAOBgNVBAMTB3Jvb3QtY2EwHhcNMjAwNTI3MTM1\nNDAwWhcNMzAwNTI2MjM1OTAwWjAqMRcwFQYDVQQLEw5hY21lMmNlcnRpZmllcjEP\nMA0GA1UEAxMGc3ViLWNhMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA\nxXHaGZsolXe+PBdUryngHP9VbBC1mehqeTtYI+hqsqGNH7q9a7bSrxMwFuF1kYL8\njqqxkJdtl0L94xcxJg/ZdMx7Nt0vGI+BaAuTpEpUEHeN4tqS6NhB/m/0LGkAELc/\nqkzmoO4B1FDwEEj/3IXtZcupqG80oDt7jWSGXdtF7NTjzcumznMeRXidCdhxRxT/\n/WrsChaytXo0xWZ56oeNwd6x6Dr8/39PBOWtj4fldyDcg+Q+alci2tx9pxmu2bCV\nXcB9ftCLKhDk2WEHE88bgKSp7fV2RCmq9po+Tx8JJ7qecLunUsK/F0XN4kpoQLm9\nhcymqchnMSncSiyin1dQHGHWgXDtBDdq6A2Z6rx26Qk5H9HTYvcNSe1YwFEDoGLB\nZQjbCPWiaqoaH4agBQTclPvrrSCRaVmhUSO+pBtSXDkmN4t3MDZxfgRkp8ixwkB1\n5Y5f0LTpCyAJsdQDw8+Ea0aDqO30eskh4CErnm9+Fejd9Ew2cwpdwfBXzVSbYilM\nGueQihZHvJmVRxAwU69aO2Qs8B0tQ60CfWKVlmWPiakrvYYlPp0FBsM61G6LZEN8\nhH2CKnS8hHv5IWEXZvp0Pk8V3P5h6bWN0Tl+x/V1Prt7Wp8NoiPETE8XyDDxe6dm\nKxztWBH/mTsJyMGb6ZiUoXdPU9TFUKqHxTRLHaxfsPsCAwEAAaN4MHYwEgYDVR0T\nAQH/BAgwBgEB/wIBATAdBgNVHQ4EFgQUv96OjgYiIqutQ8jd1E+oq0hBPtUwDgYD\nVR0PAQH/BAQDAgGGMBEGCWCGSAGG+EIBAQQEAwIABzAeBglghkgBhvhCAQ0EERYP\neGNhIGNlcnRpZmljYXRlMA0GCSqGSIb3DQEBCwUAA4ICAQBbHLEVyg4f9uEujroc\n31UVyDRLMdPgEPLjOenSBCBmH0N81whDmxNI/7JAAB6J14WMX8OLF0HkZnb7G77W\nvDhy1aFvQFbXHBz3/zUO9Mw9J4L2XEW6ond3Nsh1m2oXeBde3R3ANxuIzHqZDlP9\n6YrRcHjnf4+1/5AKDJAvJD+gFb5YnYUKH2iSvHUvG17xcZx98Rf2eo8LealG4JqH\nJh4sKRy0VjDQD7jXSCbweTHEb8wz+6OfNGrIo+BhTFP5vPcwE4nlJwYBoaOJ5cVa\n7gdQJ7WkLSxvwHxuxzvSVK73u3jl3I9SqTrbMLG/jeJyV0P8EvdljOaGnCtQVRwC\nzM4ptXUvKhKOHy7/nyTF/Bc35ZwwL/2xWvNK1+NibgE/6CFxupwWpdmxQbVVuoQ3\n2tUil9ty0yC6m5GKE8+t1lrZuxyA+b/TBnYNO5xo8UEMbkpxaNYSwmw+f/loxXP/\nM7sIBcLvy2ugHEBxwd9o/kLXeXT2DaRvxPjp4yk8MpJRpNmz3aB5HJwaUnaRLVo5\nZ3XWWXmjMGZ6/m0AAoDbDz/pXtOoJZT8BJdD1DuDdszVsQnLVn4B/LtIXL6FbXsF\nzfv6ERP9a5gpKUZ+4NjgrnlGtdccNZpwyWF0IXcvaq3b8hXIRO4hMjzHeHfzJN4t\njX1vlY35Ofonc4+6dRVamBiF9A==\n-----END CERTIFICATE-----\n",
            "-----BEGIN CERTIFICATE-----\nMIIFcDCCA1igAwIBAgIIevLTTxOMoZgwDQYJKoZIhvcNAQELBQAwKzEXMBUGA1UE\nCxMOYWNtZTJjZXJ0aWZpZXIxEDAOBgNVBAMTB3Jvb3QtY2EwHhcNMjAwNTI3MDAw\nMDAwWhcNMzAwNTI2MjM1OTU5WjArMRcwFQYDVQQLEw5hY21lMmNlcnRpZmllcjEQ\nMA4GA1UEAxMHcm9vdC1jYTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIB\nAJy4UZHdZgYt64k/rFamoC676tYvtabeuiqVw1c6oVZI897cFLG6BYwyr2Eaj7tF\nrqTJDeMN4vZSudLsmLDq6m8KwX/riPzUTIlcjM5aIMANZr9rLEs3NWtcivolB5aQ\n1slhdVitUPLuxsFnYeQTyxFyP7lng9M/Z403KLG8phdmKjM0vJkaj4OuKOXf3UsW\nqWQYyRl/ms07xVj02uq08LkoeO+jtQisvyVXURdaCceZtyK/ZBQ7NFCsbK112cVR\n1e2aJol7NJAA6Wm6iBzAdkAA2l3kh40SLoEbaiaVMixLN2vilIZOOAoDXX4+T6ir\n+KnDVSJ2yu5c/OJMwuXwHrh7Lgg1vsFR5TNehknhjUuWOUO+0TkKPg2A7KTg72OZ\n2mOcLZIbxzr1P5RRvdmLQLPrTF2EJvpQPNmbXqN3ZVWEvfHTjkkTFY/dsOTvFTgS\nri15zYKch8votcU7z+BQhgmMtwO2JhPMmZ6ABd9skI7ijWpwOltAhxtdoBO6T6CB\nCrE2yXc6V/PyyAKcFglNmIght5oXsnE+ub/dtx8f9Iea/xNPdo5aGy8fdaitolDK\n16kd3Kb7OE4HMHIwOxxF1BEAqerxxhbLMRBr8hRSZI5cvLzWLvpAQ5zuhjD6V3b9\nBYFd4ujAu3zl3mbzdbYjFoGOX6aBZaGDxlc4O2W7HxntAgMBAAGjgZcwgZQwDwYD\nVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUDGVvuTFYZtEAkz3af9wRKDDvAswwHwYD\nVR0jBBgwFoAUDGVvuTFYZtEAkz3af9wRKDDvAswwDgYDVR0PAQH/BAQDAgGGMBEG\nCWCGSAGG+EIBAQQEAwIABzAeBglghkgBhvhCAQ0EERYPeGNhIGNlcnRpZmljYXRl\nMA0GCSqGSIb3DQEBCwUAA4ICAQAjko7dX+iCgT+m3Iy1Vg6j7MRevPAzq1lqHRRN\nNdt2ct530pIut7Fv5V2xYk35ka+i/G+XyOvTXa9vAUKiBtiRnUPsXu4UcS7CcrCX\nEzHx4eOtHnp5wDhO0Fx5/OUZTaP+L7Pd1GD/j953ibx5bMa/M9Rj+S486nst57tu\nDRmEAavFDiMd6L3jH4YSckjmIH2uSeDIaRa9k6ag077XmWhvVYQ9tuR7RGbSuuV3\nFc6pqcFbbWpoLhNRcFc+hbUKOsKl2cP+QEKP/H2s3WMllqgAKKZeO+1KOsGo1CDs\n475bIXyCBpFbH2HOPatmu3yZRQ9fj9ta9EW46n33DFRNLinFWa4WJs4yLVP1juge\n2TCOyA1t61iy++RRXSG3e7NFYrEZuCht1EdDAdzIUY89m9NCPwoDYS4CahgnfkkO\n7YQe6f6yqK6isyf8ZFcp1uF58eERDiF/FDqS8nLmCdURuI56DDoNvDpig5J/9RNW\nG8vEvt2p7QrjeZ3EAatx5JuYty/NKTHZwJWk51CgzEgzDwzE2JIiqeldtL5d0Sl6\neVuv0G04BEyuXxEWpgVVzBS4qEFIBSnTJzgu1PXmId3yLvg2Nr8NKvwyZmN5xKFp\n0A9BWo15zW1PXDaD+l39oTYD7agjXkzTAjYIcfNJ7ATIYFD0xAvNAOf70s7aNupF\nfvkG2Q==\n-----END CERTIFICATE-----\n",
        ]
        self.assertEqual(result, self.cahandler._pkcs7_to_pem(file_content, "list"))


if __name__ == "__main__":

    unittest.main()
