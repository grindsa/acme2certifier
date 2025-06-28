#!/usr/bin/python
# -*- coding: utf-8 -*-
"""unittests for openssl_ca_handler"""
# pylint: disable=C0415, R0904, W0212
import sys
import os
import unittest
from unittest.mock import patch, Mock, MagicMock
import requests
import base64

sys.path.insert(0, ".")
sys.path.insert(1, "..")


class TestACMEHandler(unittest.TestCase):
    """test class for cgi_handler"""

    def setUp(self):
        """setup unittest"""
        import logging
        from examples.ca_handler.asa_ca_handler import CAhandler

        logging.basicConfig(level=logging.CRITICAL)
        self.logger = logging.getLogger("test_a2c")
        self.cahandler = CAhandler(False, self.logger)
        self.dir_path = os.path.dirname(os.path.realpath(__file__))
        self.maxDiff = None

    def test_001_default(self):
        """default test which always passes"""
        self.assertEqual("foo", "foo")

    @patch("examples.ca_handler.asa_ca_handler.CAhandler._config_load")
    def test_002__enter__(self, mock_cfg):
        """test enter  called"""
        mock_cfg.return_value = True
        self.cahandler.__enter__()
        self.assertTrue(mock_cfg.called)

    def test_003_poll(self):
        """test polling"""
        self.assertEqual(
            ("Method not implemented.", None, None, "poll_identifier", False),
            self.cahandler.poll("cert_name", "poll_identifier", "csr"),
        )

    def test_004_trigger(self):
        """test polling"""
        self.assertEqual(
            ("Method not implemented.", None, None), self.cahandler.trigger("payload")
        )

    @patch("examples.ca_handler.asa_ca_handler.load_config")
    def test_005_config_load(self, mock_config_load):
        """test _config_load"""
        mock_config_load.return_value = {"CAhandler": {"api_host": "api_host"}}
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.cahandler._config_load()
        self.assertIn(
            "ERROR:test_a2c:CAhandler._config_load(): api_user not set", lcm.output
        )
        self.assertIn(
            "ERROR:test_a2c:CAhandler._config_load(): api_password not set", lcm.output
        )
        self.assertIn(
            "ERROR:test_a2c:CAhandler._config_load(): api_key not set", lcm.output
        )
        self.assertEqual("api_host", self.cahandler.api_host)
        self.assertFalse(self.cahandler.api_user)
        self.assertFalse(self.cahandler.api_password)
        self.assertFalse(self.cahandler.api_key)
        self.assertFalse(self.cahandler.ca_bundle)
        self.assertFalse(self.cahandler.proxy)
        self.assertEqual(10, self.cahandler.request_timeout)
        self.assertEqual(30, self.cahandler.cert_validity_days)
        self.assertFalse(self.cahandler.header_info_field)

    @patch("examples.ca_handler.asa_ca_handler.load_config")
    def test_006_config_load(self, mock_config_load):
        """test _config_load"""
        mock_config_load.return_value = {"CAhandler": {"api_user": "api_user"}}
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.cahandler._config_load()
        self.assertIn(
            "ERROR:test_a2c:CAhandler._config_load(): api_host not set", lcm.output
        )
        self.assertIn(
            "ERROR:test_a2c:CAhandler._config_load(): api_password not set", lcm.output
        )
        self.assertIn(
            "ERROR:test_a2c:CAhandler._config_load(): api_key not set", lcm.output
        )
        self.assertFalse(self.cahandler.api_host)
        self.assertEqual("api_user", self.cahandler.api_user)
        self.assertFalse(self.cahandler.api_password)
        self.assertFalse(self.cahandler.api_key)
        self.assertFalse(self.cahandler.ca_bundle)
        self.assertFalse(self.cahandler.proxy)
        self.assertEqual(10, self.cahandler.request_timeout)
        self.assertEqual(30, self.cahandler.cert_validity_days)
        self.assertFalse(self.cahandler.header_info_field)

    @patch("examples.ca_handler.asa_ca_handler.load_config")
    def test_007_config_load(self, mock_config_load):
        """test _config_load"""
        mock_config_load.return_value = {"CAhandler": {"api_password": "api_password"}}
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.cahandler._config_load()
        self.assertIn(
            "ERROR:test_a2c:CAhandler._config_load(): api_host not set", lcm.output
        )
        self.assertIn(
            "ERROR:test_a2c:CAhandler._config_load(): api_user not set", lcm.output
        )
        self.assertIn(
            "ERROR:test_a2c:CAhandler._config_load(): api_key not set", lcm.output
        )
        self.assertFalse(self.cahandler.api_host)
        self.assertFalse(self.cahandler.api_user)
        self.assertEqual("api_password", self.cahandler.api_password)
        self.assertFalse(self.cahandler.api_key)
        self.assertFalse(self.cahandler.ca_bundle)
        self.assertFalse(self.cahandler.proxy)
        self.assertEqual(10, self.cahandler.request_timeout)
        self.assertEqual(30, self.cahandler.cert_validity_days)
        self.assertFalse(self.cahandler.header_info_field)

    @patch("examples.ca_handler.asa_ca_handler.load_config")
    def test_008_config_load(self, mock_config_load):
        """test _config_load"""
        mock_config_load.return_value = {"CAhandler": {"api_key": "api_key"}}
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.cahandler._config_load()
        self.assertIn(
            "ERROR:test_a2c:CAhandler._config_load(): api_host not set", lcm.output
        )
        self.assertIn(
            "ERROR:test_a2c:CAhandler._config_load(): api_user not set", lcm.output
        )
        self.assertIn(
            "ERROR:test_a2c:CAhandler._config_load(): api_password not set", lcm.output
        )
        self.assertFalse(self.cahandler.api_host)
        self.assertFalse(self.cahandler.api_user)
        self.assertFalse(self.cahandler.api_password)
        self.assertEqual("api_key", self.cahandler.api_key)
        self.assertFalse(self.cahandler.ca_bundle)
        self.assertFalse(self.cahandler.proxy)
        self.assertEqual(10, self.cahandler.request_timeout)
        self.assertEqual(30, self.cahandler.cert_validity_days)
        self.assertFalse(self.cahandler.header_info_field)

    @patch("examples.ca_handler.asa_ca_handler.load_config")
    def test_009_config_load(self, mock_config_load):
        """test _config_load"""
        mock_config_load.return_value = {
            "CAhandler": {
                "api_host": "api_host",
                "api_user": "api_user",
                "api_password": "api_password",
                "api_key": "api_key",
            }
        }
        self.cahandler._config_load()
        self.assertEqual("api_host", self.cahandler.api_host)
        self.assertEqual("api_user", self.cahandler.api_user)
        self.assertEqual("api_password", self.cahandler.api_password)
        self.assertEqual("api_key", self.cahandler.api_key)
        self.assertFalse(self.cahandler.proxy)
        self.assertEqual(10, self.cahandler.request_timeout)
        self.assertEqual(30, self.cahandler.cert_validity_days)
        self.assertFalse(self.cahandler.header_info_field)

    @patch("examples.ca_handler.asa_ca_handler.load_config")
    def test_010_config_load(self, mock_config_load):
        """test _config_load"""
        mock_config_load.return_value = {"foo": "bar"}
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.cahandler._config_load()
        self.assertIn(
            "ERROR:test_a2c:CAhandler._config_load(): api_host not set", lcm.output
        )
        self.assertIn(
            "ERROR:test_a2c:CAhandler._config_load(): api_user not set", lcm.output
        )
        self.assertIn(
            "ERROR:test_a2c:CAhandler._config_load(): api_password not set", lcm.output
        )
        self.assertIn(
            "ERROR:test_a2c:CAhandler._config_load(): api_key not set", lcm.output
        )
        self.assertFalse(self.cahandler.api_host)
        self.assertFalse(self.cahandler.api_user)
        self.assertFalse(self.cahandler.api_password)
        self.assertFalse(self.cahandler.api_key)
        self.assertFalse(self.cahandler.ca_bundle)
        self.assertFalse(self.cahandler.proxy)
        self.assertEqual(10, self.cahandler.request_timeout)
        self.assertEqual(30, self.cahandler.cert_validity_days)
        self.assertFalse(self.cahandler.header_info_field)

    @patch("examples.ca_handler.asa_ca_handler.load_config")
    def test_011_config_load(self, mock_config_load):
        """test _config_load"""
        mock_config_load.return_value = {"CAhandler": {"request_timeout": 20}}
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.cahandler._config_load()
        self.assertIn(
            "ERROR:test_a2c:CAhandler._config_load(): api_host not set", lcm.output
        )
        self.assertIn(
            "ERROR:test_a2c:CAhandler._config_load(): api_user not set", lcm.output
        )
        self.assertIn(
            "ERROR:test_a2c:CAhandler._config_load(): api_key not set", lcm.output
        )
        self.assertIn(
            "ERROR:test_a2c:CAhandler._config_load(): api_password not set", lcm.output
        )
        self.assertFalse(self.cahandler.api_host)
        self.assertFalse(self.cahandler.api_user)
        self.assertFalse(self.cahandler.api_password)
        self.assertFalse(self.cahandler.api_key)
        self.assertFalse(self.cahandler.ca_bundle)
        self.assertFalse(self.cahandler.proxy)
        self.assertEqual(20, self.cahandler.request_timeout)
        self.assertEqual(30, self.cahandler.cert_validity_days)
        self.assertFalse(self.cahandler.header_info_field)

    @patch("examples.ca_handler.asa_ca_handler.load_config")
    def test_012_config_load(self, mock_config_load):
        """test _config_load"""
        mock_config_load.return_value = {"CAhandler": {"request_timeout": "aa"}}
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.cahandler._config_load()
        self.assertIn(
            "ERROR:test_a2c:CAhandler._config_load(): api_host not set", lcm.output
        )
        self.assertIn(
            "ERROR:test_a2c:CAhandler._config_load(): api_user not set", lcm.output
        )
        self.assertIn(
            "ERROR:test_a2c:CAhandler._config_load(): api_key not set", lcm.output
        )
        self.assertIn(
            "ERROR:test_a2c:CAhandler._config_load(): api_password not set", lcm.output
        )
        self.assertIn(
            "ERROR:test_a2c:CAhandler._config_load(): request_timeout not an integer",
            lcm.output,
        )
        self.assertFalse(self.cahandler.api_host)
        self.assertFalse(self.cahandler.api_user)
        self.assertFalse(self.cahandler.api_password)
        self.assertFalse(self.cahandler.api_key)
        self.assertFalse(self.cahandler.ca_bundle)
        self.assertFalse(self.cahandler.proxy)
        self.assertEqual(10, self.cahandler.request_timeout)
        self.assertEqual(30, self.cahandler.cert_validity_days)
        self.assertFalse(self.cahandler.header_info_field)

    @patch("examples.ca_handler.asa_ca_handler.load_config")
    def test_013_config_load(self, mock_config_load):
        """test _config_load"""
        mock_config_load.return_value = {"CAhandler": {"cert_validity_days": 10}}
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.cahandler._config_load()
        self.assertIn(
            "ERROR:test_a2c:CAhandler._config_load(): api_host not set", lcm.output
        )
        self.assertIn(
            "ERROR:test_a2c:CAhandler._config_load(): api_user not set", lcm.output
        )
        self.assertIn(
            "ERROR:test_a2c:CAhandler._config_load(): api_key not set", lcm.output
        )
        self.assertIn(
            "ERROR:test_a2c:CAhandler._config_load(): api_password not set", lcm.output
        )
        # self.assertIn('ERROR:test_a2c:CAhandler._config_load(): request_timeout not an integer', lcm.output)
        self.assertFalse(self.cahandler.api_host)
        self.assertFalse(self.cahandler.api_user)
        self.assertFalse(self.cahandler.api_password)
        self.assertFalse(self.cahandler.api_key)
        self.assertFalse(self.cahandler.ca_bundle)
        self.assertFalse(self.cahandler.proxy)
        self.assertEqual(10, self.cahandler.request_timeout)
        self.assertEqual(10, self.cahandler.cert_validity_days)
        self.assertFalse(self.cahandler.header_info_field)

    @patch("examples.ca_handler.asa_ca_handler.load_config")
    def test_014_config_load(self, mock_config_load):
        """test _config_load"""
        mock_config_load.return_value = {"CAhandler": {"cert_validity_days": "aa"}}
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.cahandler._config_load()
        self.assertIn(
            "ERROR:test_a2c:CAhandler._config_load(): api_host not set", lcm.output
        )
        self.assertIn(
            "ERROR:test_a2c:CAhandler._config_load(): api_user not set", lcm.output
        )
        self.assertIn(
            "ERROR:test_a2c:CAhandler._config_load(): api_key not set", lcm.output
        )
        self.assertIn(
            "ERROR:test_a2c:CAhandler._config_load(): api_password not set", lcm.output
        )
        self.assertIn(
            "ERROR:test_a2c:CAhandler._config_load(): cert_validity_days not an integer",
            lcm.output,
        )
        self.assertFalse(self.cahandler.api_host)
        self.assertFalse(self.cahandler.api_user)
        self.assertFalse(self.cahandler.api_password)
        self.assertFalse(self.cahandler.api_key)
        self.assertFalse(self.cahandler.ca_bundle)
        self.assertFalse(self.cahandler.proxy)
        self.assertEqual(10, self.cahandler.request_timeout)
        self.assertEqual(30, self.cahandler.cert_validity_days)
        self.assertFalse(self.cahandler.header_info_field)

    @patch("examples.ca_handler.asa_ca_handler.load_config")
    def test_015_config_load(self, mock_config_load):
        """test _config_load"""
        mock_config_load.return_value = {"CAhandler": {"ca_bundle": "aa"}}
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.cahandler._config_load()
        self.assertIn(
            "ERROR:test_a2c:CAhandler._config_load(): api_host not set", lcm.output
        )
        self.assertIn(
            "ERROR:test_a2c:CAhandler._config_load(): api_user not set", lcm.output
        )
        self.assertIn(
            "ERROR:test_a2c:CAhandler._config_load(): api_key not set", lcm.output
        )
        self.assertIn(
            "ERROR:test_a2c:CAhandler._config_load(): api_password not set", lcm.output
        )
        self.assertFalse(self.cahandler.api_host)
        self.assertFalse(self.cahandler.api_user)
        self.assertFalse(self.cahandler.api_password)
        self.assertFalse(self.cahandler.api_key)
        self.assertEqual("aa", self.cahandler.ca_bundle)
        self.assertFalse(self.cahandler.proxy)
        self.assertEqual(10, self.cahandler.request_timeout)
        self.assertEqual(30, self.cahandler.cert_validity_days)
        self.assertFalse(self.cahandler.header_info_field)

    @patch("examples.ca_handler.asa_ca_handler.load_config")
    def test_016_config_load(self, mock_config_load):
        """test _config_load"""
        mock_config_load.return_value = {"CAhandler": {"ca_bundle": "False"}}
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.cahandler._config_load()
        self.assertIn(
            "ERROR:test_a2c:CAhandler._config_load(): api_host not set", lcm.output
        )
        self.assertIn(
            "ERROR:test_a2c:CAhandler._config_load(): api_user not set", lcm.output
        )
        self.assertIn(
            "ERROR:test_a2c:CAhandler._config_load(): api_key not set", lcm.output
        )
        self.assertIn(
            "ERROR:test_a2c:CAhandler._config_load(): api_password not set", lcm.output
        )
        self.assertFalse(self.cahandler.api_host)
        self.assertFalse(self.cahandler.api_user)
        self.assertFalse(self.cahandler.api_password)
        self.assertFalse(self.cahandler.api_key)
        self.assertFalse(self.cahandler.ca_bundle)
        self.assertFalse(self.cahandler.proxy)
        self.assertEqual(10, self.cahandler.request_timeout)
        self.assertEqual(30, self.cahandler.cert_validity_days)
        self.assertFalse(self.cahandler.header_info_field)

    @patch("examples.ca_handler.asa_ca_handler.load_config")
    def test_017_config_load(self, mock_config_load):
        """test _config_load"""
        mock_config_load.return_value = {"Order": {"header_info_list": '["foo"]'}}
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.cahandler._config_load()
        self.assertIn(
            "ERROR:test_a2c:CAhandler._config_load(): api_host not set", lcm.output
        )
        self.assertIn(
            "ERROR:test_a2c:CAhandler._config_load(): api_user not set", lcm.output
        )
        self.assertIn(
            "ERROR:test_a2c:CAhandler._config_load(): api_key not set", lcm.output
        )
        self.assertIn(
            "ERROR:test_a2c:CAhandler._config_load(): api_password not set", lcm.output
        )
        self.assertFalse(self.cahandler.api_host)
        self.assertFalse(self.cahandler.api_user)
        self.assertFalse(self.cahandler.api_password)
        self.assertFalse(self.cahandler.api_key)
        self.assertFalse(self.cahandler.ca_bundle)
        self.assertFalse(self.cahandler.proxy)
        self.assertEqual(10, self.cahandler.request_timeout)
        self.assertEqual(30, self.cahandler.cert_validity_days)
        self.assertEqual("foo", self.cahandler.header_info_field)

    @patch.object(requests, "post")
    def test_018__api_post(self, mock_req):
        """test _api_post()"""
        mockresponse = Mock()
        mockresponse.status_code = "status_code"
        mockresponse.json = lambda: {"foo": "bar"}
        mock_req.return_value = mockresponse
        self.assertEqual(
            ("status_code", {"foo": "bar"}), self.cahandler._api_post("url", "data")
        )

    @patch("requests.post")
    def test_019__api_post(self, mock_req):
        """test _api_post()"""
        mockresponse = Mock()
        mockresponse.status_code = "status_code"
        mockresponse.json = "aaaa"
        mock_req.return_value = mockresponse
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.assertEqual(
                ("status_code", "'str' object is not callable"),
                self.cahandler._api_post("url", "data"),
            )
        self.assertIn(
            "ERROR:test_a2c:CAhandler._api_post() returned error during json parsing: 'str' object is not callable",
            lcm.output,
        )

    @patch("requests.post")
    def test_020__api_post(self, mock_req):
        """test _api_post()"""
        mockresponse = Mock()
        mockresponse.status_code = "status_code"
        mockresponse.text = None
        mock_req.return_value = mockresponse
        self.assertEqual(("status_code", None), self.cahandler._api_post("url", "data"))

    @patch("requests.post")
    def test_021__api_post(self, mock_req):
        """test _api_post(="""
        self.cahandler.api_host = "api_host"
        self.cahandler.auth = "auth"
        mock_req.side_effect = Exception("exc_api_post")
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.assertEqual(
                (500, "exc_api_post"), self.cahandler._api_post("url", "data")
            )
        self.assertIn(
            "ERROR:test_a2c:CAhandler._api_post() returned error: exc_api_post",
            lcm.output,
        )

    @patch.object(requests, "get")
    def test_022__api_get(self, mock_req):
        """test _api_get()"""
        mockresponse = Mock()
        mockresponse.status_code = "status_code"
        mockresponse.json = lambda: {"foo": "bar"}
        mock_req.return_value = mockresponse
        self.assertEqual(
            ("status_code", {"foo": "bar"}), self.cahandler._api_get("url")
        )

    @patch("requests.get")
    def test_023__api_get(self, mock_req):
        """test _api_get()"""
        mockresponse = Mock()
        mockresponse.status_code = "status_code"
        mockresponse.json = "aaaa"
        mock_req.return_value = mockresponse
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.assertEqual(
                ("status_code", "'str' object is not callable"),
                self.cahandler._api_get("url"),
            )
        self.assertIn(
            "ERROR:test_a2c:CAhandler._api_get() returned error during json parsing: 'str' object is not callable",
            lcm.output,
        )

    @patch("requests.get")
    def test_024__api_get(self, mock_req):
        """test _api_get()"""
        self.cahandler.api_host = "api_host"
        self.cahandler.auth = "auth"
        mock_req.side_effect = Exception("exc_api_get")
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.assertEqual((500, "exc_api_get"), self.cahandler._api_get("url"))
        self.assertIn(
            "ERROR:test_a2c:CAhandler._api_get() returned error: exc_api_get",
            lcm.output,
        )

    @patch("examples.ca_handler.asa_ca_handler.CAhandler._api_get")
    def test_025__issuers_list(self, mock_get):
        """test _issuers_list()"""
        mock_get.return_value = (200, "content")
        self.assertEqual("content", self.cahandler._issuers_list())

    @patch("examples.ca_handler.asa_ca_handler.CAhandler._api_get")
    def test_026__profiles_list(self, mock_get):
        """test _profiles_list()"""
        self.cahandler.ca_name = "ca_name"
        mock_get.return_value = (200, "content")
        self.assertEqual("content", self.cahandler._profiles_list())

    @patch("examples.ca_handler.asa_ca_handler.CAhandler._api_get")
    def test_027__certificates_list(self, mock_get):
        """test _profiles_list()"""
        self.cahandler.ca_name = "ca_name"
        mock_get.return_value = (200, "content")
        self.assertEqual("content", self.cahandler._certificates_list())

    @patch("examples.ca_handler.asa_ca_handler.CAhandler._api_post")
    def test_028_cert_status_get(self, mock_req):
        """test _profiles_list()"""
        self.cahandler.ca_name = "ca_name"
        mock_req.return_value = ("status_code", {"foo": "bar"})
        self.assertEqual(
            {"foo": "bar", "code": "status_code"},
            self.cahandler._cert_status_get("cert"),
        )

    @patch("examples.ca_handler.asa_ca_handler.csr_san_get")
    @patch("examples.ca_handler.asa_ca_handler.csr_cn_get")
    def test_029__csr_cn_get(self, mock_cn, mock_san):
        """test _csr_cn_get()"""
        mock_cn.return_value = "cn"
        mock_san.return_value = ["san0", "san1"]
        self.assertEqual("cn", self.cahandler._csr_cn_get("csr"))
        self.assertFalse(mock_san.called)

    @patch("examples.ca_handler.asa_ca_handler.csr_san_get")
    @patch("examples.ca_handler.asa_ca_handler.csr_cn_get")
    def test_030__csr_cn_get(self, mock_cn, mock_san):
        """test _csr_cn_get()"""
        mock_cn.return_value = None
        mock_san.return_value = ["dns:san0", "dns:san1"]
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.assertEqual("san0", self.cahandler._csr_cn_get("csr"))
        self.assertIn("INFO:test_a2c:CN not found in CSR", lcm.output)
        self.assertIn(
            "INFO:test_a2c:CN not found in CSR. Using first SAN entry as CN: san0",
            lcm.output,
        )
        self.assertTrue(mock_san.called)

    @patch("examples.ca_handler.asa_ca_handler.csr_san_get")
    @patch("examples.ca_handler.asa_ca_handler.csr_cn_get")
    def test_031__csr_cn_get(self, mock_cn, mock_san):
        """test _csr_cn_get()"""
        mock_cn.return_value = None
        mock_san.return_value = None
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.assertEqual(None, self.cahandler._csr_cn_get("csr"))
        self.assertIn("INFO:test_a2c:CN not found in CSR", lcm.output)
        self.assertIn(
            "ERROR:test_a2c:CN not found in CSR. No SAN entries found",
            lcm.output,
        )
        self.assertTrue(mock_san.called)

    @patch("examples.ca_handler.asa_ca_handler.CAhandler._issuers_list")
    def test_032_issuer_verify(self, mock_list):
        """_issuer_verify()"""
        self.cahandler.ca_name = "ca_name"
        mock_list.return_value = {"issuers": ["1", "2", "ca_name"]}
        self.assertFalse(self.cahandler._issuer_verify())

    @patch("examples.ca_handler.asa_ca_handler.CAhandler._issuers_list")
    def test_033_issuer_verify(self, mock_list):
        """_issuer_verify()"""
        self.cahandler.ca_name = "ca_name"
        mock_list.return_value = {"issuers": ["1", "2", "3"]}
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.assertEqual("CA ca_name not found", self.cahandler._issuer_verify())
        self.assertIn(
            "ERROR:test_a2c:CAhandler.enroll(): CA ca_name not found", lcm.output
        )

    @patch("examples.ca_handler.asa_ca_handler.CAhandler._issuers_list")
    def test_034_issuer_verify(self, mock_list):
        """_issuer_verify()"""
        self.cahandler.ca_name = "ca_name"
        mock_list.return_value = {"foo": "bar"}
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.assertEqual("Malformed response", self.cahandler._issuer_verify())
        self.assertIn(
            'ERROR:test_a2c:CAhandler.enroll(): "Malformed response. "issuers" key not found',
            lcm.output,
        )

    @patch("examples.ca_handler.asa_ca_handler.CAhandler._profiles_list")
    def test_035_profile_verify(self, mock_list):
        """_profile_verify()"""
        self.cahandler.profile_name = "profile_name"
        mock_list.return_value = {"profiles": ["1", "2", "profile_name"]}
        self.assertFalse(self.cahandler._profile_verify())

    @patch("examples.ca_handler.asa_ca_handler.CAhandler._profiles_list")
    def test_036_profile_verify(self, mock_list):
        """_profile_verify()"""
        self.cahandler.profile_name = "profile_name"
        mock_list.return_value = {"profiles": ["1", "2", "3"]}
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.assertEqual(
                "Profile profile_name not found", self.cahandler._profile_verify()
            )
        self.assertIn(
            "ERROR:test_a2c:CAhandler.enroll(): Profile profile_name not found",
            lcm.output,
        )

    @patch("examples.ca_handler.asa_ca_handler.CAhandler._profiles_list")
    def test_037_profile_verify(self, mock_list):
        """_profile_verify()"""
        self.cahandler.ca_name = "ca_name"
        mock_list.return_value = {"foo": "bar"}
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.assertEqual("Malformed response", self.cahandler._profile_verify())
        self.assertIn(
            'ERROR:test_a2c:CAhandler.enroll(): "Malformed response. "profiles" key not found',
            lcm.output,
        )

    @patch("examples.ca_handler.asa_ca_handler.uts_to_date_utc")
    @patch("examples.ca_handler.asa_ca_handler.uts_now")
    def test_038__validity_dates_get(self, mock_now, mock_utc):
        """test _validity_dates_get()"""
        mock_now.return_value = 10
        mock_utc.side_effect = ["date1", "date2"]
        self.assertEqual(("date1", "date2"), self.cahandler._validity_dates_get())
        self.assertTrue(mock_now.called)

    @patch("examples.ca_handler.asa_ca_handler.convert_byte_to_string")
    @patch("examples.ca_handler.asa_ca_handler.cert_der2pem")
    @patch("examples.ca_handler.asa_ca_handler.b64_decode")
    def test_039__pem_cert_chain_generate(self, mock_dec, mock_d2p, mock_b2s):
        """test _pem_cert_chain_generate()"""
        mock_b2s.return_value = "cert"
        self.assertEqual(
            "certcert", self.cahandler._pem_cert_chain_generate(["cert", "chain"])
        )

    def test_040__pem_cert_chain_generate(self):
        """test _pem_cert_chain_generate()"""
        cert_list = [
            "MIIF7DCCBFSgAwIBAgIKB/8cQ9wAI3UbITANBgkqhkiG9w0BAQsFADBaMQswCQYDVQQGEwJERTERMA8GA1UECgwIT3BlblhQS0kxDDAKBgNVBAsMA1BLSTEqMCgGA1UEAwwhT3BlblhQS0kgRGVtbyBJc3N1aW5nIENBIDIwMjMwMjA0MB4XDTIzMDIwNTA2NDY0MloXDTI0MDIwNTA2NDY0MlowazETMBEGCgmSJomT8ixkARkWA29yZzEYMBYGCgmSJomT8ixkARkWCE9wZW5YUEtJMR8wHQYKCZImiZPyLGQBGRYPVGVzdCBEZXBsb3ltZW50MRkwFwYDVQQDDBBhY21lMS5keW5hbW9wLmRlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAre1jtb8Xjqr49QH3fWe2kH+yDk3NXfxHyOmKcNcBke68WMRB5Irrdj15JfAsXxu9psLVEOJgvdOLOnUbhN57uBLHwMAC1LH6HruYuCqtbaSezgJIYIEACvtQmIy6BIvigqwX31eLkA7kk7YXeJCnvrr461t/uZkhmaXZM9+G4asSj6fT0ffA7OVVqewDdE+d2VgCjPlH9uqPMOVK2m/AQj+jEVV/IV2znngZmkAsmYi6h2Wg08vEzTMyvhZIEma3xo6M9g9VIsTQP/ETxxhAAgzEQ0Jlz90rOioZK7mkx8xH1fLlhyfX53vqcEbva5evy1YMGEs0XZPYu2B6Oya9WQIDAQABo4ICITCCAh0wgYcGCCsGAQUFBwEBBHsweTBRBggrBgEFBQcwAoZFaHR0cDovL3BraS5leGFtcGxlLmNvbS9kb3dubG9hZC9PcGVuWFBLSV9EZW1vX0lzc3VpbmdfQ0FfMjAyMzAyMDQuY2VyMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5leGFtcGxlLmNvbS8wHwYDVR0jBBgwFoAU0f8PWcniVXltJeA6q7wYtyJrNFAwDAYDVR0TAQH/BAIwADBWBgNVHR8ETzBNMEugSaBHhkVodHRwOi8vcGtpLmV4YW1wbGUuY29tL2Rvd25sb2FkL09wZW5YUEtJX0RlbW9fSXNzdWluZ19DQV8yMDIzMDIwNC5jcmwwEwYDVR0lBAwwCgYIKwYBBQUHAwEwDgYDVR0PAQH/BAQDAgWgMIGoBgNVHSAEgaAwgZ0wgZoGAyoDBDCBkjArBggrBgEFBQcCARYfaHR0cDovL3BraS5leGFtcGxlLmNvbS9jcHMuaHRtbDArBggrBgEFBQcCARYfaHR0cDovL3BraS5leGFtcGxlLmNvbS9jcHMuaHRtbDA2BggrBgEFBQcCAjAqGihUaGlzIGlzIGEgY29tbWVudCBmb3IgcG9saWN5IG9pZCAxLjIuMy40MBsGA1UdEQQUMBKCEGFjbWUxLmR5bmFtb3AuZGUwHQYDVR0OBBYEFA3AUTV0pg0fsd3Cd6/BskOEB9MVMA0GCSqGSIb3DQEBCwUAA4IBgQB0xnnl6BJDXrbTQr7TdkRPmcCDFUmi8aVTYozbQ8EKxIYEPsfzxOFbSG/wn+4Sjz7HqvzqxyisfTopqWrvpqIhlXOEFMnNYTDO4LzCd81Dcs4czjoIRxRTisgNCvWR9hbeH9HzdRT1UF/c4VxxLEONSsGHksoXa+G4u7XmPwD4dTUIP49Mmj2a28z/viG8KftcjAEo1S7OB+/xyPeVDYrgagMR31a69pI+yuQa0J66O/LJQrzjWf6wHToQErQPcEBtDxY2wx3hROMtdla9lUEU8XLb3e9zByZwOfDhFpw8iYkJx/BUZlsmIKaZSpYVS+0D5LI1R5PENhT/2gRxaA31RiNLK/E8CSU7MMadqImkFLkDHU2x+2SRENwvoOEUAOewjVlhB1pK0r5WEye2lBjl8cUa+8qhIrAOqggApQ7eCQq7v2bL08VxKz5baOhKfLZ9u4MH6q52pnqXmll0W7JXrJSbam5r3YoSelm94VwVyaSkfd+LT4YMAP7GDDvtT6Y="
        ]
        result = """-----BEGIN CERTIFICATE-----
MIIF7DCCBFSgAwIBAgIKB/8cQ9wAI3UbITANBgkqhkiG9w0BAQsFADBaMQswCQYD
VQQGEwJERTERMA8GA1UECgwIT3BlblhQS0kxDDAKBgNVBAsMA1BLSTEqMCgGA1UE
AwwhT3BlblhQS0kgRGVtbyBJc3N1aW5nIENBIDIwMjMwMjA0MB4XDTIzMDIwNTA2
NDY0MloXDTI0MDIwNTA2NDY0MlowazETMBEGCgmSJomT8ixkARkWA29yZzEYMBYG
CgmSJomT8ixkARkWCE9wZW5YUEtJMR8wHQYKCZImiZPyLGQBGRYPVGVzdCBEZXBs
b3ltZW50MRkwFwYDVQQDDBBhY21lMS5keW5hbW9wLmRlMIIBIjANBgkqhkiG9w0B
AQEFAAOCAQ8AMIIBCgKCAQEAre1jtb8Xjqr49QH3fWe2kH+yDk3NXfxHyOmKcNcB
ke68WMRB5Irrdj15JfAsXxu9psLVEOJgvdOLOnUbhN57uBLHwMAC1LH6HruYuCqt
baSezgJIYIEACvtQmIy6BIvigqwX31eLkA7kk7YXeJCnvrr461t/uZkhmaXZM9+G
4asSj6fT0ffA7OVVqewDdE+d2VgCjPlH9uqPMOVK2m/AQj+jEVV/IV2znngZmkAs
mYi6h2Wg08vEzTMyvhZIEma3xo6M9g9VIsTQP/ETxxhAAgzEQ0Jlz90rOioZK7mk
x8xH1fLlhyfX53vqcEbva5evy1YMGEs0XZPYu2B6Oya9WQIDAQABo4ICITCCAh0w
gYcGCCsGAQUFBwEBBHsweTBRBggrBgEFBQcwAoZFaHR0cDovL3BraS5leGFtcGxl
LmNvbS9kb3dubG9hZC9PcGVuWFBLSV9EZW1vX0lzc3VpbmdfQ0FfMjAyMzAyMDQu
Y2VyMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5leGFtcGxlLmNvbS8wHwYDVR0j
BBgwFoAU0f8PWcniVXltJeA6q7wYtyJrNFAwDAYDVR0TAQH/BAIwADBWBgNVHR8E
TzBNMEugSaBHhkVodHRwOi8vcGtpLmV4YW1wbGUuY29tL2Rvd25sb2FkL09wZW5Y
UEtJX0RlbW9fSXNzdWluZ19DQV8yMDIzMDIwNC5jcmwwEwYDVR0lBAwwCgYIKwYB
BQUHAwEwDgYDVR0PAQH/BAQDAgWgMIGoBgNVHSAEgaAwgZ0wgZoGAyoDBDCBkjAr
BggrBgEFBQcCARYfaHR0cDovL3BraS5leGFtcGxlLmNvbS9jcHMuaHRtbDArBggr
BgEFBQcCARYfaHR0cDovL3BraS5leGFtcGxlLmNvbS9jcHMuaHRtbDA2BggrBgEF
BQcCAjAqGihUaGlzIGlzIGEgY29tbWVudCBmb3IgcG9saWN5IG9pZCAxLjIuMy40
MBsGA1UdEQQUMBKCEGFjbWUxLmR5bmFtb3AuZGUwHQYDVR0OBBYEFA3AUTV0pg0f
sd3Cd6/BskOEB9MVMA0GCSqGSIb3DQEBCwUAA4IBgQB0xnnl6BJDXrbTQr7TdkRP
mcCDFUmi8aVTYozbQ8EKxIYEPsfzxOFbSG/wn+4Sjz7HqvzqxyisfTopqWrvpqIh
lXOEFMnNYTDO4LzCd81Dcs4czjoIRxRTisgNCvWR9hbeH9HzdRT1UF/c4VxxLEON
SsGHksoXa+G4u7XmPwD4dTUIP49Mmj2a28z/viG8KftcjAEo1S7OB+/xyPeVDYrg
agMR31a69pI+yuQa0J66O/LJQrzjWf6wHToQErQPcEBtDxY2wx3hROMtdla9lUEU
8XLb3e9zByZwOfDhFpw8iYkJx/BUZlsmIKaZSpYVS+0D5LI1R5PENhT/2gRxaA31
RiNLK/E8CSU7MMadqImkFLkDHU2x+2SRENwvoOEUAOewjVlhB1pK0r5WEye2lBjl
8cUa+8qhIrAOqggApQ7eCQq7v2bL08VxKz5baOhKfLZ9u4MH6q52pnqXmll0W7JX
rJSbam5r3YoSelm94VwVyaSkfd+LT4YMAP7GDDvtT6Y=
-----END CERTIFICATE-----
"""
        self.assertEqual(result, self.cahandler._pem_cert_chain_generate(cert_list))

    @patch("examples.ca_handler.asa_ca_handler.CAhandler._pem_cert_chain_generate")
    @patch("examples.ca_handler.asa_ca_handler.CAhandler._api_get")
    def test_041___issuer_chain_get(self, mock_req, mock_pem):
        """test _issuer_chain_get()"""
        mock_req.return_value = ("code", {"certs": ["bar", "foo"]})
        mock_pem.return_value = "issuer_chain"
        self.cahandler.ca_name = "ca_name"
        self.assertEqual("issuer_chain", self.cahandler._issuer_chain_get())
        self.assertTrue(mock_pem.called)

    @patch("examples.ca_handler.asa_ca_handler.CAhandler._pem_cert_chain_generate")
    @patch("examples.ca_handler.asa_ca_handler.CAhandler._api_get")
    def test_042___issuer_chain_get(self, mock_req, mock_pem):
        """test _issuer_chain_get()"""
        mock_req.return_value = ("code", {"foobar": ["bar", "foo"]})
        mock_pem.return_value = "issuer_chain"
        self.cahandler.ca_name = "ca_name"
        self.assertFalse(self.cahandler._issuer_chain_get())
        self.assertFalse(mock_pem.called)

    @patch("examples.ca_handler.asa_ca_handler.allowed_domainlist_check")
    @patch("examples.ca_handler.asa_ca_handler.enrollment_config_log")
    @patch("examples.ca_handler.asa_ca_handler.CAhandler._api_post")
    @patch("examples.ca_handler.asa_ca_handler.convert_byte_to_string")
    @patch("examples.ca_handler.asa_ca_handler.cert_der2pem")
    @patch("examples.ca_handler.asa_ca_handler.b64_decode")
    @patch("examples.ca_handler.asa_ca_handler.CAhandler._validity_dates_get")
    @patch("examples.ca_handler.asa_ca_handler.CAhandler._csr_cn_get")
    @patch("examples.ca_handler.asa_ca_handler.csr_pubkey_get")
    @patch("examples.ca_handler.asa_ca_handler.CAhandler._issuer_chain_get")
    @patch("examples.ca_handler.asa_ca_handler.CAhandler._issuer_verify")
    @patch("examples.ca_handler.asa_ca_handler.eab_profile_header_info_check")
    def test_043_enroll(
        self,
        mock_pv,
        mock_iv,
        mock_icg,
        mock_cpg,
        mockccg,
        mock_vdg,
        mock_b64,
        mock_d2p,
        mock_b2s,
        mock_post,
        mock_ecl,
        mock_adl,
    ):
        """test enroll()"""
        mock_iv.return_value = None
        mock_pv.return_value = "pv_error"
        mock_icg.return_value = "issuer_chain"
        mock_vdg.return_value = ("date1", "date2")
        mock_post.return_value = (200, "cert")
        mock_b2s.return_value = "bcert"
        self.cahandler.header_info_field = "foo"
        self.assertEqual(("pv_error", None, None, None), self.cahandler.enroll("csr"))
        self.assertTrue(mock_pv.called)
        self.assertFalse(mock_iv.called)
        self.assertFalse(mock_icg.called)
        self.assertFalse(mock_cpg.called)
        self.assertFalse(mockccg.called)
        self.assertFalse(mock_vdg.called)
        self.assertFalse(mock_b64.called)
        self.assertFalse(mock_post.called)
        self.assertFalse(mock_b2s.called)
        self.assertFalse(mock_d2p.called)
        self.assertFalse(mock_ecl.called)
        self.assertFalse(mock_adl.called)

    @patch("examples.ca_handler.asa_ca_handler.allowed_domainlist_check")
    @patch("examples.ca_handler.asa_ca_handler.enrollment_config_log")
    @patch("examples.ca_handler.asa_ca_handler.CAhandler._api_post")
    @patch("examples.ca_handler.asa_ca_handler.convert_byte_to_string")
    @patch("examples.ca_handler.asa_ca_handler.cert_der2pem")
    @patch("examples.ca_handler.asa_ca_handler.b64_decode")
    @patch("examples.ca_handler.asa_ca_handler.CAhandler._validity_dates_get")
    @patch("examples.ca_handler.asa_ca_handler.CAhandler._csr_cn_get")
    @patch("examples.ca_handler.asa_ca_handler.csr_pubkey_get")
    @patch("examples.ca_handler.asa_ca_handler.CAhandler._issuer_chain_get")
    @patch("examples.ca_handler.asa_ca_handler.CAhandler._issuer_verify")
    @patch("examples.ca_handler.asa_ca_handler.eab_profile_header_info_check")
    def test_044_enroll(
        self,
        mock_pv,
        mock_iv,
        mock_icg,
        mock_cpg,
        mockccg,
        mock_vdg,
        mock_b64,
        mock_d2p,
        mock_b2s,
        mock_post,
        mock_ecl,
        mock_adl,
    ):
        """test enroll()"""
        mock_iv.return_value = None
        mock_pv.return_value = None
        mock_adl.return_value = "adl_error"
        mock_icg.return_value = "issuer_chain"
        mock_vdg.return_value = ("date1", "date2")
        mock_post.return_value = (200, "cert")
        mock_b2s.return_value = "bcert"
        self.cahandler.header_info_field = "foo"
        self.assertEqual(("adl_error", None, None, None), self.cahandler.enroll("csr"))
        self.assertTrue(mock_pv.called)
        self.assertFalse(mock_iv.called)
        self.assertFalse(mock_icg.called)
        self.assertFalse(mock_cpg.called)
        self.assertFalse(mockccg.called)
        self.assertFalse(mock_vdg.called)
        self.assertFalse(mock_b64.called)
        self.assertFalse(mock_post.called)
        self.assertFalse(mock_b2s.called)
        self.assertFalse(mock_d2p.called)
        self.assertFalse(mock_ecl.called)
        self.assertTrue(mock_adl.called)

    @patch("examples.ca_handler.asa_ca_handler.enrollment_config_log")
    @patch("examples.ca_handler.asa_ca_handler.CAhandler._api_post")
    @patch("examples.ca_handler.asa_ca_handler.convert_byte_to_string")
    @patch("examples.ca_handler.asa_ca_handler.cert_der2pem")
    @patch("examples.ca_handler.asa_ca_handler.b64_decode")
    @patch("examples.ca_handler.asa_ca_handler.CAhandler._validity_dates_get")
    @patch("examples.ca_handler.asa_ca_handler.CAhandler._csr_cn_get")
    @patch("examples.ca_handler.asa_ca_handler.csr_pubkey_get")
    @patch("examples.ca_handler.asa_ca_handler.CAhandler._issuer_chain_get")
    @patch("examples.ca_handler.asa_ca_handler.CAhandler._profile_verify")
    @patch("examples.ca_handler.asa_ca_handler.CAhandler._issuer_verify")
    def test_045_enroll(
        self,
        mock_iv,
        mock_pv,
        mock_icg,
        mock_cpg,
        mockccg,
        mock_vdg,
        mock_b64,
        mock_d2p,
        mock_b2s,
        mock_post,
        mock_ecl,
    ):
        """test enroll()"""
        mock_iv.return_value = None
        mock_pv.return_value = None
        mock_icg.return_value = "issuer_chain"
        mock_vdg.return_value = ("date1", "date2")
        mock_post.return_value = (200, "cert")
        mock_b2s.return_value = "bcert"
        self.cahandler.header_info_field = "foo"
        self.cahandler.enrollment_config_log = True
        self.assertEqual(
            (None, "bcertissuer_chain", "cert", None), self.cahandler.enroll("csr")
        )
        self.assertTrue(mock_iv.called)
        self.assertTrue(mock_pv.called)
        self.assertTrue(mock_icg.called)
        self.assertTrue(mock_cpg.called)
        self.assertTrue(mockccg.called)
        self.assertTrue(mock_vdg.called)
        self.assertTrue(mock_b64.called)
        self.assertTrue(mock_post.called)
        self.assertTrue(mock_b2s.called)
        self.assertTrue(mock_d2p.called)
        self.assertTrue(mock_ecl.called)

    @patch("examples.ca_handler.asa_ca_handler.CAhandler._api_post")
    @patch("examples.ca_handler.asa_ca_handler.convert_byte_to_string")
    @patch("examples.ca_handler.asa_ca_handler.cert_der2pem")
    @patch("examples.ca_handler.asa_ca_handler.b64_decode")
    @patch("examples.ca_handler.asa_ca_handler.CAhandler._validity_dates_get")
    @patch("examples.ca_handler.asa_ca_handler.CAhandler._csr_cn_get")
    @patch("examples.ca_handler.asa_ca_handler.csr_pubkey_get")
    @patch("examples.ca_handler.asa_ca_handler.CAhandler._issuer_chain_get")
    @patch("examples.ca_handler.asa_ca_handler.CAhandler._profile_verify")
    @patch("examples.ca_handler.asa_ca_handler.CAhandler._issuer_verify")
    def test_046_enroll(
        self,
        mock_iv,
        mock_pv,
        mock_icg,
        mock_cpg,
        mockccg,
        mock_vdg,
        mock_b64,
        mock_d2p,
        mock_b2s,
        mock_post,
    ):
        """test enroll()"""
        mock_iv.return_value = None
        mock_pv.return_value = None
        mock_icg.return_value = "issuer_chain"
        mock_vdg.return_value = ("date1", "date2")
        mock_post.return_value = (200, "cert")
        mock_b2s.return_value = "bcert"
        self.assertEqual(
            (None, "bcertissuer_chain", "cert", None), self.cahandler.enroll("csr")
        )
        self.assertTrue(mock_iv.called)
        self.assertTrue(mock_pv.called)
        self.assertTrue(mock_icg.called)
        self.assertTrue(mock_cpg.called)
        self.assertTrue(mockccg.called)
        self.assertTrue(mock_vdg.called)
        self.assertTrue(mock_b64.called)
        self.assertTrue(mock_post.called)
        self.assertTrue(mock_b2s.called)
        self.assertTrue(mock_d2p.called)

    @patch("examples.ca_handler.asa_ca_handler.CAhandler._api_post")
    @patch("examples.ca_handler.asa_ca_handler.convert_byte_to_string")
    @patch("examples.ca_handler.asa_ca_handler.cert_der2pem")
    @patch("examples.ca_handler.asa_ca_handler.b64_decode")
    @patch("examples.ca_handler.asa_ca_handler.CAhandler._validity_dates_get")
    @patch("examples.ca_handler.asa_ca_handler.CAhandler._csr_cn_get")
    @patch("examples.ca_handler.asa_ca_handler.csr_pubkey_get")
    @patch("examples.ca_handler.asa_ca_handler.CAhandler._issuer_chain_get")
    @patch("examples.ca_handler.asa_ca_handler.CAhandler._profile_verify")
    @patch("examples.ca_handler.asa_ca_handler.CAhandler._issuer_verify")
    def test_047_enroll(
        self,
        mock_iv,
        mock_pv,
        mock_icg,
        mock_cpg,
        mockccg,
        mock_vdg,
        mock_b64,
        mock_d2p,
        mock_b2s,
        mock_post,
    ):
        """test enroll()"""
        mock_iv.return_value = "mock_iv"
        mock_pv.return_value = None
        mock_icg.return_value = "issuer_chain"
        mock_vdg.return_value = ("date1", "date2")
        mock_post.return_value = ("code", "cert")
        mock_b2s.return_value = "bcert"
        self.assertEqual(("mock_iv", None, None, None), self.cahandler.enroll("csr"))
        self.assertTrue(mock_iv.called)
        self.assertFalse(mock_pv.called)
        self.assertFalse(mock_icg.called)
        self.assertFalse(mock_cpg.called)
        self.assertFalse(mockccg.called)
        self.assertFalse(mock_vdg.called)
        self.assertFalse(mock_b64.called)
        self.assertFalse(mock_post.called)
        self.assertFalse(mock_b2s.called)
        self.assertFalse(mock_d2p.called)

    @patch("examples.ca_handler.asa_ca_handler.CAhandler._api_post")
    @patch("examples.ca_handler.asa_ca_handler.convert_byte_to_string")
    @patch("examples.ca_handler.asa_ca_handler.cert_der2pem")
    @patch("examples.ca_handler.asa_ca_handler.b64_decode")
    @patch("examples.ca_handler.asa_ca_handler.CAhandler._validity_dates_get")
    @patch("examples.ca_handler.asa_ca_handler.CAhandler._csr_cn_get")
    @patch("examples.ca_handler.asa_ca_handler.csr_pubkey_get")
    @patch("examples.ca_handler.asa_ca_handler.CAhandler._issuer_chain_get")
    @patch("examples.ca_handler.asa_ca_handler.CAhandler._profile_verify")
    @patch("examples.ca_handler.asa_ca_handler.CAhandler._issuer_verify")
    def test_048_enroll(
        self,
        mock_iv,
        mock_pv,
        mock_icg,
        mock_cpg,
        mockccg,
        mock_vdg,
        mock_b64,
        mock_d2p,
        mock_b2s,
        mock_post,
    ):
        """test enroll()"""
        mock_iv.return_value = None
        mock_pv.return_value = "mock_pv"
        mock_icg.return_value = "issuer_chain"
        mock_vdg.return_value = ("date1", "date2")
        mock_post.return_value = ("code", "cert")
        mock_b2s.return_value = "bcert"
        self.assertEqual(("mock_pv", None, None, None), self.cahandler.enroll("csr"))
        self.assertTrue(mock_iv.called)
        self.assertTrue(mock_pv.called)
        self.assertFalse(mock_icg.called)
        self.assertFalse(mock_cpg.called)
        self.assertFalse(mockccg.called)
        self.assertFalse(mock_vdg.called)
        self.assertFalse(mock_b64.called)
        self.assertFalse(mock_post.called)
        self.assertFalse(mock_b2s.called)
        self.assertFalse(mock_d2p.called)

    @patch("examples.ca_handler.asa_ca_handler.CAhandler._api_post")
    @patch("examples.ca_handler.asa_ca_handler.convert_byte_to_string")
    @patch("examples.ca_handler.asa_ca_handler.cert_der2pem")
    @patch("examples.ca_handler.asa_ca_handler.b64_decode")
    @patch("examples.ca_handler.asa_ca_handler.CAhandler._validity_dates_get")
    @patch("examples.ca_handler.asa_ca_handler.CAhandler._csr_cn_get")
    @patch("examples.ca_handler.asa_ca_handler.csr_pubkey_get")
    @patch("examples.ca_handler.asa_ca_handler.CAhandler._issuer_chain_get")
    @patch("examples.ca_handler.asa_ca_handler.CAhandler._profile_verify")
    @patch("examples.ca_handler.asa_ca_handler.CAhandler._issuer_verify")
    def test_049_enroll(
        self,
        mock_iv,
        mock_pv,
        mock_icg,
        mock_cpg,
        mockccg,
        mock_vdg,
        mock_b64,
        mock_d2p,
        mock_b2s,
        mock_post,
    ):
        """test enroll()"""
        mock_iv.return_value = None
        mock_pv.return_value = None
        mock_icg.return_value = "issuer_chain"
        mock_vdg.return_value = ("date1", "date2")
        mock_post.return_value = (500, "cert")
        mock_b2s.return_value = "bcert"
        self.assertEqual(
            ("Enrollment failed", None, None, None), self.cahandler.enroll("csr")
        )
        self.assertTrue(mock_iv.called)
        self.assertTrue(mock_pv.called)
        self.assertTrue(mock_icg.called)
        self.assertTrue(mock_cpg.called)
        self.assertTrue(mockccg.called)
        self.assertTrue(mock_vdg.called)
        self.assertFalse(mock_b64.called)
        self.assertTrue(mock_post.called)
        self.assertFalse(mock_b2s.called)
        self.assertFalse(mock_d2p.called)

    @patch("examples.ca_handler.asa_ca_handler.CAhandler._api_post")
    @patch("examples.ca_handler.asa_ca_handler.convert_byte_to_string")
    @patch("examples.ca_handler.asa_ca_handler.cert_der2pem")
    @patch("examples.ca_handler.asa_ca_handler.b64_decode")
    @patch("examples.ca_handler.asa_ca_handler.CAhandler._validity_dates_get")
    @patch("examples.ca_handler.asa_ca_handler.CAhandler._csr_cn_get")
    @patch("examples.ca_handler.asa_ca_handler.csr_pubkey_get")
    @patch("examples.ca_handler.asa_ca_handler.CAhandler._issuer_chain_get")
    @patch("examples.ca_handler.asa_ca_handler.CAhandler._profile_verify")
    @patch("examples.ca_handler.asa_ca_handler.CAhandler._issuer_verify")
    def test_050_enroll(
        self,
        mock_iv,
        mock_pv,
        mock_icg,
        mock_cpg,
        mockccg,
        mock_vdg,
        mock_b64,
        mock_d2p,
        mock_b2s,
        mock_post,
    ):
        """test enroll()"""
        mock_iv.return_value = None
        mock_pv.return_value = None
        mock_icg.return_value = "issuer_chain"
        mock_vdg.return_value = ("date1", "date2")
        mock_post.return_value = (500, "cert")
        mock_b2s.return_value = "bcert"
        mock_cpg.return_value = None
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.assertEqual(
                ("Enrollment failed", None, None, None), self.cahandler.enroll("csr")
            )
        self.assertIn(
            "ERROR:test_a2c:CAhandler._enrollment_dic_create(): public key not found",
            lcm.output,
        )
        self.assertTrue(mock_iv.called)
        self.assertTrue(mock_pv.called)
        self.assertTrue(mock_icg.called)
        self.assertTrue(mock_cpg.called)
        self.assertFalse(mockccg.called)
        self.assertFalse(mock_vdg.called)
        self.assertFalse(mock_b64.called)
        self.assertFalse(mock_post.called)
        self.assertFalse(mock_b2s.called)
        self.assertFalse(mock_d2p.called)

    @patch("examples.ca_handler.asa_ca_handler.CAhandler._api_post")
    @patch("examples.ca_handler.asa_ca_handler.cert_ski_get")
    def test_051_revoke(self, mock_ski, mock_post):
        """test revoke()"""
        self.cahandler.ca_name = "ca_name"
        mock_ski.return_value = "serial"
        mock_post.return_value = ("code", None)
        self.assertEqual(("code", None, None), self.cahandler.revoke("cert"))
        self.assertTrue(mock_ski.called)
        self.assertTrue(mock_post.called)

    @patch("examples.ca_handler.asa_ca_handler.CAhandler._api_post")
    @patch("examples.ca_handler.asa_ca_handler.cert_ski_get")
    def test_052_revoke(self, mock_ski, mock_post):
        """test revoke()"""
        self.cahandler.ca_name = "ca_name"
        mock_ski.return_value = "mock_ski"
        mock_post.return_value = ("code", {"message": "message"})
        self.assertEqual(
            ("code", "urn:ietf:params:acme:error:serverInternal", "message"),
            self.cahandler.revoke("cert"),
        )
        self.assertTrue(mock_ski.called)
        self.assertTrue(mock_post.called)

    @patch("examples.ca_handler.asa_ca_handler.CAhandler._api_post")
    @patch("examples.ca_handler.asa_ca_handler.cert_ski_get")
    def test_053_revoke(self, mock_ski, mock_post):
        """test revoke()"""
        self.cahandler.ca_name = "ca_name"
        mock_ski.return_value = "ski"
        mock_post.return_value = ("code", {"Message": "Message"})
        self.assertEqual(
            ("code", "urn:ietf:params:acme:error:serverInternal", "Message"),
            self.cahandler.revoke("cert"),
        )
        self.assertTrue(mock_ski.called)
        self.assertTrue(mock_post.called)

    @patch("examples.ca_handler.asa_ca_handler.CAhandler._api_post")
    @patch("examples.ca_handler.asa_ca_handler.cert_ski_get")
    def test_054_revoke(self, mock_ski, mock_post):
        """test revoke()"""
        self.cahandler.ca_name = "ca_name"
        mock_ski.return_value = "ski"
        mock_post.return_value = ("code", {"foo": "bar"})
        self.assertEqual(
            ("code", "urn:ietf:params:acme:error:serverInternal", "Unknown error"),
            self.cahandler.revoke("cert"),
        )
        self.assertTrue(mock_ski.called)
        self.assertTrue(mock_post.called)

    @patch.dict("os.environ", {"api_user_var": "user_var"})
    def test_055_config_user_load(self):
        """test _config_load - load template with user variable"""
        config_dic = {"api_user_variable": "api_user_var"}
        self.cahandler._config_user_load(config_dic)
        self.assertEqual("user_var", self.cahandler.api_user)
        self.assertFalse(self.cahandler.profile_name)

    @patch.dict("os.environ", {"api_user_var": "user_var"})
    def test_056_config_user_load(self):
        """test _config_load - load template with user variable"""
        config_dic = {"api_user_variable": "does_not_exist"}
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.cahandler._config_user_load(config_dic)
        self.assertFalse(self.cahandler.api_user)
        self.assertIn(
            "ERROR:test_a2c:CAhandler._config_user_load() could not load user_variable: does_not_exist",
            lcm.output,
        )
        self.assertFalse(self.cahandler.profile_name)

    @patch.dict("os.environ", {"api_user_var": "user_var"})
    def test_057_config_user_load(self):
        """test _config_load - load template with user variable"""
        config_dic = {"api_user_variable": "api_user_var", "api_user": "api_user"}
        self.cahandler._config_user_load(config_dic)
        # with self.assertLogs('test_a2c', level='INFO') as lcm:
        self.assertEqual("api_user", self.cahandler.api_user)
        # self.assertIn("foo", lcm.output)
        self.assertFalse(self.cahandler.profile_name)

    @patch.dict("os.environ", {"api_host_var": "host_var"})
    def test_058_config_host_load(self):
        """test _config_load - load template with host variable"""
        config_dic = {"api_host_variable": "api_host_var"}
        self.cahandler._config_host_load(config_dic)
        self.assertEqual("host_var", self.cahandler.api_host)
        self.assertFalse(self.cahandler.profile_name)

    @patch.dict("os.environ", {"api_host_var": "host_var"})
    def test_059_config_host_load(self):
        """test _config_load - load template with host variable"""
        config_dic = {"api_host_variable": "does_not_exist"}
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.cahandler._config_host_load(config_dic)
        self.assertFalse(self.cahandler.api_host)
        self.assertIn(
            "ERROR:test_a2c:CAhandler._config_host_load() could not load host_variable: does_not_exist",
            lcm.output,
        )
        self.assertFalse(self.cahandler.profile_name)

    @patch.dict("os.environ", {"api_host_var": "host_var"})
    def test_060_config_host_load(self):
        """test _config_load - load template with host variable"""
        config_dic = {"api_host_variable": "api_host_var", "api_host": "api_host"}
        self.cahandler._config_host_load(config_dic)
        # with self.assertLogs('test_a2c', level='INFO') as lcm:
        self.assertEqual("api_host", self.cahandler.api_host)
        # self.assertIn("foo", lcm.output)
        self.assertFalse(self.cahandler.profile_name)

    @patch.dict("os.environ", {"api_key_var": "key_var"})
    def test_061_config_key_load(self):
        """test _config_load - load template with key variable"""
        config_dic = {"api_key_variable": "api_key_var"}
        self.cahandler._config_key_load(config_dic)
        self.assertEqual("key_var", self.cahandler.api_key)
        self.assertFalse(self.cahandler.profile_name)

    @patch.dict("os.environ", {"api_key_var": "key_var"})
    def test_062_config_key_load(self):
        """test _config_load - load template with key variable"""
        config_dic = {"api_key_variable": "does_not_exist"}
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.cahandler._config_key_load(config_dic)
        self.assertFalse(self.cahandler.api_key)
        self.assertIn(
            "ERROR:test_a2c:CAhandler._config_key_load() could not load key_variable: does_not_exist",
            lcm.output,
        )
        self.assertFalse(self.cahandler.profile_name)

    @patch.dict("os.environ", {"api_key_var": "key_var"})
    def test_063_config_key_load(self):
        """test _config_load - load template with key variable"""
        config_dic = {"api_key_variable": "api_key_var", "api_key": "api_key"}
        self.cahandler._config_key_load(config_dic)
        # with self.assertLogs('test_a2c', level='INFO') as lcm:
        self.assertEqual("api_key", self.cahandler.api_key)
        # self.assertIn("foo", lcm.output)
        self.assertFalse(self.cahandler.profile_name)

    @patch.dict("os.environ", {"api_password_var": "password_var"})
    def test_064_config_password_load(self):
        """test _config_load - load template with password variable"""
        config_dic = {"api_password_variable": "api_password_var"}
        self.cahandler._config_password_load(config_dic)
        self.assertEqual("password_var", self.cahandler.api_password)
        self.assertFalse(self.cahandler.profile_name)

    @patch.dict("os.environ", {"api_password_var": "password_var"})
    def test_065_config_password_load(self):
        """test _config_load - load template with password variable"""
        config_dic = {"api_password_variable": "does_not_exist"}
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.cahandler._config_password_load(config_dic)
        self.assertFalse(self.cahandler.api_password)
        self.assertIn(
            "ERROR:test_a2c:CAhandler._config_password_load() could not load password_variable: does_not_exist",
            lcm.output,
        )
        self.assertFalse(self.cahandler.profile_name)

    @patch.dict("os.environ", {"api_password_var": "password_var"})
    def test_066_config_password_load(self):
        """test _config_load - load template with password variable"""
        config_dic = {
            "api_password_variable": "api_password_var",
            "api_password": "api_password",
        }
        self.cahandler._config_password_load(config_dic)
        # with self.assertLogs('test_a2c', level='INFO') as lcm:
        self.assertEqual("api_password", self.cahandler.api_password)
        # self.assertIn("foo", lcm.output)
        self.assertFalse(self.cahandler.profile_name)

    @patch("examples.ca_handler.asa_ca_handler.CAhandler._validity_dates_get")
    @patch("examples.ca_handler.asa_ca_handler.CAhandler._csr_cn_get")
    @patch("examples.ca_handler.asa_ca_handler.csr_pubkey_get")
    def test_067_enrollment_dic_create(self, mock_pkg, mock_ccg, mock_vdg):
        """test _enrollment_dic_create()"""
        mock_pkg.return_value = "pubkey"
        mock_ccg.return_value = "cn"
        mock_vdg.return_value = ("date1", "date2")
        result = {
            "publicKey": "pubkey",
            "profileName": None,
            "issuerName": None,
            "cn": "cn",
            "notBefore": "date1",
            "notAfter": "date2",
        }
        self.assertEqual(result, self.cahandler._enrollment_dic_create("csr"))


if __name__ == "__main__":

    unittest.main()
