#!/usr/bin/python
# -*- coding: utf-8 -*-
"""unittests for openxpki_ca_handler"""
# pylint: disable=C0415, R0904, W0212
import sys
import os
import unittest
from unittest.mock import patch, mock_open, Mock, MagicMock
import requests
import base64
from OpenSSL import crypto
import configparser

sys.path.insert(0, ".")
sys.path.insert(1, "..")


class FakeDBStore(object):
    """face DBStore class needed for mocking"""

    # pylint: disable=W0107, R0903
    pass


class TestACMEHandler(unittest.TestCase):
    """test class for cgi_handler"""

    def setUp(self):
        """setup unittest"""
        models_mock = MagicMock()
        models_mock.acme_srv.db_handler.DBstore.return_value = FakeDBStore
        modules = {"acme_srv.db_handler": models_mock}
        patch.dict("sys.modules", modules).start()
        import logging
        from examples.ca_handler.entrust_ca_handler import CAhandler

        logging.basicConfig(level=logging.CRITICAL)
        self.logger = logging.getLogger("test_a2c")
        self.cahandler = CAhandler(False, self.logger)
        self.dir_path = os.path.dirname(os.path.realpath(__file__))

    def test_001_default(self):
        """default test which always passes"""
        self.assertEqual("foo", "foo")

    @patch("examples.ca_handler.entrust_ca_handler.CAhandler._config_load")
    def test_002__enter__(self, mock_cfg):
        """test enter  called"""
        mock_cfg.return_value = True
        self.cahandler.__enter__()
        self.assertTrue(mock_cfg.called)

    @patch("examples.ca_handler.entrust_ca_handler.CAhandler._config_load")
    def test_003__enter__(self, mock_cfg):
        """test enter api hosts defined"""
        mock_cfg.return_value = True
        self.cahandler.session = "session"
        self.cahandler.__enter__()
        self.assertFalse(mock_cfg.called)

    def test_004_poll(self):
        """test polling"""
        self.assertEqual(
            ("Method not implemented.", None, None, "poll_identifier", False),
            self.cahandler.poll("cert_name", "poll_identifier", "csr"),
        )

    def test_005_trigger(self):
        """test polling"""
        self.assertEqual(
            ("Method not implemented.", None, None), self.cahandler.trigger("payload")
        )

    def test_006__api_post(self):
        """test _api_post()"""
        mockresponse = Mock()
        mockresponse2 = Mock()
        mockresponse2.status_code = "status_code"
        mockresponse2.text = "foo"
        mockresponse2.json = lambda: {"foo": "bar"}
        mockresponse = Mock()
        mockresponse.post.side_effect = [mockresponse2]
        self.cahandler.session = mockresponse
        self.assertEqual(
            ("status_code", {"foo": "bar"}), self.cahandler._api_post("url", "data")
        )

    def test_007__api_post(self):
        """test _api_post()"""
        mockresponse2 = Mock()
        mockresponse2.status_code = "status_code"
        mockresponse2.text = "foo"
        mockresponse2.json.side_effect = Exception("ex_json")
        mockresponse = Mock()
        mockresponse.post.side_effect = [mockresponse2]
        self.cahandler.session = mockresponse
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.assertEqual(
                ("status_code", "ex_json"), self.cahandler._api_post("url", "data")
            )
        self.assertIn(
            "ERROR:test_a2c:Request_operation returned error during json parsing: ex_json",
            lcm.output,
        )

    def test_008__api_post(self):
        """test _api_post()"""
        mockresponse2 = Mock()
        mockresponse2.status_code = "status_code"
        mockresponse2.text = None
        mockresponse2.json = lambda: {"foo": "bar"}
        mockresponse = Mock()
        mockresponse.post.side_effect = [mockresponse2]
        self.cahandler.session = mockresponse
        self.assertEqual(("status_code", None), self.cahandler._api_post("url", "data"))

    def test_009__api_post(self):
        """test _api_post(="""
        mockresponse = Mock()
        mockresponse.post.side_effect = [Exception("exc_api_post")]
        self.cahandler.session = mockresponse
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.assertEqual(
                (500, "exc_api_post"), self.cahandler._api_post("url", "data")
            )
        self.assertIn(
            "ERROR:test_a2c:Request_operation returned error: exc_api_post", lcm.output
        )

    def test_010__api_get(self):
        """test _api_get()"""
        mockresponse2 = Mock()
        mockresponse2.status_code = "status_code"
        mockresponse2.text = "foo"
        mockresponse2.json = lambda: {"foo": "bar"}
        mockresponse = Mock()
        mockresponse.get.side_effect = [mockresponse2]
        self.cahandler.session = mockresponse
        self.assertEqual(
            ("status_code", {"foo": "bar"}), self.cahandler._api_get("url")
        )

    def test_011__api_get(self):
        """test _api_get()"""
        mockresponse2 = Mock()
        mockresponse2.status_code = "status_code"
        mockresponse2.text = "foo"
        mockresponse2.json.side_effect = Exception("ex_json")
        mockresponse = Mock()
        mockresponse.get.side_effect = [mockresponse2]
        self.cahandler.session = mockresponse
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.assertEqual(("status_code", "ex_json"), self.cahandler._api_get("url"))
        self.assertIn(
            "ERROR:test_a2c:Request_operation returned error during json parsing: ex_json",
            lcm.output,
        )

    def test_012__api_get(self):
        """test _api_get()"""
        mockresponse = Mock()
        mockresponse.get.side_effect = [Exception("exc_api_get")]
        self.cahandler.session = mockresponse
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.assertEqual((500, "exc_api_get"), self.cahandler._api_get("url"))
        self.assertIn(
            "ERROR:test_a2c:Request_operation returned error: exc_api_get", lcm.output
        )

    def test_013__api_put(self):
        """test _api_put()"""
        mockresponse = Mock()
        mockresponse2 = Mock()
        mockresponse2.status_code = "status_code"
        mockresponse2.text = "foo"
        mockresponse2.json = lambda: {"foo": "bar"}
        mockresponse = Mock()
        mockresponse.put.side_effect = [mockresponse2]
        self.cahandler.session = mockresponse
        self.assertEqual(
            ("status_code", {"foo": "bar"}), self.cahandler._api_put("url", "data")
        )

    def test_014__api_put(self):
        """test _api_put()"""
        mockresponse2 = Mock()
        mockresponse2.status_code = "status_code"
        mockresponse2.text = "foo"
        mockresponse2.json.side_effect = Exception("ex_json")
        mockresponse = Mock()
        mockresponse.put.side_effect = [mockresponse2]
        self.cahandler.session = mockresponse
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.assertEqual(
                ("status_code", "ex_json"), self.cahandler._api_put("url", "data")
            )
        self.assertIn(
            "ERROR:test_a2c:Request_operation returned error during json parsing: ex_json",
            lcm.output,
        )

    def test_015__api_put(self):
        """test _api_put()"""
        mockresponse2 = Mock()
        mockresponse2.status_code = "foo"
        mockresponse2.text = None
        mockresponse2.json = lambda: {"foo": "bar"}
        mockresponse = Mock()
        mockresponse.put.side_effect = [mockresponse2]
        self.cahandler.session = mockresponse
        self.assertEqual(("foo", None), self.cahandler._api_put("url", "data"))

    def test_016__api_put(self):
        """test _api_put()"""
        mockresponse = Mock()
        mockresponse.put.side_effect = Exception("exc_api_put")
        self.cahandler.session = mockresponse
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.assertEqual(
                (500, "exc_api_put"), self.cahandler._api_put("url", "data")
            )
        self.assertIn(
            "ERROR:test_a2c:Request_operation returned error: exc_api_put", lcm.output
        )

    @patch("examples.ca_handler.entrust_ca_handler.CAhandler._api_get")
    def test_017_certificates_get_from_serial(self, mock_api):
        """test certificates_get_from_serial"""
        mock_api.return_value = (200, {"certificates": ["foo", "bar"]})
        self.assertEqual(
            ["foo", "bar"], self.cahandler._certificates_get_from_serial("serial")
        )

    @patch("examples.ca_handler.entrust_ca_handler.CAhandler._api_get")
    def test_018_certificates_get_from_serial(self, mock_api):
        """test certificates_get_from_serial"""
        mock_api.return_value = (300, {"certificates": ["foo", "bar"]})
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.assertFalse(self.cahandler._certificates_get_from_serial("serial"))
        self.assertIn(
            "ERROR:test_a2c:Certificate lookup based on serial number failed for serial with code: 300",
            lcm.output,
        )

    @patch("examples.ca_handler.entrust_ca_handler.CAhandler._api_get")
    def test_019_certificates_get_from_serial(self, mock_api):
        """test certificates_get_from_serial"""
        mock_api.return_value = (200, {"certificates1": ["foo", "bar"]})
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.assertFalse(self.cahandler._certificates_get_from_serial("serial"))
        self.assertIn(
            "ERROR:test_a2c:Certificate lookup based on serial number failed for serial with code: 200",
            lcm.output,
        )

    @patch("examples.ca_handler.entrust_ca_handler.CAhandler._api_get")
    def test_020_certificates_get_from_serial(self, mock_api):
        """test certificates_get_from_serial"""
        mock_api.return_value = (200, {"certificates": ["foo", "bar"]})
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.assertEqual(
                ["foo", "bar"], self.cahandler._certificates_get_from_serial("0serial")
            )
        self.assertIn(
            "INFO:test_a2c:Remove leading zeros from serial number",
            lcm.output,
        )

    @patch("examples.ca_handler.entrust_ca_handler.config_headerinfo_load")
    @patch("examples.ca_handler.entrust_ca_handler.config_eab_profile_load")
    @patch("examples.ca_handler.entrust_ca_handler.CAhandler._config_root_load")
    @patch("examples.ca_handler.entrust_ca_handler.CAhandler._config_session_load")
    @patch("examples.ca_handler.entrust_ca_handler.load_config")
    def test_021_config_load(
        self, mock_load, mock_session, mock_root, mock_eab, mock_header
    ):
        """test load_config()"""
        parser = configparser.ConfigParser()
        # parser['CAhandler'] = {'foo': 'bar'}
        mock_load.return_value = parser
        mock_eab.return_value = (True, "handler")
        mock_header.return_value = "hil"
        self.cahandler._config_load()
        self.assertFalse(mock_session.called)
        self.assertFalse(mock_root.called)
        self.assertTrue(mock_eab.called)
        self.assertTrue(mock_header.called)
        self.assertEqual(
            "https://api.entrust.net/enterprise/v2", self.cahandler.api_url
        )
        self.assertEqual(10, self.cahandler.request_timeout)
        self.assertEqual("handler", self.cahandler.eab_handler)
        self.assertTrue(self.cahandler.eab_profiling)
        self.assertEqual(365, self.cahandler.cert_validity_days)
        self.assertFalse(self.cahandler.username)
        self.assertFalse(self.cahandler.password)
        self.assertFalse(self.cahandler.organization_name)
        self.assertEqual("STANDARD_SSL", self.cahandler.certtype)
        self.assertFalse(self.cahandler.allowed_domainlist)
        self.assertEqual("hil", self.cahandler.header_info_field)

    @patch("examples.ca_handler.entrust_ca_handler.config_headerinfo_load")
    @patch("examples.ca_handler.entrust_ca_handler.config_eab_profile_load")
    @patch("examples.ca_handler.entrust_ca_handler.CAhandler._config_root_load")
    @patch("examples.ca_handler.entrust_ca_handler.CAhandler._config_session_load")
    @patch("examples.ca_handler.entrust_ca_handler.load_config")
    def test_022_config_load(
        self, mock_load, mock_session, mock_root, mock_eab, mock_header
    ):
        """test load_config()"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"foo": "bar"}
        mock_load.return_value = parser
        mock_eab.return_value = (True, "handler")
        mock_header.return_value = "hil"
        self.cahandler._config_load()
        self.assertTrue(mock_session.called)
        self.assertTrue(mock_root.called)
        self.assertTrue(mock_eab.called)
        self.assertTrue(mock_header.called)
        self.assertEqual(
            "https://api.entrust.net/enterprise/v2", self.cahandler.api_url
        )
        self.assertEqual(10, self.cahandler.request_timeout)
        self.assertEqual("handler", self.cahandler.eab_handler)
        self.assertTrue(self.cahandler.eab_profiling)
        self.assertEqual(365, self.cahandler.cert_validity_days)
        self.assertFalse(self.cahandler.username)
        self.assertFalse(self.cahandler.password)
        self.assertFalse(self.cahandler.organization_name)
        self.assertEqual("STANDARD_SSL", self.cahandler.certtype)
        self.assertFalse(self.cahandler.allowed_domainlist)
        self.assertEqual("hil", self.cahandler.header_info_field)

    @patch("examples.ca_handler.entrust_ca_handler.config_headerinfo_load")
    @patch("examples.ca_handler.entrust_ca_handler.config_eab_profile_load")
    @patch("examples.ca_handler.entrust_ca_handler.CAhandler._config_root_load")
    @patch("examples.ca_handler.entrust_ca_handler.CAhandler._config_session_load")
    @patch("examples.ca_handler.entrust_ca_handler.load_config")
    def test_023_config_load(
        self, mock_load, mock_session, mock_root, mock_eab, mock_header
    ):
        """test load_config()"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"api_url": "api_url", "foo": "bar"}
        mock_load.return_value = parser
        mock_eab.return_value = (True, "handler")
        mock_header.return_value = "hil"
        self.cahandler._config_load()
        self.assertTrue(mock_session.called)
        self.assertTrue(mock_root.called)
        self.assertTrue(mock_eab.called)
        self.assertTrue(mock_header.called)
        self.assertEqual("api_url", self.cahandler.api_url)
        self.assertEqual(10, self.cahandler.request_timeout)
        self.assertEqual("handler", self.cahandler.eab_handler)
        self.assertTrue(self.cahandler.eab_profiling)
        self.assertEqual(365, self.cahandler.cert_validity_days)
        self.assertFalse(self.cahandler.username)
        self.assertFalse(self.cahandler.password)
        self.assertFalse(self.cahandler.organization_name)
        self.assertEqual("STANDARD_SSL", self.cahandler.certtype)
        self.assertFalse(self.cahandler.allowed_domainlist)
        self.assertEqual("hil", self.cahandler.header_info_field)

    @patch("examples.ca_handler.entrust_ca_handler.config_headerinfo_load")
    @patch("examples.ca_handler.entrust_ca_handler.config_eab_profile_load")
    @patch("examples.ca_handler.entrust_ca_handler.CAhandler._config_root_load")
    @patch("examples.ca_handler.entrust_ca_handler.CAhandler._config_session_load")
    @patch("examples.ca_handler.entrust_ca_handler.load_config")
    def test_024_config_load(
        self, mock_load, mock_session, mock_root, mock_eab, mock_header
    ):
        """test load_config()"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"request_timeout": "15", "foo": "bar"}
        mock_load.return_value = parser
        mock_eab.return_value = (True, "handler")
        mock_header.return_value = "hil"
        self.cahandler._config_load()
        self.assertTrue(mock_session.called)
        self.assertTrue(mock_root.called)
        self.assertTrue(mock_eab.called)
        self.assertTrue(mock_header.called)
        self.assertEqual(
            "https://api.entrust.net/enterprise/v2", self.cahandler.api_url
        )
        self.assertEqual(15, self.cahandler.request_timeout)
        self.assertEqual("handler", self.cahandler.eab_handler)
        self.assertTrue(self.cahandler.eab_profiling)
        self.assertEqual(365, self.cahandler.cert_validity_days)
        self.assertFalse(self.cahandler.username)
        self.assertFalse(self.cahandler.password)
        self.assertFalse(self.cahandler.organization_name)
        self.assertEqual("STANDARD_SSL", self.cahandler.certtype)
        self.assertFalse(self.cahandler.allowed_domainlist)
        self.assertEqual("hil", self.cahandler.header_info_field)

    @patch("examples.ca_handler.entrust_ca_handler.config_headerinfo_load")
    @patch("examples.ca_handler.entrust_ca_handler.config_eab_profile_load")
    @patch("examples.ca_handler.entrust_ca_handler.CAhandler._config_root_load")
    @patch("examples.ca_handler.entrust_ca_handler.CAhandler._config_session_load")
    @patch("examples.ca_handler.entrust_ca_handler.load_config")
    def test_025_config_load(
        self, mock_load, mock_session, mock_root, mock_eab, mock_header
    ):
        """test load_config()"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"request_timeout": "aa", "foo": "bar"}
        mock_load.return_value = parser
        mock_eab.return_value = (True, "handler")
        mock_header.return_value = "hil"
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.cahandler._config_load()
        self.assertIn(
            "ERROR:test_a2c:Failed to parse request_timeout parameter: invalid literal for int() with base 10: 'aa'",
            lcm.output,
        )
        self.assertTrue(mock_session.called)
        self.assertTrue(mock_root.called)
        self.assertTrue(mock_eab.called)
        self.assertTrue(mock_header.called)
        self.assertEqual(
            "https://api.entrust.net/enterprise/v2", self.cahandler.api_url
        )
        self.assertEqual(10, self.cahandler.request_timeout)
        self.assertEqual("handler", self.cahandler.eab_handler)
        self.assertTrue(self.cahandler.eab_profiling)
        self.assertEqual(365, self.cahandler.cert_validity_days)
        self.assertFalse(self.cahandler.username)
        self.assertFalse(self.cahandler.password)
        self.assertFalse(self.cahandler.organization_name)
        self.assertEqual("STANDARD_SSL", self.cahandler.certtype)
        self.assertFalse(self.cahandler.allowed_domainlist)
        self.assertEqual("hil", self.cahandler.header_info_field)

    @patch("examples.ca_handler.entrust_ca_handler.config_headerinfo_load")
    @patch("examples.ca_handler.entrust_ca_handler.config_eab_profile_load")
    @patch("examples.ca_handler.entrust_ca_handler.CAhandler._config_root_load")
    @patch("examples.ca_handler.entrust_ca_handler.CAhandler._config_session_load")
    @patch("examples.ca_handler.entrust_ca_handler.load_config")
    def test_026_config_load(
        self, mock_load, mock_session, mock_root, mock_eab, mock_header
    ):
        """test load_config()"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"cert_validity_days": "10", "foo": "bar"}
        mock_load.return_value = parser
        mock_eab.return_value = (True, "handler")
        mock_header.return_value = "hil"
        self.cahandler._config_load()
        self.assertTrue(mock_session.called)
        self.assertTrue(mock_root.called)
        self.assertTrue(mock_eab.called)
        self.assertTrue(mock_header.called)
        self.assertEqual(
            "https://api.entrust.net/enterprise/v2", self.cahandler.api_url
        )
        self.assertEqual(10, self.cahandler.request_timeout)
        self.assertEqual("handler", self.cahandler.eab_handler)
        self.assertTrue(self.cahandler.eab_profiling)
        self.assertEqual(10, self.cahandler.cert_validity_days)
        self.assertFalse(self.cahandler.username)
        self.assertFalse(self.cahandler.password)
        self.assertFalse(self.cahandler.organization_name)
        self.assertEqual("STANDARD_SSL", self.cahandler.certtype)
        self.assertFalse(self.cahandler.allowed_domainlist)
        self.assertEqual("hil", self.cahandler.header_info_field)

    @patch("examples.ca_handler.entrust_ca_handler.config_headerinfo_load")
    @patch("examples.ca_handler.entrust_ca_handler.config_eab_profile_load")
    @patch("examples.ca_handler.entrust_ca_handler.CAhandler._config_root_load")
    @patch("examples.ca_handler.entrust_ca_handler.CAhandler._config_session_load")
    @patch("examples.ca_handler.entrust_ca_handler.load_config")
    def test_027_config_load(
        self, mock_load, mock_session, mock_root, mock_eab, mock_header
    ):
        """test load_config()"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"cert_validity_days": "aa", "foo": "bar"}
        mock_load.return_value = parser
        mock_eab.return_value = (True, "handler")
        mock_header.return_value = "hil"
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.cahandler._config_load()
        self.assertIn(
            "ERROR:test_a2c:Failed to parse cert_validity_days invalid literal for int() with base 10: 'aa' parameter",
            lcm.output,
        )
        self.assertTrue(mock_session.called)
        self.assertTrue(mock_root.called)
        self.assertTrue(mock_eab.called)
        self.assertTrue(mock_header.called)
        self.assertEqual(
            "https://api.entrust.net/enterprise/v2", self.cahandler.api_url
        )
        self.assertEqual(10, self.cahandler.request_timeout)
        self.assertEqual("handler", self.cahandler.eab_handler)
        self.assertTrue(self.cahandler.eab_profiling)
        self.assertEqual(365, self.cahandler.cert_validity_days)
        self.assertFalse(self.cahandler.username)
        self.assertFalse(self.cahandler.password)
        self.assertFalse(self.cahandler.organization_name)
        self.assertEqual("STANDARD_SSL", self.cahandler.certtype)
        self.assertFalse(self.cahandler.allowed_domainlist)
        self.assertEqual("hil", self.cahandler.header_info_field)

    @patch("examples.ca_handler.entrust_ca_handler.config_headerinfo_load")
    @patch("examples.ca_handler.entrust_ca_handler.config_eab_profile_load")
    @patch("examples.ca_handler.entrust_ca_handler.CAhandler._config_root_load")
    @patch("examples.ca_handler.entrust_ca_handler.CAhandler._config_session_load")
    @patch("examples.ca_handler.entrust_ca_handler.load_config")
    def test_028_config_load(
        self, mock_load, mock_session, mock_root, mock_eab, mock_header
    ):
        """test load_config()"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"username": "username", "foo": "bar"}
        mock_load.return_value = parser
        mock_eab.return_value = (True, "handler")
        mock_header.return_value = "hil"
        self.cahandler._config_load()
        self.assertTrue(mock_session.called)
        self.assertTrue(mock_root.called)
        self.assertTrue(mock_eab.called)
        self.assertTrue(mock_header.called)
        self.assertEqual(
            "https://api.entrust.net/enterprise/v2", self.cahandler.api_url
        )
        self.assertEqual(10, self.cahandler.request_timeout)
        self.assertEqual("handler", self.cahandler.eab_handler)
        self.assertTrue(self.cahandler.eab_profiling)
        self.assertEqual(365, self.cahandler.cert_validity_days)
        self.assertEqual("username", self.cahandler.username)
        self.assertFalse(self.cahandler.password)
        self.assertFalse(self.cahandler.organization_name)
        self.assertEqual("STANDARD_SSL", self.cahandler.certtype)
        self.assertFalse(self.cahandler.allowed_domainlist)
        self.assertEqual("hil", self.cahandler.header_info_field)

    @patch("examples.ca_handler.entrust_ca_handler.config_headerinfo_load")
    @patch("examples.ca_handler.entrust_ca_handler.config_eab_profile_load")
    @patch("examples.ca_handler.entrust_ca_handler.CAhandler._config_root_load")
    @patch("examples.ca_handler.entrust_ca_handler.CAhandler._config_session_load")
    @patch("examples.ca_handler.entrust_ca_handler.load_config")
    def test_029_config_load(
        self, mock_load, mock_session, mock_root, mock_eab, mock_header
    ):
        """test load_config()"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"password": "password", "foo": "bar"}
        mock_load.return_value = parser
        mock_eab.return_value = (True, "handler")
        mock_header.return_value = "hil"
        self.cahandler._config_load()
        self.assertTrue(mock_session.called)
        self.assertTrue(mock_root.called)
        self.assertTrue(mock_eab.called)
        self.assertTrue(mock_header.called)
        self.assertEqual(
            "https://api.entrust.net/enterprise/v2", self.cahandler.api_url
        )
        self.assertEqual(10, self.cahandler.request_timeout)
        self.assertEqual("handler", self.cahandler.eab_handler)
        self.assertTrue(self.cahandler.eab_profiling)
        self.assertEqual(365, self.cahandler.cert_validity_days)
        self.assertFalse(self.cahandler.username)
        self.assertEqual("password", self.cahandler.password)
        self.assertFalse(self.cahandler.organization_name)
        self.assertEqual("STANDARD_SSL", self.cahandler.certtype)
        self.assertFalse(self.cahandler.allowed_domainlist)
        self.assertEqual("hil", self.cahandler.header_info_field)

    @patch("examples.ca_handler.entrust_ca_handler.config_headerinfo_load")
    @patch("examples.ca_handler.entrust_ca_handler.config_eab_profile_load")
    @patch("examples.ca_handler.entrust_ca_handler.CAhandler._config_root_load")
    @patch("examples.ca_handler.entrust_ca_handler.CAhandler._config_session_load")
    @patch("examples.ca_handler.entrust_ca_handler.load_config")
    def test_030_config_load(
        self, mock_load, mock_session, mock_root, mock_eab, mock_header
    ):
        """test load_config()"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"organization_name": "organization_name", "foo": "bar"}
        mock_load.return_value = parser
        mock_eab.return_value = (True, "handler")
        mock_header.return_value = "hil"
        self.cahandler._config_load()
        self.assertTrue(mock_session.called)
        self.assertTrue(mock_root.called)
        self.assertTrue(mock_eab.called)
        self.assertTrue(mock_header.called)
        self.assertEqual(
            "https://api.entrust.net/enterprise/v2", self.cahandler.api_url
        )
        self.assertEqual(10, self.cahandler.request_timeout)
        self.assertEqual("handler", self.cahandler.eab_handler)
        self.assertTrue(self.cahandler.eab_profiling)
        self.assertEqual(365, self.cahandler.cert_validity_days)
        self.assertFalse(self.cahandler.username)
        self.assertFalse(self.cahandler.password)
        self.assertEqual("organization_name", self.cahandler.organization_name)
        self.assertEqual("STANDARD_SSL", self.cahandler.certtype)
        self.assertFalse(self.cahandler.allowed_domainlist)
        self.assertEqual("hil", self.cahandler.header_info_field)

    @patch("examples.ca_handler.entrust_ca_handler.config_headerinfo_load")
    @patch("examples.ca_handler.entrust_ca_handler.config_eab_profile_load")
    @patch("examples.ca_handler.entrust_ca_handler.CAhandler._config_root_load")
    @patch("examples.ca_handler.entrust_ca_handler.CAhandler._config_session_load")
    @patch("examples.ca_handler.entrust_ca_handler.load_config")
    def test_031_config_load(
        self, mock_load, mock_session, mock_root, mock_eab, mock_header
    ):
        """test load_config()"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"certtype": "certtype", "foo": "bar"}
        mock_load.return_value = parser
        mock_eab.return_value = (True, "handler")
        mock_header.return_value = "hil"
        self.cahandler._config_load()
        self.assertTrue(mock_session.called)
        self.assertTrue(mock_root.called)
        self.assertTrue(mock_eab.called)
        self.assertTrue(mock_header.called)
        self.assertEqual(
            "https://api.entrust.net/enterprise/v2", self.cahandler.api_url
        )
        self.assertEqual(10, self.cahandler.request_timeout)
        self.assertEqual("handler", self.cahandler.eab_handler)
        self.assertTrue(self.cahandler.eab_profiling)
        self.assertEqual(365, self.cahandler.cert_validity_days)
        self.assertFalse(self.cahandler.username)
        self.assertFalse(self.cahandler.password)
        self.assertFalse(self.cahandler.organization_name)
        self.assertEqual("certtype", self.cahandler.certtype)
        self.assertFalse(self.cahandler.allowed_domainlist)
        self.assertEqual("hil", self.cahandler.header_info_field)

    @patch("examples.ca_handler.entrust_ca_handler.config_headerinfo_load")
    @patch("examples.ca_handler.entrust_ca_handler.config_eab_profile_load")
    @patch("examples.ca_handler.entrust_ca_handler.CAhandler._config_root_load")
    @patch("examples.ca_handler.entrust_ca_handler.CAhandler._config_session_load")
    @patch("examples.ca_handler.entrust_ca_handler.load_config")
    def test_032_config_load(
        self, mock_load, mock_session, mock_root, mock_eab, mock_header
    ):
        """test load_config()"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"allowed_domainlist": '["foo", "bar"]', "foo": "bar"}
        mock_load.return_value = parser
        mock_eab.return_value = (True, "handler")
        mock_header.return_value = "hil"
        self.cahandler._config_load()
        self.assertTrue(mock_session.called)
        self.assertTrue(mock_root.called)
        self.assertTrue(mock_eab.called)
        self.assertTrue(mock_header.called)
        self.assertEqual(
            "https://api.entrust.net/enterprise/v2", self.cahandler.api_url
        )
        self.assertEqual(10, self.cahandler.request_timeout)
        self.assertEqual("handler", self.cahandler.eab_handler)
        self.assertTrue(self.cahandler.eab_profiling)
        self.assertEqual(365, self.cahandler.cert_validity_days)
        self.assertFalse(self.cahandler.username)
        self.assertFalse(self.cahandler.password)
        self.assertFalse(self.cahandler.organization_name)
        self.assertEqual("STANDARD_SSL", self.cahandler.certtype)
        self.assertEqual(["foo", "bar"], self.cahandler.allowed_domainlist)
        self.assertEqual("hil", self.cahandler.header_info_field)

    @patch("examples.ca_handler.entrust_ca_handler.config_headerinfo_load")
    @patch("examples.ca_handler.entrust_ca_handler.config_eab_profile_load")
    @patch("examples.ca_handler.entrust_ca_handler.CAhandler._config_root_load")
    @patch("examples.ca_handler.entrust_ca_handler.CAhandler._config_session_load")
    @patch("examples.ca_handler.entrust_ca_handler.load_config")
    def test_033_config_load(
        self, mock_load, mock_session, mock_root, mock_eab, mock_header
    ):
        """test load_config()"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"allowed_domainlist": "bar", "foo": "bar"}
        mock_load.return_value = parser
        mock_eab.return_value = (True, "handler")
        mock_header.return_value = "hil"
        self.cahandler._config_load()
        self.assertTrue(mock_session.called)
        self.assertTrue(mock_root.called)
        self.assertTrue(mock_eab.called)
        self.assertTrue(mock_header.called)
        self.assertEqual(
            "https://api.entrust.net/enterprise/v2", self.cahandler.api_url
        )
        self.assertEqual(10, self.cahandler.request_timeout)
        self.assertEqual("handler", self.cahandler.eab_handler)
        self.assertTrue(self.cahandler.eab_profiling)
        self.assertEqual(365, self.cahandler.cert_validity_days)
        self.assertFalse(self.cahandler.username)
        self.assertFalse(self.cahandler.password)
        self.assertFalse(self.cahandler.organization_name)
        self.assertEqual("STANDARD_SSL", self.cahandler.certtype)
        self.assertEqual("failed to parse", self.cahandler.allowed_domainlist)
        self.assertEqual("hil", self.cahandler.header_info_field)

    @patch.dict("os.environ", {"cert_passphrase_var": "user_var"})
    def test_034_config_passphrase_load(self):
        """test _config_load - load template with user variable"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"cert_passphrase_variable": "cert_passphrase_var"}
        self.cahandler._config_passphrase_load(parser)
        self.assertEqual("user_var", self.cahandler.cert_passphrase)

    @patch.dict("os.environ", {"cert_passphrase_var": "user_var"})
    def test_035_config_passphrase_load(self):
        """test _config_load - load template with user variable"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"cert_passphrase_variable": "does_not_exist"}
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.cahandler._config_passphrase_load(parser)
        self.assertFalse(self.cahandler.cert_passphrase)
        self.assertIn(
            "ERROR:test_a2c:Could not load cert_passphrase_variable:'does_not_exist'",
            lcm.output,
        )

    @patch.dict("os.environ", {"cert_passphrase_var": "user_var"})
    def test_036_config_passphrase_load(self):
        """test _config_load - load template with user variable"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {
            "cert_passphrase_variable": "cert_passphrase_var",
            "cert_passphrase": "cert_passphrase",
        }
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.cahandler._config_passphrase_load(parser)
        self.assertIn(
            "INFO:test_a2c:Overwrite cert_passphrase",
            lcm.output,
        )
        self.assertEqual("cert_passphrase", self.cahandler.cert_passphrase)

    @patch("builtins.open", mock_open(read_data="cert"), create=True)
    @patch("os.path.isfile")
    def test_037_config_root_load(self, mock_file):
        """_config_root_load()"""
        mock_file.return_value = True
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"entrust_root_cert": "root_cert"}
        self.cahandler._config_root_load(parser)
        self.assertEqual("cert", self.cahandler.entrust_root_cert)

    @patch("builtins.open", mock_open(read_data="cert"), create=True)
    @patch("os.path.isfile")
    def test_038_config_root_load(self, mock_file):
        """_config_root_load()"""
        mock_file.return_value = False
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"entrust_root_cert": "root_cert"}
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.cahandler._config_root_load(parser)
        self.assertIn(
            "ERROR:test_a2c:Root CA file configured but not not found. Using default one.",
            lcm.output,
        )
        self.assertIn("290IENlcnRpZmljYXRpb24g", self.cahandler.entrust_root_cert)

    @patch("builtins.open", mock_open(read_data="cert"), create=True)
    @patch("os.path.isfile")
    def test_039_config_root_load(self, mock_file):
        """_config_root_load()"""
        mock_file.return_value = False
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"unk": "root_cert"}
        self.cahandler._config_root_load(parser)
        self.assertIn("290IENlcnRpZmljYXRpb24g", self.cahandler.entrust_root_cert)

    @patch("examples.ca_handler.entrust_ca_handler.CAhandler._config_passphrase_load")
    def test_040_config_session_load(self, mock_sl):
        """_config_session_load()"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"client_cert": "client_cert", "client_key": "client_key"}
        self.cahandler._config_session_load(parser)
        self.assertFalse(mock_sl.called)
        self.assertTrue(self.cahandler.session)

    @patch("examples.ca_handler.entrust_ca_handler.requests.Session")
    @patch("examples.ca_handler.entrust_ca_handler.Pkcs12Adapter")
    @patch("examples.ca_handler.entrust_ca_handler.CAhandler._config_passphrase_load")
    def test_041_config_session_load(self, mock_sl, mock_pkcs12, mock_session):
        """_config_session_load()"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"client_cert": "client_cert"}
        mock_session.return_value.__enter__.return_value = Mock()
        self.cahandler.cert_passphrase = "cert_passphrase"
        self.cahandler._config_session_load(parser)
        self.assertTrue(mock_sl.called)
        self.assertTrue(self.cahandler.session)
        self.assertTrue(mock_pkcs12.called)

    @patch("examples.ca_handler.entrust_ca_handler.requests.Session")
    @patch("examples.ca_handler.entrust_ca_handler.Pkcs12Adapter")
    @patch("examples.ca_handler.entrust_ca_handler.CAhandler._config_passphrase_load")
    def test_042_config_session_load(self, mock_sl, mock_pkcs12, mock_session):
        """_config_session_load()"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"foo": "client_cert"}
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.cahandler._config_session_load(parser)
        self.assertTrue(mock_sl.called)
        self.assertTrue(self.cahandler.session)
        self.assertIn(
            'WARNING:test_a2c:Configuration might be incomplete: "client_cert", "client_key" or "client_passphrase[_variable]" parameter is missing in config file',
            lcm.output,
        )
        self.assertFalse(mock_pkcs12.called)

    @patch("examples.ca_handler.entrust_ca_handler.CAhandler._domains_get")
    @patch("examples.ca_handler.entrust_ca_handler.CAhandler._organizations_get")
    def test_043_org_domain_cfg_check(self, mock_org, mock_domain):
        """test _org_domain_cfg_check()"""
        mock_org.return_value = []
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.assertEqual(
                "Organization None not found in Entrust API",
                self.cahandler._org_domain_cfg_check(),
            )
        self.assertTrue(mock_org.called)
        self.assertFalse(mock_domain.called)

    @patch("examples.ca_handler.entrust_ca_handler.CAhandler._domains_get")
    @patch("examples.ca_handler.entrust_ca_handler.CAhandler._organizations_get")
    def test_044_org_domain_cfg_check(self, mock_org, mock_domain):
        """test _org_domain_cfg_check()"""
        mock_org.return_value = {"foo": 1, "bar": 2}
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.assertEqual(
                "Organization None not found in Entrust API",
                self.cahandler._org_domain_cfg_check(),
            )
        self.assertTrue(mock_org.called)
        self.assertFalse(mock_domain.called)

    @patch("examples.ca_handler.entrust_ca_handler.CAhandler._domains_get")
    @patch("examples.ca_handler.entrust_ca_handler.CAhandler._organizations_get")
    def test_045_org_domain_cfg_check(self, mock_org, mock_domain):
        """test _org_domain_cfg_check()"""
        mock_org.return_value = {"foo": 1, "bar": 2}
        mock_domain.return_value = ["foo1", "foo2"]
        self.cahandler.organization_name = "foo1"
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.assertEqual(
                "Organization foo1 not found in Entrust API",
                self.cahandler._org_domain_cfg_check(),
            )
        self.assertTrue(mock_org.called)
        self.assertFalse(mock_domain.called)

    @patch("examples.ca_handler.entrust_ca_handler.CAhandler._domains_get")
    @patch("examples.ca_handler.entrust_ca_handler.CAhandler._organizations_get")
    def test_046_org_domain_cfg_check(self, mock_org, mock_domain):
        """test _org_domain_cfg_check()"""
        mock_org.return_value = {"foo": 1, "bar": 2}
        mock_domain.return_value = ["foo1", "foo2"]
        self.cahandler.organization_name = "foo"
        self.assertFalse(self.cahandler._org_domain_cfg_check())
        self.assertTrue(mock_org.called)
        self.assertTrue(mock_domain.called)
        self.assertEqual(["foo1", "foo2"], self.cahandler.allowed_domainlist)

    @patch("examples.ca_handler.entrust_ca_handler.CAhandler._domains_get")
    @patch("examples.ca_handler.entrust_ca_handler.CAhandler._organizations_get")
    def test_047_org_domain_cfg_check(self, mock_org, mock_domain):
        """test _org_domain_cfg_check()"""
        mock_org.return_value = {"foo": 1, "bar": 2}
        mock_domain.return_value = ["foo1", "foo2"]
        self.cahandler.organization_name = "foo"
        self.cahandler.allowed_domainlist = ["foo3", "foo4"]
        self.assertFalse(self.cahandler._org_domain_cfg_check())
        self.assertTrue(mock_org.called)
        self.assertTrue(mock_domain.called)
        self.assertEqual(["foo3", "foo4"], self.cahandler.allowed_domainlist)

    @patch("examples.ca_handler.entrust_ca_handler.CAhandler._api_get")
    def test_048__organizations_get(self, mock_api):
        """test _organizations_get()"""
        mock_api.return_value = (500, "foo")
        self.cahandler.organization_name = "organization_name"
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.cahandler._organizations_get()
        self.assertIn(
            "ERROR:test_a2c:Malformed response while getting the organization list from API",
            lcm.output,
        )

    @patch("examples.ca_handler.entrust_ca_handler.CAhandler._api_get")
    def test_049__organizations_get(self, mock_api):
        """test _organizations_get()"""
        input_dic = {
            "organizations": [
                {"verificationStatus": "APPROVED", "name": "foo", "clientId": 1},
                {"verificationStatus": "APPROVED", "name": "bar", "clientId": 2},
            ]
        }
        mock_api.return_value = (200, input_dic)
        self.cahandler.organization_name = "organization_name"
        self.assertEqual({"foo": 1, "bar": 2}, self.cahandler._organizations_get())

    @patch("examples.ca_handler.entrust_ca_handler.CAhandler._api_get")
    def test_050__organizations_get(self, mock_api):
        """test _organizations_get()"""
        input_dic = {
            "organizations": [
                {"verificationStatus": "NOTAPPROVED", "name": "foo", "clientId": 1},
                {"verificationStatus": "APPROVED", "name": "bar", "clientId": 2},
            ]
        }
        mock_api.return_value = (200, input_dic)
        self.cahandler.organization_name = "organization_name"
        self.assertEqual({"bar": 2}, self.cahandler._organizations_get())

    @patch("examples.ca_handler.entrust_ca_handler.CAhandler._api_get")
    def test_051__organizations_get(self, mock_api):
        """test _organizations_get()"""
        input_dic = {
            "organizations": [
                {"name": "foo", "clientId": 1},
                {"verificationStatus": "APPROVED", "name": "bar", "clientId": 2},
            ]
        }
        mock_api.return_value = (200, input_dic)
        self.cahandler.organization_name = "organization_name"
        self.assertEqual({"bar": 2}, self.cahandler._organizations_get())

    @patch("examples.ca_handler.entrust_ca_handler.CAhandler._api_get")
    def test_052__organizations_get(self, mock_api):
        """test _organizations_get()"""
        input_dic = {
            "organizations": [
                {"verificationStatus": "APPROVED", "_name": "foo", "_clientId": 1},
                {"verificationStatus": "APPROVED", "name": "bar", "clientId": 2},
            ]
        }
        mock_api.return_value = (200, input_dic)
        self.cahandler.organization_name = "organization_name"
        self.assertEqual({"bar": 2}, self.cahandler._organizations_get())

    @patch("examples.ca_handler.entrust_ca_handler.CAhandler._api_get")
    def test_053__domains_get(self, mock_api):
        """test _organizations_get()"""
        mock_api.return_value = (500, "foo")
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.cahandler._domains_get(1)
        self.assertIn(
            "ERROR:test_a2c:Malformed response while getting the domain list from API",
            lcm.output,
        )

    @patch("examples.ca_handler.entrust_ca_handler.CAhandler._api_get")
    def test_054__domains_get(self, mock_api):
        """test _organizations_get()"""
        input_dic = {
            "domains": [
                {
                    "verificationStatus": "APPROVED",
                    "domainName": "foo.bar",
                    "clientId": 1,
                },
                {
                    "verificationStatus": "APPROVED",
                    "domainName": "bar.foo",
                    "clientId": 2,
                },
            ]
        }
        mock_api.return_value = (200, input_dic)
        self.assertEqual(["foo.bar", "bar.foo"], self.cahandler._domains_get(1))

    @patch("examples.ca_handler.entrust_ca_handler.CAhandler._api_get")
    def test_055__domains_get(self, mock_api):
        """test _organizations_get()"""
        input_dic = {
            "domains": [
                {
                    "verificationStatus": "NOTAPPROVED",
                    "domainName": "foo.bar",
                    "clientId": 1,
                },
                {
                    "verificationStatus": "APPROVED",
                    "domainName": "bar.foo",
                    "clientId": 2,
                },
            ]
        }
        mock_api.return_value = (200, input_dic)
        self.assertEqual(["bar.foo"], self.cahandler._domains_get(1))

    @patch("examples.ca_handler.entrust_ca_handler.CAhandler._api_get")
    def test_056__domains_get(self, mock_api):
        """test _organizations_get()"""
        input_dic = {
            "domains": [
                {"Status": "APPROVED", "domainName": "foo.bar", "clientId": 1},
                {
                    "verificationStatus": "APPROVED",
                    "domainName": "bar.foo",
                    "clientId": 2,
                },
            ]
        }
        mock_api.return_value = (200, input_dic)
        self.assertEqual(["bar.foo"], self.cahandler._domains_get(1))

    @patch("examples.ca_handler.entrust_ca_handler.CAhandler._api_get")
    def test_057__domains_get(self, mock_api):
        """test _organizations_get()"""
        input_dic = {
            "domains": [
                {"verificationStatus": "APPROVED", "Name": "foo.bar", "clientId": 1},
                {
                    "verificationStatus": "APPROVED",
                    "domainName": "bar.foo",
                    "clientId": 2,
                },
            ]
        }
        mock_api.return_value = (200, input_dic)
        self.assertEqual(["bar.foo"], self.cahandler._domains_get(1))

    @patch("examples.ca_handler.entrust_ca_handler.CAhandler._api_get")
    def test_058_credential_check(self, mock_api):
        """test _organizations_get()"""
        mock_api.return_value = (500, "foo")
        self.assertEqual(
            "Connection to Entrust API failed: foo", self.cahandler.credential_check()
        )

    @patch("examples.ca_handler.entrust_ca_handler.CAhandler._api_get")
    def test_059_credential_check(self, mock_api):
        """test _organizations_get()"""
        mock_api.return_value = (200, "foo")
        self.assertFalse(self.cahandler.credential_check())

    def test_060_oonfig_check(self):
        """test _config_check()"""
        self.cahandler.api_url = None
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.cahandler._config_check()
        self.assertIn(
            "ERROR:test_a2c:Configuration check ended with error: api_url parameter in missing in config file",
            lcm.output,
        )

    def test_061_oonfig_check(self):
        """test _config_check()"""
        self.cahandler.api_url = "api_url"
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.cahandler._config_check()
        self.assertIn(
            "ERROR:test_a2c:Configuration check ended with error: username parameter in missing in config file",
            lcm.output,
        )

    def test_062_oonfig_check(self):
        """test _config_check()"""
        self.cahandler.api_url = "api_url"
        self.cahandler.username = "username"
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.cahandler._config_check()
        self.assertIn(
            "ERROR:test_a2c:Configuration check ended with error: password parameter in missing in config file",
            lcm.output,
        )

    def test_063_oonfig_check(self):
        """test _config_check()"""
        self.cahandler.api_url = "api_url"
        self.cahandler.username = "username"
        self.cahandler.password = "password"
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.cahandler._config_check()
        self.assertIn(
            "ERROR:test_a2c:Configuration check ended with error: organization_name parameter in missing in config file",
            lcm.output,
        )

    def test_064_oonfig_check(self):
        """test _config_check()"""
        self.cahandler.api_url = "api_url"
        self.cahandler.username = "username"
        self.cahandler.password = "password"
        self.cahandler.organization_name = "organization_name"
        self.assertFalse(self.cahandler._config_check())

    @patch("examples.ca_handler.entrust_ca_handler.allowed_domainlist_check")
    @patch("examples.ca_handler.entrust_ca_handler.CAhandler._org_domain_cfg_check")
    @patch("examples.ca_handler.entrust_ca_handler.CAhandler.credential_check")
    @patch("examples.ca_handler.entrust_ca_handler.CAhandler._config_check")
    @patch("examples.ca_handler.entrust_ca_handler.eab_profile_header_info_check")
    def test_065_enroll_check(
        self, mock_eab, mock_config, mock_credential, mock_org, mock_domain
    ):
        """test _enroll_check()"""
        mock_eab.return_value = "mock_eab_error"
        mock_config.return_value = "mock_config_error"
        mock_credential.return_value = "mock_credential_error"
        mock_org.return_value = "mock_org_error"
        mock_domain.return_value = "mock_domain_error"
        self.assertEqual("mock_eab_error", self.cahandler._enroll_check("csr"))
        self.assertTrue(mock_eab.called)
        self.assertFalse(mock_config.called)
        self.assertFalse(mock_credential.called)
        self.assertFalse(mock_org.called)
        self.assertFalse(mock_domain.called)

    @patch("examples.ca_handler.entrust_ca_handler.allowed_domainlist_check")
    @patch("examples.ca_handler.entrust_ca_handler.CAhandler._org_domain_cfg_check")
    @patch("examples.ca_handler.entrust_ca_handler.CAhandler.credential_check")
    @patch("examples.ca_handler.entrust_ca_handler.CAhandler._config_check")
    @patch("examples.ca_handler.entrust_ca_handler.eab_profile_header_info_check")
    def test_066_enroll_check(
        self, mock_eab, mock_config, mock_credential, mock_org, mock_domain
    ):
        """test _enroll_check()"""
        mock_eab.return_value = False
        mock_config.return_value = "mock_config_error"
        mock_credential.return_value = "mock_credential_error"
        mock_org.return_value = "mock_org_error"
        mock_domain.return_value = "mock_domain_error"
        self.assertEqual("mock_config_error", self.cahandler._enroll_check("csr"))
        self.assertTrue(mock_eab.called)
        self.assertTrue(mock_config.called)
        self.assertFalse(mock_credential.called)
        self.assertFalse(mock_org.called)
        self.assertFalse(mock_domain.called)

    @patch("examples.ca_handler.entrust_ca_handler.allowed_domainlist_check")
    @patch("examples.ca_handler.entrust_ca_handler.CAhandler._org_domain_cfg_check")
    @patch("examples.ca_handler.entrust_ca_handler.CAhandler.credential_check")
    @patch("examples.ca_handler.entrust_ca_handler.CAhandler._config_check")
    @patch("examples.ca_handler.entrust_ca_handler.eab_profile_header_info_check")
    def test_067_enroll_check(
        self, mock_eab, mock_config, mock_credential, mock_org, mock_domain
    ):
        """test _enroll_check()"""
        mock_eab.return_value = False
        mock_config.return_value = False
        mock_credential.return_value = "mock_credential_error"
        mock_org.return_value = False
        mock_domain.return_value = False
        self.assertEqual("mock_credential_error", self.cahandler._enroll_check("csr"))
        self.assertTrue(mock_eab.called)
        self.assertTrue(mock_config.called)
        self.assertTrue(mock_credential.called)
        self.assertTrue(mock_org.called)
        self.assertTrue(mock_domain.called)

    @patch("examples.ca_handler.entrust_ca_handler.allowed_domainlist_check")
    @patch("examples.ca_handler.entrust_ca_handler.CAhandler._org_domain_cfg_check")
    @patch("examples.ca_handler.entrust_ca_handler.CAhandler.credential_check")
    @patch("examples.ca_handler.entrust_ca_handler.CAhandler._config_check")
    @patch("examples.ca_handler.entrust_ca_handler.eab_profile_header_info_check")
    def test_068_enroll_check(
        self, mock_eab, mock_config, mock_credential, mock_org, mock_domain
    ):
        """test _enroll_check()"""
        mock_eab.return_value = False
        mock_config.return_value = False
        mock_credential.return_value = False
        mock_org.return_value = "mock_org_error"
        mock_domain.return_value = "mock_domain_error"
        self.assertEqual("mock_org_error", self.cahandler._enroll_check("csr"))
        self.assertTrue(mock_eab.called)
        self.assertTrue(mock_config.called)
        self.assertTrue(mock_org.called)
        self.assertFalse(mock_domain.called)
        self.assertFalse(mock_credential.called)

    @patch("examples.ca_handler.entrust_ca_handler.allowed_domainlist_check")
    @patch("examples.ca_handler.entrust_ca_handler.CAhandler._org_domain_cfg_check")
    @patch("examples.ca_handler.entrust_ca_handler.CAhandler.credential_check")
    @patch("examples.ca_handler.entrust_ca_handler.CAhandler._config_check")
    @patch("examples.ca_handler.entrust_ca_handler.eab_profile_header_info_check")
    def test_069_enroll_check(
        self, mock_eab, mock_config, mock_credential, mock_org, mock_domain
    ):
        """test _enroll_check()"""
        mock_eab.return_value = False
        mock_config.return_value = False
        mock_credential.return_value = False
        mock_org.return_value = False
        mock_domain.return_value = "mock_domain_error"
        self.assertEqual("mock_domain_error", self.cahandler._enroll_check("csr"))
        self.assertTrue(mock_eab.called)
        self.assertTrue(mock_org.called)
        self.assertTrue(mock_domain.called)
        self.assertTrue(mock_config.called)
        self.assertFalse(mock_credential.called)

    @patch(
        "examples.ca_handler.entrust_ca_handler.CAhandler._certificates_get_from_serial"
    )
    @patch("examples.ca_handler.entrust_ca_handler.cert_serial_get")
    @patch("examples.ca_handler.entrust_ca_handler.header_info_get")
    def test_070__trackingid_get(self, mock_header, mock_serial, mock_cert):
        """test _trackingid_get()"""
        mock_header.return_value = [
            {"poll_identifier": "tracking_id"},
            {"poll_identifier": "tracking_id2"},
        ]
        self.assertEqual("tracking_id", self.cahandler._trackingid_get("csr"))
        self.assertFalse(mock_serial.called)
        self.assertFalse(mock_cert.called)

    @patch(
        "examples.ca_handler.entrust_ca_handler.CAhandler._certificates_get_from_serial"
    )
    @patch("examples.ca_handler.entrust_ca_handler.cert_serial_get")
    @patch("examples.ca_handler.entrust_ca_handler.header_info_get")
    def test_071__trackingid_get(self, mock_header, mock_serial, mock_cert):
        """test _trackingid_get()"""
        mock_header.return_value = [
            {"identifier": "tracking_id1"},
            {"poll_identifier": "tracking_id2"},
        ]
        self.assertEqual("tracking_id2", self.cahandler._trackingid_get("csr"))
        self.assertFalse(mock_serial.called)
        self.assertFalse(mock_cert.called)

    @patch(
        "examples.ca_handler.entrust_ca_handler.CAhandler._certificates_get_from_serial"
    )
    @patch("examples.ca_handler.entrust_ca_handler.cert_serial_get")
    @patch("examples.ca_handler.entrust_ca_handler.header_info_get")
    def test_072__trackingid_get(self, mock_header, mock_serial, mock_cert):
        """test _trackingid_get()"""
        mock_header.return_value = []
        mock_serial.return_value = "serial"
        mock_cert.return_value = [{"trackingId": "tracking_id"}]
        self.assertEqual("tracking_id", self.cahandler._trackingid_get("csr"))
        self.assertTrue(mock_serial.called)
        self.assertTrue(mock_cert.called)

    @patch(
        "examples.ca_handler.entrust_ca_handler.CAhandler._certificates_get_from_serial"
    )
    @patch("examples.ca_handler.entrust_ca_handler.cert_serial_get")
    @patch("examples.ca_handler.entrust_ca_handler.header_info_get")
    def test_073__trackingid_get(self, mock_header, mock_serial, mock_cert):
        """test _trackingid_get()"""
        mock_header.return_value = []
        mock_serial.return_value = "serial"
        mock_cert.return_value = [{"id": "tracking_id"}]
        self.assertFalse(self.cahandler._trackingid_get("csr"))
        self.assertTrue(mock_serial.called)
        self.assertTrue(mock_cert.called)

    @patch(
        "examples.ca_handler.entrust_ca_handler.CAhandler._certificates_get_from_serial"
    )
    @patch("examples.ca_handler.entrust_ca_handler.cert_serial_get")
    @patch("examples.ca_handler.entrust_ca_handler.header_info_get")
    def test_074__trackingid_get(self, mock_header, mock_serial, mock_cert):
        """test _trackingid_get()"""
        mock_header.return_value = []
        mock_serial.return_value = "serial"
        mock_cert.return_value = [
            {"id": "tracking_id1"},
            {"trackingId": "tracking_id2"},
        ]
        self.assertEqual("tracking_id2", self.cahandler._trackingid_get("csr"))
        self.assertTrue(mock_serial.called)
        self.assertTrue(mock_cert.called)

    @patch("examples.ca_handler.entrust_ca_handler.b64_encode")
    @patch("examples.ca_handler.entrust_ca_handler.cert_pem2der")
    def test_075_response_parse(self, mock_der, mock_enc):
        """test _rsponse_parse()"""
        mock_der.return_value = "cert_data"
        mock_enc.return_value = "mock_enc"
        self.cahandler.entrust_root_cert = "root_cert"
        response = {
            "trackingId": "trackingId",
            "endEntityCert": "endEntityCert",
            "chainCerts": ["foo1", "foo2"],
        }
        self.assertEqual(
            ("foo1\nfoo2\nroot_cert\n", "mock_enc", "trackingId"),
            self.cahandler._response_parse(response),
        )
        self.assertTrue(mock_der.called)
        self.assertTrue(mock_enc.called)

    @patch("examples.ca_handler.entrust_ca_handler.b64_encode")
    @patch("examples.ca_handler.entrust_ca_handler.cert_pem2der")
    def test_076_response_parse(self, mock_der, mock_enc):
        """test _rsponse_parse()"""
        mock_der.return_value = "cert_data"
        mock_enc.return_value = "mock_enc"
        self.cahandler.entrust_root_cert = "root_cert"
        response = {
            "falsetrackingId": "trackingId",
            "endEntityCert": "endEntityCert",
            "chainCerts": ["foo1", "foo2"],
        }
        self.assertEqual(
            ("foo1\nfoo2\nroot_cert\n", "mock_enc", None),
            self.cahandler._response_parse(response),
        )
        self.assertTrue(mock_der.called)
        self.assertTrue(mock_enc.called)

    @patch("examples.ca_handler.entrust_ca_handler.b64_encode")
    @patch("examples.ca_handler.entrust_ca_handler.cert_pem2der")
    def test_077_response_parse(self, mock_der, mock_enc):
        """test _rsponse_parse()"""
        mock_der.return_value = "cert_data"
        mock_enc.return_value = "mock_enc"
        self.cahandler.entrust_root_cert = "root_cert"
        response = {
            "trackingId": "trackingId",
            "endEntityCert": "endEntityCert",
            "Certs": ["foo1", "foo2"],
        }
        self.assertEqual(
            (None, None, "trackingId"), self.cahandler._response_parse(response)
        )
        self.assertFalse(mock_der.called)
        self.assertFalse(mock_enc.called)

    @patch("examples.ca_handler.entrust_ca_handler.b64_encode")
    @patch("examples.ca_handler.entrust_ca_handler.cert_pem2der")
    def test_078_response_parse(self, mock_der, mock_enc):
        """test _rsponse_parse()"""
        mock_der.return_value = "cert_data"
        mock_enc.return_value = "mock_enc"
        self.cahandler.entrust_root_cert = "root_cert"
        response = {
            "trackingId": "trackingId",
            "EntityCert": "endEntityCert",
            "chainCerts": ["foo1", "foo2"],
        }
        self.assertEqual(
            (None, None, "trackingId"), self.cahandler._response_parse(response)
        )
        self.assertFalse(mock_der.called)
        self.assertFalse(mock_enc.called)

    @patch("examples.ca_handler.entrust_ca_handler.b64_encode")
    @patch("examples.ca_handler.entrust_ca_handler.cert_pem2der")
    def test_079_response_parse(self, mock_der, mock_enc):
        """test _rsponse_parse()"""
        mock_der.return_value = "cert_data"
        mock_enc.return_value = "mock_enc"
        self.cahandler.entrust_root_cert = "root_cert"
        response = {
            "trackingId": "trackingId",
            "endEntityCert": "endEntityCert",
            "chainCerts": [],
        }
        self.assertEqual(
            ("root_cert\n", "mock_enc", "trackingId"),
            self.cahandler._response_parse(response),
        )
        self.assertTrue(mock_der.called)
        self.assertTrue(mock_enc.called)

    @patch("examples.ca_handler.entrust_ca_handler.enrollment_config_log")
    @patch("examples.ca_handler.entrust_ca_handler.CAhandler._response_parse")
    @patch("examples.ca_handler.entrust_ca_handler.csr_cn_lookup")
    @patch("examples.ca_handler.entrust_ca_handler.CAhandler._api_post")
    def test_080_enroll(self, mock_req, mock_cn, mock_parse, mock_ecl):
        """test _enroll()"""
        mock_cn.return_value = "cn"
        mock_req.return_value = (201, "response")
        mock_parse.return_value = ("cert_bundle", "cert_raw", "poll_indentifier")
        self.assertEqual(
            (None, "cert_bundle", "cert_raw", "poll_indentifier"),
            self.cahandler._enroll("csr"),
        )
        self.assertTrue(mock_cn.called)
        self.assertTrue(mock_req.called)
        self.assertTrue(mock_parse.called)
        self.assertFalse(mock_ecl.called)

    @patch("examples.ca_handler.entrust_ca_handler.CAhandler._response_parse")
    @patch("examples.ca_handler.entrust_ca_handler.csr_cn_lookup")
    @patch("examples.ca_handler.entrust_ca_handler.CAhandler._api_post")
    def test_081_enroll(self, mock_req, mock_cn, mock_parse):
        """test _enroll()"""
        mock_cn.return_value = "cn"
        mock_req.return_value = (404, "response")
        mock_parse.return_value = ("cert_bundle", "cert_raw", "poll_indentifier")
        self.assertEqual(
            ("Error during order creation: 404 - response", None, None, None),
            self.cahandler._enroll("csr"),
        )
        self.assertTrue(mock_cn.called)
        self.assertTrue(mock_req.called)
        self.assertFalse(mock_parse.called)

    @patch("examples.ca_handler.entrust_ca_handler.CAhandler._response_parse")
    @patch("examples.ca_handler.entrust_ca_handler.csr_cn_lookup")
    @patch("examples.ca_handler.entrust_ca_handler.CAhandler._api_post")
    def test_082_enroll(self, mock_req, mock_cn, mock_parse):
        """test _enroll()"""
        mock_cn.return_value = "cn"
        mock_req.return_value = (404, {"errors": "response, response2"})
        mock_parse.return_value = ("cert_bundle", "cert_raw", "poll_indentifier")
        self.assertEqual(
            (
                "Error during order creation: 404 - response, response2",
                None,
                None,
                None,
            ),
            self.cahandler._enroll("csr"),
        )
        self.assertTrue(mock_cn.called)
        self.assertTrue(mock_req.called)
        self.assertFalse(mock_parse.called)

    @patch("examples.ca_handler.entrust_ca_handler.enrollment_config_log")
    @patch("examples.ca_handler.entrust_ca_handler.CAhandler._response_parse")
    @patch("examples.ca_handler.entrust_ca_handler.csr_cn_lookup")
    @patch("examples.ca_handler.entrust_ca_handler.CAhandler._api_post")
    def test_083_enroll(self, mock_req, mock_cn, mock_parse, mock_ecl):
        """test _enroll()"""
        mock_cn.return_value = "cn"
        mock_req.return_value = (201, "response")
        mock_parse.return_value = ("cert_bundle", "cert_raw", "poll_indentifier")
        self.cahandler.enrollment_config_log = True
        self.assertEqual(
            (None, "cert_bundle", "cert_raw", "poll_indentifier"),
            self.cahandler._enroll("csr"),
        )
        self.assertTrue(mock_cn.called)
        self.assertTrue(mock_req.called)
        self.assertTrue(mock_parse.called)
        self.assertTrue(mock_ecl.called)

    @patch("examples.ca_handler.entrust_ca_handler.CAhandler._enroll")
    @patch("examples.ca_handler.entrust_ca_handler.CAhandler._enroll_check")
    def test_084_enroll(self, mock_chk, mock_enroll):
        """test enroll()"""
        mock_chk.return_value = None
        mock_enroll.return_value = ("mock_err", "mock_bundle", "mock_raw", "mock_poll")
        self.assertEqual(
            ("mock_err", "mock_bundle", "mock_raw", "mock_poll"),
            self.cahandler.enroll("csr"),
        )

    @patch("examples.ca_handler.entrust_ca_handler.CAhandler._enroll")
    @patch("examples.ca_handler.entrust_ca_handler.CAhandler._enroll_check")
    def test_085_enroll(self, mock_chk, mock_enroll):
        """test enroll()"""
        mock_chk.return_value = "mock_chk"
        mock_enroll.return_value = ("mock_err", "mock_bundle", "mock_raw", "mock_poll")
        self.assertEqual(("mock_chk", None, None, None), self.cahandler.enroll("csr"))

    @patch("examples.ca_handler.entrust_ca_handler.CAhandler._api_post")
    @patch("examples.ca_handler.entrust_ca_handler.CAhandler._trackingid_get")
    def test_086_revoke(self, mock_track, mock_req):
        """test revoke()"""
        mock_track.return_value = "tracking_id"
        mock_req.return_value = (200, "response")
        self.assertEqual(
            (200, "Certificate revoked", None), self.cahandler.revoke("csr")
        )

    @patch("examples.ca_handler.entrust_ca_handler.CAhandler._api_post")
    @patch("examples.ca_handler.entrust_ca_handler.CAhandler._trackingid_get")
    def test_087_revoke(self, mock_track, mock_req):
        """test revoke()"""
        mock_track.return_value = "tracking_id"
        mock_req.return_value = (500, "response")
        self.assertEqual(
            (500, "urn:ietf:params:acme:error:serverInternal", "response"),
            self.cahandler.revoke("csr"),
        )

    @patch("examples.ca_handler.entrust_ca_handler.CAhandler._api_post")
    @patch("examples.ca_handler.entrust_ca_handler.CAhandler._trackingid_get")
    def test_088_revoke(self, mock_track, mock_req):
        """test revoke()"""
        mock_track.return_value = None
        mock_req.return_value = (200, "response")
        self.assertEqual(
            (
                500,
                "urn:ietf:params:acme:error:serverInternal",
                "Failed to get tracking id",
            ),
            self.cahandler.revoke("csr"),
        )

    @patch("examples.ca_handler.entrust_ca_handler.CAhandler._api_get")
    def test_089_certificates_get(self, mock_req):
        """test certificates_get()"""
        mock_req.return_value = (500, "response")
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.assertFalse(self.cahandler.certificates_get())
        self.assertIn(
            "ERROR:test_a2c:Getting certificate data failed with code: 500",
            lcm.output,
        )

    @patch("examples.ca_handler.entrust_ca_handler.CAhandler._api_get")
    def test_090_certificates_get(self, mock_req):
        """test certificates_get()"""
        content = {"certificates": [1, 2, 3, 4], "summary": {"total": 4}}
        mock_req.return_value = (200, content)
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.assertEqual([1, 2, 3, 4], self.cahandler.certificates_get())
        self.assertIn(
            "INFO:test_a2c:fetching certs offset: 0, limit: 200, total: 1, buffered: 0",
            lcm.output,
        )

    @patch("examples.ca_handler.entrust_ca_handler.CAhandler._api_get")
    def test_091_certificates_get(self, mock_req):
        """test certificates_get()"""
        response1 = (200, {"certificates": [1, 2, 3, 4], "summary": {"total": 8}})
        response2 = (200, {"certificates": [5, 6, 7, 8]})
        mock_req.side_effect = [response1, response2]
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.assertEqual(
                [1, 2, 3, 4, 5, 6, 7, 8], self.cahandler.certificates_get()
            )
        self.assertIn(
            "INFO:test_a2c:fetching certs offset: 0, limit: 200, total: 1, buffered: 0",
            lcm.output,
        )
        self.assertIn(
            "INFO:test_a2c:fetching certs offset: 200, limit: 200, total: 8, buffered: 4",
            lcm.output,
        )

    @patch("examples.ca_handler.entrust_ca_handler.CAhandler._api_get")
    def test_092_certificates_get(self, mock_req):
        """test certificates_get()"""
        response1 = (200, {"certificates": [1, 2, 3, 4]})
        response2 = (200, {"certificates": [5, 6, 7, 8]})
        mock_req.side_effect = [response1, response2]
        with self.assertRaises(Exception) as err:
            self.assertFalse(self.cahandler.certificates_get())
        self.assertEqual(
            "Certificates lookup failed: did not get any total value",
            str(err.exception),
        )

    @patch("examples.ca_handler.entrust_ca_handler.CAhandler._api_get")
    def test_093_certificates_get(self, mock_req):
        """test certificates_get()"""
        response1 = (200, {"certificates": [1, 2, 3, 4], "summary": {"total": 9}})
        response2 = (200, {"certificates": [5, 6, 7, 8]})
        response3 = (200, {"certificates": [5, 6, 7, 8]})
        mock_req.side_effect = [response1, response2, response3]
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.assertEqual(
                [1, 2, 3, 4, 5, 6, 7, 8], self.cahandler.certificates_get()
            )
        self.assertIn(
            "INFO:test_a2c:fetching certs offset: 0, limit: 200, total: 1, buffered: 0",
            lcm.output,
        )
        self.assertIn(
            "INFO:test_a2c:fetching certs offset: 200, limit: 200, total: 9, buffered: 4",
            lcm.output,
        )
        self.assertIn(
            "INFO:test_a2c:fetching certs offset: 400, limit: 200, total: 9, buffered: 8",
            lcm.output,
        )
        self.assertIn(
            "INFO:test_a2c:Could not get get new certificate data in loop. Stopping the loop.",
            lcm.output,
        )


if __name__ == "__main__":

    unittest.main()
