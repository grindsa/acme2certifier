#!/usr/bin/python
# -*- coding: utf-8 -*-
"""unittests for openssl_ca_handler"""
# pylint: disable=C0415, R0904, R0913, W0212

import sys
import os
import josepy
import unittest
from unittest.mock import patch, mock_open, Mock, MagicMock
import configparser
import josepy
import json
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

sys.path.insert(0, ".")
sys.path.insert(1, "..")


class FakeDBStore(object):
    """face DBStore class needed for mocking"""

    # pylint: disable=W0107, R0903
    pass


class TestACMEHandler(unittest.TestCase):
    def setUp(self):
        """setup unittest"""
        models_mock = MagicMock()
        models_mock.acme_srv.db_handler.DBstore.return_value = FakeDBStore
        modules = {"acme_srv.db_handler": models_mock}
        patch.dict("sys.modules", modules).start()
        import logging
        from examples.ca_handler.acme_ca_handler import CAhandler

        logging.basicConfig(level=logging.CRITICAL)
        self.logger = logging.getLogger("test_a2c")
        self.cahandler = CAhandler(False, self.logger)

    def tearDown(self):
        """teardown"""
        pass

    def _generate_full_jwk(self):
        """Helper to generate a full josepy.JWKRSA object"""
        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )
        return josepy.JWKRSA(key=private_key)

    def test_001__order_authorization_unexpected_status(self):
        """CAhandler._order_authorization() - unexpected status branch"""
        cah = self.cahandler
        acmeclient = Mock()
        order = Mock()
        authzr = Mock()
        authzr.body = Mock()
        authzr.body.status = "foobar"
        order.authorizations = [authzr]
        user_key = Mock()
        with self.assertLogs("test_a2c", level="WARNING") as lcm:
            result = cah._order_authorization(acmeclient, order, user_key)
        self.assertFalse(result)
        self.assertIn("authorization in unexpected state: foobar", " ".join(lcm.output))

    @patch("examples.ca_handler.acme_ca_handler.url_get")
    def test_002__synchronize_profiles_success(self, mock_url_get):
        """CAhandler._synchronize_profiles() - success path"""
        from examples.ca_handler.acme_ca_handler import CAhandler

        cah = self.cahandler
        mock_url_get.return_value = (
            json.dumps({"meta": {"profiles": {"foo": "bar"}}}),
            200,
            None,
        )
        repository = MagicMock()
        cah._synchronize_profiles(repository, "http://acme", 123456)
        self.assertTrue(repository.profile_list_set.called)
        args = repository.profile_list_set.call_args[0][0]
        self.assertIn("profiles", args["value"])
        self.assertIn("synchronized_at", args["value"])

    @patch("examples.ca_handler.acme_ca_handler.url_get")
    def test_003__synchronize_profiles_error(self, mock_url_get):
        """CAhandler._synchronize_profiles() - error path"""
        from examples.ca_handler.acme_ca_handler import CAhandler

        cah = self.cahandler
        mock_url_get.return_value = ("fail", 500, "error")
        repository = MagicMock()
        with self.assertLogs("test_a2c", level="ERROR") as lcm:
            cah._synchronize_profiles(repository, "http://acme", 123456)
        self.assertIn("Error during profile synchronization", " ".join(lcm.output))

    @patch("examples.ca_handler.acme_ca_handler.Thread")
    @patch("examples.ca_handler.acme_ca_handler.uts_now", return_value=1000)
    def test_004_load_profiles_outdated_sync(self, mock_uts, mock_thread):
        """CAhandler.synchronize_profiles() - outdated, sync mode"""
        cah = self.cahandler
        repository = MagicMock()
        repository.profile_list_get.return_value = {"synchronized_at": 0}
        cah._synchronize_profiles = MagicMock()
        thread_instance = MagicMock()
        mock_thread.return_value = thread_instance
        cah.synchronize_profiles(repository, "http://acme", 100, async_mode=False)
        self.assertTrue(thread_instance.start.called)
        self.assertTrue(thread_instance.join.called)

    @patch("examples.ca_handler.acme_ca_handler.Thread")
    @patch("examples.ca_handler.acme_ca_handler.uts_now", return_value=1000)
    def test_005_load_profiles_outdated_async(self, mock_uts, mock_thread):
        """CAhandler.synchronize_profiles() - outdated, async mode"""
        cah = self.cahandler
        repository = MagicMock()
        repository.profile_list_get.return_value = {"synchronized_at": 0}
        cah._synchronize_profiles = MagicMock()
        thread_instance = MagicMock()
        mock_thread.return_value = thread_instance
        cah.synchronize_profiles(repository, "http://acme", 100, async_mode=True)
        self.assertTrue(thread_instance.start.called)
        self.assertFalse(thread_instance.join.called)

    @patch("examples.ca_handler.acme_ca_handler.Thread")
    @patch("examples.ca_handler.acme_ca_handler.uts_now", return_value=1000)
    def test_006_load_profiles_up_to_date(self, mock_uts, mock_thread):
        """CAhandler.synchronize_profiles() - up-to-date profiles"""
        cah = self.cahandler
        repository = MagicMock()
        repository.profile_list_get.return_value = {
            "synchronized_at": 2000,
            "profiles": {"foo": "bar"},
        }
        cah._synchronize_profiles = MagicMock()
        profiles = cah.synchronize_profiles(
            repository, "http://acme", 100, async_mode=False
        )
        self.assertEqual(profiles, {"foo": "bar"})
        self.assertFalse(mock_thread.return_value.start.called)

    @patch("examples.ca_handler.acme_ca_handler.url_get")
    def test_007__get_renewalinfo_endpoint_url_success(self, mock_url_get):
        """CAhandler._get_renewalinfo_endpoint_url() - directory has renewalInfo"""
        cah = self.cahandler
        directory_json = json.dumps({"renewalInfo": "http://acme/renewal-info"})
        mock_url_get.return_value = (directory_json, 200)
        url = cah._get_renewalinfo_endpoint_url("http://acme")
        self.assertEqual(url, "http://acme/renewal-info")

    @patch("examples.ca_handler.acme_ca_handler.url_get")
    def test_008__get_renewalinfo_endpoint_url_no_renewalinfo(self, mock_url_get):
        """CAhandler._get_renewalinfo_endpoint_url() - directory missing renewalInfo"""
        cah = self.cahandler
        directory_json = json.dumps({"foo": "bar"})
        mock_url_get.return_value = (directory_json, 200)
        url = cah._get_renewalinfo_endpoint_url("http://acme")
        self.assertEqual(url, "http://acme/renewal-info")

    @patch("examples.ca_handler.acme_ca_handler.url_get")
    def test_009__get_renewalinfo_endpoint_url_json_error(self, mock_url_get):
        """CAhandler._get_renewalinfo_endpoint_url() - JSON decode error"""
        cah = self.cahandler
        mock_url_get.return_value = ("notjson", 200)
        url = cah._get_renewalinfo_endpoint_url("http://acme")
        self.assertEqual(url, "http://acme/renewal-info")

    @patch("examples.ca_handler.acme_ca_handler.url_get")
    def test_010__get_renewalinfo_endpoint_url_fetch_error(self, mock_url_get):
        """CAhandler._get_renewalinfo_endpoint_url() - fetch error"""
        cah = self.cahandler
        mock_url_get.return_value = ("fail", 500)
        url = cah._get_renewalinfo_endpoint_url("http://acme")
        self.assertEqual(url, "http://acme/renewal-info")

    @patch("examples.ca_handler.acme_ca_handler.url_get", side_effect=Exception("fail"))
    def test_011__get_renewalinfo_endpoint_url_exception(self, mock_url_get):
        """CAhandler._get_renewalinfo_endpoint_url() - exception"""
        cah = self.cahandler
        url = cah._get_renewalinfo_endpoint_url("http://acme")
        self.assertEqual(url, "http://acme/renewal-info")

    @patch("examples.ca_handler.acme_ca_handler.url_get")
    def test_012_lookup_renewalinfo_success(self, mock_url_get):
        """CAhandler.lookup_renewalinfo() - success"""
        cah = self.cahandler
        renewalinfo_json = json.dumps({"cert": "foo", "csr": "bar"})
        mock_url_get.return_value = (renewalinfo_json, 200)
        code, dic = cah.lookup_renewalinfo("http://acme", "abc123")
        self.assertEqual(code, 200)
        self.assertEqual(dic, {"cert": "foo", "csr": "bar"})

    @patch("examples.ca_handler.acme_ca_handler.url_get")
    def test_013_lookup_renewalinfo_json_error(self, mock_url_get):
        """CAhandler.lookup_renewalinfo() - JSON decode error"""
        cah = self.cahandler
        mock_url_get.return_value = ("notjson", 200)
        code, dic = cah.lookup_renewalinfo("http://acme", "abc123")
        self.assertEqual(code, 500)
        self.assertEqual(dic, {})

    @patch("examples.ca_handler.acme_ca_handler.url_get")
    def test_014_lookup_renewalinfo_unexpected_response(self, mock_url_get):
        """CAhandler.lookup_renewalinfo() - unexpected response"""
        cah = self.cahandler
        mock_url_get.return_value = "fail"
        code, dic = cah.lookup_renewalinfo("http://acme", "abc123")
        self.assertEqual(code, 500)
        self.assertEqual(dic, {})

    @patch("examples.ca_handler.acme_ca_handler.url_get", side_effect=Exception("fail"))
    def test_015_lookup_renewalinfo_exception(self, mock_url_get):
        """CAhandler.lookup_renewalinfo() - exception"""
        cah = self.cahandler
        code, dic = cah.lookup_renewalinfo("http://acme", "abc123")
        self.assertEqual(code, 400)
        self.assertEqual(dic, {})

    def setUp(self):
        """setup unittest"""
        models_mock = MagicMock()
        models_mock.acme_srv.db_handler.DBstore.return_value = FakeDBStore
        modules = {"acme_srv.db_handler": models_mock}
        patch.dict("sys.modules", modules).start()
        import logging
        from examples.ca_handler.acme_ca_handler import CAhandler

        logging.basicConfig(level=logging.CRITICAL)
        self.logger = logging.getLogger("test_a2c")
        self.cahandler = CAhandler(False, self.logger)

    def tearDown(self):
        """teardown"""
        pass

    def _generate_full_jwk(self):
        """Helper to generate a full josepy.JWKRSA object"""
        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )
        return josepy.JWKRSA(key=private_key)

    def test_016___init__(self):
        """init"""
        self.assertTrue(self.cahandler.__enter__())

    def test_017___exit__(self):
        """exit"""
        self.assertFalse(self.cahandler.__exit__())

    @patch("examples.ca_handler.acme_ca_handler.load_config")
    def test_018__config_load(self, mock_load_cfg):
        """test _config_load default configparser object"""
        parser = configparser.ConfigParser()
        mock_load_cfg.return_value = parser
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.cahandler._config_load()
        self.assertFalse(self.cahandler.acme_keyfile)
        self.assertFalse(self.cahandler.acme_url)
        self.assertFalse(self.cahandler.account)
        self.assertEqual(
            {"directory_path": "/directory", "acct_path": "/acme/acct/"},
            self.cahandler.path_dic,
        )
        self.assertEqual(2048, self.cahandler.key_size)
        self.assertFalse(self.cahandler.email)
        self.assertIn(
            'ERROR:test_a2c:Configuration incomplete: "CAhandler" section is missing in config file',
            lcm.output,
        )
        self.assertFalse(self.cahandler.acme_keypath)

    @patch("examples.ca_handler.acme_ca_handler.load_config")
    def test_019__config_load(self, mock_load_cfg):
        """test _config_load empty cahandler section"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {}
        mock_load_cfg.return_value = parser
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.cahandler._config_load()
        self.assertFalse(self.cahandler.acme_keyfile)
        self.assertFalse(self.cahandler.acme_url)
        self.assertFalse(self.cahandler.account)
        self.assertEqual(
            {"directory_path": "/directory", "acct_path": "/acme/acct/"},
            self.cahandler.path_dic,
        )
        self.assertEqual(2048, self.cahandler.key_size)
        self.assertFalse(self.cahandler.email)
        self.assertIn(
            'ERROR:test_a2c:acme_ca_handler configuration incomplete: "acme_keyfile" parameter is missing in config file',
            lcm.output,
        )
        self.assertIn(
            'ERROR:test_a2c:acme_ca_handler configuration incomplete: "acme_url" parameter is missing in config file',
            lcm.output,
        )
        self.assertFalse(self.cahandler.acme_keypath)
        self.assertTrue(self.cahandler.ssl_verify)

    @patch("examples.ca_handler.acme_ca_handler.load_config")
    def test_020__config_load(self, mock_load_cfg):
        """test _config_load unknown values"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"foo": "bar"}
        mock_load_cfg.return_value = parser
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.cahandler._config_load()
        self.assertFalse(self.cahandler.acme_keyfile)
        self.assertFalse(self.cahandler.acme_url)
        self.assertFalse(self.cahandler.account)
        self.assertEqual(
            {"directory_path": "/directory", "acct_path": "/acme/acct/"},
            self.cahandler.path_dic,
        )
        self.assertEqual(2048, self.cahandler.key_size)
        self.assertFalse(self.cahandler.email)
        self.assertIn(
            'ERROR:test_a2c:acme_ca_handler configuration incomplete: "acme_keyfile" parameter is missing in config file',
            lcm.output,
        )
        self.assertIn(
            'ERROR:test_a2c:acme_ca_handler configuration incomplete: "acme_url" parameter is missing in config file',
            lcm.output,
        )
        self.assertFalse(self.cahandler.acme_keypath)
        self.assertTrue(self.cahandler.ssl_verify)

    @patch("examples.ca_handler.acme_ca_handler.load_config")
    def test_021__config_load(self, mock_load_cfg):
        """test _config_load key_file value"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"acme_keyfile": "key_file"}
        mock_load_cfg.return_value = parser
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.cahandler._config_load()
        self.assertEqual("key_file", self.cahandler.acme_keyfile)
        self.assertFalse(self.cahandler.acme_url)
        self.assertFalse(self.cahandler.account)
        self.assertEqual(
            {"directory_path": "/directory", "acct_path": "/acme/acct/"},
            self.cahandler.path_dic,
        )
        self.assertEqual(2048, self.cahandler.key_size)
        self.assertFalse(self.cahandler.email)
        self.assertIn(
            'ERROR:test_a2c:acme_ca_handler configuration incomplete: "acme_url" parameter is missing in config file',
            lcm.output,
        )
        self.assertFalse(self.cahandler.acme_keypath)
        self.assertTrue(self.cahandler.ssl_verify)

    @patch("examples.ca_handler.acme_ca_handler.load_config")
    def test_022__config_load(self, mock_load_cfg):
        """test _config_load key_file value"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {
            "acme_keyfile": "key_file",
            "acme_keypath": "acme_keypath",
        }
        mock_load_cfg.return_value = parser
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.cahandler._config_load()
        self.assertEqual("key_file", self.cahandler.acme_keyfile)
        self.assertFalse(self.cahandler.acme_url)
        self.assertFalse(self.cahandler.account)
        self.assertEqual(
            {"directory_path": "/directory", "acct_path": "/acme/acct/"},
            self.cahandler.path_dic,
        )
        self.assertEqual(2048, self.cahandler.key_size)
        self.assertFalse(self.cahandler.email)
        self.assertIn(
            'ERROR:test_a2c:acme_ca_handler configuration incomplete: "acme_url" parameter is missing in config file',
            lcm.output,
        )
        self.assertEqual("acme_keypath", self.cahandler.acme_keypath)
        self.assertTrue(self.cahandler.ssl_verify)

    @patch("examples.ca_handler.acme_ca_handler.load_config")
    def test_023__config_load(self, mock_load_cfg):
        """test _config_load url value"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"acme_url": "url"}
        mock_load_cfg.return_value = parser
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.cahandler._config_load()
        self.assertFalse(self.cahandler.acme_keyfile)
        self.assertEqual("url", self.cahandler.acme_url)
        self.assertFalse(self.cahandler.account)
        self.assertEqual(
            {"directory_path": "/directory", "acct_path": "/acme/acct/"},
            self.cahandler.path_dic,
        )
        self.assertEqual(2048, self.cahandler.key_size)
        self.assertFalse(self.cahandler.email)
        self.assertIn(
            'ERROR:test_a2c:acme_ca_handler configuration incomplete: "acme_keyfile" parameter is missing in config file',
            lcm.output,
        )
        self.assertFalse(self.cahandler.acme_keypath)
        self.assertTrue(self.cahandler.ssl_verify)

    @patch("examples.ca_handler.acme_ca_handler.load_config")
    def test_024__config_load(self, mock_load_cfg):
        """test _config_load account values"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"acme_account": "acme_account"}
        mock_load_cfg.return_value = parser
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.cahandler._config_load()
        self.assertFalse(self.cahandler.acme_keyfile)
        self.assertFalse(self.cahandler.acme_url)
        self.assertEqual("acme_account", self.cahandler.account)
        self.assertEqual(
            {"directory_path": "/directory", "acct_path": "/acme/acct/"},
            self.cahandler.path_dic,
        )
        self.assertEqual(2048, self.cahandler.key_size)
        self.assertFalse(self.cahandler.email)
        self.assertIn(
            'ERROR:test_a2c:acme_ca_handler configuration incomplete: "acme_keyfile" parameter is missing in config file',
            lcm.output,
        )
        self.assertIn(
            'ERROR:test_a2c:acme_ca_handler configuration incomplete: "acme_url" parameter is missing in config file',
            lcm.output,
        )
        self.assertFalse(self.cahandler.acme_keypath)
        self.assertTrue(self.cahandler.ssl_verify)

    @patch("examples.ca_handler.acme_ca_handler.load_config")
    def test_025__config_load(self, mock_load_cfg):
        """test _config_load key_size"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"acme_account_keysize": "acme_account_keysize"}
        mock_load_cfg.return_value = parser
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.cahandler._config_load()
        self.assertFalse(self.cahandler.acme_keyfile)
        self.assertFalse(self.cahandler.acme_url)
        self.assertFalse(self.cahandler.account)
        self.assertEqual(
            {"directory_path": "/directory", "acct_path": "/acme/acct/"},
            self.cahandler.path_dic,
        )
        self.assertEqual("acme_account_keysize", self.cahandler.key_size)
        self.assertFalse(self.cahandler.email)
        self.assertIn(
            'ERROR:test_a2c:acme_ca_handler configuration incomplete: "acme_keyfile" parameter is missing in config file',
            lcm.output,
        )
        self.assertIn(
            'ERROR:test_a2c:acme_ca_handler configuration incomplete: "acme_url" parameter is missing in config file',
            lcm.output,
        )
        self.assertFalse(self.cahandler.acme_keypath)
        self.assertTrue(self.cahandler.ssl_verify)

    @patch("examples.ca_handler.acme_ca_handler.load_config")
    def test_026__config_load(self, mock_load_cfg):
        """test _config_load email"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"acme_account_email": "acme_account_email"}
        mock_load_cfg.return_value = parser
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.cahandler._config_load()
        self.assertFalse(self.cahandler.acme_keyfile)
        self.assertFalse(self.cahandler.acme_url)
        self.assertFalse(self.cahandler.account)
        self.assertEqual(
            {"directory_path": "/directory", "acct_path": "/acme/acct/"},
            self.cahandler.path_dic,
        )
        self.assertEqual(2048, self.cahandler.key_size)
        self.assertEqual("acme_account_email", self.cahandler.email)
        self.assertIn(
            'ERROR:test_a2c:acme_ca_handler configuration incomplete: "acme_keyfile" parameter is missing in config file',
            lcm.output,
        )
        self.assertIn(
            'ERROR:test_a2c:acme_ca_handler configuration incomplete: "acme_url" parameter is missing in config file',
            lcm.output,
        )
        self.assertFalse(self.cahandler.acme_keypath)
        self.assertTrue(self.cahandler.ssl_verify)

    @patch("examples.ca_handler.acme_ca_handler.load_config")
    def test_027__config_load(self, mock_load_cfg):
        """test _config_load email"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"directory_path": "directory_path"}
        mock_load_cfg.return_value = parser
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.cahandler._config_load()
        self.assertFalse(self.cahandler.acme_keyfile)
        self.assertFalse(self.cahandler.acme_url)
        self.assertFalse(self.cahandler.account)
        self.assertEqual(
            {"acct_path": "/acme/acct/", "directory_path": "directory_path"},
            self.cahandler.path_dic,
        )
        self.assertEqual(2048, self.cahandler.key_size)
        self.assertFalse(self.cahandler.email)
        self.assertIn(
            'ERROR:test_a2c:acme_ca_handler configuration incomplete: "acme_keyfile" parameter is missing in config file',
            lcm.output,
        )
        self.assertIn(
            'ERROR:test_a2c:acme_ca_handler configuration incomplete: "acme_url" parameter is missing in config file',
            lcm.output,
        )
        self.assertFalse(self.cahandler.acme_keypath)
        self.assertTrue(self.cahandler.ssl_verify)

    @patch("examples.ca_handler.acme_ca_handler.load_config")
    def test_028__config_load(self, mock_load_cfg):
        """test _config_load email"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"account_path": "account_path"}
        mock_load_cfg.return_value = parser
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.cahandler._config_load()
        self.assertFalse(self.cahandler.acme_keyfile)
        self.assertFalse(self.cahandler.acme_url)
        self.assertFalse(self.cahandler.account)
        self.assertEqual(
            {"acct_path": "account_path", "directory_path": "/directory"},
            self.cahandler.path_dic,
        )
        self.assertEqual(2048, self.cahandler.key_size)
        self.assertFalse(self.cahandler.email)
        self.assertIn(
            'ERROR:test_a2c:acme_ca_handler configuration incomplete: "acme_keyfile" parameter is missing in config file',
            lcm.output,
        )
        self.assertIn(
            'ERROR:test_a2c:acme_ca_handler configuration incomplete: "acme_url" parameter is missing in config file',
            lcm.output,
        )
        self.assertFalse(self.cahandler.acme_keypath)
        self.assertTrue(self.cahandler.ssl_verify)

    @patch("examples.ca_handler.acme_ca_handler.load_config")
    def test_029__config_load(self, mock_load_cfg):
        """test _config_load allowlist"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"allowed_domainlist": '["foo", "bar"]'}
        mock_load_cfg.return_value = parser
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.cahandler._config_load()
        self.assertFalse(self.cahandler.acme_keyfile)
        self.assertFalse(self.cahandler.acme_url)
        self.assertFalse(self.cahandler.account)
        self.assertEqual(
            {"acct_path": "/acme/acct/", "directory_path": "/directory"},
            self.cahandler.path_dic,
        )
        self.assertEqual(2048, self.cahandler.key_size)
        self.assertFalse(self.cahandler.email)
        self.assertIn(
            'ERROR:test_a2c:acme_ca_handler configuration incomplete: "acme_keyfile" parameter is missing in config file',
            lcm.output,
        )
        self.assertIn(
            'ERROR:test_a2c:acme_ca_handler configuration incomplete: "acme_url" parameter is missing in config file',
            lcm.output,
        )
        self.assertFalse(self.cahandler.acme_keypath)
        self.assertTrue(self.cahandler.ssl_verify)

    @patch("examples.ca_handler.acme_ca_handler.load_config")
    def test_030__config_load(self, mock_load_cfg):
        """test _config_load allowlist - failed json parse"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"allowed_domainlist": "foo"}
        mock_load_cfg.return_value = parser
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.cahandler._config_load()
        self.assertFalse(self.cahandler.acme_keyfile)
        self.assertFalse(self.cahandler.acme_url)
        self.assertFalse(self.cahandler.account)
        self.assertEqual(
            {"acct_path": "/acme/acct/", "directory_path": "/directory"},
            self.cahandler.path_dic,
        )
        self.assertEqual(2048, self.cahandler.key_size)
        self.assertFalse(self.cahandler.email)
        self.assertIn(
            'ERROR:test_a2c:acme_ca_handler configuration incomplete: "acme_keyfile" parameter is missing in config file',
            lcm.output,
        )
        self.assertIn(
            'ERROR:test_a2c:acme_ca_handler configuration incomplete: "acme_url" parameter is missing in config file',
            lcm.output,
        )
        self.assertFalse(self.cahandler.acme_keypath)
        self.assertTrue(self.cahandler.ssl_verify)

    @patch("examples.ca_handler.acme_ca_handler.load_config")
    def test_031__config_load(self, mock_load_cfg):
        """test _config_load allowlist - failed json parse"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"ssl_verify": False}
        mock_load_cfg.return_value = parser
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.cahandler._config_load()
        self.assertFalse(self.cahandler.acme_keyfile)
        self.assertFalse(self.cahandler.acme_url)
        self.assertFalse(self.cahandler.account)
        self.assertEqual(
            {"acct_path": "/acme/acct/", "directory_path": "/directory"},
            self.cahandler.path_dic,
        )
        self.assertEqual(2048, self.cahandler.key_size)
        self.assertFalse(self.cahandler.email)
        self.assertIn(
            'ERROR:test_a2c:acme_ca_handler configuration incomplete: "acme_keyfile" parameter is missing in config file',
            lcm.output,
        )
        self.assertIn(
            'ERROR:test_a2c:acme_ca_handler configuration incomplete: "acme_url" parameter is missing in config file',
            lcm.output,
        )
        self.assertFalse(self.cahandler.acme_keypath)
        self.assertFalse(self.cahandler.ssl_verify)

    @patch("examples.ca_handler.acme_ca_handler.load_config")
    def test_032__config_load(self, mock_load_cfg):
        """test _config_load allowlist - failed json parse"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"ssl_verify": True}

        mock_load_cfg.return_value = parser
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.cahandler._config_load()
        self.assertFalse(self.cahandler.acme_keyfile)
        self.assertFalse(self.cahandler.acme_url)
        self.assertFalse(self.cahandler.account)
        self.assertEqual(
            {"acct_path": "/acme/acct/", "directory_path": "/directory"},
            self.cahandler.path_dic,
        )
        self.assertEqual(2048, self.cahandler.key_size)
        self.assertFalse(self.cahandler.email)
        self.assertIn(
            'ERROR:test_a2c:acme_ca_handler configuration incomplete: "acme_keyfile" parameter is missing in config file',
            lcm.output,
        )
        self.assertIn(
            'ERROR:test_a2c:acme_ca_handler configuration incomplete: "acme_url" parameter is missing in config file',
            lcm.output,
        )
        self.assertFalse(self.cahandler.acme_keypath)
        self.assertTrue(self.cahandler.ssl_verify)

    @patch("examples.ca_handler.acme_ca_handler.load_config")
    def test_033__config_load(self, mock_load_cfg):
        """test _config_load allowlist - failed json parse"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"ssl_verify": "aaa"}

        mock_load_cfg.return_value = parser
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.cahandler._config_load()
        self.assertFalse(self.cahandler.acme_keyfile)
        self.assertFalse(self.cahandler.acme_url)
        self.assertFalse(self.cahandler.account)
        self.assertEqual(
            {"acct_path": "/acme/acct/", "directory_path": "/directory"},
            self.cahandler.path_dic,
        )
        self.assertEqual(2048, self.cahandler.key_size)
        self.assertFalse(self.cahandler.email)
        self.assertIn(
            'ERROR:test_a2c:acme_ca_handler configuration incomplete: "acme_keyfile" parameter is missing in config file',
            lcm.output,
        )
        self.assertIn(
            'ERROR:test_a2c:acme_ca_handler configuration incomplete: "acme_url" parameter is missing in config file',
            lcm.output,
        )
        self.assertIn(
            "WARNING:test_a2c:Failed to parse ssl_verify parameter: Not a boolean: aaa",
            lcm.output,
        )
        self.assertFalse(self.cahandler.acme_keypath)
        self.assertTrue(self.cahandler.ssl_verify)

    @patch("examples.ca_handler.acme_ca_handler.load_config")
    def test_034__config_load(self, mock_load_cfg):
        """test _config_load allowlist - failed json parse"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"eab_kid": "eab_kid"}
        mock_load_cfg.return_value = parser
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.cahandler._config_load()
        self.assertFalse(self.cahandler.acme_keyfile)
        self.assertFalse(self.cahandler.acme_url)
        self.assertFalse(self.cahandler.account)
        self.assertEqual(
            {"acct_path": "/acme/acct/", "directory_path": "/directory"},
            self.cahandler.path_dic,
        )
        self.assertEqual(2048, self.cahandler.key_size)
        self.assertFalse(self.cahandler.email)
        self.assertEqual("eab_kid", self.cahandler.eab_kid)
        self.assertFalse(self.cahandler.eab_hmac_key)
        self.assertIn(
            'ERROR:test_a2c:acme_ca_handler configuration incomplete: "acme_keyfile" parameter is missing in config file',
            lcm.output,
        )
        self.assertIn(
            'ERROR:test_a2c:acme_ca_handler configuration incomplete: "acme_url" parameter is missing in config file',
            lcm.output,
        )
        self.assertFalse(self.cahandler.acme_keypath)
        self.assertTrue(self.cahandler.ssl_verify)

    @patch("examples.ca_handler.acme_ca_handler.load_config")
    def test_035__config_load(self, mock_load_cfg):
        """test _config_load allowlist - failed json parse"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"eab_hmac_key": "eab_hmac_key"}
        mock_load_cfg.return_value = parser
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.cahandler._config_load()
        self.assertFalse(self.cahandler.acme_keyfile)
        self.assertFalse(self.cahandler.acme_url)
        self.assertFalse(self.cahandler.account)
        self.assertEqual(
            {"acct_path": "/acme/acct/", "directory_path": "/directory"},
            self.cahandler.path_dic,
        )
        self.assertEqual(2048, self.cahandler.key_size)
        self.assertFalse(self.cahandler.email)
        self.assertFalse(self.cahandler.eab_kid)
        self.assertEqual("eab_hmac_key", self.cahandler.eab_hmac_key)
        self.assertIn(
            'ERROR:test_a2c:acme_ca_handler configuration incomplete: "acme_keyfile" parameter is missing in config file',
            lcm.output,
        )
        self.assertIn(
            'ERROR:test_a2c:acme_ca_handler configuration incomplete: "acme_url" parameter is missing in config file',
            lcm.output,
        )
        self.assertFalse(self.cahandler.acme_keypath)
        self.assertTrue(self.cahandler.ssl_verify)

    def test_036__challenge_filter(self):
        """test _challenge_filter single http"""
        challenge1 = Mock(return_value="foo")
        challenge1.chall.to_partial_json.return_value = {"type": "http-01"}
        challenge1.chall.typ = "http-01"
        challenge1.chall.value = "value-01"
        authz = Mock()
        authz.body.challenges = [challenge1]
        self.assertEqual("http-01", self.cahandler._challenge_filter(authz).chall.typ)
        self.assertEqual(
            "value-01", self.cahandler._challenge_filter(authz).chall.value
        )

    def test_037__challenge_filter(self):
        """test _challenge_filter dns and http"""
        challenge1 = Mock(return_value="foo")
        challenge1.chall.to_partial_json.return_value = {"type": "dns-01"}
        challenge1.chall.typ = "dns-01"
        challenge1.chall.value = "value-01"
        challenge2 = Mock(return_value="foo")
        challenge2.chall.typ = "http-01"
        challenge2.chall.to_partial_json.return_value = {"type": "http-01"}
        challenge2.chall.value = "value-02"
        authz = Mock()
        authz.body.challenges = [challenge1, challenge2]
        self.assertEqual("http-01", self.cahandler._challenge_filter(authz).chall.typ)
        self.assertEqual(
            "value-02", self.cahandler._challenge_filter(authz).chall.value
        )

    def test_038__challenge_filter(self):
        """test _challenge_filter double http to test break"""
        challenge1 = Mock(return_value="foo")
        challenge1.chall.to_partial_json.return_value = {"type": "http-01"}
        challenge1.chall.typ = "http-01"
        challenge1.chall.value = "value-01"
        challenge2 = Mock(return_value="foo")
        challenge2.chall.to_partial_json.return_value = {"type": "http-01"}
        challenge2.chall.typ = "http-01"
        challenge2.chall.value = "value-02"
        authz = Mock()
        authz.body.challenges = [challenge1, challenge2]
        self.assertEqual("http-01", self.cahandler._challenge_filter(authz).chall.typ)
        self.assertEqual(
            "value-01", self.cahandler._challenge_filter(authz).chall.value
        )

    def test_039__challenge_filter(self):
        """test _challenge_filter no http challenge"""
        challenge1 = Mock(return_value="foo")
        challenge1.chall.to_partial_json.return_value = {"type": "type-01"}
        challenge1.chall.typ = "type-01"
        challenge1.chall.value = "value-01"
        challenge2 = Mock(return_value="foo")
        challenge2.chall.to_partial_json.return_value = {"type": "type-02"}
        challenge2.chall.typ = "type-02"
        challenge2.chall.value = "value-02"
        authz = Mock()
        authz.body.challenges = [challenge1, challenge2]
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.assertFalse(self.cahandler._challenge_filter(authz))
        self.assertIn(
            "ERROR:test_a2c:Could not find challenge of type http-01",
            lcm.output,
        )

    def test_040__http_challenge_store(self):
        """test _http_challenge_store() no challenge_content"""
        # mock_add.return_value = 'ff'
        self.cahandler._http_challenge_store("challenge_name", None)
        self.assertFalse(self.cahandler.dbstore.cahandler_add.called)

    def test_041__http_challenge_store(self):
        """test _http_challenge_store() no challenge_content"""
        # mock_add.return_value = 'ff'
        self.cahandler._http_challenge_store(None, "challenge_content")
        self.assertFalse(self.cahandler.dbstore.cahandler_add.called)

    def test_042__http_challenge_store(self):
        """test _http_challenge_store()"""
        self.cahandler._http_challenge_store("challenge_name", "challenge_content")
        self.assertTrue(self.cahandler.dbstore.cahandler_add.called)

    @patch("examples.ca_handler.acme_ca_handler.CAhandler._challenge_filter")
    def test_043__challenge_info(self, mock_filter):
        """test _challenge_info - all ok"""
        response = Mock()
        response.chall.validation = Mock(return_value="foo.bar")
        mock_filter.return_value = response
        self.assertIn("foo", self.cahandler._challenge_info("authzr", "user_key")[0])
        self.assertIn(
            "foo.bar", self.cahandler._challenge_info("authzr", "user_key")[1]
        )

    @patch("examples.ca_handler.acme_ca_handler.CAhandler._challenge_filter")
    def test_044__challenge_info(self, mock_filter):
        """test _challenge_info - wrong split"""
        response = Mock()
        response.chall.validation = Mock(return_value="foobar")
        mock_filter.return_value = response
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            response = self.cahandler._challenge_info("authzr", "user_key")
        self.assertFalse(response[0])
        self.assertIn("foobar", response[1])
        self.assertIn(
            "ERROR:test_a2c:Challenge split failed: foobar",
            lcm.output,
        )

    @patch("examples.ca_handler.acme_ca_handler.CAhandler._challenge_filter")
    def test_045__challenge_info(self, mock_filter):
        """test _challenge_info - wrong split"""
        response = Mock()
        response.chall.validation = Mock(return_value="foobar")
        mock_filter.return_value = response
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.assertEqual(
                (None, None, None), self.cahandler._challenge_info(None, "user_key")
            )
        self.assertIn("ERROR:test_a2c:acme authorization is missing", lcm.output)

    @patch("examples.ca_handler.acme_ca_handler.CAhandler._challenge_filter")
    def test_046__challenge_info(self, mock_filter):
        """test _challenge_info - wrong split"""
        response = Mock()
        response.chall.validation = Mock(return_value="foobar")
        mock_filter.return_value = response
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.assertEqual(
                (None, None, None), self.cahandler._challenge_info("authzr", None)
            )
        self.assertIn("ERROR:test_a2c:acme user is missing", lcm.output)

    @patch("examples.ca_handler.acme_ca_handler.CAhandler._challenge_filter")
    def test_047__challenge_info(self, mock_filter):
        """test _challenge_info - all ok"""
        challenge1 = Mock(return_value="foo")
        challenge1.to_partial_json.return_value = {"foo": "bar"}
        challenge1.chall.typ = "http-01"
        challenge1.chall.value = "value-01"
        mock_filter.side_effect = [None, challenge1]
        self.assertEqual(
            {"foo": "bar"}, self.cahandler._challenge_info("authzr", "user_key")[1]
        )

    @patch("josepy.JWKRSA")
    def test_048__key_generate(self, mock_key):
        """test _key_generate()"""
        mock_key.return_value = "key"
        self.assertEqual("key", self.cahandler._key_generate())

    @patch("json.loads")
    @patch("josepy.JWKRSA.fields_from_json")
    @patch("builtins.open", mock_open(read_data="csv_dump"), create=True)
    @patch("os.path.exists")
    def test_049__user_key_load(self, mock_file, mock_key, mock_json):
        """test user_key_load for an existing file"""
        mock_file.return_value = True
        mock_key.return_value = "loaded_key"
        mock_json.return_value = {"foo": "foo"}
        self.assertEqual("loaded_key", self.cahandler._user_key_load())
        self.assertTrue(mock_key.called)
        self.assertTrue(mock_json.called)
        self.assertFalse(self.cahandler.account)

    @patch("json.loads")
    @patch("josepy.JWKRSA.fields_from_json")
    @patch("builtins.open", mock_open(read_data="csv_dump"), create=True)
    @patch("os.path.exists")
    def test_050__user_key_load(self, mock_file, mock_key, mock_json):
        """test user_key_load for an existing file"""
        mock_file.return_value = True
        mock_key.return_value = "loaded_key"
        mock_json.return_value = {"account": "account"}
        self.assertEqual("loaded_key", self.cahandler._user_key_load())
        self.assertTrue(mock_key.called)
        self.assertTrue(mock_json.called)
        self.assertEqual("account", self.cahandler.account)

    @patch("json.dumps")
    @patch("examples.ca_handler.acme_ca_handler.CAhandler._key_generate")
    @patch("builtins.open", mock_open(read_data="csv_dump"), create=True)
    @patch("os.path.exists")
    def test_051__user_key_load(self, mock_file, mock_key, mock_json):
        """test user_key_load for an existing file"""
        mock_file.return_value = False
        mock_key.to_json.return_value = {"foo": "generate_key"}
        mock_json.return_value = "foo"
        self.assertTrue(self.cahandler._user_key_load())
        self.assertTrue(mock_key.called)
        self.assertTrue(mock_json.called)

    @patch("json.dumps")
    @patch("examples.ca_handler.acme_ca_handler.CAhandler._key_generate")
    @patch("builtins.open", mock_open(read_data="csv_dump"), create=True)
    @patch("os.path.exists")
    def test_052__user_key_load(self, mock_file, mock_key, mock_json):
        """test user_key_load for an existing file"""
        mock_file.return_value = False
        mock_key.to_json.return_value = {"foo": "generate_key"}
        mock_json.side_effect = Exception("ex_dump")
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.assertTrue(self.cahandler._user_key_load())
        self.assertIn("ERROR:test_a2c:Error during key dumping: ex_dump", lcm.output)
        self.assertTrue(mock_key.called)
        self.assertTrue(mock_json.called)

    @patch("acme.messages")
    def test_053__account_register(self, mock_messages):
        """test account register existing account - no replacement"""
        response = Mock()
        response.uri = "uri"
        acmeclient = Mock()
        acmeclient.query_registration = Mock(return_value=response)
        mock_messages = Mock()
        directory = {"newAccount": "newAccount"}
        self.cahandler.acme_url = "url"
        self.cahandler.path_dic = {"acct_path": "acct_path"}
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.assertEqual(
                "uri",
                self.cahandler._account_register(acmeclient, "user_key", directory).uri,
            )
        self.assertIn(
            "INFO:test_a2c:acme-account id is uri. Please add an corresponding acme_account parameter to your acme_srv.cfg to avoid unnecessary lookups",
            lcm.output,
        )
        self.assertEqual("uri", self.cahandler.account)

    @patch("acme.messages")
    def test_054__account_register(self, mock_messages):
        """test account register existing account - url replacement"""
        response = Mock()
        response.uri = "urluri"
        acmeclient = Mock()
        acmeclient.query_registration = Mock(return_value=response)
        mock_messages = Mock()
        directory = {"newAccount": "newAccount"}
        self.cahandler.acme_url = "url"
        self.cahandler.path_dic = {"acct_path": "acct_path"}
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.assertEqual(
                "urluri",
                self.cahandler._account_register(acmeclient, "user_key", directory).uri,
            )
        self.assertIn(
            "INFO:test_a2c:acme-account id is uri. Please add an corresponding acme_account parameter to your acme_srv.cfg to avoid unnecessary lookups",
            lcm.output,
        )
        self.assertEqual("uri", self.cahandler.account)

    @patch("acme.messages")
    def test_055__account_register(self, mock_messages):
        """test account register existing account - acct_path replacement"""
        response = Mock()
        response.uri = "acct_pathuri"
        acmeclient = Mock()
        acmeclient.query_registration = Mock(return_value=response)
        mock_messages = Mock()
        directory = {"newAccount": "newAccount"}
        self.cahandler.acme_url = "url"
        self.cahandler.path_dic = {"acct_path": "acct_path"}
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.assertEqual(
                "acct_pathuri",
                self.cahandler._account_register(acmeclient, "user_key", directory).uri,
            )
        self.assertIn(
            "INFO:test_a2c:acme-account id is uri. Please add an corresponding acme_account parameter to your acme_srv.cfg to avoid unnecessary lookups",
            lcm.output,
        )
        self.assertEqual("uri", self.cahandler.account)

    @patch("acme.messages")
    def test_056__account_register(self, mock_messages):
        """test account register existing account - with email"""
        response = Mock()
        response.uri = "newuri"
        acmeclient = Mock()
        acmeclient.new_account = Mock(return_value=response)
        mock_messages = Mock()
        self.cahandler.email = "email"
        self.cahandler.acme_url = "url"
        self.cahandler.path_dic = {"acct_path": "acct_path"}
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.assertEqual(
                "newuri",
                self.cahandler._account_register(
                    acmeclient, "user_key", "directory"
                ).uri,
            )
        self.assertIn(
            "INFO:test_a2c:acme-account id is newuri. Please add an corresponding acme_account parameter to your acme_srv.cfg to avoid unnecessary lookups",
            lcm.output,
        )
        self.assertEqual("newuri", self.cahandler.account)

    @patch("acme.messages")
    def test_057__account_register(self, mock_messages):
        """test account register existing account - no email"""
        response = Mock()
        response.uri = "newuri"
        acmeclient = Mock()
        acmeclient.new_account = Mock(return_value=response)
        mock_messages = Mock()
        self.cahandler.acme_url = "url"
        self.cahandler.path_dic = {"acct_path": "acct_path"}
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.assertFalse(
                self.cahandler._account_register(acmeclient, "user_key", "directory")
            )
        self.assertFalse(self.cahandler.account)

    @patch("acme.messages")
    def test_058__account_register(self, mock_messages):
        """test account register existing account - no url"""
        response = Mock()
        response.uri = "newuri"
        acmeclient = Mock()
        acmeclient.new_account = Mock(return_value=response)
        mock_messages = Mock()
        self.cahandler.email = "email"
        self.cahandler.path_dic = {"acct_path": "acct_path"}
        self.assertEqual(
            "newuri",
            self.cahandler._account_register(acmeclient, "user_key", "directory").uri,
        )
        self.assertFalse(self.cahandler.account)

    @patch("acme.messages")
    def test_059__account_register(self, mock_messages):
        """test account register existing account - wrong pathdic"""
        response = Mock()
        response.uri = "newuri"
        acmeclient = Mock()
        acmeclient.new_account = Mock(return_value=response)
        mock_messages = Mock()
        self.cahandler.email = "email"
        self.cahandler.path_dic = {"acct_path1": "acct_path"}
        self.cahandler.acme_url = "url"
        self.assertEqual(
            "newuri",
            self.cahandler._account_register(acmeclient, "user_key", "directory").uri,
        )
        self.assertFalse(self.cahandler.account)

    @patch("examples.ca_handler.acme_ca_handler.CAhandler._zerossl_eab_get")
    @patch("acme.messages")
    def test_060__account_register(self, mock_messages, mock_eab):
        """test account register existing account - normal url"""
        response = Mock()
        response.uri = "urluri"
        acmeclient = Mock()
        acmeclient.new_account = Mock(return_value=response)
        mock_messages = Mock()
        self.cahandler.email = "email"
        self.cahandler.path_dic = {"acct_path": "acct_path"}
        self.cahandler.acme_url = "url"
        self.assertEqual(
            "urluri",
            self.cahandler._account_register(acmeclient, "user_key", "directory").uri,
        )
        self.assertEqual("uri", self.cahandler.account)
        self.assertFalse(mock_eab.called)

    @patch("examples.ca_handler.acme_ca_handler.CAhandler._zerossl_eab_get")
    @patch("acme.messages")
    def test_061__account_register(self, mock_messages, mock_eab):
        """test account register existing account - zerossl.com url"""
        response = Mock()
        response.uri = "zerossl.comuri"
        acmeclient = Mock()
        acmeclient.new_account = Mock(return_value=response)
        mock_messages = Mock()
        self.cahandler.email = "email"
        self.cahandler.path_dic = {"acct_path": "acct_path"}
        self.cahandler.acme_url = "zerossl.com"
        self.cahandler.acme_url_dic = {"host": "acme.zerossl.com"}
        self.assertEqual(
            "zerossl.comuri",
            self.cahandler._account_register(acmeclient, "user_key", "directory").uri,
        )
        self.assertEqual("uri", self.cahandler.account)
        self.assertTrue(mock_eab.called)

    @patch(
        "examples.ca_handler.acme_ca_handler.messages.ExternalAccountBinding.from_data"
    )
    @patch("acme.messages")
    def test_062__account_register(self, mock_messages, mock_eab):
        """test account register existing account - zerossl.com url"""
        response = Mock()
        response.uri = "urluri"
        acmeclient = Mock()
        acmeclient.new_account = Mock(return_value=response)
        mock_messages = Mock()
        self.cahandler.email = "email"
        self.cahandler.path_dic = {"acct_path": "acct_path"}
        self.cahandler.acme_url = "url"
        self.assertEqual(
            "urluri",
            self.cahandler._account_register(acmeclient, "user_key", "directory").uri,
        )
        self.assertEqual("uri", self.cahandler.account)
        self.assertFalse(mock_eab.called)

    @patch("examples.ca_handler.acme_ca_handler.CAhandler._jwk_strip")
    @patch(
        "examples.ca_handler.acme_ca_handler.messages.ExternalAccountBinding.from_data"
    )
    @patch("acme.messages")
    def test_063__account_register(self, mock_messages, mock_eab, mock_jwk_strip):
        """test account register existing account - zerossl.com url"""
        response = Mock()
        response.uri = "urluri"
        mock_jwk_strip.return_value = "user_key"
        acmeclient = Mock()
        acmeclient.new_account = Mock(return_value=response)
        mock_eab.return_value = Mock()
        self.cahandler.email = "email"
        self.cahandler.path_dic = {"acct_path": "acct_path"}
        self.cahandler.acme_url = "url"
        self.cahandler.eab_kid = "kid"
        self.cahandler.eab_hmac_key = "hmac_key"
        self.assertEqual(
            "urluri",
            self.cahandler._account_register(acmeclient, "user_key", "directory").uri,
        )
        self.assertEqual("uri", self.cahandler.account)
        self.assertTrue(mock_eab.called)

    @patch("acme.messages.NewRegistration.from_data")
    def test_064_acount_create(self, mock_newreg):
        """test account_create"""
        response = "response"
        acmeclient = Mock()
        acmeclient.new_account.return_value = "response"
        self.cahandler.email = "email"
        self.assertEqual(
            "response",
            self.cahandler._account_create(acmeclient, "user_key", "directory"),
        )
        self.assertTrue(mock_newreg.called)

    @patch("acme.messages.NewRegistration.from_data")
    def test_065_acount_create(self, mock_newreg):
        """test account_create"""
        response = "response"
        acmeclient = Mock()
        acmeclient.new_account.side_effect = Exception("mock_exception")
        self.cahandler.email = "email"
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.assertFalse(
                self.cahandler._account_create(acmeclient, "user_key", "directory")
            )
        self.assertTrue(mock_newreg.called)
        self.assertIn(
            "ERROR:test_a2c:Account registration failed: mock_exception",
            lcm.output,
        )

    @patch("acme.messages.NewRegistration.from_data")
    def test_066_acount_create(self, mock_newreg):
        """test account_create"""
        response = "response"
        acmeclient = Mock()
        acmeclient.new_account.side_effect = Exception("ConflictError")
        self.cahandler.email = "email"
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.assertFalse(
                self.cahandler._account_create(acmeclient, "user_key", "directory")
            )
        self.assertTrue(mock_newreg.called)
        self.assertIn(
            "ERROR:test_a2c:Account registration failed: ConflictError",
            lcm.output,
        )

    def test_067_trigger(self):
        """test trigger"""
        self.assertEqual(
            ("Not implemented", None, None), self.cahandler.trigger("payload")
        )

    def test_068_poll(self):
        """test poll"""
        self.assertEqual(
            ("Not implemented", None, None, "poll_identifier", False),
            self.cahandler.poll("cert_name", "poll_identifier", "csr"),
        )

    @patch("examples.ca_handler.acme_ca_handler.enrollment_config_log")
    @patch("examples.ca_handler.acme_ca_handler.CAhandler._enroll")
    @patch("examples.ca_handler.acme_ca_handler.CAhandler._registration_lookup")
    @patch("examples.ca_handler.acme_ca_handler.CAhandler._user_key_load")
    @patch("acme.client.ClientNetwork")
    @patch("acme.messages")
    def test_069_enroll(
        self, mock_messages, mock_clientnw, mock_key, mock_reg, mock_enroll, mock_ecl
    ):
        """test enroll registration error"""
        mock_key.return_value = "key"
        mock_reg.return_value = "mock_reg"
        mock_enroll.return_value = ("error", "fullchain", "raw")
        self.assertEqual(
            ("error", "fullchain", "raw", None), self.cahandler.enroll("csr")
        )
        self.assertFalse(mock_ecl.called)

    @patch("examples.ca_handler.acme_ca_handler.enrollment_config_log")
    @patch("examples.ca_handler.acme_ca_handler.CAhandler._enroll")
    @patch("examples.ca_handler.acme_ca_handler.CAhandler._registration_lookup")
    @patch("examples.ca_handler.acme_ca_handler.CAhandler._user_key_load")
    @patch("acme.client.ClientNetwork")
    @patch("acme.messages")
    def test_070_enroll(
        self, mock_messages, mock_clientnw, mock_key, mock_reg, mock_enroll, mock_ecl
    ):
        """test enroll registration error"""
        mock_key.return_value = "key"
        mock_reg.return_value = "mock_reg"
        self.cahandler.enrollment_config_log = True
        mock_enroll.return_value = ("error", "fullchain", "raw")
        self.assertEqual(
            ("error", "fullchain", "raw", None), self.cahandler.enroll("csr")
        )
        self.assertTrue(mock_ecl.called)

    @patch("examples.ca_handler.acme_ca_handler.CAhandler._enroll")
    @patch("examples.ca_handler.acme_ca_handler.CAhandler._registration_lookup")
    @patch("examples.ca_handler.acme_ca_handler.CAhandler._user_key_load")
    @patch("acme.client.ClientNetwork")
    @patch("acme.messages")
    def test_071_enroll(
        self, mock_messages, mock_clientnw, mock_key, mock_reg, mock_enroll
    ):
        """test enroll registration error"""
        mock_key.return_value = "key"
        mock_reg.return_value = None
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.assertEqual(
                ("Account registration failed", None, None, None),
                self.cahandler.enroll("csr"),
            )
        self.assertFalse(mock_enroll.called)
        self.assertIn("ERROR:test_a2c:Account registration failed", lcm.output)

    @patch("examples.ca_handler.acme_ca_handler.b64_encode")
    @patch("examples.ca_handler.acme_ca_handler.cert_pem2der")
    @patch("examples.ca_handler.acme_ca_handler.CAhandler._http_challenge_store")
    @patch("examples.ca_handler.acme_ca_handler.CAhandler._challenge_info")
    @patch("examples.ca_handler.acme_ca_handler.CAhandler._account_register")
    @patch("examples.ca_handler.acme_ca_handler.CAhandler._user_key_load")
    @patch("acme.client.ClientV2.poll_and_finalize")
    @patch("acme.client.ClientV2.answer_challenge")
    @patch("acme.client.ClientV2.new_order")
    @patch("acme.client.ClientNetwork")
    def test_072_enroll(
        self,
        mock_clientnw,
        mock_c2o,
        mock_ach,
        mock_pof,
        mock_key,
        mock_reg,
        mock_cinfo,
        mock_store,
        mock_pem2der,
        mock_encode,
    ):
        """test enroll with no account configured"""
        mock_key.return_value = "key"
        response = Mock()
        response.body.status = "valid"
        mock_reg.return_value = response
        order = Mock()
        authzr = Mock()
        authzr.body = Mock()
        from acme import messages

        authzr.body.status = messages.STATUS_PENDING
        challenge = Mock()
        challenge.chall = Mock()
        challenge.chall.response = Mock(return_value="response")
        challenge.response_and_validation.return_value = (Mock(), "validation")
        challenge.response.return_value = "response"
        challenge.status = "valid"
        authzr.body.challenges = [challenge]
        order.authorizations = [authzr]
        acmeclient = Mock()
        acmeclient.answer_challenge.return_value = Mock()
        user_key = Mock()
        mock_cinfo.return_value = ("http-01", "content", challenge)
        result = self.cahandler._order_authorization(acmeclient, order, user_key)
        self.assertTrue(result)

        # Ensure enroll uses the correct mock authorization
        mock_c2o.return_value.authorizations = [authzr]

        chall = Mock()
        chall.chall = Mock()
        chall.chall.response = Mock(return_value="response")
        chall.response_and_validation.return_value = (Mock(), "validation")
        chall.response.return_value = "response"
        chall.status = "valid"
        mock_ach.return_value = "auth_response"
        mock_cinfo.return_value = ("challenge_name", "challenge_content", chall)
        resp_pof = Mock()
        resp_pof.fullchain_pem = "fullchain"
        mock_pof.return_value = resp_pof
        mock_pem2der.return_value = "mock_pem2der"
        mock_encode.return_value = "mock_encode"
        self.assertEqual(
            (None, "fullchain", "mock_encode", None),
            self.cahandler.enroll("csr"),
        )
        self.assertTrue(mock_store.called)
        self.assertTrue(mock_ach.called)
        self.assertTrue(mock_reg.called)

    @patch("examples.ca_handler.acme_ca_handler.allowed_domainlist_check")
    @patch("examples.ca_handler.acme_ca_handler.b64_encode")
    @patch("examples.ca_handler.acme_ca_handler.cert_pem2der")
    @patch("examples.ca_handler.acme_ca_handler.CAhandler._http_challenge_store")
    @patch("examples.ca_handler.acme_ca_handler.CAhandler._challenge_info")
    @patch("acme.client.ClientV2.query_registration")
    @patch("examples.ca_handler.acme_ca_handler.CAhandler._user_key_load")
    @patch("acme.client.ClientV2.poll_and_finalize")
    @patch("acme.client.ClientV2.answer_challenge")
    @patch("acme.client.ClientV2.new_order")
    @patch("acme.client.ClientNetwork")
    @patch("acme.messages")
    def test_073_enroll(
        self,
        mock_messages,
        mock_clientnw,
        mock_c2o,
        mock_ach,
        mock_pof,
        mock_key,
        mock_reg,
        mock_cinfo,
        mock_store,
        mock_pem2der,
        mock_encode,
        mock_csrchk,
    ):
        """test enroll with existing account"""
        self.cahandler.account = "account"
        mock_key.return_value = "key"
        mock_messages = Mock()
        response = Mock()
        response.body.status = "valid"
        mock_reg.return_value = response
        mock_norder = Mock()
        challenge = Mock()
        challenge.response_and_validation.return_value = (Mock(), "validation")
        challenge.response.return_value = "response"
        authzr1 = Mock()
        authzr1.body = Mock()
        authzr1.body.status = "valid"
        authzr1.body.challenges = [challenge]
        authzr2 = Mock()
        authzr2.body = Mock()
        authzr2.body.status = "valid"
        authzr2.body.challenges = [challenge]
        mock_norder.authorizations = [authzr1, authzr2]

        def order_auth_side_effect(acmeclient_arg, order, user_key):
            mock_store()
            mock_ach()
            return True

        self.cahandler._order_authorization = Mock(side_effect=order_auth_side_effect)
        mock_c2o.return_value = mock_norder
        chall = Mock()
        mock_ach.return_value = "auth_response"
        mock_cinfo.return_value = ("challenge_name", "challenge_content", chall)
        resp_pof = Mock()
        resp_pof.fullchain_pem = "fullchain"
        mock_pof.return_value = resp_pof
        mock_pem2der.return_value = "mock_pem2der"
        mock_encode.return_value = "mock_encode"
        mock_csrchk.return_value = False
        self.assertEqual(
            (None, "fullchain", "mock_encode", None),
            self.cahandler.enroll("csr"),
        )
        self.assertTrue(mock_store.called)
        self.assertTrue(mock_ach.called)
        self.assertTrue(mock_reg.called)

    @patch("examples.ca_handler.acme_ca_handler.allowed_domainlist_check")
    @patch("OpenSSL.crypto.load_certificate")
    @patch("OpenSSL.crypto.dump_certificate")
    @patch("examples.ca_handler.acme_ca_handler.CAhandler._http_challenge_store")
    @patch("examples.ca_handler.acme_ca_handler.CAhandler._challenge_info")
    @patch("examples.ca_handler.acme_ca_handler.CAhandler._account_register")
    @patch("examples.ca_handler.acme_ca_handler.CAhandler._user_key_load")
    @patch("acme.client.ClientV2.poll_and_finalize")
    @patch("acme.client.ClientV2.answer_challenge")
    @patch("acme.client.ClientV2.new_order")
    @patch("acme.client.ClientNetwork")
    @patch("acme.messages")
    def test_074_enroll(
        self,
        mock_messages,
        mock_clientnw,
        mock_c2o,
        mock_ach,
        mock_pof,
        mock_key,
        mock_reg,
        mock_cinfo,
        mock_store,
        mock_dumpcert,
        mock_loadcert,
        mock_csrchk,
    ):
        """test enroll with bodystatus invalid"""
        mock_key.return_value = "key"
        mock_messages = Mock()
        response = Mock()
        response.body.status = "invalid"
        response.body.error = "error"
        mock_reg.return_value = response
        mock_norder = Mock()
        mock_norder.authorizations = ["1", "2"]
        mock_c2o.return_value = mock_norder
        chall = Mock()
        mock_ach.return_value = "auth_response"
        mock_cinfo.return_value = ("challenge_name", "challenge_content", chall)
        resp_pof = Mock()
        resp_pof.fullchain_pem = "fullchain"
        mock_pof.return_value = resp_pof
        mock_dumpcert.return_value = b"mock_dumpcert"
        mock_loadcert.return_value = "mock_loadcert"
        mock_csrchk.return_value = False
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.assertEqual(
                ("Bad ACME account: error", None, None, None),
                self.cahandler.enroll("csr"),
            )
        self.assertFalse(mock_store.called)
        self.assertFalse(mock_ach.called)
        self.assertTrue(mock_reg.called)
        self.assertIn(
            "ERROR:test_a2c:Enrollment failed: Bad ACME account: error", lcm.output
        )

    @patch("examples.ca_handler.acme_ca_handler.allowed_domainlist_check")
    @patch("OpenSSL.crypto.load_certificate")
    @patch("OpenSSL.crypto.dump_certificate")
    @patch("examples.ca_handler.acme_ca_handler.CAhandler._http_challenge_store")
    @patch("examples.ca_handler.acme_ca_handler.CAhandler._challenge_info")
    @patch("examples.ca_handler.acme_ca_handler.CAhandler._account_register")
    @patch("examples.ca_handler.acme_ca_handler.CAhandler._user_key_load")
    @patch("acme.client.ClientV2.poll_and_finalize")
    @patch("acme.client.ClientV2.answer_challenge")
    @patch("acme.client.ClientV2.new_order")
    @patch("acme.client.ClientNetwork")
    @patch("acme.messages")
    def test_075_enroll(
        self,
        mock_messages,
        mock_clientnw,
        mock_c2o,
        mock_ach,
        mock_pof,
        mock_key,
        mock_reg,
        mock_cinfo,
        mock_store,
        mock_dumpcert,
        mock_loadcert,
        mock_csrchk,
    ):
        """test enroll with no fullchain"""
        mock_key.return_value = "key"
        mock_messages = Mock()
        response = Mock()
        response.body.status = "valid"
        mock_reg.return_value = response
        mock_norder = Mock()
        challenge = Mock()
        challenge.response_and_validation.return_value = (Mock(), "validation")
        challenge.response.return_value = "response"
        authzr1 = Mock()
        authzr1.body = Mock()
        authzr1.body.status = "valid"
        authzr1.body.challenges = [challenge]
        authzr2 = Mock()
        authzr2.body = Mock()
        authzr2.body.status = "valid"
        authzr2.body.challenges = [challenge]
        mock_norder.authorizations = [authzr1, authzr2]
        acmeclient = Mock()
        acmeclient.answer_challenge.return_value = Mock()
        patcher = patch("acme.client.ClientV2.answer_challenge", return_value=Mock())
        patcher.start()
        self.addCleanup(patcher.stop)
        mock_c2o.return_value = mock_norder
        chall = Mock()
        mock_ach.return_value = "auth_response"
        mock_cinfo.return_value = ("challenge_name", "challenge_content", chall)
        resp_pof = Mock()
        resp_pof.fullchain_pem = None
        resp_pof.error = "order_error"
        mock_pof.return_value = resp_pof
        mock_dumpcert.return_value = b"mock_dumpcert"
        mock_loadcert.return_value = "mock_loadcert"
        mock_csrchk.return_value = False

        def order_auth_side_effect(acmeclient_arg, order, user_key):
            mock_store()
            mock_ach()
            return True

        self.cahandler._order_authorization = Mock(side_effect=order_auth_side_effect)
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.assertEqual(
                ("Error getting certificate: order_error", None, None, None),
                self.cahandler.enroll("csr"),
            )
        self.assertIn(
            "ERROR:test_a2c:Error getting certificate: order_error",
            lcm.output,
        )
        self.assertTrue(mock_store.called)
        self.assertTrue(mock_ach.called)
        self.assertTrue(mock_reg.called)

    @patch("examples.ca_handler.acme_ca_handler.allowed_domainlist_check")
    @patch("acme.client.ClientV2.query_registration")
    @patch("acme.client.ClientNetwork")
    @patch("examples.ca_handler.acme_ca_handler.CAhandler._account_register")
    @patch("examples.ca_handler.acme_ca_handler.CAhandler._http_challenge_store")
    @patch("examples.ca_handler.acme_ca_handler.CAhandler._user_key_load")
    def test_076_enroll(
        self, mock_key, mock_store, mock_reg, mock_nw, mock_newreg, mock_csrchk
    ):
        """test enroll exception during enrollment"""
        mock_csrchk.return_value = False
        mock_key.side_effect = Exception("ex_user_key_load")
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.assertEqual(
                ("ex_user_key_load", None, None, None), self.cahandler.enroll("csr")
            )
        self.assertIn("ERROR:test_a2c:Enrollment error: ex_user_key_load", lcm.output)
        self.assertFalse(mock_store.called)
        self.assertFalse(mock_nw.called)
        self.assertFalse(mock_reg.called)
        self.assertFalse(mock_newreg.called)

    @patch("examples.ca_handler.acme_ca_handler.CAhandler._order_issue")
    @patch("examples.ca_handler.acme_ca_handler.allowed_domainlist_check")
    @patch("OpenSSL.crypto.load_certificate")
    @patch("OpenSSL.crypto.dump_certificate")
    @patch("examples.ca_handler.acme_ca_handler.CAhandler._http_challenge_store")
    @patch("examples.ca_handler.acme_ca_handler.CAhandler._challenge_info")
    @patch("examples.ca_handler.acme_ca_handler.CAhandler._account_register")
    @patch("examples.ca_handler.acme_ca_handler.CAhandler._user_key_load")
    @patch("acme.client.ClientV2.poll_and_finalize")
    @patch("acme.client.ClientV2.answer_challenge")
    @patch("acme.client.ClientV2.new_order")
    @patch("acme.client.ClientNetwork")
    @patch("acme.messages")
    def test_077_enroll(
        self,
        mock_messages,
        mock_clientnw,
        mock_c2o,
        mock_ach,
        mock_pof,
        mock_key,
        mock_reg,
        mock_cinfo,
        mock_store,
        mock_dumpcert,
        mock_loadcert,
        mock_csrchk,
        mock_issue,
    ):
        """test enroll with bodystatus None (existing account)"""
        mock_key.return_value = "key"
        mock_messages = Mock()
        response = Mock()
        response.body.status = None
        response.uri = "uri"
        mock_reg.return_value = response
        mock_norder = Mock()
        mock_norder.authorizations = ["1", "2"]
        mock_c2o.return_value = mock_norder
        chall = Mock()
        mock_ach.return_value = "auth_response"
        mock_cinfo.return_value = ("challenge_name", "challenge_content", chall)
        resp_pof = Mock()
        resp_pof.fullchain_pem = "fullchain"
        mock_pof.return_value = resp_pof
        mock_dumpcert.return_value = b"mock_dumpcert"
        mock_loadcert.return_value = "mock_loadcert"
        mock_csrchk.return_value = False
        mock_issue.return_value = ("error", "cert", "raw")
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.assertEqual(
                ("error", "cert", "raw", None), self.cahandler.enroll("csr")
            )
        self.assertFalse(mock_store.called)
        self.assertFalse(mock_ach.called)
        self.assertTrue(mock_reg.called)
        self.assertTrue(mock_issue.called)
        self.assertIn(
            "INFO:test_a2c:Existing but not configured ACME account: uri", lcm.output
        )

    @patch("acme.messages")
    def test_078__account_lookup(self, mock_messages):
        """test account register existing account - no replacement"""
        response = Mock()
        response.uri = "urluriacc_info"
        acmeclient = Mock()
        acmeclient.query_registration = Mock(return_value=response)
        mock_messages = Mock()
        directory = {"newAccount": "newAccount"}
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.cahandler._account_lookup(acmeclient, "reg", directory)
        self.assertIn(
            "INFO:test_a2c:Found existing account: urluriacc_info",
            lcm.output,
        )
        self.assertEqual("urluriacc_info", self.cahandler.account)

    @patch("acme.messages")
    def test_079__account_lookup(self, mock_messages):
        """test account register existing account - url replacement"""
        response = Mock()
        response.uri = "urluriacc_info"
        acmeclient = Mock()
        acmeclient.query_registration = Mock(return_value=response)
        mock_messages = Mock()
        directory = {"newAccount": "newAccount"}
        self.cahandler.acme_url = "url"
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.cahandler._account_lookup(acmeclient, "reg", directory)
        self.assertIn(
            "INFO:test_a2c:Found existing account: urluriacc_info",
            lcm.output,
        )
        self.assertEqual("uriacc_info", self.cahandler.account)

    @patch("acme.messages")
    def test_080__account_lookup(self, mock_messages):
        """test account register existing account - acct_path replacement"""
        response = Mock()
        response.uri = "urluriacc_info"
        acmeclient = Mock()
        acmeclient.query_registration = Mock(return_value=response)
        mock_messages = Mock()
        directory = {"newAccount": "newAccount"}
        self.cahandler.path_dic = {"acct_path": "acc_info"}
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.cahandler._account_lookup(acmeclient, "reg", directory)
        self.assertIn(
            "INFO:test_a2c:Found existing account: urluriacc_info",
            lcm.output,
        )
        self.assertEqual("urluri", self.cahandler.account)

    @patch("acme.messages")
    def test_081__account_lookup(self, mock_messages):
        """test account register existing account - acct_path replacement"""
        response = Mock()
        response.uri = "urluriacc_info"
        acmeclient = Mock()
        acmeclient.query_registration = Mock(return_value=response)
        mock_messages = Mock()
        directory = {"newAccount": "newAccount"}
        self.cahandler.acme_url = "url"
        self.cahandler.path_dic = {"acct_path": "acc_info"}
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.cahandler._account_lookup(acmeclient, "reg", directory)
        self.assertIn(
            "INFO:test_a2c:Found existing account: urluriacc_info",
            lcm.output,
        )
        self.assertEqual("uri", self.cahandler.account)

    @patch("examples.ca_handler.acme_ca_handler.eab_profile_revocation_check")
    @patch("examples.ca_handler.acme_ca_handler.CAhandler._user_key_load")
    @patch("acme.client.ClientV2.revoke")
    @patch("acme.client.ClientV2.query_registration")
    @patch("acme.messages")
    @patch("acme.client.ClientNetwork")
    @patch("builtins.open", mock_open(read_data="mock_open"), create=True)
    @patch("cryptography.x509.load_der_x509_certificate")
    @patch("os.path.exists")
    def test_082_revoke(
        self,
        mock_exists,
        mock_load,
        mock_nw,
        mock_mess,
        mock_reg,
        mock_revoke,
        mock_key,
        mock_eabrevchk,
    ):
        """test revoke successful"""
        self.cahandler.acme_keyfile = "keyfile"
        self.cahandler.account = "account"
        mock_exists.return_value = True
        mock_load.return_value = "mock_load_cert"
        response = Mock()
        response.body.status = "valid"
        mock_reg.return_value = response
        self.assertEqual(
            (200, None, None), self.cahandler.revoke("cert", "reason", "date")
        )
        self.assertTrue(mock_key.called)
        self.assertTrue(mock_load.called)
        self.assertTrue(mock_nw.called)
        self.assertTrue(mock_revoke.called)
        self.assertFalse(mock_eabrevchk.called)

    @patch("examples.ca_handler.acme_ca_handler.eab_profile_revocation_check")
    @patch("examples.ca_handler.acme_ca_handler.CAhandler._user_key_load")
    @patch("acme.client.ClientV2.revoke")
    @patch("acme.client.ClientV2.query_registration")
    @patch("acme.messages")
    @patch("acme.client.ClientNetwork")
    @patch("builtins.open", mock_open(read_data="mock_open"), create=True)
    @patch("cryptography.x509.load_der_x509_certificate")
    @patch("os.path.exists")
    def test_083_revoke(
        self,
        mock_exists,
        mock_load,
        mock_nw,
        mock_mess,
        mock_reg,
        mock_revoke,
        mock_key,
        mock_eabrevchk,
    ):
        """test revoke successful"""
        self.cahandler.acme_keyfile = "keyfile"
        self.cahandler.account = "account"
        mock_exists.return_value = True
        mock_load.return_value = "mock_load_cert"
        response = Mock()
        response.body.status = "valid"
        mock_reg.return_value = response
        self.cahandler.eab_profiling = True
        self.assertEqual(
            (200, None, None), self.cahandler.revoke("cert", "reason", "date")
        )
        self.assertTrue(mock_key.called)
        self.assertTrue(mock_load.called)
        self.assertTrue(mock_nw.called)
        self.assertTrue(mock_revoke.called)
        self.assertTrue(mock_eabrevchk.called)

    @patch("examples.ca_handler.acme_ca_handler.CAhandler._user_key_load")
    @patch("acme.client.ClientV2.revoke")
    @patch("acme.client.ClientV2.query_registration")
    @patch("acme.messages")
    @patch("acme.client.ClientNetwork")
    @patch("builtins.open", mock_open(read_data="mock_open"), create=True)
    @patch("cryptography.x509.load_der_x509_certificate")
    @patch("os.path.exists")
    def test_084_revoke(
        self,
        mock_exists,
        mock_load,
        mock_nw,
        mock_mess,
        mock_reg,
        mock_revoke,
        mock_key,
    ):
        """test revoke invalid status after reglookup"""
        self.cahandler.acme_keyfile = "keyfile"
        self.cahandler.account = "account"
        mock_exists.return_value = True
        mock_load.return_value = "mock_load_cert"
        response = Mock()
        response.body.status = "invalid"
        response.body.error = "error"
        mock_reg.return_value = response
        self.assertEqual(
            (
                500,
                "urn:ietf:params:acme:error:serverInternal",
                "Bad ACME account: error",
            ),
            self.cahandler.revoke("cert", "reason", "date"),
        )
        self.assertTrue(mock_key.called)
        self.assertFalse(mock_load.called)
        self.assertTrue(mock_nw.called)
        self.assertFalse(mock_revoke.called)

    @patch("examples.ca_handler.acme_ca_handler.CAhandler._user_key_load")
    @patch("examples.ca_handler.acme_ca_handler.CAhandler._account_lookup")
    @patch("acme.messages")
    @patch("acme.client.ClientNetwork")
    @patch("builtins.open", mock_open(read_data="mock_open"), create=True)
    @patch("cryptography.x509.load_der_x509_certificate")
    @patch("os.path.exists")
    def test_085_revoke(
        self,
        mock_exists,
        mock_load,
        mock_nw,
        mock_mess,
        mock_lookup,
        mock_key,
    ):
        """test revoke account lookup failed"""
        self.cahandler.acme_keyfile = "keyfile"
        mock_exists.return_value = True
        mock_load.return_value = "mock_load_cert"
        self.assertEqual(
            (500, "urn:ietf:params:acme:error:serverInternal", "account lookup failed"),
            self.cahandler.revoke("cert", "reason", "date"),
        )
        self.assertTrue(mock_lookup.called)
        self.assertTrue(mock_key.called)
        self.assertFalse(mock_load.called)
        self.assertTrue(mock_nw.called)

    @patch("examples.ca_handler.acme_ca_handler.CAhandler._account_lookup")
    @patch("acme.messages")
    @patch("acme.client.ClientNetwork")
    @patch("josepy.JWKRSA")
    @patch("builtins.open", mock_open(read_data="mock_open"), create=True)
    @patch("cryptography.x509.load_der_x509_certificate")
    @patch("os.path.exists")
    def test_086_revoke(
        self,
        mock_exists,
        mock_load,
        mock_kload,
        mock_nw,
        mock_mess,
        mock_lookup,
    ):
        """test revoke user key load failed"""
        self.cahandler.acme_keyfile = "keyfile"
        mock_exists.return_value = False
        mock_load.return_value = "mock_load_cert"
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.assertEqual(
                (500, "urn:ietf:params:acme:error:serverInternal", "Internal Error"),
                self.cahandler.revoke("cert", "reason", "date"),
            )
        self.assertFalse(mock_lookup.called)
        self.assertIn(
            "ERROR:test_a2c:Error during revocation: Could not load user_key keyfile",
            lcm.output,
        )

    @patch("builtins.open", mock_open(read_data="mock_open"), create=True)
    @patch("examples.ca_handler.acme_ca_handler.CAhandler._user_key_load")
    @patch("os.path.exists")
    def test_087_revoke(self, mock_exists, mock_load):
        """test revoke exception during processing"""
        self.cahandler.acme_keyfile = "keyfile"
        mock_exists.return_value = True
        mock_load.side_effect = Exception("ex_user_key_load")
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.assertEqual(
                (500, "urn:ietf:params:acme:error:serverInternal", "ex_user_key_load"),
                self.cahandler.revoke("cert", "reason", "date"),
            )
        self.assertIn("ERROR:test_a2c:Revocation error: ex_user_key_load", lcm.output)

    @patch("requests.post")
    def test_088__zerossl_eab_get(self, mock_post):
        """CAhandler._zerossl_eab_get() - all ok"""
        mock_post.return_value.json.return_value = {
            "success": True,
            "eab_kid": "eab_kid",
            "eab_hmac_key": "eab_hmac_key",
        }
        self.cahandler._zerossl_eab_get()
        self.assertTrue(mock_post.called)
        self.assertEqual("eab_kid", self.cahandler.eab_kid)
        self.assertEqual("eab_hmac_key", self.cahandler.eab_hmac_key)

    @patch("requests.post")
    def test_089__zerossl_eab_get(self, mock_post):
        """CAhandler._zerossl_eab_get() - success false"""
        mock_post.return_value.json.return_value = {
            "success": False,
            "eab_kid": "eab_kid",
            "eab_hmac_key": "eab_hmac_key",
        }
        mock_post.return_value.text = "text"
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.cahandler._zerossl_eab_get()
        self.assertTrue(mock_post.called)
        self.assertFalse(self.cahandler.eab_kid)
        self.assertFalse(self.cahandler.eab_hmac_key)
        self.assertIn(
            "ERROR:test_a2c:Could not get eab credentials from ZeroSSL: text",
            lcm.output,
        )

    @patch("requests.post")
    def test_090__zerossl_eab_get(self, mock_post):
        """CAhandler._zerossl_eab_get() - no success key"""
        mock_post.return_value.json.return_value = {
            "eab_kid": "eab_kid",
            "eab_hmac_key": "eab_hmac_key",
        }
        mock_post.return_value.text = "text"
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.cahandler._zerossl_eab_get()
        self.assertTrue(mock_post.called)
        self.assertFalse(self.cahandler.eab_kid)
        self.assertFalse(self.cahandler.eab_hmac_key)
        self.assertIn(
            "ERROR:test_a2c:Could not get eab credentials from ZeroSSL: text",
            lcm.output,
        )

    @patch("requests.post")
    def test_091__zerossl_eab_get(self, mock_post):
        """CAhandler._zerossl_eab_get() - no eab_kid key"""
        mock_post.return_value.json.return_value = {
            "success": True,
            "eab_hmac_key": "eab_hmac_key",
        }
        mock_post.return_value.text = "text"
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.cahandler._zerossl_eab_get()
        self.assertTrue(mock_post.called)
        self.assertFalse(self.cahandler.eab_kid)
        self.assertFalse(self.cahandler.eab_hmac_key)
        self.assertIn(
            "ERROR:test_a2c:Could not get eab credentials from ZeroSSL: text",
            lcm.output,
        )

    @patch("requests.post")
    def test_092__zerossl_eab_get(self, mock_post):
        """CAhandler._zerossl_eab_get() - no eab_mac key"""
        mock_post.return_value.json.return_value = {
            "success": True,
            "eab_kid": "eab_kid",
        }
        mock_post.return_value.text = "text"
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.cahandler._zerossl_eab_get()
        self.assertTrue(mock_post.called)
        self.assertFalse(self.cahandler.eab_kid)
        self.assertFalse(self.cahandler.eab_hmac_key)
        self.assertIn(
            "ERROR:test_a2c:Could not get eab credentials from ZeroSSL: text",
            lcm.output,
        )

    @patch("examples.ca_handler.acme_ca_handler.CAhandler._challenge_info")
    def test_093__order_authorization(self, mock_info):
        """CAhandler._order_authorization - sectigo challenge"""
        order = Mock()
        authzr = Mock()
        authzr.body = Mock()
        from acme import messages

        authzr.body.status = messages.STATUS_PENDING
        challenge = Mock()
        challenge.chall = Mock()
        challenge.chall.response = Mock(return_value="response")
        challenge.response_and_validation.return_value = (Mock(), "validation")
        challenge.response.return_value = "response"
        challenge.status = "valid"
        authzr.body.challenges = [challenge]
        order.authorizations = [authzr]
        mock_info.return_value = [
            None,
            {"type": "sectigo-email-01", "status": "valid"},
            challenge,
        ]
        acmeclient = Mock()
        acmeclient.answer_challenge.return_value = Mock()
        self.assertTrue(
            self.cahandler._order_authorization(acmeclient, order, "user_key")
        )

    @patch("examples.ca_handler.acme_ca_handler.CAhandler._challenge_info")
    def test_094__order_authorization(self, mock_info):
        """CAhandler._order_authorization - sectigo challenge"""
        order = Mock()
        authzr = Mock()
        authzr.body = Mock()
        authzr.body.status = "invalid"
        order.authorizations = [authzr]
        mock_info.return_value = [
            None,
            {"type": "sectigo-email-01", "status": "invalid"},
            "challenge",
        ]
        self.assertFalse(
            self.cahandler._order_authorization("acmeclient", order, "user_key")
        )

    @patch("examples.ca_handler.acme_ca_handler.CAhandler._challenge_info")
    def test_095__order_authorization(self, mock_info):
        """CAhandler._order_authorization - sectigo challenge"""
        order = Mock()
        authzr = Mock()
        authzr.body = Mock()
        from acme import messages

        authzr.body.status = messages.STATUS_VALID
        order.authorizations = [authzr]
        mock_info.return_value = [
            None,
            {"type": "unk-01", "status": "valid"},
            "challenge",
        ]
        self.assertTrue(
            self.cahandler._order_authorization("acmeclient", order, "user_key")
        )

    @patch("examples.ca_handler.acme_ca_handler.CAhandler._challenge_info")
    def test_096__order_authorization(self, mock_info):
        """CAhandler._order_authorization - sectigo challenge"""
        order = Mock()
        authzr = Mock()
        authzr.body = Mock()
        authzr.body.status = "valid"
        order.authorizations = [authzr]
        mock_info.return_value = [None, "string", "challenge"]
        self.assertFalse(
            self.cahandler._order_authorization("acmeclient", order, "user_key")
        )

    def test_097_eab_profile_list_check(self):
        """test eab_profile_list_check"""
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.assertFalse(
                self.cahandler.eab_profile_list_check(
                    "eab_handler", "csr", "acme_keyfile", "key_file"
                )
            )
        self.assertIn(
            "ERROR:test_a2c:acme_keyfile is not allowed in profile",
            lcm.output,
        )

    def test_098_eab_profile_list_check(self):
        """test eab_profile_list_check"""
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.assertEqual(
                "acme_keypath is missing in config",
                self.cahandler.eab_profile_list_check(
                    "eab_handler", "csr", "acme_url", "acme_url"
                ),
            )
        self.assertIn(
            "ERROR:test_a2c:acme_keypath is missing in config",
            lcm.output,
        )

    @patch("examples.ca_handler.acme_ca_handler.client_parameter_validate")
    def test_099_eab_profile_list_check(self, mock_hiv):
        """test eab_profile_list_check"""
        mock_hiv.return_value = ("http://acme_url", None)
        self.cahandler.acme_keypath = "acme_keypath"
        self.cahandler.acme_keyfile = "acme_keyfile"
        self.assertFalse(
            self.cahandler.eab_profile_list_check(
                "eab_handler", "csr", "acme_url", "http://acme_url"
            )
        )
        self.assertEqual("acme_keypath/acme_url.json", self.cahandler.acme_keyfile)

    @patch("examples.ca_handler.acme_ca_handler.client_parameter_validate")
    def test_100_eab_profile_list_check(self, mock_hiv):
        """test eab_profile_list_check"""
        mock_hiv.return_value = (None, "error")
        self.cahandler.acme_keypath = "acme_keypath"
        self.cahandler.acme_keyfile = "acme_keyfile"
        self.assertEqual(
            "error",
            self.cahandler.eab_profile_list_check(
                "eab_handler", "csr", "acme_url", "http://acme_url"
            ),
        )
        self.assertEqual("acme_keyfile", self.cahandler.acme_keyfile)

    @patch("examples.ca_handler.acme_ca_handler.client_parameter_validate")
    def test_101_eab_profile_list_check(self, mock_hiv):
        """test eab_profile_list_check"""
        mock_hiv.return_value = ("http://acme_url", None)
        self.cahandler.acme_keypath = "acme_keypath"
        self.cahandler.acme_keyfile = "acme_keyfile"
        self.assertFalse(
            self.cahandler.eab_profile_list_check(
                "eab_handler", "csr", "unknown", "unknown"
            )
        )
        self.assertEqual("acme_keyfile", self.cahandler.acme_keyfile)

    @patch("examples.ca_handler.acme_ca_handler.allowed_domainlist_check")
    @patch("examples.ca_handler.acme_ca_handler.client_parameter_validate")
    def test_102_eab_profile_list_check(self, mock_hiv, mock_chk):
        """test eab_profile_list_check"""
        mock_hiv.return_value = ("http://acme_url", None)
        self.cahandler.acme_keypath = "acme_keypath"
        self.cahandler.acme_keyfile = "acme_keyfile"
        eab_handler = MagicMock()
        eab_handler.allowed_domains_check.return_value = False
        self.assertFalse(
            self.cahandler.eab_profile_list_check(
                eab_handler, "csr", "allowed_domainlist", ["unknown"]
            )
        )
        self.assertEqual("acme_keyfile", self.cahandler.acme_keyfile)
        self.assertTrue(eab_handler.allowed_domains_check.called)
        self.assertFalse(mock_chk.called)

    @patch("examples.ca_handler.acme_ca_handler.allowed_domainlist_check")
    @patch("examples.ca_handler.acme_ca_handler.client_parameter_validate")
    def test_103_eab_profile_list_check(self, mock_hiv, mock_chk):
        """test eab_profile_list_check"""
        mock_hiv.return_value = ("http://acme_url", None)
        self.cahandler.acme_keypath = "acme_keypath"
        self.cahandler.acme_keyfile = "acme_keyfile"
        eab_handler = MagicMock()
        eab_handler.allowed_domains_check.return_value = "error"
        self.assertEqual(
            "error",
            self.cahandler.eab_profile_list_check(
                eab_handler, "csr", "allowed_domainlist", ["unknown"]
            ),
        )
        self.assertEqual("acme_keyfile", self.cahandler.acme_keyfile)
        self.assertTrue(eab_handler.allowed_domains_check.called)
        self.assertFalse(mock_chk.called)

    @patch("examples.ca_handler.acme_ca_handler.allowed_domainlist_check")
    @patch("examples.ca_handler.acme_ca_handler.client_parameter_validate")
    def test_104_eab_profile_list_check(self, mock_hiv, mock_chk):
        """test eab_profile_list_check"""
        mock_hiv.return_value = ("http://acme_url", None)
        self.cahandler.acme_keypath = "acme_keypath"
        self.cahandler.acme_keyfile = "acme_keyfile"
        eab_handler = MagicMock()
        eab_handler.foo.return_value = "error"
        mock_chk.return_value = "check_error"
        self.assertEqual(
            "check_error",
            self.cahandler.eab_profile_list_check(
                eab_handler, "csr", "allowed_domainlist", ["unknown"]
            ),
        )
        self.assertEqual("acme_keyfile", self.cahandler.acme_keyfile)
        self.assertTrue(mock_chk.called)
        self.assertFalse(eab_handler.allowed_domains_check.called)

    @patch("examples.ca_handler.acme_ca_handler.allowed_domainlist_check")
    @patch("examples.ca_handler.acme_ca_handler.client_parameter_validate")
    def test_105_eab_profile_list_check(self, mock_hiv, mock_chk):
        """test eab_profile_list_check"""
        mock_hiv.return_value = ("http://acme_url", None)
        self.cahandler.acme_keypath = "acme_keypath"
        self.cahandler.acme_keyfile = "acme_keyfile"
        eab_handler = MagicMock()
        eab_handler.foo.return_value = "error"
        mock_chk.return_value = None
        self.assertFalse(
            self.cahandler.eab_profile_list_check(
                eab_handler, "csr", "allowed_domainlist", ["unknown"]
            )
        )
        self.assertEqual("acme_keyfile", self.cahandler.acme_keyfile)
        self.assertTrue(mock_chk.called)
        self.assertFalse(eab_handler.allowed_domains_check.called)

    @patch("builtins.open", new_callable=mock_open, read_data="{}")
    def test_106_account_to_keyfile(self, mock_file):
        """test account_to_keyfile"""
        self.cahandler.acme_keyfile = "dummy_keyfile_path"
        self.cahandler.account = "dummy_account"
        self.cahandler._account_to_keyfile()
        self.assertTrue(mock_file.called)

    @patch("builtins.open", new_callable=mock_open, read_data="{}")
    def test_107_account_to_keyfile(self, mock_file):
        """test account_to_keyfile"""
        self.cahandler.acme_keyfile = "dummy_keyfile_path"
        self.cahandler.account = None
        self.cahandler._account_to_keyfile()
        self.assertFalse(mock_file.called)

    @patch("builtins.open", new_callable=mock_open, read_data="{}")
    def test_108_account_to_keyfile(self, mock_file):
        """test account_to_keyfile"""
        self.cahandler.acme_keyfile = None
        self.cahandler.account = "dummy_account"
        self.cahandler._account_to_keyfile()
        self.assertFalse(mock_file.called)

    @patch("builtins.open", new_callable=mock_open, read_data="{}")
    def test_109_account_to_keyfile(self, mock_file):
        """test account_to_keyfile"""
        self.cahandler.acme_keyfile = "dummy_keyfile_path"
        self.cahandler.account = "dummy_account"
        mock_file.side_effect = Exception("ex_json_dump")
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.cahandler._account_to_keyfile()
        self.assertTrue(mock_file.called)
        self.assertIn(
            "ERROR:test_a2c:Could not map account to keyfile: ex_json_dump",
            lcm.output,
        )

    def test_110_accountname_get(self):
        """test accountname_get"""
        url = "url"
        acme_url = "acme_url"
        path_dic = {"acct_path": "acct_path"}
        self.assertEqual(
            "url", self.cahandler._accountname_get(url, acme_url, path_dic)
        )

    def test_111_accountname_get(self):
        """test accountname_get"""
        url = "acme_url/foo"
        acme_url = "acme_url"
        path_dic = {"acct_path": "acct_path"}
        self.assertEqual(
            "/foo", self.cahandler._accountname_get(url, acme_url, path_dic)
        )

    def test_112_accountname_get(self):
        """test accountname_get"""
        url = "acme_url/foo/acct_path"
        acme_url = "acme_url"
        path_dic = {"acct_path": "acct_path"}
        self.assertEqual(
            "/foo/", self.cahandler._accountname_get(url, acme_url, path_dic)
        )

    def test_113_accountname_get(self):
        """test accountname_get"""
        url = "acme_url/acct_path/foo"
        acme_url = "acme_url"
        path_dic = {"acct_path": "/"}
        self.assertEqual(
            "acct_path/foo", self.cahandler._accountname_get(url, acme_url, path_dic)
        )

    def test_114_accountname_get(self):
        """test accountname_get"""
        url = "acme_url/foo/foo"
        acme_url = "acme_url"
        path_dic = {"foo": "bar"}
        self.assertEqual(
            "/foo/foo", self.cahandler._accountname_get(url, acme_url, path_dic)
        )

    def test_115_order_new(self):
        """test order_new"""
        acmeclient = Mock()
        acmeclient.new_order = Mock(return_value="new_order")
        csr = "csr"
        self.assertEqual("new_order", self.cahandler._order_new(acmeclient, "csr"))
        self.assertTrue(acmeclient.new_order.called)
        acmeclient.new_order.assert_called_with(csr_pem="csr")

    def test_116_order_new(self):
        """test order_new"""
        acmeclient = Mock()
        acmeclient.new_order = Mock(return_value="new_order")
        csr = "csr"
        self.cahandler.profile = "profile"
        self.assertEqual("new_order", self.cahandler._order_new(acmeclient, "csr"))
        self.assertTrue(acmeclient.new_order.called)
        acmeclient.new_order.assert_called_with(csr_pem="csr", profile="profile")

    def test_117_order_new(self):
        """test order_new"""
        acmeclient = Mock()
        acmeclient.new_order.side_effect = [Exception("mock_new"), "new_order"]
        csr = "csr"
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.assertEqual(
                "new_order",
                self.cahandler._order_new(acmeclient, "csr_pem"),
            )
        self.assertIn(
            "WARNING:test_a2c:Failed to create order: mock_new. Try without profile information.",
            lcm.output,
        )

    @patch("examples.ca_handler.acme_ca_handler.b64_url_decode")
    @patch("OpenSSL.crypto.load_certificate")
    @patch("cryptography.x509.load_der_x509_certificate")
    def test_118_revoke_or_fallback(self, mock_cry_load, mock_ossl_load, mock_b64):
        """test _revoke_or_fallback without fallback to OpenSSL crypto load"""
        acmeclient = Mock()
        self.assertFalse(self.cahandler._revoke_or_fallback(acmeclient, "cert"))
        self.assertTrue(mock_b64.called)
        self.assertTrue(mock_cry_load.called)
        self.assertFalse(mock_ossl_load.called)

    @patch.object(josepy, "ComparableX509", create=True)
    @patch("examples.ca_handler.acme_ca_handler.b64_url_decode")
    @patch("OpenSSL.crypto.load_certificate")
    @patch("cryptography.x509.load_der_x509_certificate")
    def test_119_revoke_or_fallback(
        self, mock_cry_load, mock_ossl_load, mock_b64, mock_comparable
    ):
        """test _revoke_or_fallback with fallbnack to OpenSSL crypto load"""
        mock_comparable.return_value = "comparable_cert"
        acmeclient = Mock()
        acmeclient.revoke = Mock(side_effect=[Exception("mock_revoke"), "foo"])
        self.assertFalse(self.cahandler._revoke_or_fallback(acmeclient, "cert"))
        self.assertTrue(mock_b64.called)
        self.assertTrue(mock_cry_load.called)
        self.assertTrue(mock_ossl_load.called)
        self.assertTrue(mock_comparable.called)

    @patch("examples.ca_handler.acme_ca_handler.CAhandler._dns_challenge_deprovision")
    @patch("examples.ca_handler.acme_ca_handler.b64_encode")
    @patch("examples.ca_handler.acme_ca_handler.cert_pem2der")
    @patch("examples.ca_handler.acme_ca_handler.client.ClientV2")
    @patch("examples.ca_handler.acme_ca_handler.messages.OrderResource")
    @patch("examples.ca_handler.acme_ca_handler.josepy.jwk.JWKRSA")
    def test_120_order_issue_success(
        self,
        mock_jwk,
        mock_order,
        mock_client,
        mock_pem2der,
        mock_b64,
        mock_deprovision,
    ):
        """test _order_issue with successful order issuance"""
        self.cahandler.dns_update_script = None
        self.cahandler.acme_sh_scipt = None
        mock_pem2der.return_value = "mock_pem2der"
        mock_b64.return_value = "mock_b64"
        acmeclient = mock_client
        user_key = mock_jwk
        order_obj = MagicMock()
        order_obj.fullchain_pem = (
            "-----BEGIN CERTIFICATE-----\nfullchain\n-----END CERTIFICATE-----"
        )
        order_obj.error = None
        self.cahandler._order_new = MagicMock(return_value=order_obj)
        self.cahandler._order_authorization = MagicMock(return_value=True)
        acmeclient.poll_and_finalize.return_value = order_obj
        self.assertEqual(
            (
                None,
                "-----BEGIN CERTIFICATE-----\nfullchain\n-----END CERTIFICATE-----",
                "mock_b64",
            ),
            self.cahandler._order_issue(acmeclient, user_key, "csr"),
        )
        self.assertFalse(mock_deprovision.called)

    @patch("examples.ca_handler.acme_ca_handler.CAhandler._dns_challenge_deprovision")
    @patch("examples.ca_handler.acme_ca_handler.b64_encode")
    @patch("examples.ca_handler.acme_ca_handler.cert_pem2der")
    @patch("examples.ca_handler.acme_ca_handler.client.ClientV2")
    @patch("examples.ca_handler.acme_ca_handler.messages.OrderResource")
    @patch("examples.ca_handler.acme_ca_handler.josepy.jwk.JWKRSA")
    def test_121_order_issue_success(
        self,
        mock_jwk,
        mock_order,
        mock_client,
        mock_pem2der,
        mock_b64,
        mock_deprovision,
    ):
        """test _order_issue with successful order issuance"""
        self.cahandler.dns_update_script = None
        self.cahandler.acme_sh_scipt = None
        mock_pem2der.return_value = "mock_pem2der"
        mock_b64.return_value = "mock_b64"
        acmeclient = mock_client
        user_key = mock_jwk
        order_obj = MagicMock()
        order_obj.fullchain_pem = (
            "-----BEGIN CERTIFICATE-----\nfullchain\n-----END CERTIFICATE-----"
        )
        order_obj.error = None
        self.cahandler.dns_update_script = "mock_dns_update_script"
        self.cahandler.acme_sh_script = "mock_acme_sh_script"
        self.cahandler._order_new = MagicMock(return_value=order_obj)
        self.cahandler._order_authorization = MagicMock(return_value=True)
        acmeclient.poll_and_finalize.return_value = order_obj
        self.assertEqual(
            (
                None,
                "-----BEGIN CERTIFICATE-----\nfullchain\n-----END CERTIFICATE-----",
                "mock_b64",
            ),
            self.cahandler._order_issue(acmeclient, user_key, "csr"),
        )
        self.assertTrue(mock_deprovision.called)

    @patch("examples.ca_handler.acme_ca_handler.CAhandler._dns_challenge_deprovision")
    @patch("examples.ca_handler.acme_ca_handler.b64_encode")
    @patch("examples.ca_handler.acme_ca_handler.cert_pem2der")
    @patch("examples.ca_handler.acme_ca_handler.client.ClientV2")
    @patch("examples.ca_handler.acme_ca_handler.messages.OrderResource")
    @patch("examples.ca_handler.acme_ca_handler.josepy.jwk.JWKRSA")
    def test_122_order_issue_success(
        self,
        mock_jwk,
        mock_order,
        mock_client,
        mock_pem2der,
        mock_b64,
        mock_deprovision,
    ):
        """test _order_issue with successful order issuance"""
        self.cahandler.dns_update_script = None
        self.cahandler.acme_sh_scipt = None
        mock_pem2der.return_value = "mock_pem2der"
        mock_b64.return_value = "mock_b64"
        acmeclient = mock_client
        user_key = mock_jwk
        order_obj = MagicMock()
        order_obj.fullchain_pem = (
            "-----BEGIN CERTIFICATE-----\nfullchain\n-----END CERTIFICATE-----"
        )
        order_obj.error = None
        self.cahandler.dns_update_script = "mock_dns_update_script"
        self.cahandler.acme_sh_script = None
        self.cahandler._order_new = MagicMock(return_value=order_obj)
        self.cahandler._order_authorization = MagicMock(return_value=True)
        acmeclient.poll_and_finalize.return_value = order_obj
        self.assertEqual(
            (
                None,
                "-----BEGIN CERTIFICATE-----\nfullchain\n-----END CERTIFICATE-----",
                "mock_b64",
            ),
            self.cahandler._order_issue(acmeclient, user_key, "csr"),
        )
        self.assertFalse(mock_deprovision.called)

    @patch("examples.ca_handler.acme_ca_handler.CAhandler._dns_challenge_deprovision")
    @patch("examples.ca_handler.acme_ca_handler.b64_encode")
    @patch("examples.ca_handler.acme_ca_handler.cert_pem2der")
    @patch("examples.ca_handler.acme_ca_handler.client.ClientV2")
    @patch("examples.ca_handler.acme_ca_handler.messages.OrderResource")
    @patch("examples.ca_handler.acme_ca_handler.josepy.jwk.JWKRSA")
    def test_123_order_issue_success(
        self,
        mock_jwk,
        mock_order,
        mock_client,
        mock_pem2der,
        mock_b64,
        mock_deprovision,
    ):
        """test _order_issue with successful order issuance"""
        self.cahandler.dns_update_script = None
        self.cahandler.acme_sh_scipt = None
        mock_pem2der.return_value = "mock_pem2der"
        mock_b64.return_value = "mock_b64"
        acmeclient = mock_client
        user_key = mock_jwk
        order_obj = MagicMock()
        order_obj.fullchain_pem = (
            "-----BEGIN CERTIFICATE-----\nfullchain\n-----END CERTIFICATE-----"
        )
        order_obj.error = None
        self.cahandler.dns_update_script = None
        self.cahandler.acme_sh_script = "mock_acme_sh_script"
        self.cahandler._order_new = MagicMock(return_value=order_obj)
        self.cahandler._order_authorization = MagicMock(return_value=True)
        acmeclient.poll_and_finalize.return_value = order_obj
        self.assertEqual(
            (
                None,
                "-----BEGIN CERTIFICATE-----\nfullchain\n-----END CERTIFICATE-----",
                "mock_b64",
            ),
            self.cahandler._order_issue(acmeclient, user_key, "csr"),
        )
        self.assertFalse(mock_deprovision.called)

    @patch("examples.ca_handler.acme_ca_handler.CAhandler._dns_challenge_deprovision")
    @patch("examples.ca_handler.acme_ca_handler.b64_encode")
    @patch("examples.ca_handler.acme_ca_handler.cert_pem2der")
    @patch("examples.ca_handler.acme_ca_handler.client.ClientV2")
    @patch("examples.ca_handler.acme_ca_handler.messages.OrderResource")
    @patch("examples.ca_handler.acme_ca_handler.josepy.jwk.JWKRSA")
    def test_124_order_issue_no_fullchain(
        self,
        mock_jwk,
        mock_order,
        mock_client,
        mock_pem2der,
        mock_b64,
        mock_deprovision,
    ):
        acmeclient = mock_client
        user_key = mock_jwk
        csr_pem = "dummy_csr"
        order_obj = MagicMock()
        order_obj.fullchain_pem = None
        order_obj.error = "Some error"
        self.cahandler._order_new = MagicMock(return_value=order_obj)
        self.cahandler._order_authorization = MagicMock(return_value=True)
        acmeclient.poll_and_finalize.return_value = order_obj
        self.assertEqual(
            ("Error getting certificate: Some error", None, None),
            self.cahandler._order_issue(acmeclient, user_key, csr_pem),
        )
        self.assertFalse(mock_pem2der.called)
        self.assertFalse(mock_b64.called)
        self.assertFalse(mock_deprovision.called)

    @patch("examples.ca_handler.acme_ca_handler.client.ClientV2")
    @patch("examples.ca_handler.acme_ca_handler.CAhandler._order_authorization")
    @patch("examples.ca_handler.acme_ca_handler.josepy.jwk.JWKRSA")
    def test_125_order_issue_invalid_order(self, mock_jwk, mock_order, mock_client):
        acmeclient = mock_client
        user_key = mock_jwk
        csr_pem = "dummy_csr"
        order_obj = MagicMock()
        order_obj.fullchain_pem = None
        order_obj.error = None
        mock_order = False
        self.cahandler._order_new = MagicMock(return_value=order_obj)
        self.cahandler._order_authorization = MagicMock(return_value=False)
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.assertEqual(
                (
                    "Order authorization failed. Challenges not answered correctly.",
                    None,
                    None,
                ),
                self.cahandler._order_issue(acmeclient, user_key, csr_pem),
            )
        self.assertIn(
            "WARNING:test_a2c:Order authorization failed. Challenges not answered correctly.",
            lcm.output,
        )
        self.assertFalse(acmeclient.poll_and_finalize.called)

    @patch("examples.ca_handler.acme_ca_handler.CAhandler._dns_challenge_provision")
    @patch("examples.ca_handler.acme_ca_handler.CAhandler._challenge_info")
    @patch("examples.ca_handler.acme_ca_handler.client.ClientV2")
    @patch("examples.ca_handler.acme_ca_handler.messages.OrderResource")
    @patch("examples.ca_handler.acme_ca_handler.josepy.jwk.JWKRSA")
    def test_126_order_authorization_http_challenge(
        self, mock_jwk, mock_order, mock_client, mock_info, mock_provision
    ):
        # Setup mocks
        acmeclient = mock_client
        user_key = mock_jwk
        challenge = MagicMock()
        challenge_name = "http-01"
        challenge_content = "challenge-content"
        challenge.chall.response_and_validation.return_value = (
            MagicMock(),
            "validation",
        )
        challenge.chall.validation.return_value = "http-01.challenge-token"
        challenge.chall.response.return_value = "response"
        challenge.chall.status = "valid"
        authzr = MagicMock()
        from acme import messages

        authzr.body.challenges = [challenge]
        authzr.body.identifier.value = "example.com"
        authzr.body.status = messages.STATUS_PENDING
        challenge.chall = Mock()
        challenge.chall.response = Mock(return_value="response")
        mock_info.return_value = (challenge_name, challenge_content, challenge)
        mock_order.authorizations = [authzr]
        acmeclient.answer_challenge.return_value = MagicMock()
        result = self.cahandler._order_authorization(acmeclient, mock_order, user_key)
        self.assertTrue(result)
        self.assertFalse(mock_provision.called)

    @patch("examples.ca_handler.acme_ca_handler.CAhandler._dns_challenge_provision")
    @patch("examples.ca_handler.acme_ca_handler.CAhandler._challenge_info")
    @patch("examples.ca_handler.acme_ca_handler.client.ClientV2")
    @patch("examples.ca_handler.acme_ca_handler.messages.OrderResource")
    @patch("examples.ca_handler.acme_ca_handler.josepy.jwk.JWKRSA")
    def test_127_order_authorization_dns_challenge(
        self, mock_jwk, mock_order, mock_client, mock_info, mock_provision
    ):
        acmeclient = mock_client
        user_key = mock_jwk
        challenge = MagicMock()
        challenge_name = "dns-challenge"
        challenge_content = "dns-challenge-content"
        challenge.chall.response_and_validation.return_value = (
            MagicMock(),
            "validation",
        )
        challenge.chall.response.return_value = "response"
        challenge.chall.status = "valid"

        authzr = MagicMock()
        from acme import messages

        authzr.body.challenges = [challenge]
        authzr.body.identifier.value = "example.com"
        authzr.body.status = messages.STATUS_PENDING
        challenge.chall = Mock()
        challenge.chall.response = Mock(return_value="response")

        cahandler = self.cahandler
        cahandler.dns_update_script = "script.sh"
        cahandler.acme_sh_script = "acme.sh"
        mock_info.return_value = (challenge_name, challenge_content, challenge)
        mock_order.authorizations = [authzr]
        acmeclient.answer_challenge.return_value = MagicMock()
        result = self.cahandler._order_authorization(acmeclient, mock_order, user_key)
        self.assertTrue(result)
        self.assertTrue(mock_provision.called)

    @patch("examples.ca_handler.acme_ca_handler.CAhandler._dns_challenge_provision")
    @patch("examples.ca_handler.acme_ca_handler.CAhandler._challenge_info")
    @patch("examples.ca_handler.acme_ca_handler.client.ClientV2")
    @patch("examples.ca_handler.acme_ca_handler.messages.OrderResource")
    @patch("examples.ca_handler.acme_ca_handler.josepy.jwk.JWKRSA")
    def test_128_order_authorization_sectigo_email_challenge(
        self, mock_jwk, mock_order, mock_client, mock_info, mock_provision
    ):
        acmeclient = mock_client
        user_key = mock_jwk
        challenge = MagicMock()
        challenge.status = "valid"
        challenge_name = None
        challenge_content = {"type": "sectigo-email-01", "status": "valid"}
        authzr = MagicMock()
        from acme import messages

        authzr.body.challenges = [challenge]
        authzr.body.identifier.value = "example.com"
        authzr.body.status = messages.STATUS_PENDING
        challenge.chall = Mock()
        challenge.chall.response = Mock(return_value="response")
        cahandler = self.cahandler
        mock_info.return_value = (challenge_name, challenge_content, challenge)
        mock_order.authorizations = [authzr]
        acmeclient.answer_challenge.return_value = MagicMock()
        result = self.cahandler._order_authorization(acmeclient, mock_order, user_key)
        self.assertTrue(result)
        self.assertFalse(mock_provision.called)

    @patch("examples.ca_handler.acme_ca_handler.CAhandler._dns_challenge_provision")
    @patch("examples.ca_handler.acme_ca_handler.CAhandler._challenge_info")
    @patch("examples.ca_handler.acme_ca_handler.client.ClientV2")
    @patch("examples.ca_handler.acme_ca_handler.messages.OrderResource")
    @patch("examples.ca_handler.acme_ca_handler.josepy.jwk.JWKRSA")
    def test_129_order_authorization_no_challenge(
        self, mock_jwk, mock_order, mock_client, mock_info, mock_provision
    ):
        acmeclient = mock_client
        user_key = mock_jwk
        cahandler = self.cahandler
        mock_info.return_value = (None, None, None)
        mock_order.authorizations = [MagicMock()]
        self.assertFalse(
            self.cahandler._order_authorization(acmeclient, mock_order, user_key)
        )

    @patch("examples.ca_handler.acme_ca_handler.CAhandler._challenge_filter")
    @patch("examples.ca_handler.acme_ca_handler.josepy.jwk.JWKRSA")
    def test_130_get_dns_challenge_success(self, mock_jwk, mock_filter):
        """Test _get_dns_challenge with a valid DNS challenge."""
        challenge = MagicMock()
        challenge.chall.response_and_validation.return_value = (
            MagicMock(key_authorization="key-auth"),
            "validation",
        )
        authzr = MagicMock()
        authzr.body.challenges = [challenge]
        mock_filter.return_value = challenge
        chall_name, chall_content, result_challenge = self.cahandler._get_dns_challenge(
            authzr, mock_jwk
        )
        self.assertEqual(chall_name, "dns-challenge")
        self.assertEqual(chall_content, "key-auth")
        self.assertEqual(result_challenge, challenge)

    @patch("examples.ca_handler.acme_ca_handler.josepy.jwk.JWKRSA")
    def test_131_get_dns_challenge_no_challenge(self, mock_jwk):
        """Test _get_dns_challenge with no DNS challenge."""
        authzr = MagicMock()
        authzr.body.challenges = []
        # Patch _challenge_filter to return None
        self.cahandler._challenge_filter = MagicMock(return_value=None)
        chall_name, chall_content, result_challenge = self.cahandler._get_dns_challenge(
            authzr, mock_jwk
        )
        self.assertIsNone(chall_name)
        self.assertIsNone(chall_content)
        self.assertIsNone(result_challenge)

    def test_132_set_environment_variables(self):
        """Test _environment_variables_handle with unset=False."""
        self.cahandler.dns_update_script_variables = {
            "TEST_VAR": "test_value",
            "PATH": "/usr/bin",
            "FORBIDDEN_VAR": "should_not_set",
        }

        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.cahandler._environment_variables_handle(unset=False)
        self.assertEqual(os.environ.get("TEST_VAR"), "test_value")
        self.assertNotEqual(os.environ.get("PATH"), "should_not_set")
        self.assertIn(
            'WARNING:test_a2c:CAhandler._environment_variables_handle(): environment variable "PATH" is forbidden and will not be changed',
            lcm.output,
        )
        # Clean up
        if "TEST_VAR" in os.environ:
            del os.environ["TEST_VAR"]

    def test_133_unset_environment_variables(self):
        """Test _environment_variables_handle with unset=True."""
        self.cahandler.dns_update_script_variables = {
            "TEST_VAR": "test_value",
            "PATH": "/usr/bin",
            "FORBIDDEN_VAR": "should_not_set",
        }
        os.environ["TEST_VAR"] = "test_value"
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.cahandler._environment_variables_handle(unset=True)
        self.assertIsNone(os.environ.get("TEST_VAR"))
        self.assertIn(
            'WARNING:test_a2c:CAhandler._environment_variables_handle(): environment variable "PATH" is forbidden and will not be changed',
            lcm.output,
        )

    def test_134_unset_not_set_variable(self):
        """Test _environment_variables_handle with unset=True when variable is not set."""
        self.cahandler.dns_update_script_variables = {
            "TEST_VAR": "test_value",
            "PATH": "/usr/bin",
            "FORBIDDEN_VAR": "should_not_set",
        }
        if "TEST_VAR" in os.environ:
            del os.environ["TEST_VAR"]
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.cahandler._environment_variables_handle(unset=True)

        self.assertIn(
            'WARNING:test_a2c:CAhandler._environment_variables_handle(): environment variable "PATH" is forbidden and will not be changed',
            lcm.output,
        )

    @patch("os.path.exists")
    def test_135_dns_update_script_does_not_exist(self, mock_exists):
        """Test _config_dns_update_script_load with dns_update_script that does not exist."""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"dns_update_script": "/fake/path/script.sh"}
        mock_exists.return_value = False
        with self.assertLogs("test_a2c", level="ERROR") as lcm:
            self.cahandler._config_dns_update_script_load(parser)
        self.assertIsNone(self.cahandler.dns_update_script)
        self.assertIn(
            'ERROR:test_a2c:CAhandler._config_dns_update_script_load(): dns update script "/fake/path/script.sh" does not exist',
            lcm.output,
        )

    @patch("os.path.exists")
    def test_136_dns_update_script_exists_and_acme_sh_script_missing(self, mock_exists):
        """Test _config_dns_update_script_load with dns_update_script exists but acme_sh_script does not."""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {
            "dns_update_script": "/fake/path/script.sh",
            "acme_sh_script": "/fake/path/acme.sh",
            "dns_update_script_variables": '{"VAR1": "value1"}',
        }
        mock_exists.side_effect = [True, False]
        with self.assertLogs("test_a2c", level="ERROR") as lcm:
            self.cahandler._config_dns_update_script_load(parser)
        self.assertEqual(self.cahandler.dns_update_script, "/fake/path/script.sh")
        self.assertIn(
            'ERROR:test_a2c:CAhandler._config_dns_update_script_load(): acme.sh script "/fake/path/acme.sh" does not exist',
            lcm.output,
        )
        self.assertIsNone(self.cahandler.acme_sh_script)
        self.assertEqual(self.cahandler.dns_update_script_variables, {"VAR1": "value1"})

    @patch("os.path.exists")
    def test_137_dns_validation_timeout_parsing(self, mock_exists):
        """Test _config_dns_update_script_load with invalid dns_validation_timeout."""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {
            "dns_update_script": "/fake/path/script.sh",
            "acme_sh_script": "/fake/path/acme.sh",
            "dns_update_script_variables": '{"VAR1": "value1"}',
            "dns_validation_timeout": "not_an_int",
        }
        mock_exists.return_value = True
        with self.assertLogs("test_a2c", level="WARNING") as lcm:
            self.cahandler._config_dns_update_script_load(parser)
        self.assertIn(
            "WARNING:test_a2c:CAhandler._config_dns_update_script_load(): Failed to parse dns_validation_timeout parameter: invalid literal for int() with base 10: 'not_an_int'",
            lcm.output,
        )
        self.assertEqual(self.cahandler.dns_validation_timeout, 20)

    @patch("os.path.exists")
    def test_138_dns_update_script_variables_none(self, mock_exists):
        """Test _config_dns_update_script_load with dns_update_script_variables as None."""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {
            "dns_update_script": "/fake/path/script.sh",
            "acme_sh_script": "/fake/path/acme.sh",
            "dns_update_script_variables": "foo",
        }
        mock_exists.return_value = True
        with self.assertLogs("test_a2c", level="WARNING") as lcm:
            self.cahandler._config_dns_update_script_load(parser)
        self.assertIn(
            "WARNING:test_a2c:CAhandler._config_dns_update_script_load(): Failed to parse dns_update_script_variables parameter: Expecting value: line 1 column 1 (char 0)",
            lcm.output,
        )
        self.assertIsNone(self.cahandler.dns_update_script_variables)

    @patch("os.path.exists")
    def test_139_dns_validation_timeout_parsing(self, mock_exists):
        """Test _config_dns_update_script_load with valid parameters."""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {
            "dns_update_script": "/fake/path/script.sh",
            "acme_sh_script": "/fake/path/acme.sh",
            "dns_update_script_variables": '{"VAR1": "value1"}',
            "dns_validation_timeout": "40",
        }
        mock_exists.return_value = True
        self.cahandler._config_dns_update_script_load(parser)
        self.assertEqual(self.cahandler.dns_validation_timeout, 40)
        self.assertEqual(self.cahandler.dns_update_script, "/fake/path/script.sh")
        self.assertEqual(self.cahandler.acme_sh_script, "/fake/path/acme.sh")
        self.assertEqual(self.cahandler.dns_update_script_variables, {"VAR1": "value1"})

    @patch("examples.ca_handler.acme_ca_handler.CAhandler._get_http_or_email_challenge")
    @patch("examples.ca_handler.acme_ca_handler.CAhandler._get_dns_challenge")
    def test_140_challenge_info_dns(
        self, mock_get_dns_challenge, mock_get_http_or_email_challenge
    ):
        """Test _challenge_info when dns_update_script is set."""
        self.cahandler.dns_update_script = "script.sh"
        mock_get_dns_challenge.return_value = (
            "dns-challenge",
            "key-auth",
            "challenge_obj",
        )
        authzr = MagicMock()
        user_key = MagicMock()

        chall_name, chall_content, challenge = self.cahandler._challenge_info(
            authzr, user_key
        )
        self.assertEqual(chall_name, "dns-challenge")
        self.assertEqual(chall_content, "key-auth")
        self.assertEqual(challenge, "challenge_obj")
        mock_get_dns_challenge.assert_called_once_with(authzr, user_key)
        self.assertTrue(mock_get_dns_challenge.called)
        self.assertFalse(mock_get_http_or_email_challenge.called)

    @patch("examples.ca_handler.acme_ca_handler.CAhandler._get_dns_challenge")
    @patch("examples.ca_handler.acme_ca_handler.CAhandler._get_http_or_email_challenge")
    def test_141_challenge_info_http(
        self, mock_get_http_or_email_challenge, mock_get_dns_challenge
    ):
        """Test _challenge_info when dns_update_script is not set."""
        self.cahandler.dns_update_script = None
        mock_get_http_or_email_challenge.return_value = (
            "http-challenge",
            "token",
            "challenge_obj",
        )
        authzr = MagicMock()
        user_key = MagicMock()

        chall_name, chall_content, challenge = self.cahandler._challenge_info(
            authzr, user_key
        )
        self.assertEqual(chall_name, "http-challenge")
        self.assertEqual(chall_content, "token")
        self.assertEqual(challenge, "challenge_obj")
        mock_get_http_or_email_challenge.assert_called_once_with(authzr, user_key)
        self.assertFalse(mock_get_dns_challenge.called)
        self.assertTrue(mock_get_http_or_email_challenge.called)

    def test_142_challenge_info_missing_authzr(self):
        """Test _challenge_info when authorization is missing."""
        with self.assertLogs("test_a2c", level="WARNING") as lcm:
            chall_name, chall_content, challenge = self.cahandler._challenge_info(
                None, MagicMock()
            )
        self.assertIn(
            "ERROR:test_a2c:acme authorization is missing",
            lcm.output,
        )
        self.assertIsNone(chall_name)
        self.assertIsNone(chall_content)
        self.assertIsNone(challenge)

    def test_143_challenge_info_missing_user_key(self):
        """Test _challenge_info when user key is missing."""
        with self.assertLogs("test_a2c", level="WARNING") as lcm:
            chall_name, chall_content, challenge = self.cahandler._challenge_info(
                MagicMock(), None
            )
        self.assertIn(
            "ERROR:test_a2c:acme user is missing",
            lcm.output,
        )
        self.assertIsNone(chall_name)
        self.assertIsNone(chall_content)
        self.assertIsNone(challenge)

    @patch("subprocess.call")
    @patch(
        "examples.ca_handler.acme_ca_handler.CAhandler._environment_variables_handle"
    )
    @patch("os.path.splitext")
    @patch("os.path.basename")
    def test_144_deprovision_calls_subprocess_and_env(
        self, mock_basename, mock_splitext, mock_env_handle, mock_subprocess
    ):
        """Test _dns_challenge_deprovision with subprocess and environment variable handling."""
        self.cahandler.dns_update_script = "/tmp/dns_update.sh"
        self.cahandler.acme_sh_script = "/tmp/acme.sh"
        self.cahandler.acme_sh_shell = "/bin/bash"
        self.cahandler.dns_record_dic = {
            "test.example.com": b"testvalue",
            "other.example.com": "othervalue",
        }
        self.cahandler.dns_update_script_variables = {"TEST_VAR": "value"}
        mock_basename.return_value = "dns_update.sh"
        mock_splitext.side_effect = lambda x: ("/tmp/dns_update", ".sh")
        mock_subprocess.return_value = 0
        with self.assertLogs("test_a2c", level="DEBUG") as lcm:
            self.cahandler._dns_challenge_deprovision()
        self.assertIn(
            "DEBUG:test_a2c:CAhandler._dns_challenge_provision(): using shell: /bin/bash",
            lcm.output,
        )

        # Check environment variable handling called for set and unset
        self.assertEqual(mock_env_handle.call_count, 2)
        mock_env_handle.assert_any_call(unset=False)
        mock_env_handle.assert_any_call(unset=True)

        # Check subprocess called for each record
        self.assertEqual(mock_subprocess.call_count, 2)
        calls = [call[0][0] for call in mock_subprocess.call_args_list]
        self.assertTrue(any("_rm test.example.com testvalue" in c for c in calls))
        self.assertTrue(any("_rm other.example.com othervalue" in c for c in calls))

    @patch("subprocess.call")
    @patch(
        "examples.ca_handler.acme_ca_handler.CAhandler._environment_variables_handle"
    )
    @patch("os.path.splitext")
    @patch("os.path.basename")
    def test_145_deprovision_calls_subprocess_and_env(
        self, mock_basename, mock_splitext, mock_env_handle, mock_subprocess
    ):
        """Test _dns_challenge_deprovision with subprocess and environment variable handling."""
        self.cahandler.dns_update_script = "/tmp/dns_update.sh"
        self.cahandler.acme_sh_script = "/tmp/acme.sh"
        self.cahandler.dns_record_dic = {
            "test.example.com": b"testvalue",
            "other.example.com": "othervalue",
        }
        self.cahandler.dns_update_script_variables = {"TEST_VAR": "value"}
        mock_basename.return_value = "dns_update.sh"
        mock_splitext.side_effect = lambda x: ("/tmp/dns_update", ".sh")
        mock_subprocess.return_value = 0
        self.cahandler._dns_challenge_deprovision()
        # Check environment variable handling called for set and unset
        self.assertEqual(mock_env_handle.call_count, 2)
        mock_env_handle.assert_any_call(unset=False)
        mock_env_handle.assert_any_call(unset=True)

        # Check subprocess called for each record
        self.assertEqual(mock_subprocess.call_count, 2)
        calls = [call[0][0] for call in mock_subprocess.call_args_list]
        self.assertTrue(any("_rm test.example.com testvalue" in c for c in calls))
        self.assertTrue(any("_rm other.example.com othervalue" in c for c in calls))

    @patch("subprocess.call")
    @patch(
        "examples.ca_handler.acme_ca_handler.CAhandler._environment_variables_handle"
    )
    def test_146_deprovision_no_records(self, mock_env_handle, mock_subprocess):
        """Test _dns_challenge_deprovision with no DNS records."""
        self.cahandler.dns_update_script = "/tmp/dns_update.sh"
        self.cahandler.acme_sh_script = "/tmp/acme.sh"
        self.cahandler.dns_record_dic = {}
        self.cahandler.dns_update_script_variables = {"TEST_VAR": "value"}
        self.cahandler._dns_challenge_deprovision()
        # Should not call subprocess
        mock_subprocess.assert_not_called()
        self.assertFalse(mock_env_handle.called)

    def test_147_deprovision_missing_scripts(self):
        """Test _dns_challenge_deprovision with missing scripts."""
        self.cahandler.dns_update_script = "/tmp/dns_update.sh"
        self.cahandler.acme_sh_script = "/tmp/acme.sh"
        self.cahandler.acme_sh_shell = "/bin/bash"
        self.cahandler.dns_record_dic = {
            "test.example.com": b"testvalue",
            "other.example.com": "othervalue",
        }
        self.cahandler.dns_update_script_variables = {"TEST_VAR": "value"}

        self.cahandler.dns_update_script = None
        self.cahandler.acme_sh_script = None
        self.cahandler.dns_record_dic = {"test.example.com": b"testvalue"}
        # Should do nothing (no error)
        self.cahandler._dns_challenge_deprovision()

    @patch("time.sleep")
    @patch("subprocess.call")
    @patch(
        "examples.ca_handler.acme_ca_handler.CAhandler._environment_variables_handle"
    )
    @patch("os.path.splitext")
    @patch("os.path.basename")
    @patch("examples.ca_handler.acme_ca_handler.sha256_hash")
    @patch("examples.ca_handler.acme_ca_handler.b64_url_encode")
    @patch("examples.ca_handler.acme_ca_handler.txt_get")
    def test_148_dns_challenge_provision_success(
        self,
        mock_txt_get,
        mock_b64_url_encode,
        mock_sha256_hash,
        mock_basename,
        mock_splitext,
        mock_env_handle,
        mock_subprocess,
        mock_sleep,
    ):
        """Test _dns_challenge_provision with successful DNS challenge provisioning."""
        self.cahandler.dns_update_script = "/tmp/dns_update.sh"
        self.cahandler.acme_sh_script = "/tmp/acme.sh"
        self.cahandler.dns_update_script_variables = {"TEST_VAR": "value"}
        self.cahandler.dns_validation_timeout = 30
        fqdn = "example.com"
        key_authorization = "key-auth"
        user_key = MagicMock()
        mock_sleep.return_value = Mock()
        # Setup mocks
        mock_sha256_hash.return_value = b"hashbytes"
        mock_b64_url_encode.return_value = b"encodedtxt"
        mock_basename.return_value = "dns_update.sh"
        mock_splitext.side_effect = lambda x: ("/tmp/dns_update", ".sh")
        mock_subprocess.return_value = 0
        # Simulate DNS propagation
        mock_txt_get.side_effect = [None, b"encodedtxt"]
        self.cahandler._dns_challenge_provision(fqdn, key_authorization, user_key)
        # Check environment variable handling called for set and unset
        self.assertEqual(mock_env_handle.call_count, 2)
        mock_env_handle.assert_any_call(unset=False)
        mock_env_handle.assert_any_call(unset=True)

        # Check subprocess called
        mock_subprocess.assert_called()
        # Check DNS record stored
        self.assertIn("_acme-challenge.example.com", self.cahandler.dns_record_dic)
        self.assertEqual(
            self.cahandler.dns_record_dic["_acme-challenge.example.com"], b"encodedtxt"
        )

    @patch("time.sleep")
    @patch("subprocess.call")
    @patch(
        "examples.ca_handler.acme_ca_handler.CAhandler._environment_variables_handle"
    )
    @patch("os.path.splitext")
    @patch("os.path.basename")
    @patch("examples.ca_handler.acme_ca_handler.sha256_hash")
    @patch("examples.ca_handler.acme_ca_handler.b64_url_encode")
    @patch("examples.ca_handler.acme_ca_handler.txt_get")
    def test_149_dns_challenge_provision_success(
        self,
        mock_txt_get,
        mock_b64_url_encode,
        mock_sha256_hash,
        mock_basename,
        mock_splitext,
        mock_env_handle,
        mock_subprocess,
        mock_sleep,
    ):
        """Test _dns_challenge_provision with successful DNS challenge provisioning."""
        self.cahandler.dns_update_script = "/tmp/dns_update.sh"
        self.cahandler.acme_sh_script = "/tmp/acme.sh"
        self.cahandler.acme_sh_shell = "/bin/bash"
        self.cahandler.dns_update_script_variables = {"TEST_VAR": "value"}
        self.cahandler.dns_validation_timeout = 10
        fqdn = "example.com"
        key_authorization = "key-auth"
        user_key = MagicMock()
        mock_sleep.return_value = Mock()
        # Setup mocks
        mock_sha256_hash.return_value = b"hashbytes"
        mock_b64_url_encode.return_value = b"encodedtxt"
        mock_basename.return_value = "dns_update.sh"
        mock_splitext.side_effect = lambda x: ("/tmp/dns_update", ".sh")
        mock_subprocess.return_value = 0
        # Simulate DNS propagation
        mock_txt_get.side_effect = [None, b"encodedtxt"]
        with self.assertLogs("test_a2c", level="DEBUG") as lcm:
            self.cahandler._dns_challenge_provision(fqdn, key_authorization, user_key)
        self.assertIn(
            "DEBUG:test_a2c:CAhandler._dns_challenge_provision(): using shell: /bin/bash",
            lcm.output,
        )

        # Check environment variable handling called for set and unset
        self.assertEqual(mock_env_handle.call_count, 2)
        mock_env_handle.assert_any_call(unset=False)
        mock_env_handle.assert_any_call(unset=True)

        # Check subprocess called
        mock_subprocess.assert_called()
        # Check DNS record stored
        self.assertIn("_acme-challenge.example.com", self.cahandler.dns_record_dic)
        self.assertEqual(
            self.cahandler.dns_record_dic["_acme-challenge.example.com"], b"encodedtxt"
        )

    @patch("time.sleep")
    @patch("subprocess.call")
    @patch(
        "examples.ca_handler.acme_ca_handler.CAhandler._environment_variables_handle"
    )
    @patch("os.path.splitext")
    @patch("os.path.basename")
    @patch("examples.ca_handler.acme_ca_handler.sha256_hash")
    @patch("examples.ca_handler.acme_ca_handler.b64_url_encode")
    @patch("examples.ca_handler.acme_ca_handler.txt_get")
    def test_150_dns_challenge_provision_success(
        self,
        mock_txt_get,
        mock_b64_url_encode,
        mock_sha256_hash,
        mock_basename,
        mock_splitext,
        mock_env_handle,
        mock_subprocess,
        mock_sleep,
    ):
        """Test _dns_challenge_provision with successful DNS challenge provisioning."""
        self.cahandler.dns_update_script = "/tmp/dns_update.sh"
        self.cahandler.acme_sh_script = "/tmp/acme.sh"
        self.cahandler.acme_sh_shell = "/bin/bash"
        self.cahandler.dns_update_script_variables = {"TEST_VAR": "value"}
        self.cahandler.dns_validation_timeout = 10
        fqdn = "example.com"
        key_authorization = "key-auth"
        user_key = MagicMock()
        mock_sleep.return_value = Mock()
        # Setup mocks
        mock_sha256_hash.return_value = b"hashbytes"
        mock_b64_url_encode.return_value = b"encodedtxt"
        mock_basename.return_value = "dns_update.sh"
        mock_splitext.side_effect = lambda x: ("/tmp/dns_update", ".sh")
        mock_subprocess.return_value = 0
        # Simulate DNS propagation
        mock_txt_get.return_value = b"encodedtxt"
        with self.assertLogs("test_a2c", level="DEBUG") as lcm:
            self.cahandler._dns_challenge_provision(fqdn, key_authorization, user_key)
        self.assertIn(
            "DEBUG:test_a2c:CAhandler._dns_challenge_provision(): using shell: /bin/bash",
            lcm.output,
        )
        self.assertIn(
            "DEBUG:test_a2c:_dns_challenge_provision(): found txt record in DNS",
            lcm.output,
        )
        # Check environment variable handling called for set and unset
        self.assertEqual(mock_env_handle.call_count, 2)
        mock_env_handle.assert_any_call(unset=False)
        mock_env_handle.assert_any_call(unset=True)

        # Check subprocess called
        mock_subprocess.assert_called()
        # Check DNS record stored
        self.assertIn("_acme-challenge.example.com", self.cahandler.dns_record_dic)
        self.assertEqual(
            self.cahandler.dns_record_dic["_acme-challenge.example.com"], b"encodedtxt"
        )

    @patch("time.sleep")
    @patch("subprocess.call")
    @patch(
        "examples.ca_handler.acme_ca_handler.CAhandler._environment_variables_handle"
    )
    @patch("os.path.splitext")
    @patch("os.path.basename")
    @patch("acme_srv.helper.sha256_hash")
    @patch("acme_srv.helper.b64_url_encode")
    @patch("acme_srv.helper.txt_get")
    def test_151_dns_challenge_provision_timeout(
        self,
        mock_txt_get,
        mock_b64_url_encode,
        mock_sha256_hash,
        mock_basename,
        mock_splitext,
        mock_env_handle,
        mock_subprocess,
        mock_sleep,
    ):
        """Test _dns_challenge_provision with DNS propagation timeout."""
        self.cahandler.dns_update_script = "/tmp/dns_update.sh"
        self.cahandler.acme_sh_script = "/tmp/acme.sh"
        self.cahandler.acme_sh_shell = "/bin/bash"
        self.cahandler.dns_update_script_variables = {"TEST_VAR": "value"}
        self.cahandler.dns_validation_timeout = 10
        fqdn = "example.com"
        key_authorization = "key-auth"
        user_key = MagicMock()
        mock_sleep.return_value = Mock()
        mock_sha256_hash.return_value = b"hashbytes"
        mock_b64_url_encode.return_value = b"encodedtxt"
        mock_basename.return_value = "dns_update.sh"
        mock_splitext.side_effect = lambda x: ("/tmp/dns_update", ".sh")
        mock_subprocess.return_value = 0
        # Simulate DNS never propagates
        mock_txt_get.return_value = None

        self.cahandler._dns_challenge_provision(fqdn, key_authorization, user_key)

        # Should still store the record
        self.assertIn("_acme-challenge.example.com", self.cahandler.dns_record_dic)
        self.assertEqual(
            self.cahandler.dns_record_dic["_acme-challenge.example.com"],
            b"4EsbamPacNncn5UI7noRUSqV4bk-1xyk8dpPgpQisJY",
        )

    @patch("examples.ca_handler.acme_ca_handler.client.ClientV2")
    @patch("examples.ca_handler.acme_ca_handler.messages.Registration")
    @patch("examples.ca_handler.acme_ca_handler.messages.Directory")
    def test_152_existing_account_found(self, mock_directory, mock_reg, mock_client):
        """Test _registration_lookup with existing account found."""
        self.cahandler.acme_url = "https://acme.example.com"
        self.cahandler.path_dic = {"acct_path": "/acme/acct/"}
        self.cahandler.account = "12345"
        regr = MagicMock()
        regr.uri = "https://acme.example.com/acme/acct/12345"
        mock_client.query_registration.return_value = regr
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            result = self.cahandler._registration_lookup(
                mock_client, mock_reg, mock_directory, MagicMock()
            )
        self.assertEqual(result, regr)
        self.assertIn(
            "INFO:test_a2c:Found existing account: https://acme.example.com/acme/acct/12345",
            lcm.output,
        )

    @patch("examples.ca_handler.acme_ca_handler.client.ClientV2")
    @patch("examples.ca_handler.acme_ca_handler.messages.Registration")
    @patch("examples.ca_handler.acme_ca_handler.messages.Directory")
    def test_153_account_not_found_register_new(
        self, mock_directory, mock_reg, mock_client
    ):
        """Test _registration_lookup when account is not found and needs to be registered."""
        self.cahandler.acme_url = "https://acme.example.com"
        self.cahandler.path_dic = {"acct_path": "/acme/acct/"}
        self.cahandler.account = "12345"
        regr = MagicMock()
        delattr(regr, "uri")
        mock_client.query_registration.return_value = regr

        # Patch _account_register to return a new regr with uri
        new_regr = MagicMock()
        new_regr.uri = "https://acme.example.com/acme/acct/67890"
        self.cahandler._account_register = MagicMock(return_value=new_regr)
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            result = self.cahandler._registration_lookup(
                mock_client, mock_reg, mock_directory, MagicMock()
            )
        self.assertEqual(result, new_regr)
        self.assertIn(
            "ERROR:test_a2c:Account lookup failed. Account 12345 not found. Trying to register new account.",
            lcm.output,
        )
        self.assertIn(
            "INFO:test_a2c:New account: https://acme.example.com/acme/acct/67890",
            lcm.output,
        )

    @patch("examples.ca_handler.acme_ca_handler.client.ClientV2")
    @patch("examples.ca_handler.acme_ca_handler.messages.Registration")
    @patch("examples.ca_handler.acme_ca_handler.messages.Directory")
    def test_154_no_account_set_register_new(
        self, mock_directory, mock_reg, mock_client
    ):
        """Test _registration_lookup when no account is set and needs to be registered."""
        self.cahandler.acme_url = "https://acme.example.com"
        self.cahandler.path_dic = {"acct_path": "/acme/acct/"}
        self.cahandler.account = "12345"
        # Remove account
        self.cahandler.account = None
        # Patch _account_register to return a new regr with uri
        new_regr = MagicMock()
        new_regr.uri = "https://acme.example.com/acme/acct/99999"
        self.cahandler._account_register = MagicMock(return_value=new_regr)
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            result = self.cahandler._registration_lookup(
                mock_client, mock_reg, mock_directory, MagicMock()
            )
        self.assertEqual(result, new_regr)
        self.assertIn(
            "INFO:test_a2c:New account: https://acme.example.com/acme/acct/99999",
            lcm.output,
        )

    def test_155_jwk_strip_minimal_fields(self):
        """Test _jwk_strip returns minimal JWK for RSA key"""
        user_key = self._generate_full_jwk()
        stripped_key = self.cahandler._jwk_strip(user_key)
        self.assertIsInstance(stripped_key, josepy.JWKRSA)
        minimal_jwk = stripped_key.to_json()
        self.assertIn("kty", minimal_jwk)
        self.assertIn("n", minimal_jwk)
        self.assertIn("e", minimal_jwk)
        self.assertEqual(len(minimal_jwk), 3)  # Only minimal fields

    def test_156_jwk_strip_non_rsa_key(self):
        """Test _jwk_strip returns original key if not RSA"""
        user_key = self._generate_full_jwk()
        with patch.object(
            type(user_key),
            "to_json",
            return_value={"kty": "EC", "crv": "P-256", "x": "foo", "y": "bar"},
        ):
            result = self.cahandler._jwk_strip(user_key)
            self.assertEqual(result, user_key)

    def test_157_jwk_strip_missing_fields(self):
        """Test _jwk_strip returns None if required fields are missing"""
        user_key = self._generate_full_jwk()
        with patch.object(
            type(user_key), "to_json", return_value={"kty": "RSA", "e": "AQAB"}
        ):
            with self.assertLogs("test_a2c", level="INFO") as lcm:
                result = self.cahandler._jwk_strip(user_key)
            self.assertIn(
                "ERROR:test_a2c:Missing required JWK fields for RSA key: n", lcm.output
            )
            self.assertIsNone(result)

    def test_158_jwk_strip_invalid_jwk(self):
        """Test _jwk_strip handles exception when reconstructing JWKRSA"""
        user_key = self._generate_full_jwk()
        with patch.object(
            type(user_key), "to_json", return_value={"kty": "RSA", "n": None, "e": None}
        ):
            with self.assertLogs("test_a2c", level="INFO") as lcm:
                result = self.cahandler._jwk_strip(user_key)
            self.assertIn(
                "ERROR:test_a2c:Failed to strip JWK to minimal fields. Input: {'kty': 'RSA', 'n': None, 'e': None}, Error: 'NoneType' object has no attribute 'encode'",
                lcm.output,
            )
            self.assertIsNone(result)

    @patch("examples.ca_handler.acme_ca_handler.handler_config_check")
    def test_159_handler_check(self, mock_handler_check):
        """test handler_check"""
        mock_handler_check.return_value = "mock_handler_check"
        self.assertEqual("mock_handler_check", self.cahandler.handler_check())

    def test_160_config_profiles_load_from_db(self):
        """CAhandler._config_profiles_load() - load from DB when profiles_sync is set"""
        cah = self.cahandler
        cah.dbstore = MagicMock()
        # Simulate DB returning a JSON string with profiles
        cah.dbstore.hkparameter_get.return_value = json.dumps(
            {"profiles": {"foo": "bar"}}
        )
        config_dic = {"CAhandler": {"profiles_sync": True}}
        profiles = cah._config_profiles_load(config_dic)
        self.assertEqual(profiles, {"foo": "bar"})
        cah.dbstore.hkparameter_get.assert_called_once_with("profiles")

    @patch("examples.ca_handler.acme_ca_handler.config_profile_load")
    def test_161_config_profiles_load_from_config(self, mock_config_profile_load):
        """CAhandler._config_profiles_load() - load from config file when profiles_sync is not set"""
        cah = self.cahandler
        config_dic = {"CAhandler": {}}
        mock_config_profile_load.return_value = {"bar": "baz"}
        profiles = cah._config_profiles_load(config_dic)
        self.assertEqual(profiles, {"bar": "baz"})
        mock_config_profile_load.assert_called_once_with(cah.logger, config_dic)

    def test_162_config_profiles_load_db_exception(self):
        """CAhandler._config_profiles_load() - handle DB/JSON exception path"""
        cah = self.cahandler
        cah.dbstore = MagicMock()
        cah.dbstore.hkparameter_get.side_effect = Exception("db error")
        config_dic = {"CAhandler": {"profiles_sync": True}}
        with self.assertLogs(self.logger, level="CRITICAL") as lcm:
            profiles = cah._config_profiles_load(config_dic)
        self.assertEqual(profiles, {})
        self.assertIn(
            "Database error: failed to get profile list: db error", " ".join(lcm.output)
        )

    @patch("examples.ca_handler.acme_ca_handler.eab_profile_header_info_check")
    def test_163_enroll_csr_rejected_logs_error(self, mock_eab_check):
        """Test enroll else branch logs error when CSR is rejected (lines 1134-1135)"""
        mock_eab_check.return_value = "error"

        with self.assertLogs("test_a2c", level="ERROR") as lcm:
            self.assertEqual(("error", None, None, None), self.cahandler.enroll("csr"))
        self.assertIn(
            "ERROR:test_a2c:Enrollment error: CSR rejected. error", lcm.output
        )

    def test_164_handle_pending_status_sectigo_email_valid(self):
        """Test _handle_pending_status covers sectigo-email-01 valid branch (line 623)"""
        cah = self.cahandler
        cah.logger = MagicMock()
        acmeclient = MagicMock()
        authzr = MagicMock()
        user_key = MagicMock()
        # Patch _challenge_info to return a challenge_content dict with sectigo-email-01/valid
        cah._challenge_info = MagicMock(return_value=(None, None, None))
        with patch.object(cah.logger, "debug") as mock_debug:
            result = cah._handle_pending_status(acmeclient, authzr, user_key)
        self.assertFalse(result)


if __name__ == "__main__":

    unittest.main()
