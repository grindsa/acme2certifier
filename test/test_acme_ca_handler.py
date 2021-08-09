#!/usr/bin/python
# -*- coding: utf-8 -*-
""" unittests for openssl_ca_handler """
# pylint: disable=C0415, R0904, R0913, W0212
import sys
import os
import unittest
from unittest.mock import patch, mock_open, Mock
# from OpenSSL import crypto
import shutil

sys.path.insert(0, '.')
sys.path.insert(1, '..')

class TestACMEHandler(unittest.TestCase):
    """ test class for cgi_handler """
    def setUp(self):
        """ setup unittest """
        import logging
        from examples.ca_handler.acme_ca_handler import CAhandler
        logging.basicConfig(level=logging.CRITICAL)
        self.logger = logging.getLogger('test_a2c')
        self.cahandler = CAhandler(False, self.logger)

    def tearDown(self):
        """ teardown """
        pass

    def test_001___init__(self):
        """ init """
        self.assertTrue(self.cahandler.__enter__())

    def test_002___exit__(self):
        """ exit """
        self.assertFalse(self.cahandler.__exit__())

    @patch('examples.ca_handler.acme_ca_handler.load_config')
    def test_003__config_load(self, mock_load_cfg):
        """ test _config_load no cahandler section """
        mock_load_cfg.return_value = {}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_load()
        self.assertFalse(self.cahandler.keyfile)
        self.assertFalse(self.cahandler.url)
        self.assertFalse(self.cahandler.account)
        self.assertEqual({'directory_path': '/directory', 'acct_path' : '/acme/acct/'}, self.cahandler.path_dic)
        self.assertEqual(2048, self.cahandler.key_size)
        self.assertFalse(self.cahandler.email)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load() configuration incomplete: "CAhandler" section is missing in config file', lcm.output)

    @patch('examples.ca_handler.acme_ca_handler.load_config')
    def test_004__config_load(self, mock_load_cfg):
        """ test _config_load empty cahandler section """
        mock_load_cfg.return_value = {'CAhandler': {}}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_load()
        self.assertFalse(self.cahandler.keyfile)
        self.assertFalse(self.cahandler.url)
        self.assertFalse(self.cahandler.account)
        self.assertEqual({'directory_path': '/directory', 'acct_path' : '/acme/acct/'}, self.cahandler.path_dic)
        self.assertEqual(2048, self.cahandler.key_size)
        self.assertFalse(self.cahandler.email)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load() configuration incomplete: "acme_keyfile" parameter is missing in config file', lcm.output)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load() configuration incomplete: "acme_url" parameter is missing in config file', lcm.output)

    @patch('examples.ca_handler.acme_ca_handler.load_config')
    def test_005__config_load(self, mock_load_cfg):
        """ test _config_load unknown values """
        mock_load_cfg.return_value = {'CAhandler': {'foo': 'bar'}}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_load()
        self.assertFalse(self.cahandler.keyfile)
        self.assertFalse(self.cahandler.url)
        self.assertFalse(self.cahandler.account)
        self.assertEqual({'directory_path': '/directory', 'acct_path' : '/acme/acct/'}, self.cahandler.path_dic)
        self.assertEqual(2048, self.cahandler.key_size)
        self.assertFalse(self.cahandler.email)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load() configuration incomplete: "acme_keyfile" parameter is missing in config file', lcm.output)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load() configuration incomplete: "acme_url" parameter is missing in config file', lcm.output)

    @patch('examples.ca_handler.acme_ca_handler.load_config')
    def test_006__config_load(self, mock_load_cfg):
        """ test _config_load key_file value """
        mock_load_cfg.return_value = {'CAhandler': {'acme_keyfile': 'key_file'}}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_load()
        self.assertEqual('key_file', self.cahandler.keyfile)
        self.assertFalse(self.cahandler.url)
        self.assertFalse(self.cahandler.account)
        self.assertEqual({'directory_path': '/directory', 'acct_path' : '/acme/acct/'}, self.cahandler.path_dic)
        self.assertEqual(2048, self.cahandler.key_size)
        self.assertFalse(self.cahandler.email)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load() configuration incomplete: "acme_url" parameter is missing in config file', lcm.output)

    @patch('examples.ca_handler.acme_ca_handler.load_config')
    def test_007__config_load(self, mock_load_cfg):
        """ test _config_load url value """
        mock_load_cfg.return_value = {'CAhandler': {'acme_url': 'url'}}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_load()
        self.assertFalse(self.cahandler.keyfile)
        self.assertEqual('url', self.cahandler.url)
        self.assertFalse(self.cahandler.account)
        self.assertEqual({'directory_path': '/directory', 'acct_path' : '/acme/acct/'}, self.cahandler.path_dic)
        self.assertEqual(2048, self.cahandler.key_size)
        self.assertFalse(self.cahandler.email)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load() configuration incomplete: "acme_keyfile" parameter is missing in config file', lcm.output)

    @patch('examples.ca_handler.acme_ca_handler.load_config')
    def test_008__config_load(self, mock_load_cfg):
        """ test _config_load account values """
        mock_load_cfg.return_value = {'CAhandler': {'acme_account': 'acme_account'}}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_load()
        self.assertFalse(self.cahandler.keyfile)
        self.assertFalse(self.cahandler.url)
        self.assertEqual('acme_account', self.cahandler.account)
        self.assertEqual({'directory_path': '/directory', 'acct_path' : '/acme/acct/'}, self.cahandler.path_dic)
        self.assertEqual(2048, self.cahandler.key_size)
        self.assertFalse(self.cahandler.email)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load() configuration incomplete: "acme_keyfile" parameter is missing in config file', lcm.output)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load() configuration incomplete: "acme_url" parameter is missing in config file', lcm.output)

    @patch('examples.ca_handler.acme_ca_handler.load_config')
    def test_009__config_load(self, mock_load_cfg):
        """ test _config_load key_size """
        mock_load_cfg.return_value = {'CAhandler': {'acme_account_keysize': 'acme_account_keysize'}}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_load()
        self.assertFalse(self.cahandler.keyfile)
        self.assertFalse(self.cahandler.url)
        self.assertFalse(self.cahandler.account)
        self.assertEqual({'directory_path': '/directory', 'acct_path' : '/acme/acct/'}, self.cahandler.path_dic)
        self.assertEqual('acme_account_keysize', self.cahandler.key_size)
        self.assertFalse(self.cahandler.email)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load() configuration incomplete: "acme_keyfile" parameter is missing in config file', lcm.output)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load() configuration incomplete: "acme_url" parameter is missing in config file', lcm.output)

    @patch('examples.ca_handler.acme_ca_handler.load_config')
    def test_010__config_load(self, mock_load_cfg):
        """ test _config_load email """
        mock_load_cfg.return_value = {'CAhandler': {'acme_account_email': 'acme_account_email'}}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_load()
        self.assertFalse(self.cahandler.keyfile)
        self.assertFalse(self.cahandler.url)
        self.assertFalse(self.cahandler.account)
        self.assertEqual({'directory_path': '/directory', 'acct_path' : '/acme/acct/'}, self.cahandler.path_dic)
        self.assertEqual(2048, self.cahandler.key_size)
        self.assertEqual('acme_account_email', self.cahandler.email)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load() configuration incomplete: "acme_keyfile" parameter is missing in config file', lcm.output)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load() configuration incomplete: "acme_url" parameter is missing in config file', lcm.output)

    @patch('examples.ca_handler.acme_ca_handler.load_config')
    def test_011__config_load(self, mock_load_cfg):
        """ test _config_load email """
        mock_load_cfg.return_value = {'CAhandler': {'directory_path': 'directory_path'}}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_load()
        self.assertFalse(self.cahandler.keyfile)
        self.assertFalse(self.cahandler.url)
        self.assertFalse(self.cahandler.account)
        self.assertEqual({'acct_path': '/acme/acct/', 'directory_path': 'directory_path'}, self.cahandler.path_dic)
        self.assertEqual(2048, self.cahandler.key_size)
        self.assertFalse(self.cahandler.email)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load() configuration incomplete: "acme_keyfile" parameter is missing in config file', lcm.output)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load() configuration incomplete: "acme_url" parameter is missing in config file', lcm.output)

    @patch('examples.ca_handler.acme_ca_handler.load_config')
    def test_012__config_load(self, mock_load_cfg):
        """ test _config_load email """
        mock_load_cfg.return_value = {'CAhandler': {'account_path': 'account_path'}}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_load()
        self.assertFalse(self.cahandler.keyfile)
        self.assertFalse(self.cahandler.url)
        self.assertFalse(self.cahandler.account)
        self.assertEqual({'acct_path': 'account_path', 'directory_path': '/directory'}, self.cahandler.path_dic)
        self.assertEqual(2048, self.cahandler.key_size)
        self.assertFalse(self.cahandler.email)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load() configuration incomplete: "acme_keyfile" parameter is missing in config file', lcm.output)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load() configuration incomplete: "acme_url" parameter is missing in config file', lcm.output)

    def test_013__challenge_filter(self):
        """ test _challenge_filter single http """
        challenge1 = Mock(return_value='foo')
        challenge1.chall.typ = 'http-01'
        challenge1.chall.value = 'value-01'
        authz = Mock()
        authz.body.challenges = [challenge1]
        self.assertEqual('http-01', self.cahandler._challenge_filter(authz).chall.typ)
        self.assertEqual('value-01', self.cahandler._challenge_filter(authz).chall.value)

    def test_014__challenge_filter(self):
        """ test _challenge_filter dns and http """
        challenge1 = Mock(return_value='foo')
        challenge1.chall.typ = 'dns-01'
        challenge1.chall.value = 'value-01'
        challenge2 = Mock(return_value='foo')
        challenge2.chall.typ = 'http-01'
        challenge2.chall.value = 'value-02'
        authz = Mock()
        authz.body.challenges = [challenge1, challenge2]
        self.assertEqual('http-01', self.cahandler._challenge_filter(authz).chall.typ)
        self.assertEqual('value-02', self.cahandler._challenge_filter(authz).chall.value)

    def test_015__challenge_filter(self):
        """ test _challenge_filter double http to test break """
        challenge1 = Mock(return_value='foo')
        challenge1.chall.typ = 'http-01'
        challenge1.chall.value = 'value-01'
        challenge2 = Mock(return_value='foo')
        challenge2.chall.typ = 'http-01'
        challenge2.chall.value = 'value-02'
        authz = Mock()
        authz.body.challenges = [challenge1, challenge2]
        self.assertEqual('http-01', self.cahandler._challenge_filter(authz).chall.typ)
        self.assertEqual('value-01', self.cahandler._challenge_filter(authz).chall.value)

    def test_016__challenge_filter(self):
        """ test _challenge_filter no http challenge """
        challenge1 = Mock(return_value='foo')
        challenge1.chall.typ = 'type-01'
        challenge1.chall.value = 'value-01'
        challenge2 = Mock(return_value='foo')
        challenge2.chall.typ = 'type-02'
        challenge2.chall.value = 'value-02'
        authz = Mock()
        authz.body.challenges = [challenge1, challenge2]
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertFalse(self.cahandler._challenge_filter(authz))
        self.assertIn('ERROR:test_a2c:CAhandler._challenge_filter() ended. Could not find challenge of type http-01', lcm.output)

if __name__ == '__main__':

    unittest.main()
