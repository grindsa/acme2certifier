#!/usr/bin/python
# -*- coding: utf-8 -*-
""" unittests for openssl_ca_handler """
# pylint: disable=C0415, R0904, W0212
import sys
import os
import unittest
from unittest.mock import patch, mock_open
from OpenSSL import crypto

sys.path.insert(0, '.')
sys.path.insert(1, '..')

class TestACMEHandler(unittest.TestCase):
    """ test class for cgi_handler """

    def setUp(self):
        """ setup unittest """
        import logging
        from examples.ca_handler.est_ca_handler import CAhandler
        logging.basicConfig(level=logging.CRITICAL)
        self.logger = logging.getLogger('test_a2c')
        self.cahandler = CAhandler(False, self.logger)
        self.dir_path = os.path.dirname(os.path.realpath(__file__))

    def test_001_default(self):
        """ default test which always passes """
        self.assertEqual('foo', 'foo')

    @patch('examples.ca_handler.est_ca_handler.CAhandler._config_load')
    def test_002_config_load(self, mock_load_cfg):
        """ test _config_load no cahandler section """
        mock_load_cfg.return_value = {}
        self.cahandler._config_load()
        self.assertFalse(self.cahandler.est_host)
        self.assertFalse(self.cahandler.est_client_cert)
        self.assertFalse(self.cahandler.est_user)
        self.assertFalse(self.cahandler.est_password)
        self.assertTrue(self.cahandler.ca_bundle)

    @patch('examples.ca_handler.est_ca_handler.load_config')
    def test_003_config_load(self, mock_load_cfg):
        """ test _config_load - est host configured """
        mock_load_cfg.return_value = {'CAhandler': {'est_host': 'foo_host'}}
        self.cahandler._config_load()
        self.assertEqual('foo_host/.well-known/est', self.cahandler.est_host)

    @patch('examples.ca_handler.est_ca_handler.load_config')
    def test_004_config_load(self, mock_load_cfg):
        """ test _config_load - no est host configured """
        mock_load_cfg.return_value = {'CAhandler': {'foo': 'bar'}}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_load()
        self.assertIn('ERROR:test_a2c:CAhandler._config_load(): missing "est_host" parameter in config file', lcm.output)

    @patch('examples.ca_handler.est_ca_handler.load_config')
    def test_005_config_load(self, mock_load_cfg):
        """ test _config_load - client certificate configured but no key """
        mock_load_cfg.return_value = {'CAhandler': {'est_host': 'foo', 'est_client_cert': 'est_client_cert'}}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_load()
        self.assertFalse(self.cahandler.est_client_cert)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load() configuration incomplete: either "est_client_cert or "est_client_key" parameter is missing in config file', lcm.output)

    @patch('examples.ca_handler.est_ca_handler.load_config')
    def test_006_config_load(self, mock_load_cfg):
        """ test _config_load - client certificate configured but no key """
        mock_load_cfg.return_value = {'CAhandler': {'est_host': 'foo', 'est_client_key': 'est_client_key'}}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_load()
        self.assertFalse(self.cahandler.est_client_cert)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load() configuration incomplete: either "est_client_cert or "est_client_key" parameter is missing in config file', lcm.output)

    @patch('examples.ca_handler.est_ca_handler.load_config')
    def test_007_config_load(self, mock_load_cfg):
        """ test _config_load - user is configured but no password """
        mock_load_cfg.return_value = {'CAhandler': {'est_host': 'foo', 'est_user': 'est_user'}}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_load()
        self.assertFalse(self.cahandler.est_user)
        self.assertFalse(self.cahandler.est_password)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load() configuration incomplete: either "est_user" or "est_password" parameter is missing in config file', lcm.output)

    @patch('examples.ca_handler.est_ca_handler.load_config')
    def test_008_config_load(self, mock_load_cfg):
        """ test _config_load - password is configured but no user_name """
        mock_load_cfg.return_value = {'CAhandler': {'est_host': 'foo', 'est_password': 'est_password'}}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_load()
        self.assertFalse(self.cahandler.est_user)
        self.assertFalse(self.cahandler.est_password)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load() configuration incomplete: either "est_user" or "est_password" parameter is missing in config file', lcm.output)

    @patch('examples.ca_handler.est_ca_handler.load_config')
    def test_009_config_load(self, mock_load_cfg):
        """ test _config_load - username and password are configured """
        mock_load_cfg.return_value = {'CAhandler': {'est_host': 'foo', 'est_user': 'est_user', 'est_password': 'est_password'}}
        self.cahandler._config_load()
        self.assertEqual('est_user', self.cahandler.est_user)
        self.assertEqual('est_password', self.cahandler.est_password)

    @patch('examples.ca_handler.est_ca_handler.load_config')
    def test_010_config_load(self, mock_load_cfg):
        """ test _config_load - neither client nor user_auth are configured """
        mock_load_cfg.return_value = {'CAhandler': {'est_host': 'foo'}}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_load()
        self.assertFalse(self.cahandler.est_user)
        self.assertFalse(self.cahandler.est_password)
        self.assertFalse(self.cahandler.est_client_cert)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load() configuration incomplete: either user or client authentication must be configured', lcm.output)

    @patch('examples.ca_handler.est_ca_handler.load_config')
    def test_011_config_load(self, mock_load_cfg):
        """ test _config_load - neither client nor user_auth are configured """
        mock_load_cfg.return_value = {'CAhandler':
            {'est_host': 'foo', 'est_host': 'foo', 'est_user': 'est_user', 'est_password': 'est_password', 'est_client_cert': 'est_client_cert', 'est_client_key': 'est_client_key'}}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_load()
        self.assertEqual('est_user', self.cahandler.est_user)
        self.assertEqual('est_password', self.cahandler.est_password)
        self.assertEqual(['est_client_cert', 'est_client_key'], self.cahandler.est_client_cert)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load() configuration wrong: user and client authentication cannot be configured together', lcm.output)

    @patch('examples.ca_handler.est_ca_handler.load_config')
    def test_012_config_load(self, mock_load_cfg):
        """ test _config_load - ca bundle not configured """
        mock_load_cfg.return_value = {'CAhandler': {'est_host': 'foo', 'est_user': 'est_user', 'est_password': 'est_password'}}
        self.cahandler._config_load()
        self.assertTrue(self.cahandler.ca_bundle)

    @patch('examples.ca_handler.est_ca_handler.load_config')
    def test_013_config_load(self, mock_load_cfg):
        """ test _config_load - ca bundle True """
        mock_load_cfg.return_value = {'CAhandler': {'est_host': 'foo', 'est_user': 'est_user', 'est_password': 'est_password', 'ca_bundle': True}}
        self.cahandler._config_load()
        self.assertTrue(self.cahandler.ca_bundle)

    @patch('examples.ca_handler.est_ca_handler.load_config')
    def test_014_config_load(self, mock_load_cfg):
        """ test _config_load - ca bundle False """
        mock_load_cfg.return_value = {'CAhandler': {'est_host': 'foo', 'est_user': 'est_user', 'est_password': 'est_password', 'ca_bundle': False}}
        self.cahandler._config_load()
        self.assertFalse(self.cahandler.ca_bundle)

    @patch('examples.ca_handler.est_ca_handler.load_config')
    def test_015_config_load(self, mock_load_cfg):
        """ test _config_load - ca bundle string """
        mock_load_cfg.return_value = {'CAhandler': {'est_host': 'foo', 'est_user': 'est_user', 'est_password': 'est_password', 'ca_bundle': 'bar'}}
        self.cahandler._config_load()
        self.assertEqual('bar', self.cahandler.ca_bundle)

if __name__ == '__main__':

    unittest.main()
