#!/usr/bin/python
# -*- coding: utf-8 -*-
""" unittests for ejbca rest handler """
# pylint: disable= C0415, W0212
import unittest
import sys
import os
from unittest.mock import patch, Mock
import configparser

sys.path.insert(0, '.')
sys.path.insert(1, '..')

class TestACMEHandler(unittest.TestCase):
    """ test class for ejbca_ca_handler """

    def setUp(self):
        """ setup unittest """
        import logging
        logging.basicConfig(level=logging.CRITICAL)
        self.logger = logging.getLogger('test_a2c')
        from examples.ca_handler.ejbca_ca_handler import CAhandler
        self.cahandler = CAhandler(False, self.logger)

    def test_001_default(self):
        """ default test which always passes """
        self.assertEqual('foo', 'foo')

    def test_002__config_server_load(self):
        """ test _config_server_load() """
        parser = configparser.ConfigParser()
        parser['foo'] = {'foo': 'bar'}
        self.cahandler._config_server_load(parser)
        self.assertFalse(self.cahandler.api_host)
        self.assertEqual(5, self.cahandler.request_timeout)
        self.assertTrue(self.cahandler.ca_bundle)

    def test_003__config_server_load(self):
        """ test _config_server_load() """
        config_dic = {'foo': 'bar'}
        self.cahandler._config_server_load(config_dic)
        self.assertFalse(self.cahandler.api_host)
        self.assertEqual(5, self.cahandler.request_timeout)
        self.assertTrue(self.cahandler.ca_bundle)

    def test_004__config_server_load(self):
        """ test _config_server_load() """
        parser = configparser.ConfigParser()
        parser['CAhandler'] = {'foo': 'bar'}
        self.cahandler._config_server_load(parser)
        self.assertFalse(self.cahandler.api_host)
        self.assertEqual(5, self.cahandler.request_timeout)
        self.assertTrue(self.cahandler.ca_bundle)

    def test_005__config_server_load(self):
        """ test _config_server_load() """
        parser = configparser.ConfigParser()
        parser['CAhandler'] = {'api_host': 'api_host'}
        self.cahandler._config_server_load(parser)
        self.assertEqual('api_host', self.cahandler.api_host)
        self.assertEqual(5, self.cahandler.request_timeout)
        self.assertTrue(self.cahandler.ca_bundle)

    def test_006__config_server_load(self):
        """ test _config_server_load() """
        parser = configparser.ConfigParser()
        parser['CAhandler'] = {'request_timeout': 10}
        self.cahandler._config_server_load(parser)
        self.assertFalse(self.cahandler.api_host)
        self.assertEqual(10, self.cahandler.request_timeout)
        self.assertTrue(self.cahandler.ca_bundle)

    def test_007__config_server_load(self):
        """ test _config_server_load() """
        parser = configparser.ConfigParser()
        parser['CAhandler'] = {'request_timeout': '20'}
        self.cahandler._config_server_load(parser)
        self.assertFalse(self.cahandler.api_host)
        self.assertEqual(20, self.cahandler.request_timeout)
        self.assertTrue(self.cahandler.ca_bundle)

    def test_008__config_server_load(self):
        """ test _config_server_load() """
        parser = configparser.ConfigParser()
        parser['CAhandler'] = {'request_timeout': 'aa'}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_server_load(parser)
        self.assertIn("ERROR:test_a2c:CAhandler._config_server_load() could not load request_timeout:invalid literal for int() with base 10: 'aa'", lcm.output)
        self.assertFalse(self.cahandler.api_host)
        self.assertEqual(5, self.cahandler.request_timeout)
        self.assertTrue(self.cahandler.ca_bundle)

    def test_009__config_server_load(self):
        """ test _config_server_load() """
        parser = configparser.ConfigParser()
        parser['CAhandler'] = {'ca_bundle': 'ca_bundle'}
        self.cahandler._config_server_load(parser)
        self.assertFalse(self.cahandler.api_host)
        self.assertEqual(5, self.cahandler.request_timeout)
        self.assertEqual('ca_bundle', self.cahandler.ca_bundle)

    def test_010__config_server_load(self):
        """ test _config_server_load() """
        parser = configparser.ConfigParser()
        parser['CAhandler'] = {'ca_bundle': False}
        self.cahandler._config_server_load(parser)
        self.assertFalse(self.cahandler.api_host)
        self.assertEqual(5, self.cahandler.request_timeout)
        self.assertFalse(self.cahandler.ca_bundle)

    def test_011__config_auth_load(self):
        """ test _config_server_load() """
        parser = configparser.ConfigParser()
        parser['CAhandler'] = {'foo': 'bar'}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_auth_load(parser)
        self.assertFalse(self.cahandler.username)
        self.assertFalse(self.cahandler.enrollment_code)
        self.assertFalse(self.cahandler.session)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load(): configuration incomplete: "cert_file"/"cert_passphrase" parameter is missing in configuration file.', lcm.output)

    def test_012__config_auth_load(self):
        """ test _config_server_load() """
        parser = configparser.ConfigParser()
        parser['CAhandler'] = {'username': 'username'}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_auth_load(parser)
        self.assertEqual('username', self.cahandler.username)
        self.assertFalse(self.cahandler.enrollment_code)
        self.assertFalse(self.cahandler.session)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load(): configuration incomplete: "cert_file"/"cert_passphrase" parameter is missing in configuration file.', lcm.output)

    def test_013__config_auth_load(self):
        """ test _config_server_load() """
        parser = configparser.ConfigParser()
        parser['CAhandler'] = {'enrollment_code': 'enrollment_code'}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_auth_load(parser)
        self.assertEqual('enrollment_code', self.cahandler.enrollment_code)
        self.assertFalse(self.cahandler.username)
        self.assertFalse(self.cahandler.session)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load(): configuration incomplete: "cert_file"/"cert_passphrase" parameter is missing in configuration file.', lcm.output)

    def test_014__config_auth_load(self):
        """ test _config_server_load() """
        parser = configparser.ConfigParser()
        parser['CAhandler'] = {'cert_passphrase': 'cert_passphrase'}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_auth_load(parser)
        self.assertFalse(self.cahandler.username)
        self.assertFalse(self.cahandler.enrollment_code)
        self.assertFalse(self.cahandler.session)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load(): configuration incomplete: "cert_file"/"cert_passphrase" parameter is missing in configuration file.', lcm.output)

    def test_015__config_auth_load(self):
        """ test _config_server_load() """
        parser = configparser.ConfigParser()
        parser['CAhandler'] = {'cert_file': 'cert_file'}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_auth_load(parser)
        self.assertFalse(self.cahandler.username)
        self.assertFalse(self.cahandler.enrollment_code)
        self.assertFalse(self.cahandler.session)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load(): configuration incomplete: "cert_file"/"cert_passphrase" parameter is missing in configuration file.', lcm.output)

    @patch('examples.ca_handler.ejbca_ca_handler.requests.Session')
    def test_016__config_auth_load(self, mock_sess):
        """ test _config_server_load() """
        parser = configparser.ConfigParser()
        parser['CAhandler'] = {'cert_file': 'cert_file', 'cert_passphrase': 'cert_passphrase'}
        mock_sess.return_value = Mock()
        mock_sess.return_value.__enter__= Mock()
        mock_sess.return_value.__exit__= Mock()
        self.cahandler._config_auth_load(parser)
        self.assertFalse(self.cahandler.username)
        self.assertFalse(self.cahandler.enrollment_code)
        self.assertTrue(self.cahandler.session)

    def test_017__config_cainfo_load(self):
        """ test _config_server_load() """
        parser = configparser.ConfigParser()
        parser['CAhandler'] = {'foo': 'bar'}
        self.cahandler._config_cainfo_load(parser)
        self.assertFalse(self.cahandler.ca_name)
        self.assertFalse(self.cahandler.cert_profile_name)
        self.assertFalse(self.cahandler.ee_profile_name)

    def test_018__config_cainfo_load(self):
        """ test _config_server_load() """
        parser = configparser.ConfigParser()
        parser['CAhandler'] = {'ca_name': 'ca_name'}
        self.cahandler._config_cainfo_load(parser)
        self.assertEqual('ca_name', self.cahandler.ca_name)
        self.assertFalse(self.cahandler.cert_profile_name)
        self.assertFalse(self.cahandler.ee_profile_name)

    def test_019__config_cainfo_load(self):
        """ test _config_server_load() """
        parser = configparser.ConfigParser()
        parser['CAhandler'] = {'cert_profile_name': 'cert_profile_name'}
        self.cahandler._config_cainfo_load(parser)
        self.assertFalse(self.cahandler.ca_name)
        self.assertEqual('cert_profile_name', self.cahandler.cert_profile_name)
        self.assertFalse(self.cahandler.ee_profile_name)

    def test_020__config_cainfo_load(self):
        """ test _config_server_load() """
        parser = configparser.ConfigParser()
        parser['CAhandler'] = {'ee_profile_name': 'ee_profile_name'}
        self.cahandler._config_cainfo_load(parser)
        self.assertFalse(self.cahandler.ca_name)
        self.assertFalse(self.cahandler.cert_profile_name)
        self.assertEqual('ee_profile_name', self.cahandler.ee_profile_name)

    @patch('examples.ca_handler.ejbca_ca_handler.CAhandler._config_server_load')
    @patch('examples.ca_handler.ejbca_ca_handler.CAhandler._config_auth_load')
    @patch('examples.ca_handler.ejbca_ca_handler.CAhandler._config_cainfo_load')
    @patch('examples.ca_handler.ejbca_ca_handler.load_config')
    def test_021_config_load(self, mock_load_cfg, mock_cainfo, mock_auth_load, mock_server_load):
        """ load config """
        parser = configparser.ConfigParser()
        parser['CAhandler'] = {'foo': 'bar'}
        mock_load_cfg.return_value = parser
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_load()
        self.assertTrue(mock_cainfo.called)
        self.assertTrue(mock_auth_load.called)
        self.assertTrue(mock_server_load.called)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load(): configuration incomplete: parameter "api_host" is missing in configuration file.', lcm.output)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load(): configuration incomplete: parameter "cert_profile_name" is missing in configuration file.', lcm.output)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load(): configuration incomplete: parameter "ee_profile_name" is missing in configuration file.', lcm.output)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load(): configuration incomplete: parameter "ca_name" is missing in configuration file.', lcm.output)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load(): configuration incomplete: parameter "username" is missing in configuration file.', lcm.output)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load(): configuration incomplete: parameter "enrollment_code" is missing in configuration file.', lcm.output)

    @patch('examples.ca_handler.ejbca_ca_handler.CAhandler._config_server_load')
    @patch('examples.ca_handler.ejbca_ca_handler.CAhandler._config_auth_load')
    @patch('examples.ca_handler.ejbca_ca_handler.CAhandler._config_cainfo_load')
    @patch('examples.ca_handler.ejbca_ca_handler.load_config')
    def test_022_config_load(self, mock_load_cfg, mock_cainfo, mock_auth_load, mock_server_load):
        """ load config """
        parser = configparser.ConfigParser()
        parser['CAhandler'] = {'foo': 'bar'}
        mock_load_cfg.return_value = parser
        self.cahandler.api_host = 'api_host'
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_load()
        self.assertTrue(mock_cainfo.called)
        self.assertTrue(mock_auth_load.called)
        self.assertTrue(mock_server_load.called)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load(): configuration incomplete: parameter "cert_profile_name" is missing in configuration file.', lcm.output)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load(): configuration incomplete: parameter "ee_profile_name" is missing in configuration file.', lcm.output)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load(): configuration incomplete: parameter "ca_name" is missing in configuration file.', lcm.output)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load(): configuration incomplete: parameter "username" is missing in configuration file.', lcm.output)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load(): configuration incomplete: parameter "enrollment_code" is missing in configuration file.', lcm.output)

    @patch('examples.ca_handler.ejbca_ca_handler.CAhandler._config_server_load')
    @patch('examples.ca_handler.ejbca_ca_handler.CAhandler._config_auth_load')
    @patch('examples.ca_handler.ejbca_ca_handler.CAhandler._config_cainfo_load')
    @patch('examples.ca_handler.ejbca_ca_handler.load_config')
    def test_023_config_load(self, mock_load_cfg, mock_cainfo, mock_auth_load, mock_server_load):
        """ load config """
        parser = configparser.ConfigParser()
        parser['CAhandler'] = {'foo': 'bar'}
        mock_load_cfg.return_value = parser
        self.cahandler.cert_profile_name = 'cert_profile_name'
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_load()
        self.assertTrue(mock_cainfo.called)
        self.assertTrue(mock_auth_load.called)
        self.assertTrue(mock_server_load.called)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load(): configuration incomplete: parameter "api_host" is missing in configuration file.', lcm.output)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load(): configuration incomplete: parameter "ee_profile_name" is missing in configuration file.', lcm.output)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load(): configuration incomplete: parameter "ca_name" is missing in configuration file.', lcm.output)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load(): configuration incomplete: parameter "username" is missing in configuration file.', lcm.output)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load(): configuration incomplete: parameter "enrollment_code" is missing in configuration file.', lcm.output)

    @patch('examples.ca_handler.ejbca_ca_handler.CAhandler._config_server_load')
    @patch('examples.ca_handler.ejbca_ca_handler.CAhandler._config_auth_load')
    @patch('examples.ca_handler.ejbca_ca_handler.CAhandler._config_cainfo_load')
    @patch('examples.ca_handler.ejbca_ca_handler.load_config')
    def test_024_config_load(self, mock_load_cfg, mock_cainfo, mock_auth_load, mock_server_load):
        """ load config """
        parser = configparser.ConfigParser()
        parser['CAhandler'] = {'foo': 'bar'}
        mock_load_cfg.return_value = parser
        self.cahandler.ee_profile_name = 'ee_profile_name'
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_load()
        self.assertTrue(mock_cainfo.called)
        self.assertTrue(mock_auth_load.called)
        self.assertTrue(mock_server_load.called)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load(): configuration incomplete: parameter "api_host" is missing in configuration file.', lcm.output)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load(): configuration incomplete: parameter "cert_profile_name" is missing in configuration file.', lcm.output)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load(): configuration incomplete: parameter "ca_name" is missing in configuration file.', lcm.output)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load(): configuration incomplete: parameter "username" is missing in configuration file.', lcm.output)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load(): configuration incomplete: parameter "enrollment_code" is missing in configuration file.', lcm.output)

    @patch('examples.ca_handler.ejbca_ca_handler.CAhandler._config_server_load')
    @patch('examples.ca_handler.ejbca_ca_handler.CAhandler._config_auth_load')
    @patch('examples.ca_handler.ejbca_ca_handler.CAhandler._config_cainfo_load')
    @patch('examples.ca_handler.ejbca_ca_handler.load_config')
    def test_025_config_load(self, mock_load_cfg, mock_cainfo, mock_auth_load, mock_server_load):
        """ load config """
        parser = configparser.ConfigParser()
        parser['CAhandler'] = {'foo': 'bar'}
        mock_load_cfg.return_value = parser
        self.cahandler.ca_name = 'ca_name'
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_load()
        self.assertTrue(mock_cainfo.called)
        self.assertTrue(mock_auth_load.called)
        self.assertTrue(mock_server_load.called)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load(): configuration incomplete: parameter "api_host" is missing in configuration file.', lcm.output)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load(): configuration incomplete: parameter "cert_profile_name" is missing in configuration file.', lcm.output)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load(): configuration incomplete: parameter "ee_profile_name" is missing in configuration file.', lcm.output)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load(): configuration incomplete: parameter "username" is missing in configuration file.', lcm.output)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load(): configuration incomplete: parameter "enrollment_code" is missing in configuration file.', lcm.output)

    @patch('examples.ca_handler.ejbca_ca_handler.CAhandler._config_server_load')
    @patch('examples.ca_handler.ejbca_ca_handler.CAhandler._config_auth_load')
    @patch('examples.ca_handler.ejbca_ca_handler.CAhandler._config_cainfo_load')
    @patch('examples.ca_handler.ejbca_ca_handler.load_config')
    def test_026_config_load(self, mock_load_cfg, mock_cainfo, mock_auth_load, mock_server_load):
        """ load config """
        parser = configparser.ConfigParser()
        parser['CAhandler'] = {'foo': 'bar'}
        mock_load_cfg.return_value = parser
        self.cahandler.username = 'username'
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_load()
        self.assertTrue(mock_cainfo.called)
        self.assertTrue(mock_auth_load.called)
        self.assertTrue(mock_server_load.called)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load(): configuration incomplete: parameter "api_host" is missing in configuration file.', lcm.output)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load(): configuration incomplete: parameter "cert_profile_name" is missing in configuration file.', lcm.output)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load(): configuration incomplete: parameter "ee_profile_name" is missing in configuration file.', lcm.output)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load(): configuration incomplete: parameter "ca_name" is missing in configuration file.', lcm.output)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load(): configuration incomplete: parameter "enrollment_code" is missing in configuration file.', lcm.output)

    @patch('examples.ca_handler.ejbca_ca_handler.CAhandler._config_server_load')
    @patch('examples.ca_handler.ejbca_ca_handler.CAhandler._config_auth_load')
    @patch('examples.ca_handler.ejbca_ca_handler.CAhandler._config_cainfo_load')
    @patch('examples.ca_handler.ejbca_ca_handler.load_config')
    def test_027_config_load(self, mock_load_cfg, mock_cainfo, mock_auth_load, mock_server_load):
        """ load config """
        parser = configparser.ConfigParser()
        parser['CAhandler'] = {'foo': 'bar'}
        mock_load_cfg.return_value = parser
        self.cahandler.enrollment_code = 'enrollment_code'
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_load()
        self.assertTrue(mock_cainfo.called)
        self.assertTrue(mock_auth_load.called)
        self.assertTrue(mock_server_load.called)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load(): configuration incomplete: parameter "api_host" is missing in configuration file.', lcm.output)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load(): configuration incomplete: parameter "cert_profile_name" is missing in configuration file.', lcm.output)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load(): configuration incomplete: parameter "ee_profile_name" is missing in configuration file.', lcm.output)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load(): configuration incomplete: parameter "ca_name" is missing in configuration file.', lcm.output)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load(): configuration incomplete: parameter "username" is missing in configuration file.', lcm.output)

    @patch.dict('os.environ', {'username_var': 'user_var'})
    def test_028_config_authuser_load(self):
        """ test _config_load - load template with user variable """
        parser = configparser.ConfigParser()
        parser['CAhandler'] = {'username_variable': 'username_var'}
        self.cahandler._config_authuser_load(parser)
        self.assertEqual('user_var', self.cahandler.username)

    @patch.dict('os.environ', {'username_var': 'user_var'})
    def test_029_config_authuser_load(self):
        """ test _config_load - load template with user variable """
        parser = configparser.ConfigParser()
        parser['CAhandler'] = {'username_variable': 'does_not_exist'}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_authuser_load(parser)
        self.assertFalse(self.cahandler.username)
        self.assertIn("ERROR:test_a2c:CAhandler._config_authuser_load() could not load username_variable:'does_not_exist'", lcm.output)

    @patch.dict('os.environ', {'username_var': 'user_var'})
    def test_030_config_authuser_load(self):
        """ test _config_load - load template with user variable """
        parser = configparser.ConfigParser()
        parser['CAhandler'] = {'username_variable': 'username_var', 'username': 'username'}
        self.cahandler._config_authuser_load(parser)
        self.assertEqual('username', self.cahandler.username)

    @patch.dict('os.environ', {'foo': 'bar'})
    def test_031_config_authuser_load(self):
        """ test _config_load - load template with user variable """
        parser = configparser.ConfigParser()
        parser['CAhandler'] = {'foo': 'bar', 'foo1': 'bar1'}
        self.cahandler._config_authuser_load(parser)
        # with self.assertLogs('test_a2c', level='INFO') as lcm:
        self.assertFalse(self.cahandler.username)
        # self.assertIn("foo", lcm.output)

    @patch.dict('os.environ', {'enrollment_code_var': 'user_var'})
    def test_032_config_enrollmentcode_load(self):
        """ test _config_load - load template with user variable """
        parser = configparser.ConfigParser()
        parser['CAhandler'] = {'enrollment_code_variable': 'enrollment_code_var'}
        self.cahandler._config_enrollmentcode_load(parser)
        self.assertEqual('user_var', self.cahandler.enrollment_code)

    @patch.dict('os.environ', {'enrollment_code_var': 'user_var'})
    def test_033_config_enrollmentcode_load(self):
        """ test _config_load - load template with user variable """
        parser = configparser.ConfigParser()
        parser['CAhandler'] = {'enrollment_code_variable': 'does_not_exist'}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_enrollmentcode_load(parser)
        self.assertFalse(self.cahandler.enrollment_code)
        self.assertIn("ERROR:test_a2c:CAhandler._config_authuser_load() could not load enrollment_code_variable:'does_not_exist'", lcm.output)

    @patch.dict('os.environ', {'enrollment_code_var': 'user_var'})
    def test_034_config_enrollmentcode_load(self):
        """ test _config_load - load template with user variable """
        parser = configparser.ConfigParser()
        parser['CAhandler'] = {'enrollment_code_variable': 'enrollment_code_var', 'enrollment_code': 'enrollment_code'}
        self.cahandler._config_enrollmentcode_load(parser)
        self.assertEqual('enrollment_code', self.cahandler.enrollment_code)

    @patch.dict('os.environ', {'foo': 'bar'})
    def test_035_config_enrollmentcode_load(self):
        """ test _config_load - load template with user variable """
        parser = configparser.ConfigParser()
        parser['CAhandler'] = {'foo': 'bar', 'foo1': 'bar1'}
        self.cahandler._config_enrollmentcode_load(parser)
        # with self.assertLogs('test_a2c', level='INFO') as lcm:
        self.assertFalse(self.cahandler.enrollment_code)
        # self.assertIn("foo", lcm.output)

    @patch.dict('os.environ', {'cert_passphrase_var': 'user_var'})
    def test_036_config_session_load(self):
        """ test _config_load - load template with user variable """
        parser = configparser.ConfigParser()
        parser['CAhandler'] = {'cert_passphrase_variable': 'cert_passphrase_var'}
        self.cahandler._config_session_load(parser)
        self.assertEqual('user_var', self.cahandler.cert_passphrase)

    @patch.dict('os.environ', {'cert_passphrase_var': 'user_var'})
    def test_037_config_session_load(self):
        """ test _config_load - load template with user variable """
        parser = configparser.ConfigParser()
        parser['CAhandler'] = {'cert_passphrase_variable': 'does_not_exist'}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_session_load(parser)
        self.assertFalse(self.cahandler.cert_passphrase)
        self.assertIn("ERROR:test_a2c:CAhandler._config_authuser_load() could not load cert_passphrase_variable:'does_not_exist'", lcm.output)

    @patch.dict('os.environ', {'cert_passphrase_var': 'user_var'})
    def test_038_config_session_load(self):
        """ test _config_load - load template with user variable """
        parser = configparser.ConfigParser()
        parser['CAhandler'] = {'cert_passphrase_variable': 'cert_passphrase_var', 'cert_passphrase': 'cert_passphrase'}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_session_load(parser)
        self.assertIn('INFO:test_a2c:CAhandler._config_load() overwrite cert_passphrase', lcm.output)
        self.assertEqual('cert_passphrase', self.cahandler.cert_passphrase)

    @patch.dict('os.environ', {'foo': 'bar'})
    def test_039_config_session_load(self):
        """ test _config_load - load template with user variable """
        parser = configparser.ConfigParser()
        parser['CAhandler'] = {'foo': 'bar', 'foo1': 'bar1'}
        self.cahandler._config_session_load(parser)
        self.assertFalse(self.cahandler.cert_passphrase)

    @patch('requests.Session')
    @patch('examples.ca_handler.ejbca_ca_handler.Pkcs12Adapter')
    def test_040_config_session_load(self, mock_pkcs12, mock_session):
        """ test _config_load - load template with user variable """
        parser = configparser.ConfigParser()
        parser['CAhandler'] = {'cert_file': 'cert_file', 'cert_passphrase': 'cert_passphrase'}
        mock_session.return_value.__enter__.return_value = Mock()
        self.cahandler._config_session_load(parser)
        self.assertEqual('cert_passphrase', self.cahandler.cert_passphrase)
        self.assertTrue(mock_pkcs12.called)
        self.assertTrue(mock_session.called)

    @patch('requests.Session')
    @patch('examples.ca_handler.ejbca_ca_handler.Pkcs12Adapter')
    def test_041_config_session_load(self, mock_pkcs12, mock_session):
        """ test _config_load - load template with user variable """
        parser = configparser.ConfigParser()
        parser['CAhandler'] = {'cert_passphrase': 'cert_passphrase'}
        mock_session.return_value.__enter__.return_value = Mock()
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_session_load(parser)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load(): configuration incomplete: "cert_file"/"cert_passphrase" parameter is missing in configuration file.', lcm.output)
        self.assertEqual('cert_passphrase', self.cahandler.cert_passphrase)
        self.assertFalse(mock_pkcs12.called)
        self.assertFalse(mock_session.called)

    def test_042__api_post(self):
        """ test _api_post successful run """
        mockresponse2 = Mock()
        mockresponse2.json = lambda: {'foo': 'bar'}
        mockresponse = Mock()
        mockresponse.post.side_effect = [mockresponse2]
        self.cahandler.session = mockresponse
        self.assertEqual({'foo': 'bar'}, self.cahandler._api_post('url', 'data'))

    def test_043__api_post(self):
        """ CAhandler._api_post() returns an http error """
        mockresponse = Mock()
        mockresponse.post.side_effect = [Exception('exc_api_post')]
        self.cahandler.session = mockresponse
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual('exc_api_post', self.cahandler._api_post('url', 'data'))
        self.assertIn('ERROR:test_a2c:CAhandler._api_post() returned error: exc_api_post', lcm.output)

    def test_044__api_put(self):
        """ test _api_put successful run """
        mockresponse2 = Mock()
        mockresponse2.json = lambda: {'foo': 'bar'}
        mockresponse = Mock()
        mockresponse.put.side_effect = [mockresponse2]
        self.cahandler.session = mockresponse
        self.assertEqual({'foo': 'bar'}, self.cahandler._api_put('url'))

    def test_045__api_put(self):
        """ CAhandler._api_put() returns an http error """
        mockresponse = Mock()
        mockresponse.put.side_effect = [Exception('exc_api_put')]
        self.cahandler.session = mockresponse
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual('exc_api_put', self.cahandler._api_put('url'))
        self.assertIn('ERROR:test_a2c:CAhandler._api_put() returned error: exc_api_put', lcm.output)

    @patch('examples.ca_handler.ejbca_ca_handler.CAhandler._config_load')
    def test_046__enter(self, mock_cfgload):
        """ CAhandler._enter() with config load """
        self.cahandler.__enter__()
        self.assertTrue(mock_cfgload.called)

    @patch('examples.ca_handler.ejbca_ca_handler.CAhandler._config_load')
    def test_047__enter(self, mock_cfgload):
        """ CAhandler._enter() with config load """
        self.cahandler.api_host = 'api_host'
        self.cahandler.__enter__()
        self.assertFalse(mock_cfgload.called)

    def test_048__cert_status_check(self):
        """ test _cert_status_check  successful run """
        mockresponse = Mock()
        mockresponse.json = lambda: {'foo': 'bar'}
        self.cahandler.session = Mock()
        self.cahandler.session.get.return_value  = mockresponse
        self.cahandler.api_host = 'api_host'
        self.assertEqual({'foo': 'bar'}, self.cahandler._cert_status_check('issuer_dn', 'cert_serial'))

    def test_049__cert_status_check(self):
        """ test _cert_status_check no api host """
        mockresponse = Mock()
        mockresponse.json = lambda: {'foo': 'bar'}
        self.cahandler.session = Mock()
        self.cahandler.session.get.return_value  = mockresponse
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._cert_status_check('issuer_dn', 'cert_serial')
        self.assertIn('ERROR:test_a2c:CAhandler._status_get(): api_host option is misisng in configuration', lcm.output)

    def test_050__cert_status_check(self):
        """ test _cert_status_check exception """
        mockresponse = Mock()
        mockresponse.get.side_effect = [Exception('exc_cert_chk')]
        self.cahandler.session = mockresponse
        self.cahandler.api_host = 'api_host'
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual({'error': 'exc_cert_chk', 'status': 'nok'}, self.cahandler._cert_status_check('issuer_dn', 'cert_serial'))
        self.assertIn('ERROR:test_a2c:CAhandler._ca_get() returned error: exc_cert_chk', lcm.output)

    def test_051__status_get(self):
        """ test _status_get  successful run """
        mockresponse = Mock()
        mockresponse.json = lambda: {'foo': 'bar'}
        self.cahandler.session = Mock()
        self.cahandler.session.get.return_value  = mockresponse
        self.cahandler.api_host = 'api_host'
        self.assertEqual({'foo': 'bar'}, self.cahandler._status_get())

    def test_052__status_get(self):
        """ test _status_get  no api host """
        mockresponse = Mock()
        mockresponse.json = lambda: {'foo': 'bar'}
        self.cahandler.session = Mock()
        self.cahandler.session.get.return_value  = mockresponse
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._status_get()
        self.assertIn('ERROR:test_a2c:CAhandler._status_get(): api_host parameter is missing in configuration', lcm.output)

    def test_053__status_get(self):
        """ test _cert_status_check exception """
        mockresponse = Mock()
        mockresponse.get.side_effect = [Exception('exc_status_chk')]
        self.cahandler.session = mockresponse
        self.cahandler.api_host = 'api_host'
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual({'error': 'exc_status_chk', 'status': 'nok'}, self.cahandler._status_get())
        self.assertIn('ERROR:test_a2c:CAhandler._status_get() returned error: exc_status_chk', lcm.output)

    @patch('examples.ca_handler.ejbca_ca_handler.CAhandler._api_post')
    def test_054__sign(self, mock_post):
        """ test _sign """
        self.cahandler.api_host = 'foo'
        mock_post.return_value = 'foo'
        self.assertEqual('foo', self.cahandler._sign('csr'))


    @patch('examples.ca_handler.ejbca_ca_handler.CAhandler._api_post')
    def test_055__sign(self, mock_post):
        """ test _sign """
        mock_post.return_value = 'foo'
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertFalse(self.cahandler._sign('csr'))
        self.assertIn('ERROR:test_a2c:CAhandler._status_get(): api_host is misisng in configuration', lcm.output)

    def test_056_poll(self):
        """ test polling """
        self.assertEqual(('Method not implemented.', None, None, 'poll_identifier', False), self.cahandler.poll('cert_name', 'poll_identifier', 'csr'))

    def test_057_trigger(self):
        """ test polling """
        self.assertEqual(('Method not implemented.', None, None), self.cahandler.trigger('payload'))

    @patch('examples.ca_handler.ejbca_ca_handler.CAhandler._status_get')
    def test_058_enroll(self, mock_status):
        """ test enrollment """
        mock_status.return_value = {'foo': 'bar'}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual(('Unknown error', None, None, None), self.cahandler.enroll('csr'))
        self.assertIn('ERROR:test_a2c:CAhandler.enroll(): Unknown error', lcm.output)

    @patch('examples.ca_handler.ejbca_ca_handler.CAhandler._status_get')
    def test_059_enroll(self, mock_status):
        """ test enrollment """
        mock_status.return_value = {'status': 'nok'}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual(('Unknown error', None, None, None), self.cahandler.enroll('csr'))
        self.assertIn('ERROR:test_a2c:CAhandler.enroll(): Unknown error', lcm.output)

    @patch('examples.ca_handler.ejbca_ca_handler.CAhandler._status_get')
    def test_060_enroll(self, mock_status):
        """ test enrollment """
        mock_status.return_value = {'status': 'nok', 'error': 'error_msg'}
        self.assertEqual(('error_msg', None, None, None), self.cahandler.enroll('csr'))

    @patch('examples.ca_handler.ejbca_ca_handler.convert_byte_to_string')
    @patch('examples.ca_handler.ejbca_ca_handler.cert_der2pem')
    @patch('examples.ca_handler.ejbca_ca_handler.b64_decode')
    @patch('examples.ca_handler.ejbca_ca_handler.b64_url_recode')
    @patch('examples.ca_handler.ejbca_ca_handler.build_pem_file')
    @patch('examples.ca_handler.ejbca_ca_handler.CAhandler._sign')
    @patch('examples.ca_handler.ejbca_ca_handler.CAhandler._status_get')
    def test_061_enroll(self, mock_status, mock_sign, mock_pem, mock_recode, mock_decode, mock_d2p, mock_b2s):
        """ test enrollment """
        mock_status.return_value = {'status': 'ok'}
        mock_sign.return_value = {}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual(('Malformed response', None, None, None), self.cahandler.enroll('csr'))
        self.assertIn("ERROR:test_a2c:CAhandler.enroll(): Malformed Rest response: {}", lcm.output)
        self.assertTrue(mock_recode.called)
        self.assertTrue(mock_pem.called)
        self.assertTrue(mock_sign.called)
        self.assertFalse(mock_decode.called)
        self.assertFalse(mock_d2p.called)
        self.assertFalse(mock_b2s.called)

    @patch('examples.ca_handler.ejbca_ca_handler.convert_byte_to_string')
    @patch('examples.ca_handler.ejbca_ca_handler.cert_der2pem')
    @patch('examples.ca_handler.ejbca_ca_handler.b64_decode')
    @patch('examples.ca_handler.ejbca_ca_handler.b64_url_recode')
    @patch('examples.ca_handler.ejbca_ca_handler.build_pem_file')
    @patch('examples.ca_handler.ejbca_ca_handler.CAhandler._sign')
    @patch('examples.ca_handler.ejbca_ca_handler.CAhandler._status_get')
    def test_062_enroll(self, mock_status, mock_sign, mock_pem, mock_recode, mock_decode, mock_d2p, mock_b2s):
        """ test enrollment """
        mock_status.return_value = {'status': 'ok'}
        mock_sign.return_value = {'certificate': 'certificate'}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual(('Malformed response', None, None, None), self.cahandler.enroll('csr'))
        self.assertIn("ERROR:test_a2c:CAhandler.enroll(): Malformed Rest response: {'certificate': 'certificate'}", lcm.output)
        self.assertTrue(mock_recode.called)
        self.assertTrue(mock_pem.called)
        self.assertTrue(mock_sign.called)
        self.assertFalse(mock_decode.called)
        self.assertFalse(mock_d2p.called)
        self.assertFalse(mock_b2s.called)

    @patch('examples.ca_handler.ejbca_ca_handler.enrollment_config_log')
    @patch('examples.ca_handler.ejbca_ca_handler.convert_byte_to_string')
    @patch('examples.ca_handler.ejbca_ca_handler.cert_der2pem')
    @patch('examples.ca_handler.ejbca_ca_handler.b64_decode')
    @patch('examples.ca_handler.ejbca_ca_handler.b64_url_recode')
    @patch('examples.ca_handler.ejbca_ca_handler.build_pem_file')
    @patch('examples.ca_handler.ejbca_ca_handler.CAhandler._sign')
    @patch('examples.ca_handler.ejbca_ca_handler.CAhandler._status_get')
    def test_063_enroll(self, mock_status, mock_sign, mock_pem, mock_recode, mock_decode, mock_d2p, mock_b2s, mock_ecl):
        """ test enrollment """
        mock_status.return_value = {'status': 'ok'}
        mock_sign.return_value = {'certificate_chain': 'certificate_chain'}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual(('Malformed response', None, None, None), self.cahandler.enroll('csr'))
        self.assertIn("ERROR:test_a2c:CAhandler.enroll(): Malformed Rest response: {'certificate_chain': 'certificate_chain'}", lcm.output)
        self.assertTrue(mock_recode.called)
        self.assertTrue(mock_pem.called)
        self.assertTrue(mock_sign.called)
        self.assertFalse(mock_decode.called)
        self.assertFalse(mock_d2p.called)
        self.assertFalse(mock_b2s.called)
        self.assertFalse(mock_ecl.called)

    @patch('examples.ca_handler.ejbca_ca_handler.enrollment_config_log')
    @patch('examples.ca_handler.ejbca_ca_handler.convert_byte_to_string')
    @patch('examples.ca_handler.ejbca_ca_handler.cert_der2pem')
    @patch('examples.ca_handler.ejbca_ca_handler.b64_decode')
    @patch('examples.ca_handler.ejbca_ca_handler.b64_url_recode')
    @patch('examples.ca_handler.ejbca_ca_handler.build_pem_file')
    @patch('examples.ca_handler.ejbca_ca_handler.CAhandler._sign')
    @patch('examples.ca_handler.ejbca_ca_handler.CAhandler._status_get')
    def test_064_enroll(self, mock_status, mock_sign, mock_pem, mock_recode, mock_decode, mock_d2p, mock_b2s, mock_ecl):
        """ test enrollment """
        mock_status.return_value = {'status': 'ok'}
        mock_sign.return_value = {'certificate_chain': 'certificate_chain'}
        self.cahandler.enrollment_config_log = True
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual(('Malformed response', None, None, None), self.cahandler.enroll('csr'))
        self.assertIn("ERROR:test_a2c:CAhandler.enroll(): Malformed Rest response: {'certificate_chain': 'certificate_chain'}", lcm.output)
        self.assertTrue(mock_recode.called)
        self.assertTrue(mock_pem.called)
        self.assertTrue(mock_sign.called)
        self.assertFalse(mock_decode.called)
        self.assertFalse(mock_d2p.called)
        self.assertFalse(mock_b2s.called)
        self.assertTrue(mock_ecl.called)

    @patch('examples.ca_handler.ejbca_ca_handler.allowed_domainlist_check')
    @patch('examples.ca_handler.ejbca_ca_handler.eab_profile_header_info_check')
    @patch('examples.ca_handler.ejbca_ca_handler.convert_byte_to_string')
    @patch('examples.ca_handler.ejbca_ca_handler.cert_der2pem')
    @patch('examples.ca_handler.ejbca_ca_handler.b64_decode')
    @patch('examples.ca_handler.ejbca_ca_handler.b64_url_recode')
    @patch('examples.ca_handler.ejbca_ca_handler.build_pem_file')
    @patch('examples.ca_handler.ejbca_ca_handler.CAhandler._sign')
    @patch('examples.ca_handler.ejbca_ca_handler.CAhandler._status_get')
    def test_065_enroll(self, mock_status, mock_sign, mock_pem, mock_recode, mock_decode, mock_d2p, mock_b2s, profile_header_info_check, mock_adl):
        """ test enrollment one ca-cert """
        mock_status.return_value = {'status': 'ok'}
        mock_sign.return_value = {'certificate': 'certificate', 'certificate_chain': ['certificate_chain']}
        mock_b2s.side_effect = ['foo1', 'foo2',]
        profile_header_info_check.return_value = False
        mock_adl.return_value = None
        self.assertEqual((None, 'foo1foo2', 'certificate', None), self.cahandler.enroll('csr'))
        self.assertTrue(mock_recode.called)
        self.assertTrue(mock_pem.called)
        self.assertTrue(mock_sign.called)
        self.assertTrue(mock_decode.called)
        self.assertTrue(mock_d2p.called)
        self.assertTrue(mock_b2s.called)
        self.assertTrue(mock_adl.called)

    @patch('examples.ca_handler.ejbca_ca_handler.allowed_domainlist_check')
    @patch('examples.ca_handler.ejbca_ca_handler.eab_profile_header_info_check')
    @patch('examples.ca_handler.ejbca_ca_handler.convert_byte_to_string')
    @patch('examples.ca_handler.ejbca_ca_handler.cert_der2pem')
    @patch('examples.ca_handler.ejbca_ca_handler.b64_decode')
    @patch('examples.ca_handler.ejbca_ca_handler.b64_url_recode')
    @patch('examples.ca_handler.ejbca_ca_handler.build_pem_file')
    @patch('examples.ca_handler.ejbca_ca_handler.CAhandler._sign')
    @patch('examples.ca_handler.ejbca_ca_handler.CAhandler._status_get')
    def test_066_enroll(self, mock_status, mock_sign, mock_pem, mock_recode, mock_decode, mock_d2p, mock_b2s, profile_header_info_check, mock_adl):
        """ test enrollment one ca-cert """
        mock_status.return_value = {'status': 'ok'}
        mock_sign.return_value = {'certificate': 'certificate', 'certificate_chain': ['certificate_chain']}
        mock_b2s.side_effect = ['foo1', 'foo2',]
        profile_header_info_check.return_value = False
        mock_adl.return_value = 'mock_adl'
        self.assertEqual(('mock_adl', None, None, None), self.cahandler.enroll('csr'))
        self.assertFalse(mock_recode.called)
        self.assertFalse(mock_pem.called)
        self.assertFalse(mock_sign.called)
        self.assertFalse(mock_decode.called)
        self.assertFalse(mock_d2p.called)
        self.assertFalse(mock_b2s.called)
        self.assertTrue(mock_adl.called)

    @patch('examples.ca_handler.ejbca_ca_handler.eab_profile_header_info_check')
    @patch('examples.ca_handler.ejbca_ca_handler.convert_byte_to_string')
    @patch('examples.ca_handler.ejbca_ca_handler.cert_der2pem')
    @patch('examples.ca_handler.ejbca_ca_handler.b64_decode')
    @patch('examples.ca_handler.ejbca_ca_handler.b64_url_recode')
    @patch('examples.ca_handler.ejbca_ca_handler.build_pem_file')
    @patch('examples.ca_handler.ejbca_ca_handler.CAhandler._sign')
    @patch('examples.ca_handler.ejbca_ca_handler.CAhandler._status_get')
    def test_067_enroll(self, mock_status, mock_sign, mock_pem, mock_recode, mock_decode, mock_d2p, mock_b2s, profile_header_info_check):
        """ test enrollment one ca-cert """
        mock_status.return_value = {'status': 'ok'}
        mock_sign.return_value = {'certificate': 'certificate', 'certificate_chain': ['certificate_chain']}
        mock_b2s.side_effect = ['foo1', 'foo2',]
        profile_header_info_check.return_value = 'error'
        self.assertEqual(('error', None, None, None), self.cahandler.enroll('csr'))
        self.assertFalse(mock_recode.called)
        self.assertFalse(mock_pem.called)
        self.assertFalse(mock_sign.called)
        self.assertFalse(mock_decode.called)
        self.assertFalse(mock_d2p.called)
        self.assertFalse(mock_b2s.called)

    @patch('examples.ca_handler.ejbca_ca_handler.convert_byte_to_string')
    @patch('examples.ca_handler.ejbca_ca_handler.cert_der2pem')
    @patch('examples.ca_handler.ejbca_ca_handler.b64_decode')
    @patch('examples.ca_handler.ejbca_ca_handler.b64_url_recode')
    @patch('examples.ca_handler.ejbca_ca_handler.build_pem_file')
    @patch('examples.ca_handler.ejbca_ca_handler.CAhandler._sign')
    @patch('examples.ca_handler.ejbca_ca_handler.CAhandler._status_get')
    def test_068_enroll(self, mock_status, mock_sign, mock_pem, mock_recode, mock_decode, mock_d2p, mock_b2s):
        """ test enrollment two ca-certs """
        mock_status.return_value = {'status': 'ok'}
        mock_sign.return_value = {'certificate': 'certificate', 'certificate_chain': ['certificate_chain', 'certificate_chain']}
        mock_b2s.side_effect = ['foo1', 'foo2', 'foo3']
        self.assertEqual((None, 'foo1foo2foo3', 'certificate', None), self.cahandler.enroll('csr'))
        self.assertTrue(mock_recode.called)
        self.assertTrue(mock_pem.called)
        self.assertTrue(mock_sign.called)
        self.assertTrue(mock_decode.called)
        self.assertTrue(mock_d2p.called)
        self.assertTrue(mock_b2s.called)

    @patch('examples.ca_handler.ejbca_ca_handler.CAhandler._api_put')
    @patch('examples.ca_handler.ejbca_ca_handler.encode_url')
    @patch('examples.ca_handler.ejbca_ca_handler.CAhandler._cert_status_check')
    @patch('examples.ca_handler.ejbca_ca_handler.cert_issuer_get')
    @patch('examples.ca_handler.ejbca_ca_handler.cert_serial_get')
    def test_069_revoke(self, mock_serial, mock_issuer, mock_status, mock_encode, mock_put):
        """ test revoke operation malformed api response """
        mock_status.return_value = {}
        self.assertEqual((400, 'urn:ietf:params:acme:error:serverInternal', 'Unknown status'), self.cahandler.revoke('cert'))
        self.assertTrue(mock_serial.called)
        self.assertTrue(mock_issuer.called)

    @patch('examples.ca_handler.ejbca_ca_handler.CAhandler._api_put')
    @patch('examples.ca_handler.ejbca_ca_handler.encode_url')
    @patch('examples.ca_handler.ejbca_ca_handler.CAhandler._cert_status_check')
    @patch('examples.ca_handler.ejbca_ca_handler.cert_issuer_get')
    @patch('examples.ca_handler.ejbca_ca_handler.cert_serial_get')
    def test_070_revoke(self, mock_serial, mock_issuer, mock_status, mock_encode, mock_put):
        """ test revoke operation cert already revoked """
        mock_status.return_value = {'revoked': True}
        self.assertEqual((400, 'urn:ietf:params:acme:error:alreadyRevoked', 'Certificate has already been revoked'), self.cahandler.revoke('cert'))
        self.assertTrue(mock_serial.called)
        self.assertTrue(mock_issuer.called)

    @patch('examples.ca_handler.ejbca_ca_handler.CAhandler._api_put')
    @patch('examples.ca_handler.ejbca_ca_handler.encode_url')
    @patch('examples.ca_handler.ejbca_ca_handler.CAhandler._cert_status_check')
    @patch('examples.ca_handler.ejbca_ca_handler.cert_issuer_get')
    @patch('examples.ca_handler.ejbca_ca_handler.cert_serial_get')
    def test_071_revoke(self, mock_serial, mock_issuer, mock_status, mock_encode, mock_put):
        """ test revoke operation - revocation response malformed """
        mock_status.return_value = {'revoked': False}
        mock_put.return_value = {'foo': 'bar'}
        self.cahandler.api_host = 'api_host'
        self.assertEqual((400, 'urn:ietf:params:acme:error:serverInternal', "{'foo': 'bar'}"), self.cahandler.revoke('cert'))
        self.assertTrue(mock_serial.called)
        self.assertTrue(mock_issuer.called)
        self.assertTrue(mock_encode.called)
        self.assertTrue(mock_put.called)

    @patch('examples.ca_handler.ejbca_ca_handler.CAhandler._api_put')
    @patch('examples.ca_handler.ejbca_ca_handler.encode_url')
    @patch('examples.ca_handler.ejbca_ca_handler.CAhandler._cert_status_check')
    @patch('examples.ca_handler.ejbca_ca_handler.cert_issuer_get')
    @patch('examples.ca_handler.ejbca_ca_handler.cert_serial_get')
    def test_072_revoke(self, mock_serial, mock_issuer, mock_status, mock_encode, mock_put):
        """ test revoke operation - revocation unsuccessful """
        mock_status.return_value = {'revoked': False}
        mock_put.return_value = {'revoked': False}
        self.cahandler.api_host = 'api_host'
        self.assertEqual((400, 'urn:ietf:params:acme:error:serverInternal', "{'revoked': False}"), self.cahandler.revoke('cert'))
        self.assertTrue(mock_serial.called)
        self.assertTrue(mock_issuer.called)
        self.assertTrue(mock_encode.called)
        self.assertTrue(mock_put.called)

    @patch('examples.ca_handler.ejbca_ca_handler.CAhandler._api_put')
    @patch('examples.ca_handler.ejbca_ca_handler.encode_url')
    @patch('examples.ca_handler.ejbca_ca_handler.CAhandler._cert_status_check')
    @patch('examples.ca_handler.ejbca_ca_handler.cert_issuer_get')
    @patch('examples.ca_handler.ejbca_ca_handler.cert_serial_get')
    def test_073_revoke(self, mock_serial, mock_issuer, mock_status, mock_encode, mock_put):
        """ test revoke operation - revocation unsuccessful """
        mock_status.return_value = {'revoked': False}
        mock_put.return_value = {'revoked': True}
        self.cahandler.api_host = 'api_host'
        self.assertEqual((200, None, None), self.cahandler.revoke('cert'))
        self.assertTrue(mock_serial.called)
        self.assertTrue(mock_issuer.called)
        self.assertTrue(mock_encode.called)
        self.assertTrue(mock_put.called)


if __name__ == '__main__':

    if os.path.exists('acme_test.db'):
        os.remove('acme_test.db')
    unittest.main()
