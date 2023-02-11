#!/usr/bin/python
# -*- coding: utf-8 -*-
""" unittests for acme2certifier """
# pylint: disable= C0415, W0212
import unittest
import sys
import os
from unittest.mock import patch, Mock

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
        config_dic = {}
        self.cahandler._config_server_load(config_dic)
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
        config_dic = {'CAhandler': {'foo': 'bar'}}
        self.cahandler._config_server_load(config_dic)
        self.assertFalse(self.cahandler.api_host)
        self.assertEqual(5, self.cahandler.request_timeout)
        self.assertTrue(self.cahandler.ca_bundle)

    def test_005__config_server_load(self):
        """ test _config_server_load() """
        config_dic = {'CAhandler': {'api_host': 'api_host'}}
        self.cahandler._config_server_load(config_dic)
        self.assertEqual('api_host', self.cahandler.api_host)
        self.assertEqual(5, self.cahandler.request_timeout)
        self.assertTrue(self.cahandler.ca_bundle)

    def test_006__config_server_load(self):
        """ test _config_server_load() """
        config_dic = {'CAhandler': {'request_timeout': 10}}
        self.cahandler._config_server_load(config_dic)
        self.assertFalse(self.cahandler.api_host)
        self.assertEqual(10, self.cahandler.request_timeout)
        self.assertTrue(self.cahandler.ca_bundle)

    def test_007__config_server_load(self):
        """ test _config_server_load() """
        config_dic = {'CAhandler': {'ca_bundle': 'ca_bundle'}}
        self.cahandler._config_server_load(config_dic)
        self.assertFalse(self.cahandler.api_host)
        self.assertEqual(5, self.cahandler.request_timeout)
        self.assertEqual('ca_bundle', self.cahandler.ca_bundle)

    def test_008__config_server_load(self):
        """ test _config_server_load() """
        config_dic = {'CAhandler': {'ca_bundle': False}}
        self.cahandler._config_server_load(config_dic)
        self.assertFalse(self.cahandler.api_host)
        self.assertEqual(5, self.cahandler.request_timeout)
        self.assertFalse(self.cahandler.ca_bundle)

    def test_009__config_auth_load(self):
        """ test _config_server_load() """
        config_dic = {'CAhandler': {'foo': 'bar'}}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_auth_load(config_dic)
        self.assertFalse(self.cahandler.username)
        self.assertFalse(self.cahandler.enrollment_code)
        self.assertFalse(self.cahandler.session)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load(): configuration incomplete: "cert_file"/"cert_passphrase" parameter is missing in configuration file.', lcm.output)

    def test_010__config_auth_load(self):
        """ test _config_server_load() """
        config_dic = {'CAhandler': {'username': 'username'}}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_auth_load(config_dic)
        self.assertEqual('username', self.cahandler.username)
        self.assertFalse(self.cahandler.enrollment_code)
        self.assertFalse(self.cahandler.session)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load(): configuration incomplete: "cert_file"/"cert_passphrase" parameter is missing in configuration file.', lcm.output)

    def test_011__config_auth_load(self):
        """ test _config_server_load() """
        config_dic = {'CAhandler': {'enrollment_code': 'enrollment_code'}}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_auth_load(config_dic)
        self.assertEqual('enrollment_code', self.cahandler.enrollment_code)
        self.assertFalse(self.cahandler.username)
        self.assertFalse(self.cahandler.session)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load(): configuration incomplete: "cert_file"/"cert_passphrase" parameter is missing in configuration file.', lcm.output)

    def test_012__config_auth_load(self):
        """ test _config_server_load() """
        config_dic = {'CAhandler': {'cert_passphrase': 'cert_passphrase'}}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_auth_load(config_dic)
        self.assertFalse(self.cahandler.username)
        self.assertFalse(self.cahandler.enrollment_code)
        self.assertFalse(self.cahandler.session)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load(): configuration incomplete: "cert_file"/"cert_passphrase" parameter is missing in configuration file.', lcm.output)

    def test_013__config_auth_load(self):
        """ test _config_server_load() """
        config_dic = {'CAhandler': {'cert_file': 'cert_file'}}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_auth_load(config_dic)
        self.assertFalse(self.cahandler.username)
        self.assertFalse(self.cahandler.enrollment_code)
        self.assertFalse(self.cahandler.session)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load(): configuration incomplete: "cert_file"/"cert_passphrase" parameter is missing in configuration file.', lcm.output)

    @patch('examples.ca_handler.ejbca_ca_handler.requests.Session')
    def test_014__config_auth_load(self, mock_sess):
        """ test _config_server_load() """
        config_dic = {'CAhandler': {'cert_file': 'cert_file', 'cert_passphrase': 'cert_passphrase'}}
        mock_sess.return_value = Mock()
        mock_sess.return_value.__enter__= Mock()
        mock_sess.return_value.__exit__= Mock()
        self.cahandler._config_auth_load(config_dic)
        self.assertFalse(self.cahandler.username)
        self.assertFalse(self.cahandler.enrollment_code)
        self.assertTrue(self.cahandler.session)

    def test_015__config_cainfo_load(self):
        """ test _config_server_load() """
        config_dic = {'CAhandler': {'foo': 'bar'}}
        self.cahandler._config_cainfo_load(config_dic)
        self.assertFalse(self.cahandler.ca_name)
        self.assertFalse(self.cahandler.cert_profile_name)
        self.assertFalse(self.cahandler.ee_profile_name)

    def test_016__config_cainfo_load(self):
        """ test _config_server_load() """
        config_dic = {'CAhandler': {'ca_name': 'ca_name'}}
        self.cahandler._config_cainfo_load(config_dic)
        self.assertEqual('ca_name', self.cahandler.ca_name)
        self.assertFalse(self.cahandler.cert_profile_name)
        self.assertFalse(self.cahandler.ee_profile_name)

    def test_017__config_cainfo_load(self):
        """ test _config_server_load() """
        config_dic = {'CAhandler': {'cert_profile_name': 'cert_profile_name'}}
        self.cahandler._config_cainfo_load(config_dic)
        self.assertFalse(self.cahandler.ca_name)
        self.assertEqual('cert_profile_name', self.cahandler.cert_profile_name)
        self.assertFalse(self.cahandler.ee_profile_name)

    def test_018__config_cainfo_load(self):
        """ test _config_server_load() """
        config_dic = {'CAhandler': {'ee_profile_name': 'ee_profile_name'}}
        self.cahandler._config_cainfo_load(config_dic)
        self.assertFalse(self.cahandler.ca_name)
        self.assertFalse(self.cahandler.cert_profile_name)
        self.assertEqual('ee_profile_name', self.cahandler.ee_profile_name)

    @patch('examples.ca_handler.ejbca_ca_handler.CAhandler._config_server_load')
    @patch('examples.ca_handler.ejbca_ca_handler.CAhandler._config_auth_load')
    @patch('examples.ca_handler.ejbca_ca_handler.CAhandler._config_cainfo_load')
    @patch('examples.ca_handler.ejbca_ca_handler.load_config')
    def test_019_config_load(self, mock_load_cfg, mock_cainfo, mock_auth_load, mock_server_load):
        """ load config """
        mock_load_cfg.return_value = {'foo': 'bar'}
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
    def test_020_config_load(self, mock_load_cfg, mock_cainfo, mock_auth_load, mock_server_load):
        """ load config """
        mock_load_cfg.return_value = {'foo': 'bar'}
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
    def test_021_config_load(self, mock_load_cfg, mock_cainfo, mock_auth_load, mock_server_load):
        """ load config """
        mock_load_cfg.return_value = {'foo': 'bar'}
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
    def test_022_config_load(self, mock_load_cfg, mock_cainfo, mock_auth_load, mock_server_load):
        """ load config """
        mock_load_cfg.return_value = {'foo': 'bar'}
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
    def test_023_config_load(self, mock_load_cfg, mock_cainfo, mock_auth_load, mock_server_load):
        """ load config """
        mock_load_cfg.return_value = {'foo': 'bar'}
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
    def test_024_config_load(self, mock_load_cfg, mock_cainfo, mock_auth_load, mock_server_load):
        """ load config """
        mock_load_cfg.return_value = {'foo': 'bar'}
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
    def test_025_config_load(self, mock_load_cfg, mock_cainfo, mock_auth_load, mock_server_load):
        """ load config """
        mock_load_cfg.return_value = {'foo': 'bar'}
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

    def test_026__api_post(self):
        """ test _api_post successful run """
        mockresponse2 = Mock()
        mockresponse2.json = lambda: {'foo': 'bar'}
        mockresponse = Mock()
        mockresponse.post.side_effect = [mockresponse2]
        self.cahandler.session = mockresponse
        self.assertEqual({'foo': 'bar'}, self.cahandler._api_post('url', 'data'))

    def test_027__api_post(self):
        """ CAhandler._api_post() returns an http error """
        mockresponse = Mock()
        mockresponse.post.side_effect = [Exception('exc_api_post')]
        self.cahandler.session = mockresponse
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual('exc_api_post', self.cahandler._api_post('url', 'data'))
        self.assertIn('ERROR:test_a2c:CAhandler._api_post() returned error: exc_api_post', lcm.output)

    def test_028__api_put(self):
        """ test _api_put successful run """
        mockresponse2 = Mock()
        mockresponse2.json = lambda: {'foo': 'bar'}
        mockresponse = Mock()
        mockresponse.put.side_effect = [mockresponse2]
        self.cahandler.session = mockresponse
        self.assertEqual({'foo': 'bar'}, self.cahandler._api_put('url', 'data'))

    def test_028__api_put(self):
        """ CAhandler._api_put() returns an http error """
        mockresponse = Mock()
        mockresponse.put.side_effect = [Exception('exc_api_put')]
        self.cahandler.session = mockresponse
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual('exc_api_put', self.cahandler._api_put('url'))
        self.assertIn('ERROR:test_a2c:CAhandler._api_put() returned error: exc_api_put', lcm.output)

    @patch('examples.ca_handler.ejbca_ca_handler.CAhandler._config_load')
    def test_029__enter(self, mock_cfgload):
        """ CAhandler._enter() with config load """
        self.cahandler.__enter__()
        self.assertTrue(mock_cfgload.called)

    @patch('examples.ca_handler.ejbca_ca_handler.CAhandler._config_load')
    def test_030__enter(self, mock_cfgload):
        """ CAhandler._enter() with config load """
        self.cahandler.api_host = 'api_host'
        self.cahandler.__enter__()
        self.assertFalse(mock_cfgload.called)

    def test_031__cert_status_check(self):
        """ test _cert_status_check  successful run """
        mockresponse = Mock()
        mockresponse.json = lambda: {'foo': 'bar'}
        self.cahandler.session = Mock()
        self.cahandler.session.get.return_value  = mockresponse
        self.cahandler.api_host = 'api_host'
        self.assertEqual({'foo': 'bar'}, self.cahandler._cert_status_check('issuer_dn', 'cert_serial'))

    def test_032__cert_status_check(self):
        """ test _cert_status_check no api host """
        mockresponse = Mock()
        mockresponse.json = lambda: {'foo': 'bar'}
        self.cahandler.session = Mock()
        self.cahandler.session.get.return_value  = mockresponse
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._cert_status_check('issuer_dn', 'cert_serial')
        self.assertIn('ERROR:test_a2c:CAhandler._status_get(): api_host option is misisng in configuration', lcm.output)

    def test_033__cert_status_check(self):
        """ test _cert_status_check exception """
        mockresponse = Mock()
        mockresponse.get.side_effect = [Exception('exc_cert_chk')]
        self.cahandler.session = mockresponse
        self.cahandler.api_host = 'api_host'
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual({'error': 'exc_cert_chk', 'status': 'nok'}, self.cahandler._cert_status_check('issuer_dn', 'cert_serial'))
        self.assertIn('ERROR:test_a2c:CAhandler._ca_get() returned error: exc_cert_chk', lcm.output)

    def test_034__status_get(self):
        """ test _status_get  successful run """
        mockresponse = Mock()
        mockresponse.json = lambda: {'foo': 'bar'}
        self.cahandler.session = Mock()
        self.cahandler.session.get.return_value  = mockresponse
        self.cahandler.api_host = 'api_host'
        self.assertEqual({'foo': 'bar'}, self.cahandler._status_get())

    def test_035__status_get(self):
        """ test _status_get  no api host """
        mockresponse = Mock()
        mockresponse.json = lambda: {'foo': 'bar'}
        self.cahandler.session = Mock()
        self.cahandler.session.get.return_value  = mockresponse
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._status_get()
        self.assertIn('ERROR:test_a2c:CAhandler._status_get(): api_host parameter is misisng in configuration', lcm.output)

    def test_036__status_get(self):
        """ test _cert_status_check exception """
        mockresponse = Mock()
        mockresponse.get.side_effect = [Exception('exc_status_chk')]
        self.cahandler.session = mockresponse
        self.cahandler.api_host = 'api_host'
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual({'error': 'exc_status_chk', 'status': 'nok'}, self.cahandler._status_get())
        self.assertIn('ERROR:test_a2c:CAhandler._ca_get() returned error: exc_status_chk', lcm.output)

    @patch('examples.ca_handler.ejbca_ca_handler.CAhandler._api_post')
    def test_037__sign(self, mock_post):
        """ test _sign """
        self.cahandler.api_host = 'foo'
        mock_post.return_value = 'foo'
        self.assertEqual('foo', self.cahandler._sign('csr'))


    @patch('examples.ca_handler.ejbca_ca_handler.CAhandler._api_post')
    def test_038__sign(self, mock_post):
        """ test _sign """
        mock_post.return_value = 'foo'
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertFalse(self.cahandler._sign('csr'))
        self.assertIn('ERROR:test_a2c:CAhandler._status_get(): api_host is misisng in configuration', lcm.output)

    def test_039_poll(self):
        """ test polling """
        self.assertEqual(('Method not implemented.', None, None, 'poll_identifier', False), self.cahandler.poll('cert_name', 'poll_identifier', 'csr'))

    def test_040_trigger(self):
        """ test polling """
        self.assertEqual(('Method not implemented.', None, None), self.cahandler.trigger('payload'))

    @patch('examples.ca_handler.ejbca_ca_handler.CAhandler._status_get')
    def test_041_enroll(self, mock_status):
        """ test enrollment """
        mock_status.return_value = {'foo': 'bar'}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual(('Unknown error', None, None, None), self.cahandler.enroll('csr'))
        self.assertIn('ERROR:test_a2c:CAhandler.enroll(): Unknown error', lcm.output)

    @patch('examples.ca_handler.ejbca_ca_handler.CAhandler._status_get')
    def test_042_enroll(self, mock_status):
        """ test enrollment """
        mock_status.return_value = {'status': 'nok'}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual(('Unknown error', None, None, None), self.cahandler.enroll('csr'))
        self.assertIn('ERROR:test_a2c:CAhandler.enroll(): Unknown error', lcm.output)

    @patch('examples.ca_handler.ejbca_ca_handler.CAhandler._status_get')
    def test_043_enroll(self, mock_status):
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
    def test_044_enroll(self, mock_status, mock_sign, mock_pem, mock_recode, mock_decode, mock_d2p, mock_b2s):
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
    def test_045_enroll(self, mock_status, mock_sign, mock_pem, mock_recode, mock_decode, mock_d2p, mock_b2s):
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

    @patch('examples.ca_handler.ejbca_ca_handler.convert_byte_to_string')
    @patch('examples.ca_handler.ejbca_ca_handler.cert_der2pem')
    @patch('examples.ca_handler.ejbca_ca_handler.b64_decode')
    @patch('examples.ca_handler.ejbca_ca_handler.b64_url_recode')
    @patch('examples.ca_handler.ejbca_ca_handler.build_pem_file')
    @patch('examples.ca_handler.ejbca_ca_handler.CAhandler._sign')
    @patch('examples.ca_handler.ejbca_ca_handler.CAhandler._status_get')
    def test_046_enroll(self, mock_status, mock_sign, mock_pem, mock_recode, mock_decode, mock_d2p, mock_b2s):
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

    @patch('examples.ca_handler.ejbca_ca_handler.convert_byte_to_string')
    @patch('examples.ca_handler.ejbca_ca_handler.cert_der2pem')
    @patch('examples.ca_handler.ejbca_ca_handler.b64_decode')
    @patch('examples.ca_handler.ejbca_ca_handler.b64_url_recode')
    @patch('examples.ca_handler.ejbca_ca_handler.build_pem_file')
    @patch('examples.ca_handler.ejbca_ca_handler.CAhandler._sign')
    @patch('examples.ca_handler.ejbca_ca_handler.CAhandler._status_get')
    def test_047_enroll(self, mock_status, mock_sign, mock_pem, mock_recode, mock_decode, mock_d2p, mock_b2s):
        """ test enrollment one ca-cert """
        mock_status.return_value = {'status': 'ok'}
        mock_sign.return_value = {'certificate': 'certificate', 'certificate_chain': ['certificate_chain']}
        mock_b2s.side_effect = ['foo1', 'foo2',]
        self.assertEqual((None, 'foo1foo2', 'certificate', None), self.cahandler.enroll('csr'))
        self.assertTrue(mock_recode.called)
        self.assertTrue(mock_pem.called)
        self.assertTrue(mock_sign.called)
        self.assertTrue(mock_decode.called)
        self.assertTrue(mock_d2p.called)
        self.assertTrue(mock_b2s.called)

    @patch('examples.ca_handler.ejbca_ca_handler.convert_byte_to_string')
    @patch('examples.ca_handler.ejbca_ca_handler.cert_der2pem')
    @patch('examples.ca_handler.ejbca_ca_handler.b64_decode')
    @patch('examples.ca_handler.ejbca_ca_handler.b64_url_recode')
    @patch('examples.ca_handler.ejbca_ca_handler.build_pem_file')
    @patch('examples.ca_handler.ejbca_ca_handler.CAhandler._sign')
    @patch('examples.ca_handler.ejbca_ca_handler.CAhandler._status_get')
    def test_048_enroll(self, mock_status, mock_sign, mock_pem, mock_recode, mock_decode, mock_d2p, mock_b2s):
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
    def test_049_revoke(self, mock_serial, mock_issuer, mock_status, mock_encode, mock_put):
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
    def test_050_revoke(self, mock_serial, mock_issuer, mock_status, mock_encode, mock_put):
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
    def test_051_revoke(self, mock_serial, mock_issuer, mock_status, mock_encode, mock_put):
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
    def test_052_revoke(self, mock_serial, mock_issuer, mock_status, mock_encode, mock_put):
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
    def test_053_revoke(self, mock_serial, mock_issuer, mock_status, mock_encode, mock_put):
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
