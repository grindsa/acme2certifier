#!/usr/bin/python
# -*- coding: utf-8 -*-
""" unittests for acme2certifier """
# pylint: disable= C0415, W0212
import unittest
import sys
import os
from unittest.mock import patch, Mock
import requests
import configparser

sys.path.insert(0, '.')
sys.path.insert(1, '..')

class TestACMEHandler(unittest.TestCase):
    """ test class for cgi_handler """

    def setUp(self):
        """ setup unittest """
        import logging
        logging.basicConfig(level=logging.CRITICAL)
        self.logger = logging.getLogger('test_a2c')
        from examples.ca_handler.nclm_ca_handler import CAhandler
        self.cahandler = CAhandler(False, self.logger)
        # self.cahandler.api_host = 'api_host'
        # self.cahandler.auth = 'auth'

    def test_001_default(self):
        """ default test which always passes """
        self.assertEqual('foo', 'foo')

    @patch.object(requests, 'post')
    def test_002__api_post(self, mock_req):
        """ test _api_post successful run """
        mockresponse = Mock()
        mock_req.return_value = mockresponse
        mockresponse.json = lambda: {'foo': 'bar'}
        self.assertEqual({'foo': 'bar'}, self.cahandler._api_post('url', 'data'))

    @patch('requests.post')
    def test_003__api_post(self, mock_post):
        """ CAhandler.get_ca() returns an http error """
        self.cahandler.api_host = 'api_host'
        self.cahandler.auth = 'auth'
        mock_post.side_effect = Exception('exc_api_post')
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual('exc_api_post', self.cahandler._api_post('url', 'data'))
        self.assertIn('ERROR:test_a2c:CAhandler._api_post() returned error: exc_api_post', lcm.output)

    @patch.object(requests, 'post')
    def test_004__api_post(self, mock_req):
        """ test _api_post successful run """
        mockresponse = Mock()
        mock_req.return_value = mockresponse
        mockresponse.status_code = 'status_code'
        mockresponse.json = Exception('json_exc')
        self.assertEqual({'status': 'status_code'}, self.cahandler._api_post('url', 'data'))

    def test_005__config_check(self):
        """ CAhandler._config.check() no api_host """
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_check()
        self.assertEqual('api_host to be set in config file', self.cahandler.error)
        self.assertIn('ERROR:test_a2c:"api_host" to be set in config file', lcm.output)

    def test_006__config_check(self):
        """ CAhandler._config.check() no api_user """
        self.cahandler.api_host = 'api_host'
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_check()
        self.assertEqual('api_user to be set in config file', self.cahandler.error)
        self.assertIn('ERROR:test_a2c:"api_user" to be set in config file', lcm.output)

    def test_007__config_check(self):
        """ CAhandler._config.check() no api_user """
        self.cahandler.api_host = 'api_host'
        self.cahandler.credential_dic = {'api_user': False}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_check()
        self.assertEqual('api_user to be set in config file', self.cahandler.error)
        self.assertIn('ERROR:test_a2c:"api_user" to be set in config file', lcm.output)

    def test_008__config_check(self):
        """ CAhandler._config.check() no api_password """
        self.cahandler.api_host = 'api_host'
        self.cahandler.credential_dic = {'api_user': 'api_user'}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_check()
        self.assertEqual('api_password to be set in config file', self.cahandler.error)
        self.assertIn('ERROR:test_a2c:"api_password" to be set in config file', lcm.output)

    def test_009__config_check(self):
        """ CAhandler._config.check() no api_password """
        self.cahandler.api_host = 'api_host'
        self.cahandler.credential_dic = {'api_user': 'api_user', 'api_password': False}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_check()
        self.assertEqual('api_password to be set in config file', self.cahandler.error)
        self.assertIn('ERROR:test_a2c:"api_password" to be set in config file', lcm.output)

    def test_010__config_check(self):
        """ CAhandler._config.check() no tsg_name """
        self.cahandler.api_host = 'api_host'
        self.cahandler.credential_dic = {'api_user': 'api_user', 'api_password': 'api_password'}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_check()
        self.assertEqual('tsg_name to be set in config file', self.cahandler.error)
        self.assertIn('ERROR:test_a2c:"tsg_name" to be set in config file', lcm.output)

    def test_011__config_check(self):
        """ CAhandler._config.check() no tsg_name """
        self.cahandler.api_host = 'api_host'
        self.cahandler.credential_dic = {'api_user': 'api_user', 'api_password': 'api_password'}
        self.cahandler.container_info_dic = {'name': False}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_check()
        self.assertEqual('tsg_name to be set in config file', self.cahandler.error)
        self.assertIn('ERROR:test_a2c:"tsg_name" to be set in config file', lcm.output)

    def test_012__config_check(self):
        """ CAhandler._config.check() no ca_name """
        self.cahandler.api_host = 'api_host'
        self.cahandler.credential_dic = {'api_user': 'api_user', 'api_password': 'api_password'}
        self.cahandler.container_info_dic = {'name': 'name'}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_check()
        self.assertEqual('ca_name to be set in config file', self.cahandler.error)
        self.assertIn('ERROR:test_a2c:"ca_name" to be set in config file', lcm.output)

    def test_013__config_check(self):
        """ CAhandler._config.check() ca_bundle False """
        self.cahandler.api_host = 'api_host'
        self.cahandler.credential_dic = {'api_user': 'api_user', 'api_password': 'api_password'}
        self.cahandler.container_info_dic = {'name': 'name'}
        self.cahandler.ca_name = 'ca_name'
        self.cahandler.ca_id_list = ['id1', 'id2']
        self.cahandler.ca_bundle = False
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_check()
        self.assertFalse(self.cahandler.error)
        self.assertIn('WARNING:test_a2c:"ca_bundle" set to "False" - validation of server certificate disabled', lcm.output)

    @patch('examples.ca_handler.nclm_ca_handler.load_config')
    def test_014_config_load(self, mock_load_cfg):
        """ CAhandler._config_load no cahandler section """
        parser = configparser.ConfigParser()
        mock_load_cfg.return_value = parser
        self.cahandler._config_load()
        self.assertFalse(self.cahandler.api_host)
        self.assertEqual({'api_user': None, 'api_password': None}, self.cahandler.credential_dic)
        self.assertFalse(self.cahandler.ca_name)
        self.assertTrue(self.cahandler.ca_bundle)
        self.assertEqual({'name': None, 'id': None}, self.cahandler.template_info_dic)
        self.assertEqual(20, self.cahandler.request_timeout)

    @patch('examples.ca_handler.nclm_ca_handler.load_config')
    def test_015_config_load(self, mock_load_cfg):
        """ CAhandler._config_load api_host """
        parser = configparser.ConfigParser()
        parser['CAhandler'] = {'api_host': 'api_host', 'foo': 'bar'}
        mock_load_cfg.return_value = parser
        self.cahandler._config_load()
        self.assertEqual('api_host', self.cahandler.api_host)
        self.assertEqual({'api_user': None, 'api_password': None}, self.cahandler.credential_dic)
        self.assertFalse(self.cahandler.ca_name)
        self.assertTrue(self.cahandler.ca_bundle)
        self.assertEqual({'name': None, 'id': None}, self.cahandler.template_info_dic)
        self.assertEqual(20, self.cahandler.request_timeout)

    @patch('examples.ca_handler.nclm_ca_handler.load_config')
    def test_016_config_load(self, mock_load_cfg):
        """ CAhandler._config_load api_user """
        parser = configparser.ConfigParser()
        parser['CAhandler'] = {'api_user': 'api_user'}
        mock_load_cfg.return_value = parser
        self.cahandler._config_load()
        self.assertFalse(self.cahandler.api_host)
        self.assertEqual({'api_user': 'api_user', 'api_password': None}, self.cahandler.credential_dic)
        self.assertFalse(self.cahandler.ca_name)
        self.assertTrue(self.cahandler.ca_bundle)
        self.assertEqual({'name': None, 'id': None}, self.cahandler.template_info_dic)
        self.assertEqual(20, self.cahandler.request_timeout)

    @patch('examples.ca_handler.nclm_ca_handler.load_config')
    def test_017_config_load(self, mock_load_cfg):
        """ CAhandler._config_load api_password """
        parser = configparser.ConfigParser()
        parser['CAhandler'] = {'api_password': 'api_password'}
        mock_load_cfg.return_value = parser
        self.cahandler._config_load()
        self.assertFalse(self.cahandler.api_host)
        self.assertEqual({'api_user': None, 'api_password': 'api_password'}, self.cahandler.credential_dic)
        self.assertFalse(self.cahandler.ca_name)
        self.assertTrue(self.cahandler.ca_bundle)
        self.assertEqual({'name': None, 'id': None}, self.cahandler.template_info_dic)
        self.assertEqual(20, self.cahandler.request_timeout)

    @patch('examples.ca_handler.nclm_ca_handler.load_config')
    def test_018_config_load(self, mock_load_cfg):
        """ CAhandler._config_load ca_name """
        parser = configparser.ConfigParser()
        parser['CAhandler'] = {'ca_name': 'ca_name'}
        mock_load_cfg.return_value = parser
        self.cahandler._config_load()
        self.assertFalse(self.cahandler.api_host)
        self.assertEqual({'api_user': None, 'api_password': None}, self.cahandler.credential_dic)
        self.assertEqual('ca_name', self.cahandler.ca_name)
        self.assertTrue(self.cahandler.ca_bundle)
        self.assertEqual({'name': None, 'id': None}, self.cahandler.template_info_dic)
        self.assertEqual(20, self.cahandler.request_timeout)

    @patch('examples.ca_handler.nclm_ca_handler.load_config')
    def test_019_config_load(self, mock_load_cfg):
        """ CAhandler._config_load tsg_name """
        parser = configparser.ConfigParser()
        parser['CAhandler'] = {'tsg_name': 'tsg_name'}
        mock_load_cfg.return_value = parser
        with( self.assertLogs('test_a2c', level='INFO')) as lcm:
            self.cahandler._config_load()
        self.assertIn('WARNING:test_a2c:CAhandler._config_names_load() tsg_name is deprecated. Use container_name instead.', lcm.output)
        self.assertFalse(self.cahandler.api_host)
        self.assertEqual({'api_user': None, 'api_password': None}, self.cahandler.credential_dic)
        self.assertFalse(self.cahandler.ca_name)
        self.assertTrue(self.cahandler.ca_bundle)
        self.assertEqual({'name': None, 'id': None}, self.cahandler.template_info_dic)
        self.assertEqual(20, self.cahandler.request_timeout)

    @patch('examples.ca_handler.nclm_ca_handler.load_config')
    def test_020_config_load(self, mock_load_cfg):
        """ CAhandler._config_load ca_bundle string """
        parser = configparser.ConfigParser()
        parser['CAhandler'] = {'ca_bundle': 'ca_bundle'}
        mock_load_cfg.return_value = parser
        self.cahandler._config_load()
        self.assertFalse(self.cahandler.api_host)
        self.assertEqual({'api_user': None, 'api_password': None}, self.cahandler.credential_dic)
        self.assertFalse(self.cahandler.ca_name)
        self.assertEqual('ca_bundle', self.cahandler.ca_bundle)
        self.assertEqual({'name': None, 'id': None}, self.cahandler.template_info_dic)
        self.assertEqual(20, self.cahandler.request_timeout)

    @patch('examples.ca_handler.nclm_ca_handler.load_config')
    def test_021_config_load(self, mock_load_cfg):
        """ CAhandler._config_load ca_bundle False """
        parser = configparser.ConfigParser()
        parser['CAhandler'] = {'ca_bundle': False}
        mock_load_cfg.return_value = parser
        self.cahandler._config_load()
        self.assertFalse(self.cahandler.api_host)
        self.assertEqual({'api_user': None, 'api_password': None}, self.cahandler.credential_dic)
        self.assertFalse(self.cahandler.ca_name)
        self.assertFalse(self.cahandler.ca_bundle)
        self.assertEqual({'name': None, 'id': None}, self.cahandler.template_info_dic)
        self.assertEqual(20, self.cahandler.request_timeout)

    @patch('examples.ca_handler.nclm_ca_handler.load_config')
    def test_022_config_load(self, mock_load_cfg):
        """ CAhandler._config_load template_name """
        parser = configparser.ConfigParser()
        parser['CAhandler'] = {'template_name': 'template_name'}
        mock_load_cfg.return_value = parser
        self.cahandler._config_load()
        self.assertFalse(self.cahandler.api_host)
        self.assertEqual({'api_user': None, 'api_password': None}, self.cahandler.credential_dic)
        self.assertFalse(self.cahandler.ca_name)
        self.assertEqual({'name': 'template_name', 'id': None}, self.cahandler.template_info_dic)
        self.assertEqual(20, self.cahandler.request_timeout)

    @patch.dict('os.environ', {'api_user_var': 'user_var'})
    @patch('examples.ca_handler.nclm_ca_handler.load_config')
    def test_023_config_load(self, mock_load_cfg):
        """ CAhandler._config_load load username from variable """
        parser = configparser.ConfigParser()
        parser['CAhandler'] = {'api_user_variable': 'api_user_var'}
        mock_load_cfg.return_value = parser
        self.cahandler._config_load()
        self.assertFalse(self.cahandler.api_host)
        self.assertEqual({'api_user': 'user_var', 'api_password': None}, self.cahandler.credential_dic)

    @patch.dict('os.environ', {'api_user_var': 'user_var'})
    @patch('examples.ca_handler.nclm_ca_handler.load_config')
    def test_024_config_load(self, mock_load_cfg):
        """ CAhandler._config_load load username from non existing """
        parser = configparser.ConfigParser()
        parser['CAhandler'] = {'api_user_variable': 'does_not_exist'}
        mock_load_cfg.return_value = parser
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_load()
        self.assertFalse(self.cahandler.api_host)
        self.assertEqual({'api_user': None, 'api_password': None}, self.cahandler.credential_dic)
        self.assertIn("ERROR:test_a2c:CAhandler._config_load() could not load user_variable:'does_not_exist'", lcm.output)

    @patch.dict('os.environ', {'api_user_var': 'user_var'})
    @patch('examples.ca_handler.nclm_ca_handler.load_config')
    def test_025_config_load(self, mock_load_cfg):
        """ CAhandler._config_load load username from wich gets overwritten from cfg-file """
        parser = configparser.ConfigParser()
        parser['CAhandler'] = {'api_user_variable': 'api_user_var', 'api_user': 'api_user'}
        mock_load_cfg.return_value = parser
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_load()
        self.assertFalse(self.cahandler.api_host)
        self.assertEqual({'api_user': 'api_user', 'api_password': None}, self.cahandler.credential_dic)
        self.assertIn('INFO:test_a2c:CAhandler._config_load() overwrite api_user', lcm.output)

    @patch.dict('os.environ', {'api_password_var': 'password_var'})
    @patch('examples.ca_handler.nclm_ca_handler.load_config')
    def test_026_config_load(self, mock_load_cfg):
        """ CAhandler._config_load load password from variable """
        parser = configparser.ConfigParser()
        parser['CAhandler'] = {'api_password_variable': 'api_password_var'}
        mock_load_cfg.return_value = parser
        self.cahandler._config_load()
        self.assertFalse(self.cahandler.api_host)
        self.assertEqual({'api_user': None, 'api_password': 'password_var'}, self.cahandler.credential_dic)

    @patch.dict('os.environ', {'api_password_var': 'password_var'})
    @patch('examples.ca_handler.nclm_ca_handler.load_config')
    def test_027_config_load(self, mock_load_cfg):
        """ CAhandler._config_load load password from non existing variable """
        parser = configparser.ConfigParser()
        parser['CAhandler'] = {'api_password_variable': 'does_not_exist'}
        mock_load_cfg.return_value = parser
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_load()
        self.assertFalse(self.cahandler.api_host)
        self.assertEqual({'api_user': None, 'api_password': None}, self.cahandler.credential_dic)
        self.assertIn("ERROR:test_a2c:CAhandler._config_load() could not load password_variable:'does_not_exist'", lcm.output)

    @patch.dict('os.environ', {'api_password_var': 'password_var'})
    @patch('examples.ca_handler.nclm_ca_handler.load_config')
    def test_028_config_load(self, mock_load_cfg):
        """ CAhandler._config_load load password from variable which gets overwritten """
        parser = configparser.ConfigParser()
        parser['CAhandler'] = {'api_password_variable': 'api_password_var', 'api_password': 'api_password'}
        mock_load_cfg.return_value = parser
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_load()
        self.assertFalse(self.cahandler.api_host)
        self.assertEqual({'api_password': 'api_password', 'api_user': None}, self.cahandler.credential_dic)
        self.assertIn('INFO:test_a2c:CAhandler._config_load() overwrite api_password', lcm.output)

    @patch('examples.ca_handler.nclm_ca_handler.parse_url')
    @patch('json.loads')
    @patch('examples.ca_handler.nclm_ca_handler.load_config')
    def test_029_config_load(self, mock_load_cfg, mock_json, mock_url):
        """ test _config_load ca_handler configured load proxies """
        parser = configparser.ConfigParser()
        parser['DEFAULT'] = {'proxy_server_list': 'foo'}
        mock_load_cfg.return_value = parser
        mock_url.return_value = {'foo': 'bar'}
        mock_json.return_value = 'foo'
        self.cahandler._config_load()
        self.assertTrue(mock_json.called)
        self.assertTrue(mock_url.called)

    @patch('examples.ca_handler.nclm_ca_handler.proxy_check')
    @patch('examples.ca_handler.nclm_ca_handler.parse_url')
    @patch('json.loads')
    @patch('examples.ca_handler.nclm_ca_handler.load_config')
    def test_030_config_load(self, mock_load_cfg, mock_json, mock_url, mock_chk):
        """ test _config_load ca_handler configured load proxies """
        parser = configparser.ConfigParser()
        parser['DEFAULT'] = {'proxy_server_list': 'foo'}
        mock_load_cfg.return_value = parser
        mock_url.return_value = {'host': 'bar:8888'}
        mock_json.return_value = 'foo.bar.local'
        mock_chk.return_value = 'proxy.bar.local'
        self.cahandler._config_load()
        self.assertTrue(mock_json.called)
        self.assertTrue(mock_url.called)
        self.assertTrue(mock_chk.called)
        self.assertEqual({'http': 'proxy.bar.local', 'https': 'proxy.bar.local'},self.cahandler.proxy )

    @patch('examples.ca_handler.nclm_ca_handler.proxy_check')
    @patch('examples.ca_handler.nclm_ca_handler.parse_url')
    @patch('json.loads')
    @patch('examples.ca_handler.nclm_ca_handler.load_config')
    def test_031_config_load(self, mock_load_cfg, mock_json, mock_url, mock_chk):
        """ test _config_load ca_handler configured load proxies """
        parser = configparser.ConfigParser()
        parser['DEFAULT'] = {'proxy_server_list': 'foo'}
        mock_load_cfg.return_value = parser
        mock_url.return_value = {'host': 'bar'}
        mock_json.return_value = 'foo.bar.local'
        mock_chk.return_value = 'proxy.bar.local'
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_load()
        self.assertTrue(mock_json.called)
        self.assertTrue(mock_url.called)
        self.assertFalse(mock_chk.called)
        self.assertFalse(self.cahandler.proxy )
        self.assertIn('WARNING:test_a2c:Challenge._config_load() proxy_server_list failed with error: not enough values to unpack (expected 2, got 1)', lcm.output)

    @patch('examples.ca_handler.nclm_ca_handler.load_config')
    def test_032_config_load(self, mock_load_cfg):
        """ CAhandler._config_load request_delta_treshold """
        parser = configparser.ConfigParser()
        parser['CAhandler'] = {'request_timeout': 10}
        mock_load_cfg.return_value = parser
        self.cahandler._config_load()
        self.assertEqual(10, self.cahandler.request_timeout)

    @patch('examples.ca_handler.nclm_ca_handler.load_config')
    def test_033_config_load(self, mock_load_cfg):
        """ CAhandler._config_load request_delta_treshold """
        parser = configparser.ConfigParser()
        parser['CAhandler'] = {'request_timeout': 'aa'}
        mock_load_cfg.return_value = parser
        self.cahandler._config_load()
        self.assertEqual(20, self.cahandler.request_timeout)

    @patch('examples.ca_handler.nclm_ca_handler.load_config')
    def test_034_config_load(self, mock_load_cfg):
        """ CAhandler._config_load  """
        parser = configparser.ConfigParser()
        parser['CAhandler'] = {'container_name': 'container_name'}
        mock_load_cfg.return_value = parser
        self.cahandler._config_load()
        self.assertEqual({'name': 'container_name', 'id': None}, self.cahandler.container_info_dic)

    @patch('requests.post')
    @patch('requests.get')
    def test_035__login(self, mock_get, mock_post):
        """ CAhandler._unusedrequests_get """
        self.cahandler.api_host = 'api_host'
        mockresponse1 = Mock()
        mockresponse1.status_code = '500'
        mockresponse1.ok = None
        mock_get.return_value = mockresponse1
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._login()
        self.assertIn('ERROR:test_a2c:CAhandler._login() error during get: 500', lcm.output)
        self.assertFalse(mock_post.called)
        self.assertFalse(self.cahandler.headers)

    @patch('requests.post')
    @patch('requests.get')
    def test_036__login(self, mock_get, mock_post):
        """ CAhandler._unusedrequests_get """
        self.cahandler.api_host = 'api_host'
        mockresponse1 = Mock()
        mockresponse1.status_code = '200'
        mockresponse1.json = lambda: {'versionNumber': 'versionNumber'}
        mockresponse1.ok = True
        mock_get.return_value = mockresponse1
        mockresponse2 = Mock()
        mockresponse2.status_code = '500'
        mockresponse2.json = lambda: {'foo': 'bar', 'username': 'username', 'realms': 'realms'}
        mockresponse2.ok = None
        mock_post.return_value = mockresponse2
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._login()
        self.assertIn('ERROR:test_a2c:CAhandler._login() error during post: 500', lcm.output)
        self.assertTrue(mock_post.called)
        self.assertFalse(self.cahandler.headers)
        self.assertEqual('versionNumber', self.cahandler.nclm_version)

    @patch('requests.post')
    @patch('requests.get')
    def test_037__login(self, mock_get, mock_post):
        """ CAhandler._unusedrequests_get """
        self.cahandler.api_host = 'api_host'
        mockresponse1 = Mock()
        mockresponse1.status_code = '200'
        mockresponse1.json = lambda: {'versionNumber': 'versionNumber'}
        mockresponse1.ok = True
        mock_get.return_value = mockresponse1
        mockresponse2 = Mock()
        mockresponse2.status_code = '200'
        mockresponse2.json = lambda: {'foo': 'bar', 'username': 'username', 'realms': 'realms'}
        mockresponse2.ok = True
        mock_post.return_value = mockresponse2
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._login()
        self.assertIn('ERROR:test_a2c:CAhandler._login(): No token returned. Aborting.', lcm.output)
        self.assertTrue(mock_post.called)
        self.assertFalse(self.cahandler.headers)
        self.assertEqual('versionNumber', self.cahandler.nclm_version)

    @patch('requests.post')
    @patch('requests.get')
    def test_038__login(self, mock_get, mock_post):
        """ CAhandler._unusedrequests_get """
        self.cahandler.api_host = 'api_host'
        mockresponse1 = Mock()
        mockresponse1.status_code = '200'
        mockresponse1.json = lambda: {'versionNumber': 'versionNumber'}
        mockresponse1.ok = True
        mock_get.return_value = mockresponse1
        mockresponse2 = Mock()
        mockresponse2.status_code = '200'
        mockresponse2.json = lambda: {'access_token': 'access_token', 'username': 'username', 'realms': 'realms'}
        mockresponse2.ok = True
        mock_post.return_value = mockresponse2
        self.cahandler._login()
        self.assertTrue(mock_post.called)
        self.assertEqual({'Authorization': 'Bearer access_token'}, self.cahandler.headers)
        self.assertEqual('versionNumber', self.cahandler.nclm_version)


    def test_039_poll(self):
        """ CAhandler.poll() """
        self.assertEqual(('Method not implemented.', None, None, 'poll_identifier', False), self.cahandler.poll('cert_name', 'poll_identifier', 'csr'))

    def test_040_trigger(self):
        """ CAhandler.trigger() """
        self.assertEqual(('Method not implemented.', None, None), self.cahandler.trigger('payload'))

    @patch('requests.get')
    def test_041_container_id_lookup(self, mock_get):
        """ CAhandler._container_id_lookup() """
        self.cahandler.api_host = 'api_host'
        mockresponse = Mock()
        mockresponse.json = lambda: {'items': [{'name': 'name1', 'id': 'id1'}, {'name': 'name2', 'id': 'id2'}]}
        mock_get.return_value = mockresponse
        self.cahandler.container_info_dic = {'name': 'name1', 'id': None}
        self.cahandler._container_id_lookup()
        self.assertEqual({'name': 'name1', 'id': 'id1'}, self.cahandler.container_info_dic)

    @patch('requests.get')
    def test_042_container_id_lookup(self, mock_get):
        """ CAhandler._container_id_lookup() """
        self.cahandler.api_host = 'api_host'
        mockresponse = Mock()
        mockresponse.json = lambda: {'items': [{'name1': 'name1', 'id': 'id1'}, {'name': 'name2', 'id': 'id2'}]}
        mock_get.return_value = mockresponse
        self.cahandler.container_info_dic = {'name': 'name', 'id': None}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._container_id_lookup()
        self.assertIn("ERROR:test_a2c:CAhandler._container_id_lookup() incomplete response: {'name1': 'name1', 'id': 'id1'}", lcm.output)
        self.assertEqual({'name': 'name', 'id': None}, self.cahandler.container_info_dic)

    @patch('requests.get')
    def test_043_container_id_lookup(self, mock_get):
        """ CAhandler._container_id_lookup() """
        self.cahandler.api_host = 'api_host'
        mockresponse = Mock()
        mockresponse.json = lambda: {'foo': [{'name': 'name1', 'id': 'id1'}, {'name': 'name2', 'id': 'id2'}]}
        mock_get.return_value = mockresponse
        self.cahandler.container_info_dic = {'name': 'name', 'id': None}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._container_id_lookup()
        self.assertIn('ERROR:test_a2c:CAhandler._container_id_lookup() no target-system-groups found for filter: name.', lcm.output)
        self.assertEqual({'name': 'name', 'id': None}, self.cahandler.container_info_dic)

    @patch('requests.get')
    def test_044_container_id_lookup(self, mock_req):
        """ CAhandler._container_id_lookup() """
        self.cahandler.api_host = 'api_host'
        mock_req.side_effect = Exception('exc_container_id_lookup')
        self.cahandler.container_info_dic = {'name': 'name', 'id': None}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._container_id_lookup()
        self.assertIn('ERROR:test_a2c:CAhandler._container_id_lookup() returned error: exc_container_id_lookup', lcm.output)
        self.assertIn('ERROR:test_a2c:CAhandler._container_id_lookup() no target-system-groups found for filter: name.', lcm.output)
        self.assertEqual({'name': 'name', 'id': None}, self.cahandler.container_info_dic)


    @patch('examples.ca_handler.nclm_ca_handler.CAhandler._templates_enumerate')
    @patch('examples.ca_handler.nclm_ca_handler.CAhandler._template_list_get')
    def test_045__template_id_lookup(self, mock_list, mock_enum):
        """ CAhandler._template_id_lookup """
        mock_list.return_value = {'foo': 'bar'}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._template_id_lookup('caid')
        self.assertIn('ERROR:test_a2c:CAhandler._template_id_lookup() no templates found for filter: None.', lcm.output)
        self.assertFalse(mock_enum.called)

    @patch('examples.ca_handler.nclm_ca_handler.CAhandler._templates_enumerate')
    @patch('examples.ca_handler.nclm_ca_handler.CAhandler._template_list_get')
    def test_046__template_id_lookup(self, mock_list, mock_enum):
        """ CAhandler._template_id_lookup """
        mock_list.return_value = {'items': ['foo', 'bar']}
        self.cahandler._template_id_lookup('caid')
        self.assertTrue(mock_enum.called)

    @patch('requests.get')
    def test_047__template_list_get(self, mock_get):
        """ CAhandler._template_id_lookup() """
        self.cahandler.api_host = 'api_host'
        mockresponse = Mock()
        mockresponse.json = lambda: {'foo': 'bar'}
        mock_get.return_value = mockresponse
        self.assertEqual({'foo': 'bar'}, self.cahandler._template_list_get(6))

    @patch('requests.get')
    def test_048__template_list_get(self, mock_get):
        """ CAhandler._template_id_lookup() """
        self.cahandler.api_host = 'api_host'
        mock_get.side_effect = Exception('req_exc')
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertFalse(self.cahandler._template_list_get(6))
        self.assertIn('ERROR:test_a2c:CAhandler._template_list_get() returned error: req_exc', lcm.output)

    @patch('requests.get')
    def test_049__template_list_get(self, mock_get):
        """ CAhandler._template_id_lookup() """
        self.cahandler.api_host = 'api_host'
        mockresponse = Mock()
        mockresponse.json = lambda: {'items': 'bar'}
        mock_get.return_value = mockresponse
        self.assertEqual({'items': 'bar'}, self.cahandler._template_list_get(6))

    def test_050__templates_enumerate(self):
        """ CAhandler._templates_enumerate() """
        template_list = {'items': [{'name': 'foo', 'id': 'id'}, {'name': 'foo1', 'id': 'id1'}]}
        self.cahandler.template_info_dic = {'name': 'foo'}
        self.cahandler._templates_enumerate(template_list)
        self.assertEqual({'id': 'id', 'name': 'foo'}, self.cahandler.template_info_dic)

    def test_051__templates_enumerate(self):
        """ CAhandler._templates_enumerate() """
        template_list = {'items': [{'name': 'foo', 'id': 'id'}, {'name': 'foo1', 'id': 'id1'}]}
        self.cahandler.template_info_dic = {'name': 'foo1'}
        self.cahandler._templates_enumerate(template_list)
        self.assertEqual({'id': 'id1', 'name': 'foo1'}, self.cahandler.template_info_dic)

    def test_052__templates_enumerate(self):
        """ CAhandler._templates_enumerate() """
        template_list = {'items': [{'name': 'foo', 'id': 'id'}, {'name': 'foo1', 'id': 'id1'}, {'name': 'foo', 'id': 'id2'}]}
        self.cahandler.template_info_dic = {'name': 'foo'}
        self.cahandler._templates_enumerate(template_list)
        self.assertEqual({'id': 'id', 'name': 'foo'}, self.cahandler.template_info_dic)

    @patch('examples.ca_handler.nclm_ca_handler.CAhandler._config_load')
    @patch('examples.ca_handler.nclm_ca_handler.CAhandler._config_check')
    @patch('examples.ca_handler.nclm_ca_handler.CAhandler._login')
    @patch('examples.ca_handler.nclm_ca_handler.CAhandler._container_id_lookup')
    def test_053__enter__(self, mock_lookup, mock_login, mock_check, mock_load):
        """ test enter """
        self.cahandler.__enter__()
        self.assertTrue(mock_load.called)
        self.assertTrue(mock_check.called)
        self.assertTrue(mock_login.called)
        self.assertTrue(mock_lookup.called)

    @patch('examples.ca_handler.nclm_ca_handler.CAhandler._config_load')
    @patch('examples.ca_handler.nclm_ca_handler.CAhandler._config_check')
    @patch('examples.ca_handler.nclm_ca_handler.CAhandler._login')
    @patch('examples.ca_handler.nclm_ca_handler.CAhandler._container_id_lookup')
    def test_054__enter__(self, mock_lookup, mock_login, mock_check, mock_load):
        """ test enter  with host already defined """
        self.cahandler.api_host = 'api_host'
        self.cahandler.__enter__()
        self.assertFalse(mock_load.called)
        self.assertFalse(mock_check.called)
        self.assertTrue(mock_login.called)
        self.assertTrue(mock_lookup.called)

    @patch('examples.ca_handler.nclm_ca_handler.CAhandler._config_load')
    @patch('examples.ca_handler.nclm_ca_handler.CAhandler._config_check')
    @patch('examples.ca_handler.nclm_ca_handler.CAhandler._login')
    @patch('examples.ca_handler.nclm_ca_handler.CAhandler._container_id_lookup')
    def test_055__enter__(self, mock_lookup, mock_login, mock_check, mock_load):
        """ test enter with header defined """
        self.cahandler.headers = 'header'
        self.cahandler.__enter__()
        self.assertTrue(mock_load.called)
        self.assertTrue(mock_check.called)
        self.assertFalse(mock_login.called)
        self.assertTrue(mock_lookup.called)

    @patch('examples.ca_handler.nclm_ca_handler.CAhandler._config_load')
    @patch('examples.ca_handler.nclm_ca_handler.CAhandler._config_check')
    @patch('examples.ca_handler.nclm_ca_handler.CAhandler._login')
    @patch('examples.ca_handler.nclm_ca_handler.CAhandler._container_id_lookup')
    def test_056__enter__(self, mock_lookup, mock_login, mock_check, mock_load):
        """ test enter with error defined """
        self.cahandler.error = 'error'
        self.cahandler.__enter__()
        self.assertTrue(mock_load.called)
        self.assertTrue(mock_check.called)
        self.assertFalse(mock_login.called)
        self.assertFalse(mock_lookup.called)

    @patch('examples.ca_handler.nclm_ca_handler.CAhandler._config_load')
    @patch('examples.ca_handler.nclm_ca_handler.CAhandler._config_check')
    @patch('examples.ca_handler.nclm_ca_handler.CAhandler._login')
    @patch('examples.ca_handler.nclm_ca_handler.CAhandler._container_id_lookup')
    def test_057__enter__(self, mock_lookup, mock_login, mock_check, mock_load):
        """ test enter with tst_info_dic defined """
        self.cahandler.container_info_dic = {'id': 'foo'}
        self.cahandler.__enter__()
        self.assertTrue(mock_load.called)
        self.assertTrue(mock_check.called)
        self.assertTrue(mock_login.called)
        self.assertFalse(mock_lookup.called)

    @patch('examples.ca_handler.nclm_ca_handler.CAhandler._config_load')
    @patch('examples.ca_handler.nclm_ca_handler.CAhandler._config_check')
    @patch('examples.ca_handler.nclm_ca_handler.CAhandler._login')
    @patch('examples.ca_handler.nclm_ca_handler.CAhandler._container_id_lookup')
    def test_058__enter__(self, mock_lookup, mock_login, mock_check, mock_load):
        """ test enter with error defined """
        self.cahandler.container_info_dic = {'id': 'foo'}
        self.cahandler.error = 'error'
        self.cahandler.__enter__()
        self.assertTrue(mock_load.called)
        self.assertTrue(mock_check.called)
        self.assertFalse(mock_login.called)
        self.assertFalse(mock_lookup.called)

    def test_059__ca_id_get(self):
        """ test _ca_id_get() """
        ca_list = {}
        self.assertFalse(self.cahandler._ca_id_get(ca_list))

    def test_060__ca_id_get(self):
        """ test _ca_id_get() """
        ca_list = {'ca': {'foo': 'bar'}}
        self.assertFalse(self.cahandler._ca_id_get(ca_list))

    def test_061__ca_id_get(self):
        """ test _ca_id_get() """
        ca_list = {'items': 'bar'}
        self.assertFalse(self.cahandler._ca_id_get(ca_list))

    def test_062__ca_id_get(self):
        """ test _ca_id_get() """
        ca_list = {'items': [{'foo': 'bar'}]}
        self.assertFalse(self.cahandler._ca_id_get(ca_list))

    def test_063__ca_id_get(self):
        """ test _ca_id_get() """
        self.cahandler.ca_name = 'ca_name'
        ca_list = {'items': [{'name': 'ca_name', 'id': 'id'}]}
        self.assertEqual('id', self.cahandler._ca_id_get(ca_list))

    def test_064__ca_id_get(self):
        """ test _ca_id_get() """
        self.cahandler.ca_name = 'ca_name'
        ca_list = {'items': [{'name': 'ca_name', 'id1': 'id'}]}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertFalse(self.cahandler._ca_id_get(ca_list))
        self.assertIn('ERROR:test_a2c:ca_id.lookup() policyLinkId field is missing  ...', lcm.output)

    def test_065__ca_id_get(self):
        """ test _ca_id_get() """
        self.cahandler.ca_name = 'ca_name1'
        ca_list = {'items': [{'name': 'ca_name', 'id': 'id'}]}
        self.assertFalse(self.cahandler._ca_id_get(ca_list))

    @patch('examples.ca_handler.nclm_ca_handler.CAhandler._ca_id_get')
    @patch('requests.get')
    def test_066__ca_policylink_id_lookup(self, mock_req, mock_caid):
        """ test _ca_policylink_id_lookup() """
        self.cahandler.api_host = 'api_host'
        self.cahandler.container_info_dic = {'id': 'id'}
        mockresponse = Mock()
        mockresponse.json = lambda: {'items': ['foo', 'bar', 'foo', 'bar']}
        mock_req.return_value = mockresponse
        mock_caid.return_value = 10
        self.assertEqual(10, self.cahandler._ca_policylink_id_lookup())
        self.assertTrue(mock_caid.called)

    @patch('examples.ca_handler.nclm_ca_handler.CAhandler._ca_id_get')
    @patch('requests.get')
    def test_067__ca_policylink_id_lookup(self, mock_req, mock_caid):
        """ test _ca_policylink_id_lookup() """
        self.cahandler.api_host = 'api_host'
        self.cahandler.container_info_dic = {'id': 'id'}
        mockresponse = Mock()
        mockresponse.json = lambda: {'items': ['foo', 'bar', 'foo', 'bar']}
        mock_req.return_value = mockresponse
        mock_caid.return_value = None
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertFalse(self.cahandler._ca_policylink_id_lookup())
        self.assertIn('ERROR:test_a2c:CAhandler_ca_policylink_id_lookup(): no policylink id found for None', lcm.output)
        self.assertTrue(mock_caid.called)

    @patch('examples.ca_handler.nclm_ca_handler.CAhandler._ca_id_get')
    @patch('requests.get')
    def test_068__ca_policylink_id_lookup(self, mock_req, mock_caid):
        """ test _ca_policylink_id_lookup() """
        self.cahandler.api_host = 'api_host'
        self.cahandler.container_info_dic = {'id': 'id'}
        mockresponse = Mock()
        mockresponse.json = lambda: {'foo': ['foo', 'bar', 'foo', 'bar']}
        mock_req.return_value = mockresponse
        mock_caid.return_value = None
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertFalse(self.cahandler._ca_policylink_id_lookup())
        self.assertIn('ERROR:test_a2c:CAhandler_ca_policylink_id_lookup(): no policylink id found for None', lcm.output)
        self.assertIn('ERROR:test_a2c:ca_id.lookup() no CAs found in response ...', lcm.output)
        self.assertFalse(mock_caid.called)

    @patch('examples.ca_handler.nclm_ca_handler.CAhandler._cert_bundle_build')
    @patch('examples.ca_handler.nclm_ca_handler.CAhandler._cert_id_get')
    @patch('examples.ca_handler.nclm_ca_handler.CAhandler._csr_post')
    def test_069__cert_enroll(self, mock_post, mock_idget, mock_build):
        """ test _cert_enroll() """
        mock_post.return_value = 'mock_post'
        mock_idget.return_value = 'mock_idget'
        mock_build.return_value = ('error', 'bundle', 'raw')
        self.assertEqual(('error', 'bundle', 'raw', 'mock_idget'), self.cahandler._cert_enroll('cr', 'policylink_id'))
        self.assertTrue(mock_post.called)
        self.assertTrue(mock_idget.called)
        self.assertTrue(mock_build.called)

    @patch('examples.ca_handler.nclm_ca_handler.CAhandler._cert_bundle_build')
    @patch('examples.ca_handler.nclm_ca_handler.CAhandler._cert_id_get')
    @patch('examples.ca_handler.nclm_ca_handler.CAhandler._csr_post')
    def test_070__cert_enroll(self, mock_post, mock_idget, mock_build):
        """ test _cert_enroll() """
        mock_post.return_value = 'mock_post'
        mock_idget.return_value = None
        mock_build.return_value = ('error', 'bundle', 'raw')
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual(('Certifcate_id lookup failed', None, None, None), self.cahandler._cert_enroll('cr', 'policylink_id'))
        self.assertIn('ERROR:test_a2c:CAhandler.eroll(): certifcate_id lookup failed for job: mock_post', lcm.output)
        self.assertTrue(mock_post.called)
        self.assertTrue(mock_idget.called)
        self.assertFalse(mock_build.called)

    @patch('examples.ca_handler.nclm_ca_handler.CAhandler._cert_bundle_build')
    @patch('examples.ca_handler.nclm_ca_handler.CAhandler._cert_id_get')
    @patch('examples.ca_handler.nclm_ca_handler.CAhandler._csr_post')
    def test_071__cert_enroll(self, mock_post, mock_idget, mock_build):
        """ test _cert_enroll() """
        mock_post.return_value = None
        mock_idget.return_value = 'mock_idget'
        mock_build.return_value = ('error', 'bundle', 'raw')
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual(('job_id lookup failed', None, None, None), self.cahandler._cert_enroll('cr', 'policylink_id'))
        self.assertIn('ERROR:test_a2c:CAhandler.eroll(): job_id lookup failed for job', lcm.output)
        self.assertTrue(mock_post.called)
        self.assertFalse(mock_idget.called)
        self.assertFalse(mock_build.called)

    @patch('examples.ca_handler.nclm_ca_handler.CAhandler._api_post')
    @patch('examples.ca_handler.nclm_ca_handler.convert_string_to_byte')
    @patch('examples.ca_handler.nclm_ca_handler.b64_encode')
    @patch('examples.ca_handler.nclm_ca_handler.build_pem_file')
    def test_072__csr_post(self, mock_pem, mock_enc, mock_convert, mock_post):
        """ test _csr_post() """
        mock_pem.return_value = 'mock_pem'
        mock_enc.return_value = 'mock_enc'
        mock_convert.return_value = 'mock_convert'
        mock_post.return_value = {'id': 'id', 'foo': 'bar'}
        self.assertEqual('id', self.cahandler._csr_post('csr', 'policylink_id'))
        self.assertTrue(mock_convert.called)
        self.assertTrue(mock_enc.called)
        self.assertTrue(mock_pem.called)

    @patch('examples.ca_handler.nclm_ca_handler.CAhandler._api_post')
    @patch('examples.ca_handler.nclm_ca_handler.convert_string_to_byte')
    @patch('examples.ca_handler.nclm_ca_handler.b64_encode')
    @patch('examples.ca_handler.nclm_ca_handler.build_pem_file')
    def test_073__csr_post(self, mock_pem, mock_enc, mock_convert, mock_post):
        """ test _csr_post() """
        mock_pem.return_value = 'mock_pem'
        mock_enc.return_value = 'mock_enc'
        mock_convert.return_value = 'mock_convert'
        mock_post.return_value = {'foo': 'bar'}
        self.cahandler.template_info_dic = {'id': 'id'}
        self.assertFalse(self.cahandler._csr_post('csr', 'policylink_id'))
        self.assertTrue(mock_convert.called)
        self.assertTrue(mock_enc.called)
        self.assertTrue(mock_pem.called)

    @patch('requests.get')
    def test_074__issuer_certid_get(self, mock_req):
        """ test _issuer_certid_get() """
        cert_dic = {'urls': {'issuer': 'issuer'}}
        self.cahandler.api_host = 'api_host'
        mockresponse = Mock()
        mockresponse.json = lambda: {'urls': {'certificate': 'foo/v2/certificates/'}}
        mock_req.return_value = mockresponse
        self.assertEqual(('foo', True), self.cahandler._issuer_certid_get(cert_dic))

    @patch('requests.get')
    def test_075__issuer_certid_get(self, mock_req):
        """ test _issuer_certid_get() """
        cert_dic = {'urls': {'issuer': 'issuer'}}
        self.cahandler.api_host = 'api_host'
        mockresponse = Mock()
        mockresponse.json = lambda: {'urls': {'bar': 'foo/v2/certificates/'}}
        mock_req.return_value = mockresponse
        self.assertEqual((None, False), self.cahandler._issuer_certid_get(cert_dic))

    @patch('examples.ca_handler.nclm_ca_handler.CAhandler._issuer_certid_get')
    @patch('examples.ca_handler.nclm_ca_handler.build_pem_file')
    @patch('requests.get')
    def test_076__cert_bundle_build(self, mock_req, mock_pem, mock_certid):
        """ test _cert_bundle_build() """
        mock_pem.return_value = 'mock_pem'
        mock_certid.return_value = ('id', False)
        mockresponse = Mock()
        mockresponse.json = lambda: {'der': 'der'}
        mock_req.return_value = mockresponse
        self.assertEqual((None, 'mock_pem', 'der'), self.cahandler._cert_bundle_build('cert_id'))

    @patch('examples.ca_handler.nclm_ca_handler.CAhandler._issuer_certid_get')
    @patch('examples.ca_handler.nclm_ca_handler.build_pem_file')
    @patch('requests.get')
    def test_077__cert_bundle_build(self, mock_req, mock_pem, mock_certid):
        """ test _cert_bundle_build() """
        mock_pem.side_effect = ['mock_pem1', 'mock_pem2']
        mock_certid.side_effect = [('id1', True), ('id2', False)]
        mockresponse = Mock()
        mockresponse.json = lambda: {'der': 'der'}
        mock_req.return_value = mockresponse
        self.assertEqual((None, 'mock_pem2', 'der'), self.cahandler._cert_bundle_build('cert_id'))

    @patch('examples.ca_handler.nclm_ca_handler.CAhandler._issuer_certid_get')
    @patch('examples.ca_handler.nclm_ca_handler.build_pem_file')
    @patch('requests.get')
    def test_078__cert_bundle_build(self, mock_req, mock_pem, mock_certid):
        """ test _cert_bundle_build() """
        mock_pem.return_value = ''
        mock_certid.return_value = ('id', False)
        mockresponse = Mock()
        mockresponse.json = lambda: {'der': 'der'}
        mock_req.return_value = mockresponse
        self.assertEqual((None, None, 'der'), self.cahandler._cert_bundle_build('cert_id'))

    @patch('time.sleep')
    @patch('requests.get')
    def test_079__cert_id_get(self, mock_req, mock_sleep):
        """ test _cert_id_get() """
        mockresponse = Mock()
        mockresponse.json = lambda: {'status': 'done', 'entities': [{'ref': 'certificate', 'url': 'foo/v2/certificates/'}]}
        mock_req.return_value = mockresponse
        self.assertEqual('foo', self.cahandler._cert_id_get(10))

    @patch('time.sleep')
    @patch('requests.get')
    def test_080__cert_id_get(self, mock_req, mock_sleep):
        """ test _cert_id_get() """
        mockresponse1 = Mock()
        mockresponse1.json = lambda: {'status': 'note', 'entities': [{'ref': 'certificate', 'url': 'foo1/v2/certificates/'}]}
        mockresponse2 = Mock()
        mockresponse2.json = lambda: {'status': 'done', 'entities': [{'ref': 'certificate', 'url': 'foo2/v2/certificates/'}]}
        mock_req.side_effect = [mockresponse1, mockresponse2]
        self.assertEqual('foo2', self.cahandler._cert_id_get(10))

    @patch('requests.get')
    @patch('examples.ca_handler.nclm_ca_handler.cert_serial_get')
    def test_081__certid_get_from_serial(self, mock_serial, mock_req):
        """ _certid_get_from_serial() """
        mock_serial.return_value = 'mock_serial'
        mockresponse = Mock()
        mockresponse.json = lambda: {'items': [{'id': 'id1'}, {'id': 'id2'}]}
        mock_req.return_value = mockresponse
        self.assertEqual('id1', self.cahandler._certid_get_from_serial('cert_raw'))

    @patch('requests.get')
    @patch('examples.ca_handler.nclm_ca_handler.cert_serial_get')
    def test_082__certid_get_from_serial(self, mock_serial, mock_req):
        """ _certid_get_from_serial() """
        mock_serial.return_value = 'mock_serial'
        mockresponse = Mock()
        mockresponse.json = lambda: {'items': [{'di': 'id1'}, {'id': 'id2'}]}
        mock_req.return_value = mockresponse
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual(None, self.cahandler._certid_get_from_serial('cert_raw'))
        self.assertIn('ERROR:test_a2c:CAhandler._certid_get_from_serial(): no certificate found for serial: mock_serial', lcm.output)

    @patch('requests.get')
    @patch('examples.ca_handler.nclm_ca_handler.cert_serial_get')
    def test_083__certid_get_from_serial(self, mock_serial, mock_req):
        """ _certid_get_from_serial() """
        mock_serial.return_value = 'mock_serial'
        mock_req.side_effect = Exception('mock_req')
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual(None, self.cahandler._certid_get_from_serial('cert_raw'))
        self.assertIn('ERROR:test_a2c:CAhandler._certid_get_from_serial(): request get aborted with err: mock_req', lcm.output)
        self.assertIn('ERROR:test_a2c:CAhandler._certid_get_from_serial(): no certificate found for serial: mock_serial', lcm.output)

    @patch('examples.ca_handler.nclm_ca_handler.CAhandler._certid_get_from_serial')
    @patch('examples.ca_handler.nclm_ca_handler.header_info_get')
    @patch('examples.ca_handler.nclm_ca_handler.b64_url_recode')
    def test_084__cert_id_lookup(self, mock_enc, mock_info, mock_serial):
        """ test _cert_id_lookup() """
        mock_enc.return_value = 'mock_enc'
        mock_info.return_value = [{'poll_identifier': 'poll_identifier'}]
        mock_serial.return_value = 'mock_serial'
        self.assertEqual('poll_identifier', self.cahandler._cert_id_lookup('cert_raw'))
        self.assertFalse(mock_serial.called)

    @patch('examples.ca_handler.nclm_ca_handler.CAhandler._certid_get_from_serial')
    @patch('examples.ca_handler.nclm_ca_handler.header_info_get')
    @patch('examples.ca_handler.nclm_ca_handler.b64_url_recode')
    def test_085__cert_id_lookup(self, mock_enc, mock_info, mock_serial):
        """ test _cert_id_lookup() """
        mock_enc.return_value = 'mock_enc'
        mock_info.return_value = [{'poll_identifier': None}]
        mock_serial.return_value = 'mock_serial'
        self.assertEqual('mock_serial', self.cahandler._cert_id_lookup('cert_raw'))
        self.assertTrue(mock_serial.called)

    @patch('examples.ca_handler.nclm_ca_handler.CAhandler._certid_get_from_serial')
    @patch('examples.ca_handler.nclm_ca_handler.header_info_get')
    @patch('examples.ca_handler.nclm_ca_handler.b64_url_recode')
    def test_086__cert_id_lookup(self, mock_enc, mock_info, mock_serial):
        """ test _cert_id_lookup() """
        mock_enc.return_value = 'mock_enc'
        mock_info.return_value = [{'foo': 'bar'}]
        mock_serial.return_value = 'mock_serial'
        self.assertEqual('mock_serial', self.cahandler._cert_id_lookup('cert_raw'))
        self.assertTrue(mock_serial.called)

    @patch('time.sleep')
    @patch('requests.get')
    def test_087__revocation_status_poll(self, mock_req, mock_sleep):
        """ test _revocation_status_poll() """
        mockresponse = Mock()
        mockresponse.json = lambda: {'status': 'done'}
        mock_req.return_value = mockresponse
        err_dic = {'serverinternal': 'serverinternal'}
        self.assertEqual((200, None, None), self.cahandler._revocation_status_poll('cert_id', err_dic))

    @patch('time.sleep')
    @patch('requests.get')
    def test_088__revocation_status_poll(self, mock_req, mock_sleep):
        """ test _revocation_status_poll() """
        mockresponse = Mock()
        mockresponse.json = lambda: {'status': 'failed'}
        mock_req.return_value = mockresponse
        err_dic = {'serverinternal': 'serverinternal'}
        self.assertEqual((500, 'serverinternal', 'Revocation operation failed: error from API'), self.cahandler._revocation_status_poll('cert_id', err_dic))

    @patch('time.sleep')
    @patch('requests.get')
    def test_089__revocation_status_poll(self, mock_req, mock_sleep):
        """ test _revocation_status_poll() """
        mockresponse1 = Mock()
        mockresponse1.json = lambda: {'status': 'pending'}
        mockresponse2 = Mock()
        mockresponse2.json = lambda: {'status': 'done'}
        mock_req.side_effect = [mockresponse2, mockresponse2]
        err_dic = {'serverinternal': 'serverinternal'}
        self.assertEqual((200, None, None), self.cahandler._revocation_status_poll('cert_id', err_dic))

    @patch('time.sleep')
    @patch('requests.get')
    def test_090__revocation_status_poll(self, mock_req, mock_sleep):
        """ test _revocation_status_poll() """
        mockresponse1 = Mock()
        mockresponse1.json = lambda: {'status': 'pending'}
        mockresponse2 = Mock()
        mockresponse2.json = lambda: {'status': 'failed'}
        mock_req.side_effect = [mockresponse2, mockresponse2]
        err_dic = {'serverinternal': 'serverinternal'}
        self.assertEqual((500, 'serverinternal', 'Revocation operation failed: error from API'), self.cahandler._revocation_status_poll('cert_id', err_dic))

    @patch('time.sleep')
    @patch('requests.get')
    def test_091__revocation_status_poll(self, mock_req, mock_sleep):
        """ test _revocation_status_poll() """
        mockresponse = Mock()
        mockresponse.json = lambda: {'status': 'pending'}
        mock_req.return_value = mockresponse
        err_dic = {'serverinternal': 'serverinternal'}
        self.assertEqual((500, 'serverinternal', 'Revocation operation failed: Timeout'), self.cahandler._revocation_status_poll('cert_id', err_dic))

    @patch('examples.ca_handler.nclm_ca_handler.enrollment_config_log')
    @patch('examples.ca_handler.nclm_ca_handler.CAhandler._cert_enroll')
    @patch('examples.ca_handler.nclm_ca_handler.CAhandler._template_id_lookup')
    @patch('examples.ca_handler.nclm_ca_handler.CAhandler._ca_policylink_id_lookup')
    @patch('examples.ca_handler.nclm_ca_handler.b64_url_recode')
    def test_092_enroll(self, mock_recode, mock_policy, mock_template, mock_enroll, mock_ecl):
        """ test enroll """
        mock_recode.return_value = 'csr'
        mock_policy.return_value = 'policylink_id'
        mock_template.return_value = 'template_id'
        mock_enroll.return_value = ('error', 'bundle', 'raw', 'cert_id')
        self.cahandler.template_info_dic = {'name': 'name', 'id': None}
        self.cahandler.container_info_dic = {'name': 'name', 'id': 'id'}
        self.assertEqual(('error', 'bundle', 'raw', 'cert_id'), self.cahandler.enroll('csr'))
        self.assertTrue(mock_recode.called)
        self.assertTrue(mock_policy.called)
        self.assertTrue(mock_template.called)
        self.assertTrue(mock_enroll.called)
        self.assertFalse(mock_ecl.called)

    @patch('examples.ca_handler.nclm_ca_handler.enrollment_config_log')
    @patch('examples.ca_handler.nclm_ca_handler.CAhandler._cert_enroll')
    @patch('examples.ca_handler.nclm_ca_handler.CAhandler._template_id_lookup')
    @patch('examples.ca_handler.nclm_ca_handler.CAhandler._ca_policylink_id_lookup')
    @patch('examples.ca_handler.nclm_ca_handler.b64_url_recode')
    def test_093_enroll(self, mock_recode, mock_policy, mock_template, mock_enroll, mock_ecl):
        """ test enroll """
        mock_recode.return_value = 'csr'
        mock_policy.return_value = 'policylink_id'
        mock_template.return_value = 'template_id'
        mock_enroll.return_value = ('error', 'bundle', 'raw', 'cert_id')
        self.cahandler.enrollment_config_log = True
        self.cahandler.template_info_dic = {'name': 'name', 'id': None}
        self.cahandler.container_info_dic = {'name': 'name', 'id': 'id'}
        self.assertEqual(('error', 'bundle', 'raw', 'cert_id'), self.cahandler.enroll('csr'))
        self.assertTrue(mock_recode.called)
        self.assertTrue(mock_policy.called)
        self.assertTrue(mock_template.called)
        self.assertTrue(mock_enroll.called)
        self.assertTrue(mock_ecl.called)

    @patch('examples.ca_handler.nclm_ca_handler.CAhandler._cert_enroll')
    @patch('examples.ca_handler.nclm_ca_handler.CAhandler._template_id_lookup')
    @patch('examples.ca_handler.nclm_ca_handler.CAhandler._ca_policylink_id_lookup')
    @patch('examples.ca_handler.nclm_ca_handler.b64_url_recode')
    def test_094_enroll(self, mock_recode, mock_policy, mock_template, mock_enroll):
        """ test enroll """
        mock_recode.return_value = 'csr'
        mock_policy.return_value = 'policylink_id'
        mock_template.return_value = 'template_id'
        mock_enroll.return_value = ('error', 'bundle', 'raw', 'cert_id')
        self.cahandler.template_info_dic = {'name': 'name', 'id': None}
        self.cahandler.container_info_dic = {'name': 'name', 'id': None}
        self.assertEqual(('CAhandler.eroll(): ID lookup for container"name" failed.', None, None, None), self.cahandler.enroll('csr'))
        self.assertTrue(mock_recode.called)
        self.assertFalse(mock_policy.called)
        self.assertFalse(mock_template.called)
        self.assertFalse(mock_enroll.called)

    @patch('examples.ca_handler.nclm_ca_handler.CAhandler._cert_enroll')
    @patch('examples.ca_handler.nclm_ca_handler.CAhandler._template_id_lookup')
    @patch('examples.ca_handler.nclm_ca_handler.CAhandler._ca_policylink_id_lookup')
    @patch('examples.ca_handler.nclm_ca_handler.b64_url_recode')
    def test_095_enroll(self, mock_recode, mock_policy, mock_template, mock_enroll):
        """ test enroll """
        mock_recode.return_value = 'csr'
        mock_policy.return_value = None
        mock_template.return_value = 'template_id'
        mock_enroll.return_value = ('error', 'bundle', 'raw', 'cert_id')
        self.cahandler.template_info_dic = {'name': 'name', 'id': None}
        self.cahandler.container_info_dic = {'name': 'name', 'id': 'id'}
        self.assertEqual(('Enrollment aborted. ca: None, tsg_id: id', None, None, None), self.cahandler.enroll('csr'))
        self.assertTrue(mock_recode.called)
        self.assertTrue(mock_policy.called)
        self.assertFalse(mock_template.called)
        self.assertFalse(mock_enroll.called)

    @patch('examples.ca_handler.nclm_ca_handler.CAhandler._cert_enroll')
    @patch('examples.ca_handler.nclm_ca_handler.CAhandler._template_id_lookup')
    @patch('examples.ca_handler.nclm_ca_handler.CAhandler._ca_policylink_id_lookup')
    @patch('examples.ca_handler.nclm_ca_handler.b64_url_recode')
    def test_096_enroll(self, mock_recode, mock_policy, mock_template, mock_enroll):
        """ test enroll """
        mock_recode.return_value = 'csr'
        mock_policy.return_value = None
        mock_template.return_value = 'template_id'
        mock_enroll.return_value = ('error', 'bundle', 'raw', 'cert_id')
        self.cahandler.template_info_dic = {'name': 'name', 'id': None}
        self.cahandler.container_info_dic = {'name': 'name', 'id': 'id'}
        self.cahandler.error = 'error'
        self.assertEqual(('error', None, None, None), self.cahandler.enroll('csr'))
        self.assertTrue(mock_recode.called)
        self.assertFalse(mock_policy.called)
        self.assertFalse(mock_template.called)
        self.assertFalse(mock_enroll.called)

    @patch('examples.ca_handler.nclm_ca_handler.allowed_domainlist_check')
    @patch('examples.ca_handler.nclm_ca_handler.eab_profile_header_info_check')
    @patch('examples.ca_handler.nclm_ca_handler.CAhandler._cert_enroll')
    @patch('examples.ca_handler.nclm_ca_handler.CAhandler._template_id_lookup')
    @patch('examples.ca_handler.nclm_ca_handler.CAhandler._ca_policylink_id_lookup')
    @patch('examples.ca_handler.nclm_ca_handler.b64_url_recode')
    def test_097_enroll(self, mock_recode, mock_policy, mock_template, mock_enroll, mock_eab, mock_adl):
        """ test enroll """
        mock_recode.return_value = 'csr'
        mock_policy.return_value = 'policylink_id'
        mock_template.return_value = 'template_id'
        mock_adl.return_value = None
        mock_enroll.return_value = ('error', 'bundle', 'raw', 'cert_id')
        mock_eab.return_value = 'eab'
        self.cahandler.template_info_dic = {'name': 'name', 'id': None}
        self.cahandler.container_info_dic = {'name': 'name', 'id': 'id'}
        self.assertEqual(('eab', None, None, None), self.cahandler.enroll('csr'))
        self.assertTrue(mock_recode.called)
        self.assertTrue(mock_policy.called)
        self.assertTrue(mock_template.called)
        self.assertFalse(mock_enroll.called)
        self.assertFalse(mock_adl.called)

    @patch('examples.ca_handler.nclm_ca_handler.allowed_domainlist_check')
    @patch('examples.ca_handler.nclm_ca_handler.eab_profile_header_info_check')
    @patch('examples.ca_handler.nclm_ca_handler.CAhandler._cert_enroll')
    @patch('examples.ca_handler.nclm_ca_handler.CAhandler._template_id_lookup')
    @patch('examples.ca_handler.nclm_ca_handler.CAhandler._ca_policylink_id_lookup')
    @patch('examples.ca_handler.nclm_ca_handler.b64_url_recode')
    def test_098_enroll(self, mock_recode, mock_policy, mock_template, mock_enroll, mock_eab, mock_adl):
        """ test enroll """
        mock_recode.return_value = 'csr'
        mock_policy.return_value = 'policylink_id'
        mock_template.return_value = 'template_id'
        mock_adl.return_value = 'mock_adl'
        mock_enroll.return_value = ('error', 'bundle', 'raw', 'cert_id')
        mock_eab.return_value = False
        self.cahandler.template_info_dic = {'name': 'name', 'id': None}
        self.cahandler.container_info_dic = {'name': 'name', 'id': 'id'}
        self.assertEqual(('mock_adl', None, None, None), self.cahandler.enroll('csr'))
        self.assertTrue(mock_recode.called)
        self.assertTrue(mock_policy.called)
        self.assertTrue(mock_template.called)
        self.assertFalse(mock_enroll.called)
        self.assertTrue(mock_adl.called)

    @patch('examples.ca_handler.nclm_ca_handler.CAhandler._revocation_status_poll')
    @patch('examples.ca_handler.nclm_ca_handler.CAhandler._api_post')
    @patch('examples.ca_handler.nclm_ca_handler.CAhandler._cert_id_lookup')
    @patch('examples.ca_handler.nclm_ca_handler.error_dic_get')
    def test_099_revoke(self, mock_err, mock_idl, mock_post, mock_poll):
        """ test revoke """
        mock_err.return_value = {'foo': 'bar', 'serverinternal': 'serverinternal'}
        mock_idl.return_value = 'cert_id'
        mock_post.return_value = {'urls': {'job': 'foo/v2/jobs/'}}
        mock_poll.return_value = (200, 'message', 'detail')
        self.assertEqual((200, 'message', 'detail'), self.cahandler.revoke('cert_raw'))
        self.assertTrue(mock_err.called)
        self.assertTrue(mock_idl.called)
        self.assertTrue(mock_post.called)
        self.assertTrue(mock_poll.called)

    @patch('examples.ca_handler.nclm_ca_handler.CAhandler._revocation_status_poll')
    @patch('examples.ca_handler.nclm_ca_handler.CAhandler._api_post')
    @patch('examples.ca_handler.nclm_ca_handler.CAhandler._cert_id_lookup')
    @patch('examples.ca_handler.nclm_ca_handler.error_dic_get')
    def test_100_revoke(self, mock_err, mock_idl, mock_post, mock_poll):
        """ test revoke """
        mock_err.return_value = {'foo': 'bar', 'serverinternal': 'serverinternal'}
        mock_idl.return_value = 'cert_id'
        mock_post.return_value = {'urls': {'foo': 'foo'}}
        mock_poll.return_value = (200, 'message', 'detail')
        self.assertEqual((500, 'serverinternal', 'Revocation operation failed'), self.cahandler.revoke('cert_raw'))
        self.assertTrue(mock_err.called)
        self.assertTrue(mock_idl.called)
        self.assertTrue(mock_post.called)
        self.assertFalse(mock_poll.called)

if __name__ == '__main__':

    if os.path.exists('acme_test.db'):
        os.remove('acme_test.db')
    unittest.main()
