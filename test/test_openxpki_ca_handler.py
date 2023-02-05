#!/usr/bin/python
# -*- coding: utf-8 -*-
""" unittests for openssl_ca_handler """
# pylint: disable=C0415, R0904, W0212
import sys
import os
import unittest
from unittest.mock import patch, Mock
import requests
import base64
from OpenSSL import crypto

sys.path.insert(0, '.')
sys.path.insert(1, '..')

class TestACMEHandler(unittest.TestCase):
    """ test class for cgi_handler """

    def setUp(self):
        """ setup unittest """
        import logging
        from examples.ca_handler.openxpki_ca_handler import CAhandler
        logging.basicConfig(level=logging.CRITICAL)
        self.logger = logging.getLogger('test_a2c')
        self.cahandler = CAhandler(False, self.logger)
        self.dir_path = os.path.dirname(os.path.realpath(__file__))

    def test_001_default(self):
        """ default test which always passes """
        self.assertEqual('foo', 'foo')

    @patch('examples.ca_handler.openxpki_ca_handler.CAhandler._config_load')
    def test_002__enter__(self, mock_cfg):
        """ test enter  called """
        mock_cfg.return_value = True
        self.cahandler.__enter__()
        self.assertTrue(mock_cfg.called)

    @patch('examples.ca_handler.openxpki_ca_handler.CAhandler._config_load')
    def test_003__enter__(self, mock_cfg):
        """ test enter api hosts defined """
        mock_cfg.return_value = True
        self.cahandler.host = 'host'
        self.cahandler.__enter__()
        self.assertFalse(mock_cfg.called)

    @patch('examples.ca_handler.openxpki_ca_handler.cert_pem2der')
    @patch('examples.ca_handler.openxpki_ca_handler.b64_encode')
    def test_004_cert_bundle_create(self, mock_enc, mock_p2d):
        """ test _cert_bundle_create() """
        response_dic = {}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual(('Malformed response', None, None), self.cahandler._cert_bundle_create(response_dic))
        self.assertFalse(mock_enc.called)
        self.assertFalse(mock_p2d.called)
        self.assertIn('ERROR:test_a2c:CAhandler._cert_bundle_create() returned malformed response: {}', lcm.output)

    @patch('examples.ca_handler.openxpki_ca_handler.cert_pem2der')
    @patch('examples.ca_handler.openxpki_ca_handler.b64_encode')
    def test_005_cert_bundle_create(self, mock_enc, mock_p2d):
        """ test _cert_bundle_create() """
        response_dic = {'data': {'certificate': 'certificate', 'chain': 'chain'}}
        mock_enc.return_value = 'mock_enc'
        self.assertEqual((None, 'certificatechain', 'mock_enc'), self.cahandler._cert_bundle_create(response_dic))
        self.assertTrue(mock_enc.called)
        self.assertTrue(mock_p2d.called)

    @patch('examples.ca_handler.openxpki_ca_handler.cert_pem2der')
    @patch('examples.ca_handler.openxpki_ca_handler.b64_encode')
    def test_006_cert_bundle_create(self, mock_enc, mock_p2d):
        """ test _cert_bundle_create() """
        response_dic = {'foo': 'bar'}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual(('Malformed response', None, None), self.cahandler._cert_bundle_create(response_dic))
        self.assertFalse(mock_enc.called)
        self.assertFalse(mock_p2d.called)
        self.assertIn("ERROR:test_a2c:CAhandler._cert_bundle_create() returned malformed response: {'foo': 'bar'}", lcm.output)

    @patch('examples.ca_handler.openxpki_ca_handler.cert_pem2der')
    @patch('examples.ca_handler.openxpki_ca_handler.b64_encode')
    def test_007_cert_bundle_create(self, mock_enc, mock_p2d):
        """ test _cert_bundle_create() """
        response_dic = {'data': {'certificate': 'certificate'}}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual(('Malformed response', None, None), self.cahandler._cert_bundle_create(response_dic))
        self.assertFalse(mock_enc.called)
        self.assertFalse(mock_p2d.called)
        self.assertIn("ERROR:test_a2c:CAhandler._cert_bundle_create() returned malformed response: {'data': {'certificate': 'certificate'}}", lcm.output)

    @patch('examples.ca_handler.openxpki_ca_handler.cert_pem2der')
    @patch('examples.ca_handler.openxpki_ca_handler.b64_encode')
    def test_008_cert_bundle_create(self, mock_enc, mock_p2d):
        """ test _cert_bundle_create() """
        response_dic = {'data': {'chain': 'chain'}}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual(('Malformed response', None, None), self.cahandler._cert_bundle_create(response_dic))
        self.assertFalse(mock_enc.called)
        self.assertFalse(mock_p2d.called)
        self.assertIn("ERROR:test_a2c:CAhandler._cert_bundle_create() returned malformed response: {'data': {'chain': 'chain'}}", lcm.output)

    def test_009__config_server_load(self):
        """ test _config_server_load() """
        config_dic = {}
        self.cahandler._config_server_load(config_dic)
        self.assertFalse(self.cahandler.host)
        self.assertEqual(5, self.cahandler.request_timeout)
        self.assertTrue(self.cahandler.ca_bundle)
        self.assertFalse(self.cahandler.endpoint_name)
        self.assertFalse(self.cahandler.cert_profile_name)

    def test_010__config_server_load(self):
        """ test _config_server_load() """
        config_dic = {'CAhandler': {'foo': 'bar'}}
        self.cahandler._config_server_load(config_dic)
        self.assertFalse(self.cahandler.host)
        self.assertEqual(5, self.cahandler.request_timeout)
        self.assertTrue(self.cahandler.ca_bundle)
        self.assertFalse(self.cahandler.endpoint_name)
        self.assertFalse(self.cahandler.cert_profile_name)

    def test_011__config_server_load(self):
        """ test _config_server_load() """
        config_dic = {'CAhandler': {'endpoint_name': 'endpoint_name'}}
        self.cahandler._config_server_load(config_dic)
        self.assertFalse(self.cahandler.host)
        self.assertEqual(5, self.cahandler.request_timeout)
        self.assertTrue(self.cahandler.ca_bundle)
        self.assertEqual('endpoint_name', self.cahandler.endpoint_name)
        self.assertFalse(self.cahandler.cert_profile_name)

    def test_012__config_server_load(self):
        """ test _config_server_load() """
        config_dic = {'CAhandler': {'host': 'host'}}
        self.cahandler._config_server_load(config_dic)
        self.assertEqual('host', self.cahandler.host)
        self.assertEqual(5, self.cahandler.request_timeout)
        self.assertTrue(self.cahandler.ca_bundle)
        self.assertFalse(self.cahandler.endpoint_name)
        self.assertFalse(self.cahandler.cert_profile_name)

    def test_013__config_server_load(self):
        """ test _config_server_load() """
        config_dic = {'CAhandler': {'cert_profile_name': 'cert_profile_name'}}
        self.cahandler._config_server_load(config_dic)
        self.assertFalse(self.cahandler.host)
        self.assertEqual(5, self.cahandler.request_timeout)
        self.assertTrue(self.cahandler.ca_bundle)
        self.assertFalse(self.cahandler.endpoint_name)
        self.assertEqual('cert_profile_name', self.cahandler.cert_profile_name)

    def test_014__config_server_load(self):
        """ test _config_server_load() """
        config_dic = {'CAhandler': {'request_timeout': 10}}
        self.cahandler._config_server_load(config_dic)
        self.assertFalse(self.cahandler.host)
        self.assertEqual(10, self.cahandler.request_timeout)
        self.assertTrue(self.cahandler.ca_bundle)
        self.assertFalse(self.cahandler.endpoint_name)
        self.assertFalse(self.cahandler.cert_profile_name)

    def test_015__config_server_load(self):
        """ test _config_server_load() """
        config_dic = {'CAhandler': {'ca_bundle': False}}
        self.cahandler._config_server_load(config_dic)
        self.assertFalse(self.cahandler.host)
        self.assertEqual(5, self.cahandler.request_timeout)
        self.assertFalse(self.cahandler.ca_bundle)
        self.assertFalse(self.cahandler.endpoint_name)
        self.assertFalse(self.cahandler.cert_profile_name)

    def test_016__config_server_load(self):
        """ test _config_server_load() """
        config_dic = {'CAhandler': {'ca_bundle': ''}}
        self.cahandler._config_server_load(config_dic)
        self.assertFalse(self.cahandler.host)
        self.assertEqual(5, self.cahandler.request_timeout)
        self.assertFalse(self.cahandler.ca_bundle)
        self.assertFalse(self.cahandler.endpoint_name)
        self.assertFalse(self.cahandler.cert_profile_name)

    def test_017__config_server_load(self):
        """ test _config_server_load() """
        config_dic = {'CAhandler': {'ca_bundle': 'ca_bundle'}}
        self.cahandler._config_server_load(config_dic)
        self.assertFalse(self.cahandler.host)
        self.assertEqual(5, self.cahandler.request_timeout)
        self.assertEqual('ca_bundle', self.cahandler.ca_bundle)
        self.assertFalse(self.cahandler.endpoint_name)
        self.assertFalse(self.cahandler.cert_profile_name)

    def test_018__config_clientauth_load(self):
        """ test _config_server_load() """
        config_dic = {'CAhandler': {'foo': 'bar'}}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_clientauth_load(config_dic)
        self.assertFalse(self.cahandler.client_cert)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load() configuration incomplete: either "client_cert or "client_key" parameter is missing in config file', lcm.output)

    def test_019__config_clientauth_load(self):
        """ test _config_server_load() """
        config_dic = {'CAhandler': {'client_cert': 'client_cert'}}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_clientauth_load(config_dic)
        self.assertFalse(self.cahandler.client_cert)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load() configuration incomplete: either "client_cert or "client_key" parameter is missing in config file', lcm.output)

    def test_20__config_clientauth_load(self):
        """ test _config_server_load() """
        config_dic = {'CAhandler': {'client_key': 'client_key'}}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_clientauth_load(config_dic)
        self.assertFalse(self.cahandler.client_cert)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load() configuration incomplete: either "client_cert or "client_key" parameter is missing in config file', lcm.output)

    def test_21__config_clientauth_load(self):
        """ test _config_server_load() """
        config_dic = {'CAhandler': {'client_key': 'client_key', 'client_cert': 'client_cert'}}
        self.cahandler._config_clientauth_load(config_dic)
        self.assertEqual(['client_cert', 'client_key'], self.cahandler.client_cert)

    @patch('examples.ca_handler.openxpki_ca_handler.CAhandler._config_server_load')
    @patch('examples.ca_handler.openxpki_ca_handler.CAhandler._config_clientauth_load')
    @patch('examples.ca_handler.openxpki_ca_handler.load_config')
    def test_022_config_load(self, mock_load_cfg, mock_auth_load, mock_server_load):
        """ load config """
        mock_load_cfg.return_value = {'foo': 'bar'}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_load()
        self.assertTrue(mock_auth_load.called)
        self.assertTrue(mock_server_load.called)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load(): configuration incomplete: parameter "host" is missing in configuration file.', lcm.output)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load(): configuration incomplete: parameter "cert_profile_name" is missing in configuration file.', lcm.output)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load(): configuration incomplete: parameter "client_cert" is missing in configuration file.', lcm.output)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load(): configuration incomplete: parameter "endpoint_name" is missing in configuration file.', lcm.output)

    @patch('examples.ca_handler.openxpki_ca_handler.CAhandler._config_server_load')
    @patch('examples.ca_handler.openxpki_ca_handler.CAhandler._config_clientauth_load')
    @patch('examples.ca_handler.openxpki_ca_handler.load_config')
    def test_023_config_load(self, mock_load_cfg, mock_auth_load, mock_server_load):
        """ load config """
        mock_load_cfg.return_value = {'foo': 'bar'}
        self.cahandler.host = 'host'
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_load()
        self.assertTrue(mock_auth_load.called)
        self.assertTrue(mock_server_load.called)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load(): configuration incomplete: parameter "cert_profile_name" is missing in configuration file.', lcm.output)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load(): configuration incomplete: parameter "client_cert" is missing in configuration file.', lcm.output)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load(): configuration incomplete: parameter "endpoint_name" is missing in configuration file.', lcm.output)

    @patch('examples.ca_handler.openxpki_ca_handler.CAhandler._config_server_load')
    @patch('examples.ca_handler.openxpki_ca_handler.CAhandler._config_clientauth_load')
    @patch('examples.ca_handler.openxpki_ca_handler.load_config')
    def test_024_config_load(self, mock_load_cfg, mock_auth_load, mock_server_load):
        """ load config """
        mock_load_cfg.return_value = {'foo': 'bar'}
        self.cahandler.cert_profile_name = 'cert_profile_name'
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_load()
        self.assertTrue(mock_auth_load.called)
        self.assertTrue(mock_server_load.called)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load(): configuration incomplete: parameter "host" is missing in configuration file.', lcm.output)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load(): configuration incomplete: parameter "client_cert" is missing in configuration file.', lcm.output)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load(): configuration incomplete: parameter "endpoint_name" is missing in configuration file.', lcm.output)

    @patch('examples.ca_handler.openxpki_ca_handler.CAhandler._config_server_load')
    @patch('examples.ca_handler.openxpki_ca_handler.CAhandler._config_clientauth_load')
    @patch('examples.ca_handler.openxpki_ca_handler.load_config')
    def test_025_config_load(self, mock_load_cfg, mock_auth_load, mock_server_load):
        """ load config """
        mock_load_cfg.return_value = {'foo': 'bar'}
        self.cahandler.client_cert = 'client_cert'
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_load()
        self.assertTrue(mock_auth_load.called)
        self.assertTrue(mock_server_load.called)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load(): configuration incomplete: parameter "host" is missing in configuration file.', lcm.output)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load(): configuration incomplete: parameter "cert_profile_name" is missing in configuration file.', lcm.output)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load(): configuration incomplete: parameter "endpoint_name" is missing in configuration file.', lcm.output)

    @patch('examples.ca_handler.openxpki_ca_handler.CAhandler._config_server_load')
    @patch('examples.ca_handler.openxpki_ca_handler.CAhandler._config_clientauth_load')
    @patch('examples.ca_handler.openxpki_ca_handler.load_config')
    def test_026_config_load(self, mock_load_cfg, mock_auth_load, mock_server_load):
        """ load config """
        mock_load_cfg.return_value = {'foo': 'bar'}
        self.cahandler.endpoint_name = 'endpoint_name'
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_load()
        self.assertTrue(mock_auth_load.called)
        self.assertTrue(mock_server_load.called)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load(): configuration incomplete: parameter "host" is missing in configuration file.', lcm.output)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load(): configuration incomplete: parameter "cert_profile_name" is missing in configuration file.', lcm.output)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load(): configuration incomplete: parameter "client_cert" is missing in configuration file.', lcm.output)

    def test_027_poll(self):
        """ test polling """
        self.assertEqual(('Method not implemented.', None, None, 'poll_identifier', False), self.cahandler.poll('cert_name', 'poll_identifier', 'csr'))

    def test_028_trigger(self):
        """ test polling """
        self.assertEqual(('Method not implemented.', None, None), self.cahandler.trigger('payload'))

    @patch.object(requests, 'post')
    def test_029__rpc_post(self, mock_req):
        """ test _api_post successful run """
        mockresponse = Mock()
        mock_req.return_value = mockresponse
        mockresponse.json = lambda: {'foo': 'bar'}
        self.cahandler.host = 'host'
        self.assertEqual({'foo': 'bar'}, self.cahandler._rpc_post('url', 'data'))

    @patch('requests.post')
    def test_030__rpc_post(self, mock_post):
        """ CAhandler.get_ca() returns an http error """
        self.cahandler.host = 'api_host'
        mock_post.side_effect = Exception('exc_api_post')
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertFalse(self.cahandler._rpc_post('url', 'data'))
        self.assertIn('ERROR:test_a2c:CAhandler._rpc_post() returned an error: exc_api_post', lcm.output)

    @patch('examples.ca_handler.openxpki_ca_handler.CAhandler._cert_bundle_create')
    @patch('examples.ca_handler.openxpki_ca_handler.CAhandler._rpc_post')
    @patch('examples.ca_handler.openxpki_ca_handler.build_pem_file')
    @patch('examples.ca_handler.openxpki_ca_handler.b64_url_recode')
    def test_031_enroll(self, mock_recode, mock_pem, mock_post, mock_create):
        """ test ernoll """
        csr = 'csr'
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual(('Configuration incomplete', None, None, None), self.cahandler.enroll(csr))
        self.assertIn('ERROR:test_a2c:CAhandler.enroll(): Configuration incomplete. Host variable is missing...', lcm.output)
        self.assertFalse(mock_recode.called)
        self.assertFalse(mock_pem.called)
        self.assertFalse(mock_post.called)
        self.assertFalse(mock_create.called)

    @patch('examples.ca_handler.openxpki_ca_handler.CAhandler._cert_bundle_create')
    @patch('examples.ca_handler.openxpki_ca_handler.CAhandler._rpc_post')
    @patch('examples.ca_handler.openxpki_ca_handler.build_pem_file')
    @patch('examples.ca_handler.openxpki_ca_handler.b64_url_recode')
    def test_032_enroll(self, mock_recode, mock_pem, mock_post, mock_create):
        """ test ernoll """
        csr = 'csr'
        self.cahandler.host = 'host'
        mock_recode.return_value = 'mock_recode'
        mock_pem.return_value = 'mock_pem'
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual(('Configuration incomplete', None, None, None), self.cahandler.enroll(csr))
        self.assertIn('ERROR:test_a2c:CAhandler.enroll(): Configuration incomplete. Clientauthentication is missing...', lcm.output)
        self.assertTrue(mock_recode.called)
        self.assertTrue(mock_pem.called)
        self.assertFalse(mock_post.called)
        self.assertFalse(mock_create.called)

    @patch('examples.ca_handler.openxpki_ca_handler.CAhandler._cert_bundle_create')
    @patch('examples.ca_handler.openxpki_ca_handler.CAhandler._rpc_post')
    @patch('examples.ca_handler.openxpki_ca_handler.build_pem_file')
    @patch('examples.ca_handler.openxpki_ca_handler.b64_url_recode')
    def test_033_enroll(self, mock_recode, mock_pem, mock_post, mock_create):
        """ test ernoll """
        csr = 'csr'
        self.cahandler.host = 'host'
        self.cahandler.endpoint_name = 'endpoint_name'
        self.cahandler.client_cert = 'client_cert'
        mock_recode.return_value = 'mock_recode'
        mock_pem.return_value = 'mock_pem'
        mock_post.return_value = 'mock_post'
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual(('Malformed response', None, None, None), self.cahandler.enroll(csr))
        self.assertIn('ERROR:test_a2c:CAhandler.enroll(): Malformed Rest response: mock_post', lcm.output)
        self.assertTrue(mock_recode.called)
        self.assertTrue(mock_pem.called)
        self.assertTrue(mock_post.called)
        self.assertFalse(mock_create.called)

    @patch('examples.ca_handler.openxpki_ca_handler.CAhandler._cert_bundle_create')
    @patch('examples.ca_handler.openxpki_ca_handler.CAhandler._rpc_post')
    @patch('examples.ca_handler.openxpki_ca_handler.build_pem_file')
    @patch('examples.ca_handler.openxpki_ca_handler.b64_url_recode')
    def test_034_enroll(self, mock_recode, mock_pem, mock_post, mock_create):
        """ test ernoll """
        csr = 'csr'
        self.cahandler.host = 'host'
        self.cahandler.endpoint_name = 'endpoint_name'
        self.cahandler.client_cert = 'client_cert'
        mock_recode.return_value = 'mock_recode'
        mock_pem.return_value = 'mock_pem'
        mock_post.return_value = {'result': {'foo': 'bar'}}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual(('Malformed response', None, None, None), self.cahandler.enroll(csr))
        self.assertIn("ERROR:test_a2c:CAhandler.enroll(): Malformed Rest response: {'result': {'foo': 'bar'}}", lcm.output)
        self.assertTrue(mock_recode.called)
        self.assertTrue(mock_pem.called)
        self.assertTrue(mock_post.called)
        self.assertFalse(mock_create.called)

    @patch('examples.ca_handler.openxpki_ca_handler.CAhandler._cert_bundle_create')
    @patch('examples.ca_handler.openxpki_ca_handler.CAhandler._rpc_post')
    @patch('examples.ca_handler.openxpki_ca_handler.build_pem_file')
    @patch('examples.ca_handler.openxpki_ca_handler.b64_url_recode')
    def test_035_enroll(self, mock_recode, mock_pem, mock_post, mock_create):
        """ test ernoll """
        csr = 'csr'
        self.cahandler.host = 'host'
        self.cahandler.endpoint_name = 'endpoint_name'
        self.cahandler.client_cert = 'client_cert'
        mock_recode.return_value = 'mock_recode'
        mock_pem.return_value = 'mock_pem'
        mock_post.return_value = {'result': {'state': 'bar'}}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual(('Malformed response', None, None, None), self.cahandler.enroll(csr))
        self.assertIn("ERROR:test_a2c:CAhandler.enroll(): Malformed Rest response: {'result': {'state': 'bar'}}", lcm.output)
        self.assertTrue(mock_recode.called)
        self.assertTrue(mock_pem.called)
        self.assertTrue(mock_post.called)
        self.assertFalse(mock_create.called)

    @patch('examples.ca_handler.openxpki_ca_handler.CAhandler._cert_bundle_create')
    @patch('examples.ca_handler.openxpki_ca_handler.CAhandler._rpc_post')
    @patch('examples.ca_handler.openxpki_ca_handler.build_pem_file')
    @patch('examples.ca_handler.openxpki_ca_handler.b64_url_recode')
    def test_036_enroll(self, mock_recode, mock_pem, mock_post, mock_create):
        """ test ernoll """
        csr = 'csr'
        self.cahandler.host = 'host'
        self.cahandler.endpoint_name = 'endpoint_name'
        self.cahandler.client_cert = 'client_cert'
        mock_recode.return_value = 'mock_recode'
        mock_pem.return_value = 'mock_pem'
        mock_post.return_value = {'result': {'state': 'success'}}
        mock_create.return_value = ('error', 'bundle', 'raw')
        self.assertEqual(('error', 'bundle', 'raw', None), self.cahandler.enroll(csr))
        self.assertTrue(mock_recode.called)
        self.assertTrue(mock_pem.called)
        self.assertTrue(mock_post.called)
        self.assertTrue(mock_create.called)

if __name__ == '__main__':

    unittest.main()
