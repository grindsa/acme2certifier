#!/usr/bin/python
# -*- coding: utf-8 -*-
""" unittests for openssl_ca_handler """
# pylint: disable=C0415, R0904, W0212
import sys
import os
import unittest
from unittest.mock import patch, Mock, MagicMock
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
        self.assertEqual((None, 'certificate\nchain', 'mock_enc'), self.cahandler._cert_bundle_create(response_dic))
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
        self.assertFalse(self.cahandler.endpoint_name)
        self.assertEqual('/rpc/', self.cahandler.rpc_path)

    def test_010__config_server_load(self):
        """ test _config_server_load() """
        config_dic = {'CAhandler': {'foo': 'bar'}}
        self.cahandler._config_server_load(config_dic)
        self.assertFalse(self.cahandler.host)
        self.assertEqual(5, self.cahandler.request_timeout)
        self.assertFalse(self.cahandler.endpoint_name)
        self.assertEqual('/rpc/', self.cahandler.rpc_path)

    def test_011__config_server_load(self):
        """ test _config_server_load() """
        config_dic = {'CAhandler': {'endpoint_name': 'endpoint_name'}}
        self.cahandler._config_server_load(config_dic)
        self.assertFalse(self.cahandler.host)
        self.assertEqual(5, self.cahandler.request_timeout)
        self.assertEqual('endpoint_name', self.cahandler.endpoint_name)
        self.assertEqual('/rpc/', self.cahandler.rpc_path)

    def test_012__config_server_load(self):
        """ test _config_server_load() """
        config_dic = {'CAhandler': {'host': 'host'}}
        self.cahandler._config_server_load(config_dic)
        self.assertEqual('host', self.cahandler.host)
        self.assertEqual(5, self.cahandler.request_timeout)
        self.assertFalse(self.cahandler.endpoint_name)
        self.assertEqual('/rpc/', self.cahandler.rpc_path)

    def test_013__config_server_load(self):
        """ test _config_server_load() """
        config_dic = {'CAhandler': {'rpc_path': 'rpc_path'}}
        self.cahandler._config_server_load(config_dic)
        self.assertFalse(self.cahandler.host)
        self.assertEqual(5, self.cahandler.request_timeout)
        self.assertFalse(self.cahandler.endpoint_name)
        self.assertEqual('rpc_path', self.cahandler.rpc_path)

    def test_014__config_ca_loadd(self):
        """ test _config_server_load() """
        config_dic = {'CAhandler': {'cert_profile_name': 'cert_profile_name'}}
        self.cahandler._config_ca_load(config_dic)
        self.assertTrue(self.cahandler.ca_bundle)
        self.assertEqual('cert_profile_name', self.cahandler.cert_profile_name)
        self.assertEqual(0, self.cahandler.polling_timeout)

    def test_015__config_server_load(self):
        """ test _config_server_load() """
        config_dic = {'CAhandler': {'request_timeout': 10}}
        self.cahandler._config_server_load(config_dic)
        self.assertFalse(self.cahandler.host)
        self.assertEqual(10, self.cahandler.request_timeout)
        self.assertFalse(self.cahandler.endpoint_name)
        self.assertEqual('/rpc/', self.cahandler.rpc_path)

    def test_016__config_ca_load(self):
        """ test _config_server_load() """
        config_dic = {'CAhandler': {'ca_bundle': False}}
        self.cahandler._config_ca_load(config_dic)
        self.assertFalse(self.cahandler.ca_bundle)
        self.assertFalse(self.cahandler.cert_profile_name)
        self.assertEqual(0, self.cahandler.polling_timeout)

    def test_017__config_ca_load(self):
        """ test _config_server_load() """
        config_dic = {'CAhandler': {'ca_bundle': ''}}
        self.cahandler._config_ca_load(config_dic)
        self.assertFalse(self.cahandler.ca_bundle)
        self.assertFalse(self.cahandler.cert_profile_name)
        self.assertEqual(0, self.cahandler.polling_timeout)

    def test_018__config_ca_load(self):
        """ test _config_server_load() """
        config_dic = {'CAhandler': {'ca_bundle': 'ca_bundle'}}
        self.cahandler._config_ca_load(config_dic)
        self.assertEqual('ca_bundle', self.cahandler.ca_bundle)
        self.assertFalse(self.cahandler.cert_profile_name)
        self.assertEqual(0, self.cahandler.polling_timeout)

    def test_019__config_ca_load(self):
        """ test _config_server_load() """
        config_dic = {'CAhandler': {'polling_timeout': 10}}
        self.cahandler._config_ca_load(config_dic)
        self.assertEqual(10, self.cahandler.polling_timeout)
        self.assertTrue(self.cahandler.ca_bundle)
        self.assertFalse(self.cahandler.cert_profile_name)

    def test_020__config_ca_load(self):
        """ test _config_server_load() """
        config_dic = {'CAhandler': {'polling_timeout': 'polling_timeout'}}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_ca_load(config_dic)
        self.assertIn("ERROR:test_a2c:CAhandler._config_server_load(): failed to load polling_timeout option: invalid literal for int() with base 10: 'polling_timeout'", lcm.output)
        self.assertEqual(0, self.cahandler.polling_timeout)
        self.assertTrue(self.cahandler.ca_bundle)
        self.assertFalse(self.cahandler.cert_profile_name)

    def test_021__config_session_load(self):
        """ test _config_server_load() """
        config_dic = {'CAhandler': {'foo': 'bar'}}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_session_load(config_dic)
        self.assertFalse(self.cahandler.client_cert)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load() configuration incomplete: either "client_cert. "client_key" or "client_passphrase[_variable] parameter is missing in config file', lcm.output)

    @patch('examples.ca_handler.openxpki_ca_handler.CAhandler._config_passphrase_load')
    def test_022__config_session_load(self, mock_pass):
        """ test _config_server_load() """
        config_dic = {'CAhandler': {'client_cert': 'client_cert', 'client_key': 'client_key'}}
        self.cahandler._config_session_load(config_dic)
        self.assertEqual(('client_cert', 'client_key'), self.cahandler.session.cert)
        self.assertFalse(mock_pass.called)

    @patch('examples.ca_handler.openxpki_ca_handler.CAhandler._config_passphrase_load')
    def test_023__config_session_load(self, mock_pass):
        """ test _config_server_load() """
        config_dic = {'CAhandler': {'client_cert': 'client_cert', 'cert_passphrase': 'cert_passphrase'}}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_session_load(config_dic)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load() configuration incomplete: either "client_cert. "client_key" or "client_passphrase[_variable] parameter is missing in config file', lcm.output)
        self.assertTrue(mock_pass.called)

    @patch('requests.Session')
    @patch('examples.ca_handler.openxpki_ca_handler.Pkcs12Adapter')
    @patch('examples.ca_handler.openxpki_ca_handler.CAhandler._config_passphrase_load')
    def test_024__config_session_load(self, mock_pass, mock_req, mock_session):
        """ test _config_server_load() """
        config_dic = {'CAhandler': {'client_cert': 'client_cert', 'cert_passphrase': 'cert_passphrase'}}
        mock_session.return_value.__enter__.return_value = Mock()
        self.cahandler.cert_passphrase = 'cert_passphrase'
        self.cahandler._config_session_load(config_dic)
        self.assertTrue(mock_pass.called)
        self.assertTrue(mock_req.called)

    def test_025__config_passphrase_load(self):
        """ test _config_passphrase_load() """
        config_dic = {'CAhandler': {'foo': 'bar'}}
        self.cahandler._config_passphrase_load(config_dic)
        self.assertFalse(self.cahandler.cert_passphrase)

    def test_026__config_passphrase_load(self):
        """ test _config_passphrase_load() """
        config_dic = {'CAhandler': {'cert_passphrase': 'cert_passphrase'}}
        self.cahandler._config_passphrase_load(config_dic)
        self.assertEqual('cert_passphrase', self.cahandler.cert_passphrase)

    @patch.dict('os.environ', {'cert_passphrase_variable': 'cert_passphrase_variable'})
    def test_027__config_passphrase_load(self):
        """ test _config_passphrase_load() """
        config_dic = {'CAhandler': {'cert_passphrase_variable': 'cert_passphrase_variable'}}
        self.cahandler._config_passphrase_load(config_dic)
        self.assertEqual('cert_passphrase_variable', self.cahandler.cert_passphrase)

    @patch.dict('os.environ', {'foo': 'bar'})
    def test_028__config_passphrase_load(self):
        """ test _config_passphrase_load() """
        config_dic = {'CAhandler': {'cert_passphrase_variable': 'cert_passphrase_variable'}}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_passphrase_load(config_dic)
        self.assertIn("ERROR:test_a2c:CAhandler._config_passphrase_load() could not load cert_passphrase_variable:'cert_passphrase_variable'", lcm.output)
        self.assertFalse(self.cahandler.cert_passphrase)

    @patch.dict('os.environ', {'cert_passphrase_variable': 'cert_passphrase_variable'})
    def test_029__config_passphrase_load(self):
        """ test _config_passphrase_load() """
        config_dic = {'CAhandler': {'cert_passphrase_variable': 'cert_passphrase_variable', 'cert_passphrase': 'cert_passphrase'}}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_passphrase_load(config_dic)
        self.assertIn('INFO:test_a2c:CAhandler._config_load() overwrite cert_passphrase', lcm.output)
        self.assertEqual('cert_passphrase', self.cahandler.cert_passphrase)

    @patch('examples.ca_handler.openxpki_ca_handler.CAhandler._config_server_load')
    @patch('examples.ca_handler.openxpki_ca_handler.CAhandler._config_session_load')
    @patch('examples.ca_handler.openxpki_ca_handler.load_config')
    def test_030_config_load(self, mock_load_cfg, mock_auth_load, mock_server_load):
        """ load config """
        mock_load_cfg.return_value = {'foo': 'bar'}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_load()
        self.assertTrue(mock_auth_load.called)
        self.assertTrue(mock_server_load.called)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load(): configuration incomplete: parameter "host" is missing in configuration file.', lcm.output)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load(): configuration incomplete: parameter "cert_profile_name" is missing in configuration file.', lcm.output)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load(): configuration incomplete: parameter "endpoint_name" is missing in configuration file.', lcm.output)

    @patch('examples.ca_handler.openxpki_ca_handler.CAhandler._config_server_load')
    @patch('examples.ca_handler.openxpki_ca_handler.CAhandler._config_session_load')
    @patch('examples.ca_handler.openxpki_ca_handler.load_config')
    def test_031_config_load(self, mock_load_cfg, mock_auth_load, mock_server_load):
        """ load config """
        mock_load_cfg.return_value = {'foo': 'bar'}
        self.cahandler.host = 'host'
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_load()
        self.assertTrue(mock_auth_load.called)
        self.assertTrue(mock_server_load.called)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load(): configuration incomplete: parameter "cert_profile_name" is missing in configuration file.', lcm.output)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load(): configuration incomplete: parameter "endpoint_name" is missing in configuration file.', lcm.output)

    @patch('examples.ca_handler.openxpki_ca_handler.CAhandler._config_server_load')
    @patch('examples.ca_handler.openxpki_ca_handler.CAhandler._config_session_load')
    @patch('examples.ca_handler.openxpki_ca_handler.load_config')
    def test_032_config_load(self, mock_load_cfg, mock_auth_load, mock_server_load):
        """ load config """
        mock_load_cfg.return_value = {'foo': 'bar'}
        self.cahandler.cert_profile_name = 'cert_profile_name'
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_load()
        self.assertTrue(mock_auth_load.called)
        self.assertTrue(mock_server_load.called)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load(): configuration incomplete: parameter "host" is missing in configuration file.', lcm.output)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load(): configuration incomplete: parameter "endpoint_name" is missing in configuration file.', lcm.output)

    @patch('examples.ca_handler.openxpki_ca_handler.CAhandler._config_server_load')
    @patch('examples.ca_handler.openxpki_ca_handler.CAhandler._config_session_load')
    @patch('examples.ca_handler.openxpki_ca_handler.load_config')
    def test_033_config_load(self, mock_load_cfg, mock_auth_load, mock_server_load):
        """ load config """
        mock_load_cfg.return_value = {'foo': 'bar'}
        self.cahandler.endpoint_name = 'endpoint_name'
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_load()
        self.assertTrue(mock_auth_load.called)
        self.assertTrue(mock_server_load.called)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load(): configuration incomplete: parameter "host" is missing in configuration file.', lcm.output)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load(): configuration incomplete: parameter "cert_profile_name" is missing in configuration file.', lcm.output)

    def test_034_poll(self):
        """ test polling """
        self.assertEqual(('Method not implemented.', None, None, 'poll_identifier', False), self.cahandler.poll('cert_name', 'poll_identifier', 'csr'))

    def test_035_trigger(self):
        """ test polling """
        self.assertEqual(('Method not implemented.', None, None), self.cahandler.trigger('payload'))

    @patch.object(requests, 'post')
    def test_036__rpc_post(self, mock_req):
        """ test _api_post successful run """
        mockresponse2 = Mock()
        mockresponse2.json = lambda: {'foo': 'bar'}
        mockresponse = Mock()
        mockresponse.post.side_effect = [mockresponse2]
        self.cahandler.session = mockresponse
        self.cahandler.host = 'host'
        self.assertEqual({'foo': 'bar'}, self.cahandler._rpc_post('url', 'data'))

    @patch('requests.post')
    def test_037__rpc_post(self, mock_post):
        """ CAhandler.get_ca() returns an http error """
        self.cahandler.host = 'api_host'
        mockresponse = Mock()
        mockresponse.post.side_effect = [Exception('exc_api_post')]
        self.cahandler.session = mockresponse
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertFalse(self.cahandler._rpc_post('url', 'data'))
        self.assertIn('ERROR:test_a2c:CAhandler._rpc_post() returned an error: exc_api_post', lcm.output)

    @patch('examples.ca_handler.openxpki_ca_handler.CAhandler._enroll')
    @patch('examples.ca_handler.openxpki_ca_handler.build_pem_file')
    @patch('examples.ca_handler.openxpki_ca_handler.b64_url_recode')
    def test_038_enroll(self, mock_recode, mock_pem, mock_enroll):
        """ test ernoll """
        csr = 'csr'
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual(('Configuration incomplete', None, None, None), self.cahandler.enroll(csr))
        self.assertIn('ERROR:test_a2c:CAhandler.enroll(): Configuration incomplete. Host variable is missing...', lcm.output)
        self.assertFalse(mock_recode.called)
        self.assertFalse(mock_pem.called)
        self.assertFalse(mock_enroll.called)

    @patch('examples.ca_handler.openxpki_ca_handler.CAhandler._enroll')
    @patch('examples.ca_handler.openxpki_ca_handler.build_pem_file')
    @patch('examples.ca_handler.openxpki_ca_handler.b64_url_recode')
    def test_039_enroll(self, mock_recode, mock_pem, mock_enroll):
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
        self.assertFalse(mock_enroll.called)

    @patch('examples.ca_handler.openxpki_ca_handler.CAhandler._enroll')
    @patch('examples.ca_handler.openxpki_ca_handler.build_pem_file')
    @patch('examples.ca_handler.openxpki_ca_handler.b64_url_recode')
    def test_040_enroll(self, mock_recode, mock_pem, mock_enroll):
        """ test ernoll """
        csr = 'csr'
        self.cahandler.host = 'host'
        self.cahandler.endpoint_name = 'endpoint_name'
        self.cahandler.session = 'session'
        mock_enroll.return_value = ('error', 'cert_bundle', 'cert_raw', 'poll_indentifier')
        self.assertEqual(('error', 'cert_bundle', 'cert_raw', 'poll_indentifier'), self.cahandler.enroll(csr))
        self.assertTrue(mock_recode.called)
        self.assertTrue(mock_pem.called)
        self.assertTrue(mock_enroll.called)

    @patch('examples.ca_handler.openxpki_ca_handler.CAhandler._cert_bundle_create')
    @patch('examples.ca_handler.openxpki_ca_handler.CAhandler._rpc_post')
    def test_041__enroll(self, mock_post, mock_create):
        """ test _enroll() """
        mock_post.return_value = {'foo': 'bar'}
        self.cahandler.endpoint_name = 'endpoint_name'
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual(('Malformed response', None, None, None), self.cahandler._enroll({'foo': 'bar'}))
        self.assertIn("ERROR:test_a2c:CAhandler.enroll(): Malformed Rest response: {'foo': 'bar'}", lcm.output)
        self.assertFalse(mock_create.called)

    @patch('examples.ca_handler.openxpki_ca_handler.CAhandler._cert_bundle_create')
    @patch('examples.ca_handler.openxpki_ca_handler.CAhandler._rpc_post')
    def test_042__enroll(self, mock_post, mock_create):
        """ test _enroll() """
        mock_post.return_value = {'result': {'id': 'id', 'state': 'pending', 'data': {'transaction_id': 'transaction_id'}}}
        self.cahandler.endpoint_name = 'endpoint_name'
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual((None, None, None, 'transaction_id'), self.cahandler._enroll({'foo': 'bar'}))
        self.assertIn('INFO:test_a2c:CAhandler.enroll(): Request pending. Transaction_id: transaction_id Workflow_id: id', lcm.output)
        self.assertFalse(mock_create.called)

    @patch('examples.ca_handler.openxpki_ca_handler.CAhandler._cert_bundle_create')
    @patch('examples.ca_handler.openxpki_ca_handler.CAhandler._rpc_post')
    def test_043__enroll(self, mock_post, mock_create):
        """ test _enroll() """
        mock_post.return_value = {'result': {'id': 'id', 'state': 'SUCCESS', 'data': {'cert_identifier': 'cert_identifier'}}}
        self.cahandler.endpoint_name = 'endpoint_name'
        mock_create.return_value = ('error', 'cert_bundle', 'cert_raw')
        self.assertEqual(('error', 'cert_bundle', 'cert_raw', 'cert_identifier'), self.cahandler._enroll({'foo': 'bar'}))
        self.assertTrue(mock_create.called)

    @patch('examples.ca_handler.openxpki_ca_handler.CAhandler._cert_bundle_create')
    @patch('examples.ca_handler.openxpki_ca_handler.CAhandler._rpc_post')
    def test_044__enroll(self, mock_post, mock_create):
        """ test _enroll() """
        mock_post.side_effect = [{'result': {'id': 'id', 'state': 'pending', 'data': {'transaction_id': 'transaction_id'}}}, {'result': {'id': 'id', 'state': 'SUCCESS', 'data': {'transaction_id': 'transaction_id'}}}]
        self.cahandler.endpoint_name = 'endpoint_name'
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual((None, None, None, 'transaction_id'), self.cahandler._enroll({'foo': 'bar'}))
        self.assertIn('INFO:test_a2c:CAhandler.enroll(): Request pending. Transaction_id: transaction_id Workflow_id: id', lcm.output)
        self.assertFalse(mock_create.called)

    @patch('time.sleep')
    @patch('examples.ca_handler.openxpki_ca_handler.CAhandler._cert_bundle_create')
    @patch('examples.ca_handler.openxpki_ca_handler.CAhandler._rpc_post')
    def test_045__enroll(self, mock_post, mock_create, mock_sleep):
        """ test _enroll() """
        mock_post.side_effect = [{'result': {'id': 'id', 'state': 'pending', 'data': {'transaction_id': 'transaction_id'}}}, {'result': {'id': 'id', 'state': 'SUCCESS', 'data': {'cert_identifier': 'cert_identifier'}}}]
        self.cahandler.endpoint_name = 'endpoint_name'
        self.cahandler.polling_timeout = 60
        mock_sleep.return_value = Mock()
        mock_create.return_value = ('error', 'cert_bundle', 'cert_raw')
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual(('error', 'cert_bundle', 'cert_raw', 'cert_identifier'), self.cahandler._enroll({'foo': 'bar'}))
        self.assertIn('INFO:test_a2c:CAhandler.enroll(): Request pending. Transaction_id: transaction_id Workflow_id: id', lcm.output)
        self.assertTrue(mock_create.called)

    @patch('examples.ca_handler.openxpki_ca_handler.DBstore.certificate_lookup')
    def test_046__cert_identifier_get(self, mock_certlookup):
        """ test _cert_identifier_get() """
        self.cahandler.endpoint_name = 'endpoint_name'
        mock_certlookup.return_value = {'poll_identifier' : 'cert_identifier'}
        self.assertEqual('cert_identifier', self.cahandler._cert_identifier_get('certcn'))

    @patch('examples.ca_handler.openxpki_ca_handler.DBstore.certificate_lookup')
    def test_047__cert_identifier_get(self, mock_certlookup):
        """ test _cert_identifier_get() """
        self.cahandler.endpoint_name = 'endpoint_name'
        mock_certlookup.return_value = {'poll_identifier' : ''}
        self.assertFalse(self.cahandler._cert_identifier_get('certcn'))

    @patch('examples.ca_handler.openxpki_ca_handler.DBstore.certificate_lookup')
    def test_048__cert_identifier_get(self, mock_certlookup):
        """ test _cert_identifier_get() """
        self.cahandler.endpoint_name = 'endpoint_name'
        mock_certlookup.return_value = {'poll_identifier' : None}
        self.assertFalse(self.cahandler._cert_identifier_get('certcn'))

    @patch('examples.ca_handler.openxpki_ca_handler.DBstore.certificate_lookup')
    def test_049__cert_identifier_get(self, mock_certlookup):
        """ test _cert_identifier_get() """
        self.cahandler.endpoint_name = 'endpoint_name'
        mock_certlookup.return_value = {'foo' : 'bar'}
        self.assertFalse(self.cahandler._cert_identifier_get('certcn'))

    @patch('examples.ca_handler.openxpki_ca_handler.DBstore.certificate_lookup')
    def test_050__cert_identifier_get(self, mock_certlookup):
        """ test _cert_identifier_get() """
        self.cahandler.endpoint_name = 'endpoint_name'
        mock_certlookup.return_value = {'poll_identifier' : ''}
        self.assertFalse(self.cahandler._cert_identifier_get('certcn'))

    @patch('examples.ca_handler.openxpki_ca_handler.CAhandler._rpc_post')
    def test_051__revoke(self, mock_post):
        """ test _revoke() """
        self.assertEqual((400, 'urn:ietf:params:acme:error:serverInternal', 'Incomplete configuration'), self.cahandler._revoke('cert_identifier', 'rev_reason'))

    @patch('examples.ca_handler.openxpki_ca_handler.CAhandler._rpc_post')
    def test_052__revoke(self, mock_post):
        """ test _revoke() """
        self.cahandler.host = 'host'
        self.cahandler.endpoint_name = 'endpoint_name'
        mock_post.return_value = {'result': {'state': 'failure'}}
        self.assertEqual((400, 'urn:ietf:params:acme:error:serverInternal', 'Revocation failed'), self.cahandler._revoke('cert_identifier', 'rev_reason'))

    @patch('examples.ca_handler.openxpki_ca_handler.CAhandler._rpc_post')
    def test_053__revoke(self, mock_post):
        """ test _revoke() """
        self.cahandler.host = 'host'
        self.cahandler.endpoint_name = 'endpoint_name'
        mock_post.return_value = {'result': {'state': 'success'}}
        self.assertEqual((200, None, None), self.cahandler._revoke('cert_identifier', 'rev_reason'))

    @patch('examples.ca_handler.openxpki_ca_handler.CAhandler._revoke')
    @patch('examples.ca_handler.openxpki_ca_handler.CAhandler._cert_identifier_get')
    def test_054_revoke(self, mock_certid, mock_revoke):
        """  test revoke """
        mock_certid.return_value = None
        self.assertEqual((400, 'urn:ietf:params:acme:error:serverInternal', 'Unknown status'), self.cahandler.revoke('cert', 'reason', 'date'))
        self.assertTrue(mock_certid.called)
        self.assertFalse(mock_revoke.called)

    @patch('examples.ca_handler.openxpki_ca_handler.CAhandler._revoke')
    @patch('examples.ca_handler.openxpki_ca_handler.CAhandler._cert_identifier_get')
    def test_055_revoke(self, mock_certid, mock_revoke):
        """  test revoke """
        mock_certid.return_value = 'cert_identifier'
        mock_revoke.return_value = ('code', 'error', 'detail')
        self.assertEqual(('code', 'error', 'detail'), self.cahandler.revoke('cert', 'reason', 'date'))
        self.assertTrue(mock_certid.called)
        self.assertTrue(mock_revoke.called)

if __name__ == '__main__':

    unittest.main()
