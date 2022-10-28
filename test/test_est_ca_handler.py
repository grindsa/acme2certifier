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
        from examples.ca_handler.est_ca_handler import CAhandler, _get_certificates
        logging.basicConfig(level=logging.CRITICAL)
        self.logger = logging.getLogger('test_a2c')
        self.cahandler = CAhandler(False, self.logger)
        self._get_certificates = _get_certificates
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
        self.assertEqual(20, self.cahandler.request_timeout)

    @patch('examples.ca_handler.est_ca_handler.load_config')
    def test_003_config_load(self, mock_load_cfg):
        """ test _config_load - est host configured """
        mock_load_cfg.return_value = {'CAhandler': {'est_host': 'foo_host'}}
        self.cahandler._config_load()
        self.assertEqual('foo_host/.well-known/est', self.cahandler.est_host)
        self.assertEqual(20, self.cahandler.request_timeout)

    @patch.dict('os.environ', {'est_host_var': 'foo_host'})
    @patch('examples.ca_handler.est_ca_handler.load_config')
    def test_004_config_load(self, mock_load_cfg):
        """ test _config_load - est host configured via environment variable """
        mock_load_cfg.return_value = {'CAhandler': {'est_host_variable': 'est_host_var'}}
        self.cahandler._config_load()
        self.assertEqual('foo_host/.well-known/est', self.cahandler.est_host)
        self.assertEqual(20, self.cahandler.request_timeout)

    @patch.dict('os.environ', {'est_host_var': 'foo_host'})
    @patch('examples.ca_handler.est_ca_handler.load_config')
    def test_005_config_load(self, mock_load_cfg):
        """ test _config_load - est host configured  via not existing environment variable """
        mock_load_cfg.return_value = {'CAhandler': {'est_host_variable': 'does_not_exist'}}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_load()
        self.assertFalse(self.cahandler.est_host)
        self.assertIn("ERROR:test_a2c:CAhandler._config_load() could not load est_host_variable:'does_not_exist'", lcm.output)
        self.assertEqual(20, self.cahandler.request_timeout)

    @patch.dict('os.environ', {'est_host_var': 'foo_host'})
    @patch('examples.ca_handler.est_ca_handler.load_config')
    def test_006_config_load(self, mock_load_cfg):
        """ test _config_load - est host configured as variable and in cfg """
        mock_load_cfg.return_value = {'CAhandler': {'est_host_variable': 'est_host_var', 'est_host': 'foo_host_loc'}}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_load()
        self.assertEqual('foo_host_loc/.well-known/est', self.cahandler.est_host)
        self.assertIn('INFO:test_a2c:CAhandler._config_load() overwrite est_host', lcm.output)
        self.assertEqual(20, self.cahandler.request_timeout)

    @patch('examples.ca_handler.est_ca_handler.load_config')
    def test_007_config_load(self, mock_load_cfg):
        """ test _config_load - no est host configured """
        mock_load_cfg.return_value = {'CAhandler': {'foo': 'bar'}}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_load()
        self.assertIn('ERROR:test_a2c:CAhandler._config_load(): missing "est_host" parameter', lcm.output)
        self.assertEqual(20, self.cahandler.request_timeout)

    @patch('examples.ca_handler.est_ca_handler.load_config')
    def test_008_config_load(self, mock_load_cfg):
        """ test _config_load - client certificate configured but no key """
        mock_load_cfg.return_value = {'CAhandler': {'est_host': 'foo', 'est_client_cert': 'est_client_cert'}}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_load()
        self.assertFalse(self.cahandler.est_client_cert)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load() configuration incomplete: either "est_client_cert or "est_client_key" parameter is missing in config file', lcm.output)
        self.assertEqual(20, self.cahandler.request_timeout)

    @patch('examples.ca_handler.est_ca_handler.load_config')
    def test_009_config_load(self, mock_load_cfg):
        """ test _config_load - client certificate configured but no key """
        mock_load_cfg.return_value = {'CAhandler': {'est_host': 'foo', 'est_client_key': 'est_client_key'}}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_load()
        self.assertFalse(self.cahandler.est_client_cert)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load() configuration incomplete: either "est_client_cert or "est_client_key" parameter is missing in config file', lcm.output)
        self.assertEqual(20, self.cahandler.request_timeout)

    @patch('examples.ca_handler.est_ca_handler.load_config')
    def test_010_config_load(self, mock_load_cfg):
        """ test _config_load - user is configured but no password """
        mock_load_cfg.return_value = {'CAhandler': {'est_host': 'foo', 'est_user': 'est_user'}}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_load()
        self.assertTrue(self.cahandler.est_user)
        self.assertFalse(self.cahandler.est_password)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load() configuration incomplete: either "est_user" or "est_password" parameter is missing in config file', lcm.output)
        self.assertEqual(20, self.cahandler.request_timeout)

    @patch('examples.ca_handler.est_ca_handler.load_config')
    def test_011_config_load(self, mock_load_cfg):
        """ test _config_load - password is configured but no user_name """
        mock_load_cfg.return_value = {'CAhandler': {'est_host': 'foo', 'est_password': 'est_password'}}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_load()
        self.assertFalse(self.cahandler.est_user)
        self.assertTrue(self.cahandler.est_password)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load() configuration incomplete: either "est_user" or "est_password" parameter is missing in config file', lcm.output)
        self.assertEqual(20, self.cahandler.request_timeout)

    @patch('examples.ca_handler.est_ca_handler.load_config')
    def test_012_config_load(self, mock_load_cfg):
        """ test _config_load - username and password are configured """
        mock_load_cfg.return_value = {'CAhandler': {'est_host': 'foo', 'est_user': 'est_user', 'est_password': 'est_password'}}
        self.cahandler._config_load()
        self.assertEqual('est_user', self.cahandler.est_user)
        self.assertEqual('est_password', self.cahandler.est_password)
        self.assertEqual(20, self.cahandler.request_timeout)

    @patch.dict('os.environ', {'est_user_var': 'estuser'})
    @patch('examples.ca_handler.est_ca_handler.load_config')
    def test_013_config_load(self, mock_load_cfg):
        """ test _config_load - load username from variable """
        mock_load_cfg.return_value = {'CAhandler': {'est_user_variable': 'est_user_var'}}
        self.cahandler._config_load()
        self.assertEqual('estuser', self.cahandler.est_user)
        self.assertEqual(20, self.cahandler.request_timeout)

    @patch.dict('os.environ', {'est_pass_var': 'estpass'})
    @patch('examples.ca_handler.est_ca_handler.load_config')
    def test_014_config_load(self, mock_load_cfg):
        """ test _config_load - load password from variable """
        mock_load_cfg.return_value = {'CAhandler': {'est_password_variable': 'est_pass_var'}}
        self.cahandler._config_load()
        self.assertEqual('estpass', self.cahandler.est_password)
        self.assertEqual(20, self.cahandler.request_timeout)

    @patch.dict('os.environ', {'est_user_var': 'estuser'})
    @patch('examples.ca_handler.est_ca_handler.load_config')
    def test_015_config_load(self, mock_load_cfg):
        """ test _config_load - load username from not existing variable """
        mock_load_cfg.return_value = {'CAhandler': {'est_user_variable': 'does_not_exist'}}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_load()
        self.assertFalse(self.cahandler.est_user)
        self.assertIn("ERROR:test_a2c:CAhandler._config_load() could not load est_user_variable:'does_not_exist'", lcm.output)
        self.assertEqual(20, self.cahandler.request_timeout)

    @patch.dict('os.environ', {'est_pass_var': 'estpass'})
    @patch('examples.ca_handler.est_ca_handler.load_config')
    def test_016_config_load(self, mock_load_cfg):
        """ test _config_load - load password from not existing variable """
        mock_load_cfg.return_value = {'CAhandler': {'est_password_variable': 'does_not_exist'}}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_load()
        self.assertFalse(self.cahandler.est_password)
        self.assertIn("ERROR:test_a2c:CAhandler._config_load() could not load est_password:'does_not_exist'", lcm.output)
        self.assertEqual(20, self.cahandler.request_timeout)

    @patch.dict('os.environ', {'est_user_var': 'estuser'})
    @patch('examples.ca_handler.est_ca_handler.load_config')
    def test_017_config_load(self, mock_load_cfg):
        """ test _config_load - load username from variable and cfg """
        mock_load_cfg.return_value = {'CAhandler': {'est_user_variable': 'est_user_var', 'est_user': 'estuser_loc'}}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_load()
        self.assertEqual('estuser_loc', self.cahandler.est_user)
        self.assertIn('INFO:test_a2c:CAhandler._config_load() overwrite est_user', lcm.output)
        self.assertEqual(20, self.cahandler.request_timeout)

    @patch.dict('os.environ', {'est_pass_var': 'estpass'})
    @patch('examples.ca_handler.est_ca_handler.load_config')
    def test_018_config_load(self, mock_load_cfg):
        """ test _config_load - load password from variable """
        mock_load_cfg.return_value = {'CAhandler': {'est_password_variable': 'est_pass_var', 'est_password': 'estpassword_loc'}}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_load()
        self.assertEqual('estpassword_loc', self.cahandler.est_password)
        self.assertIn('INFO:test_a2c:CAhandler._config_load() overwrite est_password', lcm.output)
        self.assertEqual(20, self.cahandler.request_timeout)

    @patch('examples.ca_handler.est_ca_handler.load_config')
    def test_019_config_load(self, mock_load_cfg):
        """ test _config_load - neither client nor user_auth are configured """
        mock_load_cfg.return_value = {'CAhandler': {'est_host': 'foo'}}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_load()
        self.assertFalse(self.cahandler.est_user)
        self.assertFalse(self.cahandler.est_password)
        self.assertFalse(self.cahandler.est_client_cert)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load() configuration incomplete: either user or client authentication must be configured', lcm.output)
        self.assertEqual(20, self.cahandler.request_timeout)

    @patch('examples.ca_handler.est_ca_handler.load_config')
    def test_020_config_load(self, mock_load_cfg):
        """ test _config_load - neither client nor user_auth are configured """
        mock_load_cfg.return_value = {'CAhandler': {'est_host': 'foo', 'est_user': 'est_user', 'est_password': 'est_password', 'est_client_cert': 'est_client_cert', 'est_client_key': 'est_client_key'}}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_load()
        self.assertEqual('est_user', self.cahandler.est_user)
        self.assertEqual('est_password', self.cahandler.est_password)
        self.assertEqual(['est_client_cert', 'est_client_key'], self.cahandler.est_client_cert)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load() configuration wrong: user and client authentication cannot be configured together', lcm.output)
        self.assertEqual(20, self.cahandler.request_timeout)

    @patch('examples.ca_handler.est_ca_handler.load_config')
    def test_021_config_load(self, mock_load_cfg):
        """ test _config_load - ca bundle not configured """
        mock_load_cfg.return_value = {'CAhandler': {'est_host': 'foo', 'est_user': 'est_user', 'est_password': 'est_password'}}
        self.cahandler._config_load()
        self.assertTrue(self.cahandler.ca_bundle)
        self.assertEqual(20, self.cahandler.request_timeout)

    @patch('examples.ca_handler.est_ca_handler.load_config')
    def test_022_config_load(self, mock_load_cfg):
        """ test _config_load - ca bundle True """
        mock_load_cfg.return_value = {'CAhandler': {'est_host': 'foo', 'est_user': 'est_user', 'est_password': 'est_password', 'ca_bundle': True}}
        self.cahandler._config_load()
        self.assertTrue(self.cahandler.ca_bundle)
        self.assertEqual(20, self.cahandler.request_timeout)

    @patch('examples.ca_handler.est_ca_handler.load_config')
    def test_023_config_load(self, mock_load_cfg):
        """ test _config_load - ca bundle False """
        mock_load_cfg.return_value = {'CAhandler': {'est_host': 'foo', 'est_user': 'est_user', 'est_password': 'est_password', 'ca_bundle': False}}
        self.cahandler._config_load()
        self.assertFalse(self.cahandler.ca_bundle)
        self.assertEqual(20, self.cahandler.request_timeout)

    @patch('examples.ca_handler.est_ca_handler.load_config')
    def test_024_config_load(self, mock_load_cfg):
        """ test _config_load - ca bundle string """
        mock_load_cfg.return_value = {'CAhandler': {'est_host': 'foo', 'est_user': 'est_user', 'est_password': 'est_password', 'ca_bundle': 'bar'}}
        self.cahandler._config_load()
        self.assertEqual('bar', self.cahandler.ca_bundle)
        self.assertEqual(20, self.cahandler.request_timeout)

    @patch('examples.ca_handler.est_ca_handler.parse_url')
    @patch('json.loads')
    @patch('examples.ca_handler.est_ca_handler.load_config')
    def test_025_config_load(self, mock_load_cfg, mock_json, mock_url):
        """ test _config_load ca_handler configured load proxies """
        mock_load_cfg.return_value = {'DEFAULT': {'proxy_server_list': 'foo'}}
        mock_url.return_value = {'foo': 'bar'}
        mock_json.return_value = 'foo'
        self.cahandler._config_load()
        self.assertTrue(mock_json.called)
        self.assertTrue(mock_url.called)
        self.assertEqual(20, self.cahandler.request_timeout)

    @patch('examples.ca_handler.est_ca_handler.proxy_check')
    @patch('examples.ca_handler.est_ca_handler.parse_url')
    @patch('json.loads')
    @patch('examples.ca_handler.est_ca_handler.load_config')
    def test_026_config_load(self, mock_load_cfg, mock_json, mock_url, mock_chk):
        """ test _config_load ca_handler configured load proxies """
        mock_load_cfg.return_value = {'DEFAULT': {'proxy_server_list': 'foo'}}
        mock_url.return_value = {'host': 'bar:8888'}
        mock_json.return_value = 'foo.bar.local'
        mock_chk.return_value = 'proxy.bar.local'
        self.cahandler._config_load()
        self.assertTrue(mock_json.called)
        self.assertTrue(mock_url.called)
        self.assertTrue(mock_chk.called)
        self.assertEqual({'http': 'proxy.bar.local', 'https': 'proxy.bar.local'},self.cahandler.proxy )
        self.assertEqual(20, self.cahandler.request_timeout)

    @patch('examples.ca_handler.est_ca_handler.proxy_check')
    @patch('examples.ca_handler.est_ca_handler.parse_url')
    @patch('json.loads')
    @patch('examples.ca_handler.est_ca_handler.load_config')
    def test_027_config_load(self, mock_load_cfg, mock_json, mock_url, mock_chk):
        """ test _config_load ca_handler configured load proxies """
        mock_load_cfg.return_value = {'DEFAULT': {'proxy_server_list': 'foo'}}
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
        self.assertEqual(20, self.cahandler.request_timeout)

    @patch('examples.ca_handler.est_ca_handler.load_config')
    def test_028_config_load(self, mock_load_cfg):
        """ test _config_load - neither client nor user_auth are configured """
        mock_load_cfg.return_value = {'CAhandler': {'request_timeout': 10}}
        self.cahandler._config_load()
        self.assertEqual(10, self.cahandler.request_timeout)

    @patch('examples.ca_handler.est_ca_handler.load_config')
    def test_029_config_load(self, mock_load_cfg):
        """ test _config_load - neither client nor user_auth are configured """
        mock_load_cfg.return_value = {'CAhandler': {'request_timeout': 'foo'}}
        self.cahandler._config_load()
        self.assertEqual(20, self.cahandler.request_timeout)

    def test_028_revoke(self):
        """ test revocation """
        self.assertEqual((500, 'urn:ietf:params:acme:error:serverInternal', 'Revocation is not supported.'), self.cahandler.revoke('cert', 'rev_reason', 'rev_date'))

    def test_029_poll(self):
        """ test polling """
        self.assertEqual(('Method not implemented.', None, None, 'poll_identifier', False), self.cahandler.poll('cert_name', 'poll_identifier', 'csr'))

    def test_030_trigger(self):
        """ test polling """
        self.assertEqual(('Method not implemented.', None, None), self.cahandler.trigger('payload'))

    @patch('examples.ca_handler.est_ca_handler.b64_decode')
    @patch('examples.ca_handler.est_ca_handler.CAhandler._pkcs7_to_pem')
    @patch.object(requests, 'get')
    def test_031__cacerts_get(self, mock_req, mock_to_pem, _mock_b64):
        """ test _cacerts_get() successful run by using client certs """
        mockresponse = Mock()
        mock_req.return_value = mockresponse
        mockresponse.text = 'mock return'
        mock_to_pem.return_value = 'pem'
        self.cahandler.est_host = 'foo'
        self.cahandler.ca_bundle = ['foo_bundle']
        self.cahandler.est_client_cert = 'est_client_cert'
        self.assertEqual((None, 'pem'), self.cahandler._cacerts_get())

    @patch('examples.ca_handler.est_ca_handler.b64_decode')
    @patch('examples.ca_handler.est_ca_handler.CAhandler._pkcs7_to_pem')
    @patch.object(requests, 'get')
    def test_032__cacerts_get(self, mock_req, mock_to_pem, _mock_b64):
        """ test _cacerts_get() successful run by using client certs """
        mockresponse = Mock()
        mock_req.return_value = mockresponse
        mockresponse.text = 'mock return'
        mock_to_pem.return_value = 'pem'
        self.cahandler.est_host = 'foo'
        self.cahandler.ca_bundle = ['foo_bundle']
        self.cahandler.est_user = 'est_user'
        self.cahandler.est_password = 'est_password'
        self.assertEqual((None, 'pem'), self.cahandler._cacerts_get())

    @patch('examples.ca_handler.est_ca_handler.b64_decode')
    @patch('examples.ca_handler.est_ca_handler.CAhandler._pkcs7_to_pem')
    @patch.object(requests, 'get')
    def test_033__cacerts_get(self, mock_req, mock_to_pem, _mock_b64):
        """ test _cacerts_get() no est_host parameter """
        mockresponse = Mock()
        mock_req.return_value = mockresponse
        mockresponse.text = 'mock return'
        mock_to_pem.return_value = 'pem'
        self.cahandler.ca_bundle = ['foo_bundle']
        self.cahandler.est_client_cert = 'est_client_cert'
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual((None, None), self.cahandler._cacerts_get())
        self.assertIn('ERROR:test_a2c:CAhandler._cacerts_get() configuration incomplete: "est_host" parameter is missing', lcm.output)

    @patch('examples.ca_handler.est_ca_handler.b64_decode')
    @patch('examples.ca_handler.est_ca_handler.CAhandler._pkcs7_to_pem')
    @patch('requests.get')
    def test_034__cacerts_get(self, mock_req, mock_to_pem, _mock_b64):
        """ test _cacerts_get() request.get triggers exception """
        mock_req.side_effect = Exception('exc_cacerts_get')
        mock_to_pem.return_value = 'pem'
        self.cahandler.est_host = 'foo'
        self.cahandler.ca_bundle = ['foo_bundle']
        self.cahandler.est_client_cert = 'est_client_cert'
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._cacerts_get()
        self.assertIn('ERROR:test_a2c:CAhandler._cacerts_get() returned an error: exc_cacerts_get', lcm.output)

    @patch('examples.ca_handler.est_ca_handler.b64_decode')
    @patch('examples.ca_handler.est_ca_handler.CAhandler._pkcs7_to_pem')
    @patch.object(requests, 'post')
    def test_035__simpleenroll(self, mock_req, mock_to_pem, _mock_b64):
        """ test _cacerts_get() successful run """
        mockresponse = Mock()
        mock_req.return_value = mockresponse
        mockresponse.text = 'mock return'
        mock_to_pem.return_value = 'pem'
        self.cahandler.est_host = 'foo'
        self.cahandler.ca_bundle = ['foo_bundle']
        self.cahandler.est_client_cert = 'est_client_cert'
        self.assertEqual((None, 'pem'), self.cahandler._simpleenroll('csr'))

    @patch('examples.ca_handler.est_ca_handler.b64_decode')
    @patch('examples.ca_handler.est_ca_handler.CAhandler._pkcs7_to_pem')
    @patch('requests.post')
    def test_036__simpleenroll(self, mock_req, mock_to_pem, _mock_b64):
        """ test _cacerts_get() successful run """
        mock_req.side_effect = Exception('exc_simple_enroll')
        mock_to_pem.return_value = 'pem'
        self.cahandler.est_host = 'foo'
        self.cahandler.ca_bundle = ['foo_bundle']
        self.cahandler.est_client_cert = 'est_client_cert'
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual(('exc_simple_enroll', None), self.cahandler._simpleenroll('csr'))
        self.assertIn('ERROR:test_a2c:CAhandler._simpleenroll() returned an error: exc_simple_enroll', lcm.output)

    @patch('examples.ca_handler.est_ca_handler.b64_decode')
    @patch('examples.ca_handler.est_ca_handler.CAhandler._pkcs7_to_pem')
    @patch('requests.post')
    def test_037__simpleenroll(self, mock_req, mock_to_pem, _mock_b64):
        """ test _cacerts_get() successful run """
        mock_req.side_effect = Exception('exc_simple_enroll')
        mock_to_pem.return_value = 'pem'
        self.cahandler.est_host = 'foo'
        self.cahandler.ca_bundle = ['foo_bundle']
        self.cahandler.est_user = 'est_user'
        self.cahandler.est_password = 'est_password'
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual(('exc_simple_enroll', None), self.cahandler._simpleenroll('csr'))
        self.assertIn('ERROR:test_a2c:CAhandler._simpleenroll() returned an error: exc_simple_enroll', lcm.output)

    @patch('examples.ca_handler.est_ca_handler.CAhandler._cacerts_get')
    def test_038_enroll(self, mock_ca):
        """ test certificate enrollment _cacert_get returns error """
        mock_ca.return_value = ('Error', None)
        self.cahandler.est_host = 'foo'
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual(('Error', None, None, None), self.cahandler.enroll('csr'))
        self.assertIn('ERROR:test_a2c:CAhandler.enroll() _cacerts_get error: Error', lcm.output)

    @patch('examples.ca_handler.est_ca_handler.CAhandler._cacerts_get')
    def test_039_enroll(self, mock_ca):
        """ test certificate enrollment no error but now ca_certs """
        mock_ca.return_value = (None, None)
        self.cahandler.est_host = 'foo'
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual(('no CA certificates found', None, None, None), self.cahandler.enroll('csr'))
        self.assertIn('ERROR:test_a2c:CAhandler.enroll(): no CA certificates found', lcm.output)

    @patch('examples.ca_handler.est_ca_handler.CAhandler._cacerts_get')
    def test_040_enroll(self, mock_ca):
        """ test certificate enrollment authentication information are missing """
        mock_ca.return_value = (None, 'ca_pem')
        self.cahandler.est_host = 'foo'
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual(('Authentication information missing', None, None, None), self.cahandler.enroll('csr'))
        self.assertIn('ERROR:test_a2c:CAhandler.enroll(): Authentication information missing.', lcm.output)

    @patch('examples.ca_handler.est_ca_handler.CAhandler._simpleenroll')
    @patch('examples.ca_handler.est_ca_handler.CAhandler._cacerts_get')
    def test_041_enroll(self, mock_ca, mock_enroll):
        """ test certificate enrollment _simpleenroll returns error """
        mock_ca.return_value = (None, 'ca_pem')
        mock_enroll.return_value = ('Error', None)
        self.cahandler.est_host = 'foo'
        self.cahandler.est_user = 'est_usr'
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual(('Error', None, None, None), self.cahandler.enroll('csr'))
        self.assertIn('ERROR:test_a2c:CAhandler.enroll() _simpleenroll error: Error', lcm.output)

    @patch('examples.ca_handler.est_ca_handler.CAhandler._simpleenroll')
    @patch('examples.ca_handler.est_ca_handler.CAhandler._cacerts_get')
    def test_042_enroll(self, mock_ca, mock_enroll):
        """ test certificate enrollment _simpleenroll returns certificate """
        mock_ca.return_value = (None, 'ca_pem')
        mock_enroll.return_value = (None, 'cert')
        self.cahandler.est_host = 'foo'
        self.cahandler.est_user = 'est_usr'
        self.assertEqual((None, 'certca_pem', 'cert', None), self.cahandler.enroll('csr'))

    @patch('examples.ca_handler.est_ca_handler.CAhandler._simpleenroll')
    @patch('examples.ca_handler.est_ca_handler.CAhandler._cacerts_get')
    def test_043_enroll(self, mock_ca, mock_enroll):
        """ test certificate enrollment replace CERT BEGIN """
        mock_ca.return_value = (None, 'ca_pem')
        mock_enroll.return_value = (None, '-----BEGIN CERTIFICATE-----\ncert')
        self.cahandler.est_host = 'foo'
        self.cahandler.est_user = 'est_usr'
        self.assertEqual((None, '-----BEGIN CERTIFICATE-----\ncertca_pem', 'cert', None), self.cahandler.enroll('csr'))

    @patch('examples.ca_handler.est_ca_handler.CAhandler._simpleenroll')
    @patch('examples.ca_handler.est_ca_handler.CAhandler._cacerts_get')
    def test_044_enroll(self, mock_ca, mock_enroll):
        """ test certificate enrollment replace CERT END """
        mock_ca.return_value = (None, 'ca_pem')
        mock_enroll.return_value = (None, 'cert-----END CERTIFICATE-----\n')
        self.cahandler.est_host = 'foo'
        self.cahandler.est_user = 'est_usr'
        self.assertEqual((None, 'cert-----END CERTIFICATE-----\nca_pem', 'cert', None), self.cahandler.enroll('csr'))

    @patch('examples.ca_handler.est_ca_handler.CAhandler._simpleenroll')
    @patch('examples.ca_handler.est_ca_handler.CAhandler._cacerts_get')
    def test_045_enroll(self, mock_ca, mock_enroll):
        """ test certificate enrollment replace CERT BEGIN AND END """
        mock_ca.return_value = (None, 'ca_pem')
        mock_enroll.return_value = (None, '-----BEGIN CERTIFICATE-----\ncert-----END CERTIFICATE-----\n')
        self.cahandler.est_host = 'foo'
        self.cahandler.est_user = 'est_usr'
        self.assertEqual((None, '-----BEGIN CERTIFICATE-----\ncert-----END CERTIFICATE-----\nca_pem', 'cert', None), self.cahandler.enroll('csr'))

    @patch('examples.ca_handler.est_ca_handler.CAhandler._simpleenroll')
    @patch('examples.ca_handler.est_ca_handler.CAhandler._cacerts_get')
    def test_046_enroll(self, mock_ca, mock_enroll):
        """ test certificate enrollment replace CERT BEGIN AND END and \n"""
        mock_ca.return_value = (None, 'ca_pem')
        mock_enroll.return_value = (None, '-----BEGIN CERTIFICATE-----\ncert\n-----END CERTIFICATE-----\n\n')
        self.cahandler.est_host = 'foo'
        self.cahandler.est_user = 'est_usr'
        self.assertEqual((None, '-----BEGIN CERTIFICATE-----\ncert\n-----END CERTIFICATE-----\n\nca_pem', 'cert', None), self.cahandler.enroll('csr'))

    @patch('examples.ca_handler.est_ca_handler.CAhandler._config_load')
    def test_047__enter__(self, mock_cfg):
        """ test enter  called """
        mock_cfg.return_value = True
        self.cahandler.__enter__()
        self.assertTrue(mock_cfg.called)

    @patch('examples.ca_handler.est_ca_handler.CAhandler._config_load')
    def test_048__enter__(self, mock_cfg):
        """ test enter api hosts defined """
        mock_cfg.return_value = True
        self.cahandler.est_host = 'api_host'
        self.cahandler.__enter__()
        self.assertFalse(mock_cfg.called)

    def test_049_get_certificates(self):
        """ test pkcs7 convrt to pem """
        cert_pem_list = []
        with open(self.dir_path + '/ca/certs.p7b', 'r') as fso:
            pkcs7 = crypto.load_pkcs7_data(crypto.FILETYPE_PEM, fso.read())
            cert_list = self._get_certificates(pkcs7)

            for cert in cert_list:
                cert_pem_list.append(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
        result = [b'-----BEGIN CERTIFICATE-----\nMIIFTzCCAzegAwIBAgIIAzHyhSyrXfMwDQYJKoZIhvcNAQELBQAwKzEXMBUGA1UE\nCxMOYWNtZTJjZXJ0aWZpZXIxEDAOBgNVBAMTB3Jvb3QtY2EwHhcNMjAwNTI3MTM1\nNDAwWhcNMzAwNTI2MjM1OTAwWjAqMRcwFQYDVQQLEw5hY21lMmNlcnRpZmllcjEP\nMA0GA1UEAxMGc3ViLWNhMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA\nxXHaGZsolXe+PBdUryngHP9VbBC1mehqeTtYI+hqsqGNH7q9a7bSrxMwFuF1kYL8\njqqxkJdtl0L94xcxJg/ZdMx7Nt0vGI+BaAuTpEpUEHeN4tqS6NhB/m/0LGkAELc/\nqkzmoO4B1FDwEEj/3IXtZcupqG80oDt7jWSGXdtF7NTjzcumznMeRXidCdhxRxT/\n/WrsChaytXo0xWZ56oeNwd6x6Dr8/39PBOWtj4fldyDcg+Q+alci2tx9pxmu2bCV\nXcB9ftCLKhDk2WEHE88bgKSp7fV2RCmq9po+Tx8JJ7qecLunUsK/F0XN4kpoQLm9\nhcymqchnMSncSiyin1dQHGHWgXDtBDdq6A2Z6rx26Qk5H9HTYvcNSe1YwFEDoGLB\nZQjbCPWiaqoaH4agBQTclPvrrSCRaVmhUSO+pBtSXDkmN4t3MDZxfgRkp8ixwkB1\n5Y5f0LTpCyAJsdQDw8+Ea0aDqO30eskh4CErnm9+Fejd9Ew2cwpdwfBXzVSbYilM\nGueQihZHvJmVRxAwU69aO2Qs8B0tQ60CfWKVlmWPiakrvYYlPp0FBsM61G6LZEN8\nhH2CKnS8hHv5IWEXZvp0Pk8V3P5h6bWN0Tl+x/V1Prt7Wp8NoiPETE8XyDDxe6dm\nKxztWBH/mTsJyMGb6ZiUoXdPU9TFUKqHxTRLHaxfsPsCAwEAAaN4MHYwEgYDVR0T\nAQH/BAgwBgEB/wIBATAdBgNVHQ4EFgQUv96OjgYiIqutQ8jd1E+oq0hBPtUwDgYD\nVR0PAQH/BAQDAgGGMBEGCWCGSAGG+EIBAQQEAwIABzAeBglghkgBhvhCAQ0EERYP\neGNhIGNlcnRpZmljYXRlMA0GCSqGSIb3DQEBCwUAA4ICAQBbHLEVyg4f9uEujroc\n31UVyDRLMdPgEPLjOenSBCBmH0N81whDmxNI/7JAAB6J14WMX8OLF0HkZnb7G77W\nvDhy1aFvQFbXHBz3/zUO9Mw9J4L2XEW6ond3Nsh1m2oXeBde3R3ANxuIzHqZDlP9\n6YrRcHjnf4+1/5AKDJAvJD+gFb5YnYUKH2iSvHUvG17xcZx98Rf2eo8LealG4JqH\nJh4sKRy0VjDQD7jXSCbweTHEb8wz+6OfNGrIo+BhTFP5vPcwE4nlJwYBoaOJ5cVa\n7gdQJ7WkLSxvwHxuxzvSVK73u3jl3I9SqTrbMLG/jeJyV0P8EvdljOaGnCtQVRwC\nzM4ptXUvKhKOHy7/nyTF/Bc35ZwwL/2xWvNK1+NibgE/6CFxupwWpdmxQbVVuoQ3\n2tUil9ty0yC6m5GKE8+t1lrZuxyA+b/TBnYNO5xo8UEMbkpxaNYSwmw+f/loxXP/\nM7sIBcLvy2ugHEBxwd9o/kLXeXT2DaRvxPjp4yk8MpJRpNmz3aB5HJwaUnaRLVo5\nZ3XWWXmjMGZ6/m0AAoDbDz/pXtOoJZT8BJdD1DuDdszVsQnLVn4B/LtIXL6FbXsF\nzfv6ERP9a5gpKUZ+4NjgrnlGtdccNZpwyWF0IXcvaq3b8hXIRO4hMjzHeHfzJN4t\njX1vlY35Ofonc4+6dRVamBiF9A==\n-----END CERTIFICATE-----\n', b'-----BEGIN CERTIFICATE-----\nMIIFcDCCA1igAwIBAgIIevLTTxOMoZgwDQYJKoZIhvcNAQELBQAwKzEXMBUGA1UE\nCxMOYWNtZTJjZXJ0aWZpZXIxEDAOBgNVBAMTB3Jvb3QtY2EwHhcNMjAwNTI3MDAw\nMDAwWhcNMzAwNTI2MjM1OTU5WjArMRcwFQYDVQQLEw5hY21lMmNlcnRpZmllcjEQ\nMA4GA1UEAxMHcm9vdC1jYTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIB\nAJy4UZHdZgYt64k/rFamoC676tYvtabeuiqVw1c6oVZI897cFLG6BYwyr2Eaj7tF\nrqTJDeMN4vZSudLsmLDq6m8KwX/riPzUTIlcjM5aIMANZr9rLEs3NWtcivolB5aQ\n1slhdVitUPLuxsFnYeQTyxFyP7lng9M/Z403KLG8phdmKjM0vJkaj4OuKOXf3UsW\nqWQYyRl/ms07xVj02uq08LkoeO+jtQisvyVXURdaCceZtyK/ZBQ7NFCsbK112cVR\n1e2aJol7NJAA6Wm6iBzAdkAA2l3kh40SLoEbaiaVMixLN2vilIZOOAoDXX4+T6ir\n+KnDVSJ2yu5c/OJMwuXwHrh7Lgg1vsFR5TNehknhjUuWOUO+0TkKPg2A7KTg72OZ\n2mOcLZIbxzr1P5RRvdmLQLPrTF2EJvpQPNmbXqN3ZVWEvfHTjkkTFY/dsOTvFTgS\nri15zYKch8votcU7z+BQhgmMtwO2JhPMmZ6ABd9skI7ijWpwOltAhxtdoBO6T6CB\nCrE2yXc6V/PyyAKcFglNmIght5oXsnE+ub/dtx8f9Iea/xNPdo5aGy8fdaitolDK\n16kd3Kb7OE4HMHIwOxxF1BEAqerxxhbLMRBr8hRSZI5cvLzWLvpAQ5zuhjD6V3b9\nBYFd4ujAu3zl3mbzdbYjFoGOX6aBZaGDxlc4O2W7HxntAgMBAAGjgZcwgZQwDwYD\nVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUDGVvuTFYZtEAkz3af9wRKDDvAswwHwYD\nVR0jBBgwFoAUDGVvuTFYZtEAkz3af9wRKDDvAswwDgYDVR0PAQH/BAQDAgGGMBEG\nCWCGSAGG+EIBAQQEAwIABzAeBglghkgBhvhCAQ0EERYPeGNhIGNlcnRpZmljYXRl\nMA0GCSqGSIb3DQEBCwUAA4ICAQAjko7dX+iCgT+m3Iy1Vg6j7MRevPAzq1lqHRRN\nNdt2ct530pIut7Fv5V2xYk35ka+i/G+XyOvTXa9vAUKiBtiRnUPsXu4UcS7CcrCX\nEzHx4eOtHnp5wDhO0Fx5/OUZTaP+L7Pd1GD/j953ibx5bMa/M9Rj+S486nst57tu\nDRmEAavFDiMd6L3jH4YSckjmIH2uSeDIaRa9k6ag077XmWhvVYQ9tuR7RGbSuuV3\nFc6pqcFbbWpoLhNRcFc+hbUKOsKl2cP+QEKP/H2s3WMllqgAKKZeO+1KOsGo1CDs\n475bIXyCBpFbH2HOPatmu3yZRQ9fj9ta9EW46n33DFRNLinFWa4WJs4yLVP1juge\n2TCOyA1t61iy++RRXSG3e7NFYrEZuCht1EdDAdzIUY89m9NCPwoDYS4CahgnfkkO\n7YQe6f6yqK6isyf8ZFcp1uF58eERDiF/FDqS8nLmCdURuI56DDoNvDpig5J/9RNW\nG8vEvt2p7QrjeZ3EAatx5JuYty/NKTHZwJWk51CgzEgzDwzE2JIiqeldtL5d0Sl6\neVuv0G04BEyuXxEWpgVVzBS4qEFIBSnTJzgu1PXmId3yLvg2Nr8NKvwyZmN5xKFp\n0A9BWo15zW1PXDaD+l39oTYD7agjXkzTAjYIcfNJ7ATIYFD0xAvNAOf70s7aNupF\nfvkG2Q==\n-----END CERTIFICATE-----\n']
        self.assertEqual(result, cert_pem_list)

    @patch('OpenSSL.crypto._lib.sk_X509_num')
    def test_050_get_certificates(self, mock_num):
        """ test get_certificates to cover cornercases """
        mock_num.return_value = 0
        input = Mock()
        input.type_is_signed = Mock(return_value=None)
        self.assertFalse(self._get_certificates(input))

    def test_051__pkcs7_to_pem(self):
        """ test pkcs7 to pem default output """
        with open(self.dir_path + '/ca/certs.p7b', 'r') as fso:
            file_content = fso.read()
        with open(self.dir_path + '/ca/certs.pem', 'r') as fso:
            result = fso.read()
        self.assertEqual(result, self.cahandler._pkcs7_to_pem(file_content))

    def test_052__pkcs7_to_pem(self):
        """ test pkcs7 to pem output string """
        with open(self.dir_path + '/ca/certs.p7b', 'r') as fso:
            file_content = fso.read()
        with open(self.dir_path + '/ca/certs.pem', 'r') as fso:
            result = fso.read()
        self.assertEqual(result, self.cahandler._pkcs7_to_pem(file_content, 'string'))

    def test_053__pkcs7_to_pem(self):
        """ test pkcs7 to pem output list """
        with open(self.dir_path + '/ca/certs.p7b', 'r') as fso:
            file_content = fso.read()
        result = ['-----BEGIN CERTIFICATE-----\nMIIFTzCCAzegAwIBAgIIAzHyhSyrXfMwDQYJKoZIhvcNAQELBQAwKzEXMBUGA1UE\nCxMOYWNtZTJjZXJ0aWZpZXIxEDAOBgNVBAMTB3Jvb3QtY2EwHhcNMjAwNTI3MTM1\nNDAwWhcNMzAwNTI2MjM1OTAwWjAqMRcwFQYDVQQLEw5hY21lMmNlcnRpZmllcjEP\nMA0GA1UEAxMGc3ViLWNhMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA\nxXHaGZsolXe+PBdUryngHP9VbBC1mehqeTtYI+hqsqGNH7q9a7bSrxMwFuF1kYL8\njqqxkJdtl0L94xcxJg/ZdMx7Nt0vGI+BaAuTpEpUEHeN4tqS6NhB/m/0LGkAELc/\nqkzmoO4B1FDwEEj/3IXtZcupqG80oDt7jWSGXdtF7NTjzcumznMeRXidCdhxRxT/\n/WrsChaytXo0xWZ56oeNwd6x6Dr8/39PBOWtj4fldyDcg+Q+alci2tx9pxmu2bCV\nXcB9ftCLKhDk2WEHE88bgKSp7fV2RCmq9po+Tx8JJ7qecLunUsK/F0XN4kpoQLm9\nhcymqchnMSncSiyin1dQHGHWgXDtBDdq6A2Z6rx26Qk5H9HTYvcNSe1YwFEDoGLB\nZQjbCPWiaqoaH4agBQTclPvrrSCRaVmhUSO+pBtSXDkmN4t3MDZxfgRkp8ixwkB1\n5Y5f0LTpCyAJsdQDw8+Ea0aDqO30eskh4CErnm9+Fejd9Ew2cwpdwfBXzVSbYilM\nGueQihZHvJmVRxAwU69aO2Qs8B0tQ60CfWKVlmWPiakrvYYlPp0FBsM61G6LZEN8\nhH2CKnS8hHv5IWEXZvp0Pk8V3P5h6bWN0Tl+x/V1Prt7Wp8NoiPETE8XyDDxe6dm\nKxztWBH/mTsJyMGb6ZiUoXdPU9TFUKqHxTRLHaxfsPsCAwEAAaN4MHYwEgYDVR0T\nAQH/BAgwBgEB/wIBATAdBgNVHQ4EFgQUv96OjgYiIqutQ8jd1E+oq0hBPtUwDgYD\nVR0PAQH/BAQDAgGGMBEGCWCGSAGG+EIBAQQEAwIABzAeBglghkgBhvhCAQ0EERYP\neGNhIGNlcnRpZmljYXRlMA0GCSqGSIb3DQEBCwUAA4ICAQBbHLEVyg4f9uEujroc\n31UVyDRLMdPgEPLjOenSBCBmH0N81whDmxNI/7JAAB6J14WMX8OLF0HkZnb7G77W\nvDhy1aFvQFbXHBz3/zUO9Mw9J4L2XEW6ond3Nsh1m2oXeBde3R3ANxuIzHqZDlP9\n6YrRcHjnf4+1/5AKDJAvJD+gFb5YnYUKH2iSvHUvG17xcZx98Rf2eo8LealG4JqH\nJh4sKRy0VjDQD7jXSCbweTHEb8wz+6OfNGrIo+BhTFP5vPcwE4nlJwYBoaOJ5cVa\n7gdQJ7WkLSxvwHxuxzvSVK73u3jl3I9SqTrbMLG/jeJyV0P8EvdljOaGnCtQVRwC\nzM4ptXUvKhKOHy7/nyTF/Bc35ZwwL/2xWvNK1+NibgE/6CFxupwWpdmxQbVVuoQ3\n2tUil9ty0yC6m5GKE8+t1lrZuxyA+b/TBnYNO5xo8UEMbkpxaNYSwmw+f/loxXP/\nM7sIBcLvy2ugHEBxwd9o/kLXeXT2DaRvxPjp4yk8MpJRpNmz3aB5HJwaUnaRLVo5\nZ3XWWXmjMGZ6/m0AAoDbDz/pXtOoJZT8BJdD1DuDdszVsQnLVn4B/LtIXL6FbXsF\nzfv6ERP9a5gpKUZ+4NjgrnlGtdccNZpwyWF0IXcvaq3b8hXIRO4hMjzHeHfzJN4t\njX1vlY35Ofonc4+6dRVamBiF9A==\n-----END CERTIFICATE-----\n', '-----BEGIN CERTIFICATE-----\nMIIFcDCCA1igAwIBAgIIevLTTxOMoZgwDQYJKoZIhvcNAQELBQAwKzEXMBUGA1UE\nCxMOYWNtZTJjZXJ0aWZpZXIxEDAOBgNVBAMTB3Jvb3QtY2EwHhcNMjAwNTI3MDAw\nMDAwWhcNMzAwNTI2MjM1OTU5WjArMRcwFQYDVQQLEw5hY21lMmNlcnRpZmllcjEQ\nMA4GA1UEAxMHcm9vdC1jYTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIB\nAJy4UZHdZgYt64k/rFamoC676tYvtabeuiqVw1c6oVZI897cFLG6BYwyr2Eaj7tF\nrqTJDeMN4vZSudLsmLDq6m8KwX/riPzUTIlcjM5aIMANZr9rLEs3NWtcivolB5aQ\n1slhdVitUPLuxsFnYeQTyxFyP7lng9M/Z403KLG8phdmKjM0vJkaj4OuKOXf3UsW\nqWQYyRl/ms07xVj02uq08LkoeO+jtQisvyVXURdaCceZtyK/ZBQ7NFCsbK112cVR\n1e2aJol7NJAA6Wm6iBzAdkAA2l3kh40SLoEbaiaVMixLN2vilIZOOAoDXX4+T6ir\n+KnDVSJ2yu5c/OJMwuXwHrh7Lgg1vsFR5TNehknhjUuWOUO+0TkKPg2A7KTg72OZ\n2mOcLZIbxzr1P5RRvdmLQLPrTF2EJvpQPNmbXqN3ZVWEvfHTjkkTFY/dsOTvFTgS\nri15zYKch8votcU7z+BQhgmMtwO2JhPMmZ6ABd9skI7ijWpwOltAhxtdoBO6T6CB\nCrE2yXc6V/PyyAKcFglNmIght5oXsnE+ub/dtx8f9Iea/xNPdo5aGy8fdaitolDK\n16kd3Kb7OE4HMHIwOxxF1BEAqerxxhbLMRBr8hRSZI5cvLzWLvpAQ5zuhjD6V3b9\nBYFd4ujAu3zl3mbzdbYjFoGOX6aBZaGDxlc4O2W7HxntAgMBAAGjgZcwgZQwDwYD\nVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUDGVvuTFYZtEAkz3af9wRKDDvAswwHwYD\nVR0jBBgwFoAUDGVvuTFYZtEAkz3af9wRKDDvAswwDgYDVR0PAQH/BAQDAgGGMBEG\nCWCGSAGG+EIBAQQEAwIABzAeBglghkgBhvhCAQ0EERYPeGNhIGNlcnRpZmljYXRl\nMA0GCSqGSIb3DQEBCwUAA4ICAQAjko7dX+iCgT+m3Iy1Vg6j7MRevPAzq1lqHRRN\nNdt2ct530pIut7Fv5V2xYk35ka+i/G+XyOvTXa9vAUKiBtiRnUPsXu4UcS7CcrCX\nEzHx4eOtHnp5wDhO0Fx5/OUZTaP+L7Pd1GD/j953ibx5bMa/M9Rj+S486nst57tu\nDRmEAavFDiMd6L3jH4YSckjmIH2uSeDIaRa9k6ag077XmWhvVYQ9tuR7RGbSuuV3\nFc6pqcFbbWpoLhNRcFc+hbUKOsKl2cP+QEKP/H2s3WMllqgAKKZeO+1KOsGo1CDs\n475bIXyCBpFbH2HOPatmu3yZRQ9fj9ta9EW46n33DFRNLinFWa4WJs4yLVP1juge\n2TCOyA1t61iy++RRXSG3e7NFYrEZuCht1EdDAdzIUY89m9NCPwoDYS4CahgnfkkO\n7YQe6f6yqK6isyf8ZFcp1uF58eERDiF/FDqS8nLmCdURuI56DDoNvDpig5J/9RNW\nG8vEvt2p7QrjeZ3EAatx5JuYty/NKTHZwJWk51CgzEgzDwzE2JIiqeldtL5d0Sl6\neVuv0G04BEyuXxEWpgVVzBS4qEFIBSnTJzgu1PXmId3yLvg2Nr8NKvwyZmN5xKFp\n0A9BWo15zW1PXDaD+l39oTYD7agjXkzTAjYIcfNJ7ATIYFD0xAvNAOf70s7aNupF\nfvkG2Q==\n-----END CERTIFICATE-----\n']
        self.assertEqual(result, self.cahandler._pkcs7_to_pem(file_content, 'list'))

    def test_054__pkcs7_to_pem(self):
        """ test pkcs7 to pem output list """
        with open(self.dir_path + '/ca/certs.p7b', 'r') as fso:
            file_content = fso.read()
        result = None
        self.assertEqual(result, self.cahandler._pkcs7_to_pem(file_content, 'unknown'))

    @patch('OpenSSL.crypto.load_pkcs7_data')
    def test_055__pkcs7_to_pem(self, mock_load):
        """ test pkcs7 to pem output list """
        with open(self.dir_path + '/ca/certs.p7b', 'r') as fso:
            file_content = fso.read()
        # mock_load.side_effects = Exception('exc_load_pkcs7')
        mock_load.return_value = None
        result = None
        self.assertEqual(result, self.cahandler._pkcs7_to_pem(file_content, 'unknown'))

    @patch('OpenSSL.crypto')
    def test_056__pkcs7_to_pem(self, mock_load):
        """ test pkcs7 to pem output list """
        with open(self.dir_path + '/ca/certs.p7b', 'r') as fso:
            file_content = fso.read()
        response = Mock()
        response.load_pkcs7_data = Exception('exc_load_pkcs7')
        mock_load.return_value = response
        result = None
        self.assertEqual(result, self.cahandler._pkcs7_to_pem(file_content, 'unknown'))

    @patch('OpenSSL.crypto.load_pkcs7_data')
    def test_057__pkcs7_to_pem(self, mock_load):
        """ test pkcs7 to pem exceptin """
        with open(self.dir_path + '/ca/certs.p7b', 'r') as fso:
            file_content = fso.read()
        mock_load.side_effect = Exception('foo')
        result = None
        self.assertEqual(result, self.cahandler._pkcs7_to_pem(file_content, 'unknown'))


if __name__ == '__main__':

    unittest.main()
