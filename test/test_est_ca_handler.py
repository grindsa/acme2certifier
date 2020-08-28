#!/usr/bin/python
# -*- coding: utf-8 -*-
""" unittests for openssl_ca_handler """
# pylint: disable=C0415, R0904, W0212
import sys
import os
import unittest
from unittest.mock import patch, Mock
import requests

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
        mock_load_cfg.return_value = {'CAhandler': {'est_host': 'foo', 'est_user': 'est_user', 'est_password': 'est_password', 'est_client_cert': 'est_client_cert', 'est_client_key': 'est_client_key'}}
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

    def test_016_revoke(self):
        """ test revocation """
        self.assertEqual((500, 'urn:ietf:params:acme:error:serverInternal', 'Revocation is not supported.'), self.cahandler.revoke('cert', 'rev_reason', 'rev_date'))

    def test_017_poll(self):
        """ test polling """
        self.assertEqual(('Method not implemented.', None, None, 'poll_identifier', False), self.cahandler.poll('cert_name', 'poll_identifier', 'csr'))

    def test_018_trigger(self):
        """ test polling """
        self.assertEqual(('Method not implemented.', None, None), self.cahandler.trigger('payload'))

    @patch('examples.ca_handler.est_ca_handler.b64_decode')
    @patch('examples.ca_handler.est_ca_handler.CAhandler._pkcs7_to_pem')
    @patch.object(requests, 'get')
    def test_019__cacerts_get(self, mock_req, mock_to_pem, _mock_b64):
        """ test _cacerts_get() successful run """
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
    def test_020__cacerts_get(self, mock_req, mock_to_pem, _mock_b64):
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
    def test_021__cacerts_get(self, mock_req, mock_to_pem, _mock_b64):
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
    def test_022__simpleenroll(self, mock_req, mock_to_pem, _mock_b64):
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
    def test_023__simpleenroll(self, mock_req, mock_to_pem, _mock_b64):
        """ test _cacerts_get() successful run """
        mock_req.side_effect = Exception('exc_simple_enroll')
        mock_to_pem.return_value = 'pem'
        self.cahandler.est_host = 'foo'
        self.cahandler.ca_bundle = ['foo_bundle']
        self.cahandler.est_client_cert = 'est_client_cert'
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual(('exc_simple_enroll', None), self.cahandler._simpleenroll('csr'))
        self.assertIn('ERROR:test_a2c:CAhandler._simpleenroll() returned an error: exc_simple_enroll', lcm.output)

    @patch('examples.ca_handler.est_ca_handler.CAhandler._cacerts_get')
    def test_024_enroll(self, mock_ca):
        """ test certificate enrollment _cacert_get returns error """
        mock_ca.return_value = ('Error', None)
        self.cahandler.est_host = 'foo'
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual(('Error', None, None, None), self.cahandler.enroll('csr'))
        self.assertIn('ERROR:test_a2c:CAhandler.enroll(): Error', lcm.output)

    @patch('examples.ca_handler.est_ca_handler.CAhandler._cacerts_get')
    def test_025_enroll(self, mock_ca):
        """ test certificate enrollment no error but now ca_certs """
        mock_ca.return_value = (None, None)
        self.cahandler.est_host = 'foo'
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual(('no CA certificates found', None, None, None), self.cahandler.enroll('csr'))
        self.assertIn('ERROR:test_a2c:CAhandler.enroll(): no CA certificates found', lcm.output)

    @patch('examples.ca_handler.est_ca_handler.CAhandler._cacerts_get')
    def test_026_enroll(self, mock_ca):
        """ test certificate enrollment authentication information are missing """
        mock_ca.return_value = (None, 'ca_pem')
        self.cahandler.est_host = 'foo'
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual(('Authentication information missing', None, None, None), self.cahandler.enroll('csr'))
        self.assertIn('ERROR:test_a2c:CAhandler.enroll(): Authentication information missing', lcm.output)

    @patch('examples.ca_handler.est_ca_handler.CAhandler._simpleenroll')
    @patch('examples.ca_handler.est_ca_handler.CAhandler._cacerts_get')
    def test_027_enroll(self, mock_ca, mock_enroll):
        """ test certificate enrollment _simpleenroll returns error """
        mock_ca.return_value = (None, 'ca_pem')
        mock_enroll.return_value = ('Error', None)
        self.cahandler.est_host = 'foo'
        self.cahandler.est_user = 'est_usr'
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual(('Error', None, None, None), self.cahandler.enroll('csr'))
        self.assertIn('ERROR:test_a2c:CAhandler.enroll(): Error', lcm.output)

    @patch('examples.ca_handler.est_ca_handler.CAhandler._simpleenroll')
    @patch('examples.ca_handler.est_ca_handler.CAhandler._cacerts_get')
    def test_028_enroll(self, mock_ca, mock_enroll):
        """ test certificate enrollment _simpleenroll returns certificate """
        mock_ca.return_value = (None, 'ca_pem')
        mock_enroll.return_value = (None, 'cert')
        self.cahandler.est_host = 'foo'
        self.cahandler.est_user = 'est_usr'
        self.assertEqual((None, 'certca_pem', 'cert', None), self.cahandler.enroll('csr'))

    @patch('examples.ca_handler.est_ca_handler.CAhandler._simpleenroll')
    @patch('examples.ca_handler.est_ca_handler.CAhandler._cacerts_get')
    def test_029_enroll(self, mock_ca, mock_enroll):
        """ test certificate enrollment replace CERT BEGIN """
        mock_ca.return_value = (None, 'ca_pem')
        mock_enroll.return_value = (None, '-----BEGIN CERTIFICATE-----\ncert')
        self.cahandler.est_host = 'foo'
        self.cahandler.est_user = 'est_usr'
        self.assertEqual((None, '-----BEGIN CERTIFICATE-----\ncertca_pem', 'cert', None), self.cahandler.enroll('csr'))

    @patch('examples.ca_handler.est_ca_handler.CAhandler._simpleenroll')
    @patch('examples.ca_handler.est_ca_handler.CAhandler._cacerts_get')
    def test_030_enroll(self, mock_ca, mock_enroll):
        """ test certificate enrollment replace CERT END """
        mock_ca.return_value = (None, 'ca_pem')
        mock_enroll.return_value = (None, 'cert-----END CERTIFICATE-----\n')
        self.cahandler.est_host = 'foo'
        self.cahandler.est_user = 'est_usr'
        self.assertEqual((None, 'cert-----END CERTIFICATE-----\nca_pem', 'cert', None), self.cahandler.enroll('csr'))

    @patch('examples.ca_handler.est_ca_handler.CAhandler._simpleenroll')
    @patch('examples.ca_handler.est_ca_handler.CAhandler._cacerts_get')
    def test_031_enroll(self, mock_ca, mock_enroll):
        """ test certificate enrollment replace CERT BEGIN AND END """
        mock_ca.return_value = (None, 'ca_pem')
        mock_enroll.return_value = (None, '-----BEGIN CERTIFICATE-----\ncert-----END CERTIFICATE-----\n')
        self.cahandler.est_host = 'foo'
        self.cahandler.est_user = 'est_usr'
        self.assertEqual((None, '-----BEGIN CERTIFICATE-----\ncert-----END CERTIFICATE-----\nca_pem', 'cert', None), self.cahandler.enroll('csr'))

    @patch('examples.ca_handler.est_ca_handler.CAhandler._simpleenroll')
    @patch('examples.ca_handler.est_ca_handler.CAhandler._cacerts_get')
    def test_032_enroll(self, mock_ca, mock_enroll):
        """ test certificate enrollment replace CERT BEGIN AND END and \n"""
        mock_ca.return_value = (None, 'ca_pem')
        mock_enroll.return_value = (None, '-----BEGIN CERTIFICATE-----\ncert\n-----END CERTIFICATE-----\n\n')
        self.cahandler.est_host = 'foo'
        self.cahandler.est_user = 'est_usr'
        self.assertEqual((None, '-----BEGIN CERTIFICATE-----\ncert\n-----END CERTIFICATE-----\n\nca_pem', 'cert', None), self.cahandler.enroll('csr'))

if __name__ == '__main__':

    unittest.main()
