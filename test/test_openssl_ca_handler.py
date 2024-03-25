#!/usr/bin/python
# -*- coding: utf-8 -*-
""" unittests for openssl_ca_handler """
# pylint: disable=C0415, R0904, W0212
import sys
import os
import unittest
import configparser
import datetime
from unittest.mock import patch, mock_open, Mock
from OpenSSL import crypto
import hashlib

sys.path.insert(0, '.')
sys.path.insert(1, '..')

def convert_string_to_byte(value):
    """ convert a variable to byte if needed """
    if hasattr(value, 'encode'):
        result = value.encode()
    else:
        result = value
    return result

class TestACMEHandler(unittest.TestCase):
    """ test class for cgi_handler """

    def setUp(self):
        """ setup unittest """
        import logging
        from examples.ca_handler.openssl_ca_handler import CAhandler
        logging.basicConfig(level=logging.CRITICAL)
        self.logger = logging.getLogger('test_a2c')
        self.cahandler = CAhandler(False, self.logger)
        self.dir_path = os.path.dirname(os.path.realpath(__file__))

    def test_001_default(self):
        """ default test which always passes """
        self.assertEqual('foo', 'foo')

    def test_002_check_config(self):
        """ CAhandler._config_check with an empty config_dict """
        self.cahandler.issuer_dict = {}
        self.assertEqual('issuing_ca_key not specfied in config_file', self.cahandler._config_check())

    @patch('os.path.exists')
    def test_003_check_config(self, mock_file):
        """ CAhandler._config_check with key in config_dict but not existing """
        self.cahandler.issuer_dict = {'issuing_ca_key': 'foo.pem'}
        mock_file.side_effect = [False]
        self.assertEqual('issuing_ca_key foo.pem does not exist', self.cahandler._config_check())

    @patch('os.path.exists')
    def test_004_check_config(self, mock_file):
        """ CAhandler._config_check with key in config_dict key is existing """
        self.cahandler.issuer_dict = {'issuing_ca_key': self.dir_path + '/ca/sub-ca-key.pem'}
        mock_file.side_effect = [True]
        self.assertEqual('issuing_ca_cert must be specified in config file', self.cahandler._config_check())

    @patch('os.path.exists')
    def test_005_check_config(self, mock_file):
        """ CAhandler._config_check with key and cert in config_dict but cert does not exist """
        self.cahandler.issuer_dict = {'issuing_ca_key': self.dir_path + '/ca/sub-ca-key.pem', 'issuing_ca_cert': 'bar'}
        mock_file.side_effect = [True, False]
        self.assertEqual('issuing_ca_cert bar does not exist', self.cahandler._config_check())

    @patch('os.path.exists')
    def test_006_check_config(self, mock_file):
        """ CAhandler._config_check withoutissuing_ca_crl in config_dic """
        self.cahandler.issuer_dict = {'issuing_ca_key': self.dir_path + '/ca/sub-ca-key.pem', 'issuing_ca_cert': self.dir_path + '/ca/sub-ca-cert.pem'}
        mock_file.side_effect = [True, True]
        self.assertEqual('issuing_ca_crl must be specified in config file', self.cahandler._config_check())

    @patch('os.path.exists')
    def test_007_check_config(self, mock_file):
        """ CAhandler._config_check with wrong CRL in config_dic """
        self.cahandler.issuer_dict = {'issuing_ca_key': self.dir_path + '/ca/sub-ca-key.pem', 'issuing_ca_cert': self.dir_path + '/ca/sub-ca-cert.pem', 'issuing_ca_crl': 'foo.pem'}
        mock_file.side_effect = [True, True, False]
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual('cert_save_path must be specified in config file', self.cahandler._config_check())
        self.assertIn('INFO:test_a2c:CAhandler._config_check_crl(): issuing_ca_crl foo.pem does not exist.', lcm.output)

    @patch('os.path.exists')
    def test_008_check_config(self, mock_file):
        """ CAhandler._config_check without cert save path """
        self.cahandler.issuer_dict = {'issuing_ca_key': self.dir_path + '/ca/sub-ca-key.pem', 'issuing_ca_cert': self.dir_path + '/ca/sub-ca-cert.pem', 'issuing_ca_crl': self.dir_path + '/ca/sub-ca-crl.pem'}
        mock_file.side_effect = [True, True, True]
        self.assertEqual('cert_save_path must be specified in config file', self.cahandler._config_check())

    @patch('os.path.exists')
    def test_009_check_config(self, mock_file):
        """ CAhandler._config_check with key and cert in config_dict """
        self.cahandler.issuer_dict = {'issuing_ca_key': self.dir_path + '/ca/sub-ca-key.pem', 'issuing_ca_cert': self.dir_path + '/ca/sub-ca-cert.pem', 'issuing_ca_crl': self.dir_path + '/ca/sub-ca-crl.pem'}
        self.cahandler.cert_save_path = 'foo'
        mock_file.side_effect = [True, True, True, False]
        self.assertEqual('cert_save_path foo does not exist', self.cahandler._config_check())

    @patch('os.path.exists')
    def test_010_check_config(self, mock_file):
        """ CAhandler._config_check with empty ca_chain_list """
        self.cahandler.issuer_dict = {'issuing_ca_key': self.dir_path + '/ca/sub-ca-key.pem', 'issuing_ca_cert': self.dir_path + '/ca/sub-ca-cert.pem', 'issuing_ca_crl': self.dir_path + '/ca/sub-ca-crl.pem'}
        self.cahandler.cert_save_path = self.dir_path + '/ca/certs'
        mock_file.side_effect = [True, True, True, True]
        self.assertEqual('ca_cert_chain_list must be specified in config file', self.cahandler._config_check())

    @patch('os.path.exists')
    def test_011_check_config(self, mock_file):
        """ CAhandler._config_check completed """
        self.cahandler.issuer_dict = {'issuing_ca_key': self.dir_path + '/ca/sub-ca-key.pem', 'issuing_ca_cert': self.dir_path + '/ca/sub-ca-cert.pem', 'issuing_ca_crl': self.dir_path + '/ca/sub-ca-crl.pem'}
        self.cahandler.cert_save_path = self.dir_path + '/ca/certs'
        self.cahandler.ca_cert_chain_list = ['foo', 'bar']
        mock_file.side_effect = [True, True, True, True]
        self.assertFalse(self.cahandler._config_check())

    @patch('os.path.exists')
    def test_012_check_config(self, mock_file):
        """ CAhandler._config_check with wrong openssl.conf """
        self.cahandler.issuer_dict = {'issuing_ca_key': self.dir_path + '/ca/sub-ca-key.pem', 'issuing_ca_cert': self.dir_path + '/ca/sub-ca-cert.pem', 'issuing_ca_crl': self.dir_path + '/ca/sub-ca-crl.pem'}
        self.cahandler.cert_save_path = self.dir_path + '/ca/certs'
        self.cahandler.ca_cert_chain_list = ['foo', 'bar']
        self.cahandler.openssl_conf = 'foo'
        mock_file.side_effect = [True, True, True, True, False]
        self.assertEqual('openssl_conf foo does not exist', self.cahandler._config_check())

    @patch('os.path.exists')
    def test_013_check_config(self, mock_file):
        """ CAhandler._config_check with openssl.conf completed successfully """
        self.cahandler.issuer_dict = {'issuing_ca_key': self.dir_path + '/ca/sub-ca-key.pem', 'issuing_ca_cert': self.dir_path + '/ca/sub-ca-cert.pem', 'issuing_ca_crl': self.dir_path + '/ca/sub-ca-crl.pem'}
        self.cahandler.cert_save_path = self.dir_path + '/ca/certs'
        self.cahandler.ca_cert_chain_list = ['foo', 'bar']
        self.cahandler.openssl_conf = self.dir_path + '/ca/fr1.txt'
        mock_file.side_effect = [True, True, True, True, True]
        self.assertFalse(self.cahandler._config_check())

    def test_014_generate_pem_chain(self):
        """ CAhandler._pemcertchain_generate with EE cert but no ca cert"""
        self.assertEqual('ee-cert', self.cahandler._pemcertchain_generate('ee-cert', None))

    def test_015_generate_pem_chain(self):
        """ CAhandler._pemcertchain_generate with EE cert and ca cert"""
        self.assertEqual('ee-certca-cert', self.cahandler._pemcertchain_generate('ee-cert', 'ca-cert'))

    def test_016_generate_pem_chain(self):
        """ CAhandler._pemcertchain_generate with EE cert ca and an invalit entry in cert_cain_list cert"""
        self.cahandler.ca_cert_chain_list = ['foo.pem']
        self.assertEqual('ee-certca-cert', self.cahandler._pemcertchain_generate('ee-cert', 'ca-cert'))

    @patch("builtins.open", mock_open(read_data='_fakeroot-cert-1'), create=True)
    @patch('os.path.exists')
    def test_017_generate_pem_chain(self, mock_file):
        """ CAhandler._pemcertchain_generate with EE cert ca and an valid entry in cert_cain_list cert"""
        self.cahandler.ca_cert_chain_list = [self.dir_path + '/ca/fr1.txt']
        mock_file.return_value = True
        mock_open.return_vlaue = 'foo'
        self.assertEqual('ee-cert_ca-cert_fakeroot-cert-1', self.cahandler._pemcertchain_generate('ee-cert', '_ca-cert'))

    @patch("builtins.open", mock_open(read_data='_fakeroot-cert-1'), create=True)
    @patch('os.path.exists')
    def test_018_generate_pem_chain(self, mock_file):
        """ CAhandler._pemcertchain_generate with EE cert ca and two valid entry in cert_cain_list"""
        self.cahandler.ca_cert_chain_list = [self.dir_path + '/ca/fr1.txt', self.dir_path + '/ca/fr2.txt']
        mock_file.side_effect = [True, True]
        self.assertEqual('ee-cert_ca-cert_fakeroot-cert-1_fakeroot-cert-1', self.cahandler._pemcertchain_generate('ee-cert', '_ca-cert'))

    @patch("builtins.open", mock_open(read_data='_fakeroot-cert-1'), create=True)
    @patch('os.path.exists')
    def test_019_generate_pem_chain(self, mock_file):
        """ CAhandler._pemcertchain_generate with EE cert ca and two valid entry in cert_cain_list and two invalid entriest"""
        self.cahandler.ca_cert_chain_list = [self.dir_path + '/ca/fr1.txt', 'foo1', self.dir_path + '/ca/fr2.txt', 'foo2']
        mock_file.side_effect = [True, False, True, False]
        self.assertEqual('ee-cert_ca-cert_fakeroot-cert-1_fakeroot-cert-1', self.cahandler._pemcertchain_generate('ee-cert', '_ca-cert'))

    def test_020_load_ca_key_cert(self):
        """ CAhandler._ca_load() with empty issuer_dict """
        self.cahandler.issuer_dict = {}
        self.assertEqual((None, None), self.cahandler._ca_load())

    def test_021_load_ca_key_cert(self):
        """ CAhandler._ca_load() with issuer_dict containing invalid key """
        self.cahandler.issuer_dict = {'issuing_ca_key': 'foo.pem'}
        self.assertEqual((None, None), self.cahandler._ca_load())

    @patch("builtins.open", mock_open(read_data='test'), create=True)
    @patch('os.path.exists')
    @patch('cryptography.hazmat.primitives.serialization.load_pem_private_key')
    def test_022_load_ca_key_cert(self, mock_crypto, mock_file):
        """ CAhandler._ca_load() with issuer_dict containing valid key """
        self.cahandler.issuer_dict = {'issuing_ca_key': self.dir_path + '/ca/sub-ca-key.pem'}
        mock_crypto.return_value = 'foo'
        mock_file.return_value = True
        self.assertEqual(('foo', None), self.cahandler._ca_load())

    @patch("builtins.open", mock_open(read_data='test'), create=True)
    @patch('os.path.exists')
    @patch('cryptography.x509.load_pem_x509_certificate')
    @patch('cryptography.hazmat.primitives.serialization.load_pem_private_key')
    def test_023_load_ca_key_cert(self, mock_crypto_key, mock_crypto_cert, mock_file):
        """ CAhandler._ca_load() with issuer_dict containing key and passphrase """
        self.cahandler.issuer_dict = {'issuing_ca_key': self.dir_path + '/ca/sub-ca-key.pem', 'passphrase': 'Test1234'}
        mock_crypto_cert.return_value = 'cert'
        mock_crypto_key.return_value = 'key'
        mock_file.return_value = True
        self.assertEqual(('key', None), self.cahandler._ca_load())

    @patch("builtins.open", mock_open(read_data='test'), create=True)
    @patch('os.path.exists')
    @patch('cryptography.x509.load_pem_x509_certificate')
    @patch('cryptography.hazmat.primitives.serialization.load_pem_private_key')
    def test_024_load_ca_key_cert(self, mock_crypto_key, mock_crypto_cert, mock_file):
        """ CAhandler._ca_load() with issuer_dict containing key and invalid cert """
        self.cahandler.issuer_dict = {'issuing_ca_key': self.dir_path + '/ca/sub-ca-key.pem', 'passphrase': 'Test1234', 'issuing_ca_cert': 'foo.pem'}
        mock_crypto_cert.return_value = None
        mock_crypto_key.return_value = 'key'
        mock_file.return_value = True
        self.assertEqual(('key', None), self.cahandler._ca_load())

    @patch("builtins.open", mock_open(read_data='test'), create=True)
    @patch('os.path.exists')
    @patch('cryptography.x509.load_pem_x509_certificate')
    @patch('cryptography.hazmat.primitives.serialization.load_pem_private_key')
    def test_025_load_ca_key_cert(self, mock_crypto_key, mock_crypto_cert, mock_file):
        """ CAhandler._ca_load() with issuer_dict containing key and invalid cert """
        self.cahandler.issuer_dict = {'issuing_ca_key': self.dir_path + '/ca/sub-ca-key.pem', 'passphrase': 'Test1234', 'issuing_ca_cert': self.dir_path + '/ca/sub-ca-cert.pem'}
        mock_crypto_key.return_value = 'foo'
        mock_crypto_cert.return_value = 'bar'
        mock_file.return_value = True
        self.assertEqual(('foo', 'bar'), self.cahandler._ca_load())

    def test_026_revocation(self):
        """ revocation without having a CRL in issuer_dic """
        with open(self.dir_path + '/ca/sub-ca-client.txt', 'r') as fso:
            cert = fso.read()
        self.assertEqual((400, 'urn:ietf:params:acme:error:serverInternal', 'Unsupported operation'), self.cahandler.revoke(cert))

    def test_027_revocation(self):
        """ revocation without having a CRL in issuer_dic but none"""
        self.cahandler.issuer_dict = {'crl' : None}
        with open(self.dir_path + '/ca/sub-ca-client.txt', 'r') as fso:
            cert = fso.read()
        self.assertEqual((400, 'urn:ietf:params:acme:error:serverInternal', 'Unsupported operation'), self.cahandler.revoke(cert))

    @patch('examples.ca_handler.openssl_ca_handler.CAhandler._ca_load')
    def test_028_revocation(self, mock_ca_load):
        """ revocation cert no CA key """
        with open(self.dir_path + '/ca/sub-ca-client.txt', 'r') as fso:
            cert = fso.read()
        self.cahandler.issuer_dict = {'issuing_ca_key': self.dir_path + '/ca/sub-ca-key.pem', 'passphrase': 'Test1234', 'issuing_ca_cert': self.dir_path + '/ca/sub-ca-cert.pem', 'issuing_ca_crl' : self.dir_path + '/ca/foo-ca-crl.pem'}
        mock_ca_load.return_value = (None, 'ca_cert')
        self.assertEqual((400, 'urn:ietf:params:acme:error:serverInternal', 'configuration error'), self.cahandler.revoke(cert))

    @patch('examples.ca_handler.openssl_ca_handler.CAhandler._ca_load')
    def test_029_revocation(self, mock_ca_load):
        """ revocation cert no CA cert """
        with open(self.dir_path + '/ca/sub-ca-client.txt', 'r') as fso:
            cert = fso.read()
        self.cahandler.issuer_dict = {'issuing_ca_key': self.dir_path + '/ca/sub-ca-key.pem', 'passphrase': 'Test1234', 'issuing_ca_cert': self.dir_path + '/ca/sub-ca-cert.pem', 'issuing_ca_crl' : self.dir_path + '/ca/foo-ca-crl.pem'}
        mock_ca_load.return_value = ('ca_key', None)
        self.assertEqual((400, 'urn:ietf:params:acme:error:serverInternal', 'configuration error'), self.cahandler.revoke(cert))

    @patch('examples.ca_handler.openssl_ca_handler.cert_serial_get')
    @patch('examples.ca_handler.openssl_ca_handler.CAhandler._ca_load')
    def test_030_revocation(self, mock_ca_load, mock_serial):
        """ revocation cert no serial """
        with open(self.dir_path + '/ca/sub-ca-client.txt', 'r') as fso:
            cert = fso.read()
        self.cahandler.issuer_dict = {'issuing_ca_key': self.dir_path + '/ca/sub-ca-key.pem', 'passphrase': 'Test1234', 'issuing_ca_cert': self.dir_path + '/ca/sub-ca-cert.pem', 'issuing_ca_crl' : self.dir_path + '/ca/foo-ca-crl.pem'}
        mock_ca_load.return_value = ('ca_key', 'ca_cert')
        mock_serial.return_value = None
        self.assertEqual((400, 'urn:ietf:params:acme:error:serverInternal', 'configuration error'), self.cahandler.revoke(cert))

    def test_031_list_check(self):
        """ CAhandler._list_check failed check as empty entry"""
        list_ = ['bar.foo$', 'foo.bar$']
        entry = None
        self.assertFalse(self.cahandler._list_check(entry, list_))

    def test_032_list_check(self):
        """ CAhandler._list_check check against empty list"""
        list_ = []
        entry = 'host.bar.foo'
        self.assertTrue(self.cahandler._list_check(entry, list_))

    def test_033_list_check(self):
        """ CAhandler._list_check successful check against 1st element of a list"""
        list_ = ['bar.foo$', 'foo.bar$']
        entry = 'host.bar.foo'
        self.assertTrue(self.cahandler._list_check(entry, list_))

    def test_034_list_check(self):
        """ CAhandler._list_check unsuccessful as endcheck failed"""
        list_ = ['bar.foo$', 'foo.bar$']
        entry = 'host.bar.foo.bar_'
        self.assertFalse(self.cahandler._list_check(entry, list_))

    def test_035_list_check(self):
        """ CAhandler._list_check successful without $"""
        list_ = ['bar.foo', 'foo.bar$']
        entry = 'host.bar.foo.bar_'
        self.assertTrue(self.cahandler._list_check(entry, list_))

    def test_036_list_check(self):
        """ CAhandler._list_check wildcard check"""
        list_ = ['bar.foo$', 'foo.bar$']
        entry = '*.bar.foo'
        self.assertTrue(self.cahandler._list_check(entry, list_))

    def test_037_list_check(self):
        """ CAhandler._list_check failed wildcard check"""
        list_ = ['bar.foo$', 'foo.bar$']
        entry = '*.bar.foo_'
        self.assertFalse(self.cahandler._list_check(entry, list_))

    def test_038_list_check(self):
        """ CAhandler._list_check not end check"""
        list_ = ['bar.foo$', 'foo.bar$']
        entry = 'bar.foo gna'
        self.assertFalse(self.cahandler._list_check(entry, list_))

    def test_039_list_check(self):
        """ CAhandler._list_check $ at the end"""
        list_ = ['bar.foo$', 'foo.bar$']
        entry = 'bar.foo$'
        self.assertFalse(self.cahandler._list_check(entry, list_))

    def test_040_list_check(self):
        """ CAhandler._list_check check against empty list flip"""
        list_ = []
        entry = 'host.bar.foo'
        self.assertFalse(self.cahandler._list_check(entry, list_, True))

    def test_041_list_check(self):
        """ CAhandler._list_check flip successful check """
        list_ = ['bar.foo$', 'foo.bar$']
        entry = 'host.bar.foo'
        self.assertFalse(self.cahandler._list_check(entry, list_, True))

    def test_042_list_check(self):
        """ CAhandler._list_check flip unsuccessful check"""
        list_ = ['bar.foo$', 'foo.bar$']
        entry = 'host.bar.foo'
        self.assertFalse(self.cahandler._list_check(entry, list_, True))

    def test_043_list_check(self):
        """ CAhandler._list_check unsuccessful whildcard check"""
        list_ = ['foo.bar$', r'\*.bar.foo']
        entry = 'host.bar.foo'
        self.assertFalse(self.cahandler._list_check(entry, list_))

    def test_044_list_check(self):
        """ CAhandler._list_check successful whildcard check"""
        list_ = ['foo.bar$', r'\*.bar.foo']
        entry = '*.bar.foo'
        self.assertTrue(self.cahandler._list_check(entry, list_))

    def test_045_list_check(self):
        """ CAhandler._list_check successful whildcard in list but not in string """
        list_ = ['foo.bar$', '*.bar.foo']
        entry = 'foo.bar.foo'
        self.assertTrue(self.cahandler._list_check(entry, list_))

    def test_046_string_wlbl_check(self):
        """ CAhandler._string_wlbl_check against empty lists"""
        white_list = []
        black_list = []
        entry = 'host.bar.foo'
        self.assertTrue(self.cahandler._string_wlbl_check(entry, white_list, black_list))

    def test_047_string_wlbl_check(self):
        """ CAhandler._string_wlbl_check against empty whitlist but match in blocked_domainlist """
        white_list = []
        black_list = ['host.bar.foo$']
        entry = 'host.bar.foo'
        self.assertFalse(self.cahandler._string_wlbl_check(entry, white_list, black_list))

    def test_048_string_wlbl_check(self):
        """ CAhandler._string_wlbl_check against empty whitlist but no match in blocked_domainlist """
        white_list = []
        black_list = ['faulty.bar.foo$']
        entry = 'host.bar.foo'
        self.assertTrue(self.cahandler._string_wlbl_check(entry, white_list, black_list))

    def test_049_string_wlbl_check(self):
        """ CAhandler._string_wlbl_check against empty whitlist wildcard check does not hit """
        white_list = []
        black_list = [r'\*.bar.foo$']
        entry = 'host.bar.foo'
        self.assertTrue(self.cahandler._string_wlbl_check(entry, white_list, black_list))

    def test_050_string_wlbl_check(self):
        """ CAhandler._string_wlbl_check against empty whitlist wildcard check hit """
        white_list = []
        black_list = [r'\*.bar.foo$']
        entry = '*.bar.foo'
        self.assertFalse(self.cahandler._string_wlbl_check(entry, white_list, black_list))

    def test_051_string_wlbl_check(self):
        """ CAhandler._string_wlbl_check successful wl check with empty bl"""
        white_list = ['foo.foo', 'bar.foo$']
        black_list = []
        entry = 'host.bar.foo'
        self.assertTrue(self.cahandler._string_wlbl_check(entry, white_list, black_list))

    def test_052_string_wlbl_check(self):
        """ CAhandler._string_wlbl_check unsuccessful empty bl """
        white_list = ['foo.foo$', 'host.bar.foo$']
        black_list = []
        entry = 'host.bar.foo.bar'
        self.assertFalse(self.cahandler._string_wlbl_check(entry, white_list, black_list))

    def test_053_string_wlbl_check(self):
        """ CAhandler._string_wlbl_check unsuccessful host in bl"""
        white_list = ['foo.foo', 'bar.foo$']
        black_list = ['host.bar.foo']
        entry = 'host.bar.foo'
        self.assertFalse(self.cahandler._string_wlbl_check(entry, white_list, black_list))

    def test_054_string_wlbl_check(self):
        """ CAhandler._string_wlbl_check unsuccessful host in bl but not on first position"""
        white_list = ['foo.foo', 'bar.foo$']
        black_list = ['foo.bar$', 'host.bar.foo', 'foo.foo']
        entry = 'host.bar.foo'
        self.assertFalse(self.cahandler._string_wlbl_check(entry, white_list, black_list))

    def test_055_string_wlbl_check(self):
        """ CAhandler._string_wlbl_check successful wildcard in entry not n bl """
        white_list = ['foo.foo', 'bar.foo$']
        black_list = ['host.bar.foo']
        entry = '*.bar.foo'
        self.assertTrue(self.cahandler._string_wlbl_check(entry, white_list, black_list))

    def test_056_string_wlbl_check(self):
        """ CAhandler._string_wlbl_check successful wildcard blocked_domainlisting - no match"""
        white_list = ['foo.foo', 'bar.foo$']
        black_list = [r'\*.bar.foo']
        entry = 'host.bar.foo'
        self.assertTrue(self.cahandler._string_wlbl_check(entry, white_list, black_list))

    def test_057_string_wlbl_check(self):
        """ CAhandler._string_wlbl_check  failed wildcard black-listing """
        white_list = ['foo.foo', 'bar.foo$']
        black_list = [r'\*.bar.foo']
        entry = '*.bar.foo'
        self.assertFalse(self.cahandler._string_wlbl_check(entry, white_list, black_list))

    def test_058_string_wlbl_check(self):
        """ CAhandler._string_wlbl_check faked domain"""
        white_list = ['foo.foo', 'bar.foo$']
        black_list = ['google.com.bar.foo']
        entry = 'foo.google.com.bar.foo'
        self.assertFalse(self.cahandler._string_wlbl_check(entry, white_list, black_list))

    def test_059_string_wlbl_check(self):
        """ CAhandler._string_wlbl_check faked wc domain"""
        white_list = ['foo.foo', 'bar.foo$']
        black_list = ['google.com.bar.foo$']
        entry = '*.google.com.bar.foo'
        self.assertFalse(self.cahandler._string_wlbl_check(entry, white_list, black_list))

    def test_060_string_wlbl_check(self):
        """ CAhandler._string_wlbl_check faked domain"""
        white_list = ['foo.foo', 'bar.foo$']
        black_list = ['google.com']
        entry = '*.google.com.bar.foo'
        self.assertFalse(self.cahandler._string_wlbl_check(entry, white_list, black_list))

    def test_061_string_wlbl_check(self):
        """ CAhandler._string_wlbl_check faked hostname and domain"""
        white_list = ['foo.foo', 'bar.foo$']
        black_list = ['google.com']
        entry = 'www.google.com.bar.foo'
        self.assertFalse(self.cahandler._string_wlbl_check(entry, white_list, black_list))

    @patch('examples.ca_handler.openssl_ca_handler.csr_cn_get')
    @patch('examples.ca_handler.openssl_ca_handler.csr_san_get')
    def test_062_csr_check(self,  mock_san, mock_cn):
        """ CAhandler._check_csr with empty allowed_domainlist and blocked_domainlists """
        self.cahandler.allowed_domainlist = []
        self.cahandler.blocked_domainlist = []
        mock_san.return_value = ['DNS:host.foo.bar']
        mock_cn.return_value = 'host2.foo.bar'
        csr = 'csr'
        self.assertEqual((True, None), self.cahandler._csr_check(csr))

    @patch('examples.ca_handler.openssl_ca_handler.CAhandler._string_wlbl_check')
    @patch('examples.ca_handler.openssl_ca_handler.csr_cn_get')
    @patch('examples.ca_handler.openssl_ca_handler.csr_san_get')
    def test_063_csr_check(self, mock_san, mock_cn, mock_lcheck):
        """ CAhandler._check_csr with list and failed check """
        self.cahandler.allowed_domainlist = ['foo.bar']
        self.cahandler.blocked_domainlist = []
        mock_san.return_value = ['DNS:host.foo.bar']
        mock_cn.return_value = 'host2.foo.bar'
        mock_lcheck.side_effect = [True, False]
        csr = 'csr'
        self.assertEqual((False, None), self.cahandler._csr_check(csr))

    @patch('examples.ca_handler.openssl_ca_handler.CAhandler._string_wlbl_check')
    @patch('examples.ca_handler.openssl_ca_handler.csr_cn_get')
    @patch('examples.ca_handler.openssl_ca_handler.csr_san_get')
    def test_064_csr_check(self, mock_san, mock_cn, mock_lcheck):
        """ CAhandler._check_csr with list and successful check """
        self.cahandler.allowed_domainlist = ['foo.bar']
        self.cahandler.blocked_domainlist = []
        mock_san.return_value = ['DNS:host.foo.bar']
        mock_cn.return_value = 'host2.foo.bar'
        mock_lcheck.side_effect = [True, True]
        csr = 'csr'
        self.assertEqual((True, None), self.cahandler._csr_check(csr))

    @patch('examples.ca_handler.openssl_ca_handler.CAhandler._string_wlbl_check')
    @patch('examples.ca_handler.openssl_ca_handler.csr_cn_get')
    @patch('examples.ca_handler.openssl_ca_handler.csr_san_get')
    def test_065_csr_check(self, mock_san, mock_cn, mock_lcheck):
        """ CAhandler._check_csr san parsing failed """
        self.cahandler.allowed_domainlist = ['foo.bar']
        self.cahandler.blocked_domainlist = []
        mock_san.return_value = ['host.google.com']
        mock_cn.return_value = 'host2.foo.bar'
        mock_lcheck.side_effect = [True, True]
        csr = 'csr'
        self.assertEqual((False, None), self.cahandler._csr_check(csr))

    @patch('examples.ca_handler.openssl_ca_handler.csr_cn_get')
    @patch('examples.ca_handler.openssl_ca_handler.csr_san_get')
    def test_066_csr_check(self, mock_san, mock_cn):
        """ CAhandler._check_csr san parsing failed """
        self.cahandler.allowed_domainlist = ['foo.bar']
        self.cahandler.blocked_domainlist = []
        mock_san.return_value = []
        mock_cn.return_value = None
        csr = 'csr'
        self.assertEqual((False, None), self.cahandler._csr_check(csr))

    @patch('examples.ca_handler.openssl_ca_handler.csr_cn_get')
    @patch('examples.ca_handler.openssl_ca_handler.csr_san_get')
    def test_067_csr_check(self,  mock_san, mock_cn):
        """ CAhandler._check_csr cn_enforce """
        mock_san.return_value = ['DNS:host.foo.bar']
        mock_cn.return_value = None
        csr = 'csr'
        self.assertEqual((True, 'host.foo.bar'), self.cahandler._csr_check(csr))

    @patch('examples.ca_handler.openssl_ca_handler.csr_cn_get')
    @patch('examples.ca_handler.openssl_ca_handler.csr_san_get')
    def test_068_csr_check(self,  mock_san, mock_cn):
        """ CAhandler._check_csr cn_enforce  but no san"""
        mock_san.return_value = []
        mock_cn.return_value = None
        csr = 'csr'
        self.assertEqual((True, None), self.cahandler._csr_check(csr))

    @patch('examples.ca_handler.openssl_ca_handler.CAhandler._config_load')
    def test_069__enter__(self, mock_cfg):
        """ test enter """
        mock_cfg.return_value = True
        self.cahandler.__enter__()
        self.assertTrue(mock_cfg.called)

    def test_070_trigger(self):
        """ test trigger """
        self.assertEqual(('Method not implemented.', None, None), self.cahandler.trigger('payload'))

    def test_071_poll(self):
        """ test poll """
        self.assertEqual(('Method not implemented.', None, None, 'poll_identifier', False), self.cahandler.poll('cert_name', 'poll_identifier','csr'))

    def test_072_certificate_store(self):
        """ _certificate_store() """
        cert = Mock()
        cert.get_serial_number = Mock(return_value=42)
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._certificate_store(cert)
        self.assertIn('ERROR:test_a2c:CAhandler._certificate_store() handler configuration incomplete: cert_save_path is missing', lcm.output)

    @patch('OpenSSL.crypto.dump_certificate')
    @patch('builtins.open', mock_open(read_data="foo"))
    @patch('os.mkdir')
    @patch('os.path.isdir')
    def test_073_certificate_store(self, mock_os, mock_mkdir, mock_dump):
        """ _certificate_store() """
        mock_os.return_value = True
        mock_mkdir.return_value = Mock()
        cert = Mock()
        cert.serial_number = 42
        self.cahandler.cert_save_path  = 'template'
        mock_dump.return_value = 'foo'
        self.cahandler._certificate_store(cert)
        self.assertFalse(mock_mkdir.called)

    @patch('OpenSSL.crypto.dump_certificate')
    @patch('builtins.open', mock_open(read_data="foo"))
    @patch('os.mkdir')
    @patch('os.path.isdir')
    def test_074_certificate_store(self, mock_os, mock_mkdir, mock_dump):
        """ _certificate_store() """
        mock_os.return_value = False
        mock_mkdir.return_value = Mock()
        cert = Mock()
        cert.serial_number = 42
        self.cahandler.cert_save_path  = 'template'
        mock_dump.return_value = 'foo'
        self.cahandler._certificate_store(cert)
        self.assertTrue(mock_mkdir.called)

    @patch('OpenSSL.crypto.dump_certificate')
    @patch('builtins.open', mock_open(read_data="foo"))
    @patch('os.mkdir')
    @patch('os.path.isdir')
    def test_075_certificate_store(self, mock_os, mock_mkdir, mock_dump):
        """ _certificate_store() """
        mock_os.return_value = True
        mock_mkdir.return_value = Mock()
        cert = Mock()
        cert.serial_number = 42
        self.cahandler.cert_save_path  = 'template'
        self.cahandler.save_cert_as_hex = True
        mock_dump.return_value = 'foo'
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._certificate_store(cert)
        self.assertIn('INFO:test_a2c:convert serial to hex: 42: 2A', lcm.output)

    @patch('examples.ca_handler.openssl_ca_handler.load_config')
    def test_076__config_load(self, mock_load_cfg):
        """ config load """
        parser = configparser.ConfigParser()
        parser['CAhandler'] = {'save_cert_as_hex': False}
        mock_load_cfg.return_value = parser
        self.cahandler._config_load()
        self.assertFalse(self.cahandler.save_cert_as_hex )

    @patch('examples.ca_handler.openssl_ca_handler.load_config')
    def test_077__config_load(self, mock_load_cfg):
        """ config load """
        parser = configparser.ConfigParser()
        parser['CAhandler'] = {'save_cert_as_hex': True}
        mock_load_cfg.return_value = parser
        self.cahandler._config_load()
        self.assertTrue(self.cahandler.save_cert_as_hex )

    @patch('json.loads')
    @patch('examples.ca_handler.openssl_ca_handler.load_config')
    def test_078__config_load(self, mock_load_cfg, mock_jl):
        """ config load """
        parser = configparser.ConfigParser()
        parser['CAhandler'] = {'blocked_domainlist': 'foo.json'}
        mock_load_cfg.return_value = parser
        mock_jl.return_value = 'blocked_domainlist'
        self.cahandler._config_load()
        self.assertEqual('blocked_domainlist', self.cahandler.blocked_domainlist)

    @patch('json.loads')
    @patch('examples.ca_handler.openssl_ca_handler.load_config')
    def test_079__config_load(self, mock_load_cfg, mock_jl):
        """ config load """
        parser = configparser.ConfigParser()
        parser['CAhandler'] = {'blacklist': 'foo.json'}
        mock_load_cfg.return_value = parser
        mock_jl.return_value = 'blocked_domainlist'
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_load()
        self.assertEqual('blocked_domainlist', self.cahandler.blocked_domainlist)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load() found "blacklist" parameter in configfile which should be renamed to "blocked_domainlist"', lcm.output)

    @patch('json.loads')
    @patch('examples.ca_handler.openssl_ca_handler.load_config')
    def test_080__config_load(self, mock_load_cfg, mock_jl):
        """ config load """
        parser = configparser.ConfigParser()
        parser['CAhandler'] = {'whitelist': 'foo.json'}
        mock_load_cfg.return_value = parser
        mock_jl.return_value = 'allowed_domainlist'
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_load()
        self.assertEqual('allowed_domainlist', self.cahandler.allowed_domainlist)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load() found "whitelist" parameter in configfile which should be renamed to "allowed_domainlist"', lcm.output)

    @patch('json.loads')
    @patch('examples.ca_handler.openssl_ca_handler.load_config')
    def test_081__config_load(self, mock_load_cfg, mock_jl):
        """ config load """
        parser = configparser.ConfigParser()
        parser['CAhandler'] = {'allowed_domainlist': 'foo.json'}
        mock_load_cfg.return_value = parser
        mock_jl.return_value = 'allowed_domainlist'
        self.cahandler._config_load()
        self.assertEqual('allowed_domainlist', self.cahandler.allowed_domainlist)

    @patch('json.loads')
    @patch('examples.ca_handler.openssl_ca_handler.load_config')
    def test_082__config_load(self, mock_load_cfg, mock_jl):
        """ config load """
        parser = configparser.ConfigParser()
        parser['CAhandler'] = {'openssl_conf': 'openssl_conf'}
        mock_load_cfg.return_value = parser
        mock_jl.return_value = 'openssl_conf'
        self.cahandler._config_load()
        self.assertEqual('openssl_conf', self.cahandler.openssl_conf)

    @patch('examples.ca_handler.openssl_ca_handler.load_config')
    def test_083__config_load(self, mock_load_cfg):
        """ config load """
        parser = configparser.ConfigParser()
        parser['CAhandler'] = {'issuing_ca_key': 'issuing_ca_key'}
        mock_load_cfg.return_value = parser
        self.cahandler._config_load()
        self.assertEqual('issuing_ca_key', self.cahandler.issuer_dict['issuing_ca_key'])

    @patch('examples.ca_handler.openssl_ca_handler.load_config')
    def test_084__config_load(self, mock_load_cfg):
        """ config load """
        parser = configparser.ConfigParser()
        parser['CAhandler'] = {'issuing_ca_cert': 'issuing_ca_cert'}
        mock_load_cfg.return_value = parser
        self.cahandler._config_load()
        self.assertEqual('issuing_ca_cert', self.cahandler.issuer_dict['issuing_ca_cert'])

    @patch('examples.ca_handler.openssl_ca_handler.load_config')
    def test_085__config_load(self, mock_load_cfg):
        """ config load """
        parser = configparser.ConfigParser()
        parser['CAhandler'] = {'issuing_ca_key_passphrase': 'issuing_ca_key_passphrase'}
        mock_load_cfg.return_value = parser
        self.cahandler._config_load()
        self.assertEqual(b'issuing_ca_key_passphrase', self.cahandler.issuer_dict['passphrase'])

    @patch('examples.ca_handler.openssl_ca_handler.load_config')
    def test_086__config_load(self, mock_load_cfg):
        """ config load """
        parser = configparser.ConfigParser()
        parser['CAhandler'] = {'cert_validity_days': 10}
        mock_load_cfg.return_value = parser
        self.cahandler._config_load()
        self.assertEqual(10, self.cahandler.cert_validity_days )

    @patch('examples.ca_handler.openssl_ca_handler.load_config')
    def test_087__config_load(self, mock_load_cfg):
        """ config load """
        parser = configparser.ConfigParser()
        parser['CAhandler'] = {'cert_save_path': 'cert_save_path'}
        mock_load_cfg.return_value = parser
        self.cahandler._config_load()
        self.assertEqual('cert_save_path', self.cahandler.cert_save_path)

    @patch('examples.ca_handler.openssl_ca_handler.load_config')
    def test_088__config_load(self, mock_load_cfg):
        """ config load """
        parser = configparser.ConfigParser()
        parser['CAhandler'] = {'ca_cert_chain_list': '["root_ca"]'}
        mock_load_cfg.return_value = parser
        self.cahandler._config_load()
        self.assertEqual(['root_ca'], self.cahandler.ca_cert_chain_list)

    @patch('examples.ca_handler.openssl_ca_handler.load_config')
    def test_089__config_load(self, mock_load_cfg):
        """ config load """
        parser = configparser.ConfigParser()
        parser['CAhandler'] = {'ca_cert_chain_list': '["root_ca", "sub_ca"]'}
        mock_load_cfg.return_value = parser
        self.cahandler._config_load()
        self.assertEqual(['root_ca', 'sub_ca'], self.cahandler.ca_cert_chain_list)

    @patch('examples.ca_handler.openssl_ca_handler.load_config')
    def test_090__config_load(self, mock_load_cfg):
        """ config load """
        parser = configparser.ConfigParser()
        parser['CAhandler'] = {'issuing_ca_crl': 'issuing_ca_crl'}
        mock_load_cfg.return_value = parser
        self.cahandler._config_load()
        self.assertEqual('issuing_ca_crl', self.cahandler.issuer_dict['issuing_ca_crl'])

    @patch.dict('os.environ', {'foo': 'foo_var'})
    @patch('examples.ca_handler.openssl_ca_handler.load_config')
    def test_091_config_load(self, mock_load_cfg):
        """ test _config_load - load template with passphrase variable """
        parser = configparser.ConfigParser()
        parser['CAhandler'] = {'issuing_ca_key_passphrase_variable': 'foo'}
        mock_load_cfg.return_value = parser
        self.cahandler._config_load()
        self.assertEqual(b'foo_var', self.cahandler.issuer_dict['passphrase'])

    @patch.dict('os.environ', {'foo': 'foo_var'})
    @patch('examples.ca_handler.openssl_ca_handler.load_config')
    def test_092_config_load(self, mock_load_cfg):
        """ test _config_load - load template passpharese variable configured but does not exist """
        parser = configparser.ConfigParser()
        parser['CAhandler'] = {'issuing_ca_key_passphrase_variable': 'does_not_exist'}
        mock_load_cfg.return_value = parser
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_load()
        self.assertIn("ERROR:test_a2c:CAhandler._config_load() could not load issuing_ca_key_passphrase_variable:'does_not_exist'", lcm.output)

    @patch.dict('os.environ', {'foo': 'foo_var'})
    @patch('examples.ca_handler.openssl_ca_handler.load_config')
    def test_093_config_load(self, mock_load_cfg):
        """ test _config_load - load template with passphrase variable  - overwritten bei cfg file"""
        parser = configparser.ConfigParser()
        parser['CAhandler'] = {'issuing_ca_key_passphrase_variable': 'foo', 'issuing_ca_key_passphrase': 'foo_file'}
        mock_load_cfg.return_value = parser
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_load()
        self.assertEqual(b'foo_file', self.cahandler.issuer_dict['passphrase'])
        self.assertIn('INFO:test_a2c:CAhandler._config_load() overwrite issuing_ca_key_passphrase_variable', lcm.output)

    @patch('examples.ca_handler.openssl_ca_handler.load_config')
    def test_094__config_load(self, mock_load_cfg):
        """ config load no cn_enforce """
        parser = configparser.ConfigParser()
        parser['CAhandler'] = {'foo': 'bar'}
        mock_load_cfg.return_value = parser
        self.cahandler._config_load()
        self.assertFalse(self.cahandler.cn_enforce)

    @patch('examples.ca_handler.openssl_ca_handler.load_config')
    def test_095__config_load(self, mock_load_cfg):
        """ config load cn_enforce True """
        parser = configparser.ConfigParser()
        parser['CAhandler'] = {'cn_enforce': True}
        mock_load_cfg.return_value = parser
        self.cahandler._config_load()
        self.assertTrue(self.cahandler.cn_enforce)

    @patch('examples.ca_handler.openssl_ca_handler.load_config')
    def test_096__config_load(self, mock_load_cfg):
        """ config load cn_enforce True """
        parser = configparser.ConfigParser()
        parser['CAhandler'] = {'cn_enforce': False}
        mock_load_cfg.return_value = parser
        self.cahandler._config_load()
        self.assertFalse(self.cahandler.cn_enforce)

    @patch('examples.ca_handler.openssl_ca_handler.load_config')
    def test_097__config_load(self, mock_load_cfg):
        """ config load cn_enforce True """
        parser = configparser.ConfigParser()
        parser['CAhandler'] = {'cn_enforce': 'bar'}
        mock_load_cfg.return_value = parser
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_load()
        self.assertFalse(self.cahandler.cn_enforce)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load() variable cn_enforce cannot be parsed', lcm.output)

    @patch('examples.ca_handler.openssl_ca_handler.load_config')
    def test_098__config_load(self, mock_load_cfg):
        """ config load cn_enforce True """
        parser = configparser.ConfigParser()
        parser['CAhandler'] = {'cert_validity_adjust': 'bar'}
        mock_load_cfg.return_value = parser
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_load()
        self.assertFalse(self.cahandler.cn_enforce)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load() variable cert_validity_adjust cannot be parsed', lcm.output)

    @patch('examples.ca_handler.openssl_ca_handler.load_config')
    def test_099___certificate_extensions_load(self, mock_load_cfg):
        """ extension list load - empty list """
        # mock_load_cfg.return_value = {'extensions': {'foo': 'critical, serverAuth'}}
        mock_load_cfg.return_value = {'extensions': {'foo': 'bar'}}
        result = {'foo': {'critical': False, 'value': 'bar'}}
        self.assertEqual(result, self.cahandler._certificate_extensions_load())

    @patch('examples.ca_handler.openssl_ca_handler.load_config')
    def test_100___certificate_extensions_load(self, mock_load_cfg):
        """ extension list load - empty list """
        # mock_load_cfg.return_value = {'extensions': {'foo': 'critical, serverAuth'}}
        mock_load_cfg.return_value = {'extensions': {'foo': 'bar, foobar'}}
        result = {'foo': {'critical': False, 'value': 'bar, foobar'}}
        self.assertEqual(result, self.cahandler._certificate_extensions_load())

    @patch('examples.ca_handler.openssl_ca_handler.load_config')
    def test_101___certificate_extensions_load(self, mock_load_cfg):
        """ extension list load - empty list """
        # mock_load_cfg.return_value = {'extensions': {'foo': 'critical, serverAuth'}}
        mock_load_cfg.return_value = {'extensions': {'foo': 'bar', 'foo1': 'bar1'}}
        result = {'foo': {'critical': False, 'value': 'bar'}, 'foo1': {'critical': False, 'value': 'bar1'}}
        self.assertEqual(result, self.cahandler._certificate_extensions_load())

    @patch('examples.ca_handler.openssl_ca_handler.load_config')
    def test_102___certificate_extensions_load(self, mock_load_cfg):
        """ extension list load - empty list """
        mock_load_cfg.return_value = {'extensions': {'foo': 'critical, bar'}}
        result = {'foo': {'critical': True, 'value': 'bar'}}
        self.assertEqual(result, self.cahandler._certificate_extensions_load())

    @patch('examples.ca_handler.openssl_ca_handler.load_config')
    def test_103___certificate_extensions_load(self, mock_load_cfg):
        """ extension list load - empty list """
        # mock_load_cfg.return_value = {'extensions': {'foo': 'critical, serverAuth'}}
        mock_load_cfg.return_value = {'extensions': {'foo': ' bar, foobar'}}
        result = {'foo': {'critical': False, 'value': 'bar, foobar'}}
        self.assertEqual(result, self.cahandler._certificate_extensions_load())

    @patch('examples.ca_handler.openssl_ca_handler.load_config')
    def test_104___certificate_extensions_load(self, mock_load_cfg):
        """ extension list load - empty list """
        # mock_load_cfg.return_value = {'extensions': {'foo': 'critical, serverAuth'}}
        mock_load_cfg.return_value = {'extensions': {'foo': ' bar, issuer:'}}
        result = {'foo': {'critical': False, 'issuer': True, 'value': 'bar'}}
        self.assertEqual(result, self.cahandler._certificate_extensions_load())

    @patch('examples.ca_handler.openssl_ca_handler.load_config')
    def test_105___certificate_extensions_load(self, mock_load_cfg):
        """ extension list load - empty list """
        # mock_load_cfg.return_value = {'extensions': {'foo': 'critical, serverAuth'}}
        mock_load_cfg.return_value = {'extensions': {'foo': ' bar, subject:'}}
        result = {'foo': {'critical': False, 'subject': True, 'value': 'bar'}}
        self.assertEqual(result, self.cahandler._certificate_extensions_load())

    @patch('examples.ca_handler.openssl_ca_handler.CAhandler._config_check')
    def test_106_enroll(self, mock_chk):
        """ enroll test error returned from config_check"""
        mock_chk.return_value = 'error'
        self.assertEqual(('error', None, None, None), self.cahandler.enroll('csr'))

    def test_107__cert_extension_ku_parse(self):
        """ test _cert_extension_ku_parse() """
        ext = ''
        result = {'digital_signature': False, 'content_commitment': False, 'key_encipherment': False, 'data_encipherment': False, 'key_agreement': False, 'key_cert_sign': False, 'crl_sign': False, 'encipher_only': False, 'decipher_only': False}
        self.assertEqual(result, self.cahandler._cert_extension_ku_parse(ext))

    def test_108__cert_extension_ku_parse(self):
        """ test _cert_extension_ku_parse() """
        ext = 'digitalSignature'
        result = {'digital_signature': True, 'content_commitment': False, 'key_encipherment': False, 'data_encipherment': False, 'key_agreement': False, 'key_cert_sign': False, 'crl_sign': False, 'encipher_only': False, 'decipher_only': False}
        self.assertEqual(result, self.cahandler._cert_extension_ku_parse(ext))

    def test_109__cert_extension_ku_parse(self):
        """ test _cert_extension_ku_parse() """
        ext = 'critical, digitalSignature'
        result = {'digital_signature': True, 'content_commitment': False, 'key_encipherment': False, 'data_encipherment': False, 'key_agreement': False, 'key_cert_sign': False, 'crl_sign': False, 'encipher_only': False, 'decipher_only': False}
        self.assertEqual(result, self.cahandler._cert_extension_ku_parse(ext))

    def test_110__cert_extension_ku_parse(self):
        """ test _cert_extension_ku_parse() """
        ext = 'critical, digitalSignature,keyEncipherment'
        result = {'digital_signature': True, 'content_commitment': False, 'key_encipherment': True, 'data_encipherment': False, 'key_agreement': False, 'key_cert_sign': False, 'crl_sign': False, 'encipher_only': False, 'decipher_only': False}
        self.assertEqual(result, self.cahandler._cert_extension_ku_parse(ext))

    def test_111__cert_extension_ku_parse(self):
        """ test _cert_extension_ku_parse() """
        ext = 'critical, digitalSignature,keyEncipherment, nonRepudiation'
        result = {'digital_signature': True, 'content_commitment': True, 'key_encipherment': True, 'data_encipherment': False, 'key_agreement': False, 'key_cert_sign': False, 'crl_sign': False, 'encipher_only': False, 'decipher_only': False}
        self.assertEqual(result, self.cahandler._cert_extension_ku_parse(ext))

    def test_112__cert_extension_eku_parse(self):
        """ test _cert_extension_eku_parse()"""
        extension = 'ekeyuse'
        self.assertEqual(['eKeyUse'], self.cahandler._cert_extension_eku_parse(extension))

    def test_113__cert_extension_eku_parse(self):
        """ test _cert_extension_eku_parse()"""
        extension = 'ekeyUSE'
        self.assertEqual(['eKeyUse'], self.cahandler._cert_extension_eku_parse(extension))

    def test_114__cert_extension_eku_parse(self):
        """ test _cert_extension_eku_parse()"""
        extension = 'ekeyUSE, ekeyUSE'
        self.assertEqual(['eKeyUse', 'eKeyUse'], self.cahandler._cert_extension_eku_parse(extension))

    def test_115__cert_extension_eku_parse(self):
        """ test _cert_extension_eku_parse()"""
        extension = 'ekeyUSE, unknown'
        self.assertEqual(['eKeyUse'], self.cahandler._cert_extension_eku_parse(extension))

    @patch('examples.ca_handler.openssl_ca_handler.ExtendedKeyUsage')
    @patch('examples.ca_handler.openssl_ca_handler.KeyUsage')
    @patch('examples.ca_handler.openssl_ca_handler.SubjectKeyIdentifier')
    @patch('examples.ca_handler.openssl_ca_handler.KeyUsage')
    @patch('examples.ca_handler.openssl_ca_handler.BasicConstraints')
    def test_116__cert_extension_dic_parse(self,  mock_bc, mock_ku, mock_ski, mock_aki, mock_eku):
        """ test _cert_extension_dic_parse()"""
        cert = Mock()
        mock_bc.return_value = 'mock_bc'
        mock_ku.return_value = 'mock_ku'
        mock_eku.return_value = 'mock_eku'
        mock_ski.from_public_key.return_value = 'mock_ski'
        mock_aki.from_issuer_public_key.return_value = 'mock_aki'
        cert_extension_dic = {'basicConstraints': {'critical': False, 'value': 'CA:TRUE, pathlen:0'}}
        result = [{'critical': False, 'name': 'mock_bc'}]
        self.assertEqual(result, self.cahandler._cert_extension_dic_parse(cert_extension_dic, cert, cert))
        self.assertTrue(mock_bc.called)
        self.assertFalse(mock_ku.called)
        self.assertFalse(mock_eku.called)
        self.assertFalse(mock_ski.called)
        self.assertFalse(mock_aki.called)

    @patch('examples.ca_handler.openssl_ca_handler.ExtendedKeyUsage')
    @patch('examples.ca_handler.openssl_ca_handler.KeyUsage')
    @patch('examples.ca_handler.openssl_ca_handler.SubjectKeyIdentifier')
    @patch('examples.ca_handler.openssl_ca_handler.KeyUsage')
    @patch('examples.ca_handler.openssl_ca_handler.BasicConstraints')
    def test_117__cert_extension_dic_parse(self,  mock_bc, mock_ku, mock_ski, mock_aki, mock_eku):
        """ test _cert_extension_dic_parse()"""
        cert = Mock()
        mock_bc.return_value = 'mock_bc'
        mock_ku.return_value = 'mock_ku'
        mock_eku.return_value = 'mock_eku'
        mock_ski.from_public_key.return_value = 'mock_ski'
        mock_aki.from_issuer_public_key.return_value = 'mock_aki'
        cert_extension_dic = {'basicConstraints': {'critical': True, 'value': 'CA:TRUE, pathlen:0'}}
        result = [{'critical': True, 'name': 'mock_bc'}]
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual(result, self.cahandler._cert_extension_dic_parse(cert_extension_dic, cert, cert))
        self.assertIn('INFO:test_a2c:CAhandler.cert_extesion_dic_parse(): basicConstraints', lcm.output)

    @patch('examples.ca_handler.openssl_ca_handler.ExtendedKeyUsage')
    @patch('examples.ca_handler.openssl_ca_handler.KeyUsage')
    @patch('examples.ca_handler.openssl_ca_handler.AuthorityKeyIdentifier')
    @patch('examples.ca_handler.openssl_ca_handler.SubjectKeyIdentifier')
    @patch('examples.ca_handler.openssl_ca_handler.BasicConstraints')
    def test_118__cert_extension_dic_parse(self,  mock_bc, mock_ski, mock_aki, mock_ku, mock_eku):
        """ test _cert_extension_dic_parse()"""
        cert = Mock()
        mock_bc.return_value = 'mock_bc'
        mock_ski.from_public_key.return_value = 'mock_ski'
        mock_aki.from_issuer_public_key.return_value = 'mock_aki'
        mock_ku.return_value = 'mock_ku'
        mock_eku.return_value = 'mock_eku'
        cert_extension_dic = {'subjectKeyIdentifier': {'critical': True, 'value': 'value'}}
        result = [{'critical': True, 'name': 'mock_ski'}]
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual(result, self.cahandler._cert_extension_dic_parse(cert_extension_dic, cert, cert))
        self.assertIn('INFO:test_a2c:CAhandler.cert_extesion_dic_parse(): subjectKeyIdentifier', lcm.output)

    @patch('examples.ca_handler.openssl_ca_handler.ExtendedKeyUsage')
    @patch('examples.ca_handler.openssl_ca_handler.KeyUsage')
    @patch('examples.ca_handler.openssl_ca_handler.AuthorityKeyIdentifier')
    @patch('examples.ca_handler.openssl_ca_handler.SubjectKeyIdentifier')
    @patch('examples.ca_handler.openssl_ca_handler.BasicConstraints')
    def test_119__cert_extension_dic_parse(self,  mock_bc, mock_ski, mock_aki, mock_ku, mock_eku):
        """ test _cert_extension_dic_parse()"""
        cert = Mock()
        mock_bc.return_value = 'mock_bc'
        mock_ski.from_public_key.return_value = 'mock_ski'
        mock_aki.from_issuer_public_key.return_value = 'mock_aki'
        mock_ku.return_value = 'mock_ku'
        mock_eku.return_value = 'mock_eku'
        cert_extension_dic = {'authorityKeyIdentifier': {'critical': True, 'value': 'value'}}
        result = [{'critical': True, 'name': 'mock_aki'}]
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual(result, self.cahandler._cert_extension_dic_parse(cert_extension_dic, cert, cert))
        self.assertIn('INFO:test_a2c:CAhandler.cert_extesion_dic_parse(): authorityKeyIdentifier', lcm.output)

    @patch('examples.ca_handler.openssl_ca_handler.ExtendedKeyUsage')
    @patch('examples.ca_handler.openssl_ca_handler.KeyUsage')
    @patch('examples.ca_handler.openssl_ca_handler.AuthorityKeyIdentifier')
    @patch('examples.ca_handler.openssl_ca_handler.SubjectKeyIdentifier')
    @patch('examples.ca_handler.openssl_ca_handler.BasicConstraints')
    def test_120__cert_extension_dic_parse(self,  mock_bc, mock_ski, mock_aki, mock_ku, mock_eku):
        """ test _cert_extension_dic_parse()"""
        cert = Mock()
        mock_bc.return_value = 'mock_bc'
        mock_ski.from_public_key.return_value = 'mock_ski'
        mock_aki.from_issuer_public_key.return_value = 'mock_aki'
        mock_ku.return_value = 'mock_ku'
        mock_eku.return_value = 'mock_eku'
        cert_extension_dic = {'keyUsage': {'critical': True, 'value': 'value'}}
        result = [{'critical': True, 'name': 'mock_ku'}]
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual(result, self.cahandler._cert_extension_dic_parse(cert_extension_dic, cert, cert))
        self.assertIn('INFO:test_a2c:CAhandler.cert_extesion_dic_parse(): keyUsage', lcm.output)

    @patch('examples.ca_handler.openssl_ca_handler.ExtendedKeyUsage')
    @patch('examples.ca_handler.openssl_ca_handler.KeyUsage')
    @patch('examples.ca_handler.openssl_ca_handler.AuthorityKeyIdentifier')
    @patch('examples.ca_handler.openssl_ca_handler.SubjectKeyIdentifier')
    @patch('examples.ca_handler.openssl_ca_handler.BasicConstraints')
    def test_121__cert_extension_dic_parse(self,  mock_bc, mock_ski, mock_aki, mock_ku, mock_eku):
        """ test _cert_extension_dic_parse()"""
        cert = Mock()
        mock_bc.return_value = 'mock_bc'
        mock_ski.from_public_key.return_value = 'mock_ski'
        mock_aki.from_issuer_public_key.return_value = 'mock_aki'
        mock_ku.return_value = 'mock_ku'
        mock_eku.return_value = 'mock_eku'
        cert_extension_dic = {'extendedKeyUsage': {'critical': True, 'value': 'value'}}
        result = [{'critical': True, 'name': 'mock_eku'}]
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual(result, self.cahandler._cert_extension_dic_parse(cert_extension_dic, cert, cert))
        self.assertIn('INFO:test_a2c:CAhandler.cert_extesion_dic_parse(): extendedKeyUsage', lcm.output)

    @patch('examples.ca_handler.xca_ca_handler.x509.CertificateBuilder')
    def test_122__cert_signing_prep(self, mock_builder):
        """ test _cert_extension_dic_parse()"""
        req = cert = Mock()
        self.assertTrue(self.cahandler._cert_signing_prep(cert, req, 'subject'))


    @patch('examples.ca_handler.openssl_ca_handler.ExtendedKeyUsage')
    @patch('examples.ca_handler.openssl_ca_handler.KeyUsage')
    @patch('examples.ca_handler.openssl_ca_handler.AuthorityKeyIdentifier')
    @patch('examples.ca_handler.openssl_ca_handler.SubjectKeyIdentifier')
    @patch('examples.ca_handler.openssl_ca_handler.BasicConstraints')
    def test_123__cert_extension_default(self, mock_bc, mock_ski, mock_aki, mock_ku, mock_eku):
        """ test _cert_extension_default()"""
        mock_bc.return_value = 'mock_bc'
        mock_ski.from_public_key.return_value = 'mock_ski'
        mock_aki.from_issuer_public_key.return_value = 'mock_aki'
        mock_ku.return_value = 'mock_ku'
        mock_eku.return_value = 'mock_eku'
        result = [{'name': 'mock_bc', 'critical': True}, {'name': 'mock_eku', 'critical': False}, {'name': 'mock_ku', 'critical': True}]
        self.assertEqual(result, self.cahandler._cert_extension_default(False, False))

    @patch('examples.ca_handler.openssl_ca_handler.ExtendedKeyUsage')
    @patch('examples.ca_handler.openssl_ca_handler.KeyUsage')
    @patch('examples.ca_handler.openssl_ca_handler.AuthorityKeyIdentifier')
    @patch('examples.ca_handler.openssl_ca_handler.SubjectKeyIdentifier')
    @patch('examples.ca_handler.openssl_ca_handler.BasicConstraints')
    def test_124__cert_extension_default(self, mock_bc, mock_ski, mock_aki, mock_ku, mock_eku):
        """ test _cert_extension_default()"""
        cert = Mock()
        mock_bc.return_value = 'mock_bc'
        mock_ski.from_public_key.return_value = 'mock_ski'
        mock_aki.from_issuer_public_key.return_value = 'mock_aki'
        mock_ku.return_value = 'mock_ku'
        mock_eku.return_value = 'mock_eku'
        result = [{'name': 'mock_bc', 'critical': True}, {'name': 'mock_eku', 'critical': False}, {'name': 'mock_ku', 'critical': True}, {'name': 'mock_aki', 'critical': False}]
        self.assertEqual(result, self.cahandler._cert_extension_default(cert, False))

    @patch('examples.ca_handler.openssl_ca_handler.ExtendedKeyUsage')
    @patch('examples.ca_handler.openssl_ca_handler.KeyUsage')
    @patch('examples.ca_handler.openssl_ca_handler.AuthorityKeyIdentifier')
    @patch('examples.ca_handler.openssl_ca_handler.SubjectKeyIdentifier')
    @patch('examples.ca_handler.openssl_ca_handler.BasicConstraints')
    def test_125__cert_extension_default(self, mock_bc, mock_ski, mock_aki, mock_ku, mock_eku):
        """ test _cert_extension_default()"""
        cert = Mock()
        mock_bc.return_value = 'mock_bc'
        mock_ski.from_public_key.return_value = 'mock_ski'
        mock_aki.from_issuer_public_key.return_value = 'mock_aki'
        mock_ku.return_value = 'mock_ku'
        mock_eku.return_value = 'mock_eku'
        result = [{'name': 'mock_bc', 'critical': True}, {'name': 'mock_eku', 'critical': False}, {'name': 'mock_ku', 'critical': True}, {'name': 'mock_ski', 'critical': False}]
        self.assertEqual(result, self.cahandler._cert_extension_default(False, cert))

    @patch('examples.ca_handler.openssl_ca_handler.ExtendedKeyUsage')
    @patch('examples.ca_handler.openssl_ca_handler.KeyUsage')
    @patch('examples.ca_handler.openssl_ca_handler.AuthorityKeyIdentifier')
    @patch('examples.ca_handler.openssl_ca_handler.SubjectKeyIdentifier')
    @patch('examples.ca_handler.openssl_ca_handler.BasicConstraints')
    def test_126__cert_extension_default(self, mock_bc, mock_ski, mock_aki, mock_ku, mock_eku):
        """ test _cert_extension_default()"""
        cert = Mock()
        mock_bc.return_value = 'mock_bc'
        mock_ski.from_public_key.return_value = 'mock_ski'
        mock_aki.from_issuer_public_key.return_value = 'mock_aki'
        mock_ku.return_value = 'mock_ku'
        mock_eku.return_value = 'mock_eku'
        result = [{'name': 'mock_bc', 'critical': True}, {'name': 'mock_eku', 'critical': False}, {'name': 'mock_ku', 'critical': True}, {'name': 'mock_ski', 'critical': False}, {'name': 'mock_aki', 'critical': False}]
        self.assertEqual(result, self.cahandler._cert_extension_default(cert, cert))

    @patch('examples.ca_handler.openssl_ca_handler.SubjectAlternativeName')
    @patch('examples.ca_handler.openssl_ca_handler.CAhandler._cert_extension_default')
    @patch('examples.ca_handler.openssl_ca_handler.CAhandler._cert_extension_dic_parse')
    @patch('examples.ca_handler.openssl_ca_handler.CAhandler._certificate_extensions_load')
    def test_127__cert_extension_apply(self, mock_cel, mock_cep, mock_ced, mock_san):
        """ test _cert_extension_apply() """

        mock_cel.return_value = {'foo': 'bar'}
        mock_cep.return_value = [{'name': 'mock_cep', 'critical': False}]
        mock_ced.return_value = [{'name': 'mock_ced', 'critical': False}]
        mock_san.return_value = 'mock_san'
        cert = Mock()
        builder = Mock()
        self.assertTrue(self.cahandler._cert_extension_apply(builder, cert, None))
        self.assertFalse(mock_cel.called)
        self.assertFalse(mock_cep.called)
        self.assertTrue(mock_ced.called)
        self.assertFalse(mock_san.called)

    @patch('examples.ca_handler.openssl_ca_handler.SubjectAlternativeName')
    @patch('examples.ca_handler.openssl_ca_handler.CAhandler._cert_extension_default')
    @patch('examples.ca_handler.openssl_ca_handler.CAhandler._cert_extension_dic_parse')
    @patch('examples.ca_handler.openssl_ca_handler.CAhandler._certificate_extensions_load')
    def test_128__cert_extension_apply(self, mock_cel, mock_cep, mock_ced, mock_san):
        """ test _cert_extension_apply() """

        mock_cel.return_value = {'foo': 'bar'}
        mock_cep.return_value = [{'name': 'mock_cep', 'critical': False}]
        mock_ced.return_value = [{'name': 'mock_ced', 'critical': False}]
        mock_san.return_value = 'mock_san'
        cert = Mock()
        builder = Mock()
        self.cahandler.openssl_conf = 'openssl_conf'
        self.assertTrue(self.cahandler._cert_extension_apply(builder, cert, None))
        self.assertTrue(mock_cel.called)
        self.assertTrue(mock_cep.called)
        self.assertFalse(mock_ced.called)
        self.assertFalse(mock_san.called)

    @patch('examples.ca_handler.openssl_ca_handler.SubjectAlternativeName')
    @patch('examples.ca_handler.openssl_ca_handler.CAhandler._cert_extension_default')
    @patch('examples.ca_handler.openssl_ca_handler.CAhandler._cert_extension_dic_parse')
    @patch('examples.ca_handler.openssl_ca_handler.CAhandler._certificate_extensions_load')
    def test_129__cert_extension_apply(self, mock_cel, mock_cep, mock_ced, mock_san):
        """ test _cert_extension_apply() """
        mock_cel.return_value = {'foo': 'bar'}
        mock_cep.return_value = [{'name': 'mock_cep', 'critical': False}]
        mock_ced.return_value = [{'name': 'mock_ced', 'critical': False}]
        mock_san.return_value = 'mock_san'
        req = Mock()
        ext1 = Mock()
        ext1.oid._name = 'subjectAltName'
        ext2 = Mock()
        ext2.oid._name = 'mock_ext'
        req.extensions = [ext1, ext2]
        cert = Mock()
        builder = Mock()
        self.assertTrue(self.cahandler._cert_extension_apply(builder, cert, req))
        self.assertFalse(mock_cel.called)
        self.assertFalse(mock_cep.called)
        self.assertTrue(mock_ced.called)
        self.assertTrue(mock_san.called)

    @patch("builtins.open", mock_open(read_data='cacert'), create=True)
    @patch('examples.ca_handler.openssl_ca_handler.x509.NameAttribute')
    @patch('examples.ca_handler.openssl_ca_handler.x509.Name')
    @patch('base64.b64encode')
    @patch('examples.ca_handler.openssl_ca_handler.convert_byte_to_string')
    @patch('examples.ca_handler.openssl_ca_handler.CAhandler._pemcertchain_generate')
    @patch('examples.ca_handler.openssl_ca_handler.CAhandler._certificate_store')
    @patch('examples.ca_handler.openssl_ca_handler.CAhandler._cert_extension_apply')
    @patch('examples.ca_handler.openssl_ca_handler.CAhandler._cert_signing_prep')
    @patch('examples.ca_handler.openssl_ca_handler.x509.load_pem_x509_csr')
    @patch('examples.ca_handler.openssl_ca_handler.convert_string_to_byte')
    @patch('examples.ca_handler.openssl_ca_handler.CAhandler._ca_load')
    @patch('examples.ca_handler.openssl_ca_handler.build_pem_file')
    @patch('examples.ca_handler.openssl_ca_handler.b64_url_recode')
    @patch('examples.ca_handler.openssl_ca_handler.CAhandler._csr_check')
    @patch('examples.ca_handler.openssl_ca_handler.CAhandler._config_check')
    def test_130_enroll(self, mock_cfgchk, mock_csrchk, mock_recode, mock_bpf, mock_caload, mock_c2b, mock_csrload, mock_csp, mock_csa, mock_store, mock_pem, mock_b2s, mock_b64e, mock_name, mock_nameattr):
        """ enroll test  """
        mock_cfgchk.return_value = False
        mock_csrchk.return_value = (True, 'enforce_cn')
        mock_caload.return_value = ('key', 'cert')
        mock_pem.return_value = 'mock_pem'
        mock_b2s.return_value = 'mock_b2s'
        self.assertEqual((False, 'mock_pem', 'mock_b2s', None), self.cahandler.enroll('csr'))
        self.assertTrue(mock_cfgchk.called)
        self.assertTrue(mock_csrchk.called)
        self.assertTrue(mock_caload.called)
        self.assertTrue(mock_pem.called)
        self.assertTrue(mock_b2s.called)
        self.assertTrue(mock_c2b.called)
        self.assertTrue(mock_csrload.called)
        self.assertTrue(mock_csp.called)
        self.assertTrue(mock_csa.called)
        self.assertTrue(mock_store.called)
        self.assertTrue(mock_bpf.called)
        self.assertTrue(mock_b64e.called)
        self.assertFalse(mock_name.called)
        self.assertFalse(mock_nameattr.called)

    @patch("builtins.open", mock_open(read_data='cacert'), create=True)
    @patch('examples.ca_handler.openssl_ca_handler.x509.NameAttribute')
    @patch('examples.ca_handler.openssl_ca_handler.x509.Name')
    @patch('base64.b64encode')
    @patch('examples.ca_handler.openssl_ca_handler.convert_byte_to_string')
    @patch('examples.ca_handler.openssl_ca_handler.CAhandler._pemcertchain_generate')
    @patch('examples.ca_handler.openssl_ca_handler.CAhandler._certificate_store')
    @patch('examples.ca_handler.openssl_ca_handler.CAhandler._cert_extension_apply')
    @patch('examples.ca_handler.openssl_ca_handler.CAhandler._cert_signing_prep')
    @patch('examples.ca_handler.openssl_ca_handler.x509.load_pem_x509_csr')
    @patch('examples.ca_handler.openssl_ca_handler.convert_string_to_byte')
    @patch('examples.ca_handler.openssl_ca_handler.CAhandler._ca_load')
    @patch('examples.ca_handler.openssl_ca_handler.build_pem_file')
    @patch('examples.ca_handler.openssl_ca_handler.b64_url_recode')
    @patch('examples.ca_handler.openssl_ca_handler.CAhandler._csr_check')
    @patch('examples.ca_handler.openssl_ca_handler.CAhandler._config_check')
    def test_131_enroll(self, mock_cfgchk, mock_csrchk, mock_recode, mock_bpf, mock_caload, mock_c2b, mock_csrload, mock_csp, mock_csa, mock_store, mock_pem, mock_b2s, mock_b64e, mock_name, mock_nameattr):
        """ enroll test config check failed """
        mock_cfgchk.return_value = 'error'
        mock_csrchk.return_value = (True, 'enforce_cn')
        mock_caload.return_value = ('key', 'cert')
        mock_pem.return_value = 'mock_pem'
        mock_b2s.return_value = 'mock_b2s'
        self.assertEqual(('error', None, None, None), self.cahandler.enroll('csr'))
        self.assertTrue(mock_cfgchk.called)
        self.assertFalse(mock_csrchk.called)
        self.assertFalse(mock_caload.called)
        self.assertFalse(mock_pem.called)
        self.assertFalse(mock_b2s.called)
        self.assertFalse(mock_c2b.called)
        self.assertFalse(mock_csrload.called)
        self.assertFalse(mock_csp.called)
        self.assertFalse(mock_csa.called)
        self.assertFalse(mock_store.called)
        self.assertFalse(mock_bpf.called)
        self.assertFalse(mock_b64e.called)
        self.assertFalse(mock_name.called)
        self.assertFalse(mock_nameattr.called)

    @patch("builtins.open", mock_open(read_data='cacert'), create=True)
    @patch('examples.ca_handler.openssl_ca_handler.x509.NameAttribute')
    @patch('examples.ca_handler.openssl_ca_handler.x509.Name')
    @patch('base64.b64encode')
    @patch('examples.ca_handler.openssl_ca_handler.convert_byte_to_string')
    @patch('examples.ca_handler.openssl_ca_handler.CAhandler._pemcertchain_generate')
    @patch('examples.ca_handler.openssl_ca_handler.CAhandler._certificate_store')
    @patch('examples.ca_handler.openssl_ca_handler.CAhandler._cert_extension_apply')
    @patch('examples.ca_handler.openssl_ca_handler.CAhandler._cert_signing_prep')
    @patch('examples.ca_handler.openssl_ca_handler.x509.load_pem_x509_csr')
    @patch('examples.ca_handler.openssl_ca_handler.convert_string_to_byte')
    @patch('examples.ca_handler.openssl_ca_handler.CAhandler._ca_load')
    @patch('examples.ca_handler.openssl_ca_handler.build_pem_file')
    @patch('examples.ca_handler.openssl_ca_handler.b64_url_recode')
    @patch('examples.ca_handler.openssl_ca_handler.CAhandler._csr_check')
    @patch('examples.ca_handler.openssl_ca_handler.CAhandler._config_check')
    def test_132_enroll(self, mock_cfgchk, mock_csrchk, mock_recode, mock_bpf, mock_caload, mock_c2b, mock_csrload, mock_csp, mock_csa, mock_store, mock_pem, mock_b2s, mock_b64e, mock_name, mock_nameattr):
        """ enroll test config check failed """
        mock_cfgchk.return_value = False
        mock_csrchk.return_value = (False, 'enforce_cn')
        mock_caload.return_value = ('key', 'cert')
        mock_pem.return_value = 'mock_pem'
        mock_b2s.return_value = 'mock_b2s'
        self.assertEqual(('urn:ietf:params:acme:badCSR', None, None, None), self.cahandler.enroll('csr'))
        self.assertTrue(mock_cfgchk.called)
        self.assertTrue(mock_csrchk.called)
        self.assertFalse(mock_caload.called)
        self.assertFalse(mock_pem.called)
        self.assertFalse(mock_b2s.called)
        self.assertFalse(mock_c2b.called)
        self.assertFalse(mock_csrload.called)
        self.assertFalse(mock_csp.called)
        self.assertFalse(mock_csa.called)
        self.assertFalse(mock_store.called)
        self.assertFalse(mock_bpf.called)
        self.assertFalse(mock_b64e.called)
        self.assertFalse(mock_name.called)
        self.assertFalse(mock_nameattr.called)

    @patch("builtins.open", mock_open(read_data='cacert'), create=True)
    @patch('examples.ca_handler.openssl_ca_handler.x509.NameAttribute')
    @patch('examples.ca_handler.openssl_ca_handler.x509.Name')
    @patch('base64.b64encode')
    @patch('examples.ca_handler.openssl_ca_handler.convert_byte_to_string')
    @patch('examples.ca_handler.openssl_ca_handler.CAhandler._pemcertchain_generate')
    @patch('examples.ca_handler.openssl_ca_handler.CAhandler._certificate_store')
    @patch('examples.ca_handler.openssl_ca_handler.CAhandler._cert_extension_apply')
    @patch('examples.ca_handler.openssl_ca_handler.CAhandler._cert_signing_prep')
    @patch('examples.ca_handler.openssl_ca_handler.x509.load_pem_x509_csr')
    @patch('examples.ca_handler.openssl_ca_handler.convert_string_to_byte')
    @patch('examples.ca_handler.openssl_ca_handler.CAhandler._ca_load')
    @patch('examples.ca_handler.openssl_ca_handler.build_pem_file')
    @patch('examples.ca_handler.openssl_ca_handler.b64_url_recode')
    @patch('examples.ca_handler.openssl_ca_handler.CAhandler._csr_check')
    @patch('examples.ca_handler.openssl_ca_handler.CAhandler._config_check')
    def test_133_enroll(self, mock_cfgchk, mock_csrchk, mock_recode, mock_bpf, mock_caload, mock_c2b, mock_csrload, mock_csp, mock_csa, mock_store, mock_pem, mock_b2s, mock_b64e, mock_name, mock_nameattr):
        """ enroll test config check failed """
        mock_cfgchk.return_value = None
        mock_csrchk.side_effect = Exception('exc_csr_check')
        mock_caload.return_value = ('key', 'cert')
        mock_pem.return_value = 'mock_pem'
        mock_b2s.return_value = 'mock_b2s'
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual(('Unknown exception', None, None, None), self.cahandler.enroll('csr'))
        self.assertIn('ERROR:test_a2c:CAhandler.enroll() error: exc_csr_check', lcm.output)
        self.assertTrue(mock_cfgchk.called)
        self.assertTrue(mock_csrchk.called)
        self.assertFalse(mock_caload.called)
        self.assertFalse(mock_pem.called)
        self.assertFalse(mock_b2s.called)
        self.assertFalse(mock_c2b.called)
        self.assertFalse(mock_csrload.called)
        self.assertFalse(mock_csp.called)
        self.assertFalse(mock_csa.called)
        self.assertFalse(mock_store.called)
        self.assertFalse(mock_bpf.called)
        self.assertFalse(mock_b64e.called)
        self.assertFalse(mock_name.called)
        self.assertFalse(mock_nameattr.called)

    @patch("builtins.open", mock_open(read_data='cacert'), create=True)
    @patch('examples.ca_handler.openssl_ca_handler.x509.NameAttribute')
    @patch('examples.ca_handler.openssl_ca_handler.x509.Name')
    @patch('base64.b64encode')
    @patch('examples.ca_handler.openssl_ca_handler.convert_byte_to_string')
    @patch('examples.ca_handler.openssl_ca_handler.CAhandler._pemcertchain_generate')
    @patch('examples.ca_handler.openssl_ca_handler.CAhandler._certificate_store')
    @patch('examples.ca_handler.openssl_ca_handler.CAhandler._cert_extension_apply')
    @patch('examples.ca_handler.openssl_ca_handler.CAhandler._cert_signing_prep')
    @patch('examples.ca_handler.openssl_ca_handler.x509.load_pem_x509_csr')
    @patch('examples.ca_handler.openssl_ca_handler.convert_string_to_byte')
    @patch('examples.ca_handler.openssl_ca_handler.CAhandler._ca_load')
    @patch('examples.ca_handler.openssl_ca_handler.build_pem_file')
    @patch('examples.ca_handler.openssl_ca_handler.b64_url_recode')
    @patch('examples.ca_handler.openssl_ca_handler.CAhandler._csr_check')
    @patch('examples.ca_handler.openssl_ca_handler.CAhandler._config_check')
    def test_134_enroll(self, mock_cfgchk, mock_csrchk, mock_recode, mock_bpf, mock_caload, mock_c2b, mock_csrload, mock_csp, mock_csa, mock_store, mock_pem, mock_b2s, mock_b64e, mock_name, mock_nameattr):
        """ enroll test  """
        mock_cfgchk.return_value = False
        mock_csrchk.return_value = (True, 'enforce_cn')
        mock_caload.return_value = ('key', 'cert')
        mock_pem.return_value = 'mock_pem'
        mock_b2s.return_value = 'mock_b2s'
        self.cahandler.cn_enforce = True
        mock_csrload.return_value.subject = None
        self.assertEqual((False, 'mock_pem', 'mock_b2s', None), self.cahandler.enroll('csr'))
        self.assertTrue(mock_cfgchk.called)
        self.assertTrue(mock_csrchk.called)
        self.assertTrue(mock_caload.called)
        self.assertTrue(mock_pem.called)
        self.assertTrue(mock_b2s.called)
        self.assertTrue(mock_c2b.called)
        self.assertTrue(mock_csrload.called)
        self.assertTrue(mock_csp.called)
        self.assertTrue(mock_csa.called)
        self.assertTrue(mock_store.called)
        self.assertTrue(mock_bpf.called)
        self.assertTrue(mock_b64e.called)
        self.assertTrue(mock_name.called)
        self.assertTrue(mock_nameattr.called)

    @patch("builtins.open", mock_open(read_data='test'), create=True)
    @patch('datetime.datetime')
    @patch('os.path.exists')
    @patch('examples.ca_handler.openssl_ca_handler.x509.RevokedCertificateBuilder')
    @patch('examples.ca_handler.openssl_ca_handler.x509.CertificateRevocationListBuilder')
    @patch('examples.ca_handler.openssl_ca_handler.x509.load_pem_x509_crl')
    @patch('examples.ca_handler.openssl_ca_handler.cert_serial_get')
    @patch('examples.ca_handler.openssl_ca_handler.CAhandler._ca_load')
    @patch('examples.ca_handler.openssl_ca_handler.uts_now')
    @patch('examples.ca_handler.openssl_ca_handler.uts_to_date_utc')
    def test_135_revoke(self, mock_uts, mock_now, mock_ca_load, mock_serial, mock_crl, mock_certbuilder, mock_revoke, mock_file, mock_datetime):
        """ test revoke)() """
        self.cahandler.issuer_dict = {'issuing_ca_crl' : 'issuing_ca_crl'}
        mock_ca_load.return_value = ('ca_key', 'ca_cert')
        mock_serial.return_value = 42
        mock_crl = Mock()
        mock_crl.issuer = 'issuer'
        mock_file.return_value = True
        mock_now.return_value = 'now'
        mock_datetime.utcnow.return_value.utctimetuple.return_value = 'utcnow'
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual((200, None, None), self.cahandler.revoke('cert'))
        self.assertIn('INFO:test_a2c:CAhandler.revoke(): load existing crl issuing_ca_crl)', lcm.output)
        self.assertTrue(mock_ca_load.called)
        self.assertTrue(mock_serial.called)
        self.assertTrue(mock_certbuilder.called)
        self.assertTrue(mock_revoke.called)
        self.assertTrue(mock_file.called)
        self.assertTrue(mock_now.called)

    @patch("builtins.open", mock_open(read_data='test'), create=True)
    @patch('datetime.datetime')
    @patch('os.path.exists')
    @patch('examples.ca_handler.openssl_ca_handler.x509.RevokedCertificateBuilder')
    @patch('examples.ca_handler.openssl_ca_handler.x509.CertificateRevocationListBuilder')
    @patch('examples.ca_handler.openssl_ca_handler.x509.load_pem_x509_crl')
    @patch('examples.ca_handler.openssl_ca_handler.cert_serial_get')
    @patch('examples.ca_handler.openssl_ca_handler.CAhandler._ca_load')
    @patch('examples.ca_handler.openssl_ca_handler.uts_now')
    @patch('examples.ca_handler.openssl_ca_handler.uts_to_date_utc')
    def test_136_revoke(self, mock_uts, mock_now, mock_ca_load, mock_serial, mock_crl, mock_certbuilder, mock_revoke, mock_file, mock_datetime):
        """ test revoke)() """
        self.cahandler.issuer_dict = {'issuing_ca_crl' : 'issuing_ca_crl'}
        mock_ca_load.return_value = ('ca_key', Mock())
        mock_serial.return_value = 42
        mock_crl = Mock()
        mock_crl.issuer = 'issuer'
        mock_file.return_value = False
        mock_now.return_value = 'now'
        mock_datetime.utcnow.return_value.utctimetuple.return_value = 'utcnow'
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual((200, None, None), self.cahandler.revoke('cert'))
        self.assertIn('INFO:test_a2c:CAhandler._crlobject_build(): create new crl issuing_ca_crl)', lcm.output)
        self.assertTrue(mock_ca_load.called)
        self.assertTrue(mock_serial.called)
        self.assertTrue(mock_certbuilder.called)
        self.assertTrue(mock_revoke.called)
        self.assertTrue(mock_file.called)
        self.assertTrue(mock_now.called)

    @patch("builtins.open", mock_open(read_data='test'), create=True)
    @patch('examples.ca_handler.openssl_ca_handler.isinstance', return_value=True)
    @patch('datetime.datetime')
    @patch('os.path.exists')
    @patch('examples.ca_handler.openssl_ca_handler.x509.RevokedCertificateBuilder')
    @patch('examples.ca_handler.openssl_ca_handler.x509.CertificateRevocationListBuilder')
    @patch('examples.ca_handler.openssl_ca_handler.x509.load_pem_x509_crl')
    @patch('examples.ca_handler.openssl_ca_handler.cert_serial_get')
    @patch('examples.ca_handler.openssl_ca_handler.CAhandler._ca_load')
    @patch('examples.ca_handler.openssl_ca_handler.uts_now')
    @patch('examples.ca_handler.openssl_ca_handler.uts_to_date_utc')
    def test_137_revoke(self, mock_uts, mock_now, mock_ca_load, mock_serial, mock_crl, mock_certbuilder, mock_revoke, mock_file, mock_datetime, mock_instance):
        """ test revoke)() """
        self.cahandler.issuer_dict = {'issuing_ca_crl' : 'issuing_ca_crl'}
        mock_ca_load.return_value = ('ca_key', Mock())
        mock_serial.return_value = 42
        mock_crl = Mock()
        mock_crl.issuer = 'issuer'
        mock_file.return_value = True
        mock_now.return_value = 'now'
        mock_datetime.utcnow.return_value.utctimetuple.return_value = 'utcnow'
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual((400, 'urn:ietf:params:acme:error:alreadyRevoked', 'Certificate has already been revoked'), self.cahandler.revoke('cert'))
        self.assertIn('INFO:test_a2c:CAhandler.revoke(): load existing crl issuing_ca_crl)', lcm.output)
        self.assertTrue(mock_ca_load.called)
        self.assertTrue(mock_serial.called)
        self.assertTrue(mock_certbuilder.called)
        self.assertFalse(mock_revoke.called)
        self.assertTrue(mock_file.called)
        self.assertTrue(mock_now.called)

    @patch('examples.ca_handler.openssl_ca_handler.datetime')
    @patch('examples.ca_handler.openssl_ca_handler.CAhandler._cert_expiry_get')
    @patch("builtins.open", mock_open(read_data='test'), create=True)
    @patch('os.path.exists')
    @patch('examples.ca_handler.openssl_ca_handler.x509.load_pem_x509_certificate')
    def test_138__cacert_expiry_get(self, mock_certload, mock_exists, mock_exp, mock_now):
        """ test _cacert_expiry_get() """
        mock_certload.return_value = 'cert1'
        mock_exp.return_value = datetime.datetime(2024, 12, 31, 5, 0, 1)
        mock_now.datetime.now.return_value = datetime.datetime(2023, 12, 31, 5, 0, 1)
        mock_exists.return_value = True
        self.cahandler.ca_cert_chain_list = ['cacert1']
        self.assertEqual((366, 'cert1'), self.cahandler._cacert_expiry_get())

    @patch('examples.ca_handler.openssl_ca_handler.datetime')
    @patch('examples.ca_handler.openssl_ca_handler.CAhandler._cert_expiry_get')
    @patch("builtins.open", mock_open(read_data='test'), create=True)
    @patch('os.path.exists')
    @patch('examples.ca_handler.openssl_ca_handler.x509.load_pem_x509_certificate')
    def test_139__cacert_expiry_get(self, mock_certload, mock_exists, mock_exp, mock_now):
        """ test _cacert_expiry_get() """
        mock_certload.side_effect = ['cert1', 'cert2']
        mock_exp.side_effect = [datetime.datetime(2024, 12, 31, 5, 0, 1), datetime.datetime(2024, 11, 30, 5, 0, 1)]
        mock_now.datetime.now.return_value = datetime.datetime(2023, 12, 31, 5, 0, 1)
        mock_exists.return_value = True
        self.cahandler.ca_cert_chain_list = ['cacert1', 'cacert2']
        self.assertEqual((335, 'cert2'), self.cahandler._cacert_expiry_get())

    @patch('examples.ca_handler.openssl_ca_handler.datetime')
    @patch('examples.ca_handler.openssl_ca_handler.CAhandler._cert_expiry_get')
    @patch("builtins.open", mock_open(read_data='test'), create=True)
    @patch('os.path.exists')
    @patch('examples.ca_handler.openssl_ca_handler.x509.load_pem_x509_certificate')
    def test_140__cacert_expiry_get(self, mock_certload, mock_exists, mock_exp, mock_now):
        """ test _cacert_expiry_get() """
        mock_certload.side_effect = ['cert1', 'cert2']
        mock_exp.side_effect = [datetime.datetime(2024, 10, 30, 5, 0, 1), datetime.datetime(2024, 12, 31, 5, 0, 1)]
        mock_now.datetime.now.return_value = datetime.datetime(2023, 12, 31, 5, 0, 1)
        mock_exists.return_value = True
        self.cahandler.ca_cert_chain_list = ['cacert1', 'cacert2']
        self.assertEqual((304, 'cert1'), self.cahandler._cacert_expiry_get())

    @patch('examples.ca_handler.openssl_ca_handler.datetime')
    @patch('examples.ca_handler.openssl_ca_handler.CAhandler._cert_expiry_get')
    @patch("builtins.open", mock_open(read_data='test'), create=True)
    @patch('os.path.exists')
    @patch('examples.ca_handler.openssl_ca_handler.x509.load_pem_x509_certificate')
    def test_141__cacert_expiry_get(self, mock_certload, mock_exists, mock_exp, mock_now):
        """ test _cacert_expiry_get() """
        mock_certload.side_effect = ['cert1', 'issuing_ca_cert']
        mock_exp.side_effect = [datetime.datetime(2024, 12, 31, 5, 0, 1), datetime.datetime(2024, 11, 30, 5, 0, 1)]
        mock_now.datetime.now.return_value = datetime.datetime(2023, 12, 31, 5, 0, 1)
        mock_exists.return_value = True
        self.cahandler.ca_cert_chain_list = ['cacert1']
        self.cahandler.issuer_dict = {'issuing_ca_cert' : 'issuing_ca_cert'}
        self.assertEqual((335, 'issuing_ca_cert'), self.cahandler._cacert_expiry_get())

    @patch('examples.ca_handler.openssl_ca_handler.datetime')
    @patch('examples.ca_handler.openssl_ca_handler.CAhandler._cert_expiry_get')
    @patch("builtins.open", mock_open(read_data='test'), create=True)
    @patch('os.path.exists')
    @patch('examples.ca_handler.openssl_ca_handler.x509.load_pem_x509_certificate')
    def test_142__cacert_expiry_get(self, mock_certload, mock_exists, mock_exp, mock_now):
        """ test _cacert_expiry_get() """
        mock_certload.side_effect = ['cert1', 'issuing_ca_cert']
        mock_exp.side_effect = [datetime.datetime(2024, 10, 30, 5, 0, 1), datetime.datetime(2024, 12, 31, 5, 0, 1)]
        mock_now.datetime.now.return_value = datetime.datetime(2023, 12, 31, 5, 0, 1)
        mock_exists.return_value = True
        self.cahandler.ca_cert_chain_list = ['cacert1']
        self.cahandler.issuer_dict = {'issuing_ca_cert' : 'issuing_ca_cert'}
        self.assertEqual((304, 'cert1'), self.cahandler._cacert_expiry_get())

    @patch('examples.ca_handler.openssl_ca_handler.datetime')
    @patch('examples.ca_handler.openssl_ca_handler.CAhandler._cert_expiry_get')
    @patch("builtins.open", mock_open(read_data='test'), create=True)
    @patch('os.path.exists')
    @patch('examples.ca_handler.openssl_ca_handler.x509.load_pem_x509_certificate')
    def test_143__cacert_expiry_get(self, mock_certload, mock_exists, mock_exp, mock_now):
        """ test _cacert_expiry_get() """
        mock_certload.side_effect = ['cert1', 'cert2']
        mock_exp.side_effect = [datetime.datetime(2024, 12, 31, 5, 0, 1), datetime.datetime(2024, 11, 30, 5, 0, 1)]
        mock_now.datetime.now.return_value = datetime.datetime(2023, 12, 31, 5, 0, 1)
        mock_exists.side_effect = [True, False]
        self.cahandler.ca_cert_chain_list = ['cacert1', 'cacert2']
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual((366, 'cert1'), self.cahandler._cacert_expiry_get())
        self.assertIn('ERROR:test_a2c:CAhandler._cacert_expiry_get(): file cacert2 does not exist', lcm.output)

    def test_144__cert_expiry_get(self):
        """ test _cert_expiry_get() """
        cert = Mock()
        cert.not_valid_after = 'not_valid_after'
        self.assertEqual('not_valid_after', self.cahandler._cert_expiry_get(cert))

    @patch('examples.ca_handler.openssl_ca_handler.datetime')
    def test_145__certexpiry_date_default(self, mock_now):
        """ test _certexpiry_date_default() """
        mock_now.datetime.now.return_value = datetime.datetime(2023, 12, 31, 5, 0, 1)
        mock_now.timedelta.return_value = datetime.timedelta(days=2)
        self.assertEqual(datetime.datetime(2024, 1, 2, 5, 0, 1), self.cahandler._certexpiry_date_default())

    @patch('examples.ca_handler.openssl_ca_handler.CAhandler._cacert_expiry_get')
    @patch('examples.ca_handler.openssl_ca_handler.CAhandler._certexpiry_date_default')
    def test_146__certexpiry_date_set(self, mock_default, mock_get):
        """ test _certexpiry_date_set() """
        mock_default.return_value = 365
        mock_get.return_value = (720, 'cert')
        self.assertEqual(365, self.cahandler._certexpiry_date_set())
        self.assertTrue(mock_default.called)
        self.assertFalse(mock_get.called)

    @patch('examples.ca_handler.openssl_ca_handler.CAhandler._cacert_expiry_get')
    @patch('examples.ca_handler.openssl_ca_handler.CAhandler._certexpiry_date_default')
    def test_147__certexpiry_date_set(self, mock_default, mock_get):
        """ test _certexpiry_date_set() """
        mock_default.return_value = 365
        mock_get.return_value = (720, 'cert')
        self.cahandler.cert_validity_adjust = True
        self.cahandler.cert_validity_days = 30
        self.assertEqual(365, self.cahandler._certexpiry_date_set())
        self.assertTrue(mock_default.called)
        self.assertTrue(mock_get.called)

    @patch('examples.ca_handler.openssl_ca_handler.CAhandler._cacert_expiry_get')
    @patch('examples.ca_handler.openssl_ca_handler.CAhandler._certexpiry_date_default')
    def test_148__certexpiry_date_set(self, mock_default, mock_get):
        """ test _certexpiry_date_set() """
        mock_default.return_value = 365
        cert = Mock()
        cert.not_valid_after = 'not_valid_after'
        mock_get.return_value = (20, cert)
        self.cahandler.cert_validity_adjust = True
        self.cahandler.cert_validity_days = 30
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual('not_valid_after', self.cahandler._certexpiry_date_set())
        self.assertIn('INFO:test_a2c:CAhandler._certexpiry_date_set(): adjust validity to 20 days.', lcm.output)
        self.assertTrue(mock_default.called)
        self.assertTrue(mock_get.called)

if __name__ == '__main__':

    unittest.main()
