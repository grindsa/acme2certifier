#!/usr/bin/python
# -*- coding: utf-8 -*-
""" unittests for openssl_ca_handler """
# pylint: disable=C0415, R0904, W0212
import sys
import os
import unittest
import configparser
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
        self.assertEqual('issuing_ca_crl foo.pem does not exist', self.cahandler._config_check())

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

    def test_014_check_serialagainstcrl(self):
        """ CAhandler._crl_check without specifying a CRL"""
        crl = None
        self.assertFalse(self.cahandler._crl_check(crl, 1))

    def test_015_check_serialagainstcrl(self):
        """ CAhandler._crl_check without specifying a serial number"""
        crl = 'foo'
        self.assertFalse(self.cahandler._crl_check(crl, None))

    def test_016_check_serialagainstcrl(self):
        """ CAhandler._crl_check with a serial number not in CRL"""
        with open(self.dir_path + '/ca/sub-ca-crl.pem', 'r') as fso:
            crl = crypto.load_crl(crypto.FILETYPE_PEM, fso.read())
        self.assertFalse(self.cahandler._crl_check(crl, 2))

    def test_017_check_serialagainstcrl(self):
        """ CAhandler._crl_check with a serial number already in CRL"""
        # crl = crypto.load_crl(crypto.FILETYPE_PEM, open(self.dir_path + '/ca/sub-ca-crl.pem').read())
        with open(self.dir_path + '/ca/sub-ca-crl.pem', 'r') as fso:
            crl = crypto.load_crl(crypto.FILETYPE_PEM, fso.read())
        self.assertTrue(self.cahandler._crl_check(crl, '0BCC30C544EF26A4'))

    def test_018_check_serialagainstcrl(self):
        """ CAhandler._crl_check with a serial number already in CRL"""
        # crl = crypto.load_crl(crypto.FILETYPE_PEM, open(self.dir_path + '/ca/sub-ca-crl.pem').read())
        with open(self.dir_path + '/ca/sub-ca-crl.pem', 'r') as fso:
            crl = crypto.load_crl(crypto.FILETYPE_PEM, fso.read())
        self.assertTrue(self.cahandler._crl_check(crl, '0bcc30c544ef26a4'))

    def test_019_generate_pem_chain(self):
        """ CAhandler._pemcertchain_generate with EE cert but no ca cert"""
        self.assertEqual('ee-cert', self.cahandler._pemcertchain_generate('ee-cert', None))

    def test_020_generate_pem_chain(self):
        """ CAhandler._pemcertchain_generate with EE cert and ca cert"""
        self.assertEqual('ee-certca-cert', self.cahandler._pemcertchain_generate('ee-cert', 'ca-cert'))

    def test_021_generate_pem_chain(self):
        """ CAhandler._pemcertchain_generate with EE cert ca and an invalit entry in cert_cain_list cert"""
        self.cahandler.ca_cert_chain_list = ['foo.pem']
        self.assertEqual('ee-certca-cert', self.cahandler._pemcertchain_generate('ee-cert', 'ca-cert'))

    @patch("builtins.open", mock_open(read_data='_fakeroot-cert-1'), create=True)
    @patch('os.path.exists')
    def test_022_generate_pem_chain(self, mock_file):
        """ CAhandler._pemcertchain_generate with EE cert ca and an valid entry in cert_cain_list cert"""
        self.cahandler.ca_cert_chain_list = [self.dir_path + '/ca/fr1.txt']
        mock_file.return_value = True
        mock_open.return_vlaue = 'foo'
        self.assertEqual('ee-cert_ca-cert_fakeroot-cert-1', self.cahandler._pemcertchain_generate('ee-cert', '_ca-cert'))

    @patch("builtins.open", mock_open(read_data='_fakeroot-cert-1'), create=True)
    @patch('os.path.exists')
    def test_023_generate_pem_chain(self, mock_file):
        """ CAhandler._pemcertchain_generate with EE cert ca and two valid entry in cert_cain_list"""
        self.cahandler.ca_cert_chain_list = [self.dir_path + '/ca/fr1.txt', self.dir_path + '/ca/fr2.txt']
        mock_file.side_effect = [True, True]
        self.assertEqual('ee-cert_ca-cert_fakeroot-cert-1_fakeroot-cert-1', self.cahandler._pemcertchain_generate('ee-cert', '_ca-cert'))

    @patch("builtins.open", mock_open(read_data='_fakeroot-cert-1'), create=True)
    @patch('os.path.exists')
    def test_024_generate_pem_chain(self, mock_file):
        """ CAhandler._pemcertchain_generate with EE cert ca and two valid entry in cert_cain_list and two invalid entriest"""
        self.cahandler.ca_cert_chain_list = [self.dir_path + '/ca/fr1.txt', 'foo1', self.dir_path + '/ca/fr2.txt', 'foo2']
        mock_file.side_effect = [True, False, True, False]
        self.assertEqual('ee-cert_ca-cert_fakeroot-cert-1_fakeroot-cert-1', self.cahandler._pemcertchain_generate('ee-cert', '_ca-cert'))

    def test_025_load_ca_key_cert(self):
        """ CAhandler._ca_load() with empty issuer_dict """
        self.cahandler.issuer_dict = {}
        self.assertEqual((None, None), self.cahandler._ca_load())

    def test_026_load_ca_key_cert(self):
        """ CAhandler._ca_load() with issuer_dict containing invalid key """
        self.cahandler.issuer_dict = {'issuing_ca_key': 'foo.pem'}
        self.assertEqual((None, None), self.cahandler._ca_load())

    @patch("builtins.open", mock_open(read_data='test'), create=True)
    @patch('os.path.exists')
    @patch('OpenSSL.crypto.load_privatekey')
    def test_027_load_ca_key_cert(self, mock_crypto, mock_file):
        """ CAhandler._ca_load() with issuer_dict containing valid key """
        self.cahandler.issuer_dict = {'issuing_ca_key': self.dir_path + '/ca/sub-ca-key.pem'}
        mock_crypto.return_value = 'foo'
        mock_file.return_value = True
        self.assertEqual(('foo', None), self.cahandler._ca_load())

    @patch("builtins.open", mock_open(read_data='test'), create=True)
    @patch('os.path.exists')
    @patch('OpenSSL.crypto.load_certificate')
    @patch('OpenSSL.crypto.load_privatekey')
    def test_028_load_ca_key_cert(self, mock_crypto_key, mock_crypto_cert, mock_file):
        """ CAhandler._ca_load() with issuer_dict containing key and passphrase """
        self.cahandler.issuer_dict = {'issuing_ca_key': self.dir_path + '/ca/sub-ca-key.pem', 'passphrase': 'Test1234'}
        mock_crypto_cert.return_value = 'cert'
        mock_crypto_key.return_value = 'key'
        mock_file.return_value = True
        self.assertEqual(('key', None), self.cahandler._ca_load())

    @patch("builtins.open", mock_open(read_data='test'), create=True)
    @patch('os.path.exists')
    @patch('OpenSSL.crypto.load_certificate')
    @patch('OpenSSL.crypto.load_privatekey')
    def test_029_load_ca_key_cert(self, mock_crypto_key, mock_crypto_cert, mock_file):
        """ CAhandler._ca_load() with issuer_dict containing key and invalid cert """
        self.cahandler.issuer_dict = {'issuing_ca_key': self.dir_path + '/ca/sub-ca-key.pem', 'passphrase': 'Test1234', 'issuing_ca_cert': 'foo.pem'}
        mock_crypto_cert.return_value = None
        mock_crypto_key.return_value = 'key'
        mock_file.return_value = True
        self.assertEqual(('key', None), self.cahandler._ca_load())

    @patch("builtins.open", mock_open(read_data='test'), create=True)
    @patch('os.path.exists')
    @patch('OpenSSL.crypto.load_certificate')
    @patch('OpenSSL.crypto.load_privatekey')
    def test_030_load_ca_key_cert(self, mock_crypto_key, mock_crypto_cert, mock_file):
        """ CAhandler._ca_load() with issuer_dict containing key and invalid cert """
        self.cahandler.issuer_dict = {'issuing_ca_key': self.dir_path + '/ca/sub-ca-key.pem', 'passphrase': 'Test1234', 'issuing_ca_cert': self.dir_path + '/ca/sub-ca-cert.pem'}
        mock_crypto_key.return_value = 'foo'
        mock_crypto_cert.return_value = 'bar'
        mock_file.return_value = True
        self.assertEqual(('foo', 'bar'), self.cahandler._ca_load())

    def test_031_verifycertificatechain(self):
        """ successful verification of one level certificate chain """
        with open(self.dir_path + '/ca/root-ca-client.txt', 'r') as fso:
            cert = fso.read()
        with open(self.dir_path + '/ca/root-ca-cert.pem', 'r') as fso:
            ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, fso.read())
        self.assertFalse(self.cahandler._certificate_chain_verify(cert, ca_cert))

    def test_032_verifycertificatechain(self):
        """ unsuccessful verification of one level certificate chain """
        with open(self.dir_path + '/ca/sub-ca-client.txt', 'r') as fso:
            cert = fso.read()
        with open(self.dir_path + '/ca/root-ca-cert.pem', 'r') as fso:
            ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, fso.read())
        self.assertEqual('unable to get local issuer certificate', self.cahandler._certificate_chain_verify(cert, ca_cert))

    def test_033_verifycertificatechain(self):
        """ unsuccessful verification of two level certificate chain with incomplete chain"""
        with open(self.dir_path + '/ca/sub-ca-client.txt', 'r') as fso:
            cert = fso.read()
        with open(self.dir_path + '/ca/sub-ca-cert.pem', 'r') as fso:
            ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, fso.read())
        self.assertEqual('unable to get issuer certificate', self.cahandler._certificate_chain_verify(cert, ca_cert))

    def test_034_verifycertificatechain(self):
        """ successful verification of two level certificate chain with complete chain"""
        self.cahandler.ca_cert_chain_list = [self.dir_path + '/ca/root-ca-cert.pem']
        with open(self.dir_path + '/ca/sub-ca-client.txt', 'r') as fso:
            cert = fso.read()
        with open(self.dir_path + '/ca/sub-ca-cert.pem', 'r') as fso:
            ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, fso.read())
        self.assertFalse(self.cahandler._certificate_chain_verify(cert, ca_cert))

    def test_035_verifycertificatechain(self):
        """ unsuccessful verification as certificate is damaged"""
        cert = 'foo'
        with open(self.dir_path + '/ca/root-ca-cert.pem', 'r') as fso:
            ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, fso.read())
        self.assertEqual('certificate could not get parsed', (self.cahandler._certificate_chain_verify(cert, ca_cert)))

    def test_036_verifycertificatechain(self):
        """ unsuccessful verification as ca-certificate is damaged"""
        with open(self.dir_path + '/ca/root-ca-client.txt', 'r') as fso:
            cert = fso.read()
        ca_cert = 'foo'
        self.assertEqual('issuing certificate could not be added to trust-store', self.cahandler._certificate_chain_verify(cert, ca_cert))

    def test_037_verifycertificatechain(self):
        """ unsuccessful verification of two level certificate chain as cain cert is damaged"""
        self.cahandler.ca_cert_chain_list = ['ca/root-.pem']
        with open(self.dir_path + '/ca/sub-ca-client.txt', 'r') as fso:
            cert = fso.read()
        with open(self.dir_path + '/ca/sub-ca-cert.pem', 'r') as fso:
            ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, fso.read())
        self.assertEqual('certificate ca/root-.pem could not be added to trust store', self.cahandler._certificate_chain_verify(cert, ca_cert))

    def test_038_revocation(self):
        """ revocation without having a CRL in issuer_dic """
        with open(self.dir_path + '/ca/sub-ca-client.txt', 'r') as fso:
            cert = fso.read()
        self.assertEqual((400, 'urn:ietf:params:acme:error:serverInternal', 'Unsupported operation'), self.cahandler.revoke(cert))

    def test_039_revocation(self):
        """ revocation without having a CRL in issuer_dic but none"""
        self.cahandler.issuer_dict = {'crl' : None}
        with open(self.dir_path + '/ca/sub-ca-client.txt', 'r') as fso:
            cert = fso.read()
        self.assertEqual((400, 'urn:ietf:params:acme:error:serverInternal', 'Unsupported operation'), self.cahandler.revoke(cert))

    # @patch('examples.ca_handler.openssl_ca_handler.CAhandler._certificate_chain_verify')
    # @patch('examples.ca_handler.openssl_ca_handler.CAhandler._ca_load')
    #def test_039_revocation(self, mock_ca_load, mock_vrf):
    #    """ revocation cert validation failed """
    #    with open('ca/sub-ca-client.txt', 'r') as fso:
    #        cert = fso.read()
    #    self.cahandler.issuer_dict = {'issuing_ca_key': 'ca/sub-ca-key.pem', 'passphrase': 'Test1234', 'issuing_ca_cert': 'ca/sub-ca-cert.pem', 'issuing_ca_crl' : 'ca/foo-ca-crl.pem'}
    #    mock_ca_load.return_value = ('ca_key', 'ca_cert')
    #    mock_vrf.return_value = 'test'
    #    self.assertEqual((400, 'urn:ietf:params:acme:error:serverInternal', 'foo'), self.cahandler.revoke(cert))

    @patch('examples.ca_handler.openssl_ca_handler.CAhandler._certificate_chain_verify')
    @patch('examples.ca_handler.openssl_ca_handler.CAhandler._ca_load')
    def test_040_revocation(self, mock_ca_load, mock_vrf):
        """ revocation cert no CA key """
        with open(self.dir_path + '/ca/sub-ca-client.txt', 'r') as fso:
            cert = fso.read()
        self.cahandler.issuer_dict = {'issuing_ca_key': self.dir_path + '/ca/sub-ca-key.pem', 'passphrase': 'Test1234', 'issuing_ca_cert': self.dir_path + '/ca/sub-ca-cert.pem', 'issuing_ca_crl' : self.dir_path + '/ca/foo-ca-crl.pem'}
        mock_ca_load.return_value = (None, 'ca_cert')
        mock_vrf.return_value = None
        self.assertEqual((400, 'urn:ietf:params:acme:error:serverInternal', 'configuration error'), self.cahandler.revoke(cert))

    @patch('examples.ca_handler.openssl_ca_handler.CAhandler._certificate_chain_verify')
    @patch('examples.ca_handler.openssl_ca_handler.CAhandler._ca_load')
    def test_041_revocation(self, mock_ca_load, mock_vrf):
        """ revocation cert no CA cert """
        with open(self.dir_path + '/ca/sub-ca-client.txt', 'r') as fso:
            cert = fso.read()
        self.cahandler.issuer_dict = {'issuing_ca_key': self.dir_path + '/ca/sub-ca-key.pem', 'passphrase': 'Test1234', 'issuing_ca_cert': self.dir_path + '/ca/sub-ca-cert.pem', 'issuing_ca_crl' : self.dir_path + '/ca/foo-ca-crl.pem'}
        mock_ca_load.return_value = ('ca_key', None)
        mock_vrf.return_value = None
        self.assertEqual((400, 'urn:ietf:params:acme:error:serverInternal', 'configuration error'), self.cahandler.revoke(cert))

    @patch('examples.ca_handler.openssl_ca_handler.cert_serial_get')
    @patch('examples.ca_handler.openssl_ca_handler.CAhandler._certificate_chain_verify')
    @patch('examples.ca_handler.openssl_ca_handler.CAhandler._ca_load')
    def test_042_revocation(self, mock_ca_load, mock_vrf, mock_serial):
        """ revocation cert no serial """
        with open(self.dir_path + '/ca/sub-ca-client.txt', 'r') as fso:
            cert = fso.read()
        self.cahandler.issuer_dict = {'issuing_ca_key': self.dir_path + '/ca/sub-ca-key.pem', 'passphrase': 'Test1234', 'issuing_ca_cert': self.dir_path + '/ca/sub-ca-cert.pem', 'issuing_ca_crl' : self.dir_path + '/ca/foo-ca-crl.pem'}
        mock_ca_load.return_value = ('ca_key', 'ca_cert')
        mock_vrf.return_value = None
        mock_serial.return_value = None
        self.assertEqual((400, 'urn:ietf:params:acme:error:serverInternal', 'configuration error'), self.cahandler.revoke(cert))

    @patch('examples.ca_handler.openssl_ca_handler.cert_serial_get')
    @patch('examples.ca_handler.openssl_ca_handler.CAhandler._certificate_chain_verify')
    # @patch('examples.ca_handler.openssl_ca_handler.CAhandler._ca_load')
    def test_043_revocation(self, mock_vrf, mock_serial):
        """ revocation cert """
        with open(self.dir_path + '/ca/sub-ca-client.txt', 'r') as fso:
            cert = fso.read()
        self.cahandler.issuer_dict = {'issuing_ca_key': self.dir_path + '/ca/sub-ca-key.pem', 'passphrase': 'Test1234', 'issuing_ca_cert': self.dir_path + '/ca/sub-ca-cert.pem', 'issuing_ca_crl' : self.dir_path + '/ca/foo-ca-crl.pem'}
        # mock_ca_load.return_value = ('ca_key', 'ca_cert')
        mock_vrf.return_value = None
        mock_serial.return_value = 14
        self.assertEqual((200, None, None), self.cahandler.revoke(cert))

    @patch('examples.ca_handler.openssl_ca_handler.CAhandler._crl_check')
    @patch('examples.ca_handler.openssl_ca_handler.cert_serial_get')
    @patch('examples.ca_handler.openssl_ca_handler.CAhandler._certificate_chain_verify')
    def test_044_revocation(self, mock_vrf, mock_serial, mock_crl):
        """ revocation cert """
        with open(self.dir_path + '/ca/sub-ca-client.txt', 'r') as fso:
            cert = fso.read()
        self.cahandler.issuer_dict = {'issuing_ca_key': self.dir_path + '/ca/sub-ca-key.pem', 'passphrase': 'Test1234', 'issuing_ca_cert': self.dir_path + '/ca/sub-ca-cert.pem', 'issuing_ca_crl' : self.dir_path + '/ca/foo-ca-crl.pem'}
        # mock_ca_load.return_value = ('ca_key', 'ca_cert')
        mock_vrf.return_value = None
        mock_serial.return_value = 14
        mock_crl.return_value = True
        self.assertEqual((400, 'urn:ietf:params:acme:error:alreadyRevoked', 'Certificate has already been revoked'), self.cahandler.revoke(cert))

    def test_045_list_check(self):
        """ CAhandler._list_check failed check as empty entry"""
        list_ = ['bar.foo$', 'foo.bar$']
        entry = None
        self.assertFalse(self.cahandler._list_check(entry, list_))

    def test_046_list_check(self):
        """ CAhandler._list_check check against empty list"""
        list_ = []
        entry = 'host.bar.foo'
        self.assertTrue(self.cahandler._list_check(entry, list_))

    def test_047_list_check(self):
        """ CAhandler._list_check successful check against 1st element of a list"""
        list_ = ['bar.foo$', 'foo.bar$']
        entry = 'host.bar.foo'
        self.assertTrue(self.cahandler._list_check(entry, list_))

    def test_048_list_check(self):
        """ CAhandler._list_check unsuccessful as endcheck failed"""
        list_ = ['bar.foo$', 'foo.bar$']
        entry = 'host.bar.foo.bar_'
        self.assertFalse(self.cahandler._list_check(entry, list_))

    def test_049_list_check(self):
        """ CAhandler._list_check successful without $"""
        list_ = ['bar.foo', 'foo.bar$']
        entry = 'host.bar.foo.bar_'
        self.assertTrue(self.cahandler._list_check(entry, list_))

    def test_050_list_check(self):
        """ CAhandler._list_check wildcard check"""
        list_ = ['bar.foo$', 'foo.bar$']
        entry = '*.bar.foo'
        self.assertTrue(self.cahandler._list_check(entry, list_))

    def test_051_list_check(self):
        """ CAhandler._list_check failed wildcard check"""
        list_ = ['bar.foo$', 'foo.bar$']
        entry = '*.bar.foo_'
        self.assertFalse(self.cahandler._list_check(entry, list_))

    def test_052_list_check(self):
        """ CAhandler._list_check not end check"""
        list_ = ['bar.foo$', 'foo.bar$']
        entry = 'bar.foo gna'
        self.assertFalse(self.cahandler._list_check(entry, list_))

    def test_053_list_check(self):
        """ CAhandler._list_check $ at the end"""
        list_ = ['bar.foo$', 'foo.bar$']
        entry = 'bar.foo$'
        self.assertFalse(self.cahandler._list_check(entry, list_))

    def test_054_list_check(self):
        """ CAhandler._list_check check against empty list flip"""
        list_ = []
        entry = 'host.bar.foo'
        self.assertFalse(self.cahandler._list_check(entry, list_, True))

    def test_055_list_check(self):
        """ CAhandler._list_check flip successful check """
        list_ = ['bar.foo$', 'foo.bar$']
        entry = 'host.bar.foo'
        self.assertFalse(self.cahandler._list_check(entry, list_, True))

    def test_056_list_check(self):
        """ CAhandler._list_check flip unsuccessful check"""
        list_ = ['bar.foo$', 'foo.bar$']
        entry = 'host.bar.foo'
        self.assertFalse(self.cahandler._list_check(entry, list_, True))

    def test_057_list_check(self):
        """ CAhandler._list_check unsuccessful whildcard check"""
        list_ = ['foo.bar$', r'\*.bar.foo']
        entry = 'host.bar.foo'
        self.assertFalse(self.cahandler._list_check(entry, list_))

    def test_058_list_check(self):
        """ CAhandler._list_check successful whildcard check"""
        list_ = ['foo.bar$', r'\*.bar.foo']
        entry = '*.bar.foo'
        self.assertTrue(self.cahandler._list_check(entry, list_))

    def test_059_list_check(self):
        """ CAhandler._list_check successful whildcard in list but not in string """
        list_ = ['foo.bar$', '*.bar.foo']
        entry = 'foo.bar.foo'
        self.assertTrue(self.cahandler._list_check(entry, list_))

    def test_060_string_wlbl_check(self):
        """ CAhandler._string_wlbl_check against empty lists"""
        white_list = []
        black_list = []
        entry = 'host.bar.foo'
        self.assertTrue(self.cahandler._string_wlbl_check(entry, white_list, black_list))

    def test_061_string_wlbl_check(self):
        """ CAhandler._string_wlbl_check against empty whitlist but match in blocked_domainlist """
        white_list = []
        black_list = ['host.bar.foo$']
        entry = 'host.bar.foo'
        self.assertFalse(self.cahandler._string_wlbl_check(entry, white_list, black_list))

    def test_062_string_wlbl_check(self):
        """ CAhandler._string_wlbl_check against empty whitlist but no match in blocked_domainlist """
        white_list = []
        black_list = ['faulty.bar.foo$']
        entry = 'host.bar.foo'
        self.assertTrue(self.cahandler._string_wlbl_check(entry, white_list, black_list))

    def test_063_string_wlbl_check(self):
        """ CAhandler._string_wlbl_check against empty whitlist wildcard check does not hit """
        white_list = []
        black_list = [r'\*.bar.foo$']
        entry = 'host.bar.foo'
        self.assertTrue(self.cahandler._string_wlbl_check(entry, white_list, black_list))

    def test_064_string_wlbl_check(self):
        """ CAhandler._string_wlbl_check against empty whitlist wildcard check hit """
        white_list = []
        black_list = [r'\*.bar.foo$']
        entry = '*.bar.foo'
        self.assertFalse(self.cahandler._string_wlbl_check(entry, white_list, black_list))

    def test_065_string_wlbl_check(self):
        """ CAhandler._string_wlbl_check successful wl check with empty bl"""
        white_list = ['foo.foo', 'bar.foo$']
        black_list = []
        entry = 'host.bar.foo'
        self.assertTrue(self.cahandler._string_wlbl_check(entry, white_list, black_list))

    def test_066_string_wlbl_check(self):
        """ CAhandler._string_wlbl_check unsuccessful empty bl """
        white_list = ['foo.foo$', 'host.bar.foo$']
        black_list = []
        entry = 'host.bar.foo.bar'
        self.assertFalse(self.cahandler._string_wlbl_check(entry, white_list, black_list))

    def test_067_string_wlbl_check(self):
        """ CAhandler._string_wlbl_check unsuccessful host in bl"""
        white_list = ['foo.foo', 'bar.foo$']
        black_list = ['host.bar.foo']
        entry = 'host.bar.foo'
        self.assertFalse(self.cahandler._string_wlbl_check(entry, white_list, black_list))

    def test_068_string_wlbl_check(self):
        """ CAhandler._string_wlbl_check unsuccessful host in bl but not on first position"""
        white_list = ['foo.foo', 'bar.foo$']
        black_list = ['foo.bar$', 'host.bar.foo', 'foo.foo']
        entry = 'host.bar.foo'
        self.assertFalse(self.cahandler._string_wlbl_check(entry, white_list, black_list))

    def test_069_string_wlbl_check(self):
        """ CAhandler._string_wlbl_check successful wildcard in entry not n bl """
        white_list = ['foo.foo', 'bar.foo$']
        black_list = ['host.bar.foo']
        entry = '*.bar.foo'
        self.assertTrue(self.cahandler._string_wlbl_check(entry, white_list, black_list))

    def test_070_string_wlbl_check(self):
        """ CAhandler._string_wlbl_check successful wildcard blocked_domainlisting - no match"""
        white_list = ['foo.foo', 'bar.foo$']
        black_list = [r'\*.bar.foo']
        entry = 'host.bar.foo'
        self.assertTrue(self.cahandler._string_wlbl_check(entry, white_list, black_list))

    def test_071_string_wlbl_check(self):
        """ CAhandler._string_wlbl_check  failed wildcard black-listing """
        white_list = ['foo.foo', 'bar.foo$']
        black_list = [r'\*.bar.foo']
        entry = '*.bar.foo'
        self.assertFalse(self.cahandler._string_wlbl_check(entry, white_list, black_list))

    def test_072_string_wlbl_check(self):
        """ CAhandler._string_wlbl_check faked domain"""
        white_list = ['foo.foo', 'bar.foo$']
        black_list = ['google.com.bar.foo']
        entry = 'foo.google.com.bar.foo'
        self.assertFalse(self.cahandler._string_wlbl_check(entry, white_list, black_list))

    def test_073_string_wlbl_check(self):
        """ CAhandler._string_wlbl_check faked wc domain"""
        white_list = ['foo.foo', 'bar.foo$']
        black_list = ['google.com.bar.foo$']
        entry = '*.google.com.bar.foo'
        self.assertFalse(self.cahandler._string_wlbl_check(entry, white_list, black_list))

    def test_074_string_wlbl_check(self):
        """ CAhandler._string_wlbl_check faked domain"""
        white_list = ['foo.foo', 'bar.foo$']
        black_list = ['google.com']
        entry = '*.google.com.bar.foo'
        self.assertFalse(self.cahandler._string_wlbl_check(entry, white_list, black_list))

    def test_075_string_wlbl_check(self):
        """ CAhandler._string_wlbl_check faked hostname and domain"""
        white_list = ['foo.foo', 'bar.foo$']
        black_list = ['google.com']
        entry = 'www.google.com.bar.foo'
        self.assertFalse(self.cahandler._string_wlbl_check(entry, white_list, black_list))

    @patch('examples.ca_handler.openssl_ca_handler.csr_cn_get')
    @patch('examples.ca_handler.openssl_ca_handler.csr_san_get')
    def test_076_csr_check(self,  mock_san, mock_cn):
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
    def test_077_csr_check(self, mock_san, mock_cn, mock_lcheck):
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
    def test_078_csr_check(self, mock_san, mock_cn, mock_lcheck):
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
    def test_079_csr_check(self, mock_san, mock_cn, mock_lcheck):
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
    def test_080_csr_check(self, mock_san, mock_cn):
        """ CAhandler._check_csr san parsing failed """
        self.cahandler.allowed_domainlist = ['foo.bar']
        self.cahandler.blocked_domainlist = []
        mock_san.return_value = []
        mock_cn.return_value = None
        csr = 'csr'
        self.assertEqual((False, None), self.cahandler._csr_check(csr))

    @patch('examples.ca_handler.openssl_ca_handler.csr_cn_get')
    @patch('examples.ca_handler.openssl_ca_handler.csr_san_get')
    def test_081_csr_check(self,  mock_san, mock_cn):
        """ CAhandler._check_csr cn_enforce """
        mock_san.return_value = ['DNS:host.foo.bar']
        mock_cn.return_value = None
        csr = 'csr'
        self.assertEqual((True, 'host.foo.bar'), self.cahandler._csr_check(csr))

    @patch('examples.ca_handler.openssl_ca_handler.csr_cn_get')
    @patch('examples.ca_handler.openssl_ca_handler.csr_san_get')
    def test_082_csr_check(self,  mock_san, mock_cn):
        """ CAhandler._check_csr cn_enforce  but no san"""
        mock_san.return_value = []
        mock_cn.return_value = None
        csr = 'csr'
        self.assertEqual((True, None), self.cahandler._csr_check(csr))

    @patch('examples.ca_handler.openssl_ca_handler.CAhandler._config_load')
    def test_083__enter__(self, mock_cfg):
        """ test enter """
        mock_cfg.return_value = True
        self.cahandler.__enter__()
        self.assertTrue(mock_cfg.called)

    def test_084_trigger(self):
        """ test trigger """
        self.assertEqual(('Method not implemented.', None, None), self.cahandler.trigger('payload'))

    def test_085_poll(self):
        """ test poll """
        self.assertEqual(('Method not implemented.', None, None, 'poll_identifier', False), self.cahandler.poll('cert_name', 'poll_identifier','csr'))

    def test_086_certificate_store(self):
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
    def test_087_certificate_store(self, mock_os, mock_mkdir, mock_dump):
        """ _certificate_store() """
        mock_os.return_value = True
        mock_mkdir.return_value = Mock()
        cert = Mock()
        cert.get_serial_number = Mock(return_value=42)
        self.cahandler.cert_save_path  = 'template'
        mock_dump.return_value = 'foo'
        self.cahandler._certificate_store(cert)
        self.assertFalse(mock_mkdir.called)

    @patch('OpenSSL.crypto.dump_certificate')
    @patch('builtins.open', mock_open(read_data="foo"))
    @patch('os.mkdir')
    @patch('os.path.isdir')
    def test_088_certificate_store(self, mock_os, mock_mkdir, mock_dump):
        """ _certificate_store() """
        mock_os.return_value = False
        mock_mkdir.return_value = Mock()
        cert = Mock()
        cert.get_serial_number = Mock(return_value=42)
        self.cahandler.cert_save_path  = 'template'
        mock_dump.return_value = 'foo'
        self.cahandler._certificate_store(cert)
        self.assertTrue(mock_mkdir.called)

    @patch('OpenSSL.crypto.dump_certificate')
    @patch('builtins.open', mock_open(read_data="foo"))
    @patch('os.mkdir')
    @patch('os.path.isdir')
    def test_089_certificate_store(self, mock_os, mock_mkdir, mock_dump):
        """ _certificate_store() """
        mock_os.return_value = True
        mock_mkdir.return_value = Mock()
        cert = Mock()
        cert.get_serial_number = Mock(return_value=42)
        self.cahandler.cert_save_path  = 'template'
        self.cahandler.save_cert_as_hex = True
        mock_dump.return_value = 'foo'
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._certificate_store(cert)
        self.assertIn('INFO:test_a2c:convert serial to hex: 42: 2A', lcm.output)

    @patch('examples.ca_handler.openssl_ca_handler.load_config')
    def test_090__config_load(self, mock_load_cfg):
        """ config load """
        parser = configparser.ConfigParser()
        parser['CAhandler'] = {'save_cert_as_hex': False}
        mock_load_cfg.return_value = parser
        self.cahandler._config_load()
        self.assertFalse(self.cahandler.save_cert_as_hex )

    @patch('examples.ca_handler.openssl_ca_handler.load_config')
    def test_091__config_load(self, mock_load_cfg):
        """ config load """
        parser = configparser.ConfigParser()
        parser['CAhandler'] = {'save_cert_as_hex': True}
        mock_load_cfg.return_value = parser
        self.cahandler._config_load()
        self.assertTrue(self.cahandler.save_cert_as_hex )

    @patch('json.loads')
    @patch('examples.ca_handler.openssl_ca_handler.load_config')
    def test_092__config_load(self, mock_load_cfg, mock_jl):
        """ config load """
        parser = configparser.ConfigParser()
        parser['CAhandler'] = {'blocked_domainlist': 'foo.json'}
        mock_load_cfg.return_value = parser
        mock_jl.return_value = 'blocked_domainlist'
        self.cahandler._config_load()
        self.assertEqual('blocked_domainlist', self.cahandler.blocked_domainlist)

    @patch('json.loads')
    @patch('examples.ca_handler.openssl_ca_handler.load_config')
    def test_093__config_load(self, mock_load_cfg, mock_jl):
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
    def test_094__config_load(self, mock_load_cfg, mock_jl):
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
    def test_095__config_load(self, mock_load_cfg, mock_jl):
        """ config load """
        parser = configparser.ConfigParser()
        parser['CAhandler'] = {'allowed_domainlist': 'foo.json'}
        mock_load_cfg.return_value = parser
        mock_jl.return_value = 'allowed_domainlist'
        self.cahandler._config_load()
        self.assertEqual('allowed_domainlist', self.cahandler.allowed_domainlist)

    @patch('json.loads')
    @patch('examples.ca_handler.openssl_ca_handler.load_config')
    def test_096__config_load(self, mock_load_cfg, mock_jl):
        """ config load """
        parser = configparser.ConfigParser()
        parser['CAhandler'] = {'openssl_conf': 'openssl_conf'}
        mock_load_cfg.return_value = parser
        mock_jl.return_value = 'openssl_conf'
        self.cahandler._config_load()
        self.assertEqual('openssl_conf', self.cahandler.openssl_conf)

    @patch('examples.ca_handler.openssl_ca_handler.load_config')
    def test_097__config_load(self, mock_load_cfg):
        """ config load """
        parser = configparser.ConfigParser()
        parser['CAhandler'] = {'issuing_ca_key': 'issuing_ca_key'}
        mock_load_cfg.return_value = parser
        self.cahandler._config_load()
        self.assertEqual('issuing_ca_key', self.cahandler.issuer_dict['issuing_ca_key'])

    @patch('examples.ca_handler.openssl_ca_handler.load_config')
    def test_098__config_load(self, mock_load_cfg):
        """ config load """
        parser = configparser.ConfigParser()
        parser['CAhandler'] = {'issuing_ca_cert': 'issuing_ca_cert'}
        mock_load_cfg.return_value = parser
        self.cahandler._config_load()
        self.assertEqual('issuing_ca_cert', self.cahandler.issuer_dict['issuing_ca_cert'])

    @patch('examples.ca_handler.openssl_ca_handler.load_config')
    def test_099__config_load(self, mock_load_cfg):
        """ config load """
        parser = configparser.ConfigParser()
        parser['CAhandler'] = {'issuing_ca_key_passphrase': 'issuing_ca_key_passphrase'}
        mock_load_cfg.return_value = parser
        self.cahandler._config_load()
        self.assertEqual(b'issuing_ca_key_passphrase', self.cahandler.issuer_dict['passphrase'])

    @patch('examples.ca_handler.openssl_ca_handler.load_config')
    def test_100__config_load(self, mock_load_cfg):
        """ config load """
        parser = configparser.ConfigParser()
        parser['CAhandler'] = {'cert_validity_days': 10}
        mock_load_cfg.return_value = parser
        self.cahandler._config_load()
        self.assertEqual(10, self.cahandler.cert_validity_days )

    @patch('examples.ca_handler.openssl_ca_handler.load_config')
    def test_101__config_load(self, mock_load_cfg):
        """ config load """
        parser = configparser.ConfigParser()
        parser['CAhandler'] = {'cert_save_path': 'cert_save_path'}
        mock_load_cfg.return_value = parser
        self.cahandler._config_load()
        self.assertEqual('cert_save_path', self.cahandler.cert_save_path)

    @patch('examples.ca_handler.openssl_ca_handler.load_config')
    def test_102__config_load(self, mock_load_cfg):
        """ config load """
        parser = configparser.ConfigParser()
        parser['CAhandler'] = {'ca_cert_chain_list': '["root_ca"]'}
        mock_load_cfg.return_value = parser
        self.cahandler._config_load()
        self.assertEqual(['root_ca'], self.cahandler.ca_cert_chain_list)

    @patch('examples.ca_handler.openssl_ca_handler.load_config')
    def test_103__config_load(self, mock_load_cfg):
        """ config load """
        parser = configparser.ConfigParser()
        parser['CAhandler'] = {'ca_cert_chain_list': '["root_ca", "sub_ca"]'}
        mock_load_cfg.return_value = parser
        self.cahandler._config_load()
        self.assertEqual(['root_ca', 'sub_ca'], self.cahandler.ca_cert_chain_list)

    @patch('examples.ca_handler.openssl_ca_handler.load_config')
    def test_104__config_load(self, mock_load_cfg):
        """ config load """
        parser = configparser.ConfigParser()
        parser['CAhandler'] = {'issuing_ca_crl': 'issuing_ca_crl'}
        mock_load_cfg.return_value = parser
        self.cahandler._config_load()
        self.assertEqual('issuing_ca_crl', self.cahandler.issuer_dict['issuing_ca_crl'])

    @patch.dict('os.environ', {'foo': 'foo_var'})
    @patch('examples.ca_handler.openssl_ca_handler.load_config')
    def test_105_config_load(self, mock_load_cfg):
        """ test _config_load - load template with passphrase variable """
        parser = configparser.ConfigParser()
        parser['CAhandler'] = {'issuing_ca_key_passphrase_variable': 'foo'}
        mock_load_cfg.return_value = parser
        self.cahandler._config_load()
        self.assertEqual(b'foo_var', self.cahandler.issuer_dict['passphrase'])

    @patch.dict('os.environ', {'foo': 'foo_var'})
    @patch('examples.ca_handler.openssl_ca_handler.load_config')
    def test_106_config_load(self, mock_load_cfg):
        """ test _config_load - load template passpharese variable configured but does not exist """
        parser = configparser.ConfigParser()
        parser['CAhandler'] = {'issuing_ca_key_passphrase_variable': 'does_not_exist'}
        mock_load_cfg.return_value = parser
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_load()
        self.assertIn("ERROR:test_a2c:CAhandler._config_load() could not load issuing_ca_key_passphrase_variable:'does_not_exist'", lcm.output)

    @patch.dict('os.environ', {'foo': 'foo_var'})
    @patch('examples.ca_handler.openssl_ca_handler.load_config')
    def test_107_config_load(self, mock_load_cfg):
        """ test _config_load - load template with passphrase variable  - overwritten bei cfg file"""
        parser = configparser.ConfigParser()
        parser['CAhandler'] = {'issuing_ca_key_passphrase_variable': 'foo', 'issuing_ca_key_passphrase': 'foo_file'}
        mock_load_cfg.return_value = parser
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_load()
        self.assertEqual(b'foo_file', self.cahandler.issuer_dict['passphrase'])
        self.assertIn('INFO:test_a2c:CAhandler._config_load() overwrite issuing_ca_key_passphrase_variable', lcm.output)

    @patch('examples.ca_handler.openssl_ca_handler.load_config')
    def test_108__config_load(self, mock_load_cfg):
        """ config load no cn_enforce """
        parser = configparser.ConfigParser()
        parser['CAhandler'] = {'foo': 'bar'}
        mock_load_cfg.return_value = parser
        self.cahandler._config_load()
        self.assertFalse(self.cahandler.cn_enforce)

    @patch('examples.ca_handler.openssl_ca_handler.load_config')
    def test_109__config_load(self, mock_load_cfg):
        """ config load cn_enforce True """
        parser = configparser.ConfigParser()
        parser['CAhandler'] = {'cn_enforce': True}
        mock_load_cfg.return_value = parser
        self.cahandler._config_load()
        self.assertTrue(self.cahandler.cn_enforce)

    @patch('examples.ca_handler.openssl_ca_handler.load_config')
    def test_110__config_load(self, mock_load_cfg):
        """ config load cn_enforce True """
        parser = configparser.ConfigParser()
        parser['CAhandler'] = {'cn_enforce': False}
        mock_load_cfg.return_value = parser
        self.cahandler._config_load()
        self.assertFalse(self.cahandler.cn_enforce)

    @patch('examples.ca_handler.openssl_ca_handler.load_config')
    def test_111__config_load(self, mock_load_cfg):
        """ config load cn_enforce True """
        parser = configparser.ConfigParser()
        parser['CAhandler'] = {'cn_enforce': 'bar'}
        mock_load_cfg.return_value = parser
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_load()
        self.assertFalse(self.cahandler.cn_enforce)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load() variable cn_enforce cannot be parsed', lcm.output)

    @patch('OpenSSL.crypto.X509Extension')
    def test_112___certificate_extensions_add(self, mock_ext):
        """ extension list add """
        cert_extension_dic = {'foo1': {'critical': False, 'value': 'bar'}}
        mock_ext.side_effect = ['foo1']
        result = ['foo1']
        self.assertEqual(result, self.cahandler._certificate_extensions_add(cert_extension_dic, 'cert', 'ca_cert'))

    @patch('OpenSSL.crypto.X509Extension')
    def test_113___certificate_extensions_add(self, mock_ext):
        """ extension list add """
        cert_extension_dic = {'subjectKeyIdentifier': {'critical': False, 'value': 'bar'}}
        mock_ext.side_effect = ['foo1']
        result = ['foo1']
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual(result, self.cahandler._certificate_extensions_add(cert_extension_dic, 'cert', 'ca_cert'))
        self.assertIn('INFO:test_a2c:_certificate_extensions_add(): subjectKeyIdentifier', lcm.output)

    @patch('OpenSSL.crypto.X509Extension')
    def test_114___certificate_extensions_add(self, mock_ext):
        """ extension list add """
        cert_extension_dic = {'foo': {'critical': False, 'value': 'bar', 'subject': True}}
        mock_ext.side_effect = ['foo1']
        result = ['foo1']
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual(result, self.cahandler._certificate_extensions_add(cert_extension_dic, 'cert', 'ca_cert'))
        self.assertIn('INFO:test_a2c:_certificate_extensions_add(): subject', lcm.output)

    @patch('OpenSSL.crypto.X509Extension')
    def test_115___certificate_extensions_add(self, mock_ext):
        """ extension list add """
        cert_extension_dic = {'foo': {'critical': False, 'value': 'bar', 'issuer': True}}
        mock_ext.side_effect = ['foo1']
        result = ['foo1']
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual(result, self.cahandler._certificate_extensions_add(cert_extension_dic, 'cert', 'ca_cert'))
        self.assertIn('INFO:test_a2c:_certificate_extensions_add(): issuer', lcm.output)

    @patch('examples.ca_handler.openssl_ca_handler.load_config')
    def test_116___certificate_extensions_load(self, mock_load_cfg):
        """ extension list load - empty list """
        # mock_load_cfg.return_value = {'extensions': {'foo': 'critical, serverAuth'}}
        mock_load_cfg.return_value = {'extensions': {'foo': 'bar'}}
        result = {'foo': {'critical': False, 'value': 'bar'}}
        self.assertEqual(result, self.cahandler._certificate_extensions_load())

    @patch('examples.ca_handler.openssl_ca_handler.load_config')
    def test_117___certificate_extensions_load(self, mock_load_cfg):
        """ extension list load - empty list """
        # mock_load_cfg.return_value = {'extensions': {'foo': 'critical, serverAuth'}}
        mock_load_cfg.return_value = {'extensions': {'foo': 'bar, foobar'}}
        result = {'foo': {'critical': False, 'value': 'bar, foobar'}}
        self.assertEqual(result, self.cahandler._certificate_extensions_load())

    @patch('examples.ca_handler.openssl_ca_handler.load_config')
    def test_118___certificate_extensions_load(self, mock_load_cfg):
        """ extension list load - empty list """
        # mock_load_cfg.return_value = {'extensions': {'foo': 'critical, serverAuth'}}
        mock_load_cfg.return_value = {'extensions': {'foo': 'bar', 'foo1': 'bar1'}}
        result = {'foo': {'critical': False, 'value': 'bar'}, 'foo1': {'critical': False, 'value': 'bar1'}}
        self.assertEqual(result, self.cahandler._certificate_extensions_load())

    @patch('examples.ca_handler.openssl_ca_handler.load_config')
    def test_119___certificate_extensions_load(self, mock_load_cfg):
        """ extension list load - empty list """
        mock_load_cfg.return_value = {'extensions': {'foo': 'critical, bar'}}
        result = {'foo': {'critical': True, 'value': 'bar'}}
        self.assertEqual(result, self.cahandler._certificate_extensions_load())

    @patch('examples.ca_handler.openssl_ca_handler.load_config')
    def test_120___certificate_extensions_load(self, mock_load_cfg):
        """ extension list load - empty list """
        # mock_load_cfg.return_value = {'extensions': {'foo': 'critical, serverAuth'}}
        mock_load_cfg.return_value = {'extensions': {'foo': ' bar, foobar'}}
        result = {'foo': {'critical': False, 'value': 'bar, foobar'}}
        self.assertEqual(result, self.cahandler._certificate_extensions_load())

    @patch('examples.ca_handler.openssl_ca_handler.load_config')
    def test_121___certificate_extensions_load(self, mock_load_cfg):
        """ extension list load - empty list """
        # mock_load_cfg.return_value = {'extensions': {'foo': 'critical, serverAuth'}}
        mock_load_cfg.return_value = {'extensions': {'foo': ' bar, issuer:'}}
        result = {'foo': {'critical': False, 'issuer': True, 'value': 'bar'}}
        self.assertEqual(result, self.cahandler._certificate_extensions_load())

    @patch('examples.ca_handler.openssl_ca_handler.load_config')
    def test_122___certificate_extensions_load(self, mock_load_cfg):
        """ extension list load - empty list """
        # mock_load_cfg.return_value = {'extensions': {'foo': 'critical, serverAuth'}}
        mock_load_cfg.return_value = {'extensions': {'foo': ' bar, subject:'}}
        result = {'foo': {'critical': False, 'subject': True, 'value': 'bar'}}
        self.assertEqual(result, self.cahandler._certificate_extensions_load())

    @patch('examples.ca_handler.openssl_ca_handler.CAhandler._config_check')
    def test_123_enroll(self, mock_chk):
        """ enroll test error returned from config_check"""
        mock_chk.return_value = 'error'
        self.assertEqual(('error', None, None, None), self.cahandler.enroll('csr'))

    @patch('examples.ca_handler.openssl_ca_handler.CAhandler._csr_check')
    @patch('examples.ca_handler.openssl_ca_handler.CAhandler._config_check')
    def test_124_enroll(self, mock_cfgchk, mock_csrchk):
        """ enroll test error returned from config_check"""
        mock_cfgchk.return_value = None
        mock_csrchk.return_value = (False, None)
        self.assertEqual(('urn:ietf:params:acme:badCSR', None, None, None), self.cahandler.enroll('csr'))

    @patch('examples.ca_handler.openssl_ca_handler.CAhandler._csr_check')
    @patch('examples.ca_handler.openssl_ca_handler.CAhandler._config_check')
    def test_125_enroll(self, mock_cfgchk, mock_csrchk):
        """ enroll test error returned from csr_check """
        mock_cfgchk.return_value = None
        mock_csrchk.side_effect = Exception('exc_csr_check')
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual(('Unknown exception', None, None, None), self.cahandler.enroll('csr'))
        self.assertIn('ERROR:test_a2c:CAhandler.enroll() error: exc_csr_check', lcm.output)

    @patch("builtins.open", mock_open(read_data='cacert'), create=True)
    @patch('base64.b64encode')
    @patch('examples.ca_handler.openssl_ca_handler.CAhandler._pemcertchain_generate')
    @patch('examples.ca_handler.openssl_ca_handler.convert_byte_to_string')
    @patch('OpenSSL.crypto.dump_certificate')
    @patch('OpenSSL.crypto.X509Extension')
    @patch('OpenSSL.crypto.X509')
    @patch('OpenSSL.crypto.load_certificate_request')
    @patch('examples.ca_handler.openssl_ca_handler.CAhandler._ca_load')
    @patch('examples.ca_handler.openssl_ca_handler.CAhandler._csr_check')
    @patch('examples.ca_handler.openssl_ca_handler.CAhandler._config_check')
    def test_126_enroll(self, mock_cfgchk, mock_csrchk, mock_caload, mock_csrload, mock_x509, mock_ext, mock_dmp, mock_b2s, mock_pem, mock_b64e):
        """ enroll test error cert_save_path is missing """
        mock_ext = Mock()
        mock_cfgchk.return_value = None
        mock_csrchk.return_value = (True, None)
        ca_obj = Mock()
        ca_obj.subject_name_hash = Mock(return_value=42)
        mock_caload.return_value = ('ca_key', ca_obj)
        dn_obj = Mock()
        dn_obj.CN = 'foo'
        mock_csrload.return_value = Mock()
        mock_csrload.return_value.get_subject = Mock(return_value=dn_obj)
        extension = Mock()
        extension.get_short_name(return_value='short_name')
        mock_csrload.return_value.get_extensions = Mock(return_value=[extension, extension])
        mock_x509 = Mock()
        mock_dmp.return_value = 'dump'
        mock_b2s.return_value = 'b2s'
        mock_pem.return_value = 'pem'
        mock_b64e.return_value = 'b64e'
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual((None, 'pem', 'b2s', None), self.cahandler.enroll('csr'))
        self.assertIn('ERROR:test_a2c:CAhandler._certificate_store() handler configuration incomplete: cert_save_path is missing', lcm.output)

    @patch("builtins.open", mock_open(read_data='cacert'), create=True)
    @patch('base64.b64encode')
    @patch('examples.ca_handler.openssl_ca_handler.CAhandler._pemcertchain_generate')
    @patch('examples.ca_handler.openssl_ca_handler.convert_byte_to_string')
    @patch('examples.ca_handler.openssl_ca_handler.CAhandler._certificate_store')
    @patch('OpenSSL.crypto.dump_certificate')
    @patch('OpenSSL.crypto.X509Extension')
    @patch('OpenSSL.crypto.X509')
    @patch('OpenSSL.crypto.load_certificate_request')
    @patch('examples.ca_handler.openssl_ca_handler.CAhandler._ca_load')
    @patch('examples.ca_handler.openssl_ca_handler.CAhandler._csr_check')
    @patch('examples.ca_handler.openssl_ca_handler.CAhandler._config_check')
    def test_127_enroll(self, mock_cfgchk, mock_csrchk, mock_caload, mock_csrload, mock_x509, mock_ext, mock_dmp, mock_store, mock_b2s, mock_pem, mock_b64e):
        """ enroll """
        mock_ext = Mock()
        mock_cfgchk.return_value = None
        mock_csrchk.return_value = (True, None)
        ca_obj = Mock()
        ca_obj.subject_name_hash = Mock(return_value=42)
        mock_caload.return_value = ('ca_key', ca_obj)
        dn_obj = Mock()
        dn_obj.CN = 'foo'
        mock_csrload.return_value = Mock()
        mock_csrload.return_value.get_subject = Mock(return_value=dn_obj)
        extension = Mock()
        extension.get_short_name(return_value='short_name')
        mock_csrload.return_value.get_extensions = Mock(return_value=[extension, extension])
        mock_x509 = Mock()
        mock_dmp.return_value = 'dump'
        mock_store.return_value = True
        mock_b2s.return_value = 'b2s'
        mock_pem.return_value = 'pem'
        mock_b64e.return_value = 'b64e'
        self.assertEqual((None, 'pem', 'b2s', None), self.cahandler.enroll('csr'))

    @patch("builtins.open", mock_open(read_data='cacert'), create=True)
    @patch('base64.b64encode')
    @patch('examples.ca_handler.openssl_ca_handler.CAhandler._pemcertchain_generate')
    @patch('examples.ca_handler.openssl_ca_handler.convert_byte_to_string')
    @patch('examples.ca_handler.openssl_ca_handler.CAhandler._certificate_extensions_load')
    @patch('examples.ca_handler.openssl_ca_handler.CAhandler._certificate_store')
    @patch('OpenSSL.crypto.dump_certificate')
    @patch('OpenSSL.crypto.X509Extension')
    @patch('OpenSSL.crypto.X509')
    @patch('OpenSSL.crypto.load_certificate_request')
    @patch('examples.ca_handler.openssl_ca_handler.CAhandler._ca_load')
    @patch('examples.ca_handler.openssl_ca_handler.CAhandler._csr_check')
    @patch('examples.ca_handler.openssl_ca_handler.CAhandler._config_check')
    def test_128_enroll(self, mock_cfgchk, mock_csrchk, mock_caload, mock_csrload, mock_x509, mock_ext, mock_dmp, mock_store, mock_ext_load,  mock_b2s, mock_pem, mock_b64e):
        """ enroll  with extensions from openssl.cnf """
        mock_ext_load.return_value = {'foo': 'bar'}
        mock_ext = Mock()
        mock_cfgchk.return_value = None
        mock_csrchk.return_value = (True, None)
        ca_obj = Mock()
        ca_obj.subject_name_hash = Mock(return_value=42)
        mock_caload.return_value = ('ca_key', ca_obj)
        dn_obj = Mock()
        dn_obj.CN = 'foo'
        mock_csrload.return_value = Mock()
        mock_csrload.return_value.get_subject = Mock(return_value=dn_obj)
        extension = Mock()
        extension.get_short_name(return_value='short_name')
        mock_csrload.return_value.get_extensions = Mock(return_value=[extension, extension])
        mock_x509 = Mock()
        mock_dmp.return_value = 'dump'
        mock_store.return_value = True
        mock_b2s.return_value = 'b2s'
        mock_pem.return_value = 'pem'
        mock_b64e.return_value = 'b64e'
        self.cahandler.openssl_conf = 'openssl.cnf'
        self.assertEqual((None, 'pem', 'b2s', None), self.cahandler.enroll('csr'))

    @patch("builtins.open", mock_open(read_data='cacert'), create=True)
    @patch('base64.b64encode')
    @patch('examples.ca_handler.openssl_ca_handler.CAhandler._pemcertchain_generate')
    @patch('examples.ca_handler.openssl_ca_handler.convert_byte_to_string')
    @patch('examples.ca_handler.openssl_ca_handler.CAhandler._certificate_store')
    @patch('OpenSSL.crypto.dump_certificate')
    @patch('OpenSSL.crypto.X509Extension')
    @patch('OpenSSL.crypto.X509')
    @patch('OpenSSL.crypto.load_certificate_request')
    @patch('examples.ca_handler.openssl_ca_handler.CAhandler._ca_load')
    @patch('examples.ca_handler.openssl_ca_handler.CAhandler._csr_check')
    @patch('examples.ca_handler.openssl_ca_handler.CAhandler._config_check')
    def test_129_enroll(self, mock_cfgchk, mock_csrchk, mock_caload, mock_csrload, mock_x509, mock_ext, mock_dmp, mock_store, mock_b2s, mock_pem, mock_b64e):
        """ enroll enrollment without extenstions """
        mock_ext = Mock()
        mock_cfgchk.return_value = None
        mock_csrchk.return_value = (True, None)
        ca_obj = Mock()
        ca_obj.subject_name_hash = Mock(return_value=42)
        mock_caload.return_value = ('ca_key', ca_obj)
        dn_obj = Mock()
        dn_obj.CN = 'foo'
        mock_csrload.return_value = Mock()
        mock_csrload.return_value.get_subject = Mock(return_value=dn_obj)
        extension = Mock()
        extension.get_short_name = Mock(return_value='keyUsage')
        mock_csrload.return_value.get_extensions = Mock(return_value=[extension])
        mock_x509 = Mock()
        mock_dmp.return_value = 'dump'
        mock_store.return_value = True
        mock_b2s.return_value = 'b2s'
        mock_pem.return_value = 'pem'
        mock_b64e.return_value = 'b64e'
        self.assertEqual((None, 'pem', 'b2s', None), self.cahandler.enroll('csr'))

    @patch("builtins.open", mock_open(read_data='cacert'), create=True)
    @patch('base64.b64encode')
    @patch('examples.ca_handler.openssl_ca_handler.CAhandler._pemcertchain_generate')
    @patch('examples.ca_handler.openssl_ca_handler.convert_byte_to_string')
    @patch('examples.ca_handler.openssl_ca_handler.CAhandler._certificate_store')
    @patch('OpenSSL.crypto.dump_certificate')
    @patch('OpenSSL.crypto.X509Extension')
    @patch('OpenSSL.crypto.X509')
    @patch('OpenSSL.crypto.load_certificate_request')
    @patch('examples.ca_handler.openssl_ca_handler.CAhandler._ca_load')
    @patch('examples.ca_handler.openssl_ca_handler.CAhandler._csr_check')
    @patch('examples.ca_handler.openssl_ca_handler.CAhandler._config_check')
    def test_130_enroll(self, mock_cfgchk, mock_csrchk, mock_caload, mock_csrload, mock_x509, mock_ext, mock_dmp, mock_store, mock_b2s, mock_pem, mock_b64e):
        """ enroll with enforce cn """
        self.cahandler.cn_enforce = True
        mock_ext = Mock()
        mock_cfgchk.return_value = None
        mock_csrchk.return_value = (True, 'foo')
        ca_obj = Mock()
        ca_obj.subject_name_hash = Mock(return_value=42)
        mock_caload.return_value = ('ca_key', ca_obj)
        dn_obj = Mock()
        dn_obj.CN = 'foo'
        mock_csrload.return_value = Mock()
        mock_csrload.return_value.get_subject = Mock(return_value=dn_obj)
        extension = Mock()
        extension.get_short_name = Mock(return_value='keyUsage')
        mock_csrload.return_value.get_extensions = Mock(return_value=[extension])
        mock_x509 = Mock()
        mock_dmp.return_value = 'dump'
        mock_store.return_value = True
        mock_b2s.return_value = 'b2s'
        mock_pem.return_value = 'pem'
        mock_b64e.return_value = 'b64e'
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual((None, 'pem', 'b2s', None), self.cahandler.enroll('csr'))
        self.assertIn('INFO:test_a2c:CAhandler.enroll(): overwrite CN with foo', lcm.output)

    @patch("builtins.open", mock_open(read_data='cacert'), create=True)
    @patch('base64.b64encode')
    @patch('examples.ca_handler.openssl_ca_handler.CAhandler._pemcertchain_generate')
    @patch('examples.ca_handler.openssl_ca_handler.convert_byte_to_string')
    @patch('examples.ca_handler.openssl_ca_handler.CAhandler._certificate_store')
    @patch('OpenSSL.crypto.dump_certificate')
    @patch('OpenSSL.crypto.X509Extension')
    @patch('OpenSSL.crypto.X509')
    @patch('OpenSSL.crypto.load_certificate_request')
    @patch('examples.ca_handler.openssl_ca_handler.CAhandler._ca_load')
    @patch('examples.ca_handler.openssl_ca_handler.CAhandler._csr_check')
    @patch('examples.ca_handler.openssl_ca_handler.CAhandler._config_check')
    def test_131_enroll(self, mock_cfgchk, mock_csrchk, mock_caload, mock_csrload, mock_x509, mock_ext, mock_dmp, mock_store, mock_b2s, mock_pem, mock_b64e):
        """ enroll enrollment without extenstions """
        mock_ext = Mock()
        mock_cfgchk.return_value = None
        mock_csrchk.return_value = (True, None)
        ca_obj = Mock()
        ca_obj.subject_name_hash = Mock(return_value=42)
        mock_caload.return_value = ('ca_key', ca_obj)
        dn_obj = Mock()
        dn_obj.CN = 'foo'
        mock_csrload.return_value = Mock()
        mock_csrload.return_value.get_subject = Mock(return_value=dn_obj)
        extension = Mock()
        extension.get_short_name = Mock(return_value=b'keyUsage')
        mock_csrload.return_value.get_extensions = Mock(return_value=[extension])
        mock_x509 = Mock()
        mock_dmp.return_value = 'dump'
        mock_store.return_value = True
        mock_b2s.return_value = 'keyUsage'
        mock_pem.return_value = 'pem'
        mock_b64e.return_value = 'b64e'
        self.assertEqual((None, 'pem', 'keyUsage', None), self.cahandler.enroll('csr'))
        self.assertTrue(mock_caload.called)
        self.assertTrue(mock_csrload.called)

    def test_132_duplicates_clean(self):
        """ duplicates_clean no extensions in csr """

        default_extension_list = [
            crypto.X509Extension(convert_string_to_byte('basicConstraints'), True, convert_string_to_byte('CA:FALSE')),
            crypto.X509Extension(convert_string_to_byte('extendedKeyUsage'), False, convert_string_to_byte('clientAuth,serverAuth')),
        ]
        csr_extension_list = [
            crypto.X509Extension(convert_string_to_byte('subjectAltName'), False, convert_string_to_byte('DNS:localhost'))
        ]
        self.assertEqual(b'subjectAltName', self.cahandler._duplicates_clean(default_extension_list, csr_extension_list)[0].get_short_name())
        self.assertEqual('DNS:localhost', self.cahandler._duplicates_clean(default_extension_list, csr_extension_list)[0].__str__())
        self.assertEqual(b'basicConstraints', self.cahandler._duplicates_clean(default_extension_list, csr_extension_list)[1].get_short_name())
        self.assertEqual('CA:FALSE', self.cahandler._duplicates_clean(default_extension_list, csr_extension_list)[1].__str__())
        self.assertEqual(b'extendedKeyUsage', self.cahandler._duplicates_clean(default_extension_list, csr_extension_list)[2].get_short_name())
        self.assertEqual('TLS Web Client Authentication, TLS Web Server Authentication', self.cahandler._duplicates_clean(default_extension_list, csr_extension_list)[2].__str__())

    def test_133_duplicates_clean(self):
        """ duplicates_clean no extensions in defaultextensions """

        csr_extension_list = [
            crypto.X509Extension(convert_string_to_byte('subjectAltName'), False, convert_string_to_byte('DNS:localhost')),
            crypto.X509Extension(convert_string_to_byte('basicConstraints'), True, convert_string_to_byte('CA:FALSE')),
            crypto.X509Extension(convert_string_to_byte('extendedKeyUsage'), False, convert_string_to_byte('clientAuth,serverAuth')),
        ]
        default_extension_list = []
        self.assertEqual(b'subjectAltName', self.cahandler._duplicates_clean(default_extension_list, csr_extension_list)[0].get_short_name())
        self.assertEqual('DNS:localhost', self.cahandler._duplicates_clean(default_extension_list, csr_extension_list)[0].__str__())
        self.assertEqual(b'basicConstraints', self.cahandler._duplicates_clean(default_extension_list, csr_extension_list)[1].get_short_name())
        self.assertEqual('CA:FALSE', self.cahandler._duplicates_clean(default_extension_list, csr_extension_list)[1].__str__())
        self.assertEqual(b'extendedKeyUsage', self.cahandler._duplicates_clean(default_extension_list, csr_extension_list)[2].get_short_name())
        self.assertEqual('TLS Web Client Authentication, TLS Web Server Authentication', self.cahandler._duplicates_clean(default_extension_list, csr_extension_list)[2].__str__())

    def test_134_duplicates_clean(self):
        """ duplicates_clean no extensions default extension overrides cert extension """

        default_extension_list = [
            crypto.X509Extension(convert_string_to_byte('basicConstraints'), True, convert_string_to_byte('CA:FALSE')),
            crypto.X509Extension(convert_string_to_byte('extendedKeyUsage'), False, convert_string_to_byte('clientAuth,serverAuth')),
        ]
        csr_extension_list = [
            crypto.X509Extension(convert_string_to_byte('subjectAltName'), False, convert_string_to_byte('DNS:localhost')),
            crypto.X509Extension(convert_string_to_byte('basicConstraints'), True, convert_string_to_byte('CA:TRUE')),
            crypto.X509Extension(convert_string_to_byte('extendedKeyUsage'), False, convert_string_to_byte('serverAuth')),
        ]
        self.assertEqual(b'subjectAltName', self.cahandler._duplicates_clean(default_extension_list, csr_extension_list)[0].get_short_name())
        self.assertEqual('DNS:localhost', self.cahandler._duplicates_clean(default_extension_list, csr_extension_list)[0].__str__())
        self.assertEqual(b'basicConstraints', self.cahandler._duplicates_clean(default_extension_list, csr_extension_list)[1].get_short_name())
        self.assertEqual('CA:FALSE', self.cahandler._duplicates_clean(default_extension_list, csr_extension_list)[1].__str__())
        self.assertEqual(b'extendedKeyUsage', self.cahandler._duplicates_clean(default_extension_list, csr_extension_list)[2].get_short_name())
        self.assertEqual('TLS Web Client Authentication, TLS Web Server Authentication', self.cahandler._duplicates_clean(default_extension_list, csr_extension_list)[2].__str__())

    def test_135_duplicates_clean(self):
        """ duplicates_clean no extensions default extension overrides cert extension """

        default_extension_list = [
            crypto.X509Extension(convert_string_to_byte('basicConstraints'), True, convert_string_to_byte('CA:FALSE')),
            crypto.X509Extension(convert_string_to_byte('extendedKeyUsage'), False, convert_string_to_byte('serverAuth')),
        ]
        csr_extension_list = [
            crypto.X509Extension(convert_string_to_byte('subjectAltName'), False, convert_string_to_byte('DNS:localhost')),
            crypto.X509Extension(convert_string_to_byte('basicConstraints'), True, convert_string_to_byte('CA:TRUE')),
            crypto.X509Extension(convert_string_to_byte('extendedKeyUsage'), False, convert_string_to_byte('clientAuth,serverAuth')),
        ]
        self.assertEqual(b'basicConstraints', self.cahandler._duplicates_clean(default_extension_list, csr_extension_list)[1].get_short_name())
        self.assertEqual(b'subjectAltName', self.cahandler._duplicates_clean(default_extension_list, csr_extension_list)[0].get_short_name())
        self.assertEqual('DNS:localhost', self.cahandler._duplicates_clean(default_extension_list, csr_extension_list)[0].__str__())
        self.assertEqual('CA:FALSE', self.cahandler._duplicates_clean(default_extension_list, csr_extension_list)[1].__str__())
        self.assertEqual(b'extendedKeyUsage', self.cahandler._duplicates_clean(default_extension_list, csr_extension_list)[2].get_short_name())
        self.assertEqual('TLS Web Server Authentication', self.cahandler._duplicates_clean(default_extension_list, csr_extension_list)[2].__str__())

    def test_136_duplicates_clean(self):
        """ duplicates_clean no extensions default copy csr-extension to default_extensoion """

        default_extension_list = [
            crypto.X509Extension(convert_string_to_byte('basicConstraints'), True, convert_string_to_byte('CA:FALSE')),
        ]
        csr_extension_list = [
            crypto.X509Extension(convert_string_to_byte('subjectAltName'), False, convert_string_to_byte('DNS:localhost')),
            crypto.X509Extension(convert_string_to_byte('basicConstraints'), True, convert_string_to_byte('CA:TRUE')),
            crypto.X509Extension(convert_string_to_byte('extendedKeyUsage'), False, convert_string_to_byte('clientAuth,serverAuth')),
        ]
        self.assertEqual(b'subjectAltName', self.cahandler._duplicates_clean(default_extension_list, csr_extension_list)[0].get_short_name())
        self.assertEqual('DNS:localhost', self.cahandler._duplicates_clean(default_extension_list, csr_extension_list)[0].__str__())
        self.assertEqual(b'extendedKeyUsage', self.cahandler._duplicates_clean(default_extension_list, csr_extension_list)[1].get_short_name())
        self.assertEqual('TLS Web Client Authentication, TLS Web Server Authentication', self.cahandler._duplicates_clean(default_extension_list, csr_extension_list)[1].__str__())
        self.assertEqual(b'basicConstraints', self.cahandler._duplicates_clean(default_extension_list, csr_extension_list)[2].get_short_name())
        self.assertEqual('CA:FALSE', self.cahandler._duplicates_clean(default_extension_list, csr_extension_list)[2].__str__())


if __name__ == '__main__':

    unittest.main()
