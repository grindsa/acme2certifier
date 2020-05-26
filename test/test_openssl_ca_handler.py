#!/usr/bin/python
# -*- coding: utf-8 -*-
""" unittests for openssl_ca_handler """
import sys
import os
import unittest
try:
    from mock import patch #, MagicMock, Mock
except ImportError:
    from unittest.mock import patch #, MagicMock, Mock
from OpenSSL import crypto

sys.path.insert(0, '..')

class TestACMEHandler(unittest.TestCase):
    """ test class for cgi_handler """

    def setUp(self):
        """ setup unittest """
        import logging
        from examples.ca_handler.openssl_ca_handler import CAhandler
        logging.basicConfig(
            # format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            format='%(asctime)s - acme2certifier - %(levelname)s - %(message)s',
            datefmt="%Y-%m-%d %H:%M:%S",
            level=logging.INFO)
        self.logger = logging.getLogger('test_acme2certifier')
        self.cahandler = CAhandler(False, self.logger)

    def test_001_default(self):
        """ default test which always passes """
        self.assertEqual('foo', 'foo')

    def test_002_check_config(self):
        """ CAhandler._config_check with an empty config_dict """
        self.cahandler.issuer_dict = {}
        self.assertEqual('issuing_ca_key not specfied in config_file', self.cahandler._config_check())

    def test_003_check_config(self):
        """ CAhandler._config_check with key in config_dict but not existing """
        self.cahandler.issuer_dict = {'issuing_ca_key': 'foo.pem'}
        self.assertEqual('issuing_ca_key foo.pem does not exist', self.cahandler._config_check())

    def test_004_check_config(self):
        """ CAhandler._config_check with key in config_dict key is existing """
        self.cahandler.issuer_dict = {'issuing_ca_key': 'ca/sub-ca-key.pem'}
        # mock_exists.return_value = True
        self.assertEqual('issuing_ca_cert must be specified in config file', self.cahandler._config_check())

    def test_005_check_config(self):
        """ CAhandler._config_check with key and cert in config_dict but cert does not exist """
        self.cahandler.issuer_dict = {'issuing_ca_key': 'ca/sub-ca-key.pem', 'issuing_ca_cert': 'bar'}
        self.assertEqual('issuing_ca_cert bar does not exist', self.cahandler._config_check())

    def test_006_check_config(self):
        """ CAhandler._config_check withoutissuing_ca_crl in config_dic """
        self.cahandler.issuer_dict = {'issuing_ca_key': 'ca/sub-ca-key.pem', 'issuing_ca_cert': 'ca/sub-ca-cert.pem'}
        self.assertEqual('issuing_ca_crl must be specified in config file', self.cahandler._config_check())

    def test_007_check_config(self):
        """ CAhandler._config_check with wrong CRL in config_dic """
        self.cahandler.issuer_dict = {'issuing_ca_key': 'ca/sub-ca-key.pem', 'issuing_ca_cert': 'ca/sub-ca-cert.pem', 'issuing_ca_crl': 'foo.pem'}
        self.assertEqual('issuing_ca_crl foo.pem does not exist', self.cahandler._config_check())

    def test_008_check_config(self):
        """ CAhandler._config_check without cert save path """
        self.cahandler.issuer_dict = {'issuing_ca_key': 'ca/sub-ca-key.pem', 'issuing_ca_cert': 'ca/sub-ca-cert.pem', 'issuing_ca_crl': 'ca/sub-ca-crl.pem'}
        self.assertEqual('cert_save_path must be specified in config file', self.cahandler._config_check())

    def test_009_check_config(self):
        """ CAhandler._config_check with key and cert in config_dict """
        self.cahandler.issuer_dict = {'issuing_ca_key': 'ca/sub-ca-key.pem', 'issuing_ca_cert': 'ca/sub-ca-cert.pem', 'issuing_ca_crl': 'ca/sub-ca-crl.pem'}
        self.cahandler.cert_save_path = 'foo'
        self.assertEqual('cert_save_path foo does not exist', self.cahandler._config_check())

    def test_010_check_config(self):
        """ CAhandler._config_check with empty ca_chain_list """
        self.cahandler.issuer_dict = {'issuing_ca_key': 'ca/sub-ca-key.pem', 'issuing_ca_cert': 'ca/sub-ca-cert.pem', 'issuing_ca_crl': 'ca/sub-ca-crl.pem'}
        self.cahandler.cert_save_path = 'ca/certs'
        self.assertEqual('ca_cert_chain_list must be specified in config file', self.cahandler._config_check())

    def test_011_check_config(self):
        """ CAhandler._config_check completed """
        self.cahandler.issuer_dict = {'issuing_ca_key': 'ca/sub-ca-key.pem', 'issuing_ca_cert': 'ca/sub-ca-cert.pem', 'issuing_ca_crl': 'ca/sub-ca-crl.pem'}
        self.cahandler.cert_save_path = 'ca/certs'
        self.cahandler.ca_cert_chain_list = ['foo', 'bar']
        self.assertFalse(self.cahandler._config_check())

    def test_012_check_config(self):
        """ CAhandler._config_check with wrong openssl.conf """
        self.cahandler.issuer_dict = {'issuing_ca_key': 'ca/sub-ca-key.pem', 'issuing_ca_cert': 'ca/sub-ca-cert.pem', 'issuing_ca_crl': 'ca/sub-ca-crl.pem'}
        self.cahandler.cert_save_path = 'ca/certs'
        self.cahandler.ca_cert_chain_list = ['foo', 'bar']
        self.cahandler.openssl_conf = 'foo'
        self.assertEqual('openssl_conf foo does not exist', self.cahandler._config_check())

    def test_013_check_config(self):
        """ CAhandler._config_check with openssl.conf completed successfully """
        self.cahandler.issuer_dict = {'issuing_ca_key': 'ca/sub-ca-key.pem', 'issuing_ca_cert': 'ca/sub-ca-cert.pem', 'issuing_ca_crl': 'ca/sub-ca-crl.pem'}
        self.cahandler.cert_save_path = 'ca/certs'
        self.cahandler.ca_cert_chain_list = ['foo', 'bar']
        self.cahandler.openssl_conf = 'ca/fr1.txt'
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
        with open('ca/sub-ca-crl.pem', 'r') as fso:
            crl = crypto.load_crl(crypto.FILETYPE_PEM, fso.read())
            self.assertFalse(self.cahandler._crl_check(crl, 2))

    def test_017_check_serialagainstcrl(self):
        """ CAhandler._crl_check with a serial number already in CRL"""
        # crl = crypto.load_crl(crypto.FILETYPE_PEM, open('ca/sub-ca-crl.pem').read())
        with open('ca/sub-ca-crl.pem', 'r') as fso:
            crl = crypto.load_crl(crypto.FILETYPE_PEM, fso.read())
        self.assertTrue(self.cahandler._crl_check(crl, '5d0e9535'))

    def test_018_generate_pem_chain(self):
        """ CAhandler._pemcertchain_generate with EE cert but no ca cert"""
        self.assertEqual('ee-cert', self.cahandler._pemcertchain_generate('ee-cert', None))

    def test_019_generate_pem_chain(self):
        """ CAhandler._pemcertchain_generate with EE cert and ca cert"""
        self.assertEqual('ee-certca-cert', self.cahandler._pemcertchain_generate('ee-cert', 'ca-cert'))

    def test_020_generate_pem_chain(self):
        """ CAhandler._pemcertchain_generate with EE cert ca and an invalit entry in cert_cain_list cert"""
        self.cahandler.ca_cert_chain_list = ['foo.pem']
        self.assertEqual('ee-certca-cert', self.cahandler._pemcertchain_generate('ee-cert', 'ca-cert'))

    def test_021_generate_pem_chain(self):
        """ CAhandler._pemcertchain_generate with EE cert ca and an valid entry in cert_cain_list cert"""
        self.cahandler.ca_cert_chain_list = ['ca/fr1.txt']
        self.assertEqual('ee-cert_ca-cert_fakeroot-cert-1', self.cahandler._pemcertchain_generate('ee-cert', '_ca-cert'))

    def test_022_generate_pem_chain(self):
        """ CAhandler._pemcertchain_generate with EE cert ca and two valid entry in cert_cain_list"""
        self.cahandler.ca_cert_chain_list = ['ca/fr1.txt', 'ca/fr2.txt']
        self.assertEqual('ee-cert_ca-cert_fakeroot-cert-1_fakeroot-cert-2', self.cahandler._pemcertchain_generate('ee-cert', '_ca-cert'))

    def test_023_generate_pem_chain(self):
        """ CAhandler._pemcertchain_generate with EE cert ca and two valid entry in cert_cain_list and two invalid entriest"""
        self.cahandler.ca_cert_chain_list = ['ca/fr1.txt', 'foo1', 'ca/fr2.txt', 'foo2']
        self.assertEqual('ee-cert_ca-cert_fakeroot-cert-1_fakeroot-cert-2', self.cahandler._pemcertchain_generate('ee-cert', '_ca-cert'))

    def test_024_load_ca_key_cert(self):
        """ CAhandler._ca_load() with empty issuer_dict """
        self.cahandler.issuer_dict = {}
        self.assertEqual((None, None), self.cahandler._ca_load())

    def test_025_load_ca_key_cert(self):
        """ CAhandler._ca_load() with issuer_dict containing invalid key """
        self.cahandler.issuer_dict = {'issuing_ca_key': 'foo.pem'}
        self.assertEqual((None, None), self.cahandler._ca_load())

    @patch('OpenSSL.crypto.load_privatekey')
    def test_026_load_ca_key_cert(self, mock_crypto):
        """ CAhandler._ca_load() with issuer_dict containing valid key """
        self.cahandler.issuer_dict = {'issuing_ca_key': 'ca/sub-ca-key.pem'}
        mock_crypto.return_value = 'foo'
        self.assertEqual(('foo', None), self.cahandler._ca_load())

    @patch('OpenSSL.crypto.load_privatekey')
    def test_027_load_ca_key_cert(self, mock_crypto):
        """ CAhandler._ca_load() with issuer_dict containing key and passphrase """
        self.cahandler.issuer_dict = {'issuing_ca_key': 'ca/sub-ca-key.pem', 'passphrase': 'Test1234'}
        mock_crypto.return_value = 'foo'
        self.assertEqual(('foo', None), self.cahandler._ca_load())

    @patch('OpenSSL.crypto.load_privatekey')
    def test_028_load_ca_key_cert(self, mock_crypto):
        """ CAhandler._ca_load() with issuer_dict containing key and invalid cert """
        self.cahandler.issuer_dict = {'issuing_ca_key': 'ca/sub-ca-key.pem', 'passphrase': 'Test1234', 'issuing_ca_cert': 'foo.pem'}
        mock_crypto.return_value = 'foo'
        self.assertEqual(('foo', None), self.cahandler._ca_load())

    @patch('OpenSSL.crypto.load_certificate')
    @patch('OpenSSL.crypto.load_privatekey')
    def test_029_load_ca_key_cert(self, mock_crypto_key, mock_crypto_cert):
        """ CAhandler._ca_load() with issuer_dict containing key and invalid cert """
        self.cahandler.issuer_dict = {'issuing_ca_key': 'ca/sub-ca-key.pem', 'passphrase': 'Test1234', 'issuing_ca_cert': 'ca/sub-ca-cert.pem'}
        mock_crypto_key.return_value = 'foo'
        mock_crypto_cert.return_value = 'bar'
        self.assertEqual(('foo', 'bar'), self.cahandler._ca_load())

    def test_030_verifycertificatechain(self):
        """ successful verification of one level certificate chain """
        with open('ca/root-ca-client.txt', 'r') as fso:
            cert = fso.read()
        with open('ca/root-ca-cert.pem', 'r') as fso:
            ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, fso.read())
        self.assertFalse(self.cahandler._certificate_chain_verify(cert, ca_cert))

    def test_031_verifycertificatechain(self):
        """ unsuccessful verification of one level certificate chain """
        with open('ca/sub-ca-client.txt', 'r') as fso:
            cert = fso.read()
        with open('ca/root-ca-cert.pem', 'r') as fso:
            ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, fso.read())
        self.assertEqual("[20, 0, 'unable to get local issuer certificate']", self.cahandler._certificate_chain_verify(cert, ca_cert))

    def test_032_verifycertificatechain(self):
        """ unsuccessful verification of two level certificate chain with incomplete chain"""
        with open('ca/sub-ca-client.txt', 'r') as fso:
            cert = fso.read()
        with open('ca/sub-ca-cert.pem', 'r') as fso:
            ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, fso.read())
        self.assertEqual("[2, 1, 'unable to get issuer certificate']", self.cahandler._certificate_chain_verify(cert, ca_cert))

    def test_033_verifycertificatechain(self):
        """ successful verification of two level certificate chain with complete chain"""
        self.cahandler.ca_cert_chain_list = ['ca/root-ca-cert.pem']
        with open('ca/sub-ca-client.txt', 'r') as fso:
            cert = fso.read()
        with open('ca/sub-ca-cert.pem', 'r') as fso:
            ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, fso.read())
        self.assertFalse(self.cahandler._certificate_chain_verify(cert, ca_cert))

    def test_034_verifycertificatechain(self):
        """ unsuccessful verification as certificate is damaged"""
        cert = 'foo'
        with open('ca/root-ca-cert.pem', 'r') as fso:
            ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, fso.read())
        self.assertEqual('certificate could not get parsed', (self.cahandler._certificate_chain_verify(cert, ca_cert)))

    def test_035_verifycertificatechain(self):
        """ unsuccessful verification as ca-certificate is damaged"""
        with open('ca/root-ca-client.txt', 'r') as fso:
            cert = fso.read()
        ca_cert = 'foo'
        self.assertEqual('issuing certificate could not be added to trust-store', self.cahandler._certificate_chain_verify(cert, ca_cert))

    def test_036_verifycertificatechain(self):
        """ unsuccessful verification of two level certificate chain as cain cert is damaged"""
        self.cahandler.ca_cert_chain_list = ['ca/root-.pem']
        with open('ca/sub-ca-client.txt', 'r') as fso:
            cert = fso.read()
        with open('ca/sub-ca-cert.pem', 'r') as fso:
            ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, fso.read())
        self.assertEqual('certificate ca/root-.pem could not be added to trust store', self.cahandler._certificate_chain_verify(cert, ca_cert))

    def test_037_revocation(self):
        """ revocation without having a CRL in issuer_dic """
        with open('ca/sub-ca-client.txt', 'r') as fso:
            cert = fso.read()
        self.assertEqual((400, 'urn:ietf:params:acme:error:serverInternal', 'Unsupported operation'), self.cahandler.revoke(cert))

    def test_038_revocation(self):
        """ revocation without having a CRL in issuer_dic but none"""
        self.cahandler.issuer_dict = {'crl' : None}
        with open('ca/sub-ca-client.txt', 'r') as fso:
            cert = fso.read()
        self.assertEqual((400, 'urn:ietf:params:acme:error:serverInternal', 'Unsupported operation'), self.cahandler.revoke(cert))

    @patch('examples.ca_handler.openssl_ca_handler.CAhandler._certificate_chain_verify')
    @patch('examples.ca_handler.openssl_ca_handler.CAhandler._ca_load')
    def test_039_revocation(self, mock_ca_load, mock_vrf):
        """ revocation cert validation failed """
        with open('ca/sub-ca-client.txt', 'r') as fso:
            cert = fso.read()
        self.cahandler.issuer_dict = {'issuing_ca_key': 'ca/sub-ca-key.pem', 'passphrase': 'Test1234', 'issuing_ca_cert': 'ca/sub-ca-cert.pem', 'issuing_ca_crl' : 'ca/foo-ca-crl.pem'}
        mock_ca_load.return_value = ('ca_key', 'ca_cert')
        mock_vrf.return_value = 'foo'
        self.assertEqual((400, 'urn:ietf:params:acme:error:serverInternal', 'foo'), self.cahandler.revoke(cert))

    @patch('examples.ca_handler.openssl_ca_handler.CAhandler._certificate_chain_verify')
    @patch('examples.ca_handler.openssl_ca_handler.CAhandler._ca_load')
    def test_040_revocation(self, mock_ca_load, mock_vrf):
        """ revocation cert no CA key """
        with open('ca/sub-ca-client.txt', 'r') as fso:
            cert = fso.read()
        self.cahandler.issuer_dict = {'issuing_ca_key': 'ca/sub-ca-key.pem', 'passphrase': 'Test1234', 'issuing_ca_cert': 'ca/sub-ca-cert.pem', 'issuing_ca_crl' : 'ca/foo-ca-crl.pem'}
        mock_ca_load.return_value = (None, 'ca_cert')
        mock_vrf.return_value = None
        self.assertEqual((400, 'urn:ietf:params:acme:error:serverInternal', 'configuration error'), self.cahandler.revoke(cert))

    @patch('examples.ca_handler.openssl_ca_handler.CAhandler._certificate_chain_verify')
    @patch('examples.ca_handler.openssl_ca_handler.CAhandler._ca_load')
    def test_041_revocation(self, mock_ca_load, mock_vrf):
        """ revocation cert no CA cert """
        with open('ca/sub-ca-client.txt', 'r') as fso:
            cert = fso.read()
        self.cahandler.issuer_dict = {'issuing_ca_key': 'ca/sub-ca-key.pem', 'passphrase': 'Test1234', 'issuing_ca_cert': 'ca/sub-ca-cert.pem', 'issuing_ca_crl' : 'ca/foo-ca-crl.pem'}
        mock_ca_load.return_value = ('ca_key', None)
        mock_vrf.return_value = None
        self.assertEqual((400, 'urn:ietf:params:acme:error:serverInternal', 'configuration error'), self.cahandler.revoke(cert))

    @patch('examples.ca_handler.openssl_ca_handler.cert_serial_get')
    @patch('examples.ca_handler.openssl_ca_handler.CAhandler._certificate_chain_verify')
    @patch('examples.ca_handler.openssl_ca_handler.CAhandler._ca_load')
    def test_042_revocation(self, mock_ca_load, mock_vrf, mock_serial):
        """ revocation cert no serial """
        with open('ca/sub-ca-client.txt', 'r') as fso:
            cert = fso.read()
        self.cahandler.issuer_dict = {'issuing_ca_key': 'ca/sub-ca-key.pem', 'passphrase': 'Test1234', 'issuing_ca_cert': 'ca/sub-ca-cert.pem', 'issuing_ca_crl' : 'ca/foo-ca-crl.pem'}
        mock_ca_load.return_value = ('ca_key', 'ca_cert')
        mock_vrf.return_value = None
        mock_serial.return_value = None
        self.assertEqual((400, 'urn:ietf:params:acme:error:serverInternal', 'configuration error'), self.cahandler.revoke(cert))

    @patch('examples.ca_handler.openssl_ca_handler.cert_serial_get')
    @patch('examples.ca_handler.openssl_ca_handler.CAhandler._certificate_chain_verify')
    # @patch('examples.ca_handler.openssl_ca_handler.CAhandler._ca_load')
    def test_043_revocation(self, mock_vrf, mock_serial):
        """ revocation cert """
        with open('ca/sub-ca-client.txt', 'r') as fso:
            cert = fso.read()
        self.cahandler.issuer_dict = {'issuing_ca_key': 'ca/sub-ca-key.pem', 'passphrase': 'Test1234', 'issuing_ca_cert': 'ca/sub-ca-cert.pem', 'issuing_ca_crl' : 'ca/foo-ca-crl.pem'}
        # mock_ca_load.return_value = ('ca_key', 'ca_cert')
        mock_vrf.return_value = None
        mock_serial.return_value = 14
        self.assertEqual((200, None, None), self.cahandler.revoke(cert))

    @patch('examples.ca_handler.openssl_ca_handler.CAhandler._crl_check')
    @patch('examples.ca_handler.openssl_ca_handler.cert_serial_get')
    @patch('examples.ca_handler.openssl_ca_handler.CAhandler._certificate_chain_verify')
    def test_044_revocation(self, mock_vrf, mock_serial, mock_crl):
        """ revocation cert """
        with open('ca/sub-ca-client.txt', 'r') as fso:
            cert = fso.read()
        self.cahandler.issuer_dict = {'issuing_ca_key': 'ca/sub-ca-key.pem', 'passphrase': 'Test1234', 'issuing_ca_cert': 'ca/sub-ca-cert.pem', 'issuing_ca_crl' : 'ca/foo-ca-crl.pem'}
        # mock_ca_load.return_value = ('ca_key', 'ca_cert')
        mock_vrf.return_value = None
        mock_serial.return_value = 14
        mock_crl.return_value = True
        self.assertEqual((400, 'urn:ietf:params:acme:error:alreadyRevoked', 'Certificate has already been revoked'), self.cahandler.revoke(cert))

if __name__ == '__main__':

    if os.path.exists('acme_test.db'):
        os.remove('acme_test.db')
    unittest.main()
