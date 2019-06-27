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
        """ CAhandler.check_config with an empty config_dict """
        self.cahandler.issuer_dict = {}
        self.assertEqual('key "key" does not exist in config_hash', self.cahandler.check_config())

    def test_003_check_config(self):
        """ CAhandler.check_config with key in config_dict but not existing """
        self.cahandler.issuer_dict = {'key': 'foo.pem'}
        self.assertEqual('signing key foo.pem does not exist', self.cahandler.check_config())

    def test_004_check_config(self):
        """ CAhandler.check_config with key in config_dict key is existing """
        self.cahandler.issuer_dict = {'key': 'ca/sub-ca-key.pem'}
        # mock_exists.return_value = True
        self.assertEqual('key "cert" does not exist in config_hash', self.cahandler.check_config())

    def test_005_check_config(self):
        """ CAhandler.check_config with key and cert in config_dict but cert does not exist """
        self.cahandler.issuer_dict = {'key': 'ca/sub-ca-key.pem', 'cert': 'bar'}
        self.assertEqual('signing cert bar does not exist', self.cahandler.check_config())

    def test_006_check_config(self):
        """ CAhandler.check_config with key and cert in config_dict """
        self.cahandler.issuer_dict = {'key': 'ca/sub-ca-key.pem', 'cert': 'ca/sub-ca-cert.pem'}
        self.assertFalse(self.cahandler.check_config())

    def test_007_check_serialagainstcrl(self):
        """ CAhandler.check_serial_against_crl without specifying a CRL"""
        crl = None
        self.assertFalse(self.cahandler.check_serial_against_crl(crl, 1))

    def test_008_check_serialagainstcrl(self):
        """ CAhandler.check_serial_against_crl without specifying a serial number"""
        crl = 'foo'
        self.assertFalse(self.cahandler.check_serial_against_crl(crl, None))

    def test_009_check_serialagainstcrl(self):
        """ CAhandler.check_serial_against_crl with a serial number not in CRL"""
        with open('ca/sub-ca-crl.pem', 'r') as fso:
            crl = crypto.load_crl(crypto.FILETYPE_PEM, fso.read())
            self.assertFalse(self.cahandler.check_serial_against_crl(crl, 2))

    def test_010_check_serialagainstcrl(self):
        """ CAhandler.check_serial_against_crl with a serial number already in CRL"""
        # crl = crypto.load_crl(crypto.FILETYPE_PEM, open('ca/sub-ca-crl.pem').read())
        with open('ca/sub-ca-crl.pem', 'r') as fso:
            crl = crypto.load_crl(crypto.FILETYPE_PEM, fso.read())
        self.assertTrue(self.cahandler.check_serial_against_crl(crl, '5d0e9535'))

    def test_011_generate_pem_chain(self):
        """ CAhandler.generate_pem_cert_chain with EE cert but no ca cert"""
        self.assertEqual('ee-cert', self.cahandler.generate_pem_cert_chain('ee-cert', None))

    def test_012_generate_pem_chain(self):
        """ CAhandler.generate_pem_cert_chain with EE cert and ca cert"""
        self.assertEqual('ee-certca-cert', self.cahandler.generate_pem_cert_chain('ee-cert', 'ca-cert'))

    def test_013_generate_pem_chain(self):
        """ CAhandler.generate_pem_cert_chain with EE cert ca and an invalit entry in cert_cain_list cert"""
        self.cahandler.ca_cert_chain_list = ['foo.pem']
        self.assertEqual('ee-certca-cert', self.cahandler.generate_pem_cert_chain('ee-cert', 'ca-cert'))

    def test_014_generate_pem_chain(self):
        """ CAhandler.generate_pem_cert_chain with EE cert ca and an valid entry in cert_cain_list cert"""
        self.cahandler.ca_cert_chain_list = ['ca/fr1.txt']
        self.assertEqual('ee-cert_ca-cert_fakeroot-cert-1', self.cahandler.generate_pem_cert_chain('ee-cert', '_ca-cert'))

    def test_015_generate_pem_chain(self):
        """ CAhandler.generate_pem_cert_chain with EE cert ca and two valid entry in cert_cain_list"""
        self.cahandler.ca_cert_chain_list = ['ca/fr1.txt', 'ca/fr2.txt']
        self.assertEqual('ee-cert_ca-cert_fakeroot-cert-1_fakeroot-cert-2', self.cahandler.generate_pem_cert_chain('ee-cert', '_ca-cert'))

    def test_016_generate_pem_chain(self):
        """ CAhandler.generate_pem_cert_chain with EE cert ca and two valid entry in cert_cain_list and two invalid entriest"""
        self.cahandler.ca_cert_chain_list = ['ca/fr1.txt', 'foo1', 'ca/fr2.txt', 'foo2']
        self.assertEqual('ee-cert_ca-cert_fakeroot-cert-1_fakeroot-cert-2', self.cahandler.generate_pem_cert_chain('ee-cert', '_ca-cert'))

    def test_017_load_ca_key_cert(self):
        """ CAhandler.load_ca_key_cert() with empty issuer_dict """
        self.cahandler.issuer_dict = {}
        self.assertEqual((None, None), self.cahandler.load_ca_key_cert())

    def test_018_load_ca_key_cert(self):
        """ CAhandler.load_ca_key_cert() with issuer_dict containing invalid key """
        self.cahandler.issuer_dict = {'key': 'foo.pem'}
        self.assertEqual((None, None), self.cahandler.load_ca_key_cert())

    @patch('OpenSSL.crypto.load_privatekey')
    def test_019_load_ca_key_cert(self, mock_crypto):
        """ CAhandler.load_ca_key_cert() with issuer_dict containing valid key """
        self.cahandler.issuer_dict = {'key': 'ca/sub-ca-key.pem'}
        mock_crypto.return_value = 'foo'
        self.assertEqual(('foo', None), self.cahandler.load_ca_key_cert())

    @patch('OpenSSL.crypto.load_privatekey')
    def test_020_load_ca_key_cert(self, mock_crypto):
        """ CAhandler.load_ca_key_cert() with issuer_dict containing key and passphrase """
        self.cahandler.issuer_dict = {'key': 'ca/sub-ca-key.pem', 'passphrase': 'Test1234'}
        mock_crypto.return_value = 'foo'
        self.assertEqual(('foo', None), self.cahandler.load_ca_key_cert())

    @patch('OpenSSL.crypto.load_privatekey')
    def test_021_load_ca_key_cert(self, mock_crypto):
        """ CAhandler.load_ca_key_cert() with issuer_dict containing key and invalid cert """
        self.cahandler.issuer_dict = {'key': 'ca/sub-ca-key.pem', 'passphrase': 'Test1234', 'cert': 'foo.pem'}
        mock_crypto.return_value = 'foo'
        self.assertEqual(('foo', None), self.cahandler.load_ca_key_cert())

    @patch('OpenSSL.crypto.load_certificate')
    @patch('OpenSSL.crypto.load_privatekey')
    def test_022_load_ca_key_cert(self, mock_crypto_key, mock_crypto_cert):
        """ CAhandler.load_ca_key_cert() with issuer_dict containing key and invalid cert """
        self.cahandler.issuer_dict = {'key': 'ca/sub-ca-key.pem', 'passphrase': 'Test1234', 'cert': 'ca/sub-ca-cert.pem'}
        mock_crypto_key.return_value = 'foo'
        mock_crypto_cert.return_value = 'bar'
        self.assertEqual(('foo', 'bar'), self.cahandler.load_ca_key_cert())

    def test_023_verifycertificatechain(self):
        """ successful verification of one level certificate chain """
        with open('ca/root-ca-client.txt', 'r') as fso:
            cert = fso.read()
        with open('ca/root-ca-cert.pem', 'r') as fso:
            ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, fso.read())
        self.assertFalse(self.cahandler.verify_certificate_chain(cert, ca_cert))

    def test_024_verifycertificatechain(self):
        """ unsuccessful verification of one level certificate chain """
        with open('ca/sub-ca-client.txt', 'r') as fso:
            cert = fso.read()
        with open('ca/root-ca-cert.pem', 'r') as fso:
            ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, fso.read())
        self.assertEqual("[20, 0, 'unable to get local issuer certificate']", self.cahandler.verify_certificate_chain(cert, ca_cert))

    def test_025_verifycertificatechain(self):
        """ unsuccessful verification of two level certificate chain with incomplete chain"""
        with open('ca/sub-ca-client.txt', 'r') as fso:
            cert = fso.read()
        with open('ca/sub-ca-cert.pem', 'r') as fso:
            ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, fso.read())
        self.assertEqual("[2, 1, 'unable to get issuer certificate']", self.cahandler.verify_certificate_chain(cert, ca_cert))

    def test_026_verifycertificatechain(self):
        """ successful verification of two level certificate chain with complete chain"""
        self.cahandler.ca_cert_chain_list = ['ca/root-ca-cert.pem']
        with open('ca/sub-ca-client.txt', 'r') as fso:
            cert = fso.read()
        with open('ca/sub-ca-cert.pem', 'r') as fso:
            ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, fso.read())
        self.assertFalse(self.cahandler.verify_certificate_chain(cert, ca_cert))

    def test_027_verifycertificatechain(self):
        """ unsuccessful verification as certificate is damaged"""
        cert = 'foo'
        with open('ca/root-ca-cert.pem', 'r') as fso:
            ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, fso.read())
        self.assertEqual('certificate could not get parsed', (self.cahandler.verify_certificate_chain(cert, ca_cert)))

    def test_028_verifycertificatechain(self):
        """ unsuccessful verification as ca-certificate is damaged"""
        with open('ca/root-ca-client.txt', 'r') as fso:
            cert = fso.read()
        ca_cert = 'foo'
        self.assertEqual('issuing certificate could not be added to trust-store', self.cahandler.verify_certificate_chain(cert, ca_cert))

    def test_029_verifycertificatechain(self):
        """ unsuccessful verification of two level certificate chain as cain cert is damaged"""
        self.cahandler.ca_cert_chain_list = ['ca/root-.pem']
        with open('ca/sub-ca-client.txt', 'r') as fso:
            cert = fso.read()
        with open('ca/sub-ca-cert.pem', 'r') as fso:
            ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, fso.read())
        self.assertEqual('certificate ca/root-.pem could not be added to trust store', self.cahandler.verify_certificate_chain(cert, ca_cert))

    def test_030_revocation(self):
        """ revocation without having a CRL in issuer_dic """
        with open('ca/sub-ca-client.txt', 'r') as fso:
            cert = fso.read()
        self.assertEqual((400, 'urn:ietf:params:acme:error:serverInternal', 'Unsupported operation'), self.cahandler.revoke(cert))

    def test_031_revocation(self):
        """ revocation without having a CRL in issuer_dic but none"""
        self.cahandler.issuer_dict = {'crl' : None}
        with open('ca/sub-ca-client.txt', 'r') as fso:
            cert = fso.read()
        self.assertEqual((400, 'urn:ietf:params:acme:error:serverInternal', 'Unsupported operation'), self.cahandler.revoke(cert))

    @patch('examples.ca_handler.openssl_ca_handler.CAhandler.verify_certificate_chain')
    @patch('examples.ca_handler.openssl_ca_handler.CAhandler.load_ca_key_cert')
    def test_032_revocation(self, mock_ca_load, mock_vrf):
        """ revocation cert validation failed """
        with open('ca/sub-ca-client.txt', 'r') as fso:
            cert = fso.read()
        self.cahandler.issuer_dict = {'key': 'ca/sub-ca-key.pem', 'passphrase': 'Test1234', 'cert': 'ca/sub-ca-cert.pem', 'crl' : 'ca/foo-ca-crl.pem'}
        mock_ca_load.return_value = ('ca_key', 'ca_cert')
        mock_vrf.return_value = 'foo'
        self.assertEqual((400, 'urn:ietf:params:acme:error:serverInternal', 'foo'), self.cahandler.revoke(cert))

    @patch('examples.ca_handler.openssl_ca_handler.CAhandler.verify_certificate_chain')
    @patch('examples.ca_handler.openssl_ca_handler.CAhandler.load_ca_key_cert')
    def test_033_revocation(self, mock_ca_load, mock_vrf):
        """ revocation cert no CA key """
        with open('ca/sub-ca-client.txt', 'r') as fso:
            cert = fso.read()
        self.cahandler.issuer_dict = {'key': 'ca/sub-ca-key.pem', 'passphrase': 'Test1234', 'cert': 'ca/sub-ca-cert.pem', 'crl' : 'ca/foo-ca-crl.pem'}
        mock_ca_load.return_value = (None, 'ca_cert')
        mock_vrf.return_value = None
        self.assertEqual((400, 'urn:ietf:params:acme:error:serverInternal', 'configuration error'), self.cahandler.revoke(cert))

    @patch('examples.ca_handler.openssl_ca_handler.CAhandler.verify_certificate_chain')
    @patch('examples.ca_handler.openssl_ca_handler.CAhandler.load_ca_key_cert')
    def test_034_revocation(self, mock_ca_load, mock_vrf):
        """ revocation cert no CA cert """
        with open('ca/sub-ca-client.txt', 'r') as fso:
            cert = fso.read()
        self.cahandler.issuer_dict = {'key': 'ca/sub-ca-key.pem', 'passphrase': 'Test1234', 'cert': 'ca/sub-ca-cert.pem', 'crl' : 'ca/foo-ca-crl.pem'}
        mock_ca_load.return_value = ('ca_key', None)
        mock_vrf.return_value = None
        self.assertEqual((400, 'urn:ietf:params:acme:error:serverInternal', 'configuration error'), self.cahandler.revoke(cert))

    @patch('examples.ca_handler.openssl_ca_handler.cert_serial_get')
    @patch('examples.ca_handler.openssl_ca_handler.CAhandler.verify_certificate_chain')
    @patch('examples.ca_handler.openssl_ca_handler.CAhandler.load_ca_key_cert')
    def test_035_revocation(self, mock_ca_load, mock_vrf, mock_serial):
        """ revocation cert no serial """
        with open('ca/sub-ca-client.txt', 'r') as fso:
            cert = fso.read()
        self.cahandler.issuer_dict = {'key': 'ca/sub-ca-key.pem', 'passphrase': 'Test1234', 'cert': 'ca/sub-ca-cert.pem', 'crl' : 'ca/foo-ca-crl.pem'}
        mock_ca_load.return_value = ('ca_key', 'ca_cert')
        mock_vrf.return_value = None
        mock_serial.return_value = None
        self.assertEqual((400, 'urn:ietf:params:acme:error:serverInternal', 'configuration error'), self.cahandler.revoke(cert))

    @patch('examples.ca_handler.openssl_ca_handler.cert_serial_get')
    @patch('examples.ca_handler.openssl_ca_handler.CAhandler.verify_certificate_chain')
    @patch('examples.ca_handler.openssl_ca_handler.CAhandler.load_ca_key_cert')
    def test_035_revocation(self, mock_ca_load, mock_vrf, mock_serial):
        """ revocation cert """
        with open('ca/sub-ca-client.txt', 'r') as fso:
            cert = fso.read()
        self.cahandler.issuer_dict = {'key': 'ca/sub-ca-key.pem', 'passphrase': 'Test1234', 'cert': 'ca/sub-ca-cert.pem', 'crl' : 'ca/foo-ca-crl.pem'}
        mock_ca_load.return_value = ('ca_key', 'ca_cert')
        mock_vrf.return_value = None
        mock_serial.return_value = 14
        self.assertEqual((400, 'urn:ietf:params:acme:error:serverInternal', 'configuration error'), self.cahandler.revoke(cert))        
        


if __name__ == '__main__':

    if os.path.exists('acme_test.db'):
        os.remove('acme_test.db')
    unittest.main()
