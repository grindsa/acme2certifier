#!/usr/bin/python
# -*- coding: utf-8 -*-
""" unittests for openssl_ca_handler """
import unittest
import sys
import os
import unittest
import requests
from OpenSSL import crypto
from requests.exceptions import HTTPError

try:
    from mock import patch, MagicMock, Mock
except ImportError:
    from unittest.mock import patch, MagicMock, Mock
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
        
    def test_007_check_serial_against_crl(self):
        """ CAhandler.check_serial_against_crl without specifying a CRL"""
        crl = None
        self.assertFalse(self.cahandler.check_serial_against_crl(crl, 1))        

    def test_008_check_serial_against_crl(self):
        """ CAhandler.check_serial_against_crl without specifying a serial number"""
        crl = 'foo'
        self.assertFalse(self.cahandler.check_serial_against_crl(crl, None))              

    def test_009_check_serial_against_crl(self):
        """ CAhandler.check_serial_against_crl with a serial number not in CRL"""
        crl = crypto.load_crl(crypto.FILETYPE_PEM, open('ca/sub-ca-crl.pem').read())
        self.assertFalse(self.cahandler.check_serial_against_crl(crl, 2))     

    def test_010_check_serial_against_crl(self):
        """ CAhandler.check_serial_against_crl with a serial number already in CRL"""
        crl = crypto.load_crl(crypto.FILETYPE_PEM, open('ca/sub-ca-crl.pem').read())
        self.assertTrue(self.cahandler.check_serial_against_crl(crl, '5d0e9535'))     




if __name__ == '__main__':

    if os.path.exists('acme_test.db'):
        os.remove('acme_test.db')
    unittest.main()
