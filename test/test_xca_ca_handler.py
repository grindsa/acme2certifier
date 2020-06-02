#!/usr/bin/python
# -*- coding: utf-8 -*-
""" unittests for openssl_ca_handler """
import sys
import os
import unittest
from unittest.mock import patch, mock_open
from OpenSSL import crypto
import shutil

sys.path.insert(0, '..')

class TestACMEHandler(unittest.TestCase):
    """ test class for cgi_handler """

    def setUp(self):
        """ setup unittest """
        import logging
        from examples.ca_handler.xca_ca_handler import CAhandler
        logging.basicConfig(level=logging.CRITICAL)
        self.logger = logging.getLogger('test_xca_handler')
        self.cahandler = CAhandler(False, self.logger)

    def test_001_default(self):
        """ default test which always passes """
        self.assertEqual('foo', 'foo')

    def test_002_check_config(self):
        """ CAhandler._config_check with an empty config_dict """
        self.assertEqual('xdb_file must be specified in config file', self.cahandler._config_check())

    def test_003_check_config(self):
        """ CAhandler._config_check non existing xdb """
        self.cahandler.xdb_file = 'foo'
        self.assertEqual('xdb_file foo does not exist', self.cahandler._config_check())

    @patch('os.path.exists')
    def test_004_check_config(self, mock_file):
        """ CAhandler._config_check xdb exists but no issuing ca_name """
        self.cahandler.xdb_file = 'foo'
        mock_file.return_value = True
        self.assertEqual('issuing_ca_name must be set in config file', self.cahandler._config_check())

    @patch('os.path.exists')
    def test_005_check_config(self, mock_file):
        """ CAhandler._config_check xdb exists but no issuing ca_name """
        self.cahandler.xdb_file = 'foo'
        self.cahandler.issuing_ca_name = 'foo'
        mock_file.return_value = True
        self.assertFalse(self.cahandler._config_check())

    def test_006_csr_search(self):
        """ CAhandler._config_check non existing request """
        self.cahandler.xdb_file = 'ca/acme2certifier.xdb'
        self.assertFalse(self.cahandler._csr_search('name', 'foo'))

    def test_007_csr_search(self):
        """ CAhandler._config_check existing request """
        self.cahandler.xdb_file = 'ca/acme2certifier.xdb'
        self.assertTrue(self.cahandler._csr_search('name', 'test_request'))

    @patch('examples.ca_handler.xca_ca_handler.CAhandler._ca_cert_load')
    @patch('examples.ca_handler.xca_ca_handler.CAhandler._ca_key_load')
    def test_008_ca_load(self, mock_key, mock_cert):
        """ CAhandler._ca_load for both cert and key """
        mock_key.return_value = 'key'
        mock_cert.return_value = ('cert', 1)
        self.assertEqual(('key', 'cert', 1), self.cahandler._ca_load())

    @patch('examples.ca_handler.xca_ca_handler.CAhandler._ca_cert_load')
    @patch('examples.ca_handler.xca_ca_handler.CAhandler._ca_key_load')
    def test_009_ca_load(self, mock_key, mock_cert):
        """ CAhandler._ca_load for cert only """
        mock_key.return_value = None
        mock_cert.return_value = ('cert', 1)
        self.assertEqual((None, 'cert', 1), self.cahandler._ca_load())

    @patch('examples.ca_handler.xca_ca_handler.CAhandler._ca_cert_load')
    @patch('examples.ca_handler.xca_ca_handler.CAhandler._ca_key_load')
    def test_010_ca_load(self, mock_key, mock_cert):
        """ CAhandler._ca_load for cert only """
        mock_key.return_value = 'key'
        mock_cert.return_value = (None, None)
        self.assertEqual(('key', None, None), self.cahandler._ca_load())

    @patch('examples.ca_handler.xca_ca_handler.CAhandler._ca_cert_load')
    @patch('examples.ca_handler.xca_ca_handler.CAhandler._ca_key_load')
    def test_011_ca_load(self, mock_key, mock_cert):
        """ CAhandler._ca_load without key and cert """
        mock_key.return_value = None
        mock_cert.return_value = (None, None)
        self.assertEqual((None, None, None), self.cahandler._ca_load())
        
    def test_012_ca_cert_load(self):
        """ CAhandler._ca_cert_load """
        self.cahandler.xdb_file = 'ca/acme2certifier.xdb'
        self.cahandler.issuing_ca_name = 'sub-ca'       
        self.assertTrue(self.cahandler._ca_cert_load())        

    def test_013_ca_cert_load(self):
        """ CAhandler._ca_cert_load for non existing cert """
        self.cahandler.xdb_file = 'ca/acme2certifier.xdb'
        self.cahandler.issuing_ca_name = 'bar'       
        self.assertEqual((None, None), self.cahandler._ca_cert_load()) 

    def test_014_ca_key_load(self):
        """ CAhandler._ca_key_load """
        self.cahandler.xdb_file = 'ca/acme2certifier.xdb'
        self.cahandler.issuing_ca_name = 'sub-ca'
        self.cahandler.passphrase = 'test1234'        
        self.assertTrue(self.cahandler._ca_key_load()) 

    def test_015_ca_key_load(self):
        """ CAhandler._ca_key_load with wrong passphrase """
        self.cahandler.xdb_file = 'ca/acme2certifier.xdb'
        self.cahandler.issuing_ca_name = 'sub-ca'
        self.cahandler.passphrase = 'wrongpw'        
        self.assertFalse(self.cahandler._ca_key_load()) 

    def test_016_ca_key_load(self):
        """ CAhandler._ca_key_load without passphrase (should fail) """
        self.cahandler.xdb_file = 'ca/acme2certifier.xdb'
        self.cahandler.issuing_ca_name = 'sub-ca'
        # self.cahandler.passphrase = 'wrongpw'        
        self.assertFalse(self.cahandler._ca_key_load()) 

    def test_017_csr_insert(self):
        """ CAhandler._csr_insert empty item dic """
        self.cahandler.xdb_file = 'ca/acme2certifier.xdb'
        self.cahandler.issuing_ca_name = 'sub-ca'
        csr_dic =  {}
        self.assertFalse(self.cahandler._csr_insert(csr_dic)) 

    def test_018_csr_insert(self):
        """ CAhandler._csr_insert full item dic """
        self.cahandler.xdb_file = 'ca/acme2certifier.xdb'
        self.cahandler.issuing_ca_name = 'sub-ca'
        csr_dic =  {'item': 2, 'signed': 0, 'request': 'request'}
        self.assertEqual(2, self.cahandler._csr_insert(csr_dic)) 

    def test_010_csr_insert(self):
        """ CAhandler._csr_insert full item dic item has wrong datatype """
        self.cahandler.xdb_file = 'ca/acme2certifier.xdb'
        self.cahandler.issuing_ca_name = 'sub-ca'
        csr_dic =  {'item': '2', 'signed': 0, 'request': 'request'}
        self.assertFalse(self.cahandler._csr_insert(csr_dic)) 

    def test_011_csr_insert(self):
        """ CAhandler._csr_insert full item dic item has wrong datatype """
        self.cahandler.xdb_file = 'ca/acme2certifier.xdb'
        self.cahandler.issuing_ca_name = 'sub-ca'
        csr_dic =  {'item': 2, 'signed': '0', 'request': 'request'}
        self.assertFalse(self.cahandler._csr_insert(csr_dic)) 

    def test_019_csr_insert(self):
        """ CAhandler._csr_insert item dic without item """
        self.cahandler.xdb_file = 'ca/acme2certifier.xdb'
        self.cahandler.issuing_ca_name = 'sub-ca'
        csr_dic =  {'signed': 0, 'request': 'request'}
        self.assertFalse(self.cahandler._csr_insert(csr_dic)) 

    def test_020_csr_insert(self):
        """ CAhandler._csr_insert item dic without signed """
        self.cahandler.xdb_file = 'ca/acme2certifier.xdb'
        self.cahandler.issuing_ca_name = 'sub-ca'
        csr_dic =  {'item': 2, 'request': 'request'}
        self.assertFalse(self.cahandler._csr_insert(csr_dic)) 

    def test_021_csr_insert(self):
        """ CAhandler._csr_insert item dic without request """
        self.cahandler.xdb_file = 'ca/acme2certifier.xdb'
        self.cahandler.issuing_ca_name = 'sub-ca'
        csr_dic =  {'item': 2, 'signed': 0}
        self.assertFalse(self.cahandler._csr_insert(csr_dic)) 

    def test_022_item_insert(self):
        """ CAhandler._item_insert empty item dic """
        self.cahandler.xdb_file = 'ca/acme2certifier.xdb'
        self.cahandler.issuing_ca_name = 'sub-ca'
        item_dic = {}
        self.assertFalse(self.cahandler._item_insert(item_dic)) 

    def test_023_item_insert(self):
        """ CAhandler._item_insert full item dic """
        self.cahandler.xdb_file = 'ca/acme2certifier.xdb'
        self.cahandler.issuing_ca_name = 'sub-ca'
        item_dic = {'name': 'name', 'type': 2, 'source': 0 , 'date': 'date', 'comment': 'comment'}
        self.assertEqual(8, self.cahandler._item_insert(item_dic)) 

    def test_024_item_insert(self):
        """ CAhandler._item_insert no name """
        self.cahandler.xdb_file = 'ca/acme2certifier.xdb'
        self.cahandler.issuing_ca_name = 'sub-ca'
        item_dic = {'type': 2, 'source': 0 , 'date': 'date', 'comment': 'comment'}
        self.assertFalse(self.cahandler._item_insert(item_dic)) 

    def test_025_item_insert(self):
        """ CAhandler._item_insert no type """
        self.cahandler.xdb_file = 'ca/acme2certifier.xdb'
        self.cahandler.issuing_ca_name = 'sub-ca'
        item_dic = {'name': 'name', 'source': 0 , 'date': 'date', 'comment': 'comment'}
        self.assertFalse(self.cahandler._item_insert(item_dic)) 

    def test_026_item_insert(self):
        """ CAhandler._item_insert no siurce """
        self.cahandler.xdb_file = 'ca/acme2certifier.xdb'
        self.cahandler.issuing_ca_name = 'sub-ca'
        item_dic = {'name': 'name', 'item': 2 , 'date': 'date', 'comment': 'comment'}
        self.assertFalse(self.cahandler._item_insert(item_dic)) 

    def test_027_item_insert(self):
        """ CAhandler._item_insert no date  """
        self.cahandler.xdb_file = 'ca/acme2certifier.xdb'
        self.cahandler.issuing_ca_name = 'sub-ca'
        item_dic = {'name': 'name', 'type': 2, 'source': 0, 'comment': 'comment'}
        self.assertFalse(self.cahandler._item_insert(item_dic)) 

    def test_028_item_insert(self):
        """ CAhandler._item_insert no date  """
        self.cahandler.xdb_file = 'ca/acme2certifier.xdb'
        self.cahandler.issuing_ca_name = 'sub-ca'
        item_dic = {'name': 'name', 'type': 2, 'source': 0, 'date': 'date'}
        self.assertFalse(self.cahandler._item_insert(item_dic)) 

    def test_029_item_insert(self):
        """ CAhandler._item_insert full item dic type has wrong datatype """
        self.cahandler.xdb_file = 'ca/acme2certifier.xdb'
        self.cahandler.issuing_ca_name = 'sub-ca'
        item_dic = {'name': 'name', 'type': '2', 'source': 0, 'date': 'date', 'comment': 'comment'}
        self.assertFalse(self.cahandler._item_insert(item_dic)) 

    def test_030_item_insert(self):
        """ CAhandler._item_insert full item dic source has wrong datatype """
        self.cahandler.xdb_file = 'ca/acme2certifier.xdb'
        self.cahandler.issuing_ca_name = 'sub-ca'
        item_dic = {'name': 'name', 'type': 2, 'source': '0', 'date': 'date', 'comment': 'comment'}
        self.assertFalse(self.cahandler._item_insert(item_dic)) 


if __name__ == '__main__':

    if os.path.exists('ca/acme2certifier.xdb'):
         os.remove('ca/acme2certifier.xdb')

    if not os.path.exists('ca/acme2certifier.xdb'):
        shutil.copy('ca/acme2certifier-clean.xdb', 'ca/acme2certifier.xdb')

    unittest.main()


