#!/usr/bin/python
# -*- coding: utf-8 -*-
""" unittests for openssl_ca_handler """
import sys
import os
import unittest
from unittest.mock import patch, mock_open
from OpenSSL import crypto
import shutil

sys.path.insert(0, '.')
sys.path.insert(1, '..')

def _prepare(dir_path):
    """ prepare testing """
     # copy clean database
    if os.path.exists(dir_path + '/ca/acme2certifier-clean.xdb'):
        shutil.copy(dir_path + '/ca/acme2certifier-clean.xdb', dir_path + '/ca/acme2certifier.xdb')

def _cleanup(dir_path):
    """ cleanup function """
    # remove old db
    if os.path.exists(dir_path + '/ca/acme2certifier.xdb'):
         os.remove(dir_path + '/ca/acme2certifier.xdb')

class TestACMEHandler(unittest.TestCase):
    """ test class for cgi_handler """

    def setUp(self):
        """ setup unittest """
        import logging
        from examples.ca_handler.xca_ca_handler import CAhandler
        logging.basicConfig(level=logging.CRITICAL)
        self.logger = logging.getLogger('test_xca_handler')
        self.cahandler = CAhandler(False, self.logger)
        self.dir_path = os.path.dirname(os.path.realpath(__file__))
        _prepare(self.dir_path)

    def tearDown(self):
        """ teardown """
        _cleanup(self.dir_path)

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
        self.cahandler.xdb_file = self.dir_path + '/ca/acme2certifier.xdb'
        self.assertFalse(self.cahandler._csr_search('name', 'foo'))

    def test_007_csr_search(self):
        """ CAhandler._config_check existing request """
        self.cahandler.xdb_file = self.dir_path + '/ca/acme2certifier.xdb'
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
        self.cahandler.xdb_file = self.dir_path + '/ca/acme2certifier.xdb'
        self.cahandler.issuing_ca_name = 'sub-ca'
        self.assertTrue(self.cahandler._ca_cert_load())

    def test_013_ca_cert_load(self):
        """ CAhandler._ca_cert_load for non existing cert """
        self.cahandler.xdb_file = self.dir_path + '/ca/acme2certifier.xdb'
        self.cahandler.issuing_ca_name = 'bar'
        self.assertEqual((None, None), self.cahandler._ca_cert_load())

    def test_014_ca_key_load(self):
        """ CAhandler._ca_key_load """
        self.cahandler.xdb_file = self.dir_path + '/ca/acme2certifier.xdb'
        self.cahandler.issuing_ca_name = 'sub-ca'
        self.cahandler.passphrase = 'test1234'
        self.assertTrue(self.cahandler._ca_key_load())

    def test_015_ca_key_load(self):
        """ CAhandler._ca_key_load with wrong passphrase """
        self.cahandler.xdb_file = self.dir_path + '/ca/acme2certifier.xdb'
        self.cahandler.issuing_ca_name = 'sub-ca'
        self.cahandler.passphrase = 'wrongpw'
        self.assertFalse(self.cahandler._ca_key_load())

    def test_016_ca_key_load(self):
        """ CAhandler._ca_key_load without passphrase (should fail) """
        self.cahandler.xdb_file = self.dir_path + '/ca/acme2certifier.xdb'
        self.cahandler.issuing_ca_name = 'sub-ca'
        # self.cahandler.passphrase = 'wrongpw'
        self.assertFalse(self.cahandler._ca_key_load())

    def test_017_csr_insert(self):
        """ CAhandler._csr_insert empty item dic """
        self.cahandler.xdb_file = self.dir_path + '/ca/acme2certifier.xdb'
        self.cahandler.issuing_ca_name = 'sub-ca'
        csr_dic =  {}
        self.assertFalse(self.cahandler._csr_insert(csr_dic))

    def test_018_csr_insert(self):
        """ CAhandler._csr_insert full item dic """
        self.cahandler.xdb_file = self.dir_path + '/ca/acme2certifier.xdb'
        self.cahandler.issuing_ca_name = 'sub-ca'
        csr_dic =  {'item': 2, 'signed': 0, 'request': 'request'}
        self.assertEqual(2, self.cahandler._csr_insert(csr_dic))

    def test_010_csr_insert(self):
        """ CAhandler._csr_insert full item dic item has wrong datatype """
        self.cahandler.xdb_file = self.dir_path + '/ca/acme2certifier.xdb'
        self.cahandler.issuing_ca_name = 'sub-ca'
        csr_dic =  {'item': '2', 'signed': 0, 'request': 'request'}
        self.assertFalse(self.cahandler._csr_insert(csr_dic))

    def test_011_csr_insert(self):
        """ CAhandler._csr_insert full item dic item has wrong datatype """
        self.cahandler.xdb_file = self.dir_path + '/ca/acme2certifier.xdb'
        self.cahandler.issuing_ca_name = 'sub-ca'
        csr_dic =  {'item': 2, 'signed': '0', 'request': 'request'}
        self.assertFalse(self.cahandler._csr_insert(csr_dic))

    def test_019_csr_insert(self):
        """ CAhandler._csr_insert item dic without item """
        self.cahandler.xdb_file = self.dir_path + '/ca/acme2certifier.xdb'
        self.cahandler.issuing_ca_name = 'sub-ca'
        csr_dic =  {'signed': 0, 'request': 'request'}
        self.assertFalse(self.cahandler._csr_insert(csr_dic))

    def test_020_csr_insert(self):
        """ CAhandler._csr_insert item dic without signed """
        self.cahandler.xdb_file = self.dir_path + '/ca/acme2certifier.xdb'
        self.cahandler.issuing_ca_name = 'sub-ca'
        csr_dic =  {'item': 2, 'request': 'request'}
        self.assertFalse(self.cahandler._csr_insert(csr_dic))

    def test_021_csr_insert(self):
        """ CAhandler._csr_insert item dic without request """
        self.cahandler.xdb_file = self.dir_path + '/ca/acme2certifier.xdb'
        self.cahandler.issuing_ca_name = 'sub-ca'
        csr_dic =  {'item': 2, 'signed': 0}
        self.assertFalse(self.cahandler._csr_insert(csr_dic))

    def test_022_item_insert(self):
        """ CAhandler._item_insert empty item dic """
        self.cahandler.xdb_file = self.dir_path + '/ca/acme2certifier.xdb'
        self.cahandler.issuing_ca_name = 'sub-ca'
        item_dic = {}
        self.assertFalse(self.cahandler._item_insert(item_dic))

    def test_023_item_insert(self):
        """ CAhandler._item_insert full item dic """
        self.cahandler.xdb_file = self.dir_path + '/ca/acme2certifier.xdb'
        self.cahandler.issuing_ca_name = 'sub-ca'
        item_dic = {'name': 'name', 'type': 2, 'source': 0 , 'date': 'date', 'comment': 'comment'}
        self.assertEqual(8, self.cahandler._item_insert(item_dic))

    def test_024_item_insert(self):
        """ CAhandler._item_insert no name """
        self.cahandler.xdb_file = self.dir_path + '/ca/acme2certifier.xdb'
        self.cahandler.issuing_ca_name = 'sub-ca'
        item_dic = {'type': 2, 'source': 0 , 'date': 'date', 'comment': 'comment'}
        self.assertFalse(self.cahandler._item_insert(item_dic))

    def test_025_item_insert(self):
        """ CAhandler._item_insert no type """
        self.cahandler.xdb_file = self.dir_path + '/ca/acme2certifier.xdb'
        self.cahandler.issuing_ca_name = 'sub-ca'
        item_dic = {'name': 'name', 'source': 0 , 'date': 'date', 'comment': 'comment'}
        self.assertFalse(self.cahandler._item_insert(item_dic))

    def test_026_item_insert(self):
        """ CAhandler._item_insert no siurce """
        self.cahandler.xdb_file = self.dir_path + '/ca/acme2certifier.xdb'
        self.cahandler.issuing_ca_name = 'sub-ca'
        item_dic = {'name': 'name', 'item': 2 , 'date': 'date', 'comment': 'comment'}
        self.assertFalse(self.cahandler._item_insert(item_dic))

    def test_027_item_insert(self):
        """ CAhandler._item_insert no date  """
        self.cahandler.xdb_file = self.dir_path + '/ca/acme2certifier.xdb'
        self.cahandler.issuing_ca_name = 'sub-ca'
        item_dic = {'name': 'name', 'type': 2, 'source': 0, 'comment': 'comment'}
        self.assertFalse(self.cahandler._item_insert(item_dic))

    def test_028_item_insert(self):
        """ CAhandler._item_insert no date  """
        self.cahandler.xdb_file = self.dir_path + '/ca/acme2certifier.xdb'
        self.cahandler.issuing_ca_name = 'sub-ca'
        item_dic = {'name': 'name', 'type': 2, 'source': 0, 'date': 'date'}
        self.assertFalse(self.cahandler._item_insert(item_dic))

    def test_029_item_insert(self):
        """ CAhandler._item_insert full item dic type has wrong datatype """
        self.cahandler.xdb_file = self.dir_path + '/ca/acme2certifier.xdb'
        self.cahandler.issuing_ca_name = 'sub-ca'
        item_dic = {'name': 'name', 'type': '2', 'source': 0, 'date': 'date', 'comment': 'comment'}
        self.assertFalse(self.cahandler._item_insert(item_dic))

    def test_030_item_insert(self):
        """ CAhandler._item_insert full item dic source has wrong datatype """
        self.cahandler.xdb_file = self.dir_path + '/ca/acme2certifier.xdb'
        self.cahandler.issuing_ca_name = 'sub-ca'
        item_dic = {'name': 'name', 'type': 2, 'source': '0', 'date': 'date', 'comment': 'comment'}
        self.assertFalse(self.cahandler._item_insert(item_dic))

    @patch('examples.ca_handler.xca_ca_handler.CAhandler._csr_search')
    def test_031_csr_import(self, mock_search):
        """ CAhandler._csr_import with existing cert_dic """
        mock_search.return_value = {'foo', 'bar'}
        self.assertEqual({'foo', 'bar'}, self.cahandler._csr_import('csr', 'request_name'))

    @patch('examples.ca_handler.xca_ca_handler.CAhandler._item_insert')
    @patch('examples.ca_handler.xca_ca_handler.CAhandler._csr_insert')
    @patch('examples.ca_handler.xca_ca_handler.CAhandler._csr_search')
    def test_032_csr_import(self, mock_search, mock_csr_insert, mock_item_insert):
        """ CAhandler._csr_import with existing cert_dic """
        mock_search.return_value = {}
        mock_csr_insert.return_value = 5
        mock_item_insert.return_value = 10
        self.assertEqual({'item': 10, 'signed': 1, 'request': 'csr'}, self.cahandler._csr_import('csr', 'request_name'))

    def test_033_cert_insert(self):
        """ CAhandler._csr_import with empty cert_dic """
        cert_dic = {}
        self.assertFalse(self.cahandler._cert_insert(cert_dic))

    def test_034_cert_insert(self):
        """ CAhandler._csr_import item missing """
        cert_dic = {'serial': 'serial', 'issuer': 'issuer', 'ca': 'ca', 'cert': 'cert', 'iss_hash': 'iss_hash', 'hash': 'hash'}
        self.assertFalse(self.cahandler._cert_insert(cert_dic))

    def test_035_cert_insert(self):
        """ CAhandler._csr_import serial missing """
        cert_dic = {'item': 'item', 'issuer': 'issuer', 'ca': 'ca', 'cert': 'cert', 'iss_hash': 'iss_hash', 'hash': 'hash'}
        self.assertFalse(self.cahandler._cert_insert(cert_dic))

    def test_036_cert_insert(self):
        """ CAhandler._csr_import issuer missing """
        cert_dic = {'item': 'item', 'serial': 'serial', 'ca': 'ca', 'cert': 'cert', 'iss_hash': 'iss_hash', 'hash': 'hash'}
        self.assertFalse(self.cahandler._cert_insert(cert_dic))

    def test_037_cert_insert(self):
        """ CAhandler._csr_import ca missing """
        cert_dic = {'item': 'item', 'serial': 'serial', 'issuer': 'issuer', 'cert': 'cert', 'iss_hash': 'iss_hash', 'hash': 'hash'}
        self.assertFalse(self.cahandler._cert_insert(cert_dic))

    def test_038_cert_insert(self):
        """ CAhandler._csr_import cert missing """
        cert_dic = {'item': 'item', 'serial': 'serial', 'issuer': 'issuer', 'ca': 'ca', 'iss_hash': 'iss_hash', 'hash': 'hash'}
        self.assertFalse(self.cahandler._cert_insert(cert_dic))

    def test_039_cert_insert(self):
        """ CAhandler._csr_import iss_hash missing """
        cert_dic = {'item': 'item', 'serial': 'serial', 'issuer': 'issuer', 'ca': 'ca', 'cert': 'cert', 'hash': 'hash'}
        self.assertFalse(self.cahandler._cert_insert(cert_dic))

    def test_040_cert_insert(self):
        """ CAhandler._csr_import hash missing """
        cert_dic = {'item': 'item', 'serial': 'serial', 'issuer': 'issuer', 'ca': 'ca', 'cert': 'cert', 'iss_hash': 'iss_hash'}
        self.assertFalse(self.cahandler._cert_insert(cert_dic))

    def test_041_cert_insert(self):
        """ CAhandler._csr_import with item not int """
        cert_dic = {'item': 'item', 'serial': 'serial', 'issuer': 'issuer', 'ca': 'ca', 'cert': 'cert', 'iss_hash': 'iss_hash', 'hash': 'hash'}
        self.assertFalse(self.cahandler._cert_insert(cert_dic))

    def test_042_cert_insert(self):
        """ CAhandler._csr_import with issuer not int """
        cert_dic = {'item': 1, 'serial': 'serial', 'issuer': 'issuer', 'ca': 'ca', 'cert': 'cert', 'iss_hash': 'iss_hash', 'hash': 'hash'}
        self.assertFalse(self.cahandler._cert_insert(cert_dic))

    def test_043_cert_insert(self):
        """ CAhandler._csr_import with ca not int """
        cert_dic = {'item': 1, 'serial': 'serial', 'issuer': 1, 'ca': 'ca', 'cert': 'cert', 'iss_hash': 'iss_hash', 'hash': 'hash'}
        self.assertFalse(self.cahandler._cert_insert(cert_dic))

    def test_044_cert_insert(self):
        """ CAhandler._csr_import with iss_hash not int """
        cert_dic = {'item': 1, 'serial': 'serial', 'issuer': 2, 'ca': 3, 'cert': 'cert', 'iss_hash': 'iss_hash', 'hash': 'hash'}
        self.assertFalse(self.cahandler._cert_insert(cert_dic))

    def test_045_cert_insert(self):
        """ CAhandler._csr_import with hash not int """
        cert_dic = {'item': 1, 'serial': 'serial', 'issuer': 2, 'ca': 3, 'cert': 'cert', 'iss_hash': 4, 'hash': 'hash'}
        self.assertFalse(self.cahandler._cert_insert(cert_dic))

    def test_046_pemcertchain_generate(self):
        """ CAhandler._pemcertchain_generate no certificates """
        ee_cert = None
        issuer_cert = None
        self.cahandler.ca_cert_chain_list = []
        self.assertFalse(self.cahandler._pemcertchain_generate(ee_cert, issuer_cert))

    def test_047_pemcertchain_generate(self):
        """ CAhandler._pemcertchain_generate no issuer """
        ee_cert = 'ee_cert'
        issuer_cert = None
        self.cahandler.ca_cert_chain_list = []
        self.assertEqual('ee_cert', self.cahandler._pemcertchain_generate(ee_cert, issuer_cert))

    def test_048_pemcertchain_generate(self):
        """ CAhandler._pemcertchain_generate no ca chain """
        ee_cert = 'ee_cert'
        issuer_cert = 'issuer_cert'
        self.cahandler.ca_cert_chain_list = []
        self.assertEqual('ee_certissuer_cert', self.cahandler._pemcertchain_generate(ee_cert, issuer_cert))

    @patch('examples.ca_handler.xca_ca_handler.CAhandler._cert_search')
    @patch('OpenSSL.crypto.load_certificate')
    def test_049_pemcertchain_generate(self, mock_cert, mock_search):
        """ CAhandler._pemcertchain_generate empty cert dic in ca_chain """
        ee_cert = 'ee_cert'
        issuer_cert = 'issuer_cert'
        self.cahandler.ca_cert_chain_list = ['foo_bar']
        mock_search.return_value = None
        mock_cert.side_effect = ['foo', 'bar']
        self.assertEqual('ee_certissuer_cert', self.cahandler._pemcertchain_generate(ee_cert, issuer_cert))

    @patch('examples.ca_handler.xca_ca_handler.CAhandler._cert_search')
    @patch('OpenSSL.crypto.load_certificate')
    def test_050_pemcertchain_generate(self, mock_cert, mock_search):
        """ CAhandler._pemcertchain_generate empty no cert in chain """
        ee_cert = 'ee_cert'
        issuer_cert = 'issuer_cert'
        self.cahandler.ca_cert_chain_list = ['foo_bar']
        mock_search.return_value = {'foo', 'bar'}
        mock_cert.side_effect = ['foo', 'bar']
        self.assertEqual('ee_certissuer_cert', self.cahandler._pemcertchain_generate(ee_cert, issuer_cert))

    @patch('examples.ca_handler.xca_ca_handler.b64_decode')
    @patch('examples.ca_handler.xca_ca_handler.CAhandler._cert_search')
    @patch('OpenSSL.crypto.load_certificate')
    @patch('OpenSSL.crypto.dump_certificate')
    def test_051_pemcertchain_generate(self, mock_dump, mock_load, mock_search, mock_b64dec):
        """ CAhandler._pemcertchain_generate one cert in chain """
        ee_cert = 'ee_cert'
        issuer_cert = 'issuer_cert'
        self.cahandler.ca_cert_chain_list = ['foo_bar']
        mock_search.return_value = {'cert': 'foo'}
        mock_load.return_value = 'foo'
        mock_dump.side_effect = ['foo1']
        mock_b64dec.return_value ='b64dec'
        self.assertEqual('ee_certissuer_certfoo1', self.cahandler._pemcertchain_generate(ee_cert, issuer_cert))

    @patch('examples.ca_handler.xca_ca_handler.b64_decode')
    @patch('examples.ca_handler.xca_ca_handler.CAhandler._cert_search')
    @patch('OpenSSL.crypto.load_certificate')
    @patch('OpenSSL.crypto.dump_certificate')
    def test_052_pemcertchain_generate(self, mock_dump, mock_load, mock_search, mock_b64dec):
        """ CAhandler._pemcertchain_generate two certs in chain """
        ee_cert = 'ee_cert'
        issuer_cert = 'issuer_cert'
        self.cahandler.ca_cert_chain_list = ['foo_bar', 'foo_bar']
        mock_search.return_value = {'cert': 'foo'}
        mock_load.return_value = 'foo'
        mock_dump.side_effect = ['foo1', 'foo2']
        mock_b64dec.return_value ='b64dec'
        self.assertEqual('ee_certissuer_certfoo1foo2', self.cahandler._pemcertchain_generate(ee_cert, issuer_cert))

    @patch('examples.ca_handler.xca_ca_handler.csr_cn_get')
    def test_053_requestname_get(self, mock_cn):
        """ CAhandler._requestname_get from cn """
        mock_cn.return_value = 'foo'
        self.assertEqual('foo', self.cahandler._requestname_get('csr'))

    @patch('examples.ca_handler.xca_ca_handler.csr_san_get')
    @patch('examples.ca_handler.xca_ca_handler.csr_cn_get')
    def test_054_requestname_get(self, mock_cn,  mock_san):
        """ CAhandler._requestname_get empty cn empty san"""
        mock_cn.return_value = None
        mock_san.return_value = []
        self.assertFalse(self.cahandler._requestname_get('csr'))

    @patch('examples.ca_handler.xca_ca_handler.csr_san_get')
    @patch('examples.ca_handler.xca_ca_handler.csr_cn_get')
    def test_055_requestname_get(self, mock_cn,  mock_san):
        """ CAhandler._requestname_get empty cn empty dsmaged san"""
        mock_cn.return_value = None
        mock_san.return_value = ['foo']
        self.assertFalse(self.cahandler._requestname_get('csr'))

    @patch('examples.ca_handler.xca_ca_handler.csr_san_get')
    @patch('examples.ca_handler.xca_ca_handler.csr_cn_get')
    def test_056_requestname_get(self, mock_cn,  mock_san):
        """ CAhandler._requestname_get empty cn empty dsmaged san"""
        mock_cn.return_value = None
        mock_san.return_value = ['dns:foo']
        self.assertEqual('foo', self.cahandler._requestname_get('csr'))

    @patch('examples.ca_handler.xca_ca_handler.csr_san_get')
    @patch('examples.ca_handler.xca_ca_handler.csr_cn_get')
    def test_057_requestname_get(self, mock_cn,  mock_san):
        """ CAhandler._requestname_get empty cn empty dsmaged san"""
        mock_cn.return_value = None
        mock_san.return_value = ['dns:foo', 'bar']
        self.assertEqual('foo', self.cahandler._requestname_get('csr'))

    def test_058_cert_insert(self):
        """ CAhandler._revocation_insert with empty rev_dic """
        rev_dic = {}
        self.assertFalse(self.cahandler._revocation_insert(rev_dic))

    def test_059_cert_insert(self):
        """ CAhandler._revocation_insert no caID """
        rev_dic = {'serial': 'serial', 'date': 'date', 'invaldate': 'invaldate', 'reasonBit': 0}
        self.assertFalse(self.cahandler._revocation_insert(rev_dic))

    def test_060_cert_insert(self):
        """ CAhandler._revocation_insert no serial """
        rev_dic = {'caID': 4, 'date': 'date', 'invaldate': 'invaldate', 'reasonBit': 0}
        self.assertFalse(self.cahandler._revocation_insert(rev_dic))

    def test_061_cert_insert(self):
        """ CAhandler._revocation_insert no date """
        rev_dic = {'caID': 4, 'serial': 'serial', 'invaldate': 'invaldate', 'reasonBit': 0}
        self.assertFalse(self.cahandler._revocation_insert(rev_dic))

    def test_062_cert_insert(self):
        """ CAhandler._revocation_insert no invaldate """
        rev_dic = {'caID': 4, 'serial': 'serial', 'date': 'date', 'reasonBit': 0}
        self.assertFalse(self.cahandler._revocation_insert(rev_dic))

    def test_063_cert_insert(self):
        """ CAhandler._revocation_insert no resonBit """
        rev_dic = {'caID': 4, 'serial': 'serial', 'date': 'date', 'invaldate': 'invaldate'}
        self.assertFalse(self.cahandler._revocation_insert(rev_dic))

    def test_064_cert_insert(self):
        """ CAhandler._revocation_insert with caID is not int """
        rev_dic = {'caID': 'caID', 'serial': 'serial', 'date': 'date', 'invaldate': 'invaldate', 'reasonBit': 0}
        self.assertFalse(self.cahandler._revocation_insert(rev_dic))

    def test_065_cert_insert(self):
        """ CAhandler._revocation_insert with caID is not int """
        rev_dic = {'caID': 0, 'serial': 'serial', 'date': 'date', 'invaldate': 'invaldate', 'reasonBit': '0'}
        self.assertFalse(self.cahandler._revocation_insert(rev_dic))

    @patch('examples.ca_handler.xca_ca_handler.uts_to_date_utc')
    def test_066_revoke(self, mock_date):
        """ CAhandler.revocation without xdb file """
        mock_date = 'foo'
        self.assertEqual((500, 'urn:ietf:params:acme:error:serverInternal', 'configuration error'), self.cahandler.revoke('cert', 'reason', None))

    @patch('examples.ca_handler.xca_ca_handler.cert_serial_get')
    @patch('examples.ca_handler.xca_ca_handler.CAhandler._ca_load')
    @patch('examples.ca_handler.xca_ca_handler.uts_to_date_utc')
    def test_067_revoke(self, mock_date, mock_ca, mock_serial):
        """ CAhandler.revocation no CA ID """
        self.cahandler.xdb_file = self.dir_path + '/ca/acme2certifier.xdb'
        mock_date.return_value = 'foo'
        mock_ca.return_value = ('key', 'cert', None)
        mock_serial.return_value = 1000
        self.assertEqual((500, 'urn:ietf:params:acme:error:serverInternal', 'certificate lookup failed'), self.cahandler.revoke('cert', 'reason', None))

    @patch('examples.ca_handler.xca_ca_handler.cert_serial_get')
    @patch('examples.ca_handler.xca_ca_handler.CAhandler._ca_load')
    @patch('examples.ca_handler.xca_ca_handler.uts_to_date_utc')
    def test_068_revoke(self, mock_date, mock_ca, mock_serial):
        """ CAhandler.revocation no serial """
        self.cahandler.xdb_file = self.dir_path + '/ca/acme2certifier.xdb'
        mock_date.return_value = 'foo'
        mock_ca.return_value = ('key', 'cert', 2)
        mock_serial.return_value = None
        self.assertEqual((500, 'urn:ietf:params:acme:error:serverInternal', 'certificate lookup failed'), self.cahandler.revoke('cert', 'reason', None))

    @patch('examples.ca_handler.xca_ca_handler.CAhandler._revocation_search')
    @patch('examples.ca_handler.xca_ca_handler.CAhandler._revocation_insert')
    @patch('examples.ca_handler.xca_ca_handler.cert_serial_get')
    @patch('examples.ca_handler.xca_ca_handler.CAhandler._ca_load')
    @patch('examples.ca_handler.xca_ca_handler.uts_to_date_utc')
    def test_069_revoke(self, mock_date, mock_ca, mock_serial, mock_rev_insert, mock_search):
        """ CAhandler.revocation no serial """
        self.cahandler.xdb_file = self.dir_path + '/ca/acme2certifier.xdb'
        mock_date.return_value = 'foo'
        mock_ca.return_value = ('key', 'cert', 2)
        mock_search.return_value = None
        mock_rev_insert.return_value = None
        mock_serial.return_value = 1000
        self.assertEqual((500, 'urn:ietf:params:acme:error:serverInternal', 'database update failed'), self.cahandler.revoke('cert', 'reason', None))

    @patch('examples.ca_handler.xca_ca_handler.CAhandler._revocation_search')
    @patch('examples.ca_handler.xca_ca_handler.CAhandler._revocation_insert')
    @patch('examples.ca_handler.xca_ca_handler.cert_serial_get')
    @patch('examples.ca_handler.xca_ca_handler.CAhandler._ca_load')
    @patch('examples.ca_handler.xca_ca_handler.uts_to_date_utc')
    def test_070_revoke(self, mock_date, mock_ca, mock_serial, mock_rev_insert, mock_search):
        """ CAhandler.revocation no serial """
        self.cahandler.xdb_file = self.dir_path + '/ca/acme2certifier.xdb'
        mock_date.return_value = 'foo'
        mock_ca.return_value = ('key', 'cert', 2)
        mock_search.return_value = 'foo'
        mock_rev_insert.return_value = 20
        mock_serial.return_value = 1000
        self.assertEqual((400, 'urn:ietf:params:acme:error:alreadyRevoked', 'Certificate has already been revoked'), self.cahandler.revoke('cert', 'reason', None))

    @patch('examples.ca_handler.xca_ca_handler.CAhandler._revocation_search')
    @patch('examples.ca_handler.xca_ca_handler.CAhandler._revocation_insert')
    @patch('examples.ca_handler.xca_ca_handler.cert_serial_get')
    @patch('examples.ca_handler.xca_ca_handler.CAhandler._ca_load')
    @patch('examples.ca_handler.xca_ca_handler.uts_to_date_utc')
    def test_071_revoke(self, mock_date, mock_ca, mock_serial, mock_rev_insert, mock_search):
        """ CAhandler.revocation no serial """
        self.cahandler.xdb_file = self.dir_path + '/ca/acme2certifier.xdb'
        mock_date.return_value = 'foo'
        mock_ca.return_value = ('key', 'cert', 2)
        mock_search.return_value = None
        mock_rev_insert.return_value = 20
        mock_serial.return_value = 1000
        self.assertEqual((200, None, None), self.cahandler.revoke('cert', 'reason', None))

if __name__ == '__main__':

    unittest.main()


