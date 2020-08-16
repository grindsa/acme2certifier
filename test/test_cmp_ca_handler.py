#!/usr/bin/python
# -*- coding: utf-8 -*-
""" unittests for openssl_ca_handler """
# pylint: disable=C0415, R0904, R0913, W0212
import sys
import os
import unittest
from unittest.mock import patch
# from OpenSSL import crypto
import shutil

sys.path.insert(0, '.')
sys.path.insert(1, '..')

class TestACMEHandler(unittest.TestCase):
    """ test class for cgi_handler """

    def setUp(self):
        """ setup unittest """
        import logging
        from examples.ca_handler.cmp_ca_handler import CAhandler
        logging.basicConfig(level=logging.CRITICAL)
        self.logger = logging.getLogger('test_a2c')
        self.cahandler = CAhandler(False, self.logger)

    def tearDown(self):
        """ teardown """
        pass

    def test_001_default(self):
        """ default test which always passes """
        self.assertEqual('foo', 'foo')

    @patch('examples.ca_handler.cmp_ca_handler.load_config')
    def test_002_config_load(self, mock_load_cfg):
        """ test _config_load no cahandler section """
        mock_load_cfg.return_value = {}
        self.cahandler._config_load()
        odict = {'cmd': 'ir', 'popo': 0}
        self.assertEqual(odict, self.cahandler.config_dic)

    @patch('examples.ca_handler.cmp_ca_handler.load_config')
    def test_003_config_load(self, mock_load_cfg):
        """ test _config_load wrong cahandler section """
        mock_load_cfg.return_value = {'CAhandler': 'foo'}
        self.cahandler._config_load()
        odict = {'cmd': 'ir', 'popo': 0}
        self.assertEqual(odict, self.cahandler.config_dic)

    @patch('examples.ca_handler.cmp_ca_handler.load_config')
    def test_004_config_load(self, mock_load_cfg):
        """ test _config_load cmd predefined in cahandler """
        mock_load_cfg.return_value = {'CAhandler': {'cmp_cmd': 'foo'}}
        self.cahandler._config_load()
        odict = {'cmd': 'foo', 'popo': 0}
        self.assertEqual(odict, self.cahandler.config_dic)

    @patch('examples.ca_handler.cmp_ca_handler.load_config')
    def test_005_config_load(self, mock_load_cfg):
        """ test _config_load popo predefined in cahandler  """
        mock_load_cfg.return_value = {'CAhandler': {'cmp_popo': 1}}
        self.cahandler._config_load()
        odict = {'cmd': 'ir', 'popo': 1}
        self.assertEqual(odict, self.cahandler.config_dic)

    @patch('examples.ca_handler.cmp_ca_handler.load_config')
    def test_006_config_load(self, mock_load_cfg):
        """ test _config_load cmd and popo predefined in cahandler  """
        mock_load_cfg.return_value = {'CAhandler': {'cmp_cmd': 'foo', 'cmp_popo': 1}}
        self.cahandler._config_load()
        odict = {'cmd': 'foo', 'popo': 1}
        self.assertEqual(odict, self.cahandler.config_dic)

    @patch('examples.ca_handler.cmp_ca_handler.load_config')
    def test_006_config_load(self, mock_load_cfg):
        """ test _config_load - cmp_openssl_bin parameter"""
        mock_load_cfg.return_value = {'CAhandler': {'cmp_openssl_bin': 'foo'}}
        self.cahandler._config_load()
        odict = {'cmd': 'ir', 'popo': 0}
        self.assertEqual(odict, self.cahandler.config_dic)
        self.assertEqual('foo', self.cahandler.openssl_bin)

    @patch('examples.ca_handler.cmp_ca_handler.load_config')
    def test_007_config_load(self, mock_load_cfg):
        """ test _config_load - cmd_tmp-dir parameter """
        mock_load_cfg.return_value = {'CAhandler': {'cmp_tmp_dir': 'foo_tmp'}}
        self.cahandler._config_load()
        odict = {'cmd': 'ir', 'popo': 0}
        self.assertEqual(odict, self.cahandler.config_dic)
        self.assertEqual('foo_tmp', self.cahandler.tmp_dir)

    @patch('examples.ca_handler.cmp_ca_handler.load_config')
    def test_008_config_load(self, mock_load_cfg):
        """ test _config_load - cmp_recipient-dir parameter """
        mock_load_cfg.return_value = {'CAhandler': {'cmp_recipient': 'foo'}}
        self.cahandler._config_load()
        odict = {'cmd': 'ir', 'popo': 0, 'recipient': '/foo'}
        self.assertEqual(odict, self.cahandler.config_dic)

    @patch('examples.ca_handler.cmp_ca_handler.load_config')
    def test_009_config_load(self, mock_load_cfg):
        """ test _config_load - cmd_tmp-cmp_recipient startwith '/' """
        mock_load_cfg.return_value = {'CAhandler': {'cmp_recipient': '/foo'}}
        self.cahandler._config_load()
        odict = {'cmd': 'ir', 'popo': 0, 'recipient': '/foo'}
        self.assertEqual(odict, self.cahandler.config_dic)

    @patch('examples.ca_handler.cmp_ca_handler.load_config')
    def test_010_config_load(self, mock_load_cfg):
        """ test _config_load - cmd_tmp-cmp_recipient contains , """
        mock_load_cfg.return_value = {'CAhandler': {'cmp_recipient': 'fo,o'}}
        self.cahandler._config_load()
        odict = {'cmd': 'ir', 'popo': 0, 'recipient': '/fo/o'}
        self.assertEqual(odict, self.cahandler.config_dic)

    @patch('examples.ca_handler.cmp_ca_handler.load_config')
    def test_011_config_load(self, mock_load_cfg):
        """ test _config_load - cmd_tmp-cmp_recipient contains ,blank """
        mock_load_cfg.return_value = {'CAhandler': {'cmp_recipient': 'fo, o'}}
        self.cahandler._config_load()
        odict = {'cmd': 'ir', 'popo': 0, 'recipient': '/fo/o'}
        self.assertEqual(odict, self.cahandler.config_dic)

    @patch('examples.ca_handler.cmp_ca_handler.load_config')
    def test_012_config_load(self, mock_load_cfg):
        """ test _config_load - cmd_tmp-cmp_recipient contains ,blank and ,"""
        mock_load_cfg.return_value = {'CAhandler': {'cmp_recipient': 'foo, bar,doo'}}
        self.cahandler._config_load()
        odict = {'cmd': 'ir', 'popo': 0, 'recipient': '/foo/bar/doo'}
        self.assertEqual(odict, self.cahandler.config_dic)

    @patch('examples.ca_handler.cmp_ca_handler.load_config')
    def test_013_config_load(self, mock_load_cfg):
        """ test _config_load - cmd_tmp-cmp_recipient contains ,blank and ,"""
        mock_load_cfg.return_value = {'CAhandler': {'cmp_recipient': 'foo, bar, doo,bar,doo'}}
        self.cahandler._config_load()
        odict = {'cmd': 'ir', 'popo': 0, 'recipient': '/foo/bar/doo/bar/doo'}
        self.assertEqual(odict, self.cahandler.config_dic)

    @patch('examples.ca_handler.cmp_ca_handler.load_config')
    def test_014_config_load(self, mock_load_cfg):
        """ test _config_load - any parameter string """
        mock_load_cfg.return_value = {'CAhandler': {'cmp_foo': 'bar'}}
        self.cahandler._config_load()
        odict = {'cmd': 'ir', 'foo': 'bar', 'popo': 0}
        self.assertEqual(odict, self.cahandler.config_dic)

    @patch('examples.ca_handler.cmp_ca_handler.load_config')
    def test_015_config_load(self, mock_load_cfg):
        """ test _config_load - any parameter int """
        mock_load_cfg.return_value = {'CAhandler': {'cmp_foo': 1}}
        self.cahandler._config_load()
        odict = {'cmd': 'ir', 'foo': 1, 'popo': 0}
        self.assertEqual(odict, self.cahandler.config_dic)

    @patch('examples.ca_handler.cmp_ca_handler.load_config')
    def test_016_config_load(self, mock_load_cfg):
        """ test _config_load - any parameter float """
        mock_load_cfg.return_value = {'CAhandler': {'cmp_foo': 0.1}}
        self.cahandler._config_load()
        odict = {'cmd': 'ir', 'foo': 0.1, 'popo': 0}
        self.assertEqual(odict, self.cahandler.config_dic)

    @patch('examples.ca_handler.cmp_ca_handler.load_config')
    def test_017_config_load(self, mock_load_cfg):
        """ test _config_load - tmp_dir not configured """
        mock_load_cfg.return_value = {}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_load()
        self.assertIn('ERROR:test_a2c:CAhandler config error: "cmp_tmp_dir" parameter must be specified in config_file', lcm.output)

    @patch('examples.ca_handler.cmp_ca_handler.load_config')
    def test_018_config_load(self, mock_load_cfg):
        """  test _config_load - cmp_openssl_bin not configured """
        mock_load_cfg.return_value = {}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_load()
        self.assertIn('WARNING:test_a2c:CAhandler config error: "cmp_openssl_bin" parameter not in config_file. Using default (/usr/bin/openssl)', lcm.output)

    @patch('examples.ca_handler.cmp_ca_handler.load_config')
    def test_019_config_load(self, mock_load_cfg):
        """  test _config_load - cmp_recipient not configured """
        mock_load_cfg.return_value = {}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_load()
        self.assertIn('ERROR:test_a2c:CAhandler config error: "cmp_recipient" is missing in config_file.', lcm.output)

    @patch('examples.ca_handler.cmp_ca_handler.csr_san_get')
    def test_020_csr_san_get(self, mock_san):
        """  test _config_load - empty san list """
        mock_san.return_value = []
        olist = []
        self.assertFalse(self.cahandler._csr_san_get('csr'))

    @patch('examples.ca_handler.cmp_ca_handler.csr_san_get')
    def test_021_csr_san_get(self, mock_san):
        """ test _csr_san_get  - incomplete san returned """
        mock_san.return_value = ['foo']
        olist = []
        self.assertFalse(self.cahandler._csr_san_get('csr'))

    @patch('examples.ca_handler.cmp_ca_handler.csr_san_get')
    def test_022_csr_san_get(self, mock_san):
        """ test _csr_san_get  - single san returned """
        mock_san.return_value = ['foo1:bar1']
        olist = []
        self.assertEqual('"bar1"', self.cahandler._csr_san_get('csr'))

    @patch('examples.ca_handler.cmp_ca_handler.csr_san_get')
    def test_022_csr_san_get(self, mock_san):
        """ test _csr_san_get  - single san returned mix upper and lower cases """
        mock_san.return_value = ['fOo1:BaR1']
        olist = []
        self.assertEqual('"bar1"', self.cahandler._csr_san_get('csr'))

    @patch('examples.ca_handler.cmp_ca_handler.csr_san_get')
    def test_023_csr_san_get(self, mock_san):
        """ test _csr_san_get  - single san returned mix upper and lower cases """
        mock_san.return_value = ['fOo1:BaR1', 'foo2:bar2']
        olist = []
        self.assertEqual('"bar1, bar2"', self.cahandler._csr_san_get('csr'))


if __name__ == '__main__':

    unittest.main()
