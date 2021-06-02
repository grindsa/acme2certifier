#!/usr/bin/python
# -*- coding: utf-8 -*-
""" unittests for acme2certifier """
# pylint: disable= C0415, W0212
import unittest
import sys
import os
from OpenSSL import crypto
from unittest.mock import patch, Mock, MagicMock, mock_open
import requests

sys.path.insert(0, '.')
sys.path.insert(1, '..')


class TestACMEHandler(unittest.TestCase):
    """ test class for cgi_handler """

    def setUp(self):
        """ setup unittest """
        import logging
        logging.basicConfig(level=logging.CRITICAL)
        self.logger = logging.getLogger('test_a2c')
        from examples.eab_handler.file_handler import EABhandler
        self.eabhandler = EABhandler(self.logger)
        self.dir_path = os.path.dirname(os.path.realpath(__file__))

    def test_001_default(self):
        """ default test which always passes """
        self.assertEqual('foo', 'foo')

    @patch('examples.eab_handler.file_handler.EABhandler._config_load')
    def test_002__enter__(self, mock_cfg):
        """ test enter  called """
        mock_cfg.return_value = True
        self.eabhandler.__enter__()
        self.assertTrue(mock_cfg.called)

    @patch('examples.eab_handler.file_handler.load_config')
    def test_003_config_load(self, mock_load_cfg):
        """ test _config_load - empty dictionary """
        mock_load_cfg.return_value = {}
        self.eabhandler._config_load()
        self.assertFalse(self.eabhandler.key_file)

    @patch('examples.eab_handler.file_handler.load_config')
    def test_004_config_load(self, mock_load_cfg):
        """ test _config_load - bogus values """
        mock_load_cfg.return_value = {'foo': 'bar'}
        self.eabhandler._config_load()
        self.assertFalse(self.eabhandler.key_file)

    @patch('examples.eab_handler.file_handler.load_config')
    def test_005_config_load(self, mock_load_cfg):
        """ test _config_load - bogus values """
        mock_load_cfg.return_value = {'EABhandler': {'foo': 'bar'}}
        self.eabhandler._config_load()
        self.assertFalse(self.eabhandler.key_file)

    @patch('examples.eab_handler.file_handler.load_config')
    def test_006_config_load(self, mock_load_cfg):
        """ test _config_load - bogus values """
        mock_load_cfg.return_value = {'EABhandler': {'key_file': 'key_file'}}
        self.eabhandler._config_load()
        self.assertEqual('key_file', self.eabhandler.key_file)

    def test_007_mac_key_get(self):
        """ test mac_key_get without file specified """
        self.assertFalse(self.eabhandler.mac_key_get(None))

    @patch("builtins.open", mock_open(read_data='foo'), create=True)
    def test_008_mac_key_get(self):
        """ test mac_key_get with file but no kid """
        self.eabhandler.key_file = 'file'
        self.assertFalse(self.eabhandler.mac_key_get(None))

    @patch('csv.DictReader')
    @patch("builtins.open", mock_open(read_data='foo'), create=True)
    def test_009_mac_key_get(self, mock_csv):
        """ test mac_key_get csv reader return bogus values """
        self.eabhandler.key_file = 'file'
        mock_csv.return_value = ['foo', 'bar']
        self.assertFalse(self.eabhandler.mac_key_get('kid'))

    @patch('csv.DictReader')
    @patch("builtins.open", mock_open(read_data='foo'), create=True)
    def test_010_mac_key_get(self, mock_csv):
        """ test mac_key_get csv reader return match """
        self.eabhandler.key_file = 'file'
        mock_csv.return_value = [{'eab_kid': 'kid', 'eab_mac': 'mac'}]
        self.assertEqual('mac', self.eabhandler.mac_key_get('kid'))

    @patch('csv.DictReader')
    @patch("builtins.open", mock_open(read_data='foo'), create=True)
    def test_011_mac_key_get(self, mock_csv):
        """ test mac_key_get csv reader no match """
        self.eabhandler.key_file = 'file'
        mock_csv.return_value = [{'eab_kid': 'kid1', 'eab_mac': 'mac'}]
        self.assertFalse(self.eabhandler.mac_key_get('kid'))

    @patch('csv.DictReader')
    @patch("builtins.open", mock_open(read_data='foo'), create=True)
    def test_012_mac_key_get(self, mock_csv):
        """ test mac_key_get check break after first match """
        self.eabhandler.key_file = 'file'
        mock_csv.return_value = [{'eab_kid': 'kid', 'eab_mac': 'mac'}, {'eab_kid': 'kid', 'eab_mac': 'mac2'}]
        self.assertEqual('mac', self.eabhandler.mac_key_get('kid'))

    @patch('csv.DictReader')
    @patch("builtins.open", mock_open(read_data='foo'), create=True)
    def test_013_mac_key_get(self, mock_csv):
        """ test mac_key_get match in the 2nd record """
        self.eabhandler.key_file = 'file'
        mock_csv.return_value = [{'eab_kid': 'kid1', 'eab_mac': 'mac'}, {'eab_kid': 'kid', 'eab_mac': 'mac2'}]
        self.assertEqual('mac2', self.eabhandler.mac_key_get('kid'))

    @patch('csv.DictReader')
    @patch("builtins.open", mock_open(read_data='foo'), create=True)
    def test_014_mac_key_get(self, mock_csv):
        """ test mac_key_get csv reader no eab_kid """
        self.eabhandler.key_file = 'file'
        mock_csv.return_value = [{'eab__kid': 'kid', 'eab_mac': 'mac'}]
        self.assertFalse(self.eabhandler.mac_key_get('kid'))

    @patch('csv.DictReader')
    @patch("builtins.open", mock_open(read_data='foo'), create=True)
    def test_015_mac_key_get(self, mock_csv):
        """ test mac_key_get csv reader no mac but match """
        self.eabhandler.key_file = 'file'
        mock_csv.return_value = [{'eab_kid': 'kid', '_eab_mac': 'mac'}]
        self.assertFalse(self.eabhandler.mac_key_get('kid'))

    @patch('csv.DictReader')
    @patch("builtins.open", mock_open(read_data='foo'), create=True)
    def test_016_mac_key_get(self, mock_csv):
        """ test mac_key_get csv reader no mac but match """
        self.eabhandler.key_file = 'file'
        mock_csv.side_effect = Exception('ex_mock_csv')
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertFalse(self.eabhandler.mac_key_get('kid'))
        self.assertIn('ERROR:test_a2c:EABhandler.mac_key_get() error: ex_mock_csv', lcm.output)

if __name__ == '__main__':

    unittest.main()
