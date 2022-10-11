#!/usr/bin/python
# -*- coding: utf-8 -*-
""" unittests for account.py """
# pylint: disable=C0302, C0415, R0904, R0913, R0914, R0915, W0212
import unittest
import configparser
import sys
from unittest.mock import patch, MagicMock

sys.path.insert(0, '.')
sys.path.insert(1, '..')

class FakeDBStore(object):
    """ face DBStore class needed for mocking """
    # pylint: disable=W0107, R0903
    pass

class TestACMEHandler(unittest.TestCase):
    """ test class for ACMEHandler """
    acme = None
    def setUp(self):
        """ setup unittest """
        models_mock = MagicMock()
        models_mock.acme_srv.db_handler.DBstore.return_value = FakeDBStore
        modules = {'acme_srv.db_handler': models_mock}
        patch.dict('sys.modules', modules).start()
        import logging
        logging.basicConfig(level=logging.CRITICAL)
        self.logger = logging.getLogger('test_a2c')
        from acme_srv.directory import Directory
        self.directory = Directory(False, 'http://tester.local', self.logger)

    def test_001_directory_servername_get(self):
        """ test Directory.get_server_name() method """
        self.assertEqual('http://tester.local', self.directory.servername_get())

    def test_002_directory_directory_get(self):
        """ test Directory.get_directory() method and check for "newnonce" tag in output"""
        output_dic = {'newNonce': 'http://tester.local/acme/newnonce'}
        self.assertTrue(output_dic.items() <= self.directory.directory_get().items())

    def test_003_directory_directory_get(self):
        """ test Directory.get_directory() method and check for "newnonce" tag in output"""
        output_dic = {'newAccount': 'http://tester.local/acme/newaccount'}
        self.assertTrue(output_dic.items() <= self.directory.directory_get().items())

    def test_004_directory_directory_get(self):
        """ test Directory.get_directory() method and check for "meta" tag in output"""
        self.directory.supress_version = True
        output_dic = {'meta': {'home': 'https://github.com/grindsa/acme2certifier', 'author': 'grindsa <grindelsack@gmail.com>', 'name': 'acme2certifier'}}
        self.assertTrue(output_dic.items() <= self.directory.directory_get().items())

    def test_005_directory_directory_get(self):
        """ test Directory.get_directory() method and check for "meta" tag in output"""
        self.directory.tos_url = 'foo'
        self.directory.supress_version = True
        output_dic = {'meta': {'home': 'https://github.com/grindsa/acme2certifier', 'author': 'grindsa <grindelsack@gmail.com>', 'name': 'acme2certifier', 'termsOfService': 'foo'}}
        self.assertTrue(output_dic.items() <= self.directory.directory_get().items())

    def test_006_directory_directory_get(self):
        """ test Directory.get_directory() method and check for "meta" tag in output"""
        self.directory.version = '0.1'
        output_dic = {'meta': {'home': 'https://github.com/grindsa/acme2certifier', 'author': 'grindsa <grindelsack@gmail.com>', 'name': 'acme2certifier', 'version': '0.1'}}
        self.assertTrue(output_dic.items() <= self.directory.directory_get().items())

    def test_007_directory_directory_get(self):
        """ test Directory.get_directory() method and check for "meta" tag in output"""
        self.directory.version = '0.1'
        self.directory.tos_url = 'foo'
        output_dic = {'meta': {'home': 'https://github.com/grindsa/acme2certifier', 'author': 'grindsa <grindelsack@gmail.com>', 'name': 'acme2certifier', 'version': '0.1', 'termsOfService': 'foo'}}
        self.assertTrue(output_dic.items() <= self.directory.directory_get().items())

    def test_008_directory_directory_get(self):
        """ test Directory.get_directory() method and check for "eab" key in meta tag"""
        self.directory.version = '0.1'
        self.directory.eab = 'foo'
        output_dic = {'meta': {'home': 'https://github.com/grindsa/acme2certifier', 'author': 'grindsa <grindelsack@gmail.com>', 'name': 'acme2certifier', 'version': '0.1', 'externalAccountRequired': True}}
        self.assertTrue(output_dic.items() <= self.directory.directory_get().items())

    def test_009_directory_directory_get(self):
        """ test Directory.get_directory()  url prefix """
        self.directory.url_prefix = 'url_prefix'
        self.directory.version = '0.1'
        output_dic = {'newAuthz': 'http://tester.localurl_prefix/acme/new-authz', 'newNonce': 'http://tester.localurl_prefix/acme/newnonce', 'newAccount': 'http://tester.localurl_prefix/acme/newaccount', 'newOrder': 'http://tester.localurl_prefix/acme/neworders', 'revokeCert': 'http://tester.localurl_prefix/acme/revokecert', 'keyChange': 'http://tester.localurl_prefix/acme/key-change'}
        self.assertTrue(output_dic.items() <= self.directory.directory_get().items())

    def test_010_directory_directory_get(self):
        """ test Directory.get_directory() - dbcheck nok """
        self.directory.url_prefix = 'url_prefix'
        self.directory.dbstore.dbversion_get.return_value = ('0.1', 'script_name')
        self.directory.version = '0.1'
        self.directory.dbversion = '0.1.1'
        self.directory.db_check = True
        output_dic = {'newAuthz': 'http://tester.localurl_prefix/acme/new-authz', 'newNonce': 'http://tester.localurl_prefix/acme/newnonce', 'newAccount': 'http://tester.localurl_prefix/acme/newaccount', 'newOrder': 'http://tester.localurl_prefix/acme/neworders', 'revokeCert': 'http://tester.localurl_prefix/acme/revokecert', 'keyChange': 'http://tester.localurl_prefix/acme/key-change'}
        result = self.directory.directory_get()
        self.assertTrue(output_dic.items() <= result.items())
        self.assertEqual('NOK', result['meta']['db_check'])

    def test_011_directory_directory_get(self):
        """ test Directory.get_directory() - dbcheck ok """
        self.directory.url_prefix = 'url_prefix'
        self.directory.dbstore.dbversion_get.return_value = ('0.1', 'script_name')
        self.directory.version = '0.1'
        self.directory.dbversion = '0.1'
        self.directory.db_check = True
        output_dic = {'newAuthz': 'http://tester.localurl_prefix/acme/new-authz', 'newNonce': 'http://tester.localurl_prefix/acme/newnonce', 'newAccount': 'http://tester.localurl_prefix/acme/newaccount', 'newOrder': 'http://tester.localurl_prefix/acme/neworders', 'revokeCert': 'http://tester.localurl_prefix/acme/revokecert', 'keyChange': 'http://tester.localurl_prefix/acme/key-change'}
        result = self.directory.directory_get()
        self.assertTrue(output_dic.items() <= result.items())
        self.assertEqual('OK', result['meta']['db_check'])

    def test_012_directory_directory_get(self):
        """ test Directory.get_directory() - dbcheck returned exception """
        self.directory.url_prefix = 'url_prefix'
        self.directory.dbstore.dbversion_get.side_effect = Exception('exc_dbversion_get')
        self.directory.version = '0.1'
        self.directory.dbversion = '0.1'
        self.directory.db_check = True
        output_dic = {'newAuthz': 'http://tester.localurl_prefix/acme/new-authz', 'newNonce': 'http://tester.localurl_prefix/acme/newnonce', 'newAccount': 'http://tester.localurl_prefix/acme/newaccount', 'newOrder': 'http://tester.localurl_prefix/acme/neworders', 'revokeCert': 'http://tester.localurl_prefix/acme/revokecert', 'keyChange': 'http://tester.localurl_prefix/acme/key-change'}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            result = self.directory.directory_get()
        self.assertIn('CRITICAL:test_a2c:acme2certifier database error in Directory.dbversion_check(): exc_dbversion_get', lcm.output)
        self.assertTrue(output_dic.items() <= result.items())
        self.assertEqual('NOK', result['meta']['db_check'])

    @patch('acme_srv.directory.load_config')
    def test_013_config_load(self, mock_load_cfg):
        """ test _config_load empty config """
        parser = configparser.ConfigParser()
        # parser['Account'] = {'foo': 'bar'}
        mock_load_cfg.return_value = parser
        self.directory._config_load()
        self.assertFalse(self.directory.supress_version)
        self.assertFalse(self.directory.tos_url)
        self.assertFalse(self.directory.eab)

    @patch('acme_srv.directory.load_config')
    def test_014_config_load(self, mock_load_cfg):
        """ test _config_load with unknown values config """
        parser = configparser.ConfigParser()
        parser['Account'] = {'foo': 'bar'}
        mock_load_cfg.return_value = parser
        self.directory._config_load()
        self.assertFalse(self.directory.supress_version)
        self.assertFalse(self.directory.tos_url)
        self.assertFalse(self.directory.eab)

    @patch('acme_srv.directory.load_config')
    def test_015_config_load(self, mock_load_cfg):
        """ test _config_load with unknown values config """
        parser = configparser.ConfigParser()
        parser['Directory'] = {'foo': 'bar'}
        mock_load_cfg.return_value = parser
        self.directory._config_load()
        self.assertFalse(self.directory.supress_version)
        self.assertFalse(self.directory.tos_url)
        self.assertFalse(self.directory.eab)

    @patch('acme_srv.directory.load_config')
    def test_016_config_load(self, mock_load_cfg):
        """ test _config_load supress version number """
        parser = configparser.ConfigParser()
        parser['Directory'] = {'supress_version': True}
        mock_load_cfg.return_value = parser
        self.directory._config_load()
        self.assertTrue(self.directory.supress_version)
        self.assertFalse(self.directory.tos_url)
        self.assertFalse(self.directory.eab)

    @patch('acme_srv.directory.load_config')
    def test_017_config_load(self, mock_load_cfg):
        """ test _config_load tos url """
        parser = configparser.ConfigParser()
        parser['Directory'] = {'tos_url': 'tos_url'}
        mock_load_cfg.return_value = parser
        self.directory._config_load()
        self.assertFalse(self.directory.supress_version)
        self.assertEqual('tos_url', self.directory.tos_url)
        self.assertFalse(self.directory.eab)

    @patch('acme_srv.directory.load_config')
    def test_018_config_load(self, mock_load_cfg):
        """ test _config_load eab """
        parser = configparser.ConfigParser()
        parser['EABhandler'] = {'eab_handler_file': 'eab_handler_file'}
        mock_load_cfg.return_value = parser
        self.directory._config_load()
        self.assertFalse(self.directory.supress_version)
        self.assertFalse(self.directory.tos_url)
        self.assertTrue(self.directory.eab)
        self.assertFalse(self.directory.url_prefix)

    @patch('acme_srv.directory.load_config')
    def test_019_config_load(self, mock_load_cfg):
        """ test _config_load all parameters set """
        parser = configparser.ConfigParser()
        parser['EABhandler'] = {'eab_handler_file': 'eab_handler_file'}
        parser['Directory'] = {'tos_url': 'tos_url', 'supress_version': True}
        mock_load_cfg.return_value = parser
        self.directory._config_load()
        self.assertTrue(self.directory.supress_version)
        self.assertEqual('tos_url', self.directory.tos_url)
        self.assertTrue(self.directory.eab)

    @patch('acme_srv.directory.load_config')
    def test_020_config_load(self, mock_load_cfg):
        """ test _config_load eab """
        parser = configparser.ConfigParser()
        parser['Directory'] = {'url_prefix': 'url_prefix'}
        mock_load_cfg.return_value = parser
        self.directory._config_load()
        self.assertFalse(self.directory.supress_version)
        self.assertFalse(self.directory.tos_url)
        self.assertFalse(self.directory.eab)
        self.assertEqual('url_prefix', self.directory.url_prefix)

    @patch('acme_srv.directory.Directory._config_load')
    def test_021__enter__(self, mock_cfg):
        """ test enter """
        mock_cfg.return_value = True
        self.directory.__enter__()
        self.assertTrue(mock_cfg.called)

if __name__ == '__main__':
    unittest.main()
