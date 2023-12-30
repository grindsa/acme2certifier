#!/usr/bin/python
# -*- coding: utf-8 -*-
""" unittests for renewalinfo.py """
# pylint: disable=C0302, C0415, R0904, R0913, R0914, R0915, W0212
import unittest
import sys
from unittest.mock import patch, call, MagicMock, mock_open
import configparser

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
        from acme_srv.renewalinfo import Renewalinfo
        self.renewalinfo = Renewalinfo(False, 'http://tester.local', self.logger)

    @patch('acme_srv.renewalinfo.load_config')
    def test_001_config_load(self, mock_load_cfg):
        """ test _config_load  """
        parser = configparser.ConfigParser()
        mock_load_cfg.return_value = parser
        self.renewalinfo._config_load()
        self.assertTrue(mock_load_cfg.called)
        self.assertEqual(85, self.renewalinfo.renewaltreshold_pctg)
        self.assertEqual(86400, self.renewalinfo.retry_after_timeout)
        self.assertFalse(self.renewalinfo.renewal_force)

    @patch('acme_srv.renewalinfo.load_config')
    def test_002_config_load(self, mock_load_cfg):
        """ test _config_load  """
        parser = configparser.ConfigParser()
        mock_load_cfg.return_value = parser
        parser['Renewalinfo'] = {'foo': 'bar'}
        self.renewalinfo._config_load()
        self.assertTrue(mock_load_cfg.called)
        self.assertEqual(85, self.renewalinfo.renewaltreshold_pctg)
        self.assertEqual(86400, self.renewalinfo.retry_after_timeout)
        self.assertFalse(self.renewalinfo.renewal_force)

    @patch('acme_srv.renewalinfo.load_config')
    def test_003_config_load(self, mock_load_cfg):
        """ test _config_load  """
        parser = configparser.ConfigParser()
        mock_load_cfg.return_value = parser
        parser['Renewalinfo'] = {'renewaltreshold_pctg': 90}
        self.renewalinfo._config_load()
        self.assertTrue(mock_load_cfg.called)
        self.assertEqual(90, self.renewalinfo.renewaltreshold_pctg)
        self.assertEqual(86400, self.renewalinfo.retry_after_timeout)
        self.assertFalse(self.renewalinfo.renewal_force)

    @patch('acme_srv.renewalinfo.load_config')
    def test_004_config_load(self, mock_load_cfg):
        """ test _config_load  """
        parser = configparser.ConfigParser()
        mock_load_cfg.return_value = parser
        parser['Renewalinfo'] = {'renewaltreshold_pctg': '90'}
        self.renewalinfo._config_load()
        self.assertTrue(mock_load_cfg.called)
        self.assertEqual(90, self.renewalinfo.renewaltreshold_pctg)
        self.assertEqual(86400, self.renewalinfo.retry_after_timeout)
        self.assertFalse(self.renewalinfo.renewal_force)

    @patch('acme_srv.renewalinfo.load_config')
    def test_005_config_load(self, mock_load_cfg):
        """ test _config_load  """
        parser = configparser.ConfigParser()
        mock_load_cfg.return_value = parser
        parser['Renewalinfo'] = {'renewaltreshold_pctg': 'aa'}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.renewalinfo._config_load()
        self.assertTrue(mock_load_cfg.called)
        self.assertEqual(85, self.renewalinfo.renewaltreshold_pctg)
        self.assertEqual(86400, self.renewalinfo.retry_after_timeout)
        self.assertIn("ERROR:test_a2c:acme2certifier Renewalinfo._config_load() renewaltreshold_pctg parsing error: could not convert string to float: 'aa'", lcm.output)
        self.assertFalse(self.renewalinfo.renewal_force)

    @patch('acme_srv.renewalinfo.load_config')
    def test_006_config_load(self, mock_load_cfg):
        """ test _config_load  """
        parser = configparser.ConfigParser()
        mock_load_cfg.return_value = parser
        parser['Renewalinfo'] = {'retry_after_timeout': 90}
        self.renewalinfo._config_load()
        self.assertTrue(mock_load_cfg.called)
        self.assertEqual(85, self.renewalinfo.renewaltreshold_pctg)
        self.assertEqual(90, self.renewalinfo.retry_after_timeout)
        self.assertFalse(self.renewalinfo.renewal_force)

    @patch('acme_srv.renewalinfo.load_config')
    def test_007_config_load(self, mock_load_cfg):
        """ test _config_load  """
        parser = configparser.ConfigParser()
        mock_load_cfg.return_value = parser
        parser['Renewalinfo'] = {'retry_after_timeout': '90'}
        self.renewalinfo._config_load()
        self.assertTrue(mock_load_cfg.called)
        self.assertEqual(85, self.renewalinfo.renewaltreshold_pctg)
        self.assertEqual(90, self.renewalinfo.retry_after_timeout)
        self.assertFalse(self.renewalinfo.renewal_force)

    @patch('acme_srv.renewalinfo.load_config')
    def test_008_config_load(self, mock_load_cfg):
        """ test _config_load  """
        parser = configparser.ConfigParser()
        mock_load_cfg.return_value = parser
        parser['Renewalinfo'] = {'retry_after_timeout': 'aa'}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.renewalinfo._config_load()
        self.assertTrue(mock_load_cfg.called)
        self.assertEqual(85, self.renewalinfo.renewaltreshold_pctg)
        self.assertEqual(86400, self.renewalinfo.retry_after_timeout)
        self.assertIn("ERROR:test_a2c:acme2certifier Renewalinfo._config_load() retry_after_timeout parsing error: invalid literal for int() with base 10: 'aa'", lcm.output)
        self.assertFalse(self.renewalinfo.renewal_force)

    @patch('acme_srv.renewalinfo.load_config')
    def test_009_config_load(self, mock_load_cfg):
        """ test _config_load  """
        parser = configparser.ConfigParser()
        mock_load_cfg.return_value = parser
        parser['Renewalinfo'] = {'renewal_force': True}
        self.renewalinfo._config_load()
        self.assertTrue(mock_load_cfg.called)
        self.assertEqual(85, self.renewalinfo.renewaltreshold_pctg)
        self.assertEqual(86400, self.renewalinfo.retry_after_timeout)
        self.assertTrue(self.renewalinfo.renewal_force)

    @patch('acme_srv.renewalinfo.load_config')
    def test_010_config_load(self, mock_load_cfg):
        """ test _config_load  """
        parser = configparser.ConfigParser()
        mock_load_cfg.return_value = parser
        parser['Renewalinfo'] = {'renewal_force': False}
        self.renewalinfo._config_load()
        self.assertTrue(mock_load_cfg.called)
        self.assertEqual(85, self.renewalinfo.renewaltreshold_pctg)
        self.assertEqual(86400, self.renewalinfo.retry_after_timeout)
        self.assertFalse(self.renewalinfo.renewal_force)

    @patch('acme_srv.renewalinfo.Renewalinfo._config_load')
    def test_011_config_enter(self, mock_load_cfg):
        """ test __enter __"""
        self.renewalinfo.__enter__()
        self.assertTrue(mock_load_cfg.called)

    def test_012_lookup(self):
        """ test _lookup() """
        self.renewalinfo.dbstore.certificate_lookup.return_value = {'foo': 'bar'}
        self.assertEqual({'foo': 'bar'}, self.renewalinfo._lookup('foo1'))

    def test_013_lookup(self):
        """ test _lookup() """
        self.renewalinfo.dbstore.certificate_lookup.side_effect = Exception('cert_lookup')
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertFalse(self.renewalinfo._lookup('foo1'))
        self.assertIn('CRITICAL:test_a2c:acme2certifier database error in Renewalinfo._lookup(): cert_lookup', lcm.output)

    @patch('acme_srv.renewalinfo.Renewalinfo._lookup')
    def test_014_renewalinfo_get(self, mock_lookup):
        """ test _renewalinfo_get() """
        mock_lookup.return_value = {}
        self.assertFalse(self.renewalinfo._renewalinfo_get('1a2b3c4d5e6f'))

    @patch('acme_srv.renewalinfo.Renewalinfo._lookup')
    def test_015_renewalinfo_get(self, mock_lookup):
        """ test _renewalinfo_get() """
        mock_lookup.return_value = {'foo': 'bar'}
        self.assertFalse(self.renewalinfo._renewalinfo_get('1a2b3c4d5e6f'))

    @patch('acme_srv.renewalinfo.Renewalinfo._lookup')
    def test_016_renewalinfo_get(self, mock_lookup):
        """ test _renewalinfo_get() """
        mock_lookup.return_value = {'expire_uts': 0}
        self.assertFalse(self.renewalinfo._renewalinfo_get('1a2b3c4d5e6f'))

    @patch('acme_srv.renewalinfo.Renewalinfo._lookup')
    def test_017_renewalinfo_get(self, mock_lookup):
        """ test _renewalinfo_get() """
        mock_lookup.return_value = {'expire_uts': 1000, 'issue_uts': 100}
        self.assertEqual({'suggestedWindow': {'start': '1970-01-01T00:14:25Z', 'end': '1970-01-01T00:16:40Z'}}, self.renewalinfo._renewalinfo_get('1a2b3c4d5e6f'))

    @patch('acme_srv.renewalinfo.uts_now')
    @patch('acme_srv.renewalinfo.Renewalinfo._lookup')
    def test_018_renewalinfo_get(self, mock_lookup, mock_uts):
        """ test _renewalinfo_get() """
        mock_uts.return_value = 100
        mock_lookup.return_value = {'expire_uts': 1000}
        self.assertEqual({'suggestedWindow': {'start': '1970-01-01T00:14:25Z', 'end': '1970-01-01T00:16:40Z'}}, self.renewalinfo._renewalinfo_get('1a2b3c4d5e6f'))
        self.assertTrue(mock_uts.called)

    @patch('acme_srv.renewalinfo.uts_now')
    @patch('acme_srv.renewalinfo.Renewalinfo._lookup')
    def test_019_renewalinfo_get(self, mock_lookup, mock_uts):
        """ test _renewalinfo_get() """
        mock_uts.return_value = 86400000
        mock_lookup.return_value = {'expire_uts': 1000, 'issue_uts': 200}
        self.renewalinfo.renewal_force = True
        self.assertEqual({'suggestedWindow': {'start': '1971-09-29T00:00:00Z', 'end': '1972-09-28T00:00:00Z'}}, self.renewalinfo._renewalinfo_get('1a2b3c4d5e6f'))
        self.assertTrue(mock_uts.called)

    @patch('acme_srv.renewalinfo.Renewalinfo._renewalinfo_get')
    @patch('acme_srv.renewalinfo.certid_hex_get')
    @patch('acme_srv.renewalinfo.string_sanitize')
    def test_020_get(self, mock_sanitize, mock_hexget, mock_renget):
        """ test get() """
        mock_renget.return_value = {'foo': 'bar'}
        mock_hexget.return_value = ('300b0609608648016503040201', 'bar')
        self.assertEqual({'code': 200, 'data': {'foo': 'bar'}, 'header': {'Retry-After': '86400'}}, self. renewalinfo.get('url'))
        self.assertTrue(mock_sanitize.called)
        self.assertTrue(mock_hexget.called)

    @patch('acme_srv.renewalinfo.Renewalinfo._renewalinfo_get')
    @patch('acme_srv.renewalinfo.certid_hex_get')
    @patch('acme_srv.renewalinfo.string_sanitize')
    def test_021_get(self, mock_sanitize, mock_hexget, mock_renget):
        """ test get() """
        mock_renget.return_value = None
        mock_hexget.return_value = ('300b0609608648016503040201', 'bar')
        self.assertEqual({'code': 404, 'data': 'urn:ietf:params:acme:error:malformed'}, self. renewalinfo.get('url'))
        self.assertTrue(mock_sanitize.called)
        self.assertTrue(mock_hexget.called)

    @patch('acme_srv.renewalinfo.Renewalinfo._renewalinfo_get')
    @patch('acme_srv.renewalinfo.certid_hex_get')
    @patch('acme_srv.renewalinfo.string_sanitize')
    def test_022_get(self, mock_sanitize, mock_hexget, mock_renget):
        """ test get() """
        mock_renget.return_value = None
        mock_hexget.return_value = (None, 'bar')
        self.assertEqual({'code': 400, 'data': 'urn:ietf:params:acme:error:malformed'}, self. renewalinfo.get('url'))
        self.assertTrue(mock_sanitize.called)
        self.assertTrue(mock_hexget.called)

    @patch('acme_srv.message.Message.check')
    def test_023_update(self, mock_mcheck):
        """ test update() """
        mock_mcheck.return_value = (400, 'message', 'detail', 'protected', 'payload', 'account_name')
        self.assertEqual({'code': 400}, self.renewalinfo.update('content'))

    @patch('acme_srv.message.Message.check')
    def test_024_update(self, mock_mcheck):
        """ test update() """
        mock_mcheck.return_value = (200, 'message', 'detail', 'protected', {'certid': 'certid'}, 'account_name')
        self.assertEqual({'code': 400}, self.renewalinfo.update('content'))

    @patch('acme_srv.renewalinfo.Renewalinfo._lookup')
    @patch('acme_srv.renewalinfo.certid_hex_get')
    @patch('acme_srv.message.Message.check')
    def test_025_update(self, mock_mcheck, mock_hex, mock_lookup):
        """ test update() """
        mock_mcheck.return_value = (200, 'message', 'detail', 'protected', {'certid': 'certid', 'replaced': True}, 'account_name')
        mock_hex.return_value = ('300b0609608648016503040201', 'certhex')
        mock_lookup.return_value = None
        self.assertEqual({'code': 400}, self.renewalinfo.update('content'))

    @patch('acme_srv.renewalinfo.Renewalinfo._lookup')
    @patch('acme_srv.renewalinfo.certid_hex_get')
    @patch('acme_srv.message.Message.check')
    def test_026_update(self, mock_mcheck, mock_hex, mock_lookup):
        """ test update() """
        mock_mcheck.return_value = (200, 'message', 'detail', 'protected', {'certid': 'certid', 'replaced': False}, 'account_name')
        mock_hex.return_value = ('300b0609608648016503040201', 'certhex')
        mock_lookup.return_value = {'foo': 'bar'}
        self.assertEqual({'code': 400}, self.renewalinfo.update('content'))

    @patch('acme_srv.renewalinfo.Renewalinfo._lookup')
    @patch('acme_srv.renewalinfo.certid_hex_get')
    @patch('acme_srv.message.Message.check')
    def test_027_update(self, mock_mcheck, mock_hex, mock_lookup):
        """ test update() """
        mock_mcheck.return_value = (200, 'message', 'detail', 'protected', {'certid': 'certid', 'replaced': True}, 'account_name')
        mock_hex.return_value = ('300b0609608648016503040201', 'certhex')
        mock_lookup.return_value = {'foo': 'bar'}
        self.renewalinfo.dbstore.certificate_add.return_value = None
        self.assertEqual({'code': 400}, self.renewalinfo.update('content'))

    @patch('acme_srv.renewalinfo.Renewalinfo._lookup')
    @patch('acme_srv.renewalinfo.certid_hex_get')
    @patch('acme_srv.message.Message.check')
    def test_028_update(self, mock_mcheck, mock_hex, mock_lookup):
        """ test update() """
        mock_mcheck.return_value = (200, 'message', 'detail', 'protected', {'certid': 'certid', 'replaced': True}, 'account_name')
        mock_hex.return_value = ('300b0609608648016503040201', 'certhex')
        mock_lookup.return_value = {'foo': 'bar'}
        self.renewalinfo.dbstore.certificate_add.return_value = 1
        self.assertEqual({'code': 200}, self.renewalinfo.update('content'))

    def test_029_renewalinfo_string_get(self):
        """ test update() """
        self.renewalinfo.server_name = 'http://server.name'
        self.renewalinfo.path_dic = {'renewalinfo': '/renewalinfo'}
        input_string = 'http://server.name/renewalinfo/foo'
        self.assertEqual('foo', self.renewalinfo.renewalinfo_string_get(input_string))

    def test_030_renewalinfo_string_get(self):
        """ test update() """
        self.renewalinfo.server_name = 'http://server.name'
        self.renewalinfo.path_dic = {'renewalinfo': '/renewalinfo'}
        input_string = 'http://server.name/renewalinfofoo'
        self.assertEqual('foo', self.renewalinfo.renewalinfo_string_get(input_string))

    def test_031_renewalinfo_string_get(self):
        """ test update() """
        self.renewalinfo.server_name = 'http://server.name'
        self.renewalinfo.path_dic = {'renewalinfo': '/renewalinfo/'}
        input_string = 'http://server.name/renewalinfo/foo'
        self.assertEqual('foo', self.renewalinfo.renewalinfo_string_get(input_string))

if __name__ == '__main__':
    unittest.main()
