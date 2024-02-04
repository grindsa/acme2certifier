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

    @patch('acme_srv.renewalinfo.Renewalinfo._renewalinfo_generate')
    @patch('acme_srv.renewalinfo.Renewalinfo._cert_dic_lookup')
    def test_019_renewalinfo_get(self, mock_lookup, mock_gen):
        """ test _renewalinfo_get() """
        mock_gen.return_value = {'foo': 'bar'}
        self.assertEqual({'foo': 'bar'}, self.renewalinfo._renewalinfo_get('1a2b3c4d5e6f'))
        self.assertTrue(mock_lookup.called)

    @patch('acme_srv.renewalinfo.Renewalinfo._renewalinfo_get')
    @patch('acme_srv.renewalinfo.Renewalinfo._renewalinfo_string_get')
    @patch('acme_srv.renewalinfo.Renewalinfo._cert_table_update')
    def test_020_get(self, mock_update, mock_renstr_get, mock_renget):
        """ test get() """
        mock_renget.return_value = {'foo': 'bar'}
        mock_renstr_get.return_value = 'mock_renstr_get'
        self.renewalinfo.dbstore.hkparameter_get.return_value = None
        self.assertEqual({'code': 200, 'data': {'foo': 'bar'}, 'header': {'Retry-After': '86400'}}, self. renewalinfo.get('url'))
        self.assertTrue(mock_update.called)

    @patch('acme_srv.renewalinfo.Renewalinfo._renewalinfo_get')
    @patch('acme_srv.renewalinfo.Renewalinfo._renewalinfo_string_get')
    @patch('acme_srv.renewalinfo.Renewalinfo._cert_table_update')
    def test_021_get(self, mock_update, mock_renstr_get, mock_renget):
        """ test get() """
        mock_renget.return_value = {'foo': 'bar'}
        mock_renstr_get.return_value = 'mock_renstr_get'
        self.renewalinfo.dbstore.hkparameter_get.return_value = {'foo': 'bar'}
        self.assertEqual({'code': 200, 'data': {'foo': 'bar'}, 'header': {'Retry-After': '86400'}}, self. renewalinfo.get('url'))
        self.assertFalse(mock_update.called)

    @patch('acme_srv.renewalinfo.Renewalinfo._renewalinfo_get')
    @patch('acme_srv.renewalinfo.Renewalinfo._renewalinfo_string_get')
    @patch('acme_srv.renewalinfo.Renewalinfo._cert_table_update')
    def test_022_get(self, mock_update, mock_renstr_get, mock_renget):
        """ test get() """
        mock_renget.return_value = None
        self.renewalinfo.dbstore.hkparameter_get.return_value = None
        self.assertEqual({'code': 404, 'data': 'urn:ietf:params:acme:error:malformed'}, self. renewalinfo.get('url'))
        self.assertTrue(mock_update.called)
        self.assertTrue(mock_renstr_get.called)

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

    @patch('acme_srv.renewalinfo.Renewalinfo._cert_dic_lookup')
    @patch('acme_srv.message.Message.check')
    def test_025_update(self, mock_mcheck, mock_lookup):
        """ test update() """
        mock_mcheck.return_value = (200, 'message', 'detail', 'protected', {'certid': 'certid', 'replaced': True}, 'account_name')
        mock_lookup.return_value = None
        self.assertEqual({'code': 400}, self.renewalinfo.update('content'))

    @patch('acme_srv.renewalinfo.Renewalinfo._cert_dic_lookup')
    @patch('acme_srv.message.Message.check')
    def test_026_update(self, mock_mcheck, mock_lookup):
        """ test update() """
        mock_mcheck.return_value = (200, 'message', 'detail', 'protected', {'certid': 'certid', 'replaced': False}, 'account_name')
        mock_lookup.return_value = {'foo': 'bar'}
        self.assertEqual({'code': 400}, self.renewalinfo.update('content'))

    @patch('acme_srv.renewalinfo.Renewalinfo._cert_dic_lookup')
    @patch('acme_srv.message.Message.check')
    def test_027_update(self, mock_mcheck, mock_lookup):
        """ test update() """
        mock_mcheck.return_value = (200, 'message', 'detail', 'protected', {'certid': 'certid', 'replaced': True}, 'account_name')
        mock_lookup.return_value = {'foo': 'bar'}
        self.renewalinfo.dbstore.certificate_add.return_value = None
        self.assertEqual({'code': 400}, self.renewalinfo.update('content'))

    @patch('acme_srv.renewalinfo.Renewalinfo._cert_dic_lookup')
    @patch('acme_srv.message.Message.check')
    def test_028_update(self, mock_mcheck, mock_lookup):
        """ test update() """
        mock_mcheck.return_value = (200, 'message', 'detail', 'protected', {'certid': 'certid', 'replaced': True}, 'account_name')
        mock_lookup.return_value = {'foo': 'bar'}
        self.renewalinfo.dbstore.certificate_add.return_value = 1
        self.assertEqual({'code': 200}, self.renewalinfo.update('content'))

    def test_029_renewalinfo_string_get(self):
        """ test update() """
        self.renewalinfo.server_name = 'http://server.name'
        self.renewalinfo.path_dic = {'renewalinfo': '/renewalinfo'}
        input_string = 'http://server.name/renewalinfo/foo'
        self.assertEqual('foo', self.renewalinfo._renewalinfo_string_get(input_string))

    def test_030_renewalinfo_string_get(self):
        """ test update() """
        self.renewalinfo.server_name = 'http://server.name'
        self.renewalinfo.path_dic = {'renewalinfo': '/renewalinfo'}
        input_string = 'http://server.name/renewalinfofoo'
        self.assertEqual('foo', self.renewalinfo._renewalinfo_string_get(input_string))

    def test_031_renewalinfo_string_get(self):
        """ test update() """
        self.renewalinfo.server_name = 'http://server.name'
        self.renewalinfo.path_dic = {'renewalinfo': '/renewalinfo/'}
        input_string = 'http://server.name/renewalinfo/foo'
        self.assertEqual('foo', self.renewalinfo._renewalinfo_string_get(input_string))

    @patch('acme_srv.renewalinfo.Renewalinfo._draft02_lookup')
    @patch('acme_srv.renewalinfo.Renewalinfo._draft01_lookup')
    @patch('acme_srv.renewalinfo.certid_hex_get')
    @patch('acme_srv.renewalinfo.Renewalinfo._serial_aki_get')
    def test_032_cert_dic_lookup(self, mock_aki, mock_certid, mock_draft01, mock_draft02):
        """ test _cert_dic_lookup() """
        mock_aki.return_value = ('serail', 'aki')
        mock_draft01.return_value = {'foo': 'draft01'}
        mock_draft02.return_value = {'foo': 'draft02'}
        self.assertEqual({'foo': 'draft02'}, self.renewalinfo._cert_dic_lookup('cert.id'))
        self.assertTrue(mock_aki.called)
        self.assertFalse(mock_certid.called)
        self.assertFalse(mock_draft01.called)
        self.assertTrue(mock_draft02.called)

    @patch('acme_srv.renewalinfo.Renewalinfo._draft02_lookup')
    @patch('acme_srv.renewalinfo.Renewalinfo._draft01_lookup')
    @patch('acme_srv.renewalinfo.certid_hex_get')
    @patch('acme_srv.renewalinfo.Renewalinfo._serial_aki_get')
    def test_033_cert_dic_lookup(self, mock_aki, mock_certid, mock_draft01, mock_draft02):
        """ test _cert_dic_lookup() """
        mock_aki.return_value = ('serail', 'aki')
        mock_certid.return_value = ('mda', 'certid')
        mock_draft01.return_value = {'foo': 'draft01'}
        mock_draft02.return_value = {'foo': 'draft02'}
        self.assertEqual({'foo': 'draft01'}, self.renewalinfo._cert_dic_lookup('certid'))
        self.assertFalse(mock_aki.called)
        self.assertTrue(mock_certid.called)
        self.assertTrue(mock_draft01.called)
        self.assertFalse(mock_draft02.called)

    def test_034_draft01_lookup(self):
        """ test _draft01_lookup() """
        self.renewalinfo.dbstore.certificate_lookup.return_value = {'foo': 'bar'}
        self.assertEqual({'foo': 'bar'}, self.renewalinfo._draft01_lookup('certid_hex'))

    def test_035_draft01_lookup(self):
        """ test _draft01_lookup() """
        self.renewalinfo.dbstore.certificate_lookup.side_effect = Exception('cert_lookup')
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertFalse(self.renewalinfo._draft01_lookup('certid_hex'))
        self.assertIn('CRITICAL:test_a2c:acme2certifier database error in Renewalinfo._draft01_lookup(): cert_lookup', lcm.output)

    def test_036_draft02_lookup(self):
        """ test _draft02_lookup() """
        self.renewalinfo.dbstore.certificates_search.return_value = [{'foo': 'bar01', 'aki': 'aki01'}, {'foo': 'bar02', 'aki': 'aki02'}]
        self.assertEqual({'aki': 'aki01', 'foo': 'bar01'}, self.renewalinfo._draft02_lookup('serial', 'aki01'))

    def test_037_draft02_lookup(self):
        """ test _draft02_lookup() """
        self.renewalinfo.dbstore.certificates_search.return_value = [{'foo': 'bar01', 'aki': 'aki01'}, {'foo': 'bar02', 'aki': 'aki02'}]
        self.assertEqual({'aki': 'aki02', 'foo': 'bar02'}, self.renewalinfo._draft02_lookup('serial', 'aki02'))

    @patch('acme_srv.renewalinfo.cert_aki_get')
    @patch('acme_srv.renewalinfo.cert_serial_get')
    def test_038_cert_table_update(self, mock_serial, mock_aki):
        """ test _cert_table_update() """
        self.renewalinfo.dbstore.certificates_search.return_value = [{'foo': 'bar', 'cert_raw': 'cert_raw', 'name': 'name', 'cert': 'cert'}]
        self.assertFalse(self.renewalinfo._cert_table_update())
        self.assertTrue(mock_serial.called)
        self.assertTrue(mock_aki.called)

    @patch('acme_srv.renewalinfo.cert_aki_get')
    @patch('acme_srv.renewalinfo.cert_serial_get')
    def test_039_cert_table_update(self, mock_serial, mock_aki):
        """ test _cert_table_update() """
        self.renewalinfo.dbstore.certificates_search.return_value = [{'foo': 'bar', 'cert_raw': None, 'name': 'name', 'cert': 'cert'}]
        self.assertFalse(self.renewalinfo._cert_table_update())
        self.assertFalse(mock_serial.called)
        self.assertFalse(mock_aki.called)

    @patch('acme_srv.renewalinfo.cert_aki_get')
    @patch('acme_srv.renewalinfo.cert_serial_get')
    def test_040_cert_table_update(self, mock_serial, mock_aki):
        """ test _cert_table_update() """
        self.renewalinfo.dbstore.certificates_search.return_value = [{'foo': 'bar', 'name': 'name', 'cert': 'cert'}]
        self.assertFalse(self.renewalinfo._cert_table_update())
        self.assertFalse(mock_serial.called)
        self.assertFalse(mock_aki.called)

    @patch('acme_srv.renewalinfo.cert_aki_get')
    @patch('acme_srv.renewalinfo.cert_serial_get')
    def test_041_cert_table_update(self, mock_serial, mock_aki):
        """ test _cert_table_update() """
        self.renewalinfo.dbstore.certificates_search.return_value = Exception('certificates_search')
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertFalse(self.renewalinfo._cert_table_update())
        self.assertIn('CRITICAL:test_a2c:acme2certifier database error in Renewalinfo._cert_table_update(): certificates_search', lcm.output)
        self.assertFalse(mock_serial.called)
        self.assertFalse(mock_aki.called)

    def test_038_draft02_lookup(self):
        """ test _draft02_lookup() """
        self.renewalinfo.dbstore.certificates_search.return_value = [{'foo': 'bar01', 'aki': 'aki01'}, {'foo': 'bar02', 'aki': 'aki02'}]
        self.assertFalse(self.renewalinfo._draft02_lookup('serial', 'aki03'))

    def test_039_draft02_lookup(self):
        """ test _draft02_lookup() """
        self.renewalinfo.dbstore.certificates_search.return_value = [{'foo': 'bar01', }, {'foo': 'bar02', 'aki': 'aki02'}]
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertFalse(self.renewalinfo._draft02_lookup('serial', 'aki03'))
        self.assertIn("CRITICAL:test_a2c:acme2certifier database error in Renewalinfo._draft02_lookup(): 'aki'", lcm.output)

    def test_040_draft02_lookup(self):
        """ test _draft02_lookup() """
        self.renewalinfo.dbstore.certificates_search.side_effect = Exception('certificates_search')
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertFalse(self.renewalinfo._draft02_lookup('serial', 'aki03'))
        self.assertIn('CRITICAL:test_a2c:acme2certifier database error in Renewalinfo._draft02_lookup(): certificates_search', lcm.output)

    @patch('acme_srv.renewalinfo.b64_url_recode')
    @patch('acme_srv.renewalinfo.b64_decode')
    def test_041_serial_aki_get(self, mock_dec, mock_rec):
        """ test _serial_aki_get() """
        mock_dec.side_effect = [b'aki', b'serial']
        mock_rec.side_effect = ['foo1', 'foo2']
        self.assertEqual(('616b69', '73657269616c'), self.renewalinfo._serial_aki_get('renewal.info'))
        self.assertEqual(2, mock_dec.call_count)
        self.assertEqual(2, mock_rec.call_count)

    @patch('acme_srv.renewalinfo.b64_url_recode')
    @patch('acme_srv.renewalinfo.b64_decode')
    def test_042_serial_aki_get(self, mock_dec, mock_rec):
        """ test _serial_aki_get() """
        mock_dec.side_effect = [b'aki', b'serial']
        mock_rec.side_effect = ['foo1', 'foo2']
        self.assertEqual((None, None), self.renewalinfo._serial_aki_get('ren.ewal.info'))
        self.assertFalse(mock_dec.called)
        self.assertFalse(mock_rec.called)

    @patch('acme_srv.renewalinfo.b64_url_recode')
    @patch('acme_srv.renewalinfo.b64_decode')
    def test_043_serial_aki_get(self, mock_dec, mock_rec):
        """ test _serial_aki_get() """
        mock_dec.side_effect = [b'aki', b'serial']
        mock_rec.side_effect = ['foo1', 'foo2']
        self.assertEqual((None, None), self.renewalinfo._serial_aki_get('renewalinfo'))
        self.assertFalse(mock_dec.called)
        self.assertFalse(mock_rec.called)

    def test_014_renewalinfo_generate(self):
        """ test _renewalinfo_generate() """
        self.assertFalse(self.renewalinfo._renewalinfo_generate({}))

    def test_015_renewalinfo_generate(self):
        """ test _renewalinfo_generate() """
        cert_dic = {'foo': 'bar'}
        self.assertFalse(self.renewalinfo._renewalinfo_generate(cert_dic))

    def test_016_renewalinfo_generate(self):
        """ test _renewalinfo_generate() """
        cert_dic  = {'expire_uts': 0}
        self.assertFalse(self.renewalinfo._renewalinfo_generate(cert_dic))

    def test_017_renewalinfo_generate(self):
        """ test _renewalinfo_generate() """
        cert_dic = {'expire_uts': 1000, 'issue_uts': 100}
        self.assertEqual({'suggestedWindow': {'start': '1970-01-01T00:14:25Z', 'end': '1970-01-01T00:16:40Z'}}, self.renewalinfo._renewalinfo_generate(cert_dic))

    @patch('acme_srv.renewalinfo.uts_now')
    def test_018_renewalinfo_generate(self, mock_uts):
        """ test _renewalinfo_generate() """
        mock_uts.return_value = 100
        cert_dic = {'expire_uts': 1000}
        self.assertEqual({'suggestedWindow': {'start': '1970-01-01T00:14:25Z', 'end': '1970-01-01T00:16:40Z'}}, self.renewalinfo._renewalinfo_generate(cert_dic))
        self.assertTrue(mock_uts.called)

    @patch('acme_srv.renewalinfo.uts_now')
    def test_019_renewalinfo_generate(self, mock_uts):
        """ test _renewalinfo_generate() """
        mock_uts.return_value = 86400000
        cert_dic = {'expire_uts': 1000, 'issue_uts': 200}
        self.renewalinfo.renewal_force = True
        self.assertEqual({'suggestedWindow': {'start': '1971-09-29T00:00:00Z', 'end': '1972-09-28T00:00:00Z'}}, self.renewalinfo._renewalinfo_generate(cert_dic))
        self.assertTrue(mock_uts.called)

if __name__ == '__main__':
    unittest.main()
