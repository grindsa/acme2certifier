#!/usr/bin/python
# -*- coding: utf-8 -*-
""" unittests for openssl_ca_handler """
# pylint: disable=C0415, R0904, R0913, W0212
import sys
import os
import unittest
from unittest.mock import patch, mock_open, Mock
# from OpenSSL import crypto
import shutil
import configparser

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
    def test_007_config_load(self, mock_load_cfg):
        """ test _config_load - cmp_openssl_bin parameter"""
        mock_load_cfg.return_value = {'CAhandler': {'cmp_openssl_bin': 'foo'}}
        self.cahandler._config_load()
        odict = {'cmd': 'ir', 'popo': 0}
        self.assertEqual(odict, self.cahandler.config_dic)
        self.assertEqual('foo', self.cahandler.openssl_bin)

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
        """  test _config_load - cmp_openssl_bin not configured """
        mock_load_cfg.return_value = {}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_load()
        self.assertIn('WARNING:test_a2c:CAhandler config error: "cmp_openssl_bin" parameter not in config_file. Using default (/usr/bin/openssl)', lcm.output)

    @patch('examples.ca_handler.cmp_ca_handler.load_config')
    def test_018_config_load(self, mock_load_cfg):
        """  test _config_load - cmp_recipient not configured """
        mock_load_cfg.return_value = {}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_load()
        self.assertIn('ERROR:test_a2c:CAhandler config error: "cmp_recipient" is missing in config_file.', lcm.output)

    @patch.dict('os.environ', {'cmp_ref': 'cmp_ref'})
    @patch('examples.ca_handler.cmp_ca_handler.load_config')
    def test_019_config_load(self, mock_load_cfg):
        """ test _config_load - load template with ref variable """
        mock_load_cfg.return_value = {'CAhandler': {'cmp_ref_variable': 'cmp_ref'}}
        self.cahandler._config_load()
        self.assertEqual('cmp_ref', self.cahandler.ref)

    @patch.dict('os.environ', {'cmp_ref': 'user_var'})
    @patch('examples.ca_handler.cmp_ca_handler.load_config')
    def test_020_config_load(self, mock_load_cfg):
        """ test _config_load - load template with not existing ref variable """
        mock_load_cfg.return_value = {'CAhandler': {'cmp_ref_variable': 'does_not_exist'}}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_load()
        self.assertFalse(self.cahandler.ref)
        self.assertIn("ERROR:test_a2c:CAhandler._config_load() could not load cmp_ref:'does_not_exist'", lcm.output)

    @patch.dict('os.environ', {'cmp_ref': 'cmp_ref'})
    @patch('examples.ca_handler.cmp_ca_handler.load_config')
    def test_021_config_load(self, mock_load_cfg):
        """ test _config_load - load template overwrite ref variable """
        mock_load_cfg.return_value = {'CAhandler': {'cmp_ref_variable': 'cmp_ref', 'cmp_ref': 'cmp_ref_local'}}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_load()
        self.assertEqual('cmp_ref_local', self.cahandler.ref)
        self.assertIn('INFO:test_a2c:CAhandler._config_load() overwrite cmp_ref variable', lcm.output)

    @patch.dict('os.environ', {'cmp_secret': 'cmp_secret'})
    @patch('examples.ca_handler.cmp_ca_handler.load_config')
    def test_022_config_load(self, mock_load_cfg):
        """ test _config_load - load template with secret variable """
        mock_load_cfg.return_value = {'CAhandler': {'cmp_secret_variable': 'cmp_secret'}}
        self.cahandler._config_load()
        self.assertEqual('cmp_secret', self.cahandler.secret)

    @patch.dict('os.environ', {'cmp_secret': 'cmp_secret'})
    @patch('examples.ca_handler.cmp_ca_handler.load_config')
    def test_023_config_load(self, mock_load_cfg):
        """ test _config_load - load template with not existing secret variable """
        mock_load_cfg.return_value = {'CAhandler': {'cmp_secret_variable': 'does_not_exist'}}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_load()
        self.assertFalse(self.cahandler.secret)
        self.assertIn("ERROR:test_a2c:CAhandler._config_load() could not load cmp_secret_variable:'does_not_exist'", lcm.output)

    @patch.dict('os.environ', {'cmp_secret': 'cmp_secret'})
    @patch('examples.ca_handler.cmp_ca_handler.load_config')
    def test_024_config_load(self, mock_load_cfg):
        """ test _config_load - load template overwrite ref variable """
        mock_load_cfg.return_value = {'CAhandler': {'cmp_secret_variable': 'cmp_secret', 'cmp_secret': 'cmp_secret_local'}}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_load()
        self.assertEqual('cmp_secret_local', self.cahandler.secret)
        self.assertIn('INFO:test_a2c:CAhandler._config_load() overwrite cmp_secret variable', lcm.output)

    @patch('examples.ca_handler.cmp_ca_handler.load_config')
    def test_025__config_load(self, mock_load_cfg):
        """ config load enforce cmp_boolean True """
        parser = configparser.ConfigParser()
        parser['CAhandler'] = {'cmp_bool': 'True'}
        mock_load_cfg.return_value = parser
        self.cahandler._config_load()
        self.assertEqual({'bool': True, 'cmd': 'ir', 'popo': 0}, self.cahandler.config_dic)

    @patch('examples.ca_handler.cmp_ca_handler.load_config')
    def test_026__config_load(self, mock_load_cfg):
        """ config load enforce cmp_boolean False """
        parser = configparser.ConfigParser()
        parser['CAhandler'] = {'cmp_bool': 'False'}
        mock_load_cfg.return_value = parser
        self.cahandler._config_load()
        self.assertEqual({'bool': False, 'cmd': 'ir', 'popo': 0}, self.cahandler.config_dic)

    def test_027_poll(self):
        """ test trigger """
        self.assertEqual(('Method not implemented.', None, None, 'poll_identifier', False), self.cahandler.poll('cert_name', 'poll_identifier', 'csr'))

    def test_028_trigger(self):
        """ test trigger """
        self.assertEqual(('Method not implemented.', None, None), self.cahandler.trigger('payload'))

    def test_029_revoke(self):
        """ test revoke """
        self.assertEqual((500, 'urn:ietf:params:acme:error:serverInternal', 'Revocation is not supported.'), self.cahandler.revoke('cert', 'rev_reason', 'rev_date'))

    @patch('examples.ca_handler.cmp_ca_handler.CAhandler._config_load')
    def test_030__enter__(self, mock_load):
        """ test enter """
        self.cahandler.__enter__()
        self.assertTrue(mock_load.called)

    @patch('examples.ca_handler.cmp_ca_handler.CAhandler._config_load')
    def test_031__enter__(self, mock_load):
        """ test enter """
        self.cahandler.openssl_bin = 'openssl_bin'
        self.cahandler.__enter__()
        self.assertFalse(mock_load.called)

    @patch('shutil.rmtree')
    @patch('os.path.exists')
    def test_032_tmp_dir_delete(self, mock_exists, mock_remove):
        """ test files_delete if file exists """
        mock_exists.return_value = True
        self.cahandler._tmp_dir_delete()
        self.assertTrue(mock_remove.called)

    @patch('shutil.rmtree')
    @patch('os.path.exists')
    def test_033_tmp_dir_delete(self, mock_exists, mock_remove):
        """ test files_delete if file exists """
        mock_exists.return_value = False
        self.cahandler._tmp_dir_delete()
        self.assertFalse(mock_remove.called)

    @patch("builtins.open", mock_open(read_data='foo'), create=True)
    @patch('os.path.isfile')
    def test_034_certs_bundle(self, mock_exists):
        """ certs bundle if no file exists """
        mock_exists.return_value = False
        self.assertEqual((None, None), self.cahandler._certs_bundle())

    @patch("builtins.open", mock_open(read_data='foo'), create=True)
    @patch('os.path.isfile')
    def test_035_certs_bundle(self, mock_exists):
        """ certs bundle if no file exists """
        mock_exists.return_value = False
        self.assertEqual((None, None), self.cahandler._certs_bundle())

    @patch("builtins.open", mock_open(read_data='foo'), create=True)
    @patch('os.path.isfile')
    def test_036_certs_bundle(self, mock_exists):
        """ certs bundle if only capubs exists """
        mock_exists.side_effect = (True, False)
        self.assertEqual((None, None), self.cahandler._certs_bundle())

    @patch("builtins.open", mock_open(read_data='foo'), create=True)
    @patch('os.path.isfile')
    def test_037_certs_bundle(self, mock_exists):
        """ certs bundle if only cert exists """
        mock_exists.side_effect = (False, True)
        self.assertEqual(('foo', 'foo'), self.cahandler._certs_bundle())

    @patch("builtins.open", mock_open(read_data='foo'), create=True)
    @patch('os.path.isfile')
    def test_038_certs_bundle(self, mock_exists):
        """ certs bundle if all exists """
        mock_exists.side_effect = (True, True)
        self.assertEqual(('foofoo', 'foo'), self.cahandler._certs_bundle())

    @patch("builtins.open", mock_open(read_data='-----BEGIN CERTIFICATE-----\nfoo'), create=True)
    @patch('os.path.isfile')
    def test_039_certs_bundle(self, mock_exists):
        """ certs bundle if cert exists replace begin tag """
        mock_exists.side_effect = (False, True)
        self.assertEqual(('-----BEGIN CERTIFICATE-----\nfoo', 'foo'), self.cahandler._certs_bundle())

    @patch("builtins.open", mock_open(read_data='-----BEGIN CERTIFICATE-----\nfoo-----END CERTIFICATE-----\n'), create=True)
    @patch('os.path.isfile')
    def test_040_certs_bundle(self, mock_exists):
        """ certs bundle if cert exists replace end tag """
        mock_exists.side_effect = (False, True)
        self.assertEqual(('-----BEGIN CERTIFICATE-----\nfoo-----END CERTIFICATE-----\n', 'foo'), self.cahandler._certs_bundle())

    @patch("builtins.open", mock_open(read_data='foo\n'), create=True)
    @patch('os.path.isfile')
    def test_041_certs_bundle(self, mock_exists):
        """ certs bundle if cert exists replace end tag """
        mock_exists.side_effect = (False, True)
        self.assertEqual(('foo\n', 'foo'), self.cahandler._certs_bundle())

    def test_042_opensslcmd_build(self):
        """test _openssl_cmd_build()"""
        self.cahandler.openssl_bin = 'openssl_bin'
        self.cahandler.tmp_dir = '/tmp'
        self.cahandler.ca_pubs_file = '/tmp/capubs.pem'
        self.cahandler.cert_file = '/tmp/cert.pem'
        result = ['openssl_bin', 'cmp', '-csr', '/tmp/csr.pem', '-extracertsout', '/tmp/capubs.pem', '-certout', '/tmp/cert.pem', '-msg_timeout', '5', '-total_timeout', '10']
        self.assertEqual(result, self.cahandler._opensslcmd_build())

    def test_043_opensslcmd_build(self):
        """test _openssl_cmd_build() with option including in config dic"""
        self.cahandler.openssl_bin = 'openssl_bin'
        self.cahandler.tmp_dir = '/tmp'
        self.cahandler.ca_pubs_file = '/tmp/capubs.pem'
        self.cahandler.cert_file = '/tmp/cert.pem'
        self.cahandler.config_dic = {'foo1': 'bar1', 'foo2': 'bar2'}
        result = ['openssl_bin', 'cmp', '-foo1', 'bar1', '-foo2', 'bar2', '-csr', '/tmp/csr.pem', '-extracertsout', '/tmp/capubs.pem', '-certout', '/tmp/cert.pem', '-msg_timeout', '5', '-total_timeout', '10']
        self.assertEqual(result, self.cahandler._opensslcmd_build())

    def test_044_opensslcmd_build(self):
        """test _openssl_cmd_build() - customized msg_timeout"""
        self.cahandler.openssl_bin = 'openssl_bin'
        self.cahandler.tmp_dir = '/tmp'
        self.cahandler.ca_pubs_file = '/tmp/capubs.pem'
        self.cahandler.cert_file = '/tmp/cert.pem'
        self.cahandler.config_dic = {'msg_timeout': 10}
        result = ['openssl_bin', 'cmp', '-msg_timeout', '10', '-csr', '/tmp/csr.pem', '-extracertsout', '/tmp/capubs.pem', '-certout', '/tmp/cert.pem', '-total_timeout', '10']
        self.assertEqual(result, self.cahandler._opensslcmd_build())

    def test_045_opensslcmd_build(self):
        """test _openssl_cmd_build()"""
        self.cahandler.openssl_bin = 'openssl_bin'
        self.cahandler.tmp_dir = '/tmp'
        self.cahandler.config_dic = {'total_timeout': 20}
        self.cahandler.ca_pubs_file = '/tmp/capubs.pem'
        self.cahandler.cert_file = '/tmp/cert.pem'
        result = ['openssl_bin', 'cmp', '-total_timeout', '20', '-csr', '/tmp/csr.pem', '-extracertsout', '/tmp/capubs.pem', '-certout', '/tmp/cert.pem', '-msg_timeout', '5']
        self.assertEqual(result, self.cahandler._opensslcmd_build())

    def test_046_opensslcmd_build(self):
        """test _openssl_cmd_build() with secret"""
        self.cahandler.openssl_bin = 'openssl_bin'
        self.cahandler.secret = 'secret'
        self.cahandler.tmp_dir = '/tmp'
        self.cahandler.ca_pubs_file = '/tmp/capubs.pem'
        self.cahandler.cert_file = '/tmp/cert.pem'
        self.cahandler.config_dic = {'total_timeout': 20}
        result = ['openssl_bin', 'cmp', '-total_timeout', '20', '-csr', '/tmp/csr.pem', '-extracertsout', '/tmp/capubs.pem', '-certout', '/tmp/cert.pem', '-msg_timeout', '5']
        self.assertEqual(result, self.cahandler._opensslcmd_build())

    def test_047_opensslcmd_build(self):
        """test _openssl_cmd_build() with ref """
        self.cahandler.openssl_bin = 'openssl_bin'
        self.cahandler.ref = 'ref'
        self.cahandler.tmp_dir = '/tmp'
        self.cahandler.ca_pubs_file = '/tmp/capubs.pem'
        self.cahandler.cert_file = '/tmp/cert.pem'
        self.cahandler.config_dic = {'total_timeout': 20}
        result = ['openssl_bin', 'cmp', '-total_timeout', '20', '-csr', '/tmp/csr.pem', '-extracertsout', '/tmp/capubs.pem', '-certout', '/tmp/cert.pem', '-msg_timeout', '5']
        self.assertEqual(result, self.cahandler._opensslcmd_build())

    def test_048_opensslcmd_build(self):
        """test _openssl_cmd_build() with ref and secret """
        self.cahandler.openssl_bin = 'openssl_bin'
        self.cahandler.ref = 'ref'
        self.cahandler.secret = 'secret'
        self.cahandler.tmp_dir = '/tmp'
        self.cahandler.ca_pubs_file = '/tmp/capubs.pem'
        self.cahandler.cert_file = '/tmp/cert.pem'
        self.cahandler.config_dic = {'total_timeout': 20}
        result = ['openssl_bin', 'cmp', '-total_timeout', '20', '-csr', '/tmp/csr.pem', '-extracertsout', '/tmp/capubs.pem', '-certout', '/tmp/cert.pem', '-msg_timeout', '5', '-ref', 'ref', '-secret', 'secret']
        self.assertEqual(result, self.cahandler._opensslcmd_build())

    def test_049_enroll(self):
        """ test enroll without openssl_bin """
        self.assertEqual(('Config incomplete', None, None, None), self.cahandler.enroll('csr'))

    @patch('examples.ca_handler.cmp_ca_handler.CAhandler._certs_bundle')
    @patch('examples.ca_handler.cmp_ca_handler.CAhandler._tmp_dir_delete')
    @patch('os.path.isfile')
    @patch('subprocess.call')
    @patch('examples.ca_handler.cmp_ca_handler.CAhandler._opensslcmd_build')
    @patch('examples.ca_handler.cmp_ca_handler.CAhandler._file_save')
    def test_050_enroll(self, mock_save, mock_build, mock_call, mock_exists, mock_del, mock_bundle):
        """ test enroll subprocess.call returns 0 """
        self.cahandler.openssl_bin = 'openssl_bin'
        mock_save.return_value = True
        mock_build.return_value = 'opensslcmd'
        mock_call.return_value = 0
        mock_exists.return_value = True
        mock_bundle.return_value = ('cert_bundle', 'cert_raw')
        mock_del.return_value = True
        self.assertEqual((None, 'cert_bundle', 'cert_raw', None), self.cahandler.enroll('csr'))
        self.assertTrue(mock_save.called)
        self.assertTrue(mock_build.called)
        self.assertTrue(mock_call.called)
        self.assertTrue(mock_exists.called)
        self.assertTrue(mock_del.called)
        self.assertTrue(mock_bundle.called)

    @patch('examples.ca_handler.cmp_ca_handler.CAhandler._certs_bundle')
    @patch('examples.ca_handler.cmp_ca_handler.CAhandler._tmp_dir_delete')
    @patch('os.path.isfile')
    @patch('subprocess.call')
    @patch('examples.ca_handler.cmp_ca_handler.CAhandler._opensslcmd_build')
    @patch('examples.ca_handler.cmp_ca_handler.CAhandler._file_save')
    def test_051_enroll(self, mock_save, mock_build, mock_call, mock_exists, mock_del, mock_bundle):
        """ test enroll subprocess.call returns other than 0 """
        self.cahandler.openssl_bin = 'openssl_bin'
        mock_save.return_value = True
        mock_build.return_value = 'opensslcmd'
        mock_call.return_value = 25
        mock_exists.return_value = True
        mock_bundle.return_value = ('cert_bundle', 'cert_raw')
        mock_del.return_value = True
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual(('rc from enrollment not 0', 'cert_bundle', 'cert_raw', None), self.cahandler.enroll('csr'))
        self.assertIn('ERROR:test_a2c:CAhandler.enroll(): failed: 25', lcm.output)
        self.assertTrue(mock_save.called)
        self.assertTrue(mock_build.called)
        self.assertTrue(mock_call.called)
        self.assertTrue(mock_exists.called)
        self.assertTrue(mock_del.called)
        self.assertTrue(mock_bundle.called)

    @patch('examples.ca_handler.cmp_ca_handler.CAhandler._certs_bundle')
    @patch('examples.ca_handler.cmp_ca_handler.CAhandler._tmp_dir_delete')
    @patch('os.path.isfile')
    @patch('subprocess.call')
    @patch('examples.ca_handler.cmp_ca_handler.CAhandler._opensslcmd_build')
    @patch('examples.ca_handler.cmp_ca_handler.CAhandler._file_save')
    def test_052_enroll(self, mock_save, mock_build, mock_call, mock_exists, mock_del, mock_bundle):
        """ test enroll tmp_dir does not exists """
        self.cahandler.openssl_bin = 'openssl_bin'
        mock_save.return_value = True
        mock_build.return_value = 'opensslcmd'
        mock_call.return_value = 25
        mock_exists.return_value = False
        mock_bundle.return_value = ('cert_bundle', 'cert_raw')
        mock_del.return_value = True
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual(('Enrollment failed', None, None, None), self.cahandler.enroll('csr'))
        self.assertIn('ERROR:test_a2c:CAhandler.enroll(): failed: 25', lcm.output)
        self.assertTrue(mock_save.called)
        self.assertTrue(mock_build.called)
        self.assertTrue(mock_call.called)
        self.assertTrue(mock_exists.called)
        self.assertTrue(mock_del.called)
        self.assertFalse(mock_bundle.called)

    @patch("builtins.open")
    def test_053__file_save(self, mock_op):
        """ test file save """
        self.assertFalse(self.cahandler._file_save('filename', 'content'))
        self.assertTrue(mock_op.called)

if __name__ == '__main__':

    unittest.main()
