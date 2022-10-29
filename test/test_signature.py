#!/usr/bin/python
# -*- coding: utf-8 -*-
""" unittests for account.py """
# pylint: disable=C0302, C0415, R0904, R0913, R0914, R0915, W0212
import unittest
import sys
import configparser
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
        from acme_srv.signature import Signature
        self.signature = Signature(False, 'http://tester.local', self.logger)

    def test_001_signature__jwk_load(self):
        """ test jwk load """
        self.signature.dbstore.jwk_load.return_value = 'foo'
        self.assertEqual('foo', self.signature._jwk_load(1))

    def test_002_signature_check(self):
        """ test Signature.check() without having content """
        self.assertEqual((False, 'urn:ietf:params:acme:error:malformed', None), self.signature.check('foo', None))

    @patch('acme_srv.signature.Signature._jwk_load')
    def test_003_signature_check(self, mock_jwk):
        """ test Signature.check() while pubkey lookup failed """
        mock_jwk.return_value = {}
        self.assertEqual((False, 'urn:ietf:params:acme:error:accountDoesNotExist', None), self.signature.check('foo', 1))

    @patch('acme_srv.signature.signature_check')
    @patch('acme_srv.signature.Signature._jwk_load')
    def test_004_signature_check(self, mock_jwk, mock_sig):
        """ test successful Signature.check()  """
        mock_jwk.return_value = {'foo' : 'bar'}
        mock_sig.return_value = (True, None)
        self.assertEqual((True, None, None), self.signature.check('foo', 1))

    def test_005_signature_check(self):
        """ test successful Signature.check() without account_name and use_emb_key False"""
        self.assertEqual((False, 'urn:ietf:params:acme:error:accountDoesNotExist', None), self.signature.check(None, 1, False))

    def test_006_signature_check(self):
        """ test successful Signature.check() without account_name and use_emb_key True but having a corrupted protected header"""
        protected = {'foo': 'foo'}
        self.assertEqual((False, 'urn:ietf:params:acme:error:accountDoesNotExist', None), self.signature.check(None, 1, True, protected))

    @patch('acme_srv.signature.signature_check')
    def test_007_signature_check(self, mock_sig):
        """ test successful Signature.check() with account_name and use_emb_key True, sigcheck returns something"""
        mock_sig.return_value = ('result', 'error')
        self.assertEqual(('result', 'error', None), self.signature.check('foo', 1, True))

    @patch('acme_srv.signature.signature_check')
    def test_008_signature_check(self, mock_sig):
        """ test successful Signature.check() without account_name and use_emb_key True, sigcheck returns something"""
        mock_sig.return_value = ('result', 'error')
        protected = {'url' : 'url', 'jwk': 'jwk'}
        self.assertEqual(('result', 'error', None), self.signature.check(None, 1, True, protected))

    def test_009_signature__jwk_load(self):
        """ test jwk load  - dbstore.jwk_load() raises an exception"""
        self.signature.dbstore.jwk_load.side_effect = Exception('exc_sig_jw_load')
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.signature._jwk_load(1)
        self.assertIn('CRITICAL:test_a2c:acme2certifier database error in Signature._jwk_load(): exc_sig_jw_load', lcm.output)

    @patch('acme_srv.signature.signature_check')
    def test_010_signature_eab_check(self, mock_sigchk):
        """ test eab_check  -  result and error """
        content = 'content'
        mac_key = 'mac_key'
        mock_sigchk.return_value = ('result', 'error')
        self.assertEqual(('result', 'error'), self.signature.eab_check(content, mac_key))

    @patch('acme_srv.signature.signature_check')
    def test_011_signature_eab_check(self, mock_sigchk):
        """ test eab_check  -  result no error """
        content = 'content'
        mac_key = 'mac_key'
        mock_sigchk.return_value = ('result', None)
        self.assertEqual(('result', None), self.signature.eab_check(content, mac_key))

    @patch('acme_srv.signature.signature_check')
    def test_012_signature_eab_check(self, mock_sigchk):
        """ test eab_check  -  result false and  error """
        content = 'content'
        mac_key = 'mac_key'
        mock_sigchk.return_value = (False, 'error')
        self.assertEqual((False, 'error'), self.signature.eab_check(content, mac_key))

    @patch('acme_srv.signature.signature_check')
    def test_013_signature_eab_check(self, mock_sigchk):
        """ test eab_check  -  content None """
        content = None
        mac_key = 'mac_key'
        mock_sigchk.return_value = (False, 'error')
        self.assertEqual((False, None), self.signature.eab_check(content, mac_key))

    @patch('acme_srv.signature.signature_check')
    def test_014_signature_eab_check(self, mock_sigchk):
        """ test eab_check  -  mac_key None """
        content = 'content'
        mac_key = None
        mock_sigchk.return_value = (False, 'error')
        self.assertEqual((False, None), self.signature.eab_check(content, mac_key))

    @patch('acme_srv.signature.signature_check')
    def test_015_signature_eab_check(self, mock_sigchk):
        """ test eab_check  -  mac_key and content None """
        content = None
        mac_key = None
        mock_sigchk.return_value = (False, 'error')
        self.assertEqual((False, None), self.signature.eab_check(content, mac_key))

    @patch('acme_srv.signature.load_config')
    def test_016__init(self, mock_load_cfg):
        """ test _config_load account with url prefix without tailing slash configured """
        parser = configparser.ConfigParser()
        parser['Directory'] = {'foo': 'bar', 'url_prefix': 'url_prefix'}
        mock_load_cfg.return_value = parser
        self.signature.__init__(False, 'http://tester.local', self.logger)
        self.assertEqual('url_prefix/acme/revokecert', self.signature.revocation_path )

    @patch('acme_srv.signature.load_config')
    def test_017__init(self, mock_load_cfg):
        """ test _config_load account with url prefix without tailing slash configured """
        parser = configparser.ConfigParser()
        parser['Directory'] = {'foo': 'bar'}
        mock_load_cfg.return_value = parser
        self.signature.__init__(False, 'http://tester.local', self.logger)
        self.assertEqual('/acme/revokecert', self.signature.revocation_path )

    def test_018_signature__cli_jwk_load(self):
        """ test jwk load """
        self.signature.dbstore.cli_jwk_load.return_value = 'foo'
        self.assertEqual('foo', self.signature._cli_jwk_load(1))

    def test_019_signature__cli_jwk_load(self):
        """ test jwk load  - dbstore.jwk_load() raises an exception"""
        self.signature.dbstore.cli_jwk_load.side_effect = Exception('exc_sig_jw_load')
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.signature._cli_jwk_load(1)
        self.assertIn('CRITICAL:test_a2c:acme2certifier database error in Signature._cli_jwk_load(): exc_sig_jw_load', lcm.output)

    def test_020_signature_check(self):
        """ test Signature.cli_check() without having aname """
        self.assertEqual((False, 'urn:ietf:params:acme:error:accountDoesNotExist', None), self.signature.cli_check(None, 'content'))

    def test_021_signature_check(self):
        """ test Signature.check() without having content """
        self.assertEqual((False, 'urn:ietf:params:acme:error:malformed', None), self.signature.cli_check('foo', None))

    @patch('acme_srv.signature.Signature._cli_jwk_load')
    def test_022_signature_check(self, mock_jwk):
        """ test Signature.check() while pubkey lookup failed """
        mock_jwk.return_value = {}
        self.assertEqual((False, 'urn:ietf:params:acme:error:accountDoesNotExist', None), self.signature.cli_check('foo', 1))

    @patch('acme_srv.signature.signature_check')
    @patch('acme_srv.signature.Signature._cli_jwk_load')
    def test_023_signature_check(self, mock_jwk, mock_sig):
        """ test successful Signature.check()  """
        mock_jwk.return_value = {'foo' : 'bar'}
        mock_sig.return_value = (True, None)
        self.assertEqual((True, None, None), self.signature.cli_check('foo', 1))

    @patch('acme_srv.signature.signature_check')
    @patch('acme_srv.signature.Signature._cli_jwk_load')
    def test_024_signature_check(self, mock_jwk, mock_sig):
        """ test successful Signature.check() without account_name  sigcheck returns something"""
        mock_jwk.return_value = {'foo' : 'bar'}
        mock_sig.return_value = ('result', 'error')
        self.assertEqual(('result', 'error', None), self.signature.cli_check('foo', 1))


if __name__ == '__main__':
    unittest.main()
