#!/usr/bin/python
# -*- coding: utf-8 -*-
""" unittests for account.py """
# pylint: disable=C0302, C0415, R0904, R0913, R0914, R0915, W0212
import unittest
import sys
import importlib
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
        from acme_srv.message import Message
        self.message = Message(False, 'http://tester.local', self.logger)

    @patch('acme_srv.message.decode_message')
    def test_001_message_check(self, mock_decode):
        """ message_check failed bcs of decoding error """
        message = '{"foo" : "bar"}'
        mock_decode.return_value = (False, 'detail', None, None, None)
        self.assertEqual((400, 'urn:ietf:params:acme:error:malformed', 'detail', None, None, None), self.message.check(message))

    @patch('acme_srv.nonce.Nonce.check')
    @patch('acme_srv.message.decode_message')
    def test_002_message_check(self, mock_decode, mock_nonce_check):
        """ message_check nonce check failed """
        message = '{"foo" : "bar"}'
        mock_decode.return_value = (True, None, 'protected', 'payload', 'signature')
        mock_nonce_check.return_value = (400, 'badnonce', None)
        self.assertEqual((400, 'badnonce', None, 'protected', 'payload', None), self.message.check(message))

    @patch('acme_srv.nonce.Nonce.check')
    @patch('acme_srv.message.decode_message')
    def test_003_message_check(self, mock_decode, mock_nonce_check):
        """ message check failed bcs account id lookup failed """
        mock_decode.return_value = (True, None, 'protected', 'payload', 'signature')
        mock_nonce_check.return_value = (200, None, None)
        self.message.eabkid_check_disable = True
        message = '{"foo" : "bar"}'
        self.assertEqual((403, 'urn:ietf:params:acme:error:accountDoesNotExist', None, 'protected', 'payload', None), self.message.check(message))

    @patch('acme_srv.message.Message._invalid_eab_check')
    @patch('acme_srv.signature.Signature.check')
    @patch('acme_srv.message.Message._name_get')
    @patch('acme_srv.nonce.Nonce.check')
    @patch('acme_srv.message.decode_message')
    def test_004_message_check(self, mock_decode, mock_nonce_check, mock_aname, mock_sig, mock_eabchk):
        """ message check failed bcs signature_check_failed """
        mock_decode.return_value = (True, None, 'protected', 'payload', 'signature')
        mock_nonce_check.return_value = (200, None, None)
        mock_aname.return_value = 'account_name'
        mock_eabchk.return_value = 'account_name'
        mock_sig.return_value = (False, 'error', 'detail')
        message = '{"foo" : "bar"}'
        self.assertEqual((403, 'error', 'detail', 'protected', 'payload', 'account_name'), self.message.check(message))

    @patch('acme_srv.message.Message._invalid_eab_check')
    @patch('acme_srv.signature.Signature.check')
    @patch('acme_srv.message.Message._name_get')
    @patch('acme_srv.nonce.Nonce.check')
    @patch('acme_srv.message.decode_message')
    def test_005_message_check(self, mock_decode, mock_nonce_check, mock_aname, mock_sig, mock_eabchk):
        """ message check failed bcs signature_check_failed """
        mock_decode.return_value = (True, None, 'protected', 'payload', 'signature')
        mock_nonce_check.return_value = (200, None, None)
        mock_aname.return_value = 'account_name'
        mock_eabchk.return_value = None
        mock_sig.return_value = (False, 'error', 'detail')
        message = '{"foo" : "bar"}'
        self.message.eabkid_check_disable = False
        self.assertEqual((403, 'urn:ietf:params:acme:error:unauthorized', 'invalid eab credentials', 'protected', 'payload', None), self.message.check(message))

    @patch('acme_srv.message.Message._invalid_eab_check')
    @patch('acme_srv.signature.Signature.check')
    @patch('acme_srv.message.Message._name_get')
    @patch('acme_srv.nonce.Nonce.check')
    @patch('acme_srv.message.decode_message')
    def test_006_message_check(self, mock_decode, mock_nonce_check, mock_aname, mock_sig, mock_eabchk):
        """ message check successful """
        mock_decode.return_value = (True, None, 'protected', 'payload', 'signature')
        mock_nonce_check.return_value = (200, None, None)
        mock_aname.return_value = 'account_name'
        mock_eabchk.return_value = 'account_name'
        mock_sig.return_value = (True, None, None)
        message = '{"foo" : "bar"}'
        self.assertEqual((200, None, None, 'protected', 'payload', 'account_name'), self.message.check(message))

    @patch('acme_srv.message.Message._invalid_eab_check')
    @patch('acme_srv.signature.Signature.check')
    @patch('acme_srv.message.Message._name_get')
    @patch('acme_srv.nonce.Nonce.check')
    @patch('acme_srv.message.decode_message')
    def test_007_message_check(self, mock_decode, mock_nonce_check, mock_aname, mock_sig, mock_eabchk):
        """ message check successful as nonce check is disabled """
        mock_decode.return_value = (True, None, 'protected', 'payload', 'signature')
        mock_nonce_check.return_value = (400, 'badnonce', None)
        mock_aname.return_value = 'account_name'
        mock_sig.return_value = (True, None, None)
        mock_eabchk.return_value = 'account_name'
        message = '{"foo" : "bar"}'
        self.message.disable_dic = {'nonce_check_disable': True, 'signature_check_disable': False}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual((200, None, None, 'protected', 'payload', 'account_name'), self.message.check(message, skip_nonce_check=True))
        self.assertIn('ERROR:test_a2c:**** NONCE CHECK DISABLED!!! Severe security issue ****', lcm.output)

    @patch('acme_srv.message.Message._invalid_eab_check')
    @patch('acme_srv.signature.Signature.check')
    @patch('acme_srv.message.Message._name_get')
    @patch('acme_srv.nonce.Nonce.check')
    @patch('acme_srv.message.decode_message')
    def test_008_message_check(self, mock_decode, mock_nonce_check, mock_aname, mock_sig, mock_eabchk):
        """ message check successful as nonce check is disabled """
        mock_decode.return_value = (True, None, 'protected', 'payload', 'signature')
        mock_nonce_check.return_value = (400, 'badnonce', None)
        mock_aname.return_value = 'account_name'
        mock_sig.return_value = (True, None, None)
        self.message.eabkid_check_disable = True
        message = '{"foo" : "bar"}'
        self.message.disable_dic = {'nonce_check_disable': True, 'signature_check_disable': True}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual((200, None, None, 'protected', 'payload', 'account_name'), self.message.check(message, skip_nonce_check=True))
        self.assertIn('ERROR:test_a2c:**** SIGNATURE_CHECK_DISABLE!!! Severe security issue ****', lcm.output)
        self.assertIn('ERROR:test_a2c:**** NONCE CHECK DISABLED!!! Severe security issue ****', lcm.output)
        self.assertFalse(mock_eabchk.called)

    @patch('acme_srv.message.Message._invalid_eab_check')
    @patch('acme_srv.signature.Signature.check')
    @patch('acme_srv.message.Message._name_get')
    @patch('acme_srv.nonce.Nonce.check')
    @patch('acme_srv.message.decode_message')
    def test_009_message_check(self, mock_decode, mock_nonce_check, mock_aname, mock_sig, mock_eab_chk):
        """ message check successful as nonce check is disabled """
        mock_decode.return_value = (True, None, 'protected', 'payload', 'signature')
        mock_nonce_check.return_value = (400, 'badnonce', None)
        mock_aname.return_value = 'account_name'
        mock_sig.return_value = (True, None, None)
        mock_eab_chk.return_value = 'account_name'
        message = '{"foo" : "bar"}'
        self.message.disable_dic = {'nonce_check_disable': False, 'signature_check_disable': False}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual((200, None, None, 'protected', 'payload', 'account_name'), self.message.check(message, skip_nonce_check=True))
        self.assertIn('INFO:test_a2c:skip nonce check of inner payload during keyrollover', lcm.output)

    @patch('acme_srv.nonce.Nonce.generate_and_add')
    def test_010_message_prepare_response(self, mock_nnonce):
        """ Message.prepare_respons for code 200 and complete data """
        data_dic = {'data' : {'foo_data' : 'bar_bar'}, 'header': {'foo_header' : 'bar_header'}}
        mock_nnonce.return_value = 'new_nonce'
        config_dic = {'code' : 200, 'message' : 'message', 'detail' : 'detail'}
        self.assertEqual({'header': {'foo_header': 'bar_header', 'Replay-Nonce': 'new_nonce'}, 'code': 200, 'data': {'foo_data': 'bar_bar'}}, self.message.prepare_response(data_dic, config_dic))

    @patch('acme_srv.error.Error.enrich_error')
    @patch('acme_srv.nonce.Nonce.generate_and_add')
    def test_011_message_prepare_response(self, mock_nnonce, mock_error):
        """ Message.prepare_respons for code 200 without header tag in response_dic """
        data_dic = {'data' : {'foo_data' : 'bar_bar'},}
        mock_nnonce.return_value = 'new_nonce'
        mock_error.return_value = 'mock_error'
        config_dic = {'code' : 200, 'message' : 'message', 'detail' : 'detail'}
        self.assertEqual({'header': {'Replay-Nonce': 'new_nonce'}, 'code': 200, 'data': {'foo_data': 'bar_bar'}}, self.message.prepare_response(data_dic, config_dic))

    @patch('acme_srv.nonce.Nonce.generate_and_add')
    def test_012_message_prepare_response(self, mock_nnonce):
        """ Message.prepare_response for config_dic without code key """
        data_dic = {'data' : {'foo_data' : 'bar_bar'}, 'header': {'foo_header' : 'bar_header'}}
        mock_nnonce.return_value = 'new_nonce'
        # mock_error.return_value = 'mock_error'
        config_dic = {'message' : 'type', 'detail' : 'detail'}
        self.assertEqual({'header': {'Replay-Nonce': 'new_nonce', 'foo_header': 'bar_header'}, 'code': 400, 'data': {'detail': 'http status code missing', 'type': 'urn:ietf:params:acme:error:serverInternal', 'status': 400}}, self.message.prepare_response(data_dic, config_dic))

    @patch('acme_srv.nonce.Nonce.generate_and_add')
    def test_013_message_prepare_response(self, mock_nnonce):
        """ Message.prepare_response for config_dic without message key """
        data_dic = {'data' : {'foo_data' : 'bar_bar'}, 'header': {'foo_header' : 'bar_header'}}
        mock_nnonce.return_value = 'new_nonce'
        # mock_error.return_value = 'mock_error'
        config_dic = {'code' : 400, 'detail' : 'detail'}
        self.assertEqual({'header': {'Replay-Nonce': 'new_nonce', 'foo_header': 'bar_header'}, 'code': 400, 'data': {'detail': 'detail', 'type': 'urn:ietf:params:acme:error:serverInternal', 'status': 400}}, self.message.prepare_response(data_dic, config_dic))

    @patch('acme_srv.nonce.Nonce.generate_and_add')
    def test_014_message_prepare_response(self, mock_nnonce):
        """ Message.repare_response for config_dic without detail key """
        data_dic = {'data' : {'foo_data' : 'bar_bar'}, 'header': {'foo_header' : 'bar_header'}}
        mock_nnonce.return_value = 'new_nonce'
        config_dic = {'code' : 400, 'type': 'message'}
        self.assertEqual({'header': {'Replay-Nonce': 'new_nonce', 'foo_header': 'bar_header'}, 'code': 400, 'data': {'type': 'message', 'status': 400}}, self.message.prepare_response(data_dic, config_dic))

    @patch('acme_srv.error.Error.enrich_error')
    @patch('acme_srv.nonce.Nonce.generate_and_add')
    def test_015_message_prepare_response(self, mock_nnonce, mock_error):
        """ Message.prepare_response for response_dic without data key """
        data_dic = {'header': {'foo_header' : 'bar_header'}}
        mock_nnonce.return_value = 'new_nonce'
        mock_error.return_value = 'mock_error'
        config_dic = {'code' : 400, 'type': 'message', 'detail' : 'detail'}
        self.assertEqual({'header': {'Replay-Nonce': 'new_nonce', 'foo_header': 'bar_header'}, 'code': 400, 'data': {'detail': 'mock_error', 'type': 'message', 'status': 400}}, self.message.prepare_response(data_dic, config_dic))

    def test_016_message__name_get(self):
        """ test Message.name_get() with empty content"""
        protected = {}
        self.assertFalse(self.message._name_get(protected))

    def test_017_message__name_get(self):
        """ test Message.name_get() with kid with nonsens in content"""
        protected = {'kid' : 'foo'}
        self.assertEqual('foo', self.message._name_get(protected))

    def test_018_message__name_get(self):
        """ test Message.name_get() with wrong kid in content"""
        protected = {'kid' : 'http://tester.local/acme/account/account_name'}
        self.assertEqual(None, self.message._name_get(protected))

    def test_019_message__name_get(self):
        """ test Message.name_get() with correct kid in content"""
        protected = {'kid' : 'http://tester.local/acme/acct/account_name'}
        self.assertEqual('account_name', self.message._name_get(protected))

    def test_020_message__name_get(self):
        """ test Message.name_get() with 'jwk' in content but without URL"""
        protected = {'jwk' : 'jwk'}
        self.assertEqual(None, self.message._name_get(protected))

    def test_021_message__name_get(self):
        """ test Message.name_get() with 'jwk' and 'url' in content but url is wrong"""
        protected = {'jwk' : 'jwk', 'url' : 'url'}
        self.assertEqual(None, self.message._name_get(protected))

    def test_022_message__name_get(self):
        """ test Message.name_get() with 'jwk' and correct 'url' in content but no 'n' in jwk """
        protected = {'jwk' : 'jwk', 'url' : 'http://tester.local/acme/revokecert'}
        self.assertEqual(None, self.message._name_get(protected))

    def test_023_message__name_get(self):
        """ test Message.name_get() with 'jwk' and correct 'url' but account lookup failed """
        protected = {'jwk' : {'n' : 'n'}, 'url' : 'http://tester.local/acme/revokecert'}
        self.message.dbstore.account_lookup.return_value = {}
        self.assertEqual(None, self.message._name_get(protected))

    def test_024_message__name_get(self):
        """ test Message.name_get() with 'jwk' and correct 'url' and wrong account lookup data"""
        protected = {'jwk' : {'n' : 'n'}, 'url' : 'http://tester.local/acme/revokecert'}
        self.message.dbstore.account_lookup.return_value = {'bar' : 'foo'}
        self.assertEqual(None, self.message._name_get(protected))

    def test_025_message__name_get(self):
        """ test Message.name_get() with 'jwk' and correct 'url' and wrong account lookup data"""
        protected = {'jwk' : {'n' : 'n'}, 'url' : 'http://tester.local/acme/revokecert'}
        self.message.dbstore.account_lookup.return_value = {'name' : 'foo'}
        self.assertEqual('foo', self.message._name_get(protected))

    def test_026_message__name_get(self):
        """ test Message.name_get() - dbstore.account_lookup raises an exception """
        protected = {'jwk' : {'n' : 'n'}, 'url' : 'http://tester.local/acme/revokecert'}
        self.message.dbstore.account_lookup.side_effect = Exception('exc_mess__name_get')
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.message._name_get(protected)
        self.assertIn('CRITICAL:test_a2c:acme2certifier database error in Message._name_rev_get(): exc_mess__name_get', lcm.output)

    def test_027__enter__(self):
        """ test enter """
        self.message.__enter__()

    @patch('acme_srv.message.load_config')
    def test_028_config_load(self, mock_load_cfg):
        """ test _config_load empty config """
        parser = configparser.ConfigParser()
        # parser['Account'] = {'foo': 'bar'}
        mock_load_cfg.return_value = parser
        self.message._config_load()
        self.assertFalse(self.message.disable_dic['nonce_check_disable'])
        self.assertFalse(self.message.disable_dic['signature_check_disable'])
        self.assertTrue(self.message.eabkid_check_disable)
        self.assertFalse(self.message.invalid_eabkid_deactivate)

    @patch('acme_srv.message.load_config')
    def test_029_config_load(self, mock_load_cfg):
        """ test _config_load """
        parser = configparser.ConfigParser()
        parser['Nonce'] = {'nonce_check_disable': False, 'signature_check_disable': False}
        mock_load_cfg.return_value = parser
        self.message._config_load()
        self.assertFalse(self.message.disable_dic['nonce_check_disable'])
        self.assertFalse(self.message.disable_dic['signature_check_disable'])
        self.assertTrue(self.message.eabkid_check_disable)
        self.assertFalse(self.message.invalid_eabkid_deactivate)

    @patch('acme_srv.message.load_config')
    def test_030_config_load(self, mock_load_cfg):
        """ test _config_load """
        parser = configparser.ConfigParser()
        parser['Nonce'] = {'nonce_check_disable': True, 'signature_check_disable': False}
        mock_load_cfg.return_value = parser
        self.message._config_load()
        self.assertTrue(self.message.disable_dic['nonce_check_disable'])
        self.assertFalse(self.message.disable_dic['signature_check_disable'])
        self.assertTrue(self.message.eabkid_check_disable)
        self.assertFalse(self.message.invalid_eabkid_deactivate)

    @patch('acme_srv.message.load_config')
    def test_031_config_load(self, mock_load_cfg):
        """ test _config_load """
        parser = configparser.ConfigParser()
        parser['Nonce'] = {'nonce_check_disable': False, 'signature_check_disable': True}
        mock_load_cfg.return_value = parser
        self.message._config_load()
        self.assertFalse(self.message.disable_dic['nonce_check_disable'])
        self.assertTrue(self.message.disable_dic['signature_check_disable'])
        self.assertTrue(self.message.eabkid_check_disable)
        self.assertFalse(self.message.invalid_eabkid_deactivate)

    @patch('acme_srv.message.load_config')
    def test_032_config_load(self, mock_load_cfg):
        """ test _config_load """
        parser = configparser.ConfigParser()
        parser['Directory'] = {'url_prefix': 'url_prefix', 'foo': 'bar'}
        mock_load_cfg.return_value = parser
        self.message._config_load()
        self.assertFalse(self.message.disable_dic['nonce_check_disable'])
        self.assertFalse(self.message.disable_dic['signature_check_disable'])
        self.assertEqual({'acct_path': 'url_prefix/acme/acct/', 'revocation_path': 'url_prefix/acme/revokecert'}, self.message.path_dic)
        self.assertTrue(self.message.eabkid_check_disable)
        self.assertFalse(self.message.invalid_eabkid_deactivate)

    @patch('acme_srv.message.eab_handler_load')
    @patch('acme_srv.message.load_config')
    def test_033_config_load(self, mock_load_cfg, mock_eab):
        """ test _config_load explicit false in cfg """
        parser = configparser.ConfigParser()
        parser['EABhandler'] = {'eab_handler_file': 'eab_handler_file', 'eabkid_check_disable': False}
        mock_load_cfg.return_value = parser
        mock_eab.return_value = MagicMock()
        from acme_srv.message import Message
        self.message = Message(False, 'http://tester.local', self.logger)
        # self.message._config_load()
        self.assertFalse(self.message.disable_dic['nonce_check_disable'])
        self.assertFalse(self.message.disable_dic['signature_check_disable'])
        self.assertFalse(self.message.eabkid_check_disable)
        self.assertTrue(mock_eab.called)
        self.assertFalse(self.message.invalid_eabkid_deactivate)

    @patch('acme_srv.message.eab_handler_load')
    @patch('acme_srv.message.load_config')
    def test_034_config_load(self, mock_load_cfg, mock_eab):
        """ test _config_load """
        parser = configparser.ConfigParser()
        parser['EABhandler'] = {'eab_handler_file': 'eab_handler_file', 'eabkid_check_disable': True}
        mock_load_cfg.return_value = parser
        self.message._config_load()
        self.assertFalse(self.message.disable_dic['nonce_check_disable'])
        self.assertFalse(self.message.disable_dic['signature_check_disable'])
        self.assertTrue(self.message.eabkid_check_disable)
        self.assertFalse(mock_eab.called)
        self.assertFalse(self.message.invalid_eabkid_deactivate)

    @patch('acme_srv.message.eab_handler_load')
    @patch('acme_srv.message.load_config')
    def test_035_config_load(self, mock_load_cfg, mock_eab):
        """ test _config_load """
        parser = configparser.ConfigParser()
        parser['EABhandler'] = {'foo': 'bar', 'eabkid_check_disable': True}
        mock_load_cfg.return_value = parser
        self.message._config_load()
        self.assertFalse(self.message.disable_dic['nonce_check_disable'])
        self.assertFalse(self.message.disable_dic['signature_check_disable'])
        self.assertTrue(self.message.eabkid_check_disable)
        self.assertFalse(mock_eab.called)
        self.assertFalse(self.message.invalid_eabkid_deactivate)

    @patch('acme_srv.message.eab_handler_load')
    @patch('acme_srv.message.load_config')
    def test_036_config_load(self, mock_load_cfg, mock_eab):
        """ test _config_load wrong eab handler config """
        parser = configparser.ConfigParser()
        parser['EABhandler'] = {'foo': 'bar', 'invalid_eabkid_deactivate': True}
        mock_load_cfg.return_value = parser
        mock_eab.return_value = None
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.message._config_load()
        self.assertIn('CRITICAL:test_a2c:Message._config_load(): EABHandler configuration incomplete', lcm.output)
        self.assertFalse(self.message.disable_dic['nonce_check_disable'])
        self.assertFalse(self.message.disable_dic['signature_check_disable'])
        self.assertTrue(self.message.eabkid_check_disable)
        self.assertFalse(mock_eab.called)
        self.assertFalse(self.message.invalid_eabkid_deactivate)


    @patch('acme_srv.message.eab_handler_load')
    @patch('acme_srv.message.load_config')
    def test_037_config_load(self, mock_load_cfg, mock_eab):
        """ test _config_load """
        parser = configparser.ConfigParser()
        parser['EABhandler'] = {'eab_handler_file': 'eab_handler_file', 'eabkid_check_disable': True}
        mock_load_cfg.return_value = parser
        mock_eab.return_value = None
        # with self.assertLogs('test_a2c', level='INFO') as lcm:
        self.message._config_load()
        # self.assertIn('CRITICAL:test_a2c:Account._config_load(): EABHandler could not get loaded', lcm.output)
        self.assertFalse(self.message.disable_dic['nonce_check_disable'])
        self.assertFalse(self.message.disable_dic['signature_check_disable'])
        self.assertTrue(self.message.eabkid_check_disable)
        self.assertFalse(mock_eab.called)
        self.assertFalse(self.message.invalid_eabkid_deactivate)

    @patch('acme_srv.message.eab_handler_load')
    @patch('acme_srv.message.load_config')
    def test_038_config_load(self, mock_load_cfg, mock_eab):
        """ test _config_load eab_load returned None"""
        parser = configparser.ConfigParser()
        parser['EABhandler'] = {'eab_handler_file': 'eab_handler_file'}
        mock_load_cfg.return_value = parser
        mock_eab.return_value = None
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.message._config_load()
        self.assertIn('CRITICAL:test_a2c:Message._config_load(): EABHandler could not get loaded', lcm.output)
        self.assertFalse(self.message.disable_dic['nonce_check_disable'])
        self.assertFalse(self.message.disable_dic['signature_check_disable'])
        self.assertTrue(self.message.eabkid_check_disable)
        self.assertTrue(mock_eab.called)
        self.assertFalse(self.message.invalid_eabkid_deactivate)

    @patch('acme_srv.message.eab_handler_load')
    @patch('acme_srv.message.load_config')
    def test_039_config_load(self, mock_load_cfg, mock_eab):
        """ test _config_load """
        parser = configparser.ConfigParser()
        parser['EABhandler'] = {'eab_handler_file': 'eab_handler_file', 'invalid_eabkid_deactivate': True}
        mock_load_cfg.return_value = parser
        mock_eab.return_value = MagicMock()
        # with self.assertLogs('test_a2c', level='INFO') as lcm:
        self.message._config_load()
        self.assertFalse(self.message.disable_dic['nonce_check_disable'])
        self.assertFalse(self.message.disable_dic['signature_check_disable'])
        self.assertTrue(self.message.eabkid_check_disable)
        self.assertTrue(mock_eab.called)
        self.assertTrue(self.message.invalid_eabkid_deactivate)

    @patch('acme_srv.message.eab_handler_load')
    @patch('acme_srv.message.load_config')
    def test_040_config_load(self, mock_load_cfg, mock_eab):
        """ test _config_load """
        parser = configparser.ConfigParser()
        parser['EABhandler'] = {'eab_handler_file': 'eab_handler_file', 'invalid_eabkid_deactivate': True, 'eabkid_check_disable': True}
        mock_load_cfg.return_value = parser
        mock_eab.return_value = None
        # with self.assertLogs('test_a2c', level='INFO') as lcm:
        self.message._config_load()
        # self.assertIn('CRITICAL:test_a2c:Account._config_load(): EABHandler could not get loaded', lcm.output)
        self.assertFalse(self.message.disable_dic['nonce_check_disable'])
        self.assertFalse(self.message.disable_dic['signature_check_disable'])
        self.assertTrue(self.message.eabkid_check_disable)
        self.assertFalse(mock_eab.called)
        self.assertFalse(self.message.invalid_eabkid_deactivate)

    @patch('acme_srv.message.decode_message')
    def test_041_message_check(self, mock_decode):
        """ cli_check failed bcs of decoding error """
        message = '{"foo" : "bar"}'
        mock_decode.return_value = (False, 'detail', None, None, None)
        self.assertEqual((400, 'urn:ietf:params:acme:error:malformed', 'detail', None, None, None, {}), self.message.cli_check(message))

    @patch('acme_srv.signature.Signature.cli_check')
    @patch('acme_srv.message.Message._name_get')
    @patch('acme_srv.message.decode_message')
    def test_042_message_check(self, mock_decode, mock_name_get, mock_check):
        """ message check failed bcs sig.cli_check() failed """
        mock_decode.return_value = (True, None, 'protected', 'payload', 'signature')
        mock_check.return_value = (False, 'error', 'detail')
        mock_name_get.return_value = 'name'
        message = '{"foo" : "bar"}'
        self.assertEqual((403, 'error', 'detail', 'protected', 'payload', 'name', {}), self.message.cli_check(message))
        self.assertFalse(self.message.dbstore.cli_permissions_get.called)

    @patch('acme_srv.signature.Signature.cli_check')
    @patch('acme_srv.message.Message._name_get')
    @patch('acme_srv.message.decode_message')
    def test_043_message_check(self, mock_decode, mock_name_get, mock_check):
        """ message check failed bcs sig.cli_check() successful """
        mock_decode.return_value = (True, None, 'protected', 'payload', 'signature')
        mock_check.return_value = ('True', 'error', 'detail')
        self.message.dbstore.cli_permissions_get.return_value = {'foo' : 'bar'}
        mock_name_get.return_value = 'name'
        message = '{"foo" : "bar"}'
        self.assertEqual((200, None, None, 'protected', 'payload', 'name', {'foo': 'bar'}), self.message.cli_check(message))

    def test_044_invalid_eab_check(self):
        """ test _invalid_eab_check - ok """
        self.message.dbstore.account_lookup.side_effect = None
        self.message.dbstore.account_lookup.return_value = {'eab_kid': 'eab_kid'}
        eab_handler_module = importlib.import_module('examples.eab_handler.skeleton_eab_handler')
        self.message.eab_handler = eab_handler_module.EABhandler
        self.message.eab_handler.mac_key_get = MagicMock(return_value='mac_key')
        self.assertEqual('account_name', self.message._invalid_eab_check('account_name'))

    def test_045_invalid_eab_check(self):
        """ test _invalid_eab_check - ok """
        self.message.dbstore.account_lookup.side_effect = None
        self.message.dbstore.account_lookup.return_value = {'eab_kid': 'eab_kid'}
        eab_handler_module = importlib.import_module('examples.eab_handler.skeleton_eab_handler')
        self.message.eab_handler = eab_handler_module.EABhandler
        self.message.eab_handler.mac_key_get = MagicMock(return_value=None)
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertFalse(self.message._invalid_eab_check('account_name'))
        self.assertIn('ERROR:test_a2c:EAB credentials: eab_kid could not be found in eab-credential store.', lcm.output)

    def test_046_invalid_eab_check(self):
        """ test _invalid_eab_check - ok """
        self.message.dbstore.account_lookup.side_effect = None
        self.message.dbstore.account_lookup.return_value = {'eab_kid': 'eab_kid'}
        eab_handler_module = importlib.import_module('examples.eab_handler.skeleton_eab_handler')
        self.message.eab_handler = eab_handler_module.EABhandler
        self.message.eab_handler.mac_key_get = MagicMock(return_value=None)
        self.message.invalid_eabkid_deactivate = True
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertFalse(self.message._invalid_eab_check('account_name'))
        self.assertIn('ERROR:test_a2c:EAB credentials: eab_kid could not be found in eab-credential store.', lcm.output)
        self.assertIn('ERROR:test_a2c:Account account_name will be deactivated due to missing eab credentials', lcm.output)
        self.assertTrue(self.message.dbstore.account_update.called)

    def test_047_invalid_eab_check(self):
        """ test _invalid_eab_check - ok """
        self.message.dbstore.account_lookup.side_effect = None
        self.message.dbstore.account_lookup.return_value = {'foo': 'bar'}
        eab_handler_module = importlib.import_module('examples.eab_handler.skeleton_eab_handler')
        self.message.eab_handler = eab_handler_module.EABhandler
        self.message.eab_handler.mac_key_get = MagicMock(return_value=None)
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertFalse(self.message._invalid_eab_check('account_name'))
        self.assertIn('ERROR:test_a2c:Account account_name has no eab credentials', lcm.output)

    def test_048_invalid_eab_check(self):
        """ test _invalid_eab_check - ok """
        self.message.dbstore.account_lookup.side_effect = None
        self.message.dbstore.account_lookup.return_value = None
        eab_handler_module = importlib.import_module('examples.eab_handler.skeleton_eab_handler')
        self.message.eab_handler = eab_handler_module.EABhandler
        self.message.eab_handler.mac_key_get = MagicMock(return_value=None)
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertFalse(self.message._invalid_eab_check('account_name'))
        self.assertIn('ERROR:test_a2c:Account lookup for  account_name failed.', lcm.output)

if __name__ == '__main__':
    unittest.main()
