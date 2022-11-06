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
        message = '{"foo" : "bar"}'
        self.assertEqual((403, 'urn:ietf:params:acme:error:accountDoesNotExist', None, 'protected', 'payload', None), self.message.check(message))

    @patch('acme_srv.signature.Signature.check')
    @patch('acme_srv.message.Message._name_get')
    @patch('acme_srv.nonce.Nonce.check')
    @patch('acme_srv.message.decode_message')
    def test_004_message_check(self, mock_decode, mock_nonce_check, mock_aname, mock_sig):
        """ message check failed bcs signature_check_failed """
        mock_decode.return_value = (True, None, 'protected', 'payload', 'signature')
        mock_nonce_check.return_value = (200, None, None)
        mock_aname.return_value = 'account_name'
        mock_sig.return_value = (False, 'error', 'detail')
        message = '{"foo" : "bar"}'
        self.assertEqual((403, 'error', 'detail', 'protected', 'payload', 'account_name'), self.message.check(message))

    @patch('acme_srv.signature.Signature.check')
    @patch('acme_srv.message.Message._name_get')
    @patch('acme_srv.nonce.Nonce.check')
    @patch('acme_srv.message.decode_message')
    def test_005_message_check(self, mock_decode, mock_nonce_check, mock_aname, mock_sig):
        """ message check successful """
        mock_decode.return_value = (True, None, 'protected', 'payload', 'signature')
        mock_nonce_check.return_value = (200, None, None)
        mock_aname.return_value = 'account_name'
        mock_sig.return_value = (True, None, None)
        message = '{"foo" : "bar"}'
        self.assertEqual((200, None, None, 'protected', 'payload', 'account_name'), self.message.check(message))

    @patch('acme_srv.signature.Signature.check')
    @patch('acme_srv.message.Message._name_get')
    @patch('acme_srv.nonce.Nonce.check')
    @patch('acme_srv.message.decode_message')
    def test_006_message_check(self, mock_decode, mock_nonce_check, mock_aname, mock_sig):
        """ message check successful as nonce check is disabled """
        mock_decode.return_value = (True, None, 'protected', 'payload', 'signature')
        mock_nonce_check.return_value = (400, 'badnonce', None)
        mock_aname.return_value = 'account_name'
        mock_sig.return_value = (True, None, None)
        message = '{"foo" : "bar"}'
        self.message.disable_dic = {'nonce_check_disable': True, 'signature_check_disable': False}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual((200, None, None, 'protected', 'payload', 'account_name'), self.message.check(message, skip_nonce_check=True))
        self.assertIn('ERROR:test_a2c:**** NONCE CHECK DISABLED!!! Severe security issue ****', lcm.output)

    @patch('acme_srv.signature.Signature.check')
    @patch('acme_srv.message.Message._name_get')
    @patch('acme_srv.nonce.Nonce.check')
    @patch('acme_srv.message.decode_message')
    def test_007_message_check(self, mock_decode, mock_nonce_check, mock_aname, mock_sig):
        """ message check successful as nonce check is disabled """
        mock_decode.return_value = (True, None, 'protected', 'payload', 'signature')
        mock_nonce_check.return_value = (400, 'badnonce', None)
        mock_aname.return_value = 'account_name'
        mock_sig.return_value = (True, None, None)
        message = '{"foo" : "bar"}'
        self.message.disable_dic = {'nonce_check_disable': True, 'signature_check_disable': True}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual((200, None, None, 'protected', 'payload', None), self.message.check(message, skip_nonce_check=True))
        self.assertIn('ERROR:test_a2c:**** SIGNATURE_CHECK_DISABLE!!! Severe security issue ****', lcm.output)
        self.assertIn('ERROR:test_a2c:**** NONCE CHECK DISABLED!!! Severe security issue ****', lcm.output)

    @patch('acme_srv.signature.Signature.check')
    @patch('acme_srv.message.Message._name_get')
    @patch('acme_srv.nonce.Nonce.check')
    @patch('acme_srv.message.decode_message')
    def test_008_message_check(self, mock_decode, mock_nonce_check, mock_aname, mock_sig):
        """ message check successful as nonce check is disabled """
        mock_decode.return_value = (True, None, 'protected', 'payload', 'signature')
        mock_nonce_check.return_value = (400, 'badnonce', None)
        mock_aname.return_value = 'account_name'
        mock_sig.return_value = (True, None, None)
        message = '{"foo" : "bar"}'
        self.message.disable_dic = {'nonce_check_disable': False, 'signature_check_disable': False}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual((200, None, None, 'protected', 'payload', 'account_name'), self.message.check(message, skip_nonce_check=True))
        self.assertIn('INFO:test_a2c:skip nonce check of inner payload during keyrollover', lcm.output)

    @patch('acme_srv.nonce.Nonce.generate_and_add')
    def test_009_message_prepare_response(self, mock_nnonce):
        """ Message.prepare_respons for code 200 and complete data """
        data_dic = {'data' : {'foo_data' : 'bar_bar'}, 'header': {'foo_header' : 'bar_header'}}
        mock_nnonce.return_value = 'new_nonce'
        config_dic = {'code' : 200, 'message' : 'message', 'detail' : 'detail'}
        self.assertEqual({'header': {'foo_header': 'bar_header', 'Replay-Nonce': 'new_nonce'}, 'code': 200, 'data': {'foo_data': 'bar_bar'}}, self.message.prepare_response(data_dic, config_dic))

    @patch('acme_srv.error.Error.enrich_error')
    @patch('acme_srv.nonce.Nonce.generate_and_add')
    def test_010_message_prepare_response(self, mock_nnonce, mock_error):
        """ Message.prepare_respons for code 200 without header tag in response_dic """
        data_dic = {'data' : {'foo_data' : 'bar_bar'},}
        mock_nnonce.return_value = 'new_nonce'
        mock_error.return_value = 'mock_error'
        config_dic = {'code' : 200, 'message' : 'message', 'detail' : 'detail'}
        self.assertEqual({'header': {'Replay-Nonce': 'new_nonce'}, 'code': 200, 'data': {'foo_data': 'bar_bar'}}, self.message.prepare_response(data_dic, config_dic))

    @patch('acme_srv.nonce.Nonce.generate_and_add')
    def test_011_message_prepare_response(self, mock_nnonce):
        """ Message.prepare_response for config_dic without code key """
        data_dic = {'data' : {'foo_data' : 'bar_bar'}, 'header': {'foo_header' : 'bar_header'}}
        mock_nnonce.return_value = 'new_nonce'
        # mock_error.return_value = 'mock_error'
        config_dic = {'message' : 'type', 'detail' : 'detail'}
        self.assertEqual({'header': {'foo_header': 'bar_header'}, 'code': 400, 'data': {'detail': 'http status code missing', 'type': 'urn:ietf:params:acme:error:serverInternal', 'status': 400}}, self.message.prepare_response(data_dic, config_dic))

    @patch('acme_srv.nonce.Nonce.generate_and_add')
    def test_012_message_prepare_response(self, mock_nnonce):
        """ Message.prepare_response for config_dic without message key """
        data_dic = {'data' : {'foo_data' : 'bar_bar'}, 'header': {'foo_header' : 'bar_header'}}
        mock_nnonce.return_value = 'new_nonce'
        # mock_error.return_value = 'mock_error'
        config_dic = {'code' : 400, 'detail' : 'detail'}
        self.assertEqual({'header': {'foo_header': 'bar_header'}, 'code': 400, 'data': {'detail': 'detail', 'type': 'urn:ietf:params:acme:error:serverInternal', 'status': 400}}, self.message.prepare_response(data_dic, config_dic))

    @patch('acme_srv.nonce.Nonce.generate_and_add')
    def test_013_message_prepare_response(self, mock_nnonce):
        """ Message.repare_response for config_dic without detail key """
        data_dic = {'data' : {'foo_data' : 'bar_bar'}, 'header': {'foo_header' : 'bar_header'}}
        mock_nnonce.return_value = 'new_nonce'
        config_dic = {'code' : 400, 'type': 'message'}
        self.assertEqual({'header': {'foo_header': 'bar_header'}, 'code': 400, 'data': {'type': 'message', 'status': 400}}, self.message.prepare_response(data_dic, config_dic))

    @patch('acme_srv.error.Error.enrich_error')
    @patch('acme_srv.nonce.Nonce.generate_and_add')
    def test_014_message_prepare_response(self, mock_nnonce, mock_error):
        """ Message.prepare_response for response_dic without data key """
        data_dic = {'header': {'foo_header' : 'bar_header'}}
        mock_nnonce.return_value = 'new_nonce'
        mock_error.return_value = 'mock_error'
        config_dic = {'code' : 400, 'type': 'message', 'detail' : 'detail'}
        self.assertEqual({'header': {'foo_header': 'bar_header'}, 'code': 400, 'data': {'detail': 'mock_error', 'type': 'message', 'status': 400}}, self.message.prepare_response(data_dic, config_dic))

    def test_015_message__name_get(self):
        """ test Message.name_get() with empty content"""
        protected = {}
        self.assertFalse(self.message._name_get(protected))

    def test_016_message__name_get(self):
        """ test Message.name_get() with kid with nonsens in content"""
        protected = {'kid' : 'foo'}
        self.assertEqual('foo', self.message._name_get(protected))

    def test_017_message__name_get(self):
        """ test Message.name_get() with wrong kid in content"""
        protected = {'kid' : 'http://tester.local/acme/account/account_name'}
        self.assertEqual(None, self.message._name_get(protected))

    def test_018_message__name_get(self):
        """ test Message.name_get() with correct kid in content"""
        protected = {'kid' : 'http://tester.local/acme/acct/account_name'}
        self.assertEqual('account_name', self.message._name_get(protected))

    def test_019_message__name_get(self):
        """ test Message.name_get() with 'jwk' in content but without URL"""
        protected = {'jwk' : 'jwk'}
        self.assertEqual(None, self.message._name_get(protected))

    def test_020_message__name_get(self):
        """ test Message.name_get() with 'jwk' and 'url' in content but url is wrong"""
        protected = {'jwk' : 'jwk', 'url' : 'url'}
        self.assertEqual(None, self.message._name_get(protected))

    def test_021_message__name_get(self):
        """ test Message.name_get() with 'jwk' and correct 'url' in content but no 'n' in jwk """
        protected = {'jwk' : 'jwk', 'url' : 'http://tester.local/acme/revokecert'}
        self.assertEqual(None, self.message._name_get(protected))

    def test_022_message__name_get(self):
        """ test Message.name_get() with 'jwk' and correct 'url' but account lookup failed """
        protected = {'jwk' : {'n' : 'n'}, 'url' : 'http://tester.local/acme/revokecert'}
        self.message.dbstore.account_lookup.return_value = {}
        self.assertEqual(None, self.message._name_get(protected))

    def test_023_message__name_get(self):
        """ test Message.name_get() with 'jwk' and correct 'url' and wrong account lookup data"""
        protected = {'jwk' : {'n' : 'n'}, 'url' : 'http://tester.local/acme/revokecert'}
        self.message.dbstore.account_lookup.return_value = {'bar' : 'foo'}
        self.assertEqual(None, self.message._name_get(protected))

    def test_024_message__name_get(self):
        """ test Message.name_get() with 'jwk' and correct 'url' and wrong account lookup data"""
        protected = {'jwk' : {'n' : 'n'}, 'url' : 'http://tester.local/acme/revokecert'}
        self.message.dbstore.account_lookup.return_value = {'name' : 'foo'}
        self.assertEqual('foo', self.message._name_get(protected))

    def test_025_message__name_get(self):
        """ test Message.name_get() - dbstore.account_lookup raises an exception """
        protected = {'jwk' : {'n' : 'n'}, 'url' : 'http://tester.local/acme/revokecert'}
        self.message.dbstore.account_lookup.side_effect = Exception('exc_mess__name_get')
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.message._name_get(protected)
        self.assertIn('CRITICAL:test_a2c:acme2certifier database error in Message._name_rev_get(): exc_mess__name_get', lcm.output)

    def test_026__enter__(self):
        """ test enter """
        self.message.__enter__()

    @patch('acme_srv.message.load_config')
    def test_027_config_load(self, mock_load_cfg):
        """ test _config_load empty config """
        parser = configparser.ConfigParser()
        # parser['Account'] = {'foo': 'bar'}
        mock_load_cfg.return_value = parser
        self.message._config_load()
        self.assertFalse(self.message.disable_dic['nonce_check_disable'])
        self.assertFalse(self.message.disable_dic['signature_check_disable'])

    @patch('acme_srv.message.load_config')
    def test_028_config_load(self, mock_load_cfg):
        """ test _config_load """
        parser = configparser.ConfigParser()
        parser['Nonce'] = {'nonce_check_disable': False, 'signature_check_disable': False}
        mock_load_cfg.return_value = parser
        self.message._config_load()
        self.assertFalse(self.message.disable_dic['nonce_check_disable'])
        self.assertFalse(self.message.disable_dic['signature_check_disable'])

    @patch('acme_srv.message.load_config')
    def test_029_config_load(self, mock_load_cfg):
        """ test _config_load """
        parser = configparser.ConfigParser()
        parser['Nonce'] = {'nonce_check_disable': True, 'signature_check_disable': False}
        mock_load_cfg.return_value = parser
        self.message._config_load()
        self.assertTrue(self.message.disable_dic['nonce_check_disable'])
        self.assertFalse(self.message.disable_dic['signature_check_disable'])

    @patch('acme_srv.message.load_config')
    def test_030_config_load(self, mock_load_cfg):
        """ test _config_load """
        parser = configparser.ConfigParser()
        parser['Nonce'] = {'nonce_check_disable': False, 'signature_check_disable': True}
        mock_load_cfg.return_value = parser
        self.message._config_load()
        self.assertFalse(self.message.disable_dic['nonce_check_disable'])
        self.assertTrue(self.message.disable_dic['signature_check_disable'])

    @patch('acme_srv.message.load_config')
    def test_031_config_load(self, mock_load_cfg):
        """ test _config_load """
        parser = configparser.ConfigParser()
        parser['Directory'] = {'url_prefix': 'url_prefix', 'foo': 'bar'}
        mock_load_cfg.return_value = parser
        self.message._config_load()
        self.assertFalse(self.message.disable_dic['nonce_check_disable'])
        self.assertFalse(self.message.disable_dic['signature_check_disable'])
        self.assertEqual({'acct_path': 'url_prefix/acme/acct/', 'revocation_path': 'url_prefix/acme/revokecert'}, self.message.path_dic)

    @patch('acme_srv.message.decode_message')
    def test_032_message_check(self, mock_decode):
        """ cli_check failed bcs of decoding error """
        message = '{"foo" : "bar"}'
        mock_decode.return_value = (False, 'detail', None, None, None)
        self.assertEqual((400, 'urn:ietf:params:acme:error:malformed', 'detail', None, None, None, {}), self.message.cli_check(message))

    @patch('acme_srv.signature.Signature.cli_check')
    @patch('acme_srv.message.Message._name_get')
    @patch('acme_srv.message.decode_message')
    def test_033_message_check(self, mock_decode, mock_name_get, mock_check):
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
    def test_034_message_check(self, mock_decode, mock_name_get, mock_check):
        """ message check failed bcs sig.cli_check() successful """
        mock_decode.return_value = (True, None, 'protected', 'payload', 'signature')
        mock_check.return_value = ('True', 'error', 'detail')
        self.message.dbstore.cli_permissions_get.return_value = {'foo' : 'bar'}
        mock_name_get.return_value = 'name'
        message = '{"foo" : "bar"}'
        self.assertEqual((200, None, None, 'protected', 'payload', 'name', {'foo': 'bar'}), self.message.cli_check(message))


if __name__ == '__main__':
    unittest.main()
