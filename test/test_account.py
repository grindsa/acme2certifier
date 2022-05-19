#!/usr/bin/python
# -*- coding: utf-8 -*-
""" unittests for account.py """
# pylint: disable=C0302, C0415, R0904, R0913, R0914, R0915, W0212
import unittest
import importlib
import configparser
import sys
from unittest.mock import patch, MagicMock, Mock

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
        from acme_srv.account import Account
        from acme_srv.nonce import Nonce
        from acme_srv.signature import Signature
        self.account = Account(False, 'http://tester.local', self.logger)
        self.nonce = Nonce(False, self.logger)
        self.signature = Signature(False, 'http://tester.local', self.logger)

    def test_001_account__tos_check(self):
        """ test successful tos check """
        self.assertEqual((200, None, None), self.account._tos_check({'termsofserviceagreed': True}))

    def test_002_account__tos_check(self):
        """ test successful tos check """
        self.assertEqual((403, 'urn:ietf:params:acme:error:userActionRequired', 'tosfalse'), self.account._tos_check({'termsofserviceagreed': False}))

    def test_003_account__tos_check(self):
        """ test successful tos check """
        self.assertEqual((403, 'urn:ietf:params:acme:error:userActionRequired', 'tosfalse'), self.account._tos_check({'foo': 'bar'}))

    def test_004_account__contact_check(self):
        """ test successful tos check """
        self.assertEqual((200, None, None), self.account._contact_check({'contact': ['mailto: foo@example.com']}))

    def test_005_account__contact_check(self):
        """ test successful tos check """
        self.assertEqual((400, 'urn:ietf:params:acme:error:invalidContact', 'mailto: bar@exa,mple.com'), self.account._contact_check({'contact': ['mailto: bar@exa,mple.com']}))

    def test_006_account__contact_check(self):
        """ test successful tos check """
        self.assertEqual((400, 'urn:ietf:params:acme:error:invalidContact', 'no contacts specified'), self.account._contact_check({'foo': 'bar'}))

    @patch('acme_srv.account.generate_random_string')
    def test_007_account__add(self, mock_name):
        """ test successful account add for a new account"""
        self.account.dbstore.account_add.return_value = (2, True)
        mock_name.return_value = 'randowm_string'
        content = {'alg': 'RS256', 'jwk': {'e': u'AQAB', 'kty': u'RSA', 'n': u'foo'}, 'nonce': u'bar', 'url': u'acme_srv.srv/acme/newaccount'}
        payload = 'payload'
        self.assertEqual((201, 'randowm_string', None), self.account._add(content, payload, 'foo@example.com'))

    @patch('acme_srv.account.generate_random_string')
    def test_008_account__add(self, mock_name):
        """ test successful account add for a new account"""
        self.account.dbstore.account_add.return_value = ('foo', False)
        mock_name.return_value = 'randowm_string'
        content = {'alg': 'RS256', 'jwk': {'e': u'AQAB', 'kty': u'RSA', 'n': u'foo'}, 'nonce': u'bar', 'url': u'acme_srv.srv/acme/newaccount'}
        payload = 'payload'
        self.assertEqual((200, 'foo', None), self.account._add(content, payload, 'foo@example.com'))

    def test_009_account__add(self):
        """ test account add without ALG """
        content = {'foo': 'bar', 'jwk': {'e': u'AQAB', 'kty': u'RSA', 'n': u'foo'}, 'nonce': u'bar', 'url': u'acme_srv.srv/acme/newaccount'}
        payload = 'payload'
        self.assertEqual((400, 'urn:ietf:params:acme:error:malformed', 'incomplete protected payload'), self.account._add(content, payload, ['me@example.com']))

    def test_010_account__add(self):
        """ test account add without jwk """
        content = {'alg': 'RS256', 'foo': {'foo': u'bar'}, 'nonce': u'bar', 'url': u'acme_srv.srv/acme/newaccount'}
        payload = 'payload'
        self.assertEqual((400, 'urn:ietf:params:acme:error:malformed', 'incomplete protected payload'), self.account._add(content, payload, ['me@example.com']))

    def test_011_account__add(self):
        """ test account add without contact """
        self.account.tos_check_disable = False
        self.account.contact_check_disable = False
        content = {'alg': 'RS256', 'jwk': {'e': u'AQAB', 'kty': u'RSA', 'n': u'foo'}, 'nonce': u'bar', 'url': u'acme_srv.srv/acme/newaccount'}
        payload = 'payload'
        self.assertEqual((400, 'urn:ietf:params:acme:error:malformed', 'incomplete protected payload'), self.account._add(content, payload, None))

    def test_012_account__name_get(self):
        """ test successfull get_id """
        string = {'kid' : 'http://tester.local/acme/acct/foo'}
        self.assertEqual('foo', self.account._name_get(string))

    def test_013_account__name_get(self):
        """ test failed get_id bcs of suffix """
        string = 'http://tester.local/acme/acct/bar/foo'
        self.assertFalse(self.account._name_get(string))

    def test_014_account__name_get(self):
        """ test failed get_id bcs wrong servername """
        string = {'kid' : 'http://test.local/acme/acct/foo'}
        self.assertFalse(self.account._name_get(string))

    def test_015_account__name_get(self):
        """ test failed get_id bcs of wrong path """
        string = {'kid' : 'http://tester.local/acct/foo'}
        self.assertFalse(self.account._name_get(string))

    @patch('acme_srv.message.Message.check')
    def test_016_account_new(self, mock_mcheck):
        """ Account.new() failed bcs. of failed message check """
        mock_mcheck.return_value = (400, 'message', 'detail', None, None, None)
        message = '{"foo" : "bar"}'
        self.assertEqual({'header': {}, 'code': 400, 'data': {'detail': 'detail', 'type': 'message', 'status': 400}}, self.account.new(message))

    @patch('acme_srv.account.Account._tos_check')
    @patch('acme_srv.message.Message.check')
    def test_017_account_new(self, mock_mcheck, mock_tos):
        """ Account.new() failed bcs failed tos check """
        mock_mcheck.return_value = (200, None, None, 'protected', 'payload', None)
        mock_tos.return_value = (403, 'urn:ietf:params:acme:error:userActionRequired', 'tosfalse')
        message = {'foo' : 'bar'}
        self.account.tos_url = 'foo'
        e_result = {'code': 403, 'data': {'detail': 'Terms of service must be accepted', 'type': 'urn:ietf:params:acme:error:userActionRequired', 'status': 403}, 'header': {}}
        self.assertEqual(e_result, self.account.new(message))

    @patch('acme_srv.account.Account._contact_check')
    @patch('acme_srv.account.Account._tos_check')
    @patch('acme_srv.message.Message.check')
    def test_018_account_new(self, mock_mcheck, mock_tos, mock_contact):
        """ Account.new() failed bcs failed contact check """
        mock_mcheck.return_value = (200, None, None, 'protected', 'payload', None)
        mock_tos.return_value = (200, None, None)
        mock_contact.return_value = (400, 'urn:ietf:params:acme:error:invalidContact', 'no contacts specified')
        message = {'foo' : 'bar'}
        e_result = {'code': 400, 'data': {'detail': 'The provided contact URI was invalid: no contacts specified', 'type': 'urn:ietf:params:acme:error:invalidContact', 'status': 400}, 'header': {}}
        self.assertEqual(e_result, self.account.new(message))

    @patch('acme_srv.account.Account._add')
    @patch('acme_srv.account.Account._contact_check')
    @patch('acme_srv.account.Account._tos_check')
    @patch('acme_srv.message.Message.check')
    def test_019_account_new(self, mock_mcheck, mock_tos, mock_contact, mock_aad):
        """ Account.new() failed bcs of failed add """
        mock_mcheck.return_value = (200, None, None, 'protected', {'contact' : 'foo@bar.com'}, None)
        mock_tos.return_value = (200, None, None)
        mock_contact.return_value = (200, None, None)
        mock_aad.return_value = (400, 'urn:ietf:params:acme:error:malformed', 'incomplete JSON Web Key')
        message = {'foo' : 'bar'}
        e_result = {'code': 400, 'data': {'detail': 'incomplete JSON Web Key', 'type': 'urn:ietf:params:acme:error:malformed', 'status': 400}, 'header': {}}
        self.assertEqual(e_result, self.account.new(message))

    @patch('acme_srv.nonce.Nonce.generate_and_add')
    @patch('acme_srv.account.Account._add')
    @patch('acme_srv.account.Account._contact_check')
    @patch('acme_srv.account.Account._tos_check')
    @patch('acme_srv.message.Message.check')
    def test_020_account_new(self, mock_mcheck, mock_tos, mock_contact, mock_aad, mock_nnonce):
        """ Account.new() successful for a new account"""
        mock_mcheck.return_value = (200, None, None, 'protected', {'contact' : [u'mailto: foo@bar.com']}, None)
        mock_tos.return_value = (200, None, None)
        mock_contact.return_value = (200, None, None)
        mock_aad.return_value = (201, 1, None)
        mock_nnonce.return_value = 'new_nonce'
        message = {'foo' : 'bar'}
        e_result = {'code': 201, 'data': {'contact': [u'mailto: foo@bar.com'], 'orders': 'http://tester.local/acme/acct/1/orders', 'status': 'valid'}, 'header': {'Location': 'http://tester.local/acme/acct/1', 'Replay-Nonce': 'new_nonce'}}
        self.assertEqual(e_result, self.account.new(message))

    @patch('acme_srv.nonce.Nonce.generate_and_add')
    @patch('acme_srv.account.Account._add')
    @patch('acme_srv.account.Account._contact_check')
    @patch('acme_srv.account.Account._tos_check')
    @patch('acme_srv.message.Message.check')
    def test_021_account_new(self, mock_mcheck, mock_tos, mock_contact, mock_aad, mock_nnonce):
        """ Account.new() successful for an existing account"""
        mock_mcheck.return_value = (200, None, None, 'protected', {'contact' : [u'mailto: foo@bar.com']}, None)
        mock_tos.return_value = (200, None, None)
        mock_contact.return_value = (200, None, None)
        mock_aad.return_value = (200, 1, None)
        mock_nnonce.return_value = 'new_nonce'
        message = {'foo' : 'bar'}
        e_result = {'code': 200, 'data': {}, 'header': {'Location': 'http://tester.local/acme/acct/1', 'Replay-Nonce': 'new_nonce'}}
        self.assertEqual(e_result, self.account.new(message))

    @patch('acme_srv.account.Account._onlyreturnexisting')
    @patch('acme_srv.message.Message.check')
    def test_022_account_new(self, mock_mcheck, mock_existing):
        """ Account.new() onlyReturnExisting for a non existing account """
        mock_mcheck.return_value = (200, None, None, 'protected', {"onlyreturnexisting": 'true'}, None)
        mock_existing.return_value = (400, 'urn:ietf:params:acme:error:accountDoesNotExist', None)
        message = {'foo': 'bar'}
        e_result = {'code': 400, 'data': {'type': 'urn:ietf:params:acme:error:accountDoesNotExist', 'status': 400}, 'header': {}}
        self.assertEqual(e_result, self.account.new(message))

    @patch('acme_srv.nonce.Nonce.generate_and_add')
    @patch('acme_srv.account.Account._onlyreturnexisting')
    @patch('acme_srv.message.Message.check')
    def test_023_account_new(self, mock_mcheck, mock_existing, mock_nnonce):
        """ Account.new() onlyReturnExisting for an existing account """
        mock_mcheck.return_value = (200, None, None, 'protected', {"onlyreturnexisting": 'true'}, None)
        mock_existing.return_value = (200, 100, None)
        mock_nnonce.return_value = 'new_nonce'
        message = {'foo' : 'bar'}
        e_result = {'code': 200, 'data': {}, 'header': {'Location': 'http://tester.local/acme/acct/100', 'Replay-Nonce': 'new_nonce'}}
        self.assertEqual(e_result, self.account.new(message))

    @patch('acme_srv.account.Account._eab_check')
    @patch('acme_srv.nonce.Nonce.generate_and_add')
    @patch('acme_srv.account.Account._add')
    @patch('acme_srv.account.Account._contact_check')
    @patch('acme_srv.account.Account._tos_check')
    @patch('acme_srv.message.Message.check')
    def test_024_account_new(self, mock_mcheck, mock_tos, mock_contact, mock_aad, mock_nnonce, mock_eab):
        """ Account.new() successful for an existing account and eab """
        mock_mcheck.return_value = (200, None, None, 'protected', {'contact' : [u'mailto: foo@bar.com'], 'externalaccountbinding': 'eab'}, None)
        mock_tos.return_value = (200, None, None)
        mock_contact.return_value = (200, None, None)
        mock_aad.return_value = (200, 1, None)
        mock_nnonce.return_value = 'new_nonce'
        mock_eab.return_value = (200, None, None)
        self.account.eab_check = True
        message = {'foo' : 'bar'}
        e_result = {'code': 200, 'data': {'externalaccountbinding': 'eab'}, 'header': {'Location': 'http://tester.local/acme/acct/1', 'Replay-Nonce': 'new_nonce'}}
        self.assertEqual(e_result, self.account.new(message))

    @patch('acme_srv.account.Account._eab_check')
    @patch('acme_srv.nonce.Nonce.generate_and_add')
    @patch('acme_srv.account.Account._add')
    @patch('acme_srv.account.Account._contact_check')
    @patch('acme_srv.account.Account._tos_check')
    @patch('acme_srv.message.Message.check')
    def test_025_account_new(self, mock_mcheck, mock_tos, mock_contact, mock_aad, mock_nnonce, mock_eab):
        """ Account.new() successful for a new account and eab """
        mock_mcheck.return_value = (200, None, None, 'protected', {'contact' : [u'mailto: foo@bar.com'], 'externalaccountbinding': 'eab'}, None)
        mock_tos.return_value = (200, None, None)
        mock_contact.return_value = (200, None, None)
        mock_aad.return_value = (201, 1, None)
        mock_nnonce.return_value = 'new_nonce'
        mock_eab.return_value = (200, None, None)
        self.account.eab_check = True
        message = {'foo' : 'bar'}
        e_result = {'code': 201, 'data': {'externalaccountbinding': 'eab', 'contact': [u'mailto: foo@bar.com'], 'orders': 'http://tester.local/acme/acct/1/orders', 'status': 'valid'}, 'header': {'Location': 'http://tester.local/acme/acct/1', 'Replay-Nonce': 'new_nonce'}}
        self.assertEqual(e_result, self.account.new(message))

    def test_026_account__name_get(self):
        """ test failed get_id bcs of wrong data """
        string = {'foo' : 'bar'}
        self.assertFalse(self.account._name_get(string))

    @patch('acme_srv.message.Message.check')
    def test_027_account_parse(self, mock_mcheck):
        """ Account.parse() failed bcs. of failed message check """
        mock_mcheck.return_value = (400, 'message', 'detail', None, None, 'account_name')
        message = '{"foo" : "bar"}'
        self.assertEqual({'header': {}, 'code': 400, 'data': {'detail': 'detail', 'type': 'message', 'status': 400}}, self.account.parse(message))

    @patch('acme_srv.message.Message.check')
    def test_028_account_parse(self, mock_mcheck):
        """ test failed account parse for request which does not has a "status" field in payload """
        mock_mcheck.return_value = (200, None, None, 'protected', {"foo" : "bar"}, 'account_name')
        message = '{"foo" : "bar"}'
        self.assertEqual({'header': {}, 'code': 400, 'data': {'status': 400, 'type': 'urn:ietf:params:acme:error:malformed', 'detail': 'dont know what to do with this request'}}, self.account.parse(message))

    @patch('acme_srv.message.Message.check')
    def test_029_account_parse(self, mock_mcheck):
        """ test failed account parse for reqeust with a "status" field other than "deactivated" """
        mock_mcheck.return_value = (200, None, None, 'protected', {"status" : "foo"}, 'account_name')
        message = '{"foo" : "bar"}'
        self.assertEqual({'header': {}, 'code': 400, 'data': {'status': 400, 'type': 'urn:ietf:params:acme:error:malformed', 'detail': 'status attribute without sense'}}, self.account.parse(message))

    @patch('acme_srv.account.Account._delete')
    @patch('acme_srv.message.Message.check')
    def test_030_account_parse(self, mock_mcheck, mock_del):
        """ test failed account parse for reqeust with failed deletion """
        mock_mcheck.return_value = (200, None, None, 'protected', {"status" : "deactivated"}, 'account_name')
        mock_del.return_value = (400, 'urn:ietf:params:acme:error:accountDoesNotExist', 'deletion failed')
        message = '{"foo" : "bar"}'
        self.assertEqual({'header': {}, 'code': 400, 'data': {'status': 400, 'type': 'urn:ietf:params:acme:error:accountDoesNotExist', 'detail': 'deletion failed'}}, self.account.parse(message))

    @patch('acme_srv.nonce.Nonce.generate_and_add')
    @patch('acme_srv.account.Account._delete')
    @patch('acme_srv.message.Message.check')
    def test_031_account_parse(self, mock_mcheck, mock_del, mock_nnonce):
        """ test succ account parse for reqeust with succ deletion """
        mock_mcheck.return_value = (200, None, None, 'protected', {"status" : "deactivated"}, 'account_name')
        mock_del.return_value = (200, None, None)
        mock_nnonce.return_value = 'new_nonce'
        message = '{"foo" : "bar"}'
        self.assertEqual({'code': 200, 'data': {'status': 'deactivated'}, 'header': {'Replay-Nonce': 'new_nonce'}}, self.account.parse(message))

    @patch('acme_srv.account.Account._key_change')
    @patch('acme_srv.nonce.Nonce.generate_and_add')
    @patch('acme_srv.account.Account._delete')
    @patch('acme_srv.message.Message.check')
    def test_032_account_parse(self, mock_mcheck, mock_del, mock_nnonce, mock_keychange):
        """ test succ account parse for key-change (unsuccessful) """
        mock_mcheck.return_value = (200, None, None, 'protected', {"payload" : "foo"}, 'account_name')
        mock_del.return_value = (200, None, None)
        mock_nnonce.return_value = 'new_nonce'
        mock_keychange.return_value = (400, 'message', 'detail')
        message = '{"foo" : "bar"}'
        self.assertEqual({'code': 400, 'data': {'detail': 'detail', 'type': 'message', 'status': 400}, 'header': {}}, self.account.parse(message))

    @patch('acme_srv.account.Account._key_change')
    @patch('acme_srv.nonce.Nonce.generate_and_add')
    @patch('acme_srv.account.Account._delete')
    @patch('acme_srv.message.Message.check')
    def test_033_account_parse(self, mock_mcheck, mock_del, mock_nnonce, mock_keychange):
        """ test succ account parse for key-change (successful) """
        mock_mcheck.return_value = (200, None, None, 'protected', {"payload" : "foo"}, 'account_name')
        mock_del.return_value = (200, None, None)
        mock_nnonce.return_value = 'new_nonce'
        mock_keychange.return_value = (200, None, None)
        message = '{"foo" : "bar"}'
        self.assertEqual({'code': 200, 'data': {}, 'header': {'Replay-Nonce': 'new_nonce'}}, self.account.parse(message))

    @patch('acme_srv.account.Account._contacts_update')
    @patch('acme_srv.message.Message.check')
    def test_034_account_parse(self, mock_mcheck, mock_contact_upd):
        """ test failed account parse for contacts update as contact updated failed """
        mock_mcheck.return_value = (200, None, None, 'protected', {"contact" : "deactivated"}, 'account_name')
        mock_contact_upd.return_value = (400, 'message', 'detail')
        message = 'message'
        self.assertEqual({'code': 400, 'data': {'detail': 'update failed', 'type': 'urn:ietf:params:acme:error:accountDoesNotExist', 'status': 400}, 'header': {}}, self.account.parse(message))

    @patch('acme_srv.account.Account._info')
    @patch('acme_srv.nonce.Nonce.generate_and_add')
    @patch('acme_srv.account.Account._lookup')
    @patch('acme_srv.account.Account._contacts_update')
    @patch('acme_srv.message.Message.check')
    def test_035_account_parse(self, mock_mcheck, mock_contact_upd, mock_account_lookup, mock_nnonce, mock_info):
        """ test succ account parse for request with succ contacts update """
        mock_mcheck.return_value = (200, None, None, 'protected', {"contact" : "deactivated"}, 'account_name')
        mock_contact_upd.return_value = (200, None, None)
        mock_nnonce.return_value = 'new_nonce'
        mock_account_lookup.return_value = 'mock_account_lookup'
        mock_info.return_value = 'mock_info'
        message = 'message'
        self.assertEqual({'code': 200, 'data': 'mock_info', 'header': {'Replay-Nonce': 'new_nonce'}}, self.account.parse(message))

    @patch('acme_srv.account.Account._info')
    @patch('acme_srv.nonce.Nonce.generate_and_add')
    @patch('acme_srv.account.Account._lookup')
    @patch('acme_srv.message.Message.check')
    def test_036_account_parse(self, mock_mcheck, mock_account_lookup, mock_nnonce, mock_info):
        """ test succ account parse for request for account info """
        mock_mcheck.return_value = (200, None, None, 'protected', {}, 'account_name')
        mock_nnonce.return_value = 'new_nonce'
        mock_account_lookup.return_value = 'mock_account_lookup'
        mock_info.return_value = {'foo': 'bar'}
        message = 'message'
        self.assertEqual({'code': 200, 'data': {'foo': 'bar', 'status': 'valid'}, 'header': {'Replay-Nonce': 'new_nonce'}}, self.account.parse(message))
        self.assertTrue(mock_info.called)

    @patch('acme_srv.account.Account._info')
    @patch('acme_srv.nonce.Nonce.generate_and_add')
    @patch('acme_srv.account.Account._lookup')
    @patch('acme_srv.message.Message.check')
    def test_037_account_parse(self, mock_mcheck, mock_account_lookup, mock_nnonce, mock_info):
        """ test succ account parse for request for account info """
        mock_mcheck.return_value = (200, None, None, 'protected', {}, 'account_name')
        mock_nnonce.return_value = 'new_nonce'
        mock_account_lookup.return_value = None
        mock_info.return_value = {'foo': 'bar'}
        message = 'message'
        self.assertEqual({'code': 200, 'data': {'status': 'invalid'}, 'header': {'Replay-Nonce': 'new_nonce'}}, self.account.parse(message))
        self.assertFalse(mock_info.called)

    def test_038_account__onlyreturnexisting(self):
        """ test onlyReturnExisting with False """
        # self.signature.dbstore.jwk_load.return_value = 1
        protected = {}
        payload = {'onlyreturnexisting' : False}
        self.assertEqual((400, 'urn:ietf:params:acme:error:userActionRequired', 'onlyReturnExisting must be true'), self.account._onlyreturnexisting(protected, payload))

    def test_039_account__onlyreturnexisting(self):
        """ test onlyReturnExisting without jwk structure """
        # self.signature.dbstore.jwk_load.return_value = 1
        protected = {}
        payload = {'onlyreturnexisting' : True}
        self.assertEqual((400, 'urn:ietf:params:acme:error:malformed', 'jwk structure missing'), self.account._onlyreturnexisting(protected, payload))

    def test_040_account__onlyreturnexisting(self):
        """ test onlyReturnExisting fucntion without onlyReturnExisting structure """
        # self.signature.dbstore.jwk_load.return_value = 1
        protected = {}
        payload = {}
        self.assertEqual((500, 'urn:ietf:params:acme:error:serverInternal', 'onlyReturnExisting without payload'), self.account._onlyreturnexisting(protected, payload))

    def test_041_account__onlyreturnexisting(self):
        """ test onlyReturnExisting for existing account """
        self.signature.dbstore.account_lookup.return_value = {'name' : 'foo', 'alg' : 'RS256'}
        protected = {'jwk' : {'n' : 'foo'}}
        payload = {'onlyreturnexisting' : True}
        self.assertEqual((200, 'foo', None), self.account._onlyreturnexisting(protected, payload))

    def test_042_account__onlyreturnexisting(self):
        """ test onlyReturnExisting for non existing account """
        self.signature.dbstore.account_lookup.return_value = False
        protected = {'jwk' : {'n' : 'foo'}}
        payload = {'onlyreturnexisting' : True}
        self.assertEqual((400, 'urn:ietf:params:acme:error:accountDoesNotExist', None), self.account._onlyreturnexisting(protected, payload))

    @patch('acme_srv.account.Account._contact_check')
    def test_043_account__contacts_update(self, mock_contact_chk,):
        """ Account.contact_update() failed contact_check failed """
        mock_contact_chk.return_value = (400, 'message', 'detail')
        payload = '{"foo" : "bar"}'
        aname = 'aname'
        self.assertEqual((400, 'message', 'detail'), self.account._contacts_update(aname, payload))

    @patch('acme_srv.account.Account._contact_check')
    def test_044_account__contacts_update(self, mock_contact_chk,):
        """ Account.contact_update() failed bcs account update failed """
        mock_contact_chk.return_value = (200, 'message', 'detail')
        self.account.dbstore.account_update.return_value = None
        payload = {"contact" : "foo"}
        aname = 'aname'
        self.assertEqual((400, 'urn:ietf:params:acme:error:accountDoesNotExist', 'update failed'), self.account._contacts_update(aname, payload))

    @patch('acme_srv.account.Account._contact_check')
    def test_045_account__contacts_update(self, mock_contact_chk,):
        """ Account.contact_update() succ """
        mock_contact_chk.return_value = (200, 'message', 'detail')
        self.account.dbstore.account_update.return_value = 'foo'
        payload = {"contact" : "foo"}
        aname = 'aname'
        self.assertEqual((200, 'message', 'detail'), self.account._contacts_update(aname, payload))

    def test_046_account__key_compare(self):
        """ Account.key_compare() with two empty dictionaries"""
        self.account.dbstore.jwk_load.return_value = {}
        aname = 'foo'
        okey = {}
        self.assertEqual((401, 'urn:ietf:params:acme:error:unauthorized', 'wrong public key'), self.account._key_compare(aname, okey))

    def test_047_account__key_compare(self):
        """ Account.key_compare() with empty pub_key and existing old_key"""
        self.account.dbstore.jwk_load.return_value = {}
        aname = 'foo'
        okey = {'foo': 'bar'}
        self.assertEqual((401, 'urn:ietf:params:acme:error:unauthorized', 'wrong public key'), self.account._key_compare(aname, okey))

    def test_048_account__key_compare(self):
        """ Account.key_compare() with existing pub_key and empty old_key"""
        self.account.dbstore.jwk_load.return_value = {'foo': 'bar'}
        aname = 'foo'
        okey = {}
        self.assertEqual((401, 'urn:ietf:params:acme:error:unauthorized', 'wrong public key'), self.account._key_compare(aname, okey))

    def test_049_account__key_compare(self):
        """ Account.key_compare() with similar pub_key empty old_key"""
        self.account.dbstore.jwk_load.return_value = {'foo1': 'bar1', 'foo2': 'bar2', 'foo3': None}
        aname = 'foo'
        okey = {'foo1': 'bar1', 'foo2': 'bar2', 'foo3': None}
        self.assertEqual((200, None, None), self.account._key_compare(aname, okey))

    def test_050_account__key_compare(self):
        """ Account.key_compare() with similar pub_key empty old_key but different order"""
        self.account.dbstore.jwk_load.return_value = {'foo1': 'bar1', 'foo2': 'bar2', 'foo3': None}
        aname = 'foo'
        okey = {'foo3': None, 'foo2': 'bar2', 'foo1': 'bar1'}
        self.assertEqual((200, None, None), self.account._key_compare(aname, okey))

    def test_051_account__key_compare(self):
        """ Account.key_compare() pub_key alg rewrite"""
        self.account.dbstore.jwk_load.return_value = {'foo1': 'bar1', 'foo2': 'bar2', 'alg': 'ESfoo'}
        aname = 'foo'
        okey = {'alg': 'ECDSA', 'foo2': 'bar2', 'foo1': 'bar1'}
        self.assertEqual((200, None, None), self.account._key_compare(aname, okey))

    def test_052_account__key_compare(self):
        """ Account.key_compare() pub_key failed alg rewrite"""
        self.account.dbstore.jwk_load.return_value = {'foo1': 'bar1', 'foo2': 'bar2', 'alg': 'foo'}
        aname = 'foo'
        okey = {'alg': 'ECDSA', 'foo2': 'bar2', 'foo1': 'bar1'}
        self.assertEqual((401, 'urn:ietf:params:acme:error:unauthorized', 'wrong public key'), self.account._key_compare(aname, okey))

    def test_053_account__key_compare(self):
        """ Account.key_compare() pub_key failed alg rewrite"""
        self.account.dbstore.jwk_load.return_value = {'foo1': 'bar1', 'foo2': 'bar2', 'alg': 'ESfoo'}
        aname = 'foo'
        okey = {'alg': 'rsa', 'foo2': 'bar2', 'foo1': 'bar1'}
        self.assertEqual((401, 'urn:ietf:params:acme:error:unauthorized', 'wrong public key'), self.account._key_compare(aname, okey))

    def test_054_account__key_compare(self):
        """ Account.key_compare() pub_key failed alg rewrite no alg statement in old_key"""
        self.account.dbstore.jwk_load.return_value = {'foo1': 'bar1', 'foo2': 'bar2', 'alg': 'ESfoo'}
        aname = 'foo'
        okey = {'foo3': None, 'foo2': 'bar2', 'foo1': 'bar1'}
        self.assertEqual((401, 'urn:ietf:params:acme:error:unauthorized', 'wrong public key'), self.account._key_compare(aname, okey))

    def test_055_account__key_compare(self):
        """ Account.key_compare() pub_key failed alg rewrite no alg statement in pub_key"""
        self.account.dbstore.jwk_load.return_value = {'foo1': 'bar1', 'foo2': 'bar2', 'foo3': 'bar3'}
        aname = 'foo'
        okey = {'alg': 'ECDSA', 'foo2': 'bar2', 'foo1': 'bar1'}
        self.assertEqual((401, 'urn:ietf:params:acme:error:unauthorized', 'wrong public key'), self.account._key_compare(aname, okey))

    def test_056_account__inner_jws_check(self):
        """ Account.inner_jws_check() no jwk in inner header"""
        outer = {}
        inner = {'foo': 'bar'}
        self.assertEqual((400, 'urn:ietf:params:acme:error:malformed', 'inner jws is missing jwk'), self.account._inner_jws_check(outer, inner))

    def test_057_account__inner_jws_check(self):
        """ Account.inner_jws_check() no url in inner header """
        outer = {'url' : 'url'}
        inner = {'jwk': 'jwk'}
        self.assertEqual((400, 'urn:ietf:params:acme:error:malformed', 'inner or outer jws is missing url header parameter'), self.account._inner_jws_check(outer, inner))

    def test_058_account__inner_jws_check(self):
        """ Account.inner_jws_check() no url in outer header """
        outer = {'foo' : 'bar'}
        inner = {'jwk': 'jwk', 'url': 'url'}
        self.assertEqual((400, 'urn:ietf:params:acme:error:malformed', 'inner or outer jws is missing url header parameter'), self.account._inner_jws_check(outer, inner))

    def test_059_account__inner_jws_check(self):
        """ Account.inner_jws_check() different url string in inner and outer header """
        outer = {'url' : 'url_'}
        inner = {'jwk': 'jwk', 'url': 'url'}
        self.assertEqual((400, 'urn:ietf:params:acme:error:malformed', 'url parameter differ in inner and outer jws'), self.account._inner_jws_check(outer, inner))

    def test_060_account__inner_jws_check(self):
        """ Account.inner_jws_check() same url string in inner and outer header """
        outer = {'url' : 'url'}
        inner = {'jwk': 'jwk', 'url': 'url'}
        self.assertEqual((200, None, None), self.account._inner_jws_check(outer, inner))

    def test_061_account__inner_jws_check(self):
        """ Account.inner_jws_check() nonce in inner header """
        outer = {'url' : 'url'}
        inner = {'jwk': 'jwk', 'url': 'url', 'nonce': 'nonce'}
        self.assertEqual((400, 'urn:ietf:params:acme:error:malformed', 'inner jws must omit nonce header'), self.account._inner_jws_check(outer, inner))

    def test_062_account__inner_jws_check(self):
        """ Account.inner_jws_check() nonce in inner header and inner_header_nonce_allow True """
        outer = {'url' : 'url'}
        inner = {'jwk': 'jwk', 'url': 'url', 'nonce': 'nonce'}
        self.account.inner_header_nonce_allow = True
        self.assertEqual((200, None, None), self.account._inner_jws_check(outer, inner))

    def test_063_account__inner_payload_check(self):
        """ Account.inner_payload_check() without kid in outer protected """
        outer_protected = {}
        inner_payload = {}
        self.assertEqual((400, 'urn:ietf:params:acme:error:malformed', 'kid is missing in outer header'), self.account._inner_payload_check('aname', outer_protected, inner_payload))

    def test_064_account__inner_payload_check(self):
        """ Account.inner_payload_check() with kid in outer protected but without account object in inner_payload """
        outer_protected = {'kid': 'kid'}
        inner_payload = {}
        self.assertEqual((400, 'urn:ietf:params:acme:error:malformed', 'account object is missing on inner payload'), self.account._inner_payload_check('aname', outer_protected, inner_payload))

    def test_065_account__inner_payload_check(self):
        """ Account.inner_payload_check() with different kid and account values """
        outer_protected = {'kid': 'kid'}
        inner_payload = {'account': 'account'}
        self.assertEqual((400, 'urn:ietf:params:acme:error:malformed', 'kid and account objects do not match'), self.account._inner_payload_check('aname', outer_protected, inner_payload))

    def test_066_account__inner_payload_check(self):
        """ Account.inner_payload_check() with same kid and account values but no old_key"""
        outer_protected = {'kid': 'kid'}
        inner_payload = {'account': 'kid'}
        self.assertEqual((400, 'urn:ietf:params:acme:error:malformed', 'old key is missing'), self.account._inner_payload_check('aname', outer_protected, inner_payload))

    @patch('acme_srv.account.Account._key_compare')
    def test_067_account__inner_payload_check(self, mock_cmp):
        """ Account.inner_payload_check() with same kid and account values but no old_key"""
        outer_protected = {'kid': 'kid'}
        inner_payload = {'account': 'kid', 'oldkey': 'oldkey'}
        mock_cmp.return_value = ('code', 'message', 'detail')
        self.assertEqual(('code', 'message', 'detail'), self.account._inner_payload_check('aname', outer_protected, inner_payload))

    def test_068_account__key_change_validate(self):
        """ Account.key_change_validate() without JWK in inner_protected """
        inner_protected = {}
        self.assertEqual((400, 'urn:ietf:params:acme:error:malformed', 'inner jws is missing jwk'), self.account._key_change_validate('aname', {}, inner_protected, {}))

    @patch('acme_srv.account.Account._lookup')
    def test_069_account__key_change_validate(self, mock_lup):
        """ Account.key_change_validate() for existing key """
        inner_protected = {'jwk': 'jwk'}
        mock_lup.return_value = True
        self.assertEqual((400, 'urn:ietf:params:acme:error:badPublicKey', 'public key does already exists'), self.account._key_change_validate('aname', {}, inner_protected, {}))

    @patch('acme_srv.account.Account._inner_jws_check')
    @patch('acme_srv.account.Account._lookup')
    def test_070_account__key_change_validate(self, mock_lup, mock_jws_chk):
        """ Account.key_change_validate() inner_jws_check returns 400 """
        inner_protected = {'jwk': 'jwk'}
        mock_lup.return_value = False
        mock_jws_chk.return_value = (400, 'message1', 'detail1')
        self.assertEqual((400, 'message1', 'detail1'), self.account._key_change_validate('aname', {}, inner_protected, {}))

    @patch('acme_srv.account.Account._inner_payload_check')
    @patch('acme_srv.account.Account._inner_jws_check')
    @patch('acme_srv.account.Account._lookup')
    def test_071_account__key_change_validate(self, mock_lup, mock_jws_chk, mock_pl_chk):
        """ Account.key_change_validate() inner_jws_check returns 200 """
        inner_protected = {'jwk': 'jwk'}
        mock_lup.return_value = False
        mock_jws_chk.return_value = (200, 'message1', 'detail1')
        mock_pl_chk.return_value = ('code2', 'message2', 'detail2')
        self.assertEqual(('code2', 'message2', 'detail2'), self.account._key_change_validate('aname', {}, inner_protected, {}))

    def test_072_account__key_change(self):
        """ Account.key_change() without URL in protected """
        protected = {}
        self.assertEqual((400, 'urn:ietf:params:acme:error:malformed', 'malformed request'), self.account._key_change('aname', {}, protected))

    def test_073_account__key_change(self):
        """ Account.key_change() with URL in protected without key-change in url"""
        protected = {'url': 'url'}
        self.assertEqual((400, 'urn:ietf:params:acme:error:malformed', 'malformed request. not a key-change'), self.account._key_change('aname', {}, protected))

    @patch('acme_srv.message.Message.check')
    def test_074_account__key_change(self, mock_mcheck):
        """ Account.key_change() message.check() returns non-200"""
        protected = {'url': 'url/key-change'}
        mock_mcheck.return_value = ('code1', 'message1', 'detail1', 'prot', 'payload', 'aname')
        self.assertEqual(('code1', 'message1', 'detail1'), self.account._key_change('aname', {}, protected))

    @patch('acme_srv.account.Account._key_change_validate')
    @patch('acme_srv.message.Message.check')
    def test_075_account__key_change(self, mock_mcheck, moch_kchval):
        """ Account.key_change() with URL in protected without key-change in url"""
        protected = {'url': 'url/key-change'}
        mock_mcheck.return_value = (200, 'message1', 'detail1', 'prot', 'payload', 'aname')
        moch_kchval.return_value = ('code2', 'message2', 'detail2')
        self.assertEqual(('code2', 'message2', 'detail2'), self.account._key_change('aname', {}, protected))

    @patch('acme_srv.account.Account._key_change_validate')
    @patch('acme_srv.message.Message.check')
    def test_076_account__key_change(self, mock_mcheck, moch_kchval):
        """ Account.key_change() - account_update returns nothing"""
        protected = {'url': 'url/key-change'}
        mock_mcheck.return_value = (200, 'message1', 'detail1', {'jwk': {'h1': 'h1a', 'h2': 'h2a', 'h3': 'h3a'}}, 'payload', 'aname')
        moch_kchval.return_value = (200, 'message2', 'detail2')
        self.account.dbstore.account_update.return_value = None
        self.assertEqual((500, 'urn:ietf:params:acme:error:serverInternal', 'key rollover failed'), self.account._key_change('aname', {}, protected))

    @patch('acme_srv.account.Account._key_change_validate')
    @patch('acme_srv.message.Message.check')
    def test_077_account__key_change(self, mock_mcheck, moch_kchval):
        """ Account.key_change() - account_update returns nothing"""
        protected = {'url': 'url/key-change'}
        mock_mcheck.return_value = (200, 'message1', 'detail1', {'jwk': {'h1': 'h1a', 'h2': 'h2a', 'h3': 'h3a'}}, 'payload', 'aname')
        moch_kchval.return_value = (200, 'message2', 'detail2')
        self.account.dbstore.account_update.return_value = True
        self.assertEqual((200, None, None), self.account._key_change('aname', {}, protected))

    @patch('acme_srv.account.generate_random_string')
    def test_078_account__add(self, mock_name):
        """ test failed account add due to ecc mandated """
        # self.account.dbstore.account_add.return_value = (2, True)
        self.account.ecc_only = True
        mock_name.return_value = 'randowm_string'
        content = {'alg': 'RS256', 'jwk': {'e': u'AQAB', 'kty': u'RSA', 'n': u'foo'}, 'nonce': u'bar', 'url': u'acme_srv.srv/acme/newaccount'}
        payload = 'payload'
        self.assertEqual((403, 'urn:ietf:params:acme:error:badPublicKey', 'Only ECC keys are supported'), self.account._add(content, payload, 'foo@example.com'))

    @patch('acme_srv.account.generate_random_string')
    def test_079_account__add(self, mock_name):
        """ test successful account add for a new account"""
        self.account.dbstore.account_add.return_value = (2, True)
        self.account.ecc_only = True
        mock_name.return_value = 'randowm_string'
        content = {'alg': 'ES256', 'jwk': {'e': u'AQAB', 'kty': u'RSA', 'n': u'foo'}, 'nonce': u'bar', 'url': u'acme_srv.srv/acme/newaccount'}
        payload = 'payload'
        self.assertEqual((201, 'randowm_string', None), self.account._add(content, payload, 'foo@example.com'))

    @patch('acme_srv.account.generate_random_string')
    def test_080_account__add(self, mock_name):
        """ test account add without contact """
        self.account.contact_check_disable = True
        self.account.dbstore.account_add.return_value = ('foo', False)
        mock_name.return_value = 'randowm_string'
        content = {'alg': 'RS256', 'jwk': {'e': u'AQAB', 'kty': u'RSA', 'n': u'foo'}, 'nonce': u'bar', 'url': u'acme_srv.srv/acme/newaccount'}
        payload = 'payload'
        self.assertEqual((200, 'foo', None), self.account._add(content, payload, None))

    @patch('acme_srv.account.generate_random_string')
    def test_081__account__add(self, mock_name):
        """ test successful account add with eab_check False"""
        self.account.dbstore.account_add.return_value = (2, True)
        self.account.ecc_only = True
        mock_name.return_value = 'randowm_string'
        content = {'alg': 'ES256', 'jwk': {'e': u'AQAB', 'kty': u'RSA', 'n': u'foo'}, 'nonce': u'bar', 'url': u'acme_srv.srv/acme/newaccount'}
        self.account.eab_check = False
        payload = 'payload'
        self.assertEqual((201, 'randowm_string', None), self.account._add(content, payload, 'foo@example.com'))

    @patch('acme_srv.account.generate_random_string')
    def test_082__account__add(self, mock_name):
        """ test successful account add with eab_check True but no binding information - should never happen"""
        self.account.dbstore.account_add.return_value = (2, True)
        self.account.ecc_only = True
        mock_name.return_value = 'randowm_string'
        content = {'alg': 'ES256', 'jwk': {'e': u'AQAB', 'kty': u'RSA', 'n': u'foo'}, 'nonce': u'bar', 'url': u'acme_srv.srv/acme/newaccount'}
        self.account.eab_check = True
        payload = {'foo': 'bar'}
        self.assertEqual((201, 'randowm_string', None), self.account._add(content, payload, 'foo@example.com'))

    @patch('acme_srv.account.Account._eab_kid_get')
    @patch('acme_srv.account.generate_random_string')
    def test_083__account__add(self, mock_name, mock_eabkid):
        """ test successful account add with eab_check True but binding information """
        self.account.dbstore.account_add.return_value = (2, True)
        self.account.ecc_only = True
        mock_name.return_value = 'randowm_string'
        content = {'alg': 'ES256', 'jwk': {'e': u'AQAB', 'kty': u'RSA', 'n': u'foo'}, 'nonce': u'bar', 'url': u'acme_srv.srv/acme/newaccount'}
        self.account.eab_check = True
        payload = {'externalaccountbinding': {'protected': 'foo'}}
        mock_eabkid.return_value = 'eab_kid'
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual((201, 'randowm_string', None), self.account._add(content, payload, 'foo@example.com'))
        self.assertIn('INFO:test_a2c:add eab_kid: eab_kid to data_dic', lcm.output)

    @patch('acme_srv.message.Message.check')
    def test_084_account_new(self, mock_mcheck):
        """ Account.new() tos required"""
        mock_mcheck.return_value = (200, None, None, 'protected', {'contact' : [u'mailto: foo@bar.com']}, None)
        self.account.tos_check_disable = False
        self.account.tos_url = 'foo'
        message = {'foo' : 'bar'}
        e_result = {'code': 403, 'data': {'detail': 'Terms of service must be accepted', 'type': 'urn:ietf:params:acme:error:userActionRequired', 'status': 403}, 'header': {}}
        self.assertEqual(e_result, self.account.new(message))

    @patch('acme_srv.nonce.Nonce.generate_and_add')
    @patch('acme_srv.account.Account._add')
    @patch('acme_srv.account.Account._contact_check')
    @patch('acme_srv.message.Message.check')
    def test_085_account_new(self, mock_mcheck, mock_contact, mock_aad, mock_nnonce):
        """ Account.new() successful tos disabled no tos url configured"""
        mock_mcheck.return_value = (200, None, None, 'protected', {'contact' : [u'mailto: foo@bar.com']}, None)
        self.account.tos_check_disable = True
        mock_contact.return_value = (200, None, None)
        mock_aad.return_value = (200, 1, None)
        mock_nnonce.return_value = 'new_nonce'
        message = {'foo' : 'bar'}
        e_result = {'code': 200, 'data': {}, 'header': {'Location': 'http://tester.local/acme/acct/1', 'Replay-Nonce': 'new_nonce'}}
        self.assertEqual(e_result, self.account.new(message))

    @patch('acme_srv.nonce.Nonce.generate_and_add')
    @patch('acme_srv.account.Account._add')
    @patch('acme_srv.account.Account._contact_check')
    @patch('acme_srv.message.Message.check')
    def test_086_account_new(self, mock_mcheck, mock_contact, mock_aad, mock_nnonce):
        """ Account.new() successful tos disabled tos url configured"""
        mock_mcheck.return_value = (200, None, None, 'protected', {'contact' : [u'mailto: foo@bar.com']}, None)
        self.account.tos_check_disable = True
        self.account.tos_url = 'foo'
        mock_contact.return_value = (200, None, None)
        mock_aad.return_value = (200, 1, None)
        mock_nnonce.return_value = 'new_nonce'
        message = {'foo' : 'bar'}
        e_result = {'code': 200, 'data': {}, 'header': {'Location': 'http://tester.local/acme/acct/1', 'Replay-Nonce': 'new_nonce'}}
        self.assertEqual(e_result, self.account.new(message))

    @patch('acme_srv.nonce.Nonce.generate_and_add')
    @patch('acme_srv.account.Account._add')
    @patch('acme_srv.message.Message.check')
    def test_087_account_new(self, mock_mcheck, mock_aad, mock_nnonce):
        """ Account.new() successful tos/email checks_disabled"""
        mock_mcheck.return_value = (200, None, None, 'protected', {}, None)
        self.account.tos_check_disable = True
        self.account.contact_check_disable = True
        mock_aad.return_value = (200, 1, None)
        mock_nnonce.return_value = 'new_nonce'
        message = {'foo' : 'bar'}
        e_result = {'code': 200, 'data': {}, 'header': {'Location': 'http://tester.local/acme/acct/1', 'Replay-Nonce': 'new_nonce'}}
        self.assertEqual(e_result, self.account.new(message))

    @patch('acme_srv.account.Account._tos_check')
    @patch('acme_srv.nonce.Nonce.generate_and_add')
    @patch('acme_srv.account.Account._add')
    @patch('acme_srv.message.Message.check')
    def test_088_account_new(self, mock_mcheck, mock_aad, mock_nnonce, mock_tos):
        """ Account.new() successful email checks_disabled"""
        mock_mcheck.return_value = (200, None, None, 'protected', {}, None)
        self.account.contact_check_disable = True
        mock_tos.return_value = (200, None, None)
        mock_aad.return_value = (200, 1, None)
        mock_nnonce.return_value = 'new_nonce'
        message = {'foo' : 'bar'}
        e_result = {'code': 200, 'data': {}, 'header': {'Location': 'http://tester.local/acme/acct/1', 'Replay-Nonce': 'new_nonce'}}
        self.assertEqual(e_result, self.account.new(message))

    @patch('acme_srv.account.Account._eab_check')
    @patch('acme_srv.account.Account._tos_check')
    @patch('acme_srv.nonce.Nonce.generate_and_add')
    @patch('acme_srv.account.Account._add')
    @patch('acme_srv.message.Message.check')
    def test_089_account_new(self, mock_mcheck, mock_aad, mock_nnonce, mock_tos, mock_eab):
        """ Account.new() successful eab check retured error """
        mock_mcheck.return_value = (200, None, None, 'protected', {}, None)
        self.account.contact_check_disable = True
        self.account.eab_check = True
        mock_tos.return_value = (200, None, None)
        mock_aad.return_value = (200, 1, None)
        mock_nnonce.return_value = 'new_nonce'
        mock_eab.return_value = (400, 'message', 'detail')
        message = {'foo' : 'bar'}
        e_result = {'code': 400, 'data': {'detail': 'detail', 'type': 'message', 'status': 400}, 'header': {}}
        self.assertEqual(e_result, self.account.new(message))

    @patch('acme_srv.account.Account._eab_check')
    @patch('acme_srv.account.Account._tos_check')
    @patch('acme_srv.nonce.Nonce.generate_and_add')
    @patch('acme_srv.account.Account._add')
    @patch('acme_srv.message.Message.check')
    def test_090_account_new(self, mock_mcheck, mock_aad, mock_nnonce, mock_tos, mock_eab):
        """ Account.new() successful """
        mock_mcheck.return_value = (200, None, None, 'protected', {}, None)
        self.account.contact_check_disable = True
        self.account.eab_check = True
        mock_tos.return_value = (200, None, None)
        mock_aad.return_value = (200, 1, None)
        mock_nnonce.return_value = 'new_nonce'
        mock_eab.return_value = (200, None, None)
        message = {'foo' : 'bar'}
        e_result = {'code': 200, 'data': {}, 'header': {'Location': 'http://tester.local/acme/acct/1', 'Replay-Nonce': 'new_nonce'}}
        self.assertEqual(e_result, self.account.new(message))

    @patch('acme_srv.message.Message.check')
    def test_091_account_new(self, mock_mcheck):
        """ Account.new() tos check skipped as no tos """
        mock_mcheck.return_value = (200, None, None, 'protected', 'payload', None)
        message = {'foo' : 'bar'}
        e_result = {'code': 400, 'data': {'detail': 'The provided contact URI was invalid: no contacts specified', 'type': 'urn:ietf:params:acme:error:invalidContact', 'status': 400}, 'header': {}}
        self.assertEqual(e_result, self.account.new(message))

    def test_092_account__lookup(self):
        """ test Account._lookup() if dbstore.account_lookup raises an exception """
        self.account.dbstore.account_lookup.side_effect = Exception('exc_acc_lookup')
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.account._lookup('foo')
        self.assertIn('CRITICAL:test_a2c:acme2certifier database error in Account._lookup(): exc_acc_lookup', lcm.output)

    def test_093_account__onlyreturnexisting(self):
        """ test Account._onlyreturnexisting() if dbstore.account_lookup raises an exception """
        self.account.dbstore.account_lookup.side_effect = Exception('exc_acc_returnexit')
        protected = {'jwk' : {'n' : 'foo'}}
        payload = {'onlyreturnexisting' : True}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.account._onlyreturnexisting(protected, payload)
        self.assertIn('CRITICAL:test_a2c:acme2certifier database error in Account._onlyreturnexisting(): exc_acc_returnexit', lcm.output)
        self.account.dbstore.account_lookup.side_effect = None

    def test_094_account__key_compare(self):
        """ test Account._key_compare() if dbstore.jwk_load raises an exception """
        self.account.dbstore.jwk_load.side_effect = Exception('exc_key_compare')
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.account._key_compare('foo', 'bar')
        self.assertIn('CRITICAL:test_a2c:acme2certifier database error in Account._key_compare(): exc_key_compare', lcm.output)
        self.account.dbstore.jwk_load.side_effect = None

    @patch('acme_srv.account.Account._key_change_validate')
    @patch('acme_srv.message.Message.check')
    def test_095_account__key_change(self, mock_mcheck, moch_kchval):
        """ Account.key_change() - if dbstore.account_update raises an exception"""
        protected = {'url': 'url/key-change'}
        mock_mcheck.return_value = (200, 'message1', 'detail1', {'jwk': {'h1': 'h1a', 'h2': 'h2a', 'h3': 'h3a'}}, 'payload', 'aname')
        moch_kchval.return_value = (200, 'message2', 'detail2')
        self.account.dbstore.account_update.side_effect = Exception('exc_key_change')
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.account._key_change('aname', {}, protected)
        self.assertIn('CRITICAL:test_a2c:acme2certifier database error in Account._key_change(): exc_key_change', lcm.output)

    def test_096_account__delete(self):
        """ test Account._delete() if dbstore.account_delete ok """
        self.account.dbstore.account_delete.return_value = 200
        self.assertEqual((200, None, None), self.account._delete('foo'))

    def test_097_account__delete(self):
        """ test Account._delete() if dbstore.account_delete raises an exception """
        self.account.dbstore.account_delete.side_effect = Exception('exc_delete')
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.account._delete('foo')
        self.assertIn('CRITICAL:test_a2c:acme2certifier database error in Account._delete(): exc_delete', lcm.output)

    @patch('acme_srv.account.Account._contact_check')
    def test_098_account__contacts_update(self, mock_contact_chk,):
        """ Account.contact_update() - if dbstore.account_update raises an exception"""
        mock_contact_chk.return_value = (200, 'message', 'detail')
        self.account.dbstore.account_update.side_effect = Exception('exc_contact_upd')
        payload = {"contact" : "foo"}
        aname = 'aname'
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.account._contacts_update(aname, payload)
        self.assertIn('CRITICAL:test_a2c:acme2certifier database error in Account._contacts_update(): exc_contact_upd', lcm.output)

    @patch('acme_srv.account.generate_random_string')
    def test_099_account__add(self, mock_name):
        """ test account add - if dbstore.account_add raises an exception"""
        self.account.dbstore.account_add.side_effect = Exception('exc_acc_add')
        mock_name.return_value = 'randowm_string'
        content = {'alg': 'RS256', 'jwk': {'e': u'AQAB', 'kty': u'RSA', 'n': u'foo'}, 'nonce': u'bar', 'url': u'acme_srv.srv/acme/newaccount'}
        payload = 'payload'
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.account._add(content, payload, 'foo@example.com')
        self.assertIn('CRITICAL:test_a2c:Account.account._add(): Database error: exc_acc_add', lcm.output)

    def test_100_eab_check(self):
        """ test external account binding No payload and no protected """
        payload = None
        protected = None
        result = (403, 'urn:ietf:params:acme:error:externalAccountRequired', 'external account binding required')
        self.assertEqual(result, self.account._eab_check(protected, payload))

    def test_101_eab_check(self):
        """ test external account binding No payload and but protected """
        payload = None
        protected = 'protected'
        result = (403, 'urn:ietf:params:acme:error:externalAccountRequired', 'external account binding required')
        self.assertEqual(result, self.account._eab_check(protected, payload))

    def test_102_eab_check(self):
        """ test external account binding payload and but no protected """
        payload = 'payload'
        protected = None
        result = (403, 'urn:ietf:params:acme:error:externalAccountRequired', 'external account binding required')
        self.assertEqual(result, self.account._eab_check(protected, payload))

    def test_103_eab_check(self):
        """ test external account binding payload and protected """
        payload = 'payload'
        protected = 'protected'
        result = (403, 'urn:ietf:params:acme:error:externalAccountRequired', 'external account binding required')
        self.assertEqual(result, self.account._eab_check(protected, payload))

    def test_104_eab_check(self):
        """ test external account binding wrong payload """
        payload = {'foo': 'bar'}
        protected = 'protected'
        result = (403, 'urn:ietf:params:acme:error:externalAccountRequired', 'external account binding required')
        self.assertEqual(result, self.account._eab_check(protected, payload))

    def test_105_eab_check(self):
        """ test external account binding False """
        payload = {'externalaccountbinding': False}
        protected = 'protected'
        result = (403, 'urn:ietf:params:acme:error:externalAccountRequired', 'external account binding required')
        self.assertEqual(result, self.account._eab_check(protected, payload))

    def test_106_eab_check(self):
        """ test external account binding True but protected in accountbinding structure is missing """
        payload = {'externalaccountbinding': {'payload': 'foo'}}
        protected = 'protected'
        self.account.eab_check = True
        self.account.eab_handler = 'foo'
        result = (403, 'urn:ietf:params:acme:error:malformed', 'Malformed request')
        self.assertEqual(result, self.account._eab_check(protected, payload))

    @patch('acme_srv.account.Account._eab_jwk_compare')
    def test_107_eab_check(self, mock_cmp):
        """ test external account binding False """
        payload = {'externalaccountbinding': {'payload': 'payload', 'protected': 'protected'}}
        protected = 'protected'
        mock_cmp.return_value = False
        self.account.eab_check = True
        self.account.eab_handler = 'foo'
        result = (403, 'urn:ietf:params:acme:error:malformed', 'Malformed request')
        self.assertEqual(result, self.account._eab_check(protected, payload))

    @patch('acme_srv.account.Account._eab_kid_get')
    @patch('acme_srv.account.Account._eab_jwk_compare')
    def test_108_eab_check(self, mock_cmp, mock_kget):
        """ test external _eab_kid_get returns None """
        payload = {'externalaccountbinding': {'payload': 'payload', 'protected': 'protected'}}
        protected = 'protected'
        mock_cmp.return_value = True
        mock_kget.return_value = None
        self.account.eab_check = True
        self.account.eab_handler = 'foo'
        result = (403, 'urn:ietf:params:acme:error:unauthorized', 'eab kid lookup failed')
        self.assertEqual(result, self.account._eab_check(protected, payload))

    @patch('acme_srv.account.Account._eab_kid_get')
    @patch('acme_srv.account.Account._eab_jwk_compare')
    def test_109_eab_check(self, mock_cmp, mock_kget):
        """ test external _eab_kid_get returns value but mac lookup failed """
        payload = {'externalaccountbinding': {'payload': 'payload', 'protected': 'protected'}}
        protected = 'protected'
        mock_cmp.return_value = True
        mock_kget.return_value = 'kid'
        eab_handler_module = importlib.import_module('examples.eab_handler.skeleton_eab_handler')
        self.account.eab_handler = eab_handler_module.EABhandler
        self.account.eab_handler.mac_key_get = Mock(return_value=None)
        result = (403, 'urn:ietf:params:acme:error:unauthorized', 'eab kid lookup failed')
        self.assertEqual(result, self.account._eab_check(protected, payload))

    @patch('acme_srv.account.Account._eab_signature_verify')
    @patch('acme_srv.account.Account._eab_kid_get')
    @patch('acme_srv.account.Account._eab_jwk_compare')
    def test_110_eab_check(self, mock_cmp, mock_kget, mock_sigvrf):
        """ test external _eab_kid_get returns value but mac lookup successful sig verification failed"""
        payload = {'externalaccountbinding': {'payload': 'payload', 'protected': 'protected'}}
        protected = 'protected'
        mock_cmp.return_value = True
        mock_kget.return_value = 'kid'
        eab_handler_module = importlib.import_module('examples.eab_handler.skeleton_eab_handler')
        self.account.eab_handler = eab_handler_module.EABhandler
        self.account.eab_handler.mac_key_get = Mock(return_value='mac_key')
        mock_sigvrf.return_value = (False, 'error')
        result = (403, 'urn:ietf:params:acme:error:unauthorized', 'eab signature verification failed')
        self.assertEqual(result, self.account._eab_check(protected, payload))

    @patch('acme_srv.account.Account._eab_signature_verify')
    @patch('acme_srv.account.Account._eab_kid_get')
    @patch('acme_srv.account.Account._eab_jwk_compare')
    def test_111_eab_check(self, mock_cmp, mock_kget, mock_sigvrf):
        """ test external _eab_kid_get returns value but mac lookup successful sig verification failed"""
        payload = {'externalaccountbinding': {'payload': 'payload', 'protected': 'protected'}}
        protected = 'protected'
        mock_cmp.return_value = True
        mock_kget.return_value = 'kid'
        eab_handler_module = importlib.import_module('examples.eab_handler.skeleton_eab_handler')
        self.account.eab_handler = eab_handler_module.EABhandler
        self.account.eab_handler.mac_key_get = Mock(return_value='mac_key')
        mock_sigvrf.return_value = (True, None)
        result = (200, None, None)
        self.assertEqual(result, self.account._eab_check(protected, payload))

    @patch('acme_srv.account.load_config')
    def test_112_config_load(self, mock_load_cfg):
        """ test _config_load empty config """
        parser = configparser.ConfigParser()
        # parser['Account'] = {'foo': 'bar'}
        mock_load_cfg.return_value = parser
        self.account._config_load()
        self.assertFalse(self.account.inner_header_nonce_allow)
        self.assertFalse(self.account.ecc_only)
        self.assertFalse(self.account.tos_check_disable)
        self.assertFalse(self.account.contact_check_disable)
        self.assertFalse(self.account.eab_check)

    @patch('acme_srv.account.load_config')
    def test_113_config_load(self, mock_load_cfg):
        """ test _config_load account with unknown values """
        parser = configparser.ConfigParser()
        parser['Account'] = {'foo': 'bar'}
        mock_load_cfg.return_value = parser
        self.account._config_load()
        self.assertFalse(self.account.inner_header_nonce_allow)
        self.assertFalse(self.account.ecc_only)
        self.assertFalse(self.account.tos_check_disable)
        self.assertFalse(self.account.contact_check_disable)
        self.assertFalse(self.account.eab_check)

    @patch('acme_srv.account.load_config')
    def test_114_config_load(self, mock_load_cfg):
        """ test _config_load account with inner_header_nonce_allow False """
        parser = configparser.ConfigParser()
        parser['Account'] = {'foo': 'bar', 'inner_header_nonce_allow': False}
        mock_load_cfg.return_value = parser
        self.account._config_load()
        self.assertFalse(self.account.inner_header_nonce_allow)
        self.assertFalse(self.account.ecc_only)
        self.assertFalse(self.account.tos_check_disable)
        self.assertFalse(self.account.contact_check_disable)
        self.assertFalse(self.account.eab_check)

    @patch('acme_srv.account.load_config')
    def test_115_config_load(self, mock_load_cfg):
        """ test _config_load account with inner_header_nonce_allow True """
        parser = configparser.ConfigParser()
        parser['Account'] = {'foo': 'bar', 'inner_header_nonce_allow': True}
        mock_load_cfg.return_value = parser
        self.account._config_load()
        self.assertTrue(self.account.inner_header_nonce_allow)
        self.assertFalse(self.account.ecc_only)
        self.assertFalse(self.account.tos_check_disable)
        self.assertFalse(self.account.contact_check_disable)
        self.assertFalse(self.account.eab_check)

    @patch('acme_srv.account.load_config')
    def test_116_config_load(self, mock_load_cfg):
        """ test _config_load account with ecc_only False """
        parser = configparser.ConfigParser()
        parser['Account'] = {'foo': 'bar', 'ecc_only': False}
        mock_load_cfg.return_value = parser
        self.account._config_load()
        self.assertFalse(self.account.inner_header_nonce_allow)
        self.assertFalse(self.account.ecc_only)
        self.assertFalse(self.account.tos_check_disable)
        self.assertFalse(self.account.contact_check_disable)
        self.assertFalse(self.account.eab_check)

    @patch('acme_srv.account.load_config')
    def test_117_config_load(self, mock_load_cfg):
        """ test _config_load account with ecc_only True """
        parser = configparser.ConfigParser()
        parser['Account'] = {'foo': 'bar', 'ecc_only': True}
        mock_load_cfg.return_value = parser
        self.account._config_load()
        self.assertFalse(self.account.inner_header_nonce_allow)
        self.assertTrue(self.account.ecc_only)
        self.assertFalse(self.account.tos_check_disable)
        self.assertFalse(self.account.contact_check_disable)
        self.assertFalse(self.account.eab_check)

    @patch('acme_srv.account.load_config')
    def test_118_config_load(self, mock_load_cfg):
        """ test _config_load account with tos_check_disable False """
        parser = configparser.ConfigParser()
        parser['Account'] = {'foo': 'bar', 'tos_check_disable': False}
        mock_load_cfg.return_value = parser
        self.account._config_load()
        self.assertFalse(self.account.inner_header_nonce_allow)
        self.assertFalse(self.account.ecc_only)
        self.assertFalse(self.account.tos_check_disable)
        self.assertFalse(self.account.contact_check_disable)
        self.assertFalse(self.account.eab_check)

    @patch('acme_srv.account.load_config')
    def test_119_config_load(self, mock_load_cfg):
        """ test _config_load account with tos_check_disable True """
        parser = configparser.ConfigParser()
        parser['Account'] = {'foo': 'bar', 'tos_check_disable': True}
        mock_load_cfg.return_value = parser
        self.account._config_load()
        self.assertFalse(self.account.inner_header_nonce_allow)
        self.assertFalse(self.account.ecc_only)
        self.assertTrue(self.account.tos_check_disable)
        self.assertFalse(self.account.contact_check_disable)
        self.assertFalse(self.account.eab_check)

    @patch('acme_srv.account.load_config')
    def test_120_config_load(self, mock_load_cfg):
        """ test _config_load account with contact_check_disable False """
        parser = configparser.ConfigParser()
        parser['Account'] = {'foo': 'bar', 'contact_check_disable': False}
        mock_load_cfg.return_value = parser
        self.account._config_load()
        self.assertFalse(self.account.inner_header_nonce_allow)
        self.assertFalse(self.account.ecc_only)
        self.assertFalse(self.account.tos_check_disable)
        self.assertFalse(self.account.contact_check_disable)
        self.assertFalse(self.account.eab_check)

    @patch('acme_srv.account.load_config')
    def test_121_config_load(self, mock_load_cfg):
        """ test _config_load account with contact_check_disable True """
        parser = configparser.ConfigParser()
        parser['Account'] = {'foo': 'bar', 'contact_check_disable': True}
        mock_load_cfg.return_value = parser
        self.account._config_load()
        self.assertFalse(self.account.inner_header_nonce_allow)
        self.assertFalse(self.account.ecc_only)
        self.assertFalse(self.account.tos_check_disable)
        self.assertTrue(self.account.contact_check_disable)
        self.assertFalse(self.account.eab_check)

    @patch('acme_srv.account.eab_handler_load')
    @patch('acme_srv.account.load_config')
    def test_122_config_load(self, mock_load_cfg, mock_eab):
        """ test _config_load account with failed eab load """
        parser = configparser.ConfigParser()
        parser['EABhandler'] = {'foo': 'bar', 'eab_handler_file': 'foo'}
        mock_load_cfg.return_value = parser
        mock_eab.return_value = False
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.account._config_load()
        self.assertFalse(self.account.inner_header_nonce_allow)
        self.assertFalse(self.account.ecc_only)
        self.assertFalse(self.account.tos_check_disable)
        self.assertFalse(self.account.contact_check_disable)
        self.assertTrue(self.account.eab_check)
        self.assertIn('CRITICAL:test_a2c:Account._config_load(): EABHandler could not get loaded', lcm.output)


    @patch('acme_srv.account.eab_handler_load')
    @patch('acme_srv.account.load_config')
    def test_123_config_load(self, mock_load_cfg, mock_eab):
        """ test _config_load account with failed eab load """
        parser = configparser.ConfigParser()
        parser['EABhandler'] = {'foo': 'bar'}
        mock_load_cfg.return_value = parser
        mock_eab.return_value = False
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.account._config_load()
        self.assertFalse(self.account.inner_header_nonce_allow)
        self.assertFalse(self.account.ecc_only)
        self.assertFalse(self.account.tos_check_disable)
        self.assertFalse(self.account.contact_check_disable)
        self.assertTrue(self.account.eab_check)
        self.assertIn('CRITICAL:test_a2c:Account._config_load(): EABHandler configuration incomplete', lcm.output)

    @patch('acme_srv.account.eab_handler_load')
    @patch('acme_srv.account.load_config')
    def test_124_config_load(self, mock_load_cfg, mock_eab):
        """ test _config_load account with failed eab load """
        parser = configparser.ConfigParser()
        parser['EABhandler'] = {'foo': 'bar', 'eab_handler_file': 'foo'}
        mock_load_cfg.return_value = parser
        mock_eab.EABhandler.return_value = 'foo'
        self.account._config_load()
        self.assertFalse(self.account.inner_header_nonce_allow)
        self.assertFalse(self.account.ecc_only)
        self.assertFalse(self.account.tos_check_disable)
        self.assertFalse(self.account.contact_check_disable)
        self.assertTrue(self.account.eab_check)
        self.assertTrue(self.account.eab_handler)

    @patch('importlib.import_module')
    @patch('acme_srv.account.load_config')
    def test_125_config_load(self, mock_load_cfg, mock_imp):
        """ test _config_load account with contact_check_disable True """
        parser = configparser.ConfigParser()
        parser['EABhandler'] = {'foo': 'bar', 'eab_handler_file': 'foo'}
        mock_load_cfg.return_value = parser
        mock_imp.return_value = Mock()
        self.account._config_load()
        self.assertFalse(self.account.inner_header_nonce_allow)
        self.assertFalse(self.account.ecc_only)
        self.assertFalse(self.account.tos_check_disable)
        self.assertFalse(self.account.contact_check_disable)
        self.assertTrue(self.account.eab_check)
        self.assertTrue(self.account.eab_handler)

    @patch('acme_srv.account.load_config')
    def test_126_config_load(self, mock_load_cfg):
        """ test _config_load account with tos url check """
        parser = configparser.ConfigParser()
        parser['Directory'] = {'foo': 'bar'}
        mock_load_cfg.return_value = parser
        self.account._config_load()
        self.assertFalse(self.account.inner_header_nonce_allow)
        self.assertFalse(self.account.ecc_only)
        self.assertFalse(self.account.tos_check_disable)
        self.assertFalse(self.account.contact_check_disable)
        self.assertFalse(self.account.eab_check)
        self.assertFalse(self.account.tos_url)

    @patch('acme_srv.account.load_config')
    def test_127_config_load(self, mock_load_cfg):
        """ test _config_load account with tos url configured """
        parser = configparser.ConfigParser()
        parser['Directory'] = {'foo': 'bar', 'tos_url': 'tos_url'}
        mock_load_cfg.return_value = parser
        self.account._config_load()
        self.assertFalse(self.account.inner_header_nonce_allow)
        self.assertFalse(self.account.ecc_only)
        self.assertFalse(self.account.tos_check_disable)
        self.assertFalse(self.account.contact_check_disable)
        self.assertFalse(self.account.eab_check)
        self.assertEqual('tos_url', self.account.tos_url)

    @patch('acme_srv.account.load_config')
    def test_128_config_load(self, mock_load_cfg):
        """ test _config_load account with url prefix without tailing slash configured """
        parser = configparser.ConfigParser()
        parser['Directory'] = {'foo': 'bar', 'url_prefix': 'url_prefix'}
        mock_load_cfg.return_value = parser
        self.account._config_load()
        self.assertFalse(self.account.inner_header_nonce_allow)
        self.assertFalse(self.account.ecc_only)
        self.assertFalse(self.account.tos_check_disable)
        self.assertFalse(self.account.contact_check_disable)
        self.assertFalse(self.account.eab_check)
        self.assertFalse(self.account.tos_url)
        self.assertEqual({'acct_path': 'url_prefix/acme/acct/'}, self.account.path_dic)

    @patch('json.loads')
    def test_129_eab_kid_get(self, mock_json):
        """ tes eab_kid all ok """
        mock_json.return_value = {'kid': 'foo'}
        self.assertEqual('foo', self.account._eab_kid_get('Zm9vYmFyMjM'))

    @patch('json.loads')
    def test_130_eab_kid_get(self, mock_json):
        """ json does not have a kid key """
        mock_json.return_value = {'foo': 'bar'}
        self.assertFalse(self.account._eab_kid_get('Zm9vYmFyMjM'))

    @patch('json.loads')
    def test_131_eab_kid_get(self, mock_json):
        """ json is empty """
        mock_json.return_value = {}
        self.assertFalse(self.account._eab_kid_get('Zm9vYmFyMjM'))

    @patch('json.loads')
    def test_132_eab_kid_get(self, mock_json):
        """ json returns a string """
        mock_json.return_value = 'nonjson'
        self.assertFalse(self.account._eab_kid_get('Zm9vYmFyMjM'))

    def test_133__eab_jwk_compare(self):
        """ jwk inner ok """
        protected = {'jwk': 'foobar'}
        payload = 'ImZvb2JhciI='
        self.assertTrue(self.account._eab_jwk_compare(protected, payload))

    def test_134__eab_jwk_compare(self):
        """ jwk inner ok no padding """
        protected = {'jwk': 'foobar'}
        payload = 'ImZvb2JhciI'
        self.assertTrue(self.account._eab_jwk_compare(protected, payload))

    def test_135__eab_jwk_compare(self):
        """ jwk inner payload does not match """
        protected = {'jwk': 'foobar'}
        payload = 'ImZvb2Ii'
        self.assertFalse(self.account._eab_jwk_compare(protected, payload))

    def test_136__eab_jwk_compare(self):
        """ no jwk in protected """
        protected = {'foo': 'bar'}
        payload = 'Zm9vYg'
        self.assertFalse(self.account._eab_jwk_compare(protected, payload))

    def test_137__eab_jwk_compare(self):
        """ protected is a string """
        protected = 'protected'
        payload = 'Zm9vYg'
        self.assertFalse(self.account._eab_jwk_compare(protected, payload))

    def test_138__eab_jwk_compare(self):
        """ protected is a string containg jwk """
        protected = 'protected-jwk'
        payload = 'Zm9vYg'
        self.assertFalse(self.account._eab_jwk_compare(protected, payload))

    def test_139__eab_signature_verify(self):
        """ content and mac_key are missing """
        content = None
        mac_key = None
        self.assertEqual((False, None), self.account._eab_signature_verify(content, mac_key))

    def test_140__eab_signature_verify(self):
        """ mac_key is issing """
        content = 'content'
        mac_key = None
        self.assertEqual((False, None), self.account._eab_signature_verify(content, mac_key))

    @patch('acme_srv.signature.Signature.eab_check')
    def test_141__eab_signature_verify(self, mock_eabchk):
        """ result and error returned """
        content = 'content'
        mac_key = 'mac_key'
        mock_eabchk.return_value = ('foo', 'bar')
        self.assertEqual(('foo', 'bar'), self.account._eab_signature_verify(content, mac_key))

    @patch('acme_srv.signature.Signature.eab_check')
    def test_142__eab_signature_verify(self, mock_eabchk):
        """ result and no error returned """
        content = 'content'
        mac_key = 'mac_key'
        mock_eabchk.return_value = (True, None)
        self.assertEqual((True, None), self.account._eab_signature_verify(content, mac_key))

    @patch('acme_srv.signature.Signature.eab_check')
    def test_143__eab_signature_verify(self, mock_eabchk):
        """ result and no error returned """
        content = 'content'
        mac_key = 'mac_key'
        mock_eabchk.return_value = (False, 'error')
        self.assertEqual((False, 'error'), self.account._eab_signature_verify(content, mac_key))

    @patch('acme_srv.account.Account._config_load')
    def test_144__enter__(self, mock_cfg):
        """ test enter """
        mock_cfg.return_value = True
        self.account.__enter__()
        self.assertTrue(mock_cfg.called)

    @patch('acme_srv.account.date_to_datestr')
    def test_145__info_(self, mock_date):
        """ test Account.info() without eab """
        account_obj = {'jwk': "[\"jwk\"]", 'contact': "[\"contact\"]", 'created_at': '2021-07-18T09:08:01Z'}
        mock_date.return_value = 'created_at'
        self.assertEqual({'status': 'valid', 'key': ['jwk'], 'contact': ['contact'], 'createdAt': 'created_at'}, self.account._info(account_obj))

    @patch('acme_srv.account.date_to_datestr')
    def test_146__info_(self, mock_date):
        """ test Account.info() with eab """
        account_obj = {'jwk': "[\"jwk\"]", 'contact': "[\"contact\"]", 'created_at': '2021-07-18T09:08:01Z', 'eab_kid': 'eab_kid'}
        mock_date.return_value = 'created_at'
        self.assertEqual({'status': 'valid', 'key': ['jwk'], 'contact': ['contact'], 'createdAt': 'created_at', 'eab_kid': 'eab_kid'}, self.account._info(account_obj))


if __name__ == '__main__':
    unittest.main()
