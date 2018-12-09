#!/usr/bin/python
# -*- coding: utf-8 -*-
""" unittests for acme2certifier """
import unittest
try:
    from mock import patch, MagicMock
except ImportError:
    from unittest.mock import patch, MagicMock
import sys
sys.path.insert(0, '..')


class FakeDBStore(object):
    """ face DBStore class needed for mocking """
    pass

class TestACMEHandler(unittest.TestCase):
    """ test class for ACMEHandler """
    acme = None
    def setUp(self):
        """ setup unittest """
        models_mock = MagicMock()
        models_mock.acme.django_handler.DBstore.return_value = FakeDBStore
        models_mock.acme.cgi_handler.DBstore.return_value = FakeDBStore
        modules = {'acme.django_handler': models_mock, 'acme.cgi_handler': models_mock}
        patch.dict('sys.modules', modules).start()
        from acme.acmesrv import Account, Directory, Nonce, Error
        from acme.helper import b64decode_pad, decode_deserialize, validate_email
        self.directory = Directory(False, 'http://tester.local')
        self.account = Account(False, 'http://tester.local')
        self.nonce = Nonce(False)
        self.error = Error(False)
        self.b64decode_pad = b64decode_pad
        self.validate_email = validate_email
        self.decode_deserialize = decode_deserialize

    def test_servername_new(self):
        """ test Directory.get_server_name() method """
        self.assertEqual('http://tester.local', self.directory.servername_get())

    def test_get_dir_newnonce(self):
        """ test Directory.get_directory() method and check for "newnonce" tag in output"""
        self.assertDictContainsSubset({'newNonce': 'http://tester.local/acme/newnonce'}, self.directory.directory_get())

    def test_get_dir_newaccount(self):
        """ test Directory.get_directory() method and check for "newnonce" tag in output"""
        self.assertDictContainsSubset({'newAccount': 'http://tester.local/acme/newaccount'}, self.directory.directory_get())

    def test_get_dir_meta(self):
        """ test Directory.get_directory() method and check for "meta" tag in output"""
        self.assertDictContainsSubset({'meta': {'home': 'https://github.com/grindsa/acme2certifier', 'author': 'grindsa <grindelsack@gmail.com>'}}, self.directory.directory_get())

    def test_nonce_new(self):
        """ test Nonce.new() and check if we get something back """
        self.assertIsNotNone(self.nonce.new())

    def test_nonce_generate_and_add(self):
        """ test Nonce.nonce_generate_and_add() and check if we get something back """
        self.assertIsNotNone(self.nonce.generate_and_add())

    def test_nonce_check_failed(self):
        """ test Nonce.nonce_check_and_delete """
        self.assertEqual((400, 'urn:ietf:params:acme:error:badNonce', 'NONE'), self.nonce.check({'foo':'bar'}))

    def test_nonce_check_succ(self):
        """ test Nonce.nonce_check_and_delete """
        self.assertEqual((200, None, None), self.nonce.check({'nonce':'aaa'}))

    def test_nonce_check_and_delete(self):
        """ test Nonce.nonce_check_and_delete """
        self.assertEqual((200, None, None), self.nonce.check_and_delete('aaa'))

    def test_err_badnonce(self):
        """ test badnonce error message """
        self.assertEqual('JWS has invalid anti-replay nonce', self.error.acme_errormessage('urn:ietf:params:acme:error:badNonce'))

    def test_err_invalidcontact(self):
        """ test badnonce error message """
        self.assertEqual('The provided contact URI was invalid', self.error.acme_errormessage('urn:ietf:params:acme:error:invalidContact'))

    def test_err_useractionrequired(self):
        """ test badnonce error message """
        self.assertEqual('', self.error.acme_errormessage('urn:ietf:params:acme:error:userActionRequired'))

    def test_err_malformed(self):
        """ test badnonce error message """
        self.assertEqual('', self.error.acme_errormessage('urn:ietf:params:acme:error:malformed'))

    def test_b64decode_pad_correct(self):
        """ test b64decode_pad() method with a regular base64 encoded string """
        self.assertEqual('this-is-foo-correctly-padded', self.b64decode_pad(False, 'dGhpcy1pcy1mb28tY29ycmVjdGx5LXBhZGRlZA=='))

    def test_b64decode_pad_missing(self):
        """ test b64decode_pad() method with a regular base64 encoded string """
        self.assertEqual('this-is-foo-with-incorrect-padding', self.b64decode_pad(False, 'dGhpcy1pcy1mb28td2l0aC1pbmNvcnJlY3QtcGFkZGluZw'))

    def test_b64decode_failed(self):
        """ test b64 decoding failure """
        self.assertEqual('ERR: b64 decoding error', self.b64decode_pad(False, 'b'))

    def test_decode_deserialize(self):
        """ test successful deserialization of a b64 encoded string """
        self.assertEqual({u'a': u'b', u'c': u'd'}, self.decode_deserialize(False, 'eyJhIiA6ICJiIiwgImMiIDogImQifQ=='))

    def test_decode_deserialize_failed(self):
        """ test failed deserialization of a b64 encoded string """
        self.assertEqual('ERR: Json decoding error', self.decode_deserialize(False, 'Zm9vLXdoaWNoLWNhbm5vdC1iZS1qc29uaXplZA=='))

    def test_validate_email_0(self):
        """ validate normal email """
        self.assertTrue(self.validate_email(False, 'foo@example.com'))

    def test_validate_email_1(self):
        """ validate normal email """
        self.assertTrue(self.validate_email(False, 'mailto:foo@example.com'))

    def test_validate_email_2(self):
        """ validate normal email """
        self.assertTrue(self.validate_email(False, 'mailto: foo@example.com'))

    def test_validate_email_3(self):
        """ validate normal email """
        self.assertTrue(self.validate_email(False, ['mailto: foo@example.com', 'mailto: bar@example.com']))

    def test_validate_wrong_email_1(self):
        """ validate normal email """
        self.assertFalse(self.validate_email(False, 'example.com'))

    def test_validate_wrong_email_2(self):
        """ validate normal email """
        self.assertFalse(self.validate_email(False, 'me@exam,ple.com'))

    def test_validate_wrong_email_3(self):
        """ validate normal email """
        self.assertFalse(self.validate_email(False, ['mailto: foo@exa,mple.com', 'mailto: bar@example.com']))

    def test_validate_wrong_email_4(self):
        """ validate normal email """
        self.assertFalse(self.validate_email(False, ['mailto: foo@example.com', 'mailto: bar@exa,mple.com']))

    def test_tos_check_true(self):
        """ test successful tos check """
        self.assertEqual((200, None, None), self.account.tos_check({'termsOfServiceAgreed': True}))

    def test_tos_check_false(self):
        """ test successful tos check """
        self.assertEqual((403, 'urn:ietf:params:acme:error:userActionRequired', 'tosfalse'), self.account.tos_check({'termsOfServiceAgreed': False}))

    def test_tos_check_missing(self):
        """ test successful tos check """
        self.assertEqual((403, 'urn:ietf:params:acme:error:userActionRequired', 'tosfalse'), self.account.tos_check({'foo': 'bar'}))

    def test_contact_check_valid(self):
        """ test successful tos check """
        self.assertEqual((200, None, None), self.account.contact_check({'contact': ['mailto: foo@example.com']}))

    def test_contact_check_invalid(self):
        """ test successful tos check """
        self.assertEqual((400, 'urn:ietf:params:acme:error:invalidContact', 'mailto: bar@exa,mple.com'), self.account.contact_check({'contact': ['mailto: bar@exa,mple.com']}))

    def test_contact_check_missing(self):
        """ test successful tos check """
        self.assertEqual((400, 'urn:ietf:params:acme:error:invalidContact', 'no contacts specified'), self.account.contact_check({'foo': 'bar'}))

    def test_account_add_failed1(self):
        """ test account add without ALG """
        dic = {'foo': 'bar', 'jwk': {'e': u'AQAB', 'kty': u'RSA', 'n': u'foo'}, 'nonce': u'bar', 'url': u'acme.srv/acme/newaccount'}
        self.assertEqual((400, 'urn:ietf:params:acme:error:malformed', 'incomplete protectedpayload'), self.account.add(dic, ['me@example.com']))

    def test_account_add_failed2(self):
        """ test account add without jwk """
        dic = {'alg': 'RS256', 'foo': {'foo': u'bar'}, 'nonce': u'bar', 'url': u'acme.srv/acme/newaccount'}
        self.assertEqual((400, 'urn:ietf:params:acme:error:malformed', 'incomplete protectedpayload'), self.account.add(dic, ['me@example.com']))

    def test_account_add_failed3(self):
        """ test account add without jwk e """
        dic = {'alg': 'RS256', 'jwk': {'kty': u'RSA', 'n': u'foo'}, 'nonce': u'bar', 'url': u'acme.srv/acme/newaccount'}
        self.assertEqual((400, 'urn:ietf:params:acme:error:malformed', 'incomplete JSON Web Key'), self.account.add(dic, ['me@example.com']))

    def test_account_add_failed4(self):
        """ test account add without jwk kty """
        dic = {'alg': 'RS256', 'jwk': {'e': u'AQAB', 'n': u'foo'}, 'nonce': u'bar', 'url': u'acme.srv/acme/newaccount'}
        self.assertEqual((400, 'urn:ietf:params:acme:error:malformed', 'incomplete JSON Web Key'), self.account.add(dic, ['me@example.com']))

    def test_account_add_failed5(self):
        """ test account add without jwk n """
        dic = {'alg': 'RS256', 'jwk': {'e': u'AQAB', 'kty': u'RSA'}, 'nonce': u'bar', 'url': u'acme.srv/acme/newaccount'}
        self.assertEqual((400, 'urn:ietf:params:acme:error:malformed', 'incomplete JSON Web Key'), self.account.add(dic, ['me@example.com']))

    def test_account_add_failed6(self):
        """ test account add without contact """
        dic = {'alg': 'RS256', 'jwk': {'e': u'AQAB', 'kty': u'RSA', 'n': u'foo'}, 'nonce': u'bar', 'url': u'acme.srv/acme/newaccount'}
        self.assertEqual((400, 'urn:ietf:params:acme:error:malformed', 'incomplete protectedpayload'), self.account.add(dic, None))

if __name__ == '__main__':

    unittest.main()
