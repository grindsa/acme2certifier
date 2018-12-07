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
        from acme.acmesrv import ACMEsrv
        self.acme = ACMEsrv(False, 'http://tester.local')

    def test_servername_new(self):
        """ test ACMEsrv.get_server_name() method """
        self.assertEqual('http://tester.local', self.acme.servername_get())

    def test_get_dir_newnonce(self):
        """ test ACMEsrv.get_directory() method and check for "newnonce" tag in output"""
        self.assertDictContainsSubset({'newNonce': 'http://tester.local/acme/newnonce'}, self.acme.directory_get())

    def test_nonce_new(self):
        """ test ACMEsrv.newnonce() and check if we get something back """
        self.assertIsNotNone(self.acme.nonce_new())

    def test_get_dir_meta(self):
        """ test ACMEsrv.get_directory() method and check for "meta" tag in output"""
        self.assertDictContainsSubset({'meta': {'home': 'https://github.com/grindsa/acme2certifier', 'author': 'grindsa <grindelsack@gmail.com>'}}, self.acme.directory_get())

    def test_get_dir_newaccount(self):
        """ test ACMEsrv.get_directory() method and check for "newnonce" tag in output"""
        self.assertDictContainsSubset({'newAccount': 'http://tester.local/acme/newaccount'}, self.acme.directory_get())

    def test_b64decode_pad_correct(self):
        """ test ACMEsrv.b64decode_pad() method with a regular base64 encoded string """
        self.assertEqual('this-is-foo-correctly-padded', self.acme.b64decode_pad('dGhpcy1pcy1mb28tY29ycmVjdGx5LXBhZGRlZA=='))

    def test_b64decode_pad_missing(self):
        """ test ACMEsrv.b64decode_pad() method with a regular base64 encoded string """
        self.assertEqual('this-is-foo-with-incorrect-padding', self.acme.b64decode_pad('dGhpcy1pcy1mb28td2l0aC1pbmNvcnJlY3QtcGFkZGluZw'))

    def test_b64decode_failed(self):
        """ test b64 decoding failure """
        self.assertEqual('ERR: b64 decoding error', self.acme.b64decode_pad('b'))

    def test_decode_deserialize(self):
        """ test successful deserialization of a b64 encoded string """
        self.assertEqual({u'a': u'b', u'c': u'd'}, self.acme.decode_deserialize('eyJhIiA6ICJiIiwgImMiIDogImQifQ=='))

    def test_decode_deserialize_failed(self):
        """ test failed deserialization of a b64 encoded string """
        self.assertEqual('ERR: Json decoding error', self.acme.decode_deserialize('Zm9vLXdoaWNoLWNhbm5vdC1iZS1qc29uaXplZA=='))
        
    def test_acme_err_badnonce(self):
        """ test badnonce error message """
        self.assertEqual('JWS has invalid anti-replay nonce', self.acme.acme_errormessage('urn:ietf:params:acme:error:badNonce'))  

    def test_nonce_generate_and_add(self):
        """ test ACMEsrv.nonce_generate_and_add() and check if we get something back """
        self.assertIsNotNone(self.acme.nonce_generate_and_add())
        
    def test_nonce_check_and_delete(self):
        """ test ACMEsrv.nonce_check_and_delete """
        self.assertEqual((200, None, None), self.acme.nonce_check_and_delete('aaa'))        
        

if __name__ == '__main__':

    unittest.main()
