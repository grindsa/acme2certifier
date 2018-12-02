""" unittests for acme2certifier """

import unittest
import sys
from acme.acmesrv import ACMEsrv
sys.path.insert(0, '..')


class TestACMEHandler(unittest.TestCase):
    """ test class for ACMEHandler """
    acme = None
    def setUp(self):
        """ setup unittest """
        self.acme = ACMEsrv('http://tester.local')

    def test_get_servername(self):
        """ test ACMEsrv.get_server_name() method """
        self.assertEqual('http://tester.local', self.acme.get_server_name())

    def test_get_dir_newnonce(self):
        """ test ACMEsrv.get_directory() method and check for "newnonce" tag in output"""
        self.assertDictContainsSubset({'newNonce': 'http://tester.local/acme/newnonce'}, self.acme.get_directory())

    def test_new_noce(self):
        """ test ACMEsrv.newnonce() and check if we get something back """
        self.assertIsNotNone(self.acme.newnonce())

    def test_get_dir_meta(self):
        """ test ACMEsrv.get_directory() method and check for "meta" tag in output"""
        self.assertDictContainsSubset({'meta': {'home': 'https://github.com/grindsa/acme2certifier', 'author': 'grindsa <grindelsack@gmail.com>'}}, self.acme.get_directory())

    def test_get_dir_newaccount(self):
        """ test ACMEsrv.get_directory() method and check for "newnonce" tag in output"""
        self.assertDictContainsSubset({'newAccount': 'http://tester.local/acme/newaccount'}, self.acme.get_directory())

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

if __name__ == '__main__':

    unittest.main()
