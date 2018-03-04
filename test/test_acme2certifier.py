""" unittests for acme2certifier """

import unittest
import os
import sys
from acme2certifier import ACMEHandler
sys.path.insert(0, '..')

class TestACMEHandler(unittest.TestCase):
    """ test class for ACMEHandler """
    acme = None
    def setUp(self):
        """ setup unittest """
        os.environ['SERVER_NAME'] = 'http://acme.test.local'
        self.acme = ACMEHandler()

    def test_get_servername(self):
        """ test ACMEHandler.get_server_name() method """
        self.assertEqual(self.acme.get_server_name(), 'http://acme.test.local')

    def test_get_uri(self):
        """ test ACMEHandler.get_uri() method """
        os.environ['REQUEST_URI'] = '/testing'
        self.assertEqual(self.acme.get_uri(), '/testing')

    def test_return_error(self):
        """ test ACMEHandler.get_error() method """
        os.environ['REQUEST_URI'] = '/foo'
        self.assertEqual(self.acme.return_error(), '{"error": "dont now what to do"}')

    def test_get_dir_new_authz(self):
        """ test ACMEHandler.get_directory() method and check for "new-authz" tag in output"""
        os.environ['REQUEST_URI'] = '/directory'
        self.assertIn('"new-authz": "http://acme.test.local/acme/new-authz"', self.acme.get_directory())

    def test_get_dir_key_change(self):
        """ test ACMEHandler.get_directory() method and check for "key-change" tag in output"""
        os.environ['REQUEST_URI'] = '/directory'
        self.assertIn('"key-change": "http://acme.test.local/acme/key-change"', self.acme.get_directory())

    def test_get_dir_revoke_cert(self):
        """ test ACMEHandler.get_directory() method and check for "revoke-cert" tag in output"""
        os.environ['REQUEST_URI'] = '/directory'
        self.assertIn('"revoke-cert": "http://acme.test.local/acme/revoke-cert"', self.acme.get_directory())

    def test_get_dir_meta(self):
        """ test ACMEHandler.get_directory() method and check for "meta" tag in output"""
        os.environ['REQUEST_URI'] = '/directory'
        self.assertIn('"meta": {"home": "https://github.com/grindsa/acme2certifier", "author": "grindsa <grindelsack@gmail.com>"}', self.acme.get_directory())

    def test_get_dir_new_cert(self):
        """ test ACMEHandler.get_directory() method and check for "new-cert" tag in output"""
        os.environ['REQUEST_URI'] = '/directory'
        self.assertIn('"new-cert": "http://acme.test.local/acme/new-cert"', self.acme.get_directory())

    def test_get_dir_new_reg(self):
        """ test ACMEHandler.get_directory() method and check for "new-req" tag in output"""
        os.environ['REQUEST_URI'] = '/directory'
        self.assertIn('"new-reg": "http://acme.test.local/acme/new-reg"', self.acme.get_directory())

if __name__ == '__main__':

    unittest.main()
