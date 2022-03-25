#!/usr/bin/python
# -*- coding: utf-8 -*-
""" unittests for openssl_ca_handler """
# pylint: disable=C0415, R0904, R0913, W0212
import sys
import os
import unittest
from unittest.mock import patch, mock_open, Mock
from io import StringIO
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
        from examples.acme2certifier_wsgi import create_header, get_request_body
        logging.basicConfig(level=logging.CRITICAL)
        self.logger = logging.getLogger('test_a2c')
        self.create_header = create_header
        self.get_request_body = get_request_body

    def tearDown(self):
        """ teardown """
        pass

    def test_001_default(self):
        """ default test which always passes """
        self.assertEqual('foo', 'foo')

    def test_002_create_header(self):
        """ create header """
        response_dic = {}
        result = [('Content-Type', 'application/json')]
        self.assertEqual(result, self.create_header(response_dic))

    def test_003_create_header(self):
        """ create header unknown response_dic"""
        response_dic = {'foo': 'bar'}
        result = [('Content-Type', 'application/json')]
        self.assertEqual(result, self.create_header(response_dic))

    def test_004_create_header(self):
        """ create header response_dic with header """
        response_dic = {'header': {'foo': 'bar'}}
        result = [('Content-Type', 'application/json'),  ('foo', 'bar')]
        self.assertEqual(result, self.create_header(response_dic))

    def test_005_create_header(self):
        """ create header response_dic with header and code = 200 """
        response_dic = {'code': 200, 'header': {'foo': 'bar'}}
        result = [('Content-Type', 'application/json'),  ('foo', 'bar')]
        self.assertEqual(result, self.create_header(response_dic))

    def test_006_create_header(self):
        """ create header response_dic with header and code = 201 """
        response_dic = {'code': 201, 'header': {'foo': 'bar'}}
        result = [('Content-Type', 'application/json'),  ('foo', 'bar')]
        self.assertEqual(result, self.create_header(response_dic))

    def test_007_create_header(self):
        """ create header response_dic with header and code = 400 """
        response_dic = {'code': 400, 'header': {'foo': 'bar'}}
        result = [('Content-Type', 'application/problem+json'),  ('foo', 'bar')]
        self.assertEqual(result, self.create_header(response_dic))

    def test_008_create_header(self):
        """ create header response_dic with header and add_json_header false """
        response_dic = {'code': 400, 'header': {'foo': 'bar'}}
        result = [('foo', 'bar')]
        self.assertEqual(result, self.create_header(response_dic, add_json_header=False))

    def test_009_create_header(self):
        """ create header response_dic with header and code = 400 and add_json_header true """
        response_dic = {'code': 400, 'header': {'foo': 'bar'}}
        result = [('Content-Type', 'application/problem+json'),  ('foo', 'bar')]
        self.assertEqual(result, self.create_header(response_dic, add_json_header=True))

    def test_010_get_request_body(self):
        """ get_request_body with empty environment  """
        environ = {}
        self.assertFalse(self.get_request_body(environ))

    def test_010_get_request_body(self):
        """ get_request_body with environment data but no CONTENT_LENGTH specification  """
        environ = {'wsgi.input': StringIO("""foo""")}
        self.assertFalse(self.get_request_body(environ))

    def test_011_get_request_body(self):
        """ get_request_body with environment data but CONTENT_LENGTH specification 0 (read full content) """
        environ = {'wsgi.input': StringIO("""foo"""), 'CONTENT_LENGTH': 0}
        self.assertFalse(self.get_request_body(environ))

    def test_012_get_request_body(self):
        """ get_request_body with environment data content length lower than string length """
        environ = {'wsgi.input': StringIO("""foo"""), 'CONTENT_LENGTH': 2}
        self.assertEqual('fo', self.get_request_body(environ))

    def test_013_get_request_body(self):
        """ get_request_body with environment data content length lower than string length """
        environ = {'wsgi.input': StringIO("""foo"""), 'CONTENT_LENGTH': 3}
        self.assertEqual('foo', self.get_request_body(environ))

    def test_014_get_request_body(self):
        """ get_request_body with environment data content length lower than string length """
        environ = {'wsgi.input': StringIO("""foo"""), 'CONTENT_LENGTH': 10}
        self.assertEqual('foo', self.get_request_body(environ))

if __name__ == '__main__':

    unittest.main()
