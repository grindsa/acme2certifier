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
import json

sys.path.insert(0, '.')
sys.path.insert(1, '..')

class FakeDBStore(object):
    """ face DBStore class needed for mocking """
    # pylint: disable=W0107, R0903
    pass

class TestACMEHandler(unittest.TestCase):
    """ test class for cgi_handler """
    def setUp(self):
        """ setup unittest """
        import logging
        from examples.acme2certifier_wsgi import create_header, get_request_body, acct, acmechallenge_serve, authz, handle_exception, newaccount, directory, cert, chall, neworders, newnonce, order, revokecert, trigger, not_found, application, get_handler_cls, housekeeping
        logging.basicConfig(level=logging.CRITICAL)
        self.logger = logging.getLogger('test_a2c')
        self.acct = acct
        self.create_header = create_header
        self.get_request_body = get_request_body
        self.acmechallenge_serve = acmechallenge_serve
        self.handle_exception = handle_exception
        self.housekeeping = housekeeping
        self.authz = authz
        self.newaccount = newaccount
        self.neworders = neworders
        self.newnonce = newnonce
        self.directory = directory
        self.cert = cert
        self.chall = chall
        self.order = order
        self.revokecert = revokecert
        self.trigger = trigger
        self.not_found = not_found
        self.application = application
        self.get_handler_cls = get_handler_cls

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

    def test_011_get_request_body(self):
        """ get_request_body with environment data but no CONTENT_LENGTH specification  """
        environ = {'wsgi.input': StringIO("""foo""")}
        self.assertFalse(self.get_request_body(environ))

    def test_012_get_request_body(self):
        """ get_request_body with environment data but CONTENT_LENGTH specification 0 (read full content) """
        environ = {'wsgi.input': StringIO("""foo"""), 'CONTENT_LENGTH': 0}
        self.assertFalse(self.get_request_body(environ))

    def test_013_get_request_body(self):
        """ get_request_body with environment data content length lower than string length """
        environ = {'wsgi.input': StringIO("""foo"""), 'CONTENT_LENGTH': 2}
        self.assertEqual('fo', self.get_request_body(environ))

    def test_014_get_request_body(self):
        """ get_request_body with environment data content length lower than string length """
        environ = {'wsgi.input': StringIO("""foo"""), 'CONTENT_LENGTH': 3}
        self.assertEqual('foo', self.get_request_body(environ))

    def test_015_get_request_body(self):
        """ get_request_body with environment data content length lower than string length """
        environ = {'wsgi.input': StringIO("""foo"""), 'CONTENT_LENGTH': 10}
        self.assertEqual('foo', self.get_request_body(environ))

    def test_016_get_request_body(self):
        """ get_request_body with environment data content length lower than string length """
        environ = {'wsgi.input': StringIO("""foo"""), 'CONTENT_LENGTH': 'aaa'}
        self.assertFalse(self.get_request_body(environ))

    @patch('examples.acme2certifier_wsgi.create_header')
    @patch('examples.acme2certifier_wsgi.get_url')
    @patch('examples.acme2certifier_wsgi.get_request_body')
    @patch('acme_srv.account.Account.parse')
    def test_017_acct(self, mock_parse, mock_body, mock_url, mock_header):
        """ acct """
        environ = 'environ'
        mock_parse.return_value = {'code': 200, 'data': 'data'}
        self.assertEqual([b'"data"'], self.acct(environ, Mock()))
        self.assertTrue(mock_body.called)
        self.assertTrue(mock_parse.called)
        self.assertTrue(mock_url.called)
        self.assertTrue(mock_header.called)

    @patch('acme_srv.acmechallenge.Acmechallenge.lookup')
    def test_018_acmechallenge_serve(self, mock_lookup):
        """ acmechallenge_serve """
        environ = {'PATH_INFO': 'PATH_INFO', 'REMOTE_ADDR': 'REMOTE_ADDR'}
        mock_lookup.return_value = 'foo'
        self.assertEqual([b'foo'], self.acmechallenge_serve(environ, Mock()))

    @patch('acme_srv.acmechallenge.Acmechallenge.lookup')
    def test_019_acmechallenge_serve(self, mock_lookup):
        """ acmechallenge_serve no key_authorization """
        environ = {'PATH_INFO': 'PATH_INFO', 'REMOTE_ADDR': 'REMOTE_ADDR'}
        mock_lookup.return_value = None
        self.assertEqual([b'NOT FOUND'], self.acmechallenge_serve(environ, Mock()))

    @patch('acme_srv.authorization.Authorization.new_post')
    @patch('acme_srv.authorization.Authorization.new_get')
    def test_020_authz(self, mock_get, mock_post):
        """ authz neither get or post """
        environ = {'foo': 'bar', 'wsgi.input': StringIO("""foo""")}
        self.assertEqual([b'{"status": 405, "message": "Method Not Allowed", "detail": "Wrong request type. Expected POST."}'], self.authz(environ, Mock()))
        self.assertFalse(mock_get.called)
        self.assertFalse(mock_post.called)

    @patch('examples.acme2certifier_wsgi.create_header')
    @patch('acme_srv.authorization.Authorization.new_post')
    @patch('acme_srv.authorization.Authorization.new_get')
    def test_021_authz(self, mock_get, mock_post, mock_header):
        """ authz get """
        environ = {'REQUEST_METHOD': 'GET', 'REMOTE_ADDR': 'REMOTE_ADDR', 'PATH_INFO': 'PATH_INFO', 'wsgi.input': StringIO("""foo""")}
        mock_header.return_value = {'header': 'foo'}
        mock_get.return_value = {'code': 200, 'data': 'data'}
        self.assertEqual([b'"data"'], self.authz(environ, Mock()))
        self.assertTrue(mock_get.called)
        self.assertFalse(mock_post.called)

    @patch('examples.acme2certifier_wsgi.create_header')
    @patch('acme_srv.authorization.Authorization.new_post')
    @patch('acme_srv.authorization.Authorization.new_get')
    def test_022_authz(self, mock_get, mock_post, mock_header):
        """ authz post no content length """
        environ = {'REQUEST_METHOD': 'POST', 'REMOTE_ADDR': 'REMOTE_ADDR', 'PATH_INFO': 'PATH_INFO', 'wsgi.input': StringIO("""foo""")}
        mock_header.return_value = {'header': 'foo'}
        mock_post.return_value = {'code': 200, 'data': 'data'}
        self.assertEqual([b'"data"'], self.authz(environ, Mock()))
        self.assertFalse(mock_get.called)
        self.assertTrue(mock_post.called)

    @patch('examples.acme2certifier_wsgi.create_header')
    @patch('acme_srv.authorization.Authorization.new_post')
    @patch('acme_srv.authorization.Authorization.new_get')
    def test_023_authz(self, mock_get, mock_post, mock_header):
        """ authz post content length int """
        environ = {'CONTENT_LENGTH': 2, 'REQUEST_METHOD': 'POST', 'REMOTE_ADDR': 'REMOTE_ADDR', 'PATH_INFO': 'PATH_INFO', 'wsgi.input': StringIO("""foo""")}
        mock_header.return_value = {'header': 'foo'}
        mock_post.return_value = {'code': 200, 'data': 'data'}
        self.assertEqual([b'"data"'], self.authz(environ, Mock()))
        self.assertFalse(mock_get.called)
        self.assertTrue(mock_post.called)

    @patch('examples.acme2certifier_wsgi.create_header')
    @patch('acme_srv.authorization.Authorization.new_post')
    @patch('acme_srv.authorization.Authorization.new_get')
    def test_024_authz(self, mock_get, mock_post, mock_header):
        """ authz post no content length string """
        environ = {'CONTENT_LENGTH': 'A', 'REQUEST_METHOD': 'POST', 'REMOTE_ADDR': 'REMOTE_ADDR', 'PATH_INFO': 'PATH_INFO', 'wsgi.input': StringIO("""foo""")}
        mock_header.return_value = {'header': 'foo'}
        mock_post.return_value = {'code': 200, 'data': 'data'}
        self.assertEqual([b'"data"'], self.authz(environ, Mock()))
        self.assertFalse(mock_get.called)
        self.assertTrue(mock_post.called)

    def test_025_handle_exception(self):
        """ test exception handler """
        exc_type = FakeDBStore
        exc_value = Mock()
        exc_traceback = Mock()
        self.handle_exception(exc_type, exc_value, exc_traceback)

    @patch('examples.acme2certifier_wsgi.create_header')
    @patch('examples.acme2certifier_wsgi.get_url')
    @patch('examples.acme2certifier_wsgi.get_request_body')
    @patch('acme_srv.account.Account.new')
    def test_026_newaccount(self, mock_new, mock_body, mock_url, mock_header):
        """ new account - post """
        environ = {'REQUEST_METHOD': 'POST', 'REMOTE_ADDR': 'REMOTE_ADDR', 'PATH_INFO': 'PATH_INFO'}
        mock_new.return_value = {'code': 200, 'data': 'data'}
        self.assertEqual([b'"data"'], self.newaccount(environ, Mock()))
        self.assertTrue(mock_body.called)
        self.assertTrue(mock_new.called)
        self.assertTrue(mock_url.called)
        self.assertTrue(mock_header.called)

    @patch('examples.acme2certifier_wsgi.create_header')
    @patch('examples.acme2certifier_wsgi.get_url')
    @patch('examples.acme2certifier_wsgi.get_request_body')
    @patch('acme_srv.account.Account.new')
    def test_027_newaccount(self, mock_new, mock_body, mock_url, mock_header):
        """ newaccount - wrong request method """
        environ = {'REQUEST_METHOD': 'WRONG', 'REMOTE_ADDR': 'REMOTE_ADDR', 'PATH_INFO': 'PATH_INFO'}
        mock_new.return_value = {'code': 200, 'data': 'data'}
        self.assertEqual([b'{"status": 405, "message": "Method Not Allowed", "detail": "Wrong request type. Expected POST."}'], self.newaccount(environ, Mock()))
        self.assertFalse(mock_body.called)
        self.assertFalse(mock_new.called)
        self.assertFalse(mock_url.called)
        self.assertFalse(mock_header.called)

    @patch('examples.acme2certifier_wsgi.create_header')
    @patch('examples.acme2certifier_wsgi.get_url')
    @patch('examples.acme2certifier_wsgi.get_request_body')
    @patch('acme_srv.directory.Directory.directory_get')
    def test_028_directory(self, mock_get, mock_body, mock_url, mock_header):
        """ newaccount - wrong request method """
        environ = {'REMOTE_ADDR': 'REMOTE_ADDR', 'PATH_INFO': 'PATH_INFO'}
        mock_get.return_value = {'code': 200, 'data': 'data'}
        self.assertEqual([b'{"code": 200, "data": "data"}'], self.directory(environ, Mock()))
        self.assertFalse(mock_body.called)
        self.assertTrue(mock_get.called)
        self.assertTrue(mock_url.called)
        self.assertTrue(mock_header.called)

    @patch('examples.acme2certifier_wsgi.get_request_body')
    @patch('examples.acme2certifier_wsgi.create_header')
    @patch('examples.acme2certifier_wsgi.get_url')
    @patch('acme_srv.certificate.Certificate.new_post')
    @patch('acme_srv.certificate.Certificate.new_get')
    def test_029_cert(self, mock_get, mock_post, mock_url, mock_header, mock_body):
        """ cert unknown request method """
        environ = {'REQUEST_METHOD': 'UNK', 'REMOTE_ADDR': 'REMOTE_ADDR', 'PATH_INFO': 'PATH_INFO'}
        mock_header.return_value = {'header': 'foo'}
        # mock_post.return_value = {'code': 200, 'data': 'data'}
        self.assertEqual([b'{"status": 405, "message": "Method Not Allowed", "detail": "Wrong request type. Expected POST."}'], self.cert(environ, Mock()))
        self.assertFalse(mock_get.called)
        self.assertFalse(mock_post.called)
        self.assertTrue(mock_url.called)
        self.assertFalse(mock_header.called)
        self.assertFalse(mock_body.called)

    @patch('examples.acme2certifier_wsgi.get_request_body')
    @patch('examples.acme2certifier_wsgi.create_header')
    @patch('examples.acme2certifier_wsgi.get_url')
    @patch('acme_srv.certificate.Certificate.new_post')
    @patch('acme_srv.certificate.Certificate.new_get')
    def test_030_cert(self, mock_get, mock_post, mock_url, mock_header, mock_body):
        """ cert GET request """
        environ = {'REQUEST_METHOD': 'GET', 'REMOTE_ADDR': 'REMOTE_ADDR', 'PATH_INFO': 'PATH_INFO'}
        mock_header.return_value = {'header': 'foo'}
        mock_get.return_value = {'code': 200, 'data': 'data'}
        self.assertEqual(['data'], self.cert(environ, Mock()))
        self.assertTrue(mock_get.called)
        self.assertFalse(mock_post.called)
        self.assertTrue(mock_url.called)
        self.assertTrue(mock_header.called)
        self.assertFalse(mock_body.called)

    @patch('examples.acme2certifier_wsgi.get_request_body')
    @patch('examples.acme2certifier_wsgi.create_header')
    @patch('examples.acme2certifier_wsgi.get_url')
    @patch('acme_srv.certificate.Certificate.new_post')
    @patch('acme_srv.certificate.Certificate.new_get')
    def test_031_cert(self, mock_get, mock_post, mock_url, mock_header, mock_body):
        """ cert POST request """
        environ = {'REQUEST_METHOD': 'POST', 'REMOTE_ADDR': 'REMOTE_ADDR', 'PATH_INFO': 'PATH_INFO'}
        mock_header.return_value = {'header': 'foo'}
        mock_post.return_value = {'code': 200, 'data': 'data'}
        self.assertEqual([b'data'], self.cert(environ, Mock()))
        self.assertFalse(mock_get.called)
        self.assertTrue(mock_post.called)
        self.assertTrue(mock_url.called)
        self.assertTrue(mock_header.called)
        self.assertTrue(mock_body.called)

    @patch('examples.acme2certifier_wsgi.get_request_body')
    @patch('examples.acme2certifier_wsgi.create_header')
    @patch('examples.acme2certifier_wsgi.get_url')
    @patch('acme_srv.challenge.Challenge.parse')
    @patch('acme_srv.challenge.Challenge.get')
    def test_032_chall(self, mock_get, mock_post, mock_url, mock_header, mock_body):
        """ chall unknown request method """
        environ = {'REQUEST_METHOD': 'UNK', 'REMOTE_ADDR': 'REMOTE_ADDR', 'PATH_INFO': 'PATH_INFO'}
        mock_header.return_value = {'header': 'foo'}
        # mock_post.return_value = {'code': 200, 'data': 'data'}
        self.assertEqual([b'{"status": 405, "message": "Method Not Allowed", "detail": "Wrong request type. Expected POST."}'], self.chall(environ, Mock()))
        self.assertFalse(mock_get.called)
        self.assertFalse(mock_post.called)
        self.assertTrue(mock_url.called)
        self.assertFalse(mock_header.called)
        self.assertFalse(mock_body.called)

    @patch('examples.acme2certifier_wsgi.get_request_body')
    @patch('examples.acme2certifier_wsgi.create_header')
    @patch('examples.acme2certifier_wsgi.get_url')
    @patch('acme_srv.challenge.Challenge.parse')
    @patch('acme_srv.challenge.Challenge.get')
    def test_033_chall(self, mock_get, mock_post, mock_url, mock_header, mock_body):
        """ chall GET request """
        environ = {'REQUEST_METHOD': 'GET', 'REMOTE_ADDR': 'REMOTE_ADDR', 'PATH_INFO': 'PATH_INFO'}
        mock_header.return_value = {'header': 'foo'}
        mock_get.return_value = {'code': 200, 'data': 'data'}
        self.assertEqual([b'"data"'], self.chall(environ, Mock()))
        self.assertTrue(mock_get.called)
        self.assertFalse(mock_post.called)
        self.assertTrue(mock_url.called)
        self.assertFalse(mock_header.called)
        self.assertFalse(mock_body.called)

    @patch('examples.acme2certifier_wsgi.get_request_body')
    @patch('examples.acme2certifier_wsgi.create_header')
    @patch('examples.acme2certifier_wsgi.get_url')
    @patch('acme_srv.challenge.Challenge.parse')
    @patch('acme_srv.challenge.Challenge.get')
    def test_034_chall(self, mock_get, mock_post, mock_url, mock_header, mock_body):
        """ chall POST request """
        environ = {'REQUEST_METHOD': 'POST', 'REMOTE_ADDR': 'REMOTE_ADDR', 'PATH_INFO': 'PATH_INFO'}
        mock_header.return_value = {'header': 'foo'}
        mock_post.return_value = {'code': 200, 'data': 'data'}
        self.assertEqual([b'"data"'], self.chall(environ, Mock()))
        self.assertFalse(mock_get.called)
        self.assertTrue(mock_post.called)
        self.assertTrue(mock_url.called)
        self.assertTrue(mock_header.called)
        self.assertTrue(mock_body.called)

    @patch('examples.acme2certifier_wsgi.get_request_body')
    @patch('examples.acme2certifier_wsgi.create_header')
    @patch('examples.acme2certifier_wsgi.get_url')
    @patch('acme_srv.order.Order.new')
    def test_035_order(self, mock_post, mock_url, mock_header, mock_body):
        """ order POST request """
        environ = {'REQUEST_METHOD': 'POST', 'REMOTE_ADDR': 'REMOTE_ADDR', 'PATH_INFO': 'PATH_INFO'}
        mock_header.return_value = {'header': 'foo'}
        mock_post.return_value = {'code': 200, 'data': 'data'}
        self.assertEqual([b'"data"'], self.neworders(environ, Mock()))
        self.assertTrue(mock_post.called)
        self.assertTrue(mock_url.called)
        self.assertTrue(mock_header.called)
        self.assertTrue(mock_body.called)

    @patch('examples.acme2certifier_wsgi.get_request_body')
    @patch('examples.acme2certifier_wsgi.create_header')
    @patch('examples.acme2certifier_wsgi.get_url')
    @patch('acme_srv.order.Order.new')
    def test_036_order(self, mock_post, mock_url, mock_header, mock_body):
        """ order unknown request type """
        environ = {'REQUEST_METHOD': 'UNK', 'REMOTE_ADDR': 'REMOTE_ADDR', 'PATH_INFO': 'PATH_INFO'}
        mock_header.return_value = {'header': 'foo'}
        mock_post.return_value = {'code': 200, 'data': 'data'}
        self.assertEqual([b'{"status": 405, "message": "Method Not Allowed", "detail": "Wrong request type. Expected POST."}'], self.neworders(environ, Mock()))
        self.assertFalse(mock_post.called)
        self.assertFalse(mock_url.called)
        self.assertFalse(mock_header.called)
        self.assertFalse(mock_body.called)

    @patch('examples.acme2certifier_wsgi.get_request_body')
    @patch('examples.acme2certifier_wsgi.create_header')
    @patch('acme_srv.nonce.Nonce.generate_and_add')
    def test_037_nnonce(self, mock_gen, mock_header, mock_body):
        """ chall GET request """
        environ = {'REQUEST_METHOD': 'GET', 'REMOTE_ADDR': 'REMOTE_ADDR', 'PATH_INFO': 'PATH_INFO'}
        mock_header.return_value = {'header': 'foo'}
        mock_gen.return_value = 'foo'
        self.assertFalse(self.newnonce(environ, Mock()))
        self.assertTrue(mock_gen.called)
        self.assertFalse(mock_header.called)
        self.assertFalse(mock_body.called)

    @patch('acme_srv.nonce.Nonce.generate_and_add')
    def test_038_nnonce(self, mock_gen):
        """ chall HEAD request """
        environ = {'REQUEST_METHOD': 'HEAD', 'REMOTE_ADDR': 'REMOTE_ADDR', 'PATH_INFO': 'PATH_INFO'}
        mock_gen.return_value = 'foo'
        self.assertFalse(self.newnonce(environ, Mock()))
        self.assertTrue(mock_gen.called)

    @patch('acme_srv.nonce.Nonce.generate_and_add')
    def test_039_nnonce(self, mock_gen):
        """ chall HEAD request """
        environ = {'REQUEST_METHOD': 'UNK', 'REMOTE_ADDR': 'REMOTE_ADDR', 'PATH_INFO': 'PATH_INFO'}
        mock_gen.return_value = 'foo'
        self.assertEqual([b'{"status": 405, "message": "Method Not Allowed", "detail": "Wrong request type. Expected HEAD or GET."}'], self.newnonce(environ, Mock()))
        self.assertFalse(mock_gen.called)

    @patch('examples.acme2certifier_wsgi.get_request_body')
    @patch('examples.acme2certifier_wsgi.create_header')
    @patch('examples.acme2certifier_wsgi.get_url')
    @patch('acme_srv.order.Order.parse')
    def test_040_order(self, mock_post, mock_url, mock_header, mock_body):
        """ order POST request """
        environ = {'REQUEST_METHOD': 'POST', 'REMOTE_ADDR': 'REMOTE_ADDR', 'PATH_INFO': 'PATH_INFO'}
        mock_header.return_value = {'header': 'foo'}
        mock_post.return_value = {'code': 200, 'data': 'data'}
        self.assertEqual([b'"data"'], self.order(environ, Mock()))
        self.assertTrue(mock_post.called)
        self.assertTrue(mock_url.called)
        self.assertTrue(mock_header.called)
        self.assertTrue(mock_body.called)

    @patch('examples.acme2certifier_wsgi.get_request_body')
    @patch('examples.acme2certifier_wsgi.create_header')
    @patch('examples.acme2certifier_wsgi.get_url')
    @patch('acme_srv.order.Order.new')
    def test_041_order(self, mock_post, mock_url, mock_header, mock_body):
        """ order unknown request type """
        environ = {'REQUEST_METHOD': 'UNK', 'REMOTE_ADDR': 'REMOTE_ADDR', 'PATH_INFO': 'PATH_INFO'}
        mock_header.return_value = {'header': 'foo'}
        mock_post.return_value = {'code': 200, 'data': 'data'}
        self.assertEqual([b'{"status": 405, "message": "Method Not Allowed", "detail": "Wrong request type. Expected POST."}'], self.order(environ, Mock()))
        self.assertFalse(mock_post.called)
        self.assertFalse(mock_url.called)
        self.assertFalse(mock_header.called)
        self.assertFalse(mock_body.called)

    @patch('examples.acme2certifier_wsgi.get_request_body')
    @patch('examples.acme2certifier_wsgi.create_header')
    @patch('examples.acme2certifier_wsgi.get_url')
    @patch('acme_srv.certificate.Certificate.revoke')
    def test_042_revokecert(self, mock_post, mock_url, mock_header, mock_body):
        """ order POST request """
        environ = {'REQUEST_METHOD': 'POST', 'REMOTE_ADDR': 'REMOTE_ADDR', 'PATH_INFO': 'PATH_INFO'}
        mock_header.return_value = {'header': 'foo'}
        mock_post.return_value = {'code': 200, 'data': 'data'}
        self.assertEqual([b'"data"'], self.revokecert(environ, Mock()))
        self.assertTrue(mock_post.called)
        self.assertTrue(mock_url.called)
        self.assertTrue(mock_header.called)
        self.assertTrue(mock_body.called)

    @patch('examples.acme2certifier_wsgi.get_request_body')
    @patch('examples.acme2certifier_wsgi.create_header')
    @patch('examples.acme2certifier_wsgi.get_url')
    @patch('acme_srv.certificate.Certificate.revoke')
    def test_043_revokecert(self, mock_post, mock_url, mock_header, mock_body):
        """ order POST request """
        environ = {'REQUEST_METHOD': 'POST', 'REMOTE_ADDR': 'REMOTE_ADDR', 'PATH_INFO': 'PATH_INFO'}
        mock_header.return_value = {'header': 'foo'}
        mock_post.return_value = {'code': 200}
        self.assertFalse(self.revokecert(environ, Mock()))
        self.assertTrue(mock_post.called)
        self.assertTrue(mock_url.called)
        self.assertTrue(mock_header.called)
        self.assertTrue(mock_body.called)

    @patch('examples.acme2certifier_wsgi.get_request_body')
    @patch('examples.acme2certifier_wsgi.create_header')
    @patch('examples.acme2certifier_wsgi.get_url')
    @patch('acme_srv.order.Order.new')
    def test_044_revokecert(self, mock_post, mock_url, mock_header, mock_body):
        """ order unknown request type """
        environ = {'REQUEST_METHOD': 'UNK', 'REMOTE_ADDR': 'REMOTE_ADDR', 'PATH_INFO': 'PATH_INFO'}
        mock_header.return_value = {'header': 'foo'}
        mock_post.return_value = {'code': 200, 'data': 'data'}
        self.assertEqual([b'{"status": 405, "message": "Method Not Allowed", "detail": "Wrong request type. Expected POST."}'], self.revokecert(environ, Mock()))
        self.assertFalse(mock_post.called)
        self.assertFalse(mock_url.called)
        self.assertFalse(mock_header.called)
        self.assertFalse(mock_body.called)

    @patch('examples.acme2certifier_wsgi.get_request_body')
    @patch('examples.acme2certifier_wsgi.create_header')
    @patch('examples.acme2certifier_wsgi.get_url')
    @patch('acme_srv.trigger.Trigger.parse')
    def test_044_trigger(self, mock_post, mock_url, mock_header, mock_body):
        """ trigger POST request """
        environ = {'REQUEST_METHOD': 'POST', 'REMOTE_ADDR': 'REMOTE_ADDR', 'PATH_INFO': 'PATH_INFO'}
        mock_header.return_value = {'header': 'foo'}
        mock_post.return_value = {'code': 200, 'data': 'data'}
        self.assertEqual([b'"data"'], self.trigger(environ, Mock()))
        self.assertTrue(mock_post.called)
        self.assertTrue(mock_url.called)
        self.assertTrue(mock_header.called)
        self.assertTrue(mock_body.called)

    @patch('examples.acme2certifier_wsgi.get_request_body')
    @patch('examples.acme2certifier_wsgi.create_header')
    @patch('examples.acme2certifier_wsgi.get_url')
    @patch('acme_srv.trigger.Trigger.parse')
    def test_045_trigger(self, mock_post, mock_url, mock_header, mock_body):
        """ trigger POST request """
        environ = {'REQUEST_METHOD': 'POST', 'REMOTE_ADDR': 'REMOTE_ADDR', 'PATH_INFO': 'PATH_INFO'}
        mock_header.return_value = {'header': 'foo'}
        mock_post.return_value = {'code': 200}
        self.assertFalse(self.trigger(environ, Mock()))
        self.assertTrue(mock_post.called)
        self.assertTrue(mock_url.called)
        self.assertTrue(mock_header.called)
        self.assertTrue(mock_body.called)

    @patch('examples.acme2certifier_wsgi.get_request_body')
    @patch('examples.acme2certifier_wsgi.create_header')
    @patch('examples.acme2certifier_wsgi.get_url')
    @patch('acme_srv.trigger.Trigger.parse')
    def test_046_trigger(self, mock_post, mock_url, mock_header, mock_body):
        """ trigger unknown request type """
        environ = {'REQUEST_METHOD': 'UNK', 'REMOTE_ADDR': 'REMOTE_ADDR', 'PATH_INFO': 'PATH_INFO'}
        mock_header.return_value = {'header': 'foo'}
        mock_post.return_value = {'code': 200, 'data': 'data'}
        self.assertEqual([b'{"status": 405, "message": "Method Not Allowed", "detail": "Wrong request type. Expected POST."}'], self.trigger(environ, Mock()))
        self.assertFalse(mock_post.called)
        self.assertFalse(mock_url.called)
        self.assertFalse(mock_header.called)
        self.assertFalse(mock_body.called)

    def test_046_notfound(self):
        """ notfound """
        environ = {'REQUEST_METHOD': 'UNK', 'REMOTE_ADDR': 'REMOTE_ADDR', 'PATH_INFO': 'PATH_INFO'}
        self.assertEqual([b'{"status": 404, "message": "Not Found", "detail": "Not Found"}'], self.not_found(environ, Mock()))

    def test_047_application(self):
        """ test application function valid pathinfo """
        environ = {'REQUEST_METHOD': 'UNK', 'REMOTE_ADDR': 'REMOTE_ADDR', 'PATH_INFO': 'directory'}
        result_expected = {"newAuthz": "http://localhost/acme/new-authz", "newNonce": "http://localhost/acme/newnonce", "newAccount": "http://localhost/acme/newaccount", "newOrder": "http://localhost/acme/neworders", "revokeCert": "http://localhost/acme/revokecert", "keyChange": "http://localhost/acme/key-change", "meta": {"home": "https://github.com/grindsa/acme2certifier", "author": "grindsa <grindelsack@gmail.com>", "name": "acme2certifier"}}
        result_func = json.loads(self.application(environ, Mock())[0])
        del(result_func['meta']['version'])
        self.assertTrue(result_expected['meta'].items() <= result_func['meta'].items())
        self.assertEqual(result_expected['newAuthz'], result_func['newAuthz'])
        self.assertEqual(result_expected['newNonce'], result_func['newNonce'])
        self.assertEqual(result_expected['newAccount'], result_func['newAccount'])
        self.assertEqual(result_expected['newOrder'], result_func['newOrder'])
        self.assertEqual(result_expected['revokeCert'], result_func['revokeCert'])
        self.assertEqual(result_expected['keyChange'], result_func['keyChange'])

    def test_048_application(self):
        """ test application function wrong pathinfo """
        environ = {'REQUEST_METHOD': 'UNK', 'REMOTE_ADDR': 'REMOTE_ADDR', 'PATH_INFO': 'unk'}
        result_expected = {"newAuthz": "http://localhost/acme/new-authz", "newNonce": "http://localhost/acme/newnonce", "newAccount": "http://localhost/acme/newaccount", "newOrder": "http://localhost/acme/neworders", "revokeCert": "http://localhost/acme/revokecert", "keyChange": "http://localhost/acme/key-change", "meta": {"home": "https://github.com/grindsa/acme2certifier", "author": "grindsa <grindelsack@gmail.com>", "name": "acme2certifier", "version": "0.22"}}
        self.assertEqual([b'{"status": 404, "message": "Not Found", "detail": "Not Found"}'], self.application(environ, Mock()))

    @patch('examples.acme2certifier_wsgi.CONFIG', {'Directory': {'url_prefix': 'url_prefix'}})
    def test_049_application(self):
        """ test application function wrong pathinfo """
        environ = {'REQUEST_METHOD': 'UNK', 'REMOTE_ADDR': 'REMOTE_ADDR', 'PATH_INFO': 'url_prefix/directory'}
        result_expected = {"newAuthz": "http://localhost/acme/new-authz", "newNonce": "http://localhost/acme/newnonce", "newAccount": "http://localhost/acme/newaccount", "newOrder": "http://localhost/acme/neworders", "revokeCert": "http://localhost/acme/revokecert", "keyChange": "http://localhost/acme/key-change", "meta": {"home": "https://github.com/grindsa/acme2certifier", "author": "grindsa <grindelsack@gmail.com>", "name": "acme2certifier"}}
        result_func = json.loads(self.application(environ, Mock())[0])
        del(result_func['meta']['version'])
        self.assertTrue(result_expected['meta'].items() <= result_func['meta'].items())
        self.assertEqual(result_expected['newAuthz'], result_func['newAuthz'])
        self.assertEqual(result_expected['newNonce'], result_func['newNonce'])
        self.assertEqual(result_expected['newAccount'], result_func['newAccount'])
        self.assertEqual(result_expected['newOrder'], result_func['newOrder'])
        self.assertEqual(result_expected['revokeCert'], result_func['revokeCert'])
        self.assertEqual(result_expected['keyChange'], result_func['keyChange'])

    @patch('examples.acme2certifier_wsgi.CONFIG', {'CAhandler': {'acme_url': 'acme_url'}})
    def test_050_application(self):
        """ test application function wrong pathinfo """
        environ = {'REQUEST_METHOD': 'UNK', 'REMOTE_ADDR': 'REMOTE_ADDR', 'PATH_INFO': 'directory'}
        result_expected = {"newAuthz": "http://localhost/acme/new-authz", "newNonce": "http://localhost/acme/newnonce", "newAccount": "http://localhost/acme/newaccount", "newOrder": "http://localhost/acme/neworders", "revokeCert": "http://localhost/acme/revokecert", "keyChange": "http://localhost/acme/key-change", "meta": {"home": "https://github.com/grindsa/acme2certifier", "author": "grindsa <grindelsack@gmail.com>", "name": "acme2certifier"}}
        result_func = json.loads(self.application(environ, Mock())[0])
        del(result_func['meta']['version'])
        self.assertTrue(result_expected['meta'].items() <= result_func['meta'].items())
        self.assertEqual(result_expected['newAuthz'], result_func['newAuthz'])
        self.assertEqual(result_expected['newNonce'], result_func['newNonce'])
        self.assertEqual(result_expected['newAccount'], result_func['newAccount'])
        self.assertEqual(result_expected['newOrder'], result_func['newOrder'])
        self.assertEqual(result_expected['revokeCert'], result_func['revokeCert'])
        self.assertEqual(result_expected['keyChange'], result_func['keyChange'])

    def test_051_get_handler_cls(self):
        """ test get_handler_cls() """
        self.assertTrue('foo', self.get_handler_cls())


    @patch('examples.acme2certifier_wsgi.get_request_body')
    @patch('examples.acme2certifier_wsgi.create_header')
    @patch('acme_srv.housekeeping.Housekeeping.parse')
    def test_051_housekeeping(self, mock_post, mock_header, mock_body):
        """ housekeeping POST request """
        environ = {'REQUEST_METHOD': 'POST', 'REMOTE_ADDR': 'REMOTE_ADDR', 'PATH_INFO': 'PATH_INFO'}
        mock_header.return_value = {'header': 'foo'}
        mock_post.return_value = {'code': 200, 'data': 'data'}
        self.assertEqual([b'"data"'], self.housekeeping(environ, Mock()))
        self.assertTrue(mock_post.called)
        self.assertTrue(mock_header.called)
        self.assertTrue(mock_body.called)

    @patch('examples.acme2certifier_wsgi.get_request_body')
    @patch('examples.acme2certifier_wsgi.create_header')
    @patch('acme_srv.housekeeping.Housekeeping.parse')
    def test_052_housekeeping(self, mock_post, mock_header, mock_body):
        """ housekeeping POST request """
        environ = {'REQUEST_METHOD': 'UNK', 'REMOTE_ADDR': 'REMOTE_ADDR', 'PATH_INFO': 'PATH_INFO'}
        mock_header.return_value = {'header': 'foo'}
        mock_post.return_value = {'code': 200, 'data': 'data'}
        self.assertEqual([b'{"status": 405, "message": "Method Not Allowed", "detail": "Wrong request type. Expected POST."}'], self.housekeeping(environ, Mock()))
        self.assertFalse(mock_post.called)
        self.assertFalse(mock_header.called)
        self.assertFalse(mock_body.called)

    @patch('examples.acme2certifier_wsgi.get_request_body')
    @patch('examples.acme2certifier_wsgi.create_header')
    @patch('acme_srv.housekeeping.Housekeeping.parse')
    def test_053_housekeeping(self, mock_post, mock_header, mock_body):
        """ housekeeping POST request without data """
        environ = {'REQUEST_METHOD': 'POST', 'REMOTE_ADDR': 'REMOTE_ADDR', 'PATH_INFO': 'PATH_INFO'}
        mock_header.return_value = {'header': 'foo'}
        mock_post.return_value = {'code': 200, 'foo': 'bar'}
        self.assertFalse(self.housekeeping(environ, Mock()))
        self.assertTrue(mock_post.called)
        self.assertTrue(mock_header.called)
        self.assertTrue(mock_body.called)


if __name__ == '__main__':

    unittest.main()
