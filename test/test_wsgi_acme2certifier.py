#!/usr/bin/python
# -*- coding: utf-8 -*-
"""unittests for openssl_ca_handler"""
# pylint: disable=C0415, R0904, R0913, W0212
import sys
import os
import unittest
from unittest.mock import patch, mock_open, Mock, MagicMock
from io import StringIO

# from OpenSSL import crypto
import shutil
import configparser
import json


sys.path.insert(0, ".")
sys.path.insert(1, "..")


class FakeDBStore(object):
    """face DBStore class needed for mocking"""

    # pylint: disable=W0107, R0903
    pass


class TestACMEHandler(unittest.TestCase):
    """test class for cgi_handler"""

    @patch.dict("os.environ", {"ACME_SRV_CONFIGFILE": "ACME_SRV_CONFIGFILE"})
    def setUp(self):
        """setup unittest"""
        import logging
        from examples.acme2certifier_wsgi import (
            create_header,
            get_request_body,
            acct,
            acmechallenge_serve,
            authz,
            handle_exception,
            newaccount,
            directory,
            cert,
            chall,
            neworders,
            newnonce,
            order,
            revokecert,
            trigger,
            not_found,
            application,
            get_handler_cls,
            housekeeping,
            renewalinfo,
        )

        logging.basicConfig(level=logging.CRITICAL)
        self.logger = logging.getLogger("test_a2c")
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
        self.renewalinfo = renewalinfo
        self.start_response = MagicMock()

    def tearDown(self):
        """teardown"""
        pass

    def test_001_default(self):
        """default test which always passes"""
        self.assertEqual("foo", "foo")

    def test_002_create_header(self):
        """create header"""
        response_dic = {}
        result = [("Content-Type", "application/json")]
        self.assertEqual(result, self.create_header(response_dic))

    def test_003_create_header(self):
        """create header unknown response_dic"""
        response_dic = {"foo": "bar"}
        result = [("Content-Type", "application/json")]
        self.assertEqual(result, self.create_header(response_dic))

    def test_004_create_header(self):
        """create header response_dic with header"""
        response_dic = {"header": {"foo": "bar"}}
        result = [("Content-Type", "application/json"), ("foo", "bar")]
        self.assertEqual(result, self.create_header(response_dic))

    def test_005_create_header(self):
        """create header response_dic with header and code = 200"""
        response_dic = {"code": 200, "header": {"foo": "bar"}}
        result = [("Content-Type", "application/json"), ("foo", "bar")]
        self.assertEqual(result, self.create_header(response_dic))

    def test_006_create_header(self):
        """create header response_dic with header and code = 201"""
        response_dic = {"code": 201, "header": {"foo": "bar"}}
        result = [("Content-Type", "application/json"), ("foo", "bar")]
        self.assertEqual(result, self.create_header(response_dic))

    def test_007_create_header(self):
        """create header response_dic with header and code = 400"""
        response_dic = {"code": 400, "header": {"foo": "bar"}}
        result = [("Content-Type", "application/problem+json"), ("foo", "bar")]
        self.assertEqual(result, self.create_header(response_dic))

    def test_008_create_header(self):
        """create header response_dic with header and add_json_header false"""
        response_dic = {"code": 400, "header": {"foo": "bar"}}
        result = [("foo", "bar")]
        self.assertEqual(
            result, self.create_header(response_dic, add_json_header=False)
        )

    def test_009_create_header(self):
        """create header response_dic with header and code = 400 and add_json_header true"""
        response_dic = {"code": 400, "header": {"foo": "bar"}}
        result = [("Content-Type", "application/problem+json"), ("foo", "bar")]
        self.assertEqual(result, self.create_header(response_dic, add_json_header=True))

    def test_010_get_request_body(self):
        """get_request_body with empty environment"""
        environ = {}
        self.assertFalse(self.get_request_body(environ))

    def test_011_get_request_body(self):
        """get_request_body with environment data but no CONTENT_LENGTH specification"""
        environ = {"wsgi.input": StringIO("""foo""")}
        self.assertFalse(self.get_request_body(environ))

    def test_012_get_request_body(self):
        """get_request_body with environment data but CONTENT_LENGTH specification 0 (read full content)"""
        environ = {"wsgi.input": StringIO("""foo"""), "CONTENT_LENGTH": 0}
        self.assertFalse(self.get_request_body(environ))

    def test_013_get_request_body(self):
        """get_request_body with environment data content length lower than string length"""
        environ = {"wsgi.input": StringIO("""foo"""), "CONTENT_LENGTH": 2}
        self.assertEqual("fo", self.get_request_body(environ))

    def test_014_get_request_body(self):
        """get_request_body with environment data content length lower than string length"""
        environ = {"wsgi.input": StringIO("""foo"""), "CONTENT_LENGTH": 3}
        self.assertEqual("foo", self.get_request_body(environ))

    def test_015_get_request_body(self):
        """get_request_body with environment data content length lower than string length"""
        environ = {"wsgi.input": StringIO("""foo"""), "CONTENT_LENGTH": 10}
        self.assertEqual("foo", self.get_request_body(environ))

    def test_016_get_request_body(self):
        """get_request_body with environment data content length lower than string length"""
        environ = {"wsgi.input": StringIO("""foo"""), "CONTENT_LENGTH": "aaa"}
        self.assertFalse(self.get_request_body(environ))

    @patch("examples.acme2certifier_wsgi.create_header")
    @patch("examples.acme2certifier_wsgi.get_url")
    @patch("examples.acme2certifier_wsgi.get_request_body")
    @patch("acme_srv.account.Account.parse")
    def test_017_acct(self, mock_parse, mock_body, mock_url, mock_header):
        """acct"""
        environ = "environ"
        mock_parse.return_value = {"code": 200, "data": "data"}
        self.assertEqual([b'"data"'], self.acct(environ, Mock()))
        self.assertTrue(mock_body.called)
        self.assertTrue(mock_parse.called)
        self.assertTrue(mock_url.called)
        self.assertTrue(mock_header.called)

    @patch("acme_srv.acmechallenge.Acmechallenge.lookup")
    def test_018_acmechallenge_serve(self, mock_lookup):
        """acmechallenge_serve"""
        environ = {"PATH_INFO": "PATH_INFO", "REMOTE_ADDR": "REMOTE_ADDR"}
        mock_lookup.return_value = "foo"
        self.assertEqual([b"foo"], self.acmechallenge_serve(environ, Mock()))

    @patch("acme_srv.acmechallenge.Acmechallenge.lookup")
    def test_019_acmechallenge_serve(self, mock_lookup):
        """acmechallenge_serve no key_authorization"""
        environ = {"PATH_INFO": "PATH_INFO", "REMOTE_ADDR": "REMOTE_ADDR"}
        mock_lookup.return_value = None
        self.assertEqual([b"NOT FOUND"], self.acmechallenge_serve(environ, Mock()))

    @patch("acme_srv.authorization.Authorization.new_post")
    @patch("acme_srv.authorization.Authorization.new_get")
    def test_020_authz(self, mock_get, mock_post):
        """authz neither get or post"""
        environ = {"foo": "bar", "wsgi.input": StringIO("""foo""")}
        self.assertEqual(
            [
                b'{"status": 405, "message": "Method Not Allowed", "detail": "Wrong request type. Expected POST."}'
            ],
            self.authz(environ, Mock()),
        )
        self.assertFalse(mock_get.called)
        self.assertFalse(mock_post.called)

    @patch("examples.acme2certifier_wsgi.create_header")
    @patch("acme_srv.authorization.Authorization.new_post")
    @patch("acme_srv.authorization.Authorization.new_get")
    def test_021_authz(self, mock_get, mock_post, mock_header):
        """authz get"""
        environ = {
            "REQUEST_METHOD": "GET",
            "REMOTE_ADDR": "REMOTE_ADDR",
            "PATH_INFO": "PATH_INFO",
            "wsgi.input": StringIO("""foo"""),
        }
        mock_header.return_value = {"header": "foo"}
        mock_get.return_value = {"code": 200, "data": "data"}
        self.assertEqual([b'"data"'], self.authz(environ, Mock()))
        self.assertTrue(mock_get.called)
        self.assertFalse(mock_post.called)

    @patch("examples.acme2certifier_wsgi.create_header")
    @patch("acme_srv.authorization.Authorization.new_post")
    @patch("acme_srv.authorization.Authorization.new_get")
    def test_022_authz(self, mock_get, mock_post, mock_header):
        """authz post no content length"""
        environ = {
            "REQUEST_METHOD": "POST",
            "REMOTE_ADDR": "REMOTE_ADDR",
            "PATH_INFO": "PATH_INFO",
            "wsgi.input": StringIO("""foo"""),
        }
        mock_header.return_value = {"header": "foo"}
        mock_post.return_value = {"code": 200, "data": "data"}
        self.assertEqual([b'"data"'], self.authz(environ, Mock()))
        self.assertFalse(mock_get.called)
        self.assertTrue(mock_post.called)

    @patch("examples.acme2certifier_wsgi.create_header")
    @patch("acme_srv.authorization.Authorization.new_post")
    @patch("acme_srv.authorization.Authorization.new_get")
    def test_023_authz(self, mock_get, mock_post, mock_header):
        """authz post content length int"""
        environ = {
            "CONTENT_LENGTH": 2,
            "REQUEST_METHOD": "POST",
            "REMOTE_ADDR": "REMOTE_ADDR",
            "PATH_INFO": "PATH_INFO",
            "wsgi.input": StringIO("""foo"""),
        }
        mock_header.return_value = {"header": "foo"}
        mock_post.return_value = {"code": 200, "data": "data"}
        self.assertEqual([b'"data"'], self.authz(environ, Mock()))
        self.assertFalse(mock_get.called)
        self.assertTrue(mock_post.called)

    @patch("examples.acme2certifier_wsgi.create_header")
    @patch("acme_srv.authorization.Authorization.new_post")
    @patch("acme_srv.authorization.Authorization.new_get")
    def test_024_authz(self, mock_get, mock_post, mock_header):
        """authz post no content length string"""
        environ = {
            "CONTENT_LENGTH": "A",
            "REQUEST_METHOD": "POST",
            "REMOTE_ADDR": "REMOTE_ADDR",
            "PATH_INFO": "PATH_INFO",
            "wsgi.input": StringIO("""foo"""),
        }
        mock_header.return_value = {"header": "foo"}
        mock_post.return_value = {"code": 200, "data": "data"}
        self.assertEqual([b'"data"'], self.authz(environ, Mock()))
        self.assertFalse(mock_get.called)
        self.assertTrue(mock_post.called)

    @patch("sys.__excepthook__")
    def test_025_handle_exception_keyboard_interrupt(self, mock_excepthook):
        """test handle_exception with KeyboardInterrupt - should call sys.__excepthook__"""
        exc_type = KeyboardInterrupt
        exc_value = KeyboardInterrupt("Test keyboard interrupt")
        exc_traceback = Mock()

        result = self.handle_exception(exc_type, exc_value, exc_traceback)

        # Verify that sys.__excepthook__ was called with correct parameters
        mock_excepthook.assert_called_once_with(exc_type, exc_value, exc_traceback)
        # Verify function returned None (early return)
        self.assertIsNone(result)

    @patch("sys.__excepthook__")
    def test_026_handle_exception_keyboard_interrupt_subclass(self, mock_excepthook):
        """test handle_exception with KeyboardInterrupt subclass"""

        class CustomKeyboardInterrupt(KeyboardInterrupt):
            pass

        exc_type = CustomKeyboardInterrupt
        exc_value = CustomKeyboardInterrupt("Custom keyboard interrupt")
        exc_traceback = Mock()

        result = self.handle_exception(exc_type, exc_value, exc_traceback)

        # Verify that sys.__excepthook__ was called
        mock_excepthook.assert_called_once_with(exc_type, exc_value, exc_traceback)
        self.assertIsNone(result)

    @patch("examples.acme2certifier_wsgi.LOGGER")
    @patch("sys.__excepthook__")
    def test_027_handle_exception_regular_exception(self, mock_excepthook, mock_logger):
        """test handle_exception with regular exception - should log via LOGGER"""
        exc_type = ValueError
        exc_value = ValueError("Test value error")
        exc_traceback = Mock()

        result = self.handle_exception(exc_type, exc_value, exc_traceback)

        # Verify that sys.__excepthook__ was NOT called
        mock_excepthook.assert_not_called()

        # Verify that LOGGER.exception was called with correct parameters
        mock_logger.exception.assert_called_once_with(
            "Uncaught exception", exc_info=(exc_type, exc_value, exc_traceback)
        )
        self.assertIsNone(result)

    @patch("examples.acme2certifier_wsgi.LOGGER")
    @patch("sys.__excepthook__")
    def test_028_handle_exception_runtime_error(self, mock_excepthook, mock_logger):
        """test handle_exception with RuntimeError"""
        exc_type = RuntimeError
        exc_value = RuntimeError("Test runtime error")
        exc_traceback = Mock()

        result = self.handle_exception(exc_type, exc_value, exc_traceback)

        mock_excepthook.assert_not_called()
        mock_logger.exception.assert_called_once_with(
            "Uncaught exception", exc_info=(exc_type, exc_value, exc_traceback)
        )
        self.assertIsNone(result)

    @patch("examples.acme2certifier_wsgi.LOGGER")
    @patch("sys.__excepthook__")
    def test_029_handle_exception_system_exit(self, mock_excepthook, mock_logger):
        """test handle_exception with SystemExit - should log, not call excepthook"""
        exc_type = SystemExit
        exc_value = SystemExit(1)
        exc_traceback = Mock()

        result = self.handle_exception(exc_type, exc_value, exc_traceback)

        # SystemExit is not a subclass of KeyboardInterrupt, so should log
        mock_excepthook.assert_not_called()
        mock_logger.exception.assert_called_once_with(
            "Uncaught exception", exc_info=(exc_type, exc_value, exc_traceback)
        )
        self.assertIsNone(result)

    @patch("examples.acme2certifier_wsgi.LOGGER")
    @patch("sys.__excepthook__")
    def test_030_handle_exception_exc_info_tuple_format(
        self, mock_excepthook, mock_logger
    ):
        """test that exc_info is passed as correct tuple format"""
        exc_type = RuntimeError
        exc_value = RuntimeError("Test runtime error")
        exc_traceback = Mock()

        self.handle_exception(exc_type, exc_value, exc_traceback)

        # Verify the exc_info parameter is passed as a tuple
        mock_logger.exception.assert_called_once()
        call_args = mock_logger.exception.call_args

        # Check the exc_info keyword argument
        self.assertIn("exc_info", call_args.kwargs)
        exc_info_tuple = call_args.kwargs["exc_info"]

        # Verify it's a tuple with 3 elements
        self.assertIsInstance(exc_info_tuple, tuple)
        self.assertEqual(len(exc_info_tuple), 3)
        self.assertEqual(exc_info_tuple[0], exc_type)
        self.assertEqual(exc_info_tuple[1], exc_value)
        self.assertEqual(exc_info_tuple[2], exc_traceback)

    def test_031_handle_exception_issubclass_check_various_types(self):
        """test that issubclass check works correctly for various exception types"""
        test_cases = [
            (ValueError, False),
            (RuntimeError, False),
            (AttributeError, False),
            (TypeError, False),
            (KeyError, False),
            (IndexError, False),
            (ImportError, False),
            (OSError, False),
            (SystemExit, False),
            (BaseException, False),
            (KeyboardInterrupt, True),
        ]

        for exc_type, should_call_excepthook in test_cases:
            with self.subTest(exc_type=exc_type):
                with patch("examples.acme2certifier_wsgi.LOGGER") as mock_logger:
                    with patch("sys.__excepthook__") as mock_excepthook:
                        exc_value = exc_type("Test exception")
                        exc_traceback = Mock()

                        result = self.handle_exception(
                            exc_type, exc_value, exc_traceback
                        )

                        if should_call_excepthook:
                            mock_excepthook.assert_called_once()
                            mock_logger.exception.assert_not_called()
                        else:
                            mock_excepthook.assert_not_called()
                            mock_logger.exception.assert_called_once()

                        self.assertIsNone(result)

    @patch("examples.acme2certifier_wsgi.create_header")
    @patch("examples.acme2certifier_wsgi.get_url")
    @patch("examples.acme2certifier_wsgi.get_request_body")
    @patch("acme_srv.account.Account.new")
    def test_032_newaccount(self, mock_new, mock_body, mock_url, mock_header):
        """new account - post"""
        environ = {
            "REQUEST_METHOD": "POST",
            "REMOTE_ADDR": "REMOTE_ADDR",
            "PATH_INFO": "PATH_INFO",
        }
        mock_new.return_value = {"code": 200, "data": "data"}
        self.assertEqual([b'"data"'], self.newaccount(environ, Mock()))
        self.assertTrue(mock_body.called)
        self.assertTrue(mock_new.called)
        self.assertTrue(mock_url.called)
        self.assertTrue(mock_header.called)

    @patch("examples.acme2certifier_wsgi.create_header")
    @patch("examples.acme2certifier_wsgi.get_url")
    @patch("examples.acme2certifier_wsgi.get_request_body")
    @patch("acme_srv.account.Account.new")
    def test_033_newaccount(self, mock_new, mock_body, mock_url, mock_header):
        """newaccount - wrong request method"""
        environ = {
            "REQUEST_METHOD": "WRONG",
            "REMOTE_ADDR": "REMOTE_ADDR",
            "PATH_INFO": "PATH_INFO",
        }
        mock_new.return_value = {"code": 200, "data": "data"}
        self.assertEqual(
            [
                b'{"status": 405, "message": "Method Not Allowed", "detail": "Wrong request type. Expected POST."}'
            ],
            self.newaccount(environ, Mock()),
        )
        self.assertFalse(mock_body.called)
        self.assertFalse(mock_new.called)
        self.assertFalse(mock_url.called)
        self.assertFalse(mock_header.called)

    @patch("examples.acme2certifier_wsgi.create_header")
    @patch("examples.acme2certifier_wsgi.get_url")
    @patch("examples.acme2certifier_wsgi.get_request_body")
    @patch("acme_srv.directory.Directory.directory_get")
    def test_034_directory(self, mock_get, mock_body, mock_url, mock_header):
        """newaccount - all ok"""
        environ = {"REMOTE_ADDR": "REMOTE_ADDR", "PATH_INFO": "PATH_INFO"}
        mock_get.return_value = {"code": 200, "data": "data"}
        self.assertEqual(
            [b'{"code": 200, "data": "data"}'], self.directory(environ, Mock())
        )
        self.assertFalse(mock_body.called)
        self.assertTrue(mock_get.called)
        self.assertTrue(mock_url.called)
        self.assertTrue(mock_header.called)

    @patch("examples.acme2certifier_wsgi.create_header")
    @patch("examples.acme2certifier_wsgi.get_url")
    @patch("examples.acme2certifier_wsgi.get_request_body")
    @patch("acme_srv.directory.Directory.directory_get")
    def test_035_directory(self, mock_get, mock_body, mock_url, mock_header):
        """newaccount - directory.get throws an error"""
        environ = {"REMOTE_ADDR": "REMOTE_ADDR", "PATH_INFO": "PATH_INFO"}
        mock_get.return_value = {"code": 500, "error": "error"}
        self.assertEqual(
            [b'{"status": 403, "message": "Forbidden", "detail": "error"}'],
            self.directory(environ, Mock()),
        )
        self.assertFalse(mock_body.called)
        self.assertTrue(mock_get.called)
        self.assertTrue(mock_url.called)
        self.assertTrue(mock_header.called)

    @patch("examples.acme2certifier_wsgi.get_request_body")
    @patch("examples.acme2certifier_wsgi.create_header")
    @patch("examples.acme2certifier_wsgi.get_url")
    @patch("acme_srv.certificate.Certificate.new_post")
    @patch("acme_srv.certificate.Certificate.new_get")
    def test_036_cert(self, mock_get, mock_post, mock_url, mock_header, mock_body):
        """cert unknown request method"""
        environ = {
            "REQUEST_METHOD": "UNK",
            "REMOTE_ADDR": "REMOTE_ADDR",
            "PATH_INFO": "PATH_INFO",
        }
        mock_header.return_value = {"header": "foo"}
        # mock_post.return_value = {'code': 200, 'data': 'data'}
        self.assertEqual(
            [
                b'{"status": 405, "message": "Method Not Allowed", "detail": "Wrong request type. Expected POST."}'
            ],
            self.cert(environ, Mock()),
        )
        self.assertFalse(mock_get.called)
        self.assertFalse(mock_post.called)
        self.assertTrue(mock_url.called)
        self.assertFalse(mock_header.called)
        self.assertFalse(mock_body.called)

    @patch("examples.acme2certifier_wsgi.get_request_body")
    @patch("examples.acme2certifier_wsgi.create_header")
    @patch("examples.acme2certifier_wsgi.get_url")
    @patch("acme_srv.certificate.Certificate.new_post")
    @patch("acme_srv.certificate.Certificate.new_get")
    def test_037_cert(self, mock_get, mock_post, mock_url, mock_header, mock_body):
        """cert GET request"""
        environ = {
            "REQUEST_METHOD": "GET",
            "REMOTE_ADDR": "REMOTE_ADDR",
            "PATH_INFO": "PATH_INFO",
        }
        mock_header.return_value = {"header": "foo"}
        mock_get.return_value = {"code": 200, "data": "data"}
        self.assertEqual(["data"], self.cert(environ, Mock()))
        self.assertTrue(mock_get.called)
        self.assertFalse(mock_post.called)
        self.assertTrue(mock_url.called)
        self.assertTrue(mock_header.called)
        self.assertFalse(mock_body.called)

    @patch("examples.acme2certifier_wsgi.get_request_body")
    @patch("examples.acme2certifier_wsgi.create_header")
    @patch("examples.acme2certifier_wsgi.get_url")
    @patch("acme_srv.certificate.Certificate.new_post")
    @patch("acme_srv.certificate.Certificate.new_get")
    def test_038_cert(self, mock_get, mock_post, mock_url, mock_header, mock_body):
        """cert POST request"""
        environ = {
            "REQUEST_METHOD": "POST",
            "REMOTE_ADDR": "REMOTE_ADDR",
            "PATH_INFO": "PATH_INFO",
        }
        mock_header.return_value = {"header": "foo"}
        mock_post.return_value = {"code": 200, "data": "data"}
        self.assertEqual([b"data"], self.cert(environ, Mock()))
        self.assertFalse(mock_get.called)
        self.assertTrue(mock_post.called)
        self.assertTrue(mock_url.called)
        self.assertTrue(mock_header.called)
        self.assertTrue(mock_body.called)

    @patch("examples.acme2certifier_wsgi.get_request_body")
    @patch("examples.acme2certifier_wsgi.create_header")
    @patch("examples.acme2certifier_wsgi.get_url")
    @patch("acme_srv.challenge.Challenge.parse")
    @patch("acme_srv.challenge.Challenge.get")
    def test_039_chall(self, mock_get, mock_post, mock_url, mock_header, mock_body):
        """chall unknown request method"""
        environ = {
            "REQUEST_METHOD": "UNK",
            "REMOTE_ADDR": "REMOTE_ADDR",
            "PATH_INFO": "PATH_INFO",
        }
        mock_header.return_value = {"header": "foo"}
        # mock_post.return_value = {'code': 200, 'data': 'data'}
        self.assertEqual(
            [
                b'{"status": 405, "message": "Method Not Allowed", "detail": "Wrong request type. Expected POST."}'
            ],
            self.chall(environ, Mock()),
        )
        self.assertFalse(mock_get.called)
        self.assertFalse(mock_post.called)
        self.assertTrue(mock_url.called)
        self.assertFalse(mock_header.called)
        self.assertFalse(mock_body.called)

    @patch("examples.acme2certifier_wsgi.get_request_body")
    @patch("examples.acme2certifier_wsgi.create_header")
    @patch("examples.acme2certifier_wsgi.get_url")
    @patch("acme_srv.challenge.Challenge.parse")
    @patch("acme_srv.challenge.Challenge.get")
    def test_040_chall(self, mock_get, mock_post, mock_url, mock_header, mock_body):
        """chall GET request"""
        environ = {
            "REQUEST_METHOD": "GET",
            "REMOTE_ADDR": "REMOTE_ADDR",
            "PATH_INFO": "PATH_INFO",
        }
        mock_header.return_value = {"header": "foo"}
        mock_get.return_value = {"code": 200, "data": "data"}
        self.assertEqual([b'"data"'], self.chall(environ, Mock()))
        self.assertTrue(mock_get.called)
        self.assertFalse(mock_post.called)
        self.assertTrue(mock_url.called)
        self.assertFalse(mock_header.called)
        self.assertFalse(mock_body.called)

    @patch("examples.acme2certifier_wsgi.get_request_body")
    @patch("examples.acme2certifier_wsgi.create_header")
    @patch("examples.acme2certifier_wsgi.get_url")
    @patch("acme_srv.challenge.Challenge.parse")
    @patch("acme_srv.challenge.Challenge.get")
    def test_041_chall(self, mock_get, mock_post, mock_url, mock_header, mock_body):
        """chall POST request"""
        environ = {
            "REQUEST_METHOD": "POST",
            "REMOTE_ADDR": "REMOTE_ADDR",
            "PATH_INFO": "PATH_INFO",
        }
        mock_header.return_value = {"header": "foo"}
        mock_post.return_value = {"code": 200, "data": "data"}
        self.assertEqual([b'"data"'], self.chall(environ, Mock()))
        self.assertFalse(mock_get.called)
        self.assertTrue(mock_post.called)
        self.assertTrue(mock_url.called)
        self.assertTrue(mock_header.called)
        self.assertTrue(mock_body.called)

    @patch("examples.acme2certifier_wsgi.get_request_body")
    @patch("examples.acme2certifier_wsgi.create_header")
    @patch("examples.acme2certifier_wsgi.get_url")
    @patch("acme_srv.order.Order.new")
    def test_042_order(self, mock_post, mock_url, mock_header, mock_body):
        """order POST request"""
        environ = {
            "REQUEST_METHOD": "POST",
            "REMOTE_ADDR": "REMOTE_ADDR",
            "PATH_INFO": "PATH_INFO",
        }
        mock_header.return_value = {"header": "foo"}
        mock_post.return_value = {"code": 200, "data": "data"}
        self.assertEqual([b'"data"'], self.neworders(environ, Mock()))
        self.assertTrue(mock_post.called)
        self.assertTrue(mock_url.called)
        self.assertTrue(mock_header.called)
        self.assertTrue(mock_body.called)

    @patch("examples.acme2certifier_wsgi.get_request_body")
    @patch("examples.acme2certifier_wsgi.create_header")
    @patch("examples.acme2certifier_wsgi.get_url")
    @patch("acme_srv.order.Order.new")
    def test_043_order(self, mock_post, mock_url, mock_header, mock_body):
        """order unknown request type"""
        environ = {
            "REQUEST_METHOD": "UNK",
            "REMOTE_ADDR": "REMOTE_ADDR",
            "PATH_INFO": "PATH_INFO",
        }
        mock_header.return_value = {"header": "foo"}
        mock_post.return_value = {"code": 200, "data": "data"}
        self.assertEqual(
            [
                b'{"status": 405, "message": "Method Not Allowed", "detail": "Wrong request type. Expected POST."}'
            ],
            self.neworders(environ, Mock()),
        )
        self.assertFalse(mock_post.called)
        self.assertFalse(mock_url.called)
        self.assertFalse(mock_header.called)
        self.assertFalse(mock_body.called)

    @patch("examples.acme2certifier_wsgi.get_request_body")
    @patch("examples.acme2certifier_wsgi.create_header")
    @patch("acme_srv.nonce.Nonce.generate_and_add")
    def test_044_nnonce(self, mock_gen, mock_header, mock_body):
        """chall GET request"""
        environ = {
            "REQUEST_METHOD": "GET",
            "REMOTE_ADDR": "REMOTE_ADDR",
            "PATH_INFO": "PATH_INFO",
        }
        mock_header.return_value = {"header": "foo"}
        mock_gen.return_value = "foo"
        self.assertFalse(self.newnonce(environ, Mock()))
        self.assertTrue(mock_gen.called)
        self.assertFalse(mock_header.called)
        self.assertFalse(mock_body.called)

    @patch("acme_srv.nonce.Nonce.generate_and_add")
    def test_045_nnonce(self, mock_gen):
        """chall HEAD request"""
        environ = {
            "REQUEST_METHOD": "HEAD",
            "REMOTE_ADDR": "REMOTE_ADDR",
            "PATH_INFO": "PATH_INFO",
        }
        mock_gen.return_value = "foo"
        self.assertFalse(self.newnonce(environ, Mock()))
        self.assertTrue(mock_gen.called)

    @patch("acme_srv.nonce.Nonce.generate_and_add")
    def test_046_nnonce(self, mock_gen):
        """chall HEAD request"""
        environ = {
            "REQUEST_METHOD": "UNK",
            "REMOTE_ADDR": "REMOTE_ADDR",
            "PATH_INFO": "PATH_INFO",
        }
        mock_gen.return_value = "foo"
        self.assertEqual(
            [
                b'{"status": 405, "message": "Method Not Allowed", "detail": "Wrong request type. Expected HEAD or GET."}'
            ],
            self.newnonce(environ, Mock()),
        )
        self.assertFalse(mock_gen.called)

    @patch("examples.acme2certifier_wsgi.get_request_body")
    @patch("examples.acme2certifier_wsgi.create_header")
    @patch("examples.acme2certifier_wsgi.get_url")
    @patch("acme_srv.order.Order.parse")
    def test_047_order(self, mock_post, mock_url, mock_header, mock_body):
        """order POST request"""
        environ = {
            "REQUEST_METHOD": "POST",
            "REMOTE_ADDR": "REMOTE_ADDR",
            "PATH_INFO": "PATH_INFO",
        }
        mock_header.return_value = {"header": "foo"}
        mock_post.return_value = {"code": 200, "data": "data"}
        self.assertEqual([b'"data"'], self.order(environ, Mock()))
        self.assertTrue(mock_post.called)
        self.assertTrue(mock_url.called)
        self.assertTrue(mock_header.called)
        self.assertTrue(mock_body.called)

    @patch("examples.acme2certifier_wsgi.get_request_body")
    @patch("examples.acme2certifier_wsgi.create_header")
    @patch("examples.acme2certifier_wsgi.get_url")
    @patch("acme_srv.order.Order.new")
    def test_048_order(self, mock_post, mock_url, mock_header, mock_body):
        """order unknown request type"""
        environ = {
            "REQUEST_METHOD": "UNK",
            "REMOTE_ADDR": "REMOTE_ADDR",
            "PATH_INFO": "PATH_INFO",
        }
        mock_header.return_value = {"header": "foo"}
        mock_post.return_value = {"code": 200, "data": "data"}
        self.assertEqual(
            [
                b'{"status": 405, "message": "Method Not Allowed", "detail": "Wrong request type. Expected POST."}'
            ],
            self.order(environ, Mock()),
        )
        self.assertFalse(mock_post.called)
        self.assertFalse(mock_url.called)
        self.assertFalse(mock_header.called)
        self.assertFalse(mock_body.called)

    @patch("examples.acme2certifier_wsgi.get_request_body")
    @patch("examples.acme2certifier_wsgi.create_header")
    @patch("examples.acme2certifier_wsgi.get_url")
    @patch("acme_srv.certificate.Certificate.revoke")
    def test_049_revokecert(self, mock_post, mock_url, mock_header, mock_body):
        """order POST request"""
        environ = {
            "REQUEST_METHOD": "POST",
            "REMOTE_ADDR": "REMOTE_ADDR",
            "PATH_INFO": "PATH_INFO",
        }
        mock_header.return_value = {"header": "foo"}
        mock_post.return_value = {"code": 200, "data": "data"}
        self.assertEqual([b'"data"'], self.revokecert(environ, Mock()))
        self.assertTrue(mock_post.called)
        self.assertTrue(mock_url.called)
        self.assertTrue(mock_header.called)
        self.assertTrue(mock_body.called)

    @patch("examples.acme2certifier_wsgi.get_request_body")
    @patch("examples.acme2certifier_wsgi.create_header")
    @patch("examples.acme2certifier_wsgi.get_url")
    @patch("acme_srv.certificate.Certificate.revoke")
    def test_050_revokecert(self, mock_post, mock_url, mock_header, mock_body):
        """order POST request"""
        environ = {
            "REQUEST_METHOD": "POST",
            "REMOTE_ADDR": "REMOTE_ADDR",
            "PATH_INFO": "PATH_INFO",
        }
        mock_header.return_value = {"header": "foo"}
        mock_post.return_value = {"code": 200}
        self.assertFalse(self.revokecert(environ, Mock()))
        self.assertTrue(mock_post.called)
        self.assertTrue(mock_url.called)
        self.assertTrue(mock_header.called)
        self.assertTrue(mock_body.called)

    @patch("examples.acme2certifier_wsgi.get_request_body")
    @patch("examples.acme2certifier_wsgi.create_header")
    @patch("examples.acme2certifier_wsgi.get_url")
    @patch("acme_srv.order.Order.new")
    def test_051_revokecert(self, mock_post, mock_url, mock_header, mock_body):
        """order unknown request type"""
        environ = {
            "REQUEST_METHOD": "UNK",
            "REMOTE_ADDR": "REMOTE_ADDR",
            "PATH_INFO": "PATH_INFO",
        }
        mock_header.return_value = {"header": "foo"}
        mock_post.return_value = {"code": 200, "data": "data"}
        self.assertEqual(
            [
                b'{"status": 405, "message": "Method Not Allowed", "detail": "Wrong request type. Expected POST."}'
            ],
            self.revokecert(environ, Mock()),
        )
        self.assertFalse(mock_post.called)
        self.assertFalse(mock_url.called)
        self.assertFalse(mock_header.called)
        self.assertFalse(mock_body.called)

    @patch("examples.acme2certifier_wsgi.get_request_body")
    @patch("examples.acme2certifier_wsgi.create_header")
    @patch("examples.acme2certifier_wsgi.get_url")
    @patch("acme_srv.trigger.Trigger.parse")
    def test_052_trigger(self, mock_post, mock_url, mock_header, mock_body):
        """trigger POST request"""
        environ = {
            "REQUEST_METHOD": "POST",
            "REMOTE_ADDR": "REMOTE_ADDR",
            "PATH_INFO": "PATH_INFO",
        }
        mock_header.return_value = {"header": "foo"}
        mock_post.return_value = {"code": 200, "data": "data"}
        self.assertEqual([b'"data"'], self.trigger(environ, Mock()))
        self.assertTrue(mock_post.called)
        self.assertTrue(mock_url.called)
        self.assertTrue(mock_header.called)
        self.assertTrue(mock_body.called)

    @patch("examples.acme2certifier_wsgi.get_request_body")
    @patch("examples.acme2certifier_wsgi.create_header")
    @patch("examples.acme2certifier_wsgi.get_url")
    @patch("acme_srv.trigger.Trigger.parse")
    def test_053_trigger(self, mock_post, mock_url, mock_header, mock_body):
        """trigger POST request"""
        environ = {
            "REQUEST_METHOD": "POST",
            "REMOTE_ADDR": "REMOTE_ADDR",
            "PATH_INFO": "PATH_INFO",
        }
        mock_header.return_value = {"header": "foo"}
        mock_post.return_value = {"code": 200}
        self.assertFalse(self.trigger(environ, Mock()))
        self.assertTrue(mock_post.called)
        self.assertTrue(mock_url.called)
        self.assertTrue(mock_header.called)
        self.assertTrue(mock_body.called)

    @patch("examples.acme2certifier_wsgi.get_request_body")
    @patch("examples.acme2certifier_wsgi.create_header")
    @patch("examples.acme2certifier_wsgi.get_url")
    @patch("acme_srv.trigger.Trigger.parse")
    def test_054_trigger(self, mock_post, mock_url, mock_header, mock_body):
        """trigger unknown request type"""
        environ = {
            "REQUEST_METHOD": "UNK",
            "REMOTE_ADDR": "REMOTE_ADDR",
            "PATH_INFO": "PATH_INFO",
        }
        mock_header.return_value = {"header": "foo"}
        mock_post.return_value = {"code": 200, "data": "data"}
        self.assertEqual(
            [
                b'{"status": 405, "message": "Method Not Allowed", "detail": "Wrong request type. Expected POST."}'
            ],
            self.trigger(environ, Mock()),
        )
        self.assertFalse(mock_post.called)
        self.assertFalse(mock_url.called)
        self.assertFalse(mock_header.called)
        self.assertFalse(mock_body.called)

    def test_055_notfound(self):
        """notfound"""
        environ = {
            "REQUEST_METHOD": "UNK",
            "REMOTE_ADDR": "REMOTE_ADDR",
            "PATH_INFO": "PATH_INFO",
        }
        self.assertEqual(
            [b'{"status": 404, "message": "Not Found", "detail": "Not Found"}'],
            self.not_found(environ, Mock()),
        )

    @patch("examples.acme2certifier_wsgi.CONFIG", {"Directory": {"url_prefix": ""}})
    def test_056_application(self):
        """Test redirect to /directory when root URL is accessed."""
        self.environ = {
            "REQUEST_METHOD": "GET",
            "PATH_INFO": "",
            "REMOTE_ADDR": "127.0.0.1",
        }
        self.start_response = MagicMock()
        self.environ["PATH_INFO"] = "/"
        response = self.application(self.environ, self.start_response)
        self.start_response.assert_called_with(
            "302 Found", [("Location", "/directory")]
        )
        self.assertEqual(response, [])

    @patch("examples.acme2certifier_wsgi.CONFIG", {"Directory": {"url_prefix": ""}})
    def test_057_application(self):
        """Test accessing the /acme/directory endpoint."""
        self.environ = {
            "REQUEST_METHOD": "GET",
            "PATH_INFO": "",
            "REMOTE_ADDR": "127.0.0.1",
            "PATH_INFO": "/acme/directory",
        }
        with patch("examples.acme2certifier_wsgi.directory", self.directory):
            response = self.application(self.environ, self.start_response)
            self.start_response.assert_called()
            self.assertIsInstance(response, list)

    @patch("examples.acme2certifier_wsgi.CONFIG", {"Directory": {"url_prefix": ""}})
    def test_058_application(self):
        """Test accessing the /acme/acct endpoint."""
        self.environ = {
            "REQUEST_METHOD": "GET",
            "PATH_INFO": "",
            "REMOTE_ADDR": "127.0.0.1",
            "PATH_INFO": "/acme/acct",
        }
        with patch("examples.acme2certifier_wsgi.acct", self.acct):
            response = self.application(self.environ, self.start_response)
            self.start_response.assert_called()
            self.assertIsInstance(response, list)

    @patch("examples.acme2certifier_wsgi.CONFIG", {"Directory": {"url_prefix": ""}})
    def test_059_application(self):
        """Test accessing the /acme/newaccount endpoint."""
        self.environ = {
            "REQUEST_METHOD": "POST",
            "PATH_INFO": "",
            "REMOTE_ADDR": "127.0.0.1",
            "PATH_INFO": "/acme/newaccount",
        }
        with patch("examples.acme2certifier_wsgi.newaccount", self.newaccount):
            response = self.application(self.environ, self.start_response)
            self.start_response.assert_called()
            self.assertIsInstance(response, list)

    @patch("examples.acme2certifier_wsgi.CONFIG", {"Directory": {"url_prefix": ""}})
    def test_060_application(self):
        """Test accessing an unknown endpoint."""
        self.environ = {
            "REQUEST_METHOD": "POST",
            "PATH_INFO": "",
            "REMOTE_ADDR": "127.0.0.1",
            "PATH_INFO": "/unknown/path",
        }
        with patch("examples.acme2certifier_wsgi.not_found", self.not_found):
            response = self.application(self.environ, self.start_response)
            self.start_response.assert_called_with(
                "404 NOT FOUND", [("Content-Type", "text/plain")]
            )
            self.assertIsInstance(response, list)

    @patch("examples.acme2certifier_wsgi.get_request_body")
    @patch("examples.acme2certifier_wsgi.create_header")
    @patch("acme_srv.housekeeping.Housekeeping.parse")
    def test_061_housekeeping(self, mock_post, mock_header, mock_body):
        """housekeeping POST request"""
        environ = {
            "REQUEST_METHOD": "POST",
            "REMOTE_ADDR": "REMOTE_ADDR",
            "PATH_INFO": "PATH_INFO",
        }
        mock_header.return_value = {"header": "foo"}
        mock_post.return_value = {"code": 200, "data": "data"}
        self.assertEqual([b'"data"'], self.housekeeping(environ, Mock()))
        self.assertTrue(mock_post.called)
        self.assertTrue(mock_header.called)
        self.assertTrue(mock_body.called)

    @patch("examples.acme2certifier_wsgi.get_request_body")
    @patch("examples.acme2certifier_wsgi.create_header")
    @patch("acme_srv.housekeeping.Housekeeping.parse")
    def test_062_housekeeping(self, mock_post, mock_header, mock_body):
        """housekeeping POST request"""
        environ = {
            "REQUEST_METHOD": "UNK",
            "REMOTE_ADDR": "REMOTE_ADDR",
            "PATH_INFO": "PATH_INFO",
        }
        mock_header.return_value = {"header": "foo"}
        mock_post.return_value = {"code": 200, "data": "data"}
        self.assertEqual(
            [
                b'{"status": 405, "message": "Method Not Allowed", "detail": "Wrong request type. Expected POST."}'
            ],
            self.housekeeping(environ, Mock()),
        )
        self.assertFalse(mock_post.called)
        self.assertFalse(mock_header.called)
        self.assertFalse(mock_body.called)

    @patch("examples.acme2certifier_wsgi.get_request_body")
    @patch("examples.acme2certifier_wsgi.create_header")
    @patch("acme_srv.housekeeping.Housekeeping.parse")
    def test_063_housekeeping(self, mock_post, mock_header, mock_body):
        """housekeeping POST request without data"""
        environ = {
            "REQUEST_METHOD": "POST",
            "REMOTE_ADDR": "REMOTE_ADDR",
            "PATH_INFO": "PATH_INFO",
        }
        mock_header.return_value = {"header": "foo"}
        mock_post.return_value = {"code": 200, "foo": "bar"}
        self.assertFalse(self.housekeeping(environ, Mock()))
        self.assertTrue(mock_post.called)
        self.assertTrue(mock_header.called)
        self.assertTrue(mock_body.called)

    @patch("examples.acme2certifier_wsgi.get_request_body")
    @patch("examples.acme2certifier_wsgi.create_header")
    @patch("examples.acme2certifier_wsgi.get_url")
    @patch("acme_srv.renewalinfo.Renewalinfo.update")
    @patch("acme_srv.renewalinfo.Renewalinfo.get")
    def test_064_renewalinfo(
        self, mock_get, mock_post, mock_url, mock_header, mock_body
    ):
        """renewalinfo unknown request method"""
        environ = {
            "REQUEST_METHOD": "UNK",
            "REMOTE_ADDR": "REMOTE_ADDR",
            "PATH_INFO": "PATH_INFO",
        }
        mock_header.return_value = {"header": "foo"}
        # mock_post.return_value = {'code': 200, 'data': 'data'}
        self.assertEqual(
            [
                b'{"status": 405, "message": "Method Not Allowed", "detail": "Wrong request type. Expected POST."}'
            ],
            self.renewalinfo(environ, Mock()),
        )
        self.assertFalse(mock_get.called)
        self.assertFalse(mock_post.called)
        self.assertTrue(mock_url.called)
        self.assertFalse(mock_header.called)
        self.assertFalse(mock_body.called)

    @patch("examples.acme2certifier_wsgi.get_request_body")
    @patch("examples.acme2certifier_wsgi.create_header")
    @patch("examples.acme2certifier_wsgi.get_url")
    @patch("acme_srv.renewalinfo.Renewalinfo.update")
    @patch("acme_srv.renewalinfo.Renewalinfo.get")
    def test_065_renewalinfo(
        self, mock_get, mock_post, mock_url, mock_header, mock_body
    ):
        """renewalinfo GET request"""
        environ = {
            "REQUEST_METHOD": "GET",
            "REMOTE_ADDR": "REMOTE_ADDR",
            "PATH_INFO": "PATH_INFO",
        }
        mock_header.return_value = {"header": "foo"}
        mock_get.return_value = {"code": 200, "data": "data"}
        self.assertEqual([b'"data"'], self.renewalinfo(environ, Mock()))
        self.assertTrue(mock_get.called)
        self.assertFalse(mock_post.called)
        self.assertTrue(mock_url.called)
        self.assertTrue(mock_header.called)
        self.assertFalse(mock_body.called)

    @patch("examples.acme2certifier_wsgi.get_request_body")
    @patch("examples.acme2certifier_wsgi.create_header")
    @patch("examples.acme2certifier_wsgi.get_url")
    @patch("acme_srv.renewalinfo.Renewalinfo.update")
    @patch("acme_srv.renewalinfo.Renewalinfo.get")
    def test_066_renewalinfo(
        self, mock_get, mock_post, mock_url, mock_header, mock_body
    ):
        """renewalinfo GET request"""
        environ = {
            "REQUEST_METHOD": "GET",
            "REMOTE_ADDR": "REMOTE_ADDR",
            "PATH_INFO": "PATH_INFO",
        }
        mock_header.return_value = {"header": "foo"}
        mock_get.return_value = {"code": 200}
        self.assertFalse(self.renewalinfo(environ, Mock()))
        self.assertTrue(mock_get.called)
        self.assertFalse(mock_post.called)
        self.assertTrue(mock_url.called)
        self.assertTrue(mock_header.called)
        self.assertFalse(mock_body.called)

    @patch("examples.acme2certifier_wsgi.get_request_body")
    @patch("examples.acme2certifier_wsgi.create_header")
    @patch("examples.acme2certifier_wsgi.get_url")
    @patch("acme_srv.renewalinfo.Renewalinfo.update")
    @patch("acme_srv.renewalinfo.Renewalinfo.get")
    def test_067_renewalinfot(
        self, mock_get, mock_post, mock_url, mock_header, mock_body
    ):
        """renewalinfo POST request"""
        environ = {
            "REQUEST_METHOD": "POST",
            "REMOTE_ADDR": "REMOTE_ADDR",
            "PATH_INFO": "PATH_INFO",
        }
        mock_header.return_value = {"header": "foo"}
        mock_post.return_value = {"code": 200, "data": "data"}
        self.assertEqual([], self.renewalinfo(environ, Mock()))
        self.assertFalse(mock_get.called)
        self.assertTrue(mock_post.called)
        self.assertTrue(mock_url.called)
        self.assertTrue(mock_header.called)
        self.assertTrue(mock_body.called)


if __name__ == "__main__":

    unittest.main()
