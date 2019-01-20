#!/usr/bin/python
# -*- coding: utf-8 -*-
""" unittests for acme2certifier """
import unittest
import sys
import os
import unittest
import requests
from requests.exceptions import HTTPError

try:
    from mock import patch, MagicMock, Mock
except ImportError:
    from unittest.mock import patch, MagicMock, Mock
sys.path.insert(0, '..')


class TestACMEHandler(unittest.TestCase):
    """ test class for cgi_handler """

    def setUp(self):
        """ setup unittest """
        from acme.ca_handler import CAhandler
        self.cahandler = CAhandler(False)
        self.cahandler.api_host = 'api_host'
        self.cahandler.auth = 'auth'

    def test_001_default(self):
        """ default test which always passes """
        self.assertEqual('foo', 'foo')

    @patch('acme.ca_handler.CAhandler.set_auth')
    @patch('requests.get')
    def test_002_get_ca(self, mock_get, mock_auth):
        """ CAhandler.get_ca() returns an http error """
        mock_get.side_effect = requests.exceptions.HTTPError
        self.assertEqual({'status': 500, 'message': '', 'statusMessage': 'Internal Server Error'}, self.cahandler.get_ca('foo', 'bar'))

    @patch('requests.get')
    def test_003_get_ca(self, mock_get):
        """ CAhandler.get_ca() returns an not json file """
        mock_get.status_code = 200
        mock_get.return_value.json = {"bbs": "hahha"}
        self.assertEqual({'status': 500, 'message': "'dict' object is not callable", 'statusMessage': 'Internal Server Error'}, self.cahandler.get_ca('foo', 'bar'))




if __name__ == '__main__':

    if os.path.exists('acme_test.db'):
        os.remove('acme_test.db')
    unittest.main()
