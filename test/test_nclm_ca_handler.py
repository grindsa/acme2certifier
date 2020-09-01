#!/usr/bin/python
# -*- coding: utf-8 -*-
""" unittests for acme2certifier """
# pylint: disable= C0415, W0212
import unittest
import sys
import os
from unittest.mock import patch, Mock
import requests

sys.path.insert(0, '.')
sys.path.insert(1, '..')

class TestACMEHandler(unittest.TestCase):
    """ test class for cgi_handler """

    def setUp(self):
        """ setup unittest """
        import logging
        logging.basicConfig(level=logging.CRITICAL)
        self.logger = logging.getLogger('test_a2c')
        from examples.ca_handler.nclm_ca_handler import CAhandler
        self.cahandler = CAhandler(False, self.logger)
        # self.cahandler.api_host = 'api_host'
        # self.cahandler.auth = 'auth'

    def test_001_default(self):
        """ default test which always passes """
        self.assertEqual('foo', 'foo')

    @patch.object(requests, 'post')
    def test_002__api_post(self, mock_req):
        """ test _api_post successful run """
        mockresponse = Mock()
        mock_req.return_value = mockresponse
        mockresponse.json = lambda: {'foo': 'bar'}
        self.assertEqual({'foo': 'bar'}, self.cahandler._api_post('url', 'data'))

    @patch('requests.post')
    def test_003__api_post(self, mock_post):
        """ CAhandler.get_ca() returns an http error """
        self.cahandler.api_host = 'api_host'
        self.cahandler.auth = 'auth'
        mock_post.side_effect = Exception('exc_api_post')
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual('exc_api_post', self.cahandler._api_post('url', 'data'))
        self.assertIn('ERROR:test_a2c:CAhandler._api_post() returned error: exc_api_post', lcm.output)

    @patch('requests.get')
    def test_004_ca_get(self, mock_req):
        """ CAhandler._ca_id_lookup() returns nothing """
        self.cahandler.api_host = 'api_host'
        self.cahandler.ca_name = 'ca_name'
        self.cahandler.headers = 'headers'
        mockresponse = Mock()
        mock_req.return_value = mockresponse
        mockresponse.json = lambda: {}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertFalse(self.cahandler._ca_id_lookup())
        self.assertIn('ERROR:test_a2c:ca_id.lookup() no CAs found in response ...', lcm.output)

    @patch('requests.get')
    def test_005_ca_get(self, mock_req):
        """ CAhandler._ca_id_lookup() returns wrong data """
        self.cahandler.api_host = 'api_host'
        self.cahandler.ca_name = 'ca_name'
        self.cahandler.headers = 'headers'
        mockresponse = Mock()
        mock_req.return_value = mockresponse
        mockresponse.json = lambda: {'foo': 'bar'}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertFalse(self.cahandler._ca_id_lookup())
        self.assertIn('ERROR:test_a2c:ca_id.lookup() no CAs found in response ...', lcm.output)

    @patch('requests.get')
    def test_006_ca_get(self, mock_req):
        """ CAhandler._ca_id_lookup() returns wrong data """
        self.cahandler.api_host = 'api_host'
        self.cahandler.ca_name = 'ca_name'
        self.cahandler.headers = 'headers'
        mockresponse = Mock()
        mock_req.return_value = mockresponse
        mockresponse.json = lambda: {'foo': 'bar'}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertFalse(self.cahandler._ca_id_lookup())
        self.assertIn('ERROR:test_a2c:ca_id.lookup() no CAs found in response ...', lcm.output)

    @patch('requests.get')
    def test_006_ca_get(self, mock_req):
        """ CAhandler._ca_id_lookup() returns empty ca-list """
        self.cahandler.api_host = 'api_host'
        self.cahandler.ca_name = 'ca_name'
        self.cahandler.headers = 'headers'
        mockresponse = Mock()
        mock_req.return_value = mockresponse
        mockresponse.json = lambda: {'CAs': []}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertFalse(self.cahandler._ca_id_lookup())
        self.assertIn('ERROR:test_a2c:_ca_id_lookup(): no ca id found for ca_name', lcm.output)

    @patch('requests.get')
    def test_007_ca_get(self, mock_req):
        """ CAhandler._ca_id_lookup() returns wrong ca-list """
        self.cahandler.api_host = 'api_host'
        self.cahandler.ca_name = 'ca_name'
        self.cahandler.headers = 'headers'
        mockresponse = Mock()
        mock_req.return_value = mockresponse
        mockresponse.json = lambda: {'CAs': [{'foo': 'foo'}]}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertFalse(self.cahandler._ca_id_lookup())
        self.assertIn('ERROR:test_a2c:_ca_id_lookup(): no ca id found for ca_name', lcm.output)

    @patch('requests.get')
    def test_008_ca_get(self, mock_req):
        """ CAhandler._ca_id_lookup() returns ca-list with name not matching """
        self.cahandler.api_host = 'api_host'
        self.cahandler.ca_name = 'ca_name'
        self.cahandler.headers = 'headers'
        mockresponse = Mock()
        mock_req.return_value = mockresponse
        mockresponse.json = lambda: {'CAs': [{'name': 'foo'}]}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertFalse(self.cahandler._ca_id_lookup())
        self.assertIn('ERROR:test_a2c:_ca_id_lookup(): no ca id found for ca_name', lcm.output)

    @patch('requests.get')
    def test_009_ca_get(self, mock_req):
        """ CAhandler._ca_id_lookup() returns ca-list with name matching  but no id """
        self.cahandler.api_host = 'api_host'
        self.cahandler.ca_name = 'ca_name'
        self.cahandler.headers = 'headers'
        mockresponse = Mock()
        mock_req.return_value = mockresponse
        mockresponse.json = lambda: {'CAs': [{'name': 'ca_name'}]}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertFalse(self.cahandler._ca_id_lookup())
        self.assertIn('ERROR:test_a2c:_ca_id_lookup(): no ca id found for ca_name', lcm.output)

    @patch('requests.get')
    def test_010_ca_get(self, mock_req):
        """ CAhandler._ca_id_lookup() returns ca-list with name matching  and id """
        self.cahandler.api_host = 'api_host'
        self.cahandler.ca_name = 'ca_name'
        self.cahandler.headers = 'headers'
        mockresponse = Mock()
        mock_req.return_value = mockresponse
        mockresponse.json = lambda: {'CAs': [{'name': 'ca_name', 'id': 'id'}]}
        self.assertEqual('id', self.cahandler._ca_id_lookup())

    @patch('requests.get')
    def test_011_ca_get(self, mock_req):
        """ CAhandler._ca_id_lookup() returns ca-list with desc not matching """
        self.cahandler.api_host = 'api_host'
        self.cahandler.ca_name = 'ca_name'
        self.cahandler.headers = 'headers'
        mockresponse = Mock()
        mock_req.return_value = mockresponse
        mockresponse.json = lambda: {'CAs': [{'desc': 'foo'}]}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertFalse(self.cahandler._ca_id_lookup())
        self.assertIn('ERROR:test_a2c:_ca_id_lookup(): no ca id found for ca_name', lcm.output)

    @patch('requests.get')
    def test_012_ca_get(self, mock_req):
        """ CAhandler._ca_id_lookup() returns ca-list with desc matching  but no id """
        self.cahandler.api_host = 'api_host'
        self.cahandler.ca_name = 'ca_name'
        self.cahandler.headers = 'headers'
        mockresponse = Mock()
        mock_req.return_value = mockresponse
        mockresponse.json = lambda: {'CAs': [{'desc': 'ca_name'}]}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertFalse(self.cahandler._ca_id_lookup())
        self.assertIn('ERROR:test_a2c:_ca_id_lookup(): no ca id found for ca_name', lcm.output)

    @patch('requests.get')
    def test_013_ca_get(self, mock_req):
        """ CAhandler._ca_id_lookup() returns ca-list with desc matching  and id """
        self.cahandler.api_host = 'api_host'
        self.cahandler.ca_name = 'ca_name'
        self.cahandler.headers = 'headers'
        mockresponse = Mock()
        mock_req.return_value = mockresponse
        mockresponse.json = lambda: {'CAs': [{'desc': 'ca_name', 'id': 'id'}]}
        self.assertEqual('id', self.cahandler._ca_id_lookup())


if __name__ == '__main__':

    if os.path.exists('acme_test.db'):
        os.remove('acme_test.db')
    unittest.main()
