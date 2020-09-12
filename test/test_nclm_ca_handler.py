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
    def test_004_ca_id_lookup(self, mock_req):
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
    def test_005_ca_id_lookup(self, mock_req):
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
    def test_006_ca_id_lookup(self, mock_req):
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
    def test_007_ca_id_lookup(self, mock_req):
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
    def test_008_ca_id_lookup(self, mock_req):
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
    def test_009_ca_id_lookup(self, mock_req):
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
    def test_010_ca_id_lookup(self, mock_req):
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
    def test_011_ca_id_lookup(self, mock_req):
        """ CAhandler._ca_id_lookup() returns ca-list with name matching  and id """
        self.cahandler.api_host = 'api_host'
        self.cahandler.ca_name = 'ca_name'
        self.cahandler.headers = 'headers'
        mockresponse = Mock()
        mock_req.return_value = mockresponse
        mockresponse.json = lambda: {'CAs': [{'name': 'ca_name', 'id': 'id'}]}
        self.assertEqual('id', self.cahandler._ca_id_lookup())

    @patch('requests.get')
    def test_012_ca_id_lookup(self, mock_req):
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
    def test_013_ca_id_lookup(self, mock_req):
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
    def test_014_ca_id_lookup(self, mock_req):
        """ CAhandler._ca_id_lookup() returns ca-list with desc matching  and id """
        self.cahandler.api_host = 'api_host'
        self.cahandler.ca_name = 'ca_name'
        self.cahandler.headers = 'headers'
        mockresponse = Mock()
        mock_req.return_value = mockresponse
        mockresponse.json = lambda: {'CAs': [{'desc': 'ca_name', 'id': 'id'}]}
        self.assertEqual('id', self.cahandler._ca_id_lookup())

    @patch('requests.get')
    def test_015_ca_id_lookup(self, mock_get):
        """ CAhandler._cert_bundle_build() returns everything with one ca cert """
        self.cahandler.api_host = 'api_host'
        self.cahandler.ca_id_list = [1]
        mockresponse1 = Mock()
        mockresponse1.json = lambda: {'certificate': {'der': 'der', 'pem': 'pem'}}
        mockresponse2 = Mock()
        mockresponse2.json = lambda: {'certificate': {'pem': 'pemca'}}
        mock_get.side_effect = [mockresponse1, mockresponse2]
        self.assertEqual((None, 'pempemca', 'der'), self.cahandler._cert_bundle_build('foo'))

    @patch('requests.get')
    def test_016_ca_id_lookup(self, mock_get):
        """ CAhandler._cert_bundle_build() returns everything with two ca cert """
        self.cahandler.api_host = 'api_host'
        self.cahandler.ca_id_list = [1, 2]
        mockresponse1 = Mock()
        mockresponse1.json = lambda: {'certificate': {'der': 'der', 'pem': 'pem'}}
        mockresponse2 = Mock()
        mockresponse2.json = lambda: {'certificate': {'pem': 'pemca1'}}
        mockresponse3 = Mock()
        mockresponse3.json = lambda: {'certificate': {'pem': 'pemca2'}}
        mock_get.side_effect = [mockresponse1, mockresponse2, mockresponse3]
        self.assertEqual((None, 'pempemca1pemca2', 'der'), self.cahandler._cert_bundle_build('foo'))

    @patch('requests.get')
    def test_017_ca_id_lookup(self, mock_get):
        """ CAhandler._cert_bundle_build() returns everything without der in cert_dic """
        self.cahandler.api_host = 'api_host'
        self.cahandler.ca_id_list = [1]
        mockresponse1 = Mock()
        mockresponse1.json = lambda: {'certificate': {'pem': 'pem'}}
        mockresponse2 = Mock()
        mockresponse2.json = lambda: {'certificate': {'pem': 'pemca'}}
        mock_get.side_effect = [mockresponse1, mockresponse2]
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual(('no der certificate returned for id foo', 'pempemca', None), self.cahandler._cert_bundle_build('foo'))
        self.assertIn('ERROR:test_a2c:CAhandler._cert_bundle_build(): no der certificate returned for id: foo', lcm.output)

    @patch('requests.get')
    def test_018_ca_id_lookup(self, mock_get):
        """ CAhandler._cert_bundle_build() returns everything without pem in cert_dic """
        self.cahandler.api_host = 'api_host'
        self.cahandler.ca_id_list = [1]
        mockresponse1 = Mock()
        mockresponse1.json = lambda: {'certificate': {'der': 'der'}}
        mockresponse2 = Mock()
        mockresponse2.json = lambda: {'certificate': {'pem': 'pemca'}}
        mock_get.side_effect = [mockresponse1, mockresponse2]
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual(('no pem certificate returned for id foo', 'pemca', 'der'), self.cahandler._cert_bundle_build('foo'))
        self.assertIn('ERROR:test_a2c:CAhandler._cert_bundle_build(): no pem certificate returned for id: foo', lcm.output)

    @patch('requests.get')
    def test_019_ca_id_lookup(self, mock_get):
        """ CAhandler._cert_bundle_build() returns everything without pem in ca_dic """
        self.cahandler.api_host = 'api_host'
        self.cahandler.ca_id_list = [1]
        mockresponse1 = Mock()
        mockresponse1.json = lambda: {'certificate': {'der': 'der', 'pem': 'pem'}}
        mockresponse2 = Mock()
        mockresponse2.json = lambda: {'certificate': {'foo': 'bar'}}
        mock_get.side_effect = [mockresponse1, mockresponse2]
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual(('no pem ca-certificate returned for id foo', 'pem', 'der'), self.cahandler._cert_bundle_build('foo'))
        self.assertIn('ERROR:test_a2c:CAhandler._cert_bundle_build(): no pem ca-certificate returned for id: foo', lcm.output)

    @patch('requests.get')
    def test_020_ca_id_lookup(self, mock_get):
        """ CAhandler._cert_bundle_build() returns wrong ca_dic """
        self.cahandler.api_host = 'api_host'
        self.cahandler.ca_id_list = [1]
        mockresponse1 = Mock()
        mockresponse1.json = lambda: {'certificate': {'der': 'der', 'pem': 'pem'}}
        mockresponse2 = Mock()
        mockresponse2.json = lambda: {'foo': 'bar'}
        mock_get.side_effect = [mockresponse1, mockresponse2]
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual(('no ca-certificate returned for id: foo', 'pem', 'der'), self.cahandler._cert_bundle_build('foo'))
        self.assertIn('ERROR:test_a2c:CAhandler._cert_bundle_build(): no ca-certificate returned for id: foo', lcm.output)

    @patch('requests.get')
    def test_021_ca_id_lookup(self, mock_get):
        """ CAhandler._cert_bundle_build() returns wrong cert_dic """
        self.cahandler.api_host = 'api_host'
        self.cahandler.ca_id_list = [1]
        mockresponse1 = Mock()
        mockresponse1.json = lambda: {'foo': 'bar'}
        mockresponse2 = Mock()
        mockresponse2.json = lambda: {'foo': 'bar'}
        mock_get.side_effect = [mockresponse1, mockresponse2]
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual(('no certificate returned for id: foo', None, None), self.cahandler._cert_bundle_build('foo'))
        self.assertIn('ERROR:test_a2c:CAhandler._cert_bundle_build(): no certificate returned for id: foo', lcm.output)

if __name__ == '__main__':

    if os.path.exists('acme_test.db'):
        os.remove('acme_test.db')
    unittest.main()
