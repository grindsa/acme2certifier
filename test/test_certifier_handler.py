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
        from examples.ca_handler.certifier_ca_handler import CAhandler
        self.cahandler = CAhandler(False, self.logger)
        # self.cahandler.api_host = 'api_host'
        # self.cahandler.auth = 'auth'

    def test_001_default(self):
        """ default test which always passes """
        self.assertEqual('foo', 'foo')

    @patch('requests.get')
    def test_002_ca_get(self, mock_get):
        """ CAhandler.get_ca() returns an http error """
        self.cahandler.api_host = 'api_host'
        self.cahandler.auth = 'auth'
        mock_get.side_effect = requests.exceptions.HTTPError
        self.assertEqual({'status': 500, 'message': '', 'statusMessage': 'Internal Server Error'}, self.cahandler._ca_get('foo', 'bar'))

    @patch('requests.get')
    def test_003_ca_get(self, mock_get):
        """ CAhandler.get_ca() returns no json file """
        self.cahandler.api_host = 'api_host'
        self.cahandler.auth = 'auth'
        mock_get.status_code = 200
        mock_get.return_value.json = {"bbs": "hahha"}
        self.assertEqual({'status': 500, 'message': "'dict' object is not callable", 'statusMessage': 'Internal Server Error'}, self.cahandler._ca_get('foo', 'bar'))

    @patch('examples.ca_handler.certifier_ca_handler.load_config')
    def test_004_config_load(self, mock_load_cfg):
        """ test _config_load no cahandler section """
        mock_load_cfg.return_value = {}
        self.cahandler._config_load()
        self.assertFalse(self.cahandler.api_host)
        self.assertFalse(self.cahandler.api_user)
        self.assertFalse(self.cahandler.api_password)
        self.assertTrue(self.cahandler.ca_bundle)
        self.assertFalse(self.cahandler.ca_name)
        self.assertEqual(60, self.cahandler.polling_timeout)

    @patch('examples.ca_handler.certifier_ca_handler.load_config')
    def test_005_config_load(self, mock_load_cfg):
        """ test _config_load no api_host parameter """
        mock_load_cfg.return_value = {'CAhandler': {'foo': 'bar'}}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_load()
        self.assertFalse(self.cahandler.api_host)
        self.assertFalse(self.cahandler.api_user)
        self.assertFalse(self.cahandler.api_password)
        self.assertTrue(self.cahandler.ca_bundle)
        self.assertFalse(self.cahandler.ca_name)
        self.assertEqual(60, self.cahandler.polling_timeout)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load() configuration incomplete: "api_host" parameter is missing in config file', lcm.output)

    @patch('examples.ca_handler.certifier_ca_handler.load_config')
    def test_006_config_load(self, mock_load_cfg):
        """ test _config_load no api_user parameter """
        mock_load_cfg.return_value = {'CAhandler': {'api_host': 'api_host', 'foo': 'bar'}}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_load()
        self.assertEqual('api_host', self.cahandler.api_host)
        self.assertFalse(self.cahandler.api_user)
        self.assertFalse(self.cahandler.api_password)
        self.assertTrue(self.cahandler.ca_bundle)
        self.assertFalse(self.cahandler.ca_name)
        self.assertEqual(60, self.cahandler.polling_timeout)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load() configuration incomplete: "api_user" parameter is missing in config file', lcm.output)

    @patch('examples.ca_handler.certifier_ca_handler.load_config')
    def test_007_config_load(self, mock_load_cfg):
        """ test _config_load no api_password parameter """
        mock_load_cfg.return_value = {'CAhandler': {'api_host': 'api_host', 'api_user': 'api_user', 'foo': 'bar'}}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_load()
        self.assertEqual('api_host', self.cahandler.api_host)
        self.assertEqual('api_user', self.cahandler.api_user)
        self.assertFalse(self.cahandler.api_password)
        self.assertTrue(self.cahandler.ca_bundle)
        self.assertFalse(self.cahandler.ca_name)
        self.assertEqual(60, self.cahandler.polling_timeout)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load() configuration incomplete: "api_password" parameter is missing in config file', lcm.output)

    @patch('examples.ca_handler.certifier_ca_handler.load_config')
    def test_008_config_load(self, mock_load_cfg):
        """ test _config_load no ca_name parameter """
        mock_load_cfg.return_value = {'CAhandler': {'api_host': 'api_host', 'api_user': 'api_user', 'api_password': 'api_password', 'foo': 'bar'}}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_load()
        self.assertEqual('api_host', self.cahandler.api_host)
        self.assertEqual('api_user', self.cahandler.api_user)
        self.assertEqual('api_password', self.cahandler.api_password)
        self.assertTrue(self.cahandler.ca_bundle)
        self.assertFalse(self.cahandler.ca_name)
        self.assertEqual(60, self.cahandler.polling_timeout)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load() configuration incomplete: "ca_name" parameter is missing in config file', lcm.output)

    @patch('examples.ca_handler.certifier_ca_handler.load_config')
    def test_009_config_load(self, mock_load_cfg):
        """ test _config_load standard polling interval """
        mock_load_cfg.return_value = {'CAhandler': {'api_host': 'api_host', 'api_user': 'api_user', 'api_password': 'api_password', 'ca_name': 'ca_name', 'foo': 'bar'}}
        self.cahandler._config_load()
        self.assertEqual('api_host', self.cahandler.api_host)
        self.assertEqual('api_user', self.cahandler.api_user)
        self.assertEqual('api_password', self.cahandler.api_password)
        self.assertTrue(self.cahandler.ca_bundle)
        self.assertEqual('ca_name', self.cahandler.ca_name)
        self.assertEqual(60, self.cahandler.polling_timeout)

    @patch('examples.ca_handler.certifier_ca_handler.load_config')
    def test_010_config_load(self, mock_load_cfg):
        """ test _config_load custom polling interval """
        mock_load_cfg.return_value = {'CAhandler': {'api_host': 'api_host', 'api_user': 'api_user', 'api_password': 'api_password', 'ca_name': 'ca_name', 'foo': 'bar', 'polling_timeout': 120}}
        self.cahandler._config_load()
        self.assertEqual('api_host', self.cahandler.api_host)
        self.assertEqual('api_user', self.cahandler.api_user)
        self.assertEqual('api_password', self.cahandler.api_password)
        self.assertTrue(self.cahandler.ca_bundle)
        self.assertEqual('ca_name', self.cahandler.ca_name)
        self.assertEqual(120, self.cahandler.polling_timeout)

    @patch('examples.ca_handler.certifier_ca_handler.load_config')
    def test_011_config_load(self, mock_load_cfg):
        """ test _config_load ca_handler True """
        mock_load_cfg.return_value = {'CAhandler': {'api_host': 'api_host', 'api_user': 'api_user', 'api_password': 'api_password', 'ca_name': 'ca_name', 'foo': 'bar', 'polling_timeout': 120, 'ca_bundle': True}}
        self.cahandler._config_load()
        self.assertEqual('api_host', self.cahandler.api_host)
        self.assertEqual('api_user', self.cahandler.api_user)
        self.assertEqual('api_password', self.cahandler.api_password)
        self.assertTrue(self.cahandler.ca_bundle)
        self.assertEqual('ca_name', self.cahandler.ca_name)
        self.assertEqual(120, self.cahandler.polling_timeout)

    @patch('examples.ca_handler.certifier_ca_handler.load_config')
    def test_012_config_load(self, mock_load_cfg):
        """ test _config_load ca_handler False """
        mock_load_cfg.return_value = {'CAhandler': {'api_host': 'api_host', 'api_user': 'api_user', 'api_password': 'api_password', 'ca_name': 'ca_name', 'foo': 'bar', 'polling_timeout': 120, 'ca_bundle': False}}
        self.cahandler._config_load()
        self.assertEqual('api_host', self.cahandler.api_host)
        self.assertEqual('api_user', self.cahandler.api_user)
        self.assertEqual('api_password', self.cahandler.api_password)
        self.assertFalse(self.cahandler.ca_bundle)
        self.assertEqual('ca_name', self.cahandler.ca_name)
        self.assertEqual(120, self.cahandler.polling_timeout)

    @patch('examples.ca_handler.certifier_ca_handler.load_config')
    def test_013_config_load(self, mock_load_cfg):
        """ test _config_load ca_handler configured """
        mock_load_cfg.return_value = {'CAhandler': {'api_host': 'api_host', 'api_user': 'api_user', 'api_password': 'api_password', 'ca_name': 'ca_name', 'foo': 'bar', 'polling_timeout': 120, 'ca_bundle': 'foo'}}
        self.cahandler._config_load()
        self.assertEqual('api_host', self.cahandler.api_host)
        self.assertEqual('api_user', self.cahandler.api_user)
        self.assertEqual('api_password', self.cahandler.api_password)
        self.assertEqual('foo', self.cahandler.ca_bundle)
        self.assertEqual('ca_name', self.cahandler.ca_name)
        self.assertEqual(120, self.cahandler.polling_timeout)

    def test_011_auth_set(self):
        """ test _auth_set """
        self.cahandler.api_user = 'api_user'
        self.cahandler.api_password = 'api_password'
        self.cahandler._auth_set()
        self.assertTrue(self.cahandler.auth)

    def test_012_auth_set(self):
        """ test _auth_set without api_user """
        self.cahandler.api_user = None
        self.cahandler.api_password = 'api_password'
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._auth_set()
        self.assertFalse(self.cahandler.auth)
        self.assertIn('ERROR:test_a2c:CAhandler._auth_set(): auth information incomplete. Either "api_user" or "api_password" parameter is missing in config file', lcm.output)

    def test_013_auth_set(self):
        """ test _auth_set without api_user """
        self.cahandler.api_user = 'api_user'
        self.cahandler.api_password = None
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._auth_set()
        self.assertFalse(self.cahandler.auth)
        self.assertIn('ERROR:test_a2c:CAhandler._auth_set(): auth information incomplete. Either "api_user" or "api_password" parameter is missing in config file', lcm.output)

    @patch.object(requests, 'post')
    def test_014__api_post(self, mock_req):
        """ test _api_post successful run """
        mockresponse = Mock()
        mock_req.return_value = mockresponse
        mockresponse.json = lambda: {'foo': 'bar'}
        self.assertEqual({'foo': 'bar'}, self.cahandler._api_post('url', 'data'))

    @patch('requests.post')
    def test_015__api_post(self, mock_post):
        """ CAhandler.get_ca() returns an http error """
        self.cahandler.api_host = 'api_host'
        self.cahandler.auth = 'auth'
        mock_post.side_effect = Exception('exc_api_post')
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual('exc_api_post', self.cahandler._api_post('url', 'data'))
        self.assertIn('ERROR:test_a2c:CAhandler._api_post() returned error: exc_api_post', lcm.output)

    @patch.object(requests, 'get')
    def test_016__ca_get(self, mock_req):
        """ test _ca_get successful run """
        self.cahandler.api_host = 'api_host'
        self.cahandler.auth = 'auth'
        mockresponse = Mock()
        mock_req.return_value = mockresponse
        mockresponse.json = lambda: {'foo': 'bar'}
        self.assertEqual({'foo': 'bar'}, self.cahandler._ca_get())

    def test_017__api_post(self):
        """ test _ca_get no api_host"""
        self.cahandler.auth = 'auth'
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual({}, self.cahandler._ca_get())
        self.assertIn('ERROR:test_a2c:CAhandler._ca_get(): api_host is misisng in configuration', lcm.output)

    @patch.object(requests, 'get')
    def test_018__ca_get(self, mock_req):
        """ test _ca_get auth none """
        self.cahandler.api_host = 'api_host'
        mockresponse = Mock()
        mock_req.return_value = mockresponse
        mockresponse.json = lambda: {'foo': 'bar'}
        self.assertEqual({'foo': 'bar'}, self.cahandler._ca_get())

    @patch('requests.get')
    def test_019__api_post(self, mock_get):
        """ CAhandler.get_ca() returns an http error """
        self.cahandler.api_host = 'api_host'
        self.cahandler.auth = 'auth'
        mock_get.side_effect = Exception('exc_ca_get')
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual({'status': 500, 'message': 'exc_ca_get', 'statusMessage': 'Internal Server Error'}, self.cahandler._ca_get())
        self.assertIn('ERROR:test_a2c:CAhandler._ca_get() returned error: exc_ca_get', lcm.output)

    @patch('examples.ca_handler.certifier_ca_handler.CAhandler._ca_get')
    def test_020__ca_get_properties(self, mock_caget):
        """ CAhandler._ca_get_properties() ca_get returns nothing """
        mock_caget.return_value = []
        self.assertEqual({'status': 404, 'message': 'CA could not be found', 'statusMessage': 'Not Found'}, self.cahandler._ca_get_properties('filterkey', 'filtervalue'))

    @patch('examples.ca_handler.certifier_ca_handler.CAhandler._ca_get')
    def test_021__ca_get_properties(self, mock_caget):
        """ CAhandler._ca_get_properties() ca_get returns wrong information """
        mock_caget.return_value = 'foo'
        self.assertEqual({'status': 404, 'message': 'CA could not be found', 'statusMessage': 'Not Found'}, self.cahandler._ca_get_properties('filterkey', 'filtervalue'))

    @patch('examples.ca_handler.certifier_ca_handler.CAhandler._ca_get')
    def test_022__ca_get_properties(self, mock_caget):
        """ CAhandler._ca_get_properties() ca_get returns error message """
        mock_caget.return_value = {'status': 'status', 'message': 'message'}
        self.assertEqual({'message': 'message', 'status': 'status'}, self.cahandler._ca_get_properties('filterkey', 'filtervalue'))

    @patch('examples.ca_handler.certifier_ca_handler.CAhandler._ca_get')
    def test_023__ca_get_properties(self, mock_caget):
        """ CAhandler._ca_get_properties() ca_get returns empty ca_list """
        mock_caget.return_value = {'cas': None}
        self.assertEqual({'status': 404, 'message': 'CA could not be found', 'statusMessage': 'Not Found'}, self.cahandler._ca_get_properties('filterkey', 'filtervalue'))

    @patch('examples.ca_handler.certifier_ca_handler.CAhandler._ca_get')
    def test_024__ca_get_properties(self, mock_caget):
        """ CAhandler._ca_get_properties() ca_get returns ca_list but filter does not match """
        mock_caget.return_value = {'cas': [{'foo': 'bar'}]}
        self.assertEqual({'status': 404, 'message': 'CA could not be found', 'statusMessage': 'Not Found'}, self.cahandler._ca_get_properties('filterkey', 'filtervalue'))

    @patch('examples.ca_handler.certifier_ca_handler.CAhandler._ca_get')
    def test_025__ca_get_properties(self, mock_caget):
        """ CAhandler._ca_get_properties() ca_get returns ca_list but filter matches """
        mock_caget.return_value = {'cas': [{'foo': 'bar'}, {'filterkey': 'filtervalue'}, {'foo1': 'bar1'}]}
        self.assertEqual({'filterkey': 'filtervalue'}, self.cahandler._ca_get_properties('filterkey', 'filtervalue'))

    @patch('examples.ca_handler.certifier_ca_handler.CAhandler._ca_get')
    def test_026__ca_get_properties(self, mock_caget):
        """ CAhandler._ca_get_properties() ca_get returns ca_list another filterkey """
        mock_caget.return_value = {'cas': [{'foo': 'bar'}, {'filterkey': 'filtervalue'}, {'foo1': 'bar1'}]}
        self.assertEqual({'foo': 'bar'}, self.cahandler._ca_get_properties('foo', 'bar'))

    @patch('examples.ca_handler.certifier_ca_handler.CAhandler._ca_get')
    def test_027__ca_get_properties(self, mock_caget):
        """ CAhandler._ca_get_properties() ca_get returns ca_list filterkey check first match"""
        mock_caget.return_value = {'cas': [{'foo': 'bar_bogus'}, {'foo': 'bar'}, {'foo': 'bar1'}, {'foo': 'bar2'}]}
        self.assertEqual({'foo': 'bar'}, self.cahandler._ca_get_properties('foo', 'bar'))

    @patch('examples.ca_handler.certifier_ca_handler.CAhandler._ca_get_properties')
    def test_028__cert_get(self, mock_caget):
        """ CAhandler._ca_get_properties() _ca_get_properties returns empty dic """
        mock_caget.return_value = {}
        self.assertEqual({}, self.cahandler._cert_get('csr'))

    @patch('examples.ca_handler.certifier_ca_handler.CAhandler._api_post')
    @patch('examples.ca_handler.certifier_ca_handler.CAhandler._ca_get_properties')
    def test_020__cert_get(self, mock_caget, mock_post):
        """ CAhandler._ca_get_properties() _ca_get_properties does returns "href" key """
        self.cahandler.api_host = 'api_host'
        mock_caget.return_value = {'href': 'href'}
        mock_post.return_value = {'mock': 'post'}
        self.assertEqual({'mock': 'post'}, self.cahandler._cert_get('csr'))

    @patch('examples.ca_handler.certifier_ca_handler.CAhandler._api_post')
    @patch('examples.ca_handler.certifier_ca_handler.CAhandler._ca_get_properties')
    def test_030__cert_get(self, mock_caget, mock_post):
        """ CAhandler._ca_get_properties() _ca_get_properties returns "href" key but cert_dic is empty """
        self.cahandler.api_host = 'api_host'
        mock_caget.return_value = {'href': 'href'}
        mock_post.return_value = {}
        self.assertEqual({'href': 'href'}, self.cahandler._cert_get('csr'))

    @patch('requests.get')
    def test_031__cert_get_properties(self, mock_req):
        """ CAhandler._cert_get_properties() all good """
        self.cahandler.api_host = 'api_host'
        self.cahandler.auth = 'auth'
        mockresponse = Mock()
        mock_req.return_value = mockresponse
        mockresponse.json = lambda: {'foo': 'bar'}
        self.assertEqual({'foo': 'bar'}, self.cahandler._cert_get_properties('serial', 'link'))

    @patch('requests.get')
    def test_032__cert_get_properties(self, mock_get):
        """ CAhandler._cert_get_properties() all good """
        self.cahandler.api_host = 'api_host'
        self.cahandler.auth = 'auth'
        mock_get.side_effect = Exception('exc_api_get')
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual({'status': 500, 'message': 'exc_api_get', 'statusMessage': 'Internal Server Error'}, self.cahandler._cert_get_properties('serial', 'link'))
        self.assertIn('ERROR:test_a2c:CAhandler._cert_get_properties() returned error: exc_api_get', lcm.output)

    def test_033_poll(self):
        """ CAhandler.poll() poll_identifier is none """
        self.assertEqual((None, None, None, None, False), self.cahandler.poll('cert_name', None, 'csr'))

    @patch('examples.ca_handler.certifier_ca_handler.CAhandler._request_poll')
    def test_034_poll(self, mock_poll):
        """ CAhandler.poll() poll_identifier is none """
        mock_poll.return_value = ('error', 'cert_bundle', 'cert_raw', 'poll_identifier', 'rejected')
        self.assertEqual(('error', 'cert_bundle', 'cert_raw', 'poll_identifier', 'rejected'), self.cahandler.poll('cert_name', 'poll_identifier', 'csr'))

    def test_035__loop_poll(self):
        """ CAhandler._loop_poll() - no request url"""
        request_url = None
        self.assertEqual((None, None, None, None), self.cahandler._loop_poll(request_url))

    @patch('requests.get')
    def test_036__loop_poll(self, mock_get):
        """ CAhandler._loop_poll() - nothing come back from request get"""
        self.cahandler.polling_timeout = 5
        self.cahandler.timeout = 0
        request_url = 'request_url'
        mockresponse = Mock()
        mock_get.return_value = mockresponse
        mockresponse.json = lambda: {}
        self.assertEqual((None, None, None, 'request_url'), self.cahandler._loop_poll(request_url))

    @patch('requests.get')
    def test_037__loop_poll(self, mock_get):
        """ CAhandler._loop_poll() - no status returned from  request get"""
        self.cahandler.polling_timeout = 5
        self.cahandler.timeout = 0
        request_url = 'request_url'
        mockresponse = Mock()
        mock_get.return_value = mockresponse
        mockresponse.json = lambda: {'foo': 'bar'}
        self.assertEqual((None, None, None, 'request_url'), self.cahandler._loop_poll(request_url))

    @patch('requests.get')
    def test_038__loop_poll(self, mock_get):
        """ CAhandler._loop_poll() - status "rejected" returned from  request get"""
        self.cahandler.polling_timeout = 6
        self.cahandler.timeout = 0
        request_url = 'request_url'
        mockresponse = Mock()
        mock_get.return_value = mockresponse
        mockresponse.json = lambda: {'status': 'rejected', 'foo': 'bar'}
        self.assertEqual(('Request rejected by operator', None, None, None), self.cahandler._loop_poll(request_url))

    @patch('requests.get')
    def test_039__loop_poll(self, mock_get):
        """ CAhandler._loop_poll() - status "accepted" returned from  request get but no certificate in"""
        self.cahandler.polling_timeout = 6
        self.cahandler.timeout = 0
        request_url = 'request_url'
        mockresponse = Mock()
        mock_get.return_value = mockresponse
        mockresponse.json = lambda: {'status': 'accepted', 'foo': 'bar'}
        self.assertEqual(('Request accepted but no certificate returned', None, None, 'request_url'), self.cahandler._loop_poll(request_url))

    @patch('requests.get')
    def test_040__loop_poll(self, mock_get):
        """ CAhandler._loop_poll() - status "accepted" returned from  request "certifiate" in but no "certificateBase64" in 2dn request """
        self.cahandler.polling_timeout = 6
        self.cahandler.timeout = 0
        request_url = 'request_url'
        mockresponse = Mock()
        mock_get.return_value = mockresponse
        mockresponse.json = lambda: {'status': 'accepted', 'foo': 'bar', 'certificate': 'certificate'}
        self.assertEqual(('Request accepted but no certificateBase64 returned', None, None, 'request_url'), self.cahandler._loop_poll(request_url))

    @patch('examples.ca_handler.certifier_ca_handler.CAhandler._pem_cert_chain_generate')
    @patch('requests.get')
    def test_041__loop_poll(self, mock_get, mock_chain):
        """ CAhandler._loop_poll() - status "accepted" returned from  request "certifiate" in but no "certificateBase64" in 2dn request """
        self.cahandler.polling_timeout = 6
        self.cahandler.timeout = 0
        request_url = 'request_url'
        mockresponse = Mock()
        mock_get.return_value = mockresponse
        mockresponse.json = lambda: {'status': 'accepted', 'foo': 'bar', 'certificate': 'certificate', 'certificateBase64': 'certificateBase64'}
        mock_chain.return_value = 'foo'
        self.assertEqual((None, 'foo', 'certificateBase64', None), self.cahandler._loop_poll(request_url))

    @patch('examples.ca_handler.certifier_ca_handler.CAhandler._cert_get')
    def test_042_enroll(self, mock_certget):
        """ CAhandler.enroll() _cert_get returns None """
        mock_certget.return_value = {}
        self.assertEqual(('internal error', None, None, None), self.cahandler.enroll('csr'))

    @patch('examples.ca_handler.certifier_ca_handler.CAhandler._cert_get')
    def test_043_enroll(self, mock_certget):
        """ CAhandler.enroll() _cert_get returns wrong information """
        mock_certget.return_value = {'foo': 'bar'}
        self.assertEqual(('no certificate information found', None, None, None), self.cahandler.enroll('csr'))

    @patch('examples.ca_handler.certifier_ca_handler.CAhandler._cert_get')
    def test_044_enroll(self, mock_certget):
        """ CAhandler.enroll() _cert_get returns status without error message """
        mock_certget.return_value = {'foo': 'bar', 'status': 'foo'}
        self.assertEqual(('unknown errror', None, None, None), self.cahandler.enroll('csr'))

    @patch('examples.ca_handler.certifier_ca_handler.CAhandler._cert_get')
    def test_045_enroll(self, mock_certget):
        """ CAhandler.enroll() _cert_get returns status with error message """
        mock_certget.return_value = {'foo': 'bar', 'status': 'foo', 'message': 'message'}
        self.assertEqual(('message', None, None, None), self.cahandler.enroll('csr'))

    @patch('examples.ca_handler.certifier_ca_handler.CAhandler._pem_cert_chain_generate')
    @patch('examples.ca_handler.certifier_ca_handler.CAhandler._cert_get')
    def test_046_enroll(self, mock_certget, mock_chain):
        """ CAhandler.enroll() _cert_get returns certb64 """
        mock_certget.return_value = {'foo': 'bar', 'certificateBase64': 'certificateBase64'}
        mock_chain.return_value = 'mock_chain'
        self.assertEqual((None, 'mock_chain', 'certificateBase64', None), self.cahandler.enroll('csr'))

    @patch('examples.ca_handler.certifier_ca_handler.CAhandler._loop_poll')
    @patch('examples.ca_handler.certifier_ca_handler.CAhandler._cert_get')
    def test_047_enroll(self, mock_certget, mock_loop):
        """ CAhandler.enroll() _cert_get returns certb64 """
        mock_certget.return_value = {'foo': 'bar', 'href': 'href'}
        mock_loop.return_value = ('error', 'cert_bundle', 'cert_raw', 'poll_identifier')
        self.assertEqual(('error', 'cert_bundle', 'cert_raw', 'poll_identifier'), self.cahandler.enroll('csr'))

    @patch('examples.ca_handler.certifier_ca_handler.CAhandler._ca_get_properties')
    def test_048_revoke(self, mock_getca):
        """ CAhandler.revoke() _ca_get_properties returns nothing """
        mock_getca.return_value = {}
        self.assertEqual((404, 'urn:ietf:params:acme:error:serverInternal', 'CA could not be found'), self.cahandler.revoke('cert'))

    @patch('examples.ca_handler.certifier_ca_handler.CAhandler._ca_get_properties')
    def test_049_revoke(self, mock_getca):
        """ CAhandler.revoke() _ca_get_properties returns wrong information """
        mock_getca.return_value = {'foo': 'bar'}
        self.assertEqual((404, 'urn:ietf:params:acme:error:serverInternal', 'CA could not be found'), self.cahandler.revoke('cert'))

    @patch('examples.ca_handler.certifier_ca_handler.cert_serial_get')
    @patch('examples.ca_handler.certifier_ca_handler.CAhandler._ca_get_properties')
    def test_050_revoke(self, mock_getca, mock_serial):
        """ CAhandler.revoke() _ca_get_properties cert_serial_get failed """
        mock_getca.return_value = {'foo': 'bar', 'href': 'href'}
        mock_serial.return_value = None
        self.assertEqual((404, 'urn:ietf:params:acme:error:serverInternal', 'failed to get serial number from cert'), self.cahandler.revoke('cert'))

    @patch('examples.ca_handler.certifier_ca_handler.CAhandler._cert_get_properties')
    @patch('examples.ca_handler.certifier_ca_handler.cert_serial_get')
    @patch('examples.ca_handler.certifier_ca_handler.CAhandler._ca_get_properties')
    def test_051_revoke(self, mock_getca, mock_serial, mock_getcert):
        """ CAhandler.revoke() _ca_get_properties get_cert_properties failed """
        mock_getca.return_value = {'foo': 'bar', 'href': 'href'}
        mock_serial.return_value = 123
        mock_getcert.return_value = {}
        self.assertEqual((404, 'urn:ietf:params:acme:error:serverInternal', 'Cert could not be found'), self.cahandler.revoke('cert'))

    @patch('examples.ca_handler.certifier_ca_handler.CAhandler._cert_get_properties')
    @patch('examples.ca_handler.certifier_ca_handler.cert_serial_get')
    @patch('examples.ca_handler.certifier_ca_handler.CAhandler._ca_get_properties')
    def test_052_revoke(self, mock_getca, mock_serial, mock_getcert):
        """ CAhandler.revoke() _ca_get_properties get_cert_properties returns wrong information """
        mock_getca.return_value = {'foo': 'bar', 'href': 'href'}
        mock_serial.return_value = 123
        mock_getcert.return_value = {'foo': 'bar'}
        self.assertEqual((404, 'urn:ietf:params:acme:error:serverInternal', 'Cert could not be found'), self.cahandler.revoke('cert'))

    @patch('examples.ca_handler.certifier_ca_handler.CAhandler._cert_get_properties')
    @patch('examples.ca_handler.certifier_ca_handler.cert_serial_get')
    @patch('examples.ca_handler.certifier_ca_handler.CAhandler._ca_get_properties')
    def test_053_revoke(self, mock_getca, mock_serial, mock_getcert):
        """ CAhandler.revoke() _ca_get_properties get_cert_properties empty cert_list """
        mock_getca.return_value = {'foo': 'bar', 'href': 'href'}
        mock_serial.return_value = 123
        mock_getcert.return_value = {'foo': 'bar', 'certificates': []}
        self.assertEqual((404, 'urn:ietf:params:acme:error:serverInternal', 'Cert path could not be found'), self.cahandler.revoke('cert'))

    @patch('examples.ca_handler.certifier_ca_handler.CAhandler._cert_get_properties')
    @patch('examples.ca_handler.certifier_ca_handler.cert_serial_get')
    @patch('examples.ca_handler.certifier_ca_handler.CAhandler._ca_get_properties')
    def test_054_revoke(self, mock_getca, mock_serial, mock_getcert):
        """ CAhandler.revoke() _ca_get_properties get_cert_properties returns cert_list with wrong information """
        mock_getca.return_value = {'foo': 'bar', 'href': 'href'}
        mock_serial.return_value = 123
        mock_getcert.return_value = {'foo': 'bar', 'certificates': [{'foo': 'bar'}]}
        self.assertEqual((404, 'urn:ietf:params:acme:error:serverInternal', 'Cert path could not be found'), self.cahandler.revoke('cert'))

    @patch('examples.ca_handler.certifier_ca_handler.CAhandler._api_post')
    @patch('examples.ca_handler.certifier_ca_handler.CAhandler._cert_get_properties')
    @patch('examples.ca_handler.certifier_ca_handler.cert_serial_get')
    @patch('examples.ca_handler.certifier_ca_handler.CAhandler._ca_get_properties')
    def test_055_revoke(self, mock_getca, mock_serial, mock_getcert, mock_post):
        """ CAhandler.revoke() _ca_get_properties get_cert_properties returns cert_list revocation successful """
        mock_getca.return_value = {'foo': 'bar', 'href': 'href'}
        mock_serial.return_value = 123
        mock_getcert.return_value = {'foo': 'bar', 'certificates': [{'foo': 'bar', 'href': 'href'}]}
        mock_post.return_value = {}
        self.assertEqual((200, None, None), self.cahandler.revoke('cert'))

    @patch('examples.ca_handler.certifier_ca_handler.CAhandler._api_post')
    @patch('examples.ca_handler.certifier_ca_handler.CAhandler._cert_get_properties')
    @patch('examples.ca_handler.certifier_ca_handler.cert_serial_get')
    @patch('examples.ca_handler.certifier_ca_handler.CAhandler._ca_get_properties')
    def test_056_revoke(self, mock_getca, mock_serial, mock_getcert, mock_post):
        """ CAhandler.revoke() _ca_get_properties get_cert_properties returns href. revocation returns status without message """
        mock_getca.return_value = {'foo': 'bar', 'href': 'href'}
        mock_serial.return_value = 123
        mock_getcert.return_value = {'foo': 'bar', 'certificates': [{'foo': 'bar', 'href': 'href'}]}
        mock_post.return_value = {'foo': 'bar', 'status': 'status'}
        self.assertEqual((400, 'urn:ietf:params:acme:error:alreadyRevoked', 'no details'), self.cahandler.revoke('cert'))

    @patch('examples.ca_handler.certifier_ca_handler.CAhandler._api_post')
    @patch('examples.ca_handler.certifier_ca_handler.CAhandler._cert_get_properties')
    @patch('examples.ca_handler.certifier_ca_handler.cert_serial_get')
    @patch('examples.ca_handler.certifier_ca_handler.CAhandler._ca_get_properties')
    def test_057_revoke(self, mock_getca, mock_serial, mock_getcert, mock_post):
        """ CAhandler.revoke() _ca_get_properties get_cert_properties returns href. revocation returns status with message """
        mock_getca.return_value = {'foo': 'bar', 'href': 'href'}
        mock_serial.return_value = 123
        mock_getcert.return_value = {'foo': 'bar', 'certificates': [{'foo': 'bar', 'href': 'href'}]}
        mock_post.return_value = {'foo': 'bar', 'status': 'status', 'message': 'message'}
        self.assertEqual((400, 'urn:ietf:params:acme:error:alreadyRevoked', 'message'), self.cahandler.revoke('cert'))

    def test_058_trigger(self):
        """ CAhandler.trigger() - no payload given """
        payload = None
        self.assertEqual(('No payload given', None, None), self.cahandler.trigger(payload))

    @patch('examples.ca_handler.certifier_ca_handler.CAhandler._ca_get_properties')
    @patch('examples.ca_handler.certifier_ca_handler.cert_pem2der')
    @patch('examples.ca_handler.certifier_ca_handler.b64_decode')
    @patch('examples.ca_handler.certifier_ca_handler.b64_encode')
    def test_059_trigger(self, mock_b64dec, mock_b64enc, mock_p2d, mock_caprop):
        """ CAhandler.trigger() - payload  but ca_lookup failed"""
        payload = 'foo'
        mock_b64dec.return_value = 'foodecode'
        mock_p2d.return_value = 'p2d'
        mock_caprop.return_value = {}
        self.assertEqual(('CA could not be found', None, 'foodecode'), self.cahandler.trigger(payload))

    @patch('examples.ca_handler.certifier_ca_handler.cert_serial_get')
    @patch('examples.ca_handler.certifier_ca_handler.CAhandler._ca_get_properties')
    @patch('examples.ca_handler.certifier_ca_handler.cert_pem2der')
    @patch('examples.ca_handler.certifier_ca_handler.b64_decode')
    @patch('examples.ca_handler.certifier_ca_handler.b64_encode')
    def test_060_trigger(self, mock_b64dec, mock_b64enc, mock_p2d, mock_caprop, mock_serial):
        """ CAhandler.trigger() - payload serial number lookup failed"""
        payload = 'foo'
        mock_b64dec.return_value = 'foodecode'
        mock_serial.return_value = None
        mock_p2d.return_value = 'p2d'
        mock_caprop.return_value = {'href': 'href'}
        self.assertEqual(('serial number lookup via rest failed', None, 'foodecode'), self.cahandler.trigger(payload))

    @patch('examples.ca_handler.certifier_ca_handler.CAhandler._cert_get_properties')
    @patch('examples.ca_handler.certifier_ca_handler.cert_serial_get')
    @patch('examples.ca_handler.certifier_ca_handler.CAhandler._ca_get_properties')
    @patch('examples.ca_handler.certifier_ca_handler.cert_pem2der')
    @patch('examples.ca_handler.certifier_ca_handler.b64_decode')
    @patch('examples.ca_handler.certifier_ca_handler.b64_encode')
    def test_061_trigger(self, mock_b64dec, mock_b64enc, mock_p2d, mock_caprop, mock_serial, mock_certprop):
        """ CAhandler.trigger() - payload serial number lookup failed"""
        payload = 'foo'
        mock_b64dec.return_value = 'foodecode'
        mock_serial.return_value = 123
        mock_p2d.return_value = 'p2d'
        mock_caprop.return_value = {'href': 'href'}
        mock_certprop.return_value = {}
        self.assertEqual(('no certifcates found in rest query', None, 'foodecode'), self.cahandler.trigger(payload))

    @patch('examples.ca_handler.certifier_ca_handler.CAhandler._pem_cert_chain_generate')
    @patch('examples.ca_handler.certifier_ca_handler.CAhandler._cert_get_properties')
    @patch('examples.ca_handler.certifier_ca_handler.cert_serial_get')
    @patch('examples.ca_handler.certifier_ca_handler.CAhandler._ca_get_properties')
    @patch('examples.ca_handler.certifier_ca_handler.cert_pem2der')
    @patch('examples.ca_handler.certifier_ca_handler.b64_decode')
    @patch('examples.ca_handler.certifier_ca_handler.b64_encode')
    def test_062_trigger(self, mock_b64dec, mock_b64enc, mock_p2d, mock_caprop, mock_serial, mock_certprop, mock_chain):
        """ CAhandler.trigger() - payload serial number lookup failed"""
        payload = 'foo'
        mock_b64dec.return_value = 'foodecode'
        mock_serial.return_value = 123
        mock_p2d.return_value = 'p2d'
        mock_caprop.return_value = {'href': 'href'}
        mock_certprop.return_value = {'certificates': [{'foo': 'bar'}]}
        mock_chain.return_value = 'chain'
        self.assertEqual((None, 'chain', 'foodecode'), self.cahandler.trigger(payload))

    @patch('examples.ca_handler.certifier_ca_handler.CAhandler._pem_cert_chain_generate')
    @patch('examples.ca_handler.certifier_ca_handler.CAhandler._cert_get_properties')
    @patch('examples.ca_handler.certifier_ca_handler.cert_serial_get')
    @patch('examples.ca_handler.certifier_ca_handler.CAhandler._ca_get_properties')
    @patch('examples.ca_handler.certifier_ca_handler.cert_pem2der')
    @patch('examples.ca_handler.certifier_ca_handler.b64_decode')
    @patch('examples.ca_handler.certifier_ca_handler.b64_encode')
    def test_063_trigger(self, mock_b64dec, mock_b64enc, mock_p2d, mock_caprop, mock_serial, mock_certprop, mock_chain):
        """ CAhandler.trigger() - payload serial number lookup failed"""
        payload = 'foo'
        mock_b64dec.return_value = 'foodecode'
        mock_serial.return_value = 123
        mock_p2d.side_effect = Exception('p2d')
        mock_caprop.return_value = {'href': 'href'}
        mock_certprop.return_value = {'certificates': [{'foo': 'bar'}]}
        mock_chain.return_value = 'chain'
        self.assertEqual((None, 'chain', 'foodecode'), self.cahandler.trigger(payload))

    def test_064__pem_cert_chain_generate(self):
        """ _pem_cert_chain_generate - empty cert_dic """
        cert_dic = {}
        self.assertFalse(self.cahandler._pem_cert_chain_generate(cert_dic))

    def test_065__pem_cert_chain_generate(self):
        """ _pem_cert_chain_generate - wrong dic """
        cert_dic = {'foo': 'bar'}
        self.assertFalse(self.cahandler._pem_cert_chain_generate(cert_dic))

    def test_066__pem_cert_chain_generate(self):
        """ _pem_cert_chain_generate - certificateBase64 in dict """
        cert_dic = {'certificateBase64': 'certificateBase64'}
        self.assertEqual('-----BEGIN CERTIFICATE-----\ncertificateBase64\n-----END CERTIFICATE-----\n', self.cahandler._pem_cert_chain_generate(cert_dic))

    @patch('requests.get')
    def test_067__pem_cert_chain_generate(self, mock_get):
        """ _pem_cert_chain_generate - issuer in dict without certificateBase64 """
        cert_dic = {'issuer': 'issuer'}
        mockresponse = Mock()
        mock_get.return_value = mockresponse
        mockresponse.json = lambda: {'foo': 'bar'}
        self.assertFalse(self.cahandler._pem_cert_chain_generate(cert_dic))

    @patch('requests.get')
    def test_068__pem_cert_chain_generate(self, mock_get):
        """ _pem_cert_chain_generate - request returns "certificates" but no active """
        cert_dic = {'issuer': 'issuer', 'certificateBase64': 'certificateBase641'}
        mockresponse1 = Mock()
        mockresponse1.json = lambda: {'certificates': 'certificates'}
        mockresponse2 = Mock()
        mockresponse2.json = lambda: {'foo': 'bar'}
        mock_get.side_effect = [mockresponse1, mockresponse2]
        self.assertEqual('-----BEGIN CERTIFICATE-----\ncertificateBase641\n-----END CERTIFICATE-----\n', self.cahandler._pem_cert_chain_generate(cert_dic))

    @patch('requests.get')
    def test_069__pem_cert_chain_generate(self, mock_get):
        """ _pem_cert_chain_generate - request returns certificate and active, 2nd request is bogus """
        cert_dic = {'issuer': 'issuer', 'certificateBase64': 'certificateBase641'}
        mockresponse1 = Mock()
        mockresponse1.json = lambda: {'certificates': {'active': 'active'}}
        mockresponse2 = Mock()
        mockresponse2.json = lambda: {'foo': 'bar'}
        mock_get.side_effect = [mockresponse1, mockresponse2]
        self.assertEqual('-----BEGIN CERTIFICATE-----\ncertificateBase641\n-----END CERTIFICATE-----\n', self.cahandler._pem_cert_chain_generate(cert_dic))

    @patch('requests.get')
    def test_070__pem_cert_chain_generate(self, mock_get):
        """ _pem_cert_chain_generate - request returns certificate two certs """
        cert_dic = {'issuer': 'issuer', 'certificateBase64': 'certificateBase641'}
        mockresponse1 = Mock()
        mockresponse1.json = lambda: {'certificates': {'active': 'active'}}
        mockresponse2 = Mock()
        mockresponse2.json = lambda: {'certificateBase64': 'certificateBase642', 'issuer': 'issuer'}
        mockresponse3 = Mock()
        mockresponse3.json = lambda: {'foo': 'bar'}
        mock_get.side_effect = [mockresponse1, mockresponse2, mockresponse3]
        self.assertEqual('-----BEGIN CERTIFICATE-----\ncertificateBase641\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\ncertificateBase642\n-----END CERTIFICATE-----\n', self.cahandler._pem_cert_chain_generate(cert_dic))

    @patch('requests.get')
    def test_071__pem_cert_chain_generate(self, mock_get):
        """ _pem_cert_chain_generate - request returns certificate three certs """
        cert_dic = {'issuer': 'issuer', 'certificateBase64': 'certificateBase641'}
        mockresponse1 = Mock()
        mockresponse1.json = lambda: {'certificates': {'active': 'active'}}
        mockresponse2 = Mock()
        mockresponse2.json = lambda: {'certificateBase64': 'certificateBase642', 'issuer': 'issuer'}
        mockresponse3 = Mock()
        mockresponse3.json = lambda: {'certificates': {'active': 'active'}}
        mockresponse4 = Mock()
        mockresponse4.json = lambda: {'certificateBase64': 'certificateBase643', 'issuer': 'issuer'}
        mockresponse5 = Mock()
        mockresponse5.json = lambda: {'foo': 'bar'}
        mock_get.side_effect = [mockresponse1, mockresponse2, mockresponse3, mockresponse4, mockresponse5]
        self.assertEqual('-----BEGIN CERTIFICATE-----\ncertificateBase641\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\ncertificateBase642\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\ncertificateBase643\n-----END CERTIFICATE-----\n', self.cahandler._pem_cert_chain_generate(cert_dic))

    @patch('requests.get')
    def test_072__pem_cert_chain_generate(self, mock_get):
        """ _pem_cert_chain_generate - issuerCa in """
        cert_dic = {'issuerCa': 'issuerCa', 'certificateBase64': 'certificateBase641'}
        mockresponse1 = Mock()
        mockresponse1.json = lambda: {'certificates': 'certificates'}
        mockresponse2 = Mock()
        mockresponse2.json = lambda: {'foo': 'bar'}
        mock_get.side_effect = [mockresponse1, mockresponse2]
        self.assertEqual('-----BEGIN CERTIFICATE-----\ncertificateBase641\n-----END CERTIFICATE-----\n', self.cahandler._pem_cert_chain_generate(cert_dic))

if __name__ == '__main__':

    if os.path.exists('acme_test.db'):
        os.remove('acme_test.db')
    unittest.main()
