#!/usr/bin/python
# -*- coding: utf-8 -*-
""" unittests for openxpki_ca_handler """
# pylint: disable=C0415, R0904, W0212
import sys
import os
import unittest
from unittest.mock import patch, Mock, MagicMock
import requests
import base64
from OpenSSL import crypto

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
        models_mock = MagicMock()
        models_mock.acme_srv.db_handler.DBstore.return_value = FakeDBStore
        modules = {'acme_srv.db_handler': models_mock}
        patch.dict('sys.modules', modules).start()
        import logging
        from examples.ca_handler.digicert_ca_handler import CAhandler
        logging.basicConfig(level=logging.CRITICAL)
        self.logger = logging.getLogger('test_a2c')
        self.cahandler = CAhandler(False, self.logger)
        self.dir_path = os.path.dirname(os.path.realpath(__file__))

    def test_001_default(self):
        """ default test which always passes """
        self.assertEqual('foo', 'foo')

    @patch('examples.ca_handler.digicert_ca_handler.CAhandler._config_load')
    def test_002__enter__(self, mock_cfg):
        """ test enter  called """
        mock_cfg.return_value = True
        self.cahandler.__enter__()
        self.assertTrue(mock_cfg.called)

    @patch('examples.ca_handler.digicert_ca_handler.CAhandler._config_load')
    def test_003__enter__(self, mock_cfg):
        """ test enter api hosts defined """
        mock_cfg.return_value = True
        self.cahandler.api_key = 'api_key'
        self.cahandler.__enter__()
        self.assertFalse(mock_cfg.called)

    def test_004_poll(self):
        """ test polling """
        self.assertEqual(('Method not implemented.', None, None, 'poll_identifier', False), self.cahandler.poll('cert_name', 'poll_identifier', 'csr'))

    def test_005_trigger(self):
        """ test polling """
        self.assertEqual(('Method not implemented.', None, None), self.cahandler.trigger('payload'))

    @patch.object(requests, 'post')
    def test_009__api_post(self, mock_req):
        """ test _api_post() """
        mockresponse = Mock()
        mockresponse.status_code = 'status_code'
        mockresponse.json = lambda: {'foo': 'bar'}
        mock_req.return_value = mockresponse
        self.assertEqual(('status_code', {'foo': 'bar'}), self.cahandler._api_post('url', 'data'))

    @patch('requests.post')
    def test_010__api_post(self, mock_req):
        """ test _api_post() """
        mockresponse = Mock()
        mockresponse.status_code = 'status_code'
        mockresponse.json = "aaaa"
        mock_req.return_value = mockresponse
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual(('status_code', "'str' object is not callable"), self.cahandler._api_post('url', 'data'))
        self.assertIn("ERROR:test_a2c:request_operation returned error during json parsing: 'str' object is not callable", lcm.output)

    @patch('requests.post')
    def test_011__api_post(self, mock_req):
        """ test _api_post() """
        mockresponse = Mock()
        mockresponse.status_code = 'status_code'
        mockresponse.text = None
        mock_req.return_value = mockresponse
        self.assertEqual(('status_code', None), self.cahandler._api_post('url', 'data'))

    @patch('requests.post')
    def test_012__api_post(self, mock_req):
        """ test _api_post(= """
        self.cahandler.api_host = 'api_host'
        self.cahandler.auth = 'auth'
        mock_req.side_effect = Exception('exc_api_post')
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual((500, 'exc_api_post'), self.cahandler._api_post('url', 'data'))
        self.assertIn('ERROR:test_a2c:request_operation returned error: exc_api_post', lcm.output)

    @patch.object(requests, 'get')
    def test_013__api_get(self, mock_req):
        """ test _api_get() """
        mockresponse = Mock()
        mockresponse.status_code = 'status_code'
        mockresponse.json = lambda: {'foo': 'bar'}
        mock_req.return_value = mockresponse
        self.assertEqual(('status_code', {'foo': 'bar'}), self.cahandler._api_get('url'))

    @patch('requests.get')
    def test_014__api_get(self, mock_req):
        """ test _api_get() """
        mockresponse = Mock()
        mockresponse.status_code = 'status_code'
        mockresponse.json = "aaaa"
        mock_req.return_value = mockresponse
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual(('status_code', "'str' object is not callable"), self.cahandler._api_get('url'))
        self.assertIn("ERROR:test_a2c:request_operation returned error during json parsing: 'str' object is not callable", lcm.output)

    @patch('requests.get')
    def test_015__api_get(self, mock_req):
        """ test _api_get() """
        self.cahandler.api_host = 'api_host'
        self.cahandler.auth = 'auth'
        mock_req.side_effect = Exception('exc_api_get')
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual((500, 'exc_api_get'), self.cahandler._api_get('url'))
        self.assertIn('ERROR:test_a2c:request_operation returned error: exc_api_get', lcm.output)

    @patch.object(requests, 'put')
    def test_016__api_put(self, mock_req):
        """ test _api_put() """
        mockresponse = Mock()
        mockresponse.status_code = 'status_code'
        mockresponse.json = lambda: {'foo': 'bar'}
        mock_req.return_value = mockresponse
        self.assertEqual(('status_code', {'foo': 'bar'}), self.cahandler._api_put('url', 'data'))

    @patch('requests.put')
    def test_017__api_put(self, mock_req):
        """ test _api_put() """
        mockresponse = Mock()
        mockresponse.status_code = 'status_code'
        mockresponse.json = "aaaa"
        mock_req.return_value = mockresponse
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual(('status_code', "'str' object is not callable"), self.cahandler._api_put('url', 'data'))
        self.assertIn("ERROR:test_a2c:request_operation returned error during json parsing: 'str' object is not callable", lcm.output)

    @patch('requests.put')
    def test_018__api_put(self, mock_req):
        """ test _api_put() """
        mockresponse = Mock()
        mockresponse.status_code = 'status_code'
        mockresponse.text = None
        mock_req.return_value = mockresponse
        self.assertEqual(('status_code', None), self.cahandler._api_put('url', 'data'))

    @patch('requests.put')
    def test_019__api_put(self, mock_req):
        """ test _api_put() """
        self.cahandler.api_host = 'api_host'
        self.cahandler.auth = 'auth'
        mock_req.side_effect = Exception('exc_api_put')
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual((500, 'exc_api_put'), self.cahandler._api_put('url', 'data'))
        self.assertIn('ERROR:test_a2c:request_operation returned error: exc_api_put', lcm.output)

    def test_020__config_check(self):
        """ test _config_check() """
        self.cahandler.api_url = 'api_url'
        self.assertEqual('api_key parameter in missing in config file', self.cahandler._config_check())

    def test_021__config_check(self):
        """ test _config_check() """
        self.cahandler.api_url = 'api_url'
        self.cahandler.api_key = 'api_key'
        self.assertEqual('organization_name parameter in missing in config file', self.cahandler._config_check())

    def test_022__config_check(self):
        """ test _config_check() """
        self.cahandler.api_url = 'api_url'
        self.cahandler.api_key = 'api_key'
        self.cahandler.organization_name = 'organization_name'
        self.assertFalse(self.cahandler._config_check())

    @patch('examples.ca_handler.digicert_ca_handler.config_headerinfo_load')
    @patch('examples.ca_handler.digicert_ca_handler.config_eab_profile_load')
    @patch('examples.ca_handler.digicert_ca_handler.load_config')
    def test_023_config_load(self, mock_load, mock_eab, mock_hdl):
        """ test _config_load() """
        mock_load.return_value = {'foo': 'bar'}
        mock_eab.return_value = True, 'eab'
        mock_hdl.return_value = 'hdl'
        self.cahandler._config_load()
        self.assertTrue(mock_load.called)
        self.assertEqual('https://www.digicert.com/services/v2/', self.cahandler.api_url)
        self.assertFalse(self.cahandler.api_key)
        self.assertEqual('ssl_basic', self.cahandler.cert_type)
        self.assertEqual('sha256', self.cahandler.signature_hash)
        self.assertEqual(1, self.cahandler.order_validity)
        self.assertEqual(10, self.cahandler.request_timeout)
        self.assertFalse(self.cahandler.organization_name)
        self.assertFalse(self.cahandler.organization_id)
        self.assertFalse(self.cahandler.allowed_domainlist)
        self.assertTrue(self.cahandler.eab_profiling)
        self.assertEqual('eab', self.cahandler.eab_handler)
        self.assertEqual('hdl', self.cahandler.header_info_field)

    @patch('examples.ca_handler.digicert_ca_handler.config_headerinfo_load')
    @patch('examples.ca_handler.digicert_ca_handler.config_eab_profile_load')
    @patch('examples.ca_handler.digicert_ca_handler.load_config')
    def test_024_config_load(self, mock_load, mock_eab, mock_hdl):
        """ test _config_load() """
        mock_load.return_value = {'foo': 'bar', 'CAhandler': {'api_url': 'api_url'}}
        mock_eab.return_value = True, 'eab'
        mock_hdl.return_value = 'hdl'
        self.cahandler._config_load()
        self.assertTrue(mock_load.called)
        self.assertEqual('api_url', self.cahandler.api_url)
        self.assertFalse(self.cahandler.api_key)
        self.assertEqual('ssl_basic', self.cahandler.cert_type)
        self.assertEqual('sha256', self.cahandler.signature_hash)
        self.assertEqual(1, self.cahandler.order_validity)
        self.assertEqual(10, self.cahandler.request_timeout)
        self.assertFalse(self.cahandler.organization_name)
        self.assertFalse(self.cahandler.organization_id)
        self.assertFalse(self.cahandler.allowed_domainlist)
        self.assertTrue(self.cahandler.eab_profiling)
        self.assertEqual('eab', self.cahandler.eab_handler)
        self.assertEqual('hdl', self.cahandler.header_info_field)

    @patch('examples.ca_handler.digicert_ca_handler.config_headerinfo_load')
    @patch('examples.ca_handler.digicert_ca_handler.config_eab_profile_load')
    @patch('examples.ca_handler.digicert_ca_handler.load_config')
    def test_025_config_load(self, mock_load, mock_eab, mock_hdl):
        """ test _config_load() """
        mock_load.return_value = {'foo': 'bar', 'CAhandler': {'api_key': 'api_key'}}
        mock_eab.return_value = True, 'eab'
        mock_hdl.return_value = 'hdl'
        self.cahandler._config_load()
        self.assertTrue(mock_load.called)
        self.assertEqual('https://www.digicert.com/services/v2/', self.cahandler.api_url)
        self.assertEqual('api_key', self.cahandler.api_key)
        self.assertEqual('ssl_basic', self.cahandler.cert_type)
        self.assertEqual('sha256', self.cahandler.signature_hash)
        self.assertEqual(1, self.cahandler.order_validity)
        self.assertEqual(10, self.cahandler.request_timeout)
        self.assertFalse(self.cahandler.organization_name)
        self.assertFalse(self.cahandler.organization_id)
        self.assertFalse(self.cahandler.allowed_domainlist)
        self.assertTrue(self.cahandler.eab_profiling)
        self.assertEqual('eab', self.cahandler.eab_handler)
        self.assertEqual('hdl', self.cahandler.header_info_field)

    @patch('examples.ca_handler.digicert_ca_handler.config_headerinfo_load')
    @patch('examples.ca_handler.digicert_ca_handler.config_eab_profile_load')
    @patch('examples.ca_handler.digicert_ca_handler.load_config')
    def test_026_config_load(self, mock_load, mock_eab, mock_hdl):
        """ test _config_load() """
        mock_load.return_value = {'foo': 'bar', 'CAhandler': {'signature_hash': 'signature_hash'}}
        mock_eab.return_value = True, 'eab'
        mock_hdl.return_value = 'hdl'
        self.cahandler._config_load()
        self.assertTrue(mock_load.called)
        self.assertEqual('https://www.digicert.com/services/v2/', self.cahandler.api_url)
        self.assertFalse(self.cahandler.api_key)
        self.assertEqual('ssl_basic', self.cahandler.cert_type)
        self.assertEqual('signature_hash', self.cahandler.signature_hash)
        self.assertEqual(1, self.cahandler.order_validity)
        self.assertEqual(10, self.cahandler.request_timeout)
        self.assertFalse(self.cahandler.organization_name)
        self.assertFalse(self.cahandler.organization_id)
        self.assertFalse(self.cahandler.allowed_domainlist)
        self.assertTrue(self.cahandler.eab_profiling)
        self.assertEqual('eab', self.cahandler.eab_handler)
        self.assertEqual('hdl', self.cahandler.header_info_field)

    @patch('examples.ca_handler.digicert_ca_handler.config_headerinfo_load')
    @patch('examples.ca_handler.digicert_ca_handler.config_eab_profile_load')
    @patch('examples.ca_handler.digicert_ca_handler.load_config')
    def test_027_config_load(self, mock_load, mock_eab, mock_hdl):
        """ test _config_load() """
        mock_load.return_value = {'foo': 'bar', 'CAhandler': {'cert_type': 'cert_type'}}
        mock_eab.return_value = True, 'eab'
        mock_hdl.return_value = 'hdl'
        self.cahandler._config_load()
        self.assertTrue(mock_load.called)
        self.assertEqual('https://www.digicert.com/services/v2/', self.cahandler.api_url)
        self.assertFalse(self.cahandler.api_key)
        self.assertEqual('cert_type', self.cahandler.cert_type)
        self.assertEqual('sha256', self.cahandler.signature_hash)
        self.assertEqual(1, self.cahandler.order_validity)
        self.assertEqual(10, self.cahandler.request_timeout)
        self.assertFalse(self.cahandler.organization_name)
        self.assertFalse(self.cahandler.organization_id)
        self.assertFalse(self.cahandler.allowed_domainlist)
        self.assertTrue(self.cahandler.eab_profiling)
        self.assertEqual('eab', self.cahandler.eab_handler)
        self.assertEqual('hdl', self.cahandler.header_info_field)

    @patch('examples.ca_handler.digicert_ca_handler.config_headerinfo_load')
    @patch('examples.ca_handler.digicert_ca_handler.config_eab_profile_load')
    @patch('examples.ca_handler.digicert_ca_handler.load_config')
    def test_028_config_load(self, mock_load, mock_eab, mock_hdl):
        """ test _config_load() """
        mock_load.return_value = {'foo': 'bar', 'CAhandler': {'order_validity': 2}}
        mock_eab.return_value = True, 'eab'
        mock_hdl.return_value = 'hdl'
        self.cahandler._config_load()
        self.assertTrue(mock_load.called)
        self.assertEqual('https://www.digicert.com/services/v2/', self.cahandler.api_url)
        self.assertFalse(self.cahandler.api_key)
        self.assertEqual('ssl_basic', self.cahandler.cert_type)
        self.assertEqual('sha256', self.cahandler.signature_hash)
        self.assertEqual(2, self.cahandler.order_validity)
        self.assertEqual(10, self.cahandler.request_timeout)
        self.assertFalse(self.cahandler.organization_name)
        self.assertFalse(self.cahandler.organization_id)
        self.assertFalse(self.cahandler.allowed_domainlist)
        self.assertTrue(self.cahandler.eab_profiling)
        self.assertEqual('eab', self.cahandler.eab_handler)
        self.assertEqual('hdl', self.cahandler.header_info_field)

    @patch('examples.ca_handler.digicert_ca_handler.config_headerinfo_load')
    @patch('examples.ca_handler.digicert_ca_handler.config_eab_profile_load')
    @patch('examples.ca_handler.digicert_ca_handler.load_config')
    def test_029_config_load(self, mock_load, mock_eab, mock_hdl):
        """ test _config_load() """
        mock_load.return_value = {'foo': 'bar', 'CAhandler': {'request_timeout': 20}}
        mock_eab.return_value = True, 'eab'
        mock_hdl.return_value = 'hdl'
        self.cahandler._config_load()
        self.assertTrue(mock_load.called)
        self.assertEqual('https://www.digicert.com/services/v2/', self.cahandler.api_url)
        self.assertFalse(self.cahandler.api_key)
        self.assertEqual('ssl_basic', self.cahandler.cert_type)
        self.assertEqual('sha256', self.cahandler.signature_hash)
        self.assertEqual(1, self.cahandler.order_validity)
        self.assertEqual(20, self.cahandler.request_timeout)
        self.assertFalse(self.cahandler.organization_name)
        self.assertFalse(self.cahandler.organization_id)
        self.assertFalse(self.cahandler.allowed_domainlist)
        self.assertTrue(self.cahandler.eab_profiling)
        self.assertEqual('eab', self.cahandler.eab_handler)
        self.assertEqual('hdl', self.cahandler.header_info_field)

    @patch('examples.ca_handler.digicert_ca_handler.config_headerinfo_load')
    @patch('examples.ca_handler.digicert_ca_handler.config_eab_profile_load')
    @patch('examples.ca_handler.digicert_ca_handler.load_config')
    def test_030_config_load(self, mock_load, mock_eab, mock_hdl):
        """ test _config_load() """
        mock_load.return_value = {'foo': 'bar', 'CAhandler': {'organization_name': 'organization_name'}}
        mock_eab.return_value = True, 'eab'
        mock_hdl.return_value = 'hdl'
        self.cahandler._config_load()
        self.assertTrue(mock_load.called)
        self.assertEqual('https://www.digicert.com/services/v2/', self.cahandler.api_url)
        self.assertFalse(self.cahandler.api_key)
        self.assertEqual('ssl_basic', self.cahandler.cert_type)
        self.assertEqual('sha256', self.cahandler.signature_hash)
        self.assertEqual(1, self.cahandler.order_validity)
        self.assertEqual(10, self.cahandler.request_timeout)
        self.assertEqual('organization_name', self.cahandler.organization_name)
        self.assertFalse(self.cahandler.organization_id)
        self.assertFalse(self.cahandler.allowed_domainlist)
        self.assertTrue(self.cahandler.eab_profiling)
        self.assertEqual('eab', self.cahandler.eab_handler)
        self.assertEqual('hdl', self.cahandler.header_info_field)

    @patch('examples.ca_handler.digicert_ca_handler.config_headerinfo_load')
    @patch('examples.ca_handler.digicert_ca_handler.config_eab_profile_load')
    @patch('examples.ca_handler.digicert_ca_handler.load_config')
    def test_031_config_load(self, mock_load, mock_eab, mock_hdl):
        """ test _config_load() """
        mock_load.return_value = {'foo': 'bar', 'CAhandler': {'organization_id': 'organization_id'}}
        mock_eab.return_value = True, 'eab'
        mock_hdl.return_value = 'hdl'
        self.cahandler._config_load()
        self.assertTrue(mock_load.called)
        self.assertEqual('https://www.digicert.com/services/v2/', self.cahandler.api_url)
        self.assertFalse(self.cahandler.api_key)
        self.assertEqual('ssl_basic', self.cahandler.cert_type)
        self.assertEqual('sha256', self.cahandler.signature_hash)
        self.assertEqual(1, self.cahandler.order_validity)
        self.assertEqual(10, self.cahandler.request_timeout)
        self.assertFalse(self.cahandler.organization_name)
        self.assertEqual('organization_id', self.cahandler.organization_id)
        self.assertFalse(self.cahandler.allowed_domainlist)
        self.assertTrue(self.cahandler.eab_profiling)
        self.assertEqual('eab', self.cahandler.eab_handler)
        self.assertEqual('hdl', self.cahandler.header_info_field)

    @patch('examples.ca_handler.digicert_ca_handler.config_headerinfo_load')
    @patch('examples.ca_handler.digicert_ca_handler.config_eab_profile_load')
    @patch('examples.ca_handler.digicert_ca_handler.load_config')
    def test_032_config_load(self, mock_load, mock_eab, mock_hdl):
        """ test _config_load() """
        mock_load.return_value = {'foo': 'bar', 'CAhandler': {'allowed_domainlist': '["foo", "bar"]'}}
        mock_eab.return_value = True, 'eab'
        mock_hdl.return_value = 'hdl'
        self.cahandler._config_load()
        self.assertTrue(mock_load.called)
        self.assertEqual('https://www.digicert.com/services/v2/', self.cahandler.api_url)
        self.assertFalse(self.cahandler.api_key)
        self.assertEqual('ssl_basic', self.cahandler.cert_type)
        self.assertEqual('sha256', self.cahandler.signature_hash)
        self.assertEqual(1, self.cahandler.order_validity)
        self.assertEqual(10, self.cahandler.request_timeout)
        self.assertFalse(self.cahandler.organization_name)
        self.assertFalse(self.cahandler.organization_id)
        self.assertEqual(['foo', 'bar'], self.cahandler.allowed_domainlist)
        self.assertTrue(self.cahandler.eab_profiling)
        self.assertEqual('eab', self.cahandler.eab_handler)
        self.assertEqual('hdl', self.cahandler.header_info_field)

    @patch('examples.ca_handler.digicert_ca_handler.config_headerinfo_load')
    @patch('examples.ca_handler.digicert_ca_handler.config_eab_profile_load')
    @patch('examples.ca_handler.digicert_ca_handler.load_config')
    def test_033_config_load(self, mock_load, mock_eab, mock_hdl):
        """ test _config_load() """
        mock_load.return_value = {'foo': 'bar', 'CAhandler': {'allowed_domainlist': '["foo"]'}}
        mock_eab.return_value = True, 'eab'
        mock_hdl.return_value = 'hdl'
        self.cahandler._config_load()
        self.assertTrue(mock_load.called)
        self.assertEqual('https://www.digicert.com/services/v2/', self.cahandler.api_url)
        self.assertFalse(self.cahandler.api_key)
        self.assertEqual('ssl_basic', self.cahandler.cert_type)
        self.assertEqual('sha256', self.cahandler.signature_hash)
        self.assertEqual(1, self.cahandler.order_validity)
        self.assertEqual(10, self.cahandler.request_timeout)
        self.assertFalse(self.cahandler.organization_name)
        self.assertFalse(self.cahandler.organization_id)
        self.assertEqual(['foo'], self.cahandler.allowed_domainlist)
        self.assertTrue(self.cahandler.eab_profiling)
        self.assertEqual('eab', self.cahandler.eab_handler)
        self.assertEqual('hdl', self.cahandler.header_info_field)

    @patch('examples.ca_handler.digicert_ca_handler.config_headerinfo_load')
    @patch('examples.ca_handler.digicert_ca_handler.config_eab_profile_load')
    @patch('examples.ca_handler.digicert_ca_handler.load_config')
    def test_034_config_load(self, mock_load, mock_eab, mock_hdl):
        """ test _config_load() """
        mock_load.return_value = {'foo': 'bar', 'CAhandler': {'allowed_domainlist': "foo"}}
        mock_eab.return_value = True, 'eab'
        mock_hdl.return_value = 'hdl'
        self.cahandler._config_load()
        self.assertTrue(mock_load.called)
        self.assertEqual('https://www.digicert.com/services/v2/', self.cahandler.api_url)
        self.assertFalse(self.cahandler.api_key)
        self.assertEqual('ssl_basic', self.cahandler.cert_type)
        self.assertEqual('sha256', self.cahandler.signature_hash)
        self.assertEqual(1, self.cahandler.order_validity)
        self.assertEqual(10, self.cahandler.request_timeout)
        self.assertFalse(self.cahandler.organization_name)
        self.assertFalse(self.cahandler.organization_id)
        self.assertEqual('failed to parse', self.cahandler.allowed_domainlist)
        self.assertTrue(self.cahandler.eab_profiling)
        self.assertEqual('eab', self.cahandler.eab_handler)
        self.assertEqual('hdl', self.cahandler.header_info_field)

    @patch('examples.ca_handler.digicert_ca_handler.CAhandler._organiation_id_get')
    @patch('examples.ca_handler.digicert_ca_handler.CAhandler._api_post')
    def test_035_order_send(self, mock_post, mock_orgid):
        """ test _order_send() """
        mock_post.return_value = ('code', 'content')
        self.cahandler.organization_id = 'organization_id'
        self.assertEqual(('code', 'content'), self.cahandler._order_send('csr', 'cn'))
        self.assertFalse(mock_orgid.called)

    @patch('examples.ca_handler.digicert_ca_handler.CAhandler._organiation_id_get')
    @patch('examples.ca_handler.digicert_ca_handler.CAhandler._api_post')
    def test_036_order_send(self, mock_post, mock_orgid):
        """ test _order_send() """
        mock_post.return_value = ('code', 'content')
        self.assertEqual((500, 'organisation_id is missing'), self.cahandler._order_send('csr', 'cn'))
        self.assertFalse(mock_orgid.called)

    @patch('examples.ca_handler.digicert_ca_handler.CAhandler._organiation_id_get')
    @patch('examples.ca_handler.digicert_ca_handler.CAhandler._api_post')
    def test_037_order_send(self, mock_post, mock_orgid):
        """ test _order_send() """
        mock_post.return_value = ('code', 'content')
        self.cahandler.eab_profiling = True
        self.cahandler.api_key = 'api_key'
        self.cahandler.organization_name = 'organization_name'
        self.cahandler.organization_id = 'organization_id'
        self.assertEqual(('code', 'content'), self.cahandler._order_send('csr', 'cn'))
        self.assertTrue(mock_orgid.called)

    @patch('examples.ca_handler.digicert_ca_handler.CAhandler._organiation_id_get')
    @patch('examples.ca_handler.digicert_ca_handler.CAhandler._api_post')
    def test_038_order_send(self, mock_post, mock_orgid):
        """ test _order_send() """
        mock_post.return_value = ('code', 'content')
        self.cahandler.eab_profiling = True
        self.cahandler.api_key = 'api_key'
        self.cahandler.organization_name = 'organization_name'
        self.cahandler.organization_id = None
        mock_orgid.return_value = 1
        self.assertEqual(('code', 'content'), self.cahandler._order_send('csr', 'cn'))
        self.assertTrue(mock_orgid.called)

    @patch('examples.ca_handler.digicert_ca_handler.CAhandler._organiation_id_get')
    @patch('examples.ca_handler.digicert_ca_handler.CAhandler._api_post')
    def test_039_order_send(self, mock_post, mock_orgid):
        """ test _order_send() """
        mock_post.return_value = ('code', 'content')
        self.cahandler.api_key = 'api_key'
        self.cahandler.organization_name = 'organization_name'
        self.cahandler.organization_id = None
        mock_orgid.return_value = 1
        self.assertEqual(('code', 'content'), self.cahandler._order_send('csr', 'cn'))
        self.assertTrue(mock_orgid.called)

    @patch('examples.ca_handler.digicert_ca_handler.CAhandler._organiation_id_get')
    @patch('examples.ca_handler.digicert_ca_handler.CAhandler._api_post')
    def test_040_order_send(self, mock_post, mock_orgid):
        """ test _order_send() """
        mock_post.return_value = ('code', 'content')
        self.cahandler.api_key = 'api_key'
        self.cahandler.organization_name = None
        self.cahandler.organization_id = None
        mock_orgid.return_value = 1
        self.assertEqual((500, 'organisation_id is missing'), self.cahandler._order_send('csr', 'cn'))
        self.assertFalse(mock_orgid.called)

    @patch('examples.ca_handler.digicert_ca_handler.enrollment_config_log')
    @patch('examples.ca_handler.digicert_ca_handler.CAhandler._organiation_id_get')
    @patch('examples.ca_handler.digicert_ca_handler.CAhandler._api_post')
    def test_041_order_send(self, mock_post, mock_orgid, mock_ecl):
        """ test _order_send() """
        mock_post.return_value = ('code', 'content')
        self.cahandler.api_key = None
        self.cahandler.organization_name = 'organization_name'
        self.cahandler.organization_id = None
        mock_orgid.return_value = 1
        self.assertEqual((500, 'organisation_id is missing'), self.cahandler._order_send('csr', 'cn'))
        self.assertFalse(mock_orgid.called)
        self.assertFalse(mock_ecl.called)

    @patch('examples.ca_handler.digicert_ca_handler.enrollment_config_log')
    @patch('examples.ca_handler.digicert_ca_handler.CAhandler._organiation_id_get')
    @patch('examples.ca_handler.digicert_ca_handler.CAhandler._api_post')
    def test_042_order_send(self, mock_post, mock_orgid, mock_ecl):
        """ test _order_send() """
        mock_post.return_value = ('code', 'content')
        self.cahandler.api_key = None
        self.cahandler.organization_name = 'organization_name'
        self.cahandler.organization_id = None
        self.cahandler.enrollment_config_log = True
        mock_orgid.return_value = 1
        self.assertEqual((500, 'organisation_id is missing'), self.cahandler._order_send('csr', 'cn'))
        self.assertFalse(mock_orgid.called)
        self.assertTrue(mock_ecl.called)

    @patch('examples.ca_handler.digicert_ca_handler.cert_pem2der')
    @patch('examples.ca_handler.digicert_ca_handler.b64_encode')
    def test_043_order_response_parse(self, mock_b64, mock_pem2der):
        """ test _order_parse() """
        content_dic = {'id': 'id', 'certificate_chain': [{'pem': 'pem1'}, {'pem': 'pem2'}, {'pem': 'pem3'}]}
        mock_b64.return_value = 'b64'
        self.assertEqual(('pem1\npem2\npem3\n', 'b64', 'id'), self.cahandler._order_response_parse(content_dic))

    @patch('examples.ca_handler.digicert_ca_handler.cert_pem2der')
    @patch('examples.ca_handler.digicert_ca_handler.b64_encode')
    def test_044_order_response_parse(self, mock_b64, mock_pem2der):
        """ test _order_parse() """
        content_dic = {'id': 'id', 'cert_chain': [{'pem': 'pem1'}, {'pem': 'pem2'}, {'pem': 'pem3'}]}
        mock_b64.return_value = 'b64'
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual((None, None, None), self.cahandler._order_response_parse(content_dic))
        self.assertIn('ERROR:test_a2c:CAhandler._order_response_parse() failed: no certificate_chain in response', lcm.output)

    @patch('examples.ca_handler.digicert_ca_handler.cert_pem2der')
    @patch('examples.ca_handler.digicert_ca_handler.b64_encode')
    def test_045_order_response_parse(self, mock_b64, mock_pem2der):
        """ test _order_parse() """
        content_dic = {'id': 'id', 'certificate_chain': [{'pem': 'pem1'}, {'_pem': 'pem2'}, {'pem': 'pem3'}]}
        mock_b64.return_value = 'b64'
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual(('pem1\npem3\n', 'b64', 'id'), self.cahandler._order_response_parse(content_dic))
        self.assertIn('ERROR:test_a2c:CAhandler._order_response_parse() failed: no pem in certificate_chain', lcm.output)

    @patch('examples.ca_handler.digicert_ca_handler.cert_pem2der')
    @patch('examples.ca_handler.digicert_ca_handler.b64_encode')
    def test_046_order_response_parse(self, mock_b64, mock_pem2der):
        """ test _order_parse() """
        content_dic = {'_id': 'id', 'certificate_chain': [{'pem': 'pem1'}, {'pem': 'pem2'}, {'pem': 'pem3'}]}
        mock_b64.return_value = 'b64'
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual(('pem1\npem2\npem3\n', 'b64', None), self.cahandler._order_response_parse(content_dic))
        self.assertIn('ERROR:test_a2c:CAhandler._order_response_parse() polling_identifier generation failed: no id in response', lcm.output)

    @patch('examples.ca_handler.digicert_ca_handler.CAhandler._api_get')
    def test_047_organiation_id_get(self, mock_get):
        """ test _organiation_id_get() """
        mock_get.return_value = (500, {'id': 'id'})
        self.cahandler.organization_name = 'organization_name'
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._organiation_id_get()
        self.assertIn('ERROR:test_a2c:CAhandler._organiation_id_get() failed', lcm.output)
        self.assertFalse(self.cahandler.organization_id)

    @patch('examples.ca_handler.digicert_ca_handler.CAhandler._api_get')
    def test_048_organiation_id_get(self, mock_get):
        """ test _organiation_id_get() """
        mock_get.return_value = (200, {'organizations': [{'name': 'name1', 'id': 'id1'}, {'name': 'name2', 'id': 'id2'}, {'name': 'name3', 'id': 'id3'}]})
        self.cahandler.organization_name = 'name1'
        self.assertEqual('id1', self.cahandler._organiation_id_get())

    @patch('examples.ca_handler.digicert_ca_handler.CAhandler._api_get')
    def test_049_organiation_id_get(self, mock_get):
        """ test _organiation_id_get() """
        mock_get.return_value = (200, {'organizations': [{'name': 'name1', 'id': 'id1'}, {'name': 'name2', 'id': 'id2'}, {'name': 'name3', 'id': 'id3'}]})
        self.cahandler.organization_name = 'name2'
        self.assertEqual('id2', self.cahandler._organiation_id_get())

    @patch('examples.ca_handler.digicert_ca_handler.eab_profile_header_info_check')
    @patch('examples.ca_handler.digicert_ca_handler.allowed_domainlist_check_error')
    def test_050_csr_check(self, mock_dlchk, mock_ehichk):
        """ test _csr_check() """
        mock_dlchk.return_value = 'mock_dlchk'
        mock_ehichk.return_value = 'mock_hichk'

        self.assertEqual('mock_dlchk', self.cahandler._csr_check('csr'))

    @patch('examples.ca_handler.digicert_ca_handler.eab_profile_header_info_check')
    @patch('examples.ca_handler.digicert_ca_handler.allowed_domainlist_check_error')
    def test_051_csr_check(self, mock_dlchk, mock_ehichk):
        """ test _csr_check() """
        mock_dlchk.return_value = False
        mock_ehichk.return_value = 'mock_hichk'
        self.assertEqual('mock_hichk', self.cahandler._csr_check('csr'))

    @patch('examples.ca_handler.digicert_ca_handler.eab_profile_header_info_check')
    @patch('examples.ca_handler.digicert_ca_handler.allowed_domainlist_check_error')
    def test_052_csr_check(self, mock_dlchk, mock_ehichk):
        """ test _csr_check() """
        mock_dlchk.return_value = False
        mock_ehichk.return_value = False
        self.assertFalse(self.cahandler._csr_check('csr'))

    @patch('examples.ca_handler.digicert_ca_handler.CAhandler._order_response_parse')
    @patch('examples.ca_handler.digicert_ca_handler.CAhandler._order_send')
    @patch('examples.ca_handler.digicert_ca_handler.csr_cn_lookup')
    @patch('examples.ca_handler.digicert_ca_handler.CAhandler._csr_check')
    @patch('examples.ca_handler.digicert_ca_handler.CAhandler._config_check')
    def test_053_enroll(self, mock_cfgchk, mock_csrchk, mock_cnget, mock_ordersend, mock_orderparse):
        """ test enroll() """
        mock_cfgchk.return_value = 'mock_cfgchk'
        mock_csrchk.return_value = 'mock_csrchk'
        mock_cnget.return_value = 'cn'
        mock_ordersend.return_value = ('code', 'content')
        mock_orderparse.return_value = ('pem', 'b64', 'id')
        self.assertEqual(('mock_cfgchk', None, None, None), self.cahandler.enroll('csr'))
        self.assertTrue(mock_cfgchk.called)
        self.assertFalse(mock_csrchk.called)
        self.assertFalse(mock_cnget.called)
        self.assertFalse(mock_ordersend.called)
        self.assertFalse(mock_orderparse.called)

    @patch('examples.ca_handler.digicert_ca_handler.CAhandler._order_response_parse')
    @patch('examples.ca_handler.digicert_ca_handler.CAhandler._order_send')
    @patch('examples.ca_handler.digicert_ca_handler.csr_cn_lookup')
    @patch('examples.ca_handler.digicert_ca_handler.CAhandler._csr_check')
    @patch('examples.ca_handler.digicert_ca_handler.CAhandler._config_check')
    def test_054_enroll(self, mock_cfgchk, mock_csrchk, mock_cnget, mock_ordersend, mock_orderparse):
        """ test enroll() """
        mock_cfgchk.return_value = False
        mock_csrchk.return_value = 'mock_csrchk'
        mock_cnget.return_value = 'cn'
        mock_ordersend.return_value = ('code', 'content')
        mock_orderparse.return_value = ('pem', 'b64', 'id')
        self.assertEqual(('mock_csrchk', None, None, None), self.cahandler.enroll('csr'))
        self.assertTrue(mock_cfgchk.called)
        self.assertTrue(mock_csrchk.called)
        self.assertFalse(mock_cnget.called)
        self.assertFalse(mock_ordersend.called)
        self.assertFalse(mock_orderparse.called)

    @patch('examples.ca_handler.digicert_ca_handler.CAhandler._order_response_parse')
    @patch('examples.ca_handler.digicert_ca_handler.CAhandler._order_send')
    @patch('examples.ca_handler.digicert_ca_handler.csr_cn_lookup')
    @patch('examples.ca_handler.digicert_ca_handler.CAhandler._csr_check')
    @patch('examples.ca_handler.digicert_ca_handler.CAhandler._config_check')
    def test_055_enroll(self, mock_cfgchk, mock_csrchk, mock_cnget, mock_ordersend, mock_orderparse):
        """ test enroll() """
        mock_cfgchk.return_value = False
        mock_csrchk.return_value = False
        mock_cnget.return_value = 'cn'
        mock_ordersend.return_value = ('code', 'content')
        mock_orderparse.return_value = ('pem', 'b64', 'id')
        self.assertEqual(('Error during order creation: code - content', None, None, None), self.cahandler.enroll('csr'))
        self.assertTrue(mock_cfgchk.called)
        self.assertTrue(mock_csrchk.called)
        self.assertTrue(mock_cnget.called)
        self.assertTrue(mock_ordersend.called)
        self.assertFalse(mock_orderparse.called)

    @patch('examples.ca_handler.digicert_ca_handler.CAhandler._order_response_parse')
    @patch('examples.ca_handler.digicert_ca_handler.CAhandler._order_send')
    @patch('examples.ca_handler.digicert_ca_handler.csr_cn_lookup')
    @patch('examples.ca_handler.digicert_ca_handler.CAhandler._csr_check')
    @patch('examples.ca_handler.digicert_ca_handler.CAhandler._config_check')
    def test_056_enroll(self, mock_cfgchk, mock_csrchk, mock_cnget, mock_ordersend, mock_orderparse):
        """ test enroll() """
        mock_cfgchk.return_value = False
        mock_csrchk.return_value = False
        mock_cnget.return_value = 'cn'
        mock_ordersend.return_value = ('code', {'errors': [{'code': 'code', 'message': 'content'}]})
        mock_orderparse.return_value = ('pem', 'b64', 'id')
        self.assertEqual(("Error during order creation: code - [{'code': 'code', 'message': 'content'}]", None, None, None), self.cahandler.enroll('csr'))
        self.assertTrue(mock_cfgchk.called)
        self.assertTrue(mock_csrchk.called)
        self.assertTrue(mock_cnget.called)
        self.assertTrue(mock_ordersend.called)
        self.assertFalse(mock_orderparse.called)

    @patch('examples.ca_handler.digicert_ca_handler.CAhandler._order_response_parse')
    @patch('examples.ca_handler.digicert_ca_handler.CAhandler._order_send')
    @patch('examples.ca_handler.digicert_ca_handler.csr_cn_lookup')
    @patch('examples.ca_handler.digicert_ca_handler.CAhandler._csr_check')
    @patch('examples.ca_handler.digicert_ca_handler.CAhandler._config_check')
    def test_057_enroll(self, mock_cfgchk, mock_csrchk, mock_cnget, mock_ordersend, mock_orderparse):
        """ test enroll() """
        mock_cfgchk.return_value = False
        mock_csrchk.return_value = False
        mock_cnget.return_value = 'cn'
        mock_ordersend.return_value = (200, 'content')
        mock_orderparse.return_value = ('pem', 'b64', 'id')
        self.assertEqual((False, 'pem', 'b64', 'id'), self.cahandler.enroll('csr'))
        self.assertTrue(mock_cfgchk.called)
        self.assertTrue(mock_csrchk.called)
        self.assertTrue(mock_cnget.called)
        self.assertTrue(mock_ordersend.called)
        self.assertTrue(mock_orderparse.called)

    @patch('examples.ca_handler.digicert_ca_handler.CAhandler._api_put')
    @patch('examples.ca_handler.digicert_ca_handler.cert_serial_get')
    def test_058_revoke(self, mock_serial, mock_put):
        """ test revoke() """
        mock_serial.return_value = 'serial'
        mock_put.return_value = ('code', 'content')
        self.assertEqual(('code', None, 'content'), self.cahandler.revoke('cert'))

    @patch('examples.ca_handler.digicert_ca_handler.CAhandler._api_put')
    @patch('examples.ca_handler.digicert_ca_handler.cert_serial_get')
    def test_059_revoke(self, mock_serial, mock_put):
        """ test revoke() """
        mock_serial.return_value = None
        mock_put.return_value = ('code', 'content')
        self.assertEqual((500, None, 'Failed to parse certificate serial'), self.cahandler.revoke('cert'))

    @patch('examples.ca_handler.digicert_ca_handler.CAhandler._api_put')
    @patch('examples.ca_handler.digicert_ca_handler.cert_serial_get')
    def test_060_revoke(self, mock_serial, mock_put):
        """ test revoke() """
        mock_serial.return_value = 'serial'
        mock_put.return_value = (204, 'content')
        self.assertEqual((200, None, 'content'), self.cahandler.revoke('cert'))


if __name__ == '__main__':

    unittest.main()
