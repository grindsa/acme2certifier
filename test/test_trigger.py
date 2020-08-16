#!/usr/bin/python
# -*- coding: utf-8 -*-
""" unittests for account.py """
# pylint: disable=C0302, C0415, R0904, R0913, R0914, R0915, W0212
import unittest
import sys
import importlib
from unittest.mock import patch, MagicMock, Mock

sys.path.insert(0, '.')
sys.path.insert(1, '..')

class FakeDBStore(object):
    """ face DBStore class needed for mocking """
    # pylint: disable=W0107, R0903
    pass

class TestACMEHandler(unittest.TestCase):
    """ test class for ACMEHandler """
    acme = None
    def setUp(self):
        """ setup unittest """
        models_mock = MagicMock()
        models_mock.acme.db_handler.DBstore.return_value = FakeDBStore
        modules = {'acme.db_handler': models_mock}
        patch.dict('sys.modules', modules).start()
        import logging
        logging.basicConfig(level=logging.CRITICAL)
        self.logger = logging.getLogger('test_a2c')
        from acme.trigger import Trigger
        from acme.order import Order
        self.order = Order(False, 'http://tester.local', self.logger)
        self.trigger = Trigger(False, 'http://tester.local', self.logger)

    @patch('importlib.import_module')
    @patch('acme.certificate.Certificate.certlist_search')
    @patch('acme.trigger.cert_pubkey_get')
    def test_001_trigger__certname_lookup(self, mock_cert_pub, mock_search_list, mock_import):
        """ trigger._certname_lookup() failed bcs. of empty certificate list """
        mock_cert_pub.return_value = 'foo'
        mock_search_list.return_value = []
        mock_import.return_value = importlib.import_module('examples.ca_handler.skeleton_ca_handler')
        self.assertEqual([], self.trigger._certname_lookup('cert_pem'))

    @patch('importlib.import_module')
    @patch('acme.certificate.Certificate.certlist_search')
    @patch('acme.trigger.cert_pubkey_get')
    def test_002_trigger__certname_lookup(self, mock_cert_pub, mock_search_list, mock_import):
        """ trigger._certname_lookup() failed bcs. of wrong certificate list """
        mock_cert_pub.return_value = 'foo'
        mock_search_list.return_value = [{'foo': 'bar'}]
        mock_import.return_value = importlib.import_module('examples.ca_handler.skeleton_ca_handler')
        self.assertEqual([], self.trigger._certname_lookup('cert_pem'))

    @patch('importlib.import_module')
    @patch('acme.certificate.Certificate.certlist_search')
    @patch('acme.trigger.cert_pubkey_get')
    def test_003_trigger__certname_lookup(self, mock_cert_pub, mock_search_list, mock_import):
        """ trigger._certname_lookup() failed bcs. of emty csr field """
        mock_cert_pub.return_value = 'foo'
        mock_search_list.return_value = [{'csr': None}]
        mock_import.return_value = importlib.import_module('examples.ca_handler.skeleton_ca_handler')
        self.assertEqual([], self.trigger._certname_lookup('cert_pem'))

    @patch('importlib.import_module')
    @patch('acme.trigger.csr_pubkey_get')
    @patch('acme.certificate.Certificate.certlist_search')
    @patch('acme.trigger.cert_pubkey_get')
    def test_004_trigger__certname_lookup(self, mock_cert_pub, mock_search_list, mock_csr_pub, mock_import):
        """ trigger._certname_lookup() failed bcs. of emty csr field """
        mock_cert_pub.return_value = 'foo'
        mock_csr_pub.return_value = 'foo1'
        mock_search_list.return_value = [{'csr': None}]
        mock_import.return_value = importlib.import_module('examples.ca_handler.skeleton_ca_handler')
        self.assertEqual([], self.trigger._certname_lookup('cert_pem'))

    @patch('importlib.import_module')
    @patch('acme.trigger.csr_pubkey_get')
    @patch('acme.certificate.Certificate.certlist_search')
    @patch('acme.trigger.cert_pubkey_get')
    def test_005_trigger__certname_lookup(self, mock_cert_pub, mock_search_list, mock_csr_pub, mock_import):
        """ trigger._certname_lookup() failed bcs. of emty csr field """
        mock_cert_pub.return_value = 'foo'
        mock_csr_pub.return_value = 'foo'
        mock_search_list.return_value = [{'csr': 'csr', 'name': 'cert_name', 'order__name': 'order_name'}]
        mock_import.return_value = importlib.import_module('examples.ca_handler.skeleton_ca_handler')
        self.assertEqual([{'cert_name': 'cert_name', 'order_name': 'order_name'}], self.trigger._certname_lookup('cert_pem'))

    def test_006_trigger_parse(self):
        """ Trigger.parse() with empty payload """
        payload = ""
        result = {'header': {}, 'code': 400, 'data': {'detail': 'payload missing', 'message': 'malformed', 'status': 400}}
        self.assertEqual(result, self.trigger.parse(payload))

    def test_007_trigger_parse(self):
        """ Trigger.parse() with wrong payload """
        payload = '{"foo": "bar"}'
        result = {'header': {}, 'code': 400, 'data': {'detail': 'payload missing', 'message': 'malformed', 'status': 400}}
        self.assertEqual(result, self.trigger.parse(payload))

    def test_008_trigger_parse(self):
        """ Trigger.parse() with empty payload key"""
        payload = '{"payload": ""}'
        result = {'header': {}, 'code': 400, 'data': {'detail': 'payload empty', 'message': 'malformed', 'status': 400}}
        self.assertEqual(result, self.trigger.parse(payload))

    @patch('acme.trigger.Trigger._payload_process')
    def test_009_trigger_parse(self, mock_process):
        """ Trigger.parse() with payload mock result 400"""
        payload = '{"payload": "foo"}'
        mock_process.return_value = (400, 'message', 'detail')
        result = {'header': {}, 'code': 400, 'data': {'detail': 'detail', 'message': 'message', 'status': 400}}
        self.assertEqual(result, self.trigger.parse(payload))

    @patch('acme.trigger.Trigger._payload_process')
    def test_010_trigger_parse(self, mock_process):
        """ Trigger.parse() with payload mock result 200"""
        payload = '{"payload": "foo"}'
        mock_process.return_value = (200, 'message', 'detail')
        result = {'header': {}, 'code': 200, 'data': {'detail': 'detail', 'message': 'message', 'status': 200}}
        self.assertEqual(result, self.trigger.parse(payload))

    def test_011_trigger__payload_process(self):
        """ Trigger._payload_process() without payload"""
        payload = {}
        ca_handler_module = importlib.import_module('examples.ca_handler.skeleton_ca_handler')
        self.trigger.cahandler = ca_handler_module.CAhandler
        self.trigger.cahandler.trigger = Mock(return_value=('error', None, None))
        self.assertEqual((400, 'payload malformed', None), self.trigger._payload_process(payload))

    def test_012_trigger__payload_process(self):
        """ Trigger._payload_process() without certbunde and cert_raw"""
        payload = {'payload': 'foo'}
        ca_handler_module = importlib.import_module('examples.ca_handler.skeleton_ca_handler')
        self.trigger.cahandler = ca_handler_module.CAhandler
        self.trigger.cahandler.trigger = Mock(return_value=('error', None, None))
        self.assertEqual((400, 'error', None), self.trigger._payload_process(payload))

    def test_013_trigger__payload_process(self):
        """ Trigger._payload_process() with bundle and without cart_raw"""
        payload = {'payload': 'foo'}
        ca_handler_module = importlib.import_module('examples.ca_handler.skeleton_ca_handler')
        self.trigger.cahandler = ca_handler_module.CAhandler
        self.trigger.cahandler.trigger = Mock(return_value=('error', 'bundle', None))
        self.assertEqual((400, 'error', None), self.trigger._payload_process(payload))

    def test_014_trigger__payload_process(self):
        """ Trigger._payload_process() with bundle and without cart_raw"""
        payload = {'payload': 'foo'}
        ca_handler_module = importlib.import_module('examples.ca_handler.skeleton_ca_handler')
        self.trigger.cahandler = ca_handler_module.CAhandler
        self.trigger.cahandler.trigger = Mock(return_value=('error', None, 'raw'))
        self.assertEqual((400, 'error', None), self.trigger._payload_process(payload))

    @patch('acme.trigger.Trigger._certname_lookup')
    @patch('acme.trigger.b64_decode')
    @patch('acme.trigger.cert_der2pem')
    @patch('acme.trigger.convert_byte_to_string')
    def test_015_trigger__payload_process(self, mock_cobystr, mock_der2pem, mock_b64dec, mock_lookup):
        """ Trigger._payload_process() with certificae_name"""
        payload = {'payload': 'foo'}
        ca_handler_module = importlib.import_module('examples.ca_handler.skeleton_ca_handler')
        self.trigger.cahandler = ca_handler_module.CAhandler
        self.trigger.cahandler.trigger = Mock(return_value=('error', 'bundle', 'raw'))
        mock_der2pem.return_value = 'der2pem'
        mock_cobystr.return_value = 'cert_pem'
        mock_b64dec.return_value = 'b64dec'
        mock_lookup.return_value = [{'cert_name': 'certificate_name', 'order_name': None}]
        self.assertEqual((200, 'OK', None), self.trigger._payload_process(payload))

    @patch('acme.trigger.Trigger._certname_lookup')
    @patch('acme.trigger.b64_decode')
    @patch('acme.trigger.cert_der2pem')
    @patch('acme.trigger.convert_byte_to_string')
    def test_016_trigger__payload_process(self, mock_cobystr, mock_der2pem, mock_b64dec, mock_lookup):
        """ Trigger._payload_process() without certificate_name """
        payload = {'payload': 'foo'}
        ca_handler_module = importlib.import_module('examples.ca_handler.skeleton_ca_handler')
        self.trigger.cahandler = ca_handler_module.CAhandler
        self.trigger.cahandler.trigger = Mock(return_value=('error', 'bundle', 'raw'))
        mock_der2pem.return_value = 'der2pem'
        mock_cobystr.return_value = 'cert_pem'
        mock_b64dec.return_value = 'b64dec'
        mock_lookup.return_value = [{'cert_name': None, 'order_name': 'order_name'}]
        self.assertEqual((200, 'OK', None), self.trigger._payload_process(payload))

    @patch('acme.trigger.Trigger._certname_lookup')
    @patch('acme.trigger.b64_decode')
    @patch('acme.trigger.cert_der2pem')
    @patch('acme.trigger.convert_byte_to_string')
    def test_017_trigger__payload_process(self, mock_cobystr, mock_der2pem, mock_b64dec, mock_lookup):
        """ Trigger._payload_process() without certificate_name """
        payload = {'payload': 'foo'}
        ca_handler_module = importlib.import_module('examples.ca_handler.skeleton_ca_handler')
        self.trigger.cahandler = ca_handler_module.CAhandler
        self.trigger.cahandler.trigger = Mock(return_value=('error', 'bundle', 'raw'))
        mock_der2pem.return_value = 'der2pem'
        mock_cobystr.return_value = 'cert_pem'
        mock_b64dec.return_value = 'b64dec'
        mock_lookup.return_value = [{'cert_name': 'certificate_name', 'order_name': 'order_name'}]
        self.order.dbstore.order_update.return_value = None
        self.assertEqual((200, 'OK', None), self.trigger._payload_process(payload))

    @patch('acme.trigger.Trigger._certname_lookup')
    @patch('acme.trigger.b64_decode')
    @patch('acme.trigger.cert_der2pem')
    @patch('acme.trigger.convert_byte_to_string')
    def test_018_trigger__payload_process(self, mock_cobystr, mock_der2pem, mock_b64dec, mock_lookup):
        """ Trigger._payload_process() without certificate_name """
        payload = {'payload': 'foo'}
        ca_handler_module = importlib.import_module('examples.ca_handler.skeleton_ca_handler')
        self.trigger.cahandler = ca_handler_module.CAhandler
        self.trigger.cahandler.trigger = Mock(return_value=('error', 'bundle', 'raw'))
        mock_der2pem.return_value = 'der2pem'
        mock_cobystr.return_value = 'cert_pem'
        mock_b64dec.return_value = 'b64dec'
        mock_lookup.return_value = [{'cert_name': 'certificate_name1', 'order_name': 'order_name1'}, {'cert_name': 'certificate_name2', 'order_name': 'order_name2'}]
        self.assertEqual((200, 'OK', None), self.trigger._payload_process(payload))

    @patch('acme.trigger.b64_decode')
    @patch('acme.trigger.cert_der2pem')
    @patch('acme.trigger.Trigger._certname_lookup')
    @patch('acme.trigger.convert_byte_to_string')
    def test_019_trigger__payload_process(self, mock_cobystr, mock_lookup, mock_der2pem, mock_b64dec):
        """ test Trigger._payload_process - dbstore.order_update() raises an exception  """
        ca_handler_module = importlib.import_module('examples.ca_handler.skeleton_ca_handler')
        self.trigger.cahandler = ca_handler_module.CAhandler
        self.trigger.cahandler.trigger = Mock(return_value=(None, 'certificate', 'certificate_raw'))
        mock_der2pem.return_value = 'der2pem'
        mock_cobystr.return_value = 'cert_pem'
        mock_b64dec.return_value = 'b64dec'
        mock_lookup.return_value = [{'cert_name': 'certificate_name1', 'order_name': 'order_name1'}, {'cert_name': 'certificate_name2', 'order_name': 'order_name2'}]
        self.trigger.dbstore.certificate_add.return_value = True
        self.trigger.dbstore.order_update.side_effect = Exception('exc_trigger_order_upd')
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.trigger._payload_process('payload')
        self.assertIn('CRITICAL:test_a2c:acme2certifier database error in trigger._payload_process() upd: exc_trigger_order_upd', lcm.output)

    @patch('acme.trigger.b64_decode')
    @patch('acme.trigger.cert_der2pem')
    @patch('acme.trigger.Trigger._certname_lookup')
    @patch('acme.trigger.convert_byte_to_string')
    def test_020_trigger__payload_process(self, mock_cobystr, mock_lookup, mock_der2pem, mock_b64dec):
        """ test Trigger._payload_process - dbstore.order_update() raises an exception  """
        ca_handler_module = importlib.import_module('examples.ca_handler.skeleton_ca_handler')
        self.trigger.cahandler = ca_handler_module.CAhandler
        self.trigger.cahandler.trigger = Mock(return_value=(None, 'certificate', 'certificate_raw'))
        mock_der2pem.return_value = 'der2pem'
        mock_cobystr.return_value = 'cert_pem'
        mock_b64dec.return_value = 'b64dec'
        mock_lookup.return_value = [{'cert_name': 'certificate_name1', 'order_name': 'order_name1'}, {'cert_name': 'certificate_name2', 'order_name': 'order_name2'}]
        self.trigger.dbstore.certificate_add.side_effect = Exception('exc_trigger_order_add')
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.trigger._payload_process('payload')
        self.assertIn('CRITICAL:test_a2c:acme2certifier database error in trigger._payload_process() add: exc_trigger_order_add', lcm.output)

if __name__ == '__main__':
    unittest.main()
