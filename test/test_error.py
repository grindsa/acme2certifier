#!/usr/bin/python
# -*- coding: utf-8 -*-
""" unittests for account.py """
# pylint: disable=C0302, C0415, R0904, R0913, R0914, R0915, W0212
import unittest
import sys
from unittest.mock import patch, MagicMock

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
        models_mock.acme_srv.db_handler.DBstore.return_value = FakeDBStore
        modules = {'acme_srv.db_handler': models_mock}
        patch.dict('sys.modules', modules).start()
        import logging
        logging.basicConfig(level=logging.CRITICAL)
        self.logger = logging.getLogger('test_a2c')
        from acme_srv.error import Error
        self.error = Error(False, self.logger)

    def test_001_error__acme_errormessage(self):
        """ test badnonce error message """
        self.assertEqual('JWS has invalid anti-replay nonce', self.error._acme_errormessage('urn:ietf:params:acme:error:badNonce'))

    def test_002_error__acme_errormessage(self):
        """ test badnonce error message """
        self.assertEqual('The provided contact URI was invalid', self.error._acme_errormessage('urn:ietf:params:acme:error:invalidContact'))

    def test_003_error__acme_errormessage(self):
        """ test badnonce error message """
        self.assertFalse(self.error._acme_errormessage('urn:ietf:params:acme:error:userActionRequired'))

    def test_004_error__acme_errormessage(self):
        """ test badnonce error message """
        self.assertFalse(self.error._acme_errormessage('urn:ietf:params:acme:error:malformed'))

    def test_005_error__acme_errormessage(self):
        """ Error.acme_errormessage for existing value with content """
        self.assertEqual('JWS has invalid anti-replay nonce', self.error._acme_errormessage('urn:ietf:params:acme:error:badNonce'))

    def test_006_error__acme_errormessage(self):
        """ Error.acme_errormessage for existing value without content """
        self.assertFalse(self.error._acme_errormessage('urn:ietf:params:acme:error:unauthorized'))

    def test_007_error__acme_errormessage(self):
        """ Error.acme_errormessage for message None """
        self.assertFalse(self.error._acme_errormessage(None))

    def test_008_error__acme_errormessage(self):
        """ Error.acme_errormessage for not unknown message """
        self.assertFalse(self.error._acme_errormessage('unknown'))

    def test_009_error_enrich_error(self):
        """ Error.enrich_error for valid message and detail """
        self.assertEqual('JWS has invalid anti-replay nonce: detail', self.error.enrich_error('urn:ietf:params:acme:error:badNonce', 'detail'))

    def test_010_error_enrich_error(self):
        """ Error.enrich_error for valid message, detail and None in error_hash hash """
        self.assertEqual('detail', self.error.enrich_error('urn:ietf:params:acme:error:badCSR', 'detail'))

    def test_011_error_enrich_error(self):
        """ Error.enrich_error for valid message, no detail and someting in error_hash hash """
        self.assertEqual('JWS has invalid anti-replay nonce: None', self.error.enrich_error('urn:ietf:params:acme:error:badNonce', None))

    def test_012_error_enrich_error(self):
        """ Error.enrich_error for valid message, no detail and nothing in error_hash hash """
        self.assertFalse(self.error.enrich_error('urn:ietf:params:acme:error:badCSR', None))

    @patch('acme_srv.error.Error._acme_errormessage')
    def test_013_error_enrich_error(self, mock_error):
        """ Error.enrich_error for valid message, no detail and nothing in error_hash hash """
        mock_error.return_value = 'foo'
        self.assertEqual('foo', self.error.enrich_error(None, ''))

if __name__ == '__main__':
    unittest.main()
