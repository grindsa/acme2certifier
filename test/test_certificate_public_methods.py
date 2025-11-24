#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# pylint: disable=C0302, E0401, C0415, R0904, R0913, R0914, R0915, W0212, C0413, W0611
"""Comprehensive unit tests for Certificate class public methods"""
import os
import json
import unittest
from unittest.mock import Mock, patch, call, MagicMock
from datetime import datetime
import sys

# Ensure the parent directory is in the Python path
test_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(test_dir)
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

# Mock the db_handler module completely before importing Certificate
with patch.dict(
    "sys.modules",
    {
        "acme_srv.db_handler": MagicMock(),
    },
):
    # Try to import and handle missing dependencies gracefully
    try:
        from acme_srv.certificate import Certificate
    except ImportError as e:
        print(f"Import error: {e}")
        print(f"Current working directory: {os.getcwd()}")
        print(f"Python path: {sys.path}")
        print("\nTo run this test, use one of the following:")
        print("1. pytest test/test_certificate_public_methods.py")
        print("2. python -m pytest test/test_certificate_public_methods.py")
        print("3. Activate the virtual environment first:")
        print(
            "   source a2c-env/bin/activate && python3 test/test_certificate_public_methods.py"
        )
        sys.exit(1)


class TestCertificatePublicMethods(unittest.TestCase):
    """Test class for Certificate public methods"""

    def setUp(self):
        """Set up test fixtures"""
        self.debug = False
        self.srv_name = "acme2certifier"

        # Create real logger instead of Mock to avoid AttributeError
        import logging

        self.mock_logger = logging.getLogger("test")
        self.mock_logger.setLevel(logging.DEBUG)

        # Mock external dependencies
        self.dbstore_mock = Mock()
        self.message_mock = Mock()
        self.hooks_mock = Mock()

        # Create Certificate instance with mocked dependencies
        with patch.dict("sys.modules", {"acme_srv.db_handler": MagicMock()}), patch(
            "acme_srv.certificate.DBstore"
        ) as mock_dbstore_class, patch(
            "acme_srv.certificate.Message"
        ) as mock_message_class, patch(
            "acme_srv.certificate.load_config"
        ) as mock_load_config, patch(
            "acme_srv.certificate.ca_handler_load"
        ) as mock_ca_handler_load, patch(
            "acme_srv.certificate.hooks_load"
        ) as mock_hooks_load, patch(
            "acme_srv.certificate.error_dic_get"
        ) as mock_error_dic_get:

            # Setup mock returns
            mock_dbstore_class.return_value = self.dbstore_mock
            mock_message_class.return_value = self.message_mock
            mock_load_config.return_value = {}
            # Fix CA handler to support context manager protocol
            mock_cahandler = MagicMock()
            mock_cahandler_instance = MagicMock()
            mock_cahandler.return_value = mock_cahandler_instance
            mock_cahandler_instance.__enter__ = MagicMock(
                return_value=mock_cahandler_instance
            )
            mock_cahandler_instance.__exit__ = MagicMock(return_value=False)
            mock_ca_handler_load.return_value = mock_cahandler
            mock_hooks_load.return_value = None
            mock_error_dic_get.return_value = {
                "malformed": "malformed request",
                "serverinternal": "server error",
                "ratelimited": "rate limited",
                "badcsr": "bad csr",
            }

            self.certificate = Certificate(
                debug=self.debug, srv_name=self.srv_name, logger=self.mock_logger
            )

            # Ensure the mocks are properly connected after initialization
            self.certificate.dbstore = self.dbstore_mock
            self.certificate.message = self.message_mock

    def test_001_init_with_defaults(self):
        """Test Certificate initialization with default parameters"""
        with patch.dict("sys.modules", {"acme_srv.db_handler": MagicMock()}), patch(
            "acme_srv.certificate.DBstore"
        ) as mock_dbstore_class, patch(
            "acme_srv.certificate.Message"
        ) as mock_message_class, patch(
            "acme_srv.certificate.load_config"
        ) as mock_load_config, patch(
            "acme_srv.certificate.ca_handler_load"
        ) as mock_ca_handler_load, patch(
            "acme_srv.certificate.hooks_load"
        ) as mock_hooks_load, patch(
            "acme_srv.certificate.error_dic_get"
        ) as mock_error_dic_get:

            mock_load_config.return_value = {}
            mock_ca_handler_load.return_value = None
            mock_hooks_load.return_value = None
            mock_error_dic_get.return_value = {"malformed": "malformed request"}
            mock_dbstore_class.return_value = MagicMock()
            mock_message_class.return_value = MagicMock()

            cert = Certificate(logger=self.mock_logger)

            self.assertFalse(cert.debug)
            # Note: server_name might be None in default initialization
            self.assertIsNotNone(cert.logger)

    def test_002_init_with_custom_params(self):
        """Test Certificate initialization with custom parameters"""
        custom_logger = Mock()

        with patch.dict("sys.modules", {"acme_srv.db_handler": MagicMock()}), patch(
            "acme_srv.certificate.DBstore"
        ) as mock_dbstore_class, patch(
            "acme_srv.certificate.Message"
        ) as mock_message_class, patch(
            "acme_srv.certificate.load_config"
        ) as mock_load_config, patch(
            "acme_srv.certificate.ca_handler_load"
        ) as mock_ca_handler_load, patch(
            "acme_srv.certificate.hooks_load"
        ) as mock_hooks_load, patch(
            "acme_srv.certificate.error_dic_get"
        ) as mock_error_dic_get:

            mock_load_config.return_value = {}
            mock_ca_handler_load.return_value = None
            mock_hooks_load.return_value = None
            mock_error_dic_get.return_value = {"malformed": "malformed request"}

            cert = Certificate(
                debug=True, srv_name="custom_server", logger=custom_logger
            )

            self.assertTrue(cert.debug)
            self.assertEqual(cert.server_name, "custom_server")
            self.assertEqual(cert.logger, custom_logger)

    def test_003_context_manager_enter_exit(self):
        """Test Certificate as context manager"""
        with self.certificate as cert:
            self.assertIsInstance(cert, Certificate)

    @patch("acme_srv.certificate.uts_now")
    def test_004_dates_update_success(self, mock_uts_now):
        """Test dates_update method success"""
        mock_uts_now.return_value = 1699999999

        # Mock database response
        mock_certificates = [
            {
                "id": 1,
                "name": "cert1",
                "cert_raw": "cert_data_1",
                "issue_uts": 0,  # Set to 0 to trigger update
                "expire_uts": 0,
            },
            {
                "id": 2,
                "name": "cert2",
                "cert_raw": "cert_data_2",
                "issue_uts": 0,  # Set to 0 to trigger update
                "expire_uts": 0,
            },
        ]

        self.dbstore_mock.certificates_search.return_value = mock_certificates
        self.certificate._dates_update = Mock()

        self.certificate.dates_update()

        # Verify database calls
        self.dbstore_mock.certificates_search.assert_called_once()
        # Verify _dates_update was called for each certificate
        self.assertEqual(self.certificate._dates_update.call_count, 2)

    @patch("acme_srv.certificate.uts_now")
    def test_005_dates_update_empty_certificates(self, mock_uts_now):
        """Test dates_update with no certificates"""
        mock_uts_now.return_value = 1699999999
        self.dbstore_mock.certificates_search.return_value = []

        self.certificate.dates_update()

        self.dbstore_mock.certificates_search.assert_called_once()
        self.dbstore_mock.certificate_add.assert_not_called()

    @patch.object(Certificate, "_cert_dates_update")
    def test_006_dates_update_database_error(self, mock_cert_dates_update):
        """Test dates_update with database error"""
        # Mock certificate list to not be None
        self.dbstore_mock.certificates_search.return_value = [
            {"name": "cert1"},
            {"name": "cert2"},
        ]
        mock_cert_dates_update.side_effect = Exception("Database error")

        self.certificate.dates_update()

        self.dbstore_mock.certificates_search.assert_called_once()
        mock_cert_dates_update.assert_called()

    def test_007_certlist_search_success(self):
        """Test certlist_search method success"""
        mock_results = [
            {"name": "cert1", "csr": "csr1", "cert": "cert1_data"},
            {"name": "cert2", "csr": "csr2", "cert": "cert2_data"},
        ]

        self.dbstore_mock.certificates_search.return_value = mock_results

        result = self.certificate.certlist_search("name", "test_cert")

        self.assertEqual(result, mock_results)
        self.dbstore_mock.certificates_search.assert_called_once_with(
            "name", "test_cert", ["name", "csr", "cert", "order__name"]
        )

    def test_008_certlist_search_with_custom_vlist(self):
        """Test certlist_search with custom value list"""
        mock_results = [{"name": "cert1", "status": "valid"}]
        custom_vlist = ["name", "status"]

        self.dbstore_mock.certificates_search.return_value = mock_results

        result = self.certificate.certlist_search("status", "valid", custom_vlist)

        self.assertEqual(result, mock_results)
        self.dbstore_mock.certificates_search.assert_called_once_with(
            "status", "valid", custom_vlist
        )

    def test_009_certlist_search_database_error(self):
        """Test certlist_search with database error"""
        self.dbstore_mock.certificates_search.side_effect = Exception("Database error")

        result = self.certificate.certlist_search("name", "test_cert")

        self.assertIsNone(result)
        self.mock_logger.critical.assert_called_once()

    @patch("acme_srv.certificate.uts_now")
    @patch("acme_srv.certificate.uts_to_date_utc")
    def test_010_cleanup_modify_mode(self, mock_uts_to_date, mock_uts_now):
        """Test cleanup method in modify mode (purge=False)"""
        timestamp = 1699999999
        mock_uts_now.return_value = timestamp
        mock_uts_to_date.return_value = "2023-11-15 00:00:00"

        # Mock certificates to cleanup
        mock_certificates = [
            {
                "id": 1,
                "name": "cert1",
                "cert_raw": "cert_data_1",
                "issue_uts": 1699900000,
                "expire_uts": 1700000000,
            }
        ]

        self.dbstore_mock.certificates_search.return_value = mock_certificates
        self.dbstore_mock.certificate_add.return_value = True

        result = self.certificate.cleanup(timestamp, purge=False)

        # Verify the result structure
        self.assertIsInstance(result, tuple)
        self.assertEqual(len(result), 2)

        # Verify database calls
        self.dbstore_mock.certificates_search.assert_called()
        self.dbstore_mock.certificate_add.assert_called()
        self.dbstore_mock.certificate_delete.assert_not_called()

    @patch("acme_srv.certificate.uts_now")
    def test_011_cleanup_purge_mode(self, mock_uts_now):
        """Test cleanup method in purge mode (purge=True)"""
        timestamp = 1699999999
        mock_uts_now.return_value = timestamp

        # Mock certificates to cleanup
        mock_certificates = [
            {
                "id": 1,
                "name": "cert1",
                "cert_raw": "cert_data_1",
                "issue_uts": 1699900000,
                "expire_uts": 1700000000,
            }
        ]

        self.dbstore_mock.certificates_search.return_value = mock_certificates

        result = self.certificate.cleanup(timestamp, purge=True)

        # Verify the result structure
        self.assertIsInstance(result, tuple)
        self.assertEqual(len(result), 2)

        # Verify database calls
        self.dbstore_mock.certificates_search.assert_called()
        self.dbstore_mock.certificate_delete.assert_called()
        self.dbstore_mock.certificate_add.assert_not_called()

    @patch("acme_srv.certificate.uts_now")
    def test_012_cleanup_default_timestamp(self, mock_uts_now):
        """Test cleanup method with default timestamp"""
        mock_uts_now.return_value = 1699999999
        self.dbstore_mock.certificates_search.return_value = []

        result = self.certificate.cleanup()

        self.assertIsInstance(result, tuple)
        self.dbstore_mock.certificates_search.assert_called()

    @patch("acme_srv.certificate.string_sanitize")
    def test_013_new_get_valid_certificate(self, mock_string_sanitize):
        """Test new_get method with valid certificate"""
        mock_string_sanitize.return_value = "test_cert"

        # Mock certificate info
        mock_cert_info = {
            "name": "test_cert",
            "csr": "test_csr",
            "cert": "test_certificate_data",
            "order__name": "test_order",
            "order__status_id": 5,  # Valid status
        }

        self.certificate._info = Mock(return_value=mock_cert_info)
        self.certificate.server_name = "https://example.com"
        self.certificate.path_dic = {"cert_path": "/acme/cert/"}

        with patch("acme_srv.certificate.pembundle_to_list") as mock_pembundle:
            mock_pembundle.return_value = ["cert1", "cert2"]

            result = self.certificate.new_get("https://example.com/acme/cert/test_cert")

            self.assertEqual(result["code"], 200)
            self.assertIn("data", result)

    @patch("acme_srv.certificate.string_sanitize")
    def test_014_new_get_pending_certificate(self, mock_string_sanitize):
        """Test new_get method with pending certificate"""
        mock_string_sanitize.return_value = "test_cert"

        # Mock certificate info with pending status
        mock_cert_info = {"name": "test_cert", "order__status_id": 4}  # Pending status

        self.certificate._info = Mock(return_value=mock_cert_info)
        self.certificate.server_name = "https://example.com"
        self.certificate.path_dic = {"cert_path": "/acme/cert/"}

        result = self.certificate.new_get("https://example.com/acme/cert/test_cert")

        self.assertEqual(result["code"], 403)

    @patch("acme_srv.certificate.string_sanitize")
    def test_015_new_get_nonexistent_certificate(self, mock_string_sanitize):
        """Test new_get method with non-existent certificate"""
        mock_string_sanitize.return_value = "test_cert"

        self.certificate._info = Mock(return_value={})
        self.certificate.server_name = "https://example.com"
        self.certificate.path_dic = {"cert_path": "/acme/cert/"}

        result = self.certificate.new_get("https://example.com/acme/cert/test_cert")

        self.assertEqual(result["code"], 403)

    def test_016_new_post_success(self):
        """Test new_post method success"""
        content = "test_content"

        # Mock message check
        self.message_mock.check.return_value = (
            200,
            "success",
            "detail",
            {"url": "https://example.com/acme/cert/test_cert"},
            {},
            "account",
        )

        # Mock new_get method
        self.certificate.new_get = Mock(return_value={"code": 200, "data": "cert_data"})

        # Mock message.prepare_response to return proper structure
        self.message_mock.prepare_response.return_value = {
            "code": 200,
            "data": {"certificate": "cert_data"},
        }

        result = self.certificate.new_post(content)

        self.assertEqual(result["code"], 200)
        self.message_mock.check.assert_called_once_with(content)
        self.certificate.new_get.assert_called_once_with(
            "https://example.com/acme/cert/test_cert"
        )

    def test_017_new_post_invalid_message(self):
        """Test new_post method with invalid message"""
        content = "invalid_content"

        # Mock message check failure
        self.message_mock.check.return_value = (
            400,
            "error",
            "bad request",
            {},
            {},
            None,
        )
        self.message_mock.prepare_response.return_value = {
            "code": 400,
            "data": "bad request",
        }

        result = self.certificate.new_post(content)

        self.message_mock.check.assert_called_once_with(content)
        self.message_mock.prepare_response.assert_called_once()

    def test_018_new_post_missing_url(self):
        """Test new_post method with missing URL in protected header"""
        content = "test_content"

        # Mock message check with missing URL in protected
        self.message_mock.check.return_value = (
            200,
            "success",
            "detail",
            {},
            {},
            "account",
        )
        self.message_mock.prepare_response.return_value = {
            "code": 400,
            "data": "url missing in protected header",
        }

        result = self.certificate.new_post(content)

        self.message_mock.check.assert_called_once_with(content)
        self.message_mock.prepare_response.assert_called_once()

    def test_019_revoke_success(self):
        """Test revoke method success"""
        content = "revoke_content"

        # Mock message check
        self.message_mock.check.return_value = (
            200,
            "success",
            "detail",
            {},
            {"certificate": "test_cert", "reason": 1},
            "test_account",
        )

        # Mock revocation validation
        self.certificate._revocation_request_validate = Mock(return_value=(200, None))

        # Mock CA handler
        mock_ca_handler = Mock()
        mock_ca_handler.revoke.return_value = (200, "success", None)
        self.certificate.cahandler = Mock(return_value=mock_ca_handler)

        # Mock revocation logging
        self.certificate._cert_revocation_log = Mock()

        # Mock date utilities
        with patch("acme_srv.certificate.uts_now") as mock_uts_now, patch(
            "acme_srv.certificate.uts_to_date_utc"
        ) as mock_uts_to_date:

            mock_uts_now.return_value = 1699999999
            mock_uts_to_date.return_value = "2023-11-15 00:00:00"

            self.certificate.cert_operations_log = "json"
            result = self.certificate.revoke(content)

            self.message_mock.check.assert_called_once_with(content)
            self.certificate._revocation_request_validate.assert_called_once()
            self.certificate._cert_revocation_log.assert_called_once()

    def test_020_revoke_missing_certificate(self):
        """Test revoke method with missing certificate"""
        content = "revoke_content"

        # Mock message check without certificate
        self.message_mock.check.return_value = (
            200,
            "success",
            "detail",
            {},
            {},
            "test_account",
        )
        self.message_mock.prepare_response.return_value = {
            "code": 400,
            "type": "malformed",
        }

        result = self.certificate.revoke(content)

        self.message_mock.check.assert_called_once_with(content)
        self.message_mock.prepare_response.assert_called_once()

    def test_021_revoke_invalid_message(self):
        """Test revoke method with invalid message"""
        content = "invalid_content"

        # Mock message check failure
        self.message_mock.check.return_value = (
            400,
            "error",
            "bad request",
            {},
            {},
            None,
        )
        self.message_mock.prepare_response.return_value = {"code": 400, "type": "error"}

        result = self.certificate.revoke(content)

        self.message_mock.check.assert_called_once_with(content)
        self.message_mock.prepare_response.assert_called_once()

    def test_022_revoke_validation_failure(self):
        """Test revoke method with validation failure"""
        content = "revoke_content"

        # Mock message check
        self.message_mock.check.return_value = (
            200,
            "success",
            "detail",
            {},
            {"certificate": "test_cert"},
            "test_account",
        )

        # Mock revocation validation failure
        self.certificate._revocation_request_validate = Mock(
            return_value=(403, "unauthorized")
        )
        self.message_mock.prepare_response.return_value = {
            "code": 403,
            "type": "unauthorized",
        }

        result = self.certificate.revoke(content)

        self.certificate._revocation_request_validate.assert_called_once()
        self.message_mock.prepare_response.assert_called_once()

    def test_023_poll_success_with_certificate(self):
        """Test poll method success with certificate returned"""
        certificate_name = "test_cert"
        poll_identifier = "poll_123"
        csr = "test_csr"
        order_name = "test_order"

        # Mock CA handler
        mock_ca_handler = Mock()
        mock_ca_handler.poll.return_value = (
            None,  # error
            "certificate_data",  # certificate
            "raw_certificate_data",  # certificate_raw
            "poll_456",  # new poll_identifier
            False,  # rejected
        )
        self.certificate.cahandler = Mock(return_value=mock_ca_handler)

        # Mock certificate storage
        self.certificate._store_cert = Mock(return_value=True)
        self.dbstore_mock.order_update.return_value = True

        with patch("acme_srv.certificate.cert_dates_get") as mock_cert_dates:
            mock_cert_dates.return_value = (1699900000, 1700000000)

            result = self.certificate.poll(
                certificate_name, poll_identifier, csr, order_name
            )

            mock_ca_handler.poll.assert_called_once_with(
                certificate_name, poll_identifier, csr
            )
            self.certificate._store_cert.assert_called_once()
            self.dbstore_mock.order_update.assert_called_once_with(
                {"name": order_name, "status": "valid"}
            )

    def test_024_poll_failure_with_error(self):
        """Test poll method with error from CA handler"""
        certificate_name = "test_cert"
        poll_identifier = "poll_123"
        csr = "test_csr"
        order_name = "test_order"

        # Mock CA handler with error
        mock_ca_handler = Mock()
        mock_ca_handler.poll.return_value = (
            "Certificate not ready",  # error
            None,  # certificate
            None,  # certificate_raw
            "poll_456",  # poll_identifier
            False,  # rejected
        )
        self.certificate.cahandler = Mock(return_value=mock_ca_handler)

        # Mock error storage
        self.certificate._store_cert_error = Mock(return_value=True)

        result = self.certificate.poll(
            certificate_name, poll_identifier, csr, order_name
        )

        mock_ca_handler.poll.assert_called_once_with(
            certificate_name, poll_identifier, csr
        )
        self.certificate._store_cert_error.assert_called_once_with(
            certificate_name, "Certificate not ready", "poll_456"
        )

    def test_025_poll_rejected_certificate(self):
        """Test poll method with rejected certificate"""
        certificate_name = "test_cert"
        poll_identifier = "poll_123"
        csr = "test_csr"
        order_name = "test_order"

        # Mock CA handler with rejection
        mock_ca_handler = Mock()
        mock_ca_handler.poll.return_value = (
            "Certificate rejected",  # error
            None,  # certificate
            None,  # certificate_raw
            None,  # poll_identifier
            True,  # rejected
        )
        self.certificate.cahandler = Mock(return_value=mock_ca_handler)

        # Mock error storage and order update
        self.certificate._store_cert_error = Mock(return_value=True)
        self.dbstore_mock.order_update.return_value = True

        result = self.certificate.poll(
            certificate_name, poll_identifier, csr, order_name
        )

        mock_ca_handler.poll.assert_called_once()
        self.certificate._store_cert_error.assert_called_once()
        self.dbstore_mock.order_update.assert_called_once_with(
            {"name": order_name, "status": "invalid"}
        )

    @patch("acme_srv.certificate.generate_random_string")
    def test_026_store_csr_success(self, mock_gen_string):
        """Test store_csr method success"""
        order_name = "test_order"
        csr = "test_csr"

        mock_gen_string.return_value = "random_cert_name"
        self.certificate._csr_check = Mock(return_value=(200, None, None))
        self.dbstore_mock.certificate_add.return_value = True

        result = self.certificate.store_csr(order_name, csr)

        self.certificate._csr_check.assert_called_once_with(csr)
        self.dbstore_mock.certificate_add.assert_called_once()
        self.assertEqual(result, "random_cert_name")

    @patch("acme_srv.certificate.generate_random_string")
    def test_027_store_csr_database_error(self, mock_gen_string):
        """Test store_csr method with database error"""
        order_name = "test_order"
        csr = "test_csr"

        mock_gen_string.return_value = "random_cert_name"
        self.certificate._csr_check = Mock(return_value=(200, None, None))
        self.dbstore_mock.certificate_add.side_effect = Exception("Database error")

        result = self.certificate.store_csr(order_name, csr)

        self.certificate._csr_check.assert_called_once_with(csr)
        self.dbstore_mock.certificate_add.assert_called_once()
        # Should still return a certificate name even with database error
        self.assertEqual(result, "random_cert_name")

    def test_028_certlist_search_integer_value(self):
        """Test certlist_search method with integer value"""
        mock_results = [{"id": 123, "name": "cert123"}]

        self.dbstore_mock.certificates_search.return_value = mock_results

        result = self.certificate.certlist_search("id", 123)

        self.assertEqual(result, mock_results)
        self.dbstore_mock.certificates_search.assert_called_once_with(
            "id", 123, ["name", "csr", "cert", "order__name"]
        )

    def test_029_cleanup_database_error_during_cleanup(self):
        """Test cleanup method with database error during cleanup operations"""
        timestamp = 1699999999

        # Mock certificates that will cause database error during cleanup
        mock_certificates = [
            {
                "id": 1,
                "name": "cert1",
                "cert_raw": "cert_data_1",
                "issue_uts": 1699900000,
                "expire_uts": 1700000000,
            }
        ]

        self.dbstore_mock.certificates_search.return_value = mock_certificates
        self.dbstore_mock.certificate_add.side_effect = Exception("Database error")

        with patch("acme_srv.certificate.uts_to_date_utc") as mock_uts_to_date:
            mock_uts_to_date.return_value = "2023-11-15 00:00:00"

            result = self.certificate.cleanup(timestamp, purge=False)

            self.assertIsInstance(result, tuple)
            self.mock_logger.critical.assert_called()

    @patch("acme_srv.certificate.string_sanitize")
    def test_030_new_get_certificate_without_cert_data(self, mock_string_sanitize):
        """Test new_get method when certificate exists but has no cert data"""
        mock_string_sanitize.return_value = "test_cert"

        # Mock certificate info with valid status but no cert data
        mock_cert_info = {
            "name": "test_cert",
            "order__status_id": 5,  # Valid status
            "cert": None,  # No certificate data
        }

        self.certificate._info = Mock(return_value=mock_cert_info)
        self.certificate.server_name = "https://example.com"
        self.certificate.path_dic = {"cert_path": "/acme/cert/"}

        result = self.certificate.new_get("https://example.com/acme/cert/test_cert")

        self.assertEqual(result["code"], 403)

    def test_031_poll_database_error_during_order_update(self):
        """Test poll method with database error during order update"""
        certificate_name = "test_cert"
        poll_identifier = "poll_123"
        csr = "test_csr"
        order_name = "test_order"

        # Mock CA handler returning certificate
        mock_ca_handler = Mock()
        mock_ca_handler.poll.return_value = (
            None,
            "certificate_data",
            "raw_certificate_data",
            None,
            False,
        )
        self.certificate.cahandler = Mock(return_value=mock_ca_handler)

        # Mock certificate storage success but order update failure
        self.certificate._store_cert = Mock(return_value=True)
        self.dbstore_mock.order_update.side_effect = Exception("Database error")

        with patch("acme_srv.certificate.cert_dates_get") as mock_cert_dates:
            mock_cert_dates.return_value = (1699900000, 1700000000)

            result = self.certificate.poll(
                certificate_name, poll_identifier, csr, order_name
            )

            self.mock_logger.critical.assert_called()

    def test_032_revoke_ca_handler_error(self):
        """Test revoke method with CA handler error"""
        content = "revoke_content"

        # Mock message check
        self.message_mock.check.return_value = (
            200,
            "success",
            "detail",
            {},
            {"certificate": "test_cert", "reason": 1},
            "test_account",
        )

        # Mock successful validation
        self.certificate._revocation_request_validate = Mock(return_value=(200, 1))

        # Mock CA handler with error
        mock_ca_handler = Mock()
        mock_ca_handler.revoke.return_value = (500, "CA error", "Internal CA error")
        self.certificate.cahandler = Mock(return_value=mock_ca_handler)

        # Mock revocation logging
        self.certificate._cert_revocation_log = Mock()
        self.message_mock.prepare_response.return_value = {
            "code": 500,
            "type": "CA error",
        }

        with patch("acme_srv.certificate.uts_now") as mock_uts_now, patch(
            "acme_srv.certificate.uts_to_date_utc"
        ) as mock_uts_to_date:

            mock_uts_now.return_value = 1699999999
            mock_uts_to_date.return_value = "2023-11-15 00:00:00"

            self.certificate.cert_operations_log = "json"
            result = self.certificate.revoke(content)

            mock_ca_handler.revoke.assert_called_once()
            self.certificate._cert_revocation_log.assert_called_once_with(
                "test_cert", 500
            )

    def test_033_dates_update_cert_dates_error(self):
        """Test dates_update with cert_dates_get error"""
        # Mock database response
        mock_certificates = [
            {
                "id": 1,
                "name": "cert1",
                "cert_raw": "invalid_cert_data",
                "issue_uts": 1699900000,
                "expire_uts": 1700000000,
            }
        ]

        self.dbstore_mock.certificates_search.return_value = mock_certificates

        with patch("acme_srv.certificate.cert_dates_get") as mock_cert_dates_get:
            mock_cert_dates_get.side_effect = Exception("Invalid certificate data")

            with patch("acme_srv.certificate.uts_now") as mock_uts_now:
                mock_uts_now.return_value = 1699999999

                self.certificate.dates_update()

                # Verify error was logged
                self.mock_logger.error.assert_called()

    def test_034_new_post_with_response_preparation_error(self):
        """Test new_post method when response preparation encounters issues"""
        content = "test_content"

        # Mock message check failure
        self.message_mock.check.return_value = (
            400,
            "malformed",
            "Invalid JSON",
            {},
            {},
            None,
        )
        self.message_mock.prepare_response.return_value = {
            "code": 400,
            "type": "malformed",
            "detail": "Invalid JSON",
        }

        result = self.certificate.new_post(content)

        self.message_mock.check.assert_called_once_with(content)
        self.message_mock.prepare_response.assert_called_once()
        self.assertIn("code", result)

    def test_035_certlist_search_none_vlist_handling(self):
        """Test certlist_search method with None as vlist parameter"""
        mock_results = [{"name": "cert1", "csr": "csr1"}]

        self.dbstore_mock.certificates_search.return_value = mock_results

        # Explicitly pass None for vlist
        result = self.certificate.certlist_search("name", "test_cert", None)

        self.assertEqual(result, mock_results)
        self.dbstore_mock.certificates_search.assert_called_once_with(
            "name", "test_cert", ["name", "csr", "cert", "order__name"]
        )

    def test_036_enroll_and_store_success(self):
        """Test enroll_and_store method success"""
        certificate_name = "test_cert"
        csr = "test_csr_data"
        order_name = "test_order"

        # Mock CSR check to return True
        self.certificate._csr_check = Mock(return_value=True)
        self.certificate._enroll_and_store = Mock(
            return_value=("certificate_data", "poll_identifier")
        )

        # Mock ThreadWithReturnValue
        with patch("acme_srv.certificate.ThreadWithReturnValue") as mock_thread:
            mock_thread_instance = Mock()
            mock_thread_instance.join.return_value = None
            mock_thread_instance.result = ("certificate_data", "poll_identifier")
            mock_thread.return_value = mock_thread_instance

            result = self.certificate.enroll_and_store(
                certificate_name, csr, order_name
            )

            self.certificate._csr_check.assert_called_once_with(certificate_name, csr)
            mock_thread.assert_called_once()

    def test_037_enroll_and_store_csr_check_failure(self):
        """Test enroll_and_store method with CSR check failure"""
        certificate_name = "test_cert"
        csr = "invalid_csr_data"
        order_name = "test_order"

        # Mock CSR check to return False
        self.certificate._csr_check = Mock(return_value=False)

        result = self.certificate.enroll_and_store(certificate_name, csr, order_name)

        self.certificate._csr_check.assert_called_once_with(certificate_name, csr)
        # Should not proceed to enrollment if CSR check fails
        self.assertEqual(result, (None, None))


if __name__ == "__main__":
    unittest.main()
