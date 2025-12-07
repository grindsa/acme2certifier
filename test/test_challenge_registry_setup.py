#!/usr/bin/python
# -*- coding: utf-8 -*-
"""Comprehensive unit tests for challenge_registry_setup.py"""
# pylint: disable=C0302, C0415, R0904, R0913, R0914, R0915, W0212
import unittest
import sys
import logging
from unittest.mock import Mock, patch, call

sys.path.insert(0, ".")
sys.path.insert(1, "..")


class MockConfig:
    """Mock configuration object for testing"""

    def __init__(self, **kwargs):
        self.email_identifier_support = kwargs.get("email_identifier_support", False)
        self.tnauthlist_support = kwargs.get("tnauthlist_support", False)
        self.forward_address_check = kwargs.get("forward_address_check", False)
        self.reverse_address_check = kwargs.get("reverse_address_check", False)


class TestChallengeRegistrySetup(unittest.TestCase):
    """Test cases for challenge_registry_setup.py functions"""

    def setUp(self):
        """Setup for tests"""
        self.logger = Mock(spec=logging.Logger)
        self.config = MockConfig()

    @patch.dict(
        "sys.modules",
        {
            "OpenSSL": Mock(),
            "OpenSSL.crypto": Mock(),
            "acme_srv.helper": Mock(),
            "acme_srv.helpers.certificates": Mock(),
            "acme_srv.challenge_validators": Mock(),
        },
    )
    def test_001_create_challenge_validator_registry_basic(self):
        """Test basic challenge validator registry creation with minimal config"""

        # Mock all the validator classes
        mock_registry = Mock()
        mock_registry_instance = Mock()
        mock_registry_instance.get_supported_types.return_value = [
            "http-01",
            "dns-01",
            "tls-alpn-01",
        ]
        mock_registry.return_value = mock_registry_instance

        mock_http_validator = Mock()
        mock_dns_validator = Mock()
        mock_tls_validator = Mock()
        mock_email_validator = Mock()
        mock_tkauth_validator = Mock()
        mock_source_validator = Mock()

        mock_http_instance = Mock()
        mock_dns_instance = Mock()
        mock_tls_instance = Mock()

        mock_http_validator.return_value = mock_http_instance
        mock_dns_validator.return_value = mock_dns_instance
        mock_tls_validator.return_value = mock_tls_instance

        # Patch both the source module and the target module where imports are used
        with patch.multiple(
            "acme_srv.challenge_validators",
            ChallengeValidatorRegistry=mock_registry,
            HttpChallengeValidator=mock_http_validator,
            DnsChallengeValidator=mock_dns_validator,
            TlsAlpnChallengeValidator=mock_tls_validator,
            EmailReplyChallengeValidator=mock_email_validator,
            TkauthChallengeValidator=mock_tkauth_validator,
            SourceAddressValidator=mock_source_validator,
        ), patch.multiple(
            "acme_srv.challenge_registry_setup",
            ChallengeValidatorRegistry=mock_registry,
            HttpChallengeValidator=mock_http_validator,
            DnsChallengeValidator=mock_dns_validator,
            TlsAlpnChallengeValidator=mock_tls_validator,
            EmailReplyChallengeValidator=mock_email_validator,
            TkauthChallengeValidator=mock_tkauth_validator,
            SourceAddressValidator=mock_source_validator,
        ):

            # Import and test
            from acme_srv.challenge_registry_setup import (
                create_challenge_validator_registry,
            )

            # Test with minimal config (no optional validators)
            config = MockConfig(
                email_identifier_support=False,
                tnauthlist_support=False,
                forward_address_check=False,
                reverse_address_check=False,
            )

            result = create_challenge_validator_registry(self.logger, config)

            # Verify registry creation
            mock_registry.assert_called_once_with(self.logger)
            self.assertEqual(result, mock_registry_instance)

            # Verify standard validators registered
            mock_http_validator.assert_called_once_with(self.logger)
            mock_dns_validator.assert_called_once_with(self.logger)
            mock_tls_validator.assert_called_once_with(self.logger)

            expected_calls = [
                call.register_validator(mock_http_instance),
                call.register_validator(mock_dns_instance),
                call.register_validator(mock_tls_instance),
            ]
            mock_registry_instance.register_validator.assert_has_calls(
                expected_calls, any_order=True
            )

            # Verify optional validators NOT called
            mock_email_validator.assert_not_called()
            mock_tkauth_validator.assert_not_called()
            mock_source_validator.assert_called_once()

            # Verify logging
            self.logger.debug.assert_has_calls(
                [
                    call(
                        "challenge_registry_setup.create_challenge_validator_registry()"
                    ),
                    call(
                        "create_challenge_validator_registry(): Registry created with %d validators: %s",
                        3,
                        "http-01, dns-01, tls-alpn-01",
                    ),
                    call(
                        "challenge_registry_setup.create_challenge_validator_registry() ended"
                    ),
                ]
            )

    @patch.dict(
        "sys.modules",
        {
            "OpenSSL": Mock(),
            "OpenSSL.crypto": Mock(),
            "acme_srv.helper": Mock(),
            "acme_srv.helpers.certificates": Mock(),
            "acme_srv.challenge_validators": Mock(),
        },
    )
    def test_002_create_challenge_validator_registry_email_support(self):
        """Test registry creation with email identifier support enabled"""

        # Mock all the validator classes
        mock_registry = Mock()
        mock_registry_instance = Mock()
        mock_registry_instance.get_supported_types.return_value = [
            "http-01",
            "dns-01",
            "tls-alpn-01",
            "email-reply-00",
        ]
        mock_registry.return_value = mock_registry_instance

        mock_http_validator = Mock()
        mock_dns_validator = Mock()
        mock_tls_validator = Mock()
        mock_email_validator = Mock()
        mock_tkauth_validator = Mock()
        mock_source_validator = Mock()

        mock_email_instance = Mock()
        mock_email_validator.return_value = mock_email_instance

        # Patch both the source module and the target module where imports are used
        with patch.multiple(
            "acme_srv.challenge_validators",
            ChallengeValidatorRegistry=mock_registry,
            HttpChallengeValidator=mock_http_validator,
            DnsChallengeValidator=mock_dns_validator,
            TlsAlpnChallengeValidator=mock_tls_validator,
            EmailReplyChallengeValidator=mock_email_validator,
            TkauthChallengeValidator=mock_tkauth_validator,
            SourceAddressValidator=mock_source_validator,
        ), patch.multiple(
            "acme_srv.challenge_registry_setup",
            ChallengeValidatorRegistry=mock_registry,
            HttpChallengeValidator=mock_http_validator,
            DnsChallengeValidator=mock_dns_validator,
            TlsAlpnChallengeValidator=mock_tls_validator,
            EmailReplyChallengeValidator=mock_email_validator,
            TkauthChallengeValidator=mock_tkauth_validator,
            SourceAddressValidator=mock_source_validator,
        ):

            from acme_srv.challenge_registry_setup import (
                create_challenge_validator_registry,
            )

            # Test with email support enabled
            config = MockConfig(email_identifier_support=True)

            create_challenge_validator_registry(self.logger, config)

            # Verify email validator registered
            mock_email_validator.assert_called_once_with(self.logger)
            mock_registry_instance.register_validator.assert_any_call(
                mock_email_instance
            )

            # Verify tkauth and source validators NOT called
            mock_tkauth_validator.assert_not_called()
            mock_source_validator.assert_called_once()
            mock_http_validator.assert_called_once()
            mock_dns_validator.assert_called_once()
            mock_tls_validator.assert_called_once()

    @patch.dict(
        "sys.modules",
        {
            "OpenSSL": Mock(),
            "OpenSSL.crypto": Mock(),
            "acme_srv.helper": Mock(),
            "acme_srv.helpers.certificates": Mock(),
            "acme_srv.challenge_validators": Mock(),
        },
    )
    def test_003_create_challenge_validator_registry_all_enabled(self):
        """Test registry creation with all optional features enabled"""

        # Mock all the validator classes
        mock_registry = Mock()
        mock_registry_instance = Mock()
        mock_registry_instance.get_supported_types.return_value = [
            "http-01",
            "dns-01",
            "tls-alpn-01",
            "email-reply-00",
            "tkauth-01",
            "source-address",
        ]
        mock_registry.return_value = mock_registry_instance

        mock_http_validator = Mock()
        mock_dns_validator = Mock()
        mock_tls_validator = Mock()
        mock_email_validator = Mock()
        mock_tkauth_validator = Mock()
        mock_source_validator = Mock()

        mock_http_instance = Mock()
        mock_dns_instance = Mock()
        mock_tls_instance = Mock()
        mock_email_instance = Mock()
        mock_tkauth_instance = Mock()
        mock_source_instance = Mock()

        mock_http_validator.return_value = mock_http_instance
        mock_dns_validator.return_value = mock_dns_instance
        mock_tls_validator.return_value = mock_tls_instance
        mock_email_validator.return_value = mock_email_instance
        mock_tkauth_validator.return_value = mock_tkauth_instance
        mock_source_validator.return_value = mock_source_instance

        # Patch both the source module and the target module where imports are used
        with patch.multiple(
            "acme_srv.challenge_validators",
            ChallengeValidatorRegistry=mock_registry,
            HttpChallengeValidator=mock_http_validator,
            DnsChallengeValidator=mock_dns_validator,
            TlsAlpnChallengeValidator=mock_tls_validator,
            EmailReplyChallengeValidator=mock_email_validator,
            TkauthChallengeValidator=mock_tkauth_validator,
            SourceAddressValidator=mock_source_validator,
        ), patch.multiple(
            "acme_srv.challenge_registry_setup",
            ChallengeValidatorRegistry=mock_registry,
            HttpChallengeValidator=mock_http_validator,
            DnsChallengeValidator=mock_dns_validator,
            TlsAlpnChallengeValidator=mock_tls_validator,
            EmailReplyChallengeValidator=mock_email_validator,
            TkauthChallengeValidator=mock_tkauth_validator,
            SourceAddressValidator=mock_source_validator,
        ):

            from acme_srv.challenge_registry_setup import (
                create_challenge_validator_registry,
            )

            # Test with all features enabled
            config = MockConfig(
                email_identifier_support=True,
                tnauthlist_support=True,
                forward_address_check=True,
                reverse_address_check=True,
            )

            create_challenge_validator_registry(self.logger, config)

            # Verify all validators created and registered
            mock_http_validator.assert_called_once_with(self.logger)
            mock_dns_validator.assert_called_once_with(self.logger)
            mock_tls_validator.assert_called_once_with(self.logger)
            mock_email_validator.assert_called_once_with(self.logger)
            mock_tkauth_validator.assert_called_once_with(self.logger)
            mock_source_validator.assert_called_once_with(
                self.logger, forward_check=True, reverse_check=True
            )

            expected_calls = [
                call.register_validator(mock_http_instance),
                call.register_validator(mock_dns_instance),
                call.register_validator(mock_tls_instance),
                call.register_validator(mock_email_instance),
                call.register_validator(mock_tkauth_instance),
                call.register_validator(mock_source_instance),
            ]
            mock_registry_instance.register_validator.assert_has_calls(
                expected_calls, any_order=True
            )

            # Verify logging - the function uses debug(), not info()
            self.logger.debug.assert_has_calls(
                [
                    call(
                        "challenge_registry_setup.create_challenge_validator_registry()"
                    ),
                    call(
                        "create_challenge_validator_registry(): Registry created with %d validators: %s",
                        6,
                        "http-01, dns-01, tls-alpn-01, email-reply-00, tkauth-01, source-address",
                    ),
                    call(
                        "challenge_registry_setup.create_challenge_validator_registry() ended"
                    ),
                ]
            )

    @patch.dict(
        "sys.modules",
        {
            "OpenSSL": Mock(),
            "OpenSSL.crypto": Mock(),
            "acme_srv.helper": Mock(),
            "acme_srv.helpers.certificates": Mock(),
            "acme_srv.challenge_validators": Mock(),
        },
    )
    def test_004_create_challenge_validator_registry_none_config(self):
        """Test registry creation with None config"""

        # Mock all the validator classes
        mock_registry = Mock()
        mock_registry_instance = Mock()
        mock_registry.return_value = mock_registry_instance

        mock_http_validator = Mock()
        mock_dns_validator = Mock()
        mock_tls_validator = Mock()
        mock_email_validator = Mock()
        mock_tkauth_validator = Mock()
        mock_source_validator = Mock()

        # Patch both the source module and the target module where imports are used
        with patch.multiple(
            "acme_srv.challenge_validators",
            ChallengeValidatorRegistry=mock_registry,
            HttpChallengeValidator=mock_http_validator,
            DnsChallengeValidator=mock_dns_validator,
            TlsAlpnChallengeValidator=mock_tls_validator,
            EmailReplyChallengeValidator=mock_email_validator,
            TkauthChallengeValidator=mock_tkauth_validator,
            SourceAddressValidator=mock_source_validator,
        ), patch.multiple(
            "acme_srv.challenge_registry_setup",
            ChallengeValidatorRegistry=mock_registry,
            HttpChallengeValidator=mock_http_validator,
            DnsChallengeValidator=mock_dns_validator,
            TlsAlpnChallengeValidator=mock_tls_validator,
            EmailReplyChallengeValidator=mock_email_validator,
            TkauthChallengeValidator=mock_tkauth_validator,
            SourceAddressValidator=mock_source_validator,
        ):

            from acme_srv.challenge_registry_setup import (
                create_challenge_validator_registry,
            )

            # Test with None config - should handle gracefully
            try:
                create_challenge_validator_registry(self.logger, None)
                # This should raise an AttributeError since None.email_identifier_support would fail
                self.fail("Expected AttributeError for None config")
            except AttributeError:
                # Expected behavior
                pass

    @patch.dict(
        "sys.modules",
        {
            "OpenSSL": Mock(),
            "OpenSSL.crypto": Mock(),
            "acme_srv.helper": Mock(),
            "acme_srv.helpers.certificates": Mock(),
            "acme_srv.challenge_validators": Mock(),
        },
    )
    def test_005_create_challenge_validator_registry_registry_exception(self):
        """Test registry creation when registry constructor raises exception"""

        # Mock all the validator classes
        mock_registry = Mock()
        mock_registry.side_effect = Exception("Registry creation failed")

        mock_http_validator = Mock()
        mock_dns_validator = Mock()
        mock_tls_validator = Mock()
        mock_email_validator = Mock()
        mock_tkauth_validator = Mock()
        mock_source_validator = Mock()

        # Patch both the source module and the target module where imports are used
        with patch.multiple(
            "acme_srv.challenge_validators",
            ChallengeValidatorRegistry=mock_registry,
            HttpChallengeValidator=mock_http_validator,
            DnsChallengeValidator=mock_dns_validator,
            TlsAlpnChallengeValidator=mock_tls_validator,
            EmailReplyChallengeValidator=mock_email_validator,
            TkauthChallengeValidator=mock_tkauth_validator,
            SourceAddressValidator=mock_source_validator,
        ), patch.multiple(
            "acme_srv.challenge_registry_setup",
            ChallengeValidatorRegistry=mock_registry,
            HttpChallengeValidator=mock_http_validator,
            DnsChallengeValidator=mock_dns_validator,
            TlsAlpnChallengeValidator=mock_tls_validator,
            EmailReplyChallengeValidator=mock_email_validator,
            TkauthChallengeValidator=mock_tkauth_validator,
            SourceAddressValidator=mock_source_validator,
        ):

            from acme_srv.challenge_registry_setup import (
                create_challenge_validator_registry,
            )

            config = MockConfig()

            with self.assertRaises(Exception) as context:
                create_challenge_validator_registry(self.logger, config)

            self.assertEqual(str(context.exception), "Registry creation failed")

    @patch.dict(
        "sys.modules",
        {
            "OpenSSL": Mock(),
            "OpenSSL.crypto": Mock(),
            "acme_srv.helper": Mock(),
            "acme_srv.helpers.certificates": Mock(),
            "acme_srv.challenge_validators": Mock(),
        },
    )
    def test_006_create_custom_registry_basic(self):
        """Test basic custom registry creation"""

        # Mock all the validator classes
        mock_registry = Mock()
        mock_registry_instance = Mock()
        mock_registry_instance.get_supported_types.return_value = ["mock-01", "mock-02"]
        mock_registry.return_value = mock_registry_instance

        # Patch both the source module and the target module where imports are used
        with patch.multiple(
            "acme_srv.challenge_validators", ChallengeValidatorRegistry=mock_registry
        ), patch.multiple(
            "acme_srv.challenge_registry_setup",
            ChallengeValidatorRegistry=mock_registry,
        ):

            from acme_srv.challenge_registry_setup import create_custom_registry

            # Create mock validator classes
            mock_validator_class1 = Mock()
            mock_validator_class2 = Mock()
            mock_validator1 = Mock()
            mock_validator2 = Mock()
            mock_validator_class1.return_value = mock_validator1
            mock_validator_class2.return_value = mock_validator2

            validator_classes = [mock_validator_class1, mock_validator_class2]

            result = create_custom_registry(self.logger, validator_classes)

            # Verify registry creation
            mock_registry.assert_called_once_with(self.logger)
            self.assertEqual(result, mock_registry_instance)

            # Verify validators created and registered
            mock_validator_class1.assert_called_once_with(self.logger)
            mock_validator_class2.assert_called_once_with(self.logger)

            expected_calls = [
                call.register_validator(mock_validator1),
                call.register_validator(mock_validator2),
            ]
            mock_registry_instance.register_validator.assert_has_calls(
                expected_calls, any_order=True
            )

            # Verify logging
            self.logger.info.assert_called_once()
            info_call_args = self.logger.info.call_args[0]
            self.assertIn(
                "Custom challenge validator registry created with 2 validators",
                info_call_args[0] % 2,
            )

    @patch.dict(
        "sys.modules",
        {
            "OpenSSL": Mock(),
            "OpenSSL.crypto": Mock(),
            "acme_srv.helper": Mock(),
            "acme_srv.helpers.certificates": Mock(),
            "acme_srv.challenge_validators": Mock(),
        },
    )
    def test_007_create_custom_registry_empty_validators(self):
        """Test custom registry creation with empty validator list"""

        # Mock all the validator classes
        mock_registry = Mock()
        mock_registry_instance = Mock()
        mock_registry_instance.get_supported_types.return_value = []
        mock_registry.return_value = mock_registry_instance

        # Patch both the source module and the target module where imports are used
        with patch.multiple(
            "acme_srv.challenge_validators", ChallengeValidatorRegistry=mock_registry
        ), patch.multiple(
            "acme_srv.challenge_registry_setup",
            ChallengeValidatorRegistry=mock_registry,
        ):

            from acme_srv.challenge_registry_setup import create_custom_registry

            validator_classes = []

            result = create_custom_registry(self.logger, validator_classes)

            # Verify registry creation
            mock_registry.assert_called_once_with(self.logger)
            self.assertEqual(result, mock_registry_instance)

            # Verify no validators registered
            mock_registry_instance.register_validator.assert_not_called()

            # Verify logging
            self.logger.info.assert_called_once()
            info_call_args = self.logger.info.call_args[0]
            self.assertIn(
                "Custom challenge validator registry created with 0 validators",
                info_call_args[0] % 0,
            )

    @patch.dict(
        "sys.modules",
        {
            "OpenSSL": Mock(),
            "OpenSSL.crypto": Mock(),
            "acme_srv.helper": Mock(),
            "acme_srv.helpers.certificates": Mock(),
            "acme_srv.challenge_validators": Mock(),
        },
    )
    def test_008_create_custom_registry_none_validator_classes(self):
        """Test custom registry creation with None validator classes"""

        # Mock all the validator classes
        mock_registry = Mock()
        mock_registry_instance = Mock()
        mock_registry.return_value = mock_registry_instance

        # Patch both the source module and the target module where imports are used
        with patch.multiple(
            "acme_srv.challenge_validators", ChallengeValidatorRegistry=mock_registry
        ), patch.multiple(
            "acme_srv.challenge_registry_setup",
            ChallengeValidatorRegistry=mock_registry,
        ):

            from acme_srv.challenge_registry_setup import create_custom_registry

            # Test with None validator classes - should raise TypeError
            with self.assertRaises(TypeError):
                create_custom_registry(self.logger, None)

    @patch.dict(
        "sys.modules",
        {
            "OpenSSL": Mock(),
            "OpenSSL.crypto": Mock(),
            "acme_srv.helper": Mock(),
            "acme_srv.helpers.certificates": Mock(),
            "acme_srv.challenge_validators": Mock(),
        },
    )
    def test_009_create_custom_registry_validator_exception(self):
        """Test custom registry creation when validator constructor raises exception"""

        # Mock all the validator classes
        mock_registry = Mock()
        mock_registry_instance = Mock()
        mock_registry.return_value = mock_registry_instance

        # Patch both the source module and the target module where imports are used
        with patch.multiple(
            "acme_srv.challenge_validators", ChallengeValidatorRegistry=mock_registry
        ), patch.multiple(
            "acme_srv.challenge_registry_setup",
            ChallengeValidatorRegistry=mock_registry,
        ):

            from acme_srv.challenge_registry_setup import create_custom_registry

            mock_validator_class = Mock()
            mock_validator_class.side_effect = Exception("Validator creation failed")

            validator_classes = [mock_validator_class]

            with self.assertRaises(Exception) as context:
                create_custom_registry(self.logger, validator_classes)

            self.assertEqual(str(context.exception), "Validator creation failed")

    @patch.dict(
        "sys.modules",
        {
            "OpenSSL": Mock(),
            "OpenSSL.crypto": Mock(),
            "acme_srv.helper": Mock(),
            "acme_srv.helpers.certificates": Mock(),
            "acme_srv.challenge_validators": Mock(),
        },
    )
    def test_010_create_custom_registry_registration_exception(self):
        """Test custom registry creation when validator registration raises exception"""

        # Mock all the validator classes
        mock_registry = Mock()
        mock_registry_instance = Mock()
        mock_registry_instance.register_validator.side_effect = Exception(
            "Registration failed"
        )
        mock_registry.return_value = mock_registry_instance

        # Patch both the source module and the target module where imports are used
        with patch.multiple(
            "acme_srv.challenge_validators", ChallengeValidatorRegistry=mock_registry
        ), patch.multiple(
            "acme_srv.challenge_registry_setup",
            ChallengeValidatorRegistry=mock_registry,
        ):

            from acme_srv.challenge_registry_setup import create_custom_registry

            mock_validator_class = Mock()
            mock_validator = Mock()
            mock_validator_class.return_value = mock_validator

            validator_classes = [mock_validator_class]

            with self.assertRaises(Exception) as context:
                create_custom_registry(self.logger, validator_classes)

            self.assertEqual(str(context.exception), "Registration failed")

    @patch.dict(
        "sys.modules",
        {
            "OpenSSL": Mock(),
            "OpenSSL.crypto": Mock(),
            "acme_srv.helper": Mock(),
            "acme_srv.helpers.certificates": Mock(),
            "acme_srv.challenge_validators": Mock(),
        },
    )
    def test_011_create_challenge_validator_registry_tnauthlist_support(self):
        """Test registry creation with tnauthlist support enabled"""

        # Mock the module's imports
        mock_registry = Mock()
        mock_registry_instance = Mock()
        mock_registry_instance.get_supported_types.return_value = [
            "http-01",
            "dns-01",
            "tls-alpn-01",
            "tkauth-01",
        ]
        mock_registry.return_value = mock_registry_instance

        mock_http_validator = Mock()
        mock_dns_validator = Mock()
        mock_tls_validator = Mock()
        mock_email_validator = Mock()
        mock_tkauth_validator = Mock()
        mock_source_validator = Mock()

        mock_tkauth_instance = Mock()
        mock_tkauth_validator.return_value = mock_tkauth_instance

        # Patch both the source module and the target module where imports are used
        with patch.multiple(
            "acme_srv.challenge_validators",
            ChallengeValidatorRegistry=mock_registry,
            HttpChallengeValidator=mock_http_validator,
            DnsChallengeValidator=mock_dns_validator,
            TlsAlpnChallengeValidator=mock_tls_validator,
            EmailReplyChallengeValidator=mock_email_validator,
            TkauthChallengeValidator=mock_tkauth_validator,
            SourceAddressValidator=mock_source_validator,
        ), patch.multiple(
            "acme_srv.challenge_registry_setup",
            ChallengeValidatorRegistry=mock_registry,
            HttpChallengeValidator=mock_http_validator,
            DnsChallengeValidator=mock_dns_validator,
            TlsAlpnChallengeValidator=mock_tls_validator,
            EmailReplyChallengeValidator=mock_email_validator,
            TkauthChallengeValidator=mock_tkauth_validator,
            SourceAddressValidator=mock_source_validator,
        ):

            from acme_srv.challenge_registry_setup import (
                create_challenge_validator_registry,
            )

            # Test with tnauthlist support enabled
            config = MockConfig(tnauthlist_support=True)

            create_challenge_validator_registry(self.logger, config)

            # Verify tkauth validator registered
            mock_tkauth_validator.assert_called_once_with(self.logger)
            mock_registry_instance.register_validator.assert_any_call(
                mock_tkauth_instance
            )

            # Verify email and source validators NOT called
            mock_email_validator.assert_not_called()
            mock_source_validator.assert_called_once()
            mock_http_validator.assert_called_once()
            mock_dns_validator.assert_called_once()
            mock_tls_validator.assert_called_once()

    @patch.dict(
        "sys.modules",
        {
            "OpenSSL": Mock(),
            "OpenSSL.crypto": Mock(),
            "acme_srv.helper": Mock(),
            "acme_srv.helpers.certificates": Mock(),
            "acme_srv.challenge_validators": Mock(),
        },
    )
    def test_012_create_challenge_validator_registry_forward_address_check(self):
        """Test registry creation with forward address checking enabled"""

        # Mock the module's imports
        mock_registry = Mock()
        mock_registry_instance = Mock()
        mock_registry_instance.get_supported_types.return_value = [
            "http-01",
            "dns-01",
            "tls-alpn-01",
            "source-address",
        ]
        mock_registry.return_value = mock_registry_instance

        mock_http_validator = Mock()
        mock_dns_validator = Mock()
        mock_tls_validator = Mock()
        mock_email_validator = Mock()
        mock_tkauth_validator = Mock()
        mock_source_validator = Mock()

        mock_source_instance = Mock()
        mock_source_validator.return_value = mock_source_instance

        # Patch both the source module and the target module where imports are used
        with patch.multiple(
            "acme_srv.challenge_validators",
            ChallengeValidatorRegistry=mock_registry,
            HttpChallengeValidator=mock_http_validator,
            DnsChallengeValidator=mock_dns_validator,
            TlsAlpnChallengeValidator=mock_tls_validator,
            EmailReplyChallengeValidator=mock_email_validator,
            TkauthChallengeValidator=mock_tkauth_validator,
            SourceAddressValidator=mock_source_validator,
        ), patch.multiple(
            "acme_srv.challenge_registry_setup",
            ChallengeValidatorRegistry=mock_registry,
            HttpChallengeValidator=mock_http_validator,
            DnsChallengeValidator=mock_dns_validator,
            TlsAlpnChallengeValidator=mock_tls_validator,
            EmailReplyChallengeValidator=mock_email_validator,
            TkauthChallengeValidator=mock_tkauth_validator,
            SourceAddressValidator=mock_source_validator,
        ):

            from acme_srv.challenge_registry_setup import (
                create_challenge_validator_registry,
            )

            # Test with forward address check enabled
            config = MockConfig(forward_address_check=True)

            create_challenge_validator_registry(self.logger, config)

            # Verify source address validator registered with correct parameters
            mock_source_validator.assert_called_once_with(
                self.logger, forward_check=True, reverse_check=False
            )
            mock_registry_instance.register_validator.assert_any_call(
                mock_source_instance
            )

            # Verify email and tkauth validators NOT called
            mock_email_validator.assert_not_called()
            mock_tkauth_validator.assert_not_called()

    @patch.dict(
        "sys.modules",
        {
            "OpenSSL": Mock(),
            "OpenSSL.crypto": Mock(),
            "acme_srv.helper": Mock(),
            "acme_srv.helpers.certificates": Mock(),
            "acme_srv.challenge_validators": Mock(),
        },
    )
    def test_013_create_challenge_validator_registry_reverse_address_check(self):
        """Test registry creation with reverse address checking enabled"""

        # Mock the module's imports
        mock_registry = Mock()
        mock_registry_instance = Mock()
        mock_registry_instance.get_supported_types.return_value = [
            "http-01",
            "dns-01",
            "tls-alpn-01",
            "source-address",
        ]
        mock_registry.return_value = mock_registry_instance

        mock_http_validator = Mock()
        mock_dns_validator = Mock()
        mock_tls_validator = Mock()
        mock_email_validator = Mock()
        mock_tkauth_validator = Mock()
        mock_source_validator = Mock()

        mock_source_instance = Mock()
        mock_source_validator.return_value = mock_source_instance

        # Patch both the source module and the target module where imports are used
        with patch.multiple(
            "acme_srv.challenge_validators",
            ChallengeValidatorRegistry=mock_registry,
            HttpChallengeValidator=mock_http_validator,
            DnsChallengeValidator=mock_dns_validator,
            TlsAlpnChallengeValidator=mock_tls_validator,
            EmailReplyChallengeValidator=mock_email_validator,
            TkauthChallengeValidator=mock_tkauth_validator,
            SourceAddressValidator=mock_source_validator,
        ), patch.multiple(
            "acme_srv.challenge_registry_setup",
            ChallengeValidatorRegistry=mock_registry,
            HttpChallengeValidator=mock_http_validator,
            DnsChallengeValidator=mock_dns_validator,
            TlsAlpnChallengeValidator=mock_tls_validator,
            EmailReplyChallengeValidator=mock_email_validator,
            TkauthChallengeValidator=mock_tkauth_validator,
            SourceAddressValidator=mock_source_validator,
        ):

            from acme_srv.challenge_registry_setup import (
                create_challenge_validator_registry,
            )

            # Test with reverse address check enabled
            config = MockConfig(reverse_address_check=True)

            create_challenge_validator_registry(self.logger, config)

            # Verify source address validator registered with correct parameters
            mock_source_validator.assert_called_once_with(
                self.logger, forward_check=False, reverse_check=True
            )
            mock_registry_instance.register_validator.assert_any_call(
                mock_source_instance
            )

    @patch.dict(
        "sys.modules",
        {
            "OpenSSL": Mock(),
            "OpenSSL.crypto": Mock(),
            "acme_srv.helper": Mock(),
            "acme_srv.helpers.certificates": Mock(),
            "acme_srv.challenge_validators": Mock(),
        },
    )
    def test_014_create_challenge_validator_registry_both_address_checks(self):
        """Test registry creation with both forward and reverse address checking enabled"""

        # Mock the module's imports
        mock_registry = Mock()
        mock_registry_instance = Mock()
        mock_registry_instance.get_supported_types.return_value = [
            "http-01",
            "dns-01",
            "tls-alpn-01",
            "source-address",
        ]
        mock_registry.return_value = mock_registry_instance

        mock_http_validator = Mock()
        mock_dns_validator = Mock()
        mock_tls_validator = Mock()
        mock_email_validator = Mock()
        mock_tkauth_validator = Mock()
        mock_source_validator = Mock()

        mock_source_instance = Mock()
        mock_source_validator.return_value = mock_source_instance

        # Patch both the source module and the target module where imports are used
        with patch.multiple(
            "acme_srv.challenge_validators",
            ChallengeValidatorRegistry=mock_registry,
            HttpChallengeValidator=mock_http_validator,
            DnsChallengeValidator=mock_dns_validator,
            TlsAlpnChallengeValidator=mock_tls_validator,
            EmailReplyChallengeValidator=mock_email_validator,
            TkauthChallengeValidator=mock_tkauth_validator,
            SourceAddressValidator=mock_source_validator,
        ), patch.multiple(
            "acme_srv.challenge_registry_setup",
            ChallengeValidatorRegistry=mock_registry,
            HttpChallengeValidator=mock_http_validator,
            DnsChallengeValidator=mock_dns_validator,
            TlsAlpnChallengeValidator=mock_tls_validator,
            EmailReplyChallengeValidator=mock_email_validator,
            TkauthChallengeValidator=mock_tkauth_validator,
            SourceAddressValidator=mock_source_validator,
        ):

            from acme_srv.challenge_registry_setup import (
                create_challenge_validator_registry,
            )

            # Test with both address checks enabled
            config = MockConfig(forward_address_check=True, reverse_address_check=True)

            create_challenge_validator_registry(self.logger, config)

            # Verify source address validator registered with both checks
            mock_source_validator.assert_called_once_with(
                self.logger, forward_check=True, reverse_check=True
            )

    @patch.dict(
        "sys.modules",
        {
            "OpenSSL": Mock(),
            "OpenSSL.crypto": Mock(),
            "acme_srv.helper": Mock(),
            "acme_srv.helpers.certificates": Mock(),
            "acme_srv.challenge_validators": Mock(),
        },
    )
    def test_015_create_custom_registry_with_config(self):
        """Test custom registry creation with config parameter"""

        # Mock all the validator classes
        mock_registry = Mock()
        mock_registry_instance = Mock()
        mock_registry_instance.get_supported_types.return_value = ["mock-01"]
        mock_registry.return_value = mock_registry_instance

        # Patch both the source module and the target module where imports are used
        with patch.multiple(
            "acme_srv.challenge_validators", ChallengeValidatorRegistry=mock_registry
        ), patch.multiple(
            "acme_srv.challenge_registry_setup",
            ChallengeValidatorRegistry=mock_registry,
        ):

            from acme_srv.challenge_registry_setup import create_custom_registry

            mock_validator_class = Mock()
            mock_validator = Mock()
            mock_validator_class.return_value = mock_validator

            validator_classes = [mock_validator_class]
            config = {"test": "value"}

            create_custom_registry(self.logger, validator_classes, config)

            # Verify registry creation (config not used in current implementation)
            mock_registry.assert_called_once_with(self.logger)
            mock_validator_class.assert_called_once_with(self.logger)
            mock_registry_instance.register_validator.assert_called_once_with(
                mock_validator
            )

    @patch.dict(
        "sys.modules",
        {
            "OpenSSL": Mock(),
            "OpenSSL.crypto": Mock(),
            "acme_srv.helper": Mock(),
            "acme_srv.helpers.certificates": Mock(),
            "acme_srv.challenge_validators": Mock(),
        },
    )
    def test_016_create_custom_registry_get_supported_types_exception(self):
        """Test custom registry creation when get_supported_types raises exception"""

        # Mock all the validator classes
        mock_registry = Mock()
        mock_registry_instance = Mock()
        mock_registry_instance.get_supported_types.side_effect = Exception(
            "Get types failed"
        )
        mock_registry.return_value = mock_registry_instance

        # Patch both the source module and the target module where imports are used
        with patch.multiple(
            "acme_srv.challenge_validators", ChallengeValidatorRegistry=mock_registry
        ), patch.multiple(
            "acme_srv.challenge_registry_setup",
            ChallengeValidatorRegistry=mock_registry,
        ):

            from acme_srv.challenge_registry_setup import create_custom_registry

            mock_validator_class = Mock()
            mock_validator = Mock()
            mock_validator_class.return_value = mock_validator

            validator_classes = [mock_validator_class]

            with self.assertRaises(Exception) as context:
                create_custom_registry(self.logger, validator_classes)

            self.assertEqual(str(context.exception), "Get types failed")

    @patch.dict(
        "sys.modules",
        {
            "OpenSSL": Mock(),
            "OpenSSL.crypto": Mock(),
            "acme_srv.helper": Mock(),
            "acme_srv.helpers.certificates": Mock(),
            "acme_srv.challenge_validators": Mock(),
        },
    )
    def test_017_create_custom_registry_mixed_validator_types(self):
        """Test custom registry creation with different validator types"""

        # Mock all the validator classes
        mock_registry = Mock()
        mock_registry_instance = Mock()
        mock_registry_instance.get_supported_types.return_value = [
            "http-01",
            "custom-01",
            "test-01",
        ]
        mock_registry.return_value = mock_registry_instance

        # Patch both the source module and the target module where imports are used
        with patch.multiple(
            "acme_srv.challenge_validators", ChallengeValidatorRegistry=mock_registry
        ), patch.multiple(
            "acme_srv.challenge_registry_setup",
            ChallengeValidatorRegistry=mock_registry,
        ):

            from acme_srv.challenge_registry_setup import create_custom_registry

            # Create different types of mock validator classes
            class MockHttpValidator:
                def __init__(self, logger):
                    self.logger = logger

            class MockCustomValidator:
                def __init__(self, logger):
                    self.logger = logger

            mock_test_validator_class = Mock()
            mock_test_validator = Mock()
            mock_test_validator_class.return_value = mock_test_validator

            validator_classes = [
                MockHttpValidator,
                MockCustomValidator,
                mock_test_validator_class,
            ]

            result = create_custom_registry(self.logger, validator_classes)

            # Verify registry creation
            self.assertEqual(result, mock_registry_instance)

            # Verify all validator types were handled
            self.assertEqual(mock_registry_instance.register_validator.call_count, 3)

    @patch.dict(
        "sys.modules",
        {
            "OpenSSL": Mock(),
            "OpenSSL.crypto": Mock(),
            "acme_srv.helper": Mock(),
            "acme_srv.helpers.certificates": Mock(),
            "acme_srv.challenge_validators": Mock(),
        },
    )
    def test_018_create_challenge_validator_registry_validator_exception(self):
        """Test registry creation when validator constructor raises exception"""

        # Mock all the validator classes
        mock_registry = Mock()
        mock_registry_instance = Mock()
        mock_registry.return_value = mock_registry_instance

        mock_http_validator = Mock()
        mock_http_validator.side_effect = Exception("Validator creation failed")
        mock_dns_validator = Mock()
        mock_tls_validator = Mock()
        mock_email_validator = Mock()
        mock_tkauth_validator = Mock()
        mock_source_validator = Mock()

        # Patch both the source module and the target module where imports are used
        with patch.multiple(
            "acme_srv.challenge_validators",
            ChallengeValidatorRegistry=mock_registry,
            HttpChallengeValidator=mock_http_validator,
            DnsChallengeValidator=mock_dns_validator,
            TlsAlpnChallengeValidator=mock_tls_validator,
            EmailReplyChallengeValidator=mock_email_validator,
            TkauthChallengeValidator=mock_tkauth_validator,
            SourceAddressValidator=mock_source_validator,
        ), patch.multiple(
            "acme_srv.challenge_registry_setup",
            ChallengeValidatorRegistry=mock_registry,
            HttpChallengeValidator=mock_http_validator,
            DnsChallengeValidator=mock_dns_validator,
            TlsAlpnChallengeValidator=mock_tls_validator,
            EmailReplyChallengeValidator=mock_email_validator,
            TkauthChallengeValidator=mock_tkauth_validator,
            SourceAddressValidator=mock_source_validator,
        ):

            from acme_srv.challenge_registry_setup import (
                create_challenge_validator_registry,
            )

            config = MockConfig()

            with self.assertRaises(Exception) as context:
                create_challenge_validator_registry(self.logger, config)

            self.assertEqual(str(context.exception), "Validator creation failed")

    @patch.dict(
        "sys.modules",
        {
            "OpenSSL": Mock(),
            "OpenSSL.crypto": Mock(),
            "acme_srv.helper": Mock(),
            "acme_srv.helpers.certificates": Mock(),
            "acme_srv.challenge_validators": Mock(),
        },
    )
    def test_019_create_challenge_validator_registry_missing_config_attributes(self):
        """Test registry creation with config missing some attributes"""

        # Mock all the validator classes
        mock_registry = Mock()
        mock_registry_instance = Mock()
        mock_registry.return_value = mock_registry_instance

        mock_http_validator = Mock()
        mock_dns_validator = Mock()
        mock_tls_validator = Mock()
        mock_email_validator = Mock()
        mock_tkauth_validator = Mock()
        mock_source_validator = Mock()

        # Patch both the source module and the target module where imports are used
        with patch.multiple(
            "acme_srv.challenge_validators",
            ChallengeValidatorRegistry=mock_registry,
            HttpChallengeValidator=mock_http_validator,
            DnsChallengeValidator=mock_dns_validator,
            TlsAlpnChallengeValidator=mock_tls_validator,
            EmailReplyChallengeValidator=mock_email_validator,
            TkauthChallengeValidator=mock_tkauth_validator,
            SourceAddressValidator=mock_source_validator,
        ), patch.multiple(
            "acme_srv.challenge_registry_setup",
            ChallengeValidatorRegistry=mock_registry,
            HttpChallengeValidator=mock_http_validator,
            DnsChallengeValidator=mock_dns_validator,
            TlsAlpnChallengeValidator=mock_tls_validator,
            EmailReplyChallengeValidator=mock_email_validator,
            TkauthChallengeValidator=mock_tkauth_validator,
            SourceAddressValidator=mock_source_validator,
        ):

            from acme_srv.challenge_registry_setup import (
                create_challenge_validator_registry,
            )

            # Create config with missing attributes
            class PartialConfig:
                email_identifier_support = False
                # Missing tnauthlist_support, forward_address_check, reverse_address_check

            config = PartialConfig()

            # Should raise AttributeError when accessing missing attributes
            with self.assertRaises(AttributeError):
                create_challenge_validator_registry(self.logger, config)

    @patch.dict(
        "sys.modules",
        {
            "OpenSSL": Mock(),
            "OpenSSL.crypto": Mock(),
            "acme_srv.helper": Mock(),
            "acme_srv.helpers.certificates": Mock(),
            "acme_srv.challenge_validators": Mock(),
        },
    )
    def test_020_create_challenge_validator_registry_registration_exception(self):
        """Test registry creation when validator registration raises exception"""

        # Mock all the validator classes
        mock_registry = Mock()
        mock_registry_instance = Mock()
        mock_registry_instance.register_validator.side_effect = Exception(
            "Registration failed"
        )
        mock_registry.return_value = mock_registry_instance

        mock_http_validator = Mock()
        mock_dns_validator = Mock()
        mock_tls_validator = Mock()
        mock_email_validator = Mock()
        mock_tkauth_validator = Mock()
        mock_source_validator = Mock()

        mock_http_instance = Mock()
        mock_http_validator.return_value = mock_http_instance

        # Patch both the source module and the target module where imports are used
        with patch.multiple(
            "acme_srv.challenge_validators",
            ChallengeValidatorRegistry=mock_registry,
            HttpChallengeValidator=mock_http_validator,
            DnsChallengeValidator=mock_dns_validator,
            TlsAlpnChallengeValidator=mock_tls_validator,
            EmailReplyChallengeValidator=mock_email_validator,
            TkauthChallengeValidator=mock_tkauth_validator,
            SourceAddressValidator=mock_source_validator,
        ), patch.multiple(
            "acme_srv.challenge_registry_setup",
            ChallengeValidatorRegistry=mock_registry,
            HttpChallengeValidator=mock_http_validator,
            DnsChallengeValidator=mock_dns_validator,
            TlsAlpnChallengeValidator=mock_tls_validator,
            EmailReplyChallengeValidator=mock_email_validator,
            TkauthChallengeValidator=mock_tkauth_validator,
            SourceAddressValidator=mock_source_validator,
        ):

            from acme_srv.challenge_registry_setup import (
                create_challenge_validator_registry,
            )

            config = MockConfig()

            with self.assertRaises(Exception) as context:
                create_challenge_validator_registry(self.logger, config)

            self.assertEqual(str(context.exception), "Registration failed")


if __name__ == "__main__":
    unittest.main()
