"""
Example Usage of Refactored Challenge System
"""

# Example 1: Basic challenge processing (maintains backward compatibility)
def example_legacy_usage():
    """Example showing backward compatibility with existing code"""
    from refactored_challenge_manager import Challenge

    # Existing code works unchanged
    with Challenge(debug=True, srv_name="acme.example.com", logger=logger) as challenge:
        # Get challenge information
        response = challenge.get("https://acme.example.com/acme/chall/abc123")

        # Process challenge validation request
        request_content = '{"protected": "...", "payload": "...", "signature": "..."}'
        result = challenge.parse(request_content)

        # Create challenge set for authorization
        challenges = challenge.challengeset_get(
            authz_name="auth_123",
            auth_status="pending",
            token="token_456",
            tnauth=False,
            id_type="dns",
            id_value="example.com"
        )


# Example 2: Using new architecture directly
def example_new_architecture():
    """Example showing how to use the new architecture components"""
    from refactored_challenge_manager import ChallengeWorkflowManager
    from refactored_challenge_processors import ChallengeProcessorFactory
    from refactored_challenge_models import ValidationContext, ChallengeData, ChallengeType, IdentifierType

    # Initialize the workflow manager
    manager = ChallengeWorkflowManager(
        debug=True,
        srv_name="acme.example.com",
        logger=logger,
        source="192.168.1.100"
    )

    # Process a challenge request
    response = manager.process_challenge_request(request_content)

    # Create challenges for an authorization
    challenges = manager.create_challenge_set(
        authorization_name="auth_123",
        token="token_456",
        identifier_type="dns",
        identifier_value="example.com"
    )


# Example 3: Adding a custom challenge processor
def example_custom_processor():
    """Example showing how to add a new challenge type"""
    from refactored_challenge_processors import ChallengeProcessor, ChallengeProcessorFactory
    from refactored_challenge_models import ValidationContext, ValidationResult

    class CustomChallengeProcessor(ChallengeProcessor):
        """Custom challenge processor for a hypothetical new challenge type"""

        def get_supported_type(self) -> str:
            return "custom-01"

        def process(self, context: ValidationContext) -> ValidationResult:
            """Process custom challenge validation"""
            self._log_validation_start(context)

            try:
                # Implement custom validation logic
                success = self._perform_custom_validation(context)
                result = ValidationResult(success=success, invalid=not success)

            except Exception as e:
                self.logger.error(f"Custom challenge validation error: {e}")
                result = ValidationResult(success=False, invalid=True, error_message=str(e))

            self._log_validation_end(context, result)
            return result

        def _perform_custom_validation(self, context: ValidationContext) -> bool:
            """Implement your custom validation logic here"""
            # Example: Check if a specific file exists on the server
            import requests
            try:
                url = f"https://{context.challenge_data.identifier.value}/.well-known/custom-challenge"
                response = requests.get(url, timeout=context.timeout)
                return response.status_code == 200 and context.challenge_data.token in response.text
            except:
                return False

    # Register the new processor
    factory = ChallengeProcessorFactory(logger, config)
    factory.register_processor("custom-01", CustomChallengeProcessor)

    # Now the factory can create processors for "custom-01" challenges


# Example 4: Error handling with structured exceptions
def example_error_handling():
    """Example showing improved error handling"""
    from refactored_challenge_manager import ChallengeWorkflowManager
    from refactored_challenge_models import (
        ChallengeNotFoundError, ChallengeValidationError,
        ChallengeDatabaseError, ChallengeNetworkError
    )

    manager = ChallengeWorkflowManager(logger=logger)

    try:
        response = manager.get_challenge_info(url)

    except ChallengeNotFoundError as e:
        logger.error(f"Challenge not found: {e}")
        # Handle missing challenge

    except ChallengeValidationError as e:
        logger.error(f"Validation failed: {e}")
        # Handle validation failure

    except ChallengeDatabaseError as e:
        logger.error(f"Database error: {e}")
        # Handle database issues

    except ChallengeNetworkError as e:
        logger.error(f"Network error: {e}")
        # Handle network problems


# Example 5: Configuration customization
def example_configuration():
    """Example showing configuration options"""
    from refactored_challenge_repository import ConfigurationManager
    from refactored_challenge_models import ChallengeConfiguration

    # Load default configuration
    config_manager = ConfigurationManager(logger)
    config = config_manager.load_configuration()

    # Customize configuration
    config.validation_timeout = 30  # Increase timeout
    config.dns_validation_pause_timer = 1.0  # Longer pause between retries
    config.forward_address_check = True  # Enable address validation

    # Use custom configuration
    manager = ChallengeWorkflowManager(logger=logger)
    manager.config = config


# Example 6: Testing individual components
def example_unit_testing():
    """Example showing how to test individual components"""
    import unittest
    from unittest.mock import Mock, patch
    from refactored_challenge_processors import HttpChallengeProcessor
    from refactored_challenge_models import ValidationContext, ChallengeData, ChallengeType, IdentifierType

    class TestHttpChallengeProcessor(unittest.TestCase):

        def setUp(self):
            self.logger = Mock()
            self.config = Mock()
            self.processor = HttpChallengeProcessor(self.logger, self.config)

        def test_http_challenge_success(self):
            """Test successful HTTP challenge validation"""
            # Create test data
            challenge_data = ChallengeData(
                name="test_challenge",
                type=ChallengeType.HTTP_01,
                token="test_token",
                jwk_thumbprint="test_thumbprint",
                identifier=Mock(type=IdentifierType.DNS, value="example.com")
            )

            context = ValidationContext(challenge_data=challenge_data, payload={})

            # Mock HTTP response
            with patch('refactored_challenge_processors.url_get') as mock_url_get:
                mock_url_get.return_value = "test_token.test_thumbprint"

                result = self.processor.process(context)

                self.assertTrue(result.success)
                self.assertFalse(result.invalid)

        def test_http_challenge_failure(self):
            """Test failed HTTP challenge validation"""
            challenge_data = ChallengeData(
                name="test_challenge",
                type=ChallengeType.HTTP_01,
                token="test_token",
                jwk_thumbprint="test_thumbprint",
                identifier=Mock(type=IdentifierType.DNS, value="example.com")
            )

            context = ValidationContext(challenge_data=challenge_data, payload={})

            # Mock failed HTTP response
            with patch('refactored_challenge_processors.url_get') as mock_url_get:
                mock_url_get.return_value = "wrong_response"

                result = self.processor.process(context)

                self.assertFalse(result.success)


if __name__ == "__main__":
    # Example logger setup
    import logging
    logging.basicConfig(level=logging.DEBUG)
    logger = logging.getLogger(__name__)

    # Run examples
    print("Running challenge system examples...")

    # These would need actual implementation context to run
    # example_legacy_usage()
    # example_new_architecture()
    # example_custom_processor()
    # example_error_handling()
    # example_configuration()

    print("Examples completed successfully!")