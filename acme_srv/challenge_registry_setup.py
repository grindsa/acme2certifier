"""
Registry setup utilities for creating and configuring challenge validator registries.

This module provides factory functions for creating pre-configured challenge
validator registries with all standard ACME challenge types.
"""
from typing import Dict, Any, Optional
import logging
from .challenge_validators import (
    ChallengeValidatorRegistry,
    HttpChallengeValidator,
    DnsChallengeValidator,
    TlsAlpnChallengeValidator,
    EmailReplyChallengeValidator,
    TkauthChallengeValidator,
    SourceAddressValidator,
)


def create_challenge_validator_registry(
    logger: logging.Logger, config: Optional[Dict[str, Any]] = None
) -> ChallengeValidatorRegistry:
    """Create a fully configured challenge validator registry with all standard validators"""

    logger.debug("challenge_registry_setup.create_challenge_validator_registry()")
    registry = ChallengeValidatorRegistry(logger)

    # Register standard ACME challenge validators
    registry.register_validator(HttpChallengeValidator(logger))
    registry.register_validator(DnsChallengeValidator(logger))
    registry.register_validator(TlsAlpnChallengeValidator(logger))

    if config.email_identifier_support:
        # Register Email-Reply challenge validator if configured
        registry.register_validator(EmailReplyChallengeValidator(logger))
    if config.tnauthlist_support:
        # Register Tkauth challenge validator if configured
        registry.register_validator(TkauthChallengeValidator(logger))

    # Register Source Address validator if address checking is enabled
    # if config.forward_address_check or config.reverse_address_check:
    registry.register_validator(
        SourceAddressValidator(
            logger,
            forward_check=config.forward_address_check,
            reverse_check=config.reverse_address_check,
        )
    )

    logger.debug(
        "create_challenge_validator_registry(): Registry created with %d validators: %s",
        len(registry.get_supported_types()),
        ", ".join(registry.get_supported_types()),
    )

    logger.debug("challenge_registry_setup.create_challenge_validator_registry() ended")
    return registry


def create_custom_registry(
    logger: logging.Logger,
    validator_classes: list,
    config: Optional[Dict[str, Any]] = None,
) -> ChallengeValidatorRegistry:
    """
    Create a custom challenge validator registry with specified validators.

    Args:
        logger: Logger instance for validation operations
        validator_classes: List of validator classes to register
        config: Optional configuration dictionary for validator setup

    Returns:
        ChallengeValidatorRegistry: Configured registry with specified validators
    """
    registry = ChallengeValidatorRegistry(logger)

    for validator_class in validator_classes:
        validator = validator_class(logger)
        registry.register_validator(validator)

    logger.info(
        "Custom challenge validator registry created with %d validators",
        len(registry.get_supported_types()),
    )

    return registry
