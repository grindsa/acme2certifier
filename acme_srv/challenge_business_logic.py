"""
Separation of challenge validation logic and database/state management
operations for challenge processing.

"""
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass
import logging
import json
from abc import ABC, abstractmethod


@dataclass
class ChallengeInfo:
    """Information about a challenge."""

    name: str
    type: str
    token: str
    status: str
    authorization_name: str
    authorization_type: str
    authorization_value: str
    url: str
    validated: Optional[str] = None
    validation_error: Optional[str] = None


@dataclass
class ChallengeCreationRequest:
    """Request for creating a new challenge."""

    authorization_name: str
    challenge_type: str
    token: str
    value: Optional[str] = None
    expiry: int = 3600


@dataclass
class ChallengeUpdateRequest:
    """Request for updating a challenge."""

    name: str
    status: Optional[str] = None
    source: Optional[str] = None
    validated: Optional[int] = None
    keyauthorization: Optional[str] = None
    validation_error: Optional[str] = None


class ChallengeRepository(ABC):
    """Abstract repository for challenge data operations."""

    @abstractmethod
    def find_challenges_by_authorization(
        self, authorization_name: str
    ) -> List[ChallengeInfo]:
        """Find all challenges for a given authorization."""
        pass  # pragma: no cover

    @abstractmethod
    def get_challenge_by_name(self, name: str) -> Optional[ChallengeInfo]:
        """Get challenge information by name."""
        pass  # pragma: no cover

    @abstractmethod
    def get_challengeinfo_by_challengename(self, name: str) -> Optional[ChallengeInfo]:
        """Get challenge information by challenge name."""
        pass  # pragma: no cover

    @abstractmethod
    def create_challenge(self, request: ChallengeCreationRequest) -> Optional[str]:
        """Create a new challenge and return its name."""
        pass  # pragma: no cover

    @abstractmethod
    def update_challenge(self, request: ChallengeUpdateRequest) -> bool:
        """Update an existing challenge."""
        pass  # pragma: no cover

    @abstractmethod
    def update_authorization_status(self, challenge_name: str, status: str) -> bool:
        """Update authorization status based on challenge."""
        pass  # pragma: no cover

    @abstractmethod
    def get_account_jwk(self, challenge_name: str) -> Optional[Dict[str, Any]]:
        """Get JWK for the account associated with the challenge."""
        pass  # pragma: no cover


class ChallengeStateManager:
    """Manages challenge state transitions and business rules."""

    def __init__(self, repository: ChallengeRepository, logger: logging.Logger):
        self.repository = repository
        self.logger = logger

    def transition_to_processing(self, challenge_name: str) -> bool:
        """Transition challenge to processing state."""
        self.logger.debug(
            "ChallengeStateManager.transition_to_processing(%s)", challenge_name
        )

        update_request = ChallengeUpdateRequest(
            name=challenge_name, status="processing"
        )
        result = self.repository.update_challenge(update_request)
        self.logger.debug(
            "ChallengeStateManager.transition_to_processing() updated challenge %s to processing/%s",
            challenge_name,
            result,
        )
        return result

    def transition_to_valid(
        self,
        challenge_name: str,
        source_address: Optional[str] = None,
        validated_timestamp: Optional[int] = None,
    ) -> bool:
        """Transition challenge to valid state."""
        self.logger.debug(
            "ChallengeStateManager.transition_to_valid(%s)", challenge_name
        )

        update_request = ChallengeUpdateRequest(
            name=challenge_name,
            status="valid",
            source=source_address,
            validated=validated_timestamp,
        )

        success = self.repository.update_challenge(update_request)
        if success:
            success = self.repository.update_authorization_status(
                challenge_name, "valid"
            )

        self.logger.debug(
            "ChallengeStateManager.transition_to_valid() updated challenge %s to valid/%s",
            challenge_name,
            success,
        )
        return success

    def transition_to_invalid(
        self,
        challenge_name: str,
        source_address: Optional[str] = None,
        validation_error: Optional[str] = None,
    ) -> bool:
        """Transition challenge to invalid state."""
        self.logger.debug(
            "ChallengeStateManager.transition_to_invalid(%s)", challenge_name
        )

        update_request = ChallengeUpdateRequest(
            name=challenge_name,
            status="invalid",
            source=source_address,
            validation_error=validation_error,
        )

        success = self.repository.update_challenge(update_request)
        if success:
            success = self.repository.update_authorization_status(
                challenge_name, "invalid"
            )

        self.logger.debug(
            "ChallengeStateManager.transition_to_invalid() ended: updated challenge %s to invalid/%s",
            challenge_name,
            success,
        )
        return success

    def update_key_authorization(
        self, challenge_name: str, key_authorization: str
    ) -> bool:
        """Update challenge with key authorization."""
        self.logger.debug(
            "ChallengeStateManager.update_key_authorization(%s)", challenge_name
        )

        update_request = ChallengeUpdateRequest(
            name=challenge_name, keyauthorization=key_authorization
        )
        self.logger.debug(
            "ChallengeStateManager.update_key_authorization() ended: updating challenge %s with key authorization",
            challenge_name,
        )
        return self.repository.update_challenge(update_request)


class ChallengeFactory:
    """Factory for creating different types of challenges."""

    def __init__(
        self,
        repository: ChallengeRepository,
        logger: logging.Logger,
        server_name: str,
        challenge_path: str,
        email_address: Optional[str] = None,
    ):
        self.repository = repository
        self.logger = logger
        self.server_name = server_name
        self.challenge_path = challenge_path
        self.email_address = email_address

    def create_standard_challenge_set(
        self, authorization_name: str, token: str, id_type: str, value: str
    ) -> List[Dict[str, Any]]:
        """Create standard ACME challenge set (http-01, dns-01, tls-alpn-01)."""
        self.logger.debug(
            "ChallengeFactory.create_standard_challenge_set(%s)", authorization_name
        )

        challenge_types = ["http-01", "dns-01", "tls-alpn-01"]
        # Skip DNS challenge for IP identifiers
        if id_type == "ip":
            self.logger.debug(
                "ChallengeFactory.create_standard_challenge_set(): Skipping dns-01 challenge for IP identifier"
            )
            challenge_types.remove("dns-01")

        challenges = []
        for challenge_type in challenge_types:
            challenge_dict = self._create_single_challenge(
                authorization_name, challenge_type, token, value
            )
            if challenge_dict:
                challenges.append(challenge_dict)
        self.logger.debug(
            "ChallengeFactory.create_standard_challenge_set() ended: Created %d challenges",
            len(challenges),
        )
        return challenges

    def create_email_reply_challenge(
        self,
        authorization_name: str,
        token: str,
        email_address: str,
        sender_address: str,
    ) -> Optional[Dict[str, Any]]:
        """Create email-reply-00 challenge."""
        self.logger.debug(
            "ChallengeFactory.create_email_reply_challenge(%s)", email_address
        )
        if sender_address:
            self.email_address = sender_address

        result = self._create_single_challenge(
            authorization_name, "email-reply-00", token, email_address
        )
        self.logger.debug(
            "ChallengeFactory.create_email_reply_challenge() ended: %s", result
        )
        return result

    def create_tkauth_challenge(
        self, authorization_name: str, token: str
    ) -> Optional[Dict[str, Any]]:
        """Create tkauth-01 challenge."""
        self.logger.debug(
            "ChallengeFactory.create_tkauth_challenge(%s)", authorization_name
        )

        result = self._create_single_challenge(authorization_name, "tkauth-01", token)
        self.logger.debug(
            "ChallengeFactory.create_tkauth_challenge() ended: %s", result
        )
        return result

    def _create_single_challenge(
        self,
        authorization_name: str,
        challenge_type: str,
        token: str,
        value: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Create a single challenge of the specified type."""
        self.logger.debug(
            "ChallengeFactory._create_single_challenge(): Creating %s challenge for authorization: %s",
            challenge_type,
            authorization_name,
        )
        request = ChallengeCreationRequest(
            authorization_name=authorization_name,
            challenge_type=challenge_type,
            token=token,
            value=value,
        )
        challenge_name = self.repository.create_challenge(request)
        if not challenge_name:
            self.logger.error("Failed to create %s challenge", challenge_type)
            return None

        challenge_dict = {
            "type": challenge_type,
            "url": f"{self.server_name}{self.challenge_path}{challenge_name}",
            "token": token,
            "status": "pending",
        }

        # Add type-specific properties
        if challenge_type == "email-reply-00" and self.email_address:
            challenge_dict["from"] = self.email_address
            result = self.repository.get_challengeinfo_by_challengename(
                challenge_name,
                vlist=("name", "keyauthorization", "authorization__value"),
            )
            if (
                result
                and "keyauthorization" in result
                and "authorization__value" in result
            ):
                print("jupp", result)
                # send challange email
                from acme_srv.email_handler import EmailHandler

                with EmailHandler(logger=self.logger) as email_handler:
                    email_handler.send_email_challenge(
                        to_address=result["authorization__value"],
                        token1=result["keyauthorization"],
                    )

        elif challenge_type == "tkauth-01":
            challenge_dict["tkauth-type"] = "atc"
        elif challenge_type == "sectigo-email-01":
            challenge_dict["status"] = "valid"
            challenge_dict.pop("token", None)

        self.logger.debug(
            "ChallengeFactory._create_single_challenge() ended: created challenge %s/%s",
            challenge_type,
            challenge_name,
        )
        return challenge_dict


class ChallengeService:
    """High-level service for challenge operations."""

    def __init__(
        self,
        repository: ChallengeRepository,
        state_manager: ChallengeStateManager,
        factory: ChallengeFactory,
        logger: logging.Logger,
    ):
        self.repository = repository
        self.state_manager = state_manager
        self.factory = factory
        self.logger = logger

    def get_challenge_set_for_authorization(
        self,
        authorization_name: str,
        token: str,
        id_type: str,
        id_value: str,
        config: Dict[str, Any],
        url: str = "",
    ) -> List[Dict[str, Any]]:
        """Get challenge set for an authorization."""
        self.logger.debug(
            "ChallengeService.get_challenge_set_for_authorization(%s)",
            authorization_name,
        )

        # Check for existing challenges
        existing_challenges = self.repository.find_challenges_by_authorization(
            authorization_name
        )

        if existing_challenges:
            self.logger.debug(
                "ChallengeService.get_challenge_set_for_authorization(): Found existing challenges"
            )
            return self._format_existing_challenges(
                challenges=existing_challenges, url=url, config=config
            )

        # Create new challenge set
        self.logger.debug(
            "ChallengeService.get_challenge_set_for_authorization(%s): Creating new challenge set",
            authorization_name,
        )

        return self._create_new_challenge_set(
            authorization_name,
            token,
            id_type,
            id_value,
            config,
        )

    def _format_existing_challenges(
        self,
        challenges: List[ChallengeInfo],
        url: str = "",
        config: Dict[str, Any] = {},
    ) -> List[Dict[str, Any]]:
        """Format existing challenges for response."""
        self.logger.debug(
            "ChallengeService._format_existing_challenges(%s)", len(challenges)
        )
        challenge_list = []
        for challenge in challenges:
            challenge_dict = {
                "type": challenge.type,
                "url": f"{url}{challenge.name}",
                "token": challenge.token,
                "status": challenge.status,
            }

            if challenge.validation_error:
                # add error message if present
                try:
                    challenge_dict["error"] = json.loads(challenge.validation_error)
                except Exception:
                    challenge_dict["error"] = {
                        "status": 400,
                        "type": "urn:ietf:params:acme:error:unknown",
                        "detail": challenge.validation_error,
                    }

            if challenge.type == "email-reply-00" and config.email_address:
                challenge_dict["from"] = config.email_address

            challenge_list.append(challenge_dict)

        self.logger.debug(
            "ChallengeService._format_existing_challenges() ended with %s challenges",
            len(challenge_list),
        )
        return challenge_list

    def _create_new_challenge_set(
        self,
        authorization_name: str,
        token: str,
        id_type: str,
        id_value: str,
        config: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        """Create a new challenge set based on configuration."""
        self.logger.debug(
            "ChallengeService._create_new_challenge_set(%s)", authorization_name
        )

        challenge_list = []

        if config.email_identifier_support and config.email_address and "@" in id_value:
            # in case of an email identifier we return only one challenge
            self.logger.debug(
                "ChallengeService._create_new_challenge_set(): Creating email-reply-00 challenge for email identifier"
            )
            challenge = self.factory.create_email_reply_challenge(
                authorization_name, token, id_value, config.email_address
            )
            return [challenge] if challenge else []

        if config.tnauthlist_support and id_type.lower() == "tnauthlist":
            # in case of an tnauthlist identifier we return only one challenge
            self.logger.debug(
                "ChallengeService._create_new_challenge_set(): Creating tkauth-01 challenge for tnauthlist identifier"
            )
            challenge = self.factory.create_tkauth_challenge(authorization_name, token)
            return [challenge] if challenge else []

        if config.sectigo_sim:
            challenge = self.factory._create_single_challenge(
                authorization_name, "sectigo-email-01", token
            )
            challenge_list.append(challenge) if challenge else None

        challenge_list.extend(
            self.factory.create_standard_challenge_set(
                authorization_name, token, id_type, id_value
            )
        )

        self.logger.debug(
            "ChallengeService._create_new_challenge_set() ended with %s challenges",
            len(challenge_list),
        )
        return challenge_list
