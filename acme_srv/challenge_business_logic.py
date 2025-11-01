"""
Separation of challenge validation logic and database/state management
operations for challenge processing.

"""
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass
import logging
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

class ChallengeRepository(ABC):
    """Abstract repository for challenge data operations."""

    @abstractmethod
    def find_challenges_by_authorization(
        self,
        authorization_name: str
    ) -> List[ChallengeInfo]:
        """Find all challenges for a given authorization."""
        pass

    @abstractmethod
    def get_challenge_by_name(self, name: str) -> Optional[ChallengeInfo]:
        """Get challenge information by name."""
        pass

    @abstractmethod
    def create_challenge(self, request: ChallengeCreationRequest) -> Optional[str]:
        """Create a new challenge and return its name."""
        pass

    @abstractmethod
    def update_challenge(self, request: ChallengeUpdateRequest) -> bool:
        """Update an existing challenge."""
        pass

    @abstractmethod
    def update_authorization_status(
        self,
        challenge_name: str,
        status: str
    ) -> bool:
        """Update authorization status based on challenge."""
        pass

    @abstractmethod
    def get_account_jwk(self, challenge_name: str) -> Optional[Dict[str, Any]]:
        """Get JWK for the account associated with the challenge."""
        pass

class ChallengeStateManager:
    """Manages challenge state transitions and business rules."""

    def __init__(self, repository: ChallengeRepository, logger: logging.Logger):
        self.repository = repository
        self.logger = logger

    def transition_to_processing(self, challenge_name: str) -> bool:
        """Transition challenge to processing state."""
        self.logger.debug("ChallengeStateManager.transition_to_processing(%s)", challenge_name)

        update_request = ChallengeUpdateRequest(
            name=challenge_name,
            status="processing"
        )
        result = self.repository.update_challenge(update_request)
        self.logger.debug("ChallengeStateManager.transition_to_processing() updated challenge %s to processing/%s", challenge_name, result)
        return result

    def transition_to_valid(
        self,
        challenge_name: str,
        source_address: Optional[str] = None,
        validated_timestamp: Optional[int] = None
    ) -> bool:
        """Transition challenge to valid state."""
        self.logger.debug("ChallengeStateManager.transition_to_valid(%s)", challenge_name)

        update_request = ChallengeUpdateRequest(
            name=challenge_name,
            status="valid",
            source=source_address,
            validated=validated_timestamp
        )

        success = self.repository.update_challenge(update_request)
        if success:
            success = self.repository.update_authorization_status(challenge_name, "valid")

        self.logger.debug("ChallengeStateManager.transition_to_valid() updated challenge %s to valid/%s", challenge_name, success)
        return success

    def transition_to_invalid(
        self,
        challenge_name: str,
        source_address: Optional[str] = None
    ) -> bool:
        """Transition challenge to invalid state."""
        self.logger.debug("ChallengeStateManager.transition_to_invalid(%s)", challenge_name)

        update_request = ChallengeUpdateRequest(
            name=challenge_name,
            status="invalid",
            source=source_address
        )

        success = self.repository.update_challenge(update_request)
        if success:
            success = self.repository.update_authorization_status(challenge_name, "invalid")

        self.logger.debug("ChallengeStateManager.transition_to_invalid() ended: updated challenge %s to invalid/%s", challenge_name, success)
        return success

    def update_key_authorization(
        self,
        challenge_name: str,
        key_authorization: str
    ) -> bool:
        """Update challenge with key authorization."""
        self.logger.debug("ChallengeStateManager.update_key_authorization(%s)", challenge_name)

        update_request = ChallengeUpdateRequest(
            name=challenge_name,
            keyauthorization=key_authorization
        )
        self.logger.debug("ChallengeStateManager.update_key_authorization() ended: updating challenge %s with key authorization", challenge_name)
        return self.repository.update_challenge(update_request)

class ChallengeFactory:
    """Factory for creating different types of challenges."""

    def __init__(
        self,
        repository: ChallengeRepository,
        logger: logging.Logger,
        server_name: str,
        challenge_path: str,
        email_address: Optional[str] = None
    ):
        self.repository = repository
        self.logger = logger
        self.server_name = server_name
        self.challenge_path = challenge_path
        self.email_address = email_address

    def create_standard_challenge_set(
        self,
        authorization_name: str,
        token: str,
        id_type: str,
        value: str
    ) -> List[Dict[str, Any]]:
        """Create standard ACME challenge set (http-01, dns-01, tls-alpn-01)."""
        self.logger.debug(
            "ChallengeFactory.create_standard_challenge_set(%s)",
            authorization_name
        )

        challenge_types = ["http-01", "dns-01", "tls-alpn-01"]

        # Skip DNS challenge for IP identifiers
        if id_type == "ip":
            self.logger.debug("ChallengeFactory.create_standard_challenge_set(): Skipping dns-01 challenge for IP identifier")
            challenge_types.remove("dns-01")

        challenges = []
        for challenge_type in challenge_types:
            challenge_dict = self._create_single_challenge(
                authorization_name, challenge_type, token, value
            )
            if challenge_dict:
                challenges.append(challenge_dict)
        self.logger.debug(
            "ChallengeFactory.create_standard_challenge_set() ended: Created %d challenges", len(challenges)
        )
        return challenges

    def create_email_reply_challenge(
        self,
        authorization_name: str,
        token: str,
        email_address: str
    ) -> Optional[Dict[str, Any]]:
        """Create email-reply-00 challenge."""
        self.logger.debug("ChallengeFactory.create_email_reply_challenge(%s)", email_address)

        result = self._create_single_challenge(
            authorization_name, "email-reply-00", token, email_address
        )
        self.logger.debug("ChallengeFactory.create_email_reply_challenge() ended: %s", result)
        return result

    def create_tkauth_challenge(
        self,
        authorization_name: str,
        token: str
    ) -> Optional[Dict[str, Any]]:
        """Create tkauth-01 challenge."""
        self.logger.debug("ChallengeFactory.create_tkauth_challenge(%s)", authorization_name)

        result =  self._create_single_challenge(
            authorization_name, "tkauth-01", token
        )
        self.logger.debug("ChallengeFactory.create_tkauth_challenge() ended: %s", result)
        return result

    def _create_single_challenge(
        self,
        authorization_name: str,
        challenge_type: str,
        token: str,
        value: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        """Create a single challenge of the specified type."""
        self.logger.debug(
            "ChallengeFactory._create_single_challenge(): Creating %s challenge for authorization: %s",
            challenge_type, authorization_name
        )
        request = ChallengeCreationRequest(
            authorization_name=authorization_name,
            challenge_type=challenge_type,
            token=token,
            value=value
        )
        challenge_name = self.repository.create_challenge(request)
        if not challenge_name:
            self.logger.error("Failed to create %s challenge", challenge_type)
            return None

        challenge_dict = {
            "type": challenge_type,
            "url": f"{self.server_name}{self.challenge_path}{challenge_name}",
            "token": token,
            "status": "pending"
        }

        # Add type-specific properties
        if challenge_type == "email-reply-00" and self.email_address:
            challenge_dict["from"] = self.email_address
        elif challenge_type == "tkauth-01":
            challenge_dict["tkauth-type"] = "atc"
        elif challenge_type == "sectigo-email-01":
            challenge_dict["status"] = "valid"
            challenge_dict.pop("token", None)

        self.logger.debug("ChallengeFactory._create_single_challenge() ended: created challenge %s/%s", challenge_type, challenge_name)
        return challenge_dict

class ChallengeService:
    """High-level service for challenge operations."""

    def __init__(
        self,
        repository: ChallengeRepository,
        state_manager: ChallengeStateManager,
        factory: ChallengeFactory,
        logger: logging.Logger
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
        tnauthlist_support: bool,
        email_identifier_support: bool = False,
        sectigo_sim: bool = False,
        url: str = ""
    ) -> List[Dict[str, Any]]:
        """Get challenge set for an authorization."""
        self.logger.debug(
            "ChallengeService.get_challenge_set_for_authorization(%s)", authorization_name
        )

        # Check for existing challenges
        existing_challenges = self.repository.find_challenges_by_authorization(
            authorization_name
        )

        if existing_challenges:
            self.logger.debug("ChallengeService.get_challenge_set_for_authorization(): Found existing challenges")
            return self._format_existing_challenges(challenges=existing_challenges, url=url)

        # Create new challenge set
        self.logger.debug("ChallengeService.get_challenge_set_for_authorization(%s): Creating new challenge set", authorization_name)
        return self._create_new_challenge_set(
            authorization_name, token, tnauthlist_support, id_type, id_value,
            email_identifier_support, sectigo_sim
        )

    def _format_existing_challenges(
        self,
        challenges: List[ChallengeInfo],
        url: str = ""
    ) -> List[Dict[str, Any]]:
        """Format existing challenges for response."""
        self.logger.debug(
            "ChallengeService._format_existing_challenges(%s)", len(challenges)
        )
        challenge_list = []
        for challenge in challenges:
            challenge_dict = {
                "type": challenge.type,
                "url": f'{url}{challenge.name}',
                "token": challenge.token,
                "status": challenge.status
            }

            # Add email address for email-reply challenges
            if challenge.type == "email-reply-00" and hasattr(self.factory, 'email_address'):
                challenge_dict["from"] = self.factory.email_address

            challenge_list.append(challenge_dict)

        self.logger.debug("ChallengeService._format_existing_challenges() ended with %s challenges", len(challenge_list))
        return challenge_list

    def _create_new_challenge_set(
        self,
        authorization_name: str,
        token: str,
        tnauthlist_support: bool,
        id_type: str,
        id_value: str,
        email_identifier_support: bool,
        sectigo_sim: bool
    ) -> List[Dict[str, Any]]:
        """Create a new challenge set based on configuration."""
        self.logger.debug(
            "ChallengeService._create_new_challenge_set(%s)", authorization_name
        )
        if tnauthlist_support:
            challenge = self.factory.create_tkauth_challenge(authorization_name, token)
            return [challenge] if challenge else []

        if sectigo_sim:
            challenge = self.factory._create_single_challenge(
                authorization_name, "sectigo-email-01", token
            )
            return [challenge] if challenge else []

        if email_identifier_support and "@" in id_value:
            challenge = self.factory.create_email_reply_challenge(
                authorization_name, token, id_value
            )
            return [challenge] if challenge else []

        return self.factory.create_standard_challenge_set(
            authorization_name, token, id_type, id_value
        )