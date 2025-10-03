"""
Challenge Repository and Network Validator
"""

from typing import Dict, List, Optional, Tuple
from refactored_challenge_models import (
    ChallengeData, ChallengeIdentifier, ChallengeType, ChallengeStatus,
    IdentifierType, ChallengeDatabaseError, ChallengeNetworkError
)
from acme_srv.db_handler import DBstore
from acme_srv.helper import fqdn_resolve, ptr_resolve


class ChallengeRepository:
    """Repository for challenge data access operations"""

    def __init__(self, dbstore: DBstore, logger):
        self.dbstore = dbstore
        self.logger = logger

    def find_by_name(self, challenge_name: str) -> Optional[ChallengeData]:
        """Find challenge by name"""
        try:
            challenge_dict = self.dbstore.challenge_lookup(
                "name", challenge_name,
                [
                    "type", "status__name", "token", "authorization__name",
                    "authorization__type", "authorization__value",
                    "authorization__order__account__name", "validated", "expires"
                ]
            )

            if challenge_dict:
                return self._map_to_challenge_data(challenge_name, challenge_dict)

        except Exception as e:
            self.logger.critical(f"Database error during challenge lookup: {e}")
            raise ChallengeDatabaseError(f"Failed to find challenge {challenge_name}: {e}")

        return None

    def find_by_authorization(self, authorization_name: str) -> List[ChallengeData]:
        """Find challenges by authorization name"""
        try:
            challenge_list = self.dbstore.challenges_search(
                "authorization__name", authorization_name,
                ["name", "type", "status__name", "token"]
            )

            return [self._map_search_result_to_challenge_data(challenge)
                   for challenge in challenge_list]

        except Exception as e:
            self.logger.critical(f"Database error during challenges search: {e}")
            raise ChallengeDatabaseError(f"Failed to find challenges for authorization {authorization_name}: {e}")

    def save(self, challenge_data: ChallengeData) -> bool:
        """Save challenge data"""
        try:
            data_dict = self._map_from_challenge_data(challenge_data)
            self.dbstore.challenge_update(data_dict)
            return True

        except Exception as e:
            self.logger.critical(f"Database error during challenge update: {e}")
            raise ChallengeDatabaseError(f"Failed to save challenge {challenge_data.name}: {e}")

    def create(self, authorization_name: str, challenge_type: str, token: str,
              identifier_value: str = None) -> Optional[str]:
        """Create new challenge"""
        try:
            from acme_srv.helper import generate_random_string

            challenge_name = generate_random_string(self.logger, 12)

            data_dict = {
                "name": challenge_name,
                "expires": 3600,  # Default expiry
                "type": challenge_type,
                "token": token,
                "authorization": authorization_name,
                "status": 2,  # pending status
            }

            chid = self.dbstore.challenge_add(identifier_value, challenge_type, data_dict)
            return challenge_name if chid else None

        except Exception as e:
            self.logger.critical(f"Database error during challenge creation: {e}")
            raise ChallengeDatabaseError(f"Failed to create challenge: {e}")

    def get_jwk_for_challenge(self, challenge_name: str) -> Optional[Dict[str, str]]:
        """Get JWK for challenge"""
        try:
            challenge_dict = self.dbstore.challenge_lookup(
                "name", challenge_name,
                ["authorization__order__account__name"]
            )

            if "authorization__order__account__name" in challenge_dict:
                account_name = challenge_dict["authorization__order__account__name"]
                return self.dbstore.jwk_load(account_name)

        except Exception as e:
            self.logger.critical(f"Database error getting JWK: {e}")
            raise ChallengeDatabaseError(f"Failed to get JWK for challenge {challenge_name}: {e}")

        return None

    def update_authorization_status(self, challenge_name: str, status: str) -> bool:
        """Update authorization status based on challenge"""
        try:
            # Lookup authorization based on challenge_name
            authz_result = self.dbstore.challenge_lookup(
                "name", challenge_name, ["authorization__name"]
            )

            if authz_result and "authorization" in authz_result:
                authz_name = authz_result["authorization"]
                data_dict = {"name": authz_name, "status": status}
                self.dbstore.authorization_update(data_dict)
                return True

        except Exception as e:
            self.logger.critical(f"Database error updating authorization: {e}")
            raise ChallengeDatabaseError(f"Failed to update authorization for challenge {challenge_name}: {e}")

        return False

    def _map_to_challenge_data(self, challenge_name: str, challenge_dict: Dict) -> ChallengeData:
        """Map database result to ChallengeData"""
        identifier = ChallengeIdentifier(
            type=IdentifierType(challenge_dict.get("authorization__type", "dns")),
            value=challenge_dict.get("authorization__value", "")
        )

        return ChallengeData(
            name=challenge_name,
            type=ChallengeType(challenge_dict.get("type", "http-01")),
            status=ChallengeStatus(challenge_dict.get("status__name", "pending")),
            token=challenge_dict.get("token", ""),
            identifier=identifier,
            authorization_name=challenge_dict.get("authorization__name", ""),
            account_name=challenge_dict.get("authorization__order__account__name", ""),
            validated_at=challenge_dict.get("validated"),
            expires=challenge_dict.get("expires")
        )

    def _map_search_result_to_challenge_data(self, challenge_dict: Dict) -> ChallengeData:
        """Map search result to ChallengeData (limited fields)"""
        return ChallengeData(
            name=challenge_dict.get("name", ""),
            type=ChallengeType(challenge_dict.get("type", "http-01")),
            status=ChallengeStatus(challenge_dict.get("status__name", "pending")),
            token=challenge_dict.get("token", ""),
            identifier=ChallengeIdentifier(type=IdentifierType.DNS, value=""),  # Placeholder
            authorization_name="",  # Will be filled if needed
            account_name=""  # Will be filled if needed
        )

    def _map_from_challenge_data(self, challenge_data: ChallengeData) -> Dict:
        """Map ChallengeData to database format"""
        data_dict = {
            "name": challenge_data.name,
            "status": challenge_data.status.value,
        }

        if challenge_data.validated_at:
            data_dict["validated"] = challenge_data.validated_at

        if challenge_data.key_authorization:
            data_dict["keyauthorization"] = challenge_data.key_authorization

        if challenge_data.error_detail:
            data_dict["error"] = challenge_data.error_detail

        return data_dict


class NetworkValidator:
    """Handles network-related validations"""

    def __init__(self, logger, config):
        self.logger = logger
        self.config = config

    def validate_source_address(self, challenge_data: ChallengeData,
                               source_address: Optional[str]) -> Tuple[bool, bool]:
        """Validate source address against challenge identifier"""
        if not source_address:
            return True, False

        try:
            if self.config.forward_address_check:
                success, invalid = self._forward_address_check(challenge_data, source_address)
                if not success:
                    return success, invalid

            if self.config.reverse_address_check:
                success, invalid = self._reverse_address_check(challenge_data, source_address)
                return success, invalid

            return True, False

        except Exception as e:
            self.logger.error(f"Network validation error: {e}")
            raise ChallengeNetworkError(f"Source address validation failed: {e}")

    def _forward_address_check(self, challenge_data: ChallengeData,
                              source_address: str) -> Tuple[bool, bool]:
        """Perform forward DNS address check"""
        if (challenge_data.identifier.type != IdentifierType.DNS or
            not challenge_data.identifier.value):
            return True, False

        try:
            response_list, invalid = fqdn_resolve(
                self.logger, challenge_data.identifier.value,
                self.config.dns_server_list, catch_all=True
            )

            if invalid:
                self.logger.error(f"DNS check returned invalid for {challenge_data.identifier.value}")
                return False, True
            elif response_list and source_address in response_list:
                self.logger.debug(f"Forward address check passed for {source_address}")
                return True, False
            else:
                self.logger.error(f"DNS check failed for {challenge_data.identifier.value}/{source_address}")
                return False, True

        except Exception as e:
            self.logger.error(f"Forward address check failed: {e}")
            return False, True

    def _reverse_address_check(self, challenge_data: ChallengeData,
                              source_address: str) -> Tuple[bool, bool]:
        """Perform reverse DNS address check"""
        if (challenge_data.identifier.type != IdentifierType.DNS or
            not challenge_data.identifier.value):
            return True, False

        try:
            response, invalid = ptr_resolve(
                self.logger, source_address, self.config.dns_server_list
            )

            if response and response == challenge_data.identifier.value:
                self.logger.debug(f"Reverse address check succeeded for {source_address}")
                return True, False
            else:
                self.logger.error(f"PTR check failed for {source_address}")
                return False, True

        except Exception as e:
            self.logger.error(f"Reverse address check failed: {e}")
            return False, True


class ConfigurationManager:
    """Manages challenge configuration"""

    def __init__(self, logger):
        self.logger = logger

    def load_configuration(self) -> 'ChallengeConfiguration':
        """Load challenge configuration from file"""
        from acme_srv.helper import load_config, config_eab_profile_load
        from refactored_challenge_models import ChallengeConfiguration

        config_dict = load_config()

        # Default configuration
        config = ChallengeConfiguration()

        # Load challenge-specific settings
        if "Challenge" in config_dict:
            challenge_section = config_dict["Challenge"]

            config.validation_disabled = config_dict.getboolean(
                "Challenge", "challenge_validation_disable", fallback=False
            )
            config.forward_address_check = config_dict.getboolean(
                "Challenge", "forward_address_check", fallback=False
            )
            config.reverse_address_check = config_dict.getboolean(
                "Challenge", "reverse_address_check", fallback=False
            )
            config.sectigo_simulation = config_dict.getboolean(
                "Challenge", "sectigo_sim", fallback=False
            )

            try:
                config.validation_timeout = int(
                    challenge_section.get("challenge_validation_timeout", config.validation_timeout)
                )
                config.dns_validation_pause_timer = float(
                    challenge_section.get("dns_validation_pause_timer", config.dns_validation_pause_timer)
                )
            except (ValueError, TypeError) as e:
                self.logger.warning(f"Failed to parse timeout configuration: {e}")

            # Load DNS server list
            if "dns_server_list" in challenge_section:
                try:
                    import json
                    config.dns_server_list = json.loads(challenge_section["dns_server_list"])
                except (json.JSONDecodeError, TypeError) as e:
                    self.logger.warning(f"Failed to load DNS server list: {e}")

        # Load Order-specific settings
        if "Order" in config_dict:
            config.tnauthlist_support = config_dict.getboolean(
                "Order", "tnauthlist_support", fallback=False
            )
            config.email_identifier_support = config_dict.getboolean(
                "Order", "email_identifier_support", fallback=False
            )

        # Load email settings
        if config.email_identifier_support:
            if "DEFAULT" in config_dict and "email_address" in config_dict["DEFAULT"]:
                config.email_address = config_dict["DEFAULT"]["email_address"]
            else:
                self.logger.warning("Email identifier support enabled but no email address configured")
                config.email_identifier_support = False

        # Load proxy configuration
        if "DEFAULT" in config_dict and "proxy_server_list" in config_dict["DEFAULT"]:
            try:
                import json
                config.proxy_server_list = json.loads(config_dict["DEFAULT"]["proxy_server_list"])
            except (json.JSONDecodeError, TypeError) as e:
                self.logger.warning(f"Failed to load proxy server list: {e}")

        return config

    def get_eab_challenge_validation_disabled(self, challenge_name: str,
                                            eab_handler, dbstore: DBstore) -> bool:
        """Check if challenge validation is disabled via EAB profile"""
        if not eab_handler:
            return False

        try:
            challenge_dict = dbstore.challenge_lookup(
                "name", challenge_name,
                ["authorization__order__account__eab_kid"]
            )

            eab_kid = challenge_dict.get("authorization__order__account__eab_kid")
            if not eab_kid:
                return False

            with eab_handler(self.logger) as handler:
                profile_dict = handler.key_file_load()
                return (profile_dict.get(eab_kid, {})
                       .get("challenge", {})
                       .get("challenge_validation_disable", False))

        except Exception as e:
            self.logger.error(f"Failed to check EAB profile: {e}")
            return False