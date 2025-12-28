# -*- coding: utf-8 -*-
"""Authorization class - refactored version"""
# pylint: disable=R0913, R1705
from __future__ import print_function
import json
from typing import List, Tuple, Dict, Optional, Any
from dataclasses import dataclass
from acme_srv.db_handler import DBstore
from acme_srv.challenge import Challenge
from acme_srv.helper import (
    generate_random_string,
    uts_now,
    uts_to_date_utc,
    string_sanitize,
)
from acme_srv.helpers.config import load_config, config_eab_profile_load
from acme_srv.helpers.domain_utils import is_domain_whitelisted
from acme_srv.message import Message
from acme_srv.nonce import Nonce


# Custom Exceptions
class AuthorizationError(Exception):
    """Base exception for authorization operations"""

    # pylint: disable=unnecessary-pass
    pass


class AuthorizationNotFoundError(AuthorizationError):
    """Raised when authorization is not found"""

    # pylint: disable=unnecessary-pass
    pass


class AuthorizationExpiredError(AuthorizationError):
    """Raised when authorization has expired"""

    # pylint: disable=unnecessary-pass
    pass


class ConfigurationError(AuthorizationError):
    """Raised when configuration is invalid"""

    # pylint: disable=unnecessary-pass
    pass


@dataclass
class AuthorizationConfiguration:
    """Configuration for Authorization operations"""

    validity: int = 86400
    expiry_check_disable: bool = False
    authz_path: str = "/acme/authz/"
    prevalidated_domainlist: Optional[List[str]] = None
    eab_profiling: bool = False
    eab_handler: Optional[Any] = None


@dataclass
class AuthorizationData:
    """Authorization data structure"""

    name: str
    status: str
    expires: int
    token: str
    identifier: Optional[Dict[str, str]] = None
    challenges: Optional[List[Dict[str, str]]] = None
    wildcard: bool = False

    def to_dict(self) -> Dict[str, str]:
        """Convert to dictionary for response"""
        result = {
            "status": self.status,
            "expires": uts_to_date_utc(self.expires),
        }

        if self.identifier:
            result["identifier"] = self.identifier

        if self.wildcard:
            result["wildcard"] = self.wildcard

        if self.challenges:
            result["challenges"] = self.challenges

        return result


class AuthorizationRepository:
    """Repository class for authorization database operations"""

    def __init__(self, dbstore: DBstore, logger):
        self.dbstore = dbstore
        self.logger = logger

    def find_authorization_by_name(
        self, authz_name: str, field_list: List[str] = None
    ) -> Optional[Dict[str, str]]:
        """Find authorization by name in database"""
        self.logger.debug(
            "AuthorizationRepository.find_authorization_by_name(%s)", authz_name
        )

        try:
            if field_list:
                authz_list = self.dbstore.authorization_lookup(
                    "name", authz_name, field_list
                )
            else:
                authz_list = self.dbstore.authorization_lookup("name", authz_name)

            # authorization_lookup returns a list, we want the first item if it exists
            if authz_list and len(authz_list) > 0:
                return authz_list[0]
            else:
                return None

        except Exception as err:
            self.logger.critical(
                "Database error: failed to lookup authorization '%s': %s",
                authz_name,
                err,
            )
            raise AuthorizationError(
                f"Failed to find authorization '{authz_name}': {err}"
            ) from err

    def update_authorization_expiry(
        self, authz_name: str, token: str, expires: int
    ) -> None:
        """Update authorization expiry date and token"""
        self.logger.debug(
            "AuthorizationRepository.update_authorization_expiry(%s)", authz_name
        )

        try:
            self.dbstore.authorization_update(
                {"name": authz_name, "token": token, "expires": expires}
            )
        except Exception as err:
            self.logger.error(
                "Database error during authorization update (%s): %s", authz_name, err
            )
            raise AuthorizationError(
                f"Failed to update authorization '{authz_name}': {err}"
            ) from err

    def search_expired_authorizations(
        self, timestamp: int, field_list: List[str]
    ) -> List[Dict[str, str]]:
        """Search for expired authorizations"""
        self.logger.debug(
            "AuthorizationRepository.search_expired_authorizations(%s)", timestamp
        )

        try:
            return self.dbstore.authorizations_expired_search(
                "expires", timestamp, vlist=field_list, operant="<="
            )
        except Exception as err:
            self.logger.critical(
                "Database error: failed to search for expired authorizations: %s", err
            )
            raise AuthorizationError(
                f"Failed to search expired authorizations: {err}"
            ) from err

    def mark_authorization_as_expired(self, authz_name: str) -> None:
        """Mark authorization as expired"""
        self.logger.debug(
            "AuthorizationRepository.mark_authorization_as_expired(%s)", authz_name
        )

        try:
            self.dbstore.authorization_update({"name": authz_name, "status": "expired"})
        except Exception as err:
            self.logger.critical(
                "Database error: failed to update authorization '%s' as expired: %s",
                authz_name,
                err,
            )
            raise AuthorizationError(
                f"Failed to expire authorization '{authz_name}': {err}"
            ) from err

    def mark_authorization_as_valid(self, authz_name: str) -> None:
        """Mark authorization as valid"""
        self.logger.debug(
            "AuthorizationRepository.mark_authorization_as_valid(%s)", authz_name
        )

        try:
            self.dbstore.authorization_update({"name": authz_name, "status": "valid"})
        except Exception as err:
            self.logger.critical(
                "Database error: failed to update authorization '%s' as valid: %s",
                authz_name,
                err,
            )
            raise AuthorizationError(
                f"Failed to mark authorization '{authz_name}' as valid: {err}"
            ) from err

    def mark_order_as_ready(self, order_name: str) -> None:
        """Mark order as ready"""
        self.logger.debug("AuthorizationRepository.mark_order_as_ready(%s)", order_name)

        try:
            self.dbstore.order_update({"name": order_name, "status": "ready"})
        except Exception as err:
            self.logger.critical(
                "Database error: failed to update order '%s' as valid: %s",
                order_name,
                err,
            )
            raise AuthorizationError(
                f"Failed to mark order '{order_name}' as valid: {err}"
            ) from err


class AuthorizationBusinessLogic:
    """Business logic for authorization operations"""

    def __init__(
        self,
        config: AuthorizationConfiguration,
        repository: AuthorizationRepository,
        logger,
    ):
        self.config = config
        self.repository = repository
        self.logger = logger

    def extract_authorization_name_from_url(self, url: str, server_name: str) -> str:
        """Extract authorization name from URL"""
        self.logger.debug(
            "AuthorizationBusinessLogic.extract_authorization_name_from_url()"
        )

        authz_name = string_sanitize(
            self.logger, url.replace(f"{server_name}{self.config.authz_path}", "")
        )
        return authz_name

    def generate_authorization_token_and_expiry(self) -> Tuple[str, int]:
        """Generate new token and expiry time"""
        self.logger.debug(
            "AuthorizationBusinessLogic.generate_authorization_token_and_expiry()"
        )

        expires = uts_now() + self.config.validity
        token = generate_random_string(self.logger, 32)
        self.logger.debug(
            "AuthorizationBusinessLogic.generate_authorization_token_and_expiry() ended: Generated token expires at: %s",
            expires,
        )
        return token, expires

    def enrich_authorization_with_identifier_info(
        self, auth_db_info: Dict[str, str]
    ) -> Tuple[Dict[str, str], bool]:
        """Extract and enrich authorization with identifier information"""
        self.logger.debug(
            "AuthorizationBusinessLogic.enrich_authorization_with_identifier_info()"
        )

        if not auth_db_info:
            return {}, False

        auth_info = auth_db_info[0] if isinstance(auth_db_info, list) else auth_db_info
        identifier_info = {}
        is_tnauth = False

        # Extract status
        status = auth_info.get("status__name", "pending")
        identifier_info["status"] = status

        # Extract identifier
        if "type" in auth_info and "value" in auth_info:
            identifier_info["identifier"] = {
                "type": auth_info["type"],
                "value": auth_info["value"],
            }

            # Check for TNAuthList
            if auth_info["type"] == "TNAuthList":
                is_tnauth = True

            # Handle wildcard domains
            if auth_info["value"].startswith("*."):
                self.logger.debug("Adding wildcard flag to authorization")
                identifier_info["identifier"]["value"] = auth_info["value"][2:]
                identifier_info["wildcard"] = True

        return identifier_info, is_tnauth

    def extract_identifier_info_for_challenge(
        self, authz_info_dict: Dict[str, str]
    ) -> Tuple[str, str]:
        """Extract identifier type and value for challenge operations"""
        self.logger.debug(
            "AuthorizationBusinessLogic.extract_identifier_info_for_challenge()"
        )

        if "identifier" not in authz_info_dict:
            return None, None

        identifier = authz_info_dict["identifier"]
        id_type = identifier.get("type")
        id_value = identifier.get("value")

        return id_type, id_value

    def is_authorization_eligible_for_expiry(self, auth_record: Dict[str, str]) -> bool:
        """Check if authorization should be expired"""
        self.logger.debug(
            "AuthorizationBusinessLogic.is_authorization_eligible_for_expiry()"
        )

        # Must have name and status
        if "name" not in auth_record or "status__name" not in auth_record:
            return False

        # Skip if already expired
        if auth_record["status__name"] == "expired":
            return False

        # Skip corner cases where expiry is set to 0
        if "expires" in auth_record and auth_record["expires"] == 0:
            return False

        return True


class ChallengeSetManager:
    """Manager for challenge set operations"""

    def __init__(self, debug: bool, server_name: str, logger):
        self.debug = debug
        self.server_name = server_name
        self.logger = logger

    def get_challenge_set_for_authorization(
        self,
        authz_name: str,
        status: str,
        token: str,
        is_tnauth: bool,
        expires: int,
        id_type: str = None,
        id_value: str = None,
    ) -> List[Dict[str, str]]:
        """Get challenge set for authorization"""
        self.logger.debug(
            "ChallengeSetManager.get_challenge_set_for_authorization(%s)", authz_name
        )

        with Challenge(
            debug=self.debug,
            srv_name=self.server_name,
            logger=self.logger,
            expiry=expires,
        ) as challenge:
            return challenge.challengeset_get(
                authz_name, status, token, is_tnauth, id_type, id_value
            )


class Authorization(object):
    """Refactored Authorization class with clear separation of concerns"""

    def __init__(
        self, debug: bool = False, srv_name: str = None, logger: object = None
    ):
        self.server_name = srv_name
        self.debug = debug
        self.logger = logger

        # Initialize dependencies
        self.dbstore = DBstore(debug, self.logger)
        self.message = Message(debug, self.server_name, self.logger)
        self.nonce = Nonce(debug, self.logger)

        # Initialize components immediately
        self.config = AuthorizationConfiguration()
        self.repository = AuthorizationRepository(self.dbstore, self.logger)
        self.business_logic = AuthorizationBusinessLogic(
            self.config, self.repository, self.logger
        )
        self.challenge_manager = ChallengeSetManager(
            self.debug, self.server_name, self.logger
        )

    def __enter__(self):
        """Makes Authorization a Context Manager"""
        self._load_configuration()
        # Re-initialize business logic with updated config
        self.business_logic = AuthorizationBusinessLogic(
            self.config, self.repository, self.logger
        )
        return self

    def __exit__(self, *args):
        """Close the connection at the end of the context"""
        # pylint: disable=unnecessary-pass
        pass

    def _load_configuration(self) -> AuthorizationConfiguration:
        """Load configuration from file"""
        self.logger.debug("Authorization._load_configuration()")

        config_dic = load_config()

        if config_dic:

            try:
                self.config.validity = int(
                    config_dic.get("Authorization", "validity", fallback=86400)
                )
            except ValueError as err:
                raise ConfigurationError(
                    f"Invalid validity parameter: {config_dic.get('Authorization', 'validity')}"
                ) from err

            self.config.expiry_check_disable = config_dic.getboolean(
                "Authorization", "expiry_check_disable", fallback=False
            )
            url_prefix = config_dic.get("Directory", "url_prefix", fallback=None)
            if url_prefix:
                self.config.authz_path = f"{url_prefix}{self.config.authz_path}"

            try:
                # load  prevalidated_domainlist
                self.config.prevalidated_domainlist = json.loads(
                    config_dic.get(
                        "Authorization", "prevalidated_domainlist", fallback="null"
                    )
                )
                self.logger.warning(
                    "Prevalidated list of domains loaded globally. Such configuration is NOT recommended as this is a severe security risk!"
                )
            except json.JSONDecodeError as err:
                self.config.prevalidated_domainlist = None
                raise ConfigurationError(
                    "Invalid prevalidated_domainlist parameter"
                ) from err

            # load profiling
            (
                self.config.eab_profiling,
                self.config.eab_handler,
            ) = config_eab_profile_load(self.logger, config_dic)

        self.logger.debug("Authorization._load_configuration() ended:")

    @property
    def validity(self):
        """Backward compatibility property for validity"""
        return self.config.validity

    @validity.setter
    def validity(self, value):
        """Setter for validity"""
        self.config.validity = value

    @property
    def expiry_check_disable(self):
        """Backward compatibility property for expiry_check_disable"""
        return self.config.expiry_check_disable

    @expiry_check_disable.setter
    def expiry_check_disable(self, value):
        """Setter for expiry_check_disable"""
        self.config.expiry_check_disable = value

    def _authz_info(self, url: str) -> Dict[str, str]:
        """Backward compatibility method - delegates to get_authorization_details"""
        return self.get_authorization_details(url)

    def get_authorization_details(self, url: str) -> Optional[Dict[str, str]]:
        """Get detailed authorization information"""
        self.logger.debug("Authorization.get_authorization_details()")

        # Extract authorization name from URL
        authz_name = self.business_logic.extract_authorization_name_from_url(
            url, self.server_name
        )
        self.logger.debug("Authorization name: %s", authz_name)

        # Check if authorization exists
        authz = self.repository.find_authorization_by_name(authz_name)
        if not authz:
            self.logger.debug("Authorization not found: %s", authz_name)
            return {}

        # Generate new token and expiry
        token, expires = self.business_logic.generate_authorization_token_and_expiry()
        # Update authorization with new expiry and token (if there is no token yet)
        self.repository.update_authorization_expiry(authz_name, token, expires)

        # Create base authorization info
        authz_info = {
            "expires": uts_to_date_utc(expires),
        }

        # Get detailed authorization information
        auth_details = self.repository.find_authorization_by_name(
            authz_name,
            [
                "status__name",
                "type",
                "value",
                "order__name",
                "order__account__name",
                "order__account__eab_kid",
            ],
        )

        if auth_details:
            (
                identifier_info,
                is_tnauth,
            ) = self.business_logic.enrich_authorization_with_identifier_info(
                auth_details
            )
            authz_info.update(identifier_info)
        else:
            authz_info["status"] = "pending"
            is_tnauth = False

        # Extract identifier type and value
        id_type, id_value = self.business_logic.extract_identifier_info_for_challenge(
            authz_info
        )

        if auth_details:
            # Apply EAB profile and domain whitelist logic
            self._apply_eab_and_domain_whitelist(
                authz_name, auth_details, id_type, id_value, authz_info
            )

        # Get challenge set
        try:
            authz_info[
                "challenges"
            ] = self.challenge_manager.get_challenge_set_for_authorization(
                authz_name,
                authz_info["status"],
                token,
                is_tnauth,
                expires,
                id_type,
                id_value,
            )
        except Exception as err:
            self.logger.error(
                "Failed to create challenge set for authorization %s: %s",
                authz_name,
                err,
            )
            return None

        self.logger.debug(
            "Authorization.get_authorization_details() returns: %s",
            json.dumps(authz_info),
        )
        return authz_info

    def _apply_eab_and_domain_whitelist(
        self, authz_name, auth_details, id_type, id_value, authz_info
    ):
        """Apply EAB profile settings and domain whitelist logic to authorization info."""
        self._apply_eab_profile(authz_name, auth_details)
        self._apply_domain_whitelist(
            authz_name, auth_details, id_type, id_value, authz_info
        )

    def _apply_eab_profile(self, authz_name, auth_details):
        if not self.config.eab_profiling:
            return
        self.logger.debug(
            "Authorization._apply_eab_and_domain_whitelist() - apply eab profile setting"
        )
        eab_kid = auth_details.get("order__account__eab_kid") if auth_details else None
        if not eab_kid:
            return
        try:
            with self.config.eab_handler(self.logger) as eab_handler:
                profile_dic = eab_handler.key_file_load()
                prevalidated_domainlist = (
                    profile_dic.get(eab_kid, {})
                    .get("authorization", {})
                    .get("prevalidated_domainlist")
                )
                if prevalidated_domainlist:
                    self.logger.debug(
                        "Authorization._apply_eab_and_domain_whitelist() - apply prevalidated_domainlist from eab profile."
                    )
                    self.config.prevalidated_domainlist = prevalidated_domainlist
        except Exception as err:
            self.logger.error(
                "Failed to process EAB profile for challenge %s (kid: %s): %s",
                authz_name,
                eab_kid,
                err,
            )

    def _apply_domain_whitelist(
        self, authz_name, auth_details, id_type, id_value, authz_info
    ):
        if id_type != "dns" or not getattr(
            self.config, "prevalidated_domainlist", None
        ):
            return
        self.logger.debug(
            "Authorization.get_authorization_details() - Checking preauthorized domain list for DNS identifier"
        )
        if is_domain_whitelisted(
            self.logger, id_value, self.config.prevalidated_domainlist
        ):
            self.logger.debug(
                "Domain %s is preauthorized, setting authorization status to 'valid'",
                id_value,
            )
            authz_info["status"] = "valid"
            self.repository.mark_authorization_as_valid(authz_name)
            if auth_details is not None:
                self.repository.mark_order_as_ready(auth_details.get("order__name"))
            else:
                self.logger.debug(
                    "No order information found for authorization %s", authz_name
                )

    def expire_invalid_authorizations(
        self, timestamp: int = None
    ) -> Tuple[List[str], List[str]]:
        """Expire invalid authorizations"""
        self.logger.debug("Authorization.expire_invalid_authorizations(%s)", timestamp)

        if timestamp is None:
            timestamp = uts_now()
            self.logger.debug("Set timestamp to current time: %s", timestamp)

        field_list = [
            "id",
            "name",
            "expires",
            "value",
            "created_at",
            "token",
            "status__id",
            "status__name",
            "order__id",
            "order__name",
        ]

        try:
            # Search for expired authorizations
            expired_authz_list = self.repository.search_expired_authorizations(
                timestamp, field_list
            )
        except AuthorizationError as err:
            self.logger.warning("Failed to search for expired authorizations: %s", err)
            return field_list, []

        # Process expired authorizations
        expired_output = []
        for authz_record in expired_authz_list:
            try:
                if self.business_logic.is_authorization_eligible_for_expiry(
                    authz_record
                ):
                    expired_output.append(authz_record)
                    self.repository.mark_authorization_as_expired(authz_record["name"])
            except AuthorizationError as err:
                self.logger.warning(
                    "Failed to expire authorization %s: %s",
                    authz_record.get("name"),
                    err,
                )
                # Continue processing other authorizations
                continue

        self.logger.debug(
            "Authorization.expire_invalid_authorizations() ended: %s authorizations expired",
            len(expired_output),
        )
        return field_list, expired_output

    def handle_get_request(self, url: str) -> Dict[str, str]:
        """Handle GET request for authorization"""
        self.logger.debug("Authorization.handle_get_request()")

        try:
            authorization_data = self.get_authorization_details(url)
            if authorization_data:
                return {"code": 200, "header": {}, "data": authorization_data}
            else:
                return {
                    "code": 404,
                    "header": {},
                    "data": {"error": "Authorization not found"},
                }
        except AuthorizationError as err:
            self.logger.error("Authorization error: %s", err)
            return {"code": 404, "header": {}, "data": {"error": str(err)}}

    def handle_post_request(self, content: str) -> Dict[str, str]:
        """Handle POST request for authorization"""
        self.logger.debug("Authorization.handle_post_request()")

        # Expire invalid authorizations if not disabled
        if not self.expiry_check_disable:
            try:
                self.invalidate()  # Call public method for backward compatibility
            except Exception as err:
                self.logger.warning("Failed to expire authorizations: %s", err)
                # Continue with processing - don't fail the request

        # Validate message
        code, message, detail, protected, _payload, _account_name = self.message.check(
            content
        )

        response_dic = {}
        if code == 200:
            if "url" not in protected:
                code = 400
                message = "urn:ietf:params:acme:error:malformed"
                detail = "url is missing in protected"
            else:
                try:
                    auth_info = self.get_authorization_details(protected["url"])
                    if auth_info:
                        response_dic["data"] = auth_info
                    else:
                        code = 403
                        message = "urn:ietf:params:acme:error:unauthorized"
                        detail = "authorization lookup failed"
                except AuthorizationError as err:
                    self.logger.error("Authorization error: %s", err)
                    code = 403
                    message = "urn:ietf:params:acme:error:unauthorized"
                    detail = f"authorization error: {err}"

        # Prepare response
        status_dic = {"code": code, "type": message, "detail": detail}
        response_dic = self.message.prepare_response(response_dic, status_dic)

        self.logger.debug(
            "Authorization.handle_post_request() returns: %s", json.dumps(response_dic)
        )
        return response_dic

    # Backward compatibility methods (delegating to new methods)
    def new_get(self, url: str) -> Dict[str, str]:
        """Backward compatibility: handle GET request"""
        self.logger.debug("Authorization.new_get()")
        return self.handle_get_request(url)

    def new_post(self, content: str) -> Dict[str, str]:
        """Backward compatibility: handle POST request"""
        self.logger.debug("Authorization.new_post()")
        return self.handle_post_request(content)

    def invalidate(self, timestamp: int = None) -> Tuple[List[str], List[str]]:
        """Backward compatibility: expire invalid authorizations"""
        self.logger.debug("Authorization.invalidate()")
        return self.expire_invalid_authorizations(timestamp)
