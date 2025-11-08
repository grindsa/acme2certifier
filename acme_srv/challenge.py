import json
import time
from typing import List, Tuple, Dict, Optional, Any
from dataclasses import dataclass

from acme_srv.helper import (
    generate_random_string,
    jwk_thumbprint_get,
    parse_url,
    uts_now,
    uts_to_date_utc,
    load_config,
    error_dic_get,
    config_eab_profile_load,
)
from acme_srv.db_handler import DBstore
from acme_srv.email_handler import EmailHandler
from acme_srv.message import Message
from acme_srv.threadwithreturnvalue import ThreadWithReturnValue

# Import our refactored modules
from acme_srv.challenge_validators import (
    ChallengeValidatorRegistry,
    ChallengeContext,
    ValidationResult,
)
from acme_srv.challenge_registry_setup import create_challenge_validator_registry

from acme_srv.challenge_business_logic import (
    ChallengeRepository,
    ChallengeStateManager,
    ChallengeFactory,
    ChallengeService,
    ChallengeInfo,
    ChallengeCreationRequest,
    ChallengeUpdateRequest,
)
from acme_srv.challenge_error_handling import (
    ErrorHandler,
    ChallengeError,
    ValidationError,
    DatabaseError,
    UnsupportedChallengeTypeError,
)


@dataclass
class ChallengeConfiguration:
    """Configuration for challenge processing."""

    validation_disabled: bool = False
    validation_timeout: int = 10
    dns_server_list: Optional[List[str]] = None
    dns_validation_pause_timer: float = 0.5
    proxy_server_list: Optional[Dict[str, str]] = None
    sectigo_sim: bool = False
    tnauthlist_support: bool = False
    email_identifier_support: bool = False
    email_address: Optional[str] = None
    forward_address_check: bool = False
    reverse_address_check: bool = False
    source_address: Optional[str] = None
    eab_profiling: bool = False


class DatabaseChallengeRepository(ChallengeRepository):
    """Database implementation of challenge repository."""

    def __init__(self, dbstore: DBstore, logger, expiry: float = 3600):
        self.dbstore = dbstore
        self.logger = logger
        self.expiry = expiry

    def find_challenges_by_authorization(
        self, authorization_name: str
    ) -> List[ChallengeInfo]:
        """Find all challenges for a given authorization."""
        self.logger.debug(
            "DatabaseChallengeRepository.find_challenges_by_authorization(%s)",
            authorization_name,
        )
        try:
            challenge_list = self.dbstore.challenges_search(
                "authorization__name",
                authorization_name,
                ("name", "type", "status__name", "token"),
            )

            result = []
            for challenge in challenge_list:
                challenge_info = ChallengeInfo(
                    name=challenge["name"],
                    type=challenge["type"],
                    token=challenge["token"],
                    status=challenge.get("status__name", "pending"),
                    authorization_name=authorization_name,
                    authorization_type="",  # Would need additional query
                    authorization_value="",  # Would need additional query
                    url="",  # Will be constructed later
                )
                result.append(challenge_info)

            self.logger.debug(
                "DatabaseChallengeRepository.find_challenges_by_authorization() ended: found %d challenges",
                len(result),
            )
            return result
        except Exception as err:
            self.logger.critical(
                "Database error: failed to search for challenges: %s", err
            )
            raise DatabaseError(f"Failed to search challenges: {err}")

    def get_challengeinfo_by_challengename(
        self, name: str, vlist: Optional[List[str]] = ("name", "type", "status__name")
    ) -> Optional[str]:
        """Get challenge information challenge name."""
        self.logger.debug(
            "DatabaseChallengeRepository.get_challengeinfo_by_challengename(%s)", name
        )
        try:
            challenge_dic = self.dbstore.challenge_lookup(
                "name",
                name,
                vlist=vlist,
            )

            self.logger.debug(
                "DatabaseChallengeRepository.get_challengeinfo_by_challengename() ended: found challenge %s",
                challenge_dic,
            )
            if not challenge_dic:
                return None
            return challenge_dic

        except Exception as err:
            self.logger.critical(
                "Database error: failed to lookup challenge keyauthorization: %s", err
            )
            raise DatabaseError(f"Failed to lookup challenge keyauthorization: {err}")

    def get_challenge_by_name(
        self, name: str, vlist: Optional[List[str]] = None
    ) -> Optional[ChallengeInfo]:
        """Get challenge information by name."""
        self.logger.debug("DatabaseChallengeRepository.get_challenge_by_name(%s)", name)
        try:
            challenge_dic = self.dbstore.challenge_lookup(
                "name",
                name,
                vlist=(
                    "type",
                    "token",
                    "status__name",
                    "authorization__name",
                    "authorization__type",
                    "authorization__value",
                    "validated",
                ),
            )

            self.logger.debug(
                "DatabaseChallengeRepository.get_challenge_by_name() ended: found challenge %s",
                challenge_dic,
            )
            if not challenge_dic:
                return None
            return ChallengeInfo(
                name=name,
                type=challenge_dic.get("type", ""),
                token=challenge_dic.get("token", ""),
                status=challenge_dic.get("status", "pending"),
                authorization_name=challenge_dic.get("authorization__name", ""),
                authorization_type=challenge_dic.get("authorization__type", ""),
                authorization_value=challenge_dic.get("authorization__value", ""),
                url="",  # Will be constructed later
                validated=uts_to_date_utc(challenge_dic.get("validated"))
                if challenge_dic.get("status") == "valid"
                else None,
            )
        except Exception as err:
            self.logger.critical("Database error: failed to lookup challenge: %s", err)
            raise DatabaseError(f"Failed to lookup challenge: {err}")

    def create_challenge(self, request: ChallengeCreationRequest) -> Optional[str]:
        """Create a new challenge and return its name."""
        self.logger.debug("DatabaseChallengeRepository.create_challenge(%s)", request)
        try:
            challenge_name = generate_random_string(self.logger, 12)
            data_dic = {
                "name": challenge_name,
                "expires": uts_now() + self.expiry,
                # "expires": request.expires if request.expires else uts_now() + self.expiry,
                "type": request.challenge_type,
                "token": request.token,
                "authorization": request.authorization_name,
                "status": 2,  # pending
            }

            # Handle special challenge types
            if request.challenge_type == "email-reply-00":
                token1 = generate_random_string(self.logger, 32)
                data_dic["keyauthorization"] = token1
                # Email sending would be handled elsewhere
            elif request.challenge_type == "sectigo-email-01":
                data_dic["status"] = 5  # valid

            chid = self.dbstore.challenge_add(
                request.value, request.challenge_type, data_dic
            )
            self.logger.debug(
                "DatabaseChallengeRepository.create_challenge() ended: created challenge %s/%s",
                challenge_name,
                chid,
            )
            return challenge_name if chid else None

        except Exception as err:
            self.logger.critical("Database error: failed to add new challenge: %s", err)
            raise DatabaseError(f"Failed to create challenge: {err}")

    def update_challenge(self, request: ChallengeUpdateRequest) -> bool:
        """Update an existing challenge."""
        self.logger.debug(
            "DatabaseChallengeRepository.update_challenge(%s)", request.name
        )
        try:
            data_dic = {"name": request.name}

            if request.status:
                data_dic["status"] = request.status
            if request.source:
                data_dic["source"] = request.source
            if request.validated:
                data_dic["validated"] = request.validated
            if request.keyauthorization:
                data_dic["keyauthorization"] = request.keyauthorization

            self.dbstore.challenge_update(data_dic)
            self.logger.debug(
                "DatabaseChallengeRepository.update_challenge() ended: updated challenge %s",
                request.name,
            )
            return True
        except Exception as err:
            self.logger.critical("Database error: failed to update challenge: %s", err)
            raise DatabaseError(f"Failed to update challenge: {err}")

    def update_authorization_status(self, challenge_name: str, status: str) -> bool:
        """Update authorization status based on challenge."""
        self.logger.debug(
            "DatabaseChallengeRepository.update_authorization_status(%s, %s)",
            challenge_name,
            status,
        )
        try:
            result = False
            # Get authorization name from challenge
            authz_info = self.dbstore.challenge_lookup(
                "name", challenge_name, ["authorization__name"]
            )

            if authz_info and "authorization" in authz_info:
                data_dic = {"name": authz_info["authorization"], "status": status}
                self.dbstore.authorization_update(data_dic)
                result = True

            self.logger.debug(
                "DatabaseChallengeRepository.update_authorization_status() ended: updated authorization for challenge %s/%s",
                challenge_name,
                result,
            )
            return result

        except Exception as err:
            self.logger.critical(
                "Database error: failed to update authorization: %s", err
            )
            raise DatabaseError(f"Failed to update authorization: {err}")

    def get_account_jwk(self, challenge_name: str) -> Optional[Dict[str, Any]]:
        """Get JWK for the account associated with the challenge."""
        self.logger.debug(
            "DatabaseChallengeRepository.get_account_jwk(%s)", challenge_name
        )
        try:
            challenge_dic = self.dbstore.challenge_lookup(
                "name", challenge_name, ["authorization__order__account__name"]
            )
            result = None
            if challenge_dic and "authorization__order__account__name" in challenge_dic:
                result = self.dbstore.jwk_load(
                    challenge_dic["authorization__order__account__name"]
                )
            self.logger.debug(
                "DatabaseChallengeRepository.get_account_jwk() ended: retrieved JWK for challenge %s/%s",
                challenge_name,
                result,
            )
            return result
        except Exception as err:
            self.logger.critical("Database error: failed to get account JWK: %s", err)
            raise DatabaseError(f"Failed to get account JWK: {err}")


class Challenge:
    """Challenge Class - Refactored for Clarity and Maintainability"""

    def __init__(
        self,
        debug: bool = False,
        srv_name: str = None,
        logger=None,
        source: str = None,
        expiry: int = 3600,
    ):
        """Initialize the refactored challenge handler."""
        self.logger = logger
        self.config = ChallengeConfiguration()
        self.expiry = expiry
        self.server_name = srv_name
        self.path_dic = {"chall_path": "/acme/chall/", "authz_path": "/acme/authz/"}
        self.source_address = source

        # Initialize core components
        self.dbstore = DBstore(debug, self.logger)
        self.message = Message(debug, self.server_name, self.logger)

        # Initialize error message dictionary for error responses
        self.err_msg_dic = error_dic_get(self.logger)
        # Initialize error handler
        self.error_handler = ErrorHandler(self.logger)

        # class containing all database operations
        self.repository = DatabaseChallengeRepository(self.dbstore, self.logger)
        # class managing challenge state transitions
        self.state_manager = ChallengeStateManager(self.repository, self.logger)
        # class creating and managing the different challenges
        self.factory = ChallengeFactory(
            self.repository,
            self.logger,
            self.server_name,
            self.path_dic["chall_path"],
            self.config.email_address,
        )
        self.service = ChallengeService(
            self.repository, self.state_manager, self.factory, self.logger
        )

        # Initialize validation components
        self.validator_registry = None

    def __enter__(self):
        """Context manager entry."""
        self._load_configuration()
        return self

    def __exit__(self, *args):
        """Context manager exit."""
        pass

    def _create_error_response(
        self, code: int, message: str, detail: str
    ) -> Dict[str, str]:
        """Create standardized error response."""
        self.logger.debug("Challenge._create_error_response() called")
        status_dic = {"code": code, "type": message, "detail": detail}
        return self.message.prepare_response({}, status_dic)

    def _create_success_response(self, response_dic: Dict[str, Any]) -> Dict[str, str]:
        """Create standardized success response."""
        self.logger.debug("Challenge._create_success_response() called")
        status_dic = {"code": 200, "type": None, "detail": None}
        return self.message.prepare_response(response_dic, status_dic)

    def _execute_challenge_validation(
        self, challenge_name: str, payload: Dict[str, str]
    ) -> ValidationResult:
        """Execute challenge validation using registry."""
        self.logger.debug("Challenge._execute_challenge_validation(%s)", challenge_name)

        # Get challenge details for validation
        challenge_details = self._get_challenge_validation_details(challenge_name)
        if not challenge_details:
            raise ValidationError("Could not retrieve challenge details for validation")

        challenge_type = challenge_details["type"]

        # Check if challenge type is supported
        if not self.validator_registry.is_supported(challenge_type):
            raise UnsupportedChallengeTypeError(
                challenge_type, self.validator_registry.get_supported_types()
            )

        # Create validation context
        context = ChallengeContext(
            challenge_name=challenge_name,
            token=challenge_details["token"],
            jwk_thumbprint=challenge_details["jwk_thumbprint"],
            keyauthorization=challenge_details["keyauthorization"],
            authorization_type=challenge_details["authorization_type"],
            authorization_value=challenge_details["authorization_value"],
            dns_servers=self.config.dns_server_list,
            proxy_servers=self.config.proxy_server_list,
            timeout=self.config.validation_timeout,
        )

        # Perform validation with retry logic for DNS challenges
        return self._perform_validation_with_retry(challenge_type, context)

    def _extract_challenge_name_from_url(self, url: str) -> str:
        """Extract challenge name from URL."""
        self.logger.debug("Challenge._extract_challenge_name_from_url(%s)", url)
        url_dic = parse_url(self.logger, url)
        challenge_name = url_dic["path"].replace(self.path_dic["chall_path"], "")
        if "/" in challenge_name:
            (challenge_name, _suffix) = challenge_name.split("/", 1)
        return challenge_name

    def _get_challenge_validation_details(
        self, challenge_name: str
    ) -> Optional[Dict[str, str]]:
        """Get all details needed for challenge validation."""
        self.logger.debug(
            "Challenge._get_challenge_validation_details(%s)", challenge_name
        )
        try:
            challenge_dic = self.dbstore.challenge_lookup(
                "name",
                challenge_name,
                [
                    "type",
                    "status__name",
                    "token",
                    "keyauthorization",
                    "authorization__name",
                    "authorization__type",
                    "authorization__value",
                    "authorization__token",
                    "authorization__order__account__name",
                ],
            )

            if not challenge_dic:
                return None

            # Get JWK for thumbprint calculation
            pub_key = self.repository.get_account_jwk(challenge_name)
            if not pub_key:
                return None

            jwk_thumbprint = jwk_thumbprint_get(self.logger, pub_key)
            self.logger.debug("Challenge._get_challenge_validation_details() ended")
            return {
                "type": challenge_dic["type"],
                "token": challenge_dic["token"],
                "authorization_type": challenge_dic["authorization__type"],
                "authorization_value": challenge_dic["authorization__value"],
                "jwk_thumbprint": jwk_thumbprint,
                "keyauthorization": challenge_dic["keyauthorization"],
            }

        except Exception as err:
            self.logger.error("Failed to get challenge validation details: %s", err)
            self.logger.debug(
                "Challenge._get_challenge_validation_details() ended with error"
            )
            return None

    def _handle_challenge_validation_request(
        self,
        code: int,
        payload: Dict[str, str],
        protected: Dict[str, str],
        challenge_name: str,
        challenge_info: ChallengeInfo,
    ) -> Dict[str, str]:
        """Handle challenge validation request with improved flow."""
        self.logger.debug(
            "Challenge._handle_challenge_validation_request(%s)", challenge_name
        )
        # Check tnauthlist payload if needed
        if self.config.tnauthlist_support:
            tnauthlist_result = self._validate_tnauthlist_payload(
                payload, challenge_info
            )
            if tnauthlist_result["code"] != 200:
                return tnauthlist_result

        # Start validation if challenge is not already valid or processing
        if challenge_info.status not in ("valid", "processing"):
            self._start_async_validation(challenge_name, payload)

        # Get updated challenge info
        updated_challenge_info = self.repository.get_challenge_by_name(challenge_name)

        # Prepare response
        response_dic = {
            "data": {
                "type": updated_challenge_info.type,
                "status": updated_challenge_info.status,
                "token": updated_challenge_info.token,
                "url": protected["url"],
            },
            "header": {
                "Link": f'<{self.server_name}{self.path_dic["authz_path"]}>;rel="up"'
            },
        }

        if (
            updated_challenge_info.type == "email-reply-00"
            and self.config.email_address
        ):
            # add from address in response for email challenges
            response_dic["data"]["from"] = self.config.email_address

        # add validated flag if challenge is valid
        if (
            updated_challenge_info.validated
            and updated_challenge_info.status == "valid"
        ):
            response_dic["data"]["validated"] = updated_challenge_info.validated

        self.logger.debug("Challenge._handle_challenge_validation_request() ended")
        return self._create_success_response(response_dic)

    def _handle_validation_disabled(self, challenge_name: str) -> bool:
        """Handle validation when it's disabled."""
        self.logger.debug("Challenge._handle_validation_disabled(%s)", challenge_name)
        if self.config.forward_address_check or self.config.reverse_address_check:
            # Perform source address checks even when validation is disabled
            challenge_check, invalid = self._perform_source_address_validation(
                challenge_name
            )
        else:
            self.logger.warning(
                "Source address checks are disabled. Setting challenge status to valid. "
                "This is not recommended as this is a severe security risk!"
            )
            challenge_check = True
            invalid = False

        if invalid:
            self.state_manager.transition_to_invalid(
                challenge_name, self.source_address
            )
        elif challenge_check:
            self.state_manager.transition_to_valid(
                challenge_name, self.source_address, uts_now()
            )
        self.logger.debug(
            "Challenge._handle_validation_disabled() ended with: %s", challenge_check
        )
        return challenge_check

    def _load_address_check_configuration(self, config_dic: Dict[str, str]):
        """Load address check configuration."""
        self.logger.debug("Challenge._load_address_check_configuration()")

        self.config.validation_disabled = config_dic.getboolean(
            "Challenge", "challenge_validation_disable", fallback=False
        )
        if "source_address_check" in config_dic["Challenge"]:
            self.logger.warning(
                "source_address_check is deprecated, please use forward_address_check instead"
            )
            self.config.forward_address_check = config_dic.getboolean(
                "Challenge", "source_address_check", fallback=False
            )
        else:
            self.config.forward_address_check = config_dic.getboolean(
                "Challenge", "forward_address_check", fallback=False
            )
        self.config.reverse_address_check = config_dic.getboolean(
            "Challenge", "reverse_address_check", fallback=False
        )
        self.logger.debug("Challenge._load_address_check_configuration() ended")

    def _load_dns_configuration(self, config_dic: Dict[str, str]):
        """load dns config"""
        self.logger.debug("Challenge._load_dns_configuration()")

        if "Challenge" in config_dic and "dns_server_list" in config_dic["Challenge"]:
            try:
                self.config.dns_server_list = json.loads(
                    config_dic["Challenge"]["dns_server_list"]
                )
            except Exception as err_:
                self.logger.warning(
                    "Failed to load dns_server_list from configuration: %s",
                    err_,
                )
        if (
            "Challenge" in config_dic
            and "dns_validation_pause_timer" in config_dic["Challenge"]
        ):
            try:
                self.config.dns_validation_pause_timer = int(
                    config_dic["Challenge"]["dns_validation_pause_timer"]
                )
            except Exception as err_:
                self.logger.warning(
                    "Failed to parse dns_validation_pause_timer from configuration: %s",
                    err_,
                )

        self.logger.debug("Challenge._load_dns_configuration() ended")

    def _load_proxy_configuration(self, config_dic: Dict[str, str]):
        """load proxy config"""
        self.logger.debug("Challenge._load_proxy_configuration()")

        if "DEFAULT" in config_dic and "proxy_server_list" in config_dic["DEFAULT"]:
            try:
                self.proxy_server_list = json.loads(
                    config_dic["DEFAULT"]["proxy_server_list"]
                )
            except Exception as err_:
                self.logger.warning(
                    "Failed to load proxy_server_list from configuration: %s",
                    err_,
                )

        self.logger.debug("Challenge._load_proxy_configuration() ended")

    def _load_configuration(self):
        """Load configuration from file."""
        self.logger.debug("Challenge._load_configuration()")

        config_dic = load_config(self.logger, "Challenge")
        if config_dic:

            try:
                self.config.validation_timeout = int(
                    config_dic.get(
                        "Challenge",
                        "challenge_validation_timeout",
                        fallback=self.config.validation_timeout,
                    )
                )
            except Exception as err_:
                self.logger.warning(
                    "Failed to parse challenge_validation_timeout from configuration: %s",
                    err_,
                )

            self._load_dns_configuration(config_dic)
            self._load_proxy_configuration(config_dic)
            self._load_address_check_configuration(config_dic)

            self.config.sectigo_sim = config_dic.getboolean(
                "Challenge", "sectigo_sim", fallback=False
            )
            self.config.tnauthlist_support = config_dic.getboolean(
                "Order", "tnauthlist_support", fallback=False
            )
            self.config.email_identifier_support = config_dic.getboolean(
                "Order", "email_identifier_support", fallback=False
            )
            if self.config.email_identifier_support:
                if "DEFAULT" in config_dic and "email_address" in config_dic["DEFAULT"]:
                    self.config.email_address = config_dic["DEFAULT"].get(
                        "email_address"
                    )
                else:
                    self.logger.warning(
                        "Email identifier support is enabled but no email address is configured. Disabling email identifier support."
                    )
                    self.config.email_identifier_support = False

            if "Directory" in config_dic and "url_prefix" in config_dic["Directory"]:
                self.path_dic = {
                    k: config_dic["Directory"]["url_prefix"] + v
                    for k, v in self.path_dic.items()
                }

            # load profiling
            (
                self.config.eab_profiling,
                self.config.eab_handler,
            ) = config_eab_profile_load(self.logger, config_dic)
            # create validator registry
            self.validator_registry = create_challenge_validator_registry(
                self.logger, self.config
            )

        self.logger.debug("Challenge._load_configuration() ended")

    def _perform_challenge_validation(
        self, challenge_name: str, payload: Dict[str, str]
    ) -> bool:
        """Perform complete challenge validation process."""
        self.logger.debug("Challenge._perform_challenge_validation(%s)", challenge_name)
        try:
            # Transition to processing state
            self.state_manager.transition_to_processing(challenge_name)

            # Check if validation is disabled
            if self.config.validation_disabled:
                self.logger.warning("Challenge validation is globally disabled.")
                return self._handle_validation_disabled(challenge_name)

            # Perform actual validation
            validation_result = self._execute_challenge_validation(
                challenge_name, payload
            )
            result = self._update_challenge_state_from_validation(
                challenge_name, validation_result
            )

        except Exception as err:
            error_detail = self.error_handler.handle_error(
                err, context={"challenge_name": challenge_name}
            )

            # Mark challenge as invalid on error
            self.state_manager.transition_to_invalid(
                challenge_name, self.source_address
            )
            self.logger.debug(
                "Challenge._perform_challenge_validation() ended with error"
            )
            result = False

        # Update challenge state based on result
        self.logger.debug(
            "Challenge._perform_challenge_validation() ended with: %s", result
        )
        return result

    def _perform_source_address_validation(
        self, challenge_name: str
    ) -> Tuple[bool, bool]:
        """Perform source address validation checks using the validator registry."""
        self.logger.debug(
            "Challenge._perform_source_address_validation(%s)", challenge_name
        )

        # If no address checking is configured, skip validation
        if not (self.config.forward_address_check or self.config.reverse_address_check):
            self.logger.debug("Source address validation disabled")
            return True, False

        challenge_info = self.repository.get_challenge_by_name(challenge_name)
        self.logger.debug(
            "Challenge._perform_source_address_validation() found: %s", challenge_info
        )

        if not challenge_info:
            self.logger.error("Challenge not found: %s", challenge_name)
            return False, True

        # Create challenge context for source address validation
        try:
            from .challenge_validators import ChallengeContext

            context = ChallengeContext(
                challenge_name=challenge_name,
                token=challenge_info.token,
                jwk_thumbprint="",  # Not needed for source validation
                authorization_type="dns",  # Default, will be determined from challenge
                authorization_value=challenge_info.authorization_value,
                source_address=self.source_address,
                dns_servers=self.config.dns_server_list,
                timeout=self.config.validation_timeout,
            )

            # Use the source address validator from registry
            if self.validator_registry.is_supported("source-address"):
                result = self.validator_registry.validate_challenge(
                    "source-address", context
                )

                if result.success:
                    self.logger.debug(
                        "Source address validation passed for %s", challenge_name
                    )
                    return True, False
                else:
                    self.logger.warning(
                        "Source address validation failed for %s: %s",
                        challenge_name,
                        result.error_message,
                    )
                    return False, result.invalid
            else:
                self.logger.warning("Source address validator not available")
                return True, False  # Don't fail if validator not available

        except Exception as e:
            self.logger.error(
                "Source address validation error for %s: %s", challenge_name, str(e)
            )
            return False, True

    def _perform_validation_with_retry(
        self, challenge_type: str, context: ChallengeContext
    ) -> ValidationResult:
        """Perform validation with retry logic for certain challenge types."""

        retry_challenge_types = ["dns-01", "email-reply-00"]
        max_attempts = 5 if challenge_type in retry_challenge_types else 1

        for attempt in range(max_attempts):
            result = self.validator_registry.validate_challenge(challenge_type, context)

            # Break if successful or definitely invalid
            if result.success or result.invalid:
                break

            # Sleep before retry for certain challenge types
            if challenge_type in retry_challenge_types and attempt < max_attempts - 1:
                time.sleep(self.config.dns_validation_pause_timer)

        return result

    def _start_async_validation(self, challenge_name: str, payload: Dict[str, str]):
        """Start asynchronous challenge validation."""
        self.logger.debug("Challenge._start_async_validation(%s)", challenge_name)
        twrv = ThreadWithReturnValue(
            target=self._perform_challenge_validation, args=(challenge_name, payload)
        )
        twrv.start()
        _validation = twrv.join(timeout=self.config.validation_timeout)

    def _update_challenge_state_from_validation(
        self, challenge_name: str, validation_result: ValidationResult
    ) -> bool:
        """Update challenge state based on validation result."""

        if validation_result.invalid:
            self.state_manager.transition_to_invalid(
                challenge_name, self.source_address
            )
            return False
        elif validation_result.success:
            self.state_manager.transition_to_valid(
                challenge_name, self.source_address, uts_now()
            )
            return True
        else:
            # Validation inconclusive - keep in processing state
            return False

    def _validate_tnauthlist_payload(
        self, payload: Dict[str, str], challenge_info: ChallengeInfo
    ) -> Dict[str, str]:
        """Validate tnauthlist payload."""
        self.logger.debug("Challenge._validate_tnauthlist_payload()")
        if challenge_info.type == "tkauth-01":
            if "atc" not in payload:
                self.logger.error(
                    "TNauthlist payload validation failed. atc claim is missing"
                )
                return self._create_error_response(
                    400, self.err_msg_dic["malformed"], "atc claim is missing"
                )
            if not payload["atc"]:
                self.logger.error(
                    "TNauthlist payload validation failed. SPC token is missing"
                )
                return self._create_error_response(
                    400, self.err_msg_dic["malformed"], "SPC token is missing"
                )

        return {"code": 200}

    # === Public Implementation Methods ===

    def process_challenge_request(self, content: str) -> Dict[str, str]:
        """Process challenge request (replaces parse)."""
        self.logger.debug("Challenge.process_challenge_request()")

        try:
            # Check message format
            (
                code,
                message,
                detail,
                protected,
                payload,
                _account_name,
            ) = self.message.check(content)

            if code != 200:
                return self._create_error_response(code, message, detail)

            if "url" not in protected:
                return self._create_error_response(
                    400,
                    self.err_msg_dic["malformed"],
                    "url missing in protected header",
                )

            challenge_name = self._extract_challenge_name_from_url(protected["url"])
            if not challenge_name:
                return self._create_error_response(
                    400, self.err_msg_dic["malformed"], "could not get challenge"
                )

            challenge_info = self.repository.get_challenge_by_name(challenge_name)
            if not challenge_info:
                return self._create_error_response(
                    400,
                    self.err_msg_dic["malformed"],
                    f"invalid challenge: {challenge_name}",
                )

            return self._handle_challenge_validation_request(
                code, payload, protected, challenge_name, challenge_info
            )

        except Exception as err:
            error_detail = self.error_handler.handle_error(err)
            return self.error_handler.create_acme_error_response(error_detail, 500)

    def retrieve_challenge_set(
        self,
        authz_name: str,
        auth_status: str,
        token: str,
        tnauth: bool,
        id_type: str = "dns",
        id_value: str = None,
    ) -> List[Dict[str, str]]:
        """Retrieve existing or create new challenge set (replaces challengeset_get)."""
        self.logger.debug(
            "Challenge.retrieve_challenge_set() for auth: %s:%s", authz_name, id_value
        )
        result = []
        try:
            result = self.service.get_challenge_set_for_authorization(
                authorization_name=authz_name,
                token=token,
                id_type=id_type,
                id_value=id_value,
                config=self.config,
                url=f"{self.server_name}{self.path_dic['chall_path']}",
            )
        except Exception as err:
            error_detail = self.error_handler.handle_error(err)
            self.logger.error(
                "Failed to retrieve challenge set: %s", error_detail.message
            )

        self.logger.debug(
            "Challenge.retrieve_challenge_set() ended with %d challenges", len(result)
        )
        return result

    # === Legacy API Compatibility ===

    def challengeset_get(self, *args, **kwargs) -> List[Dict[str, str]]:
        """Legacy API compatibility - use retrieve_challenge_set instead."""
        self.logger.debug("Challenge.challengeset_get() called - legacy API")
        return self.retrieve_challenge_set(*args, **kwargs)

    def parse(self, content: str) -> Dict[str, str]:
        """Legacy API compatibility - use process_challenge_request instead."""
        self.logger.debug("Challenge.parse() called - legacy API")
        return self.process_challenge_request(content)
