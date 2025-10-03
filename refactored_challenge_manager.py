"""
Challenge Manager - Main Orchestrator for Refactored Challenge System
"""

import json
import time
from typing import Dict, List, Optional, Tuple

from refactored_challenge_models import (
    ChallengeData, ChallengeConfiguration, ValidationContext, ValidationResult,
    ChallengeType, ChallengeStatus, IdentifierType, ChallengeIdentifier,
    ChallengeError, ChallengeNotFoundError, ChallengeValidationError
)
from refactored_challenge_processors import ChallengeProcessorFactory
from refactored_challenge_repository import ChallengeRepository, NetworkValidator, ConfigurationManager

from acme_srv.db_handler import DBstore
from acme_srv.message import Message
from acme_srv.helper import (
    generate_random_string, jwk_thumbprint_get, uts_now, uts_to_date_utc,
    parse_url, error_dic_get, config_eab_profile_load
)
from acme_srv.threadwithreturnvalue import ThreadWithReturnValue


class ChallengeWorkflowManager:
    """Main orchestrator for challenge operations"""

    def __init__(self, debug: bool = False, srv_name: str = None,
                 logger=None, source: str = None, expiry: int = 3600):
        self.logger = logger
        self.server_name = srv_name
        self.source_address = source
        self.expiry = expiry
        self.path_dict = {"chall_path": "/acme/chall/", "authz_path": "/acme/authz/"}

        # Initialize components
        self.dbstore = DBstore(debug, self.logger)
        self.message = Message(debug, self.server_name, self.logger)
        self.err_msg_dict = error_dic_get(self.logger)

        # Load configuration
        self.config_manager = ConfigurationManager(self.logger)
        self.config = self.config_manager.load_configuration()

        # Initialize other components
        self.repository = ChallengeRepository(self.dbstore, self.logger)
        self.network_validator = NetworkValidator(self.logger, self.config)
        self.processor_factory = ChallengeProcessorFactory(self.logger, self.config)

        # Load EAB configuration
        config_dict = self._load_raw_config()
        self.eab_profiling, self.eab_handler = config_eab_profile_load(self.logger, config_dict)

    def __enter__(self):
        """Context manager entry"""
        return self

    def __exit__(self, *args):
        """Context manager exit"""
        pass

    def get_challenge_info(self, url: str) -> Dict[str, str]:
        """Get challenge information for GET request"""
        challenge_name = self._extract_challenge_name_from_url(url)
        self.logger.debug(f"ChallengeManager.get_challenge_info({challenge_name})")

        try:
            challenge_data = self.repository.find_by_name(challenge_name)
            if not challenge_data:
                raise ChallengeNotFoundError(f"Challenge not found: {challenge_name}")

            # Convert to response format
            response_data = self._convert_challenge_to_response(challenge_data)

            return {"code": 200, "data": response_data}

        except ChallengeError as e:
            self.logger.error(f"Challenge error: {e}")
            return {"code": 404, "data": {}}
        except Exception as e:
            self.logger.error(f"Unexpected error getting challenge info: {e}")
            return {"code": 500, "data": {}}

    def process_challenge_request(self, content: str) -> Dict[str, str]:
        """Process challenge validation request"""
        self.logger.debug("ChallengeManager.process_challenge_request()")

        try:
            # Parse and validate message
            code, message, detail, protected, payload, _ = self.message.check(content)

            if code != 200:
                return self._create_error_response(code, message, detail)

            # Extract challenge name from URL
            if "url" not in protected:
                return self._create_error_response(
                    400, self.err_msg_dict["malformed"], "URL missing in protected header"
                )

            challenge_name = self._extract_challenge_name_from_url(protected["url"])
            if not challenge_name:
                return self._create_error_response(
                    400, self.err_msg_dict["malformed"], "Could not extract challenge name"
                )

            # Get challenge data
            challenge_data = self.repository.find_by_name(challenge_name)
            if not challenge_data:
                return self._create_error_response(
                    400, self.err_msg_dict["malformed"], f"Invalid challenge: {challenge_name}"
                )

            # Process challenge
            code, message, detail, response_data = self._execute_challenge_workflow(
                challenge_data, payload, protected
            )

            # Prepare response
            status_dict = {"code": code, "type": message, "detail": detail}
            response_dict = {"data": response_data, "header": {}}
            if code == 200:
                response_dict["header"]["Link"] = f'<{self.server_name}{self.path_dict["authz_path"]}>;rel="up"'

            return self.message.prepare_response(response_dict, status_dict)

        except Exception as e:
            self.logger.error(f"Unexpected error processing challenge request: {e}")
            return self._create_error_response(500, "Internal server error", str(e))

    def create_challenge_set(self, authorization_name: str, token: str,
                           tnauth: bool = False, identifier_type: str = "dns",
                           identifier_value: str = None) -> List[Dict[str, str]]:
        """Create a new set of challenges for an authorization"""
        self.logger.debug(f"ChallengeManager.create_challenge_set({authorization_name}, {identifier_value})")

        challenge_list = []

        try:
            # Determine challenge types to create
            if tnauth:
                challenge_list.append(self._create_single_challenge(
                    authorization_name, "tkauth-01", token, identifier_value
                ))
            elif self.config.sectigo_simulation:
                challenge_list.append(self._create_single_challenge(
                    authorization_name, "sectigo-email-01", token, identifier_value
                ))
            elif self._should_create_email_reply_challenge(identifier_type, identifier_value):
                challenge_list.append(self._create_single_challenge(
                    authorization_name, "email-reply-00", token, identifier_value
                ))
            else:
                # Create standard challenges
                challenge_types = self._get_standard_challenge_types(identifier_type)
                for challenge_type in challenge_types:
                    challenge_json = self._create_single_challenge(
                        authorization_name, challenge_type, token, identifier_value
                    )
                    if challenge_json:
                        challenge_list.append(challenge_json)

        except Exception as e:
            self.logger.error(f"Error creating challenge set: {e}")
            raise ChallengeError(f"Failed to create challenge set: {e}")

        self.logger.debug(f"ChallengeManager.create_challenge_set() returned {len(challenge_list)} challenges")
        return challenge_list

    def get_existing_challenges(self, authorization_name: str, _auth_status: str,
                              token: str, tnauth: bool, identifier_type: str = "dns",
                              identifier_value: str = None) -> List[Dict[str, str]]:
        """Get existing challenges for an authorization"""
        self.logger.debug(f"ChallengeManager.get_existing_challenges({authorization_name})")

        try:
            challenge_data_list = self.repository.find_by_authorization(authorization_name)

            if challenge_data_list:
                # Convert to response format
                challenge_list = []
                for challenge_data in challenge_data_list:
                    challenge_json = self._convert_challenge_to_response(challenge_data)
                    challenge_json["url"] = f"{self.server_name}{self.path_dict['chall_path']}{challenge_data.name}"
                    challenge_list.append(challenge_json)
                return challenge_list
            else:
                # Create new challenges
                return self.create_challenge_set(
                    authorization_name, token, tnauth, identifier_type, identifier_value
                )

        except Exception as e:
            self.logger.error(f"Error getting existing challenges: {e}")
            raise ChallengeError(f"Failed to get challenges: {e}")

    def _execute_challenge_workflow(self, challenge_data: ChallengeData,
                                   payload: Dict[str, str], protected: Dict[str, str]) -> Tuple[int, str, str, Dict]:
        """Execute the main challenge validation workflow"""
        try:
            # Validate tnauthlist payload if needed
            if self.config.tnauthlist_support:
                code, message, detail = self._validate_tnauthlist_payload(payload, challenge_data)
                if code != 200:
                    return code, message, detail, {}

            # Start validation if challenge is not already valid/processing
            if challenge_data.status not in (ChallengeStatus.VALID, ChallengeStatus.PROCESSING):
                self._start_validation_thread(challenge_data.name, payload)
                # Refresh challenge data after validation
                challenge_data = self.repository.find_by_name(challenge_data.name)

            # Prepare response
            response_data = self._convert_challenge_to_response(challenge_data)
            response_data["url"] = protected["url"]

            return 200, None, None, response_data

        except Exception as e:
            self.logger.error(f"Error executing challenge workflow: {e}")
            return 500, "Internal server error", str(e), {}

    def _start_validation_thread(self, challenge_name: str, payload: Dict[str, str]):
        """Start challenge validation in a separate thread"""
        thread = ThreadWithReturnValue(
            target=self._validate_challenge, args=(challenge_name, payload)
        )
        thread.start()
        thread.join(timeout=self.config.validation_timeout)

    def _validate_challenge(self, challenge_name: str, payload: Dict[str, str]) -> bool:
        """Main challenge validation method"""
        self.logger.debug(f"ChallengeManager._validate_challenge({challenge_name})")

        try:
            # Update status to processing
            challenge_data = self.repository.find_by_name(challenge_name)
            if not challenge_data:
                return False

            challenge_data.status = ChallengeStatus.PROCESSING
            self.repository.save(challenge_data)

            # Check if validation is disabled
            validation_disabled = self._is_validation_disabled(challenge_name)

            if validation_disabled:
                validation_result = self._handle_disabled_validation(challenge_data)
            else:
                validation_result = self._perform_actual_validation(challenge_data, payload)

            # Update challenge based on result
            self._update_challenge_from_result(challenge_data, validation_result, payload)

            return validation_result.success

        except Exception as e:
            self.logger.error(f"Error validating challenge: {e}")
            self._mark_challenge_invalid(challenge_name, str(e))
            return False

    def _perform_actual_validation(self, challenge_data: ChallengeData,
                                 payload: Dict[str, str]) -> ValidationResult:
        """Perform the actual challenge validation"""
        try:
            # Get JWK and compute thumbprint
            jwk = self.repository.get_jwk_for_challenge(challenge_data.name)
            if not jwk:
                return ValidationResult(success=False, invalid=True,
                                      error_message="Could not get JWK")

            challenge_data.jwk_thumbprint = jwk_thumbprint_get(self.logger, jwk)

            # Create validation context
            context = ValidationContext(
                challenge_data=challenge_data,
                payload=payload,
                dns_server_list=self.config.dns_server_list,
                proxy_server_list=self.config.proxy_server_list,
                timeout=self.config.validation_timeout,
                source_address=self.source_address
            )

            # Get processor and validate
            processor = self.processor_factory.create_processor(challenge_data.type.value)

            # Retry logic for DNS and email challenges
            retry_types = ["dns-01", "email-reply-00"]
            max_retries = 5 if challenge_data.type.value in retry_types else 1

            for attempt in range(max_retries):
                result = processor.process(context)

                if result.success or result.invalid:
                    break
                elif challenge_data.type.value in retry_types and attempt < max_retries - 1:
                    time.sleep(self.config.dns_validation_pause_timer)

            return result

        except Exception as e:
            self.logger.error(f"Error performing validation: {e}")
            return ValidationResult(success=False, invalid=True, error_message=str(e))

    def _handle_disabled_validation(self, challenge_data: ChallengeData) -> ValidationResult:
        """Handle validation when it's disabled"""
        if self.config.forward_address_check or self.config.reverse_address_check:
            return self._perform_source_address_validation(challenge_data)
        else:
            self.logger.warning("Validation disabled and no source address checks - security risk!")
            return ValidationResult(success=True, invalid=False)

    def _perform_source_address_validation(self, challenge_data: ChallengeData) -> ValidationResult:
        """Perform source address validation"""
        try:
            success, invalid = self.network_validator.validate_source_address(
                challenge_data, self.source_address
            )
            return ValidationResult(success=success, invalid=invalid)
        except Exception as e:
            self.logger.error(f"Source address validation failed: {e}")
            return ValidationResult(success=False, invalid=True, error_message=str(e))

    def _update_challenge_from_result(self, challenge_data: ChallengeData,
                                    result: ValidationResult, payload: Dict[str, str]):
        """Update challenge based on validation result"""
        if result.invalid:
            challenge_data.status = ChallengeStatus.INVALID
            challenge_data.error_detail = result.error_message
            self.repository.update_authorization_status(challenge_data.name, "invalid")
        elif result.success:
            challenge_data.status = ChallengeStatus.VALID
            challenge_data.validated_at = uts_now()
            self.repository.update_authorization_status(challenge_data.name, "valid")

        # Update key authorization if provided
        if payload and "keyAuthorization" in payload:
            challenge_data.key_authorization = payload["keyAuthorization"]

        self.repository.save(challenge_data)

    def _is_validation_disabled(self, challenge_name: str) -> bool:
        """Check if validation is disabled globally or via EAB profile"""
        if self.config.validation_disabled:
            return True

        if self.eab_profiling and self.eab_handler:
            return self.config_manager.get_eab_challenge_validation_disabled(
                challenge_name, self.eab_handler, self.dbstore
            )

        return False

    def _create_single_challenge(self, authorization_name: str, challenge_type: str,
                               token: str, identifier_value: str = None) -> Optional[Dict[str, str]]:
        """Create a single challenge"""
        challenge_name = self.repository.create(authorization_name, challenge_type, token, identifier_value)

        if challenge_name:
            challenge_dict = {
                "type": challenge_type,
                "url": f"{self.server_name}{self.path_dict['chall_path']}{challenge_name}",
                "token": token,
                "status": "pending"
            }

            # Add type-specific fields
            if challenge_type == "email-reply-00" and self.config.email_address:
                challenge_dict["from"] = self.config.email_address
            elif challenge_type == "tkauth-01":
                challenge_dict["tkauth-type"] = "atc"
            elif challenge_type == "sectigo-email-01":
                challenge_dict["status"] = "valid"
                challenge_dict.pop("token", None)

            return challenge_dict

        return None

    def _should_create_email_reply_challenge(self, identifier_type: str, value: str) -> bool:
        """Determine if email-reply challenge should be created"""
        if not self.config.email_identifier_support:
            return False

        return (identifier_type == "email" or
                (identifier_type == "dns" and value and "@" in value))

    def _get_standard_challenge_types(self, identifier_type: str) -> List[str]:
        """Get standard challenge types for identifier type"""
        challenge_types = ["http-01", "dns-01", "tls-alpn-01"]
        if identifier_type == "ip":
            challenge_types.remove("dns-01")  # DNS challenges not supported for IP identifiers
        return challenge_types

    def _validate_tnauthlist_payload(self, payload: Dict[str, str],
                                   challenge_data: ChallengeData) -> Tuple[int, str, str]:
        """Validate tnauthlist payload"""
        if challenge_data.type == ChallengeType.TKAUTH_01:
            if "atc" not in payload:
                return 400, self.err_msg_dict["malformed"], "atc claim is missing"
            elif not bool(payload["atc"]):
                return 400, self.err_msg_dict["malformed"], "SPC token is missing"

        return 200, None, None

    def _convert_challenge_to_response(self, challenge_data: ChallengeData) -> Dict[str, str]:
        """Convert ChallengeData to response format"""
        response = {
            "type": challenge_data.type.value,
            "token": challenge_data.token,
            "status": challenge_data.status.value
        }

        if challenge_data.status == ChallengeStatus.VALID and challenge_data.validated_at:
            try:
                response["validated"] = uts_to_date_utc(challenge_data.validated_at)
            except Exception:
                pass  # Remove if conversion fails

        if (self.config.email_identifier_support and self.config.email_address and
            challenge_data.type == ChallengeType.EMAIL_REPLY_00):
            response["from"] = self.config.email_address

        return response

    def _extract_challenge_name_from_url(self, url: str) -> str:
        """Extract challenge name from URL"""
        url_dict = parse_url(self.logger, url)
        challenge_name = url_dict["path"].replace(self.path_dict["chall_path"], "")
        if "/" in challenge_name:
            challenge_name = challenge_name.split("/", 1)[0]
        return challenge_name

    def _mark_challenge_invalid(self, challenge_name: str, error_message: str):
        """Mark challenge as invalid with error message"""
        try:
            challenge_data = self.repository.find_by_name(challenge_name)
            if challenge_data:
                challenge_data.status = ChallengeStatus.INVALID
                challenge_data.error_detail = error_message
                self.repository.save(challenge_data)
                self.repository.update_authorization_status(challenge_name, "invalid")
        except Exception as e:
            self.logger.error(f"Failed to mark challenge invalid: {e}")

    def _create_error_response(self, code: int, message: str, detail: str) -> Dict[str, str]:
        """Create error response"""
        status_dict = {"code": code, "type": message, "detail": detail}
        return self.message.prepare_response({}, status_dict)

    def _load_raw_config(self) -> Dict:
        """Load raw configuration dictionary"""
        from acme_srv.helper import load_config
        return load_config()


# Backward compatibility wrapper
class Challenge:
    """Backward compatibility wrapper for existing Challenge class interface"""

    def __init__(self, debug: bool = False, srv_name: str = None,
                 logger=None, source: str = None, expiry: int = 3600):
        self.manager = ChallengeWorkflowManager(debug, srv_name, logger, source, expiry)

    def __enter__(self):
        return self.manager.__enter__()

    def __exit__(self, *args):
        return self.manager.__exit__(*args)

    def get(self, url: str) -> Dict[str, str]:
        """Get challenge details based on GET request"""
        return self.manager.get_challenge_info(url)

    def parse(self, content: str) -> Dict[str, str]:
        """Parse challenge request"""
        return self.manager.process_challenge_request(content)

    def challengeset_get(self, authz_name: str, auth_status: str, token: str,
                        tnauth: bool, id_type: str = "dns", id_value: str = None) -> List[str]:
        """Get challenge set for authorization"""
        return self.manager.get_existing_challenges(
            authz_name, auth_status, token, tnauth, id_type, id_value
        )

    def new_set(self, authz_name: str, token: str, tnauth: bool = False,
               id_type: str = "dns", value: str = None) -> List[str]:
        """Create new challenge set"""
        return self.manager.create_challenge_set(authz_name, token, tnauth, id_type, value)