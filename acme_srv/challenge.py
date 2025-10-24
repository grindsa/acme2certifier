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
# from acme_srv.challenge_validators import (
#    ChallengeValidatorRegistry,
#    ChallengeContext,
#    ValidationResult
# )
from acme_srv.challenge_registry_setup import create_challenge_validator_registry

# from acme_srv.challenge_business_logic import (
#    ChallengeRepository,
#    ChallengeStateManager,
#    ChallengeFactory,
#    ChallengeService,
#    ChallengeInfo,
#    ChallengeCreationRequest,
#    ChallengeUpdateRequest
# )
from acme_srv.challenge_error_handling import (
    ErrorHandler,
    #    ChallengeError,
    #    ValidationError,
    #    DatabaseError,
    #    UnsupportedChallengeTypeError
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

        # Initialize core components
        self.dbstore = DBstore(debug, self.logger)
        self.message = Message(debug, self.server_name, self.logger)

        # Initialize error message dictionary for error responses
        self.err_msg_dic = error_dic_get(self.logger)
        # Initialize error handler
        self.error_handler = ErrorHandler(self.logger)

        # Initialize refactored components
        # self.repository = DatabaseChallengeRepository(self.dbstore, self.logger)
        # self.state_manager = ChallengeStateManager(self.repository, self.logger)
        # self.factory = ChallengeFactory(
        #    self.repository,
        #    self.logger,
        #    self.server_name,
        #    self.path_dic["chall_path"],
        #    self.config.email_address
        # )
        # self.service = ChallengeService(
        #    self.repository,
        #    self.state_manager,
        #    self.factory,
        #    self.logger
        # )

        # Initialize validation components
        self.validator_registry = None

    def __enter__(self):
        """Context manager entry."""
        self._load_configuration()
        return self

    def __exit__(self, *args):
        """Context manager exit."""
        pass

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
            self.forward_address_check = config_dic.getboolean(
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
        try:
            return self.service.get_challenge_set_for_authorization(
                authorization_name=authz_name,
                token=token,
                id_type=id_type,
                id_value=id_value,
                tnauthlist_support=self.config.tnauthlist_support,
                email_identifier_support=self.config.email_identifier_support,
                sectigo_sim=self.config.sectigo_sim,
                url=f"{self.server_name}{self.path_dic['chall_path']}",
            )
        except Exception as err:
            error_detail = self.error_handler.handle_error(err)
            self.logger.error(
                "Failed to retrieve challenge set: %s", error_detail.message
            )
            return []

    # === Legacy API Compatibility ===

    def challengeset_get(self, *args, **kwargs) -> List[Dict[str, str]]:
        """Legacy API compatibility - use retrieve_challenge_set instead."""
        self.logger.debug("Challenge.challengeset_get() called - legacy API")
        return self.retrieve_challenge_set(*args, **kwargs)
