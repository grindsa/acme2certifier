# -*- coding: utf-8 -*-
# pylint: disable=r0902, r0912, r0913, r0915
"""certificate class"""
from __future__ import print_function
import json
from typing import List, Tuple, Dict, Union
from acme_srv.helper import (
    b64_url_recode,
    ca_handler_load,
    cert_aki_get,
    cert_cn_get,
    cert_dates_get,
    cert_extensions_get,
    cert_san_get,
    cert_serial_get,
    certid_asn1_get,
    csr_san_get,
    csr_extensions_get,
    date_to_uts_utc,
    error_dic_get,
    generate_random_string,
    hooks_load,
    load_config,
    pembundle_to_list,
    string_sanitize,
    uts_now,
    uts_to_date_utc,
)
from acme_srv.db_handler import DBstore
from acme_srv.message import Message
from acme_srv.threadwithreturnvalue import ThreadWithReturnValue
from acme_srv.certificate_manager import CertificateManager
from acme_srv.certificate_repository import DatabaseCertificateRepository

# CertificateLogger moved from certificate_logger.py
class CertificateLogger:
    """Handles all certificate operation logging"""

    def __init__(self, logger, cert_operations_log: str, repository):
        """
        Initialize certificate logger

        Args:
            logger: Logger instance for output
            cert_operations_log: Logging format ("json", "text", or "")
            repository: Repository for database operations
        """
        self.logger = logger
        self.cert_operations_log = cert_operations_log
        self.repository = repository

    def log_certificate_issuance(
        self,
        certificate_name: str,
        certificate: str,
        order_name: str,
        cert_reusage: bool = False,
    ):
        """Log certificate issuance"""
        self.logger.debug(
            "CertificateLogger.log_certificate_issuance(%s)", certificate_name
        )

        # Lookup account name and kid
        try:
            order_dic = self.repository.order_lookup(
                "name",
                order_name,
                [
                    "id",
                    "name",
                    "account__name",
                    "account__eab_kid",
                    "profile",
                    "expires",
                    "account__contact",
                ],
            )
        except Exception as err:
            self.logger.error(
                "Database error: failed to get account information for cert issuance log: %s",
                err,
            )
            order_dic = {}

        data_dic = {
            "account_name": order_dic.get("account__name", ""),
            "account_contact": order_dic.get("account__contact", ""),
            "certificate_name": certificate_name,
            "serial_number": cert_serial_get(self.logger, certificate, hexformat=True),
            "common_name": cert_cn_get(self.logger, certificate),
            "san_list": cert_san_get(self.logger, certificate),
        }

        if cert_reusage:
            # Add cert reusage flag if set to true
            data_dic["reused"] = cert_reusage

        if order_dic.get("account__eab_kid", ""):
            # Add kid if existing
            data_dic["eab_kid"] = order_dic.get("account__eab_kid", "")

        if order_dic.get("profile", None):
            # Add profile if existing
            data_dic["profile"] = order_dic.get("profile", "")

        if order_dic.get("expires", ""):
            # add expires if existing
            data_dic["expires"] = uts_to_date_utc(order_dic.get("expires", ""))

        if self.cert_operations_log == "json":
            # Log in json format
            self._log_as_json(data_dic, "Certificate issued")
        else:
            # Log in text format
            self._log_issuance_as_text(certificate_name, data_dic)

        self.logger.debug("CertificateLogger.log_certificate_issuance() ended")

    def log_certificate_revocation(self, certificate: str, code: int):
        """Log certificate revocation"""
        self.logger.debug("CertificateLogger.log_certificate_revocation()")

        if code == 200:
            status = "successful"
        else:
            status = "failed"

        # Lookup account name and kid
        try:
            cert_dic = self.repository.certificate_lookup(
                "cert_raw",
                b64_url_recode(self.logger, certificate),
                [
                    "name",
                    "order__account__name",
                    "order__account__eab_kid",
                    "order__account__contact",
                    "order__profile",
                ],
            )
        except Exception as err:
            self.logger.error(
                "Database error: failed to get account information for cert revocation: %s",
                err,
            )
            cert_dic = {}

        # Construct log message including certificate name
        self.logger.debug(
            "CertificateLogger.log_certificate_revocation(%s)", cert_dic.get("name", "")
        )

        data_dic = {
            "account_name": cert_dic.get("order__account__name", ""),
            "account_contact": cert_dic.get("order__account__contact", ""),
            "certificate_name": cert_dic.get("name", ""),
            "serial_number": cert_serial_get(self.logger, certificate, hexformat=True),
            "common_name": cert_cn_get(self.logger, certificate),
            "profile": cert_dic.get("order__profile", ""),
            "san_list": cert_san_get(self.logger, certificate),
            "status": status,
        }

        if cert_dic.get("order__account__eab_kid", ""):
            data_dic["eab_kid"] = cert_dic.get("order__account__eab_kid")

        if self.cert_operations_log == "json":
            # Log in json format
            self._log_as_json(data_dic, "Certificate revoked")
        else:
            # Log in text format
            self._log_revocation_as_text(data_dic)

        self.logger.debug("CertificateLogger.log_certificate_revocation() ended")

    def _log_as_json(self, data_dic: Dict, operation_type: str):
        """Log data as JSON format"""
        self.logger.info(
            "%s: %s",
            operation_type,
            json.dumps(data_dic, sort_keys=True),
        )

    def _log_issuance_as_text(self, certificate_name: str, data_dic: Dict):
        """Log certificate issuance as text string"""
        log_string = f'Certificate {certificate_name} issued for account {data_dic["account_name"]} {data_dic["account_contact"]}'

        if data_dic.get("eab_kid", ""):
            log_string = log_string + f' with EAB KID {data_dic["eab_kid"]}'

        if data_dic.get("profile", ""):
            log_string = log_string + f' with Profile {data_dic["profile"]}'

        log_string = (
            log_string
            + f'. Serial: {data_dic["serial_number"]}, Common Name: {data_dic["common_name"]}, SANs: {data_dic["san_list"]}, Expires: {data_dic["expires"]}'
        )

        if data_dic.get("reused", ""):
            log_string = log_string + f' reused: {data_dic["reused"]}'

        self.logger.info(log_string)

    def _log_revocation_as_text(self, data_dic: Dict):
        """Log certificate revocation as text string"""
        log_string = f'Certificate {data_dic["certificate_name"]} revocation {data_dic["status"]} for account {data_dic["account_name"]} {data_dic["account_contact"]}'

        if data_dic.get("eab_kid", ""):
            log_string = log_string + f' with EAB KID {data_dic["eab_kid"]}'

        if data_dic.get("profile", ""):
            log_string = log_string + f' with Profile {data_dic["profile"]}'

        log_string = (
            log_string
            + f'. Serial: {data_dic["serial_number"]}, Common Name: {data_dic["common_name"]}, SANs: {data_dic["san_list"]}'
        )

        self.logger.info(log_string)

from dataclasses import dataclass
from typing import Dict, Optional, Any

# CertificateConfig moved from certificate_config.py
@dataclass
class CertificateConfig:
    """
    Configuration dataclass for Certificate operations.

    This centralizes all configuration settings for the Certificate class
    and its components, providing type safety and clear documentation.

    Similar to the pattern used in challenge refactoring.
    """

    # Basic settings
    debug: bool = False
    server_name: Optional[str] = None

    # Certificate processing settings
    cert_operations_log: Optional[Any] = None
    cert_reusage_timeframe: int = 0
    cn2san_add: bool = False
    enrollment_timeout: int = 5

    # Path and URL settings
    path_dic: Optional[Dict[str, str]] = None
    retry_after: int = 600

    # Feature flags
    tnauthlist_support: bool = False

    # Hook configuration
    ignore_pre_hook_failure: bool = False
    ignore_post_hook_failure: bool = True
    ignore_success_hook_failure: bool = False

    def __post_init__(self):
        """Initialize default values that can't be set in field defaults"""
        if self.path_dic is None:
            self.path_dic = {"cert_path": "/acme/cert/"}

    @classmethod
    def from_legacy_params(
        cls, debug: bool = False, srv_name: str = None, **kwargs
    ) -> "CertificateConfig":
        """
        Create configuration from legacy parameters for backward compatibility.

        Args:
            debug: Debug mode flag
            srv_name: Server name
            **kwargs: Additional configuration parameters

        Returns:
            CertificateConfig instance with provided parameters
        """
        return cls(debug=debug, server_name=srv_name, **kwargs)

    @classmethod
    def from_config_file(
        cls, debug: bool = False, srv_name: str = None
    ) -> "CertificateConfig":
        """
        Create configuration by loading from config file.

        Args:
            debug: Debug mode flag
            srv_name: Server name

        Returns:
            CertificateConfig instance with values loaded from config file
        """
        # Load configuration from file
        config_dic = load_config()

        # Extract Certificate section parameters
        cert_reusage_timeframe = 0
        enrollment_timeout = 5
        cert_operations_log = None

        try:
            cert_reusage_timeframe = int(
                config_dic.get(
                    "Certificate",
                    "cert_reusage_timeframe",
                    fallback=cert_reusage_timeframe,
                )
            )
        except Exception:
            pass  # Keep default value

        try:
            enrollment_timeout = int(
                config_dic.get(
                    "Certificate", "enrollment_timeout", fallback=enrollment_timeout
                )
            )
        except Exception:
            pass  # Keep default value

        cert_operations_log = config_dic.get(
            "Certificate", "cert_operations_log", fallback=cert_operations_log
        )
        if cert_operations_log:
            cert_operations_log = cert_operations_log.lower()

        # Extract Order section parameters
        tnauthlist_support = False
        if "Order" in config_dic:
            tnauthlist_support = config_dic.getboolean(
                "Order", "tnauthlist_support", fallback=False
            )

        # Extract CAhandler section parameters
        cn2san_add = False
        if (
            "CAhandler" in config_dic
            and config_dic.get("CAhandler", "handler_file", fallback=None)
            == "examples/ca_handler/asa_ca_handler.py"
        ):
            cn2san_add = True

        # Handle path_dic with url_prefix
        path_dic = {"cert_path": "/acme/cert/"}
        if "Directory" in config_dic and "url_prefix" in config_dic["Directory"]:
            path_dic = {
                k: config_dic["Directory"]["url_prefix"] + v
                for k, v in path_dic.items()
            }

        # Extract Hook section parameters
        ignore_pre_hook_failure = False
        ignore_post_hook_failure = True
        ignore_success_hook_failure = False

        if "Hooks" in config_dic:
            ignore_pre_hook_failure = config_dic.getboolean(
                "Hooks", "ignore_pre_hook_failure", fallback=False
            )
            ignore_post_hook_failure = config_dic.getboolean(
                "Hooks", "ignore_post_hook_failure", fallback=True
            )
            ignore_success_hook_failure = config_dic.getboolean(
                "Hooks", "ignore_success_hook_failure", fallback=False
            )

        return cls(
            debug=debug,
            server_name=srv_name,
            cert_operations_log=cert_operations_log,
            cert_reusage_timeframe=cert_reusage_timeframe,
            cn2san_add=cn2san_add,
            enrollment_timeout=enrollment_timeout,
            path_dic=path_dic,
            tnauthlist_support=tnauthlist_support,
            ignore_pre_hook_failure=ignore_pre_hook_failure,
            ignore_post_hook_failure=ignore_post_hook_failure,
            ignore_success_hook_failure=ignore_success_hook_failure,
        )

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert configuration to dictionary for easy access.

        Returns:
            Dictionary representation of configuration
        """
        return {
            "debug": self.debug,
            "server_name": self.server_name,
            "cert_operations_log": self.cert_operations_log,
            "cert_reusage_timeframe": self.cert_reusage_timeframe,
            "cn2san_add": self.cn2san_add,
            "enrollment_timeout": self.enrollment_timeout,
            "path_dic": self.path_dic,
            "retry_after": self.retry_after,
            "tnauthlist_support": self.tnauthlist_support,
            "ignore_pre_hook_failure": self.ignore_pre_hook_failure,
            "ignore_post_hook_failure": self.ignore_post_hook_failure,
            "ignore_success_hook_failure": self.ignore_success_hook_failure,
        }

    def update(self, **kwargs) -> "CertificateConfig":
        """
        Create a new configuration instance with updated values.

        Args:
            **kwargs: Configuration parameters to update

        Returns:
            New CertificateConfig instance with updated values
        """
        current_dict = self.to_dict()
        current_dict.update(kwargs)
        return CertificateConfig(**current_dict)

    def apply_to_business_logic(self, business_logic) -> None:
        """
        Apply relevant configuration settings to business logic component.

        Args:
            business_logic: CertificateBusinessLogic instance to configure
        """
        business_logic.cert_reusage_timeframe = self.cert_reusage_timeframe
        business_logic.tnauthlist_support = self.tnauthlist_support
        business_logic.cn2san_add = self.cn2san_add

    def apply_to_manager(self, manager) -> None:
        """
        Apply relevant configuration settings to manager component.

        Args:
            manager: CertificateManager instance to configure
        """
        manager.cert_operations_log = self.cert_operations_log
        manager.tnauthlist_support = self.tnauthlist_support


class Certificate(object):
    """CA  handler"""

    def __init__(self, debug: bool = False, srv_name: str = None, logger=None):
        self.debug = debug
        self.logger = logger
        self.server_name = srv_name

        # Create configuration dataclass from config file
        self.config = CertificateConfig.from_config_file(debug=debug, srv_name=srv_name)

        # Core components
        self.dbstore = DBstore(self.debug, self.logger)
        self.repository = DatabaseCertificateRepository(self.dbstore, self.logger)

        # Legacy properties for backward compatibility
        self.cahandler = None
        self.cert_operations_log = None
        self.cert_reusage_timeframe = 0
        self.cn2san_add = False
        self.dbstore = DBstore(self.debug, self.logger)
        self.enrollment_timeout = 5
        self.err_msg_dic = error_dic_get(self.logger)
        self.hooks = None
        self.ignore_pre_hook_failure = False
        self.ignore_post_hook_failure = True
        self.ignore_success_hook_failure = False
        self.message = Message(self.debug, self.server_name, self.logger)
        self.path_dic = {"cert_path": "/acme/cert/"}
        self.retry_after = 600
        self.tnauthlist_support = False

    def __enter__(self):
        """Makes ACMEHandler a Context Manager"""
        self._config_load()
        return self

    def __exit__(self, *args):
        """cose the connection at the end of the context"""

    def _validate_input_parameters(self, **kwargs) -> Dict[str, str]:
        """Validate input parameters and return validation errors"""
        errors = {}
        for param_name, param_value in kwargs.items():
            if param_value is None or (
                isinstance(param_value, str) and not param_value.strip()
            ):
                errors[param_name] = f"{param_name} cannot be empty or None"
        return errors

    def _create_error_response(
        self, code: int, message: str, detail: str = None
    ) -> Dict[str, str]:
        """Create standardized error response"""
        return {"code": code, "data": message, "detail": detail}

    def _validate_certificate_account_ownership(
        self, account_name: str, certificate: str
    ) -> bool:
        """Validate that the account owns the certificate"""
        self.logger.debug("Certificate._validate_certificate_account_ownership()")
        try:
            result = self.dbstore.certificate_account_check(
                account_name, b64_url_recode(self.logger, certificate)
            )
        except Exception as err_:
            self.logger.critical(
                "Database error: failed to check account for certificate: %s", err_
            )
            result = None
        self.logger.debug("Certificate._account_check() ended with: %s", result)
        return result

    def _authz_check(
        self, identifier_dic: Dict[str, str], certificate: str
    ) -> List[str]:
        self.logger.debug("Certificate._authz_check()")
        # load identifiers
        try:
            identifiers = json.loads(identifier_dic["identifiers"].lower())
        except Exception:
            identifiers = []

        # check if we have a tnauthlist identifier
        tnauthlist_identifer_in = self._tnauth_identifier_check(identifiers)
        if self.tnauthlist_support and tnauthlist_identifer_in:
            try:
                # get list of certextensions in base64 format and identifier status
                tnauthlist = cert_extensions_get(self.logger, certificate)
                identifier_status = self._identifer_tnauth_list(
                    identifier_dic, tnauthlist
                )
            except Exception as err:
                # enough to set identifier_list as empty list
                identifier_status = []
                self.logger.warning(
                    "Error while parsing certificate for TNAuthList identifier check: %s",
                    err,
                )
        else:
            try:
                # get sans
                san_list = cert_san_get(self.logger, certificate)
                if self.cn2san_add:
                    # add common name to SANs
                    cert_cn = cert_cn_get(self.logger, certificate)
                    if not san_list and cert_cn:
                        san_list.append(f"DNS:{cert_cn}")

                identifier_status = self._identifer_status_list(identifiers, san_list)
            except Exception as err:
                # enough to set identifier_list as empty list
                identifier_status = []
                self.logger.warning(
                    "Error while parsing certificate for SAN identifier check: %s",
                    err,
                )

        self.logger.debug("Certificate._authz_check() ended")
        return identifier_status

    def _authorization_check(self, order_name: str, certificate: str) -> bool:
        """check if an acount holds authorization for all identifiers = SANs in the certificate"""
        self.logger.debug("Certificate._authorization_check()")

        # empty list of statuses
        identifier_status = []

        # get identifiers for order
        try:
            identifier_dic = self.dbstore.order_lookup(
                "name", order_name, ["identifiers"]
            )
        except Exception as err_:
            self.logger.critical(
                "Database error: failed to check authorization for order '%s': %s",
                order_name,
                err_,
            )
            identifier_dic = {}

        if identifier_dic and "identifiers" in identifier_dic:
            # get identifier status list
            identifier_status = self._authz_check(identifier_dic, certificate)

        result = False
        if identifier_status and False not in identifier_status:
            result = True

        self.logger.debug("Certificate._authorization_check() ended with %s", result)
        return result

    def _cert_issuance_log_text(self, certificate_name, data_dic):
        """log cert issuance as text string"""

        log_string = f'Certificate {certificate_name} issued for account {data_dic["account_name"]} {data_dic["account_contact"]}'

        if data_dic.get("eab_kid", ""):
            log_string = log_string + f' with EAB KID {data_dic["eab_kid"]}'

        if data_dic.get("profile", ""):
            log_string = log_string + f' with Profile {data_dic["profile"]}'

        log_string = (
            log_string
            + f'. Serial: {data_dic["serial_number"]}, Common Name: {data_dic["common_name"]}, SANs: {data_dic["san_list"]}, Expires: {data_dic["expires"]}'
        )

        if data_dic.get("reused", ""):
            log_string = log_string + f' reused: {data_dic["reused"]}'

        self.logger.info(log_string)

    def _cert_issuance_log(
        self,
        certificate_name: str,
        certificate: str,
        order_name: str,
        cert_reusage: bool = False,
    ):
        """log certificate issuance"""
        self.logger.debug("Certificate._certificate_issuance_log(%s)", certificate_name)

        # lookup account name and kid
        try:
            order_dic = self.dbstore.order_lookup(
                "name",
                order_name,
                ["id", "name", "account__name", "account__eab_kid", "profile", "expires", "account__contact"],
            )
        except Exception as err:
            self.logger.error(
                "Database error: failed to get account information for cert issuance log: %s",
                err,
            )
            order_dic = {}

        data_dic = {
            "account_name": order_dic.get("account__name", ""),
            "account_contact": order_dic.get("account__contact", ""),
            "certificate_name": certificate_name,
            "serial_number": cert_serial_get(self.logger, certificate, hexformat=True),
            "common_name": cert_cn_get(self.logger, certificate),
            "san_list": cert_san_get(self.logger, certificate),
        }

        if cert_reusage:
            # add cert reusage flag if set to true
            data_dic["reused"] = cert_reusage

        if order_dic.get("account__eab_kid", ""):
            # add kid if existing
            data_dic["eab_kid"] = order_dic.get("account__eab_kid", "")

        if order_dic.get("profile", None):
            # add profile if existing
            data_dic["profile"] = order_dic.get("profile", "")

        if order_dic.get("expires", ""):
            # add expires if existing
            data_dic["expires"] = uts_to_date_utc(order_dic.get("expires", ""))

        if self.cert_operations_log == "json":
            # log in json format
            self.logger.info(
                "Certificate issued: %s",
                json.dumps(data_dic, sort_keys=True),
            )
        else:
            # log in text format
            self._cert_issuance_log_text(certificate_name, data_dic)

        self.logger.debug("Certificate._certificate_issuance_log() ended")

    def _cert_revocation_log(self, certificate: str, code: int):
        """log certificate revocation"""
        if code == 200:
            status = "successful"
        else:
            status = "failed"

        # lookup account name and kid
        try:
            cert_dic = self.dbstore.certificate_lookup(
                "cert_raw",
                b64_url_recode(self.logger, certificate),
                [
                    "name",
                    "order__account__name",
                    "order__account__eab_kid",
                    "order__account__contact",
                    "order__profile",
                ],
            )
        except Exception as err:
            self.logger.error(
                "Database error: failed to get account information for cert revocation: %s",
                err,
            )
            cert_dic = {}

        # construct log message including certificate name
        self.logger.debug(
            "Certificate._cert_revocation_log(%s)", cert_dic.get("name", "")
        )

        data_dic = {
            "account_name": cert_dic.get("order__account__name", ""),
            "account_contact": cert_dic.get("order__account__contact", ""),
            "certificate_name": cert_dic.get("name", ""),
            "serial_number": cert_serial_get(self.logger, certificate, hexformat=True),
            "common_name": cert_cn_get(self.logger, certificate),
            "profile": cert_dic.get("order__profile", ""),
            "san_list": cert_san_get(self.logger, certificate),
            "status": status,
        }

        if cert_dic.get("order__account__eab_kid", ""):
            data_dic["eab_kid"] = cert_dic.get("order__account__eab_kid")

        if self.cert_operations_log == "json":
            # log in json format
            self.logger.info(
                "Certificate revoked: %s",
                json.dumps(data_dic, sort_keys=True),
            )
        else:

            log_string = f'Certificate {data_dic["certificate_name"]} revocation {data_dic["status"]} for account {data_dic["account_name"]} {data_dic["account_contact"]}'
            if data_dic.get("eab_kid", ""):
                log_string = log_string + f' with EAB KID {data_dic["eab_kid"]}'
            if data_dic.get("profile", ""):
                log_string = log_string + f' with Profile {data_dic["profile"]}'
            log_string = (
                log_string
                + f'. Serial: {data_dic["serial_number"]}, Common Name: {data_dic["common_name"]}, SANs: {data_dic["san_list"]}'
            )

            # log in text format
            self.logger.info(log_string)

    def _cert_reusage_check(self, csr: str) -> Tuple[None, str, str, str]:
        """check if an existing certificate an be reused"""
        self.logger.debug(
            "Certificate._cert_reusage_check(%s)", self.cert_reusage_timeframe
        )

        try:
            result_dic = self.dbstore.certificates_search(
                "csr",
                csr,
                ("cert", "cert_raw", "expire_uts", "issue_uts", "created_at", "id"),
            )
        except Exception as err_:
            self.logger.critical(
                "Database error: failed to search for certificate reusage: %s", err_
            )
            result_dic = None

        cert = None
        cert_raw = None
        message = None

        if result_dic:
            self.logger.debug(
                "Certificate._cert_reusage_check(): found %s certificates",
                len(result_dic),
            )
            uts = uts_now()
            # sort certificates by creation date
            for certificate in sorted(
                result_dic, key=lambda i: i["issue_uts"], reverse=True
            ):
                try:
                    uts_create = date_to_uts_utc(certificate["created_at"])
                except Exception as _err:
                    self.logger.error(
                        "Date conversion error during certificate reusage check: id:%s/created_at:%s",
                        certificate["id"],
                        certificate["created_at"],
                    )
                    uts_create = 0

                self.logger.debug(
                    "uts: %s, reusage_tf: %s,  uts_create: %s, uts_exp: %s",
                    uts,
                    self.cert_reusage_timeframe,
                    uts_create,
                    certificate["expire_uts"],
                )
                # check if there certificates within reusage timeframe
                if (
                    certificate["cert_raw"]
                    and certificate["cert"]
                    and uts - self.cert_reusage_timeframe <= uts_create
                    and uts <= certificate["expire_uts"]
                ):
                    cert = certificate["cert"]
                    cert_raw = certificate["cert_raw"]
                    message = f'reused certificate from id: {certificate["id"]}'
                    break
        else:
            self.logger.debug(
                "Certificate._cert_reusage_check(): no certificates found"
            )

        self.logger.debug("Certificate._cert_reusage_check() ended with {%s", message)
        return (None, cert, cert_raw, message)

    def _config_hooks_load(self, config_dic: Dict[str, str]):
        """load hook configuration"""
        self.logger.debug("Certificate._config_hooks_load()")

        # load hooks according to configuration
        hooks_module = hooks_load(self.logger, config_dic)
        if hooks_module:
            try:
                # store handler in variable
                self.hooks = hooks_module.Hooks(self.logger)
            except Exception as err:
                self.logger.critical("Enrollment hooks could not be loaded: %s", err)

            self.ignore_pre_hook_failure = config_dic.getboolean(
                "Hooks", "ignore_pre_hook_failure", fallback=False
            )
            self.ignore_post_hook_failure = config_dic.getboolean(
                "Hooks", "ignore_post_hook_failure", fallback=True
            )
            self.ignore_success_hook_failure = config_dic.getboolean(
                "Hooks", "ignore_success_hook_failure", fallback=False
            )

        self.logger.debug("Certificate._config_hooks_load() ended")

    def _config_parameters_load(self, config_dic: Dict[str, str]):
        """load various parameters"""
        self.logger.debug("Certificate._config_parameters_load()")

        try:
            self.cert_reusage_timeframe = int(
                config_dic.get(
                    "Certificate",
                    "cert_reusage_timeframe",
                    fallback=self.cert_reusage_timeframe,
                )
            )
        except Exception as err_:
            self.logger.error(
                "cert_reusage_timout parsing error: %s",
                err_,
            )

        try:
            self.enrollment_timeout = int(
                config_dic.get(
                    "Certificate",
                    "enrollment_timeout",
                    fallback=self.enrollment_timeout,
                )
            )
            self.logger.info(
                "enrollment_timeout set to %s",
                self.enrollment_timeout,
            )
        except Exception as err_:
            self.logger.error(
                "enrollment_timeout parsing error: %s",
                err_,
            )

        if "Directory" in config_dic and "url_prefix" in config_dic["Directory"]:
            self.path_dic = {
                k: config_dic["Directory"]["url_prefix"] + v
                for k, v in self.path_dic.items()
            }

        self.cert_operations_log = config_dic.get(
            "Certificate", "cert_operations_log", fallback=self.cert_operations_log
        )
        if self.cert_operations_log:
            self.cert_operations_log = self.cert_operations_log.lower()

        self.logger.debug("Certificate._config_parameters_load() ended")

    def _config_load(self):
        """ " load config from file"""
        self.logger.debug("Certificate._config_load()")
        config_dic = load_config()

        if "Order" in config_dic:
            self.tnauthlist_support = config_dic.getboolean(
                "Order", "tnauthlist_support", fallback=False
            )

        if (
            "CAhandler" in config_dic
            and config_dic.get("CAhandler", "handler_file", fallback=None)
            == "examples/ca_handler/asa_ca_handler.py"
        ):
            self.cn2san_add = True
            self.logger.debug("Certificate._config_load(): cn2san_add enabled")

        # load ca_handler according to configuration
        ca_handler_module = ca_handler_load(self.logger, config_dic)

        if ca_handler_module:
            # store handler in variable
            self.cahandler = ca_handler_module.CAhandler
        else:
            self.logger.critical("No ca_handler loaded")

        # load hooks
        self._config_hooks_load(config_dic)

        # load parametrs
        self._config_parameters_load(config_dic)

        self.logger.debug("ca_handler: %s", ca_handler_module)
        self.logger.debug("Certificate._config_load() ended.")

    def _identifiers_load(self, identifier_dic: Dict[str, str], csr: str) -> List[str]:
        self.logger.debug("Certificate._identifiers_load()")
        # load identifiers
        try:
            identifiers = json.loads(identifier_dic["identifiers"].lower())
        except Exception:
            identifiers = []

        # do we need to check for tnauth
        tnauthlist_identifer_in = self._tnauth_identifier_check(identifiers)

        if self.tnauthlist_support and tnauthlist_identifer_in:
            # get list of certextensions in base64 format
            try:
                tnauthlist = csr_extensions_get(self.logger, csr)
                identifier_status = self._identifer_tnauth_list(
                    identifier_dic, tnauthlist
                )
            except Exception as err_:
                identifier_status = []
                self.logger.warning(
                    "Error while parsing CSR for TNAuthList identifier check: %s", err_
                )
        else:
            # get sans and compare identifiers against san
            try:
                san_list = csr_san_get(self.logger, csr)
                identifier_status = self._identifer_status_list(identifiers, san_list)
            except Exception as err_:
                identifier_status = []
                self.logger.warning(
                    "Error while checking identifiers against SAN: %s",
                    err_,
                )

        self.logger.debug(
            "Certificate._identifiers_load() ended with %s", identifier_status
        )
        return identifier_status

    def _csr_check(self, certificate_name: str, csr: str) -> bool:
        """compare csr extensions against order"""
        self.logger.debug("Certificate._csr_check()")

        # fetch certificate dictionary from DB
        certificate_dic = self._info(certificate_name)
        self.logger.debug("Certificate._info() ended with:%s", certificate_dic)

        # empty list of statuses
        identifier_status = []

        if "order" in certificate_dic:
            # get identifiers for order
            try:
                identifier_dic = self.dbstore.order_lookup(
                    "name", certificate_dic["order"], ["identifiers"]
                )
            except Exception as err_:
                self.logger.critical(
                    "Database error in Certificate when checking the CSR identifiers: %s",
                    err_,
                )
                identifier_dic = {}

            if identifier_dic and "identifiers" in identifier_dic:
                identifier_status = self._identifiers_load(identifier_dic, csr)

        csr_check_result = False

        if identifier_status and False not in identifier_status:
            csr_check_result = True

        self.logger.debug("Certificate._csr_check() ended with %s", csr_check_result)
        return csr_check_result

    def _enroll(self, csr: str) -> Tuple[str, str, str, str]:
        self.logger.debug("Certificate._enroll()")
        if self.cert_reusage_timeframe:
            (
                error,
                certificate,
                certificate_raw,
                poll_identifier,
            ) = self._cert_reusage_check(csr)
        else:
            certificate = None
            certificate_raw = None

        if not certificate or not certificate_raw:
            self.logger.debug("Certificate._enroll(): trigger enrollment")
            with self.cahandler(self.debug, self.logger) as ca_handler:
                (
                    error,
                    certificate,
                    certificate_raw,
                    poll_identifier,
                ) = ca_handler.enroll(csr)
            cert_reusage = False
        else:
            self.logger.info("Reuse existing certificate")
            cert_reusage = True

        self.logger.debug("Certificate._enroll() ended")
        return (error, certificate, certificate_raw, poll_identifier, cert_reusage)

    def _renewal_info_get(self, certificate: str) -> str:
        """get renewal info"""
        self.logger.debug("Certificate._renewal_info_get()")

        certificate_list = pembundle_to_list(self.logger, certificate)

        renewal_info_hex = certid_asn1_get(
            self.logger, certificate_list[0], certificate_list[1]
        )

        self.logger.debug(
            "Certificate.certid_asn1_get() ended with %s", renewal_info_hex
        )
        return renewal_info_hex

    def _store(
        self,
        certificate: str,
        certificate_raw: str,
        poll_identifier: str,
        certificate_name: str,
        order_name: str,
        csr: str,
    ) -> Tuple[int, str]:
        """store  certificate"""
        self.logger.debug("Certificate._store()")

        error = None
        (issue_uts, expire_uts) = cert_dates_get(self.logger, certificate_raw)
        try:
            result = self._store_cert(
                certificate_name,
                certificate,
                certificate_raw,
                issue_uts,
                expire_uts,
                poll_identifier,
            )
            if result:
                self._order_update({"name": order_name, "status": "valid"})
            if self.hooks:
                try:
                    self.hooks.success_hook(
                        certificate_name,
                        order_name,
                        csr,
                        certificate,
                        certificate_raw,
                        poll_identifier,
                    )
                    self.logger.debug("Certificate._store: success_hook successful")
                except Exception as err:
                    self.logger.error(
                        "Exception during success_hook execution: %s", err
                    )
                    if not self.ignore_success_hook_failure:
                        error = (None, "success_hook_error", str(err))

        except Exception as err_:
            result = None
            self.logger.critical(
                "Database error: failed to store certificate: %s", err_
            )

        self.logger.debug("Certificate._store() ended")
        return (result, error)

    def _enrollerror_handler(
        self, error: str, poll_identifier: str, order_name: str, certificate_name: str
    ) -> Tuple[None, str, str]:
        """store error message for later analysis"""
        self.logger.debug("Certificate._enrollerror_handler(%s)", error)

        result = None
        detail = None
        try:
            if not poll_identifier:
                self.logger.debug(
                    "Certificate._enrollerror_handler(): invalidating order as there is no certificate and no poll_identifier: %s/%s",
                    error,
                    order_name,
                )
                self._order_update({"name": order_name, "status": "invalid"})
            self._store_cert_error(certificate_name, error, poll_identifier)
        except Exception as err_:
            result = None
            self.logger.critical(
                "Database error: failed to store certificate error: %s", err_
            )

        # cover polling cases
        if poll_identifier:
            detail = poll_identifier
        elif error == "Either CN or SANs are not allowed by configuration":
            error = self.err_msg_dic["rejectedidentifier"]
            detail = "CN or SANs are not allowed by configuration"
        else:
            error = self.err_msg_dic["serverinternal"]
        self.logger.debug("Certificate._enrollerror_handler() ended with: %s", result)
        return (result, error, detail)

    def _pre_hooks_process(
        self, certificate_name: str, order_name: str, csr: str
    ) -> List[str]:
        self.logger.debug(
            "Certificate._pre_hooks_process(%s, %s)", certificate_name, order_name
        )
        hook_error = []
        if self.hooks:
            try:
                self.hooks.pre_hook(certificate_name, order_name, csr)
                self.logger.debug(
                    "Certificate._pre_hooks_process(): pre_hook successful"
                )
            except Exception as err:
                self.logger.error("Exception during pre_hook execution: %s", err)
                if not self.ignore_pre_hook_failure:
                    hook_error = (None, "pre_hook_error", str(err))

        self.logger.debug("Certificate._pre_hooks_process(%s)", hook_error)
        return hook_error

    def _post_hooks_process(
        self, certificate_name: str, order_name: str, csr: str, error: str
    ) -> List[str]:
        self.logger.debug(
            "Certificate._post_hooks_process(%s, %s", certificate_name, order_name
        )

        hook_error = []
        if self.hooks:
            try:
                self.hooks.post_hook(certificate_name, order_name, csr, error)
                self.logger.debug(
                    "Certificate._post_hooks_process(): post_hook successful"
                )
            except Exception as err:
                self.logger.error("Exception during post_hook execution: %s", err)
                if not self.ignore_post_hook_failure:
                    hook_error = (None, "post_hook_error", str(err))

        self.logger.debug("Certificate._post_hooks_process(%s)", hook_error)
        return hook_error

    def _enroll_and_store(
        self, certificate_name: str, csr: str, order_name: str = None
    ) -> Tuple[str, str, str]:
        """enroll and store certificate"""
        self.logger.debug(
            "Certificate._enroll_and_store(%s, %s, %s)",
            certificate_name,
            order_name,
            csr,
        )

        detail = None
        error = None

        hook_error = self._pre_hooks_process(certificate_name, order_name, csr)
        if hook_error:
            return hook_error

        # enroll certificate
        (
            error,
            certificate,
            certificate_raw,
            poll_identifier,
            cert_reusage,
        ) = self._enroll(csr)
        if certificate:
            (result, error) = self._store(
                certificate,
                certificate_raw,
                poll_identifier,
                certificate_name,
                order_name,
                csr,
            )
            if error:
                return error
            elif self.cert_operations_log:
                self._cert_issuance_log(
                    certificate_name, certificate_raw, order_name, cert_reusage
                )

        else:
            self.logger.error("Enrollment error: %s", error)
            (result, error, detail) = self._enrollerror_handler(
                error, poll_identifier, order_name, certificate_name
            )

        hook_error = self._post_hooks_process(certificate_name, order_name, csr, error)
        if hook_error:
            return hook_error

        self.logger.debug(
            "Certificate._enroll_and_store() ended with: %s:%s", result, error
        )
        return (result, error, detail)

    def _identifier_chk(
        self, cert_type: str, cert_value: str, identifiers: List[str], san_is_in: bool
    ) -> bool:
        """check identifier"""
        self.logger.debug("Certificate._identifier_chk(%s/%s)", cert_type, cert_value)

        if cert_type and cert_value:
            for identifier in identifiers:
                if (
                    "type" in identifier
                    and identifier["type"].lower() == cert_type
                    and identifier["value"].lower() == cert_value
                ):
                    san_is_in = True
                    break

        self.logger.debug("Certificate._identifier_chk(%s)", san_is_in)
        return san_is_in

    def _identifer_status_list(
        self, identifiers: List[str], san_list: List[str]
    ) -> List[str]:
        """compare identifiers and check if each san is in identifer list"""
        self.logger.debug("Certificate._identifer_status_list()")

        identifier_status = []
        for san in san_list:
            san_is_in = False
            try:
                (cert_type, cert_value) = san.lower().split(":", 1)
            except Exception as err_:
                self.logger.error("Error while splitting san %s: %s", san, err_)
                cert_type = None
                cert_value = None

            # check identifiers
            san_is_in = self._identifier_chk(
                cert_type, cert_value, identifiers, san_is_in
            )

            self.logger.debug(
                "SAN check for %s against identifiers returned %s",
                san.lower(),
                san_is_in,
            )
            identifier_status.append(san_is_in)

        if not identifier_status:
            identifier_status.append(False)

        self.logger.debug(
            "Certificate._identifer_status_list() ended with %s", identifier_status
        )
        return identifier_status

    def _identifier_tnauth_chk(
        self, identifier: Dict[str, str], tnauthlist: List[str]
    ) -> bool:
        """check tnauth identifier against tnauthlist"""
        self.logger.debug("Certificate._identifier_tnauth_chk(%s)", identifier)

        result = False
        # get the tnauthlist identifier
        if "type" in identifier and identifier["type"].lower() == "tnauthlist":
            # check if tnauthlist extension is in extension list
            if "value" in identifier and identifier["value"] in tnauthlist:
                result = True

        self.logger.debug("Certificate._identifier_tnauth_chk() endedt with %s", result)
        return result

    def _identifer_tnauth_list(
        self, identifier_dic: Dict[str, str], tnauthlist: List[str]
    ):
        """compare identifiers and check if each san is in identifer list"""
        self.logger.debug("Certificate._identifer_tnauth_list()")

        identifier_status = []
        # reload identifiers (case senetive)
        try:
            identifiers = json.loads(identifier_dic["identifiers"])
        except Exception:
            identifiers = []

        if tnauthlist and not identifier_dic:
            identifier_status.append(False)
        elif identifiers and tnauthlist:
            for identifier in identifiers:
                identifier_status.append(
                    self._identifier_tnauth_chk(identifier, tnauthlist)
                )
        else:
            identifier_status.append(False)

        self.logger.debug(
            "Certificate._identifer_tnauth_list() ended with %s", identifier_status
        )
        return identifier_status

    def _info(
        self,
        certificate_name: str,
        flist: List[str] = ("name", "csr", "cert", "order__name"),
    ) -> Dict[str, str]:
        """get certificate from database"""
        self.logger.debug("Certificate._info(%s)", certificate_name)
        try:
            result = self.dbstore.certificate_lookup("name", certificate_name, flist)
        except Exception as err_:
            self.logger.critical(
                "Database error: failed to get certificate info: %s", err_
            )
            result = None
        return result

    def _expirydate_assume(
        self, cert: Dict[str, str], timestamp: int, to_be_cleared: bool
    ) -> bool:
        """assume expiry date"""
        self.logger.debug("Certificate._expirydate_assume()")

        if "csr" in cert and cert["csr"]:
            # cover cases for enrollments in flight
            # we assume that a CSR should turn int a cert within two weeks
            if "created_at" in cert:
                created_at_uts = date_to_uts_utc(cert["created_at"])
                if 0 < created_at_uts < timestamp - (14 * 86400):
                    to_be_cleared = True
            else:
                # this scneario should never been happen so lets be careful and not clear it
                to_be_cleared = False
        else:
            # no csr and no cert - to be cleared
            to_be_cleared = True

        self.logger.debug("Certificate._expirydate_assume() ended")
        return to_be_cleared

    def _expiredate_get(
        self, cert: Dict[str, str], timestamp: int, to_be_cleared: bool
    ) -> bool:
        """get expirey date from certificate"""
        self.logger.debug("Certificate._expiredate_get()")

        # in case cert_expiry in table is 0 try to get it from cert
        if cert["expire_uts"] == 0:
            if "cert_raw" in cert and cert["cert_raw"]:
                # get expiration from certificate
                (issue_uts, expire_uts) = cert_dates_get(self.logger, cert["cert_raw"])
                if 0 < expire_uts < timestamp:
                    # returned date is other than 0 and lower than given timestamp
                    cert["issue_uts"] = issue_uts
                    cert["expire_uts"] = expire_uts
                    to_be_cleared = True
            else:
                to_be_cleared = self._expirydate_assume(cert, timestamp, to_be_cleared)
        else:
            # expired based on expire_uts from db
            to_be_cleared = True

        self.logger.debug(
            "Certificate._expiredate_get() ended with: to_be_cleared:  %s",
            to_be_cleared,
        )
        return to_be_cleared

    def _invalidation_check(
        self, cert: Dict[str, str], timestamp: int, purge: bool = False
    ):
        """check if cert must be invalidated"""
        if "name" in cert:
            self.logger.debug("Certificate._invalidation_check(%s)", cert["name"])
        else:
            self.logger.debug("Certificate._invalidation_check()")

        to_be_cleared = False

        if cert and "name" in cert:
            if "cert" in cert and cert["cert"] and "removed by" in cert["cert"].lower():
                if purge:
                    # skip entries which had been cleared before cert[cert] check is needed to cover corner cases
                    to_be_cleared = True

            elif "expire_uts" in cert:
                # get expiry date from either dictionary or certificate
                to_be_cleared = self._expiredate_get(cert, timestamp, to_be_cleared)
            else:
                # this scneario should never been happen so lets be careful and not clear it
                to_be_cleared = False
        else:
            # entries without a cert-name can be to_be_cleared
            to_be_cleared = True

        if "name" in cert:
            self.logger.debug(
                "Certificate._invalidation_check(%s) ended with %s",
                cert["name"],
                to_be_cleared,
            )
        else:
            self.logger.debug(
                "Certificate._invalidation_check() ended with %s", to_be_cleared
            )

        return (to_be_cleared, cert)

    def _order_update(self, data_dic: Dict[str, str]):
        """update order based on ordername"""
        self.logger.debug("Certificate._order_update(%s)", data_dic)
        try:
            self.dbstore.order_update(data_dic)
        except Exception as err_:
            self.logger.critical("Database error: failed to update order: %s", err_)

    def _revocation_reason_check(self, reason: str) -> str:
        """check reason"""
        self.logger.debug("Certificate._revocation_reason_check(%s)", reason)

        # taken from https://tools.ietf.org/html/rfc5280#section-5.3.1
        allowed_reasons = {
            0: "unspecified",
            1: "keyCompromise",
            # 2: 'cACompromise',
            3: "affiliationChanged",
            4: "superseded",
            5: "cessationOfOperation",
            6: "certificateHold",
            # 8: 'removeFromCRL',
            # 9: 'privilegeWithdrawn',
            # 10: 'aACompromise'
        }

        result = allowed_reasons.get(reason, None)
        self.logger.debug(
            "Certificate._revocation_reason_check() ended with %s", result
        )
        return result

    def _revocation_request_validate(
        self, account_name: str, payload: Dict[str, str]
    ) -> Tuple[int, str]:
        """check revocaton request for consistency"""
        self.logger.debug("Certificate._revocation_request_validate(%s)", account_name)

        # set a value to avoid that we are returning none by accident
        code = 400
        error = None
        if "reason" in payload:
            # check revocatoin reason if we get one
            rev_reason = self._revocation_reason_check(payload["reason"])
            # successful
            if not rev_reason:
                error = self.err_msg_dic["badrevocationreason"]
        else:
            # set revocation reason to unspecified
            rev_reason = "unspecified"

        if rev_reason:
            # check if the account issued the certificate and return the order name
            if "certificate" in payload:
                order_name = self._account_check(account_name, payload["certificate"])
            else:
                order_name = None

            error = rev_reason
            if order_name:
                # check if the account holds the authorization for the identifiers
                auth_chk = self._authorization_check(order_name, payload["certificate"])
                if auth_chk:
                    # all good set code to 200
                    code = 200
                else:
                    error = self.err_msg_dic["unauthorized"]

        self.logger.debug(
            "Certificate._revocation_request_validate() ended with: %s, %s", code, error
        )
        return (code, error)

    def _store_cert(
        self,
        certificate_name: str,
        certificate: str,
        raw: str,
        issue_uts: int = 0,
        expire_uts: int = 0,
        poll_identifier: str = None,
    ) -> int:
        """get key for a specific account id"""
        self.logger.debug("Certificate._store_cert(%s)", certificate_name)

        renewal_info_hex = self._renewal_info_get(certificate)
        serial = cert_serial_get(self.logger, raw, hexformat=True)
        aki = cert_aki_get(self.logger, raw)

        data_dic = {
            "cert": certificate,
            "name": certificate_name,
            "cert_raw": raw,
            "issue_uts": issue_uts,
            "expire_uts": expire_uts,
            "poll_identifier": poll_identifier,
            "renewal_info": renewal_info_hex,
            "serial": serial,
            "aki": aki,
        }
        try:
            cert_id = self.dbstore.certificate_add(data_dic)
        except Exception as err_:
            cert_id = None
            self.logger.critical(
                "acme2certifier database error in Certificate._store_cert(): %s", err_
            )
        self.logger.debug("Certificate._store_cert(%s) ended", cert_id)
        return cert_id

    def _store_cert_error(
        self, certificate_name: str, error: str, poll_identifier: str
    ) -> int:
        """get key for a specific account id"""
        self.logger.debug("Certificate._store_cert_error(%s)", certificate_name)
        data_dic = {
            "error": error,
            "name": certificate_name,
            "poll_identifier": poll_identifier,
        }
        try:
            cert_id = self.dbstore.certificate_add(data_dic)
        except Exception as err_:
            cert_id = None
            self.logger.critical(
                "Database error: failed to store certificate error: %s", err_
            )
        self.logger.debug("Certificate._store_cert_error(%s) ended", cert_id)
        return cert_id

    def _tnauth_identifier_check(self, identifier_dic: Dict[str, str]) -> int:
        """check if we have an tnauthlist_identifier"""
        self.logger.debug("Certificate._tnauth_identifier_check()")
        # check if we have a tnauthlist identifier
        tnauthlist_identifer_in = False
        if identifier_dic:
            for identifier in identifier_dic:
                if "type" in identifier:
                    if identifier["type"].lower() == "tnauthlist":
                        tnauthlist_identifer_in = True
        self.logger.debug(
            "Certificate._tnauth_identifier_check() ended with: %s",
            tnauthlist_identifer_in,
        )
        return tnauthlist_identifer_in

    def certlist_search(
        self,
        key: str,
        value: Union[str, int],
        vlist: List[str] = None,
    ) -> Dict[str, str]:
        """get certificate from database"""
        self.logger.debug("Certificate.certlist_search(%s: %s)", key, value)
        if vlist is None:
            vlist = ["name", "csr", "cert", "order__name"]

        try:
            result = self.dbstore.certificates_search(key, value, vlist)
        except Exception as err_:
            self.logger.critical(
                "Database error while searching for certificates: %s",
                err_,
            )
            result = None
        return result

    def _cleanup(self, report_list: List[str], timestamp: int, purge: bool):
        """cleanup"""
        self.logger.debug("Certificate.cleanup(%s,%s)", timestamp, purge)
        if not purge:
            # we are just modifiying data
            for cert in report_list:
                data_dic = {
                    "name": cert["name"],
                    "expire_uts": cert["expire_uts"],
                    "issue_uts": cert["issue_uts"],
                    "cert": f"removed by certificates.cleanup() on {uts_to_date_utc(timestamp)}",
                    "cert_raw": cert["cert_raw"],
                }
                try:
                    self.dbstore.certificate_add(data_dic)
                except Exception as err_:
                    self.logger.critical(
                        "Database error: failed to add certificate during cleanup: %s",
                        err_,
                    )
        else:
            # delete entries from certificates table
            for cert in report_list:
                try:
                    self.dbstore.certificate_delete("id", cert["id"])
                except Exception as err_:
                    self.logger.critical(
                        "Database error: failed to delete certificate during cleanup: %s",
                        err_,
                    )

        self.logger.debug("Certificate.cleanup() ended")

    def cleanup(
        self, timestamp: int = None, purge: bool = False
    ) -> Tuple[List[str], List[str]]:
        """cleanup routine to shrink table-size"""
        self.logger.debug("Certificate.cleanup(%s,%s)", timestamp, purge)

        field_list = [
            "id",
            "name",
            "expire_uts",
            "issue_uts",
            "cert",
            "cert_raw",
            "csr",
            "created_at",
            "order__id",
            "order__name",
        ]

        # get expired certificates
        try:
            certificate_list = self.dbstore.certificates_search(
                "expire_uts", timestamp, field_list, "<="
            )
        except Exception as err_:
            self.logger.critical(
                "Database error: failed to search for certificates to clean up: %s",
                err_,
            )
            certificate_list = []

        report_list = []
        for cert in certificate_list:
            (to_be_cleared, cert) = self._invalidation_check(cert, timestamp, purge)

            if to_be_cleared:
                report_list.append(cert)

        # cleanup
        self._cleanup(report_list, timestamp, purge)

        self.logger.debug(
            "Certificate.cleanup() ended with: %s certs", len(report_list)
        )
        return (field_list, report_list)

    def _dates_update(self, cert: Dict[str, str]):
        """update issue and expiry date with date from certificate"""
        self.logger.debug("Certificate._dates_update()")

        if "issue_uts" in cert and "expire_uts" in cert:
            if cert["issue_uts"] == 0 and cert["expire_uts"] == 0:
                if cert["cert_raw"]:
                    (issue_uts, expire_uts) = cert_dates_get(
                        self.logger, cert["cert_raw"]
                    )
                    if issue_uts or expire_uts:
                        self._store_cert(
                            cert["name"],
                            cert["cert"],
                            cert["cert_raw"],
                            issue_uts,
                            expire_uts,
                        )

        self.logger.debug("Certificate._dates_update() ended")

    def dates_update(self):
        """scan certificates and update issue/expiry date"""
        self.logger.debug("Certificate.dates_update()")

        cert_list = self.certlist_search(
            "issue_uts",
            0,
            vlist=["id", "name", "cert", "cert_raw", "issue_uts", "expire_uts"],
        )
        self.logger.debug("Got {%s} certificates to be updated...", len(cert_list))
        for cert in cert_list:
            self._dates_update(cert)

        self.logger.debug("Certificate.dates_update() ended")

    def _handle_enrollment_thread_execution(
        self, certificate_name: str, csr: str, order_name: str
    ) -> Tuple[str, str]:
        """Handle the threaded enrollment execution with proper error handling"""
        try:
            twrv = ThreadWithReturnValue(
                target=self._process_enrollment_and_store_certificate,
                args=(certificate_name, csr, order_name),
            )
            twrv.daemon = True
            twrv.start()

            enroll_result = twrv.join(timeout=self.config.enrollment_timeout)
            self.logger.debug("Certificate enrollment thread completed")

            if enroll_result is None:
                return "timeout", "Enrollment process timed out"

            return self._parse_enrollment_result(enroll_result)

        except Exception as err:
            self.logger.error("Error during threaded enrollment execution: %s", err)
            return (
                self.err_msg_dic["serverinternal"],
                "Enrollment thread execution failed",
            )

    def _parse_enrollment_result(self, enroll_result) -> Tuple[str, str]:
        """Parse enrollment result with proper error handling"""
        self.logger.debug("Certificate._parse_enrollment_result(%s)", enroll_result)
        try:
            if isinstance(enroll_result, tuple) and len(enroll_result) >= 2:
                _, error, *detail = enroll_result
                return error, detail[0] if detail else ""
            else:
                self.logger.error(
                    "Unexpected enrollment result format: %s", enroll_result
                )
                return (
                    self.err_msg_dic["serverinternal"],
                    "Unexpected enrollment result format",
                )
        except Exception as err:
            self.logger.error("Error parsing enrollment result: %s", err)
            return (
                self.err_msg_dic["serverinternal"],
                "Failed to parse enrollment result",
            )

    def process_certificate_enrollment_request(
        self, certificate_name: str, csr: str, order_name: str = None
    ) -> Tuple[str, str]:
        """Process certificate enrollment request and validate CSR with improved error handling"""
        try:
            # Validate input parameters
            validation_errors = self._validate_input_parameters(
                certificate_name=certificate_name, csr=csr
            )
            if validation_errors:
                self.logger.error(self.INVALID_INPUT_PARAMS_MSG, validation_errors)
                return self.err_msg_dic["badcsr"], "Invalid input parameters"

            self.logger.debug(
                "Certificate.process_certificate_enrollment_request(%s, %s)",
                certificate_name,
                order_name,
            )

            # Validate CSR against order
            try:
                csr_check_result = self._validate_csr_against_order(
                    certificate_name, csr
                )
            except Exception as err:
                self.logger.error("Error validating CSR against order: %s", err)
                return self.err_msg_dic["serverinternal"], "CSR validation failed"

            if not csr_check_result:
                return self.err_msg_dic["badcsr"], "CSR validation failed"

            # Process enrollment
            error, detail = self._handle_enrollment_thread_execution(
                certificate_name, csr, order_name
            )
            self.logger.debug(
                "Certificate.process_certificate_enrollment_request() ended with: %s:%s",
                error,
                detail,
            )
            return (error, detail)

        except Exception as err:
            self.logger.critical(
                "Unexpected error in process_certificate_enrollment_request: %s", err
            )
            return (
                self.err_msg_dic["serverinternal"],
                "Unexpected error during enrollment",
            )

    def _determine_certificate_response(self, cert_info: Dict) -> Dict[str, str]:
        """Determine appropriate response based on certificate info"""
        self.logger.debug("Certificate._determine_certificate_response()")

        if not cert_info or "order__status_id" not in cert_info:
            return self._create_error_response(500, self.err_msg_dic["serverinternal"])

        order_status = cert_info["order__status_id"]

        if order_status == self.ORDER_STATUS_VALID:
            return self._handle_valid_certificate(cert_info)
        elif order_status == self.ORDER_STATUS_PROCESSING:
            return self._handle_processing_certificate()
        else:
            return self._create_error_response(403, self.err_msg_dic["ordernotready"])

    def _handle_valid_certificate(self, cert_info: Dict) -> Dict[str, str]:
        """Handle response for valid certificate"""
        if "cert" in cert_info and cert_info["cert"]:
            return {
                "code": 200,
                "data": cert_info["cert"],
                "header": {"Content-Type": "application/pem-certificate-chain"},
            }
        else:
            return self._create_error_response(500, self.err_msg_dic["serverinternal"])

    def _handle_processing_certificate(self) -> Dict[str, str]:
        """Handle response for processing certificate"""
        return {
            "code": 403,
            "data": self.err_msg_dic["ratelimited"],
            "header": {"Retry-After": f"{self.config.retry_after}"},
        }

    def get_certificate_details(self, url: str) -> Dict[str, str]:
        """Get certificate details from URL with improved error handling"""
        try:
            # Validate input
            validation_errors = self._validate_input_parameters(url=url)
            if validation_errors:
                self.logger.error(self.INVALID_INPUT_PARAMS_MSG, validation_errors)
                return self._create_error_response(400, "Invalid URL parameter")

            certificate_name = string_sanitize(
                self.logger,
                url.replace(
                    f'{self.server_name}{self.config.path_dic["cert_path"]}', ""
                ),
            )
            self.logger.debug(
                "Certificate.get_certificate_details(%s)", certificate_name
            )

            # Get certificate info using manager with error handling
            try:
                cert_info = self.certificate_manager.get_certificate_info(
                    certificate_name
                )
            except Exception as err:
                self.logger.error("Error retrieving certificate info: %s", err)
                return self._create_error_response(
                    500, self.err_msg_dic["serverinternal"]
                )

            response_dic = self._determine_certificate_response(cert_info)
            self.logger.debug(
                "Certificate.get_certificate_details(%s) ended", response_dic["code"]
            )
            return response_dic

        except Exception as err:
            self.logger.critical("Unexpected error in get_certificate_details: %s", err)
            return self._create_error_response(500, self.err_msg_dic["serverinternal"])

    def _validate_certificate_request_message(
        self, content: str
    ) -> Tuple[int, str, str, Dict, Dict, str]:
        """Validate certificate request message"""
        try:
            return self.message.check(content)
        except Exception as err:
            self.logger.error("Error validating certificate request message: %s", err)
            return (
                400,
                self.err_msg_dic["malformed"],
                "Message validation failed",
                {},
                {},
                "",
            )

    def _prepare_certificate_response(
        self, response_dic: Dict, code: int, message: str, detail: str
    ) -> Dict[str, str]:
        """Prepare and format certificate response"""
        try:
            status_dic = {"code": code, "type": message, "detail": detail}
            response_dic = self.message.prepare_response(response_dic, status_dic)

            # Serialize dict data to JSON if needed
            if isinstance(response_dic.get("data"), dict):
                response_dic["data"] = json.dumps(response_dic["data"])

            return response_dic
        except Exception as err:
            self.logger.error("Error preparing certificate response: %s", err)
            return {
                "code": 500,
                "data": self.err_msg_dic["serverinternal"],
                "detail": "Response formatting failed",
            }

    def process_certificate_request(self, content: str) -> Dict[str, str]:
        """Process certificate request with improved error handling and reduced complexity"""
        try:
            # Validate input
            validation_errors = self._validate_input_parameters(content=content)
            if validation_errors:
                self.logger.error(self.INVALID_INPUT_PARAMS_MSG, validation_errors)
                return self._prepare_certificate_response(
                    {}, 400, self.err_msg_dic["malformed"], "Invalid content parameter"
                )

            self.logger.debug("Certificate.process_certificate_request()")

            # Validate and parse message
            (
                code,
                message,
                detail,
                protected,
                _payload,
                _account_name,
            ) = self._validate_certificate_request_message(content)

            response_dic = {}

            if code == 200:
                if "url" in protected:
                    try:
                        response_dic = self.get_certificate_details(protected["url"])
                        # Update error details if certificate retrieval failed
                        if response_dic["code"] in (400, 403, 500):
                            code = response_dic["code"]
                            message = response_dic["data"]
                            detail = response_dic.get("detail")
                    except Exception as err:
                        self.logger.error("Error getting certificate details: %s", err)
                        code = 500
                        message = self.err_msg_dic["serverinternal"]
                        detail = "Certificate retrieval failed"
                        response_dic = {}
                else:
                    code = 400
                    message = self.err_msg_dic["malformed"]
                    detail = "url missing in protected header"
                    response_dic = {}

            # Prepare final response
            final_response = self._prepare_certificate_response(
                response_dic, code, message, detail
            )

            result_code = final_response.get("code", "no code found")
            self.logger.debug(
                "Certificate.process_certificate_request() ended with: %s", result_code
            )
            return final_response

        except Exception as err:
            self.logger.critical(
                "Unexpected error in process_certificate_request: %s", err
            )
            return self._prepare_certificate_response(
                {},
                500,
                self.err_msg_dic["serverinternal"],
                "Unexpected error during request processing",
            )

    def _validate_revocation_message(
        self, content: str
    ) -> Tuple[int, str, str, str, Dict, str]:
        """Validate revocation message and extract components"""
        try:
            return self.message.check(content)
        except Exception as err:
            self.logger.error("Error validating revocation message: %s", err)
            return (
                400,
                self.err_msg_dic["malformed"],
                "Message validation failed",
                {},
                {},
                "",
            )

    def _process_certificate_revocation(
        self, account_name: str, payload: Dict
    ) -> Tuple[int, str, str]:
        """Process the actual certificate revocation"""
        try:
            (code, error) = self._validate_revocation_request(account_name, payload)
            if code != 200:
                return code, error, None

            # Perform revocation
            rev_date = uts_to_date_utc(uts_now())
            with self.cahandler(self.debug, self.logger) as ca_handler:
                (code, message, detail) = ca_handler.revoke(
                    payload["certificate"], error, rev_date
                )

            # Log revocation if configured
            if self.config.cert_operations_log:
                try:
                    self.certificate_logger.log_certificate_revocation(
                        payload["certificate"], code
                    )
                except Exception as log_err:
                    self.logger.warning(
                        "Failed to log certificate revocation: %s", log_err
                    )

            return code, message, detail

        except Exception as err:
            self.logger.error("Error during certificate revocation: %s", err)
            return (
                500,
                self.err_msg_dic["serverinternal"],
                "Revocation processing failed",
            )

    def revoke_certificate(self, content: str) -> Dict[str, str]:
        """Process certificate revocation request with improved error handling"""
        try:
            # Validate input
            validation_errors = self._validate_input_parameters(content=content)
            if validation_errors:
                self.logger.error(self.INVALID_INPUT_PARAMS_MSG, validation_errors)
                return self.message.prepare_response(
                    {},
                    {
                        "code": 400,
                        "type": self.err_msg_dic["malformed"],
                        "detail": "Invalid content",
                    },
                )

            self.logger.debug("Certificate.revoke_certificate()")

            # Validate and parse message
            (
                code,
                message,
                detail,
                _protected,
                payload,
                account_name,
            ) = self._validate_revocation_message(content)

            if code == 200:
                if "certificate" in payload:
                    (code, message, detail) = self._process_certificate_revocation(
                        account_name, payload
                    )
                else:
                    code = 400
                    message = self.err_msg_dic["malformed"]
                    detail = "certificate not found"

            # Prepare response
            status_dic = {"code": code, "type": message, "detail": detail}
            response_dic = self.message.prepare_response({}, status_dic)

            self.logger.debug(
                "Certificate.revoke_certificate() ended with: %s", response_dic
            )
            return response_dic

        except Exception as err:
            self.logger.critical("Unexpected error in revoke_certificate: %s", err)
            error_response = {
                "code": 500,
                "type": self.err_msg_dic["serverinternal"],
                "detail": "Unexpected error during revocation",
            }
            return self.message.prepare_response({}, error_response)

    def _handle_successful_certificate_poll(
        self,
        certificate_name: str,
        certificate: str,
        certificate_raw: str,
        order_name: str,
    ) -> Optional[int]:
        """Handle successful certificate polling result"""
        try:
            # Get issuing and expiration date
            (issue_uts, expire_uts) = cert_dates_get(self.logger, certificate_raw)

            # Update certificate record in database
            result = self._store_certificate_in_database(
                certificate_name, certificate, certificate_raw, issue_uts, expire_uts
            )

            # Update order status to valid
            try:
                self.repository.order_update({"name": order_name, "status": "valid"})
            except Exception as err:
                self.logger.critical(
                    "Database error updating order status during polling: %s", err
                )
                # Continue execution as certificate was stored successfully

            return result

        except Exception as err:
            self.logger.error("Error handling successful certificate poll: %s", err)
            return None

    def _handle_failed_certificate_poll(
        self,
        certificate_name: str,
        error: str,
        poll_identifier: str,
        order_name: str,
        rejected: bool,
    ) -> None:
        """Handle failed certificate polling result"""
        try:
            # Store error message for later analysis
            self._store_certificate_error(certificate_name, error, poll_identifier)

            # Update order status if rejected
            if rejected:
                try:
                    self.repository.order_update(
                        {"name": order_name, "status": "invalid"}
                    )
                except Exception as err:
                    self.logger.critical(
                        "Database error updating order status to invalid: %s", err
                    )

        except Exception as err:
            self.logger.error("Error handling failed certificate poll: %s", err)

    def poll_certificate_status(
        self, certificate_name: str, poll_identifier: str, csr: str, order_name: str
    ) -> Optional[int]:
        """Poll certificate status from CA and store result in database with improved error handling"""
        try:
            # Validate input parameters
            validation_errors = self._validate_input_parameters(
                certificate_name=certificate_name,
                poll_identifier=poll_identifier,
                csr=csr,
                order_name=order_name,
            )
            if validation_errors:
                self.logger.error(self.INVALID_INPUT_PARAMS_MSG, validation_errors)
                return None

            self.logger.debug(
                "Certificate.poll_certificate_status(%s: %s)",
                certificate_name,
                poll_identifier,
            )

            # Poll certificate from CA handler
            try:
                with self.cahandler(self.debug, self.logger) as ca_handler:
                    (
                        error,
                        certificate,
                        certificate_raw,
                        poll_identifier,
                        rejected,
                    ) = ca_handler.poll(certificate_name, poll_identifier, csr)
            except Exception as err:
                self.logger.error("Error polling certificate from CA handler: %s", err)
                return None

            # Process poll result
            if certificate:
                result = self._handle_successful_certificate_poll(
                    certificate_name, certificate, certificate_raw, order_name
                )
            else:
                self._handle_failed_certificate_poll(
                    certificate_name, error, poll_identifier, order_name, rejected
                )
                result = None

            self.logger.debug(
                "Certificate.poll_certificate_status(%s: %s) ended",
                certificate_name,
                poll_identifier,
            )
            return result

        except Exception as err:
            self.logger.critical("Unexpected error in poll_certificate_status: %s", err)
            return None

    def store_certificate_signing_request(
        self, order_name: str, csr: str, header_info: str
    ) -> str:
        """Store certificate signing request into database with improved error handling"""
        self.logger.debug(
            "Certificate.store_certificate_signing_request(%s)", order_name
        )
        try:
            # Delegate to certificate manager for CSR validation and storage
            try:
                (
                    success,
                    certificate_name,
                ) = self.certificate_manager.validate_and_store_csr(
                    order_name, csr, header_info
                )
            except Exception as err:
                self.logger.error("Error during CSR validation and storage: %s", err)
                raise RuntimeError(f"CSR storage failed: {err}")

            if not success:
                error_msg = f"Failed to store CSR for order {order_name}"
                self.logger.error(error_msg)
                raise RuntimeError(error_msg)

            self.logger.debug(
                "Certificate.store_certificate_signing_request() ended successfully"
            )
            return certificate_name

        except (ValueError, RuntimeError):
            # Re-raise validation and known errors
            raise
        except Exception as err:
            self.logger.critical(
                "Unexpected error in store_certificate_signing_request: %s", err
            )
            raise RuntimeError(f"Unexpected error during CSR storage: {err}")

    # === Legacy API Compatibility ===
    # Legacy methods for backward compatibility - use descriptive methods instead

    def enroll_and_store(
        self, certificate_name: str, csr: str, order_name: str = None
    ) -> Tuple[str, str]:
        """check csr and trigger enrollment"""
        self.logger.debug(
            "Certificate.enroll_and_store(%s, %s)", certificate_name, order_name
        )

        # check csr against order
        csr_check_result = self._csr_check(certificate_name, csr)

        # only continue if self.csr_check returned True
        if csr_check_result:
            twrv = ThreadWithReturnValue(
                target=self._enroll_and_store, args=(certificate_name, csr, order_name)
            )
            twrv.daemon = True
            twrv.start()
            enroll_result = twrv.join(timeout=self.enrollment_timeout)
            self.logger.debug(
                "Certificate.enroll_and_store() ThreadWithReturnValue ended"
            )
            if enroll_result:
                try:
                    (result, error, detail) = enroll_result
                except Exception as err_:
                    self.logger.error(
                        "Enrollment error message split of %s failed with err: %s",
                        enroll_result,
                        err_,
                    )
                    result = None
                    error = self.err_msg_dic["serverinternal"]
                    detail = "unexpected enrollment result"
            else:
                result = None
                error = "timeout"
                detail = "timeout"
        else:
            result = None
            error = self.err_msg_dic["badcsr"]
            detail = "CSR validation failed"

        self.logger.debug(
            "Certificate.enroll_and_store() ended with: %s:%s", result, error
        )
        return (error, detail)

    def new_get(self, url: str) -> Dict[str, str]:
        """get request"""
        certificate_name = string_sanitize(
            self.logger,
            url.replace(f'{self.server_name}{self.path_dic["cert_path"]}', ""),
        )
        self.logger.debug("Certificate.new_get(%s)", certificate_name)

        # fetch certificate dictionary from DB
        certificate_dic = self._info(
            certificate_name, ["name", "csr", "cert", "order__name", "order__status_id"]
        )
        response_dic = {}
        if "order__status_id" in certificate_dic:
            if certificate_dic["order__status_id"] == 5:
                # oder status is valid - download certificate
                if "cert" in certificate_dic and certificate_dic["cert"]:
                    response_dic["code"] = 200
                    # filter certificate and decode it
                    response_dic["data"] = certificate_dic["cert"]
                    response_dic["header"] = {}
                    response_dic["header"][
                        "Content-Type"
                    ] = "application/pem-certificate-chain"
                else:
                    response_dic["code"] = 500
                    response_dic["data"] = self.err_msg_dic["serverinternal"]
            elif certificate_dic["order__status_id"] == 4:
                # order status is processing - ratelimiting
                response_dic["header"] = {"Retry-After": f"{self.retry_after}"}
                response_dic["code"] = 403
                response_dic["data"] = self.err_msg_dic["ratelimited"]
            else:
                response_dic["code"] = 403
                response_dic["data"] = self.err_msg_dic["ordernotready"]
        else:
            response_dic["code"] = 500
            response_dic["data"] = self.err_msg_dic["serverinternal"]

        self.logger.debug("Certificate.new_get(%s) ended", response_dic["code"])
        return response_dic

    def new_post(self, content: str) -> Dict[str, str]:
        """post request"""
        self.logger.debug("Certificate.new_post()")

        response_dic = {}
        # check message
        (
            code,
            message,
            detail,
            protected,
            _payload,
            _account_name,
        ) = self.message.check(content)
        if code == 200:
            if "url" in protected:
                response_dic = self.new_get(protected["url"])
                if response_dic["code"] in (400, 403, 400, 500):
                    code = response_dic["code"]
                    message = response_dic["data"]
                    detail = None
            else:
                response_dic["code"] = code = 400
                # pylint: disable=w0612, w0622
                response_dic["data"] = self.err_msg_dic["malformed"]
                detail = "url missing in protected header"

        # prepare/enrich response
        status_dic = {"code": code, "type": message, "detail": detail}
        response_dic = self.message.prepare_response(response_dic, status_dic)

        # depending on the response the content of responsedic['data'] can be either string or dict
        # data will get serialzed
        if isinstance(response_dic["data"], dict):
            response_dic["data"] = json.dumps(response_dic["data"])

        # cover cornercase - not sure if we ever run into such situation
        if "code" in response_dic:
            result = response_dic["code"]
        else:
            result = "no code found"

        self.logger.debug("Certificate.new_post() ended with: %s", result)
        return response_dic

    def revoke(self, content: str) -> Dict[str, str]:
        """revoke request"""
        self.logger.debug("Certificate.revoke()")

        response_dic = {}
        # check message
        (code, message, detail, _protected, payload, account_name) = self.message.check(
            content
        )

        if code == 200:
            if "certificate" in payload:
                (code, error) = self._revocation_request_validate(account_name, payload)
                if code == 200:
                    # revocation starts here
                    # revocation reason is stored in error variable
                    rev_date = uts_to_date_utc(uts_now())
                    with self.cahandler(self.debug, self.logger) as ca_handler:
                        (code, message, detail) = ca_handler.revoke(
                            payload["certificate"], error, rev_date
                        )

                    if self.cert_operations_log:
                        self._cert_revocation_log(
                            payload["certificate"],
                            code,
                        )

                else:
                    message = error
                    detail = None

            else:
                # message could not get decoded
                code = 400
                message = self.err_msg_dic["malformed"]
                detail = "certificate not found"

        # prepare/enrich response
        status_dic = {"code": code, "type": message, "detail": detail}
        response_dic = self.message.prepare_response(response_dic, status_dic)
        self.logger.debug("Certificate.revoke() ended with: %s", response_dic)
        return response_dic

    def poll(
        self, certificate_name: str, poll_identifier: str, csr: str, order_name: str
    ) -> int:
        """try to fetch a certificate from CA and store it into database"""
        self.logger.debug("Certificate.poll(%s: %s)", certificate_name, poll_identifier)

        with self.cahandler(self.debug, self.logger) as ca_handler:
            (
                error,
                certificate,
                certificate_raw,
                poll_identifier,
                rejected,
            ) = ca_handler.poll(certificate_name, poll_identifier, csr)
            if certificate:
                # get issuing and expiration date
                (issue_uts, expire_uts) = cert_dates_get(self.logger, certificate_raw)
                # update certificate record in database
                _result = self._store_cert(
                    certificate_name,
                    certificate,
                    certificate_raw,
                    issue_uts,
                    expire_uts,
                )
                # update order status to 5 (valid)
                try:
                    self.dbstore.order_update({"name": order_name, "status": "valid"})
                except Exception as err_:
                    self.logger.critical(
                        "Database error during Certificate polling: %s", err_
                    )
            else:
                # store error message for later analysis
                self._store_cert_error(certificate_name, error, poll_identifier)
                _result = None
                if rejected:
                    try:
                        self.dbstore.order_update(
                            {"name": order_name, "status": "invalid"}
                        )
                    except Exception as err_:
                        self.logger.critical(
                            "Database error during Certificate polling: %s", err_
                        )
        self.logger.debug("Certificate.poll(%s: %s)", certificate_name, poll_identifier)
        return _result

    def store_csr(self, order_name: str, csr: str, header_info: str) -> str:
        """store csr into database"""
        self.logger.debug("Certificate.store_csr(%s)", order_name)

        certificate_name = generate_random_string(self.logger, 12)
        data_dic = {
            "order": order_name,
            "csr": csr,
            "name": certificate_name,
            "header_info": header_info,
        }
        try:
            self.dbstore.certificate_add(data_dic)
        except Exception as err_:
            self.logger.critical("Database error in Certificate.store_csr(): %s", err_)
        self.logger.debug("Certificate.store_csr() ended")
        return certificate_name
