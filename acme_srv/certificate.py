# -*- coding: utf-8 -*-
# pylint: disable=r0902, r0912, r0913, r0915, r1705
"""certificate class"""
from __future__ import print_function
import json
from typing import List, Tuple, Dict, Union, Optional, Any
from dataclasses import dataclass
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
    hooks_load,
    load_config,
    pembundle_to_list,
    string_sanitize,
    uts_now,
    uts_to_date_utc,
    config_async_mode_load,
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
        log_string = f'Certificate {data_dic["certificate_name"]} revocation {data_dic["status"]} for account {data_dic["account_name"]} {data_dic["account_contact"]}'  # noqa: E501

        if data_dic.get("eab_kid", ""):
            log_string = log_string + f' with EAB KID {data_dic["eab_kid"]}'

        if data_dic.get("profile", ""):
            log_string = log_string + f' with Profile {data_dic["profile"]}'

        log_string = (
            log_string
            + f'. Serial: {data_dic["serial_number"]}, Common Name: {data_dic["common_name"]}, SANs: {data_dic["san_list"]}'
        )

        self.logger.info(log_string)


# CertificateConfiguration harmonized with Challenge class approach
@dataclass
class CertificateConfiguration:
    """
    Configuration dataclass for Certificate operations.
    Centralizes all configuration settings for the Certificate class and its components.
    """

    debug: bool = False
    server_name: Optional[str] = None
    cert_operations_log: Optional[Any] = None
    cert_reusage_timeframe: int = 0
    cn2san_add: bool = False
    enrollment_timeout: int = 5
    retry_after: int = 600
    tnauthlist_support: bool = False
    async_mode: bool = False
    ignore_pre_hook_failure: bool = False
    ignore_post_hook_failure: bool = True
    ignore_success_hook_failure: bool = False


class Certificate(object):
    """CA  handler"""

    # Order status constants for better readability
    ORDER_STATUS_PROCESSING = 4
    ORDER_STATUS_VALID = 5

    # Error message constants
    INVALID_INPUT_PARAMS_MSG = "Invalid input parameters: %s"

    def __init__(self, debug: bool = False, srv_name: str = None, logger=None):
        self.debug = debug
        self.logger = logger
        self.server_name = srv_name

        self.path_dic = {"cert_path": "/acme/cert/"}

        # Create configuration dataclass from config file using harmonized approach
        self.config = CertificateConfiguration()

        # Core components
        self.dbstore = DBstore(self.debug, self.logger)
        self.repository = DatabaseCertificateRepository(self.dbstore, self.logger)

        # Legacy properties for backward compatibility
        self.cahandler = None
        self.err_msg_dic = error_dic_get(self.logger)
        self.hooks = None
        self.message = Message(self.debug, self.server_name, self.logger)

        # Initialize the new architecture components with configuration
        self.certificate_manager = CertificateManager(
            self.debug, self.logger, self.err_msg_dic, self.repository, self.config
        )
        self.certificate_logger = CertificateLogger(
            self.logger, self.config.cert_operations_log, self.repository
        )

    def __enter__(self):
        """Makes ACMEHandler a Context Manager"""
        self._load_configuration()
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
            result = self.repository.certificate_account_check(
                account_name, b64_url_recode(self.logger, certificate)
            )
        except Exception as err_:
            self.logger.critical(
                "Database error: failed to check account for certificate: %s", err_
            )
            result = None
        self.logger.debug(
            "Certificate._validate_certificate_account_ownership() ended with: %s",
            result,
        )
        return result

    def _validate_certificate_authorization(
        self, identifier_dic: Dict[str, str], certificate: str
    ) -> List[str]:
        self.logger.debug("Certificate._validate_certificate_authorization()")
        # load identifiers
        try:
            identifiers = json.loads(identifier_dic["identifiers"].lower())
        except Exception:
            identifiers = []

        # check if we have a tnauthlist identifier
        tnauthlist_identifer_in = self._check_for_tnauth_identifiers(identifiers)
        if self.config.tnauthlist_support and tnauthlist_identifer_in:
            try:
                # get list of certextensions in base64 format and identifier status
                tnauthlist = cert_extensions_get(self.logger, certificate)
                identifier_status = self._validate_identifiers_against_tnauthlist(
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
                if self.config.cn2san_add:
                    # add common name to SANs
                    cert_cn = cert_cn_get(self.logger, certificate)
                    if not san_list and cert_cn:
                        san_list.append(f"DNS:{cert_cn}")

                identifier_status = self._validate_identifiers_against_sans(
                    identifiers, san_list
                )
            except Exception as err:
                # enough to set identifier_list as empty list
                identifier_status = []
                self.logger.warning(
                    "Error while parsing certificate for SAN identifier check: %s",
                    err,
                )

        self.logger.debug("Certificate._validate_certificate_authorization() ended")
        return identifier_status

    def _validate_order_authorization(self, order_name: str, certificate: str) -> bool:
        """Validate that the account holds authorization for all identifiers = SANs in the certificate"""
        self.logger.debug("Certificate._validate_order_authorization()")

        # empty list of statuses
        identifier_status = []

        # get identifiers for order
        try:
            identifier_dic = self.repository.order_lookup(
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
            identifier_status = self._validate_certificate_authorization(
                identifier_dic, certificate
            )

        result = False
        if identifier_status and False not in identifier_status:
            result = True

        self.logger.debug(
            "Certificate._validate_order_authorization() ended with %s", result
        )
        return result

    def _check_certificate_reusability(self, csr: str) -> Tuple[None, str, str, str]:
        """Check if an existing certificate can be reused"""
        self.logger.debug(
            "Certificate._check_certificate_reusability(%s)",
            self.config.cert_reusage_timeframe,
        )
        try:
            result_dic = self.repository.search_certificates(
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
                "Certificate._check_certificate_reusability(): found %s certificates",
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
                    self.config.cert_reusage_timeframe,
                    uts_create,
                    certificate["expire_uts"],
                )
                # check if there certificates within reusage timeframe
                if (
                    certificate["cert_raw"]
                    and certificate["cert"]
                    and uts - self.config.cert_reusage_timeframe <= uts_create
                    and uts <= certificate["expire_uts"]
                ):
                    cert = certificate["cert"]
                    cert_raw = certificate["cert_raw"]
                    message = f'reused certificate from id: {certificate["id"]}'
                    break
        else:
            self.logger.debug(
                "Certificate._check_certificate_reusability(): no certificates found"
            )

        self.logger.debug(
            "Certificate._check_certificate_reusability() ended with %s", message
        )
        return (None, cert, cert_raw, message)

    def _load_hooks_configuration(self, config_dic: Dict[str, str]):
        """Load hook configuration from config dictionary"""
        self.logger.debug("Certificate._load_hooks_configuration()")

        # load hooks according to configuration
        hooks_module = hooks_load(self.logger, config_dic)
        if hooks_module:
            try:
                # store handler in variable
                self.hooks = hooks_module.Hooks(self.logger)
            except Exception as err:
                self.logger.critical("Enrollment hooks could not be loaded: %s", err)

        # Hooks section
        if "Hooks" in config_dic:
            self.config.ignore_pre_hook_failure = config_dic.getboolean(
                "Hooks", "ignore_pre_hook_failure", fallback=False
            )
            self.config.ignore_post_hook_failure = config_dic.getboolean(
                "Hooks", "ignore_post_hook_failure", fallback=True
            )
            self.config.ignore_success_hook_failure = config_dic.getboolean(
                "Hooks", "ignore_success_hook_failure", fallback=False
            )

        self.logger.debug("Certificate._load_hooks_configuration() ended")

    def _load_certificate_parameters(self, config_dic: Dict[str, str] = None):
        """Load various certificate parameters - now handled by CertificateConfig"""
        self.logger.debug(
            "Certificate._load_certificate_parameters() - delegated to CertificateConfig"
        )
        # Certificate section
        try:
            self.config.cert_reusage_timeframe = int(
                config_dic.get(
                    "Certificate",
                    "cert_reusage_timeframe",
                    fallback=0,
                )
            )
        except Exception:
            pass

        try:
            self.config.enrollment_timeout = int(
                config_dic.get("Certificate", "enrollment_timeout", fallback=5)
            )
        except Exception:
            pass

        try:
            self.config.retry_after = int(
                config_dic.get("Certificate", "retry_after", fallback=600)
            )
        except Exception:
            pass

        self.config.cert_operations_log = config_dic.get(
            "Certificate", "cert_operations_log", fallback=None
        )
        if self.config.cert_operations_log:
            self.config.cert_operations_log = self.config.cert_operations_log.lower()

        # Order section
        if "Order" in config_dic:
            self.config.tnauthlist_support = config_dic.getboolean(
                "Order", "tnauthlist_support", fallback=False
            )

        # CAhandler section
        if (
            "CAhandler" in config_dic
            and config_dic.get("CAhandler", "handler_file", fallback=None)
            == "examples/ca_handler/asa_ca_handler.py"
        ):
            self.config.cn2san_add = True

        # Directory section
        if "Directory" in config_dic and "url_prefix" in config_dic["Directory"]:
            self.path_dic = {
                k: config_dic["Directory"]["url_prefix"] + v
                for k, v in self.path_dic.items()
            }

        self.config.async_mode = config_async_mode_load(
            self.logger, config_dic, self.dbstore.type
        )

        self.logger.debug("Certificate._load_certificate_parameters() ended")

    def _load_configuration(self):
        """Load certificate configuration from file"""
        self.logger.debug("Certificate._load_configuration()")
        config_dic = load_config()

        # load ca_handler according to configuration
        ca_handler_module = ca_handler_load(self.logger, config_dic)

        if ca_handler_module:
            # store handler in variable
            self.cahandler = ca_handler_module.CAhandler
        else:
            self.logger.critical("No ca_handler loaded")

        # load hooks
        self._load_hooks_configuration(config_dic)

        # load certificate parameters
        self._load_certificate_parameters(config_dic)

        self.logger.debug("ca_handler: %s", ca_handler_module)
        self.logger.debug("Certificate._load_configuration() ended.")

    def _load_and_validate_identifiers(
        self, identifier_dic: Dict[str, str], csr: str
    ) -> List[str]:
        self.logger.debug("Certificate._load_and_validate_identifiers()")
        # load identifiers
        try:
            identifiers = json.loads(identifier_dic["identifiers"].lower())
        except Exception:
            identifiers = []

        # do we need to check for tnauth
        tnauthlist_identifer_in = self._check_for_tnauth_identifiers(identifiers)

        if self.config.tnauthlist_support and tnauthlist_identifer_in:
            # get list of certextensions in base64 format
            try:
                tnauthlist = csr_extensions_get(self.logger, csr)
                identifier_status = self._validate_identifiers_against_tnauthlist(
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
                identifier_status = self._validate_identifiers_against_sans(
                    identifiers, san_list
                )
            except Exception as err_:
                identifier_status = []
                self.logger.warning(
                    "Error while checking identifiers against SAN: %s",
                    err_,
                )

        self.logger.debug(
            "Certificate._load_and_validate_identifiers() ended with %s",
            identifier_status,
        )
        return identifier_status

    def _validate_csr_against_order(self, certificate_name: str, csr: str) -> bool:
        """Validate CSR extensions against order requirements"""
        self.logger.debug("Certificate._validate_csr_against_order()")

        # fetch certificate dictionary from DB
        certificate_dic = self._get_certificate_info(certificate_name)
        self.logger.debug(
            "Certificate._get_certificate_info() ended with:%s", certificate_dic
        )

        # empty list of statuses
        identifier_status = []

        if "order" in certificate_dic:
            # get identifiers for order
            try:
                identifier_dic = self.repository.order_lookup(
                    "name", certificate_dic["order"], ["identifiers"]
                )
            except Exception as err_:
                self.logger.critical(
                    "Database error in Certificate when checking the CSR identifiers: %s",
                    err_,
                )
                identifier_dic = {}

            if identifier_dic and "identifiers" in identifier_dic:
                identifier_status = self._load_and_validate_identifiers(
                    identifier_dic, csr
                )

        csr_check_result = False

        if identifier_status and False not in identifier_status:
            csr_check_result = True

        self.logger.debug(
            "Certificate._validate_csr_against_order() ended with %s", csr_check_result
        )
        return csr_check_result

    def _process_certificate_enrollment(self, csr: str) -> Tuple[str, str, str, str]:
        self.logger.debug("Certificate._process_certificate_enrollment()")

        poll_identifier = None
        error = None
        if self.config.cert_reusage_timeframe:
            (
                error,
                certificate,
                certificate_raw,
                poll_identifier,
            ) = self._check_certificate_reusability(csr)
        else:
            certificate = None
            certificate_raw = None

        if not certificate or not certificate_raw:
            self.logger.debug(
                "Certificate._process_certificate_enrollment(): trigger enrollment"
            )
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

        self.logger.debug("Certificate._process_certificate_enrollment() ended")
        return (error, certificate, certificate_raw, poll_identifier, cert_reusage)

    def _get_certificate_renewal_info(self, certificate: str) -> str:
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

    def _store_certificate_and_update_order(
        self,
        certificate: str,
        certificate_raw: str,
        poll_identifier: str,
        certificate_name: str,
        order_name: str,
        csr: str,
    ) -> Tuple[int, str]:
        """Store certificate and update order status"""
        self.logger.debug("Certificate._store_certificate_and_update_order()")

        error = None
        (issue_uts, expire_uts) = cert_dates_get(self.logger, certificate_raw)
        try:
            result = self._store_certificate_in_database(
                certificate_name,
                certificate,
                certificate_raw,
                issue_uts,
                expire_uts,
                poll_identifier,
            )
            if result:
                self._update_order_status({"name": order_name, "status": "valid"})
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
                    self.logger.debug(
                        "Certificate._store_certificate_and_update_order: success_hook successful"
                    )
                except Exception as err:
                    self.logger.error(
                        "Exception during success_hook execution: %s", err
                    )
                    if not self.config.ignore_success_hook_failure:
                        error = (None, "success_hook_error", str(err))

        except Exception as err_:
            result = None
            self.logger.critical(
                "Database error: failed to store certificate: %s", err_
            )
            error = self.err_msg_dic.get(
                "serverinternal", "Unknown error"
            )  # Ensure error is set

        self.logger.debug("Certificate._store_certificate_and_update_order() ended")
        return (result, error)

    def _handle_enrollment_error(
        self, error: str, poll_identifier: str, order_name: str, certificate_name: str
    ) -> Tuple[None, str, str]:
        """Store error message for later analysis"""
        self.logger.debug("Certificate._handle_enrollment_error(%s)", error)

        result = None
        detail = None
        try:
            if not poll_identifier:
                self.logger.debug(
                    "Certificate._handle_enrollment_error(): invalidating order as there is no certificate and no poll_identifier: %s/%s",
                    error,
                    order_name,
                )
                self._update_order_status({"name": order_name, "status": "invalid"})
            self._store_certificate_error(certificate_name, error, poll_identifier)
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
        self.logger.debug(
            "Certificate._handle_enrollment_error() ended with: %s", result
        )
        return (result, error, detail)

    def _execute_pre_enrollment_hooks(
        self, certificate_name: str, order_name: str, csr: str
    ) -> List[str]:
        self.logger.debug(
            "Certificate._execute_pre_enrollment_hooks(%s, %s)",
            certificate_name,
            order_name,
        )
        hook_error = []
        if self.hooks:
            try:
                self.hooks.pre_hook(certificate_name, order_name, csr)
                self.logger.debug(
                    "Certificate._execute_pre_enrollment_hooks(): pre_hook successful"
                )
            except Exception as err:
                self.logger.error("Exception during pre_hook execution: %s", err)
                if not self.config.ignore_pre_hook_failure:
                    hook_error = (None, "pre_hook_error", str(err))

        self.logger.debug("Certificate._execute_pre_enrollment_hooks(%s)", hook_error)
        return hook_error

    def _execute_post_enrollment_hooks(
        self, certificate_name: str, order_name: str, csr: str, error: str
    ) -> List[str]:
        self.logger.debug(
            "Certificate._execute_post_enrollment_hooks(%s, %s",
            certificate_name,
            order_name,
        )
        hook_error = []
        if self.hooks:
            try:
                self.hooks.post_hook(certificate_name, order_name, csr, error)
                self.logger.debug(
                    "Certificate._execute_post_enrollment_hooks(): post_hook successful"
                )
            except Exception as err:
                self.logger.error("Exception during post_hook execution: %s", err)
                if not self.config.ignore_post_hook_failure:
                    hook_error.append(
                        str(err)
                    )  # Append error message to hook_error list

        self.logger.debug("Certificate._execute_post_enrollment_hooks(%s)", hook_error)
        return hook_error

    def _process_enrollment_and_store_certificate(
        self, certificate_name: str, csr: str, order_name: str = None
    ) -> Tuple[str, str, str]:
        """Process certificate enrollment and store the result"""
        self.logger.debug(
            "Certificate._process_enrollment_and_store_certificate(%s, %s, %s)",
            certificate_name,
            order_name,
            csr,
        )

        detail = None
        error = None

        hook_error = self._execute_pre_enrollment_hooks(
            certificate_name, order_name, csr
        )
        if hook_error:
            return hook_error

        # enroll certificate
        (
            error,
            certificate,
            certificate_raw,
            poll_identifier,
            cert_reusage,
        ) = self._process_certificate_enrollment(csr)
        if certificate:
            (result, error) = self._store_certificate_and_update_order(
                certificate,
                certificate_raw,
                poll_identifier,
                certificate_name,
                order_name,
                csr,
            )
            if error:
                return error
            elif self.config.cert_operations_log:
                try:
                    self.certificate_logger.log_certificate_issuance(
                        certificate_name, certificate_raw, order_name, cert_reusage
                    )
                except Exception as log_exc:
                    self.logger.error(
                        "Exception during log_certificate_issuance: %s", log_exc
                    )

        else:
            self.logger.error("Enrollment error: %s", error)
            (result, error, detail) = self._handle_enrollment_error(
                error, poll_identifier, order_name, certificate_name
            )

        hook_error = self._execute_post_enrollment_hooks(
            certificate_name, order_name, csr, error
        )
        if hook_error:
            return hook_error

        self.logger.debug(
            "Certificate._process_enrollment_and_store_certificate() ended with: %s:%s",
            result,
            error,
        )
        return (result, error, detail)

    def _check_identifier_match(
        self, cert_type: str, cert_value: str, identifiers: List[str], san_is_in: bool
    ) -> bool:
        """Check if identifier matches certificate values"""
        self.logger.debug(
            "Certificate._check_identifier_match(%s/%s)", cert_type, cert_value
        )

        if cert_type and cert_value:
            for identifier in identifiers:
                if (
                    "type" in identifier
                    and identifier["type"].lower() == cert_type
                    and identifier["value"].lower() == cert_value
                ):
                    san_is_in = True
                    break

        self.logger.debug("Certificate._check_identifier_match(%s)", san_is_in)
        return san_is_in

    def _validate_identifiers_against_sans(
        self, identifiers: List[str], san_list: List[str]
    ) -> List[str]:
        """Compare identifiers and check if each SAN is in identifier list"""
        self.logger.debug("Certificate._validate_identifiers_against_sans()")

        identifier_status = []
        for san in san_list:
            san_is_in = False
            try:
                (cert_type, cert_value) = san.lower().split(":", 1)
            except Exception as err_:
                self.logger.error("Error while splitting san %s: %s", san, err_)
                cert_type = None
                cert_value = None

            san_is_in = self._check_identifier_match(
                cert_type, cert_value, identifiers, san_is_in
            )

            self.logger.debug(
                "SAN check for %s against identifiers returned %s",
                san.lower(),
                san_is_in,
            )
            identifier_status.append(san_is_in)

        if not identifier_status:
            self.logger.error("No SANs found in certificate")
            identifier_status.append(False)

        self.logger.debug(
            "Certificate._validate_identifiers_against_sans() ended with %s",
            identifier_status,
        )
        return identifier_status

    def _check_tnauth_identifier_match(
        self, identifier: Dict[str, str], tnauthlist: List[str]
    ) -> bool:
        """Check TNAuth identifier against TNAuth list"""
        self.logger.debug("Certificate._check_tnauth_identifier_match(%s)", identifier)

        result = False
        # get the tnauthlist identifier
        if "type" in identifier and identifier["type"].lower() == "tnauthlist":
            # check if tnauthlist extension is in extension list
            if "value" in identifier and identifier["value"] in tnauthlist:
                result = True

        self.logger.debug(
            "Certificate._check_tnauth_identifier_match() ended with %s", result
        )
        return result

    def _validate_identifiers_against_tnauthlist(
        self, identifier_dic: Dict[str, str], tnauthlist: List[str]
    ):
        """Compare identifiers and check if each is in TNAuth list"""
        self.logger.debug("Certificate._validate_identifiers_against_tnauthlist()")

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
                    self._check_tnauth_identifier_match(identifier, tnauthlist)
                )
        else:
            identifier_status.append(False)

        self.logger.debug(
            "Certificate._validate_identifiers_against_tnauthlist() ended with %s",
            identifier_status,
        )
        return identifier_status

    def _get_certificate_info(
        self,
        certificate_name: str,
        flist: List[str] = ("name", "csr", "cert", "order__name"),
    ) -> Dict[str, str]:
        """Get certificate information from database"""
        self.logger.debug("Certificate._get_certificate_info(%s)", certificate_name)
        try:
            result = self.repository.certificate_lookup("name", certificate_name, flist)
        except Exception as err_:
            self.logger.critical(
                "Database error: failed to get certificate info: %s", err_
            )
            result = None
        return result

    def _update_order_status(self, data_dic: Dict[str, str]):
        """Update order status based on order name"""
        self.logger.debug("Certificate._update_order_status(%s)", data_dic)
        try:
            self.repository.order_update(data_dic)
        except Exception as err_:
            self.logger.critical("Database error: failed to update order: %s", err_)

    def _validate_revocation_reason(self, reason: str) -> str:
        """Validate revocation reason code"""
        self.logger.debug("Certificate._validate_revocation_reason(%s)", reason)

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
            "Certificate._validate_revocation_reason() ended with %s", result
        )
        return result

    def _validate_revocation_request(
        self, account_name: str, payload: Dict[str, str]
    ) -> Tuple[int, str]:
        """Validate revocation request for consistency"""
        self.logger.debug("Certificate._validate_revocation_request(%s)", account_name)

        # set a value to avoid that we are returning none by accident
        code = 400
        error = None
        if "reason" in payload:
            # check revocatoin reason if we get one
            rev_reason = self._validate_revocation_reason(payload["reason"])
            # successful
            if not rev_reason:
                error = self.err_msg_dic["badrevocationreason"]
        else:
            # set revocation reason to unspecified
            rev_reason = "unspecified"

        if rev_reason:
            # check if the account issued the certificate and return the order name
            if "certificate" in payload:
                order_name = self._validate_certificate_account_ownership(
                    account_name, payload["certificate"]
                )
            else:
                self.logger.debug(
                    "Certificate._validate_revocation_request(): Revocation request missing 'certificate' field"
                )
                order_name = None

            error = rev_reason
            if order_name:
                # check if the account holds the authorization for the identifiers
                auth_chk = self._validate_order_authorization(
                    order_name, payload["certificate"]
                )
                if auth_chk:
                    # all good set code to 200
                    code = 200
                else:
                    error = self.err_msg_dic["unauthorized"]

        self.logger.debug(
            "Certificate._validate_revocation_request() ended with: %s, %s", code, error
        )
        return (code, error)

    def _store_certificate_in_database(
        self,
        certificate_name: str,
        certificate: str,
        raw: str,
        issue_uts: int = 0,
        expire_uts: int = 0,
        poll_identifier: str = None,
    ) -> int:
        """Store certificate in database"""
        self.logger.debug(
            "Certificate._store_certificate_in_database(%s)", certificate_name
        )

        renewal_info_hex = self._get_certificate_renewal_info(certificate)
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
            cert_id = self.repository.certificate_add(data_dic)
        except Exception as err_:
            cert_id = None
            self.logger.critical(
                "acme2certifier database error in Certificate._store_certificate_in_database(): %s",
                err_,
            )
        self.logger.debug(
            "Certificate._store_certificate_in_database(%s) ended", cert_id
        )
        return cert_id

    def _store_certificate_error(
        self, certificate_name: str, error: str, poll_identifier: str
    ) -> int:
        """Store certificate error information in database"""
        self.logger.debug("Certificate._store_certificate_error(%s)", certificate_name)
        data_dic = {
            "error": error,
            "name": certificate_name,
            "poll_identifier": poll_identifier,
        }
        try:
            cert_id = self.repository.certificate_add(data_dic)
        except Exception as err_:
            cert_id = None
            self.logger.critical(
                "Database error: failed to store certificate error: %s", err_
            )
        self.logger.debug("Certificate._store_certificate_error(%s) ended", cert_id)
        return cert_id

    def _check_for_tnauth_identifiers(self, identifier_dic: Dict[str, str]) -> int:
        """Check if we have TNAuth list identifiers"""
        self.logger.debug("Certificate._check_for_tnauth_identifiers()")
        # check if we have a tnauthlist identifier
        tnauthlist_identifer_in = False
        if identifier_dic:
            for identifier in identifier_dic:
                if "type" in identifier:
                    if identifier["type"].lower() == "tnauthlist":
                        tnauthlist_identifer_in = True
        self.logger.debug(
            "Certificate._check_for_tnauth_identifiers() ended with: %s",
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

        # Delegate to certificate manager for search with business logic
        search_result = self.certificate_manager.search_certificates(key, value, vlist)

        # Return certificates list for backward compatibility
        return search_result.get("certificates", None)

    def cleanup(
        self, timestamp: int = None, purge: bool = False
    ) -> Tuple[List[str], List[str]]:
        """cleanup routine to shrink table-size"""
        self.logger.debug("Certificate.cleanup(%s,%s)", timestamp, purge)

        if not timestamp:
            timestamp = uts_now()

        # Delegate to certificate manager
        (field_list, report_list) = self.certificate_manager.cleanup_certificates(
            timestamp, purge
        )

        self.logger.debug(
            "Certificate.cleanup() ended with: %s certs", len(report_list)
        )
        return (field_list, report_list)

    def _update_certificate_dates(self, cert: Dict[str, str]):
        """Update issue and expiry date with date from certificate"""
        self.logger.debug("Certificate._update_certificate_dates()")

        if "issue_uts" in cert and "expire_uts" in cert:
            if cert["issue_uts"] == 0 and cert["expire_uts"] == 0:
                if cert["cert_raw"]:
                    (issue_uts, expire_uts) = cert_dates_get(
                        self.logger, cert["cert_raw"]
                    )
                    if issue_uts or expire_uts:
                        self._store_certificate_in_database(
                            cert["name"],
                            cert["cert"],
                            cert["cert_raw"],
                            issue_uts,
                            expire_uts,
                        )

        self.logger.debug("Certificate._update_certificate_dates() ended")

    def dates_update(self):
        """scan certificates and update issue/expiry date"""
        self.logger.debug("Certificate.dates_update()")

        # For backward compatibility with tests, get certificate list and process each
        cert_list = self.certlist_search(
            "issue_uts",
            0,
            vlist=["id", "name", "cert", "cert_raw", "issue_uts", "expire_uts"],
        )
        if cert_list:
            for cert in cert_list:
                self._update_certificate_dates(cert)

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
            if self.config.async_mode:
                enroll_result = (None, None, "asynchronous enrollment started")
            else:
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
        if isinstance(enroll_result, tuple) and len(enroll_result) >= 2:
            _, error, *detail = enroll_result
            return error, detail[0] if detail else ""
        else:
            self.logger.error("Unexpected enrollment result format: %s", enroll_result)
            return (
                self.err_msg_dic["serverinternal"],
                "Unexpected enrollment result format",
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
                url.replace(f'{self.server_name}{self.path_dic["cert_path"]}', ""),
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
            certificate_name = ""
            success = False

        if not success:
            error_msg = f"Failed to store CSR for order {order_name}"
            self.logger.error(error_msg)

        self.logger.debug(
            "Certificate.store_certificate_signing_request() ended successfully"
        )
        return certificate_name

    # === Legacy API Compatibility ===
    # Legacy methods for backward compatibility - use descriptive methods instead

    def enroll_and_store(
        self, certificate_name: str, csr: str, order_name: str = None
    ) -> Tuple[str, str]:
        """Legacy API compatibility - use process_certificate_enrollment_request instead."""
        self.logger.debug("Certificate.enroll_and_store() called - legacy API")
        return self.process_certificate_enrollment_request(
            certificate_name, csr, order_name
        )

    def new_get(self, url: str) -> Dict[str, str]:
        """Legacy API compatibility - use get_certificate_details instead."""
        self.logger.debug("Certificate.new_get() called - legacy API")
        return self.get_certificate_details(url)

    def new_post(self, content: str) -> Dict[str, str]:
        """Legacy API compatibility - use process_certificate_request instead."""
        self.logger.debug("Certificate.new_post() called - legacy API")
        return self.process_certificate_request(content)

    def revoke(self, content: str) -> Dict[str, str]:
        """Legacy API compatibility - use revoke_certificate instead."""
        self.logger.debug("Certificate.revoke() called - legacy API")
        return self.revoke_certificate(content)

    def poll(
        self, certificate_name: str, poll_identifier: str, csr: str, order_name: str
    ) -> int:
        """Legacy API compatibility - use poll_certificate_status instead."""
        self.logger.debug("Certificate.poll() called - legacy API")
        return self.poll_certificate_status(
            certificate_name, poll_identifier, csr, order_name
        )

    def store_csr(self, order_name: str, csr: str, header_info: str) -> str:
        """Legacy API compatibility - use store_certificate_signing_request instead."""
        self.logger.debug("Certificate.store_csr() called - legacy API")
        return self.store_certificate_signing_request(order_name, csr, header_info)
