# -*- coding: utf-8 -*-
"""Order class"""
from __future__ import print_function
import json
import copy
from typing import Any, List, Tuple, Dict
from dataclasses import dataclass, field
from acme_srv.helper import (
    b64_url_recode,
    config_profile_load,
    error_dic_get,
    generate_random_string,
    load_config,
    parse_url,
    uts_to_date_utc,
    uts_now,
    validate_identifier,
)
from acme_srv.certificate import Certificate
from acme_srv.db_handler import DBstore
from acme_srv.message import Message


class OrderDatabaseError(Exception):
    """Exception raised for database-related errors in Order operations."""

    # pylint: disable=unnecessary-pass
    pass


class OrderValidationError(Exception):
    """Exception raised for validation errors in Order operations."""

    # pylint: disable=unnecessary-pass
    pass


class OrderRepository:
    """Repository for all Order-related database operations."""

    def __init__(self, dbstore):
        self.dbstore = dbstore

    def add_order(self, data_dic):
        """Add a new order to the database."""
        try:
            return self.dbstore.order_add(data_dic)
        except Exception as err:
            raise OrderDatabaseError(f"Failed to add order: {err}") from err

    def add_authorization(self, auth):
        """Add a new authorization to the database."""
        try:
            return self.dbstore.authorization_add(auth)
        except Exception as err:
            raise OrderDatabaseError(f"Failed to add authorization: {err}") from err

    def update_authorization(self, auth):
        """Update an existing authorization in the database."""
        try:
            return self.dbstore.authorization_update(auth)
        except Exception as err:
            raise OrderDatabaseError(f"Failed to update authorization: {err}") from err

    def order_lookup(self, key, value):
        """Look up an order in the database."""
        try:
            return self.dbstore.order_lookup(key, value)
        except Exception as err:
            raise OrderDatabaseError(f"Failed to look up order: {err}") from err

    def order_update(self, data_dic):
        """Update an existing order in the database."""
        try:
            return self.dbstore.order_update(data_dic)
        except Exception as err:
            raise OrderDatabaseError(f"Failed to update order: {err}") from err

    def authorization_lookup(self, key, value, fields):
        """Look up an authorization in the database."""
        try:
            return self.dbstore.authorization_lookup(key, value, fields)
        except Exception as err:
            raise OrderDatabaseError(f"Failed to look up authorization: {err}") from err

    def certificate_lookup(self, key, value):
        """Look up a certificate in the database."""
        try:
            return self.dbstore.certificate_lookup(key, value)
        except Exception as err:
            raise OrderDatabaseError(f"Failed to look up certificate: {err}") from err

    def hkparameter_get(self, param):
        """Get a hkparameter from the database."""
        try:
            return self.dbstore.hkparameter_get(param)
        except Exception as err:
            raise OrderDatabaseError(f"Failed to get hkparameter: {err}") from err

    def orders_invalid_search(self, order_field, timestamp, vlist, operant):
        """Search for invalid orders in the database."""
        try:
            return self.dbstore.orders_invalid_search(
                order_field, timestamp, vlist=vlist, operant=operant
            )
        except Exception as err:
            raise OrderDatabaseError(
                f"Failed to search for invalid orders: {err}"
            ) from err


@dataclass
class OrderConfiguration:
    """Configuration parameters for Order handling"""

    validity: int = 86400
    authz_validity: int = 86400
    expiry_check_disable: bool = False
    retry_after: int = 600
    tnauthlist_support: bool = False
    email_identifier_support: bool = False
    email_identifier_rewrite: bool = False
    sectigo_sim: bool = False
    identifier_limit: int = 20
    header_info_list: List[Any] = field(default_factory=list)
    profiles: Dict[str, Any] = field(default_factory=dict)
    profiles_sync: bool = False
    profiles_check_disable: bool = True
    idempotent_finalize: bool = False


class Order(object):
    """class for order handling"""

    def __init__(
        self, debug: bool = None, server_name: str = None, logger: object = None
    ) -> None:
        """Initialize the Order handler"""
        self.debug = debug
        self.server_name = server_name
        self.config = OrderConfiguration()
        self.logger = logger
        self.dbstore = DBstore(self.debug, self.logger)
        self.path_dic = {
            "authz_path": "/acme/authz/",
            "order_path": "/acme/order/",
            "cert_path": "/acme/cert/",
        }
        self.repository = OrderRepository(self.dbstore)
        self.message = Message(self.debug, self.server_name, self.logger)
        self.error_msg_dic = error_dic_get(self.logger)

    def __enter__(self) -> "Order":
        """Enter the context manager, loading configuration."""
        self._load_configuration()
        return self

    def __exit__(self, *args) -> None:
        """
        Exit the context manager. (No-op, placeholder for cleanup.)
        """

    def _add_authorizations_to_db(
        self, oid: str, payload: Dict[str, str], auth_dic: Dict[str, str]
    ) -> str:
        """Add authorizations to the database for the given order id. Returns error message or None."""
        self.logger.debug("Order._add_authorizations_to_db(%s)", oid)

        if oid:
            error = None
            for auth in payload["identifiers"]:
                auth_name = generate_random_string(self.logger, 12)
                auth_dic[auth_name] = auth.copy()
                auth["name"] = auth_name
                auth["order"] = oid
                auth["status"] = "pending"
                auth["expires"] = uts_now() + self.config.authz_validity
                try:
                    self.repository.add_authorization(auth)
                    if self.config.sectigo_sim:
                        auth["status"] = "valid"
                        self.repository.update_authorization(auth)
                except OrderDatabaseError as err_:
                    self.logger.critical(
                        "Database error: failed to add authorization: %s", err_
                    )
        else:
            error = self.error_msg_dic["malformed"]

        self.logger.debug("Order._add_authorizations_to_db() ended with %s", error)
        return error

    def is_profile_valid(self, profile: str) -> str:
        """Check if the given profile is valid."""
        self.logger.debug("Order.is_profile_valid(%s)", profile)
        error = self.error_msg_dic["invalidprofile"]
        if self.config.profiles_check_disable:
            self.logger.debug("Order.is_profile_valid(): profile check disabled")
            error = None
        else:
            if profile in self.config.profiles:
                error = None
            else:
                self.logger.warning(
                    "Profile '%s' is not valid. Ignoring submitted profile.", profile
                )
        self.logger.debug("Order.is_profile_valid() ended with %s", error)
        return error

    def _add_order_and_authorizations(
        self,
        data_dic: Dict[str, str],
        auth_dic: Dict[str, str],
        payload: Dict[str, str],
        error: str,
    ) -> Tuple[str, Dict[str, str]]:
        """Add order and its authorizations to the database. Returns error message or None."""
        self.logger.debug("Order._add_order_and_authorizations()")

        try:
            oid = self.repository.add_order(data_dic)
        except OrderDatabaseError as err_:
            self.logger.critical("Database error: failed to add order: %s", err_)
            oid = None

        if not error:
            error = self._add_authorizations_to_db(oid, payload, auth_dic)

        self.logger.debug("Order._add_order_and_authorizations() ended with %s", error)
        return error

    def add_profile_to_order(
        self, data_dic: Dict[str, str], payload: Dict[str, str]
    ) -> Tuple[str, Dict[str, str]]:
        """Add a profile to the order if valid."""
        self.logger.debug("Order.add_profile_to_order(%s)", data_dic)
        error = self.is_profile_valid(payload["profile"])
        if not error:
            if self.config.profiles:
                data_dic["profile"] = payload["profile"]
            else:
                self.logger.warning(
                    "Ignore submitted profile '%s' as no profiles are configured.",
                    payload["profile"],
                )
        self.logger.debug("Order.add_profile_to_order() ended with %s", error)
        return error, data_dic

    def create_order(
        self, payload: Dict[str, str], account_name: str
    ) -> Tuple[str, str, Dict[str, str], int]:
        """Create a new order and add it to the database."""
        self.logger.debug("Order.create_order(%s)", account_name)

        error = None
        auth_dic = {}
        order_name = generate_random_string(self.logger, 12)
        expires = uts_now() + self.config.validity

        if "identifiers" in payload:
            data_dic = {"status": 2, "expires": expires, "account": account_name}
            data_dic["name"] = order_name
            data_dic["identifiers"] = json.dumps(payload["identifiers"])
            error = self._check_identifiers_validity(payload["identifiers"])
            if error:
                data_dic["status"] = 1
            else:
                if "profile" in payload:
                    (error, data_dic) = self.add_profile_to_order(data_dic, payload)
            error = self._add_order_and_authorizations(
                data_dic, auth_dic, payload, error
            )
        else:
            error = self.error_msg_dic["unsupportedidentifier"]

        self.logger.debug("Order.create_order() ended")
        return (error, order_name, auth_dic, uts_to_date_utc(expires))

    def _load_header_info_config(self, config_dic: Dict[str, str]):
        """Load header info list from config file."""
        self.logger.debug("Order._load_header_info_config()")
        if "Order" in config_dic and "header_info_list" in config_dic["Order"]:
            try:
                self.config.header_info_list = json.loads(
                    config_dic["Order"]["header_info_list"]
                )
            except Exception as err_:
                self.logger.warning(
                    "Failed to parse header_info_list from configuration: %s",
                    err_,
                )
        self.logger.debug("Order._load_header_info_config() ended")

    def _load_order_config(self, config_dic: Dict[str, str]):
        """Load order-related configuration from file."""
        self.logger.debug("Order._load_order_config()")
        if "Challenge" in config_dic:
            self.config.sectigo_sim = config_dic.getboolean(
                "Challenge", "sectigo_sim", fallback=False
            )
        if "Order" in config_dic:
            self.config.tnauthlist_support = config_dic.getboolean(
                "Order", "tnauthlist_support", fallback=False
            )
            self.config.email_identifier_support = config_dic.getboolean(
                "Order", "email_identifier_support", fallback=False
            )
            self.config.email_identifier_rewrite = config_dic.getboolean(
                "Order", "email_identifier_rewrite", fallback=False
            )
            self.config.expiry_check_disable = config_dic.getboolean(
                "Order", "expiry_check_disable", fallback=False
            )
            self.config.idempotent_finalize = config_dic.getboolean(
                "Order", "idempotent_finalize", fallback=False
            )
            try:
                self.config.retry_after = int(
                    config_dic.get(
                        "Order", "retry_after_timeout", fallback=self.config.retry_after
                    )
                )
            except Exception:
                self.logger.warning(
                    "Failed to parse retry_after from configuration: %s",
                    config_dic["Order"].get("retry_after_timeout", None),
                )
            try:
                self.config.validity = int(
                    config_dic.get("Order", "validity", fallback=self.config.validity)
                )
            except Exception:
                self.logger.warning(
                    "Failed to parse validity from configuration: %s",
                    config_dic["Order"].get("validity", None),
                )
            try:
                self.config.identifier_limit = int(
                    config_dic.get("Order", "identifier_limit", fallback=20)
                )
            except Exception:
                self.logger.warning(
                    "Failed to parse identifier_limit from configuration: %s",
                    config_dic["Order"].get("identifier_limit", None),
                )
        self.logger.debug("Order._load_order_config() ended")

    def _load_profile_config(self, config_dic: Dict[str, str]):
        """Load profiles from file or database."""
        self.logger.debug("Order._load_profile_config()")
        self._load_profiles_from_config(config_dic)
        self._load_profiles_from_db_if_sync(config_dic)
        self._maybe_disable_profile_check(config_dic)
        self.logger.debug("Order._load_profile_config() ended")

    def _load_profiles_from_config(self, config_dic: Dict[str, str]):
        """Load profiles from configuration file."""
        if "Order" in config_dic and "profiles" in config_dic["Order"]:
            self.logger.debug("Order._config_load(): profile check enabled")
            self.config.profiles_check_disable = False
            self.config.profiles = config_profile_load(self.logger, config_dic)

    def _load_profiles_from_db_if_sync(self, config_dic: Dict[str, str]):
        """Load profiles from database if profiles_sync is set."""
        if "CAhandler" in config_dic and "profiles_sync" in config_dic["CAhandler"]:
            self.config.profiles_sync = config_dic.getboolean(
                "CAhandler", "profiles_sync", fallback=False
            )
            if self.config.profiles_sync:
                self.logger.debug(
                    "Order._config_load(): profile_sync set. Loading profiles"
                )
                try:
                    profiles = self.repository.hkparameter_get("profiles")
                except OrderDatabaseError as err:
                    self.logger.critical(
                        "Database error: failed to get profile list: %s", err
                    )
                    profiles = None
                if profiles:
                    self._set_profiles_from_db(profiles)

    def _set_profiles_from_db(self, profiles):
        """Set profiles from database string."""
        try:
            profile_dic = json.loads(profiles)
            self.config.profiles = profile_dic.get("profiles", {})
        except Exception as err_:
            self.logger.error(
                "Error when loading the profiles parameter from database: %s", err_
            )

    def _maybe_disable_profile_check(self, config_dic: Dict[str, str]):
        """Disable profile check"""
        if self.config.profiles and "Order" in config_dic:
            self.config.profiles_check_disable = config_dic.getboolean(
                "Order", "profiles_check_disable", fallback=False
            )

    def _load_configuration(self):
        """Load all configuration from file."""
        self.logger.debug("Order._load_configuration()")
        config_dic = load_config()
        # load order config
        self._load_order_config(config_dic)
        self._load_header_info_config(config_dic)
        if "Authorization" in config_dic:
            try:
                self.config.authz_validity = int(
                    config_dic.get(
                        "Authorization", "validity", fallback=self.config.authz_validity
                    )
                )
            except Exception:
                self.logger.warning(
                    "Failed to parse authz validity from configuration: %s",
                    config_dic["Authorization"].get("validity", None),
                )
        if "Directory" in config_dic and "url_prefix" in config_dic["Directory"]:
            self.path_dic = {
                k: config_dic["Directory"]["url_prefix"] + v
                for k, v in self.path_dic.items()
            }
        self._load_profile_config(config_dic)
        self.logger.debug("Order._config_load() ended.")

    def _name_get(self, url: str) -> str:
        """get ordername"""
        self.logger.debug("Order._name_get(%s)", url)

        url_dic = parse_url(self.logger, url)
        order_name = url_dic["path"].replace(self.path_dic["order_path"], "")
        if "/" in order_name:
            (order_name, _sinin) = order_name.split("/", 1)
        self.logger.debug("Order._name_get() ended")
        return order_name

    def are_identifiers_allowed(self, identifiers_list: List[str]) -> bool:
        """Check if the provided identifiers are allowed."""
        self.logger.debug("Order.are_identifiers_allowed()")
        error = None
        allowed_identifers = ["dns", "ip"]
        if self.config.tnauthlist_support:
            allowed_identifers.append("tnauthlist")
        if self.config.email_identifier_support:
            allowed_identifers.append("email")
        for identifier in identifiers_list:
            if "type" in identifier:
                # pylint: disable=R1723
                if identifier["type"].lower() not in allowed_identifers:
                    error = self.error_msg_dic["unsupportedidentifier"]
                    break
                else:
                    if not validate_identifier(
                        self.logger,
                        identifier["type"].lower(),
                        identifier["value"],
                        self.config.tnauthlist_support,
                    ):
                        error = self.error_msg_dic["rejectedidentifier"]
                        break
            else:
                error = self.error_msg_dic["malformed"]
        self.logger.debug("Order.are_identifiers_allowed() ended with: %s", error)
        return error

    def _rewrite_email_identifiers(
        self, identifiers_list: List[Dict[str, str]]
    ) -> List[Dict[str, str]]:
        """Rewrite DNS identifiers with @ to email identifiers."""
        self.logger.debug("Order._rewrite_email_identifiers()")
        identifiers_modified = []
        for ident in identifiers_list:
            if (
                "type" in ident
                and "value" in ident
                and ident["type"].lower() == "dns"
                and "@" in ident["value"]
            ):
                self.logger.info(
                    "Rewrite DNS identifier '%s' to email identifier",
                    ident["value"],
                )
                ident["type"] = "email"
            identifiers_modified.append(ident)
        self.logger.debug("Order._rewrite_email_identifiers() ended")
        return identifiers_modified

    def _check_identifiers_validity(self, identifiers_list: List[str]) -> str:
        """Check validity of identifiers in the order."""
        self.logger.debug("Order._check_identifiers_validity(%s)", identifiers_list)
        identifiers_list = copy.deepcopy(identifiers_list)
        if identifiers_list and isinstance(identifiers_list, list):
            if len(identifiers_list) > self.config.identifier_limit:
                error = self.error_msg_dic["rejectedidentifier"]
                self.logger.warning("Number of identifiers %d exceeds limit %d", len(identifiers_list), self.config.identifier_limit)
            else:
                if (
                    self.config.email_identifier_support
                    and self.config.email_identifier_rewrite
                ):
                    identifiers_list = self._rewrite_email_identifiers(identifiers_list)
                error = self.are_identifiers_allowed(identifiers_list)
        else:
            error = self.error_msg_dic["malformed"]
        self.logger.debug("Order._check_identifiers_validity() done with %s:", error)
        return error

    def _get_order_info(self, order_name: str) -> Dict[str, str]:
        """List details of an order. Returns order dict or empty dict on error."""
        self.logger.debug("Order._get_order_info(%s)", order_name)
        try:
            result = self.repository.order_lookup("name", order_name)
        except OrderDatabaseError as err_:
            self.logger.critical("Database error: failed to look up order: %s", err_)
            result = None
        return result

    def _header_info_lookup(self, header: str) -> str:
        """lookup header information and serialize them in a string"""
        self.logger.debug("Order._header_info_lookup()")

        header_info_dic = {}
        if header and self.config.header_info_list:
            for ele in self.config.header_info_list:
                if ele in header:
                    header_info_dic[ele] = header[ele]

        result = None
        if header_info_dic:
            result = json.dumps(header_info_dic)

        self.logger.debug(
            "Order._header_info_lookup() ended with: %s keys in dic",
            len(header_info_dic.keys()),
        )
        return result

    def _finalize_csr(
        self, order_name: str, payload: Dict[str, str], header: str = None
    ) -> Tuple[int, str, str, str]:
        """Handle CSR finalization for an order"""
        self.logger.debug("Order._finalize_csr(%s)", order_name)

        message = None
        # lookup header information
        header_info = self._header_info_lookup(header)
        # this is a new request
        (code, certificate_name, detail) = self._process_csr(
            order_name, payload["csr"], header_info
        )
        # change status only if we do not have a poll_identifier (stored in detail variable)
        if code == 200:
            if not detail:
                # update order_status / set to valid
                self.repository.order_update({"name": order_name, "status": "valid"})
        elif certificate_name == "timeout":
            code = 200
            message = certificate_name
        elif certificate_name == "urn:ietf:params:acme:error:rejectedIdentifier":
            code = 401
            message = certificate_name
        else:
            message = certificate_name
            detail = "enrollment failed"

        self.logger.debug("Order._finalize_csr() ended")
        return (code, message, detail, certificate_name)

    def _finalize_order(
        self, order_name: str, payload: Dict[str, str], header: str = None
    ) -> Tuple[int, str, str, str]:
        """finalize request"""
        self.logger.debug("Order._finalize_order()")

        certificate_name = None
        message = None
        detail = None

        # lookup order-status (must be ready to proceed)
        order_dic = self._get_order_info(order_name)
        if "status" in order_dic and order_dic["status"] == "ready":
            # update order_status / set to processing
            self.repository.order_update({"name": order_name, "status": "processing"})
            if "csr" in payload:
                (code, message, detail, certificate_name) = self._finalize_csr(
                    order_name, payload, header
                )
            else:
                code = 400
                message = self.error_msg_dic["badcsr"]
                detail = "csr is missing in payload"
        elif (
            "status" in order_dic
            and order_dic["status"] == "valid"
            and self.config.idempotent_finalize
        ):
            self.logger.debug(
                "Order._finalize_order(): kind of polling request - order is already valid - lookup certificate"
            )
            code = 200
            try:
                cert_dic = self.repository.certificate_lookup("order__name", order_name)
            except OrderDatabaseError as err_:
                self.logger.critical(
                    "Database error: Certificate lookup failed: %s", err_
                )
                cert_dic = {}
            if cert_dic:
                if "name" in cert_dic:
                    certificate_name = cert_dic["name"]
        else:
            code = 403
            message = self.error_msg_dic["ordernotready"]
            detail = "Order is not ready"

        self.logger.debug("Order._finalize_order() ended")
        return (code, message, detail, certificate_name)

    def _process_order_request(
        self,
        order_name: str,
        protected: Dict[str, str],
        payload: Dict[str, str],
        header: str = None,
    ) -> Tuple[int, str, str, str]:
        """process order"""
        self.logger.debug("Order._process_order_request({%s)", order_name)

        certificate_name = None
        message = None
        detail = None

        if "url" in protected:
            if "finalize" in protected["url"]:
                (code, message, detail, certificate_name) = self._finalize_order(
                    order_name, payload, header
                )
            else:
                self.logger.debug("polling request()")
                code = 200
                try:
                    cert_dic = self.repository.certificate_lookup(
                        "order__name", order_name
                    )
                except OrderDatabaseError as err_:
                    self.logger.critical(
                        "Database error: Certificate lookup failed: %s", err_
                    )
                    cert_dic = {}
                if cert_dic:
                    if "name" in cert_dic:
                        certificate_name = cert_dic["name"]
        else:
            code = 400
            message = self.error_msg_dic["malformed"]
            detail = "url is missing in protected"

        self.logger.debug(
            "Order._process_order_request() ended with order:%s %s:%s:%s",
            order_name,
            code,
            message,
            detail,
        )
        return (code, message, detail, certificate_name)

    def _process_csr(
        self, order_name: str, csr: str, header_info: str
    ) -> Tuple[int, str, str]:
        """process certificate signing request"""
        self.logger.debug("Order._process_csr(%s)", order_name)

        order_dic = self._get_order_info(order_name)
        if order_dic:
            # change decoding from b64url to b64
            csr = b64_url_recode(self.logger, csr)

            with Certificate(self.debug, self.server_name, self.logger) as certificate:
                certificate_name = certificate.store_csr(order_name, csr, header_info)
                if certificate_name:
                    (error, detail) = certificate.enroll_and_store(
                        certificate_name, csr, order_name
                    )
                    if not error:
                        code = 200
                        message = certificate_name
                    elif error == "urn:ietf:params:acme:error:rejectedIdentifier":
                        code = 401
                        message = error
                    else:
                        code = 400
                        message = error
                        if message == self.error_msg_dic["serverinternal"]:
                            code = 500
                else:
                    code = 500
                    message = self.error_msg_dic["serverinternal"]
                    detail = "CSR processing failed"
        else:
            code = 400
            message = self.error_msg_dic["unauthorized"]
            detail = f"order: {order_name} not found"

        self.logger.debug(
            "Order._process_csr() ended with order:%s %s:{%s:%s",
            order_name,
            code,
            message,
            detail,
        )
        return (code, message, detail)

    def _order_dic_create(self, tmp_dic: Dict[str, str]) -> Dict[str, str]:
        """create order dictionary"""
        self.logger.debug("Order._order_dic_create()")

        order_dic = {}
        if "status" in tmp_dic:
            order_dic["status"] = tmp_dic["status"]
        if "expires" in tmp_dic:
            order_dic["expires"] = uts_to_date_utc(tmp_dic["expires"])
        if "notbefore" in tmp_dic and tmp_dic["notbefore"] != 0:
            order_dic["notBefore"] = uts_to_date_utc(tmp_dic["notbefore"])
        if "notafter" in tmp_dic and tmp_dic["notafter"] != 0:
            order_dic["notAfter"] = uts_to_date_utc(tmp_dic["notafter"])
        if "identifiers" in tmp_dic:
            try:
                order_dic["identifiers"] = json.loads(tmp_dic["identifiers"])
            except Exception:
                self.logger.error(
                    "Error while parsing the identifier %s",
                    tmp_dic["identifiers"],
                )

        self.logger.debug("Order._order_dic_create() ended")
        return order_dic

    def _get_authorization_list(self, order_name: str) -> List[str]:
        """Lookup authorization list. Returns list or empty list on error."""
        self.logger.debug("Order._get_authorization_list(%s)", order_name)
        try:
            authz_list = self.repository.authorization_lookup(
                "order__name", order_name, ["name", "status__name"]
            )
        except OrderDatabaseError as err_:
            self.logger.critical(
                "Database error: failed to look up authorization list: %s", err_
            )
            authz_list = []
        self.logger.debug("Order._get_authorization_list() ended")
        return authz_list

    def _update_validity_list(
        self, authz_list: List[str], order_dic: Dict[str, str], order_name: str
    ):
        """update validity list and order status"""
        self.logger.debug("Order._update_validity_list()")
        validity_list = []
        for authz in authz_list:
            if "name" in authz:
                order_dic["authorizations"].append(
                    f'{self.server_name}{self.path_dic["authz_path"]}{authz["name"]}'
                )
            if "status__name" in authz:
                if authz["status__name"] == "valid":
                    validity_list.append(True)
                else:
                    validity_list.append(False)

        # update orders status from pending to ready
        if validity_list and "status" in order_dic:
            if False not in validity_list and order_dic["status"] == "pending":
                self.repository.order_update({"name": order_name, "status": "ready"})

        self.logger.debug("Order.get_order_details() ended")

    def get_order_details(self, order_name: str) -> Dict[str, str]:
        """Show order details based on order name."""
        self.logger.debug("Order.get_order_details(%s)", order_name)

        order_dic = {}
        tmp_dic = self._get_order_info(order_name)
        if tmp_dic:
            # create order dictionary and lookup authorization list
            order_dic = self._order_dic_create(tmp_dic)
            authz_list = self._get_authorization_list(order_name)
            if authz_list:
                order_dic["authorizations"] = []
                # collect status of different authorizations in list and update order status
                self._update_validity_list(authz_list, order_dic, order_name)
        self.logger.debug("Order.get_order_details() ended")
        return order_dic

    def invalidate_expired_orders(
        self, timestamp: int = None
    ) -> Tuple[List[str], List[str]]:
        """Invalidate orders that have expired."""
        self.logger.debug("Order.invalidate_expired_orders(%s)", timestamp)

        if not timestamp:
            timestamp = uts_now()
            self.logger.debug(
                "Order.invalidate_expired_orders(): set timestamp to %s", timestamp
            )

        field_list = [
            "id",
            "name",
            "expires",
            "identifiers",
            "created_at",
            "status__id",
            "status__name",
            "account__id",
            "account__name",
            "account__contact",
        ]
        try:
            order_list = self.repository.orders_invalid_search(
                "expires", timestamp, vlist=field_list, operant="<="
            )
        except OrderDatabaseError as err_:
            self.logger.critical(
                "Database error: failed to search for expired orders: %s", err_
            )
            order_list = []
        output_list = []
        for order in order_list:
            # select all orders which are not invalid
            if (
                "name" in order
                and "status__name" in order
                and order["status__name"] != "invalid"
            ):
                # change status and add to output list
                output_list.append(order)
                data_dic = {"name": order["name"], "status": "invalid"}
                try:
                    self.repository.order_update(data_dic)
                except OrderDatabaseError as err_:
                    self.logger.critical(
                        "Database error: failed to update order status to invalid: %s",
                        err_,
                    )

        self.logger.debug(
            "Order.invalidate_expired_orders() ended: %s orders identified",
            len(output_list),
        )
        return (field_list, output_list)

    def create_from_content(self, content: str) -> Dict[str, str]:
        """new order request (renamed from new)"""
        self.logger.debug("Order.create_from_content()")

        response_dic = {}
        # check message
        (code, message, detail, _protected, payload, account_name) = self.message.check(
            content
        )

        if code == 200:
            (error, order_name, auth_dic, expires) = self.create_order(
                payload, account_name
            )
            if not error:
                code = 201
                response_dic["header"] = {}
                response_dic["header"][
                    "Location"
                ] = f'{self.server_name}{self.path_dic["order_path"]}{order_name}'
                response_dic["data"] = {}
                response_dic["data"]["identifiers"] = []
                response_dic["data"]["authorizations"] = []
                response_dic["data"]["status"] = "pending"
                response_dic["data"]["expires"] = expires
                response_dic["data"][
                    "finalize"
                ] = f'{self.server_name}{self.path_dic["order_path"]}{order_name}/finalize'
                for auth_name, value in auth_dic.items():
                    response_dic["data"]["authorizations"].append(
                        f'{self.server_name}{self.path_dic["authz_path"]}{auth_name}'
                    )
                    response_dic["data"]["identifiers"].append(value)
            elif error == self.error_msg_dic["rejectedidentifier"]:
                code = 403
                message = error
                detail = "Some of the requested identifiers got rejected"
            else:
                code = 400
                message = error
                detail = "Could not process order"

        # prepare/enrich response
        status_dic = {"code": code, "type": message, "detail": detail}
        response_dic = self.message.prepare_response(response_dic, status_dic)

        self.logger.debug(
            "Order.create_from_content() returns: %s", json.dumps(response_dic)
        )
        return response_dic

    def _parse_order_message(
        self, protected: Dict[str, str], payload: Dict[str, str], header: str = None
    ) -> Tuple[int, str, str, str, str]:
        """parse new order message"""
        self.logger.debug("Order._parse_order_message()")

        order_name = certificate_name = None

        if "url" in protected:
            order_name = self._name_get(protected["url"])
            if order_name:
                order_dic = self.get_order_details(order_name)
                if order_dic:
                    (
                        code,
                        message,
                        detail,
                        certificate_name,
                    ) = self._process_order_request(
                        order_name, protected, payload, header
                    )
                else:
                    code = 403
                    message = self.error_msg_dic["ordernotready"]
                    detail = "order not found"
            else:
                code = 400
                message = self.error_msg_dic["malformed"]
                detail = "order name is missing"
        else:
            code = 400
            message = self.error_msg_dic["malformed"]
            detail = "url is missing in protected"

        self.logger.debug("Order._parse_order_message() ended with code: %s", code)
        return (code, message, detail, certificate_name, order_name)

    def parse_order_content(self, content: str, header: str = None) -> Dict[str, str]:
        """parse order request (renamed from parse)"""
        self.logger.debug("Order.parse_order_content()")

        # invalidate expired orders
        if not self.config.expiry_check_disable:
            self.invalidate_expired_orders()

        response_dic = {}
        # check message
        (code, message, detail, protected, payload, _account_name) = self.message.check(
            content
        )

        if code == 200:
            # parse message
            (
                code,
                message,
                detail,
                certificate_name,
                order_name,
            ) = self._parse_order_message(protected, payload, header)

            if code == 200:
                # create response
                response_dic["header"] = {}
                response_dic["header"][
                    "Location"
                ] = f'{self.server_name}{self.path_dic["order_path"]}{order_name}'
                response_dic["data"] = self.get_order_details(order_name)
                if (
                    "status" in response_dic["data"]
                    and response_dic["data"]["status"] == "processing"
                ):
                    # set retry header as cert issuane is not completed.
                    response_dic["header"]["Retry-After"] = f"{self.config.retry_after}"
                response_dic["data"][
                    "finalize"
                ] = f'{self.server_name}{self.path_dic["order_path"]}{order_name}/finalize'
                # add the path to certificate if order-status is ready
                if (
                    certificate_name
                    and "status" in response_dic["data"]
                    and response_dic["data"]["status"] == "valid"
                ):
                    response_dic["data"][
                        "certificate"
                    ] = f'{self.server_name}{self.path_dic["cert_path"]}{certificate_name}'

        # prepare/enrich response
        status_dic = {"code": code, "type": message, "detail": detail}
        response_dic = self.message.prepare_response(response_dic, status_dic)

        self.logger.debug(
            "Order.parse_order_content() returns: %s", json.dumps(response_dic)
        )
        return response_dic

    # === Legacy API Compatibility ===

    def invalidate(self, timestamp: int = None) -> Tuple[List[str], List[str]]:
        """invalidate orders"""
        self.logger.debug(
            "Order.invalidate() - Compatibility wrapper for old method name"
        )
        return self.invalidate_expired_orders(timestamp)

    def new(self, content: str) -> Dict[str, str]:
        """new order request"""
        self.logger.debug("Order.new() - Compatibility wrapper for old method name")
        return self.create_from_content(content)

    def parse(self, content: str, header: str = None) -> Dict[str, str]:
        """parse order request"""
        self.logger.debug("Order.parse() - Compatibility wrapper for old method name")
        return self.parse_order_content(content, header)
