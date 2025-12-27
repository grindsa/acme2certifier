# -*- coding: utf-8 -*-
"""Order class"""
from __future__ import print_function
import json
import copy
from typing import List, Tuple, Dict
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


class Order(object):
    """class for order handling"""

    def __init__(self, debug: bool = None, srv_name: str = None, logger: object = None):
        self.server_name = srv_name
        self.debug = debug
        self.logger = logger
        self.dbstore = DBstore(self.debug, self.logger)
        self.message = Message(self.debug, self.server_name, self.logger)
        self.error_msg_dic = error_dic_get(self.logger)
        self.validity = 86400
        self.authz_validity = 86400
        self.expiry_check_disable = False
        self.path_dic = {
            "authz_path": "/acme/authz/",
            "order_path": "/acme/order/",
            "cert_path": "/acme/cert/",
        }
        self.retry_after = 600
        self.tnauthlist_support = False
        self.email_identifier_support = False
        self.email_identifier_rewrite = False
        self.sectigo_sim = False
        self.identifier_limit = 20
        self.header_info_list = []
        self.profiles = {}
        self.profiles_sync = False
        # turn off check by default
        self.profiles_check_disable = True
        self.idempotent_finalize = False

    def __enter__(self):
        """Makes ACMEHandler a Context Manager"""
        self._config_load()
        return self

    def __exit__(self, *args):
        """cose the connection at the end of the context"""

    def _auth_add(
        self, oid: str, payload: Dict[str, str], auth_dic: Dict[str, str]
    ) -> str:
        self.logger.debug("Order._auth_add(%s)", oid)

        if oid:
            error = None
            for auth in payload["identifiers"]:
                # generate name
                auth_name = generate_random_string(self.logger, 12)
                # store to return to upper func
                auth_dic[auth_name] = auth.copy()
                auth["name"] = auth_name
                auth["order"] = oid
                auth["status"] = "pending"
                auth["expires"] = uts_now() + self.authz_validity
                try:
                    self.dbstore.authorization_add(auth)
                    if self.sectigo_sim:
                        auth["status"] = "valid"
                        self.dbstore.authorization_update(auth)
                except Exception as err_:
                    self.logger.critical(
                        "Database error: failed to add authorization: %s", err_
                    )
        else:
            error = self.error_msg_dic["malformed"]

        self.logger.debug("Order._auth_add() ended with %s", error)
        return error

    def _profile_check(self, profile: str) -> str:
        """check if profile is valid"""
        self.logger.debug("Order._profile_check(%s)", profile)

        error = self.error_msg_dic["invalidprofile"]
        if self.profiles_check_disable:
            self.logger.debug("Order._profile_check(): profile check disabled")
            error = None
        else:
            # profie check is enabled
            if profile in self.profiles:
                # check if profile is valid
                error = None
            else:
                # profile is not valid
                self.logger.warning(
                    "Profile '%s' is not valid. Ignoring submitted profile.", profile
                )

        self.logger.debug("Order._profile_check() ended with %s", error)
        return error

    def _order_auth_add(
        self,
        data_dic: Dict[str, str],
        auth_dic: Dict[str, str],
        payload: Dict[str, str],
        error: str,
    ) -> Tuple[str, Dict[str, str]]:
        """add order and authorization to database"""
        self.logger.debug("Order._order_auth_add()")

        try:
            # add order to db
            oid = self.dbstore.order_add(data_dic)
        except Exception as err_:
            self.logger.critical("Database error: failed to add order: %s", err_)
            oid = None

        if not error:
            # authorization add
            error = self._auth_add(oid, payload, auth_dic)

        self.logger.debug("Order._order_auth_add() ended with %s", error)
        return error

    def _profile_add(
        self, data_dic: Dict[str, str], payload: Dict[str, str]
    ) -> Tuple[str, Dict[str, str]]:
        """add profile to database"""
        self.logger.debug("Order._profile_add(%s)", data_dic)

        # check if profile is valid
        error = self._profile_check(payload["profile"])
        if not error:
            if self.profiles:
                # add profile to order
                data_dic["profile"] = payload["profile"]
            else:
                # profile check is enabled but no profiles are configured
                self.logger.warning(
                    "Ignore submitted profile '%s' as no profiles are configured.",
                    payload["profile"],
                )

        self.logger.debug("Order._profile_add() ended with %s", error)
        return error, data_dic

    def _add(
        self, payload: Dict[str, str], aname: str
    ) -> Tuple[str, str, Dict[str, str], int]:
        """add order request"""
        self.logger.debug("Order._add(%s)", aname)

        error = None
        auth_dic = {}
        order_name = generate_random_string(self.logger, 12)
        expires = uts_now() + self.validity

        if "identifiers" in payload:

            data_dic = {"status": 2, "expires": expires, "account": aname}

            data_dic["name"] = order_name
            data_dic["identifiers"] = json.dumps(payload["identifiers"])

            # check identifiers
            error = self._identifiers_check(payload["identifiers"])

            # change order status if needed
            if error:
                data_dic["status"] = 1
            else:
                if "profile" in payload:
                    # check if profile is valid
                    (error, data_dic) = self._profile_add(data_dic, payload)

            # add order and authorization to database
            error = self._order_auth_add(data_dic, auth_dic, payload, error)

        else:
            error = self.error_msg_dic["unsupportedidentifier"]

        self.logger.debug("Order._add() ended")
        return (error, order_name, auth_dic, uts_to_date_utc(expires))

    def _config_headerinfo_config_load(self, config_dic: Dict[str, str]):
        """ " load config from file"""
        self.logger.debug("Order._config_headerinfo_config_load()")

        if "Order" in config_dic and "header_info_list" in config_dic["Order"]:
            try:
                self.header_info_list = json.loads(
                    config_dic["Order"]["header_info_list"]
                )
            except Exception as err_:
                self.logger.warning(
                    "Failed to parse header_info_list from configuration: %s",
                    err_,
                )

        self.logger.debug("Order._config_headerinfo_config_load() ended")

    def _config_orderconfig_load(self, config_dic: Dict[str, str]):
        """ " load config from file"""
        self.logger.debug("Order._config_orderconfig_load()")

        if "Challenge" in config_dic:
            self.sectigo_sim = config_dic.getboolean(
                "Challenge", "sectigo_sim", fallback=False
            )

        if "Order" in config_dic:
            self.tnauthlist_support = config_dic.getboolean(
                "Order", "tnauthlist_support", fallback=False
            )
            self.email_identifier_support = config_dic.getboolean(
                "Order", "email_identifier_support", fallback=False
            )
            self.email_identifier_rewrite = config_dic.getboolean(
                "Order", "email_identifier_rewrite", fallback=False
            )
            self.expiry_check_disable = config_dic.getboolean(
                "Order", "expiry_check_disable", fallback=False
            )
            self.idempotent_finalize = config_dic.getboolean(
                "Order", "idempotent_finalize", fallback=False
            )
            try:
                self.retry_after = int(
                    config_dic.get(
                        "Order", "retry_after_timeout", fallback=self.retry_after
                    )
                )
            except Exception:
                self.logger.warning(
                    "Failed to parse retry_after from configuration: %s",
                    config_dic["Order"]["retry_after_timeout"],
                )
            try:
                self.validity = int(
                    config_dic.get("Order", "validity", fallback=self.validity)
                )
            except Exception:
                self.logger.warning(
                    "Failed to parse validity from configuration: %s",
                    config_dic["Order"]["validity"],
                )
            try:
                self.identifier_limit = int(
                    config_dic.get("Order", "identifier_limit", fallback=20)
                )
            except Exception:
                self.logger.warning(
                    "Failed to parse identifier_limit from configuration: %s",
                    config_dic["Order"]["identifier_limit"],
                )

        self.logger.debug("Order._config_orderconfig_load() ended")

    def _config_profile_load(self, config_dic: Dict[str, str]):
        """load profiles from file or database, refactored for clarity"""
        self.logger.debug("Order._config_profile_load()")
        self._load_profiles_from_config(config_dic)
        self._load_profiles_from_db_if_sync(config_dic)
        self._maybe_disable_profile_check(config_dic)
        self.logger.debug("Order._config_profile_load() ended")

    def _load_profiles_from_config(self, config_dic: Dict[str, str]):
        if "Order" in config_dic and "profiles" in config_dic["Order"]:
            self.logger.debug("Order._config_load(): profile check enabled")
            self.profiles_check_disable = False
            self.profiles = config_profile_load(self.logger, config_dic)

    def _load_profiles_from_db_if_sync(self, config_dic: Dict[str, str]):
        if "CAhandler" in config_dic and "profiles_sync" in config_dic["CAhandler"]:
            self.profiles_sync = config_dic.getboolean(
                "CAhandler", "profiles_sync", fallback=False
            )
            if self.profiles_sync:
                self.logger.debug(
                    "Order._config_load(): profile_sync set. Loading profiles"
                )
                profiles = self._get_profiles_from_db()
                if profiles:
                    self._set_profiles_from_db(profiles)

    def _get_profiles_from_db(self):
        try:
            return self.dbstore.hkparameter_get("profiles")
        except Exception as err:
            self.logger.critical("Database error: failed to get profile list: %s", err)
            return None

    def _set_profiles_from_db(self, profiles):
        try:
            profile_dic = json.loads(profiles)
            self.profiles = profile_dic.get("profiles", {})
        except Exception as err_:
            self.logger.error(
                "Error when loading the profiles parameter from database: %s", err_
            )

    def _maybe_disable_profile_check(self, config_dic: Dict[str, str]):
        if self.profiles and "Order" in config_dic:
            self.profiles_check_disable = config_dic.getboolean(
                "Order", "profiles_check_disable", fallback=False
            )

    def _config_load(self):
        """ " load config from file"""
        self.logger.debug("Order._config_load()")

        config_dic = load_config()
        # load order config
        self._config_orderconfig_load(config_dic)
        self._config_headerinfo_config_load(config_dic)

        if "Authorization" in config_dic:
            try:
                self.authz_validity = int(
                    config_dic.get(
                        "Authorization", "validity", fallback=self.authz_validity
                    )
                )
            except Exception:
                self.logger.warning(
                    "Failed to parse authz validity from configuration: %s",
                    config_dic["Authorization"]["validity"],
                )

        if "Directory" in config_dic and "url_prefix" in config_dic["Directory"]:
            self.path_dic = {
                k: config_dic["Directory"]["url_prefix"] + v
                for k, v in self.path_dic.items()
            }

        self._config_profile_load(config_dic)

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

    def _identifiers_allowed(self, identifiers_list: List[str]) -> bool:
        """check if identifiers are allowed"""
        self.logger.debug("Order._identifiers_allowed()")

        error = None
        allowed_identifers = ["dns", "ip"]

        # add tnauthlist to list of supported identfiers if configured to do so
        if self.tnauthlist_support:
            allowed_identifers.append("tnauthlist")
        if self.email_identifier_support:
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
                        self.tnauthlist_support,
                    ):
                        error = self.error_msg_dic["rejectedidentifier"]
                        break
            else:
                error = self.error_msg_dic["malformed"]

        self.logger.debug("Order._identifiers_allowed() ended with: %s", error)
        return error

    def _email_identifier_rewrite(
        self, identifiers_list: List[Dict[str, str]]
    ) -> List[Dict[str, str]]:
        """rewrite email identifiers to address acme_email issue"""
        self.logger.debug("Order._email_identifier_rewrite()")
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
                # rewrite dns identifier to acme_email
                ident["type"] = "email"
            identifiers_modified.append(ident)
        self.logger.debug("Order._email_identifier_rewrite() ended")
        return identifiers_modified

    def _identifiers_check(self, identifiers_list: List[str]) -> str:
        """check validity of identifers in order"""
        self.logger.debug("Order._identifiers_check(%s)", identifiers_list)

        # Create a deep copy to avoid modifying the original
        identifiers_list = copy.deepcopy(identifiers_list)

        if identifiers_list and isinstance(identifiers_list, list):
            if len(identifiers_list) > self.identifier_limit:
                error = self.error_msg_dic["rejectedidentifier"]
            else:
                if self.email_identifier_support and self.email_identifier_rewrite:
                    # rewirte email identifiers to address acme_email issue
                    identifiers_list = self._email_identifier_rewrite(identifiers_list)
                error = self._identifiers_allowed(identifiers_list)
        else:
            error = self.error_msg_dic["malformed"]

        self.logger.debug("Order._identifiers_check() done with %s:", error)
        return error

    def _info(self, order_name: str) -> Dict[str, str]:
        """list details of an order"""
        self.logger.debug("Order._info(%s)", order_name)
        try:
            result = self.dbstore.order_lookup("name", order_name)
        except Exception as err_:
            self.logger.critical("Database error: failed to look up order: %s", err_)
            result = None
        return result

    def _header_info_lookup(self, header: str) -> str:
        """lookup header information and serialize them in a string"""
        self.logger.debug("Order._header_info_lookup()")

        header_info_dic = {}
        if header and self.header_info_list:
            for ele in self.header_info_list:
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

    def _csr_finalize(
        self, order_name: str, payload: Dict[str, str], header: str = None
    ) -> Tuple[int, str, str, str]:
        """Handle CSR finalization for an order"""
        self.logger.debug("Order._csr_finalize(%s)", order_name)

        message = None

        # lookup header information
        header_info = self._header_info_lookup(header)

        # this is a new request
        (code, certificate_name, detail) = self._csr_process(
            order_name, payload["csr"], header_info
        )
        # change status only if we do not have a poll_identifier (stored in detail variable)
        if code == 200:
            if not detail:
                # update order_status / set to valid
                self._update({"name": order_name, "status": "valid"})
        elif certificate_name == "timeout":
            code = 200
            message = certificate_name
        elif certificate_name == "urn:ietf:params:acme:error:rejectedIdentifier":
            code = 401
            message = certificate_name
        else:
            message = certificate_name
            detail = "enrollment failed"

        self.logger.debug("Order._csr_finalize() ended")
        return (code, message, detail, certificate_name)

    def _finalize(
        self, order_name: str, payload: Dict[str, str], header: str = None
    ) -> Tuple[int, str, str, str]:
        """finalize request"""
        self.logger.debug("Order._finalize()")

        certificate_name = None
        message = None
        detail = None

        # lookup order-status (must be ready to proceed)
        order_dic = self._info(order_name)

        if "status" in order_dic and order_dic["status"] == "ready":
            # update order_status / set to processing
            self._update({"name": order_name, "status": "processing"})
            if "csr" in payload:
                (code, message, detail, certificate_name) = self._csr_finalize(
                    order_name, payload, header
                )
            else:
                code = 400
                message = self.error_msg_dic["badcsr"]
                detail = "csr is missing in payload"
        elif (
            "status" in order_dic
            and order_dic["status"] == "valid"
            and self.idempotent_finalize
        ):
            # this is polling request via finalize call; lookup certificate
            self.logger.debug(
                "Order._finalize(): kind of polling request - order is already valid - lookup certificate"
            )
            code = 200
            try:
                cert_dic = self.dbstore.certificate_lookup("order__name", order_name)
            except Exception as err_:
                self.logger.critical(
                    "Database error: Certificate lookup failed: %s", err_
                )
                cert_dic = {}
            if cert_dic:
                # we found a cert in the database
                # pylint: disable=R1715
                if "name" in cert_dic:
                    certificate_name = cert_dic["name"]
        else:
            code = 403
            message = self.error_msg_dic["ordernotready"]
            detail = "Order is not ready"

        self.logger.debug("Order._finalize() ended")
        return (code, message, detail, certificate_name)

    def _process(
        self,
        order_name: str,
        protected: Dict[str, str],
        payload: Dict[str, str],
        header: str = None,
    ) -> Tuple[int, str, str, str]:
        """process order"""
        self.logger.debug("Order._process({%s)", order_name)

        certificate_name = None
        message = None
        detail = None

        if "url" in protected:
            if "finalize" in protected["url"]:
                # finalize order
                (code, message, detail, certificate_name) = self._finalize(
                    order_name, payload, header
                )
            else:
                self.logger.debug("polling request()")
                code = 200
                # this is a polling request; lookup certificate
                try:
                    cert_dic = self.dbstore.certificate_lookup(
                        "order__name", order_name
                    )
                except Exception as err_:
                    self.logger.critical(
                        "Database error: Certificate lookup failed: %s", err_
                    )
                    cert_dic = {}
                if cert_dic:
                    # we found a cert in the database
                    # pylint: disable=R1715
                    if "name" in cert_dic:
                        certificate_name = cert_dic["name"]
        else:
            code = 400
            message = self.error_msg_dic["malformed"]
            detail = "url is missing in protected"

        self.logger.debug(
            "Order._process() ended with order:%s %s:%s:%s",
            order_name,
            code,
            message,
            detail,
        )
        return (code, message, detail, certificate_name)

    def _csr_process(
        self, order_name: str, csr: str, header_info: str
    ) -> Tuple[int, str, str]:
        """process certificate signing request"""
        self.logger.debug("Order._csr_process(%s)", order_name)

        order_dic = self._info(order_name)

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
            "Order._csr_process() ended with order:%s %s:{%s:%s",
            order_name,
            code,
            message,
            detail,
        )
        return (code, message, detail)

    def _update(self, data_dic: Dict[str, str]):
        """update order based on ordername"""
        self.logger.debug("Order._update(%s)", data_dic)

        try:
            self.dbstore.order_update(data_dic)
        except Exception as err_:
            self.logger.critical("Database error: failed to update order: %s", err_)

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

    def _authz_list_lookup(self, order_name: str) -> List[str]:
        """lookup authorization list"""
        self.logger.debug("Order._authz_list_lookup(%s)", order_name)

        try:
            authz_list = self.dbstore.authorization_lookup(
                "order__name", order_name, ["name", "status__name"]
            )
        except Exception as err_:
            self.logger.critical(
                "Database error: failed to look up authorization list: %s", err_
            )
            authz_list = []

        self.logger.debug("Order._authz_list_lookup() ended")
        return authz_list

    def _validity_list_create(
        self, authz_list: List[str], order_dic: Dict[str, str], order_name: str
    ):
        self.logger.debug("Order._validity_list_create()")
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
                self._update({"name": order_name, "status": "ready"})

        self.logger.debug("Order._lookup() ended")

    def _lookup(self, order_name: str) -> Dict[str, str]:
        """sohw order details based on ordername"""
        self.logger.debug("Order._validity_list_create(%s)", order_name)
        order_dic = {}

        tmp_dic = self._info(order_name)
        if tmp_dic:

            # create order dictionary and lookup authorizatio list
            order_dic = self._order_dic_create(tmp_dic)
            authz_list = self._authz_list_lookup(order_name)

            if authz_list:
                order_dic["authorizations"] = []

                # collect status of different authorizations in list and update order status
                self._validity_list_create(authz_list, order_dic, order_name)

        self.logger.debug("Order._lookup() ended")
        return order_dic

    def invalidate(self, timestamp: int = None) -> Tuple[List[str], List[str]]:
        """invalidate orders"""
        self.logger.debug("Order.invalidate(%s)", timestamp)
        if not timestamp:
            timestamp = uts_now()
            self.logger.debug("Order.invalidate(): set timestamp to %s", timestamp)

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
            order_list = self.dbstore.orders_invalid_search(
                "expires", timestamp, vlist=field_list, operant="<="
            )
        except Exception as err_:
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
                    self.dbstore.order_update(data_dic)
                except Exception as err_:
                    self.logger.critical(
                        "Database error: failed to update order status to invalid: %s",
                        err_,
                    )

        self.logger.debug(
            "Order.invalidate() ended: %s orders identified", len(output_list)
        )
        return (field_list, output_list)

    def new(self, content: str) -> Dict[str, str]:
        """new oder request"""
        self.logger.debug("Order.new()")

        response_dic = {}
        # check message
        (code, message, detail, _protected, payload, account_name) = self.message.check(
            content
        )

        if code == 200:
            (error, order_name, auth_dic, expires) = self._add(payload, account_name)
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

        self.logger.debug("Order.new() returns: %s", json.dumps(response_dic))
        return response_dic

    def _parse(
        self, protected: Dict[str, str], payload: Dict[str, str], header: str = None
    ) -> Tuple[int, str, str, str, str]:
        """new oder parse"""
        self.logger.debug("Order._parse()")

        order_name = certificate_name = None

        if "url" in protected:
            order_name = self._name_get(protected["url"])
            if order_name:
                order_dic = self._lookup(order_name)
                if order_dic:
                    (code, message, detail, certificate_name) = self._process(
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

        self.logger.debug("Order._parse() ended with code: %s", code)
        return (code, message, detail, certificate_name, order_name)

    def parse(self, content: str, header: str = None) -> Dict[str, str]:
        """new oder request"""
        self.logger.debug("Order.parse()")

        # invalidate expired orders
        if not self.expiry_check_disable:
            self.invalidate()

        response_dic = {}
        # check message
        (code, message, detail, protected, payload, _account_name) = self.message.check(
            content
        )

        if code == 200:

            # parse message
            (code, message, detail, certificate_name, order_name) = self._parse(
                protected, payload, header
            )

            if code == 200:
                # create response
                response_dic["header"] = {}
                response_dic["header"][
                    "Location"
                ] = f'{self.server_name}{self.path_dic["order_path"]}{order_name}'
                response_dic["data"] = self._lookup(order_name)
                if (
                    "status" in response_dic["data"]
                    and response_dic["data"]["status"] == "processing"
                ):
                    # set retry header as cert issuane is not completed.
                    response_dic["header"]["Retry-After"] = f"{self.retry_after}"
                response_dic["data"][
                    "finalize"
                ] = f'{self.server_name}{self.path_dic["order_path"]}{order_name}/finalize'
                # add the path to certificate if order-status is ready
                # if certificate_name:
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

        self.logger.debug("Order.parse() returns: %s", json.dumps(response_dic))
        return response_dic
