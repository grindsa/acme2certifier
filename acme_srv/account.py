# -*- coding: utf-8 -*-
"""Refactored Account class with improved design and maintainability"""

from __future__ import print_function
import json
from typing import List, Tuple, Dict, Optional
from dataclasses import dataclass, field
from acme_srv.helper import (
    generate_random_string,
    validate_email,
    date_to_datestr,
    load_config,
    eab_handler_load,
    b64decode_pad,
    error_dic_get,
    uts_to_date_utc,
    uts_now,
)
from acme_srv.db_handler import DBstore
from acme_srv.message import Message

from acme_srv.signature import Signature

# --- ExternalAccountBinding class integrated here ---
import json
from acme_srv.helper import b64decode_pad

class ExternalAccountBinding:
    """Encapsulates EAB validation and signature verification logic."""
    def __init__(self, logger, eab_handler, server_name=None):
        self.logger = logger
        self.eab_handler = eab_handler
        self.server_name = server_name

    def get_kid(self, protected: str) -> str:
        """Extract key identifier (kid) from protected header."""
        self.logger.debug("ExternalAccountBinding.get_kid()")
        protected_dic = json.loads(b64decode_pad(self.logger, protected))
        if isinstance(protected_dic, dict):
            eab_key_id = protected_dic.get("kid", None)
        else:
            eab_key_id = None
        self.logger.debug("ExternalAccountBinding.get_kid() ended with: %s", eab_key_id)
        return eab_key_id

    def compare_jwk(self, protected: dict, payload: str) -> bool:
        """Compare JWK from outer header with JWK in EAB payload."""
        self.logger.debug("ExternalAccountBinding.compare_jwk()")
        result = False
        if "jwk" in protected:
            jwk_outer = protected["jwk"]
            jwk_inner = b64decode_pad(self.logger, payload)
            jwk_inner = json.loads(jwk_inner)
            if json.dumps(jwk_outer, sort_keys=True) == json.dumps(jwk_inner, sort_keys=True):
                result = True
            else:
                self.logger.error("JWK from outer and inner JWS do not match")
                self.logger.debug("outer: %s", jwk_outer)
                self.logger.debug("inner: %s", jwk_inner)
        else:
            self.logger.error("No JWK in protected header")
        self.logger.debug("ExternalAccountBinding.compare_jwk() ended with: %s", result)
        return result

    def verify_signature(self, content: dict, mac_key: str) -> tuple:
        """Verify EAB signature."""
        self.logger.debug("ExternalAccountBinding.verify_signature()")
        if content and mac_key:
            signature = Signature(None, self.server_name, self.logger)
            jwk_ = json.dumps({"k": mac_key, "kty": "oct"})
            (sig_check, error) = signature.eab_check(json.dumps(content), jwk_)
        else:
            sig_check = False
            error = None
        self.logger.debug("ExternalAccountBinding.verify_signature() ended with: %s: %s", sig_check, error)
        return (sig_check, error)

    def verify(self, payload: dict, err_msg_dic: dict) -> tuple:
        """Check for external account binding and verify signature."""
        self.logger.debug("ExternalAccountBinding.verify()")
        eab_kid = self.get_kid(payload["externalaccountbinding"]["protected"])
        if eab_kid:
            with self.eab_handler(self.logger) as eab_handler:
                eab_mac_key = eab_handler.mac_key_get(eab_kid)
        else:
            eab_mac_key = None
        if eab_mac_key:
            (result, error) = self.verify_signature(payload["externalaccountbinding"], eab_mac_key)
            if result:
                code = 200
                message = None
                detail = None
            else:
                code = 403
                message = err_msg_dic["unauthorized"]
                detail = "EAB signature verification failed"
                self.logger.error("EAB verification returned an error: %s", error)
        else:
            code = 403
            message = err_msg_dic["unauthorized"]
            detail = "EAB kid lookup failed"
        self.logger.debug("ExternalAccountBinding.verify() ended with: %s", code)
        return (code, message, detail)

    def check(self, protected: dict, payload: dict, err_msg_dic: dict) -> tuple:
        """Check for external account binding, compare JWK, and verify signature."""
        self.logger.debug("ExternalAccountBinding.check()")
        if (
            self.eab_handler
            and protected
            and payload
            and "externalaccountbinding" in payload
            and payload["externalaccountbinding"]
        ):
            jwk_compare = self.compare_jwk(protected, payload["externalaccountbinding"]["payload"])
            if jwk_compare and "protected" in payload["externalaccountbinding"]:
                return self.verify(payload, err_msg_dic)
            else:
                code = 403
                message = err_msg_dic["malformed"]
                detail = "Malformed request"
        else:
            code = 403
            message = err_msg_dic["externalaccountrequired"]
            detail = "External account binding required"
        self.logger.debug("ExternalAccountBinding.check() ended with: %s", code)
        return (code, message, detail)


class AccountDatabaseError(Exception):
    """Exception raised for database-related errors in Account operations."""
    pass


class AccountRepository:
    """Repository for all Account-related database operations."""

    def __init__(self, dbstore):
        self.dbstore = dbstore

    def lookup_account(self, field: str, value: str) -> Optional[Dict[str, str]]:
        """Look up an account in the database."""
        try:
            return self.dbstore.account_lookup(field, value)
        except Exception as err:
            raise AccountDatabaseError(f"Failed to look up account: {err}") from err

    def add_account(self, data_dic: Dict[str, str]) -> Tuple[Optional[str], bool]:
        """Add a new account to the database."""
        try:
            return self.dbstore.account_add(data_dic)
        except Exception as err:
            raise AccountDatabaseError(f"Failed to add account: {err}") from err

    def update_account(self, data_dic: Dict[str, str], active: bool = True) -> bool:
        """Update an account in the database."""
        try:
            return self.dbstore.account_update(data_dic, active)
        except Exception as err:
            raise AccountDatabaseError(f"Failed to update account: {err}") from err

    def delete_account(self, account_name: str) -> bool:
        """Delete an account from the database."""
        try:
            return self.dbstore.account_delete(account_name)
        except Exception as err:
            raise AccountDatabaseError(f"Failed to delete account: {err}") from err

    def load_jwk(self, account_name: str) -> Optional[Dict[str, str]]:
        """Load the JWK for a given account."""
        try:
            return self.dbstore.jwk_load(account_name)
        except Exception as err:
            raise AccountDatabaseError(f"Failed to load JWK: {err}") from err


@dataclass
class AccountConfiguration:
    """Configuration for the Account class."""
    ecc_only: bool = False
    contact_check_disable: bool = False
    tos_check_disable: bool = False
    inner_header_nonce_allow: bool = False
    tos_url: Optional[str] = None
    eab_check: bool = False
    eab_handler: Optional[object] = None
    path_dic: Dict[str, str] = field(default_factory=lambda: {"acct_path": "/acme/acct/"})


@dataclass
class AccountData:
    """Data structure for account information."""
    name: str
    alg: str
    jwk: Dict[str, str]
    contact: List[str]
    eab_kid: Optional[str] = None
    status: str = "valid"
    created_at: Optional[str] = None


class Account:
    """Refactored ACME server class."""

    def __init__(self, debug: bool = False, srv_name: str = None, logger=None):
        self.server_name = srv_name
        self.logger = logger
        self.dbstore = DBstore(debug, self.logger)
        self.repository = AccountRepository(self.dbstore)
        self.message = Message(debug, self.server_name, self.logger)
        self.config = AccountConfiguration()
        self.err_msg_dic = error_dic_get(self.logger)

    def __enter__(self) -> "Order":
        """Enter the context manager, loading configuration."""
        self._load_configuration()
        return self

    def __exit__(self, *args) -> None:
        """
        Exit the context manager. (No-op, placeholder for cleanup.)
        """

    def _load_configuration(self):
        """Load configuration into the AccountConfiguration dataclass."""
        self.logger.debug("Account._load_configuration()")
        config_dic = load_config()

        self.config.inner_header_nonce_allow = config_dic.getboolean(
            "Account", "inner_header_nonce_allow", fallback=False
        )
        self.config.ecc_only = config_dic.getboolean("Account", "ecc_only", fallback=False)
        self.config.tos_check_disable = config_dic.getboolean(
            "Account", "tos_check_disable", fallback=False
        )
        self.config.contact_check_disable = config_dic.getboolean(
            "Account", "contact_check_disable", fallback=False
        )

        if "EABhandler" in config_dic:
            self.logger.debug("Account._load_configuration(): loading eab_handler")
            self.config.eab_check = True
            if "eab_handler_file" in config_dic["EABhandler"]:
                eab_handler_module = eab_handler_load(self.logger, config_dic)
                if eab_handler_module:
                    self.config.eab_handler = eab_handler_module.EABhandler
                else:
                    self.logger.critical("EABHandler could not get loaded")
            else:
                self.logger.critical("EABHandler configuration incomplete")

        self.config.tos_url = config_dic.get("Directory", "tos_url", fallback=None)
        if config_dic.get("Directory", "url_prefix", fallback=None):
            self.config.path_dic = {
                k: config_dic.get("Directory", "url_prefix") + v
                for k, v in self.config.path_dic.items()
            }
        self.logger.debug("Account._load_configuration() ended")

    def _add_account_to_db(self, account_data: AccountData) -> Tuple[int, str, Optional[Dict[str, str]]]:
        """Add a new account to the database."""
        self.logger.debug("Account._add_account_to_db(%s)", account_data.name)
        try:

            # convert dict and list to string
            account_data.jwk = json.dumps(account_data.jwk)
            account_data.contact = json.dumps(account_data.contact)

            db_name, is_new = self.repository.add_account(account_data.__dict__)
            if is_new:
                self.logger.debug("Account._add_account_to_db() ended with: 201, %s", db_name)
                return 201, db_name, None
            self.logger.debug("Account._add_account_to_db() ended with: 200, %s", db_name)
            return 200, db_name, None

        except AccountDatabaseError as err:
            self.logger.critical("Database error while adding account: %s", err)
            return 500, self.err_msg_dic["serverinternal"], "Database error"

    def _validate_contact(self, contact: List[str]) -> Tuple[int, str, str]:
        """Validate contact information."""
        self.logger.debug("Account._validate_contact()")
        if not contact:
            return 400, self.err_msg_dic["malformed"], "Contact information is missing"
        if not validate_email(self.logger, contact):
            return 400, self.err_msg_dic["invalidcontact"], "Invalid contact information"
        return 200, None, None


    def _check_tos(self, content: Dict[str, str]) -> Tuple[int, str, str]:
        """check terms of service"""
        self.logger.debug("Account._check_tos()")
        if "termsofserviceagreed" in content:
            self.logger.debug("tos:%s", content["termsofserviceagreed"])
            if content["termsofserviceagreed"]:
                code = 200
                message = None
                detail = None
            else:
                code = 403
                message = self.err_msg_dic["useractionrequired"]
                detail = "Terms of service must be agreed"
        else:
            self.logger.debug("no tos statement found.")
            code = 403
            message = self.err_msg_dic["useractionrequired"]
            detail = "termsofserviceagreed flag missing"

        self.logger.debug("Account._check_tos() ended with:%s", code)
        return (code, message, detail)


    def _create_account(self, payload: Dict[str, str], protected: Dict[str, str]) -> Tuple[int, str, str]:
        """Create a new account."""
        self.logger.debug("Account._create_account()")
        account_name = generate_random_string(self.logger, 12)
        contact_list = payload.get("contact", [])

        # tos check
        if self.config.tos_url and not self.config.tos_check_disable:
            (code, message, detail) = self._check_tos(payload)
            if code != 200:
                return code, message, detail

        # EAB check
        if self.config.eab_check and "externalaccountbinding" in payload:
            eab_handler = ExternalAccountBinding(
                self.logger,
                self.config.eab_handler,
                self.server_name
            )
            code, message, detail = eab_handler.check(protected, payload, self.err_msg_dic)
            if code != 200:
                return code, message, detail

        # Validate contact information
        if not self.config.contact_check_disable:
            code, message, detail = self._validate_contact(contact_list)
            if code != 200:
                return code, message, detail


        # Prepare account data
        account_data = AccountData(
            name=account_name,
            alg=protected["alg"],
            jwk=protected["jwk"],
            contact=contact_list,
            created_at=date_to_datestr(uts_now())
        )

        # Add account to database
        return self._add_account_to_db(account_data)

    def _parse_query(self, account_name: str) -> Dict[str, str]:
        """update contacts"""
        self.logger.debug("Account._parse_query(%s)", account_name)

        # this is a query for account information
        account_obj = self._lookup_account_by_name(account_name)
        if account_obj:
            data = self._build_account_info(account_obj)
            data["status"] = "valid"
        else:
            data = {"status": "invalid"}

        self.logger.debug("Account._parse_query() ended")
        return data

    def _onlyreturnexisting(
        self, protected: Dict[str, str], payload: Dict[str, str]
    ) -> Tuple[int, str, str]:
        """check onlyreturnexisting"""
        self.logger.debug("Account._onlyreturnexisting(}")

        if "onlyreturnexisting" in payload:
            if payload["onlyreturnexisting"]:

                if "jwk" in protected:
                    result = self._lookup_account_by_field(json.dumps(protected["jwk"]), "jwk")
                    if result:
                        code = 200
                        message = result["name"]
                        detail = self._parse_query(message)
                    else:
                        code = 400
                        message = self.err_msg_dic["accountdoesnotexist"]
                        detail = None
                else:
                    code = 400
                    message = self.err_msg_dic["malformed"]
                    detail = "jwk structure missing"

            else:
                code = 400
                message = self.err_msg_dic["useractionrequired"]
                detail = "onlyReturnExisting must be true"
        else:
            code = 500
            message = self.err_msg_dic["serverinternal"]
            detail = "onlyReturnExisting without payload"

        self.logger.debug("Account.onlyreturnexisting() ended with: %s", code)
        return (code, message, detail)


    def _handle_deactivation(self, account_name: str, payload: Dict[str, str]) -> Dict[str, str]:
        """Handle account deactivation."""
        self.logger.debug("Account._handle_deactivation(%s)", account_name)
        if payload.get("status", "").lower() == "deactivated":
            code, message, detail = self._deactivate_account(account_name)
            if code == 200:
                return self._build_response(code, message, payload)
            else:
                return self._build_response(code, message, detail)
        else:
            return self._build_response(400, self.err_msg_dic["malformed"], "Invalid status for deactivation")

    def _deactivate_account(self, account_name: str) -> Tuple[int, str, str]:
        """Deactivate an account."""
        self.logger.debug("Account._deactivate_account(%s)", account_name)
        try:
            data_dic = {
                "name": account_name,
                "status_id": 7,
                "jwk": f"DEACTIVATED {uts_to_date_utc(uts_now())}",
            }
            result = self.repository.update_account(data_dic, active=False)
            if result:
                return 200, None, None
            else:
                return 400, self.err_msg_dic["accountdoesnotexist"], "Deactivation failed"
        except AccountDatabaseError as err:
            self.logger.critical("Database error while deactivating account: %s", err)
            return 500, self.err_msg_dic["serverinternal"], "Database error"

    def _handle_contact_update(self, account_name: str, payload: Dict[str, str]) -> Dict[str, str]:
        """Handle contact update for an account."""
        self.logger.debug("Account._handle_contact_update(%s)", account_name)
        code, message, detail = self._update_account_contacts(account_name, payload)
        if code == 200:
            account_obj = self._lookup_account_by_name(account_name)
            if account_obj:
                data = self._build_account_info(account_obj)
                return self._build_response(code, message, data)
        return self._build_response(code, message, detail)

    def _update_account_contacts(self, account_name: str, payload: Dict[str, str]) -> Tuple[int, str, str]:
        """Update account contacts in the database."""
        self.logger.debug("Account._update_account_contacts(%s)", account_name)
        code, message, detail = self._validate_contact(payload.get("contact", []))
        if code != 200:
            return code, message, detail

        try:
            data_dic = {"name": account_name, "contact": json.dumps(payload["contact"])}
            result = self.dbstore.account_update(data_dic)
            if result:
                return 200, None, None
            else:
                return 400, self.err_msg_dic["accountdoesnotexist"], "Update failed"
        except Exception as err:
            self.logger.critical("Database error while updating account contacts: %s", err)
            return 500, self.err_msg_dic["serverinternal"], "Database error"

    def _handle_key_change(self, account_name: str, payload: Dict[str, str], protected: Dict[str, str]) -> Dict[str, str]:
        """Handle key change for an account."""
        self.logger.debug("Account._handle_key_change(%s)", account_name)
        if "url" in protected and "key-change" in protected["url"]:
            code, message, detail, inner_protected, inner_payload, _ = self.message.check(
                json.dumps(payload), use_emb_key=True, skip_nonce_check=True
            )
            if code == 200:
                code, message, detail = self._rollover_account_key(
                    account_name, protected, inner_protected, inner_payload
                )
                if code == 200:
                    return self._build_response(code, message, None)
        return self._build_response(400, self.err_msg_dic["malformed"], "Malformed key-change request")

    def _rollover_account_key(
        self, account_name: str, protected: Dict[str, str], inner_protected: Dict[str, str], inner_payload: Dict[str, str]
    ) -> Tuple[int, str, str]:
        """Perform key rollover for an account."""
        self.logger.debug("Account._rollover_account_key(%s)", account_name)
        code, message, detail = self._validate_key_change(account_name, protected, inner_protected, inner_payload)
        if code == 200:
            try:
                data_dic = {"name": account_name, "jwk": json.dumps(inner_protected["jwk"])}
                result = self.dbstore.account_update(data_dic)
                if result:
                    return 200, None, None
                else:
                    return 500, self.err_msg_dic["serverinternal"], "Key rollover failed"
            except Exception as err:
                self.logger.critical("Database error while updating account key: %s", err)
                return 500, self.err_msg_dic["serverinternal"], "Database error"
        return code, message, detail

    def _validate_key_change(
        self, account_name: str, protected: Dict[str, str], inner_protected: Dict[str, str], inner_payload: Dict[str, str]
    ) -> Tuple[int, str, str]:
        """Validate key change request."""
        self.logger.debug("Account._validate_key_change(%s)", account_name)
        if "jwk" not in inner_protected:
            return 400, self.err_msg_dic["malformed"], "Inner JWS is missing JWK"

        key_exists = self._lookup_account_by_field(json.dumps(inner_protected["jwk"]), "jwk")
        if key_exists:
            return 400, self.err_msg_dic["badpubkey"], "Public key already exists"

        if "url" in protected and "url" in inner_protected:
            if protected["url"] != inner_protected["url"]:
                return 400, self.err_msg_dic["malformed"], "URL mismatch in inner and outer JWS"
        else:
            return 400, self.err_msg_dic["malformed"], "Missing URL in inner or outer JWS"

        if "kid" in protected and "account" in inner_payload:
            if protected["kid"] != inner_payload["account"]:
                return 400, self.err_msg_dic["malformed"], "KID and account do not match"
        else:
            return 400, self.err_msg_dic["malformed"], "Missing KID or account in payload"

        return 200, None, None

    def _handle_account_query(self, account_name: str) -> Dict[str, str]:
        """Handle account query."""
        self.logger.debug("Account._handle_account_query(%s)", account_name)
        account_obj = self._lookup_account_by_name(account_name)
        if account_obj:
            data = self._build_account_info(account_obj)
            return self._build_response(200, None, data)
        return self._build_response(400, self.err_msg_dic["accountdoesnotexist"], "Account not found")

    def _lookup_account_by_name(self, value: str) -> Optional[Dict[str, str]]:
        """Lookup an account in the database."""
        self.logger.debug("Account._lookup_account_by_name(%s: %s)", field, value)
        try:
            return self.repository.lookup_account("name", value)
        except AccountDatabaseError as err:
            self.logger.critical("Database error during account lookup: %s", err)
            return None

    def _lookup_account_by_field(self, value: str, field: str) -> Optional[Dict[str, str]]:
        """Lookup account by a specific field."""
        self.logger.debug("Account._lookup_account_by_field(%s: %s)", field, value)
        try:
            return self.dbstore.account_lookup(field, value)
        except Exception as err:
            self.logger.critical("Database error during account lookup: %s", err)
            return None

    def _build_account_info(self, account_obj: Dict[str, str]) -> Dict[str, str]:
        """Build account information for response."""
        self.logger.debug("Account._build_account_info()")
        account_info =  {
            "status": account_obj.get("status", "valid"),
            "key": json.loads(account_obj["jwk"]),
            "contact": json.loads(account_obj["contact"]),
            "createdAt": date_to_datestr(account_obj["created_at"]),

        }
        if "eab_kid" in account_obj and account_obj['eab_kid']:
            account_info["eab_kid"] = account_obj.get("eab_kid"),

        self.logger.debug("Account._build_account_info() ended with: %s", bool(account_info))
        return account_info


    def _build_response(self, code: int, message: str, detail: Optional[str], payload: Optional[Dict] = None) -> Dict[str, str]:
        """Build a response dictionary."""
        self.logger.debug("Account._build_response()")
        response_dic = {}
        if code in (200, 201):
            response_dic["data"] = {}
            if code == 201:
                response_dic["data"] = {
                    "status": "valid",
                    "orders": f'{self.server_name}{self.config.path_dic["acct_path"]}{message}/orders',
                }
                if payload and "contact" in payload:
                    response_dic["data"]["contact"] = payload["contact"]
            elif code == 200 and detail and "status" in detail:
                response_dic["data"] = detail

            response_dic["header"] = {}
            response_dic["header"][
                "Location"
            ] = f'{self.server_name}{self.config.path_dic["acct_path"]}{message}'

            # add exernal account binding
            if self.config.eab_check and "externalaccountbinding" in payload:
                response_dic["data"]["externalaccountbinding"] = payload[
                    "externalaccountbinding"
                ]

        else:
            if detail == "tosfalse":
                detail = "Terms of service must be accepted"

        # prepare/enrich response
        status_dic = {"code": code, "type": message, "detail": detail}
        response_dic = self.message.prepare_response(response_dic, status_dic)

        return response_dic


    def create_account(self, content: Dict[str, str]) -> Dict[str, str]:
        """Public method to create a new account."""
        self.logger.debug("Account.create_account()")
        code, message, detail, protected, payload, _ = self.message.check(content, True)
        if code != 200:
            return self._build_response(code, message, detail, payload)


        # onlyReturnExisting check
        if "onlyreturnexisting" in payload:
            code, message, detail = self._onlyreturnexisting(protected, payload)
        else:
            code, message, detail = self._create_account(payload, protected)

        self.logger.debug("Account.create_account() ended with: %s, %s", code, message)
        return self._build_response(code, message, detail, payload)

    def parse_request(self, content: Dict[str, str]) -> Dict[str, str]:
        """Public method to parse an account-related request."""
        self.logger.debug("Account.parse_request()")
        code, message, detail, protected, payload, account_name = self.message.check(content)
        if code != 200:
            return self._build_response(code, message, detail)

        if "status" in payload:
            return self._handle_deactivation(account_name, payload)
        elif "contact" in payload:
            return self._handle_contact_update(account_name, payload)
        elif "payload" in payload:
            return self._handle_key_change(account_name, payload, protected)
        elif not payload:
            return self._handle_account_query(account_name)
        else:
            return self._build_response(400, self.err_msg_dic["malformed"], "Unknown request")

    # Compatibility layer for external methods
    def new(self, content: Dict[str, str]) -> Dict[str, str]:
        """Compatibility layer for the new method."""
        return self.create_account(content)

    def parse(self, content: Dict[str, str]) -> Dict[str, str]:
        """Compatibility layer for the parse method."""
        return self.parse_request(content)


