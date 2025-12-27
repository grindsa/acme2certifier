# -*- coding: utf-8 -*-
# pylint: disable=r0913
"""message class"""
from __future__ import print_function
import json
from typing import Tuple, Dict, Optional
from dataclasses import dataclass
from acme_srv.helper import (
    decode_message,
    load_config,
    eab_handler_load,
    uts_to_date_utc,
    uts_now,
)
from acme_srv.error import Error
from acme_srv.db_handler import DBstore
from acme_srv.nonce import Nonce
from acme_srv.signature import Signature


@dataclass
class MessageConfiguration:
    """Contains message related configuration options."""

    signature_check_disable: bool = False
    nonce_check_disable: bool = False
    acct_path: str = "/acme/acct/"
    revocation_path: str = "/acme/revokecert"
    eabkid_check_disable: bool = False
    invalid_eabkid_deactivate: bool = False
    eab_handler: Optional[object] = None


class AccountRepository:
    """Repository for account related database operations"""

    def __init__(self, dbstore):
        self.dbstore = dbstore

    def account_lookup(self, key, value):
        """Lookup an account by a given key and value."""
        return self.dbstore.account_lookup(key, value)

    def account_update(self, data_dic, active):
        """Update account information in the database."""
        return self.dbstore.account_update(data_dic, active)

    def cli_permissions_get(self, account_name):
        """Get CLI permissions for a specific account."""
        return self.dbstore.cli_permissions_get(account_name)


class Message(object):
    """Message handler"""

    def __init__(
        self, debug: bool = False, srv_name: str = None, logger: object = None
    ):
        self.debug = debug
        self.logger = logger
        self.nonce = Nonce(self.debug, self.logger)
        self.dbstore = DBstore(self.debug, self.logger)
        self.repo = AccountRepository(self.dbstore)
        self.server_name = srv_name
        self.config = self._load_configuration()

    def __enter__(self):
        """Makes ACMEHandler a Context Manager"""
        return self

    def __exit__(self, *args):
        """Close the connection at the end of the context"""

    def _load_configuration(self) -> MessageConfiguration:
        """Load and parse config from file and return MessageConfiguration dataclass."""
        self.logger.debug("Message._load_configuration()")
        config_dic = load_config()
        msg_config = MessageConfiguration()
        if "Nonce" in config_dic:
            msg_config.nonce_check_disable = config_dic.getboolean(
                "Nonce", "nonce_check_disable", fallback=False
            )
            msg_config.signature_check_disable = config_dic.getboolean(
                "Nonce", "signature_check_disable", fallback=False
            )
        if "EABhandler" in config_dic:
            if config_dic.getboolean(
                "EABhandler", "eabkid_check_disable", fallback=False
            ):
                msg_config.eabkid_check_disable = True
            elif "eab_handler_file" in config_dic["EABhandler"]:
                eab_handler_module = eab_handler_load(self.logger, config_dic)
                if eab_handler_module:
                    msg_config.invalid_eabkid_deactivate = config_dic.getboolean(
                        "EABhandler", "invalid_eabkid_deactivate", fallback=False
                    )
                    msg_config.eab_handler = eab_handler_module.EABhandler
                else:
                    self.logger.critical("EABHandler could not get loaded")
            else:
                self.logger.critical("EABHandler configuration incomplete")
        else:
            msg_config.eabkid_check_disable = True

        if "Directory" in config_dic and "url_prefix" in config_dic["Directory"]:
            url_prefix = config_dic["Directory"]["url_prefix"]
            msg_config.acct_path = url_prefix + "/acme/acct/"
            msg_config.revocation_path = url_prefix + "/acme/revokecert"

        self.logger.debug("Message._load_configuration() ended")
        return msg_config

    def _check_and_handle_invalid_eab_credentials(self, account_name: str):
        """Check for accounts with invalid eab credentials."""
        self.logger.debug("Message._check_and_handle_invalid_eab_credentials()")

        try:
            account_dic = self.repo.account_lookup("name", account_name)
        except Exception as err:
            self.logger.error(f"Account lookup for {account_name} failed: {err}")
            account_dic = None

        if account_dic:
            eab_kid = account_dic.get("eab_kid", None)
            if eab_kid and self.config.eab_handler:
                try:
                    with self.config.eab_handler(self.logger) as eab_handler:
                        eab_mac_key = eab_handler.mac_key_get(eab_kid)
                        if not eab_mac_key:
                            self.logger.error(
                                "EAB credentials: %s could not be found in eab-credential store.",
                                eab_kid,
                            )
                            if self.config.invalid_eabkid_deactivate:
                                self.logger.error(
                                    "Account %s will be deactivated due to missing eab credentials",
                                    account_name,
                                )
                                data_dic = {
                                    "name": account_name,
                                    "status_id": 7,
                                    "jwk": f"DEACTIVATED invalid_eabkid_deactivate {uts_to_date_utc(uts_now())}",
                                }
                                try:
                                    self.repo.account_update(data_dic, active=False)
                                except Exception as err:
                                    self.logger.error(f"Account update failed: {err}")
                            account_name = None

                except Exception as err:
                    self.logger.error(f"EAB handler error: {err}")
                    account_name = None
            elif not eab_kid:
                self.logger.error("Account %s has no eab credentials", account_name)
                account_name = None
        else:
            self.logger.error("Account lookup for %s failed.", account_name)
            account_name = None
        self.logger.debug(
            "Message._check_and_handle_invalid_eab_credentials() ended with account_name: %s",
            account_name,
        )
        return account_name

    def _extract_account_name_for_revocation(
        self, content: Dict[str, str]
    ) -> Optional[str]:
        """this is needed for cases where we get a revocation message signed with account key but account name is missing"""
        self.logger.debug("Message._extract_account_name_for_revocation()")

        try:
            account_list = self.repo.account_lookup("jwk", json.dumps(content["jwk"]))
        except Exception as err_:
            self.logger.critical(
                f"Database error: failed to look up account name for revocation: {err_}"
            )
            return None
        if account_list and "name" in account_list:
            kid = account_list["name"]
        else:
            kid = None

        self.logger.debug(
            "Message._get_account_name_for_revocation() ended with kid: %s", kid
        )
        return kid

    def _extract_account_name_from_content(
        self, content: Dict[str, str]
    ) -> Optional[str]:
        """get name for account"""
        self.logger.debug("Message._name_get(): content: %s", content)

        if "kid" in content:
            self.logger.debug("Message._name_get(): kid: %s", content["kid"])
            kid = content["kid"].replace(
                f"{self.server_name}{self.config.acct_path}", ""
            )
            if "/" in kid:
                self.logger.debug("Message._name_get(): clear kid")
                kid = None
        elif "jwk" in content and "url" in content:
            self.logger.debug(
                "Message._name_get(): server_name: %s url: %s",
                self.server_name,
                content["url"],
            )
            if content["url"] == f"{self.server_name}{self.config.revocation_path}":
                self.logger.debug("Message._name_get(): revocation")
                kid = self._extract_account_name_for_revocation(content)
            else:
                kid = None
        else:
            kid = None

        self.logger.debug(
            "Message._extract_account_name_from_content() returns: %s", kid
        )
        return kid

    def extract_account_name_from_content(
        self, content: Dict[str, str]
    ) -> Optional[str]:
        """public method to get name for account"""
        self.logger.debug("Message.extract_account_name_from_content()")
        kid = self._extract_account_name_from_content(content)
        self.logger.debug(
            "Message.extract_account_name_from_content() ended with: %s", kid
        )
        return kid

    def _check_nonce_for_replay_protection(
        self, skip_nonce_check: bool, protected: Dict[str, str]
    ) -> Tuple[int, Optional[str], Optional[str]]:
        """check nonce for anti replay protection"""
        self.logger.debug("Message._check_nonce_for_replay_protection()")
        if skip_nonce_check or self.config.nonce_check_disable:
            if self.config.nonce_check_disable:
                self.logger.error(
                    "**** NONCE CHECK DISABLED!!! Severe security issue ****"
                )
            else:
                self.logger.info("Skip nonce check of inner payload during keyrollover")
            code = 200
            message = None
            detail = None
        else:
            (code, message, detail) = self.nonce.check(protected)

        self.logger.debug(
            "Message._check_nonce_for_replay_protection() ended with: %s", code
        )
        return (code, message, detail)

    def _validate_message_and_check_signature(
        self,
        skip_nonce_check: bool,
        skip_signature_check: bool,
        content: str,
        protected: Dict[str, str],
        use_emb_key: bool,
    ) -> Tuple[int, str, str, str]:
        """Decoding successful - check nonce for anti replay protection and signature."""
        self.logger.debug("Message._validate_message_and_check_signature()")

        (code, message, detail) = self._check_nonce_for_replay_protection(
            skip_nonce_check, protected
        )
        account_name = None

        # nonce check successful - get account name
        account_name = self._extract_account_name_from_content(protected)
        # check for invalid eab-credentials if not disabled and not using embedded key
        if code == 200 and not self.config.eabkid_check_disable and not use_emb_key:
            account_name = self._check_and_handle_invalid_eab_credentials(account_name)
            if not account_name:
                return (
                    403,
                    "urn:ietf:params:acme:error:unauthorized",
                    "invalid eab credentials",
                    None,
                )

        if code == 200 and not skip_signature_check:
            signature = Signature(self.debug, self.server_name, self.logger)
            (sig_check, error, error_detail) = signature.check(
                account_name, content, use_emb_key, protected
            )
            if sig_check:
                code = 200
                message = None
                detail = None
            else:
                code = 403
                message = error
                detail = error_detail

            self.logger.debug(
                "Message._validate_message_and_check_signature() ended with: %s", code
            )
        return (code, message, detail, account_name)

    # pylint: disable=R0914
    def check(
        self, content: str, use_emb_key: bool = False, skip_nonce_check: bool = False
    ) -> Tuple[int, str, str, Dict[str, str], Dict[str, str], str]:
        """validate message"""
        self.logger.debug("Message.check()")

        # disable signature check if paramter has been set
        if self.config.signature_check_disable:
            self.logger.error(
                "**** SIGNATURE_CHECK_DISABLE!!! Severe security issue ****"
            )
            skip_signature_check = True
        else:
            skip_signature_check = False

        # decode message
        (result, error_detail, protected, payload, _signature) = decode_message(
            self.logger, content
        )
        account_name = None
        if result:
            (
                code,
                message,
                detail,
                account_name,
            ) = self._validate_message_and_check_signature(
                skip_nonce_check, skip_signature_check, content, protected, use_emb_key
            )
        else:
            code = 400
            message = "urn:ietf:params:acme:error:malformed"
            detail = error_detail

        self.logger.debug("Message._check() ended with:%s", code)
        return (code, message, detail, protected, payload, account_name)

    def cli_check(
        self, content: str
    ) -> Tuple[int, str, str, Dict[str, str], Dict[str, str], str, Dict[str, str]]:
        """validate message coming from CLI client"""
        self.logger.debug("Message.cli_check()")

        # decode message
        (result, error_detail, protected, payload, _signature) = decode_message(
            self.logger, content
        )
        account_name = None
        permissions = {}
        if result:
            # check signature
            account_name = self._extract_account_name_from_content(protected)
            signature = Signature(self.debug, self.server_name, self.logger)
            (sig_check, error, error_detail) = signature.cli_check(
                account_name, content
            )
            if sig_check:
                code = 200
                message = None
                detail = None
                try:
                    permissions = self.repo.cli_permissions_get(account_name)
                except Exception as err:
                    self.logger.error(f"cli_permissions_get failed: {err}")
                    permissions = {}
            else:
                code = 403
                message = error
                detail = error_detail
        else:
            # message could not get decoded
            code = 400
            message = "urn:ietf:params:acme:error:malformed"
            detail = error_detail

        self.logger.debug("Message.cli_check() ended with:%s", code)
        return (code, message, detail, protected, payload, account_name, permissions)

    def prepare_response(
        self,
        response_dic: Dict[str, str],
        status_dic: Dict[str, str],
        add_nonce: bool = True,
    ) -> Dict[str, str]:
        """prepare response_dic"""
        self.logger.debug("Message.prepare_response()")
        if "code" not in status_dic:
            status_dic["code"] = 500
            status_dic["type"] = "urn:ietf:params:acme:error:serverInternal"
            status_dic["detail"] = "http status code missing"

        if "type" not in status_dic:
            status_dic["type"] = "urn:ietf:params:acme:error:serverInternal"

        if "detail" not in status_dic:
            status_dic["detail"] = None

        # create response
        response_dic["code"] = status_dic["code"]

        # create header if not existing
        if "header" not in response_dic:
            response_dic["header"] = {}

        if status_dic["code"] >= 400:
            if status_dic["detail"]:
                # some error occured get details
                error_message = Error(self.debug, self.logger)
                status_dic["detail"] = error_message.enrich_error(
                    status_dic["type"], status_dic["detail"]
                )
                response_dic["data"] = {
                    "status": status_dic["code"],
                    "type": status_dic["type"],
                    "detail": status_dic["detail"],
                }
            else:
                response_dic["data"] = {
                    "status": status_dic["code"],
                    "type": status_dic["type"],
                }

        # always add nonce to header
        if add_nonce:
            response_dic["header"]["Replay-Nonce"] = self.nonce.generate_and_add()

        return response_dic
