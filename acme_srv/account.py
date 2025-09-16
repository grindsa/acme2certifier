# -*- coding: utf-8 -*-
"""Account class"""
from __future__ import print_function
import json
from typing import List, Tuple, Dict
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


class Account(object):
    """ACME server class"""

    def __init__(self, debug: bool = False, srv_name: str = None, logger=None):
        self.server_name = srv_name
        self.logger = logger
        self.dbstore = DBstore(debug, self.logger)
        self.message = Message(debug, self.server_name, self.logger)
        self.path_dic = {"acct_path": "/acme/acct/"}
        self.err_msg_dic = error_dic_get(self.logger)
        self.ecc_only = False
        self.contact_check_disable = False
        self.tos_check_disable = False
        self.inner_header_nonce_allow = False
        self.tos_url = None
        self.eab_check = False
        self.eab_handler = None

    def __enter__(self):
        """Makes ACMEHandler a Context Manager"""
        self._config_load()
        return self

    def __exit__(self, *args):
        """cose the connection at the end of the context"""

    def _account_tune(
        self, result: Dict[str, str], jwk: Dict[str, str]
    ) -> Dict[str, str]:
        """tune result of account_lookup"""
        self.logger.debug("Account._account_tune(}")
        result["status"] = "valid"
        # modify date
        if "created_at" in result:
            result["created_at"] = date_to_datestr(result["created_at"])
        if "contact" in result:
            result["contact"] = json.loads(result["contact"])
        if "jwk" in result:
            result.pop("jwk")
            result["key"] = jwk
        self.logger.debug("Account._account_tune(} ended")
        return result

    def _account_lookup(self, jwk: Dict[str, str]) -> Tuple[int, str, Dict[str, str]]:
        """lookup account"""
        self.logger.debug("Account._account_lookup(}")

        try:
            result = self.dbstore.account_lookup("jwk", json.dumps(jwk))
        except Exception as err_:
            self.logger.critical(
                "acme2certifier database error in Account._account_lookup(): %s", err_
            )
            result = None

        if result:
            code = 200
            message = result["name"]
            # set status be returned to client
            # detail = self._account_tune(result,  jwk)
            detail = self._parse_query(message)
        else:
            code = 400
            message = self.err_msg_dic["accountdoesnotexist"]
            detail = None

        self.logger.debug("Account._acount_lookup() ended with: %s", code)
        return (code, message, detail)

    def _account_add_check(
        self, account_name: str, data_dic: Dict[str, str]
    ) -> Tuple[int, str, str]:
        """perform database operation"""
        self.logger.debug("Account.account._account_add_check(%s)", account_name)

        try:
            (db_name, new) = self.dbstore.account_add(data_dic)
        except Exception as err_:
            self.logger.critical("Account.account._add(): Database error: %s", err_)
            db_name = None
            new = False

        self.logger.debug("got account_name: %s new: %s", db_name, new)

        if new:
            code = 201
            message = account_name
        else:
            code = 200
            message = db_name
        detail = None

        self.logger.debug(
            "Account.account._account_add_check() ended with: %s", account_name
        )
        return (code, message, detail)

    def _account_eab_add(
        self, payload: Dict[str, str], data_dic: Dict[str, str]
    ) -> Dict[str, str]:
        """prepare add keyid"""
        self.logger.debug("Account.account._account_eab_add()")

        if (
            payload
            and "externalaccountbinding" in payload
            and payload["externalaccountbinding"]
            and "protected" in payload["externalaccountbinding"]
        ):
            eab_kid = self._eab_kid_get(payload["externalaccountbinding"]["protected"])
            self.logger.info("add eab_kid: %s to data_dic", eab_kid)
            if eab_kid:
                data_dic["eab_kid"] = eab_kid

        self.logger.debug("Account.account._account_eab_add()")
        return data_dic

    def _account_add(
        self,
        account_name: str,
        content: Dict[str, str],
        contact: List[str],
        payload: Dict[str, str],
    ):
        """prepare db insert and call DBstore helper"""
        self.logger.debug("Account.account._account_add(%s)", account_name)

        # ecc_only check
        if self.ecc_only and not content["alg"].startswith("ES"):
            code = 403
            message = self.err_msg_dic["badpubkey"]
            detail = "Only ECC keys are supported"
        else:
            # check jwk
            data_dic = {
                "name": account_name,
                "alg": content["alg"],
                "jwk": json.dumps(content["jwk"]),
                "contact": json.dumps(contact),
            }
            # add eab_kid to data_dic if eab_check is enabled and kid is part of the request
            if self.eab_check:
                data_dic = self._account_eab_add(payload, data_dic)

            # check code to be returned
            (code, message, detail) = self._account_add_check(account_name, data_dic)

        self.logger.debug("Account.account._account_add() ended with: %s", account_name)
        return (code, message, detail)

    def _add(
        self, content: Dict[str, str], payload: Dict[str, str], contact: List[str]
    ):
        """prepare db insert and call DBstore helper"""
        self.logger.debug("Account.account._add()")

        account_name = generate_random_string(self.logger, 12)

        # check request
        if "alg" in content and "jwk" in content:

            if not self.contact_check_disable and not contact:
                code = 400
                message = self.err_msg_dic["malformed"]
                detail = "incomplete protected payload"
            else:
                # add account
                (code, message, detail) = self._account_add(
                    account_name, content, contact, payload
                )
        else:
            code = 400
            message = self.err_msg_dic["malformed"]
            detail = "incomplete protected payload"

        self.logger.debug("Account.account._add() ended with: %s", code)
        return (code, message, detail)

    def _contact_check(self, content: Dict[str, str]) -> Tuple[int, str, str]:
        """check contact information from payload"""
        self.logger.debug("Account._contact_check()")
        code = 200
        message = None
        detail = None
        if "contact" in content:
            contact_check = validate_email(self.logger, content["contact"])
            if not contact_check:
                # invalidcontact message
                code = 400
                message = self.err_msg_dic["invalidcontact"]
                detail = ", ".join(content["contact"])
        else:
            code = 400
            message = self.err_msg_dic["invalidcontact"]
            detail = "no contacts specified"

        self.logger.debug("Account._contact_check() ended with: %s", code)
        return (code, message, detail)

    def _contact_list_build(self, payload: Dict[str, str]) -> List[str]:
        """build contact list"""
        self.logger.debug("Account._contact_list_build()")

        if "contact" in payload:
            contact_list = payload["contact"]
        else:
            contact_list = []

        self.logger.debug("Account._contact_list_build() ended")
        return contact_list

    def _contacts_update(
        self, aname: str, payload: Dict[str, str]
    ) -> Tuple[int, str, str]:
        """update account"""
        self.logger.debug("Account.update()")
        (code, message, detail) = self._contact_check(payload)
        if code == 200:
            data_dic = {"name": aname, "contact": json.dumps(payload["contact"])}
            try:
                result = self.dbstore.account_update(data_dic)
            except Exception as err_:
                self.logger.critical(
                    "acme2certifier database error in Account._contacts_update(): %s",
                    err_,
                )
                result = None

            if result:
                code = 200
            else:
                code = 400
                message = self.err_msg_dic["accountdoesnotexist"]
                detail = "update failed"

        return (code, message, detail)

    def _delete(self, aname: str) -> Tuple[int, str, str]:
        """delete account"""
        self.logger.debug("Account._delete(%s)", aname)
        try:
            result = self.dbstore.account_delete(aname)
        except Exception as err_:
            self.logger.critical(
                "acme2certifier database error in Account._delete(): %s", err_
            )
            result = None

        if result:
            code = 200
            message = None
            detail = None
        else:
            code = 400
            message = self.err_msg_dic["accountdoesnotexist"]
            detail = "deletion failed"

        self.logger.debug("Account._delete() ended with: %s", code)
        return (code, message, detail)

    def _deactivate(self, aname: str) -> Tuple[int, str, str]:
        """deactivate account"""
        self.logger.debug("Account._deactivate(%s)", aname)
        try:
            data_dic = {
                "name": aname,
                "status_id": 7,
                "jwk": f"DEACTIVATED {uts_to_date_utc(uts_now())}",
            }
            result = self.dbstore.account_update(data_dic, active=False)
        except Exception as err_:
            self.logger.critical(
                "acme2certifier database error in Account._deactivate(): %s", err_
            )
            result = None

        if result:
            code = 200
            message = None
            detail = None
        else:
            code = 400
            message = self.err_msg_dic["accountdoesnotexist"]
            detail = "deactivation failed"

        self.logger.debug("Account._deactivate() ended with: %s", code)
        return (code, message, detail)

    def _eab_jwk_compare(
        self, protected: Dict[str, str], payload: Dict[str, str]
    ) -> bool:
        """compare jwk from outer header with jwk in eab playload"""
        self.logger.debug("Account._eab_jwk_compare()")
        result = False
        if "jwk" in protected:
            self.logger.debug("compare jwk from outer and inner jws")
            # convert outer jwk into string for better comparison
            if isinstance(protected, dict):
                # extract outer jwk
                jwk_outer = protected["jwk"]
                # decode inner jwk
                jwk_inner = b64decode_pad(self.logger, payload)
                jwk_inner = json.loads(jwk_inner)
                if jwk_outer == jwk_inner:
                    result = True
                else:
                    self.logger.error("jwk from outer and inner jws do not match")
                    self.logger.debug("outer: %s", jwk_outer)
                    self.logger.debug("inner: %s", jwk_inner)
            else:
                self.logger.error("protected header: %s is not a dictionary", protected)

        self.logger.debug("_eab_jwk_compare() ended with: %s", result)
        return result

    def _eab_kid_get(self, protected: str) -> str:
        """get key identifier for eab validation"""
        self.logger.debug("Account._eab_kid_get()")
        # load protected into json format
        protected_dic = json.loads(b64decode_pad(self.logger, protected))
        # extract kid
        if isinstance(protected_dic, dict):
            eab_key_id = protected_dic.get("kid", None)
        else:
            eab_key_id = None

        self.logger.debug("Account._eab_kid_get() ended with: %s", eab_key_id)
        return eab_key_id

    def _eab_verify(self, payload: Dict[str, str]) -> Tuple[int, str, str]:
        """ " check for external account binding"""
        self.logger.debug("Account._eab_verify()")

        # get key identifier
        eab_kid = self._eab_kid_get(payload["externalaccountbinding"]["protected"])
        if eab_kid:
            # get eab_mac_key
            with self.eab_handler(self.logger) as eab_handler:
                eab_mac_key = eab_handler.mac_key_get(eab_kid)
        else:
            eab_mac_key = None

        if eab_mac_key:
            (result, error) = self._eab_signature_verify(
                payload["externalaccountbinding"], eab_mac_key
            )
            if result:
                code = 200
                message = None
                detail = None
            else:
                code = 403
                message = self.err_msg_dic["unauthorized"]
                detail = "eab signature verification failed"
                self.logger.error("Account._eab_check() returned error: %s", error)
        else:
            code = 403
            message = self.err_msg_dic["unauthorized"]
            detail = "eab kid lookup failed"

        self.logger.debug("Account._eab_verify() ended with: %s", code)
        return (code, message, detail)

    def _eab_check(
        self, protected: Dict[str, str], payload: Dict[str, str]
    ) -> Tuple[int, str, str]:
        """ " check for external account binding"""
        self.logger.debug("Account._eab_check()")

        if (
            self.eab_handler
            and protected
            and payload
            and "externalaccountbinding" in payload
            and payload["externalaccountbinding"]
        ):
            # compare JWK from protected (outer) header if jwk included in payload of external account binding
            jwk_compare = self._eab_jwk_compare(
                protected, payload["externalaccountbinding"]["payload"]
            )

            if jwk_compare and "protected" in payload["externalaccountbinding"]:
                # verify eab signature
                (code, message, detail) = self._eab_verify(payload)
            else:
                code = 403
                message = self.err_msg_dic["malformed"]
                detail = "Malformed request"
        else:
            # no external account binding key in payload - error
            code = 403
            message = self.err_msg_dic["externalaccountrequired"]
            detail = "external account binding required"

        self.logger.debug("Account._eab_check() ended with: %s", code)
        return (code, message, detail)

    def _eab_signature_verify(
        self, content: Dict[str, str], mac_key: str
    ) -> Tuple[bool, str]:
        """verify inner signature"""
        self.logger.debug("Account._eab_signature_verify()")

        if content and mac_key:
            signature = Signature(None, self.server_name, self.logger)
            jwk_ = json.dumps({"k": mac_key, "kty": "oct"})
            (sig_check, error) = signature.eab_check(json.dumps(content), jwk_)
        else:
            sig_check = False
            error = None
        self.logger.debug(
            "Account._eab_signature_verify() ended with: %s: %s", sig_check, error
        )
        return (sig_check, error)

    def _header_url_compare(
        self, outer_protected: Dict[str, str], inner_protected: Dict[str, str]
    ) -> Tuple[int, str, str]:
        """compare url header of inner and outer header"""
        self.logger.debug("Account._header_url_compare()")

        if outer_protected["url"] == inner_protected["url"]:
            if self.inner_header_nonce_allow or "nonce" not in inner_protected:
                code = 200
                message = None
                detail = None
            else:
                code = 400
                message = self.err_msg_dic["malformed"]
                detail = "inner jws must omit nonce header"
        else:
            code = 400
            message = self.err_msg_dic["malformed"]
            detail = "url parameter differ in inner and outer jws"

        self.logger.debug("Account._header_url_compare() ended with: %s", code)
        return (code, message, detail)

    def _info(self, account_obj: Dict[str, str]) -> Dict[str, str]:
        """account info"""
        self.logger.debug("Account._info()")

        if account_obj:
            response_dic = {}
            response_dic["status"] = "valid"
            response_dic["key"] = json.loads(account_obj["jwk"])
            response_dic["contact"] = json.loads(account_obj["contact"])
            response_dic["createdAt"] = date_to_datestr(account_obj["created_at"])
            if "eab_kid" in account_obj and account_obj["eab_kid"]:
                response_dic["eab_kid"] = account_obj["eab_kid"]

        self.logger.debug("Account._info() returns: %s", json.dumps(response_dic))
        return response_dic

    def _inner_jws_check(
        self, outer_protected: Dict[str, str], inner_protected: Dict[str, str]
    ) -> Tuple[int, str, str]:
        """RFC8655 7.3.5 checs of inner JWS"""
        self.logger.debug("Account._inner_jws_check()")

        # check for jwk header
        if "jwk" in inner_protected:
            if "url" in outer_protected and "url" in inner_protected:
                # inner and outer JWS must have the same "url" header parameter
                (code, message, detail) = self._header_url_compare(
                    outer_protected, inner_protected
                )
            else:
                code = 400
                message = self.err_msg_dic["malformed"]
                detail = "inner or outer jws is missing url header parameter"
        else:
            code = 400
            message = self.err_msg_dic["malformed"]
            detail = "inner jws is missing jwk"

        self.logger.debug("Account._inner_jws_check() ended with: %s:%s", code, detail)
        return (code, message, detail)

    def _inner_payload_check(
        self, aname: str, outer_protected: Dict[str, str], inner_payload: Dict[str, str]
    ) -> Tuple[int, str, str]:
        """RFC8655 7.3.5 checs of inner payload"""
        self.logger.debug("Account._inner_payload_check()")

        if "kid" in outer_protected:
            if "account" in inner_payload:
                if outer_protected["kid"] == inner_payload["account"]:
                    if "oldkey" in inner_payload:
                        # compare oldkey with database
                        (code, message, detail) = self._key_compare(
                            aname, inner_payload["oldkey"]
                        )
                    else:
                        code = 400
                        message = self.err_msg_dic["malformed"]
                        detail = "old key is missing"
                else:
                    code = 400
                    message = self.err_msg_dic["malformed"]
                    detail = "kid and account objects do not match"
            else:
                code = 400
                message = self.err_msg_dic["malformed"]
                detail = "account object is missing on inner payload"
        else:
            code = 400
            message = self.err_msg_dic["malformed"]
            detail = "kid is missing in outer header"

        self.logger.debug(
            "Account._inner_payload_check() ended with: %s:%s", code, detail
        )
        return (code, message, detail)

    def _key_change_validate(
        self,
        aname: str,
        outer_protected: Dict[str, str],
        inner_protected: Dict[str, str],
        inner_payload: Dict[str, str],
    ):
        """validate key_change before exectution"""
        self.logger.debug("Account._key_change_validate(%s)", aname)
        if "jwk" in inner_protected:
            # check if we already have the key stored in DB
            key_exists = self._lookup(json.dumps(inner_protected["jwk"]), "jwk")
            if not key_exists:
                (code, message, detail) = self._inner_jws_check(
                    outer_protected, inner_protected
                )

                if code == 200:
                    (code, message, detail) = self._inner_payload_check(
                        aname, outer_protected, inner_payload
                    )
            else:
                code = 400
                message = self.err_msg_dic["badpubkey"]
                detail = "public key does already exists"
        else:
            code = 400
            message = self.err_msg_dic["malformed"]
            detail = "inner jws is missing jwk"

        self.logger.debug(
            "Account._key_change_validate() ended with: %s:%s", code, detail
        )
        return (code, message, detail)

    def _key_rollover(
        self,
        aname: str,
        protected: Dict[str, str],
        inner_protected: Dict[str, str],
        inner_payload: Dict[str, str],
    ) -> Tuple[int, str, str]:
        """key update after key change"""
        self.logger.debug("Account._key_rollover(%s)", aname)

        (code, message, detail) = self._key_change_validate(
            aname, protected, inner_protected, inner_payload
        )
        if code == 200:
            data_dic = {"name": aname, "jwk": json.dumps(inner_protected["jwk"])}
            try:
                result = self.dbstore.account_update(data_dic)
            except Exception as err_:
                self.logger.critical(
                    "acme2certifier database error in Account._key_change(): %s", err_
                )
                result = None
            if result:
                code = 200
                message = None
                detail = None
            else:
                code = 500
                message = self.err_msg_dic["serverinternal"]
                detail = "key rollover failed"

        self.logger.debug("Account._key_rollover() ended with: %s", code)
        return (code, message, detail)

    def _key_change(
        self, aname: str, payload: Dict[str, str], protected: Dict[str, str]
    ) -> Tuple[int, str, str]:
        """key change for a given account"""
        self.logger.debug("Account._key_change(%s)", aname)

        if "url" in protected:
            if "key-change" in protected["url"]:
                # check message
                (
                    code,
                    message,
                    detail,
                    inner_protected,
                    inner_payload,
                    _account_name,
                ) = self.message.check(
                    json.dumps(payload), use_emb_key=True, skip_nonce_check=True
                )
                if code == 200:
                    # key rollover
                    (code, message, detail) = self._key_rollover(
                        aname, protected, inner_protected, inner_payload
                    )
            else:
                code = 400
                message = self.err_msg_dic["malformed"]
                detail = "malformed request. not a key-change"
        else:
            code = 400
            message = self.err_msg_dic["malformed"]
            detail = "malformed request"

        self.logger.debug("Account._key_change() ended with: %s", code)
        return (code, message, detail)

    def _keys_adjust(
        self, pub_key: Dict[str, str], old_key: Dict[str, str]
    ) -> Tuple[Dict[str, str], Dict[str, str]]:
        """adjust keys to cover corner cases"""
        self.logger.debug("Account._key_compare()")
        if "alg" in pub_key:
            # Posh-Acme does not send 'alg' attribute in old key
            if "alg" not in old_key:
                old_key["alg"] = pub_key["alg"]
            # rewrite alg statement in pubkey for acmeshell
            if pub_key["alg"].startswith("ES") and old_key["alg"] == "ECDSA":
                pub_key["alg"] = "ECDSA"

        self.logger.debug("Account._keys_adjust()")
        return (pub_key, old_key)

    def _key_compare(self, aname: str, old_key: Dict[str, str]) -> Tuple[int, str, str]:
        """compare key with the one stored in database"""
        self.logger.debug("Account._key_compare(%s)", aname)

        # load current public key from database
        try:
            pub_key = self.dbstore.jwk_load(aname)
        except Exception as err_:
            self.logger.critical(
                "acme2certifier database error in Account._key_compare(): %s", err_
            )
            pub_key = None

        if old_key and pub_key:
            # modify key format to prepare comparison
            (pub_key, old_key) = self._keys_adjust(pub_key, old_key)

            if old_key == pub_key:
                code = 200
                message = None
                detail = None
            else:
                code = 401
                message = self.err_msg_dic["unauthorized"]
                detail = "wrong public key"
        else:
            code = 401
            message = self.err_msg_dic["unauthorized"]
            detail = "wrong public key"

        self.logger.debug("Account._key_compare() ended with: %s", code)
        return (code, message, detail)

    def _config_load(self):
        """ " load config from file"""
        self.logger.debug("Account._config_load()")
        config_dic = load_config()

        self.inner_header_nonce_allow = config_dic.getboolean(
            "Account", "inner_header_nonce_allow", fallback=False
        )
        self.ecc_only = config_dic.getboolean("Account", "ecc_only", fallback=False)
        self.tos_check_disable = config_dic.getboolean(
            "Account", "tos_check_disable", fallback=False
        )
        self.contact_check_disable = config_dic.getboolean(
            "Account", "contact_check_disable", fallback=False
        )

        if "EABhandler" in config_dic:
            self.logger.debug("Account._config.load(): loading eab_handler")
            # mandate eab check regardless if handler is configured or could get loaded or not
            self.eab_check = True
            if "eab_handler_file" in config_dic["EABhandler"]:
                # load eab_handler according to configuration
                eab_handler_module = eab_handler_load(self.logger, config_dic)
                if eab_handler_module:
                    # store handler in variable
                    self.eab_handler = eab_handler_module.EABhandler
                else:
                    self.logger.critical("EABHandler could not get loaded")
            else:
                self.logger.critical("EABHandler configuration incomplete")

        self.tos_url = config_dic.get("Directory", "tos_url", fallback=None)
        if config_dic.get("Directory", "url_prefix", fallback=None):
            self.path_dic = {
                k: config_dic.get("Directory", "url_prefix") + v
                for k, v in self.path_dic.items()
            }
        self.logger.debug("Account._config_load() ended")

    def _lookup(self, value: str, field: str = "name") -> Dict[str, str]:
        """lookup account"""
        self.logger.debug("Account._lookup(%s:%s)", field, value)
        try:
            result = self.dbstore.account_lookup(field, value)
        except Exception as err_:
            self.logger.critical(
                "acme2certifier database error in Account._lookup(): %s", err_
            )
            result = None
        return result

    # pylint: disable=W0212
    def _name_get(self, content: Dict[str, str]) -> str:
        """get id for account depricated"""
        self.logger.debug("Account._name_get()")
        # _deprecated
        return self.message._name_get(content)

    def _onlyreturnexisting(
        self, protected: Dict[str, str], payload: Dict[str, str]
    ) -> Tuple[int, str, str]:
        """check onlyreturnexisting"""
        self.logger.debug("Account._onlyreturnexisting(}")

        if "onlyreturnexisting" in payload:
            if payload["onlyreturnexisting"]:
                code = None
                message = None
                detail = None

                if "jwk" in protected:
                    (code, message, detail) = self._account_lookup(protected["jwk"])
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

    def _parse_deactivation(
        self, account_name: str, payload: Dict[str, str]
    ) -> Tuple[int, str, str]:
        self.logger.debug("Account._parse_deactivation(%s)", account_name)
        data = None
        # account deactivation
        if payload["status"].lower() == "deactivated":
            (code, message, detail) = self._deactivate(account_name)
            if code == 200:
                data = payload
        else:
            code = 400
            message = self.err_msg_dic["malformed"]
            detail = "status attribute without sense"

        self.logger.debug("Account._parse_deactivation() ended")
        return (code, message, detail, data)

    def _parse_contacts_update(
        self, account_name: str, payload: Dict[str, str]
    ) -> Tuple[int, str, str, Dict[str, str]]:
        """update contacts"""
        self.logger.debug("Account._parse_contacts_update(%s)", account_name)
        data = None
        (code, message, detail) = self._contacts_update(account_name, payload)
        if code == 200:
            account_obj = self._lookup(account_name)
            data = self._info(account_obj)
        else:
            code = 400
            message = self.err_msg_dic["accountdoesnotexist"]
            detail = "update failed"

        self.logger.debug("Account._parse_contacts_update() ended")
        return (code, message, detail, data)

    def _parse_query(self, account_name: str) -> Dict[str, str]:
        """update contacts"""
        self.logger.debug("Account._parse_query(%s)", account_name)

        # this is a query for account information
        account_obj = self._lookup(account_name)
        if account_obj:
            data = self._info(account_obj)
            data["status"] = "valid"
        else:
            data = {"status": "invalid"}

        self.logger.debug("Account._parse_query() ended")
        return data

    def _tos_check(self, content: Dict[str, str]) -> Tuple[int, str, str]:
        """check terms of service"""
        self.logger.debug("Account._tos_check()")
        if "termsofserviceagreed" in content:
            self.logger.debug("tos:%s", content["termsofserviceagreed"])
            if content["termsofserviceagreed"]:
                code = 200
                message = None
                detail = None
            else:
                code = 403
                message = self.err_msg_dic["useractionrequired"]
                detail = "tosfalse"
        else:
            self.logger.debug("no tos statement found.")
            code = 403
            message = self.err_msg_dic["useractionrequired"]
            detail = "tosfalse"

        self.logger.debug("Account._tos_check() ended with:%s", code)
        return (code, message, detail)

    def _new(
        self, code: int, payload: Dict[str, str], protected: Dict[str, str]
    ) -> Tuple[int, str, str]:
        """generate a new account"""
        self.logger.debug("Account._new()")

        # onlyReturnExisting check
        if "onlyreturnexisting" in payload:
            (code, message, detail) = self._onlyreturnexisting(protected, payload)
        else:
            # tos check
            if self.tos_url and not self.tos_check_disable:
                (code, message, detail) = self._tos_check(payload)

            # check for external account binding
            if code == 200 and self.eab_check:
                (code, message, detail) = self._eab_check(protected, payload)

            # contact check
            if code == 200 and not self.contact_check_disable:
                (code, message, detail) = self._contact_check(payload)

            # add account to database
            if code == 200:
                contact_list = self._contact_list_build(payload)

                # add new account
                (code, message, detail) = self._add(protected, payload, contact_list)

        self.logger.debug("Account._new() ended with: %s", code)
        return (code, message, detail)

    def new(self, content: Dict[str, str]) -> Dict[str, str]:
        """generate a new account"""
        self.logger.debug("Account.new()")

        response_dic = {}
        # check message but skip signature check as this is a new account (True)
        (code, message, detail, protected, payload, _account_name) = self.message.check(
            content, True
        )
        if code == 200:
            (code, message, detail) = self._new(code, payload, protected)

        if code in (200, 201):
            response_dic["data"] = {}
            if code == 201:
                response_dic["data"] = {
                    "status": "valid",
                    "orders": f'{self.server_name}{self.path_dic["acct_path"]}{message}/orders',
                }
                if "contact" in payload:
                    response_dic["data"]["contact"] = payload["contact"]
            elif code == 200 and detail and "status" in detail:
                response_dic["data"] = detail

            response_dic["header"] = {}
            response_dic["header"][
                "Location"
            ] = f'{self.server_name}{self.path_dic["acct_path"]}{message}'

            # add exernal account binding
            if self.eab_check and "externalaccountbinding" in payload:
                response_dic["data"]["externalaccountbinding"] = payload[
                    "externalaccountbinding"
                ]

        else:
            if detail == "tosfalse":
                detail = "Terms of service must be accepted"

        # prepare/enrich response
        status_dic = {"code": code, "type": message, "detail": detail}
        response_dic = self.message.prepare_response(response_dic, status_dic)

        self.logger.debug("Account.new() returns: %s", json.dumps(response_dic))
        return response_dic

    def parse(self, content: Dict[str, str]) -> Dict[str, str]:
        """parse message"""
        self.logger.debug("Account.parse()")

        response_dic = {}

        data = None
        # check message
        (code, message, detail, protected, payload, account_name) = self.message.check(
            content
        )
        if code == 200:
            if "status" in payload:
                (code, message, detail, data) = self._parse_deactivation(
                    account_name, payload
                )

            elif "contact" in payload:
                (code, message, detail, data) = self._parse_contacts_update(
                    account_name, payload
                )

            elif "payload" in payload:
                # this could be a key-change
                (code, message, detail) = self._key_change(
                    account_name, payload, protected
                )
                if code == 200:
                    response_dic["data"] = {}
            elif not payload:
                data = self._parse_query(account_name)
            else:
                code = 400
                message = self.err_msg_dic["malformed"]
                detail = "dont know what to do with this request"

        if data:
            response_dic["data"] = data

        # prepare/enrich response
        status_dic = {"code": code, "type": message, "detail": detail}
        response_dic = self.message.prepare_response(response_dic, status_dic)

        self.logger.debug(
            "Account.account_parse() returns: %s", json.dumps(response_dic)
        )
        return response_dic
