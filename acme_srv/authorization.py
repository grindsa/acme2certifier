# -*- coding: utf-8 -*-
"""Order class"""
# pylint: disable=R0913
from __future__ import print_function
import json
from typing import List, Tuple, Dict
from acme_srv.db_handler import DBstore
from acme_srv.challenge import Challenge
from acme_srv.helper import (
    generate_random_string,
    uts_now,
    uts_to_date_utc,
    load_config,
    string_sanitize,
)
from acme_srv.message import Message
from acme_srv.nonce import Nonce


class Authorization(object):
    """class for Authorization handling"""

    def __init__(
        self, debug: bool = False, srv_name: str = None, logger: object = None
    ):
        self.server_name = srv_name
        self.debug = debug
        self.logger = logger
        self.dbstore = DBstore(debug, self.logger)
        self.message = Message(debug, self.server_name, self.logger)
        self.nonce = Nonce(debug, self.logger)
        self.validity = 86400
        self.expiry_check_disable = False
        self.path_dic = {"authz_path": "/acme/authz/"}

    def __enter__(self):
        """Makes ACMEHandler a Context Manager"""
        self._config_load()
        return self

    def __exit__(self, *args):
        """cose the connection at the end of the context"""

    def _expiry_update(self, authz_name: str, token: str, expires: int):
        """expiry date and token of an existing authorization"""
        self.logger.debug("Authorization._expiry_update()")

        try:
            self.dbstore.authorization_update(
                {"name": authz_name, "token": token, "expires": expires}
            )
        except Exception as err_:
            self.logger.error(
                "acme2certifier database error in Authorization._expiry_update(%s) update: %s",
                authz_name,
                err_,
            )

        self.logger.debug("Authorization._expiry_update() ended")

    def _authz_lookup(self, authz_name: str, vlist: List[str] = None) -> Dict[str, str]:
        self.logger.debug("Authorization._authz_lookup(%s)", authz_name)

        # lookup authorization based on name
        try:
            if vlist:
                authz = self.dbstore.authorization_lookup("name", authz_name, vlist)
            else:
                authz = self.dbstore.authorization_lookup("name", authz_name)
        except Exception as err_:
            self.logger.critical(
                "acme2certifier database error in Authorization._authz_lookup(%s) lookup: %s",
                authz_name,
                err_,
            )
            authz = None

        self.logger.debug("Authorization._authz_lookup() ended")
        return authz

    def _challengeset_get(
        self,
        authz_info_dic: Dict[str, str],
        authz_name: str,
        token: str,
        tnauth: bool,
        expires: int,
    ) -> Dict[str, str]:
        """get challenge set"""
        self.logger.debug("Authorization._challengeset_get(%s)", authz_name)

        with Challenge(self.debug, self.server_name, self.logger, expires) as challenge:
            # get challenge data (either existing or new ones)
            if "identifier" in authz_info_dic:
                if "type" in authz_info_dic["identifier"]:
                    id_type = authz_info_dic["identifier"]["type"]
                else:
                    id_type = None
                if "value" in authz_info_dic["identifier"]:
                    id_value = authz_info_dic["identifier"]["value"]
                else:
                    id_value = None
            else:
                id_type = None
                id_value = None

            self.logger.debug("Authorization._challengeset_get() ended")
            return challenge.challengeset_get(
                authz_name, authz_info_dic["status"], token, tnauth, id_type, id_value
            )

    def _authz_info_dic_update(
        self, authz_info_dic: Dict[str, str], auth_info: Dict[str, str]
    ) -> Tuple[Dict[str, str], bool]:
        """enrich authinfo dic with information"""
        self.logger.debug("Authorization._authz_info_dic_update()")

        tnauth = False
        if "status__name" in auth_info[0]:
            authz_info_dic["status"] = auth_info[0]["status__name"]
        else:
            authz_info_dic["status"] = "pending"

        if "type" in auth_info[0] and "value" in auth_info[0]:
            authz_info_dic["identifier"] = {
                "type": auth_info[0]["type"],
                "value": auth_info[0]["value"],
            }
            if auth_info[0]["type"] == "TNAuthList":
                tnauth = True
            # add wildcard flag into authoritzation response and modify identifier
            if auth_info[0]["value"].startswith("*."):
                self.logger.debug("Authorization._authz_info() - adding wildcard flag")
                authz_info_dic["identifier"]["value"] = auth_info[0]["value"][2:]
                authz_info_dic["wildcard"] = True

        self.logger.debug("Authorization._authz_info_dic_update() ended")
        return (authz_info_dic, tnauth)

    def _authz_info(self, url: str) -> Dict[str, str]:
        """return authzs information"""
        self.logger.debug("Authorization._authz_info()")

        authz_name = string_sanitize(
            self.logger,
            url.replace(f'{self.server_name}{self.path_dic["authz_path"]}', ""),
        )
        self.logger.debug("Authorization._authz_info(%s)", authz_name)

        expires = uts_now() + self.validity
        token = generate_random_string(self.logger, 32)
        authz_info_dic = {}

        # lookup authorization based on name
        authz = self._authz_lookup(authz_name)

        if authz:
            # update authorization with expiry date and token (just to be sure)
            self._expiry_update(authz_name, token, expires)
            authz_info_dic["expires"] = uts_to_date_utc(expires)

            # get authorization information from db to be inserted in message
            tnauth = False
            auth_info = self._authz_lookup(
                authz_name, ["status__name", "type", "value"]
            )

            if auth_info:
                (authz_info_dic, tnauth) = self._authz_info_dic_update(
                    authz_info_dic, auth_info
                )
            else:
                authz_info_dic["status"] = "pending"

            # get challenge-set
            authz_info_dic["challenges"] = self._challengeset_get(
                authz_info_dic, authz_name, token, tnauth, expires
            )

        self.logger.debug(
            "Authorization._authz_info() returns: %s", json.dumps(authz_info_dic)
        )
        return authz_info_dic

    def _config_load(self):
        """ " load config from file"""
        self.logger.debug("Authorization._config_load()")

        config_dic = load_config()

        try:
            self.validity = int(
                config_dic.get("Authorization", "validity", fallback=self.validity)
            )
        except ValueError:
            self.logger.warning(
                "Failed to parse validity parameter: %s",
                config_dic.get("Authorization", "validity"),
            )

        self.expiry_check_disable = config_dic.getboolean(
            "Authorization", "expiry_check_disable", fallback=False
        )
        if config_dic.get("Directory", "url_prefix", fallback=None):
            self.path_dic = {
                k: config_dic.get("Directory", "url_prefix") + v
                for k, v in self.path_dic.items()
            }
        self.logger.debug("Authorization._config_load() ended.")

    def invalidate(self, timestamp: int = None) -> Tuple[List[str], List[str]]:
        """invalidate authorizations"""
        self.logger.debug("Authorization.invalidate(%s)", timestamp)
        if not timestamp:
            timestamp = uts_now()
            self.logger.debug(
                "Authorization.invalidate(): set timestamp to %s", timestamp
            )

        field_list = [
            "id",
            "name",
            "expires",
            "value",
            "created_at",
            "token",
            "status__id",
            "status__name",
            "order__id",
            "order__name",
        ]
        try:
            authz_list = self.dbstore.authorizations_expired_search(
                "expires", timestamp, vlist=field_list, operant="<="
            )
        except Exception as err_:
            self.logger.critical(
                "acme2certifier database error in Authorization.invalidate(): %s", err_
            )
            authz_list = []

        output_list = []
        for authz in authz_list:
            # select all authz which are not invalid
            if (
                "name" in authz
                and "status__name" in authz
                and authz["status__name"] != "expired"
            ):
                # skip corner cases where authz expiry is set to 0
                if "expires" not in authz or authz["expires"] > 0:
                    # change status and add to output list
                    output_list.append(authz)
                    data_dic = {"name": authz["name"], "status": "expired"}
                    try:
                        self.dbstore.authorization_update(data_dic)
                    except Exception as err_:
                        self.logger.critical(
                            "acme2certifier database error in Authorization.invalidate(): %s",
                            err_,
                        )

        self.logger.debug(
            "Authorization.invalidate() ended: %s authorizations identified",
            len(output_list),
        )
        return (field_list, output_list)

    def new_get(self, url: str) -> Dict[str, str]:
        """challenge computation based on get request"""
        self.logger.debug("Authorization.new_get()")
        response_dic = {}
        response_dic["code"] = 200
        response_dic["header"] = {}
        response_dic["data"] = self._authz_info(url)
        return response_dic

    def new_post(self, content: str) -> Dict[str, str]:
        """challenge computation based on post request"""
        self.logger.debug("Authorization.new_post()")

        # invalidate expired authorizations
        if not self.expiry_check_disable:
            self.invalidate()

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
                auth_info = self._authz_info(protected["url"])
                if auth_info:
                    response_dic["data"] = auth_info
                else:
                    code = 403
                    message = "urn:ietf:params:acme:error:unauthorized"
                    detail = "authorizations lookup failed"
            else:
                code = 400
                message = "urn:ietf:params:acme:error:malformed"
                detail = "url is missing in protected"

        # prepare/enrich response
        status_dic = {"code": code, "type": message, "detail": detail}
        response_dic = self.message.prepare_response(response_dic, status_dic)

        self.logger.debug(
            "Authorization.new_post() returns: %s", json.dumps(response_dic)
        )
        return response_dic
