# pylint: disable=c0302, r0913
# -*- coding: utf-8 -*-
"""Challenge class"""
from __future__ import print_function
import json
import time
from typing import List, Tuple, Dict
from acme_srv.helper import (
    b64_encode,
    b64_url_encode,
    cert_extensions_get,
    cert_san_get,
    config_eab_profile_load,
    error_dic_get,
    fqdn_in_san_check,
    fqdn_resolve,
    generate_random_string,
    ip_validate,
    jwk_thumbprint_get,
    load_config,
    parse_url,
    proxy_check,
    servercert_get,
    sha256_hash,
    sha256_hash_hex,
    txt_get,
    url_get,
    uts_now,
    uts_to_date_utc,
)
from acme_srv.db_handler import DBstore
from acme_srv.email_handler import EmailHandler
from acme_srv.message import Message
from acme_srv.threadwithreturnvalue import ThreadWithReturnValue


class Challenge(object):
    """Challenge handler"""

    def __init__(
        self,
        debug: bool = False,
        srv_name: str = None,
        logger: object = None,
        source: str = None,
        expiry: int = 3600,
    ):
        self.challenge_validation_disable = False
        self.challenge_validation_timeout = 10
        self.dns_server_list = None
        self.dns_validation_pause_timer = 0.5
        self.eab_handler = None
        self.eab_profiling = False
        self.expiry = expiry
        self.logger = logger
        self.path_dic = {"chall_path": "/acme/chall/", "authz_path": "/acme/authz/"}
        self.proxy_server_list = {}
        self.sectigo_sim = False
        self.server_name = srv_name
        self.source_address = source
        self.tnauthlist_support = False
        self.email_identifier_support = False
        self.email_address = None
        self.dbstore = DBstore(debug, self.logger)
        self.err_msg_dic = error_dic_get(self.logger)
        self.message = Message(debug, self.server_name, self.logger)
        self.source_address_check = False

    def __enter__(self):
        """Makes ACMEHandler a Context Manager"""
        self._config_load()
        return self

    def __exit__(self, *args):
        """close the connection at the end of the context"""

    def _challengelist_search(
        self,
        key: str,
        value: str,
        vlist: List = ("name", "type", "status__name", "token"),
    ) -> List[str]:
        """get exsting challenges for a given authorization"""
        self.logger.debug("Challenge._challengelist_search()")

        try:
            challenge_list = self.dbstore.challenges_search(key, value, vlist)
        except Exception as err_:
            self.logger.critical(
                "Database error: failed to search for challenges: %s", err_
            )
            challenge_list = []

        challenge_dic = {}
        for challenge in challenge_list:
            if challenge["type"] not in challenge_dic:
                challenge_dic[challenge["type"]] = {}

            challenge_dic[challenge["type"]]["token"] = challenge["token"]
            challenge_dic[challenge["type"]]["type"] = challenge["type"]
            challenge_dic[challenge["type"]]["url"] = challenge["name"]
            challenge_dic[challenge["type"]][
                "url"
            ] = f"{self.server_name}{self.path_dic['chall_path']}{challenge['name']}"
            challenge_dic[challenge["type"]]["name"] = challenge["name"]
            if "status__name" in challenge:
                challenge_dic[challenge["type"]]["status"] = challenge["status__name"]

        challenge_list = []
        for challenge, challenge_items in challenge_dic.items():
            challenge_list.append(challenge_items)

        self.logger.debug(
            "Challenge._challengelist_search() ended with: %s", challenge_list
        )
        return challenge_list

    def _challenge_validate_loop(
        self,
        challenge_name: str,
        challenge_dic: Dict[str, str],
        payload: Dict[str, str],
        jwk_thumbprint: str,
    ) -> Tuple[bool, bool]:
        """inner loop function to validate challenges"""
        self.logger.debug("Challenge._challenge_validate_loop(%s)", challenge_name)

        if challenge_dic["type"] == "http-01" and jwk_thumbprint:
            (result, invalid) = self._validate_http_challenge(
                challenge_name,
                challenge_dic["authorization__type"],
                challenge_dic["authorization__value"],
                challenge_dic["token"],
                jwk_thumbprint,
            )
        elif challenge_dic["type"] == "dns-01" and jwk_thumbprint:
            (result, invalid) = self._validate_dns_challenge(
                challenge_name,
                challenge_dic["authorization__type"],
                challenge_dic["authorization__value"],
                challenge_dic["token"],
                jwk_thumbprint,
            )
        elif challenge_dic["type"] == "tls-alpn-01" and jwk_thumbprint:
            (result, invalid) = self._validate_alpn_challenge(
                challenge_name,
                challenge_dic["authorization__type"],
                challenge_dic["authorization__value"],
                challenge_dic["token"],
                jwk_thumbprint,
            )
        elif (
            challenge_dic["type"] == "tkauth-01"
            and jwk_thumbprint
            and self.tnauthlist_support
        ):
            (result, invalid) = self._validate_tkauth_challenge(
                challenge_name,
                challenge_dic["authorization__type"],
                challenge_dic["authorization__value"],
                challenge_dic["token"],
                jwk_thumbprint,
                payload,
            )
        else:
            self.logger.error(
                'Unknown challenge type "%s". Setting check result to False',
                challenge_dic["type"],
            )
            result = False
            invalid = True

        self.logger.debug(
            "Challenge._challenge_validate_loop() ended with: %s/%s", result, invalid
        )
        return (result, invalid)

    def _challenge_validate(
        self,
        pub_key: Dict[str, str],
        challenge_name: str,
        challenge_dic: Dict[str, str],
        payload: Dict[str, str],
    ) -> Tuple[bool, bool]:
        """challenge validate"""
        self.logger.debug("Challenge._challenge_validate(%s)", challenge_name)

        jwk_thumbprint = jwk_thumbprint_get(self.logger, pub_key)

        for _ele in range(0, 5):

            result, invalid = self._challenge_validate_loop(
                challenge_name, challenge_dic, payload, jwk_thumbprint
            )
            # pylint: disable=r1723
            if result or invalid:
                # break loop if we got any good or bad response
                break
            elif challenge_dic["type"] == "dns-01" and jwk_thumbprint:
                # sleep for a while before we try again
                time.sleep(self.dns_validation_pause_timer)

        self.logger.debug(
            "Challenge._challenge_validate() ended with: %s/%s", result, invalid
        )
        return (result, invalid)

    def _check(self, challenge_name: str, payload: Dict[str, str]) -> Tuple[bool, bool]:
        """challenge check"""
        self.logger.debug("Challenge._check(%s)", challenge_name)

        try:
            challenge_dic = self.dbstore.challenge_lookup(
                "name",
                challenge_name,
                [
                    "type",
                    "status__name",
                    "token",
                    "authorization__name",
                    "authorization__type",
                    "authorization__value",
                    "authorization__token",
                    "authorization__order__account__name",
                ],
            )
        except Exception as err_:
            self.logger.critical(
                "Database error: failed to lookup challenge during challenge check:'%s': %s",
                challenge_name,
                err_,
            )
            challenge_dic = {}

        if (
            "type" in challenge_dic
            and "authorization__value" in challenge_dic
            and "token" in challenge_dic
            and "authorization__order__account__name" in challenge_dic
        ):
            try:
                pub_key = self.dbstore.jwk_load(
                    challenge_dic["authorization__order__account__name"]
                )
            except Exception as err_:
                self.logger.critical("Database error: could not get jwk: %s", err_)
                pub_key = None

            if pub_key:
                (result, invalid) = self._challenge_validate(
                    pub_key, challenge_name, challenge_dic, payload
                )
            else:
                result = False
                invalid = False
        else:
            result = False
            invalid = False

        self.logger.debug("challenge._check() ended with: %s/%s", result, invalid)
        return (result, invalid)

    def _existing_challenge_validate(self, challenge_list: List[str]) -> Dict[str, str]:
        """validate an existing challenge set"""
        self.logger.debug("Challenge._existing_challenge_validate()")

        # for challenge in challenge_list:
        for challenge in sorted(challenge_list, key=lambda k: k["type"]):
            challenge_check = self._validate(challenge["name"], {})
            if challenge_check:
                # end loop if challenge check was successful
                break
        self.logger.debug("Challenge._existing_challenge_validate ended()")

    def _info(self, challenge_name):
        """get challenge details"""
        self.logger.debug("Challenge._info(%s)", challenge_name)
        try:
            challenge_dic = self.dbstore.challenge_lookup(
                "name",
                challenge_name,
                vlist=("type", "token", "status__name", "validated"),
            )
        except Exception as err_:
            self.logger.critical(
                "Database error: failed to lookup challenge: '%s': %s",
                challenge_name,
                err_,
            )
            challenge_dic = {}

        if "status" in challenge_dic and challenge_dic["status"] == "valid":
            if "validated" in challenge_dic:
                # convert validated timestamp to RFC3339 format - if it fails remove key from dictionary
                try:
                    challenge_dic["validated"] = uts_to_date_utc(
                        challenge_dic["validated"]
                    )
                except Exception:
                    challenge_dic.pop("validated")
        else:
            if "validated" in challenge_dic:
                challenge_dic.pop("validated")

        if self.email_identifier_support and self.email_address:
            # add email address to challenge_dic for email-reply-00 challenges
            self.logger.debug("Adding email address to challenge_dic")
            challenge_dic["from"] = self.email_address

        self.logger.debug("Challenge._info(%s) ended", challenge_name)
        return challenge_dic

    def _config_proxy_load(self, config_dic: Dict[str, str]):
        """load proxy config"""
        self.logger.debug("Challenge._config_proxy_load()")

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

        self.logger.debug("Challenge._config_proxy_load() ended")

    def _config_dns_load(self, config_dic: Dict[str, str]):
        """load dns config"""
        self.logger.debug("Challenge._config_dns_load()")

        if "Challenge" in config_dic and "dns_server_list" in config_dic["Challenge"]:
            try:
                self.dns_server_list = json.loads(
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
                self.dns_validation_pause_timer = int(
                    config_dic["Challenge"]["dns_validation_pause_timer"]
                )
            except Exception as err_:
                self.logger.warning(
                    "Failed to parse dns_validation_pause_timer from configuration: %s",
                    err_,
                )

        self.logger.debug("Challenge._config_dns_load() ended")

    def _config_challenge_load(self, config_dic: Dict[str, str]):
        """load proxy config"""
        self.logger.debug("Challenge._config_challenge_load()")

        if "Challenge" in config_dic:
            self.challenge_validation_disable = config_dic.getboolean(
                "Challenge", "challenge_validation_disable", fallback=False
            )
            self.source_address_check = config_dic.getboolean(
                "Challenge", "source_address_check", fallback=False
            )
            self.sectigo_sim = config_dic.getboolean(
                "Challenge", "sectigo_sim", fallback=False
            )
            try:
                self.challenge_validation_timeout = int(
                    config_dic.get(
                        "Challenge",
                        "challenge_validation_timeout",
                        fallback=self.challenge_validation_timeout,
                    )
                )
            except Exception as err_:
                self.logger.warning(
                    "Failed to parse challenge_validation_timeout from configuration: %s",
                    err_,
                )

        self.logger.debug("Challenge._config_challenge_load() ended")

    def _config_load(self):
        """ " load config from file"""
        self.logger.debug("Challenge._config_load()")
        config_dic = load_config()

        # load challenge parameters
        self._config_challenge_load(config_dic)
        self._config_dns_load(config_dic)

        if "Order" in config_dic:
            self.tnauthlist_support = config_dic.getboolean(
                "Order", "tnauthlist_support", fallback=False
            )
            self.email_identifier_support = config_dic.getboolean(
                "Order", "email_identifier_support", fallback=False
            )

        if (
            self.email_identifier_support
            and "DEFAULT" in config_dic
            and "email_address" in config_dic["DEFAULT"]
        ):
            self.email_address = config_dic["DEFAULT"].get("email_address")
        else:
            self.logger.warning(
                "Email identifier support is enabled but no email address is configured. Disabling email identifier support."
            )
            self.email_identifier_support = False

        if "Directory" in config_dic and "url_prefix" in config_dic["Directory"]:
            self.path_dic = {
                k: config_dic["Directory"]["url_prefix"] + v
                for k, v in self.path_dic.items()
            }

        # load proxy config from config
        self._config_proxy_load(config_dic)
        # load profiling
        self.eab_profiling, self.eab_handler = config_eab_profile_load(
            self.logger, config_dic
        )
        self.logger.debug("Challenge._config_load() ended.")

    def _cvd_via_eabprofile_check(self, challenge_name: str) -> bool:
        """parse challenge profile"""
        self.logger.debug("Challenge._cvd_via_eabprofile_check(%s)", challenge_name)

        challenge_validation_disable = False
        if self.eab_profiling and self.eab_handler:
            try:
                challenge_dic = self.dbstore.challenge_lookup(
                    "name",
                    challenge_name,
                    [
                        "status__name",
                        "authorization__order__account__name",
                        "authorization__order__account__eab_kid",
                    ],
                )
            except Exception as err_:
                self.logger.critical(
                    "Database error: failed to lookup challenge during profile check:'%s': %s",
                    challenge_name,
                    err_,
                )
                challenge_dic = {}

            if (
                "authorization__order__account__eab_kid" in challenge_dic
                and challenge_dic["authorization__order__account__eab_kid"]
            ):
                # if eab_kid is set, we need to return the profile
                eab_kid = challenge_dic["authorization__order__account__eab_kid"]

                with self.eab_handler(self.logger) as eab_handler:
                    profile_dic = eab_handler.key_file_load()
                    if (
                        eab_kid in profile_dic
                        and "challenge" in profile_dic[eab_kid]
                        and "challenge_validation_disable"
                        in profile_dic[eab_kid]["challenge"]
                    ):
                        challenge_validation_disable = (
                            profile_dic.get(eab_kid, {})
                            .get("challenge", {})
                            .get("challenge_validation_disable", False)
                        )

        self.logger.debug(
            "Challenge._profile_parse() ended with: %s", challenge_validation_disable
        )
        return challenge_validation_disable

    def _extensions_validate(self, cert: str, extension_value: str, fqdn: str) -> bool:
        """validate extension"""
        self.logger.debug(
            "Challenge._extensions_validate(%s/%s)", extension_value, fqdn
        )
        result = False
        san_list = cert_san_get(self.logger, cert, recode=False)
        fqdn_in_san = fqdn_in_san_check(self.logger, san_list, fqdn)
        if fqdn_in_san:
            extension_list = cert_extensions_get(self.logger, cert, recode=False)
            if extension_value in extension_list:
                self.logger.debug("alpn validation successful")
                result = True
            else:
                self.logger.debug("alpn validation not successful")
        else:
            self.logger.debug("fqdn check against san failed")

        self.logger.debug("Challenge._extensions_validate() ended with: %s", result)
        return result

    def _name_get(self, url: str) -> str:
        """get challenge"""
        self.logger.debug("Challenge.get_name()")

        url_dic = parse_url(self.logger, url)
        challenge_name = url_dic["path"].replace(self.path_dic["chall_path"], "")
        if "/" in challenge_name:
            (challenge_name, _sinin) = challenge_name.split("/", 1)

        self.logger.debug("Challenge.get_name() ended with: %s", challenge_name)
        return challenge_name

    def _email_send(self, to_address: str = None, token1: str = None):
        """send challenge email"""
        self.logger.debug("Challenge._email_send(%s)", to_address)
        message_text = f"""
  This is an automatically generated ACME challenge for email address
  "{to_address}". If you haven't requested an S/MIME
  certificate generation for this email address, be very afraid.
  If you did request it, your email client might be able to process
  this request automatically, or you might have to paste the first
  token part into an external program.
"""
        with EmailHandler(logger=self.logger) as email_handler:
            email_handler.send(
                to_address=to_address, subject=f"ACME: {token1}", message=message_text
            )

    def _new(
        self, authz_name: str, mtype: str, token: str = None, value: str = None
    ) -> Dict[str, str]:
        """new challenge"""
        self.logger.debug("Challenge._new(%s:%s:%s)", authz_name, mtype, value)

        challenge_name = generate_random_string(self.logger, 12)

        data_dic = {
            "name": challenge_name,
            "expires": self.expiry,
            "type": mtype,
            "token": token,
            "authorization": authz_name,
            "status": 2,
        }

        if mtype == "email-reply-00":
            token1 = data_dic["keyauthorization"] = generate_random_string(
                self.logger, 12
            )
            self._email_send(to_address=value, token1=token1)

        elif mtype == "sectigo-email-01":
            data_dic["status"] = 5

        try:
            chid = self.dbstore.challenge_add(value, mtype, data_dic)
        except Exception as err_:
            self.logger.critical(
                "Database error: failed to add new challenge: %s, value: %s, type: %s",
                err_,
                value,
                mtype,
            )
            chid = None

        challenge_dic = {}
        if chid:
            challenge_dic["type"] = mtype
            challenge_dic[
                "url"
            ] = f'{self.server_name}{self.path_dic["chall_path"]}{challenge_name}'
            challenge_dic["token"] = token
            challenge_dic["status"] = "pending"
            if mtype == "email-reply-00":
                challenge_dic["from"] = self.email_address
                challenge_dic["token"] = token
            elif mtype == "tkauth-01":
                challenge_dic["tkauth-type"] = "atc"
            elif mtype == "sectigo-email-01":
                challenge_dic["status"] = "valid"
                challenge_dic.pop("token", None)

        return challenge_dic

    def _parse(
        self,
        code: int,
        payload: Dict[str, str],
        protected: Dict[str, str],
        challenge_name: str,
        challenge_dic: Dict[str, str],
    ) -> Tuple[int, str, str, Dict[str, str]]:
        # pylint: disable=R0913
        """challenge parse"""
        self.logger.debug("Challenge._parse(%s)", challenge_name)

        response_dic = {}
        message = None
        detail = None

        # check tnauthlist payload
        if self.tnauthlist_support:
            (code, message, detail) = self._validate_tnauthlist_payload(
                payload, challenge_dic
            )

        if code == 200:
            # start validation
            if "status" in challenge_dic:
                if challenge_dic["status"] not in ("valid", "processing"):
                    twrv = ThreadWithReturnValue(
                        target=self._validate, args=(challenge_name, payload)
                    )
                    twrv.start()
                    _validation = twrv.join(
                        timeout=self.challenge_validation_timeout
                    )  # lgtm [py/unused-local-variable]
                    # query challenge again (bcs. it could get updated by self._validate)
                    challenge_dic = self._info(challenge_name)
            else:
                # rather unlikely that we run in this situation but you never know
                twrv = ThreadWithReturnValue(
                    target=self._validate, args=(challenge_name, payload)
                )
                twrv.start()
                _validation = twrv.join(timeout=self.challenge_validation_timeout)
                # _validation = self._validate(challenge_name, payload)  # lgtm [py/unused-local-variable]
                # query challenge again (bcs. it could get updated by self._validate)
                challenge_dic = self._info(challenge_name)

            code = 200
            challenge_dic["url"] = protected["url"]
            response_dic["data"] = challenge_dic
            response_dic["header"] = {}
            response_dic["header"][
                "Link"
            ] = f'<{self.server_name}{self.path_dic["authz_path"]}>;rel="up"'

        self.logger.debug("Challenge._parse() ended with: %s", code)
        return (code, message, detail, response_dic)

    def _source_address_check(self, challenge_name: str = None) -> Tuple[bool, bool]:
        """check dns responses against a pre-defined ip"""
        self.logger.debug("Challenge._source_address_check(%s)", challenge_name)

        challenge_check = False
        invalid = False

        if challenge_name:
            try:
                challenge_dic = self.dbstore.challenge_lookup(
                    "name",
                    challenge_name,
                    [
                        "authorization__name",
                        "authorization__type",
                        "authorization__value",
                    ],
                )
            except Exception as err_:
                self.logger.critical(
                    "Database error: failed to lookup challenge during challenge check:'%s': %s",
                    challenge_name,
                    err_,
                )
                challenge_dic = {}

            self.logger.debug(
                "Challenge._source_address_check() challenge_dic: %s", challenge_dic
            )

            if (
                challenge_dic
                and challenge_dic.get("authorization__type", None) == "dns"
                and challenge_dic.get("authorization__value", None)
                and self.source_address
            ):
                response_list, invalid = fqdn_resolve(
                    self.logger,
                    challenge_dic.get("authorization__value"),
                    self.dns_server_list,
                    catch_all=True,
                )
                self.logger.debug(
                    "fqdn_resolve() ended with: %s/%s",
                    response_list,
                    invalid,
                )
                if response_list and self.source_address in response_list:
                    challenge_check = True
                else:
                    challenge_check = False

        self.logger.debug(
            "Challenge._source_address_check() ended with %s/%s",
            challenge_check,
            invalid,
        )
        return challenge_check, invalid

    def _update(self, data_dic: Dict[str, str]):
        """update challenge"""
        self.logger.debug("Challenge._update(%s)", data_dic)

        try:
            self.dbstore.challenge_update(data_dic)
        except Exception as err_:
            self.logger.critical("Database error: failed to update challenge: %s", err_)
        self.logger.debug("Challenge._update() ended")

    def _update_authz(self, challenge_name: str, data_dic: Dict[str, str]):
        """update authorizsation based on challenge_name"""
        self.logger.debug("Challenge._update_authz(%s)", challenge_name)
        try:
            # lookup autorization based on challenge_name
            authz_name = self.dbstore.challenge_lookup(
                "name", challenge_name, ["authorization__name"]
            )["authorization"]
        except Exception as err_:
            self.logger.critical(
                "Database error: failed to lookup authorization for challenge '%s': %s",
                challenge_name,
                err_,
            )
            authz_name = None

        if authz_name:
            data_dic["name"] = authz_name
        try:
            # update authorization
            self.dbstore.authorization_update(data_dic)
        except Exception as err_:
            self.logger.critical(
                "Database error: failed to update authorization for challenge: %s", err_
            )

        self.logger.debug("Challenge._update_authz() ended")

    def _validate(self, challenge_name: str, payload: Dict[str, str]) -> bool:
        """validate challenge"""
        self.logger.debug("Challenge._validate(%s: %s)", challenge_name, payload)

        # change state to processing
        self._update({"name": challenge_name, "status": "processing"})

        challenge_validation_disable_eab_profile = self._cvd_via_eabprofile_check(
            challenge_name
        )

        if (
            self.challenge_validation_disable
            or challenge_validation_disable_eab_profile
        ):
            if self.challenge_validation_disable:
                self.logger.warning(
                    "Challenge validation is globally disabled. Setting challenge status to valid."
                )
            else:
                self.logger.info(
                    "Challenge validation disabled via eab profile. Setting challenge status to valid."
                )

            if self.source_address_check:
                challenge_check, invalid = self._source_address_check(challenge_name)
                self.logger.info(
                    "Challenge._validate(): validate source_ip: %s ended with: %s",
                    self.source_address,
                    challenge_check,
                )
            else:
                challenge_check = True
                invalid = False
        else:
            (challenge_check, invalid) = self._check(challenge_name, payload)

        if invalid:
            self._update(
                {
                    "name": challenge_name,
                    "status": "invalid",
                    "source": self.source_address,
                }
            )
            # authorization update to valid state
            self._update_authz(challenge_name, {"status": "invalid"})
        elif challenge_check:
            self._update(
                {
                    "name": challenge_name,
                    "status": "valid",
                    "source": self.source_address,
                    "validated": uts_now(),
                }
            )
            # authorization update to valid state
            self._update_authz(challenge_name, {"status": "valid"})

        if payload and "keyAuthorization" in payload:
            # update challenge to ready state
            data_dic = {
                "name": challenge_name,
                "keyauthorization": payload["keyAuthorization"],
            }
            self._update(data_dic)

        self.logger.debug("Challenge._validate() ended with:%s", challenge_check)
        return challenge_check

    def _validate_alpn_challenge(
        self,
        challenge_name: str,
        id_type: str,
        id_value: str,
        token: str,
        jwk_thumbprint: str,
    ) -> Tuple[bool, bool]:
        """validate dns challenge"""
        self.logger.debug(
            "Challenge._validate_alpn_challenge(%s:%s:%s)",
            challenge_name,
            id_value,
            token,
        )

        if id_type == "dns":
            # resolve name
            (response, invalid) = fqdn_resolve(
                self.logger, id_value, self.dns_server_list
            )
            self.logger.debug("fqdn_resolve() ended with: %s/%s", response, invalid)
            sni = id_value
        elif id_type == "ip":
            (sni, invalid) = ip_validate(self.logger, id_value)
        else:
            invalid = True
            sni = None

        # we are expecting a certifiate extension which is the sha256 hexdigest of token in a byte structure
        # which is base64 encoded '0420' has been taken from acme_srv.sh sources
        sha256_digest = sha256_hash_hex(self.logger, f"{token}.{jwk_thumbprint}")
        extension_value = b64_encode(
            self.logger, bytearray.fromhex(f"0420{sha256_digest}")
        )
        self.logger.debug("computed value: %s", extension_value)

        if not invalid:
            # check if we need to set a proxy
            if self.proxy_server_list:
                proxy_server = proxy_check(
                    self.logger, id_value, self.proxy_server_list
                )
            else:
                proxy_server = None
            cert = servercert_get(self.logger, id_value, 443, proxy_server, sni)
            if cert:
                result = self._extensions_validate(cert, extension_value, id_value)
            else:
                self.logger.debug("no cert returned...")
                result = False
        else:
            result = False

        self.logger.debug(
            "Challenge._validate_alpn_challenge() ended with: %s/%s", result, invalid
        )
        return (result, invalid)

    def _validate_dns_challenge(
        self,
        challenge_name: str,
        _type: str,
        fqdn: str,
        token: str,
        jwk_thumbprint: str,
    ) -> Tuple[bool, bool]:
        """validate dns challenge"""
        self.logger.debug(
            "Challenge._validate_dns_challenge(%s:%s:%s)", challenge_name, fqdn, token
        )

        # handle wildcard domain
        fqdn = self._wcd_manipulate(fqdn)

        # rewrite fqdn to resolve txt record
        fqdn = f"_acme-challenge.{fqdn}"

        # compute sha256 hash
        _hash = b64_url_encode(
            self.logger, sha256_hash(self.logger, f"{token}.{jwk_thumbprint}")
        )

        # query dns
        txt_list = txt_get(self.logger, fqdn, self.dns_server_list)

        # compare computed hash with result from DNS query
        self.logger.debug("response_got: %s response_expected: %s", txt_list, _hash)
        if _hash in txt_list:
            self.logger.debug("validation successful")
            result = True
        else:
            self.logger.debug("validation not successful")
            result = False

        self.logger.debug("Challenge._validate_dns_challenge() ended with: %s", result)
        return (result, False)

    def _validate_http_challenge(
        self,
        challenge_name: str,
        id_type: str,
        id_value: str,
        token: str,
        jwk_thumbprint: str,
    ) -> Tuple[bool, bool]:
        """validate http challenge"""
        self.logger.debug(
            "Challenge._validate_http_challenge(%s:%s:%s)",
            challenge_name,
            id_value,
            token,
        )

        if id_type == "dns":
            # resolve name
            (response, invalid) = fqdn_resolve(
                self.logger, id_value, self.dns_server_list
            )
            self.logger.debug("fqdn_resolve() ended with: %s/%s", response, invalid)
        elif id_type == "ip":
            invalid = False
            (_sni, invalid) = ip_validate(self.logger, id_value)
        else:
            invalid = True

        if not invalid:
            # check if we need to set a proxy
            if self.proxy_server_list:
                proxy_server = proxy_check(
                    self.logger, id_value, self.proxy_server_list
                )
            else:
                proxy_server = None
            req = url_get(
                self.logger,
                f"http://{id_value}/.well-known/acme-challenge/{token}",
                dns_server_list=self.dns_server_list,
                proxy_server=proxy_server,
                verify=False,
                timeout=self.challenge_validation_timeout,
            )
            if req:
                response_got = req.splitlines()[0]
                response_expected = f"{token}.{jwk_thumbprint}"
                self.logger.debug(
                    "response_got: %s response_expected: %s",
                    response_got,
                    response_expected,
                )
                if response_got == response_expected:
                    self.logger.debug("validation successful")
                    result = True
                else:
                    self.logger.debug("validation not successful")
                    result = False
            else:
                self.logger.debug("validation not successfull.. no request object")
                result = False
        else:
            result = False

        self.logger.debug(
            "Challenge._validate_http_challenge() ended with: %s/%s", result, invalid
        )
        return (result, invalid)

    def _validate_tkauth_challenge(
        self,
        challenge_name: str,
        _type: str,
        tnauthlist: str,
        _token: str,
        _jwk_thumbprint: str,
        payload: Dict[str, str],
    ) -> Tuple[bool, bool]:
        """validate tkauth challenge"""
        self.logger.debug(
            "Challenge._validate_tkauth_challenge(%s:%s:%s)",
            challenge_name,
            tnauthlist,
            payload,
        )

        result = True
        invalid = False
        self.logger.debug(
            "Challenge._validate_tkauth_challenge() ended with: %s/%s", result, invalid
        )
        return (result, invalid)

    def _validate_tnauthlist_payload(
        self, payload: Dict[str, str], challenge_dic: Dict[str, str]
    ) -> Tuple[int, str, str]:
        """check payload in cae tnauthlist option has been set"""
        self.logger.debug("Challenge._validate_tnauthlist_payload(%s)", payload)

        code = 400
        message = None
        detail = None

        if "type" in challenge_dic:
            if challenge_dic["type"] == "tkauth-01":
                self.logger.debug("tkauth identifier found")
                # check if we havegot an atc claim in the challenge request
                if "atc" in payload:
                    # check if we got a SPC token in the challenge request
                    if not bool(payload["atc"]):
                        code = 400
                        message = self.err_msg_dic["malformed"]
                        detail = "SPC token is missing"
                    else:
                        code = 200
                else:
                    code = 400
                    message = self.err_msg_dic["malformed"]
                    detail = "atc claim is missing"
            else:
                code = 200
        else:
            message = self.err_msg_dic["malformed"]
            detail = f"invalid challenge: {challenge_dic}"

        self.logger.debug(
            "Challenge._validate_tnauthlist_payload() ended with:%s", code
        )
        return (code, message, detail)

    def _wcd_manipulate(self, fqdn: str) -> str:
        """wildcard domain handling"""
        self.logger.debug("Challenge._wc_manipulate() for fqdn: %s", fqdn)

        if fqdn.startswith("*."):
            fqdn = fqdn[2:]
        self.logger.debug("Challenge._wc_manipulate() ended with: %s", fqdn)
        return fqdn

    def challengeset_get(
        self,
        authz_name: str,
        _auth_status: str,
        token: str,
        tnauth: bool,
        id_type: str = "dns",
        id_value: str = None,
    ) -> List[str]:
        """get the challengeset for an authorization"""
        self.logger.debug(
            "Challenge.challengeset_get() for auth: %s:%s", authz_name, id_value
        )

        # check database if there are exsting challenges for a particular authorization
        challenge_list = self._challengelist_search("authorization__name", authz_name)

        if challenge_list:
            self.logger.debug("Challenges found.")
            # trigger challenge validation
            # if auth_status == 'pending':
            #    self._existing_challenge_validate(challenge_list)

            challenge_name_list = []
            for challenge in challenge_list:
                if (
                    self.email_identifier_support
                    and self.email_address
                    and challenge["type"] == "email-reply-00"
                ):
                    # add email address to challenge_dic for email-reply-00 challenges
                    self.logger.debug("Adding email address to challenge_dic")
                    challenge["from"] = self.email_address
                challenge_name_list.append(challenge.pop("name"))
        else:
            # new challenges to be created
            self.logger.debug("Challenges not found. Create a new set.")
            challenge_list = self.new_set(authz_name, token, tnauth, id_type, id_value)

        return challenge_list

    def get(self, url: str) -> Dict[str, str]:
        """get challenge details based on get request"""
        challenge_name = self._name_get(url)
        self.logger.debug("Challenge.get(%s)", challenge_name)

        response_dic = {}
        response_dic["code"] = 200
        response_dic["data"] = self._info(challenge_name)
        return response_dic

    def new_set(
        self,
        authz_name: str,
        token: str,
        tnauth: bool = False,
        id_type: str = "dns",
        value: str = None,
    ) -> List[str]:
        """net challenge set"""
        self.logger.debug("Challenge.new_set(%s, %s)", authz_name, value)

        challenge_list = []

        # check if we need to create a email-reply challenge
        email_reply = False
        if self.email_identifier_support:
            if id_type == "email" or (id_type == "dns" and "@" in value):
                email_reply = True
                self.logger.debug(
                    "Challenge.new_set(): create email-reply-00 challenge"
                )

        if tnauth:
            challenge_list.append(
                self._new(authz_name=authz_name, mtype="tkauth-01", token=token)
            )
        elif self.sectigo_sim:
            challenge_list.append(
                self._new(authz_name=authz_name, mtype="sectigo-email-01")
            )
        elif email_reply:
            challenge_list.append(
                self._new(
                    authz_name=authz_name,
                    mtype="email-reply-00",
                    token=token,
                    value=value,
                )
            )
        else:
            challenge_type_list = ["http-01", "dns-01", "tls-alpn-01"]
            # remove dns challnge for ip-addresses
            if id_type == "ip":
                self.logger.debug("Challenge.new_set(): skip dns-01 challenge()")
                challenge_type_list.pop(1)

            for challenge_type in challenge_type_list:
                challenge_json = self._new(
                    authz_name=authz_name,
                    mtype=challenge_type,
                    token=token,
                    value=value,
                )
                if challenge_json:
                    challenge_list.append(challenge_json)
                else:
                    self.logger.error("Empty challenge returned for %s", challenge_type)

        self.logger.debug("Challenge._new_set returned (%s)", challenge_list)
        return challenge_list

    def parse(self, content: str) -> Dict[str, str]:
        """parse challenge"""
        self.logger.debug("Challenge.parse()")

        response_dic = {}
        # check message
        (code, message, detail, protected, payload, _account_name) = self.message.check(
            content
        )

        if code == 200:
            if "url" in protected:
                challenge_name = self._name_get(protected["url"])
                if challenge_name:
                    challenge_dic = self._info(challenge_name)

                    if challenge_dic:
                        (code, message, detail, response_dic) = self._parse(
                            code, payload, protected, challenge_name, challenge_dic
                        )

                    else:
                        code = 400
                        message = self.err_msg_dic["malformed"]
                        detail = f"invalid challenge: {challenge_name}"
                else:
                    code = 400
                    message = self.err_msg_dic["malformed"]
                    detail = "could not get challenge"
            else:
                code = 400
                message = self.err_msg_dic["malformed"]
                detail = "url missing in protected header"

        # prepare/enrich response
        status_dic = {"code": code, "type": message, "detail": detail}
        response_dic = self.message.prepare_response(response_dic, status_dic)
        self.logger.debug("challenge.parse() returns: %s", json.dumps(response_dic))
        return response_dic
