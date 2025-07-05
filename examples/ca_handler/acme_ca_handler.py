# -*- coding: utf-8 -*-
"""generic ca handler for CAs supporting acme protocol"""
from __future__ import print_function

# pylint: disable= e0401, w0105, w0212
import json
import textwrap
import os.path
from typing import Tuple, Dict
import requests
import josepy
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from OpenSSL import crypto
from acme import client, messages, errors
from acme_srv.db_handler import DBstore
from acme_srv.helper import (
    load_config,
    allowed_domainlist_check,
    b64_encode,
    b64_url_recode,
    b64_url_decode,
    client_parameter_validate,
    config_allowed_domainlist_load,
    config_eab_profile_load,
    config_headerinfo_load,
    config_enroll_config_log_load,
    config_profile_load,
    eab_profile_header_info_check,
    enrollment_config_log,
    parse_url,
    cert_pem2der,
    uts_now,
    uts_to_date_utc,
)


class CAhandler(object):
    """EST CA  handler"""

    def __init__(self, _debug: bool = False, logger: object = None):
        self.logger = logger
        self.acme_url = None
        self.acme_url_dic = {}
        self.acme_keyfile = None
        self.key_size = 2048
        self.account = None
        self.email = None
        self.path_dic = {"directory_path": "/directory", "acct_path": "/acme/acct/"}
        self.dbstore = DBstore(None, self.logger)
        self.allowed_domainlist = []
        self.eab_kid = None
        self.eab_hmac_key = None
        self.header_info_field = False
        self.eab_handler = None
        self.eab_profiling = False
        self.acme_keypath = None
        self.ssl_verify = True
        self.enrollment_config_log = False
        self.enrollment_config_log_skip_list = []
        self.profiles = {}
        self.profile = None

    def __enter__(self):
        """Makes CAhandler a Context Manager"""
        if not self.acme_url:
            self._config_load()
        return self

    def __exit__(self, *args):
        """close the connection at the end of the context"""

    def _config_account_load(self, config_dic: Dict[str, str]):
        self.logger.debug("CAhandler._config_account_load()")

        self.acme_keyfile = config_dic.get("CAhandler", "acme_keyfile", fallback=None)
        self.acme_url = config_dic.get("CAhandler", "acme_url", fallback=None)
        self.acme_url_dic = parse_url(self.logger, self.acme_url)

        for ele in ("acme_keyfile", "acme_url"):
            if not getattr(self, ele):
                self.logger.error(
                    'acme_ca_handler configuration incomplete: "%s" parameter is missing in config file',
                    ele,
                )

        self.path_dic["acct_path"] = config_dic["CAhandler"].get(
            "account_path", "/acme/acct/"
        )
        self.key_size = config_dic.get(
            "CAhandler", "acme_account_keysize", fallback=2048
        )
        self.account = config_dic.get("CAhandler", "acme_account", fallback=None)
        self.email = config_dic.get("CAhandler", "acme_account_email", fallback=None)

        if "ssl_verify" in config_dic["CAhandler"]:
            try:
                self.ssl_verify = config_dic.getboolean(
                    "CAhandler", "ssl_verify", fallback=False
                )
            except Exception as err:
                self.logger.warning("Failed to parse ssl_verify parameter: %s", err)
        self.logger.debug("CAhandler._config_account_load() ended")

    def _config_parameters_load(self, config_dic: Dict[str, str]):
        """ " load eab config"""
        self.logger.debug("CAhandler._config_eab_load()")

        self.path_dic["directory_path"] = config_dic.get(
            "CAhandler", "directory_path", fallback="/directory"
        )
        self.eab_kid = config_dic.get("CAhandler", "eab_kid", fallback=None)
        self.eab_hmac_key = config_dic.get("CAhandler", "eab_hmac_key", fallback=None)
        self.acme_keypath = config_dic.get("CAhandler", "acme_keypath", fallback=None)
        self.profile = config_dic.get("CAhandler", "profile", fallback=None)

        self.logger.debug("CAhandler._config_eab_load() ended")

    def _config_load(self):
        """ " load config from file"""
        self.logger.debug("CAhandler._config_load()")
        config_dic = load_config()
        if "CAhandler" in config_dic:

            # load account configuration and paramters
            self._config_account_load(config_dic)
            self._config_parameters_load(config_dic)

            self.logger.debug("CAhandler._config_load() ended")
        else:
            self.logger.error(
                'Configuration incomplete: "CAhandler" section is missing in config file'
            )

        # load allowed domainlist
        self.allowed_domainlist = config_allowed_domainlist_load(
            self.logger, config_dic
        )
        # load profiling
        self.eab_profiling, self.eab_handler = config_eab_profile_load(
            self.logger, config_dic
        )
        # load profiles
        self.profiles = config_profile_load(self.logger, config_dic)
        # load header info
        self.header_info_field = config_headerinfo_load(self.logger, config_dic)
        # load enrollment config log
        (
            self.enrollment_config_log,
            self.enrollment_config_log_skip_list,
        ) = config_enroll_config_log_load(self.logger, config_dic)

    def _challenge_filter(
        self, authzr: messages.AuthorizationResource, chall_type: str = "http-01"
    ) -> messages.ChallengeBody:
        """filter authorization for challenge"""
        self.logger.debug("CAhandler._challenge_filter(%s)", chall_type)
        result = None
        for challenge in authzr.body.challenges:
            if challenge.chall.to_partial_json()["type"] == chall_type:
                result = challenge
                break
        if not result:
            self.logger.error(
                "Could not find challenge of type %s",
                chall_type,
            )

        return result

    def _challenge_store(self, challenge_name: str, challenge_content: str):
        """store challenge into database"""
        self.logger.debug("CAhandler._challenge_store(%s)", challenge_name)

        if challenge_name and challenge_content:
            data_dic = {"name": challenge_name, "value1": challenge_content}
            # store challenge into db
            self.dbstore.cahandler_add(data_dic)

    def _challenge_info(
        self, authzr: messages.AuthorizationResource, user_key: josepy.jwk.JWKRSA
    ):
        """filter challenges and get challenge details"""
        self.logger.debug("CAhandler._challenge_info()")

        chall_name = None
        chall_content = None

        if authzr and user_key:
            challenge = self._challenge_filter(authzr)
            if challenge:
                chall_content = challenge.chall.validation(user_key)
                try:
                    (chall_name, _token) = chall_content.split(".", 2)
                except Exception:
                    self.logger.error(
                        "Challenge split failed: %s",
                        chall_content,
                    )

            else:
                challenge = self._challenge_filter(
                    authzr, chall_type="sectigo-email-01"
                )
                chall_content = challenge.to_partial_json()
        else:
            if authzr:
                self.logger.error("acme user is missing")
            else:
                self.logger.error("acme authorization is missing")
            challenge = None

        self.logger.debug("CAhandler._challenge_info() ended with %s", chall_name)
        return (chall_name, chall_content, challenge)

    def _key_generate(self) -> josepy.jwk.JWKRSA:
        """generate key"""
        self.logger.debug("CAhandler._key_generate(%s)", self.key_size)
        user_key = josepy.JWKRSA(
            key=rsa.generate_private_key(
                public_exponent=65537, key_size=self.key_size, backend=default_backend()
            )
        )
        self.logger.debug("CAhandler._key_generate() ended.")
        return user_key

    def _user_key_load(self) -> josepy.jwk.JWKRSA:
        """enroll certificate"""
        self.logger.debug("CAhandler._user_key_load(%s)", self.acme_keyfile)

        if os.path.exists(self.acme_keyfile):
            self.logger.debug("CAhandler.enroll() opening user_key")
            with open(self.acme_keyfile, "r", encoding="utf8") as keyf:

                user_key_dic = json.loads(keyf.read())
                # check if account_name is stored in keyfile
                if "account" in user_key_dic:
                    self.account = user_key_dic["account"]
                    self.logger.info("Account %s found in keyfile", self.account)
                    del user_key_dic["account"]
                user_key = josepy.JWKRSA.fields_from_json(user_key_dic)
        else:
            self.logger.debug("CAhandler.enroll() generate and register key")
            user_key = self._key_generate()
            # dump keyfile to file
            try:
                with open(self.acme_keyfile, "w", encoding="utf8") as keyf:
                    keyf.write(json.dumps(user_key.to_json()))
            except Exception as err:
                self.logger.error("Error during key dumping: %s", err)

        self.logger.debug("CAhandler._user_key_load() ended with: %s", bool(user_key))
        return user_key

    def _order_authorization(
        self,
        acmeclient: client.ClientV2,
        order: messages.OrderResource,
        user_key: josepy.jwk.JWKRSA,
    ) -> bool:
        """validate challgenges"""
        self.logger.debug("CAhandler._order_authorization()")

        authz_valid = False

        # query challenges
        for authzr in order.authorizations:
            (challenge_name, challenge_content, challenge) = self._challenge_info(
                authzr, user_key
            )
            if challenge_name and challenge_content:
                self.logger.debug(
                    "CAhandler._order_authorization(): http-01 challenge detected"
                )
                # store challenge in database to allow challenge validation
                self._challenge_store(challenge_name, challenge_content)
                _auth_response = acmeclient.answer_challenge(
                    challenge, challenge.chall.response(user_key)
                )  # lgtm [py/unused-local-variable]
                authz_valid = True
            else:
                if (
                    isinstance(challenge_content, dict)
                    and challenge_content.get("type", None) == "sectigo-email-01"
                    and challenge_content.get("status", None) == "valid"
                ):
                    self.logger.debug(
                        "CAhandler._order_authorization(): sectigo-email-01 challenge detected"
                    )
                    authz_valid = True

        self.logger.debug(
            "CAhandler._order_authorization() ended with: %s", authz_valid
        )
        return authz_valid

    def _order_new(
        self, acmeclient: client.ClientV2, csr_pem: str
    ) -> messages.OrderResource:
        """create new order"""
        self.logger.debug("CAhandler._order_new()")

        order = None
        try:
            if self.profile:
                # profile is set
                self.logger.debug(
                    "CAhandler._order_new() adding profile: %s", self.profile
                )
                order = acmeclient.new_order(csr_pem=csr_pem, profile=self.profile)
            else:
                # no profile set
                self.logger.debug("CAhandler._order_new() no profile set")
                order = acmeclient.new_order(csr_pem=csr_pem)
        except Exception as err:
            self.logger.warning(
                "Failed to create order: %s. Try without profile information.",
                err,
            )
            order = acmeclient.new_order(csr_pem=csr_pem)
        self.logger.debug("CAhandler._order_new() ended with: %s", bool(order))
        return order

    def _order_issue(
        self, acmeclient: client.ClientV2, user_key: josepy.jwk.JWKRSA, csr_pem: str
    ) -> Tuple[str, str, str]:
        """isuse order"""
        self.logger.debug("CAhandler._order_issue() csr: " + str(csr_pem))

        # create new order
        order = self._order_new(acmeclient, csr_pem)

        error = None
        cert_bundle = None
        cert_raw = None

        # valid orders
        order_valid = self._order_authorization(acmeclient, order, user_key)

        if order_valid:
            self.logger.debug("CAhandler.enroll() polling for certificate")
            order = acmeclient.poll_and_finalize(order)

            if order.fullchain_pem:
                self.logger.debug("CAhandler.enroll() successful")
                cert_bundle = str(order.fullchain_pem)
                # Split the chain into individual certificates
                certs = cert_bundle.strip().split("-----END CERTIFICATE-----")
                # The first certificate is the end-entity certificate
                cert_raw = b64_encode(
                    self.logger, cert_pem2der(certs[0] + "-----END CERTIFICATE-----")
                )
            else:
                self.logger.error("Error getting certificate: %s", order.error)
                error = f"Error getting certificate: {order.error}"

        self.logger.debug("CAhandler._order_issue() ended")
        return (error, cert_bundle, cert_raw)

    def _account_lookup(
        self, acmeclient: client.ClientV2, reg: str, directory: messages.Directory
    ):
        """lookup account"""
        self.logger.debug("CAhandler._account_lookup()")

        response = acmeclient._post(directory["newAccount"], reg)
        regr = acmeclient._regr_from_response(response)
        regr = acmeclient.query_registration(regr)
        if regr:
            self.logger.info("Found existing account: %s", regr.uri)
            self.account = regr.uri
            if self.acme_url:
                # remove url from string
                self.account = self.account.replace(self.acme_url, "")
            if "acct_path" in self.path_dic and self.path_dic["acct_path"]:
                # remove acc_path
                self.account = self.account.replace(self.path_dic["acct_path"], "")

    def _account_create(
        self,
        acmeclient: client.ClientV2,
        user_key: josepy.jwk.JWKRSA,
        directory: messages.Directory,
    ) -> messages.RegistrationResource:
        """register account"""
        self.logger.debug(
            "CAhandler._account_create(): register new account with email: %s",
            self.email,
        )

        regr = None
        if self.email:
            self.logger.debug(
                "CAhandler._account_create(): register new account with email: %s",
                self.email,
            )
            if (
                self.acme_url
                and "host" in self.acme_url_dic
                and self.acme_url_dic["host"].endswith("zerossl.com")
            ):  # lgtm [py/incomplete-url-substring-sanitization]
                # get zerossl eab credentials
                self._zerossl_eab_get()
            if self.eab_kid and self.eab_hmac_key:
                # we have to do some freaky eab to keep ZeroSSL happy
                eab = messages.ExternalAccountBinding.from_data(
                    account_public_key=user_key,
                    kid=self.eab_kid,
                    hmac_key=self.eab_hmac_key,
                    directory=directory,
                )
                reg = messages.NewRegistration.from_data(
                    key=user_key,
                    email=self.email,
                    terms_of_service_agreed=True,
                    external_account_binding=eab,
                )
            else:
                # register with email
                reg = messages.NewRegistration.from_data(
                    key=user_key, email=self.email, terms_of_service_agreed=True
                )
            try:
                regr = acmeclient.new_account(reg)
                self.logger.debug(
                    "CAhandler._account_create(): new account reqistered."
                )
            except errors.ConflictError:
                self.logger.error(
                    "Account registration failed: ConflictError"
                )  # pragma: no cover
            except Exception as err:
                self.logger.error("Account registration failed: %s", err)
        else:
            self.logger.error("Registration aborted. Email address is missing")

        self.logger.debug("CAhandler._account_create() ended with: %s", bool(regr))
        return regr

    def _accountname_get(
        self, url: str, acme_url: str, path_dic: Dict[str, str]
    ) -> str:
        """get accountname from url"""
        self.logger.debug("CAhandler._accountname_get()")

        account = None

        acct_path = path_dic.get("acct_path", None)
        if acct_path == "/":
            # remove url from string
            account = url.replace(acme_url, "").lstrip("/")
        elif acct_path:
            # remove url from string
            account = url.replace(acme_url, "").replace(path_dic["acct_path"], "")
        else:
            account = url.replace(acme_url, "")

        self.logger.debug("CAhandler._accountname_get() ended with: %s", account)
        return account

    def _account_register(
        self,
        acmeclient: client.ClientV2,
        user_key: josepy.jwk.JWKRSA,
        directory: messages.Directory,
    ) -> messages.RegistrationResource:
        """register account / check registration"""
        self.logger.debug("CAhandler._account_register(%s)", self.email)

        try:
            # we assume that the account exist and need to query the account id
            reg = messages.NewRegistration.from_data(
                key=user_key,
                email=self.email,
                terms_of_service_agreed=True,
                only_return_existing=True,
            )
            response = acmeclient._post(directory["newAccount"], reg)
            regr = acmeclient._regr_from_response(response)
            regr = acmeclient.query_registration(regr)
            if hasattr(regr, "uri"):
                self.logger.debug(
                    "CAhandler.__account_register(): found existing account: %s",
                    regr.uri,
                )
        except Exception:
            regr = self._account_create(acmeclient, user_key, directory)

        if regr:
            # extract the account-name from registration ressource
            if self.acme_url and "acct_path" in self.path_dic:
                if hasattr(regr, "uri"):
                    self.account = self._accountname_get(
                        regr.uri, self.acme_url, self.path_dic
                    )

            if self.account:
                self.logger.info(
                    "acme-account id is %s. Please add an corresponding acme_account parameter to your acme_srv.cfg to avoid unnecessary lookups",
                    self.account,
                )
                self._account_to_keyfile()

        else:
            self.logger.error("Registration failed")
        return regr

    def _account_to_keyfile(self):
        """add account to keyfile"""
        self.logger.debug("CAhandler._account_to_keyfile()")

        if self.acme_keyfile and self.account:
            try:
                with open(self.acme_keyfile, "r", encoding="utf8") as keyf:
                    key_dic = json.loads(keyf.read())
                    key_dic["account"] = self.account

                with open(self.acme_keyfile, "w", encoding="utf8") as keyf:
                    keyf.write(json.dumps(key_dic))
            except Exception as err:
                self.logger.error("Could not map account to keyfile: %s", err)

    def _zerossl_eab_get(self):
        """get eab credentials from zerossl"""
        self.logger.debug("CAhandler._zerossl_eab_get()")

        zero_eab_email = "http://api.zerossl.com/acme/eab-credentials-email"
        data = {"email": self.email}

        response = requests.post(zero_eab_email, data=data, timeout=20)
        if (
            "success" in response.json()
            and response.json()["success"]
            and "eab_kid" in response.json()
            and "eab_hmac_key" in response.json()
        ):
            self.eab_kid = response.json()["eab_kid"]
            self.eab_hmac_key = response.json()["eab_hmac_key"]
            self.logger.debug("CAhandler._zerossl_eab_get() ended successfully")
        else:
            self.logger.error(
                "Could not get eab credentials from ZeroSSL: %s", response.text
            )

    def _eab_profile_list_set(self, csr: str, key: str, value: str) -> str:
        self.logger.debug(
            "CAhandler._acme_keyfile_set(): list: key: %s, value: %s", key, value
        )

        result = None
        new_value, error = client_parameter_validate(self.logger, csr, self, key, value)
        if new_value:
            self.logger.debug(
                "CAhandler._eab_profile_list_set(): setting attribute: %s to %s",
                key,
                new_value,
            )
            setattr(self, key, new_value)
            if key == "acme_url":
                if not self.acme_keypath:
                    result = "acme_keypath is missing in config"
                    self.logger.error("acme_keypath is missing in config")
                else:
                    self.acme_url_dic = parse_url(self.logger, new_value)
                    self.acme_keyfile = f"{self.acme_keypath.rstrip('/')}/{self.acme_url_dic['host'].replace(':', '.')}.json"
        else:
            result = error

        return result

    def eab_profile_list_check(
        self, eab_handler: str, csr: str, key: str, value: str
    ) -> str:
        """check eab profile list"""
        self.logger.debug(
            "CAhandler._eab_profile_list_check(): list: key: %s, value: %s", key, value
        )

        result = None
        if hasattr(self, key) and key != "allowed_domainlist":
            if key == "acme_keyfile":
                self.logger.error("acme_keyfile is not allowed in profile")
            else:
                result = self._eab_profile_list_set(csr, key, value)

        elif key == "allowed_domainlist":
            # check if csr contains allowed domains
            if "allowed_domains_check" in dir(eab_handler):
                # execute a function from eab_handler
                self.logger.info("Execute allowed_domains_check() from eab handler")
                error = eab_handler.allowed_domains_check(csr, value)
            else:
                # execute default adl function from helper
                self.logger.debug(
                    "Helper.eab_profile_list_check(): execute default allowed_domainlist_check()"
                )
                error = allowed_domainlist_check(self.logger, csr, value)
            if error:
                result = error
        else:
            self.logger.error(
                "handler specific EAB profile list checking: ignore list attribute: key: %s value: %s",
                key,
                value,
            )

        self.logger.debug("CAhandler._eab_profile_list_check() ended with: %s", result)
        return result

    def _enroll(
        self,
        acmeclient: client.ClientV2,
        user_key: josepy.jwk.JWKRSA,
        csr_pem: str,
        regr: messages.RegistrationResource,
    ) -> Tuple[str, str, str]:
        """enroll certificate"""
        self.logger.debug("CAhandler._enroll()")
        error = None
        cert_bundle = None
        cert_raw = None

        if regr.body.status == "valid":
            (error, cert_bundle, cert_raw) = self._order_issue(
                acmeclient, user_key, csr_pem
            )
        elif not regr.body.status and regr.uri:
            # this is an exisitng but not configured account. Throw error but continue enrolling
            self.logger.info("Existing but not configured ACME account: %s", regr.uri)
            (error, cert_bundle, cert_raw) = self._order_issue(
                acmeclient, user_key, csr_pem
            )
        else:
            self.logger.error(
                "Enrollment failed: Bad ACME account: %s", regr.body.error
            )
            error = f"Bad ACME account: {regr.body.error}"

        self.logger.debug("CAhandler._enroll() ended with %s", bool(cert_raw))
        return error, cert_bundle, cert_raw

    def _registration_lookup(
        self,
        acmeclient: client.ClientV2,
        reg: messages.Registration,
        directory: messages.Directory,
        user_key,
    ) -> messages.RegistrationResource:
        """lookup registration"""
        self.logger.debug("CAhandler._registration_lookup()")

        if self.account:
            regr = messages.RegistrationResource(
                uri=f"{self.acme_url}{self.path_dic['acct_path']}{self.account}",
                body=reg,
            )
            self.logger.debug(
                "CAhandler._registration_lookup(): checking remote registration status"
            )
            regr = acmeclient.query_registration(regr)
            if hasattr(regr, "uri"):
                self.logger.info(
                    "Found existing account: %s",
                    regr.uri,
                )
            else:
                self.logger.error(
                    "Account lookup failed. Account %s not found. Trying to register new account.",
                    self.account,
                )
                regr = self._account_register(acmeclient, user_key, directory)
                if hasattr(regr, "uri"):
                    self.logger.info("New account: %s", regr.uri)
        else:
            # new account or existing account with missing account id
            regr = self._account_register(acmeclient, user_key, directory)
            if hasattr(regr, "uri"):
                self.logger.info("New account: %s", regr.uri)

        self.logger.debug("CAhandler._registration_lookup() ended with: %s", bool(regr))
        return regr

    def _revoke_or_fallback(self, acmeclient=None, cert: str = None):
        """revoke certificate or fallback to pre-4.0 method"""
        self.logger.debug("CAhandler._revoke_or_fallback()")

        try:
            cert_obj = x509.load_der_x509_certificate(
                b64_url_decode(self.logger, cert), backend=default_backend()
            )
            acmeclient.revoke(cert_obj, 1)
        except Exception as err:
            self.logger.error(
                "Revocation error: %s. Fallback to pre-4.0 method",
                err,
            )
            cert_obj = josepy.ComparableX509(
                crypto.load_certificate(
                    crypto.FILETYPE_ASN1,
                    b64_url_decode(self.logger, cert),
                )
            )
            acmeclient.revoke(cert_obj, 1)

    def enroll(self, csr: str) -> Tuple[str, str, str, str]:
        """enroll certificate"""
        # pylint: disable=R0915
        self.logger.debug("CAhandler.enroll()")

        csr_pem = f"-----BEGIN CERTIFICATE REQUEST-----\n{textwrap.fill(str(b64_url_recode(self.logger, csr)), 64)}\n-----END CERTIFICATE REQUEST-----\n".encode(
            "utf-8"
        )

        cert_bundle = None
        cert_raw = None
        poll_indentifier = None
        user_key = None

        error = allowed_domainlist_check(self.logger, csr, self.allowed_domainlist)

        # check for eab profiling and header_info
        if not error:
            error = eab_profile_header_info_check(self.logger, self, csr, "profile")

        if self.enrollment_config_log:
            self.enrollment_config_log_skip_list.extend(["dbstore", "eab_mac_key"])
            enrollment_config_log(
                self.logger, self, self.enrollment_config_log_skip_list
            )

        if not error:
            try:
                user_key = self._user_key_load()
                net = client.ClientNetwork(user_key, verify_ssl=self.ssl_verify)

                directory = messages.Directory.from_json(
                    net.get(f'{self.acme_url}{self.path_dic["directory_path"]}').json()
                )
                acmeclient = client.ClientV2(directory, net=net)
                reg = messages.Registration.from_data(
                    key=user_key, terms_of_service_agreed=True
                )

                # lookup account / create new account
                regr = self._registration_lookup(acmeclient, reg, directory, user_key)
                if regr:
                    # enroll certificate
                    error, cert_bundle, cert_raw = self._enroll(
                        acmeclient, user_key, csr_pem, regr
                    )
                else:
                    self.logger.error("Account registration failed")
                    error = "Account registration failed"
            except Exception as err:
                self.logger.error("Enrollment error: %s", err)
                error = str(err)
            finally:
                del user_key
        else:
            self.logger.error("Enrollment error: CSR rejected. %s", error)

        self.logger.debug("Certificate.enroll() ended")
        return (error, cert_bundle, cert_raw, poll_indentifier)

    def poll(
        self, _cert_name: str, poll_identifier: str, _csr: str
    ) -> Tuple[str, str, str, str, bool]:
        """poll status of pending CSR and download certificates"""
        self.logger.debug("CAhandler.poll()")

        error = "Not implemented"
        cert_bundle = None
        cert_raw = None
        rejected = False

        self.logger.debug("CAhandler.poll() ended")
        return (error, cert_bundle, cert_raw, poll_identifier, rejected)

    def revoke(
        self,
        _cert: str,
        _rev_reason: str = "unspecified",
        _rev_date: str = uts_to_date_utc(uts_now()),
    ) -> Tuple[int, str, str]:
        """revoke certificate"""
        self.logger.debug("CAhandler.revoke()")

        user_key = None
        code = 500
        message = "urn:ietf:params:acme:error:serverInternal"
        detail = None

        try:
            if os.path.exists(self.acme_keyfile):
                user_key = self._user_key_load()

            if user_key:
                net = client.ClientNetwork(user_key)

                directory = messages.Directory.from_json(
                    net.get(f"{self.acme_url}{self.path_dic['directory_path']}").json()
                )
                acmeclient = client.ClientV2(directory, net=net)

                reg = messages.NewRegistration.from_data(
                    key=user_key,
                    email=self.email,
                    terms_of_service_agreed=True,
                    only_return_existing=True,
                )

                if not self.account:
                    self._account_lookup(acmeclient, reg, directory)

                if self.account:
                    regr = messages.RegistrationResource(
                        uri=f"{self.acme_url}{self.path_dic['acct_path']}{self.account}",
                        body=reg,
                    )
                    self.logger.debug(
                        "CAhandler.revoke() checking remote registration status"
                    )
                    regr = acmeclient.query_registration(regr)

                    if regr.body.status == "valid":
                        self.logger.debug("CAhandler.revoke() issuing revocation order")
                        # revoke certificate
                        self._revoke_or_fallback(acmeclient, _cert)
                        self.logger.debug("CAhandler.revoke() successful")
                        code = 200
                        message = None
                    else:
                        self.logger.error(
                            "Enrollment error: Bad ACME account: %s", regr.body.error
                        )
                        detail = f"Bad ACME account: {regr.body.error}"

                else:
                    self.logger.error(
                        "Error during revocation operation. Could not find account key and lookup at acme-endpoint failed."
                    )
                    detail = "account lookup failed"
            else:
                self.logger.error(
                    "Error during revocation: Could not load user_key %s",
                    self.acme_keyfile,
                )
                detail = "Internal Error"

        except Exception as err:
            self.logger.error("Revocation error: %s", err)
            detail = str(err)

        finally:
            del user_key

        self.logger.debug("Certificate.revoke() ended")
        return (code, message, detail)

    def trigger(self, _payload: str) -> Tuple[int, str, str]:
        """process trigger message and return certificate"""
        self.logger.debug("CAhandler.trigger()")

        error = "Not implemented"
        cert_bundle = None
        cert_raw = None

        self.logger.debug("CAhandler.trigger() ended with error: %s", error)
        return (error, cert_bundle, cert_raw)
