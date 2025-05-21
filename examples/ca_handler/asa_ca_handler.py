# -*- coding: utf-8 -*-
"""Insta Active Security API  handler"""
from __future__ import print_function
from typing import Tuple, Dict
import os
import requests
from requests.auth import HTTPBasicAuth

# pylint: disable=e0401
from acme_srv.helper import (
    load_config,
    encode_url,
    csr_pubkey_get,
    csr_cn_get,
    csr_san_get,
    uts_now,
    uts_to_date_utc,
    b64_decode,
    cert_der2pem,
    convert_byte_to_string,
    cert_ski_get,
    config_eab_profile_load,
    config_headerinfo_load,
    eab_profile_header_info_check,
    config_enroll_config_log_load,
    enrollment_config_log,
    config_allowed_domainlist_load,
    allowed_domainlist_check,
)


class CAhandler(object):
    """EST CA  handler"""

    def __init__(self, _debug: bool = None, logger: object = None):
        self.logger = logger
        self.api_host = None
        self.api_user = None
        self.api_password = None
        self.api_key = None
        self.ca_bundle = None
        self.proxy = None
        self.request_timeout = 10
        self.ca_name = None
        self.auth = None
        self.profile_name = None
        self.cert_validity_days = 30
        self.header_info_field = False
        self.eab_handler = None
        self.eab_profiling = False
        self.enrollment_config_log = False
        self.enrollment_config_log_skip_list = []
        self.allowed_domainlist = []
        self.profiles = {}

    def __enter__(self):
        """Makes CAhandler a Context Manager"""
        if not self.api_host:
            self._config_load()
        return self

    def __exit__(self, *args):
        """cose the connection at the end of the context"""

    def _api_get(self, url: str) -> Tuple[int, Dict[str, str]]:
        """post data to API"""
        self.logger.debug("CAhandler._api_get()")
        headers = {"x-api-key": self.api_key}

        try:
            api_response = requests.get(
                url=url,
                headers=headers,
                auth=self.auth,
                verify=self.ca_bundle,
                proxies=self.proxy,
                timeout=self.request_timeout,
            )
            code = api_response.status_code
            try:
                content = api_response.json()
            except Exception as err_:
                self.logger.error(
                    "CAhandler._api_get() returned error during json parsing: %s", err_
                )
                content = str(err_)
        except Exception as err_:
            self.logger.error("CAhandler._api_get() returned error: %s", err_)
            code = 500
            content = str(err_)

        return code, content

    def _api_post(self, url: str, data: Dict[str, str]) -> Tuple[int, Dict[str, str]]:
        """post data to API"""
        self.logger.debug("CAhandler._api_post()")
        headers = {"x-api-key": self.api_key}

        try:
            api_response = requests.post(
                url=url,
                headers=headers,
                json=data,
                auth=self.auth,
                verify=self.ca_bundle,
                proxies=self.proxy,
                timeout=self.request_timeout,
            )
            code = api_response.status_code
            if api_response.text:
                try:
                    content = api_response.json()
                except Exception as err_:
                    self.logger.error(
                        "CAhandler._api_post() returned error during json parsing: %s",
                        err_,
                    )
                    content = str(err_)
            else:
                content = None
        except Exception as err_:
            self.logger.error("CAhandler._api_post() returned error: %s", err_)
            code = 500
            content = str(err_)

        return code, content

    def _auth_set(self):
        """set basic authentication header"""
        self.logger.debug("CAhandler._auth_set()")
        if self.api_user and self.api_password:
            self.auth = HTTPBasicAuth(self.api_user, self.api_password)
        else:
            self.logger.error(
                'CAhandler._auth_set(): auth information incomplete. Either "api_user" or "api_password" parameter is missing in config file'
            )
        self.logger.debug("CAhandler._auth_set() ended")

    def _config_host_load(self, config_dic: Dict[str, str]):
        """load hostname"""
        self.logger.debug("_config_host_load()")

        api_host_variable = config_dic.get("api_host_variable")
        if api_host_variable:
            self.api_host = os.environ.get(api_host_variable)
            if not self.api_host:
                self.logger.error(
                    f"CAhandler._config_host_load() could not load host_variable: {api_host_variable}"
                )

        api_host = config_dic.get("api_host")
        if api_host:
            if self.api_host:
                self.logger.info("CAhandler._config_host_load() overwrite api_host")
            self.api_host = api_host

        self.logger.debug("_config_host_load() ended")

    def _certificates_list(self) -> Dict[str, str]:
        """list profiles"""
        self.logger.debug("CAhandler._certificates_list()")

        url = f"{self.api_host}/list_certificates?issuerName={encode_url(self.logger, self.ca_name)}"
        _code, api_response = self._api_get(url)

        self.logger.debug("CAhandler._certificates_list() ended")
        return api_response

    def _config_key_load(self, config_dic: Dict[str, str]):
        """load keyname"""
        self.logger.debug("_config_key_load()")

        api_key_variable = config_dic.get("api_key_variable")
        if api_key_variable:
            self.api_key = os.environ.get(api_key_variable)
            if not self.api_key:
                self.logger.error(
                    f"CAhandler._config_key_load() could not load key_variable: {api_key_variable}"
                )

        api_key = config_dic.get("api_key")
        if api_key:
            if self.api_key:
                self.logger.info("CAhandler._config_key_load() overwrite api_key")
            self.api_key = api_key

        self.logger.debug("_config_key_load() ended")

    def _config_password_load(self, config_dic: Dict[str, str]):
        """load passwordname"""
        self.logger.debug("_config_password_load()")

        api_password_variable = config_dic.get("api_password_variable")
        if api_password_variable:
            self.api_password = os.environ.get(api_password_variable)
            if not self.api_password:
                self.logger.error(
                    f"CAhandler._config_password_load() could not load password_variable: {api_password_variable}"
                )

        api_password = config_dic.get("api_password")
        if api_password:
            if self.api_password:
                self.logger.info(
                    "CAhandler._config_password_load() overwrite api_password"
                )
            self.api_password = api_password

        self.logger.debug("_config_password_load() ended")

    def _config_user_load(self, config_dic: Dict[str, str]):
        """load username"""
        self.logger.debug("_config_user_load()")

        api_user_variable = config_dic.get("api_user_variable")
        if api_user_variable:
            self.api_user = os.environ.get(api_user_variable)
            if not self.api_user:
                self.logger.error(
                    f"CAhandler._config_user_load() could not load user_variable: {api_user_variable}"
                )

        api_user = config_dic.get("api_user")
        if api_user:
            if self.api_user:
                self.logger.info("CAhandler._config_user_load() overwrite api_user")
            self.api_user = api_user

        self.logger.debug("_config_user_load() ended")

    def _config_load(self):
        """ " load config from file"""
        self.logger.debug("CAhandler._config_load()")

        config_dic = load_config(self.logger, "CAhandler")

        if "CAhandler" in config_dic:
            self._config_host_load(config_dic["CAhandler"])
            self._config_user_load(config_dic["CAhandler"])
            self._config_password_load(config_dic["CAhandler"])
            self._config_key_load(config_dic["CAhandler"])
            self.ca_name = config_dic["CAhandler"].get("ca_name")
            self.profile_name = config_dic["CAhandler"].get("profile_name")

            if (
                "ca_bundle" in config_dic["CAhandler"]
                and config_dic["CAhandler"]["ca_bundle"] == "False"
            ):
                self.ca_bundle = False
            else:
                self.ca_bundle = config_dic["CAhandler"].get("ca_bundle")

            try:
                self.request_timeout = int(
                    config_dic["CAhandler"].get("request_timeout", 10)
                )
            except Exception:
                self.logger.error(
                    "CAhandler._config_load(): request_timeout not an integer"
                )

            try:
                self.cert_validity_days = int(
                    config_dic["CAhandler"].get("cert_validity_days", 30)
                )
            except Exception:
                self.logger.error(
                    "CAhandler._config_load(): cert_validity_days not an integer"
                )

        for ele in [
            "api_host",
            "api_user",
            "api_password",
            "api_key",
            "ca_name",
            "profile_name",
        ]:
            if not getattr(self, ele):
                self.logger.error("CAhandler._config_load(): %s not set", ele)

        # load profiling
        self.eab_profiling, self.eab_handler = config_eab_profile_load(
            self.logger, config_dic
        )

        self._auth_set()

        # load header info
        self.header_info_field = config_headerinfo_load(self.logger, config_dic)
        # load enrollment config log
        (
            self.enrollment_config_log,
            self.enrollment_config_log_skip_list,
        ) = config_enroll_config_log_load(self.logger, config_dic)
        # load allowed domainlist
        self.allowed_domainlist = config_allowed_domainlist_load(
            self.logger, config_dic
        )
        self.logger.debug("CAhandler._config_load() ended")

    def _csr_cn_get(self, csr: str) -> str:
        """get CN from csr"""
        self.logger.debug("CAhandler._csr_cn_get()")

        cn = csr_cn_get(self.logger, csr)

        if not cn:
            self.logger.info("CAhandler._csr_cn_get(): CN not found in CSR")
            san_list = csr_san_get(self.logger, csr)
            if san_list:
                (_type, san_value) = san_list[0].split(":")
                cn = san_value
                self.logger.info(
                    "CAhandler._csr_cn_get(): CN not found in CSR. Using first SAN entry as CN: %s",
                    san_value,
                )
            else:
                self.logger.error(
                    "CAhandler._csr_cn_get(): CN not found in CSR. No SAN entries found"
                )

        self.logger.debug("CAhandler._csr_cn_get() ended with: %s", cn)
        return cn

    def _issuer_verify(self) -> str:
        """verify issuer"""
        self.logger.debug("CAhandler._issuer_verify()")

        api_response = self._issuers_list()

        if "issuers" in api_response:
            if self.ca_name in api_response["issuers"]:
                error = None
            else:
                error = f"CA {self.ca_name} not found"
                self.logger.error("CAhandler.enroll(): CA %s not found", self.ca_name)
        else:
            error = "Malformed response"
            self.logger.error(
                'CAhandler.enroll(): "Malformed response. "issuers" key not found'
            )

        self.logger.debug("CAhandler._issuer_verify() ended with: %s", error)
        return error

    def _issuers_list(self) -> Dict[str, str]:
        """list issuers"""
        self.logger.debug("CAhandler._list_issuers()")

        url = f"{self.api_host}/list_issuers"
        _code, api_response = self._api_get(url)

        self.logger.debug("CAhandler._list_issuers() ended")
        return api_response

    def _profiles_list(self) -> Dict[str, str]:
        """list profiles"""
        self.logger.debug("CAhandler._profiles_list()")

        url = f"{self.api_host}/list_profiles?issuerName={encode_url(self.logger, self.ca_name)}"
        _code, api_response = self._api_get(url)

        self.logger.debug("CAhandler._profiles_list() ended")
        return api_response

    def _profile_verify(self) -> str:
        """verify profile"""
        self.logger.debug("CAhandler._profile_verify(%s)", self.profile_name)
        api_response = self._profiles_list()

        if "profiles" in api_response:
            if self.profile_name in api_response["profiles"]:
                error = None
            else:
                error = f"Profile {self.profile_name} not found"
                self.logger.error(
                    "CAhandler.enroll(): Profile %s not found", self.profile_name
                )
        else:
            error = "Malformed response"
            self.logger.error(
                'CAhandler.enroll(): "Malformed response. "profiles" key not found'
            )

        self.logger.debug("CAhandler._profile_verify() ended with: %s", error)
        return error

    def _validity_dates_get(self) -> Tuple[str, str]:
        """calculate validity dates"""
        self.logger.debug("CAhandler._validity_dates_get()")

        uts_now_ = uts_now()
        validfrom = uts_to_date_utc(uts_now_, tformat="%Y-%m-%dT%H:%M:%S")
        validto = uts_to_date_utc(
            uts_now_ + (self.cert_validity_days * 24 * 60 * 60),
            tformat="%Y-%m-%dT%H:%M:%S",
        )

        self.logger.debug("CAhandler._validity_dates_get() ended")
        return validfrom, validto

    def _pem_cert_chain_generate(self, certs_list: list) -> str:
        """generate PEM certificate chain"""
        self.logger.debug("CAhandler._pem_cert_chain_generate()")

        pem_chain = ""
        for cert in certs_list:
            pem_chain += convert_byte_to_string(
                cert_der2pem(b64_decode(self.logger, cert))
            )

        self.logger.debug("CAhandler._pem_cert_chain_generate() ended")
        return pem_chain

    def _issuer_chain_get(self) -> str:
        """get issuer chain"""
        self.logger.debug("CAhandler._issuer_chain_get()")

        url = f"{self.api_host}/get_issuer_chain?issuerName={encode_url(self.logger, self.ca_name)}"
        _code, api_response = self._api_get(url)
        if "certs" in api_response:
            pem_chain = self._pem_cert_chain_generate(api_response["certs"])
        else:
            self.logger.error('CAhandler._issuer_chain_get(): "certs" key not found')
            pem_chain = None

        self.logger.debug("CAhandler._issuer_chain_get() ended")
        return pem_chain

    def _cert_get(self, data_dic: Dict[str, str]) -> str:
        """get certificate"""
        self.logger.debug("CAhandler._cert_get()")

        url = f"{self.api_host}/issue_certificate"
        code, api_response = self._api_post(url, data_dic)

        if code == 200 and api_response:
            cert = api_response
        else:
            self.logger.error(
                "CAhandler._cert_get(): enrollment failed: %s/%s", code, api_response
            )
            cert = None

        self.logger.debug("CAhandler._cert_get() ended")
        return cert

    def _cert_status_get(self, certificate: str) -> str:
        """get certificate status"""
        self.logger.debug("CAhandler._cert_status_get()")

        data_dic = {"certificateFile": certificate}
        url = f"{self.api_host}/verify_certificate?issuerName={encode_url(self.logger, self.ca_name)}"
        code, api_response = self._api_post(url, data_dic)
        api_response["code"] = code

        return api_response

    def _enrollment_dic_create(self, csr: str) -> Dict[str, str]:
        """create enrollment dic"""
        self.logger.debug("CAhandler._enrollment_dic_create()")

        # get public key from csr
        csr_pubkey = csr_pubkey_get(self.logger, csr, encoding="base64der")
        if csr_pubkey:
            # get CN from csr
            csr_cn = self._csr_cn_get(csr)

            # calculate validiaty dates
            validfrom, validto = self._validity_dates_get()

            # prepare payload for api call
            data_dic = {
                "publicKey": csr_pubkey,
                "profileName": self.profile_name,
                "issuerName": self.ca_name,
                "cn": csr_cn,
                "notBefore": validfrom,
                "notAfter": validto,
            }

            # get SANs from csr as base64 encoded byte sequence
            # sans_base64 = csr_san_byte_get(self.logger, csr)
            # if sans_base64:
            #    data_dic['extensions'] = [{'oid': '2.5.29.17', 'value': sans_base64}]  # 'Zm9vLmJhci5sb2NhbA=='

        else:
            self.logger.error(
                "CAhandler._enrollment_dic_create(): public key not found"
            )
            data_dic = None

        return data_dic

    def enroll(self, csr: str) -> Tuple[str, str, str, str]:
        """enroll certificate"""
        self.logger.debug("CAhandler.enroll()")

        cert_bundle = None
        error = None
        cert_raw = None
        poll_indentifier = None

        # check for eab profiling and header_info
        error = eab_profile_header_info_check(self.logger, self, csr, "profile_name")

        if not error:
            # check for allowed domainlist
            error = allowed_domainlist_check(self.logger, csr, self.allowed_domainlist)

        if self.enrollment_config_log:
            self.enrollment_config_log_skip_list.extend(["api_password", "auth"])
            enrollment_config_log(
                self.logger, self, self.enrollment_config_log_skip_list
            )

        if not error:
            # verify issuer
            error = self._issuer_verify()

        if not error:
            # verify profile
            error = self._profile_verify()
            if not error:

                # get issuer chain
                issuer_chain = self._issuer_chain_get()

                data_dic = self._enrollment_dic_create(csr)
                if data_dic:
                    cert_raw = self._cert_get(data_dic)

                if cert_raw:
                    cert = convert_byte_to_string(
                        cert_der2pem(b64_decode(self.logger, cert_raw))
                    )
                    cert_bundle = cert + issuer_chain
                else:
                    error = "Enrollment failed"

        self.logger.debug("Certificate.enroll() ended with: %s", error)
        return (error, cert_bundle, cert_raw, poll_indentifier)

    def poll(
        self, _cert_name: str, poll_identifier: str, _csr: str
    ) -> Tuple[str, str, str, str, bool]:
        """poll status of pending CSR and download certificates"""
        self.logger.debug("CAhandler.poll()")

        error = "Method not implemented."
        cert_bundle = None
        cert_raw = None
        rejected = False

        self.logger.debug("CAhandler.poll() ended")
        return (error, cert_bundle, cert_raw, poll_identifier, rejected)

    def revoke(
        self,
        cert: str,
        _rev_reason: str = "unspecified",
        _rev_date: str = uts_to_date_utc(uts_now()),
    ) -> Tuple[int, str, str]:
        """revoke certificate"""
        self.logger.debug("CAhandler.revoke()")

        code = None
        message = None
        detail = None

        cert_ski = cert_ski_get(
            self.logger, cert
        )  # get subjectKeyIdentifier from certificate

        url = f"{self.api_host}/revoke_certificate?issuerName={encode_url(self.logger, self.ca_name)}&certificateId={cert_ski}"
        data_dic = {}
        code, content_dic = self._api_post(url, data_dic)
        if content_dic:
            message = "urn:ietf:params:acme:error:serverInternal"
            if "Message" in content_dic:
                detail = content_dic.get("Message")
            elif "message" in content_dic:
                detail = content_dic.get("message")
            else:
                detail = "Unknown error"

        self.logger.debug("Certificate.revoke() ended")
        return (code, message, detail)

    def trigger(self, _payload: str) -> Tuple[str, str, str]:
        """process trigger message and return certificate"""
        self.logger.debug("CAhandler.trigger()")

        error = "Method not implemented."
        cert_bundle = None
        cert_raw = None

        self.logger.debug("CAhandler.trigger() ended with error: %s", error)
        return (error, cert_bundle, cert_raw)
