# -*- coding: utf-8 -*-
"""ca handler for generic EST server"""
from __future__ import print_function
import os
import textwrap
import json
from typing import List, Tuple, Dict
import requests
from requests.auth import HTTPBasicAuth
from requests_pkcs12 import Pkcs12Adapter
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization.pkcs7 import (
    load_pem_pkcs7_certificates,
    load_der_pkcs7_certificates,
)

# pylint: disable=e0401
from acme_srv.helper import (
    load_config,
    b64_decode,
    b64_url_recode,
    convert_byte_to_string,
    convert_string_to_byte,
    parse_url,
    proxy_check,
    config_allowed_domainlist_load,
    allowed_domainlist_check,
)


class CAhandler(object):
    """EST CA  handler"""

    def __init__(self, _debug: bool = False, logger: object = None):
        self.logger = logger
        self.est_host = None
        self.est_client_cert = False
        self.cert_passphrase = False
        self.est_user = None
        self.est_password = None
        self.ca_bundle = True
        self.proxy = None
        self.request_timeout = 20
        self.session = None
        self.allowed_domainlist = []

    def __enter__(self):
        """Makes CAhandler a Context Manager"""
        if not self.est_host:
            self._config_load()
        return self

    def __exit__(self, *args):
        """cose the connection at the end of the context"""

    def _cacerts_get(self) -> Tuple[str, str]:
        """get ca certs from cerver"""
        self.logger.debug("CAhandler._cacerts_get()")
        error = None
        if self.est_host:
            try:
                if self.est_client_cert:
                    self.logger.debug("CAhandler._cacerts_get() by using client-certs")
                    # client auth
                    response = self.session.get(
                        self.est_host + "/cacerts",
                        verify=self.ca_bundle,
                        proxies=self.proxy,
                        timeout=self.request_timeout,
                    )
                else:
                    self.logger.debug(
                        "CAhandler._cacerts_get() by using userid/password"
                    )
                    response = self.session.get(
                        self.est_host + "/cacerts",
                        auth=HTTPBasicAuth(self.est_user, self.est_password),
                        verify=self.ca_bundle,
                        proxies=self.proxy,
                        timeout=self.request_timeout,
                    )
                pem = self._pkcs7_to_pem(b64_decode(self.logger, response.text))
            except Exception as err_:
                self.logger.error(
                    "CAhandler._cacerts_get() returned an error: %s", err_
                )
                error = err_
                pem = None
        else:
            self.logger.error(
                'CAhandler._cacerts_get() configuration incomplete: "est_host" parameter is missing'
            )
            error = None
            pem = None

        self.logger.debug("CAhandler._cacerts_get() ended with err: %s", error)
        return (error, pem)

    def _cert_bundle_create(
        self, error: str, ca_pem: str, cert_raw: str
    ) -> Tuple[str, str, str]:
        """create cert bundle"""
        self.logger.debug("CAhandler._cert_bundle_create()")

        cert_bundle = None
        if not error:
            cert_bundle = cert_raw + ca_pem
            cert_raw = cert_raw.replace("-----BEGIN CERTIFICATE-----\n", "")
            cert_raw = cert_raw.replace("-----END CERTIFICATE-----\n", "")
            cert_raw = cert_raw.replace("\n", "")
        else:
            self.logger.error("CAhandler.enroll() _simpleenroll error: %s", error)

        self.logger.debug("CAhandler._cert_bundle_create()")
        return (error, cert_bundle, cert_raw)

    def _config_host_load(self, config_dic: Dict[str, str]):
        """load est server address"""
        self.logger.debug("CAhandler._config_host_load()")

        if "est_host_variable" in config_dic["CAhandler"]:
            try:
                self.est_host = (
                    os.environ[config_dic.get("CAhandler", "est_host_variable")]
                    + "/.well-known/est"
                )
            except Exception as err:
                self.logger.error(
                    "CAhandler._config_load() could not load est_host_variable:%s", err
                )
        if "est_host" in config_dic["CAhandler"]:
            if self.est_host:
                self.logger.info("Overwrite est_host")
            self.est_host = config_dic.get("CAhandler", "est_host") + "/.well-known/est"
        if not self.est_host:
            self.logger.error('CAhandler._config_load(): missing "est_host" parameter')

        self.logger.debug("CAhandler._config_host_load() ended")

    def _cert_passphrase_load(self, config_dic: Dict[str, str]):
        """load cert passphrase"""
        self.logger.debug("CAhandler._cert_passphrase_load()")
        if "cert_passphrase_variable" in config_dic["CAhandler"]:
            try:
                self.cert_passphrase = os.environ[
                    config_dic.get("CAhandler", "cert_passphrase_variable")
                ]
            except Exception as err:
                self.logger.error(
                    "CAhandler._config_authuser_load() could not load cert_passphrase_variable:%s",
                    err,
                )
        if "cert_passphrase" in config_dic["CAhandler"]:
            if self.cert_passphrase:
                self.logger.info("Overwrite cert_passphrase")
            self.cert_passphrase = config_dic.get("CAhandler", "cert_passphrase")
        self.logger.debug("CAhandler._cert_passphrase_load() ended")

    def _config_clientauth_load(self, config_dic: Dict[str, str]):
        """check if we need to use clientauth"""
        self.logger.debug("CAhandler._config_clientauth_load()")

        # client auth via pem files
        if "est_client_cert" in config_dic["CAhandler"]:
            if "est_client_key" in config_dic["CAhandler"]:
                self.logger.debug("CAhandler._config_clientauth_load(): load pem")
                self.est_client_cert = config_dic.get(
                    "CAhandler", "est_client_cert", fallback=self.est_client_cert
                )
                self.session.cert = (
                    config_dic.get("CAhandler", "est_client_cert"),
                    config_dic.get("CAhandler", "est_client_key"),
                )
            elif (
                "cert_passphrase" in config_dic["CAhandler"]
                or "cert_passphrase_variable" in config_dic["CAhandler"]
            ):
                self.logger.debug("CAhandler._config_clientauth_load(): load pkcs12")
                self.est_client_cert = config_dic.get("CAhandler", "est_client_cert")
                self._cert_passphrase_load(config_dic)
                self.session.mount(
                    self.est_host,
                    Pkcs12Adapter(
                        pkcs12_filename=config_dic.get("CAhandler", "est_client_cert"),
                        pkcs12_password=self.cert_passphrase,
                    ),
                )
            else:
                self.logger.error(
                    'ERROR:test_a2c:CAhandler._config_load() clientauth configuration incomplete: either "est_client_key or "cert_passphrase" parameter is missing in config file'
                )

        self.logger.debug("CAhandler._config_clientauth_load() ended")

    def _config_userauth_load(self, config_dic: Dict[str, str]):
        """check if we need to use user-auth"""
        self.logger.debug("CAhandler._config_userauth_load()")

        if "est_user_variable" in config_dic["CAhandler"]:
            try:
                self.est_user = os.environ[
                    config_dic.get("CAhandler", "est_user_variable")
                ]
            except Exception as err:
                self.logger.error(
                    "CAhandler._config_load() could not load est_user_variable:%s", err
                )
        if "est_user" in config_dic["CAhandler"]:
            if self.est_user:
                self.logger.info("CAhandler._config_load() overwrite est_user")
            self.est_user = config_dic.get("CAhandler", "est_user")

        self.logger.debug("CAhandler._config_userauth_load() ended")

    def _config_password_load(self, config_dic: Dict[str, str]):
        """load password"""
        self.logger.debug("CAhandler._config_password_load()")

        if "est_password_variable" in config_dic["CAhandler"]:
            try:
                self.est_password = os.environ[
                    config_dic.get("CAhandler", "est_password_variable")
                ]
            except Exception as err:
                self.logger.error(
                    "CAhandler._config_load() could not load est_password:%s", err
                )
        if "est_password" in config_dic["CAhandler"]:
            if self.est_password:
                self.logger.info("Overwrite est_password")
            self.est_password = config_dic.get("CAhandler", "est_password")

        if (self.est_user and not self.est_password) or (
            self.est_password and not self.est_user
        ):
            self.logger.error(
                'CAhandler._config_load() configuration incomplete: either "est_user" or "est_password" parameter is missing in config file'
            )

        self.logger.debug("CAhandler._config_password_load() ended")

    def _config_parameters_load(self, config_dic: Dict[str, str]):
        """load config paramters"""
        self.logger.debug("CAhandler._config_load()")

        # check if we get a ca bundle for verification
        try:
            self.ca_bundle = config_dic.getboolean("CAhandler", "ca_bundle")
        except Exception:
            self.ca_bundle = config_dic.get(
                "CAhandler", "ca_bundle", fallback=self.ca_bundle
            )

        try:
            self.request_timeout = int(
                config_dic.get(
                    "CAhandler", "request_timeout", fallback=self.request_timeout
                )
            )
        except Exception:
            self.logger.error(
                "CAhandler._config_load() could not load request_timeout:%s",
                config_dic.get("CAhandler", "request_timeout"),
            )

        self.logger.debug("CAhandler._config_load() ended")

    def _config_proxy_load(self, config_dic: Dict[str, str]):
        """load config paramters"""
        self.logger.debug("CAhandler._config_proxy_load()")

        if "DEFAULT" in config_dic and "proxy_server_list" in config_dic["DEFAULT"]:
            try:
                proxy_list = json.loads(config_dic.get("DEFAULT", "proxy_server_list"))
                url_dic = parse_url(self.logger, self.est_host)
                if "host" in url_dic:
                    (fqdn, _port) = url_dic["host"].split(":")
                    proxy_server = proxy_check(self.logger, fqdn, proxy_list)
                    self.proxy = {"http": proxy_server, "https": proxy_server}
            except Exception as err_:
                self.logger.warning(
                    "Challenge._config_load() proxy_server_list failed with error: %s",
                    err_,
                )

        self.logger.debug("CAhandler._config_proxy_load() ended")

    def _config_load(self):
        """ " load config from file"""
        # pylint: disable=R0912, R0915
        self.logger.debug("CAhandler._config_load()")
        config_dic = load_config(self.logger, "CAhandler")

        if "CAhandler" in config_dic:

            with requests.Session() as self.session:
                # load host information
                self._config_host_load(config_dic)
                # load clientauth
                self._config_clientauth_load(config_dic)
                # load user
                self._config_userauth_load(config_dic)
                # load password
                self._config_password_load(config_dic)
                # load paramters
                self._config_parameters_load(config_dic)
                # load allowed domainlist
                self.allowed_domainlist = config_allowed_domainlist_load(
                    self.logger, config_dic
                )
                # check if we have one authentication scheme
                if not self.est_client_cert and not self.est_user:
                    self.logger.error(
                        "CAhandler._config_load() configuration incomplete: either user or client authentication must be configured."
                    )
                elif self.est_client_cert and self.est_user:
                    self.logger.error(
                        "CAhandler._config_load() configuration wrong: user and client authentication cannot be configured together."
                    )
                if self.est_client_cert and not self.ca_bundle:
                    self.logger.error(
                        "CAhandler._config_load() configuration wrong: client authentication requires a ca_bundle."
                    )

        # load proxy information
        self._config_proxy_load(config_dic)

        self.logger.debug("CAhandler._config_load() ended")

    def _pkcs7_to_pem(self, pkcs7_content: str, outform: str = "string") -> List[str]:
        """convert pkcs7 to pem"""
        self.logger.debug("CAhandler._pkcs7_to_pem()")

        try:
            pkcs7_obj = load_pem_pkcs7_certificates(
                convert_string_to_byte(pkcs7_content)
            )
        except Exception:
            self.logger.debug("CAhandler._pkcs7_to_pem(): load pem failed. Try der...")
            pkcs7_obj = load_der_pkcs7_certificates(pkcs7_content)

        cert_pem_list = []
        for cert in pkcs7_obj:
            cert_pem_list.append(
                convert_byte_to_string(cert.public_bytes(serialization.Encoding.PEM))
            )

        # define output format
        if outform == "string":
            result = "".join(cert_pem_list)
        elif outform == "list":
            result = cert_pem_list
        else:
            result = None

        self.logger.debug("Certificate._pkcs7_to_pem() ended")
        return result

    def _simpleenroll(self, csr: str) -> Tuple[str, str]:
        """EST /simpleenroll request."""
        self.logger.debug("CAhandler._simpleenroll()")
        error = None
        try:
            headers = {"Content-Type": "application/pkcs10"}
            if self.est_client_cert:
                # client auth
                response = self.session.post(
                    self.est_host + "/simpleenroll",
                    data=csr,
                    headers=headers,
                    verify=self.ca_bundle,
                    proxies=self.proxy,
                    timeout=self.request_timeout,
                )
            else:
                response = self.session.post(
                    self.est_host + "/simpleenroll",
                    data=csr,
                    auth=HTTPBasicAuth(self.est_user, self.est_password),
                    headers=headers,
                    verify=self.ca_bundle,
                    proxies=self.proxy,
                    timeout=self.request_timeout,
                )
            # response.raise_for_status()
            pem = self._pkcs7_to_pem(b64_decode(self.logger, response.text))
        except Exception as err_:
            self.logger.error("CAhandler._simpleenroll() returned an error: %s", err_)
            error = str(err_)
            pem = None

        self.logger.debug("CAhandler._simpleenroll() ended with err: %s", error)
        return (error, pem)

    def enroll(self, csr: str) -> Tuple[str, str, str, bool]:
        """enroll certificate from NCLM"""
        self.logger.debug("CAhandler.enroll()")
        cert_bundle = None
        error = None
        cert_raw = None

        # check for allowed domainlist
        error = allowed_domainlist_check(self.logger, csr, self.allowed_domainlist)

        if not error:
            # recode csr
            csr = textwrap.fill(b64_url_recode(self.logger, csr), 64) + "\n"

            if self.est_host:
                (error, ca_pem) = self._cacerts_get()

            if not error:
                if ca_pem:
                    (error, cert_raw) = self._simpleenroll(csr)
                    # build certificate bundle
                    (error, cert_bundle, cert_raw) = self._cert_bundle_create(
                        error, ca_pem, cert_raw
                    )
                else:
                    error = "no CA certificates found"
                    self.logger.error("CAhandler.enroll(): no CA certificates found")
            else:
                self.logger.error("CAhandler.enroll() _cacerts_get error: %s", error)

        self.logger.debug("Certificate.enroll() ended")
        return (error, cert_bundle, cert_raw, None)

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
        self, _cert: str, _rev_reason: str, _rev_date: str
    ) -> Tuple[int, str, str]:
        """revoke certificate"""
        self.logger.debug("CAhandler.tsg_id_lookup()")

        code = 500
        message = "urn:ietf:params:acme:error:serverInternal"
        detail = "Revocation is not supported."

        self.logger.debug("CAhandler.revoke() ended")
        return (code, message, detail)

    def trigger(self, _payload: str) -> Tuple[str, str, str]:
        """process trigger message and return certificate"""
        self.logger.debug("CAhandler.trigger()")

        error = "Method not implemented."
        cert_bundle = None
        cert_raw = None

        self.logger.debug("CAhandler.trigger() ended with error: %s", error)
        return (error, cert_bundle, cert_raw)
