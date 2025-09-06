# -*- coding: utf-8 -*-
"""CA handler using HashiCorp Vault"""
from __future__ import print_function
from typing import Tuple, Dict, List
import datetime
import os
import requests
import json
from requests_pkcs12 import Pkcs12Adapter

# pylint: disable=e0401
from acme_srv.helper import (
    b64_encode,
    b64_url_recode,
    build_pem_file,
    cert_pem2der,
    cert_serial_get,
    eab_profile_header_info_check,
    eab_profile_revocation_check,
    load_config,
    uts_now,
    uts_to_date_utc,
    allowed_domainlist_check,
    csr_cn_lookup,
    config_allowed_domainlist_load,
    config_eab_profile_load,
    config_enroll_config_log_load,
    config_headerinfo_load,
    config_profile_load,
    config_proxy_load,
    enrollment_config_log,
    request_operation,
)


CONTENT_TYPE = "application/json"


class CAhandler(object):
    """Hashicorp vault handler"""

    def __init__(self, _debug: bool = None, logger: object = None):
        self.logger = logger
        self.vault_url = None
        self.vault_path = None
        self.vault_role = None
        self.vault_token = None
        self.issuer_ref = None
        self.cert_validity_days = 365
        self.request_timeout = 20
        self.ca_bundle = True

        self.allowed_domainlist = []
        self.header_info_field = False
        self.eab_handler = None
        self.eab_profiling = False
        self.enrollment_config_log = False
        self.enrollment_config_log_skip_list = []
        self.profiles = {}
        self.proxy = {}

    def __enter__(self):
        """Makes CAhandler a Context Manager"""
        if not self.vault_url:
            self._config_load()
        return self

    def __exit__(self, *args):
        """close the connection at the end of the context"""

    def _api_get(self, url: str) -> Tuple[int, Dict[str, str]]:
        """post data to API"""
        self.logger.debug("CAhandler._api_get()")
        headers = {"Content-Type": CONTENT_TYPE, "X-Vault-Token": self.vault_token}

        code, content = request_operation(
            self.logger,
            method="get",
            url=url,
            headers=headers,
            proxy=self.proxy,
            timeout=self.request_timeout,
            payload=None,
        )
        self.logger.debug("CAhandler._api_get() ended with code: %s", code)
        return code, content

    def _api_post(self, url: str, data: Dict[str, str]) -> Tuple[int, Dict[str, str]]:
        """post data to API"""
        self.logger.debug("CAhandler._api_post()")
        headers = {"Content-Type": CONTENT_TYPE, "X-Vault-Token": self.vault_token}
        code, content = request_operation(
            self.logger,
            method="post",
            url=url,
            headers=headers,
            proxy=self.proxy,
            timeout=self.request_timeout,
            payload=data,
            verify=self.ca_bundle,
        )
        self.logger.debug("CAhandler._api_post() ended with code: %s", code)
        return code, content

    def _api_put(self, url: str, data: Dict[str, str]) -> Tuple[int, Dict[str, str]]:
        """post data to API"""
        self.logger.debug("CAhandler._api_put()")
        headers = {"Content-Type": CONTENT_TYPE, "X-Vault-Token": self.vault_token}
        code, content = request_operation(
            self.logger,
            method="put",
            url=url,
            headers=headers,
            proxy=self.proxy,
            timeout=self.request_timeout,
            payload=data,
        )

        self.logger.debug("CAhandler._api_put() ended with code: %s", code)
        return code, content

    def _config_check(self) -> str:
        """check if config is valid"""
        self.logger.debug("CAhandler._config_check()")
        error = None

        error = None
        for ele in ["vault_url", "vault_path", "vault_role", "vault_token"]:
            if not getattr(self, ele):

                error = f"{ele} parameter is missing in config file"
                self.logger.error("Configuration check ended with error: %s", error)
                break

        self.logger.debug("CAhandler._config_check() ended with %s", error)
        return error

    def _config_load(self):
        """load config from file"""
        self.logger.debug("CAhandler._config_load()")

        config_dic = load_config(self.logger, "CAhandler")
        if "CAhandler" in config_dic:
            self.vault_url = config_dic.get("CAhandler", "vault_url", fallback=None)
            self.vault_path = config_dic.get("CAhandler", "vault_path", fallback=None)
            self.vault_role = config_dic.get("CAhandler", "vault_role", fallback=None)
            self.vault_token = config_dic.get("CAhandler", "vault_token", fallback=None)
            self.issuer_ref = config_dic.get("CAhandler", "issuer_ref", fallback=None)
            try:
                self.request_timeout = int(
                    config_dic.get(
                        "CAhandler", "request_timeout", fallback=self.request_timeout
                    )
                )
            except Exception as err:
                self.logger.error("Failed to parse request_timeout parameter: %s", err)
            try:
                self.cert_validity_days = int(
                    config_dic.get(
                        "CAhandler",
                        "cert_validity_days",
                        fallback=self.cert_validity_days,
                    )
                )
            except Exception as err:
                self.logger.error(
                    "Failed to parse cert_validity_days %s parameter",
                    err,
                )

            try:
                self.ca_bundle = config_dic.getboolean("CAhandler", "ca_bundle")
            except Exception:
                self.ca_bundle = config_dic.get(
                    "CAhandler", "ca_bundle", fallback=self.ca_bundle
                )

        # load allowed domainlist
        self.allowed_domainlist = config_allowed_domainlist_load(
            self.logger, config_dic
        )
        # load profiling
        self.eab_profiling, self.eab_handler = config_eab_profile_load(
            self.logger, config_dic
        )

        # load proxies
        self.proxy = config_proxy_load(self.logger, config_dic, self.vault_url)

        # load profiles
        self.profiles = config_profile_load(self.logger, config_dic)

        # load header info
        self.header_info_field = config_headerinfo_load(self.logger, config_dic)
        # load enrollment config log
        (
            self.enrollment_config_log,
            self.enrollment_config_log_skip_list,
        ) = config_enroll_config_log_load(self.logger, config_dic)

        self.logger.debug("CAhandler._config_load() ended")

    def _csr_check(self, csr: str) -> str:
        """check csr"""
        self.logger.debug("CAhandler._csr_check()")

        # check for allowed domainlist
        error = allowed_domainlist_check(self.logger, csr, self.allowed_domainlist)

        # check for eab profiling and header_info
        if not error:
            error = eab_profile_header_info_check(self.logger, self, csr, "vault_role")

        self.logger.debug("CAhandler._csr_check() ended with: %s", error)
        return error

    def enroll(self, csr: str) -> Tuple[str, str, str, str]:
        """enroll certificate"""
        self.logger.debug("CAhandler.enroll()")

        cert_bundle = None
        error = None
        cert_raw = None
        poll_indentifier = None

        error = self._config_check()

        if not error:
            error = self._csr_check(csr)

            if not error:
                csr_cn = csr_cn_lookup(self.logger, csr)
                # reformat csr
                # prepare the CSR to be signed
                csr = build_pem_file(
                    self.logger, None, b64_url_recode(self.logger, csr), None, True
                )

                data_dic = {
                    "csr": csr,
                    "common_name": csr_cn,
                }
                if self.issuer_ref:
                    enroll_url = f"{self.vault_url}/v1/{self.vault_path}/issuer/{self.issuer_ref}/sign/{self.vault_role}"
                else:
                    enroll_url = (
                        f"{self.vault_url}/v1/{self.vault_path}/sign/{self.vault_role}"
                    )

                if self.enrollment_config_log:
                    self.enrollment_config_log_skip_list.extend(
                        [
                            "vault_token",
                            "enrollment_config_log_skip_list",
                            "enrollment_config_log",
                        ]
                    )
                    enrollment_config_log(
                        self.logger, self, self.enrollment_config_log_skip_list
                    )

                # enroll certificate
                code, content = self._api_post(enroll_url, data_dic)

                if (
                    code in (200, 201)
                    and content.get("data").get("certificate")
                    and content.get("data").get("ca_chain")
                ):
                    cert_bundle = f'{content["data"]["certificate"]}\n' + "\n".join(
                        content["data"]["ca_chain"]
                    )
                    cert_raw = b64_encode(
                        self.logger, cert_pem2der(content["data"]["certificate"])
                    )
                else:
                    error = (
                        json.dumps(content["errors"])
                        if "errors" in content
                        else json.dumps(content)
                    )
                    self.logger.error("Failed to enroll certificate: %s", error)

        self.logger.debug("Certificate.enroll() ended")
        return error, cert_bundle, cert_raw, poll_indentifier

    def handler_check(self):
        """check if handler is ready"""
        self.logger.debug("CAhandler.check()")

        error = self._config_check()

        self.logger.debug("CAhandler.check() ended with %s", error)
        return error

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
        certificate_raw: str,
        _rev_reason: str = "unspecified",
        _rev_date: str = uts_to_date_utc(uts_now()),
    ) -> Tuple[int, str, str]:
        """revoke certificate"""
        self.logger.debug("CAhandler.revoke()")

        code = None
        message = None
        detail = None

        cert_serial = cert_serial_get(self.logger, certificate_raw, hexformat=True)

        if cert_serial:
            self.logger.debug("Certificate serial number found: %s", cert_serial)

            # modify handler configuration in case of eab profiling
            if self.eab_profiling:
                eab_profile_revocation_check(self.logger, self, certificate_raw)

            if self.enrollment_config_log:
                # log enrollment config
                self.enrollment_config_log_skip_list.extend(
                    [
                        "vault_token",
                        "enrollment_config_log_skip_list",
                        "enrollment_config_log",
                    ]
                )
                enrollment_config_log(
                    self.logger, self, self.enrollment_config_log_skip_list
                )

            # reformat serial number
            cert_serial = ":".join(
                cert_serial[i : i + 2] for i in range(0, len(cert_serial), 2)
            ).lower()
            data_dic = {"serial_number": f"{cert_serial}"}
            revoke_url = f"{self.vault_url}/v1/{self.vault_path}/revoke"
            code, content = self._api_post(revoke_url, data_dic)
            if code not in (200, 201):
                detail = (
                    json.dumps(content["errors"])
                    if "errors" in content
                    else json.dumps(content)
                )
                self.logger.error("Failed to revoke certificate: %s", detail)
        else:
            self.logger.error("Failed to get certificate serial number")
            code = 500
            detail = "Failed to parse certificate serial"

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
