# -*- coding: utf-8 -*-
"""CA handler using Digicert CertCentralAPI"""
from __future__ import print_function
from typing import Tuple, Dict

# pylint: disable=e0401
from acme_srv.helper import (
    allowed_domainlist_check,
    b64_encode,
    cert_pem2der,
    cert_serial_get,
    config_allowed_domainlist_load,
    config_eab_profile_load,
    config_enroll_config_log_load,
    config_headerinfo_load,
    config_profile_load,
    csr_cn_lookup,
    eab_profile_header_info_check,
    eab_profile_revocation_check,
    enrollment_config_log,
    handler_config_check,
    load_config,
    request_operation,
    uts_now,
    uts_to_date_utc,
)


CONTENT_TYPE = "application/json"


class CAhandler(object):
    """Digicert CertCentralAP handler"""

    def __init__(self, _debug: bool = None, logger: object = None):
        self.logger = logger
        self.api_url = "https://www.digicert.com/services/v2/"
        self.api_key = None
        self.cert_type = "ssl_basic"
        self.signature_hash = "sha256"
        self.order_validity = 1
        self.proxy = None
        self.request_timeout = 10
        self.organization_id = None
        self.organization_name = None
        self.allowed_domainlist = []
        self.header_info_field = False
        self.eab_handler = None
        self.eab_profiling = False
        self.enrollment_config_log = False
        self.enrollment_config_log_skip_list = []
        self.profiles = {}

    def __enter__(self):
        """Makes CAhandler a Context Manager"""
        if not self.api_key:
            self._config_load()
        return self

    def __exit__(self, *args):
        """cose the connection at the end of the context"""

    def _api_get(self, url: str) -> Tuple[int, Dict[str, str]]:
        """post data to API"""
        self.logger.debug("CAhandler._api_get()")
        headers = {"X-DC-DEVKEY": self.api_key, "Content-Type": CONTENT_TYPE}
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
        headers = {"X-DC-DEVKEY": self.api_key, "Content-Type": CONTENT_TYPE}
        code, content = request_operation(
            self.logger,
            method="post",
            url=url,
            headers=headers,
            proxy=self.proxy,
            timeout=self.request_timeout,
            payload=data,
        )

        self.logger.debug("CAhandler._api_post() ended with code: %s", code)
        return code, content

    def _api_put(self, url: str, data: Dict[str, str]) -> Tuple[int, Dict[str, str]]:
        """post data to API"""
        self.logger.debug("CAhandler._api_put()")
        headers = {"X-DC-DEVKEY": self.api_key, "Content-Type": CONTENT_TYPE}
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
        """check config"""
        self.logger.debug("CAhandler._config_check()")

        error = handler_config_check(
            self.logger, self, ["api_url", "api_key", "organization_name"]
        )

        self.logger.debug("CAhandler._config_check() ended with: %s", error)
        return error

    def _config_load(self):
        """ " load config from file"""
        self.logger.debug("CAhandler._config_load()")

        config_dic = load_config(self.logger, "CAhandler")
        if "CAhandler" in config_dic:
            self.api_url = config_dic.get(
                "CAhandler", "api_url", fallback="https://www.digicert.com/services/v2/"
            )
            self.api_key = config_dic.get("CAhandler", "api_key", fallback=self.api_key)
            self.cert_type = config_dic.get(
                "CAhandler", "cert_type", fallback="ssl_basic"
            )
            self.signature_hash = config_dic.get(
                "CAhandler", "signature_hash", fallback="sha256"
            )
            try:
                self.order_validity = int(
                    config_dic.get("CAhandler", "order_validity", fallback=1)
                )
            except Exception as err:
                self.logger.error(
                    "Could not load order_validity:%s",
                    err,
                )

            try:
                self.request_timeout = int(
                    config_dic.get("CAhandler", "request_timeout", fallback=10)
                )
            except Exception as err:
                self.logger.error(
                    "Could not load request_timeout:%s",
                    err,
                )
                self.request_timeout = 10
            self.organization_id = config_dic.get(
                "CAhandler", "organization_id", fallback=self.organization_id
            )
            self.organization_name = config_dic.get(
                "CAhandler", "organization_name", fallback=self.organization_name
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

        self.logger.debug("CAhandler._config_load() ended")

    def _order_send(self, csr: str, csr_cn) -> Tuple[str, str]:
        """place certificate order"""
        self.logger.debug("CAhandler._order_send()")
        order_url = f"{self.api_url}order/certificate/{self.cert_type}"

        if self.enrollment_config_log:
            enrollment_config_log(
                self.logger, self, self.enrollment_config_log_skip_list
            )

        if not csr.endswith("="):
            # padding if needed
            csr = csr + "=" * (-len(csr) % 4)

        if (
            (not self.organization_id or self.eab_profiling)
            and self.organization_name
            and self.api_key
        ):
            self.organization_id = self._organiation_id_get()

        if self.organization_id:
            data_dic = {
                "certificate": {
                    "common_name": csr_cn,
                    "csr": csr,
                    "signature_hash": self.signature_hash,
                    "server_platform": {"id": 34},
                },
                "organization": {
                    "id": self.organization_id,
                },
                "order_validity": {"years": self.order_validity},
            }
            # enroll certificate
            code, content = self._api_post(order_url, data_dic)
        else:
            self.logger.error("Configuration incomplete: organisation_id is missing")
            code = 500
            content = "organisation_id is missing"

        self.logger.debug("CAhandler._order_send() ended with code: %s", code)
        return code, content

    def _order_response_parse(self, content: Dict[str, str]) -> Tuple[str, str, str]:
        """parse order response"""
        self.logger.debug("CAhandler._order_response_parse()")

        cert_bundle = None
        cert_raw = None
        poll_identifier = None

        if content and "certificate_chain" in content:
            cert_bundle = ""
            for cert in content["certificate_chain"]:
                if "pem" in cert:
                    cert_bundle += cert["pem"] + "\n"
                else:
                    self.logger.error(
                        "Order response parsing failed: no pem in certificate_chain"
                    )
            cert_raw = b64_encode(
                self.logger, cert_pem2der(content["certificate_chain"][0]["pem"])
            )
            if "id" in content:
                poll_identifier = content["id"]
            else:
                self.logger.error(
                    "Polling_identifier generation failed: no id in response"
                )
        else:
            self.logger.error(
                "Order response parsing failed: no certificate_chain in response"
            )

        self.logger.debug("CAhandler._order_response_parse() ended")
        return cert_bundle, cert_raw, poll_identifier

    def _organiation_id_get(self):
        """get organization ID"""
        self.logger.debug("CAhandler._organiation_id_get()")

        org_url = f"{self.api_url}organization"
        code, content = self._api_get(org_url)

        organization_id = None
        if code in (200, 201):
            for org in content["organizations"]:
                if org["name"] == self.organization_name:
                    self.logger.debug(
                        "CAhandler._organiation_id_get() found organization ID: %s",
                        org["id"],
                    )
                    organization_id = org["id"]
                    break

        if not organization_id:
            self.logger.error("Could not get organization id.")

        self.logger.debug(
            "CAhandler._organiation_id_get() ended with: %s", organization_id
        )
        return organization_id

    def _csr_check(self, csr: str) -> str:
        """check csr"""
        self.logger.debug("CAhandler._csr_check()")

        # check for allowed domainlist
        error = allowed_domainlist_check(self.logger, csr, self.allowed_domainlist)

        # check for eab profiling and header_info
        if not error:
            error = eab_profile_header_info_check(self.logger, self, csr, "cert_type")

        self.logger.debug("CAhandler._csr_check() ended with: %s", error)
        return error

    def enroll(self, csr: str) -> Tuple[str, str, str, str]:
        """enroll certificate"""
        self.logger.debug("CAhandler.enroll()")

        cert_bundle = None
        error = None
        cert_raw = None
        poll_indentifier = None

        # check configuration
        error = self._config_check()

        if not error:
            # check csr and profiling
            error = self._csr_check(csr)

            if not error:
                csr_cn = csr_cn_lookup(self.logger, csr)
                code, content = self._order_send(csr, csr_cn)

                if code in (200, 201):
                    # successful
                    (
                        cert_bundle,
                        cert_raw,
                        poll_indentifier,
                    ) = self._order_response_parse(content)
                else:
                    if "errors" in content:
                        error = (
                            f"Error during order creation: {code} - {content['errors']}"
                        )
                    else:
                        error = f"Error during order creation: {code} - {content}"

        self.logger.debug("Certificate.enroll() ended")
        return (error, cert_bundle, cert_raw, poll_indentifier)

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
            # modify handler configuration in case of eab profiling
            if self.eab_profiling:
                self._config_check()

            revocation_url = f"{self.api_url}certificate/{cert_serial}/revoke"
            data_dic = {"skip_approval": True}
            code, detail = self._api_put(revocation_url, data_dic)
            if code == 204:
                # rewrite reponse code to not confuse with success
                code = 200
        else:
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
