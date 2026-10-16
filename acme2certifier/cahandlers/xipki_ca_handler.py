# -*- coding: utf-8 -*-
"""CA handler for XiPKI REST gateway"""

from __future__ import print_function

import base64
import re
from typing import Optional, Tuple
from urllib.parse import urlencode

import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from requests.auth import HTTPBasicAuth

# pylint: disable=e0401
from acme2certifier.acme_srv.helper import (
    b64_encode,
    b64_url_recode,
    cert_der2pem,
    cert_serial_get,
    config_ca_bundle_load,
    config_eab_profile_load,
    config_enroll_config_log_load,
    config_headerinfo_load,
    config_option_load,
    config_profile_load,
    config_proxy_load,
    convert_byte_to_string,
    eab_profile_header_info_check,
    eab_profile_revocation_check,
    enrollment_config_log,
    error_dic_get,
    handler_config_check,
    load_config,
)
from acme2certifier.acme_srv.helpers.global_variables import CONFIGURATION_ERROR_DETAIL

CONTENT_TYPE_PKCS10 = "application/pkcs10"


class CAhandler(object):
    """XiPKI REST CA handler (HTTP Basic requestor auth)"""

    supports_trigger = False
    profile_mapping_field = "profile"

    def __init__(self, _debug: bool = None, logger: object = None):
        self.logger = logger
        self.api_host = None
        self.api_user = None
        self.api_password = None
        self.ca_bundle = True
        self.profile = None
        self.proxy = None
        self.request_timeout = 20
        self.session = None
        self.header_info_field = False
        self.eab_handler = None
        self.eab_profiling = False
        self.enrollment_config_log = False
        self.enrollment_config_log_skip_list = []
        self.profiles = {}
        self._ca_sha1 = None
        self._cacerts_pem = None
        self.err_msg_dic = error_dic_get(self.logger)

    def __enter__(self):
        """Makes CAhandler a Context Manager"""
        if not self.api_host:
            self._config_load()
            self._auth_set()
        return self

    def __exit__(self, *args):
        """close the connection at the end of the context"""

    def _api_host_normalize(self) -> Optional[str]:
        """strip trailing slash from api_host"""
        if self.api_host:
            return self.api_host.rstrip("/")
        return None

    def _auth_set(self) -> None:
        """configure session with HTTP Basic auth"""
        self.logger.debug("CAhandler._auth_set()")
        self.session = requests.Session()
        if self.api_user and self.api_password:
            self.session.auth = HTTPBasicAuth(self.api_user, self.api_password)
        else:
            self.logger.error(
                '%s: Auth incomplete. Either "api_user" or "api_password" is missing',
                CONFIGURATION_ERROR_DETAIL,
            )
        self.logger.debug("CAhandler._auth_set() ended")

    def _config_load(self) -> None:
        """load config from file"""
        self.logger.debug("CAhandler._config_load()")

        config_dic = load_config(self.logger, "CAhandler")
        if "CAhandler" in config_dic:
            self.api_host = config_dic.get(
                "CAhandler", "api_host", fallback=self.api_host
            )
            self.api_user = config_option_load(
                self.logger, config_dic, "api_user", current=self.api_user
            )
            self.api_password = config_option_load(
                self.logger, config_dic, "api_password", current=self.api_password
            )
            self.profile = config_dic.get(
                "CAhandler", self.profile_mapping_field, fallback=self.profile
            )
            try:
                self.request_timeout = int(
                    config_dic.get("CAhandler", "request_timeout", fallback=20)
                )
            except Exception as err:
                self.logger.error("Could not load request_timeout:%s", err)
                self.request_timeout = 20

            self.ca_bundle = config_ca_bundle_load(
                self.logger, config_dic, current=self.ca_bundle
            )
            self.proxy = config_proxy_load(
                self.logger, config_dic, self.api_host
            )

        self.eab_profiling, self.eab_handler = config_eab_profile_load(
            self.logger, config_dic
        )
        self.profiles = config_profile_load(self.logger, config_dic)
        self.header_info_field = config_headerinfo_load(self.logger, config_dic)
        (
            self.enrollment_config_log,
            self.enrollment_config_log_skip_list,
        ) = config_enroll_config_log_load(self.logger, config_dic)

        for ele in ["api_host", "api_user", "api_password", self.profile_mapping_field]:
            if not getattr(self, ele, None):
                self.logger.error(
                    '%s: parameter "%s" is missing in configuration file',
                    CONFIGURATION_ERROR_DETAIL,
                    ele,
                )

        self.logger.debug("CAhandler._config_load() ended")

    def _http_request(
        self,
        method: str,
        url: str,
        data: Optional[bytes] = None,
        headers: Optional[dict] = None,
    ) -> Tuple[int, bytes, str]:
        """HTTP request returning status, raw content, and text"""
        self.logger.debug("CAhandler._http_request(%s %s)", method, url)
        code = 500
        content = b""
        text = ""
        try:
            response = self.session.request(
                method=method,
                url=url,
                data=data,
                headers=headers,
                verify=self.ca_bundle,
                proxies=self.proxy,
                timeout=self.request_timeout,
            )
            code = response.status_code
            content = response.content or b""
            text = response.text or ""
        except Exception as err:
            self.logger.error("HTTP request failed: %s", err)
            text = str(err)
        self.logger.debug("CAhandler._http_request() ended with: %s", code)
        return code, content, text

    @staticmethod
    def _reason_normalize(rev_reason: Optional[str]) -> str:
        """map ACME/CRL reason tokens to XiPKI CrlReason names"""
        if not rev_reason:
            return "UNSPECIFIED"
        reason = rev_reason.strip()
        if not reason:
            return "UNSPECIFIED"
        if "_" in reason or reason.isupper():
            return reason.upper()
        # camelCase / mixed -> UPPER_SNAKE (keyCompromise -> KEY_COMPROMISE)
        snake = re.sub(r"(?<!^)(?=[A-Z])", "_", reason).upper()
        return snake

    def _csr_der_get(self, csr: str) -> bytes:
        """convert ACME CSR (base64url) to PKCS#10 DER"""
        self.logger.debug("CAhandler._csr_der_get()")
        csr_b64 = b64_url_recode(self.logger, csr)
        return base64.b64decode(csr_b64)

    def _ca_sha1_from_der(self, der_cert: bytes) -> str:
        """SHA-1 fingerprint of a DER certificate as lowercase hex"""
        cert = x509.load_der_x509_certificate(der_cert)
        return cert.fingerprint(hashes.SHA1()).hex()

    def _cacert_cache(self) -> Tuple[Optional[str], Optional[str]]:
        """fetch and cache CA cert (/cacert) and chain (/cacerts)"""
        self.logger.debug("CAhandler._cacert_cache()")
        error = None
        api_host = self._api_host_normalize()
        if not api_host:
            return f"{CONFIGURATION_ERROR_DETAIL}: api_host missing", None

        if self._cacerts_pem and self._ca_sha1:
            return None, self._cacerts_pem

        code, content, text = self._http_request("GET", f"{api_host}/cacerts")
        if code == 200 and content:
            self._cacerts_pem = convert_byte_to_string(content)
            if not self._cacerts_pem.endswith("\n"):
                self._cacerts_pem = f"{self._cacerts_pem}\n"
        else:
            error = f"Could not fetch /cacerts: HTTP {code}"
            if text:
                error = f"{error} - {text}"
            self.logger.error("%s", error)
            return error, None

        code, content, text = self._http_request("GET", f"{api_host}/cacert")
        if code == 200 and content:
            try:
                self._ca_sha1 = self._ca_sha1_from_der(content)
            except Exception as err:
                error = f"Could not parse /cacert: {err}"
                self.logger.error("%s", error)
                return error, None
        else:
            error = f"Could not fetch /cacert: HTTP {code}"
            if text:
                error = f"{error} - {text}"
            self.logger.error("%s", error)
            return error, None

        self.logger.debug(
            "CAhandler._cacert_cache() ended ca-sha1=%s", self._ca_sha1
        )
        return None, self._cacerts_pem

    def _enroll_post(self, csr_der: bytes) -> Tuple[Optional[str], Optional[bytes]]:
        """POST PKCS#10 enrollment to XiPKI"""
        self.logger.debug("CAhandler._enroll_post()")
        api_host = self._api_host_normalize()
        if not api_host:
            return f"{CONFIGURATION_ERROR_DETAIL}: api_host missing", None
        if not self.profile:
            return f"{CONFIGURATION_ERROR_DETAIL}: profile missing", None

        if self.enrollment_config_log:
            enrollment_config_log(
                self.logger, self, self.enrollment_config_log_skip_list
            )

        params = urlencode({"profile": self.profile})
        url = f"{api_host}/enroll-cert?{params}"
        headers = {"Content-Type": CONTENT_TYPE_PKCS10}
        code, content, text = self._http_request(
            "POST", url, data=csr_der, headers=headers
        )

        if code == 200 and content:
            self.logger.debug("CAhandler._enroll_post() ended ok")
            return None, content

        error = f"Enrollment failed: HTTP {code}"
        if text:
            error = f"{error} - {text}"
        self.logger.error("%s", error)
        return error, None

    def _bundle_create(
        self, leaf_der: bytes, ca_pem: str
    ) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        """build PEM bundle and base64 DER leaf"""
        self.logger.debug("CAhandler._bundle_create()")
        try:
            leaf_pem = convert_byte_to_string(cert_der2pem(leaf_der))
            cert_raw = b64_encode(self.logger, leaf_der)
            cert_bundle = f"{leaf_pem}{ca_pem}"
            return None, cert_bundle, cert_raw
        except Exception as err:
            error = f"Certificate parse failed: {err}"
            self.logger.error("%s", error)
            return error, None, None

    def enroll(self, csr: str) -> Tuple[str, str, str, str]:
        """enroll certificate via XiPKI REST"""
        self.logger.debug("CAhandler.enroll()")

        cert_bundle = None
        error = None
        cert_raw = None
        poll_identifier = None

        error = eab_profile_header_info_check(
            self.logger, self, csr, self.profile_mapping_field
        )

        if not error:
            error, ca_pem = self._cacert_cache()
            if not error:
                try:
                    csr_der = self._csr_der_get(csr)
                except Exception as err:
                    error = f"Invalid CSR: {err}"
                    self.logger.error("%s", error)
                    csr_der = None

                if not error and csr_der is not None:
                    error, leaf_der = self._enroll_post(csr_der)
                    if not error and leaf_der:
                        error, cert_bundle, cert_raw = self._bundle_create(
                            leaf_der, ca_pem
                        )
        else:
            self.logger.warning("CSR check failed: %s", error)

        self.logger.debug("CAhandler.enroll() ended with error: %s", error)
        return (error, cert_bundle, cert_raw, poll_identifier)

    def handler_check(self) -> str:
        """check if handler is ready"""
        self.logger.debug("CAhandler.handler_check()")
        error = handler_config_check(
            self.logger,
            self,
            ["api_host", "api_user", "api_password", self.profile_mapping_field],
        )
        self.logger.debug("CAhandler.handler_check() ended with %s", error)
        return error

    def poll(
        self, _cert_name: str, poll_identifier: str, _csr: str
    ) -> Tuple[str, str, str, str, bool]:
        """poll is not used (XiPKI REST enroll is synchronous)"""
        self.logger.debug("CAhandler.poll()")
        return ("Method not implemented.", None, None, poll_identifier, False)

    def revoke(
        self, cert: str, rev_reason: str = "unspecified", rev_date: str = None
    ) -> Tuple[int, str, str]:
        """revoke certificate via XiPKI REST"""
        self.logger.debug("CAhandler.revoke(%s: %s)", rev_reason, rev_date)
        code = 500
        message = self.err_msg_dic["serverinternal"]
        detail = None

        if self.eab_profiling:
            eab_profile_revocation_check(self.logger, self, cert)

        api_host = self._api_host_normalize()
        if not api_host:
            detail = f"{CONFIGURATION_ERROR_DETAIL}: api_host missing"
            return (400, message, detail)

        error, _ca_pem = self._cacert_cache()
        if error or not self._ca_sha1:
            detail = error or "ca-sha1 unavailable"
            return (400, message, detail)

        try:
            serial = cert_serial_get(self.logger, cert, hexformat=True)
        except Exception as err:
            self.logger.error("Could not parse certificate serial: %s", err)
            return (400, message, f"Invalid certificate: {err}")

        reason = self._reason_normalize(rev_reason)
        params = urlencode(
            {
                "ca-sha1": self._ca_sha1,
                "serial-number": f"0x{serial}",
                "reason": reason,
            }
        )
        url = f"{api_host}/revoke-cert?{params}"
        http_code, _content, text = self._http_request("GET", url)

        if http_code == 200:
            code = 200
            message = None
            detail = None
        else:
            code = 400
            detail = text or f"HTTP {http_code}"
            self.logger.error("Revocation failed: %s", detail)

        self.logger.debug("CAhandler.revoke() ended with: %s", code)
        return (code, message, detail)

    def trigger(self, _payload: str) -> Tuple[str, str, str]:
        """trigger is not supported"""
        self.logger.debug("CAhandler.trigger()")
        return ("Method not implemented.", None, None)
