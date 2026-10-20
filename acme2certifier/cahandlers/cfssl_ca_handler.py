# -*- coding: utf-8 -*-
"""CA handler for Cloudflare CFSSL (cfssl serve)."""

from __future__ import print_function

import base64
import hashlib
import hmac
import json
from typing import Dict, Optional, Tuple, Union

# pylint: disable=e0401
from acme2certifier.acme_srv.helper import (
    b64_encode,
    b64_url_recode,
    build_pem_file,
    ca_api_request,
    cert_aki_get,
    cert_pem2der,
    cert_serial_get,
    config_ca_bundle_load,
    config_eab_profile_load,
    config_enroll_config_log_load,
    config_headerinfo_load,
    config_option_load,
    config_profile_load,
    config_proxy_load,
    eab_profile_header_info_check,
    eab_profile_revocation_check,
    enrollment_config_log,
    error_dic_get,
    handler_config_check,
    load_config,
)
from acme2certifier.acme_srv.helpers.global_variables import CONFIGURATION_ERROR_DETAIL

CONTENT_TYPE = "application/json"
API_PREFIX = "/api/v1/cfssl"


class CAhandler(object):
    """CFSSL REST CA handler (sign / authsign / info / revoke)."""

    supports_trigger = False
    profile_mapping_field = "profile"

    def __init__(self, _debug: bool = None, logger: object = None):
        self.logger = logger
        self.cfssl_url = None
        self.profile = None
        self.label = None
        self.auth_key = None
        self.chain_file = None
        self.ca_bundle = True
        self.proxy = None
        self.request_timeout = 20
        self.request_retries = 3
        self.request_retry_backoff = 2.0
        self.header_info_field = False
        self.eab_handler = None
        self.eab_profiling = False
        self.enrollment_config_log = False
        self.enrollment_config_log_skip_list = []
        self.profiles = {}
        self.err_msg_dic = error_dic_get(self.logger)
        self._signer_pem = None
        self._signer_cache_key = None

    def __enter__(self):
        """Makes CAhandler a context manager."""
        if not self.cfssl_url:
            self._config_load()
        return self

    def __exit__(self, *args):
        """Close the connection at the end of the context."""

    def _config_number(self, config_dic, key: str, current, cast):
        """Load a numeric option, keeping current when parsing fails."""
        try:
            return cast(config_dic.get("CAhandler", key, fallback=current))
        except Exception as err:
            self.logger.error("Could not load %s: %s", key, err)
            return current

    def _config_load(self) -> None:
        """Load config from file."""
        self.logger.debug("CAhandler._config_load()")
        config_dic = load_config(self.logger, "CAhandler")
        if "CAhandler" in config_dic:
            self.cfssl_url = config_dic.get(
                "CAhandler", "cfssl_url", fallback=self.cfssl_url
            )
            self.profile = config_dic.get(
                "CAhandler", self.profile_mapping_field, fallback=self.profile
            )
            self.label = config_dic.get("CAhandler", "label", fallback=self.label)
            self.auth_key = config_option_load(
                self.logger, config_dic, "auth_key", current=self.auth_key
            )
            self.chain_file = config_dic.get(
                "CAhandler", "chain_file", fallback=self.chain_file
            )
            self.request_timeout = self._config_number(
                config_dic, "request_timeout", self.request_timeout, int
            )
            self.request_retries = self._config_number(
                config_dic, "request_retries", self.request_retries, int
            )
            self.request_retry_backoff = self._config_number(
                config_dic, "request_retry_backoff", self.request_retry_backoff, float
            )
            self.ca_bundle = config_ca_bundle_load(
                self.logger, config_dic, current=self.ca_bundle
            )
            self.proxy = config_proxy_load(self.logger, config_dic, self.cfssl_url)

        self.eab_profiling, self.eab_handler = config_eab_profile_load(
            self.logger, config_dic
        )
        self.profiles = config_profile_load(self.logger, config_dic)
        self.header_info_field = config_headerinfo_load(self.logger, config_dic)
        (
            self.enrollment_config_log,
            self.enrollment_config_log_skip_list,
        ) = config_enroll_config_log_load(self.logger, config_dic)

        if not self.cfssl_url:
            self.logger.error(
                '%s: parameter "cfssl_url" is missing in configuration file',
                CONFIGURATION_ERROR_DETAIL,
            )
        self.logger.debug("CAhandler._config_load() ended")

    def _endpoint(self, name: str) -> str:
        """Build a CFSSL v1 API URL."""
        return f"{self.cfssl_url.rstrip('/')}{API_PREFIX}/{name}"

    def _api_post(self, name: str, payload: Dict) -> Tuple[int, Union[Dict, str, None]]:
        """POST JSON to a CFSSL endpoint."""
        headers = {"Content-Type": CONTENT_TYPE}
        return ca_api_request(
            self.logger,
            "post",
            self._endpoint(name),
            headers=headers,
            proxy=self.proxy,
            timeout=self.request_timeout,
            payload=payload,
            verify=self.ca_bundle,
            retries=self.request_retries,
            retry_backoff=self.request_retry_backoff,
        )

    def _sign_body(self, csr_pem: str) -> Dict[str, str]:
        """JSON body for /sign. CSR subject and SANs are left unchanged."""
        body = {"certificate_request": csr_pem}
        if self.profile:
            body["profile"] = self.profile
        if self.label:
            body["label"] = self.label
        return body

    def _auth_wrap(self, body: Dict[str, str]) -> Tuple[Optional[str], Optional[Dict]]:
        """Wrap a request for /authsign (HMAC-SHA256, standard authenticator)."""
        self.logger.debug("CAhandler._auth_wrap()")
        try:
            raw = json.dumps(body, separators=(",", ":")).encode("utf-8")
            key = bytes.fromhex(self.auth_key.strip())
            digest = hmac.new(key, raw, hashlib.sha256).digest()
        except Exception as err:
            error = f"{CONFIGURATION_ERROR_DETAIL}: invalid auth_key: {err}"
            self.logger.error("%s", error)
            return error, None
        wrapped = {
            "token": base64.b64encode(digest).decode("ascii"),
            "request": base64.b64encode(raw).decode("ascii"),
        }
        self.logger.debug("CAhandler._auth_wrap() ended")
        return None, wrapped

    def _result_get(
        self, code: int, content, required: Optional[str] = None
    ) -> Tuple[Optional[str], Optional[Dict]]:
        """Return CFSSL result object or an error string."""
        if code != 200 or not isinstance(content, dict):
            detail = content if isinstance(content, str) else json.dumps(content)
            return f"CFSSL HTTP {code}: {detail}", None
        if not content.get("success"):
            return json.dumps(content.get("errors") or content), None
        result = content.get("result")
        if not isinstance(result, dict):
            return "CFSSL response missing result", None
        if required and not result.get(required):
            return f"CFSSL response missing {required}", None
        return None, result

    @staticmethod
    def _pem_normalize(pem: str) -> str:
        """Ensure a PEM blob ends with a single trailing newline."""
        return pem.strip() + "\n"

    def _chain_extra(self) -> Tuple[Optional[str], str]:
        """Read optional PEM certificates appended after the signer."""
        if not self.chain_file:
            return None, ""
        try:
            with open(self.chain_file, "r", encoding="utf-8") as handle:
                extra = handle.read()
        except Exception as err:
            error = f"Could not read chain_file: {err}"
            self.logger.error("%s", error)
            return error, ""
        if extra.strip():
            return None, self._pem_normalize(extra)
        return None, ""

    def _signer_pem_get(self) -> Tuple[Optional[str], Optional[str]]:
        """Fetch and cache the signing CA certificate from /info."""
        cache_key = (self.label or "", self.profile or "")
        if self._signer_pem and self._signer_cache_key == cache_key:
            return None, self._signer_pem

        body = {}
        if self.label:
            body["label"] = self.label
        if self.profile:
            body["profile"] = self.profile
        code, content = self._api_post("info", body)
        error, result = self._result_get(code, content, required="certificate")
        if error:
            self.logger.error("CFSSL info failed: %s", error)
            return error, None
        self._signer_pem = self._pem_normalize(result["certificate"])
        self._signer_cache_key = cache_key
        return None, self._signer_pem

    def _csr_pem(self, csr: str) -> Tuple[Optional[str], Optional[str]]:
        """Convert an ACME base64url PKCS#10 CSR to PEM."""
        try:
            csr_pem = build_pem_file(
                self.logger, None, b64_url_recode(self.logger, csr), None, True
            )
        except Exception as err:
            error = f"Invalid CSR: {err}"
            self.logger.error("%s", error)
            return error, None
        return None, csr_pem

    def _enroll_log(self) -> None:
        """Log enrollment configuration without the HMAC key."""
        if not self.enrollment_config_log:
            return
        skip = self.enrollment_config_log_skip_list
        if not isinstance(skip, list):
            skip = []
        enrollment_config_log(self.logger, self, skip + ["auth_key"])

    def _bundle_from_leaf(
        self, certificate: str
    ) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        """Build the PEM bundle and base64 DER leaf from a CFSSL certificate."""
        try:
            leaf_pem = self._pem_normalize(certificate)
            cert_raw = b64_encode(self.logger, cert_pem2der(leaf_pem))
        except Exception as err:
            error = f"Certificate parse failed: {err}"
            self.logger.error("%s", error)
            return error, None, None

        error, signer_pem = self._signer_pem_get()
        if error:
            return error, None, None
        error, extra = self._chain_extra()
        if error:
            return error, None, None
        return None, f"{leaf_pem}{signer_pem}{extra}", cert_raw

    def _enroll_submit(
        self, csr: str
    ) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        """Sign the CSR and assemble the chain."""
        error, csr_pem = self._csr_pem(csr)
        if error:
            return error, None, None

        self._enroll_log()
        body = self._sign_body(csr_pem)
        endpoint = "sign"
        if self.auth_key:
            error, body = self._auth_wrap(body)
            endpoint = "authsign"
        if error:
            return error, None, None

        code, content = self._api_post(endpoint, body)
        error, result = self._result_get(code, content, required="certificate")
        if error:
            self.logger.error("CFSSL sign failed: %s", error)
            return error, None, None
        return self._bundle_from_leaf(result["certificate"])

    def enroll(
        self, csr: str
    ) -> Tuple[Optional[str], Optional[str], Optional[str], None]:
        """Enroll a certificate. Issuance is synchronous."""
        self.logger.debug("CAhandler.enroll()")
        cert_bundle = None
        cert_raw = None

        error = eab_profile_header_info_check(
            self.logger, self, csr, self.profile_mapping_field
        )
        if error:
            self.logger.warning("CSR check failed: %s", error)
        elif not self.cfssl_url:
            error = f"{CONFIGURATION_ERROR_DETAIL}: cfssl_url missing"
            self.logger.error("%s", error)
        else:
            error, cert_bundle, cert_raw = self._enroll_submit(csr)

        self.logger.debug("CAhandler.enroll() ended with error: %s", error)
        return (error, cert_bundle, cert_raw, None)

    def handler_check(self) -> Optional[str]:
        """Check if the handler is ready."""
        self.logger.debug("CAhandler.handler_check()")
        error = handler_config_check(self.logger, self, ["cfssl_url"])
        self.logger.debug("CAhandler.handler_check() ended with %s", error)
        return error

    def poll(
        self, _cert_name: str, poll_identifier: str, _csr: str
    ) -> Tuple[str, None, None, str, bool]:
        """Poll is unused. CFSSL signs synchronously."""
        self.logger.debug("CAhandler.poll()")
        return ("Method not implemented.", None, None, poll_identifier, False)

    def revoke(
        self, cert: str, rev_reason: str = "unspecified", rev_date: str = None
    ) -> Tuple[int, Optional[str], Optional[str]]:
        """Revoke a certificate. Requires CFSSL -db-config."""
        self.logger.debug("CAhandler.revoke(%s: %s)", rev_reason, rev_date)
        message = self.err_msg_dic["serverinternal"]
        detail = None

        if self.eab_profiling:
            eab_profile_revocation_check(self.logger, self, cert)

        if not self.cfssl_url:
            detail = f"{CONFIGURATION_ERROR_DETAIL}: cfssl_url missing"
            return (400, message, detail)

        try:
            serial = cert_serial_get(self.logger, cert)
            aki = cert_aki_get(self.logger, cert)
        except Exception as err:
            self.logger.error("Could not parse certificate: %s", err)
            return (400, message, f"Invalid certificate: {err}")

        if serial is None or not aki:
            detail = "Certificate serial or authority key identifier missing"
            self.logger.error("%s", detail)
            return (400, message, detail)

        reason = rev_reason or "unspecified"
        http_code, content = self._api_post(
            "revoke",
            {
                "serial": str(serial),
                "authority_key_id": str(aki).lower(),
                "reason": reason,
            },
        )
        error, _result = self._result_get(http_code, content)
        if error:
            self.logger.error("Revocation failed: %s", error)
            return (400, message, error)

        self.logger.debug("CAhandler.revoke() ended with: 200")
        return (200, None, None)

    def trigger(self, _payload: str) -> Tuple[str, None, None]:
        """Trigger is not supported."""
        self.logger.debug("CAhandler.trigger()")
        return ("Method not implemented.", None, None)
