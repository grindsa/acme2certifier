# -*- coding: utf-8 -*-
"""CA handler using Google Cloud Certificate Authority Service (Private CAS) REST."""

from __future__ import annotations

import json
import os
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote, urlencode

import requests

from acme2certifier.acme_srv.helper import (
    b64_encode,
    b64_url_recode,
    build_pem_file,
    cert_pem2der,
    cert_serial_get,
    config_ca_bundle_load,
    config_eab_profile_load,
    config_enroll_config_log_load,
    config_headerinfo_load,
    config_number_load,
    config_option_load,
    config_profile_load,
    config_proxy_load,
    eab_profile_header_info_check,
    eab_profile_revocation_check,
    enrollment_config_log,
    handler_config_check,
    load_config,
    uts_now,
    uts_to_date_utc,
)

CONTENT_TYPE = "application/json"
DEFAULT_API_HOST = "https://privateca.googleapis.com"
ACME_ERR_SERVER_INTERNAL = "urn:ietf:params:acme:error:serverInternal"
GCP_OAUTH_SCOPE = "https://www.googleapis.com/auth/cloud-platform"
PLACEHOLDER_BEARER = "mock-token"

# ACME / RFC 5280 reason names -> Private CAS RevocationReason
_REV_REASON_MAP: Dict[str, str] = {
    "unspecified": "REVOCATION_REASON_UNSPECIFIED",
    "keycompromise": "KEY_COMPROMISE",
    "cacompromise": "CERTIFICATE_AUTHORITY_COMPROMISE",
    "affiliationchanged": "AFFILIATION_CHANGED",
    "superseded": "SUPERSEDED",
    "cessationofoperation": "CESSATION_OF_OPERATION",
    "certificatehold": "CERTIFICATE_HOLD",
    "privilegewithdrawn": "PRIVILEGE_WITHDRAWN",
    "aacompromise": "ATTRIBUTE_AUTHORITY_COMPROMISE",
}


class CAhandler:
    """Google Cloud Private CAS handler using HTTPS REST + Bearer (google-auth optional)."""

    def __init__(self, _debug: bool = None, logger: object = None):
        self.logger = logger
        self.project: Optional[str] = None
        self.location: Optional[str] = None
        self.ca_pool: Optional[str] = None
        self.issuing_certificate_authority_id: Optional[str] = None
        self.certificate_template: Optional[str] = None
        self.lifetime_days: int = 365
        self.endpoint_url: Optional[str] = None
        self.credentials_file: Optional[str] = None
        self.access_token: Optional[str] = None
        self.request_timeout: int = 60
        self.request_retries: int = 0
        self.proxy: Dict[str, str] = {}
        self.ca_bundle: Any = True
        self.verify: bool = True

        self.header_info_field = False
        self.eab_handler = None
        self.eab_profiling = False
        self.enrollment_config_log = False
        self.enrollment_config_log_skip_list: list = []
        self.profiles: Dict[str, str] = {}
        self.profile_mapping_field = "certificate_template"

    def __enter__(self):
        """Makes CAhandler a Context Manager"""
        if not self.ca_pool and not self.project:
            self._config_load()
        return self

    def __exit__(self, *args):
        """close the connection at the end of the context"""

    def _parent_resource(self) -> str:
        """Return caPools parent resource name."""
        self.logger.debug("CAhandler._parent_resource()")
        pool = (self.ca_pool or "").strip()
        if pool.startswith("projects/"):
            return pool.rstrip("/")
        if not self.project or not self.location or not pool:
            raise RuntimeError(
                "project, location, and ca_pool are required "
                "(or set ca_pool to a full projects/.../caPools/... name)"
            )
        return f"projects/{self.project}/locations/{self.location}/caPools/{pool}"

    def _service_url(self) -> str:
        """Private CAS API base (production or endpoint_url mock)."""
        if self.endpoint_url:
            return self.endpoint_url.rstrip("/")
        return DEFAULT_API_HOST

    def _credentials_resolve(self) -> str:
        """
        Return Bearer access token.

        Precedence: access_token > credentials_file > ADC.
        With endpoint_url and no explicit credentials, use PLACEHOLDER_BEARER
        without attempting ADC/google-auth (local mock).
        """
        self.logger.debug("CAhandler._credentials_resolve()")
        if self.access_token:
            return self.access_token

        if self.credentials_file:
            return self._token_from_credentials_file(self.credentials_file)

        # Mock / custom endpoint: do not probe ADC (avoids google-auth noise).
        if self.endpoint_url:
            self.logger.debug(
                "Using placeholder Bearer for endpoint_url=%s", self.endpoint_url
            )
            return PLACEHOLDER_BEARER

        return self._token_from_adc()

    def _google_auth_import(self):
        """Lazy-import google-auth; raise a clear error if the [gcp] extra is missing."""
        try:
            import google.auth  # noqa: WPS433
            import google.auth.transport.requests  # noqa: WPS433
            from google.oauth2 import service_account  # noqa: WPS433
        except ImportError as err:
            raise RuntimeError(
                "google-auth is required for Google Private CAS authentication "
                "(install with: pip install 'acme2certifier[gcp]'). "
                "For the local mock, set endpoint_url and optionally access_token."
            ) from err
        return google.auth, google.auth.transport.requests, service_account

    def _token_from_credentials_file(self, path: str) -> str:
        """Load a service-account JSON and refresh a Bearer token."""
        self.logger.debug("CAhandler._token_from_credentials_file(%s)", path)
        _google_auth, transport_requests, service_account = self._google_auth_import()
        creds = service_account.Credentials.from_service_account_file(
            path, scopes=[GCP_OAUTH_SCOPE]
        )
        request = transport_requests.Request()
        creds.refresh(request)
        if not creds.token:
            raise RuntimeError("Failed to obtain access token from credentials_file")
        return creds.token

    def _token_from_adc(self) -> str:
        """Application Default Credentials → Bearer token."""
        self.logger.debug("CAhandler._token_from_adc()")
        google_auth, transport_requests, _service_account = self._google_auth_import()
        creds, _project = google_auth.default(scopes=[GCP_OAUTH_SCOPE])
        request = transport_requests.Request()
        if not getattr(creds, "valid", False) or not getattr(creds, "token", None):
            creds.refresh(request)
        if not creds.token:
            raise RuntimeError("Failed to obtain access token from ADC")
        return creds.token

    def _config_check(self) -> Optional[str]:
        """check if config is valid"""
        self.logger.debug("CAhandler._config_check()")
        error = None
        try:
            self._parent_resource()
        except RuntimeError as err:
            error = str(err)
            self.logger.error("Configuration error: %s", error)

        if not error:
            required = ["project", "location", "ca_pool"]
            pool = (self.ca_pool or "").strip()
            if pool.startswith("projects/"):
                required = []
            error = handler_config_check(self.logger, self, required)

        if not error:
            try:
                self._credentials_resolve()
            except RuntimeError as err:
                error = str(err)
                self.logger.error("Configuration error: %s", error)

        self.logger.debug("CAhandler._config_check() ended with %s", error)
        return error

    def _config_load(self) -> None:
        """load config from file"""
        self.logger.debug("CAhandler._config_load()")

        config_dic = load_config(self.logger, "CAhandler")
        if "CAhandler" in config_dic:
            self.project = config_dic.get("CAhandler", "project", fallback=self.project)
            self.location = config_dic.get(
                "CAhandler", "location", fallback=self.location
            )
            self.ca_pool = config_dic.get("CAhandler", "ca_pool", fallback=self.ca_pool)
            self.issuing_certificate_authority_id = (
                config_dic.get(
                    "CAhandler",
                    "issuing_certificate_authority_id",
                    fallback=self.issuing_certificate_authority_id,
                )
                or None
            )
            self.certificate_template = (
                config_dic.get(
                    "CAhandler",
                    "certificate_template",
                    fallback=self.certificate_template,
                )
                or None
            )
            self.endpoint_url = (
                config_dic.get("CAhandler", "endpoint_url", fallback=self.endpoint_url)
                or None
            )

            self.credentials_file = config_option_load(
                self.logger,
                config_dic,
                "credentials_file",
                current=self.credentials_file,
            )
            self.access_token = config_option_load(
                self.logger,
                config_dic,
                "access_token",
                current=self.access_token,
            )

            self.lifetime_days = config_number_load(
                self.logger,
                config_dic,
                "lifetime_days",
                cast=int,
                current=self.lifetime_days,
            )
            self.request_timeout = config_number_load(
                self.logger,
                config_dic,
                "request_timeout",
                cast=int,
                current=self.request_timeout,
            )
            self.request_retries = config_number_load(
                self.logger,
                config_dic,
                "request_retries",
                cast=int,
                current=self.request_retries,
            )

            self.ca_bundle = config_ca_bundle_load(
                self.logger, config_dic, current=self.ca_bundle
            )
            self.verify = config_dic.getboolean(
                "CAhandler", "verify", fallback=self.verify
            )
            self._security_configuration_warnings_log()

        # Standard GCP env hints when config did not set credentials
        if not self.credentials_file:
            self.credentials_file = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS")
        if not self.access_token:
            self.access_token = os.environ.get("GOOGLE_CAS_ACCESS_TOKEN")

        self.eab_profiling, self.eab_handler = config_eab_profile_load(
            self.logger, config_dic
        )
        self.profiles = config_profile_load(self.logger, config_dic)
        self.header_info_field = config_headerinfo_load(self.logger, config_dic)
        (
            self.enrollment_config_log,
            self.enrollment_config_log_skip_list,
        ) = config_enroll_config_log_load(self.logger, config_dic)
        self.proxy = config_proxy_load(self.logger, config_dic, self._service_url())

        self.logger.debug("CAhandler._config_load() ended")

    def _security_configuration_warnings_log(self) -> None:
        """Log non-blocking security risk warnings."""
        self.logger.debug("CAhandler._security_configuration_warnings_log()")
        if self.verify is False or self.ca_bundle is False:
            self.logger.warning(
                "TLS certificate verification is disabled "
                "(verify=%s, ca_bundle=%s). Private CAS / endpoint_url traffic "
                "is vulnerable to MITM. Prefer ca_bundle / system trust.",
                self.verify,
                self.ca_bundle,
            )
        self.logger.debug("CAhandler._security_configuration_warnings_log() ended")

    def _tls_verify(self):
        """Return requests verify argument for Private CAS HTTPS."""
        self.logger.debug("CAhandler._tls_verify()")
        if self.verify is False or self.ca_bundle is False:
            return False
        if self.ca_bundle not in (None, True, False, ""):
            return self.ca_bundle
        return True

    def _csr_pem(self, csr: str) -> str:
        """normalize ACME CSR to PEM"""
        return build_pem_file(
            self.logger, None, b64_url_recode(self.logger, csr), None, True
        )

    def _lifetime_duration(self) -> str:
        """Google Duration string for end-entity lifetime."""
        seconds = max(int(self.lifetime_days) * 86400, 60)
        return f"{seconds}s"

    def _revocation_reason(self, rev_reason: str) -> str:
        """map ACME revocation reason to Private CAS enum"""
        key = (rev_reason or "unspecified").replace("_", "").replace("-", "").lower()
        return _REV_REASON_MAP.get(key, "REVOCATION_REASON_UNSPECIFIED")

    def _api_error_message(self, code: int, content: Any) -> str:
        """Format Google API / HTTP error for callers."""
        if isinstance(content, dict):
            err = content.get("error") or {}
            if isinstance(err, dict):
                status = err.get("status") or ""
                message = err.get("message") or ""
                if status or message:
                    return f"{status}: {message}".strip(": ")
            message = content.get("message") or ""
            if message:
                return str(message)
        return f"HTTP {code}: {content}"

    def _response_content(self, response: requests.Response) -> Any:
        """Parse JSON body when possible; otherwise return raw text."""
        self.logger.debug("CAhandler._response_content()")
        try:
            return response.json() if response.text else {}
        except Exception:
            return response.text

    @staticmethod
    def _http_retryable(status_code: int) -> bool:
        return status_code in (429, 500, 502, 503, 504)

    @staticmethod
    def _api_backoff(attempt: int) -> None:
        time.sleep(min(2.0 * attempt, 5.0))

    def _api_response_process(
        self, response: requests.Response, attempt: int, attempts: int
    ) -> Optional[Dict[str, Any]]:
        """
        Interpret a Private CAS HTTP response.

        Returns the JSON body on success, None when the caller should retry,
        or raises RuntimeError for a non-retryable failure.
        """
        content = self._response_content(response)
        if response.status_code < 400:
            if not isinstance(content, dict):
                raise RuntimeError(f"Unexpected Private CAS response: {content}")
            return content

        last_error = self._api_error_message(response.status_code, content)
        if self._http_retryable(response.status_code) and attempt < attempts:
            return None
        raise RuntimeError(last_error)

    def _api_call(
        self,
        method: str,
        path: str,
        *,
        payload: Optional[Dict[str, Any]] = None,
        query: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """HTTP call against Private CAS REST; return parsed JSON body."""
        self.logger.debug("CAhandler._api_call(%s %s)", method, path)
        token = self._credentials_resolve()
        url = f"{self._service_url()}/{path.lstrip('/')}"
        if query:
            url = f"{url}?{urlencode(query)}"

        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": CONTENT_TYPE,
            "Accept": CONTENT_TYPE,
        }
        body = json.dumps(payload).encode("utf-8") if payload is not None else None

        attempts = 1 + max(self.request_retries, 0)
        last_error: Optional[str] = None
        for attempt in range(1, attempts + 1):
            try:
                response = requests.request(
                    method.upper(),
                    url,
                    data=body,
                    headers=headers,
                    timeout=self.request_timeout,
                    proxies=self.proxy or None,
                    verify=self._tls_verify(),
                )
                result = self._api_response_process(response, attempt, attempts)
                if result is None:
                    self._api_backoff(attempt)
                    continue
                self.logger.debug("CAhandler._api_call(%s %s) ended", method, path)
                return result
            except requests.RequestException as err:
                last_error = str(err)
                if attempt < attempts:
                    self._api_backoff(attempt)
                    continue
                raise RuntimeError(last_error) from err

        raise RuntimeError(last_error or "Private CAS request failed")

    def _create_certificate(self, csr_pem: str) -> Dict[str, Any]:
        """POST certificates.create and return Certificate resource."""
        self.logger.debug("CAhandler._create_certificate()")
        parent = self._parent_resource()
        query: Dict[str, str] = {}
        if self.issuing_certificate_authority_id:
            query["issuingCertificateAuthorityId"] = (
                self.issuing_certificate_authority_id
            )

        body: Dict[str, Any] = {
            "pemCsr": csr_pem,
            "lifetime": self._lifetime_duration(),
        }
        if self.certificate_template:
            body["certificateTemplate"] = self.certificate_template

        path = f"v1/{parent}/certificates"
        response = self._api_call("POST", path, payload=body, query=query or None)
        self.logger.debug(
            "CAhandler._create_certificate() ended with name=%s",
            response.get("name"),
        )
        return response

    def _get_certificate(self, name: str) -> Dict[str, Any]:
        """GET a Certificate by resource name."""
        self.logger.debug("CAhandler._get_certificate(%s)", name)
        return self._api_call("GET", f"v1/{name}")

    def _list_certificates_by_serial(self, serial_hex: str) -> List[Dict[str, Any]]:
        """List certificates filtered by serial number (hex)."""
        self.logger.debug("CAhandler._list_certificates_by_serial(%s)", serial_hex)
        parent = self._parent_resource()
        # Private CAS filter language; mock accepts serial_number="..."
        filter_expr = (
            f'certificate_description.subject_description.serial_number="{serial_hex}"'
        )
        response = self._api_call(
            "GET",
            f"v1/{parent}/certificates",
            query={"filter": filter_expr},
        )
        certs = response.get("certificates") or []
        if not isinstance(certs, list):
            return []
        return certs

    def _revoke_certificate(self, name: str, reason: str) -> Dict[str, Any]:
        """POST certificates.revoke."""
        self.logger.debug("CAhandler._revoke_certificate(%s)", name)
        return self._api_call(
            "POST",
            f"v1/{name}:revoke",
            payload={"reason": reason},
        )

    def _bundle_from_certificate(
        self, certificate: Dict[str, Any]
    ) -> Tuple[str, str, str]:
        """
        Build (cert_bundle, cert_raw_b64, poll_identifier) from a Certificate resource.
        """
        cert_pem = (certificate.get("pemCertificate") or "").strip()
        if not cert_pem:
            raise RuntimeError("Private CAS response missing pemCertificate")
        chain_parts = certificate.get("pemCertificateChain") or []
        if isinstance(chain_parts, list):
            chain_pem = "\n".join(part.strip() for part in chain_parts if part)
        else:
            chain_pem = str(chain_parts).strip()
        cert_bundle = f"{cert_pem}\n{chain_pem}" if chain_pem else cert_pem
        cert_raw = b64_encode(self.logger, cert_pem2der(cert_pem))
        poll_identifier = certificate.get("name") or ""
        return cert_bundle, cert_raw, poll_identifier

    def enroll(
        self, csr: str
    ) -> Tuple[Optional[str], Optional[str], Optional[str], Optional[str]]:
        """enroll certificate from Google Private CAS"""
        self.logger.debug("CAhandler.enroll()")

        cert_bundle = None
        error = None
        cert_raw = None
        poll_identifier = None

        error = self._config_check()
        if not error:
            error = eab_profile_header_info_check(
                self.logger, self, csr, self.profile_mapping_field
            )

        if not error:
            if self.enrollment_config_log:
                self.enrollment_config_log_skip_list.extend(
                    [
                        "enrollment_config_log_skip_list",
                        "enrollment_config_log",
                        "access_token",
                        "credentials_file",
                    ]
                )
                enrollment_config_log(
                    self.logger, self, self.enrollment_config_log_skip_list
                )

            try:
                csr_pem = self._csr_pem(csr)
                certificate = self._create_certificate(csr_pem)
                cert_bundle, cert_raw, poll_identifier = self._bundle_from_certificate(
                    certificate
                )
            except (RuntimeError, ValueError, KeyError, TypeError) as err:
                error = str(err)
                self.logger.error("Failed to enroll certificate: %s", error)

        self.logger.debug("CAhandler.enroll() ended")
        return error, cert_bundle, cert_raw, poll_identifier

    def handler_check(self):
        """check if handler is ready"""
        self.logger.debug("CAhandler.handler_check()")
        error = self._config_check()
        if not error:
            try:
                parent = self._parent_resource()
                if self.issuing_certificate_authority_id:
                    ca_id = self.issuing_certificate_authority_id
                    self._api_call(
                        "GET",
                        f"v1/{parent}/certificateAuthorities/{quote(ca_id, safe='')}",
                    )
                else:
                    # Connectivity probe when no issuing CA id is configured
                    self._api_call("GET", f"v1/{parent}/certificates")
            except RuntimeError as err:
                error = str(err)
                self.logger.error("Google CAS handler_check failed: %s", error)
        self.logger.debug("CAhandler.handler_check() ended with %s", error)
        return error

    def poll(
        self, _cert_name: str, poll_identifier: str, _csr: str
    ) -> Tuple[Optional[str], Optional[str], Optional[str], str, bool]:
        """poll / re-fetch certificate by Private CAS resource name"""
        self.logger.debug("CAhandler.poll()")

        error = None
        cert_bundle = None
        cert_raw = None
        rejected = False

        if not poll_identifier:
            error = "Missing poll_identifier (certificate resource name)."
        else:
            try:
                certificate = self._get_certificate(poll_identifier)
                cert_bundle, cert_raw, poll_identifier = self._bundle_from_certificate(
                    certificate
                )
            except (RuntimeError, KeyError, TypeError) as err:
                error = str(err)
                self.logger.error("Failed to poll certificate: %s", error)

        self.logger.debug("CAhandler.poll() ended")
        return error, cert_bundle, cert_raw, poll_identifier, rejected

    def revoke(
        self,
        certificate_raw: str,
        rev_reason: str = "unspecified",
        _rev_date: str = None,
    ) -> Tuple[int, Optional[str], Optional[str]]:
        """revoke certificate by serial → list → :revoke"""
        self.logger.debug("CAhandler.revoke()")
        if _rev_date is None:
            _rev_date = uts_to_date_utc(uts_now())

        code = None
        message = None
        detail = None

        error = self._config_check()
        if error:
            return 500, ACME_ERR_SERVER_INTERNAL, error

        cert_serial = cert_serial_get(self.logger, certificate_raw, hexformat=True)
        if not cert_serial:
            self.logger.error("Failed to get certificate serial number")
            return (
                500,
                ACME_ERR_SERVER_INTERNAL,
                "Failed to parse certificate serial",
            )

        if self.eab_profiling:
            eab_profile_revocation_check(self.logger, self, certificate_raw)

        try:
            serial_hex = str(cert_serial).lower().lstrip("0x")
            matches = self._list_certificates_by_serial(serial_hex)
            if not matches:
                raise RuntimeError(
                    f"No Private CAS certificate found for serial {serial_hex}"
                )
            name = matches[0].get("name")
            if not name:
                raise RuntimeError("Listed certificate missing name")
            self._revoke_certificate(name, self._revocation_reason(rev_reason))
            code = 200
        except RuntimeError as err:
            code = 500
            message = ACME_ERR_SERVER_INTERNAL
            detail = str(err)
            self.logger.error("Failed to revoke certificate: %s", detail)

        self.logger.debug("CAhandler.revoke() ended")
        return code, message, detail

    def trigger(self, _payload: str) -> Tuple[str, Optional[str], Optional[str]]:
        """process trigger message and return certificate"""
        self.logger.debug("CAhandler.trigger()")
        error = "Method not implemented."
        self.logger.debug("CAhandler.trigger() ended with error: %s", error)
        return error, None, None
