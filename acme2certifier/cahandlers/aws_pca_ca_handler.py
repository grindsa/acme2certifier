# -*- coding: utf-8 -*-
"""CA handler using AWS Private Certificate Authority (ACM PCA) via REST/SigV4."""

from __future__ import annotations

import base64
import datetime
import hashlib
import hmac
import json
import os
import time
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlparse

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

CONTENT_TYPE = "application/x-amz-json-1.1"
SERVICE = "acm-pca"

# ACME / RFC 5280 reason names -> AWS PCA RevocationReason
_REV_REASON_MAP: Dict[str, str] = {
    "unspecified": "UNSPECIFIED",
    "keycompromise": "KEY_COMPROMISE",
    "cacompromise": "CERTIFICATE_AUTHORITY_COMPROMISE",
    "affiliationchanged": "AFFILIATION_CHANGED",
    "superseded": "SUPERSEDED",
    "cessationofoperation": "CESSATION_OF_OPERATION",
    "certificatehold": "CERTIFICATE_HOLD",
    "privilegewithdrawn": "PRIVILEGE_WITHDRAWN",
    "aacompromise": "A_A_COMPROMISE",
}


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _hmac_sha256(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def _sigv4_sign(
    *,
    method: str,
    url: str,
    body: bytes,
    amz_target: str,
    region: str,
    access_key: str,
    secret_key: str,
    session_token: Optional[str] = None,
    now: Optional[datetime.datetime] = None,
) -> Dict[str, str]:
    """Build SigV4 headers for an ACM PCA JSON 1.1 request."""
    if now is None:
        now = datetime.datetime.now(datetime.timezone.utc)
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    date_stamp = now.strftime("%Y%m%d")

    parsed = urlparse(url)
    host = parsed.netloc
    canonical_uri = parsed.path or "/"

    headers_map: Dict[str, str] = {
        "content-type": CONTENT_TYPE,
        "host": host,
        "x-amz-date": amz_date,
        "x-amz-target": amz_target,
    }
    if session_token:
        headers_map["x-amz-security-token"] = session_token

    signed_header_names = sorted(headers_map.keys())
    signed_headers = ";".join(signed_header_names)
    canonical_headers = "".join(
        f"{name}:{headers_map[name]}\n" for name in signed_header_names
    )
    payload_hash = _sha256_hex(body)
    canonical_request = "\n".join(
        [
            method.upper(),
            canonical_uri,
            "",
            canonical_headers,
            signed_headers,
            payload_hash,
        ]
    )
    credential_scope = f"{date_stamp}/{region}/{SERVICE}/aws4_request"
    string_to_sign = "\n".join(
        [
            "AWS4-HMAC-SHA256",
            amz_date,
            credential_scope,
            _sha256_hex(canonical_request.encode("utf-8")),
        ]
    )
    k_date = _hmac_sha256(("AWS4" + secret_key).encode("utf-8"), date_stamp)
    k_region = hmac.new(k_date, region.encode("utf-8"), hashlib.sha256).digest()
    k_service = hmac.new(k_region, SERVICE.encode("utf-8"), hashlib.sha256).digest()
    k_signing = hmac.new(k_service, b"aws4_request", hashlib.sha256).digest()
    signature = hmac.new(
        k_signing, string_to_sign.encode("utf-8"), hashlib.sha256
    ).hexdigest()

    authorization = (
        f"AWS4-HMAC-SHA256 Credential={access_key}/{credential_scope}, "
        f"SignedHeaders={signed_headers}, Signature={signature}"
    )

    out: Dict[str, str] = {
        "Content-Type": CONTENT_TYPE,
        "Host": host,
        "X-Amz-Date": amz_date,
        "X-Amz-Target": amz_target,
        "Authorization": authorization,
        "X-Amz-Content-Sha256": payload_hash,
    }
    if session_token:
        out["X-Amz-Security-Token"] = session_token
    return out


class CAhandler:
    """AWS Private CA (ACM PCA) handler using HTTPS + SigV4 (no boto3)."""

    def __init__(self, _debug: bool = None, logger: object = None):
        self.logger = logger
        self.aws_region: Optional[str] = None
        self.certificate_authority_arn: Optional[str] = None
        self.signing_algorithm: str = "SHA256WITHRSA"
        self.template_arn: Optional[str] = None
        self.validity_days: int = 365
        self.endpoint_url: Optional[str] = None
        self.aws_access_key_id: Optional[str] = None
        self.aws_secret_access_key: Optional[str] = None
        self.aws_session_token: Optional[str] = None
        self.poll_timeout: int = 60
        self.poll_interval: float = 1.0
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
        self.profile_mapping_field = "template_arn"

    def __enter__(self):
        """Makes CAhandler a Context Manager"""
        if not self.certificate_authority_arn:
            self._config_load()
        return self

    def __exit__(self, *args):
        """close the connection at the end of the context"""

    def _service_url(self) -> str:
        """ACM PCA endpoint (regional or custom / LocalStack)."""
        if self.endpoint_url:
            return self.endpoint_url.rstrip("/")
        return f"https://acm-pca.{self.aws_region}.amazonaws.com"

    def _credentials_resolve(self) -> Tuple[str, str, Optional[str]]:
        """Return access/secret/session; placeholder keys for LocalStack-style endpoints."""
        access = self.aws_access_key_id
        secret = self.aws_secret_access_key
        token = self.aws_session_token
        if self.endpoint_url and not access and not secret:
            return "test", "test", None
        if not access or not secret:
            raise RuntimeError(
                "aws_access_key_id and aws_secret_access_key are required "
                "(or set endpoint_url for LocalStack placeholder credentials)"
            )
        return access, secret, token

    def _config_check(self) -> Optional[str]:
        """check if config is valid"""
        self.logger.debug("CAhandler._config_check()")
        error = handler_config_check(
            self.logger,
            self,
            ["aws_region", "certificate_authority_arn"],
        )
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
            self.aws_region = config_dic.get(
                "CAhandler", "aws_region", fallback=self.aws_region
            )
            self.certificate_authority_arn = config_dic.get(
                "CAhandler",
                "certificate_authority_arn",
                fallback=self.certificate_authority_arn,
            )
            self.signing_algorithm = config_dic.get(
                "CAhandler", "signing_algorithm", fallback=self.signing_algorithm
            )
            self.template_arn = (
                config_dic.get("CAhandler", "template_arn", fallback=self.template_arn)
                or None
            )
            self.endpoint_url = (
                config_dic.get("CAhandler", "endpoint_url", fallback=self.endpoint_url)
                or None
            )

            self.aws_access_key_id = config_option_load(
                self.logger,
                config_dic,
                "aws_access_key_id",
                current=self.aws_access_key_id,
            )
            self.aws_secret_access_key = config_option_load(
                self.logger,
                config_dic,
                "aws_secret_access_key",
                current=self.aws_secret_access_key,
            )
            self.aws_session_token = config_option_load(
                self.logger,
                config_dic,
                "aws_session_token",
                current=self.aws_session_token,
            )

            for attr, key, cast in (
                ("validity_days", "validity_days", int),
                ("poll_timeout", "poll_timeout", int),
                ("request_timeout", "request_timeout", int),
                ("request_retries", "request_retries", int),
            ):
                try:
                    setattr(
                        self,
                        attr,
                        cast(
                            config_dic.get(
                                "CAhandler", key, fallback=getattr(self, attr)
                            )
                        ),
                    )
                except Exception as err:
                    self.logger.error("Failed to parse %s parameter: %s", key, err)

            try:
                self.poll_interval = float(
                    config_dic.get(
                        "CAhandler", "poll_interval", fallback=self.poll_interval
                    )
                )
            except Exception as err:
                self.logger.error("Failed to parse poll_interval parameter: %s", err)

            self.ca_bundle = config_ca_bundle_load(
                self.logger, config_dic, current=self.ca_bundle
            )
            self.verify = config_dic.getboolean(
                "CAhandler", "verify", fallback=self.verify
            )
            self._security_configuration_warnings_log()

        # Standard AWS env vars when config did not set credentials
        if not self.aws_access_key_id:
            self.aws_access_key_id = os.environ.get("AWS_ACCESS_KEY_ID")
        if not self.aws_secret_access_key:
            self.aws_secret_access_key = os.environ.get("AWS_SECRET_ACCESS_KEY")
        if not self.aws_session_token:
            self.aws_session_token = os.environ.get("AWS_SESSION_TOKEN")

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
                "(verify=%s, ca_bundle=%s). ACM PCA / endpoint_url traffic "
                "is vulnerable to MITM. Prefer ca_bundle / system trust.",
                self.verify,
                self.ca_bundle,
            )
        self.logger.debug("CAhandler._security_configuration_warnings_log() ended")

    def _tls_verify(self):
        """Return requests verify argument for endpoint_url / ACM PCA HTTPS."""
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

    def _revocation_reason(self, rev_reason: str) -> str:
        """map ACME revocation reason to AWS PCA enum"""
        key = (rev_reason or "unspecified").replace("_", "").replace("-", "").lower()
        return _REV_REASON_MAP.get(key, "UNSPECIFIED")

    def _api_error_message(self, code: int, content: Any) -> str:
        """Format ACM PCA / HTTP error for callers."""
        if isinstance(content, dict):
            err_type = content.get("__type") or content.get("Code") or ""
            message = content.get("message") or content.get("Message") or ""
            if err_type or message:
                return f"{err_type}: {message}".strip(": ")
        return f"HTTP {code}: {content}"

    def _api_call(self, action: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        """POST ACMPrivateCA.<action> with SigV4; return parsed JSON body."""
        self.logger.debug("CAhandler._api_call(%s)", action)
        access, secret, token = self._credentials_resolve()
        url = self._service_url()
        body = json.dumps(payload).encode("utf-8")
        amz_target = f"ACMPrivateCA.{action}"
        headers = _sigv4_sign(
            method="POST",
            url=url,
            body=body,
            amz_target=amz_target,
            region=self.aws_region or "",
            access_key=access,
            secret_key=secret,
            session_token=token,
        )

        attempts = 1 + max(self.request_retries, 0)
        last_error: Optional[str] = None
        for attempt in range(1, attempts + 1):
            try:
                response = requests.post(
                    url,
                    data=body,
                    headers=headers,
                    timeout=self.request_timeout,
                    proxies=self.proxy or None,
                    verify=self._tls_verify(),
                )
                try:
                    content: Any = response.json() if response.text else {}
                except Exception:
                    content = response.text

                if response.status_code >= 400:
                    last_error = self._api_error_message(response.status_code, content)
                    # Retry only on transient HTTP codes
                    if (
                        response.status_code in (429, 500, 502, 503, 504)
                        and attempt < attempts
                    ):
                        time.sleep(min(2.0 * attempt, 5.0))
                        continue
                    raise RuntimeError(last_error)

                if not isinstance(content, dict):
                    raise RuntimeError(f"Unexpected ACM PCA response: {content}")
                self.logger.debug("CAhandler._api_call(%s) ended", action)
                return content
            except requests.RequestException as err:
                last_error = str(err)
                if attempt < attempts:
                    time.sleep(min(2.0 * attempt, 5.0))
                    continue
                raise RuntimeError(last_error) from err

        raise RuntimeError(last_error or "ACM PCA request failed")

    def _issue_certificate(self, csr_pem: str) -> str:
        """call IssueCertificate and return certificate ARN"""
        self.logger.debug("CAhandler._issue_certificate()")
        payload: Dict[str, Any] = {
            "CertificateAuthorityArn": self.certificate_authority_arn,
            "Csr": base64.b64encode(csr_pem.encode("utf-8")).decode("ascii"),
            "SigningAlgorithm": self.signing_algorithm,
            "Validity": {"Value": self.validity_days, "Type": "DAYS"},
        }
        if self.template_arn:
            payload["TemplateArn"] = self.template_arn

        response = self._api_call("IssueCertificate", payload)
        cert_arn = response["CertificateArn"]
        self.logger.debug("CAhandler._issue_certificate() ended with arn=%s", cert_arn)
        return cert_arn

    def _error_is_in_progress(self, err: Exception) -> bool:
        text = str(err)
        return "RequestInProgress" in text

    @staticmethod
    def _pem_blocks(pem_text: str) -> list:
        """Split a PEM blob into individual certificate blocks."""
        blocks: list = []
        if not pem_text:
            return blocks
        current: list = []
        for line in pem_text.replace("\r\n", "\n").split("\n"):
            if line.strip():
                current.append(line)
            if "-----END CERTIFICATE-----" in line:
                blocks.append("\n".join(current).strip())
                current = []
        return blocks

    def _issuing_ca_chain_pems(self) -> list:
        """
        Issuing CA certificate plus its CertificateChain (parents up to root).

        GetCertificate often returns only the intermediate; completing from
        GetCertificateAuthorityCertificate yields leaf→ICA→root for private PKI.
        """
        self.logger.debug("CAhandler._issuing_ca_chain_pems()")
        ca_resp = self._api_call(
            "GetCertificateAuthorityCertificate",
            {"CertificateAuthorityArn": self.certificate_authority_arn},
        )
        parts: list = []
        if ca_resp.get("Certificate"):
            parts.extend(self._pem_blocks(ca_resp["Certificate"].strip()))
        if ca_resp.get("CertificateChain"):
            parts.extend(self._pem_blocks(ca_resp["CertificateChain"].strip()))
        self.logger.debug(
            "CAhandler._issuing_ca_chain_pems() ended with %s cert(s)", len(parts)
        )
        return parts

    def _chain_pem_complete(self, pca_chain: str) -> str:
        """Merge GetCertificate chain with issuing-CA cert + parents; dedupe PEMs."""
        merged: list = []
        seen: set = set()
        for block in self._pem_blocks(pca_chain) + self._issuing_ca_chain_pems():
            key = block.replace(" ", "").replace("\n", "")
            if key in seen:
                continue
            seen.add(key)
            merged.append(block)
        return "\n".join(merged)

    def _get_certificate(self, certificate_arn: str) -> Tuple[str, str]:
        """poll GetCertificate until issued; return (cert_pem, full_chain_pem)"""
        self.logger.debug("CAhandler._get_certificate(%s)", certificate_arn)
        deadline = time.time() + self.poll_timeout
        last_error: Optional[str] = None

        while time.time() < deadline:
            try:
                response = self._api_call(
                    "GetCertificate",
                    {
                        "CertificateAuthorityArn": self.certificate_authority_arn,
                        "CertificateArn": certificate_arn,
                    },
                )
                cert_pem = response["Certificate"].strip()
                chain_pem = self._chain_pem_complete(
                    (response.get("CertificateChain") or "").strip()
                )
                self.logger.debug("CAhandler._get_certificate() ended")
                return cert_pem, chain_pem
            except RuntimeError as err:
                if self._error_is_in_progress(err):
                    last_error = str(err)
                    time.sleep(self.poll_interval)
                    continue
                raise
        raise TimeoutError(
            f"Timed out waiting for certificate {certificate_arn}: {last_error}"
        )

    def enroll(
        self, csr: str
    ) -> Tuple[Optional[str], Optional[str], Optional[str], Optional[str]]:
        """enroll certificate from AWS Private CA"""
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
                        "aws_access_key_id",
                        "aws_secret_access_key",
                        "aws_session_token",
                    ]
                )
                enrollment_config_log(
                    self.logger, self, self.enrollment_config_log_skip_list
                )

            try:
                csr_pem = self._csr_pem(csr)
                certificate_arn = self._issue_certificate(csr_pem)
                poll_identifier = certificate_arn
                cert_pem, chain_pem = self._get_certificate(certificate_arn)
                cert_bundle = f"{cert_pem}\n{chain_pem}" if chain_pem else cert_pem
                cert_raw = b64_encode(self.logger, cert_pem2der(cert_pem))
            except (RuntimeError, TimeoutError, ValueError, KeyError) as err:
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
                self._api_call(
                    "DescribeCertificateAuthority",
                    {"CertificateAuthorityArn": self.certificate_authority_arn},
                )
            except RuntimeError as err:
                error = str(err)
                self.logger.error("AWS PCA handler_check failed: %s", error)
        self.logger.debug("CAhandler.handler_check() ended with %s", error)
        return error

    def poll(
        self, _cert_name: str, poll_identifier: str, _csr: str
    ) -> Tuple[Optional[str], Optional[str], Optional[str], str, bool]:
        """poll status of pending certificate ARN and download certificate"""
        self.logger.debug("CAhandler.poll()")

        error = None
        cert_bundle = None
        cert_raw = None
        rejected = False

        if not poll_identifier:
            error = "Missing poll_identifier (certificate ARN)."
        else:
            try:
                cert_pem, chain_pem = self._get_certificate(poll_identifier)
                cert_bundle = f"{cert_pem}\n{chain_pem}" if chain_pem else cert_pem
                cert_raw = b64_encode(self.logger, cert_pem2der(cert_pem))
            except (RuntimeError, TimeoutError, KeyError) as err:
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
        """revoke certificate"""
        self.logger.debug("CAhandler.revoke()")
        if _rev_date is None:
            _rev_date = uts_to_date_utc(uts_now())

        code = None
        message = None
        detail = None

        error = self._config_check()
        if error:
            return 500, "urn:ietf:params:acme:error:serverInternal", error

        cert_serial = cert_serial_get(self.logger, certificate_raw, hexformat=True)
        if not cert_serial:
            self.logger.error("Failed to get certificate serial number")
            return (
                500,
                "urn:ietf:params:acme:error:serverInternal",
                "Failed to parse certificate serial",
            )

        if self.eab_profiling:
            eab_profile_revocation_check(self.logger, self, certificate_raw)

        try:
            self._api_call(
                "RevokeCertificate",
                {
                    "CertificateAuthorityArn": self.certificate_authority_arn,
                    "CertificateSerial": cert_serial.lower(),
                    "RevocationReason": self._revocation_reason(rev_reason),
                },
            )
            code = 200
        except RuntimeError as err:
            code = 500
            message = "urn:ietf:params:acme:error:serverInternal"
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
