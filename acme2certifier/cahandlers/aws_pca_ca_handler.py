# -*- coding: utf-8 -*-
"""CA handler using AWS Private Certificate Authority (ACM PCA)."""

from __future__ import annotations

import time
from typing import Any, Dict, Optional, Tuple

# pylint: disable=e0401
from acme2certifier.acme_srv.helper import (
    b64_encode,
    b64_url_recode,
    build_pem_file,
    cert_pem2der,
    cert_serial_get,
    config_eab_profile_load,
    config_enroll_config_log_load,
    config_headerinfo_load,
    config_profile_load,
    eab_profile_header_info_check,
    eab_profile_revocation_check,
    enrollment_config_log,
    handler_config_check,
    load_config,
    uts_now,
    uts_to_date_utc,
)

try:
    import boto3
    from botocore.exceptions import BotoCoreError, ClientError
except ImportError:  # pragma: no cover - exercised via handler_check / enroll
    boto3 = None
    BotoCoreError = Exception  # type: ignore[misc, assignment]
    ClientError = Exception  # type: ignore[misc, assignment]

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


class CAhandler:
    """AWS Private CA (ACM PCA) handler."""

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
        self.aws_profile: Optional[str] = None
        self.poll_timeout: int = 60
        self.poll_interval: float = 1.0
        self.request_timeout: int = 60

        self.header_info_field = False
        self.eab_handler = None
        self.eab_profiling = False
        self.enrollment_config_log = False
        self.enrollment_config_log_skip_list: list = []
        self.profiles: Dict[str, str] = {}
        self.profile_mapping_field = "template_arn"

        self._client = None

    def __enter__(self):
        """Makes CAhandler a Context Manager"""
        if not self.certificate_authority_arn:
            self._config_load()
        return self

    def __exit__(self, *args):
        """close the connection at the end of the context"""
        self._client = None

    def _boto3_available(self) -> Optional[str]:
        """return error string if boto3 is missing"""
        if boto3 is None:
            return (
                "boto3 is not installed; install with "
                "`pip install acme2certifier[aws]` or `pip install boto3`"
            )
        return None

    def _client_get(self):
        """lazy-create ACM PCA client"""
        self.logger.debug("CAhandler._client_get()")
        if self._client is not None:
            return self._client

        error = self._boto3_available()
        if error:
            raise RuntimeError(error)

        session_kwargs: Dict[str, Any] = {}
        if self.aws_profile:
            session_kwargs["profile_name"] = self.aws_profile
        if self.aws_access_key_id and self.aws_secret_access_key:
            session_kwargs["aws_access_key_id"] = self.aws_access_key_id
            session_kwargs["aws_secret_access_key"] = self.aws_secret_access_key
            if self.aws_session_token:
                session_kwargs["aws_session_token"] = self.aws_session_token

        session = boto3.Session(**session_kwargs)
        client_kwargs: Dict[str, Any] = {
            "service_name": "acm-pca",
            "region_name": self.aws_region,
        }
        if self.endpoint_url:
            client_kwargs["endpoint_url"] = self.endpoint_url
        # LocalStack / custom endpoints: dummy keys are enough when not set
        if self.endpoint_url and not self.aws_access_key_id and not self.aws_profile:
            client_kwargs["aws_access_key_id"] = "test"
            client_kwargs["aws_secret_access_key"] = "test"

        self._client = session.client(**client_kwargs)
        self.logger.debug("CAhandler._client_get() ended")
        return self._client

    def _config_check(self) -> Optional[str]:
        """check if config is valid"""
        self.logger.debug("CAhandler._config_check()")
        error = self._boto3_available()
        if not error:
            error = handler_config_check(
                self.logger,
                self,
                ["aws_region", "certificate_authority_arn"],
            )
        self.logger.debug("CAhandler._config_check() ended with %s", error)
        return error

    def _config_load(self) -> None:
        """load config from file"""
        self.logger.debug("CAhandler._config_load()")

        config_dic = load_config(self.logger, "CAhandler")
        if "CAhandler" in config_dic:
            section = config_dic["CAhandler"]
            self.aws_region = section.get("aws_region", fallback=self.aws_region)
            self.certificate_authority_arn = section.get(
                "certificate_authority_arn", fallback=self.certificate_authority_arn
            )
            self.signing_algorithm = section.get(
                "signing_algorithm", fallback=self.signing_algorithm
            )
            self.template_arn = (
                section.get("template_arn", fallback=self.template_arn) or None
            )
            self.endpoint_url = (
                section.get("endpoint_url", fallback=self.endpoint_url) or None
            )
            self.aws_access_key_id = (
                section.get("aws_access_key_id", fallback=self.aws_access_key_id)
                or None
            )
            self.aws_secret_access_key = (
                section.get(
                    "aws_secret_access_key", fallback=self.aws_secret_access_key
                )
                or None
            )
            self.aws_session_token = (
                section.get("aws_session_token", fallback=self.aws_session_token)
                or None
            )
            self.aws_profile = (
                section.get("aws_profile", fallback=self.aws_profile) or None
            )

            # credentials from environment variable names (optional)
            for attr, key in (
                ("aws_access_key_id", "aws_access_key_id_variable"),
                ("aws_secret_access_key", "aws_secret_access_key_variable"),
                ("aws_session_token", "aws_session_token_variable"),
            ):
                var_name = section.get(key, fallback=None)
                if var_name:
                    import os

                    value = os.environ.get(var_name)
                    if value:
                        setattr(self, attr, value)

            for attr, key, cast in (
                ("validity_days", "validity_days", int),
                ("poll_timeout", "poll_timeout", int),
                ("request_timeout", "request_timeout", int),
            ):
                try:
                    setattr(
                        self,
                        attr,
                        cast(section.get(key, fallback=getattr(self, attr))),
                    )
                except Exception as err:
                    self.logger.error("Failed to parse %s parameter: %s", key, err)

            try:
                self.poll_interval = float(
                    section.get("poll_interval", fallback=self.poll_interval)
                )
            except Exception as err:
                self.logger.error("Failed to parse poll_interval parameter: %s", err)

        self.eab_profiling, self.eab_handler = config_eab_profile_load(
            self.logger, config_dic
        )
        self.profiles = config_profile_load(self.logger, config_dic)
        self.header_info_field = config_headerinfo_load(self.logger, config_dic)
        (
            self.enrollment_config_log,
            self.enrollment_config_log_skip_list,
        ) = config_enroll_config_log_load(self.logger, config_dic)

        self.logger.debug("CAhandler._config_load() ended")

    def _csr_pem(self, csr: str) -> str:
        """normalize ACME CSR to PEM"""
        return build_pem_file(
            self.logger, None, b64_url_recode(self.logger, csr), None, True
        )

    def _revocation_reason(self, rev_reason: str) -> str:
        """map ACME revocation reason to AWS PCA enum"""
        key = (rev_reason or "unspecified").replace("_", "").replace("-", "").lower()
        return _REV_REASON_MAP.get(key, "UNSPECIFIED")

    def _issue_certificate(self, csr_pem: str) -> str:
        """call IssueCertificate and return certificate ARN"""
        self.logger.debug("CAhandler._issue_certificate()")
        client = self._client_get()
        kwargs: Dict[str, Any] = {
            "CertificateAuthorityArn": self.certificate_authority_arn,
            "Csr": csr_pem.encode("utf-8"),
            "SigningAlgorithm": self.signing_algorithm,
            "Validity": {"Value": self.validity_days, "Type": "DAYS"},
        }
        if self.template_arn:
            kwargs["TemplateArn"] = self.template_arn

        response = client.issue_certificate(**kwargs)
        cert_arn = response["CertificateArn"]
        self.logger.debug("CAhandler._issue_certificate() ended with arn=%s", cert_arn)
        return cert_arn

    def _get_certificate(self, certificate_arn: str) -> Tuple[str, str]:
        """poll GetCertificate until issued; return (cert_pem, chain_pem)"""
        self.logger.debug("CAhandler._get_certificate(%s)", certificate_arn)
        client = self._client_get()
        deadline = time.time() + self.poll_timeout
        last_error: Optional[str] = None

        while time.time() < deadline:
            try:
                response = client.get_certificate(
                    CertificateAuthorityArn=self.certificate_authority_arn,
                    CertificateArn=certificate_arn,
                )
                cert_pem = response["Certificate"].strip()
                chain_pem = (response.get("CertificateChain") or "").strip()
                if not chain_pem:
                    # single-level hierarchy: fetch CA cert as chain
                    ca_resp = client.get_certificate_authority_certificate(
                        CertificateAuthorityArn=self.certificate_authority_arn
                    )
                    chain_parts = [ca_resp["Certificate"].strip()]
                    if ca_resp.get("CertificateChain"):
                        chain_parts.append(ca_resp["CertificateChain"].strip())
                    chain_pem = "\n".join(p for p in chain_parts if p)
                self.logger.debug("CAhandler._get_certificate() ended")
                return cert_pem, chain_pem
            except ClientError as err:
                code = err.response.get("Error", {}).get("Code", "")
                if code in (
                    "RequestInProgressException",
                    "RequestInProgress",
                ):
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
                        "aws_secret_access_key",
                        "aws_session_token",
                        "_client",
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
            except (
                ClientError,
                BotoCoreError,
                RuntimeError,
                TimeoutError,
                ValueError,
            ) as err:
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
                client = self._client_get()
                client.describe_certificate_authority(
                    CertificateAuthorityArn=self.certificate_authority_arn
                )
            except (ClientError, BotoCoreError, RuntimeError) as err:
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
            except (ClientError, BotoCoreError, RuntimeError, TimeoutError) as err:
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
            client = self._client_get()
            client.revoke_certificate(
                CertificateAuthorityArn=self.certificate_authority_arn,
                CertificateSerial=cert_serial.lower(),
                RevocationReason=self._revocation_reason(rev_reason),
            )
            code = 200
        except (ClientError, BotoCoreError, RuntimeError) as err:
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
