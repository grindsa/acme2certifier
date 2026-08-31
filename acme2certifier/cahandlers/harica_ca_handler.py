# -*- coding: utf-8 -*-
"""CA handler for HARICA CertManager REST API"""

from __future__ import print_function

import base64
import hashlib
import hmac
import json
import re
import struct
import time
from typing import Dict, List, Optional, Tuple, Union

import requests

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
    csr_cn_lookup,
    csr_san_get,
    eab_profile_header_info_check,
    enrollment_config_log,
    error_dic_get,
    handler_config_check,
    load_config,
    parse_url,
    proxy_check,
    uts_now,
    uts_to_date_utc,
)
from acme2certifier.acme_srv.helpers.global_variables import CONFIGURATION_ERROR_DETAIL

RV_TOKEN_RE = re.compile(
    r'name="__RequestVerificationToken"\s+type="hidden"\s+value="([^"]+)"',
    re.IGNORECASE,
)
PENDING_STATUSES = frozenset({"Pending", "Ready", "Processing"})
REJECTED_STATUSES = frozenset({"Cancelled", "Canceled", "Rejected", "Denied"})


def _totp_generate(secret: str, period: int = 30, digits: int = 6) -> str:
    """Generate RFC 6238 TOTP code from a Base32 secret."""
    normalized = secret.strip().replace(" ", "").upper()
    pad = (-len(normalized)) % 8
    key = base64.b32decode(normalized + ("=" * pad), casefold=True)
    counter = int(time.time()) // period
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code_int = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(code_int % (10**digits)).zfill(digits)


class CAhandler(object):
    """HARICA CertManager handler"""

    supports_trigger = False
    profile_mapping_field = "transaction_type"

    def __init__(self, _debug: bool = None, logger: object = None):
        self.logger = logger
        self.api_url = "https://cm.harica.gr"
        self.email = None
        self.password = None
        self.totp_seed = None
        self.transaction_type = "OV"
        self.consent_same_key = True
        self.organization_id = None
        self.auto_approve = False
        self.approver_email = None
        self.approver_password = None
        self.approver_totp_seed = None
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
        self._session = requests.Session()
        self._jwt_token = None
        self._rv_token = None

    def __enter__(self):
        """Makes CAhandler a Context Manager"""
        if not self.email:
            self._config_load()
        return self

    def __exit__(self, *args):
        """Close the connection at the end of the context"""

    def _config_check(self) -> Optional[str]:
        """Check mandatory configuration parameters."""
        self.logger.debug("CAhandler._config_check()")
        error = handler_config_check(self.logger, self, ["api_url", "email", "password"])
        if not error and self.auto_approve:
            if not self.approver_email or not self.approver_password:
                error = (
                    "approver_email and approver_password are required when auto_approve is enabled"
                )
                self.logger.error("%s: %s", CONFIGURATION_ERROR_DETAIL, error)
        self.logger.debug("CAhandler._config_check() ended with: %s", error)
        return error

    def _config_proxy_load(self, config_dic) -> None:
        """Load proxy settings from configuration."""
        self.logger.debug("CAhandler._config_proxy_load()")
        if "DEFAULT" in config_dic and "proxy_server_list" in config_dic["DEFAULT"]:
            try:
                proxy_list = json.loads(config_dic["DEFAULT"]["proxy_server_list"])
                url_dic = parse_url(self.logger, self.api_url)
                if "host" in url_dic:
                    fqdn = url_dic["host"].split(":")[0]
                    proxy_server = proxy_check(self.logger, fqdn, proxy_list)
                    self.proxy = {"http": proxy_server, "https": proxy_server}
            except Exception as err_:
                self.logger.warning(
                    "Failed to parse proxy_server_list from configuration: %s", err_
                )
        self.logger.debug("CAhandler._config_proxy_load() ended")

    def _config_load(self) -> None:
        """Load handler configuration."""
        self.logger.debug("CAhandler._config_load()")
        config_dic = load_config(self.logger, "CAhandler")
        if "CAhandler" in config_dic:
            self.api_url = config_dic.get(
                "CAhandler", "api_url", fallback=self.api_url
            ).rstrip("/")
            self.email = config_dic.get("CAhandler", "email", fallback=self.email)
            self.password = config_dic.get(
                "CAhandler", "password", fallback=self.password
            )
            self.totp_seed = config_dic.get(
                "CAhandler", "totp_seed", fallback=self.totp_seed
            )
            self.transaction_type = config_dic.get(
                "CAhandler", self.profile_mapping_field, fallback=self.transaction_type
            )
            try:
                self.consent_same_key = config_dic.getboolean(
                    "CAhandler", "consent_same_key", fallback=self.consent_same_key
                )
            except Exception:
                self.consent_same_key = config_dic.get(
                    "CAhandler", "consent_same_key", fallback=str(self.consent_same_key)
                ).lower() in ("true", "1", "yes")
            self.organization_id = config_dic.get(
                "CAhandler", "organization_id", fallback=self.organization_id
            )
            try:
                self.auto_approve = config_dic.getboolean(
                    "CAhandler", "auto_approve", fallback=self.auto_approve
                )
            except Exception:
                self.auto_approve = False
            self.approver_email = config_dic.get(
                "CAhandler", "approver_email", fallback=self.approver_email
            )
            self.approver_password = config_dic.get(
                "CAhandler", "approver_password", fallback=self.approver_password
            )
            self.approver_totp_seed = config_dic.get(
                "CAhandler", "approver_totp_seed", fallback=self.approver_totp_seed
            )
            try:
                self.request_timeout = int(
                    config_dic.get(
                        "CAhandler", "request_timeout", fallback=self.request_timeout
                    )
                )
            except Exception:
                self.request_timeout = 20
            try:
                self.request_retries = int(
                    config_dic.get(
                        "CAhandler", "request_retries", fallback=self.request_retries
                    )
                )
            except Exception:
                self.request_retries = 3
            try:
                self.request_retry_backoff = float(
                    config_dic.get(
                        "CAhandler",
                        "request_retry_backoff",
                        fallback=self.request_retry_backoff,
                    )
                )
            except Exception:
                self.request_retry_backoff = 2.0
            if "ca_bundle" in config_dic["CAhandler"]:
                try:
                    self.ca_bundle = config_dic.getboolean("CAhandler", "ca_bundle")
                except Exception:
                    self.ca_bundle = config_dic.get(
                        "CAhandler", "ca_bundle", fallback=self.ca_bundle
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
        self._config_proxy_load(config_dic)
        self.logger.debug("CAhandler._config_load() ended")

    def _csr_check(self, csr: str) -> Optional[str]:
        """Validate CSR against profiling rules."""
        self.logger.debug("CAhandler._csr_check()")
        error = eab_profile_header_info_check(
            self.logger, self, csr, self.profile_mapping_field
        )
        self.logger.debug("CAhandler._csr_check() ended with: %s", error)
        return error

    def _fetch_rv_token(self) -> None:
        """Fetch CSRF token from CertManager landing page."""
        self.logger.debug("CAhandler._fetch_rv_token()")
        response = self._session.get(
            f"{self.api_url}/",
            timeout=self.request_timeout,
            verify=self.ca_bundle,
            proxies=self.proxy,
        )
        response.raise_for_status()
        match = RV_TOKEN_RE.search(response.text)
        if not match:
            raise ValueError("RequestVerificationToken not found in CertManager HTML")
        self._rv_token = match.group(1)
        self._session.cookies.set("HARICA", self._rv_token)
        self.logger.debug("CAhandler._fetch_rv_token() ended")

    def _login(
        self,
        email: str,
        password: str,
        totp_seed: Optional[str] = None,
    ) -> None:
        """Authenticate against CertManager and store JWT."""
        self.logger.debug("CAhandler._login()")
        self._fetch_rv_token()
        login_payload: Dict[str, str] = {"email": email, "password": password}
        endpoint = "/api/User/Login"
        if totp_seed:
            login_payload["token"] = _totp_generate(totp_seed)
            endpoint = "/api/User/Login2FA"
        headers = {
            "RequestVerificationToken": self._rv_token,
            "Content-Type": "application/json",
        }
        response = self._session.post(
            f"{self.api_url}{endpoint}",
            json=login_payload,
            headers=headers,
            timeout=self.request_timeout,
            verify=self.ca_bundle,
            proxies=self.proxy,
        )
        if response.status_code not in (200, 201):
            raise PermissionError(
                f"HARICA login failed ({response.status_code}): {response.text}"
            )
        token = response.text.strip().strip('"')
        if not token:
            raise PermissionError("HARICA login returned empty JWT token")
        self._jwt_token = token
        self._session.headers.update(
            {
                "Authorization": self._jwt_token,
                "RequestVerificationToken": self._rv_token,
            }
        )
        self.logger.debug("CAhandler._login() ended")

    def _api_post_json(
        self, endpoint: str, payload: Union[Dict, List]
    ) -> Tuple[int, Union[Dict, List, str, None]]:
        """POST JSON to CertManager API."""
        self.logger.debug("CAhandler._api_post_json(%s)", endpoint)
        if not self._jwt_token:
            raise PermissionError("Not logged in to HARICA CertManager")
        self._fetch_rv_token()
        headers = {
            "Authorization": self._jwt_token,
            "RequestVerificationToken": self._rv_token,
            "Content-Type": "application/json",
        }
        response = self._session.post(
            f"{self.api_url}{endpoint}",
            json=payload,
            headers=headers,
            timeout=self.request_timeout,
            verify=self.ca_bundle,
            proxies=self.proxy,
        )
        code = response.status_code
        if not response.text:
            return code, None
        try:
            return code, response.json()
        except ValueError:
            return code, response.text

    def _api_post_multipart(
        self, endpoint: str, form_data: Dict[str, Tuple[None, str]]
    ) -> Tuple[int, Union[Dict, str, None]]:
        """POST multipart form to CertManager API."""
        self.logger.debug("CAhandler._api_post_multipart(%s)", endpoint)
        if not self._jwt_token:
            raise PermissionError("Not logged in to HARICA CertManager")
        self._fetch_rv_token()
        headers = {
            "Authorization": self._jwt_token,
            "RequestVerificationToken": self._rv_token,
        }
        response = self._session.post(
            f"{self.api_url}{endpoint}",
            files=form_data,
            headers=headers,
            timeout=self.request_timeout,
            verify=self.ca_bundle,
            proxies=self.proxy,
        )
        code = response.status_code
        if not response.text:
            return code, None
        try:
            return code, response.json()
        except ValueError:
            return code, response.text

    def _domains_build(self, domains: List[str]) -> List[Dict[str, object]]:
        """Build domain list payload for HARICA organization lookup."""
        domains_info: List[Dict[str, object]] = []
        processed_domains = set()
        wildcard_bases = set()
        for dom in domains:
            if "*" in dom:
                wildcard_bases.add(dom.replace("*.", ""))
        for dom in domains:
            base_domain = dom.replace("www.", "")
            if base_domain in processed_domains:
                continue
            if "*" not in dom and base_domain in wildcard_bases:
                continue
            domains_info.append(
                {
                    "isWildcard": "*" in dom,
                    "domain": base_domain,
                    "includeWWW": f"www.{base_domain}" in domains,
                    "isPrevalidated": True,
                    "isValid": True,
                    "isFreeDomain": True,
                    "isFreeDomainDV": True,
                    "isFreeDomainEV": False,
                    "canRequestOV": True,
                    "canRequestEV": False,
                    "errorMessage": "",
                    "warningMessage": "",
                }
            )
            processed_domains.add(base_domain)
        return domains_info

    def _organization_dn_build(self, organization: Dict[str, str]) -> str:
        """Build organizationDN string for certificate request."""
        org_dn = f"OrganizationId:{organization.get('id')}"
        if organization.get("country"):
            org_dn += f"&C:{organization['country']}"
        if organization.get("state"):
            org_dn += f"&ST:{organization['state']}"
        if organization.get("locality"):
            org_dn += f"&L:{organization['locality']}"
        if organization.get("organizationName"):
            org_dn += f"&O:{organization['organizationName']}"
        if organization.get("organizationUnitName"):
            org_dn += f"&OU:{organization['organizationUnitName']}"
        return org_dn

    def _domains_collect(self, csr: str) -> List[str]:
        """Collect CN and SANs from CSR."""
        sans = csr_san_get(self.logger, csr)
        cn = csr_cn_lookup(self.logger, csr)
        domains = list(sans) if sans else []
        if cn and cn not in domains:
            domains.insert(0, cn)
        return domains

    def _organization_lookup(self, domains: List[str]) -> Dict[str, str]:
        """Resolve organization for domain set."""
        self.logger.debug("CAhandler._organization_lookup()")
        domains_info = self._domains_build(domains)
        code, content = self._api_post_json(
            "/api/ServerCertificate/CheckMachingOrganization", domains_info
        )
        if code not in (200, 201) or not isinstance(content, list) or not content:
            raise ValueError(f"Organization lookup failed ({code}): {content}")
        organizations = content
        if self.organization_id:
            organizations = [
                org for org in organizations if org.get("id") == self.organization_id
            ]
        if not organizations:
            raise ValueError("No matching HARICA organization for CSR domains")
        if len(organizations) > 1:
            raise ValueError("Multiple HARICA organizations match CSR domains")
        self.logger.debug("CAhandler._organization_lookup() ended")
        return organizations[0]

    def _csr_pem_get(self, csr: str) -> str:
        """Convert ACME CSR to PEM."""
        return build_pem_file(
            self.logger, None, b64_url_recode(self.logger, csr), None, True
        )

    def _certificate_request(
        self, csr_pem: str, domains: List[str], organization: Dict[str, str]
    ) -> str:
        """Submit certificate request and return transaction id."""
        self.logger.debug("CAhandler._certificate_request()")
        domains_info = self._domains_build(domains)
        domains_json = json.dumps(domains_info)
        payload = {
            "domains": (None, domains_json),
            "domainsString": (None, domains_json),
            "csr": (None, csr_pem),
            "duration": (None, "1"),
            "transactionType": (None, self.transaction_type),
            "friendlyName": (None, domains[0]),
            "isManualCSR": (None, "true"),
            "consentSameKey": (None, "true" if self.consent_same_key else "false"),
        }
        if self.transaction_type in ("OV", "EV"):
            payload["organizationDN"] = (
                None,
                self._organization_dn_build(organization),
            )
        code, content = self._api_post_multipart(
            "/api/ServerCertificate/RequestServerCertificate", payload
        )
        if code not in (200, 201) or not isinstance(content, dict) or "id" not in content:
            raise ValueError(f"Certificate request failed ({code}): {content}")
        self.logger.debug("CAhandler._certificate_request() ended")
        return content["id"]

    def _certificate_fetch(self, transaction_id: str) -> Optional[Dict]:
        """Fetch certificate details by transaction id."""
        code, content = self._api_post_json(
            "/api/OrganizationValidatorSSL/GetSSLCertificate", {"id": transaction_id}
        )
        if code == 404:
            return None
        if code not in (200, 201):
            raise ValueError(f"GetSSLCertificate failed ({code}): {content}")
        if isinstance(content, dict):
            return content
        return None

    def _transaction_status_get(self, cert_data: Dict) -> Optional[str]:
        """Extract transaction status from certificate payload."""
        for key in ("transactionStatus", "status", "transaction_status"):
            if cert_data.get(key):
                return str(cert_data[key])
        return None

    def _certificate_parse(
        self, cert_data: Dict
    ) -> Tuple[Optional[str], Optional[str]]:
        """Parse PEM bundle and base64 DER from HARICA certificate response."""
        self.logger.debug("CAhandler._certificate_parse()")
        cert_pem = cert_data.get("certificate")
        if not cert_pem or cert_pem is True:
            return None, None
        cert_bundle = cert_pem if cert_pem.endswith("\n") else f"{cert_pem}\n"
        for key in ("intermediateCertificate", "caCertificate", "chain"):
            extra = cert_data.get(key)
            if extra and isinstance(extra, str) and "BEGIN CERTIFICATE" in extra:
                cert_bundle += extra if extra.endswith("\n") else f"{extra}\n"
        cert_raw = b64_encode(self.logger, cert_pem2der(cert_pem))
        self.logger.debug("CAhandler._certificate_parse() ended")
        return cert_bundle, cert_raw

    def _approve_transaction(self, transaction_id: str) -> None:
        """Approve pending SSL request via review API."""
        self.logger.debug("CAhandler._approve_transaction()")
        payload = {
            "startIndex": 0,
            "status": "Pending",
            "filterPostDTOs": [],
        }
        code, transactions = self._api_post_json(
            "/api/OrganizationValidatorSSL/GetSSLReviewableTransactions", payload
        )
        if code not in (200, 201) or not isinstance(transactions, list):
            raise ValueError(f"GetSSLReviewableTransactions failed ({code})")
        reviews = []
        for transaction in transactions:
            if transaction.get("transactionId") != transaction_id:
                continue
            for rev in transaction.get("reviewGetDTOs", []):
                if (
                    not rev.get("isReviewed")
                    and rev.get("reviewId")
                    and "reviewValue" in rev
                ):
                    reviews.append((rev["reviewId"], rev["reviewValue"]))
        if not reviews:
            self.logger.warning(
                "No pending reviews found for transaction %s", transaction_id
            )
            return
        for review_id, review_value in reviews:
            review_payload = {
                "reviewId": (None, review_id),
                "isValid": (None, "true"),
                "informApplicant": (None, "true"),
                "reviewMessage": (None, "Approved by acme2certifier"),
                "reviewValue": (None, review_value),
            }
            rev_code, rev_content = self._api_post_multipart(
                "/api/OrganizationValidatorSSL/UpdateReviews", review_payload
            )
            if rev_code not in (200, 201):
                raise ValueError(f"UpdateReviews failed ({rev_code}): {rev_content}")
        self.logger.debug("CAhandler._approve_transaction() ended")

    def _transaction_id_by_serial(self, serial: str) -> Optional[str]:
        """Lookup HARICA transaction id by certificate serial."""
        self.logger.debug("CAhandler._transaction_id_by_serial()")
        payload = {"startIndex": 0, "status": "Completed", "filterPostDTOs": []}
        code, transactions = self._api_post_json(
            "/api/OrganizationValidatorSSL/GetSSLTransactions", payload
        )
        serial_norm = serial.lower().replace(":", "")
        if code in (200, 201) and isinstance(transactions, list):
            for item in transactions:
                for key in ("serialNumber", "serial", "certificateSerial"):
                    value = item.get(key)
                    if value and str(value).lower().replace(":", "") == serial_norm:
                        return item.get("transactionId") or item.get("id")
                txn_id = item.get("transactionId") or item.get("id")
                if txn_id:
                    cert_data = self._certificate_fetch(txn_id)
                    if cert_data:
                        cert_serial = cert_data.get("serialNumber") or cert_data.get(
                            "serial"
                        )
                        if cert_serial and str(cert_serial).lower().replace(
                            ":", ""
                        ) == serial_norm:
                            return txn_id
        code, transactions = self._api_post_json(
            "/api/ServerCertificate/GetMyTransactions", {}
        )
        if code in (200, 201) and isinstance(transactions, list):
            for item in transactions:
                txn_id = item.get("transactionId") or item.get("id")
                if not txn_id:
                    continue
                cert_data = self._certificate_fetch(txn_id)
                if not cert_data:
                    continue
                cert_serial = cert_data.get("serialNumber") or cert_data.get("serial")
                if cert_serial and str(cert_serial).lower().replace(":", "") == serial_norm:
                    return txn_id
        self.logger.debug("CAhandler._transaction_id_by_serial() ended")
        return None

    def enroll(self, csr: str) -> Tuple[Optional[str], Optional[str], Optional[str], Optional[str]]:
        """Enroll certificate via HARICA CertManager."""
        self.logger.debug("CAhandler.enroll()")
        error = self._config_check()
        cert_bundle = None
        cert_raw = None
        poll_identifier = None

        if not error:
            error = self._csr_check(csr)

        if not error:
            try:
                if self.enrollment_config_log:
                    enrollment_config_log(
                        self.logger, self, self.enrollment_config_log_skip_list
                    )
                domains = self._domains_collect(csr)
                if not domains:
                    raise ValueError("CSR contains no CN or SAN identifiers")
                csr_pem = self._csr_pem_get(csr)
                self._login(self.email, self.password, self.totp_seed)
                organization = self._organization_lookup(domains)
                poll_identifier = self._certificate_request(
                    csr_pem, domains, organization
                )
                if self.auto_approve:
                    self._login(
                        self.approver_email,
                        self.approver_password,
                        self.approver_totp_seed,
                    )
                    self._approve_transaction(poll_identifier)
                    self._login(self.email, self.password, self.totp_seed)
                cert_data = self._certificate_fetch(poll_identifier)
                if cert_data:
                    status = self._transaction_status_get(cert_data)
                    if status in REJECTED_STATUSES:
                        error = f"HARICA rejected certificate request ({status})"
                        poll_identifier = None
                    else:
                        cert_bundle, cert_raw = self._certificate_parse(cert_data)
                        if cert_bundle:
                            poll_identifier = None
            except Exception as err_:
                error = str(err_)
                self.logger.error("Certificate enrollment failed: %s", error)

        self.logger.debug("CAhandler.enroll() ended")
        return error, cert_bundle, cert_raw, poll_identifier

    def poll(
        self, _cert_name: str, poll_identifier: str, _csr: str
    ) -> Tuple[Optional[str], Optional[str], Optional[str], str, bool]:
        """Poll pending CSR and download certificate when ready."""
        self.logger.debug("CAhandler.poll()")
        error = None
        cert_bundle = None
        cert_raw = None
        rejected = False

        if not poll_identifier:
            return "Missing poll_identifier", None, None, poll_identifier, rejected

        try:
            self._login(self.email, self.password, self.totp_seed)
            cert_data = self._certificate_fetch(poll_identifier)
            if not cert_data:
                self.logger.debug("Certificate not yet available for %s", poll_identifier)
            else:
                status = self._transaction_status_get(cert_data)
                if status in REJECTED_STATUSES:
                    rejected = True
                elif status in PENDING_STATUSES or not cert_data.get("certificate"):
                    self.logger.debug("Certificate still pending (%s)", status)
                else:
                    cert_bundle, cert_raw = self._certificate_parse(cert_data)
                    if not cert_bundle:
                        error = "Certificate response did not contain PEM data"
        except Exception as err_:
            error = str(err_)
            self.logger.error("Certificate poll failed: %s", error)

        self.logger.debug("CAhandler.poll() ended")
        return error, cert_bundle, cert_raw, poll_identifier, rejected

    def revoke(
        self,
        certificate_raw: str,
        _rev_reason: str = "unspecified",
        _rev_date: str = uts_to_date_utc(uts_now()),
    ) -> Tuple[int, Optional[str], Optional[str]]:
        """Revoke certificate on HARICA CertManager."""
        self.logger.debug("CAhandler.revoke()")
        err_dic = error_dic_get(self.logger)
        code = 500
        message = err_dic.get("serverinternal")
        detail = None

        cert_serial = cert_serial_get(self.logger, certificate_raw, hexformat=True)
        if not cert_serial:
            detail = "Failed to parse certificate serial"
            self.logger.warning("Certificate revoke failed: %s", detail)
            return 400, message, detail

        try:
            error = self._config_check()
            if error:
                detail = error
                return 500, message, detail
            self._login(self.email, self.password, self.totp_seed)
            transaction_id = self._transaction_id_by_serial(cert_serial)
            if not transaction_id:
                detail = f"No HARICA transaction found for serial {cert_serial}"
                return 404, message, detail
            payload = {
                "transactionId": transaction_id,
                "name": "4.9.1.1.1.1",
                "notes": "Revoked via acme2certifier",
                "message": "",
            }
            rev_code, rev_content = self._api_post_json(
                "/api/OrganizationValidatorSSL/RevokeCertificate", payload
            )
            if rev_code in (200, 201, 204):
                code = 200
                message = None
                detail = None
            else:
                detail = f"Revoke failed ({rev_code}): {rev_content}"
        except Exception as err_:
            detail = str(err_)
            self.logger.error("Certificate revoke failed: %s", detail)

        self.logger.debug("CAhandler.revoke() ended")
        return code, message, detail

    def trigger(self, _payload: str) -> Tuple[str, Optional[str], Optional[str]]:
        """Process trigger message and return certificate."""
        self.logger.debug("CAhandler.trigger()")
        error = "Method not implemented."
        self.logger.debug("CAhandler.trigger() ended")
        return error, None, None

    def handler_check(self) -> Optional[str]:
        """Check if handler configuration is complete."""
        self.logger.debug("CAhandler.handler_check()")
        error = self._config_check()
        self.logger.debug("CAhandler.handler_check() ended with %s", error)
        return error
