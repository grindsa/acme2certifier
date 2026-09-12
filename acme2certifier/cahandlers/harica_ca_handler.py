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
from datetime import datetime, timezone
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
    config_option_load,
    config_profile_load,
    csr_cn_lookup,
    csr_san_get,
    eab_profile_header_info_check,
    enrollment_config_log,
    error_dic_get,
    handler_config_check,
    load_config,
    config_proxy_load,
    uts_now,
    uts_to_date_utc,
)
from acme2certifier.acme_srv.helpers.global_variables import CONFIGURATION_ERROR_DETAIL

RV_TOKEN_RE = re.compile(
    r'name=["\']__RequestVerificationToken["\'][^>]*value=["\']([^"\']+)["\']',
    re.IGNORECASE,
)
PEM_CERT_BLOCK_RE = re.compile(
    r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
    re.DOTALL,
)
PENDING_STATUSES = frozenset({"Pending", "Ready", "Processing"})
REJECTED_STATUSES = frozenset({"Cancelled", "Canceled", "Rejected", "Denied"})
CONTENT_TYPE_JSON = "application/json"
BEGIN_CERTIFICATE = "BEGIN CERTIFICATE"


def totp_generate(secret: str, period: int = 30, digits: int = 6) -> str:
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
        self.requester_email = None
        self.requester_password = None
        self.requester_totp_seed = None
        self.transaction_type = "OV"
        self.consent_same_key = True
        self.organization_id = None
        self.auto_approve = False
        self.approver_email = None
        self.approver_password = None
        self.approver_totp_seed = None
        self.ca_bundle = True
        self.proxy = None
        self.request_timeout = 60
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
        if not self.requester_email:
            self._config_load()
        return self

    def __exit__(self, *args):
        """Close the connection at the end of the context"""

    def _config_check(self) -> Optional[str]:
        """Check mandatory configuration parameters."""
        self.logger.debug("CAhandler._config_check()")
        error = handler_config_check(
            self.logger,
            self,
            ["api_url", "requester_email", "requester_password"],
        )
        if not error and self.auto_approve:
            if not self.approver_email or not self.approver_password:
                error = "approver_email and approver_password are required when auto_approve is enabled"
                self.logger.error("%s: %s", CONFIGURATION_ERROR_DETAIL, error)
        self.logger.debug("CAhandler._config_check() ended with: %s", error)
        return error

    def _config_proxy_load(self, config_dic) -> None:
        """Load proxy settings from configuration."""
        self.logger.debug("CAhandler._config_proxy_load()")
        self.proxy = config_proxy_load(self.logger, config_dic, self.api_url)
        self.logger.debug("CAhandler._config_proxy_load() ended")

    def _config_bool_get(
        self,
        config_dic,
        option: str,
        fallback: Union[bool, str],
        *,
        on_error: Optional[bool] = None,
    ) -> Union[bool, str]:
        """Read a boolean CAhandler option with string/exception fallback."""
        try:
            return config_dic.getboolean("CAhandler", option, fallback=fallback)
        except Exception:
            if on_error is not None:
                return on_error
            return config_dic.get(
                "CAhandler", option, fallback=str(fallback)
            ).lower() in ("true", "1", "yes")

    def _config_int_get(self, config_dic, option: str, fallback: int) -> int:
        """Read an integer CAhandler option; keep fallback on parse errors."""
        try:
            return int(config_dic.get("CAhandler", option, fallback=fallback))
        except Exception:
            return fallback

    def _config_float_get(self, config_dic, option: str, fallback: float) -> float:
        """Read a float CAhandler option; keep fallback on parse errors."""
        try:
            return float(config_dic.get("CAhandler", option, fallback=fallback))
        except Exception:
            return fallback

    def _config_credentials_load(self, config_dic) -> None:
        """Load requester credentials and certificate profile options."""
        self.api_url = config_dic.get(
            "CAhandler", "api_url", fallback=self.api_url
        ).rstrip("/")
        self.requester_email = config_option_load(
            self.logger, config_dic, "requester_email", current=self.requester_email
        )
        self.requester_password = config_option_load(
            self.logger,
            config_dic,
            "requester_password",
            current=self.requester_password,
        )
        self.requester_totp_seed = config_option_load(
            self.logger,
            config_dic,
            "requester_totp_seed",
            current=self.requester_totp_seed,
        )
        self.transaction_type = config_dic.get(
            "CAhandler", self.profile_mapping_field, fallback=self.transaction_type
        )
        self.consent_same_key = bool(
            self._config_bool_get(config_dic, "consent_same_key", self.consent_same_key)
        )
        organization_id = config_dic.get(
            "CAhandler", "organization_id", fallback=self.organization_id
        )
        if organization_id:
            organization_id = organization_id.strip().strip("\"'")
            self.organization_id = organization_id or None
        else:
            self.organization_id = organization_id

    def _config_approver_load(self, config_dic) -> None:
        """Load optional auto-approve / approver credentials."""
        self.auto_approve = bool(
            self._config_bool_get(
                config_dic, "auto_approve", self.auto_approve, on_error=False
            )
        )
        self.approver_email = config_option_load(
            self.logger, config_dic, "approver_email", current=self.approver_email
        )
        self.approver_password = config_option_load(
            self.logger, config_dic, "approver_password", current=self.approver_password
        )
        self.approver_totp_seed = config_option_load(
            self.logger,
            config_dic,
            "approver_totp_seed",
            current=self.approver_totp_seed,
        )

    def _config_http_load(self, config_dic) -> None:
        """Load HTTP client timeouts/retries and optional CA bundle."""
        self.request_timeout = self._config_int_get(
            config_dic, "request_timeout", self.request_timeout
        )
        self.request_retries = self._config_int_get(
            config_dic, "request_retries", self.request_retries
        )
        self.request_retry_backoff = self._config_float_get(
            config_dic, "request_retry_backoff", self.request_retry_backoff
        )
        if "ca_bundle" in config_dic["CAhandler"]:
            try:
                self.ca_bundle = config_dic.getboolean("CAhandler", "ca_bundle")
            except Exception:
                # May be a filesystem path to a CA bundle file
                self.ca_bundle = config_dic.get(
                    "CAhandler", "ca_bundle", fallback=self.ca_bundle
                )

    def _config_load(self) -> None:
        """Load handler configuration."""
        self.logger.debug("CAhandler._config_load()")
        config_dic = load_config(self.logger, "CAhandler")
        if "CAhandler" in config_dic:
            self._config_credentials_load(config_dic)
            self._config_approver_load(config_dic)
            self._config_http_load(config_dic)

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
        """
        Fetch CSRF token from CertManager HTML.

        Call once before login and again after JWT login — successful login
        resets the antiforgery token (same pattern as working HARICA clients).
        Rely on Set-Cookie in the session jar; do not overwrite HARICA manually.
        """
        self.logger.debug("CAhandler._fetch_rv_token()")
        headers = {}
        if self._jwt_token:
            headers["Authorization"] = self._jwt_token
        response = self._session.get(
            f"{self.api_url}/",
            headers=headers,
            timeout=self.request_timeout,
            verify=self.ca_bundle,
            proxies=self.proxy,
        )
        response.raise_for_status()
        match = RV_TOKEN_RE.search(response.text)
        if not match:
            raise ValueError("RequestVerificationToken not found in CertManager HTML")
        self._rv_token = match.group(1)
        self._session.headers["RequestVerificationToken"] = self._rv_token
        self.logger.debug("CAhandler._fetch_rv_token() ended")

    def _auth_headers(
        self, content_type: Optional[str] = CONTENT_TYPE_JSON
    ) -> Dict[str, str]:
        """Build authenticated request headers (JWT + CSRF). Cookies come from the session jar."""
        headers = {
            "Authorization": self._jwt_token,
            "RequestVerificationToken": self._rv_token,
            "Accept": CONTENT_TYPE_JSON,
        }
        if content_type:
            headers["Content-Type"] = content_type
        return headers

    def _parse_api_response(
        self, response: requests.Response
    ) -> Tuple[int, Union[Dict, List, str, None]]:
        """Parse CertManager API response; detect login redirects."""
        code = response.status_code
        final_url = str(getattr(response, "url", "") or "")
        body = response.text or ""
        if code in (301, 302, 303, 307, 308) or "/Login" in final_url:
            raise PermissionError(
                f"HARICA API redirected to login ({code} {final_url}); "
                "session/JWT not accepted"
            )
        if body.lstrip().lower().startswith("<!doctype html") or (
            "<title>" in body and "Login" in body
        ):
            raise PermissionError(
                "HARICA API returned login HTML instead of JSON; "
                "session/JWT not accepted"
            )
        if not body:
            return code, None
        try:
            return code, response.json()
        except ValueError:
            return code, body

    def _login(
        self,
        email: str,
        password: str,
        totp_seed: Optional[str] = None,
    ) -> None:
        """Authenticate against CertManager and store JWT."""
        self.logger.debug("CAhandler._login()")
        # Pre-login CSRF (cookie jar filled via Set-Cookie on / → /Login)
        self._jwt_token = None
        self._fetch_rv_token()
        login_payload: Dict[str, str] = {"email": email, "password": password}
        endpoint = "/api/User/Login"
        if totp_seed:
            login_payload["token"] = totp_generate(totp_seed)
            endpoint = "/api/User/Login2FA"
        headers = {
            "RequestVerificationToken": self._rv_token,
            "Content-Type": CONTENT_TYPE_JSON,
            "Accept": CONTENT_TYPE_JSON,
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
        self._session.headers["Authorization"] = self._jwt_token
        # Login resets antiforgery — re-fetch with Authorization set (Münster/Nikhef pattern)
        self._fetch_rv_token()
        self.logger.debug("CAhandler._login() ended")

    def _api_post_json(
        self, endpoint: str, payload: Union[Dict, List]
    ) -> Tuple[int, Union[Dict, List, str, None]]:
        """POST JSON to CertManager API."""
        self.logger.debug("CAhandler._api_post_json(%s)", endpoint)
        if not self._jwt_token or not self._rv_token:
            raise PermissionError("Not logged in to HARICA CertManager")
        response = self._session.post(
            f"{self.api_url}{endpoint}",
            json=payload,
            headers=self._auth_headers(CONTENT_TYPE_JSON),
            timeout=self.request_timeout,
            verify=self.ca_bundle,
            proxies=self.proxy,
            allow_redirects=False,
        )
        return self._parse_api_response(response)

    def _api_post_multipart(
        self, endpoint: str, form_data: Dict[str, Tuple[None, str]]
    ) -> Tuple[int, Union[Dict, str, None]]:
        """POST multipart form to CertManager API."""
        self.logger.debug("CAhandler._api_post_multipart(%s)", endpoint)
        if not self._jwt_token or not self._rv_token:
            raise PermissionError("Not logged in to HARICA CertManager")
        response = self._session.post(
            f"{self.api_url}{endpoint}",
            files=form_data,
            headers=self._auth_headers(None),
            timeout=self.request_timeout,
            verify=self.ca_bundle,
            proxies=self.proxy,
            allow_redirects=False,
        )
        return self._parse_api_response(response)

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

    def _san_dns_name(self, san: object) -> Optional[str]:
        """
        Normalize a CSR SAN to a bare DNS name for HARICA.

        Returns None for non-strings and non-DNS SANs (IP/EMAIL).
        """
        if not isinstance(san, str):
            return None
        # csr_san_get returns "DNS:fqdn" / "IP:..." — HARICA wants bare FQDNs
        if san.startswith("DNS:"):
            name = san[4:].strip().lower()
        elif san.startswith(("IP:", "EMAIL:")):
            self.logger.warning("Skipping non-DNS SAN for HARICA SSL: %s", san)
            return None
        else:
            name = san.strip().lower()
        return name or None

    def _domains_collect(self, csr: str) -> List[str]:
        """Collect CN and SANs from CSR as bare DNS names (no DNS:/IP: prefix)."""
        domains: List[str] = []
        for san in csr_san_get(self.logger, csr) or []:
            name = self._san_dns_name(san)
            if name and name not in domains:
                domains.append(name)
        cn = csr_cn_lookup(self.logger, csr)
        if not cn:
            return domains
        cn_name = cn.strip().lower()
        if cn_name.startswith("dns:"):
            cn_name = cn_name[4:]
        if cn_name and cn_name not in domains:
            domains.insert(0, cn_name)
        return domains

    def _domain_validity_still_valid(self, validity: Optional[str]) -> Optional[bool]:
        """
        Return True if domain validation is still in force, False if expired,
        None if the validity timestamp is missing/unparseable.
        """
        if not validity:
            return None
        text = str(validity).strip()
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        try:
            # HARICA may return fractional seconds with unusual length
            if "." in text:
                head, frac = text.split(".", 1)
                digits = "".join(ch for ch in frac if ch.isdigit())
                tz = "".join(ch for ch in frac if not ch.isdigit())
                text = f"{head}.{digits[:6].ljust(6, '0')}{tz}"
            parsed = datetime.fromisoformat(text)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed > datetime.now(timezone.utc)
        except ValueError:
            self.logger.warning("Could not parse HARICA domain validity: %s", validity)
            return None

    def _domains_rows_collect(
        self, domain_rows: List[Dict]
    ) -> Tuple[List[str], Dict[str, str]]:
        """Split domain validity rows into currently valid names and expired map."""
        valid: List[str] = []
        expired: Dict[str, str] = {}
        for row in domain_rows:
            if not isinstance(row, dict):
                continue
            name = row.get("domain") or row.get("fqdn") or row.get("name")
            if not name:
                continue
            name_l = str(name).strip().lower()
            validity = row.get("validity")
            still_valid = self._domain_validity_still_valid(
                str(validity) if validity is not None else None
            )
            if still_valid is False:
                expired[name_l] = str(validity)
                self.logger.warning(
                    "HARICA enterprise domain %s validation expired (%s)",
                    name_l,
                    validity,
                )
            else:
                # valid or unknown date — keep for allowlist
                valid.append(name_l)
        return valid, expired

    def _domains_validity_rows_get(self, group_id: str) -> List[Dict]:
        """Fetch domain-validity rows for one enterprise group."""
        gcode, rows = self._api_post_json(
            "/api/OrganizationAdmin/GetDomainsValidityByGroupId",
            {"id": group_id},
        )
        if gcode not in (200, 201) or not isinstance(rows, list):
            return []
        return [r for r in rows if isinstance(r, dict)]

    def _domains_rows_from_groups(
        self, groups: List[Dict], org_id: Optional[str]
    ) -> List[Dict]:
        """Pick domain-validity rows from SearchGroups results."""
        for group in groups:
            group_id = group.get("id")
            if not group_id:
                continue
            # Prefer groups matching the resolved organization when possible
            group_org = group.get("organizationId") or group.get("organization_id")
            if org_id and group_org and group_org != org_id:
                continue
            domain_rows = self._domains_validity_rows_get(group_id)
            if domain_rows:
                return domain_rows
        # Fallback: first group only
        group_id = groups[0].get("id") if groups else None
        if group_id:
            return self._domains_validity_rows_get(group_id)
        return []

    def _domains_names_unique(self, names: List[str]) -> List[str]:
        """Deduplicate domain names while preserving order."""
        seen = set()
        unique: List[str] = []
        for name in names:
            if name not in seen:
                seen.add(name)
                unique.append(name)
        return unique

    def _domains_list_allowed(
        self, organization: Dict[str, str]
    ) -> Tuple[List[str], Dict[str, str]]:
        """
        Fetch enterprise domains allowed for SSL enrollment.

        Uses OrganizationAdmin APIs when available. Returns
        (currently_valid_domains, {expired_domain: validity_iso}).
        Empty valid+expired means the caller should skip the local check.
        """
        self.logger.debug("CAhandler._domains_list_allowed()")
        allowed: List[str] = []
        expired: Dict[str, str] = {}
        try:
            code, groups = self._api_post_json(
                "/api/OrganizationAdmin/SearchGroups", {"key": "", "value": ""}
            )
            if code not in (200, 201) or not isinstance(groups, list) or not groups:
                self.logger.debug(
                    "SearchGroups unavailable (%s); skip local domain check", code
                )
                return [], {}
            domain_rows = self._domains_rows_from_groups(groups, organization.get("id"))
            if domain_rows:
                allowed, expired = self._domains_rows_collect(domain_rows)
            elif isinstance(groups[0].get("domains"), list):
                # Fallback: group payload without per-domain validity timestamps
                for name in groups[0]["domains"]:
                    if name:
                        allowed.append(str(name).strip().lower())
        except Exception as err_:
            self.logger.warning("Could not list HARICA allowed domains: %s", err_)
            return [], {}
        unique = self._domains_names_unique(allowed)
        self.logger.debug(
            "CAhandler._domains_list_allowed() ended with %s valid, %s expired",
            len(unique),
            len(expired),
        )
        return unique, expired

    def _domain_is_allowed(self, name: str, allowed: List[str]) -> bool:
        """Return True if name is exact or under an allowed base domain."""
        name = name.lower().rstrip(".")
        for allowed_name in allowed:
            base = allowed_name.lower().rstrip(".")
            if name == base:
                return True
            if name.endswith("." + base):
                return True
            # wildcard entry *.example.com
            if base.startswith("*.") and (
                name == base[2:] or name.endswith("." + base[2:])
            ):
                return True
        return False

    def _domains_allowed_check(
        self, domains: List[str], organization: Dict[str, str]
    ) -> None:
        """Raise ValueError if CSR domains are not covered by enterprise allowlist."""
        self.logger.debug("CAhandler._domains_allowed_check()")
        allowed, expired = self._domains_list_allowed(organization)
        if not allowed and not expired:
            self.logger.debug(
                "No allowed-domain list available; skipping local domain check"
            )
            return
        expired_bases = list(expired.keys())
        rejected = [d for d in domains if not self._domain_is_allowed(d, allowed)]
        if rejected:
            expired_hits = [
                d for d in rejected if self._domain_is_allowed(d, expired_bases)
            ]
            if expired_hits:
                details = ", ".join(
                    f"{base} (expired {expired[base]})" for base in expired_bases
                )
                raise ValueError(
                    "HARICA domain validation expired for CSR domain(s) "
                    f"{expired_hits}; enterprise bases: {details}. "
                    "Re-validate the domain(s) in CertManager, then retry."
                )
            raise ValueError(
                "CSR domain(s) not allowed for HARICA enterprise: "
                f"{rejected}; allowed: {allowed}"
                + (f"; expired: {expired_bases}" if expired_bases else "")
            )
        self.logger.debug("CAhandler._domains_allowed_check() ended")

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
        if (
            code not in (200, 201)
            or not isinstance(content, dict)
            or "id" not in content
        ):
            raise ValueError(f"Certificate request failed ({code}): {content}")
        self.logger.debug("CAhandler._certificate_request() ended")
        return content["id"]

    def _certificate_fetch(self, transaction_id: str) -> Optional[Dict]:
        """Fetch certificate details by transaction id (requester session)."""
        # Documented download endpoint — OrganizationValidatorSSL/GetSSLCertificate
        # redirects to login for non-validator accounts.
        code, content = self._api_post_json(
            "/api/Certificate/GetCertificate", {"id": transaction_id}
        )
        if code == 404:
            return None
        if code not in (200, 201):
            raise ValueError(f"GetCertificate failed ({code}): {content}")
        if isinstance(content, dict):
            return content
        return None

    def _transaction_status_get(self, cert_data: Dict) -> Optional[str]:
        """Extract transaction status from certificate payload."""
        for key in ("transactionStatus", "status", "transaction_status"):
            if cert_data.get(key):
                return str(cert_data[key])
        return None

    def _pem_bundle_clean(self, pem_text: str) -> str:
        """
        Keep only PEM certificate blocks from a HARICA pemBundle.

        CertManager may prepend openssl-style subject=/issuer= lines between
        certificates; strip everything outside BEGIN/END CERTIFICATE markers.
        """
        if not pem_text or BEGIN_CERTIFICATE not in pem_text:
            return ""
        blocks = [
            match.group(0).strip() for match in PEM_CERT_BLOCK_RE.finditer(pem_text)
        ]
        if not blocks:
            return ""
        return "".join(f"{block}\n" for block in blocks)

    def _certificate_leaf_from_bundle(self, cert_bundle: str) -> Optional[str]:
        """Return the first PEM certificate block from a cleaned bundle."""
        match = PEM_CERT_BLOCK_RE.search(cert_bundle)
        return match.group(0).strip() if match else None

    def _certificate_from_pembundle(
        self, pem_bundle: str, cert_pem: object
    ) -> Tuple[str, Optional[str]]:
        """Build chain + leaf PEM from HARICA pemBundle (and optional certificate)."""
        cert_bundle = self._pem_bundle_clean(pem_bundle)
        if not cert_pem or cert_pem is True:
            leaf = self._certificate_leaf_from_bundle(cert_bundle)
        else:
            leaf = self._pem_bundle_clean(str(cert_pem)).strip() or str(cert_pem)
        return cert_bundle, leaf

    def _certificate_from_parts(
        self, cert_data: Dict, cert_pem: str
    ) -> Tuple[str, str]:
        """Build chain + leaf from certificate + optional intermediate fields."""
        leaf = self._pem_bundle_clean(cert_pem) or (
            cert_pem if cert_pem.endswith("\n") else f"{cert_pem}\n"
        )
        cert_bundle = leaf if leaf.endswith("\n") else f"{leaf}\n"
        for key in ("intermediateCertificate", "caCertificate", "chain"):
            extra = cert_data.get(key)
            if extra and isinstance(extra, str) and BEGIN_CERTIFICATE in extra:
                cleaned_extra = self._pem_bundle_clean(extra)
                if cleaned_extra:
                    cert_bundle += cleaned_extra
        return cert_bundle, leaf.strip()

    def _certificate_parse(
        self, cert_data: Dict
    ) -> Tuple[Optional[str], Optional[str]]:
        """Parse PEM bundle and base64 DER from HARICA certificate response."""
        self.logger.debug("CAhandler._certificate_parse()")
        # Prefer full chain when HARICA returns pemBundle (Münster/tcs-garr pattern)
        pem_bundle = cert_data.get("pemBundle")
        cert_pem = cert_data.get("certificate")
        if (
            pem_bundle
            and isinstance(pem_bundle, str)
            and BEGIN_CERTIFICATE in pem_bundle
        ):
            cert_bundle, leaf = self._certificate_from_pembundle(pem_bundle, cert_pem)
        elif cert_pem and cert_pem is not True and isinstance(cert_pem, str):
            cert_bundle, leaf = self._certificate_from_parts(cert_data, cert_pem)
        else:
            return None, None
        if not cert_bundle or not leaf or not isinstance(leaf, str):
            return None, None
        leaf = self._pem_bundle_clean(leaf).strip() or leaf.strip()
        cert_raw = b64_encode(self.logger, cert_pem2der(leaf))
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

    def _serial_normalize(self, serial: str) -> str:
        """Normalize certificate serial for comparison."""
        return serial.lower().replace(":", "")

    def _item_serial_match(self, item: Dict, serial_norm: str) -> Optional[str]:
        """Return transaction id if list item serial fields match."""
        for key in ("serialNumber", "serial", "certificateSerial"):
            value = item.get(key)
            if value and self._serial_normalize(str(value)) == serial_norm:
                return item.get("transactionId") or item.get("id")
        return None

    def _txn_cert_serial_match(self, txn_id: str, serial_norm: str) -> bool:
        """Return True if GetCertificate for txn_id has matching serial."""
        cert_data = self._certificate_fetch(txn_id)
        if not cert_data:
            return False
        cert_serial = cert_data.get("serialNumber") or cert_data.get("serial")
        return bool(
            cert_serial and self._serial_normalize(str(cert_serial)) == serial_norm
        )

    def _transaction_id_from_list(
        self,
        transactions: List,
        serial_norm: str,
        *,
        check_item_serial: bool,
    ) -> Optional[str]:
        """Find transaction id in a transaction list by certificate serial."""
        for item in transactions:
            if not isinstance(item, dict):
                continue
            if check_item_serial:
                matched = self._item_serial_match(item, serial_norm)
                if matched:
                    return matched
            txn_id = item.get("transactionId") or item.get("id")
            if txn_id and self._txn_cert_serial_match(txn_id, serial_norm):
                return txn_id
        return None

    def _transaction_id_by_serial(self, serial: str) -> Optional[str]:
        """Lookup HARICA transaction id by certificate serial."""
        self.logger.debug("CAhandler._transaction_id_by_serial()")
        serial_norm = self._serial_normalize(serial)

        # Requester session first — OrganizationValidatorSSL/* redirects (302) for
        # non-validator accounts (same issue as GetSSLCertificate vs GetCertificate).
        code, transactions = self._api_post_json(
            "/api/ServerCertificate/GetMyTransactions", {}
        )
        if code in (200, 201) and isinstance(transactions, list):
            found = self._transaction_id_from_list(
                transactions, serial_norm, check_item_serial=True
            )
            if found:
                return found

        try:
            payload = {"startIndex": 0, "status": "Completed", "filterPostDTOs": []}
            code, transactions = self._api_post_json(
                "/api/OrganizationValidatorSSL/GetSSLTransactions", payload
            )
            if code in (200, 201) and isinstance(transactions, list):
                found = self._transaction_id_from_list(
                    transactions, serial_norm, check_item_serial=True
                )
                if found:
                    return found
        except PermissionError as err_:
            self.logger.debug(
                "GetSSLTransactions unavailable for this session: %s", err_
            )

        self.logger.debug("CAhandler._transaction_id_by_serial() ended")
        return None

    def _enroll_auto_approve(self, poll_identifier: str) -> None:
        """Approve pending request with approver credentials, then re-login requester."""
        self._login(
            self.approver_email,
            self.approver_password,
            self.approver_totp_seed,
        )
        self._approve_transaction(poll_identifier)
        self._login(
            self.requester_email,
            self.requester_password,
            self.requester_totp_seed,
        )

    def _enroll_issued_get(
        self, poll_identifier: str
    ) -> Tuple[Optional[str], Optional[str], Optional[str], Optional[str]]:
        """
        Fetch/parse issued certificate after request (and optional approve).

        Returns (error, cert_bundle, cert_raw, poll_identifier).
        """
        cert_data = self._certificate_fetch(poll_identifier)
        if not cert_data:
            return None, None, None, poll_identifier
        status = self._transaction_status_get(cert_data)
        if status in REJECTED_STATUSES:
            return (
                f"HARICA rejected certificate request ({status})",
                None,
                None,
                None,
            )
        cert_bundle, cert_raw = self._certificate_parse(cert_data)
        if cert_bundle:
            return None, cert_bundle, cert_raw, None
        return None, None, None, poll_identifier

    def _enroll_submit(
        self, csr: str
    ) -> Tuple[Optional[str], Optional[str], Optional[str], Optional[str]]:
        """Submit CSR to HARICA and return enroll tuple (error, bundle, raw, poll_id)."""
        if self.enrollment_config_log:
            enrollment_config_log(
                self.logger, self, self.enrollment_config_log_skip_list
            )
        domains = self._domains_collect(csr)
        if not domains:
            raise ValueError("CSR contains no CN or SAN identifiers")
        csr_pem = self._csr_pem_get(csr)
        self._login(
            self.requester_email,
            self.requester_password,
            self.requester_totp_seed,
        )
        organization = self._organization_lookup(domains)
        self._domains_allowed_check(domains, organization)
        poll_identifier = self._certificate_request(csr_pem, domains, organization)
        if self.auto_approve:
            self._enroll_auto_approve(poll_identifier)
        return self._enroll_issued_get(poll_identifier)

    def enroll(
        self, csr: str
    ) -> Tuple[Optional[str], Optional[str], Optional[str], Optional[str]]:
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
                error, cert_bundle, cert_raw, poll_identifier = self._enroll_submit(csr)
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
            self._login(
                self.requester_email,
                self.requester_password,
                self.requester_totp_seed,
            )
            cert_data = self._certificate_fetch(poll_identifier)
            if not cert_data:
                self.logger.debug(
                    "Certificate not yet available for %s", poll_identifier
                )
            else:
                status = self._transaction_status_get(cert_data)
                if status in REJECTED_STATUSES:
                    rejected = True
                elif status in PENDING_STATUSES or (
                    not cert_data.get("certificate") and not cert_data.get("pemBundle")
                ):
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
            self._login(
                self.requester_email,
                self.requester_password,
                self.requester_totp_seed,
            )
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
            # Requester path — OrganizationValidatorSSL/RevokeCertificate 302s for
            # non-validator accounts (tcs-garr revoke_user_certificate).
            rev_code, rev_content = self._api_post_json(
                "/api/Certificate/RevokeCertificate", payload
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
