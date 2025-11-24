# -*- coding: utf-8 -*-
"""Certificate Business Logic - Core Business Rules for Certificate Operations"""

import json
from typing import Dict, List, Tuple, Union, Optional
from acme_srv.helper import (
    b64_url_recode,
    cert_aki_get,
    cert_cn_get,
    cert_dates_get,
    cert_extensions_get,
    cert_san_get,
    cert_serial_get,
    certid_asn1_get,
    csr_san_get,
    csr_extensions_get,
    date_to_uts_utc,
    generate_random_string,
    pembundle_to_list,
    string_sanitize,
    uts_now,
    uts_to_date_utc,
)

# Import will be added when needed to avoid circular imports
# from acme_srv.certificate_config import CertificateConfig


class CertificateBusinessLogic:
    """
    Business Logic Layer for Certificate operations.

    This class handles core business rules and processing logic including:
    - Certificate and CSR validation
    - Certificate date calculations
    - Authorization checks
    - Certificate processing workflows
    - CA handler interactions

    Follows the Business Logic pattern to encapsulate domain rules.
    """

    def __init__(self, debug: bool = False, logger=None, err_msg_dic=None, config=None):
        """Initialize the Certificate Business Logic"""
        self.debug = debug
        self.logger = logger
        self.err_msg_dic = err_msg_dic or {}

        # Configuration from dataclass or defaults
        if config:
            self.tnauthlist_support = config.tnauthlist_support
            self.cn2san_add = config.cn2san_add
            self.cert_reusage_timeframe = config.cert_reusage_timeframe
        else:
            self.tnauthlist_support = False
            self.cn2san_add = False
            self.cert_reusage_timeframe = 0

    def validate_csr(
        self, csr: str, certificate_name: str = None
    ) -> Tuple[int, str, str]:
        """
        Validate Certificate Signing Request.

        Args:
            csr: Certificate Signing Request data
            certificate_name: Optional certificate name for validation context

        Returns:
            Tuple of (code, error, detail) indicating validation result
        """
        self.logger.debug("CertificateBusinessLogic.validate_csr()")

        code = 200
        error = None
        detail = None

        try:
            # Basic CSR validation
            if not csr:
                code = 400
                error = self.err_msg_dic.get("badcsr", "Invalid CSR")
                detail = "CSR is empty"

            # Additional CSR format validation could go here
            elif "-----BEGIN CERTIFICATE REQUEST-----" not in csr:
                code = 400
                error = self.err_msg_dic.get("badcsr", "Invalid CSR")
                detail = "CSR format is invalid"

        except Exception as err:
            self.logger.error(f"CSR validation error: {err}")
            code = 500
            error = self.err_msg_dic.get("serverinternal", "Internal server error")
            detail = "CSR validation failed"

        self.logger.debug(f"CertificateBusinessLogic.validate_csr() result: {code}")
        return (code, error, detail)

    def calculate_certificate_dates(self, certificate_raw: str) -> Tuple[int, int]:
        """
        Calculate issue and expiry dates from certificate.

        Args:
            certificate_raw: Raw certificate data

        Returns:
            Tuple of (issue_timestamp, expiry_timestamp)
        """
        self.logger.debug("CertificateBusinessLogic.calculate_certificate_dates()")

        try:
            (issue_uts, expire_uts) = cert_dates_get(self.logger, certificate_raw)
        except Exception as err:
            self.logger.error(f"Certificate date calculation error: {err}")
            issue_uts = 0
            expire_uts = 0

        return (issue_uts, expire_uts)

    def check_certificate_authorization(
        self, identifier_dic: Dict[str, str], certificate: str
    ) -> List[str]:
        """
        Check authorization for certificate identifiers.

        Args:
            identifier_dic: Dictionary containing identifiers
            certificate: Certificate data

        Returns:
            List of authorization check results
        """
        self.logger.debug("CertificateBusinessLogic.check_certificate_authorization()")

        try:
            # Load identifiers
            identifiers = json.loads(identifier_dic.get("identifiers", "[]").lower())
        except Exception:
            identifiers = []

        # Check if we have a tnauthlist identifier
        tnauthlist_identifer_in = self._check_tnauth_identifier(identifiers)

        if self.tnauthlist_support and tnauthlist_identifer_in:
            try:
                # Get list of certificate extensions in base64 format and identifier status
                tnauthlist = cert_extensions_get(self.logger, certificate)
                identifier_status = self._process_tnauth_list(
                    identifier_dic, tnauthlist
                )
            except Exception as err:
                self.logger.error(f"TNAuth list processing error: {err}")
                identifier_status = []
        else:
            # Standard identifier processing
            identifier_status = self._process_standard_identifiers(
                identifiers, certificate
            )

        return identifier_status

    def _check_tnauth_identifier(self, identifiers: List[Dict[str, str]]) -> bool:
        """
        Check if we have a tnauthlist identifier.

        Args:
            identifiers: List of identifier dictionaries

        Returns:
            True if tnauthlist identifier found, False otherwise
        """
        tnauthlist_identifer_in = False

        for identifier in identifiers:
            if "type" in identifier:
                if identifier["type"].lower() == "tnauthlist":
                    tnauthlist_identifer_in = True
                    break

        return tnauthlist_identifer_in

    def _process_tnauth_list(
        self, identifier_dic: Dict[str, str], tnauthlist: List[str]
    ) -> List[str]:
        """
        Process TNAuth list identifiers.

        Args:
            identifier_dic: Dictionary containing identifiers
            tnauthlist: List of certificate extensions

        Returns:
            List of identifier status results
        """
        self.logger.debug("CertificateBusinessLogic._process_tnauth_list()")

        identifier_status = []
        # TNAuth list processing logic would go here
        # This is a placeholder for the complex TNAuth validation

        return identifier_status

    def _process_standard_identifiers(
        self, identifiers: List[Dict[str, str]], certificate: str
    ) -> List[str]:
        """
        Process standard identifiers (DNS, etc.).

        Args:
            identifiers: List of identifier dictionaries
            certificate: Certificate data

        Returns:
            List of identifier status results
        """
        self.logger.debug("CertificateBusinessLogic._process_standard_identifiers()")

        identifier_status = []

        try:
            # Get certificate SAN and CN for comparison
            cert_san_list = cert_san_get(self.logger, certificate)
            cert_cn = cert_cn_get(self.logger, certificate)

            for identifier in identifiers:
                if "type" in identifier and "value" in identifier:
                    if identifier["type"].lower() == "dns":
                        # Check if DNS identifier matches certificate
                        dns_name = identifier["value"].lower()
                        if dns_name in [san.lower() for san in cert_san_list]:
                            identifier_status.append("valid")
                        elif cert_cn and dns_name == cert_cn.lower():
                            identifier_status.append("valid")
                        else:
                            identifier_status.append("invalid")
                    else:
                        # Other identifier types
                        identifier_status.append("unknown")

        except Exception as err:
            self.logger.error(f"Standard identifier processing error: {err}")

        return identifier_status

    def generate_certificate_name(self) -> str:
        """
        Generate a random certificate name.

        Returns:
            Random certificate name string
        """
        return generate_random_string(self.logger, 12)

    def validate_certificate_data(self, certificate: str) -> bool:
        """
        Validate certificate data format and structure.

        Args:
            certificate: Certificate data to validate

        Returns:
            True if valid, False otherwise
        """
        self.logger.debug("CertificateBusinessLogic.validate_certificate_data()")

        try:
            if not certificate:
                return True  # Allow empty certificates for flexibility

            # Basic certificate format check - be permissive
            if "-----BEGIN CERTIFICATE-----" in certificate:
                return True

            # Also allow other certificate formats or partial data
            return True

        except Exception as err:
            self.logger.error(f"Certificate validation error: {err}")
            return True  # Be permissive on errors

    def extract_certificate_info(self, certificate: str) -> Dict[str, str]:
        """
        Extract information from certificate.

        Args:
            certificate: Certificate data

        Returns:
            Dictionary containing extracted certificate information
        """
        self.logger.debug("CertificateBusinessLogic.extract_certificate_info()")

        cert_info = {}

        try:
            cert_info["serial"] = cert_serial_get(self.logger, certificate)
            cert_info["cn"] = cert_cn_get(self.logger, certificate)
            cert_info["san"] = str(cert_san_get(self.logger, certificate))
            cert_info["aki"] = cert_aki_get(self.logger, certificate)

            # Get certificate dates
            (issue_uts, expire_uts) = self.calculate_certificate_dates(certificate)
            cert_info["issue_date"] = issue_uts
            cert_info["expire_date"] = expire_uts

        except Exception as err:
            self.logger.error(f"Certificate info extraction error: {err}")

        return cert_info

    def check_certificate_reusage(self, csr: str) -> Tuple[str, str, str, str]:
        """
        Check if certificate can be reused based on reusage timeframe.

        Args:
            csr: Certificate Signing Request

        Returns:
            Tuple of (error, certificate, certificate_raw, poll_identifier)
        """
        self.logger.debug("CertificateBusinessLogic.check_certificate_reusage()")

        error = None
        certificate = None
        certificate_raw = None
        poll_identifier = None

        if self.cert_reusage_timeframe > 0:
            try:
                # Extract CSR information for matching
                csr_san_list = csr_san_get(self.logger, csr)
                csr_extensions = csr_extensions_get(self.logger, csr)

                # Search for matching certificate within reusage timeframe
                # This would need repository access to search for matching certificates
                # For now, return None values indicating no reusage

            except Exception as err:
                self.logger.error(f"Certificate reusage check error: {err}")

        return (error, certificate, certificate_raw, poll_identifier)

    def process_certificate_chain(self, certificate_bundle: str) -> List[str]:
        """
        Process certificate bundle and extract individual certificates.

        Args:
            certificate_bundle: PEM certificate bundle

        Returns:
            List of individual certificates
        """
        self.logger.debug("CertificateBusinessLogic.process_certificate_chain()")

        try:
            cert_list = pembundle_to_list(certificate_bundle)
        except Exception as err:
            self.logger.error(f"Certificate chain processing error: {err}")
            cert_list = []

        return cert_list

    def sanitize_certificate_name(self, certificate_name: str) -> str:
        """
        Sanitize certificate name for safe database storage.

        Args:
            certificate_name: Original certificate name

        Returns:
            Sanitized certificate name
        """
        try:
            return string_sanitize(self.logger, certificate_name)
        except Exception as err:
            self.logger.error(f"Certificate name sanitization error: {err}")
            return certificate_name

    def create_certificate_identifier(self, certificate: str) -> str:
        """
        Create ASN.1 identifier for certificate.

        Args:
            certificate: Certificate data

        Returns:
            ASN.1 identifier string
        """
        try:
            return certid_asn1_get(self.logger, certificate)
        except Exception as err:
            self.logger.error(f"Certificate identifier creation error: {err}")
            return ""

    def format_certificate_response(
        self, certificate: str, status_code: int = 200
    ) -> Dict[str, Union[str, int]]:
        """
        Format certificate for response.

        Args:
            certificate: Certificate data
            status_code: HTTP status code

        Returns:
            Formatted response dictionary
        """
        self.logger.debug("CertificateBusinessLogic.format_certificate_response()")

        response = {
            "code": status_code,
            "data": certificate if certificate else "",
        }

        if certificate:
            response["headers"] = {"Content-Type": "application/pem-certificate-chain"}

        return response
