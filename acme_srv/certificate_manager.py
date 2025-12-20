# -*- coding: utf-8 -*-
"""Certificate Manager - Coordination Layer for Certificate Operations"""
# pylint: disable=R0913, R1705
from typing import Dict, List, Tuple, Union, Optional
from acme_srv.certificate_business_logic import CertificateBusinessLogic
from acme_srv.helper import uts_now, b64_url_recode, date_to_uts_utc, uts_to_date_utc
from acme_srv.helpers.certificates import cert_dates_get

# Import will be added when needed to avoid circular imports
# from acme_srv.certificate import CertificateConfig


class CertificateManager:
    """
    Coordination Layer for Certificate operations.

    This class orchestrates interactions between CertificateRepository and
    CertificateBusinessLogic to implement high-level certificate workflows.

    Responsibilities:
    - Coordinate Repository and BusinessLogic operations
    - Handle complex workflows that span multiple components
    - Manage error handling and logging
    - Process hooks and notifications
    - Implement transaction-like behavior

    Follows the Manager/Service pattern for workflow coordination.
    """

    def __init__(
        self,
        debug: bool = False,
        logger=None,
        err_msg_dic=None,
        repository=None,
        config=None,
    ):
        """Initialize the Certificate Manager"""
        self.debug = debug
        self.logger = logger
        self.err_msg_dic = err_msg_dic or {}

        # Use provided repository
        self.repository = repository
        self.business_logic = CertificateBusinessLogic(
            debug, logger, err_msg_dic, config
        )

        # Configuration from dataclass or defaults
        if config:
            self.cert_operations_log = config.cert_operations_log
            self.tnauthlist_support = config.tnauthlist_support
        else:
            self.cert_operations_log = None
            self.tnauthlist_support = False

    def search_certificates(
        self, key: str, value: Union[str, int], vlist: List[str] = None
    ) -> Dict[str, Union[str, List]]:
        """
        Search for certificates with business logic validation.

        Args:
            key: Database field to search by
            value: Value to search for
            vlist: Optional list of fields to return

        Returns:
            Dictionary containing search results and metadata
        """
        self.logger.debug(f"CertificateManager.search_certificates({key}={value})")

        try:
            # Perform repository search
            cert_list = self.repository.search_certificates(key, value, vlist)

            # Handle None return from repository (database error)
            if cert_list is None:
                result = {
                    "certificates": None,
                    "count": 0,
                    "total_found": 0,
                    "error": "Database error",
                }
                return result

            # For backward compatibility, don't filter by certificate validation
            # if we don't have certificate data in the search results
            if vlist and "cert" not in vlist:
                # If cert field not requested, skip validation
                processed_results = cert_list
            else:
                # Apply business logic processing only when we have cert data
                processed_results = []
                for cert in cert_list:
                    cert_data = cert.get("cert", "")
                    if not cert_data or self.business_logic.validate_certificate_data(
                        cert_data
                    ):
                        processed_results.append(cert)

            result = {
                "certificates": processed_results,
                "count": len(processed_results),
                "total_found": len(cert_list),
            }

        except Exception as err:
            self.logger.error(f"Certificate search error: {err}")
            result = {
                "certificates": [],
                "count": 0,
                "total_found": 0,
                "error": str(err),
            }

        self.logger.debug(
            f"CertificateManager.search_certificates() found {result['count']} valid certificates"
        )
        return result

    def get_certificate_info(self, certificate_name: str) -> Dict[str, str]:
        """
        Get certificate information with validation.

        Args:
            certificate_name: Name/identifier of the certificate

        Returns:
            Dictionary containing certificate information
        """
        self.logger.debug(
            f"CertificateManager.get_certificate_info({certificate_name})"
        )

        # Sanitize certificate name
        clean_name = self.business_logic.sanitize_certificate_name(certificate_name)

        # Get certificate from repository
        cert_info = self.repository.get_certificate_info(clean_name)

        if cert_info and cert_info.get("cert"):
            # Enhance with business logic extracted info
            extracted_info = self.business_logic.extract_certificate_info(
                cert_info["cert_raw"]
            )
            cert_info.update(extracted_info)

        return cert_info

    def store_certificate(
        self,
        certificate_name: str,
        csr: str,
        order_name: str = None,
        certificate_data: str = None,
        header_info: str = None,
    ) -> Tuple[bool, Optional[str]]:
        """
        Store certificate with full validation workflow.

        Args:
            certificate_name: Name for the certificate
            csr: Certificate Signing Request
            order_name: Associated order name
            certificate_data: Certificate data if available

        Returns:
            Tuple of (success, error_message)
        """
        self.logger.debug(f"CertificateManager.store_certificate({certificate_name})")

        try:
            # Sanitize certificate name
            certificate_name = self.business_logic.sanitize_certificate_name(
                certificate_name
            )

            # Prepare certificate data for storage
            cert_data = {
                "name": certificate_name,
            }

            if csr:
                cert_data["csr"] = csr

            if order_name:
                cert_data["order"] = order_name

            if header_info:
                self.logger.debug(
                    "CertificateManager.store_certificate(): store header_info with certificate"
                )
                cert_data["header_info"] = header_info

            if certificate_data:
                cert_data["cert"] = certificate_data
                cert_data["cert_raw"] = certificate_data

                # Calculate and store certificate dates
                (
                    issue_uts,
                    expire_uts,
                ) = self.business_logic.calculate_certificate_dates(certificate_data)
                cert_data["issue_uts"] = issue_uts
                cert_data["expire_uts"] = expire_uts

            # Store in repository
            success = self.repository.add_certificate(cert_data)

            if success and self.cert_operations_log and certificate_data:
                # Log certificate operation
                self.repository.store_certificate_operation_log(
                    certificate_name, "store", "success"
                )

            return (success, None if success else "Database storage failed")

        except Exception as err:
            self.logger.error(f"Certificate storage error: {err}")
            return (False, str(err))

    def update_certificate_dates(self, certificate_name: str = None) -> Tuple[int, int]:
        """
        Update certificate issue and expiry dates from certificate data.

        Args:
            certificate_name: Specific certificate to update, or None for all

        Returns:
            Tuple of (updated_count, error_count)
        """
        self.logger.debug(
            f"CertificateManager.update_certificate_dates({certificate_name})"
        )

        updated_count = 0
        error_count = 0

        try:
            if certificate_name:
                # Update specific certificate
                cert_list = [self.repository.get_certificate_info(certificate_name)]
            else:
                # Get all certificates that need date updates
                cert_list = self.repository.search_certificates(
                    "cert", "", ["name", "cert"]
                )

            if not cert_list:
                self.logger.debug("No certificates found for date update")
                return (0, 0)

            self.logger.debug(f"Got {len(cert_list)} certificates to be updated...")

            for cert in cert_list:
                if cert and cert.get("cert"):
                    try:
                        # Calculate dates using business logic
                        (
                            issue_uts,
                            expire_uts,
                        ) = self.business_logic.calculate_certificate_dates(
                            cert["cert"]
                        )

                        # Update certificate with new dates
                        update_data = {
                            "name": cert["name"],
                            "issue_uts": issue_uts,
                            "expire_uts": expire_uts,
                        }

                        if self.repository.update_certificate(update_data):
                            updated_count += 1
                        else:
                            error_count += 1

                    except Exception as err:
                        self.logger.error(
                            f"Error updating dates for certificate {cert.get('name', 'unknown')}: {err}"
                        )
                        error_count += 1

        except Exception as err:
            self.logger.critical(f"Certificate dates update failed: {err}")
            error_count += 1

        self.logger.debug(
            f"CertificateManager.update_certificate_dates() updated {updated_count}, errors {error_count}"
        )
        return (updated_count, error_count)

    def cleanup_certificates(
        self, timestamp: int = None, purge: bool = False
    ) -> Tuple[List[str], List[str]]:
        """
        Cleanup expired certificates with business logic validation.

        Args:
            timestamp: Unix timestamp for cleanup threshold (default: current time)
            purge: Whether to purge (delete) or just mark for cleanup

        Returns:
            Tuple of (field_list, report_list) indicating cleanup results
        """
        self.logger.debug(
            f"CertificateManager.cleanup_certificates(timestamp={timestamp}, purge={purge})"
        )

        field_list = [
            "id",
            "name",
            "expire_uts",
            "issue_uts",
            "cert",
            "cert_raw",
            "csr",
            "created_at",
            "order__id",
            "order__name",
        ]

        if not timestamp:
            timestamp = uts_now()

        try:
            # Perform cleanup through repository
            certificate_list = self.repository.search_expired_certificates(
                timestamp, field_list
            )

        except Exception as err:
            self.logger.error(f"Certificate cleanup error: {err}")
            certificate_list = []
            field_list = []

        report_list = []

        for certificate in certificate_list:
            try:
                to_be_cleared = self._check_invalidation(certificate, timestamp, purge)

                if to_be_cleared:
                    # update report
                    report_list.append(certificate["name"])
                    # Update certificate status in repository

                    if purge:
                        self.repository.delete_certificate(certificate["name"])
                    else:
                        data_dic = {
                            "name": certificate["name"],
                            "expire_uts": certificate["expire_uts"],
                            "issue_uts": certificate["issue_uts"],
                            "cert": f"removed by certificates.cleanup() on {uts_to_date_utc(timestamp)}",
                            "cert_raw": certificate["cert_raw"],
                        }
                        self.repository.add_certificate(data_dic)

            except Exception as err:
                self.logger.error(
                    f"Error processing certificate {certificate.get('name', 'unknown')} during cleanup: {err}"
                )

        return (field_list, report_list)

    def _check_invalidation(
        self, cert: Dict[str, str], timestamp: int, purge: bool = False
    ):
        """check if cert must be invalidated"""
        if "name" in cert:
            self.logger.debug("Certificate._check_invalidation(%s)", cert["name"])
        else:
            self.logger.debug("Certificate._check_invalidation()")

        to_be_cleared = False

        if cert and "name" in cert:
            if "cert" in cert and cert["cert"] and "removed by" in cert["cert"].lower():
                if purge:
                    # skip entries which had been cleared before cert[cert] check is needed to cover corner cases
                    to_be_cleared = True

            elif "expire_uts" in cert:
                # get expiry date from either dictionary or certificate
                to_be_cleared = self._get_expiredate(cert, timestamp, to_be_cleared)
            else:
                # this scneario should never been happen so lets be careful and not clear it
                to_be_cleared = False
        else:
            # entries without a cert-name can be to_be_cleared
            to_be_cleared = True

        if "name" in cert:
            self.logger.debug(
                "Certificate._check_invalidation(%s) ended with %s",
                cert["name"],
                to_be_cleared,
            )
        else:
            self.logger.debug(
                "Certificate._check_invalidation() ended with %s", to_be_cleared
            )

        return to_be_cleared

    def _assume_expirydate(
        self, cert: Dict[str, str], timestamp: int, to_be_cleared: bool
    ) -> bool:
        """assume expiry date"""
        self.logger.debug("Certificate._assume_expirydate()")

        if "csr" in cert and cert["csr"]:
            # cover cases for enrollments in flight
            # we assume that a CSR should turn int a cert within two weeks
            if "created_at" in cert:
                created_at_uts = date_to_uts_utc(cert["created_at"])
                if 0 < created_at_uts < timestamp - (14 * 86400):
                    to_be_cleared = True
            else:
                # this scneario should never been happen so lets be careful and not clear it
                to_be_cleared = False
        else:
            # no csr and no cert - to be cleared
            to_be_cleared = True

        self.logger.debug("Certificate._assume_expirydate() ended")
        return to_be_cleared

    def _get_expiredate(
        self, cert: Dict[str, str], timestamp: int, to_be_cleared: bool
    ) -> bool:
        """get expirey date from certificate"""
        self.logger.debug("Certificate._get_expiredate()")
        # in case cert_expiry in table is 0 try to get it from cert
        if cert["expire_uts"] == 0:
            if "cert_raw" in cert and cert["cert_raw"]:
                # get expiration from certificate
                (issue_uts, expire_uts) = cert_dates_get(self.logger, cert["cert_raw"])
                if 0 < expire_uts < timestamp:
                    # returned date is other than 0 and lower than given timestamp
                    cert["issue_uts"] = issue_uts
                    cert["expire_uts"] = expire_uts
                    to_be_cleared = True
            else:
                to_be_cleared = self._assume_expirydate(cert, timestamp, to_be_cleared)
        else:
            # expired based on expire_uts from db
            to_be_cleared = True

        self.logger.debug(
            "Certificate._expiredate_get() ended with: to_be_cleared:  %s",
            to_be_cleared,
        )
        return to_be_cleared

    def check_account_authorization(
        self, account_name: str, certificate: str
    ) -> Dict[str, str]:
        """
        Check if account has authorization for certificate.

        Args:
            account_name: Name of the account
            certificate: Certificate data

        Returns:
            Dictionary containing authorization check result
        """
        self.logger.debug(
            f"CertificateManager.check_account_authorization({account_name})"
        )

        try:
            # Encode certificate for database lookup
            encoded_cert = b64_url_recode(self.logger, certificate)

            # Check authorization through repository
            result = self.repository.get_account_check_result(
                account_name, encoded_cert
            )

            if result:
                return {"status": "authorized", "account": account_name}
            else:
                return {
                    "status": "unauthorized",
                    "error": "Account not authorized for this certificate",
                }

        except Exception as err:
            self.logger.error(f"Account authorization check error: {err}")
            return {"status": "error", "error": str(err)}

    def prepare_certificate_response(
        self, certificate: str, status_code: int = 200
    ) -> Dict[str, Union[str, int]]:
        """
        Prepare certificate response with proper formatting.

        Args:
            certificate: Certificate data
            status_code: HTTP status code

        Returns:
            Formatted response dictionary
        """
        self.logger.debug("CertificateManager.prepare_certificate_response()")

        return self.business_logic.format_certificate_response(certificate, status_code)

    def update_order_status(
        self, order_name: str, status: str, certificate_name: str = None
    ) -> bool:
        """
        Update order status with certificate association.

        Args:
            order_name: Name of the order to update
            status: New status for the order
            certificate_name: Associated certificate name

        Returns:
            True if successful, False otherwise
        """
        self.logger.debug(
            f"CertificateManager.update_order_status({order_name}, {status})"
        )

        try:
            order_data = {"name": order_name, "status": status}

            if certificate_name:
                order_data["certificate"] = certificate_name

            return self.repository.update_order(order_data)

        except Exception as err:
            self.logger.error(f"Order status update error: {err}")
            return False

    def get_certificate_by_order(self, order_name: str) -> Dict[str, str]:
        """
        Get certificate information by order name.

        Args:
            order_name: Name of the order

        Returns:
            Certificate information dictionary
        """
        self.logger.debug(f"CertificateManager.get_certificate_by_order({order_name})")

        try:
            cert_info = self.repository.get_certificate_by_order(order_name)

            if cert_info and cert_info.get("cert"):
                # Enhance with business logic extracted info
                extracted_info = self.business_logic.extract_certificate_info(
                    cert_info["cert"]
                )
                cert_info.update(extracted_info)

            return cert_info

        except Exception as err:
            self.logger.error(f"Get certificate by order error: {err}")
            return {}

    def validate_and_store_csr(
        self, order_name: str, csr: str, header_info: str = None
    ) -> Tuple[bool, str]:
        """
        Validate CSR and store it with generated certificate name.

        Args:
            order_name: Associated order name
            csr: Certificate Signing Request
            header_info: Optional header information

        Returns:
            Tuple of (success, certificate_name)
        """
        self.logger.debug(f"CertificateManager.validate_and_store_csr({order_name})")

        try:
            # Validate CSR
            (code, error, _detail) = self.business_logic.validate_csr(csr)
            if code != 200:
                self.logger.error(f"CSR validation failed: {error}")
                return (False, "")

            # Generate certificate name
            certificate_name = self.business_logic.generate_certificate_name()

            # Store certificate with CSR
            (success, error_msg) = self.store_certificate(
                certificate_name, csr, order_name, header_info=header_info
            )

            if success:
                return (True, certificate_name)
            else:
                self.logger.error(f"CSR storage failed: {error_msg}")
                return (False, certificate_name)  # Return name even on failure

        except Exception as err:
            self.logger.error(f"CSR validation and storage error: {err}")
            # Generate name even on error for consistency
            certificate_name = self.business_logic.generate_certificate_name()
            return (False, certificate_name)
