# -*- coding: utf-8 -*-
"""Certificate Repository - Database operations abstraction"""

from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional, Union, Tuple
from acme_srv.db_handler import DBstore


class CertificateRepository(ABC):
    """Abstract base class for certificate repository operations."""

    @abstractmethod
    def search_certificates(
        self, key: str, value: Union[str, int], vlist: List[str] = None
    ) -> List[Dict[str, Any]]:
        """Search for certificates matching criteria."""
        pass  # pragma: no cover

    @abstractmethod
    def get_certificate_info(self, certificate_name: str) -> Dict[str, str]:
        """Get certificate information by name."""
        pass  # pragma: no cover

    @abstractmethod
    def cleanup_certificates(
        self, timestamp: int, purge: bool = False
    ) -> List[Dict[str, Any]]:
        """Cleanup old certificates."""
        pass  # pragma: no cover

    @abstractmethod
    def certificate_account_check(
        self, account_name: str, certificate: str
    ) -> Dict[str, str]:
        """Check account for certificate."""
        pass  # pragma: no cover

    @abstractmethod
    def certificate_lookup(
        self, key: str, value: str, vlist: List[str] = None
    ) -> Dict[str, Any]:
        """Lookup certificate by key/value."""
        pass  # pragma: no cover

    @abstractmethod
    def certificate_add(self, data_dic: Dict[str, Any]) -> int:
        """Add certificate to database."""
        pass  # pragma: no cover

    @abstractmethod
    def certificate_delete(self, key: str, value: Any) -> bool:
        """Delete certificate from database."""
        pass  # pragma: no cover

    @abstractmethod
    def order_lookup(
        self, key: str, value: str, vlist: List[str] = None
    ) -> Dict[str, Any]:
        """Lookup order by key/value."""
        pass  # pragma: no cover

    @abstractmethod
    def order_update(self, data_dic: Dict[str, Any]) -> bool:
        """Update order in database."""
        pass  # pragma: no cover


class DatabaseCertificateRepository(CertificateRepository):
    """Database implementation of certificate repository."""

    def __init__(self, dbstore: DBstore, logger):
        self.dbstore = dbstore
        self.logger = logger

    def search_certificates(
        self, key: str, value: Union[str, int], vlist: List[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Search certificates in the database.

        Args:
            key: Database field to search by
            value: Value to search for
            vlist: Optional list of fields to return

        Returns:
            List of certificate dictionaries matching the search criteria
        """
        self.logger.debug(f"CertificateRepository.search_certificates({key}={value})")

        try:
            if vlist:
                cert_list = self.dbstore.certificates_search(key, value, vlist)
            else:
                cert_list = self.dbstore.certificates_search(key, value)

            if not cert_list:
                cert_list = []

        except Exception as err:
            self.logger.critical(f"Database error during certificate search: {err}")
            cert_list = None

        if cert_list is not None:
            self.logger.debug(
                f"CertificateRepository.search_certificates() found {len(cert_list)} certificates"
            )
        else:
            self.logger.debug(
                "CertificateRepository.search_certificates() returned None due to database error"
            )
        return cert_list

    def get_certificate_info(self, certificate_name: str) -> Dict[str, str]:
        """
        Get certificate information from database.

        Args:
            certificate_name: Name/identifier of the certificate

        Returns:
            Dictionary containing certificate information
        """
        self.logger.debug(
            f"CertificateRepository.get_certificate_info({certificate_name})"
        )

        try:
            cert_info = self.dbstore.certificate_lookup(
                "name",
                certificate_name,
                ("name", "csr", "cert_raw", "cert", "order__name", "order__status_id"),
            )
        except Exception as err:
            self.logger.critical(f"Database error during certificate lookup: {err}")
            cert_info = {}

        if cert_info is not None and hasattr(cert_info, "__len__"):
            self.logger.debug(
                f"CertificateRepository.get_certificate_info() returned {len(cert_info)} fields"
            )
        else:
            self.logger.debug(
                "CertificateRepository.get_certificate_info() returned non-iterable or None result"
            )

        return cert_info

    def add_certificate(self, data_dic: Dict[str, str]) -> bool:
        """
        Add a new certificate to the database.

        Args:
            data_dic: Dictionary containing certificate data

        Returns:
            True if successful, False otherwise
        """
        self.logger.debug("CertificateRepository.add_certificate()")

        try:
            result = self.dbstore.certificate_add(data_dic)
        except Exception as err:
            self.logger.critical(f"Database error during certificate add: {err}")
            result = False

        self.logger.debug(f"CertificateRepository.add_certificate() result: {result}")
        return result

    def update_certificate(self, data_dic: Dict[str, str]) -> bool:
        """
        Update an existing certificate in the database.

        Args:
            data_dic: Dictionary containing certificate data to update

        Returns:
            True if successful, False otherwise
        """
        self.logger.debug("CertificateRepository.update_certificate()")

        try:
            result = self.dbstore.certificate_update(data_dic)
        except Exception as err:
            self.logger.critical(f"Database error during certificate update: {err}")
            result = False

        self.logger.debug(
            f"CertificateRepository.update_certificate() result: {result}"
        )
        return result

    def delete_certificate(self, certificate_name: str) -> bool:
        """
        Delete a certificate from the database.

        Args:
            certificate_name: Name/identifier of the certificate to delete

        Returns:
            True if successful, False otherwise
        """
        self.logger.debug(
            f"CertificateRepository.delete_certificate({certificate_name})"
        )

        try:
            result = self.dbstore.certificate_delete(certificate_name)
        except Exception as err:
            self.logger.critical(f"Database error during certificate delete: {err}")
            result = False

        self.logger.debug(
            f"CertificateRepository.delete_certificate() result: {result}"
        )
        return result

    def get_account_check_result(
        self, account_name: str, certificate: str
    ) -> Optional[Dict[str, str]]:
        """
        Check if account has access to certificate.

        Args:
            account_name: Name of the account
            certificate: Certificate data

        Returns:
            Account check result or None if error
        """
        self.logger.debug(
            f"CertificateRepository.get_account_check_result({account_name})"
        )

        try:
            result = self.dbstore.certificate_account_check(account_name, certificate)
        except Exception as err:
            self.logger.critical(f"Database error during account check: {err}")
            result = None

        return result

    def update_order(self, data_dic: Dict[str, str]) -> bool:
        """
        Update order information in database.

        Args:
            data_dic: Dictionary containing order data to update

        Returns:
            True if successful, False otherwise
        """
        self.logger.debug("CertificateRepository.update_order()")

        try:
            self.dbstore.order_update(data_dic)
            result = True
        except Exception as err:
            self.logger.critical(f"Database error during order update: {err}")
            result = False

        return result

    def get_orders_by_account(self, account_name: str) -> List[Dict[str, str]]:
        """
        Get all orders for a specific account.

        Args:
            account_name: Name of the account

        Returns:
            List of order dictionaries
        """
        self.logger.debug(
            f"CertificateRepository.get_orders_by_account({account_name})"
        )

        try:
            orders = self.dbstore.orders_search("account", account_name)
            if not orders:
                orders = []
        except Exception as err:
            self.logger.critical(f"Database error during orders search: {err}")
            orders = []

        return orders

    def cleanup_certificates(
        self, timestamp: int, purge: bool = False
    ) -> Tuple[List[str], List[str]]:
        """
        Cleanup certificates based on timestamp and purge flag.

        Args:
            timestamp: Unix timestamp for cleanup threshold
            purge: Whether to purge (delete) or just mark for cleanup

        Returns:
            Tuple of (field_list, report_list) indicating cleanup results
        """
        self.logger.debug(
            f"CertificateRepository.cleanup_certificates(timestamp={timestamp}, purge={purge})"
        )

        try:
            if purge:
                (field_list, report_list) = self.dbstore.certificates_expired_search(
                    timestamp, purge=True, report_format="csv"
                )
            else:
                (field_list, report_list) = self.dbstore.certificates_expired_search(
                    timestamp, report_format="csv"
                )
        except Exception as err:
            self.logger.critical(f"Database error during certificate cleanup: {err}")
            field_list = []
            report_list = []

        self.logger.debug(
            f"CertificateRepository.cleanup_certificates() processed {len(report_list)} certificates"
        )
        return (field_list, report_list)

    def get_certificate_by_order(self, order_name: str) -> Dict[str, str]:
        """
        Get certificate associated with an order.

        Args:
            order_name: Name of the order

        Returns:
            Certificate information dictionary
        """
        self.logger.debug(
            f"CertificateRepository.get_certificate_by_order({order_name})"
        )

        try:
            cert_info = self.dbstore.certificate_lookup("order__name", order_name)
        except Exception as err:
            self.logger.critical(
                f"Database error during certificate lookup by order: {err}"
            )
            cert_info = {}

        return cert_info

    def store_certificate_operation_log(
        self, certificate_name: str, operation: str, result: str
    ) -> bool:
        """
        Store certificate operation log entry.

        Args:
            certificate_name: Name of the certificate
            operation: Type of operation performed
            result: Result of the operation

        Returns:
            True if successful, False otherwise
        """
        self.logger.debug(
            f"CertificateRepository.store_certificate_operation_log({certificate_name}, {operation})"
        )

        try:
            log_data = {
                "certificate": certificate_name,
                "operation": operation,
                "result": result,
            }
            result = self.dbstore.cahandler_add(log_data)
        except Exception as err:
            self.logger.critical(
                f"Database error during certificate operation log: {err}"
            )
            result = False

        return result

    def certificate_account_check(
        self, account_name: str, certificate: str
    ) -> Dict[str, str]:
        """Check account for certificate."""
        self.logger.debug(
            f"DatabaseCertificateRepository.certificate_account_check({account_name})"
        )

        try:
            result = self.dbstore.certificate_account_check(account_name, certificate)
        except Exception as err:
            self.logger.critical(
                f"Database error during certificate account check: {err}"
            )
            result = None

        return result

    def certificate_lookup(
        self, key: str, value: str, vlist: List[str] = None
    ) -> Dict[str, Any]:
        """Lookup certificate by key/value."""
        self.logger.debug(
            f"DatabaseCertificateRepository.certificate_lookup({key}={value})"
        )

        try:
            if vlist:
                result = self.dbstore.certificate_lookup(key, value, vlist)
            else:
                result = self.dbstore.certificate_lookup(key, value)
        except Exception as err:
            self.logger.critical(f"Database error during certificate lookup: {err}")
            result = {}

        return result

    def certificate_add(self, data_dic: Dict[str, Any]) -> int:
        """Add certificate to database."""
        self.logger.debug(
            f"DatabaseCertificateRepository.certificate_add({data_dic.get('name', 'unknown')})"
        )

        try:
            result = self.dbstore.certificate_add(data_dic)
        except Exception as err:
            self.logger.critical(f"Database error during certificate add: {err}")
            result = None

        return result

    def certificate_delete(self, key: str, value: Any) -> bool:
        """Delete certificate from database."""
        self.logger.debug(
            f"DatabaseCertificateRepository.certificate_delete({key}={value})"
        )

        try:
            result = self.dbstore.certificate_delete(key, value)
        except Exception as err:
            self.logger.critical(f"Database error during certificate delete: {err}")
            result = False

        return result

    def order_lookup(
        self, key: str, value: str, vlist: List[str] = None
    ) -> Dict[str, Any]:
        """Lookup order by key/value."""
        self.logger.debug(f"DatabaseCertificateRepository.order_lookup({key}={value})")

        try:
            if vlist:
                result = self.dbstore.order_lookup(key, value, vlist)
            else:
                result = self.dbstore.order_lookup(key, value)
        except Exception as err:
            self.logger.critical(f"Database error during order lookup: {err}")
            result = {}

        return result

    def order_update(self, data_dic: Dict[str, Any]) -> bool:
        """Update order in database."""
        self.logger.debug(
            f"DatabaseCertificateRepository.order_update({data_dic.get('name', 'unknown')})"
        )

        try:
            result = self.dbstore.order_update(data_dic)
        except Exception as err:
            self.logger.critical(f"Database error during order update: {err}")
            result = False

        return result
