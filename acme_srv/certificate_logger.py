# -*- coding: utf-8 -*-
"""Certificate logging functionality"""
import json
from typing import Dict, Optional
from acme_srv.helper import (
    cert_cn_get,
    cert_san_get,
    cert_serial_get,
    b64_url_recode,
    uts_to_date_utc,
)


class CertificateLogger:
    """Handles all certificate operation logging"""

    def __init__(self, logger, cert_operations_log: str, repository):
        """
        Initialize certificate logger

        Args:
            logger: Logger instance for output
            cert_operations_log: Logging format ("json", "text", or "")
            repository: Repository for database operations
        """
        self.logger = logger
        self.cert_operations_log = cert_operations_log
        self.repository = repository

    def log_certificate_issuance(
        self,
        certificate_name: str,
        certificate: str,
        order_name: str,
        cert_reusage: bool = False,
    ):
        """Log certificate issuance"""
        self.logger.debug(
            "CertificateLogger.log_certificate_issuance(%s)", certificate_name
        )

        # Lookup account name and kid
        try:
            order_dic = self.repository.order_lookup(
                "name",
                order_name,
                [
                    "id",
                    "name",
                    "account__name",
                    "account__eab_kid",
                    "profile",
                    "expires",
                    "account__contact",
                ],
            )
        except Exception as err:
            self.logger.error(
                "Database error: failed to get account information for cert issuance log: %s",
                err,
            )
            order_dic = {}

        data_dic = {
            "account_name": order_dic.get("account__name", ""),
            "account_contact": order_dic.get("account__contact", ""),
            "certificate_name": certificate_name,
            "serial_number": cert_serial_get(self.logger, certificate, hexformat=True),
            "common_name": cert_cn_get(self.logger, certificate),
            "san_list": cert_san_get(self.logger, certificate),
        }

        if cert_reusage:
            # Add cert reusage flag if set to true
            data_dic["reused"] = cert_reusage

        if order_dic.get("account__eab_kid", ""):
            # Add kid if existing
            data_dic["eab_kid"] = order_dic.get("account__eab_kid", "")

        if order_dic.get("profile", None):
            # Add profile if existing
            data_dic["profile"] = order_dic.get("profile", "")

        if order_dic.get("expires", ""):
            # add expires if existing
            data_dic["expires"] = uts_to_date_utc(order_dic.get("expires", ""))

        if self.cert_operations_log == "json":
            # Log in json format
            self._log_as_json(data_dic, "Certificate issued")
        else:
            # Log in text format
            self._log_issuance_as_text(certificate_name, data_dic)

        self.logger.debug("CertificateLogger.log_certificate_issuance() ended")

    def log_certificate_revocation(self, certificate: str, code: int):
        """Log certificate revocation"""
        self.logger.debug("CertificateLogger.log_certificate_revocation()")

        if code == 200:
            status = "successful"
        else:
            status = "failed"

        # Lookup account name and kid
        try:
            cert_dic = self.repository.certificate_lookup(
                "cert_raw",
                b64_url_recode(self.logger, certificate),
                [
                    "name",
                    "order__account__name",
                    "order__account__eab_kid",
                    "order__account__contact",
                    "order__profile",
                ],
            )
        except Exception as err:
            self.logger.error(
                "Database error: failed to get account information for cert revocation: %s",
                err,
            )
            cert_dic = {}

        # Construct log message including certificate name
        self.logger.debug(
            "CertificateLogger.log_certificate_revocation(%s)", cert_dic.get("name", "")
        )

        data_dic = {
            "account_name": cert_dic.get("order__account__name", ""),
            "account_contact": cert_dic.get("order__account__contact", ""),
            "certificate_name": cert_dic.get("name", ""),
            "serial_number": cert_serial_get(self.logger, certificate, hexformat=True),
            "common_name": cert_cn_get(self.logger, certificate),
            "profile": cert_dic.get("order__profile", ""),
            "san_list": cert_san_get(self.logger, certificate),
            "status": status,
        }

        if cert_dic.get("order__account__eab_kid", ""):
            data_dic["eab_kid"] = cert_dic.get("order__account__eab_kid")

        if self.cert_operations_log == "json":
            # Log in json format
            self._log_as_json(data_dic, "Certificate revoked")
        else:
            # Log in text format
            self._log_revocation_as_text(data_dic)

        self.logger.debug("CertificateLogger.log_certificate_revocation() ended")

    def _log_as_json(self, data_dic: Dict, operation_type: str):
        """Log data as JSON format"""
        self.logger.info(
            "%s: %s",
            operation_type,
            json.dumps(data_dic, sort_keys=True),
        )

    def _log_issuance_as_text(self, certificate_name: str, data_dic: Dict):
        """Log certificate issuance as text string"""
        log_string = f'Certificate {certificate_name} issued for account {data_dic["account_name"]} {data_dic["account_contact"]}'

        if data_dic.get("eab_kid", ""):
            log_string = log_string + f' with EAB KID {data_dic["eab_kid"]}'

        if data_dic.get("profile", ""):
            log_string = log_string + f' with Profile {data_dic["profile"]}'

        log_string = (
            log_string
            + f'. Serial: {data_dic["serial_number"]}, Common Name: {data_dic["common_name"]}, SANs: {data_dic["san_list"]}, Expires: {data_dic["expires"]}'
        )

        if data_dic.get("reused", ""):
            log_string = log_string + f' reused: {data_dic["reused"]}'

        self.logger.info(log_string)

    def _log_revocation_as_text(self, data_dic: Dict):
        """Log certificate revocation as text string"""
        log_string = f'Certificate {data_dic["certificate_name"]} revocation {data_dic["status"]} for account {data_dic["account_name"]} {data_dic["account_contact"]}'

        if data_dic.get("eab_kid", ""):
            log_string = log_string + f' with EAB KID {data_dic["eab_kid"]}'

        if data_dic.get("profile", ""):
            log_string = log_string + f' with Profile {data_dic["profile"]}'

        log_string = (
            log_string
            + f'. Serial: {data_dic["serial_number"]}, Common Name: {data_dic["common_name"]}, SANs: {data_dic["san_list"]}'
        )

        self.logger.info(log_string)
