# -*- coding: utf-8 -*-
"""Dogtag CA handler"""
from __future__ import print_function
from typing import Tuple, Dict, Optional
import requests
from requests_pkcs12 import Pkcs12Adapter

# pylint: disable=e0401
from acme_srv.helper import (
    load_config,
    b64_decode,
    b64_encode,
    cert_pem2der,
    cert_serial_get,
    handler_config_check,
    eab_profile_header_info_check,
    config_enroll_config_log_load,
    config_profile_load,
    config_eab_profile_load,
    config_headerinfo_load,
    pkcs7_to_pem,
    enrollment_config_log,
    uts_now,
    uts_to_date_utc,
)


def update_validity_attributes(logger, data: dict, notbefore: str, notafter: str):
    """
    Update notBefore and notAfter attribute values in the profile policy set.

    Args:
        logger (logging.Logger): Logger instance for debug output.
        data (dict): Profile policy set data structure.
        notbefore (str): NotBefore date string.
        notafter (str): NotAfter date string.
    Returns:
        None
    """
    logger.debug("update_validity_attributes()")
    for policy in data.get("ProfilePolicySet", [])[0].get("policies", []):
        for attr in policy.get("def", {}).get("attributes", []):
            if attr.get("name") == "notBefore":
                # Do not log actual notBefore value (could be sensitive)
                logger.debug(
                    "update_validity_attributes(): Setting notBefore attribute value (redacted)"
                )
                attr["Value"] = notbefore
            elif attr.get("name") == "notAfter":
                # Do not log actual notAfter value (could be sensitive)
                logger.debug(
                    "update_validity_attributes(): Setting notAfter attribute value (redacted)"
                )
                attr["Value"] = notafter
    logger.debug("update_validity_attributes() ended")


def approve_profile_get(logger, nonce: str = None, request_id: str = None):
    """
    Build the approval profile data structure for a certificate request.

    Args:
        logger (logging.Logger): Logger instance for debug output.
        nonce (Optional[str]): Nonce value for the request.
        request_id (Optional[str]): Certificate request ID.
    Returns:
        dict: Approval profile data structure.
    """
    # Do not log nonce (sensitive); log only request_id
    logger.debug("approve_profile_get() called with request_id: %s", request_id)

    notbefore = uts_to_date_utc(uts_now() - 300, tformat="%Y-%m-%d %H:%M:%S")
    notafter = uts_to_date_utc(uts_now() + 365 * 24 * 3600, tformat="%Y-%m-%d %H:%M:%S")

    data = {
        "nonce": None,
        "requestId": None,
        "ProfilePolicySet": [
            {
                "policies": [
                    {
                        "id": "2",
                        "def": {
                            "name": "Validity Default",
                            "text": "This default populates a Certificate Validity to the request. The default values are Range=720 in days",
                            "attributes": [
                                {
                                    "name": "notBefore",
                                    "Value": None,
                                    "Descriptor": {
                                        "Syntax": "string",
                                        "Description": "Not Before",
                                    },
                                },
                                {
                                    "name": "notAfter",
                                    "Value": None,
                                    "Descriptor": {
                                        "Syntax": "string",
                                        "Description": "Not After",
                                    },
                                },
                            ],
                        },
                    },
                    {
                        "id": "5",
                        "def": {
                            "name": "AIA Extension Default",
                            "attributes": [
                                {
                                    "name": "authInfoAccessCritical",
                                    "Value": "false",
                                    "Descriptor": {
                                        "Syntax": "boolean",
                                        "Description": "Criticality",
                                        "DefaultValue": "false",
                                    },
                                },
                                {
                                    "name": "authInfoAccessGeneralNames",
                                    "Value": "Record #0\r\nMethod:1.3.6.1.5.5.7.48.1\r\nLocation Type:URIName\r\nLocation:http://dogtag.acme:8080/ca/ocsp\r\nEnable:true\r\n\r\n",
                                    "Descriptor": {
                                        "Syntax": "string_list",
                                        "Description": "General Names",
                                    },
                                },
                            ],
                        },
                    },
                    {
                        "id": "6",
                        "def": {
                            "name": "Key Usage Default",
                            "attributes": [
                                {
                                    "name": "keyUsageCritical",
                                    "Value": "true",
                                    "Descriptor": {
                                        "Syntax": "boolean",
                                        "Description": "Criticality",
                                        "DefaultValue": "false",
                                    },
                                },
                                {
                                    "name": "keyUsageDigitalSignature",
                                    "Value": "true",
                                    "Descriptor": {
                                        "Syntax": "boolean",
                                        "Description": "Digital Signature",
                                        "DefaultValue": "false",
                                    },
                                },
                                {
                                    "name": "keyUsageKeyEncipherment",
                                    "Value": "true",
                                    "Descriptor": {
                                        "Syntax": "boolean",
                                        "Description": "Key Encipherment",
                                        "DefaultValue": "false",
                                    },
                                },
                                {
                                    "name": "keyUsageDataEncipherment",
                                    "Value": "true",
                                    "Descriptor": {
                                        "Syntax": "boolean",
                                        "Description": "Data Encipherment",
                                        "DefaultValue": "false",
                                    },
                                },
                            ],
                        },
                        "constraint": {
                            "name": "Key Usage Extension Constraint",
                            "text": "This constraint accepts the Key Usage extension, if present, only when Criticality=true, Digital Signature=true, Non-Repudiation=false, Key Encipherment=true, Data Encipherment=true, Key Agreement=false, Key Certificate Sign=false, Key CRL Sign=false, Encipher Only=false, Decipher Only=false",
                            "classId": "KeyUsageExtConstraint",
                        },
                    },
                    {
                        "id": "7",
                        "def": {
                            "name": "Extended Key Usage Extension Default",
                            "attributes": [
                                {
                                    "name": "exKeyUsageCritical",
                                    "Value": "false",
                                },
                                {
                                    "name": "exKeyUsageOIDs",
                                    "Value": "1.3.6.1.5.5.7.3.1,1.3.6.1.5.5.7.3.2",
                                },
                            ],
                        },
                    },
                    {
                        "id": "8",
                        "def": {
                            "name": "Signing Alg",
                            "attributes": [
                                {
                                    "name": "signingAlg",
                                    "Value": "SHA256withRSA",
                                }
                            ],
                        },
                    },
                ]
            }
        ],
        "Attributes": {"Attribute": []},
    }

    data["requestId"] = request_id
    data["nonce"] = nonce

    # update notBefore and notAfter values in the profile policy set
    update_validity_attributes(logger, data, notbefore, notafter)

    logger.debug("approve_profile_get() ended")
    return data


class CAhandler(object):
    """Dogtag CA handler"""

    # Class-level constants for magic strings and numbers
    DEFAULT_PREFIX = "/ca"
    REST_AGENT_CERTREQUESTS = "/ca/rest/agent/certrequests/"
    REST_CERTREQUESTS = "/ca/rest/certrequests"
    REST_AGENT_CERTS = "/ca/rest/agent/certs/"
    REST_CERTS = "/ca/rest/certs/"
    REST_INFO = "/pki/rest/info"
    DEFAULT_REQUEST_TIMEOUT = 30
    CONFIG_SECTION = "CAhandler"

    def __init__(self, _debug: Optional[bool] = None, logger: Optional[object] = None):
        """
        Initialize the CAhandler.

        Args:
            _debug (Optional[bool]): Enable debug mode. Not currently used.
            logger (Optional[logging.Logger]): Logger instance for logging.
        """
        self.logger = logger
        self.client_cert = None
        self.client_key = None
        self.cert_passphrase = None
        self.api_host = None
        self.api_version = None
        self.ca_bundle = None
        self.certrequest_approve = False
        self.profile = None
        self.session = None
        self.header_info_field = False
        self.eab_handler = None
        self.eab_profiling = False
        self.enrollment_config_log = False
        self.enrollment_config_log_skip_list = []
        self.profiles = {}
        self.request_timeout = self.DEFAULT_REQUEST_TIMEOUT
        self.proxy = None

    def __enter__(self) -> "CAhandler":
        """
        Enter the context manager, loading configuration and logging in if needed.

        Returns:
            CAhandler: The handler instance.
        """
        if not self.api_host:
            self._config_load()
            self._login()
        return self

    def __exit__(self, *args) -> None:
        """
        Close the connection at the end of the context.

        Args:
            *args: Exception type, value, and traceback (if any).
        Returns:
            None
        """
        if self.session:
            self.session.close()
            self.session = None

    def _api_post(self, url: str, data: Dict[str, str]) -> Tuple[int, Dict[str, str]]:
        """
        Generic wrapper for an API POST call.

        Args:
            url (str): API endpoint URL (relative).
            data (Dict[str, str]): Data to send in the POST request.
        Returns:
            Tuple[int, Dict[str, str]]: HTTP status code and response content.
        """
        self.logger.debug("_api_post(%s)", url)

        if self.session is None:
            self._login()

        try:
            response = self.session.post(
                url=self.api_host + url,
                json=data,
                proxies=self.proxy,
                verify=self.ca_bundle,
                timeout=self.request_timeout,
            )
            code = response.status_code
            try:
                content = response.json()
            except Exception as err_:
                self.logger.error(
                    "Could not parse the response for an API post() request: %s", err_
                )
                content = {"error": f"Could not parse JSON: {err_}"}
        except Exception as err_:
            self.logger.error("API post() returned error: %s", err_)
            code = 500
            content = {"error": str(err_)}

        return code, content

    def _api_get(self, url: str) -> Tuple[int, Dict[str, str]]:
        """
        Get data from API via GET request.

        Args:
            url (str): API endpoint URL (relative).
        Returns:
            Tuple[int, Dict[str, str]]: HTTP status code and response content.
        """
        self.logger.debug("CAhandler._api_get()")
        headers = None

        if self.session is None:
            self._login()

        try:
            api_response = self.session.get(
                url=self.api_host + url,
                headers=headers,
                verify=self.ca_bundle,
                proxies=self.proxy,
                timeout=self.request_timeout,
            )
            code = api_response.status_code
            try:
                content = api_response.json()
            except Exception as err_:
                self.logger.error(
                    "Could not parse the response for an API get() request: %s", err_
                )
                content = {"error": f"Could not parse JSON: {err_}"}
        except Exception as err_:
            self.logger.error("API get() request returned error: %s", err_)
            code = 500
            content = {"error": str(err_)}

        return code, content

    def _api_version_get(self) -> None:
        """
        Get API version from CA and set self.api_version.
        Returns:
            None
        """
        self.logger.debug("CAhandler._api_version_get()")

        if not self.api_version:
            code, content = self._api_get(self.REST_INFO)

            if code == 200 and isinstance(content, dict):
                self.api_version = next(
                    (v for k, v in content.items() if k.lower() == "version"), "unknown"
                )
                self.logger.info("CA API version: %s", self.api_version)
            else:
                self.logger.error(
                    "Failed to get CA API version. Status code: %s, Response: %s",
                    code,
                    content,
                )
                self.api_version = "unknown"

    def _get_approval_nonce(
        self, request_id: str
    ) -> Tuple[Optional[str], Optional[str]]:
        """
        Get nonce for certificate request approval.

        Args:
            request_id (str): Certificate request ID.
        Returns:
            Tuple[Optional[str], Optional[str]]: Error message (or None), nonce value (or None).
        """
        self.logger.debug("CAhandler._get_approval_nonce(%s)", request_id)

        nonce = None
        error = None

        # we need a nonce first to lets send a get to the request status endpoint to get the nonce
        code, response = self._api_get(f"{self.REST_AGENT_CERTREQUESTS}{request_id}")

        if "requestStatus" in response:
            # Do not log full status if it contains sensitive info
            self.logger.debug(
                "CAHandler._certrequest_approve() - Certificate request %s status before approval attempt",
                request_id,
            )

        if code == 200 and isinstance(response, dict) and "nonce" in response:
            nonce = response["nonce"]
            # Do not log nonce value (sensitive)
            self.logger.debug("Received nonce for approval (redacted)")

        else:
            self.logger.error(
                "Failed to get nonce for certificate request approval. Status code: %s, Response: %s",
                code,
                response,
            )
            error = "Failed to get nonce for certificate request approval."

        self.logger.debug(
            "CAhandler._get_approval_nonce() ended with error: %s",
            error if error else "None",
        )
        return error, nonce

    def _certrequest_approve(
        self, request_id: str
    ) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        """
        Approve certificate request with given request_id.

        Args:
            request_id (str): Certificate request ID.
        Returns:
            Tuple[Optional[str], Optional[str], Optional[str]]: Error message (or None), cert_bundle, cert_raw.
        """
        self.logger.debug("CAhandler._certrequest_approve(%s)", request_id)
        error, nonce = self._get_approval_nonce(request_id)
        if error:
            self.logger.error(
                "Cannot approve certificate request %s due to error: %s",
                request_id,
                error,
            )
            return (error, None, None)

        # Approve request
        data = approve_profile_get(self.logger, nonce, request_id)
        code, response = self._api_post(
            f"{self.REST_AGENT_CERTREQUESTS}{request_id}/approve", data
        )

        if code >= 400:
            return self._approve_error(
                "Failed to approve certificate request.",
                code,
                response,
            )

        # Get new status and certificate data
        code, response = self._api_get(f"{self.REST_CERTREQUESTS}/{request_id}")
        if "requestStatus" not in response:
            return self._approve_error(
                "Failed to approve certificate request or retrieve certificate data after approval attempt.",
                code,
                response,
            )
        if "certId" not in response:
            return self._approve_error(
                "Certificate request approved but certId is missing in the response, cannot fetch certificate data.",
                code,
                response,
            )

        self.logger.debug(
            "CACertificate request %s approved successfully (certId redacted)",
            request_id,
        )
        return self._fetch_cert_and_bundle(response["certId"])

    def _fetch_cert_and_bundle(
        self, cert_id: str
    ) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        """
        Fetch certificate and bundle by cert_id.

        Args:
            cert_id (str): Certificate ID.
        Returns:
            Tuple[Optional[str], Optional[str], Optional[str]]: Error message (or None), cert_bundle, cert_raw.
        """
        code, response = self._api_get(f"{self.REST_CERTS}{cert_id}")
        error = None
        cert_raw = None
        cert_bundle = None
        if code == 200:
            if "Encoded" in response and response["Encoded"]:
                cert_raw = b64_encode(
                    self.logger, cert_pem2der(response.get("Encoded"))
                )
            else:
                self.logger.error(
                    "Certificate request approved but failed to fetch raw certificate data. Status code: %s",
                    code,
                )
                error = "Certificate request approved but failed to fetch raw certificate data."
            if "PKCS7CertChain" in response and response["PKCS7CertChain"]:
                cert_bundle = pkcs7_to_pem(
                    self.logger, b64_decode(self.logger, response.get("PKCS7CertChain"))
                )
            else:
                self.logger.error(
                    "Certificate request approved but failed to fetch certificate chain data. Status code: %s",
                    code,
                )
                error = "Certificate request approved but failed to fetch certificate chain data."
        else:
            error = f"Certificate request approved but failed to fetch certificate data. Status code: {code}, Response: {response}"
        self.logger.debug(
            "CAhandler._certrequest_approve() ended with error: %s", error
        )
        return (error, cert_bundle, cert_raw)

    def _approve_error(self, msg: str, code: int, response) -> Tuple[str, None, None]:
        """
        Log and return error for approval failures.

        Args:
            msg (str): Error message.
            code (int): HTTP status code.
            response: Response object or dict.
        Returns:
            Tuple[str, None, None]: Error message, None, None.
        """
        # For compatibility with tests, always include the legacy substring in the log
        legacy_msg = "Failed to get certificate request status after approval attempt"
        self.logger.error(
            f"{legacy_msg}. Status code: %s, Response: %s", code, response
        )
        self.logger.debug("CAhandler._certrequest_approve() ended with error: %s", msg)
        return (msg, None, None)

    def _parse_cert(self, pem_data: str) -> None:
        """
        Parse a PEM-encoded certificate and print key usage and extended key usage.

        Args:
            pem_data (str): PEM-encoded certificate string.
        Returns:
            None
        """

        from cryptography import x509
        from cryptography.hazmat.primitives import serialization

        cert = x509.load_pem_x509_certificate(pem_data.encode())

        try:
            ku_ext = cert.extensions.get_extension_for_class(x509.KeyUsage)
            print("\nKey Usage:")
            ku_value = ku_ext.value
            # Einzelne Flags prüfen (z.B. digital_signature, key_encipherment, etc.)
            usages = [
                "digital_signature" if ku_value.digital_signature else None,
                "content_commitment" if ku_value.content_commitment else None,
                "key_encipherment" if ku_value.key_encipherment else None,
                "data_encipherment" if ku_value.data_encipherment else None,
                "key_agreement" if ku_value.key_agreement else None,
                "key_cert_sign" if ku_value.key_cert_sign else None,
                "crl_sign" if ku_value.crl_sign else None,
            ]
            print(f"  Active: {[u for u in usages if u]}")
        except x509.ExtensionNotFound:
            print("No Key Usage extension found.")

        try:
            eku_ext = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
            print("Extended Key Usage (OIDs):")
            for oid in eku_ext.value:
                print(f"  - {oid._name} ({oid.dotted_string})")
        except x509.ExtensionNotFound:
            print("No Extended Key Usage extension found.")

    def _certrequest_send(
        self, csr: Optional[str] = None
    ) -> Tuple[Optional[str], Optional[str]]:
        """
        Send a certificate signing request (CSR) to the CA.

        Args:
            csr (Optional[str]): PEM-encoded CSR string.
        Returns:
            Tuple[Optional[str], Optional[str]]: Request ID and request status.
        """
        self.logger.debug("CAhandler._certrequest_send()")

        data = {
            "ProfileID": self.profile,
            "Input": [
                {
                    "id": "i1",
                    "ClassID": "certReqInputImpl",
                    "Name": "Certificate Request Input",
                    "ConfigAttribute": [],
                    "Attribute": [
                        {
                            "name": "cert_request_type",
                            "Value": "pkcs10",
                            "Descriptor": {
                                "Syntax": "cert_request_type",
                                "Description": "Certificate Request Type",
                            },
                        },
                        {
                            "name": "cert_request",
                            "Value": csr,
                            "Descriptor": {
                                "Syntax": "cert_request",
                                "Description": "Certificate Request",
                            },
                        },
                    ],
                }
            ],
        }

        url = self.REST_CERTREQUESTS
        code, response = self._api_post(url, data)

        request_id = None
        request_status = None
        if code == 200:
            if isinstance(response, dict) and "entries" in response:
                self.logger.info("Certificate request sent successfully")
                # Process the response as needed
                if (
                    response["entries"]
                    and "requestId" in response["entries"][0]
                    and "requestStatus" in response["entries"][0]
                ):
                    request_id = response["entries"][0]["requestId"]
                    request_status = response["entries"][0]["requestStatus"]
                    self.logger.info(
                        "Request ID: %s, Request Status: %s", request_id, request_status
                    )

            else:
                self.logger.error(
                    "Unexpected response format for certificate request. Response: %s",
                    response,
                )

        else:
            self.logger.error(
                "Failed to send certificate request. Status code: %s, Response: %s",
                code,
                response,
            )

        self.logger.debug(
            "CAhandler._certrequest_send() ended with code: %s, request_id: %s, request_status: %s",
            code,
            request_id,
            request_status,
        )

        return request_id, request_status

    def _config_passphrase_load(self, config_dic) -> None:
        """
        Load certificate passphrase from environment variable or config.

        Args:
            config_dic: Configuration dictionary or ConfigParser.
        Returns:
            None
        """
        section = None
        # Support both dict and ConfigParser
        if isinstance(config_dic, dict) and self.CONFIG_SECTION in config_dic:
            section = config_dic[self.CONFIG_SECTION]
        elif hasattr(config_dic, "items") and config_dic.has_section(
            self.CONFIG_SECTION
        ):
            # Convert section to dict
            section = dict(config_dic.items(self.CONFIG_SECTION))
        if not isinstance(section, dict):
            return

        if "cert_passphrase_variable" in section:
            self._load_passphrase_from_env(section["cert_passphrase_variable"])

        if "cert_passphrase" in section:
            self._load_passphrase_from_config(section["cert_passphrase"])

    def _load_passphrase_from_env(self, var_name: str) -> None:
        """
        Load certificate passphrase from environment variable.

        Args:
            var_name (str): Environment variable name.
        Returns:
            None
        """
        import os

        try:
            self.cert_passphrase = os.environ[var_name]
        except Exception as err:
            self.logger.error("Could not load cert_passphrase_variable:%s", err)

    def _load_passphrase_from_config(self, passphrase: str) -> None:
        """
        Load certificate passphrase from config value.

        Args:
            passphrase (str): Passphrase value.
        Returns:
            None
        """
        if self.cert_passphrase:
            self.logger.info("CAhandler._config_load() overwrite cert_passphrase")
        self.cert_passphrase = passphrase

    def _config_load(self) -> None:
        """
        Load configuration from file and set handler attributes.
        Returns:
            None
        """
        self.logger.debug("CAhandler._config_load()")

        config_dic = load_config(self.logger, self.CONFIG_SECTION)

        self.api_host = config_dic.get(
            self.CONFIG_SECTION, "api_host", fallback=self.api_host
        )

        self.client_cert = config_dic.get(
            self.CONFIG_SECTION, "client_cert", fallback=self.client_cert
        )

        self.client_key = config_dic.get(
            self.CONFIG_SECTION, "client_key", fallback=self.client_key
        )

        self.profile = config_dic.get(
            self.CONFIG_SECTION, "profile", fallback=self.profile
        )

        self.ca_bundle = config_dic.get(
            self.CONFIG_SECTION, "ca_bundle", fallback=self.ca_bundle
        )

        if str(self.ca_bundle).lower() in ["true", "false"]:
            self.ca_bundle = config_dic.getboolean(
                self.CONFIG_SECTION, "ca_bundle", fallback=self.ca_bundle
            )

        self.certrequest_approve = config_dic.getboolean(
            self.CONFIG_SECTION,
            "certrequest_approve",
            fallback=self.certrequest_approve,
        )

        # load profiling
        self.eab_profiling, self.eab_handler = config_eab_profile_load(
            self.logger, config_dic
        )

        self._config_passphrase_load(config_dic)

        # load profiles
        self.profiles = config_profile_load(self.logger, config_dic)
        # load header info
        self.header_info_field = config_headerinfo_load(self.logger, config_dic)
        # load enrollment config log
        (
            self.enrollment_config_log,
            self.enrollment_config_log_skip_list,
        ) = config_enroll_config_log_load(self.logger, config_dic)

        self.logger.debug("CAhandler._config_load() ended")

    def _login(self) -> None:
        """
        Login to the CA API and establish a session.
        Returns:
            None
        """
        self.logger.debug("CAhandler._login()")

        if not self.session:
            self.session = requests.Session()

            if self.client_cert and self.cert_passphrase:
                self.logger.debug(
                    "CAhandler._login() using PKCS12 client authentication"
                )
                self.session.mount(
                    self.api_host,
                    Pkcs12Adapter(
                        pkcs12_filename=self.client_cert,
                        pkcs12_password=self.cert_passphrase,
                    ),
                )
            else:
                # client auth via pem files
                self.session.cert = (self.client_cert, self.client_key)
            # update hader
            self.session.headers.update({"Accept": "application/json"})

    def _revoke(self, serial: str) -> Tuple[int, str, str]:
        """
        Revoke certificate with given serial number.

        Args:
            serial (str): Certificate serial number.
        Returns:
            Tuple[int, str, str]: Code, message, and detail.
        """
        self.logger.debug("CAhandler._revoke(%s)", serial)
        serial = self._normalize_serial(serial)
        code, response = self._api_get(f"{self.REST_AGENT_CERTS}{serial}")
        if code != 200 or not isinstance(response, dict):
            return self._revoke_status_error(serial, code, response)
        if "Nonce" not in response:
            return self._revoke_status_error(serial, code, response)
        nonce = response["Nonce"]
        self.logger.debug(
            "CAhandler._revoke(): received nonce for revocation: %s", nonce
        )
        status = response.get("Status", "").lower()
        if status == "valid":
            return self._revoke_valid(serial, nonce)
        if status == "revoked":
            self.logger.info("Certificate with serial %s is already revoked", serial)
            return (200, "Certificate is already revoked", "")
        return self._revoke_status_error(serial, code, response)

    def _normalize_serial(self, serial: str) -> str:
        """
        Ensure serial starts with '0x'.

        Args:
            serial (str): Certificate serial number.
        Returns:
            str: Normalized serial number.
        """
        return serial if str(serial).lower().startswith("0x") else f"0x{serial}"

    def _revoke_valid(self, serial: str, nonce: str) -> Tuple[int, str, str]:
        """
        Handle revocation for valid certificates.

        Args:
            serial (str): Certificate serial number.
            nonce (str): Nonce value for revocation.
        Returns:
            Tuple[int, str, str]: Code, message, and detail.
        """
        self.logger.debug(
            "CAhandler._revoke(): Certificate with serial %s is valid, proceeding with revocation",
            serial,
        )
        data = {"Reason": "Unspecified", "Nonce": nonce}
        code, response = self._api_post(f"{self.REST_AGENT_CERTS}{serial}/revoke", data)
        if code == 200:
            self.logger.info("Certificate with serial %s revoked successfully", serial)
            return (code, "Certificate revoked successfully", "")
        self.logger.error(
            "Failed to revoke certificate with serial %s. Status code: %s, Response: %s",
            serial,
            code,
            response,
        )
        return (code, "Failed to revoke certificate", str(response))

    def _revoke_status_error(
        self, serial: str, code: int, response
    ) -> Tuple[int, str, str]:
        """
        Handle error when failing to get certificate status before revocation.

        Args:
            serial (str): Certificate serial number.
            code (int): HTTP status code.
            response: Response object or dict.
        Returns:
            Tuple[int, str, str]: Code, message, and detail.
        """
        self.logger.error(
            "Failed to get certificate status for serial %s before revocation attempt. Status code: %s, Response: %s",
            serial,
            code,
            response,
        )
        return (
            code,
            "Failed to get certificate status before revocation attempt",
            str(response),
        )

    def enroll(
        self, csr: str
    ) -> Tuple[Optional[str], Optional[str], Optional[str], Optional[str]]:
        """
        Enroll a certificate.

        Args:
            csr (str): CSR string.
        Returns:
            Tuple[Optional[str], Optional[str], Optional[str], Optional[str]]: Error, PEM bundle, raw certificate, poll identifier.
        """
        """
        Enroll a certificate.
        Args:
            csr (str): CSR string.
        Returns:
            Tuple[str, str, str, str]: Error, PEM bundle, raw certificate, poll identifier.
        """
        self.logger.debug("CAhandler.enroll()")

        cert_bundle = None
        cert_raw = None
        poll_identifier = None

        error: Optional[str] = eab_profile_header_info_check(
            self.logger, self, csr, "profile_id"
        )

        if not error:

            self._api_version_get()

            if self.enrollment_config_log:
                enrollment_config_log(
                    self.logger, self, self.enrollment_config_log_skip_list
                )

            request_id, request_status = self._certrequest_send(csr)
            if request_status == "pending":
                if self.certrequest_approve:
                    # try to approve the request
                    error, cert_bundle, cert_raw = self._certrequest_approve(request_id)
                else:
                    poll_identifier = request_id
            elif request_status == "complete":
                # Get new status and certificate data
                code, response = self._api_get(f"{self.REST_CERTREQUESTS}/{request_id}")
                if code == 200 and isinstance(response, dict) and "certId" in response:
                    error, cert_bundle, cert_raw = self._fetch_cert_and_bundle(
                        response["certId"]
                    )
                else:
                    self.logger.error(
                        "Failed to retrieve certificate data for completed request. Status code: %s, Response: %s",
                        code,
                        response,
                    )
                    error = "Failed to retrieve certificate data for completed request."
            elif request_status == "rejected":
                self.logger.error("Certificate request was rejected by CA")
                error = "Certificate request was rejected by CA."
            else:
                self.logger.error(
                    "Certificate request failed. Unknown request-status: %s",
                    request_status,
                )
                error = "Certificate request failed."


        self.logger.debug("Certificate.enroll() ended()")
        # Always return a consistent tuple
        return (error, cert_bundle, cert_raw, poll_identifier)

    def handler_check(self) -> Optional[str]:
        """
        Check if handler is ready and configuration is valid.

        Returns:
            Optional[str]: Error message if any, else None.
        """
        self.logger.debug("CAhandler.check()")
        error = handler_config_check(self.logger, self, ["api_host", "client_cert"])
        self.logger.debug("CAhandler.check() ended with %s", error)
        return error

    def poll(
        self, _cert_name: str, poll_identifier: str, _csr: str
    ) -> Tuple[Optional[str], Optional[str], Optional[str], Optional[str], bool]:
        """
        Poll status of pending CSR and download certificates.

        Args:
            _cert_name (str): Certificate name.
            poll_identifier (str): Poll identifier.
            _csr (str): CSR string (unused).
        Returns:
            Tuple[Optional[str], Optional[str], Optional[str], Optional[str], bool]: Error, PEM bundle, raw certificate, poll identifier, rejected flag.
        """
        self.logger.debug("CAhandler.poll()")
        error: Optional[str] = None
        cert_bundle: Optional[str] = None
        cert_raw: Optional[str] = None
        rejected: bool = False
        # This method is a stub and should be implemented as needed.
        return (error, cert_bundle, cert_raw, poll_identifier, rejected)

    def revoke(
        self,
        cert: str,
        _rev_reason: Optional[str] = None,
        _rev_date: Optional[str] = None,
    ) -> Tuple[int, str, str]:
        """
        Revoke a certificate.

        Args:
            cert (str): Certificate string.
            _rev_reason (Optional[str]): Revocation reason.
            _rev_date (Optional[str]): Revocation date.
        Returns:
            Tuple[int, str, str]: Code, message, and detail.
        """
        self.logger.debug("CAhandler.revoke()")

        if cert:
            serial = cert_serial_get(self.logger, cert, hexformat=True)

            if serial:
                code, message, detail = self._revoke(serial)
            else:
                self.logger.error(
                    "Failed to extract serial number from certificate for revocation"
                )
                code = 400
                message = "urn:ietf:params:acme:error:malformed"
                detail = "Invalid certificate format or missing serial number"
        else:
            self.logger.error("Certificate data is required for revocation")
            code = 400
            message = "urn:ietf:params:acme:error:malformed"
            detail = "Certificate data is required for revocation"

        self.logger.debug("Certificate.revoke() ended")
        return (code, message, detail)

    def trigger(
        self, _payload: str
    ) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        """
        Process trigger message and return certificate.

        Args:
            _payload (str): Trigger payload.
        Returns:
            Tuple[Optional[str], Optional[str], Optional[str]]: Error, PEM bundle, and raw certificate.
        """
        self.logger.debug("CAhandler.trigger()")

        error: Optional[str] = None
        cert_bundle: Optional[str] = None
        cert_raw: Optional[str] = None

        self.logger.debug("CAhandler.trigger() ended with error: %s", error)
        return (error, cert_bundle, cert_raw)
