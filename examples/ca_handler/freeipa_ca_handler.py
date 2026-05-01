# -*- coding: utf-8 -*-
"""skeleton for customized CA handler"""
from __future__ import print_function
from typing import Tuple, Dict
import re
import requests


# pylint: disable=e0401
from acme_srv.helper import (
    load_config,
    csr_cn_get,
    csr_san_get,
    build_pem_file,
    b64_decode,
    cert_der2pem,
    cert_serial_get,
    handler_config_check,
    eab_profile_header_info_check,
    config_enroll_config_log_load,
    config_profile_load,
    config_eab_profile_load,
    config_headerinfo_load,
    enrollment_config_log,
)


class CAhandler(object):
    """EST CA  handler"""

    # Class-level constants for magic strings and numbers
    DEFAULT_PREFIX = "/ipa"
    DEFAULT_JSON_RPC_URL = "/session/json"
    DEFAULT_REQUEST_TIMEOUT = 30
    CONFIG_SECTION = "CAhandler"
    CONFIG_DEFAULT_SECTION = "DEFAULT"
    LOGIN_URL = "/session/login_password"

    def __init__(self, _debug: bool = None, logger: object = None):
        """
        Initialize the CAhandler.
        Args:
            _debug (bool, optional): Enable debug mode. Not currently used.
            logger (object, optional): Logger instance for logging.
        """
        self.logger = logger
        self.api_host = None
        self.prefix = self.DEFAULT_PREFIX
        self.json_rpc_url = self.DEFAULT_JSON_RPC_URL
        self.api_user = None
        self.api_password = None
        self.api_version = None  # 2.257
        self.fqdn = None
        self.ca_bundle = True
        self.session = None
        self.proxy = None
        self.request_timeout = self.DEFAULT_REQUEST_TIMEOUT
        self.realm = None
        self.profile_id = None
        self.header_info_field = False
        self.eab_handler = None
        self.eab_profiling = False
        self.enrollment_config_log = False
        self.enrollment_config_log_skip_list = []
        self.profiles = {}

    def __enter__(self):
        """
        Enter the context manager, loading configuration and logging in if needed.
        Returns:
            CAhandler: The handler instance.
        """
        if not self.api_host:
            self._config_load()
            self._login()
            self._extract_api_version()
        return self

    def __exit__(self, *args):
        """
        Close the connection at the end of the context.
        Args:
            *args: Exception type, value, and traceback (if any).
        """
        if self.session:
            self.session.close()
            self.session = None

    def _config_load(self):
        """
        Load configuration from file and set handler attributes.
        """
        self.logger.debug("CAhandler._config_load()")

        config_dic = load_config(self.logger, self.CONFIG_SECTION)
        self.api_host = config_dic.get(
            self.CONFIG_SECTION, "api_host", fallback=self.api_host
        )
        self.fqdn = config_dic.get(
            self.CONFIG_DEFAULT_SECTION, "fqdn", fallback=self.fqdn
        )
        if not self.fqdn:
            self.logger.debug("FQDN not configured in DEFAULT section")
            self.fqdn = config_dic.get(self.CONFIG_SECTION, "fqdn", fallback=self.fqdn)
        self.api_user = config_dic.get(
            self.CONFIG_SECTION, "api_user", fallback=self.api_user
        )
        self.api_password = config_dic.get(
            self.CONFIG_SECTION, "api_password", fallback=self.api_password
        )
        self.realm = config_dic.get(self.CONFIG_SECTION, "realm", fallback=self.realm)

        self.profile_id = config_dic.get(
            self.CONFIG_SECTION, "profile_id", fallback=self.profile_id
        )

        self.ca_bundle = config_dic.get(
            self.CONFIG_SECTION, "ca_bundle", fallback=self.ca_bundle
        )

        if str(self.ca_bundle).lower() in ["true", "false"]:
            self.ca_bundle = config_dic.getboolean(
                self.CONFIG_SECTION, "ca_bundle", fallback=self.ca_bundle
            )

        # load profiling
        self.eab_profiling, self.eab_handler = config_eab_profile_load(
            self.logger, config_dic
        )
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

    def _ensure_host_and_principals(self, hostname: str, alias_list: list) -> str:
        """
        Ensure the host exists in FreeIPA, add if missing, set managedby, and add all principals.
        Args:
            hostname (str): Hostname to check/add.
            alias_list (list): List of FQDNs to add as principals.
        Returns:
            str: Error message if any, else None.
        """
        self.logger.debug("CAhandler._ensure_host_and_principals()")
        error = None
        content = self._host_search(hostname)
        if "result" in content:
            if content.get("result"):
                self.logger.debug("Host %s found in FreeIPA", hostname)
            else:
                self.logger.debug("Host %s not found in FreeIPA. Creating...", hostname)
                self._host_add(hostname)
            self._host_add_managedby(hostname)
            for fqdn in alias_list:
                self._host_add_principal(hostname, fqdn)
        else:
            self.logger.error(
                "Host search failed: %s", content.get("error", "Unknown error")
            )
            error = "Malformed host search response"
        self.logger.debug(
            "CAhandler._ensure_host_and_principals() ended with error: %s", error
        )
        return error

    def _login(self):
        """
        Login to the FreeIPA API and store session cookies.
        Returns:
            dict: None on success, or error dict on failure.
        """
        self.logger.debug("CAhandler._login()")

        if self.session is None:
            self.session = requests.Session()

        # client auth via pem files
        self.session.headers.update(
            {"Referer": f"{self.api_host}/ipa", "Accept": "application/json"}
        )

        login_url = self.LOGIN_URL
        payload = {"user": self.api_user, "password": self.api_password}

        try:
            # FreeIPA login expects form-encoded data
            response = self.session.post(
                self.api_host + self.prefix + login_url,
                data=payload,
                verify=self.ca_bundle,
            )
            response.raise_for_status()
        except requests.exceptions.HTTPError as e:
            self.logger.error(f"HTTP error during login: {e}")
            return {"error": f"HTTP error during login: {e}"}
        except requests.exceptions.ConnectionError as e:
            self.logger.error(f"Connection error during login: {e}")
            return {"error": f"Connection error during login: {e}"}
        except requests.exceptions.Timeout as e:
            self.logger.error(f"Timeout during login: {e}")
            return {"error": f"Timeout during login: {e}"}
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Unexpected request exception during login: {e}")
            return {"error": f"Unexpected request exception during login: {e}"}
        return None

    def _ipa_ping(self) -> bool:
        """
        Ping FreeIPA to check connectivity.
        Returns:
            dict: The response content from the ping request.
        """
        self.logger.debug("CAhandler._ipa_ping()")
        payload = {
            "id": 0,
            "method": "ping",
            "params": [[], {"version": "2.0"}],
        }
        content = self._rpc_post(payload)
        return content

    def _host_add_managedby(self, hostname: str = None):
        """
        Add host to FreeIPA with managedby attribute.
        Args:
            hostname (str): Hostname to add as managed by this handler's FQDN.
        """
        self.logger.debug("CAhandler._host_add_managedby()")
        rpc_payload = {
            "id": 0,
            "method": "host_add_managedby/1",
            "params": [
                [f"{hostname}"],
                {"host": [f"{self.fqdn}"], "version": f"{self.api_version}"},
            ],
        }
        content = self._rpc_post(rpc_payload)
        if "error" in content and content["error"] is not None:
            self.logger.error("Failed to add host %s: %s", hostname, content["error"])
        else:
            self.logger.debug(
                "Host %s added managed by %s successfully", hostname, self.fqdn
            )

    def _host_add(self, hostname: str = None):
        """
        Add a host to FreeIPA.
        Args:
            hostname (str): Hostname to add.
        """
        self.logger.debug("CAhandler._host_add()")
        if not hostname or not isinstance(hostname, str):
            self.logger.error("Invalid hostname provided to _host_add: %s", hostname)
            return

        rpc_payload = {
            "id": 0,
            "method": "host_add/1",
            "params": [[hostname], {"force": True, "version": f"{self.api_version}"}],
        }

        content = self._rpc_post(rpc_payload)
        if "error" in content and content["error"] is not None:
            self.logger.error("Failed to add host %s: %s", hostname, content["error"])
        else:
            self.logger.info("Host %s added successfully to freeIPA", hostname)

    def _host_add_principal(self, hostname: str = None, fqdn: str = None):
        """
        Add a host principal to FreeIPA.
        Args:
            hostname (str): Hostname to add principal to.
            fqdn (str): FQDN to use for the principal.
        """
        self.logger.debug("CAhandler._host_add_principal()")
        if not hostname or not isinstance(hostname, str):
            self.logger.error(
                "Invalid hostname provided to _host_add_principal: %s", hostname
            )
            return
        if not fqdn or not isinstance(fqdn, str):
            self.logger.error("Invalid fqdn provided to _host_add_principal: %s", fqdn)
            return

        rpc_payload = {
            "id": 0,
            "method": "host_add_principal/1",
            "params": [
                [hostname, [f"host/{fqdn}@{self.realm}"]],
                {"version": f"{self.api_version}"},
            ],
        }

        content = self._rpc_post(rpc_payload)
        if "error" in content and content["error"] is not None:
            self.logger.error(
                "Failed to add host principal %s for host %s: %s",
                fqdn,
                hostname,
                content["error"],
            )
        else:
            self.logger.debug(
                "Host principal %s added to host %s successfully", fqdn, hostname
            )

    def _host_search(self, hostname: str) -> dict:
        """
        Search for a host in FreeIPA.
        Args:
            hostname (str): Hostname to search for.
        Returns:
            dict: The response content from the search request.
        """
        self.logger.debug("CAhandler._host_search(%s)", hostname)
        if not hostname or not isinstance(hostname, str):
            self.logger.error("Invalid hostname provided to _host_search: %s", hostname)
            return {}
        rpc_payload = {
            "id": 0,
            "method": "host_show",
            "params": [[hostname], {"version": f"{self.api_version}"}],
        }
        content = self._rpc_post(rpc_payload)
        return content

    def _parse_csr(self, csr: str) -> Tuple[str, list]:
        """
        Parse a CSR and extract the CN and SANs.
        Args:
            csr (str): The CSR string.
        Returns:
            Tuple[str, list]: The CN and list of SANs.
        """
        self.logger.debug("CAhandler._parse_csr()")
        if not csr or not isinstance(csr, str):
            self.logger.error("Invalid CSR provided to _parse_csr: %s", csr)
            return None, []
        cn = csr_cn_get(self.logger, csr)
        tmp_san_list = csr_san_get(self.logger, csr)
        san_list = []
        for san in tmp_san_list:
            if isinstance(san, str) and san.startswith("DNS:"):
                san_list.append(san[4:])

        if not cn:
            self.logger.debug("Failed to extract CN from CSR")
            cn = san_list.pop(0) if san_list else None

        self.logger.debug(
            "CAhandler._parse_csr() extracted CN: %s, SANs: %s", cn, san_list
        )
        return cn, san_list

    def _rpc_post(self, data_dic: Dict[str, str]) -> Dict[str, str]:
        """
        Send a POST request to the FreeIPA JSON-RPC interface.
        Args:
            data_dic (dict): The payload to send.
        Returns:
            dict: The response content.
        Raises:
            requests.exceptions.RequestException: If the request fails.
        """
        self.logger.debug("CAhandler._rpc_post()")
        try:
            resp = self.session.post(
                self.api_host + self.prefix + self.json_rpc_url,
                json=data_dic,
                verify=self.ca_bundle,
                proxies=self.proxy,
                timeout=self.request_timeout,
            )
            resp.raise_for_status()
            response = resp.json()
        except requests.exceptions.HTTPError as err:
            self.logger.error("HTTP error during RPC POST: %s", err)
            return {"error": f"HTTP error: {err}"}
        except requests.exceptions.ConnectionError as err:
            self.logger.error("Connection error during RPC POST: %s", err)
            return {"error": f"Connection error: {err}"}
        except requests.exceptions.Timeout as err:
            self.logger.error("Timeout during RPC POST: %s", err)
            return {"error": f"Timeout error: {err}"}
        except requests.exceptions.RequestException as err:
            self.logger.error("Unexpected request exception during RPC POST: %s", err)
            return {"error": f"Request exception: {err}"}
        except ValueError as err:
            self.logger.error("Failed to decode JSON response: %s", err)
            response = {"error": f"JSON decode error: {err}"}
        self.logger.debug("CAhandler._rpc_post() ended.")
        return response

    def _extract_api_version(self):
        """
        Extract API version from ping response and set self.api_version.
        """
        self.logger.debug("CAhandler._extract_api_version()")
        content = self._ipa_ping()
        summary = content.get("result", {}).get("summary", "")
        match = re.search(r"API version ([\d.]+)", summary)
        if match:
            self.logger.debug(
                "CAhandler._extract_api_version() returned API version: %s",
                match.group(1),
            )
            self.api_version = match.group(1)

    def _cert_chain_to_pem(self, certifcate_chain):
        """
        Convert a list of dicts with '__base64__' keys to a PEM certificate chain string.
        Args:
            certifcate_chain (list): List of certificate dicts.
        Returns:
            str: PEM-formatted certificate chain.
        """
        self.logger.debug("CAhandler._cert_chain_to_pem()")
        pem_chain = []
        for cert in certifcate_chain:
            b64_cert = cert.get("__base64__")
            if not b64_cert:
                continue

            der_bytes = b64_decode(self.logger, b64_cert)
            pem = cert_der2pem(der_bytes).decode("utf-8")
            pem_chain.append(pem.strip())
        self.logger.debug(
            "CAhandler._cert_chain_to_pem() ended with %d certificates in the chain",
            len(pem_chain),
        )
        return "\n".join(pem_chain)

    def _enroll(self, hostname: str, csr: str):
        """
        Enroll a certificate via RPC.
        Args:
            hostname (str): Hostname for the certificate.
            csr (str): CSR string.
        Returns:
            Tuple[str, str, str]: Error message, PEM bundle, and raw certificate.
        """
        self.logger.debug("CAhandler._enroll()")

        if self.enrollment_config_log:
            enrollment_config_log(
                self.logger, self, self.enrollment_config_log_skip_list
            )

        rpc_payload = {
            "id": 0,
            "method": "cert_request/1",
            "params": [
                [csr],
                {
                    "principal": f"host/{hostname}@{self.realm}",
                    "add": True,
                    "chain": True,
                    "version": f"{self.api_version}",
                },
            ],
        }

        if self.profile_id:
            self.logger.debug(
                "CAhandler._enroll(): Adding profile_id %s to RPC payload for enrollment",
                self.profile_id,
            )
            rpc_payload["params"][1]["profile_id"] = self.profile_id

        content = self._rpc_post(rpc_payload)
        error = None
        cert_raw = None
        cert_bundle = None
        if "error" in content and content["error"] is not None:
            error = str(content["error"])
            self.logger.error(
                "Certificate enrollment failed for host %s: %s", hostname, error
            )
            return error, None, None
        if "result" in content:
            try:
                result = content.get("result", {}).get("result", {})
                if isinstance(result, dict):
                    cert_raw = result.get("certificate", None)
                    cert_chain = result.get("certificate_chain", [])
                    cert_bundle = self._cert_chain_to_pem(cert_chain)
                    self.logger.debug(
                        "Certificate chain converted to PEM format successfully"
                    )
                else:
                    error = f"Unexpected structure for 'result': {type(result)}"
                    self.logger.error(error)
                    return error, None, None
            except Exception as ex:
                error = f"Error extracting certificate or chain: {ex}"
                self.logger.error(error)
                return error, None, None
        else:
            error = "Certificate chain not found in response"
            self.logger.error(error)
            return error, None, None
        self.logger.debug(
            "CAhandler._enroll() ended successfully for host %s", hostname
        )
        return error, cert_bundle, cert_raw

    def _revoke(self, serial: str):
        """
        Revoke a certificate via RPC.
        Args:
            serial (str): Certificate serial number.
        Returns:
            Tuple[int, str, str]: Code, message, and detail.
        """
        self.logger.debug("CAhandler._revoke()")

        rpc_payload = {
            "id": 0,
            "method": "cert_revoke/1",
            "params": [[serial], {"version": f"{self.api_version}"}],
        }
        content = self._rpc_post(rpc_payload)
        if "error" in content and content["error"] is not None:
            self.logger.error(
                "Certificate revocation failed for serial %s: %s",
                serial,
                content["error"],
            )
            return 500, str(content["error"]), None
        self.logger.debug("Certificate revocation successful for serial %s", serial)
        return 200, "Certificate revoked successfully", None

    def enroll(self, csr: str) -> Tuple[str, str, str, str]:
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

        error = eab_profile_header_info_check(self.logger, self, csr, "profile_id")

        if not error:
            # optional: lookup http header information from request
            hostname, alias_list = self._parse_csr(csr)
            # ensure host and principals exist in FreeIPA
            error = self._ensure_host_and_principals(hostname, alias_list)

        if not error:
            # reformat csr
            csr_reformatted = build_pem_file(
                self.logger, None, csr, wrap=True, csr=True
            )
            error, cert_bundle, cert_raw = self._enroll(hostname, csr_reformatted)

        self.logger.debug("Certificate.enroll() ended()")
        # Always return a consistent tuple
        return (error, cert_bundle, cert_raw, poll_identifier)

    def handler_check(self):
        """
        Check if handler is ready and configuration is valid.
        Returns:
            str: Error message if any, else None.
        """
        self.logger.debug("CAhandler.check()")
        error = handler_config_check(
            self.logger, self, ["api_host", "api_user", "api_password", "realm"]
        )
        self.logger.debug("CAhandler.check() ended with %s", error)
        return error

    def poll(
        self, _cert_name: str, poll_identifier: str, _csr: str
    ) -> Tuple[str, str, str, str, bool]:
        """
        Poll status of pending CSR and download certificates.
        Args:
            cert_name (str): Certificate name.
            poll_identifier (str): Poll identifier.
            _csr (str): CSR string (unused).
        Returns:
            Tuple[str, str, str, str, bool]: Error, PEM bundle, raw certificate, poll identifier, rejected flag.
        """
        self.logger.debug("CAhandler.poll()")
        error = None
        cert_bundle = None
        cert_raw = None
        rejected = False
        # This method is a stub and should be implemented as needed.
        return (error, cert_bundle, cert_raw, poll_identifier, rejected)

    def revoke(
        self, cert: str, _rev_reason: str = None, _rev_date: str = None
    ) -> Tuple[int, str, str]:
        """
        Revoke a certificate.
        Args:
            cert (str): Certificate string.
            _rev_reason (str, optional): Revocation reason.
            _rev_date (str, optional): Revocation date.
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

    def trigger(self, _payload: str) -> Tuple[str, str, str]:
        """
        Process trigger message and return certificate.
        Args:
            payload (str): Trigger payload.
        Returns:
            Tuple[str, str, str]: Error, PEM bundle, and raw certificate.
        """
        self.logger.debug("CAhandler.trigger()")

        error = None
        cert_bundle = None
        cert_raw = None

        self.logger.debug("CAhandler.trigger() ended with error: %s", error)
        return (error, cert_bundle, cert_raw)
