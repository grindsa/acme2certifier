# -*- coding: utf-8 -*-
"""ca handler for  Microsoft Webenrollment service (certsrv)"""

from __future__ import print_function
import os
import textwrap
import json
import tempfile
import importlib
import subprocess
import threading
from contextlib import contextmanager
from typing import List, Tuple, Dict, Optional
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization.pkcs7 import (
    load_pem_pkcs7_certificates,
    load_der_pkcs7_certificates,
)

# pylint: disable=e0401, e0611
from acme2certifier.cahandlers.certsrv import (
    CHANNEL_BINDINGS_TLS_SERVER_END_POINT,
    Certsrv,
    gssapi_channel_bindings_supported,
)
from acme2certifier.acme_srv.helper import (
    b64_url_recode,
    config_eab_profile_load,
    config_enroll_config_log_load,
    config_profile_load,
    convert_byte_to_string,



    convert_string_to_byte,
    eab_profile_header_info_check,
    enrollment_config_log,
    handler_config_check,
    header_info_get,
    load_config,
    proxy_check,
    pkcs7_to_pem,
)  # pylint: disable=e0401
from acme2certifier.acme_srv.helpers.global_variables import CONFIGURATION_ERROR_DETAIL


class CAhandler(object):
    """EST CA  handler"""

    KINIT_TIMEOUT_SECONDS = 30
    CERT_FETCH_ERROR = "Could not get certificate from CA server"
    _ca_templates_cache: Dict[str, List[str]] = {}
    _ca_templates_lock = threading.Lock()

    def __init__(self, _debug: bool = False, logger: object = None):
        self.logger = logger
        self.host = None
        self.url = None
        self.user = None
        self.password = None
        self.auth_method = "basic"
        self.gssapi_channel_bindings = "auto"
        self.ca_bundle = False
        self.template = None
        self.allowed_templates: List[str] = []
        self.ca_templates_check = "warn"
        self.krb5_principal = None
        self.krb5_keytab = None
        self.krb5_cache = None
        self.krb5_config = None
        self.krb5_kinit_path = "kinit"
        self.proxy = None
        self.header_info_field = False
        self.verify = True
        self.eab_handler = None
        self.eab_profiling = False
        self.enrollment_config_log = False
        self.enrollment_config_log_skip_list = []
        self.profiles = {}
        self._krb5_cache_is_temporary = False
        self._gssapi_creds = None
        self.profile_mapping_field = "template"

    def __enter__(self):
        """Makes CAhandler a Context Manager"""
        if not self.host:
            self._config_load()
        return self

    def __exit__(self, *args):
        """cose the connection at the end of the context"""

    def _check_credentials(self, ca_server: object) -> bool:
        """check creadentials"""
        self.logger.debug("CAhandler.__check_credentials()")
        auth_check = ca_server.check_credentials()
        self.logger.debug("CAhandler.__check_credentials() ended with %s", auth_check)
        return auth_check

    def _cert_bundle_create(
        self, ca_pem: str = None, cert_raw: str = None
    ) -> Tuple[str, str, str]:
        """create bundle"""
        self.logger.debug("CAhandler._cert_bundle_create()")

        error = None
        cert_bundle = None

        if ca_pem and cert_raw:
            cert_bundle = cert_raw + ca_pem
            cert_raw = cert_raw.replace("-----BEGIN CERTIFICATE-----\n", "")
            cert_raw = cert_raw.replace("-----END CERTIFICATE-----\n", "")
            cert_raw = cert_raw.replace("\n", "")
        else:
            self.logger.error(
                "Failed to bundle certificates: missing ca_pem or cert_raw."
            )
            error = "Certificate bundling failed: missing CA certificate or issued certificate."

        return (error, cert_bundle, cert_raw)

    def _config_headerinfo_load(self, config_dic: Dict[str, str]):
        """load parameters"""
        self.logger.debug("_config_header_info()")

        if (
            "Order" in config_dic
            and "header_info_list" in config_dic["Order"]
            and config_dic["Order"]["header_info_list"]
        ):
            try:
                self.header_info_field = json.loads(
                    config_dic["Order"]["header_info_list"]
                )[0]
            except Exception as err_:
                self.logger.warning(
                    "Failed to parse header_info_list from configuration: %s",
                    err_,
                )

        self.logger.debug("_config_header_info() ended")

    def _config_user_load(self, config_dic: Dict[str, str]):
        """load username"""
        self.logger.debug("CAhandler._config_user_load()")

        if "user_variable" in config_dic["CAhandler"]:
            try:
                self.user = os.environ[config_dic.get("CAhandler", "user_variable")]
            except Exception as err:
                self.logger.error(
                    "Could not load user_variable from environment: %s", err
                )
        if "user" in config_dic["CAhandler"]:
            if self.user:
                self.logger.info("Overwrite user")
            self.user = config_dic.get("CAhandler", "user")

        self.logger.debug("CAhandler._config_user_load() ended")

    def _config_password_load(self, config_dic: Dict[str, str]):
        """load username"""
        self.logger.debug("CAhandler._config_password_load()")

        if "password_variable" in config_dic["CAhandler"]:
            try:
                self.password = os.environ[
                    config_dic.get("CAhandler", "password_variable")
                ]
            except Exception as err:
                self.logger.error(
                    "Could not load password_variable from environment: %s", err
                )
        if "password" in config_dic["CAhandler"]:
            if self.password:
                self.logger.info("Overwrite password")
            self.password = config_dic.get("CAhandler", "password")

        self.logger.debug("CAhandler._config_password_load() ended")

    def _config_hostname_load(self, config_dic: Dict[str, str]):
        """load hostname"""
        self.logger.debug("CAhandler._config_hostname_load()")

        if "host_variable" in config_dic["CAhandler"]:
            try:
                self.host = os.environ[config_dic.get("CAhandler", "host_variable")]
            except Exception as err:
                self.logger.error(
                    "Could not load host_variable from environment: %s", err
                )
        if "host" in config_dic["CAhandler"]:
            if self.host:
                self.logger.info("Overwrite host")
            self.host = config_dic.get("CAhandler", "host")
        self.logger.debug("CAhandler._config_hostname_load() ended")

    def _config_url_load(self, config_dic: Dict[str, str]):
        if "url_variable" in config_dic["CAhandler"]:
            try:
                self.url = os.environ[config_dic.get("CAhandler", "url_variable")]
            except Exception as err:
                self.logger.error(
                    "Could not load url_variable from environment: %s", err
                )
        if "url" in config_dic["CAhandler"]:
            if self.url:
                self.logger.info("Overwrite url")
            self.url = config_dic.get("CAhandler", "url")

        self.logger.debug("CAhandler._config_url_load() ended")

    def _config_parameters_load(self, config_dic: Dict[str, str]):
        """load hostname"""
        self.logger.debug("CAhandler._config_parameters_load()")

        self.template = config_dic.get(
            "CAhandler", self.profile_mapping_field, fallback=self.template
        )
        self._config_allowed_templates_load(config_dic)
        self._config_ca_templates_check_load(config_dic)
        if "auth_method" in config_dic["CAhandler"] and config_dic["CAhandler"][
            "auth_method"
        ] in ["basic", "ntlm", "gssapi"]:
            self.auth_method = config_dic.get("CAhandler", "auth_method")
        channel_bindings_mode = config_dic.get(
            "CAhandler", "gssapi_channel_bindings", fallback=self.gssapi_channel_bindings
        )
        if isinstance(channel_bindings_mode, str):
            channel_bindings_mode = channel_bindings_mode.lower()
        if channel_bindings_mode in ["auto", "on", "off"]:
            self.gssapi_channel_bindings = channel_bindings_mode
        else:
            self.logger.warning(
                "Invalid gssapi_channel_bindings '%s'; using 'auto'. "
                "Allowed values: auto, on, off.",
                channel_bindings_mode,
            )
            self.gssapi_channel_bindings = "auto"
        # check if we get a ca bundle for verification
        self.ca_bundle = config_dic.get(
            "CAhandler", "ca_bundle", fallback=self.ca_bundle
        )
        self.krb5_principal = config_dic.get(
            "CAhandler", "krb5_principal", fallback=self.krb5_principal
        )
        self.krb5_keytab = config_dic.get(
            "CAhandler", "krb5_keytab", fallback=self.krb5_keytab
        )
        self.krb5_cache = config_dic.get(
            "CAhandler", "krb5_cache", fallback=self.krb5_cache
        )
        self.krb5_config = config_dic.get(
            "CAhandler", "krb5_config", fallback=self.krb5_config
        )
        self.krb5_kinit_path = config_dic.get(
            "CAhandler", "krb5_kinit_path", fallback=self.krb5_kinit_path
        )
        self.verify = config_dic.getboolean("CAhandler", "verify", fallback=True)

        # load enrollment config log
        (
            self.enrollment_config_log,
            self.enrollment_config_log_skip_list,
        ) = config_enroll_config_log_load(self.logger, config_dic)

        self._security_configuration_warnings_log()
        self.logger.debug("CAhandler._config_parameters_load() ended")

    def _security_configuration_warnings_log(self) -> None:
        """Log non-blocking security risk warnings for current handler settings."""
        self.logger.debug("CAhandler._security_configuration_warnings_log()")
        if self.verify is False:
            self.logger.warning(
                "TLS certificate verification is disabled (verify=False). "
                "Enrollment traffic to AD CS is vulnerable to MITM. "
                "Prefer ca_bundle / system trust."
            )
        if self.auth_method in ["basic", "ntlm"]:
            self.logger.warning(
                "Auth method '%s' is deprecated and will be removed in a future release. "
                "Please migrate to 'gssapi' (Kerberos).",
                self.auth_method,
            )
        self.logger.debug("CAhandler._security_configuration_warnings_log() ended")

    def _config_allowed_templates_load(self, config_dic: Dict[str, str]) -> None:
        """Load allowed_templates allowlist from config."""
        self.logger.debug("CAhandler._config_allowed_templates_load()")
        if "allowed_templates" not in config_dic["CAhandler"]:
            self.logger.warning(
                "allowed_templates is empty; any client-selected template is permitted. "
                "Configure allowed_templates to restrict enrollment templates."
            )
            self.logger.debug("CAhandler._config_allowed_templates_load() ended")
            return

        try:
            loaded = json.loads(config_dic.get("CAhandler", "allowed_templates"))
            if not isinstance(loaded, list):
                raise ValueError("allowed_templates must be a JSON list")
            self.allowed_templates = [str(item) for item in loaded]
        except Exception as err_:
            self.logger.warning(
                "Failed to parse allowed_templates from configuration: %s. "
                "Treating as empty allowlist.",
                err_,
            )
            self.allowed_templates = []

        if not self.allowed_templates:
            self.logger.warning(
                "allowed_templates is empty; any client-selected template is permitted. "
                "Configure allowed_templates to restrict enrollment templates."
            )
        self.logger.debug(
            "CAhandler._config_allowed_templates_load() ended with %s entries",
            len(self.allowed_templates),
        )

    def _config_ca_templates_check_load(self, config_dic: Dict[str, str]) -> None:
        """Load ca_templates_check mode (warn|on|off)."""
        self.logger.debug("CAhandler._config_ca_templates_check_load()")
        mode = config_dic.get(
            "CAhandler", "ca_templates_check", fallback=self.ca_templates_check
        )
        if isinstance(mode, str):
            mode = mode.lower()
        if mode in ["warn", "on", "off"]:
            self.ca_templates_check = mode
        else:
            self.logger.warning(
                "Invalid ca_templates_check '%s'; using 'warn'. "
                "Allowed values: warn, on, off.",
                mode,
            )
            self.ca_templates_check = "warn"
        self.logger.debug(
            "CAhandler._config_ca_templates_check_load() ended with %s",
            self.ca_templates_check,
        )

    def _config_proxy_load(self, config_dic: Dict[str, str]):
        """load hostname"""
        self.logger.debug("CAhandler._config_proxy_load()")

        if "DEFAULT" in config_dic and "proxy_server_list" in config_dic["DEFAULT"]:
            try:
                proxy_list = json.loads(config_dic.get("DEFAULT", "proxy_server_list"))
                proxy_server = proxy_check(self.logger, self.host, proxy_list)
                self.proxy = {"http": proxy_server, "https": proxy_server}
            except Exception as err_:
                self.logger.warning(
                    "Failed to load proxy_server_list from configuration: %s",
                    err_,
                )

        self.logger.debug("CAhandler._config_proxy_load() ended")

    def _config_load(self):
        """ " load config from file"""
        self.logger.debug("CAhandler._config_load()")
        config_dic = load_config(self.logger, "CAhandler")

        if "CAhandler" in config_dic:
            # load parameters from config dic
            self._config_hostname_load(config_dic)
            self._config_url_load(config_dic)
            self._config_user_load(config_dic)
            self._config_password_load(config_dic)
            self._config_kerberos_parameters_load(config_dic)
            self._config_parameters_load(config_dic)
            # load profiling
            self.eab_profiling, self.eab_handler = config_eab_profile_load(
                self.logger, config_dic
            )
            # load profiles
            self.profiles = config_profile_load(self.logger, config_dic)
            self._config_headerinfo_load(config_dic)

        # load proxy config
        self._config_proxy_load(config_dic)

        self.logger.debug("CAhandler._config_load() ended")

    def _config_kerberos_parameter_item_load(
        self,
        config_dic: Dict[str, str],
        current_value: Optional[str],
        cfg_key: str,
        cfg_var_key: str,
        env_load_error_msg: str,
    ) -> Optional[str]:
        """load one kerberos parameter from env variable and/or config"""
        loaded_value = current_value
        cahandler_cfg = config_dic["CAhandler"]

        if cfg_var_key in cahandler_cfg:
            try:
                loaded_value = os.environ[config_dic.get("CAhandler", cfg_var_key)]
            except Exception as err:
                self.logger.error(env_load_error_msg, err)

        if cfg_key in cahandler_cfg:
            loaded_value = config_dic.get("CAhandler", cfg_key)

        return loaded_value

    def _config_kerberos_parameters_load(self, config_dic: Dict[str, str]):
        """load kerberos related parameters from env or config"""
        self.logger.debug("CAhandler._config_kerberos_parameters_load()")
        if "CAhandler" not in config_dic:
            return

        self.krb5_principal = self._config_kerberos_parameter_item_load(
            config_dic,
            self.krb5_principal,
            "krb5_principal",
            "krb5_principal_variable",
            "Could not load krb5_principal_variable from environment: %s",
        )
        self.krb5_keytab = self._config_kerberos_parameter_item_load(
            config_dic,
            self.krb5_keytab,
            "krb5_keytab",
            "krb5_keytab_variable",
            "Could not load krb5_keytab_variable from environment: %s",
        )
        self.krb5_cache = self._config_kerberos_parameter_item_load(
            config_dic,
            self.krb5_cache,
            "krb5_cache",
            "krb5_cache_variable",
            "Could not load krb5_cache_variable from environment: %s",
        )
        self.krb5_config = self._config_kerberos_parameter_item_load(
            config_dic,
            self.krb5_config,
            "krb5_config",
            "krb5_config_variable",
            "Could not load krb5_config_variable from environment: %s",
        )
        self.krb5_kinit_path = self._config_kerberos_parameter_item_load(
            config_dic,
            self.krb5_kinit_path,
            "krb5_kinit_path",
            "krb5_kinit_path_variable",
            "Could not load krb5_kinit_path_variable from environment: %s",
        )
        self.logger.debug("CAhandler._config_kerberos_parameters_load() ended")

    def _kerberos_keytab_is_configured(self) -> bool:
        """check if keytab flow can be used"""
        self.logger.debug("CAhandler._kerberos_keytab_is_configured()")
        result = bool(self.krb5_principal and self.krb5_keytab)
        self.logger.debug("CAhandler._kerberos_keytab_is_configured() = %s", result)
        return result

    @contextmanager
    def _kerberos_runtime_environment(self):
        """Deprecated no-op kept for callers/tests; prefer explicit GSSAPI creds.

        Process-wide KRB5CCNAME/KRB5_CONFIG mutation is unsafe under threaded WSGI.
        Keytab enroll loads credentials from the ccache store and passes them to
        Certsrv via gssapi_creds instead.
        """
        self.logger.debug(
            "CAhandler._kerberos_runtime_environment() is a no-op; "
            "using explicit GSSAPI credentials"
        )
        yield
        self.logger.debug("CAhandler._kerberos_runtime_environment() ended")

    def _kerberos_cleanup_temporary_ccache(self):
        """remove temporary kerberos ccache if it was created by this handler"""
        if not self._krb5_cache_is_temporary or not self.krb5_cache:
            return

        try:
            os.unlink(self.krb5_cache)
            self.logger.debug(
                "Removed temporary kerberos ccache file: %s",
                self.krb5_cache,
            )
        except FileNotFoundError:
            self.logger.debug(
                "Temporary kerberos ccache file already removed: %s",
                self.krb5_cache,
            )
        except Exception as err:
            self.logger.warning(
                "Failed to remove temporary kerberos ccache file '%s': %s",
                self.krb5_cache,
                err,
            )
        finally:
            self._krb5_cache_is_temporary = False
            self.krb5_cache = None
            self._gssapi_creds = None

    @staticmethod
    def _kerberos_ccache_path(ccache_value: Optional[str]) -> Optional[str]:
        """Normalize FILE:/path and plain path forms for GSSAPI store lookups."""
        if not ccache_value:
            return None
        if ccache_value.startswith("FILE:"):
            return ccache_value.split("FILE:", maxsplit=1)[1]
        return ccache_value

    def _kerberos_gssapi_creds_from_cache(
        self,
    ) -> Tuple[Optional[object], Optional[str]]:
        """Load initiate GSSAPI credentials from the prepared ccache (no env)."""
        self.logger.debug("CAhandler._kerberos_gssapi_creds_from_cache()")
        if self.auth_method != "gssapi" or not self._kerberos_keytab_is_configured():
            return (None, None)

        ccache_file = self._kerberos_ccache_path(self.krb5_cache)
        if not ccache_file:
            return (
                None,
                "Kerberos ccache is not available for GSSAPI keytab authentication.",
            )

        try:
            gssapi = importlib.import_module("gssapi")
        except Exception as err:
            self.logger.error("Failed to import gssapi module: %s", err)
            return (None, "gssapi module is required for gssapi keytab authentication.")

        try:
            credentials_class = getattr(gssapi, "Credentials", None)
            if credentials_class is None:
                return (
                    None,
                    "gssapi.Credentials is required to load credentials from ccache.",
                )
            creds = credentials_class(usage="initiate", store={"ccache": ccache_file})
            self.logger.debug(
                "Loaded GSSAPI credentials from ccache store '%s'", ccache_file
            )
            return (creds, None)
        except Exception as err:
            self.logger.error(
                "Failed to load GSSAPI credentials from ccache '%s': %s",
                ccache_file,
                err,
            )
            return (
                None,
                "Failed to load GSSAPI credentials from Kerberos ccache.",
            )

    def _kerberos_acquire_with_gssapi_raw(
        self,
        gssapi: object,
        principal: object,
        ccache_file: str,
    ) -> bool:
        """acquire kerberos credentials using gssapi.raw.acquire_cred_from"""
        self.logger.debug("CAhandler._kerberos_acquire_with_gssapi_raw()")
        try:
            gssapi_raw = getattr(gssapi, "raw", None)
            raw_acquire = getattr(gssapi_raw, "acquire_cred_from", None)
            if not raw_acquire:
                self.logger.debug(
                    "gssapi.raw.acquire_cred_from is not available in this gssapi build"
                )
                return False

            store = {
                b"client_keytab": self.krb5_keytab.encode("utf-8"),
                b"ccache": ccache_file.encode("utf-8"),
            }
            raw_acquire(
                store=store,
                desired_name=principal,
                cred_usage="initiate",
            )
            self.logger.debug(
                "Kerberos credentials acquired using gssapi.raw.acquire_cred_from"
            )
            return True
        except Exception as err:
            self.logger.warning(
                "Failed to acquire kerberos credentials via gssapi.raw.acquire_cred_from: %s",
                err,
            )
            return False

    def _kerberos_acquire_with_gssapi_highlevel(
        self,
        gssapi: object,
        principal: object,
        ccache_file: str,
    ) -> bool:
        """acquire kerberos credentials using gssapi.Credentials.acquire"""
        self.logger.debug("CAhandler._kerberos_acquire_with_gssapi_highlevel()")
        try:
            credentials_class = getattr(gssapi, "Credentials", None)
            credentials_acquire = getattr(credentials_class, "acquire", None)
            if not credentials_acquire:
                self.logger.debug(
                    "gssapi.Credentials.acquire is not available in this gssapi build"
                )
                return False

            credentials_acquire(
                name=principal,
                usage="initiate",
                store={
                    "client_keytab": self.krb5_keytab,
                    "ccache": ccache_file,
                },
            )
            self.logger.debug(
                "Kerberos credentials acquired using gssapi.Credentials.acquire"
            )
            return True
        except Exception as err:
            self.logger.warning(
                "Failed to acquire kerberos credentials via gssapi.Credentials.acquire: %s",
                err,
            )
            return False

    def _kerberos_acquire_with_kinit(self, ccache_file: str) -> bool:
        """acquire kerberos credentials using kinit fallback"""
        self.logger.debug("CAhandler._kerberos_acquire_with_kinit()")
        kinit_cmd = self.krb5_kinit_path or "kinit"
        try:
            kinit_env = dict(os.environ)
            kinit_env["KRB5CCNAME"] = ccache_file
            if self.krb5_config:
                kinit_env["KRB5_CONFIG"] = self.krb5_config

            subprocess.run(
                [
                    kinit_cmd,
                    "-k",
                    "-t",
                    self.krb5_keytab,
                    self.krb5_principal,
                ],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=kinit_env,
                timeout=self.KINIT_TIMEOUT_SECONDS,
            )
            self.logger.debug("Kerberos credentials acquired using kinit fallback")
            return True
        except subprocess.TimeoutExpired:
            self.logger.error(
                "kinit timed out after %s seconds while acquiring kerberos credentials",
                self.KINIT_TIMEOUT_SECONDS,
            )
            return False
        except FileNotFoundError as err:
            self.logger.error("%s command not found: %s", kinit_cmd, err)
            return False
        except Exception as err:
            stderr = None
            if hasattr(err, "stderr") and err.stderr:
                stderr = err.stderr.decode("utf-8", errors="replace").strip()

            if stderr:
                self.logger.error(
                    "Failed to acquire kerberos credentials via kinit: %s",
                    stderr,
                )
            else:
                self.logger.error(
                    "Failed to acquire kerberos credentials via kinit: %s",
                    err,
                )
            return False

    def _kerberos_prepare_gssapi_backend(self) -> Optional[str]:
        """prepare kerberos credentials in python using gssapi/keytab"""
        self.logger.debug("CAhandler._kerberos_prepare_gssapi_backend()")
        if self.auth_method != "gssapi" or not self._kerberos_keytab_is_configured():
            return None

        if not os.path.isfile(self.krb5_keytab):
            self.logger.error(
                "Kerberos keytab file does not exist: %s", self.krb5_keytab
            )
            return "Kerberos keytab file does not exist."

        try:
            gssapi = importlib.import_module("gssapi")
        except Exception as err:
            self.logger.error("Failed to import gssapi module: %s", err)
            return "gssapi module is required for gssapi keytab authentication."

        ccache_file = self.krb5_cache
        self._krb5_cache_is_temporary = False
        if not ccache_file:
            ccache_fd, ccache_file = tempfile.mkstemp(prefix="acme2certifier_krb5cc_")
            os.close(ccache_fd)
            self.logger.debug(
                "No kerberos ccache configured, created temporary ccache file: %s",
                ccache_file,
            )
            self.krb5_cache = ccache_file
            self._krb5_cache_is_temporary = True

        if ccache_file.startswith("FILE:"):
            ccache_file = ccache_file.split("FILE:", maxsplit=1)[1]
            self.logger.debug(
                "Normalized kerberos ccache path from FILE: prefix: %s", ccache_file
            )
            self.krb5_cache = ccache_file

        if not os.path.exists(ccache_file):
            with open(ccache_file, "a", encoding="utf-8") as ccache_handle:
                ccache_handle.write("")

        self.logger.debug("Using kerberos ccache file: %s", ccache_file)

        try:
            principal = gssapi.Name(
                self.krb5_principal,
                gssapi.NameType.kerberos_principal,
            )
        except Exception as err:
            self.logger.error(
                "Failed to build kerberos principal from '%s': %s",
                self.krb5_principal,
                err,
            )
            return (
                "Failed to build kerberos principal for kerberos keytab authentication."
            )

        self.logger.debug(
            "Acquiring kerberos credentials for principal '%s' using keytab '%s'",
            self.krb5_principal,
            self.krb5_keytab,
        )

        if self._kerberos_acquire_with_gssapi_raw(gssapi, principal, ccache_file):
            return None

        if self._kerberos_acquire_with_gssapi_highlevel(gssapi, principal, ccache_file):
            return None

        if self._kerberos_acquire_with_kinit(ccache_file):
            return None

        return "Failed to acquire kerberos credentials via gssapi/keytab."

    def _credentials_are_configured(self) -> bool:
        """check credential completeness based on selected auth mode"""
        self.logger.debug("CAhandler._credentials_are_configured()")
        if self.auth_method == "gssapi" and self._kerberos_keytab_is_configured():
            return True
        self.logger.debug(
            "CAhandler._credentials_are_configured() ended with user/password check"
        )
        return bool(self.user and self.password)

    def _pkcs7_to_pem(self, pkcs7_content: str, outform: str = "string") -> List[str]:
        """convert pkcs7 to pem"""
        self.logger.debug("CAhandler._pkcs7_to_pem()")

        result = pkcs7_to_pem(self.logger, pkcs7_content, outform)

        self.logger.debug("Certificate._pkcs7_to_pem() ended")
        return result

    def _template_name_get(self, csr: str) -> str:
        """get templaate from csr"""
        self.logger.debug("CAhandler._template_name_get()")
        template_name = None

        # parse profileid from http_header
        header_info = header_info_get(self.logger, csr=csr)
        if header_info:
            try:
                header_info_dic = json.loads(header_info[-1]["header_info"])
                if self.header_info_field in header_info_dic:
                    for ele in header_info_dic[self.header_info_field].split(" "):
                        if self.profile_mapping_field in ele.lower():
                            template_name = ele.split("=")[1]
                            break
            except Exception as err:
                self.logger.error("Failed to parse template from header_info: %s", err)

        self.logger.debug(
            "CAhandler._template_name_get() ended with: %s", template_name
        )
        return template_name

    def _allowed_templates_check(self) -> Optional[str]:
        """Enforce configured allowed_templates allowlist."""
        self.logger.debug(
            "CAhandler._allowed_templates_check(%s)", self.template
        )
        if not self.allowed_templates:
            return None
        if self.template not in self.allowed_templates:
            self.logger.error(
                "Template '%s' is not in allowed_templates: %s",
                self.template,
                self.allowed_templates,
            )
            return f"Template '{self.template}' is not allowed"
        self.logger.debug("CAhandler._allowed_templates_check() ended")
        return None

    def _ca_templates_cache_key(self) -> str:
        """Cache key for CA-reported templates."""
        return self.url or self.host or ""

    def _ca_templates_get(self, ca_server: object) -> List[str]:
        """Fetch CA templates with a process-wide thread-safe cache."""
        cache_key = self._ca_templates_cache_key()
        with self._ca_templates_lock:
            cached = self._ca_templates_cache.get(cache_key)
            if cached is not None:
                self.logger.debug(
                    "Using cached CA templates for %s (%s entries)",
                    cache_key,
                    len(cached),
                )
                return list(cached)

        try:
            templates = ca_server.get_templates()
            if not isinstance(templates, list):
                templates = []
        except Exception as err_:
            self.logger.warning(
                "Failed to fetch CA templates from Web Enrollment: %s", err_
            )
            return []

        with self._ca_templates_lock:
            self._ca_templates_cache[cache_key] = list(templates)
        self.logger.debug(
            "Cached %s CA templates for %s", len(templates), cache_key
        )
        return list(templates)

    def _ca_templates_membership_check(self, ca_server: object) -> Optional[str]:
        """Compare enrollment template against CA-reported Web Enrollment list."""
        self.logger.debug(
            "CAhandler._ca_templates_membership_check(mode=%s, template=%s)",
            self.ca_templates_check,
            self.template,
        )
        if self.ca_templates_check == "off":
            return None

        ca_templates = self._ca_templates_get(ca_server)
        if not ca_templates:
            self.logger.warning(
                "CA template list is empty or unavailable; continuing without "
                "CA-side template membership check."
            )
            return None

        if self.template in ca_templates:
            self.logger.debug(
                "CAhandler._ca_templates_membership_check() ended: template present"
            )
            return None

        message = (
            f"Template '{self.template}' was not found in CA Web Enrollment "
            f"templates ({len(ca_templates)} reported)"
        )
        if self.ca_templates_check == "on":
            self.logger.error(message)
            return message

        self.logger.warning("%s; continuing (ca_templates_check=warn)", message)
        return None

    def _csr_process(self, ca_server, csr: str) -> Tuple[str, str, str]:

        # recode csr
        csr = textwrap.fill(b64_url_recode(self.logger, csr), 64) + "\n"
        error = None

        # get ca_chain
        try:
            ca_pkcs7 = convert_byte_to_string(ca_server.get_chain(encoding="b64"))
            ca_pem = self._pkcs7_to_pem(ca_pkcs7)
            # replace crlf with lf
            # ca_pem = ca_pem.replace('\r\n', '\n')
        except Exception as err_:
            ca_pem = None
            self.logger.error("Failed to get CA certificate chain: %s", err_)

        try:
            cert_p2b = ca_server.get_cert(csr, self.template)
            cert_raw = convert_byte_to_string(cert_p2b)
            # replace crlf with lf
            cert_raw = cert_raw.replace("\r\n", "\n")
        except Exception as err_:
            cert_raw = None
            # Keep ACME/client-visible detail short even when ca_error_details_forward
            # is enabled; full CA/auth exception text stays in the server log.
            error = self.CERT_FETCH_ERROR
            self.logger.error("Failed to enroll certificate from CA: %s", err_)

        # create bundle
        if cert_raw:
            error, cert_bundle, cert_raw = self._cert_bundle_create(ca_pem, cert_raw)
        else:
            cert_bundle = None

        return (error, cert_bundle, cert_raw)

    def _gssapi_channel_bindings_resolve(self) -> Tuple[Optional[str], Optional[str]]:
        """Resolve gssapi_channel_bindings mode to Certsrv channel_bindings value."""
        self.logger.debug(
            "CAhandler._gssapi_channel_bindings_resolve(%s)",
            self.gssapi_channel_bindings,
        )
        if self.auth_method != "gssapi" or self.gssapi_channel_bindings == "off":
            return (None, None)

        supported = gssapi_channel_bindings_supported()
        if self.gssapi_channel_bindings == "on":
            if not supported:
                return (
                    None,
                    "gssapi_channel_bindings=on requires requests-gssapi >= 1.4.0 "
                    "with channel_bindings support.",
                )
            return (CHANNEL_BINDINGS_TLS_SERVER_END_POINT, None)

        # auto
        if supported:
            self.logger.info(
                "Enabling GSSAPI channel bindings (%s)",
                CHANNEL_BINDINGS_TLS_SERVER_END_POINT,
            )
            return (CHANNEL_BINDINGS_TLS_SERVER_END_POINT, None)

        self.logger.warning(
            "requests-gssapi does not support channel_bindings; continuing without. "
            "For EPA Required, upgrade to requests-gssapi >= 1.4.0 or set IIS "
            "Extended Protection to Accept."
        )
        return (None, None)

    def _parameter_overwrite(self, _csr: str):
        """overwrite overwrite krb5.conf or user-template"""
        if self.krb5_config:
            self.logger.info("Load krb5config from %s", self.krb5_config)

    def _enroll(self, csr: str) -> Tuple[str, str, str]:
        """enroll certificate"""
        self.logger.debug("CAhandler._enroll()")
        channel_bindings, channel_bindings_error = (
            self._gssapi_channel_bindings_resolve()
        )
        if channel_bindings_error:
            self.logger.error(channel_bindings_error)
            return (channel_bindings_error, None, None)

        # setup certserv
        ca_server = Certsrv(
            self.host,
            self.url,
            self.user,
            self.password,
            self.auth_method,
            self.ca_bundle,
            verify=self.verify,
            proxies=self.proxy,
            channel_bindings=channel_bindings,
            gssapi_creds=self._gssapi_creds,
        )

        error = None
        cert_bundle = None
        cert_raw = None

        # check connection and credentials
        auth_check = self._check_credentials(ca_server)

        if self.enrollment_config_log:
            enrollment_config_log(
                self.logger,
                self,
                list(self.enrollment_config_log_skip_list)
                + [
                    "password",
                    "krb5_keytab",
                    "krb5_cache",
                    "krb5_config",
                    "krb5_kinit_path",
                    "_gssapi_creds",
                ],
            )

        if auth_check:
            ca_template_error = self._ca_templates_membership_check(ca_server)
            if ca_template_error:
                self.logger.error(
                    "CA template membership check failed: %s", ca_template_error
                )
                return (ca_template_error, None, None)
            # enroll certificate
            error, cert_bundle, cert_raw = self._csr_process(ca_server, csr)
        else:
            self.logger.error("Connection or credential check failed for CA server.")
            error = "Connection or Credentialcheck failed."

        self.logger.debug("CAhandler._enroll() ended with error: %s", error)
        return (error, cert_bundle, cert_raw)

    def enroll(self, csr: str) -> Tuple[str, str, str, bool]:
        """enroll certificate from via MS certsrv"""
        self.logger.debug("CAhandler.enroll(%s)", self.template)
        cert_bundle = None
        error = None
        cert_raw = None
        self._gssapi_creds = None

        self._parameter_overwrite(csr)

        if not (
            (self.host or self.url)
            and self._credentials_are_configured()
            and self.template
        ):
            self.logger.error("%s", CONFIGURATION_ERROR_DETAIL)
            error = CONFIGURATION_ERROR_DETAIL
            self.logger.debug("Certificate.enroll() ended")
            return (error, cert_bundle, cert_raw, None)

        kerberos_error = self._kerberos_prepare_gssapi_backend()
        if kerberos_error:
            self.logger.error("Kerberos backend setup failed: %s", kerberos_error)
            self._kerberos_cleanup_temporary_ccache()
            return (kerberos_error, None, None, None)

        gssapi_creds, gssapi_creds_error = self._kerberos_gssapi_creds_from_cache()
        if gssapi_creds_error:
            self.logger.error("Kerberos credential load failed: %s", gssapi_creds_error)
            self._kerberos_cleanup_temporary_ccache()
            return (gssapi_creds_error, None, None, None)
        self._gssapi_creds = gssapi_creds

        # check for eab profiling and header_info
        error = eab_profile_header_info_check(
            self.logger, self, csr, self.profile_mapping_field
        )
        if error:
            self.logger.error("EAB profile check failed: %s", error)
        else:
            error = self._allowed_templates_check()
            if error:
                self.logger.error("Template allowlist check failed: %s", error)
            else:
                # enroll certificate (explicit GSSAPI creds; no process env mutation)
                error, cert_bundle, cert_raw = self._enroll(csr)

        self._kerberos_cleanup_temporary_ccache()
        self.logger.debug("Certificate.enroll() ended")
        return (error, cert_bundle, cert_raw, None)

    def handler_check(self):
        """check if handler is ready"""
        self.logger.debug("CAhandler.check()")
        required = ["host", self.profile_mapping_field]
        if not self._kerberos_keytab_is_configured():
            required.extend(["user", "password"])

        error = handler_config_check(self.logger, self, required)
        self.logger.debug("CAhandler.check() ended with %s", error)
        return error

    def poll(
        self, _cert_name: str, poll_identifier: str, _csr: str
    ) -> Tuple[str, str, str, str, bool]:
        """poll status of pending CSR and download certificates"""
        self.logger.debug("CAhandler.poll()")

        error = "Method not implemented."
        cert_bundle = None
        cert_raw = None
        rejected = False

        self.logger.debug("CAhandler.poll() ended")
        return (error, cert_bundle, cert_raw, poll_identifier, rejected)

    def revoke(
        self, _cert: str, _rev_reason: str, _rev_date: str
    ) -> Tuple[int, str, str]:
        """revoke certificate"""
        self.logger.debug("CAhandler.tsg_id_lookup()")
        # get serial from pem file and convert to formated hex

        code = 500
        message = "urn:ietf:params:acme:error:serverInternal"
        detail = "Revocation is not supported."

        return (code, message, detail)

    def trigger(self, _payload: str) -> Tuple[int, str, str]:
        """process trigger message and return certificate"""
        self.logger.debug("CAhandler.trigger()")

        error = "Method not implemented."
        cert_bundle = None
        cert_raw = None

        self.logger.debug("CAhandler.trigger() ended with error: %s", error)
        return (error, cert_bundle, cert_raw)
