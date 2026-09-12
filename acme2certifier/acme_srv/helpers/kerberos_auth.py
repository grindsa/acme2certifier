# -*- coding: utf-8 -*-
"""Shared Kerberos/GSSAPI helpers for MS-CertSrv and MS-ICPR CA handlers."""

from __future__ import annotations

import importlib
import logging
import os
import subprocess
import sys
import tempfile
from typing import Any, Dict, List, Optional

from .utils import kerberos_kinit_command_resolve

KRB5_CCACHE_FILE_PREFIX = "FILE:"
KINIT_TIMEOUT_SECONDS = 30
KRB5_CONFIG_MISSING_LOG = "Configured krb5_config does not exist: %s"


class KerberosAuthMixin:
    """Keytab/ccache/kinit helpers shared by Microsoft CA handlers.

    Handler-module ``os`` / ``subprocess`` / ``importlib`` / ``tempfile`` and
    ``kerberos_kinit_command_resolve`` are used so existing unit-test patches
    keep working.
    """

    logger: logging.Logger
    krb5_principal: Optional[str]
    krb5_keytab: Optional[str]
    krb5_cache: Optional[str]
    krb5_config: Optional[str]
    krb5_kinit_path: str
    user: Optional[str]
    password: Optional[str]
    _krb5_cache_is_temporary: bool

    KRB5_CCACHE_FILE_PREFIX = KRB5_CCACHE_FILE_PREFIX
    KINIT_TIMEOUT_SECONDS = KINIT_TIMEOUT_SECONDS
    KRB5_CONFIG_MISSING_LOG = KRB5_CONFIG_MISSING_LOG
    _KRB5_CACHE_EXTRA_ATTR: Optional[str] = None
    _KRB5_KINIT_REQUIRE_CONFIG_FILE = False

    def _kerberos_handler_attr(self, name: str, fallback: Any) -> Any:
        """Return a symbol from the concrete handler module when present."""
        mod = sys.modules.get(self.__class__.__module__)
        if mod is not None and hasattr(mod, name):
            return getattr(mod, name)
        return fallback

    def _kerberos_keytab_is_configured(self) -> bool:
        """check if keytab flow can be used"""
        self.logger.debug("CAhandler._kerberos_keytab_is_configured()")
        result = bool(self.krb5_principal and self.krb5_keytab)
        self.logger.debug("CAhandler._kerberos_keytab_is_configured() = %s", result)
        return result

    def _kerberos_username_from_principal(self, principal: str) -> Optional[str]:
        """extract username from kerberos principal"""
        self.logger.debug("CAhandler._kerberos_username_from_principal()")
        if not principal:
            self.logger.error(
                "Kerberos principal is not configured, cannot extract username."
            )
            return None
        self.logger.debug("Extracting username from kerberos principal '%s'", principal)
        return principal.split("@", maxsplit=1)[0]

    def _kerberos_cleanup_temporary_ccache(self):
        """remove temporary kerberos ccache if it was created by this handler"""
        if not self._krb5_cache_is_temporary or not self.krb5_cache:
            return

        os_mod = self._kerberos_handler_attr("os", os)
        try:
            os_mod.unlink(self.krb5_cache)
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
            extra = self._KRB5_CACHE_EXTRA_ATTR
            if extra:
                setattr(self, extra, None)

    @staticmethod
    def _kerberos_ccache_path(ccache_value: Optional[str]) -> Optional[str]:
        """Normalize FILE:/path and plain path forms for GSSAPI store lookups."""
        if not ccache_value:
            return None
        if ccache_value.startswith(KRB5_CCACHE_FILE_PREFIX):
            return ccache_value.split(KRB5_CCACHE_FILE_PREFIX, maxsplit=1)[1]
        return ccache_value

    def _kerberos_config_path_resolve(self) -> Optional[str]:
        """Resolve configured krb5_config to an absolute existing path."""
        if not self.krb5_config:
            return None
        os_mod = self._kerberos_handler_attr("os", os)
        candidates = [self.krb5_config]
        if not os_mod.path.isabs(self.krb5_config):
            candidates.append(os_mod.path.abspath(self.krb5_config))
        for candidate in candidates:
            if os_mod.path.isfile(candidate):
                return os_mod.path.abspath(candidate)
        return None

    def _kerberos_ccache_prepare(self) -> str:
        """Ensure a ccache path exists; create a temporary file when unset."""
        os_mod = self._kerberos_handler_attr("os", os)
        tempfile_mod = self._kerberos_handler_attr("tempfile", tempfile)
        ccache_file = self._kerberos_ccache_path(self.krb5_cache)
        self._krb5_cache_is_temporary = False
        if not ccache_file:
            ccache_fd, ccache_file = tempfile_mod.mkstemp(
                prefix="acme2certifier_krb5cc_"
            )
            os_mod.close(ccache_fd)
            self.logger.debug(
                "No kerberos ccache configured, created temporary ccache file: %s",
                ccache_file,
            )
            self.krb5_cache = ccache_file
            self._krb5_cache_is_temporary = True
        else:
            self.krb5_cache = ccache_file

        if not os_mod.path.exists(ccache_file):
            with open(ccache_file, "a", encoding="utf-8") as ccache_handle:
                ccache_handle.write("")

        self.logger.debug("Using kerberos ccache file: %s", ccache_file)
        return ccache_file

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

    def _kerberos_kinit_env(self, ccache_file: str) -> Optional[Dict[str, str]]:
        """Build kinit subprocess env. None if configured krb5_config is missing."""
        os_mod = self._kerberos_handler_attr("os", os)
        kinit_env = dict(os_mod.environ)
        kinit_env["KRB5CCNAME"] = ccache_file
        krb5_config = self._kerberos_config_path_resolve()
        if krb5_config:
            kinit_env["KRB5_CONFIG"] = krb5_config
            return kinit_env
        if self.krb5_config:
            if self._KRB5_KINIT_REQUIRE_CONFIG_FILE:
                self.logger.error(self.KRB5_CONFIG_MISSING_LOG, self.krb5_config)
                return None
            self.logger.warning(
                "Configured krb5_config does not exist: %s. Ignoring for kinit fallback.",
                self.krb5_config,
            )
        return kinit_env

    def _kerberos_kinit_error_text(self, err: Exception) -> Optional[str]:
        """Return stripped stderr from a kinit subprocess exception."""
        stderr = getattr(err, "stderr", None)
        if not stderr:
            return None
        if isinstance(stderr, bytes):
            return stderr.decode("utf-8", errors="replace").strip()
        return str(stderr).strip()

    def _kerberos_kinit_run(
        self,
        args: List[str],
        kinit_env: Dict[str, str],
        failure_action: str,
        stdin_input: Optional[str] = None,
        text: bool = False,
    ) -> bool:
        """Run kinit and log failures. Returns True on success."""
        subprocess_mod = self._kerberos_handler_attr("subprocess", subprocess)
        try:
            subprocess_mod.run(  # nosec B603
                args,
                check=True,
                stdout=subprocess_mod.PIPE,
                stderr=subprocess_mod.PIPE,
                env=kinit_env,
                timeout=self.KINIT_TIMEOUT_SECONDS,
                input=stdin_input,
                text=text,
            )
            return True
        except subprocess_mod.TimeoutExpired:
            self.logger.error(
                "kinit timed out after %s seconds while acquiring kerberos credentials",
                self.KINIT_TIMEOUT_SECONDS,
            )
            return False
        except FileNotFoundError as err:
            self.logger.error("%s command not found: %s", args[0], err)
            return False
        except Exception as err:
            detail = self._kerberos_kinit_error_text(err)
            self.logger.error(
                "Failed to acquire kerberos credentials via %s: %s",
                failure_action,
                detail if detail else err,
            )
            return False

    def _kerberos_acquire_with_kinit(self, ccache_file: str) -> bool:
        """acquire kerberos credentials using kinit fallback"""
        self.logger.debug("CAhandler._kerberos_acquire_with_kinit()")
        resolve = self._kerberos_handler_attr(
            "kerberos_kinit_command_resolve", kerberos_kinit_command_resolve
        )
        kinit_cmd = resolve(self.logger, self.krb5_kinit_path)
        if not kinit_cmd:
            return False
        kinit_env = self._kerberos_kinit_env(ccache_file)
        if kinit_env is None:
            return False
        if not self._kerberos_kinit_run(
            [kinit_cmd, "-k", "-t", self.krb5_keytab, self.krb5_principal],
            kinit_env,
            "kinit",
        ):
            return False
        self.logger.debug("Kerberos credentials acquired using kinit fallback")
        return True

    def _kerberos_acquire_with_kinit_password(self, ccache_file: str) -> bool:
        """Acquire Kerberos credentials via password kinit (subprocess-local env)."""
        self.logger.debug("CAhandler._kerberos_acquire_with_kinit_password()")
        resolve = self._kerberos_handler_attr(
            "kerberos_kinit_command_resolve", kerberos_kinit_command_resolve
        )
        kinit_cmd = resolve(self.logger, self.krb5_kinit_path)
        if not kinit_cmd:
            return False
        if not self.user or not self.password:
            self.logger.error(
                "user/password are required for GSSAPI password kinit authentication"
            )
            return False

        kinit_env = self._kerberos_kinit_env(ccache_file)
        if kinit_env is None:
            return False
        if not self._kerberos_kinit_run(
            [kinit_cmd, self.user],
            kinit_env,
            "password kinit",
            stdin_input=f"{self.password}\n",
            text=True,
        ):
            return False
        self.logger.debug(
            "Kerberos credentials acquired using password kinit for principal '%s'",
            self.user,
        )
        return True

    def _kerberos_acquire_keytab_credentials(
        self, *, gssapi_required_error: str
    ) -> Optional[str]:
        """Import GSSAPI, prepare a ccache, and acquire initiator creds from keytab."""
        os_mod = self._kerberos_handler_attr("os", os)
        importlib_mod = self._kerberos_handler_attr("importlib", importlib)

        if not os_mod.path.isfile(self.krb5_keytab):
            self.logger.error(
                "Kerberos keytab file does not exist: %s", self.krb5_keytab
            )
            return "Kerberos keytab file does not exist."

        try:
            gssapi = importlib_mod.import_module("gssapi")
        except Exception as err:
            self.logger.error("Failed to import gssapi module: %s", err)
            return gssapi_required_error

        ccache_file = self._kerberos_ccache_prepare()

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
