# -*- coding: utf-8 -*-
"""EAB handler using HashiCorp Vault / OpenBao KV v2."""

from __future__ import print_function

import json
import time
from logging import Logger
from typing import Any, Dict, List, Optional, Tuple

from acme2certifier.acme_srv.helper import (
    ca_api_request,
    config_ca_bundle_load,
    config_number_load,
    config_option_load,
    config_proxy_load,
    load_config,
)
from acme2certifier.acme_srv.helpers.eab_profile import EabProfileMixin
from acme2certifier.eabhandlers.base import EABhandlerBase

CONTENT_TYPE = "application/json"


class EABhandler(EABhandlerBase, EabProfileMixin):
    """EAB handler backed by HashiCorp Vault or OpenBao KV v2."""

    def __init__(self, logger: Logger = None):
        super().__init__(logger)
        self.vault_url: Optional[str] = None
        self.vault_mount: str = "secret"
        self.vault_prefix: str = "acme/eab"
        self.vault_token: Optional[str] = None
        self.vault_secret_key: str = "value"
        self.request_timeout: int = 20
        self.request_retries: int = 3
        self.request_retry_backoff: float = 2.0
        self.cache_ttl: int = 60
        self.ca_bundle: Any = True
        self.proxy: Dict[str, str] = {}
        self._cache: Dict[str, Tuple[float, Dict[str, Any]]] = {}

    def __enter__(self):
        """Makes EABhandler a Context Manager."""
        self._config_load()
        return self

    def _config_load(self) -> None:
        """Load Vault / OpenBao settings from the EABhandler config section."""
        self.logger.debug("EABhandler._config_load()")
        config_dic = load_config(self.logger, "EABhandler")
        if "EABhandler" in config_dic:
            self.vault_url = config_dic.get(
                "EABhandler", "vault_url", fallback=self.vault_url
            )
            self.vault_mount = config_dic.get(
                "EABhandler", "vault_mount", fallback=self.vault_mount
            )
            self.vault_prefix = config_dic.get(
                "EABhandler", "vault_prefix", fallback=self.vault_prefix
            )
            self.vault_secret_key = config_dic.get(
                "EABhandler", "vault_secret_key", fallback=self.vault_secret_key
            )
            self.vault_token = config_option_load(
                self.logger,
                config_dic,
                "vault_token",
                section="EABhandler",
                current=self.vault_token,
            )
            self.request_timeout = config_number_load(
                self.logger,
                config_dic,
                "request_timeout",
                cast=int,
                current=self.request_timeout,
                section="EABhandler",
            )
            self.request_retries = config_number_load(
                self.logger,
                config_dic,
                "request_retries",
                cast=int,
                current=self.request_retries,
                section="EABhandler",
            )
            self.request_retry_backoff = config_number_load(
                self.logger,
                config_dic,
                "request_retry_backoff",
                cast=float,
                current=self.request_retry_backoff,
                section="EABhandler",
            )
            self.cache_ttl = config_number_load(
                self.logger,
                config_dic,
                "cache_ttl",
                cast=int,
                current=self.cache_ttl,
                section="EABhandler",
            )
            self.ca_bundle = config_ca_bundle_load(
                self.logger,
                config_dic,
                current=self.ca_bundle,
                section="EABhandler",
            )
        self.proxy = config_proxy_load(self.logger, config_dic, self.vault_url or "")
        self.logger.debug("EABhandler._config_load() ended")

    def _secret_url(self, kid: str) -> str:
        """Build KV v2 data URL for a kid."""
        prefix = (self.vault_prefix or "").strip("/")
        mount = (self.vault_mount or "secret").strip("/")
        base = (self.vault_url or "").rstrip("/")
        return f"{base}/v1/{mount}/data/{prefix}/{kid}"

    def _list_url(self) -> str:
        """Build KV v2 metadata list URL for the configured prefix."""
        prefix = (self.vault_prefix or "").strip("/")
        mount = (self.vault_mount or "secret").strip("/")
        base = (self.vault_url or "").rstrip("/")
        return f"{base}/v1/{mount}/metadata/{prefix}?list=true"

    def _api_get(self, url: str) -> Tuple[int, Any]:
        """GET from Vault / OpenBao with token auth."""
        headers = {
            "Content-Type": CONTENT_TYPE,
            "X-Vault-Token": self.vault_token,
        }
        return ca_api_request(
            self.logger,
            "get",
            url,
            headers=headers,
            proxy=self.proxy,
            timeout=self.request_timeout,
            payload=None,
            verify=self.ca_bundle,
            retries=self.request_retries,
            retry_backoff=self.request_retry_backoff,
        )

    def _payload_normalize(self, data: Any) -> Optional[Dict[str, Any]]:
        """Normalize KV secret data to a profile dict with at least ``hmac``."""
        self.logger.debug("EABhandler._payload_normalize()")
        if data is None:
            return None

        if isinstance(data, str):
            stripped = data.strip()
            if stripped.startswith("{"):
                try:
                    parsed = json.loads(stripped)
                except Exception as err:
                    self.logger.error("Failed to parse secret JSON string: %s", err)
                    return None
                return self._payload_normalize(parsed)
            return {"hmac": data}

        if not isinstance(data, dict):
            self.logger.warning("Unsupported secret payload type: %s", type(data))
            return None

        secret_key = self.vault_secret_key or "value"
        if secret_key in data and secret_key != "hmac":
            return self._payload_normalize(data[secret_key])

        if "hmac" in data:
            return data

        if len(data) == 1:
            only_value = next(iter(data.values()))
            if isinstance(only_value, str):
                return self._payload_normalize(only_value)

        self.logger.warning("Secret payload missing hmac / %s field", secret_key)
        return None

    def _cache_get(self, kid: str) -> Optional[Dict[str, Any]]:
        """Return a cached profile for kid if still valid."""
        if kid not in self._cache:
            return None
        expires_at, profile = self._cache[kid]
        if time.time() < expires_at:
            return profile
        del self._cache[kid]
        return None

    def _cache_set(self, kid: str, profile: Dict[str, Any]) -> None:
        """Store profile in the short TTL cache (disabled when cache_ttl <= 0)."""
        if self.cache_ttl <= 0:
            return
        self._cache[kid] = (time.time() + self.cache_ttl, profile)

    def _kid_secret_get(self, kid: str) -> Optional[Dict[str, Any]]:
        """Fetch and normalize one kid secret from Vault / OpenBao."""
        self.logger.debug("EABhandler._kid_secret_get(%s)", kid)
        cached = self._cache_get(kid)
        if cached is not None:
            self.logger.debug("EABhandler._kid_secret_get() cache hit")
            return cached

        if not kid or not self.vault_url or not self.vault_token:
            self.logger.warning(
                "MAC key retrieval failed: kid=%s vault_url=%s token_set=%s",
                kid,
                bool(self.vault_url),
                bool(self.vault_token),
            )
            return None

        try:
            code, content = self._api_get(self._secret_url(kid))
        except Exception as err:
            self.logger.error("Vault request failed for kid=%s: %s", kid, err)
            return None

        if code != 200 or not isinstance(content, dict):
            self.logger.warning(
                "MAC key retrieval failed: kid=%s http_code=%s", kid, code
            )
            return None

        raw_data = content.get("data", {})
        if isinstance(raw_data, dict):
            raw_data = raw_data.get("data", raw_data)

        profile = self._payload_normalize(raw_data)
        if profile is None:
            self.logger.warning(
                "MAC key retrieval failed: kid=%s could not normalize payload", kid
            )
            return None
        if "hmac" not in profile:
            self.logger.warning(
                "MAC key retrieval failed: kid=%s missing hmac in profile", kid
            )
            return None

        self._cache_set(kid, profile)
        self.logger.debug("EABhandler._kid_secret_get() ended with profile")
        return profile

    def _kids_list(self) -> List[str]:
        """List kid names under the configured KV prefix."""
        self.logger.debug("EABhandler._kids_list()")
        if not self.vault_url or not self.vault_token:
            return []
        try:
            code, content = self._api_get(self._list_url())
        except Exception as err:
            self.logger.error("Vault list failed: %s", err)
            return []
        if code != 200 or not isinstance(content, dict):
            self.logger.warning("Vault list failed: http_code=%s", code)
            return []
        keys = content.get("data", {}).get("keys", []) if content.get("data") else []
        kids = [key.rstrip("/") for key in keys if key and not str(key).endswith("/")]
        self.logger.debug("EABhandler._kids_list() ended with %s kids", len(kids))
        return kids

    def key_file_load(self) -> Dict[str, Any]:
        """Load kid -> profile mappings (list prefix, then per-kid read)."""
        self.logger.debug("EABhandler.key_file_load()")
        data_dic: Dict[str, Any] = {}
        for kid in self._kids_list():
            profile = self._kid_secret_get(kid)
            if profile is not None:
                data_dic[kid] = profile
        self.logger.debug("EABhandler.key_file_load() ended with %s", bool(data_dic))
        return data_dic

    def mac_key_get(self, kid: str = None) -> Optional[str]:
        """Look up the MAC key for an external account binding kid."""
        self.logger.debug("EABhandler.mac_key_get(%s)", kid)
        mac_key = None
        if not kid:
            self.logger.warning("MAC key retrieval failed: kid=%s", kid)
        else:
            profile = self._kid_secret_get(kid)
            if profile and "hmac" in profile:
                mac_key = profile["hmac"]
        self.logger.debug("EABhandler.mac_key_get() ended with: %s", bool(mac_key))
        return mac_key
