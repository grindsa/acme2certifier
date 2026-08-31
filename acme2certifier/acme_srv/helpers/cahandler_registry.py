# -*- coding: utf-8 -*-
"""CA handler registry for single- and multi-handler mode."""

from __future__ import annotations

import json
import logging
import re
from typing import Any, Dict, List, Optional, Type

from .config import (
    cahandler_config_section_reset,
    cahandler_config_section_set,
    load_config,
)
from .plugin_loader import ca_handler_load_from_section


class _BoundCAHandlerInstance:
    """Activate bound section for ``load_config()`` during handler context."""

    def __init__(self, handler: Any, section: str) -> None:
        self._handler = handler
        self._section = section
        self._token = None

    def __enter__(self) -> Any:
        self._token = cahandler_config_section_set(self._section)
        return self._handler.__enter__()

    def __exit__(self, *args: Any) -> Any:
        try:
            return self._handler.__exit__(*args)
        finally:
            if self._token is not None:
                cahandler_config_section_reset(self._token)
                self._token = None

    def __getattr__(self, item: str) -> Any:
        return getattr(self._handler, item)


def _domain_matches(entry: str, patterns: List[str]) -> bool:
    """Return True if ``entry`` matches any regex in ``patterns``."""
    if not entry or not patterns:
        return False
    for pattern in patterns:
        regex = pattern
        if regex.startswith("*."):
            regex = regex.replace("*.", ".", 1)
        if re.search(regex, entry):
            return True
    return False


class BoundCAHandler:
    """Factory binding a CAhandler class to a named config section."""

    def __init__(
        self,
        handler_cls: Type[Any],
        section: str,
        name: str,
    ) -> None:
        self.handler_cls = handler_cls
        self.section = section
        self.name = name

    def __call__(self, debug: bool, logger: logging.Logger) -> Any:
        inst = self.handler_cls(debug, logger)
        inst.config_section = self.section
        inst.cahandler_registry_name = self.name
        return _BoundCAHandlerInstance(inst, self.section)

    def __getattr__(self, item: str) -> Any:
        return getattr(self.handler_cls, item)


class CAHandlerRegistry:
    """Build and resolve CA handlers in single- or multi-handler mode."""

    SECTION_PREFIX = "CAhandler:"

    def __init__(self, logger: logging.Logger) -> None:
        self.logger = logger
        self.multi_handler = False
        self.default_name: Optional[str] = None
        self.handlers: Dict[str, Dict[str, Any]] = {}
        self.profile_cahandler: Dict[str, str] = {}
        self._single_bound: Optional[BoundCAHandler] = None
        self._startup_error: Optional[str] = None

    def load(self, config_dic: Optional[Any] = None) -> "CAHandlerRegistry":
        """Parse acme_srv config and populate the registry."""
        self.logger.debug("CAHandlerRegistry.load()")
        if config_dic is None:
            config_dic = load_config(self.logger)

        if "CAhandler" not in config_dic:
            self._startup_error = "CAhandler configuration missing in config file"
            self.logger.error("%s", self._startup_error)
            return self

        try:
            self.multi_handler = config_dic.getboolean(
                "CAhandler", "multi_handler", fallback=False
            )
        except Exception as err:
            self.logger.warning("Failed to parse multi_handler: %s", err)
            self.multi_handler = False

        if not self.multi_handler:
            module = ca_handler_load_from_section(
                self.logger, config_dic, "CAhandler"
            )
            if module is not None:
                self._single_bound = BoundCAHandler(
                    module.CAhandler, "CAhandler", "default"
                )
            return self

        if config_dic.get("CAhandler", "handler_module", fallback=None) or config_dic.get(
            "CAhandler", "handler_file", fallback=None
        ):
            self.logger.warning(
                "multi_handler enabled: handler_module/handler_file on [CAhandler] "
                "are ignored; use [CAhandler:<name>] sections"
            )

        self.default_name = config_dic.get(
            "CAhandler", "default_handler", fallback=None
        )
        if not self.default_name:
            self._startup_error = (
                "multi_handler enabled but no default_handler configured"
            )
            self.logger.error("%s", self._startup_error)
            return self

        if "Order" in config_dic and config_dic.get(
            "Order", "profile_cahandler", fallback=None
        ):
            try:
                self.profile_cahandler = json.loads(
                    config_dic["Order"]["profile_cahandler"]
                )
            except Exception as err:
                self.logger.warning("Failed to parse profile_cahandler: %s", err)
                self.profile_cahandler = {}

        for section in config_dic.sections():
            if not section.startswith(self.SECTION_PREFIX):
                continue
            name = section[len(self.SECTION_PREFIX) :]
            module = ca_handler_load_from_section(self.logger, config_dic, section)
            if module is None:
                self.logger.error(
                    "CAHandlerRegistry: failed to load handler for [%s]", section
                )
                continue
            self.handlers[name] = {
                "module": module,
                "config_section": section,
                "allowed_domainlist": self._allowed_domainlist_load(
                    config_dic, section
                ),
            }
            self.logger.debug(
                "CAHandlerRegistry: registered handler '%s' (section %s)",
                name,
                section,
            )

        if self.default_name not in self.handlers:
            self._startup_error = (
                f"default_handler '{self.default_name}' is not registered"
            )
            self.logger.error("CAHandlerRegistry: %s", self._startup_error)

        for profile_name, handler_name in self.profile_cahandler.items():
            if handler_name not in self.handlers:
                self.logger.error(
                    "profile_cahandler[%s] -> '%s' is not registered",
                    profile_name,
                    handler_name,
                )

        self.logger.debug(
            "CAHandlerRegistry.load() ended with %d handlers", len(self.handlers)
        )
        return self

    def _allowed_domainlist_load(self, config_dic: Any, section: str) -> List[str]:
        raw = config_dic.get(section, "allowed_domainlist", fallback=None)
        if not raw:
            return []
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, list):
                return parsed
        except Exception as err:
            self.logger.warning(
                "CAHandlerRegistry: failed to parse allowed_domainlist in [%s]: %s",
                section,
                err,
            )
        return []

    def resolve(
        self,
        *,
        cahandler_name: Optional[str] = None,
        order_profile: Optional[str] = None,
        csr: Optional[str] = None,
        stored_name: Optional[str] = None,
    ) -> Optional[BoundCAHandler]:
        """Return the bound handler factory for one enroll/revoke/poll call."""
        self.logger.debug(
            "CAHandlerRegistry.resolve(name=%s, profile=%s, stored=%s, csr=%s)",
            cahandler_name,
            order_profile,
            stored_name,
            bool(csr),
        )

        if not self.multi_handler:
            return self._single_bound

        if stored_name:
            if stored_name in self.handlers:
                return self._bind(stored_name)
            self.logger.warning(
                "Stored cahandler '%s' is not registered; re-resolving",
                stored_name,
            )

        if cahandler_name:
            if cahandler_name in self.handlers:
                return self._bind(cahandler_name)
            self.logger.error(
                "Unknown EAB cahandler_name '%s'; refusing silent fallback",
                cahandler_name,
            )
            return None

        name: Optional[str] = None
        if (
            order_profile
            and self.profile_cahandler
            and order_profile in self.profile_cahandler
        ):
            mapped = self.profile_cahandler[order_profile]
            if mapped in self.handlers:
                name = mapped
            else:
                self.logger.error(
                    "profile_cahandler maps profile '%s' to unknown handler '%s'",
                    order_profile,
                    mapped,
                )
                return None

        if name is None and csr is not None:
            name = self._resolve_by_csr(csr)

        if name is None and self.default_name and self.default_name in self.handlers:
            name = self.default_name

        if name is None:
            self.logger.error(
                "CAHandlerRegistry.resolve: no handler matched "
                "(profile=%s, default=%s)",
                order_profile,
                self.default_name,
            )
            return None

        return self._bind(name)

    def _resolve_by_csr(self, csr: str) -> Optional[str]:
        from acme2certifier.acme_srv.helper import (  # pylint: disable=c0415
            csr_cn_get,
            csr_san_get,
        )

        self.logger.debug("CAHandlerRegistry._resolve_by_csr()")
        identifiers: List[str] = []
        try:
            cn = csr_cn_get(self.logger, csr)
            if cn:
                identifiers.append(cn.lower())
            for san in csr_san_get(self.logger, csr) or []:
                try:
                    san_type, san_value = san.lower().split(":", 1)
                    if san_type == "dns":
                        identifiers.append(san_value)
                except ValueError:
                    self.logger.debug(
                        "CAHandlerRegistry._resolve_by_csr: skipping SAN %s", san
                    )
        except Exception as err:
            self.logger.warning(
                "CAHandlerRegistry._resolve_by_csr: failed to parse CSR: %s", err
            )
            return None

        if not identifiers:
            return None

        matches: List[str] = []
        for name, entry in self.handlers.items():
            patterns = entry.get("allowed_domainlist") or []
            if not patterns:
                continue
            if all(_domain_matches(ident, patterns) for ident in identifiers):
                matches.append(name)

        if len(matches) > 1:
            self.logger.warning(
                "Multiple handlers matched CSR identifiers %s: %s; using '%s'",
                identifiers,
                matches,
                matches[0],
            )
        if matches:
            return matches[0]
        return None

    def _bind(self, name: str) -> BoundCAHandler:
        entry = self.handlers[name]
        return BoundCAHandler(
            entry["module"].CAhandler,
            entry["config_section"],
            name,
        )

    def default_handler(self) -> Optional[BoundCAHandler]:
        """Return the default handler for directory/trigger/renewalinfo."""
        if not self.multi_handler:
            return self._single_bound
        if self.default_name and self.default_name in self.handlers:
            return self._bind(self.default_name)
        return None

    def all_handlers(self) -> List[BoundCAHandler]:
        """Return every registered handler (multi mode) or the single handler."""
        if not self.multi_handler:
            return [self._single_bound] if self._single_bound else []
        return [self._bind(name) for name in self.handlers]

    def referenced_handlers(self) -> List[BoundCAHandler]:
        """Handlers that must pass handler_check: default + profile map targets."""
        names: List[str] = []
        if self.default_name and self.default_name in self.handlers:
            names.append(self.default_name)
        for handler_name in self.profile_cahandler.values():
            if handler_name in self.handlers and handler_name not in names:
                names.append(handler_name)
        return [self._bind(name) for name in names]

    @property
    def startup_error(self) -> Optional[str]:
        return self._startup_error
