# -*- coding: utf-8 -*-
"""CA handler registry for single- and multi-handler mode."""

import json
import logging
from typing import Any, Callable, Dict, List, Optional, Tuple, Type

from .config import (
    cahandler_config_section_reset,
    cahandler_config_section_set,
    load_config,
)
from .domain_utils import is_domain_whitelisted
from .plugin_loader import ca_handler_load_from_section


class _BoundCAHandlerInstance:
    """Activate bound section for ``load_config()`` during handler context."""

    def __init__(self, handler: Any, section: str) -> None:
        self._handler = handler
        self._section = section
        self._token = None

    def __enter__(self) -> Any:
        logger = getattr(self._handler, "logger", None)
        self.logger.debug(
            "BoundCAHandlerInstance.__enter__() binding config section %r",
            self._section,
        )
        self._token = cahandler_config_section_set(self._section, logger)
        return self._handler.__enter__()

    def __exit__(self, *args: Any) -> Any:
        logger = getattr(self._handler, "logger", None)
        try:
            return self._handler.__exit__(*args)
        finally:
            if self._token is not None:
                self.logger.debug(
                    "BoundCAHandlerInstance.__exit__() clearing config section %r",
                    self._section,
                )
                cahandler_config_section_reset(self._token, logger)
                self._token = None

    @property
    def logger(self) -> logging.Logger:
        return getattr(self._handler, "logger", None) or logging.getLogger(__name__)

    def __getattr__(self, item: str) -> Any:
        return getattr(self._handler, item)


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
        logger.debug(
            "BoundCAHandler.__call__() name=%r section=%r handler=%s",
            self.name,
            self.section,
            getattr(self.handler_cls, "__name__", self.handler_cls),
        )
        inst = self.handler_cls(debug, logger)
        inst.config_section = self.section
        inst.cahandler_registry_name = self.name
        return _BoundCAHandlerInstance(inst, self.section)

    def __getattr__(self, item: str) -> Any:
        return getattr(self.handler_cls, item)


def resolve_default_ca_handler(
    logger: logging.Logger,
    registry: "CAHandlerRegistry",
    config_dic: object,
    ca_handler_load_fn: Optional[Callable] = None,
) -> Optional[BoundCAHandler]:
    """Return the registry default, or wrap the classical ca_handler_load fallback."""
    default_bound = registry.default_handler()
    if default_bound is not None:
        return default_bound
    loader = ca_handler_load_fn
    if loader is None:
        from .plugin_loader import ca_handler_load  # pylint: disable=c0415

        loader = ca_handler_load
    ca_handler_module = loader(logger, config_dic)
    if ca_handler_module:
        try:
            return BoundCAHandler(ca_handler_module.CAhandler, "CAhandler", "default")
        except Exception as err:
            logger.critical("Failed to load CA handler module: %s", err)
            return None
    logger.critical("No ca_handler loaded")
    return None


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

        self.multi_handler = self._multi_handler_parse(config_dic)
        if self.multi_handler:
            self._multi_load(config_dic)
        else:
            self._classical_load(config_dic)
        return self

    def _multi_handler_parse(self, config_dic: Any) -> bool:
        """Return the ``multi_handler`` flag from ``[CAhandler]``."""
        self.logger.debug("CAHandlerRegistry._multi_handler_parse()")
        try:
            return config_dic.getboolean("CAhandler", "multi_handler", fallback=False)
        except Exception as err:
            self.logger.warning("Failed to parse multi_handler: %s", err)
            return False

    def _classical_load(self, config_dic: Any) -> None:
        """Load the single handler from ``[CAhandler]``."""
        module = ca_handler_load_from_section(self.logger, config_dic, "CAhandler")
        if module is not None:
            self._single_bound = BoundCAHandler(
                module.CAhandler, "CAhandler", "default"
            )
            self.logger.debug(
                "CAHandlerRegistry.load() classical mode handler=%s",
                getattr(module, "__name__", module),
            )
        else:
            self.logger.debug(
                "CAHandlerRegistry.load() classical mode: no handler loaded"
            )
        self.logger.debug(
            "CAHandlerRegistry.load() ended multi_handler=False bound=%s",
            self._single_bound is not None,
        )

    def _multi_load(self, config_dic: Any) -> None:
        """Load named handlers and profile mapping for multi-handler mode."""
        self.logger.debug("CAHandlerRegistry._multi_load()")
        self._legacy_handler_keys_warn(config_dic)
        self.default_name = config_dic.get(
            "CAhandler", "default_handler", fallback=None
        )
        if not self.default_name:
            self._startup_error = (
                "multi_handler enabled but no default_handler configured"
            )
            self.logger.error("%s", self._startup_error)
            return

        self.logger.debug(
            "CAHandlerRegistry.load() multi_handler=True default_handler=%r",
            self.default_name,
        )
        self.profile_cahandler = self._profile_cahandler_load(config_dic)
        self._named_handlers_register(config_dic)
        self._multi_references_validate()
        self.logger.debug(
            "CAHandlerRegistry.load() ended with %d handlers", len(self.handlers)
        )

    def _legacy_handler_keys_warn(self, config_dic: Any) -> None:
        """Warn if classical handler keys are set while multi_handler is on."""
        self.logger.debug("CAHandlerRegistry._legacy_handler_keys_warn()")
        if config_dic.get(
            "CAhandler", "handler_module", fallback=None
        ) or config_dic.get("CAhandler", "handler_file", fallback=None):
            self.logger.warning(
                "multi_handler enabled: handler_module/handler_file on [CAhandler] "
                "are ignored; use [CAhandler:<name>] sections"
            )
        self.logger.debug("CAHandlerRegistry._legacy_handler_keys_warn() ended")

    def _profile_cahandler_load(self, config_dic: Any) -> Dict[str, str]:
        """Parse ``[Order] profile_cahandler`` JSON mapping."""
        self.logger.debug("CAHandlerRegistry._profile_cahandler_load()")
        if "Order" not in config_dic or not config_dic.get(
            "Order", "profile_cahandler", fallback=None
        ):
            return {}
        try:
            mapping = json.loads(config_dic["Order"]["profile_cahandler"])
        except Exception as err:
            self.logger.warning("Failed to parse profile_cahandler: %s", err)
            return {}
        if mapping:
            self.logger.debug("CAHandlerRegistry.load() profile_cahandler=%s", mapping)
        self.logger.debug("CAHandlerRegistry._profile_cahandler_load() ended")
        return mapping

    def _named_handlers_register(self, config_dic: Any) -> None:
        """Register each ``[CAhandler:<name>]`` section."""
        for section in config_dic.sections():
            if not section.startswith(self.SECTION_PREFIX):
                continue
            name = section[len(self.SECTION_PREFIX) :]
            module = ca_handler_load_from_section(
                self.logger,
                config_dic,
                section,
                allow_default_fallback=False,
            )
            if module is None:
                self.logger.error(
                    "CAHandlerRegistry: failed to load handler for [%s]", section
                )
                continue
            self.handlers[name] = {
                "module": module,
                "config_section": section,
                "route_domainlist": self._route_domainlist_load(config_dic, section),
            }
            self.logger.debug(
                "CAHandlerRegistry: registered handler '%s' (section %s)",
                name,
                section,
            )

    def _multi_references_validate(self) -> None:
        """Ensure ``default_handler`` and profile map targets are registered."""
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

    def _route_domainlist_load(self, config_dic: Any, section: str) -> List[str]:
        self.logger.debug(
            "CAHandlerRegistry._route_domainlist_load() section=%s", section
        )
        raw = config_dic.get(section, "route_domainlist", fallback=None)
        if not raw:
            self.logger.debug(
                "CAHandlerRegistry._route_domainlist_load() ended with []"
            )
            return []
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, list):
                self.logger.debug(
                    "CAHandlerRegistry._route_domainlist_load() ended with %s",
                    parsed,
                )
                return parsed
        except Exception as err:
            self.logger.warning(
                "CAHandlerRegistry: failed to parse route_domainlist in [%s]: %s",
                section,
                err,
            )
        self.logger.debug("CAHandlerRegistry._route_domainlist_load() ended with []")
        return []

    def _bind_resolved(self, name: str, kind: str = "") -> BoundCAHandler:
        """Bind a registered handler and emit the resolve() completion log."""
        bound = self._bind(name)
        label = f"{kind} handler" if kind else "handler"
        self.logger.debug(
            "CAHandlerRegistry.resolve() ended with %s %r",
            label,
            name,
        )
        return bound

    def _bind_if_registered(
        self, name: str, kind: str = ""
    ) -> Optional[BoundCAHandler]:
        """Bind ``name`` when it is registered; otherwise return None."""
        if name in self.handlers:
            return self._bind_resolved(name, kind)
        return None

    def _resolve_classical(self) -> Optional[BoundCAHandler]:
        """Return the single bound handler used outside multi-handler mode."""
        self.logger.debug(
            "CAHandlerRegistry.resolve() ended with classical handler %r",
            getattr(self._single_bound, "name", None),
        )
        return self._single_bound

    def _resolve_stored(self, stored_name: Optional[str]) -> Optional[BoundCAHandler]:
        """Return a previously stored handler, or None to continue resolving."""
        if not stored_name:
            return None
        bound = self._bind_if_registered(stored_name, "stored")
        if bound:
            return bound
        self.logger.warning(
            "Stored cahandler '%s' is not registered; re-resolving",
            stored_name,
        )
        return None

    def _resolve_eab(self, cahandler_name: str) -> Optional[BoundCAHandler]:
        """Return the EAB-named handler, or None without falling back."""
        bound = self._bind_if_registered(cahandler_name, "EAB")
        if bound:
            return bound
        self.logger.error(
            "Unknown EAB cahandler_name '%s'; refusing silent fallback",
            cahandler_name,
        )
        return None

    def _profile_handler_name(
        self, order_profile: Optional[str]
    ) -> Tuple[Optional[str], bool]:
        """Map an order profile to a handler name.

        Returns ``(name, hard_fail)``. ``hard_fail`` is True when the profile
        maps to an unregistered handler and resolve() must stop.
        """
        if not (
            order_profile
            and self.profile_cahandler
            and order_profile in self.profile_cahandler
        ):
            return None, False
        mapped = self.profile_cahandler[order_profile]
        if mapped in self.handlers:
            return mapped, False
        self.logger.error(
            "profile_cahandler maps profile '%s' to unknown handler '%s'",
            order_profile,
            mapped,
        )
        return None, True

    def _default_handler_name(self) -> Optional[str]:
        """Return the configured default handler name when it is registered."""
        if self.default_name and self.default_name in self.handlers:
            return self.default_name
        return None

    def _resolve_fallback_name(
        self, order_profile: Optional[str], csr: Optional[str]
    ) -> Tuple[Optional[str], bool]:
        """Resolve via profile mapping, CSR routing, then default_handler."""
        name, hard_fail = self._profile_handler_name(order_profile)
        if hard_fail:
            return None, True
        if name is None and csr is not None:
            name = self._resolve_by_csr(csr)
        if name is None:
            name = self._default_handler_name()
        return name, False

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
            return self._resolve_classical()

        bound = self._resolve_stored(stored_name)
        if bound:
            return bound
        if cahandler_name:
            return self._resolve_eab(cahandler_name)

        name, hard_fail = self._resolve_fallback_name(order_profile, csr)
        if hard_fail:
            return None
        if name is None:
            self.logger.error(
                "CAHandlerRegistry.resolve: no handler matched "
                "(profile=%s, default=%s)",
                order_profile,
                self.default_name,
            )
            self.logger.debug("CAHandlerRegistry.resolve() ended with None")
            return None
        return self._bind_resolved(name)

    def _csr_dns_sans(self, sans: List[str]) -> List[str]:
        """Return DNS SAN values, skipping malformed entries."""
        values: List[str] = []
        for san in sans:
            try:
                san_type, san_value = san.lower().split(":", 1)
            except ValueError:
                self.logger.debug(
                    "CAHandlerRegistry._resolve_by_csr: skipping SAN %s", san
                )
                continue
            if san_type == "dns":
                values.append(san_value)
        return values

    def _csr_dns_identifiers(self, csr: str) -> Optional[List[str]]:
        """Return CN and DNS SAN identifiers from a CSR, or None on parse failure."""
        from acme2certifier.acme_srv.helper import (  # pylint: disable=c0415
            csr_cn_get,
            csr_san_get,
        )

        identifiers: List[str] = []
        try:
            cn = csr_cn_get(self.logger, csr)
            if cn:
                identifiers.append(cn.lower())
            identifiers.extend(self._csr_dns_sans(csr_san_get(self.logger, csr) or []))
        except Exception as err:
            self.logger.warning(
                "CAHandlerRegistry._resolve_by_csr: failed to parse CSR: %s", err
            )
            return None
        return identifiers

    def _csr_route_matches(self, identifiers: List[str]) -> List[str]:
        """Return handler names whose route_domainlist covers every identifier."""
        matches: List[str] = []
        for name, entry in self.handlers.items():
            patterns = entry.get("route_domainlist") or []
            if patterns and all(
                is_domain_whitelisted(self.logger, ident, patterns)
                for ident in identifiers
            ):
                matches.append(name)
        return matches

    def _resolve_by_csr(self, csr: str) -> Optional[str]:
        self.logger.debug("CAHandlerRegistry._resolve_by_csr()")
        identifiers = self._csr_dns_identifiers(csr)
        if identifiers is None:
            return None
        if not identifiers:
            self.logger.debug(
                "CAHandlerRegistry._resolve_by_csr() ended with no identifiers"
            )
            return None

        self.logger.debug(
            "CAHandlerRegistry._resolve_by_csr() identifiers=%s", identifiers
        )
        matches = self._csr_route_matches(identifiers)
        if len(matches) > 1:
            self.logger.warning(
                "Multiple handlers matched CSR identifiers %s: %s; using '%s'",
                identifiers,
                matches,
                matches[0],
            )
        if matches:
            self.logger.debug(
                "CAHandlerRegistry._resolve_by_csr() ended with %r", matches[0]
            )
            return matches[0]
        self.logger.debug("CAHandlerRegistry._resolve_by_csr() ended with None")
        return None

    def _bind(self, name: str) -> BoundCAHandler:
        self.logger.debug("CAHandlerRegistry._bind() name=%r", name)
        entry = self.handlers[name]
        bound = BoundCAHandler(
            entry["module"].CAhandler,
            entry["config_section"],
            name,
        )
        self.logger.debug(
            "CAHandlerRegistry._bind() ended section=%r handler=%s",
            entry["config_section"],
            getattr(entry["module"], "__name__", entry["module"]),
        )
        return bound

    def default_handler(self) -> Optional[BoundCAHandler]:
        """Return the default handler for directory/trigger/renewalinfo."""
        self.logger.debug("CAHandlerRegistry.default_handler()")
        if not self.multi_handler:
            self.logger.debug(
                "CAHandlerRegistry.default_handler() ended with classical handler %r",
                getattr(self._single_bound, "name", None),
            )
            return self._single_bound
        if self.default_name and self.default_name in self.handlers:
            bound = self._bind(self.default_name)
            self.logger.debug(
                "CAHandlerRegistry.default_handler() ended with %r",
                self.default_name,
            )
            return bound
        self.logger.debug("CAHandlerRegistry.default_handler() ended with None")
        return None

    def all_handlers(self) -> List[BoundCAHandler]:
        """Return every registered handler (multi mode) or the single handler."""
        self.logger.debug("CAHandlerRegistry.all_handlers()")
        if not self.multi_handler:
            handlers = [self._single_bound] if self._single_bound else []
        else:
            handlers = [self._bind(name) for name in self.handlers]
        self.logger.debug(
            "CAHandlerRegistry.all_handlers() ended with %d handler(s)",
            len(handlers),
        )
        return handlers

    def referenced_handlers(self) -> List[BoundCAHandler]:
        """Handlers that must pass handler_check: default + profile map targets."""
        self.logger.debug("CAHandlerRegistry.referenced_handlers()")
        names: List[str] = []
        if self.default_name and self.default_name in self.handlers:
            names.append(self.default_name)
        for handler_name in self.profile_cahandler.values():
            if handler_name in self.handlers and handler_name not in names:
                names.append(handler_name)
        handlers = [self._bind(name) for name in names]
        self.logger.debug(
            "CAHandlerRegistry.referenced_handlers() ended with %s",
            names,
        )
        return handlers

    @property
    def startup_error(self) -> Optional[str]:
        return self._startup_error
