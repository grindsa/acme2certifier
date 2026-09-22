# -*- coding: utf-8 -*-
"""CA handler registry for single- and multi-handler mode."""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional, Type

from .config import (
    CERT_CHAIN_PROFILE_KEYS,
    cahandler_config_section_reset,
    cahandler_config_section_set,
    config_cert_chain_append_load,
    config_cert_chain_link_check_load,
    config_cert_chain_profile_load,
    config_cert_chain_skip_list_load,
    load_config,
)
from .certificates import cert_chain_append, cert_chain_skip
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


def _cert_chain_bind_kwargs(
    logger: logging.Logger, config_dic: Any, section: str
) -> Dict[str, Any]:
    """Load skip-list and append PEMs for *section*."""
    skip_error, skip_list = config_cert_chain_skip_list_load(
        logger, config_dic, section
    )
    append_error, append_pems = config_cert_chain_append_load(
        logger, config_dic, section
    )
    link_error, link_check = config_cert_chain_link_check_load(
        logger, config_dic, section
    )
    return {
        "cert_chain_skip_list": skip_list or [],
        "cert_chain_skip_list_error": skip_error,
        "cert_chain_append": append_pems or [],
        "cert_chain_append_error": append_error,
        "cert_chain_link_check": link_check,
        "cert_chain_link_check_error": link_error,
    }


class BoundCAHandler:
    """Factory binding a CAhandler class to a named config section."""

    def __init__(
        self,
        handler_cls: Type[Any],
        section: str,
        name: str,
        *,
        cert_chain_skip_list: Optional[List[str]] = None,
        cert_chain_skip_list_error: Optional[str] = None,
        cert_chain_append: Optional[List[str]] = None,
        cert_chain_append_error: Optional[str] = None,
        cert_chain_link_check: bool = True,
        cert_chain_link_check_error: Optional[str] = None,
    ) -> None:
        self.handler_cls = handler_cls
        self.section = section
        self.name = name
        self.cert_chain_skip_list = cert_chain_skip_list or []
        self.cert_chain_skip_list_error = cert_chain_skip_list_error
        self.cert_chain_append = cert_chain_append or []
        self.cert_chain_append_error = cert_chain_append_error
        self.cert_chain_link_check = cert_chain_link_check
        self.cert_chain_link_check_error = cert_chain_link_check_error

    @classmethod
    def from_config(
        cls,
        logger: logging.Logger,
        handler_cls: Type[Any],
        section: str,
        name: str,
        config_dic: Any,
    ) -> "BoundCAHandler":
        """Bind a handler class and load chain-rewrite options from *section*."""
        return cls(
            handler_cls,
            section,
            name,
            **_cert_chain_bind_kwargs(logger, config_dic, section),
        )

    def eab_chain_overlay(
        self, logger: logging.Logger, profile_dic: Optional[dict]
    ) -> Tuple[Optional[str], "BoundCAHandler"]:
        """Return ``(error, factory)`` with kid-profile skip/append overlaid.

        Does not mutate this factory. Keys present in *profile_dic* replace the
        bound config values, including empty lists. Omitted keys keep the
        bound values.
        """
        if not profile_dic:
            return None, self
        skip_list = self.cert_chain_skip_list
        skip_error = self.cert_chain_skip_list_error
        append = self.cert_chain_append
        append_error = self.cert_chain_append_error
        link_check = self.cert_chain_link_check
        link_error = self.cert_chain_link_check_error
        changed = False
        for key in CERT_CHAIN_PROFILE_KEYS:
            if key not in profile_dic:
                continue
            changed = True
            error, loaded = config_cert_chain_profile_load(
                logger, key, profile_dic[key]
            )
            if key == "cert_chain_skip_list":
                skip_list = loaded or []
                skip_error = error
            elif key == "cert_chain_append":
                append = loaded or []
                append_error = error
            else:
                link_check = True if loaded is None else bool(loaded)
                link_error = error
            if error:
                return error, self
        if not changed:
            return None, self
        return None, BoundCAHandler(
            self.handler_cls,
            self.section,
            self.name,
            cert_chain_skip_list=skip_list,
            cert_chain_skip_list_error=skip_error,
            cert_chain_append=append,
            cert_chain_append_error=append_error,
            cert_chain_link_check=link_check,
            cert_chain_link_check_error=link_error,
        )

    def cert_chain_rewrite(
        self, logger: logging.Logger, pem_bundle: Optional[str]
    ) -> Tuple[Optional[str], Optional[str]]:
        """Apply skip-list then append PEMs to a handler bundle."""
        error = (
            self.cert_chain_skip_list_error
            or self.cert_chain_append_error
            or self.cert_chain_link_check_error
        )
        if error:
            return error, None
        error, pem_bundle = cert_chain_skip(
            logger,
            pem_bundle,
            self.cert_chain_skip_list,
            link_check=self.cert_chain_link_check,
        )
        if error:
            return error, None
        return cert_chain_append(
            logger,
            pem_bundle,
            self.cert_chain_append,
            link_check=self.cert_chain_link_check,
        )

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
            return BoundCAHandler.from_config(
                logger,
                ca_handler_module.CAhandler,
                "CAhandler",
                "default",
                config_dic,
            )
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
            self._single_bound = BoundCAHandler.from_config(
                self.logger, module.CAhandler, "CAhandler", "default", config_dic
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
            skip_kwargs = _cert_chain_bind_kwargs(self.logger, config_dic, section)
            self.handlers[name] = {
                "module": module,
                "config_section": section,
                "route_domainlist": self._route_domainlist_load(config_dic, section),
                **skip_kwargs,
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
            self.logger.debug(
                "CAHandlerRegistry.resolve() ended with classical handler %r",
                getattr(self._single_bound, "name", None),
            )
            return self._single_bound

        if stored_name:
            if stored_name in self.handlers:
                bound = self._bind(stored_name)
                self.logger.debug(
                    "CAHandlerRegistry.resolve() ended with stored handler %r",
                    stored_name,
                )
                return bound
            self.logger.warning(
                "Stored cahandler '%s' is not registered; re-resolving",
                stored_name,
            )

        if cahandler_name:
            if cahandler_name in self.handlers:
                bound = self._bind(cahandler_name)
                self.logger.debug(
                    "CAHandlerRegistry.resolve() ended with EAB handler %r",
                    cahandler_name,
                )
                return bound
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
            self.logger.debug("CAHandlerRegistry.resolve() ended with None")
            return None

        bound = self._bind(name)
        self.logger.debug("CAHandlerRegistry.resolve() ended with handler %r", name)
        return bound

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
            self.logger.debug(
                "CAHandlerRegistry._resolve_by_csr() ended with no identifiers"
            )
            return None

        self.logger.debug(
            "CAHandlerRegistry._resolve_by_csr() identifiers=%s", identifiers
        )
        matches: List[str] = []
        for name, entry in self.handlers.items():
            patterns = entry.get("route_domainlist") or []
            if not patterns:
                continue
            if all(
                is_domain_whitelisted(self.logger, ident, patterns)
                for ident in identifiers
            ):
                matches.append(name)

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
            cert_chain_skip_list=entry.get("cert_chain_skip_list") or [],
            cert_chain_skip_list_error=entry.get("cert_chain_skip_list_error"),
            cert_chain_append=entry.get("cert_chain_append") or [],
            cert_chain_append_error=entry.get("cert_chain_append_error"),
            cert_chain_link_check=entry.get("cert_chain_link_check", True),
            cert_chain_link_check_error=entry.get("cert_chain_link_check_error"),
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
