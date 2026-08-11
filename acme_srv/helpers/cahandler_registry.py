# -*- coding: utf-8 -*-
"""CA handler registry for multi-handler mode.

In multi-handler mode acme2certifier can serve several CA handlers from one
instance. Selection precedence (highest first):

1. EAB kid profile ``cahandler_name`` (sibling of the ``cahandler`` dict in the
   kid keyfile entry, see docs/architecture/multi-cahandler-design.md).
2. ``[Order] profile_cahandler`` map: order profile -> handler name.
3. Domain-based auto-routing: the handler whose ``allowed_domainlist`` matches
   all identifiers in the CSR (CN + DNS SANs) is selected. Each named handler
   section may set ``allowed_domainlist`` (JSON list of regexes, same syntax as
   the handler's own config) to participate in domain-based routing.
4. ``[CAhandler] default_handler``.

When ``multi_handler`` is absent or ``False`` the registry degrades to the
classical single-handler behaviour and :py:meth:`resolve` always returns the
default handler loaded from the global ``[CAhandler]`` section.

Each named handler is configured in its own ``[CAhandler:<name>]`` section.
Handler instances are tagged with ``config_section = "CAhandler:<name>"`` so
they can read their own section via
:py:func:`acme_srv.helpers.config.load_config_section`; the section's keys are
also aliased under ``"CAhandler"`` so existing handler code keeps working
without per-handler edits.
"""

import json
import logging
import re
from typing import Dict, List, Optional

from .config import load_config
from .plugin_loader import ca_handler_load, ca_handler_load_by_file


def _domain_matches(entry: str, patterns: List[str]) -> bool:
    """Return True if ``entry`` matches any regex in ``patterns``.

    Mirrors EABhandler._list_regex_check semantics: a pattern starting with
    ``*.`` is treated as a suffix match (``*.`` -> ``.``).
    """
    if not entry or not patterns:
        return False
    for pattern in patterns:
        regex = pattern
        if regex.startswith("*."):
            regex = regex.replace("*.", ".")
        if re.search(regex, entry):
            return True
    return False


class CAHandlerRegistry:
    """Build and resolve CA handlers in single- or multi-handler mode."""

    def __init__(self, logger: logging.Logger):
        self.logger = logger
        self.multi_handler = False
        self.default_name = None
        # name -> {"module": <module>, "config_section": "CAhandler:<name>",
        #           "allowed_domainlist": [<regex>, ...]}
        self.handlers: Dict[str, Dict] = {}
        # order profile -> handler name
        self.profile_cahandler: Dict[str, str] = {}
        # lazily-built default handler for single-handler mode
        self._single_handler_class = None

    # -- construction --------------------------------------------------------

    def load(self) -> "CAHandlerRegistry":
        """Parse acme_srv.cfg and populate the registry."""
        self.logger.debug("CAHandlerRegistry.load()")
        config_dic = load_config(self.logger)

        if "CAhandler" not in config_dic:
            self.logger.error("CAhandler configuration missing in config file")
            return self

        try:
            self.multi_handler = config_dic.getboolean(
                "CAhandler", "multi_handler", fallback=False
            )
        except Exception as err:
            self.logger.warning("Failed to parse multi_handler: %s", err)
            self.multi_handler = False

        if not self.multi_handler:
            # classical mode: load the single handler from [CAhandler]
            module = ca_handler_load(self.logger, config_dic)
            if module is not None:
                self._single_handler_class = module.CAhandler
            return self

        self.default_name = config_dic.get("CAhandler", "default_handler", fallback=None)
        if not self.default_name:
            self.logger.error(
                "multi_handler enabled but no default_handler configured"
            )
            return self

        # profile_cahandler map (order profile -> handler name)
        if "Order" in config_dic and "profile_cahandler" in config_dic["Order"]:
            try:
                self.profile_cahandler = json.loads(
                    config_dic["Order"]["profile_cahandler"]
                )
            except Exception as err:
                self.logger.warning("Failed to parse profile_cahandler: %s", err)

        # load every [CAhandler:<name>] section
        for section in config_dic.sections():
            prefix = "CAhandler:"
            if not section.startswith(prefix):
                continue
            name = section[len(prefix):]
            handler_file = config_dic.get(section, "handler_file", fallback=None)
            if not handler_file:
                self.logger.error(
                    "CAHandlerRegistry: [%s] has no handler_file; skipping",
                    section,
                )
                continue
            module = ca_handler_load_by_file(self.logger, handler_file)
            if module is None:
                self.logger.error(
                    "CAHandlerRegistry: failed to load handler for [%s]; skipping",
                    section,
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
                "CAHandlerRegistry: registered handler '%s' -> %s (section %s, "
                "allowed_domainlist=%s)",
                name,
                handler_file,
                section,
                self.handlers[name]["allowed_domainlist"],
            )

        if self.default_name not in self.handlers:
            self.logger.error(
                "CAHandlerRegistry: default_handler '%s' is not registered",
                self.default_name,
            )

        self.logger.debug(
            "CAHandlerRegistry.load() ended with %d handlers", len(self.handlers)
        )
        return self

    def _allowed_domainlist_load(self, config_dic, section: str) -> List[str]:
        """parse the ``allowed_domainlist`` JSON value from a handler section.

        Returns an empty list when the key is absent (handler does not
        participate in domain-based routing). Logs and returns [] on parse
        errors so a malformed entry never silently matches everything.
        """
        if "allowed_domainlist" not in config_dic[section]:
            return []
        try:
            return json.loads(config_dic.get(section, "allowed_domainlist"))
        except Exception as err:
            self.logger.warning(
                "CAHandlerRegistry: failed to parse allowed_domainlist in [%s]: %s",
                section,
                err,
            )
            return []

    # -- resolution ----------------------------------------------------------

    def resolve(
        self,
        cahandler_name: Optional[str] = None,
        order_profile: Optional[str] = None,
        csr: Optional[str] = None,
    ) -> Optional[type]:
        """Return the CAhandler class to use for one enroll/revoke/poll.

        Args:
            cahandler_name: value of the EAB kid's ``cahandler_name`` field
                (highest precedence). ``None`` if EAB profiling is inactive
                or the kid has no ``cahandler_name``.
            order_profile: profile string on the ACME order, looked up in the
                ``profile_cahandler`` map.
            csr: base64url CSR (as carried through the ACME flow). When set,
                domain-based auto-routing applies: the handler whose
                ``allowed_domainlist`` matches every identifier in the CSR
                (CN + DNS SANs) is selected. This runs *after* cahandler_name
                and order_profile, but before the default fallback, so an
                explicit selector always wins and domain routing only picks
                the handler when nothing else decided.

        Returns the CAhandler class, or ``None`` if no handler could be
        resolved (caller should treat this as a hard error).
        """
        self.logger.debug(
            "CAHandlerRegistry.resolve(name=%s, profile=%s, csr=%s)",
            cahandler_name,
            order_profile,
            bool(csr),
        )

        if not self.multi_handler:
            return self._single_handler_class

        name = None
        if cahandler_name and cahandler_name in self.handlers:
            name = cahandler_name
        elif (
            order_profile
            and self.profile_cahandler
            and order_profile in self.profile_cahandler
            and self.profile_cahandler[order_profile] in self.handlers
        ):
            name = self.profile_cahandler[order_profile]
        elif csr is not None:
            name = self._resolve_by_csr(csr)

        if name is None and self.default_name and self.default_name in self.handlers:
            name = self.default_name

        if name is None:
            self.logger.error(
                "CAHandlerRegistry.resolve: no handler matched "
                "(cahandler_name=%s, order_profile=%s, default=%s)",
                cahandler_name,
                order_profile,
                self.default_name,
            )
            return None

        return self._bind(name)

    def _resolve_by_csr(self, csr: str) -> Optional[str]:
        """Pick a handler name by matching CSR identifiers against each
        handler's ``allowed_domainlist``. Returns the handler name, or None if
        no handler's domainlist matches all identifiers (caller falls back to
        default). A handler with an empty allowed_domainlist never matches
        here (it does not opt into domain routing).
        """
        self.logger.debug("CAHandlerRegistry._resolve_by_csr()")
        # local import to avoid a circular dependency on acme_srv.helper at
        # module import time (helper pulls in network/dns helpers)
        from acme_srv.helper import csr_cn_get, csr_san_get  # pylint: disable=C0415

        try:
            identifiers = []
            cn = csr_cn_get(self.logger, csr)
            if cn:
                identifiers.append(cn.lower())
            for san in csr_san_get(self.logger, csr) or []:
                # san entries look like "dns:foo.example.com"
                try:
                    san_type, san_value = san.lower().split(":", 1)
                    if san_type == "dns":
                        identifiers.append(san_value)
                except ValueError:
                    self.logger.debug(
                        "CAHandlerRegistry._resolve_by_csr: skipping non-dns SAN %s",
                        san,
                    )
        except Exception as err:
            self.logger.warning(
                "CAHandlerRegistry._resolve_by_csr: failed to parse CSR: %s", err
            )
            return None

        if not identifiers:
            self.logger.debug(
                "CAHandlerRegistry._resolve_by_csr: no DNS identifiers in CSR"
            )
            return None

        # A handler matches when *every* identifier matches its allowed list.
        # The first matching handler wins; ordering follows dict insertion
        # (i.e. the order sections appear in acme_srv.cfg).
        for name, entry in self.handlers.items():
            patterns = entry.get("allowed_domainlist") or []
            if not patterns:
                continue
            if all(_domain_matches(i, patterns) for i in identifiers):
                self.logger.debug(
                    "CAHandlerRegistry._resolve_by_csr: identifiers %s matched "
                    "handler '%s' (allowed_domainlist=%s)",
                    identifiers,
                    name,
                    patterns,
                )
                return name

        self.logger.debug(
            "CAHandlerRegistry._resolve_by_csr: no handler matched identifiers %s",
            identifiers,
        )
        return None

    def _bind(self, name: str) -> Optional[type]:
        """tag the named handler's class with its config_section and return it."""
        entry = self.handlers[name]
        handler_class = entry["module"].CAhandler
        # tag the class with the config section so instances read the right
        # [CAhandler:<name>] section in their _config_load()
        handler_class.config_section = entry["config_section"]
        self.logger.debug(
            "CAHandlerRegistry.resolve() -> handler '%s' (section %s)",
            name,
            entry["config_section"],
        )
        return handler_class

    # -- convenience ---------------------------------------------------------

    def default_handler(self) -> Optional[type]:
        """Return the default handler class (for directory/trigger/renewalinfo
        operations that are not tied to a specific order)."""
        if not self.multi_handler:
            return self._single_handler_class
        return self.resolve(cahandler_name=self.default_name)
