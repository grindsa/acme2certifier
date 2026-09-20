# -*- coding: utf-8 -*-
"""Tests for CAHandlerRegistry (Phase A — classical mode foundation)."""

from __future__ import annotations

import configparser
import logging
import sys
from types import SimpleNamespace
from unittest.mock import patch, MagicMock

import pytest

from acme2certifier.acme_srv.helpers.cahandler_registry import (
    BoundCAHandler,
    CAHandlerRegistry,
)
from acme2certifier.acme_srv.helpers.config import (
    cahandler_config_section_set,
    cahandler_config_section_reset,
    load_config,
    load_config_section,
)


class _DummyHandler:
    config_section = "CAhandler"

    def __init__(self, debug: bool = False, logger=None):
        self.debug = debug
        self.logger = logger

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def _config_load(self):
        config_dic = load_config(self.logger, "CAhandler")
        self.api_host = config_dic.get("CAhandler", "api_host", fallback=None)


@pytest.fixture(name="logger")
def fixture_logger() -> logging.Logger:
    return logging.getLogger("test_cahandler_registry")


def _cfg(sections: dict) -> configparser.ConfigParser:
    config = configparser.ConfigParser()
    for section, options in sections.items():
        if not config.has_section(section):
            config.add_section(section)
        for key, value in options.items():
            config.set(section, key, value)
    return config


@patch("acme2certifier.acme_srv.helpers.cahandler_registry.ca_handler_load_from_section")
def test_classical_mode_single_handler(mock_load, logger: logging.Logger) -> None:
    module = SimpleNamespace(CAhandler=_DummyHandler)
    mock_load.return_value = module
    config = _cfg({"CAhandler": {"handler_module": "acme2certifier.cahandlers.openssl_ca_handler"}})

    registry = CAHandlerRegistry(logger).load(config)

    assert registry.multi_handler is False
    bound = registry.resolve()
    assert bound is not None
    assert bound.name == "default"
    with bound(False, logger) as inst:
        assert inst.config_section == "CAhandler"


@patch("acme2certifier.acme_srv.helpers.cahandler_registry.ca_handler_load_from_section")
def test_multi_handler_config_parse(mock_load, logger: logging.Logger) -> None:
    module = SimpleNamespace(CAhandler=_DummyHandler)
    mock_load.return_value = module
    config = _cfg(
        {
            "CAhandler": {
                "multi_handler": "True",
                "default_handler": "openssl",
            },
            "CAhandler:openssl": {
                "handler_module": "acme2certifier.cahandlers.openssl_ca_handler",
            },
            "Order": {
                "profile_cahandler": '{"long": "ejbca"}',
            },
        }
    )

    registry = CAHandlerRegistry(logger).load(config)

    assert registry.multi_handler is True
    assert registry.default_name == "openssl"
    assert "openssl" in registry.handlers
    assert registry.profile_cahandler == {"long": "ejbca"}


def test_load_config_honors_bound_section_via_context(logger: logging.Logger) -> None:
    config = _cfg(
        {
            "CAhandler": {"shared_flag": "yes"},
            "CAhandler:ejbca": {"api_host": "https://ejbca.example"},
        }
    )

    with patch(
        "acme2certifier.acme_srv.helpers.config._read_config_file",
        return_value="",
    ), patch(
        "acme2certifier.acme_srv.helpers.config._parse_config_content",
        return_value=(config, "ini"),
    ):
        token = cahandler_config_section_set("CAhandler:ejbca")
        try:
            merged = load_config(logger)
        finally:
            cahandler_config_section_reset(token)

    assert merged.get("CAhandler", "api_host") == "https://ejbca.example"
    assert merged.get("CAhandler", "shared_flag") == "yes"


def test_load_config_section_aliases_named_section(logger: logging.Logger) -> None:
    config = _cfg(
        {
            "CAhandler": {"shared_flag": "yes"},
            "CAhandler:ejbca": {"api_host": "https://ejbca.example"},
        }
    )

    with patch(
        "acme2certifier.acme_srv.helpers.config._read_config_file",
        return_value="",
    ), patch(
        "acme2certifier.acme_srv.helpers.config._parse_config_content",
        return_value=(config, "ini"),
    ):
        merged = load_config_section(logger, "CAhandler:ejbca")

    assert merged.get("CAhandler", "api_host") == "https://ejbca.example"
    assert merged.get("CAhandler", "shared_flag") == "yes"


def test_bound_cahandler_load_config_in_context(logger: logging.Logger) -> None:
    config = _cfg(
        {
            "CAhandler": {"shared_flag": "yes"},
            "CAhandler:ejbca": {"api_host": "https://ejbca.example"},
        }
    )
    bound = BoundCAHandler(_DummyHandler, "CAhandler:ejbca", "ejbca")

    with patch(
        "acme2certifier.acme_srv.helpers.config._read_config_file",
        return_value="",
    ), patch(
        "acme2certifier.acme_srv.helpers.config._parse_config_content",
        return_value=(config, "ini"),
    ):
        with bound(False, logger) as handler:
            handler._config_load()

    assert handler.api_host == "https://ejbca.example"


def _multi_registry(logger: logging.Logger) -> CAHandlerRegistry:
    """Build a loaded multi-handler registry with openssl + ejbca."""
    config = _cfg(
        {
            "CAhandler": {
                "multi_handler": "True",
                "default_handler": "openssl",
            },
            "CAhandler:openssl": {
                "handler_module": "acme2certifier.cahandlers.openssl_ca_handler",
            },
            "CAhandler:ejbca": {
                "handler_module": "acme2certifier.cahandlers.ejbca_ca_handler",
            },
            "Order": {
                "profile_cahandler": '{"long": "ejbca", "short": "openssl"}',
            },
        }
    )
    module = SimpleNamespace(CAhandler=_DummyHandler)
    with patch(
        "acme2certifier.acme_srv.helpers.cahandler_registry.ca_handler_load_from_section",
        return_value=module,
    ):
        return CAHandlerRegistry(logger).load(config)


def test_resolve_default_handler(logger: logging.Logger) -> None:
    registry = _multi_registry(logger)
    bound = registry.resolve(csr="dummy-csr-with-no-domain-match")
    assert bound is not None
    assert bound.name == "openssl"


def test_resolve_profile_cahandler(logger: logging.Logger) -> None:
    registry = _multi_registry(logger)
    bound = registry.resolve(order_profile="long", csr="dummy")
    assert bound is not None
    assert bound.name == "ejbca"


def test_resolve_eab_cahandler_name(logger: logging.Logger) -> None:
    registry = _multi_registry(logger)
    bound = registry.resolve(cahandler_name="ejbca", csr="dummy")
    assert bound is not None
    assert bound.name == "ejbca"


def test_resolve_unknown_eab_name_returns_none(logger: logging.Logger) -> None:
    registry = _multi_registry(logger)
    assert registry.resolve(cahandler_name="missing", csr="dummy") is None


def test_resolve_stored_name(logger: logging.Logger) -> None:
    registry = _multi_registry(logger)
    bound = registry.resolve(stored_name="ejbca", csr="dummy")
    assert bound is not None
    assert bound.name == "ejbca"


def _routing_registry(
    logger: logging.Logger, route_domainlist: str
) -> CAHandlerRegistry:
    """Multi-handler registry with openssl default and an internal route list."""
    config = _cfg(
        {
            "CAhandler": {
                "multi_handler": "True",
                "default_handler": "openssl",
            },
            "CAhandler:openssl": {
                "handler_module": "acme2certifier.cahandlers.openssl_ca_handler",
            },
            "CAhandler:internal": {
                "handler_module": "acme2certifier.cahandlers.openssl_ca_handler",
                "route_domainlist": route_domainlist,
            },
        }
    )
    module = SimpleNamespace(CAhandler=_DummyHandler)
    with patch(
        "acme2certifier.acme_srv.helpers.cahandler_registry.ca_handler_load_from_section",
        return_value=module,
    ):
        return CAHandlerRegistry(logger).load(config)


@patch(
    "acme2certifier.acme_srv.helper.csr_cn_get",
    return_value="host.internal.example",
)
@patch(
    "acme2certifier.acme_srv.helper.csr_san_get",
    return_value=["dns:host.internal.example"],
)
def test_resolve_domain_routing(
    _mock_san,
    _mock_cn,
    logger: logging.Logger,
) -> None:
    registry = _routing_registry(logger, '["*.internal.example"]')
    bound = registry.resolve(csr="dummy-csr")
    assert bound is not None
    assert bound.name == "internal"


@patch(
    "acme2certifier.acme_srv.helper.csr_cn_get",
    return_value="host.internal.example",
)
@patch(
    "acme2certifier.acme_srv.helper.csr_san_get",
    return_value=["dns:host.internal.example"],
)
def test_resolve_domain_routing_exact_host(
    _mock_san,
    _mock_cn,
    logger: logging.Logger,
) -> None:
    registry = _routing_registry(logger, '["host.internal.example"]')
    bound = registry.resolve(csr="dummy-csr")
    assert bound is not None
    assert bound.name == "internal"


@patch(
    "acme2certifier.acme_srv.helper.csr_cn_get",
    return_value="internal.example",
)
@patch(
    "acme2certifier.acme_srv.helper.csr_san_get",
    return_value=["dns:internal.example"],
)
def test_resolve_domain_routing_wildcard_skips_apex(
    _mock_san,
    _mock_cn,
    logger: logging.Logger,
) -> None:
    registry = _routing_registry(logger, '["*.internal.example"]')
    bound = registry.resolve(csr="dummy-csr")
    assert bound is not None
    assert bound.name == "openssl"


@patch(
    "acme2certifier.acme_srv.helper.csr_cn_get",
    return_value="foointernal.example",
)
@patch(
    "acme2certifier.acme_srv.helper.csr_san_get",
    return_value=["dns:foointernal.example"],
)
def test_resolve_domain_routing_wildcard_requires_dot(
    _mock_san,
    _mock_cn,
    logger: logging.Logger,
) -> None:
    registry = _routing_registry(logger, '["*.internal.example"]')
    bound = registry.resolve(csr="dummy-csr")
    assert bound is not None
    assert bound.name == "openssl"


@patch(
    "acme2certifier.acme_srv.helper.csr_cn_get",
    return_value="host.internal.example",
)
@patch(
    "acme2certifier.acme_srv.helper.csr_san_get",
    return_value=["dns:other.example.com"],
)
def test_resolve_domain_routing_all_identifiers_must_match(
    _mock_san,
    _mock_cn,
    logger: logging.Logger,
) -> None:
    registry = _routing_registry(logger, '["*.internal.example"]')
    bound = registry.resolve(csr="dummy-csr")
    assert bound is not None
    assert bound.name == "openssl"


@patch(
    "acme2certifier.acme_srv.helper.csr_cn_get",
    return_value="host.internal.example",
)
@patch(
    "acme2certifier.acme_srv.helper.csr_san_get",
    return_value=["dns:host.internal.example"],
)
def test_resolve_domain_routing_regex_pattern_is_literal(
    _mock_san,
    _mock_cn,
    logger: logging.Logger,
) -> None:
    registry = _routing_registry(logger, '["\\\\.internal\\\\.example$"]')
    bound = registry.resolve(csr="dummy-csr")
    assert bound is not None
    assert bound.name == "openssl"


def test_cahandler_lookup_from_csr(logger: logging.Logger) -> None:
    models_mock = MagicMock()
    models_mock.DBstore.return_value.certificates_search.return_value = [
        {"order__cahandler": "ejbca"}
    ]
    modules = {"acme2certifier.acme_srv.db_handler": models_mock}
    with patch.dict(sys.modules, modules):
        from acme2certifier.acme_srv.helpers.config import cahandler_lookup

        assert cahandler_lookup(logger, csr="test-csr") == "ejbca"


def test_cahandler_lookup_recodes_cert_raw(logger: logging.Logger) -> None:
    models_mock = MagicMock()
    search = models_mock.DBstore.return_value.certificates_search
    search.return_value = [{"order__cahandler": "harica"}]
    modules = {"acme2certifier.acme_srv.db_handler": models_mock}
    with patch.dict(sys.modules, modules):
        from acme2certifier.acme_srv.helpers.config import cahandler_lookup

        models_mock = MagicMock()
        search = models_mock.DBstore.return_value.certificates_search
        search.return_value = [{"order__cahandler": "harica"}]
        modules = {"acme2certifier.acme_srv.db_handler": models_mock}
        with patch.dict(sys.modules, modules):
            self.assertEqual(
                cahandler_lookup(self.logger, cert_raw="abc-def_ghi"), "harica"
            )
        search.assert_called_once()
        self.assertEqual(search.call_args[0][0], "cert_raw")
        self.assertEqual(search.call_args[0][1], "abc+def/ghi=")

    def test_020_bound_instance_getattr_and_handler_cls_getattr(self):
        """wrapper and factory forward unknown attributes to the handler"""
        bound = self.BoundCAHandler(_DummyHandler, "CAhandler", "default")
        self.assertEqual(bound.config_section, "CAhandler")
        wrapper = bound(False, self.logger)
        self.assertFalse(wrapper.debug)

    def test_021_load_none_config_dic_uses_load_config(self):
        """load() without config_dic reads via load_config()"""
        config = self._cfg(
            {
                "CAhandler": {
                    "handler_module": "acme2certifier.cahandlers.openssl_ca_handler"
                }
            }
        )
        module = SimpleNamespace(CAhandler=_DummyHandler)
        with (
            patch(
                "acme2certifier.acme_srv.helpers.cahandler_registry.load_config",
                return_value=config,
            ),
            patch(
                "acme2certifier.acme_srv.helpers.cahandler_registry.ca_handler_load_from_section",
                return_value=module,
            ),
        ):
            registry = self.CAHandlerRegistry(self.logger).load()
        self.assertFalse(registry.multi_handler)
        self.assertIsNotNone(registry.default_handler())

    def test_022_load_missing_cahandler_section(self):
        """missing [CAhandler] sets startup_error"""
        with self.assertLogs("test_a2c", level="ERROR") as lcm:
            registry = self.CAHandlerRegistry(self.logger).load(
                self._cfg({"Directory": {}})
            )
        self.assertEqual(
            registry.startup_error, "CAhandler configuration missing in config file"
        )
        self.assertIn(
            "ERROR:test_a2c:CAhandler configuration missing in config file",
            lcm.output,
        )

    def test_023_multi_handler_parse_invalid_boolean(self):
        """invalid multi_handler values fall back to classical mode"""
        module = SimpleNamespace(CAhandler=_DummyHandler)
        config = self._cfg({"CAhandler": {"multi_handler": "not-a-bool"}})
        with patch(
            "acme2certifier.acme_srv.helpers.cahandler_registry.ca_handler_load_from_section",
            return_value=module,
        ):
            with self.assertLogs("test_a2c", level="WARNING") as lcm:
                registry = self.CAHandlerRegistry(self.logger).load(config)
        self.assertFalse(registry.multi_handler)
        self.assertTrue(
            any("Failed to parse multi_handler" in msg for msg in lcm.output)
        )

    def test_024_classical_load_no_handler(self):
        """classical mode without a loadable handler leaves no bound default"""
        config = self._cfg({"CAhandler": {"foo": "bar"}})
        with patch(
            "acme2certifier.acme_srv.helpers.cahandler_registry.ca_handler_load_from_section",
            return_value=None,
        ):
            registry = self.CAHandlerRegistry(self.logger).load(config)
        self.assertIsNone(registry.default_handler())
        self.assertEqual(registry.all_handlers(), [])

    def test_025_multi_load_missing_default_handler(self):
        """multi_handler without default_handler sets startup_error"""
        config = self._cfg({"CAhandler": {"multi_handler": "True"}})
        with self.assertLogs("test_a2c", level="ERROR") as lcm:
            registry = self.CAHandlerRegistry(self.logger).load(config)
        self.assertEqual(
            registry.startup_error,
            "multi_handler enabled but no default_handler configured",
        )
        self.assertTrue(
            any("no default_handler configured" in msg for msg in lcm.output)
        )

    def test_026_legacy_handler_keys_warn(self):
        """handler_module on [CAhandler] is ignored in multi-handler mode"""
        config = self._cfg(
            {
                "CAhandler": {
                    "multi_handler": "True",
                    "default_handler": "openssl",
                    "handler_module": "acme2certifier.cahandlers.openssl_ca_handler",
                },
                "CAhandler:openssl": {
                    "handler_module": "acme2certifier.cahandlers.openssl_ca_handler",
                },
            }
        )
        module = SimpleNamespace(CAhandler=_DummyHandler)
        with patch(
            "acme2certifier.acme_srv.helpers.cahandler_registry.ca_handler_load_from_section",
            return_value=module,
        ):
            with self.assertLogs("test_a2c", level="WARNING") as lcm:
                self.CAHandlerRegistry(self.logger).load(config)
        self.assertTrue(
            any(
                "handler_module/handler_file on [CAhandler]" in msg
                for msg in lcm.output
            )
        )

    def test_027_profile_cahandler_parse_error(self):
        """invalid profile_cahandler JSON is ignored"""
        config = self._cfg(
            {
                "CAhandler": {
                    "multi_handler": "True",
                    "default_handler": "openssl",
                },
                "CAhandler:openssl": {
                    "handler_module": "acme2certifier.cahandlers.openssl_ca_handler",
                },
                "Order": {"profile_cahandler": "not-json"},
            }
        )
        module = SimpleNamespace(CAhandler=_DummyHandler)
        with patch(
            "acme2certifier.acme_srv.helpers.cahandler_registry.ca_handler_load_from_section",
            return_value=module,
        ):
            with self.assertLogs("test_a2c", level="WARNING") as lcm:
                registry = self.CAHandlerRegistry(self.logger).load(config)
        self.assertEqual(registry.profile_cahandler, {})
        self.assertTrue(
            any("Failed to parse profile_cahandler" in msg for msg in lcm.output)
        )

    def test_028_named_handler_load_failure(self):
        """failed [CAhandler:name] loads are skipped"""
        config = self._cfg(
            {
                "CAhandler": {
                    "multi_handler": "True",
                    "default_handler": "openssl",
                },
                "CAhandler:openssl": {
                    "handler_module": "acme2certifier.cahandlers.openssl_ca_handler",
                },
            }
        )
        with patch(
            "acme2certifier.acme_srv.helpers.cahandler_registry.ca_handler_load_from_section",
            return_value=None,
        ):
            with self.assertLogs("test_a2c", level="ERROR") as lcm:
                registry = self.CAHandlerRegistry(self.logger).load(config)
        self.assertEqual(registry.handlers, {})
        self.assertTrue(
            any(
                "failed to load handler for [CAhandler:openssl]" in msg
                for msg in lcm.output
            )
        )
        self.assertEqual(
            registry.startup_error, "default_handler 'openssl' is not registered"
        )

    def test_029_route_domainlist_invalid(self):
        """invalid or non-list route_domainlist values become empty lists"""
        with self.assertLogs("test_a2c", level="WARNING") as lcm:
            registry = self._routing_registry("not-json")
        self.assertEqual(registry.handlers["internal"]["route_domainlist"], [])
        self.assertTrue(
            any("failed to parse route_domainlist" in msg for msg in lcm.output)
        )
        registry = self._routing_registry('{"a": 1}')
        self.assertEqual(registry.handlers["internal"]["route_domainlist"], [])

    def test_030_resolve_stored_name_unregistered_falls_through(self):
        """unknown stored names are re-resolved via the default handler"""
        registry = self._multi_registry()
        with self.assertLogs("test_a2c", level="WARNING") as lcm:
            bound = registry.resolve(stored_name="ghost")
        self.assertIsNotNone(bound)
        self.assertEqual(bound.name, "openssl")
        self.assertTrue(
            any(
                "Stored cahandler 'ghost' is not registered" in msg
                for msg in lcm.output
            )
        )

    def test_031_resolve_profile_unknown_handler(self):
        """profile_cahandler mapping to an unknown handler returns None"""
        registry = self._multi_registry()
        registry.profile_cahandler = {"long": "ghost"}
        with self.assertLogs("test_a2c", level="ERROR") as lcm:
            self.assertIsNone(registry.resolve(order_profile="long"))
        self.assertTrue(
            any(
                "maps profile 'long' to unknown handler 'ghost'" in msg
                for msg in lcm.output
            )
        )

    def test_032_resolve_no_handler_matched(self):
        """resolve() returns None when default_handler is also unregistered"""
        registry = self._multi_registry()
        registry.default_name = "gone"
        with self.assertLogs("test_a2c", level="ERROR") as lcm:
            self.assertIsNone(registry.resolve())
        self.assertTrue(any("no handler matched" in msg for msg in lcm.output))

    @patch(
        "acme2certifier.acme_srv.helper.csr_cn_get",
        return_value="host.internal.example",
    )
    @patch(
        "acme2certifier.acme_srv.helper.csr_san_get",
        return_value=["not-a-san", "dns:host.internal.example"],
    )
    def test_033_resolve_by_csr_skips_malformed_san(self, _mock_san, _mock_cn):
        """SANs without a type prefix are skipped during domain routing"""
        registry = self._routing_registry('["*.internal.example"]')
        bound = registry.resolve(csr="dummy-csr")
        self.assertIsNotNone(bound)
        self.assertEqual(bound.name, "internal")

    @patch("acme2certifier.acme_srv.helper.csr_cn_get", return_value=None)
    @patch("acme2certifier.acme_srv.helper.csr_san_get", return_value=[])
    def test_034_resolve_by_csr_no_identifiers(self, _mock_san, _mock_cn):
        """CSR with no identifiers falls back to the default handler"""
        registry = self._routing_registry('["*.internal.example"]')
        bound = registry.resolve(csr="dummy-csr")
        self.assertIsNotNone(bound)
        self.assertEqual(bound.name, "openssl")

    @patch(
        "acme2certifier.acme_srv.helper.csr_cn_get",
        side_effect=Exception("parse fail"),
    )
    def test_035_resolve_by_csr_parse_error(self, _mock_cn):
        """CSR parse failures fall back to the default handler"""
        registry = self._routing_registry('["*.internal.example"]')
        with self.assertLogs("test_a2c", level="WARNING") as lcm:
            bound = registry.resolve(csr="dummy-csr")
        self.assertIsNotNone(bound)
        self.assertEqual(bound.name, "openssl")
        self.assertTrue(any("failed to parse CSR" in msg for msg in lcm.output))

    @patch(
        "acme2certifier.acme_srv.helper.csr_cn_get",
        return_value="host.internal.example",
    )
    @patch(
        "acme2certifier.acme_srv.helper.csr_san_get",
        return_value=["dns:host.internal.example"],
    )
    def test_036_resolve_by_csr_multiple_matches(self, _mock_san, _mock_cn):
        """multiple matching route lists warn and pick the first match"""
        config = self._cfg(
            {
                "CAhandler": {
                    "multi_handler": "True",
                    "default_handler": "openssl",
                },
                "CAhandler:openssl": {
                    "handler_module": "acme2certifier.cahandlers.openssl_ca_handler",
                },
                "CAhandler:internal": {
                    "handler_module": "acme2certifier.cahandlers.openssl_ca_handler",
                    "route_domainlist": '["*.internal.example"]',
                },
                "CAhandler:internal2": {
                    "handler_module": "acme2certifier.cahandlers.openssl_ca_handler",
                    "route_domainlist": '["*.internal.example"]',
                },
            }
        )
        module = SimpleNamespace(CAhandler=_DummyHandler)
        with patch(
            "acme2certifier.acme_srv.helpers.cahandler_registry.ca_handler_load_from_section",
            return_value=module,
        ):
            registry = self.CAHandlerRegistry(self.logger).load(config)
        with self.assertLogs("test_a2c", level="WARNING") as lcm:
            bound = registry.resolve(csr="dummy-csr")
        self.assertIsNotNone(bound)
        self.assertEqual(bound.name, "internal")
        self.assertTrue(
            any(
                "Multiple handlers matched CSR identifiers" in msg for msg in lcm.output
            )
        )

    def test_037_default_all_and_referenced_handlers(self):
        """default_handler, all_handlers, and referenced_handlers cover both modes"""
        classical = self.CAHandlerRegistry(self.logger)
        classical._single_bound = self.BoundCAHandler(
            _DummyHandler, "CAhandler", "default"
        )
        self.assertEqual(classical.default_handler().name, "default")
        self.assertEqual(len(classical.all_handlers()), 1)

        registry = self._multi_registry()
        self.assertEqual(registry.default_handler().name, "openssl")
        names = [bound.name for bound in registry.all_handlers()]
        self.assertIn("openssl", names)
        self.assertIn("ejbca", names)
        referenced = [bound.name for bound in registry.referenced_handlers()]
        self.assertEqual(referenced, ["openssl", "ejbca"])

        registry.default_name = "gone"
        registry.profile_cahandler = {}
        self.assertIsNone(registry.default_handler())
        self.assertEqual(registry.referenced_handlers(), [])
        self.assertIsNone(registry.startup_error)

    def test_038_resolve_default_ca_handler_uses_registry(self):
        """resolve_default_ca_handler returns the registry default when set"""
        from acme2certifier.acme_srv.helpers.cahandler_registry import (
            resolve_default_ca_handler,
        )

        bound = self.BoundCAHandler(_DummyHandler, "CAhandler", "default")
        registry = MagicMock()
        registry.default_handler.return_value = bound
        result = resolve_default_ca_handler(self.logger, registry, {}, MagicMock())
        self.assertIs(result, bound)

    def test_039_resolve_default_ca_handler_classical_fallback(self):
        """resolve_default_ca_handler wraps ca_handler_load when no registry default"""
        from acme2certifier.acme_srv.helpers.cahandler_registry import (
            resolve_default_ca_handler,
        )

        mock_module = MagicMock()
        mock_module.CAhandler = _DummyHandler
        registry = MagicMock()
        registry.default_handler.return_value = None
        result = resolve_default_ca_handler(
            self.logger, registry, {}, lambda _logger, _cfg: mock_module
        )
        self.assertIsInstance(result, self.BoundCAHandler)
        self.assertIs(result.handler_cls, _DummyHandler)

    def test_040_resolve_default_ca_handler_missing_module(self):
        """resolve_default_ca_handler logs critical when no handler can be loaded"""
        from acme2certifier.acme_srv.helpers.cahandler_registry import (
            resolve_default_ca_handler,
        )

        registry = MagicMock()
        registry.default_handler.return_value = None
        with self.assertLogs("test_a2c", level="CRITICAL") as lcm:
            result = resolve_default_ca_handler(
                self.logger, registry, {}, lambda _logger, _cfg: None
            )
        self.assertIsNone(result)
        self.assertIn("CRITICAL:test_a2c:No ca_handler loaded", lcm.output)

    def test_041_resolve_default_ca_handler_imports_plugin_loader(self):
        """resolve_default_ca_handler imports ca_handler_load when loader is omitted"""
        from acme2certifier.acme_srv.helpers.cahandler_registry import (
            resolve_default_ca_handler,
        )

        mock_module = MagicMock()
        mock_module.CAhandler = _DummyHandler
        registry = MagicMock()
        registry.default_handler.return_value = None
        with patch(
            "acme2certifier.acme_srv.helpers.plugin_loader.ca_handler_load",
            return_value=mock_module,
        ) as mock_load:
            result = resolve_default_ca_handler(self.logger, registry, {})
        mock_load.assert_called_once_with(self.logger, {})
        self.assertIsInstance(result, self.BoundCAHandler)
        self.assertIs(result.handler_cls, _DummyHandler)

    def test_042_resolve_default_ca_handler_bound_construction_error(self):
        """resolve_default_ca_handler logs critical when BoundCAHandler construction fails"""
        from acme2certifier.acme_srv.helpers.cahandler_registry import (
            resolve_default_ca_handler,
        )

        class _BrokenModule:
            @property
            def CAhandler(self):
                raise RuntimeError("broken handler class")

        registry = MagicMock()
        registry.default_handler.return_value = None
        with self.assertLogs("test_a2c", level="CRITICAL") as lcm:
            result = resolve_default_ca_handler(
                self.logger, registry, {}, lambda _logger, _cfg: _BrokenModule()
            )
        self.assertIsNone(result)
        self.assertTrue(
            any("Failed to load CA handler module" in msg for msg in lcm.output)
        )

    def test_043_classical_load_skip_list(self):
        """classical BoundCAHandler loads cert_chain_skip_list from [CAhandler]"""
        config = self._cfg(
            {
                "CAhandler": {
                    "handler_module": "acme2certifier.cahandlers.openssl_ca_handler",
                    "cert_chain_skip_list": '["AA:BB"]',
                }
            }
        )
        module = SimpleNamespace(CAhandler=_DummyHandler)
        with patch(
            "acme2certifier.acme_srv.helpers.cahandler_registry.ca_handler_load_from_section",
            return_value=module,
        ):
            registry = self.CAHandlerRegistry(self.logger).load(config)
        bound = registry.default_handler()
        self.assertIsNotNone(bound)
        self.assertIsNone(bound.cert_chain_skip_list_error)
        self.assertEqual(["aabb"], bound.cert_chain_skip_list)

    def test_044_named_handler_skip_list(self):
        """named section skip-list is bound; [CAhandler] list is not inherited"""
        config = self._cfg(
            {
                "CAhandler": {
                    "multi_handler": "True",
                    "default_handler": "openssl",
                    "cert_chain_skip_list": '["bb"]',
                },
                "CAhandler:openssl": {
                    "handler_module": "acme2certifier.cahandlers.openssl_ca_handler",
                },
                "CAhandler:ejbca": {
                    "handler_module": "acme2certifier.cahandlers.ejbca_ca_handler",
                    "cert_chain_skip_list": '["AA"]',
                },
            }
        )
        module = SimpleNamespace(CAhandler=_DummyHandler)
        with patch(
            "acme2certifier.acme_srv.helpers.cahandler_registry.ca_handler_load_from_section",
            return_value=module,
        ):
            registry = self.CAHandlerRegistry(self.logger).load(config)
        openssl = registry.resolve(cahandler_name="openssl")
        ejbca = registry.resolve(cahandler_name="ejbca")
        self.assertEqual([], openssl.cert_chain_skip_list)
        self.assertEqual(["aa"], ejbca.cert_chain_skip_list)

    def test_045_named_handler_skip_list_invalid(self):
        """invalid skip-list JSON is stored as a bind error"""
        config = self._cfg(
            {
                "CAhandler": {
                    "multi_handler": "True",
                    "default_handler": "openssl",
                },
                "CAhandler:openssl": {
                    "handler_module": "acme2certifier.cahandlers.openssl_ca_handler",
                    "cert_chain_skip_list": "not-json",
                },
            }
        )
        module = SimpleNamespace(CAhandler=_DummyHandler)
        with patch(
            "acme2certifier.acme_srv.helpers.cahandler_registry.ca_handler_load_from_section",
            return_value=module,
        ):
            registry = self.CAHandlerRegistry(self.logger).load(config)
        bound = registry.default_handler()
        self.assertTrue(
            bound.cert_chain_skip_list_error.startswith("Configuration error:")
        )
        self.assertEqual([], bound.cert_chain_skip_list)


if __name__ == "__main__":
    unittest.main()
