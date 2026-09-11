# -*- coding: utf-8 -*-
"""unittests for CAHandlerRegistry"""

# pylint: disable=C0415, R0904, W0212
import configparser
import logging
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

sys.path.insert(0, ".")
sys.path.insert(1, "..")


class _DummyHandler:
    """Minimal CAhandler stand-in for registry bind/load tests."""

    config_section = "CAhandler"

    def __init__(self, debug: bool = False, logger=None):
        self.debug = debug
        self.logger = logger

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def _config_load(self):
        from acme2certifier.acme_srv.helpers.config import load_config

        config_dic = load_config(self.logger, "CAhandler")
        self.api_host = config_dic.get("CAhandler", "api_host", fallback=None)


class TestCAHandlerRegistry(unittest.TestCase):
    """test class for CAHandlerRegistry"""

    def setUp(self):
        """setup unittest"""
        from acme2certifier.acme_srv.helpers.config import load_config_cache_clear
        from acme2certifier.acme_srv.helpers.cahandler_registry import (
            BoundCAHandler,
            CAHandlerRegistry,
        )

        load_config_cache_clear()
        logging.basicConfig(level=logging.CRITICAL)
        self.logger = logging.getLogger("test_a2c")
        self.BoundCAHandler = BoundCAHandler
        self.CAHandlerRegistry = CAHandlerRegistry

    def tearDown(self):
        """teardown"""
        from acme2certifier.acme_srv.helpers.config import load_config_cache_clear

        load_config_cache_clear()

    def _cfg(self, sections: dict) -> configparser.ConfigParser:
        """Build a ConfigParser from a nested dict of sections."""
        config = configparser.ConfigParser()
        for section, options in sections.items():
            if not config.has_section(section):
                config.add_section(section)
            for key, value in options.items():
                config.set(section, key, value)
        return config

    def _multi_registry(self):
        """Build a loaded multi-handler registry with openssl + ejbca."""
        config = self._cfg(
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
            return self.CAHandlerRegistry(self.logger).load(config)

    def _routing_registry(self, route_domainlist: str):
        """Multi-handler registry with openssl default and an internal route list."""
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
                    "route_domainlist": route_domainlist,
                },
            }
        )
        module = SimpleNamespace(CAhandler=_DummyHandler)
        with patch(
            "acme2certifier.acme_srv.helpers.cahandler_registry.ca_handler_load_from_section",
            return_value=module,
        ):
            return self.CAHandlerRegistry(self.logger).load(config)

    @patch(
        "acme2certifier.acme_srv.helpers.cahandler_registry.ca_handler_load_from_section"
    )
    def test_001_classical_mode_single_handler(self, mock_load):
        """classical mode loads a single bound default handler"""
        module = SimpleNamespace(CAhandler=_DummyHandler)
        mock_load.return_value = module
        config = self._cfg(
            {
                "CAhandler": {
                    "handler_module": "acme2certifier.cahandlers.openssl_ca_handler"
                }
            }
        )
        registry = self.CAHandlerRegistry(self.logger).load(config)
        self.assertFalse(registry.multi_handler)
        bound = registry.resolve()
        self.assertIsNotNone(bound)
        self.assertEqual(bound.name, "default")
        with bound(False, self.logger) as inst:
            self.assertEqual(inst.config_section, "CAhandler")

    @patch(
        "acme2certifier.acme_srv.helpers.cahandler_registry.ca_handler_load_from_section"
    )
    def test_002_multi_handler_config_parse(self, mock_load):
        """multi_handler parses default_handler and profile_cahandler"""
        module = SimpleNamespace(CAhandler=_DummyHandler)
        mock_load.return_value = module
        config = self._cfg(
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
        registry = self.CAHandlerRegistry(self.logger).load(config)
        self.assertTrue(registry.multi_handler)
        self.assertEqual(registry.default_name, "openssl")
        self.assertIn("openssl", registry.handlers)
        self.assertEqual(registry.profile_cahandler, {"long": "ejbca"})

    def test_003_load_config_honors_bound_section_via_context(self):
        """load_config merges a thread-local bound named CAhandler section"""
        from acme2certifier.acme_srv.helpers.config import (
            cahandler_config_section_reset,
            cahandler_config_section_set,
            load_config,
        )

        config = self._cfg(
            {
                "CAhandler": {"shared_flag": "yes"},
                "CAhandler:ejbca": {"api_host": "https://ejbca.example"},
            }
        )
        with (
            patch(
                "acme2certifier.acme_srv.helpers.config._read_config_file",
                return_value="",
            ),
            patch(
                "acme2certifier.acme_srv.helpers.config._parse_config_content",
                return_value=(config, "ini"),
            ),
        ):
            token = cahandler_config_section_set("CAhandler:ejbca")
            try:
                merged = load_config(self.logger)
            finally:
                cahandler_config_section_reset(token)
        self.assertEqual(merged.get("CAhandler", "api_host"), "https://ejbca.example")
        self.assertEqual(merged.get("CAhandler", "shared_flag"), "yes")

    def test_004_nested_section_bind_restores_previous(self):
        """Nested set/reset restores the previous bound section"""
        from acme2certifier.acme_srv.helpers.config import (
            cahandler_config_section_get,
            cahandler_config_section_reset,
            cahandler_config_section_set,
        )

        self.assertIsNone(cahandler_config_section_get())
        outer = cahandler_config_section_set("CAhandler:openssl")
        try:
            self.assertEqual(cahandler_config_section_get(), "CAhandler:openssl")
            inner = cahandler_config_section_set("CAhandler:ejbca")
            try:
                self.assertEqual(cahandler_config_section_get(), "CAhandler:ejbca")
            finally:
                cahandler_config_section_reset(inner)
            self.assertEqual(cahandler_config_section_get(), "CAhandler:openssl")
        finally:
            cahandler_config_section_reset(outer)
        self.assertIsNone(cahandler_config_section_get())

    def test_005_load_config_section_aliases_named_section(self):
        """load_config_section aliases a named handler section onto CAhandler"""
        from acme2certifier.acme_srv.helpers.config import load_config_section

        config = self._cfg(
            {
                "CAhandler": {"shared_flag": "yes"},
                "CAhandler:ejbca": {"api_host": "https://ejbca.example"},
            }
        )
        with (
            patch(
                "acme2certifier.acme_srv.helpers.config._read_config_file",
                return_value="",
            ),
            patch(
                "acme2certifier.acme_srv.helpers.config._parse_config_content",
                return_value=(config, "ini"),
            ),
        ):
            merged = load_config_section(self.logger, "CAhandler:ejbca")
        self.assertEqual(merged.get("CAhandler", "api_host"), "https://ejbca.example")
        self.assertEqual(merged.get("CAhandler", "shared_flag"), "yes")

    def test_006_bound_cahandler_load_config_in_context(self):
        """BoundCAHandler context makes load_config see the named section"""
        config = self._cfg(
            {
                "CAhandler": {"shared_flag": "yes"},
                "CAhandler:ejbca": {"api_host": "https://ejbca.example"},
            }
        )
        bound = self.BoundCAHandler(_DummyHandler, "CAhandler:ejbca", "ejbca")
        with (
            patch(
                "acme2certifier.acme_srv.helpers.config._read_config_file",
                return_value="",
            ),
            patch(
                "acme2certifier.acme_srv.helpers.config._parse_config_content",
                return_value=(config, "ini"),
            ),
        ):
            with bound(False, self.logger) as handler:
                handler._config_load()
        self.assertEqual(handler.api_host, "https://ejbca.example")

    def test_007_resolve_default_handler(self):
        """resolve() without a match returns the default handler"""
        registry = self._multi_registry()
        bound = registry.resolve(csr="dummy-csr-with-no-domain-match")
        self.assertIsNotNone(bound)
        self.assertEqual(bound.name, "openssl")

    def test_008_resolve_profile_cahandler(self):
        """resolve() uses Order profile_cahandler mapping"""
        registry = self._multi_registry()
        bound = registry.resolve(order_profile="long", csr="dummy")
        self.assertIsNotNone(bound)
        self.assertEqual(bound.name, "ejbca")

    def test_009_resolve_eab_cahandler_name(self):
        """resolve() prefers an explicit EAB cahandler_name"""
        registry = self._multi_registry()
        bound = registry.resolve(cahandler_name="ejbca", csr="dummy")
        self.assertIsNotNone(bound)
        self.assertEqual(bound.name, "ejbca")

    def test_010_resolve_unknown_eab_name_returns_none(self):
        """unknown EAB cahandler_name does not fall back silently"""
        registry = self._multi_registry()
        self.assertIsNone(registry.resolve(cahandler_name="missing", csr="dummy"))

    def test_011_resolve_stored_name(self):
        """resolve() returns a previously stored handler name"""
        registry = self._multi_registry()
        bound = registry.resolve(stored_name="ejbca", csr="dummy")
        self.assertIsNotNone(bound)
        self.assertEqual(bound.name, "ejbca")

    @patch(
        "acme2certifier.acme_srv.helper.csr_cn_get",
        return_value="host.internal.example",
    )
    @patch(
        "acme2certifier.acme_srv.helper.csr_san_get",
        return_value=["dns:host.internal.example"],
    )
    def test_012_resolve_domain_routing(self, _mock_san, _mock_cn):
        """wildcard route_domainlist selects the matching handler"""
        registry = self._routing_registry('["*.internal.example"]')
        bound = registry.resolve(csr="dummy-csr")
        self.assertIsNotNone(bound)
        self.assertEqual(bound.name, "internal")

    @patch(
        "acme2certifier.acme_srv.helper.csr_cn_get",
        return_value="host.internal.example",
    )
    @patch(
        "acme2certifier.acme_srv.helper.csr_san_get",
        return_value=["dns:host.internal.example"],
    )
    def test_013_resolve_domain_routing_exact_host(self, _mock_san, _mock_cn):
        """exact-host route_domainlist selects the matching handler"""
        registry = self._routing_registry('["host.internal.example"]')
        bound = registry.resolve(csr="dummy-csr")
        self.assertIsNotNone(bound)
        self.assertEqual(bound.name, "internal")

    @patch(
        "acme2certifier.acme_srv.helper.csr_cn_get",
        return_value="internal.example",
    )
    @patch(
        "acme2certifier.acme_srv.helper.csr_san_get",
        return_value=["dns:internal.example"],
    )
    def test_014_resolve_domain_routing_wildcard_skips_apex(self, _mock_san, _mock_cn):
        """wildcard route_domainlist does not match the apex name"""
        registry = self._routing_registry('["*.internal.example"]')
        bound = registry.resolve(csr="dummy-csr")
        self.assertIsNotNone(bound)
        self.assertEqual(bound.name, "openssl")

    @patch(
        "acme2certifier.acme_srv.helper.csr_cn_get",
        return_value="foointernal.example",
    )
    @patch(
        "acme2certifier.acme_srv.helper.csr_san_get",
        return_value=["dns:foointernal.example"],
    )
    def test_015_resolve_domain_routing_wildcard_requires_dot(
        self, _mock_san, _mock_cn
    ):
        """wildcard route_domainlist requires a dotted label boundary"""
        registry = self._routing_registry('["*.internal.example"]')
        bound = registry.resolve(csr="dummy-csr")
        self.assertIsNotNone(bound)
        self.assertEqual(bound.name, "openssl")

    @patch(
        "acme2certifier.acme_srv.helper.csr_cn_get",
        return_value="host.internal.example",
    )
    @patch(
        "acme2certifier.acme_srv.helper.csr_san_get",
        return_value=["dns:other.example.com"],
    )
    def test_016_resolve_domain_routing_all_identifiers_must_match(
        self, _mock_san, _mock_cn
    ):
        """all CSR identifiers must match the route list"""
        registry = self._routing_registry('["*.internal.example"]')
        bound = registry.resolve(csr="dummy-csr")
        self.assertIsNotNone(bound)
        self.assertEqual(bound.name, "openssl")

    @patch(
        "acme2certifier.acme_srv.helper.csr_cn_get",
        return_value="host.internal.example",
    )
    @patch(
        "acme2certifier.acme_srv.helper.csr_san_get",
        return_value=["dns:host.internal.example"],
    )
    def test_017_resolve_domain_routing_regex_pattern_is_literal(
        self, _mock_san, _mock_cn
    ):
        """regex-like route_domainlist entries are treated as literals"""
        registry = self._routing_registry('["\\\\.internal\\\\.example$"]')
        bound = registry.resolve(csr="dummy-csr")
        self.assertIsNotNone(bound)
        self.assertEqual(bound.name, "openssl")

    def test_018_cahandler_lookup_from_csr(self):
        """cahandler_lookup returns the stored handler name for a CSR"""
        from acme2certifier.acme_srv.helpers.config import cahandler_lookup

        models_mock = MagicMock()
        models_mock.DBstore.return_value.certificates_search.return_value = [
            {"order__cahandler": "ejbca"}
        ]
        modules = {"acme2certifier.acme_srv.db_handler": models_mock}
        with patch.dict(sys.modules, modules):
            self.assertEqual(cahandler_lookup(self.logger, csr="test-csr"), "ejbca")

    def test_019_cahandler_lookup_recodes_cert_raw(self):
        """cahandler_lookup recodes cert_raw before searching"""
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


if __name__ == "__main__":
    unittest.main()
