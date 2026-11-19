#!/usr/bin/python
# -*- coding: utf-8 -*-
"""unittests for acme_srv.helpers.db_handler_select"""

# pylint: disable=C0415
import configparser
import logging
import unittest
from unittest.mock import patch

from acme2certifier.acme_srv.helpers import db_handler_select as sel


class _SectionWithoutGet:
    """ConfigParser-like section without a .get method."""

    def __init__(self, data):
        self._data = data

    def __contains__(self, key):
        return key in self._data

    def __getitem__(self, key):
        return self._data[key]


class TestDbHandlerSelect(unittest.TestCase):
    """tests for db_handler_select resolution helpers"""

    def setUp(self):
        """setup unittest"""
        logging.basicConfig(level=logging.CRITICAL)
        self.logger = logging.getLogger("test_a2c")

    def test_001_section_get_missing_key(self):
        """_section_get returns empty when key absent"""
        self.assertEqual(sel._section_get({"handler": "wsgi"}, "handler_module"), "")

    def test_002_section_get_mapping_with_get(self):
        """_section_get uses section.get when present"""
        parser = configparser.ConfigParser()
        parser.read_string("[DBhandler]\nhandler = django\n")
        section = parser["DBhandler"]
        self.assertEqual(sel._section_get(section, "handler"), "django")

    def test_003_section_get_without_get_method(self):
        """_section_get falls back to section[key] without .get"""
        section = _SectionWithoutGet({"handler": "  wsgi  "})
        self.assertEqual(sel._section_get(section, "handler"), "wsgi")

    def test_004_normalize_short_and_custom(self):
        """_normalize_handler maps shorts and passes custom modules through"""
        self.assertEqual(
            sel._normalize_handler("wsgi"),
            "acme2certifier.dbhandlers.wsgi_handler",
        )
        self.assertEqual(
            sel._normalize_handler("DJANGO"),
            "acme2certifier.dbhandlers.django_handler",
        )
        self.assertEqual(
            sel._normalize_handler("my.custom.handler"), "my.custom.handler"
        )
        self.assertEqual(
            sel._normalize_handler("   "),
            "acme2certifier.dbhandlers.wsgi_handler",
        )

    def test_005_cfg_handler_name_handler_only(self):
        """_cfg_handler_name returns handler when handler_module unset"""
        config = {"DBhandler": {"handler": "django"}}
        self.assertEqual(sel._cfg_handler_name(config), "django")

    def test_006_cfg_handler_name_module_only(self):
        """_cfg_handler_name prefers handler_module"""
        config = {
            "DBhandler": {
                "handler_module": "acme2certifier.dbhandlers.wsgi_handler",
            }
        }
        self.assertEqual(
            sel._cfg_handler_name(config),
            "acme2certifier.dbhandlers.wsgi_handler",
        )

    def test_007_cfg_handler_name_both_set_logs_info(self):
        """both handler keys set logs INFO and returns handler_module"""
        config = {
            "DBhandler": {
                "handler": "django",
                "handler_module": "acme2certifier.dbhandlers.wsgi_handler",
            }
        }
        with self.assertLogs("acme2certifier.db_handler_select", level="INFO") as lcm:
            value = sel._cfg_handler_name(config)
        self.assertEqual(value, "acme2certifier.dbhandlers.wsgi_handler")
        self.assertTrue(
            any("Both handler_module and handler set" in line for line in lcm.output)
        )

    def test_008_cfg_handler_name_missing_section(self):
        """_cfg_handler_name returns None without DBhandler section"""
        self.assertIsNone(sel._cfg_handler_name({"DEFAULT": {}}))

    def test_009_cfg_handler_name_empty_section(self):
        """_cfg_handler_name returns None when no handler keys set"""
        self.assertIsNone(sel._cfg_handler_name({"DBhandler": {}}))

    def test_010_cfg_handler_name_load_config_success(self):
        """_cfg_handler_name loads acme_srv.cfg when config_dic is None"""
        fake_cfg = {"DBhandler": {"handler": "wsgi"}}
        with patch(
            "acme2certifier.acme_srv.helpers.config.load_config",
            return_value=fake_cfg,
        ):
            self.assertEqual(sel._cfg_handler_name(None), "wsgi")

    def test_011_cfg_handler_name_load_config_failure(self):
        """_cfg_handler_name returns None when load_config raises"""
        with patch(
            "acme2certifier.acme_srv.helpers.config.load_config",
            side_effect=RuntimeError("cfg boom"),
        ):
            self.assertIsNone(sel._cfg_handler_name(None))

    def test_012_resolve_db_handler_sources(self):
        """resolve_db_handler reports cfg, env, and default sources"""
        cfg = {"DBhandler": {"handler": "django"}}
        self.assertEqual(
            sel.resolve_db_handler(cfg),
            ("acme2certifier.dbhandlers.django_handler", "cfg"),
        )
        with patch.dict("os.environ", {sel.ENV_NAME: "wsgi"}, clear=False):
            self.assertEqual(
                sel.resolve_db_handler({"DBhandler": {"dbfile": "/tmp/x.db"}}),
                ("acme2certifier.dbhandlers.wsgi_handler", "env"),
            )
        with patch.dict("os.environ", {}, clear=True):
            self.assertEqual(
                sel.resolve_db_handler({"DBhandler": {}}),
                ("acme2certifier.dbhandlers.wsgi_handler", "default"),
            )

    def test_013_resolve_db_handler_module(self):
        """resolve_db_handler_module returns dotted module path"""
        config = {"DBhandler": {"handler": "django"}}
        self.assertEqual(
            sel.resolve_db_handler_module(config),
            "acme2certifier.dbhandlers.django_handler",
        )

    def test_014_resolve_db_handler_short_known_and_custom(self):
        """resolve_db_handler_short maps known modules and custom to wsgi"""
        django_cfg = {"DBhandler": {"handler": "django"}}
        self.assertEqual(sel.resolve_db_handler_short(django_cfg), "django")
        custom_cfg = {"DBhandler": {"handler_module": "my.custom.handler"}}
        self.assertEqual(sel.resolve_db_handler_short(custom_cfg), "wsgi")

    def test_015_warn_dbhandler_missing_handler_once(self):
        """warn_dbhandler_cfg_missing emits at most one warning per process"""
        sel._DBHANDLER_CFG_WARNED = False
        config = {"DBhandler": {"dbfile": "/tmp/x.db"}}
        with self.assertLogs(self.logger.name, level="WARNING") as lcm:
            sel.warn_dbhandler_cfg_missing(self.logger, config)
            sel.warn_dbhandler_cfg_missing(self.logger, config)
        matches = [line for line in lcm.output if "[DBhandler]" in line]
        self.assertEqual(len(matches), 1)
        self.assertIn("handler not set", matches[0])

    def test_016_warn_dbhandler_skips_when_config_dic_none(self):
        """warn_dbhandler_cfg_missing is a no-op without config_dic"""
        sel._DBHANDLER_CFG_WARNED = False
        sel.warn_dbhandler_cfg_missing(self.logger, None)
        self.assertFalse(sel._DBHANDLER_CFG_WARNED)

    def test_017_env_selection_hint_default(self):
        """_env_selection_hint returns default suffix when env unset"""
        with patch.dict("os.environ", {}, clear=True):
            self.assertEqual(sel._env_selection_hint(), " (default: wsgi)")

    def test_018_env_selection_hint_from_env(self):
        """_env_selection_hint includes env value when set"""
        with patch.dict("os.environ", {sel.ENV_NAME: "django"}, clear=False):
            self.assertIn(f"{sel.ENV_NAME}=django", sel._env_selection_hint())

    def test_019_warn_dbhandler_section_missing(self):
        """warn when [DBhandler] section is absent"""
        sel._DBHANDLER_CFG_WARNED = False
        with self.assertLogs(self.logger.name, level="WARNING") as lcm:
            sel.warn_dbhandler_cfg_missing(self.logger, {"DEFAULT": {}})
        self.assertTrue(sel._DBHANDLER_CFG_WARNED)
        self.assertIn("[DBhandler] section missing", lcm.output[0])

    def test_020_warn_dbhandler_skips_when_handler_module_set(self):
        """handler_module alone suppresses the cfg warning"""
        sel._DBHANDLER_CFG_WARNED = False
        config = {
            "DBhandler": {
                "handler_module": "acme2certifier.dbhandlers.wsgi_handler",
            }
        }
        sel.warn_dbhandler_cfg_missing(self.logger, config)
        self.assertFalse(sel._DBHANDLER_CFG_WARNED)

    def test_021_warn_dbhandler_valid_handler_no_warn(self):
        """valid short handler names do not warn"""
        sel._DBHANDLER_CFG_WARNED = False
        sel.warn_dbhandler_cfg_missing(
            self.logger, {"DBhandler": {"handler": "django"}}
        )
        self.assertFalse(sel._DBHANDLER_CFG_WARNED)

    def test_022_warn_dbhandler_invalid_handler(self):
        """invalid handler value emits a warning once"""
        sel._DBHANDLER_CFG_WARNED = False
        with self.assertLogs(self.logger.name, level="WARNING") as lcm:
            sel.warn_dbhandler_cfg_missing(
                self.logger, {"DBhandler": {"handler": "custom"}}
            )
        self.assertTrue(sel._DBHANDLER_CFG_WARNED)
        self.assertIn("is not wsgi or django", lcm.output[0])
        self.assertIn("custom", lcm.output[0])


if __name__ == "__main__":
    unittest.main()
