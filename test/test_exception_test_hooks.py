#!/usr/bin/python
# -*- coding: utf-8 -*-
"""unittests for exception_test_hooks"""

# pylint: disable=C0415, W0212
import unittest
import sys
import logging
from unittest.mock import patch
import configparser

sys.path.insert(0, ".")
sys.path.insert(1, "..")


class TestExceptionTestHooks(unittest.TestCase):
    """test class for exception_test_hooks.Hooks"""

    def setUp(self):
        """setup unittest"""
        logging.basicConfig(level=logging.CRITICAL)
        self.logger = logging.getLogger("test_a2c")
        self._config_patch = patch(
            "acme2certifier.hookhandlers.exception_test_hooks.load_config",
            return_value=configparser.ConfigParser(),
        )
        self._config_patch.start()
        self.addCleanup(self._config_patch.stop)
        from acme2certifier.hookhandlers.exception_test_hooks import Hooks

        self.hooks = Hooks(self.logger)

    def test_001_init(self):
        """test Hooks.__init__ defaults"""
        self.assertFalse(self.hooks.raise_pre_hook_exception)
        self.assertFalse(self.hooks.raise_success_hook_exception)
        self.assertFalse(self.hooks.raise_post_hook_exception)

    def test_002_enter_exit(self):
        """test context manager enter/exit"""
        self.assertIs(self.hooks.__enter__(), self.hooks)
        self.assertIsNone(self.hooks.__exit__(None, None, None))

    @patch("acme2certifier.hookhandlers.exception_test_hooks.load_config")
    def test_003_config_load_no_hooks_section(self, mock_load_cfg):
        """_config_load keeps defaults without Hooks section"""
        mock_load_cfg.return_value = configparser.ConfigParser()
        self.hooks._config_load()
        self.assertFalse(self.hooks.raise_pre_hook_exception)
        self.assertFalse(self.hooks.raise_success_hook_exception)
        self.assertFalse(self.hooks.raise_post_hook_exception)

    @patch("acme2certifier.hookhandlers.exception_test_hooks.load_config")
    def test_004_config_load_flags_true(self, mock_load_cfg):
        """_config_load enables exception flags from config"""
        parser = configparser.ConfigParser()
        parser["Hooks"] = {
            "raise_pre_hook_exception": "True",
            "raise_success_hook_exception": "True",
            "raise_post_hook_exception": "True",
        }
        mock_load_cfg.return_value = parser
        self.hooks._config_load()
        self.assertTrue(self.hooks.raise_pre_hook_exception)
        self.assertTrue(self.hooks.raise_success_hook_exception)
        self.assertTrue(self.hooks.raise_post_hook_exception)

    def test_005_pre_hook_no_exception(self):
        """pre_hook does not raise when flag is False"""
        self.hooks.raise_pre_hook_exception = False
        self.hooks.pre_hook("cert", "order", "csr")

    def test_006_pre_hook_raises(self):
        """pre_hook raises SystemError when flag is True"""
        self.hooks.raise_pre_hook_exception = True
        with self.assertRaises(SystemError) as ctx:
            self.hooks.pre_hook("cert", "order", "csr")
        self.assertEqual(str(ctx.exception), "raise_pre_hook_exception")

    def test_007_post_hook_no_exception(self):
        """post_hook does not raise when flag is False"""
        self.hooks.raise_post_hook_exception = False
        self.hooks.post_hook("cert", "order", "csr", "error")

    def test_008_post_hook_raises(self):
        """post_hook raises SystemError when flag is True"""
        self.hooks.raise_post_hook_exception = True
        with self.assertRaises(SystemError) as ctx:
            self.hooks.post_hook("cert", "order", "csr", "error")
        self.assertEqual(str(ctx.exception), "raise_post_hook_exception")

    def test_009_success_hook_no_exception(self):
        """success_hook does not raise when flag is False"""
        self.hooks.raise_success_hook_exception = False
        self.hooks.success_hook("cert", "order", "csr", "c", "raw", "poll")

    def test_010_success_hook_raises(self):
        """success_hook raises SystemError when flag is True"""
        self.hooks.raise_success_hook_exception = True
        with self.assertRaises(SystemError) as ctx:
            self.hooks.success_hook("cert", "order", "csr", "c", "raw", "poll")
        self.assertEqual(str(ctx.exception), "raise_success_hook_exception")


if __name__ == "__main__":
    unittest.main()
