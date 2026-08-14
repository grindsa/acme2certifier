#!/usr/bin/python
# -*- coding: utf-8 -*-
"""unittests for cn_dump_hooks"""

# pylint: disable=C0415, W0212
import unittest
import sys
import logging
from unittest.mock import patch, mock_open, MagicMock
import configparser

sys.path.insert(0, ".")
sys.path.insert(1, "..")


class TestCnDumpHooks(unittest.TestCase):
    """test class for cn_dump_hooks.Hooks"""

    def setUp(self):
        """setup unittest"""
        logging.basicConfig(level=logging.CRITICAL)
        self.logger = logging.getLogger("test_a2c")
        self._config_patch = patch(
            "acme2certifier.hookhandlers.cn_dump_hooks.load_config",
            return_value=configparser.ConfigParser(),
        )
        self._config_patch.start()
        self.addCleanup(self._config_patch.stop)
        from acme2certifier.hookhandlers.cn_dump_hooks import Hooks

        self.hooks = Hooks(self.logger)

    def test_001_init(self):
        """test Hooks.__init__ defaults"""
        self.assertIsNone(self.hooks.save_path)
        self.assertEqual(self.hooks.logger, self.logger)

    def test_002_enter_exit(self):
        """test context manager enter/exit"""
        self.assertIs(self.hooks.__enter__(), self.hooks)
        self.assertIsNone(self.hooks.__exit__(None, None, None))

    @patch("acme2certifier.hookhandlers.cn_dump_hooks.load_config")
    def test_003_config_load_no_hooks_section(self, mock_load_cfg):
        """_config_load leaves save_path None without Hooks section"""
        mock_load_cfg.return_value = configparser.ConfigParser()
        self.hooks._config_load()
        self.assertIsNone(self.hooks.save_path)

    @patch("acme2certifier.hookhandlers.cn_dump_hooks.load_config")
    def test_004_config_load_without_save_path(self, mock_load_cfg):
        """_config_load leaves save_path None when save_path missing"""
        parser = configparser.ConfigParser()
        parser["Hooks"] = {"other": "value"}
        mock_load_cfg.return_value = parser
        self.hooks._config_load()
        self.assertIsNone(self.hooks.save_path)

    @patch("acme2certifier.hookhandlers.cn_dump_hooks.load_config")
    def test_005_config_load_with_save_path(self, mock_load_cfg):
        """_config_load sets save_path from Hooks section"""
        parser = configparser.ConfigParser()
        parser["Hooks"] = {"save_path": "/tmp/hooks"}
        mock_load_cfg.return_value = parser
        self.hooks._config_load()
        self.assertEqual(self.hooks.save_path, "/tmp/hooks")

    @patch("builtins.open", new_callable=mock_open)
    def test_006_file_append(self, mock_file):
        """_file_append writes content to file"""
        self.hooks._file_append("/tmp/hooks/out.txt", "content\n")
        mock_file.assert_called_with("/tmp/hooks/out.txt", "a", encoding="utf-8")
        mock_file().write.assert_called_with("content\n")

    @patch("acme2certifier.hookhandlers.cn_dump_hooks.csr_san_get")
    @patch("builtins.open", new_callable=mock_open)
    def test_007_pre_hook(self, mock_file, mock_csr_san):
        """pre_hook appends SAN list to pre_hook.txt"""
        mock_csr_san.return_value = ["DNS:example.com"]
        self.hooks.save_path = "/tmp/hooks"
        self.hooks.pre_hook("cert", "order", "csrdata")
        mock_csr_san.assert_called_with(self.logger, "csrdata")
        mock_file.assert_called_with("/tmp/hooks/pre_hook.txt", "a", encoding="utf-8")
        mock_file().write.assert_called_with('["DNS:example.com"]\n')

    @patch("acme2certifier.hookhandlers.cn_dump_hooks.csr_san_get")
    @patch("builtins.open", new_callable=mock_open)
    def test_008_post_hook(self, mock_file, mock_csr_san):
        """post_hook appends SAN list to post_hook.txt"""
        mock_csr_san.return_value = ["DNS:example.com"]
        self.hooks.save_path = "/tmp/hooks"
        self.hooks.post_hook("cert", "order", "csrdata", "error")
        mock_csr_san.assert_called_with(self.logger, "csrdata")
        mock_file.assert_called_with("/tmp/hooks/post_hook.txt", "a", encoding="utf-8")
        mock_file().write.assert_called_with('["DNS:example.com"]\n')

    @patch("acme2certifier.hookhandlers.cn_dump_hooks.cert_san_get")
    @patch("builtins.open", new_callable=mock_open)
    def test_009_success_hook(self, mock_file, mock_cert_san):
        """success_hook appends SAN list to success_hook.txt"""
        mock_cert_san.return_value = ["DNS:example.com"]
        self.hooks.save_path = "/tmp/hooks"
        self.hooks.success_hook(
            "cert", "order", "csr", "certificate", "cert_raw", "poll"
        )
        mock_cert_san.assert_called_with(self.logger, "cert_raw")
        mock_file.assert_called_with(
            "/tmp/hooks/success_hook.txt", "a", encoding="utf-8"
        )
        mock_file().write.assert_called_with('["DNS:example.com"]\n')


if __name__ == "__main__":
    unittest.main()
