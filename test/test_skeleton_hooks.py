#!/usr/bin/python
# -*- coding: utf-8 -*-
"""unittests for skeleton_hooks"""

# pylint: disable=C0415, W0212
import unittest
import sys
import logging

sys.path.insert(0, ".")
sys.path.insert(1, "..")


class TestSkeletonHooks(unittest.TestCase):
    """test class for skeleton_hooks.Hooks"""

    def setUp(self):
        """setup unittest"""
        logging.basicConfig(level=logging.CRITICAL)
        self.logger = logging.getLogger("test_a2c")
        from acme2certifier.hookhandlers.skeleton_hooks import Hooks

        self.hooks = Hooks(self.logger)

    def test_001_init(self):
        """test Hooks.__init__"""
        self.assertEqual(self.hooks.logger, self.logger)

    def test_002_pre_hook(self):
        """pre_hook runs without error"""
        self.hooks.pre_hook("cert", "order", "csr")

    def test_003_post_hook(self):
        """post_hook runs without error"""
        self.hooks.post_hook("cert", "order", "csr", "error")

    def test_004_success_hook(self):
        """success_hook runs without error"""
        self.hooks.success_hook("cert", "order", "csr", "certificate", "raw", "poll")


if __name__ == "__main__":
    unittest.main()
