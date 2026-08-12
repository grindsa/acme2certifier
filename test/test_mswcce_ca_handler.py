# -*- coding: utf-8 -*-
"""Compatibility tests for deprecated MS-WCCE handler alias."""

from __future__ import annotations

import sys
import warnings
import unittest


class TestMswcceAliases(unittest.TestCase):
    """Ensure legacy handler module path keeps working."""

    def test_mswcce_ca_handler_alias(self):
        """mswcce_ca_handler re-exports msicpr CAhandler and warns."""
        sys.modules.pop("acme2certifier.cahandlers.mswcce_ca_handler", None)
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            from acme2certifier.cahandlers import mswcce_ca_handler
            from acme2certifier.cahandlers.msicpr_ca_handler import CAhandler as Canon

        self.assertIs(mswcce_ca_handler.CAhandler, Canon)
        self.assertTrue(
            any(issubclass(w.category, DeprecationWarning) for w in caught),
            caught,
        )


if __name__ == "__main__":
    unittest.main()
