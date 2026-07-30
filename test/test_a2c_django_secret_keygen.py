#!/usr/bin/python
# -*- coding: utf-8 -*-
"""unittests for a2c_django_secret_keygen.py"""

# pylint: disable=C0415
import sys
import unittest
from unittest.mock import patch


class TestA2CDjangoSecretKeygen(unittest.TestCase):
    """tests for a2c_django_secret_keygen"""

    def test_001_main_prints_secret_key(self):
        """main() prints get_random_secret_key()"""
        with (
            patch(
                "django.core.management.utils.get_random_secret_key",
                return_value="secret-key-value",
            ),
            patch("builtins.print") as mock_print,
        ):
            from acme2certifier.tools import a2c_django_secret_keygen

            a2c_django_secret_keygen.main()

        mock_print.assert_called_once_with("secret-key-value")

    def test_002_module_main_entrypoint(self):
        """``__main__`` guard calls main()"""
        import runpy

        sys.modules.pop("acme2certifier.tools.a2c_django_secret_keygen", None)
        with (
            patch(
                "django.core.management.utils.get_random_secret_key",
                return_value="sk",
            ),
            patch("builtins.print") as mock_print,
        ):
            runpy.run_module(
                "acme2certifier.tools.a2c_django_secret_keygen",
                run_name="__main__",
                alter_sys=True,
            )
        mock_print.assert_called_once_with("sk")


if __name__ == "__main__":
    unittest.main()
