#!/usr/bin/python
# -*- coding: utf-8 -*-
"""unittests for a2c_django_secret_keygen.py"""

# pylint: disable=C0415
import sys
import unittest
from unittest.mock import patch

from acme2certifier.tools.a2c_django_secret_keygen import (
    _SECRET_KEY_CHARS,
    _SECRET_KEY_LENGTH,
    generate_secret_key,
)


class TestA2CDjangoSecretKeygen(unittest.TestCase):
    """tests for a2c_django_secret_keygen"""

    def test_001_main_prints_secret_key(self):
        """main() prints generate_secret_key()"""
        with (
            patch(
                "acme2certifier.tools.a2c_django_secret_keygen.generate_secret_key",
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
        with patch("builtins.print") as mock_print:
            runpy.run_module(
                "acme2certifier.tools.a2c_django_secret_keygen",
                run_name="__main__",
                alter_sys=True,
            )
        mock_print.assert_called_once()
        key = mock_print.call_args[0][0]
        self.assertEqual(_SECRET_KEY_LENGTH, len(key))
        self.assertTrue(set(key) <= set(_SECRET_KEY_CHARS))

    def test_003_generate_secret_key_avoids_uwsgi_placeholders(self):
        """Keys omit % @ ( ) so uWSGI ini does not treat them as @(file) / magic"""
        for _ in range(20):
            key = generate_secret_key()
            self.assertEqual(_SECRET_KEY_LENGTH, len(key))
            self.assertTrue(set(key) <= set(_SECRET_KEY_CHARS))
            self.assertNotRegex(key, r"[@%()]")


if __name__ == "__main__":
    unittest.main()
