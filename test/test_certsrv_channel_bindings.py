#!/usr/bin/python
# -*- coding: utf-8 -*-
"""unit tests for certsrv GSSAPI channel bindings helpers"""

# pylint: disable=C0415, W0212
import sys
import types
import unittest
from unittest.mock import patch

sys.path.insert(0, ".")
sys.path.insert(1, "..")


def _fake_requests_gssapi(auth_cls):
    """Build a fake requests_gssapi module exposing HTTPSPNEGOAuth."""
    fake_mod = types.ModuleType("requests_gssapi")
    fake_mod.HTTPSPNEGOAuth = auth_cls
    return fake_mod


class TestCertsrvChannelBindings(unittest.TestCase):
    """tests for channel bindings helpers in certsrv.py"""

    def setUp(self):
        """setup"""
        from acme2certifier.cahandlers import certsrv as certsrv_mod

        self.certsrv_mod = certsrv_mod

    def test_001_supported_true(self):
        """gssapi_channel_bindings_supported returns True when parameter exists"""

        class FakeAuth:
            def __init__(self, channel_bindings=None, **_kwargs):
                self.channel_bindings = channel_bindings

        with patch.dict(
            "sys.modules", {"requests_gssapi": _fake_requests_gssapi(FakeAuth)}
        ):
            self.assertTrue(self.certsrv_mod.gssapi_channel_bindings_supported())

    def test_002_supported_false_missing_param(self):
        """gssapi_channel_bindings_supported returns False without parameter"""

        class FakeAuth:
            def __init__(self, **_kwargs):
                pass

        with patch.dict(
            "sys.modules", {"requests_gssapi": _fake_requests_gssapi(FakeAuth)}
        ):
            self.assertFalse(self.certsrv_mod.gssapi_channel_bindings_supported())

    def test_003_supported_false_import_error(self):
        """gssapi_channel_bindings_supported returns False if import fails"""
        import builtins

        real_import = builtins.__import__

        def _fake_import(name, *args, **kwargs):
            if name == "requests_gssapi":
                raise ImportError("missing")
            return real_import(name, *args, **kwargs)

        with patch("builtins.__import__", side_effect=_fake_import):
            self.assertFalse(self.certsrv_mod.gssapi_channel_bindings_supported())

    def test_004_http_spnego_auth_without_bindings(self):
        """_http_spnego_auth omits channel_bindings when unset"""
        calls = []

        class FakeAuth:
            def __init__(self, **kwargs):
                calls.append(kwargs)

        with patch.dict(
            "sys.modules", {"requests_gssapi": _fake_requests_gssapi(FakeAuth)}
        ):
            client = self.certsrv_mod.Certsrv.__new__(self.certsrv_mod.Certsrv)
            client.channel_bindings = None
            auth = client._http_spnego_auth(creds="cred")
            self.assertIsInstance(auth, FakeAuth)
            self.assertEqual([{"creds": "cred"}], calls)

    def test_005_http_spnego_auth_with_bindings(self):
        """_http_spnego_auth passes channel_bindings when supported"""
        calls = []

        class FakeAuth:
            def __init__(self, channel_bindings=None, **kwargs):
                calls.append({"channel_bindings": channel_bindings, **kwargs})

        with patch.dict(
            "sys.modules", {"requests_gssapi": _fake_requests_gssapi(FakeAuth)}
        ):
            with patch(
                "acme2certifier.cahandlers.certsrv.gssapi_channel_bindings_supported",
                return_value=True,
            ):
                client = self.certsrv_mod.Certsrv.__new__(self.certsrv_mod.Certsrv)
                client.channel_bindings = "tls-server-end-point"
                client._http_spnego_auth()
                self.assertEqual(
                    [{"channel_bindings": "tls-server-end-point"}], calls
                )

    def test_006_http_spnego_auth_unsupported_raises(self):
        """_http_spnego_auth raises when bindings requested but unsupported"""

        class FakeAuth:
            def __init__(self, **_kwargs):
                pass

        with patch.dict(
            "sys.modules", {"requests_gssapi": _fake_requests_gssapi(FakeAuth)}
        ):
            with patch(
                "acme2certifier.cahandlers.certsrv.gssapi_channel_bindings_supported",
                return_value=False,
            ):
                client = self.certsrv_mod.Certsrv.__new__(self.certsrv_mod.Certsrv)
                client.channel_bindings = "tls-server-end-point"
                with self.assertRaises(RuntimeError):
                    client._http_spnego_auth()

    def test_007_http_spnego_auth_invalid_value(self):
        """_http_spnego_auth rejects unsupported channel_bindings values"""

        class FakeAuth:
            def __init__(self, **_kwargs):
                pass

        with patch.dict(
            "sys.modules", {"requests_gssapi": _fake_requests_gssapi(FakeAuth)}
        ):
            client = self.certsrv_mod.Certsrv.__new__(self.certsrv_mod.Certsrv)
            client.channel_bindings = "invalid"
            with self.assertRaises(ValueError):
                client._http_spnego_auth()


if __name__ == "__main__":
    unittest.main()
