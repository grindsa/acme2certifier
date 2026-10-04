# -*- coding: utf-8 -*-
"""Tests for cross-origin redirect credential header stripping."""

# pylint: disable=C0415, W0212
import sys
import unittest
from unittest.mock import Mock

import requests

sys.path.insert(0, ".")
sys.path.insert(1, "..")


class TestRedirectCredentialStrip(unittest.TestCase):
    """requests.Session rebuild_auth credential strip patch"""

    def setUp(self):
        # Ensure network helpers (and the Session patch) are loaded.
        from acme2certifier.acme_srv.helpers import network as network_mod

        self.network = network_mod
        self.is_cred = network_mod._is_credential_header
        self.assertTrue(
            getattr(requests.Session, "_a2c_rebuild_auth_patched", False),
            "Session.rebuild_auth patch should be installed",
        )

    def _prepared(self, session, url, headers):
        req = requests.Request("GET", url, headers=headers)
        return session.prepare_request(req)

    def _response(self, url):
        resp = Mock()
        resp.request = Mock()
        resp.request.url = url
        return resp

    def test_001_is_credential_header_known_names(self):
        """Known CA API credential headers are detected"""
        self.assertTrue(self.is_cred("X-Vault-Token"))
        self.assertTrue(self.is_cred("X-DC-DEVKEY"))
        self.assertTrue(self.is_cred("x-api-key"))
        self.assertTrue(self.is_cred("Authorization"))
        self.assertFalse(self.is_cred("Content-Type"))
        self.assertFalse(self.is_cred("Accept"))

    def test_002_strips_custom_creds_on_cross_host_redirect(self):
        """Cross-host redirect drops Vault/DigiCert/ASA headers"""
        session = requests.Session()
        prepared = self._prepared(
            session,
            "https://evil.example/steal",
            {
                "X-Vault-Token": "vault-secret",
                "X-DC-DEVKEY": "dc-secret",
                "x-api-key": "asa-secret",
                "Authorization": "Bearer keep-stripped",
                "Content-Type": "application/json",
            },
        )
        prepared.url = "https://evil.example/steal"
        session.rebuild_auth(prepared, self._response("https://vault.example/v1/issue"))
        self.assertIsNone(prepared.headers.get("X-Vault-Token"))
        self.assertIsNone(prepared.headers.get("X-DC-DEVKEY"))
        self.assertIsNone(prepared.headers.get("x-api-key"))
        self.assertIsNone(prepared.headers.get("Authorization"))
        self.assertEqual(prepared.headers.get("Content-Type"), "application/json")

    def test_003_keeps_creds_on_same_host_redirect(self):
        """Same-host redirect retains custom credential headers"""
        session = requests.Session()
        prepared = self._prepared(
            session,
            "https://vault.example/v1/bar",
            {
                "X-Vault-Token": "vault-secret",
                "Content-Type": "application/json",
            },
        )
        prepared.url = "https://vault.example/v1/bar"
        session.rebuild_auth(prepared, self._response("https://vault.example/v1/foo"))
        self.assertEqual(prepared.headers.get("X-Vault-Token"), "vault-secret")
        self.assertEqual(prepared.headers.get("Content-Type"), "application/json")

    def test_004_strips_on_https_to_http_same_host(self):
        """Scheme downgrade strips credentials (requests should_strip_auth)"""
        session = requests.Session()
        prepared = self._prepared(
            session,
            "http://vault.example/v1/bar",
            {"X-Vault-Token": "vault-secret"},
        )
        prepared.url = "http://vault.example/v1/bar"
        session.rebuild_auth(prepared, self._response("https://vault.example/v1/foo"))
        self.assertIsNone(prepared.headers.get("X-Vault-Token"))

    def test_005_resolve_keeps_requests_module(self):
        """Default session stays the requests module so handler tests can mock it"""
        self.assertIs(self.network.resolve_request_session(requests), requests)
        self.assertIs(self.network.resolve_request_session(None), requests)

    def test_006_redirect_credential_strip_session_subclass(self):
        """RedirectCredentialStripSession also strips via the class patch"""
        session = self.network.RedirectCredentialStripSession()
        prepared = self._prepared(
            session,
            "https://evil.example/",
            {"X-DC-DEVKEY": "dc-secret", "Accept": "application/json"},
        )
        prepared.url = "https://evil.example/"
        session.rebuild_auth(
            prepared, self._response("https://api.digicert.com/v2/order")
        )
        self.assertIsNone(prepared.headers.get("X-DC-DEVKEY"))
        self.assertEqual(prepared.headers.get("Accept"), "application/json")

    def test_007_is_credential_header_apikey_and_token_suffix(self):
        """Heuristic matches apikey substring and *-token / *_token suffixes"""
        self.assertTrue(self.is_cred("X-Custom-Apikey"))
        self.assertTrue(self.is_cred("X-Service-Token"))
        self.assertTrue(self.is_cred("x_refresh_token"))
        self.assertFalse(self.is_cred("X-Request-Id"))

    def test_008_normalize_request_url_empty_and_match(self):
        """normalize_request_url handles empty input; match helper compares"""
        self.assertEqual(self.network.normalize_request_url(""), "")
        self.assertEqual(self.network.normalize_request_url(None), "")
        self.assertTrue(
            self.network.protected_url_matches_request(
                "HTTPS://Host.Example/acme/new/",
                "https://host.example/acme/new",
            )
        )

    def test_009_first_resolved_address_variants(self):
        """_first_resolved_address picks list/str or falls back"""
        first = self.network._first_resolved_address
        self.assertEqual(first(["10.0.0.1", "10.0.0.2"], "fallback"), "10.0.0.1")
        self.assertEqual(first([], "fallback"), "fallback")
        self.assertEqual(first("10.0.0.9", "fallback"), "10.0.0.9")
        self.assertEqual(first("", "fallback"), "fallback")
        self.assertEqual(first(None, "fallback"), "fallback")

    def test_010_ensure_custom_dns_connect_wrapper_races_and_idempotent(self):
        """Second check inside lock returns early; install is idempotent"""
        from unittest.mock import patch

        # Already installed: first-line early return
        self.network._dns_connect_wrapper_installed = True
        self.network._ensure_custom_dns_connect_wrapper()

        # Simulate race: flag becomes True after outer check, before inner check
        self.network._dns_connect_wrapper_installed = False

        class _RaceLock:
            def __enter__(self_inner):
                self.network._dns_connect_wrapper_installed = True
                return self_inner

            def __exit__(self_inner, *args):
                return False

        with patch.object(self.network, "_dns_connect_install_lock", _RaceLock()):
            self.network._ensure_custom_dns_connect_wrapper()
        self.assertTrue(self.network._dns_connect_wrapper_installed)

    def test_011_install_session_rebuild_auth_patch_idempotent(self):
        """_install_session_rebuild_auth_patch returns early when already patched"""
        self.assertTrue(getattr(requests.Session, "_a2c_rebuild_auth_patched", False))
        self.network._install_session_rebuild_auth_patch()


if __name__ == "__main__":
    unittest.main()
