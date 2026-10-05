#!/usr/bin/python
# -*- coding: utf-8 -*-
"""unittests for django_project.urls"""

# pylint: disable=C0415
import configparser
import importlib
import logging
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

import django
from django.conf import settings


def _bootstrap_django() -> None:
    if settings.configured:
        return
    settings.configure(
        INSTALLED_APPS=[
            "django.contrib.contenttypes",
            "django.contrib.auth",
            "django.contrib.sessions",
            "django.contrib.messages",
            "django.contrib.staticfiles",
            "acme2certifier.django_app.apps.AcmeSrvConfig",
        ],
        DATABASES={
            "default": {"ENGINE": "django.db.backends.sqlite3", "NAME": ":memory:"}
        },
        SECRET_KEY="test-django-project-urls",
        USE_TZ=True,
        ROOT_URLCONF="acme2certifier.django_project.urls",
        MIDDLEWARE=[],
        TEMPLATES=[
            {
                "BACKEND": "django.template.backends.django.DjangoTemplates",
                "DIRS": [],
                "APP_DIRS": True,
                "OPTIONS": {"context_processors": []},
            }
        ],
        ALLOWED_HOSTS=["*"],
    )
    django.setup()


_bootstrap_django()

_URLS = "acme2certifier.django_project.urls"
_VIEWS = "acme2certifier.django_app.views"
_APP_URLS = "acme2certifier.django_app.urls"


def _cfg(**sections) -> configparser.ConfigParser:
    """build ConfigParser usable by both urls and views imports"""
    cfg = configparser.ConfigParser()
    cfg["DEFAULT"] = {"debug": "False"}
    for section, values in sections.items():
        cfg[section] = values
    return cfg


class TestDjangoProjectUrls(unittest.TestCase):
    """cover PREFIX / acme-challenge urlpattern branches"""

    def setUp(self) -> None:
        logging.basicConfig(level=logging.CRITICAL)
        self.logger = logging.getLogger("test_a2c")
        self._tmpdir = tempfile.mkdtemp(prefix="a2c_dj_urls_")
        self._env = patch.dict(
            "os.environ", {"ACME2CERTIFIER_BASE_DIR": self._tmpdir}, clear=False
        )
        self._env.start()
        for name in (_URLS, _VIEWS, _APP_URLS):
            sys.modules.pop(name, None)

    def tearDown(self) -> None:
        self._env.stop()
        import shutil

        shutil.rmtree(self._tmpdir, ignore_errors=True)
        for name in (_URLS, _VIEWS, _APP_URLS):
            sys.modules.pop(name, None)

    def _reload_urls(
        self, config, trigger_enabled: bool = False, housekeeping_enabled: bool = False
    ):
        # Avoid coupling to whichever Django apps the prior suite configured.
        mock_views = MagicMock()
        mock_views.TRIGGER_ENDPOINT_ENABLED = trigger_enabled
        mock_views.HOUSEKEEPING_CLI_ENABLED = housekeeping_enabled
        mock_app_urls = MagicMock(urlpatterns=[])
        sys.modules[_VIEWS] = mock_views
        sys.modules[_APP_URLS] = mock_app_urls
        # Parent package may already hold a real submodule reference from other tests.
        import acme2certifier.django_app as django_app_pkg

        django_app_pkg.views = mock_views
        django_app_pkg.urls = mock_app_urls
        with patch("acme2certifier.acme_srv.helper.load_config", return_value=config):
            return importlib.import_module(_URLS)

    def test_001_no_prefix_no_acme_challenge(self) -> None:
        """empty Directory config → PREFIX '' and no acme-challenge / trigger / housekeeping routes"""
        mod = self._reload_urls(_cfg())
        self.assertEqual("", mod.PREFIX)
        names = [getattr(p, "name", None) for p in mod.urlpatterns]
        self.assertNotIn("acmechallenge_serve", names)
        self.assertNotIn("trigger", names)
        self.assertNotIn("housekeeping", names)
        self.assertIn("directory", names)

    def test_002_trigger_enabled(self) -> None:
        """TRIGGER_ENDPOINT_ENABLED True registers trigger route"""
        mod = self._reload_urls(_cfg(), trigger_enabled=True)
        names = [getattr(p, "name", None) for p in mod.urlpatterns]
        self.assertIn("trigger", names)

    def test_003_housekeeping_enabled(self) -> None:
        """HOUSEKEEPING_CLI_ENABLED True registers housekeeping route"""
        mod = self._reload_urls(_cfg(), housekeeping_enabled=True)
        names = [getattr(p, "name", None) for p in mod.urlpatterns]
        self.assertIn("housekeeping", names)

    def test_004_prefix_without_leading_slash(self) -> None:
        """url_prefix without leading slash is used as-is plus trailing /"""
        mod = self._reload_urls(_cfg(Directory={"url_prefix": "acme"}))
        self.assertEqual("acme/", mod.PREFIX)

    def test_005_prefix_with_leading_slash_stripped(self) -> None:
        """url_prefix starting with / is stripped"""
        mod = self._reload_urls(_cfg(Directory={"url_prefix": "/prefixed"}))
        self.assertEqual("prefixed/", mod.PREFIX)

    def test_006_acme_challenge_route_when_cahandler_acme_url(self) -> None:
        """CAhandler.acme_url adds .well-known/acme-challenge route"""
        mod = self._reload_urls(
            _cfg(
                Directory={"url_prefix": "p"},
                CAhandler={"acme_url": "http://example/acme"},
            )
        )
        names = [getattr(p, "name", None) for p in mod.urlpatterns]
        self.assertIn("acmechallenge_serve", names)

    def test_007_no_admin_route(self) -> None:
        """Django admin is not mounted (unused; avoids CSRF exposure)"""
        mod = self._reload_urls(_cfg())
        patterns = [str(getattr(p, "pattern", "")) for p in mod.urlpatterns]
        self.assertFalse(any("admin" in pattern for pattern in patterns))


if __name__ == "__main__":
    unittest.main()
