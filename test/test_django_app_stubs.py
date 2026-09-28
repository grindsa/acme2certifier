#!/usr/bin/python
# -*- coding: utf-8 -*-
"""unittests for django_app admin/tests/urls stubs"""

# pylint: disable=C0415
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
            "acme2certifier.django_app.apps.AcmeSrvConfig",
        ],
        DATABASES={
            "default": {"ENGINE": "django.db.backends.sqlite3", "NAME": ":memory:"}
        },
        SECRET_KEY="test-django-app-stubs",
        USE_TZ=True,
        ROOT_URLCONF="acme2certifier.django_app.urls",
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


class TestDjangoAppStubs(unittest.TestCase):
    """import coverage for admin / tests / urls"""

    def setUp(self) -> None:
        logging.basicConfig(level=logging.CRITICAL)
        self.logger = logging.getLogger("test_a2c")
        self._tmpdir = tempfile.mkdtemp(prefix="a2c_django_stubs_")
        self._env = patch.dict(
            "os.environ", {"ACME2CERTIFIER_BASE_DIR": self._tmpdir}, clear=False
        )
        self._env.start()

    def tearDown(self) -> None:
        self._env.stop()
        import shutil

        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_001_import_admin(self) -> None:
        """admin module imports (empty registration)"""
        import acme2certifier.django_app.admin as admin_mod

        self.assertTrue(hasattr(admin_mod, "__doc__"))

    def test_002_import_tests(self) -> None:
        """django_app.tests stub imports"""
        import acme2certifier.django_app.tests as tests_mod

        self.assertTrue(hasattr(tests_mod, "__doc__"))

    def test_003_import_urls(self) -> None:
        """urls module builds urlpatterns after views import"""
        mock_hk = MagicMock()
        mock_hk.dbversion_check = MagicMock()
        mock_hk.nonce_cleanup = MagicMock()
        mock_cm = MagicMock()
        mock_cm.__enter__.return_value = mock_hk
        mock_cm.__exit__.return_value = False

        for name in (
            "acme2certifier.django_app.urls",
            "acme2certifier.django_app.views",
        ):
            sys.modules.pop(name, None)

        with patch(
            "acme2certifier.acme_srv.housekeeping.Housekeeping", return_value=mock_cm
        ):
            import acme2certifier.django_app.urls as urls_mod

        self.assertTrue(len(urls_mod.urlpatterns) >= 10)
        names = {getattr(p, "name", None) for p in urls_mod.urlpatterns}
        self.assertIn("directory", names)
        self.assertIn("newaccount", names)

    def test_004_resource_routes_no_capture_args(self) -> None:
        """Path suffixes must not pass extra positional args into Django views."""
        import re

        from django.urls import resolve

        mock_hk = MagicMock()
        mock_cm = MagicMock()
        mock_cm.__enter__.return_value = mock_hk
        mock_cm.__exit__.return_value = False

        for name in (
            "acme2certifier.django_app.urls",
            "acme2certifier.django_app.views",
        ):
            sys.modules.pop(name, None)

        with patch(
            "acme2certifier.acme_srv.housekeeping.Housekeeping", return_value=mock_cm
        ):
            import acme2certifier.django_app.urls as urls_mod

        for pattern in urls_mod.urlpatterns:
            regex = str(getattr(pattern, "pattern", ""))
            self.assertFalse(
                re.search(r"\([^?][^)]*\)", regex),
                f"capturing group in {regex!r} would break view arity",
            )

        for path in (
            "authz/UJd0j258FXIs",
            "order/f10UwlTs5bMc",
            "order/f10UwlTs5bMc/finalize",
            "acct/abc",
            "chall/xyz",
            "cert/abc",
            "renewal-info/abc",
        ):
            match = resolve("/" + path)
            self.assertEqual(match.args, ())


if __name__ == "__main__":
    unittest.main()
