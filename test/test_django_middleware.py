#!/usr/bin/python
# -*- coding: utf-8 -*-
"""unittests for django_app.middleware"""

# pylint: disable=C0415
import logging
import unittest
from unittest.mock import MagicMock, patch

import django
from django.conf import settings


def _bootstrap_django() -> None:
    if settings.configured:
        return
    settings.configure(
        INSTALLED_APPS=["django.contrib.contenttypes"],
        SECRET_KEY="test-a2c-middleware",
        USE_TZ=True,
    )
    django.setup()


_bootstrap_django()

from acme2certifier.django_app.middleware import (  # noqa: E402
    AcmeOpenTelemetryMiddleware,
)


class TestAcmeOpenTelemetryMiddleware(unittest.TestCase):
    """Django request root span wrapper"""

    def setUp(self) -> None:
        logging.basicConfig(level=logging.CRITICAL)
        self.logger = logging.getLogger("test_a2c")

    def _request(self, method: str, path: str, body: bytes = b"") -> MagicMock:
        request = MagicMock()
        request.method = method
        request.path = path
        request.body = body
        return request

    def test_001_post_marks_http_status(self) -> None:
        """POST body is traced and the response status is recorded"""
        request = self._request("POST", "/acme/new-order", b'{"protected":"e30"}')
        response = MagicMock()
        response.status_code = 201
        active = MagicMock()
        traced = MagicMock()
        traced.return_value.__enter__.return_value = active
        traced.return_value.__exit__.return_value = False
        with (
            patch(
                "acme2certifier.django_app.middleware.acme_traced_request", traced
            ),
            patch(
                "acme2certifier.django_app.middleware.mark_http_status"
            ) as mark,
        ):
            middleware = AcmeOpenTelemetryMiddleware(lambda _req: response)
            self.assertIs(response, middleware(request))
        traced.assert_called_once_with(
            "POST", "/acme/new-order", b'{"protected":"e30"}'
        )
        mark.assert_called_once_with(active, 201)

    def test_002_get_and_status_errors(self) -> None:
        """GET sends an empty body; bad status values are ignored"""
        request = self._request(None, None)
        response = MagicMock()
        response.status_code = "nope"
        traced = MagicMock()
        traced.return_value.__enter__.return_value = MagicMock()
        traced.return_value.__exit__.return_value = False
        with (
            patch(
                "acme2certifier.django_app.middleware.acme_traced_request", traced
            ),
            patch(
                "acme2certifier.django_app.middleware.mark_http_status"
            ) as mark,
        ):
            middleware = AcmeOpenTelemetryMiddleware(lambda _req: response)
            self.assertIs(response, middleware(request))
            mark.assert_not_called()

            response.status_code = 500
            mark.side_effect = TypeError("bad status")
            self.assertIs(response, middleware(request))
        traced.assert_called_with("", "", b"")


if __name__ == "__main__":
    unittest.main()
