#!/usr/bin/python
# -*- coding: utf-8 -*-
"""unittests for django_app.a2c_response"""

# pylint: disable=C0415
import json
import logging
import unittest

import django
from django.conf import settings


def _bootstrap_django() -> None:
    if settings.configured:
        return
    settings.configure(
        INSTALLED_APPS=["django.contrib.contenttypes"],
        SECRET_KEY="test-a2c-response",
        USE_TZ=True,
    )
    django.setup()


_bootstrap_django()

from acme2certifier.django_app.a2c_response import JsonResponse  # noqa: E402


class TestJsonResponse(unittest.TestCase):
    """test JsonResponse content-type and safe handling"""

    def setUp(self) -> None:
        logging.basicConfig(level=logging.CRITICAL)
        self.logger = logging.getLogger("test_a2c")

    def test_001_dict_ok_application_json(self) -> None:
        """dict payload uses application/json by default"""
        resp = JsonResponse({"foo": "bar"})
        self.assertEqual("application/json", resp["Content-Type"])
        self.assertEqual({"foo": "bar"}, json.loads(resp.content))

    def test_002_status_gt_201_problem_json(self) -> None:
        """status > 201 switches to application/problem+json"""
        resp = JsonResponse({"status": 400}, status=400)
        self.assertEqual("application/problem+json", resp["Content-Type"])

    def test_003_status_201_stays_application_json(self) -> None:
        """status 201 keeps application/json"""
        resp = JsonResponse({"ok": True}, status=201)
        self.assertEqual("application/json", resp["Content-Type"])

    def test_004_safe_true_rejects_non_dict(self) -> None:
        """safe=True raises TypeError for non-dict data"""
        with self.assertRaises(TypeError) as cm:
            JsonResponse(["not", "a", "dict"], safe=True)
        self.assertIn("safe parameter to False", str(cm.exception))

    def test_005_safe_false_allows_list(self) -> None:
        """safe=False serializes list payloads"""
        resp = JsonResponse([1, 2], safe=False)
        self.assertEqual([1, 2], json.loads(resp.content))

    def test_006_custom_json_dumps_params(self) -> None:
        """explicit json_dumps_params are honored"""
        resp = JsonResponse({"a": 1}, json_dumps_params={"indent": None, "separators": (",", ":")})
        self.assertEqual(b'{"a":1}', resp.content)


if __name__ == "__main__":
    unittest.main()
