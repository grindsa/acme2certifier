# -*- coding: utf-8 -*-
"""Django middleware for optional OpenTelemetry request root spans."""

from __future__ import annotations

from typing import Callable

from django.http import HttpRequest, HttpResponse

from acme2certifier.acme_srv.helpers.otel import acme_traced_request


class AcmeOpenTelemetryMiddleware:
    """Wrap each Django request in the enrollment-session OTEL request helper."""

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]) -> None:
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        path = request.path or ""
        body = request.body if request.method == "POST" else b""
        with acme_traced_request(request.method or "", path, body) as active:
            response = self.get_response(request)
            try:
                active.set_attribute("http.status_code", int(response.status_code))
            except (TypeError, ValueError, AttributeError):
                pass
            return response
