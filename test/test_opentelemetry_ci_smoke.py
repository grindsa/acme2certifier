# -*- coding: utf-8 -*-
"""CI smoke: real OTLP HTTP export to a collector (Jaeger).

Skipped unless ``A2C_OTEL_CI_SMOKE=1``. Used by
``.github/workflows/quality-opentelemetry.yml``.
"""

from __future__ import annotations

import logging
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

import configparser
import pytest

from acme2certifier.acme_srv.helpers import otel as otel_mod


def _smoke_enabled() -> bool:
    return os.environ.get("A2C_OTEL_CI_SMOKE", "").strip() in ("1", "true", "True")


pytestmark = pytest.mark.skipif(
    not _smoke_enabled(),
    reason="set A2C_OTEL_CI_SMOKE=1 with a reachable OTLP HTTP collector",
)


def _cfg(**otel_items: str) -> configparser.ConfigParser:
    parser = configparser.ConfigParser()
    parser["OpenTelemetry"] = dict(otel_items)
    return parser


def _jaeger_services(ui_base: str) -> list[str]:
    url = f"{ui_base.rstrip('/')}/api/services"
    with urllib.request.urlopen(url, timeout=5) as resp:  # noqa: S310 — CI localhost
        import json

        payload = json.loads(resp.read().decode("utf-8"))
    data = payload.get("data")
    if isinstance(data, list):
        return [str(x) for x in data]
    return []


def _jaeger_trace_count(ui_base: str, service: str) -> int:
    query = urllib.parse.urlencode({"service": service, "limit": "20"})
    url = f"{ui_base.rstrip('/')}/api/traces?{query}"
    with urllib.request.urlopen(url, timeout=5) as resp:  # noqa: S310 — CI localhost
        import json

        payload = json.loads(resp.read().decode("utf-8"))
    data = payload.get("data")
    if isinstance(data, list):
        return len(data)
    return 0


def _force_flush(timeout_ms: int = 15000) -> None:
    from opentelemetry import trace

    provider = trace.get_tracer_provider()
    flush = getattr(provider, "force_flush", None)
    if callable(flush):
        assert flush(timeout_millis=timeout_ms) is not False


def test_otlp_http_export_appears_in_jaeger() -> None:
    """Export one span via the facade; Jaeger must list the service + a trace."""
    pytest.importorskip("opentelemetry.sdk")
    endpoint = os.environ.get("A2C_OTEL_ENDPOINT", "http://127.0.0.1:4318").strip()
    service = os.environ.get("A2C_OTEL_SERVICE_NAME", "acme2certifier-ci").strip()
    ui = os.environ.get("A2C_OTEL_JAEGER_UI", "http://127.0.0.1:16686").strip()

    otel_mod.reset_otel_state()
    # Allow set_*_provider again after other tests / prior init.
    try:
        from opentelemetry import trace
        from opentelemetry.metrics import _internal as metrics_internal
        from opentelemetry.util._once import Once

        trace._TRACER_PROVIDER = None  # type: ignore[attr-defined]
        trace._TRACER_PROVIDER_SET_ONCE = Once()  # type: ignore[attr-defined]
        metrics_internal._METER_PROVIDER = None  # type: ignore[attr-defined]
        metrics_internal._METER_PROVIDER_SET_ONCE = Once()  # type: ignore[attr-defined]
    except ImportError:
        pass

    cfg = _cfg(
        opentelemetry_support="True",
        endpoint=endpoint,
        protocol="http/protobuf",
        service_name=service,
        sample_ratio="1.0",
        metrics_export="False",
    )
    logger = logging.getLogger("acme2certifier")
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(otel_mod, "load_config", lambda *_a, **_k: cfg)
        assert otel_mod.init_otel(logger) is True

    with otel_mod.span(
        "acme.ci.smoke",
        attributes={"acme.outcome": "success", "ci.smoke": True},
    ):
        pass

    _force_flush()

    deadline = time.time() + 45.0
    last_err: Any = None
    while time.time() < deadline:
        try:
            services = _jaeger_services(ui)
            if service in services and _jaeger_trace_count(ui, service) >= 1:
                return
        except (urllib.error.URLError, TimeoutError, ValueError, KeyError) as err:
            last_err = err
        time.sleep(1.0)

    raise AssertionError(
        f"Jaeger did not show service={service!r} with traces within timeout "
        f"(endpoint={endpoint}, last_err={last_err})"
    )
