# -*- coding: utf-8 -*-
"""Tests for acme_srv.helpers.otel (NoOp gate + optional SDK InMemory cases)."""

from __future__ import annotations

import configparser
import logging
from typing import Any, Tuple
from unittest.mock import MagicMock, patch

import pytest

from acme2certifier.acme_srv.helpers import otel as otel_mod


def _cfg(**otel_items: str) -> configparser.ConfigParser:
    parser = configparser.ConfigParser()
    if otel_items:
        parser["OpenTelemetry"] = dict(otel_items)
    return parser


def _require_otel_sdk() -> None:
    """Skip SDK-backed tests when optional extra [otel] is not installed."""
    pytest.importorskip(
        "opentelemetry", reason="optional extra [otel] not installed"
    )
    pytest.importorskip(
        "opentelemetry.sdk", reason="optional extra [otel] not installed"
    )


def _reset_otel_api_providers() -> None:
    """Allow set_*_provider again between tests (SDK Once lock)."""
    try:
        from opentelemetry import trace
        from opentelemetry.metrics import _internal as metrics_internal
        from opentelemetry.util._once import Once
    except ImportError:
        return
    # Private API used by OpenTelemetry's own tests.
    trace._TRACER_PROVIDER = None  # type: ignore[attr-defined]
    trace._TRACER_PROVIDER_SET_ONCE = Once()  # type: ignore[attr-defined]
    metrics_internal._METER_PROVIDER = None  # type: ignore[attr-defined]
    metrics_internal._METER_PROVIDER_SET_ONCE = Once()  # type: ignore[attr-defined]


@pytest.fixture(autouse=True)
def _reset_otel() -> None:
    """Isolate module state between tests."""
    otel_mod._reset_otel_state()
    _reset_otel_api_providers()
    yield
    otel_mod._reset_otel_state()
    _reset_otel_api_providers()


def _enable_inmemory_providers() -> Tuple[Any, Any]:
    """Wire InMemory span/metric backends into the facade (no OTLP network)."""
    _require_otel_sdk()
    _reset_otel_api_providers()
    from opentelemetry import metrics, trace
    from opentelemetry.sdk.metrics import MeterProvider
    from opentelemetry.sdk.metrics.export import InMemoryMetricReader
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import (
        InMemorySpanExporter,
    )

    resource = Resource.create({"service.name": "acme2certifier-test"})
    span_exporter = InMemorySpanExporter()
    tracer_provider = TracerProvider(resource=resource)
    tracer_provider.add_span_processor(SimpleSpanProcessor(span_exporter))
    trace.set_tracer_provider(tracer_provider)

    metric_reader = InMemoryMetricReader()
    meter_provider = MeterProvider(
        resource=resource, metric_readers=[metric_reader]
    )
    metrics.set_meter_provider(meter_provider)

    otel_mod._initialized = True
    otel_mod._enabled = True
    otel_mod._tracer = trace.get_tracer("acme2certifier")
    otel_mod._meter = metrics.get_meter("acme2certifier")
    otel_mod._counters = {}
    otel_mod._histograms = {}
    return span_exporter, metric_reader


def test_init_otel_default_disabled() -> None:
    """Missing / empty OpenTelemetry section keeps NoOp."""
    with patch.object(otel_mod, "load_config", return_value=_cfg()):
        assert otel_mod.init_otel(logging.getLogger("test")) is False
    assert otel_mod.is_otel_enabled() is False


def test_init_otel_explicit_false() -> None:
    """opentelemetry_support=False stays NoOp."""
    with patch.object(
        otel_mod, "load_config", return_value=_cfg(opentelemetry_support="False")
    ):
        assert otel_mod.init_otel() is False
    assert otel_mod.is_otel_enabled() is False


def test_span_and_metrics_noop_when_disabled() -> None:
    """Facade helpers do not raise when OTEL is off."""
    with patch.object(otel_mod, "load_config", return_value=_cfg()):
        otel_mod.init_otel()
    with otel_mod.span("acme.test", attributes={"acme.outcome": "ok"}) as active:
        active.set_attribute("x", 1)
        active.set_status("ignored")
    otel_mod.counter_add("acme.test.counter", attributes={"result": "ok"})
    otel_mod.histogram_record("acme.test.duration", 1.5, attributes={"result": "ok"})


def test_init_otel_true_without_sdk_stays_noop(caplog: pytest.LogCaptureFixture) -> None:
    """Enabled in config but missing packages → NoOp + error log."""
    logger = logging.getLogger("otel-missing-sdk")
    with patch.object(
        otel_mod, "load_config", return_value=_cfg(opentelemetry_support="True")
    ):
        with patch.object(
            otel_mod, "_import_otel_sdk", side_effect=ImportError("simulated missing")
        ):
            with caplog.at_level(logging.ERROR):
                assert otel_mod.init_otel(logger) is False
    assert otel_mod.is_otel_enabled() is False
    assert any("packages missing" in r.getMessage() for r in caplog.records)


def test_init_otel_idempotent() -> None:
    """Second init_otel call returns the same enabled flag without re-init."""
    with patch.object(otel_mod, "load_config", return_value=_cfg()) as mock_load:
        assert otel_mod.init_otel() is False
        assert otel_mod.init_otel() is False
        assert mock_load.call_count == 1


def test_otlp_traces_endpoint_helper() -> None:
    """Endpoint helper appends /v1/traces once."""
    assert (
        otel_mod._otlp_traces_endpoint("http://192.168.64.3:4318")
        == "http://192.168.64.3:4318/v1/traces"
    )
    assert (
        otel_mod._otlp_traces_endpoint("http://192.168.64.3:4318/v1/traces")
        == "http://192.168.64.3:4318/v1/traces"
    )


def test_sample_ratio_clamped() -> None:
    """sample_ratio outside [0,1] is clamped."""
    cfg_high = _cfg(sample_ratio="2.5")
    cfg_low = _cfg(sample_ratio="-1")
    assert otel_mod._config_sample_ratio(cfg_high) == 1.0
    assert otel_mod._config_sample_ratio(cfg_low) == 0.0


def test_boot_acme_http_stack_calls_init_otel() -> None:
    """Shared ACME HTTP boot wires init_otel after logger_setup."""
    from acme2certifier.acme_srv.helpers.acme_http_boot import boot_acme_http_stack

    logger = logging.getLogger("test-otel-boot")
    mock_hk = MagicMock()
    mock_cm = MagicMock()
    mock_cm.__enter__.return_value = mock_hk
    mock_cm.__exit__.return_value = False
    with (
        patch("acme2certifier.acme_srv.helper.apply_log_levels"),
        patch("acme2certifier.acme_srv.helper.load_config", return_value={}),
        patch("acme2certifier.acme_srv.helper.config_debug_get", return_value=False),
        patch("acme2certifier.acme_srv.helper.logger_setup", return_value=logger),
        patch(
            "acme2certifier.acme_srv.helper.init_otel", return_value=False
        ) as mock_otel,
        patch("acme2certifier.acme_srv.helper.log_loaded_acme_srv_cfg"),
        patch(
            "acme2certifier.acme_srv.helpers.acme_http_boot.db_handler_mod.log_active_db_handler"
        ),
        patch("acme2certifier.acme_srv.helper.config_check"),
        patch("acme2certifier.acme_srv.helper.server_name_configuration_validate"),
        patch("acme2certifier.acme_srv.helper.tnauthlist_configuration_validate"),
        patch("acme2certifier.acme_srv.helper.challenge_type_configuration_validate"),
        patch("acme2certifier.acme_srv.helper.legacy_acme_get_load", return_value=False),
        patch(
            "acme2certifier.acme_srv.trigger.resolve_trigger_endpoint",
            return_value=False,
        ),
        patch(
            "acme2certifier.acme_srv.housekeeping.resolve_housekeeping_cli_endpoint",
            return_value=False,
        ),
        patch(
            "acme2certifier.acme_srv.housekeeping.Housekeeping", return_value=mock_cm
        ),
    ):
        boot_acme_http_stack()
    mock_otel.assert_called_once_with(logger)


def test_init_otel_unsupported_protocol(caplog: pytest.LogCaptureFixture) -> None:
    """Unsupported protocol stays NoOp."""
    with patch.object(
        otel_mod,
        "load_config",
        return_value=_cfg(opentelemetry_support="True", protocol="grpc"),
    ):
        with caplog.at_level(logging.ERROR):
            assert otel_mod.init_otel() is False
    assert otel_mod.is_otel_enabled() is False
    assert any("unsupported protocol" in r.getMessage() for r in caplog.records)


def test_sdk_span_records_name_and_attributes() -> None:
    """Enabled facade records spans via InMemorySpanExporter."""
    span_exporter, _reader = _enable_inmemory_providers()
    with otel_mod.span(
        "acme.challenge.validate",
        attributes={"acme.challenge_type": "http-01"},
    ) as active:
        active.set_attribute("acme.outcome", "success")
    spans = span_exporter.get_finished_spans()
    assert len(spans) == 1
    assert spans[0].name == "acme.challenge.validate"
    assert spans[0].attributes["acme.challenge_type"] == "http-01"
    assert spans[0].attributes["acme.outcome"] == "success"


def test_sdk_counter_and_histogram_record() -> None:
    """Enabled facade records counter/histogram via InMemoryMetricReader."""
    _exporter, metric_reader = _enable_inmemory_providers()
    otel_mod.counter_add(
        "acme.challenge.validation",
        attributes={"acme.challenge_type": "dns-01", "acme.outcome": "success"},
    )
    otel_mod.histogram_record(
        "acme.issuance.duration",
        0.25,
        attributes={"acme.outcome": "success"},
    )
    data = metric_reader.get_metrics_data()
    assert data is not None
    metric_names = set()
    for rm in data.resource_metrics:
        for sm in rm.scope_metrics:
            for metric in sm.metrics:
                metric_names.add(metric.name)
    assert "acme.challenge.validation" in metric_names
    assert "acme.issuance.duration" in metric_names


def test_init_otel_true_with_sdk_sets_enabled(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """opentelemetry_support=True with SDK present enables facade (no real OTLP)."""
    _require_otel_sdk()
    _reset_otel_api_providers()
    real_import = otel_mod._import_otel_sdk

    def _sdk_with_noop_exporters() -> Any:
        sdk = real_import()
        sdk["OTLPSpanExporter"] = lambda **_kwargs: MagicMock()
        sdk["OTLPMetricExporter"] = lambda **_kwargs: MagicMock()
        return sdk

    logger = logging.getLogger("otel-sdk-init")
    with patch.object(
        otel_mod,
        "load_config",
        return_value=_cfg(
            opentelemetry_support="True",
            endpoint="http://192.168.64.3:4318",
            service_name="acme2certifier-test",
        ),
    ):
        with patch.object(
            otel_mod, "_import_otel_sdk", side_effect=_sdk_with_noop_exporters
        ):
            with caplog.at_level(logging.WARNING):
                assert otel_mod.init_otel(logger) is True
    assert otel_mod.is_otel_enabled() is True
    assert any("experimental" in r.getMessage() for r in caplog.records)

    with otel_mod.span("acme.certificate.enroll") as active:
        active.set_attribute("acme.outcome", "success")
    otel_mod.counter_add("acme.ca_handler.call", attributes={"acme.outcome": "success"})
    otel_mod.histogram_record("acme.issuance.duration", 1.0)
