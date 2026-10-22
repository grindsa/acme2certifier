# -*- coding: utf-8 -*-
"""Optional OpenTelemetry facade for acme2certifier (experimental).

Config-gated via ``[OpenTelemetry] opentelemetry_support`` (default False).
When disabled or when the SDK is missing, all helpers are no-ops so the
core package stays free of an OpenTelemetry dependency.
"""

from __future__ import annotations

import logging
from contextlib import contextmanager
from typing import Any, Dict, Iterator, Optional

from .config import load_config

_SECTION = "OpenTelemetry"
_DEFAULT_ENDPOINT = "http://127.0.0.1:4318"
_DEFAULT_SERVICE_NAME = "acme2certifier"
_DEFAULT_PROTOCOL = "http/protobuf"
_DEFAULT_SAMPLE_RATIO = 1.0

_initialized: bool = False
_enabled: bool = False
_tracer: Any = None
_meter: Any = None
_counters: Dict[str, Any] = {}
_histograms: Dict[str, Any] = {}


class _NoOpSpan:
    """Span stand-in used when OpenTelemetry is off or unavailable."""

    def set_attribute(self, key: str, value: Any) -> None:
        return None

    def set_status(self, status: Any) -> None:
        return None

    def record_exception(self, exception: BaseException) -> None:
        return None

    def end(self) -> None:
        return None

    def __enter__(self) -> "_NoOpSpan":
        return self

    def __exit__(self, *args: Any) -> bool:
        return False


def is_otel_enabled() -> bool:
    """Return True when OpenTelemetry export was successfully initialized."""
    return _enabled


def _config_getboolean(config_dic: Any, key: str, fallback: bool = False) -> bool:
    """Read a boolean from ``[OpenTelemetry]``; missing section → fallback."""
    if _SECTION not in config_dic:
        return fallback
    getboolean = getattr(config_dic, "getboolean", None)
    if callable(getboolean):
        try:
            return bool(getboolean(_SECTION, key, fallback=fallback))
        except (ValueError, TypeError):
            return fallback
    section = config_dic.get(_SECTION) if hasattr(config_dic, "get") else None
    if not isinstance(section, dict):
        return fallback
    raw = section.get(key, fallback)
    if isinstance(raw, bool):
        return raw
    if isinstance(raw, str):
        return raw.strip().lower() in ("1", "true", "yes", "on")
    return fallback


def _config_get(config_dic: Any, key: str, fallback: str) -> str:
    """Read a string from ``[OpenTelemetry]``."""
    if _SECTION not in config_dic:
        return fallback
    try:
        return str(config_dic.get(_SECTION, key, fallback=fallback)).strip() or fallback
    except (TypeError, AttributeError, KeyError):
        return fallback


def _config_sample_ratio(config_dic: Any) -> float:
    """Read sample_ratio; clamp to [0.0, 1.0]."""
    raw = _config_get(config_dic, "sample_ratio", str(_DEFAULT_SAMPLE_RATIO))
    try:
        ratio = float(raw)
    except (TypeError, ValueError):
        return _DEFAULT_SAMPLE_RATIO
    if ratio < 0.0:
        return 0.0
    if ratio > 1.0:
        return 1.0
    return ratio


def _otlp_traces_endpoint(base: str) -> str:
    """Ensure OTLP HTTP traces path is present on the endpoint URL."""
    base = base.rstrip("/")
    if base.endswith("/v1/traces"):
        return base
    return f"{base}/v1/traces"


def _reset_otel_state() -> None:
    """Clear module state (for tests)."""
    global _initialized, _enabled, _tracer, _meter, _counters, _histograms
    _initialized = False
    _enabled = False
    _tracer = None
    _meter = None
    _counters = {}
    _histograms = {}


def _import_otel_sdk() -> Any:
    """Import OpenTelemetry SDK modules (lazy; raises ImportError if missing)."""
    from opentelemetry import metrics, trace
    from opentelemetry.exporter.otlp.proto.http.metric_exporter import (
        OTLPMetricExporter,
    )
    from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
    from opentelemetry.sdk.metrics import MeterProvider
    from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor
    from opentelemetry.sdk.trace.sampling import ALWAYS_ON, ParentBasedTraceIdRatio

    return {
        "metrics": metrics,
        "trace": trace,
        "OTLPMetricExporter": OTLPMetricExporter,
        "OTLPSpanExporter": OTLPSpanExporter,
        "MeterProvider": MeterProvider,
        "PeriodicExportingMetricReader": PeriodicExportingMetricReader,
        "Resource": Resource,
        "TracerProvider": TracerProvider,
        "BatchSpanProcessor": BatchSpanProcessor,
        "ALWAYS_ON": ALWAYS_ON,
        "ParentBasedTraceIdRatio": ParentBasedTraceIdRatio,
    }


def init_otel(logger: Optional[logging.Logger] = None) -> bool:
    """Initialize OpenTelemetry from config. Safe to call more than once.

    Returns True when export is active. Never raises for missing packages
    or config errors — falls back to NoOp and logs.
    """
    global _initialized, _enabled, _tracer, _meter

    log = logger or logging.getLogger("acme2certifier")
    if _initialized:
        return _enabled

    _initialized = True
    config_dic = load_config(log)
    if not _config_getboolean(config_dic, "opentelemetry_support", fallback=False):
        log.debug("OpenTelemetry: opentelemetry_support is False; NoOp facade")
        return False

    endpoint = _config_get(config_dic, "endpoint", _DEFAULT_ENDPOINT)
    protocol = _config_get(config_dic, "protocol", _DEFAULT_PROTOCOL).lower()
    service_name = _config_get(config_dic, "service_name", _DEFAULT_SERVICE_NAME)
    sample_ratio = _config_sample_ratio(config_dic)

    if protocol not in ("http/protobuf", "http", "http/json"):
        log.error(
            "OpenTelemetry: unsupported protocol %r (v1 supports http/protobuf); NoOp",
            protocol,
        )
        return False

    try:
        sdk = _import_otel_sdk()
    except ImportError as err:
        log.error(
            "OpenTelemetry: enabled but packages missing (%s). "
            "Install acme2certifier[otel] or disable opentelemetry_support. NoOp.",
            err,
        )
        return False

    try:
        resource = sdk["Resource"].create({"service.name": service_name})
        sampler = (
            sdk["ALWAYS_ON"]
            if sample_ratio >= 1.0
            else sdk["ParentBasedTraceIdRatio"](sample_ratio)
        )
        tracer_provider = sdk["TracerProvider"](resource=resource, sampler=sampler)
        traces_endpoint = _otlp_traces_endpoint(endpoint)
        tracer_provider.add_span_processor(
            sdk["BatchSpanProcessor"](
                sdk["OTLPSpanExporter"](endpoint=traces_endpoint)
            )
        )
        sdk["trace"].set_tracer_provider(tracer_provider)
        _tracer = sdk["trace"].get_tracer("acme2certifier")

        # Metrics: OTLP HTTP metrics path is /v1/metrics on the same host base.
        metrics_base = endpoint.rstrip("/")
        if metrics_base.endswith("/v1/traces"):
            metrics_base = metrics_base[: -len("/v1/traces")]
        metrics_endpoint = f"{metrics_base.rstrip('/')}/v1/metrics"
        metric_reader = sdk["PeriodicExportingMetricReader"](
            sdk["OTLPMetricExporter"](endpoint=metrics_endpoint)
        )
        meter_provider = sdk["MeterProvider"](
            resource=resource, metric_readers=[metric_reader]
        )
        sdk["metrics"].set_meter_provider(meter_provider)
        _meter = sdk["metrics"].get_meter("acme2certifier")
    except Exception as err:  # noqa: BLE001 — never break ACME boot
        log.error("OpenTelemetry: initialization failed (%s); NoOp", err)
        _tracer = None
        _meter = None
        return False

    _enabled = True
    log.warning(
        "OpenTelemetry support is experimental "
        "(endpoint=%s, service_name=%s, sample_ratio=%s)",
        endpoint,
        service_name,
        sample_ratio,
    )
    return True


@contextmanager
def span(
    name: str, attributes: Optional[Dict[str, Any]] = None
) -> Iterator[Any]:
    """Start a span when OTEL is active; otherwise yield a NoOp span."""
    if not _enabled or _tracer is None:
        yield _NoOpSpan()
        return

    with _tracer.start_as_current_span(name) as active:
        if attributes:
            for key, value in attributes.items():
                if value is not None:
                    active.set_attribute(key, value)
        yield active


def _counter(name: str) -> Any:
    """Return (and cache) a counter instrument, or None when NoOp."""
    if not _enabled or _meter is None:
        return None
    if name not in _counters:
        _counters[name] = _meter.create_counter(name)
    return _counters[name]


def _histogram(name: str) -> Any:
    """Return (and cache) a histogram instrument, or None when NoOp."""
    if not _enabled or _meter is None:
        return None
    if name not in _histograms:
        _histograms[name] = _meter.create_histogram(name)
    return _histograms[name]


def counter_add(
    name: str,
    amount: int = 1,
    attributes: Optional[Dict[str, Any]] = None,
) -> None:
    """Increment a counter when OTEL is active; otherwise no-op."""
    instrument = _counter(name)
    if instrument is None:
        return
    instrument.add(amount, attributes=attributes or {})


def histogram_record(
    name: str,
    value: float,
    attributes: Optional[Dict[str, Any]] = None,
) -> None:
    """Record a histogram value when OTEL is active; otherwise no-op."""
    instrument = _histogram(name)
    if instrument is None:
        return
    instrument.record(value, attributes=attributes or {})
