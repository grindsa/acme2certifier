# -*- coding: utf-8 -*-
"""Optional OpenTelemetry facade for acme2certifier (experimental).

Config-gated via ``[OpenTelemetry] opentelemetry_support`` (default False).
When disabled or when the SDK is missing, all helpers are no-ops so the
core package stays free of an OpenTelemetry dependency.
"""

from __future__ import annotations

import base64
import json
import logging
import threading
from contextlib import contextmanager
from typing import Any, Dict, Iterator, Optional, Union

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
# In-process SpanContext store for enrollment-session chaining.
# Not shared across workers/processes.
_span_contexts: Dict[str, Any] = {}

# Tip for GETs without a JWS nonce (directory, newNonce, renewalInfo, ``/``).
SESSION_TIP_KEY = "acme:session_tip"

# After a successful enroll, the next ``/`` or ``directory`` starts a new
# enrollment-session root instead of continuing the previous tip.
_session_boundary_pending: bool = False

# Per-thread active ``acme.http.request`` span context (tip/nonce parent).
_tls = threading.local()


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
    global _span_contexts, _session_boundary_pending
    _initialized = False
    _enabled = False
    _tracer = None
    _meter = None
    _counters = {}
    _histograms = {}
    _span_contexts = {}
    _session_boundary_pending = False
    _tls.request_span_ctx = None


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
    name: str,
    attributes: Optional[Dict[str, Any]] = None,
    kind: Any = None,
) -> Iterator[Any]:
    """Start a span when OTEL is active; otherwise yield a NoOp span."""
    if not _enabled or _tracer is None:
        yield _NoOpSpan()
        return

    start_kwargs: Dict[str, Any] = {}
    if kind is not None:
        start_kwargs["kind"] = kind
    with _tracer.start_as_current_span(name, **start_kwargs) as active:
        if attributes:
            for key, value in attributes.items():
                if value is not None:
                    active.set_attribute(key, value)
        yield active


@contextmanager
def http_request_span(
    method: str, path: str, attributes: Optional[Dict[str, Any]] = None
) -> Iterator[Any]:
    """SERVER span for one ACME HTTP request so nested spans share a trace."""
    attrs: Dict[str, Any] = {
        "http.method": method or "",
        "http.route": path or "",
    }
    if attributes:
        attrs.update(attributes)
    kind = None
    if _enabled:
        try:
            from opentelemetry.trace import SpanKind

            kind = SpanKind.SERVER
        except ImportError:
            kind = None
    with span("acme.http.request", attributes=attrs, kind=kind) as active:
        prev = getattr(_tls, "request_span_ctx", None)
        try:
            if _enabled and not isinstance(active, _NoOpSpan):
                try:
                    span_ctx = active.get_span_context()
                except Exception:  # noqa: BLE001
                    span_ctx = None
                _tls.request_span_ctx = (
                    span_ctx if span_ctx is not None and span_ctx.is_valid else None
                )
            else:
                _tls.request_span_ctx = None
            yield active
        finally:
            _tls.request_span_ctx = prev


def context_capture() -> Any:
    """Capture the current OTEL context for cross-thread nesting (or None)."""
    if not _enabled:
        return None
    try:
        from opentelemetry import context as otel_context
    except ImportError:
        return None
    return otel_context.get_current()


@contextmanager
def context_attach(ctx: Any) -> Iterator[None]:
    """Attach a captured context in this thread; no-op when ctx is None."""
    if ctx is None or not _enabled:
        yield
        return
    try:
        from opentelemetry import context as otel_context
    except ImportError:
        yield
        return
    token = otel_context.attach(ctx)
    try:
        yield
    finally:
        otel_context.detach(token)


def _store_span_context(key: str, span_ctx: Any) -> None:
    """Persist a valid span context under ``key``."""
    if not key or span_ctx is None or not getattr(span_ctx, "is_valid", False):
        return
    _span_contexts[key] = span_ctx


def remember_span_context(key: str) -> None:
    """Store the current span context under ``key`` for a later request."""
    if not _enabled or not key:
        return
    try:
        from opentelemetry import trace
    except ImportError:
        return
    current = trace.get_current_span()
    if current is None:
        return
    _store_span_context(key, current.get_span_context())


def remember_request_span_context(key: str) -> None:
    """Store the active ``acme.http.request`` span under ``key``.

    Prefers the request-root span so the next hop continues from
    ``acme.http.request`` (not a nested span). Falls back to the current span.
    """
    if not _enabled or not key:
        return
    request_ctx = getattr(_tls, "request_span_ctx", None)
    if request_ctx is not None and getattr(request_ctx, "is_valid", False):
        _store_span_context(key, request_ctx)
        return
    remember_span_context(key)


@contextmanager
def continue_span_context(key: str) -> Iterator[None]:
    """Attach a remembered span context as the parent for nested spans.

    ``nonce:…`` keys are consumed after continue (single-use, bounds memory).
    The session tip key is kept. No-op when OTEL is off or ``key`` is unknown.
    """
    if not _enabled or not key:
        yield
        return
    stored = _span_contexts.get(key)
    if stored is None:
        yield
        return
    try:
        from opentelemetry import context as otel_context
        from opentelemetry import trace
        from opentelemetry.trace import NonRecordingSpan, SpanContext
    except ImportError:
        yield
        return
    token = None
    try:
        remote = SpanContext(
            trace_id=stored.trace_id,
            span_id=stored.span_id,
            is_remote=True,
            trace_flags=stored.trace_flags,
            trace_state=getattr(stored, "trace_state", None),
        )
        ctx = trace.set_span_in_context(NonRecordingSpan(remote))
        token = otel_context.attach(ctx)
    except Exception:  # noqa: BLE001 — never break ACME paths
        yield
        return
    try:
        yield
    finally:
        if token is not None:
            otel_context.detach(token)
        if key.startswith("nonce:"):
            _span_contexts.pop(key, None)


def _path_leaf(path: str) -> str:
    """Return the last path segment (lowercased), or ``/`` for empty."""
    if path is None:
        return ""
    normalized = path.lower().rstrip("/") or "/"
    if normalized == "/":
        return "/"
    return normalized.rsplit("/", 1)[-1]


def is_session_entry_path(path: str) -> bool:
    """``/`` or ``directory`` — may open a new root after enroll completes."""
    return _path_leaf(path) in ("/", "directory")


def is_session_tip_path(path: str) -> bool:
    """Paths that update the session tip after the request."""
    if path is None:
        return False
    normalized = path.lower().rstrip("/") or "/"
    if normalized == "/":
        return True
    if "/renewal-info" in normalized or "/renewalinfo" in normalized:
        return True
    return _path_leaf(path) in ("directory", "newnonce")


def mark_enrollment_session_complete() -> None:
    """Arm a session boundary so the next ``/`` or ``directory`` starts fresh."""
    global _session_boundary_pending
    if _enabled:
        _session_boundary_pending = True


def remember_session_tip() -> None:
    """Point the session tip at the active ``acme.http.request`` span."""
    remember_request_span_context(SESSION_TIP_KEY)


def has_remembered_span_context(key: str) -> bool:
    """Return True when ``key`` is present in the in-process span-context store."""
    return bool(_enabled and key and key in _span_contexts)


def nonce_trace_key_from_jws_body(body: Union[bytes, str, None]) -> str:
    """Extract ``nonce:<value>`` from a JWS body for session-trace continuation."""
    if not body:
        return ""
    try:
        text = body.decode("utf-8") if isinstance(body, bytes) else str(body)
        outer = json.loads(text)
        protected_b64 = outer.get("protected")
        if not isinstance(protected_b64, str) or not protected_b64:
            return ""
        pad = "=" * (-len(protected_b64) % 4)
        protected = json.loads(
            base64.urlsafe_b64decode(protected_b64 + pad).decode("utf-8")
        )
        nonce = protected.get("nonce")
        if isinstance(nonce, str) and nonce:
            return f"nonce:{nonce}"
    except Exception:  # noqa: BLE001 — tracing must never break ACME
        return ""
    return ""


def _is_challenge_resource_path(path: str) -> bool:
    """True for ACME challenge resource URLs (``/chall/…``)."""
    if not path:
        return False
    normalized = path.lower()
    return "/chall/" in normalized or normalized.rstrip("/").endswith("/chall")


def setup_trace_key_for_request(
    path: str, body: Union[bytes, str, None] = None
) -> str:
    """Return continue key for the enrollment-session trace.

    Prefer a *remembered* Replay-Nonce. Otherwise continue the session tip for
    ``/`` / directory / newNonce / ARI / challenge. After a successful enroll,
    the next ``/`` or ``directory`` returns no key so a new session root starts
    (without splitting ``/`` → ``directory`` within one session).
    """
    if not _enabled:
        return ""
    if is_session_entry_path(path) and _session_boundary_pending:
        return ""
    nonce_key = nonce_trace_key_from_jws_body(body)
    if nonce_key and has_remembered_span_context(nonce_key):
        return nonce_key
    if has_remembered_span_context(SESSION_TIP_KEY) and (
        is_session_tip_path(path)
        or _is_challenge_resource_path(path)
        or bool(nonce_key)
    ):
        return SESSION_TIP_KEY
    return ""


@contextmanager
def acme_traced_request(
    method: str,
    path: str,
    body: Union[bytes, str, None] = None,
) -> Iterator[Any]:
    """Continue the enrollment-session trace and open ``acme.http.request``.

    Shared by Django middleware and classic WSGI. Yields the request span.
    Advances the session tip for tip-paths and successful joins. Consumes a
    post-enroll session boundary on the next ``/`` or ``directory``.
    """
    global _session_boundary_pending
    consume_boundary = bool(
        is_session_entry_path(path) and _session_boundary_pending
    )
    setup_key = setup_trace_key_for_request(path, body)
    joined = has_remembered_span_context(setup_key)
    with continue_span_context(setup_key):
        with http_request_span(method, path) as active:
            try:
                yield active
            finally:
                if joined or is_session_tip_path(path):
                    remember_session_tip()
                if consume_boundary:
                    _session_boundary_pending = False


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
