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
import time
from collections import OrderedDict
from contextlib import contextmanager
from typing import Any, Callable, Dict, FrozenSet, Iterator, Optional, Tuple, Union

from .config import load_config

_SECTION = "OpenTelemetry"
_DEFAULT_ENDPOINT = "http://127.0.0.1:4318"
_DEFAULT_SERVICE_NAME = "acme2certifier"
_DEFAULT_PROTOCOL = "http/protobuf"
_DEFAULT_SAMPLE_RATIO = 1.0
# Bound in-process span-context memory (nonce keys + tips).
_DEFAULT_SPAN_CTX_MAX = 1024
_DEFAULT_SPAN_CTX_TTL_SEC = 86400  # match default Nonce.validity
# Cap JWS body parse for tip/nonce chaining (ACME protected headers are small).
_JWS_TRACE_BODY_MAX_BYTES = 65536

_initialized: bool = False
_enabled: bool = False
_tracer: Any = None
_meter: Any = None
_counters: Dict[str, Any] = {}
_histograms: Dict[str, Any] = {}
# In-process SpanContext store for enrollment-session chaining.
# Not shared across workers/processes. Values: (span_ctx, monotonic_ts).
_span_contexts: "OrderedDict[str, Tuple[Any, float]]" = OrderedDict()
_span_contexts_lock = threading.Lock()
_span_ctx_max: int = _DEFAULT_SPAN_CTX_MAX
_span_ctx_ttl_sec: float = float(_DEFAULT_SPAN_CTX_TTL_SEC)

# Tip for GETs without a JWS nonce (directory, newNonce, renewalInfo, ``/``).
# One global tip per worker — concurrent anonymous GETs can interleave.
SESSION_TIP_KEY = "acme:session_tip"
# After the account ``kid`` is known, tip continues under this prefix so two
# enrolled clients on one worker do not share one tip.
ACCOUNT_TIP_PREFIX = "acme:session_tip:acct:"

# After a successful enroll, the next ``/`` or ``directory`` starts a new
# enrollment-session root instead of continuing the previous tip.
# Process-global: one flag for all clients on this worker (see docs).
_session_boundary_pending: bool = False
_session_boundary_lock = threading.Lock()

# Per-thread active ``acme.http.request`` span context (tip/nonce parent).
_tls = threading.local()

# Default: mutating DBstore APIs only (lookups/nonce/jwk are too chatty).
# Overridable via ``[OpenTelemetry] db_span_methods`` (JSON list; ``[]`` = off).
_DEFAULT_DB_SPAN_METHODS: FrozenSet[str] = frozenset(
    {
        "account_add",
        "account_update",
        "account_delete",
        "authorization_add",
        "authorization_update",
        "cahandler_add",
        "certificate_add",
        "certificate_delete",
        "certificate_replaced_update",
        "challenge_add",
        "challenge_update",
        "cliaccount_add",
        "cliaccount_delete",
        "hkparameter_add",
        "order_add",
        "order_update",
        "order_update_if_status",
    }
)
_db_span_methods: FrozenSet[str] = _DEFAULT_DB_SPAN_METHODS

# Placeholder IDs when no active span (keep log_format ``%(otelTraceID)s`` safe).
_TRACE_ID_ZERO = "0" * 32
_SPAN_ID_ZERO = "0" * 16


class _NoOpSpan:
    """Span stand-in used when OpenTelemetry is off or unavailable."""

    def set_attribute(self, key: str, value: Any) -> None:
        return None

    def set_attributes(self, attributes: Dict[str, Any]) -> None:
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


def _config_db_span_methods(
    config_dic: Any, logger: logging.Logger
) -> FrozenSet[str]:
    """Parse ``db_span_methods`` JSON list; missing/invalid → default allowlist."""
    if _SECTION not in config_dic:
        return _DEFAULT_DB_SPAN_METHODS
    try:
        has_option = config_dic.has_option(_SECTION, "db_span_methods")
    except (AttributeError, TypeError):
        section = config_dic.get(_SECTION) if hasattr(config_dic, "get") else None
        has_option = isinstance(section, dict) and "db_span_methods" in section
    if not has_option:
        return _DEFAULT_DB_SPAN_METHODS
    raw = _config_get(config_dic, "db_span_methods", "")
    if not raw.strip():
        return frozenset()
    try:
        loaded = json.loads(raw)
    except (TypeError, ValueError) as err:
        logger.warning(
            "OpenTelemetry: invalid db_span_methods %r (%s); using default",
            raw,
            err,
        )
        return _DEFAULT_DB_SPAN_METHODS
    if not isinstance(loaded, list):
        logger.warning(
            "OpenTelemetry: db_span_methods must be a JSON list; using default"
        )
        return _DEFAULT_DB_SPAN_METHODS
    methods = {str(item).strip() for item in loaded if str(item).strip()}
    return frozenset(methods)


def reset_otel_state() -> None:
    """Clear module state between tests (and for test fixtures)."""
    global _initialized, _enabled, _tracer, _meter, _counters, _histograms
    global _span_contexts, _session_boundary_pending
    global _span_ctx_max, _span_ctx_ttl_sec, _db_span_methods
    _initialized = False
    _enabled = False
    _tracer = None
    _meter = None
    _counters = {}
    _histograms = {}
    with _span_contexts_lock:
        _span_contexts = OrderedDict()
    _span_ctx_max = _DEFAULT_SPAN_CTX_MAX
    _span_ctx_ttl_sec = float(_DEFAULT_SPAN_CTX_TTL_SEC)
    _db_span_methods = _DEFAULT_DB_SPAN_METHODS
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
    global _initialized, _enabled, _tracer, _meter, _db_span_methods

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
    # Default off: Jaeger all-in-one often has no /v1/metrics (404 spam).
    metrics_export = _config_getboolean(
        config_dic, "metrics_export", fallback=False
    )
    _db_span_methods = _config_db_span_methods(config_dic, log)

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
        span_exporter = _ResilientExporter(
            sdk["OTLPSpanExporter"](endpoint=traces_endpoint),
            log,
            kind="spans",
        )
        tracer_provider.add_span_processor(
            sdk["BatchSpanProcessor"](span_exporter)
        )
        sdk["trace"].set_tracer_provider(tracer_provider)
        _tracer = sdk["trace"].get_tracer("acme2certifier")

        if metrics_export:
            metrics_base = endpoint.rstrip("/")
            if metrics_base.endswith("/v1/traces"):
                metrics_base = metrics_base[: -len("/v1/traces")]
            metrics_endpoint = f"{metrics_base.rstrip('/')}/v1/metrics"
            metric_exporter = _ResilientExporter(
                sdk["OTLPMetricExporter"](endpoint=metrics_endpoint),
                log,
                kind="metrics",
            )
            metric_reader = sdk["PeriodicExportingMetricReader"](metric_exporter)
            meter_provider = sdk["MeterProvider"](
                resource=resource, metric_readers=[metric_reader]
            )
            sdk["metrics"].set_meter_provider(meter_provider)
            _meter = sdk["metrics"].get_meter("acme2certifier")
        else:
            _meter = None
            log.debug(
                "OpenTelemetry: metrics_export is False; traces only (no /v1/metrics)"
            )
    except Exception as err:  # noqa: BLE001 — never break ACME boot
        log.error("OpenTelemetry: initialization failed (%s); NoOp", err)
        _tracer = None
        _meter = None
        return False

    _enabled = True
    install_log_correlation(log)
    log.warning(
        "OpenTelemetry support is experimental "
        "(endpoint=%s, service_name=%s, sample_ratio=%s, metrics_export=%s)",
        endpoint,
        service_name,
        sample_ratio,
        metrics_export,
    )
    return True


def get_trace_context_ids() -> Tuple[str, str]:
    """Return ``(trace_id_hex, span_id_hex)`` for the current span, or zeros."""
    if not _enabled:
        return _TRACE_ID_ZERO, _SPAN_ID_ZERO
    try:
        from opentelemetry import trace
    except ImportError:
        return _TRACE_ID_ZERO, _SPAN_ID_ZERO
    try:
        span_ctx = trace.get_current_span().get_span_context()
    except Exception:  # noqa: BLE001
        return _TRACE_ID_ZERO, _SPAN_ID_ZERO
    if span_ctx is None or not span_ctx.is_valid:
        return _TRACE_ID_ZERO, _SPAN_ID_ZERO
    return format(span_ctx.trace_id, "032x"), format(span_ctx.span_id, "016x")


class TraceContextFilter(logging.Filter):
    """Inject ``otelTraceID`` / ``otelSpanID`` into LogRecords for log↔trace."""

    def filter(self, record: logging.LogRecord) -> bool:
        if not hasattr(record, "otelTraceID") or not hasattr(record, "otelSpanID"):
            trace_id, span_id = get_trace_context_ids()
            record.otelTraceID = trace_id  # type: ignore[attr-defined]
            record.otelSpanID = span_id  # type: ignore[attr-defined]
        return True


def _handler_has_trace_filter(handler: logging.Handler) -> bool:
    return any(isinstance(f, TraceContextFilter) for f in handler.filters)


def install_log_correlation(
    logger: Optional[logging.Logger] = None,
) -> None:
    """Attach :class:`TraceContextFilter` to ACME/root loggers **and handlers**.

    Handler filters are required: child loggers (e.g. OTEL exporters) propagate
    to root handlers without running root logger filters, which otherwise
    breaks ``log_format`` containing ``%(otelTraceID)s``.
    """
    targets = [logger or logging.getLogger("acme2certifier"), logging.getLogger()]
    seen_loggers: set[int] = set()
    for target in targets:
        if id(target) in seen_loggers:
            continue
        seen_loggers.add(id(target))
        if not any(isinstance(f, TraceContextFilter) for f in target.filters):
            target.addFilter(TraceContextFilter())
        for handler in target.handlers:
            if not _handler_has_trace_filter(handler):
                handler.addFilter(TraceContextFilter())


class _ResilientExporter:
    """Wrap OTLP exporters: never raise into ACME; CRITICAL once on failure."""

    def __init__(
        self,
        inner: Any,
        logger: logging.Logger,
        *,
        kind: str,
    ) -> None:
        self._inner = inner
        self._logger = logger
        self._kind = kind
        self._lock = threading.Lock()
        self._reported = False

    def __getattr__(self, item: str) -> Any:
        # Metric exporters expose attrs such as ``_preferred_temporality``.
        return getattr(self._inner, item)

    def export(self, *args: Any, **kwargs: Any) -> Any:
        try:
            result = self._inner.export(*args, **kwargs)
        except Exception as err:  # noqa: BLE001 — never break the export worker
            self._report_failure(err)
            return self._failure_result()
        if self._is_failure(result):
            self._report_failure(result)
        return result

    def shutdown(self, *args: Any, **kwargs: Any) -> Any:
        try:
            return self._inner.shutdown(*args, **kwargs)
        except Exception as err:  # noqa: BLE001
            self._logger.critical(
                "OpenTelemetry: %s exporter shutdown failed: %s", self._kind, err
            )
            return None

    def force_flush(self, *args: Any, **kwargs: Any) -> bool:
        flush = getattr(self._inner, "force_flush", None)
        if not callable(flush):
            return True
        try:
            return bool(flush(*args, **kwargs))
        except Exception as err:  # noqa: BLE001
            self._report_failure(err)
            return False

    def _failure_result(self) -> Any:
        try:
            if self._kind == "metrics":
                from opentelemetry.sdk.metrics.export import MetricExportResult

                return MetricExportResult.FAILURE
            from opentelemetry.sdk.trace.export import SpanExportResult

            return SpanExportResult.FAILURE
        except ImportError:
            return 1

    @staticmethod
    def _is_failure(result: Any) -> bool:
        name = getattr(result, "name", None)
        if name == "FAILURE":
            return True
        try:
            return int(result) == 1 and type(result).__name__.endswith("ExportResult")
        except (TypeError, ValueError):
            return False

    def _report_failure(self, detail: Any) -> None:
        with self._lock:
            first = not self._reported
            self._reported = True
        if first:
            self._logger.critical(
                "OpenTelemetry: %s export failed (collector unreachable or "
                "misconfigured); ACME requests continue. Detail: %s",
                self._kind,
                detail,
            )
        else:
            self._logger.debug(
                "OpenTelemetry: %s export still failing: %s", self._kind, detail
            )

def set_span_outcome(
    active: Any,
    outcome: str,
    exception: Optional[BaseException] = None,
) -> None:
    """Set ``acme.outcome``; Jaeger ERROR status only for server-side failures.

    Protocol/client rejects use ``failure`` / ``skipped`` (attributes only).
    Unexpected failures use ``error`` and optionally ``record_exception``.
    """
    if active is None:
        return
    try:
        active.set_attribute("acme.outcome", outcome)
    except Exception:  # noqa: BLE001
        return
    if outcome != "error" and exception is None:
        return
    if not _enabled or isinstance(active, _NoOpSpan):
        return
    try:
        from opentelemetry.trace import Status, StatusCode

        description = str(exception) if exception is not None else str(outcome)
        active.set_status(Status(StatusCode.ERROR, description))
        if exception is not None:
            active.record_exception(exception)
    except Exception:  # noqa: BLE001 — never break ACME paths
        return


def mark_http_status(active: Any, status_code: int) -> None:
    """Set ``http.status_code``; ERROR status for HTTP 5xx only."""
    if active is None:
        return
    try:
        code = int(status_code)
    except (TypeError, ValueError):
        return
    try:
        active.set_attribute("http.status_code", code)
    except Exception:  # noqa: BLE001
        return
    if code < 500:
        return
    if not _enabled or isinstance(active, _NoOpSpan):
        return
    try:
        from opentelemetry.trace import Status, StatusCode

        active.set_status(Status(StatusCode.ERROR, f"HTTP {code}"))
    except Exception:  # noqa: BLE001
        return


def _apply_span_attributes(active: Any, attributes: Optional[Dict[str, Any]]) -> None:
    """Set span attributes, preferring ``set_attributes`` when available."""
    if not attributes:
        return
    filtered = {k: v for k, v in attributes.items() if v is not None}
    if not filtered:
        return
    set_attrs = getattr(active, "set_attributes", None)
    if callable(set_attrs):
        try:
            set_attrs(filtered)
            return
        except Exception:  # noqa: BLE001
            pass
    for key, value in filtered.items():
        active.set_attribute(key, value)


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
        _apply_span_attributes(active, attributes)
        yield active


def _db_method_should_span(name: str) -> bool:
    """Return True when *name* is in the active ``db_span_methods`` allowlist."""
    return name in _db_span_methods


def _wrap_db_method(method: Callable[..., Any], name: str) -> Callable[..., Any]:
    """Wrap a DBstore method with ``acme.db.<name>`` (NoOp when OTEL off)."""

    def wrapped(self: Any, *args: Any, **kwargs: Any) -> Any:
        # Call-time allowlist (``db_span_methods`` may change at init_otel).
        if not _db_method_should_span(name):
            return method(self, *args, **kwargs)
        attrs: Dict[str, Any] = {"db.operation": name}
        handler_label = getattr(self, "type", None)
        if isinstance(handler_label, str) and handler_label:
            attrs["db.system"] = handler_label
        with span(f"acme.db.{name}", attributes=attrs) as active:
            try:
                result = method(self, *args, **kwargs)
            except Exception as err:
                set_span_outcome(active, "error", exception=err)
                raise
            set_span_outcome(active, "success")
            return result

    wrapped.__name__ = getattr(method, "__name__", name)
    wrapped.__doc__ = getattr(method, "__doc__", None)
    wrapped._otel_db_wrapped = True  # type: ignore[attr-defined]
    return wrapped


def instrument_dbstore_class(cls: type) -> type:
    """Wrap public DBstore methods; spans gated by ``db_span_methods``.

    All non-private callables are wrapped so config can enable lookups later
    without re-import. Actual span emission uses the allowlist (default:
    writes only). Safe to call more than once. When OTEL is disabled, wrappers
    are NoOps. Does not change return values or exception behavior.
    """
    if getattr(cls, "_otel_db_instrumented", False):
        return cls
    for name, attr in list(vars(cls).items()):
        if name.startswith("_") or not callable(attr):
            continue
        if getattr(attr, "_otel_db_wrapped", False):
            continue
        setattr(cls, name, _wrap_db_method(attr, name))
    cls._otel_db_instrumented = True  # type: ignore[attr-defined]
    return cls


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


def _prune_expired_locked(now: Optional[float] = None) -> None:
    """Drop TTL-expired entries (caller holds ``_span_contexts_lock``)."""
    if _span_ctx_ttl_sec <= 0:
        return
    deadline = (now if now is not None else time.monotonic()) - _span_ctx_ttl_sec
    expired = [key for key, (_ctx, ts) in _span_contexts.items() if ts < deadline]
    for key in expired:
        _span_contexts.pop(key, None)


def _first_key_matching(predicate: Callable[[str], bool]) -> Optional[str]:
    """Return the first store key for which ``predicate(key)`` is true."""
    for key in _span_contexts:
        if predicate(key):
            return key
    return None


def _next_eviction_victim() -> Optional[str]:
    """Pick the next overflow victim (prefer ``nonce:``, keep global tip last)."""
    victim = _first_key_matching(lambda key: key.startswith("nonce:"))
    if victim is not None:
        return victim
    victim = _first_key_matching(
        lambda key: key != SESSION_TIP_KEY and not key.startswith(ACCOUNT_TIP_PREFIX)
    )
    if victim is not None:
        return victim
    return _first_key_matching(lambda key: key != SESSION_TIP_KEY)


def _evict_overflow_locked() -> None:
    """Evict oldest entries until under max (prefer ``nonce:`` keys)."""
    while len(_span_contexts) > _span_ctx_max:
        victim = _next_eviction_victim()
        if victim is None:
            break
        _span_contexts.pop(victim, None)


def _store_span_context(key: str, span_ctx: Any) -> None:
    """Persist a valid span context under ``key`` (TTL + size capped)."""
    if not key or span_ctx is None or not getattr(span_ctx, "is_valid", False):
        return
    now = time.monotonic()
    with _span_contexts_lock:
        _prune_expired_locked(now)
        _span_contexts.pop(key, None)
        _span_contexts[key] = (span_ctx, now)
        _evict_overflow_locked()


def _lookup_span_context(key: str) -> Any:
    """Return a live span context for ``key``, or None if missing/expired."""
    if not key:
        return None
    now = time.monotonic()
    with _span_contexts_lock:
        _prune_expired_locked(now)
        entry = _span_contexts.get(key)
        if entry is None:
            return None
        span_ctx, _ts = entry
        _span_contexts.move_to_end(key)
        return span_ctx


def _pop_span_context(key: str) -> None:
    """Remove ``key`` from the store."""
    if not key:
        return
    with _span_contexts_lock:
        _span_contexts.pop(key, None)


def _drop_nonce_span_contexts_locked() -> None:
    """Remove all ``nonce:`` entries (caller holds the lock)."""
    for key in [k for k in _span_contexts if k.startswith("nonce:")]:
        _span_contexts.pop(key, None)


def forget_nonce_span_contexts(nonce_values: Any) -> None:
    """Drop remembered contexts for expired/deleted ACME nonces."""
    if not _enabled or not nonce_values:
        return
    keys = []
    for value in nonce_values:
        if isinstance(value, str) and value:
            keys.append(value if value.startswith("nonce:") else f"nonce:{value}")
    if not keys:
        return
    with _span_contexts_lock:
        for key in keys:
            _span_contexts.pop(key, None)


def account_tip_key(account_name: str) -> str:
    """Return the per-account session-tip store key."""
    if not account_name:
        return ""
    return f"{ACCOUNT_TIP_PREFIX}{account_name}"


def _account_name_from_kid(kid: Any) -> str:
    """Extract account name from an ACME account ``kid`` URL."""
    if not isinstance(kid, str) or not kid:
        return ""
    leaf = kid.rstrip("/").rsplit("/", 1)[-1]
    if not leaf or leaf.lower() in ("acct", "acme", "account"):
        return ""
    return leaf


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

    ``nonce:…`` keys are consumed after continue (single-use). Tip keys are
    kept. No-op when OTEL is off or ``key`` is unknown/expired.
    """
    if not _enabled or not key:
        yield
        return
    stored = _lookup_span_context(key)
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
            _pop_span_context(key)


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
    """Arm a session boundary so the next ``/`` or ``directory`` starts fresh.

    The flag is process-global on this worker: any client's next entry path may
    consume it (usually harmless; see docs/opentelemetry.md).
    """
    global _session_boundary_pending
    if not _enabled:
        return
    with _session_boundary_lock:
        _session_boundary_pending = True


def jws_trace_body_max_bytes() -> int:
    """Max POST body size parsed for nonce/kid tip chaining."""
    return _JWS_TRACE_BODY_MAX_BYTES


def remember_session_tip(account_name: str = "") -> None:
    """Point the session tip at the active ``acme.http.request`` span.

    Always updates the global tip (anonymous GETs). When ``account_name`` is
    known (from JWS ``kid``), also updates that account's tip so concurrent
    clients on one worker stay on separate trees after authentication.
    """
    remember_request_span_context(SESSION_TIP_KEY)
    acct_key = account_tip_key(account_name)
    if acct_key:
        remember_request_span_context(acct_key)


def has_remembered_span_context(key: str) -> bool:
    """Return True when ``key`` is present and not TTL-expired."""
    return bool(_enabled and key and _lookup_span_context(key) is not None)


def jws_trace_hints_from_body(
    body: Union[bytes, str, None],
) -> Tuple[str, str]:
    """Return ``(nonce_key, account_name)`` from a JWS body for tip chaining.

    Skips parse when the body exceeds ``jws_trace_body_max_bytes()`` so large
    POSTs do not pay JSON decode cost for tracing alone.
    """
    if not body:
        return "", ""
    try:
        if isinstance(body, bytes):
            if len(body) > _JWS_TRACE_BODY_MAX_BYTES:
                return "", ""
            text = body.decode("utf-8")
        else:
            text = str(body)
            if len(text) > _JWS_TRACE_BODY_MAX_BYTES:
                return "", ""
        outer = json.loads(text)
        protected_b64 = outer.get("protected")
        if not isinstance(protected_b64, str) or not protected_b64:
            return "", ""
        pad = "=" * (-len(protected_b64) % 4)
        protected = json.loads(
            base64.urlsafe_b64decode(protected_b64 + pad).decode("utf-8")
        )
        nonce_key = ""
        nonce = protected.get("nonce")
        if isinstance(nonce, str) and nonce:
            nonce_key = f"nonce:{nonce}"
        account_name = _account_name_from_kid(protected.get("kid"))
        return nonce_key, account_name
    except Exception:  # noqa: BLE001 — tracing must never break ACME
        return "", ""


def nonce_trace_key_from_jws_body(body: Union[bytes, str, None]) -> str:
    """Extract ``nonce:<value>`` from a JWS body for session-trace continuation."""
    nonce_key, _account_name = jws_trace_hints_from_body(body)
    return nonce_key


def _is_challenge_resource_path(path: str) -> bool:
    """True for ACME challenge resource URLs (``/chall/…``)."""
    if not path:
        return False
    normalized = path.lower()
    return "/chall/" in normalized or normalized.rstrip("/").endswith("/chall")


def setup_trace_key_for_request(
    path: str,
    body: Union[bytes, str, None] = None,
    hints: Optional[Tuple[str, str]] = None,
) -> str:
    """Return continue key for the enrollment-session trace.

    Prefer a *remembered* Replay-Nonce. Otherwise prefer an *account tip* when
    the JWS ``kid`` is known, else the global session tip for ``/`` /
    directory / newNonce / ARI / challenge. After a successful enroll, the
    next ``/`` or ``directory`` returns no key so a new session root starts.

    ``hints`` may supply a precomputed ``(nonce_key, account_name)`` to avoid
    parsing the JWS body twice.
    """
    if not _enabled:
        return ""
    if is_session_entry_path(path):
        with _session_boundary_lock:
            if _session_boundary_pending:
                return ""
    if hints is None:
        nonce_key, account_name = jws_trace_hints_from_body(body)
    else:
        nonce_key, account_name = hints
    if nonce_key and has_remembered_span_context(nonce_key):
        return nonce_key
    tip_eligible = (
        is_session_tip_path(path)
        or _is_challenge_resource_path(path)
        or bool(nonce_key)
    )
    if not tip_eligible:
        return ""
    acct_key = account_tip_key(account_name)
    if acct_key and has_remembered_span_context(acct_key):
        return acct_key
    if has_remembered_span_context(SESSION_TIP_KEY):
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
    consume_boundary = False
    with _session_boundary_lock:
        if is_session_entry_path(path) and _session_boundary_pending:
            _session_boundary_pending = False
            consume_boundary = True
    hints = jws_trace_hints_from_body(body)
    _nonce_key, account_name = hints
    if consume_boundary:
        setup_key = ""
        with _span_contexts_lock:
            _drop_nonce_span_contexts_locked()
    else:
        setup_key = setup_trace_key_for_request(path, body, hints=hints)
    joined = has_remembered_span_context(setup_key)
    with continue_span_context(setup_key):
        with http_request_span(method, path) as active:
            try:
                yield active
            finally:
                if joined or is_session_tip_path(path):
                    remember_session_tip(account_name)


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
