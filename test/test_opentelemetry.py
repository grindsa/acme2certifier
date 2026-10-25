# -*- coding: utf-8 -*-
"""Tests for acme_srv.helpers.otel (NoOp gate + optional SDK InMemory cases).

CI smoke ``test_054_otlp_http_export_appears_in_jaeger`` runs only when
``A2C_OTEL_CI_SMOKE=1`` with a reachable OTLP HTTP collector / Jaeger UI.
"""

from __future__ import annotations

import configparser
import json
import logging
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from contextlib import contextmanager
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
    pytest.importorskip("opentelemetry", reason="optional extra [otel] not installed")
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
    otel_mod.reset_otel_state()
    _reset_otel_api_providers()
    yield
    otel_mod.reset_otel_state()
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
    meter_provider = MeterProvider(resource=resource, metric_readers=[metric_reader])
    metrics.set_meter_provider(meter_provider)

    otel_mod._initialized = True
    otel_mod._enabled = True
    otel_mod._tracer = trace.get_tracer("acme2certifier")
    otel_mod._meter = metrics.get_meter("acme2certifier")
    otel_mod._counters = {}
    otel_mod._histograms = {}
    return span_exporter, metric_reader


def test_001_init_otel_default_disabled() -> None:
    """Missing / empty OpenTelemetry section keeps NoOp."""
    with patch.object(otel_mod, "load_config", return_value=_cfg()):
        assert otel_mod.init_otel(logging.getLogger("test")) is False
    assert otel_mod.is_otel_enabled() is False


def test_002_init_otel_explicit_false() -> None:
    """opentelemetry_support=False stays NoOp."""
    with patch.object(
        otel_mod, "load_config", return_value=_cfg(opentelemetry_support="False")
    ):
        assert otel_mod.init_otel() is False
    assert otel_mod.is_otel_enabled() is False


def test_003_span_and_metrics_noop_when_disabled() -> None:
    """Facade helpers do not raise when OTEL is off."""
    with patch.object(otel_mod, "load_config", return_value=_cfg()):
        otel_mod.init_otel()
    with otel_mod.span("acme.test", attributes={"acme.outcome": "ok"}) as active:
        active.set_attribute("x", 1)
        active.set_status("ignored")
    otel_mod.counter_add("acme.test.counter", attributes={"result": "ok"})
    otel_mod.histogram_record("acme.test.duration", 1.5, attributes={"result": "ok"})


def test_004_init_otel_true_without_sdk_stays_noop(
    caplog: pytest.LogCaptureFixture,
) -> None:
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


def test_005_init_otel_idempotent() -> None:
    """Second init_otel call returns the same enabled flag without re-init."""
    with patch.object(otel_mod, "load_config", return_value=_cfg()) as mock_load:
        assert otel_mod.init_otel() is False
        assert otel_mod.init_otel() is False
        assert mock_load.call_count == 1


def test_006_otlp_traces_endpoint_helper() -> None:
    """Endpoint helper appends /v1/traces once."""
    assert (
        otel_mod._otlp_traces_endpoint("http://192.168.64.3:4318")
        == "http://192.168.64.3:4318/v1/traces"
    )
    assert (
        otel_mod._otlp_traces_endpoint("http://192.168.64.3:4318/v1/traces")
        == "http://192.168.64.3:4318/v1/traces"
    )


def test_007_sample_ratio_clamped() -> None:
    """sample_ratio outside [0,1] is clamped."""
    cfg_high = _cfg(sample_ratio="2.5")
    cfg_low = _cfg(sample_ratio="-1")
    assert otel_mod._config_sample_ratio(cfg_high) == 1.0
    assert otel_mod._config_sample_ratio(cfg_low) == 0.0


def test_008_boot_acme_http_stack_calls_init_otel() -> None:
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
        patch(
            "acme2certifier.acme_srv.helper.legacy_acme_get_load", return_value=False
        ),
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


def test_009_init_otel_unsupported_protocol(caplog: pytest.LogCaptureFixture) -> None:
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


def test_010_sdk_span_records_name_and_attributes() -> None:
    """Enabled facade records spans via InMemorySpanExporter."""
    span_exporter, _reader = _enable_inmemory_providers()
    with otel_mod.span(
        "acme.challenge.validate",
        attributes={"acme.challenge_type": "http-01", "acme.skip": None},
    ) as active:
        active.set_attribute("acme.outcome", "success")
    spans = span_exporter.get_finished_spans()
    assert len(spans) == 1
    assert spans[0].name == "acme.challenge.validate"
    assert spans[0].attributes["acme.challenge_type"] == "http-01"
    assert spans[0].attributes["acme.outcome"] == "success"
    assert "acme.skip" not in spans[0].attributes


def test_011_sdk_span_set_attributes_batch() -> None:
    """span() prefers Span.set_attributes when the SDK provides it."""
    span_exporter, _reader = _enable_inmemory_providers()
    with otel_mod.span(
        "acme.account.key_change",
        attributes={
            "acme.account_name": "acct1",
            "acme.account.operation": "key_change",
        },
    ):
        pass
    root = span_exporter.get_finished_spans()[0]
    assert root.attributes["acme.account_name"] == "acct1"
    assert root.attributes["acme.account.operation"] == "key_change"


def test_012_sdk_http_request_span_parents_nested_span() -> None:
    """Root http span and nested hot-path span share one trace."""
    span_exporter, _reader = _enable_inmemory_providers()
    with otel_mod.http_request_span("POST", "/acme/chall/xyz") as root:
        root.set_attribute("http.status_code", 200)
        with otel_mod.span(
            "acme.challenge.validate",
            attributes={"acme.challenge_type": "http-01"},
        ):
            pass
    spans = {s.name: s for s in span_exporter.get_finished_spans()}
    assert "acme.http.request" in spans
    assert "acme.challenge.validate" in spans
    root = spans["acme.http.request"]
    child = spans["acme.challenge.validate"]
    assert root.attributes["http.method"] == "POST"
    assert root.attributes["http.route"] == "/acme/chall/xyz"
    assert child.parent is not None
    assert child.parent.span_id == root.context.span_id
    assert child.context.trace_id == root.context.trace_id


def test_013_sdk_nonce_key_consumed_after_continue() -> None:
    """nonce: keys are single-use; session tip is retained."""
    _exporter, _reader = _enable_inmemory_providers()
    with otel_mod.http_request_span("HEAD", "/acme/newnonce"):
        otel_mod.remember_request_span_context("nonce:once")
        otel_mod.remember_session_tip()
    assert otel_mod.has_remembered_span_context("nonce:once")
    assert otel_mod.has_remembered_span_context(otel_mod.SESSION_TIP_KEY)
    with otel_mod.continue_span_context("nonce:once"):
        pass
    assert not otel_mod.has_remembered_span_context("nonce:once")
    assert otel_mod.has_remembered_span_context(otel_mod.SESSION_TIP_KEY)


def test_014_sdk_acme_traced_request_chains_http_requests() -> None:
    """Shared request helper continues nonce and advances tip."""
    import base64
    import json

    span_exporter, _reader = _enable_inmemory_providers()
    with otel_mod.acme_traced_request("HEAD", "/acme/newnonce") as first_http:
        with otel_mod.span("acme.nonce.issue"):
            otel_mod.remember_request_span_context("nonce:abc123")
        first_http_id = first_http.get_span_context().span_id
        first_trace = first_http.get_span_context().trace_id
    protected = (
        base64.urlsafe_b64encode(
            json.dumps({"nonce": "abc123", "url": "https://x/acme/newacct"}).encode()
        )
        .decode()
        .rstrip("=")
    )
    body = json.dumps(
        {"protected": protected, "payload": "", "signature": "x"}
    ).encode()
    with otel_mod.acme_traced_request("POST", "/acme/newacct", body):
        with otel_mod.span("acme.jws.verify"):
            pass
    finished = span_exporter.get_finished_spans()
    second_http = [
        s
        for s in finished
        if s.name == "acme.http.request"
        and s.attributes.get("http.route") == "/acme/newacct"
    ]
    assert second_http
    assert second_http[0].context.trace_id == first_trace
    assert second_http[0].parent is not None
    assert second_http[0].parent.span_id == first_http_id
    assert not otel_mod.has_remembered_span_context("nonce:abc123")
    assert otel_mod.has_remembered_span_context(otel_mod.SESSION_TIP_KEY)


def test_015_sdk_nonce_issue_does_not_become_next_http_parent() -> None:
    """remember_request_span_context ignores nested nonce.issue as tip parent."""
    span_exporter, _reader = _enable_inmemory_providers()
    with otel_mod.http_request_span("HEAD", "/acme/newnonce") as first_http:
        with otel_mod.span("acme.nonce.issue"):
            otel_mod.remember_request_span_context("nonce:n1")
        first_id = first_http.get_span_context().span_id
    with otel_mod.continue_span_context("nonce:n1"):
        with otel_mod.http_request_span("POST", "/acme/newaccount"):
            pass
    second = next(
        s
        for s in span_exporter.get_finished_spans()
        if s.name == "acme.http.request"
        and s.attributes.get("http.route") == "/acme/newaccount"
    )
    assert second.parent.span_id == first_id
    nonce_span = next(
        s for s in span_exporter.get_finished_spans() if s.name == "acme.nonce.issue"
    )
    assert second.parent.span_id != nonce_span.context.span_id


def test_016_setup_trace_key_prefers_remembered_nonce() -> None:
    """Challenge POSTs use a remembered nonce when present."""
    import base64
    import json

    _exporter, _reader = _enable_inmemory_providers()
    with otel_mod.http_request_span("HEAD", "/acme/newnonce"):
        otel_mod.remember_request_span_context("nonce:n1")
        otel_mod.remember_session_tip()
    protected = (
        base64.urlsafe_b64encode(json.dumps({"nonce": "n1"}).encode())
        .decode()
        .rstrip("=")
    )
    body = json.dumps({"protected": protected, "payload": "", "signature": "x"})
    assert otel_mod.setup_trace_key_for_request("/acme/chall/xyz", body) == "nonce:n1"


def test_017_setup_trace_key_falls_back_to_tip_for_unknown_nonce() -> None:
    """Unknown/missing nonce on /chall still joins via session tip."""
    import base64
    import json

    span_exporter, _reader = _enable_inmemory_providers()
    with otel_mod.acme_traced_request("GET", "/directory") as directory:
        directory_trace = directory.get_span_context().trace_id
    protected = (
        base64.urlsafe_b64encode(json.dumps({"nonce": "unknown"}).encode())
        .decode()
        .rstrip("=")
    )
    body = json.dumps({"protected": protected, "payload": "", "signature": "x"})
    assert (
        otel_mod.setup_trace_key_for_request("/acme/chall/xyz", body)
        == otel_mod.SESSION_TIP_KEY
    )
    with otel_mod.acme_traced_request("POST", "/acme/chall/xyz", body):
        with otel_mod.span("acme.challenge.validate"):
            pass
    validate = next(
        s
        for s in span_exporter.get_finished_spans()
        if s.name == "acme.challenge.validate"
    )
    assert validate.context.trace_id == directory_trace


def test_018_sdk_session_tip_joins_directory_and_newnonce() -> None:
    """Within one session, / → directory → newNonce → ARI share a tip chain."""
    span_exporter, _reader = _enable_inmemory_providers()
    assert otel_mod.is_session_entry_path("/directory") is True
    assert otel_mod.is_session_tip_path("/acme/newnonce") is True

    with otel_mod.acme_traced_request("GET", "/") as root:
        root_trace = root.get_span_context().trace_id
    with otel_mod.acme_traced_request("GET", "/directory"):
        pass
    with otel_mod.acme_traced_request("HEAD", "/acme/newnonce"):
        pass
    with otel_mod.acme_traced_request("GET", "/acme/renewal-info/aki.serial"):
        pass

    finished = span_exporter.get_finished_spans()
    routes = {
        s.attributes.get("http.route"): s
        for s in finished
        if s.name == "acme.http.request"
    }
    assert routes["/"].context.trace_id == root_trace
    assert routes["/directory"].context.trace_id == root_trace
    assert routes["/acme/newnonce"].context.trace_id == root_trace
    assert routes["/acme/renewal-info/aki.serial"].context.trace_id == root_trace


def test_019_sdk_directory_starts_new_session_after_enroll() -> None:
    """After enroll completes, the next / or directory opens a new session root."""
    span_exporter, _reader = _enable_inmemory_providers()
    with otel_mod.acme_traced_request("GET", "/") as first:
        first_trace = first.get_span_context().trace_id
    with otel_mod.acme_traced_request("GET", "/directory"):
        pass
    with otel_mod.acme_traced_request("HEAD", "/acme/newnonce"):
        pass
    otel_mod.mark_enrollment_session_complete()
    with otel_mod.acme_traced_request("GET", "/") as second:
        second_trace = second.get_span_context().trace_id
    assert first_trace != second_trace
    with otel_mod.acme_traced_request("GET", "/directory") as third:
        assert third.get_span_context().trace_id == second_trace
    with otel_mod.acme_traced_request("HEAD", "/acme/newnonce") as fourth:
        assert fourth.get_span_context().trace_id == second_trace
    finished = span_exporter.get_finished_spans()
    assert len([s for s in finished if s.name == "acme.http.request"]) == 6


def test_020_span_context_ttl_expires_nonce_keys() -> None:
    """Unused nonce continue keys expire after the configured TTL."""
    _exporter, _reader = _enable_inmemory_providers()
    otel_mod._span_ctx_ttl_sec = 0.05
    with otel_mod.http_request_span("HEAD", "/acme/newnonce"):
        otel_mod.remember_request_span_context("nonce:stale")
    assert otel_mod.has_remembered_span_context("nonce:stale")
    time.sleep(0.06)
    assert not otel_mod.has_remembered_span_context("nonce:stale")


def test_021_span_context_max_evicts_oldest_nonce() -> None:
    """Overflow prefers dropping oldest nonce: keys before tips."""
    _exporter, _reader = _enable_inmemory_providers()
    otel_mod._span_ctx_max = 3
    with otel_mod.http_request_span("HEAD", "/acme/newnonce"):
        otel_mod.remember_session_tip()
        otel_mod.remember_request_span_context("nonce:a")
        otel_mod.remember_request_span_context("nonce:b")
        otel_mod.remember_request_span_context("nonce:c")
    assert otel_mod.has_remembered_span_context(otel_mod.SESSION_TIP_KEY)
    assert not otel_mod.has_remembered_span_context("nonce:a")
    assert otel_mod.has_remembered_span_context("nonce:b")
    assert otel_mod.has_remembered_span_context("nonce:c")


def test_022_jws_trace_hints_skip_oversized_body() -> None:
    """Bodies above the tip-parse cap are not JSON-decoded for chaining."""
    _exporter, _reader = _enable_inmemory_providers()
    huge = b"x" * (otel_mod.jws_trace_body_max_bytes() + 1)
    assert otel_mod.jws_trace_hints_from_body(huge) == ("", "")


def test_023_forget_nonce_span_contexts_drops_keys() -> None:
    """Nonce expiry housekeeping clears matching OTEL continue keys."""
    _exporter, _reader = _enable_inmemory_providers()
    with otel_mod.http_request_span("HEAD", "/acme/newnonce"):
        otel_mod.remember_request_span_context("nonce:gone")
        otel_mod.remember_session_tip()
    otel_mod.forget_nonce_span_contexts(["gone"])
    assert not otel_mod.has_remembered_span_context("nonce:gone")
    assert otel_mod.has_remembered_span_context(otel_mod.SESSION_TIP_KEY)


def test_024_account_tip_isolates_authenticated_clients() -> None:
    """After kid is known, account tips keep two clients on separate traces."""
    import base64
    import json

    span_exporter, _reader = _enable_inmemory_providers()

    def _body(nonce: str, account: str) -> bytes:
        protected = (
            base64.urlsafe_b64encode(
                json.dumps(
                    {
                        "nonce": nonce,
                        "kid": f"https://acme.example/acme/acct/{account}",
                    }
                ).encode()
            )
            .decode()
            .rstrip("=")
        )
        return json.dumps(
            {"protected": protected, "payload": "", "signature": "x"}
        ).encode()

    # Seed Alice's tree, then an authenticated POST records her account tip.
    with otel_mod.acme_traced_request("GET", "/directory") as alice_root:
        alice_trace = alice_root.get_span_context().trace_id
    with otel_mod.acme_traced_request(
        "POST", "/acme/order", _body("unknown-a", "alice")
    ):
        pass
    assert otel_mod.has_remembered_span_context(otel_mod.account_tip_key("alice"))
    # Drop the global tip so Bob's directory opens a new root (last-writer
    # overwrite alone would still continue Alice's tip).
    otel_mod._pop_span_context(otel_mod.SESSION_TIP_KEY)
    with otel_mod.acme_traced_request("GET", "/directory") as bob_dir:
        bob_trace = bob_dir.get_span_context().trace_id
    assert alice_trace != bob_trace
    # Alice continues via account tip despite global tip now pointing at Bob.
    key = otel_mod.setup_trace_key_for_request(
        "/acme/order", _body("unknown-b", "alice")
    )
    assert key == otel_mod.account_tip_key("alice")
    with otel_mod.acme_traced_request(
        "POST", "/acme/order", _body("unknown-b", "alice")
    ) as alice_again:
        assert alice_again.get_span_context().trace_id == alice_trace
    http_spans = [
        s for s in span_exporter.get_finished_spans() if s.name == "acme.http.request"
    ]
    assert len(http_spans) == 4
    assert bob_dir.get_span_context().trace_id == bob_trace


def test_025_sdk_http_request_span_kind_server() -> None:
    """http.request uses SERVER span kind when the SDK is present."""
    span_exporter, _reader = _enable_inmemory_providers()
    from opentelemetry.trace import SpanKind

    with otel_mod.http_request_span("GET", "/directory"):
        pass
    root = span_exporter.get_finished_spans()[0]
    assert root.kind == SpanKind.SERVER


def test_026_sdk_thread_with_return_value_propagates_context() -> None:
    """Challenge-style worker thread nests spans under the captured parent."""
    from acme2certifier.acme_srv.threadwithreturnvalue import ThreadWithReturnValue

    span_exporter, _reader = _enable_inmemory_providers()

    def _worker() -> None:
        with otel_mod.span("acme.challenge.validate"):
            pass

    with otel_mod.http_request_span("POST", "/acme/chall/xyz") as root:
        root_id = root.get_span_context().span_id
        root_trace = root.get_span_context().trace_id
        twrv = ThreadWithReturnValue(target=_worker)
        twrv.start()
        twrv.join(timeout=5)
    validate = next(
        s
        for s in span_exporter.get_finished_spans()
        if s.name == "acme.challenge.validate"
    )
    assert validate.context.trace_id == root_trace
    assert validate.parent is not None
    assert validate.parent.span_id == root_id


def test_027_remember_continue_noop_when_disabled() -> None:
    """remember/continue are safe no-ops when OTEL is off."""
    with patch.object(otel_mod, "load_config", return_value=_cfg()):
        otel_mod.init_otel()
    otel_mod.remember_request_span_context("nonce:x")
    with otel_mod.continue_span_context("nonce:x"):
        pass
    with otel_mod.acme_traced_request("GET", "/directory"):
        pass


def test_028_sdk_counter_and_histogram_record() -> None:
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


def test_029_init_otel_true_with_sdk_sets_enabled(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """opentelemetry_support=True with SDK present enables facade (no real OTLP)."""
    _require_otel_sdk()
    _reset_otel_api_providers()
    real_import = otel_mod._import_otel_sdk
    metric_exporter = MagicMock()

    def _sdk_with_noop_exporters() -> Any:
        sdk = real_import()
        sdk["OTLPSpanExporter"] = lambda **_kwargs: MagicMock()
        sdk["OTLPMetricExporter"] = lambda **_kwargs: metric_exporter
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
    assert otel_mod._meter is None  # metrics_export defaults False
    assert any("experimental" in r.getMessage() for r in caplog.records)
    assert any("metrics_export=False" in r.getMessage() for r in caplog.records)

    with otel_mod.span("acme.certificate.enroll") as active:
        active.set_attribute("acme.outcome", "success")
    otel_mod.counter_add("acme.ca_handler.call", attributes={"acme.outcome": "success"})
    otel_mod.histogram_record("acme.issuance.duration", 1.0)


def test_030_init_otel_metrics_export_opt_in() -> None:
    """metrics_export=True wires the OTLP metric exporter."""
    _require_otel_sdk()
    _reset_otel_api_providers()
    real_import = otel_mod._import_otel_sdk
    metric_calls: list = []

    def _sdk_with_noop_exporters() -> Any:
        sdk = real_import()
        sdk["OTLPSpanExporter"] = lambda **_kwargs: MagicMock()

        def _metric_exporter(**kwargs: Any) -> Any:
            metric_calls.append(kwargs)
            return MagicMock()

        sdk["OTLPMetricExporter"] = _metric_exporter
        return sdk

    with patch.object(
        otel_mod,
        "load_config",
        return_value=_cfg(
            opentelemetry_support="True",
            metrics_export="True",
            endpoint="http://127.0.0.1:4318",
        ),
    ):
        with patch.object(
            otel_mod, "_import_otel_sdk", side_effect=_sdk_with_noop_exporters
        ):
            assert otel_mod.init_otel() is True
    assert otel_mod._meter is not None
    assert metric_calls
    assert metric_calls[0].get("endpoint", "").endswith("/v1/metrics")


def test_031_set_span_outcome_error_sets_status() -> None:
    """outcome=error marks StatusCode.ERROR; failure does not."""
    span_exporter, _reader = _enable_inmemory_providers()
    from opentelemetry.trace import StatusCode

    with otel_mod.span("acme.certificate.enroll") as active:
        otel_mod.set_span_outcome(active, "failure")
    with otel_mod.span("acme.certificate.enroll") as active:
        otel_mod.set_span_outcome(active, "error", RuntimeError("boom"))
    with otel_mod.http_request_span("POST", "/acme/order") as active:
        otel_mod.mark_http_status(active, 500)
    with otel_mod.http_request_span("POST", "/acme/order") as active:
        otel_mod.mark_http_status(active, 403)
    enrolls = [
        s
        for s in span_exporter.get_finished_spans()
        if s.name == "acme.certificate.enroll"
    ]
    https = [
        s for s in span_exporter.get_finished_spans() if s.name == "acme.http.request"
    ]
    assert enrolls[0].attributes["acme.outcome"] == "failure"
    assert enrolls[0].status.status_code != StatusCode.ERROR
    assert enrolls[1].attributes["acme.outcome"] == "error"
    assert enrolls[1].status.status_code == StatusCode.ERROR
    assert https[0].status.status_code == StatusCode.ERROR
    assert https[1].status.status_code != StatusCode.ERROR


def test_032_config_db_span_methods_default_and_override() -> None:
    """db_span_methods JSON list overrides default; invalid keeps default."""
    logger = logging.getLogger("otel-db-span-cfg")
    assert (
        otel_mod._config_db_span_methods(_cfg(), logger)
        == otel_mod._DEFAULT_DB_SPAN_METHODS
    )
    assert otel_mod._config_db_span_methods(
        _cfg(db_span_methods='["order_add", "account_lookup"]'), logger
    ) == frozenset({"order_add", "account_lookup"})
    assert (
        otel_mod._config_db_span_methods(_cfg(db_span_methods="[]"), logger)
        == frozenset()
    )
    assert (
        otel_mod._config_db_span_methods(_cfg(db_span_methods="not-json"), logger)
        == otel_mod._DEFAULT_DB_SPAN_METHODS
    )


def test_033_instrument_dbstore_class_noop_when_disabled() -> None:
    """DBstore wrappers return values unchanged when OTEL is off."""

    class FakeStore:
        type = "wsgi"

        def order_add(self, data_dic: dict) -> int:
            return 7

        def account_lookup(self, key: str, value: str) -> dict:
            return {key: value}

        def _private(self) -> str:
            return "skip"

    store_cls = otel_mod.instrument_dbstore_class(FakeStore)
    assert store_cls is FakeStore
    assert FakeStore._otel_db_instrumented is True
    assert FakeStore().order_add({"name": "o"}) == 7
    assert FakeStore().account_lookup("name", "acct1") == {"name": "acct1"}
    assert FakeStore()._private() == "skip"
    # Idempotent
    assert otel_mod.instrument_dbstore_class(FakeStore) is FakeStore


def test_034_instrument_dbstore_class_records_spans() -> None:
    """Enabled facade records ``acme.db.*`` only for mutating DBstore methods."""
    span_exporter, _reader = _enable_inmemory_providers()

    class FakeStore:
        type = "django"

        def order_add(self, data_dic: dict) -> int:
            return 42

        def order_update(self, data_dic: dict) -> None:
            raise RuntimeError("conflict")

        def order_lookup(self, key: str, value: str) -> dict:
            return {key: value}

        def nonce_check(self, nonce: str) -> bool:
            return True

    otel_mod.instrument_dbstore_class(FakeStore)
    store = FakeStore()
    assert store.order_add({"name": "ord1"}) == 42
    assert store.order_lookup("name", "ord1") == {"name": "ord1"}
    assert store.nonce_check("n1") is True
    with pytest.raises(RuntimeError, match="conflict"):
        store.order_update({"name": "ord1"})

    spans = {s.name: s for s in span_exporter.get_finished_spans()}
    assert "acme.db.order_add" in spans
    assert spans["acme.db.order_add"].attributes["db.operation"] == "order_add"
    assert spans["acme.db.order_add"].attributes["db.system"] == "django"
    assert spans["acme.db.order_add"].attributes["acme.outcome"] == "success"
    assert "acme.db.order_update" in spans
    assert spans["acme.db.order_update"].attributes["acme.outcome"] == "error"
    assert "acme.db.order_lookup" not in spans
    assert "acme.db.nonce_check" not in spans


def test_035_instrument_dbstore_respects_runtime_allowlist() -> None:
    """Call-time ``_db_span_methods`` can enable a lookup that default omits."""
    span_exporter, _reader = _enable_inmemory_providers()

    class FakeStore:
        type = "wsgi"

        def account_lookup(self, key: str, value: str) -> dict:
            return {key: value}

    otel_mod.instrument_dbstore_class(FakeStore)
    otel_mod._db_span_methods = frozenset({"account_lookup"})
    assert FakeStore().account_lookup("name", "a1") == {"name": "a1"}
    spans = span_exporter.get_finished_spans()
    assert len(spans) == 1
    assert spans[0].name == "acme.db.account_lookup"


def test_036_get_trace_context_ids_zeros_when_disabled() -> None:
    """Without OTEL, correlation helpers return zero placeholders."""
    assert otel_mod.get_trace_context_ids() == (
        otel_mod._TRACE_ID_ZERO,
        otel_mod._SPAN_ID_ZERO,
    )


def test_037_trace_context_filter_injects_ids_under_span() -> None:
    """Filter sets otelTraceID/otelSpanID from the active span."""
    _enable_inmemory_providers()
    logger = logging.getLogger("otel-log-corr-test")
    logger.handlers.clear()
    logger.filters.clear()
    logger.propagate = False
    logger.setLevel(logging.INFO)
    records: list[logging.LogRecord] = []

    class _Capture(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            records.append(record)

    handler = _Capture()
    logger.addHandler(handler)
    otel_mod.install_log_correlation(logger)

    with otel_mod.span("acme.test.log_corr"):
        logger.info("inside span")
        in_trace, in_span = otel_mod.get_trace_context_ids()

    assert records
    assert records[0].otelTraceID == in_trace  # type: ignore[attr-defined]
    assert records[0].otelSpanID == in_span  # type: ignore[attr-defined]
    assert records[0].otelTraceID != otel_mod._TRACE_ID_ZERO  # type: ignore[attr-defined]
    assert len(records[0].otelTraceID) == 32  # type: ignore[attr-defined]
    assert len(records[0].otelSpanID) == 16  # type: ignore[attr-defined]

    # Idempotent install (logger + handler)
    otel_mod.install_log_correlation(logger)
    assert (
        sum(1 for f in logger.filters if isinstance(f, otel_mod.TraceContextFilter))
        == 1
    )
    assert (
        sum(1 for f in handler.filters if isinstance(f, otel_mod.TraceContextFilter))
        == 1
    )


def test_038_handler_filter_covers_propagated_child_logger() -> None:
    """Child logger → root handler still gets otelTraceID (SDK export case)."""
    root = logging.getLogger()
    # Isolate root handlers for this test.
    old_handlers = list(root.handlers)
    for h in old_handlers:
        root.removeHandler(h)
    try:
        records: list[logging.LogRecord] = []

        class _Capture(logging.Handler):
            def emit(self, record: logging.LogRecord) -> None:
                # Mimic Formatter needing otelTraceID
                assert hasattr(record, "otelTraceID")
                assert hasattr(record, "otelSpanID")
                records.append(record)

        handler = _Capture()
        handler.setFormatter(logging.Formatter("trace=%(otelTraceID)s %(message)s"))
        root.addHandler(handler)
        otel_mod.install_log_correlation(logging.getLogger("acme2certifier"))

        child = logging.getLogger("acme2certifier.otel_propagate_probe")
        child.setLevel(logging.WARNING)
        child.propagate = True
        child.handlers.clear()
        child.warning("Transient error exporting spans")
        assert records
        formatted = handler.format(records[0])
        assert formatted.startswith("trace=")
        assert "Transient error" in formatted
    finally:
        for h in list(root.handlers):
            root.removeHandler(h)
        for h in old_handlers:
            root.addHandler(h)


def test_039_resilient_exporter_logs_critical_once(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Export failures never raise; first failure is CRITICAL on a2c logger."""

    class _Failing:
        def export(self, _batch: Any) -> Any:
            raise ConnectionError("connection refused")

        def shutdown(self) -> None:
            return None

    logger = logging.getLogger("otel-resilient-export")
    wrapper = otel_mod._ResilientExporter(_Failing(), logger, kind="spans")
    with caplog.at_level(logging.CRITICAL, logger="otel-resilient-export"):
        result1 = wrapper.export([])
        result2 = wrapper.export([])
    assert result1 is not None
    assert result2 is not None
    criticals = [r for r in caplog.records if r.levelno >= logging.CRITICAL]
    assert len(criticals) == 1
    assert "ACME requests continue" in criticals[0].getMessage()


class _MappingConfig:
    """Config stand-in without ConfigParser.getboolean/has_option."""

    def __init__(self, section: Any) -> None:
        self._section = section

    def __contains__(self, key: object) -> bool:
        return key == "OpenTelemetry"

    def get(self, key: str, option: Any = None, fallback: Any = None) -> Any:
        if key != "OpenTelemetry":
            raise TypeError(key)
        if option is None:
            return self._section
        if not isinstance(self._section, dict):
            return fallback
        return self._section.get(option, fallback)


class _RaisingConfig:
    def __contains__(self, key: object) -> bool:
        return key == "OpenTelemetry"

    def get(self, *_args: Any, **_kwargs: Any) -> Any:
        raise TypeError("unreadable")


def test_040_noop_span_methods() -> None:
    """NoOp span implements the SDK surface used by callers."""
    active = otel_mod._NoOpSpan()
    assert active.set_attributes({"acme.outcome": "ok"}) is None
    assert active.record_exception(RuntimeError("x")) is None
    assert active.end() is None
    with active as entered:
        assert entered is active


def test_041_config_readers_fallbacks(caplog: pytest.LogCaptureFixture) -> None:
    """Non-ConfigParser and invalid values use documented fallbacks."""
    logger = logging.getLogger("test_a2c")
    assert otel_mod._config_get(_cfg(), "endpoint", "fallback") == "fallback"
    assert otel_mod._config_get(_RaisingConfig(), "endpoint", "fallback") == "fallback"
    assert otel_mod._config_sample_ratio(_cfg(sample_ratio="nope")) == 1.0
    assert (
        otel_mod._config_getboolean(
            _cfg(opentelemetry_support="not-a-bool"), "opentelemetry_support"
        )
        is False
    )

    mapping = _MappingConfig(
        {"flag": True, "word": " YES ", "num": 3, "db_span_methods": ""}
    )
    assert otel_mod._config_getboolean(mapping, "missing", fallback=False) is False
    assert otel_mod._config_getboolean(mapping, "word") is True
    assert otel_mod._config_getboolean(mapping, "num", fallback=True) is True
    assert otel_mod._config_getboolean(_MappingConfig("nope"), "flag", fallback=True)

    empty_methods = _MappingConfig({"db_span_methods": ""})
    assert otel_mod._config_db_span_methods(empty_methods, logger) == frozenset()
    not_a_list = _MappingConfig({"db_span_methods": '{"order_add": true}'})
    with caplog.at_level(logging.WARNING, logger="test_a2c"):
        assert (
            otel_mod._config_db_span_methods(not_a_list, logger)
            == otel_mod._DEFAULT_DB_SPAN_METHODS
        )
    assert any("must be a JSON list" in r.getMessage() for r in caplog.records)


def test_042_init_otel_metrics_strips_traces_suffix() -> None:
    """metrics endpoint is derived when the traces URL already includes /v1/traces."""
    _require_otel_sdk()
    _reset_otel_api_providers()
    real_import = otel_mod._import_otel_sdk
    metric_calls: list = []

    def _sdk_with_noop_exporters() -> Any:
        sdk = real_import()
        sdk["OTLPSpanExporter"] = lambda **_kwargs: MagicMock()

        def _metric_exporter(**kwargs: Any) -> Any:
            metric_calls.append(kwargs)
            return MagicMock()

        sdk["OTLPMetricExporter"] = _metric_exporter
        return sdk

    with patch.object(
        otel_mod,
        "load_config",
        return_value=_cfg(
            opentelemetry_support="True",
            metrics_export="True",
            endpoint="http://127.0.0.1:4318/v1/traces",
        ),
    ):
        with patch.object(
            otel_mod, "_import_otel_sdk", side_effect=_sdk_with_noop_exporters
        ):
            assert otel_mod.init_otel() is True
    assert metric_calls[0]["endpoint"] == "http://127.0.0.1:4318/v1/metrics"


def test_043_init_otel_setup_failure_stays_noop(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """SDK constructor errors leave tracing disabled."""
    _require_otel_sdk()
    real_import = otel_mod._import_otel_sdk

    def _sdk_boom() -> Any:
        sdk = real_import()

        class _BoomResource:
            @staticmethod
            def create(_attrs: Any) -> Any:
                raise RuntimeError("init boom")

        sdk["Resource"] = _BoomResource
        return sdk

    with patch.object(
        otel_mod,
        "load_config",
        return_value=_cfg(opentelemetry_support="True"),
    ):
        with patch.object(otel_mod, "_import_otel_sdk", side_effect=_sdk_boom):
            with caplog.at_level(logging.ERROR):
                assert otel_mod.init_otel() is False
    assert otel_mod.is_otel_enabled() is False
    assert any("initialization failed" in r.getMessage() for r in caplog.records)


def test_044_trace_context_ids_import_and_lookup_errors() -> None:
    """Missing SDK or a broken current span yields zero ids."""
    import sys

    otel_mod._enabled = True
    saved = sys.modules.get("opentelemetry.trace")
    sys.modules["opentelemetry.trace"] = None
    try:
        import opentelemetry

        trace_attr = getattr(opentelemetry, "trace", None)
        if hasattr(opentelemetry, "trace"):
            delattr(opentelemetry, "trace")
        try:
            assert otel_mod.get_trace_context_ids() == (
                otel_mod._TRACE_ID_ZERO,
                otel_mod._SPAN_ID_ZERO,
            )
        finally:
            if trace_attr is not None:
                opentelemetry.trace = trace_attr
    finally:
        if saved is None:
            sys.modules.pop("opentelemetry.trace", None)
        else:
            sys.modules["opentelemetry.trace"] = saved

    otel_mod._enabled = True
    with patch("opentelemetry.trace.get_current_span", side_effect=RuntimeError("x")):
        assert otel_mod.get_trace_context_ids() == (
            otel_mod._TRACE_ID_ZERO,
            otel_mod._SPAN_ID_ZERO,
        )


def test_045_install_log_correlation_skips_duplicate_logger() -> None:
    """Passing the root logger does not attach a second filter to it."""
    root = logging.getLogger()
    before = list(root.filters)
    try:
        otel_mod.install_log_correlation(root)
        added = [f for f in root.filters if isinstance(f, otel_mod.TraceContextFilter)]
        assert len(added) == 1
    finally:
        for filt in list(root.filters):
            if filt not in before:
                root.removeFilter(filt)


def test_046_resilient_exporter_failure_results_and_flush(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """FAILURE results, shutdown errors, and flush edges stay inside the wrapper."""

    class _Result:
        name = "FAILURE"

        def __int__(self) -> int:
            return 1

    class _Inner:
        def export(self, _batch: Any) -> Any:
            return _Result()

        def shutdown(self) -> None:
            raise RuntimeError("shutdown down")

        def force_flush(self, *_args: Any) -> bool:
            raise RuntimeError("flush down")

    logger = logging.getLogger("test_a2c")
    wrapper = otel_mod._ResilientExporter(_Inner(), logger, kind="spans")
    with caplog.at_level(logging.CRITICAL, logger="test_a2c"):
        assert wrapper._is_failure(_Result()) is True
        assert wrapper.export([]) is not None
        assert wrapper.shutdown() is None
        assert wrapper.force_flush() is False
    assert any("shutdown failed" in r.getMessage() for r in caplog.records)

    class _NoFlush:
        def export(self, _batch: Any) -> int:
            return 0

    no_flush = otel_mod._ResilientExporter(_NoFlush(), logger, kind="spans")
    assert no_flush.force_flush() is True
    assert no_flush._is_failure(object()) is False

    class SpanExportResult(int):
        """Name matches the SDK result type checked by _is_failure."""

    assert wrapper._is_failure(SpanExportResult(1)) is True

    metrics = otel_mod._ResilientExporter(MagicMock(), logger, kind="metrics")
    failure = metrics._failure_result()
    assert getattr(failure, "name", None) == "FAILURE" or failure == 1
    with patch.dict("sys.modules", {"opentelemetry.sdk.trace.export": None}):
        spans = otel_mod._ResilientExporter(MagicMock(), logger, kind="spans")
        assert spans._failure_result() == 1


def test_047_span_outcome_and_http_status_edges() -> None:
    """None spans, attribute errors, and 5xx NoOp status updates do not raise."""
    otel_mod.set_span_outcome(None, "error")
    otel_mod.mark_http_status(None, 200)
    otel_mod.mark_http_status(MagicMock(), "nope")

    class _BoomAttr:
        def set_attribute(self, *_args: Any, **_kwargs: Any) -> None:
            raise RuntimeError("attr")

    otel_mod.set_span_outcome(_BoomAttr(), "success")
    otel_mod.mark_http_status(_BoomAttr(), 200)

    class _BoomStatus:
        def set_attribute(self, *_args: Any, **_kwargs: Any) -> None:
            return None

        def set_status(self, *_args: Any, **_kwargs: Any) -> None:
            raise RuntimeError("status")

        def record_exception(self, *_args: Any, **_kwargs: Any) -> None:
            return None

    otel_mod._enabled = True
    otel_mod.set_span_outcome(_BoomStatus(), "error", RuntimeError("boom"))
    otel_mod.mark_http_status(_BoomStatus(), 503)
    otel_mod._enabled = False
    otel_mod.mark_http_status(MagicMock(), 500)

    class _Batch:
        def __init__(self) -> None:
            self.single: list = []

        def set_attributes(self, _attrs: Any) -> None:
            raise RuntimeError("batch")

        def set_attribute(self, key: str, value: Any) -> None:
            self.single.append((key, value))

    batch = _Batch()
    otel_mod._apply_span_attributes(batch, {"skip": None})
    otel_mod._apply_span_attributes(batch, {"acme.outcome": "ok"})
    assert batch.single == [("acme.outcome", "ok")]


def test_048_instrument_skips_already_wrapped_method() -> None:
    """Methods already marked wrapped are left in place."""

    def already(self: Any) -> int:
        return 1

    already._otel_db_wrapped = True  # type: ignore[attr-defined]

    class Store:
        wrapped = already

        def order_add(self) -> int:
            return 2

    otel_mod.instrument_dbstore_class(Store)
    assert Store.wrapped is already
    assert getattr(Store.order_add, "_otel_db_wrapped", False) is True


def test_049_http_request_span_import_and_context_errors() -> None:
    """SpanKind import failure and a broken span context stay NoOp-safe."""
    import opentelemetry.trace as trace_mod

    saved = trace_mod.SpanKind
    otel_mod._enabled = True
    try:
        del trace_mod.SpanKind
        with otel_mod.http_request_span(
            "GET", "/acme/directory", attributes={"acme.account_name": "acct"}
        ):
            pass
    finally:
        trace_mod.SpanKind = saved

    class _BrokenSpan:
        def set_attribute(self, *_args: Any, **_kwargs: Any) -> None:
            return None

        def set_attributes(self, *_args: Any, **_kwargs: Any) -> None:
            return None

        def get_span_context(self) -> Any:
            raise RuntimeError("ctx")

    @contextmanager
    def _fake_span(*_args: Any, **_kwargs: Any) -> Any:
        yield _BrokenSpan()

    otel_mod._enabled = True
    otel_mod._tracer = object()
    with patch.object(otel_mod, "span", _fake_span):
        with otel_mod.http_request_span("POST", "/acme/order"):
            pass


def test_050_context_helpers_when_import_fails() -> None:
    """Context capture/attach no-op when the context API cannot be imported."""
    import sys

    otel_mod._enabled = True
    import opentelemetry

    saved = sys.modules.get("opentelemetry.context")
    saved_attr = getattr(opentelemetry, "context", None)
    sys.modules["opentelemetry.context"] = None
    try:
        if hasattr(opentelemetry, "context"):
            delattr(opentelemetry, "context")
        assert otel_mod.context_capture() is None
        with otel_mod.context_attach(object()):
            pass
    finally:
        if saved_attr is not None:
            opentelemetry.context = saved_attr
        if saved is None:
            sys.modules.pop("opentelemetry.context", None)
        else:
            sys.modules["opentelemetry.context"] = saved


def test_051_span_context_store_edges() -> None:
    """TTL disable, eviction order, and empty keys."""
    ctx = MagicMock()
    ctx.is_valid = True
    otel_mod._span_contexts.clear()
    otel_mod._span_ctx_ttl_sec = 0
    otel_mod._prune_expired_locked()
    otel_mod._span_contexts["other"] = (ctx, time.monotonic())
    assert otel_mod._first_key_matching(lambda key: key == "other") == "other"
    assert otel_mod._next_eviction_victim() == "other"
    otel_mod._span_contexts.clear()
    otel_mod._span_contexts[f"{otel_mod.ACCOUNT_TIP_PREFIX}acct"] = (
        ctx,
        time.monotonic(),
    )
    otel_mod._span_contexts[otel_mod.SESSION_TIP_KEY] = (ctx, time.monotonic())
    assert otel_mod._next_eviction_victim() == f"{otel_mod.ACCOUNT_TIP_PREFIX}acct"
    otel_mod._span_contexts.clear()
    otel_mod._span_contexts[otel_mod.SESSION_TIP_KEY] = (ctx, time.monotonic())
    otel_mod._span_ctx_max = 0
    otel_mod._evict_overflow_locked()
    assert otel_mod.SESSION_TIP_KEY in otel_mod._span_contexts

    otel_mod._store_span_context("", ctx)
    otel_mod._store_span_context("nonce:bad", MagicMock(is_valid=False))
    assert otel_mod._lookup_span_context("") is None
    otel_mod._pop_span_context("")
    otel_mod._span_contexts["nonce:drop"] = (ctx, time.monotonic())
    otel_mod._drop_nonce_span_contexts_locked()
    assert "nonce:drop" not in otel_mod._span_contexts

    otel_mod._enabled = True
    otel_mod.forget_nonce_span_contexts([None, ""])
    otel_mod._span_contexts["nonce:keep"] = (ctx, time.monotonic())
    otel_mod.forget_nonce_span_contexts(["keep"])
    assert "nonce:keep" not in otel_mod._span_contexts


def test_052_remember_and_continue_span_edges() -> None:
    """Remember/continue tolerate a missing SDK, a null span, and attach errors."""
    import sys

    assert otel_mod._account_name_from_kid("https://ca.example/acme/acct") == ""
    assert otel_mod._path_leaf(None) == ""
    assert otel_mod.is_session_tip_path(None) is False
    assert otel_mod._is_challenge_resource_path("") is False

    otel_mod.remember_span_context("nonce:disabled")
    otel_mod._enabled = True
    otel_mod.remember_span_context("")
    ctx = MagicMock()
    ctx.is_valid = True
    ctx.trace_id = 1
    ctx.span_id = 2
    ctx.trace_flags = 1
    otel_mod._span_contexts["nonce:stored"] = (ctx, time.monotonic())
    saved = sys.modules.get("opentelemetry.trace")
    sys.modules["opentelemetry.trace"] = None
    try:
        import opentelemetry

        trace_attr = getattr(opentelemetry, "trace", None)
        if hasattr(opentelemetry, "trace"):
            delattr(opentelemetry, "trace")
        try:
            otel_mod.remember_span_context("nonce:missing-sdk")
            with otel_mod.continue_span_context("nonce:stored"):
                pass
        finally:
            if trace_attr is not None:
                opentelemetry.trace = trace_attr
    finally:
        if saved is None:
            sys.modules.pop("opentelemetry.trace", None)
        else:
            sys.modules["opentelemetry.trace"] = saved

    otel_mod._enabled = True
    with patch("opentelemetry.trace.get_current_span", return_value=None):
        otel_mod.remember_span_context("nonce:none")
    current = MagicMock()
    current.get_span_context.return_value = MagicMock(is_valid=False)
    with patch("opentelemetry.trace.get_current_span", return_value=current):
        otel_mod.remember_span_context("nonce:invalid")
    otel_mod._tls.request_span_ctx = None
    with patch("opentelemetry.trace.get_current_span", return_value=None):
        otel_mod.remember_request_span_context("nonce:fallback")

    with otel_mod.continue_span_context("nonce:unknown"):
        pass
    with patch("opentelemetry.trace.SpanContext", side_effect=RuntimeError("bad")):
        with otel_mod.continue_span_context("nonce:stored"):
            pass


def test_053_jws_trace_hints_and_setup_key_edges() -> None:
    """Oversized, non-JWS, and session-boundary requests do not chain a tip."""
    import base64

    saved_max = otel_mod._JWS_TRACE_BODY_MAX_BYTES
    otel_mod._JWS_TRACE_BODY_MAX_BYTES = 4
    try:
        assert otel_mod.jws_trace_hints_from_body("abcdef") == ("", "")
    finally:
        otel_mod._JWS_TRACE_BODY_MAX_BYTES = saved_max
    assert otel_mod.jws_trace_hints_from_body('{"protected": 1}') == ("", "")
    assert otel_mod.jws_trace_hints_from_body('{"protected": "%%%"}') == ("", "")

    protected = (
        base64.urlsafe_b64encode(
            b'{"nonce":"abc","kid":"https://ca.example/acme/acct/id1"}'
        )
        .decode()
        .rstrip("=")
    )
    body = '{"protected": "%s", "payload": "", "signature": "x"}' % protected
    assert otel_mod.nonce_trace_key_from_jws_body(body) == "nonce:abc"

    otel_mod._enabled = True
    otel_mod._session_boundary_pending = True
    assert otel_mod.setup_trace_key_for_request("/") == ""
    otel_mod._session_boundary_pending = False
    assert otel_mod.setup_trace_key_for_request("/acme/order/final/finalize") == ""


def _smoke_enabled() -> bool:
    return os.environ.get("A2C_OTEL_CI_SMOKE", "").strip() in ("1", "true", "True")


def _jaeger_services(ui_base: str) -> list[str]:
    url = f"{ui_base.rstrip('/')}/api/services"
    with urllib.request.urlopen(url, timeout=5) as resp:  # noqa: S310 — CI localhost
        payload = json.loads(resp.read().decode("utf-8"))
    data = payload.get("data")
    if isinstance(data, list):
        return [str(x) for x in data]
    return []


def _jaeger_trace_count(ui_base: str, service: str) -> int:
    query = urllib.parse.urlencode({"service": service, "limit": "20"})
    url = f"{ui_base.rstrip('/')}/api/traces?{query}"
    with urllib.request.urlopen(url, timeout=5) as resp:  # noqa: S310 — CI localhost
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


@pytest.mark.skipif(
    not _smoke_enabled(),
    reason="set A2C_OTEL_CI_SMOKE=1 with a reachable OTLP HTTP collector",
)
def test_054_otlp_http_export_appears_in_jaeger() -> None:
    """Export one span via the facade; Jaeger must list the service + a trace."""
    pytest.importorskip("opentelemetry.sdk")
    endpoint = os.environ.get("A2C_OTEL_ENDPOINT", "http://127.0.0.1:4318").strip()
    service = os.environ.get("A2C_OTEL_SERVICE_NAME", "acme2certifier-ci").strip()
    ui = os.environ.get("A2C_OTEL_JAEGER_UI", "http://127.0.0.1:16686").strip()

    # Allow set_*_provider again after other tests / prior init.
    _reset_otel_api_providers()

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
