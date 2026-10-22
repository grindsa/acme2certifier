# -*- coding: utf-8 -*-
"""Tests for acme_srv.helpers.otel (Step 4a: NoOp / config gate)."""

from __future__ import annotations

import configparser
import logging
from unittest.mock import MagicMock, patch

import pytest

from acme2certifier.acme_srv.helpers import otel as otel_mod


@pytest.fixture(autouse=True)
def _reset_otel() -> None:
    """Isolate module state between tests."""
    otel_mod._reset_otel_state()
    yield
    otel_mod._reset_otel_state()


def _cfg(**otel_items: str) -> configparser.ConfigParser:
    parser = configparser.ConfigParser()
    if otel_items:
        parser["OpenTelemetry"] = dict(otel_items)
    return parser


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
