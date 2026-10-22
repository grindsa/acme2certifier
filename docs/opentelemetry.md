<!-- markdownlint-disable MD013 -->

<!-- wiki-title: OpenTelemetry (experimental) -->
<!-- wiki-category: Configuration -->

# OpenTelemetry support (experimental)

Optional, **config-gated** export of traces and metrics via **OTLP HTTP**. Logging remains the primary ops surface ([Logging](logging.md)); OpenTelemetry is additive.

**Status:** experimental. Span/metric names and config knobs may change. Enabling logs a one-line `WARNING` at ACME HTTP boot.

## Install

Requires **Python ≥ 3.8** (OpenTelemetry SDK). Core acme2certifier without this extra still supports older Pythons.

```bash
pip install 'acme2certifier[otel]'
```

Use a dedicated/disposable virtualenv for the extra; do not require OTEL packages for a normal install. Distro DEB/RPM packages do **not** pull OTEL dependencies — install the PyPI extra (or equivalent wheels) only where you enable the feature.

If `opentelemetry_support` is `True` but packages are missing, boot continues with a NoOp facade and an error is logged.

## Configuration (`[OpenTelemetry]`)

| Option | Description | Values | Default |
| ------ | ----------- | ------ | ------- |
| `opentelemetry_support` | Master switch | True/False | False |
| `endpoint` | OTLP HTTP base URL (traces use `/v1/traces`, metrics `/v1/metrics`) | URL | `http://127.0.0.1:4318` |
| `protocol` | Export protocol (v1: HTTP/protobuf only) | `http/protobuf` | `http/protobuf` |
| `service_name` | OTEL resource `service.name` | string | `acme2certifier` |
| `sample_ratio` | Trace sampling ratio in \[0.0, 1.0\] | float | `1.0` |

### Example

```ini
[OpenTelemetry]
opentelemetry_support: True
endpoint: http://127.0.0.1:4318
protocol: http/protobuf
service_name: acme2certifier
sample_ratio: 1.0
```

Restart acme2certifier after changing the file. Init runs from the shared ACME HTTP boot path (`acme_http_boot`), used by classic WSGI and Django ACME views.

## What is instrumented (v1)

| Spans | Metrics |
| ----- | ------- |
| `acme.challenge.validate` | `acme.challenge.validation` (counter; type + outcome) |
| `acme.certificate.enroll` | `acme.issuance.duration` (histogram; outcome) |
| `acme.ca_handler.call` (enroll / revoke) | `acme.ca_handler.call` (counter; handler + operation + outcome) |
| | `acme.auth.failure` (counter; jws / eab) |

Common attributes (when available): `acme.challenge_type`, `acme.cahandler`, `acme.ca_operation`, `acme.order_name`, `acme.account_name`, `acme.outcome`.

**Not in v1:** Prometheus scrape endpoint, log correlation bridge, Django/DB auto-instrumentation, per-handler deep spans. Light DB spans are a planned follow-up.

## Lab smoke (Jaeger)

1. Run Jaeger (OTLP HTTP on `:4318`, UI on `:16686`) — any OTLP-compatible backend works; a common self-hosted choice is `jaegertracing/all-in-one` with `COLLECTOR_OTLP_ENABLED=true`.
2. Install `[otel]`, set `[OpenTelemetry]` as above (`endpoint` pointing at that collector), restart a2c.
3. Exercise challenge validation and/or enrollment.
4. Open the Jaeger UI → service **`acme2certifier`** (or your `service_name`) → Find Traces.

If a2c and Jaeger run on different hosts, use the collector’s reachable address (for example `http://192.168.64.3:4318`). On the same host, `http://127.0.0.1:4318` is enough.

## Related

- Config table: [acme_srv.md](acme_srv.md) (`OpenTelemetry` section)
- Logging (primary): [logging.md](logging.md)
