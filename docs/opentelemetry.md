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
| `endpoint` | OTLP HTTP base URL (traces use `/v1/traces`, metrics `/v1/metrics` when enabled) | URL | `http://127.0.0.1:4318` |
| `protocol` | Export protocol (v1: HTTP/protobuf only) | `http/protobuf` | `http/protobuf` |
| `service_name` | OTEL resource `service.name` | string | `acme2certifier` |
| `sample_ratio` | Trace sampling ratio in \[0.0, 1.0\] | float | `1.0` |
| `metrics_export` | Export OTLP metrics to `{endpoint}/v1/metrics`. Leave `False` for Jaeger-only (many all-in-one builds have no metrics endpoint → periodic 404s). | True/False | False |

### Example

```ini
[OpenTelemetry]
opentelemetry_support: True
endpoint: http://127.0.0.1:4318
protocol: http/protobuf
service_name: acme2certifier
sample_ratio: 1.0
metrics_export: False
```

Restart acme2certifier after changing the file. Init runs from the shared ACME HTTP boot path (`acme_http_boot`), used by classic WSGI and Django ACME views.

## What is instrumented (v1)

| Spans | Metrics |
| ----- | ------- |
| `acme.http.request` (root per HTTP request; Django middleware / classic WSGI) | |
| `acme.nonce.check` / `acme.nonce.issue` | |
| `acme.jws.verify` | `acme.auth.failure` (counter; jws / eab) |
| `acme.account.create` | |
| `acme.account.query` (`onlyreturnexisting` / POST empty payload) | |
| `acme.order.create` | |
| `acme.authorization.create` | |
| `acme.challenge.create` | |
| `acme.challenge.validate` | `acme.challenge.validation` (counter; type + outcome) |
| `acme.certificate.enroll` | `acme.issuance.duration` (histogram; outcome) |
| `acme.ca_handler.call` (enroll / revoke) | `acme.ca_handler.call` (counter; handler + operation + outcome) |

**Enrollment-session single trace:** Django middleware and classic WSGI share `acme_traced_request()`:

- **POSTs:** continue via a *remembered* `nonce:<Replay-Nonce>` (key consumed after continue). Unused keys are dropped on nonce expiry housekeeping, on session-boundary consume, and by a **TTL + max-size** cap on the in-process store (default TTL 86400s / max 1024 entries). If that nonce is not in the store, fall back to an **account tip** (when the JWS `kid` is known) or the **global session tip**.
- **Same-session GETs** (`/`, `directory`, `newNonce`, ARI `renewal-info/…`): continue the tip (`/` → `directory` stay one tree).
- **Session boundary:** after a successful enroll, the next `/` or `directory` starts a **new** root (and clears leftover `nonce:` keys).
- Tip/nonce remember always binds to the active `acme.http.request` (`span.kind=SERVER`), so the tree is a chain of HTTP requests with work nested underneath.

**Limits (experimental):** Tip/nonce state is **in-process only** (not shared across workers). The **global** tip is last-writer-wins for anonymous GETs on one worker (two clients hitting `/`/`directory` concurrently can interleave). After requests carry an account `kid`, each account keeps its **own** tip so authenticated hops stay separated. Challenge validation and certificate enrollment run in `ThreadWithReturnValue` so child spans keep the enrollment-session context.

Common attributes (when available): `http.method`, `http.route`, `http.status_code`, `acme.challenge_type`, `acme.identifier_type`, `acme.cahandler`, `acme.ca_operation`, `acme.order_name`, `acme.account_name`, `acme.outcome`.

**Span status (Jaeger error flag):** OTEL `StatusCode.ERROR` is set only for server-side failures — `acme.outcome=error` (exceptions / unexpected internal failures) and HTTP `5xx` on `acme.http.request`. ACME protocol rejects stay `acme.outcome=failure` (or `skipped`) without ERROR status.

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
