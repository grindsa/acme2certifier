



# Logging in acme2certifier

A small guide for destinations, format, ACME problem lines, HTTP edge dumps, and redaction.

Config reference table: [acme_srv.md](acme_srv.md) (`Helper` section). Implementation: `acme2certifier/acme_srv/helpers/logging_utils.py`, `Message.prepare_response`.

## Defaults


| Behavior    | Default                                   |
| ----------- | ----------------------------------------- |
| Destination | stderr via `logging.basicConfig`          |
| Level       | `INFO` (`DEFAULT.debug = True` → `DEBUG`) |
| Format      | `%(message)s`                             |
| Syslog      | off until `Helper.syslog_address` is set  |
| File log    | off until `Helper.log_file` is set        |


Stderr always remains. Syslog and file handlers are **additional** destinations when configured.

## Configuration (`[Helper]`)


| Option             | Description                                                                            | Values                                                                                      | Default       |
| ------------------ | -------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------- | ------------- |
| `log_format`       | Python logging format string                                                           | [LogRecord attributes](https://docs.python.org/3/library/logging.html#logrecord-attributes) | `%(message)s` |
| `syslog_address`   | Enables syslog when set. Unix socket or `host:port` (UDP)                              | path or `host:port`                                                                         | None          |
| `syslog_facility`  | Facility when syslog is enabled                                                        | e.g. `user`, `daemon`, `local0`                                                             | `user`        |
| `log_file`         | Enables append-only file logging when set                                              | path/file                                                                                   | None          |
| `log_cert_content` | When `True`, keep certificate / chain PEM in edge log dumps (legacy). Default redacts. | True/False                                                                                  | False         |




### Example: local syslog (preferred for rotation)

```ini
[Helper]
log_format: %(asctime)s - acme2certifier - %(levelname)s - %(message)s
syslog_address: /dev/log
# syslog_facility: user
```

Use `/dev/log` for the local syslog/journald socket. Prefer this when rotation is needed (especially multi-worker WSGI): let rsyslog, syslog-ng, or journald rotate.

### Example: remote syslog (UDP)

```ini
[Helper]
syslog_address: syslog.example.com:514
syslog_facility: local0
```

Python `SysLogHandler` uses **UDP**. The remote listener must accept classic syslog on that port. TCP/TLS syslog is not supported by this option.

### Example: log file

```ini
[Helper]
log_file: /var/log/acme2certifier/acme2certifier.log
```

- Parent directory must already exist and be writable by the service user.
- Plain `FileHandler` (append only); **no in-process rotation**.
- For rotation under multi-worker WSGI, prefer `syslog_address` (or external logrotate on a carefully shared file).



### Example: combined destinations

```ini
[Helper]
log_format: %(asctime)s - acme2certifier - %(levelname)s - %(message)s
syslog_address: /dev/log
log_file: /var/log/acme2certifier/acme2certifier.log
```

All three destinations (stderr, syslog, file) receive the same logger output.

### Redundancy note (stderr + `/dev/log`)

Under **systemd**, stderr is often already captured by journald. Adding `syslog_address: /dev/log` can duplicate events in the journal. Under Apache/nginx/gunicorn that write stderr to a separate app log, syslog is a distinct stream with facility/severity and daemon-managed rotation — usually not redundant.

## What operators see



### ACME problem responses (primary ops signal)

When `Message.prepare_response` builds an ACME problem document (`code >= 400`), it logs **once**:

```text
WARNING: ACME problem code=403 type=urn:ietf:params:acme:error:unauthorized detail=… account=acct-123
ERROR:   ACME problem code=500 type=… detail=… account=None
```


| HTTP code | Level     |
| --------- | --------- |
| 400–499   | `WARNING` |
| ≥ 500     | `ERROR`   |


`detail` is the enriched message (after `Error.enrich_error`). `account=` is set when the call site knows the account name.

This is the greppable line for registration, authn, order, and similar client/server ACME failures that return a problem document.

### HTTP edge dumps (`log_response`)

Django/WSGI views call `log_response` with client address, path, and response dict:


| Outcome                             | Level   | Content                                                                |
| ----------------------------------- | ------- | ---------------------------------------------------------------------- |
| Success (`code` missing or `< 400`) | `INFO`  | Redacted response dump                                                 |
| Failure (`4xx` / `5xx`)             | `DEBUG` | Redacted dump only (avoids duplicating the ACME problem WARNING/ERROR) |


Example success line:

```text
INFO: 203.0.113.1 /acme/neworder {'code': 201, 'header': {'Replay-Nonce': '- modified -'}, 'data': {...}}
```



## Redaction

`log_response` deep-copies the response and redacts before logging:


| Data                                                                            | Redaction                                                   |
| ------------------------------------------------------------------------------- | ----------------------------------------------------------- |
| `header.Replay-Nonce`                                                           | `- modified -`                                              |
| Challenge `token` / challenge list tokens                                       | `- modified -`                                              |
| Certificate download body (`/acme/cert…` path, or PEM with `BEGIN CERTIFICATE`) | `- certificate -` (unless `Helper.log_cert_content = True`) |


Certificate chains are not written to logs by default. Set `log_cert_content: True` to restore the previous behavior of logging the full PEM body. Client responses are unchanged; only the log copy is sanitized.

## Grep / journalctl examples

```bash
# ACME problem summaries
journalctl -u acme2certifier | grep 'ACME problem'

# Client errors only
grep 'ACME problem code=4' /var/log/acme2certifier/acme2certifier.log

# Server faults
grep 'ACME problem code=5' /var/log/…

# Account-scoped
grep 'account=acct-123' /var/log/…
```



## Related config


| Option  | Section   | Effect on logging                                                              |
| ------- | --------- | ------------------------------------------------------------------------------ |
| `debug` | `DEFAULT` | `True` → logger level `DEBUG` (full edge dumps on failures, verbose internals) |

Other modules may emit their own `ERROR`/`CRITICAL` lines (DB failures, enrollment errors, EAB HMAC failures, etc.) independent of the ACME problem path.
