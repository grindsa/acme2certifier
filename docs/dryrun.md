# Dry Run Mode

## Overview

The **dry run mode** is a simulation feature that allows operators and ACME clients to test their certificate enrollment workflow without actually issuing certificates or storing anything in the CA or the database.

When dry run mode is active, acme2certifier performs the full ACME protocol flow — including order creation, domain authorization, and CSR validation — but **stops before contacting the CA** and returns an error response instead of a certificate. This makes it easy to verify that clients, profiles, and domain configurations are correct without generating real certificates.

Typical use cases include:

- Validating ACME client configuration during onboarding
- Testing that a custom profile or domain policy is accepted
- Verifying end-to-end connectivity and protocol compliance in a staging environment
- Allowing ACME clients to self-test without requesting a real certificate

---

## How It Works

When an ACME client submits a certificate order and the dry run mode is enabled (globally or via profile), the following happens:

1. The order is created and authorizations are issued normally.
2. The client completes the ACME challenges normally.
3. The CSR is submitted and validated (domain names, SANs, profile, etc.) normally.
4. **Instead of forwarding the CSR to the CA**, acme2certifier returns an `unauthorized` error with the detail message:

   ```
   Dry run mode - enrollment skipped
   ```

5. No certificate is stored in the database and nothing is sent to the CA backend.

The full ACME protocol exchange succeeds up to the finalization step, so any errors detected before that point (e.g. invalid CSR, unknown profile, domain not allowed) are reported as usual.

---

## Configuration

Dry run mode is configured in `acme_srv.cfg` under the `[DEFAULT]` section.

### Option 1 – Global dry run (all requests)

Set `dryrun = True` to enable dry run mode for **every** certificate enrollment request, regardless of client or profile:

```ini
[DEFAULT]
dryrun = True
```

All enrollment requests will be intercepted after CSR validation and return the dry run error. No certificates will be issued.

To disable dry run mode, set the option to `False` (the default):

```ini
[DEFAULT]
dryrun = False
```

### Option 2 – Profile-based dry run (per-request control)

Set `dryrun = profile` to activate dry run mode only when an ACME client includes a specific **ACME profile** in its order request (as defined in [draft-aaron-acme-profiles](https://datatracker.ietf.org/doc/draft-aaron-acme-profiles/)).

You must also specify the profile name that triggers dry run mode using the `dryrun_profile` parameter:

```ini
[DEFAULT]
dryrun = profile
dryrun_profile = dry-run
```

With this configuration:

- Requests that include the profile `dry-run` are processed in dry run mode — the CSR is validated but no certificate is issued.
- Requests that include any other profile, or no profile at all, are processed normally and receive real certificates.

> **Note:** If `dryrun = profile` is set but `dryrun_profile` is missing or empty, acme2certifier will log a warning:
>
> ```
> Dryrun profile name not set in configuration, please set dryrun_profile parameter
> ```
>
> Dry run mode will not be activated for any request in this case.

---

## Configuration Reference

The following parameters are available in the `[DEFAULT]` section of `acme_srv.cfg`:

| Parameter        | Description                                                                                                                                                                      | Values              | Default |
| :--------------- | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :------------------ | :------ |
| `dryrun`         | Enables dry run mode. `True` activates it globally. `profile` activates it only when the ACME client submits the profile name defined by `dryrun_profile`. `False` disables it. | `True`/`False`/`profile` | `False` |
| `dryrun_profile` | The ACME profile name that triggers dry run mode. Only evaluated when `dryrun = profile`.                                                                                        | string              | (none)  |

---

## Example Configurations

### Always-on dry run (testing / staging environment)

```ini
[DEFAULT]
dryrun = True
```

All clients that connect to this acme2certifier instance will never receive a real certificate. The full ACME exchange is simulated.

### Client-controlled dry run via profile

```ini
[DEFAULT]
dryrun = profile
dryrun_profile = dry-run
```

ACME clients can trigger a dry run by requesting the profile `dry-run` in their order. Clients that do not send this profile receive real certificates.

Example using [lego](https://go-acme.github.io/lego/):

```bash
# Dry run request – no certificate issued
lego --server https://acme-srv --email user@example.com \
     -d example.com --http run --profile dry-run

# Normal request – real certificate issued
lego --server https://acme-srv --email user@example.com \
     -d example.com --http run
```

---

## Log Messages

The following log entries can help confirm that dry run mode is working as expected:

| Log message | Meaning |
| :---------- | :------ |
| `Helper.config_dryrun_load() ended with: True/None` | Global dry run mode is enabled. |
| `Certificate._validate_csr_against_order(): enabling dryrun mode for profile: <name>` | Profile-based dry run has been triggered for this request. |
| `Dry run mode enabled - skipping enrollment and database storage` | The enrollment step has been skipped for this request. |
| `Dryrun profile name not set in configuration, please set dryrun_profile parameter` | `dryrun = profile` is configured but `dryrun_profile` is missing. |

---

## Interaction with Other Features

- **Profile support:** Profile-based dry run requires that the ACME client submits a profile attribute in the order. If no profiles are configured in the `[Order]` section, the dry run profile is still accepted and stored on the order without enforcing normal profile validation.
- **Async mode:** Dry run mode is compatible with [asynchronous mode](async_mode.md). The enrollment step is still skipped and the dry run error is returned at finalization time.
- **CSR validation:** All CSR checks (domain names, SANs, allowed domain lists, etc.) are performed before the dry run intercept. A malformed or policy-violating CSR will be rejected before reaching the dry run check.
