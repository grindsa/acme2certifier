# Threat model — acme2certifier

acme2certifier is an ACME v2 server/proxy (RFC 8555 and related extensions). It accepts
certificate lifecycle requests from ACME clients and fulfills them via pluggable CA backends
(`cahandlers`), optional External Account Binding handlers (`eabhandlers`), challenge validators,
and hooks. Prefer findings that affect unauthorized issuance, account takeover, or secret exposure
over packaging or documentation issues.

Project policies in `SECURITY.md` take precedence when they conflict with this summary.

## What this project does and where untrusted input enters

Untrusted input primarily arrives over the public ACME HTTP API (WSGI or Django):

- Directory, new-nonce, new-account, new-order, authorization, challenge, finalize, certificate
  download, revoke-cert, and key-change flows under `acme2certifier/acme_srv/`.
- JWS-protected request bodies, account keys, CSRs, identifiers (DNS/IP), and challenge responses.
- External Account Binding (EAB) credentials and EAB profiling policy (kid-bound CN/SAN/CSR rules).
- Challenge validation paths that contact applicant-controlled HTTP/DNS/TLS-ALPN endpoints
  (`challenge_validators/`) — treat those remote responses as adversarial.
- Configuration and plugin paths (`handler_module`, `eab_handler_module`, `hooks_module`) that may
  load code from the filesystem; treat attacker-controlled config or volume contents as a high-risk
  trust boundary.
- Outbound CA integrations (Vault, EJBCA, Dogtag, DigiCert, Microsoft/impacket, generic ACME
  upstream, OpenSSL local CA, SOAP helpers, etc.): credentials, tokens, and API/RPC replies.
- Housekeeping / schema migration / ARI metadata backfill tools that rewrite certificate rows
  (`dates_update`, serial/AKI migration, `db_update` / `a2c_schema_update`).

## Components that matter most / least

- Most: ACME protocol state machine; JWS/account authentication; order/authz/challenge binding;
  finalize CSR-to-order checks; revoke authorization; EAB and EAB profiling; challenge validators;
  handler/plugin loading; secret handling in config and CA credentials.
- Important: Django/WSGI request plumbing, nonce handling, database-backed account/order state,
  ARI renewal-info parsing and certificate metadata migrations, hardening covered by
  `test/test_hardening.py`.
- Less: CLI maintenance tools under `acme2certifier/tools/` unless they process untrusted input by
  default; example configs that are not loaded in production.
- Out of scope for root-cause ownership: bugs solely inside third-party CA products or upstream
  libraries (cryptography, jwcrypto, Django, impacket, etc.) unless acme2certifier misuses them in a
  way that creates a practical vulnerability. Production packaging under `examples/Docker/` is lower
  priority unless the issue is reachable from the core Python package.

## Hunt units (protocol / logic — scanners miss these)

After every confirmed fix, sweep **sibling callers** of the same helper (do not stop at the first
handler or path that was patched). Prior external reports and incomplete remediations motivate
these units:

### Finalize / CSR binding

- Multi-value subject: every subject CN (and multi-valued RDNs), not only the first
  (`csr_cn_get` / `csr_extra_cn_get` / `csr_bound_names_get`). Extra CNs must fail finalize
  (`badCSR`) for **all** CA handlers, including those that forward the CSR as-is — not only
  openssl/xca that rebuild via `csr_subject_cn_only`.
- Repeated non-CN subject attributes: helpers that collapse subject to a dict (last-wins) used by
  EAB subject checks (`csr_subject_get` / `eab_profile_subject_check`) — e.g. `O=Evil, O=Allowed`
  must not pass a profile that allows only `Allowed`.
- Unbound SAN types and identifier set equality under both `csr_binding_strict` True and False,
  plus TNAuthList orders.
- Fail closed when CSR / subject cannot be parsed.

### Domain allow / block lists

- Every matcher, not only `is_domain_whitelisted`: `list_regex_check` / `wllist_check`,
  openssl/EAB `allowed_domainlist` / `blocked_domainlist`, prevalidation lists.
- `*.example.com` style entries: label-boundary wildcards (GHSA-4g95 family); unanchored
  `re.search` after `*.` → `.` conversion is a known failure mode.
- Wildcard-vs-wildcard and suffix confusion (`*.evilexample.com` vs `*.example.com`).

### Authz / challenge / ownership

- POST paths: resource ownership on order, authorization, challenge, certificate, ARI.
- **Enabled unsafe modes:** with `legacy_acme_get=True`, unauthenticated GET on authorization /
  challenge must not be assumed safe. Hunt whether `handle_get_request` →
  `get_authorization_details` persists token/expiry, creates challenges, runs EAB/prevalidation,
  or JIT dns-persist (state change without ownership). Default-off is not a close-out for this unit.
- Challenge validation timeouts, pending-only start, redirect / SSRF policy for HTTP-01.

### ARI / DB migrations / process environment

- Certificate row updates that omit `issue_uts` / `expire_uts` must not overwrite stored timestamps
  with `0` (WSGI `_certificate_update` historically defaulted missing keys to 0 while preserving
  `renewal_info` / `aki` / `serial` from `exists`).
- Schema / housekeeping updates must not mark `dbversion` complete when migrate or status-seed
  steps failed (WSGI `db_update`, Django `a2c_schema_update`).
- Encoding helpers used by ARI / certid parsing: inconsistent `str` vs `bytes` return types must
  not become unhandled exceptions on renewal-info paths.
- Subprocess / DNS-script env: inject via a copied env for the child; never mutate process-wide
  `os.environ` without restore (Kerberos `KRB5_CONFIG` contexts are a separate, already-scoped
  pattern).

### CA handlers and config

- Handlers that forward CSR bytes vs rebuild subject/SAN — binding gates must cover both.
- EAB profile overlays cannot override script/shell paths; credential overrides remain intentional.
- Plugin / handler module loading from config paths.

## How to exercise it

- Checkout is `/src`. Virtualenv with test dependencies is on `PATH` (`/opt/a2c-venv`).
- Example server config is installed at `acme2certifier/acme_srv/acme_srv.cfg` (copied from
  `examples/acme_srv.cfg` during the image build).
- Unit/regression tests: `pytest` with suites under `test/`. Prefer
  `test/test_hardening.py` for CSR binding / domain-list / gate regressions. Session fixtures may
  bootstrap local OpenSSL test CAs via `tools/make_test_cas.sh` (offline after the image build).
- Prefer minimal pytest reproductions or small standalone scripts against the installed package.
  Do not require live external CAs, Microsoft AD, or production credentials. Bound CPU, memory, and
  runtime; avoid sustained network scanning of third-party infrastructure.
- When validating a candidate, name the affected principal, resource, and security outcome. A
  defense-in-depth gap behind a working control is not a confirmed vulnerability.

## How you rate severity

- Critical: unauthenticated or cross-account unauthorized certificate issuance; private key, CA
  credential, or EAB secret disclosure to a remote attacker; remote code execution via ACME input or
  default plugin loading.
- High: authentication/authorization bypass on ACME account or order objects; CSR/identifier binding
  bypass that yields a cert for a name the account did not prove; practical SSRF or challenge
  confusion that undermines domain control validation; stored secrets written to world-readable logs.
- Medium: availability issues (crash/DoS) from a single request without amplification to cluster-wide
  impact; information leaks of non-secret internal state; integrity bugs in migrations/metadata that
  break ARI or expiry logic; issues requiring uncommon but supported configuration
  (e.g. `legacy_acme_get=True`).
- Low: issues that require deliberately unsafe operator configuration already documented as unsafe,
  or pure defense-in-depth gaps with no demonstrated security impact.

## Anything to leave alone

- Do not report “operator disabled challenge validation” (`challenge_validation_disable`) or similar
  explicit lab/dev toggles as vulnerabilities **when** they are correctly gated by
  `ACME2CERTIFIER_I_KNOW_THE_RISK` (or equivalent documented break-glass). Do report ungated bypasses.
- Do not report missing TLS termination on the ACME listener when TLS is expected at the reverse
  proxy (documented deployment model).
- Do not report dependency CVEs without a concrete reachable path through acme2certifier.
- Do not treat “openssl/xca already strip extra CNs” as closing a multi-CN binding bug for handlers
  that forward the CSR unchanged.
- Patches should target `acme2certifier/` (or tests under `test/`) with a minimal reproducer.
