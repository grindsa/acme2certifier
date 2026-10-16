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

## Components that matter most / least

- Most: ACME protocol state machine; JWS/account authentication; order/authz/challenge binding;
  finalize CSR-to-order checks; revoke authorization; EAB and EAB profiling; challenge validators;
  handler/plugin loading; secret handling in config and CA credentials.
- Important: Django/WSGI request plumbing, nonce handling, database-backed account/order state,
  hardening covered by `test/test_hardening.py`.
- Less: CLI maintenance tools under `acme2certifier/tools/` unless they process untrusted input by
  default; example configs that are not loaded in production.
- Out of scope for root-cause ownership: bugs solely inside third-party CA products or upstream
  libraries (cryptography, jwcrypto, Django, impacket, etc.) unless acme2certifier misuses them in a
  way that creates a practical vulnerability. Production packaging under `examples/Docker/` is lower
  priority unless the issue is reachable from the core Python package.

## How to exercise it

- Checkout is `/src`. Virtualenv with test dependencies is on `PATH` (`/opt/a2c-venv`).
- Example server config is installed at `acme2certifier/acme_srv/acme_srv.cfg` (copied from
  `examples/acme_srv.cfg` during the image build).
- Unit/regression tests: `pytest` with suites under `test/`. Session fixtures may bootstrap local
  OpenSSL test CAs via `tools/make_test_cas.sh` (offline after the image build).
- Prefer minimal pytest reproductions or small standalone scripts against the installed package.
  Do not require live external CAs, Microsoft AD, or production credentials. Bound CPU, memory, and
  runtime; avoid sustained network scanning of third-party infrastructure.

## How you rate severity

- Critical: unauthenticated or cross-account unauthorized certificate issuance; private key, CA
  credential, or EAB secret disclosure to a remote attacker; remote code execution via ACME input or
  default plugin loading.
- High: authentication/authorization bypass on ACME account or order objects; CSR/identifier binding
  bypass that yields a cert for a name the account did not prove; practical SSRF or challenge
  confusion that undermines domain control validation; stored secrets written to world-readable logs.
- Medium: availability issues (crash/DoS) from a single request without amplification to cluster-wide
  impact; information leaks of non-secret internal state; issues requiring uncommon but supported
  configuration.
- Low: issues that require deliberately unsafe operator configuration already documented as unsafe,
  or pure defense-in-depth gaps with no demonstrated security impact.

## Anything to leave alone

- Do not report “operator disabled challenge validation” (`challenge_validation_disable`) or similar
  explicit lab/dev toggles as vulnerabilities.
- Do not report missing TLS termination on the ACME listener when TLS is expected at the reverse
  proxy (documented deployment model).
- Do not report dependency CVEs without a concrete reachable path through acme2certifier.
- Patches should target `acme2certifier/` (or tests under `test/`) with a minimal reproducer.
