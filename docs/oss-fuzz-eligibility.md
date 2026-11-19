# OSS-Fuzz eligibility — acme2certifier

acme2certifier is an open-source ACME (RFC 8555) protocol proxy that enables
automated certificate issuance for Certificate Authorities that do not speak
ACME natively. It sits on the trust path between ACME clients and enterprise /
public CA backends.

## Why it belongs on OSS-Fuzz

- **Infrastructure role:** Parses untrusted client JWS, CSRs, certificates,
  PKCS#7, and ARI CertIDs before talking to CAs (Dogtag, EJBCA, Microsoft AD CS,
  DigiCert, HashiCorp Vault, OpenXPKI, FreeIPA, and others). Bugs in those
  parsers can affect certificate enrollment pipelines.
- **User / adoption signals:** ~290 GitHub stars, 50+ forks, multi-year release
  history (since 2018), and **~150k Docker Hub pulls** for
  `grindsa/acme2certifier`.
- **Client ecosystem:** Regularly tested against widely deployed ACME clients
  (certbot, lego, acme.sh, cert-manager, Caddy, Traefik, dehydrated, win-acme,
  Posh-ACME).

Primary language: Python. Homepage / main repo:
[https://github.com/grindsa/acme2certifier](https://github.com/grindsa/acme2certifier)
