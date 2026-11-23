<!-- markdownlint-disable MD013 -->

<!-- wiki-title: ML-DSA account keys -->
<!-- wiki-category: Configuration -->

# ML-DSA account keys

acme2certifier accepts ACME account keys using **ML-DSA** (FIPS 204) as specified for JOSE in [RFC 9964](https://www.rfc-editor.org/rfc/rfc9964.html):

| JOSE `alg` | JWK |
| --- | --- |
| `ML-DSA-44` | `kty: AKP`, `alg: ML-DSA-44`, `pub: …` |
| `ML-DSA-65` | `kty: AKP`, `alg: ML-DSA-65`, `pub: …` |
| `ML-DSA-87` | `kty: AKP`, `alg: ML-DSA-87`, `pub: …` |

Supported for **newAccount** and later kid-signed requests (orders, challenges, …) when the Python stack can load `kty: AKP`.

## Dependencies (pip)

[`pyproject.toml`](../pyproject.toml) floors:

- `jwcrypto>=1.5.9` (JOSE ML-DSA / AKP)
- `cryptography>=49` (ML-DSA primitives; wheels ship a capable OpenSSL)

Install or upgrade with pip/wheels so those versions resolve. Official cryptography wheels include OpenSSL ≥ 3.5 with ML-DSA.

## Distro packages (RPM / DEB)

### EL RPM

There are **no** EL cryptography/jwcrypto backports for ML-DSA. Use whatever AppStream/EPEL (or existing companions) provide, or use pip.

### Ubuntu DEB (optional companions)

Stock **Ubuntu 26.04** ships cryptography ~46 and jwcrypto 1.5.6 (no AKP). Companion `.deb`s for a2c are in [grindsa/sbom `deb-repo/DEBs/ub26.04/`](https://github.com/grindsa/sbom/tree/main/deb-repo/DEBs/ub26.04):

| Package | Notes |
| --- | --- |
| [python3-cryptography_49.0.0-2ubuntu1grindsa_amd64.deb](https://github.com/grindsa/sbom/raw/main/deb-repo/DEBs/ub26.04/python3-cryptography_49.0.0-2ubuntu1grindsa_amd64.deb) | cryptography **49** (amd64) |
| [python3-cryptography_49.0.0-2ubuntu1grindsa_arm64.deb](https://github.com/grindsa/sbom/raw/main/deb-repo/DEBs/ub26.04/python3-cryptography_49.0.0-2ubuntu1grindsa_arm64.deb) | cryptography **49** (arm64) |
| [python3-jwcrypto_1.5.9-1grindsa_all.deb](https://github.com/grindsa/sbom/raw/main/deb-repo/DEBs/ub26.04/python3-jwcrypto_1.5.9-1grindsa_all.deb) | jwcrypto **1.5.9** (AKP; `Architecture: all`) |

- **Support expectation:** built and tested for a2c only. Third-party use is fine if that limitation is understood.
- Official a2c container images install these companions automatically. For manual DEB installs, see [DEB installation](install_deb.md).

### If the stack lacks AKP

Clients that register with an ML-DSA key receive:

- `type`: `urn:ietf:params:acme:error:badPublicKey`
- `detail`: `JWK key type "AKP" (alg "ML-DSA-…") is not supported by this ACME server`

## Clients

[lego](https://go-acme.github.io/lego/) v5.7+ maps `--key-type MLDSA44|MLDSA65|MLDSA87` to JOSE `ML-DSA-44|65|87`. See [Example commands for acme clients](acme-clients.md#lego).

## Limitations

- Certificate / CSR public keys remain whatever the CA handler and underlying CA accept; a2c does not specially filter ML-DSA leaf keys.

## Key rollover

ACME `keyChange` updates both the stored account `jwk` and `alg` fields (from the inner JWS protected `alg`, or `jwk.alg` for AKP). Cross-algorithm rollovers (RSA↔EC↔ML-DSA), including lego `accounts keyrollover --key-type MLDSA65`, are supported.
