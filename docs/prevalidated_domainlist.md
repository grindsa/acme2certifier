<!-- markdownlint-disable MD013 -->

<!-- wiki-title Prevalidated Domain List Feature for ACME Authorization -->

# Prevalidated Domain List Feature for ACME Authorization

## Overview

The `prevalidated_domainlist` feature in the ACME Authorization module allows a2c-administrators to specify a list of DNS domains that are considered pre-authorized (prevalidated) for certificate issuance. When enabled, any ACME authorization request for a domain in this list will be automatically marked as valid, bypassing the standard ACME challenge validation process.

This feature is intended for special use cases where certain domains are trusted by policy or infrastructure, and strict validation is not required. **It introduces significant security risks if misused.**

## How It Works

- When a new authorization request is processed, the Authorization class checks if the requested DNS identifier matches any entry in the `prevalidated_domainlist`.

- If a match is found, the authorization status is set to `valid` immediately, and the associated order gets marked as `ready`. ACME Clients following RFC8555 will then skip the challenge validation process and directly finalize the order by submitting a CSR.

- The feature can be enabled in two ways:

  - **Direct Configuration:** By setting the `prevalidated_domainlist` option in the `acme_srv.cfg` configuration file.

  - **ACME Profiling (EAB Profile):** By enabling EAB profiling, which can dynamically provide a `prevalidated_domainlist` for specific accounts via the EAB handler/profile mechanism.

## Enabling the Feature

### 1. Direct Configuration in `acme_srv.cfg`

Add the following to your `[Authorization]` section:

```ini
[Authorization]
prevalidated_domainlist: ["example.com", "trusted.example.org"]
```

- The value must be a valid JSON array of domain names.
- Restart the ACME service after changing the configuration.

### 2. Enabling via ACME Profiling (EAB Profile)

If you use EAB (External Account Binding) profiles, you can provide a `prevalidated_domainlist` for specific accounts. This is controlled by the `eab_profiling` and `eab_handler` options, and the profile data structure must include the domain list:

Example EAB profile snippet:

```json
{
  "keyid_03": {
    "authorization": {
      "prevalidated_domainlist": ["profiled.example.com"]
    }
  }
}
```

When an account with key ID `keyid_03` requests authorization, the specified domains will be approved for that account.

## Security Implications

**Warning: Enabling the prevalidated domain list feature can severely weaken the security of your ACME deployment.**

- Any domain listed in `prevalidated_domainlist` will be issued certificates without proof of control.
- If the list is set globally, any client can obtain certificates for those domains.
- Use this feature only in tightly controlled environments, such as internal PKIs or for legacy migration scenarios.
- Always audit and restrict the list to the minimum set of domains required.
- Consider using EAB profiling to scope prevalidation to specific accounts rather than globally.

## Example Configuration

**acme_srv.cfg:**

```ini
[Authorization]
prevalidated_domainlist = ["internal.example.com", "vpn.example.com"]
```

**EAB Profile JSON:**

```json
{
  "special_kid": {
    "authorization": {
      "prevalidated_domainlist": ["special.example.com"]
    }
  }
}
```

## References

- See the `Authorization` class in `acme_srv/authorization.py` for implementation details.
- For EAB profiling, refer to your EAB handler and profile documentation.

______________________________________________________________________

**Again: Use with extreme caution.** This feature is for advanced administrators who understand the security trade-offs.
