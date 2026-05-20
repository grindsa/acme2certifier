<!-- markdownlint-disable MD013 -->

<!-- wiki-title Prevalidated Domain/IP/Email List Features for ACME Authorization -->

# Prevalidated Domain, IP, and Email List Features for ACME Authorization

## Overview

The ACME Authorization module supports three prevalidation features:

- `prevalidated_domainlist`: List of DNS domains considered pre-authorized for certificate issuance.
- `prevalidated_iplist`: List of IP addresses or CIDR ranges considered pre-authorized for certificate issuance.
- `prevalidated_emaillist`: List of email addresses considered pre-authorized for certificate issuance (for S/MIME or email identifier ACME flows).

When enabled, any ACME authorization request for a matching domain, IP, or email will be automatically marked as valid, bypassing the standard ACME challenge validation process.

**These features introduce significant security risks if misused.**

## How It Works

- When a new authorization request is processed, the Authorization class checks if the requested identifier matches any entry in the corresponding prevalidated list.
  - For DNS identifiers, `prevalidated_domainlist` is checked.
  - For IP identifiers, `prevalidated_iplist` is checked.
  - For email identifiers, `prevalidated_emaillist` is checked.
- If a match is found, the authorization status is set to `valid` immediately, and the associated order gets marked as `ready` (if order info is available).
- ACME Clients following RFC8555 will then skip the challenge validation process and directly finalize the order by submitting a CSR.

The feature can be enabled in two ways:

- **Direct Configuration:** By setting the relevant option in the `acme_srv.cfg` configuration file.
- **ACME Profiling (EAB Profile):** By enabling EAB profiling, which can dynamically provide prevalidated lists for specific accounts via the EAB handler/profile mechanism.

## Enabling the Features

### 1. Direct Configuration in `acme_srv.cfg`

Add the following to your `[Authorization]` section as needed:

```ini
[Authorization]
prevalidated_domainlist = ["example.com", "trusted.example.org"]
prevalidated_iplist = ["192.168.1.0/24", "10.0.0.1"]
prevalidated_emaillist = ["admin@example.com", "user@trusted.org"]
```

- Each value must be a valid JSON array (domains, IPs/CIDRs, or email addresses).
- Restart the ACME service after changing the configuration.

### 2. Enabling via ACME Profiling (EAB Profile)

If you use EAB (External Account Binding) profiles, you can provide any of the prevalidated lists for specific accounts. This is controlled by the `eab_profiling` and `eab_handler` options, and the profile data structure must include the relevant lists:

Example EAB profile snippet:

```json
{
  "keyid_03": {
    "authorization": {
      "prevalidated_domainlist": ["profiled.example.com"],
      "prevalidated_iplist": ["10.10.0.0/16", "203.0.113.5"],
      "prevalidated_emaillist": ["profiled@example.com"]
    }
  }
}
```

When an account with key ID `keyid_03` requests authorization, the specified domains, IPs, or emails will be approved for that account.

## Security Implications

**Warning: Enabling any prevalidated list feature can severely weaken the security of your ACME deployment.**

- Any identifier listed in a prevalidated list will be issued certificates without proof of control.
- If the lists are set globally, any client can obtain certificates for those identifiers.
- Use these features only in tightly controlled environments, such as internal PKIs or for legacy migration scenarios.
- Always audit and restrict the lists to the minimum set of identifiers required.
- Consider using EAB profiling to scope prevalidation to specific accounts rather than globally.

## Example Configuration

**acme_srv.cfg:**

```ini
[Authorization]
prevalidated_domainlist = ["internal.example.com", "vpn.example.com"]
prevalidated_iplist = ["10.0.0.0/8", "203.0.113.5"]
prevalidated_emaillist = ["admin@internal.example.com", "alerts@vpn.example.com"]
```

**EAB Profile JSON:**

```json
{
  "special_kid": {
    "authorization": {
      "prevalidated_domainlist": ["special.example.com"],
      "prevalidated_iplist": ["172.16.0.0/12"],
      "prevalidated_emaillist": ["special@special.example.com"]
    }
  }
}
```

## References

- See the `Authorization` class in `acme_srv/authorization.py` for implementation details.
- For EAB profiling, refer to your EAB handler and profile documentation.

______________________________________________________________________

**Again: Use with extreme caution.** These features are for advanced administrators who understand the security trade-offs.
