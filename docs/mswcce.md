<!-- markdownlint-disable MD013 -->

<!-- wiki-title: CA Handler for Microsoft Windows Client Certificate Enrollment Protocol (MS-WCCE) -->
<!-- wiki-category: CA Handlers -->

# CA Handler formerly named MS-WCCE

This page is retained for compatibility with older links and documentation.

The handler historically marketed as **MS-WCCE** enrolls certificates via the **MS-ICPR** RPC interface (not DCOM MS-WCCE). Canonical documentation and configuration live here:

- **[MS-ICPR CA handler](msicpr.md)**
- Preferred `handler_module`: `acme2certifier.cahandlers.msicpr_ca_handler`

The previous module path remains a deprecated alias:

```ini
[CAhandler]
handler_module: acme2certifier.cahandlers.mswcce_ca_handler
```

Prefer:

```ini
[CAhandler]
handler_module: acme2certifier.cahandlers.msicpr_ca_handler
```

## Note on RPC Port Requirements

MS-ICPR does not honor static DCOM "CertSrv Request" endpoints. When TCP RPC is used, dynamic high ports from the RPC Endpoint Mapper apply in addition to TCP 445 (and typically TCP 135 for endpoint mapping). Details: [msicpr.md](msicpr.md#note-on-rpc-port-requirements).
