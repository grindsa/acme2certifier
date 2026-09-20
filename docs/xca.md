<!-- markdownlint-disable MD013 -->

<!-- wiki-title: CA Handler for XCA -->
<!-- wiki-category: CA Handlers -->

# Support for XCA-Based Certificate Authorities

This handler allows **acme2certifier** to store **certificates** and **requests** in an [XCA](https://github.com/chris2511/xca/) database — either a local SQLite `.xdb` file or the same [MySQL/MariaDB or PostgreSQL](https://www.hohnstaedt.de/xca/index.php/documentation/remote-databases) database the XCA GUI already uses.

It also supports fetching **enrollment templates** from XCA and applying them to **certificate signing requests (CSRs)**.

This is the **XCA schema** (`items`, `certs`, `view_certs`, …), not Django ACME storage. For ACME account/order data see [External database support](external_database_support.md).

## Prerequisites

To use this handler, you need:

- A **preconfigured XCA database** with **CA certificates** and **keys** imported. acme2certifier does **not** create the XCA schema; initialize the store with the XCA GUI or CLI first.
- The **Internal Name** of the Certificate Authority, as shown in the XCA application.

![xca-ca-list](xca-ca-list.png)

## Configuration

### 1. Configure the CA Handler

Set `handler_module` in `acme_srv.cfg` (do not copy handler files into `acme_srv/`):

```ini
[CAhandler]
handler_module: acme2certifier.cahandlers.xca_ca_handler
```

See [Upgrading](upgrading.md).

### 2. Ensure Database Accessibility (SQLite)

- Place the **XCA database** in a directory accessible to **acme2certifier**.
- Set ownership to the user running the web services.
- Restrict permissions to prevent unauthorized access.

For MySQL/MariaDB or PostgreSQL, skip this step and use the [remote database](#remote-database-mysqlmariadb-or-postgresql) settings below.

### 3. Modify the Server Configuration

Edit the **server configuration** (`/acme_srv/acme_srv.cfg`) and add the following parameters:

```ini
[CAhandler]
handler_module: acme2certifier.cahandlers.xca_ca_handler
xdb_file: acme_srv/xca/acme2certifier.xdb
xdb_permission: 600
issuing_ca_name: sub-ca
issuing_ca_key: sub-ca-key
passphrase_variable: XCA_PASSPHRASE
ca_cert_chain_list: ["root-ca"]
template_name: XCA template to be applied to CSRs
```

### Parameter Explanations

- **xdb_file** – Path to the **XCA SQLite database** (`.xdb`). Mutually exclusive with a remote `xdb_engine`.
- **xdb_permission** *(optional)* – **File permissions** for the SQLite XCA database (default: `660`). Ignored for remote engines.
- **issuing_ca_name** – **XCA name** of the CA used for certificate issuance.
- **issuing_ca_key** – **XCA name** of the key used to sign certificates. If not set, it defaults to the value in `issuing_ca_name`.
- **passphrase_variable** *(optional)* – Environment variable containing the **passphrase** to decrypt the CA key (overridden if `passphrase` is set). This is **not** the SQL login password.
- **passphrase** *(optional)* – **Passphrase** to decrypt the private CA key stored in XCA.
- **ca_cert_chain_list** *(optional)* – List of **root and intermediate CA certificates** to be included in the bundle returned to an ACME client (**do not include the issuing CA certificate**).
- **template_name** *(optional)* – Name of the **XCA template** to be applied during certificate issuance.
- **allowed_domainlist** *(optional)* – List of allowed **domain names** for enrollment (JSON format). Example: `["bar.local", "bar.foo.local"]` (default: `[]`).
- **enrollment_config_log** *(optional)* – Enable logging of enrollment parameters (default: `False`).
- **enrollment_config_log_skip_list** *(optional)* – List of **enrollment parameters** to exclude from logs (JSON format). Example: `["parameter1", "parameter2"]` (default: `[]`).

## Remote database (MySQL/MariaDB or PostgreSQL)

Use this when the [XCA GUI runs off-server](https://www.hohnstaedt.de/xca/index.php/documentation/remote-databases) against a shared SQL database. acme2certifier talks to the **same** XCA tables; it does not create them.

Install the matching Python driver if it is not already present (Django PostgreSQL already ships `psycopg2`; Django MySQL/`mysqlclient` is **not** a substitute for PyMySQL):

```bash
pip install PyMySQL
# or
pip install psycopg2-binary
```

Do **not** set `xdb_file` together with a remote engine.

```ini
[CAhandler]
handler_module: acme2certifier.cahandlers.xca_ca_handler
xdb_engine: mysql
xdb_host: 10.1.0.1
xdb_port: 3306
xdb_name: xca
xdb_user: youruser
xdb_password_variable: XCA_DB_PASSWORD
xdb_table_prefix:
xdb_ssl_ca: /path/cacert.pem
xdb_ssl_mode: verify-ca
issuing_ca_name: sub-ca
issuing_ca_key: sub-ca-key
passphrase_variable: XCA_PASSPHRASE
ca_cert_chain_list: ["root-ca"]
```

PostgreSQL example (`xdb_engine: postgresql`; `postgres` and `pgsql` are accepted aliases). `mariadb` is treated as `mysql`.

### Remote parameters

- **xdb_engine** – `sqlite` (default), `mysql`, `mariadb`, or `postgresql`.
- **xdb_host** / **xdb_port** / **xdb_name** / **xdb_user** – SQL connection. Host, database name, and user are required for remote engines.
- **xdb_password_variable** / **xdb_password** – SQL login password (same `*_variable` overwrite rules as `passphrase`). Distinct from the CA-key **passphrase**.
- **xdb_table_prefix** *(optional)* – XCA table prefix (`user@host/TYPE:dbname#prefix` in the XCA dialog). Concatenated in front of every XCA table and view (`items` → `prefixitems`, `view_certs` → `prefixview_certs`). Put an underscore in the value if you want one.
- **xdb_ssl_ca** / **xdb_ssl_mode** *(optional)* – TLS CA file and mode (`verify-ca` / `verify-full` for MySQL hostname checks; PostgreSQL `sslmode` values such as `require`, `verify-ca`, `verify-full`).

XCA connection-dialog mapping: user → `xdb_user`, host → `xdb_host`, `QMYSQL`/`QPSQL` → `mysql`/`postgresql`, database → `xdb_name`, `#prefix` → `xdb_table_prefix`.

Do not store Django ACME tables and an unprefixed XCA schema in the same database; use `xdb_table_prefix` (or a dedicated database) if they share a server.

### Importing an existing SQLite `.xdb`

Follow [XCA Remote Databases](https://www.hohnstaedt.de/xca/index.php/documentation/remote-databases), with one extra step on SQLite 3.44+: `.dump` emits `unistr()` / `char(10)`, which MariaDB/MySQL and PostgreSQL do not accept as-is.

Prefer a newer sqlite CLI (`sqlite3 --escape off your.xdb .dump`) or dump via Python so strings keep literal newlines:

```bash
python3 .github/scripts/xca_sqlite_dump.py --dialect mysql your.xdb -o dump.sql
# or --dialect postgresql
```

Then import:

```bash
mariadb -u root -p xca < dump.sql
```

`--escape off` writes control characters (newlines in item comments) as literal bytes instead of `unistr('\u000a')`. If a dump already contains `unistr()`, replace those calls before import — `\u000a` is a newline (`CHAR(10)` in MariaDB, `chr(10)` in PostgreSQL).

## Template Support

**Template support was introduced in v0.13** and applies the following parameters during certificate issuance:

- **Certificate validity** (`validN`/`validM`)
- **Basic Constraints** (`ca`)
- **Key Usage Attributes** (`keyUse`) – Defaults to:
  `digitalSignature, nonRepudiation, keyEncipherment, keyAgreement` if not specified.
- **Extended Key Usage Attributes** (`eKeyUse`)
- **CRL Distribution Points** (`crlDist`)
- **Enforcement of DN Attributes:**
  - **OU**: Organizational Unit
  - **O**: Organization
  - **L**: Locality
  - **S**: State or Province Name
  - **C**: Country Name

## Enabling EAB Profiling

This handler supports the **EAB profiling feature**, which allows:

- **Custom enrollment configurations per ACME account**.
- **Restrictions on CN and SANs in the CSR**.

To enable **EAB profiling**, modify `acme_srv.cfg`:

```ini
[EABhandler]
eab_handler_module: acme2certifier.eabhandlers.kid_profile_handler
key_file: <profile_file>
eab_profiling: True

[CAhandler]
...
```

### Example Key File (Used in Regression Testing)

```json
{
  "keyid_00": {
    "hmac": "V2VfbmVlZF9hbm90aGVyX3ZlcnkfX2xvbmdfaG1hY190b19jaGVja19lYWJfZm9yX2tleWlkXzAwX2FzX2xlZ29fZW5mb3JjZXNfYW5faG1hY19sb25nZXJfdGhhbl8yNTZfYml0cw",
    "cahandler": {
      "template_name": ["template", "acme"],
      "allowed_domainlist": ["www.example.com", "www.example.org", "*.acme"],
      "unknown_key": "unknown_value"
    }
  },
  "keyid_01": {
    "hmac": "YW5vdXRoZXJfdmVyeV9sb25nX2htYWNfZm9yX2tleWlkXzAxX3doaWNoIHdpbGxfYmUgdXNlZF9kdXJpbmcgcmVncmVzc2lvbg",
    "cahandler": {
      "template_name": "template",
      "allowed_domainlist": ["www.example.com", "www.example.org", "*.acme"],
      "issuing_ca_name": "root-ca",
      "issuing_ca_key": "root-ca"
    }
  },
  "keyid_02": {
    "hmac": "dGhpc19pc19hX3ZlcnlfbG9uZ19obWFjX3RvX21ha2Vfc3VyZV90aGF0X2l0c19tb3JlX3RoYW5fMjU2X2JpdHM",
    "cahandler": {
      "allowed_domainlist": ["www.example.com", "www.example.org"]
    }
  },
  "keyid_03": {
    "hmac": "YW5kX2ZpbmFsbHlfdGhlX2xhc3RfaG1hY19rZXlfd2hpY2hfaXNfbG9uZ2VyX3RoYW5fMjU2X2JpdHNfYW5kX3Nob3VsZF93b3Jr"
  }
}
```

## Final Notes

Enjoy enrolling and revoking certificates! 🚀
