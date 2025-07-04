<!-- markdownlint-disable MD013 -->

<!-- wiki-title: External Account Binding -->

# External Account Binding

External Account Binding (EAB) allows an ACME account to use authorizations granted to an external, non-ACME account. This enables `acme2certifier` to handle issuance scenarios that cannot yet be fully automated, such as issuing Extended Validation (EV) certificates.

To enable EAB, the Certificate Authority (CA) operator must provide both the ACME client and `acme2certifier` with a Key Identifier (`kid`) and a MAC key (`mac_key`). These credentials authenticate `NewAccount` requests.

`kid` and `mac_key` are loaded into `acme2certifier` via a plugin-based mechanism. By default, two plugins are available in the `example/eab_handler` directory.

Key identifiers are included in reports generated by the [Housekeeping](housekeeping.md) class.

By deafault `acme2certifier` validates, during each ACME transaction, whether the EAB credentials used to create the ACME account remain valid. If this check fails, `acme2certifier` stops processing the transaction. This check can be disabled by the configuration option `eabkid_check_disable` in `a<me_srv.cfg`.

```ini
[EABhandler]
...
eabkid_check_disable: True
```

## File Handler

The `eab_file_handler.py` script allows `kid` and `mac_key` to be loaded from a CSV file. To activate this handler, configure the `EABhandler` section in `acme_srv.cfg` as follows:

```ini
[EABhandler]
eab_handler_file: examples/eab_handler/file_handler.py
key_file: examples/eab_handler/key_file.csv
```

The `key_file` must be in CSV format, with `kid` in the first column and `mac_key` (Base64 encoded) in the second column:

```csv
eab_kid,eab_mac
keyid_00,bWFjXz...Aw
keyid_01,bWFjXz...Ax
keyid_02,bWFjXz...Ay
keyid_03,bWFjXz...Az
```

## JSON Handler

The `eab_json_handler.py` script allows `kid` and `mac_key` (Base64 encoded) to be loaded from a JSON file. To activate this handler, configure the `EABhandler` section in `acme_srv.cfg` as follows:

```ini
[EABhandler]
eab_handler_file: examples/eab_handler/json_handler.py
key_file: examples/eab_handler/key_file.json
```

The `key_file` should contain key-value pairs in JSON format:

```json
{
  "keyid_00": "bWFjXz...Aw",
  "keyid_01": "bWFjXz...Ax",
  "keyid_02": "bWFjXz...Ay",
  "keyid_03": "bWFjXz...Az"
}
```

## Keyfile Verification

To check the consistency of the keyfile, use the `tools/eab_chk.py` utility:

```bash
usage: eab_chk.py [-h] -c CONFIGFILE [-d] [-v] [-vv] [-k KEYID | -s]

eab_chk.py - verify eab keyfile

options:
  -h, --help            show this help message and exit
  -c CONFIGFILE, --configfile CONFIGFILE
                        configfile
  -d, --debug           debug mode
  -v, --verbose         verbose
  -vv, --veryverbose    show enrollment profile
  -k KEYID, --keyid KEYID
                        keyid to filter
  -s, --summary         summary
```

Example usage:

```bash
python /var/www/acme2certifier/tools/eab_chk.py -c /var/www/acme2certifier/acme_srv/acme_srv.cfg -v
```

Example output:

```bash
Summary: 4 entries in key_file
keyid_00: bWFjXz...Aw
keyid_01: bWFjXz...Ax
keyid_02: bWFjXz...Ay
keyid_03: bWFjXz...Az
```

## Creating a Custom EAB Handler

Creating a custom EAB handler is straightforward. You need to create a `handler.py` file containing an `EABhandler` class with a `mac_key_get` method to look up the `mac_key` based on a given `kid`.

The `allowed_domains_check` method is optional and can be used to customize the [`allowed_domainlist_check()` function](https://github.com/grindsa/acme2certifier/blob/master/acme_srv/helper.py#L1641).

The [skeleton_eab_handler.py](../examples/eab_handler/skeleton_eab_handler.py) provides a template for creating a custom handler.

Below is an example of the class structure:

```python
class EABhandler(object):
    """EAB file handler"""

    def __init__(self, logger=None):
        self.logger = logger
        self.key = None

    def __enter__(self):
        """Makes EABhandler a Context Manager"""
        if not self.key_file:
            self._config_load()
        return self

    def __exit__(self, *args):
        """Close the connection at the end of the context"""

    def _config_load(self):
        """Load additional configuration parameters from acme_srv.cfg"""
        self.logger.debug("EABhandler._config_load()")
        config_dic = load_config(self.logger, "EABhandler")
        if "key" in config_dic["EABhandler"]:
            self.key = config_dic["EABhandler"]["key"]
        self.logger.debug("EABhandler._config_load() ended")

    def allowed_domains_check(self, csr, value) -> str:
        """Check allowed domains"""
        self.logger.debug("EABhandler.allowed_domains_check(%s, %s)", csr, value)
        error = None  # Return an error message if applicable
        return error

    def mac_key_get(self, kid=None):
        """Check external account binding"""
        self.logger.debug("EABhandler.mac_key_get({})".format(kid))
        mac_key = None  # Implement logic to look up the mac_key
        return mac_key
```
