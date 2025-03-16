<!-- markdownlint-disable  MD013 -->
<!-- wiki-title External Account Binding -->
# External Account Binding

"External Account binding (EAB)" can allow an ACME account to use authorizations granted to an external, non-ACME account. This allows acme2certifier to address issuance scenarios that cannot yet be fully automated, such as the issuance of "Extended Validation" certificates.

To enable EAB the CA operator needs to provide both ACME client and acme2certifier with a key identifier (kid) and a MAC key (mac_key) which will be used to authenticate `NewAccount` requests.

KID and MAC key will be loaded into acme2certifier by using a plugin based mechanism. Two plugins will be shipped by default and are stored in the `example/eab_handler` directory.

The key identifiers will be part of the reports created by [Housekeeping](housekeeping.md) class.

## file_handler

The eab_file_handler.py allows to load kid and mac_key from a CSV file. The handler needs to be activated in `EABhandler` section of `acme_srv.cfg`

```bash
[EABhandler]
eab_handler_file: examples/eab_handler/file_handler.py
key_file: examples/eab_handler/key_file.csv
```

The key_file must be in CSV format with kid in the 1st and mac_key (base64 encoded) in the 2nd column.

```csv
eab_kid,eab_mac
keyid_00,bWFjXzAw
keyid_01,bWFjXzAx
keyid_02,bWFjXzAy
keyid_03,bWFjXzAz
```

## json_handler

The eab_json_handler.py allows to load kid and mac_key (base64 encoded) in JSON format. The handler gets activated in `EABhandler` section of `acme_srv.cfg` as shown below.

```bash
[EABhandler]
eab_handler_file: examples/eab_handler/json_handler.py
key_file: examples/eab_handler/key_file.json
```

kid and mac_key need to be stored as key/value pairs in JSON format.

```json
{
  "keyid_00": "bWFjXzAw",
  "keyid_01": "bWFjXzAx",
  "keyid_02": "bWFjXzAy",
  "keyid_03": "bWFjXzAz"
}
```

## Keyfile verification

In the keyfile can be checked for consistency by using the `tools/eab_chk.py` utility.

```bash
 py /var/www/acme2certifier/tools/eab_chk.py --help
```

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

Below is an example output using the previously mentioned JSON key file

```bash
 py /var/www/acme2certifier/tools/eab_chk.py  -c /var/www/acme2certifier/acme_srv/acme_srv.cfg -v
```

```bash
Summary: 4 entries in kid_file
keyid_00: bWFjXzAw
keyid_01: bWFjXzAx
keyid_02: bWFjXzAy
keyid_03: bWFjXzAz
```

## Create a Customized EAB Handler

Creating your own EAB handler is straightforward.  All you need to do is to create your own handler.py with a "EABhandler" class containing a __mac_key_get__ method to lookup the `mac_key` based on a given `kid`.

The __allowed_domains_check__ method is optional an can be use to customize the [`allowed_domainlist_check()` function](https://github.com/grindsa/acme2certifier/blob/master/acme_srv/helper.py#L1641).

The [skeleton_eab_handler.py](../examples/eab_handler/skeleton_eab_handler.py) contains a skeleton which can be used to create a customized handler.

The below code describes the different input parameters given by acme2certifier as well as the expected return values.

```python
class EABhandler(object):
    """ EAB file handler """

    def __init__(self, logger=None):
        self.logger = logger
        self.key = None

    def __enter__(self):
        """ Makes EABhandler a Context Manager """
        if not self.key_file:
            self._config_load()
        return self

    def __exit__(self, *args):
        """ close the connection at the end of the context """

    def _config_load(self):
        """" load additional configuration parameters from acme_srv.cfg """
        self.logger.debug('EABhandler._config_load()')
        config_dic = load_config(self.logger, 'EABhandler')
        if 'key' in config_dic['EABhandler']:
            self.key = config_dic['EABhandler']['key']

        self.logger.debug('EABhandler._config_load() ended')

    def allowed_domains_check(self, csr, value) -> str:
        """ check allowed domains """
        self.logger.debug('EABhandler.allowed_domains_check(%s, %s)', csr, value)
        error = 'ERROR' # error message or None

        return error

    def mac_key_get(self, kid=None):
        """ check external account binding """
        self.logger.debug('EABhandler.mac_key_get({})'.format(kid))
        mac_key =  # code to lookup the mac_key...
        return mac_key
```
