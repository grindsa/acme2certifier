<!-- markdownlint-disable  MD013 -->
<!-- wiki-title Reporting and housekeeping -->
# Reporting and housekeeping

The `Housekeeping` class contains a couple of methods for internal reporting and database maintenance.

To use it you need to import the class into your script

```python
> from acme.housekeeping import Housekeeping
```

and create a respective context handler

```python
> with Housekeeping(LOGGER, DEBUG) as housekeeping:
```

- `LOGGER` is a instance of `logging` object. I recommended to use the `logger_setup()` method from `acme.helper` to create it

```python
> from acme.helper import logger_setup

LOGGER = logger_setup()
```

- `DEBUG` (True/False) - debug mode

## Reporting

There are two methods allowing the creation of reports. Both methods will return the report as dictionary. Optionally the reports can be dumped in to a file. Report name and report format can be specified as below.

- `accountreport_get(report_format, report_name, nested)`: this method contains a list of accounts and corresponding orders, authorizations and challenges
  - report_format: optional - `csv`/`json` - specifies the format of the report  (default `csv`)
  - nested: optional - `False`/`True` - creates a nested JSON report structure (default `False`)
  - report_name: optional - name of the report file (default: account_report_YY-MM-DD-HHMM.`report_format`)
- `certificatereport_get(report_format, , report_name)`: this method contains a list of certificates and corresponding accounts and orders
  - report_format: optional `csv`/`json` - specifies the format of the report  (default `csv`)
  - report_name: optional - name of the report file

Example reports and database used to create the reports can be found in the [examples/reports](../examples/reports) directory.

# Housekeeping

There a few methods for internal database maintainance.

- `certificate_cleanup(uts, purge, report_format, report_name)` - this method identifies expired certificates from `certificate` - table. It can either remove the x509 objecte to shrink the database or even delete the complete data-set.  Optionally a report of the selected certificates can be dumped in to a file.
  - uts: optional - unix timestamp to compare the certficates with. If not specified the actual unix-timestamp will be used.
  - purge: optional - can be either True or False. The `True` option will remove the entry from `certifcate` - table. Leaving the option on `False` will solely overwrite the x509 object with the string "removed by acme2certifer" - **please use this option carefully and take a backup of `acme_srv.db` before cleaning your database**
  - report_format: optional `csv`/`json` - specifies the format of the report  (default `csv`)
  - report_name: optional - name of the report file  

- `order_invalidate(uts, report_format, report_name)` - this method sets all expired orders to "invalid" state.  Must be regularly executed if the parameter `expiry_check_disable` has been enabled in the `[orders]` section of `acme_srv.cfg`
  - uts: optional - unix timestamp used for order comparison. If not specified the actual unix-timestamp will be used
  - report_format: optional `csv`/`json` - specifies the format of the report  (default `csv`)
  - report_name: optional - name of the report file  

- `authorization_invalidate(uts, report_format, report_name)` - this method sets all expired authorizations to "invalid" state.  Must be regularly executed if the parameter `expiry_check_disable` has been enabled in the `[authorization]` section of `acme_srv.cfg`
  - uts: optional - unix timestamp used for order comparison. If not specified the actual unix-timestamp will be used
  - report_format: optional `csv`/`json` - specifies the format of the report  (default `csv`)
  - report_name: optional - name of the report file  
