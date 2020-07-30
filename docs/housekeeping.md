<!-- markdownlint-disable  MD013 -->
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

There are two methods allowing the creation of reports.

- `accountreport_get(report_format, nested)`: this report contains a list of accounts and corresponding orders, authorizations and challenges
  - report_format: `csv`/`json` - specifies the format of the report  (default `csv`)
  - nested: `False`/`True` - creates a nested JSON report structure (default `False`)
  - filename: name of the report file (default: account_report_YY-MM-DD-HHMM.`report_format`)
- `certificatereport_get(report_format, nested)`: this report contains a list of certificates and corresponding accounts and orders
  - report_format: `csv`/`json` - specifies the format of the report  (default `csv`)
  - filename: name of the report file (default: certificate_report_YY-MM-DD-HHMM.`report_format`)

Example reports and database used to create the reports can be found in the [examples/reports](../examples/reports) directory.
