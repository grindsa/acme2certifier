<!-- markdownlint-disable MD013 -->

<!-- wiki-title: Reporting and Housekeeping -->

# Reporting and Housekeeping

The `Housekeeping` class contains several methods for internal reporting and database maintenance.

To use it, you need to import the class into your script:

```python
from acme.housekeeping import Housekeeping
```

Then, create a corresponding context handler:

```python
with Housekeeping(LOGGER, DEBUG) as housekeeping:
```

- `LOGGER` is an instance of a `logging` object. It is recommended to use the `logger_setup()` method from `acme.helper` to create it:

```python
from acme.helper import logger_setup

LOGGER = logger_setup()
```

- `DEBUG` (True/False) - Enables or disables debug mode.

## Reporting

There are two methods for generating reports. Both methods return the report as a dictionary. Optionally, the reports can be saved to a file. The report name and format can be specified as shown below.

- `accountreport_get(report_format, report_name, nested)`: Generates a report containing a list of accounts along with corresponding orders, authorizations, and challenges.

  - `report_format`: Optional - `csv`/`json` - Specifies the report format (default: `csv`).
  - `nested`: Optional - `False`/`True` - Creates a nested JSON report structure (default: `False`).
  - `report_name`: Optional - Specifies the report file name (default: `account_report_YY-MM-DD-HHMM.<report_format>`).

- `certificatereport_get(report_format, report_name)`: Generates a report containing a list of certificates along with corresponding accounts and orders.

  - `report_format`: Optional - `csv`/`json` - Specifies the report format (default: `csv`).
  - `report_name`: Optional - Specifies the report file name.

Example reports and the database used to generate the reports can be found in the [examples/reports](../examples/reports) directory.

## Housekeeping

There are several methods for internal database maintenance.

- `certificate_cleanup(uts, purge, report_format, report_name)`: Identifies expired certificates from the `certificate` table. This method can either remove the X.509 object to reduce database size or delete the entire dataset. Optionally, a report of the selected certificates can be saved to a file.

  - `uts`: Optional - Unix timestamp to compare certificates against. If not specified, the current Unix timestamp will be used.
  - `purge`: Optional - `True`/`False`. If set to `True`, the entry is removed from the `certificate` table. If `False`, the X.509 object is overwritten with the string `"removed by acme2certifier"`. **Use this option carefully and back up `acme_srv.db` before cleaning your database.**
  - `report_format`: Optional - `csv`/`json` - Specifies the report format (default: `csv`).
  - `report_name`: Optional - Specifies the report file name.

- `order_invalidate(uts, report_format, report_name)`: Sets all expired orders to the "invalid" state. This method must be run regularly if the `expiry_check_disable` parameter is enabled in the `[orders]` section of `acme_srv.cfg`.

  - `uts`: Optional - Unix timestamp for order comparison. If not specified, the current Unix timestamp will be used.
  - `report_format`: Optional - `csv`/`json` - Specifies the report format (default: `csv`).
  - `report_name`: Optional - Specifies the report file name.

- `authorization_invalidate(uts, report_format, report_name)`: Sets all expired authorizations to the "invalid" state. This method must be run regularly if the `expiry_check_disable` parameter is enabled in the `[authorization]` section of `acme_srv.cfg`.

  - `uts`: Optional - Unix timestamp for authorization comparison. If not specified, the current Unix timestamp will be used.
  - `report_format`: Optional - `csv`/`json` - Specifies the report format (default: `csv`).
  - `report_name`: Optional - Specifies the report file name.
