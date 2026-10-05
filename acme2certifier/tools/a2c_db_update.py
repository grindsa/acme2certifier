#!/usr/bin/python
"""Deprecated WSGI database updater.

Use ``a2c-schema-update --mode wsgi`` (or omit ``--mode`` when cfg says wsgi).
"""

import sys
from typing import List, Optional

_DEPRECATION = (
    "WARNING: a2c-db-update is deprecated; use a2c-schema-update [--mode wsgi]"
)


def main(argv: Optional[List[str]] = None) -> int:
    """Warn and delegate to a2c-schema-update --mode wsgi."""
    print(_DEPRECATION, file=sys.stderr)
    from acme2certifier.tools.a2c_schema_update import main as schema_main

    # Ignore legacy argv; always force wsgi mode.
    del argv
    return schema_main(["--mode", "wsgi"])


if __name__ == "__main__":
    sys.exit(main())
