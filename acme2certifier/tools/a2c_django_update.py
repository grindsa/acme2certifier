#!/usr/bin/python3
"""Deprecated Django database updater.

Use ``a2c-schema-update --mode django`` (or omit ``--mode`` when cfg says django).
"""

import sys
from typing import List, Optional

_DEPRECATION = (
    "WARNING: a2c-django-update is deprecated; " "use a2c-schema-update [--mode django]"
)


def main(argv: Optional[List[str]] = None) -> int:
    """Warn and delegate to a2c-schema-update --mode django."""
    print(_DEPRECATION, file=sys.stderr)
    from acme2certifier.tools.a2c_schema_update import main as schema_main

    del argv
    return schema_main(["--mode", "django"])


if __name__ == "__main__":
    sys.exit(main())
