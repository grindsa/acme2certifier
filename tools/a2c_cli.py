"""Temporary compatibility layer.

Real implementation: acme2certifier.tools
Do not add logic here.
"""

import runpy
import sys

if __name__ == "__main__":
    runpy.run_module("acme2certifier.tools.a2c_cli", run_name="__main__")
else:
    from acme2certifier.tools import a2c_cli as _impl

    sys.modules[__name__] = _impl
