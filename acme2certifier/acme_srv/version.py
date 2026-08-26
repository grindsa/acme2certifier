"""version file"""

# Store the version here so:
# 1) we don't load dependencies by storing it in __init__.py
# 2) pyproject.toml can read it via tool.setuptools.dynamic
# 3) runtime code can import the same value
__version__ = "0.45.1"
__dbversion__ = "0.41"
