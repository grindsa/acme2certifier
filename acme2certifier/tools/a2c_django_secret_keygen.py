#!/usr/bin/python3
"""secret key generator for django project"""

from __future__ import annotations


def main() -> None:
    """Print a Django SECRET_KEY to stdout."""
    # pylint: disable=E0401
    from django.core.management.utils import get_random_secret_key

    print(get_random_secret_key())  # lgtm [py/clear-text-logging-sensitive-data]


if __name__ == "__main__":
    main()
