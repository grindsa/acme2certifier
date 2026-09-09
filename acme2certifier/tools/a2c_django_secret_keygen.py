#!/usr/bin/python3
"""secret key generator for django project"""

import secrets

# Omit % @ ( ) so the key is safe in uWSGI ini (magic vars, @(file) includes).
_SECRET_KEY_CHARS = "abcdefghijklmnopqrstuvwxyz0123456789!#$^&*-_=+"
_SECRET_KEY_LENGTH = 50


def generate_secret_key() -> str:
    """Return a Django SECRET_KEY that is safe to embed in acme2certifier.ini."""
    return "".join(secrets.choice(_SECRET_KEY_CHARS) for _ in range(_SECRET_KEY_LENGTH))


def main() -> None:
    """Print a Django SECRET_KEY to stdout."""
    print(generate_secret_key())  # lgtm [py/clear-text-logging-sensitive-data]


if __name__ == "__main__":
    main()
