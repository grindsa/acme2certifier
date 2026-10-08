#!/usr/bin/python3
"""secret key generator for django project"""

import secrets

# Omit characters that break common embeddings:
# - % @ ( )  uWSGI ini magic / @(file) includes
# - # ;      ini / GITHUB_ENV comments
# - $ `      shell / GITHUB_ENV expansion
# - ! & ^ | <>  cmd.exe ``set`` / delayed expansion (win-acme launchers)
_SECRET_KEY_CHARS = "abcdefghijklmnopqrstuvwxyz0123456789*-_=+"
_SECRET_KEY_LENGTH = 50


def generate_secret_key() -> str:
    """Return a Django SECRET_KEY safe for ini, GITHUB_ENV, and cmd ``set``."""
    return "".join(secrets.choice(_SECRET_KEY_CHARS) for _ in range(_SECRET_KEY_LENGTH))


def main() -> None:
    """Print a Django SECRET_KEY to stdout."""
    print(generate_secret_key())  # lgtm [py/clear-text-logging-sensitive-data]


if __name__ == "__main__":
    main()
