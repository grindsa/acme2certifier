#!/usr/bin/python
"""database updater"""

from acme2certifier.acme_srv.db_handler import DBstore
from acme2certifier.acme_srv.helper import logger_setup


def main() -> None:
    """Run SQLite/WSGI database schema update."""
    debug = True
    logger = logger_setup(debug)
    dbstore = DBstore(debug, logger)
    dbstore.db_update()


if __name__ == "__main__":
    main()
