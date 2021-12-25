#!/usr/bin/python
""" database updater """
# pylint: disable=E0401, C0413
import sys
sys.path.insert(0, '..')
from acme_srv.db_handler import initialize  # nopep8
initialize()
from acme_srv.helper import logger_setup  # nopep8
from acme_srv.certificate import Certificate  # nopep8

if __name__ == '__main__':

    DEBUG = True

    # timeout between the different polling request
    TIMEOUT = 1

    # initialize logger
    LOGGER = logger_setup(DEBUG)

    with Certificate(DEBUG, 'foo', LOGGER) as certificate:
        # search certificates in status "processing"
        CERT_LIST = certificate.certlist_search('order__status_id', 4, ('name', 'poll_identifier', 'csr', 'order__name'))

        for cert in CERT_LIST:
            # check status of certificate
            certificate.poll(cert['name'], cert['poll_identifier'], cert['csr'], cert['order__name'])
            # time.sleep(TIMEOUT)
