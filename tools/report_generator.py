#!/usr/bin/python
""" database updater """
# pylint: disable=C0209, E0401, C0413
import sys
sys.path.insert(0, '..')
sys.path.insert(1, '.')
import time  # nopep8
from acme_srv.helper import logger_setup, uts_to_date_utc  # nopep8
from acme_srv.housekeeping import Housekeeping  # nopep8


if __name__ == '__main__':

    DEBUG = True

    # initialize logger
    LOGGER = logger_setup(DEBUG)

    SUFFIX = uts_to_date_utc(int(time.time()), '%Y-%m-%d-%H%M%S')

    # this is just for testing
    # from shutil import copyfile
    # copyfile('db.sqlite3.old', 'db.sqlite3')
    # copyfile('acme_srv/acme_srv.db.old', 'acme_srv/acme_srv.db')

    with Housekeeping(DEBUG, LOGGER) as housekeeping:

        # certificate report in json format
        cert_report = housekeeping.certreport_get(report_name='certificate_report_{0}'.format(SUFFIX), report_format='json')
        # certificate report in csv format
        housekeeping.certreport_get(report_name='certificate_report_{0}'.format(SUFFIX))

        # account report in json format
        account_report = housekeeping.accountreport_get(report_name='account_report_{0}'.format(SUFFIX), report_format='json', nested=True)
        # account report in csv report_format
        housekeeping.accountreport_get(report_name='account_report_{0}'.format(SUFFIX))

        # certifiate cleanup (no delete) dump in json
        cleanup_report = housekeeping.certificates_cleanup(report_format='json', report_name='certificate_cleanup_{0}'.format(SUFFIX))
        # certifiate cleanup (including delete) dump in csv
        # housekeeping.certificates_cleanup(report_format='csv', report_name='certificate_cleanup_{0}'.format(SUFFIX), purge=True)

        # manual order invalidation
        order_list = housekeeping.orders_invalidate(report_format='csv', report_name='orders_invalidate_{0}'.format(SUFFIX))

        # manual authorization invalidation
        authorization_list = housekeeping.authorizations_invalidate(report_format='csv', report_name='authorization_expire_{0}'.format(SUFFIX))
