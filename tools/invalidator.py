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

    with Housekeeping(DEBUG, LOGGER) as housekeeping:

        # manual order invalidation
        order_list = housekeeping.orders_invalidate(report_format='csv', report_name='orders_invalidate_{0}'.format(SUFFIX))

        # manual authorization invalidation
        authorization_list = housekeeping.authorizations_invalidate(report_format='csv', report_name='authorization_expire_{0}'.format(SUFFIX))

        # update issue_uts and expire_uts in certificates table
        housekeeping.certificate_dates_update()
