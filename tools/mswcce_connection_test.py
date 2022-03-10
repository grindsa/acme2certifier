#!/usr/bin/python3
# -*- coding: utf-8 -*-
""" CA handler for Microsoft Windows Client Certificate Enrollment Protocol (MS-WCCE) """
from __future__ import print_function
import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), os.path.pardir)))
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), os.path.pardir, os.path.pardir)))
# pylint: disable=E0401, E0611, C0209, C0413
from acme_srv.helper import logger_setup  # nopep8
from examples.ca_handler.mswcce_ca_handler import CAhandler  # nopep8

if __name__ == '__main__':

    # initialize logger
    LOGGER = logger_setup(True)

    with CAhandler(True, LOGGER) as ca_handler:
        request = ca_handler.request_create()
