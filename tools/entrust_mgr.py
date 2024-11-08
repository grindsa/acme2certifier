#!/usr/bin/python3
# -*- coding: utf-8 -*-
""" entrust manager """
from __future__ import print_function
import sys
import os
import argparse
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), os.path.pardir)))
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), os.path.pardir, os.path.pardir)))
# pylint: disable=E0401, E0611, C0209, C0413
from acme_srv.helper import logger_setup  # nopep8
from examples.ca_handler.entrust_ca_handler import CAhandler  # nopep8


def arg_parse():
    """ simple argparser """

    parser = argparse.ArgumentParser(description='enturst_mgr.py - a simple enturst certificate mananger')
    parser.add_argument('-d', '--debug', help='debug mode', action="store_true", default=False)
    parser.add_argument('-p', '--pagination', help='amout of certificates to be fetch with a single rest-call', default=200)
    parser.add_argument('-s', '--sortby', help='sortby fieldname [trackigId, status, serialNumber, expiresAfter]', default='trackingId')
    clist = parser.add_mutually_exclusive_group()
    clist.add_argument('-a', '--filteractive', help='filter output to active accounts', action="store_true", default=False)
    clist.add_argument('-r', '--revoke', help='revoke <transaction_id>', default=None)

    args = parser.parse_args()

    debug = args.debug
    config_dic = {
        'debug': args.debug,
        'filteractive': args.filteractive,
        'revoke': args.revoke,
        'pagination': int(args.pagination),
        'sortby': args.sortby
    }
    return (debug, config_dic)


if __name__ == '__main__':

    DEBUG, CONFIG_DIC = arg_parse()

    # initialize logger
    LOGGER = logger_setup(DEBUG)

    with CAhandler(logger=LOGGER) as ca_handler:
        result = ca_handler.credential_check()
        if not result:

            if CONFIG_DIC['revoke']:
                print("Revoking certificate with transaction_id: ", CONFIG_DIC['revoke'])
                CODE, CONTENT = ca_handler.revoke_by_trackingid(CONFIG_DIC['revoke'])
                if CODE == 200:
                    print("Revocation successful")
                else:
                    print(f"Revocation failed with error: {CONTENT}")
            else:
                # get list of certificates
                cert_list = ca_handler.certificates_get(limit=CONFIG_DIC['pagination'])
                for cert in sorted(cert_list, key=lambda k: k[CONFIG_DIC['sortby']]):
                    if (CONFIG_DIC['filteractive'] and cert['status'] == 'ACTIVE') or not CONFIG_DIC['filteractive']:
                        print(cert)
        else:
            print("Credential check failed: ", result)
            sys.exit(1)
