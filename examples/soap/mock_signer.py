#!/usr/bin/python3
""" signing script to create a signed pkcs7 structure out of a pkcs7 csr """
# -*- coding: utf-8 -*-
# pylint: disable=C0413, E0401, E0611, W0212
from __future__ import print_function
import sys
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), os.path.pardir)))
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), os.path.pardir, os.path.pardir)))
from acme_srv.helper import logger_setup  # nopep8
from examples.ca_handler.pkcs7_soap_ca_handler import binary_read, binary_write, CAhandler  # nopep8


if __name__ == '__main__':

    DEBUG = True

    LOGGER = logger_setup(DEBUG)

    # check amount of command line arguments
    if len(sys.argv) != 5:
        LOGGER.error('Mot enough command line arguments')
        sys.exit(1)

    IN_FILE = sys.argv[1]
    OUT_FILE = sys.argv[2]
    SIGNER_ALIAS = sys.argv[3]
    CONFIG_VARIANT = sys.argv[4]

    if IN_FILE and OUT_FILE and SIGNER_ALIAS and CONFIG_VARIANT:

        # load CSR
        csr_der = binary_read(LOGGER, IN_FILE)

        # SIGNER_ALIAS contains the signing cert
        with open(SIGNER_ALIAS, 'rb') as open_file:
            signing_cert = x509.load_pem_x509_certificate(open_file.read(), default_backend())

        # CONFIG_VARIANT contains the signing cert
        with open(CONFIG_VARIANT, 'rb') as open_file:
            signing_key = serialization.load_pem_private_key(open_file.read(), password=None, backend=default_backend())

            ca_handler = CAhandler(DEBUG, LOGGER)

        # decode signing cert
        decoded_cert = ca_handler._cert_decode(signing_cert)

        # create pkcs7 bundle and dump it to file
        (_error, pkcs7_bundle) = ca_handler._pkcs7_create(decoded_cert, csr_der, signing_key)
        binary_write(LOGGER, OUT_FILE, pkcs7_bundle)
