#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import print_function
# pylint: disable=E0401
from acme_srv.helper import load_config, b64_url_recode
from acme import client, messages
import josepy
from OpenSSL import crypto
import base64
import textwrap
import sys

"""

Only works with ACME endpoints that do not issue any challenge.

Config file section:

[CAhandler]
# CA specific options
acme_url: https://some.acme/endpoint
acme_account: <account-id>
acme_keyfile: /path/to/privkey.json

"""


class CAhandler(object):
    """ EST CA  handler """

    def __init__(self, _debug=None, logger=None):
        self.logger = logger
        self.url = None
        self.keyfile = None
        self.account = None
        self.path_dic = {'directory_path': '', 'acct_path' : '/account/'}

    def __enter__(self):
        """ Makes CAhandler a Context Manager """
        if not self.url:
            self._config_load()
        return self

    def __exit__(self, *args):
        """ cose the connection at the end of the context """

    def _config_load(self):
        """" load config from file """
        self.logger.debug('CAhandler._config_load()')
        config_dic = load_config()
        if 'CAhandler' in config_dic:
            if 'acme_keyfile' in config_dic['CAhandler']:
                self.keyfile = config_dic['CAhandler']['acme_keyfile']
            else:
                self.logger.error('CAhandler._config_load() configuration incomplete: "acme_keyfile" parameter is missing in config file')

            if 'acme_url' in config_dic['CAhandler']:
                self.url = config_dic['CAhandler']['acme_url']
            else:
                self.logger.error('CAhandler._config_load() configuration incomplete: "acme_url" parameter is missing in config file')

            if 'acme_account' in config_dic['CAhandler']:
                self.account = config_dic['CAhandler']['acme_account']
            else:
                self.logger.error('CAhandler._config_load() configuration incomplete: "acme_account" parameter is missing in config file')

            if 'account_path' in config_dic['CAhandler']:
                self.path_dic['acct_path'] = config_dic['CAhandler']['account_path']

            if 'directory_path' in config_dic['CAhandler']:
                self.path_dic['directory_path'] = config_dic['CAhandler']['directory_path']

            self.logger.debug('CAhandler._config_load() ended')

    def _challenge_filter(self, authzr, chall_type='http-01'):
        """ filter authorization for challenge """
        self.logger.debug('CAhandler._challenge_filter({0})'.format(chall_type))
        for challenge in authzr.body.challenges:
            if challenge.chall.typ == chall_type:
                return challenge
        else:
            self.logger.error('CAhandler._challenge_filter() ended. Could not find challenge of type {0}'.format(chall_type))

    def _http_challenge_info(self, authzr, user_key):
        """ filter challenges and get challenge details """
        self.logger.debug('CAhandler._http_challenge_info()')

        challenge = self._challenge_filter(authzr)
        chall_path = challenge.chall.path
        chall_content = challenge.chall.validation(user_key)
        (chall_name, _token) = chall_content.split('.', 2)

        self.logger.debug('CAhandler._http_challenge_info() ended with {0}'.format(chall_name))
        return(chall_name, chall_content)

    def enroll(self, csr):
        """ enroll certificate  """
        self.logger.debug('CAhandler.enroll()')

        csr_pem = '-----BEGIN CERTIFICATE REQUEST-----\n{0}\n-----END CERTIFICATE REQUEST-----\n'.format(textwrap.fill(str(b64_url_recode(self.logger, csr)), 64))

        cert_bundle = None
        error = None
        cert_raw = None
        poll_indentifier = None
        user_key = None

        try:
            self.logger.debug('CAhandler.enroll() opening user_key')
            with open(self.keyfile, "r") as keyf:
                user_key = josepy.JWKRSA.json_loads(keyf.read())

            net = client.ClientNetwork(user_key)
            directory = messages.Directory.from_json(net.get('{0}{1}'.format(self.url, self.path_dic['directory_path'])).json())
            acmeclient = client.ClientV2(directory, net=net)
            reg = messages.Registration.from_data(key=user_key, terms_of_service_agreed=True)

            regr = messages.RegistrationResource(uri="{0}{1}{2}".format(self.url, self.path_dic['acct_path'], self.account), body=reg)
            self.logger.debug('CAhandler.enroll() checking remote registration status')
            regr = acmeclient.query_registration(regr)

            if regr.body.status != "valid":
                raise Exception("Bad ACME account: " + str(regr.body.error))

            self.logger.debug('CAhandler.enroll() issuing signing order')
            self.logger.debug('CAhandler.enroll() CSR: ' + str(csr_pem))
            order = acmeclient.new_order(csr_pem)

            # query challenges
            for authzr in list(order.authorizations):
                (chall_name, chall_content) = self._http_challenge_info(authzr, user_key)
                print(chall_name, chall_content)

            sys.exit(0)
            self.logger.debug('CAhandler.enroll() polling for certificate')
            order = acmeclient.poll_and_finalize(order)

            if not order.fullchain_pem:
                raise Exception("Error getting certificate: " + str(order.error))

            self.logger.debug('CAhandler.enroll() successful')
            cert_bundle = str(order.fullchain_pem)
            cert_raw = str(base64.b64encode(crypto.dump_certificate(crypto.FILETYPE_ASN1, crypto.load_certificate(crypto.FILETYPE_PEM, cert_bundle))), 'utf-8')

        except Exception as e:
            self.logger.error(str(e))
            error = str(e)

        finally:
            del user_key

        self.logger.debug('Certificate.enroll() ended')
        return(error, cert_bundle, cert_raw, poll_indentifier)

    def poll(self, cert_name, poll_identifier, _csr):
        """ poll status of pending CSR and download certificates """
        self.logger.debug('CAhandler.poll()')

        error = "Not implemented"
        cert_bundle = None
        cert_raw = None
        rejected = False

        self.logger.debug('CAhandler.poll() ended')
        return(error, cert_bundle, cert_raw, poll_identifier, rejected)

    def revoke(self, _cert, _rev_reason, _rev_date):
        """ revoke certificate """
        self.logger.debug('CAhandler.revoke()')

        certpem = '-----BEGIN CERTIFICATE-----\n{0}\n-----END CERTIFICATE-----\n'.format(textwrap.fill(str(b64_url_recode(self.logger, _cert)), 64))
        cert = josepy.ComparableX509(crypto.load_certificate(crypto.FILETYPE_PEM, certpem))

        code = 200
        message = None
        detail = None

        try:
            self.logger.debug('CAhandler.revoke() opening key')
            with open(self.keyfile, "r") as keyf:
                key = josepy.JWKRSA.json_loads(keyf.read())

            net = client.ClientNetwork(key)
            directory = messages.Directory.from_json(net.get(self.url).json())
            acmeclient = client.ClientV2(directory, net=net)
            reg = messages.Registration.from_data(key=key, terms_of_service_agreed=True)
            regr = messages.RegistrationResource(uri="{}/account/{}".format(self.url, self.account), body=reg)
            self.logger.debug('CAhandler.revoke() checking remote registration status')
            regr = acmeclient.query_registration(regr)

            if regr.body.status != "valid":
                raise Exception("Bad ACME account: " + str(regr.body.error))

            self.logger.debug('CAhandler.revoke() issuing revocation order')
            acmeclient.revoke(cert, 1)
            self.logger.debug('CAhandler.revoke() successfull')


        except Exception as e:
            self.logger.error(str(e))
            code = 500
            message = 'urn:ietf:params:acme:error:serverInternal'
            detail = str(e)

        finally:
            del key

        self.logger.debug('Certificate.revoke() ended')
        return(code, message, detail)

    def trigger(self, payload):
        """ process trigger message and return certificate """
        self.logger.debug('CAhandler.trigger()')

        error = "Not implemented"
        cert_bundle = None
        cert_raw = None

        self.logger.debug('CAhandler.trigger() ended with error: {0}'.format(error))
        return (error, cert_bundle, cert_raw)
