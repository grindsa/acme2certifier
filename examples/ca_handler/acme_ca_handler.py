#!/usr/bin/python
# -*- coding: utf-8 -*-
""" generic ca handler for CAs supporting acme protocol """
from __future__ import print_function
# pylint: disable=E0401, W0105
import os.path
import json
import textwrap
import base64
import josepy
from OpenSSL import crypto
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from acme import client, messages
from acme_srv.db_handler import DBstore
from acme_srv.helper import load_config, b64_url_recode
import time

"""
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
        self.key_size = 2048
        self.account = None
        self.email = None
        self.path_dic = {'directory_path': '/directory', 'acct_path' : '/acme/acct/'}
        self.dbstore = DBstore(None, self.logger)

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
                # try to fetch acme-account id from housekeeping table
                # self.account = self.dbstore.hkparameter_get('acme_account')
                if self.account:
                    self.logger.debug('CAhandler._config_load() found acme_account in housekeeping table: {0}'.format(self.account))

            if 'account_path' in config_dic['CAhandler']:
                self.path_dic['acct_path'] = config_dic['CAhandler']['account_path']

            if 'directory_path' in config_dic['CAhandler']:
                self.path_dic['directory_path'] = config_dic['CAhandler']['directory_path']

            if 'acme_account_keysize' in config_dic['CAhandler']:
                self.key_size = config_dic['CAhandler']['acme_account_keysize']

            if 'acme_account_email' in config_dic['CAhandler']:
                self.email = config_dic['CAhandler']['acme_account_email']

            self.logger.debug('CAhandler._config_load() ended')
        else:
            self.logger.error('CAhandler._config_load() configuration incomplete: "CAhandler" section is missing in config file')

    def _challenge_filter(self, authzr, chall_type='http-01'):
        """ filter authorization for challenge """
        self.logger.debug('CAhandler._challenge_filter({0})'.format(chall_type))
        result = None
        for challenge in authzr.body.challenges:
            if challenge.chall.typ == chall_type:
                result = challenge
                break
        if not result:
            self.logger.error('CAhandler._challenge_filter() ended. Could not find challenge of type {0}'.format(chall_type))
        return result

    def _challenge_store(self, challenge_name, challenge_content):
        """ store challenge into database """
        self.logger.debug('CAhandler._challenge_store({0})'.format(challenge_name))
        if challenge_name and challenge_content:
            data_dic = {'name': challenge_name, 'value1': challenge_content}
            # store challenge into db
            self.dbstore.cahandler_add(data_dic)

    def _http_challenge_info(self, authzr, user_key):
        """ filter challenges and get challenge details """
        self.logger.debug('CAhandler._http_challenge_info()')

        chall_name = None
        chall_content = None

        if authzr and user_key:
            challenge = self._challenge_filter(authzr)
            chall_content = challenge.chall.validation(user_key)
            try:
                (chall_name, _token) = chall_content.split('.', 2)
            except BaseException:
                self.logger.error('CAhandler._http_challenge_info() challenge split failed: {0}'.format(chall_content))
        else:
            if authzr:
                self.logger.error('CAhandler._http_challenge_info() userkey is missing')
            else:
                self.logger.error('CAhandler._http_challenge_info() authzr is missing')
            challenge = None

        self.logger.debug('CAhandler._http_challenge_info() ended with {0}'.format(chall_name))
        return(chall_name, chall_content, challenge)

    def _key_generate(self):
        """ generate key """
        self.logger.debug('CAhandler._key_generate({0})'.format(self.key_size))
        user_key = josepy.JWKRSA(
            key=rsa.generate_private_key(
                public_exponent=65537,
                key_size=self.key_size,
                backend=default_backend()
            )
        )
        return user_key

    def _user_key_load(self):
        """ enroll certificate  """
        self.logger.debug('CAhandler._user_key_load()')

        if os.path.exists(self.keyfile):
            self.logger.debug('CAhandler.enroll() opening user_key')
            with open(self.keyfile, "r") as keyf:
                user_key = josepy.JWKRSA.json_loads(keyf.read())
        else:
            self.logger.debug('CAhandler.enroll() generate and register key')
            user_key = self._key_generate()
            # dump keyfile to file
            with open(self.keyfile, "w") as keyf:
                keyf.write(json.dumps(user_key.to_json()))

        self.logger.debug('CAhandler._user_key_load() ended')
        return user_key

    def _account_register(self, acmeclient, user_key, directory):
        """ register account / check registration """
        self.logger.debug('CAhandler._account_register({0})'.format(self.email))
        try:
            # we assume that the account exist and need to query the account id
            reg = messages.NewRegistration.from_data(key=user_key, email=self.email, terms_of_service_agreed=True, only_return_existing=True)
            response = acmeclient._post(directory['newAccount'], reg)
            regr = acmeclient._regr_from_response(response)
            regr = acmeclient.query_registration(regr)
            self.logger.debug('CAhandler.__account_register(): found existing account: {0}'.format(regr.uri))
        except BaseException:
            if self.email:
                self.logger.debug('CAhandler.__account_register(): register new account with email: {0}'.format(self.email))
                # account does not exists - register
                reg = messages.NewRegistration.from_data(key=user_key, email=self.email, terms_of_service_agreed=True)
                regr = acmeclient.new_account(reg)
                self.logger.debug('CAhandler.__account_register(): new account reqistered: {0}'.format(regr.uri))
            else:
                self.logger.error('CAhandler.__account_register(): registration aborted. Email address is missing')
                regr = None

        if regr:
            if self.url and 'acct_path' in self.path_dic:
                self.account = regr.uri.replace(self.url, '').replace(self.path_dic['acct_path'], '')
            if self.account:
                self.logger.info('acme-account id is {0}. Please add an corresponding acme_account parameter to your acme_srv.cfg to avoid unnecessary lookups'.format(self.account))
                # store account-id in housekeeping table to avoid unneccary rquests towards acme-server
                # self.dbstore.hkparameter_add({'name': 'acme_account', 'value': self.account})
        return regr

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
            user_key = self._user_key_load()
            net = client.ClientNetwork(user_key)

            directory = messages.Directory.from_json(net.get('{0}{1}'.format(self.url, self.path_dic['directory_path'])).json())
            acmeclient = client.ClientV2(directory, net=net)
            reg = messages.Registration.from_data(key=user_key, terms_of_service_agreed=True)

            if self.account:
                regr = messages.RegistrationResource(uri="{0}{1}{2}".format(self.url, self.path_dic['acct_path'], self.account), body=reg)
                self.logger.debug('CAhandler.enroll(): checking remote registration status')
                regr = acmeclient.query_registration(regr)
            else:
                # new account or existing account with missing account id
                regr = self._account_register(acmeclient, user_key, directory)

            if regr.body.status == "valid":
                self.logger.debug('CAhandler.enroll() issuing signing order')
                self.logger.debug('CAhandler.enroll() CSR: ' + str(csr_pem))
                order = acmeclient.new_order(csr_pem)

                # query challenges
                for authzr in list(order.authorizations):
                    (challenge_name, challenge_content, challenge) = self._http_challenge_info(authzr, user_key)
                    if challenge_name and challenge_content:
                        # store challenge in database to allow challenge validation
                        self._challenge_store(challenge_name, challenge_content)
                        auth_response = acmeclient.answer_challenge(challenge, challenge.chall.response(user_key))

                self.logger.debug('CAhandler.enroll() polling for certificate')
                order = acmeclient.poll_and_finalize(order)

                if order.fullchain_pem:
                    self.logger.debug('CAhandler.enroll() successful')
                    cert_bundle = str(order.fullchain_pem)
                    cert_raw = str(base64.b64encode(crypto.dump_certificate(crypto.FILETYPE_ASN1, crypto.load_certificate(crypto.FILETYPE_PEM, cert_bundle))), 'utf-8')
                else:
                    # raise Exception("Error getting certificate: " + str(order.error))
                    self.logger.error('CAhandler.enroll: Error getting certificate: {0}'.format(order.error))
                    error = 'Error getting certificate: {0}'.format(order.error)
            else:
                self.logger.error('CAhandler.enroll: Bad ACME account: {0}'.format(regr.body.error))
                error = 'Bad ACME account: {0}'.format(regr.body.error)
                # raise Exception("Bad ACME account: " + str(regr.body.error))

        except BaseException as err:
            self.logger.error('CAhandler.enroll: error: {0}'.format(err))
            error = str(err)
        finally:
            del user_key

        self.logger.debug('Certificate.enroll() ended')
        return(error, cert_bundle, cert_raw, poll_indentifier)

    def poll(self, _cert_name, poll_identifier, _csr):
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

        except Exception as err:
            self.logger.error(str(err))
            code = 500
            message = 'urn:ietf:params:acme:error:serverInternal'
            detail = str(err)

        finally:
            del key

        self.logger.debug('Certificate.revoke() ended')
        return(code, message, detail)

    def trigger(self, _payload):
        """ process trigger message and return certificate """
        self.logger.debug('CAhandler.trigger()')

        error = "Not implemented"
        cert_bundle = None
        cert_raw = None

        self.logger.debug('CAhandler.trigger() ended with error: {0}'.format(error))
        return (error, cert_bundle, cert_raw)
