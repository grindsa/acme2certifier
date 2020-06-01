#!/usr/bin/python
# -*- coding: utf-8 -*-
""" handler for an openssl ca """
from __future__ import print_function
import os
import sqlite3
from OpenSSL import crypto
from acme.helper import load_config, build_pem_file, uts_now, uts_to_date_utc, b64_decode, b64_url_recode, cert_serial_get, convert_string_to_byte, convert_byte_to_string, csr_cn_get, csr_san_get


def dict_from_row(row):
    """ small helper to convert the output of a "select" command into a dictionary """
    return dict(zip(row.keys(), row))

class CAhandler(object):
    """ CA  handler """

    def __init__(self, debug=None, logger=None):
        self.debug = debug
        self.logger = logger
        self.xdb_file = None
        self.passphrase = 'i_dont_know'
        self.issuing_ca_name = None

    def __enter__(self):
        """ Makes ACMEHandler a Context Manager """
        if not self.xdb_file:
            self._config_load()
        return self

    def __exit__(self, *args):
        """ cose the connection at the end of the context """

    def _ca_cert_load(self):
        """ load ca key from database """
        self.logger.debug('CAhandler._ca_cert_load()')

        # query database for key
        self._db_open()
        pre_statement = '''SELECT * from view_certs WHERE name LIKE ?'''
        self.cursor.execute(pre_statement, [self.issuing_ca_name])
        try:
            db_result = dict_from_row(self.cursor.fetchone())
        except BaseException:
            db_result = {}
        self._db_close()

        ca_cert = None
        if 'cert' in db_result:
            try:
                ca_cert = crypto.load_certificate(crypto.FILETYPE_ASN1, b64_decode(self.logger, db_result['cert']))
            except BaseException as err_:
                self.logger.error('CAhandler._ca_key_load() failed with error: {0}'.format(err_))
        return ca_cert

    def _ca_key_load(self):
        """ load ca key from database """
        self.logger.debug('CAhandler._ca_key_load()')

        # query database for key
        self._db_open()
        pre_statement = '''SELECT * from view_private WHERE name LIKE ?'''
        self.cursor.execute(pre_statement, [self.issuing_ca_name])
        db_result = dict_from_row(self.cursor.fetchone())
        self._db_close()

        ca_key = None
        if 'private' in db_result:
            try:
                private_key = '-----BEGIN ENCRYPTED PRIVATE KEY-----\n{0}\n-----END ENCRYPTED PRIVATE KEY-----'.format(db_result['private'])
                ca_key = crypto.load_privatekey(crypto.FILETYPE_PEM, private_key, convert_string_to_byte(self.passphrase))

            except BaseException as err_:
                self.logger.error('CAhandler._ca_key_load() failed with error: {0}'.format(err_))

        self.logger.debug('CAhandler._ca_key_load() ended')
        return ca_key

    def _ca_load(self):
        """ load ca key and cert """
        self.logger.debug('CAhandler._ca_load()')
        ca_key = self._ca_key_load()
        ca_cert = self._ca_cert_load()

        self.logger.debug('CAhandler._ca_load() ended')
        return(ca_key, ca_cert)

    def _config_check(self):
        """ check config for consitency """
        self.logger.debug('CAhandler._config_check()')
        error = None

        if self.xdb_file:
            if not os.path.exists(self.xdb_file):
                error = 'xdb_file {0} does not exist'.format(self.xdb_file)
        else:
            error = 'xdb_file must be specified in config file'

        if not error:
            if not self.issuing_ca_name:
                error = 'issuing_ca_name must be set in config file'

        if error:
            self.logger.debug('CAhandler config error: {0}'.format(error))

        self.logger.debug('CAhandler._config_check() ended'.format())
        return error

    def _config_load(self):
        """" load config from file """
        self.logger.debug('CAhandler._config_load()')
        config_dic = load_config(self.logger, 'CAhandler')

        if 'xdb_file' in config_dic['CAhandler']:
            self.xdb_file = config_dic['CAhandler']['xdb_file']

        if 'passphrase' in config_dic['CAhandler']:
            self.passphrase = config_dic['CAhandler']['passphrase']

        if 'issuing_ca_name' in config_dic['CAhandler']:
            self.issuing_ca_name = config_dic['CAhandler']['issuing_ca_name']

    def _csr_import(self, csr):
        """ check existance of csr and load into db """
        self.logger.debug('CAhandler._csr_insert()')

        csr_info = self._csr_search('request', csr)

        if not csr_info:

            # try to get cn for a name in database
            request_name = csr_cn_get(self.logger, csr)
            if not request_name:
                san_list = csr_san_get(self.logger, csr)
                (_identifiier, request_name,) = san_list[0].split(':')

            # csr does not exist in db - lets import it
            insert_date = uts_to_date_utc(uts_now(), '%Y%m%d%H%M%SZ')
            item_dic = {'type': 2, 'comment': 'from acme2certifier', 'source': 2, 'date': insert_date, 'name': request_name}
            row_id = self._item_insert(item_dic)

            # insert csr
            csr_dic = {'item': row_id, 'signed': 0, 'request': csr}
            self._csr_insert(csr_dic)

    def _csr_insert(self, csr_dic):
        """ insert new entry to request table """
        self.logger.debug('CAhandler._csr_insert()')
        row_id = None
        if csr_dic:
            if 'item' in csr_dic and 'signed' in csr_dic and 'request' in csr_dic:
                self._db_open()
                self.cursor.execute('''INSERT INTO REQUESTS(item, signed, request) VALUES(:item, :signed, :request)''', csr_dic)
                row_id = self.cursor.lastrowid
                self._db_close()
            else:                
                self.logger.error('CAhandler._csr_insert() aborted. dataset incomplete: {}'.format(csr_dic))                
        else:
            self.logger.error('CAhandler._csr_insert() aborted. dataset empty')
            
        self.logger.debug('CAhandler._csr_insert() ended with row_id: {0}'.format(row_id))                
        return row_id

    def _csr_search(self, column, value):
        """ load ca key from database """
        self.logger.debug('CAhandler._csr_search()')

        # query database for key
        self._db_open()
        pre_statement = '''SELECT * from view_requests WHERE {0} LIKE ?'''.format(column)
        self.cursor.execute(pre_statement, [value])

        try:
            db_result = dict_from_row(self.cursor.fetchone())
        except BaseException:
            db_result = {}
        self._db_close()

        return db_result

    def _db_open(self):
        """ opens db and sets cursor """
        self.dbs = sqlite3.connect(self.xdb_file)
        self.dbs.row_factory = sqlite3.Row
        self.cursor = self.dbs.cursor()

    def _db_close(self):
        """ commit and close """
        # self.logger.debug('DBStore._db_close()')
        self.dbs.commit()
        self.dbs.close()
        # self.logger.debug('DBStore._db_close() ended')

    def _item_insert(self, item_dic):
        """ insert new entry to item_table """
        self.logger.debug('CAhandler._item_insert()')
        row_id = None
        # insert
        if item_dic:
            if 'name' in item_dic and 'type' in item_dic and 'source' in item_dic and 'date' in item_dic and 'comment' in item_dic:
                self._db_open()
                self.cursor.execute('''INSERT INTO ITEMS(name, type, source, date, comment) VALUES(:name, :type, :source, :date, :comment)''', item_dic)
                row_id = self.cursor.lastrowid
                # update stamp field
                data_dic = {'stamp': row_id}
                self.cursor.execute('''UPDATE ITEMS SET stamp = :stamp WHERE id = :stamp''', data_dic)
                self._db_close()
            else:                
                self.logger.error('CAhandler._insert_insert() aborted. dataset incomplete: {}'.format(item_dic))                
        else:
            self.logger.error('CAhandler._insert_insert() aborted. dataset empty')    
            
        self.logger.debug('CAhandler._item_insert() ended with row_id: {0}'.format(row_id))
        return row_id


    def _stub_func(self, parameter):
        """" load config from file """
        self.logger.debug('CAhandler._stub_func({0})'.format(parameter))

        self.logger.debug('CAhandler._stub_func() ended')


    def enroll(self, csr):
        """ enroll certificate  """
        self.logger.debug('CAhandler.enroll()')

        cert_bundle = None
        cert_raw = None

        error = self._config_check()

        if not error:


            self._csr_import(csr)
            # prepare the CSR
            # csr = build_pem_file(self.logger, None, b64_url_recode(self.logger, csr), None, True)

            # load ca cert and key
            # (ca_key, ca_cert) = self._ca_load()

        self.logger.debug('Certificate.enroll() ended')
        return(error, cert_bundle, cert_raw, None)

    def poll(self, cert_name, poll_identifier, _csr):
        """ poll status of pending CSR and download certificates """
        self.logger.debug('CAhandler.poll()')

        error = None
        cert_bundle = None
        cert_raw = None
        rejected = False
        self._stub_func(cert_name)

        self.logger.debug('CAhandler.poll() ended')
        return(error, cert_bundle, cert_raw, poll_identifier, rejected)

    def revoke(self, _cert, _rev_reason, _rev_date):
        """ revoke certificate """
        self.logger.debug('CAhandler.revoke()')

        code = 500
        message = 'urn:ietf:params:acme:error:serverInternal'
        detail = 'Revocation is not supported.'

        self.logger.debug('Certificate.revoke() ended')
        return(code, message, detail)

    def trigger(self, payload):
        """ process trigger message and return certificate """
        self.logger.debug('CAhandler.trigger()')

        error = None
        cert_bundle = None
        cert_raw = None
        self._stub_func(payload)

        self.logger.debug('CAhandler.trigger() ended with error: {0}'.format(error))
        return (error, cert_bundle, cert_raw)
