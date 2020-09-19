#!/usr/bin/python
# -*- coding: utf-8 -*-
""" handler for an openssl ca """
from __future__ import print_function
import os
import sqlite3
import uuid
import json
from OpenSSL import crypto
# pylint: disable=E0401
from acme.helper import load_config, build_pem_file, uts_now, uts_to_date_utc, b64_encode, b64_decode, b64_url_recode, cert_serial_get, convert_string_to_byte, convert_byte_to_string, csr_cn_get, csr_san_get


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
        self.issuing_ca_key = None
        self.cert_validity_days = 365
        self.ca_cert_chain_list = []
        self.template_name = None

    def __enter__(self):
        """ Makes ACMEHandler a Context Manager """
        if not self.xdb_file:
            self._config_load()
        return self

    def __exit__(self, *args):
        """ cose the connection at the end of the context """

    def _asn1_stream_parse(self, asn1_stream=None):
        """ parse asn_string """

        self.logger.debug('CAhandler._asn1_stream_parse()')
        oid_dic = {
            "2.5.4.3": "commonName",
            "2.5.4.4": "surname",
            "2.5.4.5": "serialNumber",
            "2.5.4.6": "countryName",
            "2.5.4.7": "localityName",
            "2.5.4.8": "stateOrProvinceName",
            "2.5.4.9": "streetAddress",
            "2.5.4.10": "organizationName",
            "2.5.4.11": "organizationalUnitName",
            "2.5.4.12": "title",
            "2.5.4.13": "description",
            "2.5.4.42": "givenName",
        }

        dn_dic = {}
        if asn1_stream:
            # cut first 8 bytes which are bogus
            asn1_stream = asn1_stream[8:]

            # print(asn1_stream)
            stream_list = asn1_stream.split(b'\x06\x03\x55')

            # we have to remove the first element from list as it contains junk
            stream_list.pop(0)

            for ele in stream_list:
                oid = '2.5.{0}.{1}'.format(ele[0], ele[1])
                if oid in oid_dic:
                    value_len = ele[3]
                    value = ele[4:4 + value_len]
                    dn_dic[oid_dic[oid]] = value.decode('utf-8')

            self.logger.debug('CAhandler._asn1_stream_parse() ended: {0}'.format(bool(dn_dic)))
        return dn_dic

    def _ca_cert_load(self):
        """ load ca key from database """
        self.logger.debug('CAhandler._ca_cert_load({0})'.format(self.issuing_ca_name))

        # query database for key
        self._db_open()
        pre_statement = '''SELECT * from view_certs WHERE name LIKE ?'''
        self.cursor.execute(pre_statement, [self.issuing_ca_name])
        try:
            db_result = dict_from_row(self.cursor.fetchone())
        except BaseException:
            self.logger.error('cert lookup failed: {0}'.format(self.cursor.fetchone()))
            db_result = {}
        self._db_close()

        ca_cert = None
        ca_id = None

        if 'cert' in db_result:
            try:
                ca_cert = crypto.load_certificate(crypto.FILETYPE_ASN1, b64_decode(self.logger, db_result['cert']))
                ca_id = db_result['id']
            except BaseException as err_:
                self.logger.error('CAhandler._ca_cert_load() failed with error: {0}'.format(err_))
        return (ca_cert, ca_id)

    def _ca_key_load(self):
        """ load ca key from database """
        self.logger.debug('CAhandler._ca_key_load({0})'.format(self.issuing_ca_key))

        # query database for key
        self._db_open()
        pre_statement = '''SELECT * from view_private WHERE name LIKE ?'''
        self.cursor.execute(pre_statement, [self.issuing_ca_key])
        try:
            db_result = dict_from_row(self.cursor.fetchone())
        except BaseException as err_:
            self.logger.error('key lookup failed: {0}'.format(self.cursor.fetchone()))
            db_result = {}
        self._db_close()

        ca_key = None
        if db_result and 'private' in db_result:
            try:
                private_key = '-----BEGIN ENCRYPTED PRIVATE KEY-----\n{0}\n-----END ENCRYPTED PRIVATE KEY-----'.format(db_result['private'])
                ca_key = crypto.load_privatekey(crypto.FILETYPE_PEM, private_key, convert_string_to_byte(self.passphrase))

            except BaseException as err_:
                self.logger.error('CAhandler._ca_key_load() failed with error: {0}'.format(err_))
        else:
            self.logger.error('CAhandler._ca_key_load() failed to load key: {0}'.format(db_result))

        self.logger.debug('CAhandler._ca_key_load() ended')
        return ca_key

    def _ca_load(self):
        """ load ca key and cert """
        self.logger.debug('CAhandler._ca_load()')
        ca_key = self._ca_key_load()
        (ca_cert, ca_id) = self._ca_cert_load()

        self.logger.debug('CAhandler._ca_load() ended')
        return(ca_key, ca_cert, ca_id)

    def _config_check(self):
        """ check config for consitency """
        self.logger.debug('CAhandler._config_check()')
        error = None

        if self.xdb_file:
            if not os.path.exists(self.xdb_file):
                error = 'xdb_file {0} does not exist'.format(self.xdb_file)
                self.xdb_file = None
        else:
            error = 'xdb_file must be specified in config file'

        if not error:
            if not self.issuing_ca_name:
                error = 'issuing_ca_name must be set in config file'

        if error:
            self.logger.debug('CAhandler config error: {0}'.format(error))

        if not self.issuing_ca_key:
            self.logger.debug('use self.issuing_ca_name as self.issuing_ca_key: {0}'.format(self.issuing_ca_name))
            self.issuing_ca_key = self.issuing_ca_name

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

        if 'issuing_ca_key' in config_dic['CAhandler']:
            self.issuing_ca_key = config_dic['CAhandler']['issuing_ca_key']

        if 'ca_cert_chain_list' in config_dic['CAhandler']:
            try:
                self.ca_cert_chain_list = json.loads(config_dic['CAhandler']['ca_cert_chain_list'])
            except BaseException:
                self.logger.error('CAhandler._config_load(): parameter "ca_cert_chain_list" cannot be loaded')

        if 'template_name' in config_dic['CAhandler']:
            self.template_name = config_dic['CAhandler']['template_name']

    def _csr_import(self, csr, request_name):
        """ check existance of csr and load into db """
        self.logger.debug('CAhandler._csr_insert()')

        csr_info = self._csr_search('request', csr)

        if not csr_info:

            # csr does not exist in db - lets import it
            insert_date = uts_to_date_utc(uts_now(), '%Y%m%d%H%M%SZ')
            item_dic = {'type': 2, 'comment': 'from acme2certifier', 'source': 2, 'date': insert_date, 'name': request_name}
            row_id = self._item_insert(item_dic)

            # insert csr
            csr_info = {'item': row_id, 'signed': 1, 'request': csr}
            self._csr_insert(csr_info)

        self.logger.debug('CAhandler._csr_insert()')
        return csr_info

    def _cert_insert(self, cert_dic):
        """ insert new entry to request table """
        self.logger.debug('CAhandler._cert_insert()')

        row_id = None
        if cert_dic:
            if all(key in cert_dic for key in ('item', 'serial', 'issuer', 'ca', 'cert', 'iss_hash', 'hash')):
                # pylint: disable=R0916
                if isinstance(cert_dic['item'], int) and isinstance(cert_dic['issuer'], int)  and isinstance(cert_dic['ca'], int) and isinstance(cert_dic['iss_hash'], int) and isinstance(cert_dic['iss_hash'], int) and isinstance(cert_dic['hash'], int):
                    self._db_open()
                    self.cursor.execute('''INSERT INTO CERTS(item, serial, issuer, ca, cert, hash, iss_hash) VALUES(:item, :serial, :issuer, :ca, :cert, :hash, :iss_hash)''', cert_dic)
                    row_id = self.cursor.lastrowid
                    self._db_close()
                else:
                    self.logger.error('CAhandler._cert_insert() aborted. wrong datatypes: {}'.format(cert_dic))
            else:
                self.logger.error('CAhandler._cert_insert() aborted. dataset incomplete: {}'.format(cert_dic))
        else:
            self.logger.error('CAhandler._cert_insert() aborted. dataset empty')

        self.logger.debug('CAhandler._cert_insert() ended with row_id: {0}'.format(row_id))
        return row_id

    def _cert_search(self, column, value):
        """ load ca key from database """
        self.logger.debug('CAhandler._cert_search({0}:{1})'.format(column, value))

        # query database for key
        self._db_open()
        pre_statement = '''SELECT * from items WHERE type == 3 and {0} LIKE ?'''.format(column)
        self.cursor.execute(pre_statement, [value])

        cert_result = {}
        try:
            item_result = dict_from_row(self.cursor.fetchone())
        except BaseException:
            self.logger.error('CAhandler._cert_search(): item search failed: {0}'.format(self.cursor.fetchone()))
            item_result = {}

        if item_result:
            item_id = item_result['id']
            pre_statement = '''SELECT * from certs WHERE item LIKE ?'''
            self.cursor.execute(pre_statement, [item_id])
            try:
                cert_result = dict_from_row(self.cursor.fetchone())
            except BaseException:
                self.logger.error('CAhandler._cert_search(): cert search failed: item: {0}'.format(item_id))

        self._db_close()
        self.logger.debug('CAhandler._cert_search() ended')
        return cert_result

    def _csr_insert(self, csr_dic):
        """ insert new entry to request table """
        self.logger.debug('CAhandler._csr_insert()')
        row_id = None
        if csr_dic:
            if all(key in csr_dic for key in ('item', 'signed', 'request')):
                # item and signed must be integer
                if isinstance(csr_dic['item'], int) and isinstance(csr_dic['signed'], int):
                    self._db_open()
                    self.cursor.execute('''INSERT INTO REQUESTS(item, signed, request) VALUES(:item, :signed, :request)''', csr_dic)
                    row_id = self.cursor.lastrowid
                    self._db_close()
                else:
                    self.logger.error('CAhandler._csr_insert() aborted. wrong datatypes: {}'.format(csr_dic))
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
        self.logger.debug('CAhandler._csr_search() ended')
        return db_result

    def _db_open(self):
        """ opens db and sets cursor """
        # pylint: disable=W0201
        self.dbs = sqlite3.connect(self.xdb_file)
        self.dbs.row_factory = sqlite3.Row
        # pylint: disable=W0201
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
            if all(key in item_dic for key in ('name', 'type', 'source', 'date', 'comment')):
                if isinstance(item_dic['type'], int) and isinstance(item_dic['source'], int):
                    self._db_open()
                    self.cursor.execute('''INSERT INTO ITEMS(name, type, source, date, comment) VALUES(:name, :type, :source, :date, :comment)''', item_dic)
                    row_id = self.cursor.lastrowid
                    # update stamp field
                    data_dic = {'stamp': row_id}
                    self.cursor.execute('''UPDATE ITEMS SET stamp = :stamp WHERE id = :stamp''', data_dic)
                    self._db_close()
                else:
                    self.logger.error('CAhandler._insert_insert() aborted. wrong datatypes: {}'.format(item_dic))
            else:
                self.logger.error('CAhandler._item_insert() aborted. dataset incomplete: {}'.format(item_dic))
        else:
            self.logger.error('CAhandler._insert_insert() aborted. dataset empty')

        self.logger.debug('CAhandler._item_insert() ended with row_id: {0}'.format(row_id))
        return row_id

    def _pemcertchain_generate(self, ee_cert, issuer_cert):
        """ build pem chain """
        self.logger.debug('CAhandler._pemcertchain_generate()')

        if issuer_cert:
            pem_chain = '{0}{1}'.format(ee_cert, issuer_cert)
        else:
            pem_chain = ee_cert

        for cert in self.ca_cert_chain_list:
            cert_dic = self._cert_search('items.name', cert)
            if cert_dic and 'cert' in cert_dic:
                ca_cert = crypto.load_certificate(crypto.FILETYPE_ASN1, b64_decode(self.logger, cert_dic['cert']))
                pem_chain = '{0}{1}'.format(pem_chain, convert_byte_to_string(crypto.dump_certificate(crypto.FILETYPE_PEM, ca_cert)))

        self.logger.debug('CAhandler._pemcertchain_generate() ended')
        return pem_chain

    def _requestname_get(self, csr):
        """ enroll certificate  """
        self.logger.debug('CAhandler._request_name_get()')

        # try to get cn for a name in database
        request_name = csr_cn_get(self.logger, csr)
        if not request_name:
            san_list = csr_san_get(self.logger, csr)
            try:
                (_identifiier, request_name,) = san_list[0].split(':')
            except BaseException:
                pass

        self.logger.debug('CAhandler._request_name_get() ended with: {0}'.format(request_name))
        return request_name

    def _revocation_insert(self, rev_dic):
        """ insert new entry to into revocation_table """
        self.logger.debug('CAhandler._revocation_insert()')
        row_id = None
        # insert
        if rev_dic:
            if all(key in rev_dic for key in ('caID', 'serial', 'date', 'invaldate', 'reasonBit')):
                if isinstance(rev_dic['caID'], int) and isinstance(rev_dic['reasonBit'], int):
                    self._db_open()
                    self.cursor.execute('''INSERT INTO REVOCATIONS(caID, serial, date, invaldate, reasonBit) VALUES(:caID, :serial, :date, :invaldate, :reasonBit)''', rev_dic)
                    row_id = self.cursor.lastrowid
                    self._db_close()
                else:
                    self.logger.error('CAhandler._revocation_insert() aborted. wrong datatypes: {}'.format(rev_dic))
            else:
                self.logger.error('CAhandler._revocation_insert() aborted. dataset incomplete: {}'.format(rev_dic))
        else:
            self.logger.error('CAhandler._revocation_insert() aborted. dataset empty')

        self.logger.debug('CAhandler._revocation_insert() ended with row_id: {0}'.format(row_id))
        return row_id

    def _revocation_search(self, column, value):
        """ load ca key from database """
        self.logger.debug('CAhandler._revocation_search()')
        # query database for key
        self._db_open()
        pre_statement = '''SELECT * from revocations WHERE {0} LIKE ?'''.format(column)
        self.cursor.execute(pre_statement, [value])

        try:
            db_result = dict_from_row(self.cursor.fetchone())
        except BaseException:
            db_result = {}
        self._db_close()
        self.logger.debug('CAhandler._revocation_search() ended')
        return db_result

    # pylint: disable=R0913
    def _store_cert(self, ca_id, cert_name, serial, cert, name_hash, issuer_hash):
        """ store certificate to database """
        self.logger.debug('CAhandler._store_cert()')

        # insert certificate into item table
        insert_date = uts_to_date_utc(uts_now(), '%Y%m%d%H%M%SZ')
        item_dic = {'type': 3, 'comment': 'from acme2certifier', 'source': 2, 'date': insert_date, 'name': cert_name}
        row_id = self._item_insert(item_dic)
        # insert certificate to cert table
        cert_dic = {'item': row_id, 'serial': serial, 'issuer': ca_id, 'ca': 0, 'cert': cert, 'iss_hash': issuer_hash, 'hash': name_hash}
        row_id = self._cert_insert(cert_dic)

        self.logger.debug('CAhandler._store_cert() ended')

    def _stream_split(self, byte_stream):
        """ split template in asn1 structure and utf_stream """
        self.logger.debug('CAhandler._stream_split()')
        asn1_stream = None
        utf_stream = None

        # convert to byte if not already done
        byte_stream = convert_string_to_byte(byte_stream)

        if byte_stream:
            # search pattern
            pos = byte_stream.find(b'\x00\x00\x00\x0c') + 4
            if pos != 3:
                # split file 3 bcs find returns -1 in case of no-match
                asn1_stream = byte_stream[:pos]
                utf_stream = byte_stream[pos:]

        self.logger.debug('CAhandler._stream_split() ended: {0}:{1}'.format(bool(asn1_stream), bool(utf_stream)))
        return(asn1_stream, utf_stream)

    def _stub_func(self, parameter):
        """" load config from file """
        self.logger.debug('CAhandler._stub_func({0})'.format(parameter))
        self.logger.debug('CAhandler._stub_func() ended')

    def _template_load(self):
        """ load template from database """
        self.logger.debug('CAhandler._template_load({0})'.format(self.template_name))
        # query database for template
        self._db_open()
        pre_statement = '''SELECT * from view_templates WHERE name LIKE ?'''
        self.cursor.execute(pre_statement, [self.template_name])
        try:
            db_result = dict_from_row(self.cursor.fetchone())
        except BaseException:
            self.logger.error('template lookup failed: {0}'.format(self.cursor.fetchone()))
            db_result = {}

        # parse template
        dn_dic = {}
        template_dic = {}
        if 'template' in db_result:
            byte_stream = b64_decode(self.logger, db_result['template'])
            (dn_dic, template_dic) = self._template_parse(byte_stream)
        self._db_close()
        self.logger.debug('CAhandler._template_load() ended')

        return(dn_dic, template_dic)

    def _template_parse(self, byte_string=None):
        """ process template """
        self.logger.debug('CAhandler._template_parse()')
        (asn1_stream, utf_stream) = self._stream_split(byte_string)

        dn_dic = {}
        if asn1_stream:
            dn_dic = self._asn1_stream_parse(asn1_stream)

        template_dic = {}
        if utf_stream:
            template_dic = self._utf_stream_parse(utf_stream)
            if template_dic:
                # replace '' with None
                template_dic = {k: None if not v else v for k, v in template_dic.items()}

        self.logger.debug('CAhandler._template_parse() ended')
        return (dn_dic, template_dic)

    def _utf_stream_parse(self, utf_stream=None):
        """ parse template information from utf_stream into dictitionary """
        self.logger.debug('CAhandler._utf_stream_parse()')
        template_dic = {}

        if utf_stream:
            stream_list = utf_stream.split(b'\x00\x00\x00')

            # iterate list and clean up parameter
            parameter_list = []
            for idx, ele in enumerate(stream_list):
                ele = ele.replace(b'\x00', b'')
                if idx > 0:
                    # strip the first character
                    ele = ele[1:]
                parameter_list.append(ele.decode('utf-8'))

            if parameter_list:
                if len(parameter_list) % 2 != 0:
                    # remove last element from list if amount of list entries is uneven
                    parameter_list.pop()
                # convert list into a directory
                template_dic = {item : parameter_list[index+1] for index, item in enumerate(parameter_list) if index % 2 == 0}

        self.logger.debug('CAhandler._utf_stream_parse() ended: {0}'.format(bool(template_dic)))
        return template_dic

    def enroll(self, csr):
        """ enroll certificate  """
        self.logger.debug('CAhandler.enroll()')

        cert_bundle = None
        cert_raw = None

        error = self._config_check()

        if not error:

            request_name = self._requestname_get(csr)

            # import CSR to database
            _csr_info = self._csr_import(csr, request_name)

            # prepare the CSR to be signed
            csr = build_pem_file(self.logger, None, b64_url_recode(self.logger, csr), None, True)

            # load ca cert and key
            (ca_key, ca_cert, ca_id) = self._ca_load()

            if ca_key and ca_cert:
                # load request
                req = crypto.load_certificate_request(crypto.FILETYPE_PEM, csr)

                # copy cn of request
                subject = req.get_subject()
                # rewrite CN if required
                if not subject.CN:
                    self.logger.debug('rewrite CN to {0}'.format(request_name))
                    subject.CN = request_name

                # load template if configured
                if self.template_name:
                    (_dn_dic, _template_dic) = self._template_load()

                cert = crypto.X509()
                cert.gmtime_adj_notBefore(0)
                cert.gmtime_adj_notAfter(self.cert_validity_days * 86400)
                cert.set_issuer(ca_cert.get_subject())
                cert.set_subject(subject)
                cert.set_pubkey(req.get_pubkey())
                cert.set_serial_number(uuid.uuid4().int & (1<<63)-1)
                cert.set_version(2)
                cert.add_extensions(req.get_extensions())
                default_extension_list = [
                    crypto.X509Extension(convert_string_to_byte('subjectKeyIdentifier'), False, convert_string_to_byte('hash'), subject=cert),
                    crypto.X509Extension(convert_string_to_byte('keyUsage'), True, convert_string_to_byte('digitalSignature,keyEncipherment')),
                    crypto.X509Extension(convert_string_to_byte('authorityKeyIdentifier'), False, convert_string_to_byte('keyid:always'), issuer=ca_cert),
                    crypto.X509Extension(convert_string_to_byte('basicConstraints'), True, convert_string_to_byte('CA:FALSE')),
                    crypto.X509Extension(convert_string_to_byte('extendedKeyUsage'), False, convert_string_to_byte('clientAuth,serverAuth')),
                ]

                # add default extensions
                cert.add_extensions(default_extension_list)

                print('boom')
                sys.exit(0)

                # sign csr
                cert.sign(ca_key, 'sha256')
                serial = cert.get_serial_number()

                # get hsshes
                issuer_hash = ca_cert.subject_name_hash() & 0x7fffffff
                name_hash = cert.subject_name_hash() & 0x7fffffff

                # store certificate
                self._store_cert(ca_id, request_name, '{:X}'.format(serial), convert_byte_to_string(b64_encode(self.logger, crypto.dump_certificate(crypto.FILETYPE_ASN1, cert))), name_hash, issuer_hash)

                cert_bundle = self._pemcertchain_generate(convert_byte_to_string(crypto.dump_certificate(crypto.FILETYPE_PEM, cert)), convert_byte_to_string(crypto.dump_certificate(crypto.FILETYPE_PEM, ca_cert)))
                cert_raw = convert_byte_to_string(b64_encode(self.logger, crypto.dump_certificate(crypto.FILETYPE_ASN1, cert)))

        self.logger.debug('Certificate.enroll() ended')
        return(error, cert_bundle, cert_raw, None)

    def poll(self, cert_name, poll_identifier, _csr):
        """ poll status of pending CSR and download certificates """
        self.logger.debug('CAhandler.poll()')

        error = 'Method not implemented.'
        cert_bundle = None
        cert_raw = None
        rejected = False
        self._stub_func(cert_name)

        self.logger.debug('CAhandler.poll() ended')
        return(error, cert_bundle, cert_raw, poll_identifier, rejected)

    def revoke(self, cert, rev_reason='unspecified', rev_date=None):
        """ revoke certificate """
        self.logger.debug('CAhandler.revoke()')

        # overwrite revocation date - we ignore what has been submitted
        rev_date = uts_to_date_utc(uts_now(), '%Y%m%d%H%M%SZ')
        rev_reason = 0

        if self.xdb_file:
            # load ca cert and key
            (_ca_key, _ca_cert, ca_id) = self._ca_load()

            serial = cert_serial_get(self.logger, cert)
            if serial:
                serial = '{:X}'.format(serial)

            if ca_id and serial:
                # check if certificate has alreay been revoked:
                if not self._revocation_search('serial', serial):
                    rev_dic = {'caID': ca_id, 'serial': serial, 'date': rev_date, 'invaldate': rev_date, 'reasonBit': rev_reason}
                    row_id = self._revocation_insert(rev_dic)
                    if row_id:
                        code = 200
                        message = None
                        detail = None
                    else:
                        code = 500
                        message = 'urn:ietf:params:acme:error:serverInternal'
                        detail = 'database update failed'
                else:
                    code = 400
                    message = 'urn:ietf:params:acme:error:alreadyRevoked'
                    detail = 'Certificate has already been revoked'
            else:
                code = 500
                message = 'urn:ietf:params:acme:error:serverInternal'
                detail = 'certificate lookup failed'
        else:
            code = 500
            message = 'urn:ietf:params:acme:error:serverInternal'
            detail = 'configuration error'

        self.logger.debug('Certificate.revoke() ended')
        return(code, message, detail)

    def trigger(self, payload):
        """ process trigger message and return certificate """
        self.logger.debug('CAhandler.trigger()')

        error = 'Method not implemented.'
        cert_bundle = None
        cert_raw = None
        self._stub_func(payload)

        self.logger.debug('CAhandler.trigger() ended with error: {0}'.format(error))
        return (error, cert_bundle, cert_raw)
