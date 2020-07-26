#!/usr/bin/python
# -*- coding: utf-8 -*-
""" Housekeeping class """
from __future__ import print_function
import time
import csv
import json
from acme.db_handler import DBstore
from acme.helper import load_config, uts_to_date_utc, cert_dates_get

class Housekeeping(object):
    """ Housekeeping class """
    def __init__(self, debug=None, logger=None):
        self.logger = logger
        self.dbstore = DBstore(debug, self.logger)

    def __enter__(self):
        """ Makes ACMEHandler a Context Manager """
        self._config_load()
        return self

    def __exit__(self, *args):
        """ cose the connection at the end of the context """

    def _certificatelist_get(self):
        """ get list of certs from database """
        self.logger.debug('Housekeeping._certlist_get()')
        return self.dbstore.certificatelist_get()

    def _config_load(self):
        """ load config from file """
        self.logger.debug('Housekeeping._config_load()')
        config_dic = load_config()
        if 'Housekeeping' in config_dic:
            pass

    def _convert_dates(self, cert_list):
        """ convert dates from uts to real date """
        self.logger.debug('Housekeeping._convert_dates()')
        for cert in cert_list:
            if 'order__expires' in cert:
                cert['order__expires'] = uts_to_date_utc(cert['order__expires'], '%Y-%m-%d %H:%M:%S')

            # set uts to 0 if we do not have them in dictionary
            if 'issue_uts' not in cert or 'expire_uts' not in cert:
                cert['issue_uts'] = 0
                cert['expire_uts'] = 0

            # if uts is zero we try to get the dates from certificate
            if cert['issue_uts'] == 0 or cert['expire_uts'] == 0:
                # cover cases without certificate in dict
                if 'cert_raw' in cert:
                    (issue_date, expire_date) = cert_dates_get(self.logger, cert['cert_raw'])
                    cert['issue_uts'] = issue_date
                    cert['expire_uts'] = expire_date
                else:
                    cert['issue_uts'] = 0
                    cert['expire_uts'] = 0

            if cert['issue_uts'] > 0 and cert['expire_uts'] > 0:
                cert['issue_date'] = uts_to_date_utc(cert['issue_uts'], '%Y-%m-%d %H:%M:%S')
                cert['expire_date'] = uts_to_date_utc(cert['expire_uts'], '%Y-%m-%d %H:%M:%S')
            else:
                cert['issue_date'] = ''
                cert['expire_date'] = ''

        return cert_list

    def _csv_dump(self, filename, content):
        """ dump content csv file """
        self.logger.debug('Housekeeping._csv_dump()')
        with open(filename, 'w', newline='') as file_:
            writer = csv.writer(file_, delimiter=',', quotechar='"', quoting=csv.QUOTE_NONNUMERIC)
            writer.writerows(content)

    def _json_dump(self, file_name_, data_):
        """ dump content json file """
        self.logger.debug('Housekeeping._json_dump()')
        jdump = json.dumps(data_, ensure_ascii=False, indent=4, default=str)
        with open(file_name_, 'w', encoding='utf-8') as out_file:
            out_file.write(jdump)

    def _to_list(self, field_list, cert_list):
        """ convert query to csv format """
        self.logger.debug('Housekeeping._to_list()')
        csv_list = []

        # attach fieldlist as first row
        if field_list:
            csv_list.append(field_list)
        for cert in cert_list:
            tmp_list = []
            # enumarte fields and store them in temporary list
            for field in field_list:
                # in case we are missing a field put empty string in
                if field in cert:
                    try:
                        # we need to deal with some errors from past
                        value = cert[field].replace('\r\n', '\n')
                        value = value.replace('\r', '')
                        value = value.replace('\n', '')
                        tmp_list.append(value)
                    except BaseException:
                        tmp_list.append(cert[field])
                else:
                    tmp_list.append('')

            # append list to output
            csv_list.append(tmp_list)
        self.logger.debug('Housekeeping._to_list() ended with {0} entries'.format(len(csv_list)))
        return csv_list

    def certreport_get(self, report_format='csv', filename='cert_report_{0}'.format(uts_to_date_utc(int(time.time()), '%Y-%m-%d-%H%M%S'))):
        """ get certificate report """
        self.logger.debug('Housekeeping.certreport_get()')

        (field_list, cert_list) = self._certificatelist_get()
        # convert dates into human readable format
        cert_list = self._convert_dates(cert_list)

        # extend list by additional fields to have the fileds in output
        field_list.extend(['issue_date', 'expire_date'])

        self.logger.debug('output to dump: {0}.{1}'.format(filename, report_format))
        if report_format == 'csv':
            self.logger.debug('Housekeeping.certreport_get() dump in csv-format')
            csv_list = self._to_list(field_list, cert_list)
            self._csv_dump('{0}.{1}'.format(filename, report_format), csv_list)
        elif report_format == 'json':
            self.logger.debug('Housekeeping.certreport_get() dump in json-format')
            self._json_dump('{0}.{1}'.format(filename, report_format), cert_list)
        else:
            self.logger.error('Housekeeping.certreport_get() cannot dump as format is unknown')
