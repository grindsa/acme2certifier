#!/usr/bin/python
# -*- coding: utf-8 -*-
""" Timeconverter class """
from __future__ import print_function
from datetime import datetime
import time
import calendar
import pytz
from acme.helper import print_debug

class Timeconverter(object):
    """ Timeconverter """
    def __init__(self):
        pass

    def uts_to_date_utc(self, uts, format_='%Y-%m-%dT%H:%M:%S'):
        """ convert unix timestamp to date format """
        print_debug(self.debug, 'Timeconverter.uts_to_date_utc({0}:{1})'.format(uts, format_))
        date_string = datetime.fromtimestamp(int(uts), tz=pytz.utc).strftime(format_)
        return date_string

    def date_to_uts_utc(self, date_human, format_='%Y-%m-%dT%H:%M:%S'):
        """ convert date to unix timestamp """
        print_debug(self.debug, 'Timeconverter.date_to_uts_utc({0}:{1})'.format(date_human, format_))
        uts = calendar.timegm(time.strptime(date_human, format_))
        return uts
