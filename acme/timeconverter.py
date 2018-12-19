#!/usr/bin/python
# -*- coding: utf-8 -*-
""" Timeconverter class """
from __future__ import print_function
from datetime import datetime
import time
import calendar
import pytz 

class Timeconverter(object):
    """ Timeconverter """
    def __init__(self):
        pass
        
    def uts_to_date_utc(self, uts, format='%Y-%m-%dT%H:%M:%S'):
        """ convert unix timestamp to date format """
        date_string = datetime.fromtimestamp(int(uts),tz=pytz.utc).strftime(format)
        return(date_string)
            
    def date_to_uts_utc(self, date_human, format='%Y-%m-%dT%H:%M:%S'):
        """ convert date to unix timestamp """
        uts = calendar.timegm(time.strptime(date_human, format))            
        return(uts)
        
