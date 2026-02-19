# -*- coding: utf-8 -*-
"""Date and time utilities for acme2certifier"""
import calendar
import datetime
import pytz
from dateutil.parser import parse


def uts_now():
    """unixtimestamp in utc"""
    return calendar.timegm(datetime.datetime.now(datetime.timezone.utc).utctimetuple())


def uts_to_date_utc(uts: int, tformat: str = "%Y-%m-%dT%H:%M:%SZ") -> str:
    """convert unix timestamp to date format"""
    return datetime.datetime.fromtimestamp(int(uts), tz=pytz.utc).strftime(tformat)


def date_to_uts_utc(date_human: str, _tformat: str = "%Y-%m-%dT%H:%M:%S") -> int:
    """convert date to unix timestamp"""
    if isinstance(date_human, datetime.datetime):
        # we already got an datetime object as input
        result = calendar.timegm(date_human.timetuple())
    else:
        result = int(calendar.timegm(parse(date_human).timetuple()))
    return result


def date_to_datestr(
    date: datetime.datetime, tformat: str = "%Y-%m-%dT%H:%M:%SZ"
) -> str:
    """convert dateobj to datestring"""
    try:
        result = date.strftime(tformat)
    except Exception:
        result = None
    return result


def datestr_to_date(datestr: str, tformat: str = "%Y-%m-%dT%H:%M:%S") -> str:
    """convert datestr to dateobj"""
    try:
        result = datetime.datetime.strptime(datestr, tformat)
    except Exception:
        result = None
    return result
