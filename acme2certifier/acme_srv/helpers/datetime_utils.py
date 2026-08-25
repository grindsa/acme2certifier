# -*- coding: utf-8 -*-
"""Date and time utilities for acme2certifier"""

import calendar
import datetime
import re
from typing import Union

import pytz
from dateutil.parser import parse

_DURATION_RE = re.compile(r"^(\d+)\s*([smhdw]?)$", re.IGNORECASE)
_DURATION_UNIT_SECONDS = {
    "": 1,
    "s": 1,
    "m": 60,
    "h": 3600,
    "d": 86400,
    "w": 604800,
}


def duration_to_seconds(value: Union[str, int]) -> int:
    """Parse a duration into seconds.

    Accepts plain integers (seconds) or strings with an optional unit suffix:
    ``s`` (seconds), ``m`` (minutes), ``h`` (hours), ``d`` (days), ``w`` (weeks).
    Examples: ``172800``, ``"2d"``, ``"48h"``, ``"30m"``.
    """
    if isinstance(value, bool):
        raise ValueError(f"invalid duration: {value!r}")
    if isinstance(value, int):
        if value <= 0:
            raise ValueError("duration must be positive")
        return value

    text = str(value).strip()
    if not text:
        raise ValueError("empty duration")

    match = _DURATION_RE.match(text)
    if not match:
        raise ValueError(f"invalid duration: {value!r}")

    amount = int(match.group(1))
    unit = match.group(2).lower()
    seconds = amount * _DURATION_UNIT_SECONDS[unit]
    if seconds <= 0:
        raise ValueError("duration must be positive")
    return seconds


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
