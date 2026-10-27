# -*- coding: utf-8 -*-
"""Tests for acme_srv.helpers.datetime_utils."""

from __future__ import annotations

import datetime

import pytest

from acme2certifier.acme_srv.helpers.datetime_utils import (
    date_to_datestr,
    date_to_uts_utc,
    datestr_to_date,
    duration_to_seconds,
    uts_now,
    uts_to_date_utc,
)

pytestmark = pytest.mark.usefixtures("clear_config_cache", "_silence_logging")


def test_021_helper_uts_to_date_utc() -> None:
    """test uts_to_date_utc for a given format"""
    assert "2018-12-01" == uts_to_date_utc(1543640400, "%Y-%m-%d")


def test_022_helper_uts_to_date_utc() -> None:
    """test uts_to_date_utc without format"""
    assert "2018-12-01T05:00:00Z" == uts_to_date_utc(1543640400)


def test_023_helper_date_to_uts_utc() -> None:
    """test date_to_uts_utc for a given format"""
    assert 1543622400 == date_to_uts_utc("2018-12-01", "%Y-%m-%d")


def test_024_helper_date_to_uts_utc() -> None:
    """test date_to_uts_utc without format"""
    assert 1543640400 == date_to_uts_utc("2018-12-01T05:00:00")


def test_025_helper_date_to_uts_utc() -> None:
    """test date_to_uts_utc with a datestring"""
    timestamp = datetime.datetime(2018, 12, 1, 5, 0, 1)
    assert 1543640401 == date_to_uts_utc(timestamp)


def test_026_helper_duration_to_seconds_int() -> None:
    """duration_to_seconds: plain integer seconds"""
    assert 172800 == duration_to_seconds(172800)
    assert 1 == duration_to_seconds(1)


def test_027_helper_duration_to_seconds_numeric_string() -> None:
    """duration_to_seconds: numeric string without unit (seconds)"""
    assert 90 == duration_to_seconds("90")
    assert 172800 == duration_to_seconds("172800")


def test_028_helper_duration_to_seconds_units() -> None:
    """duration_to_seconds: s/m/h/d/w unit suffixes"""
    assert 90 == duration_to_seconds("90s")
    assert 1800 == duration_to_seconds("30m")
    assert 172800 == duration_to_seconds("48h")
    assert 172800 == duration_to_seconds("2d")
    assert 259200 == duration_to_seconds("3d")
    assert 604800 == duration_to_seconds("1w")


def test_029_helper_duration_to_seconds_case_and_whitespace() -> None:
    """duration_to_seconds: case-insensitive units and surrounding whitespace"""
    assert 172800 == duration_to_seconds("2D")
    assert 3600 == duration_to_seconds("1H")
    assert 172800 == duration_to_seconds(" 2d ")
    assert 1800 == duration_to_seconds("30 m")


def test_030_helper_duration_to_seconds_invalid() -> None:
    """duration_to_seconds: reject non-positive and malformed values"""
    for value in (
        0,
        -1,
        "-1d",
        "0d",
        "0",
        "",
        "   ",
        "foo",
        "2x",
        "d2",
        "1.5d",
        "2dd",
        True,
        False,
    ):
        with pytest.raises(ValueError):
            duration_to_seconds(value)


def test_071_helper_date_to_datestr() -> None:
    """convert dateobj to date-string with default format"""
    assert "2019-10-27T00:00:00Z" == date_to_datestr(datetime.date(2019, 10, 27))


def test_072_helper_date_to_datestr() -> None:
    """convert dateobj to date-string with a predefined format"""
    assert "2019.10.27" == date_to_datestr(datetime.date(2019, 10, 27), "%Y.%m.%d")


def test_073_helper_date_to_datestr() -> None:
    """convert dateobj to date-string for an knvalid date"""
    assert None == date_to_datestr("foo", "%Y.%m.%d")


def test_074_helper_datestr_to_date() -> None:
    """convert datestr to date with default format"""
    assert datetime.datetime(2019, 11, 27, 0, 1, 2) == datestr_to_date(
        "2019-11-27T00:01:02"
    )


def test_075_helper_datestr_to_date() -> None:
    """convert datestr to date with predefined format"""
    assert datetime.datetime(2019, 11, 27, 0, 0, 0) == datestr_to_date(
        "2019.11.27", "%Y.%m.%d"
    )


def test_076_helper_datestr_to_date() -> None:
    """convert datestr to date with invalid format"""
    assert None == datestr_to_date("foo", "%Y.%m.%d")


def test_362_uts_now() -> None:
    """test uts_now()"""
    assert isinstance(uts_now(), int)
