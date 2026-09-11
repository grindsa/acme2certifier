#!/usr/bin/python
# -*- coding: utf-8 -*-
"""tests for .github/scripts/xca_sqlite_dump.py"""

import io
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".github", "scripts"))

from xca_sqlite_dump import dump_xca_sqlite  # noqa: E402


def _xdb_path() -> str:
    return os.path.join(os.path.dirname(__file__), "ca", "acme2certifier-clean.xdb")


class TestXcaSqliteDump(unittest.TestCase):
    """CI import helper must not emit sqlite-only dump functions."""

    def test_001_mysql_dump_has_no_unistr(self):
        """mysql dump uses literal newlines instead of unistr()/char()"""
        buf = io.StringIO()
        dump_xca_sqlite(_xdb_path(), "mysql", buf)
        sql = buf.getvalue()
        self.assertIn("SET SESSION SQL_MODE='ANSI';", sql)
        self.assertNotIn("unistr(", sql)
        self.assertNotIn("char(10)", sql.lower())
        self.assertIn('INSERT INTO "items"', sql)
        self.assertIn("wurde neu erstellt", sql)
        self.assertIn("\n", sql)

    def test_002_postgresql_dump_has_no_unistr(self):
        """postgresql dump is free of sqlite dump helpers"""
        buf = io.StringIO()
        dump_xca_sqlite(_xdb_path(), "postgresql", buf)
        sql = buf.getvalue()
        self.assertNotIn("SET SESSION SQL_MODE", sql)
        self.assertNotIn("unistr(", sql)
        self.assertIn("CREATE TABLE items", sql)
        self.assertIn("CREATE VIEW view_certs", sql)
        self.assertGreater(sql.count("INSERT INTO"), 10)

    def test_003_item_comment_keeps_newline(self):
        """item comments retain the newline that sqlite dumps as unistr"""
        buf = io.StringIO()
        dump_xca_sqlite(_xdb_path(), "postgresql", buf)
        self.assertRegex(
            buf.getvalue(),
            r"angewendet\)\n\(Der Schlüssel",
        )

    def test_004_postgresql_inserts_match_folded_identifiers(self):
        """quoted INSERTs must use folded names to match unquoted CREATE TABLE"""
        buf = io.StringIO()
        dump_xca_sqlite(_xdb_path(), "postgresql", buf)
        sql = buf.getvalue()
        self.assertIn('INSERT INTO "private_keys" ("item", "ownpass", "private")', sql)
        self.assertNotIn('"ownPass"', sql)
        self.assertIn('INSERT INTO "revocations" ("caid"', sql)
        self.assertNotIn('"caId"', sql)
        self.assertIn('INSERT INTO "public_keys"', sql)
        self.assertIn('"public"', sql)


if __name__ == "__main__":
    unittest.main()
