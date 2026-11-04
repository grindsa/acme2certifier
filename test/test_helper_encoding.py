# -*- coding: utf-8 -*-
"""unittests for helpers/encoding.py"""

# pylint: disable=C0415
import base64
import logging
import sys
import unittest

sys.path.insert(0, ".")
sys.path.insert(1, "..")


class TestEncodingHelper(unittest.TestCase):
    """test class for b64decode_pad"""

    def setUp(self):
        """setup unittest"""
        logging.basicConfig(level=logging.CRITICAL)
        from acme2certifier.acme_srv.helpers.encoding import b64decode_pad

        self.b64decode_pad = b64decode_pad
        self.logger = logging.getLogger("test")

    def test_b64decode_pad_valid_utf8(self):
        """valid base64 with UTF-8 content decodes normally"""
        payload = base64.urlsafe_b64encode(b'{"a": 1}').decode()
        self.assertEqual('{"a": 1}', self.b64decode_pad(self.logger, payload))

    def test_b64decode_pad_missing_padding(self):
        """missing trailing padding is added before decoding"""
        payload = base64.urlsafe_b64encode(b"hello").decode().rstrip("=")
        self.assertEqual("hello", self.b64decode_pad(self.logger, payload))

    def test_b64decode_pad_non_utf8_returns_error_marker(self):
        """valid base64 decoding to non-UTF-8 bytes must not raise

        Before the fix this raised UnicodeDecodeError because the decode()
        call sat outside the try block.
        """
        payload = base64.urlsafe_b64encode(b"\xff\xfe").decode()
        self.assertEqual(
            "ERR: b64 decoding error", self.b64decode_pad(self.logger, payload)
        )


if __name__ == "__main__":
    unittest.main()
