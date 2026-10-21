# -*- coding: utf-8 -*-
"""Unit tests for allow_shortname_from_fqdn helpers."""

# pylint: disable=C0415, R0904, W0212
import logging
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, ".")
sys.path.insert(1, "..")

from acme2certifier.acme_srv.helpers.config import (
    config_shortname_denylist_load,
    warn_shortname_without_domainlist,
)
from acme2certifier.acme_srv.helpers.domain_utils import (
    allowed_domainlist_check,
    is_shortname_denied,
    is_single_label_name,
    shortname_covered_by_siblings,
)
from acme2certifier.acme_srv.helpers.eab import (
    _eab_profile_entry_check,
    eab_profile_list_check,
)


class TestShortnameFromFqdn(unittest.TestCase):
    """allow_shortname_from_fqdn helper behavior"""

    def setUp(self):
        """setup unittest"""
        logging.basicConfig(level=logging.CRITICAL)
        self.logger = logging.getLogger("test_a2c")

    def test_001_is_single_label_name_true(self):
        """single-label names are recognized"""
        self.assertTrue(is_single_label_name(self.logger, "host"))
        self.assertTrue(is_single_label_name(self.logger, "HOST"))
        self.assertTrue(is_single_label_name(self.logger, "  host  "))

    def test_002_is_single_label_name_false(self):
        """empty, wildcard, and multi-label names are not single-label"""
        self.assertFalse(is_single_label_name(self.logger, ""))
        self.assertFalse(is_single_label_name(self.logger, None))
        self.assertFalse(is_single_label_name(self.logger, "host.example.com"))
        self.assertFalse(is_single_label_name(self.logger, "*.example.com"))
        self.assertFalse(is_single_label_name(self.logger, "*"))
        self.assertFalse(is_single_label_name(self.logger, "host*"))

    def test_003_is_shortname_denied(self):
        """denylist match is case-insensitive and ignores surrounding space"""
        self.assertFalse(is_shortname_denied(self.logger, "mail", []))
        self.assertFalse(is_shortname_denied(self.logger, "mail", None))
        self.assertFalse(is_shortname_denied(self.logger, "web", ["mail", "vpn"]))
        self.assertTrue(is_shortname_denied(self.logger, "mail", ["mail", "vpn"]))
        self.assertTrue(is_shortname_denied(self.logger, "MAIL", ["mail"]))
        self.assertTrue(is_shortname_denied(self.logger, "  Vpn  ", ["vpn"]))

    def test_004_shortname_covered_matching_sibling(self):
        """shortname is covered by an allowed sibling FQDN"""
        siblings = ["host.intra.net", "host"]
        allowlist = ["*.intra.net"]
        self.assertTrue(
            shortname_covered_by_siblings(self.logger, "host", siblings, allowlist)
        )

    def test_005_shortname_covered_case_insensitive(self):
        """sibling and shortname comparison ignores case"""
        siblings = ["Host.Intra.Net"]
        allowlist = ["*.intra.net"]
        self.assertTrue(
            shortname_covered_by_siblings(self.logger, "HOST", siblings, allowlist)
        )

    def test_006_shortname_covered_missing_sibling(self):
        """shortname alone is not covered"""
        siblings = ["host"]
        allowlist = ["*.intra.net"]
        self.assertFalse(
            shortname_covered_by_siblings(self.logger, "host", siblings, allowlist)
        )

    def test_007_shortname_covered_wrong_first_label(self):
        """sibling FQDN with a different first label does not cover the shortname"""
        siblings = ["other.intra.net", "host"]
        allowlist = ["*.intra.net"]
        self.assertFalse(
            shortname_covered_by_siblings(self.logger, "host", siblings, allowlist)
        )

    def test_008_shortname_covered_wildcard_sibling_rejected(self):
        """a wildcard sibling does not cover a shortname"""
        siblings = ["*.intra.net", "host"]
        allowlist = ["*.intra.net"]
        self.assertFalse(
            shortname_covered_by_siblings(self.logger, "host", siblings, allowlist)
        )

    def test_009_shortname_covered_sibling_not_on_allowlist(self):
        """sibling FQDN outside the allowlist does not cover the shortname"""
        siblings = ["host.other.net", "host"]
        allowlist = ["*.intra.net"]
        self.assertFalse(
            shortname_covered_by_siblings(self.logger, "host", siblings, allowlist)
        )

    def test_010_shortname_covered_rejects_non_single_label(self):
        """a multi-label name is not treated as a shortname"""
        siblings = ["host.intra.net"]
        allowlist = ["*.intra.net"]
        self.assertFalse(
            shortname_covered_by_siblings(
                self.logger, "host.intra.net", siblings, allowlist
            )
        )

    def test_011_shortname_covered_ignores_ip_sibling(self):
        """an IP sibling does not cover a shortname"""
        siblings = ["10.0.0.1", "host"]
        allowlist = ["10.0.0.1", "*.intra.net"]
        self.assertFalse(
            shortname_covered_by_siblings(self.logger, "10", siblings, allowlist)
        )

    def test_012_config_shortname_denylist_load_valid(self):
        """JSON shortname_denylist is loaded from Order"""
        config_dic = {"Order": {"shortname_denylist": '["mail", "vpn"]'}}
        self.assertEqual(
            ["mail", "vpn"], config_shortname_denylist_load(self.logger, config_dic)
        )

    def test_013_config_shortname_denylist_load_empty(self):
        """missing Order or denylist yields an empty list"""
        self.assertEqual([], config_shortname_denylist_load(self.logger, {}))
        self.assertEqual([], config_shortname_denylist_load(self.logger, {"Order": {}}))

    def test_014_config_shortname_denylist_load_parse_error(self):
        """invalid JSON is reported and a warning is logged"""
        config_dic = {"Order": {"shortname_denylist": "not-json"}}
        with self.assertLogs("test_a2c", level="WARNING") as lcm:
            result = config_shortname_denylist_load(self.logger, config_dic)
        self.assertEqual("failed to parse", result)
        self.assertTrue(
            any("Failed to load shortname_denylist" in line for line in lcm.output)
        )

    def test_015_warn_shortname_without_domainlist_warns(self):
        """enabling shortnames without an allowlist logs a warning"""
        with self.assertLogs("test_a2c", level="WARNING") as lcm:
            warn_shortname_without_domainlist(self.logger, True, [])
        self.assertTrue(
            any(
                "allow_shortname_from_fqdn is enabled but allowed_domainlist is empty"
                in line
                for line in lcm.output
            )
        )

    def test_016_warn_shortname_without_domainlist_silent_when_consistent(self):
        """no warning when the flag is off or an allowlist is present"""
        with patch.object(self.logger, "warning") as mock_warn:
            warn_shortname_without_domainlist(self.logger, True, ["*.intra.net"])
            warn_shortname_without_domainlist(self.logger, False, [])
        self.assertFalse(mock_warn.called)

    @patch("acme2certifier.acme_srv.helpers.domain_utils.csr_cn_get")
    @patch("acme2certifier.acme_srv.helpers.domain_utils.csr_san_get")
    def test_017_allowed_domainlist_check_flag_off_rejects_shortname(
        self, mock_san, mock_cn
    ):
        """shortname is rejected when allow_shortname_from_fqdn is off"""
        mock_san.return_value = ["DNS:host.intra.net", "DNS:host"]
        mock_cn.return_value = None
        error = allowed_domainlist_check(
            self.logger, "csr", ["*.intra.net"], allow_shortname_from_fqdn=False
        )
        self.assertEqual("Either CN or SANs are not allowed by configuration", error)

    @patch("acme2certifier.acme_srv.helpers.domain_utils.csr_cn_get")
    @patch("acme2certifier.acme_srv.helpers.domain_utils.csr_san_get")
    def test_018_allowed_domainlist_check_flag_on_accepts_shortname(
        self, mock_san, mock_cn
    ):
        """shortname is accepted when a sibling FQDN is allowed"""
        mock_san.return_value = ["DNS:host.intra.net", "DNS:host"]
        mock_cn.return_value = None
        error = allowed_domainlist_check(
            self.logger, "csr", ["*.intra.net"], allow_shortname_from_fqdn=True
        )
        self.assertIsNone(error)

    @patch("acme2certifier.acme_srv.helpers.domain_utils.csr_cn_get")
    @patch("acme2certifier.acme_srv.helpers.domain_utils.csr_san_get")
    def test_019_allowed_domainlist_check_denylist_rejects(self, mock_san, mock_cn):
        """denylisted shortname is rejected despite a matching sibling"""
        mock_san.return_value = ["DNS:mail.intra.net", "DNS:mail"]
        mock_cn.return_value = None
        error = allowed_domainlist_check(
            self.logger,
            "csr",
            ["*.intra.net"],
            allow_shortname_from_fqdn=True,
            shortname_denylist=["mail"],
        )
        self.assertEqual("Either CN or SANs are not allowed by configuration", error)

    @patch("acme2certifier.acme_srv.helpers.domain_utils.csr_cn_get")
    @patch("acme2certifier.acme_srv.helpers.domain_utils.csr_san_get")
    def test_020_allowed_domainlist_check_shortname_only_rejected(
        self, mock_san, mock_cn
    ):
        """shortname without a sibling FQDN is rejected"""
        mock_san.return_value = ["DNS:host"]
        mock_cn.return_value = None
        error = allowed_domainlist_check(
            self.logger, "csr", ["*.intra.net"], allow_shortname_from_fqdn=True
        )
        self.assertEqual("Either CN or SANs are not allowed by configuration", error)

    @patch("acme2certifier.acme_srv.helpers.domain_utils.csr_cn_get")
    @patch("acme2certifier.acme_srv.helpers.domain_utils.csr_san_get")
    def test_021_allowed_domainlist_check_flag_on_rejects_unlisted_fqdn(
        self, mock_san, mock_cn
    ):
        """multi-label SAN outside the allowlist is rejected when shortnames are allowed"""
        mock_san.return_value = ["DNS:other.example.com"]
        mock_cn.return_value = None
        error = allowed_domainlist_check(
            self.logger, "csr", ["*.intra.net"], allow_shortname_from_fqdn=True
        )
        self.assertEqual("Either CN or SANs are not allowed by configuration", error)

    @patch("acme2certifier.acme_srv.helpers.domain_utils.csr_cn_get")
    @patch("acme2certifier.acme_srv.helpers.domain_utils.csr_san_get")
    def test_022_allowed_domainlist_check_explicit_allowlist_still_works(
        self, mock_san, mock_cn
    ):
        """denylist only gates the shortname shortcut; an explicit allowlist entry wins"""
        mock_san.return_value = ["DNS:mail"]
        mock_cn.return_value = None
        error = allowed_domainlist_check(
            self.logger,
            "csr",
            ["mail"],
            allow_shortname_from_fqdn=True,
            shortname_denylist=["mail"],
        )
        self.assertIsNone(error)

    @patch("acme2certifier.acme_srv.helpers.eab.allowed_domainlist_check")
    def test_023_eab_profile_list_passes_shortname_settings(self, mock_chk):
        """EAB allowed_domainlist check forwards cahandler shortname settings"""
        mock_chk.return_value = None
        cahandler = type(
            "CA",
            (),
            {
                "allow_shortname_from_fqdn": True,
                "shortname_denylist": ["mail"],
            },
        )()
        eabhandler = type("EAB", (), {})()
        eab_profile_list_check(
            self.logger,
            cahandler,
            eabhandler,
            "csr",
            "allowed_domainlist",
            ["*.intra.net"],
        )
        mock_chk.assert_called_once_with(
            self.logger,
            "csr",
            ["*.intra.net"],
            allow_shortname_from_fqdn=True,
            shortname_denylist=["mail"],
        )

    def test_024_eab_profile_list_sets_shortname_denylist(self):
        """a list shortname_denylist is stored on the cahandler"""
        cahandler = type("CA", (), {"shortname_denylist": []})()
        eabhandler = type("EAB", (), {})()
        eab_profile_list_check(
            self.logger,
            cahandler,
            eabhandler,
            "csr",
            "shortname_denylist",
            ["vpn", "mail"],
        )
        self.assertEqual(["vpn", "mail"], cahandler.shortname_denylist)

    def test_025_eab_profile_list_shortname_denylist_must_be_list(self):
        """a non-list shortname_denylist is ignored and a warning is logged"""
        cahandler = type("CA", (), {"shortname_denylist": ["keep"]})()
        eabhandler = type("EAB", (), {})()
        with self.assertLogs("test_a2c", level="WARNING") as lcm:
            result = eab_profile_list_check(
                self.logger, cahandler, eabhandler, "csr", "shortname_denylist", "vpn"
            )
        self.assertIsNone(result)
        self.assertEqual(["keep"], cahandler.shortname_denylist)
        self.assertTrue(
            any(
                "shortname_denylist must be a list, got str" in line
                for line in lcm.output
            )
        )

    def test_026_eab_profile_entry_sets_bool_attr(self):
        """allow_shortname_from_fqdn is applied as a boolean attribute"""
        cahandler = type("CA", (), {"allow_shortname_from_fqdn": False})()
        eabhandler = type("EAB", (), {})()
        result = _eab_profile_entry_check(
            self.logger,
            cahandler,
            eabhandler,
            "csr",
            "allow_shortname_from_fqdn",
            True,
        )
        self.assertIsNone(result)
        self.assertTrue(cahandler.allow_shortname_from_fqdn)


if __name__ == "__main__":
    unittest.main()
