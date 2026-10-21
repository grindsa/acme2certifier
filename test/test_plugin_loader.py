# -*- coding: utf-8 -*-
"""Tests for acme_srv.helpers.plugin_loader."""

from __future__ import annotations

import configparser
import logging
import os
import sys
from collections.abc import Callable
from contextlib import AbstractContextManager
from typing import Any
from unittest.mock import MagicMock, Mock, patch

import pytest

from acme2certifier.acme_srv.helpers.plugin_loader import (
    ca_handler_load,
    eab_handler_load,
    hooks_load,
)

pytestmark = pytest.mark.usefixtures("clear_config_cache", "_silence_logging")


def test_234_load_from_file_skips_reexec(logger: logging.Logger) -> None:
    """filesystem plugin is not re-executed when sys.modules already has the same path"""
    import tempfile
    from acme2certifier.acme_srv.helpers.plugin_loader import _load_from_file

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".py", delete=False, encoding="utf8"
    ) as handle:
        handle.write("class CAhandler:\n    marker = 1\n")
        path = handle.name
    module_name = "CAhandler_cachetest"
    try:
        first = _load_from_file(logger, module_name, path, "err")
        with open(path, "w", encoding="utf8") as handle:
            handle.write("class CAhandler:\n    marker = 2\n")
        second = _load_from_file(logger, module_name, path, "err")
        assert first is second
        assert first.CAhandler.marker == 1
    finally:
        os.unlink(path)
        sys.modules.pop(module_name, None)


def test_235_load_from_file_distinct_section_keys(logger: logging.Logger) -> None:
    """named handler sections use distinct sys.modules slots"""
    import tempfile
    from acme2certifier.acme_srv.helpers.plugin_loader import _load_from_file

    files = []
    try:
        for name, marker in (("CAhandler_openssl", 1), ("CAhandler_ejbca", 2)):
            handle = tempfile.NamedTemporaryFile(
                mode="w", suffix=".py", delete=False, encoding="utf8"
            )
            handle.write(f"class CAhandler:\n    marker = {marker}\n")
            handle.close()
            files.append((name, handle.name))
            loaded = _load_from_file(logger, name, handle.name, "err")
            assert loaded.CAhandler.marker == marker
        assert sys.modules[files[0][0]] is not sys.modules[files[1][0]]
    finally:
        for name, path in files:
            os.unlink(path)
            sys.modules.pop(name, None)


def test_291_ca_handler_load(logger: logging.Logger) -> None:
    """test ca_handler_load"""
    config_dic = {"foo": "bar"}
    assert not ca_handler_load(logger, config_dic)


def test_292_ca_handler_load(
    logger: logging.Logger, capture_logs: Callable[..., AbstractContextManager[Any]]
) -> None:
    """test ca_handler_load"""
    config_dic = {"foo": "bar"}
    with capture_logs("test_a2c", level="INFO") as lcm:
        assert not ca_handler_load(logger, config_dic)
    assert (
        "ERROR:test_a2c:Configuration error: CAhandler configuration missing in config file"
        in lcm.output
    )


@patch("importlib.import_module")
def test_293_ca_handler_load(
    mock_imp: MagicMock,
    logger: logging.Logger,
    capture_logs: Callable[..., AbstractContextManager[Any]],
) -> None:
    """test ca_handler_load"""
    config_dic = {"CAhandler": {"foo": "bar"}}
    mock_imp.side_effect = Exception("exc_mock_imp")
    with capture_logs("test_a2c", level="INFO") as lcm:
        assert not ca_handler_load(logger, config_dic)
    assert (
        "CRITICAL:test_a2c:Loading default CAhandler failed with err: exc_mock_imp"
        in lcm.output
    )


def test_294_ca_handler_load_skips_default_when_multi_handler(
    logger: logging.Logger,
) -> None:
    """multi_handler registry section must not import acme_srv.ca_handler"""
    config_dic = {"CAhandler": {"multi_handler": "True", "default_handler": "openssl"}}
    with patch("importlib.import_module") as mock_imp:
        assert not ca_handler_load(logger, config_dic)
    mock_imp.assert_not_called()


@patch("importlib.import_module")
def test_295_ca_handler_load(mock_imp: MagicMock, logger: logging.Logger) -> None:
    """test ca_handler_load"""
    config_dic = {"CAhandler": {"foo": "bar"}}
    mock_imp.return_value = "foo"
    assert "foo" == ca_handler_load(logger, config_dic)


@patch("importlib.import_module")
def test_296_ca_handler_load_default_deprecated(
    mock_imp: MagicMock,
    logger: logging.Logger,
    capture_logs: Callable[..., AbstractContextManager[Any]],
) -> None:
    """empty [CAhandler] fallback logs deprecation WARNING"""
    from acme2certifier import compat

    compat._WARNED.clear()
    config_dic = {"CAhandler": {"foo": "bar"}}
    mock_imp.return_value = "foo"
    with capture_logs("test_a2c", level="WARNING") as lcm:
        assert "foo" == ca_handler_load(logger, config_dic)
    mock_imp.assert_called_with("acme_srv.ca_handler")
    assert any(
        (
            "Loading default CA handler via 'acme_srv.ca_handler' is deprecated" in line
            for line in lcm.output
        )
    )
    assert any(("acme_srv.cfg" in line for line in lcm.output))
    assert any(("handler_module" in line for line in lcm.output))
    compat._WARNED.clear()


@patch("importlib.util")
def test_297_ca_handler_load(mock_util: MagicMock, logger: logging.Logger) -> None:
    """test ca_handler_load"""
    config_dic = {"CAhandler": {"handler_file": "foo"}}
    mock_util.module_from_spec = Mock(return_value="foo")
    assert "foo" == ca_handler_load(logger, config_dic)


@patch("importlib.import_module")
@patch("importlib.util")
def test_298_ca_handler_load(
    mock_util: MagicMock,
    mock_imp: MagicMock,
    logger: logging.Logger,
    capture_logs: Callable[..., AbstractContextManager[Any]],
) -> None:
    """test ca_handler_load"""
    config_dic = {"CAhandler": {"handler_file": "foo"}}
    mock_util.module_from_spec.side_effect = Exception("exc_mock_util")
    mock_imp.return_value = "foo"
    with capture_logs("test_a2c", level="INFO") as lcm:
        assert "foo" == ca_handler_load(logger, config_dic)
    assert (
        "CRITICAL:test_a2c:Loading CAhandler configured in [CAhandler] failed with err: exc_mock_util"
        in lcm.output
    )


@patch("importlib.import_module")
@patch("importlib.util")
def test_299_ca_handler_load(
    mock_util: MagicMock,
    mock_imp: MagicMock,
    logger: logging.Logger,
    capture_logs: Callable[..., AbstractContextManager[Any]],
) -> None:
    """test ca_handler_load"""
    config_dic = {"CAhandler": {"handler_file": "foo"}}
    mock_util.module_from_spec.side_effect = Exception("exc_mock_util")
    mock_imp.side_effect = Exception("exc_mock_imp")
    with capture_logs("test_a2c", level="INFO") as lcm:
        assert not ca_handler_load(logger, config_dic)
    assert (
        "CRITICAL:test_a2c:Loading default CAhandler failed with err: exc_mock_imp"
        in lcm.output
    )


def test_300_eab_handler_load(logger: logging.Logger) -> None:
    """test eab_handler_load without EABhandler section"""
    config_dic = {"foo": "bar"}
    assert not eab_handler_load(logger, config_dic)


def test_301_eab_handler_load(
    logger: logging.Logger, capture_logs: Callable[..., AbstractContextManager[Any]]
) -> None:
    """test eab_handler_load with incomplete EABhandler section"""
    config_dic = {"EABhandler": {"foo": "bar"}}
    with capture_logs("test_a2c", level="INFO") as lcm:
        assert not eab_handler_load(logger, config_dic)
    assert (
        "WARNING:test_a2c:EABhandler section present but neither eab_handler_module nor eab_handler_file is set"
        in lcm.output
    )


def test_302_eab_handler_load(logger: logging.Logger) -> None:
    """test eab_handler_load with incomplete EABhandler section returns None"""
    config_dic = {"EABhandler": {"foo": "bar"}}
    assert not eab_handler_load(logger, config_dic)


@patch("importlib.util")
def test_303_eab_handler_load(mock_util: MagicMock, logger: logging.Logger) -> None:
    """test eab_handler_load"""
    config_dic = {"EABhandler": {"eab_handler_file": "foo"}}
    mock_util.module_from_spec = Mock(return_value="foo")
    assert "foo" == eab_handler_load(logger, config_dic)


@patch("importlib.util")
def test_304_eab_handler_load(
    mock_util: MagicMock,
    logger: logging.Logger,
    capture_logs: Callable[..., AbstractContextManager[Any]],
) -> None:
    """test eab_handler_load when eab_handler_file load fails"""
    config_dic = {"EABhandler": {"eab_handler_file": "foo"}}
    mock_util.module_from_spec.side_effect = Exception("exc_mock_util")
    with capture_logs("test_a2c", level="INFO") as lcm:
        assert not eab_handler_load(logger, config_dic)
    assert (
        "CRITICAL:test_a2c:Loading EABhandler configured in cfg failed with err: exc_mock_util"
        in lcm.output
    )
    assert "WARNING:test_a2c:EAB handler_file load failed" in lcm.output


@patch("importlib.util")
def test_305_eab_handler_load(
    mock_util: MagicMock,
    logger: logging.Logger,
    capture_logs: Callable[..., AbstractContextManager[Any]],
) -> None:
    """test eab_handler_load when eab_handler_file load fails returns None"""
    config_dic = {"EABhandler": {"eab_handler_file": "foo"}}
    mock_util.module_from_spec.side_effect = Exception("exc_mock_util")
    with capture_logs("test_a2c", level="INFO") as lcm:
        assert not eab_handler_load(logger, config_dic)
    assert (
        "CRITICAL:test_a2c:Loading EABhandler configured in cfg failed with err: exc_mock_util"
        in lcm.output
    )
    assert "Loading default EABhandler failed" not in "".join(lcm.output)


def test_306_hooks_load(logger: logging.Logger) -> None:
    """test hooks load with empty config_dic"""
    config_dic = {}
    assert not hooks_load(logger, config_dic)


def test_307_hooks_load(logger: logging.Logger) -> None:
    """test hooks load with hooks but no hooks_file in config_dic"""
    config_dic = {"Hooks": {"foo": "bar"}}
    assert not hooks_load(logger, config_dic)


@patch("importlib.util")
def test_308_hooks_load(mock_util: MagicMock, logger: logging.Logger) -> None:
    """test hooks load with hooks but no hooks_file in  config_dic"""
    config_dic = {"Hooks": {"hooks_file": "bar"}}
    mock_util.module_from_spec = Mock(return_value="foo")
    assert "foo" == hooks_load(logger, config_dic)
    assert mock_util.spec_from_file_location.called
    assert mock_util.module_from_spec.called


@patch("importlib.util")
def test_309_hooks_load(
    mock_util: MagicMock,
    logger: logging.Logger,
    capture_logs: Callable[..., AbstractContextManager[Any]],
) -> None:
    """test hooks load with hooks but no hooks_file in  config_dic"""
    config_dic = {"Hooks": {"hooks_file": "bar"}}
    mock_util.module_from_spec = Exception("exc_mock_util")
    with capture_logs("test_a2c", level="INFO") as lcm:
        assert not hooks_load(logger, config_dic)
    assert (
        "CRITICAL:test_a2c:Loading Hooks configured in cfg failed with err: 'Exception' object is not callable"
        in lcm.output
    )


@patch("importlib.import_module")
def test_310_ca_handler_load_module(
    mock_imp: MagicMock, logger: logging.Logger
) -> None:
    """test ca_handler_load via handler_module"""
    config_dic = {"CAhandler": {"handler_module": "pkg.ca_handler"}}
    mock_imp.return_value = "mod"
    assert "mod" == ca_handler_load(logger, config_dic)
    mock_imp.assert_called_with("pkg.ca_handler")


@patch("importlib.import_module")
def test_311_eab_handler_load_module(
    mock_imp: MagicMock, logger: logging.Logger
) -> None:
    """test eab_handler_load via eab_handler_module"""
    config_dic = {"EABhandler": {"eab_handler_module": "pkg.eab_handler"}}
    mock_imp.return_value = "mod"
    assert "mod" == eab_handler_load(logger, config_dic)
    mock_imp.assert_called_with("pkg.eab_handler")


@patch("importlib.import_module")
def test_312_hooks_load_module(mock_imp: MagicMock, logger: logging.Logger) -> None:
    """test hooks_load via hooks_module"""
    config_dic = {"Hooks": {"hooks_module": "pkg.hooks"}}
    mock_imp.return_value = "mod"
    assert "mod" == hooks_load(logger, config_dic)
    mock_imp.assert_called_with("pkg.hooks")


@patch("importlib.util")
def test_313_ca_handler_load_file_deprecated(
    mock_util: MagicMock,
    logger: logging.Logger,
    capture_logs: Callable[..., AbstractContextManager[Any]],
) -> None:
    """file-based CA handler load emits deprecation warning"""
    config_dic = {"CAhandler": {"handler_file": "foo"}}
    mock_util.module_from_spec = Mock(return_value="foo")
    with capture_logs("test_a2c", level="WARNING") as lcm:
        assert "foo" == ca_handler_load(logger, config_dic)
    assert any(("handler_file is deprecated" in line for line in lcm.output))


@patch("importlib.import_module")
@patch("importlib.util")
def test_314_ca_handler_module_preferred_over_file(
    mock_util: MagicMock,
    mock_imp: MagicMock,
    logger: logging.Logger,
    capture_logs: Callable[..., AbstractContextManager[Any]],
) -> None:
    """handler_module takes precedence when both keys are set"""
    config_dic = {
        "CAhandler": {"handler_module": "pkg.ca_handler", "handler_file": "foo.py"}
    }
    mock_imp.return_value = "from_module"
    with capture_logs("test_a2c", level="WARNING") as lcm:
        assert "from_module" == ca_handler_load(logger, config_dic)
    assert not mock_util.spec_from_file_location.called
    assert any(("using handler_module" in line for line in lcm.output))


@patch("importlib.import_module")
def test_315_ca_handler_load_info_once(
    mock_imp: MagicMock,
    logger: logging.Logger,
    capture_logs: Callable[..., AbstractContextManager[Any]],
) -> None:
    """routine Loaded CA handler INFO is emitted once per process"""
    from acme2certifier.acme_srv.helpers import plugin_loader

    plugin_loader._HANDLER_LOAD_LOGGED.clear()
    config_dic = {"CAhandler": {"handler_module": "pkg.ca_handler"}}
    mock_imp.return_value = "mod"
    with capture_logs("test_a2c", level="INFO") as lcm1:
        assert "mod" == ca_handler_load(logger, config_dic)
    assert 1 == sum((1 for line in lcm1.output if "Loaded CA handler" in line))
    with capture_logs("test_a2c", level="DEBUG") as lcm2:
        assert "mod" == ca_handler_load(logger, config_dic)
    assert not any(("INFO:test_a2c:Loaded CA handler" in line for line in lcm2.output))
    assert any(("DEBUG:test_a2c:Loaded CA handler" in line for line in lcm2.output))
    plugin_loader._HANDLER_LOAD_LOGGED.clear()


@patch("importlib.import_module")
def test_316_eab_handler_load_info_once(
    mock_imp: MagicMock,
    logger: logging.Logger,
    capture_logs: Callable[..., AbstractContextManager[Any]],
) -> None:
    """routine Loaded EAB handler INFO is emitted once per process"""
    from acme2certifier.acme_srv.helpers import plugin_loader

    plugin_loader._HANDLER_LOAD_LOGGED.clear()
    config_dic = {"EABhandler": {"eab_handler_module": "pkg.eab_handler"}}
    mock_imp.return_value = "mod"
    with capture_logs("test_a2c", level="INFO") as lcm1:
        assert "mod" == eab_handler_load(logger, config_dic)
    assert 1 == sum((1 for line in lcm1.output if "Loaded EAB handler" in line))
    with capture_logs("test_a2c", level="DEBUG") as lcm2:
        assert "mod" == eab_handler_load(logger, config_dic)
    assert not any(("INFO:test_a2c:Loaded EAB handler" in line for line in lcm2.output))
    plugin_loader._HANDLER_LOAD_LOGGED.clear()


@patch("importlib.import_module")
def test_317_hooks_load_info_once(
    mock_imp: MagicMock,
    logger: logging.Logger,
    capture_logs: Callable[..., AbstractContextManager[Any]],
) -> None:
    """routine Loaded hooks INFO is emitted once per process"""
    from acme2certifier.acme_srv.helpers import plugin_loader

    plugin_loader._HANDLER_LOAD_LOGGED.clear()
    config_dic = {"Hooks": {"hooks_module": "pkg.hooks"}}
    mock_imp.return_value = "mod"
    with capture_logs("test_a2c", level="INFO") as lcm1:
        assert "mod" == hooks_load(logger, config_dic)
    assert 1 == sum((1 for line in lcm1.output if "Loaded hooks" in line))
    with capture_logs("test_a2c", level="DEBUG") as lcm2:
        assert "mod" == hooks_load(logger, config_dic)
    assert not any(("INFO:test_a2c:Loaded hooks" in line for line in lcm2.output))
    plugin_loader._HANDLER_LOAD_LOGGED.clear()


def test_318_is_filesystem_path() -> None:
    """_is_filesystem_path distinguishes paths from dotted module names"""
    from acme2certifier.acme_srv.helpers.plugin_loader import _is_filesystem_path

    assert _is_filesystem_path("/var/www/volume/ca_handler.py")
    assert _is_filesystem_path("volume/ca_handler.py")
    assert _is_filesystem_path("ca_handler.py")
    assert _is_filesystem_path("./handlers/my_handler.py")
    assert not _is_filesystem_path("pkg.ca_handler")
    assert not _is_filesystem_path("acme2certifier.cahandlers.openssl_ca_handler")
    assert not _is_filesystem_path("")


@patch("importlib.util")
def test_319_ca_handler_module_path(
    mock_util: MagicMock, logger: logging.Logger
) -> None:
    """handler_module with a filesystem path uses file load"""
    config_dic = {"CAhandler": {"handler_module": "/var/www/volume/ca_handler.py"}}
    mock_util.module_from_spec = Mock(return_value="from_path")
    assert "from_path" == ca_handler_load(logger, config_dic)
    mock_util.spec_from_file_location.assert_called()
    call_args = mock_util.spec_from_file_location.call_args[0]
    assert "CAhandler" == call_args[0]
    assert "/var/www/volume/ca_handler.py" == call_args[1]


@patch("importlib.import_module")
def test_320_ca_handler_module_dotted_not_path(
    mock_imp: MagicMock, logger: logging.Logger
) -> None:
    """handler_module dotted name still uses import_module"""
    config_dic = {
        "CAhandler": {"handler_module": "acme2certifier.cahandlers.openssl_ca_handler"}
    }
    mock_imp.return_value = "from_import"
    assert "from_import" == ca_handler_load(logger, config_dic)
    mock_imp.assert_called_with("acme2certifier.cahandlers.openssl_ca_handler")


@patch("importlib.util")
def test_321_eab_handler_module_path(
    mock_util: MagicMock, logger: logging.Logger
) -> None:
    """eab_handler_module with a filesystem path uses file load"""
    config_dic = {"EABhandler": {"eab_handler_module": "/volume/eab_handler.py"}}
    mock_util.module_from_spec = Mock(return_value="eab_path")
    assert "eab_path" == eab_handler_load(logger, config_dic)
    mock_util.spec_from_file_location.assert_called()


@patch("importlib.util")
def test_322_hooks_module_path(mock_util: MagicMock, logger: logging.Logger) -> None:
    """hooks_module with a filesystem path uses file load"""
    config_dic = {"Hooks": {"hooks_module": "/volume/hooks.py"}}
    mock_util.module_from_spec = Mock(return_value="hooks_path")
    assert "hooks_path" == hooks_load(logger, config_dic)
    mock_util.spec_from_file_location.assert_called()


def test_627_plugin_loader_gap_coverage(
    logger: logging.Logger, capture_logs: Callable[..., AbstractContextManager[Any]]
) -> None:
    """Cover remaining plugin_loader branches"""
    from acme2certifier.acme_srv.helpers import plugin_loader
    from acme2certifier.acme_srv.helpers.plugin_loader import (
        _is_filesystem_path,
        _load_from_module,
        db_handler_load,
    )

    assert _is_filesystem_path("volume/handlers")
    with capture_logs("test_a2c", level="CRITICAL") as lcm:
        assert _load_from_module(logger, "missing.module.path", "prefix") is None
    assert any(("prefix failed with err" in line for line in lcm.output))
    with (
        patch(
            "acme2certifier.acme_srv.helpers.plugin_loader._load_plugin_ref",
            return_value=None,
        ),
        patch(
            "acme2certifier.acme_srv.helpers.plugin_loader.importlib.import_module",
            side_effect=ImportError("no default"),
        ),
        capture_logs("test_a2c", level="WARNING") as lcm,
    ):
        assert (
            ca_handler_load(logger, {"CAhandler": {"handler_module": "pkg.missing"}})
            is None
        )
    assert any(("falling back to default CAhandler" in line for line in lcm.output))
    with (
        patch(
            "acme2certifier.acme_srv.helpers.plugin_loader._load_plugin_ref",
            return_value=None,
        ),
        capture_logs("test_a2c", level="WARNING") as lcm,
    ):
        result = eab_handler_load(
            logger,
            {
                "EABhandler": {
                    "eab_handler_module": "pkg.eab",
                    "eab_handler_file": "eab.py",
                }
            },
        )
        assert result is None
    assert any(("ignoring eab_handler_file" in line for line in lcm.output))
    with (
        patch(
            "acme2certifier.acme_srv.helpers.plugin_loader._load_plugin_ref",
            return_value=None,
        ),
        capture_logs("test_a2c", level="WARNING") as lcm,
    ):
        assert (
            hooks_load(
                logger,
                {"Hooks": {"hooks_module": "pkg.hooks", "hooks_file": "hooks.py"}},
            )
            is None
        )
    assert any(("ignoring hooks_file" in line for line in lcm.output))
    assert any(("Hooks module load failed" in line for line in lcm.output))
    plugin_loader._HANDLER_LOAD_LOGGED.clear()
    import importlib

    sys.modules.pop("acme2certifier.acme_srv.db_handler", None)
    db_handler_mod = importlib.import_module("acme2certifier.acme_srv.db_handler")
    with patch.object(db_handler_mod, "load_db_handler_module", return_value="dbmod"):
        with capture_logs("test_a2c", level="INFO") as lcm:
            assert "dbmod" == db_handler_load(logger, {})
        assert any(("Loaded DB handler" in line for line in lcm.output))


def test_687_load_from_file_spec_none(
    logger: logging.Logger, capture_logs: Callable[..., AbstractContextManager[Any]]
) -> None:
    """_load_from_file logs CRITICAL when spec_from_file_location returns None"""
    from acme2certifier.acme_srv.helpers.plugin_loader import _load_from_file

    with patch(
        "acme2certifier.acme_srv.helpers.plugin_loader.importlib.util.spec_from_file_location",
        return_value=None,
    ):
        with capture_logs("test_a2c", level="CRITICAL") as lcm:
            assert (
                _load_from_file(logger, "mod", "/tmp/missing.py", "Loading X") is None
            )
    assert any(("Loading X failed with err:" in msg for msg in lcm.output))


def test_688_loaded_identity_partial() -> None:
    """_loaded_identity falls back when name or path is missing"""
    from types import SimpleNamespace
    from acme2certifier.acme_srv.helpers.plugin_loader import _loaded_identity

    assert _loaded_identity(SimpleNamespace(__name__="mod")) == "mod"
    assert _loaded_identity(SimpleNamespace(__file__="/tmp/mod.py")) == "/tmp/mod.py"
    assert (
        _loaded_identity(SimpleNamespace(__name__="mod", __file__="/tmp/mod.py"))
        == "mod (/tmp/mod.py)"
    )


def test_689_section_flag_true_missing_and_invalid() -> None:
    """_section_flag_true handles missing sections, invalid booleans, and dicts"""
    from acme2certifier.acme_srv.helpers.plugin_loader import _section_flag_true

    assert not _section_flag_true({}, "CAhandler", "multi_handler")
    parser = configparser.ConfigParser(interpolation=None)
    parser.add_section("CAhandler")
    parser.set("CAhandler", "multi_handler", "notabool")
    assert not _section_flag_true(parser, "CAhandler", "multi_handler")

    class _Section:

        def __contains__(self, key):
            return key == "multi_handler"

        def __getitem__(self, key):
            return "yes"

    assert _section_flag_true({"CAhandler": _Section()}, "CAhandler", "multi_handler")


def test_690_ca_handler_load_from_section_missing(
    logger: logging.Logger, capture_logs: Callable[..., AbstractContextManager[Any]]
) -> None:
    """ca_handler_load_from_section errors when the section is absent"""
    from acme2certifier.acme_srv.helpers.plugin_loader import (
        ca_handler_load_from_section,
    )

    with capture_logs("test_a2c", level="ERROR") as lcm:
        assert ca_handler_load_from_section(logger, {}, "CAhandler:openssl") is None
    assert (
        "ERROR:test_a2c:Configuration error: section CAhandler:openssl missing in config file"
        in lcm.output
    )


def test_691_ca_handler_load_from_section_no_fallback(
    logger: logging.Logger, capture_logs: Callable[..., AbstractContextManager[Any]]
) -> None:
    """Named handler load failures do not fall back when allow_default_fallback is False"""
    from acme2certifier.acme_srv.helpers.plugin_loader import (
        ca_handler_load_from_section,
    )

    config_dic = {"CAhandler:openssl": {"handler_module": "not.a.module"}}
    with capture_logs("test_a2c", level="ERROR") as lcm:
        assert (
            ca_handler_load_from_section(
                logger, config_dic, "CAhandler:openssl", allow_default_fallback=False
            )
            is None
        )
    assert any(("CRITICAL:test_a2c:" in msg for msg in lcm.output))
    config_dic = {"CAhandler:openssl": {"handler_file": "/tmp/missing_handler.py"}}
    with capture_logs("test_a2c", level="ERROR") as lcm:
        assert (
            ca_handler_load_from_section(
                logger, config_dic, "CAhandler:openssl", allow_default_fallback=False
            )
            is None
        )
    assert any(("CRITICAL:test_a2c:" in msg for msg in lcm.output))
    config_dic = {"CAhandler:openssl": {}}
    with capture_logs("test_a2c", level="ERROR") as lcm:
        assert (
            ca_handler_load_from_section(
                logger, config_dic, "CAhandler:openssl", allow_default_fallback=False
            )
            is None
        )
    assert (
        "ERROR:test_a2c:[CAhandler:openssl] has no handler_module or handler_file"
        in lcm.output
    )
