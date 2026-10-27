"""Session fixtures for acme2certifier unit tests."""

from __future__ import annotations

import logging
import os
import subprocess
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path

import pytest

from acme2certifier.acme_srv.helpers.config import load_config_cache_clear

_REPO_ROOT = Path(__file__).resolve().parent.parent
_CA_DIR = Path(__file__).resolve().parent / "ca"
_BOOTSTRAP_MARKER = _CA_DIR / "sub-ca-key.pem"
_MAKE_TEST_CAS = _REPO_ROOT / "tools" / "make_test_cas.sh"


@pytest.fixture(scope="session", autouse=True)
def openssl_test_ca() -> None:
    """Ensure openssl lab CA PEMs exist under test/ca (generate-if-missing)."""
    if _BOOTSTRAP_MARKER.is_file():
        return
    if not _MAKE_TEST_CAS.is_file():
        pytest.fail(f"missing {_MAKE_TEST_CAS}")
    try:
        subprocess.run(
            [str(_MAKE_TEST_CAS), "bootstrap", "-c", str(_CA_DIR), "-o", str(_CA_DIR)],
            check=True,
            cwd=str(_REPO_ROOT),
            env={**os.environ},
        )
    except FileNotFoundError as exc:
        pytest.fail(f"openssl/bootstrap failed: {exc}")
    except subprocess.CalledProcessError as exc:
        pytest.fail(
            f"tools/make_test_cas.sh bootstrap failed with exit {exc.returncode}"
        )
    if not _BOOTSTRAP_MARKER.is_file():
        pytest.fail(f"bootstrap did not create {_BOOTSTRAP_MARKER}")


class _FakeDBStore(object):
    """face DBStore class needed for mocking"""

    profiles = {}
    header_info_field = "header_info_field"


class _LogWatcher:
    """unittest assertLogs-compatible view of records captured by caplog."""

    def __init__(
        self,
        caplog: pytest.LogCaptureFixture,
        logger_name: str,
        level: int,
        start: int,
    ) -> None:
        self._caplog = caplog
        self._logger_name = logger_name
        self._level = level
        self._start = start
        self._end: int | None = None

    def close(self, end: int) -> None:
        self._end = end

    def _records(self) -> list[logging.LogRecord]:
        end = len(self._caplog.records) if self._end is None else self._end
        matched: list[logging.LogRecord] = []
        for record in self._caplog.records[self._start : end]:
            if record.levelno < self._level:
                continue
            if record.name == self._logger_name or record.name.startswith(
                self._logger_name + "."
            ):
                matched.append(record)
        return matched

    @property
    def records(self) -> list[logging.LogRecord]:
        return self._records()

    @property
    def output(self) -> list[str]:
        return [
            f"{record.levelname}:{record.name}:{record.getMessage()}"
            for record in self._records()
        ]


def _logger_name(logger: logging.Logger | str) -> str:
    if isinstance(logger, logging.Logger):
        return logger.name
    return logger


def _level_value(level: int | str) -> int:
    if isinstance(level, int):
        return level
    return int(getattr(logging, level))


@pytest.fixture
def clear_config_cache() -> None:
    """Drop the cached acme_srv.cfg parse, matching the old helper setUp."""
    load_config_cache_clear()


@pytest.fixture
def _silence_logging() -> None:
    """Keep helper tests from configuring a verbose root logger."""
    logging.basicConfig(level=logging.CRITICAL)


@pytest.fixture
def logger() -> logging.Logger:
    """Logger name assertLogs('test_a2c') and helper calls both use."""
    return logging.getLogger("test_a2c")


@pytest.fixture
def test_dir() -> str:
    """test/ directory, used for test/ca fixtures."""
    return str(Path(__file__).resolve().parent)


@pytest.fixture
def FakeDBStore() -> type[_FakeDBStore]:
    """Class object the eab tests instantiate as a stand-in handler."""
    return _FakeDBStore


@pytest.fixture
def capture_logs(
    caplog: pytest.LogCaptureFixture,
) -> Callable[..., Iterator[_LogWatcher]]:
    """Replacement for TestCase.assertLogs that still exposes .output."""

    @contextmanager
    def _capture(
        logger: logging.Logger | str = "test_a2c",
        level: int | str = "INFO",
    ) -> Iterator[_LogWatcher]:
        logger_name = _logger_name(logger)
        numeric = _level_value(level)
        start = len(caplog.records)
        watcher = _LogWatcher(caplog, logger_name, numeric, start)
        with caplog.at_level(numeric, logger=logger_name):
            yield watcher
        watcher.close(len(caplog.records))
        if not watcher.records:
            pytest.fail(
                f"no logs of level {logging.getLevelName(numeric)} or higher "
                f"triggered on {logger_name}"
            )

    return _capture


@pytest.fixture
def capture_no_logs(
    caplog: pytest.LogCaptureFixture,
) -> Callable[..., Iterator[None]]:
    """Replacement for TestCase.assertNoLogs."""

    @contextmanager
    def _capture(
        logger: logging.Logger | str = "test_a2c",
        level: int | str = "INFO",
    ) -> Iterator[None]:
        logger_name = _logger_name(logger)
        numeric = _level_value(level)
        start = len(caplog.records)
        with caplog.at_level(numeric, logger=logger_name):
            yield
        matched = [
            record
            for record in caplog.records[start:]
            if record.levelno >= numeric
            and (
                record.name == logger_name or record.name.startswith(logger_name + ".")
            )
        ]
        if matched:
            rendered = [
                f"{record.levelname}:{record.name}:{record.getMessage()}"
                for record in matched
            ]
            pytest.fail(f"unexpected logs on {logger_name}: {rendered}")

    return _capture
