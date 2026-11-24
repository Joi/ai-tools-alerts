"""Fixtures for the pull and CLI tests."""

from pathlib import Path

import pytest

from git_env import git_env_is_ours  # noqa: F401 - first: clears git's environment at import; autouse for every test
from aitools_alerts import config, curator, pull, verify
from mirror_helpers import T0, Mirror


class _Clock:
    """The reader's clock for the tests: a fixed instant after the 2099-dated
    test events, so a pull that takes the default clock admits them."""
    def __init__(self, real, at):
        self._real, self.at = real, at

    def time(self):
        return self.at

    def __getattr__(self, name):
        return getattr(self._real, name)


@pytest.fixture(autouse=True)
def reader_clock(monkeypatch):
    clock = _Clock(pull.time, T0 + 1000)
    monkeypatch.setattr(pull, "time", clock)
    monkeypatch.setattr(curator, "time", clock)  # the curator dates replies by the same clock
    return clock


@pytest.fixture(autouse=True)
def _home_from_env(monkeypatch):
    """Tests isolate by HOME; tests/test_home.py restores the passwd resolver."""
    monkeypatch.setattr(config, "home", Path.home)


@pytest.fixture(autouse=True)
def no_source_requests(monkeypatch):
    """No test reaches a primary source: the member's source check fails every
    read unless a test sets its own fetch."""
    def refuse(*a, **k):
        raise OSError("tests make no request")
    monkeypatch.setattr(verify, "default_fetch", refuse)
    return refuse


@pytest.fixture
def mirror():
    return Mirror()


@pytest.fixture
def home(tmp_path, monkeypatch):
    h = tmp_path / "home"
    h.mkdir()
    monkeypatch.setenv("HOME", str(h))
    monkeypatch.delenv("AITOOLS_ALERTS_TRUST_ROOT", raising=False)
    return h
