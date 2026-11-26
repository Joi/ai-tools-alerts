"""Fixtures for the pull and CLI tests."""

import pytest

from git_env import git_env_is_ours  # noqa: F401 - first: clears git's environment at import; autouse for every test
import home_env  # second: points HOME and the XDG directories at a session temp dir, at import
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
    """Tests isolate by HOME, which is never the real home here (tests/home_env.py):
    the reader's home is HOME, guarded, so resolving the real home fails the test.
    A test that changes the real reader or poster directories fails too, which
    catches a subprocess that took its home from the password database.
    tests/test_home.py restores the passwd resolver; it only resolves."""
    for k, v in home_env.ENV.items():
        monkeypatch.setenv(k, v)
    with home_env.watching() as guard:
        monkeypatch.setattr(config, "home", guard.home)
        yield guard


def pytest_configure(config):
    """A --basetemp under the home holds the tests' homes: not the real home.
    (Read from the option, not created: the default basetemp is in the temp dir.)"""
    if config.option.basetemp:
        home_env.exempt(config.option.basetemp)


def pytest_sessionfinish(session, exitstatus):
    """Collection and session-scoped fixtures run outside any test: the session
    guard and the import-time fingerprint cover them."""
    why = [f"the reader's home resolved to the real home: {v}" for v in home_env.SESSION.violations]
    why += home_env.changed(home_env.BASELINE, home_env.fingerprint())
    if why:
        print("\nthe test session touched the real home (tests/home_env.py), or a reader on "
              "this machine wrote its own state during the run:\n  " + "\n  ".join(why))
        session.exitstatus = 1


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
    monkeypatch.setenv(home_env.MARKER, str(h))  # a Python child's password-database home too
    monkeypatch.delenv("AITOOLS_ALERTS_TRUST_ROOT", raising=False)
    return h
