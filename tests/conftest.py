"""Fixtures for the pull and CLI tests."""

import os
from pathlib import Path

import pytest

# Git reads these to find its repository, index and work tree BEFORE it looks at the
# directory it runs in. Tests here build throwaway repositories and run git in them
# (one deletes every ref). Started with GIT_DIR set, as any git hook does, those
# commands would act on the real repository instead: on 2026-11-23 that deleted every
# branch, tag and reflog of a shared clone (ai-tools-alerts#4e1y). They are removed for
# the whole session at import, before any test or fixture runs, and again per test.
GIT_LOCATION_VARS = ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_COMMON_DIR", "GIT_OBJECT_DIRECTORY",
                     "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_NAMESPACE", "GIT_CEILING_DIRECTORIES", "GIT_PREFIX")
for _name in GIT_LOCATION_VARS:
    os.environ.pop(_name, None)

from aitools_alerts import config, curator, pull
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
def _no_inherited_git_location(monkeypatch):
    """No test runs git with a repository location it did not choose (see GIT_LOCATION_VARS)."""
    for name in GIT_LOCATION_VARS:
        monkeypatch.delenv(name, raising=False)


@pytest.fixture(autouse=True)
def _home_from_env(monkeypatch):
    """Tests isolate by HOME; tests/test_home.py restores the passwd resolver."""
    monkeypatch.setattr(config, "home", Path.home)


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
