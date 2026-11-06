"""Fixtures for the pull and CLI tests."""

from pathlib import Path

import pytest

from aitools_alerts import config
from mirror_helpers import Mirror


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
