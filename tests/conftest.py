"""Fixtures for the pull and CLI tests."""

import pytest

from mirror_helpers import Mirror


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
