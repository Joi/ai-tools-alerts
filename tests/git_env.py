"""The test suite's git environment: nothing inherited.

Git takes its repository, index, work tree, object store and configuration from
environment variables BEFORE it looks at the directory it runs in. Tests here build
throwaway repositories and run git in them (one deletes every ref). Started with
GIT_DIR set, as any git hook does, those commands act on the real repository: on
2026-11-23 that deleted every branch, tag and reflog of a shared clone
(ai-tools-alerts#4e1y). Configuration is a second way in (GIT_CONFIG_COUNT with
core.worktree, GIT_CONFIG_PARAMETERS, a global or system config, a template directory).

So every GIT_* variable is removed, at import (before any test, fixture or other
conftest of this suite runs) and again before each test, and git is pointed at an
empty global config and no system config. A test that needs a setting passes it with
``git -c``. This module is imported by tests/conftest.py; it has its own name because
the suite has two conftest.py files and ``import conftest`` is ambiguous.
"""

import os

import pytest

ISOLATION = {"GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1", "GIT_TERMINAL_PROMPT": "0"}


def scrub(env=None) -> list[str]:
    """Remove every GIT_* variable from ``env`` (default: this process's) and set the
    isolation variables; returns the names removed."""
    env = os.environ if env is None else env
    gone = [k for k in list(env) if k.startswith("GIT_") and env.get(k) != ISOLATION.get(k)]
    for k in gone:
        del env[k]
    env.update(ISOLATION)
    return gone


scrub()


@pytest.fixture(autouse=True)
def git_env_is_ours(monkeypatch):
    """Before each test: a GIT_* variable set since import (by a test, a plugin, a
    fixture) is gone again."""
    for k in [k for k in os.environ if k.startswith("GIT_") and os.environ[k] != ISOLATION.get(k)]:
        monkeypatch.delenv(k)
    for k, v in ISOLATION.items():
        monkeypatch.setenv(k, v)
