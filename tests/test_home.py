"""The CLI's paths come from the password database, never HOME (ai-tools-alerts#fsmb)."""

import os
import pwd
from pathlib import Path

import pytest

from aitools_alerts import config, inventory

PW_HOME = Path(pwd.getpwuid(os.getuid()).pw_dir)
REAL_HOME = config.home  # captured before conftest's autouse patch


@pytest.fixture(autouse=True)
def _real_resolver(monkeypatch):
    monkeypatch.setattr(config, "home", REAL_HOME)


def test_paths_ignore_home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    assert config.home() == PW_HOME
    assert config.config_dir() == PW_HOME / ".config" / "aitools-alerts"
    assert config.config_path().parent == config.key_path().parent == config.config_dir()
    assert config.state_dir() == PW_HOME / ".local" / "state" / "aitools-alerts"
    empty, tilde = tmp_path / "empty.toml", tmp_path / "tilde.toml"
    empty.write_text("")
    tilde.write_text('telegram_token_file = "~/t"\n')
    assert config.load(empty).telegram_token_file == str(config.config_dir() / "telegram.token")
    assert config.load(tilde).telegram_token_file == str(PW_HOME / "t")
    for p in (config.config_dir(), config.state_dir()):
        assert tmp_path not in p.parents


def missing(uid):
    raise KeyError(uid)


@pytest.mark.parametrize("getpwuid", [missing, lambda uid: pwd.struct_passwd(("u", "x", uid, 20, "", "", "/bin/sh"))],
                         ids=["no-entry", "empty-dir"])
def test_no_passwd_home_is_an_error_not_home(tmp_path, monkeypatch, getpwuid):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(config.pwd, "getpwuid", getpwuid)
    with pytest.raises(config.ConfigError, match="password database"):
        config.state_dir()


def test_inventory_default_home_is_passwd_home(tmp_path, monkeypatch):
    fake = tmp_path / "pw"
    (fake / ".claude" / "skills" / "only-in-pw-home").mkdir(parents=True)
    (tmp_path / "env" / ".claude" / "skills" / "only-in-env-home").mkdir(parents=True)
    monkeypatch.setenv("HOME", str(tmp_path / "env"))
    monkeypatch.setattr(config, "home", lambda: fake)
    inv = inventory.collect(runner=lambda argv: None, apps_dirs=[])
    assert [i.name for i in inv.products["skill"]] == ["only-in-pw-home"]
