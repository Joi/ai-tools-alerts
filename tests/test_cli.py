import json
import os
import stat
import subprocess

import pytest

from aitools_alerts import cli, config, inventory, notify
from aitools_alerts.check import Match
from aitools_alerts.config import Settings
from aitools_alerts.inventory import Installed, Inventory
from aitools_alerts.notify import SendResult
from aitools_alerts.state import State
from mirror_helpers import FIXTURE_MIRROR, FIXTURE_ROOT, advisory

MIRROR = FIXTURE_MIRROR.as_uri() + "/"


@pytest.fixture(autouse=True)
def env(home, monkeypatch):
    monkeypatch.setenv(cli.TRUST_ROOT_ENV, FIXTURE_ROOT)
    inv = Inventory(products={"claude-code": [Installed("Claude Code", "2.0.0", "/invented/bin/claude")],
                              "git": [Installed("git", "2.50.0", "/invented/bin/git")]})
    monkeypatch.setattr(inventory, "collect", lambda *a, **k: inv)

    def no_exec(*a, **k):
        raise AssertionError(f"executed {a!r}")
    monkeypatch.setattr(subprocess, "run", no_exec)
    monkeypatch.setattr(subprocess, "Popen", no_exec)
    return home


@pytest.fixture
def sent(monkeypatch):
    log = {"accept": True, "calls": []}

    def fake(channel, text, settings, **kw):
        log["calls"].append((channel, text))
        return SendResult(log["accept"], "fake")
    monkeypatch.setattr(notify, "send", fake)
    return log


def write_config(text: str):
    config.write_default()
    config.config_path().write_text(text)


# ------------------------------------------------------------ plan tests

def test_run_exit_code_2_on_unseen_critical(sent, capsys):
    write_config(f'mirror_url = "{MIRROR}"\n')
    assert cli.main(["run"]) == 2
    assert len(sent["calls"]) == 1 and sent["calls"][0][1].startswith("CRITICAL: Claude Code fixture")
    assert cli.main(["run"]) == 0  # seen now
    assert len(sent["calls"]) == 1


def test_notify_marks_seen_only_after_accepted(sent):
    assert cli.main(["pull", "--mirror-url", MIRROR]) == 0
    sent["accept"] = False
    assert cli.main(["notify"]) == 1
    assert State.load().seen == set()
    sent["accept"] = True
    assert cli.main(["notify"]) == 0
    assert len(State.load().seen) == 1
    assert cli.main(["notify"]) == 0 and len(sent["calls"]) == 2


def test_notify_text_contains_level_title_action_source():
    adv = advisory(title="Claude Code invented hole")
    inst = Installed("Claude Code", "2.0.0", "/invented")
    m = Match(adv=adv, installed=inst, actions_allowed=list(adv.actions), reason="affected",
              product=adv.products[0])
    text = notify.format_text(adv, m)
    lines = text.splitlines()
    assert lines[0] == "CRITICAL: Claude Code invented hole"
    assert "Affected: Claude Code 2.0.0 (fixed in 99.0.0)" in lines
    assert "Action: upgrade Claude Code to 99.0.0 or later" in lines
    assert lines[-1] == "Source: https://example.invalid/advisory"


def test_cli_init_writes_config_and_no_key_by_default(capsys):
    assert cli.main(["init"]) == 0
    assert config.config_path().is_file()
    assert not config.key_path().exists()
    assert config.load().mirror_url == config.DEFAULT_MIRROR_URL
    assert cli.main(["init"]) == 1  # no silent overwrite


# ------------------------------------------------------------------- extra

def test_init_make_key_writes_0600_and_prints_npub_not_nsec(capsys):
    assert cli.main(["init", "--make-key"]) == 0
    out = capsys.readouterr().out
    p = config.key_path()
    assert stat.S_IMODE(os.stat(p).st_mode) == 0o600
    nsec = p.read_text().strip()
    assert nsec.startswith("nsec1") and nsec not in out
    assert "npub1" in out and "Buzz" in out
    assert cli.main(["keygen"]) == 1  # never replaces a key
    assert p.read_text().strip() == nsec


def test_pull_then_check_prints_fixture_critical(capsys):
    assert cli.main(["init"]) == 0
    assert cli.main(["pull", "--mirror-url", MIRROR]) == 0
    assert cli.main(["check"]) == 0
    out = capsys.readouterr()
    assert "CRITICAL: Claude Code fixture critical" in out.out
    assert "trust root overridden" in out.err


def test_check_json(capsys):
    cli.main(["pull", "--mirror-url", MIRROR])
    capsys.readouterr()
    assert cli.main(["check", "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert [d["level"] for d in data] == ["critical"]
    assert data[0]["posted_by"] == "relay-bot"


def test_plan_prints_template_command_and_executes_nothing(capsys):
    write_config('auto_apply = ["upgrade"]\n')
    cli.main(["pull", "--mirror-url", MIRROR])
    capsys.readouterr()
    assert cli.main(["plan", "AITA-FIXTURE-0001"]) == 0
    out = capsys.readouterr().out
    assert "command: npm install -g @anthropic-ai/claude-code@99.0.0" in out
    # relay-bot post: opted-in upgrade still asks first
    assert "prepare (ask first)" in out and "auto-apply" not in out
    assert "nothing was executed" in out
    assert cli.main(["plan", "NOPE"]) == 1


def test_state_from_another_root_is_not_used(monkeypatch, capsys):
    cli.main(["pull", "--mirror-url", MIRROR])
    monkeypatch.delenv(cli.TRUST_ROOT_ENV)
    capsys.readouterr()
    assert cli.main(["check", "--json"]) == 0
    io = capsys.readouterr()
    assert json.loads(io.out) == [] and "another trust root" in io.err


def test_bad_trust_root_override(monkeypatch):
    monkeypatch.setenv(cli.TRUST_ROOT_ENV, "nothex")
    with pytest.raises(SystemExit):
        cli.main(["check"])


def test_pull_failure_exits_1(capsys):
    assert cli.main(["pull", "--mirror-url", "file:///nonexistent/mirror/"]) == 1
    assert "manifest unreadable" in capsys.readouterr().err


def test_upgrade_command_only_from_templates():
    assert cli.upgrade_command("codex", "1.2.3") == ["npm", "install", "-g", "@openai/codex@1.2.3"]
    assert cli.upgrade_command("git", "2.0.0") is None
    assert cli.upgrade_command("claude-code", None) is None


# --------------------------------------------------------------- transports

class Run:
    def __init__(self, code=0):
        self.code, self.argv = code, None

    def __call__(self, argv, **kw):
        assert kw["shell"] is False and "timeout" in kw
        self.argv = argv
        return subprocess.CompletedProcess(argv, self.code, "", "")


@pytest.fixture
def on_path(monkeypatch):
    monkeypatch.setattr(notify.shutil, "which", lambda name: "/invented/" + name)


TEXT = 'CRITICAL: "quoted" end tell -- $(x) `y`'


def test_desktop_macos_text_is_one_argument_outside_the_script(on_path):
    r = Run()
    res = notify.send("desktop", TEXT, Settings(), run=r, platform="darwin")
    assert res.accepted
    assert r.argv[:3] == ["osascript", "-e", notify.OSASCRIPT] and r.argv[3] == TEXT
    assert TEXT not in notify.OSASCRIPT and len(r.argv) == 4


def test_desktop_linux_and_failure(on_path):
    r = Run()
    assert notify.send("desktop", TEXT, Settings(), run=r, platform="linux").accepted
    assert r.argv == ["notify-send", "--", notify.TITLE, TEXT]
    assert not notify.send("desktop", TEXT, Settings(), run=Run(1), platform="darwin").accepted


def test_imessage_and_signal_argv(on_path):
    r = Run()
    s = Settings(imessage_to="+15555550100", signal_to="+15555550101", signal_account="+15555550102")
    assert notify.send("imessage", TEXT, s, run=r).accepted
    assert r.argv == ["imsg", "send", "--to", "+15555550100", "--text", TEXT]
    assert notify.send("signal", TEXT, s, run=r).accepted
    assert r.argv == ["signal-cli", "-a", "+15555550102", "send", "-m", TEXT, "+15555550101"]


def test_missing_binary_not_accepted(monkeypatch):
    monkeypatch.setattr(notify.shutil, "which", lambda name: None)
    res = notify.send("imessage", TEXT, Settings(imessage_to="+15555550100"), run=Run())
    assert not res.accepted and "not installed" in res.detail


def test_telegram_token_file_must_be_private(home):
    tok = home / "telegram.token"
    tok.write_text("123456:invented-token\n")
    calls = []

    def post(url, payload):
        calls.append((url, payload))
        return 200, b'{"ok": true}'
    s = Settings(telegram_chat_id="12345", telegram_token_file=str(tok))
    os.chmod(tok, 0o644)
    res = notify.send("telegram", TEXT, s, post=post)
    assert not res.accepted and calls == []
    os.chmod(tok, 0o600)
    res = notify.send("telegram", TEXT, s, post=post)
    assert res.accepted and calls[0][1] == {"chat_id": "12345", "text": TEXT}
    assert "invented-token" not in res.detail


def test_webhook_accepts_2xx_only():
    s = Settings(webhook_url="https://example.invalid/hook")
    assert notify.send("webhook", TEXT, s, post=lambda u, p: (204, b"")).accepted
    assert not notify.send("webhook", TEXT, s, post=lambda u, p: (500, b"")).accepted

    def boom(u, p):
        raise OSError("down")
    assert not notify.send("webhook", TEXT, s, post=boom).accepted
