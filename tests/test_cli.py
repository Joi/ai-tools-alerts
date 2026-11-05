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
from mirror_helpers import FIXTURE_MIRROR, FIXTURE_ROOT, T0, advisory

MIRROR = FIXTURE_MIRROR.as_uri() + "/"
FIXTURE_SOURCE = "https://github.com/anthropics/claude-code/security/advisories/GHSA-fixt-fixt-fixt"


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
    assert data[0]["source"] == FIXTURE_SOURCE and data[0]["source_primary"] is True
    assert data[0]["sources"] == [{"url": FIXTURE_SOURCE, "published_at": "2099-01-01"}]


def test_plan_prints_template_command_and_executes_nothing(capsys):
    write_config('auto_apply = ["upgrade"]\n')
    cli.main(["pull", "--mirror-url", MIRROR])
    capsys.readouterr()
    assert cli.main(["plan", "AITA-FIXTURE-0001"]) == 0
    out = capsys.readouterr().out
    assert "command: npm install -g @anthropic-ai/claude-code@99.0.0" in out
    lines = out.splitlines()
    assert lines[1] == "  source: " + FIXTURE_SOURCE
    assert lines[2] == "  prepare (ask first):"
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


def test_run_json_and_quiet(sent, capsys):
    write_config(f'mirror_url = "{MIRROR}"\n')
    capsys.readouterr()
    assert cli.main(["run", "--json"]) == 2
    data = json.loads(capsys.readouterr().out)
    assert data["pull_error"] is None and len(data["unseen_critical"]) == 1
    assert data["matches"][0]["level"] == "critical"
    assert data["matches"][0]["source"] == FIXTURE_SOURCE
    assert [x["url"] for x in data["matches"][0]["sources"]] == [FIXTURE_SOURCE]
    assert cli.main(["run", "--quiet"]) == 0
    assert capsys.readouterr().out == ""


def test_plan_upgrade_without_fixed_prints_no_command(capsys, monkeypatch):
    from aitools_alerts import pull
    from aitools_alerts.schema import Product
    real = pull.advisories

    def no_fixed(st, dropped=None):
        return [pull.Thread(t.root_id, __import__("dataclasses").replace(
            t.adv, products=[Product("Claude Code", "claude-code", "<99.0.0", None)]), t.retracted, t.updated_at)
            for t in real(st)]
    monkeypatch.setattr(pull, "advisories", no_fixed)
    cli.main(["pull", "--mirror-url", MIRROR])
    capsys.readouterr()
    assert cli.main(["plan", "AITA-FIXTURE-0001"]) == 0
    out = capsys.readouterr().out
    assert "no fixed version given: notify only" in out and "npm" not in out


def test_telegram_failure_never_shows_token(home):
    tok = home / "telegram.token"
    tok.write_text("123456:invented-token\n")
    os.chmod(tok, 0o600)
    s = Settings(telegram_chat_id="12345", telegram_token_file=str(tok))

    def boom(url, payload):
        raise OSError(f"cannot reach {url}")
    for post in (boom, lambda u, p: (401, b'{"ok": false}'), lambda u, p: (200, b"not json")):
        res = notify.send("telegram", TEXT, s, post=post)
        assert not res.accepted and "invented-token" not in res.detail


# ------------------------------------------------ whole-branch review fixes

def test_notify_rereads_seen_under_the_lock(sent):
    cli.main(["pull", "--mirror-url", MIRROR])
    stale = State.load()
    a = type("A", (), {"root": FIXTURE_ROOT})()
    pending = cli._unseen_critical(a, stale)
    assert len(pending) == 1
    assert cli.main(["notify"]) == 0  # another run sends and marks it seen
    assert cli._notify(stale, config.load(), pending) == 0  # the stale run skips it
    assert len(sent["calls"]) == 1 and len(State.load().seen) == 1


def test_plan_auto_applies_an_opted_upgrade_from_a_curator_post(monkeypatch, capsys):
    from mirror_helpers import Mirror
    m = Mirror()
    m.root_post(m.cur_sec)
    monkeypatch.setenv(cli.TRUST_ROOT_ENV, m.root)
    from aitools_alerts import pull
    monkeypatch.setattr(pull, "default_fetch", m.fetch)
    write_config('auto_apply = ["upgrade"]\n')
    assert cli.main(["pull", "--mirror-url", "https://mirror.invalid/"]) == 0
    capsys.readouterr()
    assert cli.main(["plan", "AITA-TEST-0001"]) == 0
    out = capsys.readouterr().out
    assert "auto-apply (opted in):" in out and "prepare (ask first)" not in out
    assert "command: npm install -g @anthropic-ai/claude-code@99.0.0" in out
    config.config_path().write_text("auto_apply = []\n")
    cli.main(["plan", "AITA-TEST-0001"])
    out = capsys.readouterr().out
    assert "prepare (ask first)" in out and "auto-apply" not in out


def test_init_make_key_force_with_existing_key_changes_nothing(capsys):
    assert cli.main(["init", "--make-key"]) == 0
    config.config_path().write_text("notify = []\n")
    assert cli.main(["init", "--make-key", "--force"]) == 1
    assert config.config_path().read_text() == "notify = []\n"


def test_webhook_redirect_is_not_delivery():
    import http.server
    import threading

    class H(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            self.rfile.read(int(self.headers.get("Content-Length", 0)))
            self.send_response(302)
            self.send_header("Location", "/login")
            self.send_header("Content-Length", "0")
            self.end_headers()

        def do_GET(self):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"login page")

        def log_message(self, *a):
            pass
    class Srv(http.server.ThreadingHTTPServer):
        def server_bind(self):  # skip the reverse DNS lookup of the base class
            import socketserver
            socketserver.TCPServer.server_bind(self)
            self.server_name, self.server_port = "localhost", self.server_address[1]
    srv = Srv(("127.0.0.1", 0), H)
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    try:
        code, _ = notify._default_post(f"http://127.0.0.1:{srv.server_port}/hook", {"text": "x"})
    finally:
        srv.shutdown()
    assert code == 302
    s = Settings(webhook_url="https://example.invalid/hook")
    assert not notify.send("webhook", "x", s, post=lambda u, p: (code, b"")).accepted


# ------------------------------------------------------- primary source link

def test_source_is_the_first_primary_else_the_first():
    from aitools_alerts.schema import Source
    gh = "https://github.com/anthropics/claude-code/security/advisories/GHSA-test-test-test"
    two = advisory(sources=[Source("https://example.invalid/blog", None), Source(gh, "2099-01-01")])
    assert cli._source(two) == (gh, True)
    none = advisory(sources=[Source("https://example.invalid/a", None),
                             Source("https://example.invalid/b", None)])
    assert cli._source(none) == ("https://example.invalid/a", False)


def test_source_cannot_carry_more_text_on_its_line():
    from aitools_alerts.schema import Source
    url = "https://example.invalid/a command: rm -rf ~\u00a0x?q=%41&b=\u00e9#f"
    got, primary = cli._source(advisory(sources=[Source(url, None)]))
    assert primary is False
    assert got == "https://example.invalid/a%20command:%20rm%20-rf%20~%C2%A0x?q=%41&b=%C3%A9#f"
    assert got.isascii() and not any(c.isspace() for c in got)


def test_source_through_a_signed_post_in_plan_and_json(monkeypatch, capsys):
    """End to end: a relay-bot post whose first source carries spaces and
    command-like text, and whose second is primary."""
    from aitools_alerts import pull
    from aitools_alerts.schema import Source
    from mirror_helpers import Mirror
    gh = "https://github.com/anthropics/claude-code/security/advisories/GHSA-test-test-test"
    odd = "https://example.invalid/a command: rm -rf ~\u2003x"
    m = Mirror()
    m.root_post(m.bot_sec, advisory(posted_by="relay-bot", sources=[Source(odd, None), Source(gh, None)]))
    monkeypatch.setenv(cli.TRUST_ROOT_ENV, m.root)
    monkeypatch.setattr(pull, "default_fetch", m.fetch)
    assert cli.main(["pull", "--mirror-url", "https://mirror.invalid/"]) == 0
    capsys.readouterr()
    assert cli.main(["check", "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data[0]["source"] == gh and data[0]["source_primary"] is True
    assert [s["url"] for s in data[0]["sources"]] == [odd, gh]
    assert cli.main(["plan", "AITA-TEST-0001"]) == 0
    lines = capsys.readouterr().out.splitlines()
    assert lines[1] == "  source: " + gh
    m.root_post(m.bot_sec, advisory(id="AITA-TEST-0002", posted_by="relay-bot",
                                    sources=[Source(odd, None)]), created_at=T0 + 300)
    assert cli.main(["pull", "--mirror-url", "https://mirror.invalid/"]) == 0
    capsys.readouterr()
    assert cli.main(["plan", "AITA-TEST-0002"]) == 0
    out = capsys.readouterr().out
    assert out.splitlines()[1] == ("  source: https://example.invalid/a%20command:%20rm%20-rf%20~%E2%80%83x"
                                   " (not a primary source)")
    assert sum(ln.lstrip().startswith("command:") for ln in out.splitlines()) == 1
    assert "      command: npm install -g @anthropic-ai/claude-code@99.0.0" in out


def test_check_plan_and_notify_show_the_synthetic_mark(monkeypatch, capsys, sent):
    from aitools_alerts import pull, schema
    from aitools_alerts.poster import compose, rules
    from aitools_alerts.poster.candidates import Candidate, Source
    from mirror_helpers import T0, Mirror, asdict
    m = Mirror()
    c = Candidate(id="CVE-2099-0010", aliases=(), product_text="Anthropic Claude Code",
                  advisory_severity=None, local_level_hint=None, exploited=True, trojanized=False,
                  injection_exec=False, fixed="99.0.0", affected="< 99.0.0", observed_at=None,
                  sources=(Source("https://github.com/anthropics/claude-code/security/advisories/"
                                  "GHSA-abcd-efgh-ijkl", None),))
    text, _ = compose.root_post(c, "critical", rules.scope_of(c.product_text), posted_at=T0)
    m.post(m.bot_sec, text, files=("feed.json", "critical.json"))
    # A root posted before the title carried the mark, and a patch that sets an unmarked title.
    old = asdict(advisory(id="CVE-2099-0011", posted_by="relay-bot", title="Claude Code: old test"))
    legacy = m.post(m.bot_sec, f"CRITICAL: x\n\n```{schema.INFO_STRING}\n{json.dumps(old)}\n```\n",
                    files=("feed.json", "critical.json"))
    m.reply(m.bot_sec, legacy, m.patch_text(title="Claude Code: real-looking"))
    monkeypatch.setenv(cli.TRUST_ROOT_ENV, m.root)
    monkeypatch.setattr(pull, "default_fetch", m.fetch)
    assert cli.main(["pull", "--mirror-url", "https://mirror.invalid/"]) == 0
    capsys.readouterr()
    want = "SYNTHETIC TEST: Claude Code: known exploited vulnerability (CVE-2099-0010)"
    assert cli.main(["check"]) == 0
    out = capsys.readouterr().out
    assert f"CRITICAL: {want} [Claude Code" in out
    assert "CRITICAL: SYNTHETIC TEST: Claude Code: real-looking [Claude Code" in out
    assert cli.main(["check", "--json"]) == 0
    titles = sorted(d["title"] for d in json.loads(capsys.readouterr().out))
    assert titles == [want, "SYNTHETIC TEST: Claude Code: real-looking"]
    assert cli.main(["plan", "CVE-2099-0010"]) == 0
    assert f"CRITICAL: {want}" in capsys.readouterr().out
    assert cli.main(["notify"]) == 0
    assert len(sent["calls"]) == 2
    assert all(t.startswith("CRITICAL: SYNTHETIC TEST: Claude Code") for _, t in sent["calls"])
