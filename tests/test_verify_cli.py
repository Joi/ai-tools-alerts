"""The source check in the CLI (ai-tools-alerts#fv4g): where it runs, what it prints,
and that it changes nothing else."""

import json
import re
import subprocess
from pathlib import Path

import pytest

from aitools_alerts import cli, config, inventory, notify, verify
from aitools_alerts.inventory import Installed, Inventory
from aitools_alerts.notify import SendResult
from aitools_alerts.schema import Product
from mirror_helpers import Mirror, advisory
from test_verify import CVE, G1, G2, KEV_CC, SENTINEL, TRUNCATED, Net, ghsa, gurl, kev

ROOT = Path(__file__).parents[1]


@pytest.fixture(autouse=True)
def env(home, monkeypatch):
    inv = Inventory(products={"claude-code": [Installed("Claude Code", "2.0.0", "/invented/bin/claude")]})
    monkeypatch.setattr(inventory, "collect", lambda *a, **k: inv)
    monkeypatch.setattr(notify, "send", lambda *a, **k: SendResult(True, "fake"))

    def no_exec(*a, **k):
        raise AssertionError(f"executed {a!r}")
    monkeypatch.setattr(subprocess, "run", no_exec)
    return home


def bot(id=G1, level="high", products=("Claude Code",), **kw):
    return advisory(posted_by="relay-bot", id=id, level=level,
                    products=[Product(n, "claude-code", "<99.0.0", "99.0.0") for n in products], **kw)


@pytest.fixture
def feed(tmp_path, monkeypatch):
    """feed(advisories, config text, min_cli=None): a signed mirror on disk and a config that reads it."""
    def make(advs, extra="", min_cli=None):
        m = Mirror()
        if min_cli:
            m.publish_cert(min_cli=min_cli)
        for i, a in enumerate(advs):
            m.root_post(m.bot_sec, a, created_at=4070908800 + 100 + i)
        d = tmp_path / "mirror"
        d.mkdir(exist_ok=True)
        url = m.write(d)
        monkeypatch.setenv(cli.TRUST_ROOT_ENV, m.root)
        config.write_default(force=True)
        config.config_path().write_text(f'trust_root_override = true\nmirror_url = "{url}"\nsecond_origin = ""\n{extra}')
        return m
    return make


def use(monkeypatch, fetch):
    monkeypatch.setattr(verify, "default_fetch", fetch)
    return fetch


def out_of(capsys, argv):
    capsys.readouterr()
    status = cli.main(argv)
    got = capsys.readouterr()
    return status, got.out, got.err


# ------------------------------------------------------------------ where it runs

def test_only_run_and_verify_read_a_source(feed, monkeypatch, capsys):
    feed([bot()])
    n = use(monkeypatch, Net())
    assert cli.main(["run", "--json"]) == 0 and n.calls == []  # the session-start hook's command
    for argv in (["check"], ["check", "--json"], ["plan", G1], ["notify"], ["pull"], ["run", "--json"]):
        cli.main(argv)
        assert n.calls == [], argv
    cli.main(["run"])
    assert n.urls == [gurl(G1)]
    cli.main(["verify"])
    assert n.urls == [gurl(G1)] * 2  # a 404 is asked again
    cli.main(["run", "--quiet"])
    assert len(n.calls) == 3


def test_the_shipped_hook_runs_json_and_the_hourly_jobs_do_not():
    hook = (ROOT / "hooks" / "claude-code" / "session-start.sh").read_text()
    assert re.findall(r"aitools-alerts run[^\n|<>]*", hook) == ["aitools-alerts run --json "]
    for name in ("templates/launchd/com.aitools.alerts.plist", "templates/cron/aitools-alerts.cron"):
        runs = re.findall(r"aitools-alerts run\b[^\n]*", (ROOT / name).read_text())
        assert len(runs) == 1 and "--json" not in runs[0], name


def test_off_reads_nothing_and_matched_reads_only_what_is_installed(feed, monkeypatch, capsys):
    other = advisory(posted_by="relay-bot", id=G2, level="high", products=[Product("git", "git", "<9", "9")])
    feed([bot(), other], 'verify = "off"\n')
    n = use(monkeypatch, Net())
    assert out_of(capsys, ["run"])[0] == 0 and out_of(capsys, ["verify"])[1].startswith("source check: 0 confirmed, 0 contradicted, 2 not verified")
    assert n.calls == [] and not (config.state_dir() / verify.FILE).exists()
    feed([bot(), other])  # the default: matched
    cli.main(["run"])
    assert n.urls == [gurl(G1)]
    feed([bot(), other], 'verify = "all"\n')
    cli.main(["run"])
    assert sorted(n.urls) == sorted([gurl(G1), gurl(G1), gurl(G2)])


@pytest.mark.parametrize("text, ok", [('verify = "matched"', True), ('verify = "all"', True), ('verify = "off"', True),
                                      ('verify = "sometimes"', False), ("verify = true", False), ("verify = []", False)])
def test_the_verify_key(text, ok, capsys):
    config.write_default(force=True)
    assert config.load().verify == "matched"
    config.config_path().write_text(text + "\n")
    if ok:
        assert config.load().verify == text.split('"')[1]
    else:
        with pytest.raises(config.ConfigError, match="verify must be one of matched, all, off"):
            config.load()


# ------------------------------------------------------------------ a failed read changes nothing

@pytest.mark.parametrize("answer", [404, 429, TRUNCATED, OSError(SENTINEL), 301])
def test_a_failed_read_changes_nothing_the_member_is_shown(feed, monkeypatch, capsys, answer):
    feed([bot(level="critical")], 'verify = "off"\n')
    off = out_of(capsys, ["run"])
    json_off, check_off = out_of(capsys, ["run", "--json"]), out_of(capsys, ["check"])
    path = config.config_path()
    path.write_text(path.read_text().replace('verify = "off"\n', ""))  # the same feed, the check turned on
    n = use(monkeypatch, Net().set(gurl(G1), answer))
    cli.main(["verify"])  # a read fails
    assert len(n.calls) == 1
    seen = config.state_dir() / "seen.json"
    seen.unlink()  # the first run notified; ask again as if it had not
    assert out_of(capsys, ["run"]) == off
    assert out_of(capsys, ["check"]) == check_off
    after = json.loads(out_of(capsys, ["run", "--json"])[1])
    before = json.loads(json_off[1])
    assert after["matches"][0].pop("source_check") == {"result": "unknown", "why": "unread", "source_level": None}
    assert before["matches"][0].pop("source_check") == {"result": "unknown", "why": "off", "source_level": None}
    assert after == before


def test_a_crash_in_the_check_is_one_fixed_line_and_the_same_exit_status(feed, monkeypatch, capsys):
    feed([bot(level="critical")])

    def boom(*a, **k):
        raise RuntimeError(SENTINEL)
    monkeypatch.setattr(verify, "run", boom)
    status, out, err = out_of(capsys, ["run"])
    assert status == cli.EXIT_UNSEEN_CRITICAL and "CRITICAL" in out
    assert "aitools-alerts: source check failed\n" in err and SENTINEL not in out + err


# ------------------------------------------------------------------ what it prints

def test_published_below_the_source_is_flagged(feed, monkeypatch, capsys):
    feed([bot(level="high")])
    use(monkeypatch, Net().set(gurl(G1), ghsa(type="malware")))
    status, out, _ = out_of(capsys, ["run"])
    line = f"source check: {G1} is published at high for Claude Code; the source supports critical\n"
    assert status == 0 and line in out
    assert "HIGH: Invented critical for tests" in out  # the level shown is still the published one
    assert line in out_of(capsys, ["check"])[1] and line in out_of(capsys, ["plan", G1])[1]
    assert out_of(capsys, ["verify"])[1].startswith("source check: 0 confirmed, 1 contradicted, 0 not verified\n" + line)
    data = json.loads(out_of(capsys, ["check", "--json"])[1])
    assert data[0]["source_check"] == {"result": "contradicted", "why": "below-source", "source_level": "critical"}
    assert data[0]["level"] == "high"
    assert json.loads(out_of(capsys, ["run", "--json"])[1])["matches"][0]["source_check"]["why"] == "below-source"


def test_a_cli_the_root_calls_too_old_does_not_say_the_source_supports_more(feed, monkeypatch, capsys):
    feed([bot(level="high")], min_cli="99.0.0")
    use(monkeypatch, Net().set(gurl(G1), ghsa(type="malware")))
    status, out, err = out_of(capsys, ["run"])
    assert "source check:" not in out and "upgrade:" in err


def test_an_alert_the_source_does_not_support_is_flagged_per_product(feed, monkeypatch, capsys):
    feed([bot(id=CVE, level="critical", products=("Claude Code", "Codex", "Nobody Runs This"))], 'verify = "all"\n')
    use(monkeypatch, Net().set(verify.KEV_URL, kev((CVE, "OpenAI", "Codex"))))
    _, out, _ = out_of(capsys, ["run"])
    assert out.count("source check:") == 1
    assert f"source check: the source does not support {CVE} for Claude Code\n" in out
    assert "Nobody Runs This" not in out  # outside this reader's scope file: not judged, never printed
    assert out_of(capsys, ["verify"])[1].startswith("source check: 0 confirmed, 1 contradicted, 0 not verified")


def test_a_cli_the_root_calls_too_old_prints_no_source_check_line_at_all(feed, monkeypatch, capsys):
    feed([bot(id=CVE, level="critical")], min_cli="99.0.0")
    use(monkeypatch, Net().set(verify.KEV_URL, kev((CVE, "Cisco", "IOS XE"))))
    for argv in (["run"], ["check"], ["plan", CVE]):
        assert "source check: the source" not in out_of(capsys, argv)[1], argv


def test_the_notification_is_sent_before_any_source_is_read(feed, monkeypatch, capsys):
    feed([bot(id=CVE, level="critical")])
    order = []
    monkeypatch.setattr(notify, "send", lambda *a, **k: order.append("notify") or SendResult(True, "fake"))

    def fetch(*a):
        order.append("fetch")
        raise OSError("down")
    use(monkeypatch, fetch)
    assert cli.main(["run"]) == cli.EXIT_UNSEEN_CRITICAL and order == ["notify", "fetch"]


@pytest.mark.parametrize("damage", ['{"version": 1', '[]', "RESULT-LIST"])
def test_a_damaged_cache_never_stops_the_hook_s_command(feed, monkeypatch, capsys, damage):
    feed([bot(id=CVE, level="critical")])
    use(monkeypatch, Net().set(verify.KEV_URL, KEV_CC))
    cli.main(["run"])
    (config.state_dir() / "seen.json").unlink()
    path = config.state_dir() / verify.FILE
    if damage == "RESULT-LIST":
        good = json.loads(path.read_text())
        next(iter(good["results"].values()))["products"]["Claude Code"]["result"] = []
        damage = json.dumps(good)
    path.write_text(damage)
    status, out, err = out_of(capsys, ["run", "--json"])
    assert status == cli.EXIT_UNSEEN_CRITICAL and "Traceback" not in err
    assert json.loads(out)["matches"][0]["source_check"]["why"] == "unread"
    for argv in (["check"], ["plan", CVE], ["run"]):
        assert out_of(capsys, argv)[0] in (0, cli.EXIT_UNSEEN_CRITICAL)

def test_confirmed_and_unknown_print_no_line(feed, monkeypatch, capsys):
    feed([bot(id=CVE, level="critical"), bot(id="https://evil.example/GHSA-aaaa-bbbb-cccc", level="critical")],
         'verify = "all"\n')
    n = use(monkeypatch, Net().set(verify.KEV_URL, KEV_CC))
    _, out, _ = out_of(capsys, ["run"])
    assert "source check" not in out and n.urls == [verify.KEV_URL]
    assert out_of(capsys, ["verify"])[1] == "source check: 1 confirmed, 0 contradicted, 1 not verified\n"
    data = json.loads(out_of(capsys, ["check", "--json"])[1])
    assert sorted(d["source_check"]["why"] for d in data) == ["match", "no-source"]


def test_a_curator_s_thread_has_no_result(feed, monkeypatch, capsys):
    m = feed([])
    m.root_post(m.cur_sec, advisory(id=G1))
    m.write(Path(config.load().mirror_url[len("file://"):]))
    n = use(monkeypatch, Net())
    cli.main(["run"])
    assert n.calls == []
    assert json.loads(out_of(capsys, ["check", "--json"])[1])[0]["source_check"] is None
    assert out_of(capsys, ["verify"])[1] == "source check: 0 confirmed, 0 contradicted, 0 not verified\n"


def test_nothing_a_source_says_is_printed(feed, monkeypatch, capsys):
    feed([bot(id=G1, level="high"), bot(id=G2, level="critical"), bot(id=CVE, level="critical")], 'verify = "all"\n')
    hostile = ghsa(G2, type="malware", pkgs=(("npm", f"{SENTINEL}-pkg"),), withdrawn_at=f"{SENTINEL}-when")
    use(monkeypatch, Net().set(gurl(G1), ('"' + SENTINEL + '"', ghsa(type="malware", cve=f"{SENTINEL}-cve")))
        .set(gurl(G2), hostile)
        .set(verify.KEV_URL, ('{"' + SENTINEL + '": 1, "' + SENTINEL + '": 2}').encode()))
    for argv in (["run"], ["verify"], ["check"], ["check", "--json"], ["run", "--json"], ["plan", G1]):
        _, out, err = out_of(capsys, argv)
        assert SENTINEL not in out + err, argv
    assert f"{G1} is published at high" in out_of(capsys, ["check"])[1]
    use(monkeypatch, Net().set(gurl(G2), OSError(SENTINEL)).set(verify.KEV_URL, TimeoutError(SENTINEL)))
    for argv in (["run"], ["verify"]):
        _, out, err = out_of(capsys, argv)
        assert SENTINEL not in out + err, argv
