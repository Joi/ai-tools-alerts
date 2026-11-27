"""A relay-bot ``fixed`` the advisory does not state, through the CLI (ai-tools-alerts#53fy):
the acceptance cases of the issue, and the correction a member is sent when the flag is
found after the notification."""

import json

import pytest

from aitools_alerts import check, cli, inventory, verify
from aitools_alerts.inventory import Installed, Inventory
from aitools_alerts.schema import Action, Product
from aitools_alerts.state import State
from mirror_helpers import advisory
from test_curator_hold_cli import AT, serve
from test_unverified_cli import C0, sent  # noqa: F401 - sent is a fixture
from test_verify import CC, G1, G2, Net, ghsa, gurl
from test_verify_cli import _pin, bot, env, feed, out_of, use  # noqa: F401 - env and feed are fixtures
from test_verify_narrowing import vuln

CODEX = ("npm", "@openai/codex")
RIGHT = Product("Claude Code", "claude-code", "<9.9.9", "9.9.9")  # what the advisory of test_verify.ghsa states
PAST = {"name": "Claude Code", "ecosystem": "claude-code", "affected": "<50.0.0", "fixed": "50.0.0"}
LINE = cli.FIXED_LINE.format(id=G1, name="Claude Code")
NO_COMMAND = f"{check.NOT_THE_ADVISORYS}: notify only, no command"
COMMAND = "command: npm install -g @anthropic-ai/claude-code@50.0.0"
JA = "lang: ja\n\n題\nClaude Code を 50.0.0 以降に更新してください。"
OFF = 'verify = "off"\n'


def raised(feed, clock, extra="", level="critical", ja=False, **kw):
    """A relay-bot thread that stated the advisory's ``fixed`` (9.9.9), and a reply that
    raises it to 50.0.0: a widening, joined at once. Pulled."""
    root_adv = advisory(posted_by="relay-bot", id=G1, level=level, products=[RIGHT],
                        actions=[Action("upgrade", "Claude Code", "9.9.9")])
    m = feed([root_adv], extra, **kw)
    root = m.events["feed.json"][0]
    reply = m.post(m.bot_sec, m.patch_text(products=[PAST]), created_at=AT, tags=[["e", root["id"], "", "root"]])
    if ja:  # one translation of the root, one of the change: both are needed for either to show
        m.reply(m.bot_sec, root, "lang: ja\n\n題\n本文", created_at=AT + 1)
        m.reply(m.bot_sec, root, JA.replace("\n\n題", f"\nof: {reply['id']}\n"), created_at=AT + 2)
    serve(m, clock, C0)
    assert cli.main(["pull"]) == 0
    return m, root


def matches(capsys) -> list:
    return json.loads(out_of(capsys, ["check", "--json"])[1])


def source(monkeypatch, answer=None):
    return use(monkeypatch, Net().set(gurl(G1), ghsa() if answer is None else answer))


def keys() -> set:
    """What seen.json holds that is no stored event's id: the corrections sent."""
    st = State.load()
    return {k for k in st.seen if k not in st.events}


# ---------------------------------------------------------------- acceptance 1: raised past the advisory

def test_a_reply_that_raises_fixed_past_the_advisory_is_flagged_and_gives_no_upgrade_version(
        feed, sent, monkeypatch, capsys, reader_clock):
    raised(feed, reader_clock)
    (d,) = matches(capsys)
    assert d["product"]["fixed"] == "50.0.0" and d["fixed_contradicted"] is False  # joined at once; nothing read yet
    source(monkeypatch)
    status, out, _ = out_of(capsys, ["run"])
    assert status == cli.EXIT_UNSEEN_CRITICAL and LINE in out  # it still interrupts
    (d,) = matches(capsys)
    assert (d["fixed_contradicted"], d["level"], d["reason"]) == (True, "critical", "affected")
    assert d["product"] == PAST  # the alert is not narrowed: the entry is as published
    for argv in (["check"], ["plan", G1], ["verify"], ["run"]):
        assert out_of(capsys, argv)[1].count(LINE) == 1, argv
    plan = out_of(capsys, ["plan", G1])[1]
    assert "command:" not in plan and NO_COMMAND in plan and "50.0.0" not in plan
    assert "upgrade Claude Code (the fixed version given is not the advisory's)" in plan
    assert json.loads(out_of(capsys, ["run", "--json"])[1])["matches"][0]["fixed_contradicted"] is True


def test_a_root_posted_with_a_fixed_the_advisory_does_not_state_is_flagged_the_same_way(feed, sent, monkeypatch, capsys):
    feed([bot(id=G1, level="critical")])  # fixed 99.0.0
    source(monkeypatch)
    assert LINE in out_of(capsys, ["run"])[1]
    (d,) = matches(capsys)
    assert d["fixed_contradicted"] is True and "command:" not in out_of(capsys, ["plan", G1])[1]


# ---------------------------------------------------------------- acceptance 2: raised to what the advisory states

def test_a_reply_that_raises_fixed_to_what_the_advisory_now_states_shows_the_version(
        feed, sent, monkeypatch, capsys, reader_clock):
    raised(feed, reader_clock)
    source(monkeypatch, ghsa(vulnerabilities=[vuln("< 50.0.0", "50.0.0")]))
    status, out, _ = out_of(capsys, ["run"])
    assert status == cli.EXIT_UNSEEN_CRITICAL and LINE not in out
    (d,) = matches(capsys)
    assert d["fixed_contradicted"] is False and d["product"]["fixed"] == "50.0.0"
    plan = out_of(capsys, ["plan", G1])[1]
    assert COMMAND in plan and LINE not in plan and "upgrade Claude Code to 50.0.0 or later" in plan
    assert len(sent["texts"]) == 1 and keys() == set()


def test_the_flag_ends_when_the_advisory_comes_to_state_the_version(feed, sent, monkeypatch, capsys, reader_clock):
    raised(feed, reader_clock)
    n = source(monkeypatch)
    assert LINE in out_of(capsys, ["run"])[1]
    n.set(gurl(G1), ghsa(vulnerabilities=[vuln("< 50.0.0", "50.0.0")]))
    from test_unverified_cli import clock_at
    clock_at(monkeypatch, verify.time.time() + verify.RETRY_S + 60)
    out = out_of(capsys, ["run"])[1]
    assert LINE not in out and COMMAND in out_of(capsys, ["plan", G1])[1]


# ---------------------------------------------------------------- acceptance 3: the fetch fails

@pytest.mark.parametrize("how", [404, 429, OSError("ZZ-SENTINEL"), "off", "partial"])
def test_with_the_fetch_failing_nothing_changes(feed, sent, monkeypatch, capsys, reader_clock, how):
    raised(feed, reader_clock, OFF if how == "off" else "")
    if how == "partial":  # the advisory names another id, and that read fails: it may state the version
        body = ghsa(identifiers=[{"type": "GHSA", "value": G1}, {"type": "GHSA", "value": G2}])
        n = use(monkeypatch, Net().set(gurl(G1), body).set(gurl(G2), 404))
    else:
        n = source(monkeypatch, 404 if how == "off" else how)
    for _ in range(2):
        status, out, _ = out_of(capsys, ["run"])
        assert LINE not in out
    assert status == 0 and (n.calls == []) == (how == "off")
    (text,) = sent["texts"]  # one notification, as today, and no correction
    assert "Affected: Claude Code 2.0.0 (fixed in 50.0.0)" in text and "upgrade Claude Code to 50.0.0 or later" in text
    (d,) = matches(capsys)
    assert d["fixed_contradicted"] is False
    plan = out_of(capsys, ["plan", G1])[1]
    assert COMMAND in plan and LINE not in plan and LINE not in out_of(capsys, ["check"])[1]
    assert keys() == set()


def test_a_cli_the_trust_root_calls_too_old_flags_and_corrects_nothing(feed, sent, monkeypatch, capsys, reader_clock):
    """It still reads the source (``_source_check`` does not look at ``min_cli``), and what
    it read is not used: its ruleset and scope file may be the ones that are wrong."""
    raised(feed, reader_clock, min_cli="99.0.0")
    n = source(monkeypatch)
    for _ in range(2):
        assert LINE not in out_of(capsys, ["run"])[1]
    assert n.calls != []
    (text,) = sent["texts"]
    assert "50.0.0" in text and keys() == set()
    assert matches(capsys)[0]["fixed_contradicted"] is False and COMMAND in out_of(capsys, ["plan", G1])[1]
    assert cli.main(["notify"]) == 0 and len(sent["texts"]) == 1


def test_a_cli_whose_ruleset_is_out_of_date_flags_nothing(feed, sent, monkeypatch, capsys, reader_clock):
    raised(feed, reader_clock, ruleset_pin=_pin(sha256="0" * 64))
    source(monkeypatch)
    for _ in range(2):
        assert LINE not in out_of(capsys, ["run"])[1]
    assert len(sent["texts"]) == 1 and keys() == set()
    assert matches(capsys)[0]["fixed_contradicted"] is False and COMMAND in out_of(capsys, ["plan", G1])[1]


def test_an_alert_shown_at_notice_for_want_of_support_is_not_flagged(feed, monkeypatch, capsys):
    from test_never_supported_cli import read_as_unsupported
    read_as_unsupported(feed, monkeypatch)
    (d,) = matches(capsys)
    assert (d["level"], d["published_level"], d["fixed_contradicted"]) == ("notice", "critical", False)


def test_a_read_whose_cache_cannot_be_written_still_flags_in_that_command(feed, sent, monkeypatch, capsys, reader_clock):
    raised(feed, reader_clock)
    source(monkeypatch)

    def full(path, obj):
        raise OSError(28, "No space left on device")
    monkeypatch.setattr(verify, "write_json", full)
    status, out, err = out_of(capsys, ["run"])
    assert status == cli.EXIT_UNSEEN_CRITICAL and cli.SOURCE_CHECK_FAILED in err and LINE in out
    assert len(sent["texts"]) == 2 and sent["texts"][1].startswith(cli.CORRECTION_LINE)
    assert LINE in out_of(capsys, ["verify"])[1]


# ---------------------------------------------------------------- the correction

def test_run_notifies_before_it_reads_and_corrects_once_in_the_same_run(feed, sent, monkeypatch, capsys, reader_clock):
    """A critical never waits for a source, so the notification names the raised version.
    Left there it would be the only word the member gets."""
    raised(feed, reader_clock)
    source(monkeypatch)
    assert out_of(capsys, ["run"])[0] == cli.EXIT_UNSEEN_CRITICAL
    first, correction = sent["texts"]
    assert "upgrade Claude Code to 50.0.0 or later" in first
    lines = correction.splitlines()
    assert lines[0] == cli.CORRECTION_LINE and lines[1].startswith("CRITICAL: ") and "50.0.0" not in correction
    assert "Action: upgrade Claude Code (the fixed version given is not the advisory's)" in lines
    assert len(keys()) == 1
    assert out_of(capsys, ["run"])[0] == 0 and cli.main(["notify"]) == 0
    assert len(sent["texts"]) == 2 and len(keys()) == 1


def test_a_flag_found_by_a_later_run_is_corrected_then(feed, sent, monkeypatch, capsys, reader_clock):
    raised(feed, reader_clock)
    n = source(monkeypatch, 404)
    assert out_of(capsys, ["run"])[0] == cli.EXIT_UNSEEN_CRITICAL and len(sent["texts"]) == 1
    n.set(gurl(G1), ghsa())
    status, out, _ = out_of(capsys, ["run"])
    assert status == 0 and LINE in out
    assert len(sent["texts"]) == 2 and sent["texts"][1].startswith(cli.CORRECTION_LINE)
    assert out_of(capsys, ["run"])[0] == 0 and len(sent["texts"]) == 2


def test_a_correction_no_channel_accepted_is_sent_again(feed, monkeypatch, capsys, reader_clock):
    from aitools_alerts import notify
    from aitools_alerts.notify import SendResult
    log = {"refuse": True, "texts": []}

    def fake(channel, text, settings, **kw):
        log["texts"].append(text)
        return SendResult(not (log["refuse"] and text.startswith(cli.CORRECTION_LINE)), "fake")
    monkeypatch.setattr(notify, "send", fake)
    raised(feed, reader_clock)
    source(monkeypatch)
    assert out_of(capsys, ["run"])[0] == cli.EXIT_UNSEEN_CRITICAL  # the alert itself was delivered
    assert len(log["texts"]) == 2 and keys() == set()
    assert out_of(capsys, ["run"])[0] == 1 and cli.main(["notify"]) == 1 and len(log["texts"]) == 4
    log["refuse"] = False
    assert cli.main(["notify"]) == 0 and len(log["texts"]) == 5 and len(keys()) == 1
    assert cli.main(["notify"]) == 0 and out_of(capsys, ["run"])[0] == 0 and len(log["texts"]) == 5


def test_a_notification_that_named_no_version_is_not_corrected(feed, sent, monkeypatch, capsys, reader_clock):
    raised(feed, reader_clock)
    source(monkeypatch)
    assert cli.main(["verify"]) == 0 and sent["texts"] == []  # the source is read before anything is sent
    assert out_of(capsys, ["run"])[0] == cli.EXIT_UNSEEN_CRITICAL
    (text,) = sent["texts"]
    assert "50.0.0" not in text and not text.startswith(cli.CORRECTION_LINE)
    assert "Affected: Claude Code 2.0.0\n" in text
    assert out_of(capsys, ["run"])[0] == 0 and cli.main(["notify"]) == 0
    assert len(sent["texts"]) == 1 and len(keys()) == 1


def test_no_correction_for_an_alert_that_never_interrupted(feed, sent, monkeypatch, capsys, reader_clock):
    raised(feed, reader_clock, level="high")
    source(monkeypatch)
    for _ in range(2):
        status, out, _ = out_of(capsys, ["run"])
        assert status == 0 and LINE in out
    assert cli.main(["notify"]) == 0 and sent["texts"] == [] and keys() == set()


def test_run_json_sends_a_due_correction_and_prints_one_object(feed, sent, monkeypatch, capsys, reader_clock):
    raised(feed, reader_clock)
    n = source(monkeypatch, 404)
    assert out_of(capsys, ["run"])[0] == cli.EXIT_UNSEEN_CRITICAL and len(sent["texts"]) == 1
    n.set(gurl(G1), ghsa())
    assert cli.main(["verify"]) == 0 and len(sent["texts"]) == 1  # verify reads, and sends nothing
    calls = len(n.calls)
    status, out, _ = out_of(capsys, ["run", "--json"])
    data = json.loads(out)  # nothing else on stdout
    assert status == 0 and data["matches"][0]["fixed_contradicted"] is True and data["unseen_critical"] == []
    assert len(n.calls) == calls  # the hook's command reads no source
    assert len(sent["texts"]) == 2 and sent["texts"][1].startswith(cli.CORRECTION_LINE)


# ---------------------------------------------------------------- translations

def test_a_translation_that_names_the_version_is_not_shown_for_a_flagged_entry(feed, sent, monkeypatch, capsys, reader_clock):
    raised(feed, reader_clock, 'lang = "ja"\n', ja=True)
    source(monkeypatch)
    assert "更新" in out_of(capsys, ["plan", G1])[1]  # before the source is read: as today
    assert out_of(capsys, ["run"])[0] == cli.EXIT_UNSEEN_CRITICAL
    first, correction = sent["texts"]
    assert "更新" in first and "更新" not in correction and "題" not in correction and "50.0.0" not in correction
    plan = out_of(capsys, ["plan", G1])[1]
    assert "更新" not in plan and "題" not in plan and "50.0.0" not in plan and "    > " not in plan
    assert plan.startswith("CRITICAL: ") and NO_COMMAND in plan


def both(feed, monkeypatch, codex_fixed, extra=""):
    """A relay-bot critical for Claude Code (fixed 50.0.0, not the advisory's) and Codex
    (``codex_fixed``), both installed here, with a Japanese translation naming 50.0.0."""
    inv = Inventory(products={"claude-code": [Installed("Claude Code", "2.0.0", "/invented/bin/claude")],
                              "codex": [Installed("Codex", "2.0.0", "/invented/bin/codex")]})
    monkeypatch.setattr(inventory, "collect", lambda *a, **k: inv)
    a = advisory(posted_by="relay-bot", id=G1, level="critical",
                 products=[Product(**PAST), Product("Codex", "codex", f"<{codex_fixed}", codex_fixed)],
                 actions=[Action("upgrade", "Claude Code", "50.0.0"), Action("upgrade", "Codex", codex_fixed)])
    m = feed([a], extra)
    m.reply(m.bot_sec, m.events["feed.json"][0], JA, created_at=AT + 1)
    m.write(__import__("pathlib").Path(__import__("aitools_alerts").config.load().mirror_url[len("file://"):]))
    use(monkeypatch, Net().set(gurl(G1), ghsa(pkgs=(CC, CODEX))))
    assert cli.main(["pull"]) == 0 and cli.main(["verify"]) == 0
    return m


def test_two_flagged_products_are_one_notification_and_no_correction(feed, sent, monkeypatch, capsys):
    """A notification describes one match of an entry. The other flagged match was never
    said with a version either: nothing is left to correct."""
    both(feed, monkeypatch, "50.0.0")
    assert [d["fixed_contradicted"] for d in matches(capsys)] == [True, True]
    assert out_of(capsys, ["run"])[0] == cli.EXIT_UNSEEN_CRITICAL
    (text,) = sent["texts"]
    assert "50.0.0" not in text and not text.startswith(cli.CORRECTION_LINE)
    assert out_of(capsys, ["run"])[0] == 0 and cli.main(["notify"]) == 0
    assert len(sent["texts"]) == 1 and len(keys()) == 2


@pytest.mark.parametrize("first", ["claude-code", "codex"])
def test_an_unflagged_match_of_the_same_entry_shows_no_translation_either(feed, sent, monkeypatch, capsys, first):
    """The translation belongs to the entry: quoted under the Codex match, it would still
    name the version given for Claude Code."""
    both(feed, monkeypatch, "9.9.9", 'lang = "ja"\n')
    got = {d["product"]["name"]: d["fixed_contradicted"] for d in matches(capsys)}
    assert got == {"Claude Code": True, "Codex": False}
    plan = out_of(capsys, ["plan", G1])[1]
    assert "更新" not in plan and "題" not in plan and "    > " not in plan
    assert "command: npm install -g @openai/codex@9.9.9" in plan and "claude-code@" not in plan
    if first == "codex":  # whichever match the notification describes
        real = cli._interrupts

        def reordered(*a, **k):
            pending, *rest = real(*a, **k)
            return (sorted(pending, key=lambda x: x[1].product.ecosystem != "codex"), *rest)
        monkeypatch.setattr(cli, "_interrupts", reordered)
    assert out_of(capsys, ["run"])[0] == cli.EXIT_UNSEEN_CRITICAL
    (text,) = sent["texts"]
    assert "更新" not in text and "題" not in text and "50.0.0" not in text
    assert ("Affected: Codex" in text) == (first == "codex")
    assert out_of(capsys, ["run"])[0] == 0 and len(sent["texts"]) == 1
