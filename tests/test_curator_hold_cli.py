"""The member's source check decides a published lowering (ai-tools-alerts#c1g2): the three
acceptance cases of the issue through the CLI, and what a stolen key must not get."""

import json
from dataclasses import replace
from pathlib import Path

import pytest

from aitools_alerts import cli, config, pull, ruleset, verify
from mirror_helpers import T0
from test_verify import CVE, G1, KEV_CC, NOW, Net, adv, ghsa, go, gurl, kev
from test_verify_cli import bot, env, feed, out_of, use  # noqa: F401 - env and feed are fixtures

DAY = 86400
AT = T0 + 300  # when the curator acts
ALL = 'verify = "all"\n'
CC = {"name": "Claude Code", "ecosystem": "claude-code", "affected": "<99.0.0", "fixed": "99.0.0"}


def serve(m, clock, at):
    """Sign a checkpoint dated ``at``, serve the mirror again, and set the member's clock."""
    m.clock = clock.at = at
    m.checkpoint(now=at)
    m.write(Path(config.load().mirror_url[len("file://"):]))


def levels(capsys) -> dict:
    """{advisory id: level} of what ``check`` matches on this machine, after a pull."""
    assert cli.main(["pull"]) == 0
    return {d["id"]: d["level"] for d in json.loads(out_of(capsys, ["check", "--json"])[1])}


# ---------------------------------------------------------------- the acceptance cases

def test_a_curator_notice_on_a_thread_the_kev_lists_keeps_critical_and_is_flagged(feed, monkeypatch, capsys, reader_clock):
    m = feed([bot(id=CVE, level="critical")], ALL)
    m.reply(m.cur_sec, m.events["feed.json"][0], "level: notice", created_at=AT)
    serve(m, reader_clock, AT + 100)
    n = use(monkeypatch, Net().set(verify.KEV_URL, KEV_CC))
    assert levels(capsys) == {CVE: "notice"} and n.calls == []  # no source read yet: the curator's word holds
    status, out, _ = out_of(capsys, ["run"])
    line = f"source check: a lowering of {CVE} to notice is not applied: the source supports critical for Claude Code"
    assert line in out and status == cli.EXIT_UNSEEN_CRITICAL  # contradicted and notified in the same run
    first, _, after = out.partition("After the source check:\n")
    assert first.startswith("NOTICE: ") and after.startswith("CRITICAL: ")  # and listed as it now stands
    assert n.urls == [verify.KEV_URL]
    _, out, _ = out_of(capsys, ["check"])
    assert out.startswith("CRITICAL: ") and line in out
    (d,) = json.loads(out_of(capsys, ["run", "--json"])[1])["matches"]
    assert (d["level"], d["lowering_refused"]) == ("critical", "notice")
    assert out_of(capsys, ["run"])[0] == 0  # seen: one notification
    serve(m, reader_clock, AT + 15 * DAY)  # and after the hold it is the bot's thread again
    assert levels(capsys) == {CVE: "critical"}


def test_a_curator_raise_then_a_bot_lowering_the_source_confirms_lowers_after_the_hold(feed, monkeypatch, capsys,
                                                                                         reader_clock):
    m = feed([bot(id=G1, level="high")], ALL)
    root = m.events["feed.json"][0]
    m.reply(m.cur_sec, root, m.patch_text(level="critical"), created_at=AT)
    m.reply(m.bot_sec, root, m.patch_text(level="high"), created_at=AT + 5 * DAY)  # inside the 14 days
    serve(m, reader_clock, AT + 6 * DAY)
    use(monkeypatch, Net().set(gurl(G1), ghsa()))  # the source gives high
    assert levels(capsys) == {G1: "critical"}
    cli.main(["verify"])
    assert levels(capsys) == {G1: "critical"}  # confirmed, and still the curator's 14 days
    m.reply(m.bot_sec, root, m.patch_text(level="high"), created_at=AT + 15 * DAY)
    serve(m, reader_clock, AT + 15 * DAY + 100)
    assert levels(capsys) == {G1: "high"}
    assert "is not applied" not in out_of(capsys, ["check"])[1]


@pytest.mark.parametrize("source, want, flagged", [
    (OSError("down"), "critical", False),  # unread: a relay-bot lowering never applies unchecked
    (ghsa(type="malware"), "critical", True),  # the source supports more
    (ghsa(), "high", False),
])
def test_a_bot_lowering_alone_applies_only_when_the_source_gives_that_level(feed, monkeypatch, capsys, reader_clock,
                                                                             source, want, flagged):
    m = feed([bot(id=G1, level="critical")], ALL)
    m.reply(m.bot_sec, m.events["feed.json"][0], m.patch_text(level="high"), created_at=AT)
    serve(m, reader_clock, AT + 100)
    use(monkeypatch, Net().set(gurl(G1), source))
    assert levels(capsys) == {G1: "critical"}
    _, out, _ = out_of(capsys, ["verify"])
    assert (f"source check: a lowering of {G1} to high is not applied: the source supports critical for Claude Code"
            in out) is flagged
    assert levels(capsys) == {G1: want}


def test_a_curator_retraction_with_no_machine_readable_source_lapses_after_fourteen_days(feed, monkeypatch, capsys,
                                                                                          reader_clock):
    m = feed([bot(id="AITA-TEST-0001", level="critical")], ALL)
    root = m.events["feed.json"][0]
    m.reply(m.cur_sec, root, "retract", created_at=AT)
    n = use(monkeypatch, Net())
    for at, want in ((AT + 13 * DAY, {}), (AT + 14 * DAY + 1, {"AITA-TEST-0001": "critical"})):
        serve(m, reader_clock, at)
        cli.main(["verify"])
        assert levels(capsys) == want, at
    assert n.calls == []  # nothing to ask: the id names no source
    m.reply(m.cur_sec, root, "retract", created_at=AT + 15 * DAY)  # issued again, then renewed at day 25
    m.reply(m.cur_sec, root, "retract", created_at=AT + 25 * DAY)
    for at, want in ((AT + 35 * DAY, {}), (AT + 39 * DAY, {}), (AT + 39 * DAY + 1, {"AITA-TEST-0001": "critical"})):
        serve(m, reader_clock, at)
        assert levels(capsys) == want, at


def test_verify_counts_the_alert_a_refused_retraction_brought_back(feed, monkeypatch, capsys, reader_clock):
    m = feed([bot(id=CVE, level="critical")], ALL)
    m.reply(m.cur_sec, m.events["feed.json"][0], "retract", created_at=AT)
    serve(m, reader_clock, AT + 100)
    use(monkeypatch, Net().set(verify.KEV_URL, KEV_CC))
    assert levels(capsys) == {}
    _, out, _ = out_of(capsys, ["verify"])
    # the alert is back and counted; its own state is read on the next run
    assert out == ("source check: 0 confirmed, 0 contradicted, 1 not verified\n"
                   "source check: 1 lowerings or retractions asked about: 0 confirmed, 1 contradicted, 0 not settled\n"
                   f"source check: a retraction of {CVE} is not applied: the source supports critical for Claude Code\n")
    assert levels(capsys) == {CVE: "critical"}
    status, out, _ = out_of(capsys, ["run"])
    assert status == cli.EXIT_UNSEEN_CRITICAL and "After the source check" not in out  # nothing changed in this run


# ---------------------------------------------------------------- what a stolen key must not get

def test_respelling_the_product_does_not_take_a_curator_lowering_past_the_source(feed, monkeypatch, capsys, reader_clock):
    m = feed([bot(id=CVE, level="critical")], ALL)
    loud = {"name": "CLAUDE CODE", "ecosystem": "claude-code", "affected": None, "fixed": None}
    m.reply(m.cur_sec, m.events["feed.json"][0], "level: notice\n" + m.patch_text(products=[loud]), created_at=AT)
    serve(m, reader_clock, AT + 100)
    use(monkeypatch, Net().set(verify.KEV_URL, KEV_CC))
    assert levels(capsys) == {CVE: "notice"}
    _, out, _ = out_of(capsys, ["verify"])
    assert f"a lowering of {CVE} to notice is not applied: the source supports critical for Claude Code" in out
    assert levels(capsys) == {CVE: "critical"}


def test_a_fix_a_curator_supplied_keeps_the_source_at_critical_for_a_later_bot_lowering(feed, monkeypatch, capsys,
                                                                                        reader_clock):
    from aitools_alerts.schema import Product
    nofix = replace(bot(id=CVE, level="high", actions=[]), products=[Product("Claude Code", "claude-code", None, None)])
    m = feed([nofix], ALL)
    root = m.events["feed.json"][0]
    m.reply(m.cur_sec, root, m.patch_text(level="critical", products=[CC], actions=[
        {"verb": "upgrade", "target": "Claude Code", "value": "99.0.0"}]), created_at=AT)
    m.reply(m.bot_sec, root, m.patch_text(level="high"), created_at=AT + 15 * DAY)
    serve(m, reader_clock, AT + 15 * DAY + 100)
    use(monkeypatch, Net().set(verify.KEV_URL, KEV_CC))
    assert levels(capsys) == {CVE: "critical"}
    _, out, _ = out_of(capsys, ["verify"])
    assert f"a lowering of {CVE} to high is not applied: the source supports critical" in out
    assert levels(capsys) == {CVE: "critical"}


def test_a_damaged_ruleset_stops_no_alert_and_settles_no_lowering(feed, monkeypatch, capsys, reader_clock):
    m = feed([bot(id=G1, level="critical"), bot(id="AITA-TEST-0009", level="critical")], ALL)
    m.reply(m.bot_sec, m.events["feed.json"][0], m.patch_text(level="high"), created_at=AT)
    serve(m, reader_clock, AT + 100)
    assert cli.main(["pull"]) == 0

    def broken():
        raise ruleset.RulesetError("damaged")
    monkeypatch.setattr(ruleset, "load", broken)
    # notify reads no source-check result of its own: with a lowering published it must
    # still send (check and run print results and already needed the ruleset before this)
    sent = []
    monkeypatch.setattr(cli.notify, "send", lambda ch, text, s: sent.append(text) or cli.notify.SendResult(True, "fake"))
    status, _, err = out_of(capsys, ["notify"])
    assert (status, len(sent)) == (0, 2) and "Traceback" not in err

def test_clearing_the_fixed_version_does_not_make_the_source_confirm_a_lowering(feed, monkeypatch, capsys, reader_clock):
    """A KEV listing supports critical only with a fix to upgrade to (9kgk). A relay-bot
    reply may clear ``fixed``; were the source judged against that, it would give high
    and confirm the lowering the same key then signs."""
    m = feed([bot(id=CVE, level="critical")], ALL)
    root = m.events["feed.json"][0]
    m.reply(m.bot_sec, root, m.patch_text(products=[dict(CC, fixed=None)]), created_at=AT)
    m.reply(m.bot_sec, root, m.patch_text(level="high"), created_at=AT + 10)
    serve(m, reader_clock, AT + 100)
    use(monkeypatch, Net().set(verify.KEV_URL, KEV_CC))
    assert levels(capsys) == {CVE: "critical"}
    _, out, _ = out_of(capsys, ["verify"])
    assert f"a lowering of {CVE} to high is not applied: the source supports critical" in out
    assert levels(capsys) == {CVE: "critical"}


def test_fields_that_give_notice_do_not_confirm_a_lowering_below_what_a_reading_may_hold(feed, monkeypatch, capsys,
                                                                                         reader_clock):
    assert ruleset.load().reading_cap == "high"
    m = feed([bot(id=G1, level="high")], ALL)  # may rest on a reading of the advisory's prose
    m.reply(m.bot_sec, m.events["feed.json"][0], m.patch_text(level="notice"), created_at=AT)
    serve(m, reader_clock, AT + 100)
    use(monkeypatch, Net().set(gurl(G1), ghsa(high=False)))  # the fields give notice
    assert levels(capsys) == {G1: "high"}
    cli.main(["verify"])
    assert levels(capsys) == {G1: "high"}
    a = adv(level="high")
    assert verify.result_for(verify.at_level(a, "notice"), verify.load(config.state_dir()))["Claude Code"]["why"] == "match"


@pytest.mark.parametrize("extra, min_cli", [('verify = "off"\n', None), (ALL, "99.0.0")])
def test_with_verify_off_or_a_cli_too_old_nothing_is_confirmed_or_refused(feed, monkeypatch, capsys, reader_clock,
                                                                         extra, min_cli):
    m = feed([bot(id=G1, level="critical"), bot(id=CVE, level="critical")], extra, min_cli=min_cli)
    m.reply(m.bot_sec, m.events["feed.json"][0], m.patch_text(level="high"), created_at=AT)
    m.reply(m.cur_sec, m.events["feed.json"][1], "level: notice", created_at=AT)
    serve(m, reader_clock, AT + 100)
    use(monkeypatch, Net().set(gurl(G1), ghsa()).set(verify.KEV_URL, KEV_CC))
    _, out, _ = out_of(capsys, ["verify"])
    assert "is not applied" not in out
    assert levels(capsys) == {G1: "critical", CVE: "notice"}  # the bot's waits, the curator's holds
    serve(m, reader_clock, AT + 15 * DAY)
    # tavj: with the check off the bot's lowering applies once it has stood 72 hours in
    # signed checkpoints; a CLI the trust root calls too old applies none unchecked
    assert levels(capsys) == {G1: "high" if min_cli is None else "critical", CVE: "critical"}


def test_matched_asks_only_about_a_thread_whose_widest_state_matches_this_machine(feed, monkeypatch, capsys, reader_clock):
    from aitools_alerts.schema import Action, Product
    other = replace(bot(id=G1, level="critical", actions=[Action("upgrade", "Codex CLI", "9.9.9")]),
                    products=[Product("Codex CLI", "codex", "<9.9.9", "9.9.9")])
    m = feed([other])  # verify = "matched", the default; only Claude Code is installed
    m.reply(m.bot_sec, m.events["feed.json"][0], m.patch_text(level="high"), created_at=AT)
    serve(m, reader_clock, AT + 100)
    n = use(monkeypatch, Net())
    assert cli.main(["pull"]) == 0 and cli.main(["run"]) == 0 and n.calls == []


def test_the_hook_s_command_reads_no_source_for_a_lowering(feed, monkeypatch, capsys, reader_clock):
    m = feed([bot(id=G1, level="critical")], ALL)
    m.reply(m.bot_sec, m.events["feed.json"][0], m.patch_text(level="high"), created_at=AT)
    serve(m, reader_clock, AT + 100)
    n = use(monkeypatch, Net())
    cli.main(["run", "--json"])
    assert n.calls == []


def test_a_relay_bot_thread_a_curator_amended_is_never_auto_applied(feed, monkeypatch, capsys, reader_clock):
    m = feed([bot(id="AITA-TEST-0001", level="critical")], 'auto_apply = ["upgrade"]\n')
    m.reply(m.cur_sec, m.events["feed.json"][0], m.patch_text(title="Curated"), created_at=AT)
    serve(m, reader_clock, AT + 100)
    assert cli.main(["pull"]) == 0
    _, out, _ = out_of(capsys, ["plan", "AITA-TEST-0001"])
    assert "Curated" in out and "posted by relay-bot" in out and "auto-apply" not in out and "prepare (ask first)" in out


# ---------------------------------------------------------------- verify.lowering

def test_a_confirmation_is_read_again_every_day_and_does_not_outlive_two(tmp_path):
    a = adv(level="critical")
    ask = verify.at_level(a, "high")

    def run(source, now, **kw):
        n = Net().set(gurl(G1), source)
        go(tmp_path, [a, ask], n, wanted=[ask], now=now, **kw)
        return n, verify.lowering(a, "high", verify.load(tmp_path), now)
    assert run(ghsa(), NOW, recheck=[ask])[1] is True
    n, said = run(ghsa(type="malware"), NOW + verify.RETRY_S - 1, recheck=[ask])
    assert n.calls == [] and said is True  # not yet a day old
    n, said = run(ghsa(type="malware"), NOW + verify.RETRY_S)  # without recheck a match is never read again
    assert n.calls == [] and said is True
    assert verify.lowering(a, "high", verify.load(tmp_path), NOW + verify.FRESH_S + 1) is None  # too old to authorise
    assert verify.lowering(a, "high", verify.load(tmp_path), NOW - 1) is None  # a clock set back
    n, said = run(ghsa(type="malware"), NOW + verify.RETRY_S, recheck=[ask])
    assert n.urls == [gurl(G1)] and said is False  # the source now supports more
    n, said = run(OSError("down"), NOW + 2 * verify.RETRY_S, recheck=[ask])
    assert said is False  # a failed read does not take a contradiction away
    n, said = run(ghsa(), NOW + 3 * verify.RETRY_S, recheck=[ask])
    assert said is True  # a whole read does
    n, said = run(OSError("down"), NOW + 4 * verify.RETRY_S, recheck=[ask])
    assert said is None  # and a failed read confirms nothing


def test_a_refresh_the_budget_cut_short_does_not_pass_for_a_fresh_confirmation(tmp_path, monkeypatch):
    """A thread that spent requests and ran out keeps its old result with a new time, so it
    does not come first every run. For a lowering that would renew an old confirmation."""
    a = adv(id=CVE, aliases=[G1], level="critical")
    ask = verify.at_level(a, "high")
    sources = Net().set(verify.KEV_URL, kev()).set(gurl(G1), ghsa(cve=CVE))
    go(tmp_path, [a, ask], sources, wanted=[ask], recheck=[ask])
    assert verify.lowering(a, "high", verify.load(tmp_path), NOW) is True
    later = NOW + verify.RETRY_S
    monkeypatch.setattr(verify, "MAX_FETCHES", 1)  # the catalog is read, the advisory is not
    n = Net().set(verify.KEV_URL, kev()).set(gurl(G1), ghsa(cve=CVE, type="malware"))
    go(tmp_path, [a, ask], n, wanted=[ask], now=later, recheck=[ask])
    cache = verify.load(tmp_path)
    assert n.urls == [verify.KEV_URL]
    assert cache["results"][verify.state_key(ask)] == {"at": later, "products": {
        "Claude Code": {"result": "unknown", "why": "unread", "source": None}}}
    assert verify.lowering(a, "high", cache, later) is None
    # a contradiction held before the budget ran out stays one
    monkeypatch.setattr(verify, "MAX_FETCHES", 10)
    go(tmp_path, [a, ask], n, wanted=[ask], now=later + 1, recheck=[ask])
    assert verify.lowering(a, "high", verify.load(tmp_path), later + 1) is False
    monkeypatch.setattr(verify, "MAX_FETCHES", 1)
    go(tmp_path, [a, ask], n, wanted=[ask], now=later + 1 + verify.RETRY_S, recheck=[ask])
    assert verify.lowering(a, "high", verify.load(tmp_path), later + 1 + verify.RETRY_S) is False


def test_a_confirmed_lowering_is_read_again_a_day_later_through_the_cli(feed, monkeypatch, capsys, reader_clock):
    m = feed([bot(id=G1, level="critical")], ALL)
    m.reply(m.bot_sec, m.events["feed.json"][0], m.patch_text(level="high"), created_at=AT)
    serve(m, reader_clock, AT + 100)
    use(monkeypatch, Net().set(gurl(G1), ghsa()))
    assert levels(capsys) == {G1: "critical"}
    cli.main(["verify"])
    assert levels(capsys) == {G1: "high"}
    real = verify.time.time()

    class Later:
        def __getattr__(self, name):
            return getattr(__import__("time"), name)

        def time(self):
            return real + verify.RETRY_S + 60
    monkeypatch.setattr(verify, "time", Later())
    monkeypatch.setattr(cli, "time", Later())
    n = use(monkeypatch, Net().set(gurl(G1), ghsa(type="malware")))  # the source now supports critical
    _, out, _ = out_of(capsys, ["verify"])
    assert gurl(G1) in n.urls and f"a lowering of {G1} to high is not applied" in out
    data = json.loads(out_of(capsys, ["check", "--json"])[1])
    assert [(d["level"], d["lowering_refused"]) for d in data] == [("critical", "high")]


def test_lowering_without_results_or_a_cache_settles_nothing(tmp_path):
    a = adv(level="critical")
    assert verify.lowering(a, "high", None, NOW) is None  # verify = "off"
    assert verify.lowering(a, "high", verify.load(tmp_path), NOW) is None
    assert verify.lowering(replace(a, posted_by="curator"), "high", verify.load(tmp_path), NOW) is None


@pytest.mark.parametrize("first, source, why", [
    (CVE, kev(), "unauthoritative"),  # the catalog does not list it: silence is no authority
    (G1, ghsa(type="unreviewed"), "unauthoritative"),  # a source anyone can write
    (G1, ghsa(pkgs=(("npm", "another-package"),)), "unauthoritative"),  # an authority that does not name the product
    (G1, ghsa(withdrawn_at="2026-11-01T00:00:00Z"), "match"),  # withdrawn by a source that names it
    (G1, ghsa(), "below-source"),
])
def test_a_retraction_is_contradicted_by_support_and_never_confirmed(tmp_path, first, source, why):
    a = adv(id=first, level="critical")
    ask = verify.at_level(a, pull.NONE)
    url = verify.KEV_URL if first == CVE else gurl(first)
    go(tmp_path, [a, ask], Net().set(url, source), wanted=[ask])
    cache = verify.load(tmp_path)
    assert verify.result_for(ask, cache)["Claude Code"]["why"] == why
    assert verify.lowering(a, pull.NONE, cache, NOW) is (False if why == "below-source" else None)
