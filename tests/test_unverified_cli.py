"""The D8 table through the CLI (ai-tools-alerts#tavj): the acceptance cases of the issue,
the 72 hours of a lowering nobody can check, and the cap on unverified interrupts."""

import json
from pathlib import Path

import pytest

from aitools_alerts import cli, config, notify, pull, verify, wire
from aitools_alerts.notify import SendResult
from aitools_alerts.state import State
from mirror_helpers import T0
from test_curator_hold_cli import ALL, AT, DAY, levels, serve
from test_unchecked_lowering import G4, KEV_FIELDS, claim, ghsa_fields
from test_verify import CVE, G1, G2, G3, KEV_CC, Net, ghsa, gurl, kev
from test_verify_cli import bot, env, feed, out_of, use  # noqa: F401 - env and feed are fixtures

WAIT = pull.UNCHECKED_LOWERING_S
C0 = AT + 100  # the first checkpoint that lists what a test posted at AT


@pytest.fixture
def sent(monkeypatch):
    log = {"accept": True, "texts": []}

    def fake(channel, text, settings, **kw):
        log["texts"].append(text)
        return SendResult(log["accept"], "fake")
    monkeypatch.setattr(notify, "send", fake)
    return log


def lower(m, root, level, at=AT, tag=None):
    tags = [["e", root["id"], "", "root"]] + ([tag] if tag else [])
    return m.post(m.bot_sec, m.patch_text(level=level), created_at=at, tags=tags)


def claimed_root(m, adv, c):
    return m.root_post(m.bot_sec, adv, created_at=T0 + 100, tags=[wire.claim_tag(c)])


def clock_at(monkeypatch, at):
    """This machine's clock, as the CLI and the source check read it."""
    class Clock:
        def __getattr__(self, name):
            return getattr(__import__("time"), name)

        def time(self):
            return at
    monkeypatch.setattr(cli, "time", Clock())
    monkeypatch.setattr(verify, "time", Clock())


def refusal(ident, level, more="critical"):
    return f"source check: a lowering of {ident} to {level} is not applied: the source supports {more} for Claude Code"


# ---------------------------------------------------------------- acceptance 1 and 2: the member can read

def test_the_bot_key_lowers_while_the_kev_lists_it_critical_is_kept_and_flagged(feed, monkeypatch, capsys, reader_clock):
    m = feed([bot(id=CVE, level="critical")], ALL)
    lower(m, m.events["feed.json"][0], "notice")
    serve(m, reader_clock, C0)
    use(monkeypatch, Net().set(verify.KEV_URL, KEV_CC))
    assert levels(capsys) == {CVE: "critical"}
    _, out, _ = out_of(capsys, ["verify"])
    assert refusal(CVE, "notice") in out
    serve(m, reader_clock, C0 + 30 * DAY)  # and no wait ever applies it
    _, out, _ = out_of(capsys, ["verify"])
    assert levels(capsys) == {CVE: "critical"} and refusal(CVE, "notice") in out_of(capsys, ["check"])[1]
    (d,) = json.loads(out_of(capsys, ["check", "--json"])[1])
    assert (d["level"], d["lowering_refused"], d["lowering_waits"]) == ("critical", "notice", None)


def test_the_source_withdraws_and_the_lowering_is_accepted(feed, monkeypatch, capsys, reader_clock):
    m = feed([], ALL)
    root = claimed_root(m, bot(id=G1, level="critical"), claim("ghsa", ghsa_fields(type="malware")))
    lower(m, root, "notice")
    serve(m, reader_clock, C0)
    use(monkeypatch, Net().set(gurl(G1), ghsa(type="malware", withdrawn_at="2026-11-01T00:00:00Z")))
    assert levels(capsys) == {G1: "critical"}
    status, out, _ = out_of(capsys, ["run"])
    assert "NOTICE: " in out.partition("After the source check:\n")[2]  # accepted in the run that reads the source
    assert levels(capsys) == {G1: "notice"}
    cli.main(["verify"])  # the alert as it stands is read: a withdrawn advisory at notice is confirmed
    _, out, _ = out_of(capsys, ["check"])
    assert "does not support" not in out and "is not applied" not in out and "not verified" not in out
    (d,) = json.loads(out_of(capsys, ["check", "--json"])[1])
    assert d["source_check"] == {"result": "confirmed", "why": "withdrawn", "source_level": "none"}


def test_the_catalog_no_longer_lists_it_and_the_lowering_is_accepted(feed, monkeypatch, capsys, reader_clock):
    m = feed([], ALL)
    root = claimed_root(m, bot(id=CVE, level="critical"), claim("kev", KEV_FIELDS))
    lower(m, root, "notice")
    serve(m, reader_clock, C0)
    use(monkeypatch, Net().set(verify.KEV_URL, kev()))
    cli.main(["pull"])
    cli.main(["verify"])
    assert levels(capsys) == {CVE: "notice"}
    assert "does not support" not in out_of(capsys, ["check"])[1]


def test_the_catalog_s_silence_does_not_lower_a_thread_whose_level_is_not_claimed(feed, monkeypatch, capsys, reader_clock):
    m = feed([bot(id=CVE, level="critical")], ALL)  # it may rest on a source the thread does not name
    lower(m, m.events["feed.json"][0], "notice")
    serve(m, reader_clock, C0)
    use(monkeypatch, Net().set(verify.KEV_URL, kev()))
    cli.main(["pull"])
    cli.main(["verify"])
    assert levels(capsys) == {CVE: "critical"}
    (d,) = json.loads(out_of(capsys, ["check", "--json"])[1])
    assert d["lowering_waits"] == "notice"


# ---------------------------------------------------------------- acceptance 3 and 4: the member cannot read

@pytest.mark.parametrize("extra", [ALL, 'verify = "off"\n'])
@pytest.mark.parametrize("dated", [AT, T0 + 150])  # T0 + 150: backdated to just after the root
def test_with_the_fetch_failing_the_critical_stays_and_the_lowering_waits_72_hours(feed, monkeypatch, capsys,
                                                                                    reader_clock, extra, dated):
    m = feed([bot(id=CVE, level="critical")], extra)
    low = lower(m, m.events["feed.json"][0], "notice", at=dated)
    serve(m, reader_clock, C0)
    n = use(monkeypatch, Net().set(verify.KEV_URL, OSError("down")))
    assert levels(capsys) == {CVE: "critical"}
    assert State.load().lowerings == {low["id"]: C0}  # the checkpoint's time, not the reply's and not this clock's
    _, out, _ = out_of(capsys, ["run"])
    assert cli.WAITING_LINE.format(id=CVE, level="notice") in out
    serve(m, reader_clock, C0 + WAIT - 1)
    cli.main(["verify"])
    assert levels(capsys) == {CVE: "critical"}
    serve(m, reader_clock, C0 + WAIT)
    assert levels(capsys) == {CVE: "notice"}
    assert "published and not verified" not in out_of(capsys, ["check"])[1]
    assert bool(n.calls) is (extra == ALL)


def test_a_frozen_mirror_never_lets_the_wait_run_out(feed, monkeypatch, capsys, reader_clock):
    m = feed([bot(id=CVE, level="critical")], ALL)
    lower(m, m.events["feed.json"][0], "notice")
    serve(m, reader_clock, C0)
    assert levels(capsys) == {CVE: "critical"}
    reader_clock.at = C0 + 30 * DAY  # this machine's clock moves; the mirror serves the same checkpoint
    cli.main(["pull"])
    assert {d["id"]: d["level"] for d in json.loads(out_of(capsys, ["check", "--json"])[1])} == {CVE: "critical"}


def test_a_raise_ends_the_wait_and_a_new_lowering_starts_its_own(feed, monkeypatch, capsys, reader_clock):
    m = feed([bot(id=CVE, level="critical")], 'verify = "off"\n')
    root = m.events["feed.json"][0]
    lower(m, root, "high")
    serve(m, reader_clock, C0)
    assert levels(capsys) == {CVE: "critical"}
    m.reply(m.bot_sec, root, m.patch_text(level="critical"), created_at=C0 + DAY)
    again = lower(m, root, "high", at=C0 + DAY + 10)
    serve(m, reader_clock, C0 + WAIT)
    assert levels(capsys) == {CVE: "critical"} and State.load().lowerings == {again["id"]: C0 + WAIT}
    serve(m, reader_clock, C0 + 2 * WAIT)
    assert levels(capsys) == {CVE: "high"}


def test_a_cli_whose_ruleset_is_out_of_date_applies_no_lowering_unchecked(feed, monkeypatch, capsys, reader_clock):
    from aitools_alerts import ruleset
    rs = ruleset.load()
    m = feed([bot(id=CVE, level="critical")], ALL, ruleset_pin=ruleset.Pin(rs.version, "0" * 64, 1))
    lower(m, m.events["feed.json"][0], "notice")
    serve(m, reader_clock, C0)
    assert levels(capsys) == {CVE: "critical"}
    serve(m, reader_clock, C0 + WAIT)
    assert levels(capsys) == {CVE: "critical"}


# ---------------------------------------------------------------- a refusal is remembered

def test_a_refusal_outlives_a_change_of_the_thread_and_the_supporting_alias_is_still_read(feed, monkeypatch, capsys,
                                                                                         reader_clock):
    """The CVE is not in the catalog; critical support comes through an alias a reply
    added. The lowering is refused past its 72 hours. Then a reply dated before that one
    puts three other aliases in front: a new state, never asked about, in which the
    supporting alias is the fourth of three that are read."""
    m = feed([bot(id=CVE, level="critical")], ALL)
    root = m.events["feed.json"][0]
    m.reply(m.bot_sec, root, m.patch_text(aliases=[G1]), created_at=AT)
    lower(m, root, "high", at=AT + 10)
    serve(m, reader_clock, C0)
    n = use(monkeypatch, Net().set(verify.KEV_URL, kev()).set(gurl(G1), ghsa(type="malware", cve=CVE)))
    cli.main(["pull"])
    assert refusal(CVE, "high") in out_of(capsys, ["verify"])[1]
    serve(m, reader_clock, C0 + WAIT + 100)
    assert levels(capsys) == {CVE: "critical"} and State.load().refused == {root["id"]}
    m.reply(m.bot_sec, root, m.patch_text(aliases=[G2, G3, G4]), created_at=AT - 50)
    serve(m, reader_clock, C0 + WAIT + 200)
    assert levels(capsys) == {CVE: "critical"}  # before any source is asked about the new state
    assert json.loads(out_of(capsys, ["run", "--json"])[1])["matches"][0]["level"] == "critical"  # the hook's command
    n.calls.clear()
    assert refusal(CVE, "high") in out_of(capsys, ["verify"])[1]
    assert gurl(G1) in n.urls
    serve(m, reader_clock, C0 + 3 * WAIT)
    assert levels(capsys) == {CVE: "critical"}


def test_a_refusal_is_the_thread_s_a_raise_and_a_new_lowering_reply_do_not_shed_it(feed, monkeypatch, capsys,
                                                                                   reader_clock):
    m = feed([bot(id=CVE, level="critical")], ALL)
    root = m.events["feed.json"][0]
    lower(m, root, "high")
    serve(m, reader_clock, C0)
    use(monkeypatch, Net().set(verify.KEV_URL, KEV_CC))
    cli.main(["pull"])
    assert refusal(CVE, "high") in out_of(capsys, ["verify"])[1]
    m.reply(m.bot_sec, root, m.patch_text(level="critical"), created_at=AT + 20)  # the offer is withdrawn,
    again = lower(m, root, "notice", at=AT + 30)  # and made again by another reply
    serve(m, reader_clock, C0 + 100)
    use(monkeypatch, Net().set(verify.KEV_URL, OSError("down")))  # and from now the source cannot be read
    assert levels(capsys) == {CVE: "critical"} and State.load().refused == {root["id"]}
    for at in (C0 + WAIT + 200, C0 + 5 * WAIT):
        serve(m, reader_clock, at)
        cli.main(["verify"])
        assert levels(capsys) == {CVE: "critical"} and State.load().lowerings == {again["id"]: at}


def test_a_refusal_ends_on_whole_reads_that_give_no_more_and_the_wait_starts_then(feed, monkeypatch, capsys,
                                                                                    reader_clock):
    m = feed([bot(id=G1, level="high")], ALL)  # unclaimed: fields that give notice cannot confirm a lowering to notice
    low = lower(m, m.events["feed.json"][0], "notice")
    serve(m, reader_clock, C0)
    use(monkeypatch, Net().set(gurl(G1), ghsa()))  # the source gives high
    cli.main(["pull"])
    assert refusal(G1, "notice", "high") in out_of(capsys, ["verify"])[1]
    serve(m, reader_clock, C0 + 2 * WAIT)
    root = m.events["feed.json"][0]
    assert levels(capsys) == {G1: "high"} and State.load().refused == {root["id"]}
    real = verify.time.time()
    clock_at(monkeypatch, real + verify.RETRY_S + 60)
    use(monkeypatch, Net().set(gurl(G1), OSError("down")))
    cli.main(["verify"])
    assert State.load().refused == {root["id"]}  # a failed read ends nothing
    clock_at(monkeypatch, real + 2 * verify.RETRY_S + 120)
    use(monkeypatch, Net().set(gurl(G1), ghsa(high=False)))  # now it gives notice
    cli.main(["verify"])
    st = State.load()
    assert st.refused == set() and st.lowerings == {low["id"]: C0 + 2 * WAIT}
    serve(m, reader_clock, C0 + 3 * WAIT - 1)
    assert levels(capsys) == {G1: "high"}
    serve(m, reader_clock, C0 + 3 * WAIT)
    assert levels(capsys) == {G1: "notice"}


# ---------------------------------------------------------------- acceptance 5: unverified interrupts

THREE = [G1, G2, G3]


def three(feed, extra=""):
    return feed([bot(id=i, level="critical") for i in THREE], extra)


def run_json(capsys):
    status, out, _ = out_of(capsys, ["run", "--json"])
    return status, json.loads(out)


def test_a_third_unverified_critical_from_one_key_is_listed_and_does_not_interrupt(feed, sent, monkeypatch, capsys):
    m = three(feed)
    status, out, _ = out_of(capsys, ["run"])  # every source read fails
    assert status == cli.EXIT_UNSEEN_CRITICAL and len(sent["texts"]) == 2
    assert all(t.endswith("\n" + cli.NOT_VERIFIED) for t in sent["texts"])
    st = State.load()
    assert len(st.seen) == 2 and {k: len(v) for k, v in st.interrupts.items()} == {m.bot: 2}
    status, out, _ = out_of(capsys, ["run"])
    assert status == 0 and len(sent["texts"]) == 2  # the third sets no exit 2 and sends nothing
    assert out.count("CRITICAL: ") == 4 and out.count("held, not notified") == 1  # listed, and said to be held
    assert "not verified from this machine: " + ", ".join(THREE) in out
    status, data = run_json(capsys)
    held = data["held_critical"]
    assert status == 0 and data["unseen_critical"] == [] and len(held) == 1 and held[0] not in st.seen
    assert len(data["matches"]) == 3
    assert out_of(capsys, ["notify"])[0] == 0 and len(sent["texts"]) == 2
    # its source confirms it: it interrupts in the run that reads the source, and says nothing of "not verified"
    waiting = next(e for e in m.events["feed.json"] if e["id"] == held[0])
    ident = next(i for i in THREE if i in waiting["content"])
    use(monkeypatch, Net().set(gurl(ident), ghsa(ident, type="malware")))
    status, out, _ = out_of(capsys, ["run"])
    assert status == cli.EXIT_UNSEEN_CRITICAL and len(sent["texts"]) == 3 and cli.NOT_VERIFIED not in sent["texts"][2]
    assert out_of(capsys, ["run"])[0] == 0 and len(State.load().seen) == 3


def test_the_hook_s_command_holds_the_third_and_reads_no_source(feed, sent, monkeypatch, capsys):
    three(feed)
    n = use(monkeypatch, Net())
    status, data = run_json(capsys)
    assert status == cli.EXIT_UNSEEN_CRITICAL and len(data["unseen_critical"]) == 2 and len(data["held_critical"]) == 1
    assert n.calls == [] and len(sent["texts"]) == 2


def test_a_day_later_the_held_alert_interrupts(feed, sent, monkeypatch, capsys):
    three(feed, 'verify = "off"\n')
    assert out_of(capsys, ["run"])[0] == cli.EXIT_UNSEEN_CRITICAL and len(sent["texts"]) == 2
    real = verify.time.time()
    clock_at(monkeypatch, real + cli.UNVERIFIED_WINDOW_S - 60)
    assert out_of(capsys, ["run"])[0] == 0
    clock_at(monkeypatch, real + cli.UNVERIFIED_WINDOW_S + 60)
    assert out_of(capsys, ["run"])[0] == cli.EXIT_UNSEEN_CRITICAL and len(sent["texts"]) == 3


@pytest.mark.parametrize("channels", ["failing", "none"])
def test_an_interrupt_no_channel_delivered_still_uses_its_slot(feed, sent, monkeypatch, capsys, channels):
    """`run` exits 2 and the hook interrupts whether or not a notification went out."""
    m = three(feed, "notify = []\n" if channels == "none" else "")
    sent["accept"] = False
    status, first = run_json(capsys)
    assert status == cli.EXIT_UNSEEN_CRITICAL and len(first["unseen_critical"]) == 2
    extra = m.root_post(m.bot_sec, bot(id=G4, level="critical"), created_at=T0 + 50)  # one more, sorted first
    m.write(Path(config.load().mirror_url[len("file://"):]))
    for _ in range(3):
        status, data = run_json(capsys)
        assert status == cli.EXIT_UNSEEN_CRITICAL and data["unseen_critical"] == first["unseen_critical"]
        assert len(data["held_critical"]) == 2 and extra["id"] in data["held_critical"]
    assert State.load().seen == set() and {k: len(v) for k, v in State.load().interrupts.items()} == {m.bot: 2}
    sent["accept"] = True  # a later run delivers the two, and they are seen
    if channels == "failing":
        assert run_json(capsys)[0] == cli.EXIT_UNSEEN_CRITICAL and len(State.load().seen) == 2


def test_a_copy_of_a_post_confirmed_earlier_is_not_confirmed_with_it(feed, sent, monkeypatch, capsys):
    """A result belongs to the published state, not to the post. After the source withdrew,
    new roots that copy the confirmed state must not each pass as checked."""
    m = feed([bot(id=G1, level="critical")])
    use(monkeypatch, Net().set(gurl(G1), ghsa(type="malware")))
    assert out_of(capsys, ["run"])[0] == cli.EXIT_UNSEEN_CRITICAL  # notified unverified, then read and confirmed
    for i in range(4):  # the same state, another title: another alert to the reader
        m.root_post(m.bot_sec, bot(id=G1, level="critical", title=f"Invented copy {i}"), created_at=T0 + 200 + i)
    m.write(Path(config.load().mirror_url[len("file://"):]))
    status, data = run_json(capsys)
    # one on the confirmed state's slot, one on the poster key's second slot; the rest are held
    assert len(data["unseen_critical"]) == 2 and len(data["held_critical"]) == 2
    real = verify.time.time()
    clock_at(monkeypatch, real + 3 * DAY)  # the confirmation is old now, and the source has withdrawn
    use(monkeypatch, Net().set(gurl(G1), ghsa(type="malware", withdrawn_at="2026-11-01T00:00:00Z")))
    status, data = run_json(capsys)
    assert len(data["unseen_critical"]) == 2 and len(data["held_critical"]) == 0  # two more, both unverified
    assert all(t.endswith(cli.NOT_VERIFIED) for t in sent["texts"][-2:])
    _, out, _ = out_of(capsys, ["run"])  # and the hourly run reads the source again
    # 0z4e: the source supported it earlier, so nothing is said until reads 48 hours apart find none
    assert "source check:" not in out
    clock_at(monkeypatch, real + 5 * DAY + 60)
    assert cli.LOST_LINE.format(id=G1, name="Claude Code") in out_of(capsys, ["run"])[1]


def test_a_curator_s_alerts_need_no_slot(feed, sent, monkeypatch, capsys):
    from mirror_helpers import advisory
    m = feed([])
    for i in range(4):
        m.root_post(m.cur_sec, advisory(id=f"AITA-TEST-000{i}"), created_at=T0 + 100 + i)
    m.write(Path(config.load().mirror_url[len("file://"):]))
    assert out_of(capsys, ["run"])[0] == cli.EXIT_UNSEEN_CRITICAL and len(sent["texts"]) == 4
    assert cli.NOT_VERIFIED not in "".join(sent["texts"]) and State.load().interrupts == {}


def test_a_slot_dated_after_this_clock_is_not_counted(feed, sent, monkeypatch, capsys):
    m = three(feed)
    cli.main(["pull"])
    st = State.load()
    st.interrupts = {m.bot: {"a" * 64: 2**40, "b" * 64: 2**40}}  # a clock that was far ahead once
    st.save_unverified()
    assert out_of(capsys, ["run"])[0] == cli.EXIT_UNSEEN_CRITICAL and len(sent["texts"]) == 2
    assert set(State.load().interrupts[m.bot].values()) != {2**40}  # and what is out of the window is dropped


# ---------------------------------------------------------------- the record mends itself

def test_a_damaged_record_stops_nothing_and_gives_no_unverified_slot_for_a_day(feed, sent, monkeypatch, capsys):
    three(feed)
    cli.main(["pull"])
    path = config.state_dir() / "unverified.json"
    path.write_text("{not json")
    status, out, err = out_of(capsys, ["run"])
    assert status == 0 and sent["texts"] == [] and out.count("held, not notified") == 3
    assert err.count("the record of unverified alerts was unreadable and has been started again") == 1
    rec = json.loads(path.read_text())
    assert rec["interrupts"] == {} and isinstance(rec["reset_at"], int)
    status, out, err = out_of(capsys, ["run"])
    assert status == 0 and "unreadable" not in err  # mended once
    use(monkeypatch, Net().set(gurl(G1), ghsa(type="malware")))  # a confirmed alert still interrupts
    assert out_of(capsys, ["run"])[0] == cli.EXIT_UNSEEN_CRITICAL and len(sent["texts"]) == 1
    clock_at(monkeypatch, verify.time.time() + cli.UNVERIFIED_WINDOW_S + 60)
    assert out_of(capsys, ["run", "--json"])[0] == cli.EXIT_UNSEEN_CRITICAL and len(sent["texts"]) == 3


def test_a_damaged_record_restarts_a_wait(feed, monkeypatch, capsys, reader_clock):
    m = feed([bot(id=CVE, level="critical")], 'verify = "off"\n')
    low = lower(m, m.events["feed.json"][0], "notice")
    serve(m, reader_clock, C0)
    assert levels(capsys) == {CVE: "critical"}
    (config.state_dir() / "unverified.json").write_text("[]")
    serve(m, reader_clock, C0 + WAIT)
    assert levels(capsys) == {CVE: "critical"} and State.load().lowerings == {low["id"]: C0 + WAIT}
    serve(m, reader_clock, C0 + 2 * WAIT)
    assert levels(capsys) == {CVE: "notice"}


# ---------------------------------------------------------------- what the plan's review asked for

def test_the_notify_command_is_capped_too(feed, sent, monkeypatch, capsys):
    three(feed, 'verify = "off"\n')
    cli.main(["pull"])
    assert out_of(capsys, ["notify"])[0] == 0 and len(sent["texts"]) == 2
    assert all(t.endswith("\n" + cli.NOT_VERIFIED) for t in sent["texts"])  # with the check off, too
    assert out_of(capsys, ["notify"])[0] == 0 and len(sent["texts"]) == 2 and len(State.load().seen) == 2


def test_an_alert_the_source_contradicts_is_unverified_and_says_so(feed, sent, monkeypatch, capsys):
    """A critical the source supports at high (above-source) keeps its level (0z4e decided so).
    One the source does not support at all shows at notice: tests/test_never_supported_cli.py."""
    feed([bot(id=G1, level="critical")])
    use(monkeypatch, Net().set(gurl(G1), ghsa()))
    cli.main(["pull"])
    cli.main(["verify"])  # read before it is notified: contradicted, the source supports high
    assert out_of(capsys, ["run"])[0] == cli.EXIT_UNSEEN_CRITICAL
    assert len(sent["texts"]) == 1 and sent["texts"][0].endswith("\n" + cli.NOT_VERIFIED)
    assert len(sent["texts"][0]) <= notify.MAX_TEXT + len(cli.NOT_VERIFIED) + 1


def test_a_slot_a_concurrent_run_took_is_not_reported_as_an_interrupt(feed, sent, monkeypatch, capsys):
    """The slots are granted against the record as it is under the lock, before the
    command reports: the alert that lost its slot is held, in the JSON and in the exit status."""
    m = three(feed, 'verify = "off"\n')
    cli.main(["pull"])
    stale = State.load()
    a = cli._parser().parse_args(["run", "--json"])
    a.root, a.ignored_env, a.settings = m.root, [], config.load()
    _, pairs = cli._matches(a, stale)
    pending, held, grants, loose = cli._interrupts(a, stale, a.settings, pairs)
    assert (len(pending), len(held), len(grants)) == (2, 1, 2)
    other = State.load()  # a concurrent run reports two other alerts of the same key first
    other.interrupts = {m.bot: {"a" * 64: int(verify.time.time()), "b" * 64: int(verify.time.time())}}
    other.save_unverified()
    pending, held = cli._reserve(stale, pending, held, grants)
    assert (pending, len(held)) == ([], 3) and set(State.load().interrupts[m.bot]) == {"a" * 64, "b" * 64}
    status, data = run_json(capsys)
    assert status == 0 and data["unseen_critical"] == [] and len(data["held_critical"]) == 3 and sent["texts"] == []


def test_a_matching_authority_beside_a_source_that_is_none_still_confirms(tmp_path):
    """``match`` rests on an authority that gives exactly the level. A record that is no
    authority (here the catalog not listing the CVE the advisory names) adds nothing and
    takes nothing away: no such source sets more than notice, so none can hold support
    above a lowered level."""
    from test_unchecked_lowering import lowering
    from test_verify import adv
    a = adv(level="critical")
    sources = Net().set(gurl(G1), ghsa(cve=CVE)).set(verify.KEV_URL, kev())  # the advisory gives high and names a CVE
    assert lowering(tmp_path, a, "high", sources) is True
    assert verify.load(tmp_path)["sources"][CVE]["lowers"] is False
    listed = Net().set(gurl(G1), ghsa(cve=CVE)).set(verify.KEV_URL, KEV_CC)  # were it listed, that would refuse
    assert lowering(tmp_path, a, "high", listed, now=verify.RETRY_S + 1_800_000_000) is False


def test_the_record_holds_as_many_entries_as_the_store_holds_events(tmp_path):
    from aitools_alerts import state
    assert state.MAX_UNVERIFIED_ENTRIES == pull.MAX_STORED_EVENTS
    st = State.load(tmp_path)
    st.refused = {f"{i:064x}" for i in range(6000)}
    st.lowerings = {f"{i:064x}": i for i in range(6000)}
    st.save_unverified()
    again = State.load(tmp_path)
    assert not again.unverified_damaged and len(again.refused) == 6000 and len(again.lowerings) == 6000


def test_an_alert_matched_through_two_installations_takes_one_slot(feed, sent, monkeypatch, capsys):
    from aitools_alerts import inventory
    from aitools_alerts.inventory import Installed, Inventory
    inv = Inventory(products={"claude-code": [Installed("Claude Code", "2.0.0", "/invented/bin/claude"),
                                              Installed("Claude Code", "2.1.0", "/invented/other/claude")]})
    monkeypatch.setattr(inventory, "collect", lambda *a, **k: inv)
    m = feed([bot(id=G1, level="critical"), bot(id=G2, level="critical")], 'verify = "off"\n')
    status, data = run_json(capsys)
    assert len(data["matches"]) == 4 and len(data["unseen_critical"]) == 2 and data["held_critical"] == []
    assert {k: len(v) for k, v in State.load().interrupts.items()} == {m.bot: 2}


# ---------------------------------------------------------------- what the code review found

def test_support_read_before_the_request_budget_ran_out_still_refuses(tmp_path, monkeypatch):
    """The catalog lists the CVE; the alias that follows is not read, the run's requests
    being used up. What was read supports more: that is a refusal, not an unread state."""
    from test_unchecked_lowering import lowering
    from test_verify import adv
    monkeypatch.setattr(verify, "MAX_FETCHES", 1)
    a = adv(id=CVE, aliases=[G1], level="critical")
    n = Net().set(verify.KEV_URL, KEV_CC).set(gurl(G1), ghsa(cve=CVE))
    assert lowering(tmp_path, a, "high", n) is False and n.urls == [verify.KEV_URL]
    ask = verify.at_level(a, "high")
    assert verify.result_for(ask, verify.load(tmp_path))["claude-code\nClaude Code"]["why"] == "below-source"


def test_a_command_that_started_earlier_does_not_write_over_a_newer_refusal(feed, monkeypatch, capsys, reader_clock):
    m = feed([bot(id=CVE, level="critical")], ALL)
    root = m.events["feed.json"][0]
    low = lower(m, root, "high")
    serve(m, reader_clock, C0)
    use(monkeypatch, Net().set(verify.KEV_URL, OSError("down")))
    assert levels(capsys) == {CVE: "critical"}
    serve(m, reader_clock, C0 + 100)
    cli.main(["pull"])
    a = cli._parser().parse_args(["check"])
    a.root, a.ignored_env, a.settings = m.root, [], config.load()
    early = State.load()  # a command that starts now: nothing read, nothing refused
    early.lowerings = {}  # and with a change to write (as on its first sight of the reply)
    a.raw = pull.advisories(early)
    now, listed = pull.head_clock(early)
    use(monkeypatch, Net().set(verify.KEV_URL, KEV_CC))
    cli.main(["verify"])  # meanwhile another command reads support for critical and saves the refusal
    assert State.load().refused == {root["id"]}
    since = cli._note_offers(a, early, now, listed, None)  # the early command, with its view of no result at all
    st = State.load()
    assert st.refused == {root["id"]} and st.lowerings == {low["id"]: C0 + 100} and since == {}


@pytest.mark.parametrize("channels", ["working", "none"])
def test_a_held_alert_gets_the_next_free_slot_before_an_earlier_dated_or_an_undelivered_one(feed, sent, monkeypatch,
                                                                                            capsys, channels):
    """Slots must not go round the same alerts, or to whatever is dated first, while one
    waits: the alert held longest takes the first slot that is free."""
    m = three(feed, 'verify = "off"\n' + ("notify = []\n" if channels == "none" else ""))
    _, first = run_json(capsys)
    (waiting,) = first["held_critical"]
    assert State.load().held.keys() == {waiting}
    real = verify.time.time()
    for day in (1, 2, 3):
        for i in range(2):  # two more a day, each dated before every root there is
            m.root_post(m.bot_sec, bot(id=G4, level="critical", title=f"Invented early {day} {i}"),
                        created_at=T0 + 10 * day + i)
        m.write(Path(config.load().mirror_url[len("file://"):]))
        clock_at(monkeypatch, real + day * (cli.UNVERIFIED_WINDOW_S + 60))
        _, data = run_json(capsys)
        if day == 1:
            assert waiting in data["unseen_critical"] and waiting not in State.load().held
        assert len(data["unseen_critical"]) == 2
    if channels == "working":
        assert waiting in State.load().seen


def test_copies_of_a_confirmed_advisory_with_other_aliases_share_its_one_slot(feed, sent, monkeypatch, capsys):
    m = feed([bot(id=G1, level="critical")])
    use(monkeypatch, Net().set(gurl(G1), ghsa(type="malware")))
    assert out_of(capsys, ["run"])[0] == cli.EXIT_UNSEEN_CRITICAL
    for i in range(5):  # the aliases of a GHSA thread are never read: each copy is another published state
        m.root_post(m.bot_sec, bot(id=G1, level="critical", aliases=[f"CVE-2025-100{i}"]), created_at=T0 + 200 + i)
    m.write(Path(config.load().mirror_url[len("file://"):]))
    cli.main(["pull"])
    cli.main(["verify"])  # every copy's state is read and confirmed
    _, data = run_json(capsys)
    assert len(data["unseen_critical"]) == 2 and len(data["held_critical"]) == 3
    assert sum(cli.NOT_VERIFIED in t for t in sent["texts"]) == 2  # the first sight, and one copy on the poster's last slot


def test_an_alert_matched_through_a_confirmed_and_an_unconfirmed_product_is_decided_once(feed, sent, monkeypatch, capsys):
    from aitools_alerts import inventory
    from aitools_alerts.inventory import Installed, Inventory
    inv = Inventory(products={"claude-code": [Installed("Claude Code", "2.0.0", "/invented/bin/claude")],
                              "codex": [Installed("Codex", "0.1.0", "/invented/bin/codex")]})
    monkeypatch.setattr(inventory, "collect", lambda *a, **k: inv)
    from aitools_alerts.schema import Action, Product
    from dataclasses import replace
    two = replace(bot(id=G1, level="critical"), products=[Product("Claude Code", "claude-code", "<99.0.0", "99.0.0"),
                                                          Product("Codex", "codex", "<99.0.0", "99.0.0")],
                  actions=[Action("upgrade", "Claude Code", "99.0.0"), Action("upgrade", "Codex", "99.0.0")])
    m = feed([two], ALL)
    use(monkeypatch, Net().set(gurl(G1), ghsa(type="malware")))  # the source names Claude Code only
    cli.main(["pull"])
    cli.main(["verify"])
    st = State.load()
    st.interrupts = {m.bot: {"a" * 64: int(verify.time.time()), "b" * 64: int(verify.time.time())}}  # no poster slot left
    st.save_unverified()
    _, data = run_json(capsys)
    assert len(data["matches"]) == 2 and len(data["unseen_critical"]) == 1 and data["held_critical"] == []
    assert len(sent["texts"]) == 1 and cli.NOT_VERIFIED not in sent["texts"][0]  # one alert, one notification


def test_no_waiting_line_where_no_wait_runs(feed, monkeypatch, capsys, reader_clock):
    m = feed([bot(id=CVE, level="critical")], ALL, min_cli="99.0.0")  # a CLI too old applies nothing unchecked
    lower(m, m.events["feed.json"][0], "notice")
    serve(m, reader_clock, C0)
    cli.main(["pull"])
    assert "published and not verified" not in out_of(capsys, ["check"])[1]
    assert json.loads(out_of(capsys, ["check", "--json"])[1])[0]["lowering_waits"] is None


# ---------------------------------------------------------------- what the delta review found

def test_an_hourly_run_with_failing_source_reads_keeps_the_held_queue(feed, sent, monkeypatch, capsys):
    three(feed)  # verify = "matched": the hourly run reads, every read fails, and its second pass runs
    assert out_of(capsys, ["run"])[0] == cli.EXIT_UNSEEN_CRITICAL
    (since,) = State.load().held.values()
    clock_at(monkeypatch, verify.time.time() + 3600)
    assert out_of(capsys, ["run"])[0] == 0
    assert list(State.load().held.values()) == [since]  # still held, and since the first hour


def test_reserving_keeps_a_held_alert_this_command_did_not_look_at(feed, sent, monkeypatch, capsys):
    m = three(feed, 'verify = "off"\n')
    run_json(capsys)
    (mine,) = State.load().held
    early = State.load()  # a command that started before another root arrived
    a = cli._parser().parse_args(["run", "--json"])
    a.root, a.ignored_env, a.settings = m.root, [], config.load()
    _, pairs = cli._matches(a, early)
    pending, held, grants, _ = cli._interrupts(a, early, a.settings, pairs)
    other = m.root_post(m.bot_sec, bot(id=G4, level="critical"), created_at=T0 + 500)
    m.write(Path(config.load().mirror_url[len("file://"):]))
    run_json(capsys)  # another command pulls it and holds it
    before = State.load().held
    assert before.keys() == {mine, other["id"]}
    cli._reserve(early, pending, held, grants)
    assert State.load().held == before
    st = State.load()  # an entry for an alert since seen, or no longer stored, is dropped
    st.held.update({"e" * 64: 1})
    st.seen.add(other["id"])
    st.save_unverified()
    st.save_seen()
    cli._reserve(State.load(), pending, held, grants)
    assert State.load().held.keys() == {mine}


def two_products(first_confirmed: bool):
    from dataclasses import replace
    from aitools_alerts.schema import Action, Product
    names = ["Claude Code", "Codex"] if first_confirmed else ["Codex", "Claude Code"]
    eco = {"Claude Code": "claude-code", "Codex": "codex"}
    return replace(bot(id=G1, level="critical"), products=[Product(n, eco[n], "<99.0.0", "99.0.0") for n in names],
                   actions=[Action("upgrade", n, "99.0.0") for n in names])


def both_installed(monkeypatch):
    from aitools_alerts import inventory
    from aitools_alerts.inventory import Installed, Inventory
    inv = Inventory(products={"claude-code": [Installed("Claude Code", "2.0.0", "/invented/bin/claude")],
                              "codex": [Installed("Codex", "0.1.0", "/invented/bin/codex")]})
    monkeypatch.setattr(inventory, "collect", lambda *a, **k: inv)


def test_the_notification_describes_the_product_the_source_confirmed(feed, sent, monkeypatch, capsys):
    both_installed(monkeypatch)
    m = feed([two_products(first_confirmed=False)], ALL)
    use(monkeypatch, Net().set(gurl(G1), ghsa(type="malware")))  # the source names Claude Code only
    cli.main(["pull"])
    cli.main(["verify"])
    st = State.load()
    st.interrupts = {m.bot: {"a" * 64: int(verify.time.time()), "b" * 64: int(verify.time.time())}}  # no poster slot left
    st.save_unverified()
    assert run_json(capsys)[0] == cli.EXIT_UNSEEN_CRITICAL
    (text,) = sent["texts"]
    assert "Affected: Claude Code" in text and cli.NOT_VERIFIED not in text


def test_a_second_confirmed_product_s_slot_is_tried_when_the_first_is_taken(feed, sent, monkeypatch, capsys):
    both_installed(monkeypatch)
    m = feed([two_products(first_confirmed=True)], ALL)
    both = ghsa(type="malware", pkgs=(("npm", "@anthropic-ai/claude-code"), ("npm", "@openai/codex")))
    use(monkeypatch, Net().set(gurl(G1), both))
    cli.main(["pull"])
    cli.main(["verify"])
    data = json.loads(out_of(capsys, ["check", "--json"])[1])
    assert [d["source_check"]["result"] for d in data] == ["confirmed", "confirmed"]
    root = m.events["feed.json"][0]
    a = cli._parser().parse_args(["run", "--json"])
    a.root, a.ignored_env, a.settings = m.root, [], config.load()
    st = State.load()
    threads, pairs = cli._matches(a, st)
    first = next(mm for t, mm in pairs if mm.product.name == "Claude Code")
    now = int(verify.time.time())
    st.interrupts = {m.bot: {"a" * 64: now, "b" * 64: now},  # no poster slot left,
                     cli._verified_bucket(pairs[0][0], first): {"c" * 64: now}}  # and Claude Code's slot is another root's
    st.save_unverified()
    status, out = run_json(capsys)
    assert status == cli.EXIT_UNSEEN_CRITICAL and out["unseen_critical"] == [root["id"]] and out["held_critical"] == []
    assert "Affected: Codex" in sent["texts"][0]


# ---------------------------------------------------------------- one product identity (ai-tools-alerts#2mgd)

def exact_pin():
    from aitools_alerts import ruleset
    rs = ruleset.load()
    return ruleset.Pin(rs.version, rs.digest, 1)


def later_pin():
    """A pin this ruleset is permitted under without being it: a later version, min_version met."""
    from aitools_alerts import ruleset
    return ruleset.Pin(ruleset.load().version + 1, "0" * 64, 1)


def with_skill(monkeypatch):
    """The tool, and an installed skill that carries the tool's name."""
    from aitools_alerts import inventory
    from aitools_alerts.inventory import Installed, Inventory
    inv = Inventory(products={"claude-code": [Installed("Claude Code", "2.0.0", "/invented/bin/claude")],
                              "skill": [Installed("Claude Code", "1.0.0", "/invented/skills/claude-code")]})
    monkeypatch.setattr(inventory, "collect", lambda *a, **k: inv)


def under(name, ecosystem, id=CVE, **kw):
    from aitools_alerts.schema import Action, Product
    from dataclasses import replace
    return replace(bot(id=id, level="critical", **kw), products=[Product(name, ecosystem, "<99.0.0", "99.0.0")],
                   actions=[Action("upgrade", name, "99.0.0")])


def test_a_respelled_critical_the_catalog_lists_for_another_vendor_is_contradicted_by_its_scope_name(feed, sent, monkeypatch,
                                                                                                    capsys):
    feed([under("claude code", "claude-code")], ALL)
    use(monkeypatch, Net().set(verify.KEV_URL, kev((CVE, "Cisco", "IOS XE"))))
    cli.main(["pull"])
    out = out_of(capsys, ["verify"])[1]
    assert "source check: 0 confirmed, 1 contradicted, 0 not verified" in out
    assert f"source check: the source does not support {CVE} for Claude Code" in out
    (d,) = json.loads(out_of(capsys, ["check", "--json"])[1])
    assert d["source_check"] == {"result": "contradicted", "why": "unsupported", "source_level": "none"}


def test_a_match_that_cannot_be_judged_does_not_interrupt_under_the_pinned_ruleset(feed, sent, monkeypatch, capsys):
    """``Claude Code`` under ``skill`` matches the installed skill and is no scope
    product. Decided from the post, with nothing read and nothing cached."""
    with_skill(monkeypatch)
    feed([under("Claude Code", "skill")], ALL, ruleset_pin=exact_pin())
    n = use(monkeypatch, Net())
    status, data = run_json(capsys)
    assert status == 0 and data["unseen_critical"] == [] and data["held_critical"] == [] and len(data["matches"]) == 1
    assert out_of(capsys, ["notify"])[0] == 0
    status, out, _ = out_of(capsys, ["run"])
    assert status == 0 and sent["texts"] == [] and State.load().interrupts == {} and State.load().seen == set()
    assert out.count("CRITICAL: ") >= 1 and cli.UNJUDGED_LINE.format(id=CVE) in out  # listed, and said why
    assert "held, not notified" not in out
    assert cli.UNJUDGED_LINE.format(id=CVE) in out_of(capsys, ["check"])[1]
    assert n.urls in ([], [verify.KEV_URL])


@pytest.mark.parametrize("extra, pin, min_cli", [
    (ALL, None, None), (ALL, "later", None), ('verify = "off"\n', "exact", None),
    (ALL, "digest", None),  # the pinned version with another digest: this CLI's scope file may be the wrong one
    (ALL, "exact", "999.0.0"),  # a CLI the trust root calls too old
])
def test_without_the_pinned_ruleset_or_with_the_check_off_it_interrupts_as_unverified(feed, sent, monkeypatch, capsys,
                                                                                    extra, pin, min_cli):
    from aitools_alerts import ruleset
    with_skill(monkeypatch)
    pins = {"later": later_pin, "exact": exact_pin, "digest": lambda: ruleset.Pin(ruleset.load().version, "0" * 64, 1)}
    m = feed([under("Claude Code", "skill")], extra, ruleset_pin=pins[pin]() if pin else None, min_cli=min_cli)
    use(monkeypatch, Net())
    status, out, _ = out_of(capsys, ["run"])
    assert status == cli.EXIT_UNSEEN_CRITICAL and len(sent["texts"]) == 1 and sent["texts"][0].endswith(cli.NOT_VERIFIED)
    assert {k: len(v) for k, v in State.load().interrupts.items()} == {m.bot: 1}
    assert "cannot judge" not in out


def test_with_no_scope_products_read_nothing_is_left_out(feed, sent, monkeypatch, capsys):
    """A scope table that could not be built makes every product look like none: then no match is silenced."""
    from aitools_alerts import check
    feed([bot(id=CVE, level="critical")], ALL, ruleset_pin=exact_pin())
    monkeypatch.setattr(check, "scope_products", lambda: {})
    use(monkeypatch, Net())
    assert out_of(capsys, ["run"])[0] == cli.EXIT_UNSEEN_CRITICAL and len(sent["texts"]) == 1


@pytest.mark.parametrize("ident", ["https://evil.example/GHSA-aaaa-bbbb-cccc", "CVE-2099-0001"])  # the second: a synthetic check
def test_an_id_that_names_no_source_does_not_interrupt_under_the_pinned_ruleset(feed, sent, monkeypatch, capsys, ident):
    feed([bot(id=ident, level="critical")], ALL, ruleset_pin=exact_pin())
    use(monkeypatch, Net())
    status, out, _ = out_of(capsys, ["run"])
    assert status == 0 and sent["texts"] == [] and State.load().interrupts == {}
    assert "cannot judge: no interrupt" in out


def test_an_added_entry_of_the_same_name_does_not_stop_the_tool_s_match(feed, sent, monkeypatch, capsys):
    """The tool's match is judged and confirmed; the skill's is left out; one alert, one
    notification, on the verified slot."""
    from aitools_alerts.schema import Product
    from dataclasses import replace
    with_skill(monkeypatch)
    a = bot(id=CVE, level="critical")
    m = feed([replace(a, products=[*a.products, Product("Claude Code", "skill", "<99.0.0", "99.0.0")])], ALL,
             ruleset_pin=exact_pin())
    use(monkeypatch, Net().set(verify.KEV_URL, KEV_CC))
    cli.main(["pull"])
    cli.main(["verify"])
    data = json.loads(out_of(capsys, ["check", "--json"])[1])
    assert sorted((d["product"]["ecosystem"], d["source_check"]["why"]) for d in data) == \
        [("claude-code", "match"), ("skill", "no-source")]
    status, data = run_json(capsys)
    assert status == cli.EXIT_UNSEEN_CRITICAL and len(data["unseen_critical"]) == 1
    assert len(sent["texts"]) == 1 and cli.NOT_VERIFIED not in sent["texts"][0]
    assert m.bot not in State.load().interrupts  # the verified slot, not one of the poster's two


def test_a_skill_of_the_tool_s_name_never_borrows_the_tool_s_confirmation(feed, sent, monkeypatch, capsys):
    """No pin: the unjudgeable match interrupts, but as unverified, whatever the tool's result is."""
    from aitools_alerts import inventory
    from aitools_alerts.inventory import Installed, Inventory
    from aitools_alerts.schema import Product
    from dataclasses import replace
    inv = Inventory(products={"skill": [Installed("Claude Code", "1.0.0", "/invented/skills/claude-code")]})
    monkeypatch.setattr(inventory, "collect", lambda *a, **k: inv)
    a = bot(id=CVE, level="critical")
    m = feed([replace(a, products=[*a.products, Product("Claude Code", "skill", "<99.0.0", "99.0.0")])], ALL)
    use(monkeypatch, Net().set(verify.KEV_URL, KEV_CC))
    cli.main(["pull"])
    cli.main(["verify"])
    status, data = run_json(capsys)
    assert status == cli.EXIT_UNSEEN_CRITICAL and sent["texts"][0].endswith(cli.NOT_VERIFIED)
    assert {k: len(v) for k, v in State.load().interrupts.items()} == {m.bot: 1}


def test_respellings_of_one_confirmed_advisory_share_its_one_slot(feed, sent, monkeypatch, capsys):
    m = feed([under(n, "claude-code") for n in ("Claude Code", "claude code", "claude-code", "CLAUDE CODE")], ALL)
    use(monkeypatch, Net().set(verify.KEV_URL, KEV_CC))
    cli.main(["pull"])
    cli.main(["verify"])  # every copy is confirmed
    data = json.loads(out_of(capsys, ["check", "--json"])[1])
    assert [d["source_check"]["result"] for d in data] == ["confirmed"] * 4
    _, data = run_json(capsys)
    assert len(data["unseen_critical"]) == 3 and len(data["held_critical"]) == 1
    buckets = State.load().interrupts
    assert sorted(len(v) for v in buckets.values()) == [1, 2] and len(buckets[m.bot]) == 2  # one verified slot, two of the poster's


def test_a_lowering_is_still_refused_after_an_entry_of_the_same_name_under_another_ecosystem(feed, monkeypatch, capsys,
                                                                                           reader_clock):
    """Through a signed thread: the signer adds ``Claude Code`` under ``skill``, puts
    ``claude code`` with no fixed version in the tool entry's place, and offers high.
    The catalog lists the CVE for Claude Code: the tool's first entry, with its fixed
    version, is still asked about, and the lowering is refused, not left to the 72 hours."""
    m = feed([bot(id=CVE, level="critical")], ALL)
    root = m.events["feed.json"][0]
    skill = {"name": "Claude Code", "ecosystem": "skill", "affected": None, "fixed": None}
    low = {"name": "claude code", "ecosystem": "claude-code", "affected": "<99.0.0", "fixed": None}
    m.reply(m.bot_sec, root, m.patch_text(products=[skill, low]), created_at=AT)
    lower(m, root, "high", at=AT + 10)
    serve(m, reader_clock, C0)
    use(monkeypatch, Net().set(verify.KEV_URL, KEV_CC))
    cli.main(["pull"])
    assert refusal(CVE, "high") in out_of(capsys, ["verify"])[1]
    serve(m, reader_clock, C0 + WAIT + 100)
    assert levels(capsys) == {CVE: "critical"} and State.load().refused == {root["id"]}


@pytest.mark.parametrize("first", ["my-git", "mcp-server-git"])
def test_a_name_that_cannot_be_judged_does_not_hide_the_match_that_can(feed, sent, monkeypatch, capsys, first):
    """An MCP server is matched by its package and by its configured key. An entry under
    the key, listed beside the scope product with the same range, must not leave the
    alert with only a match that cannot be judged: under the pinned ruleset it still interrupts."""
    from aitools_alerts import inventory
    from aitools_alerts.inventory import Installed, Inventory
    from aitools_alerts.schema import Action, Product
    from dataclasses import replace
    inv = Inventory(products={"mcp": [Installed("mcp-server-git", "0.6.2", "/invented/m", package="pypi:mcp-server-git",
                                                server="my-git")]})
    monkeypatch.setattr(inventory, "collect", lambda *a, **k: inv)
    names = [first] + [n for n in ("my-git", "mcp-server-git") if n != first]
    a = replace(bot(id=CVE, level="critical"), products=[Product(n, "mcp", "*", "99.0.0") for n in names],
                actions=[Action("upgrade", "mcp-server-git", "99.0.0")])
    m = feed([a], ALL, ruleset_pin=exact_pin())
    use(monkeypatch, Net())
    status, data = run_json(capsys)
    assert status == cli.EXIT_UNSEEN_CRITICAL and len(data["unseen_critical"]) == 1 and len(data["matches"]) == 2
    assert len(sent["texts"]) == 1 and {k: len(v) for k, v in State.load().interrupts.items()} == {m.bot: 1}
    assert "cannot judge" not in out_of(capsys, ["check"])[1]


def test_a_widening_reply_under_a_name_that_cannot_be_judged_does_not_silence_a_thread(feed, sent, monkeypatch, capsys,
                                                                                      reader_clock):
    """A signed widening patch puts the configured key in front of the scope product,
    both with a wider range. The thread still interrupts under the pinned ruleset."""
    from aitools_alerts import inventory
    from aitools_alerts.inventory import Installed, Inventory
    from aitools_alerts.schema import Action, Product
    from dataclasses import replace
    inv = Inventory(products={"mcp": [Installed("mcp-server-git", "0.6.2", "/invented/m", package="pypi:mcp-server-git",
                                                server="my-git")]})
    monkeypatch.setattr(inventory, "collect", lambda *a, **k: inv)
    a = replace(bot(id=CVE, level="critical"), products=[Product("mcp-server-git", "mcp", "<1.0.0", "1.0.0")],
                actions=[Action("upgrade", "mcp-server-git", "1.0.0")])
    m = feed([a], ALL, ruleset_pin=exact_pin())
    wide = [{"name": n, "ecosystem": "mcp", "affected": "*", "fixed": "2.0.0"} for n in ("my-git", "mcp-server-git")]
    m.reply(m.bot_sec, m.events["feed.json"][0], m.patch_text(products=wide), created_at=AT)
    serve(m, reader_clock, C0)
    use(monkeypatch, Net())
    status, data = run_json(capsys)
    assert status == cli.EXIT_UNSEEN_CRITICAL and len(data["unseen_critical"]) == 1
    assert "mcp-server-git" in [d["product"]["name"] for d in data["matches"]]
