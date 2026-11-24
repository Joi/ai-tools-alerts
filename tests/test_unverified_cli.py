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
    assert f"source check: the source does not support {G1} for Claude Code" in out


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
    feed([bot(id=CVE, level="critical")])
    use(monkeypatch, Net().set(verify.KEV_URL, kev((CVE, "Cisco", "IOS XE"))))
    cli.main(["pull"])
    cli.main(["verify"])  # read before it is notified: contradicted, the catalog lists it for another product
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
