"""No send waits for a person (ai-tools-alerts#jsje): an unknown send is settled from
the mirror, a refused one is dropped after three days, and a raise supersedes the
lower-priority work on its own thread. Through ``main.run``, as test_main and
test_recompute."""

import datetime as dt
import json

from dataclasses import asdict, replace

import pytest

from aitools_alerts import ruleset, schema
from aitools_alerts.poster import compose, inputs, main, recompute
from aitools_alerts.poster.ledger import Ledger

from mirror_helpers import advisory, iso
from test_main import (CHANNELS, GHSA2, T0, FakeRelay, at, env, finding, kev_fixed, kev_item)  # noqa: F401
from test_recompute import (CVE, GONE, _kev_with_its_fix, _thread, catalog, entry, hours, kc, levels,  # noqa: F401
                            one, post, replies)

HOUR, DAY = 3600, 86400
OLD = {**kev_item(CVE), "dateAdded": "2026-09-01"}  # before the watermark: no candidate, only the recompute


def served(env, generated):
    """The mirror's fetch, its channel files saying they were generated at ``generated``."""
    def fetch(url, timeout=None):
        body = env.mirror.fetch(url, timeout)
        if url.endswith(("feed.json", "critical.json")):
            body = json.dumps({**json.loads(body), "generated_at": iso(generated)}).encode()
        return body
    return fetch


def run(env, now, **kw):
    """One run that reads a mirror generated five minutes before it."""
    return env.run(now=now, mirror_fetch=served(env, now - 300), **kw)


def show(env, call, when=T0 + 5, sec=None, **kw):
    """Put a send the relay took (a FakeRelay call) on the mirror, under the bot's key."""
    ch, reply_to, text = call
    tags = [["e", reply_to, "", "reply"]] if reply_to else []
    return env.mirror.post(sec or env.mirror.bot_sec, text, created_at=when, tags=tags, files=(f"{ch}.json",), **kw)


def unknown_root(env):
    env.collector([finding()])
    code, summary, relay = env.run(relay=FakeRelay("unknown"))
    assert code == 1 and len(env.ledger()[1]) == 1
    return relay.calls[0]


# ---------------------------------------------------------------- 1. an unknown send, settled from the mirror


def test_an_unknown_root_the_mirror_shows_is_recorded_by_the_next_run(env):
    ev = show(env, unknown_root(env))
    code, summary, relay = env.run(now=T0 + HOUR)  # whatever the mirror says of its age: the event is the evidence
    (e,), pending = env.ledger()
    assert code == 0 and relay.calls == [] and pending == []  # recorded, never sent again
    assert e["root_event_id"] == ev["id"] and summary.endswith(" settled=delivered:1,resent:0,dropped:0,superseded:0")
    assert [reply for _, reply, _ in relay.ja] == [ev["id"]]  # its Japanese reply follows


def test_an_unknown_reply_is_settled_in_its_thread_and_its_sibling_follows(env):
    kev_fixed(env)
    env.run()
    env.collector([finding(fid="CVE-2026-0001", fixed="2.1.1", sources=(GHSA2,))])
    code, _, relay = env.run(now=T0 + HOUR, relay=FakeRelay("unknown"))
    assert code == 1 and [c[0] for c in relay.calls] == ["critical"]
    ev = show(env, relay.calls[0], when=T0 + HOUR + 5)
    code, _, relay = env.run(now=T0 + 2 * HOUR)
    (e,), pending = env.ledger()
    assert code == 0 and [c[0] for c in relay.calls] == ["feed"] and pending == []
    assert e["replies"][0] == {"critical": ev["id"]} and len(e["replies"]) == 2


def test_an_unknown_digest_is_settled_and_the_next_day_has_its_own(env):
    env.collector([finding()])
    env.run()
    code, _, relay = env.run(now=at(9, 9), relay=FakeRelay("unknown"))
    ev = show(env, relay.calls[0], when=at(9, 9) + 5)
    code, _, relay = env.run(now=at(9, 10))
    assert code == 0 and relay.calls == [] and env.state()["digest_ids"] == [ev["id"]]
    assert len(env.run(now=at(10, 9))[2].calls) == 1  # no longer held behind it


@pytest.mark.parametrize("other", ["text", "channel", "thread", "key", "early", "recorded"])
def test_an_event_that_is_not_the_send_settles_nothing(env, other):
    ch, _, text = unknown_root(env)
    if other == "text":
        show(env, (ch, None, text + " "))
    elif other == "channel":
        show(env, ("critical", None, text))
    elif other == "thread":
        show(env, (ch, "ab" * 32, text))
    elif other == "key":
        show(env, (ch, None, text), sec=env.mirror.cur_sec)
    elif other == "early":
        show(env, (ch, None, text), when=T0 - main.SETTLE_SKEW - 1)
    else:  # the event is another post's already: a digest's id
        ev = show(env, (ch, None, text))
        st = env.state()
        env.config.state.write_text(json.dumps({**st, "digest_ids": [ev["id"]]}))
    code, summary, relay = run(env, T0 + HOUR)
    assert relay.calls == [] and len(env.ledger()[1]) == 1 and "settled=" not in summary


def test_a_send_a_fresh_mirror_never_shows_is_sent_again_after_24_hours(env):
    unknown_root(env)
    code, summary, relay = run(env, T0 + 23 * HOUR)
    assert relay.calls == [] and len(env.ledger()[1]) == 1  # a slow send can still land
    code, summary, relay = run(env, T0 + 24 * HOUR)
    (e,), pending = env.ledger()
    assert code == 0 and [c[0] for c in relay.calls] == ["feed"] and pending == []
    assert "settled=delivered:0,resent:1," in summary
    with Ledger(env.config.ledger) as led:
        assert led._state()["expired"][0]["reason"] == "not on the mirror 24 hours after the attempt"


def test_an_old_or_unreadable_mirror_proves_no_absence_until_72_hours(env):
    unknown_root(env)

    def down(url, timeout=None):
        raise OSError("mirror down")
    for hour, fetch in ((24, served(env, T0 + 22 * HOUR)), (25, served(env, T0 + 26 * HOUR)), (48, down), (71, down)):
        code, _, relay = env.run(now=T0 + hour * HOUR, mirror_fetch=fetch)  # generated 2 h before; an hour ahead
        assert relay.calls == [] and len(env.ledger()[1]) == 1, hour
    code, summary, relay = env.run(now=T0 + 72 * HOUR, mirror_fetch=down)
    assert [c[0] for c in relay.calls] == ["feed"] and env.ledger()[1] == [] and "resent:1" in summary


def test_a_pending_mark_with_no_journal_item_is_expired_and_a_withheld_items_is_cleared(env):
    env.collector([finding()])
    env.run(relay=FakeRelay("refuse"))
    (w,) = env.state()["withheld"]
    with Ledger(env.config.ledger) as led:
        led.pending(w["key"], [], now=T0)  # a run that stopped between withholding and clearing
        led.pending("root:Cursor:CVE-2026-9999:feed", ["CVE-2026-9999"], now=T0)
    env.run(now=T0 + HOUR)
    assert [p["key"] for p in env.ledger()[1]] == ["root:Cursor:CVE-2026-9999:feed"]
    assert len(env.state()["withheld"]) == 1
    env.run(now=T0 + 24 * HOUR)
    assert env.ledger()[1] == []


def test_a_delivery_that_shows_after_the_send_was_repeated_is_still_the_items(env):
    """Not on the mirror at 24 hours, so sent again, and that outcome is unknown too. The
    first attempt's event then shows: it is dated before the second attempt and is still
    this item's delivery, so no third copy goes out."""
    first = unknown_root(env)
    code, _, relay = run(env, T0 + 24 * HOUR, relay=FakeRelay("unknown"))
    assert code == 1 and len(relay.calls) == 1 and env.state()["outbox"][0]["tried"] == T0
    ev = show(env, first)
    code, summary, relay = run(env, T0 + 25 * HOUR)
    assert code == 0 and relay.calls == [] and env.ledger()[0][0]["root_event_id"] == ev["id"]


def test_a_delivery_that_shows_after_a_repeat_that_failed_is_recorded_not_sent_a_third_time(env):
    first = unknown_root(env)
    code, _, relay = run(env, T0 + 24 * HOUR, relay=FakeRelay("fail"))
    assert code == 1 and env.ledger()[1] == []  # certainly not stored: nothing is pending
    ev = show(env, first)
    code, summary, relay = run(env, T0 + 25 * HOUR)
    assert relay.calls == [] and env.ledger()[0][0]["root_event_id"] == ev["id"] and "delivered:1" in summary


def test_an_unknown_lowering_that_expired_is_sent_again_not_dropped(env):
    """The first channel's lowering may have posted. When its attempt expires, both
    lowerings stay in the journal and go out, whatever KEV says now: dropped, a channel
    that did get it would stand lower than the ledger for good. KEV lists the entry
    again, so the raise follows in the same run, in both channels."""
    post(env)
    hours(env, 1, 24)
    one(env, 25, relay=FakeRelay("unknown"), code=1)
    env.kev = main_kev(49, OLD)
    code, summary, relay = run(env, T0 + 49 * HOUR)
    assert code == 0 and "resent:1" in summary
    assert levels(relay) == levels(relay, "critical") == [{"level": "notice"}, {"level": "critical"}]
    assert entry(env)["level"] == "critical" and env.state()["outbox"] == []


# ---------------------------------------------------------------- 2. a refused item, dropped after three days


def test_a_refused_root_is_dropped_after_three_days_planned_anew_and_counted_once(env):
    env.collector([finding()])
    env.run(relay=FakeRelay("refuse"))
    code, summary, relay = env.run(now=T0 + 3 * DAY - HOUR)
    assert relay.calls == [] and len(env.state()["withheld"]) == 1 and "busy=1" in summary
    code, summary, relay = env.run(now=T0 + 3 * DAY)
    assert code == 0 and [c[0] for c in relay.calls] == ["feed"] and len(env.ledger()[0]) == 1
    assert env.state()["withheld"] == [] and env.state()["dropped"] == 1 and "dropped:1" in summary
    digest = env.run(now=at(8, 9))[2].calls[0][2]
    assert "1 new alert." in digest and "1 item withheld by the publication check." in digest
    assert env.state()["dropped"] == 0
    assert "withheld" not in env.run(now=at(9, 9))[2].calls[0][2]


@pytest.mark.parametrize("again", ["ok", "refuse"])
def test_a_refused_reply_another_channel_has_is_sent_once_more_then_given_up(env, again):
    """The feed has the fix; the critical channel's copy was refused. Dropped, nothing
    would plan it again (the ledger holds the fix). So after three days it is sent once
    more as it is; refused again, it is dropped and the digest counts it."""
    kev_fixed(env)
    env.run()
    env.collector([finding(fid="CVE-2026-0001", fixed="2.1.1", sources=(GHSA2,))])
    env.run(now=T0 + HOUR, relay=FakeRelay("refuse"))
    (w,) = env.state()["withheld"]
    code, summary, relay = env.run(now=T0 + HOUR + 3 * DAY, relay=FakeRelay(again))
    assert [(c[0], c[2]) for c in relay.calls] == [("critical", w["items"][0]["text"])]
    st = env.state()
    assert st["withheld"] == [] and st["outbox"] == [] and st["dropped"] == (again == "refuse")
    assert len(entry(env)["replies"]) == (2 if again == "ok" else 1)
    assert ("dropped:1" in summary) == (again == "refuse")


# ---------------------------------------------------------------- 3. a raise and the work in its way


def test_a_refused_lowering_is_superseded_by_the_next_raise(env):
    """The critical channel has the lowering and the feed's was refused. KEV lists the
    entry again: the raise goes to both channels in the next run, and the refused
    lowering leaves the withheld list unsent."""
    post(env)
    hours(env, 1, 24)
    relay = one(env, 25, relay=FakeRelay("ok", "refuse"))
    assert entry(env)["level"] == "notice" and len(env.state()["withheld"]) == 1
    env.kev = main_kev(26, OLD)
    code, summary, relay = env.run(now=T0 + 26 * HOUR)
    assert code == 0 and levels(relay) == levels(relay, "critical") == [{"level": "critical"}]
    assert env.state()["withheld"] == [] and env.state()["dropped"] == 0 and "superseded:1" in summary
    assert entry(env)["level"] == "critical"


def main_kev(hour, *listed):
    from test_main import FakeKEV
    return FakeKEV(catalog=catalog(f"v{hour // 6 + 1}", *listed))


def test_a_candidate_raise_goes_out_and_the_unsent_lowering_does_not(env):
    post(env)
    hours(env, 1, 24)
    one(env, 25, relay=FakeRelay("ok", "fail"), code=1)  # the feed's lowering stays in the journal
    assert entry(env)["level"] == "notice" and len(env.state()["outbox"]) == 1
    env.collector([finding(fid=CVE, sources=(GHSA_OF_CVE,), fixed="2.1.1")], name="2026-11-07T000000Z")
    relay = one(env, 26)
    assert levels(relay) == levels(relay, "critical") == [{"level": "high"}]  # never the notice
    assert entry(env)["level"] == "high" and env.state()["outbox"] == []


GHSA_OF_CVE = "https://github.com/anthropics/claude-code/security/advisories/GHSA-abcd-efgh-ijkl"


def test_a_raise_waits_while_a_send_of_its_thread_is_unknown(env):
    post(env)
    hours(env, 1, 24)
    one(env, 25, relay=FakeRelay("ok", "unknown"), code=1)
    relay = one(env, 26, (OLD,))  # listed again, and the mirror (never fresh here) does not show the send
    assert replies(relay) == [] and len(env.ledger()[1]) == 1 and len(env.state()["outbox"]) == 1
    assert entry(env)["level"] == "notice"


def test_a_raise_does_not_supersede_a_reply_with_a_fix_or_a_root(env):
    env.collector([finding(aliases=("CVE-2026-0001",))])
    env.run()
    env.collector([finding(aliases=("CVE-2026-0001",), fixed="2.1.1")])
    code, summary, relay = env.run(now=T0 + HOUR, relay=FakeRelay("refuse"))
    assert "withheld=1" in summary and "2.1.1" in env.state()["withheld"][0]["items"][0]["text"]
    env.kev.catalog = {"vulnerabilities": [kev_item()]}  # KEV lists it: a raise to critical
    code, summary, relay = env.run(now=T0 + 2 * HOUR)
    assert relay.calls == [] and len(env.state()["withheld"]) == 1 and "superseded" not in summary
    code, summary, relay = env.run(now=T0 + HOUR + 3 * DAY, relay=FakeRelay("refuse"))  # the bound
    assert [c[0] for c in relay.calls] == ["feed", "critical", "feed"] and "dropped:1" in summary
    assert "2.1.1" in relay.calls[0][2]  # sent once more, refused again, dropped; then the raise
    assert entry(env)["level"] == "critical" and env.state()["dropped"] == 1
    assert env.state()["withheld"] == [] and env.state()["outbox"] == []


def test_a_raise_does_not_supersede_a_fix_reply_another_channel_has(env):
    """A lowered thread; a fix reply the critical channel took and the feed refused. Its
    advisory is the ledger's already, and it is still not a level reply: the raise waits
    for it rather than leave the feed without the fix."""
    post(env)
    hours(env, 1, 25)
    assert entry(env)["level"] == "notice"
    env.collector([finding(fid=CVE, sources=(GHSA_OF_CVE,), fixed="2.1.5", severity=None)], name="2026-11-07T000000Z")
    relay = one(env, 26, relay=FakeRelay("ok", "refuse"))
    (w,) = env.state()["withheld"]
    assert json.loads(schema._last_block(w["items"][0]["text"]))["products"][0]["fixed"] == "2.1.5"
    assert entry(env)["advisory"]["products"][0]["fixed"] == "2.1.5"  # recorded from the critical channel
    env.kev = main_kev(27, OLD)
    code, summary, relay = env.run(now=T0 + 27 * HOUR)
    assert replies(relay) == [] and len(env.state()["withheld"]) == 1 and "superseded" not in summary


def test_a_source_only_reply_is_superseded_only_when_no_channel_can_have_it(env):
    env.collector([finding()])
    env.run()
    (e,) = env.ledger()[0]
    more = {**e["advisory"], "sources": e["advisory"]["sources"] + [{"url": GHSA2, "published_at": None}]}
    text = f"New source.\n\n```{schema.INFO_STRING}\n{json.dumps({'sources': more['sources']})}\n```\n"
    item = {"key": "reply:Claude Code:GHSA-abcd-efgh-ijkl:feed", "kind": "reply", "scope": "Claude Code",
            "ids": e["aliases"], "channel": "feed", "text": text, "adv": more, "exploited": True, "date": None,
            "sent": None, "root": e["root_event_id"]}

    def yields(it, level="critical"):
        """(may the raise be planned, is the item noted for replacement); nothing is removed."""
        st = {**env.state(), "outbox": [it]}
        with Ledger(env.config.ledger) as led:
            r = main.Run(T0, env.config, led, st, CHANNELS, None, None)
            ok = r.yields(led.thread(e["root_event_id"]), level)
            assert st["outbox"] == [it] and r.busy(e["aliases"], "Claude Code") is True
            assert r.busy(e["aliases"], "Claude Code", passing=True) is not ok
            return ok, r._passing(it)

    assert yields(item) == (True, True)
    assert yields({**item, "tried": T0}) == (False, False)  # a channel may have it
    assert yields({**item, "retried": True}) == (False, False)  # refused once, owed one more send
    old = text.replace(json.dumps({"sources": more["sources"]}), json.dumps({"sources": e["advisory"]["sources"]}))
    assert yields({**item, "text": old})[0] is False  # the thread records every source it lists: a channel has it
    fix = text.replace('{"sources"', '{"products": [], "sources"')
    assert yields({**item, "text": fix})[0] is False  # more than ids and sources
    assert yields({**item, "kind": "copy"})[0] is False and yields({**item, "sent": "ab" * 32})[0] is False
    level = {**item, "text": text.replace(json.dumps({"sources": more["sources"]}), '{"level": "notice"}')}
    assert yields(level, "high")[0] is True and yields({**level, "tried": T0}, "high")[0] is True
    assert yields(level, "notice")[0] is False  # not below the raise


def test_a_refused_root_is_not_superseded(env):
    env.collector([finding(aliases=("CVE-2026-0001",))])
    env.run(relay=FakeRelay("refuse"))
    env.kev.catalog = {"vulnerabilities": [kev_item()]}
    code, summary, relay = env.run(now=T0 + HOUR)
    assert relay.calls == [] and len(env.state()["withheld"]) == 1 and "settled=" not in summary


# ---------------------------------------------------------------- the pieces


def test_raised_agrees_with_judge_and_keeps_no_wait():
    rs, st, scope = ruleset.load(), recompute.new_state(), next(e for e in schema.load_scope() if e.name == "Claude Code")
    low = _thread(level="high", floor="high", root_fixed="2.1.0")  # a root with its fix can go to critical (9kgk)
    low.advisory["products"][0]["fixed"] = "2.1.0"
    low.advisory["actions"] = [{"verb": "upgrade", "target": "Claude Code", "value": "2.1.0"}]
    listed, gone = kc(catalog("v1", CVE), "ok", st, 0), kc(catalog("v2"), "ok", st, 1)
    before = json.dumps(st, sort_keys=True)
    assert recompute.raised(low, scope, listed, rs) == "critical"
    assert recompute.judge(low, scope, listed, rs, {**st, "dwell": {}}, 2) == ("raise", "critical")
    assert recompute.raised(low, scope, gone, rs) is None and recompute.raised(low, scope, None, rs) is None
    assert recompute.raised(replace(low, level="critical"), scope, listed, rs) is None  # already there
    assert json.dumps(st, sort_keys=True) == before


def test_the_digest_counts_dropped_items_on_a_quiet_day_too():
    day = dt.date(2026, 11, 8)
    adv = advisory()
    for lang in ("en", "ja"):
        line = compose._DIGEST[lang]["withheld"](2)
        assert compose.digest([adv], day, lang, dropped=2).endswith("\n\n" + line)
        assert compose.digest([], day, lang, dropped=2).endswith("\n\n" + line)
        assert compose.digest([], day, lang, dropped=2, summary="S").endswith("\n\n" + line + "\n\nS")
        assert compose.digest([adv], day, lang, dropped=0) == compose.digest([adv], day, lang)
        assert "\n" not in compose.digest([], day, lang)


def test_a_state_written_before_starts_with_nothing_dropped(tmp_path):
    st = inputs.new_state(T0, 3)
    del st["dropped"]
    (tmp_path / "state.json").write_text(json.dumps(st))
    assert inputs.load_state(tmp_path / "state.json", T0, 3)["dropped"] == 0
    (tmp_path / "state.json").write_text(json.dumps({**st, "dropped": -1}))
    with pytest.raises(inputs.LedgerError):
        inputs.load_state(tmp_path / "state.json", T0, 3)


OLD_STATE_KEYS = {"schema_version", "since", "heartbeat", "collector", "kev_since", "digest_date", "digest_at",
                  "digest_roots", "digest_ids", "held", "digested", "outbox", "deferred", "withheld", "waiting",
                  "gate", "weekly"}  # the state of the version before
OLD_ITEM_KEYS = {"key", "kind", "scope", "ids", "channel", "text", "adv", "exploited", "date", "sent", "root",
                 "ja", "source_title", "floor"}
OLD_DIGEST_KEYS = {"held", "cutoff", "roots", "week"}


def test_the_rollback_line_names_every_key_the_version_before_refuses(env):
    """A dropped root, then a digest whose send is unknown, expired and repeated with an
    unknown outcome again: the state holds ``dropped``, a digest snapshot's ``dropped``
    and an item's ``tried``, and nothing else that is new."""
    env.collector([finding()])
    env.run(relay=FakeRelay("refuse"))
    env.run(now=T0 + 3 * DAY, relay=FakeRelay("fail"))  # dropped, planned anew, and that send fails
    env.run(now=at(8, 9), relay=FakeRelay("ok", "unknown"))  # the root posts; the digest's outcome is unknown
    run(env, at(9, 9), relay=FakeRelay("unknown"))
    st = env.state()
    (digest,) = [it for it in st["outbox"] if it["kind"] == "digest"]
    assert set(st) - OLD_STATE_KEYS == {"dropped"} and st["dropped"] == 1
    assert set(digest) - OLD_ITEM_KEYS == {"tried"} and set(digest["adv"]) - OLD_DIGEST_KEYS == {"dropped"}
    line = next(ln for ln in (inputs.Path(__file__).parents[2] / "CHANGELOG.md").read_text().splitlines()
                if "ai-tools-alerts#jsje" not in ln and "del(.dropped)" in ln)
    assert "del(.tried, .retried)" in line and "del(.adv.dropped)" in line and "mv state.json.new state.json" in line


# ---------------------------------------------------------------- found by the whole-branch review


def test_superseded_work_stays_journaled_until_the_raise_is(env, monkeypatch):
    """The feed's lowering is unsent and KEV lists the entry again, but the run stops
    before the raise is journaled. Nothing was removed: the next run, whose catalog no
    longer lists it, sends the lowering the feed still lacks."""
    post(env)
    hours(env, 1, 24)
    one(env, 25, relay=FakeRelay("ok", "fail"), code=1)
    before = env.state()["outbox"]
    monkeypatch.setattr(main.Run, "recompute", lambda self: (_ for _ in ()).throw(main.LedgerError("stopped")))
    env.kev = main_kev(26, OLD)
    code, summary, relay = env.run(now=T0 + 26 * HOUR)
    assert code == 1 and replies(relay) == [] and env.state()["outbox"] == before
    monkeypatch.undo()
    relay = one(env, 27)
    assert levels(relay) == [{"level": "notice"}] and levels(relay, "critical") == []


def test_a_refused_reply_is_sent_once_more_whatever_the_thread_recorded_since(env):
    """On a lowered thread a raise and a fix are separate replies. The feed refuses the
    raise and takes the fix; the critical channel takes both. The ledger then holds the
    level and a newer fix than the refused reply's snapshot. It is still retried."""
    post(env)
    hours(env, 1, 25)
    env.collector([finding(fid=CVE, sources=(GHSA_OF_CVE,), fixed="2.1.5")], name="2026-11-07T000000Z")
    relay = one(env, 26, relay=FakeRelay("ok", "refuse"))
    (w,) = env.state()["withheld"]
    assert "#level:feed" in w["key"] and entry(env)["level"] == "high"
    assert entry(env)["advisory"]["products"][0]["fixed"] == "2.1.5"
    code, summary, relay = env.run(now=T0 + 26 * HOUR + 3 * DAY)
    assert levels(relay) == [{"level": "high"}] and env.state()["withheld"] == [] and "dropped" not in summary


def test_the_retry_mark_is_the_items_and_outlives_a_failed_send(env):
    kev_fixed(env)
    env.run()
    env.collector([finding(fid="CVE-2026-0001", fixed="2.1.1", sources=(GHSA2,))])
    env.run(now=T0 + HOUR, relay=FakeRelay("refuse"))
    t = T0 + HOUR + 3 * DAY
    code, _, relay = env.run(now=t, relay=FakeRelay("fail"))
    (it,) = env.state()["outbox"]
    assert code == 1 and it["retried"] is True  # on disk: the next run is another process
    env.collector([finding(fid="CVE-2026-0001", fixed="2.1.2", sources=(GHSA2,))], name="2026-11-09T000000Z")
    code, summary, relay = env.run(now=t + HOUR, relay=FakeRelay("ok", "ok", "refuse"))
    # the retried reply lands; the newer fix under the same key is refused in the second channel: withheld, not dropped
    assert env.state()["dropped"] == 0 and len(env.state()["withheld"]) == 1
    assert "retried" not in env.state()["withheld"][0]["items"][0]
    code, summary, relay = env.run(now=t + 2 * HOUR)
    assert env.state()["dropped"] == 0


def test_a_refused_repeat_is_still_settled_by_the_first_attempts_event(env):
    first = unknown_root(env)
    code, _, relay = run(env, T0 + 24 * HOUR, relay=FakeRelay("refuse"))
    (w,) = env.state()["withheld"]
    assert w["items"][0]["tried"] == T0 and env.ledger()[1] == []
    ev = show(env, first)
    code, summary, relay = run(env, T0 + 25 * HOUR)
    assert relay.calls == [] and env.ledger()[0][0]["root_event_id"] == ev["id"]
    assert env.state()["withheld"] == [] and "delivered:1" in summary


def test_a_pull_that_times_out_keeps_what_an_earlier_pull_stored(env, monkeypatch):
    ev = show(env, unknown_root(env))
    from aitools_alerts import pull
    from aitools_alerts.state import State
    st = State.load(env.config.mirror_dir)
    assert pull.fetch(env.config.translate_mirror_url, st, fetch=env.mirror.fetch, root_pubkey=env.mirror.root,
                      now=T0 + 60, checkpoint=False).error is None  # an earlier pull stored the event
    real = main.translate.bounded

    def slow(fn, seconds):
        raise main.translate.CallError("timed out")
    monkeypatch.setattr(main.translate, "bounded", slow)
    code, summary, relay = env.run(now=T0 + 72 * HOUR)
    monkeypatch.setattr(main.translate, "bounded", real)
    assert relay.calls == [] and env.ledger()[0][0]["root_event_id"] == ev["id"] and "delivered:1" in summary
