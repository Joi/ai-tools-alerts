"""A channel that lacks its thread's standing level reply is sent it again
(ai-tools-alerts#aqtf). The journal gives up a reply a channel refused twice (jsje); the
ledger names the channel (``Entry.lacks``) and ``Run.reconcile`` composes the reply anew.
Unit tests of the ledger, then ``main.run`` one run an hour with the fake relay."""

import json
from dataclasses import replace

import pytest

from aitools_alerts import ruleset, schema, wire
from aitools_alerts.poster import compose, inputs, main, recompute, signer
from aitools_alerts.poster.ledger import Entry, Ledger, LedgerError

from advisories import ghsa_json
from test_advisory_recompute import CLAUDE, G, HOUR, NO_FIX, RS, entries, hourly, post, reads, run, thread
from test_main import T0, FakeRelay, env, finding, kev_item  # noqa: F401  (env is a fixture)
from test_renew import renewals
from test_withdrawn_state import DUE, OFF, claims, moves

DAY = 24
MALWARE = dict(type="malware", packages=NO_FIX)
A, B, R1, R2 = "a" * 64, "b" * 64, "c" * 64, "d" * 64
TWO = {"feed": A, "critical": B}


def sends(relay):
    """(channel, word) of each level-only reply a run sent, in order."""
    out = []
    for c in relay.calls:
        block = schema._last_block(c[2]) if c[1] is not None else None
        patch = json.loads(block) if isinstance(block, str) else None
        if isinstance(patch, dict) and set(patch) == {"level"}:
            out.append((c[0], patch["level"]))
    return out


def edit(env, change, k=0):
    with Ledger(env.config.ledger) as led:
        change(led._state()["entries"][k])
        led._save()


def at(e, level):
    e.update(level=level, floor="notice")
    e["advisory"]["level"] = level


# ---------------------------------------------------------------- the ledger


def two(**more):
    return replace(thread(level="high", **more), channel_ids=dict(TWO))


@pytest.mark.parametrize("more, gone, standing, lacking", [
    ({}, False, "high", {}),
    (dict(withdrawn=["critical", "feed"]), True, "withdrawn", {}),
    (dict(withdrawn=["critical"]), False, "high", {"critical": "withdrawn"}),  # written by kk2q: it shows the alert
    (dict(withdrawn=["critical"], lacks={"critical": "withdrawn"}), False, "high", {"critical": "withdrawn"}),
    (dict(withdrawn=["feed"], lacks={"critical": "high"}), True, "withdrawn", {"critical": "high"}),
    (dict(lacks={"critical": "notice"}), False, "high", {"critical": "notice"}),
    (dict(lacks={"critical": "high"}), False, "high", {"critical": "high"}),  # the level, from an older event
    (dict(copied={"critical": "critical"}), False, "high", {}),
])
def test_what_an_entry_says_of_its_channels(more, gone, standing, lacking):
    e = two(**more)
    assert (e.gone, e.standing, e.lacking) == (gone, standing, lacking)
    assert e.word("feed") == ("withdrawn" if "feed" in more.get("withdrawn", ()) else "high")


def book(tmp_path, **more):
    """A ledger holding one thread at high in two channels, with ``more`` on its entry."""
    led = Ledger(tmp_path / "ledger.json")
    with led:
        led.record_root(schema.validate(two().advisory), A, {"feed": A}, scope="Claude Code", exploited=False, now=1)
        led.add_channel(A, "critical", B)
        led._state()["entries"][0].update(more)
        led._save()
    return led


def reply(led, channel, level=None, eid=R1, now=10, **kw):
    """Record a level reply in one channel: ``level``, or the withdrawal when None."""
    e = led.thread(A)
    adv = schema.validate({**e.advisory, "level": level or e.level})
    return led.record_reply(A, adv, {channel: eid}, now=now, withdrawn=level is None, **kw)


@pytest.mark.parametrize("bad", [
    dict(lacks={}), dict(lacks={"feed": "high", "critical": "high"}), dict(lacks={"other": "high"}),
    dict(lacks={"feed": "low"}), dict(lacks={"feed": "withdrawn"}), dict(lacks=["feed"]),
    dict(withdrawn=["feed"], lacks={"feed": "high"}),
    dict(withdrawn=["critical", "feed"], lacks={"feed": "withdrawn"}),  # a withdrawn channel lacks no withdrawal
    dict(copied={}), dict(copied={"other": "high"}), dict(copied={"feed": "withdrawn"}),
    dict(uneven=False), dict(uneven=1),
])
def test_a_ledger_with_a_malformed_record_of_its_channels_is_refused(tmp_path, bad):
    led = book(tmp_path, **bad)
    with pytest.raises(LedgerError, match="malformed"):
        led.__enter__()


def test_the_first_channel_to_take_a_level_reply_names_the_other_until_it_takes_its_own(tmp_path):
    with book(tmp_path) as led:
        e = reply(led, "feed", "critical")
        assert (e.level, e.lacks, e.changed) == ("critical", {"critical": "high"}, [10])
        e = reply(led, "critical", "critical", R2)
        assert e.lacks is None and e.uneven is None and e.changed == [10]
    with Ledger(tmp_path / "ledger.json") as led:
        assert led.thread(A).lacking == {}  # and it loads


def test_a_channel_at_the_level_from_an_older_event_still_lacks_the_reply(tmp_path):
    """The reply's date is what a reader counts the level from: word for word the channel
    agrees, and it would lose a notice 90 days after the older event."""
    with book(tmp_path, lacks={"critical": "notice"}) as led:
        assert reply(led, "feed", "notice").lacks == {"critical": "notice"}
        assert reply(led, "critical", "notice", R2, again=True).lacks is None


def test_the_withdrawal_and_the_reply_that_ends_it_by_channel(tmp_path):
    with book(tmp_path) as led:
        e = reply(led, "feed")
        assert (e.gone, e.withdrawn, e.lacks, e.changed, e.lowered) == (True, ["feed"], {"critical": "high"}, [10], True)
        e = reply(led, "critical", eid=R2, now=20)  # the second channel: no second level change
        assert (e.withdrawn, e.lacks, e.changed) == (["critical", "feed"], None, [10])
        e = reply(led, "feed", "high", "e" * 64, now=30)
        assert (e.gone, e.withdrawn, e.lacks) == (False, ["critical"], {"critical": "withdrawn"})
        e = reply(led, "critical", "high", "f" * 64, now=30)
        assert (e.withdrawn, e.lacks, e.uneven, e.changed) == (None, None, None, [10, 30])


def test_a_reply_sent_again_to_a_withdrawn_channel_is_no_level_change_of_the_thread(tmp_path):
    with book(tmp_path, withdrawn=["critical"], lacks={"critical": "withdrawn"}, changed=[5]) as led:
        e = reply(led, "critical", "high", now=400, again=True)
        assert (e.withdrawn, e.lacks, e.changed, e.uneven) == (None, None, [5], True)
    with book(tmp_path / "later", withdrawn=["critical"], lacks={"critical": "withdrawn"}, changed=[5]) as led:
        # kk2q's own later reply (a journal item sent once more) still counts when it lands
        assert reply(led, "critical", "high", now=400).changed == [5, 400]


def test_leaving_the_state_is_counted_whichever_channel_takes_the_reply_first(tmp_path):
    """The channel that never took the withdrawal acknowledges the return first, and the
    withdrawn one refuses: the return is a level change, and the seven quiet days before
    another lowering count from it."""
    with book(tmp_path, withdrawn=["feed"], lacks={"critical": "high"}, changed=[5]) as led:
        e = reply(led, "critical", "high", now=8 * 86400)
        assert (e.gone, e.lacks, e.changed) == (False, {"feed": "withdrawn"}, [8 * 86400])
        assert not recompute.quiet(e, 9 * 86400) and recompute.quiet(e, 15 * 86400 + 1)
        e = reply(led, "feed", "high", R2, now=12 * 86400, again=True)  # given up, then sent again: no second time
        assert (e.withdrawn, e.lacks, e.changed) == (None, None, [8 * 86400])


def test_a_withdrawn_channel_lacks_no_second_withdrawal(tmp_path):
    with book(tmp_path, withdrawn=["critical"], lacks={"critical": "withdrawn"}) as led:
        e = reply(led, "feed")
        assert (e.gone, e.withdrawn, e.lacks) == (True, ["critical", "feed"], None)


def test_a_reply_sent_again_leaves_the_channels_uneven_for_good(tmp_path):
    with book(tmp_path, lacks={"critical": "notice"}) as led:
        e = reply(led, "critical", "high", again=True)
        assert e.lacks is None and e.uneven is True
        assert reply(led, "feed", "critical", R2).uneven is True
        adv = schema.validate({**e.advisory, "aliases": ["CVE-2026-0001"]})
        assert main.Run._stated(led.thread(A), adv) == [G]  # the first id only, though the counts agree


def test_a_root_posted_ahead_of_the_ledger_has_the_level_its_thread_then_reaches(tmp_path):
    """``plan_known`` posts a raise's copy before its reply: the copy states critical while
    the ledger says high."""
    led = Ledger(tmp_path / "ledger.json")
    with led:
        led.record_root(schema.validate(two().advisory), A, {"feed": A}, scope="Claude Code", exploited=False, now=1)
        e = led.add_channel(A, "critical", B, "critical")
        assert (e.copied, e.level, e.lacking, e.word("critical")) == ({"critical": "critical"}, "high", {}, "critical")
        e = reply(led, "feed", "critical")
        assert e.lacks is None and e.copied is None and e.level == "critical"
    with led:  # a copy at the thread's level is no news, and a withdrawn thread's new channel lacks the withdrawal
        e = led.add_channel(A, "other", R2, "critical")
        assert e.copied is None
        reply(led, "feed", eid="e" * 64)
        reply(led, "critical", eid="f" * 64)
        reply(led, "other", eid="1" * 64)
        assert led.add_channel(A, "late", "2" * 64, "critical").lacks == {"late": "critical"}


def test_a_thread_whose_standing_reply_names_a_level_is_judged_as_one(tmp_path):
    """kk2q case 2: one channel still withdrawn does not make the thread withdrawn. The
    source withdraws again: a new wait, where a withdrawn thread is never due."""
    off = reads(**{G: ghsa_json(G, **OFF)})
    left = two(withdrawn=["critical"], lacks={"critical": "withdrawn"})
    assert hourly(left, off, 25)[0][-1] == DUE
    lagging = two(withdrawn=["feed"], lacks={"critical": "high"})  # case 1: the withdrawal stands
    assert hourly(lagging, off, 25)[0] == [None] * 26


# ---------------------------------------------------------------- through main.run


def critical(env):
    """A malware advisory with no fix: critical, a root in each channel, claimed."""
    relay = post(env, fixed=None, **MALWARE)
    (e,) = entries(env)
    assert e["level"] == "critical" and set(e["channel_ids"]) == {"critical", "feed"} and e.get("claim")
    return relay


def quiet(env, first, n=4):
    """No level reply in ``n`` more hourly runs."""
    return all(sends(run(env, h)) == [] for h in range(first, first + n))


def test_a_raise_refused_twice_in_one_channel_is_sent_to_it_again_and_recorded(env):
    """Acceptance 1 and 5, and the pace: the reply is withheld three days, sent once more,
    given up, and planned anew by the next run from the ledger."""
    critical(env)
    edit(env, lambda e: at(e, "high"))  # the read still says critical: this run raises it
    code, _, relay = env.run(now=T0 + HOUR, relay=FakeRelay("ok", "refuse"))
    took, lacks = sends(relay)[0][0], sends(relay)[1][0]
    assert sends(relay) == [(took, "critical"), (lacks, "critical")]
    (e,) = entries(env)
    assert (e["level"], e["lacks"]) == ("critical", {lacks: "high"}) and "uneven" not in e
    sent, codes = [], {}
    for h in range(2, 2 + 4 * DAY):
        codes[h], _, relay = env.run(now=T0 + h * HOUR, relay=FakeRelay(*["refuse"] * 9))
        sent += [(h, *s) for s in sends(relay)]
    # sent once more three days after the refusal and given up; planned anew an hour later
    assert sent == [(1 + 3 * DAY, lacks, "critical"), (2 + 3 * DAY, lacks, "critical")]
    assert codes[1 + 3 * DAY] == 0 and entries(env)[0]["lacks"] == {lacks: "high"}
    (w,) = [w for w in env.state()["withheld"] if w["items"][0]["kind"] == "reply"]
    assert w["items"][0]["again"] is True and inputs._item_ok(w["items"][0])  # on disk, through the withheld list
    took_it = []
    for h in range(2 + 4 * DAY, 2 + 8 * DAY):
        relay = run(env, h)
        took_it += [(s, c) for s, c in zip(sends(relay), claims(relay, lacks))]
        if "lacks" not in entries(env)[0]:
            break
    ((reply, claim),) = took_it
    assert reply == (lacks, "critical") and claim["level"] == "critical" and claim["id"] == G
    (e,) = entries(env)
    assert e["level"] == "critical" and e["uneven"] is True and len(e["changed"]) == 1
    assert quiet(env, h + 1)  # no reply is sent twice to a channel that has it


def test_a_lowering_one_channel_never_took_is_sent_to_it(env):
    """Acceptance 2: the ledger as the journal leaves it when it gives the reply up."""
    critical(env)
    env.api.put(G, ghsa_json(G, packages=NO_FIX))  # the advisory no longer supports critical
    edit(env, lambda e: (at(e, "high"), e.update(lacks={"critical": "critical"}, lowered=True)))
    relay = run(env, 1)
    assert sends(relay) == [("critical", "high")]
    # no claim: this run's reading states notice and the standing claim critical, neither high
    assert claims(relay, "critical") == [None]
    (e,) = entries(env)
    assert e["level"] == "high" and "lacks" not in e and e["uneven"] is True and "changed" not in e
    assert quiet(env, 2)


def test_a_withdrawal_one_channel_never_took_is_sent_to_it(env):
    """Acceptance 3 (kk2q case 1), with the claim of the withdrawn reading."""
    critical(env)
    env.api.put(G, ghsa_json(G, **OFF, **MALWARE))
    edit(env, lambda e: (at(e, "critical"), e.update(withdrawn=["feed"], lacks={"critical": "critical"}, lowered=True)))
    relay = run(env, 1)
    assert sends(relay) == [("critical", "withdrawn")]
    assert claims(relay, "critical")[0]["level"] == ruleset.NONE
    (e,) = entries(env)
    assert e["withdrawn"] == ["critical", "feed"] and "lacks" not in e and e["level"] == "critical"
    assert quiet(env, 2)


def test_the_reply_that_ends_a_withdrawal_is_sent_with_no_verdict(env):
    """Acceptance 4: the standing reply names the level; the read that would raise a
    withdrawn thread is not needed (the advisory API is down)."""
    critical(env)
    edit(env, lambda e: e.update(withdrawn=["critical"], lacks={"critical": "withdrawn"}, lowered=True))
    env.api.put(G, 503)
    relay = run(env, 1)
    assert sends(relay) == [("critical", "critical")]
    (claim,) = claims(relay, "critical")  # the standing claim, checked now
    assert claim["level"] == "critical" and claim["checked_at"] == T0 + HOUR and claim["confirmed_at"] == T0
    assert "withdrawn" not in entries(env)[0] and quiet(env, 2)


def two_threads(env):
    """Two critical threads, each in both channels: the older lacks a lowering in one
    channel, the newer a raise."""
    critical(env)
    other = "GHSA-aaaa-bbbb-cc01"
    env.api.put(other, ghsa_json(other, **MALWARE))
    env.collector([finding(fid=other, severity="moderate", fixed=None)])
    run(env, 1)
    assert [e["level"] for e in entries(env)] == ["critical", "critical"]
    env.api.put(G, ghsa_json(G, packages=NO_FIX))
    edit(env, lambda e: (at(e, "high"), e.update(lacks={"critical": "critical"}, lowered=True)), 0)
    edit(env, lambda e: e.update(lacks={"feed": "high"}), 1)


def test_a_channel_that_shows_less_goes_first(env):
    """Acceptance: raises first. The ledger lists the thread that lacks a lowering first."""
    two_threads(env)
    assert sends(run(env, 2)) == [("feed", "critical"), ("critical", "high")]
    assert all("lacks" not in e for e in entries(env)) and quiet(env, 3)


def test_a_failed_send_stops_the_run_after_the_raise_and_nothing_is_planned_twice(env):
    two_threads(env)
    code, _, relay = env.run(now=T0 + 2 * HOUR, relay=FakeRelay("fail"))
    assert code == 1 and sends(relay) == [("feed", "critical")]
    (it,) = env.state()["outbox"]
    assert it["again"] is True and it["channel"] == "feed"
    assert not inputs._item_ok({**it, "again": False}) and not inputs._item_ok({**it, "kind": "copy"})
    assert sends(run(env, 3)) == [("feed", "critical"), ("critical", "high")]  # the journal's item, then the other thread
    assert quiet(env, 4)


def test_a_thread_about_to_be_lowered_is_not_sent_its_missed_raise_first(env):
    """The lowering goes to every channel and is the standing reply from then on. A raise
    sent again before it in the same run could carry the same second and read last."""
    critical(env)
    env.api.put(G, ghsa_json(G, packages=NO_FIX))  # no longer critical: a wait of a day
    edit(env, lambda e: at(e, "critical"))
    assert all(sends(run(env, h)) == [] for h in range(1, 25))
    edit(env, lambda e: e.update(lacks={"feed": "high"}))
    relay = run(env, 25)
    (level,) = {lv for _, lv in sends(relay)}
    assert level != "critical" and sorted(ch for ch, _ in sends(relay)) == ["critical", "feed"]
    (e,) = entries(env)
    assert e["level"] == level and "lacks" not in e and "uneven" not in e


def test_channels_that_refuse_for_good_are_tried_one_thread_a_run(env):
    """Two refusals stop a run. Two threads lack a raise in a channel that refuses: one
    reply a run, and no run stops for it."""
    two_threads(env)
    edit(env, lambda e: (at(e, "critical"), e.update(lacks={"feed": "high"})), 0)
    env.api.put(G, ghsa_json(G, **MALWARE))
    for h in (2, 3):  # the relay refuses the first send of each run: the reconciliation's
        code, _, relay = env.run(now=T0 + h * HOUR, relay=FakeRelay("refuse"))
        assert code == 0 and sends(relay) == [("feed", "critical")]
    assert [w["items"][0]["again"] for w in env.state()["withheld"]] == [True, True]
    assert sends(env.run(now=T0 + 4 * HOUR, relay=FakeRelay("refuse"))[2]) == []


def test_a_reply_acknowledged_and_not_recorded_is_finished_by_the_next_run(env, monkeypatch):
    """A run that stops between the acknowledgement and the ledger's record: the item on
    disk still says the reconciliation planned it."""
    critical(env)
    env.api.put(G, ghsa_json(G, packages=NO_FIX))
    edit(env, lambda e: (at(e, "high"), e.update(lacks={"critical": "critical"}, lowered=True)))
    real = Ledger.record_reply

    def stop(self, *a, **kw):
        raise LedgerError("disk full")
    monkeypatch.setattr(Ledger, "record_reply", stop)
    code, _, relay = env.run(now=T0 + HOUR)
    assert code == 1 and sends(relay) == [("critical", "high")] and env.state()["outbox"][0]["sent"]
    monkeypatch.setattr(Ledger, "record_reply", real)
    assert sends(run(env, 2)) == []
    (e,) = entries(env)
    assert "lacks" not in e and e["uneven"] is True and env.state()["outbox"] == []


def test_a_thread_that_left_the_state_in_one_channel_is_renewed(env):
    """kk2q case 2: the other channel still refuses the reply; the thread is at its level
    and its claim is renewed when half its life is gone."""
    critical(env)
    edit(env, lambda e: e.update(withdrawn=["critical"], lacks={"critical": "withdrawn"}, lowered=True))
    code, _, relay = env.run(now=T0 + 8 * DAY * HOUR, relay=FakeRelay("refuse"))
    assert sends(relay) == [("critical", "critical")]  # refused: withheld
    assert sorted(ch for ch, _ in renewals(relay)) == ["critical", "feed"]
    assert entries(env)[0]["lacks"] == {"critical": "withdrawn"}


def test_a_lacking_channels_root_is_kept_out_of_the_checkpoint(env, monkeypatch):
    critical(env)
    env.api.put(G, ghsa_json(G, packages=NO_FIX))
    seen = []
    real = signer.run_checkpoint
    monkeypatch.setattr(signer, "run_checkpoint", lambda *a, **k: (seen.append(set(k["suppress"])), real(*a, **k))[1])
    edit(env, lambda e: (at(e, "high"), e.update(lacks={"critical": "critical"}, lowered=True)))
    env.run(now=T0 + HOUR, relay=FakeRelay("refuse"))
    assert seen[-1] == {entries(env)[0]["channel_ids"]["critical"]}  # withheld: gtw9 already kept it out
    env.run(now=T0 + (1 + 3 * DAY) * HOUR, relay=FakeRelay("refuse"))  # sent once more, refused, given up
    assert env.state()["outbox"] == [] and env.state()["withheld"] == [] and entries(env)[0]["lacks"]
    assert seen[-1] == {entries(env)[0]["channel_ids"]["critical"]}  # nothing in flight: the ledger says so
    run(env, 2 + 3 * DAY)  # planned anew, taken
    assert "lacks" not in entries(env)[0] and seen[-1] == set()
    # so is a channel that lacks the withdrawal, as one whose withdrawal waits in the journal is
    env.api.put(G, ghsa_json(G, **OFF, packages=NO_FIX))
    edit(env, lambda e: e.update(withdrawn=["feed"], lacks={"critical": "high"}))
    env.run(now=T0 + (3 + 3 * DAY) * HOUR, relay=FakeRelay("refuse"))
    assert entries(env)[0]["lacks"] == {"critical": "high"}
    assert seen[-1] == {entries(env)[0]["channel_ids"]["critical"]}


def test_a_candidates_raise_to_critical_leaves_no_channel_lacking(env):
    """``plan_known`` posts the copy in the critical channel, then the reply in the feed."""
    env.collector([finding(fid=G, aliases=("CVE-2026-0001",), affected="<2.1.0")])
    assert "roots=1" in env.run()[1]
    env.collector([])
    env.kev.catalog = {"vulnerabilities": [kev_item()]}
    code, summary, relay = env.run(now=T0 + HOUR)
    assert code == 0 and "copies=1" in summary and [c[0] for c in relay.calls] == ["critical", "feed"], summary
    (e,) = entries(env)
    assert e["level"] == "critical" and "lacks" not in e and "copied" not in e
    assert quiet(env, 2)


def test_a_copy_whose_reply_the_feed_never_took_is_sent_nothing(env):
    env.collector([finding(fid=G, aliases=("CVE-2026-0001",), affected="<2.1.0")])
    env.run()
    env.collector([])
    env.kev.catalog = {"vulnerabilities": [kev_item()]}
    code, summary, relay = env.run(now=T0 + HOUR, relay=FakeRelay("ok", "refuse"))
    (e,) = entries(env)
    assert e["level"] == "high" and e["copied"] == {"critical": "critical"} and "lacks" not in e
    env.kev.catalog = {"vulnerabilities": []}  # nothing raises it again in these runs
    for h in range(2, 2 + 3 * DAY + 4):  # past the hour the journal gives the feed's reply up
        _, _, relay = env.run(now=T0 + h * HOUR, relay=FakeRelay(*["refuse"] * 9))
        # no reply naming the level alone: the candidate's own raise, planned again once the
        # journal lets go, is what brings the thread to critical, in every channel as before
        assert sends(relay) == [] and "lacks" not in entries(env)[0]
        assert all(not it.get("again") for it in env.state()["outbox"] + [i for w in env.state()["withheld"] for i in w["items"]])
