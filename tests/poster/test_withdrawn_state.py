"""The poster reaches, sends and leaves the state ``withdrawn`` (ai-tools-alerts#kk2q;
spec/wire.md "A withdrawal"): reached as a lowering is, left as a raise is, kept in the
ledger beside the level and by channel. Unit tests of ``recompute.judge``, then
``main.run`` one run an hour with the fake relay, KEV fetch and advisory API."""

import json

import pytest

from aitools_alerts import pull, ruleset, schema, wire
from aitools_alerts.poster import compose, main, recompute

from advisories import ghsa_json, osv_json
from test_advisory_recompute import (CLAUDE, CVE, G, HOUR, MAL, NO_FIX, RS, WHEN, entries, hourly, post, reads, run,
                                     state, thread)
from test_copy_on_raise import edit
from test_main import T0, FakeRelay, env, finding, kev_item  # noqa: F401  (env is a fixture)
from test_recompute import catalog

DAY = 24
OFF = dict(withdrawn_at=WHEN)
OTHER = [("npm", "left-pad", "< 1.0.0", "1.0.0")]  # the advisory, published again, names another package
IN = dict(withdrawn=["feed"])
DUE = ("due", wire.WITHDRAWN)


# ---------------------------------------------------------------- judge


@pytest.mark.parametrize("level", ("critical", "high", "notice"))
def test_a_withdrawn_reviewed_advisory_is_due_the_state_after_a_day_of_whole_reads(level):
    got, st = hourly(thread(level=level), reads(**{G: ghsa_json(G, **OFF)}), 25)
    assert got == [None] * 24 + [DUE, DUE]  # from notice too: the state is below every level
    assert st["dwell"]["a" * 64]["level"] == wire.WITHDRAWN


def test_what_keeps_a_thread_out_of_the_state():
    off = reads(**{G: ghsa_json(G, **OFF)})
    # a level a reading of prose gave: lowered to it as before, and never below
    assert hourly(thread(level="critical", floor="high"), off, 24)[0][-1] == ("due", "high")
    got, st = hourly(thread(level="high", floor="high"), off, 30)
    assert got == [None] * 31 and st["dwell"] == {}
    # a source its subject's attacker can write: unknown, no wait
    got, st = hourly(thread(), reads(**{G: ghsa_json(G, type="unreviewed", repo=None, **OFF)}), 30)
    assert got == [None] * 31 and st["dwell"] == {}
    # a second reading counted that does not state the withdrawal: a lowering to notice, as before
    named = dict(identifiers=(MAL,), **OFF)
    one = reads(**{G: ghsa_json(G, **named), MAL: osv_json(MAL, packages=(("npm", "left-pad"),))})
    assert hourly(thread(), one, 24)[0][-1] == ("due", "notice")
    assert hourly(thread(level="notice"), one, 30)[0] == [None] * 31
    both = reads(**{G: ghsa_json(G, **named), MAL: osv_json(MAL, withdrawn=WHEN)})
    assert hourly(thread(), both, 24)[0][-1] == DUE
    # a KEV entry that lists the thread's CVE for the product holds it; the same thread with the
    # CVE in no catalog is due the state, so it is the listing that holds
    tied = reads(**{G: ghsa_json(G, cve=CVE, **OFF)})
    version = lambda h: f"2026.11.{h // 24 + 1:02d}"  # noqa: E731
    absent, _ = hourly(thread((G, CVE)), tied, 30, cat=lambda h: {**catalog("v"), "catalogVersion": version(h)})
    assert absent[24:] == [DUE] * 7
    listed, _ = hourly(thread((G, CVE)), tied, 30,
                       cat=lambda h: {**catalog("v", kev_item(CVE)), "catalogVersion": version(h)})
    assert listed == [None] * 31  # held at its level by the listing: no wait, no state


def test_a_wait_for_a_level_and_a_wait_for_the_state_are_two_waits():
    api = {G: ghsa_json(G, cwes=())}  # supports notice
    read = lambda i: reads(**api)(i)  # noqa: E731 - a fresh reader each hour, as each run has
    st = recompute.new_state()
    e = thread()
    for h in range(20):
        assert recompute.judge(e, CLAUDE, None, RS, st, h * HOUR, read) is None
    assert st["dwell"]["a" * 64]["level"] == "notice" and st["dwell"]["a" * 64]["held"] == 19 * HOUR
    api[G] = ghsa_json(G, **OFF)
    assert recompute.judge(e, CLAUDE, None, RS, st, 20 * HOUR, read) is None
    assert st["dwell"]["a" * 64] == {"level": wire.WITHDRAWN, "version": None, "last": 20 * HOUR, "held": 0}
    api[G] = 503  # a failed read inside the wait: it keeps its time and takes none
    assert recompute.judge(e, CLAUDE, None, RS, st, 21 * HOUR, read) is None
    assert st["dwell"]["a" * 64]["last"] is None and st["dwell"]["a" * 64]["held"] == 0


@pytest.mark.parametrize("kept", ("critical", "high", "notice"))
def test_a_withdrawn_thread_leaves_the_state_in_the_run_that_reads_the_cause(kept):
    e = thread(level=kept, **IN)
    back = reads(**{G: ghsa_json(G)})
    got, st = hourly(e, back, 0)
    assert got == [("raise", "high")] and st["dwell"] == {}  # the level read, whatever the ledger kept
    assert recompute.raised(e, CLAUDE, None, RS, back) == "high"
    assert hourly(e, reads(**{G: ghsa_json(G, **OFF)}), 3) == ([None] * 4, recompute.new_state())  # still withdrawn
    assert hourly(e, reads(**{G: 404}), 3)[0] == [None] * 4  # unknown: nothing
    silent = reads(**{G: ghsa_json(G, packages=OTHER)})  # read whole, no withdrawal stated, the product not named
    assert hourly(e, silent, 0)[0] == [("raise", "notice")]
    assert recompute.raised(e, CLAUDE, None, RS, silent) is None  # judge's to say: it knows what was read whole
    # two readings, both read whole, neither supporting the product: while one still states the
    # withdrawal the thread stays (entered when all state it, left this way when none does)
    named = dict(identifiers=(MAL,), packages=OTHER)
    mixed = reads(**{G: ghsa_json(G, **named, **OFF), MAL: osv_json(MAL, packages=(("npm", "left-pad"),))})
    assert hourly(e, mixed, 3)[0] == [None] * 4
    mixed = reads(**{G: ghsa_json(G, **named), MAL: osv_json(MAL, packages=(("npm", "left-pad"),), withdrawn=WHEN)})
    assert hourly(e, mixed, 3)[0] == [None] * 4
    neither = reads(**{G: ghsa_json(G, **named), MAL: osv_json(MAL, packages=(("npm", "left-pad"),))})
    assert hourly(e, neither, 0)[0] == [("raise", "notice")]
    taught = thread(level=kept, floor="high", **IN)  # a candidate taught the floor since
    still = reads(**{G: ghsa_json(G, **OFF)})
    assert hourly(taught, still, 0)[0] == [("raise", "high")] and recompute.raised(taught, CLAUDE, None, RS, still) == "high"


def test_the_state_file_takes_the_word_for_a_wait_and_for_the_digest(tmp_path):
    st = recompute.new_state()
    st["dwell"]["a" * 64] = {"level": wire.WITHDRAWN, "version": None, "last": 5, "held": 7}
    st["lowered"] = [[G, wire.WITHDRAWN], [G, "notice"]]
    recompute.save(tmp_path / "s.json", st)
    assert recompute.load(tmp_path / "s.json") == (st, False)
    for bad in ({**st, "lowered": [[G, "none"]]},
                {**st, "dwell": {"a" * 64: {"level": "gone", "version": None, "last": 5, "held": 7}}}):
        recompute.save(tmp_path / "s.json", bad)
        assert recompute.load(tmp_path / "s.json")[1] is True


# ---------------------------------------------------------------- through main.run


def moves(relay, channel="feed"):
    """The words of the level-only blocks a run's replies carried in one channel: a level,
    or ``withdrawn``."""
    out = []
    for c in relay.calls:
        block = schema._last_block(c[2]) if c[0] == channel and c[1] is not None else None
        patch = json.loads(block) if isinstance(block, str) else None
        if isinstance(patch, dict) and set(patch) == {"level"}:
            out.append(patch["level"])
    return out


def moved(env, first, last, **kw):
    return [(h, lv) for h in range(first, last + 1) for lv in moves(run(env, h, **kw))]


def claims(relay, channel="feed"):
    return [wire.claim_of({"tags": [c.claim]}) if c.claim else None for c in relay.calls
            if c[0] == channel and c[1] is not None]


def withdrawn(env, **api):
    """A thread at high (floor notice) whose advisory was withdrawn at hour 1: the runs
    up to hour 25, which sends the withdrawal. The relay of that run."""
    post(env, **api)
    env.api.put(G, ghsa_json(G, **OFF, **api))
    assert moved(env, 1, 24) == []
    return run(env, 25)


def test_a_withdrawn_reviewed_advisory_moves_its_thread_to_the_state(env):
    """Build items 1 to 3: one reply, the block alone, the claim of the withdrawn reading;
    the ledger keeps the level beside the state."""
    relay = withdrawn(env)
    (call,) = [c for c in relay.calls if c[1] is not None]
    assert call[2] == compose.withdrawal_post() and wire.is_withdrawal(json.loads(schema._last_block(call[2])))
    (claim,) = claims(relay)
    assert claim["level"] == ruleset.NONE and claim["id"] == G and claim["fields"]["withdrawn_at"] == WHEN
    (e,) = entries(env)
    assert (e["level"], e["advisory"]["level"], e["withdrawn"], e["lowered"]) == ("high", "high", ["feed"], True)
    assert e["changed"] == [T0 + 25 * HOUR]
    assert state(env)["lowered"] == [[G, wire.WITHDRAWN]] and len(state(env)["recent"]) == 1  # the breaker counts it
    assert moved(env, 26, 60) == [] and state(env)["dwell"] == {}
    # the poster's own events, as a reader takes them: a standing withdrawal
    assert schema.parse_post(call[2]) is None and compose.parse_reply(call[2], schema.validate(e["advisory"])) is None


def test_the_digest_names_the_withdrawal(env):
    withdrawn(env)
    code, _, relay = env.run(now=T0 + 26 * HOUR, digest_now=True)
    (digest,) = [c[2] for c in relay.calls if c[2].startswith("Daily digest")]
    assert code == 0 and f"Lowered since the last digest: {G} withdrawn." in digest
    assert f"{G} (取り下げ)" in "".join(c[2] for c in relay.ja)


def test_published_again_it_returns_to_its_level_in_the_same_thread(env):
    """Acceptance. The reply names the level the ledger kept, which no level reply could
    before; it is a raise, so it waits for nothing."""
    withdrawn(env)
    env.api.put(G, ghsa_json(G))
    relay = run(env, 26)
    (e,) = entries(env)
    assert moves(relay) == ["high"] and [c[1] for c in relay.calls] == [e["root_event_id"]]
    assert claims(relay)[0]["level"] == "high"
    assert e["level"] == "high" and "withdrawn" not in e and e["changed"] == [T0 + 25 * HOUR, T0 + 26 * HOUR]
    assert moved(env, 27, 60) == []
    # withdrawn again: the quiet week holds it, then the state once more
    env.api.put(G, ghsa_json(G, **OFF))
    assert moved(env, 61, 26 + 7 * DAY - 1) == [] and moved(env, 26 + 7 * DAY, 26 + 7 * DAY) == [(26 + 7 * DAY, "withdrawn")]


def test_a_critical_thread_is_withdrawn_and_returns_in_both_channels(env):
    malware = dict(type="malware", packages=NO_FIX)
    post(env, fixed=None, **malware)
    assert entries(env)[0]["level"] == "critical" and set(entries(env)[0]["channel_ids"]) == {"feed", "critical"}
    env.api.put(G, ghsa_json(G, **OFF, **malware))
    assert moved(env, 1, 24) == []
    relay = run(env, 25)
    assert moves(relay) == moves(relay, "critical") == ["withdrawn"]
    (e,) = entries(env)
    assert e["level"] == "critical" and e["withdrawn"] == ["critical", "feed"] and e["changed"] == [T0 + 25 * HOUR]
    assert state(env)["lowered"] == [[G, wire.WITHDRAWN]]  # once, for its first channel
    env.api.put(G, ghsa_json(G, **malware))
    relay = run(env, 26)
    assert moves(relay) == moves(relay, "critical") == ["critical"]
    (e,) = entries(env)
    assert e["level"] == "critical" and "withdrawn" not in e and len(e["changed"]) == 2
    assert not [c for c in relay.calls if c[1] is None] and moved(env, 27, 30) == []


def test_published_again_without_the_product_it_returns_to_notice(env):
    withdrawn(env)
    env.api.put(G, ghsa_json(G, packages=OTHER))
    relay = run(env, 26)
    assert moves(relay) == ["notice"]
    (e,) = entries(env)
    assert e["level"] == "notice" and "withdrawn" not in e


def test_a_withdrawn_unreviewed_advisory_never_reaches_the_state(env):
    post(env)
    env.api.put(G, ghsa_json(G, type="unreviewed", repo=None, **OFF))
    assert moved(env, 1, 60) == [] and "withdrawn" not in entries(env)[0] and state(env)["dwell"] == {}


def test_a_thread_whose_prose_gave_high_is_never_withdrawn(env):
    post(env)
    edit(env, lambda e: e.update(floor="high"))
    env.api.put(G, ghsa_json(G, **OFF))
    assert moved(env, 1, 60) == [] and "withdrawn" not in entries(env)[0]


def test_withdrawn_every_other_hour_sends_nothing_in_a_week(env):
    """Acceptance."""
    post(env)
    sent = []
    for h in range(1, 7 * DAY + 1):
        env.api.put(G, ghsa_json(G, **(OFF if h % 2 else {})))
        sent += moved(env, h, h)
    assert sent == [] and "withdrawn" not in entries(env)[0]


def test_withdrawn_every_other_two_days_sends_at_most_three_in_any_week(env):
    """Acceptance."""
    post(env)
    sent = []
    for h in range(1, 20 * DAY + 1):
        env.api.put(G, ghsa_json(G, **(OFF if (h // 48) % 2 == 0 else {})))
        sent += moved(env, h, h)
    assert sent[:2] == [(25, "withdrawn"), (48, "high")]  # in after a day, out in the run that reads it
    assert len(sent) >= 4 and {lv for _, lv in sent} == {"withdrawn", "high"}
    assert all(sum(a <= h < a + 7 * DAY for h, _ in sent) <= 3 for a in range(20 * DAY))


# ---------------------------------------------------------------- what a withdrawn thread does not get


def test_a_withdrawn_thread_is_not_renewed_or_stepped_down(env):
    """A step names a level, which would end the withdrawal on every reader."""
    withdrawn(env)
    assert entries(env)[0]["claim"]  # its root carried a claim: any other thread is renewed and stepped
    for day in (16, 30, 44, 45, 46, 60):
        relay = run(env, day * DAY)
        assert [c for c in relay.calls if c[1] is not None] == [], day
    (e,) = entries(env)
    assert e["level"] == "high" and e["withdrawn"] == ["feed"]


def test_a_withdrawn_thread_gets_no_copy(env):
    malware = dict(type="malware", packages=NO_FIX)
    post(env, fixed=None, **malware)
    env.run(now=T0 + HOUR, digest_now=True)  # the digest that lists its root

    def feed_only(e, state):
        e["channel_ids"] = {"feed": e["channel_ids"]["feed"]}  # as if its copy had never posted
        e.pop("withdrawn", None)
        e.update(state)
    edit(env, lambda e: feed_only(e, {"withdrawn": ["feed"]}))
    env.api.put(G, ghsa_json(G, **OFF, **malware))
    relay = run(env, 2)
    assert [c for c in relay.calls if c[1] is None] == []  # critical in the ledger, and no root in the critical channel
    edit(env, lambda e: feed_only(e, {}))
    relay = run(env, 3)
    assert [c[0] for c in relay.calls if c[1] is None] == ["critical"]  # the same thread, not withdrawn: its copy


def test_a_root_posted_since_the_last_digest_is_not_listed_once_withdrawn(env):
    post(env)
    edit(env, lambda e: e.update(withdrawn=["feed"]))
    env.api.put(G, ghsa_json(G, **OFF))
    code, _, relay = env.run(now=T0 + HOUR, digest_now=True)
    (digest,) = [c[2] for c in relay.calls if c[2].startswith("Daily digest")]
    assert code == 0 and G not in digest


def test_a_candidate_changes_no_level_of_a_withdrawn_thread(env):
    """Build item 5: its fix still replies, with no level in the block; the level is the
    recompute's to send, alone."""
    withdrawn(env)
    env.collector([finding(fid=G, severity="remote code execution", fixed="2.2.0")])  # prose that reads high
    relay = run(env, 26)
    blocks = [json.loads(schema._last_block(c[2])) for c in relay.calls if c[1] is not None]
    assert blocks and all("level" not in b for b in blocks) and [c for c in relay.calls if c[1] is None] == []
    (e,) = entries(env)
    assert e["withdrawn"] == ["feed"] and e["floor"] == "high"
    assert moves(run(env, 27)) == ["high"]  # the floor it taught ends the state, in a reply of its own
    assert "withdrawn" not in entries(env)[0]


# ---------------------------------------------------------------- the journal


def test_a_channel_whose_send_failed_gets_the_withdrawal_from_the_next_run(env):
    malware = dict(type="malware", packages=NO_FIX)
    post(env, fixed=None, **malware)
    env.api.put(G, ghsa_json(G, **OFF, **malware))
    assert moved(env, 1, 24) == []
    code, _, relay = env.run(now=T0 + 25 * HOUR, relay=FakeRelay("ok", "fail"))
    assert len(entries(env)[0]["withdrawn"]) == 1
    relay = run(env, 26)
    assert len([c for c in relay.calls if c[1] is not None]) == 1 and moves(relay) + moves(relay, "critical") == ["withdrawn"]
    assert entries(env)[0]["withdrawn"] == ["critical", "feed"] and len(entries(env)[0]["changed"]) == 1


def test_an_unsent_withdrawal_is_dropped_when_the_advisory_is_back_first(env):
    post(env)
    env.api.put(G, ghsa_json(G, **OFF))
    assert moved(env, 1, 24) == []
    env.run(now=T0 + 25 * HOUR, relay=FakeRelay("fail"))
    assert [it["key"] for it in env.state()["outbox"]] == [f"reply:Claude Code:{G}#level:feed"]
    env.api.put(G, ghsa_json(G))
    assert moved(env, 26, 30) == [] and env.state()["outbox"] == [] and "withdrawn" not in entries(env)[0]


def test_the_run_that_records_a_withdrawal_does_not_end_it(env):
    """A reader orders replies by (created_at, id) and an event is dated by the second:
    the two in one run could read in either order."""
    post(env)
    env.api.put(G, ghsa_json(G, **OFF))
    assert moved(env, 1, 24) == []
    env.run(now=T0 + 25 * HOUR, relay=FakeRelay("unknown"))  # sent, outcome not known: it stays journaled
    env.api.put(G, ghsa_json(G))
    sent = moved(env, 26, 26 + 3 * DAY)  # the unknown send expires after a day and is sent again
    assert [lv for _, lv in sent] == ["withdrawn", "high"]
    assert sent[1][0] == sent[0][0] + 1  # the reply that ends it: the next run, never the same one
    assert "withdrawn" not in entries(env)[0]


def test_a_channel_that_never_took_the_reply_that_ends_the_state_is_sent_it_again(env):
    """The journal gives up a reply refused twice (jsje). The state is kept by channel, so
    the recompute still knows which channel lacks it."""
    malware = dict(type="malware", packages=NO_FIX)
    post(env, fixed=None, **malware)
    env.api.put(G, ghsa_json(G, **OFF, **malware))
    assert moved(env, 1, 24) == [] and moves(run(env, 25)) == ["withdrawn"]
    env.api.put(G, ghsa_json(G, **malware))
    code, _, relay = env.run(now=T0 + 26 * HOUR, relay=FakeRelay("ok", "refuse"))
    took = [c[0] for c in relay.calls][0]
    lacks = "critical" if took == "feed" else "feed"
    (e,) = entries(env)
    assert e["withdrawn"] == [lacks] and e["level"] == "critical"
    sent = []
    for h in range(27, 27 + 4 * DAY):  # withheld three days, sent once more, refused again, given up, planned anew
        code, _, relay = env.run(now=T0 + h * HOUR, relay=FakeRelay(*["refuse"] * 9))
        sent += [(h, c[0], json.loads(schema._last_block(c[2]))) for c in relay.calls if c[1] is not None]
    assert len(sent) >= 2 and {(ch, b["level"]) for _, ch, b in sent} == {(lacks, "critical")}
    assert sent[1][0] - 26 >= 3 * DAY and entries(env)[0]["withdrawn"] == [lacks]  # no sooner than the journal's own retry
    took_it = []
    for h in range(27 + 4 * DAY, 27 + 8 * DAY):  # the relay takes it again: whatever is withheld waits out its days
        relay = run(env, h)
        took_it += [(c[0], json.loads(schema._last_block(c[2]))) for c in relay.calls if c[1] is not None]
        if "withdrawn" not in entries(env)[0]:
            break
    assert took_it == [(lacks, {"level": "critical"})] and "withdrawn" not in entries(env)[0]
    assert entries(env)[0]["level"] == "critical"


def test_a_partly_withdrawn_thread_is_brought_to_the_ledgers_level_not_below(env):
    malware = dict(type="malware", packages=NO_FIX)
    post(env, fixed=None, **malware)
    edit(env, lambda e: e.update(withdrawn=["critical"], lowered=True))  # the feed left at critical; critical did not
    env.api.put(G, ghsa_json(G, cwes=(), packages=NO_FIX))  # the advisory now supports notice
    relay = run(env, 1)
    assert moves(relay, "critical") == ["critical"] and moves(relay) == []
    (e,) = entries(env)
    assert e["level"] == "critical" and "withdrawn" not in e  # one level in every channel; a fall is a lowering's


def test_a_reply_that_ends_the_state_passes_the_withdrawal_one_channel_still_lacks(env, monkeypatch):
    """``yields``: one channel took the withdrawal and the other's send failed, then the
    advisory is back. The unsent withdrawal leaves the journal in the save that journals
    the level reply, which goes to the channel that is withdrawn."""
    asked = []
    real = main.Run.yields
    monkeypatch.setattr(main.Run, "yields", lambda self, e, level: asked.append(level) or real(self, e, level))
    malware = dict(type="malware", packages=NO_FIX)
    post(env, fixed=None, **malware)
    env.api.put(G, ghsa_json(G, **OFF, **malware))
    assert moved(env, 1, 24) == []
    code, _, relay = env.run(now=T0 + 25 * HOUR, relay=FakeRelay("ok", "fail"))
    (took,) = entries(env)[0]["withdrawn"]
    assert [it["channel"] for it in env.state()["outbox"]] == [c for c in ("feed", "critical") if c != took]
    env.api.put(G, ghsa_json(G, **malware))
    relay = run(env, 26)
    assert asked and [(c[0], json.loads(schema._last_block(c[2]))) for c in relay.calls] == [(took, {"level": "critical"})]
    (e,) = entries(env)
    assert "withdrawn" not in e and e["level"] == "critical" and env.state()["outbox"] == []
    assert moved(env, 27, 30) == []


# ---------------------------------------------------------------- the poster's events on this reader


def test_the_blocks_compose_writes_are_the_ones_the_reader_knows():
    """The blocks only; tests/test_wire_compat.py reads the signed events through the reader."""
    prev = schema.validate(thread().advisory)
    gone = json.loads(schema._last_block(compose.withdrawal_post()))
    back = json.loads(schema._last_block(compose.level_post(prev, prev.level, again=True)))
    assert wire.is_withdrawal(gone) and back == {"level": "high"} and pull.WITHDRAWN == wire.WITHDRAWN
    with pytest.raises(ValueError):
        compose.level_post(prev, prev.level)
