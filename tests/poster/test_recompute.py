"""When a posted thread's level may fall (ai-tools-alerts#ny5g): an outage, a cut catalog
and a flapping source lower nothing; evidence held 24 hours lowers once. Through
``main.run`` with the fake relay and fake KEV fetch of test_main, one run an hour."""

import json

import pytest

from aitools_alerts import ruleset, schema
from aitools_alerts.poster import compose, inputs, recompute
from aitools_alerts.poster.ledger import Entry, Ledger, LedgerError

from test_main import GHSA, FakeKEV, FakeRelay, T0, env, finding, kev_item  # noqa: F401  (env is a fixture)

HOUR, DAY = 3600, 86400
CVE = "CVE-2026-0001"
FIVE = [f"CVE-2026-000{i}" for i in range(1, 6)]
OPENSSH = {"cveID": "CVE-2026-123158", "vendorProject": "OpenBSD", "product": "OpenSSH", "dateAdded": "2026-11-04"}
GONE, BACK = (), (CVE,)


def catalog(version, *items, pad=200):
    """A KEV catalog as CISA serves it: a version, its own count, and enough other
    entries that one leaving is well inside the 2% rule."""
    items = [kev_item(i) if isinstance(i, str) else i for i in items]
    items += [{"cveID": f"CVE-2020-{n:04d}", "vendorProject": "Cisco", "product": "IOS", "dateAdded": "2020-01-01"}
              for n in range(1000, 1000 + pad)]
    return {"catalogVersion": version, "count": len(items), "vulnerabilities": items}


def levels(relay, channel="feed"):
    """The level-only replies a run sent in one channel, as their blocks."""
    return [json.loads(schema._last_block(text)) for ch, reply, text in relay.calls
            if ch == channel and reply is not None and text.startswith("Level is now")]


def replies(relay):
    return [c for c in relay.calls if c[1] is not None]


def entry(env, i=0):
    return env.ledger()[0][i]


def state(env):
    return recompute.load(env.config.recompute_state)[0]


def post(env, *items):
    """Post the KEV criticals at T0, from a complete catalog that lists them."""
    env.kev = FakeKEV(catalog=catalog("v0", *(items or (CVE,))))
    code, summary, relay = env.run(now=T0)
    assert code == 0, summary
    assert all(e["level"] == "critical" for e in env.ledger()[0])
    return T0


def one(env, hour, listed=GONE, *, kev=None, relay=None, code=0):
    """The run ``hour`` hours after T0. ``listed``: the entries a complete catalog lists
    (its version changes every six hours); ``kev``: another fetch altogether."""
    env.kev = kev or FakeKEV(catalog=catalog(f"v{hour // 6 + 1}", *listed))
    got, summary, relay = env.run(now=T0 + hour * HOUR, relay=relay)
    assert got == code, summary
    return relay


def hours(env, first, last, listed=GONE, **kw):
    """Hourly runs from ``first`` to ``last`` inclusive: [(hour, level block)] sent in feed."""
    sent = []
    for h in range(first, last + 1):
        relay = one(env, h, listed(h) if callable(listed) else listed, **kw)
        sent += [(h, b["level"]) for b in levels(relay)]
    return sent


def down(status):
    return FakeKEV(status=status)


# ---------------------------------------------------------------- the KEV copy


def test_kev_copy_tells_no_copy_from_an_incomplete_one():
    st, good = recompute.new_state(), catalog("v1", CVE, pad=99)
    assert recompute.kev_copy(good, "unavailable", st, 0) is None
    assert recompute.kev_copy(good, "file", st, 0) is None  # the synthetic --kev-file
    assert recompute.kev_copy({**good, "vulnerabilities": good["vulnerabilities"][:-1] + ["x"]}, "ok", st, 0) is None
    for cut in ({**good, "catalogVersion": " "}, {k: v for k, v in good.items() if k != "catalogVersion"},
                {**good, "count": 99}, {k: v for k, v in good.items() if k != "count"},
                {**good, "vulnerabilities": good["vulnerabilities"] + [kev_item(CVE)], "count": 101},
                {"catalogVersion": "v", "count": 0, "vulnerabilities": []}):
        copy = recompute.kev_copy(cut, "ok", st, 0)
        assert copy is not None and not copy.complete and st["kev"] is None
    assert CVE in recompute.kev_copy({**good, "count": 99}, "ok", st, 0).index  # what it lists still counts
    assert not recompute.kev_copy(good, "304", st, 4).complete  # a cached body no fetch of this state vouched for
    assert recompute.kev_copy(good, "ok", st, 5).complete
    copy = recompute.kev_copy(good, "304", st, 5)
    assert copy.complete and copy.version == "v1" and CVE in copy.index
    assert st["kev"] == {"version": "v1", "peak": 100, "at": 5}
    lower = {**good, "vulnerabilities": [{**kev_item(CVE), "cveID": " cve-2026-0001 "}] + good["vulnerabilities"][1:]}
    assert CVE in recompute.kev_copy(lower, "ok", st, 6).index  # looked up as the thread's id is written


def test_the_measure_is_the_largest_complete_copy_and_never_falls():
    st = recompute.new_state()
    assert recompute.kev_copy(catalog("v1", pad=100), "ok", st, 0).complete
    assert recompute.kev_copy(catalog("v2", pad=98), "ok", st, 1).complete  # 2% down: complete
    assert st["kev"]["peak"] == 100  # and not the new measure: 1% a day never adds up
    small = catalog("v3", pad=97)
    assert not recompute.kev_copy(small, "ok", st, 2).complete
    assert not recompute.kev_copy(small, "ok", st, 400 * DAY).complete  # no length of time makes it complete
    assert recompute.kev_copy(catalog("v4", pad=120), "ok", st, 3).complete and st["kev"]["peak"] == 120


# ---------------------------------------------------------------- support and the floor


def _thread(aliases=(CVE,), level="critical", product="Claude Code", **more):
    adv = {"id": aliases[0], "aliases": [], "level": level, "advisory_severity": None, "title": "t",
           "products": [{"name": product, "ecosystem": "claude-code", "affected": None, "fixed": None}],
           "actions": [], "sources": [{"url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                                       "published_at": None}],
           "posted_by": "relay-bot", "posted_at": 1, "expires_at": None}
    return Entry(root_event_id="a" * 64, channel_ids={"feed": "a" * 64}, level=level, aliases=list(aliases),
                 posted_at=1, last_change=1, scope=product, exploited=True, advisory=adv, replies=[], **more)


def _support(entry, cat, status="ok"):
    copy = recompute.kev_copy(cat, status, recompute.new_state(), 0) if cat else None
    scope = next(e for e in schema.load_scope() if e.name == entry.scope)
    return recompute.support(entry, scope, copy, ruleset.load())


def test_support_is_what_the_copy_states():
    assert _support(_thread(), catalog("v", CVE)) == ("critical", True, {CVE}, set())
    assert _support(_thread(), catalog("v")) == (ruleset.NONE, True, set(), {CVE})  # contradicted
    assert _support(_thread(), None) == (ruleset.NONE, False, set(), {CVE})  # no copy: unknown
    cut = {**catalog("v", CVE), "count": 1}
    assert _support(_thread(), cut) == ("critical", False, {CVE}, set())  # listed counts; nothing else is known
    assert _support(_thread(), {**catalog("v"), "count": 1})[1] is False
    two = _thread(aliases=(CVE, "CVE-2026-0002"))
    assert _support(two, catalog("v", "CVE-2026-0002")) == ("critical", True, {"CVE-2026-0002"}, {CVE})


def test_an_id_with_no_reader_makes_the_read_unknown():
    for extra in ("GHSA-abcd-efgh-ijkl", "MAL-2026-1", "LEAD-162d5e0f15f7"):
        assert _support(_thread(aliases=(CVE, extra)), catalog("v"))[1] is False
    assert _support(_thread(aliases=(CVE, "CVE-2026-0001:claude-code")), catalog("v"))[1] is True  # a ledger key


def test_a_cve_listed_under_another_name_is_unknown_not_gone():
    renamed = {**kev_item(CVE), "vendorProject": "Anthropic PBC", "product": "Claude"}
    assert _support(_thread(), catalog("v", renamed)) == (ruleset.NONE, False, set(), set())
    assert _support(_thread(), catalog("v", {**kev_item(CVE), "product": None}))[1] is False


def test_the_floor_is_the_ledgers_or_for_an_old_entry_as_far_as_a_reading_reaches():
    rs = ruleset.load()
    assert recompute.floor(_thread(floor="notice"), rs) == "notice"
    assert recompute.floor(_thread(floor="high"), rs) == "high"
    assert recompute.floor(_thread(), rs) == "high"  # written before the ledger kept it
    assert recompute.floor(_thread(level="notice"), rs) == "notice"


# ---------------------------------------------------------------- acceptance: absence of evidence lowers nothing


BAD = {"empty body": lambda h: (lambda url, headers: (200, {}, b"")),
       "404": lambda h: down(404), "429": lambda h: down(429), "503": lambda h: down(503),
       "half": lambda h: FakeKEV(catalog=catalog(f"v{h}", pad=100)),
       "no version": lambda h: FakeKEV(catalog={k: v for k, v in catalog("x").items() if k != "catalogVersion"}),
       "wrong count": lambda h: FakeKEV(catalog={**catalog(f"v{h}"), "count": 7}),
       # A whole catalog without the entry, reached through a redirect: a 3xx is not an answer.
       "redirect": lambda h: (lambda url, headers: (200, {inputs.REDIRECTED: "1"},
                                                    json.dumps(catalog(f"v{h}")).encode()))}


@pytest.mark.parametrize("bad", sorted(BAD))
def test_an_outage_or_a_cut_catalog_lowers_nothing(env, bad):
    post(env)
    for h in range(1, 31):
        assert replies(one(env, h, kev=BAD[bad](h))) == []
    assert entry(env)["level"] == "critical" and "lowered" not in entry(env)
    assert state(env)["dwell"] == {}  # and no wait began


def test_an_outage_adds_no_time_to_a_wait(env):
    post(env)
    assert hours(env, 1, 3) == []  # three complete reads without it: two hours held
    for h in range(4, 40):
        one(env, h, kev=down(503))
    assert state(env)["dwell"][entry(env)["root_event_id"]]["held"] == 2 * HOUR  # kept, not grown
    assert hours(env, 40, 61) == []  # the read after the outage adds nothing: 2 + 0 + 21 hours at 61
    assert hours(env, 62, 63) == [(62, "notice")]


def test_one_unknown_read_just_short_of_the_day_costs_its_two_hours(env):
    post(env)
    assert hours(env, 1, 23) == []  # 22 hours held
    one(env, 24, kev=down(429))
    assert hours(env, 25, 26) == []  # 25 adds nothing (an unknown read lies before it), 26 makes 23
    assert hours(env, 27, 27) == [(27, "notice")]


def test_complete_reads_that_alternate_with_unknown_ones_never_add_up(env):
    post(env)
    for h in range(1, 121):
        relay = one(env, h, kev=None if h % 2 else down(503))
        assert replies(relay) == []
    assert state(env)["dwell"][entry(env)["root_event_id"]]["held"] == 0


def test_a_poster_that_was_not_running_gets_no_time_for_the_gap(env):
    post(env)
    assert hours(env, 1, 2) == []  # one hour held
    assert hours(env, 40, 40) == []  # 38 hours with no read at all
    assert state(env)["dwell"][entry(env)["root_event_id"]]["held"] == HOUR


def test_each_cve_of_a_thread_must_have_been_seen_before_its_absence_counts(env):
    """A thread with two CVEs, of which the catalog has only ever listed one: when both
    are absent, the second one's absence proves nothing, so the thread is not lowered."""
    post(env)
    led = json.loads(env.config.ledger.read_text())
    led["entries"][0]["aliases"].append("CVE-2026-0777")  # learned later; KEV never listed it
    env.config.ledger.write_text(json.dumps(led))
    assert hours(env, 1, 60) == [] and state(env)["dwell"] == {}
    assert state(env)["listed"] == {entry(env)["root_event_id"]: [CVE]}
    one(env, 61, (CVE, "CVE-2026-0777"))  # now both have been seen
    assert hours(env, 62, 86) == [(86, "notice")]


# ---------------------------------------------------------------- acceptance: evidence held 24 hours lowers once


def test_an_entry_gone_for_a_day_of_complete_reads_lowers_once(env):
    post(env)
    assert entry(env)["floor"] == "notice"  # a KEV entry alone: no reading of prose supports more
    assert hours(env, 1, 24) == []
    relay = one(env, 25)
    assert [(c[0], c[1] is not None) for c in replies(relay)] == [("critical", True), ("feed", True)]
    assert levels(relay) == levels(relay, "critical") == [{"level": "notice"}]
    assert relay.ja == []  # a lowering has no Japanese copy
    assert not any(c[2].splitlines()[0].strip() == "retract" for c in relay.calls)
    e = entry(env)
    assert e["level"] == "notice" and e["lowered"] is True and e["changed"] == [T0 + 25 * HOUR]
    assert hours(env, 26, 90) == []  # still gone: nothing more
    assert state(env)["dwell"] == {}


def test_the_last_read_must_be_of_another_catalog_version(env):
    post(env)
    same = FakeKEV(catalog=catalog("v1"))
    for h in range(1, 40):
        assert replies(one(env, h, kev=same)) == []  # one copy read forty times
    assert levels(one(env, 40, kev=FakeKEV(catalog=catalog("v2")))) == [{"level": "notice"}]


def test_a_read_that_lists_it_starts_the_wait_over(env):
    post(env)
    assert hours(env, 1, 20) == []
    one(env, 21, BACK)
    assert state(env)["dwell"] == {}
    assert hours(env, 22, 45) == []
    assert hours(env, 46, 46) == [(46, "notice")]


def test_an_old_entry_is_lowered_no_further_than_a_reading_reaches(env):
    post(env)
    led = json.loads(env.config.ledger.read_text())
    del led["entries"][0]["floor"]  # as written before the ledger kept it
    env.config.ledger.write_text(json.dumps(led))
    assert hours(env, 1, 25) == [(25, "high")]
    assert hours(env, 26, 26 + 8 * 24) == []


def test_absence_proves_nothing_until_a_complete_copy_has_listed_it(env):
    """The state file is lost. A catalog without the entry, however complete it looks
    (a cut one can agree with its own count), no longer says the entry left: nothing
    this state has read ever listed it."""
    post(env)
    hours(env, 1, 3)
    env.config.recompute_state.write_text("{not json")
    assert hours(env, 4, 60, kev=None) == []
    assert state(env)["dwell"] == {} and entry(env)["level"] == "critical"
    one(env, 61, BACK)  # seen in a complete copy again
    assert hours(env, 62, 86) == [(86, "notice")]


def test_a_state_file_that_does_not_read_is_said_and_replaced(env, capsys):
    post(env)
    env.config.recompute_state.write_text("[]")
    one(env, 1)
    assert "recompute state" in capsys.readouterr().err and state(env)["kev"]["peak"] == 200


# ---------------------------------------------------------------- raises, and the quiet week


def test_a_raise_publishes_at_once_alone_and_a_week_passes_before_the_next_lowering(env):
    post(env)
    assert hours(env, 1, 25) == [(25, "notice")]
    relay = one(env, 26, BACK)  # listed again: raised in this run
    assert levels(relay) == levels(relay, "critical") == [{"level": "critical"}]
    assert entry(env)["level"] == "critical" and len(entry(env)["changed"]) == 2
    # Gone again: its day is long held when seven quiet days, counted from the raise, end.
    assert hours(env, 27, 26 + 7 * 24 - 1) == []
    assert hours(env, 26 + 7 * 24, 26 + 7 * 24) == [(26 + 7 * 24, "notice")]


def test_a_cut_catalog_that_lists_the_entry_still_raises(env):
    post(env)
    assert hours(env, 1, 25) == [(25, "notice")]
    cut = {**catalog("v9", CVE), "count": 3}
    assert levels(one(env, 26, kev=FakeKEV(catalog=cut))) == [{"level": "critical"}]


def test_a_source_that_toggles_hourly_moves_nothing(env):
    post(env)
    assert hours(env, 1, 72, lambda h: BACK if h % 2 else GONE) == []
    assert entry(env)["level"] == "critical"


def test_a_flapping_source_gives_at_most_three_level_changes_in_seven_days(env):
    post(env)
    sent = hours(env, 1, 16 * 24, lambda h: BACK if (h // 48) % 2 else GONE)  # two days gone, two days back
    assert sent and sent[0][1] == "notice"
    for at, _ in sent:
        assert len([1 for u, _ in sent if at <= u < at + 7 * 24]) <= 3
    lows = [at for at, level in sent if level == "notice"]
    assert all(b - a >= 7 * 24 for a, b in zip(lows, lows[1:]))
    ups = [at for at, level in sent if level == "critical"]
    assert ups and all((at // 48) % 2 == 1 and at % 48 == 0 for at in ups)  # each in the first run that listed it


# ---------------------------------------------------------------- a lowering is never replayed on old evidence


def test_a_lowering_that_did_not_send_is_judged_again_not_replayed(env):
    post(env)
    hours(env, 1, 24)
    relay = one(env, 25, relay=FakeRelay("fail"), code=1)  # due, and the first send fails
    assert len(relay.calls) == 1 and entry(env)["level"] == "critical"
    assert [it["key"].count("#level:") for it in env.state()["outbox"]] == [1, 1]
    assert one(env, 26, kev=down(404)).calls == []  # unknown now: nothing is sent, the journal is clear
    assert env.state()["outbox"] == [] and entry(env)["level"] == "critical"
    assert replies(one(env, 27, BACK)) == []  # and it is listed again: there is nothing to lower
    assert state(env)["dwell"] == {} and "lowered" not in entry(env)


def test_a_lowering_one_channel_has_reaches_the_other_whatever_the_next_read(env):
    post(env)
    hours(env, 1, 24)
    relay = one(env, 25, relay=FakeRelay("ok", "fail"), code=1)
    assert [c[0] for c in relay.calls] == ["critical", "feed"] and entry(env)["level"] == "notice"
    relay = one(env, 26, kev=down(503))
    assert levels(relay) == [{"level": "notice"}] and levels(relay, "critical") == []
    assert env.state()["outbox"] == [] and len(entry(env)["changed"]) == 1


def _lowering_acknowledged_but_not_recorded(env, monkeypatch):
    """Hour 25: the critical channel's lowering is acknowledged and journaled, and the
    ledger write that would record it fails. The run stops there."""
    post(env)
    hours(env, 1, 24)
    real = Ledger.record_reply
    monkeypatch.setattr(Ledger, "record_reply", lambda *a, **k: (_ for _ in ()).throw(LedgerError("disk")))
    relay = one(env, 25, code=1)
    monkeypatch.setattr(Ledger, "record_reply", real)
    assert [c[0] for c in relay.calls] == ["critical"] and entry(env)["level"] == "critical"
    sent = [it["sent"] is not None for it in env.state()["outbox"]]
    assert sent == [True, False]


def test_a_lowering_acknowledged_but_not_recorded_still_reaches_the_other_channel(env, monkeypatch):
    _lowering_acknowledged_but_not_recorded(env, monkeypatch)
    relay = one(env, 26, kev=down(503))  # the next read is unknown: the pair is finished all the same
    assert [c[0] for c in relay.calls] == ["feed"] and levels(relay) == [{"level": "notice"}]
    e = entry(env)
    assert e["level"] == "notice" and len(e["replies"]) == 2 and env.state()["outbox"] == []


def test_a_candidate_merged_before_the_journal_drained_does_not_lend_the_exploited_mark(env, monkeypatch):
    """The ledger still says critical and exploited when this run's candidates are merged;
    the drain then records the lowering. The vendor's page supports high: that is what the
    thread is raised to, alone, and KEV is not even readable this run."""
    _lowering_acknowledged_but_not_recorded(env, monkeypatch)
    env.collector([finding(fid=CVE, sources=(GHSA,), fixed="2.1.0", severity="high")], name="2026-11-07T000000Z")
    relay = one(env, 26, kev=down(503))
    assert levels(relay) == [{"level": "notice"}, {"level": "high"}] and entry(env)["level"] == "high"
    assert levels(relay, "critical") == [{"level": "high"}]


def test_an_unknown_read_in_a_run_that_stopped_early_still_breaks_the_wait(env):
    """22 hours held. Then KEV answers 503 in a run that stops at a failed send before the
    recompute. The next complete read must not take those two hours."""
    post(env)
    assert hours(env, 1, 23) == []
    env.collector([finding()], name="2026-11-07T000000Z")  # another advisory, whose root fails to send
    relay = one(env, 24, kev=down(503), relay=FakeRelay("fail"), code=1)
    assert state(env)["dwell"][entry(env)["root_event_id"]] ["last"] is None
    assert hours(env, 25, 26) == []  # 22 + 0 + 1
    assert hours(env, 27, 27) == [(27, "notice")]


def test_what_an_interrupted_run_read_about_one_thread_is_kept(env):
    """22 hours held. At hour 24 a complete catalog lists the CVE under another product's
    name (unknown for this thread) in a run that stops at a failed send; at hour 25 it is
    gone again. The read of hour 24 broke the wait although the run never got further."""
    post(env)
    assert hours(env, 1, 23) == []
    env.collector([finding()], name="2026-11-07T000000Z")
    renamed = {**kev_item(CVE), "vendorProject": "Anthropic PBC", "product": "Claude"}
    one(env, 24, (renamed,), relay=FakeRelay("fail"), code=1)
    assert hours(env, 25, 26) == [] and hours(env, 27, 27) == [(27, "notice")]


def test_a_run_that_stopped_after_reading_it_listed_starts_the_wait_over(env):
    post(env)
    assert hours(env, 1, 23) == []
    env.collector([finding()], name="2026-11-07T000000Z")
    one(env, 24, BACK, relay=FakeRelay("fail"), code=1)
    assert state(env)["dwell"] == {}
    assert hours(env, 25, 48) == [] and hours(env, 49, 49) == [(49, "notice")]


def test_a_cached_body_is_direct_only_when_it_is_the_body_that_came_direct():
    """A redirected 200 replaces the cache and the run stops before saying so; the next
    fetch is a 304 for that body. It is not the body this state knows came direct."""
    st = recompute.new_state()
    direct, moved = catalog("v1", CVE), catalog("v2")
    assert recompute.kev_copy(direct, "ok", st, 0, False).complete
    assert recompute.kev_copy(direct, "304", st, 1, None).complete  # the same body, not modified
    assert not recompute.kev_copy(moved, "304", st, 2, None).complete  # a body nobody vouched for
    assert not recompute.kev_copy(moved, "ok", st, 3, True).complete
    assert not recompute.kev_copy(moved, "304", st, 4, None).complete
    assert not recompute.kev_copy(direct, "304", st, 5, None).complete  # the last fetch was not direct
    assert recompute.kev_copy(moved, "ok", st, 6, False).complete
    assert not recompute.kev_copy(direct, "304", recompute.new_state(), 7, None).complete  # a lost state knows nothing


# ---------------------------------------------------------------- the circuit breaker and the digest


def _digest(relay):
    return next(c[2] for c in relay.calls if c[2].startswith("Daily digest"))


def test_many_due_at_once_lower_none_and_the_digest_says_so(env):
    post(env, *FIVE)
    assert hours(env, 1, 26, FIVE[:1]) == []  # four of five due from hour 25
    assert [e["level"] for e in env.ledger()[0]] == ["critical"] * 5
    relay = one(env, 27, FIVE[:1])  # 09:20 Tokyo: the digest goes out
    assert "\n\nLevel check: 4 threads are due to be lowered at once and are held back." in _digest(relay)
    assert "Lowered since" not in _digest(relay)
    assert any("4 件" in text for ch, reply, text in relay.ja)


def test_two_due_at_once_are_lowered_and_listed_in_one_digest_line(env):
    post(env, *FIVE)
    assert hours(env, 1, 26, FIVE[2:]) == [(25, "notice"), (25, "notice")]
    digest = _digest(one(env, 27, FIVE[2:]))
    assert digest.endswith("\n\nLowered since the last digest: CVE-2026-0001 to notice; CVE-2026-0002 to notice.")
    assert "Level check" not in digest
    hours(env, 28, 50, FIVE[2:])
    assert "Lowered since" not in _digest(one(env, 51, FIVE[2:]))  # the next day's: not again


def _crashed_digest(env, reported):
    """Two lowered at hour 25, the digest at hour 27; then the recompute file as a run
    that stopped before clearing the list would have left it."""
    post(env, *FIVE)
    hours(env, 1, 26, FIVE[2:])
    one(env, 27, FIVE[2:])
    st = state(env)
    assert st["lowered"] == [] and st["reported"] is None
    st.update(lowered=[[FIVE[0], "notice"], [FIVE[1], "notice"]], reported=reported)
    recompute.save(env.config.recompute_state, st)
    hours(env, 28, 50, FIVE[2:])
    return _digest(one(env, 51, FIVE[2:]))


def test_a_run_that_stopped_after_journaling_the_digest_does_not_list_them_twice(env):
    assert "Lowered since" not in _crashed_digest(env, "2026-11-06")  # that day's digest went out with them


def test_a_run_that_stopped_before_journaling_the_digest_lists_them_in_the_next(env):
    assert "Lowered since the last digest: CVE-2026-0001" in _crashed_digest(env, "2026-11-30")  # no such digest


def test_the_breakers_share_is_of_the_threads_it_judges(env):
    """Three KEV threads all due beside many other threads in the ledger: three is more
    than two and all of what can be lowered, so none is."""
    post(env, *FIVE[:3])
    env.collector([finding(fid=f"GHSA-aaaa-bbbb-cc{n:02d}") for n in range(20)])
    one(env, 1, FIVE[:3])
    assert len(env.ledger()[0]) == 23
    assert hours(env, 2, 30) == [] and state(env)["tripped"]["due"] == 3


def test_a_trip_seven_days_old_lets_two_a_run_through(env):
    post(env, *FIVE)
    last = 25 + 7 * 24
    assert hours(env, 1, last - 1, FIVE[:1]) == []
    assert hours(env, last, last + 1, FIVE[:1]) == [(last, "notice")] * 2 + [(last + 1, "notice")] * 2
    assert sorted(e["level"] for e in env.ledger()[0]) == ["critical"] + ["notice"] * 4
    assert hours(env, last + 2, last + 2, FIVE[:1]) == [] and state(env)["tripped"] is None


def test_entries_shed_one_an_hour_trip_the_breaker_as_all_at_once_do(env):
    """Four of five KEV entries leave, one each hour. Two are lowered as they fall due; the
    third in a day is more than two and more than a fifth, so it and the fourth wait
    until the first two are a day old."""
    post(env, *FIVE)
    sent = hours(env, 1, 60, lambda h: FIVE[min(h, 4):])
    assert [h for h, _ in sent] == [25, 26, 50, 50]


# ---------------------------------------------------------------- a lowered thread, and the OpenSSH thread


def test_on_a_lowered_thread_a_candidate_raise_travels_alone_before_its_fix(env):
    """spec/wire.md rule 2: a reader that kept the higher level would refuse the raise,
    and with it anything sent in the same reply. And the ledger's exploited mark does
    not raise the thread again: the catalog dropped it."""
    post(env)
    hours(env, 1, 25)
    assert entry(env)["level"] == "notice"
    env.collector([finding(fid=CVE, sources=(GHSA,), fixed="2.1.0", severity="high")], name="2026-11-07T000000Z")
    relay = one(env, 26)
    feed = [text for ch, reply, text in relay.calls if ch == "feed" and reply is not None]
    assert len(feed) == 2 and json.loads(schema._last_block(feed[0])) == {"level": "high"}
    second = json.loads(schema._last_block(feed[1]))
    assert "level" not in second and second["products"][0]["fixed"] == "2.1.0"
    e = entry(env)
    assert e["level"] == "high" and e["advisory"]["products"][0]["fixed"] == "2.1.0" and e["floor"] == "high"
    assert hours(env, 27, 27 + 9 * 24) == []  # the reading holds it: gone from KEV lowers it no further


def test_a_prose_floor_outlives_restarts_and_later_candidates(env):
    """The vendor's page rates the flaw high and CISA lists it: critical, and what a
    reading alone supports is high. Each run is a new process over the ledger file,
    and a later candidate with no severity does not lower the floor. The page's GHSA
    id is one of the thread's ids, and it has no reader yet, so when CISA drops the
    entry this thread is not lowered at all."""
    env.collector([finding(fid=CVE, sources=(GHSA,), fixed="2.1.0", severity="high")])
    post(env)
    (e,) = env.ledger()[0]
    assert e["level"] == "critical" and e["floor"] == "high" and "GHSA-abcd-efgh-ijkl" in e["aliases"]
    env.collector([finding(fid=CVE, sources=(GHSA,), fixed="2.1.0", severity=None)], name="2026-11-06T000000Z")
    assert hours(env, 1, 10 * 24) == []
    assert entry(env)["floor"] == "high" and entry(env)["level"] == "critical" and state(env)["dwell"] == {}


def test_judge_lowers_to_the_floor_and_no_further():
    rs, st, scope = ruleset.load(), recompute.new_state(), next(e for e in schema.load_scope() if e.name == "Claude Code")
    e = _thread(floor="high")
    st["listed"][e.root_event_id] = [CVE]

    def copy(version):
        return recompute.kev_copy(catalog(version), "ok", st, 0)

    assert recompute.judge(e, scope, copy("v1"), rs, st, 0) is None
    assert recompute.judge(e, scope, copy("v1"), rs, st, HOUR) is None
    for h in range(2, 24):
        assert recompute.judge(e, scope, copy("v2"), rs, st, h * HOUR) is None
    assert recompute.judge(e, scope, copy("v2"), rs, st, 24 * HOUR) == ("due", "high")
    held = _thread(level="high", floor="high")
    assert recompute.judge(held, scope, copy("v3"), rs, st, 25 * HOUR) is None and st["dwell"] == {}


OLD_ENTRY_KEYS = {"root_event_id", "channel_ids", "level", "aliases", "posted_at", "last_change", "scope",
                  "exploited", "advisory", "replies", "source_title", "listed_at", "learned_sources"}  # 0.1.7's Entry
OLD_ITEM_KEYS = {"key", "kind", "scope", "ids", "channel", "text", "adv", "exploited", "date", "sent", "root",
                 "ja", "source_title"}


def test_the_rollback_steps_name_every_key_an_older_poster_refuses(env):
    """CHANGELOG: remove ``lowered``, ``changed`` and ``floor`` from every ledger entry and
    ``floor`` from every journal item. After a lowering and a raise, with an unsent root in
    the journal, nothing else is left that 0.1.7 does not know."""
    post(env)
    hours(env, 1, 25)
    env.collector([finding()], name="2026-11-07T000000Z")
    one(env, 26, relay=FakeRelay("fail"), code=1)  # another advisory's root fails to send: it waits in the journal
    items = env.state()["outbox"]
    assert [it.get("floor") for it in items] == ["high"] and all(set(it) - {"floor"} <= OLD_ITEM_KEYS for it in items)
    one(env, 27, BACK)  # the lowered thread is raised
    e = next(e for e in env.ledger()[0] if e["exploited"])
    assert {"lowered", "changed", "floor"} <= set(e) and len(e["changed"]) == 2
    assert all(set(x) - {"lowered", "changed", "floor"} <= OLD_ENTRY_KEYS for x in env.ledger()[0])


def _kev_high():
    data = json.loads((schema.SPEC_DIR / "ruleset.json").read_text())
    data["rules"] = [dict(r, level="high") if r["class"] == "kev" else r for r in data["rules"]]
    return ruleset.Ruleset(data, schema._load_json(schema.SPEC_DIR / "scope.json"), schema.load_scope())


def test_the_openssh_thread_follows_the_rule_with_no_human(env, monkeypatch):
    """CVE-2026-123158, the one critical the service has sent. CISA lists it, so under
    ruleset version 1 it stays critical. Under a rule that gives a KEV entry high
    (ai-tools-alerts#9kgk writes that rule) it is lowered once, after a day of
    complete reads, by the recompute alone."""
    post(env, OPENSSH)
    led = json.loads(env.config.ledger.read_text())
    del led["entries"][0]["floor"]  # the live thread was written before the ledger kept it
    env.config.ledger.write_text(json.dumps(led))
    assert entry(env)["advisory"]["products"][0]["name"] == "OpenSSH"
    assert hours(env, 1, 48, (OPENSSH,)) == [] and entry(env)["level"] == "critical"
    rs = _kev_high()
    monkeypatch.setattr(ruleset, "load", lambda: rs)
    relay = None
    for h in range(49, 74):
        assert h == 73 or replies(relay := one(env, h, (OPENSSH,))) == []
    relay = one(env, 73, (OPENSSH,))
    assert levels(relay) == levels(relay, "critical") == [{"level": "high"}]
    assert entry(env)["level"] == "high"
    assert hours(env, 74, 74 + 9 * 24, (OPENSSH,)) == []


def test_level_report_prints_bare_ids_only():
    text = compose.level_report([["CVE-2026-0001", "notice"], ["CVE-2026-0002:slug", "high"]], None)
    assert text == "\n\nLowered since the last digest: CVE-2026-0001 to notice."
    assert compose.level_report([], None) == "" and compose.level_report([], None, "ja") == ""
    assert "CVE-2026-0001 (注意)" in compose.level_report([["CVE-2026-0001", "notice"]], {"due": 3}, "ja")
