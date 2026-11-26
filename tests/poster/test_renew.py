"""The poster renews the threads whose root carries a claim, and steps down a level no
read has confirmed for 45 days (ai-tools-alerts#gtw9). Through ``main.run`` with the fake
relay, KEV fetch and advisory API, one run a day unless a test says otherwise."""

import json

import pytest

from aitools_alerts import pull, ruleset, schema, wire
from aitools_alerts.poster import compose, main, signer

from advisories import ghsa_json
from test_advisory_recompute import G, WEAK, entries, post
from test_main import T0, FakeKEV, FakeRelay, env, finding, kev_fixed, kev_item  # noqa: F401  (env is a fixture)
from test_recompute import catalog
from test_signer import PutRelay, signing  # noqa: F401  (signing is a fixture)

HOUR, DAY = 3600, 86400
RS = ruleset.load()
BLOCKED = FakeKEV(403)  # the catalog refuses the poster: every read of it is unknown


def day(env, d, kev=None, hours=0, **kw):
    """One run ``d`` days (and ``hours``) after the root; the relay it sent through."""
    code, summary, relay = env.run(now=T0 + d * DAY + hours * HOUR, kev=kev, **kw)
    relay.summary, relay.code = summary, code
    return relay


def renewals(relay):
    """The claim of each renewal a run sent, with its channel."""
    assert all(c[1] is not None for c in relay.calls if c[2] == compose.RENEWAL)  # a reply, always
    return [(c[0], wire.claim_of({"tags": [c.claim]})) for c in relay.calls if c[2] == compose.RENEWAL]


def steps(relay):
    return [c for c in relay.calls if c[2].startswith("Level is now")]


def critical(env, **kw):
    """A KEV critical in both channels, its root and copy claimed at T0."""
    kev_fixed(env)
    relay = day(env, 0, **kw)
    assert [c[0] for c in relay.calls] == ["critical", "feed"] and relay.claims[0] == relay.claims[1]
    return wire.claim_of({"tags": [relay.claims[0]]})


def test_a_renewal_is_one_line_with_no_block():
    text = compose.renewal_post()
    assert text == compose.RENEWAL and pull._patch(text) is None and "```" not in text


def test_a_blocked_source_for_30_days_is_renewed_and_the_alert_stays_critical_on_a_reader(env):
    root = critical(env)
    seen, sent = [(root["confirmed_at"], root["checked_at"])], {}
    for d in range(1, 31):
        relay = day(env, d, kev=BLOCKED)
        assert relay.code == 0 and not steps(relay)
        if renewals(relay):
            sent[d] = renewals(relay)
            assert "renewed=2" in relay.summary
        else:
            assert "renewed" not in relay.summary
        seen += [(c["confirmed_at"], c["checked_at"]) for _, c in renewals(relay)]
        # what a reader of r0ra computes from the claims it has been sent
        assert RS.level_at("critical", seen, T0 + d * DAY) == "critical"
    assert sorted(sent) == [7, 14, 21, 28]  # each when seven days of life were left
    for d, pair in sent.items():
        assert [ch for ch, _ in pair] == ["critical", "feed"]
        for _, c in pair:  # the source's fields as last confirmed; confirmed then, checked now
            assert c == {**root, "checked_at": T0 + d * DAY} and ruleset.check_claim(c, "Claude Code") == "ok"
    (e,) = entries(env)
    assert e["level"] == "critical" and json.loads(e["claim"])["checked_at"] == T0 + 28 * DAY
    assert env.state()["outbox"] == [] and env.ledger()[1] == []  # nothing journaled, nothing pending


def test_a_confirming_source_renews_with_a_new_confirmation_and_never_steps(env):
    critical(env)
    last = None
    for d in range(1, 61):
        relay = day(env, d)
        assert not steps(relay)
        for _, c in renewals(relay):
            assert c["confirmed_at"] == c["checked_at"] == T0 + d * DAY and c["level"] == "critical"
            last = d
    assert last == 56 and entries(env)[0]["level"] == "critical"  # every seven days: day 7, 14, ... 56


def test_45_days_unconfirmed_steps_down_one_level_with_the_reason_then_again_by_the_levels_own_life(env):
    root = critical(env)
    sent = {}
    for d in range(1, 170):
        relay = day(env, d, kev=BLOCKED)
        if steps(relay):
            sent[d] = steps(relay)
        assert d < 44 or not renewals(relay)  # nothing can extend it past the ceiling
    assert sorted(sent) == [44, 73]  # a day before the 45th; then 29 days on, a day before high's 30 run out
    first, second = sent[44], sent[73]
    assert [c[0] for c in first] == ["critical", "feed"]
    assert first[0][2].startswith("Level is now high. No source has confirmed the higher level for 44 days.\n")
    assert json.loads(schema._last_block(first[0][2])) == {"level": "high"}
    claim = wire.claim_of({"tags": [first[0].claim]})
    assert claim == {**root, "checked_at": T0 + 44 * DAY}  # confirmed_at never moves without a confirming read
    assert second[0][2].startswith("Level is now notice. No source has confirmed the higher level for 73 days.\n")
    (e,) = entries(env)
    assert e["level"] == "notice" and e["lowered"] is True


def test_a_step_is_not_sent_a_day_early_and_a_poster_stopped_for_13_days_renews_instead(env):
    root = critical(env)
    relay = day(env, 13, kev=BLOCKED, hours=12)  # life ends in half a day; a renewal extends it to day 27
    assert not steps(relay) and [c for _, c in renewals(relay)] == [{**root, "checked_at": T0 + 13 * DAY + 12 * HOUR}] * 2
    relay = day(env, 43, kev=BLOCKED, hours=23)
    assert not steps(relay)
    relay = day(env, 44, kev=BLOCKED)  # a day before the ceiling
    assert len(steps(relay)) == 2


def test_a_source_that_states_the_stepped_level_confirms_it(env):
    """A high from the advisory's fields; the API fails for 44 days and the thread steps
    to notice. The advisory then reads as a notice: that is the level being kept, so it
    confirms, though the standing claim was of high."""
    post(env)
    (e,) = entries(env)
    assert e["level"] == "high" and json.loads(e["claim"])["level"] == "high"
    env.api.default = lambda i: 503
    del env.api.answers[G]
    for d in range(1, 45):
        relay = day(env, d)
    assert len(steps(relay)) == 1 and entries(env)[0]["level"] == "notice"
    env.api.put(G, ghsa_json(G, **WEAK))
    sent = {}
    for d in range(60, 140):
        relay = day(env, d)
        assert not steps(relay)
        sent.update({d: c for _, c in renewals(relay)})
    # confirmed again: sent at once, by a claim of notice; then when 45 of notice's 90 days are left
    assert sorted(sent) == [60, 105]
    assert sent[60]["level"] == "notice" and sent[60]["confirmed_at"] == sent[60]["checked_at"] == T0 + 60 * DAY
    assert entries(env)[0]["level"] == "notice"


def test_a_reading_too_large_for_a_tag_still_confirms(env, monkeypatch):
    root = critical(env)
    monkeypatch.setattr(main.Run, "_claim", lambda self, readings, ids, scope: None)  # as rules.claim_text past 2048 bytes
    for d in range(1, 60):
        relay = day(env, d)
        assert not steps(relay)
        for _, c in renewals(relay):  # the fields of the last reading that fit, confirmed now
            assert c == {**root, "confirmed_at": T0 + d * DAY, "checked_at": T0 + d * DAY}
    assert json.loads(entries(env)[0]["claim"])["confirmed_at"] == T0 + 56 * DAY


def test_a_thread_whose_root_carries_no_claim_is_never_renewed_or_stepped(env, monkeypatch):
    monkeypatch.setattr(main, "ROOT_CLAIMS", False)  # as every thread posted before this change
    kev_fixed(env)
    day(env, 0)
    monkeypatch.setattr(main, "ROOT_CLAIMS", True)
    for d in list(range(1, 20)) + [44, 45, 100]:
        relay = day(env, d, kev=BLOCKED)
        assert relay.calls == [] and "renewed" not in relay.summary
    assert "claim" not in entries(env)[0] and entries(env)[0]["level"] == "critical"


def test_a_renewal_the_relay_did_not_take_is_sent_by_the_next_run(env):
    critical(env)
    before = entries(env)[0]["claim"]
    relay = day(env, 7, hours=23, relay=FakeRelay("ok", "fail"))  # the critical channel took it, the feed did not
    assert relay.code == 0 and relay.summary.endswith(" renewed=1/1")
    assert entries(env)[0]["claim"] == before and env.ledger()[1] == [] and env.state()["outbox"] == []
    relay = day(env, 8, hours=1, relay=FakeRelay("unknown"))
    assert relay.summary.endswith(" renewed=0/1") and entries(env)[0]["claim"] == before
    relay = day(env, 8, hours=2)
    assert [ch for ch, _ in renewals(relay)] == ["critical", "feed"]  # both again: a renewal twice is harmless
    assert json.loads(entries(env)[0]["claim"])["checked_at"] == T0 + 8 * DAY + 2 * HOUR
    assert not renewals(day(env, 8, hours=3))


def test_a_thread_whose_renewal_keeps_failing_does_not_keep_another_unrenewed(env):
    env.kev.catalog = {"vulnerabilities": [kev_item(), kev_item("CVE-2026-0002")]}
    env.collector([finding(fid=i["cveID"], fixed="2.1.0") for i in env.kev.catalog["vulnerabilities"]])
    day(env, 0)
    a, b = entries(env)
    bad = set(a["channel_ids"].values())

    class Picky(FakeRelay):
        def __call__(self, channel_id, text, reply_to=None, claim=None):
            self.queue = ["fail"] if reply_to in bad else []
            return super().__call__(channel_id, text, reply_to, claim)
    done = set()
    for h in range(4):  # day 15: the critical's renewal is overdue and the high's is due
        relay = day(env, 15, hours=h, relay=Picky())
        done |= {c[1] for c in relay.calls if c[2] == compose.RENEWAL and c[1] not in bad}
    assert a["level"] == "critical" and b["level"] == "high" and done == set(b["channel_ids"].values())
    assert json.loads(entries(env)[1]["claim"])["checked_at"] >= T0 + 15 * DAY


def test_a_thread_the_poster_could_not_renew_is_left_out_of_the_checkpoint(signing, monkeypatch):
    env = signing
    critical(env, relay=PutRelay())
    roots = set(entries(env)[0]["channel_ids"].values())
    seen = []
    real = signer.run_checkpoint
    monkeypatch.setattr(signer, "run_checkpoint", lambda *a, **k: (seen.append(set(k["suppress"])), real(*a, **k))[1])
    day(env, 8, relay=PutRelay("fail"))  # six days of life left: still vouched for
    assert seen[-1] == set()
    day(env, 13, hours=23, relay=PutRelay("fail"))  # an hour left, and the renewal was not delivered
    assert seen[-1] == roots
    day(env, 14, relay=PutRelay())
    assert seen[-1] == set()


def test_after_the_checkpoint_state_is_lost_every_enrolled_thread_is_renewed_once(signing):
    env = signing
    critical(env, relay=PutRelay())
    relay = day(env, 1, relay=PutRelay())
    assert not renewals(relay)
    env.config.owed_state.unlink()  # what the relay acknowledged is no longer known
    relay = day(env, 1, hours=1, relay=PutRelay())
    assert [ch for ch, _ in renewals(relay)] == ["critical", "feed"] and "checkpoint=held" in relay.summary
    owed = signer.load_owed(env.config.owed_state, T0 + DAY + HOUR)["owed"]
    assert len(owed) == 2 and all(o["renewal"] == [T0 + DAY + HOUR] * 2 for o in owed)
    assert not renewals(day(env, 1, hours=2, relay=PutRelay()))


def test_a_step_down_that_could_not_be_sent_keeps_its_roots_out_of_the_checkpoint(signing, monkeypatch):
    env = signing
    critical(env, relay=PutRelay())
    e = entries(env)[0]
    seen = []
    real = signer.run_checkpoint
    monkeypatch.setattr(signer, "run_checkpoint", lambda *a, **k: (seen.append(set(k["suppress"])), real(*a, **k))[1])
    relay = day(env, 44, kev=BLOCKED, relay=PutRelay("fail"))  # the relay took neither channel's reply
    assert relay.code == 1 and entries(env)[0]["level"] == "critical"
    assert seen[-1] == set(e["channel_ids"].values())
    relay = day(env, 44, kev=BLOCKED, hours=1, relay=PutRelay("ok", "fail"))  # the critical channel's only
    assert entries(env)[0]["level"] == "high" and seen[-1] == {e["channel_ids"]["feed"]}
    relay = day(env, 44, kev=BLOCKED, hours=2, relay=PutRelay())
    assert [c[0] for c in steps(relay)] == ["feed"] and seen[-1] == set()


def test_a_level_change_recorded_by_a_later_run_counts_from_its_attempt(env):
    """The reader counts a level reply from the event's date. A reply whose outcome was
    unknown and that the mirror shows two days later is recorded then; the ledger's
    ``changed`` still says when it was sent, so the poster's life is not two days long."""
    from test_settle import show
    critical(env)
    relay = day(env, 44, kev=BLOCKED, relay=FakeRelay("unknown"))
    assert relay.code == 1 and len(steps(relay)) == 1
    show(env, relay.calls[0], when=T0 + 44 * DAY + 5)
    relay = day(env, 46, kev=BLOCKED)
    (e,) = entries(env)
    assert e["level"] == "high" and e["changed"][-1] == T0 + 44 * DAY
    assert "settled=delivered:1" in relay.summary and [c[0] for c in steps(relay)] == ["feed"]


def test_a_renewal_names_only_an_id_the_first_root_stated(env):
    """A later reply brings the thread an alias and a higher level. The standing claim
    stays one about the root's id: a reader that lacks that reply still counts every renewal."""
    post(env)
    (e,) = entries(env)
    assert e["root_ids"] == [G] and json.loads(e["claim"])["id"] == G
    for d in range(1, 40):
        for _, c in renewals(day(env, d)):
            assert c["id"] == G
    assert json.loads(entries(env)[0]["claim"])["confirmed_at"] == T0 + 30 * DAY


def test_a_claim_about_an_alias_a_later_reply_brought_never_becomes_the_standing_claim(env):
    """The root states one id. A candidate later brings the CVE, which KEV lists: the
    raise's claim is about the CVE. A reader that lacks that reply does not hold the
    CVE, so the standing claim, and each renewal, stays about the root's own id."""
    from test_advisory_recompute import CVE
    post(env)
    assert entries(env)[0]["root_ids"] == [G]
    env.api.put(G, ghsa_json(G, cve=CVE))
    env.kev.catalog = catalog("v1", CVE)
    env.collector([finding(fid=CVE, fixed="2.1.0", aliases=(G,))], name="2026-11-07T000000Z")
    relay = day(env, 1)
    raised = [wire.claim_of({"tags": [c.claim]}) for c in relay.calls if c[1] and c.claim and c[2] != compose.RENEWAL]
    (e,) = entries(env)
    assert e["level"] == "critical" and raised and all(c["id"] == CVE for c in raised)
    assert e["root_ids"] == [G] and json.loads(e["claim"])["id"] == G
    seen = [c for d in range(2, 20) for _, c in renewals(day(env, d))]
    assert seen and all(c["id"] == G for c in seen)


def test_a_confirmation_between_two_renewals_is_sent_at_once(env):
    root = critical(env)
    for d in range(1, 37):
        day(env, d, kev=BLOCKED)
    relay = day(env, 37)  # eight days of life left: not due by time, but the source answers again
    assert [c["confirmed_at"] for _, c in renewals(relay)] == [T0 + 37 * DAY] * 2
    for d in range(38, 50):
        assert not steps(day(env, d, kev=BLOCKED))  # 45 days count from day 37 now
    assert root["confirmed_at"] == T0


def test_a_renewal_pass_that_raises_costs_the_run_its_exit_code_and_nothing_else(env, monkeypatch):
    env.collector([finding()])
    monkeypatch.setattr(main.Run, "_renew", lambda self: (_ for _ in ()).throw(RuntimeError("boom")))
    code, summary, relay = env.run()
    assert code == 1 and "error=" not in summary and len(relay.calls) == 1
    assert env.state()["outbox"] == [] and len(entries(env)) == 1  # the root is recorded and the state saved
    monkeypatch.undo()
    code, summary, relay = env.run(now=T0 + HOUR)
    assert code == 0 and relay.calls == []  # nothing is sent again
