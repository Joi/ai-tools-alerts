"""The claim travels in the event tag of the level changes the poster sends, and of its
roots (``main.ROOT_CLAIMS``, on since ai-tools-alerts#gtw9; ai-tools-alerts#hh5s). Through ``main.run`` with
the fake relay, which records the claim tag each send was given (``relay.claims``)."""

import json

import pytest

from aitools_alerts import ruleset, schema, wire
from aitools_alerts.poster import inputs, main, signer

from advisories import ghsa_json
from test_advisory_recompute import (CVE, G, NO_FIX, WEAK, WHEN, entries, post, run)
from test_main import CHANNELS, T0, FakeRelay, env, finding, kev_fixed, kev_item  # noqa: F401  (env is a fixture)
from test_recompute import catalog, levels
from test_signer import PutRelay, signing  # noqa: F401  (signing is a fixture)

HOUR = 3600
CC = "Claude Code"


@pytest.fixture
def roots_on(monkeypatch):
    """As shipped since ai-tools-alerts#gtw9: a root and its copies carry their claim."""
    monkeypatch.setattr(main, "ROOT_CLAIMS", True)


def claim(tag, at, level=None, source=None):
    """The claim a recorded tag carries, checked: one canonical tag that the offline
    check accepts for the product, confirmed and checked at the run's time."""
    assert isinstance(tag, list) and tag[0] == wire.CLAIM_TAG and len(tag) == 2, tag
    obj = wire.claim_of({"tags": [tag]})
    assert obj is not None and wire.claim_tag(obj) == tag
    assert ruleset.check_claim(obj, CC) == "ok"
    assert obj["confirmed_at"] == obj["checked_at"] == at
    assert level is None or obj["level"] == level, obj
    assert source is None or obj["source"] == source, obj
    return obj


def level_claims(relay):
    """The claim tag of each level-only reply a run sent, in order."""
    return [c for (ch, reply, text), c in zip(relay.calls, relay.claims)
            if reply is not None and text.startswith("Level is now")]


# ---------------------------------------------------------------- roots and copies


def test_with_root_claims_off_a_root_and_its_copy_carry_no_claim_and_the_thread_has_none(env, monkeypatch):
    monkeypatch.setattr(main, "ROOT_CLAIMS", False)  # as every thread posted before gtw9
    kev_fixed(env)
    code, summary, relay = env.run()
    assert code == 0 and [c[0] for c in relay.calls] == ["critical", "feed"]
    assert relay.claims == [None, None]
    assert all("claim" not in it for it in env.state()["outbox"]) and "claim" not in env.ledger()[0][0]


def test_as_shipped_a_root_and_its_copy_carry_the_claim_and_the_ledger_keeps_it(env):
    kev_fixed(env)
    code, summary, relay = env.run()
    assert code == 0 and relay.claims[0] == relay.claims[1] and claim(relay.claims[0], T0, "critical", "kev")
    assert env.ledger()[0][0]["claim"] == relay.claims[0][1]


def test_with_root_claims_on_a_root_and_its_copy_carry_one_claim(env, roots_on):
    kev_fixed(env)
    code, summary, relay = env.run()
    assert code == 0 and [c[0] for c in relay.calls] == ["critical", "feed"]
    assert relay.claims[0] == relay.claims[1]
    obj = claim(relay.claims[0], T0, "critical", "kev")
    assert obj["id"] == "CVE-2026-0001" == env.ledger()[0][0]["advisory"]["id"]


def test_with_root_claims_on_a_ghsa_root_claims_the_api_reading(env, roots_on):
    relay = post(env)
    obj = claim(relay.claims[0], T0, "high", "ghsa")
    assert obj["id"] == G and obj["fields"] == env_reading(env, G)


def env_reading(env, i):
    from aitools_alerts import verify
    return verify._ghsa_reading(env.api.answers[i], i)[0]


def test_a_root_with_no_reading_carries_no_claim_and_a_three_argument_sender_serves(env, roots_on):
    env.api.default = lambda i: 404  # the API gives nothing: the candidate posts by its page, with no reading
    env.collector([finding()])
    sent = []

    def sender(channel_id, text, reply_to):  # a sender that knows no claim
        sent.append(text)
        return FakeRelay()(channel_id, text, reply_to)
    code, summary, _ = env.run(relay=sender)
    assert code == 0 and len([t for t in sent if not t.startswith("lang: ja")]) == 1, summary


def test_a_reading_too_large_posts_without_a_claim(env, roots_on, capsys):
    many = [("npm", "@anthropic-ai/claude-code", "< 2.1.0", "2.1.0"),
            *(("npm", f"some-other-package-number-{n:03d}", "< 1.0.0", "1.0.0") for n in range(40))]
    relay = post(env, packages=many)
    (e,) = entries(env)
    assert e["level"] == "high" and relay.claims == [None]
    assert "larger than 2048 bytes; sent without one" in capsys.readouterr().err
    relay = post(env, fid="GHSA-mnop-qrst-uvwx", fixed="2.2.0", at=1, packages=many[:3])
    assert len(claim(relay.claims[0], T0 + HOUR, "high")["fields"]["packages"]) == 3


def test_a_claimed_root_that_failed_is_sent_again_with_the_same_claim(env, roots_on):
    env.api.put(G, ghsa_json(G))
    env.collector([finding(fid=G, severity="moderate")])
    code, _, first = env.run(relay=FakeRelay("fail"))
    assert code == 1 and len(first.claims) == 1
    (it,) = env.state()["outbox"]
    assert ["claim", it["claim"]] == first.claims[0]
    code, _, again = env.run(now=T0 + HOUR)
    assert code == 0 and again.claims[0] == first.claims[0]  # what was read at T0, not a claim of this run
    claim(again.claims[0], T0, "high")


# ---------------------------------------------------------------- level changes


def test_the_recomputes_lowering_carries_the_reading_it_rests_on(env):
    post(env)
    env.api.put(G, ghsa_json(G, **WEAK))
    for h in range(1, 25):
        assert level_claims(run(env, h)) == []
    relay = run(env, 25)
    assert levels(relay) == [{"level": "notice"}]
    (tag,) = level_claims(relay)
    obj = claim(tag, T0 + 25 * HOUR, "notice", "ghsa")
    assert obj["id"] == G and obj["fields"] == env_reading(env, G) and obj["fields"]["cwes"] == []


def test_a_withdrawal_and_the_raise_after_it_each_carry_their_claim_in_every_channel(env):
    malware = dict(type="malware", packages=NO_FIX)
    post(env, fixed=None, **malware)
    env.api.put(G, ghsa_json(G, withdrawn_at=WHEN, **malware))
    for h in range(1, 25):
        run(env, h)
    relay = run(env, 25)
    assert levels(relay) == levels(relay, "critical") == [{"level": "notice"}]
    a, b = level_claims(relay)
    assert a == b and claim(a, T0 + 25 * HOUR, "none")["fields"]["withdrawn_at"] == WHEN  # true, and no renewal to a reader
    env.api.put(G, ghsa_json(G, **malware))
    relay = run(env, 26)
    assert levels(relay) == levels(relay, "critical") == [{"level": "critical"}]
    a, b = level_claims(relay)
    assert a == b and claim(a, T0 + 26 * HOUR, "critical")["fields"]["type"] == "malware"


def test_a_lowering_that_rests_on_an_absence_carries_no_claim_and_the_raise_back_claims_kev(env, monkeypatch):
    import test_recompute as tr
    real = main.Run.admit  # test_recompute's fixture: an admitted KEV candidate states its fix
    monkeypatch.setattr(main.Run, "admit", lambda self, c, scope: (
        lambda a: main.replace(a, fixed=a.fixed or "2.1.0") if a is not None and a.exploited is True else a)(
            real(self, c, scope)))
    tr.post(env)
    for h in range(1, 25):
        assert level_claims(tr.one(env, h)) == []
    relay = tr.one(env, 25)  # the CVE has left a complete catalog for 24 hours: no fields state that
    assert levels(relay) == [{"level": "notice"}] and level_claims(relay) == [None, None]
    relay = tr.one(env, 26, tr.BACK)
    assert levels(relay) == [{"level": "critical"}]
    a, b = level_claims(relay)
    assert a == b and claim(a, T0 + 26 * HOUR, "critical", "kev")["fields"] == {"cve_id": CVE, "name": "Anthropic Claude Code"}


def raised_thread(env):
    """A thread at high whose advisory names the CVE, as its page does."""
    env.api.put(G, ghsa_json(G, cve=CVE))
    env.collector([finding(fid=G, severity="moderate", aliases=(CVE,))])
    return run(env, 0)


def test_a_raise_a_candidate_brings_carries_the_claim_and_a_later_fix_reply_carries_none(env):
    raised_thread(env)
    (e,) = entries(env)
    assert e["level"] == "high" and CVE in e["advisory"]["aliases"]
    env.kev.catalog = catalog("v1", CVE)
    env.collector([finding(fid=CVE, fixed="2.1.0", aliases=(G,))])
    relay = run(env, 1)
    raised = [(text, c) for (ch, reply, text), c in zip(relay.calls, relay.claims) if reply is not None]
    assert entries(env)[0]["level"] == "critical" and raised
    for text, c in raised:
        assert json.loads(schema._last_block(text))["level"] == "critical"
        obj = claim(c, T0 + HOUR, "critical", "kev")
        assert obj["id"] == CVE
    copies = [c for (ch, reply, text), c in zip(relay.calls, relay.claims) if reply is None]
    assert len(copies) == 1 and claim(copies[0], T0 + HOUR, "critical", "kev")  # a root there: enrolled as the first
    env.collector([finding(fid=G, severity="moderate", fixed="2.2.0")])
    relay = run(env, 2)
    later = [c for (ch, reply, text), c in zip(relay.calls, relay.claims) if reply is not None]
    assert later and all(c is None for c in later)  # a fix is no level change


def test_with_root_claims_on_a_copy_a_raise_adds_carries_the_claim(env, roots_on):
    raised_thread(env)
    env.kev.catalog = catalog("v1", CVE)
    env.collector([finding(fid=CVE, fixed="2.1.0", aliases=(G,))])
    relay = run(env, 1)
    (copy,) = [c for (ch, reply, text), c in zip(relay.calls, relay.claims) if reply is None]
    claim(copy, T0 + HOUR, "critical", "kev")


# ---------------------------------------------------------------- the journal and the checkpoint


def item(**over):
    base = {"key": "reply:Claude Code:GHSA-abcd-efgh-ijkl#level:feed", "kind": "reply", "scope": CC, "ids": [G],
            "channel": "feed", "text": "Level is now notice.", "adv": None, "exploited": False, "date": None,
            "sent": None, "root": "a" * 64}
    adv = {"id": G, "aliases": [], "level": "notice", "advisory_severity": None, "title": "t",
           "products": [{"name": CC, "ecosystem": "claude-code", "affected": None, "fixed": "2.1.0"}],
           "actions": [], "sources": [{"url": "https://github.com/advisories/" + G, "published_at": None}],
           "posted_by": "relay-bot", "posted_at": 1, "expires_at": None}
    return {**base, "adv": adv, **over}


def test_a_journal_item_takes_only_a_canonical_claim():
    vector = json.loads((schema.SPEC_DIR / "claim-vectors.json").read_text(encoding="utf-8"))["claims"][0]
    text = vector["canonical"]
    assert inputs._item_ok(item()) and inputs._item_ok(item(claim=text))  # before this change, and after
    for bad in ("", None, 7, "{}x", '{"b":1, "a":2}', '{"b":1,"a":2}', "[]", json.dumps({"a": "x" * 2100}), ["claim", text]):
        assert not inputs._item_ok(item(claim=bad)), bad
    ja = item(kind="ja", adv=None, key="reply:x:ja")
    assert inputs._item_ok(ja) and not inputs._item_ok({**ja, "claim": text})


def test_the_owed_bytes_cover_the_claim(signing):  # noqa: F811
    env = signing  # noqa: F811
    env.api.put(G, ghsa_json(G))
    env.collector([finding(fid=G, severity="moderate")])
    run(env, 0, relay=PutRelay())
    env.api.put(G, ghsa_json(G, **WEAK))
    for h in range(1, 25):
        run(env, h, relay=PutRelay())
    relay = PutRelay()
    run(env, 25, relay=relay)
    (tag,) = level_claims(relay)
    text = next(t for ch, reply, t in relay.calls if t.startswith("Level is now"))
    owed = signer.load_owed(env.config.owed_state, T0)["owed"]
    assert len(text.encode()) + wire.tag_bytes(tag) + signer.ENVELOPE in [o["bytes"] for o in owed]
    assert wire.tag_bytes(tag) > len(tag[1])  # its quotes are escaped in a channel file


# ---------------------------------------------------------------- a lowered thread: the level travels alone


def lowered(env, start):
    """``start(env)`` posts a thread at high; its advisory then weakens and it is lowered to notice."""
    import test_recompute as tr
    start(env)
    env.api.put(G, {**env.api.answers[G], "cwes": []})
    for h in range(1, 26):
        relay = tr.one(env, h)
    assert levels(relay) == [{"level": "notice"}] and entries(env)[0]["lowered"] is True
    return tr


def test_a_level_change_on_a_lowered_thread_travels_alone_with_its_claim(env):
    tr = lowered(env, raised_thread)
    env.collector([finding(fid=CVE, fixed="2.1.0", aliases=(G,))])
    relay = tr.one(env, 26, tr.BACK)  # KEV lists the CVE the thread has published
    assert levels(relay) == [{"level": "critical"}]
    claim(level_claims(relay)[0], T0 + 26 * HOUR, "critical", "kev")
    others = [c for (ch, reply, text), c in zip(relay.calls, relay.claims)
              if reply is not None and not text.startswith("Level is now")]
    assert all(c is None for c in others)


def test_a_level_only_raise_claims_no_id_the_thread_has_not_published(env):
    tr = lowered(env, post)  # the thread publishes its GHSA id alone
    env.collector([finding(fid=CVE, fixed="2.1.0", aliases=(G,))])
    relay = tr.one(env, 26, tr.BACK)  # the raise rests on KEV's entry for a CVE the thread has not published
    assert levels(relay) == [{"level": "critical"}]
    # The level reply publishes no alias, and the reply that would may never be sent: its
    # claim is chosen among the ids published before it, so KEV's reading is not it.
    for tag in level_claims(relay):
        assert tag is None or claim(tag, T0 + 26 * HOUR)["id"] == G
    assert level_claims(relay)


# ---------------------------------------------------------------- which claim (rules.claim_text)


def reading(i=G, **api):
    from aitools_alerts import verify
    return ("ghsa", verify._ghsa_reading(ghsa_json(i, **api), i)[0])


KEV = ("kev", {"cve_id": CVE, "name": "Anthropic Claude Code"})


def text_of(readings, ids, **kw):
    from aitools_alerts.poster import rules
    text = rules.claim_text(readings, ids, CC, 1000, **kw)
    return None if text is None else json.loads(text)


def test_claim_text_takes_the_highest_reading_of_the_threads_ids():
    assert text_of([reading(), KEV], [G, CVE])["id"] == CVE  # critical over high: what the level rests on
    assert text_of([KEV, reading()], [G, CVE])["id"] == CVE
    got = text_of([reading()], [G, CVE])
    assert (got["id"], got["level"], got["confirmed_at"], got["checked_at"]) == (G, "high", 1000, 1000)
    assert ruleset.check_claim(got, CC) == "ok"


def test_claim_text_prefers_the_first_id_on_a_tie():
    g2 = "GHSA-mnop-qrst-uvwx"
    for order in ([reading(), reading(g2)], [reading(g2), reading()]):
        assert text_of(order, [g2, G])["id"] == g2 and text_of(order, [G, g2])["id"] == G


def test_claim_text_ignores_a_reading_of_an_id_the_thread_does_not_carry():
    assert text_of([KEV], [G]) is None and text_of([], [G]) is None
    assert text_of([KEV, reading()], [G])["id"] == G
    assert text_of([reading()], ["LEAD-162d5e0f15f7", None, 7]) is None


def test_claim_text_reads_a_thread_key_and_states_a_withdrawal():
    assert text_of([reading()], ["GHSA-ABCD-efgh-ijkl:claude-code"])["id"] == G
    gone = text_of([reading(withdrawn_at=WHEN)], [G])
    assert gone["level"] == "none" and ruleset.check_claim(gone, CC) == "ok"


def test_claim_text_gives_none_for_a_reading_too_large_and_never_raises():
    many = [("npm", "@anthropic-ai/claude-code", "< 2.1.0", "2.1.0"),
            *(("npm", f"some-other-package-number-{n:03d}", "< 1.0.0", "1.0.0") for n in range(40))]
    big = reading(packages=many)
    assert text_of([big], [G]) is None and text_of([big], [G], limit=False)["id"] == G
    assert text_of([big, KEV], [G, CVE])["id"] == CVE  # the higher reading is the claim; it fits
    assert text_of([big, reading("GHSA-mnop-qrst-uvwx", cwes=())], [G, "GHSA-mnop-qrst-uvwx"]) is None  # no lesser one in its place
    for bad in ([("ghsa", {"ghsa_id": G})], [("nvd", {})], [("kev", None)], [None], None):
        assert text_of(bad, [G, CVE]) is None


# ---------------------------------------------------------------- the recompute's readings


def test_support_hands_back_the_readings_it_counted():
    from aitools_alerts.poster import recompute
    from test_advisory_recompute import CLAUDE, RS, reads, thread
    from test_recompute import kc

    def counted(entry, read, cat=None):
        out = []
        copy = kc(cat, "ok", recompute.new_state(), 0) if cat else None
        recompute.support(entry, CLAUDE, copy, RS, read, out)
        return out
    assert counted(thread(), reads(**{G: ghsa_json(G)})) == [reading()]
    assert counted(thread(), reads(**{G: ghsa_json(G, withdrawn_at=WHEN)})) == [reading(withdrawn_at=WHEN)]
    assert counted(thread(), reads(**{G: 404})) == [] == counted(thread(), None)
    unreviewed = ghsa_json(G, type="unreviewed", repo=None)  # cannot lower: not counted
    assert counted(thread(), reads(**{G: unreviewed})) == []
    both = counted(thread((CVE, G), exploited=True), reads(**{G: ghsa_json(G, cve=CVE)}), catalog("v", CVE))
    assert sorted(both, key=lambda r: r[0]) == [reading(cve=CVE), KEV]
    assert counted(thread((CVE, G)), reads(**{G: ghsa_json(G)}), catalog("v", CVE)) == [KEV]  # an untied advisory
    info = {}
    recompute.judge(thread(), CLAUDE, None, RS, recompute.new_state(), 0, reads(**{G: ghsa_json(G)}), info)
    assert info["readings"] == [reading()]


def test_a_claim_names_only_ids_every_channel_of_the_thread_was_sent():
    """The ledger keeps one advisory for a thread in two channels. A reply one channel
    took and the other refused for good, or a copy added after a reply, leaves the
    channels apart: an alias may then be unknown to one of them, and a level reply,
    which states no alias, is sent to both. Only the first id is claimed then."""
    from test_advisory_recompute import thread
    adv = schema.validate(thread((G, CVE)).advisory)
    both = {"feed": "a" * 64, "critical": "b" * 64}
    from dataclasses import replace
    even = replace(thread((G, CVE)), channel_ids=both, replies=[{"critical": "c" * 64}, {"feed": "d" * 64}])
    apart = replace(thread((G, CVE)), channel_ids=both, replies=[{"critical": "c" * 64}])
    assert main.Run._stated(thread((G, CVE)), adv) == [G, CVE] == main.Run._stated(even, adv)
    assert main.Run._stated(apart, adv) == [G]
    assert main.Run._stated(apart, adv, [CVE]) == [G, CVE]  # an alias this very reply states
    assert text_of([KEV, reading()], main.Run._stated(apart, adv))["id"] == G  # KEV's reading is not claimed
    assert text_of([KEV], main.Run._stated(apart, adv)) is None


def test_the_recomputes_claim_names_no_id_the_ledger_knows_and_no_reply_published(env):
    """The ledger's identity set can hold an id no post has stated (``add_ids``), and
    the recompute reads it. Its claim is still chosen among the published ids."""
    import test_recompute as tr
    from aitools_alerts.poster.ledger import Ledger
    post(env)
    root = entries(env)[0]["root_event_id"]
    with Ledger(env.config.ledger) as led:
        led.add_ids(root, [CVE])
    env.api.put(G, ghsa_json(G, cve=CVE))  # the advisory now names the CVE; no reply has said so
    old = {**kev_item(CVE), "dateAdded": "2026-09-01"}  # before the watermark: no candidate, only the recompute
    relay = tr.one(env, 1, (old,))
    assert levels(relay) == [{"level": "critical"}] and CVE not in entries(env)[0]["advisory"]["aliases"]
    (tag,) = level_claims(relay)
    assert claim(tag, T0 + HOUR, "high", "ghsa")["id"] == G  # not KEV's reading of the unpublished CVE


def test_an_unknown_claimed_level_reply_is_settled_only_by_an_event_with_its_claim(env):
    from test_settle import show
    post(env)
    env.api.put(G, ghsa_json(G, **WEAK))
    for h in range(1, 25):
        run(env, h)
    code, summary, relay = env.run(now=T0 + 25 * HOUR, relay=FakeRelay("unknown"))
    assert code == 1 and relay.claims[0] is not None and relay.calls[0][1] is not None
    show(env, relay.calls[0], when=T0 + 25 * HOUR + 5, claim=None)  # the same text in the thread, with no claim: another event
    code, summary, again = env.run(now=T0 + 26 * HOUR)
    assert "settled" not in summary and again.calls == [] and entries(env)[0]["level"] == "high"
    ev = show(env, relay.calls[0], when=T0 + 25 * HOUR + 6, claim=relay.claims[0])
    code, summary, again = env.run(now=T0 + 27 * HOUR)
    assert "settled=delivered:1" in summary and entries(env)[0]["level"] == "notice"
    assert ev["id"] in [i for r in entries(env)[0]["replies"] for i in r.values()]
