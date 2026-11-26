"""The recompute posts the copy a thread's level lacks (ai-tools-alerts#3t4p): a
feed-only thread it raises to critical gets a root in the critical channel in that
run, with no input record; so does a thread whose copy was dropped. ``main.run`` one
run an hour with the fake relay and advisory API, as ``test_advisory_recompute``."""

import json

import pytest

from aitools_alerts import schema
from aitools_alerts.poster import main
from aitools_alerts.poster.ledger import Ledger

from advisories import ghsa_json
from test_advisory_recompute import G, NO_FIX, WHEN, entries, post, run
from test_main import T0, FakeRelay, env  # noqa: F401  (env is a fixture)
from test_recompute import levels
from test_settle import served, show

HOUR = 3600
MALWARE = dict(type="malware")  # with a patched version: critical by an upgrade


def sent(relay):
    """A run's English sends but the daily digest."""
    return [c for c in relay.calls if not c[2].startswith("Daily digest")]


def roots(relay, channel):
    return [text for ch, reply, text in sent(relay) if ch == channel and reply is None]


def raised(env, relay=None, hour=1):
    """A thread posted at high in feed alone, then one run in which its advisory reads
    as malware: (code, summary, relay) of that run."""
    post(env)
    assert list(entries(env)[0]["channel_ids"]) == ["feed"]
    env.api.put(G, ghsa_json(G, **MALWARE))
    return env.run(now=T0 + hour * HOUR, relay=relay)


def edit(env, change):
    with Ledger(env.config.ledger) as led:
        change(led._state()["entries"][0])
        led._save()


def test_a_feed_only_thread_raised_to_critical_gets_its_copy_in_the_critical_channel(env):
    """Acceptance: a root in the critical channel after that run, with no new input record."""
    records = sorted(p.name for p in env.col.iterdir())
    code, summary, relay = raised(env)
    assert code == 0 and "copies=1" in summary and "replies=1" in summary, summary
    assert [(ch, reply is None) for ch, reply, _ in relay.calls] == [("feed", False), ("critical", True)]
    assert levels(relay) == [{"level": "critical"}]
    (e,) = entries(env)
    (copy,) = roots(relay, "critical")
    assert e["level"] == "critical" and e["channel_ids"] == {"feed": e["root_event_id"], "critical": relay.ids[1]}
    assert schema.parse_post(copy) == schema.validate(e["advisory"])  # the block is the thread's, key for key
    assert copy.split("\n")[:3] == ["CRITICAL: Claude Code: security advisory",
                                    "Affected: `@anthropic-ai/claude-code`, versions not stated (npm).",
                                    "Do: upgrade Claude Code to 2.1.0 or later."]
    (ja,) = relay.ja  # the Japanese reply a copy has, to the copy
    assert ja[0] == "critical" and ja[1] == relay.ids[1] and ja[2].startswith("lang: ja\n\n緊急: Claude Code")
    assert sorted(p.name for p in env.col.iterdir()) == sorted({*records, "2026-11-05T000000Z"})  # post()'s own
    assert sent(run(env, 2)) == [] and not env.state()["outbox"]  # once


def test_a_raise_on_a_thread_with_both_channels_sends_no_copy(env):
    """Acceptance: unchanged. A level-only reply in each channel and nothing else."""
    malware = dict(type="malware", packages=NO_FIX)
    post(env, fixed=None, **malware)
    assert set(entries(env)[0]["channel_ids"]) == {"critical", "feed"}
    env.api.put(G, ghsa_json(G, withdrawn_at=WHEN, **malware))
    for h in range(1, 25):
        run(env, h)
    assert levels(run(env, 25)) == [{"level": "notice"}]
    env.api.put(G, ghsa_json(G, **malware))
    relay = run(env, 26)
    assert all(reply is not None for _, reply, _ in relay.calls) and len(relay.calls) == 2
    assert levels(relay) == levels(relay, "critical") == [{"level": "critical"}]


def test_a_failed_copy_send_is_sent_again_from_the_journal(env):
    """Acceptance: a failed copy send is retried from the journal."""
    code, summary, relay = raised(env, FakeRelay("ok", "fail"))
    assert code == 1 and "failed=1" in summary, summary
    (it,) = env.state()["outbox"]
    assert it["kind"] == "copy" and it["channel"] == "critical" and it["root"] == entries(env)[0]["root_event_id"]
    assert entries(env)[0]["level"] == "critical" and list(entries(env)[0]["channel_ids"]) == ["feed"]
    env.api.put(G, 503)  # nothing read this run: the journal alone sends it
    code, summary, relay = env.run(now=T0 + 2 * HOUR)
    assert code == 0 and roots(relay, "critical") == [it["text"]] and len(relay.calls) == 1, summary
    assert set(entries(env)[0]["channel_ids"]) == {"critical", "feed"} and not env.state()["outbox"]


def test_a_copy_whose_outcome_is_unknown_is_not_planned_twice(env):
    code, summary, relay = raised(env, FakeRelay("ok", "unknown"))
    assert code == 1 and "unknown=1" in summary, summary
    for h in (2, 3):
        code, summary, relay = env.run(now=T0 + h * HOUR)
        assert sent(relay) == [] and [it["kind"] for it in env.state()["outbox"]] == ["copy"], summary


def test_a_refused_copy_is_planned_again_once_it_is_dropped(env):
    """jsje drops a refused copy after three days and says its advisory is planned anew:
    for a copy no candidate stands behind, the recompute is what plans it."""
    code, summary, relay = raised(env, FakeRelay("ok", "refuse"))
    assert code == 0 and "withheld=1" in summary and "copies=0" in summary, summary
    assert [w["items"][0]["kind"] for w in env.state()["withheld"]] == ["copy"]
    days = main.WITHHELD_SECONDS // HOUR
    assert all(sent(run(env, h)) == [] for h in (2, 3, days))  # withheld: its thread is busy
    relay = run(env, days + 2)
    assert len(roots(relay, "critical")) == 1 and len(sent(relay)) == 1
    assert set(entries(env)[0]["channel_ids"]) == {"critical", "feed"} and not env.state()["withheld"]


def test_a_refused_raise_posts_no_copy(env):
    """The copy follows the level the ledger records, never one the relay refused."""
    code, summary, relay = raised(env, FakeRelay("refuse"))
    assert code == 0 and [ch for ch, _, _ in relay.calls] == ["feed"], summary
    assert entries(env)[0]["level"] == "high" and "copies=0" in summary


def test_a_raise_whose_send_failed_gets_its_copy_from_the_next_run(env):
    code, summary, relay = raised(env, FakeRelay("fail"))
    assert code == 1 and [ch for ch, _, _ in relay.calls] == ["feed"] and entries(env)[0]["level"] == "high"
    relay = run(env, 2)
    assert [(ch, reply is None) for ch, reply, _ in relay.calls] == [("feed", False), ("critical", True)]


def test_a_copy_compose_refuses_is_withheld_and_tried_again(env):
    raised(env, FakeRelay("ok", "fail"))
    st = env.state()
    st["outbox"] = []  # the journaled copy gone: only the ledger says what is missing
    env.config.state.write_text(json.dumps(st))
    edit(env, lambda e: e["advisory"].update(actions=[]))  # a critical with no action: 9kgk refuses it
    code, summary, relay = env.run(now=T0 + 2 * HOUR)
    assert code == 0 and "withheld=1" in summary and sent(relay) == [] and not env.state()["outbox"], summary
    edit(env, lambda e: e["advisory"].update(actions=[{"verb": "upgrade", "target": "Claude Code", "value": "2.1.0"}]))
    relay = run(env, 3)
    assert len(roots(relay, "critical")) == 1 and set(entries(env)[0]["channel_ids"]) == {"critical", "feed"}


def lost(env):
    """The raised thread, critical in feed alone, with nothing journaled: only the
    ledger says a copy is missing."""
    raised(env, FakeRelay("ok", "fail"))
    st = env.state()
    st["outbox"] = []
    env.config.state.write_text(json.dumps(st))


def rename(e, name):
    e["scope"] = e["advisory"]["products"][0]["name"] = e["advisory"]["actions"][0]["target"] = name
    e["advisory"]["title"] = e["advisory"]["title"].replace("Claude Code", name)


@pytest.mark.parametrize("name", ["Cursor", "MCP servers and clients"])
def test_a_thread_is_found_by_the_name_it_was_posted_under(env, name):
    """A display name is not always an identity (``scope_of("Cursor")`` is None), and a
    renamed product's thread keeps its former name: both get their copy."""
    lost(env)
    edit(env, lambda e: rename(e, name))
    env.last = run(env, 2)
    (copy,) = roots(env.last, "critical")
    assert copy.startswith(f"CRITICAL: {name}: ") and set(entries(env)[0]["channel_ids"]) == {"critical", "feed"}
    # a former name seven MCP entries share names no one package: never another product's
    assert copy.split("\n")[1] == f"Affected: {name}, versions not stated."
    (ja,) = [t for _, _, t in env.last.ja]
    assert f"影響: {name}（バージョン不明）。" in ja and "mcp-server-git" not in copy + ja


def test_a_withdrawn_advisory_gets_no_copy(env):
    """Never announced again (as the digest): a retracted id gets no root in a new channel."""
    lost(env)
    env.mirror.publish_manifest(retracted=[G.lower()])
    assert all(sent(run(env, h)) == [] for h in (2, 3)) and not env.state()["outbox"]


def test_a_retracted_thread_and_an_expired_advisory_get_no_copy(env):
    """The other two ways an advisory is withdrawn: its thread retracted on the mirror
    (not its id in the manifest), and its block expired."""
    lost(env)
    m = env.mirror
    ev = m.root_post(m.cur_sec, created_at=T0 + 100)  # a curator thread, retracted by a reply
    m.reply(m.cur_sec, ev, "retract\nwrong", created_at=T0 + 200)
    feed = entries(env)[0]["channel_ids"]["feed"]
    edit(env, lambda e: e["channel_ids"].update(feed=ev["id"]))  # the ledger's thread is that one
    assert sent(run(env, 2)) == [] and not env.state()["outbox"]
    edit(env, lambda e: (e["channel_ids"].update(feed=feed), e["advisory"].update(expires_at=T0 + HOUR)))
    assert sent(run(env, 3)) == [] and not env.state()["outbox"]
    edit(env, lambda e: e["advisory"].update(expires_at=None))
    assert len(roots(run(env, 4), "critical")) == 1  # neither: the copy posts


def down(url, timeout=None):
    raise OSError("mirror unreachable")


def test_a_thread_lowered_while_its_copy_was_missing_gets_none(env):
    """The copy follows the level the thread has now: lowered to high before the copy
    could post, it needs no root in the critical channel."""
    lost(env)
    env.api.put(G, ghsa_json(G))  # reviewed again: high
    for h in range(2, 24 * 9):  # the mirror down throughout: no copy can be planned
        assert roots(env.run(now=T0 + h * HOUR, mirror_fetch=down)[2], "critical") == []
    assert entries(env)[0]["level"] == "high"
    assert sent(run(env, 24 * 9)) == [] and list(entries(env)[0]["channel_ids"]) == ["feed"]


def test_no_copy_is_planned_while_the_mirror_cannot_be_read(env):
    lost(env)
    code, summary, relay = env.run(now=T0 + 2 * HOUR, mirror_fetch=down)
    assert code == 0 and sent(relay) == [] and not env.state()["outbox"], summary
    assert len(roots(run(env, 3), "critical")) == 1  # the next run that reads it


def test_an_unknown_copy_the_mirror_shows_is_recorded_and_not_sent_again(env):
    """jsje settles it with no person: the event on the mirror is the copy's delivery."""
    code, summary, relay = raised(env, FakeRelay("ok", "unknown"))
    ev = show(env, relay.calls[1], when=T0 + HOUR + 5)
    code, summary, relay = env.run(now=T0 + 2 * HOUR)
    (e,), pending = env.ledger()
    assert code == 0 and sent(relay) == [] and pending == [] and not env.state()["outbox"], summary
    assert e["channel_ids"]["critical"] == ev["id"] and " settled=delivered:1," in summary
    assert [reply for _, reply, _ in relay.ja] == [ev["id"]]  # its Japanese reply follows
    assert sent(run(env, 3)) == []


@pytest.mark.parametrize("hours, fresh", [(25, True), (73, False)])
def test_an_unknown_copy_the_mirror_never_shows_is_sent_again(env, hours, fresh):
    """After 24 hours with a fresh mirror that lacks it, or 72 hours whatever the mirror says."""
    raised(env, FakeRelay("ok", "unknown"))
    now = T0 + (1 + hours) * HOUR
    stale = served(env, T0)  # a mirror generated long ago proves no absence
    code, summary, relay = env.run(now=now - 2 * HOUR, mirror_fetch=served(env, now - 2 * HOUR - 300) if fresh else stale)
    assert sent(relay) == [] and len(env.ledger()[1]) == 1, summary  # too early: still unknown, nothing new planned
    code, summary, relay = env.run(now=now, mirror_fetch=served(env, now - 300) if fresh else stale)
    assert code == 0 and len(roots(relay, "critical")) == 1 and len(sent(relay)) == 1, summary
    (e,), pending = env.ledger()
    assert set(e["channel_ids"]) == {"critical", "feed"} and pending == [] and not env.state()["outbox"]
    assert " settled=delivered:0,resent:1," in summary


def test_a_synthetic_thread_and_one_out_of_scope_get_no_copy(env):
    lost(env)
    edit(env, lambda e: e.update(scope="No Such Product"))
    assert sent(run(env, 2)) == []
    edit(env, lambda e: (e.update(scope="Claude Code"), e["advisory"].update(id="CVE-2099-0010", aliases=[])))
    code, summary, relay = env.run(now=T0 + 3 * HOUR)
    assert sent(relay) == [] and "withheld=0" in summary  # a reserved id: a synthetic thread takes no update,
    # and none is composed for it


def test_a_thread_with_work_in_flight_gets_no_copy(env):
    """Unit: ``copies`` plans nothing on top of journaled work of the thread."""
    raised(env, FakeRelay("ok", "fail"))
    st = env.state()
    (it,) = st["outbox"]
    it.update(kind="reply", key="reply:Claude Code:x:feed", channel="feed")  # other work of the thread, unsent
    with Ledger(env.config.ledger) as led:
        r = main.Run(T0 + 2 * HOUR, env.config, led, st, {}, None, None)
        r.copies(env.mirror.root, env.mirror.fetch)
        assert st["outbox"] == [it]
        st["outbox"].clear()
        r.enqueue = lambda items, instead=None: st["outbox"].extend(items)
        r.copies(env.mirror.root, env.mirror.fetch)
        assert [(o["kind"], o["channel"], o["key"]) for o in st["outbox"]] == \
            [("copy", "critical", f"copy:Claude Code:{G}:critical")]
