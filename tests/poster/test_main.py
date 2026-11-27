"""The hourly poster run (Task B4). Fake relay, fake KEV fetch, fake source fetch: no network."""

import datetime as dt
import itertools
import json
from dataclasses import replace

import pytest

from aitools_alerts import schema
from pathlib import Path

from aitools_alerts.poster import inputs, main, transport
from mirror_helpers import Mirror, advisory
from advisories import Api, ghsa_json, plain
from pages import Pages, advisory_page
from aitools_alerts.poster.ledger import Ledger, LedgerError

CHANNELS = {"feed": "599adb9f-4f9f-4b19-aee3-66667c3293e8",
            "critical": "ac446e7a-1e2c-4d74-ac8d-9c16ecb3801b"}
NAME = {v: k for k, v in CHANNELS.items()}
GHSA = "https://github.com/anthropics/claude-code/security/advisories/GHSA-abcd-efgh-ijkl"
GHSA2 = "https://github.com/anthropics/claude-code/security/advisories/GHSA-mnop-qrst-uvwx"
APPLE = "https://cursor.com/security/advisory-120001"  # a channel vendor's own page (wa6n: macOS is out)
TOKYO = dt.timezone(dt.timedelta(hours=9))
_EVENT_IDS = (f"{i:064x}" for i in itertools.count(1))  # unique across every FakeRelay in a test


def at(day, hour, minute=20):
    return int(dt.datetime(2026, 11, day, hour, minute, tzinfo=TOKYO).timestamp())


T0 = at(5, 6)  # 06:20 Tokyo: runs a few hours later stay before the digest hour


class Call(tuple):
    """One English or Japanese send as (channel, reply_to, text); ``claim`` is the tag it was given."""
    claim = None


class FakeRelay:
    """``send(channel_id, text, reply_to)`` answering from a queue: ok, fail (certainly
    not stored), unknown (may be stored), refuse (the relay rejected the event itself,
    ai-tools-alerts#8acj). Japanese ``lang: ja`` replies go to ``ja`` and answer from
    ``ja_queue`` (default ok)."""

    def __init__(self, *outcomes, ja=()):
        self.queue, self.ja_queue = list(outcomes), list(ja)
        self.calls, self.ja = [], []
        self.claims = []  # hh5s: the claim tag each English send was given (None: none), as ``calls``

    def __call__(self, channel_id, text, reply_to=None, claim=None):
        transport.check_send(channel_id, text, reply_to, claim)  # what the real sender checks first
        ch = NAME[channel_id]
        is_ja = text.startswith("lang: ja\n")
        call = Call((ch, reply_to, text))
        call.claim = claim
        (self.ja if is_ja else self.calls).append(call)
        if not is_ja:
            self.claims.append(claim)
        queue = self.ja_queue if is_ja else self.queue
        outcome = queue.pop(0) if queue else "ok"
        if outcome == "unknown":
            return transport.SendResult(False, None, None, "no response before the deadline", "unknown")
        if outcome == "fail":
            return transport.SendResult(False, None, 429, "429", "failed")
        if outcome == "refuse":
            msg = "relay error: blocked mention"
            return transport.SendResult(False, None, 400, msg, "refused", msg)
        eid = next(_EVENT_IDS)
        if not is_ja:
            self.ids = getattr(self, "ids", []) + [eid]  # event ids of the English sends, in order
        return transport.SendResult(True, eid, 200, "", "ok")


class FakeKEV:
    def __init__(self, status=200, catalog=None):
        self.status, self.catalog = status, catalog or {"vulnerabilities": []}
        self.headers = []

    def __call__(self, url, headers):
        self.headers.append(dict(headers))
        if self.status != 200:
            return self.status, {}, b""
        return 200, {"Last-Modified": "Wed, 04 Nov 2026 12:00:00 GMT"}, json.dumps(self.catalog).encode()


def kev_item(cve="CVE-2026-0001", added="2026-11-04"):
    return {"cveID": cve, "vendorProject": "Anthropic", "product": "Claude Code", "dateAdded": added}


REPO = GHSA.rsplit("/", 1)[0] + "/"


def bare_high(**kw):
    """A high with no fix known (9kgk): the vendor's page confirms the record's trojanized
    flag. The severity word alone sets nothing; a consequence in prose needs the fix."""
    return {**finding(severity="high", **kw), "trojanized": True}


def kev_fixed(env, *items):
    """KEV lists the CVE and the vendor's page states its fix: the critical a member can
    act on (9kgk). KEV alone, with no fix known, posts at high."""
    env.kev.catalog = {"vulnerabilities": list(items) or [kev_item()]}
    env.collector([finding(fid=i["cveID"], fixed="2.1.0") for i in env.kev.catalog["vulnerabilities"]])


def finding(fid="GHSA-abcd-efgh-ijkl", product="Claude Code", severity="remote code execution",
            fixed="2.1.0", sources=None, aliases=(), observed="2026-11-05T00:00:00Z", affected=None):
    """A collector finding. Its default source is the vendor's own page for it (h340): the
    advisory's page for a GHSA id, else a page whose CVE ID field is the id (``Pages``)."""
    if sources is None:
        sources = (REPO + fid if fid.startswith("GHSA-") else GHSA,)
    return {"id": fid, "product": product, "advisory_severity": severity, "fixed": fixed, "affected": affected,
            "aliases": list(aliases), "observed_at": observed,
            "sources": [{"url": u, "published_at": None} for u in sources]}


MAC = finding(fid="CVE-2026-5000", product="Cursor IDE", severity=None, fixed=None, sources=(APPLE,))


RELAY = {"relay_key_secret": "RELAY_TEST_NSEC", "secrets_helper": Path("/opt/secrets/secrets.sh")}
RELAY_TOML = "".join(f'{k} = "{v}"\n' for k, v in RELAY.items())  # str() of the Path


@pytest.fixture
def env(tmp_path):
    class Env:
        hb, col = tmp_path / "heartbeat", tmp_path / "collector"
        config = inputs.Config(heartbeat_runs=tmp_path / "heartbeat", collector_runs=tmp_path / "collector",
                               ledger=tmp_path / "state" / "ledger.json",
                               kev_cache=tmp_path / "state" / "kev.json", **RELAY)
        kev, mirror = FakeKEV(), Mirror()  # the digest pulls the mirror first (ai-tools-alerts#d3f6)
        pages = Pages()  # the vendor pages the run fetches: each states what its finding says (h340)
        api = Api(default=plain)  # 3qyq: the advisory API answers, and says no more than the page
        _n = itertools.count()

        def collector(self, findings, validate="ok", name=None):
            d = self.col / (name or f"2026-11-05T{next(self._n):02d}0000Z")
            d.mkdir(parents=True)
            (d / "run-record.json").write_text(json.dumps({"schema_version": 1, "findings": findings}))
            self.pages.add(findings)
            (d / "job.json").write_text(json.dumps({"steps": {"validate": {"out": validate}}}))

        def heartbeat(self, name, findings, feeds=None):
            d = self.hb / name
            d.mkdir(parents=True)
            (d / "run.json").write_text(json.dumps({"schema": 1, "findings": findings}))
            self.pages.add(findings.values() if isinstance(findings, dict) else findings)
            if feeds is not None:
                (d / "feeds.json").write_text(json.dumps(feeds))

        def run(self, now=T0, relay=None, kev=None, **kw):
            relay = relay if relay is not None else FakeRelay()
            kw = {"mirror_fetch": self.mirror.fetch, "root": self.mirror.root, "page": self.pages, **kw}
            kw.setdefault("ssh", relay)  # the checkpoint route; a test's PutRelay takes both
            kw.setdefault("catalog_channel", False)  # q03f: tests/poster/test_catalog.py turns it on
            kw.setdefault("advisory_fetch", self.api)
            code, summary = main.run(now, self.config, send=relay, kev_fetch=kev or self.kev,
                                     channels=CHANNELS, **kw)
            return code, summary, relay

        def state(self):
            return json.loads(self.config.state.read_text())

        def ledger(self):
            with Ledger(self.config.ledger) as led:
                return led._state()["entries"], led._state()["pending"]

    Env.hb.mkdir()
    Env.col.mkdir()
    return Env()


def chans(relay):
    return [(c[0], c[1]) for c in relay.calls]


# ---------------------------------------------------------------- the eight named tests


def test_send_failure_leaves_advisory_unposted(env):
    env.collector([finding()])
    code, summary, relay = env.run(relay=FakeRelay("fail"))
    assert code == 1 and "failed=1" in summary and chans(relay) == [("feed", None)]
    assert env.ledger() == ([], [])
    assert [it["kind"] for it in env.state()["outbox"]] == ["root"]  # kept for the next hour
    code, _, relay = env.run(now=T0 + 3600)
    assert code == 0 and chans(relay) == [("feed", None)]
    entries, pending = env.ledger()
    assert len(entries) == 1 and pending == [] and env.state()["outbox"] == []
    env.collector([finding()])
    _, _, relay = env.run(now=T0 + 7200)
    assert relay.calls == []  # posted once, never again


def test_critical_posts_to_both_channels_in_order(env):
    kev_fixed(env)
    code, summary, relay = env.run()
    assert code == 0, summary
    assert chans(relay) == [("critical", None), ("feed", None)]
    assert relay.calls[0][2] == relay.calls[1][2] and relay.calls[0][2].startswith("CRITICAL: Claude Code")
    (e,), _ = env.ledger()
    assert set(e["channel_ids"]) == {"critical", "feed"} and e["level"] == "critical"
    assert e["root_event_id"] == e["channel_ids"]["critical"]


def test_high_posts_to_feed_only(env):
    env.collector([finding()])
    code, summary, relay = env.run()
    assert code == 0 and "roots=1" in summary
    assert chans(relay) == [("feed", None)] and relay.calls[0][2].startswith("HIGH: Claude Code")


def test_notice_waits_for_digest(env):
    env.collector([MAC])
    code, summary, relay = env.run()
    assert code == 0 and relay.calls == [] and "held=1" in summary
    code, summary, relay = env.run(now=at(5, 9))
    assert code == 0 and chans(relay) == [("feed", None)]
    assert relay.calls[0][2] == ("Daily digest for 2026-11-05: no new alerts. 1 notice added to the catalog"
                                 " this week: https://buzz.ai-tools.md/alerts/")  # qwpw: the daily lists no notice
    assert len(env.state()["held"]) == 1  # held until the weekly summary
    _, _, relay = env.run(now=at(5, 10))
    assert relay.calls == []  # one digest a day
    _, _, relay = env.run(now=at(9, 9))  # Monday: the weekly summary counts it
    assert len(relay.calls) == 1 and "Weekly summary: 1 notice added" in relay.calls[0][2]
    assert "- Cursor: 1" in relay.calls[0][2] and "CVE-2026-5000" not in relay.calls[0][2]
    st = env.state()
    assert st["held"] == [] and "Cursor|cve-2026-5000" in st["digested"]
    env.collector([MAC])  # seen again: never held again
    _, _, relay = env.run(now=at(10, 9))
    assert len(relay.calls) == 1 and "no new alerts. 0 notices" in relay.calls[0][2]
    assert env.state()["held"] == []


def replace_fixed(f, fixed):
    return {**f, "fixed": fixed}


def test_duplicate_alias_is_learned_and_rides_the_next_real_reply(env):  # 8ke5
    env.collector([finding()])
    env.run()
    (e,), _ = env.ledger()
    root = e["channel_ids"]["feed"]
    twin = finding(fid="CVE-2026-0002", aliases=("GHSA-abcd-efgh-ijkl",), sources=(GHSA, GHSA2))
    env.collector([twin])
    code, summary, relay = env.run(now=T0 + 3600)  # only an alias and a source are new: no post
    assert code == 0 and "replies=0" in summary and "roots=0" in summary and relay.calls == []
    (e,), _ = env.ledger()
    assert e["replies"] == [] and "CVE-2026-0002" in e["aliases"]  # the identity is learned
    # h340: the twin's other URL is a page nobody read for this advisory, so it is not learned
    assert "learned_sources" not in e and e["listed_at"] == e["posted_at"]
    env.collector([finding(fixed="2.1.1")])  # a real change, from a record without the twin
    code, summary, relay = env.run(now=T0 + 7200)
    assert code == 0 and "replies=1" in summary and chans(relay) == [("feed", root)]
    text = relay.calls[0][2]
    assert "Fixed in 2.1.1" in text and "Also known as: CVE-2026-0002." in text and "New sources listed." not in text
    block = json.loads(text.split("```aitools-alert\n")[1].split("```")[0])
    assert block["aliases"] == ["CVE-2026-0002"] and "sources" not in block
    (e,), _ = env.ledger()
    assert len(e["replies"]) == 1 and not e.get("learned_sources") and e["listed_at"] == T0 + 7200
    env.collector([replace_fixed(twin, "2.1.1")])
    _, _, relay = env.run(now=T0 + 9000)
    assert relay.calls == []


def test_watermark_advances_only_on_success(env):
    env.heartbeat("2026-11-05T000000Z", [])
    env.collector([finding()], name="2026-11-05T000000Z")
    code, _, _ = env.run(relay=FakeRelay("fail"))
    st = env.state()
    assert code == 1 and (st["heartbeat"], st["collector"], st["kev_since"]) == (None, None, None)
    code, _, _ = env.run(now=T0 + 3600)
    st = env.state()
    assert code == 0
    assert (st["heartbeat"], st["collector"]) == ("2026-11-05T000000Z", "2026-11-05T000000Z")
    assert st["kev_since"] == "2026-11-03"  # the UTC date of now (22:20Z on Nov 4) minus a day


def test_kev_fetch_not_modified_uses_cache(env):
    env.config.kev_cache.parent.mkdir(parents=True)
    lm = "Tue, 03 Nov 2026 10:00:00 GMT"
    env.config.kev_cache.write_text(json.dumps({"last_modified": lm,
                                                "catalog": {"vulnerabilities": [kev_item()]}}))
    env.collector([finding(fid="CVE-2026-0001", fixed="2.1.0")])  # 9kgk: the fix makes it critical
    kev = FakeKEV(status=304)
    code, _, relay = env.run(kev=kev)
    assert code == 0 and kev.headers == [{"If-Modified-Since": lm}]
    assert chans(relay) == [("critical", None), ("feed", None)]


def test_unknown_outcome_keeps_pending(env):
    env.collector([finding()])
    code, summary, relay = env.run(relay=FakeRelay("unknown"))
    assert code == 1 and "unknown=1" in summary
    entries, pending = env.ledger()
    assert entries == [] and len(pending) == 1 and len(env.state()["outbox"]) == 1
    env.collector([finding()])
    code, summary, relay = env.run(now=T0 + 3600)
    assert code == 0 and relay.calls == [] and "busy=2" in summary  # the item, then the candidate
    with Ledger(env.config.ledger) as led:  # a human found it was not delivered
        led.expire_pending(pending[0]["key"], "checked the channel: not delivered", now=T0 + 90000)
    code, _, relay = env.run(now=T0 + 90000)
    assert code == 0 and chans(relay)[0] == ("feed", None)  # resent from the journal, no new input
    assert len(env.ledger()[0]) == 1


# ---------------------------------------------------------------- pending / resolve


def test_pending_on_an_empty_journal(env):
    assert main.pending(T0, env.config) == (0, ["aitools-alerts-poster: pending=0 unknown=0 sent=0 orphan=0"])


def _unknown_root(env):
    env.collector([finding()])
    env.run(relay=FakeRelay("unknown"))
    (it,) = env.state()["outbox"]
    return it


def test_pending_lists_an_unknown_send_without_its_text(env):
    it = _unknown_root(env)
    code, lines = main.pending(T0 + 60, env.config)
    assert code == 0 and lines[-1] == "aitools-alerts-poster: pending=1 unknown=1 sent=0 orphan=0"
    assert lines[0] == (f"{it['key']} kind=root channel=feed attempted_at=2026-11-04T21:20:00Z "
                        "expires_at=2026-11-05T21:20:00Z outcome=unknown")
    assert it["text"] not in "\n".join(lines) and "GHSA-abcd" in it["key"]


def test_resolve_delivered_records_as_a_send_would(env):
    it = _unknown_root(env)
    eid = "ab" * 32
    assert main.resolve(T0 + 600, env.config, it["key"], delivered=eid)[0] == 0
    entries, pending = env.ledger()
    assert pending == [] and [it["kind"] for it in env.state()["outbox"]] == ["ja"]  # sent next run
    assert entries[0]["root_event_id"] == eid and entries[0]["channel_ids"] == {"feed": eid}
    env.collector([finding()])
    code, _, relay = env.run(now=T0 + 3600)  # neither resent nor re-recorded
    assert code == 0 and relay.calls == [] and len(env.ledger()[0]) == 1


def test_resolve_refuses_a_bad_id_or_a_key_not_pending(env):
    it = _unknown_root(env)
    before = (env.ledger(), env.state())
    assert main.resolve(T0, env.config, it["key"], delivered="AB" * 32)[0] == 2
    assert main.resolve(T0, env.config, "root:x:y:feed", delivered="ab" * 32)[0] == 2
    assert main.resolve(T0 + 90000, env.config, "root:x:y:feed", reason="checked")[0] == 2
    assert main.resolve(T0 + 90000, env.config, it["key"], reason=" ")[0] == 2
    assert (env.ledger(), env.state()) == before


def test_resolve_not_delivered_waits_24_hours_then_resends(env):
    it = _unknown_root(env)
    code, lines = main.resolve(T0 + 3600, env.config, it["key"], reason="not in the channel")
    assert code == 2 and "allowed from 2026-11-05T21:20:00Z" in lines[0] and env.ledger()[1]
    assert main.resolve(T0 + 90000, env.config, it["key"], reason="not in the channel")[0] == 0
    with Ledger(env.config.ledger) as led:
        assert led.pending_entries() == [] and led._state()["expired"][0]["reason"] == "not in the channel"
    code, _, relay = env.run(now=T0 + 90000)
    assert code == 0 and chans(relay) == [("feed", None)] and len(env.ledger()[0]) == 1


def test_resolve_not_delivered_refuses_when_the_journal_says_sent(env):
    it = _unknown_root(env)
    st = env.state()
    st["outbox"][0]["sent"] = "cd" * 32  # a run that crashed after journaling the id
    inputs.save_state(env.config.state, st)
    code, lines = main.pending(T0, env.config)
    assert f"outcome=sent:{'cd' * 32}" in lines[0] and lines[-1].endswith("unknown=0 sent=1 orphan=0")
    assert main.resolve(T0 + 90000, env.config, it["key"], reason="x")[0] == 2
    assert main.resolve(T0, env.config, it["key"], delivered="ef" * 32)[0] == 2
    assert main.resolve(T0, env.config, it["key"], delivered="cd" * 32)[0] == 0
    assert env.ledger()[0][0]["root_event_id"] == "cd" * 32


def test_resolve_delivered_refuses_what_would_not_record(env):
    env.collector([finding(fid="GHSA-zzzz-zzzz-zzzz")])
    env.run()
    known = env.ledger()[0][0]["root_event_id"]
    it = _unknown_root(env)
    before = (env.ledger(), env.state())
    code, lines = main.resolve(T0, env.config, it["key"], delivered=known)  # another thread's id
    assert code == 2 and "already recorded" in lines[0] and (env.ledger(), env.state()) == before
    st = env.state()  # another item sent and journaled, not yet recorded (a crash)
    st["outbox"].append({**it, "key": "root:other:x:feed", "sent": "cd" * 32})
    inputs.save_state(env.config.state, st)
    assert main.resolve(T0, env.config, it["key"], delivered="cd" * 32)[0] == 2
    inputs.save_state(env.config.state, before[1])
    with Ledger(env.config.ledger):  # the hourly run holds the lock
        assert main.resolve(T0, env.config, it["key"], delivered="ab" * 32)[0] == 1
        assert main.pending(T0, env.config)[0] == 1
    assert (env.ledger(), env.state()) == before


def test_resolve_delivered_acknowledges_a_digest(env):
    env.collector([MAC])
    env.run()
    env.run(now=at(9, 9), relay=FakeRelay("unknown"))  # Monday's digest carries the weekly summary (qwpw)
    (it,) = env.state()["outbox"]
    assert main.resolve(at(9, 10), env.config, it["key"], delivered="ab" * 32)[0] == 0
    st = env.state()
    assert [o["root"] for o in st["outbox"]] == ["ab" * 32]  # its Japanese reply, sent next run
    assert st["held"] == [] and st["digest_ids"] == ["ab" * 32] and "Cursor|cve-2026-5000" in st["digested"]
    assert st["digest_date"] == "2026-11-09" and st["weekly"] == "2026-W46" and env.ledger()[1] == []


def test_pending_and_resolve_from_the_command_line(env, tmp_path, capsys, monkeypatch):
    it = _unknown_root(env)
    monkeypatch.setattr(main.time, "time", lambda: T0 + 60)
    cfg = tmp_path / "config.toml"
    cfg.write_text(f'ledger = "{env.config.ledger}"\nkev_cache = "{env.config.kev_cache}"\n')
    assert main.main(["pending", "--config", str(cfg)]) == 0
    assert it["key"] in capsys.readouterr().out
    assert main.main(["resolve", it["key"], "--config", str(cfg), "--delivered", "xyz"]) == 2
    assert main.main(["resolve", it["key"], "--config", str(cfg), "--not-delivered", "--reason", "x"]) == 2
    assert "allowed from" in capsys.readouterr().err
    assert main.main(["resolve", it["key"], "--config", str(cfg), "--delivered", "ab" * 32]) == 0
    assert env.ledger()[1] == []


# ---------------------------------------------------------------- failure paths


def test_one_failure_stops_further_sends(env):
    env.collector([finding(), finding(fid="GHSA-zzzz-zzzz-zzzz"), MAC])
    code, _, relay = env.run(now=at(5, 9), relay=FakeRelay("fail"))
    assert code == 1 and len(relay.calls) == 1  # no second high, no digest
    st = env.state()
    assert st["collector"] is None and st["digest_date"] is None and st["withheld"] == []  # 8acj


def test_ledger_error_stops_sends_and_replays_without_sending(env, monkeypatch):
    env.collector([finding(), finding(fid="GHSA-zzzz-zzzz-zzzz", fixed="2.1.1")])  # faxq: two fixes, two threads
    real = Ledger.record_root

    def boom(self, *a, **k):
        raise LedgerError("disk full")

    monkeypatch.setattr(Ledger, "record_root", boom)
    code, summary, relay = env.run()
    assert code == 1 and len(relay.calls) == 1 and "error=ledger" in summary
    (it,) = [i for i in env.state()["outbox"] if i["sent"]]
    monkeypatch.setattr(Ledger, "record_root", real)
    code, _, relay = env.run(now=T0 + 3600)
    assert code == 0
    entries, pending = env.ledger()
    assert it["sent"] in {e["root_event_id"] for e in entries} and pending == []
    assert chans(relay) == [("feed", None)]  # only the second advisory: the first was not resent


def test_feed_failure_after_critical_completes_next_run(env):
    kev_fixed(env)
    code, _, relay = env.run(relay=FakeRelay("ok", "fail"))
    assert code == 1 and chans(relay) == [("critical", None), ("feed", None)]
    (e,), pending = env.ledger()
    assert set(e["channel_ids"]) == {"critical"} and pending == []
    code, _, relay = env.run(now=T0 + 3600)
    assert code == 0 and chans(relay) == [("feed", None)]
    (e,), _ = env.ledger()
    assert set(e["channel_ids"]) == {"critical", "feed"}


def test_partial_reply_retried_in_failed_channel_only(env):
    kev_fixed(env)
    env.run()
    (e,), _ = env.ledger()
    env.collector([finding(fid="CVE-2026-0001", fixed="2.1.1", sources=(GHSA2,))])  # a new fix and source
    code, _, relay = env.run(now=T0 + 3600, relay=FakeRelay("ok", "fail"))
    assert code == 1
    assert chans(relay) == [("critical", e["channel_ids"]["critical"]), ("feed", e["channel_ids"]["feed"])]
    text = relay.calls[0][2]
    code, _, relay = env.run(now=T0 + 7200)
    assert code == 0 and chans(relay) == [("feed", e["channel_ids"]["feed"])] and relay.calls[0][2] == text
    (e2,), _ = env.ledger()
    assert len(e2["replies"]) == 2


def test_a_refused_reply_is_fixed_and_requeued_when_its_sibling_recorded(env, tmp_path):  # 8acj
    kev_fixed(env)
    env.run(), env.collector([finding(fid="CVE-2026-0001", fixed="2.1.1", sources=(GHSA2,))])
    assert "withheld=1" in env.run(now=T0 + 3600, relay=FakeRelay("refuse"))[1]  # critical refused, feed recorded
    (w,) = env.state()["withheld"]
    assert main.resolve(T0, env.config, w["key"], requeue=True, text="no alert block")[0] == 2
    fixed = w["items"][0]["text"].replace("\n", " \n", 1)
    assert main.resolve(T0, env.config, w["key"], requeue=True, text=fixed)[0] == 0
    assert env.run(now=T0 + 7200)[2].calls[0][2] == fixed and len(env.ledger()[0][0]["replies"]) == 2


def test_busy_candidate_learns_ids(env):
    env.collector([finding(fid="GHSA-aaaa-aaaa-aaaa")])
    env.run(relay=FakeRelay("unknown"))
    env.collector([finding(fid="GHSA-aaaa-aaaa-aaaa", aliases=("CVE-2026-0009",))])
    env.run(now=T0 + 3600)
    assert "CVE-2026-0009" in env.state()["outbox"][0]["ids"]
    env.collector([finding(fid="CVE-2026-0009")])
    code, summary, relay = env.run(now=T0 + 7200)
    assert relay.calls == [] and "busy=2" in summary


def test_high_becoming_critical_under_another_id(env):
    env.collector([finding(fid="GHSA-abcd-efgh-ijkl", aliases=("CVE-2026-0001",))])
    env.run()
    (e,), _ = env.ledger()
    feed_root = e["channel_ids"]["feed"]
    env.kev.catalog = {"vulnerabilities": [kev_item()]}  # KEV knows it only as the CVE, with no fix
    code, summary, relay = env.run(now=T0 + 3600)
    assert code == 0, summary
    assert chans(relay) == [("critical", None), ("feed", feed_root)]
    copy, reply = relay.calls[0][2], relay.calls[1][2]
    assert copy.startswith("CRITICAL: Claude Code") and "(GHSA-abcd-efgh-ijkl)" in copy
    assert "Do: upgrade Claude Code to 2.1.0 or later." in copy  # the stored fix is kept
    assert "Level is now critical." in reply
    (e,), _ = env.ledger()
    assert e["level"] == "critical" and set(e["channel_ids"]) == {"critical", "feed"}


def test_compose_value_error_sends_nothing(env, monkeypatch):
    env.collector([finding(fid="CVE-2026-0001")])
    env.run()
    env.kev.catalog = {"vulnerabilities": [kev_item()]}

    def refuse(*a, **k):
        raise ValueError("composed post names a host; refusing to publish it")

    monkeypatch.setattr(main.compose, "reply_post", refuse)
    code, summary, relay = env.run(now=T0 + 3600)
    assert code == 0 and "withheld=1" in summary and "replies=1" in summary
    # 3qyq: nothing of the candidate's plan is sent. The recompute, which now judges a thread
    # that carries a GHSA id, sees KEV list its CVE and raises the level, alone. 3t4p: the
    # thread is then critical with no root in the critical channel, and the recompute
    # posts that copy from the ledger (compose.copy_post, which has its own guard).
    assert [(ch, reply is None, text.splitlines()[0]) for ch, reply, text in relay.calls] == [
        ("feed", False, "Level is now critical."),
        ("critical", True, "CRITICAL: Claude Code: remote code execution")]
    assert "copies=1" in summary and env.state()["outbox"] == []


def test_notice_dedup_is_per_scope(env):
    env.collector([finding(fid="CVE-2026-6000", product="Cursor IDE", severity=None, fixed=None, sources=(APPLE,)),
                   finding(fid="CVE-2026-6000", product="OpenAI Codex", severity=None, fixed=None,
                           sources=("https://openai.com/security/advisory-6000",))])
    code, summary, _ = env.run()
    assert code == 0 and "held=2" in summary
    assert len({h["scope"] for h in env.state()["held"]}) == 2


def test_digest_includes_ledger_posts(env):
    env.collector([finding()])
    env.run()
    assert env.state()["held"] == []
    code, _, relay = env.run(now=at(5, 9))
    assert code == 0 and "GHSA-abcd-efgh-ijkl" in relay.calls[0][2]


def test_backfill_floor_drops_old_candidates(env):
    env.collector([finding(observed="2026-10-01T00:00:00Z")])
    code, summary, relay = env.run()
    assert relay.calls == [] and "old=1" in summary


def test_collector_record_skipped_unless_validate_ok(env):
    env.collector([finding()], validate="failed")
    (env.col / "2026-11-05").mkdir()  # the collector's date-only copy: never read
    code, summary, relay = env.run()
    assert code == 0 and relay.calls == [] and "candidates=0" in summary


def test_heartbeat_feeds_json_never_reaches_from_kev(env, monkeypatch):
    env.heartbeat("2026-11-05T000000Z", [], feeds={"cisa-kev": {"items": [kev_item()]}})
    seen = []
    real = main.candidates.from_kev
    monkeypatch.setattr(main.candidates, "from_kev", lambda cat, since: seen.append(cat) or real(cat, since))
    code, _, relay = env.run()
    assert code == 0 and relay.calls == [] and seen == [env.kev.catalog]


def test_kev_unavailable_holds_kev_watermark(env):
    code, summary, _ = env.run(kev=FakeKEV(status=500))
    assert code == 0 and env.state()["kev_since"] is None


def test_malformed_state_refuses_to_send(env):
    env.config.state.parent.mkdir(parents=True)
    env.config.state.write_text("{not json")
    env.collector([finding()])
    code, summary, relay = env.run()
    assert code == 1 and relay.calls == [] and "error=ledger" in summary


def test_config_unknown_key_exits_2(tmp_path, capsys):
    cfg = tmp_path / "config.toml"
    cfg.write_text('ledger = "/x/ledger.json"\nprivate_key = "no"\n')
    assert main.main(["run", "--config", str(cfg)]) == 2
    assert "unknown keys" in capsys.readouterr().err


def test_main_prints_one_summary_line(tmp_path, monkeypatch, capsys):
    cfg = tmp_path / "config.toml"
    cfg.write_text(f'ledger = "{tmp_path / "s" / "ledger.json"}"\nkev_cache = "{tmp_path / "s" / "kev.json"}"\n'
                   + RELAY_TOML)
    monkeypatch.setattr(main.run, "__kwdefaults__",
                        {**main.run.__kwdefaults__, "kev_fetch": FakeKEV(), "relay": FakeRelay()})
    assert main.main(["run", "--config", str(cfg)]) == 0
    out = capsys.readouterr().out.splitlines()
    assert len(out) == 1 and out[0].startswith("aitools-alerts-poster: candidates=0")


def test_unknown_digest_is_journaled_once_and_acknowledges_its_snapshot(env):
    env.collector([MAC])
    env.run()
    code, _, relay = env.run(now=at(9, 9), relay=FakeRelay("unknown"))  # Monday: the weekly summary (qwpw)
    assert code == 1 and len(relay.calls) == 1
    env.collector([finding(fid="CVE-2026-5001", product="Cursor IDE", severity=None, fixed=None, sources=(APPLE,))])
    for h in (10, 11):
        _, _, relay = env.run(now=at(9, h))
        assert relay.calls == []
    st = env.state()
    assert [it["kind"] for it in st["outbox"]] == ["digest"] and len(st["held"]) == 2
    with Ledger(env.config.ledger) as led:
        (p,) = led._state()["pending"]
        led.expire_pending(p["key"], "checked the channel: not delivered", now=at(10, 12))
    code, _, relay = env.run(now=at(10, 12))
    assert code == 0 and len(relay.calls) == 2  # the journaled 11-09 digest, then today's
    assert "Weekly summary: 1 notice added" in relay.calls[0][2]  # its snapshot: the one held then
    assert relay.calls[1][2] == ("Daily digest for 2026-11-10: no new alerts. 1 notice added to the catalog"
                                 " this week: https://buzz.ai-tools.md/alerts/")
    st = env.state()  # the snapshot is acknowledged; the notice held after it waits for next week
    assert [h["adv"]["id"] for h in st["held"]] == ["CVE-2026-5001"] and "Cursor|cve-2026-5000" in st["digested"]


def test_affected_range_correction_posts_a_reply(env):
    first = finding()
    first["affected"] = "<2.0.0"
    env.collector([first])
    env.run()
    fixed_range = finding()
    fixed_range["affected"] = "<2.1.0"
    env.collector([fixed_range])
    code, summary, relay = env.run(now=T0 + 3600)
    assert code == 0 and "replies=1" in summary and "before 2.1.0" in relay.calls[0][2]


def test_busy_update_survives_its_source_being_replaced(env):
    env.collector([finding(fixed="2.0.0", severity=None, fid="CVE-2026-0001")])  # 9kgk: critical needs a fix
    env.kev.catalog = {"vulnerabilities": [kev_item()]}
    env.run(relay=FakeRelay("ok", "unknown"))  # critical root ok, feed copy unknown
    env.kev.catalog = {"vulnerabilities": []}
    env.collector([finding(fid="CVE-2026-0001", sources=(GHSA2,))])  # a newer fix arrives while busy
    code, _, relay = env.run(now=T0 + 3600)
    assert code == 0 and relay.calls == []
    st = env.state()
    assert [d["id"] for d in st["deferred"]] == ["CVE-2026-0001"]
    assert st["collector"] == "2026-11-05T010000Z"  # deferral, not the source, keeps the update
    env.collector([], name="2026-11-05T020000Z")  # the next record no longer names it
    with Ledger(env.config.ledger) as led:
        (p,) = led._state()["pending"]
        led.expire_pending(p["key"], "checked the channel: not delivered", now=T0 + 90000)
    code, summary, relay = env.run(now=T0 + 90000)
    assert code == 0, summary
    assert [c[0] for c in relay.calls] == ["feed", "critical", "feed"]  # the copy, then the fix replies
    assert all("Fixed in 2.1.0." in c[2] for c in relay.calls[1:])
    assert env.state()["deferred"] == []


def test_finished_send_clears_pending_before_the_item_goes(env, monkeypatch):
    env.collector([finding()])
    calls = []
    real = Ledger.clear_pending
    monkeypatch.setattr(Ledger, "clear_pending",
                        lambda self, key: calls.append(json.loads(env.config.state.read_text())["outbox"])
                        or real(self, key))
    env.run()
    assert calls and calls[0] and calls[0][0]["sent"]  # the sent item was still journaled


def test_range_correction_without_a_fix_posts_a_reply(env):
    first = finding(fid="CVE-2026-0001", fixed=None)
    first["affected"] = "<2.0.0"
    env.kev.catalog = {"vulnerabilities": [kev_item()]}  # exploited, no fix known: high (9kgk)
    env.collector([first])
    assert "roots=1" in env.run()[1]
    corrected = finding(fid="CVE-2026-0001", fixed=None)
    corrected["affected"] = "<2.5.0"
    env.collector([corrected])
    code, summary, relay = env.run(now=T0 + 3600)
    assert code == 0 and "replies=1" in summary  # the thread is in the feed: high until its fix
    assert all("before 2.5.0" in c[2] for c in relay.calls)


def test_only_ids_the_vendor_page_assigns_are_learned(env):  # h340 (was: ids learned past the alias cap)
    """A record's aliases are claims. The thread learns the ids the vendor's page assigns to
    the advisory and no other, so an alias cannot bridge threads or carry text."""
    env.pages.put(GHSA, advisory_page("GHSA-abcd-efgh-ijkl", package="Claude Code", ecosystem=None,
                                      cve="CVE-2026-0777", severity="High", title="Remote code execution"))
    env.collector([finding(aliases=[f"A-{i:03d}" for i in range(8)] + ["CVE-2026-0555", "GHSA-mnop-qrst-uvwx"])])
    _, _, relay = env.run()
    (e,), _ = env.ledger()
    assert e["advisory"]["aliases"] == ["CVE-2026-0777"] and "A-000" not in relay.calls[0][2]
    assert {a.casefold() for a in e["aliases"]} == {"ghsa-abcd-efgh-ijkl", "cve-2026-0777"}
    env.collector([finding(fid="CVE-2026-0777", sources=(GHSA,))])  # the page's own CVE: the same thread
    _, summary, relay = env.run(now=T0 + 3600)
    assert "roots=0" in summary and len(env.ledger()[0]) == 1 and relay.calls == []
    env.collector([finding(fid="CVE-2026-0555", sources=(GHSA,))])  # an id the page does not assign
    _, summary, relay = env.run(now=T0 + 7200)
    assert "roots=0" in summary and len(env.ledger()[0]) == 1 and relay.calls == []
    assert "cve-2026-0555" not in {a.casefold() for a in env.ledger()[0][0]["aliases"]}


def test_alias_reply_survives_a_stop_after_ids_were_learned(env, monkeypatch):
    env.collector([finding()])
    env.run()
    twin = finding(fid="CVE-2026-0002", aliases=("GHSA-abcd-efgh-ijkl",), fixed="2.1.1")  # 8ke5: a real change
    env.collector([twin])
    real = main.Run.enqueue

    def stop(self, items):
        raise LedgerError("stopped before journaling")

    monkeypatch.setattr(main.Run, "enqueue", stop)
    code, _, relay = env.run(now=T0 + 3600)
    assert code == 1 and relay.calls == []
    (e,), _ = env.ledger()
    assert "CVE-2026-0002" in e["aliases"]  # learned before the stop
    monkeypatch.setattr(main.Run, "enqueue", real)
    env.collector([twin])
    code, summary, relay = env.run(now=T0 + 7200)
    assert code == 0 and "replies=1" in summary and "CVE-2026-0002" in relay.calls[0][2]


def test_reply_keeps_its_thread_when_ids_bridge_two_threads(env):
    env.collector([finding(fid="CVE-2026-1111", sources=(GHSA2,)), finding()])
    env.run()
    entries, _ = env.ledger()
    e1 = next(e for e in entries if "CVE-2026-1111" in e["aliases"])
    e2 = next(e for e in entries if "GHSA-abcd-efgh-ijkl" in e["aliases"])
    fix = finding(fixed="2.2.0")
    env.collector([fix])
    env.run(now=T0 + 3600, relay=FakeRelay("unknown"))  # e2's reply: outcome unknown
    env.collector([finding(aliases=("CVE-2026-1111",), fixed="2.2.0")])  # bridges e2 to e1
    env.run(now=T0 + 7200)
    with Ledger(env.config.ledger) as led:
        (p,) = led._state()["pending"]
        led.expire_pending(p["key"], "checked the channel: not delivered", now=T0 + 90000)
    _, _, relay = env.run(now=T0 + 90000)
    assert relay.calls[0][1] == e2["channel_ids"]["feed"]  # still e2's thread
    entries, _ = env.ledger()
    assert next(e for e in entries if e["root_event_id"] == e1["root_event_id"])["advisory"]["id"] == "CVE-2026-1111"


def test_widened_root_never_starts_a_second_thread(env):
    env.collector([finding(fid="CVE-2026-1111", sources=(GHSA2,))])
    env.run()
    env.collector([finding()])
    env.run(now=T0 + 3600, relay=FakeRelay("unknown"))  # a new root for the GHSA: unknown
    env.collector([finding(aliases=("CVE-2026-1111",))])  # the GHSA is the CVE's thread after all
    env.run(now=T0 + 7200)
    with Ledger(env.config.ledger) as led:
        (p,) = led._state()["pending"]
        led.expire_pending(p["key"], "checked the channel: not delivered", now=T0 + 90000)
    _, _, relay = env.run(now=T0 + 90000)
    assert all(c[1] is not None for c in relay.calls)  # replies only, never a new root
    assert len(env.ledger()[0]) == 1


def test_unsendable_channel_never_marks_pending(env):
    env.collector([finding()])
    bad = dict(CHANNELS, feed="NOT-A-UUID")
    code, summary = main.run(T0, env.config, send=FakeRelay(), kev_fetch=env.kev,
                             page=env.pages, channels=bad)
    assert code == 1 and "withheld=1" in summary and env.ledger()[1] == []


def test_oversized_digest_posts_what_fits_and_keeps_the_rest(env, monkeypatch):
    """qwpw: the daily lists the day's new roots only (held notices are counted, not listed),
    so the roots are what an oversized digest cuts short."""
    ids = [f"GHSA-aaaa-aaaa-aa{i:02d}" for i in range(6)]
    env.collector([finding(fid=i, fixed=f"2.1.{n}") for n, i in enumerate(ids)])  # faxq: six threads
    env.run()
    assert len(env.ledger()[0]) == 6
    monkeypatch.setattr(main.transport, "MAX_CONTENT", 400)  # room for a few items only
    code, _, relay = env.run(now=at(5, 9))
    assert code == 0 and len(relay.calls) == 1 and len(relay.calls[0][2]) <= 400
    listed = {i for i in ids if i in relay.calls[0][2]}
    assert 0 < len(listed) < 6  # only what was posted is acknowledged
    _, _, relay = env.run(now=at(6, 9))
    rest = {i for i in ids if i in relay.calls[0][2]}
    assert rest and rest.isdisjoint(listed)
    for day in (7, 8, 9, 10):  # the backlog moves forward a day at a time and loses nothing
        _, _, relay = env.run(now=at(day, 9))
        later = {i for i in ids if i in relay.calls[0][2]}
        assert later.isdisjoint(listed | rest)
        rest |= later
    assert listed | rest == set(ids)


def test_fresh_correction_wins_over_a_deferred_fix(env):
    env.collector([finding(fid="CVE-2026-0001")])
    env.kev.catalog = {"vulnerabilities": [kev_item()]}
    env.run(relay=FakeRelay("ok", "unknown"))  # critical root ok, feed copy unknown: busy
    env.collector([finding(fid="CVE-2026-0001", fixed="2.1.5", sources=(GHSA2,))])
    env.run(now=T0 + 3600)  # deferred with 2.1.5
    with Ledger(env.config.ledger) as led:
        (p,) = led._state()["pending"]
        led.expire_pending(p["key"], "checked the channel: not delivered", now=T0 + 90000)
    env.collector([finding(fid="CVE-2026-0001", fixed="2.2.0", sources=(GHSA2,))])  # the correction
    code, _, relay = env.run(now=T0 + 90000)
    assert code == 0 and relay.calls
    assert all("2.2.0" in c[2] and "2.1.5" not in c[2] for c in relay.calls[1:])


def test_digest_backlog_moves_forward_day_by_day(env, monkeypatch):
    env.collector([finding(fid=f"GHSA-aaaa-aaaa-aa{i:02d}", fixed=f"2.1.{i}") for i in range(6)])  # faxq: six threads
    env.run()
    assert len(env.ledger()[0]) == 6
    monkeypatch.setattr(main.transport, "MAX_CONTENT", 700)
    seen = set()
    for day in (5, 6, 7, 8, 9, 10):
        _, _, relay = env.run(now=at(day, 9))
        if relay.calls:
            seen |= {f"GHSA-aaaa-aaaa-aa{i:02d}" for i in range(6) if f"aa{i:02d})" in relay.calls[0][2]}
    assert seen == {f"GHSA-aaaa-aaaa-aa{i:02d}" for i in range(6)}


def test_new_roots_copy_stays_on_its_thread(env):
    env.collector([finding(fid="GHSA-zzzz-zzzz-zzzz")])  # an older feed thread A
    env.run()
    kev_fixed(env)  # a new critical thread B
    env.run(now=T0 + 3600, relay=FakeRelay("ok", "unknown"))
    entries, _ = env.ledger()
    b = next(e for e in entries if "CVE-2026-0001" in e["aliases"])
    env.collector([finding(fid="GHSA-zzzz-zzzz-zzzz", aliases=("CVE-2026-0001",))])
    env.run(now=T0 + 7200)  # bridges B's ids to A while the copy is pending
    with Ledger(env.config.ledger) as led:
        (p,) = led._state()["pending"]
        led.expire_pending(p["key"], "checked the channel: not delivered", now=T0 + 90000)
    env.run(now=T0 + 90000)
    entries, _ = env.ledger()
    assert set(next(e for e in entries if e["root_event_id"] == b["root_event_id"])["channel_ids"]) \
        == {"critical", "feed"}


def test_ledger_error_keeps_unplanned_candidates(env, monkeypatch):
    env.collector([finding(), finding(fid="GHSA-zzzz-zzzz-zzzz", fixed="2.1.1")])  # faxq: two fixes, two threads
    real = Ledger.record_root
    calls = []

    def boom(self, *a, **k):
        calls.append(1)
        raise LedgerError("disk full")

    monkeypatch.setattr(Ledger, "record_root", boom)
    code, _, _ = env.run()
    assert code == 1 and calls
    assert {d["id"] for d in env.state()["deferred"]} == {"GHSA-abcd-efgh-ijkl", "GHSA-zzzz-zzzz-zzzz"}
    monkeypatch.setattr(Ledger, "record_root", real)
    env.collector([])  # the collector's newest record no longer names either
    code, summary, relay = env.run(now=T0 + 3600)
    assert code == 0 and len(env.ledger()[0]) == 2 and len(relay.calls) == 1


# ---------------------------------------------------------------- akq9: inputs, digest ids, flags

SYNTHETIC = Path(__file__).resolve().parents[1] / "fixtures" / "kev-synthetic.json"


def test_summary_shows_kev_unavailable_and_rejected_collector(env, capsys):
    d = env.col / "2026-11-05T000000Z"
    d.mkdir()
    (d / "run-record.json").write_text(json.dumps({"schema_version": 2, "findings": []}))
    (d / "job.json").write_text(json.dumps({"steps": {"validate": {"out": "ok"}}}))
    env.heartbeat("2026-11-05T000000Z", [])
    code, summary, _ = env.run(kev=FakeKEV(status=503))
    err = capsys.readouterr().err
    assert code == 0 and summary.endswith(" inputs=kev:unavailable,collector:rejected,heartbeat:1/1")
    assert "kev unavailable" in err and "collector 2026-11-05T000000Z rejected: schema_version" in err
    assert env.state()["kev_since"] is None
    env.collector([finding()], validate="failed", name="2026-11-05T010000Z")  # newer, not validated
    _, summary, _ = env.run(now=T0 + 3600)
    assert "inputs=kev:ok,collector:rejected,heartbeat:0/0" in summary
    assert "collector 2026-11-05T010000Z rejected: not validated" in capsys.readouterr().err
    (env.col / "2026-11-05T010000Z" / "job.json").write_text(json.dumps({"steps": {"validate": {"out": "ok"}}}))
    (env.col / "2026-11-05T010000Z" / "run-record.json").write_text("{not json")
    _, summary, _ = env.run(now=T0 + 5400)
    assert "collector:rejected" in summary
    assert "collector 2026-11-05T010000Z rejected: unreadable" in capsys.readouterr().err
    _, summary, _ = env.run(now=T0 + 7200, kev=FakeKEV(status=304))
    assert "kev:304" in summary  # served from the cache the 200 wrote


def test_quiet_hour_with_healthy_inputs(env):
    code, summary, _ = env.run()
    assert code == 0 and summary.endswith(" inputs=kev:ok,collector:none,heartbeat:0/0")
    env.config = inputs.Config(ledger=env.config.ledger, kev_cache=env.config.kev_cache, **RELAY)
    code, summary, _ = env.run(now=T0 + 3600, kev=FakeKEV(status=304))
    assert code == 0 and summary.endswith(" inputs=kev:304,collector:off,heartbeat:off")


def test_rejected_collector_holds_watermark(env):
    env.collector([finding()], name="2026-11-05T000000Z")
    env.run()
    d = env.col / "2026-11-05T010000Z"
    d.mkdir()
    (d / "run-record.json").write_text(json.dumps({"schema_version": 1, "findings": "nope"}))
    (d / "job.json").write_text(json.dumps({"steps": {"validate": {"out": "ok"}}}))
    code, summary, _ = env.run(now=T0 + 3600)
    assert code == 0 and "collector:rejected" in summary
    assert env.state()["collector"] == "2026-11-05T000000Z"  # the rejected record is read again
    (d / "run-record.json").write_text(json.dumps({"schema_version": 1, "findings": []}))
    _, summary, _ = env.run(now=T0 + 7200)
    assert "collector:ok" in summary and env.state()["collector"] == "2026-11-05T010000Z"


def test_rejected_heartbeat_holds_watermark(env):
    env.heartbeat("2026-11-05T000000Z", [])
    env.run()
    assert env.state()["heartbeat"] == "2026-11-05T000000Z"
    env.heartbeat("2026-11-05T010000Z", [])
    (env.hb / "2026-11-05T010000Z" / "run.json").write_text("{not json")
    env.heartbeat("2026-11-05T020000Z", [{"id": "CVE-2026-5000", "product": "Cursor IDE", "source": APPLE}])
    code, summary, relay = env.run(now=T0 + 3600)
    assert code == 0 and "heartbeat:1/2" in summary and "held=1" in summary  # the good dir is still read
    assert env.state()["heartbeat"] == "2026-11-05T000000Z"  # held before the rejected dir
    (env.hb / "2026-11-05T010000Z" / "run.json").write_text(json.dumps({"schema": 1, "findings": []}))
    code, summary, relay = env.run(now=T0 + 7200)
    assert "heartbeat:2/2" in summary and "held=0" in summary  # re-read: nothing is held twice
    assert env.state()["heartbeat"] == "2026-11-05T020000Z"


def test_digest_id_recorded_and_printed(env, capsys):
    env.collector([MAC])
    env.run()
    st = env.state()
    base = 1 << 252  # far from FakeRelay's counter, whatever ran before
    st["digest_ids"] = [f"{i:064x}" for i in range(base, base + 10)]  # ten already
    env.config.state.write_text(json.dumps(st))
    code, _, relay = env.run(now=at(5, 9))
    st = env.state()
    assert code == 0 and len(relay.calls) == 1 and len(st["digest_ids"]) == 10
    assert st["digest_ids"][0] == f"{base + 1:064x}"  # the oldest dropped
    sent = st["digest_ids"][-1]
    assert f"digest 2026-11-05 sent: {sent}" in capsys.readouterr().err


def test_old_state_without_digest_ids_loads(env):
    env.run()
    st = env.state()
    del st["digest_ids"], st["withheld"]  # 8acj: and withheld
    env.config.state.write_text(json.dumps(st))
    env.collector([MAC])
    code, _, _ = env.run(now=at(5, 9))
    assert code == 0 and len(env.state()["digest_ids"]) == 1
    st = env.state()
    st["digest_ids"] = ["not-hex"]
    env.config.state.write_text(json.dumps(st))
    code, summary, _ = env.run(now=at(5, 10))
    assert code == 1 and "error=ledger" in summary


def test_digest_replay_records_id_once(env, monkeypatch):
    env.collector([MAC])
    env.run()
    real = main.Run._record

    def boom(self, it):
        if it["kind"] == "digest":
            raise LedgerError("disk full")
        return real(self, it)

    monkeypatch.setattr(main.Run, "_record", boom)
    code, _, relay = env.run(now=at(5, 9))
    assert code == 1 and len(relay.calls) == 1
    monkeypatch.setattr(main.Run, "_record", real)
    code, _, relay = env.run(now=at(5, 10))
    assert code == 0 and relay.calls == [] and len(env.state()["digest_ids"]) == 1


def test_digest_now_once_per_date(env, capsys):
    env.collector([MAC])
    code, _, relay = env.run(digest_now=True)  # 06:20 Tokyo, before the digest hour
    assert code == 0 and len(relay.calls) == 1 and "Daily digest for 2026-11-05" in relay.calls[0][2]
    assert env.state()["digest_date"] == "2026-11-05"
    code, _, relay = env.run(now=T0 + 600, digest_now=True)
    assert code == 0 and relay.calls == []
    assert "digest for 2026-11-05 already sent; --digest-now does nothing" in capsys.readouterr().err
    _, _, relay = env.run(now=at(5, 9))
    assert relay.calls == []  # the 09:00 run sends no second digest
    _, _, relay = env.run(now=at(6, 6))
    assert relay.calls == []  # without the flag, the next date still waits for the hour


def test_kev_file_bypasses_fetch_and_marks_posts(env):
    kev = FakeKEV()
    catalog = inputs.read_kev_file(SYNTHETIC)
    code, summary, relay = env.run(now=at(20, 6), kev=kev, kev_catalog=catalog)  # dateAdded long past
    assert code == 0, summary
    assert kev.headers == [] and not env.config.kev_cache.exists()
    assert "inputs=kev:file," in summary and "roots=1" in summary
    assert chans(relay) == [("feed", None)]  # 9kgk: a KEV entry states no fix, so high until one is known
    # faxq: the headline is the KEV entry's own name after the product; the marker stays first
    assert all(c[2].startswith("HIGH (SYNTHETIC TEST): Claude Code: SYNTHETIC TEST: ") and "CVE-2099-0010" in c[2]
               for c in relay.calls)
    assert env.state()["kev_since"] is None  # the real catalog was not read
    code, summary, relay = env.run(now=at(20, 7), kev=kev, kev_catalog=catalog)
    assert code == 0 and relay.calls == [] and "withheld=1" in summary  # known: never a reply


def test_kev_file_candidate_never_deferred(env):
    catalog = inputs.read_kev_file(SYNTHETIC)
    code, _, _ = env.run(relay=FakeRelay("unknown"), kev_catalog=catalog)
    assert code == 1
    assert env.state()["deferred"] == []
    code, summary, relay = env.run(now=T0 + 3600, kev_catalog=catalog)
    assert code == 0 and relay.calls == [] and env.state()["deferred"] == []  # busy: dropped


def test_kev_file_notice_is_withheld(env, tmp_path):
    catalog = {"vulnerabilities": [{"cveID": "CVE-2099-0002", "vendorProject": "Apple", "product": "macOS",
                                    "vulnerabilityName": "SYNTHETIC TEST", "dateAdded": "2026-11-05"}]}
    code, summary, relay = env.run(kev_catalog=catalog)
    # macOS is out (wa6n): an exploited out entry starts nothing, and is never held
    assert code == 0 and env.state()["held"] == [] and "out=1" in summary
    assert not [c for c in relay.calls if not c[2].startswith("Daily digest")]


@pytest.mark.parametrize("body", [
    "{not json",
    json.dumps({"vulnerabilities": []}),
    json.dumps({"items": [], "vulnerabilities": [{"vulnerabilityName": "SYNTHETIC TEST"}]}),
    json.dumps({"vulnerabilities": [{"cveID": "CVE-2026-0001", "vulnerabilityName": "Real bug"}]}),
    json.dumps({"vulnerabilities": [{"cveID": "CVE-2026-0001", "vulnerabilityName": "SYNTHETIC TEST"}]}),
])
def test_kev_file_refused_exits_2(tmp_path, capsys, body):
    cfg = tmp_path / "config.toml"
    cfg.write_text(f'ledger = "{tmp_path / "ledger.json"}"\nkev_cache = "{tmp_path / "kev.json"}"\n' + RELAY_TOML)
    bad = tmp_path / "kev.json.in"
    bad.write_text(body)
    assert main.main(["run", "--config", str(cfg), "--kev-file", str(bad)]) == 2
    assert "config error: kev file" in capsys.readouterr().err
    assert not (tmp_path / "ledger.json").exists()


def test_synthetic_fixture_says_so():
    c = inputs.read_kev_file(SYNTHETIC)
    assert [v["cveID"] for v in c["vulnerabilities"]] == ["CVE-2099-0010"]


def test_synthetic_advisory_is_left_out_of_the_digest(env):
    catalog = inputs.read_kev_file(SYNTHETIC)
    code, summary, relay = env.run(kev_catalog=catalog, digest_now=True)  # the same run digests it
    assert code == 0 and "digest=1" in summary
    (body,) = [c[2] for c in relay.calls if c[2].startswith("Daily digest")]
    assert body == ("Daily digest for 2026-11-05: no new alerts. 0 notices added to the catalog this week:"
                    " https://buzz.ai-tools.md/alerts/")  # ai-tools-alerts#d3f6; qwpw: the quiet line
    env.kev.catalog = {"vulnerabilities": [kev_item(cve="CVE-2099-0003")]}  # any input: the id decides
    _, _, relay = env.run(now=at(6, 6))
    assert relay.calls and all(c[2].startswith("HIGH (SYNTHETIC TEST)") for c in relay.calls)  # no fix: high


def test_kev_floor_without_watermark_is_the_state_floor(env):
    env.run(kev=FakeKEV(status=503))  # first run: state since = Nov 3, KEV down
    for day in (6, 7, 8, 9):
        env.run(now=at(day, 6), kev=FakeKEV(status=503))
    assert env.state()["kev_since"] is None
    env.kev.catalog = {"vulnerabilities": [kev_item(added="2026-11-04")]}
    code, _, relay = env.run(now=at(10, 6))
    assert code == 0 and chans(relay) == [("feed", None)]  # not lost to the outage; high until its fix (9kgk)


def test_digest_now_while_a_digest_is_journaled(env, capsys):
    env.collector([MAC])
    env.run()
    code, _, relay = env.run(now=at(5, 9), relay=FakeRelay("unknown"))
    assert code == 1 and len(env.state()["outbox"]) == 1
    capsys.readouterr()
    code, summary, relay = env.run(now=at(5, 10), digest_now=True)
    assert relay.calls == [] and "busy=1" in summary
    assert "a digest is journaled and waits to send; --digest-now does nothing" in capsys.readouterr().err
    assert env.state()["digest_ids"] == []


def test_digest_ids_longer_than_ten_refused(env):
    env.run()
    st = env.state()
    st["digest_ids"] = [f"{i:064x}" for i in range(11)]
    env.config.state.write_text(json.dumps(st))
    code, summary, _ = env.run(now=T0 + 3600)
    assert code == 1 and "error=ledger" in summary


def test_reserved_alias_never_marks_or_silences_a_real_advisory(env):
    env.collector([finding(aliases=("CVE-2099-1234",))])
    code, _, relay = env.run()
    assert code == 0 and relay.calls[0][2].startswith("HIGH: Claude Code")  # not marked
    (e,), _ = env.ledger()
    assert "CVE-2099-1234" not in e["aliases"]
    env.collector([finding(aliases=("CVE-2099-1234",), fixed="2.2.0")])
    code, summary, relay = env.run(now=T0 + 3600)
    assert code == 0 and "replies=1" in summary  # its update still posts


def test_rejected_first_heartbeat_dir_sets_no_mark(env):
    env.heartbeat("2026-11-05T000000Z", [])
    (env.hb / "2026-11-05T000000Z" / "run.json").write_text("[]")
    code, summary, _ = env.run()
    assert code == 0 and "heartbeat:0/1" in summary and env.state()["heartbeat"] is None


@pytest.mark.parametrize("order", [0, 1])
def test_synthetic_never_merges_with_a_real_advisory(env, order, capsys):
    real = finding()
    fake = finding(fid="CVE-2099-0010", aliases=("GHSA-abcd-efgh-ijkl",), fixed=None)
    env.collector([real, fake] if order == 0 else [fake, real])
    env.pages.put(GHSA, advisory_page("GHSA-abcd-efgh-ijkl", title="Remote code execution"))  # one page (dmmf)
    code, summary, relay = env.run(kev_catalog=inputs.read_kev_file(SYNTHETIC))
    assert code == 0, summary
    assert "reserved synthetic id=1" in capsys.readouterr().err
    texts = [c[2] for c in relay.calls]
    assert any(t.startswith("HIGH: Claude Code") and "GHSA-abcd-efgh-ijkl" in t and "CVE-2099" not in t
               for t in texts)  # the real advisory: unmerged, unmarked, not promoted
    assert all(t.startswith("HIGH (SYNTHETIC TEST)") for t in texts if "CVE-2099" in t)  # KEV, no fix: high
    entries, _ = env.ledger()
    real_e = next(e for e in entries if "GHSA-abcd-efgh-ijkl" in [e["advisory"]["id"], *e["aliases"]])
    assert real_e["level"] == "high" and not any("2099" in a for a in real_e["aliases"])


def test_kev_added_on_the_floor_day_is_not_old(env):
    env.config = inputs.Config(ledger=env.config.ledger, kev_cache=env.config.kev_cache, backfill_days=0,
                               **RELAY)
    start = int(dt.datetime(2026, 11, 5, 10, tzinfo=dt.timezone.utc).timestamp())
    env.run(now=start)
    env.kev.catalog = {"vulnerabilities": [kev_item(added="2026-11-05")]}
    code, summary, relay = env.run(now=start + 5 * 3600)
    assert code == 0 and "old=0" in summary and len(relay.calls) == 1  # high (no fix): the feed only


def test_deferred_candidate_dropped_by_scope_reaches_the_review_list(env, monkeypatch):
    # ai-tools-alerts#3r9h: a candidate deferred under an older scope that not_match
    # now excludes leaves the deferred list, and its text is kept for human review.
    env.collector([finding()])
    monkeypatch.setattr(Ledger, "record_root", lambda self, *a, **k: (_ for _ in ()).throw(LedgerError("x")))
    assert env.run()[0] == 1
    monkeypatch.undo()
    st = env.state()
    assert [d["id"] for d in st["deferred"]] == ["GHSA-abcd-efgh-ijkl"]
    st["deferred"][0]["product_text"] = "Npm package System Information Library for Cursor"
    env.config.state.write_text(json.dumps(st))
    env.collector([], name="2026-11-05T020000Z")
    code, _, relay = env.run(now=T0 + 3600)
    assert code == 0 and relay.calls == [] and env.state()["deferred"] == []
    with Ledger(env.config.ledger) as led:
        texts = [r["text"] for r in led._state()["review"]]
    assert "Npm package System Information Library for Cursor" in texts


# ---------------------------------------------------------------- Japanese lang: ja replies (rd8t)


@pytest.mark.parametrize("critical", [False, True])
def test_root_gets_a_japanese_reply_in_each_channel(env, critical):
    kev_fixed(env) if critical else env.collector([finding()])
    code, summary, relay = env.run()
    chs = ["critical", "feed"] if critical else ["feed"]
    assert code == 0 and f"ja={len(chs)} ja_failed=0" in summary and env.state()["outbox"] == []
    assert [(c[0], c[1]) for c in relay.ja] == list(zip(chs, relay.ids))  # each replies to its own root
    head = "緊急" if critical else "重要"
    assert all(c[2].startswith(f"lang: ja\n\n{head}: Claude Code: ") and "```" not in c[2] for c in relay.ja)


def test_change_reply_japanese_names_it_in_of(env):
    first = finding(fid="CVE-2026-0001", fixed=None)
    first["affected"] = "<2.0.0"
    env.kev.catalog = {"vulnerabilities": [kev_item()]}
    env.collector([first])
    _, _, ssh0 = env.run()
    roots = dict(zip(["feed"], ssh0.ids))  # exploited with no fix: high, the feed only (9kgk)
    corrected = finding(fid="CVE-2026-0001", fixed=None)
    corrected["affected"] = "<2.5.0"
    env.collector([corrected])
    code, summary, relay = env.run(now=T0 + 3600)
    assert code == 0 and "replies=1" in summary and "ja=1" in summary
    for (ch, reply_to, text), (ech, _, _), eid in zip(relay.ja, relay.calls, relay.ids):
        assert ch == ech and reply_to == roots[ch]
        assert text.startswith(f"lang: ja\nof: {eid}\n\n") and "（2.5.0 未満）" in text
        # the current version: the source's title is the headline (faxq), the ids on 対象
        assert "\n\n重要: Claude Code: remote code execution\n" in text
        assert "\n対象: アドバイザリ 1 件: CVE-2026-0001, GHSA-abcd-efgh-ijkl\n" in text


def test_digest_gets_a_japanese_reply(env):
    env.collector([finding()])  # qwpw: the daily lists the day's new roots; a held notice is only counted
    env.run()
    code, _, relay = env.run(now=at(5, 9))
    assert code == 0 and len(relay.calls) == 1
    ((ch, reply_to, text),) = relay.ja
    assert (ch, reply_to) == ("feed", relay.ids[0])
    assert text.startswith("lang: ja\n\n2026-11-05 のデイリーダイジェスト: 新しいアラート 1 件。")
    assert "GHSA-abcd-efgh-ijkl" in text


def test_failed_japanese_send_retries_next_hour_without_the_english(env):
    env.collector([finding()])
    code, summary, relay = env.run(relay=FakeRelay(ja=["fail"]))
    assert code == 0 and "roots=1" in summary and "ja=0 ja_failed=1" in summary
    (it,) = env.state()["outbox"]
    assert it["kind"] == "ja" and it["key"] == "root:Claude Code:GHSA-abcd-efgh-ijkl:feed:ja"
    assert env.ledger()[1] == []  # a failed send is not in flight
    code, summary, ssh2 = env.run(now=T0 + 3600)
    assert code == 0 and ssh2.calls == [] and "ja=1" in summary
    assert ssh2.ja == [("feed", relay.ids[0], it["text"])] and env.state()["outbox"] == []


def test_unknown_japanese_send_never_holds_english_work(env):
    env.collector([finding()])
    code, summary, relay = env.run(relay=FakeRelay(ja=["unknown"]))
    assert code == 0 and "ja_failed=1" in summary
    (p,) = env.ledger()[1]
    assert p["key"].endswith(":ja") and p["aliases"] == []  # matches no advisory id
    # A new alias arrives (one spelled like the journal's id too): the English reply still posts.
    env.collector([finding(fid="CVE-2026-0002", aliases=("GHSA-abcd-efgh-ijkl", f"ja {p['key']}"),
                           sources=(GHSA, GHSA2), fixed="2.1.1")])  # 8ke5: a reply needs a real change
    code, summary, relay = env.run(now=T0 + 3600)
    assert code == 0 and "replies=1" in summary and "busy=1" in summary  # the unknown ja waits
    assert [c[2].startswith("lang: ja\nof: ") for c in relay.ja] == [True]


def test_journal_item_from_before_rd8t_loads_and_sends(env):
    env.collector([finding()])
    env.run(relay=FakeRelay("fail"))
    st = env.state()
    del st["outbox"][0]["ja"]  # the shape the poster before rd8t journals
    env.config.state.write_text(json.dumps(st))
    code, summary, relay = env.run(now=T0 + 3600)
    assert code == 0 and "roots=1" in summary and relay.ja == []


def test_each_english_reply_keeps_its_own_japanese_reply(env):
    env.collector([finding()])
    env.run()
    env.collector([finding(fid="CVE-2026-0002", aliases=("GHSA-abcd-efgh-ijkl",), sources=(GHSA, GHSA2),
                           fixed="2.1.1")])  # 8ke5: a reply needs a real change
    _, _, ssh1 = env.run(now=T0 + 3600, relay=FakeRelay(ja=["fail"]))
    env.collector([finding(fid="CVE-2026-0003", aliases=("GHSA-abcd-efgh-ijkl",), fixed="2.1.2")])
    _, summary, ssh2 = env.run(now=T0 + 7200, relay=FakeRelay(ja=["fail"]))  # the older one fails again
    ja = [o for o in env.state()["outbox"] if o["kind"] == "ja"]  # a refused one goes last in line
    assert [o["text"].split("\n")[1] for o in ja] == [f"of: {ssh2.ids[0]}", f"of: {ssh1.ids[0]}"]
    st = env.state()
    st["outbox"][0]["sent"] = "cd" * 32  # a crash after the id was journaled: finished, never resent
    env.config.state.write_text(json.dumps(st))
    _, summary, ssh3 = env.run(now=T0 + 9000)  # before the digest hour
    assert "ja=2" in summary and len(ssh3.ja) == 1 and env.state()["outbox"] == []


def test_japanese_sends_start_after_marks_and_deferred_are_saved(env, monkeypatch):
    env.collector([finding()])
    env.run(relay=FakeRelay("unknown"))  # the root is in flight: the next candidate is deferred
    env.collector([finding()])
    seen = []
    monkeypatch.setattr(main.Run, "drain_ja", lambda self: seen.append(env.state()))
    env.run(now=T0 + 3600)
    assert seen == [env.state()] and [d["id"] for d in seen[0]["deferred"]] == ["GHSA-abcd-efgh-ijkl"]


def test_japanese_backlog_is_bounded(env, monkeypatch):
    monkeypatch.setattr(main, "MAX_JA", 1)
    env.collector([finding()])
    env.run(relay=FakeRelay(ja=["fail"]))
    env.collector([finding(fid="CVE-2026-0002", aliases=("GHSA-abcd-efgh-ijkl",), sources=(GHSA, GHSA2),
                           fixed="2.1.1")])  # 8ke5: a reply needs a real change
    _, summary, _ = env.run(now=T0 + 3600, relay=FakeRelay(ja=["fail"]))
    assert [o["kind"] for o in env.state()["outbox"]] == ["ja"]
    assert env.state()["outbox"][0]["key"].startswith("reply:")  # the older root one was dropped
    monkeypatch.setattr(main, "MAX_JA_BYTES", 10)  # over the byte budget, all in flight: not journaled
    env.collector([finding(fid="CVE-2026-0003", aliases=("GHSA-abcd-efgh-ijkl",), fixed="2.1.2")])
    _, summary, relay = env.run(now=T0 + 7200, relay=FakeRelay(ja=["unknown"]))
    assert "ja_failed=2" in summary and env.ledger()[1] == []  # the waiting one dropped, the new one declined
    assert env.state()["outbox"] == [] and relay.ja == []


@pytest.mark.parametrize("missing", ["relay_key_secret", "secrets_helper"])
def test_no_relay_key_refuses_to_run(tmp_path, capsys, missing):
    keep = {k: v for k, v in RELAY.items() if k != missing}
    cfg = tmp_path / "config.toml"
    cfg.write_text(f'ledger = "{tmp_path / "ledger.json"}"\nkev_cache = "{tmp_path / "kev.json"}"\n'
                   + "".join(f'{k} = "{v}"\n' for k, v in keep.items()))
    assert main.main(["run", "--config", str(cfg)]) == 2
    assert "relay_key_secret and secrets_helper must be set" in capsys.readouterr().err
    relay = FakeRelay()
    config = inputs.Config(ledger=tmp_path / "ledger.json", kev_cache=tmp_path / "kev.json", **keep)
    code, summary = main.run(T0, config, send=relay, kev_fetch=FakeKEV(), channels=CHANNELS)
    assert code == 2 and summary.endswith(" error=config") and relay.calls == []
    assert not (tmp_path / "ledger.json").exists()


@pytest.mark.parametrize("key", ["relay_send_wrapper"])
def test_a_config_naming_the_retired_ssh_route_is_refused_by_name(tmp_path, capsys, key):
    cfg = tmp_path / "config.toml"
    cfg.write_text(f'ledger = "{tmp_path / "ledger.json"}"\n' + RELAY_TOML + f'{key} = "x"\n')
    assert main.main(["run", "--config", str(cfg)]) == 2
    err = capsys.readouterr().err
    assert key in err and "retired" in err and not (tmp_path / "ledger.json").exists()


def test_the_real_sender_is_built_from_the_config_and_the_manifest(tmp_path, monkeypatch):
    seen = {}

    class Relay:
        def __init__(self, url, key_source, *, expected_pubkey):
            seen.update(url=url, pub=expected_pubkey, key_source=key_source)

        def send(self, *a):
            raise AssertionError("not sent in this test")
    monkeypatch.setattr(main.transport, "Relay", Relay)
    monkeypatch.setattr(main.translate, "read_key",
                        lambda helper, *, name: seen.update(helper=helper, name=name) or "00")
    config = inputs.Config(ledger=tmp_path / "l.json", relay_url="https://relay.example.net", **RELAY)
    main.relay_sender(config)
    assert seen["url"] == "https://relay.example.net"
    bot = [p.pubkey for p in main.pull.bundled_manifest().posters if p.role == "relay-bot"]
    assert [seen["pub"]] == bot
    seen["key_source"]()
    assert seen["helper"] == RELAY["secrets_helper"] and seen["name"] == "RELAY_TEST_NSEC"


def test_a_key_helper_failure_reaches_the_sender_as_key_unavailable(tmp_path, monkeypatch):
    def broken(helper, *, name):
        raise main.translate.CallError("api key unavailable (get_secret exit 1)")
    monkeypatch.setattr(main.translate, "read_key", broken)
    send = main.relay_sender(inputs.Config(ledger=tmp_path / "l.json", **RELAY))
    r = send(CHANNELS["feed"], "x")
    assert r.outcome == "failed" and "relay key unavailable" in r.stderr


def test_a_manifest_without_one_relay_bot_is_a_config_error(tmp_path, monkeypatch):
    monkeypatch.setattr(main.pull, "bundled_manifest", lambda: None)
    with pytest.raises(inputs.ConfigError, match="relay-bot"):
        main.relay_sender(inputs.Config(ledger=tmp_path / "l.json", **RELAY))


def test_run_sets_strip_hosts_from_config(env, monkeypatch):
    monkeypatch.setattr(main.candidates, "FLEET_HOSTS", ())
    monkeypatch.setattr(main.candidates, "INTERNAL_SUFFIXES", ())
    env.config = replace(env.config, strip_hosts=("hostalpha",), internal_host_suffixes=(".corp.example",))
    env.run()
    assert main.candidates.FLEET_HOSTS == ("hostalpha",)
    assert main.candidates.INTERNAL_SUFFIXES == (".corp.example",)


def test_loaded_config_sets_relay_and_strip_hosts(env, monkeypatch):
    monkeypatch.setattr(main.candidates, "FLEET_HOSTS", ())
    cfg = env.hb.parent / "config.toml"
    cfg.write_text(f'ledger = "{env.config.ledger}"\nkev_cache = "{env.config.kev_cache}"\n'
                   f'collector_runs = "{env.col}"\nstrip_hosts = ["hostalpha"]\n'
                   'relay_url = "https://relay.example.net"\n' + RELAY_TOML)
    env.collector([finding(), finding(fid="GHSA-zzzz-zzzz-zzzz", product="Claude Code on hostalpha")])
    built = []
    fake = FakeRelay()
    monkeypatch.setattr(main, "relay_sender", lambda c: built.append(c) or fake)
    code, _ = main.run(T0, cfg, kev_fetch=env.kev, page=env.pages, channels=CHANNELS)
    assert code == 0 and fake.calls
    assert (built[0].relay_url, built[0].relay_key_secret) == ("https://relay.example.net", "RELAY_TEST_NSEC")
    assert not any("GHSA-zzzz-zzzz-zzzz" in text or "hostalpha" in text for _, _, text in fake.calls)


def test_empty_strip_hosts_warns(env, capsys):
    env.run()
    assert "warning: strip_hosts is empty" in capsys.readouterr().err
    env.config = replace(env.config, strip_hosts=("hostalpha",))
    env.run(now=T0 + 3600)
    assert "strip_hosts" not in capsys.readouterr().err


# ------------------------------------------- digest exclusions (ai-tools-alerts#d3f6)

def test_digest_leaves_out_withdrawn_ledger_posts(env, monkeypatch):
    env.collector([finding()])
    env.run()  # a high root, digested at 09:00
    env.mirror.publish_manifest(retracted=["ghsa-ABCD-efgh-ijkl"])
    _, _, relay = env.run(now=at(5, 9))
    assert [c[2] for c in relay.calls] == ["Daily digest for 2026-11-05: no new alerts. 0 notices added to the"
                                           " catalog this week: https://buzz.ai-tools.md/alerts/"]  # qwpw
    m = env.mirror  # a curator thread, retracted by a reply or expired by its amendment
    r = m.root_post(m.cur_sec, advisory(aliases=["CVE-2026-7777"]), created_at=T0 - 300)  # not ahead of the run
    m.reply(m.cur_sec, r, "retract\nwrong", created_at=T0 - 200)
    old = m.root_post(m.cur_sec, advisory(id="AITA-TEST-0002", posted_at=T0 - 9, expires_at=T0 - 1),
                      created_at=T0 - 100)
    with main.Ledger(env.config.ledger) as led:
        ids, roots = main.Run(T0, env.config, led, inputs.load_state(env.config.state, T0, 3),
                              CHANNELS, FakeRelay(), None)._withdrawn(m.root, m.fetch)
    assert ids == {"ghsa-abcd-efgh-ijkl"} and roots == {r["id"], old["id"]}  # a thread: by root only
    # c1g2: a curator's retraction of a relay-bot thread is withdrawn for its 14 days, then the bot's again
    b = m.root_post(m.bot_sec, advisory(id="AITA-TEST-0003", posted_by="relay-bot"), created_at=T0 - 20 * 86400)
    m.reply(m.cur_sec, b, "retract", created_at=T0 - 14 * 86400)
    with main.Ledger(env.config.ledger) as led:
        withdrawn = lambda now: main.Run(now, env.config, led, inputs.load_state(env.config.state, now, 3),  # noqa: E731
                                         CHANNELS, FakeRelay(), None)._withdrawn(m.root, m.fetch)[1]
        assert b["id"] in withdrawn(T0) and b["id"] not in withdrawn(T0 + 1)
    env.collector([finding(fid="GHSA-mnop-qrst-uvwx", sources=(GHSA2,)),  # one id, two products, each
                   finding(fid="GHSA-mnop-qrst-uvwx", product="Cursor IDE", severity="high",  # on its own vendor's page
                           sources=("https://cursor.com/security/ghsa-mnop",))])
    env.run(now=at(6, 6))
    e = next(e for e in env.ledger()[0] if e["aliases"][0] == "GHSA-mnop-qrst-uvwx" and e["scope"] == "Claude Code")
    monkeypatch.setattr(main.Run, "_withdrawn", lambda self, root, fetch: (set(), {e["channel_ids"]["feed"]}))
    _, _, relay = env.run(now=at(6, 9))  # the poster's own root, by its thread; the other product's stays
    # qwpw: the other product's is a held notice, counted in the quiet line and kept for the weekly summary
    assert relay.calls[0][2] == ("Daily digest for 2026-11-06: no new alerts. 1 notice added to the catalog"
                                 " this week: https://buzz.ai-tools.md/alerts/")
    assert [h["scope"] for h in env.state()["held"]] == ["Cursor"]


def test_failed_mirror_pull_holds_the_digest(env, capsys):
    env.collector([finding()])
    env.run()

    def down(url):
        raise OSError("down")
    code, summary, relay = env.run(now=at(5, 9), mirror_fetch=down)
    assert code == 0 and relay.calls == [] and " digest_held=1 " in summary and env.state()["digest_date"] != "2026-11-05"
    assert "digest held: mirror pull: unreachable" in capsys.readouterr().err
    _, _, relay = env.run(now=at(5, 10))
    assert "GHSA-abcd-efgh-ijkl" in relay.calls[0][2]


# ---------------------------------------------------------------- r7hr: the source title

TOCTOU = "TOCTOU Race in Edit Tool Allows File Writes Outside the Workspace"


def _cfe8(title=TOCTOU):
    """Shaped like the 2026-11-07T012306Z collector record's CVE-2026-88968 finding."""
    f = finding(fid="CVE-2026-88968", severity="high", fixed="2.1.251", sources=(GHSA, "https://example.org/write-up"),
                aliases=("GHSA-abcd-efgh-ijkl",), affected="<2.1.0")
    f["sources"][0]["title"] = title
    f["sources"][1]["title"] = "a non-primary source's words"
    return f


def test_root_and_digest_carry_the_source_title(env):
    env.collector([_cfe8()])
    _, _, relay = env.run()
    root = relay.calls[0][2].split("\n")
    assert root[0] == f"HIGH: Claude Code: {TOCTOU}" and "CVE-2026-88968" in root[3]  # faxq: the title is the headline
    assert relay.ja[0][2].split("\n")[2] == f"重要: Claude Code: {TOCTOU}"  # the head, in English as the source wrote it
    assert env.ledger()[0][0]["source_title"] == TOCTOU
    _, _, relay = env.run(now=at(5, 9))
    assert f"(CVE-2026-88968): {TOCTOU};" in relay.calls[0][2]


def test_a_title_learned_later_posts_nothing_and_reaches_the_digest(env):
    # 9kgk: with no title the page's prose is its severity word, which sets nothing; the
    # record's verified trojanized flag (it cites the vendor's page alone) makes the high here.
    flagged = lambda f: {**f, "trojanized": True, "sources": f["sources"][:1]}  # noqa: E731
    env.collector([flagged(_cfe8(title=None))])
    _, _, relay = env.run()
    assert relay.calls[0][2].split("\n")[1].startswith("Affected:")  # exactly as before r7hr
    assert "source_title" not in env.ledger()[0][0]
    env.collector([flagged(_cfe8())])
    _, _, relay = env.run(now=T0 + 600)
    assert relay.calls == []  # no reply for a title
    assert env.ledger()[0][0]["source_title"] == TOCTOU


def test_a_fence_in_the_title_never_withholds_the_advisory(env):
    env.collector([_cfe8(title="Race ~~~aitools-alert ``` in Edit writes outside the workspace")])
    _, _, relay = env.run()
    assert relay.calls and relay.calls[0][2].split("\n")[0] == \
        "HIGH: Claude Code: Race ~aitools-alert in Edit writes outside the workspace"  # k5tr: no backtick


def test_a_held_notice_keeps_its_title_and_the_weekly_counts_it(env):
    low = finding(severity=None, fixed=None)  # a notice: the vendor's page rates it low
    env.collector([low])
    assert "held=1" in env.run()[1] and "source_title" not in env.state()["held"][0]
    low["sources"][0]["title"] = "Kernel memory corruption"  # the vendor's page gains a title
    env.collector([low])
    env.run(now=T0 + 600)
    assert env.state()["held"][0]["source_title"] == "Kernel memory corruption"
    # qwpw: a notice is not listed in the daily; Monday's weekly summary counts it, no title or id
    _, _, relay = env.run(now=at(9, 9))
    assert "Weekly summary: 1 notice added" in relay.calls[0][2] and "- Claude Code: 1" in relay.calls[0][2]
    assert "Kernel memory corruption" not in relay.calls[0][2]
    assert env.state()["held"] == [] and "Claude Code|ghsa-abcd-efgh-ijkl" in env.state()["digested"]


# ---------------------------------------------------------------- withheld (ai-tools-alerts#8acj)

THREE = [finding(), finding(fid="GHSA-zzzz-zzzz-zzzz", fixed="2.1.1"),
         finding(fid="GHSA-yyyy-yyyy-yyyy", fixed="2.1.2")]  # faxq: three fixes, three threads


def test_a_refused_item_is_withheld_and_the_run_goes_on(env, capsys):
    env.collector(THREE)
    code, summary, relay = env.run(relay=FakeRelay("refuse", ja=("refuse",)))  # a refused ja reply is dropped
    assert code == 0 and "withheld=1" in summary and "roots=2" in summary and "ja=1 ja_failed=1" in summary
    st, (entries, pending) = env.state(), env.ledger()
    assert st["collector"] and len(entries) == 2 and not pending and not st["outbox"] and len(st["deferred"]) == 1
    assert st["withheld"][0]["message"] == "relay error: blocked mention" and "GHSA-abcd" in st["withheld"][0]["key"]
    assert capsys.readouterr().err.count("withheld=1 refused by the relay") == 1
    env.collector([finding()])
    code, summary, relay = env.run(now=T0 + 3600)  # never resent; its advisory waits
    assert code == 0 and relay.calls == [] and "busy=1" in summary and len(env.state()["deferred"]) == 1
    assert "withheld=1 refused by the relay" in capsys.readouterr().err


def test_a_refused_root_withholds_its_copy(env):
    kev_fixed(env)
    code, summary, relay = env.run(relay=FakeRelay("refuse"))
    assert code == 0 and chans(relay) == [("critical", None)] and "withheld=1" in summary
    assert [it["kind"] for it in env.state()["withheld"][0]["items"]] == ["root", "copy"] and not env.state()["outbox"]


def test_a_refused_digest_blocks_new_digests_until_resolved(env):
    env.collector([MAC]), env.run()
    assert "withheld=1" in env.run(now=at(5, 9), relay=FakeRelay("refuse"))[1] and env.state()["digest_date"] is None
    assert env.run(now=at(5, 10))[2].calls == []  # neither resent nor rebuilt


def test_pending_lists_and_resolve_requeues_or_drops_a_withheld_item(env, tmp_path, capsys, monkeypatch):
    env.collector(THREE[:2])
    assert env.run(relay=FakeRelay("refuse", "refuse"))[0] == 1  # a second refusal in one run stops it
    w, w2 = env.state()["withheld"]
    code, lines = main.pending(T0 + 60, env.config)
    assert code == 0 and lines[-1].endswith("orphan=0 withheld=2")
    assert lines[0] == f"{w['key']} kind=root channel=feed withheld_at=2026-11-04T21:20:00Z outcome=refused " \
        "message=relay error: blocked mention" and w["items"][0]["text"] not in "\n".join(lines)
    assert main.resolve(T0, env.config, "root:x:y:feed", requeue=True)[0] == 2
    monkeypatch.setattr(main.time, "time", lambda: T0 + 60)
    cfg = tmp_path / "config.toml"
    cfg.write_text(f'ledger = "{env.config.ledger}"\nkev_cache = "{env.config.kev_cache}"\n')
    assert main.main(["resolve", w["key"], "--config", str(cfg), "--requeue"]) == 0
    assert env.state()["withheld"] == [w2] and env.state()["outbox"][-1] == w["items"][0]
    code, summary, relay = env.run(now=T0 + 3600)  # requeued as the operator asked; w2's advisory still waits
    assert code == 0 and "roots=1" in summary and relay.calls[0][2] == w["items"][0]["text"]
    assert main.main(["resolve", w2["key"], "--config", str(cfg), "--drop"]) == 0
    assert env.state()["withheld"] == [] and "dropped 1 item(s)" in capsys.readouterr().out
    assert "roots=1" in env.run(now=T0 + 7200)[1]  # its deferred candidate is planned anew


def test_a_withheld_reply_holds_its_thread_under_any_alias(env):
    env.collector([finding(aliases=("CVE-2026-0042",))]), env.run()
    env.collector([finding(fixed="2.2.0")])
    assert "withheld=1" in env.run(now=T0 + 600, relay=FakeRelay("refuse"))[1]
    env.collector([finding(fid="CVE-2026-0042", fixed="2.2.0")])  # the same update under the alias alone
    assert env.run(now=T0 + 1200)[2].calls == [] and len(env.state()["withheld"]) == 1


def test_japanese_roots_carry_the_candidates_exploited_state(env, monkeypatch):  # 4yr1
    """A thread keeps its first title unless its level rises, so the title can miss a
    KEV entry: every Japanese root rendering gets the candidate's exploited flag."""
    seen = []
    real = main.compose.root_post_ja

    def spy(*a, **kw):
        seen.append(kw.get("exploited"))
        return real(*a, **kw)

    monkeypatch.setattr(main.compose, "root_post_ja", spy)
    first = finding(fid="CVE-2026-0001", fixed=None)
    first["affected"] = "<2.0.0"
    env.kev.catalog = {"vulnerabilities": [kev_item()]}
    env.collector([first])
    env.run()
    corrected = finding(fid="CVE-2026-0001", fixed=None)
    corrected["affected"] = "<2.5.0"
    env.collector([corrected])
    _, summary, relay = env.run(now=T0 + 3600)
    assert "replies=1" in summary and len(seen) == 2 and all(s is True for s in seen)  # the root, then the reply
    # (9kgk: exploited with no fix is high, so the thread is in the feed only)
    assert all("対応: 悪用が確認されています。" in text for _, _, text in relay.ja)


def test_kev_learned_on_a_flagged_thread_replies_and_makes_the_japanese_action_urgent(env):  # 4yr1, s6mt, 9kgk
    """A verified trojanized release with no fix is high: a model's reading never makes a
    critical (s6mt). KEV listing it later, still with no fix, keeps it high (9kgk: a
    critical needs a complete action) and replies; the Japanese advisory says it is exploited."""
    first = finding(fid="CVE-2026-0001", fixed=None, affected="<99.0.0")  # a range: the hold for a bare high is not this test's
    first["trojanized"] = True
    env.collector([first])
    _, summary, relay = env.run()
    assert "roots=1" in summary and chans(relay) == [("feed", None)]
    assert relay.calls[0][2].startswith("HIGH: Claude Code: remote code execution\n")  # faxq: the page's title
    assert "Covers 1 advisory: CVE-2026-0001, GHSA-abcd-efgh-ijkl" in relay.calls[0][2]
    (e,), _ = env.ledger()
    assert e["level"] == "high" and e["advisory"]["title"] == "Claude Code: trojanized release (CVE-2026-0001)"
    env.kev.catalog = {"vulnerabilities": [kev_item()]}
    code, summary, relay = env.run(now=T0 + 3600)
    # 9kgk: exploited with no fix known stays high (no copy); learning it still replies.
    assert code == 0 and "copies=0" in summary and "replies=1" in summary and "ja=1" in summary
    (e,), _ = env.ledger()
    assert e["level"] == "high"
    assert relay.ja
    for _, _, text in relay.ja:
        assert "対応: 悪用が確認されています。出典に回避策があれば適用し、修正版が出るまで続けてください。" in text


def test_a_level_rise_copy_gets_the_exploited_flag(env, monkeypatch):  # 4yr1
    seen = []
    real = main.compose.root_post_ja
    monkeypatch.setattr(main.compose, "root_post_ja",
                        lambda *a, **kw: seen.append(kw.get("exploited")) or real(*a, **kw))
    env.collector([finding(fid="GHSA-abcd-efgh-ijkl", aliases=("CVE-2026-0001",), affected="<2.1.0")])
    # 9kgk: the thread states its fix, so a KEV listing of it is critical with that upgrade
    _, summary, _ = env.run()
    assert "roots=1" in summary and seen == [False]  # high, not exploited
    env.kev.catalog = {"vulnerabilities": [kev_item()]}
    _, summary, _ = env.run(now=T0 + 3600)
    assert "copies=1" in summary and seen[1:] == [True, True]  # the copy, then the reply


def test_a_change_in_the_digest_run_is_listed_that_day_only(env):  # 8ke5
    """Live 11-10/11-11: a reply recorded in the digest's own run was listed again the
    next day, because a digest that took everything recorded no roots at its cutoff."""
    env.collector([bare_high(fixed=None, affected="<2.1.0")])
    assert "roots=1" in env.run()[1]
    env.collector([bare_high(fixed="2.1.0")])  # the fix, in the 09:20 run
    _, summary, relay = env.run(now=at(5, 9))
    assert "replies=1" in summary and [c[2].startswith("Daily digest") for c in relay.calls] == [False, True]
    assert "GHSA-abcd-efgh-ijkl" in relay.calls[1][2]
    _, _, relay = env.run(now=at(6, 9))
    assert len(relay.calls) == 1 and "GHSA-abcd-efgh-ijkl" not in relay.calls[0][2]


def test_a_source_only_change_is_not_listed_again(env):  # 8ke5
    env.collector([finding()])
    env.run()
    _, _, relay = env.run(now=at(5, 9))
    assert "GHSA-abcd-efgh-ijkl" in relay.calls[0][2]
    env.collector([finding(sources=(GHSA, GHSA2))])
    _, summary, relay = env.run(now=at(5, 12))
    assert "replies=0" in summary and relay.calls == []
    _, _, relay = env.run(now=at(6, 9))
    assert len(relay.calls) == 1 and "GHSA-abcd-efgh-ijkl" not in relay.calls[0][2]


SOCIAL = "https://mastodon.social/@bot/1"


def test_an_unconfirmed_notice_is_never_held_and_the_vendors_own_is_listed_once(env, capsys):  # 8ke5, h340
    """A sighting no authoritative source confirms is not held, not digested and not
    remembered; the vendor's own advisory for it, later, is held and listed."""
    env.collector([{**MAC, "sources": [{"url": SOCIAL, "published_at": None}]}])
    assert "held=0" in env.run()[1] and "no authoritative source=1" in capsys.readouterr().err
    _, _, relay = env.run(now=at(5, 9))
    assert "CVE-2026-5000" not in relay.calls[0][2]
    st = env.state()
    assert st["held"] == [] and st["deferred"] == [] and not [k for k in st["digested"] if "cve-2026-5000" in k]
    env.collector([{**MAC, "fixed": "27.2"}])  # Cursor's own advisory
    assert "held=1" in env.run(now=at(5, 12))[1]
    (h,) = env.state()["held"]
    assert h["adv"]["sources"][0]["url"] == APPLE
    assert "27.2" not in json.dumps(h["adv"])  # the record's version is not the vendor page's
    _, _, relay = env.run(now=at(9, 9))  # qwpw: listed once, as a count in Monday's weekly summary
    assert "Weekly summary: 1 notice added" in relay.calls[0][2] and "- Cursor: 1" in relay.calls[0][2]
    st = env.state()
    assert st["held"] == [] and "Cursor|cve-2026-5000" in st["digested"]


def test_a_primary_source_learned_while_held_reaches_the_digest(env):  # 8ke5
    env.collector([{**MAC, "sources": [{"url": SOCIAL, "published_at": None}]}])
    env.run()
    env.collector([MAC])
    env.run(now=T0 + 3600)
    (h,) = env.state()["held"]
    assert [s["url"] for s in h["adv"]["sources"]] == [APPLE]
    _, _, relay = env.run(now=at(5, 9))  # qwpw: listable, so it stays held and is counted
    assert "no new alerts. 1 notice added" in relay.calls[0][2] and len(env.state()["held"]) == 1
    _, _, relay = env.run(now=at(9, 9))  # and Monday's weekly summary acknowledges it
    assert "Weekly summary: 1 notice added" in relay.calls[0][2]
    assert env.state()["held"] == [] and "Cursor|cve-2026-5000" in env.state()["digested"]


def test_a_held_notice_keeps_the_ids_the_vendor_page_assigns(env):  # 8ke5 delta, h340
    env.pages.put(GHSA, advisory_page("GHSA-abcd-efgh-ijkl", package="Claude Code", ecosystem=None,
                                      cve="CVE-2026-5001", severity="Low"))
    env.collector([finding(fid="CVE-2026-5001", severity=None, fixed=None, aliases=("GHSA-mmmm-nnnn-pppp",))])
    env.run()
    (h,) = env.state()["held"]  # the page's GHSA is learned; the record's unassigned alias is not
    assert h["adv"]["id"] == "CVE-2026-5001" and h["adv"]["aliases"] == ["GHSA-abcd-efgh-ijkl"]
    assert [s["url"] for s in h["adv"]["sources"]] == [GHSA]
    env.run(now=at(9, 9))  # qwpw: Monday's weekly summary acknowledges it under every id
    assert {"Claude Code|cve-2026-5001", "Claude Code|ghsa-abcd-efgh-ijkl"} <= set(env.state()["digested"])
    env.collector([finding(severity=None, fixed=None)])  # the GHSA alone, later: listed once only
    summary = env.run(now=at(9, 12))[1]
    assert "candidates=1 " in summary and " old=0 " in summary and " held=0 " in summary
    assert env.state()["held"] == []


# ---------------------------------------------------------------- 0dvh: hold, age, severity

def _roots(ssh):
    return [c for c in ssh.calls if c[1] is None and not c[2].startswith("Daily digest")]


def test_a_high_with_no_fix_waits_and_posts_with_its_fix(env):  # 0dvh
    env.collector([bare_high(fixed=None)])
    _, summary, ssh = env.run()
    assert "waiting=1" in summary and _roots(ssh) == []
    assert list(env.state()["waiting"]) == ["Claude Code|ghsa-abcd-efgh-ijkl"]  # saved: a restart keeps it
    env.collector([bare_high(fixed="2.1.0")])  # the next run reads the fix
    _, summary, ssh = env.run(now=T0 + 3600)
    assert "roots=1" in summary and len(_roots(ssh)) == 1 and "Do: upgrade Claude Code to 2.1.0 or later." in _roots(ssh)[0][2]
    assert env.state()["deferred"] == []
    _, summary, ssh = env.run(now=T0 + 7200)
    assert ssh.calls == []  # posted once


def test_a_hold_ends_after_six_hours_with_what_is_known(env):  # 0dvh
    env.collector([bare_high(fixed=None)])
    env.run()
    _, summary, ssh = env.run(now=T0 + main.HOLD_SECONDS - 60)
    assert "waiting=1" in summary and _roots(ssh) == []
    _, summary, ssh = env.run(now=T0 + main.HOLD_SECONDS)
    assert "roots=1" in summary and "Do: apply the source's workaround" in _roots(ssh)[0][2] and "or later" not in _roots(ssh)[0][2]
    assert env.state()["deferred"] == []


@pytest.mark.parametrize("kind", ["kev", "range"])
def test_these_never_wait(env, kind):  # 0dvh: a KEV entry (critical, exploited), a high with a range
    if kind == "kev":
        env.kev.catalog = {"vulnerabilities": [kev_item()]}
    else:
        env.collector([bare_high(fixed=None, affected="<2.1.0")])
    _, summary, ssh = env.run()
    assert "waiting=0" in summary and _roots(ssh), summary


def test_a_full_waiting_map_holds_nothing_new(env, monkeypatch):  # 0dvh: never a state it refuses
    monkeypatch.setattr(main.inputs, "MAX_WAITING", 1)
    env.collector([bare_high(fixed=None),
                   bare_high(fid="GHSA-mnop-qrst-uvwx", fixed=None, sources=(GHSA2,))])
    _, summary, ssh = env.run()
    assert "waiting=1" in summary and len(_roots(ssh)) == 1 and len(env.state()["waiting"]) == 1


def test_an_old_source_posts_no_root_and_reaches_the_digest_notices(env):  # 0dvh
    old = bare_high(fixed=None)
    old["sources"][0]["published_at"] = "2026-10-20T00:00:00Z"  # 16 days before first sight
    env.collector([old])
    _, summary, ssh = env.run()
    assert "aged=1" in summary and ssh.calls == []
    fixed = bare_high(fixed="2.1.0")
    fixed["sources"][0]["published_at"] = None  # the date comes from the held notice
    env.collector([fixed])
    _, summary, ssh = env.run(now=T0 + 3600)
    assert "aged=1" in summary and ssh.calls == []
    env.collector([bare_high(fixed=None, affected="<2.1.0")])  # no fix: the fix stays
    env.run(now=T0 + 7200)
    p = env.state()["held"][0]["adv"]["products"][0]
    assert (p["fixed"], p["affected"]) == ("2.1.0", "<2.1.0")
    _, _, ssh = env.run(now=at(6, 9))  # qwpw: the daily counts the notice; it stays held
    assert "no new alerts. 1 notice added" in ssh.calls[0][2] and len(env.state()["held"]) == 1
    _, _, ssh = env.run(now=at(9, 9))  # Monday's weekly summary lists it, as a count
    assert "Weekly summary: 1 notice added" in ssh.calls[0][2] and "- Claude Code: 1" in ssh.calls[0][2]
    assert env.state()["held"] == [] and "Claude Code|ghsa-abcd-efgh-ijkl" in env.state()["digested"]


def test_first_sight_as_a_notice_dates_the_age_limit(env):  # 0dvh
    note = finding(severity=None, fixed=None)  # no severity word: a notice
    note["sources"][0]["published_at"] = "2026-10-30T00:00:00Z"  # six days before T0
    env.collector([note])
    env.run()
    assert env.state()["held"]
    env.collector([{**note, "fixed": "2.1.0", "advisory_severity": "remote code execution"}])
    _, summary, ssh = env.run(now=T0 + 2 * 86400 - 3600)  # eight days after the source; before the digest
    assert "aged=0" in summary and "roots=1" in summary and len(_roots(ssh)) == 1


def test_an_old_critical_posts_in_neither_channel(env, monkeypatch):  # 0dvh
    monkeypatch.setattr(main.rules, "level_for", lambda c, scope, ok: ("critical", "trojanized-primary"))
    old = finding(fixed="2.1.0")
    old["sources"][0]["published_at"] = "2026-10-01"
    env.collector([old])
    _, summary, ssh = env.run()
    assert "aged=1" in summary and "roots=0" in summary and "copies=0" in summary and ssh.calls == []


def test_the_japanese_root_says_a_range_is_in_the_source(env):  # 0dvh
    env.collector([bare_high(fixed=None, affected=">=1.0 || <0.5")])
    _, _, ssh = env.run()
    assert "affected versions: see the source" in _roots(ssh)[0][2]
    assert "影響バージョンは出典を参照" in ssh.ja[0][2]


def test_the_block_carries_the_vendor_pages_severity_word(env):  # 0dvh, dmmf: the page's, never the record's
    env.collector([finding(severity="low")])
    env.pages.put(GHSA, advisory_page("GHSA-abcd-efgh-ijkl", severity="Critical", title="Remote code execution"))
    _, _, ssh = env.run()
    assert schema.parse_post(_roots(ssh)[0][2]).advisory_severity == "critical"


def test_a_records_severity_rates_but_never_reaches_the_block(env):  # dmmf, h340 criterion 4
    """The page states no severity word; the record, citing only the vendor's page, says
    "critical". It may rate the advisory (h340 keeps it for the level); the block says nothing."""
    env.collector([bare_high()])
    env.pages.put(GHSA, advisory_page("GHSA-abcd-efgh-ijkl", severity="Unrated", title=""))
    _, summary, ssh = env.run()
    assert "roots=1" in summary
    adv = schema.parse_post(_roots(ssh)[0][2])
    assert adv.level == "high" and adv.advisory_severity is None and "critical" not in _roots(ssh)[0][2].lower()


def test_a_severity_change_rides_a_reply_and_never_posts_alone(env):  # 0dvh, dmmf: the page's word
    def page(sev, patched):
        env.pages.put(GHSA, advisory_page("GHSA-abcd-efgh-ijkl", severity=sev, affected="< 2.1.0", patched=patched))
    low = {**finding(fixed=None, severity="low"), "trojanized": True}  # 9kgk: a high with no fix
    env.collector([low])
    page("High", None)
    _, summary, _ = env.run()
    assert "roots=1" in summary  # a range is stated: no hold
    env.collector([low])
    page("Critical", None)
    _, summary, ssh = env.run(now=T0 + 600)
    assert "replies=0" in summary and ssh.calls == []
    env.collector([low])
    page("Critical", "2.1.0")
    _, summary, ssh = env.run(now=T0 + 1200)
    assert "replies=1" in summary and "Upstream severity: critical." in ssh.calls[0][2]


# ---------------------------------------------------------------- 0dvh review fixes

def test_a_kev_listing_of_an_old_advisory_still_posts(env):  # 0dvh: KEV's listing is the news
    old = finding(fid="CVE-2026-0001", aliases=("GHSA-abcd-efgh-ijkl",), fixed=None, severity="high")
    old["sources"][0]["published_at"] = "2026-09-01T00:00:00Z"
    env.collector([old])
    env.kev.catalog = {"vulnerabilities": [kev_item()]}
    _, summary, ssh = env.run()
    assert "aged=0" in summary and "roots=1" in summary and "copies=0" in summary  # 9kgk: no fix, high


def test_first_sight_outlives_the_digest_that_lists_the_notice(env):  # 0dvh
    note = finding(severity=None, fixed=None)
    note["sources"][0]["published_at"] = "2026-10-30T00:00:00Z"  # six days before T0
    env.collector([note])
    env.run()
    _, _, ssh = env.run(now=at(9, 9))  # qwpw: Monday's weekly summary lists it; the held entry goes
    assert env.state()["held"] == [] and "Weekly summary: 1 notice added" in ssh.calls[0][2]
    env.collector([{**note, "fixed": "2.1.0", "advisory_severity": "remote code execution"}])
    _, summary, ssh = env.run(now=at(10, 6))  # eleven days after the source, five after first sight
    assert "aged=0" in summary and "roots=1" in summary


def test_a_waiting_candidate_survives_a_run_that_dies(env, monkeypatch):  # 0dvh
    env.collector([bare_high(fixed=None)])
    monkeypatch.setattr(main.Run, "digest", lambda self, **kw: (_ for _ in ()).throw(RuntimeError("boom")))
    code, summary, _ = env.run()
    assert code == 1 and "waiting=1" in summary
    assert [d["id"] for d in env.state()["deferred"]] == ["GHSA-abcd-efgh-ijkl"]
    monkeypatch.undo()
    env.collector([bare_high(fixed="2.1.0")])
    _, summary, ssh = env.run(now=T0 + 3600)
    assert "roots=1" in summary and "Do: upgrade Claude Code to 2.1.0 or later." in _roots(ssh)[0][2]


def test_a_fieldless_sighting_keeps_the_notice_fix_and_first_sight(env, capsys):  # 0dvh, dmmf
    """The held notice's fix is the vendor page's. A later sighting of the same advisory
    that a vendor site page confirms (no fields) loses none of it."""
    env.pages.put(GHSA, advisory_page("GHSA-abcd-efgh-ijkl", cve="CVE-2026-5001", severity="Low",
                                      affected="< 2.1.0", patched="2.1.0"))
    env.collector([finding(severity=None, fixed=None)])
    assert "held=1" in env.run()[1]
    stamp = env.state()["held"][0]["adv"]["posted_at"]
    env.collector([finding(fid="CVE-2026-5001", severity=None, fixed=None,
                           sources=("https://www.anthropic.com/security/cve-2026-5001",))])
    capsys.readouterr()
    _, summary, _ = env.run(now=T0 + 7200)
    assert "roots=0" in summary and "skipped" not in capsys.readouterr().err  # confirmed, merged
    (h,) = env.state()["held"]
    h = h["adv"]
    assert h["products"][0]["fixed"] == "2.1.0" and h["products"][0]["affected"] == "<2.1.0"
    assert h["actions"] and h["posted_at"] == stamp and h["sources"][0]["url"] == GHSA


def test_a_spaced_timestamp_dates_the_age_limit(env):  # 0dvh
    old = bare_high(fixed=None)
    old["sources"][0]["published_at"] = "2026-10-01 00:00:00Z"
    env.collector([old])
    _, summary, ssh = env.run()
    assert "aged=1" in summary and ssh.calls == []


def test_a_hold_keeps_its_place_when_the_primary_id_changes(env, monkeypatch):  # 0dvh
    monkeypatch.setattr(main.inputs, "MAX_WAITING", 1)
    env.collector([bare_high(fixed=None, aliases=("CVE-2026-0002",))])
    env.run()
    env.collector([bare_high(fid="CVE-2026-0002", fixed=None, aliases=("GHSA-abcd-efgh-ijkl",))])
    _, summary, ssh = env.run(now=T0 + 3600)
    assert "waiting=1" in summary and _roots(ssh) == []


def test_a_reply_says_a_range_is_in_the_source(env):  # 0dvh
    env.collector([bare_high(fixed=None, affected=">=1.0 || <0.5")])
    env.run()
    env.collector([bare_high(fixed="2.1.0", affected=">=1.0 || <0.5")])
    _, summary, ssh = env.run(now=T0 + 600)
    assert "replies=1" in summary and "affected versions: see the source" in ssh.calls[0][2]
    assert "影響バージョンは出典を参照" in ssh.ja[0][2]


def test_a_spaced_timestamp_survives_in_the_held_notice(env):  # 0dvh delta review
    old = bare_high(fixed=None)
    old["sources"][0]["published_at"] = "2026-10-01 00:00:00Z"
    env.collector([old])
    env.run()
    assert env.state()["held"][0]["adv"]["sources"][0]["published_at"] == "2026-10-01T00:00:00Z"
    env.collector([bare_high(fixed="2.1.0")])  # undated this time
    _, summary, ssh = env.run(now=T0 + 3600)
    assert "aged=1" in summary and ssh.calls == []


def test_a_date_learned_while_held_is_kept_for_a_later_undated_sighting(env):  # dmmf review
    low = finding(severity=None, fixed=None)  # undated: a held notice
    env.collector([low])
    assert "held=1" in env.run()[1]
    dated = bare_high(fixed="2.1.0")
    dated["sources"][0]["published_at"] = "2026-10-01T00:00:00Z"  # 35 days before T0
    env.collector([dated])
    assert "aged=1" in env.run(now=T0 + 600)[1]
    env.collector([bare_high(fixed="2.1.0")])  # undated again
    _, summary, ssh = env.run(now=T0 + 1200)
    assert "aged=1" in summary and "roots=0" in summary and ssh.calls == []


def test_first_sight_is_the_run_that_deferred_on_a_failed_fetch(env):  # dmmf review
    """Seen six days after its source, its page failing for two days: judged at six days."""
    young = bare_high(fixed="2.1.0")
    young["sources"][0]["published_at"] = "2026-10-30T00:00:00Z"  # six days before T0
    env.collector([young])
    env.pages.put(GHSA, "", status=503)
    assert "roots=0" in env.run()[1] and env.state()["deferred"]
    del env.pages.fixed[GHSA]
    _, summary, _ = env.run(now=T0 + 2 * 86400)
    assert "aged=0" in summary and "roots=1" in summary


def test_an_unconfirmed_alias_never_takes_another_advisorys_first_sight(env):  # dmmf delta review
    other = "https://github.com/anthropics/claude-code/security/advisories/GHSA-mnop-qrst-uvwx"
    env.pages.put(GHSA, "", status=503)
    env.collector([finding(severity=None, fixed=None)])  # A: deferred, first sight now
    env.run(now=T0 - 3 * 86400)
    b = finding(fid="GHSA-mnop-qrst-uvwx", aliases=("GHSA-abcd-efgh-ijkl",), fixed="2.1.0")
    b["sources"][0]["published_at"] = "2026-10-30T00:00:00Z"  # six days before T0
    env.collector([b])  # B claims A's id; its page fails too
    env.pages.put(other, "", status=503)
    env.run()
    assert "Claude Code|ghsa-mnop-qrst-uvwx" in env.state()["waiting"]
    del env.pages.fixed[other]
    _, summary, _ = env.run(now=T0 + 2 * 86400)  # B judged at six days, not eight
    assert "aged=0" in summary and "roots=1" in summary


def test_the_hold_counts_from_the_run_that_deferred_on_a_failed_fetch(env):  # dmmf review
    env.collector([bare_high(fixed=None)])
    env.pages.put(GHSA, "", status=503)
    env.run()
    del env.pages.fixed[GHSA]  # seven hours later the page answers, still with no fix
    _, summary, _ = env.run(now=T0 + 7 * 3600)
    assert "waiting=0" in summary and "roots=1" in summary


# ---------------------------------------------------------------- h340: only what an authoritative source says

ROUTER = "https://github.com/musistudio/claude-code-router/security/advisories/GHSA-evil-evil-evil"
VENDOR_SITE = "https://www.anthropic.com/security/advisory-7"


def _nothing_was_signed(env, relay):
    """No post, no thread, no held notice, nothing kept for later, and an empty digest."""
    st = env.state()
    assert relay.calls == [] and relay.ja == [] and env.ledger()[0] == []
    assert st["held"] == [] and st["deferred"] == [] and st["outbox"] == [] and st["digested"] == []
    _, _, relay = env.run(now=at(5, 9))
    assert [c[2] for c in relay.calls] == ["Daily digest for 2026-11-05: no new alerts. 0 notices added to the"
                                           " catalog this week: https://buzz.ai-tools.md/alerts/"]  # qwpw


def _router(**kw):
    """The finding of the issue body: a GitHub advisory for a package its author owns."""
    f = finding(fid="GHSA-evil-evil-evil", product="claude-code-router", severity="high", fixed="99.0.0",
                sources=(ROUTER,))
    f["sources"][0]["title"] = "URGENT: run the installer from the link below"
    return {**f, **kw}


@pytest.mark.parametrize("variant", [
    {},  # as published: the name is not a product
    {"product": "claude-code"},  # the text is exactly a product's identity: no authoritative source says so
    {"product": "Claude Code", "package": {"ecosystem": "npm", "name": "claude-code-router"}},  # the package decides
    {"product": "claude-code", "sources": [{"url": ROUTER, "published_at": None},
                                           {"url": GHSA2, "published_at": None}]},  # the vendor's page for another advisory
    {"product": "claude-code", "aliases": ["GHSA-mnop-qrst-uvwx"],
     "sources": [{"url": GHSA2, "published_at": None}]},  # the vendor's advisory B claimed as an alias of A
    {"product": "claude-code", "sources": [{"url": "https://github.com/advisories/GHSA-evil-evil-evil",
                                            "published_at": None}]},  # the global page anyone's advisory reaches
    {"product": "claude-code", "sources": [{"url": VENDOR_SITE, "published_at": None}], "id": "LEAD-1"},
])
def test_claude_code_router_advisory_never_names_claude_code(env, variant):
    env.pages.put(GHSA2, advisory_page("GHSA-mnop-qrst-uvwx", cve="CVE-2026-0042"))  # a real one, of the vendor
    env.pages.put(ROUTER, advisory_page("GHSA-evil-evil-evil", package="claude-code-router", ecosystem="npm",
                                        affected="< 99.0.0", patched="99.0.0", repo="musistudio/claude-code-router"))
    env.collector([_router(**variant)])
    code, summary, relay = env.run()
    assert code == 0 and "roots=0" in summary and "held=0" in summary, summary
    _nothing_was_signed(env, relay)


def test_a_kev_entry_for_another_vendors_product_binds_to_no_tier1_product(env):
    env.kev.catalog = {"vulnerabilities": [{"cveID": "CVE-2026-0001", "vendorProject": "musistudio",
                                            "product": "claude-code-router", "dateAdded": "2026-11-04"}]}
    code, summary, relay = env.run()
    assert code == 0 and "in_scope=0" in summary
    _nothing_was_signed(env, relay)


def _poisoned():
    """A record about the vendor's real advisory whose every claim is someone else's."""
    f = finding(fid="CVE-2026-0007", product="claude-code", severity="critical", fixed="99.0.0",
                aliases=("CVE-2026-0666", "GHSA-evil-evil-evil"), sources=(GHSA, ROUTER))
    f["sources"][0]["title"] = "URGENT: run the installer from the link below"
    return {**f, "affected": "<99.0.0", "trojanized": True, "injection_exec": True}


@pytest.mark.parametrize("severity,race,level", [  # 9kgk: the severity word alone sets nothing
    ("Moderate", "Race in the Edit tool", "notice"), ("High", "Race in the Edit tool", "notice"),
    ("High", "Race in the Edit tool writes outside the workspace", "high")])
def test_a_record_about_a_real_advisory_posts_what_the_vendor_page_says(env, severity, race, level):
    env.pages.put(GHSA, advisory_page("GHSA-abcd-efgh-ijkl", cve="CVE-2026-0007", affected=">= 1.0, < 2.1.251",
                                      patched="2.1.251", severity=severity, title=race))
    env.collector([_poisoned()])
    code, summary, relay = env.run()
    assert code == 0, summary
    if level == "notice":
        (h,), text = env.state()["held"], json.dumps(env.state())
        adv, title = h["adv"], h["source_title"]
        assert relay.calls == []
    else:
        (e,), _ = env.ledger()
        adv, title, text = e["advisory"], e["source_title"], relay.calls[0][2]
        assert text.split("\n")[:4] == [f"HIGH: Claude Code: {race}",  # faxq: the title is the headline
                                        "Affected: `@anthropic-ai/claude-code` from 1.0 and before 2.1.251 (npm).",
                                        "Do: upgrade Claude Code to 2.1.251 or later.",
                                        "Covers 1 advisory: CVE-2026-0007, GHSA-abcd-efgh-ijkl"]
    # The level, version, range, title, ids and sources are the page's; the record's are gone.
    assert adv["level"] == level and title == race
    assert adv["products"] == [{"name": "Claude Code", "ecosystem": "claude-code", "affected": ">=1.0,<2.1.251",
                                "fixed": "2.1.251"}]
    assert adv["aliases"] == ["GHSA-abcd-efgh-ijkl"] and [s["url"] for s in adv["sources"]] == [GHSA]
    for theirs in ("99.0.0", "URGENT", "installer", "CVE-2026-0666", "evil", "musistudio", "trojanized"):
        assert theirs not in text, theirs


def test_fixed_is_read_from_the_page_not_picked_from_it(env):
    """The page says "affects 1.0 to 2.0, fixed in 3.0". A record that names 2.0, a version
    on that page, as the fix changes nothing."""
    env.pages.put(GHSA, advisory_page("GHSA-abcd-efgh-ijkl", affected=">= 1.0, <= 2.0", patched="3.0",
                                      title="Remote code execution"))
    env.collector([{**finding(fixed="2.0"), "affected": "<2.0"}])
    _, _, relay = env.run()
    assert "Do: upgrade Claude Code to 3.0 or later." in relay.calls[0][2] and "to 2.0 or later" not in relay.calls[0][2]
    assert "Affected: `@anthropic-ai/claude-code` from 1.0 and up to 2.0 (npm)." in relay.calls[0][2]


def test_an_advisory_for_another_package_in_the_products_repository_is_dropped(env, capsys):
    env.pages.put(GHSA, advisory_page("GHSA-abcd-efgh-ijkl", package="Claude Desktop", ecosystem="anthropic"))
    env.collector([finding()])
    _, summary, relay = env.run()
    assert "roots=0" in summary and "vendor page names another package=1" in capsys.readouterr().err
    _nothing_was_signed(env, relay)


def test_a_vendor_site_page_alone_makes_a_notice_whatever_the_record_says(env):
    """A site page confirms by naming the id and the product; it binds nothing by a field.
    So the record's severity, flags and version count for nothing there."""
    f = finding(fid="CVE-2026-0100", severity="critical", fixed="9.9", sources=(VENDOR_SITE,))
    env.collector([{**f, "trojanized": True, "injection_exec": True}])
    _, summary, relay = env.run()
    assert "roots=0" in summary and "held=1" in summary and relay.calls == []
    (h,) = env.state()["held"]
    assert h["adv"]["level"] == "notice" and h["adv"]["products"][0]["fixed"] is None and h["adv"]["actions"] == []
    assert h["adv"]["title"] == "Claude Code: security advisory (CVE-2026-0100)"
    assert [s["url"] for s in h["adv"]["sources"]] == [VENDOR_SITE]


def test_a_url_on_the_vendors_host_that_nobody_read_is_never_signed(env):
    """Only the page that confirmed the advisory is listed. A record cannot ride text into
    the block in the path or query of another URL on the vendor's host."""
    junk = ("https://www.anthropic.com/security?notice=UPGRADE-TO-99.0.0-via-npx-claude-code-router",
            "https://github.com/anthropics/claude-code/security/advisories/run-npx-claude-code-router-99",
            "https://www.anthropic.com/security/run-npx-claude-code-router")
    env.collector([finding(sources=(GHSA, *junk))])
    _, _, relay = env.run()
    assert "router" not in relay.calls[0][2] and [s["url"] for s in env.ledger()[0][0]["advisory"]["sources"]] == [GHSA]
    assert not [u for u in env.pages.calls if "?" in u]  # a URL with a query is never fetched


def test_a_page_that_echoes_its_query_confirms_nothing(env, capsys):
    echo = "https://nodejs.org/en/search?q=CVE-2026-99999+node.js"
    env.pages.put(echo, '<html>No results for "CVE-2026-99999 node.js"</html>')
    env.collector([{**finding(fid="CVE-2026-99999", product="node.js", sources=(echo,)), "trojanized": True}])
    _, summary, relay = env.run()
    assert "roots=0" in summary and "no authoritative source=1" in capsys.readouterr().err and env.pages.calls == []
    _nothing_was_signed(env, relay)


def test_a_model_read_flag_counts_only_from_a_record_that_cites_the_vendors_advisory_alone(env):
    pure = {**finding(fid="GHSA-aaaa-aaaa-aaaa", severity=None, fixed=None, affected="<99.0.0"), "trojanized": True}
    mixed = {**finding(fid="GHSA-bbbb-bbbb-bbbb", severity=None, fixed=None, sources=(REPO + "GHSA-bbbb-bbbb-bbbb", ROUTER)),
             "trojanized": True}
    junk = {**finding(fid="GHSA-cccc-cccc-cccc", severity=None, fixed=None,
                      sources=(REPO + "GHSA-cccc-cccc-cccc", "https://www.anthropic.com/security/unread")), "trojanized": True}
    env.collector([pure, mixed, junk])
    _, summary, relay = env.run()
    assert chans(relay) == [("feed", None)] and "held=2" in summary  # s6mt: the flag raises to high, never critical
    assert relay.calls[0][2].startswith("HIGH: Claude Code: trojanized release\n")  # faxq: no id in the headline
    assert "Covers 1 advisory: GHSA-aaaa-aaaa-aaaa" in relay.calls[0][2]
    assert sorted(h["adv"]["id"] for h in env.state()["held"]) == ["GHSA-bbbb-bbbb-bbbb", "GHSA-cccc-cccc-cccc"]


@pytest.mark.parametrize("status,body,why", [(503, "", "source fetch failed, deferred=1"), (0, "", "source fetch failed"),
                                             (403, "", "source fetch failed"), (429, "", "source fetch failed"),
                                             (200, "<html>new markup</html>", "advisory page not parsed, deferred=1")])
def test_a_failed_fetch_or_an_unparsed_page_defers_and_never_drops(env, capsys, status, body, why):
    env.pages.put(GHSA, body, status=status)
    env.collector([finding()])
    for hour in (0, 1, 24 * 9):  # still waiting nine days on: no age rule of the gate's own drops it
        code, summary, relay = env.run(now=T0 + 3600 * hour)
        assert code == 0 and relay.calls == [] and why in capsys.readouterr().err
        assert [d["id"] for d in env.state()["deferred"]] == ["GHSA-abcd-efgh-ijkl"] and env.ledger()[0] == []
    del env.pages.fixed[GHSA]  # the page answers
    _, summary, relay = env.run(now=T0 + 3600 * 24 * 9 + 3600)
    assert "roots=1" in summary and env.state()["deferred"] == []
    assert "Do: upgrade Claude Code to 2.1.0 or later." in relay.calls[0][2]


def test_a_page_that_says_no_is_dropped_not_retried(env, capsys):
    env.pages.put(GHSA, "", status=404)
    env.collector([finding()])
    _, _, relay = env.run()
    assert "no authoritative source=1" in capsys.readouterr().err
    _nothing_was_signed(env, relay)


def test_the_page_budget_defers_the_rest_to_the_next_run(env, capsys, monkeypatch):
    monkeypatch.setattr(main, "MAX_RUN_PAGES", 2)
    env.collector([finding(), finding(fid="GHSA-zzzz-zzzz-zzzz", fixed="2.1.3"),
                   finding(fid="GHSA-yyyy-yyyy-yyyy", fixed="2.1.4")])  # faxq: three fixes, three threads
    _, summary, relay = env.run()
    assert "roots=2" in summary and "page budget, deferred=1" in capsys.readouterr().err
    assert len(env.pages.calls) == 2 and [d["id"] for d in env.state()["deferred"]] == ["GHSA-yyyy-yyyy-yyyy"]
    _, summary, _ = env.run(now=T0 + 3600)
    assert "roots=1" in summary and env.state()["deferred"] == [] and len(env.ledger()[0]) == 3
    env.collector([finding(fixed="2.1.1")])  # one fetch per URL per run, whatever cites it
    before = len(env.pages.calls)
    env.run(now=T0 + 7200)
    assert len(env.pages.calls) == before + 1


def test_state_written_before_the_gate_sends_nothing_composed_before_it(env, capsys):
    """An old deferred candidate, held notice, unsent root and withheld item are removed on
    the first run; a root that was sent and not yet recorded is recorded; a send whose
    outcome is unknown still waits for resolve."""
    from dataclasses import asdict
    from aitools_alerts.poster import compose, rules
    from test_compose import cand  # a candidate the old poster would have composed as it stood
    scope = rules.scope_of("claude code")

    def item(n, kind="root", sent=None):
        c = cand(id=f"CVE-2026-900{n}", aliases=(), fixed="99.0.0")
        text, adv = compose.root_post(c, ("high", None), scope, posted_at=T0 - 60)
        return {"key": f"{kind}:Claude Code:{c.id}:feed", "kind": kind, "scope": "Claude Code", "ids": [c.id],
                "channel": "feed", "text": text, "adv": asdict(adv), "exploited": False, "date": None,
                "sent": sent, "root": None}, c

    (unsent, c1), (sent, _), (unknown, _), (refused, _) = item(1), item(2, sent="ab" * 32), item(3), item(4)
    ja = {**item(5)[0], "kind": "ja", "key": "x:ja", "ids": ["ja x"], "adv": None, "text": "lang: ja\n\n本文", "root": "cd" * 32}
    old = inputs.new_state(T0, 3)
    del old["gate"]
    old.update(deferred=[c1.to_dict()], held=[{"scope": "Claude Code", "adv": unsent["adv"]}],
               outbox=[unsent, sent, unknown, ja],
               withheld=[{"key": refused["key"], "items": [refused], "message": "blocked", "at": T0 - 60}])
    env.config.state.parent.mkdir(parents=True, exist_ok=True)
    inputs.save_state(env.config.state, old)
    with Ledger(env.config.ledger) as led:
        led.pending(unknown["key"], unknown["ids"], now=T0 - 60)
        # A thread of the old poster: it learned an id and a source from a record nobody confirmed.
        thread = compose.root_post(cand(id="CVE-2026-8000", aliases=("CVE-2026-8001",)), ("high", None), scope,
                                   posted_at=T0 - 600)[1]
        led.record_root(thread, "ef" * 32, {"feed": "ef" * 32}, scope="Claude Code", exploited=False, now=T0 - 600,
                        ids=["CVE-2026-8000", "CVE-2026-8001", "CVE-2026-0666"],
                        source_title="URGENT: run the installer from the link below")
        led.learn_sources("ef" * 32, [main.schema.Source(ROUTER, None)])
    code, summary, relay = env.run()
    st, err = env.state(), capsys.readouterr().err
    assert ("gate: first run under the authoritative-source rule; removed 1 deferred, 1 held, 1 withheld, 1 unsent; "
            "1 thread(s) forgot unpublished ids, sources and titles") in err
    assert st["gate"] == 1 and st["deferred"] == [] and st["held"] == [] and st["withheld"] == []
    assert [o["key"] for o in st["outbox"]] == [unknown["key"]]  # in flight: pending / resolve settle it
    assert relay.calls == [] and "99.0.0" not in "".join(t for _, _, t in relay.ja)  # nothing old was sent in English
    old_thread, recorded = env.ledger()[0]
    assert recorded["advisory"]["id"] == "CVE-2026-9002"  # the sent one is only recorded
    assert old_thread["aliases"] == ["CVE-2026-8000", "CVE-2026-8001"] and "learned_sources" not in old_thread
    assert "source_title" not in old_thread  # a record's title, learned and never posted: no digest prints it
    with Ledger(env.config.ledger) as led:  # a fix makes the digest list the thread again: without that title
        led.record_reply("ef" * 32, thread, {"feed": "aa" * 32}, now=T0 + 60)
    _, _, relay = env.run(now=at(5, 9))
    assert "CVE-2026-8000" in relay.calls[0][2] and "URGENT" not in relay.calls[0][2] and "installer" not in relay.calls[0][2]
    assert "gate:" not in capsys.readouterr().err  # the migration ran once


def test_a_fresh_state_is_already_past_the_gate(env, capsys):
    env.collector([MAC])
    env.run()
    assert env.state()["gate"] == 1 and "gate:" not in capsys.readouterr().err and len(env.state()["held"]) == 1


def test_sources_a_thread_learned_before_the_gate_are_listed_only_if_the_vendors(env):
    env.collector([{**finding(fixed=None, affected="< 2.1.1"), "trojanized": True}])  # a range: posts now (0dvh)
    env.run()
    with Ledger(env.config.ledger) as led:
        (e,) = led._state()["entries"]
        led.learn_sources(e["root_event_id"], [main.schema.Source("https://example.org/write-up", None),
                                               main.schema.Source(ROUTER, None), main.schema.Source(GHSA2, None)])
    env.collector([{**finding(fixed="2.1.1"), "trojanized": True}])  # a fix: a real reply with the learned sources
    _, summary, relay = env.run(now=T0 + 3600)
    assert "replies=1" in summary
    reply = relay.calls[0][2]
    assert "example.org" not in reply and "musistudio" not in reply and GHSA2 in reply


def test_an_unexpressible_vendor_fix_names_no_version_through_a_whole_run(env):
    """The vendor's page states a fix the schema cannot carry: the post sends the reader to
    the fix the source names and names no version, in English and in Japanese."""
    env.pages.put(GHSA, advisory_page("GHSA-abcd-efgh-ijkl", affected="< 2.0.0", patched="2.0.0-rc.1",
                                      title="Remote code execution"))
    env.collector([finding(fixed="2.0.0")])
    _, summary, relay = env.run()
    text, ja = relay.calls[0][2], relay.ja[0][2]
    lines = text.split("\n")
    assert "Affected: `@anthropic-ai/claude-code` before 2.0.0 (npm)." in lines
    assert "Do: upgrade Claude Code to the fixed release the source names." in lines  # faxq: names no version
    assert "or later" not in text and "rc.1" not in text and "unexpressed" not in text
    assert "出典に記載された修正版に更新してください" in ja and "以降に更新" not in ja and "rc.1" not in ja
    assert env.ledger()[0][0]["advisory"]["actions"] == [] and env.ledger()[0][0]["advisory"]["products"][0]["fixed"] is None


def test_failing_pages_ahead_never_starve_a_healthy_candidate(env, monkeypatch):
    """Two pages that fail on every run and a budget of two: the third candidate is still
    reached, because the deferred ones take turns going first."""
    monkeypatch.setattr(main, "MAX_RUN_PAGES", 2)
    bad = ["GHSA-aaaa-aaaa-aaaa", "GHSA-bbbb-bbbb-bbbb"]
    for g in bad:
        env.pages.put(REPO + g, "", status=503)
    env.collector([finding(fid=bad[0]), finding(fid=bad[1]), finding(fid="GHSA-cccc-cccc-cccc")])
    posted = 0
    for hour in range(4):
        _, summary, _ = env.run(now=T0 + 3600 * hour)
        posted += "roots=1" in summary
    assert posted == 1 and [e["advisory"]["id"] for e in env.ledger()[0]] == ["GHSA-cccc-cccc-cccc"]
    assert sorted(d["id"] for d in env.state()["deferred"]) == bad  # still waiting, not dropped


def test_a_kev_entry_posts_though_the_page_budget_is_spent(env, monkeypatch):
    monkeypatch.setattr(main, "MAX_RUN_PAGES", 0)
    env.kev.catalog = {"vulnerabilities": [{**kev_item(), "notes": "https://www.anthropic.com/security/advisory-7"}]}
    _, summary, relay = env.run()
    assert "roots=1" in summary and relay.calls[0][2].startswith("HIGH: Claude Code: known exploited vulnerability")
    assert env.state()["deferred"] == []


# ------------------------------------------------- readings reach the level through admit (s6mt)

def _levelled(env, monkeypatch, **kw):
    """(run result, the candidates level_for was asked about) for one run."""
    seen, real = [], main.rules.level_for
    monkeypatch.setattr(main.rules, "level_for", lambda c, scope, ok: seen.append((c, scope)) or real(c, scope, ok))
    return env.run(**kw), seen


def test_admit_puts_the_readings_on_what_the_level_is_computed_from(env, monkeypatch):
    from aitools_alerts import ruleset
    env.collector([finding(fid="CVE-2026-0001", severity="high", affected="<2.1.0")])
    env.kev.catalog = {"vulnerabilities": [kev_item()]}
    # 3qyq: the ghsa reading is the advisory API's answer, and counts for a CVE thread
    # because that answer names the CVE.
    env.api.put("GHSA-abcd-efgh-ijkl", ghsa_json("GHSA-abcd-efgh-ijkl", cwes=(), cve="CVE-2026-0001"))
    (code, summary, relay), seen = _levelled(env, monkeypatch)
    assert code == 0 and "roots=1" in summary and len(seen) == 1
    c, scope = seen[0]
    assert sorted(s for s, _ in c.readings) == ["ghsa", "kev"]
    fields = dict((s, json.loads(t)) for s, t in c.readings)
    assert fields["kev"] == {"cve_id": "CVE-2026-0001", "name": "Anthropic Claude Code"}
    assert fields["ghsa"]["repository"] == "anthropics/claude-code" and fields["ghsa"]["severity"] == "high"
    assert [(p["ecosystem"], p["name"], p["first_patched"]) for p in fields["ghsa"]["packages"]] == [
        ("npm", "@anthropic-ai/claude-code", "2.1.0")]
    claims = main.rules.claims_for(c, scope, T0)
    assert sorted(x["level"] for x in claims) == ["critical", "notice"]  # 9kgk: the page's severity sets nothing
    assert all(ruleset.check_claim(x, scope.name) == "ok" for x in claims)
    assert "readings" not in json.dumps(env.state())  # never in the state file


def test_a_page_confirmed_finding_alone_has_one_ghsa_reading(env, monkeypatch):
    env.collector([finding(severity="high")])
    (_, summary, _), seen = _levelled(env, monkeypatch)
    ((c, scope),) = seen
    assert [s for s, _ in c.readings] == ["ghsa"] and json.loads(c.readings[0][1])["ghsa_id"] == "GHSA-abcd-efgh-ijkl"
    assert main.rules.basis(c, scope, "notice") == "fields"
    assert main.rules.basis(c, scope, "high") == "reading"  # 9kgk: a severity word is no field rule


def test_a_later_run_without_the_flag_lowers_nothing(env):
    first = {**finding(fid="GHSA-aaaa-aaaa-aaaa", severity=None, fixed=None, affected="<99.0.0"), "trojanized": True}
    env.collector([first])
    _, summary, relay = env.run()
    assert "roots=1" in summary and relay.calls[0][2].startswith("HIGH: ")
    env.collector([{**first, "trojanized": False}])  # the model no longer reads it that way
    code, summary, relay = env.run(now=T0 + 3600)
    assert code == 0 and "roots=0" in summary and "replies=0" in summary and relay.calls == []
    (e,), _ = env.ledger()
    assert e["level"] == "high" and e["advisory"]["level"] == "high"


# ---------------------------------------------------------------- scope classes (wa6n)

INSPECTOR = "https://github.com/modelcontextprotocol/inspector/security/advisories/GHSA-4fc4-wcmh-4g86"


def test_a_code_execution_flaw_in_git_posts_at_high_though_git_is_out(env):
    url = "https://github.com/git/git/security/advisories/GHSA-wxyz-wxyz-wxyz"
    rce = finding(fid="GHSA-wxyz-wxyz-wxyz", product="git/git", fixed="2.47.1", sources=(url,), severity="high")
    rce["sources"][0]["title"] = "Remote code execution on recursive clone"  # the vendor page's own words
    env.collector([rce,
                   finding(fid="GHSA-aaaa-zzzz-aaaa", product="git/git", fixed="2.47.2", severity="high",
                           sources=("https://github.com/git/git/security/advisories/GHSA-aaaa-zzzz-aaaa",))])
    code, summary, relay = env.run()
    assert code == 0 and "roots=1" in summary and "out=1" in summary and env.state()["held"] == []
    assert chans(relay) == [("feed", None)] and relay.calls[0][2].startswith("HIGH: git")


def test_a_thread_under_a_former_name_stays_the_advisorys_thread(env):
    """The Inspector was "MCP Inspector" before scope classes: a later sighting under its
    package name reaches that thread, and no second root repeats it to every member."""
    old = schema.ScopeEntry("MCP Inspector", "mcp", "channel", ["mcp inspector"],
                            authority=("github.com/modelcontextprotocol/inspector/",))
    f = finding(fid="GHSA-4fc4-wcmh-4g86", product="npm:@modelcontextprotocol/inspector", severity="high",
                fixed=None, sources=(INSPECTOR,))
    thread = main.compose.root_post(main.inputs.candidate_from({**main.candidates.from_collector(
        {"schema_version": 1, "findings": [f]})[0].to_dict()}), ("high", None), old, posted_at=T0 - 600)[1]
    with Ledger(env.config.ledger) as led:
        led.record_root(thread, "ef" * 32, {"feed": "ef" * 32}, scope="MCP Inspector", exploited=False, now=T0 - 600)
    env.collector([dict(f, fixed="1.0.3")])
    code, summary, relay = env.run()
    entries, _ = env.ledger()
    assert code == 0 and "roots=0" in summary and len(entries) == 1 and entries[0]["scope"] == "MCP Inspector"
    assert all(reply == "ef" * 32 for _, reply, _ in relay.calls), relay.calls
    assert "replies=1" in summary and "Fixed in 1.0.3" in relay.calls[0][2], summary


def test_a_saved_notice_of_an_out_product_is_never_digested(env):
    old = inputs.new_state(T0, 3)
    adv = advisory(id="CVE-2026-7000", level="notice", posted_by="relay-bot", products=[
        schema.Product("OpenSSH", "openssh", None, None)], actions=[])
    old["held"] = [{"scope": "OpenSSH", "adv": main.asdict(adv)}, {"scope": "Claude Code", "adv": main.asdict(adv)}]
    env.config.state.parent.mkdir(parents=True, exist_ok=True)
    inputs.save_state(env.config.state, old)
    env.run()
    assert [h["scope"] for h in env.state()["held"]] == ["Claude Code"]


def test_an_old_code_execution_flaw_in_git_is_never_held(env):
    rce = finding(fid="GHSA-wxyz-wxyz-wxyz", product="git/git", fixed="2.47.1", severity="high",
                  sources=("https://github.com/git/git/security/advisories/GHSA-wxyz-wxyz-wxyz",))
    rce["sources"][0].update(title="Remote code execution on recursive clone", published_at="2026-10-01T00:00:00Z")
    env.collector([rce])
    code, summary, relay = env.run()
    assert code == 0 and "aged=1" in summary and "roots=0" in summary and env.state()["held"] == []


def test_a_notice_held_under_a_former_name_is_not_held_twice(env):
    f = finding(fid="GHSA-4fc4-wcmh-4g86", product="npm:@modelcontextprotocol/inspector", severity=None,
                fixed=None, sources=(INSPECTOR,))
    env.collector([f])
    env.run()
    st = env.state()
    (h,) = st["held"]
    h["scope"] = "MCP Inspector"  # held by the poster before scope classes
    st["waiting"] = {k.replace("@modelcontextprotocol/inspector|", "MCP Inspector|"): t for k, t in st["waiting"].items()}
    env.config.state.write_text(json.dumps(st))
    env.collector([f], name="2026-11-05T020000Z")
    env.run(now=T0 + 3600)
    assert [h["scope"] for h in env.state()["held"]] == ["MCP Inspector"]


def test_a_root_after_a_notice_under_a_former_name_takes_the_current_name(env):
    f = finding(fid="GHSA-4fc4-wcmh-4g86", product="npm:@modelcontextprotocol/inspector", severity=None,
                fixed=None, sources=(INSPECTOR,))
    env.collector([f])
    env.run()
    st = env.state()
    st["held"][0]["scope"] = "MCP Inspector"
    env.config.state.write_text(json.dumps(st))
    rce = dict(f, fixed="1.0.3", advisory_severity="high")
    rce["sources"] = [{"url": INSPECTOR, "published_at": None, "title": "Remote code execution through the proxy"}]
    env.collector([rce], name="2026-11-05T020000Z")
    code, summary, relay = env.run(now=T0 + 3600)
    assert "roots=1" in summary and relay.calls[0][2].startswith("HIGH: `@modelcontextprotocol/inspector`")
    (e,), _ = env.ledger()
    assert e["scope"] == "@modelcontextprotocol/inspector" and e["advisory"]["products"][0]["name"] == e["scope"]


# ---------------------------------------------------------------- 9kgk: a critical needs a complete action

def test_a_journaled_critical_with_no_action_never_posts(env):
    """The outbox of a poster from before 9kgk can hold a critical with no fix and no
    action. It is dropped with its copy, not sent; the candidate is planned again later."""
    kev_fixed(env)
    code, _, _ = env.run(relay=FakeRelay("fail"))
    st = env.state()
    root = next(it for it in st["outbox"] if it["kind"] == "root")
    assert code == 1 and root["adv"]["level"] == "critical" and any(it["kind"] == "copy" for it in st["outbox"])
    root["adv"]["actions"], root["adv"]["products"][0]["fixed"] = [], None  # as the older poster wrote it
    env.config.state.write_text(json.dumps(st))
    env.kev.catalog = {"vulnerabilities": []}
    env.collector([])
    code, summary, relay = env.run(now=T0 + 3600)
    assert code == 0 and "withheld=1" in summary, summary
    # what posts is the candidate the failed run deferred, planned again: with its upgrade
    assert relay.calls and all("Do: upgrade Claude Code to 2.1.0 or later." in c[2] for c in relay.calls)
    assert not [it for it in env.state()["outbox"] if it["kind"] in ("root", "copy")]


def test_a_stop_using_critical_never_raises_a_thread(env, monkeypatch):
    """A reply can carry no stop_using action, so a thread is raised to critical only by
    a fix: a stop_using critical on a known thread stays at action_cap (high)."""
    env.collector([bare_high(fixed=None, affected="<2.1.0")])
    assert "roots=1" in env.run()[1]
    monkeypatch.setattr(main.rules, "level_for", lambda c, scope, ok: ("critical", "stop-using"))
    env.collector([bare_high(fixed=None, affected="<2.1.0")])
    code, summary, relay = env.run(now=T0 + 3600)
    assert code == 0 and "copies=0" in summary and all(c[0] != "critical" for c in relay.calls), summary
    (e,), _ = env.ledger()
    assert e["level"] == "high" and "critical" not in e["channel_ids"]


def test_a_kev_listing_of_a_thread_that_states_its_fix_is_critical(env):
    """The KEV entry states no version, but the thread already does: the upgrade is complete."""
    env.collector([finding(fid="GHSA-abcd-efgh-ijkl", aliases=("CVE-2026-0001",), affected="<2.1.0")])
    assert "roots=1" in env.run()[1]
    env.collector([])
    env.kev.catalog = {"vulnerabilities": [kev_item()]}
    code, summary, relay = env.run(now=T0 + 3600)
    assert code == 0 and "copies=1" in summary and relay.calls[0][0] == "critical", summary
    assert "Do: upgrade Claude Code to 2.1.0 or later." in relay.calls[0][2]


def test_a_standing_critical_with_no_fix_still_takes_its_updates(env, monkeypatch):
    """Stage-1 review: a critical thread posted before this rule with no fix (the OpenSSH
    case) keeps its standing level; a later reply that is not a fix is sent, not dropped."""
    monkeypatch.setattr(main.rules, "level_for", lambda c, scope, ok: ("critical", None))  # as an older poster
    monkeypatch.setattr(main, "_complete", lambda adv: True)  # posted before the outbox guard existed
    env.collector([bare_high(fixed=None, affected="<2.0.0")])
    assert "roots=1" in env.run()[1]
    monkeypatch.undo()
    env.collector([bare_high(fixed=None, affected="<2.5.0")])
    code, summary, relay = env.run(now=T0 + 3600)
    assert code == 0 and "replies=2" in summary and "withheld=0" in summary, summary
    assert all("before 2.5.0" in c[2] for c in relay.calls)


def test_a_stop_using_critical_with_the_threads_fix_raises_it(env, monkeypatch):
    """Stage-1 review: the thread already states its fix, so the upgrade is complete."""
    env.collector([finding(fid="GHSA-abcd-efgh-ijkl", affected="<2.1.0")])
    assert "roots=1" in env.run()[1]
    real = main.rules.level_for
    monkeypatch.setattr(main.rules, "level_for", lambda c, scope, ok: (
        ("critical", "stop-using") if not c.fixed else ("critical", "fields")) if c.trojanized else real(c, scope, ok))
    env.collector([{**finding(fid="GHSA-abcd-efgh-ijkl", fixed=None, affected="<2.1.0"), "trojanized": True}])
    code, summary, relay = env.run(now=T0 + 3600)
    assert code == 0 and "copies=1" in summary and relay.calls[0][0] == "critical", summary
    assert "Do: upgrade Claude Code to 2.1.0 or later." in relay.calls[0][2]


def test_a_fix_reply_never_raises_a_thread_whose_root_had_no_fix(env):
    """Whole-branch review: every reader holds a fix a reply adds where the root had none
    (tyje), so a raise in that reply would leave members a critical with no version.
    The thread stays high with its fix until a source check confirms it."""
    env.kev.catalog = {"vulnerabilities": [kev_item()]}
    assert "roots=1" in env.run()[1]  # exploited, no fix: high
    env.collector([finding(fid="CVE-2026-0001", sources=(GHSA2,))])  # the vendor's fix
    code, summary, relay = env.run(now=T0 + 3600)
    assert code == 0 and "copies=0" in summary and "replies=1" in summary, summary
    assert all(c[0] == "feed" for c in relay.calls) and "Fixed in 2.1.0." in relay.calls[0][2]
    (e,), _ = env.ledger()
    assert e["level"] == "high" and e["root_fixed"] == ""  # the root stated no fix


def test_a_journaled_critical_copy_with_no_action_never_posts(env):
    """Whole-branch review: a known thread's copy keeps no adv; its text's block is checked."""
    kev_fixed(env)
    env.run(relay=FakeRelay("ok", "fail"))  # the critical root sent, the feed copy kept
    st = env.state()
    (cp,) = [it for it in st["outbox"] if it["kind"] == "copy"]
    bare = main.compose.root_post(main.candidates.Candidate(
        id="CVE-2026-0001", aliases=(), product_text="Claude Code", advisory_severity=None, local_level_hint=None,
        exploited=True, trojanized=False, injection_exec=False, fixed=None, affected=None,
        sources=(main.candidates.Source(GHSA, None),), observed_at=None), "critical",
        main.rules.scope_of("Claude Code"), posted_at=T0)  # as an older poster wrote it
    cp["adv"], cp["text"] = None, bare[0]  # a known thread's copy keeps only its text
    env.config.state.write_text(json.dumps(st))
    env.collector([])
    env.kev.catalog = {"vulnerabilities": []}
    code, summary, relay = env.run(now=T0 + 3600)
    assert code == 0 and "withheld=1" in summary, summary  # the old copy dropped; the replanned one acts
    assert all("Do: upgrade Claude Code to 2.1.0 or later." in c[2] for c in relay.calls)


def test_a_journaled_reply_raising_a_thread_to_an_actionless_critical_never_posts(env):
    """Delta review: replies are exempt only on a thread already critical."""
    env.collector([finding(fid="GHSA-abcd-efgh-ijkl", aliases=("CVE-2026-0001",), affected="<2.1.0")])
    assert "roots=1" in env.run()[1]
    env.collector([])
    env.kev.catalog = {"vulnerabilities": [kev_item()]}
    env.run(now=T0 + 3600, relay=FakeRelay("fail"))  # the raise is journaled, nothing sent
    st = env.state()
    (rp,) = [it for it in st["outbox"] if it["kind"] == "reply"]
    assert rp["adv"]["level"] == "critical"
    rp["adv"]["actions"], rp["adv"]["products"][0]["fixed"] = [], None  # as an older poster wrote it
    env.config.state.write_text(json.dumps(st))
    env.kev.catalog = {"vulnerabilities": []}
    code, summary, relay = env.run(now=T0 + 7200)
    assert code == 0 and "withheld=1" in summary, summary  # dropped; the replanned raise carries its upgrade
    assert any(c[0] == "feed" and "Level is now critical." in c[2] for c in relay.calls)


# ---------------------------------------------------------------- faxq: one release, one post

GHSA_Z = "GHSA-zzzz-zzzz-zzzz"


def test_two_advisories_one_release_fixes_are_one_post(env):
    env.collector([finding(), finding(fid=GHSA_Z)])
    code, summary, relay = env.run()
    assert code == 0 and "roots=1" in summary and chans(relay) == [("feed", None)]
    text = relay.calls[0][2]
    assert "Covers 2 advisories: GHSA-abcd-efgh-ijkl, GHSA-zzzz-zzzz-zzzz" in text.split("\n")
    assert "Do: upgrade Claude Code to 2.1.0 or later." in text.split("\n")
    (entry,), _ = env.ledger()
    assert {"GHSA-abcd-efgh-ijkl", GHSA_Z} <= set(entry["aliases"])
    env.collector([finding(fid=GHSA_Z)])  # a member sighted again is the thread's, not a new root
    code, summary, relay = env.run(now=T0 + 3600)
    assert code == 0 and "roots=0" in summary and "replies=0" in summary and relay.calls == []


def test_a_fix_group_that_must_wait_is_kept_as_its_members(env):
    """Busy behind an unknown send: each member is deferred under its own id, so the
    next run admits each from its own page (admit keeps only the ids that page assigns)."""
    env.collector([finding(), finding(fid=GHSA_Z)])
    code, _, _ = env.run(relay=FakeRelay("unknown"))
    assert code == 1
    env.collector([finding(), finding(fid=GHSA_Z)])
    code, summary, _ = env.run(now=T0 + 3600)
    assert "busy=0" not in summary and "roots=0" in summary
    assert sorted(d["id"] for d in env.state()["deferred"]) == ["GHSA-abcd-efgh-ijkl", GHSA_Z]


def test_a_run_never_lowers_a_threads_fix(env):
    """A member sighted again with its own, older fix leaves the thread's later one: an
    upgrade to it fixes every member, and readers apply a reply's fix as sent."""
    env.collector([finding(fixed="3.0")])
    code, summary, _ = env.run()
    assert code == 0 and "roots=1" in summary
    env.collector([finding(fixed="2.1.0")])
    code, summary, relay = env.run(now=T0 + 3600)
    assert code == 0 and "replies=0" in summary and relay.calls == []
    (entry,), _ = env.ledger()
    assert entry["advisory"]["products"][0]["fixed"] == "3.0"


def test_a_held_notice_takes_the_ids_of_its_fix_group(env):
    """A notice held from an earlier run, then met by a fix group: the group's new ids
    join the held notice, so the digest lists them with it (once)."""
    env.collector([finding(severity=None)])
    code, summary, _ = env.run()
    assert "held=1" in summary, summary
    env.collector([finding(severity=None), finding(fid=GHSA_Z, severity=None)])
    code, summary, _ = env.run(now=T0 + 3600)
    assert code == 0 and "roots=0" in summary
    (held,) = env.state()["held"]
    assert GHSA_Z in held["adv"]["aliases"]


def test_one_members_sighting_never_narrows_its_groups_range(env):
    """Review: A affects <2.1.0 and B >=1.5,<2.1.0; the root states <2.1.0. B, or A,
    seen again alone, must not send a reply narrowing it."""
    env.collector([finding(affected="<2.1.0"), finding(fid=GHSA_Z, affected=">=1.5,<2.1.0")])
    code, summary, relay = env.run()
    assert code == 0 and "roots=1" in summary
    assert "Affected: `@anthropic-ai/claude-code` before 2.1.0 (npm)." in relay.calls[0][2].split("\n")
    env.collector([finding(fid=GHSA_Z, affected=">=1.5,<2.1.0")])
    code, summary, relay = env.run(now=T0 + 3600)
    assert code == 0 and "replies=0" in summary and relay.calls == []
    (entry,), _ = env.ledger()
    assert entry["advisory"]["products"][0]["affected"] == "<2.1.0"


def test_a_group_meeting_a_listed_notice_holds_the_rest(env):
    """Review: notice A is listed by a digest; a later run groups A with new notice Z.
    Z is held under its own id and listed once; A is not listed again."""
    env.collector([finding(severity=None)])
    env.run()
    code, summary, _ = env.run(now=at(9, 9))  # qwpw: Monday's weekly summary lists A
    assert "digest=1" in summary and env.state()["held"] == []
    env.collector([finding(severity=None), finding(fid=GHSA_Z, severity=None)])
    code, summary, _ = env.run(now=at(9, 10))
    assert code == 0 and "held=1" in summary
    (held,) = env.state()["held"]
    assert held["adv"]["id"] == GHSA_Z and "GHSA-abcd-efgh-ijkl" not in held["adv"]["aliases"]


def test_a_held_notice_widens_its_range_for_a_member_with_none(env):
    env.collector([finding(severity=None, affected=">=2.0,<2.1.0")])
    env.run()
    env.collector([finding(severity=None, affected=">=2.0,<2.1.0"), finding(fid=GHSA_Z, severity=None)])
    env.run(now=T0 + 3600)
    (held,) = env.state()["held"]
    assert GHSA_Z in held["adv"]["aliases"] and held["adv"]["products"][0]["affected"] is None


def test_an_advisory_with_a_send_in_flight_joins_no_group(env):
    """Review: a root's send outcome is unknown; its advisory and a new one with the same
    fix must not group, or resolving the send would record the new one's ids unnamed."""
    env.collector([finding()])
    code, _, _ = env.run(relay=FakeRelay("unknown"))
    assert code == 1
    env.collector([finding(), finding(fid=GHSA_Z)])
    code, summary, relay = env.run(now=T0 + 3600)
    assert "roots=1" in summary and [c[0] for c in relay.calls] == ["feed"]
    assert "Covers 1 advisory: GHSA-zzzz-zzzz-zzzz" in relay.calls[0][2].split("\n")
    out = [it for it in env.state()["outbox"] if it["kind"] == "root"]
    assert all(GHSA_Z.casefold() not in {i.casefold() for i in it["ids"]} for it in out
               if "abcd" in it["key"])


def test_a_groups_range_widens_for_a_members_later_fix(env):
    """Delta review: A's vendor corrects its fix to 2.2.0 and its range to <2.2.0; the
    group's range must reach 2.1.5, which the new fix covers."""
    env.collector([finding(affected="<2.1.0"), finding(fid=GHSA_Z, affected="<2.1.0")])
    code, summary, _ = env.run()
    assert "roots=1" in summary
    env.collector([finding(affected="<2.2.0", fixed="2.2.0")])
    code, summary, relay = env.run(now=T0 + 3600)
    assert code == 0 and "replies=1" in summary
    (entry,), _ = env.ledger()
    assert entry["advisory"]["products"][0] == {**entry["advisory"]["products"][0], "affected": "<2.2.0", "fixed": "2.2.0"}


def test_a_cve_assigned_after_the_digest_is_not_listed_again(env):
    """Delta review: an id new to a listed advisory is not a new member."""
    env.collector([finding(severity=None)])
    env.run()
    code, summary, _ = env.run(now=at(9, 9))  # qwpw: Monday's weekly summary lists it
    assert "digest=1" in summary and env.state()["held"] == []
    env.collector([finding(severity=None, aliases=("CVE-2026-7777",))])
    code, summary, _ = env.run(now=at(9, 10))
    assert code == 0 and "candidates=1 " in summary and " old=0 " in summary and env.state()["held"] == []


# ------------------------------------- z360: retracting one member of a fix group

from aitools_alerts import pull  # noqa: E402

ZURL = REPO + GHSA_Z


def _on_mirror(env, relay, at_):
    """The roots ``relay`` sent, as the relay bot's events on the test mirror. A real
    relay's event id is the mirror event's: the ledger is given those ids."""
    out, text = [], env.config.ledger.read_text()
    for c, eid in zip(relay.calls, relay.ids):
        if c[1] is None:
            out.append(env.mirror.post(env.mirror.bot_sec, c[2], created_at=at_, files=(f"{c[0]}.json",)))
            text = text.replace(eid, out[-1]["id"])
    env.config.ledger.write_text(text)
    return out


def _retract(env, relay, ids, at_=T0 + 60):
    """The sent roots on the mirror, the manifest retracting ``ids``, and the poster's copy
    pulled (the daily digest pulls it)."""
    roots = _on_mirror(env, relay, at_)
    env.mirror.publish_manifest(retracted=ids)
    code, summary, _ = env.run(now=at(5, 9))
    assert code == 0 and "digest=1" in summary, summary
    return roots


def test_retracting_one_member_reposts_the_others(env):
    """Acceptance: the manifest retracts one advisory of a two-advisory root. The next run
    posts the other as a root of its own, and a member's reader shows it."""
    env.collector([finding(), finding(fid=GHSA_Z)])
    code, summary, relay = env.run()
    assert "roots=1" in summary
    (old,) = _retract(env, relay, ["ghsa-ABCD-efgh-ijkl"])
    code, summary, relay = env.run(now=at(5, 10))
    assert code == 0 and "roots=1" in summary, summary
    ((ch, to, text),) = relay.calls
    assert (ch, to) == ("feed", None) and "Covers 1 advisory: GHSA-zzzz-zzzz-zzzz" in text.split("\n")
    assert "abcd" not in text.casefold()
    (new,) = _on_mirror(env, relay, T0 + 120)
    threads = {t.root_id: t for t in pull.threads_from(env.mirror.events["feed.json"], env.mirror.man)}
    assert threads[old["id"]].retracted and not threads[new["id"]].retracted
    assert threads[new["id"]].adv.id == GHSA_Z  # the member's CLI holds it
    first, second = env.ledger()[0]
    assert first["split"] == {"released": [GHSA_Z], "kept": []} and GHSA_Z not in first["aliases"]
    assert second["aliases"] == [GHSA_Z]
    env.collector([finding(), finding(fid=GHSA_Z)])  # sighted again: the retracted one starts nothing
    code, summary, relay = env.run(now=at(5, 11))
    assert code == 0 and "roots=0" in summary and relay.calls == [], summary


def test_a_single_advisory_retracted_by_its_ghsa_stays_hidden_under_its_cve(env):
    """Its own page assigns the CVE with the retracted GHSA: the CVE is kept, no root."""
    env.collector([finding(aliases=("CVE-2026-0001",))])
    code, summary, relay = env.run()
    assert "roots=1" in summary
    _retract(env, relay, ["GHSA-abcd-efgh-ijkl"])
    env.collector([finding(fid="CVE-2026-0001")])  # a sighting under the CVE
    code, summary, relay = env.run(now=at(5, 10))
    assert code == 0 and "roots=0" in summary and relay.calls == [], summary
    (e,), _ = env.ledger()
    assert e["split"] == {"released": [], "kept": ["CVE-2026-0001"]} and "CVE-2026-0001" in e["aliases"]


def test_a_survivor_whose_page_fails_is_released_by_a_later_run(env):
    env.collector([finding(), finding(fid=GHSA_Z)])
    _, _, relay = env.run()
    _retract(env, relay, ["GHSA-abcd-efgh-ijkl"])
    env.pages.put(ZURL, "", status=503)
    code, summary, relay = env.run(now=at(5, 10))
    assert code == 0 and "roots=0" in summary and "split" not in env.ledger()[0][0]
    del env.pages.fixed[ZURL]
    code, summary, relay = env.run(now=at(5, 11))
    assert code == 0 and "roots=1" in summary and GHSA_Z in relay.calls[0][2]


def test_an_old_survivor_still_posts_a_root(env):
    """0dvh is for news first seen late; a survivor was news when its group posted, which
    the group's newest member made (faxq)."""
    old = finding(fid=GHSA_Z)
    old["sources"][0]["published_at"] = "2026-09-01T00:00:00Z"
    new = finding()
    new["sources"][0]["published_at"] = "2026-11-04T00:00:00Z"
    env.collector([new, old])
    code, summary, relay = env.run()
    assert "roots=1" in summary and "aged=0" in summary
    _retract(env, relay, ["GHSA-abcd-efgh-ijkl"])
    code, summary, relay = env.run(now=at(5, 10))
    assert code == 0 and "roots=1" in summary and "aged=0" in summary, summary


def test_a_relay_bot_alias_in_the_retracted_list_retires_nothing(env):
    """The reader never lets a relay-bot reply's alias pull a thread into the list, so
    neither does the poster."""
    env.collector([finding()])
    _, _, relay = env.run()
    (root,) = _on_mirror(env, relay, T0 + 60)
    env.mirror.reply(env.mirror.bot_sec, root, env.mirror.patch_text(aliases=["CVE-2026-9999"]), created_at=T0 + 70)
    env.mirror.publish_manifest(retracted=["CVE-2026-9999"])
    env.run(now=at(5, 9))
    code, summary, relay = env.run(now=at(5, 10))
    assert code == 0 and relay.calls == [] and "split" not in env.ledger()[0][0]


def test_an_advisory_already_retracted_is_never_planned(env, capsys):
    """Every reader hides a root naming a retracted id: such a candidate is not planned."""
    env.mirror.publish_manifest(retracted=["GHSA-zzzz-zzzz-zzzz"])
    code, summary, _ = env.run(now=at(5, 9))  # the digest pulls the poster's copy
    assert code == 0 and "digest=1" in summary
    env.collector([finding(fid=GHSA_Z)])
    code, summary, relay = env.run(now=at(5, 10))
    assert code == 0 and "roots=0" in summary and relay.calls == [], summary
    assert "retracted, not planned=1" in capsys.readouterr().err


def test_a_curator_alias_in_the_retracted_list_retires_nothing(env, capsys):
    """Review: a reader hides the thread, but by an id the poster never held. Its own ids
    are not judged, and the run is not stopped (a release of every id would be refused)."""
    env.collector([finding(), finding(fid=GHSA_Z)])
    _, _, relay = env.run()
    (root,) = _on_mirror(env, relay, T0 + 60)
    env.mirror.reply(env.mirror.cur_sec, root, env.mirror.patch_text(aliases=["CVE-2026-8888"]), created_at=T0 + 70)
    env.mirror.publish_manifest(retracted=["CVE-2026-8888"])
    env.run(now=at(5, 9))
    capsys.readouterr()
    code, summary, relay = env.run(now=at(5, 10))
    assert code == 0 and relay.calls == [] and "split" not in env.ledger()[0][0], summary
    assert "retired" not in capsys.readouterr().err  # no id of it was judged


def test_a_learned_id_leaves_with_its_advisory(env):
    """Review: a CVE the ledger learned with no reply goes with the advisory its page
    assigns it to; left behind, it would pull the survivor back to the hidden thread."""
    env.collector([finding(), finding(fid=GHSA_Z)])
    _, _, relay = env.run()
    (root,) = _retract(env, relay, ["GHSA-abcd-efgh-ijkl"])
    with Ledger(env.config.ledger) as led:
        led.add_ids(root["id"], ["CVE-2026-0002"])
    env.pages.add([finding(fid=GHSA_Z, aliases=("CVE-2026-0002",))])  # its page now names the CVE
    code, summary, relay = env.run(now=at(5, 10))
    assert code == 0 and "roots=1" in summary and "CVE-2026-0002" in relay.calls[0][2], summary
    first, second = env.ledger()[0]
    assert "CVE-2026-0002" not in first["aliases"] and "CVE-2026-0002" in second["aliases"]


def test_a_run_stopped_before_the_ledger_write_repeats_the_release(env, monkeypatch):
    env.collector([finding(), finding(fid=GHSA_Z)])
    _, _, relay = env.run()
    _retract(env, relay, ["GHSA-abcd-efgh-ijkl"])
    real = Ledger.release

    def once(self, *a, **kw):
        monkeypatch.setattr(Ledger, "release", real)
        raise LedgerError("disk full")
    monkeypatch.setattr(Ledger, "release", once)
    code, summary, relay = env.run(now=at(5, 10))
    assert code == 0 and "roots=0" in summary and "split" not in env.ledger()[0][0], summary
    code, summary, relay = env.run(now=at(5, 11))
    assert code == 0 and "roots=1" in summary and GHSA_Z in relay.calls[0][2], summary
    code, summary, relay = env.run(now=at(5, 12))
    assert relay.calls == [] and len(env.ledger()[0]) == 2


def test_a_page_that_keeps_failing_never_starves_another_thread(env, monkeypatch):
    """Review: the work starts at another place each hour."""
    monkeypatch.setattr(main, "RETIRE_PAGES", 1)
    env.collector([finding(), finding(fid=GHSA_Z),
                   finding(fid="GHSA-mnop-qrst-uvwx", fixed="3.0"), finding(fid="GHSA-yyyy-yyyy-yyyy", fixed="3.0")])
    code, summary, relay = env.run()
    assert "roots=2" in summary, summary
    _retract(env, relay, ["GHSA-abcd-efgh-ijkl", "GHSA-mnop-qrst-uvwx"])
    env.pages.put(ZURL, "", status=503)  # for good
    posted = []
    for hour in (10, 11):
        code, summary, relay = env.run(now=at(5, hour))
        posted += [c[2] for c in relay.calls if c[1] is None]
    assert any("GHSA-yyyy-yyyy-yyyy" in t for t in posted) and not any(GHSA_Z in t for t in posted)


def test_a_scoped_retraction_keeps_its_bare_ids_and_frees_a_scoped_survivor(env):
    """Review: ids compare by their base. The retracted CVE-or-GHSA's bare form is never
    released, and a survivor whose primary is a thread key is."""
    a, z = "GHSA-abcd-efgh-ijkl:claude-code", GHSA_Z + ":claude-code"
    env.collector([finding(fid=a, sources=(GHSA,)), finding(fid=z, sources=(ZURL,))])
    code, summary, relay = env.run()
    assert "roots=1" in summary, summary
    _retract(env, relay, [a])
    code, summary, relay = env.run(now=at(5, 10))
    assert code == 0 and "roots=1" in summary, summary
    text = relay.calls[0][2]
    assert GHSA_Z in text and "abcd" not in text.casefold()
    assert all("abcd" not in i.casefold() for i in env.ledger()[0][1]["aliases"])
