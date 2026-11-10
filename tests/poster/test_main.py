"""The hourly poster run (Task B4). Fake ssh, fake KEV fetch, fake source fetch: no network."""

import datetime as dt
import itertools
import json
import shlex
import subprocess
from dataclasses import replace

import pytest
from pathlib import Path

from aitools_alerts.poster import inputs, main
from mirror_helpers import Mirror, advisory
from aitools_alerts.poster.ledger import Ledger, LedgerError

CHANNELS = {"feed": "599adb9f-4f9f-4b19-aee3-66667c3293e8",
            "critical": "ac446e7a-1e2c-4d74-ac8d-9c16ecb3801b"}
NAME = {v: k for k, v in CHANNELS.items()}
GHSA = "https://github.com/anthropics/claude-code/security/advisories/GHSA-abcd-efgh-ijkl"
GHSA2 = "https://github.com/anthropics/claude-code/security/advisories/GHSA-mnop-qrst-uvwx"
APPLE = "https://support.apple.com/en-us/120001"
TOKYO = dt.timezone(dt.timedelta(hours=9))
_EVENT_IDS = (f"{i:064x}" for i in itertools.count(1))  # unique across every FakeSSH in a test


def at(day, hour, minute=20):
    return int(dt.datetime(2026, 11, day, hour, minute, tzinfo=TOKYO).timestamp())


T0 = at(5, 6)  # 06:20 Tokyo: runs a few hours later stay before the digest hour


class FakeSSH:
    """Answers each send from a queue: ok, fail (exit 5, never sent), unknown (timeout).
    Japanese ``lang: ja`` replies go to ``ja`` and answer from ``ja_queue`` (default ok)."""

    def __init__(self, *outcomes, ja=()):
        self.queue, self.ja_queue = list(outcomes), list(ja)
        self.calls, self.ja = [], []

    def __call__(self, argv, **kw):
        remote = shlex.split(argv[-1])
        ch = NAME[remote[remote.index("--channel") + 1]]
        reply = remote[remote.index("--reply-to") + 1] if "--reply-to" in remote else None
        text = kw["input"].decode()
        is_ja = text.startswith("lang: ja\n")
        (self.ja if is_ja else self.calls).append((ch, reply, text))
        queue = self.ja_queue if is_ja else self.queue
        outcome = queue.pop(0) if queue else "ok"
        if outcome == "unknown":
            raise subprocess.TimeoutExpired("ssh", 120)
        if outcome == "fail":
            return subprocess.CompletedProcess(argv, 5, b"", b"conflict: write refused")
        if outcome == "refuse":  # the relay's user_error, not retryable (ai-tools-alerts#8acj)
            return subprocess.CompletedProcess(argv, 1, b"", json.dumps(
                {"error": "user_error", "message": "relay error: blocked\nmention", "retryable": False}).encode())
        eid = next(_EVENT_IDS)
        if not is_ja:
            self.ids = getattr(self, "ids", []) + [eid]  # event ids of the English sends, in order
        return subprocess.CompletedProcess(
            argv, 0, json.dumps({"accepted": True, "event_id": eid}).encode(), b"")


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


def finding(fid="GHSA-abcd-efgh-ijkl", product="Claude Code", severity="remote code execution",
            fixed="2.1.0", sources=(GHSA,), aliases=(), observed="2026-11-05T00:00:00Z"):
    return {"id": fid, "product": product, "advisory_severity": severity, "fixed": fixed,
            "aliases": list(aliases), "observed_at": observed,
            "sources": [{"url": u, "published_at": None} for u in sources]}


MAC = finding(fid="CVE-2026-5000", product="macOS", severity=None, fixed=None, sources=(APPLE,))


RELAY = {"relay_ssh_host": "relay.example.net", "relay_send_wrapper": "/opt/relay/bin/buzz-send"}
RELAY_TOML = "".join(f'{k} = "{v}"\n' for k, v in RELAY.items())


@pytest.fixture
def env(tmp_path):
    class Env:
        hb, col = tmp_path / "heartbeat", tmp_path / "collector"
        config = inputs.Config(heartbeat_runs=tmp_path / "heartbeat", collector_runs=tmp_path / "collector",
                               ledger=tmp_path / "state" / "ledger.json",
                               kev_cache=tmp_path / "state" / "kev.json", **RELAY)
        kev, mirror = FakeKEV(), Mirror()  # the digest pulls the mirror first (ai-tools-alerts#d3f6)
        _n = itertools.count()

        def collector(self, findings, validate="ok", name=None):
            d = self.col / (name or f"2026-11-05T{next(self._n):02d}0000Z")
            d.mkdir(parents=True)
            (d / "run-record.json").write_text(json.dumps({"schema_version": 1, "findings": findings}))
            (d / "job.json").write_text(json.dumps({"steps": {"validate": {"out": validate}}}))

        def heartbeat(self, name, findings, feeds=None):
            d = self.hb / name
            d.mkdir(parents=True)
            (d / "run.json").write_text(json.dumps({"schema": 1, "findings": findings}))
            if feeds is not None:
                (d / "feeds.json").write_text(json.dumps(feeds))

        def run(self, now=T0, ssh=None, kev=None, **kw):
            ssh = ssh if ssh is not None else FakeSSH()
            kw = {"mirror_fetch": self.mirror.fetch, "root": self.mirror.root, **kw}
            code, summary = main.run(now, self.config, ssh=ssh, kev_fetch=kev or self.kev,
                                     http_status=lambda url, timeout: 200, channels=CHANNELS, **kw)
            return code, summary, ssh

        def state(self):
            return json.loads(self.config.state.read_text())

        def ledger(self):
            with Ledger(self.config.ledger) as led:
                return led._state()["entries"], led._state()["pending"]

    Env.hb.mkdir()
    Env.col.mkdir()
    return Env()


def chans(ssh):
    return [(c[0], c[1]) for c in ssh.calls]


# ---------------------------------------------------------------- the eight named tests


def test_send_failure_leaves_advisory_unposted(env):
    env.collector([finding()])
    code, summary, ssh = env.run(ssh=FakeSSH("fail"))
    assert code == 1 and "failed=1" in summary and chans(ssh) == [("feed", None)]
    assert env.ledger() == ([], [])
    assert [it["kind"] for it in env.state()["outbox"]] == ["root"]  # kept for the next hour
    code, _, ssh = env.run(now=T0 + 3600)
    assert code == 0 and chans(ssh) == [("feed", None)]
    entries, pending = env.ledger()
    assert len(entries) == 1 and pending == [] and env.state()["outbox"] == []
    env.collector([finding()])
    _, _, ssh = env.run(now=T0 + 7200)
    assert ssh.calls == []  # posted once, never again


def test_critical_posts_to_both_channels_in_order(env):
    env.kev.catalog = {"vulnerabilities": [kev_item()]}
    code, summary, ssh = env.run()
    assert code == 0, summary
    assert chans(ssh) == [("critical", None), ("feed", None)]
    assert ssh.calls[0][2] == ssh.calls[1][2] and ssh.calls[0][2].startswith("CRITICAL: Claude Code")
    (e,), _ = env.ledger()
    assert set(e["channel_ids"]) == {"critical", "feed"} and e["level"] == "critical"
    assert e["root_event_id"] == e["channel_ids"]["critical"]


def test_high_posts_to_feed_only(env):
    env.collector([finding()])
    code, summary, ssh = env.run()
    assert code == 0 and "roots=1" in summary
    assert chans(ssh) == [("feed", None)] and ssh.calls[0][2].startswith("HIGH: Claude Code")


def test_notice_waits_for_digest(env):
    env.collector([MAC])
    code, summary, ssh = env.run()
    assert code == 0 and ssh.calls == [] and "held=1" in summary
    code, summary, ssh = env.run(now=at(5, 9))
    assert code == 0 and chans(ssh) == [("feed", None)]
    assert "Daily digest for 2026-11-05" in ssh.calls[0][2] and "CVE-2026-5000" in ssh.calls[0][2]
    _, _, ssh = env.run(now=at(5, 10))
    assert ssh.calls == []  # one digest a day
    env.collector([MAC])  # seen again: never held again
    _, _, ssh = env.run(now=at(6, 9))
    assert len(ssh.calls) == 1 and "CVE-2026-5000" not in ssh.calls[0][2]


def test_duplicate_alias_becomes_reply(env):
    env.collector([finding()])
    env.run()
    (e,), _ = env.ledger()
    root = e["channel_ids"]["feed"]
    twin = finding(fid="CVE-2026-0002", aliases=("GHSA-abcd-efgh-ijkl",), sources=(GHSA, GHSA2))
    env.collector([twin])
    code, summary, ssh = env.run(now=T0 + 3600)
    assert code == 0 and "replies=1" in summary and "roots=0" in summary
    assert chans(ssh) == [("feed", root)]
    assert "CVE-2026-0002" in ssh.calls[0][2] and "```aitools-alert" in ssh.calls[0][2]
    (e,), _ = env.ledger()
    assert len(e["replies"]) == 1 and "CVE-2026-0002" in e["aliases"]
    env.collector([twin])
    _, _, ssh = env.run(now=T0 + 7200)
    assert ssh.calls == []


def test_watermark_advances_only_on_success(env):
    env.heartbeat("2026-11-05T000000Z", [])
    env.collector([finding()], name="2026-11-05T000000Z")
    code, _, _ = env.run(ssh=FakeSSH("fail"))
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
    kev = FakeKEV(status=304)
    code, _, ssh = env.run(kev=kev)
    assert code == 0 and kev.headers == [{"If-Modified-Since": lm}]
    assert chans(ssh) == [("critical", None), ("feed", None)]


def test_unknown_outcome_keeps_pending(env):
    env.collector([finding()])
    code, summary, ssh = env.run(ssh=FakeSSH("unknown"))
    assert code == 1 and "unknown=1" in summary
    entries, pending = env.ledger()
    assert entries == [] and len(pending) == 1 and len(env.state()["outbox"]) == 1
    env.collector([finding()])
    code, summary, ssh = env.run(now=T0 + 3600)
    assert code == 0 and ssh.calls == [] and "busy=2" in summary  # the item, then the candidate
    with Ledger(env.config.ledger) as led:  # a human found it was not delivered
        led.expire_pending(pending[0]["key"], "checked the channel: not delivered", now=T0 + 90000)
    code, _, ssh = env.run(now=T0 + 90000)
    assert code == 0 and chans(ssh)[0] == ("feed", None)  # resent from the journal, no new input
    assert len(env.ledger()[0]) == 1


# ---------------------------------------------------------------- pending / resolve


def test_pending_on_an_empty_journal(env):
    assert main.pending(T0, env.config) == (0, ["aitools-alerts-poster: pending=0 unknown=0 sent=0 orphan=0"])


def _unknown_root(env):
    env.collector([finding()])
    env.run(ssh=FakeSSH("unknown"))
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
    code, _, ssh = env.run(now=T0 + 3600)  # neither resent nor re-recorded
    assert code == 0 and ssh.calls == [] and len(env.ledger()[0]) == 1


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
    code, _, ssh = env.run(now=T0 + 90000)
    assert code == 0 and chans(ssh) == [("feed", None)] and len(env.ledger()[0]) == 1


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
    env.collector([finding(fid="GHSA-zzzz-zzzz-zzzz", sources=(GHSA2,))])
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
    env.run(now=at(5, 9), ssh=FakeSSH("unknown"))
    (it,) = env.state()["outbox"]
    assert main.resolve(at(5, 10), env.config, it["key"], delivered="ab" * 32)[0] == 0
    st = env.state()
    assert [o["root"] for o in st["outbox"]] == ["ab" * 32]  # its Japanese reply, sent next run
    assert st["held"] == [] and st["digest_ids"] == ["ab" * 32]
    assert st["digest_date"] == "2026-11-05" and env.ledger()[1] == []


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
    env.collector([finding(), finding(fid="GHSA-zzzz-zzzz-zzzz", sources=(GHSA2,)), MAC])
    code, _, ssh = env.run(now=at(5, 9), ssh=FakeSSH("fail"))
    assert code == 1 and len(ssh.calls) == 1  # no second high, no digest
    st = env.state()
    assert st["collector"] is None and st["digest_date"] is None and st["withheld"] == []  # 8acj


def test_ledger_error_stops_sends_and_replays_without_sending(env, monkeypatch):
    env.collector([finding(), finding(fid="GHSA-zzzz-zzzz-zzzz", sources=(GHSA2,))])
    real = Ledger.record_root

    def boom(self, *a, **k):
        raise LedgerError("disk full")

    monkeypatch.setattr(Ledger, "record_root", boom)
    code, summary, ssh = env.run()
    assert code == 1 and len(ssh.calls) == 1 and "error=ledger" in summary
    (it,) = [i for i in env.state()["outbox"] if i["sent"]]
    monkeypatch.setattr(Ledger, "record_root", real)
    code, _, ssh = env.run(now=T0 + 3600)
    assert code == 0
    entries, pending = env.ledger()
    assert it["sent"] in {e["root_event_id"] for e in entries} and pending == []
    assert chans(ssh) == [("feed", None)]  # only the second advisory: the first was not resent


def test_feed_failure_after_critical_completes_next_run(env):
    env.kev.catalog = {"vulnerabilities": [kev_item()]}
    code, _, ssh = env.run(ssh=FakeSSH("ok", "fail"))
    assert code == 1 and chans(ssh) == [("critical", None), ("feed", None)]
    (e,), pending = env.ledger()
    assert set(e["channel_ids"]) == {"critical"} and pending == []
    code, _, ssh = env.run(now=T0 + 3600)
    assert code == 0 and chans(ssh) == [("feed", None)]
    (e,), _ = env.ledger()
    assert set(e["channel_ids"]) == {"critical", "feed"}


def test_partial_reply_retried_in_failed_channel_only(env):
    env.kev.catalog = {"vulnerabilities": [kev_item()]}
    env.run()
    (e,), _ = env.ledger()
    env.collector([finding(fid="CVE-2026-0001", sources=(GHSA2,))])  # a fix and a new source
    code, _, ssh = env.run(now=T0 + 3600, ssh=FakeSSH("ok", "fail"))
    assert code == 1
    assert chans(ssh) == [("critical", e["channel_ids"]["critical"]), ("feed", e["channel_ids"]["feed"])]
    text = ssh.calls[0][2]
    code, _, ssh = env.run(now=T0 + 7200)
    assert code == 0 and chans(ssh) == [("feed", e["channel_ids"]["feed"])] and ssh.calls[0][2] == text
    (e2,), _ = env.ledger()
    assert len(e2["replies"]) == 2


def test_a_refused_reply_is_fixed_and_requeued_when_its_sibling_recorded(env, tmp_path):  # 8acj
    env.kev.catalog = {"vulnerabilities": [kev_item()]}
    env.run(), env.collector([finding(fid="CVE-2026-0001", sources=(GHSA2,))])
    assert "withheld=1" in env.run(now=T0 + 3600, ssh=FakeSSH("refuse"))[1]  # critical refused, feed recorded
    (w,) = env.state()["withheld"]
    assert main.resolve(T0, env.config, w["key"], requeue=True, text="no alert block")[0] == 2
    fixed = w["items"][0]["text"].replace("\n", " \n", 1)
    assert main.resolve(T0, env.config, w["key"], requeue=True, text=fixed)[0] == 0
    assert env.run(now=T0 + 7200)[2].calls[0][2] == fixed and len(env.ledger()[0][0]["replies"]) == 2


def test_busy_candidate_learns_ids(env):
    env.collector([finding(fid="GHSA-aaaa-aaaa-aaaa")])
    env.run(ssh=FakeSSH("unknown"))
    env.collector([finding(fid="GHSA-aaaa-aaaa-aaaa", aliases=("CVE-2026-0009",))])
    env.run(now=T0 + 3600)
    assert "CVE-2026-0009" in env.state()["outbox"][0]["ids"]
    env.collector([finding(fid="CVE-2026-0009")])
    code, summary, ssh = env.run(now=T0 + 7200)
    assert ssh.calls == [] and "busy=2" in summary


def test_high_becoming_critical_under_another_id(env):
    env.collector([finding(fid="GHSA-abcd-efgh-ijkl", aliases=("CVE-2026-0001",))])
    env.run()
    (e,), _ = env.ledger()
    feed_root = e["channel_ids"]["feed"]
    env.kev.catalog = {"vulnerabilities": [kev_item()]}  # KEV knows it only as the CVE, with no fix
    code, summary, ssh = env.run(now=T0 + 3600)
    assert code == 0, summary
    assert chans(ssh) == [("critical", None), ("feed", feed_root)]
    copy, reply = ssh.calls[0][2], ssh.calls[1][2]
    assert copy.startswith("CRITICAL: Claude Code") and "(GHSA-abcd-efgh-ijkl)" in copy
    assert "Fixed in 2.1.0." in copy  # the stored fix is kept
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
    code, summary, ssh = env.run(now=T0 + 3600)
    assert code == 0 and ssh.calls == [] and "withheld=1" in summary  # not even the critical copy
    assert env.state()["outbox"] == []


def test_notice_dedup_is_per_scope(env):
    env.collector([finding(fid="CVE-2026-6000", product="macOS", severity=None, fixed=None, sources=(APPLE,)),
                   finding(fid="CVE-2026-6000", product="Google Chrome", severity=None, fixed=None,
                           sources=("https://chromereleases.googleblog.com/2026/11/x.html",))])
    code, summary, _ = env.run()
    assert code == 0 and "held=2" in summary
    assert len({h["scope"] for h in env.state()["held"]}) == 2


def test_digest_includes_ledger_posts(env):
    env.collector([finding()])
    env.run()
    assert env.state()["held"] == []
    code, _, ssh = env.run(now=at(5, 9))
    assert code == 0 and "GHSA-abcd-efgh-ijkl" in ssh.calls[0][2]


def test_backfill_floor_drops_old_candidates(env):
    env.collector([finding(observed="2026-10-01T00:00:00Z")])
    code, summary, ssh = env.run()
    assert ssh.calls == [] and "old=1" in summary


def test_collector_record_skipped_unless_validate_ok(env):
    env.collector([finding()], validate="failed")
    (env.col / "2026-11-05").mkdir()  # the collector's date-only copy: never read
    code, summary, ssh = env.run()
    assert code == 0 and ssh.calls == [] and "candidates=0" in summary


def test_heartbeat_feeds_json_never_reaches_from_kev(env, monkeypatch):
    env.heartbeat("2026-11-05T000000Z", [], feeds={"cisa-kev": {"items": [kev_item()]}})
    seen = []
    real = main.candidates.from_kev
    monkeypatch.setattr(main.candidates, "from_kev", lambda cat, since: seen.append(cat) or real(cat, since))
    code, _, ssh = env.run()
    assert code == 0 and ssh.calls == [] and seen == [env.kev.catalog]


def test_kev_unavailable_holds_kev_watermark(env):
    code, summary, _ = env.run(kev=FakeKEV(status=500))
    assert code == 0 and env.state()["kev_since"] is None


def test_malformed_state_refuses_to_send(env):
    env.config.state.parent.mkdir(parents=True)
    env.config.state.write_text("{not json")
    env.collector([finding()])
    code, summary, ssh = env.run()
    assert code == 1 and ssh.calls == [] and "error=ledger" in summary


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
                        {**main.run.__kwdefaults__, "kev_fetch": FakeKEV(), "ssh": FakeSSH()})
    assert main.main(["run", "--config", str(cfg)]) == 0
    out = capsys.readouterr().out.splitlines()
    assert len(out) == 1 and out[0].startswith("aitools-alerts-poster: candidates=0")


def test_unknown_digest_is_journaled_once_and_acknowledges_its_snapshot(env):
    env.collector([MAC])
    env.run()
    code, _, ssh = env.run(now=at(5, 9), ssh=FakeSSH("unknown"))
    assert code == 1 and len(ssh.calls) == 1
    env.collector([finding(fid="CVE-2026-5001", product="macOS", severity=None, fixed=None, sources=(APPLE,))])
    for h in (10, 11):
        _, _, ssh = env.run(now=at(5, h))
        assert ssh.calls == []
    st = env.state()
    assert [it["kind"] for it in st["outbox"]] == ["digest"] and len(st["held"]) == 2
    with Ledger(env.config.ledger) as led:
        (p,) = led._state()["pending"]
        led.expire_pending(p["key"], "checked the channel: not delivered", now=at(6, 12))
    code, _, ssh = env.run(now=at(6, 12))
    assert code == 0 and len(ssh.calls) == 2  # the journaled 11-05 digest, then today's
    assert "CVE-2026-5001" not in ssh.calls[0][2] and "CVE-2026-5001" in ssh.calls[1][2]
    assert env.state()["held"] == []


def test_affected_range_correction_posts_a_reply(env):
    first = finding()
    first["affected"] = "<2.0.0"
    env.collector([first])
    env.run()
    fixed_range = finding()
    fixed_range["affected"] = "<2.1.0"
    env.collector([fixed_range])
    code, summary, ssh = env.run(now=T0 + 3600)
    assert code == 0 and "replies=1" in summary and "below 2.1.0" in ssh.calls[0][2]


def test_busy_update_survives_its_source_being_replaced(env):
    env.collector([finding(fixed=None, severity=None, fid="CVE-2026-0001")])
    env.kev.catalog = {"vulnerabilities": [kev_item()]}
    env.run(ssh=FakeSSH("ok", "unknown"))  # critical root ok, feed copy unknown
    env.kev.catalog = {"vulnerabilities": []}
    env.collector([finding(fid="CVE-2026-0001", sources=(GHSA2,))])  # the fix arrives while busy
    code, _, ssh = env.run(now=T0 + 3600)
    assert code == 0 and ssh.calls == []
    st = env.state()
    assert [d["id"] for d in st["deferred"]] == ["CVE-2026-0001"]
    assert st["collector"] == "2026-11-05T010000Z"  # deferral, not the source, keeps the update
    env.collector([], name="2026-11-05T020000Z")  # the next record no longer names it
    with Ledger(env.config.ledger) as led:
        (p,) = led._state()["pending"]
        led.expire_pending(p["key"], "checked the channel: not delivered", now=T0 + 90000)
    code, summary, ssh = env.run(now=T0 + 90000)
    assert code == 0, summary
    assert [c[0] for c in ssh.calls] == ["feed", "critical", "feed"]  # the copy, then the fix replies
    assert all("Fixed in 2.1.0." in c[2] for c in ssh.calls[1:])
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
    env.kev.catalog = {"vulnerabilities": [kev_item()]}  # critical, with no fix known
    env.collector([first])
    assert "roots=1" in env.run()[1]
    corrected = finding(fid="CVE-2026-0001", fixed=None)
    corrected["affected"] = "<2.5.0"
    env.collector([corrected])
    code, summary, ssh = env.run(now=T0 + 3600)
    assert code == 0 and "replies=2" in summary  # the thread is in both channels
    assert all("below 2.5.0" in c[2] for c in ssh.calls)


def test_ids_learned_past_the_alias_cap(env):
    env.collector([finding(aliases=[f"A-{i:03d}" for i in range(32)])])  # the adapter keeps 32
    env.run()
    env.collector([finding(aliases=[f"B-{i:03d}" for i in range(32)])])
    env.run(now=T0 + 3600)
    (e,), _ = env.ledger()
    assert len(e["advisory"]["aliases"]) == 50  # the published list is full
    env.collector([finding(aliases=("CVE-2026-0777",))])
    _, _, ssh = env.run(now=T0 + 7200)
    assert ssh.calls == []  # nothing to publish
    (e,), _ = env.ledger()
    assert "CVE-2026-0777" in e["aliases"]  # but the identity is learned
    env.collector([finding(fid="CVE-2026-0777", sources=(GHSA2,))])
    _, summary, ssh = env.run(now=T0 + 10800)
    assert "roots=0" in summary and len(env.ledger()[0]) == 1  # never a second thread


def test_alias_reply_survives_a_stop_after_ids_were_learned(env, monkeypatch):
    env.collector([finding()])
    env.run()
    twin = finding(fid="CVE-2026-0002", aliases=("GHSA-abcd-efgh-ijkl",))
    env.collector([twin])
    real = main.Run.enqueue

    def stop(self, items):
        raise LedgerError("stopped before journaling")

    monkeypatch.setattr(main.Run, "enqueue", stop)
    code, _, ssh = env.run(now=T0 + 3600)
    assert code == 1 and ssh.calls == []
    (e,), _ = env.ledger()
    assert "CVE-2026-0002" in e["aliases"]  # learned before the stop
    monkeypatch.setattr(main.Run, "enqueue", real)
    env.collector([twin])
    code, summary, ssh = env.run(now=T0 + 7200)
    assert code == 0 and "replies=1" in summary and "CVE-2026-0002" in ssh.calls[0][2]


def test_reply_keeps_its_thread_when_ids_bridge_two_threads(env):
    env.collector([finding(fid="CVE-2026-1111", sources=(GHSA2,)), finding()])
    env.run()
    entries, _ = env.ledger()
    e1 = next(e for e in entries if "CVE-2026-1111" in e["aliases"])
    e2 = next(e for e in entries if "GHSA-abcd-efgh-ijkl" in e["aliases"])
    fix = finding(fixed="2.2.0")
    env.collector([fix])
    env.run(now=T0 + 3600, ssh=FakeSSH("unknown"))  # e2's reply: outcome unknown
    env.collector([finding(aliases=("CVE-2026-1111",), fixed="2.2.0")])  # bridges e2 to e1
    env.run(now=T0 + 7200)
    with Ledger(env.config.ledger) as led:
        (p,) = led._state()["pending"]
        led.expire_pending(p["key"], "checked the channel: not delivered", now=T0 + 90000)
    _, _, ssh = env.run(now=T0 + 90000)
    assert ssh.calls[0][1] == e2["channel_ids"]["feed"]  # still e2's thread
    entries, _ = env.ledger()
    assert next(e for e in entries if e["root_event_id"] == e1["root_event_id"])["advisory"]["id"] == "CVE-2026-1111"


def test_widened_root_never_starts_a_second_thread(env):
    env.collector([finding(fid="CVE-2026-1111", sources=(GHSA2,))])
    env.run()
    env.collector([finding()])
    env.run(now=T0 + 3600, ssh=FakeSSH("unknown"))  # a new root for the GHSA: unknown
    env.collector([finding(aliases=("CVE-2026-1111",))])  # the GHSA is the CVE's thread after all
    env.run(now=T0 + 7200)
    with Ledger(env.config.ledger) as led:
        (p,) = led._state()["pending"]
        led.expire_pending(p["key"], "checked the channel: not delivered", now=T0 + 90000)
    _, _, ssh = env.run(now=T0 + 90000)
    assert all(c[1] is not None for c in ssh.calls)  # replies only, never a new root
    assert len(env.ledger()[0]) == 1


def test_unsendable_channel_never_marks_pending(env):
    env.collector([finding()])
    bad = dict(CHANNELS, feed="NOT-A-UUID")
    code, summary = main.run(T0, env.config, ssh=FakeSSH(), kev_fetch=env.kev,
                             http_status=lambda url, timeout: 200, channels=bad)
    assert code == 1 and "withheld=1" in summary and env.ledger()[1] == []


def test_oversized_digest_posts_what_fits_and_keeps_the_rest(env, monkeypatch):
    env.collector([finding(fid=f"CVE-2026-50{i:02d}", product="macOS", severity=None, fixed=None,
                           sources=(f"{APPLE}{i}",)) for i in range(6)])
    env.run()
    assert len(env.state()["held"]) == 6
    monkeypatch.setattr(main.transport, "MAX_CONTENT", 400)  # room for a few items only
    code, _, ssh = env.run(now=at(5, 9))
    assert code == 0 and len(ssh.calls) == 1 and len(ssh.calls[0][2]) <= 400
    listed = {f"CVE-2026-50{i:02d}" for i in range(6) if f"CVE-2026-50{i:02d}" in ssh.calls[0][2]}
    st = env.state()
    assert 0 < len(listed) < 6 and len(st["held"]) == 6 - len(listed)  # only what was posted is acknowledged
    left = {h["adv"]["id"] for h in st["held"]}
    assert left.isdisjoint(listed)


def test_fresh_correction_wins_over_a_deferred_fix(env):
    env.collector([finding(fid="CVE-2026-0001")])
    env.kev.catalog = {"vulnerabilities": [kev_item()]}
    env.run(ssh=FakeSSH("ok", "unknown"))  # critical root ok, feed copy unknown: busy
    env.collector([finding(fid="CVE-2026-0001", fixed="2.1.5", sources=(GHSA2,))])
    env.run(now=T0 + 3600)  # deferred with 2.1.5
    with Ledger(env.config.ledger) as led:
        (p,) = led._state()["pending"]
        led.expire_pending(p["key"], "checked the channel: not delivered", now=T0 + 90000)
    env.collector([finding(fid="CVE-2026-0001", fixed="2.2.0", sources=(GHSA2,))])  # the correction
    code, _, ssh = env.run(now=T0 + 90000)
    assert code == 0 and ssh.calls
    assert all("2.2.0" in c[2] and "2.1.5" not in c[2] for c in ssh.calls[1:])


def test_digest_backlog_moves_forward_day_by_day(env, monkeypatch):
    env.collector([finding(fid=f"GHSA-aaaa-aaaa-aa{i:02d}", sources=(f"{GHSA}{i}",)) for i in range(6)])
    env.run()
    assert len(env.ledger()[0]) == 6
    monkeypatch.setattr(main.transport, "MAX_CONTENT", 700)
    seen = set()
    for day in (5, 6, 7, 8, 9, 10):
        _, _, ssh = env.run(now=at(day, 9))
        if ssh.calls:
            seen |= {f"GHSA-aaaa-aaaa-aa{i:02d}" for i in range(6) if f"aa{i:02d})" in ssh.calls[0][2]}
    assert seen == {f"GHSA-aaaa-aaaa-aa{i:02d}" for i in range(6)}


def test_new_roots_copy_stays_on_its_thread(env):
    env.collector([finding(fid="GHSA-zzzz-zzzz-zzzz", sources=(GHSA2,))])  # an older feed thread A
    env.run()
    env.kev.catalog = {"vulnerabilities": [kev_item()]}  # a new critical thread B
    env.run(now=T0 + 3600, ssh=FakeSSH("ok", "unknown"))
    entries, _ = env.ledger()
    b = next(e for e in entries if "CVE-2026-0001" in e["aliases"])
    env.collector([finding(fid="GHSA-zzzz-zzzz-zzzz", aliases=("CVE-2026-0001",), sources=(GHSA2,))])
    env.run(now=T0 + 7200)  # bridges B's ids to A while the copy is pending
    with Ledger(env.config.ledger) as led:
        (p,) = led._state()["pending"]
        led.expire_pending(p["key"], "checked the channel: not delivered", now=T0 + 90000)
    env.run(now=T0 + 90000)
    entries, _ = env.ledger()
    assert set(next(e for e in entries if e["root_event_id"] == b["root_event_id"])["channel_ids"]) \
        == {"critical", "feed"}


def test_ledger_error_keeps_unplanned_candidates(env, monkeypatch):
    env.collector([finding(), finding(fid="GHSA-zzzz-zzzz-zzzz", sources=(GHSA2,))])
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
    code, summary, ssh = env.run(now=T0 + 3600)
    assert code == 0 and len(env.ledger()[0]) == 2 and len(ssh.calls) == 1


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
    env.heartbeat("2026-11-05T020000Z", [{"id": "CVE-2026-5000", "product": "macOS", "source": APPLE}])
    code, summary, ssh = env.run(now=T0 + 3600)
    assert code == 0 and "heartbeat:1/2" in summary and "held=1" in summary  # the good dir is still read
    assert env.state()["heartbeat"] == "2026-11-05T000000Z"  # held before the rejected dir
    (env.hb / "2026-11-05T010000Z" / "run.json").write_text(json.dumps({"schema": 1, "findings": []}))
    code, summary, ssh = env.run(now=T0 + 7200)
    assert "heartbeat:2/2" in summary and "held=0" in summary  # re-read: nothing is held twice
    assert env.state()["heartbeat"] == "2026-11-05T020000Z"


def test_digest_id_recorded_and_printed(env, capsys):
    env.collector([MAC])
    env.run()
    st = env.state()
    base = 1 << 252  # far from FakeSSH's counter, whatever ran before
    st["digest_ids"] = [f"{i:064x}" for i in range(base, base + 10)]  # ten already
    env.config.state.write_text(json.dumps(st))
    code, _, ssh = env.run(now=at(5, 9))
    st = env.state()
    assert code == 0 and len(ssh.calls) == 1 and len(st["digest_ids"]) == 10
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
    code, _, ssh = env.run(now=at(5, 9))
    assert code == 1 and len(ssh.calls) == 1
    monkeypatch.setattr(main.Run, "_record", real)
    code, _, ssh = env.run(now=at(5, 10))
    assert code == 0 and ssh.calls == [] and len(env.state()["digest_ids"]) == 1


def test_digest_now_once_per_date(env, capsys):
    env.collector([MAC])
    code, _, ssh = env.run(digest_now=True)  # 06:20 Tokyo, before the digest hour
    assert code == 0 and len(ssh.calls) == 1 and "Daily digest for 2026-11-05" in ssh.calls[0][2]
    assert env.state()["digest_date"] == "2026-11-05"
    code, _, ssh = env.run(now=T0 + 600, digest_now=True)
    assert code == 0 and ssh.calls == []
    assert "digest for 2026-11-05 already sent; --digest-now does nothing" in capsys.readouterr().err
    _, _, ssh = env.run(now=at(5, 9))
    assert ssh.calls == []  # the 09:00 run sends no second digest
    _, _, ssh = env.run(now=at(6, 6))
    assert ssh.calls == []  # without the flag, the next date still waits for the hour


def test_kev_file_bypasses_fetch_and_marks_posts(env):
    kev = FakeKEV()
    catalog = inputs.read_kev_file(SYNTHETIC)
    code, summary, ssh = env.run(now=at(20, 6), kev=kev, kev_catalog=catalog)  # dateAdded long past
    assert code == 0, summary
    assert kev.headers == [] and not env.config.kev_cache.exists()
    assert "inputs=kev:file," in summary and "roots=1" in summary
    assert chans(ssh) == [("critical", None), ("feed", None)]
    assert all(c[2].startswith("CRITICAL (SYNTHETIC TEST): SYNTHETIC TEST: Claude Code") and "CVE-2099-0010" in c[2]
               for c in ssh.calls)  # the root and its feed copy
    assert env.state()["kev_since"] is None  # the real catalog was not read
    code, summary, ssh = env.run(now=at(20, 7), kev=kev, kev_catalog=catalog)
    assert code == 0 and ssh.calls == [] and "withheld=1" in summary  # known: never a reply


def test_kev_file_candidate_never_deferred(env):
    catalog = inputs.read_kev_file(SYNTHETIC)
    code, _, _ = env.run(ssh=FakeSSH("unknown"), kev_catalog=catalog)
    assert code == 1
    assert env.state()["deferred"] == []
    code, summary, ssh = env.run(now=T0 + 3600, kev_catalog=catalog)
    assert code == 0 and ssh.calls == [] and env.state()["deferred"] == []  # busy: dropped


def test_kev_file_notice_is_withheld(env, tmp_path):
    catalog = {"vulnerabilities": [{"cveID": "CVE-2099-0002", "vendorProject": "Apple", "product": "macOS",
                                    "vulnerabilityName": "SYNTHETIC TEST", "dateAdded": "2026-11-05"}]}
    code, summary, ssh = env.run(kev_catalog=catalog)
    # macOS is tier 2: an exploited tier-2 entry is high, so it posts marked; never held
    assert code == 0 and env.state()["held"] == []
    assert all(c[2].startswith("HIGH (SYNTHETIC TEST)") for c in ssh.calls)


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
    code, summary, ssh = env.run(kev_catalog=catalog, digest_now=True)  # the same run digests it
    assert code == 0 and "digest=1" in summary
    (body,) = [c[2] for c in ssh.calls if c[2].startswith("Daily digest")]
    assert body == "Daily digest for 2026-11-05: no advisories."  # ai-tools-alerts#d3f6
    env.kev.catalog = {"vulnerabilities": [kev_item(cve="CVE-2099-0003")]}  # any input: the id decides
    _, _, ssh = env.run(now=at(6, 6))
    assert ssh.calls and all(c[2].startswith("CRITICAL (SYNTHETIC TEST)") for c in ssh.calls)


def test_kev_floor_without_watermark_is_the_state_floor(env):
    env.run(kev=FakeKEV(status=503))  # first run: state since = Nov 3, KEV down
    for day in (6, 7, 8, 9):
        env.run(now=at(day, 6), kev=FakeKEV(status=503))
    assert env.state()["kev_since"] is None
    env.kev.catalog = {"vulnerabilities": [kev_item(added="2026-11-04")]}
    code, _, ssh = env.run(now=at(10, 6))
    assert code == 0 and chans(ssh) == [("critical", None), ("feed", None)]  # not lost to the outage


def test_digest_now_while_a_digest_is_journaled(env, capsys):
    env.collector([MAC])
    env.run()
    code, _, ssh = env.run(now=at(5, 9), ssh=FakeSSH("unknown"))
    assert code == 1 and len(env.state()["outbox"]) == 1
    capsys.readouterr()
    code, summary, ssh = env.run(now=at(5, 10), digest_now=True)
    assert ssh.calls == [] and "busy=1" in summary
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
    code, _, ssh = env.run()
    assert code == 0 and ssh.calls[0][2].startswith("HIGH: Claude Code")  # not marked
    (e,), _ = env.ledger()
    assert "CVE-2099-1234" not in e["aliases"]
    env.collector([finding(aliases=("CVE-2099-1234",), fixed="2.2.0")])
    code, summary, ssh = env.run(now=T0 + 3600)
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
    code, summary, ssh = env.run(kev_catalog=inputs.read_kev_file(SYNTHETIC))
    assert code == 0, summary
    assert "reserved synthetic id=1" in capsys.readouterr().err
    texts = [c[2] for c in ssh.calls]
    assert any(t.startswith("HIGH: Claude Code") and "GHSA-abcd-efgh-ijkl" in t and "CVE-2099" not in t
               for t in texts)  # the real advisory: unmerged, unmarked, not promoted
    assert all(t.startswith("CRITICAL (SYNTHETIC TEST)") for t in texts if "CVE-2099" in t)
    entries, _ = env.ledger()
    real_e = next(e for e in entries if "GHSA-abcd-efgh-ijkl" in [e["advisory"]["id"], *e["aliases"]])
    assert real_e["level"] == "high" and not any("2099" in a for a in real_e["aliases"])


def test_kev_added_on_the_floor_day_is_not_old(env):
    env.config = inputs.Config(ledger=env.config.ledger, kev_cache=env.config.kev_cache, backfill_days=0,
                               **RELAY)
    start = int(dt.datetime(2026, 11, 5, 10, tzinfo=dt.timezone.utc).timestamp())
    env.run(now=start)
    env.kev.catalog = {"vulnerabilities": [kev_item(added="2026-11-05")]}
    code, summary, ssh = env.run(now=start + 5 * 3600)
    assert code == 0 and "old=0" in summary and len(ssh.calls) == 2


def test_deferred_candidate_dropped_by_scope_reaches_the_review_list(env, monkeypatch):
    # ai-tools-alerts#3r9h: a candidate deferred under an older scope that not_match
    # now excludes leaves the deferred list, and its text is kept for human review.
    env.collector([finding()])
    monkeypatch.setattr(Ledger, "record_root", lambda self, *a, **k: (_ for _ in ()).throw(LedgerError("x")))
    assert env.run()[0] == 1
    monkeypatch.undo()
    st = env.state()
    assert [d["id"] for d in st["deferred"]] == ["GHSA-abcd-efgh-ijkl"]
    st["deferred"][0]["product_text"] = "Npm package System Information Library for Node.JS"
    env.config.state.write_text(json.dumps(st))
    env.collector([], name="2026-11-05T020000Z")
    code, _, ssh = env.run(now=T0 + 3600)
    assert code == 0 and ssh.calls == [] and env.state()["deferred"] == []
    with Ledger(env.config.ledger) as led:
        texts = [r["text"] for r in led._state()["review"]]
    assert "Npm package System Information Library for Node.JS" in texts


# ---------------------------------------------------------------- Japanese lang: ja replies (rd8t)


@pytest.mark.parametrize("critical", [False, True])
def test_root_gets_a_japanese_reply_in_each_channel(env, critical):
    env.kev.catalog = {"vulnerabilities": [kev_item()] if critical else []}
    env.collector([] if critical else [finding()])
    code, summary, ssh = env.run()
    chs = ["critical", "feed"] if critical else ["feed"]
    assert code == 0 and f"ja={len(chs)} ja_failed=0" in summary and env.state()["outbox"] == []
    assert [(c[0], c[1]) for c in ssh.ja] == list(zip(chs, ssh.ids))  # each replies to its own root
    head = "緊急" if critical else "重要"
    assert all(c[2].startswith(f"lang: ja\n\n{head}: Claude Code: ") and "```" not in c[2] for c in ssh.ja)


def test_change_reply_japanese_names_it_in_of(env):
    first = finding(fid="CVE-2026-0001", fixed=None)
    first["affected"] = "<2.0.0"
    env.kev.catalog = {"vulnerabilities": [kev_item()]}
    env.collector([first])
    _, _, ssh0 = env.run()
    roots = dict(zip(["critical", "feed"], ssh0.ids))
    corrected = finding(fid="CVE-2026-0001", fixed=None)
    corrected["affected"] = "<2.5.0"
    env.collector([corrected])
    code, summary, ssh = env.run(now=T0 + 3600)
    assert code == 0 and "replies=2" in summary and "ja=2" in summary
    for (ch, reply_to, text), (ech, _, _), eid in zip(ssh.ja, ssh.calls, ssh.ids):
        assert ch == ech and reply_to == roots[ch]
        assert text.startswith(f"lang: ja\nof: {eid}\n\n") and "（2.5.0 未満）" in text
        assert "\n\n緊急: Claude Code: 悪用が確認された脆弱性 (CVE-2026-0001)\n" in text  # the current version


def test_digest_gets_a_japanese_reply(env):
    env.collector([MAC])
    env.run()
    code, _, ssh = env.run(now=at(5, 9))
    assert code == 0 and len(ssh.calls) == 1
    ((ch, reply_to, text),) = ssh.ja
    assert (ch, reply_to) == ("feed", ssh.ids[0])
    assert text.startswith("lang: ja\n\n2026-11-05 のデイリーダイジェスト: 1 件。") and "CVE-2026-5000" in text


def test_failed_japanese_send_retries_next_hour_without_the_english(env):
    env.collector([finding()])
    code, summary, ssh = env.run(ssh=FakeSSH(ja=["fail"]))
    assert code == 0 and "roots=1" in summary and "ja=0 ja_failed=1" in summary
    (it,) = env.state()["outbox"]
    assert it["kind"] == "ja" and it["key"] == "root:Claude Code:GHSA-abcd-efgh-ijkl:feed:ja"
    assert env.ledger()[1] == []  # a failed send is not in flight
    code, summary, ssh2 = env.run(now=T0 + 3600)
    assert code == 0 and ssh2.calls == [] and "ja=1" in summary
    assert ssh2.ja == [("feed", ssh.ids[0], it["text"])] and env.state()["outbox"] == []


def test_unknown_japanese_send_never_holds_english_work(env):
    env.collector([finding()])
    code, summary, ssh = env.run(ssh=FakeSSH(ja=["unknown"]))
    assert code == 0 and "ja_failed=1" in summary
    (p,) = env.ledger()[1]
    assert p["key"].endswith(":ja") and p["aliases"] == []  # matches no advisory id
    # A new alias arrives (one spelled like the journal's id too): the English reply still posts.
    env.collector([finding(fid="CVE-2026-0002", aliases=("GHSA-abcd-efgh-ijkl", f"ja {p['key']}"),
                           sources=(GHSA, GHSA2))])
    code, summary, ssh = env.run(now=T0 + 3600)
    assert code == 0 and "replies=1" in summary and "busy=1" in summary  # the unknown ja waits
    assert [c[2].startswith("lang: ja\nof: ") for c in ssh.ja] == [True]


def test_journal_item_from_before_rd8t_loads_and_sends(env):
    env.collector([finding()])
    env.run(ssh=FakeSSH("fail"))
    st = env.state()
    del st["outbox"][0]["ja"]  # the shape the poster before rd8t journals
    env.config.state.write_text(json.dumps(st))
    code, summary, ssh = env.run(now=T0 + 3600)
    assert code == 0 and "roots=1" in summary and ssh.ja == []


def test_each_english_reply_keeps_its_own_japanese_reply(env):
    env.collector([finding()])
    env.run()
    env.collector([finding(fid="CVE-2026-0002", aliases=("GHSA-abcd-efgh-ijkl",), sources=(GHSA, GHSA2))])
    _, _, ssh1 = env.run(now=T0 + 3600, ssh=FakeSSH(ja=["fail"]))
    env.collector([finding(fid="CVE-2026-0003", aliases=("GHSA-abcd-efgh-ijkl",))])
    _, summary, ssh2 = env.run(now=T0 + 7200, ssh=FakeSSH(ja=["fail"]))  # the older one fails again
    ja = [o for o in env.state()["outbox"] if o["kind"] == "ja"]  # a refused one goes last in line
    assert [o["text"].split("\n")[1] for o in ja] == [f"of: {ssh2.ids[0]}", f"of: {ssh1.ids[0]}"]
    st = env.state()
    st["outbox"][0]["sent"] = "cd" * 32  # a crash after the id was journaled: finished, never resent
    env.config.state.write_text(json.dumps(st))
    _, summary, ssh3 = env.run(now=T0 + 9000)  # before the digest hour
    assert "ja=2" in summary and len(ssh3.ja) == 1 and env.state()["outbox"] == []


def test_japanese_sends_start_after_marks_and_deferred_are_saved(env, monkeypatch):
    env.collector([finding()])
    env.run(ssh=FakeSSH("unknown"))  # the root is in flight: the next candidate is deferred
    env.collector([finding()])
    seen = []
    monkeypatch.setattr(main.Run, "drain_ja", lambda self: seen.append(env.state()))
    env.run(now=T0 + 3600)
    assert seen == [env.state()] and [d["id"] for d in seen[0]["deferred"]] == ["GHSA-abcd-efgh-ijkl"]


def test_japanese_backlog_is_bounded(env, monkeypatch):
    monkeypatch.setattr(main, "MAX_JA", 1)
    env.collector([finding()])
    env.run(ssh=FakeSSH(ja=["fail"]))
    env.collector([finding(fid="CVE-2026-0002", aliases=("GHSA-abcd-efgh-ijkl",), sources=(GHSA, GHSA2))])
    _, summary, _ = env.run(now=T0 + 3600, ssh=FakeSSH(ja=["fail"]))
    assert [o["kind"] for o in env.state()["outbox"]] == ["ja"]
    assert env.state()["outbox"][0]["key"].startswith("reply:")  # the older root one was dropped
    monkeypatch.setattr(main, "MAX_JA_BYTES", 10)  # over the byte budget, all in flight: not journaled
    env.collector([finding(fid="CVE-2026-0003", aliases=("GHSA-abcd-efgh-ijkl",))])
    _, summary, ssh = env.run(now=T0 + 7200, ssh=FakeSSH(ja=["unknown"]))
    assert "ja_failed=2" in summary and env.ledger()[1] == []  # the waiting one dropped, the new one declined
    assert env.state()["outbox"] == [] and ssh.ja == []


@pytest.mark.parametrize("missing", ["relay_ssh_host", "relay_send_wrapper"])
def test_no_relay_route_refuses_to_run(tmp_path, capsys, missing):
    keep = {k: v for k, v in RELAY.items() if k != missing}
    cfg = tmp_path / "config.toml"
    cfg.write_text(f'ledger = "{tmp_path / "ledger.json"}"\nkev_cache = "{tmp_path / "kev.json"}"\n'
                   + "".join(f'{k} = "{v}"\n' for k, v in keep.items()))
    assert main.main(["run", "--config", str(cfg)]) == 2
    assert "relay_ssh_host and relay_send_wrapper must be set" in capsys.readouterr().err
    ssh = FakeSSH()
    config = inputs.Config(ledger=tmp_path / "ledger.json", kev_cache=tmp_path / "kev.json", **keep)
    code, summary = main.run(T0, config, ssh=ssh, kev_fetch=FakeKEV(), channels=CHANNELS)
    assert code == 2 and summary.endswith(" error=config") and ssh.calls == []
    assert not (tmp_path / "ledger.json").exists()


def test_run_sets_strip_hosts_from_config(env, monkeypatch):
    monkeypatch.setattr(main.candidates, "FLEET_HOSTS", ())
    monkeypatch.setattr(main.candidates, "INTERNAL_SUFFIXES", ())
    env.config = replace(env.config, strip_hosts=("hostalpha",), internal_host_suffixes=(".corp.example",))
    env.run()
    assert main.candidates.FLEET_HOSTS == ("hostalpha",)
    assert main.candidates.INTERNAL_SUFFIXES == (".corp.example",)


def test_loaded_config_sets_route_and_strip_hosts(env, monkeypatch):
    monkeypatch.setattr(main.candidates, "FLEET_HOSTS", ())
    cfg = env.hb.parent / "config.toml"
    cfg.write_text(f'ledger = "{env.config.ledger}"\nkev_cache = "{env.config.kev_cache}"\n'
                   f'collector_runs = "{env.col}"\nstrip_hosts = ["hostalpha"]\n'
                   'relay_ssh_host = "op@relay.example.net"\nrelay_send_wrapper = "/opt/relay/bin/buzz-send"\n')
    env.collector([finding(), finding(fid="GHSA-zzzz-zzzz-zzzz", product="Claude Code on hostalpha")])
    fake, argvs = FakeSSH(), []
    code, _ = main.run(T0, cfg, ssh=lambda argv, **kw: argvs.append(argv) or fake(argv, **kw),
                       kev_fetch=env.kev, http_status=lambda url, timeout: 200, channels=CHANNELS)
    assert code == 0 and argvs
    for argv in argvs:
        assert argv[-2] == "op@relay.example.net" and argv[-3] == "--"
        assert shlex.split(argv[-1])[0] == "/opt/relay/bin/buzz-send"
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
    _, _, ssh = env.run(now=at(5, 9))
    assert [c[2] for c in ssh.calls] == ["Daily digest for 2026-11-05: no advisories."]
    m = env.mirror  # a curator thread, retracted by a reply or expired by its amendment
    r = m.root_post(m.cur_sec, advisory(aliases=["CVE-2026-7777"]))
    m.reply(m.cur_sec, r, "retract\nwrong")
    old = m.root_post(m.cur_sec, advisory(id="AITA-TEST-0002", posted_at=T0 - 9, expires_at=T0 - 1))
    with main.Ledger(env.config.ledger) as led:
        ids, roots = main.Run(T0, env.config, led, inputs.load_state(env.config.state, T0, 3),
                              CHANNELS, FakeSSH(), None)._withdrawn(m.root, m.fetch)
    assert ids == {"ghsa-abcd-efgh-ijkl"} and roots == {r["id"], old["id"]}  # a thread: by root only
    env.collector([finding(fid="GHSA-mnop-qrst-uvwx", sources=(GHSA2,)),
                   finding(fid="GHSA-mnop-qrst-uvwx", product="Google Chrome", sources=(GHSA2,))])
    env.run(now=at(6, 6))
    e = next(e for e in env.ledger()[0] if e["aliases"][0] == "GHSA-mnop-qrst-uvwx" and e["scope"] == "Claude Code")
    monkeypatch.setattr(main.Run, "_withdrawn", lambda self, root, fetch: (set(), {e["channel_ids"]["feed"]}))
    _, _, ssh = env.run(now=at(6, 9))  # the poster's own root, by its thread; the other product's stays
    assert ssh.calls[0][2].startswith("Daily digest for 2026-11-06: 1 advisory.") and "Chrome" in ssh.calls[0][2]


def test_failed_mirror_pull_holds_the_digest(env, capsys):
    env.collector([finding()])
    env.run()

    def down(url):
        raise OSError("down")
    code, summary, ssh = env.run(now=at(5, 9), mirror_fetch=down)
    assert code == 0 and ssh.calls == [] and " digest_held=1 " in summary and env.state()["digest_date"] != "2026-11-05"
    assert "digest held: mirror pull: unreachable" in capsys.readouterr().err
    _, _, ssh = env.run(now=at(5, 10))
    assert "GHSA-abcd-efgh-ijkl" in ssh.calls[0][2]


# ---------------------------------------------------------------- r7hr: the source title

TOCTOU = "TOCTOU Race in Edit Tool Allows File Writes Outside the Workspace"


def _cfe8(title=TOCTOU):
    """Shaped like the 2026-11-07T012306Z collector record's CVE-2026-88968 finding."""
    f = finding(fid="CVE-2026-88968", severity="high", fixed=None, sources=(GHSA, "https://example.org/write-up"),
                aliases=("GHSA-abcd-efgh-ijkl",))
    f["sources"][0]["title"] = title
    f["sources"][1]["title"] = "a non-primary source's words"
    return f


def test_root_and_digest_carry_the_source_title(env):
    env.collector([_cfe8()])
    _, _, ssh = env.run()
    root = ssh.calls[0][2].split("\n")
    assert "(CVE-2026-88968)" in root[0] and root[1] == TOCTOU
    assert ssh.ja[0][2].split("\n")[3] == f"原題: {TOCTOU}"  # lang: ja, of:, blank, head
    assert env.ledger()[0][0]["source_title"] == TOCTOU
    _, _, ssh = env.run(now=at(5, 9))
    assert f"(CVE-2026-88968): {TOCTOU};" in ssh.calls[0][2]


def test_a_title_learned_later_posts_nothing_and_reaches_the_digest(env):
    env.collector([_cfe8(title=None)])
    _, _, ssh = env.run()
    assert ssh.calls[0][2].split("\n")[1].startswith("Affected:")  # exactly as before r7hr
    assert "source_title" not in env.ledger()[0][0]
    env.collector([_cfe8()])
    _, _, ssh = env.run(now=T0 + 600)
    assert ssh.calls == []  # no reply for a title
    assert env.ledger()[0][0]["source_title"] == TOCTOU


def test_a_fence_in_the_title_never_withholds_the_advisory(env):
    env.collector([_cfe8(title="Race ~~~aitools-alert ``` in Edit")])
    _, _, ssh = env.run()
    assert ssh.calls and ssh.calls[0][2].split("\n")[1] == "Race ~aitools-alert in Edit"  # k5tr: no backtick


def test_a_held_notice_learns_its_title_for_the_digest(env):
    mac = dict(MAC, sources=[{"url": APPLE, "published_at": None}])
    env.collector([mac])
    env.run()
    mac["sources"][0]["title"] = "Kernel memory corruption"
    env.collector([mac])
    env.run(now=T0 + 600)
    assert env.state()["held"][0]["source_title"] == "Kernel memory corruption"
    _, _, ssh = env.run(now=at(5, 9))
    assert "(CVE-2026-5000): Kernel memory corruption;" in ssh.calls[0][2]


# ---------------------------------------------------------------- withheld (ai-tools-alerts#8acj)

THREE = [finding(), finding(fid="GHSA-zzzz-zzzz-zzzz", sources=(GHSA2,)),
         finding(fid="GHSA-yyyy-yyyy-yyyy", sources=(GHSA + "y",))]


def test_a_refused_item_is_withheld_and_the_run_goes_on(env, capsys):
    env.collector(THREE)
    code, summary, ssh = env.run(ssh=FakeSSH("refuse", ja=("refuse",)))  # a refused ja reply is dropped
    assert code == 0 and "withheld=1" in summary and "roots=2" in summary and "ja=1 ja_failed=1" in summary
    st, (entries, pending) = env.state(), env.ledger()
    assert st["collector"] and len(entries) == 2 and not pending and not st["outbox"] and len(st["deferred"]) == 1
    assert st["withheld"][0]["message"] == "relay error: blocked mention" and "GHSA-abcd" in st["withheld"][0]["key"]
    assert capsys.readouterr().err.count("withheld=1 refused by the relay") == 1
    env.collector([finding()])
    code, summary, ssh = env.run(now=T0 + 3600)  # never resent; its advisory waits
    assert code == 0 and ssh.calls == [] and "busy=1" in summary and len(env.state()["deferred"]) == 1
    assert "withheld=1 refused by the relay" in capsys.readouterr().err


def test_a_refused_root_withholds_its_copy(env):
    env.kev.catalog = {"vulnerabilities": [kev_item()]}
    code, summary, ssh = env.run(ssh=FakeSSH("refuse"))
    assert code == 0 and chans(ssh) == [("critical", None)] and "withheld=1" in summary
    assert [it["kind"] for it in env.state()["withheld"][0]["items"]] == ["root", "copy"] and not env.state()["outbox"]


def test_a_refused_digest_blocks_new_digests_until_resolved(env):
    env.collector([MAC]), env.run()
    assert "withheld=1" in env.run(now=at(5, 9), ssh=FakeSSH("refuse"))[1] and env.state()["digest_date"] is None
    assert env.run(now=at(5, 10))[2].calls == []  # neither resent nor rebuilt


def test_pending_lists_and_resolve_requeues_or_drops_a_withheld_item(env, tmp_path, capsys, monkeypatch):
    env.collector(THREE[:2])
    assert env.run(ssh=FakeSSH("refuse", "refuse"))[0] == 1  # a second refusal in one run stops it
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
    code, summary, ssh = env.run(now=T0 + 3600)  # requeued as the operator asked; w2's advisory still waits
    assert code == 0 and "roots=1" in summary and ssh.calls[0][2] == w["items"][0]["text"]
    assert main.main(["resolve", w2["key"], "--config", str(cfg), "--drop"]) == 0
    assert env.state()["withheld"] == [] and "dropped 1 item(s)" in capsys.readouterr().out
    assert "roots=1" in env.run(now=T0 + 7200)[1]  # its deferred candidate is planned anew


def test_a_withheld_reply_holds_its_thread_under_any_alias(env):
    env.collector([finding(aliases=("CVE-2026-0042",))]), env.run()
    env.collector([finding(fixed="2.2.0")])
    assert "withheld=1" in env.run(now=T0 + 600, ssh=FakeSSH("refuse"))[1]
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
    _, summary, ssh = env.run(now=T0 + 3600)
    assert "replies=2" in summary and len(seen) == 2 and all(s is True for s in seen)  # the new root, then the reply
    assert all("直ちに更新" in text for _, _, text in ssh.ja)
