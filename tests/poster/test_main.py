"""The hourly poster run (Task B4). Fake ssh, fake KEV fetch, fake source fetch: no network."""

import datetime as dt
import itertools
import json
import shlex
import subprocess

import pytest
from pathlib import Path

from aitools_alerts.poster import inputs, main
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
    """Answers each send from a queue: ok, fail (exit 5, never sent), unknown (timeout)."""

    def __init__(self, *outcomes):
        self.queue = list(outcomes)
        self.calls = []

    def __call__(self, argv, **kw):
        remote = shlex.split(argv[-1])
        ch = NAME[remote[remote.index("--channel") + 1]]
        reply = remote[remote.index("--reply-to") + 1] if "--reply-to" in remote else None
        self.calls.append((ch, reply, kw["input"].decode()))
        outcome = self.queue.pop(0) if self.queue else "ok"
        if outcome == "unknown":
            raise subprocess.TimeoutExpired("ssh", 120)
        if outcome == "fail":
            return subprocess.CompletedProcess(argv, 5, b"", b"conflict: write refused")
        return subprocess.CompletedProcess(
            argv, 0, json.dumps({"accepted": True, "event_id": next(_EVENT_IDS)}).encode(), b"")


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


@pytest.fixture
def env(tmp_path):
    class Env:
        hb, col = tmp_path / "heartbeat", tmp_path / "collector"
        config = inputs.Config(heartbeat_runs=tmp_path / "heartbeat", collector_runs=tmp_path / "collector",
                               ledger=tmp_path / "state" / "ledger.json",
                               kev_cache=tmp_path / "state" / "kev.json")
        kev = FakeKEV()
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


# ---------------------------------------------------------------- failure paths


def test_one_failure_stops_further_sends(env):
    env.collector([finding(), finding(fid="GHSA-zzzz-zzzz-zzzz", sources=(GHSA2,)), MAC])
    code, _, ssh = env.run(now=at(5, 9), ssh=FakeSSH("fail"))
    assert code == 1 and len(ssh.calls) == 1  # no second high, no digest
    st = env.state()
    assert st["collector"] is None and st["digest_date"] is None


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
    cfg.write_text(f'ledger = "{tmp_path / "s" / "ledger.json"}"\nkev_cache = "{tmp_path / "s" / "kev.json"}"\n')
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
    env.config = inputs.Config(ledger=env.config.ledger, kev_cache=env.config.kev_cache)
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
    st["digest_ids"] = [f"{i:064x}" for i in range(0xa0, 0xaa)]  # ten already
    env.config.state.write_text(json.dumps(st))
    code, _, ssh = env.run(now=at(5, 9))
    st = env.state()
    assert code == 0 and len(ssh.calls) == 1 and len(st["digest_ids"]) == 10
    assert st["digest_ids"][0] == f"{0xa1:064x}"  # the oldest dropped
    sent = st["digest_ids"][-1]
    assert f"digest 2026-11-05 sent: {sent}" in capsys.readouterr().err


def test_old_state_without_digest_ids_loads(env):
    env.run()
    st = env.state()
    del st["digest_ids"]
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
    cfg.write_text(f'ledger = "{tmp_path / "ledger.json"}"\nkev_cache = "{tmp_path / "kev.json"}"\n')
    bad = tmp_path / "kev.json.in"
    bad.write_text(body)
    assert main.main(["run", "--config", str(cfg), "--kev-file", str(bad)]) == 2
    assert "config error: kev file" in capsys.readouterr().err
    assert not (tmp_path / "ledger.json").exists()


def test_synthetic_fixture_says_so():
    c = inputs.read_kev_file(SYNTHETIC)
    assert [v["cveID"] for v in c["vulnerabilities"]] == ["CVE-2099-0010"]


def test_synthetic_advisory_is_marked_in_the_digest(env):
    catalog = inputs.read_kev_file(SYNTHETIC)
    code, summary, ssh = env.run(kev_catalog=catalog, digest_now=True)  # the same run digests it
    assert code == 0 and "digest=1" in summary
    (body,) = [c[2] for c in ssh.calls if c[2].startswith("Daily digest")]
    (line,) = [ln for ln in body.splitlines() if "CVE-2099-0010" in ln]
    assert line.startswith("- SYNTHETIC TEST: Claude Code") and line.count("SYNTHETIC") == 1
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
    env.config = inputs.Config(ledger=env.config.ledger, kev_cache=env.config.kev_cache, backfill_days=0)
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
