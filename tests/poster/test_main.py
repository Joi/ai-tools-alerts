"""The hourly poster run (Task B4). Fake ssh, fake KEV fetch, fake source fetch: no network."""

import datetime as dt
import itertools
import json
import shlex
import subprocess

import pytest

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

        def run(self, now=T0, ssh=None, kev=None):
            ssh = ssh if ssh is not None else FakeSSH()
            code, summary = main.run(now, self.config, ssh=ssh, kev_fetch=kev or self.kev,
                                     http_status=lambda url, timeout: 200, channels=CHANNELS)
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
