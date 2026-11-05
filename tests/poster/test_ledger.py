"""The advisory ledger and the alias merge (Task B3)."""

import json
import logging

import pytest

from aitools_alerts.poster import compose, ledger, rules
from aitools_alerts.poster.candidates import Candidate, Source
from aitools_alerts.poster.ledger import Ledger, LedgerError

KEV = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
GHSA = "https://github.com/anthropics/claude-code/security/advisories/GHSA-abcd-efgh-ijkl"
T0 = 1_800_000_000
DAY = 86400


def cand(**kw) -> Candidate:
    base = dict(id="CVE-2026-0001", aliases=(), product_text="Anthropic Claude Code",
                advisory_severity=None, local_level_hint=None, exploited=False,
                trojanized=False, injection_exec=False, fixed=None, affected=None,
                sources=(Source(KEV, None),), observed_at=None)
    base.update(kw)
    return Candidate(**base)


def pair(c):
    return c, rules.scope_of(c.product_text)


def adv_for(c, level="critical"):
    return compose.root_post(c, level, rules.scope_of(c.product_text), posted_at=T0)[1]


def test_ledger_alias_merge(tmp_path):
    kev = cand(exploited=True)
    beat = cand(id="GHSA-abcd-efgh-ijkl", aliases=("CVE-2026-0001",), fixed="2.1.0",
                sources=(Source(GHSA, None),))
    other = cand(id="FINDING-7", aliases=("CVE-2026-0001",), product_text="Docker Desktop")
    out = ledger.merge([pair(kev), pair(beat), pair(other)])
    assert len(out) == 2
    (m, ms), (o, os_) = out
    assert ms.name == "Claude Code" and m.id == "CVE-2026-0001"
    assert m.exploited and m.fixed == "2.1.0" and m.aliases == ("GHSA-abcd-efgh-ijkl",)
    assert [s.url for s in m.sources] == [KEV, GHSA]
    # A candidate under another scope never inherits the KEV clause.
    assert os_.name == "Docker" and o.exploited is False
    # Connectivity runs only through the same scope: no bridge via Docker.
    a = cand(id="CVE-2026-0005", aliases=("X-1",))
    b = cand(id="X-2", aliases=("X-1", "X-3"), product_text="docker engine")
    d = cand(id="CVE-2026-0006", aliases=("X-3",))
    assert len(ledger.merge([pair(a), pair(b), pair(d)])) == 3
    # Every member's own id survives as an alias, so a later run finds the thread by it.
    (ab, _), = ledger.merge([pair(cand(id="CVE-2026-0007", aliases=("X-9",))),
                             pair(cand(id="GHSA-zzzz-zzzz-zzzz", aliases=("X-9",)))])
    assert set(ab.aliases) == {"X-9", "GHSA-zzzz-zzzz-zzzz"}
    with Ledger(tmp_path / "m.json") as led:
        led.record_root(adv_for(ab), "r9", {"feed": "r9"}, scope="Claude Code", exploited=False, now=T0)
        assert led.lookup(["GHSA-zzzz-zzzz-zzzz"]).root_event_id == "r9"
    # The ledger carries exploited from a stored entry of the same scope only.
    with Ledger(tmp_path / "l.json") as led:
        led.record_root(adv_for(kev), "e1", {"critical": "e1", "feed": "f1"},
                        scope="Claude Code", exploited=True, now=T0)
        (got, _), = ledger.merge([pair(beat)], led)
        assert got.exploited is True
        (got, _), = ledger.merge([pair(other)], led)
        assert got.exploited is False


def test_pending_blocks_resend(tmp_path, caplog):
    path = tmp_path / "l.json"
    with Ledger(path) as led:
        led.pending("CVE-2026-0001:critical", ["CVE-2026-0001", "GHSA-x"], now=T0)
        on_disk = json.loads(path.read_text())
        assert on_disk["pending"][0]["key"] == "CVE-2026-0001:critical"  # written before the send
    with Ledger(path) as led:  # a later run, the outcome still unknown
        with pytest.raises(LedgerError):
            led.pending("CVE-2026-0001:critical", ["CVE-2026-0001"], now=T0 + 60)
        with pytest.raises(LedgerError):  # another key for the same advisory
            led.pending("GHSA-x:feed", ["ghsa-X"], now=T0 + 60)
        assert led.pending_for(["GHSA-X"])
        with pytest.raises(LedgerError):  # under 24 h
            led.expire_pending("CVE-2026-0001:critical", "operator checked", now=T0 + DAY - 1)
        with pytest.raises(LedgerError):  # no reason
            led.expire_pending("CVE-2026-0001:critical", " ", now=T0 + DAY)
        with caplog.at_level(logging.WARNING):
            led.expire_pending("CVE-2026-0001:critical", "relay shows no event", now=T0 + DAY)
        assert "relay shows no event" in caplog.text
        led.pending("CVE-2026-0001:critical", ["CVE-2026-0001"], now=T0 + DAY)
        led.clear_pending("CVE-2026-0001:critical")
        led.pending("CVE-2026-0001:critical", ["CVE-2026-0001"], now=T0 + DAY)
        with pytest.raises(LedgerError):
            led.clear_pending("never-there")
    data = json.loads(path.read_text())
    assert data["expired"][0]["reason"] == "relay shows no event"


def test_lock_refuses_second_run(tmp_path):
    with Ledger(tmp_path / "l.json"):
        with pytest.raises(LedgerError):
            Ledger(tmp_path / "l.json").__enter__()
    with Ledger(tmp_path / "l.json"):
        pass  # released on exit
    with pytest.raises(LedgerError):  # used outside the context
        Ledger(tmp_path / "l.json").lookup(["x"])


def test_malformed_ledger_is_refused(tmp_path):
    p = tmp_path / "l.json"
    for text in ("{", "[]", '{"schema_version": 1, "entries": {}}'):
        p.write_text(text)
        with pytest.raises(LedgerError):
            Ledger(p).__enter__()


def test_roots_replies_and_review(tmp_path):
    p = tmp_path / "d" / "l.json"
    c = cand(exploited=True)
    with Ledger(p) as led:
        assert led.lookup(["CVE-2026-0001"]) is None
        led.record_root(adv_for(c), "e1", {"critical": "e1", "feed": "f1"},
                        scope="Claude Code", exploited=True, now=T0)
        with pytest.raises(LedgerError):  # a known alias is a reply, never a new root
            led.record_root(adv_for(cand(aliases=("CVE-2026-0001",), id="GHSA-q")), "e2",
                            {"feed": "e2"}, scope="Claude Code", exploited=False, now=T0)
        e = led.lookup(["cve-2026-0001"])
        assert e.root_event_id == "e1" and e.channel_ids == {"critical": "e1", "feed": "f1"}
        assert led.lookup(["CVE-2026-0001"], scope="Docker") is None
        newer = adv_for(cand(aliases=("OSV-1",)), "high")
        led.record_reply("e1", newer, {"feed": "r1"}, now=T0 + 5)
        led.add_review(["Anthropic Widget\x07", "Anthropic Widget", "x" * 900], now=T0)
        led.add_review(["Anthropic Widget"], now=T0 + 9)
    assert sorted(f.name for f in p.parent.iterdir()) == ["l.json", "l.json.lock"]
    assert (p.stat().st_mode & 0o777) == 0o600
    with Ledger(p) as led:
        e = led.lookup(["OSV-1"])
        assert e.level == "high" and e.last_change == T0 + 5 and e.exploited is True
        assert e.replies == [{"feed": "r1"}] and e.advisory["level"] == "high"
        assert {"CVE-2026-0001", "OSV-1"} <= set(e.aliases)
        with pytest.raises(LedgerError):
            led.record_reply("nope", newer, {"feed": "r2"}, now=T0)
    review = json.loads(p.read_text())["review"]
    assert [r["text"] for r in review] == ["Anthropic Widget", "x" * 300]
    assert review[0]["count"] == 3 and review[0]["last_seen"] == T0 + 9
