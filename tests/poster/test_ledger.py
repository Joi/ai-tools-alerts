"""The advisory ledger and the alias merge (Task B3)."""

import json
import logging

import pytest
from dataclasses import asdict, replace

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


def test_merge_keeps_every_pages_severity_word_and_no_records():  # dmmf
    (m, _), = ledger.merge([pair(cand(advisory_severity="critical; Title", severity_word="high")),
                            pair(cand(id="GHSA-abcd-efgh-ijkl", aliases=("CVE-2026-0001",), severity_word="critical")),
                            pair(cand(id="GHSA-zzzz-zzzz-zzzz", aliases=("CVE-2026-0001",), advisory_severity="low"))])
    assert m.severity_word == "high; critical" and compose.severity(m.severity_word) == "critical"
    assert m.advisory_severity == "critical; Title; low"  # the level's input, never published


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
            led.record_root(adv_for(cand(aliases=("CVE-2026-0001",), id="GHSA-qqqq-qqqq-qqqq")), "e2",
                            {"feed": "e2"}, scope="Claude Code", exploited=False, now=T0)
        e = led.lookup(["cve-2026-0001"])
        assert e.root_event_id == "e1" and e.channel_ids == {"critical": "e1", "feed": "f1"}
        assert led.lookup(["CVE-2026-0001"], scope="Docker") is None
        newer = adv_for(cand(aliases=("CVE-2026-0101",)), "high")
        led.record_reply("e1", newer, {"feed": "r1"}, now=T0 + 5)
        led.add_review(["Anthropic Widget\x07", "Anthropic Widget", "x" * 900], now=T0)
        led.add_review(["Anthropic Widget"], now=T0 + 9)
    assert sorted(f.name for f in p.parent.iterdir()) == ["l.json", "l.json.lock"]
    assert (p.stat().st_mode & 0o777) == 0o600
    with Ledger(p) as led:
        e = led.lookup(["CVE-2026-0101"])
        assert e.level == "high" and e.last_change == T0 + 5 and e.exploited is True
        assert e.replies == [{"feed": "r1"}] and e.advisory["level"] == "high"
        assert {"CVE-2026-0001", "CVE-2026-0101"} <= set(e.aliases)
        with pytest.raises(LedgerError):
            led.record_reply("nope", newer, {"feed": "r2"}, now=T0)
    review = json.loads(p.read_text())["review"]
    assert [r["text"] for r in review] == ["Anthropic Widget", "x" * 300]
    assert review[0]["count"] == 3 and review[0]["last_seen"] == T0 + 9


def test_review_fixes_ledger(tmp_path, monkeypatch):
    p = tmp_path / "l.json"
    with Ledger(p) as led:
        led.pending("A:critical", ["A"], now=T0)
        with pytest.raises(LedgerError):  # refused, but the A~B link is kept
            led.pending("A:feed", ["A", "B"], now=T0)
    with Ledger(p) as led:
        with pytest.raises(LedgerError):
            led.pending("B:feed", ["B"], now=T0)
        many = [f"OSV-{i}" for i in range(70)]
        e = led.record_root(adv_for(cand()), "e1", {"critical": "e1"}, scope="Claude Code",
                            exploited=False, now=T0, ids=many)
        led.add_channel("e1", "feed", "f1")
        led.record_root(adv_for(cand(id="CVE-2026-0002", exploited=True)), "e2", {"feed": "e2"},
                        scope="Claude Code", exploited=True, now=T0 + 1)
        # A save that fails leaves memory as it was on disk.
        monkeypatch.setattr(ledger.os, "replace", lambda *a: (_ for _ in ()).throw(OSError("disk")))
        with pytest.raises(LedgerError):
            led.add_channel("e1", "x", "y")
        assert "x" not in led.lookup(["e1", "CVE-2026-0001"]).channel_ids
        monkeypatch.undo()
    with Ledger(p) as led:
        assert led.lookup(["OSV-69"]).channel_ids == {"critical": "e1", "feed": "f1"}
        # A candidate bridging an unexploited older entry and an exploited newer one.
        (got, _), = ledger.merge([pair(cand(id="X-1", aliases=("OSV-3", "CVE-2026-0002")))], led)
        assert got.exploited is True
    for text in ('{"schema_version": 1, "entries": [], "pending": [{"key": "k", "aliases": [7], "at": 1}],'
                 ' "expired": [], "review": []}',
                 '{"schema_version": 1, "entries": [], "pending": [{"key": "k", "aliases": ["a"], "at": 1}],'
                 ' "pending": [], "expired": [], "review": []}'):
        p.write_text(text)
        with pytest.raises(LedgerError):
            Ledger(p).__enter__()


def test_merge_keeps_severity_and_one_fix_in_either_order():
    a = cand(advisory_severity=None, fixed=None)
    b = cand(id="GHSA-qqqq-qqqq-qqqq", aliases=("CVE-2026-0001",), fixed="2.1.0", affected="<2.1.0",
             advisory_severity="remote code execution")
    for order in ([a, b], [b, a]):
        (m, s), = ledger.merge([pair(x) for x in order])
        assert rules.level_for(m, s, False) == ("high", "fix-rce-tier1")
        assert (m.fixed, m.affected) == ("2.1.0", "<2.1.0")


def test_merged_severity_words_alone_stay_a_notice():
    """9kgk: the upstream severity never sets the level alone, merged or not."""
    a = cand(advisory_severity="high", fixed=None)
    b = cand(id="GHSA-5xjx-9qx6-jcrv", aliases=("CVE-2026-0001",), advisory_severity="Critical")
    c = cand(id="CVE-2026-0001", aliases=(), advisory_severity="moderate")
    for order in ([a, b], [b, a], [c, a], [a, c]):
        (m, s), = ledger.merge([pair(x) for x in order])
        assert rules.level_for(m, s, False) == ("notice", "notice"), m.advisory_severity


def test_delta_fixes(tmp_path, monkeypatch):
    a = cand(affected="<2.0.0", fixed=None, advisory_severity="x" * 500)
    b = cand(id="GHSA-qqqq-qqqq-qqqq", aliases=("CVE-2026-0001",), fixed="2.0.0-rc.1", injection_exec=True,
             advisory_severity="remote code execution")
    for order in ([a, b], [b, a]):
        (m, _), = ledger.merge([pair(x) for x in order])
        assert m.fixed == "2.0.0-rc.1" and "remote code execution" in m.advisory_severity
    with Ledger(tmp_path / "l.json") as led:
        led.record_root(adv_for(cand()), "e1", {"feed": "e1"}, scope="Claude Code",
                        exploited=False, now=T0)
        real, calls = ledger.os.fsync, []

        def fsync(fd):  # the file syncs; the directory sync after the rename fails
            calls.append(fd)
            if len(calls) > 1:
                raise OSError("sync")
            real(fd)
        monkeypatch.setattr(ledger.os, "fsync", fsync)
        with pytest.raises(LedgerError):
            led.add_channel("e1", "critical", "c1")
        monkeypatch.undo()
        with pytest.raises(LedgerError):  # the context is unusable once disk and memory may differ
            led.lookup(["CVE-2026-0001"])


def test_entries_since_and_has_pending(tmp_path):
    with Ledger(tmp_path / "l.json") as led:
        c = cand(fixed="2.1.0")
        led.record_root(adv_for(c), "r1", {"feed": "r1"}, scope="Claude Code", exploited=False, now=T0)
        assert [e.root_event_id for e in led.entries_since(T0 - 1)] == ["r1"]
        assert led.entries_since(T0) == []
        assert not led.has_pending("k")
        led.pending("k", ["CVE-2026-0001"], now=T0)
        assert led.has_pending("k")


def test_merge_keeps_a_source_title_whichever_member_comes_first():
    beat = cand()
    col = cand(id="GHSA-abcd-efgh-ijkl", aliases=("CVE-2026-0001",), source_title="Race in Edit Tool")
    for order in ([beat, col], [col, beat]):
        (m, _), = ledger.merge([pair(c) for c in order])
        assert m.source_title == "Race in Edit Tool"


# ---------------------------------------------------------------- listing (8ke5)

def test_a_reply_lists_the_thread_again_only_for_level_fix_or_action(tmp_path):
    import dataclasses
    from aitools_alerts import schema
    with Ledger(tmp_path / "l.json") as led:
        adv = adv_for(cand(), "high")
        led.record_root(adv, "r1", {"feed": "r1"}, scope="Claude Code", exploited=False, now=T0)
        more = dataclasses.replace(adv, sources=[*adv.sources, schema.Source(GHSA, None)])
        led.record_reply("r1", more, {"feed": "a1"}, now=T0 + 10)  # sources only
        ranged = dataclasses.replace(more, products=[dataclasses.replace(more.products[0], affected="<2.0.0")])
        led.record_reply("r1", ranged, {"feed": "a2"}, now=T0 + 20)  # a range, no fix
        e = led.thread("r1")
        assert e.last_change == T0 + 20 and e.listed == T0 and led.entries_since(T0) == []
        fixed = adv_for(cand(fixed="2.1.0"), "high")
        led.record_reply("r1", fixed, {"feed": "a3"}, now=T0 + 30)  # fixed version and action
        assert led.thread("r1").listed == T0 + 30 and len(led.entries_since(T0)) == 1
        led.record_reply("r1", dataclasses.replace(fixed, level="critical"), {"feed": "a4"}, now=T0 + 40)
        assert led.thread("r1").listed == T0 + 40  # the level


def test_a_legacy_entry_keeps_its_listing_time(tmp_path):
    """An entry written before 8ke5 has no listed_at: its last change counts, once."""
    import dataclasses
    p = tmp_path / "l.json"
    with Ledger(p) as led:
        adv = adv_for(cand(), "high")
        led.record_root(adv, "r1", {"feed": "r1"}, scope="Claude Code", exploited=False, now=T0)
    data = json.loads(p.read_text())
    e = data["entries"][0]
    del e["listed_at"]
    e["last_change"] = T0 + 5  # an old source-only reply moved it
    p.write_text(json.dumps(data))
    with Ledger(p) as led:
        assert led.thread("r1").listed == T0 + 5
        ranged = dataclasses.replace(adv, products=[dataclasses.replace(adv.products[0], affected="<2.0.0")])
        led.record_reply("r1", ranged, {"feed": "a1"}, now=T0 + 99)
        assert led.thread("r1").listed == T0 + 5 and led.thread("r1").last_change == T0 + 99
    e["listed_at"] = None  # never written: refused like any other malformed entry
    p.write_text(json.dumps(data))
    with pytest.raises(LedgerError, match="malformed"):
        with Ledger(p):
            pass


def test_learned_sources_wait_for_the_next_reply(tmp_path):
    import dataclasses
    from aitools_alerts import schema
    with Ledger(tmp_path / "l.json") as led:
        adv = adv_for(cand(), "high")
        led.record_root(adv, "r1", {"feed": "r1"}, scope="Claude Code", exploited=False, now=T0)
        led.learn_sources("r1", [schema.Source(KEV, None), schema.Source(GHSA, "2026-11-01")])
        led.learn_sources("r1", [schema.Source(GHSA, None)])  # once each, never the advisory's own
        assert led.thread("r1").learned_sources == [{"url": GHSA, "published_at": "2026-11-01"}]
        led.learn_sources("r1", [schema.Source(f"{GHSA}{i}", None) for i in range(40)])
        assert len(led.thread("r1").learned_sources) == ledger.MAX_LEARNED
        posted = dataclasses.replace(adv, sources=[*adv.sources, schema.Source(GHSA, None)])
        led.record_reply("r1", posted, {"feed": "a1"}, now=T0 + 10)
        assert GHSA not in [x["url"] for x in led.thread("r1").learned_sources]


def test_a_legacy_entry_keeps_its_root_fix_through_its_first_reply(tmp_path):
    """Delta review: an entry written before root_fixed infers it from the advisory while no
    reply changed it, and keeps it when the first reply is recorded."""
    from aitools_alerts.poster.ledger import Ledger
    with Ledger(tmp_path / "ledger.json") as led:
        _, adv = compose.root_post(cand(fixed="2.1.0"), ("high", "fix-rce-tier1"), rules.scope_of("Claude Code"),
                                   posted_at=1795000000)
        led.record_root(adv, "r" * 64, {"feed": "r" * 64}, scope="Claude Code", exploited=False, now=1795000000)
        led._state()["entries"][0].pop("root_fixed")  # as written before 9kgk
        assert led.thread("r" * 64).fix_at_root == "2.1.0"
        wider = replace(adv, products=[replace(adv.products[0], affected="<2.5.0", fixed="2.5.0")])
        led.record_reply("r" * 64, wider, {"feed": "e" * 64}, now=1795000600)
        assert led.thread("r" * 64).fix_at_root == "2.1.0"


def test_a_level_change_is_counted_once_and_a_lowering_marks_the_thread(tmp_path):  # ny5g
    import dataclasses
    with Ledger(tmp_path / "l.json") as led:
        adv = adv_for(cand(), "critical")
        led.record_root(adv, "r1", {"feed": "r1", "critical": "r2"}, scope="Claude Code", exploited=True, now=T0,
                        floor="notice")
        assert led.thread("r1").floor == "notice" and led.thread("r1").lowered is None
        led.record_reply("r1", dataclasses.replace(adv, title="other"), {"feed": "a0"}, now=T0 + 5)
        assert led.thread("r1").changed is None  # the level did not change
        low = dataclasses.replace(adv, level="notice")
        led.record_reply("r1", low, {"critical": "a1"}, now=T0 + 10)
        led.record_reply("r1", low, {"feed": "a2"}, now=T0 + 11)  # the other channel's copy of the same change
        e = led.thread("r1")
        assert e.level == "notice" and e.lowered is True and e.changed == [T0 + 10]
        led.record_reply("r1", dataclasses.replace(adv, level="high"), {"feed": "a3"}, now=T0 + 8 * DAY)
        e = led.thread("r1")
        assert e.changed == [T0 + 8 * DAY] and e.lowered is True  # the older time is past seven days; the mark stays
        led.learn_floor("r1", "high")
        led.learn_floor("r1", "severe")  # not a level: ignored
        assert led.thread("r1").floor == "high" and [x.root_event_id for x in led.entries()] == ["r1"]
        # A lowered thread lends a candidate no exploited mark: the catalog dropped it.
        (merged, _), = ledger.merge([pair(cand())], led)
        assert merged.exploited is False
    with Ledger(tmp_path / "m.json") as led:
        led.record_root(adv, "r1", {"feed": "r1"}, scope="Claude Code", exploited=True, now=T0)
        assert led.thread("r1").floor is None
        (merged, _), = ledger.merge([pair(cand())], led)
        assert merged.exploited is True


def test_the_withdrawn_state_is_kept_by_channel_beside_the_level(tmp_path):  # kk2q
    with Ledger(tmp_path / "l.json") as led:
        adv = adv_for(cand(), "critical")
        led.record_root(adv, "r1", {"feed": "r1", "critical": "r2"}, scope="Claude Code", exploited=False, now=T0)
        assert led.thread("r1").withdrawn is None
        led.record_reply("r1", adv, {"feed": "a1"}, now=T0 + 10, withdrawn=True)
        e = led.thread("r1")
        assert (e.level, e.advisory, e.withdrawn, e.lowered, e.changed) == ("critical", asdict(adv), ["feed"], True, [T0 + 10])
        led.record_reply("r1", adv, {"critical": "a2"}, now=T0 + 11, withdrawn=True)  # the other channel: counted once
        e = led.thread("r1")
        assert e.withdrawn == ["critical", "feed"] and e.changed == [T0 + 10]
        led.record_reply("r1", replace(adv, title="other"), {"feed": "a3"}, now=T0 + 12)  # no level in it: the state stays
        assert led.thread("r1").withdrawn == ["critical", "feed"] and led.thread("r1").changed == [T0 + 10]
        # a reply that names a level ends it in its channel, at the kept level too, and is a change
        led.record_reply("r1", adv, {"feed": "a4"}, now=T0 + 20, withdrawn=False)
        e = led.thread("r1")
        assert e.withdrawn == ["critical"] and e.level == "critical" and e.changed == [T0 + 10, T0 + 20]
        led.record_reply("r1", adv, {"critical": "a5"}, now=T0 + 20, withdrawn=False)  # the same run: counted once
        e = led.thread("r1")
        assert e.withdrawn is None and e.changed == [T0 + 10, T0 + 20] and e.lowered is True
        # sent to one channel by a later run (it was refused there before): its own change
        led.record_reply("r1", adv, {"feed": "b1"}, now=T0 + 30, withdrawn=True)
        led.record_reply("r1", adv, {"critical": "b2"}, now=T0 + 30, withdrawn=True)
        led.record_reply("r1", replace(adv, level="high"), {"feed": "b3"}, now=T0 + 40, withdrawn=False)
        assert led.thread("r1").changed[-2:] == [T0 + 30, T0 + 40] and led.thread("r1").level == "high"  # one time, not two
        led.record_reply("r1", replace(adv, level="high"), {"critical": "b4"}, now=T0 + 50, withdrawn=False)
        e = led.thread("r1")
        assert e.withdrawn is None and e.changed[-2:] == [T0 + 40, T0 + 50]
        led.record_reply("r1", replace(adv, level="high"), {"feed": "b5"}, now=T0 + 60, withdrawn=False)  # not withdrawn: nothing
        assert led.thread("r1").changed[-1] == T0 + 50
    with Ledger(tmp_path / "l.json") as led:  # it loads again, with and without the key
        assert led.thread("r1").withdrawn is None


@pytest.mark.parametrize("bad", [{"lowered": 1}, {"floor": "severe"}, {"floor": None}, {"changed": [1.5]},
                                 {"changed": list(range(51))}, {"changed": 3},
                                 {"withdrawn": True}, {"withdrawn": []}, {"withdrawn": "feed"}, {"withdrawn": ["critical"]},
                                 {"withdrawn": ["feed", "feed"]}, {"withdrawn": None},
                                 {"joined": False}, {"joined": True}, {"joined": None}, {"joined": []},
                                 {"joined": [[]]}, {"joined": [["b", "a"]]}, {"joined": [["GHSA-A"]]}])  # btqg
def test_a_ledger_with_a_malformed_recompute_key_is_refused(tmp_path, bad):  # ny5g
    path = tmp_path / "l.json"
    with Ledger(path) as led:
        led.record_root(adv_for(cand()), "r1", {"feed": "r1"}, scope="Claude Code", exploited=True, now=T0)
    data = json.loads(path.read_text())
    data["entries"][0].update(bad)
    path.write_text(json.dumps(data))
    with pytest.raises(LedgerError, match="malformed"):
        Ledger(path).__enter__()


def test_joined_advisories_are_kept_by_group_and_leave_whole(tmp_path):  # btqg
    path = tmp_path / "l.json"
    with Ledger(path) as led:
        led.record_root(adv_for(cand()), "r1", {"feed": "r1"}, scope="Claude Code", exploited=False, now=T0)
        assert led.thread("r1").joined is None and led.thread("r1").member(["GHSA-zzzz-zzzz-zzzz"]) is None
        e = led.add_ids("r1", ["GHSA-zzzz-zzzz-zzzz"], joined=True)
        assert e.joined == [["ghsa-zzzz-zzzz-zzzz"]]
        e = led.add_ids("r1", ["GHSA-zzzz-zzzz-zzzz", "CVE-2026-0002"], joined=True)  # its CVE, learned later
        e = led.add_ids("r1", ["GHSA-yyyy-yyyy-yyyy"], joined=True)
        assert e.joined == [["cve-2026-0002", "ghsa-zzzz-zzzz-zzzz"], ["ghsa-yyyy-yyyy-yyyy"]]
        assert e.member(["CVE-2026-0002"]) == ["cve-2026-0002", "ghsa-zzzz-zzzz-zzzz"]
        assert e.member(["CVE-2026-0002", cand().id]) is None  # with one of the thread's own ids: not a member
    with Ledger(path) as led:  # it loads again
        e = led.unjoin("r1", ["CVE-2026-0002"])
        assert e.joined == [["ghsa-yyyy-yyyy-yyyy"]]
        assert not {"cve-2026-0002", "ghsa-zzzz-zzzz-zzzz"} & {a.casefold() for a in e.aliases}
        with pytest.raises(LedgerError):
            led.unjoin("r1", [cand().id])
        assert led.unjoin("r1", ["GHSA-yyyy-yyyy-yyyy"]).joined is None
    with Ledger(path) as led:
        assert "joined" not in led._state()["entries"][0]


# ---------------------------------------------------------------- faxq: one release, one post

def _gh(gid, **kw):
    return cand(id=gid, sources=(Source(f"https://github.com/anthropics/claude-code/security/advisories/{gid}", None),),
                **kw)


def test_advisories_one_release_fixes_merge_into_one_candidate():
    a = _gh("GHSA-aaaa-aaaa-aaaa", fixed="2.1.0", affected="<2.1.0", injection_exec=True)
    b = _gh("GHSA-bbbb-bbbb-bbbb", fixed="v2.1.0", affected="<2.1.0", exploited=True)
    c = _gh("GHSA-cccc-cccc-cccc", fixed="2.2.0")  # another release
    d = _gh("GHSA-dddd-dddd-dddd")  # no fix: never grouped
    e = _gh("GHSA-eeee-eeee-eeee", fixed="2.1.0", product_text="docker engine")  # another product
    f = _gh("CVE-2099-0003", fixed="2.1.0")  # a synthetic id is never grouped with a real one
    g = _gh("GHSA-gggg-gggg-gggg", fixed="2.1.0-rc 1")  # a fix the schema cannot say
    groups = {}
    out = ledger.merge([pair(x) for x in (a, b, c, d, e, f, g)], groups=groups)
    assert sorted(m.id for m, _ in out) == sorted(x.id for x in (a, c, d, e, f, g))
    (ab, s), = [(m, s) for m, s in out if m.id == a.id]
    assert ab.aliases == ("GHSA-bbbb-bbbb-bbbb",) and ab.exploited and ab.injection_exec  # the loudest member
    assert ab.fixed == "2.1.0" and ab.affected == "<2.1.0" and len(ab.sources) == 2
    assert [m.id for m in groups[("Claude Code", a.id.casefold())]] == [a.id, b.id] and len(groups) == 1


@pytest.mark.parametrize("ranges,want", [
    (("<2.1.0", "<2.1.0"), "<2.1.0"),
    ((">=2.0,<2.1.0", ">=1.0,<2.1.0"), "<2.1.0"),  # every member's installations, and more
    (("<2.1.0", None), None),  # one states none: the group states none
])
def test_a_fix_groups_range_covers_every_member(ranges, want):
    (m, _), = ledger.merge([pair(_gh(f"GHSA-aaaa-aaaa-aa{i:02d}", fixed="2.1.0", affected=r))
                            for i, r in enumerate(ranges)])
    assert m.affected == want


def test_a_candidate_with_a_thread_joins_no_fix_group(tmp_path):
    a = _gh("GHSA-aaaa-aaaa-aaaa", fixed="2.1.0")
    b = _gh("GHSA-bbbb-bbbb-bbbb", fixed="2.1.0")
    with Ledger(tmp_path / "l.json") as led:
        led.record_root(adv_for(a, "high"), "r1", {"feed": "r1"}, scope="Claude Code", exploited=False, now=T0)
        assert len(ledger.merge([pair(a), pair(b)], led)) == 2  # two threads never become one


def test_a_fix_groups_first_member_is_the_newest():
    """Review: the age limit reads the group's primary source, so the newest member's."""
    old = cand(id="GHSA-aaaa-aaaa-aaaa", fixed="2.1.0", sources=(Source(
        "https://github.com/anthropics/claude-code/security/advisories/GHSA-aaaa-aaaa-aaaa", "2026-10-01T00:00:00Z"),))
    new = cand(id="GHSA-bbbb-bbbb-bbbb", fixed="2.1.0", sources=(Source(
        "https://github.com/anthropics/claude-code/security/advisories/GHSA-bbbb-bbbb-bbbb", "2026-11-04T00:00:00Z"),))
    for order in ((old, new), (new, old)):
        (m, _), = ledger.merge([pair(x) for x in order])
        assert m.id == new.id and m.aliases == (old.id,)


def test_a_fix_group_is_cut_to_what_one_block_can_name():
    """Review: a block names an id and at most 50 aliases; a member past that would be
    recorded as posted and never named."""
    many = [_gh(f"GHSA-aaaa-aaaa-{i:04d}", fixed="2.1.0", aliases=(f"CVE-2026-{1000 + i}",)) for i in range(30)]
    out = ledger.merge([pair(x) for x in many])
    assert len(out) == 2 and all(1 + len(m.aliases) <= 51 for m, _ in out)
    assert sum(1 + len(m.aliases) for m, _ in out) == 60


def test_an_id_with_work_in_flight_or_a_thread_under_a_former_name_joins_no_group(tmp_path):
    a = _gh("GHSA-aaaa-aaaa-aaaa", fixed="2.1.0", product_text="pypi:mcp-server-git")
    b = _gh("GHSA-bbbb-bbbb-bbbb", fixed="2.1.0", product_text="pypi:mcp-server-git")
    assert len(ledger.merge([pair(a), pair(b)])) == 1
    assert len(ledger.merge([pair(a), pair(b)], settled={"mcp-server-git|ghsa-aaaa-aaaa-aaaa"})) == 2
    with Ledger(tmp_path / "l.json") as led:
        adv = adv_for(a, "high")
        led.record_root(adv, "r1", {"feed": "r1"}, scope="MCP servers and clients", exploited=False, now=T0)
        assert len(ledger.merge([pair(a), pair(b)], led)) == 2


def test_the_newest_member_is_found_whatever_form_its_date_takes():
    """Delta review: a space before the time, an offset or a date alone do not sort as strings."""
    url = "https://github.com/anthropics/claude-code/security/advisories/"
    old = cand(id="GHSA-aaaa-aaaa-aaaa", fixed="2.1.0", sources=(Source(url + "GHSA-aaaa-aaaa-aaaa", "2026-11-17T00:00:00Z"),))
    for when in ("2026-11-17 23:00:00Z", "2026-11-18T08:00:00+09:00", "2026-11-18"):
        new = cand(id="GHSA-bbbb-bbbb-bbbb", fixed="2.1.0", sources=(Source(url + "GHSA-bbbb-bbbb-bbbb", when),))
        (m, _), = ledger.merge([pair(old), pair(new)])
        assert m.id == new.id, when


def test_a_groups_members_are_keyed_under_its_former_names_too():
    a = _gh("GHSA-aaaa-aaaa-aaaa", fixed="2.1.0", product_text="pypi:mcp-server-git")
    b = _gh("GHSA-bbbb-bbbb-bbbb", fixed="2.1.0", product_text="pypi:mcp-server-git")
    groups = {}
    (m, _), = ledger.merge([pair(a), pair(b)], groups=groups)
    assert set(groups) == {("mcp-server-git", m.id.casefold()), ("MCP servers and clients", m.id.casefold())}


def test_the_standing_claim_and_the_roots_ids_are_optional_keys(tmp_path):
    """gtw9: an entry without them loads; ``set_claim`` writes the claim, and the root's
    ids once; a level change recorded later counts from when it was sent."""
    import json
    p = tmp_path / "l.json"
    with Ledger(p) as led:
        led.record_root(adv_for(cand()), "e1", {"feed": "e1"}, scope="Claude Code", exploited=False, now=T0)
        e = led.thread("e1")
        assert e.claim is None and e.root_ids is None
        with pytest.raises(LedgerError):
            led.set_claim("e1", "")
        with pytest.raises(LedgerError):
            led.set_claim("nope", "{}")
        assert led.set_claim("e1", "one", ["CVE-2026-0001", "GHSA-x"]).root_ids == ["CVE-2026-0001", "GHSA-x"]
        e = led.set_claim("e1", "two", ["other"])
        assert e.claim == "two" and e.root_ids == ["CVE-2026-0001", "GHSA-x"]  # the root's ids are written once
        led.record_reply("e1", adv_for(cand(), "high"), {"feed": "r1"}, now=T0 + 9 * DAY, changed_at=T0 + DAY)
        assert led.thread("e1").changed == [T0 + DAY]
    with Ledger(p) as led:
        assert led.thread("e1").claim == "two"
    data = json.loads(p.read_text())
    data["entries"][0]["claim"] = ""
    p.write_text(json.dumps(data))
    with pytest.raises(LedgerError):
        Ledger(p).__enter__()


def test_a_thread_ends_once_and_a_recorded_raise_makes_it_an_ordinary_thread_again(tmp_path):
    """65xv: ``end`` keeps the level a thread ended at, once, and only for a thread with a
    standing claim; a lowering recorded later keeps the key, a raise removes it."""
    import json
    p = tmp_path / "l.json"
    with Ledger(p) as led:
        led.record_root(adv_for(cand(), "high"), "e1", {"feed": "e1"}, scope="Claude Code", exploited=False, now=T0)
        with pytest.raises(LedgerError):
            led.end("e1", "high")  # no standing claim: nothing renews it, nothing ends it
        led.set_claim("e1", "one", ["CVE-2026-0001"])
        with pytest.raises(LedgerError):
            led.end("e1", "none")
        assert led.thread("e1").ended is None
        assert led.end("e1", "high").ended == "high" and led.end("e1", "notice").ended == "high"
        led.record_reply("e1", adv_for(cand(), "notice"), {"feed": "r1"}, now=T0 + DAY)
        assert led.thread("e1").ended == "high"
        led.record_reply("e1", adv_for(cand(), "critical"), {"feed": "r2"}, now=T0 + 2 * DAY)
        assert led.thread("e1").ended is None
        led.end("e1", "critical")
    data = json.loads(p.read_text())
    assert data["entries"][0]["ended"] == "critical"
    data["entries"][0]["ended"] = "none"
    p.write_text(json.dumps(data))
    with pytest.raises(LedgerError):
        Ledger(p).__enter__()


def test_leaving_the_withdrawn_state_makes_an_ended_thread_an_ordinary_one(tmp_path):
    """65xv with kk2q: the withdrawal reply is a lowering and keeps ``ended``; the reply
    that ends the withdrawal, at the same level, is news: ``ended`` goes and the 90 days
    count from it."""
    p = tmp_path / "l.json"
    with Ledger(p) as led:
        led.record_root(adv_for(cand(), "high"), "e1", {"feed": "e1"}, scope="Claude Code", exploited=False, now=T0)
        led.set_claim("e1", "one", ["CVE-2026-0001"])
        led.end("e1", "high")
        e = led.record_reply("e1", adv_for(cand(), "high"), {"feed": "r1"}, now=T0 + DAY, withdrawn=True)
        assert e.ended == "high" and e.withdrawn == ["feed"]
        e = led.record_reply("e1", adv_for(cand(), "high"), {"feed": "r2"}, now=T0 + 2 * DAY, withdrawn=False)
        assert e.ended is None and e.withdrawn is None and e.changed[-1] == T0 + 2 * DAY
