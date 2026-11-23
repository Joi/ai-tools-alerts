"""Replay of the live feed from 2026-11-07 to 11-11 under the current poster (8ke5).

The fixture holds ten events copied verbatim from the live feed: the CVE-2026-88968
thread (a high, its fix two hours later, then a source-only reply), the OpenSSH
CVE-2026-123158 thread (a critical and four replies that only added sources or a
ledger key as an alias) and the 11-10 and 11-11 digests, whose lead lines give the
lead candidates. At each live event's time the poster runs once with a candidate
equal to the thread's state after that event, so it sees what the live poster saw.
"""

import datetime as dt
import json
import re
from pathlib import Path

import pytest

from aitools_alerts import schema
from aitools_alerts.poster import compose, main
from aitools_alerts.poster.candidates import Candidate

from pages import advisory_page
from test_main import FakeSSH, env  # noqa: F401  (env is a fixture)

FIXTURE = Path(__file__).parent.parent / "fixtures" / "poster" / "live-feed-2026-11-07-to-11.json"
EVENTS = json.loads(FIXTURE.read_text())["events"]
OPENSSH, CLAUDE = "CVE-2026-123158", "CVE-2026-88968:claude-code"
TOKYO = dt.timezone(dt.timedelta(hours=9))


def _is_reply(e):
    return any(t[0] == "e" for t in e["tags"])


def _threads():
    """{root event id: [(created_at, Advisory after that event)]} for the two threads."""
    out = {}
    for e in EVENTS:
        if e["content"].startswith("Daily digest"):
            continue
        if not _is_reply(e):
            out[e["id"]] = [(e["created_at"], schema.parse_post(e["content"]))]
        else:
            root = next(t[1] for t in e["tags"] if t[0] == "e")
            prev = out[root][-1][1]
            merged = compose.parse_reply(e["content"], prev)
            assert merged is not None, e["id"]
            out[root].append((e["created_at"], merged))
    return out


def _candidate(adv, exploited):
    p = adv.products[0]
    return Candidate(id=adv.id, aliases=tuple(adv.aliases), product_text=p.name,
                     advisory_severity="high", local_level_hint=None, exploited=exploited,
                     trojanized=False, injection_exec=False, fixed=p.fixed, affected=p.affected,
                     sources=tuple(adv.sources), observed_at=None)


_SINGLE = re.compile(r"- (.+?): security advisory \((LEAD-[^)]+)\); .*? (https://\S+)$")
_GROUP = re.compile(r"- (.+?): (\d+) unrated leads\.$")


def _leads(digest_text):
    """Lead candidates read off a live digest's lead lines."""
    out = []
    for line in digest_text.splitlines():
        if m := _SINGLE.match(line):
            name, lid, url = m.groups()
            out.append((name, lid, url))
        elif m := _GROUP.match(line):
            name, n = m.group(1), int(m.group(2))
            slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
            out += [(name, f"LEAD-replay{i:02d}:{slug}", f"https://mastodon.social/@EUVD_Bot/{9000 + i}")
                    for i in range(n)]
    return [Candidate(id=lid, aliases=(), product_text=name, advisory_severity=None,
                      local_level_hint=None, exploited=False, trojanized=False, injection_exec=False,
                      fixed=None, affected=None, sources=(schema.Source(url, None),), observed_at=None)
            for name, lid, url in out]


def test_live_feed_replay(env, monkeypatch):  # noqa: F811
    threads = _threads()
    digests = [e for e in EVENTS if e["content"].startswith("Daily digest")]
    assert len(threads) == 2 and len(digests) == 2
    steps = []  # (time, candidates)
    for root, states in threads.items():
        exploited = states[0][1].id == OPENSSH
        steps += [(t, [_candidate(adv, exploited)]) for t, adv in states]
    for d in digests:  # the leads were held before the digest that listed them
        steps.append((d["created_at"] - 1800, _leads(d["content"])))
    for day in range(7, 12):  # the hourly schedule: a run at 09:20 Tokyo sends that day's digest
        steps.append((int(dt.datetime(2026, 11, day, 9, 20, tzinfo=TOKYO).timestamp()), []))
    steps.sort(key=lambda s: s[0])

    feeding = []
    monkeypatch.setattr(main, "gather", lambda *a, **k: (
        feeding.pop(0) if feeding else [], {}, {"kev": "ok", "collector": "ok", "heartbeat": "off"}))
    sent = []  # (time, channel, reply-to, text)
    for t, cands in steps:
        feeding[:] = [cands]
        for c in cands:  # h340: the vendor's page states what the live thread then said
            if c.id == CLAUDE:
                env.pages.put(c.sources[0].url, advisory_page(
                    "GHSA-5xjx-9qx6-jcrv", cve="CVE-2026-88968", affected=None, patched=c.fixed,
                    title="TOCTOU Race in Edit Tool Allows File Writes Outside the Workspace"))
        code, summary, ssh = env.run(now=t)
        assert code == 0, summary
        sent += [(t, *c) for c in ssh.calls]

    roots = {text.splitlines()[0]: (t, ch) for t, ch, reply, text in sent if reply is None
             and not text.startswith("Daily digest")}
    assert any(OPENSSH in head for head in roots) and any(CLAUDE in head for head in roots)
    replies = [(t, text) for t, ch, reply, text in sent if reply is not None]
    assert not [r for r in replies if OPENSSH in r[1] or "123158" in r[1]]  # zero source-only replies
    assert [text.splitlines()[0] for _, text in replies if "2.1.251" in text] == [
        "Action: upgrade Claude Code to 2.1.251 or later."]  # the fix still posts, once
    assert not [r for r in replies if "New sources listed." in r[1] or "Also known as" in r[1]]

    out = {re.match(r"Daily digest for (\S+):", text).group(1): text
           for t, ch, reply, text in sent if text.startswith("Daily digest")}
    assert set(out) == {f"2026-11-{d:02d}" for d in range(7, 12)}, sorted(out)
    for day in ("2026-11-10", "2026-11-11"):
        assert "LEAD-" not in out[day] and "unrated leads" not in out[day], out[day]
    # It posted at 11:20 Tokyo on 11-07, after that day's 09:20 digest, and its fix came at
    # 13:20: the 11-08 digest lists both, and no later digest lists it again (live: 11-10
    # and 11-11 did, for a source-only reply).
    assert [d for d, text in sorted(out.items()) if CLAUDE in text] == ["2026-11-08"]
    assert "fixed in 2.1.251" in out["2026-11-08"]


def test_live_digests_leads_are_never_composed():
    """The live 11-10 and 11-11 digests listed leads. A lead has no CVE or GHSA id, so the
    poster composes no post for one (h340), and its run drops it before any hold."""
    for d in (e for e in EVENTS if e["content"].startswith("Daily digest")):
        leads = _leads(d["content"])
        assert leads
        for c in leads:
            scope = main.rules.scope_of(c.product_text)
            assert scope is not None, c.product_text
            with pytest.raises(ValueError, match="not a CVE or GHSA id"):
                compose.root_post(c, ("notice", "notice"), scope, posted_at=d["created_at"])
            assert not main.rules.evidence(c, scope, lambda url, allow: (200, "")).ok
