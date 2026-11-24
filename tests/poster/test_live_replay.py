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
from test_main import FakeRelay, env  # noqa: F401  (env is a fixture)

FIXTURE = Path(__file__).parent.parent / "fixtures" / "poster" / "live-feed-2026-11-07-to-11.json"
EVENTS = json.loads(FIXTURE.read_text())["events"]
OPENSSH, CLAUDE_ID = "CVE-2026-123158", "CVE-2026-88968"
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


# wa6n: the live posts named products the scope file no longer has; the collector now
# names each by its package, as here.
V6_TEXT = {"MCP servers and clients": "pypi:mcp-server-git", "MCP Inspector": "mcp inspector",
           "MCP TypeScript SDK": "@modelcontextprotocol/sdk", "MCP Python SDK": "pip:mcp"}


def _candidate(adv, exploited):
    p = adv.products[0]
    return Candidate(id=adv.id, aliases=tuple(adv.aliases), product_text=V6_TEXT.get(p.name, p.name),
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
    return [Candidate(id=lid, aliases=(), product_text=V6_TEXT.get(name, name), advisory_severity=None,
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
            if c.id.split(":")[0] == CLAUDE_ID:
                env.pages.put(c.sources[0].url, advisory_page(
                    "GHSA-5xjx-9qx6-jcrv", cve="CVE-2026-88968", affected=None, patched=c.fixed,
                    title="TOCTOU Race in Edit Tool Allows File Writes Outside the Workspace"))
        code, summary, relay = env.run(now=t)
        assert code == 0, summary
        sent += [(t, *c) for c in relay.calls]

    roots = {text.splitlines()[0]: (t, ch) for t, ch, reply, text in sent if reply is None
             and not text.startswith("Daily digest")}
    # 0dvh: CVE-2026-88968's primary source is from 10-26, 12 days before first sight: no root.
    # wa6n: OpenSSH is out of the community service, so its KEV entry starts no thread either.
    assert roots == {}
    replies = [(t, text) for t, ch, reply, text in sent if reply is not None]
    assert replies == []  # zero source-only replies, and no thread for the fix to reply to

    out = {re.match(r"Daily digest for (\S+):", text).group(1): text
           for t, ch, reply, text in sent if text.startswith("Daily digest")}
    assert set(out) == {f"2026-11-{d:02d}" for d in range(7, 12)}, sorted(out)
    for day in ("2026-11-10", "2026-11-11"):
        assert "LEAD-" not in out[day] and "unrated leads" not in out[day], out[day]
    # First seen at 11:20 Tokyo on 11-07, after that day's 09:20 digest, its fix read at
    # 13:20: the 11-08 digest lists it once, as a notice with its fix, and no later digest
    # lists it again (live: 11-10 and 11-11 did, for a source-only reply).
    assert [d for d, text in sorted(out.items()) if CLAUDE_ID in text] == ["2026-11-08"]
    notice = out["2026-11-08"].split("\nNotice (")[1]
    assert f"({CLAUDE_ID})" in notice and "fixed in 2.1.251" in notice


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


# 0dvh: the two batches of design section 5, copied verbatim from the live feed (no
# translations, no digests): 11-07 02:20Z and 04:20Z, and 11-18 10:20Z and 11:20Z.
BATCHES = json.loads((FIXTURE.parent / "live-feed-2026-11-07-and-18.json").read_text())["events"]


def _batch_steps(day):
    """[(time, candidates)]: at each live event time, one candidate per thread it touched,
    equal to the thread's state after that event, as the live poster saw it."""
    threads, steps = {}, {}
    for e in sorted(BATCHES, key=lambda e: (e["created_at"], e["id"])):
        if dt.datetime.fromtimestamp(e["created_at"], dt.timezone.utc).day != day:
            continue
        if not _is_reply(e):
            threads[e["id"]] = schema.parse_post(e["content"])
            root = e["id"]
            second = e["content"].split("\n")[1]  # the vendor's own title, when the post carried one
            if not second.startswith("Affected:"):
                TITLES[threads[root].id.split(":")[0]] = second
        else:
            root = next(t[1] for t in e["tags"] if t[0] == "e")
            threads[root] = compose.parse_reply(e["content"], threads[root])
            assert threads[root] is not None, e["id"]
        run = e["created_at"] // 600 * 600 + 600  # the hourly run that sent it, a few seconds in
        steps.setdefault(run, {})[root] = _candidate(threads[root], False)
    return [(t, list(c.values())) for t, c in sorted(steps.items())]


TITLES = {}  # base id: the vendor page's title, as the live root quoted it (9kgk: the title states the consequence)

# The package each product's repository advisory page names (dmmf): (name, ecosystem),
# ecosystem None for GitHub's "Software" label.
PACKAGES = {"Claude Code": ("@anthropic-ai/claude-code", "npm"),
            "mcp inspector": ("@modelcontextprotocol/inspector", "npm"),
            "@modelcontextprotocol/sdk": ("@modelcontextprotocol/sdk", "npm"),
            "pip:mcp": ("mcp", "pip"),
            "pypi:mcp-server-git": ("mcp-server-git", "pip")}
_REPO_PAGE = re.compile(r"https://github\.com/([^/]+/[^/]+)/security/advisories/(GHSA(?:-[0-9a-z]{4}){3})")


def _pages(env, cands):
    """h340, dmmf: the vendor's page is the source. At each step every candidate's
    repository advisory page states what the live thread then said: its fix (or none
    yet) and its range. A live id whose slug h340's BOT_ID refuses (a slash) is cut to
    its base id; the replay is about the hold and the age limit, not the key's form."""
    out = []
    for c in cands:
        if not main.candidates.BOT_ID.fullmatch(c.id):
            c = main.replace(c, id=c.id.split(":")[0])
        for s in c.sources:
            if (m := _REPO_PAGE.fullmatch(s.url)) and c.product_text in PACKAGES:
                name, eco = PACKAGES[c.product_text]
                base = c.id.split(":")[0]
                env.pages.put(s.url, advisory_page(
                    m.group(2), package=name, ecosystem=eco, affected=c.affected, patched=c.fixed,
                    cve=base if base.startswith("CVE-") else None, repo=m.group(1),
                    title=TITLES.get(base, "A flaw")))
        out.append(c)
    return out


def _replay(env, monkeypatch, steps):  # noqa: F811
    feeding, sent, summaries = [], [], []
    monkeypatch.setattr(main, "gather", lambda *a, **k: (
        feeding.pop(0) if feeding else [], {}, {"kev": "ok", "collector": "ok", "heartbeat": "off"}))
    for t, cands in steps:
        feeding[:] = [_pages(env, cands)]
        code, summary, ssh = env.run(now=t)
        assert code == 0, summary
        summaries.append(summary)
        sent += [(t, *c) for c in ssh.calls if not c[2].startswith("Daily digest")]
    return sent, summaries


def test_replay_11_07_posts_no_old_root(env, monkeypatch, capsys):  # noqa: F811
    """17 roots whose primary sources were 12 to 226 days old, fixes two hours later."""
    steps = _batch_steps(7)
    assert len(steps) == 2 and len({c.id for _, cs in steps for c in cs}) == 17
    sent, summaries = _replay(env, monkeypatch, steps)
    assert sent == []  # no real-time root, so no reply either
    # h340: OpenClaw's root cited only github.com/advisories/, authoritative for nobody's
    # product: it is dropped before any level, so it is neither aged nor posted.
    vendor = [[c for c in cs if c.product_text != "OpenClaw"] for _, cs in steps]
    assert [sum(c.product_text == "OpenClaw" for c in cs) for _, cs in steps] == [0, 1]
    # wa6n: the SDK and Inspector items are catalog notices. 9kgk: the Claude Code ones are
    # notices too (their pages state the word "High" and no consequence), so none ages from a high.
    channel = [[c for c in cs if main.rules.scope_of(c.product_text).scope_class == "channel"] for cs in vendor]
    assert [len(c) for c in channel] == [3, 3]
    assert [int(re.search(r" aged=(\d+)", s).group(1)) for s in summaries] == [0, 0]
    assert "skipped: no authoritative source=1" in capsys.readouterr().err
    st = env.state()  # each is a notice for the digest: listed by 11-07's (sent 11:30 Tokyo) or still held
    noticed = {k.split("|", 1)[1] for k in st["digested"]} | {h["adv"]["id"].casefold() for h in st["held"]}
    held_ids = {c.id.casefold() for cs in vendor for c in _pages(env, cs)}
    assert len(held_ids) == 16 and held_ids <= noticed and not any("32846" in i for i in noticed)


def test_replay_11_18_posts_each_once_with_its_fix(env, monkeypatch):  # noqa: F811
    """Three roots at 10:20Z with no fix, the fix at 11:20Z with two more: five roots, each
    once, each with its fix, no reply, no "check the vendor"."""
    sent, summaries = _replay(env, monkeypatch, _batch_steps(18))
    # 9kgk: with no fix yet they are notices (a consequence counts with its fix), held, not waiting
    assert "held=3" in summaries[0] and "roots=0" in summaries[0]
    assert len(sent) == 5 and all(reply is None for _, _, reply, _ in sent)
    want = {"GHSA-87qg-cmw8-jc5m", "GHSA-9vjp-x34c-xg6v", "GHSA-h2g3-rwxm-xfm3", "GHSA-8wv7-r664-7594",
            "GHSA-pm7p-vphh-2cg7"}
    heads = {}
    for t, ch, reply, text in sent:
        assert t == sent[0][0] and "Fixed in 2026.11.18." in text and "vendor" not in text, text
        adv = schema.parse_post(text)  # what a v0.1.4 reader parses: the block's keys are unchanged
        assert adv is not None and adv.products[0].fixed == "2026.11.18" and adv.id.endswith(":mcp-server")
        heads[text.splitlines()[0]] = adv.id
    assert {re.search(r"\((GHSA-[^)]+)\)$", h).group(1) for h in heads} == want  # public ids only
    assert all(":mcp-server" not in h for h in heads)
    assert env.state()["deferred"] == []  # nothing waits; first sight stays for AGE_LIMIT
