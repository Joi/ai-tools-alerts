"""The recompute finds a thread's product by its name (ai-tools-alerts#zmg2). A ledger
entry keeps the name its post states; ``rules.scope_of`` resolves identities, and for
Codex, Cursor, Hermes, git, Python, Go, Rust and mcp the name is not one, so their
threads were never judged. The lookup's unit tests, then ``main.run`` one run an hour
with the fake relay, KEV fetch and advisory API."""

import pytest

from aitools_alerts import schema
from aitools_alerts.poster import catalog as catalog_lane
from aitools_alerts.poster import main, recompute, rules
from aitools_alerts.poster.ledger import Ledger

from advisories import ghsa_json
from test_main import APPLE, FakeKEV, INSPECTOR, T0, env, finding  # noqa: F401  (env is a fixture)
from test_recompute import _kev_with_its_fix, catalog, hours, levels, post  # noqa: F401  (an autouse fixture)

HOUR = 3600
G, CVE = "GHSA-abcd-efgh-ijkl", "CVE-2026-0001"
NOT_IDENTITIES = ("Codex", "Cursor", "Hermes", "git", "Python", "Go", "mcp", "Rust")  # the issue's list, and Rust
CURSOR_KEV = {"cveID": CVE, "vendorProject": "Anysphere", "product": "Cursor", "dateAdded": "2026-11-04"}
HERMES = dict(packages=[("pip", "hermes-agent", "< 1.0", "1.0")], repo="NousResearch/hermes-agent")
WHEN = "2026-11-06T00:00:00Z"


def run(env, hour, **kw):
    code, summary, relay = env.run(now=T0 + hour * HOUR, **kw)
    assert code == 0, summary
    return relay


def sent(env, first, last, **kw):
    """Hourly runs from ``first`` to ``last`` inclusive: [(hour, level)] sent in feed."""
    return [(h, b["level"]) for h in range(first, last + 1) for b in levels(run(env, h, **kw))]


def entries(env):
    return env.ledger()[0]


def state(env):
    return recompute.load(env.config.recompute_state)[0]


# ---------------------------------------------------------------- the lookup


def test_every_scope_name_resolves_by_name():
    names = {s.name for s in rules._default_index().values()}
    assert set(NOT_IDENTITIES) <= names
    for name in names:
        assert rules.scope_named(name).name == name
        same = [s for s in rules._default_index().values() if s.name == name]
        assert all(s == same[0] for s in same), name  # which of them is found makes no difference
    for name in NOT_IDENTITIES:  # the bug's precondition: were one an identity, this says which
        assert rules.scope_of(name) is None, name
    assert rules.scope_named("containerd").name == "containerd"  # a component, resolved


@pytest.mark.parametrize("text", ["cursor ide", "cursor", "CURSOR", " Cursor", "No Such Product", "", None, 7])
def test_a_text_that_is_not_a_name_resolves_nothing(text):
    assert rules.scope_named(text) is None and rules.scope_named(text, former=True) is None


def test_a_former_name_resolves_only_when_asked():
    assert rules.scope_named("MCP Inspector") is None
    old = rules.scope_named("MCP Inspector", former=True)
    now = rules.scope_named("@modelcontextprotocol/inspector")
    assert (old.name, old.formerly, old.scope_class, old.authority) == ("MCP Inspector", (), now.scope_class, now.authority)
    for name in ("Cursor", "MCP Inspector", "MCP servers and clients", "No Such Product", None):
        assert catalog_lane._scope(name) == rules.scope_named(name, former=True)


# ---------------------------------------------------------------- through main.run


def posted(env, fid, product, scope, fixed, source, level="high"):
    """A thread already in the ledger under ``scope``, as an earlier run posted it from
    a collector finding (the way test_main builds its former-name thread)."""
    f = finding(fid=fid, product=product, severity="high", fixed=fixed, sources=(source,))
    c = main.inputs.candidate_from(main.candidates.from_collector({"schema_version": 1, "findings": [f]})[0].to_dict())
    thread = main.compose.root_post(c, (level, None), scope, posted_at=T0 - 600)[1]
    with Ledger(env.config.ledger) as led:
        led.record_root(thread, "ef" * 32, {"feed": "ef" * 32}, scope=scope.name, exploited=False, now=T0 - 600)


def test_a_cursor_thread_is_raised_when_kev_lists_its_cve_with_no_candidate(env):
    """Acceptance: the thread's advisory comes to support more (it names a CVE, and KEV
    lists that CVE for Cursor, dated before the watermark so no candidate brings it);
    the recompute raises the thread in that run, from no input record."""
    posted(env, G, "Cursor IDE", rules.scope_named("Cursor"), "1.7.4", APPLE)
    env.api.put(G, ghsa_json(G, cve=CVE, cwes=(), packages=[("npm", "left-pad", "< 1", "1")]))
    assert sent(env, 0, 3, kev=FakeKEV(catalog=catalog("v1"))) == []
    (e,) = entries(env)
    assert (e["scope"], e["level"], e["exploited"]) == ("Cursor", "high", False)
    old = {**CURSOR_KEV, "dateAdded": "2026-09-01"}
    code, summary, relay = env.run(now=T0 + 4 * HOUR, kev=FakeKEV(catalog=catalog("v2", old)))
    assert code == 0 and "candidates=0" in summary, summary
    assert levels(relay) == [{"level": "critical"}]
    (e,) = entries(env)
    assert (e["level"], e["exploited"]) == ("critical", True)
    assert sent(env, 5, 8, kev=FakeKEV(catalog=catalog("v2", old))) == []  # raised once


def test_a_cursor_thread_kev_stops_listing_is_lowered_by_the_rules(env):
    """Acceptance: the support falls, and the thread falls under ny5g's rules, on the
    hour a Claude Code thread does (test_an_entry_gone_for_a_day_of_complete_reads_lowers_once)."""
    post(env, CURSOR_KEV)
    (e,) = entries(env)
    assert (e["scope"], e["level"], e["floor"]) == ("Cursor", "critical", "notice")
    assert hours(env, 1, 24) == []
    root = e["root_event_id"]
    assert state(env)["dwell"][root]["level"] == "notice"  # the wait is running: the thread is judged
    assert hours(env, 25, 25) == [(25, "notice")]
    (e,) = entries(env)
    assert e["level"] == "notice" and e["lowered"] is True
    assert hours(env, 26, 40) == [] and state(env)["dwell"] == {}


def test_a_hermes_thread_falls_when_its_advisory_stops_supporting_high(env):
    env.api.put(G, ghsa_json(G, **HERMES))
    env.collector([finding(fid=G, product="hermes-agent", severity="moderate", fixed="1.0",
                           sources=("https://github.com/NousResearch/hermes-agent/security/advisories/" + G,))])
    run(env, 0)
    (e,) = entries(env)
    assert (e["scope"], e["level"], e["floor"]) == ("Hermes", "high", "notice")
    env.api.put(G, ghsa_json(G, cwes=(), **HERMES))
    assert sent(env, 1, 24) == []
    assert sent(env, 25, 25) == [(25, "notice")]
    assert entries(env)[0]["level"] == "notice" and sent(env, 26, 40) == []


def test_a_thread_whose_product_left_the_scope_file_is_not_judged(env, monkeypatch):
    """Acceptance. The poster's scope index loses Hermes; the thread stands, unread."""
    env.api.put(G, ghsa_json(G, **HERMES))
    env.collector([finding(fid=G, product="hermes-agent", severity="moderate", fixed="1.0",
                           sources=("https://github.com/NousResearch/hermes-agent/security/advisories/" + G,))])
    run(env, 0)
    assert entries(env)[0]["scope"] == "Hermes"
    index = {k: v for k, v in rules._default_index().items() if v.name != "Hermes"}
    monkeypatch.setattr(rules, "_default_index", lambda: index)
    assert rules.scope_named("Hermes") is None
    env.api.put(G, ghsa_json(G, withdrawn_at=WHEN, **HERMES))
    asked = len(env.api.calls)
    assert sent(env, 1, 30) == [] and state(env)["dwell"] == {}
    assert entries(env)[0]["level"] == "high" and len(env.api.calls) == asked  # not read at all
    env.api.put(G, ghsa_json(G, type="malware", **HERMES))  # nor raised
    assert sent(env, 31, 33) == [] and len(env.api.calls) == asked


def test_a_thread_under_a_former_name_is_not_judged(env):
    """Decided in zmg2: no member's check can confirm a level for a former name
    (``verify.judge``: no-source), and the name stands for more than one product."""
    old = schema.ScopeEntry("MCP Inspector", "mcp", "channel", ["mcp inspector"],
                            authority=("github.com/modelcontextprotocol/inspector/",))
    fid = "GHSA-4fc4-wcmh-4g86"
    posted(env, fid, "npm:@modelcontextprotocol/inspector", old, "1.0.3", INSPECTOR)
    inspector = dict(packages=[("npm", "@modelcontextprotocol/inspector", "< 1.0.3", "1.0.3")],
                     repo="modelcontextprotocol/inspector")
    env.api.put(fid, ghsa_json(fid, withdrawn_at=WHEN, **inspector))  # would lower it
    assert sent(env, 0, 30) == [] and state(env)["dwell"] == {} and env.api.calls == []
    env.api.put(fid, ghsa_json(fid, type="malware", **inspector))  # would raise it
    assert sent(env, 31, 33) == [] and env.api.calls == []
    assert [(e["scope"], e["level"]) for e in entries(env)] == [("MCP Inspector", "high")]
