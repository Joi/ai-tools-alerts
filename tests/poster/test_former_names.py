"""A thread under a product's former name (scope ``formerly``, wa6n) is recomputed by
the poster and confirmed by a member's check, by one rule (ai-tools-alerts#aabw): the
name stands for every scope product that lists it (``Ruleset.stands_for``), and the
thread's own advisory says which of them it is about. ``main.run`` one run an hour with
the fake relay, KEV fetch and advisory API; then the member's ``verify.run`` against the
same answers."""

import pytest

from aitools_alerts import ruleset, schema, verify, wire
from aitools_alerts.poster import main, recompute, rules, sources
from aitools_alerts.poster.ledger import Ledger

from advisories import ghsa_json
from test_main import T0, env, finding  # noqa: F401  (env is a fixture)
from test_recompute import _kev_with_its_fix, levels  # noqa: F401  (an autouse fixture)
from test_recompute_names import WHEN, entries, run, sent, state
from test_renew import DAY, day, renewals, steps
from test_withdrawn_state import claims, moved, moves

SERVERS, INSPECTOR = "MCP servers and clients", "MCP Inspector"
G = "GHSA-abcd-efgh-ijkl"
GIT = dict(packages=[("pip", "mcp-server-git", "< 1.0", "1.0")], repo="modelcontextprotocol/servers")
FETCH = dict(packages=[("pip", "mcp-server-fetch", "< 1.0", "1.0")], repo="modelcontextprotocol/servers")
INSP = dict(packages=[("npm", "@modelcontextprotocol/inspector", "< 1.0.3", "1.0.3")], repo="modelcontextprotocol/inspector")
# name -> (the product text of a collector finding, its vendor's repository, the API's answer for its advisory)
CASES = {SERVERS: ("pip:mcp-server-git", "modelcontextprotocol/servers", GIT),
         INSPECTOR: ("npm:@modelcontextprotocol/inspector", "modelcontextprotocol/inspector", INSP)}


def thread(env, name, level="high", floor="notice"):
    """A thread in the ledger under former name ``name``, as a run before the rename
    posted it from its vendor's advisory, with the floor that run recorded."""
    product, repo, _ = CASES[name]
    scope = rules.scope_named(name, former=True)
    f = finding(fid=G, product=product, severity="high", fixed="1.0",
                sources=(f"https://github.com/{repo}/security/advisories/{G}",))
    c = main.inputs.candidate_from(main.candidates.from_collector({"schema_version": 1, "findings": [f]})[0].to_dict())
    adv = main.compose.root_post(c, (level, None), scope, posted_at=T0 - 600)[1]
    with Ledger(env.config.ledger) as led:
        led.record_root(adv, "ef" * 32, {"feed": "ef" * 32}, scope=name, exploited=False, now=T0 - 600, floor=floor)


def member(env, name, now=T0):
    """The member's own check of the thread as the ledger now publishes it, against the
    same API answers: (result, why, the level its sources give). ``now``: the member's
    clock; a result that is not a confirmation is read again a day later."""
    (e,) = entries(env)
    adv = schema.validate(e["advisory"])
    assert [(p.name, p.ecosystem) for p in adv.products] == [(name, "mcp")]

    def fetch(url, etag, limit, timeout):
        return (404, None, b"") if url == verify.KEV_URL else env.api(url, etag, limit, timeout)
    (r,) = verify.result_for(adv, verify.run([adv], [adv], env.config.ledger.parent, fetch=fetch, now=now)).values()
    return r["result"], r["why"], r["source"]


def confirms_withdrawal(env, name):
    """What a member's check says about the relay bot's withdrawal of the thread
    (``verify.lowering`` at ``withdrawn``), for a thread whose high carried the claim of
    its advisory's fields, against the same API answers: True, False or None."""
    (e,) = entries(env)
    adv = schema.validate(e["advisory"])
    fields = verify._ghsa_reading(ghsa_json(G, **CASES[name][2]), G)[0]
    stated = (("high", ruleset.load().claim("ghsa", fields, name, T0 - 600, T0 - 600)),)
    ask = verify.at_level(adv, wire.WITHDRAWN, verify.claimed(adv, wire.WITHDRAWN, stated))

    def fetch(url, etag, limit, timeout):
        return (404, None, b"") if url == verify.KEV_URL else env.api(url, etag, limit, timeout)
    cache = verify.run([adv, ask], [ask], env.config.ledger.parent, fetch=fetch, now=T0, recheck=[ask])
    return verify.lowering(adv, wire.WITHDRAWN, cache, T0, stated=stated)


@pytest.mark.parametrize("name", [INSPECTOR, SERVERS])
def test_a_former_name_thread_whose_advisory_is_withdrawn_is_withdrawn_and_a_member_confirms_it(env, name):
    """Acceptance: under ny5g's rules, so after 24 hours of complete reads and not
    before, once. Since kk2q what a withdrawn advisory brings is the state ``withdrawn``,
    below notice, with the claim of the withdrawn reading; the member's check of the
    same response confirms it, and the thread returns when the advisory does."""
    thread(env, name)
    live = ghsa_json(G, **CASES[name][2])
    env.api.put(G, live)
    assert confirms_withdrawal(env, name) is False  # while the source supports it, a withdrawal is refused
    env.api.put(G, ghsa_json(G, withdrawn_at=WHEN, **CASES[name][2]))
    assert moved(env, 1, 24) == []
    (e,) = entries(env)
    assert state(env)["dwell"][e["root_event_id"]]["level"] == wire.WITHDRAWN and e["level"] == "high"
    assert member(env, name) == ("contradicted", "unsupported", "none")  # the member reads the same before the bot moves
    relay = run(env, 25)
    assert moves(relay) == ["withdrawn"]
    (claim,) = claims(relay)
    assert claim["level"] == ruleset.NONE and ruleset.check_claim(claim, name) == "ok"
    (e,) = entries(env)
    assert (e["scope"], e["level"], e["withdrawn"], e["lowered"]) == (name, "high", ["feed"], True)
    assert confirms_withdrawal(env, name) is True
    assert moved(env, 26, 40) == [] and state(env)["dwell"] == {}
    env.api.put(G, live)  # published again: back at its level, in the run that reads it
    assert moves(run(env, 41)) == ["high"] and "withdrawn" not in entries(env)[0]
    assert member(env, name, T0 + 2 * DAY) == ("confirmed", "match", "high")


@pytest.mark.parametrize("name", [INSPECTOR, SERVERS])
def test_a_former_name_thread_its_advisory_supports_stands_and_a_member_confirms_it(env, name):
    thread(env, name)
    env.api.put(G, ghsa_json(G, **CASES[name][2]))
    assert sent(env, 1, 30) == [] and state(env)["dwell"] == {}
    assert env.api.calls, "the thread is read"
    assert entries(env)[0]["level"] == "high" and member(env, name) == ("confirmed", "match", "high")


def test_a_shared_former_name_is_held_by_whichever_of_its_products_the_advisory_names(env):
    """The thread was posted about mcp-server-git; its advisory now names mcp-server-fetch,
    another of the seven. That is support for the thread's name, on both sides."""
    thread(env, SERVERS)
    env.api.put(G, ghsa_json(G, **FETCH))
    assert sent(env, 1, 30) == [] and state(env)["dwell"] == {}
    assert member(env, SERVERS) == ("confirmed", "match", "high")


@pytest.mark.parametrize("withdrawn", [None, WHEN])
def test_a_former_name_thread_whose_advisory_names_none_of_its_products_is_unknown_and_stands(env, withdrawn):
    """The name was a wider entry once: "MCP servers and clients" matched any MCP server,
    so a thread under it may be about one that is none of the seven. Its advisory then
    never names them, and that silence is not absence: nothing is lowered, no wait
    starts, and a member's check answers unknown, never "the source does not support
    it". Not even when that advisory is withdrawn: it withdraws another product."""
    thread(env, SERVERS)
    env.api.put(G, ghsa_json(G, withdrawn_at=withdrawn, packages=[("npm", "mcp-remote", "< 1", "1")], repo="geelen/mcp-remote"))
    assert sent(env, 1, 40) == [] and state(env)["dwell"] == {} and env.api.calls
    assert entries(env)[0]["level"] == "high"
    assert member(env, SERVERS) == ("unknown", "unauthoritative", "none")


@pytest.mark.parametrize("name", [INSPECTOR, SERVERS])
def test_a_former_name_thread_is_raised_when_its_advisory_supports_more(env, name):
    """Acceptance: with no candidate, in the run that reads it, and the member's check
    confirms the level raised to."""
    thread(env, name, level="notice")
    env.api.put(G, ghsa_json(G, **CASES[name][2]))
    code, summary, relay = env.run(now=T0 + 3600)
    assert code == 0 and "candidates=0" in summary, summary
    assert levels(relay) == [{"level": "high"}]
    assert entries(env)[0]["level"] == "high" and member(env, name) == ("confirmed", "match", "high")
    assert sent(env, 2, 6) == []  # raised once


def test_a_thread_under_a_name_the_scope_file_never_had_is_still_not_judged(env):
    thread(env, SERVERS)
    path = env.config.ledger  # the stored name, and the product the post names, become one no entry lists
    path.write_text(path.read_text().replace(SERVERS, "MCP things"))
    assert [x["scope"] for x in entries(env)] == ["MCP things"]
    env.api.put(G, ghsa_json(G, withdrawn_at=WHEN, **GIT))
    assert sent(env, 1, 30) == [] and state(env)["dwell"] == {} and env.api.calls == []
    assert member(env, "MCP things") == ("unknown", "no-source", None)


def enrolled(env, name):
    """The thread, with the claim its root would carry since gtw9: of its advisory's
    fields, for the name it was posted under, confirmed when it was posted."""
    thread(env, name)
    fields = verify._ghsa_reading(ghsa_json(G, **CASES[name][2]), G)[0]
    claim = ruleset.load().claim("ghsa", fields, name, T0 - 600, T0 - 600)
    assert claim["level"] == "high"
    with Ledger(env.config.ledger) as led:
        (e,) = led.entries()
        led.set_claim(e.root_event_id, wire.claim_tag(claim)[1], root_ids=[G])
    return claim


@pytest.mark.parametrize("name", [INSPECTOR, SERVERS])
def test_an_enrolled_former_name_thread_is_renewed_by_its_advisory_and_never_steps_down(env, name):
    """gtw9 steps down a level nothing confirms for 45 days, and a thread that is not
    judged is never confirmed. Judged, its advisory confirms it: every renewal carries a
    new confirmation, and a reader keeps the level."""
    root = enrolled(env, name)
    env.api.put(G, ghsa_json(G, **CASES[name][2]))
    rs, seen, sent_on = ruleset.load(), [(root["confirmed_at"], root["checked_at"])], []
    for d in range(1, 91):
        relay = day(env, d)
        assert relay.code == 0 and not steps(relay), d
        for _, c in renewals(relay):
            assert c["confirmed_at"] == c["checked_at"] == T0 + d * DAY and c["level"] == "high"
            assert ruleset.check_claim(c, name) == "ok"
            seen.append((c["confirmed_at"], c["checked_at"]))
            sent_on.append(d)
        assert rs.level_at("high", seen, T0 + d * DAY) == "high"
    assert len(sent_on) >= 5 and entries(env)[0]["level"] == "high"


def test_an_enrolled_former_name_thread_no_read_confirms_keeps_its_confirmation_date_and_steps_down(env):
    """A failed read confirms nothing for a former name either: renewals say checked,
    never confirmed, and the level steps down at the ceiling as for any thread."""
    root = enrolled(env, SERVERS)
    env.api.default = lambda i: 503
    stepped = None
    for d in range(1, 46):
        relay = day(env, d)
        assert all(c["confirmed_at"] == root["confirmed_at"] for _, c in renewals(relay))
        if steps(relay) and stepped is None:
            stepped = d
    assert stepped is not None and stepped <= 45 and entries(env)[0]["level"] == "notice"


def test_a_response_counts_for_a_former_name_only_when_all_its_support_for_the_names_products_may_lower(env):
    """``recompute.support`` on a built read. No shipped entry gives two products of one
    former name different authority, so no run builds this; the rule is the member's
    (``verify.judge``), and the poster is the stricter side: it does not count such a
    response at all."""
    thread(env, SERVERS)
    with Ledger(env.config.ledger) as led:
        (e,) = led.entries()
    rs, scope = ruleset.load(), rules.scope_named(SERVERS, former=True)
    fields = verify._ghsa_reading(ghsa_json(G, **GIT), G)[0]

    def got(support):
        counted: list = []
        read = sources.Read(source="ghsa", fields=fields, support=support, lowers=True, names=())
        found, known, *_ = recompute.support(e, scope, None, rs, lambda i: read, counted)
        return found, known, len(counted)
    assert got({"mcp-server-git": ["notice", True, False], "mcp-server-fetch": ["high", True, False]}) == ("high", True, 1)
    assert got({"mcp-server-git": ["high", False, False], "mcp-server-fetch": ["notice", True, False]}) == ("none", False, 0)
    assert got({"Claude Code": ["critical", True, False]}) == ("none", False, 1)  # names none of them: not known


Z = "GHSA-zzzz-zzzz-zzzz"


def _member(env, product, repo, packages, fixed="1.0"):
    """A later advisory with the thread's fix (btqg), its vendor's page and API answer."""
    env.api.put(Z, ghsa_json(Z, packages=packages, repo=repo))
    env.collector([finding(fid=Z, product=product, severity="high", fixed=fixed,
                           sources=(f"https://github.com/{repo}/security/advisories/{Z}",))])


def test_a_shared_former_name_thread_is_never_joined_by_fix(env):
    """btqg: seven servers had "MCP servers and clients"; a git thread fixed in 1.0 says
    nothing about a fetch advisory fixed in 1.0. The fetch advisory posts its own root."""
    thread(env, SERVERS)
    _member(env, "pip:mcp-server-fetch", "modelcontextprotocol/servers", FETCH["packages"])
    code, summary, relay = env.run(now=T0)
    assert code == 0 and "roots=1" in summary, summary
    assert len(entries(env)) == 2 and not any(e.get("joined") for e in entries(env))


def test_a_former_name_only_one_product_had_is_joined_by_fix(env):
    thread(env, INSPECTOR)
    _member(env, "npm:@modelcontextprotocol/inspector", "modelcontextprotocol/inspector",
            [("npm", "@modelcontextprotocol/inspector", "< 1.0", "1.0")])
    code, summary, relay = env.run(now=T0)
    assert code == 0 and "roots=0" in summary, summary
    (e,) = entries(env)
    assert e["scope"] == INSPECTOR and e["joined"] == [[Z.casefold()]] and Z in e["aliases"]
