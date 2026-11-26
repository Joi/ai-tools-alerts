"""The recompute judges threads by GitHub's and OSV's advisory responses
(ai-tools-alerts#3qyq): a failed read is unknown, a source that cannot lower lowers
nothing, an alias counts only when the source ties it, and ny5g's rules for a
lowering hold. Unit tests of ``recompute.support`` and ``judge``, then ``main.run``
one run an hour with the fake relay, KEV fetch and advisory API."""

import json

import pytest

from aitools_alerts import ruleset, schema, verify
from aitools_alerts.poster import inputs, recompute, sources
from aitools_alerts.poster.ledger import Entry

from advisories import Api, ghsa_json, osv_json, plain
from test_main import FakeKEV, T0, env, finding, kev_item  # noqa: F401  (env is a fixture)
from test_recompute import catalog, kc, levels

HOUR, DAY = 3600, 86400
G, G2, CVE, MAL = "GHSA-abcd-efgh-ijkl", "GHSA-mnop-qrst-uvwx", "CVE-2026-0001", "MAL-2026-1"
RS = ruleset.load()
CLAUDE = next(e for e in schema.load_scope() if e.name == "Claude Code")
WEAK = dict(cwes=())  # a reviewed advisory with no weakness the rules name: a notice
NO_FIX = [("npm", "@anthropic-ai/claude-code", "<= 9.9.9", None)]
WHEN = "2026-11-06T00:00:00Z"


def thread(ids=(G,), level="high", exploited=False, actions=(), **more):
    adv = {"id": ids[0], "aliases": list(ids[1:]), "level": level, "advisory_severity": None, "title": "t",
           "products": [{"name": "Claude Code", "ecosystem": "claude-code", "affected": None, "fixed": "2.1.0"}],
           "actions": list(actions), "sources": [{"url": "https://github.com/advisories/" + G, "published_at": None}],
           "posted_by": "relay-bot", "posted_at": 1, "expires_at": None}
    return Entry(root_event_id="a" * 64, channel_ids={"feed": "a" * 64}, level=level, aliases=list(ids),
                 posted_at=1, last_change=1, scope="Claude Code", exploited=exploited, advisory=adv, replies=[],
                 **{"root_fixed": "2.1.0", "floor": "notice", **more})


def reads(**answers):
    return sources.Reader(Api(**{k.replace("_", "-"): v for k, v in answers.items()})).read


def support(entry, read, cat=None):
    copy = kc(cat, "ok", recompute.new_state(), 0) if cat else None
    return recompute.support(entry, CLAUDE, copy, RS, read)


# ---------------------------------------------------------------- support


def test_an_unread_advisory_id_is_unknown():
    for extra in (G, MAL, "LEAD-162d5e0f15f7"):
        assert support(thread((CVE, extra)), None, catalog("v"))[1] is False
    assert support(thread(), lambda i: None) == (ruleset.NONE, False, set(), set(), False)
    assert support(thread(), reads(**{G: 404})) == (ruleset.NONE, False, set(), set(), False)
    assert recompute.judged(thread()) and recompute.judged(thread((CVE,), exploited=True))
    assert not recompute.judged(thread((CVE,)))  # no source a lowering could rest on


def test_a_first_ghsa_read_is_the_threads_level():
    assert support(thread(), reads(**{G: ghsa_json(G)})) == ("high", True, set(), set(), False)
    assert support(thread(), reads(**{G: ghsa_json(G, **WEAK)}))[:2] == ("notice", True)
    assert support(thread(), reads(**{G: ghsa_json(G, withdrawn_at=WHEN)}))[:2] == (ruleset.NONE, True)
    key = thread(("GHSA-ABCD-efgh-ijkl:claude-code",))  # a thread key: its slug dropped, its id as the API writes it
    assert support(key, reads(**{G: ghsa_json(G)}))[:2] == ("high", True)


def test_a_tied_reviewed_read_counts_and_an_untied_one_does_not():
    e, cat = thread((CVE, G)), catalog("v")
    assert support(e, reads(**{G: ghsa_json(G, cve=CVE)}), cat) == ("high", True, set(), {CVE}, False)
    assert support(e, reads(**{G: ghsa_json(G)}), cat)[:2] == (ruleset.NONE, False)  # it does not name the CVE
    assert support(e, reads(**{G: ghsa_json(G, cve="CVE-2026-0002")}), cat)[:2] == (ruleset.NONE, False)
    unreviewed = ghsa_json(G, cve=CVE, type="unreviewed", repo=None)  # no authority about which ids are one advisory
    assert support(e, reads(**{G: unreviewed}), cat)[:2] == (ruleset.NONE, False)
    assert support(e, reads(**{G: ghsa_json(G, cve=CVE)}), None)[:2] == ("high", False)  # a CVE needs the KEV copy


def test_a_first_ghsa_names_what_else_is_read():
    first = ghsa_json(G, cve=CVE, identifiers=[MAL], **WEAK)
    read = reads(**{G: first, MAL: osv_json(MAL)})
    assert support(thread(), read, catalog("v")) == ("high", True, set(), {CVE}, False)  # OSV's entry gives the high
    assert support(thread(), reads(**{G: first}), catalog("v"))[:2] == ("notice", False)  # the named entry unread
    assert support(thread(), read, catalog("v", CVE)) == ("critical", True, {CVE}, set(), False)  # the named CVE, in KEV
    assert support(thread(), read, None)[:2] == ("high", False)
    four = ghsa_json(G, identifiers=[f"MAL-2026-{n}" for n in range(4)], **WEAK)
    assert support(thread(), reads(**{G: four}))[1] is False  # more than a member reads


def test_an_id_a_member_never_reads_raises_nothing():
    """A member's check reads three ids beside the first. A fourth the response names,
    or a fourth advisory alias of a CVE thread, is not counted: its level could never
    be confirmed. Nor is an id the ledger holds and the thread never published."""
    mals = [f"MAL-2026-{n}" for n in range(4)]
    first = ghsa_json(G, identifiers=mals, **WEAK)
    quiet = {m: osv_json(m, packages=[("npm", "left-pad")]) for m in mals[:3]}
    read = sources.Reader(Api(**{G: first, **quiet, mals[3]: osv_json(mals[3])})).read
    assert read(mals[3]).support["Claude Code"][0] == "high"  # the fourth alone would raise
    assert support(thread(level="notice"), read)[:2] == ("notice", False)
    late = ghsa_json(G, cve=CVE, identifiers=["CVE-2026-0002", "CVE-2026-0003", "CVE-2026-0004"], **WEAK)
    got = support(thread(level="notice"), reads(**{G: late}), catalog("v", "CVE-2026-0004"))
    assert got == ("notice", False, set(), {CVE, "CVE-2026-0002", "CVE-2026-0003"}, False)  # KEV lists the fourth: unread
    ghsas = [f"GHSA-aaaa-bbbb-cc{n:02d}" for n in range(4)]
    answers = {g: ghsa_json(g, cve=CVE, type="malware" if g == ghsas[3] else "reviewed", **WEAK) for g in ghsas}
    e = thread((CVE, *ghsas), level="notice")
    assert support(e, sources.Reader(Api(**answers)).read, catalog("v"))[:2] == (ruleset.NONE, False)
    unpublished = thread((CVE,), level="notice")
    unpublished.aliases.append(ghsas[3])  # the ledger's identity set holds it; no post ever named it
    assert support(unpublished, sources.Reader(Api(**answers)).read, catalog("v"))[:2] == (ruleset.NONE, False)


def test_a_ghsa_first_thread_whose_alias_the_first_read_does_not_name_is_unknown():
    assert support(thread((G, G2)), reads(**{G: ghsa_json(G), G2: ghsa_json(G2, type="malware")}))[:2] == ("high", False)
    # a CVE the bot lists beside it: KEV's listing lends nothing and its absence proves nothing
    lone = reads(**{G: ghsa_json(G)})
    assert support(thread((G, CVE)), lone, catalog("v", CVE)) == ("high", False, set(), set(), False)
    assert support(thread((G, CVE)), lone, catalog("v")) == ("high", False, set(), set(), False)


def test_a_class_that_cannot_lower_makes_the_read_unknown():
    gone = ghsa_json(G, type="unreviewed", repo=None, withdrawn_at=WHEN)
    assert support(thread(), reads(**{G: gone})) == (ruleset.NONE, False, set(), set(), False)
    live = ghsa_json(G, type="unreviewed", repo=None)  # its notice is not counted either
    assert support(thread(), reads(**{G: live})) == (ruleset.NONE, False, set(), set(), False)
    other = ghsa_json(G, type="unreviewed", repo=None, packages=[("npm", "left-pad", "< 1", "1")])
    assert support(thread(), reads(**{G: other}))[1] is False  # silent about the product, and no authority
    silent = ghsa_json(G, packages=[("npm", "left-pad", "< 1", "1")])
    assert support(thread(), reads(**{G: silent}))[:2] == (ruleset.NONE, True)  # a reviewed one that no longer names it
    own = ghsa_json(G, type="unreviewed", withdrawn_at=WHEN)  # the vendor's own repository: the ruleset lets it lower
    assert support(thread(), reads(**{G: own}))[:2] == (ruleset.NONE, True)


def test_stop_using_comes_from_the_read():
    stop = [{"verb": "stop_using", "target": "Claude Code", "value": None}]
    e = thread(level="notice", actions=stop)
    found, known, _, _, says = support(e, reads(**{G: ghsa_json(G, type="malware", packages=NO_FIX)}))
    assert (found, known, says) == ("critical", True, True)
    assert recompute.held(e, CLAUDE, "critical", RS, True) == "critical"
    assert recompute.held(e, CLAUDE, "critical", RS) == "high"  # nothing says so now: the action is not complete
    up = [{"verb": "upgrade", "target": "Claude Code", "value": "2.1.0"}]
    assert recompute.held(thread(level="notice", actions=up), CLAUDE, "critical", RS) == "critical"  # its root's fix
    assert recompute.held(thread(level="notice"), CLAUDE, "critical", RS, True) == "high"  # no action published at all
    patched = support(e, reads(**{G: ghsa_json(G, type="malware")}))
    assert patched[0] == "critical" and patched[4] is False  # a patched version: the upgrade completes it, not stop_using


# ---------------------------------------------------------------- judge


def hourly(entry, read, n, st=None, cat=lambda h: None):
    st = st if st is not None else recompute.new_state()
    out = []
    for h in range(n + 1):
        c = cat(h)
        copy = kc(c, "ok", st, h * HOUR) if c else None
        out.append(recompute.judge(entry, CLAUDE, copy, RS, st, h * HOUR, read))
    return out, st


def test_a_thread_never_marked_exploited_needs_no_kev_sighting():
    read = reads(**{G: ghsa_json(G, cve=CVE, **WEAK)})
    got, st = hourly(thread((G, CVE)), read, 24, cat=lambda h: catalog(f"v{h // 6 + 1}"))
    assert got[:24] == [None] * 24 and got[24] == ("due", "notice")
    # one catalog version throughout: a thread KEV never listed does not wait for another
    assert hourly(thread((G, CVE)), read, 24, cat=lambda h: catalog("v1"))[0][24] == ("due", "notice")
    assert hourly(thread((G, CVE), exploited=True), read, 30, cat=lambda h: catalog(f"v{h // 6 + 1}"))[0] == [None] * 31
    assert hourly(thread(), reads(**{G: ghsa_json(G, **WEAK)}), 24)[0][24] == ("due", "notice")  # no CVE: no KEV copy needed
    assert st["dwell"]["a" * 64]["version"] is not None


def test_a_kev_listing_is_remembered_whether_or_not_a_level_changes():
    read = reads(**{G: ghsa_json(G, cve=CVE, type="malware", packages=NO_FIX)})
    stop = [{"verb": "stop_using", "target": "Claude Code", "value": None}]
    e, st = thread((G, CVE), level="critical", actions=stop), recompute.new_state()
    cut = {**catalog("v1", CVE), "count": 1}  # not complete: it lists the CVE all the same
    assert recompute.judge(e, CLAUDE, kc(cut, "ok", st, 0), RS, st, 0, read) is None
    assert st["exploited"] == {"a" * 64: [CVE]} and st["listed"] == {}  # listed, never by a complete copy
    weak = reads(**{G: ghsa_json(G, cve=CVE, **WEAK)})
    got, _ = hourly(e, weak, 60, st, cat=lambda h: catalog(f"v{h // 6 + 2}"))
    assert got == [None] * 61  # the absence proves nothing: no complete copy ever listed it
    fresh, _ = hourly(e, weak, 24, cat=lambda h: catalog(f"v{h // 6 + 2}"))
    assert fresh[24] == ("due", "notice")  # the same thread had KEV never listed it


def test_a_cve_the_advisory_stops_naming_and_a_kev_outage_lower_nothing():
    """A GHSA thread with no CVE of its own; its response names a CVE that KEV lists.
    Then the response stops naming it. The thread rested on KEV: with the CVE no longer
    judged it is unknown, with or without a catalog, and no run stops on it."""
    e, st = thread(level="critical", actions=[{"verb": "upgrade", "target": "Claude Code", "value": "2.1.0"}]), \
        recompute.new_state()
    named = reads(**{G: ghsa_json(G, cve=CVE, **WEAK)})
    assert recompute.judge(e, CLAUDE, kc(catalog("v1", CVE), "ok", st, 0), RS, st, 0, named) is None
    assert st["exploited"] == {"a" * 64: [CVE]}
    silent = reads(**{G: ghsa_json(G, **WEAK)})
    info = {}
    assert recompute.judge(e, CLAUDE, kc(catalog("v2"), "ok", st, HOUR), RS, st, HOUR, silent, info) is None
    assert info["known"] is False and st["dwell"] == {}
    for h in range(2, 60):  # KEV down, then back with later catalogs: never due, never an exception
        copy = None if h < 30 else kc(catalog(f"v{h}"), "ok", st, h * HOUR)
        assert recompute.judge(e, CLAUDE, copy, RS, st, h * HOUR, silent) is None
    marked = thread(level="critical", exploited=True, actions=e.advisory["actions"])  # the ledger's mark alone,
    fresh = recompute.new_state()  # the recompute file lost: still no CVE to judge, still unknown
    assert hourly(marked, silent, 30, fresh, cat=lambda h: catalog(f"v{h // 6 + 1}"))[0] == [None] * 31


def test_a_patched_version_ends_what_stop_using_completed():
    """Posted at critical with stop_using, no fix. The advisory then states a patched
    version: the ruleset still gives critical, but nothing completes it now (the thread
    has no upgrade to offer), and a member's check of the same response finds high.
    The level falls to high after the day; with the advisory unread it stands."""
    stop = [{"verb": "stop_using", "target": "Claude Code", "value": None}]
    e = thread(level="critical", actions=stop, root_fixed="")
    patched = reads(**{G: ghsa_json(G, type="malware")})
    got, _ = hourly(e, patched, 24)
    assert got[:24] == [None] * 24 and got[24] == ("due", "high")
    assert hourly(e, reads(**{G: ghsa_json(G, type="malware", packages=NO_FIX)}), 30)[0] == [None] * 31
    assert hourly(e, reads(**{G: 503}), 30)[0] == [None] * 31
    rec = verify._record(RS, "ghsa", [patched(G).fields], [], None, 0)
    member = verify.judge("critical", "Claude Code", [rec], True, RS, [("stop_using", "Claude Code", None)], None)
    assert (member["result"], member["source"]) == ("contradicted", "high")


def test_a_raise_needs_no_complete_read_and_ends_a_wait():
    e, st = thread(level="notice"), recompute.new_state()
    assert recompute.judge(e, CLAUDE, None, RS, st, 0, reads(**{G: ghsa_json(G)})) == ("raise", "high")
    info = {}
    recompute.judge(thread(), CLAUDE, None, RS, st, 0, reads(**{G: 429}), info)
    assert info == {"known": False, "listed": set()}


def test_states_written_before_this_change_still_load(tmp_path):
    old = {k: v for k, v in recompute.new_state().items() if k != "exploited"}
    old["dwell"] = {"a" * 64: {"level": "high", "version": "2026.11.24", "last": 5, "held": 7}}
    inputs.write_json(tmp_path / "s.json", old)
    st, replaced = recompute.load(tmp_path / "s.json")
    assert not replaced and st["exploited"] == {} and st["dwell"] == old["dwell"]
    st["dwell"]["a" * 64]["version"] = None  # a thread with no CVE has no catalog version to wait on
    st["exploited"] = {"a" * 64: [CVE]}
    recompute.save(tmp_path / "s.json", st)
    assert recompute.load(tmp_path / "s.json") == (st, False)
    for bad in ({**st, "exploited": ["a" * 64]}, {**st, "exploited": None}, {**st, "exploited": {"a": []}},
                {**st, "dwell": {"a" * 64: {"level": "high", "version": "x", "last": 5, "held": 7}}},
                {**st, "dwell": {"a" * 64: {"level": "high", "last": 5, "held": 7}}}):
        inputs.write_json(tmp_path / "s.json", bad)
        assert recompute.load(tmp_path / "s.json")[1] is True


# ---------------------------------------------------------------- through main.run


def post(env, fid=G, fixed="2.1.0", at=0, **api):
    """A thread at high from the advisory's fields, its prose a notice (so it can fall)."""
    env.api.put(fid, ghsa_json(fid, **api))
    env.collector([finding(fid=fid, severity="moderate", fixed=fixed)])
    return run(env, at)


def run(env, hour, **kw):
    code, summary, relay = env.run(now=T0 + hour * HOUR, **kw)
    assert code == 0, summary
    return relay


def hours(env, first, last, **kw):
    """Hourly runs from ``first`` to ``last`` inclusive: [(hour, level)] sent in feed."""
    return [(h, b["level"]) for h in range(first, last + 1) for b in levels(run(env, h, **kw))]


def entries(env):
    return env.ledger()[0]


def state(env):
    return recompute.load(env.config.recompute_state)[0]


def test_a_vendor_advisory_posts_at_high_from_its_fields(env):
    relay = post(env)
    (e,) = entries(env)
    assert e["level"] == "high" and e["floor"] == "notice" and [c[0] for c in relay.calls if c[1] is None] == ["feed"]
    assert env.api.calls == ["https://api.github.com/advisories/" + G]  # one request: admission's read serves the recompute


FAILURES = [302, 403, 404, 429, 503, OSError("timed out"), b"{", b'{"ghsa_id": 1, "ghsa_id": "GHSA-abcd-efgh-ijkl"}',
            ghsa_json(G2, **WEAK), b" " * (verify.LIMITS["ghsa"] + 1)]


@pytest.mark.parametrize("answer", FAILURES, ids=lambda a: str(a)[:20])
def test_a_failed_read_lowers_nothing_starts_no_wait_and_adds_no_time(env, answer):
    """A 404 and a 429 from the advisory endpoint each lower nothing (acceptance), like
    every other answer that is not a whole 200 for this id: with no wait running, and
    inside one."""
    post(env)
    env.api.put(G, answer)
    assert hours(env, 1, 3) == [] and state(env)["dwell"] == {}
    env.api.put(G, ghsa_json(G, **WEAK))
    assert hours(env, 4, 6) == []
    root = entries(env)[0]["root_event_id"]
    assert state(env)["dwell"][root]["held"] == 2 * HOUR
    env.api.put(G, answer)
    assert hours(env, 7, 34) == []  # 27 more hours of it: were they counted, it would have fallen at 28
    wait = state(env)["dwell"][root]
    assert wait["held"] == 2 * HOUR and wait["last"] is None and entries(env)[0]["level"] == "high"


def test_a_failed_read_inside_a_wait_costs_its_two_hours(env):
    post(env)
    env.api.put(G, ghsa_json(G, **WEAK))
    assert hours(env, 1, 20) == []
    env.api.put(G, 429)
    assert hours(env, 21, 21) == []
    env.api.put(G, ghsa_json(G, **WEAK))
    assert hours(env, 22, 26) == [] and hours(env, 27, 30) == [(27, "notice")]  # 19 hours held, then five more


def test_a_reviewed_advisory_that_stops_supporting_high_lowers_once(env):
    post(env)
    env.api.put(G, ghsa_json(G, **WEAK))
    assert hours(env, 1, 24) == []
    relay = run(env, 25)
    assert levels(relay) == [{"level": "notice"}] and len([c for c in relay.calls if c[1] is not None]) == 1
    (e,) = entries(env)
    assert e["level"] == "notice" and e["lowered"] is True
    assert hours(env, 26, 60) == []


def test_a_field_that_toggles_hourly_moves_nothing(env):
    """Acceptance: an advisory whose severity toggles hourly produces at most three replies
    in a week. The severity word sets no level (9kgk); neither does a weakness that comes
    and goes every hour: none here."""
    post(env)
    sent = []
    for h in range(1, 7 * 24 + 1):
        env.api.put(G, ghsa_json(G, severity="low" if h % 2 else "critical", cwes=() if h % 2 else ("CWE-78",)))
        sent += hours(env, h, h)
    assert sent == [] and entries(env)[0]["level"] == "high"


def test_a_field_that_toggles_every_two_days_sends_at_most_three_in_any_week(env):
    post(env)
    sent = []
    for h in range(1, 16 * 24 + 1):
        env.api.put(G, ghsa_json(G, cwes=() if (h // 48) % 2 == 0 else ("CWE-78",)))
        sent += hours(env, h, h)
    assert sent[:2] == [(25, "notice"), (48, "high")]  # down after a day, up in the run that reads it
    assert all(sum(a <= h < a + 7 * 24 for h, _ in sent) <= 3 for a in range(16 * 24))
    assert len(sent) <= 5 and [lv for _, lv in sent][2:3] in ([], ["notice"])


def test_a_withdrawn_unreviewed_advisory_lowers_nothing(env):
    """Acceptance. An unreviewed advisory outside the vendor's repository is a source its
    subject's attacker can write: its withdrawal justifies no lowering, however long."""
    post(env)
    env.api.put(G, ghsa_json(G, type="unreviewed", repo=None, withdrawn_at=WHEN))
    assert hours(env, 1, 50) == [] and state(env)["dwell"] == {} and entries(env)[0]["level"] == "high"


def test_a_withdrawn_reviewed_advisory_lowers_to_notice_and_stays(env):
    post(env)
    env.api.put(G, ghsa_json(G, withdrawn_at=WHEN))
    assert hours(env, 1, 60) == [(25, "notice")]  # no lower state yet (ai-tools-alerts#y484): the thread stays
    (e,) = entries(env)
    assert e["level"] == "notice" and e["advisory"]["level"] == "notice"


def test_a_malware_advisory_withdrawn_and_published_again_returns_to_critical(env):
    malware = dict(type="malware", packages=NO_FIX)
    relay = post(env, fixed=None, **malware)
    (e,) = entries(env)
    assert e["level"] == "critical" and [a["verb"] for a in e["advisory"]["actions"]] == ["stop_using"]
    env.api.put(G, ghsa_json(G, withdrawn_at=WHEN, **malware))
    assert hours(env, 1, 24) == []
    relay = run(env, 25)
    assert levels(relay) == levels(relay, "critical") == [{"level": "notice"}]
    env.api.put(G, ghsa_json(G, **malware))
    relay = run(env, 26)
    assert levels(relay) == levels(relay, "critical") == [{"level": "critical"}]
    assert entries(env)[0]["level"] == "critical" and hours(env, 27, 30) == []


def test_kev_listing_a_critical_thread_is_remembered_and_its_later_absence_lowers_nothing(env):
    env.api.put(G, ghsa_json(G, cve=CVE, type="malware", packages=NO_FIX))
    env.collector([finding(fid=G, severity="moderate", fixed=None, aliases=[CVE])])
    run(env, 0)
    (e,) = entries(env)
    assert e["level"] == "critical" and CVE in e["aliases"] and e["exploited"] is False
    old = {**kev_item(CVE), "dateAdded": "2026-09-01"}  # before the watermark: no candidate, only the recompute
    relay = run(env, 1, kev=FakeKEV(catalog={**catalog("v1", old), "count": 1}))  # a cut copy that lists it
    assert relay.calls == [] and state(env)["exploited"] == {e["root_event_id"]: [CVE]}
    assert entries(env)[0]["exploited"] is True  # the ledger says so from the end of that run
    env.api.put(G, ghsa_json(G, cve=CVE, **WEAK))
    sent = [x for h in range(2, 32) for x in levels(run(env, h, kev=FakeKEV(catalog=catalog(f"v{h // 6 + 2}"))))]
    env.config.recompute_state.unlink()  # the recompute file lost: the ledger's mark still governs
    sent += [x for h in range(32, 62) for x in levels(run(env, h, kev=FakeKEV(catalog=catalog(f"v{h // 6 + 2}"))))]
    assert sent == [] and entries(env)[0]["level"] == "critical"


def test_a_named_mal_id_is_read_from_osv_and_its_support_holds_the_level(env):
    post(env)
    env.api.put(G, ghsa_json(G, identifiers=[MAL], **WEAK))
    env.api.put(MAL, osv_json(MAL))
    assert hours(env, 1, 30) == [] and state(env)["dwell"] == {}  # OSV's entry supports high: nothing to lower
    assert env.api.calls.count("https://api.osv.dev/v1/vulns/" + MAL) == 30
    env.api.put(MAL, 404)
    assert hours(env, 31, 60) == [] and state(env)["dwell"] == {}  # unread: unknown, never "gone"
    env.api.put(MAL, osv_json(MAL, withdrawn="2026-11-07T00:00:00Z"))
    assert hours(env, 61, 90) == [(85, "notice")]


def threads(env, n, **api):
    """n threads at high, each its own advisory and its own release (faxq), over as many
    runs as admission's ten reads a run need. Returns (their ids, the next hour)."""
    ids = [f"GHSA-aaaa-bbbb-cc{k:02d}" for k in range(n)]
    for i in ids:
        env.api.put(i, ghsa_json(i, **api))
    env.collector([finding(fid=i, severity="moderate", fixed=f"2.2.{k}") for k, i in enumerate(ids)])
    h = 0
    while len(entries(env)) < n:
        run(env, h)
        h += 1
        assert h <= n
    assert all(e["level"] == "high" for e in entries(env))
    return ids, h


def test_reads_that_keep_failing_do_not_keep_another_thread_unread(env):
    """Fourteen threads share the ten reads of their lane; thirteen answer 404 for ever.
    The order starts one thread further on each hour, so in fourteen hours every thread
    has been asked for, ten a run, and the one whose advisory comes to support critical
    is raised whichever place it holds."""
    ids, h = threads(env, 14)
    for i in ids:
        env.api.put(i, 404)
    asked, per_run = set(), []
    for k in range(h, h + 14):
        before = len(env.api.calls)
        assert levels(run(env, k)) == []
        now = {u.rsplit("/", 1)[1] for u in env.api.calls[before:]}
        per_run.append(len(now))
        asked |= now
    assert per_run == [10] * 14 and asked == set(ids)  # a fixed order would leave four never asked
    target = ids[-1]
    skipped = [k for k in range(h + 14, h + 28) if target not in _asked_in(env, k)]
    assert len(skipped) == 4  # four hours in fourteen it is past the tenth place
    env.api.put(target, ghsa_json(target, type="malware"))
    raised = [k for k in range(h + 28, h + 42) if levels(run(env, k)) == [{"level": "critical"}]]
    assert len(raised) == 1 and [e["level"] for e in entries(env)].count("critical") == 1


def _asked_in(env, hour):
    before = len(env.api.calls)
    run(env, hour)
    return {u.rsplit("/", 1)[1] for u in env.api.calls[before:]}


def test_threads_with_a_wait_are_read_in_a_lane_of_their_own(env):
    """Twelve threads. Ten are read in a run and begin a wait; from the next run those
    ten are read in the wait lane and the other two in the rest lane: twelve requests,
    where one shared lane allows ten."""
    ids, h = threads(env, 12)
    for i in ids:
        env.api.put(i, ghsa_json(i, **WEAK))
    assert len(_asked_in(env, h)) == 10 and len(state(env)["dwell"]) == 10
    assert _asked_in(env, h + 1) == set(ids) and len(state(env)["dwell"]) == 12
    assert len(_asked_in(env, h + 2)) == 10  # twelve waits now: the wait lane's ten, in turn


def test_many_candidates_leave_the_threads_their_reads(env):
    post(env)
    extra = [f"GHSA-aaaa-bbbb-dd{k:02d}" for k in range(12)]
    env.collector([finding(fid=i, severity="moderate", fixed=f"2.3.{k}") for k, i in enumerate(extra)])
    env.api.put(G, ghsa_json(G, type="malware"))
    relay = run(env, 1)
    assert levels(relay) == [{"level": "critical"}]  # twelve candidates took admission's ten reads, not this one
    admitted = [u for u in env.api.calls if "-dd" in u]
    assert len(admitted) == sources.LANE_READS


def test_the_breakers_share_is_of_the_threads_read_whole(env):
    """Three of five threads read whole fall due together: more than two and more than a
    fifth, so none is lowered. Threads nobody could read are not in the share (ny5g's
    own test of it, with twenty unread GHSA threads, still passes)."""
    ids, h = threads(env, 5)
    for i in ids[:3]:
        env.api.put(i, ghsa_json(i, **WEAK))
    assert hours(env, h, h + 30) == []
    assert state(env)["tripped"]["due"] == 3
    env.api.put(ids[0], ghsa_json(ids[0]))  # one recovers: two due is within the breaker
    sent = hours(env, h + 31, h + 32)
    assert [lv for _, lv in sent] == ["notice", "notice"]


# ---------------------------------------------------------------- candidates


def test_a_notice_held_while_the_api_failed_posts_when_it_answers(env):
    env.api.put(G, 429)
    env.collector([finding(severity="moderate")])
    relay = run(env, 0)
    assert relay.calls == [] and entries(env) == [] and len(env.state()["held"]) == 1
    assert [d["id"] for d in env.state()["deferred"]] == [G]
    env.api.put(G, ghsa_json(G))
    relay = run(env, 1)  # no new input record
    assert [c[0] for c in relay.calls if c[1] is None] == ["feed"] and entries(env)[0]["level"] == "high"
    assert env.state()["deferred"] == [] and hours(env, 2, 4) == []


def test_the_retry_of_an_unread_advisory_ends_after_seven_days(env):
    env.api.put(G, 503)
    env.collector([finding(severity="moderate")])
    kept = []
    for day in range(10):
        run(env, day * 24)
        kept.append(len(env.state()["deferred"]))
    assert kept == [1] * 7 + [0] * 3 and entries(env) == []


def test_with_no_first_sight_on_record_there_is_no_retry(env):
    run(env, 0)
    st = env.state()
    st["waiting"] = {f"Claude Code|cve-2020-{n:04d}": T0 for n in range(inputs.MAX_WAITING // 2)}  # the map is full
    inputs.save_state(env.config.state, st)
    env.api.put(G, 503)
    env.collector([finding(severity="moderate")])
    run(env, 1)
    assert env.state()["deferred"] == [] and len(env.state()["held"]) == 1


def member(env, entry):
    """The member's own check of a published thread, against the same API answers."""
    adv = schema.validate(entry["advisory"])

    def fetch(url, etag, limit, timeout):
        return (404, None, b"") if url == verify.KEV_URL else env.api(url, etag, limit, timeout)
    cache = verify.run([adv], [adv], env.config.ledger.parent, fetch=fetch, now=T0)
    return verify.result_for(adv, cache)


def test_a_fix_group_posts_under_its_loudest_member_and_at_that_members_level(env):
    """Two advisories one release fixes are one post. Its first id is the member whose
    own evidence supports most, so the level is one a member's check of that id finds."""
    env.api.put(G, ghsa_json(G))
    env.api.put(G2, ghsa_json(G2, type="malware"))
    env.collector([finding(fid=G, severity="moderate"), finding(fid=G2, severity="moderate")])
    run(env, 0)
    (e,) = entries(env)
    assert e["level"] == "critical" and e["advisory"]["id"].upper() == G2.upper()
    assert member(env, e)["claude-code\nClaude Code"]["result"] == "confirmed"


def test_a_kev_listed_member_is_the_fix_groups_first_id(env):
    """A GHSA published later would have been the group's first id, with the level of
    another member's KEV listing: critical under an id whose source says high."""
    env.kev.catalog = {"vulnerabilities": [kev_item(CVE)]}
    later = finding(fid=G2, severity="moderate")
    later["sources"][0]["published_at"] = "2026-11-05T00:00:00Z"
    env.api.put(G2, ghsa_json(G2))
    env.collector([later, finding(fid=CVE, severity="moderate", fixed="2.1.0")])
    run(env, 0)
    (e,) = entries(env)
    assert e["level"] == "critical" and e["advisory"]["id"] == CVE

    def fetch(url, etag, limit, timeout):
        if url == verify.KEV_URL:
            body = json.dumps({"catalogVersion": "1", "count": 1, "vulnerabilities": [kev_item(CVE)]}).encode()
            return 200, None, body
        return env.api(url, etag, limit, timeout)
    adv = schema.validate(e["advisory"])
    got = verify.result_for(adv, verify.run([adv], [adv], env.config.ledger.parent, fetch=fetch, now=T0))
    assert got["claude-code\nClaude Code"]["result"] == "confirmed"


def test_a_fix_group_is_as_new_as_its_newest_member(env):
    """The loudest member comes first even when its advisory is months old. The group is
    still news when another member is: it posts, and is not sent to the digest as old."""
    old, new = finding(fid=G, severity="moderate"), finding(fid=G2, severity="moderate")
    old["sources"][0]["published_at"], new["sources"][0]["published_at"] = "2026-08-01T00:00:00Z", "2026-11-04T00:00:00Z"
    env.api.put(G, ghsa_json(G, type="malware"))
    env.api.put(G2, ghsa_json(G2))
    env.collector([old, new])
    relay = run(env, 0)
    (e,) = entries(env)
    assert e["level"] == "critical" and e["advisory"]["id"].upper() == G.upper() and env.state()["held"] == []
    assert [c[0] for c in relay.calls if c[1] is None] == ["critical", "feed"]


def test_a_reading_the_first_id_does_not_tie_wins_no_place_in_a_fix_group(env):
    """A CVE candidate whose page names the CVE while the advisory API's answer, which
    supports critical, does not. Counted, it would come first and then lose that reading
    to the tie rule, taking the group down to a notice. The other member's high stands."""
    env.api.put(G, ghsa_json(G, type="malware"))  # names no CVE
    env.api.put(G2, ghsa_json(G2))
    env.collector([finding(fid=CVE, severity="moderate"), finding(fid=G2, severity="moderate")])
    run(env, 0)
    (e,) = entries(env)
    assert e["level"] == "high" and e["advisory"]["id"].upper() == G2.upper()


def test_a_kev_listing_first_seen_on_a_thread_this_run_posted_reaches_the_ledger(env):
    env.api.put(G, ghsa_json(G, cve=CVE, type="malware", packages=NO_FIX))
    env.collector([finding(fid=G, severity="moderate", fixed=None, aliases=[CVE])])
    old = {**kev_item(CVE), "dateAdded": "2026-09-01"}  # before the watermark: no candidate brings it
    run(env, 0, kev=FakeKEV(catalog=catalog("v1", old)))
    (e,) = entries(env)
    assert e["level"] == "critical" and e["exploited"] is True
    env.config.recompute_state.unlink()  # and the recompute file lost: the KEV rules still govern it
    env.api.put(G, ghsa_json(G, cve=CVE, **WEAK))
    sent = [x for h in range(1, 40) for x in levels(run(env, h, kev=FakeKEV(catalog=catalog(f"v{h // 6 + 2}"))))]
    assert sent == [] and entries(env)[0]["level"] == "critical"


def test_a_fix_groups_other_member_lends_no_level(env):
    """The post's first id supports high; the other member a notice. When that other
    member comes to support critical and is sighted again alone, under its own id, the
    thread is not raised: its first id's source does not name it, a member's check
    ignores it, and so do the candidate's level and the recompute."""
    env.api.put(G, ghsa_json(G))
    env.api.put(G2, ghsa_json(G2, **WEAK))
    env.collector([finding(fid=G, severity="moderate"), finding(fid=G2, severity="moderate")])
    run(env, 0)
    (e,) = entries(env)
    assert e["level"] == "high" and e["advisory"]["id"].upper() == G.upper() and len(e["aliases"]) == 2
    assert member(env, e)["claude-code\nClaude Code"]["result"] == "confirmed"
    env.api.put(G2, ghsa_json(G2, type="malware"))
    env.collector([finding(fid=G2, severity="moderate", affected="<2.1.0")])  # the second, alone, with something new
    relay = run(env, 1)
    assert levels(relay) == [] and entries(env)[0]["level"] == "high"
    assert hours(env, 2, 30) == [] and member(env, entries(env)[0])["claude-code\nClaude Code"]["result"] == "confirmed"
    alone = Api(default=plain, **{G2: ghsa_json(G2, type="malware")})  # the same advisory as its own thread: critical
    assert sources.Reader(alone).read(G2).support["Claude Code"][0] == "critical"
