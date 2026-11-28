"""A fix group whose first id stops supporting its level (ai-tools-alerts#yd1y): the
members whose own advisory still supports more leave the thread and are posted as a
root of their own, and the old thread is then judged by its first id alone. Through
``main.run`` one run an hour with the fake relay, pages and advisory API, and the
member's own check (``verify.run``) of what was published."""

import tempfile
from pathlib import Path

import pytest

from aitools_alerts import schema, verify
from aitools_alerts.poster import compose, main

from advisories import ghsa_json
from test_advisory_recompute import (  # noqa: F401  (env is a fixture)
    G, G2, WEAK, WHEN, entries, env, hours, run, state)
from test_main import T0, finding
from test_recompute import levels

G3 = "GHSA-yyyy-yyyy-yyyy"
KEY = "claude-code\nClaude Code"


def member(env, entry):
    """The member's own check of a published thread against the API as it answers now,
    on a machine that has checked nothing before."""
    adv = schema.validate(entry["advisory"])

    def fetch(url, etag, limit, timeout):
        return (404, None, b"") if url == verify.KEV_URL else env.api(url, etag, limit, timeout)
    with tempfile.TemporaryDirectory() as d:
        return verify.result_for(adv, verify.run([adv], [adv], Path(d), fetch=fetch, now=T0))


def group(env, *ids, **api):
    """One root for the advisories ``ids``, one release fixing them all, each high by its
    own fields (``api``: per id, what its advisory says instead). Its first id is ids[0]."""
    for i in ids:
        env.api.put(i, ghsa_json(i, **api.get(i.replace("-", "_"), {})))
    env.collector([finding(fid=i, severity="moderate") for i in ids])
    run(env, 0)
    (e,) = entries(env)
    assert e["advisory"]["id"].upper() == ids[0].upper() and len(e["aliases"]) == len(ids)
    return e


def sent(relay):
    """What a run sent, the daily digest apart."""
    return [c for c in relay.calls if not c[2].startswith("Daily digest")]


def roots(relay):
    return [c for c in sent(relay) if c[1] is None]


def test_a_member_whose_first_id_is_withdrawn_is_posted_again(env):
    """Acceptance. GHSA A and GHSA B, one release fixes both, both high, one root led by
    A. A's advisory is withdrawn; B's is not. Members are still told about B at high: B
    leaves the thread in the run that reads the withdrawal, the next run posts it as its
    own root, and a member's check of that root confirms it. The old thread, now A's
    alone, takes the withdrawal as any thread does."""
    old = group(env, G, G2)
    assert old["level"] == "high" and member(env, old)[KEY]["result"] == "confirmed"
    env.api.put(G, ghsa_json(G, withdrawn_at=WHEN))
    assert member(env, old)[KEY]["result"] != "confirmed"  # what a member's machine finds from now on
    relay = run(env, 1)
    assert sent(relay) == []
    (old,) = entries(env)
    assert old["split"] == {"released": [G2], "kept": []} and old["aliases"] == [G]
    relay = run(env, 2)
    ((ch, _, text),) = roots(relay)
    assert ch == "feed" and "Covers 1 advisory: " + G2 in text.split("\n") and G.casefold() not in text.casefold()
    old, new = entries(env)
    assert new["advisory"]["id"] == G2 and new["level"] == "high" and new["aliases"] == [G2]
    assert member(env, new)[KEY]["result"] == "confirmed"
    later = [c for h in range(3, 40) for c in sent(run(env, h))]
    assert [c[2] for c in later] == [compose.withdrawal_post()]  # the old thread's, after its wait; no second root
    old, new = entries(env)
    assert old["withdrawn"] == ["feed"] and new["level"] == "high" and "withdrawn" not in new


def test_a_member_whose_first_id_lowers_is_posted_again(env):
    """The first id's advisory now supports a notice; the other member's still high."""
    group(env, G, G2)
    env.api.put(G, ghsa_json(G, **WEAK))
    run(env, 1)
    assert len(roots(run(env, 2))) == 1
    old, new = entries(env)
    assert new["advisory"]["id"] == G2 and new["level"] == "high"
    assert hours(env, 3, 40) == [(25, "notice")] and entries(env)[0]["level"] == "notice"


def test_no_member_leaves_while_the_first_id_supports_the_level(env):
    group(env, G, G2)
    assert [c for h in range(1, 30) for c in sent(run(env, h))] == []
    (e,) = entries(env)
    assert "split" not in e and len(e["aliases"]) == 2


@pytest.mark.parametrize("answer", [503, ghsa_json(G2, type="unreviewed", repo=None)])
def test_a_member_whose_own_advisory_is_not_read_or_cannot_lower_stays(env, answer):
    """Unknown changes nothing: the member stays, the thread stays unknown and lowers
    nothing, and the run that reads the member's advisory releases it."""
    group(env, G, G2)
    env.api.put(G, ghsa_json(G, withdrawn_at=WHEN))
    env.api.put(G2, answer)
    assert [c for h in range(1, 30) for c in sent(run(env, h))] == []
    (e,) = entries(env)
    assert "split" not in e and state(env)["dwell"] == {}
    env.api.put(G2, ghsa_json(G2))
    run(env, 30)
    assert entries(env)[0]["split"] == {"released": [G2], "kept": []}


def test_a_failed_read_of_the_first_id_releases_nothing(env):
    group(env, G, G2)
    env.api.put(G, 503)
    assert [c for h in range(1, 30) for c in sent(run(env, h))] == []
    assert "split" not in entries(env)[0]


def test_members_that_leave_together_are_one_root_again(env):
    """Three advisories, the first withdrawn: the other two are one post, under the one
    whose own advisory supports more."""
    group(env, G, G2, G3, **{G.replace("-", "_"): {"type": "malware"}})
    assert entries(env)[0]["level"] == "critical"
    env.api.put(G, ghsa_json(G, withdrawn_at=WHEN))
    run(env, 1)
    assert len(roots(run(env, 2))) == 1
    old, new = entries(env)
    assert sorted(old["split"]["released"]) == sorted([G2, G3]) and old["aliases"] == [G]
    assert new["level"] == "high" and sorted(new["aliases"]) == sorted([G2, G3])
    assert member(env, new)[KEY]["result"] == "confirmed"


def test_a_member_that_supports_no_more_than_the_first_id_now_does_stays(env):
    """Nothing is lost by the thread's lowering, so there is no second root."""
    group(env, G, G2)
    env.api.put(G, ghsa_json(G, **WEAK))
    env.api.put(G2, ghsa_json(G2, **WEAK))
    assert [c for h in range(1, 24) for c in sent(run(env, h))] == [] and "split" not in entries(env)[0]


def test_a_member_whose_page_cannot_be_read_leaves_in_a_later_run(env):
    group(env, G, G2)
    env.api.put(G, ghsa_json(G, withdrawn_at=WHEN))
    url = "https://github.com/anthropics/claude-code/security/advisories/" + G2
    env.pages.put(url, "", status=503)
    run(env, 1)
    assert "split" not in entries(env)[0]
    del env.pages.fixed[url]
    run(env, 2)
    assert entries(env)[0]["split"] == {"released": [G2], "kept": []}
    assert len(roots(run(env, 3))) == 1


def test_a_released_member_does_not_join_the_thread_it_left(env):
    """btqg would put an advisory with the thread's fix back into it."""
    group(env, G, G2)
    env.api.put(G, ghsa_json(G, **WEAK))
    run(env, 1)
    run(env, 2)
    env.collector([finding(fid=G2, severity="moderate")])  # sighted again
    assert roots(run(env, 3)) == []
    old, new = entries(env)
    assert old["aliases"] == [G] and "joined" not in old and new["aliases"] == [G2]


def test_a_run_that_stops_before_the_ledger_write_releases_next_run(env, monkeypatch):
    group(env, G, G2)
    env.api.put(G, ghsa_json(G, withdrawn_at=WHEN))
    real = main.Ledger.release

    def boom(self, *a, **kw):
        raise KeyboardInterrupt  # the run stops here: nothing after this line of it happens
    monkeypatch.setattr(main.Ledger, "release", boom)
    with pytest.raises(KeyboardInterrupt):
        env.run(now=T0 + 3600)
    monkeypatch.setattr(main.Ledger, "release", real)
    assert "split" not in entries(env)[0]
    assert env.state()["deferred"][0]["id"] == G2  # the pointer was saved before the ledger write
    relay = run(env, 2)  # the release is made again, before the saved pointer is planned
    assert entries(env)[0]["split"] == {"released": [G2], "kept": []}
    assert len(roots(relay)) == 1 and len(entries(env)) == 2
    assert [c for h in range(3, 20) for c in roots(run(env, h))] == []  # the second pointer starts nothing


def test_the_ledgers_advisory_is_valid_after_a_release(env):
    group(env, G, G2)
    env.api.put(G, ghsa_json(G, withdrawn_at=WHEN))
    run(env, 1)
    adv = schema.validate(entries(env)[0]["advisory"])
    assert [adv.id, *adv.aliases] == [G, G2]  # what was published stays published


# ---------------------------------------------------------------- from the spec review


def test_members_are_read_though_other_threads_spend_the_lane(env):
    """Twelve other threads share the lane's ten reads a run. The group's members are read
    in the group's own turn, right after its first id, so within as many hours as there
    are threads the member has left."""
    group(env, G, G2)
    ids = [f"GHSA-aaaa-bbbb-cc{k:02d}" for k in range(12)]
    for i in ids:
        env.api.put(i, ghsa_json(i))
    env.collector([finding(fid=i, severity="moderate", fixed=f"2.2.{k}") for k, i in enumerate(ids)])
    h = 1
    while len(entries(env)) < 13:
        run(env, h)
        h += 1
    env.api.put(G, ghsa_json(G, withdrawn_at=WHEN))
    for k in range(h, h + 13):
        run(env, k)
    old = next(e for e in entries(env) if e["advisory"]["id"].upper() == G.upper())
    assert old["split"] == {"released": [G2], "kept": []}


def test_a_thread_already_stepped_down_to_notice_still_releases_its_member(env):
    """The member's advisory could not be read for 45 days, so nothing confirmed the level
    and the thread was stepped down. When it reads again the member leaves all the same:
    its own source supports more than the first id's, whatever the thread stands at."""
    group(env, G, G2)
    env.api.put(G, ghsa_json(G, withdrawn_at=WHEN))
    env.api.put(G2, 503)
    day = 24
    for d in range(1, 80):
        run(env, d * day)
    (e,) = entries(env)
    assert e["level"] == "notice" and "split" not in e
    env.api.put(G2, ghsa_json(G2))
    run(env, 80 * day)
    assert entries(env)[0]["split"] == {"released": [G2], "kept": []}
    assert len(roots(run(env, 80 * day + 1))) == 1
    assert entries(env)[1]["level"] == "high" and member(env, entries(env)[1])[KEY]["result"] == "confirmed"


def test_a_member_whose_title_raised_the_prose_floor_still_leaves(env):
    """The thread is held at high by a member's prose, so the poster would not lower it.
    A member's check reads fields: the first id's are withdrawn and the member's are not."""
    for i in (G, G2):
        env.api.put(i, ghsa_json(i))
    env.collector([finding(fid=G, severity="moderate"), finding(fid=G2)])  # G2's page says code execution
    run(env, 0)
    (e,) = entries(env)
    lead, other = e["advisory"]["id"], next(a for a in e["aliases"] if a != e["advisory"]["id"])
    assert e["floor"] == "high"
    env.api.put(lead, ghsa_json(lead, withdrawn_at=WHEN))
    run(env, 1)
    assert entries(env)[0]["split"] == {"released": [other], "kept": []}


def test_a_released_id_the_first_id_comes_to_name_counts_again():
    """A member's check reads what the first id's response names, whatever the ledger
    says: such an id is one of the thread's sources again."""
    from aitools_alerts.poster import recompute
    from test_advisory_recompute import reads, support, thread
    e = thread(ids=(G, G2), split={"released": [G2], "kept": []})
    apart = reads(**{G: ghsa_json(G, withdrawn_at=WHEN), G2: ghsa_json(G2)})
    assert support(e, apart)[:2] == ("none", True)  # the first id's alone: G2 is not read
    named = reads(**{G: ghsa_json(G, withdrawn_at=WHEN, identifiers=(G2,)), G2: ghsa_json(G2)})
    assert support(e, named)[:2] == ("high", True)
    assert recompute.loose(e, apart) == ([], set())
    assert recompute.released(thread(ids=(G, G2), split={"released": [G, G2], "kept": []})) == {G2}  # never its first id


# ---------------------------------------------------------------- from the code review


def test_a_member_retracted_after_it_left_does_not_strand_the_first_advisory(env):
    """The old root still names the member that left, so a retraction of that member hides
    it on every reader. z360's retirement then judges the thread though its ledger ids no
    longer hold the retracted one: the first advisory is released to be posted again, and
    the hidden thread takes the retracted id back as its own."""
    from test_main import _on_mirror, _retract, at
    for i in (G, G2):
        env.api.put(i, ghsa_json(i))
    env.collector([finding(fid=G, severity="moderate"), finding(fid=G2, severity="moderate")])
    _, _, first = env.run(now=T0)
    env.api.put(G, ghsa_json(G, **WEAK))
    run(env, 1)
    _, _, second = env.run(now=T0 + 2 * 3600)
    assert len(roots(second)) == 1 and entries(env)[0]["split"] == {"released": [G2], "kept": []}
    _on_mirror(env, first, T0 + 60)
    _retract(env, second, [G2], at_=T0 + 2 * 3600 + 60)
    code, summary, _ = env.run(now=at(5, 10))
    assert code == 0, summary
    old = entries(env)[0]
    assert old["split"]["released"] == [G] and old["aliases"] == [G2]


def test_the_listing_of_a_first_cve_is_remembered_for_a_thread_with_members():
    """``judge`` never knows a thread that has a loose member, so it never records that a
    complete copy listed the first CVE; without that, the CVE's later absence would prove
    nothing for ever and the member could never leave."""
    from aitools_alerts.poster import recompute
    from test_advisory_recompute import CLAUDE, CVE, RS, reads, thread
    from test_recompute import catalog, kc
    e = thread(ids=(CVE, G2), level="critical", exploited=True)
    read = reads(**{G2: ghsa_json(G2)})  # names no CVE: no source ties it
    st = recompute.new_state()
    listed = kc(catalog("v1", CVE), "ok", st, 0)
    assert recompute.lead(e, CLAUDE, listed, RS, st, read)[1:] == ([G2], set())
    assert st["listed"] == {e.root_event_id: [CVE]}
    absent = kc(catalog("v2"), "ok", st, 3600)
    level, members, _ = recompute.lead(e, CLAUDE, absent, RS, st, read)
    assert level == "none" and members == [G2]
    assert recompute.outlived(e, CLAUDE, absent, RS, st, read)[0] == [(G2, "high")]
    fresh = recompute.new_state()
    assert recompute.lead(e, CLAUDE, kc(catalog("v2"), "ok", fresh, 0), RS, fresh, read) is None  # never seen listed


def test_a_member_past_the_lanes_share_is_read_in_a_later_turn():
    """Eleven members, ten reads: the members start one further on each turn, so the one
    that still supports high is read within eleven turns whichever place it holds."""
    from aitools_alerts.poster import recompute, sources
    from advisories import Api
    from test_advisory_recompute import CLAUDE, RS, thread
    others = [f"GHSA-aaaa-bbbb-cc{k:02d}" for k in range(10)]
    last = "GHSA-zzzz-zzzz-zzzz"
    e = thread(ids=(G, *others, last))
    answers = {G: ghsa_json(G, withdrawn_at=WHEN), last: ghsa_json(last),
               **{i: ghsa_json(i, withdrawn_at=WHEN) for i in others}}
    found = []
    for turn in range(11):
        reader = sources.Reader(Api(**answers))
        out, _ = recompute.outlived(e, CLAUDE, None, RS, recompute.new_state(), lambda i: reader.read(i, "rest"), turn)
        found.append(out == [(last, "high")])
    assert not found[0] and any(found)


def test_in_a_mixed_group_only_the_member_that_supports_more_leaves(env):
    """A lowers to a notice, B still supports high, C a notice. B leaves; C loses nothing
    by staying and stays, and the old thread stays unknown (ai-tools-alerts#759h)."""
    group(env, G, G2, G3)
    env.api.put(G, ghsa_json(G, **WEAK))
    env.api.put(G3, ghsa_json(G3, **WEAK))
    run(env, 1)
    assert len(roots(run(env, 2))) == 1
    old, new = entries(env)
    assert old["split"] == {"released": [G2], "kept": []} and sorted(old["aliases"]) == sorted([G, G3])
    assert new["aliases"] == [G2] and hours(env, 3, 40) == [] and entries(env)[0]["level"] == "high"


def test_a_member_takes_its_own_cve_and_leaves_the_first_ids(env):
    """Each advisory has a CVE. The member that leaves takes the one its own response
    names; the first id's CVE, which that id's response names, stays. A thread with a
    CVE is known only beside a complete KEV copy, so every run has one."""
    from test_main import FakeKEV
    from test_recompute import catalog

    def go(h):
        return run(env, h, kev=FakeKEV(catalog=catalog(f"v{h + 1}")))
    mine, theirs = "CVE-2026-0101", "CVE-2026-0202"
    env.api.put(G, ghsa_json(G, cve=mine))
    env.api.put(G2, ghsa_json(G2, cve=theirs))
    env.collector([finding(fid=G, severity="moderate", aliases=[mine]),
                   finding(fid=G2, severity="moderate", aliases=[theirs])])
    go(0)
    (e,) = entries(env)
    assert e["advisory"]["id"].upper() == G.upper() and len(e["aliases"]) == 4
    env.api.put(G, ghsa_json(G, cve=mine, withdrawn_at=WHEN))
    go(1)
    old = entries(env)[0]
    assert sorted(old["split"]["released"]) == sorted([G2, theirs]) and sorted(old["aliases"]) == sorted([G, mine])
    assert len(roots(go(2))) == 1
    assert sorted(entries(env)[1]["aliases"]) == sorted([G2, theirs])


# ---------------------------------------------------------------- from the delta review


def test_an_id_released_before_does_not_keep_a_later_member(env):
    """C and its CVE leave while B's advisory cannot be read. The root still names that
    CVE. When B reads again, its page assigns the same CVE: that is no id of the first
    advisory's, so B is not kept; it leaves too."""
    from test_main import FakeKEV
    from test_recompute import catalog
    shared = "CVE-2026-0303"

    def go(h):
        return run(env, h, kev=FakeKEV(catalog=catalog(f"v{h + 1}")))
    env.api.put(G, ghsa_json(G))
    env.api.put(G2, ghsa_json(G2, cve=shared))
    env.api.put(G3, ghsa_json(G3, cve=shared))
    env.collector([finding(fid=G, severity="moderate"), finding(fid=G2, severity="moderate", aliases=[shared]),
                   finding(fid=G3, severity="moderate", aliases=[shared])])
    go(0)
    (e,) = entries(env)
    assert e["advisory"]["id"].upper() == G.upper()
    env.api.put(G, ghsa_json(G, withdrawn_at=WHEN))
    env.api.put(G2, 503)
    go(1)
    old = entries(env)[0]
    assert sorted(old["split"]["released"]) == sorted([G3, shared]) and old["split"]["kept"] == []
    env.api.put(G2, ghsa_json(G2, cve=shared))
    go(2)
    old = entries(env)[0]
    assert sorted(old["split"]["released"]) == sorted([G2, G3, shared]) and old["split"]["kept"] == []
    assert old["aliases"] == [G]


def test_a_members_pages_stop_at_the_release_budget():
    """``part`` lowers the page cap while one member's evidence is read: a fetch past it
    is a spent budget, a page already read is not a fetch."""
    from types import SimpleNamespace
    from aitools_alerts.poster import rules
    fetched = []
    stub = SimpleNamespace(pages={f"u{n}": (200, "") for n in range(3)}, page_cap=4,
                           fetch_page=lambda url, allow, timeout: fetched.append(url) or (200, "x"))
    assert main.Run.page(stub, "u0", None) == (200, "") and fetched == []
    assert main.Run.page(stub, "new", None) == (200, "x") and fetched == ["new"]
    with pytest.raises(rules.PageBudget):
        main.Run.page(stub, "another", None)
    stub.page_cap = main.MAX_RUN_PAGES
    assert main.Run.page(stub, "another", None) == (200, "x")


def test_a_released_ids_candidate_keeps_only_a_kev_mark_of_its_own():
    from types import SimpleNamespace
    from aitools_alerts.poster import candidates
    stub = SimpleNamespace(released=lambda: {G2.casefold()})

    def cand(i, readings=()):
        return candidates.Candidate(id=i, aliases=(), product_text="Claude Code", advisory_severity=None,
                                    local_level_hint=None, exploited=True, trojanized=False, injection_exec=False,
                                    fixed=None, affected=None, sources=(), observed_at=None, readings=readings)
    assert main.Run._own_mark(stub, cand(G2)).exploited is False  # lent by the thread it left
    assert main.Run._own_mark(stub, cand(G2, (("kev", "{}"),))).exploited is True  # KEV's own word
    assert main.Run._own_mark(stub, cand(G)).exploited is True  # no released id: untouched
