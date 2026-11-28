"""The poster's advisory reader (ai-tools-alerts#3qyq): one good read is the member's
reading; every failure is unknown; no id reaches a URL unless a lookup writes it so."""

import os

import pytest

from aitools_alerts import ruleset, verify
from aitools_alerts.poster import sources

from advisories import GH, OSV, Api, ghsa_json, osv_json

G, G2, CVE, MAL = "GHSA-abcd-efgh-ijkl", "GHSA-mnop-qrst-uvwx", "CVE-2026-0001", "MAL-2026-1"


def test_a_good_read_is_the_members_reading():
    obj = ghsa_json(G, cve=CVE)
    r = sources.Reader(Api(**{G: obj})).read(G)
    fields, named = verify._ghsa_reading(obj, G)
    assert r.fields == fields and ruleset.canonical(r.fields) == ruleset.canonical(fields)
    assert r.source == "ghsa" and r.support["Claude Code"] == ["high", True, False] and r.lowers
    assert r.names == (CVE, G) and r.fields["repository"] == "anthropics/claude-code"
    o = sources.Reader(Api(**{MAL: osv_json(MAL, aliases=[G])})).read(MAL)
    assert o.source == "osv" and o.support["Claude Code"][:2] == ["high", True] and o.names == (G,)


@pytest.mark.parametrize("answer", [
    302, 403, 404, 429, 500, 503, OSError("timed out"), b"{", b'{"ghsa_id": "x", "ghsa_id": "GHSA-abcd-efgh-ijkl"}',
    b"[]", {"message": "API rate limit exceeded"}, ghsa_json(G2), ghsa_json(G, type="strange"),
    ghsa_json(G, identifiers=[f"CVE-2026-{n:04d}" for n in range(60)]),
    b" " * (verify.LIMITS["ghsa"] + 1), ghsa_json(G, packages=[("npm", "café", None, None)]),
    {**ghsa_json(G), "repository_advisory_url": "https://example.com/x"}], ids=lambda a: str(a)[:24])
def test_every_failure_is_unknown(answer):
    api = Api(**{G: answer})
    reader = sources.Reader(api)
    assert reader.read(G) is None and len(api.calls) == 1


def test_a_200_whose_body_is_not_bytes_is_unknown():
    assert sources.Reader(lambda *a: (200, None, "{}")).read(G) is None
    assert sources.Reader(lambda *a: None).read(G) is None


@pytest.mark.parametrize("bad", ["ghsa-ABCD-efgh-ijkl", "GHSA-ABCD-EFGH-IJKL", "GHSA-abcd-efgh-ijkl/../x", CVE,
                                 "PYSEC-2026-1", "LEAD-1", "GHSA-abcd-efgh-ijkl:claude-code", "", None, 7])
def test_an_id_that_is_not_a_lookup_id_makes_no_request(bad):
    api = Api()
    assert sources.Reader(api).read(bad) is None and api.calls == []
    assert sources.advisory_id(bad) is None


def test_the_urls_are_the_two_fixed_prefixes():
    api = Api(**{G: ghsa_json(G), MAL: osv_json(MAL)})
    reader = sources.Reader(api)
    assert reader.read(G) and reader.read(MAL)
    assert api.calls == [GH + G, OSV + MAL] and GH == verify._GHSA_URL and OSV == verify._OSV_URL


def test_one_request_an_id_a_run():
    api = Api(**{G: ghsa_json(G)})
    reader = sources.Reader(api)
    assert reader.read(G, "admit") is reader.read(G, "rest") and reader.read(G2, "wait") is None
    assert reader.read(G2, "rest") is None and api.calls == [GH + G, GH + G2] and reader.requests == 2


def test_a_lane_spends_only_its_own_share():
    api = Api()
    reader = sources.Reader(api, clock=lambda: 0.0)
    ids = [f"GHSA-aaaa-bbbb-cc{n:02d}" for n in range(12)]
    assert [reader.read(i, "wait") for i in ids] == [None] * 12
    assert len(api.calls) == sources.LANE_READS == 10 and reader.unread == set(ids[10:])
    more = [f"GHSA-aaaa-bbbb-dd{n:02d}" for n in range(10)]
    assert [reader.read(i, "rest") for i in more + ids[10:11]] == [None] * 11 and len(api.calls) == 20
    assert reader.read(ids[10], "admit") is None and len(api.calls) == 21 and reader.unread == {ids[11]}
    assert reader.read(G, "elsewhere") is None and len(api.calls) == 21


def test_a_lane_stops_after_its_seconds():
    now = [0.0]
    api = Api()

    def fetch(*a):
        now[0] += 21.0 if len(api.calls) == 0 else 8.0
        return api(*a)
    reader = sources.Reader(fetch, clock=lambda: now[0])
    assert reader.read(G, "wait") is None and reader.read(G2, "wait") is None and len(api.calls) == 1
    assert reader.unread == {G2}
    a, b = "GHSA-aaaa-bbbb-cc01", "GHSA-aaaa-bbbb-cc02"
    reader.read(a, "rest")
    now[0] += 500.0  # a slow vendor page between two reads is not the lane's time
    reader.read(b, "rest")
    assert api.timeouts == [5.0, 5.0, 5.0] and len(api.calls) == 3
    reader.read("GHSA-aaaa-bbbb-cc03", "rest")  # 16 of the lane's 20 seconds were spent in its two requests
    assert api.timeouts[-1] == 4.0
    assert reader.read("GHSA-aaaa-bbbb-cc04", "rest") is None and len(api.calls) == 4  # 24: spent


def test_default_fetch_is_looked_up_at_call_time():
    assert sources.Reader().read(G) is None  # the suite's own refusal (conftest): no request, no exception


def test_tied_is_the_sources_word_about_the_ids_a_member_reads():
    reads = {G: sources.Reader(Api(**{G: ghsa_json(G, cve=CVE, identifiers=[MAL])})).read(G),
             G2: sources.Reader(Api(**{G2: ghsa_json(G2, type="unreviewed", repo=None, cve=CVE)})).read(G2)}
    assert sources.tied(CVE, G, reads.get, [G]) and not sources.tied("CVE-2026-0002", G, reads.get, [G])
    assert not sources.tied(CVE, G, reads.get)  # not among the thread's published aliases: a member never reads it
    assert not sources.tied(CVE, G2, reads.get, [G2])  # an unreviewed advisory ties nothing
    assert sources.tied(G, G, reads.get) and sources.tied(G, MAL, reads.get) and not sources.tied(G, G2, reads.get)
    assert sources.tied(G, CVE, reads.get)  # the first id's response names the CVE: KEV is read for it
    assert not sources.tied(G2, MAL, reads.get) and not sources.tied(None, G, reads.get)
    assert not sources.tied(CVE, CVE, reads.get) and not sources.tied(G, None, reads.get)
    assert sources.chosen(G, [], reads.get) == ([CVE, MAL], True) and sources.chosen(G2, [], reads.get) == ([], True)
    assert sources.chosen(G, [], lambda i: None) == ([], True) and sources.chosen("LEAD-1", [G], reads.get) == ([], True)
    assert sources.chosen(CVE, [G, "CVE-2026-0002", G, G2], reads.get) == ([G, G2], True)


def test_only_the_ids_a_member_reads_are_chosen():
    """A member's check reads three ids beside the first (verify.MAX_ALIASES), in its own
    order. The poster counts no other: a fourth could support a level no member confirms."""
    four = [f"MAL-2026-{n}" for n in range(4)]
    many = sources.Reader(Api(**{G: ghsa_json(G, identifiers=four)})).read(G)
    assert sources.chosen(G, [], {G: many}.get) == (four[:3], False)
    assert sources.tied(G, four[2], {G: many}.get) and not sources.tied(G, four[3], {G: many}.get)
    aliases = [f"GHSA-aaaa-bbbb-cc{n:02d}" for n in range(4)]
    assert sources.chosen(CVE, aliases, lambda i: None) == ([], False)  # which three is each member's own matter
    assert sources.chosen(CVE, aliases[:3], lambda i: None) == (aliases[:3], True)
    last = sources.Reader(Api(**{aliases[3]: ghsa_json(aliases[3], cve=CVE)})).read(aliases[3])
    assert last.lowers and CVE in last.names and not sources.tied(CVE, aliases[3], {aliases[3]: last}.get, aliases)
    assert verify.MAX_ALIASES == 3


# ---------------------------------------------------------------- the admit lane's turn (vszx)


def _ids(n):
    return [f"GHSA-aaaa-bbbb-{k:04d}" for k in range(n)]


def test_in_turn_is_every_distinct_id_once_whatever_order_they_came_in():
    ids = _ids(13)
    for seen in ((), ids, ids[::2], ["GHSA-zzzz-zzzz-zzzz"]):
        for after in (None, 7, "", ids[0], ids[5], ids[-1], "GHSA-aaaa-bbbb-0005x", "zzzz", "CVE-2026-0001"):
            got = sources.in_turn(ids, after, seen)
            assert sorted(got) == ids and got == sources.in_turn([*reversed(ids), *ids[:5]], after, seen)
    assert sources.in_turn([], ids[3], ids) == [] and sources.in_turn(iter(ids[:1]), ids[0], ids) == ids[:1]


def test_the_ring_goes_on_past_the_last_id_asked_for():
    ids = _ids(6)
    assert sources.in_turn(ids, None, ids) == ids and sources.in_turn(ids, ids[-1], ids) == ids  # round again
    assert sources.in_turn(ids, ids[1], ids) == ids[2:] + ids[:2]
    # the id it stopped at is gone, or others have come: the place is kept by the id's own order
    assert sources.in_turn(ids[:3] + ids[4:], ids[3], ids) == ids[4:] + ids[:3]
    assert sources.in_turn(ids, "GHSA-aaaa-bbbb-0002x", ids) == ids[3:] + ids[:3]


def test_an_id_never_asked_for_is_ahead_of_the_ring():
    ids = _ids(6)
    assert sources.in_turn(ids) == ids  # nothing asked for yet: all are new, in their order
    assert sources.in_turn(ids, ids[3], [ids[0], ids[2], ids[3], ids[4]]) == [ids[1], ids[5], ids[4], ids[0], ids[2], ids[3]]


def _rounds(n, made, arrive=lambda run: ()):
    """The ids asked for run by run when each run makes ``made(run)`` requests, with
    the bookkeeping ``main.Run.admit_all`` does. ``arrive(run)``: ids that join then."""
    ids, after, seen, out = _ids(n), None, set(), []
    for run in range(4 * n + 8):
        ids = sorted({*ids, *arrive(run)})
        asked = sources.in_turn(ids, after, seen)[:made(run)]
        ring = [i for i in asked if i in seen]
        after = ring[-1] if ring else after
        seen = seen | set(asked)
        out.append(asked)
    return ids, out


@pytest.mark.parametrize("n", range(1, 46))
def test_any_run_of_hours_that_could_hold_them_asks_for_every_id(n):
    """Acceptance (vszx): with n ids and ten requests a run, every id is asked for in
    any ceil(n / 10) consecutive runs, from whichever run, the first run included."""
    share = sources.LANE_READS
    ids, runs = _rounds(n, lambda run: share)
    need = -(-n // share)
    for start in range(len(runs) - need):
        assert {i for asked in runs[start:start + need] for i in asked} == set(ids), (n, start)


@pytest.mark.parametrize("n", (1, 7, 10, 20, 34))
def test_runs_that_make_fewer_requests_lose_no_id(n):
    """A slow API ends the lane's seconds before its ten requests, some runs make
    none at all, and a run that is missed makes none either: the next one goes on
    where the last request was made. Every id is asked for once before any is asked
    for twice. A turn counted by the clock left ten of twenty unread for good when
    only every other hour ran."""
    ids, runs = _rounds(n, lambda run: (4, 0, 10, 1, 0, 0, 7)[run % 7])
    flat = [i for asked in runs for i in asked]
    for k in range(0, len(flat) - n, n):
        assert sorted(flat[k:k + n]) == ids, (n, k)


def test_a_new_id_is_asked_for_in_its_first_run_and_costs_the_ring_one_request():
    new = {9: ["GHSA-aaaa-bbbb-0000a"], 10: ["GHSA-zzzz-zzzz-zzzz", "GHSA-aaaa-bbbb-0020a"]}
    ids, runs = _rounds(34, lambda run: sources.LANE_READS, lambda run: new.get(run, ()))
    assert runs[9][0] == new[9][0] and runs[10][:2] == sorted(new[10])
    assert len(runs[9]) == 10 and runs[10][2] not in new[9]  # asked once ahead, then it is in the ring
    for start in range(11, len(runs) - 4):
        assert {i for asked in runs[start:start + 4] for i in asked} == set(ids)  # 37 now: four runs still hold them


def test_the_turn_is_kept_in_a_file_of_its_own(tmp_path):
    path = tmp_path / "state" / "ledger.json.admit-turn.json"
    none = (None, frozenset())
    assert sources.load_turn(path) == none
    sources.save_turn(path, G, {G, G2})
    assert sources.load_turn(path) == (G, frozenset({G, G2}))
    sources.save_turn(path, None, [G2])
    assert sources.load_turn(path) == (None, frozenset({G2}))
    for bad in ("{", "[]", '{"after": 7, "seen": []}', '{"after": "GHSA-ABCD-efgh-ijkl", "seen": []}',
                '{"after": "CVE-2026-0001", "seen": []}', '{"after": "%s"}' % G, '{"after": "../x", "seen": []}',
                '{"after": null, "seen": ["%s", "../x"]}' % G, '{"after": null, "seen": "%s"}' % G,
                '{"after": null, "seen": [], "more": 1}', '{"after": null, "seen": [], "seen": []}',
                '{"after": null, "seen": [%s]}' % ", ".join(['"%s"' % G] * (sources.MAX_SEEN + 1)),
                '{"after": null, "seen": ["' + "x" * (1 << 18) + '"]}'):
        path.write_text(bad)
        assert sources.load_turn(path) == none, bad[:60]  # the turn starts over: never an error
    path.unlink()
    path.mkdir()
    assert sources.load_turn(path) == none
    path.rmdir()
    os.mkfifo(path)  # no writer: a blocking open would hold the run, and the ledger lock, for good
    assert sources.load_turn(path) == none


def test_what_is_remembered_is_capped_in_favour_of_this_runs_candidates(monkeypatch):
    ids = _ids(9)
    assert sources.remembered(reversed(ids), ids[:2]) == ids  # all of them while they fit
    monkeypatch.setattr(sources, "MAX_SEEN", 5)
    assert sources.remembered(ids, [ids[8], ids[6], "GHSA-zzzz-zzzz-zzzz"]) == [*ids[:3], ids[6], ids[8]]
