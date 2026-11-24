# Advisory Readers for the Poster: Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** The poster reads `api.github.com/advisories/<id>` and `api.osv.dev/v1/vulns/<id>` and judges open threads and new candidates by those reads, under ny5g's rules for lowering.

**Architecture:** One new module, `aitools_alerts/poster/sources.py`, wraps the member's own request and field builders (`aitools_alerts/verify.py`) behind a per-run budget. `recompute.support` and `judge` take a `read` function; `main.Run` owns the reader, orders the threads, and filters a candidate's readings by the same tie rule.

**Tech Stack:** Python 3 standard library; pytest. No new dependency.

**Spec:** `docs/superpowers/specs/2026-11-25-3qyq-advisory-readers-design.md`

## Global Constraints

- Nothing built may wait for a person to act.
- A timeout, 3xx, 403, 404, 429, 5xx, a parse error and a truncated or oversized body are `unknown`: no level changes, no wait starts, no wait gains time. A 404 is never a withdrawal.
- A lowering rests only on a reading whose class has `lowers` true.
- An id enters a URL only when `verify.norm_id(id) == id`. Hosts requested: `api.github.com`, `api.osv.dev`, nothing else.
- At most 30 advisory requests and 60 seconds a run: three lanes (`admit`, `wait`, `rest`) of 10 requests and 20 seconds each; one request at most 5 seconds.
- `aitools_alerts/verify.py`, `aitools_alerts/pull.py` and everything under `spec/` do not change (sibling sessions edit the first two; the third is inside the pinned digest).
- No host, tailnet, VM or home-path name and no personal email in any file or commit.
- Every commit is signed with the no-reply author.

## Review Focus

1. A GitHub response that is valid JSON of another shape (a list, an error object with `message`): `Reader.read` returns None, never raises. Test in Task 1.
2. A recompute state written before this change (every wait has a string `version`): loads unchanged, no wait restarts. Test in Task 2.
3. A thread whose first id is a GHSA and whose CVE alias the first read does not name: not known, nothing lowered. Test in Task 2.
4. A run in which `verify.default_fetch` raises for every request (the test suite's default, and a host with no network): every existing poster test still passes; no GHSA thread moves. Covered by the whole suite in Task 5.
5. The same GHSA id asked for by admission and by the recompute in one run: one request. Test in Task 1.

## Amendments after the plan's review

The review (fresheyes run 20261125-060607-9c8ff0) found seven BLOCKERs and two SUBSTANTIVE points. Where a task below disagrees with this section, this section is the plan.

1. **Order.** Task 4 (the candidate's reading) is built before Task 3's run-level tests: their helper posts a thread at high from the advisory's fields with a notice floor, which needs API-backed admission. The run-level tests are in one new file, `tests/poster/test_advisory_recompute.py`.
2. **Which first id.** `Run.one` filters a candidate's `ghsa` readings after the ledger lookup, by the thread's published id when there is a thread (`Run._tied(c, entry)`), else by the candidate's own. Test: `test_a_fix_groups_other_member_lends_no_level` sights the non-primary member again, alone.
3. **CVE aliases are tied too.** In `support`, a CVE beside an advisory first id counts, listed or absent, only when the first id's response names it; otherwise not known and nothing counted. Test: `test_a_ghsa_first_thread_whose_alias_the_first_read_does_not_name_is_unknown`.
4. **Types.** `sources.related` returns `(list, bool)`; `support` joins with `ids | set(named)`. Past `verify.MAX_ALIASES` named ids of any source the thread is not known, exactly as `verify._Run.thread` counts.
5. **`support` returns five values.** The two ny5g unit tests that compare its whole return keep their assertions; their helper `_support` takes the first four. That is the one edit to ny5g's test file.
6. **The failed read inside a wait.** Weakened at hours 1 to 20 holds 19 hours; a 429 at 21 pauses it; hour 22 adds nothing; the lowering is at hour 27. The test asserts `held` kept and `last` cleared.
7. **Existing tests that change**, in full: the spec's criterion 9 lists them. The poster tests' `env` gets `api = Api(default=plain)`, an advisory API that answers every GHSA id with a notice-level reviewed advisory, so no existing test meets the retry of an unread advisory by accident.
8. **The retry's bound.** A candidate is retried only while the state's `waiting` map holds its first sight; when the map is full and `saw` records none, there is no retry. Test: `test_with_no_first_sight_on_record_there_is_no_retry`.
9. **Coverage.** The run-level failure matrix has a duplicate-key body and another advisory's body, and runs each answer with no wait and inside one. The OSV test asserts a level that only OSV's entry supports, an unread entry, and a withdrawn one.
10. **Exploitation observed** is kept in the recompute state (`exploited`: a list of roots; `judge` adds, `Run.observe` prunes and saves), not in the ledger: `plan_known` reads the ledger's mark to decide whether "exploitation learned" earns a reply. `Ledger.mark_exploited` is not built.
11. **Found while building:** a recompute raise to critical on a feed-only thread posts no copy in the critical channel. Filed as ai-tools-alerts#3t4p; the spec says so under "Not in this slice".

---

### Task 1: The reader

**Files:**
- Create: `aitools_alerts/poster/sources.py`
- Test: `tests/poster/test_sources.py`, `tests/poster/advisories.py` (a fake API)

**Interfaces:**
- Produces:
  - `LANES = ("admit", "wait", "rest")`, `LANE_READS = 10`, `LANE_SECONDS = 20.0`, `TIMEOUT = 5.0`
  - `@dataclass(frozen=True) class Read`: `source: str`, `fields: dict` (the reading), `support: dict` (`{product: [level, lowers, stop_using]}`), `lowers: bool`, `names: tuple[str, ...]` (lookup ids the response names, `norm_id` form, sorted)
  - `class Reader(fetch=None, clock=time.monotonic, rs=None)`: `read(lookup_id: str, lane: str = "rest") -> Read | None`; `requests: int`; `unread: set[str]` (ids refused for a spent lane)
  - `advisory_id(i) -> str | None`: `i` when `verify.norm_id(i) == i` and its source is `ghsa` or `osv`, else None
  - `tied(first: str, i: str, read) -> bool`, `read` a function id → `Read | None` (see Task 2 for the rule)
  - `related(first: str, read) -> tuple[list[str], bool]`: the ids the first id's read names when `first` is an advisory id and that read may lower, and False when more than `verify.MAX_ALIASES` of them are advisory ids
  - `tests/poster/advisories.py`: `ghsa_json(ghsa_id, *, type="reviewed", cwes=("CWE-78",), packages=(("npm", "@anthropic-ai/claude-code", "< 2.1.0", "2.1.0"),), repo="anthropics/claude-code", cve=None, withdrawn_at=None, identifiers=())`, `osv_json(osv_id, *, packages=(("npm", "@anthropic-ai/claude-code"),), withdrawn=None, aliases=())`, and `class Api`: `put(lookup_id, obj_or_status)`, `__call__(url, etag, limit, timeout) -> (status, None, bytes)`, `calls: list[str]` (URLs); an id never put answers 404.

- [ ] **Step 1: Write `tests/poster/advisories.py` and the failing tests in `tests/poster/test_sources.py`**

Tests, each a function:
  - `test_a_good_read_is_the_members_reading`: `Reader(api).read(G).fields == verify._ghsa_reading(obj, G)[0]` and `ruleset.canonical` of both are equal; `support["Claude Code"] == ["high", True, False]`; `names` holds the CVE.
  - `test_every_failure_is_unknown` (parametrized: 302, 403, 404, 429, 500, 503, `OSError` from fetch, body `b"{"`, body with a duplicate key, body `b"[]"`, `{"message": "rate limit"}`, a response whose `ghsa_id` is another id, a body one byte over `verify.LIMITS["ghsa"]`, a status 200 with `body` not bytes, 51 identifiers): `read(G) is None`.
  - `test_an_id_that_is_not_a_lookup_id_makes_no_request`: `"ghsa-ABCD-efgh-ijkl"`, `"GHSA-abcd-efgh-ijkl/../x"`, `"CVE-2026-0001"`, `"PYSEC-2026-1"`, `"LEAD-1"`, `None` → None and `api.calls == []`.
  - `test_the_urls_are_the_two_fixed_prefixes`: after reading a GHSA and a `MAL-2026-1`, `api.calls == ["https://api.github.com/advisories/GHSA-abcd-efgh-ijkl", "https://api.osv.dev/v1/vulns/MAL-2026-1"]`.
  - `test_one_request_an_id_a_run`: two reads of one id (lanes `admit` then `rest`), and of a failing id: one call each.
  - `test_a_lane_spends_only_its_own_share`: 12 ids in `wait` → 10 calls, 2 None and in `unread`; then `rest` still reads 10.
  - `test_a_lane_stops_after_its_seconds`: a fake clock advanced 21 s by the first `wait` request → the second `wait` read makes no call; a `rest` read still does. The timeout passed to fetch is `min(5.0, what is left of the lane)`.
  - `test_default_fetch_is_looked_up_at_call_time`: `Reader()` with the suite's `no_source_requests` fixture → `read(G) is None`, no exception.

- [ ] **Step 2: Run them; expect import errors**

Run: `python3 -m pytest tests/poster/test_sources.py -q` — FAIL (no module `sources`).

- [ ] **Step 3: Implement `sources.py`**

`read`: memo first; `advisory_id`; lane budget (count and seconds from the lane's first request); `fetch(verify.url_of(i), None, verify.LIMITS[source], timeout)` inside `try/except Exception`; status 200 and `bytes` and within the limit; `verify._strict`; `verify._ghsa_reading` / `verify._osv_reading`; `verify._record(rs, source, [fields], named, None, 0)` gives `support`, `lowers`, `names`. Any exception is None. The default fetch is `lambda *a: verify.default_fetch(*a)`.

- [ ] **Step 4: Run; expect PASS.** `python3 -m pytest tests/poster/test_sources.py -q`

### Task 2: The recompute judges by advisory reads

**Files:**
- Modify: `aitools_alerts/poster/recompute.py` (`_ok`, `support`, `held`, `judge`, the module text)
- Test: `tests/poster/test_recompute.py` (unit tests beside `test_support_is_what_the_copy_states`)

**Interfaces:**
- Consumes: `sources.Read`, `sources.advisory_id`, `sources.tied`, `sources.related`
- Produces:
  - `support(entry, scope, copy, rs, read=None) -> tuple[str, bool, set, set, bool]`: `(found, known, listed, gone, stop)`. With `read=None` every advisory id is unread (ny5g's behaviour).
  - `held(entry, scope, found, rs, stop=False) -> str`
  - `judge(entry, scope, copy, rs, st, now, read=None, info=None)`: unchanged return; `info`, when a dict, receives `{"known": bool, "listed": set}`.
  - `judged(entry) -> bool`: the ledger marks it exploited, or one of its ids is an advisory id.
  - A wait record's `version` is `str | None`.

The rule, in order, inside `support`:

1. `ids = bare_ids(entry)`; None → `(NONE, False, set(), set(), False)` as today. `first` is the bare form of `entry.advisory["id"]`.
2. `extra, few = sources.related(first, read)`; `ids |= extra`; `known` false when not `few`.
3. KEV part over the CVE ids: ny5g's loop unchanged. `known` needs a complete copy only when there is a CVE id.
4. For each other id `i`: `r = read(i)` when `sources.advisory_id(i)`, else None. `r is None` or `not sources.tied(first, i, read)` → not known. `own = r.support.get(scope.name)`; `(own[1] if own else r.lowers)` false → not known, nothing counted. Else when `own`: `found = highest(found, own[0])`, and `stop` is whether a read at the final `found` has `own[2]`.
5. `tied(first, i, read)`: `first` a CVE → `read(i)` may lower and `first in read(i).names`; `first` an advisory id → `i == first`, or `read(first)` is a Read that may lower and names `i`; any other `first` → False.

`judge`: after `support`, `found = held(entry, scope, found, rs, stop)`. The pause condition is `not known or (entry.exploited and gone - seen)`. A new wait stores `copy.version if copy is not None else None`. Due when `held >= DWELL` and (`not entry.exploited` or the stored version is a string that the copy's version exceeds; a null stored version on an exploited thread starts the wait over). `_ok` accepts a null `version`.

- [ ] **Step 1: Write the failing unit tests**

  - `test_an_unread_advisory_id_is_unknown` (replaces `test_an_id_with_no_reader_makes_the_read_unknown`): a thread with a GHSA alias, `read` returning None → `known` False.
  - `test_a_tied_reviewed_read_counts_and_an_untied_one_does_not`: CVE-first thread with GHSA alias; a read naming the CVE → `found == "high"`, known; the same read without the CVE in `names` → `found == NONE`, not known.
  - `test_a_first_ghsa_names_what_else_is_read`: GHSA-first thread; first read names `MAL-2026-1` and a CVE; the MAL read supports high → counted; the CVE is looked up in the copy; with four named advisory ids → not known.
  - `test_a_ghsa_first_thread_whose_alias_the_first_read_does_not_name_is_unknown` (Review Focus 3).
  - `test_a_class_that_cannot_lower_makes_the_read_unknown`: type `unreviewed`, repository null, `withdrawn_at` set → not known, `found == NONE`; type `reviewed` withdrawn → known, `found == NONE`.
  - `test_stop_using_comes_from_the_read`: type `malware`, no patched version → `stop` True; `held(entry_at_notice_with_stop_action, scope, "critical", rs, True) == "critical"` and `== "high"` with `stop=False`.
  - `test_a_thread_never_marked_exploited_needs_no_kev_sighting`: `judge` over 25 hourly complete copies that never list its CVE, reads giving notice → `("due", "notice")` at hour 24; the same thread with `exploited=True` → None throughout.
  - `test_a_state_with_string_versions_still_loads` (Review Focus 2) and `test_a_null_version_loads`.

- [ ] **Step 2: Run; expect FAIL.** `python3 -m pytest tests/poster/test_recompute.py -q -k "unread or tied or names or class or stop_using or never_marked or versions or null_version"`
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run the whole file; expect PASS** (ny5g's tests included). `python3 -m pytest tests/poster/test_recompute.py -q`

### Task 3: The run reads, orders and marks

**Files:**
- Modify: `aitools_alerts/poster/ledger.py` (add `Ledger.mark_exploited(root_event_id) -> None`: sets `exploited` true and saves when it was false)
- Modify: `aitools_alerts/poster/main.py` (`Run.__init__(..., reader=None)`, `Run.observe`, `Run._judge`, `Run.recompute`, `run(..., advisory_fetch=None)`, the module text)
- Test: `tests/poster/test_recompute.py` (through `env.run(advisory_fetch=api)`), `tests/poster/test_ledger.py`

**Interfaces:**
- Consumes: Task 1 and Task 2.
- Produces: `main.run(..., advisory_fetch=None)`; `Run.api: sources.Reader`.

`Run._judge(entries, rs)`: an entry is taken when `recompute.judged(e)`, its scope resolves to its own name and it is not busy (else paused, as today). Lane: `"wait"` when its root has a wait in `rc["dwell"]`, else `"rest"`. Before `recompute.judge`, when the copy lists a CVE of the entry for this product and `not e.exploited`: `led.mark_exploited(root)` and the entry is read again from the ledger. `self.known` collects the roots whose `info["known"]` is true; `Run.recompute` passes `len(self.known & live)` to `recompute.select` in place of `len(self.judged)`.

`Run.observe` orders `entries`: those with a wait, then the rest; each group sorted by `root_event_id` and rotated left by `(now // 3600) % len(group)`. After judging, when `self.api.unread`: `_say(f"advisory reads: {len(self.api.unread)} id(s) not read this run (the lane's share was spent)")`.

- [ ] **Step 1: Write the failing tests** (helpers: `ghsa_thread(env, api, …)` posts a high thread from a finding whose API response is reviewed, CWE-78, patched)

  - `test_a_404_or_429_from_the_advisory_endpoint_lowers_nothing` (parametrized 302, 403, 404, 429, 503, `OSError`, bad JSON, oversize): the thread at high with floor notice; 30 hourly runs with that answer → no level reply, `state["dwell"] == {}`.
  - `test_a_failed_read_inside_a_wait_adds_no_time`: weakened for 20 hours, a 429 at hour 21, weakened on → lowered at hour 46, not 45 or earlier (ny5g's two-hour rule).
  - `test_a_reviewed_advisory_that_stops_supporting_high_lowers_once`: CWEs emptied from hour 1 → exactly one `{"level": "notice"}` in feed, at hour 25; the ledger entry is `lowered`.
  - `test_a_field_that_toggles_hourly_moves_nothing` and `test_a_field_that_toggles_every_two_days_sends_at_most_three_in_any_week` (acceptance; four weeks of hourly runs, every 7-day window ≤ 3).
  - `test_a_withdrawn_unreviewed_advisory_lowers_nothing` (48 hours) and `test_a_withdrawn_reviewed_advisory_lowers_to_notice_and_stays`.
  - `test_a_malware_advisory_withdrawn_and_published_again_returns_to_critical` (3a).
  - `test_a_kev_listing_that_changes_no_level_marks_the_thread_exploited` (3d): then the advisory weakens and an incomplete-then-absent KEV lowers nothing in 60 hours.
  - `test_failing_waits_do_not_starve_a_raise` (3e): 12 threads; ten hold waits and answer 404 from then on; an eleventh comes to support critical → raised within 12 hourly runs; every run makes ≤ 30 requests.
  - `test_a_named_mal_id_is_read_from_osv` (3f): `api.calls` holds the one `api.osv.dev` URL.
  - `test_the_breakers_share_is_of_the_threads_read_whole`: ny5g's share test unchanged, plus: five GHSA threads read whole and three due → not tripped only when three is at most 20% (so tripped here).
  - `test_mark_exploited_is_saved_once` in `test_ledger.py`.

- [ ] **Step 2: Run; expect FAIL.**
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run `tests/poster/test_recompute.py tests/poster/test_ledger.py`; expect PASS.**

### Task 4: The candidate's reading

**Files:**
- Modify: `aitools_alerts/poster/rules.py` (`readings_for(c, ev, read=None)`), `aitools_alerts/poster/main.py` (`Run.admit`, `Run.one`)
- Test: `tests/poster/test_rules.py`, `tests/poster/test_main.py`

**Interfaces:**
- Consumes: `Reader.read(id, "admit")`, `sources.tied`.
- Produces: `readings_for(c, ev, read=None)`: the `kev` readings as today; when `ev.structured and ev.ghsa` and `read("GHSA-" + ev.ghsa[5:].lower())` is a Read, `("ghsa", canonical text of its fields)`. No reading is built from the page.

`Run.admit`: passes `lambda i: self.api.read(i, "admit")`. When `ev.structured and ev.ghsa` and that read is None and the candidate is not synthetic: `self.saw(scope.name, c.id)`; while `self.now - self.first_seen(scope.name, [c.id]) < RETRY_DAYS * 86400`, `self.defer([(c, scope)])` with the candidate as it came in (not the admitted one) and `self.skipped["advisory api unread, tried again"] += 1`. The admitted candidate is returned as today.

`Run.one`, first thing after `ids`: `c = replace(c, readings=tuple(r for r in c.readings if r[0] != "ghsa" or sources.tied(first, json.loads(r[1])["ghsa_id"], lambda i: self.api.read(i, "admit"))))`, `first` the bare lookup form of `c.id` (CVE upper case, `GHSA-` then lower case; a thread key's slug dropped).

- [ ] **Step 1: Write the failing tests**

  - `test_rules.py`: `test_the_ghsa_reading_is_the_api_response` (fields equal `verify._ghsa_reading`'s, canonical bytes equal); `test_no_reading_without_a_read` (read None, and `read=None`); the three existing `readings_for` cases rewritten to these.
  - `test_main.py`: the two `admit` reading tests rewritten with `advisory_fetch`; `test_a_vendor_advisory_with_a_code_execution_cwe_posts_at_high_from_its_fields` (prose says nothing; ledger level high; `basis` is `fields`); `test_a_notice_held_while_the_api_failed_posts_when_it_answers` (3b: hour 0 a 429 → held, `deferred` holds it; hour 1 the API answers → a feed root, no new collector record; with the API failing for 8 days the deferred list is empty after day 7); `test_a_fix_groups_other_member_lends_no_level` (3c: then `verify.run` over the published advisory with the same `Api` gives no `contradicted`); `test_thirty_candidates_leave_the_threads_their_reads` (3e, second half).

- [ ] **Step 2: Run; expect FAIL.** - [ ] **Step 3: Implement.** - [ ] **Step 4: Run both files; expect PASS.**

### Task 5: Whole suite, changelog, commit

**Files:**
- Modify: `CHANGELOG.md` (one entry under the unreleased heading: what the poster now reads, the 30-request budget, what an operator sees on stderr, that rollback needs no state change), `README.md` only if it lists the hosts the poster contacts (`grep -n "cisa.gov" README.md docs/*.md`; add the two hosts where the KEV host is listed)

- [ ] **Step 1:** `python3 -m pytest -q` — every test passes. A ny5g test that fails is a defect in Tasks 2 to 4, not a test to edit, except the ones the spec's criterion 9 names.
- [ ] **Step 2:** `git diff --stat origin/main` — `verify.py`, `pull.py` and `spec/` are absent.
- [ ] **Step 3:** `grep -rn "api.github.com\|api.osv.dev" aitools_alerts/poster/` — no URL literal outside comments: the prefixes live in `verify.py` only.
- [ ] **Step 4:** Commit (signed, no-reply author): `poster: read GitHub and OSV advisories; judge threads and candidates by them (3qyq)`.
- [ ] **Step 5:** `scripts/test-gate.sh` in a clone holding this branch alone — exit 0.

**Acceptance for the chunk:** the spec's criteria 1 to 10. **Rollback:** revert the commit; no state file needs editing (a recompute state with a null `version` is replaced by an older poster, which only restarts waits).
