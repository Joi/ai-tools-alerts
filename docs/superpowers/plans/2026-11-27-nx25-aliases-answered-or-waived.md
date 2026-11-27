# Plan: aliases beside a CVE first id cannot hold a thread unread (ai-tools-alerts#nx25)

Spec: `docs/superpowers/specs/2026-11-27-nx25-aliases-answered-or-waived-design.md` (as revised after its review).

Two files change behaviour: `aitools_alerts/verify.py` and `tests/test_verify.py`. One chunk of code, one of docs. Nothing in `cli.py`, `pull.py` or `spec/` changes.

## Chunk 1: the check (`aitools_alerts/verify.py`, `tests/test_verify.py`)

The steps are one change: the suite is green at the end of the chunk, not after each step (the version and `MAX_PAIRS` assertions move with the last one).

- [ ] Constants: `MAX_LISTED = 8`, `ALIAS_WAIT_S = 86400`, `_ANSWERS = ("record", "absent", "refused")`, `VERSION = 6`, `MAX_PAIRS = (MAX_LISTED + 1) * ruleset.MAX_PACKAGES`. `TooLarge(OSError)` in `__all__`.
- [ ] `_request`: raise `TooLarge` when a 200 states a `Content-Length` past the limit or sends more than the limit; a missing or malformed length stays `OSError`. `default_fetch` passes `TooLarge` through its worker thread; its message carries nothing of the response.
- [ ] `_Target`: `asked = isinstance(adv, Asked)`, in the key as `{"asked": True}` only when set (a post's key is unchanged in form); `listed`: the first `MAX_LISTED` aliases whose source is not `kev`, in thread order.
- [ ] Cache: `_empty` gains `tried` and `since`. `_shape_ok`: `tried` maps a lookup id (`norm_id(i) == i`) to `[time, None or one of _ANSWERS]`; `since` maps a CVE id to a time. Anything else is an empty cache.
- [ ] `_Run._get`: set `self.how` to `cut`, `none`, `record`, `absent` or `refused` as the spec's "What counts as an attempt" lists them; the return value is unchanged (None for everything that is not a usable 200 or a 304 to the ETag sent), so the first id's read and the catalog's read are untouched.
- [ ] `_Run.read`, for a GHSA or MAL id: a body the format or the ruleset refuses is `refused`; unless `cut`, store `tried[id] = [now, how]`, keeping the earlier answer when `how` is `none`.
- [ ] `_Run._aliases(t, records, known_cves) -> (complete, whole)`: the states, the deadline, the picks and the two results as the spec's sections "Three states", "The deadline", "The reads of one run" and "When the read is complete" say. `_Run.thread` calls it when the first id is a CVE and `not t.asked`; otherwise today's loop, whose result is both `complete` and `whole`. `self.stated["whole"]` takes `whole`; `t.judge` takes `complete`.
- [ ] `run`: prune `tried` to the live ids (the set `sources` is pruned to); keep `since[F]` only while a live state with first id `F` lists, among `t.listed`, an alias with no stored record and no `absent` answer.
- [ ] Docstrings of the module, `thread`, `read`, `_get`, `default_fetch` say the rule.

Tests (`tests/test_verify.py`, a section "nx25"), one per success criterion of the spec:

- [ ] four invented aliases: `unread`, then `contradicted`, `unsupported`, each alias requested once; one 404 alias: judged in the first run, `tried` holds `absent`, `whole` is false.
- [ ] a real alias among three invented ones, read first or last: `unread`, then `confirmed`.
- [ ] no answer (a timeout, 403, 429, 500, a redirect) at 0, 1 hour, 1 day, 5 days: `unread` each time; then `confirmed` once it answers, and `since` is dropped.
- [ ] three refused aliases (a body that does not parse, a 410, `TooLarge`, another advisory's body, an oversize body) and a real fourth: the fourth is requested in the second run; `unread` one second before the day; `confirmed` at the day.
- [ ] four refused aliases: `contradicted` at the day, not before.
- [ ] a tied alias whose read then fails (a timeout, a 404, a refused body, a 500): `unread` at 1 hour, 1 day, 3 days; `confirmed` when it reads again.
- [ ] eight tied aliases are all read in the judging run; one of them failing later gives `unread`.
- [ ] a ninth alias is never requested and holds nothing.
- [ ] a read the budget did not make leaves `tried` unchanged and waives nothing.
- [ ] a signed change (another level, one more alias) does not restart the deadline; a state without the alias, read beside the widest, does not drop `since`.
- [ ] a grouped thread (four advisories of other CVEs) is confirmed in the second run.
- [ ] an answered alias comes to tie a day later with three aliases tied.
- [ ] a lowering with four aliases, and with one 404 alias, is `unread` at 0, 1 hour, 1 day, 2 days, with a post of the same content read in the same runs, before and after it; `state_key` of the two differ; `verify.lowering` is None.
- [ ] a first id that answers 404 stays `unread`.
- [ ] `default_fetch` raises `TooLarge` for a declared length past the limit.
- [ ] existing tests updated: the cache's key set, the version (6, and 5 is an empty cache), wrong kinds in `tried` and `since`, and the four-tied-aliases test, which is now judged in its second run.

Verify: `python3 -m pytest -q tests/test_verify.py tests/test_verify_cli.py tests/test_verify_narrowing.py`, then `scripts/test-gate.sh`.

Acceptance: every listed test passes; no test outside `tests/test_verify.py` changes; `git diff --stat` shows no other source file.

## Chunk 2: docs

- [ ] `CHANGELOG.md`, top, under a new "Unreleased" heading: what a member sees, what an operator should know (cache version 6, rebuilt once; requests per thread), what stays open (the spec's open questions). Correct nothing in released entries.
- [ ] `README.md` line 143, the `unknown` result: a 404 for the alert's own id; an alias that answers 404 is an answer.

Verify: `scripts/public-scan.sh`.

## Review

One independent pass (gpt-6.1-sol) on snapshot ae0e972: two blockers, two substantive. All taken:

- [ ] The result key holds `listed`, in order, when a state has more than `MAX_LISTED` GHSA or MAL aliases: two states with one alias set and another first eight are two states. Test: both read in the same runs, one contradicted, one confirmed; under eight aliases the order changes no key.
- [ ] `tests/test_verify_narrowing.py`: the `MAX_PAIRS` assertion follows the constant (the one test outside `tests/test_verify.py` that changes; the acceptance line above is corrected by this).
- [ ] Test: a tied advisory with readable ranges and one refused alias; after the deadline the post is judged, `whole` is false, `narrowing` and `narrowing(whole=True)` are None.
- [ ] Test: `default_fetch` raises `TooLarge` for a chunked body that runs past the limit, as for a declared length.

## Code review

Whole branch at 9891088 (gpt-6.1-sol, and a same-model pass): two blockers. Steps added:

- [ ] `counted` in the cache: per CVE first id, at most `MAX_LISTED` aliases, filled in the thread's order when the check reads it, kept while a current thread lists them. `_Target.listed` and the `listed` part of the result key go: the selection no longer depends on a state's order. Tests: eight, then sixteen, aliases put in front of a counted one change nothing; an alias no current thread lists stops counting.
- [ ] `tried[id][1]` is what the last request met, `none` included. An alias is answered only while that is `absent` or a record; waived only while it is `refused`. Tests: a 404, then timeouts, is `unread`; a refused answer, then timeouts across the deadline, is `unread`.
- [ ] A tied alias another thread read in the same run counts as read (`memo`).
- [ ] The lowering test reads the post or the lowering alone first, with 404 and with refused aliases, past the deadline. `408` among the no-answer cases.

## Rollback

Revert the merge. A CLI before it reads a version 6 cache as empty and rebuilds its own.

## Landing

Merge `origin/main` before the code review and again before the merge. `scripts/test-gate.sh`; one independent review of `git diff origin/main...HEAD`; a pull request merged with the no-reply author address; close ai-tools-alerts#nx25 on the merge commit; a note for the release session on ai-tools-alerts#5fry.
