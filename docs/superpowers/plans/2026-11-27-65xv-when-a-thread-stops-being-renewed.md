# Plan: when a thread stops being renewed (ai-tools-alerts#65xv)

Spec: `docs/superpowers/specs/2026-11-27-65xv-when-a-thread-stops-being-renewed-design.md`. Three chunks, each committed with its tests. Tests first in each chunk: write them, see them fail for the stated reason, then the code.

Verification for every chunk: `python3 -m pytest -q <the files named>`; for the whole: `scripts/test-gate.sh` in a clone that holds this branch alone (the shared clone fails the public scan on other sessions' refs).

## Chunk 1: the signer lists a thread without its superseded renewals

`aitools_alerts/poster/signer.py`

- [ ] `_alone(ev, m) -> bool`, after `renewals_of`: `renewals_of(ev, m)` is not empty, `pull._patch(ev["content"]) is None`, and `pull._first_line(ev["content"])` does not start with `lang:`.
- [ ] `_tops(pairs) -> frozenset`: the pairs no other pair is at least equal to in both times.
- [ ] `slim(events, m) -> list`, after `_frontier`. `events` are one thread's (`window`'s `threads[key]`). No root among them (`pull._thread_ref(e) is None`): return them unchanged. `keep` = ids of `_frontier(replies, m)` plus the id of the thread's newest event (`max` by `(created_at, id)`). `kept` = events that are in `keep` or not `_alone`. Same length: return `events`. Else build `pull.threads_from(events, m)` and `pull.threads_from(kept, m)`; return `kept` only when both lists have the same length and, thread by thread, are equal once `renewals` is replaced by `_tops` of its `(confirmed_at, checked_at)` pairs. Any exception: return `events`.
- [ ] `window`'s must-list: `core = slim(threads[key], m)` in place of root, curator replies and frontier; the branch that adds the newest event of an old thread goes (slim keeps it).
- [ ] `window`, last loop: `take(sized(slim(threads[key], m)))`. Docstring: "Then whole threads" becomes the thread without the renewals another makes redundant.
- [ ] Module docstring: one sentence on what is listed of a thread; `__all__` gains `slim`.

`tests/poster/test_signer.py` (helpers there: `signing`, `on_mirror`, `Mirror.post`)

- [ ] `test_a_checkpoint_lists_a_thread_without_its_superseded_renewals`: bot root with a claim, a `lang: ja` reply, ten renewals a day apart (confirmed and checked at their date), then a level-only reply with a claim. `slim` returns root, Japanese reply, level reply, and no renewal the level reply's own date makes redundant; `ruleset.level_at` over `pull.threads_from(...)[0].renewals` is the same for both sets at days 0, 15, 30, 60, 120.
- [ ] `test_an_unconfirmed_renewal_and_a_confirmed_one_are_both_kept_when_neither_covers_the_other`: pairs (c0, k2) and (c1, k1) with c1 > c0, k2 > k1.
- [ ] `test_a_renewal_that_names_another_id_stands_for_nothing`: claimed critical root at day 0, a renewal confirmed and checked on day 7, and a bot reply whose claim names an id the thread never held: once with both times day 20, once with the day-7 times and the lower event id of the two. `slim` returns every event both times; the reader's level over them at day 20 is critical.
- [ ] `test_a_must_listed_thread_keeps_its_raise`: high root, a reply that raises it to critical, a later renewal, and an owed entry for the thread; `pull.threads_from` over the events `window` lists gives critical. The gtw9 test of a must-listed thread that does not fit whole is rewritten to the new rule: what must be listed is the slim thread, and when that does not fit `window` returns None.
- [ ] `test_the_newest_event_of_a_thread_is_always_listed`: an unclaimed root at day 0, a renewal alone dated day 399 with times (0, 0), a bot reply dated day 1 with times (1, 1). `slim` keeps the day-399 event; `pull._retain` of the kept events at day 401 keeps the thread.
- [ ] `test_a_thread_without_its_root_is_listed_as_it_is`.
- [ ] `test_four_hundred_renewed_threads_fit_one_checkpoint`: 400 claimed roots each with 12 renewals (5,200 events); `window` lists exactly 800 ids: every root and the newest renewal of each.

Acceptance: those pass; `tests/poster/test_signer.py` and `tests/poster/test_renew.py` pass unchanged otherwise.

## Chunk 2: a thread ends; raises on an ended or unconfirmed thread

`aitools_alerts/poster/ledger.py`

- [ ] `Entry.ended: str | None = None`, with its comment. `_entry_ok`: `"ended" not in e or (e["ended"] in schema.LEVELS and "claim" in e)`.
- [ ] `Ledger.end(root_event_id, level) -> Entry`: sets `ended` when absent and saves; `LedgerError` for a level that is none, or an entry with no claim.
- [ ] `record_reply`: in the `adv.level != e["level"]` branch, a change that is not a lowering removes `ended`.

`aitools_alerts/poster/recompute.py`

- [ ] `_rises(entry, found, rs) -> bool`: `found` ranks above `entry.level` and, when `entry.ended` is set, above it. `raised` and `judge` use it where they compare `found` with `entry.level` for a raise. In `judge` an ended entry whose sources state more than its level then reaches `rs.rank(level) >= rs.rank(entry.level)`: the wait is dropped, None returned. Module docstring: one line.

`aitools_alerts/poster/compose.py`

- [ ] `AGED = "This alert is {days} days old and is no longer renewed."` beside `UNCONFIRMED`.

`aitools_alerts/poster/main.py`

- [ ] `RENEW_DAYS = 90` with its comment, beside `STEP_EARLY`.
- [ ] `Run._may_rise(c, scope, entry, level) -> bool`: False when `entry.ended` is set and `level` does not rank above it. Else True unless the standing claim parses, `now - confirmed_at >= ruleset.UNCONFIRMED_DAYS * 86400 - STEP_EARLY` and `self._confirming(entry, old)[0]` is false; then True only when `self._parsed(self._claim(rules._readings(c), entry.root_ids or [], scope.name))` is a claim whose level ranks at least `level`.
- [ ] `plan_known`: `if RANK[level] <= RANK[entry.level] or not self._may_rise(c, scope, entry, level)`: the level stays.
- [ ] `_clears`: rate once, and require `_may_rise` before `yields`, so a raise that will not be planned supersedes nothing.
- [ ] `_renew`: per entry, before `_confirming`: `ended = e.ended is not None`; when not ended, `now - max([e.posted_at, *(e.changed or ())]) >= RENEW_DAYS * 86400` and not `self.busy(e.aliases, e.scope)`: `e = self.led.end(e.root_event_id, e.level)`, ended. `life` is computed first. For an ended entry `forced` is `lost is not None and old["confirmed_at"] < lost and life >= self.now` (for any other it stays `old["checked_at"] < lost`); `fresh, text = self._confirming(e, old) if forced else (False, None)`; `best` is `life` unless `fresh`. An ended, forced entry that is not `fresh` is passed to `lapsing(life, e, anyway=True)` at once, before the step test (a notice in its last day leaves that test by `continue`). The step test itself is unchanged. The due test becomes `forced or (not ended and (...))`, and an ended entry's due text is `text` when `fresh`, else None; an ended entry is appended to `due` only when `fresh`.
- [ ] `_step_down(e, old)`: for an ended entry the reason is `compose.AGED` with the whole days since `e.posted_at`, and the stderr line says so.
- [ ] Module docstring and `renew`'s: the ending rule in two sentences.

`tests/poster/test_ledger.py`, `tests/poster/test_renew.py`, `tests/poster/test_advisory_recompute.py` (helpers: `post`, `entries`, `day`, `renewals`, `steps`, `critical`)

- [ ] ledger: `end` writes once and keeps the first level; a non-level `ended`, and `ended` without `claim`, are malformed; a recorded raise removes it, a recorded lowering keeps it.
- [ ] `test_a_confirmed_high_is_renewed_for_90_days_then_runs_down`: `post(env)`; daily runs to day 220. Renewals on days 15, 30, 45, 60 and 75 and none after (the thread ends on day 90, before that day's renewal is chosen); `ended == "high"` from day 90; one step, to notice, on day 104 (29 days after the day-75 renewal) with the line `Level is now notice. This alert is 104 days old and is no longer renewed.`; the advisory still answers high throughout and no reply raises it; ledger level notice at the end.
- [ ] `test_a_critical_ends_through_high_to_notice`: `critical(env)`; steps on two days, critical to high then high to notice 29 days later, both channels.
- [ ] `test_an_ended_thread_is_raised_only_above_the_level_it_ended_at`: the high above, ended and at notice; a collector finding for the same id raises nothing; then KEV lists its CVE with the root's fix known: raised to critical, `ended` gone, renewed again seven days later.
- [ ] `test_a_thread_with_work_in_flight_ends_on_a_later_run`.
- [ ] `test_a_candidate_does_not_pass_over_an_ended_threads_unsent_step`: an ended critical; the step's send takes the critical channel and fails in feed (`FakeRelay("ok", "fail")`); the next run has a collector finding that rates critical: the feed reply is sent in that run and the thread is not raised.
- [ ] `test_after_a_lost_checkpoint_state_an_ended_thread_is_renewed_once_confirmed_now` (on `signing`): ended notice inside its life; `owed_state` unlinked; a run whose advisory read fails sends no renewal and passes the thread's roots in `suppress`; the next, whose read confirms, sends one renewal with `confirmed_at == checked_at == now`; the run after sends none. An ended thread past its life gets nothing.
- [ ] `test_a_thread_whose_root_carries_no_claim_never_ends` (extends the existing unclaimed test's setup).
- [ ] `test_a_candidate_with_prose_alone_does_not_raise_a_thread_stepped_down_unconfirmed`, and `..._with_fields_that_state_the_level_does`.
- [ ] recompute unit: `judge` and `raised` on an entry with `ended="high"`, level notice: a source stating high gives no raise and leaves no wait; one stating critical raises.

Acceptance: those pass, and `python3 -m pytest -q tests/poster` passes.

## Chunk 3: the simulated year, the wire rules, the changelog

`tests/poster/test_end_to_end.py`

- [ ] `test_a_year_of_one_new_high_a_day_stays_inside_every_cap`, on `world`. `nostr.verify_event` is memoised for the test (the exporter verifies every row at every export). For day 0 to 365: a new reviewed advisory with its own GHSA id (API answer and collector finding), one poster run, the exporter five minutes later, a pull by the member that has pulled since day 0. The fixture's certificate lasts 90 days: the test writes `w.cert_file` anew every 60 days (`cp.build_cert`, issued then, 90 days). Each day: the poster's summary has the field `checkpoint=sent` (` renewed=N` follows it in a run that renewed); the export says the checkpoint is published; `feed.json` and `critical.json` are each at most 2,000 events and 4 MiB; the published checkpoint lists at most 990 events; the member's pull has no error. On the last day, for the daily member and for one pulling for the first time: `pull.unverified` is None; for every ledger entry that is not past its life (level above notice, or stepped to notice under 90 days ago) `pull.active(pull.advisories(st), *pull.head_clock(st))` holds its root at the ledger's level or higher; the daily member stores fewer than 20,000 events. If one run a day costs more than about two minutes, the loop runs the poster daily and the exporter and member every seventh day and on the last.

`spec/wire.md`

- [ ] "The claim": after "The step down", a paragraph "**The end of a thread.**" with the 90 days, what the clock counts from, the line, the run-down and the raise that reopens it; in the renewal paragraph, "for 90 days after the thread's level last changed".
- [ ] The paragraph on what the poster's checkpoint lists: it lists a thread's root, its replies that are not renewals alone and the renewals no other makes redundant; a reader of them shows what a reader of every event shows.
- [ ] "How this reader computes expiry" is not changed: nothing a reader does differs.

`CHANGELOG.md`, `README.md`

- [ ] Changelog entry under the unreleased heading, in the file's form. README only where it states that an alert is renewed for good (grep `renew`).

Acceptance: `scripts/test-gate.sh` exit 0 in a clone of the branch alone.

## After the chunks

- Merge `origin/main`, whole-branch fresheyes pass (`git diff origin/main...HEAD`), fix or rebut, the gate again, close-out comment, pull request, merge with the no-reply author email, check `git log -1 --format=%ae origin/main`, close on the merge commit.
- Comment on ai-tools-alerts#5fry: the poster needs this code; no exporter or reader step.
- Follow-up issue: the poster judges every ledger thread for good.

## Rollback

Revert the merge commit before any thread has ended (90 days after the first claimed root). After that a ledger holds `ended` and the earlier code refuses it: roll forward.
