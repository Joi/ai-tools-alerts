# Plan: the member strike rule (ai-tools-alerts#cftg)

Spec: `docs/superpowers/specs/2026-11-28-cftg-member-strike-rule-design.md`. Two chunks, one pull request. Line numbers are of `main` at `3d376b8`.

Mandatory review lens for every pass: "the service runs with no human in the loop. Nothing you build may wait for a person to act."; "`tests/test_wire_compat.py` is untouched".

## Chunk 1: the record, the step, the two places it bites, tests

### 1.1 `aitools_alerts/state.py`

- [ ] Line 90-91: constants `MAX_STRIKES = 2`, `MAX_STRIKE_ROOTS = 64`.
- [ ] Before `_support_ok` (line 99): `no_probation()` returning `{"strikes": {}, "since": {}}`, and `_probation_ok(v, when, ident)`: exactly the keys `strikes` and `since`; `strikes` a dict of at most `MAX_UNVERIFIED_ENTRIES` 64-hex keys, each a list of 1 to `MAX_STRIKES` items `[time, [1 to MAX_STRIKE_ROOTS 64-hex roots]]`; `since` a dict of at most `MAX_UNVERIFIED_ENTRIES` 64-hex keys to times. A time is what `when` accepts (an int, not a bool, 0 to 2**53).
- [ ] `_load_unverified` (line 117): after the step that adds `supported` to a pre-0z4e record, add `probation` to a record that has `supported` and no `probation`; require the full key set; call `_probation_ok`. Document the key in the docstring.
- [ ] `State` (line 191): field `probation`, loaded in `load` (line 244), refreshed in `locked` (line 285), written in `save_unverified` (line 345).

### 1.2 `aitools_alerts/cli.py`: the step

- [ ] Constants beside `UNJUDGED_LINE` (line 56): `STRIKE_WINDOW_S = 7 * 86400`, `PROBATION_S = 30 * 86400`, `PROBATION_LINE`, `PROBATION_HELD_LINE` (texts in spec section 4).
- [ ] Before `_note_support` (line 493):
  - `_strikes(st, entries, supported, now) -> [(poster key, roots, time)]`. Empty while `st.reset_at is not None and st.reset_at > now - SUPPORT_GAP_S` (the guard of `_never`; `reset_at` is None on a record never rebuilt). For each entry with a judged state: the products for which every root of the entry has a memory entry with `last` None and `gone` set; none, no strike; else time = the least of those products' `gone` (per product the greatest over the roots, as `_memory`). Roots grouped by the pubkey of the stored root event; a root not stored is skipped.
  - `_probation_step(record, found, now) -> record` (pure), as spec section 2: cut times to `now`; drop strikes older than `STRIKE_WINDOW_S`; each found alert inside the window replaces every recorded strike of its key that shares a root with it, with its own roots (first `MAX_STRIKE_ROOTS`) and the least of the times; recorded strikes no found alert touches stay; per key keep the `MAX_STRIKES` latest, ordered by (time, sorted roots); a key with `MAX_STRIKES` strikes and no `since` entry younger than `PROBATION_S` gets `since[key]` = the latest strike's time; `since` entries that have run out are kept (1.4 removes them).
  - `_on_probation(st, key, now)`: `since[key]` exists and `min(at, now) > now - PROBATION_S`.
- [ ] `_note_support`: compute `now` once; after `_support_step`, `marks = _probation_step(st.probation, _strikes(st, entries, want, now), now)`; return False only when neither changed; under the lock compute both again from the record on disk and save; on `OSError` keep both computed values in memory. Runs only past the existing `a.judging` guards, so a CLI that verifies nothing records no strike.
- [ ] `_start_again` (line 759): also `st.probation = no_probation()`.

### 1.3 `aitools_alerts/cli.py`: raises

- [ ] `_interrupts` (line 1238): the unverified branch becomes `elif not rebuilt and not _on_probation(st, _poster(t, st), now) and take(...)`. The confirmed branch and the curator branch above it are not touched.
- [ ] `_reserve` (line 1246): new parameter `loose=frozenset()`. Under the lock, before the grants: every pending entry with a root in `loose` whose poster key is on probation in the reloaded record is denied (held, given a `State.held` time), and a grant for a denied root is skipped. The early return also requires that no pending entry is in `loose`.
- [ ] The three callers (`cmd_notify` line 1333, `cmd_run` lines 1397 and 1441) pass `loose`.
- [ ] `cmd_check` (line 1039): a held alert of a key on probation prints `PROBATION_HELD_LINE`; then one `PROBATION_LINE` per key on probation by the clock, sorted by key, with the end time in UTC.

### 1.4 `aitools_alerts/cli.py`: lowerings and narrowings

- [ ] `_note_offers` (line 620): inner `barred(t, reply)`: the reply is not None and the pubkey of the stored root event or of the stored reply event is a key of `st.probation["since"]` (the record, not the clock). Inner `over(now)`: the keys of `since` not on probation by this machine's clock whose end (`min(since, clock) + PROBATION_S`) the checkpoint time `now` is not before.
- [ ] In `step`: the lowering's time is set to the checkpoint's when `t.root_id in refused or (said is not True and barred(t, t.offered_by))`; the narrowing's when its existing condition holds `or (said is not True and barred(t, t.narrowed_by))`.
- [ ] The record is rewritten when `(want, refused)` differs from the stored pair, or when a checkpoint is held and `over(now)` is not empty. Under the lock, after `step` has run on the refreshed state and only when a checkpoint is held: remove the `over(now)` keys from `st.probation["since"]`; then save.
- [ ] The returned record leaves out every `offered_by` and `narrowed_by` that is `barred` (after the removal above).

### 1.5 Tests

- [ ] `tests/test_unchecked_lowering.py` line 169: the set of keys of a saved record gains `probation`.
- [ ] New `tests/test_probation_cli.py`, through `cli.main` unless noted:
  - acceptance 1: two fabricated alerts, the record, the third held in `run --json`, `run`, `notify`; the held line and the probation line; no slot taken. One fabricated alert: no probation, the next interrupts unverified.
  - acceptance 2: a confirmed alert interrupts in the run that reads its source. An alert that took a slot before the probation is held after.
  - acceptance 3: parametrized on one strike (the lowering applies after 72 hours) and two (it does not, the record's time follows the checkpoint, no waiting line, `lowering_waits` None, and it applies once the source confirms it). A lowering applied unchecked before the probation stops applying. A probation found by `run` shows the thread critical in the same run.
  - acceptance 4: the roots removed from the mirror and the store, the memory emptied, `verify.json` deleted, each asserted; the third still held; strikes gone after seven days and the probation standing; over after 30 days.
  - criterion 5, the four regressions: a copy changed after the strike; a second relay-bot key on probation lowering the first key's thread; `_reserve` after a concurrent probation (a new grant and an existing slot); the machine off from day 26 to day 31, with a command on day 31 that still holds the checkpoint of day 26 before the pull (both clocks in one era, so the checkpoint's time and the probation's end compare as they do in use).
  - narrowings: parametrized on one strike (the narrowing applies after 72 hours) and two (not applied, `narrowing_waits` false and no waiting line, the record's time follows the checkpoint, a stale checkpoint on day 31 changes nothing, the wait starts at the checkpoint of day 31 and the narrowing applies 72 hours later); a narrowing this machine confirms applies during probation.
  - what is no strike (above-source, unread, a curator's, `verify = "off"`); a stored probation acted on with the check off; stale unsupported alerts not struck again; a key that keeps fabricating; copies and two products are one strike; a supported product beside a never-supported one is a strike.
  - the record: a pre-cftg record loads; save and load; malformed shapes are damage; a rebuilt record loses the probation.
  - `_probation_step` directly: two strikes and the date; more than seven days apart; per key; found again; the split; a strike not found again stands; a run-out entry kept and replaced; the cap of two and of 64 roots; times ahead of the clock.

### Verification, chunk 1

```
python3 -m pytest -q tests/test_probation_cli.py tests/test_unverified_cli.py tests/test_never_supported_cli.py tests/test_unchecked_lowering.py tests/test_narrowing_cli.py tests/test_curator_hold_cli.py tests/test_cli.py
git diff --stat origin/main -- tests/test_wire_compat.py aitools_alerts/pull.py aitools_alerts/verify.py   # prints nothing
```

Mutation check, by hand, each restored after: remove the `_on_probation` test in `_interrupts` (acceptance 1 fails); remove `barred` from `step` (acceptance 3 fails); make `_probation_step` join roots instead of replacing (the copy regression fails); make `barred` read the clock (`_on_probation`) and not the record, and make `over` ignore the checkpoint's time (the day-31 regression fails each time); drop the denial in `_reserve` (the concurrency regression fails); remove `barred` from the narrowing's condition in `step`, and leave `narrowed_by` out of what the returned record omits (the narrowing test fails each time).

Acceptance: every test above passes; the three acceptance cases of the issue are among them.

## Chunk 2: docs

- [ ] `CHANGELOG.md`, top of "Unreleased": what changed for a member, the two limits (never read, two relay-bot keys), what an older CLI does with the new record.
- [ ] `README.md`, in the list at lines 154-167 after the line on the cap of two (line 160): the rule, what is held, what a lowering needs, how it ends; and in the paragraph on `unverified.json` (line 167): strikes and probations are kept there and go with a rebuilt record.
- [ ] A comment on ai-tools-alerts#5fry for the release session: nothing to install, sign or migrate beyond the release itself; a CLI older than this one that reads the newer record starts it again.

### Verification, chunk 2

`scripts/test-gate.sh` (the public scan, then the whole suite), after merging `origin/main`.

## Order, review, landing

1. Chunk 1, chunk 2, one commit each. Merge `origin/main`.
2. `scripts/test-gate.sh`.
3. One independent review of the whole branch (`git diff origin/main...HEAD`), with a same-model Stage 1 pass beside it; every BLOCKER fixed, every SUBSTANTIVE finding fixed or rebutted; one delta if a BLOCKER fix changed behaviour.
4. Merge `origin/main` again, gate again if it moved, pull request, `gh pr merge <n> --merge --author-email '19930+Joi@users.noreply.github.com'`, check `git log -1 --format=%ae origin/main`, close the issue on the merge commit with the close-out comment.

## Rollback

Revert the merge commit. A CLI without the change reads a record with `probation` as damaged and starts it again: the waits and the memory of support start over, on the safe side, with nobody's help.
