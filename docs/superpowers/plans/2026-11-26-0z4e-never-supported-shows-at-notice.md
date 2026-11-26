# Plan: an alert the member's source never supported shows at notice (ai-tools-alerts#0z4e)

Spec: `docs/superpowers/specs/2026-11-26-0z4e-never-supported-shows-at-notice-design.md` (as revised after its review). Four chunks, in order; each ends with its tests passing. Expected size: about 200 lines of code, 350 of tests, the rest documents. One pull request.

Run every command from the repo root. Tests: `python3 -m pytest -q <file>`; the whole gate is `scripts/test-gate.sh` (the public scan, then the suite), run in a clone that holds this branch alone.

## Chunk 1: an incomplete read reports the support it read (`aitools_alerts/verify.py`)

- [ ] `judge` (line 320): the `not complete` return gives `source` the level `s` when it is above `none`, else None. The result stays `unknown`, `unread`. The docstring says the level is a lower bound.
- [ ] `VERSION` (line 57) goes to 4. The module's `lowering` and every other reader of a result decide by `why`, not by `source`, for `unread` (checked: `lowering` returns None unless every `why` is in its accepted set; `_settled`, `_waits` read `why` only).
- [ ] Tests: `tests/test_verify.py::test_judge`, the row for an incomplete read beside `high` support, expects `("unknown", "unread", "high")`; a new row: incomplete with nothing supported is still `None`.
- Verify: `python3 -m pytest -q tests/test_verify.py tests/test_verify_cli.py tests/test_unverified_cli.py tests/test_curator_hold_cli.py`.
- Acceptance: only the one named row of an existing test changed.

## Chunk 2: the record (`aitools_alerts/state.py`)

- [ ] `_UNVERIFIED_KEYS` (line 88): add `"supported"`. `_load_unverified` (line 91): accept a record whose keys are the old five (then `supported` is the empty value) or all six. Shape of `supported`: a dict with exactly `ruleset` (None or 64 lowercase hex) and `threads`; `threads` a dict of at most `MAX_UNVERIFIED_ENTRIES` entries, each key an event id, each value a dict of at most `MAX_UNVERIFIED_ENTRIES` entries whose keys are strings of 1 to 200 characters and whose values are lists of exactly three `[last, gone, seen]`, each None or a time (`when`), with `last` or `gone` set, `seen` set exactly when `gone` is, and `seen >= gone`. The default for a missing file gains the empty value `{"ruleset": None, "threads": {}}`. The docstring says what the key holds.
- [ ] `State` (line 158): field `supported: dict` (default the empty value); `load` passes it; `locked` re-reads it; `save_unverified` writes it.
- [ ] The module docstring's sentence about `unverified.json` names the memory.
- [ ] Tests, new file `tests/test_never_supported_cli.py`, first part:
  - a record without `supported` loads as not damaged, with the other five keys intact, and the empty value;
  - a saved record with `supported` loads back equal;
  - each malformed `supported` (a list, a missing `ruleset`, a digest of 63 characters, a non-id root, a value of two, `[None, None, None]`, `gone` without `seen`, `seen` before `gone`, a negative time, an empty name, a name of 201 characters) is damage (`unverified_damaged`).
  - `tests/test_unchecked_lowering.py::test_a_damaged_record_is_flagged_and_never_an_error`: the expected key set gains `supported`.
- Verify: `python3 -m pytest -q tests/test_never_supported_cli.py tests/test_unchecked_lowering.py tests/test_unverified_cli.py`.

## Chunk 3: the CLI (`aitools_alerts/cli.py`)

- [ ] Constants beside `MAX_UNVERIFIED` (line 50): `SUPPORT_GAP_S = verify.FRESH_S`; `LOST_LINE = "source check: the source has not supported {id} for {name} for more than 48 hours"`.
- [ ] `Entry` (line 179): `judged: schema.Advisory | None = None` (the thread's widest state at the level it stands at; None for a thread that is not judged) and `published: str | None = None` (the published level of an entry shown at notice).
- [ ] `_entries` (line 191): set `judged` from the first copy's thread: `replace(pull.widest(t), level=t.adv.level)` when `t.wide is not None and not t.curated and t.adv.posted_by == verify.BOT`, else None.
- [ ] `_memory(st, t, name) -> (last, gone, seen)`: over `t.root_ids`: `last` the greatest stored; `gone` and `seen` the greatest when every root has a `gone`, else None.
- [ ] `_verifies(a, st, s)`: `_results(a, st, s) is not None`. `_never(a, st, s, t, name, now) -> bool`: `t.judged` set, the CLI verifies, `st.supported["ruleset"]` is this ruleset's digest, `last is None and gone is not None`, and not (`st.reset_at` set and `now - SUPPORT_GAP_S < st.reset_at <= now`). `_lost(...)`: `last` and `gone` set and `seen - gone > SUPPORT_GAP_S`, the same digest and verifying conditions.
- [ ] `_note_support(a, st, s, threads, cache=None) -> bool`: the rules of the spec's section 1. `cache`: the results a source check of this command returned; None: the results on disk. A pure step `_support_step(record, threads, cache, digest, now, roots)` returns the new record: cut every stored time to `now`; on another digest drop every `gone` and `seen` (and entries left with nothing) and set the digest; then for every entry with `judged`, the cache's result for `verify.state_key(t.judged)` (skipped when missing or when its products are not the state's), `at = min(held["at"], now)`, and per product and per root of the entry the support and `unsupported` rules; drop roots not in `roots` (the roots of `a.raw`) and empty entries. When the step's result differs from `st.supported`: under `st.locked()` run the step again on the reloaded record (with the passed `cache`, or a freshly loaded one) and `save_unverified`; on `OSError` keep the computed value for this command. Returns whether it changed. Does nothing when the CLI does not verify or the ruleset cannot be loaded.
- [ ] `_matches` (line 246): after `threads` and the matches are built, call `_note_support`, then: an entry of `threads` every product name of whose `judged` is never supported becomes `replace(t, adv=replace(t.adv, level="notice"), published=t.adv.level)` when its level is above notice; each pair whose `m.product` is never supported gets such an entry too (its own copy when the thread's entry is not demoted).
- [ ] `_source_check` (line 409): returns the cache `verify.run` returned, or None. The states read are, per entry, `t.judged` (which carries the published level) when the entry is demoted, else `t.adv` and also `t.judged` when its `verify.state_key` differs; the same list is what the cache keeps (`current`). `recheck` gains the states of every relay-bot pair, at any level.
- [ ] `_source_lines` (line 429): per bot entry with `judged` and per scope product of it: never supported: the existing line `source check: the source does not support <id> for <name>` (from the memory, whatever the cache holds); `_lost`: `LOST_LINE`. From the cache as today otherwise, except that a cached `unsupported` prints nothing for a product whose memory has `last` (supported earlier). A product with no memory entry (a thread that is not judged, a record under another digest) keeps the existing line. A demoted entry's cache lookups are skipped (the memory speaks for it).
- [ ] `_check_json` (line 462), `_result` (line 624): a demoted entry gives `contradicted`, `unsupported`, `none`. `_match_json` (line 493): `"published_level": t.published`.
- [ ] `cmd_check` (line 568): a demoted match's line ends `(id <id>, <thread ref>; published at <level>)`. `cmd_plan` (line 798): hits are found by root id, not by entry equality; its first line carries `published at <level>` for a demoted match. `cmd_verify` (line 471): its counts read `t.judged` for a demoted entry; after the source check it hands the results to `_note_support` and matches again when `a.asked` or that changed something.
- [ ] `cmd_run` (line 843): after `_source_check`, `changed = _note_support(..., cache=<its results>)`; match again when `a.asked or changed`; "After the source check:" is printed when the levels of the threads or of the matches changed.
- [ ] `_mend` (line 365): `st.supported` is emptied with the rest.
- [ ] Tests, `tests/test_never_supported_cli.py`, with the fixtures of `tests/test_verify_cli.py` and `tests/test_unverified_cli.py`:
  1. acceptance 1: `bot(id=CVE, level="critical")`, the catalog lists the CVE for another vendor; `pull`, `verify`; then `run` exits 0, sends nothing, `check` prints `NOTICE: ` with `published at critical` and the flag line, `run --json` has it in neither list and its match has `level` notice, `published_level` critical, `source_check` contradicted/unsupported; `plan` shows NOTICE.
  2. acceptance 2: `G1` malware confirmed and notified; a day later the source has withdrawn it: `run` reads it, the level is critical, no `source check:` line; at the read more than 48 hours after that one, `run` prints `LOST_LINE` and the level is still critical; the source supports it again: the line is gone.
  3. acceptance 3: a demoted alert with every read failing stays at notice, exit 0, flag line still printed; a supported critical with every read failing stays critical and prints no flag; a "supported earlier" alert before 48 hours whose reads then fail for a week prints no line; one past 48 hours whose read then fails still prints it.
  4. the first run of a new fabricated critical interrupts once as unverified, and the same run prints "After the source check:" with NOTICE; the next run exits 0.
  5. per match: `products=("Claude Code", "Codex")`, the catalog lists the CVE for Codex, both installed: the Codex match is critical and interrupts, the Claude Code match is notice.
  6. dropping the supporting alias does not demote: a CVE thread whose support came through a GHSA alias, then a reply that replaces the aliases: still critical, and the widest state is what was read.
  7. a reply that changes a fabricated thread (adds an alias) does not shed the demotion while the new state is unread.
  8. support read later ends the demotion and the critical interrupts in that run; support read beside a failing alias ends it too (chunk 1).
  9. `verify = "off"` after a demotion: shown as posted; the memory is kept.
  10. a rebuilt record: nothing shows at notice for 48 hours, then it does.
  11. a curator's own critical is not demoted.
  12. the clock was ahead when "no support" was read: after it is set back the alert shows at notice at the next command, and the stored time is not in the future.
  13. the hook's `run --json` applies the memory and reads no source.
  14. `above-source` keeps critical and its existing line.
  15. a published `high` never supported shows at notice; a confirmed `high` match is read again a day later and its lost support is recorded.
  16. the record under another ruleset digest: nothing shows at notice until a read under this one; `gone` is dropped.
  17. two commands: one whose source check found support hands it over although `verify.json` on disk then holds an older "unsupported" (the file is overwritten in the test before the hand-over): `last` is recorded and nothing is demoted; and a support read older than `gone` clears nothing.
- [ ] Existing tests whose expectation the issue changes, each edited to the new behaviour and named in the run record: the four of the spec's "Existing tests this changes". Any other failure is a defect in the change, not a test to edit.
- Verify: `python3 -m pytest -q tests/test_never_supported_cli.py tests/test_unverified_cli.py tests/test_verify_cli.py tests/test_curator_hold_cli.py tests/test_cli.py tests/test_wire_compat.py`, then `python3 -m pytest -q`.
- Acceptance: the issue's three cases (tests 1, 2, 3) pass; `tests/test_wire_compat.py` is unchanged and passes.

## Chunk 4: documents

- [ ] `README.md`, the source-check section (lines 136 to 157): what "contradicted, does not support" now does (shown at notice, `published_level`, no interrupt; from the first read; kept through failed reads; ended by a read that supports it), the 48-hour line, that `above-source` keeps its level, that an `unread` result's `source_level` may carry what was read, and the sentence "an alert the source does not support is flagged, and still shown at its posted level (ai-tools-alerts#0z4e)" removed. The `unverified.json` paragraph names the memory and the 48 hours after a rebuild.
- [ ] `CHANGELOG.md`, under Unreleased: one paragraph and the JSON key.
- [ ] The run record: scorecards, the tests edited, the findings and what was done.
- Verify: `scripts/public-scan.sh`; `python3 -m pytest -q tests/test_public_scan.py tests/test_templates.py`.

## Amendments after the plan's review (all built)

- Chunk 1 also: `verify.run`'s budget-exhausted branch stores what the run read and keeps no old `unsupported` with a new time; `verify.Unsaved` carries the results when the cache cannot be written, and `_source_check` returns them.
- Chunk 3: `_entries` merges copies only when their judged states are equal too. `_support_step` cuts the record to the stored events (`set(st.events)`, read again under the lock), not to `a.raw`. A `confirmed` result with nothing supported clears `gone`.
- Tests added for each: the five named in the spec's "Review dispositions (plan)", and rows of `test_the_reads_are_ordered_by_their_own_times`.
- One more existing test edited: `tests/test_verify_cli.py::test_an_alert_the_source_does_not_support_is_flagged_per_product` (a substring count).

## After the chunks

1. Commit (signed, no-reply author). Merge `origin/main`; resolve; `scripts/test-gate.sh` in a clone of the branch alone.
2. One whole-branch review, independent model (`git fetch origin && git diff origin/main...HEAD`), beside a same-model pass. Every BLOCKER fixed, every SUBSTANTIVE finding fixed or rebutted; one delta only after a behaviour-changing BLOCKER fix.
3. Merge `origin/main` again, the gate again, the close-out comment, the pull request, `gh pr merge <n> --merge --author-email <the no-reply address>`, check `git log -1 --format=%ae origin/main`, close the issue on the merge commit. A note on ai-tools-alerts#m729 says where a strike can be counted.

## Rollback

Revert the pull request's merge. `unverified.json` written with the new key is read as damaged by the older code and started again by it (`_mend`); `verify.json` of version 4 is dropped by it and read again.
