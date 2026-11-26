# Plan: the recompute posts the copy a thread's level lacks (ai-tools-alerts#3t4p)

Spec: `docs/superpowers/specs/2026-11-26-3t4p-copy-on-recompute-raise-design.md`. One chunk, about 250 changed lines with tests. Tests first.

## Chunk 1: `compose.copy_post` and `Run.copies`

### Files

- `tests/poster/test_copy_on_raise.py` (new)
- `tests/poster/test_compose.py` (additions)
- `aitools_alerts/poster/compose.py`: `root_post` (line 363), new `_root_lines`, new `copy_post` after `root_post`
- `aitools_alerts/poster/main.py`: module docstring (the recompute paragraphs, lines 46 to 58), `Run._level_items` docstring (line 1366), `Run.recompute` (line 1479), new `Run.copies` after it
- `CHANGELOG.md`: the 3qyq entry's sentence that names this issue, and one paragraph under Unreleased
- `docs/superpowers/runs/2026-11-26-3t4p-copy-on-recompute-raise.md`

### Steps

- [x] 1. Write the failing end-to-end tests in `tests/poster/test_copy_on_raise.py`, on `test_main`'s `env` and `test_advisory_recompute`'s `post`, `run`, `entries` (imported by name):
  - `test_a_feed_only_thread_raised_to_critical_gets_its_copy_in_the_critical_channel`: post at high; the advisory then reads `type="malware"`; the next run sends the level reply in `feed` and a root in `critical`, in that order; the ledger entry has both channels; the copy's block (`schema.parse_post`) equals the entry's advisory; the copy has a `lang: ja` reply to it; no collector record was added. A further run sends nothing.
  - `test_a_raise_on_a_thread_with_both_channels_sends_no_copy`: the malware thread of `test_a_malware_advisory_withdrawn_and_published_again_returns_to_critical`; after the lowering and the raise, every send is a reply.
  - `test_a_failed_copy_send_is_sent_again_from_the_journal`: the raise run with `FakeRelay("ok", "fail")` exits 1 with one `copy` item in the outbox; the next run sends it and the entry gains `critical`.
  - `test_a_copy_whose_outcome_is_unknown_holds_the_thread_and_is_not_planned_twice`: `FakeRelay("ok", "unknown")`; the next run plans no second copy.
  - `test_a_refused_copy_is_planned_again_once_it_is_dropped`: `FakeRelay("ok", "refuse")`; runs inside three days send no copy; the run after `WITHHELD_SECONDS` drops it and posts a new one.
  - `test_a_refused_raise_posts_no_copy`: `FakeRelay("refuse")`; the ledger stays at high and nothing is sent to `critical`.
  - `test_a_synthetic_thread_and_a_thread_out_of_scope_get_no_copy`: unit level on `Run.copies` with a ledger entry edited to critical.
  - Added after the spec review: `test_a_thread_is_found_by_the_name_it_was_posted_under` (Cursor, whose display name is no identity; a former name), `test_a_withdrawn_advisory_gets_no_copy`, `test_no_copy_is_planned_while_the_mirror_cannot_be_read`, `test_an_unknown_copy_the_mirror_shows_is_recorded_and_not_sent_again`, `test_an_unknown_copy_the_mirror_never_shows_is_sent_again` (24 hours fresh, 72 hours stale), `test_a_raise_whose_send_failed_gets_its_copy_from_the_next_run`, `test_a_lowered_thread_keeps_its_channels_and_gets_no_copy`.
  - `test_a_copy_compose_refuses_is_withheld_and_tried_again`: the entry's advisory edited so `copy_post` refuses (no source); `withheld=1` in the summary, nothing in the outbox; restored, the next run posts the copy.
- [x] 2. Write the failing unit tests in `tests/poster/test_compose.py`:
  - `copy_post(adv, scope, title=...)` on the advisory `root_post` returned gives `root_post`'s text, for a high with a fix, a critical with a fix, a critical by stop_using, and an unverified title;
  - `schema.parse_post(copy_post(...)) == adv`;
  - it raises `ValueError` for: a critical with no action, a product named otherwise than the scope, a scope entry with components, an id of another shape, text `_guard` refuses, text that does not parse back. A title the guard refuses is dropped, not the copy.
- [x] 3. `compose.py`: move `root_post`'s body lines into `_root_lines(adv, head, title, fallback, scope, *, who=None, stop, unexpressed, range_unexpressed, exploited)`; `root_post` calls it. No output changes: the existing compose tests pass unchanged.
- [x] 4. `compose.py`: add `copy_post` as the spec describes.
- [x] 5. `main.py`: add `Run.copies(root, fetch)` and call it as the last statement of `Run.recompute`, which takes the mirror's root and fetch from `run` as `Run.digest` does. Scope by `catalog._scope`; the withdrawal check by `Run._withdrawn`. Update the two docstrings and the module docstring.
- [x] 6. `CHANGELOG.md`: replace "a thread posted at high has none in the critical channel until it is sighted again (ai-tools-alerts#3t4p)" with what happens now; add the Unreleased paragraph.
- [x] 7. Mutations, each must fail a named test: `copies` not called; `copies` ignores `busy`; `copies` posts for a synthetic thread; `copies` resolves the scope with `rules.scope_of`; `copies` skips the withdrawal check; `copy_post` skips the 9kgk check; `copy_post` does not check the product; `copies` pulls the mirror with another root; `copies` posts to every channel of the level. (The parse-back check planned for `copy_post` is `schema.render_post`'s own; none was added.)

### Verification

```
python3 -m pytest tests/poster/test_copy_on_raise.py tests/poster/test_compose.py -q
python3 -m pytest tests/poster -q
scripts/test-gate.sh        # in a clone holding this branch alone (the shared clone fails the scan on other sessions' refs)
```

### Acceptance

- The three acceptance lines of the issue, each a named test above.
- One existing test changes: `tests/poster/test_main.py::test_compose_value_error_sends_nothing` asserted the missing copy (`copies=0` after the recompute's raise); it now expects the copy in `critical`.
- `git diff origin/main --stat` under 600 lines.

### Rollback

Revert the commit. A journaled copy drains under the old code; no state key was added.
