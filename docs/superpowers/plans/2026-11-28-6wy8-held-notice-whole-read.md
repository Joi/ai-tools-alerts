# Plan: a whole read replaces a held notice's fix and range together (ai-tools-alerts#6wy8)

Spec: `docs/superpowers/specs/2026-11-28-6wy8-held-notice-whole-read-design.md`

One chunk. Tests first.

## Chunk: hold

### Files

- `tests/poster/test_main.py`, beside the 0dvh held-notice tests (after
  `test_a_fieldless_sighting_keeps_the_notice_fix_and_first_sight`): new tests.
- `tests/poster/test_catalog.py`, beside `test_a_held_notice_posts_to_the_catalog_and_not_to_feed`:
  one test.
- `aitools_alerts/poster/main.py`: `Run.__init__` (`boxed`), `Run.admit`, `Run.plan_new`
  (the `self.hold(...)` call), `Run._cover` (new) and `Run.hold`.
- `CHANGELOG.md`: one line under the unreleased heading, if the file has one.

### Steps

- [x] 1. Write the failing tests (all through `env.run`, state read with `env.state()`),
  with helpers `inspector_finding`, `inspector_notice`, `held_fields`, `held_group`
  and the box `TWO_RANGES` (the shape of GHSA-v2gx-m79c-pvxj):
  - `test_a_several_range_read_replaces_a_held_range_and_fix_together`: held with
    `>=2.0.0,<=2.16.0` and no fix; the page then states `TWO_RANGES`; the held notice
    has `("2.17.0", None)`, the action, the first run's `posted_at`, and
    `versions.check("1.0.5", None, "2.17.0") is True`.
  - `test_a_read_with_a_range_and_no_patch_clears_a_held_fix`.
  - `test_a_box_that_states_no_range_and_no_patch_clears_both` (spec review).
  - `test_one_members_read_only_widens_a_held_group`, five cases: a narrower member,
    a fix that rose, the same range, no fix now, several ranges (spec review).
  - `test_a_group_that_shares_one_member_joins_under_a_fix_that_covers_it` (spec review).
  - catalog: `test_a_held_notice_corrected_by_a_whole_read_posts_a_new_catalog_root`.
  - `test_an_old_source_posts_no_root_and_reaches_the_digest_notices`: its
    "the fix stays" assertion becomes "the fix and the action go" (spec review).
- [x] 2. Run them on main's code: the first four written failed (recorded in the run
  manifest).
- [x] 3. `Run.boxed` (a set, `scope|id`), filled in `Run.admit` when the evidence is
  structured, with the candidate's id and the page's ids.
- [x] 4. `Run._cover(was, new)`: the widening rule of the spec.
- [x] 5. `Run.hold(self, scope, adv, title=None, read=False)`: not a read, no change;
  a read of every held id, both fields replaced; else `_cover`. The existing
  `if got != was:` block rebuilds the action. Docstring states the rule.
- [x] 6. `Run.plan_new` passes `read`.
- [x] 7. Mutation checks (nine with one more on the range), each must fail a test: `read` always true; `whole` always
  true; `whole` always false; the old per-field merge; `boxed` filled from stated
  fields only; `_cover` keeping the held fix when the read states none; `_cover`
  taking the lower fix; `_cover` keeping the held range when they differ.
- [x] 8. `CHANGELOG.md`: an entry under a new unreleased heading.

### Verification

    python3 -m pytest tests/poster -q
    scripts/test-gate.sh

### Acceptance

- The new tests pass; the whole suite passes; the mutations are each caught.
- `test_a_fieldless_sighting_keeps_the_notice_fix_and_first_sight` passes unchanged.

### Rollback

Revert the commit. The state file's shape does not change.

## Landing

Merge `origin/main`, `scripts/test-gate.sh` (in a clone of this branch alone if the
shared clone's scan fails on other sessions' refs), one independent whole-branch
review, a pull request merged with the no-reply author, the issue closed on the merge
commit. A comment on ai-tools-alerts#g9bv says what a release does for the live
notice.
