# Plan: yd1y, a fix group's members outlive its first id

Spec: `docs/superpowers/specs/2026-11-28-yd1y-fix-group-outlives-first-id-design.md`.
One chunk, test first. Base: main at 4def27d with `origin/z360-fix-z360` merged.

## Chunk 1: release and repost

- [ ] `tests/poster/test_fix_group_split.py`: the acceptance scenario through
  `main.run`, with the member's `verify.run` on a fresh cache; then one test for each
  success criterion of the spec. They fail before the code.
- [ ] `aitools_alerts/poster/recompute.py`
  - `released(entry)`: the lookup forms of `Entry.split["released"]`, never the first id.
  - `support(..., skip=frozenset())`: the id loop leaves out `skip` and each released
    id no source ties to the first id.
  - `loose(entry, read)`: (untied advisory ids, CVEs an advisory first id's response
    does not name), released ids apart.
  - `lead(entry, scope, copy, rs, st, read)`: (level, members, cves) or None; reads
    only; `judge`'s KEV rules; fields only, no prose floor.
  - `outlived(entry, scope, copy, rs, st, read)`: ([(member, level)], cves).
- [ ] `aitools_alerts/poster/main.py`
  - `Run.part(e, rs, pages)`: `outlived`, read in the thread's lane; a pointer per
    supported member (`_judge_id`, `RETIRE_PAGES`); pointers into `state["deferred"]`
    and `self.deferred`, saved; `Ledger.release`; the thread judged again.
  - `observe`: each thread is judged and then parted, in `_in_turn`'s order.
  - `_fix_thread`: no join into a thread that has released an id.
- [ ] `aitools_alerts/poster/ledger.py`: the `split` comment names the second cause.
- [ ] `CHANGELOG.md`: an entry under the unreleased text, after z360's.

Verification: `python3 -m pytest tests/poster/test_fix_group_split.py -q`, then
`scripts/test-gate.sh`.

Acceptance: every test of the new file passes; the suite passes; mutation checks:
removing the `_fix_thread` condition fails the rejoin test; removing the released ids
from `support`'s loop fails the acceptance test's withdrawal; parting after every
thread is judged fails the lane test; adding the prose floor to `lead` fails the
prose-floor test.

Rollback: revert the commit.

## Landing

Merge main (and z360's branch while pull request 67 is open) before the review and
before the merge. One fresheyes review of the branch against `origin/z360-fix-z360`
while 67 is open (so z360's reviewed code is not reviewed twice), else `origin/main`.
Pull request, merged with the no-reply author address after 67 lands. Release note on
ai-tools-alerts#z3fs.
