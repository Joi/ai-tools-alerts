# Plan: 0dvh on top of h340 (dmmf)

Spec: `docs/superpowers/specs/2026-11-24-dmmf-rebuild-0dvh-on-h340-design.md`.

## Chunk 1: merge

- [x] Merge `origin/0dvh-integrate-h340-wip` (0dvh's reviewed head 0859170 with main
  at 1e9221c merged in) into this branch, which starts at main c155735.
- [x] `tests/mirror/test_export.py` conflicts with nfm3's checkpoint tests: keep both.
- [x] Commit the merge alone (signed). Ten poster tests fail at it, as on the WIP branch.

## Chunk 2: inputs from the page

- [x] `aitools_alerts/poster/rules.py`, `evidence`: a stated range the schema cannot
  carry, `*`, or several matching blocks with ranges give `UNEXPRESSED`; comment and
  docstring say so.
- [x] `aitools_alerts/poster/candidates.py`: `Candidate.severity_word`, left out of
  `to_dict`.
- [x] `aitools_alerts/poster/inputs.py`, `candidate_from`: accept a dict without it.
- [x] `aitools_alerts/poster/main.py`, `Run.admit`: `severity_word=ev.severity`.
- [x] `aitools_alerts/poster/ledger.py`, `_merged`: join members' words.
- [x] `aitools_alerts/poster/compose.py`, `root_post`: publish `severity(c.severity_word)`.

## Chunk 3: tests

- [x] `tests/poster/test_live_replay.py`: the `CLAUDE` name error; `_pages` serves a
  repository advisory page per live state and cuts a refused slug to its base id;
  11-07 asserts 16 aged, OpenClaw dropped (stderr count), no real-time root.
- [x] `tests/poster/test_main.py`: pin the page in the synthetic-merge test; severity
  tests state the word on the page; a records-severity-never-published test; the
  held-notice test rebuilt on a repository page and a vendor site page; the
  learned-sources test gives the high a range so it posts.
- [x] `tests/poster/test_rules.py`: range expectations for S3, one-block cases.
- [x] `tests/poster/test_compose.py`: the block reads `severity_word` only;
  `to_dict` leaves it out.
- [x] `tests/poster/test_ledger.py`: merge joins the pages' words, keeps the record's
  text apart.
- [x] Mutation checks: the field-preserving hold merge and the severity source each
  fail a new test when broken.

## Chunk 4: docs and record

- [x] CHANGELOG: one paragraph for 0dvh as it lands on h340.
- [x] Run record `docs/superpowers/runs/2026-11-24-dmmf-rebuild-0dvh-on-h340.md`.

## Verification

- `python3 -m pytest -q tests` (1596 passed, 1 skipped before the gate).
- `scripts/test-gate.sh` (public scan, then the suite).
- One independent whole-branch review: `git diff origin/main...HEAD`.

## Acceptance

Spec S1 to S5. Then: pull request, gate, review, merge with the no-reply author;
`git fetch origin`, check that `origin/main` is the pull request's merge commit
(`gh pr view <n> --json mergeCommit`), and only then that
`git log -1 --format=%ae origin/main` prints the no-reply address; close dmmf and
0dvh on the merge commit; close pull request 8 as replaced.

## Rollback

Never a whole revert once a root has posted under this change: the h340 compose
refuses a public-form title on a ledger-key id and a non-null severity, so every
later update to such a thread would be withheld and dropped (0dvh spec, "Blast
radius and rollback"). Roll back the behaviour only: a commit on main that restores
`Run.plan_new` without the hold and the age limit (no `waiting`, no `aged`), keeping
`compose.py`, `rules.py`, `candidates.py` and `ledger.py` as they are; reinstall the
poster. The state's `waiting` key is still read by this code, so it stays.
