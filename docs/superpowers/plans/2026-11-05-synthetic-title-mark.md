# Plan: the SYNTHETIC TEST mark reaches the advisory title (ai-tools-alerts#hhe3)

Spec: docs/superpowers/specs/2026-11-05-synthetic-title-mark-design.md

## Chunk 1: the reader contract and compose mark the title (one commit)

- [ ] `aitools_alerts/schema.py`: `SYNTHETIC`, `SYNTHETIC_ID`, `is_synthetic` (moved
  from compose); `validate` (~l.184) marks the title of a reserved id, then checks
  length ≤ 300. Docstring line.
- [ ] `tests/test_schema.py` (or test_pull.py): a legacy unmarked synthetic root and a
  patch setting an unmarked title read marked; a real id is never marked; a marked
  title over 300 is refused.
- [ ] `aitools_alerts/poster/main.py` l.247: drop the `test=` argument.

- [ ] `aitools_alerts/poster/compose.py` `_titles` (~l.138): for a reserved id
  (`is_synthetic(adv_id)`) every template title carries the `SYNTHETIC TEST: `
  prefix; otherwise unchanged.
- [ ] `compose.py` imports `SYNTHETIC`, `SYNTHETIC_ID`, `is_synthetic` from schema.
- [ ] `root_post` (~l.150): drop `test`; the head mark reads `is_synthetic(c.id)`;
  the title comes back marked from `validate`; docstring says the id decides.
- [ ] `digest` (~l.300): mark only when the title does not already start with
  `SYNTHETIC`.
- [ ] `tests/poster/test_compose.py`: new `test_synthetic_root_marks_the_block_title`
  (parsed title starts `SYNTHETIC TEST: ` for CVE-2099-0010, head line keeps
  `(SYNTHETIC TEST)`; a real id with the same candidate never carries the mark;
  re-rendering a marked advisory keeps one mark) and
  `test_synthetic_digest_and_reply_keep_one_mark` (marked title: one mark in the
  digest; an unmarked legacy synthetic advisory: prefixed; a reply patch that
  sets an unmarked template title on a synthetic thread is refused).
- [ ] `tests/poster/test_main.py`: the two assertions that pin the head line /
  digest line text (`test_kev_file_bypasses_fetch_and_marks_posts`,
  `test_synthetic_advisory_is_marked_in_the_digest`) follow the new text.
- [ ] `tests/test_cli.py`: `test_check_and_plan_show_the_synthetic_mark`: a Mirror
  with a relay-bot root composed by `compose.root_post` for CVE-2099-0010
  (Claude Code, affected <99.0.0); `check` text and `--json` and `plan` all show
  `SYNTHETIC TEST: Claude Code: known exploited vulnerability (CVE-2099-0010)`;
  the notify text (`notify.format_text`) starts `CRITICAL: SYNTHETIC TEST:`.

Verify: `python3 -m pytest -q` (the repo has no repoman row; the whole suite is
the gate, as the earlier tasks ran it).

Acceptance: spec criteria 1-7; `git diff --stat origin/main` under 150 lines of
code and tests; the fleet host-name grep over `git diff origin/main -- aitools_alerts tests`
prints nothing (the docs are excluded: the plan names the grep itself).

Rollback: `git revert <sha>`; no data or state migration.

## Ending

Review (medium: spec+plan fresheyes, then code Stage 1 ∥ fresheyes on
gpt-6-astra), `git fetch` and rebase on origin/main (ai-tools-alerts#qg7p edits
compose.py's digest), full suite on the rebased head, push the branch, ff-merge
to main from the primary checkout, close with evidence, comment the sha on
jibot-code#gr5b.
