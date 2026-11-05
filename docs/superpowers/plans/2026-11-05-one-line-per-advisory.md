# Plan: one line per advisory in check, plan and notify (ai-tools-alerts#54p7)

Spec: docs/superpowers/specs/2026-11-05-one-line-per-advisory-design.md

## Chunk 1: group threads by (advisory id, poster role) (one commit)

- [x] `aitools_alerts/cli.py`: `Entry` frozen dataclass (`root_id`, `root_ids`,
  `adv`) and `_entries(threads, warned)`: group by `(adv.id.casefold(),
  adv.posted_by)` in reader order, merging only copies with equal `adv`;
  differing copies stay separate entries, stderr warning
  `copies of <id> differ; listing each` once per command (amended after
  review; the draft's max-by-level pick dropped matches).
- [x] Skills and `snippets/AGENTS.md` (word-for-word twin, test_templates):
  document `threads`, and that `unseen_critical` lists every root.
- [ ] `_matches` (~l.122): `threads = _entries(pull.active(...))`; the rest
  unchanged.
- [ ] `_match_json` (~l.149): add `"threads": list(t.root_ids)` after `thread`.
- [ ] `cmd_check` (~l.158): the thread part reads `thread X` for one root and
  `threads X, Y` for more (helper `_thread_ref(t)`), in the match line and
  the "not installed here" line.
- [ ] `_unseen_critical` (~l.177) and `_notify` (~l.191): "seen" means any of
  `root_ids` is in `st.seen`; on acceptance add all of `root_ids`.
- [ ] `cmd_plan` (~l.218): `wanted` matches `a.advisory_id` against
  `t.root_ids` and `t.adv.id`.
- [ ] `cmd_run` (~l.252): `unseen_critical` = sorted union of `root_ids`.
- [ ] `tests/test_cli.py`: with `mirror_helpers.Mirror`, one relay-bot critical
  posted as two roots (`m.post(..., files=("critical.json",))` and
  `files=("feed.json",)`), test: check text one match line naming both
  threads; check --json one object with `threads` = both ids; plan by the id
  and by the second root id prints one block; notify sends once and seen
  holds both ids; run --json `unseen_critical` has both ids. Second test:
  two different ids list twice; the same id from curator and relay-bot lists
  twice; a high with one root has `threads == [thread]` and its text line
  `thread <12>`. Third: copies that differ list apart, keep both matches,
  warn once; a seen copy does not hide a differing unseen one; an old seen
  file holding one of two equal copies does not re-alert.

Verify: `python3 -m pytest -q` (no repoman row for this repo; the whole suite
is the gate, as the earlier tasks ran it). Fleet host-name grep over
`git diff origin/main -- aitools_alerts tests` prints nothing.

Acceptance: spec criteria 1-7; code and tests under 200 changed lines.

Rollback: `git revert <sha>`; no state migration.

## Ending

Review (medium: spec+plan fresheyes, then code Stage 1 ∥ fresheyes on
gpt-6-astra, security-shaped per the brief), `git fetch`, rebase if main
moved, suite on the rebased head, push the branch, ff-merge to main from the
primary checkout, close with evidence, comment the sha on jibot-code#gr5b.
