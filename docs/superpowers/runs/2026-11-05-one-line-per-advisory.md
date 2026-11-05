# Run: one-line-per-advisory
Instruction: Task ai-tools-alerts#54p7 per TASK-ai-tools-alerts#54p7.md — group threads by (advisory id, poster role) for check, plan and the notifications: one line, one block, one notification per advisory; --json keeps every thread id under the advisory (threads: [..]); the highest level and the latest posted_at win when copies differ (say so if they do). Tests in tests/test_cli.py. Under 200 changed lines. /do-it with the rung floored at medium; security-shaped review on gpt-6-astra. Non-repoman repo (ff-merge ending).
Stage: code-review:group-by-advisory
Rung: medium (start-floor medium: evaluator BR1 REV1 NOV1 INT1 FC1 = 5, no hard trigger; external JSON contract changes shape)
Lens: "--json keeps every thread id under the advisory (threads: [..])"; "Under 200 changed lines"; "`thread` is still one root id (the one `plan` and the skills already read)"; "A high with one root reads exactly as before (text and JSON, except the added `threads`)"
Last reviewed: spec+plan 8704c8f8dcd1d2e6bf05ae785ba7441bb8ff63ef (pass 1, gpt-6-astra)
Spec: docs/superpowers/specs/2026-11-05-one-line-per-advisory-design.md   Plan: docs/superpowers/plans/2026-11-05-one-line-per-advisory.md
Agency project: — (no mcp__agency tools in this session; built inline, as the earlier runs on this repo did)
Kata: ai-tools-alerts#54p7 (kata search "duplicate advisory group check plan notify": only 54p7)

## Scorecards
Pass 1 [spec+plan]: 4B/0S/1C/0R · fixed -/- · velocity = (—→5, escalation no)
- fresheyes gpt-6-astra, run 20261105-163151-b194ac; graded 1 critical, 4 major (read as BLOCKER), 1 minor.
- Fixed B1 (picking one copy before matching drops another copy's match) and B2 ("any root seen" hides a differing unseen copy): only equal copies merge; see the kata `decided:` comment.
- Fixed B4 (one entry can still print several lines): spec criterion 8, one line per (advisory, match); channel duplicates go.
- Rebutted B3 (the two-root fixture yields one event id): the test posts the copies at T0+100 and T0+101, so the ids differ, and it asserts `threads == [crit, feed]`.
- Rebutted B5 (snapshot commit message): 8704c8f is a dangling review snapshot built by commit-tree; it never lands on a branch.
- Rebutted C6 (the shown root id can move when updated_at changes): `plan` accepts any root id of the entry, so the shown id is not a contract.
Stage 1 [code:group-by-advisory, pre-fix diff]: 1B/1S/3C/0R (same-model subagent)
- B (match only the shown copy) and S (any root seen) are the same two as fresheyes B1/B2: fixed by the equal-copies-only merge, with tests.
- C: the run warning printed twice: fixed (once per command). C: plan by a non-shown root showed another copy: fixed by construction (differing copies are separate entries). C: skills did not document `threads`/`unseen_critical`: fixed in both skills and snippets/AGENTS.md.

## Chunks
- [ ] group-by-advisory — cli.py Entry grouping + tests

## Notes
