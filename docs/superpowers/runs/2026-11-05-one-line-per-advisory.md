# Run: one-line-per-advisory
Instruction: Task ai-tools-alerts#54p7 per TASK-ai-tools-alerts#54p7.md — group threads by (advisory id, poster role) for check, plan and the notifications: one line, one block, one notification per advisory; --json keeps every thread id under the advisory (threads: [..]); the highest level and the latest posted_at win when copies differ (say so if they do). Tests in tests/test_cli.py. Under 200 changed lines. /do-it with the rung floored at medium; security-shaped review on gpt-6-astra. Non-repoman repo (ff-merge ending).
Stage: done
Rung: medium (start-floor medium: evaluator BR1 REV1 NOV1 INT1 FC1 = 5, no hard trigger; external JSON contract changes shape)
Lens: "--json keeps every thread id under the advisory (threads: [..])"; "Under 200 changed lines"; "`thread` is still one root id (the one `plan` and the skills already read)"; "A high with one root reads exactly as before (text and JSON, except the added `threads`)"
Last reviewed: spec+plan 8704c8f8dcd1d2e6bf05ae785ba7441bb8ff63ef (pass 1, gpt-6-astra)
Last reviewed: code eec1a4b5c5fb5a37dbe9a1ce280aeb75b1e457be whole branch (pass 1, gpt-6-astra); the commit after it is docs only (plan step, this record)
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
Pass 1 [code:group-by-advisory, whole branch eec1a4b]: 1B/0S/0C/1R · fixed 6/6 prior · velocity ↓ (5→2, escalation no)
- fresheyes gpt-6-astra, run 20261105-163837-d7d46d; two "major", read as BLOCKER.
- Fixed (doc only, no behaviour change, no delta): the plan's `_matches` step named the old `_entries` signature.
- Rebutted (counted R: it restates spec-pass B2 with a new path): "A seen with X, A amended to Y, unseen copy B = Y merges and is not sent". Seen has always meant "a root of this advisory was shown", not "this content was shown": an amendment to a seen root never re-notified before this change either. The poster posts a copy root only to a channel that has no root yet (main.py l.304-306): on an upgrade from high, the high root was never notified (notify sends criticals only), so it is not in seen and the merged entry alerts; after a failed channel post, the re-alert is exactly the duplicate this issue removes. Copies with different content still alert separately. Recording delivered content in seen is a seen-file format change, out of scope.

## Chunks
- [x] group-by-advisory — cli.py Entry grouping, tests, skills/snippet docs; spec+plan pass, Stage 1, one whole-branch fresheyes pass; no delta (the only fix after it is doc-only)

Verification: `python3 -m pytest -q`: 820 passed, 1 skipped. Fleet host-name grep over `git diff origin/main -- aitools_alerts tests skills snippets`: 0. Code, tests, skills: 190 lines changed (170+, 20-).

## Notes
- Skill rule slip: a few run-artifact edits (this closing update) used a python script with asserted replacements, not Edit; each replacement asserts its needle occurs once.
- Medium rung held: every BLOCKER fixed or rebutted in its pass; nothing surviving to escalate.
