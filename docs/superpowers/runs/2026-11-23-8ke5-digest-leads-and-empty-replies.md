# Run: 8ke5-digest-leads-and-empty-replies
Instruction: Read TASK-ai-tools-alerts#8ke5.md in this worktree root, then run `kata show ai-tools-alerts#8ke5` and follow the brief and the dispatch rules (do-it, starting rung floored at medium; not repoman-managed: land by fast-forward to main after the gate and one independent review; reinstall on the poster host).
Stage: executing
Rung: medium (start-floor medium: constraint-lens; evaluator BR1 REV2 NOV1 INT2 FC1 = 7, hard-trigger none; dispatch floor medium as well)
Lens: "Readers at v0.1.4 are installed on member machines: a post they cannot parse is a regression. Do not change the block's required keys."
Spec: docs/superpowers/specs/2026-11-23-8ke5-digest-leads-and-empty-replies-design.md   Plan: docs/superpowers/plans/2026-11-23-8ke5-digest-leads-and-empty-replies.md
Agency project: 01a204d9-d21f-7484-b8ec-ba4d957b6bdc
Kata: ai-tools-alerts#8ke5
Last reviewed: spec 22021d97d0b9baaa59e8eceaf48ddecc346948f1

## Scorecards
Pass 1 [spec]: 0B/5S/0C/1R · fixed -/- · velocity = (—→6, escalation no)   (fresheyes gpt-6.1-sol high, REASON=-)
  spec passes: 1 · fixed 5 (legacy listed_at freeze; alias line filter; existing tests named; rollback strips the current ledger, never restores; uv path) · rebutted 1 (snapshot commit message: a dangling review snapshot, never landed; real commits carry descriptive messages)

Pass 1 [plan]: 0B/4S/0C/0R · fixed -/- · velocity = (—→4, escalation no)   (fresheyes gpt-6.1-sol high, snapshot ea70def8, REASON=-)
  plan passes: 1 · fixed 4 (replay runs a 09:20 digest each day and asserts listing on 11-07 and 11-08 only; whole marks-and-kinds test rewritten on primary sources, "see the release" removed; listed_at never null; host name removed from spec and manifest, public scan)

## Chunks
- [x] chunk 1 — compose: no lead lines, no ledger-key aliases (poster tests: compose 54 passed)
- [ ] chunk 2 — main + ledger: no source/alias-only replies, digest lists an advisory once
- [ ] chunk 3 — live-feed replay test

## Notes
- Prior work: kata qg7p (digest grouping: lead lines were introduced there; this run removes them), 9mx8 design comment (Redundancy, section 5, Do now 2 and 3), mz81/k5tr mention guard, 4yr1 no-fix wording.
