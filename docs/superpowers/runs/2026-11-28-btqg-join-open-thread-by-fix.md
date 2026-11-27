# Run: btqg-join-open-thread-by-fix
Instruction: Read TASK-ai-tools-alerts#btqg.md in this worktree root, then run `kata show ai-tools-alerts#btqg` and follow the brief and the dispatch rules (do-it, start rung floored at medium; landing per the brief: scripts/test-gate.sh, one independent review, a PR merged with the no-reply author, the issue closed on the merge commit).
Stage: spec
Rung: medium (start-floor medium: dispatch floor; evaluator FC=2, BR1 REV2 NOV1 INT1 FC2 = 7, no hard trigger)
Lens: "Nothing you build may wait for a person to act." (carried in every review prompt)
Spec: docs/superpowers/specs/2026-11-28-btqg-join-open-thread-by-fix-design.md   Plan: docs/superpowers/plans/2026-11-28-btqg-join-open-thread-by-fix.md
Agency project: — (no mcp__agency__* tools in this session; built directly, recorded below)
Kata: ai-tools-alerts#btqg
Last reviewed: —

## Scorecards
Pass 1 [spec]: 4B/1S/1C/0R · fixed -/- · velocity = (—→6, escalation no)   (fresheyes gpt-6.1-sol high, snapshot 1758b9a, REASON=-)
  - B KEV/exploited not tied to the first id: a join never raises or marks exploited (fixed)
  - B busy learned the member's ids into the thread's items: busy(learn=False) (fixed)
  - B the 51-id block cap: no join past it (fixed)
  - B shared former name: none under one other scope entries also list (fixed)
  - S a group's level rests on its first id through withdrawal/renewal: rebutted, pre-existing for every faxq group; follow-up filed
  - C the snapshot's commit message: rebutted, a dangling review snapshot, never on the branch
  passes: 1 · elapsed: ~20 min

## Chunks
- [ ] join — Run.one finds the open thread of the candidate's fix; plan_known widens its range; ledger `joined`

## Notes
- Built while the spec review ran (no Agency tools here); the spec findings were folded into spec, plan and code before any commit. The plan's one review runs beside the code review, on the plan as amended.
- Existing tests changed (btqg: another fix, another thread): test_recompute x3, test_wording x2, test_end_to_end x1, test_main x2. Each posted a second advisory with the same fix in a later run and needed a second root.
- Mutation check: with the shared-former-name filter off, test_a_shared_former_name_thread_is_never_joined_by_fix fails.
- Base 3d376b8 (main). Not repoman-managed (no .repoman-managed): PR, gate scripts/test-gate.sh, self-merge with --author-email (xrx2 closed).
- ai-tools-alerts#z360 (partial retraction of a fix group) is in flight on another host and touches the same files; merge main before review and before merge.
