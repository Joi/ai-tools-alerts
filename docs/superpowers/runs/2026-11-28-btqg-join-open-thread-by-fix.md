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
Pass 1 [plan]: 1B/6S/2C/0R · fixed -/- · velocity = (—→9, escalation no)   (fresheyes gpt-6.1-sol high, at 4a9293f, REASON=-; run beside the code review)
  - B a joined member's retraction while only the ledger holds it: the thread's learned ids are checked too (fixed, test)
  - S tests missing: mirror-retracted thread by root and by copy; Entry.joined's own effect; the exploited guard alone; equal range (fixed, tests; each mutation-checked)
  - S rollback command printed and replaced nothing (fixed: jq to a file and mv)
  - S busy test settles through resolve, not a later run (rebutted: deferral and settlement are the generic, tested paths; resolve stands for the settle that jsje's tests cover)
  - S rollback loses the range rule for joined threads (rebutted: accepted and written down; a rollback puts back the older behaviour, the release session decides)
  - C plan text: `joined` passed on; `was.affected` (code already right; plan fixed)
Pass 1 [code:join]: 3B/3S/2C/0R · fixed -/- · velocity = (—→8, escalation no)   (Stage 1 same-model subagent ∥ Stage 2 fresheyes gpt-6.1-sol high, whole branch origin/main...4a9293f, REASON=-)
  - B (S2) once joined, a member's later louder evidence (its GHSA, a KEV listing) was absorbed: joined ids kept as groups, never published; a louder sighting leaves (unjoin) and posts alone (fixed, tests)
  - B (S2) a run stopped between the join and journaling the widening lost it: every sighting of a joined member keeps the join's range rule (fixed, test)
  - B (S1) a failed read of the newcomer's own advisory let a louder one join for good: no join without its reading (`_judged`) (fixed, test)
  - S (S1) a joined member's later KEV listing raised the thread: KEV readings tied to the first id on a joined thread, and the leave rule (fixed, test)
  - S (S1) retraction check skipped learned ids (fixed with the plan B above)
  - S (S1) mirror-root path untested; a joined reply replaced the upstream severity word (fixed: tests; the word stays the thread's)
  - C (S1) spec's chunk claim false (fixed); two test nits (fixed)
  - S1 also: learn_floor takes a joined member's prose floor (rebutted: the in-run group does the same; the floor only stops a lowering, the safe direction)
  passes: 1 · BLOCKER fixes changed behaviour: one delta (fresheyes --since 4a9293f) follows
Pass 2 [code:join]: 4B/0S/0C/0R · fixed 6/6 prior · velocity ↓ (8→4, escalation no)   (delta: fresheyes --since 4a9293f --rebuttals, at 4d3f244, gpt-6.1-sol high, REASON=-; no standing rebuttal overturned)
  - B a joined advisory's fix corrected past the thread's was dropped: it leaves when its fix is later or incomparable (fixed, test; an older fix stays, test)
  - B a failed GHSA read kept a KEV-listed joined advisory in: the exploited mark needs no read (fixed, test)
  - B an id learned by the busy thread's work became the thread's own: no learning on a joined advisory's sightings (fixed, test)
  - B two advisories joined together were one group: one group per member (fixed, test)
  Each delta fix mutation-checked. No further pass (review cycle: the delta is the last).

## Chunks
- [ ] join — Run.one finds the open thread of the candidate's fix; plan_known widens its range; ledger `joined`

## Notes
- Built while the spec review ran (no Agency tools here); the spec findings were folded into spec, plan and code before any commit. The plan's one review runs beside the code review, on the plan as amended.
- Existing tests changed (btqg: another fix, another thread): test_recompute x3, test_wording x2, test_end_to_end x1, test_main x2. Each posted a second advisory with the same fix in a later run and needed a second root.
- Mutation check: with the shared-former-name filter off, test_a_shared_former_name_thread_is_never_joined_by_fix fails.
- Base 3d376b8 (main). Not repoman-managed (no .repoman-managed): PR, gate scripts/test-gate.sh, self-merge with --author-email (xrx2 closed).
- ai-tools-alerts#z360 (partial retraction of a fix group) is in flight on another host and touches the same files; merge main before review and before merge.
