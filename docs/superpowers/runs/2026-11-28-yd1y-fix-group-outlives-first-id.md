# Run: yd1y-fix-group-outlives-first-id
Instruction: Read TASK-ai-tools-alerts#yd1y.md in this worktree root, then run `kata show ai-tools-alerts#yd1y` and follow the brief and the dispatch rules (do-it, start rung floored at medium; pull-request landing; one independent review).
Stage: spec-review
Rung: medium (start-floor medium: dispatch floor; no hard trigger in scope: no secrets, auth or deploy path)
Spec: docs/superpowers/specs/2026-11-28-yd1y-fix-group-outlives-first-id-design.md   Plan: docs/superpowers/plans/2026-11-28-yd1y-fix-group-outlives-first-id.md
Agency project: —
Kata: ai-tools-alerts#yd1y
Limits (recorded before any review): wall clock 5 hours from 2026-11-28T00:35Z; review shape one independent pass per artifact, one delta only after a behaviour-changing BLOCKER fix; completion check: the acceptance test of the issue passes and the pull request is merged or its blocker is named.

## Scorecards

## Chunks
- [ ] release and repost the members of a fix group whose first id fell

## Notes
- Start-floor evaluator not dispatched: the dispatch floors the run at medium and no hard trigger is in scope; as z360, faxq.
- Deviation (as z360, faxq, 9kgk): spec and plan reviewed in one fresheyes pass.
- Agency not used (as every run in this repo): the plan is one chunk executed directly.
- Prior work: kata search "fix group": z360 (partial retraction; its release mechanism is reused), 9je7 (held notices, open), btqg (join by fix; this issue was filed from its spec review), 3qyq (first-id rule), faxq (fix groups). No experiment issue on the subject.
- Dependency: the branch merges origin/z360-fix-z360 at 46ebb37 (pull request 67, open, mergeable). Decision and rejected options: the `decided:` comment on the issue.
- Landed code vs issue text: "steps down at renewal time" is the 44-day step of `Run._renew`.
- The acceptance test and the code were drafted before the spec review, to find out what the release mechanism needed; the review's findings apply to both.
