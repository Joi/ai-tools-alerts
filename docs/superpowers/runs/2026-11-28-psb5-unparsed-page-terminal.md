# Run: psb5-unparsed-page-terminal
Instruction: Read TASK-ai-tools-alerts#psb5.md in this worktree root, then run `kata show ai-tools-alerts#psb5` and follow the brief and the dispatch rules (do-it, start rung floored at medium; landing per the brief: scripts/test-gate.sh, one independent review, a PR merged with the no-reply author, the issue closed on the merge commit).
Stage: spec
Rung: medium (start-floor medium: dispatch floor)
Lens: "the service runs with no human in the loop. Nothing you build may wait for a person to act." (carried in every review prompt)
Spec: docs/superpowers/specs/2026-11-28-psb5-unparsed-page-terminal-design.md   Plan: docs/superpowers/plans/2026-11-28-psb5-unparsed-page-terminal.md
Agency project: —
Kata: ai-tools-alerts#psb5
Limits: wall clock 5 hours; one independent pass per artifact, one delta when a BLOCKER fix changed behaviour; completion check: a test over repeated runs where a repository advisory page never parses and the candidate leaves the deferred list at RETRY_DAYS from first sight, as a held notice when the page names the id and the product, else dropped and counted.
Last reviewed: —

## Scorecards

## Chunks
- [ ] terminal — an unparsed page past RETRY_DAYS is read by the vendor-site rule or dropped; tests

## Notes
- No `.repoman-managed` marker and no `AGENTS.md` in this repo: the landing is the brief's (gate, one independent review, a pull request merged by this session).
