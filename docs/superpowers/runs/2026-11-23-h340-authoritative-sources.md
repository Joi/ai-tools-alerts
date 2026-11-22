# Run: h340-authoritative-sources
Instruction: ai-tools-alerts#h340 (starting rung floored at medium; repoman lane). Brief: `TASK-ai-tools-alerts#h340.md` — the poster signs only what an authoritative source says; do every item of the issue's fix list.
Stage: spec
Rung: medium (start-floor medium: dispatch brief; security-shaped, so the review model is gpt-6-astra)
Spec: docs/superpowers/specs/2026-11-23-h340-authoritative-sources-design.md   Plan: docs/superpowers/plans/2026-11-23-h340-authoritative-sources.md
Agency project: — (no agency tools in this session; the plan is executed directly)
Kata: ai-tools-alerts#h340
Wall-clock limit: 6 h. Review shape: one independent pass per artifact, one delta only when a BLOCKER fix changed behaviour. Completion check: `scripts/test-gate.sh` green and the claude-code-router regression test passing.

## Scorecards

## Chunks
- [ ] exact scope identity, authority and evidence, signed wording, tests, docs (one chunk: the whole branch)

## Notes
- Not repoman-managed (no `.repoman-managed`): the ending is the brief's — `scripts/test-gate.sh`, one independent review, pull request, merge, close on the merge commit.
- Prior work searched in kata: ai-tools-alerts#s6mt (the authoritative-source table and a ruleset file, later; this run's `authority` lists are what it will move), ai-tools-alerts#h29n comments D2 and D3 (KEV matched on CISA's vendor and product fields only; a source the subject's attacker can write never sets a level above notice). `capability-search` lives outside this worktree and the seat rules forbid reading there; not run.
- Seat rules: only this worktree and the scratchpad are read. The do-it skill's own files and the fresheyes script are run because the brief orders both.
- Split rule: the diff will pass 600 lines. Kept as one issue: see the `decided:` comment on h340.
