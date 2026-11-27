# Run: aabw-former-names-both-sides
Instruction: ai-tools-alerts#aabw (starting rung floored at medium, never light): a thread under a product's former name is never recomputed by the poster nor confirmed by a member's check; decide how a former name is read, on both sides at once
Stage: code-review:former-names
Rung: medium (start-floor medium: constraint-lens, BR2 REV2 NOV1 INT1 FC1 = 7; the dispatch brief floors it at medium too)
Lens: "the service runs with no human in the loop; nothing you build may wait for a person to act"; "no rollout, no install, no signing step, no release in this work"
Last reviewed: spec f44bc56ea7a5d444875acf6e407e7b075eee9745
Last reviewed: plan 2af413ec18310519cb199be33d26838a97a8d3e8
Spec: docs/superpowers/specs/2026-11-27-aabw-former-names-both-sides-design.md   Plan: docs/superpowers/plans/2026-11-27-aabw-former-names-both-sides.md
Agency project: — (no Agency tools on this seat's session; the chunk was built inline)
Kata: ai-tools-alerts#aabw
Limits: wall clock 5 hours from the 2026-11-26T20:27Z dispatch; review shape one independent pass per artifact (fleet default reviewer) and one delta only after a behaviour-changing BLOCKER fix, three review rounds at most; completion check `scripts/test-gate.sh` green and the pull request merged with the no-reply author.

## Scorecards
Pass 1 [spec]: 1B/2S/1C/0R · fixed -/- · velocity = (—→4, escalation no)
spec passes: 1 · reviewer gpt-6.1-sol at high (fresheyes run 20261127-053215-bad03b, REASON=-) · the BLOCKER fixed (criterion 7 names the cache-version test as a third test that changes, and that test now carries a stored `no-source`), one SUBSTANTIVE fixed (a renewal test for an enrolled former-name thread), one rebutted (the throwaway snapshot's message: a dangling commit made for the reviewer, on no branch, never lands), the COSMETIC fixed (10 requests, not 20); nothing survives, so the rung stays medium
Pass 1 [plan]: 1B/3S/0C/0R · fixed -/- · velocity = (—→4, escalation no)
plan passes: 1 · reviewer gpt-6.1-sol at high (fresheyes run 20261127-053852-24ce69, REASON=-) · all four fixed: the BLOCKER in the plan's text (the fixture as built already carried `root_ids`), two SUBSTANTIVE by a new test each (mutations 11 and 12 now fail one), one in the landing steps (fetch before the author check); nothing survives, so the rung stays medium

## Chunks
- [ ] former-names: the ruleset says what a name stands for; the member's check and the recompute read a former name by it; tests, changelog

## Notes
- The 5-hour wall clock passed while the seat's usage limit held the session (stopped about 2026-11-26T20:50Z, resumed 2026-11-27T12:00Z on a written instruction to continue through the merge and the close). Main had not moved: `origin/main` is still `dd4d195`.
- Agency: `mcp__agency__*` is not among this session's tools, so the one chunk was built inline, first in a copy of the tree outside the worktree while the spec and plan reviews read the worktree.
- A stray review: `fresheyes.sh --help` is not a help flag; it started a review of the text "--help" (run 20261127-053151-3e1392). Stopped within a minute by ending its own process group; no finding was read from it.
- Found after the spec review, while writing the changelog: `cli._source_lines` printed nothing for a former name, and `_shown` would show such an alert at notice with no line. Fixed with a test (spec "Member: cli.py").
- Mutations, each failing the test the plan names: 1, 2, 4 to 13. Mutation 3 (the KEV line by `scope.name`) survives: no entry that lists a former name has a KEV identity.
- The repository has no repoman marker: the run ends with a pull request this session merges, as the brief says, not a repoman handoff.
