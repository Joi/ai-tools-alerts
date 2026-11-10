# Run: curator-translation-mention-guard
Instruction: Read TASK-ai-tools-alerts#mz81.md in this worktree root, then run `kata show ai-tools-alerts#mz81` and follow the brief and the dispatch rules (dispatch kickoff, mode do-it, rung floored at medium).
Stage: plan-review
Rung: medium (start-floor medium: constraint-lens, BR1 REV1 NOV1 INT1 FC1 = 5; dispatch floor medium too)
Lens: "a curator text with its own code spans or a lone backtick is not damaged"; "Fire no live post to test; verify with fixtures only"
Spec: docs/superpowers/specs/2026-11-11-curator-translation-mention-guard-design.md   Plan: docs/superpowers/plans/2026-11-11-curator-translation-mention-guard.md
Agency project: — (no Agency MCP tools in this session and no agency server on this host; executed directly, test first)
Kata: ai-tools-alerts#mz81
Last reviewed: spec caf4f73036b6feec5adf3cd9f149671f2782f4b1
Last reviewed: plan 427dfbdb781bca8d2f04e9abcaba680657f86ab4

## Scorecards
Pass 1 [spec]: 0B/3S/0C/0R · fixed -/- · velocity = (—→3, escalation no)   (fresheyes gpt-6.1-sol high, snapshot caf4f73; fixed 2: backslash-before-backtick now irregular + scanner cited; full rollback command. Rebutted 1: snapshot commit message "do-it review snapshot" is a dangling review snapshot that never lands.)
passes: 1 · spec
Pass 1 [plan]: 0B/2S/1C/0R · fixed -/- · velocity = (—→3, escalation no)   (fresheyes gpt-6.1-sol high, snapshot 427dfbd; fixed all 3: the oracle replaces fences with a space like the SDK; red-before-green narrowed to the cases that can fail on the parent, fake outputs keep tokens; oracle stated as known_names=[].)
passes: 1 · plan

## Chunks
- [ ] guard — compose.mention_safe + translate_curator wiring + tests

## Notes
- Not repoman-managed (no .repoman-managed, no registry row): the k5tr lane. Gate is scripts/test-gate.sh (public scan, then the whole suite).
- Agency unavailable: recorded, not a skip of review; the plan's chunk is executed in this session.
- A `fresheyes.sh --help` probe launched a detached review with "--help" as its scope (handle 20261111-063340-e23a09); its process group was terminated within a minute. Not a review pass; not counted.
