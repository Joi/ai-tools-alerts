# Run: curator-translation-mention-guard
Instruction: Read TASK-ai-tools-alerts#mz81.md in this worktree root, then run `kata show ai-tools-alerts#mz81` and follow the brief and the dispatch rules (dispatch kickoff, mode do-it, rung floored at medium).
Stage: committing
Rung: medium (start-floor medium: constraint-lens, BR1 REV1 NOV1 INT1 FC1 = 5; dispatch floor medium too)
Lens: "a curator text with its own code spans or a lone backtick is not damaged"; "Fire no live post to test; verify with fixtures only"
Spec: docs/superpowers/specs/2026-11-11-curator-translation-mention-guard-design.md   Plan: docs/superpowers/plans/2026-11-11-curator-translation-mention-guard.md
Agency project: — (no Agency MCP tools in this session and no agency server on this host; executed directly, test first)
Kata: ai-tools-alerts#mz81
Last reviewed: spec caf4f73036b6feec5adf3cd9f149671f2782f4b1
Last reviewed: plan 427dfbdb781bca8d2f04e9abcaba680657f86ab4
Last reviewed: code 99f74e3c3130ec0764443d457ec94a492289efe0 (whole branch at 009c996, delta to 99f74e3)

## Scorecards
Pass 1 [spec]: 0B/3S/0C/0R · fixed -/- · velocity = (—→3, escalation no)   (fresheyes gpt-6.1-sol high, snapshot caf4f73; fixed 2: backslash-before-backtick now irregular + scanner cited; full rollback command. Rebutted 1: snapshot commit message "do-it review snapshot" is a dangling review snapshot that never lands.)
passes: 1 · spec
Pass 1 [plan]: 0B/2S/1C/0R · fixed -/- · velocity = (—→3, escalation no)   (fresheyes gpt-6.1-sol high, snapshot 427dfbd; fixed all 3: the oracle replaces fences with a space like the SDK; red-before-green narrowed to the cases that can fail on the parent, fake outputs keep tokens; oracle stated as known_names=[].)
passes: 1 · plan
Pass 1 [code:guard]: 1B/1S/3C/0R · fixed -/- · velocity = (—→5, escalation no)   (Stage 2 fresheyes gpt-6.1-sol high on origin/main...009c996: 1B fixed — a CR, or a backtick in <...> or a URL, could make a Markdown reader pair backticks otherwise and the wrap land inside a curator span; now irregular, never rewritten. Stage 1 same-model subagent: 1S rebutted — a lone backtick on one line blocks wrapping on the others; fails safe, and a per-line rule would rely on the relay alone where CommonMark pairs across soft line breaks; 3C fixed — \v out of the oracle, upstream vectors and fence edges added, _LIVE_AT comment.)
passes: 1 · code:guard — BLOCKER fix changed behaviour; roborev not enrolled, so one fresheyes delta --since 009c996 before the push
Pass 2 [code:guard]: 1B/0S/0C/0R · fixed 1/2 prior (1 rebutted, unchallenged) · velocity ↓ (5→1, escalation no)   (delta: fresheyes gpt-6.1-sol high --since 009c996 --rebuttals; reviewed head 99f74e3. 1B fixed after it, no further pass by rule: a multi-line HTML tag with a backtick in an attribute; now any < that can open a tag or autolink makes backticked text ambiguous.)
passes: 2 · code:guard (the last)

## Chunks
- [x] guard — compose.mention_safe + translate_curator wiring + tests (009c996; review fix in the next commit)

## Notes
- Not repoman-managed (no .repoman-managed, no registry row): the k5tr lane. Gate is scripts/test-gate.sh (public scan, then the whole suite).
- Agency unavailable: recorded, not a skip of review; the plan's chunk is executed in this session.
- A `fresheyes.sh --help` probe launched a detached review with "--help" as its scope (handle 20261111-063340-e23a09); its process group was terminated within a minute. Not a review pass; not counted.
