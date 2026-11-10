# Run: kev-no-fix-wording
Instruction: Read TASK-ai-tools-alerts#4yr1.md in this worktree root, then run `kata show ai-tools-alerts#4yr1` and follow the brief and the dispatch rules (dispatch kickoff, mode do-it, rung floored at medium).
Stage: code-review:wording
Rung: medium (start-floor medium: constraint-lens, BR1 REV1 NOV0 INT0 FC1 = 3; dispatch floor medium too)
Lens: "Fixed in X" / 修正版: X and the unexpressed branch byte-identical to today; no live post to test; already-posted roots not rewritten
Last reviewed: spec 082adaf305df29864e4bbab7d9d2baaa84d26dca
Last reviewed: plan fb656907e368fbc7264b04cf0166b5e17cb877b7
Spec: docs/superpowers/specs/2026-11-11-kev-no-fix-wording-design.md   Plan: docs/superpowers/plans/2026-11-11-kev-no-fix-wording.md
Agency project: — (no Agency MCP tools in this session; executed directly, test first, as mz81 did)
Kata: ai-tools-alerts#4yr1

## Scorecards
Pass 1 [spec]: 0B/6S/0C/0R · fixed -/- · velocity = (—→6, escalation no)   (fresheyes gpt-6.1-sol high, snapshot 082adaf; fixed 4: exploited state passed from main.py because plan_known keeps the title when the level does not rise; curator._body and main._advisory_text now say "No fixed version stated."; tests named in the spec; rollback names the uv source directory. Rebutted 2: (a) an upstream title saying "no fix" is the source's own words, quoted on its own line, not the poster's claim — rewriting it would misquote the source; (b) snapshot commit message "do-it review snapshot" is a dangling review snapshot that never lands.)
passes: 1 · spec
Pass 1 [plan]: 0B/3S/0C/0R · fixed -/- · velocity = (—→3, escalation no)   (fresheyes gpt-6.1-sol high, snapshot fb65690; fixed 2: main.py/curator.py implementation step scheduled before the grep; deployment host and home paths removed from spec and plan so the public scan passes. Rebutted 1: snapshot commit message, as in the spec pass.)
passes: 1 · plan

## Chunks
- [x] wording — compose.py root (en, ja), digest nofix, README sentence, CHANGELOG, tests

## Notes
- Not repoman-managed (no .repoman-managed, no registry row): the k5tr lane. Gate is scripts/test-gate.sh (public scan, then the whole suite).
- mz81 already landed on origin/main (bc02d3d), which is this branch's base: no rebase needed.
- roborev: this repo is not enrolled (`roborev repo list` lists no ai-tools-alerts), so a behaviour-changing BLOCKER fix after the code pass takes one fresheyes delta --since before the push.
