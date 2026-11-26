# Run: 2mgd-unjudgeable-by-construction
Instruction: Read TASK-ai-tools-alerts#2mgd.md in this worktree root, then run `kata show ai-tools-alerts#2mgd` and follow the brief and the dispatch rules (run as /do-it, starting rung floored at medium).
Stage: done
Rung: medium (start-floor medium: constraint-lens, BR1 REV1 NOV1 INT1 FC1 = 5; the dispatch floors it at medium too)
Lens: "no human in the loop"; "Stay inside this issue"; "Public repo; no rollout"
Last reviewed: spec b8f9cc7ae0b7e5f7befbfab5b60db0053962fe8d
Last reviewed: plan 8192babc3c9faab38b10c1acfe6187856aadf353
Last reviewed: code f1f8d8e0db5c2b4dbe636e9326a83d945ad38a1b (whole branch, `git diff origin/main...f1f8d8e`; main cd3dbe5 merged in)
Agency project: 01a215b6-bcba-704a-9957-5d9946532c07 (three tasks, each evaluated)
Spec: docs/superpowers/specs/2026-11-26-2mgd-unjudgeable-by-construction-design.md   Plan: docs/superpowers/plans/2026-11-26-2mgd-unjudgeable-by-construction.md
Agency project: —
Kata: ai-tools-alerts#2mgd
Limits: wall clock 5 hours from 2026-11-26T02:14Z; one independent review per artifact (spec, plan, code), one delta only after a behaviour-changing BLOCKER fix; completion check: the acceptance cases of the issue pass as tests in `scripts/test-gate.sh`.
Landing: this repo has no `.repoman-managed` marker, so the brief's landing applies: `scripts/test-gate.sh`, one independent review, a pull request this session merges.

## Scorecards
Pass 1 [spec]: 2B/4S/1C/0R · fixed -/- · velocity = (—→7, escalation no)
spec — passes: 1 · elapsed: 9 min. Fixed 6/6 in the spec text (see its Review section); the cosmetic one (the snapshot commit's message) rebutted: the snapshot is a dangling review object, never pushed.
Pass 1 [plan]: 1B/6S/0C/0R · fixed -/- · velocity = (—→7, escalation no)
plan — passes: 1 · elapsed: 8 min. Blocker (pull history keyed by name) and two substantive (budget fallback, test migration) fixed in the plan; four substantive on alias scheduling moved with the alias half to ai-tools-alerts#nx25 (split, `notice:` comment on 2mgd).
Pass 1 [code:whole-branch]: 1B/3S/3C/0R · fixed -/- · velocity = (—→7, escalation no)
code — Stage 2 (fresheyes, gpt-6.1-sol, f1f8d8e): 1 blocker. Stage 1 (same-model subagent): the same blocker, 3 substantive, 3 cosmetic. Fixed in 51ed724: the blocker (match dedup hid a judgeable entry behind an MCP server key), the empty scope table (S4), the test gaps and the docstring (C6, C7). Rebutted: S2 (release order, documented), S3 (synthetic check, documented and tested), C5 (`verify.claimed` by posted name fails closed; outside the issue).
Rung: climbs medium → heavy (cause: a BLOCKER after the medium pass whose fix changed behaviour); the one delta pass runs `--since f1f8d8e` with the rebuttals.
Pass 2 [code:whole-branch]: 0B/0S/0C/0R · fixed 1/1 prior · velocity ↓ (7→0, escalation no)
code — delta (fresheyes, gpt-6.1-sol, `--since f1f8d8e`, reviewed head 51ed724): passed, no finding, no rebuttal overturned.
Gate: `scripts/test-gate.sh` on f1f8d8e: 2 failed (tests/test_cli.py, a relay-bot fixture whose id names no source, under its own pin: the new rule), 2996 passed. On 82288c1: 3007 passed, public scan clean.
After the reviewed head 51ed724: 82288c1 (tests only: that fixture's expected exit status), then this record.

## Chunks
- [x] identity in check, verify and pull (2650112)
- [x] cli: a match that cannot be judged does not interrupt; buckets and lines by scope name (2650112)
- [x] docs: CHANGELOG, README (2650112; main merged at dc03614, f1f8d8e)

## Notes
- Skip temptations: none. The alias half was split to ai-tools-alerts#nx25 after the plan review (size rule and a design that needed its own review), by a `notice:` comment.
- Watchdog: five fresheyes runs, each FRESHEYES_DONE REASON=-; no stall.
- Prior work read: issue 2mgd, 0z4e (in flight on another branch, not pushed; touches cli.py and verify.py), specs fv4g, tavj, jsje, c1g2 in docs/superpowers/specs.
