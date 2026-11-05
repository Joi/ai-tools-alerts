# Run: primary-source-output
Instruction: Read TASK-ai-tools-alerts#h260.md in this worktree root, then run `kata show ai-tools-alerts#h260` and follow the brief and the dispatch rules (/do-it, starting rung floored at medium; not repoman-managed: ff-merge ending).
Stage: code-review:whole-branch
Rung: medium (start-floor medium: dispatch floor; evaluator agrees: BR1 REV1 NOV1 INT1 FC1 = 5, external contract (JSON read by agents) + runtime-supplied URLs; Hard-trigger none; Lens none)
Spec: docs/superpowers/specs/2026-11-05-primary-source-output-design.md   Plan: docs/superpowers/plans/2026-11-05-primary-source-output.md
Agency project: — (executed inline, as A1 to A7 did)
Kata: ai-tools-alerts#h260
Last reviewed: —
Pre-handoff review: — (not repoman-managed)

## Scorecards
Pass 1 [spec+plan]: 0B/1S/0C/1R · fixed -/- · velocity = (—→2, escalation no)   # fresheyes gpt-6-astra on snapshot 74b58e3 (REASON=-), 2 reported "major". SUBSTANTIVE fixed: plan output not tested at the agent-facing boundary (a raw URL in cmd_plan would pass) and second-primary not tested through JSON → end-to-end test through a signed relay-bot post asserts the full encoded `source:` line, one `command:` line, and JSON `source`/`sources`; mutation (raw URL in cmd_plan) verified to fail it. R (rebutted): snapshot commit message "do-it review snapshot" — a dangling review snapshot, never on a branch; same rebuttal as A2, A4, A5, A6. The reviewer found no encoding bypass.
passes: spec+plan 1. Medium rung: no spec/plan delta; the whole-branch code pass reviews the fixed spec and plan with the code.

## Chunks
- [ ] chunk 1 — cli.py, skills, snippet, tests

## Notes
- kata search "primary source plan json": only h260 itself and the closed A/B tasks; no prior attempt. Prior rule reused: poster/compose._primary (first is_primary, else first).
