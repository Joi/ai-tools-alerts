# Run: severity-tier1
Instruction: ai-tools-alerts#0vy7 per TASK-ai-tools-alerts#0vy7.md — a new reason `severity-tier1` in rules.level_for: tier 1, no critical rule applies, advisory_severity normalised is `high` or `critical` on a candidate carrying a CVE or GHSA id → ("high", "severity-tier1"), no fixed required, fix-rce-tier1 checked first, critical reserved for the three rules; docs/plan.md Global Constraints and Task B2 (notice: on the issue); tests in tests/poster/test_rules.py including the cfe8-shaped collector acceptance. Under 150 changed lines. Dispatched as /do-it, starting rung floored at medium. Not repoman-managed; non-repoman ending.
Stage: code-review
Rung: medium (start-floor medium: dispatch floor; evaluator below)
Spec: docs/superpowers/specs/2026-11-07-severity-tier1-design.md   Plan: docs/superpowers/plans/2026-11-07-severity-tier1.md
Agency project: — (executed inline, as the earlier tasks did)
Kata: ai-tools-alerts#0vy7
Last reviewed: —
Pre-handoff review: — (not repoman-managed)

## Scorecards

## Chunks
- [ ] chunk 1 — rule, tests, docs

## Notes
- kata search "severity tier1 level rule high": only 0vy7 and h2gf (B3, closed). capability-search "advisory severity level": no tool overlap.
- Code written alongside the spec and plan, as earlier tasks did; spec, plan and code are reviewed in one whole-branch fresheyes pass.
- Existing assertion changed: test_fix_rce_tier1_is_high's `"CRITICAL"` with a fix was notice and is now severity-tier1 high; that is the rule.
