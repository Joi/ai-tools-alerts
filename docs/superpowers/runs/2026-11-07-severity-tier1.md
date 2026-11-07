# Run: severity-tier1
Instruction: ai-tools-alerts#0vy7 per TASK-ai-tools-alerts#0vy7.md — a new reason `severity-tier1` in rules.level_for: tier 1, no critical rule applies, advisory_severity normalised is `high` or `critical` on a candidate carrying a CVE or GHSA id → ("high", "severity-tier1"), no fixed required, fix-rce-tier1 checked first, critical reserved for the three rules; docs/plan.md Global Constraints and Task B2 (notice: on the issue); tests in tests/poster/test_rules.py including the cfe8-shaped collector acceptance. Under 150 changed lines. Dispatched as /do-it, starting rung floored at medium. Not repoman-managed; non-repoman ending.
Stage: done
Rung: medium (start-floor medium: dispatch floor; evaluator agrees — Hard-trigger none, BR1 REV1 NOV1 INT1 FC1 = 5, prod-shaped; Lens: "Under 150 changed lines"; "critical stays reserved"; "no fix required")
Spec: docs/superpowers/specs/2026-11-07-severity-tier1-design.md   Plan: docs/superpowers/plans/2026-11-07-severity-tier1.md
Agency project: — (executed inline, as the earlier tasks did)
Kata: ai-tools-alerts#0vy7
Last reviewed: whole branch (spec+plan+code) 89f19d4628d1622278c4ed9aecfbd24efc8319a3; delta --since 89f19d4 at 4db5a4c
Pre-handoff review: — (not repoman-managed)

## Scorecards
Pass 1 [code:whole-branch]: 2B/2S/2C/0R · fixed -/- · velocity = (—→6, escalation no)   # origin/main...89f19d4. Stage 2 fresheyes gpt-6.1-sol (REASON=-): 2 major, verdict FAILED, both treated as BLOCKER. Stage 1 subagent: 0B/2S/2C. BLOCKER fixed: ledger.merge joins severities with "; " so "high; critical" fell to notice → level_for compares each ;-part, test_merge_keeps_severity_tier1 through ledger.merge; the plan's tracked verification line spelled out the fleet host names the public scan forbids → removed (the gate passed earlier only because the plan was untracked). SUBSTANTIVE fixed: GHSA/CVE match is case-blind (as pull.py casefolds). SUBSTANTIVE rebutted: a LEAD- id with a CVE alias qualifies (the brief excludes leads with no advisory id; a LEAD- prefix exclusion would drop a real advisory merged behind a lead). COSMETIC: test naming and a docstring line width, not changed.
passes: code 1 whole-branch; delta below.
Pass 2 [code:delta]: 1B/0S/0C/0R · fixed 4/4 prior · velocity ↓ (6→1, escalation no)   # fresheyes --since 89f19d4 --rebuttals (1 standing), gpt-6.1-sol (REASON=-): 1 major, rebuttal not reopened; no runtime defect. BLOCKER fixed (doc only): the plan still described the case-sensitive id and whole-field severity → plan updated. Last pass (Review Cycle).
passes: code 2 (one whole-branch, one delta).

## Chunks
- [x] chunk 1 — rule, tests, docs (89f19d4; review fixes 4db5a4c)

## Notes
- kata search "severity tier1 level rule high": only 0vy7 and h2gf (B3, closed). capability-search "advisory severity level": no tool overlap.
- Code written alongside the spec and plan, as earlier tasks did; spec, plan and code are reviewed in one whole-branch fresheyes pass.
- Existing assertion changed: test_fix_rce_tier1_is_high's `"CRITICAL"` with a fix was notice and is now severity-tier1 high; that is the rule.
- Gate (scripts/test-gate.sh) at 4db5a4c working tree: 1072 passed, 1 skipped; public scan 0. 72 changed lines (numstat, run artifacts excluded). Fleet host-name grep on the diff: 0 hits.
- notice: comment posted on the issue for the Global Constraints change, old and new sentences quoted.
- Landed: origin/main was b33573f (unmoved); final gate at aa0ebeb 1072 passed, 1 skipped; fast-forwarded main to aa0ebeb and pushed. roborev: repo not enrolled, post-push check skipped.
