# Run: inventory-check
Instruction: start at medium. Task: ai-tools-alerts#0xrc (A4) per TASK-ai-tools-alerts#0xrc.md — inventory.py, check.py, versions.py with tests and fixtures, per docs/plan.md Task A4. Not repoman-managed; non-repoman ending (ff-merge to main, close issue). Security-shaped: FRESHEYES_GPT_MODEL=gpt-6-astra.
Stage: code-review:chunk1
Rung: heavy (start-floor heavy: hard-trigger credential handling — the mcp collector parses credential-bearing configs, keeping key names only; BR1 REV0 NOV1 INT1 FC2 = 5; Lens: "No command execution anywhere in this task beyond fixed-argv version probes."; "Plan Task A4 exactly")
Spec: docs/superpowers/specs/2026-11-05-inventory-check-design.md   Plan: docs/superpowers/plans/2026-11-05-inventory-check.md
Agency project: — (mcp__agency__* tools not loaded in this session; executed inline, as A1/A2 did)
Kata: ai-tools-alerts#0xrc
Last reviewed: spec+plan eb9d714d
Pre-handoff review: — (not repoman-managed)

## Scorecards
Pass 1 [spec+plan]: 2B/5S/0C/0R · fixed -/- · velocity = (—→7, escalation no)   # fresheyes gpt-6-astra on snapshot eb9d714d (REASON=-). BLOCKERs fixed: scope match patterns used as tool aliases (containerd vs Docker's version) → IDENTITY table; disable_skill/remove_mcp_server not tied to their ecosystem → verb-ecosystem rule. SUBSTANTIVE fixed: prepared upgrades now carry product.fixed; Match.product defaults to None (four-argument construction works, never auto-applies an upgrade); plan step 2 verification no longer depends on check.py; default_runner test mocks subprocess.run (no real executable). Rebutted: snapshot commit message (a dangling review snapshot, never on a branch; same rebuttal as A2).
passes: spec+plan 1 · heavy delta for the spec/plan BLOCKER fixes is folded into the whole-branch code pass, which reviews the fixed spec, plan and code together (one launch instead of two).

## Chunks
- [x] chunk 1 — versions, inventory, check, tests, fixtures (committed; review pending)

## Notes
- kata search "inventory matching": only 0xrc itself. capability-search inventory/version: no overlapping tool. Prior runs (spec-files, alerts-bootstrap) set conventions: stdlib only, scripts/test-gate.sh, Agency MCP absent, spec+plan reviewed in one fresheyes pass.
