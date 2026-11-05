# Run: inventory-check
Instruction: start at medium. Task: ai-tools-alerts#0xrc (A4) per TASK-ai-tools-alerts#0xrc.md — inventory.py, check.py, versions.py with tests and fixtures, per docs/plan.md Task A4. Not repoman-managed; non-repoman ending (ff-merge to main, close issue). Security-shaped: FRESHEYES_GPT_MODEL=gpt-6-astra.
Stage: code-review:chunk1
Rung: heavy (start-floor heavy: hard-trigger credential handling — the mcp collector parses credential-bearing configs, keeping key names only; BR1 REV0 NOV1 INT1 FC2 = 5; Lens: "No command execution anywhere in this task beyond fixed-argv version probes."; "Plan Task A4 exactly")
Spec: docs/superpowers/specs/2026-11-05-inventory-check-design.md   Plan: docs/superpowers/plans/2026-11-05-inventory-check.md
Agency project: — (mcp__agency__* tools not loaded in this session; executed inline, as A1/A2 did)
Kata: ai-tools-alerts#0xrc
Last reviewed: spec+plan eb9d714d; code (whole branch) 51b6bce8
Pre-handoff review: — (not repoman-managed)

## Scorecards
Pass 1 [spec+plan]: 2B/5S/0C/0R · fixed -/- · velocity = (—→7, escalation no)   # fresheyes gpt-6-astra on snapshot eb9d714d (REASON=-). BLOCKERs fixed: scope match patterns used as tool aliases (containerd vs Docker's version) → IDENTITY table; disable_skill/remove_mcp_server not tied to their ecosystem → verb-ecosystem rule. SUBSTANTIVE fixed: prepared upgrades now carry product.fixed; Match.product defaults to None (four-argument construction works, never auto-applies an upgrade); plan step 2 verification no longer depends on check.py; default_runner test mocks subprocess.run (no real executable). Rebutted: snapshot commit message (a dangling review snapshot, never on a branch; same rebuttal as A2).
passes: spec+plan 1 · heavy delta for the spec/plan BLOCKER fixes is folded into the whole-branch code pass, which reviews the fixed spec, plan and code together (one launch instead of two).
Pass 1 [code:chunk1]: 2B/4S/3C/3R · fixed 6/6 prior · velocity ↑ (7→12, escalation no)   # whole branch at 51b6bce8. Stage 2 fresheyes gpt-6-astra (REASON=-; OUT empty, review read from LOG): 4 major. Stage 1 subagent: 0B/5S/3C (3 overlap fresheyes = the 3R). BLOCKERs fixed: (1) probe regex truncated pre-releases (22.1.0-rc.1 read as 22.1.0, could auto-apply) → token runs to space/comma/paren, unreadable tokens stored raw → unparsable-version; (2) suffix tags compared by spelling (a2 > alpha1: downgrade) → PEP 440 aliases + fixed rank, unknown tag unreadable. SUBSTANTIVE fixed: claude-code/ prefix never reached normalize → accepted in the probe regex; vacuous relay-bot loop test → [m] = ...; plan() trusted a hand-built Match → plan re-checks product, aliases, version range and action ecosystem; no test that name matches never auto-apply → added (plus upgrade naming another tool). COSMETIC fixed: duplicate matches per (adv, ecosystem, name); docstring says A5 builds commands from product.ecosystem; plugin key split on last @.
Escalation: none (every B/S fixed). BLOCKER fixes changed behaviour → one delta pass, fresheyes --since 51b6bce8b3cff9e3504c835de4d9f3539bd24398, no rebuttals (all fixed).

## Chunks
- [x] chunk 1 — versions, inventory, check, tests, fixtures (committed; review pending)

## Notes
- kata search "inventory matching": only 0xrc itself. capability-search inventory/version: no overlapping tool. Prior runs (spec-files, alerts-bootstrap) set conventions: stdlib only, scripts/test-gate.sh, Agency MCP absent, spec+plan reviewed in one fresheyes pass.
