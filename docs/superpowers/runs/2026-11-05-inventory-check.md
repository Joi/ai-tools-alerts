# Run: inventory-check
Instruction: start at medium. Task: ai-tools-alerts#0xrc (A4) per TASK-ai-tools-alerts#0xrc.md — inventory.py, check.py, versions.py with tests and fixtures, per docs/plan.md Task A4. Not repoman-managed; non-repoman ending (ff-merge to main, close issue). Security-shaped: FRESHEYES_GPT_MODEL=gpt-6-astra.
Stage: done
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
Pass 2 [code:chunk1 delta]: 0B/3S/0C/0R · fixed 6/6 prior · velocity ↓ (12→3, escalation no)   # fresheyes gpt-6-astra --since 51b6bce8 (REASON=-). Reported as 3 major; all three concern the defence-in-depth re-check of a hand-built Match or the cosmetic dedupe, none reachable through match() → SUBSTANTIVE. All fixed: dedupe key now includes affected/fixed (different constraints each match); plan requires the product in adv.products and each action in adv.actions; plan requires a range and that a tool installation is its ecosystem's tool (_owns). Last pass (Review Cycle: no further pass).

## Chunks
- [x] chunk 1 — versions, inventory, check, tests, fixtures (022ba42 + review fixes b08dd84, b039ae5 after rebase on 85d954e)

## Notes
- kata search "inventory matching": only 0xrc itself. capability-search inventory/version: no overlapping tool. Prior runs (spec-files, alerts-bootstrap) set conventions: stdlib only, scripts/test-gate.sh, Agency MCP absent, spec+plan reviewed in one fresheyes pass.
- Rebased on origin/main 85d954e (A3 landed). Pre-rebase shas: 51b6bce→022ba42 (whole-branch review), 3fdc379→b08dd84 (delta reviewed --since 51b6bce), 0a07637→b039ae5 (delta's fixes; no further pass per Review Cycle). Gate on rebased head: 318 passed.
- Acceptance on this Mac: inventory.collect() printed all 19 scope ecosystem keys in 0.2 s. Leak grep over the diff for fleet host names: no hit. Fixture skill/MCP names overlap the real ones: 0.
- Start floor heavy (evaluator) above the instruction's "start at medium"; heavy added only the delta pass, which the Review Cycle also requires.
