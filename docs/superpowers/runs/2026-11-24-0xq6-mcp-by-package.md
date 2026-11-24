# Run: 0xq6-mcp-by-package
Instruction: Read TASK-ai-tools-alerts#0xq6.md in this worktree root, then run `kata show ai-tools-alerts#0xq6` and follow the brief and the dispatch rules (do-it, starting rung floored at medium).
Stage: committing (PR)
Rung: medium (start-floor medium: dispatch floor; evaluator BR1 REV1 NOV1 INT2 FC1 = 6, medium)
Lens: "Additive schema only; a v0.1.x reader ignores the new fields."
Spec: docs/superpowers/specs/2026-11-24-0xq6-mcp-by-package-design.md   Plan: docs/superpowers/plans/2026-11-24-0xq6-mcp-by-package.md
Agency project: —
Kata: ai-tools-alerts#0xq6
Last reviewed: spec 4909e9e7c78bb8e20c3b78112322ddec086f465f
Last reviewed: plan 895562d63f49e03b09872628eeeee07b9dd49b9c

## Scorecards
Pass 1 [spec]: 1B/5S/0C/0R · fixed -/- · velocity = (—→6, escalation no)   # fresheyes gpt-6.1-sol high, run 20261124-221023-035acf
  B1 fixed (covers: no-bound covers only itself; criterion 12). S2 fixed (match dedupe on whole Installed; criterion 13). S3 fixed (unparsable-version kept; criterion 8 reworded). S4 fixed (one record per server key). S5 fixed (criterion 9 limited to no readable version). S6 rebutted: the reviewed commit is a dangling review snapshot from commit-tree, never on a branch; its message is not a landed commit message.
  passes: 1 · medium: no delta
Pass 1 [plan]: 2B/1S/0C/0R · fixed -/- · velocity = (—→3, escalation no)   # fresheyes gpt-6.1-sol high, run 20261124-221709-d27286
  B1 fixed (test_bot_patch expectations named and rule for updating them). B2 fixed (collect_hermes(home, name), tested via collect()). S1 fixed (source-qualified product names never match a source-less installation).
  passes: 1 · medium: no delta

Pass 1 [code:whole-branch]: 1B/5S/6C/0R · fixed -/- · velocity = (—→12, escalation no)   # fresheyes run 20261124-223254-60e75a (1B/4S) + Stage-1 subagent (0B/2S new + 1 design note/6C); reviewed head 19f3103
  B1 fixed (reason in the dedupe key). S Hermes 0.0.0 fixed. S repeated --package fixed. S scoped plugin fixed. S command-level tests added. S (Stage-1) npm partial pin fixed. Stage-1 design note (name-only malware may apply) rebutted: design rule, now stated in the spec. Cosmetics fixed: registry options, tarballs, relative paths, --refresh/--prefer-online. Cosmetics rebutted: PEP 503 product names (latent), installed.source naming, openclaw side effects (to rollout issue).
  Gate on 19f3103: scripts/test-gate.sh pass, 2360 passed. Fix commit c896ebf.
Pass 2 [code:delta]: 0B/0S/1C/0R · fixed 7/7 prior · velocity ↓ (12→1, escalation no)   # fresheyes --since 19f3103 --rebuttals (4), run 20261124-224138-0e16fc, PASSED; no rebuttal overturned
  Nit (match docstring) fixed doc-only after the delta.
  Gate on c896ebf: scripts/test-gate.sh pass, 2379 passed.

## Chunks
- [x] inventory: MCP server commands to packages; Hermes and OpenClaw probes; plugin source (e354ced)
- [x] check + CLI: package and source identity; "may apply" never interrupts; docs (a19556f)
- [x] review fixes (c896ebf)

## Notes
- Prior work: kata 9mx8 (design section 8), wa6n (package carrier is spec/scope.json, PR 23), t8jr (no new block key), h29n. capability-search not rerun: this builds no new tool.
- xrx2 (no-reply merge author) is closed: merging with --author-email is allowed again.
- Spec fixes after the spec review were applied with a count-asserting python replace script, not the Edit tool; each replacement asserted exactly one match, so none could silently no-op.
- Merging main brought release 0.1.8; git placed this slice's changelog entry under 0.1.8, moved back under Unreleased (19f3103's parent).
- Follow-ups: gj49 (rollout: release v0.2.0), 1qy4 (Hermes real version), 9x20 (skill marketplace provenance).
- No skip temptations.
