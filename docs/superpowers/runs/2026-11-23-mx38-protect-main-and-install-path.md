# Run: mx38-protect-main-and-install-path
Instruction: Read TASK-ai-tools-alerts#mx38.md in this worktree root, then run `kata show ai-tools-alerts#mx38` and follow the brief and the dispatch rules (do-it, starting rung floored at medium; not repoman-managed: scripts/test-gate.sh, one independent review on gpt-6-astra, PR, merge by this session, close on the merge commit).
Stage: spec-review
Rung: heavy (start-floor heavy: hard-trigger live deploy path — the install path and live ruleset state; evaluator BR2 REV2 NOV1 INT2 FC2 = 9; dispatch floor medium)
Lens: "ops/vm README verifies buzz-send against a signed tag never origin/main"; "signed commits required on main, pull requests required"; "public-scan.sh scans every commit message and blob reachable from every ref"
Spec: docs/superpowers/specs/2026-11-23-mx38-protect-main-and-install-path-design.md   Plan: docs/superpowers/plans/2026-11-23-mx38-protect-main-and-install-path.md
Agency project: — (no agency MCP tools in this session; execution is direct, per task, with the plan's verification commands)
Kata: ai-tools-alerts#mx38
Last reviewed: spec bc6afdb69227e31aaa7f3a945fe070a54c3bff9d (delta of 1f0c809ff6bc157f2e242e0df09cd8213d35fffc)

## Scorecards
Pass 1 [spec]: 2B/7S/0C/0R · fixed -/- · velocity = (—→9, escalation no)   (fresheyes gpt-6-astra high, snapshot 1f0c809f, REASON=-)
  B1 rebutted with follow-ups: required_signatures accepts any verified signer and GitHub signs its own merges; with one account a stolen merge-capable token still changes main. Spec now states it ("What the rules do not stop"); a second-origin pin and a base-branch signer check are filed.
  B2 fixed: every VM install input from one verified export ($rel).
  S fixed: release-agnostic Install section; tree-entry name scan; GIT_NO_REPLACE_OBJECTS; names exempt only through their tree, refs never; --hit-ids prints ids only; signer test migration named. S rebutted: snapshot commit message (dangling, never lands).
  spec passes: 1 · elapsed ~20 min
Pass 2 [spec]: 0B/2S/0C/0R · fixed 7/8 prior · velocity ↓ (9→2, escalation no)   (fresheyes gpt-6-astra high, delta 1f0c809f..bc6afdb6 with --rebuttals, REASON=-; neither rebuttal overturned)
  S fixed: stale install-block wording in the spec; full historical paths (a term spanning directories) — diff-tree --diff-filter=A pass, known through the adding commit. Last spec pass.
Pass 1 [plan]: 0B/7S/0C/0R · fixed -/- · velocity = (—→7, escalation no)   (fresheyes gpt-6-astra high, snapshot 0d6d3f72, REASON=-)
  all fixed: ruleset update is PUT with the existing scope kept and read back; per-Mac signing proof and GitHub verified:true for every branch commit; refusal proof with a new signed child of origin/main and the PR-rule message; tag target R recorded, merged and ancestor-checked; Quick install installs in the prompt itself (v0.1.4's README has the old layout); VM block chained so $rel exists only after both checks; known file built as a baseline, nothing from origin/main..HEAD (checked: 0).
Pass 1 [code:branch]: 0B/7S/7C/0R · fixed -/- · velocity = (—→14, escalation no)   (Stage 2 fresheyes gpt-6-astra high on origin/main...0d6d3f72, REASON=-: 7 major; Stage 1 same-model subagent: 0B/5S/7C)
  Stage 2 fixed: hand-off to the pinned tree's old README (install now in the prompt); VM block continues after a failed check (chained, ${rel:?}, negative tests for an unsigned tag and a signed tag on the wrong commit); --hit-ids diagnostics withhold paths; detached HEAD with no named ref is scanned; trees a tag names directly get full paths; plan PUT and refusal proof (same as plan pass).
  Stage 1 fixed: S2 remote pipx route now requires the checkout first; S3 same as hand-off; S4 same as VM block; S5 downgrade — the prompt and verify section require the pinned tag to be the newest v* tag. S1 partly: known objects that only local refs reach are now counted on stderr; not made fatal, because one fleet clone's local branches hold 402 pre-rewrite objects and a fatal check would stop every landing until tppb's purge.
  Cosmetic fixed: CODEOWNERS adds aitools_alerts/, mirror/, scripts/; header notes shallow clones and refs/pull; guard hash check says which machine; spec no longer names the private issue's content; install-line test covers .git@ and pip install git+. Not changed: gpgsig scanned raw (fails safe), raw control characters in printed names, stderr/stdout ordering when piped.

## Chunks
- [ ] 1 install path (README, mirror PIPX_LINE, pyproject pin, ops/vm/README, version 0.1.5, CHANGELOG)
- [ ] 2 SECURITY.md and CODEOWNERS
- [ ] 3 public scan over history
- [ ] 4 land by PR, tag v0.1.5, pin commit by PR, rulesets, fleet signing, slice comments

## Notes
- Prior work: kata search found b9mz (signed tags, allowed_signers), tppb (H6 history leak; M6 correction comment 79663t), z5wb (the review). docs/superpowers/runs/2026-11-06-release-tag-verification.md is the verify-section design this run extends.
