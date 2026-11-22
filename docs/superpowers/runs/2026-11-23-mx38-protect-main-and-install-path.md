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

## Chunks
- [ ] 1 install path (README, mirror PIPX_LINE, pyproject pin, ops/vm/README, version 0.1.5, CHANGELOG)
- [ ] 2 SECURITY.md and CODEOWNERS
- [ ] 3 public scan over history
- [ ] 4 land by PR, tag v0.1.5, pin commit by PR, rulesets, fleet signing, slice comments

## Notes
- Prior work: kata search found b9mz (signed tags, allowed_signers), tppb (H6 history leak; M6 correction comment 79663t), z5wb (the review). docs/superpowers/runs/2026-11-06-release-tag-verification.md is the verify-section design this run extends.
