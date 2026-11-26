# Run: 4fkh-no-pypi-install
Instruction: Read TASK-ai-tools-alerts#4fkh.md in this worktree root, then run `kata show ai-tools-alerts#4fkh` and follow the brief and the dispatch rules (do-it, start rung floored at medium; PR landing; one independent review).
Stage: code-review:branch
Rung: medium (start-floor medium: dispatch floor; no hard trigger in scope)
Spec: docs/superpowers/specs/2026-11-26-4fkh-no-pypi-install-design.md   Plan: docs/superpowers/plans/2026-11-26-4fkh-no-pypi-install.md
Agency project: — (no agency MCP tools in this session; executed directly)
Kata: ai-tools-alerts#4fkh
Limits: wall clock 2 hours; review shape one independent pass, one delta only after a behaviour-changing BLOCKER fix; completion check: the guard test fails on the old hint and `scripts/test-gate.sh` passes.

## Scorecards

## Chunks
- [x] text, hint, guard test

## Notes
- Start-floor evaluator not dispatched: the dispatch floors the run at medium and no hard trigger is in scope; it could only raise to heavy on one (as jsje, faxq, 9kgk, qwpw).
- Spec, plan and code reviewed in one fresheyes pass over the whole branch: a seven-line change, one look (the Review Cycle's one review).
- Prior work: `kata search "pypi"`: fzr2 (reservation is Joi's hand action), z5wb (the finding), the coordinator's note on 4fkh (reserved 2026-11-06).
- PyPI, 2026-11-26, one GET of `/pypi/<name>/json` each: `aitools-alerts` 200, 0.0.1, author Joichi Ito, homepage this repo, uploaded 2026-11-06; `aitools_alerts` the same project; `ai-tools-alerts`, `aitoolsalerts`, `ai-tool-alerts` 404.
- The README's "coming" sentence was already gone at 8f91677; its replacement ("There is no package on PyPI") was false once the placeholder existed.
- Mutation: restoring the old `INSTALL_HINT` fails `test_no_install_by_the_package_name` (relay.py line); restored.
- The first draft of the CHANGELOG entry quoted the old hint and failed the new test; reworded.
- Historical docs under docs/superpowers/ that record the 2026-11-06 plan to name PyPI as coming are left as written (spec, alternatives).
