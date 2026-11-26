# Run: 4fkh-no-pypi-install
Instruction: Read TASK-ai-tools-alerts#4fkh.md in this worktree root, then run `kata show ai-tools-alerts#4fkh` and follow the brief and the dispatch rules (do-it, start rung floored at medium; PR landing; one independent review).
Stage: verifying (gate on the final head, then the pull request)
Rung: medium (start-floor medium: dispatch floor; no hard trigger in scope)
Spec: docs/superpowers/specs/2026-11-26-4fkh-no-pypi-install-design.md   Plan: docs/superpowers/plans/2026-11-26-4fkh-no-pypi-install.md
Agency project: — (no agency MCP tools in this session; executed directly)
Kata: ai-tools-alerts#4fkh
Last reviewed: spec+plan+code 867680cb16344b4f2218456371ecbe2e834b4e34 (whole branch); the fix commit after it is unreviewed by a further pass (no BLOCKER, so no delta)
Limits: wall clock 2 hours; review shape one independent pass, one delta only after a behaviour-changing BLOCKER fix; completion check: the guard test fails on the old hint and `scripts/test-gate.sh` passes.

## Scorecards
Pass 1 [spec+plan+code:branch]: 0B/4S/0C/0R · fixed -/- · velocity = (—→4, escalation no)   # fresheyes whole branch at 867680cb16344b4f2218456371ecbe2e834b4e34, gpt-6.1-sol high, REASON=-; its 'major' read as SUBSTANTIVE; all 4 fixed
code: passes: 1 · elapsed: ~12 min

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
- Historical docs under docs/superpowers/ that record the 2026-11-06 plan to name PyPI as coming keep their text; after the review, each such instruction carries a 'Superseded by 4fkh' line.
- Review dispositions (all fixed in the commit after 867680c): (1) the two older docs that prescribed the PyPI sentence and the by-name hint now carry a 'Superseded by 4fkh' line at the instruction, as does the release-v0-1-0 spec; (2) the guard walks every tracked file except tests/ and docs/superpowers/ (spec/, trust/, ops/, pyproject.toml included) and asserts a list of known paths is in the walk; (3) the by-name detector reads the whole command after `pip install`, `pipx install`, `pipx inject` or `uv pip|tool install` up to a backtick, `&&`, `||`, `;`, `|`, `,` or `)`, with positive and negative cases (short options, option values, second requirement, version pins, `aitools.alerts`); (4) the promise detector joins wrapped lines and checks each sentence that names PyPI for coming/upcoming/soon/will be, with cases including 'will be on PyPI' and a wrapped sentence.
- Mutations after the fix: `pip install -U 'aitools-alerts[curator]'` in relay.py fails the guard; 'PyPI support is coming.' appended to ops/vm/README.md fails it; both reverted.
