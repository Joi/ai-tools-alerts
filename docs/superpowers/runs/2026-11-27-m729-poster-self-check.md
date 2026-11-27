# Run: m729-poster-self-check
Instruction: Read TASK-ai-tools-alerts#m729.md in this worktree root, then run `kata show ai-tools-alerts#m729` and follow the brief and the dispatch rules (run as /do-it, starting rung floored at medium).
Stage: spec
Rung: medium (the dispatch floors it at medium; evaluator verdict below)
Spec: docs/superpowers/specs/2026-11-27-m729-poster-self-check-design.md   Plan: docs/superpowers/plans/2026-11-27-m729-poster-self-check.md
Agency project: —
Kata: ai-tools-alerts#m729
Limits: wall clock 5 hours from 2026-11-27T12:10Z; one independent review per artifact (spec, plan, code), one delta only after a behaviour-changing BLOCKER fix; completion check: the acceptance cases this issue keeps pass as tests in `scripts/test-gate.sh`.
Landing: this repo has no `.repoman-managed` marker and no repoman registry row, so the unmanaged rule applies: `scripts/test-gate.sh`, one independent whole-branch review, a pull request this session merges.

## Scorecards

## Chunks
- [ ] the sent record and the check (aitools_alerts/poster/sent.py, signer, main, transport, inputs, compose)
- [ ] docs: CHANGELOG, README

## Notes
- The brief file TASK-ai-tools-alerts#m729.md is empty (0 bytes); the issue body and its one comment are the brief.
- Split before the start (two deliverables, over 600 lines together): the member strike rule is ai-tools-alerts#cftg; `notice:` comment on m729.
- Prior work read: issue m729 and comment ft97js; the design review on ai-tools-alerts#h29n (finding D14, revised rules 7 and 10, the "relay-bot key only" row of the table); ai-tools-alerts#ek5q and #vzc3 (both closed: the checkpoint exists and is signed on the poster machine with a key the relay VM never holds; the relay-bot key is still read on the VM for other channels, jibot-code#7z60); signer.py (nfm3, gtw9), the jsje `dropped` count in the digest as the pattern for a line said once. `kata search` for "foreign event own key self-check" and "probation strike" returned m729 and h29n only: no earlier attempt, no dead end.
