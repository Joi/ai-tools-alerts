# Run: manifest-retractions
Instruction: start at medium. Task: TASK-ai-tools-alerts#jpzy.md in the worktree root (kata ai-tools-alerts#jpzy): implement decisions 1-4 (manifest `retracted` list honoured by readers regardless of key state; sign-manifest --retract/--unretract; idempotent curator retract; pull docstring on ignoring 9005) with tests, spec+plan+run manifest under docs/superpowers/. Non-repoman ending: ff-merge to main from the primary checkout and close the issue.
Stage: code-review:branch
Rung: heavy (start-floor heavy: hard-trigger — the diff changes manifest.verify, the trust check, and scripts/sign-manifest.py, which reads the root key; BR2 REV1 NOV1 INT2 FC2 = 8; Lens: "a manifest without the field is unchanged"; "No current manifest is re-signed in this task"; "an unsigned or wrong-root manifest with the field still rejected"). Dispatch floor was medium; the climb's cause is the evaluator's hard trigger.
Spec: docs/superpowers/specs/2026-11-05-manifest-retractions-design.md   Plan: docs/superpowers/plans/2026-11-05-manifest-retractions.md
Agency project: —
Kata: ai-tools-alerts#jpzy
Last reviewed: spec+plan 860c6ee6bee71ff5cc1e965979fbfaf67d6a7969
Pre-handoff review: — (not repoman-managed)

## Scorecards
Pass 1 [spec+plan]: 4B/0S/0C/0R · fixed -/- · velocity = (—→4, escalation no)   # fresheyes gpt-6-astra on snapshot 860c6ee (REASON=-). major (BLOCKER) 1: case-sensitive matching while the poster ledger casefolds ids → fixed: casefold matching in advisories, manifest refuses casefold duplicates, sign-manifest merges casefolded; tests. major 2: a docstring alone does not make readers ignore 9005; advisories read any kind → fixed: advisories skips kinds 5 and 9005; parametrized test with curator- and bot-signed deletions. major 3: the plan's host-name grep matched its own text → fixed: the plan names the brief's check instead of the literals. major 4: snapshot commit message → rebutted: a dangling review snapshot (commit-tree, never on a branch), as in A3.
passes: spec+plan 1 · heavy delta for the two behaviour-changing BLOCKER fixes folded into the whole-branch code pass, which reviews the fixed spec and its implementation together (A3's precedent)

## Chunks
- [x] chunk 1 — manifest.py `retracted` field + tests
- [x] chunk 2 — pull.advisories honours the list; pull docstring (9005) + tests
- [x] chunk 3 — sign-manifest --retract/--unretract + tests
- [x] chunk 4 — curator retract idempotent + tests

## Notes
- Execution inline per the plan's chunks (TDD: each chunk's tests failed first), as every earlier task of this build; Agency MCP not used (recorded, not skipped silently). Code was written while the spec review ran; the review's fixes were applied to code and spec together.
- Gate after the spec-review fixes: scripts/test-gate.sh 787 passed.
- Follow-up ai-tools-alerts#0drq (Atom withdrawal for manifest-listed ids; the Atom builder also reads a curator kind 9005 'retract').
- kata search: prior runs A3 (docs/superpowers/runs/2026-11-05-trust-manifest.md, heavy) and A5 (2026-11-05-pull-state-notify-cli.md) set the conventions: stdlib only, scripts/test-gate.sh, spec+plan reviewed in one fresheyes pass on a snapshot, execution inline (Agency not used in any earlier task of this build).
- Security-shaped (trust manifest): every fresheyes pass exports FRESHEYES_GPT_MODEL=gpt-6-astra (brief).
