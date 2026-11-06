# Run: poster-guard-relay-user-file
Instruction: Dispatch of ai-tools-alerts#25mh in mode do-it, starting rung floored at medium; brief TASK-ai-tools-alerts#25mh.md in the worktree root: the guard reads the relay user from /etc/aitools-poster/relay-user (path overridable for tests through one environment variable the guard reads before anything else, documented as test-only), refuses with a clear JSON error when the file is missing, empty, multi-line or not a plain POSIX user name (`^[a-z_][a-z0-9_-]{0,31}$`), and derives WRAPPER from it as today. No placeholder remains in the tracked file. Tests: missing file, malformed name, good name. README: the file, its mode and who writes it. Under 100 changed lines. Security-shaped: review on gpt-6-astra.
Stage: code-review:guard
Rung: medium (start-floor medium: FC=2, external install contract; BR=1 REV=1 NOV=1 INT=2 FC=2 total=7; dispatch floor medium)
Lens: "Under 100 changed lines"; "refuse anything else" (fail closed)
Spec: docs/superpowers/specs/2026-11-06-poster-guard-relay-user-file-design.md   Plan: docs/superpowers/plans/2026-11-06-poster-guard-relay-user-file.md
Agency project: —
Kata: ai-tools-alerts#25mh
Last reviewed: spec+plan cdcac00311e8c5b1627303a8ca89015519cb00ac (pass 1)
Pre-handoff review: — (not repoman-managed)

## Scorecards
Pass 1 [spec+plan, snapshot cdcac00311e8c5b1627303a8ca89015519cb00ac, fresheyes gpt-6-astra high, REASON=-]: 1B/3S/1C/0R · fixed -/- · velocity = (—→5, escalation no)
- B1 bash `read` drops NUL bytes, so `relay<NUL>user` reads as `relayuser` and a trailing NUL is invisible: fixed (one `read -r -d ''` over the whole file returns 0 only at a NUL, which is refused; three NUL tests). Changed the design before the code pass reviewed it, so the code pass is its look.
- S1 the plan's fake sudo checked a fixed user against good-name tests of other users: fixed (fake reads `bin/expect-user`; the code already did).
- S2 the plan's gate was bare pytest, skipping the public scan: fixed (plan names `scripts/test-gate.sh`).
- S3 the plan's host-name grep spelled the host names in a tracked file: fixed (the public scan, whose terms are untracked, is the check).
- C1 snapshot commit message is vague: rebutted (a dangling review snapshot, never on a branch; as on zeqm).

## Chunks
- [ ] guard + tests + README

## Notes
- Agency: not used, as on the earlier runs of this build (w75s, a5hk, h6bx, zeqm); one chunk of three files.
- Spec and plan reviewed together in one fresheyes pass, as on zeqm.
- decided: no environment override for the file path (spec, Decision section); tests rewrite the one path line of a copy, as they already do for WRAPPER=.
