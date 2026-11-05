# Run: trust-manifest
Instruction: start at medium. Task: ai-tools-alerts#0exc (Plan Task A3, signed trust manifest) per TASK-ai-tools-alerts#0exc.md in the worktree. Non-repoman ending (ff-merge to main by hand, close kata issue yourself). Security-shaped: export FRESHEYES_GPT_MODEL=gpt-6-astra for every fresheyes pass.
Stage: code-review:branch
Rung: heavy (start-floor heavy: hard-trigger secrets — sign-manifest.py reads the root signing key; BR1 REV0 NOV1 INT1 FC2 = 5; Lens: "The secret never reaches argv, stdout, stderr, a log or a file.")
Spec: docs/superpowers/specs/2026-11-05-trust-manifest-design.md   Plan: docs/superpowers/plans/2026-11-05-trust-manifest.md
Agency project: —
Kata: ai-tools-alerts#0exc
Last reviewed: —
Pre-handoff review: — (not repoman-managed)

## Scorecards
Pass 1 [spec+plan]: 1B/3S/0C/1R · fixed -/- · velocity = (—→5, escalation no)   # fresheyes gpt-6-astra on snapshot 2f058474 (REASON=-). BLOCKER (critical): get_secret writes the value to $SECRETS_CACHE_DIR (_secrets_cache_value mktemp+rename); a throwaway dir still gets a plaintext copy → fixed: dir chmod 0500 so the helper's mktemp fails (ignored by the helper), script refuses if the dir is non-empty afterwards, test runner asserts the write is refused. SUBSTANTIVE: fake-runner test proved cleanup not absence → fixed by the write-refused assertion + forced-write refusal test; real-helper automated test rebutted (public repo gate must not depend on the private helper or decrypt the vault; the script's own emptiness check is the in-execution evidence on the real run). created_at vs issued_at plan wording → fixed (test already compared to the computed epoch). Host name in spec → removed. Rebutted: snapshot commit message (dangling review snapshot, never on a branch).
passes: spec+plan 1 · heavy delta for the BLOCKER fix folded into the whole-branch code pass, which reviews the fixed spec and its implementation together (same as A1's combined delta)

## Chunks
- [x] chunk 1 — manifest.py + tests (TDD; ImportError fail first, then 71 pass)
- [x] chunk 2 — sign-manifest.py + its tests, v1 signed (event id 4efdaa23…043e), trust/manifest.json; gate 279 passed; one commit with chunk 1

## Notes (execution)
- Agency MCP not used: execution inline by the executor per the plan's chunks, as in A1/A2 (recorded, not skipped silently).
- Real signing: VM relay-bot key re-read and matched; default cache had no AITOOLS_ALERTS_ROOT_NSEC entry before or after; the script's read-only-dir emptiness check passed (it would have refused otherwise); no sign-manifest-* temp dir left.
- Leak check on the staged diff: no fleet host name, no nsec; 64-hex strings are the root pub, the two poster pubs, the event id (plus the 128-hex sig).

## Notes
- kata search: prior runs A1 (docs/superpowers/runs/2026-11-05-alerts-bootstrap.md, heavy, root key mint) and A2 (2026-11-05-spec-files.md, medium) set the conventions followed here: stdlib only, scripts/test-gate.sh, spec+plan reviewed in one fresheyes pass on a snapshot, execution inline.
- VM relay-bot pubkey re-read before spec (ssh ... cat agent.pub.hex): matches the brief's d4f04ff6…39c1.
