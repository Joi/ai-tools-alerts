# Run: public-scan-terms-file
Instruction: Dispatch of ai-tools-alerts#a5hk in mode do-it, starting rung floored at medium; brief TASK-ai-tools-alerts#a5hk.md in the worktree root: public-scan reads its terms from an untracked file ($PUBLIC_SCAN_TERMS or ~/.config/aitools-alerts/public-scan.terms); missing or empty file is exit 2 naming the path; the tracked tree spells no term (fixture terms only); scripts/test-gate.sh unchanged; one README contributor paragraph; under 150 changed lines.
Stage: code-review:branch
Rung: medium (start-floor medium: constraint-lens, BR1 REV1 NOV1 INT1 FC1 = 5)
Lens: keep the scanner's behaviour (bytes, file names, exit 1 on a hit, exit 2 when it cannot run); scripts/test-gate.sh unchanged; the tracked tree spells no term; under 150 changed lines
Spec: docs/superpowers/specs/2026-11-06-public-scan-terms-file-design.md   Plan: docs/superpowers/plans/2026-11-06-public-scan-terms-file.md
Agency project: —
Kata: ai-tools-alerts#a5hk
Last reviewed: spec+plan 6571fee3464f3013b5a468e5ae36cf788247601b (pass 1); branch 629e57582e31c16289d513cd2fe94e63f00c85f4 (code pass 1)
Pre-handoff review: — (not repoman-managed)

## Scorecards
Pass 1 [spec+plan, snapshot 6571fee3464f3013b5a468e5ae36cf788247601b, fresheyes gpt-6-astra high, REASON=-]: 5B/0S/0C/0R · fixed -/- · velocity = (—→5, escalation no)
- B1 diff verification would match the deleted lines: fixed (plan checks added lines only).
- B2 compile failures beyond re.error (OverflowError on a huge repetition): fixed (caught; regression case).
- B3 README example term matches the tracked tests and the README, so the documented gate exits 1: fixed (example is `(?!)`, which matches nothing; test pins it).
- B4 verifier not case-insensitive: fixed (`git grep -nIiP`, exit 1 wanted, exit 2 an error).
- B5 snapshot commit message is generic: rebutted (a dangling review snapshot that never lands; h6bx rebutted the same).
- Plan delta: the fixes changed the plan; the whole-branch code review reads the amended plan with the code (as on h6bx), no separate plan pass.
Pass 1 [code:branch, origin/main...629e57582e31c16289d513cd2fe94e63f00c85f4; Stage 1 same-model subagent ∥ Stage 2 fresheyes gpt-6-astra high, REASON=-]: 1B/1S/3C/0R · fixed -/- · velocity = (—→5, escalation no)
- FB1 two invalid fragments (`(`, `)`) join into a valid pattern, so a bad terms file scans instead of exit 2: fixed (each fragment compiled alone first; the error names its line; regression case).
- S1 a leading byte-order mark disables the first term: fixed (stripped; BOM + CRLF test).
- C1 relative PUBLIC_SCAN_TERMS resolves against the repo root: rebutted — it fails closed (exit 2 naming the path); the fix plus its test took the deliverable to 154 lines, over the 150 budget.
- C2 bad-term message gave a position in the joined pattern: fixed by FB1 (line number).
- C3 no CRLF or mid-pattern inline-flag cases: fixed (both added).

## Chunks
- [x] scanner + tests + README — 629e575, review fixes in the next commit

## Notes
- Gate: tests/poster/test_main.py::test_digest_id_recorded_and_printed fails on unmodified origin/main when run in its file (passes alone); pre-existing, filed ai-tools-alerts#rvw5 (priority 1). Every other test passes.
- Agency: not used, as on the earlier runs of this build (h6bx manifest: Agency project —); the change is one chunk of three files, built directly.
