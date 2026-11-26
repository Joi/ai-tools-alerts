# Run: 3h9j-test-home-isolation
Instruction: ai-tools-alerts#3h9j — a test run wrote the real reader config. Fix the cause (tests must never read or write the real config or state directory: redirect home and the XDG paths in a session-wide fixture, and make the suite fail if a test resolves a path under the real home); repair the reader config on the Mac the issue names; check the other fleet Macs. Landing: scripts/test-gate.sh, one independent review, PR merged with --merge.
Stage: verifying
Rung: medium (start-floor: evaluator said heavy, BR2 REV1 NOV1 INT0 FC2 = 6, citing the live config repair; that repair is outside the diff and the dispatch brief allows heavy only for a hard trigger in the diff, so the brief's medium floor stands; kata decided: comment)
Lens: tests must never read or write the real config or state directory
Spec: docs/superpowers/specs/2026-11-26-3h9j-test-home-isolation-design.md   Plan: docs/superpowers/plans/2026-11-26-3h9j-test-home-isolation.md
Agency project: — (no agency MCP tools in this session; executed directly)
Kata: ai-tools-alerts#3h9j
Last reviewed: spec d884e5588f6aebcad93fd98ea60fb58fdbd5e90e; plan 179a93494a562200f6a61f68973f76c785746b9c; code 60810a91a7fd48cfdc27974a3c191333698d2124 (whole branch); delta 4c3a7d913a60b425653b40a6d463e435a2d30143
Pre-handoff review: — (unmanaged repo: no repoman lane)

## Scorecards
Pass 1 [spec]: 1B/4S/0C/0R · fixed -/- · velocity = (—→5, escalation no)   (fresheyes gpt-6.1-sol high)
  B1 child readers resolve the real home: fixed (usercustomize pwd redirect). S1 collection unguarded: fixed (guard at import, session-end check). S2 weak fingerprint: fixed (type, mode, inode, ctime, dirs; no content read, the config dir can hold a key). S3 temp-root overlap: fixed. S4 snapshot commit message: rebutted (dangling review object).
  passes: 1 · elapsed: 9 min
Pass 1 [plan]: 2B/2S/0C/0R · fixed -/- · velocity = (—→4, escalation no)   (fresheyes gpt-6.1-sol high)
  B1 usercustomize skipped in a venv / PYTHONNOUSERSITE: fixed (chained sitecustomize; venv and no-user-site child tests). B2 overlap check after mkdtemp: fixed (TMPDIR/TEMP/TMP checked before tempfile probes; inner-run test asserts nothing created). S1 hashing reads the real config: fixed before the verdict (stat-only fingerprint). S2 hooks untested: fixed (inner pytest runs on the real conftest: teardown on change, teardown on a swallowed refusal, session end on a collection-time write, TMPDIR refusal).
  passes: 1 · elapsed: 12 min
Pass 1 [code:tests]: 2B/7S/6C/0R · fixed -/- · velocity = (—→15, escalation no)   (Stage 1 same-model 0B/2S/6C; Stage 2 fresheyes gpt-6.1-sol high 2B/5S)
  Stage 2: B1 explicit-path reads bypass config.home: fixed (audit hook refuses in-process file operations in guarded dirs). B2 nested run loses the true home: fixed (hook keeps the true getpwuid). S chaining recursion: fixed (skip every hook of ours). S live reader false failure: rebutted (issue asks for this check; message names the cause). S test_home resolves real paths: fixed (stubbed pwd entry). S repair fallback python3 -m: fixed (spec text). S plan filename: fixed.
  Stage 1: S basetemp under home: fixed (exempt --basetemp when safe). S session-end message: fixed (names a concurrent reader). C home fixture marker: fixed. C doc filename leftover: fixed. C fleet line in public manifest: moved to kata. C explicit-env children, TMPDIR holding state dir, xdist: noted, not changed.
Pass 2 [code:tests delta]: 0B/2S/0C/0R · fixed 7/7 prior · velocity ↓ (15→2, escalation no)   (fresheyes --since 60810a9 --rebuttals)
  S dir_fd-relative open bypasses the hook: fixed (dir_fd and descriptor paths resolved; os.open wrapped). S link inside a guarded dir pointing out: fixed (path as written and resolved both checked). No further pass (one delta).

## Chunks
- [x] tests: session home redirect and real-home guard (4c3a7d9, delta fixes in the next commit)

## Notes
- Spec revisions were made with a python replace, not Edit (guardrail slip); content verified by grep afterwards.
- Fingerprint first drafted with a sha256 of each file; dropped because it would read the real config dir, which can hold the member's key.
- The test named in the issue (test_probe_zero) is in no ref of this clone (local or remote branches, after a fetch) and in no worktree test file on this Mac; `git log --all -S probe_zero` is empty. It was never pushed. The guard covers it and any successor.
- The fleet survey and the repair are recorded in the kata issue only.
