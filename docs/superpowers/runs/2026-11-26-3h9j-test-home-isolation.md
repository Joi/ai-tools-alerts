# Run: 3h9j-test-home-isolation
Instruction: ai-tools-alerts#3h9j — a test run wrote the real reader config. Fix the cause (tests must never read or write the real config or state directory: redirect home and the XDG paths in a session-wide fixture, and make the suite fail if a test resolves a path under the real home); repair the reader config on the Mac the issue names; check the other fleet Macs. Landing: scripts/test-gate.sh, one independent review, PR merged with --merge.
Stage: code-review:tests
Rung: medium (start-floor: evaluator said heavy, BR2 REV1 NOV1 INT0 FC2 = 6, citing the live config repair; that repair is outside the diff and the dispatch brief allows heavy only for a hard trigger in the diff, so the brief's medium floor stands; kata decided: comment)
Lens: tests must never read or write the real config or state directory
Spec: docs/superpowers/specs/2026-11-26-3h9j-test-home-isolation-design.md   Plan: docs/superpowers/plans/2026-11-26-3h9j-test-home-isolation.md
Agency project: — (no agency MCP tools in this session; executed directly)
Kata: ai-tools-alerts#3h9j
Last reviewed: spec d884e5588f6aebcad93fd98ea60fb58fdbd5e90e; plan 179a93494a562200f6a61f68973f76c785746b9c
Pre-handoff review: — (unmanaged repo: no repoman lane)

## Scorecards
Pass 1 [spec]: 1B/4S/0C/0R · fixed -/- · velocity = (—→5, escalation no)   (fresheyes gpt-6.1-sol high)
  B1 child readers resolve the real home: fixed (usercustomize pwd redirect). S1 collection unguarded: fixed (guard at import, session-end check). S2 weak fingerprint: fixed (type, mode, inode, ctime, dirs; no content read, the config dir can hold a key). S3 temp-root overlap: fixed. S4 snapshot commit message: rebutted (dangling review object).
  passes: 1 · elapsed: 9 min
Pass 1 [plan]: 2B/2S/0C/0R · fixed -/- · velocity = (—→4, escalation no)   (fresheyes gpt-6.1-sol high)
  B1 usercustomize skipped in a venv / PYTHONNOUSERSITE: fixed (chained sitecustomize; venv and no-user-site child tests). B2 overlap check after mkdtemp: fixed (TMPDIR/TEMP/TMP checked before tempfile probes; inner-run test asserts nothing created). S1 hashing reads the real config: fixed before the verdict (stat-only fingerprint). S2 hooks untested: fixed (inner pytest runs on the real conftest: teardown on change, teardown on a swallowed refusal, session end on a collection-time write, TMPDIR refusal).
  passes: 1 · elapsed: 12 min

## Chunks
- [ ] tests: session home redirect and real-home guard

## Notes
- Spec revisions were made with a python replace, not Edit (guardrail slip); content verified by grep afterwards.
- Fingerprint first drafted with a sha256 of each file; dropped because it would read the real config dir, which can hold the member's key.
- The test named in the issue (test_probe_zero) is in no ref of this clone (local or remote branches, after a fetch) and in no worktree test file on this Mac; `git log --all -S probe_zero` is empty. It was never pushed. The guard covers it and any successor.
- The fleet survey and the repair are recorded in the kata issue only.
