# Run: curator-translation
Instruction: Task ai-tools-alerts#bq8v per TASK-ai-tools-alerts#bq8v.md — poster: Japanese translation of curator free text through one Claude API call (phase 2): aitools_alerts/poster/translate.py, translate(text, *, call) -> str | None; key from Kura line ANTHROPIC_API_KEY through get_secret in a subprocess with a throwaway SECRETS_CACHE_DIR, never argv or logs; model claude-sonnet-5-5, temperature 0, fixed system prompt in the repo; deterministic check that every URL, version string and id in the source appears unchanged, else skip and count `untranslated`; cached by event id; 401/403 sets a hold no run clears; at most 20 calls a day in the poster state; 30 s timeout; the English post is never delayed. Curator posts only. Config translate_curator (default false). Tests with a fake call: success, mismatch skip, auth hold, budget, config off. README one paragraph. Standard library only (urllib). Under 400 changed lines. /do-it, floor medium; security-shaped review on gpt-6-astra. Non-repoman repo (ff-merge ending).
Stage: code-review:whole-branch
Rung: heavy (start-floor heavy: hard-trigger — the diff reads an API key from the secrets helper; evaluator BR2 REV1 NOV2 INT2 FC2 = 9; dispatch floor medium)
Lens: "the English post is never delayed"; "never argv, never logged" (the key); "no other provider-facing call is added"; "standard library only"; "Under 400 changed lines"
Spec: docs/superpowers/specs/2026-11-06-curator-translation-design.md   Plan: docs/superpowers/plans/2026-11-06-curator-translation.md
Agency project: — (no mcp__agency tools in this session; built inline, as the earlier runs on this repo did)
Kata: ai-tools-alerts#bq8v
Last reviewed: spec+plan e2faa89bdffa0cf4dfc4e965b9d3dcc33fcdf6f0 (pass 1, gpt-6-astra, run 20261106-062636-6ec28e)

## Scorecards
Pass 1 [spec+plan]: 12B/0S/1C/0R · fixed -/- · velocity = (—→13, escalation no)
- Reviewer graded 1 critical, 12 major. BLOCKER and fixed (spec, plan and the code built alongside): F1 urlopen follows POST redirects with x-api-key → `_NoRedirect` opener, test. F2 urllib timeout bounds each read, not the call; the ledger lock is held → `translate.bounded` wall-clock deadlines (call 30 s, mirror 120 s, pass 300 s). F3 an amendment that changes only the block translated as "Amended: <title>" → the source adds the whole amended advisory, test with a fixed-only patch. F4 version grammar missed 9.9p1, 1.0rc1, 22 → whole-version tokens, test. F5 `done` eviction at 5000 and sort_keys order → pruned to the mirror's event ids, no count cap. F6 no recovery between the journal and the translate file (a duplicate journal key would make load_state refuse the whole state) → journal key reconciled before a call, order in spec S4a, test. F7 one permanently failing event starves the rest → refusal/cut-off answers are untranslated at once, service failures give up after 3 runs, test. F8 summary and reader tests contradicted → translate= before inputs=, the three tests updated and named in the plan. F9 gate is scripts/test-gate.sh, grep self-match → plan says so. F11 check_paths omits the new files → added, test. F12 downgrade with the new keys stops posting → README and spec rollback say remove them first.
- F10 (400-line limit made optional): rebutted in the kata comment on size: the limit is the issue's estimate; the global split threshold is ~600; the review fixes are safeguards that cannot ship separately.
- F13 (snapshot commit message vague) COSMETIC: rebutted; the snapshot is a dangling review commit, never on the branch.
- Heavy delta: the spec's BLOCKER fixes changed it. The delta is folded into the whole-branch code pass, whose diff contains the spec and plan and which carries these 13 findings to verify (one independent look over both; recorded so the shape is auditable).

## Chunks
- [ ] translate — translate.py (prompt, check, key, call)
- [ ] poster — main.py curator pass, inputs.py config, pull.py reader rule
- [ ] docs — README paragraph, design.md

## Notes
- Built while the spec+plan pass ran (the reviewer read a snapshot sha, so the tree could move); recorded as an order deviation, not a skipped step.
- Pre-existing: tests/poster/test_main.py::test_digest_id_recorded_and_printed fails on origin/main e4edf3e (preset digest ids collide with FakeSSH's shared counter); fixed here, preset ids at 1 << 252.
- Size: 620 added / 26 deleted in aitools_alerts, tests, README.md, docs/design.md (code 385, tests 235); decided comment on the issue.
- Issue says temperature 0; Sonnet 5.5 returns 400 for it: notice comment posted.
- Prior work: kata search "translat" / "japanese" finds rd8t (templates, landed e566386) and yxd6 (reader side). capability-search "translate": no existing translation tool in the fleet's scripts. sign-manifest.py's read_root_secret is the key-reading pattern reused here.
