# Run: poster-japanese-replies
Instruction: Task ai-tools-alerts#rd8t per TASK-ai-tools-alerts#rd8t.md — poster: Japanese rendering of every post as a `lang: ja` reply (deterministic templates, no model call, no new dependency, no new secret); format into docs/design.md "Post format" exactly as the issue states it; Japanese reply sent after the original is journaled, as its own ledger item `<key>:ja`, retried next hour on failure, never delaying or blocking the original; a critical's Japanese reply goes to both channels' copies; keep product names, ids, versions, URLs and the SYNTHETIC TEST / UNVERIFIED marks as they are; under 400 changed lines. /do-it, start at medium; security-shaped review on gpt-6-astra. Non-repoman repo (ff-merge ending).
Stage: done
Rung: medium (start-floor medium: constraint-lens, evaluator BR1 REV2 NOV1 INT2 FC1 = 7, no hard trigger; dispatch floor medium)
Lens: "do not change the format"; "never delaying or blocking the original"; "Keep product names, ids, versions, URLs and the SYNTHETIC TEST / UNVERIFIED marks as they are"; "no model call, no new dependency, no new secret"; spec S7 "English output is byte-identical"; spec S8 "A state file written by the deployed poster (items without the new field) loads unchanged"
Spec: docs/superpowers/specs/2026-11-06-poster-japanese-replies-design.md   Plan: docs/superpowers/plans/2026-11-06-poster-japanese-replies.md
Agency project: — (no mcp__agency tools in this session; built inline, as the earlier runs on this repo did)
Kata: ai-tools-alerts#rd8t
Last reviewed: spec+plan 8c3c7ee2ebfa81961f0bb8d120eb092b5d7ca1d1 (pass 1, gpt-6-astra, run 20261106-051119-cf1db1)
Last reviewed: code whole branch b48167a9e5a42d64f8e3546079a5760cc01670f2 (pass 1 launched: fresheyes gpt-6-astra ∥ Stage 1 subagent)

## Scorecards
Pass 1 [spec+plan]: 5B/5S/1C/0R · fixed -/- · velocity = (—→11, escalation no)
- Reviewer graded all 11 "major". Classified BLOCKER: 2 (removal and Japanese append in separate saves), 3 (successive replies share one Japanese key), 5 (reply_to unbound on replay/resolve), 6 (a journaled Japanese id resent), 9 (resolve tests; on inspection the first build dropped the Japanese reply after `resolve --delivered`, since that Run has no channels). SUBSTANTIVE: 1 (`_ja` with `lang=` kwarg), 4 (Japanese pending id could equal an advisory alias; busy() counted Japanese items), 7 (ledger errors in the Japanese drain reach the exit code), 8 (unverified title prefix translated away), 10 (host grep not limited to added lines). COSMETIC: 11 (snapshot commit message).
- Fixed in the code built alongside the review: 1 (`_ja` forwards keywords), 2 (`_queue_ja` runs between the removal and the one save), 3 (a reply's key adds the full English event id; test `test_each_english_reply_keeps_its_own_japanese_reply`), 5 (target read from the ledger thread), 6 (`deliver_ja` finishes a journaled id without a send; same test). Fixed after it: 4 (pending id `ja <key>`, busy() skips Japanese items), 7 (drain_ja reports LedgerError/OSError/KeyError/ValueError, never the exit code), 8 (`unverified ` stays English in the Japanese title), 9 (`_queue_ja` checks only the target id, so resolve queues it; the two resolve tests now expect the queued Japanese item), 10 (plan's grep).
- Rebutted: 11. The snapshot is a dangling review commit, never on the branch.
- Medium rung: no delta on the documents; the fixes are code-reviewed in the whole-branch pass.

Pass 1 [code:whole branch b48167a]: Stage 1 0B/2S/6C · fresheyes (gpt-6-astra, run 20261106-052402-d14407) 2B/5S/0C · fixed -/- · velocity = (—→15, escalation no)
- fresheyes graded 1 critical, 6 major. BLOCKER: F1 (drain_ja saved the new watermarks before `deferred` was replaced: a crash there loses a deferred English update) — fixed, drain_ja runs after the final save of marks and deferred together (test `test_japanese_sends_start_after_marks_and_deferred_are_saved`); F2 (a candidate alias spelled `ja <key>` matched the Japanese pending entry and held English work) — fixed, the Japanese pending entry has no aliases (test: the colliding alias in `test_unknown_japanese_send_never_holds_english_work`). SUBSTANTIVE: F3 (unbounded Japanese backlog could push the journal past load_state's 16 MiB) — fixed, MAX_JA 200 drops the oldest unsent, unpending one (test `test_japanese_backlog_is_bounded`); F4 (rollback: every English item carried `ja`) — fixed, the field is written only with a body, and spec/plan rollback says empty outbox or remove the fields; F5 (spec approach key without the event id), F6 (plan/spec said `未検証の`), F7 (plan grep placeholder) — doc fixes.
- Stage 1 S1 = F4, fixed. S2 (one refused translation holds all later ones forever): fixed, a failed Japanese item moves last in the journal. C (except list narrower than the promise): fixed, `except Exception`. Rebutted: C busy counter includes a Japanese item held pending (busy already means "waits for a human"); C arrival order after a resolve (readers pick by `of:` target, order does not matter); C no stderr at compose-time drop (counted in `ja_failed`; the drain prints); C resolve-test assertions changed (the new behaviour is correct: the Japanese reply is queued, not lost); C size (decided comment).
- F1 and F2 changed behaviour: one delta pass `--since b48167a9e5a42d64f8e3546079a5760cc01670f2`.
Pass 2 [code:delta --since b48167a, head 0a0dd5a]: 0B/2S/0C/0R · fixed 9/9 prior · velocity ↓ (15→2, escalation no)
- fresheyes (gpt-6-astra, run 20261106-053135-9288f1): save-order and pending-alias fixes judged sound; no standing rebuttal overturned. Graded major, classified SUBSTANTIVE (both refine F3, the backlog bound): the cap was skipped when every item was pending; a count cap is not a byte cap. Fixed after the delta: MAX_JA_BYTES 4 MiB counted JSON-escaped, and a translation that cannot make room is not journaled (test extended in `test_japanese_backlog_is_bounded`). No further pass (ruling jibot-code#41e2).

## Chunks
- [x] compose-ja — Japanese templates in compose.py
- [x] journal-ja — `<key>:ja` journal items in main.py / inputs.py
- [x] docs — design.md Post format, README paragraph
(one commit: the three chunks are one behaviour and were reviewed as one branch)

## Notes
- Code edits were made with small python replace scripts that assert each needle occurs once; run artifacts with Edit.
- Reader rule from yxd6 (c:yv1vtk, not a directive): change-reply Japanese carries the whole current advisory too (decided comment on the issue). Size: 382 added, 46 rewritten (decided comment).
- Suite: 852 passed, 1 skipped.
- Rebased on origin/main ef5438e (8et2: cli/pull hardening, no shared files). Reviewed commits became: b48167a → 64f69f9 (whole-branch pass), 0a0dd5a → 85ccfb4 (delta pass). 948ce5f (byte budget, the delta's SUBSTANTIVE fix) had no further pass (ruling jibot-code#41e2); `git diff 85ccfb4 948ce5f` shows it. Gate `scripts/test-gate.sh` on 948ce5f: 871 passed, 1 skipped.
- Size: 433 added, 48 rewritten in code/tests/README/design.md (decided comment covers the first build; the rest is review fixes and their tests).
- yxd6 comment c:6wq570 (never a block in a lang reply): already enforced by `compose.lang_reply`, pinned by `test_lang_reply_header_and_refusals`.
- roborev: repo not enrolled; the delta pass ran before the push.
- Prior work: kata search "japanese lang ja" finds only this issue and its sibling ai-tools-alerts#yxd6 (reader side, same format). No experiment issues.
