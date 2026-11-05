# Run: poster-japanese-replies
Instruction: Task ai-tools-alerts#rd8t per TASK-ai-tools-alerts#rd8t.md — poster: Japanese rendering of every post as a `lang: ja` reply (deterministic templates, no model call, no new dependency, no new secret); format into docs/design.md "Post format" exactly as the issue states it; Japanese reply sent after the original is journaled, as its own ledger item `<key>:ja`, retried next hour on failure, never delaying or blocking the original; a critical's Japanese reply goes to both channels' copies; keep product names, ids, versions, URLs and the SYNTHETIC TEST / UNVERIFIED marks as they are; under 400 changed lines. /do-it, start at medium; security-shaped review on gpt-6-astra. Non-repoman repo (ff-merge ending).
Stage: code-review:whole branch
Rung: medium (start-floor medium: constraint-lens, evaluator BR1 REV2 NOV1 INT2 FC1 = 7, no hard trigger; dispatch floor medium)
Lens: "do not change the format"; "never delaying or blocking the original"; "Keep product names, ids, versions, URLs and the SYNTHETIC TEST / UNVERIFIED marks as they are"; "no model call, no new dependency, no new secret"; spec S7 "English output is byte-identical"; spec S8 "A state file written by the deployed poster (items without the new field) loads unchanged"
Spec: docs/superpowers/specs/2026-11-06-poster-japanese-replies-design.md   Plan: docs/superpowers/plans/2026-11-06-poster-japanese-replies.md
Agency project: — (no mcp__agency tools in this session; built inline, as the earlier runs on this repo did)
Kata: ai-tools-alerts#rd8t
Last reviewed: spec+plan 8c3c7ee2ebfa81961f0bb8d120eb092b5d7ca1d1 (pass 1, gpt-6-astra, run 20261106-051119-cf1db1)

## Scorecards
Pass 1 [spec+plan]: 5B/5S/1C/0R · fixed -/- · velocity = (—→11, escalation no)
- Reviewer graded all 11 "major". Classified BLOCKER: 2 (removal and Japanese append in separate saves), 3 (successive replies share one Japanese key), 5 (reply_to unbound on replay/resolve), 6 (a journaled Japanese id resent), 9 (resolve tests; on inspection the first build dropped the Japanese reply after `resolve --delivered`, since that Run has no channels). SUBSTANTIVE: 1 (`_ja` with `lang=` kwarg), 4 (Japanese pending id could equal an advisory alias; busy() counted Japanese items), 7 (ledger errors in the Japanese drain reach the exit code), 8 (unverified title prefix translated away), 10 (host grep not limited to added lines). COSMETIC: 11 (snapshot commit message).
- Fixed in the code built alongside the review: 1 (`_ja` forwards keywords), 2 (`_queue_ja` runs between the removal and the one save), 3 (a reply's key adds the full English event id; test `test_each_english_reply_keeps_its_own_japanese_reply`), 5 (target read from the ledger thread), 6 (`deliver_ja` finishes a journaled id without a send; same test). Fixed after it: 4 (pending id `ja <key>`, busy() skips Japanese items), 7 (drain_ja reports LedgerError/OSError/KeyError/ValueError, never the exit code), 8 (`unverified ` stays English in the Japanese title), 9 (`_queue_ja` checks only the target id, so resolve queues it; the two resolve tests now expect the queued Japanese item), 10 (plan's grep).
- Rebutted: 11. The snapshot is a dangling review commit, never on the branch.
- Medium rung: no delta on the documents; the fixes are code-reviewed in the whole-branch pass.

## Chunks
- [x] compose-ja — Japanese templates in compose.py
- [x] journal-ja — `<key>:ja` journal items in main.py / inputs.py
- [x] docs — design.md Post format, README paragraph
(one commit: the three chunks are one behaviour and were reviewed as one branch)

## Notes
- Code edits were made with small python replace scripts that assert each needle occurs once; run artifacts with Edit.
- Reader rule from yxd6 (c:yv1vtk, not a directive): change-reply Japanese carries the whole current advisory too (decided comment on the issue). Size: 382 added, 46 rewritten (decided comment).
- Suite: 852 passed, 1 skipped.
- Prior work: kata search "japanese lang ja" finds only this issue and its sibling ai-tools-alerts#yxd6 (reader side, same format). No experiment issues.
