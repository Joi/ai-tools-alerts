# Run: poster-transport-main
Instruction: start at medium. Task: ai-tools-alerts#kfq6 (B4) — relay transport and the aitools-alerts-poster command, per TASK-ai-tools-alerts#kfq6.md and the kata comments. Non-repoman repo (ff-merge ending). Security-shaped: fresheyes with FRESHEYES_GPT_MODEL=gpt-6-astra.
Stage: spec-review
Rung: heavy (start-floor heavy: hard-trigger live deploy path, BR1 REV1 NOV1 INT1 FC2 = 6; posts go to the live relay channels)
Lens: no `--private-key`, no `--relay`, no key path anywhere in this repo; nothing in a post may name a fleet host, a local path or a kata ref; no other live send from this task; transport tests never spawn a real ssh; the watermark advances only after every send of the run succeeded; send nothing more after one failure; a ValueError from compose withholds the advisory, never posts it.
Spec: docs/superpowers/specs/2026-11-05-poster-transport-main-design.md   Plan: docs/superpowers/plans/2026-11-05-poster-transport-main.md
Agency project: —
Kata: ai-tools-alerts#kfq6
Last reviewed: spec+plan 492f727ca9f94128876927ba078d0a9415fb3385 (pass 1, gpt-6-astra, run 20261105-102349-7af8f6)

## Scorecards
Pass 1 [spec+plan]: 11B/2S/0C/1R · fixed -/- · velocity = (—→14, escalation no)
- Reviewer graded all 14 "major". Counted as BLOCKER: duplicate/loss findings 1–8, 10, 11 and the privacy gap 9; SUBSTANTIVE: 12 (key path in repo), 13 (main landing size); 14 (snapshot commit message) is a restatement-class non-issue.
- Fixed in the spec/plan: 1 partial reply (outbox journal per channel), 2 unknown exits (only proven non-delivery is failed), 3 alias learning (busy candidates union ids into outbox items), 4 watermark vs unresolved work (journal survives), 5 promotion identity and compose-before-send (canonical candidate, whole plan composed before journaling), 6 copy from canonical advisory, 7 scoped notice keys, 8 digest from the ledger, 9 wider _PRIVATE, 10 KEV wall-clock deadline, 11 stop-after-failure and LedgerError tests, 13 three landings.
- Rebutted: 12 (the key path lives in E1's VM wrapper and its docs by design; the requirement binds the poster's code, which the grep checks; spec criterion 1 now says so), 14 (the snapshot is a dangling review commit that never lands).
- Spec and plan were reviewed in one pass on both files (the plan was written before the spec pass ran); recorded here rather than run twice.

Pass 2 [spec+plan delta]: 9B/0S/1C/0R · fixed 12/12 prior · velocity ↓ (14→10, escalation no)
- Delta run 20261105-103308-e43864 on 1519952 (gpt-6-astra); both standing rebuttals accepted. Last pass on the documents (heavy: one delta).
- Fixed in code, spec and tests: sent items drain before the pending filter (spec wording; the code already did), clear_pending before removing the item, busy candidates hold the watermarks, one journaled digest at a time, the digest acknowledges its journaled snapshot (notice keys, cutoff), the canonical copy keeps prev's aliases (spec wording; the code already did), a changed affected range posts a reply, drive-letter forward-slash and UNC paths in the guard, the manifest checklist.
- Rebutted: the third landing is 832 lines, over 600: the journal and the planner cannot be tested apart, and the brief sized B4 as transport first, then main.

Pass 1 [code:transport, whole branch d2f2fd7]: Stage 1 0B/4S/3C · fresheyes (gpt-6-astra, run 20261105-104159-5eb113) 6B/0S/0C · fixed -/- · velocity = (—→13, escalation no)
- Stage 1 fixed: ssh connect-phase patterns anchored per line and stdout empty; classify on the whole stderr; `duplicate:` answer is unknown; ssh=None default with a conftest that blocks real ssh; relay 4xx allowlist; -T, RequestTTY=no, RemoteCommand=none, `--`, host check; tests for each.
- fresheyes fixed: truncation (same as Stage 1); exit 2 now read from the CLI's JSON error line (category + status), never free text; docstring no longer spells the forbidden flags; for landings 2 and 3 (spec + working tree): identity learned past the alias cap (Ledger.add_ids), affected-range change without a fix, cased /Library/ guard.
- The exit-2 fix changes behaviour: one delta pass `--since d2f2fd7`.
Pass 2 [code:transport delta --since d2f2fd7]: 3B/0S/0C/0R · fixed 13/13 prior · velocity ↓ (13→3, escalation no)
- run 20261105-105044-9d91d5. Fixed: the full-stderr test (60fe808); alias publication compared with prev (landing 3); compose's case-preserved guard (92b202f, landing 2). Landed 60fe808 on main 2026-11-05.

Pass 1 [code:inputs, whole branch 9dd6636]: Stage 1 1B/6S/9C · fresheyes (run 20261105-105740-e39dfd) 6B/0S/0C · fixed 3/3 prior · velocity = (—→22, escalation no)
- All BLOCKER and SUBSTANTIVE fixed in 5d6ccc0; ledger fsync filed as ai-tools-alerts#nyav. Behaviour changed: one delta.
Pass 2 [code:inputs delta --since 9dd6636]: 2B/0S/0C/0R · fixed 13/13 prior · velocity ↓ (22→2, escalation no)
- run 20261105-110529-32750b. Both fixed in fb37d7f. Rebased onto 2569460, landed 75c73ec on main.

## Chunks
- [x] transport — `aitools_alerts/poster/transport.py`, `tests/poster/test_transport.py` (landing 1)
- [x] inputs — `aitools_alerts/poster/inputs.py`, `tests/poster/test_inputs.py`, `_PRIVATE` in candidates.py + tests (landing 2)
- [ ] run — `aitools_alerts/poster/main.py`, `tests/poster/test_main.py`, `Ledger.entries_since`/`has_pending` + test, `pyproject.toml` console script (landing 3)

## Notes
- VM facts checked 2026-11-05 (read-only): `buzz messages send --help` on buzz a5dbdf5e6 has `--reply-to <REPLY_TO>` ("Event ID to reply to (creates a thread)"); stdout JSON carries `event_id` (ops/vm/README.md, E1).
- Reply marker: no reply event exists in #security-feed (the one e-tagged event there is a kind 9005 delete with an unmarked tag). One kind-9 reply elsewhere on the relay (LIMIT 1) carries `["e", <id>, "", "reply"]`, and buzz-sdk `thread_tags` (crates/buzz-sdk/src/builders.rs:173) emits `["e", root, "", "reply"]` for a direct reply (root == parent) and `root` + `reply` for a nested one. Readers (pull.py:255, export_mirror.py:214) take root-marked, else reply-marked, so `--reply-to <root event id>` produces a tag every reader accepts. No live transport-test send was needed or made.
- Buzz CLI exit codes (crates/buzz-cli/src/error.rs `exit_code`): 1 usage/not found, 2 network / relay 5xx / delivery unknown, 3 auth/key, 4 other, 5 conflict. Connect failures stay `network error`; an ambiguous post-send failure is `delivery unknown`.
