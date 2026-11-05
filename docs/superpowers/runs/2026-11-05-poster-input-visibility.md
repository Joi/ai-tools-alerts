# Run: poster-input-visibility
Instruction: Task ai-tools-alerts#akq9 per TASK-ai-tools-alerts#akq9.md — poster summary shows skipped inputs (inputs= field, rejected inputs hold their watermark, KEV failure on stderr); keep the last 10 digest event ids (digest_ids) and print the id on stderr; `run --digest-now` once per Tokyo date; `run --kev-file <path>` with tests/fixtures/kev-synthetic.json for E3. /do-it with the rung floored at medium; security-shaped review on gpt-6-astra. Non-repoman repo (ff-merge ending).
Stage: committing
Rung: medium (start-floor medium: FC=2, evaluator BR1 REV2 NOV1 INT2 FC2 = 8, no hard trigger)
Lens: "Exit code stays 0 for a quiet hour with healthy inputs"; "recommend, do not change the contract silently"; "No live send from this task"; "do not run that reinstall yourself"
Spec: docs/superpowers/specs/2026-11-05-poster-input-visibility-design.md   Plan: docs/superpowers/plans/2026-11-05-poster-input-visibility.md
Agency project: — (no mcp__agency tools in this session; built inline, as the earlier runs on this repo did)
Kata: ai-tools-alerts#akq9
Last reviewed: spec+plan 9bc64fce8c422415700435b379d8399ca8e47220 (pass 1, gpt-6-astra, run 20261105-134230-a43cba)

## Scorecards
Pass 1 [spec+plan]: 1B/6S/0C/0R · fixed -/- · velocity = (—→7, escalation no)
- Reviewer graded all 7 "major". BLOCKER: 1 (a synthetic advisory listed in the digest without its marker). SUBSTANTIVE: 2 (a file candidate merged with a real update), 3 (KEV floor from `now` when kev_since is None), 4 (a refused input superseded by a newer one), 5 (collector diagnostic lacks the dir name), 6 (missing replay / malformed / forced-while-journaled tests), 7 (rollback without writer exclusion).
- Fixed: 1 and 2 by making the id the provenance (`--kev-file` accepts only CVE-2099-NNNN ids; compose marks the root head line and the digest line for any such id; no run-local set); 3 (floor = the state's `since`); 5 (`collector_record(..., rejected)` returns the name); 6 (tests: replay records once, >10 and non-hex refused, --digest-now while a digest is journaled, multi-day KEV recovery, same-run digest marked); 7 (spec rollback steps: bootout, wait, atomic rewrite under the ledger lock, old loader check, bootstrap).
- Rebutted: 4. Supersession is the input contract, not a loss: a collector record is a whole snapshot and only the newest is read; with no heartbeat watermark only the newest dir is read because its run.json is cumulative. Spec S3 now says so.
- Medium rung: no delta on the documents; the BLOCKER fix is code-reviewed in the whole-branch pass.

Pass 1 [code:whole branch c9c8d84]: Stage 1 0B/1S/4C · fresheyes (gpt-6-astra, run 20261105-135007-9db810) 3B/1S/0C · fixed -/- · velocity = (—→9, escalation no)
- Stage 1 S1 and fresheyes B2/B3 (one cause: a reserved alias from a real feed marks, merges into or silences an advisory): fixed in b4415a5. Only the primary id marks (`compose.is_synthetic(id)`), heartbeat and collector candidates drop CVE-2099 aliases (`main._real`).
- fresheyes B1 (a synthetic thread updated through a real alias composes unmarked): fixed in b4415a5. A thread whose primary id is synthetic takes no copy or reply from any input.
- fresheyes S4 (pre-existing: date-only KEV dateAdded on the floor day dropped as old, backfill_days=0): fixed in b4415a5 (judged at the day's end).
- Stage 1 cosmetics: 2 fixed (inputs imports SYNTHETIC/SYNTHETIC_ID from compose); 5 fixed (tests: first heartbeat dir rejected sets no mark; feed copy text asserted). 3 left: a not-validated collector record reads `collector:rejected` (an unvalidated record is not one the poster may read; "pending" would hide a validator that fails every hour). 4 left: a whole-input rejection appears in both the named stderr line and the skipped counts (the counts line is the full tally; one line names the input).
- BLOCKER fixes changed behaviour: one delta pass `--since c9c8d84`.
Pass 2 [code:delta --since c9c8d84, head b4415a5]: 1B/0S/0C/0R · fixed 6/6 prior · velocity ↓ (9→1, escalation no)
- fresheyes (gpt-6-astra, run 20261105-135718-b6389a). B: a collector candidate with a reserved primary id and a real alias still merged into the real advisory. Fixed after the delta: heartbeat and collector candidates with a reserved primary id are dropped (counted `reserved synthetic id`), so only KEV entries, which carry no aliases, can be synthetic; test in both orders. No further pass (ruling jibot-code#41e2).

## Chunks
- [x] inputs-visibility — inputs= field, watermark hold, stderr lines
- [x] digest — digest_ids, --digest-now
- [x] kev-file — --kev-file, SYNTHETIC TEST head line, fixture

## Notes
- Exit code on an input outage (the brief asks for a recommendation, not a change): keep exit 0. launchd ignores the exit code of a StartInterval job, so exit 1 would change nothing an operator sees, and it would make a one-hour CISA hiccup look like a send failure (exit 1 today means "a send failed or the ledger refused": something a human may need to clear). The outage is now in the summary line (`inputs=kev:unavailable`, `collector:rejected`, `heartbeat:N/M` with N<M) and on stderr; the right alarm is a watcher that reads several consecutive summary lines (for example kev unavailable three hours running), not a per-run exit code. If Joi wants a code anyway, a distinct exit 3 ("ran, an input was unavailable") keeps exit 1's meaning.
