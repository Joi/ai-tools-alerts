# Run: poster-input-visibility
Instruction: Task ai-tools-alerts#akq9 per TASK-ai-tools-alerts#akq9.md — poster summary shows skipped inputs (inputs= field, rejected inputs hold their watermark, KEV failure on stderr); keep the last 10 digest event ids (digest_ids) and print the id on stderr; `run --digest-now` once per Tokyo date; `run --kev-file <path>` with tests/fixtures/kev-synthetic.json for E3. /do-it with the rung floored at medium; security-shaped review on gpt-6-astra. Non-repoman repo (ff-merge ending).
Stage: spec
Rung: medium (start-floor medium: dispatch floor; evaluator verdict below)
Spec: docs/superpowers/specs/2026-11-05-poster-input-visibility-design.md   Plan: docs/superpowers/plans/2026-11-05-poster-input-visibility.md
Agency project: — (no mcp__agency tools in this session; built inline, as the earlier runs on this repo did)
Kata: ai-tools-alerts#akq9
Last reviewed: —

## Scorecards

## Chunks
- [ ] inputs-visibility — inputs= field, watermark hold, stderr lines
- [ ] digest — digest_ids, --digest-now
- [ ] kev-file — --kev-file, SYNTHETIC TEST head line, fixture

## Notes
- Exit code on an input outage (the brief asks for a recommendation, not a change): keep exit 0. launchd ignores the exit code of a StartInterval job, so exit 1 would change nothing an operator sees, and it would make a one-hour CISA hiccup look like a send failure (exit 1 today means "a send failed or the ledger refused": something a human may need to clear). The outage is now in the summary line (`inputs=kev:unavailable`, `collector:rejected`, `heartbeat:N/M` with N<M) and on stderr; the right alarm is a watcher that reads several consecutive summary lines (for example kev unavailable three hours running), not a per-run exit code. If Joi wants a code anyway, a distinct exit 3 ("ran, an input was unavailable") keeps exit 1's meaning.
