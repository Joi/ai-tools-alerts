# Run: poster-resolve-pending
Instruction: Task ai-tools-alerts#9sa2 per TASK-ai-tools-alerts#9sa2.md — add `aitools-alerts-poster pending --config <toml>` (pending ledger keys with journal item kind, channel, attempted_at and outcome; counts only, no post text) and `aitools-alerts-poster resolve <key> --config <toml> (--delivered <event id> | --not-delivered --reason <text>)`, both under the ledger lock, with the 24 h rule of expire_pending (a --not-delivered before 24 h refuses and says when it is allowed). --delivered records the event id on the journal item and the ledger entry exactly as a successful send would; --not-delivered expires the pending entry. Exit 0 on success, 2 on a key that is not pending or a malformed id. Tests in tests/poster/test_main.py; docs in the README poster section. Under 250 changed lines. /do-it with the rung floored at medium; security-shaped review on gpt-6-astra. Non-repoman repo (ff-merge ending).
Stage: spec-review
Rung: medium (start-floor medium: evaluator BR1 REV0 NOV1 INT1 FC1 = 4, no hard trigger; constraint lens + prod-shaped; also the dispatch floor)
Lens: "`--delivered` records the event id on the journal item and the ledger entry exactly as a successful send would, so the next run neither resends nor re-records"; "counts only, no post text"; "the 24 h rule the ledger's expire_pending enforces ... do not add one [--force] silently"; "No live state is touched by this task"; "Under 250 changed lines"
Spec: docs/superpowers/specs/2026-11-05-poster-resolve-pending-design.md   Plan: docs/superpowers/plans/2026-11-05-poster-resolve-pending.md
Agency project: — (no mcp__agency tools in this session; built inline, as the earlier runs on this repo did)
Kata: ai-tools-alerts#9sa2 (kata search "resolve pending poster": 9sa2, kfq6 (B4, origin), h2gf (B3, ledger))

## Scorecards
Pass 1 [spec+plan]: 1B/4S/1C/0R · fixed -/- · velocity = (—→6, escalation no)
- fresheyes gpt-6-astra, run 20261105-174149-0ef27d, snapshot cf8fbd9; six "major", graded here.
- B (stale `--delivered <id>` settles a newer send under the same key, skipping its record): fixed by the pre-checks added after Stage 1: an id already recorded anywhere in the ledger (`Ledger.has_event`) or in `digest_ids` is refused with nothing written. A newer attempt under a key cannot exist while the old one is pending (the pending entry blocks every resend), so a stale decision can only carry an already-recorded id.
- S (tests cover only the happy root path): fixed in part: digest `--delivered`, lock held (exit 1), already-recorded id, journal-says-sent, key not pending, bad id, blank reason. Copy and reply `--delivered` run the same `Run.deliver` path as a real send, whose copy/reply recording the existing run tests cover; not duplicated within the 250-line budget.
- S (host-name grep matches the plan's own text): fixed, scoped to aitools_alerts, tests, README.md.
- S (line budget scope, ledger.py missing from the file list): fixed in the plan.
- S rebutted ("counts only" contradicts per-key lines): the task brief itself asks `pending` to list "pending ledger keys with their journal item kind, channel, attempted_at and outcome; counts only, no post text". The per-key metadata is required; "counts only" excludes post text and advisory content, which are not printed.
- C rebutted (snapshot commit message): cf8fbd9 is a dangling review snapshot built by commit-tree; it never lands on a branch.
Stage 1 [code:resolve-pending, uncommitted pre-fix diff]: 0B/2S/2C/0R (same-model subagent)
- S1 (a wrong id journaled before `_record` refuses it stalls every hourly run, and the tool cannot undo it): fixed: the checks `_record` makes run before the save (root ids held by another thread; copy/reply with no thread), exit 2, nothing written.
- S2 (an id already belonging to another thread is accepted, corrupting `thread()` lookups): fixed with `Ledger.has_event` + `digest_ids`; test `test_resolve_delivered_refuses_what_would_not_record`.
Pass 1 [code:resolve-pending, whole branch fb0b0bfc1ba9df3cf54292a0f291a52ac91c75d2]: 1B/2S/0C/0R · fixed 7/7 prior · velocity ↓ (6→3, escalation no)
- fresheyes gpt-6-astra, run 20261105-174655-1a7938; three "major".
- B fixed (behaviour): an event id journaled as `sent` on another outbox item (sent, crashed before recording) was accepted; now refused, with a regression in `test_resolve_delivered_refuses_what_would_not_record`. Delta pass follows (`--since fb0b0bf`).
- S fixed (plan only): the host-name grep used a placeholder pattern; now the concrete pattern, and a planted name prints 1.
- S rebutted (a retried `--not-delivered` can expire a later attempt under the same key): it needs the resolve process to die after the expiry is saved, an hourly run to retry and get a second unknown outcome, and then the operator to re-run the same command 24 h or more later without re-reading `pending`. The operator procedure is `pending`, check the channel, `resolve`; the 24 h floor forces a fresh look at a new attempt. Binding to an attempt id would add a required flag to the interface the brief fixes (`resolve <key> (--delivered <id> | --not-delivered --reason <text>)`). Kept as is.
- C (only LedgerError caught): fixed, any other exception is exit 1 with a one-line message. C (inline dict counter): left.

## Chunks
- [ ] resolve-pending — main.py subcommands, tests, README

## Notes
- --force: not added. The 24 h floor is the ledger's guard against a resend while a slow send may still land; a bypass would lower a safeguard (class c), and a human who has checked the channel can use --delivered at any age, which is the case that matters before 24 h.
