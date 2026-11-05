# Plan: poster `pending` and `resolve` (ai-tools-alerts#9sa2)

Spec: docs/superpowers/specs/2026-11-05-poster-resolve-pending-design.md

## Chunk 1 — resolve-pending (one commit)

Files: `aitools_alerts/poster/main.py`, `aitools_alerts/poster/ledger.py`, `tests/poster/test_main.py`, `README.md`.

- [ ] `main.py`, after `run()` (l.484-549): add `_iso(t)` (UTC, `Z`), and
  `pending(now, config) -> (code, lines)`:
  `with Ledger(config.ledger) as led:` load the journal with
  `inputs.load_state(config.state, now, config.backfill_days)` (never saved),
  index outbox items by key, and for each `led._state()["pending"]` sorted by
  `at` emit `<key> kind= channel= attempted_at= expires_at= outcome=`; count
  `unknown`, `sent`, `orphan`; last line
  `aitools-alerts-poster: pending=N unknown=n sent=n orphan=n`. A LedgerError
  (lock held, malformed file) returns code 1 with the message. Add a public
  `Ledger.pending_entries()` returning copies, so main does not read `_state()`.
- [ ] `resolve(now, config, key, *, delivered=None, reason=None) -> (code, lines)`:
  - `delivered` not `None` and not `transport._HEX64.fullmatch` → 2.
  - under the lock: `p` = the pending entry for `key`, none → 2;
    `it` = journal item with `key`.
  - delivered: no `it` → 2; `it["sent"]` set and `!= delivered` → 2; unsent
    and the id already in the ledger (`Ledger.has_event`) or `digest_ids`, a
    root whose ids another thread holds, or a copy/reply with no thread → 2; else
    `it["sent"] = delivered`, `save_state`, `Run(now, config, led, state, {}, None, None).deliver(it)`;
    print `resolved <key>: delivered as <id>, recorded`.
  - not delivered: blank reason → 2; `it` with `sent` set → 2 (the journal
    says it posted); `now - p["at"] < ledger.PENDING_EXPIRY` → 2 with
    `not before <iso(p.at + 24h)>`; else `led.expire_pending(key, reason, now=now)`;
    print `resolved <key>: expired; the next run sends it again`.
  - LedgerError anywhere → 1 with the message.
- [ ] `main()`: subparsers `pending` (`--config`) and `resolve` (`key`,
  `--config`, mutually exclusive required group `--delivered ID` /
  `--not-delivered`, `--reason TEXT`). Config errors exit 2 as `run` does.
  Print lines: data lines to stdout, refusals/errors to stderr.
- [ ] Module docstring: one sentence naming the two subcommands.
- [ ] Tests (`tests/poster/test_main.py`, after `test_unknown_outcome_keeps_pending`):
  1. `pending` on an empty journal: code 0, the zero count line only.
  2. `pending` after an unknown root: key line with `kind=root channel=feed
     outcome=unknown`, no post text (assert the item's text is absent).
  3. `resolve --delivered`: ledger entry with that root id, nothing pending,
     empty outbox; a later run with the same input sends nothing.
  4. `resolve --delivered` with a malformed id → 2; with a key not pending → 2;
     nothing changed.
  5. `resolve --not-delivered` at +1 h → 2 and the message names the time;
     at +25 h → 0, the entry is in `expired`, the next run resends.
  6. `--not-delivered` when the journal item has `sent` set → 2.
  7. Through `main.main([...])` once per command, to cover argparse and exit codes.
- [ ] README: a "For the fleet: the poster" section before "## Tests": what an
  unknown send leaves behind, `pending`, the two `resolve` forms, the 24 h rule.

## Verification

- `python3 -m pytest -q tests/poster` then `scripts/test-gate.sh` (the repo's
  gate; no repoman row: the repo has no `.repoman-managed`).
- `git diff --shortstat origin/main -- aitools_alerts tests README.md` on the committed branch: under 250
  changed lines (the budget covers code, tests and README; the run artifacts under docs/ are not counted).
- `git diff origin/main -- aitools_alerts tests README.md | grep -Eic '<the pattern in scripts/public-scan.sh>'` prints 0
  (scoped to the deliverables: this plan names the pattern itself, so docs/ is excluded).

## Acceptance

Spec success criteria 1-6.

## Rollback

`git revert` the commit; `run` is untouched.
