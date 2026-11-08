# A refused item is withheld; the run goes on (ai-tools-alerts#8acj)

## Problem

On 2026-11-08 the relay refused the journaled digest with the Buzz CLI's error
line `{"error":"user_error","message":…,"retryable":false}` on stderr, exit 1.
`transport._classify` classes exit 1 as `failed`, and `Run.deliver` raises
`_Stop` on any failed send. The outbox drains first, so for 13 hours every run
stopped on the same item before any root or reply: marks were not saved, every
candidate was deferred and recounted, translation was skipped, and the same
text was resent unchanged every hour. k5tr removed that refusal's cause; this
issue makes sure one refused post can never stop the service again.

## Success criteria

1. A send whose stderr carries a CLI error line with `"error": "user_error"` and
   `"retryable": false` (exit 1) is a new transport outcome, `refused`, with the
   relay's message. Every other exit-1 result stays `failed`; exit 2, 255,
   timeouts and every other outcome are classified exactly as today.
2. On `refused`, the item (and, for a root, the copies journaled with it, which
   cannot send without it) leaves the outbox for a new state list `withheld`,
   with the message and the time. The state is saved first, then the pending
   mark is cleared (it certainly did not post): a crash between the two leaves
   the item withheld with a stale mark, which `resolve` clears; the other order
   would let a crash resend it unchanged. The summary counts `withheld=1`; the run does not stop: later
   items send, the watermarks save, curator translation and the Japanese
   replies run.
3. A withheld item is never sent again by a run. While it is withheld, a new
   candidate under any of its ids, or under any id of the ledger thread it
   belongs to (its `root`), waits (`busy`, deferred), and no new digest
   is built while a digest is withheld, so no equivalent text is regenerated
   and refused again, and two digests never acknowledge the same notices.
4. Each run prints one stderr line while `withheld` is non-empty:
   `aitools-alerts-poster: withheld=N refused by the relay; see 'pending', then 'resolve <key> --requeue|--drop'`.
5. `pending` lists each withheld item: `<key> kind=… channel=… withheld_at=… outcome=refused message=<relay message>`
   (one line, no post text), and its totals line adds `withheld=N` while the
   list is non-empty (unchanged otherwise).
6. `resolve <key> --requeue [--text-file PATH]` moves the withheld group back
   to the end of the outbox; with `--text-file`, the file's text replaces the
   refused text in every item of the group that carried it (checked as a journal
   item's text is: non-empty, within the post cap, no NUL) and must keep the
   `aitools-alert` block byte-identical (`schema._last_block`), so the ledger's
   record of the advisory still matches what posts; only the prose changes.
   `resolve <key> --drop` discards the group. Both run under the ledger lock,
   clear any pending mark left on the group's keys (never one whose key is
   journaled again as a live item), and refuse (exit 2, nothing
   changed) a key that is not withheld or a requeue whose keys are journaled
   again. Keys are unique within the journal as today; withheld keys are not
   checked against it at load, so an unexpected clash refuses the requeue
   instead of making the state unloadable.
   After `--drop`, the advisory's deferred candidates (or, for a digest, the
   held notices) are planned again by the next run from the current code: this
   is the route after a compose fix lands. If the new text is refused again it
   is withheld again: one send per operator action, never an automatic retry.
7. Transport `failed` and `unknown` keep today's behaviour: `_Stop`, exit 1,
   nothing more sent, marks not saved.
8. A Japanese reply the relay refuses is dropped (counted `ja_failed`, one
   stderr line), so it is never resent unchanged, never ends the other
   Japanese sends, and translations never grow the withheld list. Each English
   group blocks its own advisory (or the one digest) from being planned again,
   and a group is stored only while the list's JSON stays within 4 MiB (the
   Japanese backlog's bound, `MAX_JA_BYTES`); past it the refused item is
   dropped with its stderr line, so the state never nears `load_state`'s
   16 MiB limit.
9. A state file without `withheld` (every file written so far) loads as an
   empty list.

Acceptance (issue): a fixture run with one refused item and two sendable items
ends with `withheld=1`, two sends recorded, marks saved; a network failure still
stops the run; the withheld item is listed and can be requeued;
`scripts/test-gate.sh` passes; under 200 changed lines.

## Approach

- `transport.py`: `_cli_error` also returns the line's `retryable`; in
  `_classify`, `rc == 1` with category `user_error` and `retryable is False` is
  `refused`. `SendResult` gains `message: str = ""` (the relay's message, cut to
  300 characters, one line).
- `inputs.py`: `withheld` joins `_STATE_KEYS`; a missing key loads as `[]`; each
  entry is `{"key", "items", "message", "at"}` with `items` a non-empty list of
  valid journal items whose first item's key is `key`.
- `main.py`: `Run.deliver` handles `refused` before the failed/unknown branch
  through a `_withhold(it, message)` helper, then returns True (the caller goes
  on). `enqueue` skips items no longer in the outbox. `busy` also matches
  withheld items. `digest` returns early when a digest is withheld. `run` prints
  the stderr line after its last save. `pending` and `resolve` gain the
  withheld lines and the requeue/drop branch; `main` adds the flags.

## Alternatives considered

- Keep the item in the outbox with a `withheld` flag: every reader of the
  outbox (drain, busy, digest, translation reconciliation, the ja backlog bound)
  would need to skip it; one missed check resends it. A separate list is safe
  by construction.
- Drop the refused item and only log it: loses the post; the issue asks for
  requeue after a fix.
- A new subcommand (`withheld`/`requeue`) instead of `resolve` flags: the issue
  asks for the `pending`/`resolve` shape; one settle command is what an
  operator already knows.

## Blast radius and rollback

Only the poster's send path and its state file change. A state file holding a
`withheld` key is refused as malformed by the previous poster version, even
an empty one, so a rollback stops the hourly job, settles every withheld group
(`resolve --requeue` or `--drop`), always removes the `withheld` key from the
state file, reinstalls the previous version, then restarts the job. The coordinator reinstalls after landing; nothing live is
done by this run.

## Open questions

None blocking. Assumes the relay's refusal line is the Buzz CLI's
`print_error` JSON with a boolean `retryable` (tests/poster/test_transport.py
already models it that way).
