# Poster `pending` and `resolve` (ai-tools-alerts#9sa2)

## Problem

After a send whose outcome is unknown (ssh timeout, dropped session, the CLI's
`delivery_unknown`), the poster keeps the ledger's pending entry and the journal
item in `<ledger>.poster-state.json` and sends nothing more for that advisory
until a human looks (transport/main design, "Draining an item"). Today the human
has two raw paths, both Python one-liners against the state files:
`Ledger.expire_pending(key, reason, now=...)` when the post was not delivered,
or hand-setting the journal item's `sent` when it was. A hand edit of the
journal is outside the lock and easy to get wrong.

## Interface

```
aitools-alerts-poster pending [--config <toml>]
aitools-alerts-poster resolve <key> [--config <toml>] (--delivered <event id> | --not-delivered --reason <text>)
```

`--config` defaults as for `run`. Both commands take the ledger lock (the
`Ledger` context) for their whole run, so they never interleave with an hourly
run; a held lock is exit 1 with the ledger's own message.

### `pending`

One line per pending ledger entry, oldest first, then a count line:

```
<key> kind=<root|copy|reply|digest|-> channel=<feed|critical|-> attempted_at=<ISO UTC> expires_at=<ISO UTC> outcome=<unknown|sent:<event id>|no-journal-item>
aitools-alerts-poster: pending=<N> unknown=<n> sent=<n> orphan=<n>
```

`outcome` comes from the journal item with the same key: `sent:<id>` when its
`sent` is set (the post happened; the next run records it), `unknown` when it is
not, `no-journal-item` when no item carries the key. No post text, ids list or
advisory body is printed. `expires_at` is `attempted_at + 24 h`, the earliest a
`--not-delivered` is allowed. Nothing is written. An empty journal and ledger
print only `pending=0 unknown=0 sent=0 orphan=0`. Exit 0.

### `resolve <key> --delivered <event id>`

The event id must be 64 lowercase hex (the transport's own check), else exit 2.
The key must be pending in the ledger and have a journal item, else exit 2. A
journal item whose `sent` is already a different id is refused (exit 2); the
same id is accepted (finishing an interrupted resolve or run).

When the item is not yet sent, the checks `_record` would make run first, so a
wrong id is refused with nothing written (exit 2) rather than journaled where it
would stall every later run: the id is already recorded anywhere in the ledger
(`Ledger.has_event`) or in `digest_ids`; a `root` whose ids another thread
already holds; a `copy` or `reply` with no recorded thread (resolve its root
first). Stage-1 review, SUBSTANTIVE 1 and 2.

Then exactly what a successful send does in `Run.deliver`: set the item's `sent`
to the id and save the journal, then the existing post-send path records it in
the ledger (`record_root` / `add_channel` / `record_reply` / digest
acknowledgement, idempotently), clears the pending entry and removes the item.
The code path is `Run.deliver` itself, entered with `sent` set, so the two cannot
drift. The next run neither resends nor re-records. A LedgerError from recording
(for example another thread holding the ids) is exit 1 with its message; the
journal then holds the id and the next run finishes the record as for any sent
item.

### `resolve <key> --not-delivered --reason <text>`

The key must be pending (exit 2 otherwise) and the reason non-blank (exit 2). A
journal item whose `sent` is set is refused (exit 2): the journal says the post
happened, so expiring it would resend a delivered post. Before 24 h from
`attempted_at` it refuses with exit 2 and prints when it is allowed (ISO UTC).
Otherwise `Ledger.expire_pending(key, reason, now)`: the entry moves to
`expired` with the reason, and the next run sends the item again from the
journal.

### Exit codes

0 success; 2 refused with nothing changed (not pending, malformed id, under
24 h, journal disagrees, blank reason, config error); 1 the ledger or journal
could not be used (lock held, malformed file, a record error).

## Success criteria

1. `pending` on an empty state prints the zero count line and exits 0.
2. `pending` after an unknown send lists the key with kind, channel,
   attempted_at and `outcome=unknown`, and no post text.
3. `resolve --delivered` after an unknown root: the ledger has the thread with
   that event id, nothing pending, the journal empty; a following run sends
   nothing for it.
4. `resolve --not-delivered` before 24 h exits 2 naming the time; after 24 h it
   exits 0 and the next run resends the item.
5. A key not pending, and a malformed event id, exit 2 and change nothing.
6. Under 250 changed lines; standard library only.

## Approach

Two functions in `aitools_alerts/poster/main.py`, `pending(now, config)` and
`resolve(now, config, key, delivered=None, reason=None)`, each returning
`(exit code, lines)`, and two subparsers in `main()`. `resolve --delivered`
builds a `Run` (no channels, no ssh: `deliver` never reaches the transport for a
sent item) and calls `deliver`. README gains a short "For the fleet: the poster"
section with both commands.

## Alternatives

- A `--force` on `--not-delivered`: not added. The 24 h floor is the ledger's
  guard against a resend while a slow send can still land; a bypass lowers a
  safeguard. `--delivered` works at any age, which is the case a human can
  settle before 24 h.
- Methods on `Ledger`: the delivered path needs the journal and `Run._record`,
  which live in `main`; keeping it there avoids a second recording path.
- Printing the post text in `pending`: refused by the task (counts only).

## Blast radius / rollback

New subcommands only; `run` is unchanged. No live state is touched: the
coordinator reinstalls the live poster. Rollback is a revert of the commit.

## Assumes

- A pending entry without a journal item cannot be `--delivered` (there is
  nothing to record); it can be `--not-delivered` after 24 h, which just
  removes the pending entry.
