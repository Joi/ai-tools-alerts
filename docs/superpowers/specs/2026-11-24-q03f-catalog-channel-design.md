# q03f: the catalog channel and catalog.json (producer side)

Slice 8 of ai-tools-alerts#9mx8, design section "1. Two outputs". Kata:
ai-tools-alerts#q03f. Split on kata: the CLI's pull and match of
`catalog.json` is ai-tools-alerts#8nb4; the live steps are
ai-tools-alerts#q3fd.

## Problem

Version 2 has two outputs. The channel (#security-feed, #security-critical)
carries only what many members run and can act on. The catalog carries every
in-scope advisory, signed, for machines to match. Today the poster has no
catalog: a notice reaches people only as a digest line, and a machine has no
signed record of it at all. The mirror serves `feed.json` and `critical.json`
only.

## Constraints (from landed code and the t8jr note, c:dp781t)

1. Released readers v0.1.4 to v0.1.7 fetch `manifest.json`, `feed.json`,
   `critical.json`, the certificate and the checkpoint, nothing else. A new
   file is safe.
2. Catalog events must never be served in `feed.json` or `critical.json`:
   v0.1.4/v0.1.5 do not check the channel tag and would show every catalog
   entry as an alert.
3. The signed checkpoint must not list a catalog event: v0.1.6/v0.1.7 refuse a
   pull whose checkpoint names an event absent from `feed.json` and
   `critical.json` ("mirror incomplete").
4. `pull.channel_ids()`, `inputs.load_channels()` and the exporter's
   `load_channels()` each require `spec/channels.json` to name exactly
   `feed` and `critical`.
5. Standing ruling (2026-11-23): no human in the loop. Nothing here may wait
   for a person, and nothing in the catalog may stop, delay or lock out alert
   posts, the checkpoint or the alert files on the mirror.
6. The catalog channel does not exist yet; creating it is a live step (q3fd).
   The code must land dormant and switch on when its id is added.

## Answer recorded for the issue

The Buzz app cannot leave a channel muted by default. In block/buzz (main at
ed29172, 2026-11-24) a mute is a per-member flag kept by the member's own
client (desktop local storage `buzz-channel-mutes.v1:<pubkey>`, synced as the
member's kind 30078 event `d=channel-mutes`); the relay and the channel carry
no default, and an absent entry reads as unmuted. Members need not join
#security-catalog; its readers are the exporter and, through `catalog.json`,
the CLI.

## Approach

### Where the id lives

A new file `spec/catalog-channel.json`: `{"catalog": "<lowercase uuid>"}`.
Absent means the catalog is off everywhere. Present but malformed, or equal to
either alert channel id: the catalog is off for that run, with one stderr
line, in the poster and in the exporter alike; alert work and the alert files
go on as before. This slice does not add the file (no channel exists yet);
q3fd does.

### Identity

A catalog entry is one advisory for one product: key
`<product name>|<advisory id casefolded>` (the ledger's scope name is the
product name, and every block the poster composes has exactly one product).
The same CVE in two products is two entries. The reader rule (for 8nb4): the
newest catalog root per (advisory id, `products[0].name`) is that entry's
current block; for any advisory id and product that also has a thread in
`feed.json` or `critical.json`, the alert thread wins, so a curator's
correction or retraction there governs (the catalog carries no retraction of
its own; a catalog-only advisory has no curator path today, which is c1g2's
area).

### Poster: snapshot under the ledger lock, inventory after it

New module `aitools_alerts/poster/catalog.py`. While the run holds the ledger
lock, after planning and the recompute and **before** `digest()` (which
removes the notices it lists from `state["held"]`), the run takes a snapshot
in memory; no catalog file is read or written under the ledger lock (plan
review B1). The send pass merges it into the catalog inventory,
`<ledger>.catalog-known.json`, under the catalog lock. The snapshot holds:

- every ledger entry whose product is in scope now and starts at its level
  (`rules.scope_of(e.scope)` resolves to that name and
  `rules.starts(scope, e.level)`; this keeps the ruleset's `channel_if`
  exception for an out product at high and drops an out product at notice);
- every held notice (`state["held"]`; out notices are never held, wa6n);
- synthetic ids skipped (`compose.is_synthetic`).

Each gives its current advisory (the ledger entry's `advisory`, which
`record_reply` keeps merged, or the held entry's `adv`). The inventory keeps
the newest advisory per key, persists across runs (a notice the digest later
drops stays), and holds at most 20,000 keys (oldest `posted_at` dropped
first). A key whose product leaves scope is dropped. Limits stated, not
fixed here: notices digested before the lane was first switched on are not
in the inventory (the poster keeps only their ids), and a notice re-sighted
after its digest is ignored by the poster's `hold()` and so is not updated
(ai-tools-alerts follow-up filed).

### Poster: sending, after the lock and the checkpoint

After `run()` leaves `with Ledger(...)` and after the checkpoint, and only
when the run's English work succeeded (`english_ok`) and the lane is on:

- take the catalog lock `<ledger>.catalog.lock`, waiting at most 60 s
  (still busy: skip, status `busy`; the next run's snapshot carries every
  thread and every notice still held), then merge the snapshot into the
  inventory;
- read the inventory and the sent map `<ledger>.catalog.json`
  (`{"v": 1, "sent": {key: {"event": hex64|null, "digest": hex64}}}`,
  written only under the catalog lock);
- for each key whose digest (sha256 of the canonical JSON of the validated
  advisory) differs from the sent map, oldest `posted_at` first, at most
  `MAX_PER_RUN = 20` sends and no new send after `DEADLINE = 120` s from the
  start of the pass: compose the catalog post (a two-line body
  `<LEVEL>: <title>` and `Source: <primary url>`, then the block, through
  `compose._guard`), `send(channel_id, text, None)`;
  - `ok`: record `{"event": id, "digest": d}` and save;
  - `refused`, or a compose `ValueError`: record the digest with
    `"event": null`, so the same block is not tried again (a changed block
    is);
  - `failed` or `unknown`: stop the pass; record nothing (the next run
    sends again; an unknown that did post becomes a harmless duplicate);
- drop sent keys that are no longer in the inventory.

No replies and no Japanese copy: a changed advisory posts a new root with its
whole block. Every catalog post is a root, so a lost or duplicated post
heals on the next change.

**Never the checkpoint.** The lane never calls `signer.record_sent`, so no
checkpoint owes or lists a catalog event, and `signer.window` binds events
with `pull.channel_ids()`, which stays the two alert channels.

**Isolation.** The pass runs with no ledger lock held, after the checkpoint,
so its time cannot delay alert sends, the checkpoint or the next hourly run.
Any exception in it is caught. The summary gains ` catalog=<sent>/<waiting>`
(or `busy`, `error`, `off-bad-spec`) only when the file exists, so with no
file the summary line is byte for byte what it was. Nothing in the lane
reaches the exit code.

### Exporter: catalog.json, after the alert files

`mirror/export_mirror.py` reads `spec/catalog-channel.json` from its checkout
(or `--catalog PATH`). The alert channels are read, cleaned, capped and
written exactly as today, the checkpoint included, before anything touches
the catalog. Then, when the id is present and valid:

- read the catalog channel's newest `MAX_CHANNEL_EVENTS` rows (the psql
  query gains `ORDER BY created_at DESC LIMIT n` for this channel only, then
  the rows are put back in date order; the file reader takes the last n);
- `clean()` them with the binding set `{catalog id}` alone, so an
  alert-channel event never enters `catalog.json`; keep the newest within
  `MAX_CHANNEL_BYTES`;
- write `catalog.json` (`channel_doc("catalog", ...)`).

A malformed spec file, an id equal to an alert channel's, or any failure
reading or cleaning the catalog leaves the previous `catalog.json` in place
and is reported in the summary (`catalog=skipped:<reason>`); the exit code
and the alert files are what they would have been without it. The alert
files' binding set stays the two alert ids. `catalog.json` is not in the Atom
feeds, the index page or the checkpoint. Absent spec file: no `catalog.json`
is written, and an old one in `--out` stays as it was.

### Feed rule (no change)

"Only channel-class items at high or critical post to #security-feed" already
holds by ruleset class_cap (9kgk, wa6n); a catalog or out entry with
`channel_if` posts a remote-code-execution flaw at high, which is the
design's "unless code execution is remote". A test pins it.

## Success criteria

1. With no `spec/catalog-channel.json`, a poster run's summary line and every
   send are identical to today (existing tests pass unchanged).
2. With the file, a run that posts a high root to feed also posts that
   advisory's block once to the catalog channel; a held notice posts once,
   including one first seen in the run that sends the digest; a second run
   with nothing new posts nothing to the catalog; a fix learned posts one new
   catalog root.
3. The same advisory id in two products gives two catalog entries.
4. A synthetic (`--kev-file`) advisory never posts to the catalog.
5. Catalog sends happen after the ledger lock is released and after the
   checkpoint: a catalog send that fails leaves the exit code 0 and the alert
   sends done, and the ledger can be opened by another run while the catalog
   pass is sending.
6. No catalog event id is ever written to the owed checkpoint state, and the
   checkpoint a run signs lists none.
7. The exporter writes `catalog.json` with the catalog channel's verified
   events; an alert-tagged event in the catalog rows is dropped; a
   catalog-tagged event in the feed rows is dropped from `feed.json`; a bad
   catalog spec or a catalog read failure leaves `feed.json`,
   `critical.json` and the checkpoint written as without the catalog.
8. `scripts/test-gate.sh` passes.

## Alternatives considered

- **Catalog as a third channel of the alert thread** (`CHANNELS_FOR` gains
  `catalog`, notices become ledger threads). Rejected: every notice becomes a
  thread, which changes the digest's posted/held split, the recompute's set
  of judged threads and the age limit; slices 9kgk/ny5g/0dvh own those.
- **A third key in spec/channels.json.** Rejected by constraint 4.
- **Catalog replies (thread per advisory).** Rejected: needs a per-advisory
  reply chain and patch semantics for a machine-only feed; a newest-root rule
  is simpler for the reader and self-heals after a lost post.
- **Sending inside the ledger lock.** Rejected (spec review B2): 20 relay
  sends at up to 90 s each would hold the lock past the next hourly run.
- **A catalog checkpoint now.** Deferred: it needs a second signed list
  (constraint 3 forbids using the existing one). Named as a limit in 8nb4.

## Blast radius and rollback

Dormant until q3fd adds the id. Poster: one new module, a snapshot call under
the lock, a send pass after it, three new files beside the ledger. Exporter:
one optional file, written last. Rollback: remove
`spec/catalog-channel.json` (lane off, no `catalog.json` updates) or revert
the merge.

## Open questions

None blocking. The catalog's withholding limit (no checkpoint) is recorded in
8nb4.
