# Retractions that survive revocation (ai-tools-alerts#jpzy)

## Problem

`pull._filter` keeps only events whose key is in the current manifest, and
`pull.advisories` lets only a curator retract. Removing a curator from the
manifest drops every event it signed, its retraction replies included, so a
thread it retracted whose root was posted by a key that stays trusted (the
relay bot, another curator) is rebuilt as active. Confirmed live on
jibot-code#gs18 (E3): after manifest v3 removed the test curator, the
synthetic critical CVE-2099-0010 came back on both relay-bot threads.

## Decision (coordinator, recorded in the brief; ruling k777)

1. A revoked key's events stay dropped, retractions included. Revocation is
   for compromise, and a compromised curator's retractions of real alerts
   must be undone by revoking it. Rejected: keeping retractions signed by a
   curator that was trusted when they were stored (option a).
2. The signed manifest carries the retractions that must survive: an
   optional top-level `retracted` list of advisory ids. A reader marks every
   thread whose advisory id or alias is in that list as retracted, whatever
   the state of the keys that posted or retracted it.
3. `aitools-alerts curator retract` never refuses because local state
   already holds the thread as retracted: it pulls, posts, and says on
   stderr that the thread was already retracted locally.
4. A relay deletion (kind 9005) stays ignored by readers: readers trust
   signed posters, not relay admin events. The pull docstring says so.
   Rejected: the root's poster retracting its own thread (option b), because
   the relay bot never lowers an alert by design (docs/design.md).

## Approach

**manifest.py.** Content keys: `version`, `issued_at`, `posters` required;
`retracted` optional. When present it is a list of 0..`MAX_RETRACTED`
(1024) distinct strings, each matching the advisory id pattern
(`schema._IDENT`). `Manifest` gains `retracted: tuple[str, ...] = ()`;
`parse_content` and `_parse_event` return it as a fourth element, and
`verify` compares it with the event like the other fields, so a
`Manifest` whose `retracted` was edited after load does not verify. A
manifest without the key parses to `()` and loads, verifies and behaves
exactly as before. No format version is pinned anywhere (the `version` field
is the manifest's sequence number, not a format), so there is no schema
bump; the change is additive.

**pull.advisories.** After the replies are applied, a thread is marked
retracted when any advisory id it has carried is in the effective
manifest's `retracted`: the root's `id`, the root's `aliases`, and the
`aliases` a curator patch gave the thread. A patch that drops an alias
cannot take the thread out of the list (the root's aliases count), and a
relay-bot patch that adds a listed id cannot pull a thread into it, since
the bot never lowers an alert (Stage 1 code review finding). Ids compare
case-folded, as the poster's ledger compares them (`cve-2099-0010` and
`CVE-2099-0010` are one advisory); the manifest refuses two ids that differ
only in case. The manifest used is
`effective_manifest(state)`, the same one that decides roles, so it is
always a verified manifest (stored records are re-verified on load; the
bundled one is verified before use). A thread so marked keeps its
`updated_at`. Nothing in the event store changes; removing an id from the
list in a later manifest makes the thread active again unless a trusted
curator's reply retracted it.

**pull: deletion events.** `advisories` skips events of kind 9005 (relay
delete-event) and kind 5 (NIP-09 deletion) whoever signed them, so a
deletion request whose first line happens to be `retract` is not read as a
retraction (spec review finding: the reader did not check the kind). The
module docstring says so: the stored events and the manifest floor stand,
and a thread is withdrawn only by a trusted curator's retraction reply or
the manifest's `retracted` list.

**scripts/sign-manifest.py.** `--retract ID` and `--unretract ID`, both
repeatable. The signed list is the previous manifest's `retracted` (from
`--out`, when it exists) plus the content file's `retracted` (if any) plus
every `--retract`, minus every `--unretract`, deduplicated case-folded
(first spelling kept) and sorted. An
`--unretract` naming an id not in that union, or an id given to both flags,
is refused before the key is read. The key is omitted when the list is
empty, so a manifest with no retractions is byte-for-byte the shape older
readers accept. The previous manifest is carried forward only if it
verifies against `TRUST_ROOT_PUBKEY`; an unverified `--out` file is refused
(it could have had ids removed). The key-reading path is not touched.

**curator.py.** `find_threads(st, root, ref, retracted_ok=False)`; the
retract command passes `retracted_ok=True`, gets every thread of the ref,
and prints `<root id>: already retracted locally; posting the retraction
anyway` on stderr for each one already retracted. Amend keeps refusing a
retracted thread.

## Success criteria (each a test)

- The pinned case: relay-bot root, curator C retracts, manifest v2 without
  C: the thread is active; manifest v2 without C and with
  `retracted: [<id>]`: the thread is retracted.
- Alias case: a root whose `aliases` holds the listed id is retracted;
  a lower-case root id or alias matches an upper-case listed id.
- A kind 5 or 9005 event with first line `retract`, from a curator or the
  bot, does not retract.
- A manifest carrying `retracted` that is unsigned, or signed by another
  root, is still refused by pull; a tampered `retracted` fails `verify`.
- Malformed `retracted` (not a list, a non-string, a bad id, a duplicate,
  over the cap) is refused by `load`.
- Idempotent retract: a locally retracted thread, `curator retract
  --no-pull --dry-run` exits 0, prints the signed retraction and the stderr
  note.
- sign-manifest round trips: `--retract` adds and survives a later signing
  with no flags; `--unretract` drops; `--unretract` of an absent id and the
  same id on both flags are refused before the key is read; an empty list
  omits the key; an unverified previous file is refused.
- The whole suite passes (`scripts/test-gate.sh`).

## Blast radius and rollout

- Readers on an older CLI reject a manifest that has the `retracted` key
  ("content must have exactly the keys"), and keep their previous state;
  the mirror exporter on the VM loads the manifest with the same code and
  would fail its run. So the first manifest that uses the field is
  published only after the exporter and members run this version. This task
  signs no manifest; v3 stays live, unchanged.
- Rollback: revert the commits; manifests without the key are unaffected.
  A member whose state already accepted a manifest with the key cannot
  downgrade without discarding that state (the older state load refuses
  the key), which is one more reason the first such manifest waits.

## Non-goals

- Re-signing the live manifest (the root nsec stays in Kura).
- The Atom feed's "Retracted:" rendering of a manifest-listed thread
  (mirror/export_mirror.py reads only curator replies): follow-up issue.
- Honouring kind 9005 deletions; the Atom builder's own kind check
  (follow-up ai-tools-alerts#0drq).

## Assumes

- Advisory ids are the unit of retraction; a root event id is not
  accepted in the list (the curator command already resolves an event id
  to its advisory id).
