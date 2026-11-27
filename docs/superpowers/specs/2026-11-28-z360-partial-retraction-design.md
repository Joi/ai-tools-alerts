# z360: retracting one advisory of a fix group leaves the others visible

Issue: ai-tools-alerts#z360 (discovered from ai-tools-alerts#faxq).

## Problem

Since faxq, one relay-bot root covers every advisory of one product that one release
fixes: the block's id is one of them, the others are aliases. A reader hides a thread
when any id the root carried is in the trust manifest's `retracted` list
(`pull.threads_from`, the `gone` check). Retracting one member therefore hides the
others, which are still true. The poster then finds the remaining members in the
existing ledger entry, plans at most a reply on the hidden thread, and never posts them
again. A member's CLI loses a true alert with no one to notice (standing ruling: no
human in the loop).

## What the reader cannot do

The reader cannot tell a fix group's members apart from one advisory's aliases: a root
`GHSA-a` with aliases `CVE-1, GHSA-b, CVE-2` looks the same whether `CVE-1` is GHSA-a's
CVE or a second advisory. Showing the thread unless *every* id is retracted would let a
single advisory retracted by its GHSA id stay visible under its CVE. Hiding by ids the
root ever carried is also what stops a stolen relay-bot key from dropping an alias to
escape a retraction. The reader stays as it is.

## Approach: the poster releases proven survivors and reposts them

Each run, first (before `settle`), the poster reads its own verified copy of the mirror
as the last pull left it (`State.load(config.mirror_dir)`; the digest pulls daily, copies
and settle pull when they need to; no new network call). Nothing below changes when that
copy is missing or unreadable.

1. **Retired threads, by the reader's own rule.** A thread is *retired* when the reader
   hides it because of the manifest: `pull.threads_from` over the stored events marks it
   retracted under the stored manifest and not under the same manifest with an empty
   `retracted`. That is exactly the reader's predicate (root ids plus curator aliases,
   never a relay-bot alias), and a curator's own retraction is not a retirement. A
   thread maps to its ledger entry by root event id or by any of its channel roots.
2. **Release, never assume.** For each retired entry, each published id
   (`advisory.id`, `advisory.aliases`) that is not retracted and not yet decided is
   checked once against its own repository advisory page: a pointer candidate (the id,
   the entry's product, the entry's sources with those whose URL names the id first) is
   read with `rules.evidence` through the run's page cache. The id is **released** when
   the page is structured (`ev.structured`) and none of the ids it assigns is retracted.
   It is **kept** when a page answered but is not structured, or assigns a retracted id
   (the retracted GHSA's own CVE). A fetch failure, an unparsed page or the page budget
   leaves it undecided, tried again next run. On doubt the retraction wins: a kept id
   stays with the hidden thread, as today.
3. **Durable order.** Released ids go first into the state's `deferred` list as pointer
   candidates (saved), then out of the old entry's ledger identity (`aliases`), with the
   entry's `split` record (`{"released": [...], "kept": [...]}`) in the same ledger
   write. A run that stops between the two writes repeats the release next run; the
   pointer is planned once (`deferred` is keyed by scope and id). Retired-ness itself is
   not stored: a thread is decided by the ledger's `split` record, so a retraction
   later withdrawn from the manifest changes nothing already released.
4. **Ordinary planning.** A released pointer runs the normal path this run: `admit`
   reads it from its own page (h340), `merge` regroups survivors that share the fix,
   `one` finds no thread for their ids (they left the old entry) and plans a new root at
   the level the survivors' own evidence gives. No lookup is changed, so a kept id (the
   retracted advisory's CVE) still finds the hidden thread and starts nothing.
5. **Not old news.** A released id was announced with its group. The 0dvh rule (a
   source older than 7 days at first sight posts no root) does not apply to a candidate
   any of whose ids an entry has released. First sight itself is unchanged, so 3qyq's
   retry window counts from the release.
6. **Nothing retracted is planned.** After `admit`, a candidate any of whose ids is in
   the stored manifest's `retracted` list is dropped (`skipped["retracted"]`): a root
   with such an id is hidden by every reader.

Former scope names: the entry's product is `rules.scope_named(name, former=True)`; when
several current entries list that former name, each is tried and the first whose
structured page binds the id to its product is used. The pointer's product text is the
first identity of that entry that `rules.scope_of` resolves back to it.

### Assumes

- The manifest names advisory ids, as today; no manifest format change.
- A survivor's level is what its own evidence gives now (3qyq). If the retracted member
  was the loud one, the survivors' root can be lower, or a held notice.
- `exploited` is not carried over to a pointer: the KEV mark returns through the KEV
  input or the recompute, never from a retracted thread.

### Out of scope (stated, not fixed here)

- Fix groups held as notices (`state["held"]`): a notice is a digest line, not a thread
  a member's CLI holds. The digest drops a held notice with a retracted id whole, as it
  did before. Follow-up issue.
- Work already journaled for the retired thread (a copy, a reply) and recompute or
  renewal replies on it: unchanged from any retracted thread today; readers hide them.
- A survivor whose own page is past the 20-source cap of a published post cannot be
  proven and stays kept (said in the run's output).

## Success criteria

- Acceptance test: a fix group of two advisories is posted; the manifest retracts one;
  after the poster's copy holds that manifest, the next run posts one new root naming
  only the other's ids; the reader (`pull.threads_from` over the mirror events under
  that manifest) shows the new thread and hides the old.
- Test: one advisory retracted by its GHSA id: its CVE is kept, no new root.
- Test: a survivor whose page cannot be read is released by a later run.
- Test: a survivor older than 7 days still posts a root.
- Test: a relay-bot reply's alias in `retracted` retires nothing.
- Test: an old ledger entry (no `split`) loads; a bad `split` is refused.
- Gate: `scripts/test-gate.sh` passes.

## Alternatives rejected

- **Manifest retracts by thread root event id.** It retracts a thread, not an
  advisory: retracting one member still hides the group; and a manifest format change.
- **Reader hides a thread only when all its ids are retracted.** Breaks single-advisory
  retraction by one id and lets a stolen key escape by alias.
- **Ledger lookup skips a retired thread** (this spec's first draft). The review showed
  it lets the retracted advisory's CVE start a new thread on a prose page, breaks root
  recording idempotence and settle, and keeps survivors busy behind the old thread.
- **Record each group's members at post time.** Nothing for threads posted before this
  lands, and a journal format change; the advisory page is the authority anyway.

## Blast radius and rollback

Poster only (`aitools_alerts/poster/main.py`, `ledger.py`). The reader, the wire, the
manifest and the state format are unchanged; the ledger entry gains an optional `split`.
Rollback: revert the commit and remove `split` from ledger entries (an older poster
refuses an entry with an unknown key). Release: the poster must be reinstalled; noted on
ai-tools-alerts#5fry.
