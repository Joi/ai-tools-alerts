# Digest: short daily form and a weekly summary (ai-tools-alerts#qwpw)

Slice 11 of ai-tools-alerts#9mx8, design section "7. Digest".

## Problem

The daily digest lists every ledger change since the last digest and every held
notice. Under version 2 the notices are catalog material (section 4: "Catalog and
the weekly summary"), and the channel should carry only what a member acts on. The
v2 measurement found 47% of digest lines were leads and five advisories listed again
with nothing new. 8ke5 removed the leads; this slice cuts the daily post to the day's
new real-time posts and moves the notices to a weekly summary of counts.

## What the landed code already settles

- **Freshness.** The design says the CLI reads the daily post as its freshness
  signal. Since t8jr and r0ra the CLI's freshness is the signed checkpoint's validity
  (`pull.freshness`, `STALE_EVENT_S` kept only for importers); the digest is not read
  by any reader. The daily post stays daily anyway, as the human-visible sign that the
  poster runs (h29n: "the digest stays as the human-visible sign"). Nothing in the CLI
  changes.
- **Notices.** A notice is never posted in real time (9kgk); it waits in the run
  state's `held` list until a digest lists it, then its keys go to `digested`, so it is
  never held again (an advisory appears in a digest once). The catalog lane (q03f)
  reads `held` before the digest and keeps its own inventory, so holding a notice for a
  week instead of a day changes nothing there.

## Behaviour

**Daily, at `digest_hour` (09:00 Tokyo), every day.**

- Lists each relay-bot thread whose root was posted since the last digest, one line
  each, loudest first, then oldest first: `- HIGH: <title>; fixed in <v>. <source>`.
  The head line is `Daily digest for <date>: N new alert(s).` Nothing else: no level
  sections, no held notices, no release grouping (a v1 rule for KEV lines; faxq
  already makes one post per fix, so one line per post is one line per fix).
- A thread is listed by its root's `posted_at`, which never moves, so a thread is
  listed once. A later change to it (a fix, a raise) is a reply in its thread and is
  not listed again. This replaces `listed_at`, which moved on each change and listed
  the thread again.
- With no new root: `Daily digest for <date>: no new alerts. N notices added to the
  catalog this week: <mirror link>`. N counts the held notices a weekly summary has not
  yet listed. The mirror link is the poster's mirror URL when it is `https://`, else
  the public default `https://buzz.ai-tools.md/alerts/` (a `file://` URL never reaches
  a post).
- The lines that exist today stay: the recompute's level report (ny5g: lowered ids,
  the breaker) and the withheld count.
- Withdrawn threads (retracted or expired, by the mirror pull) are left out, as today.

**Weekly, in the first digest of an ISO week (Monday 09:00 Tokyo unless that run was
missed).**

- The same post carries one more section: `Weekly summary: N notices added to the
  catalog this week.`, then one line per product, `- <product>: <count>`, most first
  then by name, at most 30 lines and `- <k> more products: <count>` for the rest, then
  `Catalog: <mirror link>`. Counts only: no ids, titles or URLs from a notice.
- It lists every held notice that `compose.listable` accepts and that is not withdrawn
  (`compose.withdrawn`: a synthetic id, a retracted id or alias, an expired version,
  the filters the daily lines use). When the digest is acknowledged (sent), those
  notices leave `held` and their keys join `digested`, as the daily digest does today.
- Retired with any digest, daily or weekly, and never counted: a held notice that has
  since posted a thread (the daily lists its root) and one withdrawn since. Until now a
  posted notice stayed in `held` with nothing to remove it. On a quiet Monday the daily line drops the count (the
  summary carries it): `Daily digest for <date>: no new alerts.`
- One post a day, not two: the weekly rides the daily digest's journal item, its
  idempotent replay and its Japanese copy. A second item kind would need its own
  journal, settle and resolve paths for no member-visible gain.
- The run state gains `weekly`: the ISO week (`2026-W48`) of the last summary sent. A
  fresh state, and a state written before this slice, start with the current week, so
  the first summary is the next Monday's and no mid-week summary is sent. A summary is
  due in any digest whose week is after `weekly`: Monday's, or, when Monday's run was
  missed, the next digest that week.
- The digest item's snapshot gains an optional `week`; settling the item writes it to
  `weekly`. An item journaled before this slice has no `week` and settles as before.

**Japanese copy.** Every new line has a Japanese template, as the digest's lines do
today.

## Success criteria

1. A day with two new high roots and three held notices posts a daily digest with
   two lines and no notice; the notices stay held.
2. A day with no new root posts the one quiet line with the held count and the link.
3. A thread listed yesterday and replied to today is not listed today.
4. The first digest on a Monday carries the weekly summary of all held notices by
   product, counts only; after it is sent, `held` is empty and the keys are in
   `digested`; Tuesday's quiet line says 0.
5. A missed Monday: Tuesday's digest carries the summary; a fresh state does not send
   one before Monday.
6. A digest item journaled before the slice (no `week`) still loads and settles.
7. `scripts/test-gate.sh` passes.

## Alternatives considered

- **A separate weekly post.** Rejected: a new journal kind, a second date key, a
  second Japanese reply path; the design asks for the summary's content, not its
  container.
- **Keep `listed_at` and list changes.** Rejected: the design lists "new posts" and an
  advisory once; a change is already a real-time reply.
- **Count notices from the catalog inventory.** Rejected: the catalog lane may be off
  (`spec/catalog-channel.json` absent), and the held list is what the digest
  acknowledges.

## Blast radius and rollback

Poster only: `compose.digest`, `Run.digest`, the digest settle, the state's shape.
No reader, wire, schema or ruleset change. Rollback is a revert; a state file written
by this slice has `weekly`, and a journaled digest item may carry `adv.week`; the
previous code refuses both as malformed, so a revert also runs, on the poster state,
`jq 'del(.weekly) | (.outbox[], .withheld[].items[]) |= (if .kind == "digest" then del(.adv.week) else . end)'`
(noted in the CHANGELOG).

Migration of the acknowledgement cursor: `digest_at` was a cutoff in `listed` order and
is now read in `posted_at` order. A thread posted before the last cutoff and changed
after it is no longer listed again (the point of the slice). The one case that loses a
line: a digest cut short by the size limit at the moment of the upgrade, whose
unlisted remainder includes a thread posted before the cutoff. Such a thread has
already posted in real time; the loss is one digest line, once.

## Review dispositions (spec+plan pass, fresheyes)

- Fixed: the first Monday after a mid-week install is recovered (baseline week, not
  None); withdrawn notices are filtered before counting and retired; a notice that has
  since posted is retired; the rollback covers journaled items; the test migration
  names test_live_replay and test_catalog.
- Rebutted: an unknown or refused digest send stops later digests until settled. Not
  new: it is the journal every post uses; ai-tools-alerts#jsje (open, priority 1)
  settles unknown and refused sends without a person. A catalog snapshot lost when a
  digest's send fails and the next run's drain acknowledges it: not new, and rarer
  here, since a notice is now held, and snapshotted, for up to a week before a weekly
  summary acknowledges it (the catalog's gaps are ai-tools-alerts#v46a). A notice
  counted in a weekly summary and later raised to high is listed by its root in the
  daily: the summary names no advisory, and the daily is the list of real-time posts.
  The cursor migration (above). The snapshot commit's message (it never lands). Live install is a rollout issue, not this session.

## Open questions

None blocking. The weekly section's product label is the product name the scope file
gives (wa6n names products by package).
