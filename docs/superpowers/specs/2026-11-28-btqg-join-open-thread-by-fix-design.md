# btqg: a later advisory one release fixes joins the open thread of that fix

Issue: ai-tools-alerts#btqg (discovered from faxq). Design: 9mx8 section 5, "Group by fix".

## Problem

faxq groups advisories by fix within one run (`ledger.merge`). An advisory in the
same scope with the same stated fixed version, seen in a later run, still posts its
own root. Members get a second alert that asks for the upgrade they were already told
to make.

faxq's first spec draft joined such an advisory to the open thread; its review took
that out for three reasons, which this design answers:

1. `Run.busy` finds a thread only through overlapping ids. A member joined by fix has
   none, so it would plan an item with the thread's key while the thread has work in
   flight, and the journal could hold two items with one key (`inputs.load_state`
   then refuses the state).
2. The ledger has no retraction state; `_withdrawn` reads the mirror only for the
   digest and the copies. A join could absorb a new advisory into a retracted thread.
3. The joined member's range must widen the thread's range so it covers every
   member, never be dropped.

The code has moved since the issue was written: kk2q added `Entry.withdrawn` (the
withdrawal state, per channel); 3qyq made a fix group's first member its loudest and
ties a candidate's GHSA readings to its thread's first id (`Run._tied`); `copies`
now calls `_withdrawn` too.

## Success criteria

- A later-run advisory, in a scope with an open thread whose current fixed version
  equals its own, posts no root. The thread learns its ids (ledger aliases) and its
  sources (`learned_sources`, or the next reply's sources).
- It sends a reply only when the thread's range must widen to cover it. Ids or
  sources alone send nothing (8ke5). It never raises the level or sets the exploited
  mark: a member that would do either posts its own root (see "louder", below), so the
  acceptance's "a reply only if the level or the exploited mark changes" holds with
  the range added (see Alternatives).
- Tests: the busy case (thread with work in flight: the member is deferred, the
  journal never holds two items with one key, the next run loads the state); the
  retracted case (an id of the thread retracted in the manifest, the thread retracted
  or expired on the mirror, the thread withdrawn in the ledger, the member's own id
  retracted, the mirror unreadable: the member posts its own root); the range cases
  (a narrower thread range widens; a member stating no range makes the range none
  stated; a later sighting of a member alone never narrows a joined thread).
- Every existing test passes, or is changed with a stated reason (a test that
  posts a second advisory with the same fix in a later run and expects a second root).

## Approach

All in `aitools_alerts/poster/main.py` (`Run.one`, `Run.plan_known`, a new
`Run._fix_thread`) and `aitools_alerts/poster/ledger.py` (an `Entry.joined` field).

### Which thread

`Run.one` looks for a fix thread only when the candidate has no thread under its own
ids (current or former name) and its own ids hold no work (the busy check it makes
now runs first). The thread must:

- be in the candidate's scope, under its current name, or under a former one (wa6n)
  that no other scope entry also lists: seven products share the former name "MCP
  servers and clients", and a shared name does not say which product a thread is
  about (`Run._scope_named`);
- have a current fixed version (the thread's `products[0].fixed`, which a reply may
  have changed) with the same fix key as the candidate (`ledger._fix_key`: a
  schema-expressible version, a leading `v` ignored; none for a synthetic id);
- not be synthetic, and not be withdrawn (`Entry.withdrawn`, kk2q);
- not be withdrawn on the mirror: `_withdrawn` is read once per run, lazily, the
  first time a join is considered. No join when a retracted id is one of the
  thread's or one of the candidate's ids, when the thread's root or a channel copy
  is a retracted or expired thread there, or when `compose.withdrawn` says its
  advisory has expired. A retracted member id would retract the whole thread on
  every reader (the reader marks a thread retracted when any of its ids is; z360).
- have room: the thread's known ids (`Entry.aliases`, its first id among them) and the
  candidate's together are at most 51, the one-block cap `ledger._chunks` keeps for a
  fix group (an id and 50 aliases). A thread's ids stay what one block could name,
  and no thread grows without bound. A full thread is not joined. A later chunk of a
  group split by the cap joins the first chunk's thread only when the two fit one block.
- the candidate's own advisory reading is in hand (`_judged`): a candidate with a GHSA
  id whose reading failed this run would rate quieter than it is. It posts alone.
- If the mirror pull fails, no join this run: the candidate goes on as today and
  posts its own root. It is not deferred: an alert is not held behind the mirror.

Among several, the oldest (`Ledger.entries` order).

### When the member is louder than the thread

3qyq: a member's check reads the thread's first id; a level the thread states must be
one that id's sources give. A joined member is not tied to that id by any source:
neither its GHSA fields nor its KEV listing count for the reader (`verify._Run.thread`
follows the first id's own identities; `_tied` filters GHSA readings only, so a KEV
reading or `c.exploited` would pass it). So a join never moves the level or the
exploited mark. When the candidate alone rates above the thread's level
(`_rate(c, scope, None)`), or it is exploited and the thread is not, it does not join
and posts its own root, as today. A second thread is the price of not under-alerting.

### Busy

With a thread chosen, `busy([*thread.aliases, *ids], scope, learn=False)`: the lookup
finds the thread, so its root's journaled and withheld items and the pending sends
under any of its ids count. Busy defers the candidate under its own id (`defer`).
Unlike a busy known advisory, the hits do not learn the candidate's ids: a journal
item records its ids into the thread when it is sent (`record_reply`), so the
candidate would become an ordinary member (no `joined`, the replacing range rule)
or, behind a withdrawal, a member of a withdrawn thread, without passing the join's
checks. Deferred, it is a new candidate next run and passes them then. The jsje
passing rule (`_clears`) is asked with the chosen thread.

### Planning

`plan_known(..., joined=True)`, for the join and for every later sighting of a joined
advisory (`Entry.member`), so a run that stopped between learning the join and
journaling its widening widens on the next sighting:

- the fixed version is the thread's (equal by the key; this avoids a `v1.2` to `1.2`
  change);
- the range covers both: the thread's when they agree; none stated when either states
  none; else everything before the fix (`<fixed`). A member stating no range is
  unknown, so the cover is none stated (the in-run group rule), unlike a re-sighting
  of the same advisory, where no range is missing data (`_group_range`);
- the source title (a copy's headline, the digest line) stays the thread's;
- the member's ids are learned with `Ledger.add_ids(..., joined=True)`, into its group
  in `Entry.joined`, and are never published (no reply's aliases carry them);
- on the joined thread a KEV reading counts only for a CVE the first id's source ties
  to it (`sources.tied`), as GHSA readings already do (`_tied`);
- everything else is plan_known as it is. A range change replies; ids and sources
  alone are learned and send nothing; the reply that is sent lists the joined sources
  while the thread has fewer than 20 (the cap every thread has). The upstream severity
  word stays the thread's.

### `Entry.joined` and leaving

A list of groups, one per joined advisory: its ids, case-folded and sorted. A later
id of the same advisory goes into its group. `Entry.member(ids)` names the group a
sighting is of: some id of it and none of the thread's own ids.

A joined advisory is found by its ids on every later sighting, so the join's checks
run again there (code review): when its own reading is in hand (`_judged`) and it now
rates above the thread or is exploited where the thread is not (`_louder`), the group
leaves (`Ledger.unjoin`: its ids are dropped from the thread) and the sighting is
planned as a new advisory, which posts its own root. Its ids were never published, so
no reader holds them in the thread. Its listed sources stay listed in the thread.

On a sighting of the thread's own advisory, plan_known uses the group range rule
(`_group_range`) while the thread has a joined advisory, though the published Covers
count is one, so its narrower range never narrows the thread.

## Alternatives considered

- **Join in `ledger.merge`** (rewrite the candidate's identity to the thread's). The
  merge has no mirror state and no journal; the busy and retraction checks would be
  split across two places. Rejected.
- **Defer when the mirror is unreadable.** Keeps one thread per fix, but a high
  waits behind a mirror outage of any length. Rejected: the alert matters more than
  the duplicate.
- **Join a louder member anyway** and let the thread rise on its evidence. The
  member's check reads the first id and would find the level unsupported (3qyq), so
  every reader would count it unverified. Rejected, for a KEV listing too.
- **Join on incomplete evidence.** A newcomer with a GHSA id whose own advisory
  reading is not in hand (a failed read, a spent share) would be judged quieter than it
  is, and once joined it is never read for the level again. Rejected: it posts alone.
- **A joined member's later KEV listing** passes `_tied`, which filters GHSA readings
  only. On a joined thread, a KEV reading counts only for a CVE the first id's source
  ties to it (`sources.tied`), and the exploited mark falls with it. In-run fix groups
  keep the older rule; yd1y carries that.
- **Publish the joined ids with the next reply** (the 8ke5 rule for learned ids, and the
  first build). A published member cannot leave: every reader holds its id in the
  thread, and a retraction of it hides the whole thread (z360). Rejected: the poster
  keeps them for routing only, and the thread's range covers the member.
- **Busy learns the member's ids** as it does for an overlapping candidate. The
  thread's next reply would record them, skipping the join's checks. Rejected.
- **Decide group-ness from the ledger's full id set** instead of a new field. Changes
  the range rule for threads that learned extra CVE aliases of one advisory (a vendor's
  narrowing correction would no longer apply). Rejected.
- **No reply for a range widening** (the issue's acceptance text names only level and
  the exploited mark). Point 3 of the issue says the member's range must widen the
  thread's, never be dropped; unpublished, a member on a version only the new member
  affects is not told. faxq's decision 3 already replies for a range-only correction.
  Taken: a widening replies. Recorded as a `decided:` comment.

## Blast radius and rollback

Poster only; no reader, wire or schema change. A joined member changes what a run
posts: one root fewer, possibly one reply more. A ledger written by this release can
carry `joined`; an older poster refuses a ledger with an unknown field
(`_entry_ok`), as with kk2q's `withdrawn`. Rollback: revert the merge commit; before
running an older poster on a ledger this one wrote, with no run in progress, delete
the `joined` keys and replace the file (`jq 'del(.entries[].joined)' ledger.json >
ledger.json.new && mv ledger.json.new ledger.json`). What that loses: the older poster
reads a joined advisory's ids as the thread's own, so the joined advisory never gets a
root of its own, and a later narrower sighting of the first advisory narrows the range
again (the pre-btqg rule). Accepted for a rollback, which
puts back the older behaviour; the release session decides whether to take it. No release in this session (5fry takes a note).

## Open questions

None blocking. A fix group's level rests on its first id alone (3qyq); when that
source withdraws or lowers, members that still support the level are not read for
it (`recompute.support` reads the thread as unknown; renewals read `root_ids`). That
holds for every in-run fix group since faxq; a join extends it to later members at
the thread's level or below. Filed as a follow-up, not fixed here. z360 (partial retraction of a fix group) is in flight and touches the
same retraction logic; a joined member's later retraction is z360's case.
