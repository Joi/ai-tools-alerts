# yd1y: a fix group's members outlive its first id

Issue: ai-tools-alerts#yd1y (discovered from ai-tools-alerts#btqg). Builds on
ai-tools-alerts#z360 (pull request 67), whose branch this one merges.

## Problem

Since faxq one relay-bot root covers every advisory of a product that one release
fixes. Since 3qyq the thread's level and claim rest on its first id: a member's check
reads the first id's response and the ids that response names, and nothing else. The
other advisories of the group are ids no source ties to the first id.

When the first id's advisory is withdrawn or lowers while another member's own advisory
still supports the level:

- `recompute.support` answers `unknown` for the thread for as long as it carries an
  untied id, so the lowering or withdrawal never completes;
- `Run._confirming` reads only the readings counted for the first id, so no renewal
  rests on the other member, and after 44 days with no confirming read the thread is
  stepped down (`Run._renew`);
- a member's own check reads the withdrawn first id and stops confirming the thread at
  once.

The other member's alert is true and no member is told so. No person watches for this
(standing ruling, 2026-11-23).

Landed code against the issue text: the issue says the thread "steps down at renewal
time"; in the code that is the 44-day step of `Run._renew`. The rest holds at 4def27d.

## Approach: the members leave and are posted on their own evidence

The issue's first option, with the release mechanism z360 built for a retracted member.
Poster only.

1. **What the first id states** (`recompute.lead`). For a thread judged this run that
   has members no source ties to its first id (`recompute.loose`: untied advisory ids,
   and beside an advisory first id the CVEs its response does not name), the poster
   asks what the thread's sources state by their fields without them. It has an answer
   only when every remaining source was read whole (the `known` of `support`, under
   `judge`'s KEV rules). The level is as the thread can carry it (`held`), `none` when
   the sources state nothing, and takes no account of the prose floor: a member's check
   reads fields. This reads only; no wait is kept. A withdrawn thread and an ended one
   (65xv) are left alone.
2. **Who leaves** (`recompute.outlived`). Each member's own advisory response is then
   read, in the thread's own lane and in the thread's own turn (below). A member counts
   when its response was read and may lower (reviewed, or the vendor's own: the class a
   counted reading needs). Each counted member that supports more than the first id's
   sources state leaves. One that supports no more stays: nothing a member's check
   could confirm is lost, and what else its sources may support (a KEV listing of a
   CVE it names) is not asked. A member whose response was not read, or is one its
   subject's attacker can write, stays too. While any member stays the thread stays
   unknown, as today (ai-tools-alerts#759h). The members are read starting one further
   on each time the thread is first in its lane, so a lane that ends before the last
   member reaches every one. The
   rule does not ask what level the thread stands at: a thread already stepped down to
   notice releases its member all the same, and so does one whose member has come to
   support more than a first id that still supports the thread's level (as a joined
   advisory already leaves, btqg `_leaves`).
3. **How it leaves** (`Run.part`, called in `observe` for each thread right after it is
   judged, so the thread first in its lane this hour has its members read too). A
   member leaves only with a pointer candidate built from its own repository advisory
   page (`Run._judge_id`, z360: the page must be structured and name the id). If that
   page assigns an id of the thread's own (a vendor's GHSA whose API answer does not
   name its CVE), the id is no other advisory: it is recorded as `kept` and not asked
   again. The ids that go with a member are those of the thread's loose ids that its
   response or its page assigns. The pointers are saved to the
   state's deferred list and kept past this run's end, then the ids leave the thread's
   identity in the ledger (`Ledger.release`, the `split` record). A page not read this
   run, or not proving the id, leaves the member for the next run; at most
   `RETIRE_PAGES` new pages a run, counted at each fetch.
4. **The new root.** The next run plans the pointer like any deferred candidate:
   admitted from its own page, grouped by fix with the other members that left, posted
   as a root at the level their own evidence gives, under the loudest of them. A
   member's check reads that root's first id. z360's exemption from the seven-day age
   limit covers it (`Run.released`). A thread that has released an id takes no join by
   fix (`_fix_thread`), so the member does not return to the thread it left (btqg).
5. **The old thread.** `support` leaves out a released id (`recompute.released`) while
   no source ties it to the first id, so once every member has left the thread is
   judged by its first id alone, from the same run on. A released id the first id's response comes to name is read by
   every member's check, and counts again. So: its lowering or withdrawal completes under every ny5g rule (24 hours held,
   seven quiet days, the breaker). Its published advisory still lists the member; no
   reply narrows it (tyje).

No dwell before the split: a member's own check stops confirming the old thread as soon
as it reads the first id, so a wait is time with no alert for a true advisory. The
split is permanent. If the first id's source comes back there are two threads, and both
are true.

### Assumes

- The old thread of a group held at its level by a prose floor stays there after its
  members leave; the poster lowers nothing below a prose floor, as before.
- A survivor's level is what its own evidence gives now. `exploited` is not carried to
  a pointer (as z360).
- A run that stops between the state save and the ledger write leaves a pointer whose
  member is still the old thread's. `observe` runs before planning, so the next run
  repeats the release first when its reads allow, and the pointer then starts the root.
  When they do not, the pointer is planned onto the old thread exactly as a sighting of
  that member is planned today. That can raise the old thread's prose floor, which is
  why the rule above does not read the floor.

### Out of scope

- A thread with a member that supports no more than the first id still cannot lower by
  recompute while it carries it: it steps down at 44 days, as today
  (ai-tools-alerts#759h).
- A member whose own page is not a structured advisory page naming it is tried every
  run and never leaves. Rare; said in the run's output only when it does leave.
- Held fix-group notices (ai-tools-alerts#9je7).

## Success criteria

- Acceptance: GHSA A and GHSA B, one release, both high, one root led by A. A is
  withdrawn. B leaves in the run that reads it; the next run posts B as a root; a
  member's check (`verify.run`) of that root is `confirmed`; the old thread takes the
  withdrawal after its wait and the new one stays high.
- The same when A lowers to a notice.
- No release while A supports the level, when A's read fails, when B's read fails or
  cannot lower, or when B supports no more than A now does.
- Twelve other threads spending the lane's reads do not keep the member unread.
- A thread stepped down to notice after 45 days still releases its member.
- A thread held by a prose floor still releases its member.
- A released id that the first id's response comes to name counts again.
- Members that leave together post as one root.
- A page that cannot be read delays the release by a run.
- A released member sighted again does not join the old thread.
- A run that stops before the ledger write releases again.
- `scripts/test-gate.sh` passes.

## Changed by the spec review

The first draft released a member only when the thread would fall below its level,
prose floor included, read the members after every thread was judged, and left a
released id out for good. The review (fresheyes, gpt-6.1-sol high) showed four ways an
alert was still lost: other threads spending the lane before any member was read; a
thread already at notice; a floor raised by the member's own prose after a stopped run;
and a released id the first id's response later names. The rule is now the one above.

## Changed by the code review

- Only a member that supports more than the first id leaves. The draft also released
  every other member that was read, one that supports nothing with no pointer; a
  withdrawn member can still name a CVE that KEV lists, and btqg's rule that joined
  advisories leave one at a time would have been broken.
- `lead` records the first CVE's KEV listing (`st["listed"]`), which `judge` never does
  for a thread with members; without it a later absence proved nothing for ever.
- Members rotate; the page budget is enforced at each fetch.
- A member retracted after it left hides the old root, which still names it. `retire`
  (z360) now judges such a thread, and `Ledger.release(back=)` returns the retracted id
  to the hidden thread so it keeps an id when its first advisory is released.
- An id whose own page assigns an id of the thread's is `kept`
  (`test_a_candidate_on_the_run_a_lowering_falls_due_is_seen_before_anything_is_lowered`
  found it: a vendor's GHSA learned beside a KEV-listed CVE).
- A candidate for a released id drops an `exploited` mark that came with no KEV
  reading: `ledger.merge` runs before the release and lends the old thread's mark.

## Alternatives rejected

- **A reply moves the thread's first id.** Needs a reader rule: released readers keep
  reading the old first id until they update, and a bot reply that changes which source
  a level rests on is a new forgery surface (tyje, swfe).
- **Wait the 24-hour dwell before the split.** A day with no alert on every member's
  machine, to save one extra root when a source flaps.
- **Count an untied member's reading for the thread.** A member's check never reads it,
  so the poster would publish a level no member can confirm (3qyq).

## Blast radius and rollback

`aitools_alerts/poster/recompute.py`, `main.py`; a comment in `ledger.py`. No wire,
schema, manifest, ruleset, scope or reader change. The ledger's `split` key is z360's.
On the first run after install, every open fix-group thread whose first id already
supports less by its fields than one of its members releases its members: at most `RETIRE_PAGES` pages, so at most ten new roots a run. Rollback:
revert; a `split` already written is z360's to read, and a released member keeps its
own thread. Release: the poster must be reinstalled; noted on ai-tools-alerts#z3fs.
