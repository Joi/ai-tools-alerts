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

1. **When a thread falls** (`recompute.falls`). For a thread judged this run that has
   members no source ties to its first id (`recompute.loose`: untied advisory ids, and
   beside an advisory first id the CVEs its response does not name), the poster asks
   what the thread's sources state without them. If every remaining source was read
   whole (the `known` of `support`, under `judge`'s KEV rules) and the level they give,
   as the thread can carry it and never below its prose floor or notice, is below the
   thread's level, the thread falls to that level. This reads only; no wait is kept.
   A withdrawn thread and an ended one (65xv) never fall here.
2. **Who leaves** (`recompute.outlived`). Each member's own advisory response is read
   (`rest` lane), only for a thread that falls. A member counts when its response was
   read and may lower (reviewed, or the vendor's own: the class a counted reading
   needs). If some counted member supports more than the level the thread falls to,
   every counted member leaves. Otherwise none does: nothing is lost by the lowering.
   A member whose response was not read, or is one its subject's attacker can write,
   stays, and the thread stays unknown, as today.
3. **How it leaves** (`Run.part`, called in `observe` after the threads are judged). A
   member that still supports the product leaves only with a pointer candidate built
   from its own repository advisory page (`Run._judge_id`, z360: the page must be
   structured and name the id). A member whose response supports nothing (a withdrawal
   too) leaves with no pointer. The ids that go with a member are those of the thread's
   loose ids that its response or its page assigns. The pointers are saved to the
   state's deferred list and kept past this run's end, then the ids leave the thread's
   identity in the ledger (`Ledger.release`, the `split` record). A page not read this
   run, or not proving the id, leaves the member for the next run; at most
   `RETIRE_PAGES` new pages a run.
4. **The new root.** The next run plans the pointer like any deferred candidate:
   admitted from its own page, grouped by fix with the other members that left, posted
   as a root at the level their own evidence gives, under the loudest of them. A
   member's check reads that root's first id. z360's exemption from the seven-day age
   limit covers it (`Run.released`). A thread that has released an id takes no join by
   fix (`_fix_thread`), so the member does not return to the thread it left (btqg).
5. **The old thread.** `recompute.bare_ids` and `support` no longer count a released id
   (`recompute.released`), so the thread is judged by its first id alone from the same
   run on: its lowering or withdrawal completes under every ny5g rule (24 hours held,
   seven quiet days, the breaker). Its published advisory still lists the member; no
   reply narrows it (tyje).

No dwell before the split: a member's own check stops confirming the old thread as soon
as it reads the first id, so a wait is time with no alert for a true advisory. The
split is permanent. If the first id's source comes back there are two threads, and both
are true.

### Assumes

- The level compared is the one the poster would lower the thread to, prose floor
  included. A thread held at its level by its prose floor does not fall, so its members
  stay; what a member's check makes of such a thread is not changed here.
- A survivor's level is what its own evidence gives now. `exploited` is not carried to
  a pointer (as z360).
- A run that stops between the state save and the ledger write plans the pointer onto
  the old thread, which changes nothing, or (when the release is repeated first, as it
  is: `observe` runs before planning) posts the root one run earlier.

### Out of scope

- A thread whose members all support no more than the first id's new level still
  cannot lower by recompute while it carries them: it steps down at 44 days, as today.
  Follow-up issue.
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
- Members that leave together post as one root.
- A page that cannot be read delays the release by a run.
- A released member sighted again does not join the old thread.
- A run that stops before the ledger write releases again.
- `scripts/test-gate.sh` passes.

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
supports less than the thread's level, and that has a member supporting more, releases
that member: at most `RETIRE_PAGES` pages, so at most ten new roots a run. Rollback:
revert; a `split` already written is z360's to read, and a released member keeps its
own thread. Release: the poster must be reinstalled; noted on ai-tools-alerts#z3fs.
