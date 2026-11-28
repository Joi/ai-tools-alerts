# 9je7: retracting one advisory of a held fix-group notice keeps the others

Issue: ai-tools-alerts#9je7 (discovered from ai-tools-alerts#z360). Builds on z360's
`Run.retire`, `Run._judge_id` and the `gone` filter; this branch is stacked on the z360
branch and lands after it.

## Problem

A fix group (faxq) that rates notice is not a thread. It waits in `state["held"]` as one
notice whose `id` and `aliases` are every member's, until the weekly summary counts it.
When the manifest retracts one member:

1. `Run.digest` finds the notice withdrawn (`compose.withdrawn`: any id in the retracted
   list), leaves it out, and acknowledges it. Every key of the notice, the other
   members' too, goes into `state["digested"]`. The other members are never counted, and
   `Run.hold` never holds an id that is in `digested`.
2. Before that digest, a sighting of a surviving member that rates notice finds the held
   notice by its id (`Run.hold`, `known`) and is merged into it, then dropped with it.

A true notice is lost with no one to see it (standing ruling: no human in the loop).

## Approach: retire splits the notice; the digest waits for the split

No state format change: a held entry stays `{scope, adv[, source_title]}`.

**Terms.** For a held notice `h` and the stored manifest's retracted ids `gone`
(case-folded) with `bases = gone | {_base(i)}` (z360): the notice is *struck* when any
of its ids, case-folded, is in `gone` (the test `compose.withdrawn` applies). Its
*survivors* are its ids that are bot ids (`candidates.BOT_ID`), not synthetic, and whose
base is not in `bases`. A bare id under a scoped retraction is not a survivor: on doubt
the retraction wins, as z360.

1. **`Run.retire` judges struck held notices** (new `Run._retire_held(bases)`, called
   once `gone` is set, before the thread work and whatever that work finds; never
   raises). For each struck notice, skipping one whose keys a journaled digest already
   acknowledges (an outbox or withheld digest whose `adv.held` covers them: that digest
   decides it):
   - each survivor is judged once a run by `_judge_id`, exactly as a retired thread's
     id: the notice's product (`h["scope"]`, current or former name), its sources, the
     id's own repository advisory page. **Released** when the page is structured, names
     the id and assigns no retracted id. **Kept** when a page answers otherwise (the
     retracted advisory's own CVE) or no source confirms it. **Undecided** when a page
     could not be read; the next run tries again. A verdict covers every id of the
     notice that the page assigns.
   - new pages read for held notices are capped at `RETIRE_PAGES` a run, apart from the
     threads' own cap; the notice the work starts at rotates each hour, and so does the
     id within a notice (GHSA ids still ahead of CVEs), so a page that fails every run
     never starves the ids behind it (spec review).
   - released ids become pointer candidates in `state["deferred"]` (in place of a row
     for the same id) and leave the notice's `id`/`aliases`.
   - a notice with no undecided survivor is **dropped**: it leaves `held`, and the keys
     of the ids it still has (retracted and kept) go into `digested`, which is what the
     digest did with the whole notice before. A notice with an undecided survivor stays,
     without its released ids. When the notice's lead id was released the remaining
     notice is led by its next id, and its title's `(id)` follows.
   - one `self.save()` writes all of it: pointers, the held list and `digested` are one
     file, so no run can stop between the release and the record.
2. **Ordinary planning.** A pointer is planned like any deferred candidate this run:
   admitted from its own page (h340), grouped by fix with the other survivors, rated by
   its own evidence. At notice, `Run.hold` finds no held notice and no `digested` key
   for it and holds it as a new notice, which the weekly summary counts. z360's `gone`
   filter already keeps the retracted member out of every plan and every group.
3. **The digest waits.** In `Run.digest`, a held notice withdrawn only because an id is
   retracted (not synthetic, not expired) that still has a survivor, under the manifest
   the digest just pulled, is neither listed nor acknowledged: it stays held for the
   next run's `retire`, whose stored copy is the one this digest pulled. The digest
   reads `gone` from a fresh pull and `retire` from the stored copy; this rule is what
   keeps a retraction the digest sees first from costing the survivors. The test comes
   before `_posted` (spec review): a held group that has since posted as a root would
   otherwise be acknowledged with every id, and the survivor its thread later releases
   could never be held.
4. **A member that joins later brings its sources.** `Run.hold`, where a fix group's new
   ids join a held notice, now also adds the sighting's sources after the notice's own
   (`compose._sources`, 20 at most, the order of the old ones unchanged). Without them a
   member that joined after the notice was first held has no page to be judged by.
5. **A struck notice takes nothing.** `Run.hold` skips a held notice the stored manifest
   strikes: it gains no id, source or field, and a group one of whose members is in it
   holds its other members under their own ids. Otherwise a member released while
   another is undecided would be merged back by the next sighting of both.

### Assumes

- The catalog lane reads `state["held"]` as before. A struck notice was in that list
  until the digest that dropped it; it now stays until its survivors are decided, which
  is the same kind of wait, longer only while a page cannot be read.
- A survivor's level is what its own evidence gives now. If it rates above notice it is
  planned as a root by the ordinary rules, the 0dvh age limit included.

### Out of scope (stated, not fixed here)

- Notices already acknowledged before this lands (their survivors are in `digested`):
  there is no record of which ids were members.
- A digest journaled by an older poster that already acknowledges a struck notice and
  has not been sent: its acknowledgement stands (the skip in step 1).
- A survivor whose page is past the 20-source cap of a held notice cannot be proven: it
  is kept, or stays undecided with its notice when `rules.evidence` reports its page
  budget spent. More than 20 advisories in one group; ai-tools-alerts#5rra.
- Two notices held apart and later sighted as one fix group each take the other's ids
  (`Run.hold`, older than this change; staggered releases can reach it too): two rows,
  no advisory lost. ai-tools-alerts#1e90.
- A notice acknowledged because its group posted (`_posted`) before any retraction: the
  survivor a thread later releases is in `digested` and is not held.
  ai-tools-alerts#1m9f.

## Success criteria

- Acceptance test: a held notice of A and B; the manifest retracts A; after the
  poster's copy holds that manifest, B is held as a notice of its own, A's key is in
  `digested` and not B's, and the next weekly summary counts B.
- Test: a notice of one advisory retracted by its GHSA id, with its CVE: dropped whole,
  both keys digested, nothing held.
- Test: the digest that first sees the retraction leaves the notice held and does not
  mark the survivor digested; the next run splits it.
- Test: a survivor whose page fails stays in the held notice and is released by a later
  run.
- Test: a member that joined the held notice in a later run is released (its source was
  added).
- Test: with one page a run, a member released while another waits is not taken back
  by a sighting of both; a run later both are held and neither is digested.
- Test: a member whose page fails every run does not starve the one behind it.
- Test: a held group that posted as a root is not acknowledged whole by the digest that
  first sees the retraction.
- Gate: `scripts/test-gate.sh` passes.

## Alternatives rejected

- **A `split` record on the held entry**, as the ledger entry has. A state format
  change (an older poster refuses an unknown key) for a record that lives a day at
  most; a kept id is judged again each run only while another id of its notice is
  undecided.
- **The digest lists a struck notice without the retracted id.** The digest cannot tell
  a second advisory from the retracted advisory's own CVE; only the page can.
- **Release every non-retracted id without a page.** `admit` and the `gone` filter would
  drop a CVE read from the retracted GHSA's page, but a CVE a prose page names alone
  would be held and counted: the hole z360's "kept" closes.

## Blast radius and rollback

Poster only (`aitools_alerts/poster/main.py`). The reader, the wire, the manifest, the
ledger and the state format are unchanged. Rollback: revert the commit; a held notice
split by this version is valid state for an older one. Release: the poster must be
reinstalled, with z360; noted on ai-tools-alerts#z3fs.
