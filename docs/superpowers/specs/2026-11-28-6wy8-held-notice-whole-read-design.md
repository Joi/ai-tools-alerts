# A whole read replaces a held notice's fix and range together (ai-tools-alerts#6wy8)

## Problem

A notice waits in the poster state's `held` list until a digest lists it; the catalog
lane posts its block meanwhile. When the same advisory is sighted again, `Run.hold`
(`aitools_alerts/poster/main.py`) merges the new block into the held one:

    got = {**was, **{k: new[k] for k in ("fixed", "affected") if new[k]}}

Each field is taken from the new read only when it is non-empty. Since
ai-tools-alerts#xkbf a read of a package box with several ranges gives the highest
patched version and no range: in the block `affected` is null, and the post says
"see the source". Null there means "several ranges", not "not read". The merge keeps
the range of the earlier read and takes the fix of the later one, a pair no read
produced.

Seen on the first run of v0.5.0: the catalog notice for GHSA-v2gx-m79c-pvxj
(`@modelcontextprotocol/inspector`) went from `>=2.0.0,<=2.16.0` with no fix to
`>=2.0.0,<=2.16.0` fixed in 2.17.0. The advisory states two ranges
(`>=2.0.0,<=2.16.0` fixed in 2.17.0 and `<=1.0.6` fixed in 1.0.7). A member on 1.0.x
is not matched.

## Success criteria

1. A held notice with one range and no fix, sighted again with a page in the shape of
   GHSA-v2gx-m79c-pvxj (one package row with two ranges and two patched versions, and
   a second package row), holds `fixed: 2.17.0`, `affected: null` and the action
   "upgrade to 2.17.0". By the reader's version rule (`versions.check`) that block
   matches an install of 1.0.5.
2. A read whose box states a range and no patched version clears a fix the held
   notice had: both fields come from one read. A read whose box states neither clears
   both.
3. A sighting that read no package box (a KEV entry alone, a vendor site page) changes
   neither field (`test_a_fieldless_sighting_keeps_the_notice_fix_and_first_sight`
   stays green).
4. A read of some of a held notice's ids (one member of a held fix group, faxq, or a
   group that shares a member with it) never narrows the notice and never leaves the
   member it read with a fix or a range narrower than its page states.
5. The catalog lane posts the corrected block as a new root, as it does for any
   changed block; nothing waits for a person.
6. `scripts/test-gate.sh` passes.

## Approach

### Which sightings are reads

`Run.admit` replaces a candidate's `fixed` and `affected` with what `rules.evidence`
read. Only a repository advisory page gives them (`Evidence.structured`); a vendor
site page or KEV alone gives none. A box can also state no range and no patched
version, so the fields alone do not say whether a box was read. `admit` therefore
records, in a set on the run (`Run.boxed`, `scope|id`), the candidate's id and every
id the page assigns whenever the evidence is structured. `plan_new` passes
`read = any id of the candidate is in boxed` to `hold`. Nothing is added to the state
file or to `Candidate`: a read is of this run.

Every candidate reaches `plan_new` through `admit` (run, admit, `ledger.merge`, `one`,
`plan_new`; the spec review confirmed no other path).

### The rule in `hold`

For each held notice the sighting matches:

- **not a read:** neither field changes;
- **a read of every id the held notice holds** (the same advisory, or the same fix
  group, whose merged candidate already carries a range that covers its members,
  `ledger._fix_group`): `fixed` and `affected` are both replaced by the new block's,
  null included;
- **a read of some of its ids:** the fields become what covers both blocks
  (`Run._cover`), which only widens:
  - the fix is the higher of the two; none when the read states none (no version is
    then safe for every member) or one cannot be compared;
  - the range is theirs when they agree, else everything before the fix when both
    state one and there is a fix, else none stated. This is the rule a fix group's
    range already follows (`ledger.merge`).

The action is rebuilt from the resulting fix, as before. With no fix and no range a
reader reports "may apply" for every install of the product, the widest reading.

The partial read runs before the existing faxq step that adds a group's new members,
so a member that joins a held notice joins under a fix and range that cover it: held A
and B fixed in 2.1.0, then A and C stating 2.2.0, gives one notice fixed in 2.2.0 with
everything before it, never C under 2.1.0.

A held group whose members' pages have diverged (A now states 2.2.0, B still 2.1.0)
is no longer one fix group for `ledger.merge`; each member's read then widens the
held notice, which ends at the higher fix and a range that covers both. B's members
are told a higher fix than B's own, the safe direction, as a several-range advisory
already is (xkbf).

The rest of `hold` is unchanged: titles, publication dates, the primary source learned
later (8ke5), new members of a fix group (faxq), struck notices (9je7).

### Second notice or replacement

Decided: the changed held notice posts a new catalog root, as now. The catalog
channel has roots only; `catalog.py` states the lane's contract, "a changed advisory
posts a new root, and a reader takes the newest root per advisory id and product".
This repository has no reader of the catalog channel yet (`pull.FILES` is feed and
critical), so this change verifies the block and its publication, not a reader:
criterion 1 is checked on the held block with `versions.check`, criterion 5 on the
root the lane posts. No second mechanism is added. ai-tools-alerts#n2yj builds on the
same contract for notices a digest has already listed.

## Alternatives considered

- **Treat null as "clear" in every sighting.** A fieldless sighting (KEV alone, a
  vendor site page) would erase a fix and range the vendor's page stated. Rejected:
  criterion 3.
- **`read` from the candidate's fields** (`fixed` or `affected` stated). Misses a box
  that states neither (spec review, BLOCKER). Rejected for the recorded read.
- **A partial read changes nothing.** A member whose fix rose, or a new member joining
  through a shared one, would stay under the earlier, lower fix until a person acted
  (spec review, two BLOCKERs). Rejected for the widening rule.
- **Split a held group whose members diverge.** The splitting path exists for
  retractions (9je7) and needs each member's sources judged; widening reaches a safe
  state in the same run with a few lines. Rejected as out of proportion here.
- **Carry the read's raw package rows into the held notice and recompute.** More
  state in a file with a strict loader, for the same result. Rejected.
- **Hold a narrowing change for a second read 24 hours later** (the ny5g rule
  n2yj names). A whole read may narrow (a range that shrinks); the merge already
  replaced a stated range or fix with another at once, so this is not new. The
  narrowing rule for catalog notices is n2yj's deliverable and is left there.

## Behaviour that changes beyond the motivating case

- A read with a range and no patched version used to keep a fix read earlier ("none
  is lost", 0dvh); it now clears it.
  `test_an_old_source_posts_no_root_and_reaches_the_digest_notices` asserted the old
  rule and is changed to assert the new one and the removed action.
- A member's read of a held fix group used to overwrite the group's fix and range
  with the member's own (a narrowing). It now only widens.

## Blast radius and rollback

One function in the poster and its one caller; the state file's shape is unchanged.
Rollback is a revert of the commit. The live held notice for GHSA-v2gx-m79c-pvxj is
corrected by the first sighting after the release that reads the page (the catalog
then posts the corrected root); if a digest lists the notice first, the correction is
n2yj's re-read. No install or signing step beyond a normal release.

## Assumes

- A held notice's ids and a sighting's ids are compared as `Run._notice_keys` gives
  them (the block's id and aliases, case-folded), as the rest of `hold` does.
- A fix higher than a member's own range's end covers that range ("everything before
  the fix"), the assumption a fix group's range already rests on.

## Open questions

None.
