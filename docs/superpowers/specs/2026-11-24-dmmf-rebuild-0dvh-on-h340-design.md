# 0dvh on top of h340: where the hold, the age limit and the block take their inputs (dmmf)

Issue: ai-tools-alerts#dmmf, which blocks ai-tools-alerts#0dvh (pull request 8). Builds
on h340 (pull request 7, merged as 1e9221c) and on everything since on main. The 0dvh
design stands as written in
`docs/superpowers/specs/2026-11-23-0dvh-hold-until-complete-and-age-limit-design.md`;
this spec changes only where its inputs come from, so that h340's rule holds: the
collector record is a pointer, and what a post states is read from the vendor's page
or CISA's catalog.

Prior work: 0dvh's spec, plan, run record and decisions (kata comment c:q19ztk: KEV
entries never wait and are exempt from the age limit; a severity change alone posts no
reply; the block id stays the ledger key). h340's spec, sections 3 to 5. The WIP
merge `0dvh-integrate-h340-wip` (62d7fba) resolved the text conflicts by keeping both
sides; this branch merges it onto main and fixes what that left failing.

## Problem

With 0dvh merged onto h340 as text, ten poster tests fail. Three causes:

1. **The tests fed fix, range and severity through the record.** h340's `Run.admit`
   replaces the candidate's `fixed`, `affected` and `advisory_severity` with what the
   vendor's page states. 0dvh's tests (and the fake vendor page, which renders one
   page per URL from whichever finding cited it last) still set them on the record,
   so a high with "no fix" on its page waited where the test expected a post, and a
   "critical" on the record never reached the page.
2. **A range the schema cannot express was lost.** h340's `rules.evidence` returns no
   range when the page's range cannot be expressed or when several blocks match. 0dvh
   needs that fact twice: a high with a stated range does not wait for its fix, and
   the post says "affected versions: see the source" rather than "versions not
   stated".
3. **The block's severity could come from the record.** 0dvh publishes the loudest
   severity word of `advisory_severity`. Under h340 that field also carries a trusted
   record's own text when the page gives neither a severity word nor a title (kept
   for the level only). Published, it would break h340's criterion 4: the
   collector's `advisory_severity` never reaches a post.

## Success criteria

- S1. Every 0dvh behaviour holds with the vendor page as the only source of fix,
  range and severity: the six-hour hold, the seven-day age limit, the block's range
  and severity, public ids in titles, one mirror row per advisory.
- S2. The 11-07 replay posts zero real-time roots; each of its 16 roots whose source
  is the vendor's repository advisory page is aged into the digest, and the OpenClaw
  root, whose only source is the global GitHub advisory page, is dropped by h340
  (no authoritative source). The 11-18 replay posts five roots, each once, each with
  "Fixed in 2026.11.18", no reply, no "check the vendor", with a vendor page serving
  each state of the live thread.
- S3. A repository page whose matching block states a range the schema cannot carry
  (an `||` range, a bare version, `*`, "all versions"), or several matching blocks
  that state ranges, gives `affected = UNEXPRESSED`: the high posts without waiting,
  the post says "affected versions: see the source", and no page text reaches the
  block. An empty range field still gives no range.
- S4. The block's `advisory_severity` is the loudest word the vendor's repository
  page states (`severity_word`), or null. A record's severity text may still rate
  the advisory, as h340 allows, but never reaches a post.
- S5. `scripts/test-gate.sh` green. Readers at v0.1.4 parse every post (block keys
  unchanged).

## Approach

### Range (`rules.evidence`)

After computing the one-block range: when it is None or `*` and any matching block
states a range, set it to `rules.UNEXPRESSED` (the sentinel h340 already uses for a
fix it cannot express). `compose.schema_affected("unexpressed")` is None, so the block
carries no range; `compose.range_unexpressed` is true, so the wording says "see the
source"; `main._stated` is true, so the high does not wait. `*` joins the
unexpressed case: h340 chose not to publish "all versions" from a page, and a page
that states it has still stated a range.

### Severity (`Candidate.severity_word`)

- `Candidate` gains `severity_word: str | None = None`: the word the vendor's
  repository page states, set by `Run.admit` from `Evidence.severity` (already
  limited to critical, high, moderate, medium, low).
- `ledger._merged` joins members' words with "; ", as it does `advisory_severity`.
- `compose.root_post` publishes `severity(c.severity_word)`; `advisory_severity`
  stays the level's input only.
- `to_dict` leaves it out and `inputs.candidate_from` does not require it: a deferred
  candidate is admitted again every run, which reads the word again. The state
  file's format does not change, so rollback needs nothing new.

### Age limit date

`_published` keeps reading the `published_at` of the kept source, the vendor page
that confirmed the candidate, as written in the record. h340 already carries that
value in the block's sources. Used here it can only turn a root into a digest notice,
never make a post. Reading the page's own published time is a separate change
(follow-up issue).

### Tests

- The fake vendor page is pinned where two findings cite one URL.
- Severity tests put the word on the vendor page and a different one on the record.
- New: a record's severity rates the advisory and never reaches the block; the merge
  keeps every page's word; the compose block reads only `severity_word`; the range
  cases of S3; a held notice keeps its fix, actions and first-sight stamp when a
  vendor site page (no fields) confirms the same advisory again (replacing 0dvh's
  8ke5 case, which h340 no longer admits: a social post is no source).
- The replays serve a repository advisory page for each live state. A live id whose
  slug h340's `BOT_ID` refuses (a `/`) is cut to its base id: the replay tests the
  hold and the age limit, not the thread key's form.

## Alternatives considered

- **Leave the range as None.** Rejected: every high whose page gives an `||` range
  would wait six hours and then say "versions not stated", a false statement.
- **Publish the raw page range.** Rejected: h340 publishes no page text the schema
  cannot check.
- **Publish the first "; " part of `advisory_severity`.** Rejected: the order of
  merge members decides it, and a record's text can still be first.
- **Drop the record's severity text altogether.** Rejected: it changes h340's level
  rule, which is not this issue's.
- **Read the published date from the GitHub page.** Deferred to a follow-up: the
  page parser does not read it today and a site page states none.

## Blast radius and rollback

Poster only, one machine. No state format change beyond 0dvh's `waiting` key (its
rollback note stands). Rollback: revert the merge of this pull request on main and
reinstall, with 0dvh's `jq 'del(.waiting)'` step.

## Assumes

- GitHub's repository advisory page states a severity word for a rated advisory; an
  unrated one gives none, and the block then says nothing.
