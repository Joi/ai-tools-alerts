# The admit lane's advisory reads take turns (ai-tools-alerts#vszx)

Date: 2026-11-28. Base: main at d2dd492 (release v0.5.0). Revised after the
independent review of the first draft (see "Review dispositions"): the turn is kept
in a file, not counted by the clock.

## Problem

Each poster run may make ten advisory API requests for new candidates (the `admit`
lane, `sources.LANE_READS`). `Run.admit` spends them as it goes: for each candidate
whose repository advisory page confirms it, `rules.readings_for` asks
`sources.Reader.read(<its GHSA id>, "admit")`. Candidates are admitted in the
collector record's order (`main.run`, the `pairs` list). The collector writes a new
record every hour with the same findings in the same order. So the same ten
candidates get the ten reads on every run and the others get none, for good.

Measured on ai-tools-alerts#vszx: 34 candidates ask, the same 10 are read in all of
48 replayed hourly runs, the same 24 never. The live poster prints
`advisory reads: 20-21 id(s) not read this run` on every run since v0.3.0.

Effect: a candidate never read has no `ghsa` reading. It is rated from its vendor
page and prose alone. A level its advisory's fields support (a reviewed weakness, a
malware entry) is never reached, and a root posted from it carries no claim.

Two things already rotate and are not the defect: the thread lanes (`Run._in_turn`
starts one thread further on every hour), and candidates that come only from the
deferred list (`later` in `main.run`, sorted and rotated by the hour). The defect
needs the candidates to arrive fresh from a record each run, which is what the
collector does.

## Success criteria

1. With n page-confirmed GHSA candidates, n greater than `LANE_READS`, arriving in
   the same record order every hour, and ten requests made a run, every one of them
   is asked for in any `ceil(n / LANE_READS)` consecutive runs. A test runs
   `main.run` with a new record each hour and checks it for n = 34, counting the
   `admit` lane's requests apart from the thread lanes'.
2. A candidate in the record's last place whose advisory comes to be a malware
   entry is posted at the level the existing rules give that reading, within that
   many runs. (The rules that cap a level are unchanged: a thread whose root stated
   no fix is not raised to critical, and a reading the thread's first id does not
   tie raises nothing. The test uses a held notice with a stated fix, which posts
   at critical.)
3. A run that makes fewer than ten requests (a slow API ends the lane's twenty
   seconds first), a run that makes none, and a run that is missed lose no
   candidate its turn: every candidate is asked for once before any is asked for
   twice. A unit test over mixed request counts, and a `main.run` test with a slow
   clock and missing hours.
4. Nothing else about admission changes: the candidates admitted, their order going
   into `ledger.merge`, the pages fetched and their order, the page budget, the
   counters. The existing suite passes; the only edits to existing tests are two
   wrappers of `Run.admit` that must pass the new argument on.
5. A candidate that was read in one run and is not read in the next sends nothing:
   no reply, no lowering.
6. The run's log line names the ids that were not read, so two runs can be compared.
7. A turn file that is missing, damaged, not a regular file, unwritable, or at a
   path configured as another file's never stops or holds a run.
8. A candidate never asked for before is asked for in its first run, wherever the
   turn stands, so a new advisory waits for no round.

## Approach

### The order: `sources.in_turn(ids, after, seen)`

A pure function. First the ids not in `seen` (never asked for), sorted: criterion
8. One request makes an id seen, whatever the answer, so none stays ahead. Then
the seen ids, sorted, as a ring that starts at the first id greater than `after`
(the last ring id the run before made a request for) and wraps. `after` need not
be one of the ids: a candidate that has gone leaves its place in the sort order
behind. None starts the ring at its first id. A first request does not move the
ring's place.

Each run goes on where the last run's requests ended, however many it made. That
gives criterion 1 (ten a run: consecutive runs ask for consecutive arcs of the
ring) and criterion 3 (the place moves by exactly the requests made) with no
assumption about the clock.

### The place: `<ledger>.admit-turn.json`

`{"after": "<lookup id>" or null, "seen": [<lookup ids>]}`, at `Config.admit_turn`,
beside the poster's other per-concern files (`.recompute.json`, `.translate.json`,
`.sent.json`). `sources.load_turn` gives `(after, seen)`, or `(None, nothing)` for
a file that is missing, is not a regular file (read with
`inputs.read_regular_json`, which never blocks on a FIFO), does not read, has
another shape, or holds anything that is not a lookup id (`sources.advisory_id`).
`sources.save_turn` writes it with `inputs.write_json` (atomic; a link at the path
is replaced, never followed). `seen` holds every id asked for, in the current
record or not, at most 2000 (`sources.remembered`: over that, this run's
candidates are kept before the rest). It is written under the ledger lock, like every
other state file of a run.

The path is not in `check_paths`: a clash there is a configuration error that
stops every run until a person repairs it. `Config.admit_turn_free()` says whether
the path is none of the poster's other files, each taken as named and as
resolved (a lock file that is a link to the turn file is the turn file); when it is not, the run neither
reads nor writes the turn, says so, and goes on.

A file of its own, not a key in the run state or the recompute state: both of those
check their key set exactly, so a new key would make an earlier release refuse the
run state ("malformed; refusing to send", which waits for a person) or drop the
recompute state (every wait for a lowering starts over). An earlier release ignores
a file it does not know.

### The pre-pass: `Run.admit_all(pairs)`

`main.run` calls `r.admit_all(pairs)` where it called `r.admit` for each pair.

1. For each pair in order: `ev = rules.evidence(c, scope, self.page)`. The page
   fetches happen in the order they do today. `rules.evidence` reads only the
   candidate, the scope and the page cache, so computing every candidate's
   evidence before any candidate is admitted changes no result.
2. Collect `rules.ghsa_lookup(ev.ghsa)` for each `ev.structured and ev.ghsa`: the
   same condition under which `rules.readings_for` asks.
3. Ask `self._admit_read(i)` for each id of
   `sources.in_turn(ids, after, seen)`, noting each id for which the reader's
   request count rose, and the last such id that was in `seen` (the ring's place). The reader memoises a granted
   request and records an id the lane could not afford in `Reader.unread`, as today.
4. Save the place and the ids asked for, if any request was made. A write that
   fails is said on stderr and the run goes on: the next run starts from the old
   place, which is the old behaviour for as long as the disk refuses, and the
   ledger's own writes would be failing too.
5. For each pair in the original order: `self.admit(c, scope, ev)`. `admit` takes
   the evidence it is given, and computes it when given none. Its call to
   `rules.readings_for` finds the answer memoised, or gets None for an id whose
   turn it was not.

Reads made later in the `admit` lane by `Run._tied` and `Run._rate` (a thread's
first id, to check that a source ties a reading to it) are unchanged. They come
after admission as they do today.

### The log line

`advisory reads: N id(s) not read this run (the lane's share was spent); their
threads are unknown and nothing of theirs moves` gains `; of admission's:` and
the unread ids admission asked for, sorted, the first 40 (`UNREAD_NAMED`) and then
`and N more`. Only those: they are ids a vendor's page stated, in the one shape
`rules.ghsa_lookup` gives. A thread lane can be asked for an id that a response
named, and nothing a response says is printed; such an id is counted only. The release
session (ai-tools-alerts#g9bv) is asked to confirm that the ids differ from run to
run, which the count alone cannot show.

## Why not

- **A turn counted by the clock** (the first draft: start at `hour * 10 mod n`).
  It needs no file, but the review showed two ways it leaves ids unread. A slow API
  makes a run ask for fewer than ten, and the next hour's window starts ten further
  on regardless. And with twenty ids and a run only every other hour, every run
  starts at the same place: ten are never read. A service nobody watches must not
  depend on its own schedule being kept.
- **Least recently read first.** A map of every id's last read time, for an order
  that differs from this one only in what a set of ids already gives: new first.
- **Start one further each hour, as `_in_turn` does.** With a window of ten that
  bounds the wait at n - 9 hours, not ceil(n / 10): 25 hours for today's 34
  candidates in place of 4.
- **Rotate `pairs` itself.** The order of `pairs` decides which candidates get the
  run's page budget and which member's fix `ledger.merge` takes first. Changing it
  would change admission, not only which advisory is read.
- **Candidates with no thread first.** A strict priority starves the others as soon
  as ten candidates without a thread stay in the record (held notices do).
- **A larger share.** GitHub allows one address 60 unauthenticated requests an hour
  and the three lanes use up to 30. A larger share only moves the point at which
  the same defect returns.

## Limits, stated

- The bound of criterion 1 is for ten requests a run. A run makes at least four
  (twenty seconds, five a request), so the bound under a slow API is
  `ceil(n / 4)` runs. A run that makes none (the API unreachable before the first
  byte still counts as a request made; a lane with no seconds left does not) keeps
  the place.
- A new candidate is asked for in its first run and takes one request from the
  ring in that run. More than ten new candidates at once are read ten a run, and
  the ring waits while they are.
- A turn that cannot be kept (an unwritable file, a clashing path) leaves every run
  asking for the same ten first: the old defect, said on stderr every run. The
  poster cannot repair its own state directory.
- A request that fails still moves the place past its id: the id waits one round,
  and no failing id holds the others back.

## The other question in the issue: the MCP Inspector threads

The issue asks why the `rest` lane does not read the ids of five open MCP Inspector
threads on 0.4.0. Found, from the public feed and the code: their roots were posted
on 2026-11-07 under ids of the form
`GHSA-4fc4-wcmh-4g86:modelcontextprotocol/inspector`. The slug holds a slash. The
poster reads a thread key's slug as `[a-z0-9][a-z0-9.-]{0,31}` (`candidates.BOT_ID`)
and the member's check as `[A-Za-z0-9][A-Za-z0-9._-]{0,63}` (`verify._LEDGER_KEY`);
neither allows a slash. So `recompute.lookup_id` gives None, `recompute.bare_ids`
gives None for the thread, `recompute.judged` is False and no lane asks for it. It
is not a former-name scope and not an alias. A member's check answers `unknown` for
the same reason, so the poster and the member agree. Two MCP TypeScript SDK threads
of the same day (`CVE-...:modelcontextprotocol/typescript-sdk`) have the same shape.

Reading such an id needs the same change in the member's reader, which is a wire
question (released readers) and is not this issue. It is filed as a follow-up and
named in the close-out. This run changes nothing about it.

## Blast radius and rollback

Poster only: `aitools_alerts/poster/sources.py` (the order and the file),
`inputs.py` (the path and its clash check), `main.py` (the pre-pass, `admit`'s optional argument, the
log line), tests, changelog. One new file beside the ledger. No ledger, journal,
recompute state, wire format, schema, manifest, ruleset or scope file changes
shape. An earlier release ignores the new file; rollback is installing it.

First runs after install: candidates never read before are read over the first
`ceil(n / 10)` runs. One whose reading supports more than its thread's level is
raised as the existing rules allow, and a held notice whose reading supports a
level posts. That is the fix, and it is new traffic the release session should
expect (noted on ai-tools-alerts#g9bv).

## Prior work

`kata search` for the admit lane and its reads: ai-tools-alerts#3qyq (built the
lanes; its close-out chose "threads waiting for a lowering are read first, the rest
in rotation" and left admission in record order), ai-tools-alerts#yd1y (members
read in the thread's turn), ai-tools-alerts#5fry step 3 (found this defect). No
earlier attempt at ordering the admit lane.

## Review dispositions

Independent review of the first draft (fresheyes, gpt-6.1-sol, high) at 25df706:
1 blocker, 3 substantive, 1 cosmetic.

1. BLOCKER, the planned test used one collector record, which is consumed once, so
   later runs would have tested the deferred list's own rotation. Fixed: every
   measured run gets a new record with the same findings in the same order, and the
   tests count the `admit` lane's requests apart from the other lanes'.
2. SUBSTANTIVE, an API that answers slowly ends the lane's seconds before ten
   requests, and a clock-counted window moves on by ten regardless. Fixed by the
   redesign: the place moves by the requests made (criterion 3).
3. SUBSTANTIVE, missed runs could starve ids for good (twenty ids, every other
   hour). Fixed by the redesign: no clock.
4. SUBSTANTIVE, reading a malware advisory does not always raise (a root with no
   fix is capped; an untied reading counts for nothing). Fixed in the text:
   criterion 2 and the rollout note say "as the existing rules allow", and the test
   sets up a case those rules let through.
5. COSMETIC, the poster's and the member's slug patterns differ. Fixed in the text.

Whole-branch code review at 89e51d22b48cf37c260b53f1883a75022f71d902 (fresheyes,
gpt-6.1-sol, high): 1 blocker, 2 substantive. Same-model review of the same
commit: 2 substantive, 3 cosmetic.

6. BLOCKER (both reviews), `load_turn` opened the file with a blocking read, so a
   FIFO at the path would hold the run and the ledger lock for good. Fixed:
   `inputs.read_regular_json`; a test with a FIFO.
7. SUBSTANTIVE, the path in `check_paths` made a clash a configuration error that
   stops every run. Fixed: out of `check_paths`; `Config.admit_turn_free()` turns
   off the keeping of the turn alone. A link at the path heals on the next write.
8. SUBSTANTIVE, the log line printed every unread id, and a thread lane's unread
   ids can come from a response. Fixed: only admission's are named.
9. SUBSTANTIVE (same-model), a new candidate that the old order happened to read
   at once waited up to a round. Fixed: never-asked ids go first (criterion 8).
10. COSMETIC, the changelog said a slow API changes nothing about the bound.
    Fixed in the text.
11. COSMETIC, an unwritable turn file falls back to the old defect with one stderr
    line a run. Kept, and stated in the changelog and under "Limits".
12. COSMETIC, criterion 4 is tested for order and not for the page budget. Left:
    the pre-pass calls `rules.evidence` in the same order with the same page
    cache, and `test_many_candidates_leave_the_threads_their_reads` and the page
    budget's own tests pass unchanged.

Delta review of 91915b5503694f113259af7defc07f29a19855fb (fresheyes `--since
89e51d2`, gpt-6.1-sol, high): 1 blocker, 1 substantive. The last pass; what
follows was seen by no independent review.

13. BLOCKER, `admit_turn_free` compared paths with their last part unresolved on
    both sides, so a ledger lock that is a link to the turn file passed, and a
    write would replace the inode a running poster holds locked. Fixed: the other
    files are compared resolved as well; a test with the lock linked to the turn file.
14. SUBSTANTIVE, the ids remembered were cut to the current run's candidates, so a
    candidate whose page failed for a run was news again, and two groups failing
    by turns stayed first for good. Fixed: every id asked for is remembered
    (capped at 2000); a `main.run` test with pages failing in alternate runs.
