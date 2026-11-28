# The admit lane's advisory reads take turns (ai-tools-alerts#vszx)

Date: 2026-11-28. Base: main at d2dd492 (release v0.5.0).

## Problem

Each poster run may make ten advisory API requests for new candidates (the `admit`
lane, `sources.LANE_READS`). `Run.admit` spends them as it goes: for each candidate
whose repository advisory page confirms it, `rules.readings_for` asks
`sources.Reader.read(<its GHSA id>, "admit")`. Candidates are admitted in the
collector record's order (`main.run`, the `pairs` list), and the collector keeps
that order from hour to hour. So the same ten candidates get the ten reads on every
run and the others get none, for good.

Measured on ai-tools-alerts#vszx: 34 candidates ask, the same 10 are read in all of
48 replayed hourly runs, the same 24 never. The live poster prints
`advisory reads: 20-21 id(s) not read this run` on every run since v0.3.0.

Effect: a candidate never read has no `ghsa` reading. It is rated from its vendor
page and prose alone. A level its advisory's fields support (a reviewed weakness, a
malware entry) is never reached, and a root posted from it carries no claim. The
seven-day retry (`RETRY_DAYS`) meets the same order every time.

The thread lanes (`wait`, `rest`) do not have this defect: `Run._in_turn` starts one
thread further on every hour.

## Success criteria

1. With n page-confirmed GHSA candidates, n greater than `LANE_READS`, in a fixed
   record order, and an API that answers, every one of them is asked for within
   `ceil(n / LANE_READS)` consecutive hourly runs, starting from any hour. A test
   runs `main.run` hourly and checks it for n = 34.
2. A candidate past the tenth place whose advisory comes to support more (a malware
   entry) is raised within that many runs.
3. A read that is slow or fails cannot keep another candidate unread for good: over
   time every candidate is the first one asked in a run. A unit test checks it for
   every n from 1 to 45.
4. Nothing else about admission changes: the candidates admitted, their order going
   into `ledger.merge`, the pages fetched and their order, the page budget, the
   counters. The existing suite passes unchanged except where a test pinned the
   old order of advisory requests.
5. A candidate that was read in one run and is not read in the next sends nothing:
   no reply, no lowering. A test runs a full cycle over a steady set and checks
   that no post goes out.
6. The run's log line names the ids that were not read, so two runs can be compared.

## Approach

### The order: `sources.in_turn(ids, hour)`

A pure function. `ids` are lookup ids; `hour` is `now // 3600`.

- Sort the distinct ids. With n of them and a share of `LANE_READS` (10), start at
  `k = (hour * LANE_READS) % n` and wrap. The first ten in that order are this
  hour's window. Consecutive hours' windows are consecutive arcs of the sorted
  ring, so any `ceil(n / 10)` consecutive hours cover every id (criterion 1).
- Inside the window, start `j` places in, where
  `j = (hour // ceil(n / 10)) % len(window)`: one place further each time the ring
  has been covered once. So when the lane's seconds (`LANE_SECONDS`) run out
  before its ten requests do, the id that goes without changes from cycle to cycle
  (criterion 3). Without this, a set whose size divides evenly into windows (or
  has ten ids or fewer) would ask in the same order for good, and four reads that
  time out at the head would spend the lane before the rest every hour.
- The ids outside the window follow, in ring order. They are asked too, after the
  window: a request another lane already made this run costs the lane nothing, so
  a share the window does not use reaches them.

### The pre-pass: `Run.admit_all(pairs)`

`main.run` calls `r.admit_all(pairs)` where it called `r.admit` for each pair.

1. For each pair in order: `ev = rules.evidence(c, scope, self.page)`. The page
   fetches happen in the order they do today. `rules.evidence` reads only the
   candidate, the scope and the page cache, so computing every candidate's
   evidence before any candidate is admitted changes no result.
2. Collect `rules.ghsa_lookup(ev.ghsa)` for each `ev.structured and ev.ghsa`: the
   same condition under which `rules.readings_for` asks.
3. Ask `self._admit_read(i)` for each id of `sources.in_turn(ids, self.now // 3600)`.
   The reader memoises a granted request and records an id the lane could not
   afford in `Reader.unread`, as today.
4. For each pair in the original order: `self.admit(c, scope, ev)`. `admit` takes
   the evidence it is given (and computes it when given none, so its other callers
   and tests keep working). Its call to `rules.readings_for` now finds the answer
   memoised, or gets None for an id whose turn it was not.

Reads made later in the `admit` lane by `Run._tied` and `Run._rate` (a thread's
first id, to check that a source ties a reading to it) are unchanged. They come
after admission as they do today.

### The log line

`advisory reads: N id(s) not read this run (the lane's share was spent); their
threads are unknown and nothing of theirs moves` gains the ids, sorted, the first 40
and then `and N more`. They are public advisory ids, already in the collector
record; nothing a response says is printed. The release session (ai-tools-alerts#g9bv)
is asked to confirm that the ids differ from run to run, which the count alone
cannot show.

## Why not

- **Least recently read first, kept in the state file.** It is the better order: a
  candidate never read goes first, and a failed request does not cost a turn. But
  both state files check their key set exactly (`inputs.load_state`,
  `recompute._ok`). A new key in the run state makes every earlier release refuse
  the file ("malformed; refusing to send"), so rolling back the poster would need a
  person to edit state. That is not acceptable with no human in the loop. A new key
  in the recompute state makes an earlier release drop the file and start every
  wait for a lowering over.
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

- The bound of criterion 1 is for a steady set of candidates read on the hour. A
  candidate that joins or leaves moves the windows; a run that is missed skips one.
  Every candidate is still reached, because the ring keeps turning; the bound then
  is longer by the runs missed.
- A new candidate waits up to `ceil(n / 10) - 1` runs for its reading (three, for
  34 candidates). Until then it goes on as its page rates it, which is what a
  failed API request already does (3qyq), and is admitted again each run.
- Two runs inside one clock hour ask for the same window.

## The other question in the issue: the MCP Inspector threads

The issue asks why the `rest` lane does not read the ids of five open MCP Inspector
threads on 0.4.0. Found, from the public feed and the code: their roots were posted
on 2026-11-07 under ids of the form
`GHSA-4fc4-wcmh-4g86:modelcontextprotocol/inspector`. The slug holds a slash.
`candidates.BOT_ID` and the member's `verify.norm_id` both read a thread key's slug
as `[a-z0-9][a-z0-9.-]{0,31}`, so neither reads this id: `recompute.lookup_id` gives
None, `recompute.bare_ids` gives None for the thread, `recompute.judged` is False
and no lane asks for it. It is not a former-name scope and not an alias. A member's
check answers `unknown` for the same reason, so the poster and the member agree.
Two MCP TypeScript SDK threads of the same day (`CVE-...:modelcontextprotocol/typescript-sdk`)
have the same shape.

Reading such an id needs the same change in the member's reader, which is a wire
question (released readers) and is not this issue. It is filed as a follow-up and
named in the close-out. This run changes nothing about it.

## Blast radius and rollback

Poster only: `aitools_alerts/poster/sources.py` (one function), `main.py` (the
pre-pass, `admit`'s optional argument, the log line), tests, changelog. No state
file, ledger, wire format, schema, manifest, ruleset or scope file changes shape.
An earlier release reads what this one writes; rollback is installing it.

First runs after install: candidates never read before are read over the first
`ceil(n / 10)` runs. One whose fields support more than its thread's level is
raised then, and a held notice whose fields support a level posts. That is the
fix, and it is new traffic the release session should expect (noted on
ai-tools-alerts#g9bv).

## Prior work

`kata search` for the admit lane and its reads: ai-tools-alerts#3qyq (built the
lanes; its close-out chose "threads waiting for a lowering are read first, the rest
in rotation" and left admission in record order), ai-tools-alerts#yd1y (members
read in the thread's turn), ai-tools-alerts#5fry step 3 (found this defect). No
earlier attempt at ordering the admit lane.

## Review dispositions

(filled in after the review)
