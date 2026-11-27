# Aliases beside a CVE first id cannot hold a thread unread (ai-tools-alerts#nx25)

## Problem

The member's source check (`aitools_alerts/verify.py`, `_Run.thread`) reads a relay-bot
thread whose first id is a CVE like this: the catalog for the CVE, then each GHSA or MAL
alias the thread lists, at most `MAX_ALIASES` (3). An alias counts only when its own
response is an authority that names the CVE. The read is called incomplete when the
thread lists more than three such aliases, or when one alias read fails. An incomplete
read gives every product `unknown`, `unread`.

Whoever signs a relay-bot post can therefore hold the check at `unread` for good:

1. Four or more aliases that are not CVE ids. None needs to exist.
2. One alias whose read always fails. A GHSA id that does not exist answers 404, and a
   404 is a failed read.

The alert is then never confirmed, never contradicted, never shown at notice
(ai-tools-alerts#0z4e), and interrupts as unverified inside the cap of two per poster
key per 24 hours. An honest grouped thread (ai-tools-alerts#faxq) with more than three
GHSA aliases has the same fate.

Standing ruling (2026-11-23): no human in the loop. Nothing here waits for a person.

## Success criteria

Tests in `scripts/test-gate.sh`, all in the check itself (`tests/test_verify.py`):

- A relay-bot critical with a CVE first id that the catalog lists for another vendor,
  posted with four invented GHSA aliases, is `contradicted`, `unsupported` after the
  second run; with one alias that answers 404, after the first.
- A real malware alias listed with three invented ones gives `unread` and then
  `confirmed`, whichever of the four is read last. The same when its first read times
  out, however long it times out. Never `contradicted` on the way.
- Three aliases whose answer this reader refuses on every run do not keep a fourth from
  being read. 24 hours after the first incomplete read the thread is judged.
- An alias whose reads fail with no answer (a timeout, a 403, a 5xx) is never waived.
- A tied alias whose read fails, or answers 404, leaves the thread `unread`, before and
  after the deadline.
- More than three tied aliases are all read in one run and judged.
- Eight aliases count, the first this machine saw: one added later, in whatever place,
  is not read, holds nothing and pushes none of the eight out.
- A refresh of an answered alias that fails leaves the thread `unread`, not contradicted.
- A read the request budget refused is not an attempt.
- A lowering (an `Asked` state) with four aliases is `unread`, and one with an alias
  that answers 404 is `unread`, as today; no result of another state answers for it.
- A first id that answers 404 is a failed read, as today.

## Approach

All of it is in `verify.py`. It applies to a thread whose first id is a CVE and whose
state is not asked about as a lowering. A thread whose first id is a GHSA or MAL id is
unchanged: its related ids come from the source's own response, not from the post.

### A lowering keeps today's rule, under its own key

A state built by `verify.at_level` (an `Asked`) is a lowering or a retraction. It keeps
today's rule whole: every listed alias counts, at most three, each read with a record
in that run; a 404 is a failed read; nothing remembered is used.

Today an `Asked` state and a post with the same id, aliases, level and products have one
result key. With two rules that would let the result of a post answer for a lowering: a
signer could publish a copy of the thread at the lowered level and have its result,
read under the new rule, confirm the lowering. So `asked` becomes part of the key
(`_Target.key`). Every stored result is rebuilt once with the cache version.

### What counts as an attempt

`_Run` tells four outcomes of an alias read apart:

- **a record**: a 200 that arrived whole and this reader accepts, or a 304 to the
  stored ETag.
- **absent**: a 404. The source has no such entry.
- **refused**: the source answered and this reader cannot use the answer: a 200 body
  that is too large, does not parse, is of another shape or that the ruleset refuses;
  or a 4xx other than 403, 404, 408 and 429. `default_fetch` raises `TooLarge` for a
  body past the limit, so that it is told from a failed connection.
- **no answer**: a timeout, a network or TLS error, a redirect, 403, 408, 429, 5xx. And
  a read the run's budget did not make.

Only the middle two are things a signer can arrange by choosing an id. A member whose
network or rate limit fails gets "no answer", and that never settles anything.

### What is remembered

Three new keys of the cache (`verify.json`, version 6; a cache of version 5 is rebuilt
once, like every version before):

- `tried`: per alias id, `[at, met]`. `at`: when a request for it was last made (not
  one the budget refused). `met`: what that request met: `record`, `absent`, `refused`
  or `none`.
- `since`: per CVE first id, when a run first left one of its aliases unknown after a
  request for at least one of them.
- `counted`: per CVE first id, the aliases that count (next section).

All are per id, not in the result: a result's key changes with every signed change of
the thread, so a signer could otherwise restart any clock with a reply. `tried` is
pruned with `sources`, to the ids of current threads.

### Which aliases count

At most `MAX_LISTED` (8) GHSA or MAL aliases per first id: the first this machine saw
a thread of that first id list, taken in the thread's order when the check reads it,
and kept while a current thread still lists them. An alias that is not among them is
not read and holds nothing.

The selection is this machine's and it is sticky because the order of a thread's
aliases is not fixed: the reader replays replies by their date, which their signer
sets, so a later reply can put its aliases in front of earlier ones (code review). A
selection read from the thread each time would let a signer keep an untried alias in
front for good, and push out of the eight an alias this machine already counts. On a
machine that first sees the thread with such replies already in it, the selection is
the thread's order as replayed.

### Three states of an alias

Read from the cache, for alias `a` of first id `F`:

- **tied**: `sources[a]` is an authority (`lowers`) that names `F`. It stays tied
  whatever its later reads answer: a 404 or a refused answer for an alias this machine
  has read as evidence is a failed read of it, as today.
- **answered**: the last request for it met a 404, or a record that does not tie it.
  The source answered and did not tie it. A 404 supports nothing, lowers nothing and
  ties nothing.
- **unknown**: the last request met no answer or a refused one, or none was made. An
  answer stands only as long as the last request got one: when a refresh of an
  answered alias fails, the alias is unknown again and holds the thread (code review:
  an old 404 must not contradict an alert while the advisory cannot be reached).

`_Run.read` returns no record for a 404, so a first id that answers 404 stays a failed
read.

### The deadline

`ALIAS_WAIT_S` is 24 hours. Once `now - since[F]` reaches it, an unknown alias whose
last request met a refused answer is **waived**: it no longer makes the read
incomplete. One whose last request met no answer is never waived, whatever it met
before: it holds the thread until the source answers for it. A `since` dated after the clock is set to now.

So what a signer can arrange (an id whose entry this reader refuses to parse) holds a
thread for a day, and what a signer cannot arrange (this member's reads failing) is
read as today: a true alert whose supporting alias this member cannot reach stays
`unread`, never `contradicted`.

`since[F]` is dropped at the end of a run when no current thread with first id `F`
lists an unknown alias among those that count. It is not dropped per thread: the check
reads a thread's shown state and its widest state (every alias it ever listed) as two
states, and the shown one having no unknown alias must not restart the clock of the
other.

The deadline waives unknown aliases only. It starts whether or not the tied aliases
were read, and it never makes a failed tied read count.

### The reads of one run

1. Every tied alias. There are at most eight, and with the catalog that is inside the
   run's ten requests.
2. Up to `MAX_ALIASES` (3) unknown aliases that are not waived, longest untried first,
   then by id: three that fail every run cannot keep a fourth from being tried.
3. One more: of the waived aliases and the answered ones not tried for `RETRY_S`, the
   longest untried. An advisory that came to name the CVE after its first read becomes
   tied, and with a place of its own no other alias can keep it from that.

At most eight in all, the tied first. A thread with at most three aliases has all of
them read in every run, as today.

### When the read is complete

After the run's reads, with the states read again from the cache: the read is complete
when no unknown alias is left that is not waived, and every tied alias returned a
record in this run. Only records read in this run are judged, as today. While it is
not complete the thread is `unread`, with the support that was read as its lower bound
(0z4e), and `below-source` when that support is above the published level, as today.

`whole` of the result (what a narrowing and the end of a refusal are confirmed on,
ai-tools-alerts#swfe) keeps today's rule: at most `MAX_ALIASES` aliases, every one read
with a record in this run. A 404 or a waived alias never makes a result `whole`. So
this change confirms no narrowing that today's rule does not.

`MAX_PAIRS`, the most version ranges a cache this reader wrote can hold for a product,
grows with the number of records one thread counts, from four to nine.

### What a member sees

- The fabricated critical with invented aliases is `contradicted`, `unsupported` in one
  or two runs, and 0z4e then shows it at notice with no interrupt.
- A thread with an alias this reader cannot parse is `unread` for 24 hours from its
  first incomplete read, then judged on its first id and tied aliases, and read again
  daily like any result that is not confirmed.
- A grouped thread with more than three GHSA aliases is judged once each has answered.

## Alternatives considered

- **Waive any alias that was tried once, whatever the failure** (the issue's wording,
  and this design's first draft). A member whose reads of GitHub fail for a day would
  see a true alert, whose support is the alias, contradicted and shown at notice. The
  signer cannot make a member's reads fail; only what the signer can arrange is waived.
- **Never waive.** An entry this reader refuses to parse holds the thread for good.
- **A window per alias.** A signer who rotates aliases gets a new window with each
  reply (rejected on 2mgd). The deadline is per first id, and the aliases that count
  are bounded.
- **Ignore listed aliases for a CVE first id.** A true critical that rests on a malware
  advisory, with a CVE the catalog does not list for the product, would be contradicted.
- **A 404 for a tied alias is an answer too.** It would take away, without a read,
  support this machine has read. Today that 404 leaves the thread `unread`; it still does.
- **Expire an answer after a day and call the alias unknown again.** Every daily
  re-read of a thread with four invented aliases would be `unread` for a run. Answers
  stand; one is refreshed per run.
- **The same rule for lowerings.** Three invented aliases in front of the real one would
  confirm a lowering at a member who never read the real one. There "lower" is the
  unsafe side and not settling costs only the 72 hours.
- **Remember the alias states in the result.** Its key changes with every signed change.

## Where the issue text predates a landing

"The fallback in `run` for an exhausted budget must judge through the thread's own
product keys" is on main since 2mgd: `_Run.thread` judges every path through
`t.judge(p, ...)` per product key. Nothing to build; a test here keeps it.

## Blast radius and rollback

One module and its tests. No wire format, schema, manifest, ruleset or scope file
changes. The cache gains two keys and version 6; an older CLI reads a version 6 file as
an empty cache and rebuilds its own, so going back is reverting the merge. Results
change only for relay-bot threads with a CVE first id and listed GHSA or MAL aliases:
some that were `unread` for good are now judged. The CLI's own handling of each result
is untouched. A release is needed for members to get it (note on ai-tools-alerts#5fry).

## Open questions

- An alias this reader refuses to parse is waived after a day even when it is real
  support. The issue asks for exactly this: no entry may hold a thread for good. The
  cost is a true alert shown at notice on the strength of an entry nobody could read.
- A real advisory outside the eight that count does not count. On a machine that has
  read the thread before, later replies cannot put it there. On a machine that sees
  the thread for the first time, a signer's replies dated before an honest reply can.
- A signer who can also edit a listed advisory (refused, then readable) can drop the
  deadline and start it again with the next alias: at most once per alias that counts,
  so about eight days.
- An answered alias is refreshed one per run that reads the thread, so with seven of
  them a late tie is seen after up to seven such runs.
- A thread whose first id is a GHSA is not changed: an authority's own response that
  names more than three ids, or one whose read fails, leaves it `unread`.

## Review

One independent pass (gpt-6.1-sol) on snapshot deee8fd: four blockers and three
substantive findings. Taken, all in the text above: only a refused answer is waived,
never a failed connection (1); a tied alias stays tied through a 404 (2); one place a
run for refreshing an answered alias (3); `asked` in the result key (4); the first
eight aliases count (5); every tied alias is read in one run (6). Rebutted: the message
of the review snapshot commit (7), a dangling object that is never pushed.

The code review (gpt-6.1-sol and a same-model pass, on 9891088) changed two rules,
both in the text above: the aliases that count are a selection this machine keeps, not
the first eight of the thread as replayed; and an answer stands only while the last
request for the alias got one.
