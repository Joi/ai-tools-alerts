# The poster reads GitHub and OSV advisories (ai-tools-alerts#3qyq)

Findings D4 and D13 of the design review on ai-tools-alerts#h29n. Slice A2 of the self-correcting design, after ai-tools-alerts#ny5g. Standing ruling (2026-11-23): the service runs with no human in the loop.

## Problem

ny5g gave the poster the rules for lowering a level and one reader, the CISA KEV catalog. An id that is looked up in GitHub's advisory database or in OSV has no reader, so three things are wrong today:

1. A thread that carries a GHSA id is never lowered, whatever its sources say (`recompute.support` makes every such read `unknown`).
2. The `ghsa` reading of a new candidate is built from the vendor's HTML page (`rules.readings_for`). The page shows no `type`, `cvss_vector`, `cwes` or `withdrawn_at`, so the reading supports a notice at most, the ruleset's rows for GitHub advisories never fire, and the fields differ from what a member's check reads from the API (`verify._ghsa_reading`).
3. `Support.lowers` is declared in the ruleset and enforced nowhere in the poster.

## Scope

In: a reader for `api.github.com/advisories/<GHSA id>` and for `api.osv.dev/v1/vulns/<id>`; the recompute judging threads by those reads; the candidate's `ghsa` reading built from the API response; `lowers` enforced.

Not in this slice, each its own issue:

- The reversible `withdrawn` state (ai-tools-alerts#y484). Here a withdrawn advisory of a class that may lower takes its thread no lower than `notice` or its prose floor, and the thread stays shown.
- The claim tag on sent events (ai-tools-alerts#hh5s).
- A send whose outcome is unknown still holds its thread (ai-tools-alerts#jsje, a sibling session).
- The critical channel's copy of a thread the recompute raises to critical (ai-tools-alerts#3t4p). The recompute sends a level-only reply in the channels the thread has a root in. A thread posted at high is in `feed` only; raised by the recompute it is critical there and absent from the `critical` channel until a candidate for it is sighted again (`plan_known` posts the copy). Before this slice the recompute raised only threads that already had both roots. Raising in `feed` at once is still better than holding the raise for the copy.
- A thread kept under a product's former name is still not recomputed (`rules.scope_of` does not resolve former names; note 5 on 3qyq).

## Approach

### The reader: `aitools_alerts/poster/sources.py`

`Reader.read(lookup_id)` returns a `Read` or None. None is `unknown`.

- The id enters a URL only when `verify.norm_id(lookup_id) == lookup_id` and `ruleset.source_of` names `ghsa` or `osv`. The URL is `verify.url_of(lookup_id)`: the two fixed prefixes with the id percent-quoted. Of OSV's ids only `MAL-` ones pass `norm_id`, as for the member: the ruleset gives no other OSV entry authority.
- The request is `verify.default_fetch` (looked up at call time): https to one of the fixed hosts, no redirect followed, no proxy variable read, one deadline for the whole request, a body returned only when it arrived whole and inside `verify.LIMITS` (256 KiB).
- Only status 200 with a body that parses strictly (`verify._strict`: no duplicate key, no `NaN`) and passes `verify._ghsa_reading` or `verify._osv_reading` and then `Ruleset.read` is a read. A timeout, a 3xx, 403, 404, 429, 5xx, a parse error, a truncated or oversized body, a response for another id, and more than `verify.MAX_NAMES` named ids are None. A 404 is never a withdrawal: it is None like the rest.
- A `Read` holds the reading's `fields` and what `verify._record` keeps of them: per scope product `[level, lowers, stop_using]`, the reading's own `lowers`, and the ids the response names (`cve_id`, `identifiers`, OSV `aliases`), each in `norm_id`'s exact form.
- A run makes at most 30 requests in at most 60 seconds (GitHub allows 60 unauthenticated requests an hour for one address; the ledger lock is held), in three lanes that cannot spend each other's share: `admit` (new candidates), `wait` (threads with a wait for a lowering running) and `rest` (every other thread), each 10 requests and 20 seconds spent inside its own requests (a candidate's page fetch between two reads is not the lane's time). One request has at most 5 seconds. Past a lane's limit its reads are None. Each id is asked for once a run, whichever lane asks first; a failed read is not tried again in that run. See "Which threads are read first" for why no lane can starve another.
- Nothing is cached between runs and no ETag is sent: a 304 would stand for a stored verdict, which must be thrown away on every ruleset change.
- Nothing a response says is printed or stored, except the reading itself in a candidate (as today).

The poster and the member use the same functions, so they cannot build different fields from one response.

### The recompute: `recompute.support`, `judge`

`support(entry, scope, copy, rs, read)` judges one id set, built as the member's check builds it (`verify._Run.thread`; fv4g's note on ny5g): the thread's own ids, and, when the first id is a GHSA id whose read may lower (`Read.lowers`), every id that read names, carried by the thread or not. That is how an OSV entry is reached: a thread's ids are CVE and GHSA ids only (`BOT_ID`), and a `MAL-` id enters when the first advisory names it. A named CVE joins the KEV part. More than `verify.MAX_ALIASES` (3) named advisory ids is not known, as for the member.

The KEV part is ny5g's, over the CVE ids of that set. For every other id of the set:

- `read(id)` is None, or the id has no reader: the thread is not known (nothing is lowered), as today.
- **Tied.** Which ids are one advisory is the source's word. When the thread's first id is a CVE, an alias's read counts only when its reading may lower and names that CVE. When the first id is a GHSA id, its own read counts, and another id's read counts only when the first id's read may lower and names it. A read that is not tied adds nothing to the level and makes the thread not known. One function, `sources.tied`, decides this for the recompute and for a candidate (below).
- **`lowers`.** A tied read whose class for this product has `lowers` false (an unreviewed advisory that is not the vendor's own, an OSV entry that is not `MAL-`), or that does not name the product and whose reading has `lowers` false, makes the thread not known. Its support, a notice at most, is not counted. So a withdrawn unreviewed advisory lowers nothing.
- Otherwise the read's level for the product counts toward `found` (a withdrawn reading gives `none`), and so does its `stop_using`: `support` also returns whether a read gives `found` through a `stop_using` row. `held` passes that to `Ruleset.action_level`, beside what it infers today from a thread standing at the level. So a malware advisory that was withdrawn and is published again returns its thread to critical, when the thread's published actions still hold the `stop_using` its root carried.

`judge` changes in three places:

- A thread is judged when the ledger marks it exploited (ny5g) or it carries an id with an advisory reader. A thread with neither has no source to rest a lowering on and is not judged.
- A complete KEV copy is needed only when the thread carries a CVE id.
- The two KEV-absence rules (a gone CVE must have been seen listed by a complete copy; the wait must end on a later `catalogVersion`) apply to threads marked exploited. A thread never marked exploited does not rest on KEV: its CVE was never listed, and that absence is not what lowers it. A wait's `version` is null when the thread has no CVE id.

Exploitation is recorded when it is observed, whether or not a level changes: when a copy, complete or not, lists a CVE of the thread's id set for this product, `judge` adds the thread's root to `exploited` in the recompute state, saved by `Run.observe` before anything is sent. The KEV-absence rules govern a thread the ledger marks exploited or that list holds. A thread already at critical that KEV lists later is therefore never lowered on an absence no complete copy vouched for. The ledger's own mark is not set here: `plan_known` reads it to decide whether "exploitation learned" still earns a reply, and that reply must not be lost to the recompute having looked first.

A CVE beside an advisory first id is tied like any other alias: it counts, listed or absent, only when the first id's response names it. One the bot lists and the source does not name lends no KEV level and makes the thread not known.

The circuit breaker's share is of the threads whose every source was read whole in this run (`known`): only those can be lowered. A thread judged with an unknown read does not count, so twenty GHSA threads nobody could read do not make three due lowerings look small.

Everything else of ny5g stands unchanged: a raise publishes in the run that sees it, from any tied read; a lowering needs every source of the thread read whole, the same lower level held 24 hours over reads at most two hours apart with no unknown read between, seven quiet days, the circuit breaker; it is a level-only reply in every channel; the prose floor; `drop_unsent_lowerings`.

### Which threads are read first

Admission runs before `Run.observe` and reads in the `admit` lane only, so no number of candidates takes a read from a thread. `Run.observe` judges the threads with a wait running, reading in the `wait` lane, then the others in the `rest` lane. Each group is taken in a stable order (by root id) that starts one thread further on every hour (`now // 3600` modulo the group's size). So every thread is first in its lane once every N hours, N the group's size, and the first thread of a lane is always read: 30 waits that answer 404 for ever, or reads that all time out, cost the `wait` lane its share and nothing else, and a thread whose advisory now supports critical is read within N hours at the latest.

A thread past its lane's limit is unknown this run: nothing moves, and a wait takes no time for the gap. With more than ten ids waiting, or more than ten others, a thread is read less often than every two hours and its wait does not grow: the poster then lowers nothing on advisory evidence and says on stderr how many ids it did not read. Raises still publish, late by at most N hours.

### The candidate's reading: `rules.readings_for`

When a repository advisory page confirmed the candidate (`ev.structured`), the `ghsa` reading is `read("GHSA-…")`'s fields, whole: every package the advisory lists, its `type`, CWEs, vector and `withdrawn_at`. The HTML page no longer makes a reading.

**Only a tied reading sets a level.** `ledger.merge` joins candidates that share an id, and (faxq) advisories one release fixes, and unions their readings; the post's first id is one member's. `Run.one` therefore keeps, of the merged candidate's `ghsa` readings, only those `sources.tied` accepts for the first id of the post, from this run's reads. That id is the published id of the candidate's thread when it has one, else the candidate's own: a later sighting of one group member alone arrives under that member's id and must not raise the thread the member's check reads by another. Kept are: the first id's own; an alias's when the first id is a CVE and the alias's response may lower and names it; an alias's when the first id is a GHSA whose response may lower and names the alias. A grouped advisory the first one does not name lends no level, exactly as the member's check ignores it. `kev` readings are as today.

**An unread advisory is tried again.** When the read is None the candidate has no `ghsa` reading this run: its level rests on KEV or on prose as before, and it posts or is held as today. It is also kept in the deferred list and admitted again each run until the read succeeds, for at most `RETRY_DAYS` (7) from first sight. First sight is the state's `waiting` record; when that map is full and records none, there is no retry at all, so nothing is retried without a bound. A later run whose read gives more then starts the root (a held notice becomes a post) or raises the thread through `plan_known`, with no new collector record. For a thread that exists, the recompute raises it as well.

So the ruleset's GitHub rows fire for the poster (9kgk's note on ny5g): a vendor's own or reviewed advisory with a code-execution, credential or bypass CWE and a patched version posts at high from its fields; a malware advisory, or the vendor's own with CWE-506, at critical with `stop_using`.

### What the code review changed

The whole-branch review (see the run record) found four ways a published level could differ from what a member's check finds, or a lowering could rest on less than this document says. Where the text above disagrees, this section is the design.

- **Only the ids a member reads count.** `sources.chosen(first, aliases, read)` is `verify._Run.thread`'s own selection: beside a CVE first id, the first three advisory ids among the thread's published aliases; beside a GHSA first id whose response may lower, the first three ids that response names, sorted, CVEs among them. An id past the third, and an id the ledger holds that no post named, is not counted and makes the thread not known. Beside a CVE first id with more than three advisory aliases none is counted: since ai-tools-alerts#tavj (merged into this branch from main) a member picks its three by what its own machine read before, so no three are every member's. So a fourth alias can neither raise nor hold a level. (A CVE thread's other CVEs are still looked up in KEV, as ny5g built it.)
- **A KEV listing is remembered with its CVE, in two places.** The recompute state's `exploited` is `{root: [CVE, …]}`, written by `judge` and saved before anything is sent. `Run.recompute`, after the run's candidates are planned, sets the ledger's own `exploited` mark for those threads (`Ledger.mark_exploited`), so a lost recompute file leaves the thread governed by the KEV-absence rules. A thread so governed is not known without a complete KEV copy, while a CVE once listed is not among the ids judged (the advisory stopped naming it), and when no CVE of it is judged at all.
- **A fix group posts under its loudest member.** `ledger.merge` orders a group's members by how high each one's own structured evidence reaches (`rules.evidence_rank`: its readings, and the KEV row when it is marked exploited), then by publication date as before. The post's first id is then the one whose sources give the group's level, so KEV evidence lent by another member (faxq: "its level is the loudest member's") is never above what the first id supports. With equal evidence the order is what it was.
- **`stop_using` is what this run read.** `held` infers "the thread stands at this level by a published stop_using" only when some source was not read whole. With every source read, only a read that says so completes a critical by `stop_using`: a malware advisory that comes to state a patched version falls to high after the day, as the member's check of the same response finds.

## Success criteria

1. A 404, a 429, a 403, a 503, a 302, a timeout, a body that is not JSON, one with a duplicate key, one over 256 KiB, one for another id: each lowers nothing, starts no wait, and adds no time to one. Tested per status through `main.run`.
2. A reviewed advisory whose CWE list stops supporting high, read so for 24 hours of hourly runs, lowers its thread once, to notice or the floor, in every channel, as a level-only reply.
3. An advisory field that toggles every hour for a week sends no level reply. One that toggles every two days sends at most three level replies in any seven days.
3a. A malware advisory posted at critical with `stop_using`, withdrawn (lowered after the wait) and published again, returns to critical in the same thread.
3b. A candidate held as a notice while the API answered 429 posts its root at high in the first run the API answers, with no new input record. The retry ends seven days after first sight.
3c. A fix group whose first advisory supports a notice and whose other member supports critical posts at the first one's level; the published thread, given to `verify.run` with the same responses, is not `contradicted`.
3d. A GHSA thread at critical that a KEV copy lists (no level change) is recorded as listed in that run; when the advisory then weakens and KEV drops the CVE without a complete copy ever having listed it, nothing is lowered.
3e. Ten waiting threads whose reads fail every run do not keep an eleventh thread, whose advisory now supports critical, from being raised: it is raised within as many hours as there are other threads. Thirty candidates in one run leave the `wait` and `rest` lanes their reads.
3f. A GHSA response that names a `MAL-` id makes one request to `api.osv.dev` for it, and that entry's support counts.
4. A withdrawn unreviewed advisory lowers nothing, however long it is read. A withdrawn reviewed advisory lowers to notice or the floor, never further, and the thread stays in the ledger and the feed.
5. An alias the source does not tie to the first id lowers nothing and raises nothing.
6. A thread at high whose advisory comes to support critical is raised in the run that reads it, alone.
7. The reading of an admitted candidate equals `verify._ghsa_reading` of the same response, byte for byte in canonical form; with the API unread the candidate posts as it does today without a `ghsa` reading.
8. No id reaches a URL unless `norm_id` returns it unchanged; the only hosts requested are `api.github.com` and `api.osv.dev`; a run makes at most 30 advisory requests.
9. Every ny5g test passes unchanged, the breaker's share test included (its twenty GHSA threads are unread, so they are not in the share), with one mechanical edit: their `_support` helper takes the first four values of `support`, which now returns a fifth. The poster tests' `env` gets an advisory API that answers every GHSA id with a reviewed advisory of the vendor's own that lists no weakness (a notice by the ruleset), so the existing tests run in a world where the API works and says no more than the page. Tests rewritten because they assert the HTML-built reading: in `tests/poster/test_rules.py`, `page_cand`, `test_the_page_evidence_carries_the_fields_a_reading_needs`, the `poster-ghsa-page` case of `test_the_poster_builds_the_shared_vectors_byte_for_byte` (the vector is unchanged: an API answer that states no type, weakness or vector gives its fields) and the generator of `test_rule_of_fields_is_the_level_of_every_claim_the_poster_builds`; in `tests/poster/test_main.py`, `test_admit_puts_the_readings_on_what_the_level_is_computed_from`. One test changes because the recompute now judges its thread: `test_compose_value_error_sends_nothing` still asserts nothing of the refused plan is sent, and now also sees the recompute's level-only raise. `spec/claim-vectors.json` does not change.
10. `scripts/test-gate.sh` exits 0.

## Alternatives considered

- **A second parser in the poster.** Rejected: two builders of one reading drift, and every drift is a published level a member's check contradicts.
- **ETag cache (`If-None-Match`).** Rejected for now: the stored verdict needs invalidating by ruleset digest, a 304 must be bound to a body that came direct (note 3 on 3qyq), and unauthenticated 304s are not known to be free of the rate limit.
- **An authenticated GitHub token** (5,000 requests an hour). Rejected: a credential on the poster for a read anyone can make; the member's check is unauthenticated too.
- **Counting an untied alias.** Rejected: the member ignores it, so the poster would publish levels no member can confirm.
- **Lowering a GHSA thread without the KEV copy when it carries a CVE.** Rejected: a lowering needs every source of the thread read whole (ny5g).
- **Keeping the HTML reading as a fallback.** Rejected: its fields are not the source's (null `type`, no CWEs), so its claim could never match a member's.

## Blast radius and rollback

- The poster makes up to 30 more HTTPS requests a run, to two hosts it did not contact before, under the ledger lock, for at most 60 seconds.
- New roots can post at high or critical from an advisory's fields where prose gave a notice. That is the ruleset as written (version 3); nothing in `spec/` changes, so the pinned digest does not move.
- Open threads that carry a GHSA id become lowerable. On the first day nothing can fall (24 hours of reads), then at most two threads or 20% of those judged a day (the breaker). A thread posted before the ledger kept a floor is lowered to high at the lowest.
- A thread whose CVE a KEV copy lists is marked `exploited` in the ledger at the end of that run, level change or none. A candidate for it sighted later is then rated with the KEV row, as for any thread a KEV candidate raised.
- Advisories one release fixes post under the member with the strongest evidence, not always the newest.
- No new file and no new key in the ledger or the journal. The recompute state gains one key, `exploited` (a state written before loads with it empty), and a wait's `version` may be null. An older poster refuses a recompute state with the new key and replaces it (every wait starts over): rollback is safe at any time, with the ny5g steps for threads already marked lowered.
- Rollback of the code: revert the merge. Levels already raised stay raised (a run never lowers without the recompute).

## Open questions

None that block. Assumes: the unauthenticated `api.github.com/advisories/<id>` answer carries `repository_advisory_url`, `type`, `cwes` and `withdrawn_at` (confirmed on a live response by fv4g; this session makes no request).
