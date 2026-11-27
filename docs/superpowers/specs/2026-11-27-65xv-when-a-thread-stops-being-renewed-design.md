# When a thread stops being renewed, and what a checkpoint lists of it (ai-tools-alerts#65xv)

## Problem

Since ai-tools-alerts#gtw9 a thread whose root carries a claim is renewed for as long as its source confirms it: one reply in each of its channels every 7 days at critical, 15 at high, 45 at notice. A published advisory confirms for good, so the thread never ends.

Three stores are bounded and none of them is:

- A checkpoint lists at most 990 events (`signer.MAX_LISTED`). `signer.window` lists a thread whole or not at all, so a high posted a year ago costs 25 of them. At one new high a day a year of threads is about 4,800 events; the window then lists the 40 or so most recently renewed threads and leaves the rest out. A thread a checkpoint does not list keeps its level on a reader that has it and is not shown to a new member.
- A reader stores at most 20,000 events (`pull.MAX_STORED_EVENTS`) and drops a thread 400 days after its newest event, which a renewed thread never reaches. Past the cap a reader stores nothing new and reads stale. Released readers cannot be changed.
- A channel file holds 2,000 events (`mirror/export_mirror.py`). The exporter already keeps every event the published checkpoint lists first, so the file is the least of the three: it stays inside its caps by construction and serves whatever the checkpoint lists.

Second, from the same issue: a level the poster stepped down because nothing confirmed it for 45 days is raised again by a candidate that brings the same reading of prose (`plan_known`). It stands for the level's TTL, is stepped down again, and repeats for as long as candidates arrive: two events a month in each channel, for good.

## Success criteria

1. A checkpoint lists a thread's root, every reply that is not a renewal alone, and of its renewals only those no other makes redundant. A reader of the listed events shows every thread at the level a reader of all of them shows.
2. A thread stops being renewed 90 days after its level last changed (after its root, when it never changed). It then runs down by the step every unconfirmed level already takes: one level lower a day before its life on a reader ends, with a line that says why, to notice, and off readers 90 days after the last step.
3. A thread that has ended is raised again only to a level above the one it ended at. That raise makes it an ordinary thread again, renewed for 90 days.
4. A thread whose level no read has confirmed for 44 days is raised by a candidate only when the candidate's readings of fields state the new level for an id of the root.
5. Acceptance (the issue's): a simulated year of one new high a day, through the poster, the signer, the real exporter and a reader, keeps both channel files and every checkpoint inside their caps, and a reader that pulls the mirror on the last day, having pulled daily or for the first time, shows every thread the ledger still holds open at the ledger's level or a higher one.
6. The rule is in `spec/wire.md`.
7. `scripts/test-gate.sh` passes.

## Design

### 1. What a checkpoint lists of a thread (`signer.slim`)

A **renewal alone** is a relay-bot reply with no block that is not a translation (`pull._patch(content) is None`, first line not `lang:`) and that carries a renewal (`signer.renewals_of`). To a reader such a reply changes nothing but the thread's renewals (`pull.threads_from`: it appends the claim's pair of times and goes on). A released reader (v0.1.4 to v0.1.7) reads it as discussion.

`slim(events of one thread, m)` returns the thread without each renewal alone that `_frontier` does not keep: one whose two times are both no later than another renewal's of the thread. `Ruleset.stands_until` grows with both times for every level, so a reader loses nothing with them: `level_at` gives the same answer at every moment. Two things bound that:

- **The thread's newest event** (by `created_at`, then id) is always kept, whatever it is. A reader's retention (`pull._retain`) drops a thread 400 days after the newest event it holds, and a reader that starts today holds only what is listed. So a renewal alone that is the newest event stays listed even when a backdated event makes its times redundant, and even on a thread that is not enrolled.
- **The reader's code is the judge.** `_frontier` reads a claim as `pull._renewal` does, without asking whether the claim names an id the thread holds; the reader asks (`threads_from`: `x[0] in ok`). A reply under the bot's key whose claim names another id could stand in `_frontier` for a renewal the reader counts, with later times or with the very same ones. No rule here tries to tell them apart. `slim` builds the thread from all of its events and from the kept ones (`pull.threads_from`) and returns the kept ones only when both give the same thread in every field but `renewals`, and the same set of renewals no other makes redundant. Otherwise it returns the thread whole. Events with no root among them are returned as they are.

**The must-list.** Since gtw9 a thread on the must-list (it has a curator reply or an owed reply) is listed at the least as its root, its curator replies and `_frontier`, so that a correction is listed even when its thread has outgrown a checkpoint. Nothing checked that set: a renewal later than a raise makes the raise's own date redundant, so the frontier leaves the raise out and a new reader shows the level before it. It also left out every other relay-bot reply: one that widens a range, so that a member on a version the root does not cover is not matched, or a translation. `signer._core` now adds every relay-bot reply that names a level and uses that set only when the reader's code builds from it the very thread it builds from all the events (`_reads_alike`, the comparison `slim` makes): what is left out is then replies a reader ignores and renewals another covers. Otherwise the set is `slim(thread)`, all of which must fit. When what must be listed does not fit, nothing is signed, as today.

`window` lists `slim(thread)` where it listed the thread: whole threads newest first, a thread that does not fit skipped. Nothing else in the signer changes: `settle_gone` already gives up, after 72 hours, a renewal the mirror stopped serving that a served renewal makes redundant, and `lapsed` still judges the poster's whole copy.

The exporter is not changed. `cap` keeps the events the published checkpoint lists, and those a candidate lists, before anything else, then whole threads newest first. A thread that has outgrown the room keeps its listed events: its root, its changes and its standing renewal. A new post belongs to the thread with the newest event, which is tried first. So the files stay inside 2,000 events and 4 MiB as before, and every event a checkpoint lists is served.

Cost of a thread in a checkpoint after this: its root, the Japanese reply to it, one renewal, and a reply for each level change; the same again in a second channel for a critical.

### 2. A thread ends (`main.RENEW_DAYS = 90`, the ledger's `ended`)

The clock of a thread is the time of its last level change (`Entry.changed`, which `record_reply` keeps), or `posted_at` for a thread whose level never changed. In `Run._renew`, an enrolled thread whose clock is 90 days old, that has not ended and has no work in flight (`busy`), ends: `Ledger.end(root, level)` writes the ledger key `ended`, the level the thread holds then.

An ended thread:

- is never renewed and no read confirms it (`fresh` is false, `best` is `life`: nothing more will be sent that extends it), with one exception, next.
- **after a lost checkpoint state** (`signer.load_owed`: what was owed is forgotten). A renewal the relay acknowledged may be newer than the ledger's claim (`_send_renewal` owes it before the ledger takes it, and a run can die between) and is now owed by nobody. A renewal with the old confirmation would not make it redundant, and at notice `signer.lapsed` does not look. So an ended thread whose life has not run out and whose standing claim was confirmed before the loss gets one renewal that this run's reads confirm (`_confirming`), confirmed and checked now, which makes every earlier renewal redundant; until a run can send it the thread's roots are left out of the checkpoint (`Run.unrenewed`; decided before the step test, which a notice in its last day would otherwise leave by), where the thread keeps its level on every reader that has it. Once per loss: the new claim is confirmed after it. It gives the thread at most one more TTL of its level. An ended thread whose life by the ledger has run out is sent nothing, and its roots stay listed. A renewal would bring back a thread that is off readers, and so would leaving it out: a reader does not judge a thread its checkpoint does not list (`pull.active`) and keeps its events for 400 days, so every reader that still stores the expired thread would show it again, at the level its events give. What is not covered: an ended notice whose last renewal the relay acknowledged, the ledger never recorded (the run died between), the checkpoint state then lost and the mirror withholding that renewal, found only after the ledger's life has run out. A reader that never got that renewal drops the notice up to one TTL early. That takes three faults at once and loses a notice the poster had already stopped renewing; the alternative shows every expired alert again after any lost state.
- is stepped down by the rule gtw9 built: when `life - now` is at most `STEP_EARLY` (a day) and the level is above notice, one level lower through `_level_items` and the journal. The reply's line is `Level is now notice. This alert is 104 days old and is no longer renewed.` (`compose.AGED`, the whole days since `posted_at`). Its claim is the standing claim checked now, as an unconfirmed step's is.
- at notice gets nothing more and leaves readers 90 days after the step that brought it there.

No renewal is sent on or after day 90. So a high posted on day 0 and confirmed throughout gets its last renewal between days 75 and 89, is stepped to notice 29 days after it (days 104 to 118), and is off readers 90 days later. A critical gets its last renewal between days 83 and 89, is stepped to high 13 days after it, to notice 29 days after that, and off 90 days later. Every protection of gtw9 applies unchanged, because the steps are the same events sent the same way: `Run.unrenewed` for a step that is late, `signer.lapsed` for one that is missing, and a reader that applies the step only on its own check, after 72 hours of checkpoints, or when its renewals run out. A reader shows the ledger's level or a higher one.

**Raises.** While a thread's source still states its old level the recompute would raise an ended thread straight back. So:

- `recompute.judge` and `recompute.raised` give no raise for an entry with `ended` unless the level found is above `ended`. The entry is then judged as one whose sources hold its level: no raise, no wait for a lowering.
- `plan_known` keeps the thread's level unless the candidate's level is above `ended` (`Run._may_rise`).
- `Run._clears` asks `_may_rise` too, before `yields`: a candidate whose raise will not be planned must not make the drain pass over the thread's unsent work. Otherwise an age step that one channel took and the other did not would be passed over on every run in which a candidate brings the old level again, and the thread, busy, would never take its next step.
- `Ledger.record_reply` removes `ended` when it records a raise. The raise is a level change, so the clock starts again from it.

A raise above the level a thread ended at is news (a CVE that KEV lists a year later) and the thread is an alert again for 90 days.

A thread that is not enrolled (no standing claim: posted before gtw9, or a root with no reading) is never renewed today and never ends: no event is sent for it.

**With the withdrawn state** (ai-tools-alerts#kk2q, which landed while this was built). A withdrawn thread is sent no renewal and no step, and the renewal pass leaves it before the ending rule, so it does not end while it is withdrawn; it decays on readers as its claims say. No candidate raises it (`plan_known`, `_clears`). The recompute's way out of the state (`recompute.leaving`) is not held to `ended`: an advisory published again is news, the reply that says so is recorded as a level change, `ended` is removed and the thread is renewed for 90 days from then.

**Why 90 days, and from the last level change.** What bounds the choice is the checkpoint. With the Japanese reply an open thread costs three listed events in a channel and a daily digest two. A high is open for about 111 days at high (its last renewal, on average at day 82, and 29 days more) and 90 at notice: about 200 days. At one new high a day that is about 615 events, and the digests newer than the oldest open thread's last event about 180 more: 800 of 990. At 120 days it is 890, at 180 days 1,070. A reader that pulls daily stores about ten events for such a thread and holds it for 520 days: about 5,000 of its 20,000.

The clock runs from the last level change and not from the root so that a thread raised on day 80 is not ended ten days later. It does not run from the day a fix was published, which the issue suggests: a thread with no fix would then never end, and the caps need every thread to end.

Past that rate the checkpoint is full and `window` leaves out the threads whose newest event is oldest: the notices that have run down longest. Each keeps its level on the readers that have it and is not shown to new members. Nothing is lowered by it.

### 3. A candidate's raise of an unconfirmed thread

In `plan_known`, for an enrolled thread whose standing claim was confirmed 44 days ago or longer (`ruleset.UNCONFIRMED_DAYS` days less `STEP_EARLY`: the poster has stepped it down or is about to), a raise is planned only when the claim this candidate's readings give for the root's ids (`_claim(rules._readings(c), entry.root_ids, scope)`) is of a level no lower than the raise. Sent, that claim becomes the standing claim, confirmed now, and the thread is an ordinary one again. A candidate with a reading of prose alone, or with fields about an alias, changes nothing about the level; the rest of what it brings (a fix, ids, sources) is planned as before. A thread this run's own reads confirm (`_confirming`) is not held to this: a healthy notice is renewed every 45 days, so its claim can be 44 days old. The rule is `_may_rise`'s, so `_clears` applies it as well.

The recompute's raise is not changed: it rests on fields read in that run.

## Tests

- `tests/poster/test_signer.py`: a thread with a root, a Japanese reply, ten renewals and a level reply is listed as root, Japanese reply, level reply and the one renewal the level reply's date does not make redundant; a reader of the listed events and a reader of all of them give the same level at days 0 to 120. A renewal under the bot's key whose claim names another id, with later times or with the same times and a lower event id, makes `slim` return the thread whole. A high root, a raise to critical and a later renewal, in a thread with an owed reply and no room for it whole: what `window` lists gives a reader critical. A must-listed thread whose frontier is a claim about another id is listed slim, and with no room for that nothing is signed; so is one with a reply that widens its affected range, and a reader of what `window` lists holds the wider range. Every listing test reads `window`'s output through `pull.threads_from`. A renewal alone that is the thread's newest event is kept though a backdated reply covers its times, and `pull._retain` 401 days after the root keeps the listed thread. 400 threads of a root and twelve renewals each: `window` lists every root and exactly one renewal for each, 800 events.
- `tests/poster/test_renew.py`, through `main.run`: a confirming high is renewed to day 90 and not after; `ended` is written on day 90; the step is sent a day before its life ends with the age line; the recompute does not raise it back while the advisory still states high, on that day or after the step; a candidate that brings it again raises nothing; a KEV listing raises it to critical, removes `ended`, and it is renewed again. A critical ends through high to notice. A thread with work in flight on day 90 ends on the next run. An ended critical whose step one channel took and the other did not: a candidate that brings critical again does not pass over the unsent reply, and the next run sends it. After a lost checkpoint state an ended notice whose life has not run out is renewed once, confirmed now, and its roots are out of the checkpoint in a run whose read does not confirm; one whose life has run out is sent nothing, and its roots stay listed. A thread stepped down unconfirmed is not raised by a candidate with prose alone, and is raised by one whose fields state the level.
- `tests/poster/test_ledger.py`: `end` writes the key once; a ledger with `ended` set to something that is no level is malformed; a recorded raise removes it and a recorded lowering does not.
- `tests/poster/test_end_to_end.py`: the simulated year (criterion 5), with the real exporter and `mirror-put`. One run a day stands for the poster's 24, with the advisory reads of 24 (`sources.LANE_READS`): at one run's share a thread would be read every 36 days by the end and stepped down unconfirmed, which is the read budget's limit and not this change's. The suite runs 200 days (threads have ended, stepped down and left readers, and the checkpoint has stopped growing), about three minutes; `AITOOLS_ALERTS_SIM_DAYS=365` runs the whole year, about eleven.
- `tests/test_wire_compat.py` is not changed: an age step is a level-only reply with another sentence on its line, the shape the test's feed already holds.

## Alternatives rejected

- **End a thread N days after its fix was published** (the issue's first candidate). A thread with no fix never ends, so nothing is bounded.
- **A longer renewal interval for old threads.** The interval is half the level's TTL and the TTL is the ruleset's (version 3, pinned). Renewing later leaves fewer runs to deliver a renewal and saves under a factor of two.
- **Stop renewing and send no step.** `signer.lapsed` leaves out of checkpoints a root whose renewals no longer hold the level the bot last named, so the thread would be pinned at its level on every reader instead of running down.
- **Make the exporter drop superseded renewals** (the issue's third candidate). It already serves what a checkpoint lists first, so the listing decides what is served; a second place that judges which renewal is redundant could disagree with the signer and withhold an event a checkpoint lists.
- **End a thread at once on day 90 with a step.** The last renewal already holds the level for up to a TTL; a step at once would shorten what was sent and gives nothing.
- **Mark a thread stepped down unconfirmed in the ledger.** The standing claim's `confirmed_at` already says it.

## Not in this change

- ai-tools-alerts#0kze: the poster judges every ledger thread each run, the ended ones and those long off readers too, and reads ten advisories a run in each lane. A thread must be read once in 44 days or it is stepped down unconfirmed, so the ledger has room for about 10,000 judged threads at 24 runs a day, and the daily simulation needed 24 runs' reads. The issue asks for a slow turn for threads that are off readers.
- The CLI does not read `catalog.json` yet, so an advisory whose alert has ended is on no reader. ai-tools-alerts#8nb4 is where that reader is built.
- The 90 days as a key of `spec/ruleset.json`: it is the poster's choice of when to stop sending, not something a reader computes.

## Blast radius and rollback

- On the first run after this lands, every enrolled thread whose level last changed 90 days ago or longer ends. No such thread exists yet: roots carry claims since v0.3.0's successor only.
- Checkpoints list fewer events. A reader that already holds a superseded renewal keeps it.
- The ledger gains the key `ended`, which the code before this change refuses (`ledger._entry_ok`). Rollback is safe until the first thread ends, 90 days after the first claimed root; after that, roll forward.
- No release, install or signing step is part of this change. The exporter and the readers are not changed, so only the poster needs the new code; the release session's step is a comment on ai-tools-alerts#5fry.

## Assumes

- One poster with one ledger, as `signer` assumes.
- About one new root a day, the issue's figure. The budget above says what happens beyond it.

## Open questions

None that block.
