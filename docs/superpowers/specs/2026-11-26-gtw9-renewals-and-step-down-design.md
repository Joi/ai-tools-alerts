# The poster renews its threads, steps an unconfirmed one down, and roots carry their claim (ai-tools-alerts#gtw9)

## Problem

Readers 0.1.8 and later compute a thread's life from the claims its relay-bot events carry (ai-tools-alerts#r0ra, `spec/wire.md` "How this reader computes expiry"): a thread whose root carries a claim stands at critical for 14 days, at high to day 30, at notice to day 90 and is then gone, unless a later claim renews it. The poster sends a claim with each level change (ai-tools-alerts#hh5s) and none on a root (`main.ROOT_CLAIMS = False`), because it sends no renewal and because the signer gives up a relay-bot reply the mirror stopped serving after 72 hours (`signer.settle_gone`, `settle_owed`), after which an honest checkpoint lists the root without the renewal and the reader decays the alert. So today nothing decays: a critical whose source withdrew stays critical on every reader for as long as the thread lasts, unless the poster's recompute lowers it.

## Success criteria

1. A root, and a copy of it in another channel, carries its claim (`ROOT_CLAIMS` on). The ledger keeps the thread's standing claim: the newest claim of a level it sent for the thread.
2. Each run renews every thread that has a standing claim and needs it: a reply in each channel the thread has a root in, with a fixed line, no block, and a claim tag. When this run's reads confirm the claim, `confirmed_at` and `checked_at` are the run's time. Otherwise `confirmed_at` is the standing claim's and `checked_at` is the run's time.
3. A thread whose source answers 403 for 30 days is renewed and stays at its level on this reader and on 0.1.8 to 0.2.1.
4. When no read has confirmed a thread's level for 45 days less one day, the poster lowers the thread one level with `compose.level_post`, whose text says why. A thread at notice is not lowered further. A reader shows the ledger's level or a higher one throughout.
5. A thread whose source confirms is renewed with a new `confirmed_at` and keeps its level indefinitely.
6. The signer never signs a checkpoint that lists a thread's root without the renewals that keep it standing: not when the mirror has hidden one for 72 hours, not when the thread does not fit a checkpoint whole, not after the checkpoint state was lost, and not when the poster failed to deliver a renewal that was due. The thread is left out of checkpoints instead, and keeps its level on every reader.
7. Released readers v0.1.4 to v0.1.7 show every thread at the same or a higher level than this reader, with claimed roots, renewals and a step down on the feed (`tests/test_wire_compat.py`).
8. `scripts/test-gate.sh` passes.

## What exists (read at 9850f9e)

- `Run._claim(readings, ids, scope)` builds a claim's text with both times set to the run's `now`. `Run.observe` and `Run.recompute` keep, per thread judged, the readings its verdict rested on (`self.readings[root]`: each advisory response read, tied and allowed to lower, and each KEV entry read as this product's).
- The reader: `pull._renewal` takes a relay-bot event's claim as a renewal when it is well formed, its level is not `none`, it names an id the thread has held and `checked_at <= created_at`. A relay-bot reply whose block names a level also counts as a renewal of its own date. `Ruleset.stands_until(level, confirmed_at, checked_at) = max(confirmed_at + TTL, min(checked_at + TTL, confirmed_at + 45 days))`; `level_at` gives the highest level, from the thread's level down, that some renewal keeps standing. A thread is judged only under a checkpoint that lists its root, and not while one of its renewals is dated after that checkpoint.
- `signer.settle_gone` gives up, after `OWED_S` (72 hours), an event the poster's copy holds and the mirror no longer serves, except a curator reply, whose whole thread is left out of checkpoints instead (`suppress`). `signer.settle_owed` drops an acknowledged post never seen on the mirror after the same time.
- A ledger entry with a key this code does not know is malformed (`ledger._entry_ok`).

## Design

### The standing claim

The ledger entry gains two optional keys: `claim`, the text of the newest claim of a level sent for the thread, and `root_ids`, the ids the thread's first root stated. `Ledger.set_claim(root, text, root_ids=None)` writes them; `root_ids` is written once. A thread has a standing claim from its first root sent with one (`Run._record`), and only from there: that is what "enrolled" means below. After that a level reply's claim, a copy's and each renewal replaces it when it was checked no earlier and names one of `root_ids`. A claim whose level is `none` (the source withdrew) is never the standing claim: it renews nothing on a reader.

Why `root_ids`: a reader counts a claim only when it names an id the thread has held in the events that reader has (`pull.threads_from`). An alias a later reply brought is held only by a reader that has that reply, and a checkpoint may list a thread without it. So the standing claim, and every renewal built from it or from a fresh reading, names an id of the root, which every reader of the thread has.

A thread that is not enrolled is never renewed and never stepped down, and nothing it is sent later enrols it: a level reply's claim is not stored for it, and a copy planned for it later (`plan_known`, `Run.copies`) carries no claim. So a thread posted before this change stays exactly as it is in every channel, and so does a thread whose root's claim was too large to send (over 2048 bytes) or had no reading. Too high for too long is the safe side; the member's own source check still judges those.

### What a run's read says about a thread

`Run._confirming(e, old)` returns `(confirmed, text)`:

- Not confirmed when the thread was not judged in this run (`self.judged`: out of scope, no source to judge it by, or busy when it was looked at), or no reading its verdict rested on (`self.readings[root]`) is about one of `root_ids`.
- Else the claim is built from the reading `rules.claim_text` chooses, whatever its size (`limit=False`). It confirms when its level is no less than the lower of the standing claim's level and the thread's ledger level: the level being kept. (A critical stepped down to high is confirmed by a source that states high; a KEV claim of critical on a thread held at high by the action cap is confirmed by a reviewed advisory that states high.)
- `text` is that claim when it fits a tag. When it confirms and does not fit (the source added packages), the renewal is the standing claim with both times set to now: its fields are those of the last reading that fit, and a source still states at least its level. Size is never read as a failure to confirm.

A read that failed, a spent share, a response not tied to the thread and a response of a class that cannot lower all leave the thread unconfirmed, as they leave the recompute unknown. A thread whose only source is one its subject can write (`ghsa-other`, `osv-other`) is therefore never confirmed and steps down at the ceiling.

### Renewal (`Run.renew`)

After the alert work of a run, for every enrolled ledger thread that is not synthetic:

1. `life`: the last second a reader keeps the thread at its ledger level by what was sent, computed as the reader does: the larger of `stands_until(level, c, k)` for the standing claim's `confirmed_at` and `checked_at`, and `stands_until(level, t, t)` for `t` the time of the thread's last level change (`Entry.changed`; the reader counts a level reply as a renewal of its own date). `t` is the time of the attempt that sent the reply, never later than the event is dated: a reply recorded by a later run (a replay after a stopped run, an unknown send the mirror settled) is recorded with `changed_at`, the time of its pending mark or first attempt. `best`: the same with the claim a renewal sent now would carry (`c` now when confirmed, else unchanged; `k` now).
2. A renewal is due when `life - now` is at most half the level's TTL and `best > life`. So a confirmed critical is renewed every 7 days, a high every 15, a notice every 45; an unconfirmed critical is renewed at days 7, 14, 21, 28 and 35 and then no more, because the ceiling of 45 days is reached and a further renewal changes nothing.
3. It is also due, whatever its life, when the checkpoint state has been lost since the standing claim was checked: see "The signer keeps a renewal".
4. It is sent in every channel the thread has a root in, as a reply to that root: `compose.renewal_post()`, the line "Sources checked. No change to this alert.", no block, with the claim tag. At most `MAX_RENEWALS` (20) sends a run. The due threads are taken in a stable order that starts one thread further on each hour (as `_in_turn`), so no thread whose send keeps failing can keep another unrenewed.
5. Each acknowledged send is owed to the checkpoint first (`signer.record_sent`). When every channel's send was acknowledged, `Ledger.set_claim` records the claim.

A renewal is not journaled. It changes nothing in the thread but its claim, sending it twice is harmless, and the next run computes it again from the ledger. So an unknown or failed outcome marks nothing pending, holds no later work of the thread, and needs no settling: that thread is left for the next run and the pass goes on to the next; after three sends that were not acknowledged the pass ends (the relay is down). The pass runs after a run whose alert sends stopped (`_Stop`) too; it does not run after a `LedgerError`.

**A thread the poster could not renew is not vouched for.** These roots are left out of the run's checkpoint (`Run.unrenewed`, `run_checkpoint(..., suppress=...)`): the roots of a thread whose renewal was due and not acknowledged in every channel, when its `life` has run out or runs out within two hours; the roots of a thread whose step down is due and was not journaled (work of the thread is in flight, or compose refused it), under the same two hours; the roots of a thread whose renewal after a lost checkpoint state is not yet acknowledged, whatever its life; and the root of each channel of an enrolled thread for which a level reply waits unsent in the journal or the withheld list. The last covers a step down the relay did not take, and one that one channel took and another did not: the ledger then holds the new level and counts its TTL, while the second channel's readers have not been sent it. Listed, each of these would decay on a reader for want of an event the poster failed to deliver; unlisted, it keeps the level its events give. A thread with nothing due (unconfirmed past the ceiling at notice) stays listed and leaves readers as designed.

Not covered: a run that ends in a `LedgerError` renews nothing and still signs (as it does today). A ledger that cannot be read for seven days while checkpoints go out lets criticals fall; the run's exit code and stderr say so every hour.

The summary line gains ` renewed=N` (and `/M` not acknowledged) only in a run that tried one, so it is unchanged otherwise.

Why not every run, as the issue words it: the mirror's channel files hold 2,000 events and a checkpoint lists 990. A renewal an hour for each thread in each channel would pass both within days. Half the TTL leaves 7 days of hourly runs to deliver a critical's renewal.

### Step down

In the same pass: an enrolled thread this run does not confirm, whose `best - now` is at most `STEP_EARLY` (one day), whose level is above notice and that has no work in flight (`busy`), is lowered one level: `_level_items(e, lower, claim, reason)` through `enqueue`, the journaled path every lowering takes (level-only reply in each channel, the ledger's `lowered` mark, the digest line). `best`, not `life`: a poster that was stopped for 13 days and cannot read its source renews (which extends the critical to day 27); only a level that no renewal can extend is stepped down. The reply's line is "Level is now high. No source has confirmed the higher level for 44 days." (`compose.level_post(prev, level, reason)`, the number being the whole days since `confirmed_at`); the block stays exactly `{"level": ...}`.

The stepped-down reply's claim is the standing claim with `checked_at` now: `confirmed_at` does not move without a confirming read. The reader counts the reply itself as a renewal of its own date, so the level it names stands for its TTL from the step, and the poster's `life` uses the same rule: its second step (high to notice) comes 29 days after the first. At notice nothing more is sent and no renewal extends anything; the thread leaves readers 90 days after the last step. A later confirming read renews it, and a source that supports more raises it through the recompute as today.

**What a reader shows, against the ledger.** A reader does not apply the step at once. It is a lowering like any other (`spec/wire.md`): applied when the member's own check gives no more, after checkpoints 72 hours apart when the check cannot settle it, and never when the check finds the source supports more. Until then the reader holds the higher level, and the reply's own date renews that level too (critical for 14 more days). So after a step a reader shows the ledger's level or a higher one, never a lower one: every renewal the poster's `life` counts is an event the reader has, and `level_at` gives the highest level, from the reader's own down, that any of them keeps standing. A reader that keeps refusing (its source confirms critical) falls from critical to the stepped level 14 days after the last reply that named a level. Too high, where the member's own read supports it, is the intended side.

One day early, not at the 45th day: a reader past the ceiling shows notice at once, skipping high. The reply must be on the feed before that; a day is 24 runs to send it.

The step down does not pass through the recompute's seven quiet days or its circuit breaker. Readers apply the ceiling to each thread by its own dates whatever the poster sends; holding the reply back would only turn "one level" into "notice". A prose reading that a candidate brings again can raise a stepped thread back (`plan_known`); it then stands for that level's TTL and is stepped again. That is too high, bounded, and listed in the follow-up on when a thread ends.

### Copies

A copy planned for an enrolled thread (`Run.copies`, ai-tools-alerts#3t4p, and `plan_known`) carries the claim this run's readings state, else the standing claim with `checked_at` now, so both channels' roots are enrolled alike. A copy planned for a thread that is not enrolled carries none, for the same reason.

### The signer keeps a renewal

What a reader counts as a renewal of a thread is: a relay-bot event's claim of a level (`pull._renewal`), with the claim's two times; and a relay-bot reply whose block names a level, with its own date for both (`pull.threads_from`). `signer.renewals_of(ev, m)` returns those time pairs for a relay-bot reply. One renewal makes another redundant when both its times are no earlier.

- `settle_gone`: a held reply past `OWED_S` (72 hours), in a thread whose root carries a claim, that carries a renewal no served reply of the same thread makes redundant is not given up. Its thread root joins `suppress`, as a curator reply's does. Once a later renewal is served it is given up like any reply. A thread whose root carries no claim never decays, and its replies are given up as before.
- `record_sent(..., renewal=(c, k))`: the owed entry of such a reply, in an enrolled thread, gains the key `renewal` (for a reply that names a level, the run's time twice: the event is dated no earlier). `settle_owed` keeps such an entry past `OWED_S` unless the poster's copy holds a renewal of that thread that makes it redundant; `run_checkpoint` takes a kept one off the must-list and adds its root to `suppress`.
- `window`: a thread on the must-list (it has a curator reply or an owed reply) lists, with its root and curator replies, the renewals of the thread that no other makes redundant, one reply for each such pair of times (two replies with the same times do not remove each other). Today such a thread, when it does not fit whole, is listed as root and corrections only: a root without the renewals that keep it standing.
- Lost state: `load_owed` forgets what is owed when its file is missing or damaged, and signs nothing for 72 hours on the ground that every debt would have been given up by then. A renewal's is not. The record keeps `hold_until` after the hold ends, so the time of the loss (`hold_until - OWED_S`) stays known: `Run.renew` sends a renewal for every enrolled thread whose standing claim was checked before it, due or not, and leaves that thread's roots out of the checkpoint until the renewal is acknowledged. Each is owed anew and makes a forgotten renewal redundant. Once per thread: the new claim is checked after the loss.

One case stays open after a lost state file: a reply that changed a level, acknowledged in the 72 hours before the loss and hidden by the mirror. A renewal that could not confirm does not replace what that reply's own date gave. A reader that never received it shows the level before it and counts life from older dates. It needs a lost file and a hiding mirror in the same three days; it is in the follow-up on the checkpoint's dating, where the owed record is reworked.

A thread left out of a checkpoint keeps the level its events give on every reader (`pull.active`: judged only when listed), and new members do not see it. That is what a curator's missing correction already does. A mirror that hides a thread's renewals can pin the thread; it cannot lower it.

Not protected, as today: a reply that changes a level and is hidden is given up once a later renewal is served, and a reader that never had it shows the level before it. Hiding a raise this way is the same gap as before this change; the member's own source check is what answers it.

## Tests

`tests/poster/test_renew.py`, through `main.run` with the fake relay and the fake advisory API: a claimed root enrols and an unclaimed one does not; a thread whose source answers 403 for 30 days gets renewals at days 7, 14, 21 and 28 with the first `confirmed_at`, and this reader (`pull.active` under a checkpoint at day 30) shows it critical; a confirming source renews with a new `confirmed_at`; at day 44 the step down is posted with its reason and a claim whose `confirmed_at` is unchanged, and at day 43 it is not; a poster stopped until day 13 renews and does not step; a source that confirms the stepped level stops the second step; a claim that no longer fits renews with the standing fields; a legacy thread's later copy carries no claim and the thread is never renewed; a failed send leaves the ledger's claim and the next run sends; a failing thread does not keep the next one unrenewed; an overdue thread's roots are left out of the checkpoint; a lost checkpoint state renews every enrolled thread once. `tests/poster/test_signer.py`: a missing renewal (held, and owed) is kept and its thread suppressed until a later one is served; a level reply's date counts; a must-listed thread lists its newest renewal when it does not fit whole. `tests/test_wire_compat.py`: every released reader against a feed with a claimed root, renewals and a step down shows the same level as this reader or a higher one, now and at days 30, 50 and 100. Tests that pinned the old behaviour (roots without claims; three-argument senders that now get a claim) are updated.

## Alternatives rejected

- **Renew every run.** See above.
- **Journal the renewal like a reply.** An unknown outcome would hold a later raise of the thread for up to 24 hours (`settle`), once a week per thread, for an event that is safe to send twice.
- **Set `confirmed_at` to the step's time.** The claim would say a source confirmed what none did.
- **Keep the standing claim in the recompute's state file.** That file is replaced by an empty one when unreadable; losing it would stop every renewal and decay every thread.
- **Step down at exactly 45 days.** A late send shows notice for the hours until it arrives.
- **Protect every relay-bot reply in the signer.** A deleted digest or source-only reply would then hide its thread for good; only a renewal's absence lowers anything.
- **Enrol a thread by a copy.** A thread posted before this change, raised to critical, would get a claimed copy and then be renewed and stepped down in both channels, while its first root never decays.
- **Take the thread with the least life first.** A thread whose send keeps failing would be first every run.

## Not in this change (follow-up issues)

- The checkpoint dated when it is signed, and a reader that refuses an event dated after its checkpoint (item 2 of the r0ra review note). Nothing here needs it: the reader holds back the claim of such an event already.
- The 45 days as a key of `spec/ruleset.json`. A new key is a new ruleset version; a reader on version 3 reads a claim naming version 4 as `unknown` until the trust root pins it. It waits for the next ruleset version, as the issue says.
- When a confirmed thread stops being renewed. A thread whose source keeps confirming is renewed for good, 24 events a year for a high in one channel; at about one root a day the feed file's 1,000-event half fills in under a year.

## Blast radius and rollback

- From the first claimed root, threads decay on readers 0.1.8 and later when the poster stops renewing them. The poster must keep running: a poster stopped for more than 7 days lets its claimed criticals fall to high on those readers. Threads posted before this change are untouched.
- Readers 0.1.4 to 0.1.7 ignore the tag and read a reply without a block as discussion; a step down is a lowering they skip.
- The ledger and the checkpoint state gain keys the code before this change refuses (`claim` in a ledger entry; `renewal` in an owed entry). A rollback is safe only before the first claimed root is recorded; after it, roll forward. A rolled-back poster with such a ledger stops with a `LedgerError` and sends nothing.
- No release, install or signing step is part of this change. The release session's steps are in a comment on ai-tools-alerts#fa5a.

## Assumes

- One poster with one ledger (as `signer` already does).
- `Entry.changed` ends with the time of the thread's last level change (`Ledger.record_reply` appends it).

## Open questions

None that block.
