# Apply the member's source-check result (ai-tools-alerts#tavj)

Finding D8 of the design review (comments on ai-tools-alerts#h29n), revised design rules 5 and 6. The source check itself is ai-tools-alerts#fv4g; ai-tools-alerts#c1g2 built the first row of the table (a published lowering applies when the member's check confirms it, and is refused when the source supports more).

## Problem

Three rows of the D8 table are not built.

1. **A lowering the member cannot check never applies.** With `verify = "off"`, a source that cannot be read, or a result that settles nothing, a relay-bot lowering waits for good. The OpenSSH critical that ai-tools-alerts#h29n must lower stays critical on every such machine.
2. **Nothing is lowered below `high`, and a withdrawal reads as a fabrication.** `verify.lowering` confirms only an exact match at or above the ruleset's `reading_cap`, because a `high` may rest on a reading the member cannot see. So a lowering to `notice` is never confirmed, a withdrawn advisory published at `notice` is flagged "the source does not support", and the KEV catalog no longer listing a CVE settles nothing.
3. **An unverified raise interrupts without limit.** Whoever holds the relay-bot key can post any number of criticals that no member can check, and each one interrupts.

## What is built

### 1. A lowering nobody can check applies after 72 hours of signed checkpoints

- `Thread.offered_by`: the id of the relay-bot reply that published `offered`. When the same level is offered again the first id stays. None when a curator offered it.
- A member keeps, per such reply, the `created_at` of the checkpoint it held when it first saw a checkpoint list the reply (`lowerings` in a new state file, `unverified.json`; `pull.offers`). The entry is dropped when the reply is no longer the thread's standing offer or the held checkpoint no longer lists it or the thread's root: the wait then starts again.
- `pull.standing(t, now, check, since)`: after any curator hold, a relay-bot offer the check answers None for applies when `now - since[offered_by] >= UNCHECKED_LOWERING_S` (72 hours). `now` is the checkpoint's time (`head_clock`), so only signed times count: a frozen mirror stops the clock, and an event's own date is never read (the key that signs a lowering could backdate it).
- False from the check still refuses, whatever the wait. True still applies at once.
- **A refusal is remembered** (`refused` in `unverified.json`, by the thread's root id), and while it is remembered no wait of that thread runs: the 72 hours start when the refusal ends. It ends only when the check confirms the thread's standing lowering, or when whole reads of authorities, fresh, give no more than its level. A state the sources were not yet asked about (any reply that changes the thread's aliases, products or actions gives a new one), a failed read, a crowded request budget, `verify = "off"`, a raise and a new lowering reply all leave it standing. So nothing the thread's signer posts turns a known refusal into an unchecked lowering.
- **The alias that refused is read first.** Only three aliases of a thread are read. They are taken in the order of what this machine last read each to support for the thread's products, highest first, so a reply that puts other aliases in front cannot push the supporting one out of the read.
- Not for a curator's lowering or retraction (c1g2: it lasts its 14 days and no longer), and not for a CLI the trust root calls too old or whose ruleset is out of date: those keep the higher level.
- While it waits the CLI says so: one line in `check`, `lowering_waits` in the JSON of a match. Not where no wait runs: a CLI that applies nothing unchecked, a thread whose refusal stands.
- The record is rewritten under the state lock from the record and the source-check results as they are on disk then, so a command that started earlier cannot write its older view over a newer refusal.
- Support read before a run's request budget ran out is kept as a contradiction (`verify.run`): the lowering is refused, not left unread.
- A lowering to a second, lower level starts its own wait; the first is not applied meanwhile. Too high is the safe side.

### 2. The claim tells a field-based level from a reading

- `Thread.stated`: for a relay-bot thread, `(level, claim or None)` for the root and for every reply that names a level (a relay bot's block, a curator's block or `level:` line; a curator's has no claim).
- `verify.claimed(adv, level, stated, rs, pin)`: True when every stated level above `level` carries a claim that is well formed, whose id is the thread's first id (`verify.norm_id`), that `ruleset.check_claim` finds `ok` for every product of the thread, and whose level is at least the stated one. Then no level above `level` rests on a reading.
- The asked state carries that bit (`verify.at_level(adv, level, claimed)`, part of the state key only when set). `verify.lowering(adv, level, cache, now, rs, stated, pin)` computes it.
- `verify.lowering` is True when no product's source supports more, every product's result is `match`, `reading`, `unsupported` or `withdrawn`, the result is fresh, and either `level` is at or above `reading_cap` (nothing the member cannot see can hold more), or the state is claimed.
- What each of the four rests on: every read the thread needs arrived whole. `match`: an authority gives exactly the level and nothing read gives more. `reading`, `unsupported`, `withdrawn`: every source read is an authority and none gives more. In `match` a record that is no authority (an unreviewed advisory, the catalog not listing a CVE the advisory names) is left out, as it has been since c1g2: by the ruleset such a source sets notice at most, so it cannot hold support above any lowered level, and the level itself comes from an authority's positive word, not from a silence.
- **Withdrawal.** `verify.judge` at `notice`, when a source that may lower names the product and no source supports anything: `confirmed`, why `withdrawn` (new). A source that is silent about the product is still `unsupported`.
- **Delisting.** The KEV catalog not listing a CVE is no authority (fv4g). For a claimed asked state whose first id is a CVE it is: the thread's signed claims say the catalog listed it for this product, and the member's whole read says it no longer does. The alias reads still count, so support through an alias refuses the lowering.
- A retraction (`none`) is still never confirmed.

The cache version goes to 3 (a new `why`).

What a stolen relay-bot key gets: it can sign claims, but a lowering is refused whenever the member reads support for more, from the first id or an alias the thread ever held. Where a level rests on a reading, or on a source the thread does not name, the root's claim does not name the first id's fields, the state is not claimed, and the lowering takes the 72-hour path.

### 3. Two unverified interrupts per poster key per 24 hours

- A relay-bot critical interrupts on a **slot**, kept in `interrupts` of `unverified.json` as `{bucket: {root event id: local time}}`.
- **Verified:** the matched product's cached result is `confirmed` and was read no more than 48 hours ago (`verify.FRESH_S`). It takes the one slot of its advisory and product (a hash of the first id as the source is asked for it and the matched product's name) per 24 hours. The result belongs to what was read, not to the post: a second post about the same advisory and product, whatever its title, aliases or level, finds that slot taken and is unverified. An alert is decided once, whatever number of installations or products it matches through; it is verified when any product it matches is. `run` reads the source of every critical match again once its result is a day old, so a confirmation does not outlive a source that changed.
- **Unverified:** anything else (unknown or contradicted; `verify = "off"`, an out-of-date CLI and a damaged ruleset are all unknown). It takes one of two slots of its poster key (the root event's `pubkey`) per 24 hours.
- **The slot is taken when the interrupt is reported, not when a channel accepts it.** `run` exits 2 and lists `unseen_critical` whether or not a notification was delivered, and the session-start hook interrupts on that. `_interrupts` decides without writing; `_reserve` then records the grants under the state lock, against the record as it is then, before the command prints or returns anything, and with no channel configured. An alert whose slot a concurrent run took meanwhile comes back held, so the JSON and the exit status name only alerts that hold a slot. An alert that holds a slot keeps interrupting until it is seen, so a failed notification is tried again by later runs and uses no second slot.
- An alert with no slot is **held**: printed by `check`, in `held_critical` of `run --json`, not notified, not marked seen, not in `unseen_critical`, and it sets no exit 2. It interrupts as soon as its source is read and confirms it (in the same `run`, after the source check), or when a slot is free. A free slot goes to the alert held longest (`held` in `unverified.json`: since when), before an alert never held and before one whose own slot ran out undelivered. So neither posts dated earlier nor undelivered alerts taking their slots again keep a held alert out for good.
- The notification of an unverified alert ends with the line `Not verified from this machine`. `check` prints one line naming the relay-bot matches whose result is unknown.
- The clock is this machine's: the limit protects the member's attention, and no signed time is the member's. A slot dated after the clock is not counted (a clock set back must not silence criticals for good).
- A curator's own alert needs no slot.

### 4. The record mends itself

`unverified.json` is not in `verify.json`, which is dropped whole when damaged. A missing file is empty. A file that cannot be read or has another shape is not a `StateError` (every later run would stop on it, and nobody is there to mend it): the next command that reads the feed writes a new one, on the safe side. Every wait starts again, every remembered refusal is asked again, and `reset_at` is set: for 24 hours from then no unverified alert takes a slot, because how many were used is unknown. Verified alerts still interrupt. The CLI prints one line on stderr when it does this.

The record cannot outgrow its own loader. Every entry is keyed by a stored event (a lowering reply, a thread's root) or stands for one stored root (a bucket), `refused` is cut to the threads that exist on every update, and slots outside the window are dropped whenever one is granted. The loader's limit per record is the store's limit on events (20000), so nothing the CLI writes is refused when read back.

## Not in this issue (split, see the kata comment)

- "The source never supported it: show at notice, no interrupt", with "supported earlier, flag only past 48 hours": ai-tools-alerts#0z4e. It demotes a critical on the member's own evidence and needs the earlier-support memory.
- Comparing a narrowing of products, range or fixed version with the source: ai-tools-alerts#swfe. Today a relay-bot narrowing never applies (ai-tools-alerts#tyje).
- Strikes against a key: ai-tools-alerts#m729.
- The poster's claim tags: ai-tools-alerts#3qyq. Until the poster signs claims, no state is claimed and every lowering below `high` takes the 72-hour path.

## Known limits

- A thread with more than three aliases that this machine has never read support through is never read whole, so a lowering of it is unknown and takes the 72-hour path. The key that signs the thread decides its aliases. A member who had refused the lowering keeps refusing it.
- Whoever holds the relay-bot key can fill the queue of held alerts with false ones. A true critical the member cannot verify then waits its turn behind them, two a day, oldest held first; it is listed by `check` and in `held_critical` all the while, and interrupts at once on any machine whose source read confirms it. The cap cannot tell an unverifiable true alert from an unverifiable false one; the order only keeps any one alert from being passed over for good.
- A member whose source reads are crowded out for 72 hours (the run reads at most ten sources) applies a lowering it never refused. The design accepts 72 hours for a member who cannot read.

## Success criteria

1. The relay-bot key lowers a critical to notice while the KEV fixture lists the CVE for the product: the CLI keeps critical and prints the refusal line.
2. The source withdraws (a GHSA advisory withdrawn; a CVE the catalog no longer lists), the thread's levels are claimed: the lowering to notice applies in the run that reads the source, and no "does not support" line is printed for it.
3. The same two with the member's fetch failing: the critical stays; the lowering applies once checkpoints 72 hours apart have listed it, and not before; a backdated lowering waits the same.
4. Three unverified criticals from one key within 24 hours: two notify, the third is listed and held, `run` exits 2 only for the two; when its source confirms it, it notifies.
5. A lowering refused after its 72 hours, then a reply that changes the thread's state so the supporting alias is no longer among the first three: still refused, in the command that runs before the next source check and after it.
6. A new root that copies a state confirmed earlier, after the source withdrew: unverified, and capped.
7. `run --json` repeated with every channel failing, and with none configured: the same two alerts are reported each time and a third stays held.
8. A damaged `unverified.json`: the next run goes on, prints one line, and the cap holds for 24 hours.
9. `tests/test_wire_compat.py` passes unchanged: no event, tag, block or manifest changes. `scripts/test-gate.sh` passes.

## Alternatives considered

- **Count the 72 hours from the lowering's own date.** Refused: the relay-bot key signs that date.
- **Count them on this machine's clock.** Refused by the issue: signed checkpoint times only. A frozen mirror must not let a wait run out.
- **Treat KEV's silence as authority for every thread.** Refused: a critical resting on a source the thread does not name would be lowered at once.
- **Check the source before notifying, so nothing is unverified at first sight.** Refused: a critical never waits for a source (fv4g).
- **Keep the records in `verify.json`.** Refused by the fv4g note: that file is dropped whole when damaged, which would reset the cap.
- **Use a slot only when a channel accepted the notification.** Refused in review: the hook interrupts on the exit status, delivered or not.
- **Stop with a `StateError` on a damaged record, like `seen.json`.** Refused in review: it stops every run until a person acts.
- **Restart the wait whenever the thread's state changes.** Not enough alone: a state that can never be read whole would still run out its 72 hours after a refusal. The remembered refusal covers it.

## Blast radius and rollback

Member CLI only: `pull.py`, `verify.py`, `state.py`, `cli.py`. No wire, schema or manifest change; one new state file that a released reader ignores. The poster and the exporter call `pull.active` without a check or a record and see no change. Roll back by reverting the commit; an `unverified.json` left behind is ignored by the earlier CLI, and `verify.json` at version 3 is dropped by it and rebuilt.

Assumes: one poster key posts the relay bot's alerts, so the cap is in effect per feed.

## Open questions

None that blocks. Whether the mark belongs on every relay-bot match or only on criticals: this spec marks every one, in one line.
