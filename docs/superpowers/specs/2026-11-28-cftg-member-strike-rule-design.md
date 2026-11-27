# The member strike rule: probation for a key whose alerts the source does not support (ai-tools-alerts#cftg)

Finding D14 of the design review (comments on ai-tools-alerts#h29n), the member half; revised rule 10 ("A member's CLI puts a key on probation after two unsupported alerts in seven days") and the D8 table row "`contradicted`, the source never supported it: ... one strike against the key". ai-tools-alerts#m729 built the poster half. ai-tools-alerts#0z4e built the record a strike is read from.

## Problem

Whoever holds the relay-bot key, and a checkpoint that lists their posts, can publish alerts no source supports. Each member's CLI already limits one such alert: unread, it interrupts as one of two unverified alerts per poster key per 24 hours; once the member's own read of the source finds no support, it is shown at notice (0z4e). Nothing limits the series. Two unverified interrupts a day, every day, is what the key buys, and a lowering the member cannot check still applies after 72 hours. Removing the key from the manifest needs the trust root, which needs a person, and the ruling of 2026-11-23 says nobody is watching.

## Success criteria

Each is a test in `tests/test_probation_cli.py`, through `cli.main`.

1. Two fabricated relay-bot alerts (two threads, each for a product the catalog lists under another vendor), each read once by this machine within seven days, put the key on probation. A third critical from that key that this machine has not verified is listed in `held_critical`, is not notified, and `run` does not exit 2.
2. During probation, a critical from that key that this machine's read of the source confirms interrupts as before.
3. During probation, a relay-bot lowering of a thread of that key that the source check has not confirmed is not applied after checkpoints 72 hours apart have listed it. The same lowering on a machine with no probation applies. Once the source check confirms it, it applies during probation.
4. The probation outlives its evidence: with both fabricated threads gone from the mirror and from this machine's store, the memory of support emptied and the cached source results deleted (the test asserts each), the third alert is still held. It ends by itself 30 days after it began.
5. Each attack the design review of this spec found has its regression test: a copy changed after the strike is a second strike; a key on probation does not lower another relay-bot key's thread unchecked; a probation a concurrent command began holds an alert this command was about to report; the 72 hours start at the first command after the probation ended, however long the machine was off.
6. `scripts/test-gate.sh` passes; `tests/test_wire_compat.py` is untouched. One existing assertion changes: `tests/test_unchecked_lowering.py` lists the keys of a saved record and gains `probation`. A record without the key still loads (a test here, beside the one for a record from before 0z4e).

## Approach

All of it is in the member CLI (`aitools_alerts/cli.py`) and its state (`aitools_alerts/state.py`). `pull.py`, `verify.py`, the wire and the poster are not changed. Nothing waits for a person: the probation starts from the member's own reads and ends on the member's own clock.

### 1. What a strike is

An alert is an entry as the CLI shows it (`cli.Entry`): one thread, or the threads of one advisory with equal content and equal judged state (a critical has a root in each channel). A relay-bot alert earns a strike when this machine's memory of support says that no source it read ever supported one of the products of the alert's judged state: for that product every root of the entry has `gone` set and none has `last` (`cli._never`, the test that already shows such a match at notice). The strike's time is that product's `gone`, this machine's time of the first whole read that found no support; with several such products, the earliest.

A strike is recorded only where the memory is written (`_note_support`), so under the same guards: a CLI that verifies nothing (`verify = "off"`, a CLI the trust root calls too old, a ruleset out of date or unreadable) records none; nor does a record rebuilt from damage less than 48 hours ago; a finding under another ruleset digest was already dropped from the memory.

Not a strike, as in the issue: above-source, "supported earlier and no longer" (`last` is set), a failed or partial read, an alert never read (`verify = "matched"` reads only what matches this machine), a curator's alert, and an alert the check cannot judge by construction (2mgd).

**One product is enough.** An alert that names a supported product beside one that was never supported earns the strike. Otherwise a key holder adds a true product to every fabricated alert and is never counted. The poster binds each product to the source's own package name (rule 1), so a real alert has no such product.

**Two alerts are two entries.** Two unsupported products of one alert are one strike. Copies of one advisory with equal content are one strike. Two threads under one advisory id whose content differs are two alerts, as the CLI already lists them: were they one, a key holder would post every fabrication under one id.

### 2. The record

`unverified.json` gains `probation`: `{"strikes": {poster key: [[time, [root event id, ...]], ...]}, "since": {poster key: time}}`, this machine's times.

The issue says the start of a probation needs its own entry because the memory of support drops a root that is no longer stored. The strikes need one too. A strike read from the memory each time needs the alert to be among the current entries and its `gone` to be in the memory. A thread leaves the entries when a relay-bot withdrawal of it applies (y484: unchecked after 72 hours at the latest), and every `gone` is dropped when the ruleset digest changes. An event once applied stays applied while it is stored, so a checkpoint that stops listing a thread does not remove it; that way out does not exist, and the two above are enough. So a strike, once found, is written down and stands for seven days whatever happens to its thread.

The step (`cli._probation_step(record, found, now)`, pure; `found` is the alerts struck now as `(poster key, roots, time)`):

- Every stored time is cut to `now`, as everywhere in this file. A strike older than seven days is dropped.
- A found alert whose time is inside the seven days takes the place of every recorded strike of the same key that shares a root with it, with its own roots and the earliest of their times. So one alert read again is one strike, and copies that have become one alert are one strike. A recorded strike that two found alerts share roots with becomes two strikes: copies whose content now differs are two alerts. Without that, a key holder posts each fabrication as a copy of a struck one, lets its root join the strike, and then changes it. A recorded strike that no found alert shares a root with stands as it is.
- The poster key is the pubkey of the stored root event; the roots of an entry signed by different keys are a strike for each key.
- Per key the two latest strikes are kept, each with at most 64 roots. Two is all the rule reads. A key holder who posts a thousand fabrications cannot grow the record, and the latest two are the ones that count when a probation runs out.
- A key with two recorded strikes and no probation younger than 30 days gets `since[key]`: the time of the later strike. It is not moved while it is that young. When it has run out and two strikes of the last seven days are recorded, a new one starts from the later of them: a key that keeps fabricating stays on probation.
- The step does not remove an entry of `since` that has run out. `_note_offers` does (section 3), in the write that starts the waits of that key's lowerings again.

A strike is not taken back when a later read finds support. Nothing a key holder can do produces that read, but neither does anything else in this design need it: the strike ends in seven days and the probation in 30, both without anyone's help, and a confirmed alert interrupts throughout.

`_note_support` computes the step beside the memory, from the memory it just computed, and saves both under the state lock from the record as it is on disk then. It returns true when either changed.

The loader (`state._load_unverified`) accepts the record without `probation` (written by 0.3.0 and earlier: read as none) and checks the new key's shape: 64-hex keys and roots, integer times, at most two strikes per key, 1 to 64 roots each, at most `MAX_UNVERIFIED_ENTRIES` keys. Anything else is damage, as for every other key of the file.

### 3. Where it bites

A key is on probation while `since[key]` is less than 30 days old by this machine's clock (`cli._on_probation`); a time ahead of the clock counts as on probation. It is read whatever the `verify` setting is now: the cap on unverified alerts already applies with the check off, and this is the same branch.

**Raises** (`cli._interrupts`, `cli._reserve`). The branch that gives an unverified alert one of the two slots of its poster key gives none to a key on probation: the alert is held. `_reserve`, which runs under the state lock before a command reports anything, reads the probation again from the record as it is then and holds every unverified alert among the pending ones whose key is on probation, with a new grant or with a slot it already held: a probation another command began meanwhile counts. Listed by `check` with its own line, in `held_critical` of `run --json`, not notified, not marked seen, no exit 2. This holds for an alert that took a slot before the probation began and is still unseen. The branch above it is untouched: an alert this machine's read confirms, freshly, interrupts on the slot of its advisory and product. So is a curator's alert, which needs no slot. When the probation ends, the held alerts take slots in the order they were held, as today.

**Lowerings and narrowings** (`cli._note_offers`). For a relay-bot lowering whose reply was signed by a key on probation, or whose thread's root was, the 72-hour wait does not run: its entry in the record is set to the current checkpoint time at every command, as for a refused thread, unless the check says `True`. It is left out of what `pull.active` may count, so it is neither applied nor shown as waiting. Only `check(...) is True`, the member's own confirmation, applies it (in `pull.standing`, unchanged). A narrowing is treated the same way. Whole reads that give no more than the lowered level, on a thread whose level is not claimed, end a refusal today and start the wait; on probation the wait does not start.

The reply's signer counts because a manifest may name more than one relay-bot key, and `pull` takes a relay-bot reply on another relay-bot key's thread: by the root alone, a key on probation would lower the other key's threads unchecked.

**When a probation ends, for lowerings.** The bar on lowerings is read from the record, not from the clock: a key bars while it has an entry in `since`. `_note_offers` removes the entries that have run out by this machine's clock, under the state lock, in the same write in which it has just set the times of that key's replies to the checkpoint it holds, and only when it holds one. Nothing else removes an entry. So the 72 hours of each such reply start at the checkpoint held by the first command after the probation ended, however long the machine was off before that command: a last command on day 26 and the next on day 31 do not make five days of wait. For raises the clock decides (`_on_probation`), so an alert is not held a command longer than the 30 days.

A lowering that had already applied unchecked before the probation began stops applying at the next command, and the thread stands at its higher level again. If that level is critical and the member has not seen it, it goes through `_interrupts` like any unverified alert of the key: held.

**When.** `_matches` brings the lowerings up to date before the memory of support, so a probation found by a command bites raises in that command and lowerings from the next. `run` computes the threads again after its source check when the record changed, so in `run` both are in the same command.

### 4. What the person sees

- `check` prints, for each key on probation: `probation: poster key <first 12 hex> is on probation on this machine until <UTC time>: its sources did not support two of its alerts within seven days. Its alerts that this machine has not verified do not notify, and its lowerings apply only when this machine's source check confirms them`.
- A held alert of such a key: `held, not notified (not verified from this machine; its poster key is on probation here): CRITICAL: <title> (id <id>)` in place of the line about two alerts in 24 hours.
- `run --json` is unchanged in shape: the alert is in `held_critical`.

### 5. A rebuilt record

`unverified.json` that cannot be read is started again (`_start_again`), and the probation goes with everything else in it: what is unreadable cannot be kept. The existing rules cover the gap in part: for 24 hours after a rebuild no unverified alert takes a slot at all, and for 48 hours nothing shows at notice and no strike is recorded. After that a key that fabricates again earns its two strikes again. The file is local, so losing it takes access to the member's machine, which is outside this design. An older CLI that reads a record with `probation` treats it as damage and starts again: going back a release costs the waits and the memory, as going back past 0z4e did.

## Alternatives considered

- **Count strikes from the memory of support each time, and record only the start** (the issue's sketch). Not taken: section 2, a withdrawal that applies, or a ruleset change, sheds a strike.
- **Join a found alert into the recorded strike it shares a root with, keeping the old roots.** The first draft. Not taken: a copy that joined a strike and was then changed stayed inside it (the design review of this spec).
- **Let the clock end the bar on lowerings.** The first draft. Not taken: the wait then counted from the last command during the probation, so a machine that was off across its end applied the lowering at once.
- **A strike only when every product of the alert was never supported.** Not taken: one true product per fabrication evades it.
- **One strike per advisory id.** Not taken: every fabrication goes under one id.
- **Take a strike back when support is read later, or end a probation early.** Not taken: more state and one more way out, for a case that ends by itself.

## What this does not cover

- An alert that is never read earns no strike. The session-start hook reads no source, so a fabrication can interrupt there, unverified and inside the cap, before the hourly run reads it and strikes it. A member with `verify = "off"`, or whose machine cannot reach the sources, records no strike at all and has only the cap of two per 24 hours.
- **Whose strike, with two relay-bot keys.** A strike, a slot and a held raise are counted against the key that signed the thread's root (`cli._poster`, as the cap on unverified interrupts already is). The manifest in force names one relay-bot key (version 4), so today the root's key is the only one. With a second key, a key on probation could still add a product to, or raise, a thread the other key started: the strike and the slot would then be the other key's. Counting them against the signer of the reply that brought the product or the level needs `pull` to keep who signed what in a thread, which it does not. Follow-up issue. The other direction was weighed and not taken: holding an alert because any reply in its thread is signed by a key on probation would let that key silence the other key's true alerts by replying to them, and a missed true critical costs more than a false one (the D8 table's own order). Lowerings do count the reply's signer (section 3), where the strict side has no such cost.
- A real key whose alerts the member's sources do not support twice in seven days (the source answers the member and the poster differently, finding D7) goes on probation on that member. The cost there: for 30 days its alerts interrupt only when confirmed, and its lowerings apply only when confirmed. Both are the safe side for a lowering; for a raise it is the rule as D14 states it.
- Brief divergence of the two copies of one unsupported critical (an update one root has not had yet) reads as two alerts, so one unsupported advisory can start a probation. Accepted for the same reason.

## Blast radius and rollback

Member CLI only. One new key in a local file, read as empty when absent. Behaviour changes only for a key with two strikes. Rollback is reverting the commit; an older CLI then rebuilds the record once (section 5). No install, signing step or release is part of this change; the release session's note goes on ai-tools-alerts#5fry.

## Open questions

None that block. Decisions taken here and posted on the issue: strikes are recorded and outlive their threads; one never-supported product is a strike; the probation's time is the later strike's; a rebuilt record loses the probation.
