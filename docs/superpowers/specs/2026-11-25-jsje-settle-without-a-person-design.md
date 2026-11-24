# The poster settles an unknown or refused send without a person (ai-tools-alerts#jsje)

## Problem

Ruling of 2026-11-23: the service runs with no human in the loop. The poster's send journal still waits for one in two places (`aitools_alerts/poster/main.py`).

- A send whose outcome is unknown (a timeout after the request began, a 5xx) stays `pending` in the ledger until someone runs `aitools-alerts-poster resolve`. `Run.busy` holds every later change to that thread meanwhile, and an unknown digest holds every later digest.
- A send the relay refused waits in the state's `withheld` list until `resolve --requeue` or `--drop`. It holds its thread, and a refused digest holds every later digest, the same way.

A raise is held like anything else. A critical thread whose feed reply was recorded and whose critical-channel reply is unknown takes no further change until a person acts.

## Success criteria

Each is a test in `tests/poster/test_settle.py`.

1. An unknown send that the mirror shows is recorded by the next run with no command.
2. An unknown send the mirror never shows is sent again by the first run 24 hours after the attempt that reads a fresh mirror.
3. A thread with a refused reply takes a raise within a bounded time: the next run when the refused reply is one a raise may supersede, three days otherwise.
4. A raise planned while a lowering of the same thread is unsent goes out, and the lowering does not.
5. Nothing is superseded or sent again while a send of that thread has an unknown outcome and neither rule 1 nor rule 2 has settled it.

## Approach

### 1. An unknown send is settled from the mirror (`Run.settle`)

Runs first in a run, before the recompute observes and the journal drains, and only when the ledger holds a pending entry whose journal item has no event id. It pulls the mirror once (the writers' pull, as the digest does, 120 seconds at most).

**Delivered.** The send is delivered when the poster's verified copy of the mirror holds an event that

- is signed by the manifest's relay-bot key,
- has exactly the journaled item's text as its content,
- carries one `h` tag, the item's channel,
- replies to the item's thread root in that channel (no thread reference for a root, a copy or the digest),
- is dated no earlier than 600 seconds before the item's first unknown attempt (one machine stamps both; the margin covers a clock step), and
- has an id that no ledger thread, digest record or other journal item already holds.

The oldest such event is the delivery. It is recorded exactly as `resolve --delivered` records it: the id goes into the journal, then `Run.deliver` finishes the item (the checkpoint debt, the ledger record, the Japanese reply). The checks `resolve --delivered` makes before writing are made here too, by one shared function; an event that would not record is not a match.

A stored event is evidence whatever the state of this run's pull: its signature was verified when it was stored, and the relay-bot key signed that text for that thread.

**Not delivered.** A pending entry at least 24 hours old with no such event is expired, as `resolve --not-delivered` expires it, when this run's pull succeeded and the channel file the event would be in says it was generated within the last hour (`generated_at`). The drain that follows sends the item again. A mirror that cannot be read, or that serves an old file, proves no absence.

**An expired attempt is remembered.** Before the pending entry is expired, the journal item gets `tried`, the time of its first unknown attempt. Three things read it:

- the match above: the first attempt's event stays the item's delivery after the item was sent again, whatever the second send's outcome, so a late event stops a third copy. An unsent item with `tried` and no pending entry (its second send certainly failed) is checked against the mirror each run;
- `drop_unsent_lowerings`: a lowering with `tried` is one a channel may have, so it is sent again and never dropped. Dropped, a channel that did get it would stand lower than the ledger says for good;
- rule 3: a source-only reply with `tried` is not superseded.

**No mirror for 72 hours.** A pending entry 72 hours old is expired whatever the mirror says. The alternative is a thread, or the digest, that waits for a person; the cost is one possible duplicate post. 72 hours is the time after which the checkpoint signer gives up a post the mirror never showed (`signer.OWED_S`).

**No journal item.** A pending entry whose key is in the withheld list (a run that stopped between withholding and clearing the mark) is cleared at once, as `resolve` clears it. One with no item anywhere is expired at 24 hours: there is nothing to send again.

A Japanese reply is settled by the same rules. Its pending entry holds no advisory, so it never blocked English work; settled, it stops counting as busy every run.

### 2. A refused item leaves `withheld` after three days (`Run.expire_withheld`)

A withheld root (with its copies), copy or digest whose refusal is three days old (`WITHHELD_SECONDS`) is removed, with any pending mark its items left. Nothing then holds its advisory:

- a candidate's item: the candidate was deferred every run while the thread was busy, so the next `one()` plans it anew from its sources;
- a digest: today's digest is built anew.

A reply is not dropped at three days. Another channel may have taken the same change; the ledger then records it, nothing would plan it again, and the channel that refused it would lack it for good. Whether another channel has it cannot be read from the ledger once a later reply was recorded, so every reply is treated alike: it goes back to the journal marked `retried` and is sent once more as it is. Refused again, it is dropped and counted; the poster cannot make the relay take it. The mark is on the journal item, on disk: a restart or a failed send does not forget it, and a later reply under the same key does not inherit it. A lowering no channel has is still removed by `drop_unsent_lowerings` before it is sent on old evidence.

The run says so on stderr, counts it in a `settled=` field of the summary line, and adds one to a new state key `dropped`. The next digest adds `dropped` to its "withheld by the publication check" count, and prints that line on a quiet day too; recording that digest subtracts the number it carried. If the relay refuses the same text again, the item is withheld again and waits another three days: one attempt every three days, never a loop inside a run.

Three days, not one: a second refusal in a run stops the run, so every retry of a text the relay will always refuse costs the hour's other work a delay. Three days bounds that to one run in 72.

### 3. A raise supersedes lower-priority work on its own thread (`Run.yields`)

When a raise of a thread is about to be planned and the thread is busy, the raise is planned anyway if all the work in its way may be superseded. That work stays in the journal, or withheld, until the raise is journaled: one save removes it and adds the raise (`Run.enqueue`). Until then the drain passes over it. A run that stops in between has lost nothing, and the next run sends or supersedes the work on what it reads then.

**May be superseded:** a reply of that thread, in the journal or withheld, that the relay has not acknowledged, judged by the block it carries on the wire:

- a level below the raise's and nothing else (a lowering). Whichever channels have it: the raise is a level reply in every channel of the thread, so it states the level last in each;
- ids, sources and a severity word and nothing else, when no channel can have it: it has no `tried` and no `retried`, and the thread's advisory lacks at least one id or source it lists (those lists only grow, so a later reply cannot hide that another channel recorded it). Its candidate was deferred and brings the same ids and sources again.

**May not:** anything while a send under any of the thread's ids is pending (outcome unknown); an item the relay acknowledged; a root or a copy; a reply that carries a fix, a range, an action or a level at or above the raise's; a source-only reply another channel has or may have. The raise then waits as before, for rule 1, rule 2 or the next drain.

Where it runs:

- The recompute (`Run._judge`, before the drain and again after planning): a busy thread whose KEV reading is a raise (`recompute.raised`, a read-only form of `judge`'s first test) supersedes.
- Candidates, twice: before the drain (`Run.make_way`, over the merged candidates), so an unsent lowering is not sent only to be raised in the same run; and in `Run.one`, for work that became withheld during the run. The level is the one `one` and `plan_known` give the candidate, computed by the two helpers they now share (`_rate`, `_thread_level`); a candidate that would not raise supersedes nothing.

A superseded lowering that one channel already has leaves the channels at different levels until the raise lands, which is the next thing sent: the raise is a level-only reply in every channel of the thread.

## What is not changed

- `pending` and `resolve` stay. Nothing needs them; an operator who is watching can still settle a send sooner.
- `drop_unsent_lowerings`, the 24-hour floor in `Ledger.expire_pending`, the "second refusal stops the run" rule.
- The other direction, events under the poster's key that its ledger did not send, is ai-tools-alerts#m729. A send expired by rule 1 whose event appears on the mirror later is such an event.

## Alternatives considered

- **Query the relay for the event id.** The poster does not keep the id of an unknown send (the signature is made inside the transport), and the relay has no read route the poster holds a key for. The mirror is the copy members read; "on the mirror" is the fact that matters.
- **Expire on any successful pull at 24 hours, without the `generated_at` test.** An exporter stopped for a day would turn every unknown send into a duplicate. The field is unsigned, so a hostile mirror can still claim freshness and withhold the event; what it gains is one duplicate post per unknown send, which it could also cause by serving nothing for 72 hours.
- **Never expire without the mirror.** Then a mirror outage is a wait for a person.
- **Requeue a refused item instead of dropping it.** It would send the same text. Dropping lets the advisory be composed again from what its sources say now.
- **Let a raise supersede any unsent reply.** A reply with a fix, sent on one channel and dropped on the other, would leave that channel without the fix for good: the ledger already holds it, so nothing plans it again.
- **Supersede an unknown send.** The issue excludes it, and a raise composed on a level the thread may or may not have is the fault this journal exists to prevent.

## Blast radius and rollback

Poster only: no wire format, reader, schema or spec file changes. The poster state gains `dropped` (an integer; a state from before starts at 0), a digest item's snapshot may carry `dropped`, and a journal item may carry `tried` and `retried`. The previous version refuses a state with any of them. To roll back: stop the poster's timer; rewrite the state file (the config's `state`) in place with `jq 'del(.dropped) | (.outbox[], .withheld[].items[]) |= (del(.tried, .retried) | if .kind == "digest" then del(.adv.dropped) else . end)' state.json > state.json.new && mv state.json.new state.json`; start the timer. A test drives a state to hold `dropped`, the snapshot's `dropped` and `tried` and checks that they are the only keys the version before does not know, and that the CHANGELOG line names each; the `jq` line itself was run by hand on such a state (run record). The summary line gains ` settled=…` only in a run that settled something.

When the poster sends twice, after this change: an unknown send that did post, whose event the mirror did not show within 24 hours while claiming to be fresh, or within 72 hours at all. Before, only after a person said "not delivered".

## Known limits

- A reply that one channel took and another refused twice, three days apart, is lost to the second channel. It is counted in the digest.
- A raise waits behind a refused reply that carries a fix for up to three days, and behind a send whose outcome is unknown for up to 72 hours.
- A send repeated at 24 hours whose first event reaches the mirror later is a duplicate post; the late event is then recorded as the delivery only if the repeat is still unsettled.
- A dropped refused digest loses the "Lowered since the last digest" line it carried (cleared when it was journaled).
- A post recorded by rule 1 takes this run's time as its ledger time, as `resolve --delivered` does.

## Review dispositions (spec and plan, one independent pass, gpt-6-astra)

Two findings rated critical and four major. Nothing was built when it ran; the two critical ones are read as blockers of the design and fixed in it.

- **Fixed (critical): an unknown lowering, once expired, was dropped by `drop_unsent_lowerings`.** A channel that did get it would then stand lower than the ledger for good. The item now carries `tried` and is sent again. Test: `test_an_unknown_lowering_that_expired_is_sent_again_not_dropped`.
- **Fixed in part, rebutted in part (critical): dropping a refused reply another channel accepted loses the change in the refusing channel.** Such a reply is no longer dropped at three days: it is sent once more. What remains is a text the relay refuses twice for that channel, three days apart, after taking it in the other. The poster has no way to deliver that; keeping it queued for good would hold the thread, and every raise of it, for a person. It is dropped and counted in the digest.
- **Fixed (major): the supersession rule compared advisories, so a fix reply another channel had recorded looked like a level-only copy.** The rule now reads the reply's own block. Tests: `test_a_raise_does_not_supersede_a_fix_reply_another_channel_has`, `test_a_source_only_reply_is_superseded_only_when_no_channel_can_have_it`.
- **Fixed (major): a repeat moved the match floor past the first attempt's event.** The floor is the item's first unknown attempt (`tried`). Tests: the two `test_a_delivery_that_shows_after_…`.
- **Fixed (major): the rollback line printed JSON and changed no file.** It now names the file, the stop of the timer and the replace. A test checks that the three keys it removes are the only ones the version before does not know.
- **Rebutted (major): the snapshot commit's message.** The reviewed commit is a dangling review snapshot made with `git commit-tree`; it is on no branch and is never pushed.

## Review dispositions (whole branch, one independent pass at e63d990, gpt-6-astra, and one same-model pass)

The independent pass rated three findings critical and three major. All six are fixed; the run climbed from medium to heavy on them, so one delta pass follows.

- **Fixed (critical): supersession removed the queued work before its replacement was journaled.** A run that stopped between the two, followed by a read that no longer raised, left one channel without the lowering for good. `yields` now removes nothing; `enqueue` removes the work in the save that journals the raise. Test: `test_superseded_work_stays_journaled_until_the_raise_is`.
- **Fixed (critical): "another channel has it" was read from advisory equality, which a later recorded reply breaks.** Every refused reply is now sent once more before any drop, and the source-only test in `yields` reads the lists, which only grow. Test: `test_a_refused_reply_is_sent_once_more_whatever_the_thread_recorded_since`.
- **Fixed (critical): the retry mark was a key kept in memory, and reply keys repeat.** It is now `retried` on the item. Test: `test_the_retry_mark_is_the_items_and_outlives_a_failed_send`, which also covers the major finding that the mark did not survive a restart or a failed send.
- **Fixed (major): a repeat the relay refused ended settlement of the first attempt.** `settle` matches withheld items that carry `tried`. Test: `test_a_refused_repeat_is_still_settled_by_the_first_attempts_event`.
- **Fixed (major): a pull that timed out discarded the stored events.** Test: `test_a_pull_that_times_out_keeps_what_an_earlier_pull_stored`.

## Open questions

None that block. The three constants (24 hours with a mirror generated in the last hour, 72 hours without, three days withheld) are the decisions a reviewer may want to move.
