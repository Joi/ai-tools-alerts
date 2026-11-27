# A channel that lacks the thread's standing level reply is sent it again (ai-tools-alerts#aqtf)

## Problem

A critical thread has a root in two channels, `critical` and `feed`, and every level reply is sent to each. The journal gives up a reply a channel refused twice, three days apart (`Run._withhold`, `Run.expire_withheld`, ai-tools-alerts#jsje). The ledger keeps one level for the thread, recorded when the first channel acknowledges the reply. After the journal gives up, nothing knows the other channel lacks it:

- a raise the channel never took leaves that channel low for good. This is the one case where a reader shows less than the poster holds;
- a lowering it never took leaves it high for good;
- a withdrawal it never took leaves the alert shown there for good (kk2q case 1);
- ai-tools-alerts#kk2q keeps the withdrawn state by channel (`Entry.withdrawn`) and sends the reply that ends it again, but treats a thread withdrawn in one channel only as withdrawn in all: no renewal, no copy, no new wait if the source withdraws again (kk2q case 2).

Standing ruling (Joi, 2026-11-23): the service runs with no human in the loop.

## Success criteria

Each is a test in `scripts/test-gate.sh`.

1. A raise refused twice in one channel is sent to that channel again, and recorded when the relay takes it.
2. The same for a lowering.
3. The same for a withdrawal.
4. The same for the reply that ends a withdrawal (kk2q's test, kept).
5. No level reply is sent again to a channel the ledger records as having it: once every channel holds the standing reply, later runs send nothing. A send whose outcome is unknown is settled as every send is (jsje, m729); this change adds no rule there.
6. Raises first, within what a run newly plans: a channel that shows less than the thread's standing is sent its reply before the run's lowerings and before a channel that shows more. The journal still drains first, as for every send.
7. Nothing is sent on top of work in flight, and a channel is tried again no sooner than the journal's own pace (refused, three days withheld, sent once more, given up, planned anew by the next run).
8. A thread withdrawn in one channel only, whose standing reply names a level, is renewed, judged and copied like any thread at that level.
9. A ledger written before this change loads and behaves as it did under kk2q.
10. A journal that holds a reply the reconciliation planned loads after a restart, in `outbox` and in `withheld`, and the reply is recorded as one sent again.

## Approach

### What the ledger records

Three optional fields on a thread's entry, all absent in the ordinary case.

The thread's **standing reply** is the last level reply the ledger recorded for the thread, from whichever channel acknowledged it first: the withdrawal, or a reply naming `level`.

`lacks`: `{channel: word}`. The channels that have not acknowledged the standing reply, each with the word that channel stands at: a level, or `withdrawn`. The word may be the standing reply's own level, held from an older event: possession is of the reply, because its date is what a reader counts the level from (a channel left at an older notice would lose the thread before the poster's own count says so). Absent when every channel holds the standing reply.

The standing word is `withdrawn` when some channel named in `withdrawn` is not in `lacks`, else the thread's `level`. `Entry.gone` says the first; `Entry.standing` gives the word; `Entry.word(channel)` gives a channel's own word (`withdrawn` when `withdrawn` names it, else `lacks[channel]`, else `copied[channel]`, else `level`); `Entry.lacking` is the map of lacking channels.

`record_reply` keeps it. For a reply whose block names a level or is the withdrawal, acknowledged in channel X with word W:

- W is not the standing word: this is a new standing reply. Every other channel lacks it, with two exceptions: under a withdrawal, a channel already withdrawn (a withdrawal renews nothing, so a second one says nothing); and a channel whose root states W (`copied`, below).
- W is the standing word: the standing reply has reached X. X leaves `lacks`; the other channels stay as they were.
- X's word becomes W; `level` is set as today; `withdrawn` is the sorted list of channels whose word is `withdrawn` (what kk2q wrote); `lacks` is removed when empty; `copied` is removed.

So the first channel's acknowledgement of a new level reply names the other channel in `lacks`, and the second channel's acknowledgement, minutes later in the same run, removes it. A run that ends with every send acknowledged leaves no `lacks`. Every planner of a level change sends it to every channel of the thread (`plan_known`, the recompute, the step down), so nothing else is needed to clear it.

`copied`: `{channel: level}`. `Run.plan_known` journals a raise to critical as a root in the critical channel first, then the reply in the feed. That root states critical while the ledger still says high. `add_channel` takes the level the root's block states (`Run._record` passes it) and, when it is not the thread's level, keeps it here. The feed's reply then finds the critical channel has the level and does not name it in `lacks`. The next level reply recorded removes the key. If the feed's reply is never delivered the key stays, the ledger's level stays high, and nothing is sent because of it: the next raise goes to every channel, as today.

`add_channel` for a thread whose standing reply is the withdrawal (a copy journaled before the withdrawal; `copies` plans none after it) names the new channel in `lacks` at the level its root states.

Entering the state is counted as a level change (`changed`, `lowered`, the digest's list, the breaker) when the thread's standing word was not `withdrawn` before, in place of "when no channel was withdrawn".

`uneven`: `true` once a reply sent by the reconciliation is recorded for the thread; never removed. `Run._stated` then lets a claim name the thread's first id only. Reason: the reply the channel lost may have carried aliases with the level (a raise that shares a reply); the reply sent again names the level alone, so the channel has as many replies as the other and still lacks those aliases.

### A ledger written before

No `lacks`, no `copied`, no `uneven`. With no `withdrawn` either, every channel holds the standing reply: nothing to send. With `withdrawn` naming every channel the thread is withdrawn. With `withdrawn` naming some channels only and no `lacks`, the entry was written by kk2q, which did not say which side is standing; it reads as kk2q's recompute acted on it: the standing reply names `level` and the channels in `withdrawn` lack it. That errs toward showing the alert.

The validator (`_entry_ok`) accepts `lacks` only as a non-empty map of some, not all, of the thread's channels to a level or `withdrawn`, each value `withdrawn` exactly when `withdrawn` names the channel, and never a withdrawn channel under a standing withdrawal; `copied` only as a non-empty map of the thread's channels to levels; and `uneven` only as `true`.

### What a run sends

`Run.reconcile(up)`: for every thread, oldest first, with `lacking` non-empty, that is not synthetic and has no work in flight (`busy`: the journal, the withheld list, a pending send), one level reply for each lacking channel, through the journal like every level reply (key `reply:<scope>:<id>#level:<channel>`):

- the standing word is `withdrawn`: `compose.withdrawal_post()`;
- else `compose.level_post` naming `level`.

The journal item carries `again: true`, a field of the item on disk: `inputs._item_ok` accepts it on a reply and nowhere else. A restart, a failed send, the withheld list and the reply sent once more all keep it, and `Run._record` passes it to `record_reply`, which sets `uneven`.

`up=True` takes the channels that show less than the standing word (a lower level, or `withdrawn` under a standing level); `up=False` the rest (a higher level, the same level from an older event, a level under a standing withdrawal). `Run.recompute` calls it twice: after its own raises and before its lowerings (`up=True`), then after the lowerings and before `copies` (`up=False`). A failed or unknown send stops a run, so the order decides what a bad hour still delivers.

The journal drains before any of this, as it does before every newly planned send, a new critical root included. A lowering already in the journal that another channel took therefore still goes before a reply the reconciliation plans. The reconciliation is not moved ahead of the drain: a send that fails stops the run for everything behind it, and a raise missed three days ago must not stand in front of today's new alerts.

Not sent:

- to a thread a reply of which the relay refused in this run (`Run._withhold` notes the root). Without this, the run in which the journal gives up the reply sent once more would plan it anew at once, and a second refusal in one run stops the run. The next run plans it. The pace is then the journal's: refused, withheld three days, sent once more, refused, given up, planned by the next run.
- a reply naming a level to a thread whose withdrawal this run recorded in some channel (`Run.withdrew`; kk2q's rule that the two never carry the same second).
- to a thread this run is about to lower (code review): the lowering goes to every channel and is the standing reply from then on, and a raise sent again before it could carry the same second. For the same reason the step down (`Run._renew`) leaves a thread the reconciliation sent a reply for to the next run.

A refusal of a reply sent again does not count toward the two refusals that stop a run (`Run.deliver`): a channel that refuses for good would otherwise stop a run for each two of its threads every three days, and holding the reconciliation back after one refusal would let old failures keep a later thread untried (code review, delta).

The claim tag: of this run's reading for the thread (`_claim`, over the thread's first id) and, for a level, the thread's standing claim checked now (`_checked`), the first whose level is the standing word's (`none` for the withdrawal). None when neither is: the reply then goes without a claim, as a level change no reading states does today.

A reply sent again changes no `level`, so it adds no time to `changed` (the ledger's estimate of the thread's life on readers stays the lower one), no line to the digest and nothing to the breaker.

An unknown outcome is settled as for every send: by the mirror, by id when the poster has a checkpoint key (m729), and sent again after one to three days when no copy shows it. That can put a second copy of a reply in a channel whose first copy the mirror never showed. It is jsje's rule for every send and is not changed here; a durable send identity is its own piece of work.

### The state is the standing reply's

Every place that asked "is any channel withdrawn" (`entry.withdrawn`) to decide what the thread is now asks `entry.gone`: `Run._clears`, `Run.plan_known` (two places), `Run.drop_unsent_lowerings`, `Run._record`, `Run.copies`, `Run._renew`, `Run.level_changes`, `Run.digest`, `catalog.snapshot`, `recompute.raised`, `recompute.judge`. So:

- a thread whose standing reply is the withdrawal, with one channel that never took it, is withdrawn everywhere it was before, and that channel is sent the withdrawal;
- a thread that left the state in one channel, with the other still withdrawn, is a thread at its level: renewed, stepped down, copied, listed, judged, and due a new wait if the source withdraws again. The channel still withdrawn is sent the level reply by `reconcile`. kk2q's special case in `Run.recompute` (send the ledger's level to the channels still listed when a verdict arrives) goes: the verdict is no longer needed.

In `Run.recompute`:

- a withdrawal goes to the channels whose word is not `withdrawn`;
- a withdrawn thread that leaves the state is sent the level reply in every channel. kk2q's rule stays in part: when some channel never took the withdrawal, a return to the ledger's level or below names the ledger's level; a fall from it is a lowering's. kk2q sent that reply to the withdrawn channels only; now the channel that stood at the level gets it too, for its date;
- a raise or a lowering of a thread that is not withdrawn goes to every channel, as today.

### The checkpoint

`Run.renew` already keeps out of the checkpoint the root of a channel with an unsent level reply in the journal or the withheld list. It now also keeps out the root of every lacking channel of a claimed thread, in flight or not: the ledger's life for the thread counts a reply that channel does not have. That includes a channel that lacks the withdrawal, as it already does while the withdrawal waits in the journal or the withheld list; unlisted, a reader keeps the thread at the level its events give, which shows the alert.

## Alternatives considered

- **A map of every channel's last level word on every entry.** Simpler to state, but it would be written to every thread, and an older poster refuses a ledger with a key it does not know: no going back after one run. `lacks` is absent after any run whose sends were all acknowledged.
- **Keep the refused reply in the journal for good.** The journal holds a thread busy while it holds an item of it, and the item's text and snapshot age (jsje gave it up for that reason). The ledger is the durable record; the reply is composed anew from it.
- **Send the standing reply to every channel each time.** Breaks criterion 5 and would renew, on the channel that has it, a level the sources may no longer confirm.
- **Skip a channel already at the new level when a thread is raised or lowered.** The ledger counts the level's life from that reply's date in every channel; the channel skipped would decay sooner than the ledger believes.
- **Track the word alone, so that a channel already at the new level lacks nothing.** Same reason: a channel left at an older notice when the thread is lowered to notice would lose the thread before the poster's count says so (spec review, finding 1).
- **Send the reply before the copy in `plan_known`,** so that no root is ever ahead of the ledger. It would change which channel a raise to critical reaches first; `copied` costs one transient key instead.
- **Reconcile before the journal drains.** See "What a run sends".

## Blast radius and rollback

Poster only: `ledger.py`, `main.py`, `inputs.py` (the journal item's `again`), `recompute.py`, `catalog.py`, tests, `spec/wire.md` (the "By channel" paragraph), `CHANGELOG.md`. No wire format, schema, manifest, ruleset, scope file or CLI change. The replies sent are the ones the poster already sends (`level_post`, `withdrawal_post`).

Going back: an older poster refuses a ledger entry that holds `lacks`, `copied` or `uneven`, and a journal whose item holds `again` (in `outbox` or `withheld`). Revert only while none of them is on disk and kk2q's own conditions hold; otherwise go forward. `lacks` and `again` go away when the channel takes the reply and `copied` with the next level reply; `uneven` does not, so after the first reply sent again the way back needs that key removed by hand.

No rollout in this task: no install, signing step or release. A note for the release session goes on ai-tools-alerts#5fry.

## Tests

`tests/poster/test_reconcile.py`, with the fake relay, hourly runs:

- the ledger: `record_reply` names the other channel in `lacks` and clears it; a lowering to the level a lagging channel already stands at still names it; a second withdrawal does not name a withdrawn channel; the properties for each stored shape, the kk2q shapes included; the validator's refusals;
- a candidate's raise to critical (copy first, then the reply): no `lacks`, no `copied` after the run, and nothing sent by later runs; with the feed's reply refused for good, nothing is sent to the critical channel;
- criterion 10: a state file with an `again` item in `outbox` and in `withheld` loads; an `again` on a root is refused; a run that stops between the acknowledgement and the ledger record finishes it with `uneven` set;
- criteria 1 to 4 end to end (the raise through four days of refusals; the others from a ledger edited to the state the journal leaves, then runs);
- criterion 5: runs after the channel took it send nothing;
- criterion 6: two threads, one lacking a raise and one a lowering, one run, the order of the sends;
- criterion 7: a thread with a journaled or withheld item is sent nothing more; the run that gives up plans nothing for that thread and does not stop;
- criterion 8: the thread that left the state in one channel is renewed and gets a wait for a new withdrawal;
- the claim: the withdrawal sent again carries the withdrawn reading's claim; a level sent again carries a claim of that level or none;
- `uneven`: after a reply sent again, a claim names the first id only;
- the checkpoint: the lacking channel's root is in `unrenewed`.

kk2q's tests in `tests/poster/test_withdrawn_state.py` stay; the two that set up a partly withdrawn thread are the old-ledger case. One expectation changes: when a thread leaves the state and one channel never took the withdrawal, that channel is now sent the level reply too.

## Open questions

None that waits for a person.

- Not covered: a reply with no level that one channel refused twice (a fix, a range). The channel lacks it for good, as today. The issue is about level replies.
- A channel whose relay refuses for good is sent its reply about twice in three days, and each given-up reply is counted in the next digest (`dropped`), as jsje built it.
