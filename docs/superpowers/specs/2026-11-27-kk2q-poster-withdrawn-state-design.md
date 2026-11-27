# The poster reaches, sends and leaves the withdrawn state (ai-tools-alerts#kk2q)

Findings D4 and D13 of the design review on ai-tools-alerts#h29n. ai-tools-alerts#y484 built the member's half: the wire rule (`spec/wire.md` "A withdrawal"), the reader, the member's source check of it, and the released-reader test. This is the poster's half.

Prior work read: ai-tools-alerts#y484 (close-out and its note on this issue), #3qyq (advisory readers; a withdrawn reviewed advisory lowers to notice), #ny5g (lowering rules), #hh5s (claims), #gtw9 (root claims, renewals, step-down, `signer.lapsed`; landed, unreleased), #3t4p (`Run.copies`), #jsje (`yields`). `kata search "withdrawn state poster recompute"` finds no other issue for this half.

## Problem

The poster reads a withdrawal (`withdrawn_at`, `withdrawn`) as support at level `none` and then lowers the thread to notice, or to its prose floor, and no further. A withdrawn advisory stays shown at notice for good. The reader already hides a thread whose relay-bot reply is exactly `{"level":"withdrawn"}` when the member's own source check confirms it, and nothing sends that reply.

## Success criteria

1. A thread whose every counted advisory reading states the withdrawal, in whole reads held 24 hours, with seven quiet days and through the circuit breaker, gets one reply in each of its channels whose block is exactly `{"level":"withdrawn"}`, with the claim of the withdrawn reading (level `none`). The ledger marks the thread withdrawn.
2. The same advisory published again gets, in the run that reads it, a level-only reply in the same thread naming the level its fields support, also when that level equals the level the ledger kept. On the current reader that reply ends the withdrawal (`Thread.offered` is no longer `withdrawn`): a level at or above the thread's widest stands at once; a lower one is a published lowering like any other, applied by the member's check or after 72 hours. The run that sent a thread's withdrawal sends no such reply for it; the next run does (decision "Order on the wire").
3. A withdrawn unreviewed advisory (a class that cannot lower) moves nothing and never reaches `withdrawn`.
4. An advisory that toggles withdrawn hourly produces no reply in a week. One that toggles every two days produces at most three replies in any seven days.
5. Every released reader still shows the alert when fed the events the poster itself composes: v0.1.4 to v0.2.1, which `tests/test_wire_compat.py` lists today, and v0.3.0, which this change adds to its list (it reads the withdrawal as the current tree does and hides nothing unchecked).
6. A withdrawn thread gets no copy, is not listed by the digest, is not renewed or stepped down, and no candidate changes its level in a reply that carries anything else.
7. A thread with a prose floor above notice, a thread a KEV entry lists, and a thread with any counted advisory reading that does not state the withdrawal are lowered to the floor as today and never reach `withdrawn`.
8. Nothing waits for a person.

## Decisions

**One reply, from any level (decided; y484's note 3 left it here).** The withdrawal is sent alone from the level the thread stands at. Rejected: sending `{"level":"notice"}` first so that readers 0.1.8 to 0.2.1 show notice. `verify.claimed` asks every level the thread stated to carry a claim whose fields give at least that level; a notice reply that rests on a withdrawn reading carries a claim of level `none`, so that thread's withdrawal could never be confirmed on any member and the state would never hide anything. The cost is the one `spec/wire.md` already states: readers 0.1.4 to 0.2.1 keep the alert at its level. Where today's poster lowered such a thread to notice for readers 0.1.8 to 0.2.1, it now leaves them at the higher level. Too high is the safe side, and `min_cli` exists to tell them.

**The ledger keeps the level and adds the state, by channel.** `Entry.withdrawn` is the list of the thread's channels whose last level reply is the withdrawal, or absent; the thread is withdrawn while it names any channel. `Entry.level` and the stored advisory are unchanged by a withdrawal: the level the thread stood at is what released readers still show and what `signer` reads from the events. The first channel to take the withdrawal appends to `changed` and sets `lowered`. A reply whose block names a level, whoever planned it, takes its channel off the list, as it ends the state on a reader of that channel, and appends to `changed` once a run.

**A channel that missed the reply that ends the state gets it (review finding 1).** The journal gives up a reply a channel refused twice, three days apart (`_withhold`, jsje), whatever another channel took. Kept by channel, the state outlives that: while any channel is on the list the recompute keeps reaching the verdict that leaves it, and sends the reply to the channels still listed. When only some channels are listed and the level read is not above the ledger's, those channels are sent the ledger's level, so every channel ends at one level and any fall from there goes by the rules of a lowering. A channel that missed the withdrawal itself is not repaired: it shows the alert, the higher side, as a channel that missed any other lowering does today.

**Order on the wire (review finding 2).** A reader orders a thread's replies by `(created_at, id)` and the transport dates an event by the second. A withdrawal the journal replays and a reply that ends it, sent in one run, could carry the same second and read in either order. So the recompute sends no reply that ends the state in the run that recorded the thread's withdrawal in any channel; the next hourly run does. The other order cannot share a run: entering needs seven quiet days after the reply that left.

**Leaving is a raise.** While the flag is set the recompute reads the thread's level as `none`. It leaves the state in the run that reads the cause, with no wait, quiet week or breaker, because every way out raises what current readers show:
- a read supports a level: a level-only reply naming `highest(that level as the thread can carry it, floor, notice)`;
- the prose floor is above notice (a candidate taught it since): a reply naming the floor;
- every source was read whole, none supports the product and no counted reading states the withdrawal (the advisory was published again without naming the product): a reply naming notice.
A read that is unknown changes nothing.

The third way out states notice with no reading that gives notice, so its reply carries a claim of level `none` or none at all. `verify.claimed` then never again confirms a withdrawal of that thread on a member: if the advisory later names the product, is raised and is withdrawn once more, members read that withdrawal as a lowering to notice after 72 hours and it hides nothing (review finding 3; y484's note 4 said as much of any level change without a claim). The issue asks for this exit, no claim can be honest about a level no source states, and the result errs high. It is stated in `spec/wire.md`.

**No renewal, no step-down, and the checkpoint keeps listing it (y484's note 6).** A withdrawal reply names no level, so readers decay a claimed thread as before. The poster sends a withdrawn thread no renewal and no step: a step is a reply that names a level and would end the withdrawal on every reader. `signer.lapsed` would then leave the root out of the checkpoint once the kept level's life ran out, which stops the decay and drops the member's 72-hour record of the reply (`pull.offers` needs the root listed), returning the alert to its full level on a member that cannot confirm. So `lapsed` does not count a thread whose standing offer is the withdrawal: like a thread at notice, it is listed and leaves readers, and that is the decay the poster intends. A reply that names a level is a renewal of its own date, so a thread that leaves the state stands again.

This covers the passing of time only. The fault paths that already unlist an event are unchanged (review finding 4): a withdrawal reply the mirror stops serving is given up after 72 hours like any reply (`settle_gone`, `settle_owed`), and a thread that does not fit a checkpoint whole may lose it (`window`). A member then loses its record of the reply and shows the alert at its level again, as it does when a lowering's reply goes missing. Both fail high, which is what those paths are built to do; the withdrawal is not made a must-list event.

**A candidate changes no level of a withdrawn thread in `plan_known`.** Its other changes (a fix, a range) still reply, without a level. What it teaches (the floor, a KEV mark the recompute's own copy shows) reaches the recompute, which sends the level alone. A floor learned from a candidate after the thread was judged that run leaves the state in the next hourly run.

## Approach

`recompute`
- `withdrawal(counted)`: at least one counted advisory reading, and each states `withdrawn_at` or `withdrawn`.
- `judge`, thread not withdrawn: after `found`, `floor` and `level` are known, the target is `wire.WITHDRAWN` when `found` is `none`, the floor is notice, `listed` is empty and `withdrawal(counted)`. A target of `withdrawn` is below every level, so a thread at notice waits for it too. The wait record's `level` may be `withdrawn`; a change of target starts the wait over. The verdict is `("due", "withdrawn")`. Every existing condition of a lowering applies unchanged (whole reads, the KEV rules, `DWELL`).
- `judge` and `raised`, thread withdrawn: the leaving rules above, `("raise", level)`. `raised` uses only the first two (it has no `known` it may trust).
- State: `dwell[*].level` and `lowered[*][1]` accept `withdrawn`.

`ledger`
- `Entry.withdrawn` (a non-empty list of channel names, or absent); `record_reply(..., withdrawn=None)`: `True` adds the reply's channel (the first one counts the change), `False` removes it and counts a change even at an equal level, once for one time stamp.

`compose`
- `withdrawal_post()`: one fixed line and the block. `level_post(prev, level, reason, again=False)`: `again` allows the thread's own level, for leaving.
- `level_report`: an id whose state is `withdrawn` is printed as withdrawn, in both languages.

`main`
- `Run._patch(it)`: a reply item's block. `_record`: a withdrawal records the thread's current advisory with `withdrawn=True`, adds `[id, "withdrawn"]` to the digest's list and to the breaker's count once; any reply whose block names a level passes `withdrawn=False`.
- `_withdrawal_items`, beside `_level_items` (same key, `<id>#level`, so the journal's rules for a level reply hold for it). `recompute` sends it for a due `withdrawn`; for a withdrawn thread it sends the level reply with `again`, to the listed channels only when the list is partial and the level is not above the ledger's, and not at all in the run that recorded the thread's withdrawal.
- `drop_unsent_lowerings`: an unsent withdrawal no channel has is dropped while the ledger does not mark the thread withdrawn.
- `yields`: an unsent withdrawal is below every raise.
- `copies`, the digest's root list, `_renew`, `plan_known` (level and copies) skip a withdrawn thread.

`catalog` (plan review finding 3): `snapshot` gives `{key: None}` for a withdrawn thread and `remember` takes the key out of the inventory, so the catalog lane posts no root of it at the kept level, neither one that waited unsent nor one a fix changed. It is catalogued anew when it leaves the state.

`signer.lapsed`: as decided above.

`spec/wire.md`, `CHANGELOG.md`, the module docstrings: say what is sent.

## Tests

Existing tests that state today's behaviour change: `test_a_withdrawn_reviewed_advisory_lowers_to_notice_and_stays` and `test_a_malware_advisory_withdrawn_and_published_again_returns_to_critical` in `tests/poster/test_advisory_recompute.py`.

- `recompute`: the verdict and its wait from high and from notice; each condition that keeps a thread out of the state (floor, a class that cannot lower, a counted reading that does not state it, a KEV listing, an unknown read); the three ways out and the unknown read; the state file's new words.
- `ledger`: the list by channel, the counting of `changed`, a malformed value refused.
- `compose`: the withdrawal's text parses to no advisory and no reply patch; `again`; the digest line in both languages.
- Through `main.run`, hour by hour with the fake relay, KEV and advisory API: enter after 24 hours with the claim of level `none`; publish again and leave at the kept level; the critical thread in two channels; the silent exit to notice; the unreviewed advisory; both toggle bounds; the floor case; no copy, no renewal, no step, no digest listing; a candidate that changes no level; a channel whose send failed gets the withdrawal next run; an unsent withdrawal dropped when the advisory returns first; a raise that passes an unsent withdrawal; a reply that ends the state refused for good in one channel and sent to it again; no reply that ends the state in the run that recorded the withdrawal.
- `signer.lapsed`: a claimed root whose renewals ran out, with and without the withdrawal, and after a later level reply.
- `tests/test_wire_compat.py`: the withdrawal and the reply that ends it as `compose` writes them, with the claim `rules.claim_text` builds, on every released tag, v0.3.0 added, on a root with a claim and on one without; this reader's `Thread.offered` after each.

## Alternatives considered

- **Set the ledger level to notice on entering.** Fewer guards in `main`, but the ledger would then disagree with the events: `signer` and released readers hold the kept level, and `_life` would compute renewals for a level no reader shows. Rejected.
- **A journal item key for the state.** `inputs._item_ok` refuses unknown keys, and the block already says it. The item is recognised by its block.
- **Leaving held 24 hours.** It would keep a republished advisory hidden for a day. Acceptance asks for the same run, and the toggle bounds hold without it because entering needs the quiet week.

## Blast radius and rollback

Poster only; no schema, manifest, ruleset or scope file changes, and no new wire form (y484 defined it). The member CLI is untouched. Once a thread is withdrawn the ledger entry holds `withdrawn`, and the recompute state may hold `withdrawn` as a wait's or a reported lowering's level: an older poster refuses that ledger (as it does `claim` since gtw9) and replaces that recompute state with an empty one. Before any thread is withdrawn, revert the merge. After, roll forward, or remove the key from the entry by hand: the thread then stands at its kept level in the ledger while readers hold the withdrawal until a reply names a level.

Readers 0.1.8 to 0.2.1 lose the lowering to notice they got for a withdrawn reviewed advisory (decision 1).

## Assumes

- Released v0.3.0 reads the withdrawal as the current tree does (y484 is in it).
- The wall clock and review shape of the run manifest.

## Open questions

None that block. Not built here: a renewal rule for a thread that returns from the state long after its last confirmation (it stands by the reply's own date, then by its next confirmation, as any raised thread).
