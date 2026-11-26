# y484: the reversible withdrawn state, member's half

Issue: ai-tools-alerts#y484 (findings D4 and D13 of the design review on ai-tools-alerts#h29n). The poster's half is ai-tools-alerts#kk2q.

Prior work read: ai-tools-alerts#3qyq (the advisory readers; a withdrawn reviewed advisory lowers its thread to notice), #tavj (a lowering the member cannot check applies after 72 hours; `verify.claimed`), #c1g2 (a curator's retraction of a relay-bot thread is held 14 days), #hh5s (a level change carries its claim; a claim of level `none` is sent), #t8jr note 3 on #ny5g (`withdrawn` cannot be a level on a root). No earlier attempt at this state exists (`kata search "withdrawn state"`).

## Problem

The relay bot has no retraction: a curator's `retract` ends a thread for good, and one bad read of a source would do the same (D13). So an advisory its source withdrew stays shown at notice for the life of the thread. The design gives the bot a state instead, `withdrawn`: shown nowhere, matched by nothing, and left again when the source publishes the advisory again.

Nothing sends it yet. This change defines it on the wire and builds what a member's reader does with it, so that the poster (kk2q) can send it to readers that understand it.

## Success criteria

1. A relay-bot reply whose block is exactly `{"level":"withdrawn"}` is a withdrawal of its thread. Each released reader, v0.1.4 to v0.2.1, refuses the reply and shows the alert at the level it held (`tests/test_wire_compat.py`).
2. The current reader shows a withdrawn thread nowhere and matches nothing against it while the member's own source check confirms the withdrawal: `pull.active` leaves it out. One exception: while a curator's hold on the thread is in force the thread is as the curator left it (c1g2), withdrawal or not; the withdrawal is judged when the hold has lapsed. A curator who retracts the thread or names a level after the withdrawal replaces it as the thread's published state (the code that exists for any offer): the thread is then never hidden by it, which is the higher side.
3. Confirmed means: every source of the thread read whole no more than two days ago, each an authority, none supporting the product, at least one stating the withdrawal, and every level the thread stated carried by a claim from its first id's fields that this reader's ruleset reproduces (`verify.claimed`).
4. A withdrawal the check does not confirm is read as a lowering to notice that nobody has checked: applied once checkpoints 72 hours apart have listed the reply; refused when the source supports more than notice.
4a. One question, one result (revised after the code review, which found that two cached results, one for `withdrawn` and one for `notice`, can be read by different runs and disagree in both directions). The reader asks the check about the withdrawal only, and the check answers from the one cached state at level `none`: True (confirmed: hidden), False (a source supports more than notice: refused, and the thread's root enters `State.refused`, where it stays through failed reads and any number of checkpoints), None (anything else, a source that supports exactly notice among them: the 72 hours decide). A refusal ends on True, or on fresh whole reads of authorities that give no product more than notice. A claimed thread whose source supports exactly notice therefore waits 72 hours where a plain `{"level":"notice"}` reply would apply at once; that is the price of one result.
5. A withdrawal never hides a thread unchecked, however long it has stood.
6. A later relay-bot reply that names a level ends the withdrawal: at or above the thread's widest level the thread stands there at once; below it, the reply is a lowering like any other. The thread and its root are the same.
7. A source that publishes the advisory again brings the thread back on the member's machine without any reply: the check no longer confirms, and when it reads support above notice the withdrawal is refused. This holds for a thread that still stands by its claims. A thread whose root carries a claim decays as before (r0ra), shown or hidden: the withdrawal reply is no renewal (it names no level, and a claim of level `none` renews nothing), so a hidden thread that has run out its 90 days is gone like any other and only a new post brings the advisory back. Expiry does not change here.
8. A curator's retraction is unchanged: held 14 days, never kept past the hold by the check.
9. The bot still has no `retract`: a relay-bot reply whose first line is `retract` retracts nothing, and its block is not read, a `{"level":"withdrawn"}` block included. What such a reply does today outside its block stays as released readers 0.1.8 to 0.2.1 have it (its claim can renew; a level its block names is noted in `stated` and as a renewal): this change does not touch that.

## Approach

**Wire** (`wire.py`, `spec/wire.md`). `wire.WITHDRAWN = "withdrawn"` and `wire.is_withdrawal(patch)`: the block is a dict equal to `{"level": "withdrawn"}`. `withdrawn` is not a level: it is in no rank table, `schema.LEVELS` and `spec/advisory.schema.json` do not change, and a root that names it is no advisory, as today.

**Reader** (`pull.py`). `_bot_reply` takes a withdrawal before anything else: `offered` becomes `withdrawn` and `offered_by` the reply's id (the first of them when the withdrawal is sent again). Nothing is applied. `offered` already means "the state last published below the widest state, which replay never applies"; `none` stays the curator's retraction, so the two are told apart by the word.

- A reply that names a level is handled by the code that exists: below the widest level it replaces the offer; at or above it, it applies and ends the offer.
- `asks` returns `withdrawn` for such a thread, and nothing more: one state is asked, one result kept.
- `offers` records the reply like a lowering's, so the 72 hours of the notice reading can run.
- `pull.unchecked_level(t)`: the level a thread's offer brings it to when it applies unchecked (`notice` for a withdrawal; None when the thread stands at notice; else the offer).
- `_level_standing`, with no curator's hold in force, by `said = check(widest, "withdrawn", stated)`: True gives the thread retracted (so `active` drops it); False refuses, `refused` is `withdrawn`; None applies notice once the reply has stood 72 hours, with `waiting` notice until then. When the widest level is already notice there is nothing to lower.

**Check** (`verify.py`). `at_level(adv, "withdrawn")` asks the sources about the state at level `none`, as a retraction is asked. `claimed` treats `withdrawn` as below every level: every statement of the thread needs its claim. For `none`, the curator's word, it stays False. `lowering(adv, "withdrawn", ...)`: False when a source supports more than notice for some product (`below-source` with a source level above notice, at any age); True when the state is claimed, the result is no more than two days old and every product's result is `confirmed` / `match` at `none` (`judge` gives that only for whole reads of authorities that name the product and support nothing, which only a withdrawn reading does); None otherwise. With `whole=True` (ending a refusal): True when the result is fresh, its reads were whole, and every product is `match` or supported at exactly notice. `lowering(adv, "none", ...)` is unchanged: never True.

**CLI** (`cli.py`). The refusal line says "a withdrawal of <id> is not applied" for `refused == "withdrawn"`. `_note_offers` is unchanged: it asks the check about the thread's offer, which for a withdrawal is the one question. The `verify` count line reads "lowerings, withdrawals or retractions asked about".

**Documents.** `spec/wire.md` (the withdrawal, what each reader does), `README.md` (the member-facing sentence), `CHANGELOG.md`.

## Tests the build must carry

- The reader: a withdrawal is published and not applied; sent again it keeps the first reply; a level reply after it ends it (at the widest level, above it, below it); a `retract` first line with the withdrawal block is no withdrawal; a root naming `withdrawn` is no advisory.
- Standing: hidden on True; notice on confirmed notice; notice after 72 hours unsettled, never hidden however long; refused on False; on a notice thread nothing to lower.
- One question: the check stub is asked `withdrawn` and nothing else; through the real cache, a refresh cut short leaves the day-old confirmation (for no more than two days) and a refresh that reads support contradicts it.
- 4a through the CLI: a contradicted withdrawal stays refused through a failed read that was really tried and checkpoints past 72 hours; a refusal ends when the source gives no more than notice, and the 72 hours run from the checkpoint it ended under.
- A curator's hold: withdrawal before and after a curator's title amendment, hidden only after the hold lapses; a curator's retraction with a confirming check still lapses; a curator's later retraction or level takes the offer.
- Expiry: a hidden claimed thread un-hidden before its claims run out shows again; after, it is gone.
- The check: `lowering(..., "withdrawn")` True only claimed, fresh, whole, withdrawn; False on support; None for unclaimed, stale, an unread source, a source silent about the product; `"none"` never True.
- Every released reader (v0.1.4 to v0.2.1) shows the alert at its level with the reply on the feed.

## What a stolen relay-bot key gains

It can post the withdrawal on any thread. On a released reader: nothing. On this reader: the thread is hidden only when the member's own fresh read of the authoritative source says the advisory is withdrawn, which the key cannot cause; otherwise the reply is a lowering to notice, which the key can already post today, with the same check, wait and refusal. So the reply gives the key nothing it does not have.

A source's own withdrawal hides the alert on a member only together with the signed reply. A source that withdraws and nobody posts: the thread stands as it is.

## Alternatives considered

- **`{"level":"none"}` as the block.** `none` is already the curator's retraction inside the reader (`pull.NONE`), and one word for two rules (one never confirmed, one confirmed) is the confusion this avoids.
- **A reply with no block, only a claim of level `none`.** The wire rule is that a claim never decides whether an event is read; the issue asks for a level-only reply.
- **Hide after 72 hours unchecked.** A stolen key could then hide every alert on every member in three days. Refused.
- **An unconfirmed withdrawal changes nothing.** Then a member whose check cannot confirm (no claims on the thread's root, which is every thread until ai-tools-alerts#gtw9; a failed read; `verify = "off"`) would keep a withdrawn alert at its full level, where the poster of 3qyq brings it to notice. The notice reading keeps that floor.
- **Let the check keep a curator's retraction past its hold.** A change to c1g2 that this issue does not ask for.

## Blast radius and rollback

Member CLI only: `wire.py`, `pull.py`, `verify.py`, `cli.py`. No poster code, no schema, manifest, ruleset or state-file change; `verify.json` keeps its version (a state asked at `withdrawn` has the key of the same state asked at `none`, with its claimed flag). Until kk2q lands and is released no event on the feed carries the block, so the new code paths are reached only in tests. Rollback: revert the commit; a reader without it refuses the reply and keeps the alert.

## Assumes

- Roots carry no claim until gtw9, so on the live feed no withdrawal is confirmed before then; such threads take the notice reading. That is intended and stated in `spec/wire.md`.
- The poster sends the withdrawal alone, in every channel the thread has a root (kk2q).

## Open questions

None that block. For kk2q: whether a thread withdrawn and then returned at a level below its widest should carry a claim that lets the member confirm it at once (hh5s's rule already gives a level change its claim).
