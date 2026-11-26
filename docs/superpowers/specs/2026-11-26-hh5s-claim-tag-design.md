# The claim travels in the event tag of every root and level change (ai-tools-alerts#hh5s)

## Problem

`spec/wire.md` says the signed statement of what an alert's state rests on travels in one event tag, `["claim", "<JSON object text>"]`, on a root, a level change and a renewal. Readers 0.1.8, 0.2.0 and 0.2.1 read that tag to compute expiry (ai-tools-alerts#r0ra); the code on main also reads it in `verify.claimed` (ai-tools-alerts#tavj, not yet released). The poster sends none: `transport.message_event` builds only the `h` and `e` tags. ai-tools-alerts#3qyq left the readings in place (`rules.readings_for`, `sources.Read.fields`), built with the member's own functions, so a claim made from them is one a member can compare field by field.

## Success criteria

1. With root claims on (`main.ROOT_CLAIMS`, off as shipped: see "Root claims wait for renewals"), a root, and every copy of it in another channel however it comes to be planned, carries exactly one `claim` tag when this run holds a reading for one of the post's ids; `ruleset.check_claim(claim, product)` gives `ok` for the thread's product. With them off no root or copy carries one.
2. A level change carries one the same way: a raise that shares a reply (`plan_known`), a level-only reply planned from a candidate, and a level-only reply the recompute sends (raise or lowering), the last from the readings the verdict rested on.
3. A post whose chosen claim is larger than `wire.MAX_CLAIM_BYTES`, or cannot be written as a claim, is sent without a claim tag and is otherwise unchanged.
4. A journal item carries its claim's text, so a replay or a send after an expiry signs the same tag. A state file written before this change loads; an item without the key sends as before.
5. The bytes the checkpoint owes for a sent post (`signer.record_sent`) include the tag as a channel file holds it.
6. `tests/test_wire_compat.py` runs every released reader (v0.1.4 to v0.1.8, v0.2.0, v0.2.1) and this one against events built by the poster's own `transport.message_event` with claims its own builder made: a thread as shipped (an unclaimed root, a claimed raise) shows at the same level or higher on all of them now and a month on; a thread with a claimed root shows the same now and, a month on with no renewal, has decayed on 0.1.8 and later, which is the reason root claims are off.
7. The poster's own tests carry the claim end to end: the fake relay records the claim it was given, the fake mirror of `tests/poster/test_settle.py` serves events with it, and tests cover a replay after a stopped run, a mirror event with another claim (not the item's send), a reading too large (posted without a claim), the owed byte count, and a state file with and without the key.
8. `scripts/test-gate.sh` passes.

## What exists (read at 8f91677)

- `wire.claim_tag(obj)` writes the tag and refuses more than 2048 bytes; `wire.claim_of(event)` reads it. `Ruleset.claim(source, fields, product, confirmed_at, checked_at)` builds a claim whose level is the ruleset's for that one reading; `rules.claims_for(c, scope, now)` gives one per reading of a candidate.
- `Run._item` builds a journal item; `inputs._item_ok` accepts the optional keys `ja`, `source_title`, `floor`, `tried`, `retried`. `Run.deliver` calls `self.send(channel_id, text, reply_to)`; `transport.Relay.send` signs `message_event(...)` dated by its own clock at the send.
- `Run._owe` records `len(text) + signer.ENVELOPE` (600 bytes for id, key, signature and tags).
- `Run._delivery` (ai-tools-alerts#jsje) takes a mirror event as an item's send when the text, channel, thread and date agree.
- `recompute.support` reads each id's source; `recompute.judge` returns the verdict. Neither returns the readings.
- The reader: `pull._renewal` takes a relay-bot event's claim as a renewal when it is well formed, its level is not `none`, it names one of the thread's ids and `checked_at <= created_at`. A thread decays only when its root carries one. `verify.claimed` asks that each level stated above a lowering carry a claim whose id is the thread's first id, whose level is at least the stated one and that `check_claim` accepts.

## Design

### The carrier

- `transport.check_send(channel_id, content, reply_to=None, claim=None)`: `claim` is None or exactly what `wire.claim_tag` returns for the object it reads back to (`wire.claim_of`), else ValueError. So nothing but a canonical claim tag within the limit is ever signed, and it is checked before anything is marked pending.
- `transport.message_event(..., claim=None)` appends the tag after `h` and `e`. `Relay.send(channel_id, content, reply_to=None, claim=None)` passes it on.
- The journal item gains the optional key `claim`: the tag's text (a non-empty string), only on kinds `root`, `copy` and `reply`. `inputs._item_ok` accepts it under those conditions. `Run.deliver` sends `["claim", it["claim"]]`; with no claim it calls `send` with three arguments as today, so a sender that knows no claim still works for every post without one.
- A Japanese reply, a digest and a catalog root carry none: none of them states a thread's level.
- `Run._owe` adds `wire.tag_bytes(tag)`: the bytes the tag takes in a channel file, its JSON text and the comma before it. `ENVELOPE` stays 600 and keeps meaning id, key, signature and the `h` and `e` tags.
- `Run._delivery`: a mirror event is an item's send only when its `claim` tags are exactly the item's (none for an item without one). An event with the same text and another claim is another event.

### Which claim a post carries

One rule, `rules.claim_text(readings, ids, product, now) -> str | None`:

1. Of the readings this run holds, keep those whose id (`ruleset._id_of`, read by `verify.norm_id`) is one of the post's ids (the thread's first id and its published aliases, read the same way). For a reply these are the ids every channel of the thread was sent (`Run._stated`, added in the code review): the ledger keeps one advisory for a thread in two channels, so when the channels were not sent the same number of replies (one refused a reply for good, or a copy came after a reply) only the first id counts, with any alias the reply itself states. A claim about an id the thread does not carry renews nothing on a reader and is not sent.
2. Take the one the ruleset gives the highest level for the product; on a tie the first id's; then the first in order of (source, id).
3. Build it with `Ruleset.claim(source, fields, product, now, now)` and write it with `wire.claim_tag`. A `RulesetError` or a `ValueError` (too large, not a reading) gives None: no claim. Nothing is trimmed and no smaller reading is substituted: the claim says what the level rests on or the post says nothing.

Why the highest and not always the first id's: the tag is "what the state rests on". When the first id's reading gives the level, both rules pick it. When another id's reading gives a higher one (a GHSA thread whose CVE is in KEV), `verify.claimed` is false under either choice, and the highest one is the true statement.

The claim's level is what its fields support. The post's level can be lower (the action cap, ai-tools-alerts#9kgk) or higher (a reading of prose, the exploited mark): `check_claim` accepts the claim either way, as `spec/ruleset.json` describes.

- **A new root and its copies** (`plan_new`): the readings of the candidate after `_tied` (those its level was computed from), the ids of the post.
- **A reply that changes the level** (`plan_known`, shared or level-only): the same, with the thread's published ids. A reply with no level change carries none: it is not a root, a level change or a renewal.
- **A copy `plan_known` adds** (a channel the thread's level calls for and has no root in, whether or not this candidate changes the level): it is a root there, and carries the claim under the same switch as any root.
- **The recompute's level-only replies**: `recompute.support` takes an optional list and appends each reading it counted as `(source, fields)`: an advisory response that was read, tied and may lower (also one that supports `none`, a withdrawal), and each KEV entry it read as this product's. `judge` passes `info["readings"]`. `Run._judge` keeps them by root; `Run.recompute` builds the claim from them. A lowering that rests only on an absence (the CVE left KEV, no other reading) has no fields to state and carries no claim. A claim whose level is `none` is sent: it is true and the reader does not count it as a renewal.

`confirmed_at` and `checked_at` are the run's `now`, the time of the read. A replay sends the stored text: the claim says when the source was read, not when the event was sent. An event is dated by the sender's clock at the send, at or after `now`; were the clock to step back, the reader would take no renewal from that event and the thread would not decay by it.

### Too large (build item 3)

No claim. A larger limit helps no installed reader: 0.1.8 to 0.2.1 read a tag over 2048 bytes as no claim. Such an alert posts as today, and its level on a reader rests on the member's own check. `_say` names the id and the size.

### Root claims wait for renewals

Readers 0.1.8 and later decay a thread only when its **root** carries a claim (`pull.py`, "A thread can decay only when its root carries a renewal"): critical for 14 days, high to day 30, notice to day 90, then gone, unless a later claim renews it. The poster sends no renewal: a source that still supports the level gives no verdict (`recompute.judge`), so nothing is posted. And the signer gives up a relay-bot reply the mirror stopped serving after 72 hours (`signer.settle_gone`, `settle_owed`), so a checkpoint could list an enrolled root without a level reply that renewed it. Both are ai-tools-alerts#gtw9's to build (its body, and the note from r0ra's review on it).

So a claimed root posted now would lower a true critical on every upgraded member in 14 days. This issue therefore builds and tests the root path and ships it off: `main.ROOT_CLAIMS = False`, a constant in the code, not a setting. With it off, `plan_new` and the copies of `plan_known` attach no claim; level changes still carry theirs. A thread whose root has no claim never expires on any reader, whatever its replies carry (`spec/wire.md`), so the level-change claims can lower or expire nothing; they are read by `verify.claimed` only. gtw9 sets the constant to True in the change that adds renewals and the signer's protection. No journal item for a root can hold a claim while it is off, so no delayed replay can enrol one.

This narrows the issue's acceptance line "a root ... carries exactly one claim tag": it is met in the tests with the constant on, and on the feed when gtw9 lands.

## Alternatives rejected

- **Ship root claims now and ask the release session to deliver gtw9 within 14 days.** A note enforces nothing, and a root once posted with a claim stays enrolled after any rollback.
- **Build renewals here.** How often to renew, what an `unknown` read renews and the signer's handling are gtw9's design; with them this issue passes 600 changed lines and is two deliverables.

- **Store the claim object in the journal and serialise at send.** The bytes signed would depend on the serialiser of the run that sends; the text is what was built and checked.
- **Always the first id's reading.** See above; it states a level the thread is not at.
- **Fall back to a smaller reading when the chosen one is too large.** It would sign a statement that the level rests on something else.
- **A config setting for claims.** Someone would have to turn it on: the standing ruling is that nothing waits for a person. The constant is turned on by the change that makes it safe.
- **A claim on every reply.** A reply with no level change would then be a renewal; renewals and their timing are ai-tools-alerts#gtw9.

## Blast radius and rollback

- Released readers 0.1.4 to 0.1.7 ignore the tag (`spec/wire.md`, tested). Readers 0.1.8 to 0.2.1 read it for expiry only, and only on a thread whose root carries one: as shipped no root does, so no reader shows anything differently. The code on main reads a level change's claim in `verify.claimed`, where a claim can only allow the member's own source check to confirm a lowering.
- The relay and the mirror exporter carry a 2048-byte tag byte for byte (yw7r's note on 3qyq).
- A poster rolled back to a commit before this one refuses a state file in which any journal or withheld item holds a `claim` key: `inputs.load_state` raises `LedgerError` and the run sends nothing until the code is rolled forward again. So a rollback is safe only when no item in `outbox` or `withheld` has the key (a level change waiting to send); otherwise roll forward. Nothing is lost either way: the state file is not rewritten by a run that refuses it.
- Rollback of the code: revert the merge commit. Events already sent keep their tags; nothing reads them differently.

## Assumes

- A copy is a root in its channel and is treated as one (the issue says "every root").
- ai-tools-alerts#3t4p (the critical channel's copy on a recompute raise) passes its copy through the same root switch; ai-tools-alerts#gtw9 turns the switch on.

## Open questions

None that block. Renewals, the step down and the signer's handling of a renewal the mirror stops serving are gtw9's.
