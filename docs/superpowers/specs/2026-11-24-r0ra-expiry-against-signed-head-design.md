# Expiry is computed and applies only against a signed head (ai-tools-alerts#r0ra)

Finding D5 of the design review on ai-tools-alerts#h29n. Builds on the signed checkpoint (ek5q: `aitools_alerts/checkpoint.py`, called "the head" here), the claim and `ttl_days` (s6mt: `aitools_alerts/ruleset.py`) and the claim tag (t8jr: `aitools_alerts/wire.py`, `spec/wire.md`).

## Problem

`pull.active` drops a thread once `expires_at` is behind the member's own clock. Three consequences:

1. Whoever controls what the mirror serves can lower without a key. Freeze the mirror and every alert with an expiry ends on each member's clock. The stale warning appears; the alert still goes.
2. `expires_at` is a free field of the block. With the relay-bot key, a root whose `expires_at` is one second after `posted_at` validates, and the alert ends at once on every reader.
3. A member clock set forward expires everything it can; set back, it revives it.

A fourth path is next to these: `pull._retain` drops a thread whose newest event is 400 days behind the member's clock, so a clock set a year ahead deletes stored alerts on the next pull.

## What exists and is reused

- The head: `Checkpoint.created_at` is its issue time, `Checkpoint.events` what it lists. A head dated more than 10 minutes after the local clock is already refused (`checkpoint dated ahead of this clock`). A mirror that lacks a listed event is already refused (`mirror incomplete`), so dropping one thread's renewals is already reported; what is missing is that nothing expires meanwhile.
- The claim: `ruleset.parse_claim` checks `{id, source, fields, ruleset, level, confirmed_at, checked_at}`; `wire.claim_of` reads it from the event tag; `Ruleset.ttl_days` gives days per level (critical 14, high 30, notice 90).
- Rule 3 of `spec/wire.md`: a relay-bot block sets no expiry. The poster already writes `null`.

## Design

### 1. A relay-bot block's `expires_at` is not read

In `pull.threads_from`, a root whose key is not a curator's has its `expires_at` set to None when the advisory is built. A relay-bot reply that names `expires_at` is already refused. So the only `expires_at` a thread can hold is one a curator wrote (in a curator root or a curator patch). A curator's word stays an optional override.

### 2. Renewals

A renewal is any event of a thread (the root or a reply, whatever its text) that:

- is signed by a relay-bot key of the current manifest;
- carries a claim that `ruleset.parse_claim` accepts, whose level is not `none`;
- whose claim id is one of the ids the thread has held (the root's id and aliases, and every alias a patch gave it, kept after a later patch drops it), compared case-folded;
- whose `checked_at` is not after the event's own `created_at`.

A raise by the relay bot (a patch that is applied and sets a higher level) also counts as a renewal dated at its event, with or without a claim: the level it sets stands from then, never from an older confirmation of a lower level.

`Thread` gains `renewals`, a tuple of `(confirmed_at, checked_at, created_at)`, `enrolled_at` (the root's date when the root event itself is a renewal, else None) and `curated` (a curator posted or amended the thread; the reader already tracks this). A reply's claim counts even when the reply is otherwise discussion or a refused lowering.

**Only an enrolled thread decays.** A thread whose root carries no claim never expires, whatever its replies carry. Otherwise the relay-bot key could end any alert on today's feed, none of which has a claim, by replying with a claim confirmed in 1970: the first claim would turn "no expiry" into "expired". With the root's own claim as the floor, every later claim can only lengthen the thread's life (section 3 takes the maximum), and a root cannot be changed after it is signed.

The claim's level and its `ruleset` number are not compared. The level a reader holds may be higher than the bot's (a released reader, and this one until ai-tools-alerts#fv4g, refuses a relay-bot lowering). The reader uses its own TTL table for the level it shows.

What a renewal does not prove: that the source was read. A holder of the relay-bot key can sign a fresh claim every day and keep its own false alert alive, as it can post a new false alert every day. That is finding D2/D8's ground, not D5's: the member's own source check (ai-tools-alerts#fv4g) and the poster's check for events it did not send (D14) answer it. This change removes the ways expiry itself could be turned: the free field, the member clock, the withheld renewal, the ancient claim.

### 3. How long a level stands

In `ruleset.py`, with `UNCONFIRMED_DAYS = 45`:

    stands_until(level, confirmed_at, checked_at) =
        max(confirmed_at + TTL(level),
            min(checked_at + TTL(level), confirmed_at + 45 days))

A confirmation keeps the level for its TTL. A check that could not confirm (`confirmed_at` unchanged, `checked_at` new) keeps it for a TTL from the check, and never past 45 days from the last confirmation: a blocked source does not start the decay, and the ceiling holds without the poster. A thread's value is the maximum over its renewals, so a shorter renewal changes nothing.

`level_at(level, renewals, now)`: the highest level, from `level` down, that still stands by its own TTL; `none` when none does. A critical with no renewal is critical for 14 days, high until day 30, notice until day 90, then gone. h29n rule 4 says a critical "decays to notice then off"; it passes through high here because the function must never give a lower answer for a higher level, or a raise would shorten what a thread shows (the code review's first finding).

The 45 days is a constant in code, not a key of `spec/ruleset.json`: a new key changes the ruleset digest, which the trust root is to pin (ai-tools-alerts#ed7n), and that needs a ruleset version. Noted for the issue that adds version 2.

### 4. The head is the clock

`pull.active(threads, now=None, listed=None)`:

- `now` is the issue time of the newest accepted head, never the local clock. `None` (no head yet): nothing expires.
- `listed` is that head's event ids. A thread whose root the head does not list does not expire. `None`: every thread counts as listed (tests; the exporter does not call `active`).
- A retracted thread is dropped, as before.
- A thread with a curator's `expires_at` is dropped when `now > expires_at`.
- Otherwise, when the thread is enrolled and not `curated`: if any of its renewals is on an event dated after `now`, it is not judged and keeps its level (section 5). Else it is shown at `level_at(...)` of all its renewals and dropped at `none`.
- Any other thread does not expire. Every thread on the feed today is one: the poster sends no claim yet.

`pull.head_clock(state)` returns `(created_at, events)` of the stored head of the state's root, or `(None, None)` when there is none or when an event it lists is not in the store. The second case is an interrupted save: `_fetch` writes the head before the events, so a crash between the two leaves a later head over an earlier store, and a renewal that head lists would be missing. Nothing expires until a pull completes. The CLI calls `pull.active(pull.advisories(st), *pull.head_clock(st))`.

The stored head is used even when `unverified` says it is out of date. That is the point: with a frozen mirror the head stops, so the clock for expiry stops, the alert keeps its level and the existing stale warning fires. The local clock still bounds the head from above (10 minutes), so no head can run the clock forward.

A thread the head does not list keeps the level its events give, so a thread that had decayed shows at its first level again if a later head omits its root. The signer omits a root only when the mirror has not served it for 72 hours (`poster.signer.settle_gone`). This is kept on purpose: the other choice, decaying unlisted threads, lets a mirror that hides a root for 72 hours lower the alert on every member who holds it, because the renewals of an unlisted thread are never admitted. Too high is the safe side. Remembering the decayed level across heads would need a new state file key; not in this change.

### 5. An event dated after the head that lists it

The issue asks that such an event be refused. It cannot be refused at the pull: the honest signer lists them. The poster's checkpoint is dated at the start of its run and lists every post the relay acknowledged during the run (`poster.signer.window` lists the owed ids whatever their date; `tests/poster/test_signer.py::test_a_post_stamped_after_the_run_began_stays_owed_until_it_can_be_listed`). Refusing the head, or holding the event back a cycle, would break or delay every posting run, a curator's retraction included.

What a date ahead of the head could do is bounded instead:

- An event dated more than 10 minutes ahead of the member's clock is not admitted (ek5q, unchanged), and a head dated that far ahead is refused.
- A thread with a renewal on an event dated after the head is not judged under that head (section 4); the next head, which has reached that date, judges it with every renewal counted. So the root's own claim is always among those counted, a raise posted in the run shows at once, and an event dated ahead holds a thread only until the head passes its date, which the clock bound puts at most 10 minutes past the member's clock. A claim's `checked_at` is not after its event, so no claim states a confirmation later than its own date.

### 6. Retention by the head

`_retain` takes its clock from the caller. A checked pull passes `min(now, head time)`: the stored head's until this pull's head is accepted, then that one's. A reader with no head yet, and a writer's pull, pass the local clock as before. A member clock a year ahead no longer ages out stored threads; a clock behind only keeps more.

## Acceptance (each is a test)

1. A mirror frozen for 30 days: the critical is still critical, `stale_since` is not None.
2. A mirror that drops one thread's renewal while the new head lists it: `mirror incomplete`, the alert keeps its level; served whole, the renewal keeps it past the first claim's TTL.
3. A relay-bot root with `expires_at` one second after `posted_at`, and a relay-bot claim with a short life beside a longer one: the thread's life is the longer one.
4. An event dated ten years ahead that a head lists: the pull is refused and the event is not stored (ek5q's rule; a regression test), `stale_since` still fires. A renewal dated after its head, inside the clock bound, is admitted and its claim does not count until a head reaches its date.
5. A member clock one year ahead and one year behind: through pull, reload and display, what is shown is what the stored head gives, and no stored event is aged out (one thread is more than 35 days old, so a year ahead passes the 400 days).
6. A critical with one claim and no renewal, under a head issued after its TTL that lists it: shown as notice; after 90 days, gone.

Also tested: `stands_until` and `level_at` at their bounds; a claim for another id, a malformed claim, a `none` claim, a curator's event and a claim checked after its event are not renewals; a thread whose root has no claim does not decay when a reply carries a claim confirmed in 1970; a curated thread and an unlisted thread do not decay; a curator `expires_at` is judged by the head; a head saved over an earlier store (the interrupted save) expires nothing.

Existing test that changes: `tests/test_wire_compat.py::test_what_the_format_avoids_an_expiry_in_a_relay_bot_block_ends_the_alert`. Released readers still stop showing a relay-bot alert at its block's `expires_at`; this reader now keeps it. The expectations are split.

## Not in this change

- The poster half of r0ra: renewing on `unknown` with `confirmed_at` unchanged, and the step down after 45 days. The poster sends no claim tag and has no three-result read yet (ai-tools-alerts#ny5g). Follow-up ai-tools-alerts#gtw9, blocked by ny5g. Until it lands no thread is enrolled, so no thread decays: this change alters nothing a member sees on today's feed except that a relay-bot `expires_at` (none exists) would no longer end an alert.
- Two signer rules that must land with the first renewal, in gtw9: a renewal the mirror stops serving is never given up after 72 hours with its thread still listed (today only a missing curator reply leaves the thread out of the head), or a mirror that hides a thread's renewals for 72 hours gets an honest head that lists the root without them; and the checkpoint is dated when it is signed, so the posts of its own run are not ahead of it.
- Showing that a level was decayed, in `check` output.
- A curator action that lapses after 14 days (D9), and expiry for threads with no claim.

## Alternatives

- Refuse a head that lists an event dated after it, or skip the event: the first breaks the honest signer, the second needs a record of skipped ids so `unverified` does not read the store as incomplete, and both delay a retraction posted during a run.
- Let any claim on a thread start its decay: see "Only an enrolled thread decays".
- Decay straight to notice, as the ruling's words say: not monotonic in the level, so a raise could lower what is shown.
- Count only the renewals dated at or before the head (the first build): a reply dated before a held-back root could then be the only one counted, and a raise posted in the run showed at the old level for a cycle.
- Count only claims at or above the thread's level: a thread whose level rests on a reading (the claim is lower) would decay at once, which is lowering by absence.

## Blast radius and rollback

Reader only: `pull.py`, `ruleset.py`, one line of `cli.py`. The poster's and the curator command's pulls (`checkpoint=False`) keep the local clock for retention. No wire, state-file or spec-file format changes. `pull.active` keeps its positional `now`; its default changes from the local clock to "nothing expires". Rollback: revert the commit; state written by this reader is read by the previous one.
