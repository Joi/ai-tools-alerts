# A relay-bot narrowing is checked by the member like a lowering (ai-tools-alerts#swfe)

Revised design rule 6 (ai-tools-alerts#h29n): "lower" means anything that shrinks what a member sees, and a narrower product, range or fixed version follows the same rules as a level.

## Problem

Since ai-tools-alerts#tyje a relay-bot reply never narrows a thread. `pull._apply_patch` joins the reply's `products` to the thread's, so a stolen relay-bot key cannot silence an alert by shortening its range. The cost: a correct narrowing never reaches a member either. The vendor publishes a fixed version, or shortens the affected range, or a product was named by mistake; the poster sends the corrected `products` list (it sends the whole list whenever its entry changes, `poster/compose.py`); every reader keeps the wider entry for the life of the thread. A member on a patched version is told they are affected for good. The reader counts such a reply as `narrowing` and tells nobody (ai-tools-alerts#2wa6).

The member's source check (`aitools_alerts/verify.py`) reads the GitHub advisory's package, `vulnerable_version_range` and `first_patched_version`, and uses them only to compute a level. It does not compare them with the post (note 5 of the ai-tools-alerts#fv4g addendum on ai-tools-alerts#tavj).

## Success criteria

1. A relay-bot reply whose `products` state a `fixed` version past the advisory's `first_patched_version` is not applied, and the CLI says so (`check`, `verify`, `run`; `narrowing_refused` in the JSON). The same holds when a correct entry travels with it in one list.
2. A relay-bot reply whose `products` are what the advisory states is applied in the command that reads the source, and that command shows the result.
3. With the fetch failing, the narrowing applies once signed checkpoints 72 hours apart have listed its reply, and not before; until then the CLI says it waits (`narrowing_waits`).
4. Released readers v0.1.7, v0.2.0 and v0.2.1 still show the wider entry (`tests/test_wire_compat.py`).
5. A narrowing this machine's check has refused does not apply later because a read fails, the cache is lost, the reply is sent again, or another narrowing of the thread was confirmed in between.
6. A refusal stops only the list it refused: another list of the same thread, and the thread's lowering, keep their own check and their own 72 hours. Nothing waits for a person.
7. An entry that changes a product's ecosystem never confirms.
8. `scripts/test-gate.sh` passes.

## What a narrowing is on the wire

Nothing new is sent. A relay-bot reply on a relay-bot thread whose block names `products`, and whose list does not stand for every entry the thread's widest state holds (`pull._covered`, the test `_apply_patch` already counts as `narrowing`), is a published narrowing. Its list, as the schema validated it, is what the poster says the thread's products are.

- The widest state is built exactly as today: the list is joined. So `Thread.wide`, what the sources are asked about (`pull.widest`), and what a released reader from v0.1.7 on shows do not change.
- The thread keeps the latest such list as `Thread.narrowed` and the id of its reply as `Thread.narrowed_by`. The same list sent again keeps the first reply's id, so its wait goes on. A different narrower list replaces it and starts again.
- A later relay-bot block that names `products` and does stand for the whole widest state ends the offer: the poster's last word on products is then the wide list. So does a curator's block that names `products`.
- Past `_JOIN_SCAN` entries the widest state is no longer compared entry by entry (the join's own rule: no single event stands for a flooded list). Every valid `products` list on such a thread is an offer, so a flooded thread can still be corrected.
- A block whose `products` do not validate changes no offer.
- `Thread.narrowings`: a key for every narrowing list the thread has published, `pull.narrow_key(root id, list)`, a SHA-256 over the root's id and the list. It is what the refusal memory is pruned against.
- On a curator's own thread a relay-bot reply is discussion, as before.

Alternative considered: carry the narrowing in an event tag, as the claim is carried, so that v0.1.4 to v0.1.6 (which apply any relay-bot `products` list whole) would keep the wider entry too. Rejected: the poster already sends these lists in the block, on the live feed, and the issue asks to keep "a relay-bot narrowing as published"; a tag would need a poster change and a second wire form for the same statement. v0.1.4 to v0.1.6 narrow at once and unchecked, as they always have (`spec/wire.md`). Nothing tells those members: they do not read `min_cli` (v0.1.4 and v0.1.5 fetch no certificate at all). That is a limit of those releases, stated below, and the reason release 0.1.7 joined.

## The member's check of a narrowing

`verify.narrowing(adv, products, cache, now)`: `adv` is `pull.widest(t)`, `products` is `t.narrowed`. It answers True (the source states it), False (the source states otherwise) or None (not settled).

What the source states. Only a GitHub advisory states versions. For each good read `_record` now keeps, per scope product the response's packages bind to, a list with one item per package entry: the pair `[range, first patched]`, the range with its spaces removed, when `versions.check` can read it, else `null`. One unreadable entry does not hide the readable ones. A KEV record states no versions and has no list. An OSV record's ranges are not read: a product it names has the list `[null]`.

For a thread, `_Run.thread` joins these lists over the records it counted (the first id and the related ids, as today), taking only records that are an authority for the product (`support[product][1]`, the `lowers` of its source row): a source its subject's attacker can write neither confirms nor refuses a narrowing. The result entry of the state gains `ranges`, `{product: [pair or null, ...]}`, and `whole`, whether every read the thread needs was made. The cache `VERSION` goes to 4; the shape check covers both.

`whole` is true only for an entry whose products this run computed from whole reads. An entry kept with a new time (a level contradiction `_settled` holds over a failed read) and one written by a run the request budget cut short carry the ranges that were read and `whole` false: they still refuse, and they confirm nothing however new their time is.

The comparison is with the entries the thread shows (`Thread.wide`'s, passed as `shown`), never with `adv`'s where they differ. The sources are asked about `pull.widest`, and `widest` fills an entry that states no `fixed` with the first one the thread stated, which the thread's signer chose: a list equal to that filled state is not "nothing changed" (found by the code review; a reply could plant a `fixed` and then publish the list the filled state gives).

It goes per product, by the matcher's own rule (`verify.scope_of`, from ai-tools-alerts#2mgd, merged while this was in review): entries that are one scope product are taken together whatever their spelling, so a wider entry a reply put in under another name of the tool is the product's entry too; an entry that is no scope product is a product of its own, by its ecosystem and its name in lower case, and no source states versions for it. Two names the matcher tells apart are never one product here (the delta review found `casefold()` merging a spelling `lower()` keeps apart). A product whose entries are the same set in `shown` and in `products`, spelling included, is not asked about. For any other, with `pairs` the readable pairs the authorities state for the scope products of that name:

1. Every source pair is stated, in every ecosystem the thread shows for the product. For each ecosystem among the product's entries in `shown` and each pair `(r, f)` there must be an entry `q` of `products` for that product in that ecosystem for which `versions.covers(r, f, q.affected, q.fixed)` holds and `q.fixed` is absent or equal to `f` as versions. If not: **False**. This rests on bodies that arrived whole, so it holds on a partial read and at any age.
2. Every new entry states a source pair. Each entry of `products` for that product that is not an entry of `shown` must be in an ecosystem `shown` holds for the product and must state, in the sense of 1, at least one pair. If one does not, the answer is **False** when the reads were whole, the product has pairs and none of its items is `null`; otherwise that product is not settled. An entry under a name the thread does not show falls here: it has no ecosystem to be in.
3. A product with no pairs, or with a `null` item, is not settled.

`whole=True` asks a weaker question, for a thread one of whose narrowings this machine has refused: True whenever fresh whole reads do not contradict the list, settled or not.

**True** needs every changed product settled, the entry `whole`, and read no more than `FRESH_S` (48 hours) ago by this machine's clock. Anything else is None.

So:

- a range or a `fixed` below the source's leaves versions the source calls vulnerable unmatched: False (1);
- a `fixed` above the source's, or a `fixed` where the source states none: False (1 when it is the only entry, 2 when a correct entry travels with it). `fixed` is the version `check.plan` gives the upgrade command, so the reader takes it only as the source states it;
- a product dropped while an authority states versions for it: False (1);
- an entry moved to another ecosystem: False (1), and it is no witness for anything (2). An ecosystem the thread holds can be added to and never taken away by a confirmation;
- a product dropped, or narrowed, that no authority read by this machine states versions for: not settled, 72 hours.

The state asked about is the widest state at its own level; the CLI adds it to the states `verify.run` keeps and re-reads daily (`recheck`), as it does for a lowering.

Why two-sided for `fixed` and one-sided for the range: the issue's acceptance names "raises `fixed` past what the advisory states" as refused. An entry wider than the source in its lower bound loses nothing and misdirects nothing. A wrong `fixed` does either: too low hides vulnerable installations, too high sends the upgrade to a version the vendor did not name as the fix.

## Applying it

`pull.standing(t, now, check, since)` first decides the level as today, then the narrowing, when the thread has one, no curator's hold is in force and the thread is not retracted:

- `check.narrowing(widest(t), t.narrowed)` True: the thread's products are `t.narrowed`.
- False: the products stay the widest; `Thread.narrow_refused` is True.
- None (and with no check, `verify = "off"`): applied once `since` holds the reply and `now` is 72 hours past its recorded time (`UNCHECKED_LOWERING_S`); until then `Thread.narrow_waiting` is True when `since` holds the reply.

Only `products` change. Actions and sources stay the widest: removing an action is rule 6's too and is not this issue's. `check.plan` takes an upgrade's version from the product's `fixed`, so an applied fix shows in the upgrade command.

`pull.offers` records `narrowed_by` beside `offered_by` in the same record (`unverified.json`, `lowerings`): reply id to the issue time of the checkpoint this machine held when it first saw one list the reply. Same rules: only while the reply is its thread's standing offer and the checkpoint lists it and its root.

## The refusal memory

A refused narrowing is remembered by its content, in `State.refused` beside the root ids of refused lowerings: `pull.narrow_key(root id, list)`, a hash of the root's id and the set of entries the list holds, so the same entries in another order or written twice are the same refusal. With it the thread is marked: `pull.narrow_key(root id)` with no list. All are 64 hexadecimal characters, so `unverified.json` keeps its shape.

- The mark stays while the thread is stored. On a marked thread no list waits until fresh whole reads of its authorities do not contradict it (`verify.narrowing(whole=True)`): its recorded time is kept at the newest checkpoint until then. So a refused list respelled (`<1.0` for `<1.0.0`) does not run out 72 hours behind failing reads. It needs nobody: once the reads succeed the 72 hours run, and a list the source confirms applies at once, marked or not.
- The record is brought up to date under the state lock from the events, the checkpoint, the record and the results as they are on disk then, and the command goes on with those threads and that check: a command that started before a narrowing arrived neither drops its refusal nor applies it on an older confirmation.
- Added when the check says False about the thread's standing narrowing.
- While a list's key is there, no wait of that list runs (its reply is left out of `since`, and its recorded time is kept at the newest checkpoint, so the 72 hours start when the refusal ends), and the CLI reports it as refused, whatever the check can read today.
- Removed only when the check says True about that same list, or when no stored thread has published that list any more (`Thread.narrowings`). So the memory outlives the offer: a refused list sent again later, after another list was confirmed, after the cache was lost, with every read failing, is still refused.
- A refusal is only ever recorded on a False, and a False needs an authority that states versions for the product. The same authority can confirm the list later, so no refusal needs a person to end it.
- A refused list does not stop another list of the thread for good: that one has its own key and its own check, and its 72 hours run once whole reads do not contradict it. A refused narrowing does not stop the thread's lowering, and a refused lowering (the root's id, as today) does not stop its narrowing.
- Bound: every key belongs to a stored narrowing reply, every mark to a thread with at least one, and every root id to a stored root with a lowering reply, so the set never passes the number of stored events (`MAX_UNVERIFIED_ENTRIES` equals `pull.MAX_STORED_EVENTS`).

## CLI

- `_Check.narrowing` calls `verify.narrowing`. `_lowering_check` builds a check when a thread has a narrowing, not only a lowering.
- `_matches` adds each narrowing thread's widest state to `a.asked`, and the state the narrowing would leave (read from the same ids in the same run, so the alert is not "not verified" after it applied), and marks a thread whose standing list is remembered as refused. The refusal line is printed from those marks, with `verify = "off"` too.
- `check`: `a narrowing of <id> is published and not verified from this machine: it applies once signed checkpoints 72 hours apart have listed it`.
- `check`, `verify`, `run`: `source check: a narrowing of <id> is not applied: its products are not what the source states`. Fixed words and the id only.
- `verify`: `source check: N narrowings asked about: a confirmed, b contradicted, c not settled`.
- `run` prints its "After the source check:" listing when the products of a thread changed, not only its level: a confirmed narrowing can end this machine's match.
- JSON matches: `narrowing_refused` and `narrowing_waits`, booleans.

## What changes for a member on upgrade

Threads on the live feed already carry such replies (a fix published after the alert). After the upgrade each is asked about on the next `run` or `verify`; one the source confirms applies then, one nobody can read applies after 72 hours of checkpoints counted from that first run. Until then nothing changes.

## Blast radius and rollback

Reader only: `pull.py`, `verify.py`, `cli.py`, tests, `spec/wire.md`, README, changelog. No wire change, no poster change, no state file gains a key (`verify.json` is rebuilt under its new version; `unverified.json` keeps its shape). Reverting the commit restores the join-only reader; a record entry for a narrowing reply, and a refused list's key, are dropped by the old reader on its next run (it keeps only what its own threads name).

No rollout here. The release session installs it; a note goes on ai-tools-alerts#fa5a.

## Known limits

- v0.1.4 to v0.1.6 apply a relay-bot `products` list whole, unchecked, and nothing on the feed tells their members to upgrade.
- A relay-bot reply that widens an entry past the source (a higher `fixed` on a thread that already stated one) is joined at once, as today: a widening is a raise. Only a narrowing is checked. Follow-up: ai-tools-alerts#53fy.
- A removed action is not checked or applied.
- On a thread with no refusal yet, a list never seen by this machine's check is unknown, not refused: with reads failing it applies after 72 hours, as a lowering does (the issue's third acceptance case).
- A command acts on the state as it read it: one that started a moment before another command saved a refusal, and has nothing of its own to write, shows the thread as it was then. The next command shows the refusal.
- Dropping an ecosystem from a product an authority states versions for never confirms and never waits: it stays refused.
- A version outside this reader's grammar (a semver pre-release with a dotted tag) is not comparable: that product is settled only by the 72 hours, unless a readable range already contradicts the list.
- A CVE thread listing more than three advisory aliases is not read whole (ai-tools-alerts#tavj): its narrowing is refused on what was read or waits 72 hours, never confirmed.
- ai-tools-alerts#2wa6: the member's surface is this result. The curator listing and the exporter's log line stay with that issue.

## Review

One independent pass (fresheyes, 2026-11-26, on 77cb1c0): four BLOCKER, three SUBSTANTIVE, one cosmetic, all taken. Ecosystem binding (criterion 7, rule 1); every new entry must state a pair (rule 2); readable pairs survive an unreadable one; the refusal is remembered by content and outlives the offer; a refusal stops only its own list; a flooded thread still takes an offer; `run` shows a changed product list; the false sentence about `min_cli` is gone.

The plan's review (fresheyes, 2026-11-26, on 2795f02): seven SUBSTANTIVE, one cosmetic, all taken; the two that change this text are the `whole` paragraph above and the CLI lines.

The code's review, on the whole branch at f418801 (fresheyes, and a same-model pass in parallel): two BLOCKER, three SUBSTANTIVE, two cosmetic, all taken. A refused list written another way had another key (now a key of the entry set, and the thread's mark); a `fixed` planted through `widest` made a wrong list read as unchanged (now compared with what the thread shows, per case-folded name); an older command pruned a newer refusal and could apply on an older confirmation (now the refreshed view under the lock); a test that did not prove its name.

The one delta pass (fresheyes `--since f418801`, on 823eea5): one BLOCKER, one SUBSTANTIVE, both fixed in edd4a2d, which no review saw: the name grouping above, and a failed save under the lock that put the command's older record beside the refreshed threads. The cache version is 5: main took 4 in the meantime.

## Open questions

None that block. Decided here and posted on the issue: the block form; two-sided `fixed`; the refusal by content.
