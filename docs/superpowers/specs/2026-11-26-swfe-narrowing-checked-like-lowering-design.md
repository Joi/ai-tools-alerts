# A relay-bot narrowing is checked by the member like a lowering (ai-tools-alerts#swfe)

Revised design rule 6 (ai-tools-alerts#h29n): "lower" means anything that shrinks what a member sees, and a narrower product, range or fixed version follows the same rules as a level.

## Problem

Since ai-tools-alerts#tyje a relay-bot reply never narrows a thread. `pull._apply_patch` joins the reply's `products` to the thread's, so a stolen relay-bot key cannot silence an alert by shortening its range. The cost: a correct narrowing never reaches a member either. The vendor publishes a fixed version, or shortens the affected range, or a product was named by mistake; the poster sends the corrected `products` list (it sends the whole list whenever its entry changes, `poster/compose.py`); every reader keeps the wider entry for the life of the thread. A member on a patched version is told they are affected for good. The reader counts such a reply as `narrowing` and tells nobody (ai-tools-alerts#2wa6).

The member's source check (`aitools_alerts/verify.py`) reads the GitHub advisory's package, `vulnerable_version_range` and `first_patched_version`, and uses them only to compute a level. It does not compare them with the post (note 5 of the ai-tools-alerts#fv4g addendum on ai-tools-alerts#tavj).

## Success criteria

1. A relay-bot reply whose `products` state a `fixed` version past the advisory's `first_patched_version` is not applied, and the CLI says so (`check`, `verify`, `run`; `narrowing_refused` in the JSON).
2. A relay-bot reply whose `products` are what the advisory states is applied in the command that reads the source.
3. With the fetch failing, the narrowing applies once signed checkpoints 72 hours apart have listed its reply, and not before; until then the CLI says it waits (`narrowing_waits`).
4. Released readers v0.1.7 and v0.2.1 still show the wider entry (`tests/test_wire_compat.py`).
5. A narrowing the check has refused does not apply later because a read fails, the cache is lost or the reply is sent again.
6. `scripts/test-gate.sh` passes.

## What a narrowing is on the wire

Nothing new is sent. A relay-bot reply on a relay-bot thread whose block names `products`, and whose list does not stand for every entry the thread's widest state holds (`pull._covered`, the test `_apply_patch` already counts as `narrowing`), is a published narrowing. Its list, as the schema validated it, is what the poster says the thread's products are.

- The widest state is built exactly as today: the list is joined. So `Thread.wide`, what the sources are asked about (`pull.widest`), and what a released reader from v0.1.7 on shows do not change.
- The thread keeps the latest such list as `Thread.narrowed` and the id of its reply as `Thread.narrowed_by`. The same list sent again keeps the first reply's id, so its wait goes on. A different narrower list replaces it and starts again.
- A later relay-bot block that names `products` and does stand for the whole widest state ends the offer: the poster's last word on products is then the wide list. So does a curator's block that names `products`.
- A list is not an offer when the widest state holds more than `_JOIN_SCAN` product entries (no single event stands for a flooded list), or when the block's `products` do not validate.
- On a curator's own thread a relay-bot reply is discussion, as before.

Alternative considered: carry the narrowing in an event tag, as the claim is carried, so that v0.1.4 to v0.1.6 (which apply any relay-bot `products` list whole) would keep the wider entry too. Rejected: the poster already sends these lists in the block, on the live feed, and the issue asks to keep "a relay-bot narrowing as published"; a tag would need a poster change and a second wire form for the same statement. v0.1.4 to v0.1.6 narrow at once and unchecked, as they always have (`spec/wire.md`); that is the gap ai-tools-alerts#tyje closed by release 0.1.7, and the certificate's `min_cli` tells those members to upgrade.

## The member's check of a narrowing

`verify.narrowing(adv, products, cache, now)`: `adv` is `pull.widest(t)`, `products` is `t.narrowed`. It answers True (the source states it), False (the source states otherwise) or None (not settled).

What the source states. Only a GitHub advisory states versions. For each good read `_record` now keeps, per scope product the response's packages bind to, the list of `[range, first patched]` pairs, the range with its spaces removed. A pair is kept only when `versions.check` can read it; one unreadable or missing range makes that product's list `null` in that record (not comparable). A KEV record states no versions and contributes nothing. An OSV record's ranges are not read, so a product an OSV record names is `null` there.

For a thread, `_Run.thread` joins these over the records it counted (the first id and the related ids, as today), taking only records that are an authority for the product (`support[product][1]`, the `lowers` of its source row): a source its subject's attacker can write neither confirms nor refuses a narrowing. The result entry of the state gains `ranges`, `{product: [[range, fixed], ...] or null}`, and `whole`, whether every read the thread needs was made. The cache `VERSION` goes to 4; the shape check covers both.

The comparison, per exact product name of `adv`:

- The product is unchanged when the set of its (ecosystem, affected, fixed) entries is the same in `adv` and in `products`. Nothing is asked about it.
- Otherwise the source's pairs for it are needed. `null`, absent or empty: not settled for this product.
- Each source pair `(r, f)` must be stated by one entry `q` of `products` with that exact name: `versions.covers(r, f, q.affected, q.fixed)`, and `q.fixed` is either absent or equal to `f` as versions. If one pair is not stated the answer is False, whatever else holds.

So:

- a range or a `fixed` below the source's leaves versions the source calls vulnerable unmatched: False;
- a `fixed` above the source's, or a `fixed` where the source states none: False. `fixed` is the version `check.plan` gives the upgrade command, so the reader takes it only as the source states it;
- a product dropped while the source names its package: False;
- a product dropped, or narrowed, that no authority read by this machine states versions for: not settled, 72 hours.

True needs every changed product settled, the entry `whole`, and read no more than `FRESH_S` (48 hours) ago by this machine's clock. False holds at any age and on a partial read: it rests on bodies that arrived whole, and a missing one could only add. The state asked about is the widest state at its own level; the CLI adds it to the states `verify.run` keeps and re-reads daily (`recheck`), as it does for a lowering.

Why two-sided for `fixed` and one-sided for the range: the issue's acceptance names "raises `fixed` past what the advisory states" as refused. An entry wider than the source in its lower bound loses nothing and misdirects nothing. A wrong `fixed` does either: too low hides vulnerable installations, too high sends the upgrade to a version the vendor did not name as the fix.

## Applying it

`pull.standing(t, now, check, since)` first decides the level as today, then the narrowing, when the thread has one, no curator's hold is in force and the thread is not retracted:

- `check.narrowing(widest(t), t.narrowed)` True: the thread's products are `t.narrowed`.
- False: the products stay the widest; `Thread.narrow_refused` is True.
- None (and with no check, `verify = "off"`): applied once `since` holds the reply and `now` is 72 hours past its recorded time (`UNCHECKED_LOWERING_S`); until then `Thread.narrow_waiting` is True when `since` holds the reply.

Only `products` change. Actions and sources stay the widest: removing an action is rule 6's too and is not this issue's. `check.plan` takes an upgrade's version from the product's `fixed`, so an applied fix shows in the upgrade command.

`pull.offers` records `narrowed_by` beside `offered_by` in the same record (`unverified.json`, `lowerings`): reply id to the issue time of the checkpoint this machine held when it first saw one list the reply. Same rules: only while the reply is its thread's standing offer and the checkpoint lists it and its root.

The refusal memory is the thread's, as today (`State.refused`, root ids): a root is added when the check says False about its lowering or its narrowing, and while it is there no wait of that thread runs, for either. It ends only when every standing offer of the thread is confirmed (for the lowering also `whole`, as today). So a refused narrowing sent again, a failed read and a lost cache start no 72 hours.

## CLI

- `_Check.narrowing` calls `verify.narrowing`. `_lowering_check` builds a check when a thread has a narrowing, not only a lowering.
- `_matches` adds each narrowing thread's widest state to `a.asked`.
- `check`: `a narrowing of <id> is published and not verified from this machine: it applies once signed checkpoints 72 hours apart have listed it`.
- `check`, `verify`, `run`: `source check: a narrowing of <id> is not applied: its products are not what the source states`. Fixed words and the id only.
- `verify`: `source check: N narrowings asked about: a confirmed, b contradicted, c not settled`.
- JSON matches: `narrowing_refused` and `narrowing_waits`, booleans.

## What changes for a member on upgrade

Threads on the live feed already carry such replies (a fix published after the alert). After the upgrade each is asked about on the next `run` or `verify`; one the source confirms applies then, one nobody can read applies after 72 hours of checkpoints counted from that first run. Until then nothing changes.

## Blast radius and rollback

Reader only: `pull.py`, `verify.py`, `cli.py`, tests, `spec/wire.md`, README, changelog. No wire change, no poster change, no state file gains a key (`verify.json` is rebuilt under its new version; `unverified.json` keeps its shape). Reverting the commit restores the join-only reader; a record entry for a narrowing reply is dropped by the old reader's `pull.offers` on its next run.

No rollout here. The release session installs it; a note goes on ai-tools-alerts#fa5a.

## Known limits

- v0.1.4 to v0.1.6 apply a relay-bot `products` list whole, unchecked.
- A relay-bot reply that widens an entry past the source (a higher `fixed` on a thread that already stated one) is joined at once, as today: a widening is a raise. Only a narrowing is checked. Follow-up issue filed.
- A removed action is not checked or applied.
- A thread refused once stays refused until a confirmation: a correct narrowing of a product no authority states versions for never applies on a machine that refused an earlier one.
- A version outside this reader's grammar (a semver pre-release with a dotted tag) is not comparable: 72 hours.
- A CVE thread listing more than three advisory aliases is not read whole (ai-tools-alerts#tavj): its narrowing is refused on what was read or waits 72 hours, never confirmed.
- ai-tools-alerts#2wa6: the member's surface is this result. The curator listing and the exporter's log line stay with that issue.

## Open questions

None that block. Decided here and posted on the issue: the block form; two-sided `fixed`; the thread-wide refusal.
