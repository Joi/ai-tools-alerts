# The curator override: checked, held for 14 days, and no longer silencing the bot (c1g2)

Issue: ai-tools-alerts#c1g2. Finding D9 of the design review (comments on ai-tools-alerts#h29n; revised design rule 10). Related: ai-tools-alerts#r98k, ai-tools-alerts#tavj.

## Problem

In the reader today (`aitools_alerts/pull.py`, `threads_from`):

- A curator reply whose first line is `retract` ends a thread for good. One whose first line is `level: high|notice` lowers it for good. A curator patch replaces the fields it names, for good.
- Once a curator has posted or amended a thread, every later relay-bot reply is discussion. The bot can never raise, renew or correct that thread again, and the thread never decays.
- No member check applies to any of it. `aitools_alerts/verify.py` judges relay-bot threads and changes nothing.

The one curator in the manifest is a shared general-purpose key (ai-tools-alerts#r98k), and no curator has ever posted. With nobody watching, that key undoes every protection of the self-correcting design with one signature per thread, and an honest curator action freezes a thread out of self-correction for good.

## What the landed code changes about the issue text

The issue was written before its siblings landed. Read against main at `e2ac9b6`:

- "Checked by the member like the bot's": the bot's lowering is not checked yet. The reader refuses every relay-bot lowering outright, and applying the member's result is ai-tools-alerts#tavj, which is open and not being built now. The third acceptance case of this issue ("a bot lowering with a confirming source lowers") cannot hold without a reader that applies a confirmed lowering. This issue therefore builds the smallest part of tavj it needs: a published lowering is carried on the thread and applied only when the member's own source check confirms it. Everything else in tavj's table stays there (the 72-hour rule, unverified interrupts, "never supported", narrowings).
- "The recompute governs again": in the reader this means the thread as its signed events give it with the curator's downward word left out, which is the widest signed state (revised design rule 6).

## Scope

Relay-bot threads (the root is signed by a relay-bot key). A curator's own thread is unchanged: a relay-bot reply to it is still discussion, its retraction and expiry still stand, and it still never decays. Reasons: there is no recompute to hand such a thread back to; auto-apply is decided by the root's role, so letting a bot reply change a curator's thread would put a relay-bot action in reach of auto-apply; and the key that could misuse the override there can post its own false alert anyway.

The manifest's `retracted` list is root-signed and unchanged: it ends a thread for good.

## Design

### 1. Two states per relay-bot thread

`threads_from` keeps, for each relay-bot thread:

- **the widest state** (`Thread.wide`): every reply applied under the relay bot's rules, the curator's replies included. Nothing in it ever shrinks: levels only rise, `products`, `actions` and `sources` are joined, no expiry is set, no retraction applies.
- **the held state** (`Thread.adv`, `Thread.retracted`, as today): the curator's word applied as written.

With no curator action in force the two are the same object.

### 2. The hold

A curator action on a relay-bot thread is a reply that is a retraction, a `level:` line naming `high` or `notice` at or below the thread's level, or a patch that validates. Each one starts or renews a hold: `held_until = created_at + 14 days` (`pull.CURATOR_HOLD_S`). Discussion and translations renew nothing.

While a hold is in force:

- the held state is what readers show, unchecked unless rule 4 applies;
- a relay-bot reply that names a higher level than the held state raises the held state's level at once (the level only), also when that level is below the widest state's and so is published as a lowering (rule 3);
- every other relay-bot change waits: it is applied to the widest state and shows when the hold lapses;
- a retraction is not undone by a raise;
- the thread does not decay (as today).

When the hold lapses the widest state governs: the retraction, lowering, narrowing or expiry is gone, the bot's waiting changes show, and the thread decays by its claims again. Renewals (claims) are collected through a hold, a retraction included, so a lapsed thread is judged with every renewal counted.

A lapse is judged in two places, both needed:

- **At the end, by the checkpoint's clock** (`pull.active`, the clock of `head_clock`, as expiry is): a hold lapses when the newest accepted checkpoint is issued after `held_until` and lists the root. With no checkpoint nothing lapses. A frozen mirror therefore pins a curator's lowering, and the reader says the feed is unverified, as for expiry.
- **During replay, by the curator's own dates**: a curator's reply dated after `held_until` meets the thread already lapsed. Without this a curator's later title fix would bring back a lowering that had lapsed. Only a curator's reply does this. A relay-bot reply, however it is dated, never ends a hold in replay: a stored event dated years ahead (an older reader admitted such events) would otherwise undo every curator correction of its thread.

A curator renews by posting the action again (see 5). A hold that lapsed is not renewed by a later, different action.

### 3. A published lowering

The level a thread's signers last published, when it is below the widest state's level, is carried as `Thread.offered`:

- a relay-bot reply whose block is exactly `{"level": "<lower>"}` (the form `spec/wire.md` rule 1 fixes; today counted `bad-patch` and skipped) sets it and changes nothing else;
- a curator's `level:` line or patch level sets it;
- a curator's `retract` sets it to `none`;
- any reply that names a level at or above the widest state's clears it.

`offered` is an offer, never applied by replay. Without a member check it changes nothing.

### 4. The member's check decides

`pull.active(threads, now, listed, check)` takes `check(adv, level) -> True | False | None`: whether the sources confirm, contradict or do not settle "this advisory at this level" (`none` for a retraction). `pull` does not import `verify`; the CLI passes the function.

The advisory asked about is `pull.widest(thread)`: the widest state with every alias the thread has held (`Thread.held_aliases`) and, for a product whose entry states no fixed version, the first one the thread stated (`Thread.held_fixed`). Both matter because the signer of a lowering also signs what the check reads. The source's level is held to what the post can be acted on with (`Ruleset.action_level`, ai-tools-alerts#9kgk), and a relay-bot reply may clear `fixed` (a widening for matching): judged against that, a KEV listing would give `high` and confirm a lowering of a critical the same key then signs. Nothing else of the asked state can be weakened by a reply: products and actions are joined, and the first id cannot change.

`pull.standing(thread, now, check)` gives the thread as it stands:

| Hold | What is asked | Check says | Shown |
|---|---|---|---|
| in force | the held level if below the widest, or `none` if retracted | contradicts | the widest state, whole; `refused` names the level |
| in force | same | confirms, or does not settle; or nothing is asked (a raise, a narrowing) | the held state |
| lapsed or none | `offered` | confirms | the widest state at `offered` (retracted if `none`) |
| lapsed or none | `offered` | contradicts | the widest state; `refused` names the level |
| lapsed or none | `offered` | does not settle | the widest state |

So a curator's lowering or retraction that the member's source contradicts never applies; a lowering the source confirms stands after the hold, as a bot's does; one the member cannot check, and every retraction, holds 14 days and lapses. A curator's narrowing of `products`, `fixed`, `actions` or an expiry is not something the source check compares yet (ai-tools-alerts#tavj), so it is always the 14-day case. When a curator's lowering is contradicted the whole held state is set aside, so a narrowing sent with it does not survive it.

`verify.lowering(adv, level, cache, now)` is that function, over the results of the asked state (`verify.at_level(adv, level)`):

- **False** when any product is `below-source` (a source supports more), however old the result: too high is the safe side.
- **True** only when all of this holds:
  - every product's result is `match`: its sources were read whole and an authority gives exactly that level. A source that gives less than the lowered level confirms nothing here (ai-tools-alerts#tavj tells a withdrawal from a level that rests on a reading).
  - the level is not below the ruleset's `reading_cap` (`high`). The poster may hold an alert at up to that level on its reading of the source's prose, which no member can see, and its own recompute never lowers below that floor. Fields that give `notice` therefore prove nothing about a `high`, and a lowering to `notice`, or a retraction, is never confirmed. What can be confirmed today is a lowering from critical to high.
  - the result is at most `FRESH_S` (48 hours) old by this machine's clock, and not dated ahead of it.
- **None** otherwise, with `verify = "off"`, and for a CLI the trust root calls too old.

A result that authorises a lowering must not outlive the source's change. `verify.run(..., recheck=asked)` reads every asked state again once its result is a day old, a confirmed one too (today a `match` is never read again). A failed read is `unread` at once, as for every state, so the lowering stops applying until a read succeeds; a result that could not be refreshed stops counting after 48 hours.

`verify.judge` learns one thing for the level `none`: it is `match` only when a source that may lower names the product and supports nothing for it (a withdrawn advisory). A catalog that does not list the CVE, an unreviewed advisory and an advisory that does not name the product leave it `unauthoritative`. The reader never applies a `none` on a `match` anyway (the cap above); the result is only reported.

The CLI asks for these states in `verify.run` beside the shown ones (all of them with `verify = "all"`, those whose widest state matches this machine with `matched`), inside the same budget of 10 requests and 30 seconds.

`run` (the hourly job's form) computes its matches and sends its notifications before any source is read, and that stays: a critical never waits for a source. When a lowering was asked about, `run` then builds the matches again from what the sources just said and notifies a critical that only now shows, in the same invocation, with the same exit status 2. `run --json`, the session-start hook's command, reads no source and applies what the last hourly run left in the cache.

The CLI prints one line per refused lowering, from fixed words, the normalised id, scope product names and level words only:

    source check: a lowering of <id> to <level> is not applied: the source supports <level> for <product>
    source check: a retraction of <id> is not applied: the source supports <level> for <product>

and `check --json` / `run --json` carry `"lowering_refused": "<level>" | null` on each match (`"none"` for a retraction).

### 5. The curator command

- `curator amend` and `curator retract` work on the thread as it stands at the command's clock (`pull.standing(t, now)`): after a lapse the amendment is written against the widest state, which is what readers hold.
- `curator renew <ref>` re-signs what is held: `retract` for a retracted thread; otherwise a `level:` line when the held level is below the widest, and a patch of every field in which the held state differs from the widest. With nothing held it refuses ("nothing to renew").
- After an amendment, retraction or renewal of a relay-bot thread it prints when the hold ends and that a member whose source check contradicts it keeps the higher level.

### 6. Other readers of threads

`mirror/export_mirror.py` (`_threads`) and the poster's `_withdrawn` take `pull.standing(t, now)` with their own clock and no check, so a lapsed retraction is no longer shown as retracted on the mirror page and no longer keeps the poster off the thread. The Atom feed's withdrawal entries are built from the retraction events themselves and are not changed here (follow-up issue).

## Success criteria

1. A curator `level: notice` on a relay-bot critical whose KEV fixture lists the CVE for the product: after the source check the CLI shows critical and prints the refused-lowering line.
2. A curator raise, then 15 days later a relay-bot `{"level": "high"}` reply, with a source that gives `high`: the CLI shows high. The same with the source unread or giving more: critical. The same reply inside the 14 days: critical until the hold lapses.
2a. What a stolen relay-bot key must not get, each a test: clearing `fixed` and then lowering a KEV critical; lowering a `high` to `notice` when the fields give notice; a lowering confirmed once and the source then raised; a retraction "confirmed" by a catalog that does not list the CVE or by an unreviewed advisory.
2b. A curator's lowering that the source contradicts is shown at the higher level and notified in the same `run` that reads the source.
3. A curator retraction of a relay-bot thread whose id names no source: retracted under a checkpoint at day 13, shown again under a checkpoint after day 14; with a second `retract` at day 10, still retracted at day 20.
4. A relay-bot raise during a hold shows at once; another relay-bot change shows only after the hold.
5. A curator's own thread behaves exactly as before; a relay-bot thread a curator amended is never auto-applied.
6. `tests/test_wire_compat.py` passes, with a new case for the one place a released reader may now show less than this one: a relay-bot thread a curator lowered, after the hold. `scripts/test-gate.sh` passes.

## Alternatives considered

- **Leave the member check to tavj and ship only the hold.** Two of the three acceptance cases would not hold, and a stolen curator key would keep 14 renewable days on every thread with a readable source. Rejected.
- **Build all of tavj here.** Over twice the size; the 72-hour rule and the interrupt cap need their own state files. Rejected; the seam (`offered`, `check`) is what tavj extends.
- **Two replays (one per state).** Wrong when a curator acts again after a lapse: the second action would be applied on top of the lapsed one. Rejected for the single replay with event-date lapse.
- **Judge the lapse by the machine's clock.** A clock set back would keep a lowering; a clock set forward would end a hold the checkpoint has not reached. The checkpoint clock is the rule expiry already follows (ai-tools-alerts#r0ra). Rejected.
- **Time-box a curator's own thread too.** See Scope. Rejected.
- **Let a source that gives less than the lowered level confirm it** (the first draft). A thread held at `high` on a reading would be lowered by its own fields. Rejected for `match` at or above `reading_cap`.

## What this does not close

- A curator key can still renew a hold every 14 days where no source can be checked, and narrow `products` unchecked for 14 days. The answer to that is the manifest with no curator (Joi's hand action in the issue) and the dedicated key (ai-tools-alerts#r98k).
- A member with `verify = "off"`, or one who cannot reach the sources, holds a curator's lowering for 14 days and never applies a relay-bot lowering (ai-tools-alerts#tavj adds the 72-hour rule).
- Released readers (0.1.7 and earlier, and the current release) keep a curator's word for good and keep the bot silenced. On a thread a curator lowered or retracted, a released reader can therefore show less than this reader. `spec/wire.md` says so.

## Blast radius and rollback

Reader behaviour changes only on relay-bot threads a curator has replied to (none exist on the feed) and on threads with a relay-bot level-only lowering (the poster sends these since ny5g; they now apply on a member whose source check confirms them). No wire format, schema, manifest or state file changes. Rollback is a revert of the merge.

## Review

One independent review of this spec (2026-11-24) found three blockers and three substantive gaps, all fixed above: the cleared `fixed` version, the level a reading may hold, the age of a confirming result, a retraction read as confirmed from a source's silence, the same-run application in `run`, and the compatibility test. The run record lists them.

## Open questions

None that block. Whether a raise should undo a retraction during its hold is decided no (an honest retraction would otherwise be undone by the next recompute).
