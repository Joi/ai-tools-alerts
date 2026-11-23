# A relay-bot patch never shrinks what a member sees (ai-tools-alerts#tyje)

## Problem

A reply in a thread may carry an `aitools-alert` block of changed fields, a patch. `pull._apply_patch` replaces each field the patch names, whole. For a patch signed by a key whose manifest role is not `curator` it refuses two things: a lower `level` and any `expires_at`. Everything else applies.

The design review of 2026-11-23 (ai-tools-alerts#3mhj, finding D1, text on ai-tools-alerts#h29n) ran four patches against a relay-bot critical with the relay-bot key. All four are accepted:

| Patch | Effect on a member |
|---|---|
| `products[].fixed` changed from the real version to `0.0.1` | `check.match` needs the installed version below `fixed`: nobody matches |
| `products` replaced by a product nobody runs | nobody matches |
| `actions` emptied | the member matches and is told to do nothing |
| `sources` replaced by another https URL | the member is sent to a page the signer chose |

The thread still reads `critical`. Whoever holds the relay-bot key silences any bot alert with one signature. This is a gap in the released readers (0.1.6 and earlier), independent of the self-correcting design.

## Success criteria

1. For each of the four patches above, signed by the relay-bot key on a relay-bot critical and read through `pull.fetch` and `pull.advisories`: `check.match` still matches the member's installation, and `check.plan` still lists the upgrade action with the original fixed version. The thread's sources still contain the original URL.
2. A relay-bot patch that raises `fixed` (a real correction) applies, and the upgrade action follows it.
3. A relay-bot patch that adds a product, widens `affected`, adds an action or adds a source applies.
4. A patch that narrows one field and changes others (a title, a level raise) applies the others; nothing is taken from the narrowed field. The patch is counted under `narrowing` in the `dropped` counter that `advisories` and `threads_from` take.
4a. The result does not depend on the order the thread's relay-bot patches are read in: a patch dated before one already applied, and published after it, takes away nothing a member matched or was shown.
5. Every existing test passes unchanged, the curator tests among them: a curator patch still replaces fields whole.
6. No change to the block, the schema, the event format or the poster. Released readers are unaffected; what they do is stated in the changelog.

## The rule

A patch from a key that is not a curator's is validated as today. Its `products`, `actions` and `sources` then do not replace the thread's: each is joined to the thread's list. An entry of the patch that the thread's list already stands for adds nothing. Any other entry is appended, and replaces the entries it stands for. Nothing is removed otherwise. A patch whose list does not itself stand for every entry the thread held counts once as `narrowing`, however many fields.

"Stands for" is defined per field below, and is transitive, so an entry replaced by a wider one stays stood for when that one is replaced in turn. The thread's value of each field is therefore the widest state its signed patches have given it, and no history is stored.

### Why a join, and not "hold the field" (code review, blocker)

The first design compared the patched list with the thread's and, where it would narrow, kept the thread's list whole. That holds for one replay and fails across two. Every read rebuilds a thread from its events in `(created_at, id)` order, and the signer sets `created_at`. Root `<2.0`; a patch at time 200 widens to `<3.0`; a member on 2.5 matches. The holder of the key then publishes a patch dated 150 that adds an unrelated product. On the next read the patch dated 150 applies first, the patch dated 200 no longer names every product, its field is held, and the range is `<2.0` again. The reader admits an event dated in the past (it refuses only one dated ahead), so this needs nothing but the relay-bot key.

A join has no such order: every entry of every patch is stood for at the end, in whatever order they are read. For the same reason the three fields are joined even from a patch that is refused for another reason. A patch that lowers `level` or sets `expires_at`, or fails validation in another field, stays refused (`bad-patch`) and none of its other fields apply; its `products`, `actions` and `sources`, when valid, are still joined. Otherwise a patch dated earlier that raises the level would turn a later patch into a lowering and take its widening with it.

### products

An entry `q` stands for an entry `p` when:

- they have the same `ecosystem`, and the same `name` compared in lower case (the comparison `check.match` makes; an alias spelling of the same tool is another name, which is the strict direction);
- `q`'s version range covers `p`'s (below);
- `q.fixed` is not lower than `p.fixed`, judged apart from the range: it is null, or the same string, or both are readable by `versions.parse` and `q`'s is higher. Null (no version is known to fix it) is the highest value: it may be reached, never left. The range test alone does not give this. With `affected: "<2.0"` and `fixed: "3.0"`, a patch to `fixed: "2.0"` leaves the match set as it was, and `check.plan`, which takes an upgrade's version from `fixed`, would then tell the member to upgrade to 2.0 (spec review, blocker 1).

So a patch may add an entry, widen `affected`, raise `fixed` or clear `fixed` to null (no upper bound; the member is told to upgrade with no version, which is not silence): the wider entry replaces the one it stands for. An entry that is narrower than one the thread holds (a narrower `affected`, a lower `fixed`, a `fixed` where there was none) adds nothing. A patch that leaves an entry out removes nothing. An entry that neither stands for a held one nor is stood for by it is added beside it; a member inside both ranges then matches twice, the original match among them.

A `fixed` where there was none takes every member at or above the new version out of the match set, and a signer who wants silence would set it to `0.0.1`. A real fix published later for an alert with no fixed version is such a patch, and it adds nothing until the member check of ai-tools-alerts#h29n can confirm it, or a curator signs it. The cost is a member on the fixed version who still sees the alert. That is the safe direction.

### Range cover

`versions.covers(affected, fixed, by_affected, by_fixed)` is true only when it can show that every installation the first range matches is matched by the second with at least the same actions. It reads a range as bounds: each comparator and `fixed` (an exclusive upper bound) gives a lower or upper bound, `=` gives both. In order:

1. The two ranges are the same strings: covered.
2. The covering range is null and null (a match by name alone, with actions): covered.
3. The covered range is null and null: not covered. Any range drops the installations outside it, and an installation with an unreadable version loses its actions.
4. The covered range is unreadable (a comparator or `fixed` that `versions.parse` cannot order): it matches every installation as `unparsable-version`, with no actions. Covered only by another unreadable range or one with no bound on either side.
5. The covering range is unreadable: not covered (it would take the actions from every match).
6. The covered range is empty (its bounds cross): covered.
7. The covering range is empty: not covered.
8. Otherwise: the covering lower bound is absent or not above the covered one, and the covering upper bound is absent or not below it, with an inclusive bound counting as wider than an exclusive one at the same version.

The test is sufficient, not necessary: it may refuse a widening it cannot prove, never accept a narrowing.

### actions

An action `b` stands for an action `a` when they have the same `verb` and `target` and the same `value`. For `upgrade` the value is ordered as `fixed` is: `b` also stands for `a` when its version is higher (both readable) or it has none. So an upgrade can follow a raised `fixed`, an upgrade with no version cannot gain one, and a lower version adds nothing. A different value on another verb is another action and is added beside the first.

### sources

A source stands for another with the same URL. A patch may add a URL; it is appended, so the sources a thread already had keep their place. The first `published_at` read for a URL stays.

### Limits that stay

- The list sizes are the schema's (50 products, 20 actions, 20 sources) for what one event carries; a patch over them fails validation, as today. A joined list may pass them: capping the join would bring the order back (fill the list from an early date and a later widening no longer fits). A patch that omits a field is validated against the thread's list cut to the limit, then keeps the whole list, so a thread joined past the limit still takes a level raise or a curator's amendment. The store's own limits bound the total.
- `level` down and `expires_at` stay refused, as today (`bad-patch`); only the three joined fields of such a patch count. Their replacement is ai-tools-alerts#h29n's.
- A curator's patch is not compared: it replaces each field it names, whole, exactly as today.
- A field a curator's patch omits stays as the reader holds it. After a relay-bot narrowing that the reader did not apply, that is the wide value, where a released reader would carry the narrowed one into the curator's amendment. This is on purpose (spec review, finding 2, rebutted): the curator signed the fields the patch names, and the omitted field's narrowed value was the bot's word alone. Reading the curator's patch against the narrowed state would let any later curator amendment, a title correction for instance, put a forged narrowing into force. A curator who agrees with a narrowing signs it: the amendment names the field. The `curator` command reads threads through this reader, so a curator sees the held state when amending.
- Once a curator has posted in or amended a thread, a relay-bot patch there is discussion, as today.

## Where it lives

- `aitools_alerts/versions.py`: `covers`, with the bound reading. The module already owns the range grammar.
- `aitools_alerts/pull.py`: `_apply_patch` gains the join for non-curator roles and an optional `dropped` counter; `threads_from` passes its counter. `threads_from` is also what the mirror exporter and the poster's translation pass call, so the Atom feed and the mirror page hold the same state as the CLI.
- No change to `schema.py`, `check.py`, `poster/`, `curator.py` or `spec/`.

## Alternatives considered

- **Refuse the whole patch** (`bad-patch`) when any field narrows. Simplest, but a real correction that raises the level and also lowers `fixed` would lose the raise. The issue asks for the rest of the patch to apply.
- **Hold the field** (keep the thread's list whole when the patched one would narrow it). The first design here; a narrowing patch then has no effect on the field at all, and no junk entry enters a thread. Rejected in code review: it depends on the order patches are read in, which the signer controls (above).
- **Store the thread's history and compute the widest state when reading.** The join computes the same thing as it goes.
- **Order replies by arrival, not by `created_at`.** It would need a stored arrival order, differs between members, and changes how every thread reads.
- **Refuse in the poster.** The poster is not where a stolen key signs.

## What this does not do

- It does not judge a patch against the source. A narrowing that is true (the vendor lowered the fixed version) is left out like a forged one, until ai-tools-alerts#h29n's member check or a curator.
- A relay-bot patch may add entries: another product, a second entry for a product already listed with a lower `fixed`, an action, a source. A member inside two ranges matches twice and is shown both upgrades, the original among them. Confusing, not silent; a bot can also post a second root. Code that reads `products[0]` or `sources[0]` (a notification with no match, the curator's announcement) reads the thread's oldest surviving entry.
- A relay-bot patch may still change `title`, `aliases` and `advisory_severity`, and may add a source that a reader shows first. Those are outside finding D1; noted on ai-tools-alerts#h29n.
- Released readers (0.1.6 and earlier) apply a narrowing patch whole. Members get the rule when a release carries it: a rollout issue is filed, no release is cut here.
- The poster's ledger records what the poster sent, so after a narrowing the reader did not apply the ledger and the readers differ on that field. The poster does not resend (it compares against its ledger). Noted on ai-tools-alerts#ny5g, which owns the poster's lowering rules.

## Blast radius and rollback

Reader-side, pure functions, no state format change. A thread whose bot patches all widen reads exactly as before. A thread with a past bot narrowing reads wider after the upgrade than before (the stored events are replayed under the new rule on every read). Rollback is reverting the commit; no stored data depends on it.

## Tests

`tests/test_bot_patch.py`: the four acceptance patches end to end (mirror, pull, advisories, `check.match`, `check.plan`); the raise of `fixed`; add product, widen `affected`, add action, add source; narrower entries add nothing; `fixed` set where there was none, and lowered or set inside an unchanged range, asserted on the plan; lists of two entries losing one, with and without an addition; two-pull tests where a patch dated earlier arrives after an applied widening, for each field; a backdated level raise that turns a later patch into a lowering; every order of five product patches; a thread joined past the schema limit; a curator's amendment after a refused narrowing; a curator's narrowing applies; a bot narrowing on a curator-amended thread stays discussion; a table for `versions.covers`, a grid against `check.match`, and transitivity.

## Open questions

None blocking.
