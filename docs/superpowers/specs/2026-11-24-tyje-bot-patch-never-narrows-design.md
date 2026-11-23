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
4. A patch that narrows one field and changes others (a title, a level raise) applies the others; the narrowed field keeps its value. The patch is counted under `narrowing` in the `dropped` counter that `advisories` and `threads_from` take.
5. Every existing test passes unchanged, the curator tests among them: a curator patch still replaces fields whole.
6. No change to the block, the schema, the event format or the poster. Released readers are unaffected; what they do is stated in the changelog.

## The rule

A patch from a key that is not a curator's is validated as today. Then three fields are compared with the thread's current value, each on its own. A field whose patched value would shrink what a member sees keeps its current value; the rest of the patch applies. One held field or three, the patch counts once as `narrowing`.

Because every accepted change keeps what was there, the thread's current value of each field is the widest signed state the thread has had. No history is stored.

### products

The patched list is accepted when every current entry `p` is covered by some patched entry `q`:

- same `ecosystem`, and the same `name` compared in lower case (the comparison `check.match` makes; an alias spelling of the same tool is not accepted as the same name, which is the strict direction);
- `q`'s version range covers `p`'s (below);
- `q.fixed` is not lower than `p.fixed`, judged apart from the range: it is null, or the same string, or both are readable by `versions.parse` and `q`'s is higher. Null (no version is known to fix it) is the highest value: it may be reached, never left. The range test alone does not give this. With `affected: "<2.0"` and `fixed: "3.0"`, a patch to `fixed: "2.0"` leaves the match set as it was, and `check.plan`, which takes an upgrade's version from `fixed`, would then tell the member to upgrade to 2.0 (spec review, blocker 1).

So a patch may add an entry, widen `affected`, raise `fixed` or clear `fixed` to null (no upper bound; the member is told to upgrade with no version, which is not silence). It may not remove an entry, narrow `affected`, lower `fixed`, or set `fixed` where there was none: that last one takes every member at or above the new version out of the match set, and a signer who wants silence would set it to `0.0.1`. A real fix published later for an alert with no fixed version is such a patch, and the reader holds it back until the member check of ai-tools-alerts#h29n can confirm it, or a curator signs it. The cost is a member on the fixed version who still sees the alert. That is the safe direction.

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

The patched list is accepted when every current action is kept: a patched action with the same `verb` and `target` and the same `value`. One exception: an `upgrade` whose value rises (both values readable by `versions.parse`, the new one higher) is kept, so the action can follow a raised `fixed`. An upgrade with no version cannot gain one, for the reason `fixed` cannot.

### sources

The patched list is accepted when every current URL is still in it. `published_at` may change. A patch may add a source, in any position.

### Limits that stay

- The list sizes are the schema's (50 products, 20 actions, 20 sources). A patch over them fails validation whole, as today.
- `level` down and `expires_at` stay refused whole, as today (`bad-patch`). Their replacement is ai-tools-alerts#h29n's.
- A curator's patch is not compared: it replaces each field it names, whole, exactly as today.
- A field a curator's patch omits stays as the reader holds it. After a relay-bot narrowing that the reader held back, that is the wide value, where a released reader would carry the narrowed one into the curator's amendment. This is on purpose (spec review, finding 2, rebutted): the curator signed the fields the patch names, and the omitted field's narrowed value was the bot's word alone. Reading the curator's patch against the narrowed state would let any later curator amendment, a title correction for instance, put a forged narrowing into force. A curator who agrees with a narrowing signs it: the amendment names the field. The `curator` command reads threads through this reader, so a curator sees the held state when amending.
- Once a curator has posted in or amended a thread, a relay-bot patch there is discussion, as today.

## Where it lives

- `aitools_alerts/versions.py`: `covers`, with the bound reading. The module already owns the range grammar.
- `aitools_alerts/pull.py`: `_apply_patch` gains the comparison for non-curator roles and an optional `dropped` counter; `threads_from` passes its counter. `threads_from` is also what the mirror exporter and the poster's translation pass call, so the Atom feed and the mirror page hold the same state as the CLI.
- No change to `schema.py`, `check.py`, `poster/`, `curator.py` or `spec/`.

## Alternatives considered

- **Refuse the whole patch** (`bad-patch`) when any field narrows. Simplest, but a real correction that raises the level and also lowers `fixed` would lose the raise. The issue asks for the rest of the patch to apply.
- **Keep both entries** (the patched list plus every current entry it does not cover). The match set is then exactly the union, and an added product survives beside a narrowed one. Rejected: a signer's junk entries enter the thread, the list grows towards the schema's 50 and then every later patch fails validation, a member can match twice with two different fixed versions, and code that reads `products[0]` (the notification, the curator's amendment) would read whichever entry came first. Holding the field leaves a narrowing patch with no effect on it at all, which is easier to reason about. A poster that wants a union can send one.
- **Store the thread's history and compute the widest state when reading.** The same result as holding the field, with more state.
- **Refuse in the poster.** The poster is not where a stolen key signs.

## What this does not do

- It does not judge a patch against the source. A narrowing that is true (the vendor lowered the fixed version) is held back like a forged one, until ai-tools-alerts#h29n's member check or a curator.
- A relay-bot patch may add a second entry for a product already listed, with a lower `fixed`. A member inside both ranges then matches twice and is shown both upgrades, the original among them. Confusing, not silent; a bot can also post a second root.
- A relay-bot patch may still change `title`, `aliases` and `advisory_severity`, and may add a source that a reader shows first. Those are outside finding D1; noted on ai-tools-alerts#h29n.
- Released readers (0.1.6 and earlier) apply a narrowing patch whole. Members get the rule when a release carries it: a rollout issue is filed, no release is cut here.
- The poster's ledger records what the poster sent, so after a held narrowing the ledger and the readers differ on that field. The poster does not resend (it compares against its ledger). Noted on ai-tools-alerts#ny5g, which owns the poster's lowering rules.

## Blast radius and rollback

Reader-side, pure functions, no state format change. A thread whose bot patches all widen reads exactly as before. A thread with a past bot narrowing reads wider after the upgrade than before (the stored events are replayed under the new rule on every read). Rollback is reverting the commit; no stored data depends on it.

## Tests

`tests/test_bot_patch.py`: the four acceptance patches end to end (mirror, pull, advisories, `check.match`, `check.plan`); the raise of `fixed`; add product, widen `affected`, add action, add source; `fixed` set where there was none is held; `fixed` lowered or set inside an unchanged range is held, asserted on the plan; a curator's amendment after a held narrowing leaves the omitted field wide; a mixed patch applies the rest and counts `narrowing`; a curator's narrowing applies; a bot narrowing on a curator-amended thread stays discussion. `tests/test_check.py` (where the version tests are): a table for `versions.covers`, each of the eight cases.

## Open questions

None blocking.
