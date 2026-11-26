# A respelled product cannot make a relay-bot post unjudgeable (ai-tools-alerts#2mgd)

## Problem

The member's source check (`aitools_alerts/verify.py`, ai-tools-alerts#fv4g) gives every
product of a relay-bot thread one of `confirmed`, `contradicted`, `unknown`. Whoever
signs a relay-bot post can force `unknown` for good. The issue names three ways. Two go
through the aliases of a CVE first id and are now ai-tools-alerts#nx25 (split on
2026-11-26, see Review). This design is the third and the decision the issue asks for:

**A respelled product.** `check.match` matches an installation by lower-cased names and
tool identities (`claude code`, `claude-code`); `verify.judge` judges only the exact
scope name and gives `no-source` for anything else.

An alert that stays `unknown` is never confirmed, never contradicted, and interrupts as
unverified inside the two interrupts per poster key per 24 hours (tavj). Once
ai-tools-alerts#0z4e lands, it is also never shown at notice.

Standing ruling (2026-11-23): no human in the loop. Nothing here waits for a person.

## Success criteria

Tests in `scripts/test-gate.sh`:

- A relay-bot critical for `claude code` (lower case, ecosystem `claude-code`), CVE
  first id, that the catalog lists for another vendor, is `contradicted`, why
  `unsupported`, exactly like one for `Claude Code`; listed for the product, it is `confirmed`.
- A product entry added under another ecosystem with the same name does not change the
  genuine product's result, its interrupt, or the refusal of a lowering, in the check
  and through a signed thread.
- A relay-bot critical whose matched product resolves to no scope product does not
  interrupt when this CLI's ruleset is the pinned one: no exit 2, no notification, no
  slot, with an empty cache, in `run`, `run --json` and `notify`; `check` lists it and
  says why. Under an older permitted ruleset, with no pin, or with `verify = "off"`, it
  interrupts as unverified.
- Respellings of one product share the one verified slot of that advisory and product.
- A run cut off by the request budget leaves a product `unread`, and the next run judges it.

"Shows at notice" in the issue's acceptance is 0z4e's behaviour for `contradicted`,
`unsupported`; this change delivers the result 0z4e keys on. 0z4e is not on main.

## Approach

### 1. One product identity (`check.scope_name`, used by `verify`)

`check.match` matches product `P` to installation `I` when `P.name.lower()` is in
`_aliases(P.ecosystem, I)`. Two posted names are the same product for matching when no
installation can tell them apart. The scope product `S` that `P` resolves to is defined
by that same rule, with no installation in hand:

- `S` is a scope product (a name `Ruleset.products()` holds) whose entry has ecosystem `P.ecosystem`, and
- `S.lower() == P.name.lower()`; or the ecosystem is a tool's (not `skill`, not `mcp`)
  and both `S.lower()` and `P.name.lower()` are in `IDENTITY[ecosystem] | {ecosystem}`;
  or the ecosystem is `mcp` and `P.name.lower()` is the scope product's `package`.

Exactly one such `S`: `P` resolves to it. None or more than one: `P` resolves to nothing.
The ecosystem is part of the identity: `Claude Code` posted under ecosystem `skill`
matches an installed skill of that name and is not the tool, so the tool's KEV listing
must not confirm it. `formerly` names do not resolve (they stand for several entries and
match no installation by name); they stay `no-source`, as today.

**Results are per product identity, not per name.** A result is keyed by
`verify.pkey(product)`, the ecosystem and the posted name. Two entries that share a
name under different ecosystems are two products with two results, so adding
`Claude Code` under `skill` to a thread leaves the tool's result, its interrupt and a
`below-source` refusal of a lowering as they were (bot patches join product lists,
`pull._join`, so such an entry can be added and never removed). Callers look a match up
by `pkey(m.product)`. `fixed` is kept per identity too. `judge` receives the scope name;
`None` gives `unknown`, `no-source`. Action targets are resolved by the same function in
the product's ecosystem before `Ruleset.action_level` compares them, so a respelled true
critical with its upgrade action is not held to `action_cap`. The state key lists the
identities. The fallback of `run` for an exhausted request budget judges through the
thread's own keys, so it stays `unread`.

**The thread history a lowering is checked with** (`pull._Hold.note`, `_missing`,
`widest`) is keyed by ecosystem and name as well. Today it is keyed by name: with the
ecosystem now part of the judged identity, an entry `Claude Code` under `skill` would
pass for the tool's original entry, the original (with its fixed version) would not be
restored to the widest state, and a respelled entry with no fixed version would be
judged in its place, held to `action_cap`: no `below-source`, and the lowering would
apply after 72 hours.

In the CLI: `_verified_bucket` uses the scope name, so `Claude Code`, `claude code` and
`claude-code` share one verified slot per advisory. `_source_lines` prints the scope
name. A match whose product resolves to nothing never borrows a result: `_result` gives
`unknown` for it.

### 2. A match that cannot be judged by construction does not interrupt

Decision asked by the issue. A relay-bot match cannot be judged by construction when its
product resolves to no scope product or the alert's first id names no source
(`verify.norm_id` gives `None`). Both are the signer's choice; neither is a network
failure. The CLI decides this from the post alone, before any slot is granted and with
no look at the cache, so it holds on first sight, in `run --json` (which reads no
source) and in `notify`.

Such a match is left out of `_interrupts` (not pending, not held, no slot) when all of
these hold: the check is on (`verify` is not `off`); the trust root does not call this
CLI too old (`min_cli`); the trust root pins a ruleset; and this CLI's ruleset is that
one, same version and same digest. The digest covers the scope file, so only then is
"resolves to nothing" a fact about the post and not about this reader:
`ruleset.outdated` lets a reader below the pinned version (and at or above
`min_version`) run with another scope file, and such a reader, a reader above the pin,
and a reader with no pin interrupt as unverified, as today. The alert is still listed at
its level by `check`, with one line:
`source check: <id> names a product or an id this check cannot judge: no interrupt`.

Why not keep the unverified interrupt: the cap of two per key per day is exactly what
the respelling buys, every day, with no contradiction and so no strike (m729). An honest
relay bot posts scope names and ids the ruleset has a source for: a critical never rests
on a reading (`reading_cap`).

Rejected: showing it at notice (0z4e's demotion needs a source's word; here there is
none); counting it against the key (m729's subject).

### Cache

`verify.json` version 4: results keyed by product identity. The cache is rebuilt once.
No wire format, schema or manifest change.

## Alternatives considered

- **Resolve through the ruleset's scope index (`match` identities).** Not the rule
  `check.match` uses: the index holds `codex cli` but not `codex`, and component
  identities the tool's installation does not carry. Two rules is the bug.
- **Change `check.match` to the scope index.** Changes which curator alerts match; outside this issue.
- **Results keyed by posted name, a colliding name resolving to nothing.** One added
  product entry would erase a genuine product's result (review of this spec, finding 1).
- **Decide "cannot be judged" from the cached result (`no-source`).** An empty cache
  says `unread`, and `run` grants slots before it reads a source (review, finding 6).

## Blast radius and rollback

Member CLI only: `aitools_alerts/check.py`, `verify.py`, `cli.py`, `pull.py` (the history
keys), tests, CHANGELOG, README. A released reader is unaffected. Rollback: revert the
merge; the cache version makes the older code rebuild its cache. No rollout here: the
release session ships it (comment on ai-tools-alerts#fa5a).

## Assumes

- The relay bot posts each product under its scope name and the scope entry's ecosystem.
- Release order: the trust root pins a new scope file before the relay bot posts under
  it. A bot that posts a product of a newer scope file than the pinned one is, to a
  member on the pinned one, posting a product that is no scope product: listed, no
  interrupt. The release session is told on ai-tools-alerts#fa5a.
- A relay-bot synthetic check (an id `schema.is_synthetic` knows) names no source, so
  under the pinned ruleset it is listed and does not interrupt. Exempting synthetic
  ids would hand the signer the unverified interrupts back.
- 0z4e lands separately and may conflict in `cli.py` (it looks results up by product
  name); main is merged before review and before merge.

## Open questions

- A relay-bot critical whose GHSA first id answers 404 stays `unread` and interrupts as
  unverified. Whether a first id the source does not have should interrupt is not decided here.

## Review

One independent pass (gpt-6.1-sol) on snapshot b8f9cc7: six findings on the design, all
taken. 1: results per identity. 5: the pinned-digest condition. 6: decided from the
post, before any slot. 2, 3 and 4 concern the aliases; the alias design was rewritten
for them, and the plan review (snapshot 8192bab) then found that rewrite needs its own
scheduling design, with the work past 600 changed lines. The alias half is split to
ai-tools-alerts#nx25, which carries the design and every finding on it. A seventh
finding, the message of the review snapshot commit, is not about the design: the
snapshot is never pushed.
