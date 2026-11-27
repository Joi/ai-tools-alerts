# A former product name is read the same way by the poster and by a member's check (ai-tools-alerts#aabw)

Date: 2026-11-27. Base: main at `dd4d195` (release v0.3.0 pinned; gtw9 landed). Standing ruling (2026-11-23): the service runs with no human in the loop.

## Problem

A thread keeps the product name it was posted under. When the scope file renamed a product (wa6n), the entry kept the old name in `formerly`: "MCP Inspector", "MCP TypeScript SDK" and "MCP Python SDK" each on one entry, "MCP servers and clients" on seven. For a thread under one of these names:

- The poster's recompute does not judge it. `Run._judge` calls `rules.scope_named(e.scope)` without `former` (decided in zmg2). The thread is raised only when a candidate for its advisory is sighted again and is never lowered by the recompute. Since gtw9 an enrolled thread nothing confirms is stepped down after 45 days, and an unjudged thread is never confirmed, so a correct level on such a thread also decays.
- A member's source check answers `unknown`, why `no-source`. `verify.scope_of` (`check.scope_name`, 2mgd) resolves current names only, and `verify.judge` refuses a name outside `Ruleset.products()`. A `no-source` result is never read again (`verify._waits`).

19 of the first 28 alerts were MCP items, so this is a large share of the open threads.

One part of the system already reads former names: `Ruleset.level` and `Ruleset.action_level` take a former name to stand for every entry that lists it (wa6n), so a signed claim about such a thread is computed, and checked by a member (`ruleset.check_claim`), over those entries. The poster's recompute and the member's source check are the two readers that do not.

Prior work searched: `kata search "former name member check"` (aabw, zmg2, 3qyq, q03f, 3t4p, qwpw), `kata search "formerly verify judge"` (aabw, 3qyq). The zmg2 spec (`docs/superpowers/specs/2026-11-26-zmg2-recompute-by-name-design.md`) rejected recomputing former names for one issue's scope and filed this one. The 2mgd spec left `formerly` names at `no-source`.

Where the issue text predates a landing: it says `verify.judge` refuses the name because of `Ruleset.products()`. Since 2mgd the name is refused one step earlier, by `check.scope_name`, which returns None for it; `judge` then receives None. The effect is the one the issue states.

## Decision: option (a), one rule for both sides

**A former name stands for every scope product whose entry lists it.** What a reading supports for the name is the highest it supports for any of them. This is the rule `Ruleset.level` already applies to a claim; the recompute and the member's check now apply the same one, through one function, `Ruleset.stands_for(name)`.

All four names are handled, "MCP servers and clients" included. No case is left out.

Why this is sound for a name seven entries share. zmg2 rejected it because "a lowering there would rest on the absence of support for seven products at once". That is not what the evidence is. The readings counted for a thread are those of the thread's own ids: its first id, and the ids its source ties to it (`sources.chosen`, `verify._Run.thread`). They are one advisory. Which of the seven servers that advisory is about is stated by the advisory's own package field, and the ruleset binds it. So:

- the thread's level is held by whichever of the seven its advisory names, at what the rules give that product;
- a lowering needs what it needs for any thread: every source read whole, each an authority, none supporting the level. An advisory that names none of the seven any more is the same evidence as an advisory that no longer names a single product;
- a withdrawn advisory still names its package and supports it at `none`, which is the "named and supports nothing" both sides require for a withdrawal.

The other half of zmg2's objection, "threads no member can check", is what this change removes.

Rejected:

- (b) Read only a former name one entry lists. It leaves "MCP servers and clients" unjudged, which is most of the MCP threads, and makes a second rule beside the one claims already use.
- (c) Re-post under the current name and let the old thread expire. It repeats an old advisory to every member as a new root, and the old thread stands unconfirmed until it expires.

## Success criteria

1. `Ruleset.stands_for(name)` returns the scope products a name stands for: `{name}` for a current product or component, the names of the entries that list it for a former name, the empty set for anything else. For every name, `Ruleset.level(readings, name)` equals the highest `level` over `stands_for(name)`.
2. Member: `verify.scope_of` resolves a posted product to a former name when `check.scope_name` gives nothing, the posted name equals exactly one former name in lower case (the comparison `check.match` uses) and every entry listing it has the product's ecosystem (`check.former_name`). `verify.judge` judges a name by `stands_for`. An action whose target is the former name in another spelling counts as naming it. `check.scope_name` and `check.match` do not change.
3. Poster: `Run._judge` resolves the thread with `rules.scope_named(e.scope, former=True)`; `recompute.support` counts a reading for the thread by `stands_for(scope.name)`.
4. Acceptance, through `main.run` with the fake relay, KEV and advisory API, then the member's `verify.run` against the same answers:
   - a thread under "MCP Inspector" whose advisory is withdrawn is lowered to notice after 24 hours of complete reads and not before, once; the member's check of the lowered thread says `confirmed`, why `withdrawn`; `verify.lowering` to notice is True for the thread's state before the lowering when its higher level carries the poster's claim;
   - the same for a thread under "MCP servers and clients" whose advisory names `mcp-server-git`;
   - a thread under "MCP servers and clients" whose advisory supports its level is not lowered, starts no wait, and the member's check says `confirmed`, why `match`;
   - a thread under "MCP servers and clients" whose advisory comes to support more is raised in that run, and the member's check confirms the new level;
   - an enrolled thread (one with a standing claim, gtw9) under either name, whose advisory supports its level, is renewed over 90 daily runs with a new confirmation each time (`confirmed_at` is the run's time), is never stepped down, and a reader computing from the claims sent keeps it at its level every day; with every read failing, its renewals keep the old confirmation date and it steps down at the 45-day ceiling like any thread.
5. A name that is in no `formerly` list and is no product stays unjudged on both sides (`no-source`; not read by the poster).
6. The member's cache is rebuilt once (`verify.VERSION` 6), so a stored `no-source` for a former-name thread is read again. A test stores that result under version 6 (it is never read again) and under version 5 (the cache is dropped and the thread is read and confirmed).
7. Every other existing test passes unchanged, except three: the two that pin the old decision (`test_a_thread_under_a_former_name_is_not_judged`, removed; the "MCP servers and clients" case of `test_a_product_that_is_no_scope_product_is_not_judged`, replaced), and `test_a_cache_of_the_version_before_is_an_empty_one`, whose version numbers become 6 and 5. `scripts/test-gate.sh` exits 0.

## Approach

### `aitools_alerts/ruleset.py`

`stands_for(product) -> frozenset[str]`: `{product}` when it is in `products()`, else `frozenset(self._former.get(product, ()))`. `schema.load_scope` already refuses a `formerly` name that is a product of the file, so the two cases never overlap. `level` and `action_level` are not changed; a test holds them equal to the new function's reading.

### Member: `aitools_alerts/check.py`, `aitools_alerts/verify.py`

- `check.former_name(name, ecosystem)`: the former name the posted name is, in the scope file's spelling, or None. One former name must equal it in lower case, and every entry that lists that name must have this ecosystem, so the answer never depends on which entry is looked at. Never raises.
- `verify.scope_of(product)`: `check.scope_name(...)`, else `check.former_name(...)`. A current product wins, as it does everywhere else.
- `verify.judge(level, product, ...)`: `names = rs.stands_for(product)`; none: `no-source`, as now. Per record, each product of `names` the record supports is taken as the one product is today: support that may lower sets the level, the highest wins, `stop_using` is carried from the support that gives that level; the record may lower only when every one of them may (a record that supports none: its own `lowers`, as now). For a current name this is the code as it stands.
- `_Target.judge` resolves an action's target with the same lookup as the product (`_resolved`), so a target spelled `mcp inspector` names "MCP Inspector". `Ruleset.action_level` already compares targets with the former name.
- `_Run.thread.weight` (which alias is read first) reads the support of every product the thread's names stand for.
- `VERSION = 6`.

Not changed: the version ranges kept for a narrowing (`_Run.thread.pairs`, `verify.narrowing`). A former name has no ranges under its own name, so a narrowing of such a thread is not settled by the check, as today.

### Member: `aitools_alerts/cli.py`

`_source_lines` printed a line only for a name in `Ruleset.products()`. The CLI's "never supported shows at notice" (0z4e, `_shown`) works by result key, so a former-name thread whose result is now `unsupported` is shown at notice; without its line nothing would say why. The filter becomes "a name the scope file has": `bool(rs.stands_for(name))`. The name printed is the former name in the scope file's spelling (`verify.scope_of` returns that), never the signer's text. Found while writing the changelog, after the spec's review; the whole-branch review reads it.

### Poster: `aitools_alerts/poster/main.py`, `aitools_alerts/poster/recompute.py`

- `_judge`: `rules.scope_named(e.scope, former=True)`. The entry it returns carries the former name; `recompute` reads only `scope.name`.
- `recompute.support`: `names = rs.stands_for(scope.name)`. An advisory response: the supports it holds for `names`; it is counted only when every one may lower (none held: the response's own `lowers`), and then each support above `none` raises `found`, with `stop` as today. A KEV entry: the catalog names one product; it counts when that product is in `names`.
- `held` and `judge` already work on `scope.name`: `Ruleset.action_level` reads a former name, and the thread's published actions name the former name, because the thread was composed under it.

The poster stays the stricter side: a response in which one of the names has support that cannot lower is not counted at all by the poster, while the member still counts the others' support as a lower bound. So the poster publishes no level a member's check does not find.

## What changes for threads already posted

On the first run after this lands, every former-name thread with an advisory id or the exploited mark is judged for the first time.

- A raise publishes in that run, as for any thread, and a feed-only thread raised to critical gets its copy (3t4p; under "MCP servers and clients" the copy names no package, `Run._scope_named`).
- A lowering takes what ny5g and 3qyq require: every source read whole, 24 hours of complete reads, seven quiet days, the circuit breaker. A thread recorded before the ledger kept a floor is never lowered below `reading_cap` (high) or its own level, whichever is lower (`recompute.floor`).
- An enrolled thread can now be confirmed, so a correct level is renewed and no longer stepped down for want of a check (gtw9).
- The advisory lanes have these threads in their rotation. More threads than a lane's share delays reads; it never lowers anything.
- A member's reader rebuilds its source-check cache once and reads former-name threads like the others, within its 30 seconds and 10 requests a run (`verify.MAX_FETCHES`).

A reader of an earlier release still answers `no-source` for these threads. For it nothing changes when the thread is raised. A lowering by the relay bot is, for it, one nobody has checked, as a lowering of any thread it cannot read is today.

## Alternatives considered

Options (b) and (c) above. Also: resolve former names inside `check.scope_name`. Rejected: `check.match` uses it to decide which product entries collapse for one installation, and `cli` uses it for the per-product lines; this issue is about which level a thread's sources support, so the lookup is widened only where a level is judged.

## Blast radius and rollback

Six source files (`ruleset.py`, `check.py`, `verify.py`, `cli.py`, `poster/recompute.py`, `poster/main.py`), tests, the changelog. No wire format, schema, ruleset, scope file or ledger change; the ruleset digest the trust root pins is the same. The member's cache file is rebuilt once by the version change, as for versions 4 and 5.

Rollback is a revert. The older poster pauses the waits the newer one started (`recompute.pause`) and judges those threads no more; the older reader rebuilds its cache again. A level change already published stays published.

Rollout: the change ships with the next release (ai-tools-alerts#5fry). No install or signing step of its own.

## Review dispositions (spec, one independent pass, gpt-6.1-sol)

1. BLOCKER, criterion 7 allowed two tests to change and the cache version needs a third. Fixed: criterion 7 names `test_a_cache_of_the_version_before_is_an_empty_one`, and criterion 6 has its own test with a stored `no-source` (`test_a_no_source_stored_for_a_former_name_by_the_version_before_is_read_again`). A change to this document and the tests; no behaviour of the design changed.
2. SUBSTANTIVE, the renewal claim had no acceptance test. Fixed: the last case of criterion 4, two tests in `tests/poster/test_former_names.py`.
3. SUBSTANTIVE, the message of the snapshot commit ("do-it review snapshot"). Rebutted: a dangling commit made for the reviewer with `git commit-tree`; it is on no branch and never lands.
4. COSMETIC, the member's request limit is 10, not 20. Fixed.

## Open questions

None that blocks.
