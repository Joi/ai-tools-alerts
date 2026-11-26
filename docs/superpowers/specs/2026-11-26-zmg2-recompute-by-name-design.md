# The recompute resolves a thread's scope by its name (ai-tools-alerts#zmg2)

Date: 2026-11-26. Base: main at `8f91677` (release v0.2.1 plus tavj, 3qyq and jsje). Standing ruling (2026-11-23): the service runs with no human in the loop.

## Problem

Each run, the poster recomputes the level of every open thread that has a source to judge it by (`Run.observe`, `Run._judge`, `Run.recompute` in `aitools_alerts/poster/main.py`; the rules are `aitools_alerts/poster/recompute.py`). `_judge` finds the thread's scope entry with `rules.scope_of(e.scope)`.

`scope_of` answers a different question: "which scope entry is this text an identity of?" It looks the normalised text up among the scope file's `match` strings and package keys. A ledger entry's `scope` is not such a text. It is the entry's (or component's) display name, the one the post states and the ledger keys by. For most entries the name happens to be one of the identities. For these it is not, and `scope_of` returns None:

| Name | Class |
|---|---|
| Codex, Cursor, Hermes | channel |
| ClawHub and skills.sh | channel (never a thread's name: its components are) |
| mcp | catalog |
| Python, Go, Rust, git | out |

`_judge` reads None as "out of scope now", pauses the thread's wait and never judges it. So a Codex, Cursor or Hermes thread is never raised by the recompute when KEV or the advisory API comes to support more, and never lowered when its support falls. Nothing says so: the thread just stands. The three channel-class names are three of the six agent tools the service exists for.

`catalog._scope` already resolves a thread by its name (and by a former name, wa6n) and documents why it is not `scope_of`. ai-tools-alerts#3t4p uses it for the copy a thread's level lacks. The recompute is the one caller left on the wrong lookup.

Prior work searched: `kata search "former name recompute"` (zmg2, 3qyq, q03f), the issue's own searches (`scope_of display name`, `recompute Cursor`); 3qyq's note 5 on its own issue ("a thread kept under a product's former name is not recomputed: `rules.scope_of` does not resolve former names").

## Success criteria

1. `rules.scope_named(name, former=False)` returns the scope entry, or the entry resolved to a component, whose name is exactly `name`; None for anything else (a text that is an identity but not a name, such as `cursor ide`; a name in another case; a value that is not a string). With `former=True` it also resolves a name that an entry lists in `formerly`, to that entry carrying the former name, as `catalog._scope` does today.
2. For every value of the scope index, `scope_named(value.name).name == value.name`. A test walks the shipped scope file, so a name added later cannot fall out again.
3. `catalog._scope` is `rules.scope_named(name, former=True)`: one lookup for the catalog, the copy (3t4p, which calls `catalog._scope`) and the recompute. The catalog's behaviour does not change; its tests pass unchanged.
4. `Run._judge` resolves the thread with `rules.scope_named(e.scope)`. Acceptance, each a test through `main.run` with the fake relay, KEV and advisory API:
   - a Cursor thread whose advisory comes to support more (KEV lists the CVE its advisory names, dated before the watermark, so no candidate brings it) is raised by the recompute in that run, with no input record;
   - a Cursor thread whose support falls (a KEV critical the catalog stops listing) is lowered under ny5g's rules: after the 24 hours of complete reads and a later catalog version, not before, and to its floor;
   - a Hermes thread posted at high from its advisory's fields is lowered to notice when the reviewed advisory stops supporting high, on the same schedule as the Claude Code thread of `test_a_reviewed_advisory_that_stops_supporting_high_lowers_once`;
   - a thread whose product left the scope file is still not judged: no advisory read is made for it, no wait starts, no level moves.
5. A thread under a former name is still not judged (decision below), and a test says so.
6. Every existing test passes unchanged. `scripts/test-gate.sh` exits 0.

## Approach

`rules.scope_named` in `aitools_alerts/poster/rules.py`, beside `scope_of`: the body of today's `catalog._scope`, with the former-name branch behind a keyword. It reads `rules._default_index().values()`, which holds every entry reachable by an identity and every component resolved to its own name.

`catalog._scope` keeps its name and becomes a one-line call, so 3t4p's branch, which calls it, merges without a conflict of meaning.

`Run._judge`: `scope = rules.scope_named(e.scope) if recompute.judged(e) else None`. The test `scope.name != e.scope` that follows goes: the lookup is by exact name, so it cannot differ. `recompute.judge`, `support`, `held` and `raised` read only `scope.name`, so nothing else changes.

### Decision: a thread under a former name is not recomputed

`_judge` calls `scope_named` without `former`. Reasons:

- A member's check cannot judge such a thread. `verify.judge` returns `unknown`, why `no-source`, for a product name that is not in `Ruleset.products()`, and a former name is not. The recompute's rule since 3qyq is that the bot publishes no level a member's check could not confirm.
- A read's support is keyed by current names (`Ruleset.read`). "MCP servers and clients" is the former name of seven entries. Which one's support is the thread's is not something the thread states.
- It is what happens today (3qyq note 5), so nothing a member sees changes for those threads.

What it costs: a thread under "MCP servers and clients", "MCP Inspector", "MCP TypeScript SDK" or "MCP Python SDK" is raised only by a candidate (`plan_known`, through `Run._former`) and is never lowered by the recompute. It never falls wrongly; it can stand too high until its expiry. A follow-up issue records this for whoever takes the member's side of former names; it is not this issue's.

Rejected: recomputing a former-name thread against the highest support of the entries that list the name (as `Ruleset.level` reads a claim). It would publish raises and lowerings on threads no member can check, and a lowering there would rest on the absence of support for seven products at once.

## What changes for threads already posted

On the first run after this lands, threads under Codex, Cursor, Hermes, git, Python, Go, Rust and mcp that carry an advisory id or the exploited mark are judged for the first time.

- A raise publishes in that run, as for any other thread. That is the point of the change.
- A lowering takes what ny5g and 3qyq require of every thread: every source read whole, the same lower level over 24 hours of complete reads, seven quiet days, the circuit breaker. So the first lowering of such a thread is at least a day after landing, and many falling due at once trip the breaker like any others.
- The advisory lanes (ten reads each a run) now have these threads in their rotation. More threads than a lane's share delays reads; it never lowers anything.
- A level that rests on a reading of prose keeps its floor. Cursor has no package key, so an advisory response never names it; a Cursor thread's high from prose stays at its floor, and only KEV moves it above.

## Alternatives considered

- Add each display name to its entry's `match` list in `spec/scope.json`. It would make `scope_of("Cursor")` work, and it would also make the bare words "cursor", "codex", "hermes", "go", "python" and "git" identities for every candidate text, which h340 removed on purpose (a third-party product named with the word would bind). It changes the scope file's digest, which the trust root pins. Rejected.
- Keep `scope_of` and fall back to the name when it returns None. Two lookups with an order between them; a name that is another entry's identity would resolve to the wrong entry. Rejected for one exact lookup.
- Put the helper in `catalog.py` and import it into `main.py`. The recompute would depend on the catalog lane for a rule about the scope file. Rejected: `rules.py` owns scope lookups.

## Blast radius and rollback

Three source files (`rules.py`, `catalog.py`, `main.py`), one new test file, the changelog. No wire format, schema, state file, ruleset or scope file changes; the reader every member runs is not touched. No install, signing step or release is needed beyond the poster picking up the new code with the next release.

Rollback is a revert of the commit. The recompute state file has the same shape before and after, so the older code reads it. A wait started for a newly judged thread is not dropped by the older code: `recompute.pause` keeps the time it holds and stops it counting (`last` None), and `Run.observe` prunes a wait only when its thread leaves the ledger. If the change is applied again later, such a wait resumes with the hours of complete reads it had, as the wait of a thread that was busy for a while does: the time between is not counted, the level waited for must still be the one the sources give, and for a KEV thread the catalog version must have advanced. That is intended; it is the rule every paused wait follows, and the time held was all read from the sources. A level change already published stays published and recorded in the ledger, as any does.

## Review dispositions (spec, one independent pass, gpt-6.1-sol)

1. SUBSTANTIVE, the rollback paragraph said the older code drops the new waits; it pauses them. Fixed: the paragraph above says what is kept and what a second landing does with it.
2. SUBSTANTIVE, the message of the snapshot commit ("review snapshot"). Rebutted: a dangling commit made for the reviewer with `git commit-tree`; it is on no branch and never lands.

## Open questions

None that blocks. The follow-up named above (former names) is filed at close-out.
