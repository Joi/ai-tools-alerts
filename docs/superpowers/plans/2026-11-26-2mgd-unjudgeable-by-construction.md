# Plan: a respelled product cannot make a relay-bot post unjudgeable (ai-tools-alerts#2mgd)

Spec: `docs/superpowers/specs/2026-11-26-2mgd-unjudgeable-by-construction-design.md` (as revised after its review and the split to ai-tools-alerts#nx25).
Tests first in each chunk; `python3 -m pytest -q tests/test_verify.py tests/test_check.py tests/test_unverified_cli.py tests/test_verify_cli.py` while working, `scripts/test-gate.sh` at the end.

## Chunk 1: identity in `check`, `verify` and `pull`

### `aitools_alerts/check.py`

- [ ] Add `scope_name(name: str, ecosystem: str) -> str | None` after `_owns` (line 127) and a cached `_scope_products() -> dict[str, list[tuple[str, str | None]]]`: ecosystem to `(scope product name, package or None)`, from the values of `ruleset.index(schema.load_scope())` (the names `Ruleset.products()` holds; `check` imports `ruleset`, which imports only `schema`). A scope file that does not load: `{}`.
- [ ] Rule, with `n = name.lower()` and `tool = IDENTITY.get(ecosystem, set()) | {ecosystem}`: candidates are the scope products `S` of `ecosystem` with `S.lower() == n`, or (`ecosystem not in _NAME_ECOSYSTEMS` and `n in tool` and `S.lower() in tool`), or (`ecosystem == "mcp"` and the package, lower-cased, `== n`). Return the single candidate, else `None`. Never raises.
- [ ] Tests (`tests/test_check.py`): every scope product resolves to itself under its ecosystem; `claude code`, `claude-code`, `@anthropic-ai/claude-code`, `CLAUDE CODE` under `claude-code` give `Claude Code`; `codex` under `codex` gives `Codex`; `Claude Code` under `skill` gives `None`; `claude-code-router` gives `None`; `pypi:mcp-server-git` under `mcp` gives `mcp-server-git`; `containerd` under `docker` gives `containerd`, `docker` gives `Docker`. Property: for every tool ecosystem in `IDENTITY` and every name `n` in its identity set, `check.match` on an inventory holding that tool's installation matches `Product(n)` exactly when it matches `Product(scope_name(n))`.

### `aitools_alerts/verify.py`

- [ ] `VERSION = 4`. `from . import check`. Public `pkey(product) -> str`: `f"{product.ecosystem}\n{product.name}"` (a newline is in neither field; a test asserts `schema.validate` refuses one in each). Public `scope_of(product) -> str | None`: `check.scope_name(product.name, product.ecosystem)`.
- [ ] `_Target.__init__` (line 381): `self.products = sorted({pkey(p)})`; `self.scope = {pkey: scope name or None}`; `self.eco = {pkey: ecosystem}`; `self.fixed = {pkey: fixed}`. In the state key `"products"` is the sorted list of `[ecosystem, name]` pairs and `"fixed"` is keyed by pkey.
- [ ] `_Target.judge(key, ...)` (line 402): judge `self.scope[key]`; each action whose target resolves, in that product's ecosystem, to the same scope name is passed with that scope name as target. `fixed` by key.
- [ ] `_Run.thread` (line 716): `weight` reads `t.scope` values (the scope names), not `t.products`.
- [ ] `run` (line 807): the budget fallback calls `t.judge(p, [], False, rs)`, not `judge(t.level, p, ...)`.
- [ ] `result_for`, `_shape_ok`, `_waits`: unchanged in code; their product keys are pkeys.
- [ ] Tests (`tests/test_verify.py`; the helper `adv()` takes each product's ecosystem from the scope file, `one()` looks up by pkey, a helper `K(name)` gives the pkey of a scope product):
  - acceptance: lower-case `claude code`, the catalog lists another vendor: `contradicted`, `unsupported`; the catalog lists Claude Code: `confirmed` (the upgrade action targets the respelled name);
  - `Claude Code` under `skill` beside `Claude Code` under `claude-code`: the tool's result is as without it, the other is `no-source`; `lowering` of that state to `high` is `False` when the catalog supports critical;
  - `claude-code-router` under `claude-code`: `no-source`;
  - the budget cut-off: with `MAX_FETCHES` used up, a thread that spent a request is `unread`, and the next run judges it;
  - a version 3 cache is an empty one;
  - every existing lookup by product name is moved to the pkey: `tests/test_verify.py` lines 114, 329-332, 487, 572, 620, 635, 636, 681, 687, 916, 927, 956; `tests/test_unverified_cli.py:490`; `tests/test_curator_hold_cli.py:200, 290, 347`; `tests/test_verify_cli.py:275`; `tests/poster/test_advisory_recompute.py:546, 568`. Source support records (`cache["sources"][id]["support"]`) stay keyed by scope name.

### `aitools_alerts/pull.py`

- [ ] `_Hold.note` (line 993): `names` and `fixed` keyed by `(p.ecosystem, p.name)`. `_missing` (line 1006): `have` holds the same pairs. `held_fixed` (line 1190): `tuple(sorted(h.fixed.items()))` of those pairs. `widest` (line 1243): looks `fixed` up by `(p.ecosystem, p.name)`. Docstrings say "ecosystem and name".
- [ ] Tests (`tests/test_curator_hold.py`, beside the existing history tests): a thread whose root names `Claude Code` under `claude-code` with a fixed version; a bot reply adds `Claude Code` under `skill` and puts `claude code` with no fixed version in the tool entry's place: `pull.widest` still holds the original entry with its fixed version. Through the CLI (`tests/test_unverified_cli.py`): with the catalog listing the CVE for Claude Code, a lowering to high published after that reply is refused (`below-source`), not left to the 72 hours.

Acceptance: `python3 -m pytest -q tests/test_verify.py tests/test_check.py tests/test_curator_hold.py` passes.

## Chunk 2: CLI

### `aitools_alerts/cli.py`

- [ ] `_check_json` (line 467) and `_result` (line 629): look up `verify.pkey(m.product)`; `_result` gives `verify.UNKNOWN` for a relay-bot match whose product resolves to nothing, whatever the cache says.
- [ ] `_verified_bucket` (line 657): `verify.scope_of(m.product)` in place of the posted name when it resolves.
- [ ] `_source_lines` (lines 439-447, 456-458): iterate the thread's products with their results by pkey, print `verify.scope_of(p)`; skip a product that resolves to none; lines stay deduplicated.
- [ ] `_pinned_exactly(a, st) -> bool`: the stored certificate pins a ruleset (`cert.ruleset` is a `Pin`, `ruleset_unreadable` false), and `ruleset.load()` has that version and digest. False on any exception.
- [ ] `_unjudgeable(t, m) -> bool`: relay-bot, and `verify.norm_id(t.adv.id) is None` or `m.product is None` or `verify.scope_of(m.product) is None`. From the post alone.
- [ ] `_interrupts` (line 700): when `s.verify != "off"` and `_min_cli` is None and `_pinned_exactly`, matches that are `_unjudgeable` are left out before grouping; an alert with none left is neither pending nor held and takes no slot. A helper `_unjudged(a, st, s, pairs) -> list` gives the alerts all of whose unseen critical matches were left out, for `cmd_check`; `_interrupts` keeps its four return values. Docstring says so.
- [ ] `cmd_check` (after line 591): `UNJUDGED_LINE = "source check: {id} names a product or an id this check cannot judge: no interrupt"`, once per such alert.
- [ ] Tests (`tests/test_unverified_cli.py`, with the helpers there; the pin is `ruleset.Pin(rs.version, rs.digest, 1)`): an inventory with a skill named `Claude Code`; a relay-bot critical for `Claude Code` under `skill`, empty cache: `run`, `run --json` and `notify` give no exit 2, send nothing, grant no slot; `check` prints the line. With no pin, with a pin of a later version whose `min_version` this ruleset meets, and with `verify = "off"`: it interrupts as unverified. A respelled critical the catalog lists for another vendor prints the contradiction with the scope name, and `check --json` gives `contradicted`. Respellings of one confirmed advisory share one verified slot. A colliding entry under `skill` does not stop the genuine match from interrupting as confirmed.

Acceptance: `python3 -m pytest -q` passes.

## Chunk 3: docs

- [ ] `CHANGELOG.md` under Unreleased: what changed for a member, the cache rebuild (version 4), what stays open (the aliases, nx25; a first id that answers 404; `formerly` names).
- [ ] `README.md`, the source-check section: one sentence on product names.
- [ ] Comment on ai-tools-alerts#fa5a: nothing beyond a normal release; the cache is rebuilt once. Comment on ai-tools-alerts#0z4e: results are keyed by `verify.pkey`.

## Verification

`scripts/test-gate.sh` (public scan, then the whole suite) on the committed head.

## Rollback

Revert the merge commit. The older code reads a version 4 cache as empty and rebuilds it.

## Review

One independent pass (gpt-6.1-sol) on snapshot 8192bab: 1 blocker, 6 substantive. Taken here: the `pull` history keys (blocker), the budget fallback, the migration of every result consumer. The four on alias scheduling moved with the alias half to ai-tools-alerts#nx25.
