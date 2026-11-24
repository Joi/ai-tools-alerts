# Plan: 0xq6 — MCP by package, Hermes and OpenClaw probes, "may apply"

Spec: docs/superpowers/specs/2026-11-24-0xq6-mcp-by-package-design.md

## Chunk 1 — inventory

Files: `aitools_alerts/inventory.py`, `tests/test_inventory.py`, `tests/fixtures/inventory/` (home fixture, probes.json).

- [ ] `Installed`: add `package: str | None = None`, `source: str | None = None`, `server: str | None = None` after `path` (keyword defaults keep every positional construction in the tests valid).
- [ ] Module docstring: config files are read for server keys, and for each server's `command`/`args` only to derive a package name and version in a fixed grammar; paths from a config are read (bounded), never executed.
- [ ] `_npm_spec(spec) -> (name, version|None) | None`, `_pypi_spec(spec)`, `_pep503(name)`, grammar regexes, `_exact(version)` (via `versions.normalize`, and no range characters).
- [ ] `_runner_args(base, args)` for `npx`/`bunx` (options `-y --yes -q --quiet`; `-p/--package` value is the spec; `--` ends options) and for `uvx` / `uv tool run` / `pipx run` (`--from`/`--spec` value is the spec; value-taking options skipped: `--python -p --with --with-editable --with-requirements --index --index-url --extra-index-url --default-index -i --find-links -f --constraint -c --override --python-preference --cache-dir --directory --project --env-file --pip-args`).
- [ ] `_node_modules(path)`: package from the segments after the last `node_modules`; version from that package dir's `package.json` (`_json`, bounded) when its `name` equals the package.
- [ ] `_venv(path)`: `<dir>/bin/<exe>` with `<dir>/pyvenv.cfg`; scan `<dir>/lib/python3.*/site-packages/*.dist-info` names only (at most 4096 entries) for `<name>-<version>.dist-info` whose PEP 503 name equals the exe's.
- [ ] `mcp_package(command, args) -> (package, name, version) | None`, never raises; inputs bounded (args a list of at most 64 strings of at most 4096 chars).
- [ ] `collect_mcp`: per config, per server key with `_ok_name(key)`: the server dict's `command`/`args` → `mcp_package`; resolved → `Installed(name, version, path, package=..., server=key)`, else `Installed(key, None, path, server=key)`. Dedupe on `(name, package, version, server)` per file. Claude projects' servers included as today. Codex TOML `command`/`args` same shape.
- [ ] `collect_skills`: plugins → `Installed(name, None, path, source=marketplace)` when `name@marketplace` and both halves pass `_ok_name`; a key without `@` keeps source None.
- [ ] `TOOLS["openclaw"] = (("openclaw", "--version"), rx)` with `^(?:openclaw )?v?TOKEN` case-insensitive on the prefix word.
- [ ] `collect_hermes(home, name)`: `~/.hermes/hermes-agent/pyproject.toml`, `project.name == "hermes-agent"`, `versions.normalize(project.version)`; `add("hermes", collect_hermes, home, names.get("hermes", "Hermes"))`. Tested through `inventory.collect()` on the fixture home, not only directly.
- [ ] `collect_skills`: a skill directory or plugin name containing `@` is listed with `source` None and can never carry a qualified alias (see chunk 2).
- [ ] Tests: each command form in the spec's criteria 1–4 (npx pinned, npx tag, npx `--package`, bunx, uvx plain/pinned/`--from`, `uv tool run`, `pipx run --spec`, extras, node_modules path direct and via `node`, venv path, junk names, oversize args, non-list args); the leak test still holds (no argument text in the repr except a package name); hermes from a fixture pyproject, wrong project name ignored; openclaw from probes.json; plugin source.

Verify: `python3 -m pytest tests/test_inventory.py -q`.

## Chunk 2 — check, CLI, docs

Files: `aitools_alerts/check.py`, `aitools_alerts/cli.py`, `aitools_alerts/versions.py`, `tests/test_check.py`, `tests/test_cli.py`, `tests/test_bot_patch.py`, `skills/claude-code/aitools-alerts/SKILL.md`, `skills/hermes/aitools-alerts/SKILL.md`, `snippets/AGENTS.md`, `CHANGELOG.md`.

- [ ] `IDENTITY["openclaw"] = {"openclaw"}`, `IDENTITY["hermes"] = {"hermes", "hermes agent", "hermes-agent"}`.
- [ ] `MAY_APPLY = "may apply"` replaces `NAME`; keep `NAME = MAY_APPLY` alias only if something imports it (grep; else remove).
- [ ] `_scope_packages()` (lru_cache): identity (lowercase) → package, for every `mcp` scope entry and component with a package, from `schema.load_scope()`; a load failure yields `{}`.
- [ ] `_aliases`: `mcp` adds `inst.package` and `inst.server` (lowercased) when set; `skill` adds `f"{name}@{source}"` when source set.
- [ ] `_identity(product, inst) -> bool | None` per spec. For `skill`: a product name containing `@` is source-qualified; it matches only an installation whose `name@source` equals it (True), and is no match at all (False) for any installation without a source, including a skill directory literally named `demo@market`. Negative test beside the positive plugin test.
- [ ] `match`: skip when `_identity` is False; reason per spec (`affected` for in-range readable version, or `*`+no fixed with identity True; `unparsable-version` unchanged; else `may apply`). Dedupe key unchanged plus the installation's package/source.
- [ ] `match` dedupe key: `(product.ecosystem, inst, product.affected, product.fixed)` (the whole frozen `Installed`).
- [ ] `versions.covers`: the `by_affected is None and by_fixed is None` branch returns False (equality is handled above it); docstring says why. `tests/test_bot_patch.py`: case 2 expectations become False; `seen()` in `test_covers_agrees_with_check_match` grades a match as (matched, interrupts = reason != may apply, has actions) and the covers check compares componentwise; the literal `[2, 1, 2]` assertion is rewritten for the triples. Existing join tests whose expectation rested on a no-range product standing for a bounded one are updated to the new join result (both entries kept, and `narrowing` counted where the new list no longer stands for the old): `test_a_fixed_version_where_there_was_none_is_held`, the `(None, None)` case of `test_a_relay_bot_patch_may_add_and_widen`, and any other the gate shows; each update is checked to keep or add an interrupting match, never remove one.
- [ ] Regression (`tests/test_cli.py` or `tests/test_bot_patch.py`, whichever already builds bot replies through a mirror): critical Claude Code thread `<99.0.0`/`99.0.0`, installed 2.1.3, bot reply nulling both; `run --json` still lists it in `unseen_critical` and exits 2.
- [ ] Regression: unpinned and pinned-affected `mcp-server-git` installations, both orders; one `affected` match survives.
- [ ] `cli._unseen_critical`: drop `m.reason == check.MAY_APPLY`.
- [ ] `cmd_check`: "Critical advisories not installed here" excludes threads that have any match (unchanged), so a may-apply critical shows only in the match list with its reason. Verify the existing code already does this; no change if so.
- [ ] Skill docs: in step 1's field list, `reason` values `affected`, `unparsable-version`, `may apply`; in step 2, tell-first covers critical matches whose reason is not `may apply`; a `may apply` match is reported as "may apply to this machine".
- [ ] `tests/test_templates.py` constraints on those docs (run it).
- [ ] CHANGELOG under Unreleased.
- [ ] Tests: package identity match and the npm/pypi mismatch exclusion; `*` with identity → affected, with name only → may apply; plugin `name@source`; may-apply critical not in `unseen_critical`, `run` exits 0 and sends nothing; hermes/openclaw product matches; existing `"name"` assertions renamed.

Verify: this repo has no `.repoman-managed` marker, so the brief's gate is `scripts/test-gate.sh`, run once on the combined result before the PR.

## Acceptance

Spec success criteria 1–11. Diff under about 600 changed lines excluding the three run artifacts.

## Rollback

Revert the merge commit. No state, wire or mirror change to undo.

## After merge

- `rollout: release v0.2.0` issue (signed tag by the release recipe), labelled discovered-from:0xq6, repo:ai-tools-alerts, priority 2.
- Follow-up: marketplace-level skill matching (skill directory provenance), discovered-from:0xq6.
