# Local inventory, matching and action planning (Task A4, ai-tools-alerts#0xrc)

## Problem

The member CLI (A5) needs three things it does not have: a list of what is
installed on the member's machine, a version comparison that reads the
advisory grammar A2 fixed, and a decision, per matched advisory, on what may
run by itself and what only gets described. The decision is the security
boundary of the whole system: a post from the relay bot, an unknown verb, or
an incomplete action must never reach `auto_apply`.

## Success criteria

1. The nine plan tests pass, among them Review Focus item 1,
   `test_upgrade_without_fixed_is_notify_only`; `scripts/test-gate.sh` passes.
2. `python3 -c "from aitools_alerts import inventory; inv = inventory.collect(); print(sorted(inv.products))"`
   prints every scope ecosystem key on this Mac without raising.
3. The test suite never executes a real tool: every binary probe goes through
   an injected runner.
4. No subprocess call takes an argument that did not come from a constant in
   `inventory.py`; nothing in `check.py` or `versions.py` executes anything.
5. The diff carries no fleet host name, no real MCP server config and no real
   skill or plugin list. Fixtures are invented.

## Approach

### `versions.py`

- `normalize(s: str | None) -> str | None`: trim, keep the text before the first
  space, strip a `claude-code/` prefix, then one leading `v`; return the result
  if it is a version in the A2 grammar (`1..5` dotted integers, optional
  lowercase suffix of at most 16 characters), else `None`.
- `parse(s) -> tuple | None`: a sort key. Numeric parts are padded to five.
  A suffix splits into a tag and a trailing number (`p1` -> `("p", 1)`,
  `rc2` -> `("rc", 2)`). Tags `a`, `alpha`, `b`, `beta`, `dev`, `pre`, `rc`
  sort below the bare release (pre-releases); any other tag (`p` in OpenSSH's
  `9.9p1`) sorts above it (patch levels). Within a rank, tags compare by string,
  then by number.
- `check(installed, affected, fixed) -> bool | None`: `None` when any present
  argument is unreadable (installed missing or outside the grammar, `affected`
  not `*` or 1..4 comparators joined by `,`, `fixed` outside the grammar).
  Otherwise True when every comparator in `affected` holds (`*` and `None`
  always hold) and, if `fixed` is given, `installed < fixed`.
- `affected(installed, affected, fixed) -> bool` is the plan's interface:
  `check(...) is True`. Unreadable is never a match.

### `inventory.py`

- `Installed(name, version: str | None, path: str)`, frozen;
  `Inventory(products: dict[str, list[Installed]])`.
- `collect(home: Path | None = None, runner=None, apps_dirs=None) -> Inventory`.
  `home` defaults to `Path.home()` at call time (the plan's
  `home: Path = Path.home()` default would freeze it at import). `products`
  holds one key per ecosystem in `schema.load_scope()`, empty list when
  nothing was found, so A5 and the acceptance one-liner see the full set.
- Runner: `runner(argv: tuple[str, ...]) -> str | None`. The default runs
  `subprocess.run(list(argv), capture_output=True, text=True, errors="replace",
  timeout=5, stdin=DEVNULL, check=False)` with no shell and returns stdout, or
  stderr when stdout is empty (`ssh -V` writes to stderr); `None` on
  `OSError` (missing binary), `TimeoutExpired`, or a non-zero exit. Output is
  cut to 4096 characters.
- Tool collectors, each a function returning `Installed | None`: a FIXED argv
  per tool from a module-level table, a regex over the first output line that
  captures the version token, and `versions.normalize`. A tool whose output has
  no readable version returns `None`. Table (ecosystem: argv):
  `claude-code: claude --version`, `codex: codex --version`,
  `gemini-cli: gemini --version`, `node: node --version`,
  `python: python3 --version`, `go: go version`, `rust: rustc --version`,
  `docker: docker --version`, `tailscale: tailscale version`,
  `openssh: ssh -V`, `git: git --version`, `macos: sw_vers -productVersion`.
  `Installed.name` is the scope entry's name (`Claude Code`), `path` the argv[0].
  `macos` and `tailscale` accept a one-part version; the others need two parts
  so a stray number in a banner is not read as a version.
- Cursor: `<apps_dir>/Cursor.app/Contents/Info.plist`, `plistlib`,
  `CFBundleShortVersionString`. `apps_dirs` defaults to `/Applications` and
  `home/Applications`; tests pass only the fixture's.
- Name collectors return `list[Installed]` with `version=None`:
  - `skill`: subdirectory names of `home/.claude/skills`, and plugin names
    from the keys of `home/.claude/plugins/installed_plugins.json` `plugins`
    (the part before `@`). Not the plugin directory names the plan wrote:
    on a real install those are Claude Code's bookkeeping directories
    (`cache`, `marketplaces`, `repos`, ...), not plugins. Recorded as a
    `decided:` on the issue.
  - `mcp`: keys of `mcpServers` at the top of `home/.claude.json` and under each
    `projects.*` entry (where Claude Code keeps local-scope servers), keys of
    the `mcp_servers` table in `home/.codex/config.toml` (`tomllib`), and keys
    of `mcpServers` in `home/.cursor/mcp.json`. Only key names are kept; no
    command, argument, environment or URL is read into the inventory.
  - Names must be strings of 1..200 characters with no control characters;
    others are skipped. Duplicates (same name, same source) are kept once.
  - Config files over 64 MiB are skipped; a file that fails to parse is skipped.
- `collect` wraps every collector in `try/except Exception` and never raises.

### `check.py`

- `Config(auto_apply: frozenset[str] = frozenset())`, frozen; A5 loads it from
  the member's config file.
- `Match(adv, installed, actions_allowed: list[Action], reason: str, product: Product | None = None)`.
  `product` is added after the plan's four fields, with a default so the
  plan's four-argument construction still works: `plan` needs the matched
  product's `fixed`, and a Match built without it never auto-applies an
  upgrade. Reasons: `affected` (version read and inside the range),
  `name` (matched by name; no version or no range to compare),
  `unparsable-version` (something present could not be read; notify only,
  `actions_allowed` empty).
- `match(advs, inv)`: for each advisory, for each product, for each
  `Installed` under `inv.products[product.ecosystem]` whose name matches:
  - `skill` and `mcp`: case-insensitive equality of the names.
  - every other ecosystem: the product name lowercased equals the installed
    name lowercased, the ecosystem key, or a name in `check.IDENTITY` for that
    ecosystem (so `claude-code`, `Claude Code` and `@anthropic-ai/claude-code`
    all name Claude Code; `undici` in ecosystem `node` does not name Node.js).
    `IDENTITY` is a short table of names for the tool itself, NOT scope.json's
    `match` patterns: those also name components (`containerd` and `moby`
    under docker, `rustup` under rust, `apple webkit` under macos) whose
    versions are not the probed tool's.
  - version: if the installed version is `None` or the product has neither
    `affected` nor `fixed`, reason `name`. Otherwise `versions.check`:
    True -> `affected`, False -> no match, None -> `unparsable-version`.
  - `actions_allowed`: the advisory's actions that concern this product.
    `upgrade`, `disable_skill`, `remove_mcp_server` concern it when their target
    names it under the same name rule AND the match is in the verb's own
    ecosystem: `disable_skill` only a `skill` match, `remove_mcp_server` only an
    `mcp` match, `upgrade` only a tool ecosystem (so a `remove_mcp_server codex`
    on a Codex CLI advisory never concerns the CLI); `rotate_credential`, `stop_using`,
    `review_setting` and any verb outside `schema.VERBS` concern every match
    (an unknown verb then lands in `prepare`, below).
  - One `Match` per (advisory, product, installed); an `Advisory` is never a set
    member or dict key (A2: frozen, not hashable).
- `plan(m, config) -> Plan(notify, auto_apply, prepare)`: `notify` is True for
  every match. An action goes to `auto_apply` only when ALL hold:
  `m.adv.posted_by == "curator"`, the verb is in `schema.VERBS` and in
  `config.auto_apply`, `m.reason == "affected"`, and the action is complete.
  Complete: `upgrade` needs `m.product.fixed` and an installed version. Every
  upgrade, auto-applied or prepared, carries `value = m.product.fixed` (the
  product's `fixed` is authoritative per `spec/actions.json`; the post's own
  value is dropped, and with no `fixed` the value is None, described as "no
  fixed version given"). Every other verb is complete as validated. Every other action goes to `prepare` unchanged. `describe(action)
  -> str` renders a one-line, notify-only description from the action's
  fields for A5.
- No command templates here: those are A5/A6.

## Alternatives considered

- `versions.affected` alone (plan interface) with no tri-state: cannot tell
  "not affected" from "unreadable", which the brief requires reporting. Kept
  `affected` and added `check`.
- One generic version regex for all tools: fails on `go1.22.1` and
  `OpenSSH_9.9p1` without per-tool context; the per-tool table is as short.
- Plugin directory names as the plan wrote: yields `cache`/`marketplaces`
  on a real install; rejected.
- scope.json `match` patterns as product aliases: they name components
  (containerd under docker), so a containerd advisory would be compared
  against Docker's version. Rejected for the IDENTITY table.
- Treating any product in a tool ecosystem as the tool: an `undici` advisory
  in `node` would then compare against node's version and could auto-upgrade
  Node. Rejected.

## Blast radius and rollback

New modules and tests only; nothing imports them yet (A5 will). Rollback is a
revert of the one commit. `collect()` runs fixed local probes only, each
bounded to 5 s.

## Assumes

- The PATH lookup of the fixed tool names is the member's own (a hostile PATH
  is already code execution as the member).
- Advisory expiry, retraction and seen-state are A5's.
