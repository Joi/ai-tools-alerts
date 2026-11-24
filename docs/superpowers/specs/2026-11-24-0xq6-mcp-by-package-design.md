# 0xq6: the CLI matches MCP servers by package; Hermes and OpenClaw probes; "may apply"

Slice 10 of ai-tools-alerts#9mx8 (design section 8, "CLI and inventory"), as corrected by the notes on ai-tools-alerts#0xq6 from t8jr and wa6n.

## Problem

The member CLI cannot match most alerts the service now posts.

- An MCP alert matches only when a configured server's key equals the product name. The key is whatever the member typed (`fs`, `github`); the posts name the package (`@modelcontextprotocol/server-filesystem`, `mcp-server-git`). The design measured 19 of 28 alerts as unmatchable for this reason.
- Hermes and OpenClaw are in scope (`spec/scope.json` version 6, class `channel`) but nothing probes them, so their alerts never match. Hermes advisory GHSA-p22p-9ph6-gmrh is the confirmed miss.
- A match by name alone, with no version comparison, counts as a match like any other: a critical one sets exit 2 and sends a notification. The design says such a match "may apply" and never interrupts.

## What landed code says that the issue text does not

- The issue says "match catalog entries on `products[].package`". t8jr showed that a `package` key in a product drops the whole alert on every released reader. wa6n put the package in `spec/scope.json` instead: each MCP entry carries `package` (`pypi:mcp-server-git`) and its wire product keeps ecosystem `mcp` with name equal to the package name. This slice maps an installed server to a package and matches the product name against the package name, with the scope entry's `package` deciding which registry the name belongs to. Nothing changes on the wire or in the state file.
- Cursor's version from the application bundle already landed (`collect_cursor`, in `/Applications` and `~/Applications`). Nothing to add.
- "Release as v0.2.0 by the release recipe (signed tag)" is publishing, which this session does not do (brief: no live install or post). The release is filed as a `rollout:` issue.

## Success criteria

1. A server configured as `npx -y @modelcontextprotocol/server-filesystem@1.2.3 /dir` is inventoried as package `npm:@modelcontextprotocol/server-filesystem`, name `@modelcontextprotocol/server-filesystem`, version `1.2.3`, and matches an alert with that product and range `<1.3.0`.
2. `uvx mcp-server-git`, `uvx mcp-server-git==0.6.2`, `uvx --from mcp-server-git==0.6.2 mcp-server-git`, `uv tool run ...` and `pipx run --spec ...` resolve to `pypi:mcp-server-git` (version when pinned).
3. A command that is a path into `node_modules` (directly, or as `node <path>`) resolves to the package that directory holds, with the version from its `package.json` when that file names the same package.
4. A command that is a path to `<venv>/bin/<exe>` resolves to the distribution in that environment whose normalised name equals the executable's, with the version from its `.dist-info` directory name.
5. An installed npm `mcp-server-git` does not match an alert for the scope entry `mcp-server-git`, whose package is `pypi:mcp-server-git`.
6. Hermes is inventoried from `~/.hermes/hermes-agent/pyproject.toml` (project name `hermes-agent`) without running `hermes`; OpenClaw by `openclaw --version`. Both match their scope products ("Hermes", "OpenClaw").
7. A Claude Code plugin key `name@marketplace` is inventoried with source `marketplace`; a product named `name@marketplace` matches only that plugin from that marketplace; a product named `name` matches any skill or plugin of that name.
8. A match whose installation has no version (an unpinned MCP server, a skill, a plugin), or whose product states no range (neither `affected` nor `fixed`), has reason `may apply`, except as criterion 9 says. It is printed and listed in `--json`, but it is never counted in `unseen_critical`, never sets exit 2, never sends a notification, and never reaches auto-apply. A critical thread with a `may apply` match is not listed under "Critical advisories not installed here": it is printed in the match list with its reason. A version that is present but unreadable keeps reason `unparsable-version`, with no actions, and still notifies, as today.
9. A product that says every version is affected (`affected` `*`, no `fixed`) matches as `affected` when the installation is confirmed by package or by plugin source, version unknown or not. With no readable version it never auto-applies (plan requires `versions.check` to be True). With a readable version it may auto-apply exactly as a tool's `*` match does today: a curator post, a verb the member opted into, a target that names the installation.
10. From a config's server entries, only these enter the inventory: the server key (as today, through `_ok_name`), a package name and a version, both validated against a fixed grammar, and a plugin's marketplace name (through `_ok_name`). No command, argument, environment value or URL does. No process is started for an MCP server, a path from a config is only read (bounded), never executed.
11. `scripts/test-gate.sh` passes. Existing tests keep passing, with the reason value `name` renamed to `may apply` and the `versions.covers` cases of criterion 12 updated.
12. A relay-bot reply cannot turn an interrupting match into `may apply`. A range with neither bound now matches as `may apply`, so `versions.covers` no longer lets it stand for a bounded or unreadable range: `pull._join` keeps the earlier product beside the new one, and the bounded one still interrupts. A regression test: a critical thread for Claude Code `2.1.3` with `<99.0.0`/`99.0.0`, then a bot reply with both fields null; `unseen_critical` still lists it and `run` exits 2.
13. Two installations of one advisory's product are matched separately: an unpinned `uvx mcp-server-git` listed before a pinned, affected `mcp-server-git==0.6.2` does not hide the affected match (in either order).

## Approach

### Inventory (`aitools_alerts/inventory.py`)

`Installed` gains two optional fields, `package: str | None` (`npm:...` or `pypi:...`, lowercase) and `source: str | None` (a plugin's marketplace). For MCP servers, `server: str | None` holds the configured key, so `remove_mcp_server` can still name it. All default to None; `asdict` adds them to `check --json` and `run --json`, which is additive for JSON readers. Nothing on the wire changes.

`collect_mcp` reads, for each configured server, `command` (string) and `args` (list of strings, at most 64, each at most 4096 characters) and passes them to `mcp_package(command, args, home)`, which returns `(package, name, version)` or None:

- `npx`, `bunx` (basename): skip options (`-y`, `--yes`, `-q`, `--quiet`; `-p`/`--package <spec>` names the package); the first positional is the spec. `npm exec`/`pnpm dlx` are not read (rare in MCP configs; they fall back to the key).
- `uvx`, `uv tool run`, `pipx run`: `--from <spec>` or `--spec <spec>` names the package; options known to take a value (`--python`, `-p`, `--with`, `--index-url`, ...) skip their value; otherwise the first positional.
- An npm spec is `name`, `name@version` or `@scope/name[@version]`; the version is kept only when it is an exact version `versions.normalize` reads (a tag or a range is no version). A PyPI spec is `name`, `name==version` or `name@version`, extras (`name[x]`) dropped; the name is normalised (PEP 503: lowercase, runs of `-_.` to `-`).
- A path (command, or the first argument when the command's basename is `node`) containing `/node_modules/`: the package is the one or two path segments after the last `node_modules`; its version is read from `node_modules/<package>/package.json` (bounded read) when that file's `name` equals the package.
- A path `<dir>/bin/<exe>` where `<dir>/pyvenv.cfg` exists: the distribution is the `<dir>/lib/python3.*/site-packages/<name>-<version>.dist-info` whose normalised name equals the normalised `<exe>`; nothing else is listed or read.

Names must match the npm grammar (`(@[a-z0-9][a-z0-9._~-]*/)?[a-z0-9][a-z0-9._~-]*`, at most 214) or the PyPI grammar; anything else yields no package, and the server is listed by its key as today. The config path stays the `path` field; no argument, environment value or URL enters the inventory.

Resolved servers are listed with `name` = the package name; unresolved ones keep `name` = the key, `package` None. One record per configured key: two keys that run the same package are two records, each with its own `server`, so `remove_mcp_server` can name either. The dedupe is on `(name, package, version, server)` per config file.

New probes:

- `openclaw`: `TOOLS` row `("openclaw", "--version")`, version token after an optional `openclaw`/`OpenClaw` word and `v`. Not verified against a real install (none on hand); the regex accepts a bare version or a name-prefixed one, and anything else yields nothing.
- `hermes`: `collect_hermes(home)` reads `~/.hermes/hermes-agent/pyproject.toml` (the default install of the Hermes installer) with `tomllib`, requires `project.name == "hermes-agent"`, and takes `project.version`. `hermes --version` is not run: it checks for updates over the network (verified in its source, `_print_version_info`).

`collect_skills`: a plugin key `name@marketplace` gives `Installed(name, None, path, source=marketplace)` when both halves pass `_ok_name`.

### Check (`aitools_alerts/check.py`)

- `IDENTITY` gains `openclaw` (`openclaw`) and `hermes` (`hermes`, `hermes agent`, `hermes-agent`).
- `_aliases` adds, for an `mcp` installation, its `package` and its `server` key; for a `skill` installation with a source, `name@source`.
- New `_identity(product, inst) -> bool | None`: for `mcp`, the package the product's name resolves to (the scope entry or component whose identities contain the name, ecosystem `mcp`, with a `package`; or the name itself when it is a package key). True when the installation's package equals it, False when both are known and differ (then no match at all), None when either is unknown. For `skill`, True when the installation has a source and the product name equals `name@source`. Other ecosystems: None.
- Reasons: `affected` (readable version inside the stated range; or `affected` `*`, no `fixed`, identity True), `unparsable-version` (unchanged), and `may apply` (constant `MAY_APPLY`, replacing `NAME` = `"name"`) for everything else that matched.
- `match`'s dedupe key becomes `(ecosystem, installation, affected, fixed)`, the whole `Installed` record, so product entries repeating one range for one installation still collapse while two installations each get their own match.
- `plan` is unchanged: it already requires `reason == AFFECTED` and `versions.check(...) is True`, which fails for an unknown version.

### Versions (`aitools_alerts/versions.py`)

- `covers`: a range with neither part covers only itself. Before, it covered every range, because a name-only match carried the same actions and interrupted too; now it does not interrupt.

### CLI (`aitools_alerts/cli.py`)

- `_unseen_critical` keeps only matches whose reason is not `may apply`.
- `cmd_check`: a critical thread whose only matches are `may apply` is not repeated under "Critical advisories not installed here".
- The skill docs (`skills/claude-code/...`, `skills/hermes/...`, `snippets/AGENTS.md`): a match with reason `may apply` is reported as possibly applying and is not told first.
- CHANGELOG entry under Unreleased.

## Alternatives considered

- **A `package` key on wire products.** Drops the alert on every released reader (t8jr). Rejected.
- **Run `hermes --version`.** Contacts the network on every hourly run and session start. Rejected for the file read.
- **Run `npm ls`/`pip show` to resolve versions.** Starts processes whose behaviour depends on the member's environment and can be slow. Rejected; files are read instead.
- **Keep "name" matches interrupting.** The design rules them "may apply". A package or source identity match with "every version" is the one case kept as `affected`, because the post then says nothing about versions that the installed one could escape.
- **Marketplace-level skill matching (an alert for "ClawHub" matching every skill installed from it).** No reliable record of which marketplace a skill directory came from; not built here. Follow-up issue.

## Blast radius and rollback

Member-side only; nothing a poster, mirror or released reader sees changes. Worst case of a bug: a missed or extra match on the member's machine, or a `may apply` that should have interrupted. The reason rename changes the `reason` value in `--json` from `name` to `may apply`; the session-start skill docs are updated in the same change. Rollback: revert the merge commit.

## Amendments from the whole-branch review (reviewed head 19f3103)

- `match` dedupes on `(ecosystem, installation, affected, fixed, reason)`: a `may apply` product listed first cannot hide an `affected` one for the same installation and range (BLOCKER).
- Hermes since 0.23 declares `version = "0.0.0"` in `pyproject.toml` and takes its release from git or an install stamp (upstream `hermes_cli/version_info.py`). A version of only zeros is no version: Hermes then matches as `may apply`, never as a version below every range. Reading the stamp or the tag is a follow-up.
- npm: a version is kept only when exact (`x.y.z`); `pkg@1.2` and `pkg@1` are ranges to npm. A spec ending in `.tgz`, `.tar` or `.tar.gz` is a file, not a name.
- npx with several `--package` options: the one whose bare name is the command, else no package (the server is listed by its key).
- An option that names another registry or index (`--registry`, `--index-url`, `--extra-index-url`, `--index`, `--default-index`, `-i`, `--find-links`, `-f`) ends the reading: the name then says nothing about the public package.
- Only absolute paths are read (a relative one would resolve against the CLI's directory, not the client's).
- A plugin name with a leading `@scope/` is not a marketplace-qualified name.
- Trade-off, stated: a malicious-release critical (`*`, no fix) on an installation matched by a name alone (an MCP key with no resolvable package, a skill without its marketplace) is `may apply` and does not interrupt. Every MCP product the poster can post is a scope entry with a `package`, so an MCP server whose command resolves keeps the interrupt; one configured so that its package cannot be read does not.

## Not verified

- OpenClaw's `--version` output on a real install.
- Hermes installs other than the default `~/.hermes/hermes-agent` (for example `pip install hermes-agent` into another environment) are not found.
