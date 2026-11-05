# Scope components: a public product identity per component (ai-tools-alerts#qme5)

## Problem

`compose.root_post` publishes the matched scope entry's name as `products[0].name`, in the title and as the upgrade target. Two kinds of entry make that wrong:

- Docker's patterns cover containerd and runc. A containerd KEV entry posts "upgrade Docker to 1.7.20", a containerd version, and a member's Docker installation is compared against a containerd range.
- "MCP servers and clients", "ClawHub and skills.sh", "Linux distributions" and "Browsers" are group names. No member inventory reports them, so `check.match` never matches the post by name.

## Decision (coordinator, ruling k777, on the brief)

Schema version 4. A scope entry may carry `components`: a list of `{name, match, not_match?}`. Each name is a public product identity a member could report (containerd, runc, Docker). An entry without components behaves as today, under the entry's name. compose publishes the matched component's name. Both readers refuse any version but 4. Rejected by the coordinator: a per-pattern product-name string, because a component needs its own not_match and a stable ledger identity.

## Approach

### spec/scope.json, version 4

- Entry keys: `name`, `ecosystem`, `tier`, and at least one of `match` and `components`; `not_match` optional.
- Component keys: `name`, `match`; `not_match` optional. Patterns follow the existing rules (lowercase, trimmed, 1..100 per list).
- Names share one namespace: every entry name and component name is unique across the file, except that a component may carry its own entry's name (Docker's `Docker` component). The poster's ledger keys threads by this name.
- Version 4 is the only version read. A file with no `version` (version 1), or with version 2 or 3, is refused with a `ValueError`. `match_mode` stays (`word` default, `substring`).

### Matching order (`rules.scope_of`)

Within a tier, for each entry in file order:

1. Each component in list order: the first whose `match` hits and whose `not_match` does not is picked. A component vetoed by its own `not_match` counts as excluded (logged for review) and the search moves to the next component.
2. If no component is picked, the entry's own `match` (if any) picks the entry under its own name: the fallback for text that names the group but no component.
3. The entry's `not_match` vetoes whatever was picked, component or fallback: it names a third-party product, so the whole entry steps aside (as in version 3), and the search goes on to the next entry.

`scope_of` returns a `ScopeEntry` with `components` always emptied, so compose's guard (below) never sees an unresolved entry. For a picked component it is the entry with `name` and `match` taken from the component (and `not_match` the entry's plus the component's): the component is the scope from there on. For the fallback it is the entry under its own name. Every caller (`main.py`, `ledger.merge`, `rules.level_for`, `compose`) reads `scope.name`, `scope.ecosystem` and `scope.tier`, so the component's name becomes the post's product, the title's prefix, the upgrade target and the ledger thread key, with no change in `main.py` (which ai-tools-alerts#9sa2 is editing in parallel). Tier and ecosystem come from the entry.

`vendor_words` adds the first word of each tier-1 component name, so text naming "containerd" or "rustup" that matches no pattern is still logged for review.

### compose

`root_post` refuses (ValueError, the advisory is withheld) a scope that still carries components: an unresolved entry would publish a group name. No other compose change: it already publishes `scope.name`.

### Member side (`check.match`, `inventory.collect`)

- `inventory`: two probes report Docker's components where they are on the host: `containerd --version` and `runc --version`, named `containerd` and `runc` under ecosystem `docker`. They are fixed argv like every probe. On macOS they are inside Docker Desktop's VM and yield nothing; on a Linux member they report.
- `check._aliases`: an installation gets the ecosystem's IDENTITY names and the ecosystem name only when it IS the ecosystem's tool (its name is one of those). A component installation (containerd) is known by its own name only. Without this, adding the containerd probe would match a Docker-named advisory against containerd's version. Component names first (an installation named by a component matches only that component's posts), then the entry's identity names (the ecosystem's own tool).
- Auto-apply stays impossible for a component installation: `_owns` already requires an IDENTITY name, and the CLI builds an upgrade command from the ecosystem, which for containerd would be Docker's. A test pins that a curator containerd post plans `prepare`, never `auto_apply`.

### Fixture changes in spec/scope.json

- Docker: components `containerd` [containerd], `runc` [opencontainers runc, runc container runtime, opencontainers/runc], `Docker` [docker, moby, dockerd]; no entry `match`. containerd and runc come first so text naming both a component and Docker is the component's.
- MCP servers and clients: components `MCP Inspector` [mcp inspector, @modelcontextprotocol/inspector, modelcontextprotocol/inspector], `mcp-remote` [mcp-remote], `MCP TypeScript SDK` [@modelcontextprotocol/sdk, modelcontextprotocol/typescript-sdk, mcp typescript sdk], `MCP Python SDK` [modelcontextprotocol/python-sdk, mcp python sdk]; the entry `match` stays as the fallback for an advisory about an MCP server not listed.
- ClawHub and skills.sh: components `ClawHub` [clawhub], `skills.sh` [skills.sh]; entry `match` keeps [agent skill, claude skill] as the fallback.
- Linux distributions: components `Linux kernel`, `Ubuntu`, `Debian`, `Fedora`, the kernel first, so "Ubuntu linux kernel" (a USN for the kernel package) names the kernel and its version, not "upgrade Ubuntu to 6.8.0"; no entry `match`.
- Browsers: components `Chrome`, `Chromium`, `Safari`, `Firefox`; the `not_match` list stays on the entry so "extension for chrome" still vetoes every browser, as today.
- Rust: component `rustup` [rustup] (its versions are not rustc's); the entry keeps the rest.
- Reviewed and left as one product: Claude Code, Codex, Cursor, Gemini CLI, Hermes, OpenClaw, Node.js, Python, Go, Tailscale, OpenSSH, git. macOS stays one entry: "apple webkit" advisories are fixed by a macOS update, the member's macOS probe is the only one that can match them, and splitting WebKit out would stop that notification; noted as a follow-up candidate, not filed.

## Success criteria

1. A containerd KEV entry (product text "containerd") composes `containerd` as products[0].name, in the title and as the upgrade target, with the containerd fixed version.
2. `check.match` on an inventory reporting `containerd` under docker matches that advisory; an inventory reporting only Docker does not; a Docker advisory does not match the containerd installation; a curator containerd advisory never auto-applies.
3. MCP Inspector, mcp-remote, ClawHub and skills.sh texts resolve to their component names; an unlisted MCP server text resolves to the entry's name.
4. Version 1, 2 and 3 files are refused by `schema.load_scope`, which is both the poster's and the member's reader. Bad component shapes (missing name, empty match, unknown key, duplicate name across entries) are refused.
5. Every existing test passes, updated only where it pinned version 2/3 loading or an aggregate name.
6. Under 400 changed lines of code, data and tests. No change under `trust/` (spec/scope.json is not signed).

## Alternatives considered

- Per-pattern product name: rejected by the coordinator (no per-component not_match, no stable identity).
- Ledger keyed by the entry name, component used only in compose: an existing thread's recomposed product name would differ from the stored one, `_publishable` would refuse the reply, and every update to that thread would be withheld. Changing that needs `main.py`, which #9sa2 holds. Rejected.
- Refuse only version 3 and keep reading 1 and 2: incoherent (an older file is less like the current one than version 3 is). Rejected.
- Matching component `match` patterns against installed names in `check`: for skill and mcp, names are member-chosen, and a generic pattern would match unrelated servers that a `remove_mcp_server` action then targets. Rejected: names match by equality only, as today.

## Blast radius and rollback

- Ledger keys change for advisories that now resolve to a component: containerd, runc, the MCP and skill components, the Linux and browser components, rustup. A thread already posted under the old name keeps its entry; a later candidate for the same advisory looks up the new name, misses, and starts one new root under the correct name. KEV and collector candidates are windowed by `kev_since` / `since`, so this touches only items still arriving after landing. Accepted: the new root is the correction the issue asks for.
- A stale member install with a version 3 scope.json alongside version 4 code refuses to load scope; `inventory.collect` already treats a load failure as no names (it falls back to ecosystem names) and `rules` raises, which the poster's run reports. The live poster and member CLI are reinstalled by the coordinator after landing.
- Rollback: revert the commit; the version 3 file and readers return together.

## Open questions

None blocking. Assumes: the KEV product text for containerd and runc entries carries "containerd" / "runc" with "opencontainers" (the existing patterns were chosen from the live catalog by x838).
