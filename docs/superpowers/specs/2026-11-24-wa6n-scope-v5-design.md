# Scope classes: channel, catalog or out; products carry a package (wa6n)

Slice 4 of ai-tools-alerts#9mx8, design section "2. Scope", approved by Joi on
2026-11-23. Builds on h340 (exact identities), s6mt (ruleset), t8jr (wire format)
and 0dvh (hold and age limit).

## Problem

`spec/scope.json` sorts products into tier 1 (may interrupt) and tier 2 (feed, high
at most). The approved scope is different in kind: an item either belongs in the
channel, belongs only in the catalog, or is out of the community service. The file
also names one pseudo-product, "MCP servers and clients", which no member can
upgrade ("Upgrade MCP servers and clients to 2026.11.18").

The design calls the file "version 5"; h340 already used 5 for exact identities,
so this file is version 6.

## Decisions

1. **`class` replaces `tier`.** Each entry has `"class": "channel" | "catalog" | "out"`.
   Components take their entry's class. The JSON key is `class`; the Python field
   is `ScopeEntry.scope_class`.
   - channel: coding agents and IDEs (Claude Code, Codex, Cursor, Gemini CLI,
     Hermes, OpenClaw), MCP servers and clients of any publisher, skills, plugins
     and extensions (ClawHub, skills.sh). Any level.
   - catalog: SDKs and libraries (`@modelcontextprotocol/sdk`, `pypi:mcp`) and
     developer tools (`@modelcontextprotocol/inspector`). Notice at most, which
     today means the digest, never a real-time post. Slice 8 routes notices to
     `#security-catalog`.
   - out: macOS, Linux distributions, browsers, Node.js, Python, Go, Rust, Docker,
     Tailscale, OpenSSH, git. A new advisory starts no thread and is not held for
     the digest. An existing thread (posted under v4) still takes updates, so a
     fix or a withdrawal still reaches members.
2. **One exception key: `"channel_if": "code-execution"`**, allowed on a catalog
   or out entry. That entry posts to the channel at high, never critical, when a
   reading of it shows remote code execution: the ruleset's rows for it (GitHub
   vendor or reviewed advisory, attack vector network or adjacent, a
   code-execution CWE: 77, 78, 94, 95, 96 or 502, and a fixed version; the
   credential CWEs 522 and 798 do not count), or a prose reading whose text says
   "remote code execution" or "RCE" about a fixed flaw. Credential theft, data
   loss and local execution do not trigger it. Today's page readings carry no CVSS
   vector and no CWE, so until the collector reads them (slice 2) the prose clause
   is the path that fires; the structured rows are in place for when it does. It carries both clauses of the
   design: the Inspector "unless code execution is remote", and git's
   recursive-clone case ("a flaw an agent triggers in normal use"). It is set on
   `@modelcontextprotocol/inspector` and `git` only. KEV alone does not trigger
   it: a KEV entry has no field that says how the flaw is reached.
3. **`package` on entries and components.** Optional, `ecosystem:name`, lowercase
   ecosystem, e.g. `pypi:mcp-server-git`. It is one more identity of that product
   (it resolves like a `match` identity and is unique across the file), and it is
   the identity slice 10's CLI will match installed MCP servers on. Set on every
   product that has one registry package: Claude Code, Codex, Gemini CLI, Hermes,
   OpenClaw, every MCP entry.
4. **No MCP pseudo-product.** "MCP servers and clients" and its components are
   replaced by one entry per package, named by the package name, ecosystem `mcp`
   as before: `mcp-server-git`, `mcp-server-fetch`, `mcp-server-time` (pypi),
   `@modelcontextprotocol/server-filesystem`, `-memory`, `-everything`,
   `-sequential-thinking` (npm), `mcp-remote` (npm), all channel;
   `@modelcontextprotocol/inspector` (catalog, channel_if),
   `@modelcontextprotocol/sdk` (catalog), `mcp` (pypi, catalog). The ecosystem stays
   `mcp` because released readers collect MCP installations under that key and
   match a product only within its ecosystem; a product under `npm` or `pypi`
   would validate but match no member (review finding). The registry lives in
   `package`. The generic
   identities ("mcp server", "model context protocol", the slug
   `modelcontextprotocol/servers`) are dropped: none names one package. A
   third-party MCP server of any publisher enters the file by its package when
   the collector (slice 9) finds one; this slice adds the shape, not a pattern.
5. **The wire does not change.** A post names an MCP product with the block's
   existing fields, `{"name": "mcp-server-git", "ecosystem": "mcp"}`, the shape
   v4 posts had (`{"name": "mcp-remote", "ecosystem": "mcp"}`). Every
   released reader (v0.1.4 to v0.1.7) accepts that block: their `ecosystem`
   grammar is `[a-z0-9][a-z0-9-]{0,63}` and `name` is free text of 1 to 200
   characters. No `package` key is added to the block (t8jr note on this issue).
   `tests/test_wire_compat.py` gets this product shape in its feed first. So
   readers at v0.1.x keep working without a reader release, and no v4 file needs
   serving: `scope.json` is not on the wire.
6. **Ruleset version 2.** `spec/ruleset.json` replaces `tier_cap` with
   `class_cap` (`channel` critical, `catalog` notice, `out` notice) plus
   `channel_if_cap` (high); the rule condition `tier` becomes `scope` (a list of
   classes) and a new condition `channel_if` (true) matches an entry carrying the
   exception. The digest covers the scope file, so this is a new version; a v1
   claim is still checked by the reader's own ruleset (`check_claim` computes with
   its own version), and a reader at v1 reads a v2 claim as "unknown, upgrade".
   The trust root pins no ruleset yet, so nothing live changes.
7. **Renamed threads keep their thread.** Ledger threads are keyed by scope name.
   An entry may list `formerly`: names its product had in an earlier file. When no
   thread exists under the entry's name, `Run.one` looks under each former name;
   a thread found there is the advisory's thread, and the update is composed
   under that name, so the reply names the product as the root did (the reply
   check requires it) and no second root starts. Only the listed names count, so
   an old SDK thread never blocks a Codex root that shares its CVE. Set on the
   Inspector (`MCP Inspector`), the SDKs (`MCP TypeScript SDK`, `MCP Python SDK`)
   and the reference servers (`MCP servers and clients`).
8. **Saved notices of out products are dropped.** The state's `held` list (notices
   waiting for the digest) loses every notice whose scope name is an out entry
   or component, when the run loads its state. Composed items in the outbox are
   not reclassified: an item there may be the copy or reply of a root already
   sent, and dropping it would leave a thread half-posted; the outbox drains as
   composed.

## Success criteria

- `schema.load_scope` reads version 5 with `class`, `channel_if`, `package`;
  refuses `tier`, an unknown class, `channel_if` on a channel entry, a malformed
  package, and a package that repeats an identity.
- No entry or component is named "MCP servers and clients"; every MCP entry's
  `name` is its package's name and its `ecosystem` is `mcp`.
- A GHSA reading of `pypi:mcp-server-git` binds to `mcp-server-git` at channel
  levels; one of `npm:@modelcontextprotocol/sdk` is notice whatever its fields;
  one of the Inspector with network vector, CWE-94 and a fix is high, with CWE-522
  only it is notice; a KEV
  reading of OpenSSH is notice and the poster starts no thread for it; a git
  code-execution reading with a fix posts at high.
- A root post for `mcp-server-git` validates under every released reader and
  matches an MCP installation of that name there (wire compat test).
- A later fix for an advisory whose thread is under "MCP Inspector" posts as a
  reply on that thread; a held notice for OpenSSH is gone after the state loads.
- `scripts/test-gate.sh` passes.

## Review dispositions (spec pass 1, independent model)

Fixed: released-reader matching (ecosystem stays `mcp`); the mcp-remote thread
(same name and ecosystem); the code-execution predicate (no credential CWEs,
"remote code execution" in prose); held notices of out products; renamed threads
(`formerly`, replacing the vanished-name guard). Rebutted:
- "Adding a package does not admit any publisher's advisory": true, and not this
  slice. Admission of a GitHub reviewed or malware advisory for an enrolled
  package whose publisher is not on the primary-domain list is the poster half of
  slice 9; filed as a follow-up issue. This slice gives the file the shape to
  enroll by package.
- "Skills, plugins and imitations have no enrollment path": the same follow-up.
  An imitation never binds as the product it imitates (h340); it posts when it is
  enrolled by its own package and a malware source names it.
- Outbox reclassification: decision 8.
- The snapshot commit message: the review snapshot is a dangling commit that
  never lands.

## Alternatives rejected

- A `package` key in the alert block: every released reader drops the alert (t8jr).
- Package in the claim tag only: old readers ignore it, but the product a post
  names would still be the pseudo-product, which is the defect.
- Name patterns for "any publisher" (`npm:*mcp*`): h340 removed substring
  matching because a pattern let `claude-code-router` pass as Claude Code; a
  pattern here would let any package named like an MCP server post to the
  channel. Slice 9 selects advisories; each lands here by exact package.
- Dropping out entries from the file: their threads would lose updates, and
  their text would land in the review log as unmatched.
- Catalog capped at high (as tier 2): high posts in real time, which "never the
  channel" forbids.

## Blast radius and rollback

Poster behaviour changes on its next run after deploy: out products stop starting
threads, catalog products stop real-time posts. Reader behaviour of released CLIs
is unchanged. Rollback: revert the merge; the ledger is untouched (no thread is
rewritten), and the withheld renamed sightings post nothing.

## Assumes

- The MCP reference server package names above are the published ones
  (modelcontextprotocol/servers README).
- s564 (chromereleases as a primary domain) closes as not needed: browsers are out.
