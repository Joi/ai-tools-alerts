# scope.json: bounded matching and the missing product forms (ai-tools-alerts#x838)

## Problem

`rules.scope_of` decides whether a candidate is in scope tier 1, and a tier-1
hit on a KEV entry posts `critical` to #security-critical. It tests each
`spec/scope.json` pattern as a lowercase substring of the product text, so the
pattern list alone decides correctness, in both directions:

- Over-match. `skills.sh` is a substring of `skills.shopify`, so
  `scope_of("Shopify skills.shopify")` is ClawHub (tier 1). `docker` matches
  `dockerfile-x`, `chrome` matches `chromebook`, and every short pattern added
  later carries the same risk.
- Under-match. `openai/codex-cli` returns None. The live KEV catalog lists
  CVE-2025-48384 as vendorProject `Git`, product `Git`; the poster builds
  `Git Git`, which matches no pattern, so an exploited git CVE never posts.
  GitHub's advisory database files Cursor advisories under `cursor/cursor`,
  git's under `git/git`, MCP's under `modelcontextprotocol/servers`; none of
  the three match today.

## Evidence gathered (2026-11-05)

- KEV catalog (1,768 entries) vendor/product pairs for tier-1 vendors:
  `Git | Git`, `Docker | Desktop Community Edition`,
  `Npm package | System Information Library for Node.JS`. No KEV entry names
  Anthropic, OpenAI, Cursor, Gemini, Hermes, OpenClaw, MCP, Python, Go, Rust,
  Tailscale or OpenSSH today.
- GitHub repository advisories, package names per repo: `openai/codex`
  (`npm:@openai/codex`), `anthropics/claude-code` (`@anthropic-ai/claude-code`,
  `Claude Code for VSCode`), `cursor/cursor` (`Cursor`, `Cursor CLI`),
  `moby/moby` (`Docker Engine`, `docker-ce`), `docker/cli`
  (`github.com/docker/cli`), `tailscale/tailscale`, `git/git` (`git`, `Git`),
  `rust-lang/rust` (`Rust`, `rustc`, `std`), `modelcontextprotocol/servers`
  (`@modelcontextprotocol/server-filesystem`, `mcp-server-fetch`),
  `openclaw/openclaw` (`@openclaw/discord` and siblings). Global advisories:
  `@google/gemini-cli`, pip `mcp`, `@modelcontextprotocol/sdk`.
- `aitools_alerts/manifest.py` signs only the poster list (pubkey, role,
  name). scope.json is not covered, so nothing under `trust/` is re-signed.
- Prior work: `kata search "scope pattern word boundary"` returns nothing; the
  finding comes from the B2 review (ai-tools-alerts#31x7, run manifest
  `docs/superpowers/runs/2026-11-05-poster-level-rules.md`).
  `capability-search word boundary scope match` finds no matcher to reuse.

## Approach

### Schema version 2 with a match mode

`spec/scope.json` gains two top-level fields:

- `"version": 2`. A file without `version` is version 1 and reads exactly as
  today: substring matching. Any other value is refused by `load_scope`
  (ValueError), so a reader never guesses at a format it does not know.
- `"match_mode"`: `"word"` (the default in version 2) or `"substring"`.
  Version 1 files may not set it (they have one meaning).

Version 2 also refuses unknown top-level keys (`version`, `description`,
`match_mode`, `entries` only); version 1 keeps ignoring them, so an old file
still reads.

`schema.ScopeEntry` gains `match_mode: str = "word"` as its last field, with a
default, so every existing four-argument constructor keeps working.
`load_scope` sets it from the file on every entry. The entry objects in JSON do
not carry it (the per-entry key check is unchanged).

### The word rule

In `word` mode a pattern matches when it occurs in the normalised text and the
occurrence is bounded: if the pattern's first character is a letter or digit,
the character before the occurrence is not a letter or digit (or the text
starts there); the same at the end. A pattern edge that is itself punctuation
(`@modelcontextprotocol/`, a trailing `/`) needs no boundary, so a scoped npm
prefix keeps matching every package under it. "Letter or digit" is Unicode
`[^\W_]`, the same class `_tokens` uses, so `_` is a separator in both places.
Any bounded occurrence counts (`skills.shopify skills.sh` matches on the
second). A word-final edge allows one plural `s` before its boundary, so
`mcp server` matches `MCP servers`, `agent skill` matches `Agent Skills` and
the entry name `MCP servers and clients` matches itself (review pass 1: without
it the migration dropped plural product text that substrings matched). Tier order is unchanged: tier 1 is tried first.

`substring` mode is the current behaviour, byte for byte.

### Pattern changes (scope.json, version 2, word mode)

Added (each one from the evidence above):

- Codex: `openai/codex`, `codex-cli`.
- Cursor: `cursor/cursor`, `cursor cli`.
- MCP: `modelcontextprotocol/` replaces `@modelcontextprotocol/` (covers the
  npm scope and the GitHub org `modelcontextprotocol/servers`).
- Docker: `dockerd`. Tailscale: `tailscaled` (daemon names the word rule
  would otherwise drop).
- git: `git git` (the KEV form), `git/git`.

Already covered under the word rule, asserted in tests rather than added:
`anthropics/claude-code` (`claude-code`), `google-gemini/gemini-cli`
(`gemini-cli`), `nousresearch/hermes-agent`, `openclaw/openclaw` and
`@openclaw/discord` (`openclaw`), `moby/moby`, `github.com/docker/cli`,
`tailscale/tailscale`, `rust-lang/rust`, `python/cpython`, `golang/go`,
`nodejs/node`, `mcp-server-fetch` (`mcp-server`).

Not added, by the brief: vendor-only text (`Python`, `Go`, `Git`, `Rust`,
bare `Cursor`, bare `mcp`) stays unmatched and logged for human review; it is
not a product in scope. `rustc` alone is not added: `tests/test_schema.py`
asserts no pattern is a substring of "trustcenter portal", and `rust rustc`
already covers the KEV form.

### Tests (tests/poster/test_rules.py)

- `test_short_pattern_does_not_match_inside_another_word`: `Shopify
  skills.shopify` and `dockerfile-x` are None; `skills.sh`, `docker-compose`,
  `Docker Desktop` still match.
- `test_codex_cli_slug_matches_codex`: `openai/codex-cli`, `codex-cli`,
  `openai/codex` resolve to Codex.
- `test_every_pattern_resolves_to_its_own_entry`: for every entry and every
  `match` pattern in the shipped file, `scope_of(pattern)` is that entry.
- Left edge and plurals: `notdocker`, `2docker`, a Unicode letter before
  `docker` are None; `foo_docker` and `notdocker, then docker` match; `MCP
  servers`, `MCP servers and clients`, `Agent Skills`, `git clients` match.
- `test_source_slugs_resolve`: a table of the slugs and package names from the
  evidence that name a product (`anthropics/claude-code`, `openai/codex`,
  `cursor/cursor`, `Cursor CLI`, `@openclaw/discord`,
  `modelcontextprotocol/servers`, `mcp-server-fetch`, `moby/moby`,
  `github.com/docker/cli`, `docker-ce`, `git/git`, `Git Git`, and the rest),
  each to its entry. The vendor-only names in the evidence (`Python`, `Go`,
  `Git`, `Rust`, `Cursor`) are a separate test: None, and logged. `rustc`,
  `std` and `mcp` alone are neither added nor asserted.
- Versioning: a version-1 file (no `version`) reads in substring mode and
  `skills.shopify` still matches it; version 2 defaults to word; version 2 with
  `"match_mode": "substring"` keeps substrings; `version` 3, a bool, a string,
  an unknown `match_mode`, `match_mode` in a version-1 file, and an unknown
  top-level key in version 2 are refused.
- Every existing test in the file stays green unchanged.

## Success criteria

1. The four named tests pass; every existing test in tests/poster and
   tests/test_schema.py passes unchanged.
2. `scripts/test-gate.sh` passes.
3. No pattern in the shipped file is shadowed (the table test).
4. A version-1 file loads and behaves as before (test).

## Alternatives considered

- Tighten patterns alone, keep substrings. Rejected: every short pattern
  (`docker`, `moby`, `chrome`, `safari`, `openclaw`, `macos`) would need a
  proof that no longer word contains it, and the next addition reopens it.
- Regex patterns in scope.json. Rejected: a regex list is harder to review
  than plain strings, and a bad regex is a runtime failure in the poster.
- Per-entry or per-pattern match mode. Rejected for now: one mode for the
  file covers every current pattern; a per-entry override can be a later
  version without breaking this one.
- An exclusion list for `... for Node.JS` libraries. Out of scope here (it is
  semantic, not a substring problem); filed as a follow-up.

## Blast radius and rollback

Files: `spec/scope.json`, `aitools_alerts/schema.py` (load_scope and
ScopeEntry), `aitools_alerts/poster/rules.py` (scope_of),
`tests/poster/test_rules.py`. `schema.py` is outside the brief's three-file
list; the reader must check the version field, and `load_scope` is the reader.
B4 owns `transport.py` and `main.py`, which this does not touch.
`inventory.py` reads only ecosystem and name and is unaffected.

Behaviour change: product text where a pattern sits inside a longer word stops
matching (`dockerfile`, `chromebook`, `skills.shopify`, `tailscaledev`). The
named daemon forms are added back. Rollback: revert the commit; a version-1
file needs no code to read it.

## Code review changes (pass 1, whole branch)

- Added `opencontainers/runc` (GHSA package `github.com/opencontainers/runc`),
  `getcursor/cursor` and `cursor-agent`.
- A word-final edge that is a letter also ends where a digit starts a glued
  version (`openssh9.8p1`, `cpython3.12`, `debian12`), which substrings matched.
- `_norm` maps Unicode dashes to `-` and collapses whitespace runs.
- A version-2 `description` must be a string.

Accepted limits: `-` is a boundary, so a third-party name built on a product
(`claude-code-router`, `jenkins docker plugin`) still matches it, as it did
under substrings; CJK text glued to a Latin name (`Dockerの`) does not match,
and no source in use writes product text in Japanese; an unknown
`match_mode` on a hand-built entry uses the word rule, the stricter one,
rather than raising inside the poster.

## Open questions

None blocking. Follow-up: the KEV entry `Npm package | System Information
Library for Node.JS` matches Node.js (tier 1) by the pattern `node.js`; an
exploited third-party Node library would post critical as if it were the
runtime.
