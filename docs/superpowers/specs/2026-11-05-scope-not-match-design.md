# scope.json: a per-entry not_match list (ai-tools-alerts#3r9h)

## Problem

The live CISA KEV catalog lists CVE-2021-21315 as vendorProject `Npm package`,
product `System Information Library for Node.JS`. The poster builds the product
text `Npm package System Information Library for Node.JS`, and the Node.js
entry's pattern `node.js` matches it under the word rule (ai-tools-alerts#x838),
because the text does name the runtime. Node.js is tier 1, so an exploited
third-party npm library posts `critical` to #security-critical under jibot's key
as if it were the runtime. No boundary rule can tell the two apart: the
difference is the words around the pattern, not its edges.

## Evidence (2026-11-05)

The live KEV catalog (fetched today) run through the current `rules.scope_of`:
141 entries match. The tier-1 hits are three: `Docker Docker Desktop Community
Edition` (Docker, correct), `Git Git` (git, correct) and the Node.js library
above (wrong). The tier-2 hits are Google Chrome/Chromium, Mozilla Firefox,
Apple and Linux kernel products, plus `Redis Debian-specific Redis Servers`;
none is a browser extension or a library.

Prior work: x838's spec (`docs/superpowers/specs/2026-11-05-scope-bounded-match-design.md`)
lists this KEV pair as evidence and filed this issue. Its matcher is
`aitools_alerts/poster/rules.py` `scope_of`; the reader is
`aitools_alerts/schema.py` `load_scope`. The brief names
`aitools_alerts/poster/compose.py` and `aitools_alerts/match.py`; neither
holds a matcher (`match.py` does not exist). The member package reads scope.json
only through `schema.load_scope` (`inventory._scope_names`), and the poster
matches through `rules.scope_of`. So "both matchers" are those two places:
the shared loader, which every reader goes through, validates the field, and the
one matcher applies it.

## Decision (coordinator, ruling k777, on the issue)

Add a per-entry `not_match` list. An entry matches only when a `match` pattern
hits under the file's match mode and no `not_match` pattern hits under the same
mode. Rejected by the coordinator: narrowing the Node.js patterns to runtime
forms, because KEV spells the runtime several ways and a miss there is a missed
critical.

## Approach

### Schema version 3

- `spec/scope.json` moves to `"version": 3`. `load_scope` accepts version 2 and
  version 3 (and version-1 files with no `version`, unchanged). Any other
  version is still refused, so a reader never guesses at a format.
- A version-3 entry may carry `not_match`: a list of 1..100 strings, each
  1..200 characters, lowercase and trimmed, the same checks as `match`. It is
  optional per entry. A version-1 or version-2 file that carries `not_match` is
  refused (ValueError), so no file can hold an exclusion a reader does not
  apply.
- A v2-only reader (the x838 code) refuses a version-3 file, because its version
  check is exact. That is the property the brief asks for: no reader ignores the
  field.
- `schema.ScopeEntry` gains `not_match: tuple[str, ...] = ()` after
  `match_mode`, with a default, so every existing constructor keeps working.

### Matching

In `rules.scope_of`, an entry hits when any `match` pattern matches and no
`not_match` pattern matches, both under the entry's `match_mode` (the word rule
in this file). An excluded entry does not stop the search: a later tier-1 entry
or a tier-2 entry may still match. When nothing matches but some entry was
excluded by `not_match`, the text is appended to `log` (the review list the
caller owns), so a human sees what the exclusion dropped. The poster's
deferred-candidate pass (`poster/main.py`) passes the same review list, so a
candidate deferred under an older scope and now excluded is logged, not
silently dropped from the deferred state (review pass 1).

### The lists

| Entry | not_match | Shape it excludes |
|---|---|---|
| Node.js (tier 1) | `library for node.js`, `library for nodejs`, `node.js library`, `nodejs library` | a third-party library for the runtime |
| Go (tier 1) | `library for golang`, `golang library` | a third-party library for Go |
| git (tier 1) | `git client plugin` | the Jenkins "Git client Plugin", which `git client` matches |
| Browsers (tier 2) | `extension for chrome`, `extension for firefox`, `add-on for firefox`, `extension for safari` | a third-party extension is not the browser |

Every pattern names a third-party product, never a phrase the vendor's own
advisory could carry (code review pass 1, both stages): the coordinator's
`for node.js` vetoed "Security update for Node.js", `npm package` vetoed
"Node.js runtime (npm package manager included)" (Node.js releases patch the
bundled npm), and `chrome extension` vetoed "Google Chrome Extensions API"
(Chrome's own Extensions component, CVE-2025-3069). The KEV text is still
excluded by `library for node.js`.

Not added: Docker (review pass 1: `docker plugin install` is Docker Engine's
own command, GHSA-pxq6-2prw-chj9, so `docker plugin` would drop a runtime
advisory), Python (its patterns, `cpython` and `python software foundation`,
already name only the runtime), MCP servers and skills (third-party servers and
skills are the entry's subject), Claude Code (`Claude Code for VSCode` is
Anthropic's own extension, listed by x838 as a source form).

## Success criteria

1. `scope_of("Npm package System Information Library for Node.JS")` is None and
   the text is in the review log.
2. Runtime forms still match Node.js: `Node.js Node.js` (KEV's spelling),
   `nodejs/node`, `Node.js`, `NodeJS`.
3. A synthetic KEV entry (id in the CVE-2099 reserved range) with the live
   library vendor/product reaches no scope through the candidate adapter; one
   with vendor/product `Node.js`/`Node.js` reaches tier 1 Node.js.
4. Every `match` pattern still resolves to its own entry; no `not_match`
   pattern, read as text, resolves to its own entry.
5. `load_scope` refuses: `not_match` in a version-2 file, a non-list, an empty
   list, uppercase or untrimmed patterns, version 4.
6. The full gate (`scripts/test-gate.sh`) passes. Under 200 changed lines of
   code and tests.

## Blast radius and rollback

Only scope decisions change: texts that match a `not_match` pattern stop
posting under that entry. A wrong exclusion is a missed alert, which is why the
lists stay narrow and the exclusions are logged for review. Rollback is a
revert of the commit; scope.json is not signed by the trust manifest, so
nothing under `trust/` changes.

## Alternatives

- Narrow the Node.js patterns: rejected by the coordinator (above).
- A v2 reader that ignores unknown entry keys: rejected by the brief; an
  ignored exclusion is the bug this fixes.
- Regex patterns in scope.json: more than the shape needs, and a regex in a
  data file is a new way to get matching wrong.

## Accepted limits

- A third-party product the lists do not name ("Express, a web framework for
  Node.js") still matches Node.js. Over-alerting on such a text is the cheaper
  error; a new shape gets a new pattern.
- An exclusion vetoes the whole text, so "Node.js Node.js library" would be
  excluded and logged. No source spells the runtime that way.
