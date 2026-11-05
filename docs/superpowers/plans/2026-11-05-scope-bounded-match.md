# Plan: scope.json bounded matching (ai-tools-alerts#x838)

Spec: docs/superpowers/specs/2026-11-05-scope-bounded-match-design.md

One chunk; about 150 changed lines of code and tests.

## Chunk 1: version 2, word rule, patterns, tests

### Tests first (tests/poster/test_rules.py)

- [ ] Add `test_short_pattern_does_not_match_inside_another_word`,
      `test_codex_cli_slug_matches_codex`,
      `test_every_pattern_resolves_to_its_own_entry`,
      `test_source_slugs_resolve` (slug/package table, `Git Git`),
      `test_vendor_only_text_is_logged_not_matched`,
      `test_scope_file_versions` (tmp_path files through
      `schema.load_scope(path)` then `rules.scope_of(..., entries=...)`).
- [ ] Run `python3 -m pytest tests/poster/test_rules.py -q`: the new tests fail
      (substring matching, missing patterns, no version check).

### schema.py

- [ ] `ScopeEntry`: add `match_mode: str = "word"` after `match`.
- [ ] `load_scope`: read `version` (absent → 1; else must be the int 2, bools
      refused). Version 1: `match_mode` key refused, mode `substring`,
      top-level extras ignored. Version 2: top-level keys limited to
      `version, description, match_mode, entries`; `match_mode` absent →
      `word`, else one of `word`, `substring`. The per-entry key check uses the
      four JSON fields (`_obj` gains an optional key set, since the dataclass
      now has a fifth field that the JSON never carries).
- [ ] Pass `match_mode=mode` to every `ScopeEntry`.

### rules.py

- [ ] `_matches(pattern, text, mode)`: substring mode is `pattern in text`;
      word mode uses a cached compiled regex: `(?<![^\W_])` before the escaped
      pattern when `pattern[:1]` is a word character, `(?![^\W_])` after when
      `pattern[-1:]` is, preceded there by an optional `s` (plurals), searched
      with `re.search`.
- [ ] `scope_of`: `any(m and _matches(m, text, getattr(e, "match_mode", "word"))
      for m in e.match)`; docstring states the word rule and the substring mode.
      An unknown mode on a duck-typed entry falls to word (the stricter rule).

### spec/scope.json

- [ ] Add `"version": 2`, `"match_mode": "word"`; rewrite `description` to
      state the word rule.
- [ ] Patterns: Codex `openai/codex`, `codex-cli`; Cursor `cursor/cursor`,
      `cursor cli`; MCP `modelcontextprotocol/` in place of
      `@modelcontextprotocol/`; Docker `dockerd`; Tailscale `tailscaled`; git
      `git git`, `git/git`.

### Verification

- [ ] `python3 -m pytest tests/poster/test_rules.py tests/test_schema.py -q`
- [ ] `scripts/test-gate.sh` (the whole suite; this repo has no repoman row).
- [ ] Leak grep over the diff: `host-a|host-b|host-d|host-e|host-f|host-c`
      returns nothing in added lines outside docs/superpowers.

### Acceptance

- The four brief-named tests pass; all existing tests unchanged and green.
- `scope_of("Shopify skills.shopify") is None`;
  `scope_of("openai/codex-cli").name == "Codex"`;
  `scope_of("Git Git").name == "git"`; `scope_of("Git", log)` is None and logs.

### Rollback

`git revert` of the chunk commit. A version-1 scope.json reads with the new
code unchanged in meaning.
