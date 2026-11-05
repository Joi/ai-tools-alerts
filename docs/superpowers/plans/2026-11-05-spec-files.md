# Spec files and advisory parser Implementation Plan (Task A2, ai-tools-alerts#j153)

> **For agentic workers:** execute in order; each step has its verification.

**Goal:** the four spec files, `aitools_alerts/schema.py`, its tests and post fixtures, per docs/superpowers/specs/2026-11-05-spec-files-design.md.

**Architecture:** one stdlib-only module that hard-codes the vocabularies, loads `spec/*.json` from the repo root, and validates the last `aitools-alert` fenced block of a post into frozen dataclasses.

**Tech stack:** Python ≥ 3.11 standard library (`json`, `dataclasses`, `re`, `unicodedata`, `urllib.parse`, `pathlib`); pytest.

## Chunk 1 (one chunk, one commit; target under 600 changed lines including run artifacts)

### Files

| Path | Change |
|---|---|
| `spec/advisory.schema.json` | new: draft 2020-12 schema, `required` lists every field, `additionalProperties: false` at each object, patterns and bounds from the spec |
| `spec/actions.json` | new: six verbs `{verb, meaning, target, value}` |
| `spec/scope.json` | new: 16 tier-1, 3 tier-2 entries `{name, ecosystem, tier, match}` |
| `spec/primary-domains.json` | new: 17 hosts; `github.com` with `paths` |
| `aitools_alerts/schema.py` | new: constants, dataclasses, `validate`, `parse_post`, `render_post`, `load_scope`, `load_primary_domains`, `is_primary` |
| `tests/test_schema.py` | new |
| `tests/fixtures/posts/valid-critical.md`, `no-info-string.md`, `unknown-verb.md` | new |

### Steps

- [ ] **1. Fixtures and failing tests.** Write the three fixtures and `tests/test_schema.py` with:
  - plan tests: `test_parse_valid_post_fixture`, `test_parse_ignores_block_without_info_string`, `test_unknown_verb_rejected`, `test_unknown_level_rejected` (valid fixture with `"level": "urgent"` substituted), `test_render_then_parse_roundtrip`, `test_primary_domain_github_only_under_advisories_paths` (the plan's two URLs plus `/advisories/GHSA-x` True), `test_scope_tiers_loaded` (Claude Code tier 1, macOS tier 2);
  - `test_dataclass_fields_equal_schema_required_keys` (Advisory, Product, Action, Source against the schema's `required` lists);
  - `test_spec_files_agree_with_constants` (actions.json verbs and the schema enums == VERBS / LEVELS / ROLES; all four files load);
  - hardening: `test_last_block_wins`, `test_invalid_last_block_does_not_fall_back`, `test_block_quoted_inside_longer_fence_is_ignored`, `test_unclosed_block_ignored`, `test_duplicate_keys_rejected`, `test_unknown_key_rejected`, `test_bool_is_not_an_int`, `test_shell_metacharacters_in_fixed_rejected`, `test_newline_or_bidi_in_text_rejected`, `test_non_https_source_rejected`, `test_render_rejects_body_with_unclosed_fence`, `test_is_primary_rejects_lookalikes` (userinfo `https://cisa.gov@evil.example/`, `http://`, port 8443, `cisa.gov.evil.example`, `community.openai.com`, `https://github.com/a/b/security/advisories/../../issues/1`, `%2e%2e` path, `/a/security/advisories/x` with one segment), `test_is_primary_accepts_www_and_trailing_dot`, `test_load_scope_rejects_uppercase_pattern` (tmp file).
  - Verify: `python3 -m pytest tests/test_schema.py -q` fails on the missing module.
- [ ] **2. Spec files.** Write the four JSON files. Verify: `for f in spec/*.json; do python3 -m json.tool "$f" >/dev/null || echo BAD $f; done` prints nothing.
- [ ] **3. `schema.py`.** Implement per the spec's Approach. Verify: `python3 -m pytest tests/test_schema.py -q` passes; `python3 -c "from aitools_alerts.schema import VERBS, LEVELS; print(sorted(VERBS), sorted(LEVELS))"` prints `['disable_skill', 'remove_mcp_server', 'review_setting', 'rotate_credential', 'stop_using', 'upgrade'] ['critical', 'high', 'notice']`.
- [ ] **4. Whole gate.** `scripts/test-gate.sh` passes (nostr and trust-root tests included). `git add -N spec aitools_alerts/schema.py tests docs/superpowers && git diff --stat origin/main` (intent-to-add, so new files count) reports the size; the 600-line guide is exceeded and recorded as a `decided:` on the issue.
- [ ] **5. Leak check.** the A1 leak-check pattern (`nsec1` plus the fleet host names, kept out of this public file) over `spec`, `tests/fixtures/posts`, `tests/test_schema.py`, `aitools_alerts/schema.py` and these run artifacts prints nothing.
- [ ] **6. Commit** `feat: advisory schema, verbs, scope tiers, primary domains` with the run artifacts.

## Acceptance

Success criteria 1–5 of the spec, each with the command above.

## Rollback

`git revert <sha>`; no other module imports `schema` yet.

## After landing

Comment the landed sha on ai-tools-alerts#0exc, #0xrc, #31x7 (the issues this blocks), and on #0xrc the two notes: spec files are at repo root and need packaging for `pipx install .`; reply blocks with changed fields only need a partial parser built on `schema.validate`'s field validators.
