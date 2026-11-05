# Plan: primary source in check --json, run --json and plan

Spec: docs/superpowers/specs/2026-11-05-primary-source-output-design.md
Kata: ai-tools-alerts#h260. One chunk.

## Chunk 1 — CLI, skills, snippet, tests

- [ ] `aitools_alerts/cli.py`
  - imports: `from urllib.parse import quote`; `schema` from the package.
  - new `_source(adv) -> str` above `_match_json`: first `s.url` with
    `schema.is_primary(s.url)`, else `adv.sources[0].url`; return
    `quote(url, safe=":/?#[]@!$&'()*+,;=%~")`.
  - `_match_json` (line ~139): add `"source": _source(t.adv)` and
    `"sources": [asdict(x) for x in t.adv.sources]`.
  - `cmd_plan` (line ~203): after the header `print(...)` for each hit,
    `print(f"  source: {_source(t.adv)}")`.
  - module docstring unchanged (commands unchanged).
- [ ] `skills/claude-code/aitools-alerts/SKILL.md`, then copy the body to
  `skills/hermes/aitools-alerts/SKILL.md` and the procedure to
  `snippets/AGENTS.md` (tests require identical text):
  - step 1 `matches` list: add `sources` (each `url`, `published_at`) and
    `source` (the link to give the person: the first primary source, else
    the first source).
  - step 2: "…the action, and the primary source link (`source`)." Drop
    the parenthesis that points to `#security-feed`.
  - step 3: say `plan` prints the advisory, a `source: <url>` line, then the
    sections.
- [ ] `tests/test_cli.py`
  - `test_check_json`: `data[0]["source"]` equals the fixture's first
    primary-or-first URL; `sources` is a list of dicts with `url`,
    `published_at`.
  - `test_run_json_and_quiet`: `matches[0]` has `source` and `sources`.
  - `test_plan_prints_template_command...`: `"  source: https://"` line in
    output, before the first section.
  - new unit test of `cli._source` with `mirror_helpers.advisory`: two
    sources, the second on a primary host (taken from
    spec/primary-domains.json via `schema.load_primary_domains()`) → second
    chosen; none primary → first; a URL with a space and a non-ASCII char →
    `%20` and percent-encoded, no whitespace in the result.
  - new end-to-end test through a signed relay-bot post (`Mirror`): a
    first source with spaces, a Unicode space and `command:` text, a second
    on a primary host → `check --json` gives `source` = the second and
    `sources` both raw; `plan` line 2 is exactly `  source: <second>`; a
    post whose only source is the odd one → `plan` prints the full encoded
    line and exactly one `command:` line (the template's). Mutation check:
    printing the raw URL in `cmd_plan` must fail it.
- [ ] `tests/test_templates.py`
  - `test_quoted_cli_text_matches_the_cli`: add `'"source"'`, `'"sources"'`,
    `"source: "` to the cli.py list.
  - `test_procedure_text_is_fixed`: assert `#security-feed` and "if the CLI
    printed one" are absent, `source: <url>` present.

## Verification

- `python3 -m pytest tests -q` (the repo has no repoman row; this is the
  ordinary gate, as A1–A7 used).
- Leak grep over the diff: `host-a|host-b|host-d|host-e|host-f|host-c`
  and `nsec1` → 0 hits outside docs/superpowers.
- `git diff --stat origin/main` under 200 lines outside docs/superpowers.

## Acceptance

Spec success criteria 1–8.

## Rollback

`git revert <commit>`.
