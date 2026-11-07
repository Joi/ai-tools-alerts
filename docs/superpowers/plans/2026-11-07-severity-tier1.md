# Plan: severity-tier1

Spec: docs/superpowers/specs/2026-11-07-severity-tier1-design.md. One chunk.

## Chunk 1: rule, tests, docs

- [x] `aitools_alerts/poster/rules.py`: add `_ADVISORY_ID`
  (`CVE-\d{4}-\d{4,}|GHSA(?:-[0-9a-z]{4}){3}`) and `_HIGH_WORDS`
  (`high`, `critical`) beside `_SEVERE`; in `level_for`, after the
  `fix-rce-tier1` return and before the final `notice`, return
  `("high", "severity-tier1")` when `_norm(severity).strip()` is in
  `_HIGH_WORDS` and `c.id` or an alias fullmatches `_ADVISORY_ID`. Docstring
  lists the reason.
- [x] `tests/poster/test_rules.py`:
  - `test_fix_rce_tier1_is_high`: the `"CRITICAL"` with a fix case now expects
    `("high", "severity-tier1")` (a level word alone is the new rule).
  - `test_severity_tier1_is_high`: high, critical, `"High "`, `" CRITICAL"`,
    fullwidth `Ｈｉｇｈ`, ideographic space; GHSA id; CVE alias on a non-advisory
    id → severity-tier1. moderate, low, medium, None, `high-ish`, `not high`,
    empty → notice. Tier-2 `critical` → notice. `critical` with source_ok
    stays `high`.
  - `test_fix_rce_tier1_wins_over_severity_tier1`.
  - `test_news_lead_severity_never_raises_level`: `LEAD-…` ids, a non-advisory
    alias, lowercase `cve-…`, a CVE with a suffix → notice.
  - `test_collector_claude_code_advisory_is_tier1_high`: the acceptance, a
    cfe8-shaped record through from_collector + scope_of + level_for; pins
    `advisory_severity == "high"` and `fixed is None`.
- [x] `docs/plan.md`: a Global Constraints bullet for the high rules, and the
  Task B2 level sentence names both high reasons.

## Verification

- `python3 -m pytest tests/poster -q`, then the whole gate `scripts/test-gate.sh`.
- `git diff --numstat origin/main -- . ':!docs/superpowers'`: under 150 lines.
- `git diff origin/main | grep -E 'jibotmac|macazbd|azbd2|joimba|macct|azbdmini'`: no hits.

## Acceptance

Spec success criteria 1-4.

## Rollback

`git revert <sha>`; the coordinator reinstalls the poster.
