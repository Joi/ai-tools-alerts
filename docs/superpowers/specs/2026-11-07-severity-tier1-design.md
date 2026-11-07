# severity-tier1: an advisory's own high severity on a tier-1 product posts as high

Kata: ai-tools-alerts#0vy7 (found by amplifier-bundle-joi#cfe8).

## Problem

`rules.level_for` returns `high` for a tier-1 candidate only through
`fix-rce-tier1`, which needs both a `fixed` version and advisory text matching
`_SEVERE` (code execution, credential theft, data loss). The security-watch
collector, extended by cfe8 to the ai-tools tier-1 products and repo-level
GitHub advisories, writes `advisory_severity` as the GHSA level word (`high`,
`critical`) and no top-level `fixed`. So CVE-2026-88968
(GHSA-5xjx-9qx6-jcrv, Claude Code, high) and CVE-2026-86063
(GHSA-pq7j-f95f-qfcv, Claude Code, high) reach the poster as tier-1 candidates
and post as `notice`, in the next day's digest, instead of as `high` within the
hour.

## Decision (coordinator, ruling jibot-code#k777)

A new reason `severity-tier1`: tier 1, none of the critical rules apply,
`fix-rce-tier1` does not apply, the candidate's `advisory_severity` normalised
(`rules._norm`: NFKC, lowercase, whitespace runs to one space, then stripped)
is exactly `high` or `critical`, and the candidate's `id` or one of its
`aliases` is a CVE id (`CVE-\d{4}-\d{4,}`) or a GHSA id
(`GHSA(-[0-9a-z]{4}){3}`), matched whole → `("high", "severity-tier1")`.

- No `fixed` required. Whether a fix exists changes compose.py's advice
  sentence ("Fixed in …" / "No fixed version is known yet"), not the level.
- `fix-rce-tier1` stays and is checked first, so its reason is kept when both
  apply.
- `critical` stays reserved for the three existing critical rules: an advisory
  severity of `critical` gives `high`.
- Tier 2 is unchanged: only `kev-tier2` raises it.
- The advisory-id guard is what "the severity must come from an advisory"
  means in code. A news lead (`LEAD-…` id, no advisory alias) never qualifies,
  whatever its severity text. A heartbeat finding with a CVE id and a level
  word qualifies too, which is the same claim: the advisory set the word.

What `from_collector` sets today, pinned by the acceptance test:
`advisory_severity` is the record's `advisory_severity` string (stripped,
host-scrubbed); `fixed` is `None` unless the record carries a top-level
`fixed` (or the Apple title prefix for macOS). `from_kev` sets
`advisory_severity=None` and `exploited=True`; KEV goes through `kev-tier1`
first, so the new rule never sees it.

## Success criteria

1. A collector record finding `CVE-2026-88968`, alias `GHSA-5xjx-9qx6-jcrv`,
   product `claude-code`, `advisory_severity: "high"`, no `fixed`, runs through
   `from_collector` + `scope_of` + `level_for` to tier 1,
   `("high", "severity-tier1")` (the issue's acceptance).
2. `tests/poster/test_rules.py` covers: high, critical, `"High "` and NFKC
   variants → severity-tier1; moderate, low, None → notice; tier-2 high →
   notice; fix-rce-tier1 wins when both apply; a lead with severity text and no
   advisory id → notice.
3. docs/plan.md Global Constraints and Task B2 state the rule; the README has
   no level description, so it is unchanged.
4. Whole suite green; under 150 changed lines (run artifacts excluded); no
   version bump.

## Alternatives rejected (do not revisit)

- Keep the impact-text rule and have the collector pass impact text: two
  repos, and neither real advisory's text matches `_SEVERE`.
- Require `fixed`: the collector does not write it yet. The coordinator filed
  the amplifier-bundle-joi follow-up that adds it, for the advice text only.
- A substring or `_SEVERE`-style search on the severity: free-text heartbeat
  severities ("High: remote code execution") are already `fix-rce-tier1`'s
  job; a level word must be the whole field, so "not high" stays notice.

## Blast radius and rollback

One function in `aitools_alerts/poster/rules.py`; its consumers (main, ledger,
compose) treat `high` from any reason the same way. More candidates post as
`high` to the feed channel within the hour; none reach `critical`. Rollback:
revert the commit and reinstall the poster; posts already sent stay (a curator
`level:` reply can amend one).

The poster is live; the coordinator reinstalls it after landing. Nothing live
is done in this run.

## Open questions

None.
