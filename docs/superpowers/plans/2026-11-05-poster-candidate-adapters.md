# Poster candidate adapters — implementation plan

Spec: docs/superpowers/specs/2026-11-05-poster-candidate-adapters-design.md.
Kata: ai-tools-alerts#6j8x. One chunk; one commit
`feat: poster candidate adapters (heartbeat, KEV, collector)`.

## Chunk 1

### Files

| File | Change |
|---|---|
| `tests/fixtures/heartbeat/run.json` | new, redacted from host-b run 2026-11-04T175014Z |
| `tests/fixtures/heartbeat/feeds.json` | new, trimmed copy |
| `tests/fixtures/collector/run-record.json` | new, trimmed and redacted `run-levels.json` |
| `aitools_alerts/poster/__init__.py` | new, docstring only |
| `aitools_alerts/poster/candidates.py` | new: `Source`, `Candidate`, `CandidateList`, helpers, three adapters |
| `tests/poster/__init__.py` | not created: tests/ has no `__init__.py` today (rootdir import mode) |
| `tests/poster/test_candidates.py` | new |
| `pyproject.toml` | `packages = ["aitools_alerts", "aitools_alerts.poster"]` |

### Steps

- [ ] 1. Redact fixtures with a scratchpad script (not committed): build the real host
  set from `host_coverage`, findings' `hosts`/`affected_hosts`/`host`, key segments
  and nested host-named keys; map each to `host-A`.. in sorted order; drop
  `evidence*`, `latest_evidence`, `latest_run`, `build`; empty `alerts`; replace
  free text that carries observed versions. Then grep the output for every real
  name (exit non-zero on any hit) and for `/Users/`.
- [ ] 2. Write `tests/poster/test_candidates.py` (failing):
  - `test_from_heartbeat_maps_fixture`: ids, product_text derivation for each key
    form, one Source each, hint lowercased, `unknown` → None, `other-leads` skipped
    and counted under `no source`.
  - `test_heartbeat_adapter_never_emits_hosts_or_evidence`: serialize
    `[c.to_dict() for c in ...]` to JSON; assert no host from the fixture (built from
    the fixture's own `host_coverage` and findings) and none of the six fleet names
    appears, and no `/Users/`, `evidence`, `jibot-code#` string.
  - `test_heartbeat_scrubs_hosts_in_text_and_drops_host_urls`: inline run.json in
    `tmp_path` with a host in `advisory_severity`, `product`, and a source URL.
  - `test_heartbeat_unreadable_or_malformed_never_raises`: missing dir, invalid JSON,
    `findings` a string, a finding that is a list, wrong-typed fields.
  - `test_from_kev_maps_feed_items`: feeds fixture `cisa-kev`; exploited True,
    product_text `WordPress WordPress Core`, catalog source first.
  - `test_kev_adapter_filters_by_date_added`: three dates around `since_date`.
  - `test_kev_catalog_shape_and_notes_urls`: `vulnerabilities` key, notes with two
    URLs and junk, bad cveID and bad dateAdded skipped and counted.
  - `test_kev_rejects_bad_since_date`: `ValueError`.
  - `test_from_collector_maps_fixture`: ids, aliases, sources, hint, and
    `exploited` False even where the fixture says `true` (KEV-only); no
    affected_hosts/rationale in output.
  - `test_collector_untrusted_input`: wrong schema_version, non-list findings,
    string `exploited: "true"` stays False, overlong id skipped, too many aliases capped.
  - `test_fixtures_contain_no_fleet_names`: read all three fixture files as text.
  - Added after the spec/plan review (fresheyes pass 1): one
    `test_*_private_values_in_retained_fields` per adapter. Synthetic private values
    (a local path, a kata ref, a host in `local_severity`, `observed_at`,
    `published_at`, `affected`, a forged `exploited: true`, userinfo and `/Users/`
    URLs) go into fields the adapter keeps, with one clean source so the candidate
    survives; the test asserts the survivor's fields are dropped or normalized and
    the serialized output holds none of the markers. The fixture-level checks stay,
    but they are not the runtime privacy proof.
  - Added after the whole-branch code review (fresheyes pass 1 on 1e1cf71):
    backtick-wrapped paths, percent-encoded host/path/kata ref in source URLs, a
    host in product text, `fixed` wildcards, a hostile `affected` range timed under
    one second, deeply nested `run.json`; fixture kata refs replaced by
    `tracker#aaaN` and checked absent.
- [ ] 3. Run `python3 -m pytest -q tests/poster` → fails on import.
- [ ] 4. Implement `candidates.py` per the spec.
- [ ] 5. Run `scripts/test-gate.sh` → all pass. Run
  `python3 -c "from aitools_alerts.poster.candidates import from_kev"`.
- [ ] 6. Commit (stage named files only).

### Acceptance

- Gate green; import line exits 0; fixture-name test green.
- Size: the 600-line rule is exceeded (code and tests about 800 after two rounds of
  privacy hardening the reviews required; fixtures about 320). decided on
  ai-tools-alerts#6j8x: one module and its tests do not split into separately
  landable pieces.

### Verification commands

```
scripts/test-gate.sh
python3 -c "from aitools_alerts.poster.candidates import from_kev"
grep -RniE 'host-a|host-b|host-d|host-e|host-f|host-c' tests/fixtures/heartbeat tests/fixtures/collector  # expect no output
```

### Rollback

`git revert <sha>`; nothing else depends on the module yet.
