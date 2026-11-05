# Plan: poster input visibility, digest ids, --digest-now, --kev-file (ai-tools-alerts#akq9)

Spec: docs/superpowers/specs/2026-11-05-poster-input-visibility-design.md

## Chunk 1: inputs visibility

- [ ] `aitools_alerts/poster/candidates.py` (`CandidateList.__init__` ~l.95): add
  `self.rejected = None`; set it beside each whole-input `skipped[...]` early return in
  `from_heartbeat` (too large, unreadable, not an object, findings shape), `from_kev`
  (not an object, items not a list), `from_collector` (schema_version, findings not a list).
- [ ] `aitools_alerts/poster/inputs.py` `load_kev` (~l.330): rename body to
  `fetch_kev(cache, fetch, deadline) -> (catalog, status)`; `load_kev` wraps it.
- [ ] `aitools_alerts/poster/main.py` `gather` (~l.360): build `status` (kev, collector,
  heartbeat accepted/read); heartbeat mark = last accepted dir before the first rejected;
  collector mark only when `from_collector` did not reject; stderr lines per S2;
  `run()` passes `n`-adjacent `skipped = Counter()` and prints the per-item line.
- [ ] `SUMMARY` line: append ` inputs=...` (also on error paths; `kev:-` style fields
  are not used: before gather runs, the field reads `inputs=-`).
- [ ] Tests (`tests/poster/test_main.py`): `test_summary_shows_kev_unavailable_and_rejected_collector`,
  `test_rejected_collector_holds_watermark`, `test_rejected_heartbeat_holds_watermark`;
  `tests/poster/test_inputs.py`: `fetch_kev` statuses; `tests/poster/test_candidates.py`:
  `rejected` set.

Verify: `python3 -m pytest -q tests/poster`.

## Chunk 2: digest ids and --digest-now

- [ ] `inputs.py`: `_STATE_KEYS` += `digest_ids`; `new_state` adds `[]`; `load_state`
  accepts the old key set by adding `digest_ids: []`, validates hex64 list ≤ 10.
- [ ] `main.py` `_record` digest branch: append `it["sent"]` if absent, keep last 10;
  print the stderr line.
- [ ] `Run.digest`: `digest_now` bypasses the hour; on `digest_date == today` with
  `digest_now`, print the "already sent" line; on a journaled digest, print that.
- [ ] `main()`: `--digest-now`; `run(..., digest_now=False)`.
- [ ] Tests: `test_digest_id_recorded_and_printed` (cap 10 via a pre-filled state),
  `test_old_state_without_digest_ids_loads`, `test_digest_now_once_per_date`.

## Chunk 3: --kev-file

- [ ] `inputs.read_kev_file(path)`: strict read (`read_json`, `MAX_KEV`), `_catalog_ok`,
  non-empty, each entry dict with `vulnerabilityName` str containing `SYNTHETIC TEST`;
  else `ConfigError`.
- [ ] `gather(..., kev_catalog=None)`: when given, `from_kev(catalog, "0001-01-01")`,
  status `file`, no `kev_since` mark, `synthetic` = folded ids of those candidates;
  file candidates skip the `old` filter.
- [ ] `Run.one`: a synthetic candidate that is busy or known is dropped (counted
  `withheld`), never deferred; `plan_new` with a synthetic notice: withheld; root
  composed with `test=True`. `run()`'s stop path filters synthetic out of `defer`.
- [ ] `compose.root_post(..., test=False)`: head `+ " (SYNTHETIC TEST)"`.
- [ ] `main()`: `--kev-file PATH`, read before `run`, ConfigError → exit 2.
- [ ] `tests/fixtures/kev-synthetic.json` per spec S9.
- [ ] Tests: `test_kev_file_bypasses_fetch_and_marks_posts` (fetch never called, cache
  absent, head line, `kev_since` unchanged, `inputs=kev:file`),
  `test_kev_file_refused_exits_2` (via `main.main` with a bad file),
  `test_kev_file_candidate_never_deferred`.

## Verification

`scripts/test-gate.sh` (whole suite). Grep the diff for fleet host names
before review.

## Acceptance

Spec S1–S10.

## Rollback

Revert the commits; remove `digest_ids` from the live state file before an
older poster runs (spec, blast radius).
