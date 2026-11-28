# Plan: the admit lane's advisory reads take turns (ai-tools-alerts#vszx)

Spec: `docs/superpowers/specs/2026-11-28-vszx-admit-lane-turns-design.md`. One chunk,
one pull request, under 600 changed lines. Revised after the independent review of
the first draft (see "Review dispositions").

## Chunk: admit-turns

### 1. `aitools_alerts/poster/sources.py`

- [x] `in_turn(ids, after=None) -> list` after `advisory_id`, and in `__all__`:
  sorted distinct ids, starting at `bisect.bisect_right(ids, after)` when `after`
  is a string, else at 0, wrapping.
- [x] `load_turn(path) -> str | None`: `inputs.read_json(path, 4096)`; the value of
  `after` when the object has that key alone and `advisory_id` accepts it; None on
  any exception.
- [x] `save_turn(path, after)`: `inputs.write_json(path, {"after": after})`.
- [x] Module docstring: admission goes on where the last run's requests ended; the
  thread lanes' turn is `Run._in_turn`.

### 2. `aitools_alerts/poster/inputs.py`

- [x] `Config.admit_turn`: `<ledger>.admit-turn.json`; added to the file lists of
  `check_paths` and `check_catalog_paths`.

### 3. `aitools_alerts/poster/main.py`

- [x] `Run.admit(self, c, scope, ev=None)`: computes the evidence only when given
  none.
- [x] `Run.admit_all(self, pairs) -> list`, the spec's five steps. A request was
  made when `self.api.requests` rose across `_admit_read`. The save catches
  `OSError`, `TypeError`, `ValueError`, says so and goes on.
- [x] `main.run`: `pairs = r.admit_all(pairs)`.
- [x] `Run.observe`: the log line names the unread ids, sorted, the first
  `UNREAD_NAMED = 40`, then `and N more`; the existing sentence is kept whole.
- [x] Module docstring, the paragraph on advisory reads.

### 4. Tests

- [x] `tests/poster/test_recompute.py` and `tests/poster/test_claims.py`: the two
  wrappers of `Run.admit` take and pass on the new argument.
- [x] `tests/poster/test_sources.py`: `in_turn` is every distinct id once whatever
  the input order or `after`; the ring goes on past `after`, present or not; ten
  requests a run reach every id in any `ceil(n / 10)` consecutive runs, n = 1..45;
  mixed request counts (4, 0, 10, 1, 0, 0, 7) ask for every id once before any
  twice; the file round-trips and every damaged shape reads as None.
- [x] `tests/poster/test_inputs.py`: the path and its place in `check_paths`.
- [x] `tests/poster/test_advisory_recompute.py`, each with a new collector record
  per run (same findings, same order) and a recorder of `(lane, id)` per request:
  - 34 held notices: ten `admit` requests a run, every four consecutive runs ask
    for all 34, no other lane asks; then the last record place turns malware and
    posts at critical within four runs.
  - 14 candidates that post at high: over six more runs ten `admit` requests each
    and nothing is sent.
  - the pages are fetched and the candidates admitted in record order, every
    request made before the first admission, and the requests are the ring's first
    ten, not the record's.
  - the log line names the unread ids, caps them, and names other ids next run.
  - a six-second API and missing hours: four requests a run, every candidate once
    in each three runs.
  - a damaged turn file starts the ring over; one that cannot be written is said
    and the run is whole.

### 5. `CHANGELOG.md`

- [x] An "Unreleased" section: what was wrong, what changed, the new file, the
  first runs after install, and what is not changed (the slash-slug threads).

## Verification

- `python3 -m pytest tests/poster/test_sources.py tests/poster/test_advisory_recompute.py tests/poster/test_inputs.py -q`
- `python3 -m pytest -q` (whole suite)
- `scripts/test-gate.sh` in a clone that holds only this branch
  (`git clone --single-branch`), since the shared clone's public scan reads other
  sessions' refs. `scripts/public-scan.sh --hit-ids` against this branch's objects
  first.
- Mutations, each must fail a named test:
  1. `admit_all` asks in record order (`for i in asks`);
  2. the pre-pass dropped (`admit` per pair, as before);
  3. the place is never saved;
  4. the place is the last id asked, granted or not;
  5. `in_turn` ignores `after`;
  6. `bisect_left` in place of `bisect_right`;
  7. a failed save raises.

## Acceptance

The spec's seven criteria, each by a named test; the suite green; no assertion of
an existing test changed.

## After the code

- A comment on ai-tools-alerts#g9bv: nothing to sign or migrate; the new file to
  include in backups; what the first runs show; how to confirm the turn from the
  log line.
- A follow-up issue for the thread ids with a slash in the slug (spec, "The other
  question"), priority 2, labels `repo:ai-tools-alerts` and `discovered-from:vszx`.
- Merge main before the review and again before the merge (the brief).

## Rollback

Revert the merge commit, or install the earlier release. The turn file can stay.

## Review dispositions

Independent review of the first draft (fresheyes, gpt-6.1-sol, high) at 25df706:
2 blockers.

1. BLOCKER, two existing wrappers of `Run.admit` (`tests/poster/test_recompute.py`,
   `tests/poster/test_claims.py`) take two arguments and would raise once
   `admit_all` passes the evidence. Fixed: both pass it on (step 4).
2. BLOCKER, one collector record is consumed once, so the planned test would have
   measured the deferred list's rotation and the thread lanes' requests. Fixed:
   a new record per measured run, requests counted per lane, and the quiet-cycle
   test asserts ten `admit` requests in each of its runs.
