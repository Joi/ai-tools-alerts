# Plan: the admit lane's advisory reads take turns (ai-tools-alerts#vszx)

Spec: `docs/superpowers/specs/2026-11-28-vszx-admit-lane-turns-design.md`. One chunk,
one pull request, well under 600 changed lines.

## Chunk: admit-turns

### 1. `aitools_alerts/poster/sources.py`

- [ ] Add `in_turn(ids, hour) -> list` after `advisory_id`, and to `__all__`.
  Sorted distinct ids; `share = LANE_READS` read at call time (tests patch it);
  `k = (hour * share) % n`; `order = ids[k:] + ids[:k]`; `head = order[:share]`;
  `j = (hour // ceil(n / share)) % len(head)`; return
  `head[j:] + head[:j] + order[share:]`. Empty input gives `[]`. Non-negative
  `hour` only is promised; a negative one must still return a permutation.
- [ ] Module docstring: the `admit` lane's requests go to the candidates in turn
  (`in_turn`); the thread lanes' turn is `Run._in_turn`.

### 2. `aitools_alerts/poster/main.py`

- [ ] `Run.admit(self, c, scope, ev=None)`: after the `BOT_ID` check,
  `ev = rules.evidence(c, scope, self.page) if ev is None else ev` (line 1120).
  Docstring: one sentence on `ev`.
- [ ] New `Run.admit_all(self, pairs) -> list` next to `admit`, as the spec's four
  steps: evidence for each pair in order; the lookup ids of
  `ev.structured and ev.ghsa`; `self._admit_read(i)` over
  `sources.in_turn(ids, self.now // 3600)`; then
  `[(a, scope) for (c, scope), ev in zip(pairs, evs) if (a := self.admit(c, scope, ev)) is not None]`.
- [ ] `main.run` line 3204: `pairs = r.admit_all(pairs)`; keep the h340 comment.
- [ ] `Run.observe` lines 1909-1911: the log line names the unread ids, sorted,
  the first `UNREAD_NAMED = 40`, then `and N more`. Keep the existing sentence
  so anything that matches on it still does.
- [ ] Module docstring lines 57-61: admission's reads go to the candidates in
  turn, so each is read within `ceil(n / 10)` runs.

### 3. Tests

- [ ] `tests/poster/test_sources.py`:
  - `in_turn` returns a permutation of the distinct ids for any input order, and
    `[]` for none.
  - for every n in 1..45 and every start hour in 0..2n: the union of the first
    `LANE_READS` of `ceil(n / 10)` consecutive hours is every id (criterion 1).
  - for every n in 1..45: over `n * ceil(n / 10) * 10` hours every id is first at
    least once (criterion 3).
  - with `LANE_READS` patched to 3 the window follows it.
- [ ] `tests/poster/test_advisory_recompute.py`, beside
  `test_many_candidates_leave_the_threads_their_reads`:
  - 34 candidates in one collector record: each of four consecutive runs asks for
    ten, and together they ask for all 34; a fixed order would ask for ten
    (criterion 1). Start at an hour that is not a multiple of the cycle.
  - the candidate in the last record place answers as malware: within four runs
    its thread is posted or raised to critical (criterion 2).
  - a steady set over one full cycle after the first posts: no post in any run
    (criterion 5).
  - the log line names an unread id (capsys) and caps at 40.
  - `Run.admit` without `ev` still admits (covered by existing callers; assert
    one directly only if none exists).
- [ ] Fix any existing test that pinned the old request order, and say which in
  the pull request.

### 4. `CHANGELOG.md`

- [ ] An entry under "Unreleased": what was wrong, what changed, what the first
  runs after install look like, no state or wire change.

## Verification

- `python3 -m pytest tests/poster/test_sources.py tests/poster/test_advisory_recompute.py -q`
- `python3 -m pytest -q` (whole suite)
- `scripts/test-gate.sh` in a clone that holds only this branch
  (`git clone --single-branch`), since the shared clone's public scan reads other
  sessions' refs. `scripts/public-scan.sh --hit-ids` against this branch's objects
  first.
- Mutations, each must fail a named test: stride 1 in place of `LANE_READS`; no
  rotation inside the window (`j = 0`); `admit_all` asking in record order;
  the pre-pass dropped (`admit` per pair).

## Acceptance

The spec's six criteria, each by a named test; the suite green; no test of
admission's results changed.

## After the code

- A comment on ai-tools-alerts#g9bv: nothing to sign or migrate; what the first
  runs show; how to confirm the turn from the log line.
- A follow-up issue for the thread ids with a slash in the slug (spec, "The other
  question"), priority 2, labels `repo:ai-tools-alerts` and `discovered-from:vszx`.
- Merge main before the review and again before the merge (the brief).

## Rollback

Revert the merge commit. No state to undo.
