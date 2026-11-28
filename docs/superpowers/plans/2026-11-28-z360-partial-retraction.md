# Plan: z360 partial retraction of a fix group

Spec: docs/superpowers/specs/2026-11-28-z360-partial-retraction-design.md. One chunk.
Revised after the spec+plan review (see the run record).

## Chunk 1: poster releases proven survivors of a retired thread

- [ ] `aitools_alerts/poster/ledger.py`
  - `Entry.split: dict | None = None`; `_entry_ok` accepts absent or
    `{"released": [str], "kept": [str]}`.
  - `Ledger.release(root, released, kept)`: removes `released` (case-folded) from the
    entry's `aliases` (never the last id), unions both lists into `split`, one save.
  - `Ledger.released_ids() -> set[str]` (case-folded, every entry's `split.released`).
- [ ] `aitools_alerts/poster/main.py`
  - `Run.__init__`: `self.gone = frozenset()`.
  - `Run.retire(root) -> list[(Candidate, ScopeEntry)]`:
    - stored mirror (`State.load(config.mirror_dir)`, `accepted(root)`); on any error or
      no manifest: return [].
    - `gone` = case-folded `m.retracted`; empty: return [].
    - threads under `m` and under `replace(m, retracted=())` over the stored events;
      retired roots = retracted under the first, not the second.
    - entries whose `root_event_id` or any `channel_ids` value is a retired root.
    - for each: undecided ids = published ids not in gone, not in `split`; for each id
      (bounded by RETIRE_PAGES new page fetches a run): `_evidence_for(entry, id)` ->
      released / kept / None (undecided).
    - pointers for released ids -> `state["deferred"]` (dedup by scope and id) and
      `self.deferred`; `self.save()`; then `led.release(...)`.
    - return the released pointers as pairs for this run.
  - `_evidence_for(entry, i)`: scopes = `scope_named(name)` or every entry listing
    `name` in `formerly`; pointer per scope; `rules.evidence(c, scope, self.page)`.
    Structured and no id in gone -> (released, pointer, scope). `ev.retry` -> None.
    Else kept.
  - `run()`: `split = r.retire(root)` before `r.settle`; add to `later` (dedup against
    deferred ids). After admit: drop pairs with any id in `r.gone`
    (`skipped["retracted, not planned"]`).
  - `plan_new`: no 0dvh demotion when any id is in `led.released_ids()`.
- [ ] Tests, `tests/poster/test_main.py` section "z360":
  - acceptance (two-member group, retract one, reader check);
  - single advisory retracted by GHSA: CVE kept, no root;
  - survivor page fails: released next run;
  - old survivor still posts a root;
  - relay-bot reply alias retracted: nothing retired;
  - `tests/poster/test_ledger.py`: `split` loads, bad `split` refused, `release` keeps
    the last id.
- [ ] `CHANGELOG.md` (Unreleased).
- [ ] Follow-up issue: held fix-group notices with one retracted member.

Verification: `python3 -m pytest tests/poster -q -k "z360 or retract or split"`, then
`scripts/test-gate.sh` on the committed head.

Acceptance: the tests pass; the gate passes.

Rollback: revert; delete `split` from ledger entries.
