# Plan: btqg, a later advisory joins the open thread of its fix

Spec: docs/superpowers/specs/2026-11-28-btqg-join-open-thread-by-fix-design.md
One chunk, one deliverable. Expected size: about 120 lines of code, 200 of tests.

## Chunk 1: join

### Task 1: ledger, `Entry.joined`
File: `aitools_alerts/poster/ledger.py`
- [ ] `Entry`: add `joined: bool | None = None` after `withdrawn`, with a comment
      (btqg: a member joined this thread by its fix; the group range rule holds).
- [ ] `_entry_ok`: `and ("joined" not in e or e["joined"] is True)`.
- [ ] `Ledger.add_ids(root, ids, joined=False)`: with `joined`, set `e["joined"] = True`;
      save when either the ids or the flag changed.
- [ ] Test `tests/poster/test_ledger.py`: a ledger with `"joined": true` loads; with
      `"joined": false` or `1` is refused; `add_ids(..., joined=True)` sets it and saves.

### Task 2: finding the thread, `Run._fix_thread` and `Run._gone`
File: `aitools_alerts/poster/main.py`
- [ ] `Run.__init__`: `self.mirror = (TRUST_ROOT_PUBKEY, None)`; `_gone` caches its answer
      in `self._gone_now` (absent: not read yet; None: the pull failed this run).
- [ ] `run()`: before `r.make_way(merged)`, `r.mirror = (translate_kw.get("root", TRUST_ROOT_PUBKEY), mirror_fetch)`.
- [ ] `Run._gone()`: `(ids, roots)` from `_withdrawn(*self.mirror)` once a run; None when
      the pull failed (said once: `join by fix held: <err>`), cached either way.
- [ ] `Run._fix_thread(c, scope)` -> `(scope, entry) | None`:
      key = `ledger.fix_key_of(c.fixed)`; none, or a synthetic c -> None. Names:
      `scope.name`, and each of `scope.formerly` that no other scope entry lists
      (spec review: a shared former name says nothing of the product).
      Candidates: `self.led.entries()` with `e.scope` in names, not synthetic id, not
      `e.withdrawn`, `ledger._fix_key` of the thread's current fixed equal to key
      (a small helper `ledger.fix_key_of(fixed)` shared with `_fix_key`), and room:
      `len(fold(e.aliases) | fold(c ids)) <= ledger.BLOCK_IDS` (51, the cap `_chunks` keeps).
      None found -> None (no mirror read). Then `_gone()`; None -> None
      (`self.n["join held"] += 1`). Drop a thread when `compose.withdrawn(adv, ids, now)`,
      when the candidate's ids meet the retracted ids, or when `{root, *channel ids}`
      meets the gone roots. First left: return `(scope if e.scope == scope.name else
      replace(scope, name=e.scope, formerly=()), e)` (as `_former`).
- [ ] `Run._thread_for(c, scope)` -> `(scope, entry, joined)`: `_former` + lookup as `one`
      does now; when no entry and the candidate is not synthetic, `_fix_thread`; then the
      louder rule (spec review: a KEV listing or the exploited mark is no more tied to
      the first id than GHSA fields): `alone = self._rate(c, scope, None)[1]`;
      `RANK[alone] > RANK[entry.level]` or `c.exploited and not entry.exploited` ->
      `(scope, None, False)`. A join never changes the level or the mark.
- [ ] `make_way`: use `_thread_for` (a joined raise passes as a known one would).

### Task 3: `Run.one` and `plan_known`
- [ ] `one`: `scope, entry, joined = self._thread_for(c, scope)` replaces the `_former`
      + lookup lines. The busy check runs on `ids` first (unchanged order: a candidate
      whose own ids hold work never looks for a fix thread). Then, if joined,
      `busy([*entry.aliases, *ids], scope.name, learn=False)` with the same `_clears`
      rule, deferring under the candidate's own scope. `busy(..., learn=False)`: the hit
      items learn no ids (spec review: their send would record the member into the
      thread past the join's checks).
      Order inside `_thread_for`: the own-id busy check must come before `_fix_thread`,
      so `one` calls own-id busy, then `_thread_for` only when not busy. (make_way calls
      `_thread_for` without the busy check, as it calls `_clears` today.)
- [ ] `plan_known(c, scope, level, reason, ids, entry, joined=False)`:
      - `own_fix = False` when joined (the thread's fix stands; equal by key);
      - `fresh` learned with `add_ids(root, fresh, joined=joined)`; when joined and
        `fresh` is empty still set the flag (call `add_ids(root, [], joined=True)`);
      - affected: joined -> `_join_range(was, c, was.fixed)`; else group rule when
        `compose.covers(prev)[0] not in (0, 1) or entry.joined`, else as now;
      - `source_title=entry.source_title or compose.source_title(c)` when joined; the
        `learn_title` line unchanged (it only fills an empty title).
- [ ] `_join_range(was, c, fixed)` (module level, beside `_group_range`): member range
      `compose.schema_affected(c.affected)`; None or thread None -> None; equal -> was;
      else `<fixed` when `compose.schema_fixed(fixed)`, else None.

### Task 4: tests, `tests/poster/test_main.py` (section "btqg: a later member joins")
- [ ] joins: run 1 `finding()`; run 2 `finding(fid=GHSA_Z)` -> roots=0, replies=0, no
      calls; ledger aliases hold GHSA_Z; `learned_sources` holds Z's page; `joined` True.
- [ ] louder posts its own root: a KEV-listed CVE of another advisory with the same fix
      -> its own critical roots, the thread stays high; Z whose advisory reads as malware
      (api.put) -> its own root.
- [ ] busy: run 2 a range correction of A whose reply send is unknown; run 3 Z -> no
      send for Z, Z deferred, every outbox key unique, no item holds Z's id, the state
      loads; `resolve --delivered` records the reply without Z; run 4 joins Z (joined,
      the range widened).
- [ ] retracted: manifest retracts A's id -> Z posts its own root; Z's own id retracted
      -> own root (no join); thread withdrawn in the ledger (`withdrawn` set) -> own root;
      mirror down -> own root and the summary still exits 0.
- [ ] range: A `>=2.0,<2.1.0`, Z `<2.1.0` -> one reply, range `<2.1.0`; Z with no range
      -> reply, range None; then A alone `>=2.0,<2.1.0` again -> no reply, range kept.
- [ ] full: a thread holding 51 ids is not joined.
- [ ] former name (`tests/poster/test_former_names.py`): a fetch advisory fixed in 1.0
      never joins a git thread under "MCP servers and clients"; an inspector advisory
      joins the "MCP Inspector" thread.
- [ ] Update existing tests that post a second advisory with the same fix in a later
      run and expect a second root: give the second a different fix, as faxq did, and
      say so in a comment (`btqg: another fix, another thread`).

### Verification
- `python3 -m pytest tests/poster -q -x` while building; then `scripts/test-gate.sh`
  (public scan + whole suite) after the commit.
- Acceptance: the Task 4 tests pass; the existing suite passes.

### Rollback
Revert the merge commit. A ledger with `"joined": true` is refused by an older poster;
`jq 'del(.entries[].joined)'` before running one.

### Docs
- CHANGELOG.md Unreleased: one line.
- docs/design.md, the post format / group by fix paragraph: one sentence on the
  later-run join (check where faxq wrote its line).
