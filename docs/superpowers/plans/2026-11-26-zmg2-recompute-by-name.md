# Plan: the recompute resolves a thread's scope by its name (ai-tools-alerts#zmg2)

Spec: `docs/superpowers/specs/2026-11-26-zmg2-recompute-by-name-design.md`. One chunk, one commit; about 150 changed lines, most of them tests.

## Chunk by-name

### Task 1: the tests, failing first

- [ ] New file `tests/poster/test_recompute_names.py`. Imports as `tests/poster/test_advisory_recompute.py` does: `env`, `finding`, `FakeKEV`, `T0`, `APPLE` from `test_main`; `catalog`, `levels`, `_kev_with_its_fix` from `test_recompute` (importing the autouse fixture turns it on here, so a KEV candidate states a fix and posts at critical); `ghsa_json` from `advisories`.

Unit tests of the lookup:

- [ ] `test_every_scope_name_resolves_by_name`: for each value `s` of `rules._default_index()`, `rules.scope_named(s.name).name == s.name`; and the names the issue lists (Codex, Cursor, Hermes, git, Python, Go, mcp) each resolve while `rules.scope_of(name)` is None for them (the precondition of the bug: if the scope file later makes one an identity the test says which).
- [ ] `test_a_text_that_is_not_a_name_resolves_nothing`: `cursor ide` (an identity), `cursor` (another case), `No Such Product`, `""`, `None`, `7` all give None.
- [ ] `test_a_former_name_resolves_only_when_asked`: `scope_named("MCP Inspector")` is None; with `former=True` it is an entry named `MCP Inspector` with `formerly == ()` and the class of `@modelcontextprotocol/inspector`; `catalog._scope(x)` equals `rules.scope_named(x, former=True)` for a current name, a former name and an unknown one.

Through `main.run` (one run an hour, the fake relay, KEV fetch and advisory API):

- [ ] `test_a_cursor_thread_is_raised_when_kev_lists_its_cve_with_no_candidate`: the thread is seeded in the ledger (a helper `posted`, built as `test_main`'s former-name test builds its thread: `compose.root_post` from a collector finding with fixed `1.7.4`, then `Ledger.record_root` under scope `Cursor` at high), because a Cursor finding cannot post at high through `main.run` here: its vendor page is plain, so admission drops the fix and holds a notice (plan review, finding 1). The API answers the thread's GHSA with `cve=CVE` and a package that names nothing in scope. Hours 0 to 3 with complete catalogs that do not list the CVE: nothing sent. Hour 4 with a complete catalog that lists it as `{"vendorProject": "Anysphere", "product": "Cursor", "dateAdded": "2026-09-01"}` (before the watermark): the summary says `candidates=0`, one `Level is now` reply to critical goes out, the ledger says critical and exploited. Hours 5 to 8: nothing more. Before the fix: nothing is sent at hour 4.
- [ ] `test_a_cursor_thread_kev_stops_listing_is_lowered_by_the_rules`: `test_recompute.post(env, <a Cursor KEV item>)` posts the thread at critical with the fixture's fix; its floor is notice (a KEV entry alone, as in `test_an_entry_gone_for_a_day_of_complete_reads_lowers_once`; the first draft of this plan said high, wrongly: plan review, finding 2). Hours 1 to 24 with the entry gone from complete catalogs: nothing sent, and the wait for notice is running. Hour 25: one lowering to notice, the hour and level of the Claude Code test. Hours 26 to 40: nothing, no wait left. Before the fix: no wait, nothing ever sent.
- [ ] `test_a_hermes_thread_falls_when_its_advisory_stops_supporting_high`: a finding for `hermes-agent`, severity `moderate`, fixed `1.0`, whose source is the advisory's page in Hermes's own repository (`https://github.com/NousResearch/hermes-agent/security/advisories/<id>`; the helper's default source is Claude Code's repository, which Hermes does not authorise: plan review, finding 3), the API answering `ghsa_json(G, packages=[("pip", "hermes-agent", "< 1.0", "1.0")], repo="NousResearch/hermes-agent")`: posts at high from the fields, floor notice. Then the API answers the same without the weakness (`cwes=()`): hours 1 to 24 send nothing, hour 25 sends one lowering to notice, hours 26 to 40 nothing.
- [ ] `test_a_thread_whose_product_left_the_scope_file_is_not_judged`: post the Hermes thread of the test above, then make the scope file lose the product for the poster: monkeypatch `rules._default_index` to return the index without the entries named `Hermes`. Put a withdrawn advisory on the API and run hours 1 to 30: no level reply, the recompute state's `dwell` is empty, the ledger level is unchanged, and the advisory API was not asked for the thread's id in those runs.
- [ ] `test_a_thread_under_a_former_name_is_not_judged`: a thread seeded under `MCP Inspector` with `posted`. With an advisory API answer that would lower it, then one that would raise it, 34 hourly runs send no level reply and start no wait, and the advisory API is never asked (`env.api.calls == []`). The last assertion is the one that pins it: the seeded thread has no recorded floor, so its floor is its level and no lowering could show, and a read's support is keyed by current names, so no raise could either (plan review, finding 4). Judging the thread reads its advisory; not judging it reads nothing.

- [ ] Run `python3 -m pytest tests/poster/test_recompute_names.py -q`: the lookup tests fail on the missing function, the Cursor and Hermes run tests fail on "nothing sent"; the two not-judged tests may already pass (they pin what must not change).

### Task 2: the lookup

- [ ] `aitools_alerts/poster/rules.py`, after `scope_of` (line 131): add

```python
def scope_named(name, former: bool = False) -> schema.ScopeEntry | None:
    """The scope entry, or the entry resolved to a component, whose NAME is ``name``:
    how a posted thread or a held notice finds its product (the ledger keeps the name a
    post states). Exact, and not ``scope_of``: a name is not always an identity (the
    entry Cursor matches "cursor ide", never "cursor"; zmg2), and an identity is not a
    name. ``former``: also a name an entry lists in ``formerly`` (wa6n: a thread keeps
    the name it was posted under), as that entry carrying the former name. None when
    the scope file has neither."""
```

  with the body of today's `catalog._scope` (`dataclasses.replace` is already imported in rules.py or is added to its imports), the `formerly` branch only when `former`.
- [ ] `aitools_alerts/poster/catalog.py` lines 73 to 86: `_scope(name)` returns `rules.scope_named(name, former=True)`; its docstring says so in two lines; drop the `replace` import if nothing else in the file uses it (`remember` and `snapshot` do not).
- [ ] `aitools_alerts/poster/main.py` line 1440: `scope = rules.scope_named(e.scope) if recompute.judged(e) else None`; line 1441 loses `or scope.name != e.scope`. The `_judge` docstring's "out of scope now" gains "(by its name, `rules.scope_named`; a thread under a former name is not judged: no member's check can confirm a level for it, zmg2)".
- [ ] `aitools_alerts/poster/recompute.py` module docstring: one sentence after the first paragraph saying a thread is found by its product's name and one under a former name is not recomputed.

### Task 3: changelog

- [ ] `CHANGELOG.md`, under `## Unreleased`, a paragraph at the top: what was wrong (threads for Codex, Cursor, Hermes, git, Python, Go, Rust and the MCP Python SDK were never recomputed), what happens now (judged like every other thread; a raise in the first run that reads more, a lowering only under the existing rules, so not within a day of the release), what stays (a thread under a former product name is not recomputed), and that no state file, wire format or scope file changes and a rollback needs no step.

### Verification

- [ ] `python3 -m pytest tests/poster/test_recompute_names.py -q` passes.
- [ ] `python3 -m pytest tests/poster -q` passes with no other test edited.
- [ ] Mutation check, each must fail a named test: `_judge` back on `rules.scope_of`; `_judge` passing `former=True`; `scope_named` comparing case-insensitively; `scope_named` resolving a former name without being asked.
- [ ] `scripts/test-gate.sh` exits 0 (the public scan, then the whole suite).

### Acceptance

The issue's three (Cursor raised with no candidate; a thread whose support falls lowered under ny5g's rules; a product that left the scope file not judged), each a test named above, plus spec criteria 1 to 6.

### Rollback

Revert the commit. No state to rewrite (spec, "Blast radius and rollback").

### After the chunk

Merge `origin/main` before the whole-branch review and again before merging the pull request (3t4p touches the same files: its `Run.copies` calls `catalog._scope`, which keeps its name and meaning). File the follow-up issue for former-name threads. No rollout step: the change ships with the next release, so no note on ai-tools-alerts#fa5a is needed beyond the changelog; say so in the close-out.

## Review dispositions (plan, one independent pass, gpt-6.1-sol)

All four findings were about the planned tests, none about the lookup. Each is fixed in the test descriptions above and in `tests/poster/test_recompute_names.py`.

1. BLOCKER, the Cursor raise test could not create its thread through `main.run`. Fixed: the thread is seeded in the ledger.
2. BLOCKER, the Cursor lowering test expected high and equality with a test that expects notice. Fixed: notice.
3. BLOCKER, the Hermes finding had Claude Code's repository as its source. Fixed: Hermes's own.
4. SUBSTANTIVE, the former-name test's "no reply, no wait" would pass with the thread judged. Fixed: it asserts the advisory API is never asked; the `former=True` mutation fails it.
