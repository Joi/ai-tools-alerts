# Plan: a former product name is read the same way on both sides (ai-tools-alerts#aabw)

Spec: `docs/superpowers/specs/2026-11-27-aabw-former-names-both-sides-design.md`. One chunk. The change was first built in a copy of the tree outside the worktree while the spec's review read the worktree, to learn whether the planned tests can be built; this plan describes what that copy holds.

## Chunk: former-names

### Tests first

- [ ] `tests/test_ruleset.py`, `test_a_name_stands_for_itself_or_for_the_entries_that_list_it`: `stands_for` of a product, a component, each kind of former name and seven values that are no name; for every product and every former name, over a reading that binds an MCP server, a KEV entry and a Claude Code advisory, `level([reading], name)` equals the highest `level` over `stands_for(name)`.
- [ ] `tests/test_check.py`: `test_a_former_name_is_found_whole_under_its_entries_ecosystem` (thirteen cases: the four names, another case, another ecosystem, a part of a name, a trailing space, a current name, values that are no string); `test_every_former_name_of_the_scope_file_is_found_and_stands_for_its_entries` (walks the shipped scope file, so a name added later is covered); `test_a_former_name_two_ecosystems_share_is_not_found` (a patched scope: one former name under two ecosystems, and two former names that differ in case only).
- [ ] `tests/test_verify.py`:
  - `test_a_product_that_is_no_scope_product_is_not_judged`: the case `("MCP servers and clients", "mcp")` becomes `("MCP servers and clients", "skill")` and `("MCP servers", "mcp")`.
  - `test_a_cache_of_the_version_before_is_an_empty_one`: versions 6 and 5.
  - `test_a_no_source_stored_for_a_former_name_by_the_version_before_is_read_again`: a `no-source` written into the stored result is not read again under version 6 (no request is made a week later), and under version 5 the cache is dropped and the thread reads `confirmed`/`match` (spec review, finding 1).
  - `test_a_thread_under_a_former_name_is_judged_by_its_own_advisory`, four cases (the shared name with one of its products; in lower case with another; with a second package of another vendor beside it; "MCP Inspector"): at high `confirmed`/`match`; at notice `contradicted`/`below-source`; withdrawn, at notice `confirmed`/`withdrawn` and at high `contradicted`/`unsupported`; an advisory about another product, `contradicted`/`unsupported`.
  - `test_a_former_name_takes_the_highest_support_and_lowers_only_when_all_of_it_may`: `verify.judge` on built records.
  - `test_an_action_that_names_the_former_name_in_another_spelling_completes_a_critical`: a malware advisory, a `stop_using` action spelled in another case; an action that names the current product instead does not complete it (`Ruleset.action_level` compares targets with the name judged).
  - `test_a_claimed_lowering_of_a_former_name_thread_is_confirmed_by_its_withdrawal`: `verify.claimed` is True for the poster's own claim (`Ruleset.claim` for the former name); `verify.lowering` to notice is True after a read of the withdrawal and False after a read that supports high.
- [ ] `tests/poster/test_former_names.py` (new), through `main.run`, then `verify.run` against the same API answers. A helper seeds a thread under a former name with a recorded floor (`Ledger.record_root(..., floor=...)`), composed under `rules.scope_named(name, former=True)` as `Run._former` composes it.
  - withdrawn advisory, for "MCP Inspector" and "MCP servers and clients": nothing sent in hours 1 to 24, a wait at notice running, the member already reads `unsupported`; hour 25 sends one lowering to notice; the member reads `confirmed`/`withdrawn`; hours 26 to 40 send nothing.
  - supported advisory, both names: 30 hours send nothing, no wait, the API was asked, the member reads `confirmed`/`match`.
  - the shared name's advisory names another of the seven: the thread stands, the member confirms.
  - the shared name's advisory names none of them (a package outside the seven), live and withdrawn: 40 hours send nothing, no wait, the API was asked, the member reads `unknown`/`unauthoritative` (code review; the first draft of this line said "lowered at hour 25", which was the defect).
  - a thread at notice whose advisory supports high, both names: raised in that run with `candidates=0`, the member confirms high, not raised again.
  - a thread under a name the scope file never had: not read, no wait, the member reads `no-source`.
  - an enrolled thread (a standing claim set with `Ledger.set_claim(root, text, root_ids=[the first id])`, as a root carries one since gtw9; without `root_ids` `Run._confirming` confirms nothing, plan review finding 1), both names, advisory supporting high: 90 daily runs, no step, every renewal with `confirmed_at == checked_at ==` the run's time and `check_claim` `ok` for the former name, `Ruleset.level_at` high every day from the claims sent, at least five renewals (spec review, finding 2).
  - the same thread under the shared name with every read failing (503): every renewal keeps the root's `confirmed_at`, and the thread has stepped down to notice by day 45.
  - `test_a_response_counts_for_a_former_name_only_when_all_its_support_for_the_names_products_may_lower`: `recompute.support` on a built `sources.Read` with an injected reader: two products that may lower give the higher level, known, one reading counted; one that may not lower beside one that may gives nothing, not known, nothing counted; support for a product the name does not stand for gives nothing, known (plan review, finding 3).
- [ ] `tests/test_unchecked_lowering.py`, `test_the_alias_that_supported_a_former_name_thread_is_read_first`: the fixture of `test_the_alias_that_supported_the_thread_is_read_first` for a CVE-first thread under the shared name: the supporting alias is cached, three others are put before it, the request order is the catalog then that alias, and the lowering stays refused (plan review, finding 2).
- [ ] `tests/test_never_supported_cli.py`, `test_a_thread_under_a_former_product_name_has_its_source_line`: a relay-bot alert posted as `mcp servers and clients` whose advisory names another product; after `pull` and `verify`, `check` prints one `source check:` line, naming "MCP servers and clients".
- [ ] `tests/poster/test_recompute_names.py`: `test_a_thread_under_a_former_name_is_not_judged` is removed (the decision it pinned is reversed; its cases are the new file's); the module's use of `INSPECTOR` and `schema` goes with it if nothing else uses them.

### Code

- [ ] `aitools_alerts/ruleset.py`, after `products()`: `stands_for(product)`.
- [ ] `aitools_alerts/check.py`, before `_concerns`: `former_name(name, ecosystem)` over `schema.load_scope()`.
- [ ] `aitools_alerts/verify.py`: `VERSION = 6`; `_resolved(name, ecosystem)` and `scope_of` over it; `judge` by `rs.stands_for(product)` (docstring says so); `_Target.judge` resolves action targets with `_resolved`; `_Run.thread.weight` expands the thread's names.
- [ ] `aitools_alerts/cli.py`, `_source_lines`: the two `name in scope` tests become `known(name)`, `bool(rs.stands_for(name))` (spec, "Member: cli.py").
- [ ] `aitools_alerts/poster/recompute.py`: module docstring; `support` by `rs.stands_for(scope.name)` for an advisory response and for a KEV entry (docstring says so).
- [ ] `aitools_alerts/poster/main.py`: `_judge` passes `former=True`; its docstring.
- [ ] `CHANGELOG.md`, under `## Unreleased`, at the top: what was wrong, the rule, what a member and the poster do now, what happens to threads already posted, the cache rebuild (version 6), what stays as it was (narrowings and the per-product lines for such a thread; an earlier release's reader), no wire, schema, ruleset, scope or ledger change.
- [ ] `docs/design.md`: only if it states the old decision (grep `former`, `no-source`).

### Verification

- [ ] `python3 -m pytest -q tests/poster/test_former_names.py tests/test_verify.py tests/test_check.py tests/test_ruleset.py tests/poster/test_recompute_names.py`
- [ ] The whole suite: `python3 -m pytest -q`.
- [ ] Mutations, each must fail a named test:
  1. `_judge` without `former=True` → the poster file's lowering, raise, "is read" and renewal tests.
  2. `recompute.support` on `r.support.get(scope.name)` alone → the same.
  3. `recompute.support`'s KEV line on `.get(scope.name)` → survives: no entry that lists a former name has a KEV identity in the shipped scope file, so no catalog entry can bind to one and no test can build the case without a second scope file. The line is the single-name code with the name widened.
  4. `verify.judge` on `rs.products()` → the four-case member test.
  5. `verify.judge` with `any` for `all` in `may_lower` → the built-records test (`critical` over mixed support).
  6. `_Target.judge` back on `check.scope_name` → the action-spelling test.
  7. `check.former_name` comparing exactly → the lower-case cases.
  8. `check.former_name` ignoring the ecosystem → the `skill` cases.
  9. `VERSION` back to 5 → the two cache-version tests.
  10. `stands_for` returning `{product}` for an unknown name → the ruleset test and the "never had" poster test's member line.
  11. `_Run.thread.weight` on the name alone → `test_the_alias_that_supported_a_former_name_thread_is_read_first`.
  12. `recompute.support` with `any` for `all` → `test_a_response_counts_for_a_former_name_only_when_all_its_support_for_the_names_products_may_lower`.
  13. `cli._source_lines` back on `name in rs.products()` → `test_a_thread_under_a_former_product_name_has_its_source_line`.
- [ ] `scripts/test-gate.sh` in a clone that holds this branch alone (the shared clone's public scan reads other sessions' refs).

### Acceptance (the issue's)

- A thread under "MCP Inspector" whose advisory is withdrawn is lowered by the bot under ny5g's rules and a member's check confirms it: the first poster test, case `MCP Inspector`. Since the merge of kk2q the bot's move is the withdrawal, below notice, under the same rules; the test holds that and the member's confirmation of it (spec, "After the merge of main at `d40fef5`").
- A thread under "MCP servers and clients" is handled by the chosen rule, with a test: the same test's second case and the four tests after it.

### Added by the code review

- [ ] `aitools_alerts/verify.py` `judge` and `aitools_alerts/poster/recompute.py` `support`: for a former name, no source naming one of its products is unknown (spec, "Silence about a former name"). The member's four-case test and built-records test and the poster's built-read test carry the cases.
- [ ] `aitools_alerts/cli.py` `_installed_as`, used by `_result`, `_unjudgeable`, `_verified_bucket` and `_check_json`; `tests/test_unverified_cli.py` `test_a_match_on_a_former_product_name_is_shown_and_never_interrupts_as_confirmed` (four packages). This replaces a first fix in `check._identity`, which the delta review refused (spec, "Review dispositions (code)").
- [ ] `aitools_alerts/schema.py` `load_scope`; `tests/test_schema.py` `test_entries_that_share_a_former_name_are_one_kind_of_product`.
- [ ] `tests/test_never_supported_cli.py`: the source-line test reads a withdrawn advisory that names one of the seven (a silent one has no line now).
- [ ] Mutations 14 to 17: `judge` without the silence rule; `support` returning `known` without `named`; a former-name match judged for interrupts (`_installed_as` on `verify.scope_of`), and its `--json` result taken from the thread; `load_scope` without the shared-name rule. Each must fail the test named above.

### Review dispositions (plan, one independent pass, gpt-6.1-sol)

1. BLOCKER, the renewal fixture as described omitted `root_ids`. Fixed in the text; the test as built already passed `root_ids=[G]` and passes. No behaviour changed.
2. SUBSTANTIVE, mutation 11 had no test. Fixed: the alias-order test above; the mutation now fails it.
3. SUBSTANTIVE, mutation 12 had no test. Fixed: the built-read test above; the mutation now fails it.
4. SUBSTANTIVE, the author check could read a stale `origin/main`. Fixed: fetch, the pull request's own merge sha, then the check.

### Rollback

Revert the commit. See the spec.

### Landing

Merge `origin/main` before the whole-branch review and again before merging the pull request. One independent whole-branch review; `scripts/test-gate.sh`; a pull request merged with the no-reply author. After the merge: `git fetch origin`, take the pull request's merge commit from `gh pr view <n> --json mergeCommit`, check that it is `origin/main` (`git rev-parse origin/main`) and that `git log -1 --format=%ae <that sha>` is the no-reply address; close the issue on that sha (plan review, finding 4). A comment on ai-tools-alerts#5fry says what the release carries (no step of its own).
