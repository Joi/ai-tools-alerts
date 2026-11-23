# Plan: the poster signs only what an authoritative source says (h340)

Spec: `docs/superpowers/specs/2026-11-23-h340-authoritative-sources-design.md`
(sections cited as S1 to S7). One chunk, built in the order below; each step
ends with the named tests green. Tests are written with the step, from the
spec's verification matrix (S7).

## Chunk 1: exact identity, evidence gate, signed wording

### Step 1. Scope file version 5, its loader and the lookup (S1, S2)

Steps 1 and 2 are one step: `rules.scope_of` reads the fields the loader
drops, so neither is green alone. Their tests run together at the end of 2.

- [ ] `spec/scope.json`: `version` 5; no `match_mode`, no `not_match`; each
  `match` a list of exact identities (names, repository slugs, package keys,
  KEV `vendor product` forms, including every form S1 lists); `authority` per
  entry and, where the vendor differs, per component (`[]` for mcp-remote).
  GitHub prefixes name a repository.
- [ ] `aitools_alerts/schema.py`: `SCOPE_VERSION = 5`; `ScopeEntry(name,
  ecosystem, tier, match, authority=(), components=())`,
  `ScopeComponent(name, match, authority=None)`; `load_scope` refuses another
  version, an unknown key, an identity that is not normalised or is listed
  twice in the file, and an authority prefix that is not lowercase `host/` or
  `host/path/`, whose host is not in `spec/primary-domains.json`, or that on
  `github.com` is not exactly `github.com/<listed owner>/<repository>/`.
  Delete `SCOPE_MATCH_MODES`, `_scope_mode`, `_scope_patterns`.
- [ ] `tests/test_schema.py`: replace the cases of
  `test_load_scope_rejects_bad_entries` and
  `test_scope_patterns_avoid_common_words` that test modes with negative
  loader tests, each beside a valid version-5 control: version 4, an unknown
  key, a duplicate identity, an owner-level GitHub prefix, a prefix whose host
  is outside primary-domains.
- Verify: with step 2.

### Step 2. `rules.scope_of` by dictionary lookup (S1)

- [ ] `aitools_alerts/poster/rules.py`: delete `_word_pattern`, `_matches`
  and the tier loop; `_index(entries)` maps each normalised identity to its
  entry resolved to the component (own authority, or the entry's);
  `scope_of` looks the normalised text up and keeps the vendor-word log.
- [ ] Fixtures elsewhere that relied on word matching move to exact
  identities in this step: `tests/poster/test_compose.py`
  (`scope_of("Ubuntu linux kernel")` in the digest tests becomes
  `"linux kernel"`; `test_entry_fallback_composes_under_the_entry_name` uses
  the entry's own identity `"mcp server"`), `tests/test_check.py` wherever a
  product text is not an identity.
- [ ] `tests/poster/test_rules.py`: delete the tests of bounded matching,
  modes, `not_match` and component vetoes; add: every identity of the file
  resolves to its owner; the KEV forms of S1; normalisation (case, NFKC,
  dashes, spaces); the H4 names (`claude-code-router`, `my-docker-helper`,
  `awesome-openssh-wrapper`, `Docker Desktop on Ubuntu`, `OpenSSH9.8p1`,
  `musistudio claude-code-router`) resolve to nothing and those holding a
  vendor word are logged.
- Verify: `python3 -m pytest tests/test_schema.py tests/test_inventory.py tests/test_check.py tests/poster/test_rules.py -k "scope or identity or kev or vendor" -q`
  (the rest of `test_rules.py` goes green in step 4, when `http_page` exists).

### Step 3. Candidates (S1, S4)

- [ ] `aitools_alerts/poster/candidates.py`: `ADVISORY_ID`, `BOT_ID`;
  `from_collector` reads `package` into the product text (`bad package` skip)
  and sets no title; it keeps passing a validated `fixed` and `affected`
  through (`Run.admit` discards them), so the adapter tests of their
  validation stand; delete `_source_title`, `_apple_fixed`,
  `_APPLE_TITLE`; `from_kev` sets `source_title` from `vulnerabilityName`
  through `_title`. Purity survives the adapter: when any entry of a
  finding's `sources` was filtered out or fell past `MAX_SOURCES`,
  `from_collector` clears `advisory_severity`, `trojanized` and
  `injection_exec` itself, since `Run.admit` sees only the kept sources.
- [ ] `tests/poster/test_candidates.py`: package cases; KEV title; a ninth,
  unrelated source after eight vendor URLs and a filtered source each clear the
  three level inputs; remove the source-title and Apple-title tests.
- Verify: `python3 -m pytest tests/poster/test_candidates.py tests/poster/test_inputs.py tests/poster/test_ledger.py -q`.

### Step 4. Evidence (S2, S3)

- [ ] `rules.authoritative(url, scope)`; `rules.base_id(i)`;
  `rules.read_advisory(html) -> Advisory page fields | None` (text before
  "Description"; GHSA, CVE ID, blocks, severity, title);
  `rules.evidence(c, scope, page) -> Evidence(kev, url, ids, fixed, affected,
  title, severity, retry, unparsed)`; `rules.http_page(url, allow, timeout,
  opener) -> (status, text)` replacing `http_status` (GET, one deadline
  thread, redirects only where `allow`, 1 MiB, UTF-8 with replacement);
  `rules.PageBudget`. Remove `source_ok`, `http_status`. Highest version by
  `aitools_alerts.versions`.
- [ ] `tests/fixtures/poster/advisory-page.html`: the labelled part of a real
  repository advisory page (public page of `anthropics/claude-code`, cut to
  the header, the package block, the severity and the CVE ID), and
  `page(...)`, a helper that renders the same markup for any values.
- [ ] `tests/poster/test_rules.py`: the transport tests ported to
  `http_page`; the fixture parses; each evidence row of S7 (the id is not the
  page's; alias poisoning; another package in the repository; CVE-only
  candidate; fixed is the page's highest patched version, never the record's;
  two matching blocks give no range; vendor site page needs id and product
  name; Apple title version; 503 sets retry; unknown markup sets unparsed;
  3 pages a candidate; KEV needs no fetch).
- Verify: `python3 -m pytest tests/poster/test_rules.py -q`.

### Step 5. The gate in `main` and the migration (S4, S6)

- [ ] `aitools_alerts/poster/main.py`: `run(..., page=rules.http_page)`;
  `Run.page` (cache, 40 a run); `Run.admit(c, scope)` as S4 (pure-record rule
  included); both candidate loops call it before `ledger.merge`; `Run.level`
  passes "a page confirmed it"; `plan_known` filters `learned_sources`.
- [ ] `aitools_alerts/poster/inputs.py`: `gate` in the state keys;
  `new_state` writes `gate: 1`; `load_state` migrates a state without it (S6)
  and says so on stderr.
- [ ] `tests/poster/test_main.py`: the `env` fixture serves, for every URL, a
  page rendered from the findings written so far (so a finding whose source
  is the vendor's repository page is confirmed with its own id, product,
  fixed version and severity); findings in existing tests that relied on the
  record's `fixed`, title or severity text are given the page that says so.
  New tests: `test_claude_code_router_advisory_never_names_claude_code`
  (S7 rows 1 to 6 and the KEV `musistudio` row); deferral and retry rows; the
  migration row; the learned-sources row. Three tests assert what the gate
  ends and are rewritten, keeping their bookkeeping coverage:
  `test_ids_learned_past_the_alias_cap` (ids the page does not assign are no
  longer learned: it asserts that, and the cap with page-assigned ids is left
  to `test_compose.py`'s cap test);
  `test_an_unconfirmed_notice_is_listed_once_a_primary_source_confirms_it`
  (the social-only sighting is dropped, `held=0`; the vendor-confirmed one is
  held and listed once);
  `test_a_confirmed_held_notice_keeps_every_id_it_was_held_under` (a held
  notice keeps the ids the vendor page assigns across two sightings).
- [ ] `tests/poster/test_live_replay.py`: serve the vendor page for the
  Claude Code thread with its live fields; in `test_live_feed_replay` leads
  are dropped at admit. `test_live_digests_leads_recomposed` calls
  `compose.root_post` for `LEAD-` candidates directly; it is rewritten to
  assert that `root_post` refuses a lead id and that the two live digests,
  recomposed from the advisories that remain, list no lead.
- [ ] `tests/poster/test_inputs.py`: `gate` in fresh and migrated states.
- Verify: `python3 -m pytest tests/poster -q`.

### Step 6. Signed wording (S5)

- [ ] `aitools_alerts/poster/compose.py`: `root_post` refuses a non-`BOT_ID`
  id; `public_id` is a bare CVE or GHSA id; no Action line for an
  unexpressible fix (en, ja).
- [ ] `tests/poster/test_compose.py`: the three rows of S7; fix the tests that
  used other id shapes.
- Verify: `python3 -m pytest tests/poster/test_compose.py tests/poster/test_translate.py -q`.

### Step 7. Documents

- [ ] `docs/design.md`: the level paragraph and the source paragraph say what
  is authoritative for a product and that the poster reads fields from it.
  `CHANGELOG.md` Unreleased. `spec/primary-domains.json` description: the list
  is the outer fence; `spec/scope.json` `authority` binds a source to a
  product. `README.md` only if it describes scope matching.

## Acceptance (whole chunk)

- `scripts/test-gate.sh` exits 0.
- `grep -rn "_word_pattern\|match_mode\|not_match\|def source_ok\|rules.source_ok\|http_status\|_apple_fixed\|_source_title" aitools_alerts` prints nothing
  (`level_for` keeps its `source_ok` parameter).
- Every row of the spec's verification matrix has a test.
- No test reaches the network (the poster conftest already makes that raise).

## Rollback

Revert the merge commit, reinstall the poster, remove the `gate` key from the
state file (one `python3 -c` line, given in the rollout issue). The old
poster refuses the state until then and sends nothing.
