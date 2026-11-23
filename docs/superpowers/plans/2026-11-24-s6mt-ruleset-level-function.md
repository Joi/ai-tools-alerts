# Plan: the level as a function of structured source fields (ai-tools-alerts#s6mt)

Spec: `docs/superpowers/specs/2026-11-24-s6mt-ruleset-level-function-design.md`. Two chunks, in order; the second depends on the first. Tests first in each task. Run everything from the repo root.

## Chunk 1: the ruleset

### Task 1.1: `spec/ruleset.json` and the loader

Files: create `spec/ruleset.json`, `aitools_alerts/ruleset.py`, `tests/test_ruleset.py`.

- [ ] Tests (fail first): the shipped file loads; `load().version == 1`; `ttl_days` has the three levels; a copy with an unknown top-level key, an unknown `when` condition, a level outside `levels`, version 2, a `lowers: false` row that sets `high`, a row with a `second` or `with_second` key, or a source with no catch-all row raises `RulesetError`.
- [ ] `spec/ruleset.json`: `version`, `description`, `levels`, `ttl_days`, `tier_cap`, `reading_cap`, `fields`, `sources` (seven rows of the spec's source table), `rules` (the spec's level table).
- [ ] `ruleset.py`: `RulesetError`, `norm`, `tier_of`, `index` (moved from `poster/rules.py`, which re-exports them in chunk 2), `Ruleset.__init__` validating every key, `load()` cached, reading `schema.SPEC_DIR`.
- [ ] `pyproject.toml` needs no change: `spec/*.json` is already package data. Check with `python3 -c "import aitools_alerts.ruleset as r; print(r.load().version)"`.

### Task 1.2: readings, binding and the level

- [ ] Tests (fail first), each from a fixture in `spec/claim-vectors.json` `levels` cases:
  - KEV reading "Anthropic Claude Code": critical for "Claude Code"; KEV "Linux Kernel": high (tier 2 cap); KEV "Cisco IOS XE": `read` is `{}` and the level for "Claude Code" is `none`; KEV `name: null`: `none`.
  - OSV `MAL-` for `npm:@anthropic-ai/claude-code`: high; the same with a GHSA `type: malware` reading for that package: critical (that reading is critical alone); with a low-severity vendor advisory for the same product instead: high (nothing adds up); with a `ghsa-reviewed` reading instead: high; `MAL-` for `npm:claude-code-router`: `none`.
  - GHSA unreviewed, severity critical: notice, `lowers` false. GHSA from `anthropics/claude-code` (vendor), severity high: high; CWE-506: critical; severity medium, CVSS `AV:N`, CWE-78, a patched package: high; the same with no patch: notice. The same vendor fields with `repository: "attacker/claude-code"`: notice.
  - A withdrawn GHSA: `Support.level` is `none`, `level()` is `none`.
  - Malformed readings raise: a missing key, an extra key, a float, an unsorted `cwes`, `cwes: null`, an uppercase ecosystem, the same package twice in reverse order, the same package entry repeated, a `ghsa_id` in uppercase hex.
- [ ] `ruleset.py`: `_reading` validation, `Support`, `Ruleset.read`, `Ruleset.level`, `Ruleset.class_level`, `capped`, `rank`, `highest`.

### Task 1.3: the claim, its canonical form, the digest and the pin

- [ ] `spec/claim-vectors.json`: `description` (the canonical form in words), `claims` (each `{name, product, claim, canonical, sha256}`: a KEV claim, `poster-kev`; `poster-ghsa-page`, a vendor GHSA claim with no CWE data and one package listed with two ranges; a GHSA claim with a non-ASCII package name; an OSV `MAL-` claim; a `none` claim), `levels` (the Task 1.2 cases as `{name, product, readings, level}`).
- [ ] Tests (fail first): for every `claims` vector `canonical(claim).decode() == canonical`, its SHA-256 matches, and `check_claim(claim, product) == "ok"`; `canonical` refuses a float, a non-NFC string, a control character, an integer past 2**53; `parse_claim` refuses an id that is not the fields' id, `confirmed_at > checked_at`, an unknown key.
- [ ] Verdict tests: a claim with the wrong level is `mismatch`; malformed is `refused`; `ruleset: 2` is `unknown`; with a pin whose `min_version` is 2 and a reader at 1 it is `outdated`; with a pin at this version and another digest it is `outdated`. Downgrade: build a version-2 ruleset in the test (`VERSION` patched to 2, the `osv-mal` source row's `alone` and the `osv-mal` level rule both raised to critical); assert first that the version-2 ruleset itself computes critical for the `MAL-` reading; then the version-1 `MAL-` claim (level high) checked with it is `mismatch`, and with a pin `min_version: 2` it is `refused`.
- [ ] Digest test: `load().digest` is 64 hex characters, changes when one `ttl_days` value changes, and changes when the scope data changes.
- [ ] `ruleset.py`: `canonical`, `source_of`, `parse_claim`, `Ruleset.claim`, `Pin`, `parse_pin`, `check_claim`, `digest`.

Chunk 1 acceptance: `python3 -m pytest tests/test_ruleset.py -q` passes; `python3 -c "import aitools_alerts.ruleset, sys; assert 'aitools_alerts.poster' not in sys.modules"` exits 0.

## Chunk 2: the poster computes its level from the ruleset

### Task 2.1: evidence and candidates carry the readings

Files: `aitools_alerts/poster/rules.py`, `candidates.py`, `ledger.py`, `inputs.py`, `main.py`; tests in `tests/poster/test_rules.py`, `test_ledger.py`, `test_inputs.py`.

- [ ] Tests (fail first): `evidence` on the fixture advisory page returns `ghsa`, `repository` (`owner/repo`, lowercase) and `packages`; `from_kev` puts one `kev` reading on each candidate, its `name` the entry's `vendorProject` and `product` joined by one space, and none when that text is not a valid field; `readings_for` gives one `ghsa` reading for a page-confirmed candidate (blocks given in reverse order come out sorted, a repeated block once, `cwes` is `[]`), none for a vendor site page, none when the page's fields do not form a valid reading; merge, defer, reload: a collector candidate first and a KEV candidate for the same CVE merge to one candidate with the collector's product text, `exploited` true and the KEV reading naming CISA's own string; after `to_dict` and `candidate_from` it has `exploited` true, no reading, and `level_for` still gives `("critical", "kev-tier1")`; `Candidate.to_dict()` has no `readings`; `candidate_from(c.to_dict())` round-trips; `ledger.merge` joins members' readings without duplicates.
- [ ] `rules.py`: `_norm`, `_tier`, `_index` become the ruleset's (`from aitools_alerts.ruleset import norm as _norm, ...`); `Evidence` gains `ghsa`, `repository`, `packages`; `evidence` fills them from the page (`rank == 2` only); `readings_for(c, scope, ev)` returns a tuple of `(source, canonical JSON text of the fields)` (text, so a frozen `Candidate` stays hashable). The page's severity word `moderate` is written `medium`, the API's word.
- [ ] `candidates.py`: `Candidate.readings: tuple = ()`, dropped by `to_dict` like `severity_word`; `from_kev` sets it. `main.admit` keeps a candidate's `kev` readings and adds the page's. `inputs.py`: `candidate_from` allows for it. `ledger._merged`: the union, in order. 

### Task 2.2: `level_for`, `basis`, `claims_for`

- [ ] Tests (fail first): a tier-1 trojanized candidate and a tier-1 injection candidate with a fix are `("high", "reading")` when a page confirmed them and `("high", "unverified")` when none did; a tier-2 candidate with either flag is still a notice; an injection candidate with no fix still falls through;
- [ ] Existing tests whose expectation was a critical made by a flag change to the new level and keep their other assertions: `tests/poster/test_rules.py` `test_trojanized_without_primary_is_high_unverified`, `test_injection_exec_needs_fix`; `tests/poster/test_main.py` `test_kev_learned_at_the_same_level_makes_the_japanese_action_urgent`: a flag can no longer open a critical thread, so "KEV learned at the same level" needs a thread that is critical for another reason. The test keeps its subject (a KEV listing learned on a thread already critical makes the Japanese action urgent, the title is kept, two replies) by opening the thread through a path that is still critical; if no such path exists without a flag, it is rewritten as the raise it now is: first run one root on the feed channel (the candidate carries a range so the six-hour hold does not apply) titled "trojanized release"; after the KEV listing one copy on the critical channel and one reply on the feed, the title "known exploited vulnerability", and the urgent Japanese action asserted on the messages of that run. Title retention at the same level stays covered by `tests/poster/test_compose.py` (the thread that was a trojanized release keeps its title when KEV adds it). The source-isolation test near line 2008: its `pure` finding gets a source-confirmed range so the hold does not apply; it then posts HIGH on the feed channel only, and every assertion that no other record's text or source reaches the post stays. The hold itself keeps its own existing tests. Any other test that fails is fixed only if its expectation was a critical made by a flag, and is named in the run manifest; anything else is a bug in the change; a KEV tier-1 candidate with no reading (carried from the ledger) is still `("critical", "kev-tier1")`; `basis` is `fields` for a KEV candidate and for a page whose severity word is high, `reading` for a trojanized candidate; `claims_for` returns claims whose `check_claim(..., scope.name)` is `ok`.
- [ ] Admission path (`tests/poster/test_main.py`, through `main.run` or `Run.admit` with the fake pages): a collector finding confirmed by its repository advisory page comes out of `admit` with exactly one `ghsa` reading whose fields are the page's; a KEV candidate comes out with its `kev` reading; a KEV candidate and a page-confirmed finding for the same CVE merge to a candidate with both, and `claims_for` on it returns two claims, each `ok`; a candidate read back from the state file comes out of `admit` with no `kev` reading.
- [ ] No lowering by a reading: a thread posted HIGH from a trojanized flag, then a run where the same advisory arrives without the flag, posts no level change and the ledger keeps `high`.
- [ ] Lowering authority: for `ghsa-other` and `osv-other`, a live reading and a withdrawn one both have `lowers` false and never a level above notice; a withdrawn `ghsa-malware` and `osv-mal` have `lowers` true (Task 1.2's tests carry these).
- [ ] Property test (seeded `random`, 500 cases; it asserts the number of claims equals the number of readings put in, so a builder that drops claims fails): candidates over tier-1 and tier-2 products, every flag combination, readings built from random page fields. For each: every claim is `ok`; `level_for`'s level is never below any claim's level; it is `critical` only when the candidate is `exploited` on tier 1 or a claim is `critical`; with no claim and no `exploited` it is at most `reading_cap`.
- [ ] Shared vectors: `tests/poster/test_rules.py` loads `spec/claim-vectors.json` and builds the `poster-kev` and `poster-ghsa-page` vectors through `readings_for` and `claims_for` from a candidate and the fixture page; the canonical bytes equal the vector's; the page for `poster-ghsa-page` lists the same package in two blocks, in reverse order, and has no CWE data.
- [ ] `rules.py`: `level_for` as the spec's poster section states; `basis(c, scope, level)`; `claims_for(c, scope, now)`.
- [ ] Docs: `docs/plan.md` Global Constraints line on critical (a model's reading never makes a critical; the level table is `spec/ruleset.json`), `README.md` if it states the critical rule, `CHANGELOG.md` under Unreleased.

Chunk 2 acceptance: `python3 -m pytest tests/poster -q` passes with only the named expectations changed; `scripts/test-gate.sh` passes.

## Verification

`scripts/test-gate.sh` (the public scan, then the whole suite). Check the first commit is signed: `git log --show-signature -1`.

## Rollback

Revert the merge commit. Nothing is written to the state file, the ledger or the wire.
