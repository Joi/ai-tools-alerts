# Plan: the member's source check (ai-tools-alerts#fv4g)

Spec: `docs/superpowers/specs/2026-11-24-fv4g-member-source-check-design.md`. Two chunks, one pull request. Tests are written first in each chunk and fail before the code exists.

## Chunk 1: `aitools_alerts/verify.py`, two `Ruleset` methods, the config key

Files:

- `aitools_alerts/verify.py` (new, about 400 lines)
- `aitools_alerts/ruleset.py`, after `class_level` (about line 399): `Ruleset.products() -> frozenset[str]`, the names the scope index resolves to; `Ruleset.lowers(source, fields) -> bool`, the `lowers` of the first source row that matches the reading with no product (a row with `vendor_own` does not match). Tests in `tests/test_ruleset.py`.
- `aitools_alerts/config.py`: `VERIFY = ("matched", "all", "off")`; `Settings.verify: str = "matched"` (after `lang`, line 90); parsing in `load` beside `lang` (line 141); a commented block in `TEMPLATE` (after the `lang` block, line 203)
- `tests/conftest.py`: an autouse fixture that sets `verify.default_fetch` to a function that raises `OSError`
- `tests/test_verify.py` (new), `tests/fixtures/verify/` (invented responses: a KEV catalog of three entries, two GHSA responses, an OSV response)

Steps:

- [ ] 1. Tests for `norm_id` and `url_of`: `cve-2026-1234` becomes `CVE-2026-1234`; `GHSA-ABCD-EFGH-IJKL` becomes `GHSA-abcd-efgh-ijkl`; a `LEAD-…` key, a URL, `../x`, an id with a space, a slash or a `?`, and a synthetic id give None; `url_of` returns only the three shapes with the last segment percent-encoded, and raises for anything `norm_id` did not return.
- [ ] 2. Tests for `Ruleset.products` and `Ruleset.lowers`: KEV true; GHSA `reviewed` and `malware` true; GHSA `unreviewed` and `type` null false, also when its repository is a product's own (no product in hand); OSV `MAL-` true, other OSV false; a malformed reading raises `RulesetError`.
- [ ] 3. Tests for the three field readers against the fixtures and each malformed variant: a wrong type for every key read; `ghsa_id` or `id` that is not the id asked; a `repository_advisory_url` on another host or of another shape; `count` not equal to the list's length; a non-ASCII name; a vector cut short. Each raises. The ids a response names (`cve_id`, `identifiers[].value`, `aliases`) are returned only when `norm_id` accepts them, at most 50.
- [ ] 4. Tests for `judge`, one per row of the per-product table and for the thread summary's order, including: not complete with `S` above `P` is `unknown`; a withdrawn unreviewed GHSA under a critical is `unknown` for `unauthoritative`; a withdrawn reviewed one is `contradicted` for `unsupported`; a product outside the scope file is `unsupported`.
- [ ] 5. Tests for `run` with a recording fetch. Each names the criterion it proves.
  - Criterion 5: a KEV entry for another vendor's product on a Claude Code critical: `contradicted`, `unsupported`. A thread naming a supported product and Claude Code: the first `confirmed`, Claude Code `contradicted`, the summary `contradicted`.
  - Criterion 6: first id a CVE that KEV does not list, alias a real critical-making GHSA for the same product whose response names another CVE: no support from it. The same alias whose response names the first id: counted. First id a GHSA, an alias its response does not name: not requested. More than 3 eligible aliases: 3 requested, the thread `unread`.
  - Criterion 4: 404, 429, 403, 500, 301, a raised timeout, a truncated JSON body, a duplicate key, `NaN`, a `ghsa_id` for another id, and a 304 with nothing stored: each `unknown` for `unread`, no result stored as decisive, and the thread is requested again next run. Two lookups where one supports `P` and the other fails: `unknown`, then `contradicted` for `below-source` once the second answers with more.
  - Criterion 1: a thread whose `sources` names `https://evil.example/x`, whose title and product names hold URLs: every requested URL is one of the three shapes.
  - Criterion 2: 10,000 threads with distinct GHSA ids: 10 requests. A clock that passes 30 seconds after the third request: three requests. The timeout passed to the fetch is `min(10, what is left)`.
  - Cache: one KEV request serves every CVE thread; a second run for a changed thread sends `If-None-Match` and a 304 keeps the support; a new CVE id after a stored ETag sends none; a confirmed thread is not requested again; a changed level is; waiting threads go highest level first, then longest untried.
  - After a good 200 is cached and the published state then changes (so the thread is read again), each of 404, 429 and a truncated body gives every product `unknown` for `unread`, saves no decisive result for the new state, and the next run asks again: old support is never a fallback for a failed read.
  - State changes over persisted state, starting from a confirmed result: a bot patch that adds an unsupported product gives that product `contradicted`; one that adds an eligible alias whose read fails makes the thread `unknown`; a changed level is read again.
  - Criterion 3: an ETag with a quote, a newline or 200 characters is not stored. The response fixtures for this test carry a unique sentinel text (`ZZ-SENTINEL-n`) in every text field the reader must not keep (`summary`, `description`, `vendorProject`, `product`, `name` of a package, `vulnerable_version_range`, `source_code_location`, a named alias, an unknown key) and none appears in `verify.json`. The file is then checked by structure: its keys are the fixed ones; `sources` keys are ids the test's own threads carried; `support` keys are scope product names; every other value is a level word, a result or reason word, a boolean, an integer, a 64-character hex digest, the ETag, or null.
  - Nothing a source says is printed: `run` over responses with sentinel text in every field, a duplicate key named by a sentinel, and a fetch that raises `OSError("ZZ-SENTINEL")` prints no sentinel on stdout or stderr and logs nothing else from the exception.
  - A cache written under another ruleset digest (the `Ruleset` given to `run` is built from a changed scope) is ignored: the request carries no `If-None-Match` and the result is recomputed. A corrupt or mis-shaped file is an empty cache.
  - A curator's thread has no result; `mode="matched"` reads only the matched threads; `off` is the caller's: `results(..., mode="off")` gives `unknown`/`off` without reading the file, and a stored result is there again when the mode returns.
- [ ] 6. Tests for `default_fetch` with the connection class replaced on the module (no network): it refuses `http://`, a fourth host, `https://api.github.com@evil.example/`, `https://api.github.com:444/` without opening a connection; a 302 with `Location` returns status 302 after one request; a connection whose `connect` blocks, one whose `getresponse` blocks and one whose `read` blocks each raise within the timeout (tested with a timeout of 0.2 seconds, the elapsed time asserted under 1 second); a connection whose `connect`, `getresponse` and `read` each take 0.15 seconds raises at a timeout of 0.3 seconds (the deadline is for the whole request, not each phase); with the real `default_fetch` under `run` and a clock at 29.8 seconds of the run, a connection that blocks is abandoned after about 0.2 seconds, not 10; `Content-Length: 500` with 100 bytes of complete JSON raises; a response with neither a length nor chunking raises; `Content-Encoding: gzip` raises; a body over the limit raises; a good 200 returns its body and its ETag; the request headers are the four the spec lists.
- [ ] 7. Write `ruleset` methods and `verify.py`: constants, `norm_id`, `url_of`, `default_fetch`, the three readers, `judge`, `summary`, the cache (`_load`, `_save`), `run`, `results`, `state_key`.
- [ ] 8. `config.py` and its tests in `tests/test_cli.py` (`verify = "sometimes"` is a `ConfigError` naming the key; the three values load; the default is `matched`).

Verification: `python3 -m pytest tests/test_verify.py tests/test_ruleset.py tests/test_cli.py -q`.

Acceptance: spec criteria 1 to 6, and 7 except the README text.

## Chunk 2: the CLI, the README and the changelog

Files:

- `aitools_alerts/cli.py`: `cmd_run` calls `verify.run` when not `--json` and the mode is not `off` (after `_matches`, line 404), inside a `try` that turns any exception into the one fixed stderr line `source check failed` (never the exception's text: a parser's message can quote the response); `cmd_verify`, its parser entry and its entry `"verify": cmd_verify` in the dispatch dictionary of `main` (line 464); `_source_lines` printed by `cmd_check` (before the count line, line 313) and `cmd_plan`; `source_check` in `_match_json` (line 250); the module docstring's command list
- `README.md`: the section "Checking alerts against the source" after "Run it every hour"; one sentence in "Interrupt the next Claude Code session" that the hook's command reads no source
- `CHANGELOG.md`: a paragraph under Unreleased
- `tests/test_verify_cli.py` (new)

Steps:

- [ ] 1. Tests (criterion 8): with a recording fetch on `verify.default_fetch`, `run` requests; `run --json`, `check`, `check --json`, `plan <id>` and `notify` request nothing; `verify = "off"` makes `run` and `verify` request nothing; the exit status and stdout of `run` are the same with a fetch that raises as with `verify = "off"`.
- [ ] 2. Tests: after a run that stored `below-source`, `check` prints the line; with a certificate whose `min_cli` is above this release it does not; `unsupported` prints its line; an `unknown` prints nothing; a thread whose first id is a URL-shaped string prints no source-check line; the levels and match lines `check` prints are identical before and after a run whose fetch returns 404, 429 or a truncated body (criterion 4's "change nothing").
- [ ] 3. Tests: `check --json` and `run --json` carry `source_check` for the matched product; `cli.main(["verify"])` prints the summary line and exits 0; with responses full of sentinel text and a fetch that raises with a sentinel message, neither `run` nor `verify` prints a sentinel on stdout or stderr.
- [ ] 4. The code, then the README and the changelog.
- [ ] 5. A test that the shipped hook's command is `aitools-alerts run --json` and the cron and launchd commands are `aitools-alerts run` with no `--json`, so "never in the hook" is tied to the shipped files.

Verification: `python3 -m pytest -q` for the whole suite; then commit and run `scripts/test-gate.sh` (in a single-branch clone when the shared clone's history scan fails on other sessions' refs).

Acceptance: spec criteria 7 to 9.

## Order and landing

Chunk 1, chunk 2, one review round of the whole change (a same-model reviewer and the independent one, in parallel), fixes, commit. `git fetch origin && git merge origin/main` before the review and before the merge. The gate; a pull request; merge with the no-reply author; `git log -1 --format=%ae origin/main`; close the issue on the merge commit. Notes go on ai-tools-alerts#ny5g (which response keys the member reads) and ai-tools-alerts#tavj (what `verify` gives it).

## Rollback

Revert the merge commit. `verify.json` in a member's state directory is then a file nothing reads; the `verify` key in a config file is ignored like any unknown key.
