# The member's source check: three fixed endpoints, three results (ai-tools-alerts#fv4g)

Findings D7 and D8 of the design review on ai-tools-alerts#h29n; rules 1, 4 and 5 of its revised design. Builds on `aitools_alerts/ruleset.py` (ai-tools-alerts#s6mt) and the checkpoint (ai-tools-alerts#ek5q).

## Problem

A member's CLI believes whatever level the relay bot's key signs. The self-correcting design lets the bot lower an alert with no curator, so a stolen bot key could lower a true alert or post a false one. The defence is that each member reads the primary source and computes the level with the ruleset. Nothing does that yet.

The fetch is itself an attack surface (finding D7). If the CLI followed a URL from an event, a stolen key could point every member's machine at any host, count the members, or spend their GitHub rate limit. And a source that cannot be read must not look like a source that says no (finding D4): a 404 or a truncated body is not a withdrawal.

## Scope of this slice

The issue was split before the build (decision on ai-tools-alerts#fv4g). This slice reads the sources and reports a result for each product of each relay-bot thread. It changes no level, no notification and no auto-apply decision. Applying the results (the table of finding D8: lowerings, keep the higher, two unverified interrupts per key) is ai-tools-alerts#tavj.

## Success criteria

1. The CLI can request three URL shapes and no other: the CISA KEV file, `https://api.github.com/advisories/<GHSA id>`, `https://api.osv.dev/v1/vulns/<id>`. The id comes from the thread's advisory id and aliases, each accepted only when `ruleset.source_of` names its source. A test gives a thread `sources` on another host and asserts no request leaves for it.
2. Each request: https, no redirect followed, at most 8 MB for KEV and 256 KB for an advisory, strict JSON (no duplicate key, no `NaN`), and at most 10 seconds from the call to the answer, name lookup and TLS included. A run makes at most 10 requests and spends at most 30 seconds, and a request started late gets only what is left of the 30. A test with 10,000 threads counts at most 10; tests with a connection that blocks in each phase show the run still ends in time.
3. Only typed fields are read. Nothing a response says is printed. What is stored from a response is: levels and booleans computed by the ruleset; the ETag, kept for the conditional request, only when it has the shape of an ETag; and SHA-256 digests of the ids a response names, for the alias rule below. A test searches the state file for every string of the response fixtures.
4. Every product of every thread checked has one of three results. `confirmed` and `contradicted` rest only on bodies that came with status 200, arrived whole (the length the response declared), parsed completely and passed the checks below, under the ruleset this reader runs now. If any read a thread needs failed, every product of the thread is `unknown`. A timeout, a redirect, 403, 404, 429, a 5xx, a parse error, a size overrun, a body shorter than its declared length (even when what arrived is complete JSON) and a 304 with nothing stored are each a failed read, tested one by one, and after each the levels `check` prints are the ones it printed before.
5. Product binding: a real exploited CVE whose KEV entry names another vendor's product, posted as a Claude Code alert, is `contradicted`. A thread that names a product the source supports and adds one it does not is `contradicted` for the added product, and the thread's summary is `contradicted`.
6. A stolen bot key cannot borrow authority: an alias the source does not tie to the thread's first id adds no support. A source the subject's attacker can write (the ruleset's `lowers: false`) never gives a downward `contradicted`.
7. `verify = matched | all | off` in the config, default `matched`. The README says what each tells CISA, GitHub and OSV about the member.
8. The check runs in `aitools-alerts run` (what the hourly job runs) and in a new `aitools-alerts verify`. It never runs in `run --json` (what the session-start hook runs), in `check`, `plan` or `notify`. A test runs each and counts requests.
9. `scripts/test-gate.sh` passes, with no test touching the network.

## Approach

### 1. One module, `aitools_alerts/verify.py`

It imports `ruleset`, `schema` and `state.write_json`. The poster does not import it.

**Ids.** `norm_id(text)` puts `CVE-` ids in upper case and `GHSA-` ids in the form the poster writes (`GHSA-` then lower case) and returns the id only when `ruleset.source_of` names a source for it and it is not synthetic (`schema.is_synthetic`); otherwise None. The thread's first id is the root's `id`, which no patch can change. A thread whose first id is None has the result `unknown` for `no-source` and is never read or flagged. Everywhere below, and in every line this slice prints, "id" means a value `norm_id` returned.

**URLs.** `url_of(id)` is one of three constants with the id percent-encoded into the last path segment:

| Source | URL | Limit |
|---|---|---|
| `kev` | `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` | 8 MB |
| `ghsa` | `https://api.github.com/advisories/<id>` | 256 KB |
| `osv` | `https://api.osv.dev/v1/vulns/<id>` | 256 KB |

No other function builds a URL, and no field of an event but `id` and `aliases` reaches this one.

**Aliases.** Aliases are the bot's to replace (note from ai-tools-alerts#s6mt), so an alias proves nothing by being listed. An alias counts only when a source ties it to the first id:

- the response read for the first id names the alias (`ghsa`: `cve_id` and `identifiers[].value`; `osv`: `aliases`), or
- the response read for the alias names the first id (the same keys).

KEV names no other id, so when the first id is a CVE each `ghsa` or `osv` alias is read and counts only if its own response names that CVE. When the first id is a GHSA or OSV id, an alias is read only if the first response names it. At most 3 aliases of a thread are read, in listed order among those eligible; an eligible alias left unread makes the thread incomplete. An alias that is not tied adds no support and removes none. The cache keeps, per id read, the SHA-256 digests of the ids its response names (only values `norm_id` accepts, at most 50), never the text.

**Fetch.** `default_fetch(url, etag, limit, timeout) -> (status, etag, body)`:

- refuses a URL that is not `https://<one of the three hosts>/...` with no port and no userinfo;
- runs the request in a daemon thread and waits `timeout` seconds for it, no longer; a request still running then is abandoned and is a failed read. This bounds name lookup, connection, TLS, the header read and the body alike, which a socket timeout does not. The engine passes `min(10, what is left of the run's 30 seconds)`;
- inside the thread: `http.client.HTTPSConnection` (it follows no redirect and reads no proxy variable), socket timeout `timeout`, headers `User-Agent: aitools-alerts`, `Accept: application/json`, `Accept-Encoding: identity`, and `If-None-Match` when an ETag is passed;
- a 200 body is accepted only when the response has no `Content-Encoding` other than `identity`, and either declares `Content-Length` and exactly that many bytes arrived, or is chunked and was read to the end of the last chunk (`http.client` raises on a chunk cut short). A response with neither is a failed read: nothing says where it ends. More than `limit` bytes is a failed read;
- raises `OSError` on any failure.

Tests replace `default_fetch` for the engine, and replace the connection class to test `default_fetch` itself: a connection that blocks in `connect`, in `getresponse` and in `read`; a 302 with a `Location` (returned as 302, one request made); a declared length of 500 with 100 bytes of complete JSON; a body over the limit. A fixture in `tests/conftest.py` makes `default_fetch` raise in every other test, so no test reaches the network.

**Fields.** One function per source turns a decoded 200 body into the reading `ruleset` defines, or raises:

- `kev`: the catalog must be an object with a text `catalogVersion`, a list `vulnerabilities` of objects each with a text `cveID`, and a `count` equal to the list's length. The reading of a CVE id is `{cve_id, name}`: `name` is `vendorProject` and `product`, each trimmed, joined by one space, or null when the catalog does not list the id. An id listed more than once gives one reading per entry.
- `ghsa`: `ghsa_id` must equal the id asked for. `type` is the response's. `withdrawn_at` is null or the response's text. `repository` is the lower-cased `owner/repo` of `repository_advisory_url` when that is `https://api.github.com/repos/<owner>/<repo>/security-advisories/<id>`, null when it is null. `severity` is the response's, with `unknown` read as null. `cvss_vector` is the first text among `cvss_severities.cvss_v3.vector_string`, `cvss_severities.cvss_v4.vector_string` and `cvss.vector_string`, else null. `cwes` is the sorted distinct `cwe_id` values. `packages` is one entry per `vulnerabilities[]` item: the package's `ecosystem` in lower case, its `name`, `vulnerable_version_range` (empty read as null) and `first_patched_version`, put in order by `ruleset.ordered`.
- `osv`: `id` must equal the id asked for. `withdrawn` is the response's text or null when the key is absent. `packages` is one entry per `affected[]` item that has a `package`: its `ecosystem` in lower case and its `name`, with `range` and `first_patched` null (OSV states events, not a range text, and the ruleset derives nothing).

A key of the wrong type raises. The reading then goes through `Ruleset.read`, which refuses anything outside the ruleset's own formats (a string outside printable ASCII, a vector cut short, text in `withdrawn_at` that is not a time). Every failure here is a failed read.

What is kept from a good read of one id:

- `support`: `{scope product name: [level, lowers]}` from `Ruleset.read` (`none` for a withdrawn reading; `lowers` is the class's);
- `lowers`: whether the reading, for a product it does not name, may justify a lowering: the `lowers` of the first row of the ruleset's source table that matches the reading with no product in hand (rows that need the product, `vendor_own`, do not match). New method `Ruleset.lowers(source, fields)`. KEV: true. A reviewed or malware GHSA: true. An unreviewed one, and an OSV entry that is not `MAL-`: false;
- `names`: the digests for the alias rule;
- `etag`, `at`.

**Result, per product.** For a relay-bot thread with published level `P`, each of its products is judged alone. A product whose name is not a scope product name (`Ruleset.products()`, new: the names the scope index resolves to) is `contradicted` for `unsupported` when the thread is complete: no source can support it.

- A thread is `complete` when the first id and every eligible alias were read well in this run or are held from an earlier one.
- `S` is the highest level any counted id gives the product, `none` when none does.
- `may_lower` is true when every counted id's word on this product has `lowers` true: the product's own entry in `support` where there is one, else the reading's `lowers`.

| Case | Result | Why |
|---|---|---|
| not `complete` | `unknown` | `unread` |
| `S` above `P` | `contradicted` | `below-source`: the source supports more than was published |
| `S` equals `P` | `confirmed` | |
| `S` below `P`, not `may_lower` | `unknown` | `unauthoritative`: only a source its subject's attacker can write says less |
| `S` is `none` | `contradicted` | `unsupported`: the source does not support this alert for this product |
| `S` is notice or high, `P` is critical | `contradicted` | `above-source`: a reading of prose never makes a critical |
| `S` is notice, `P` is high | `unknown` | `reading`: the level may rest on a reading, which no member can check (finding D2) |

A failed read comes first: with one read missing, `S` is only a lower bound, and neither "equal" nor "above" is known. The thread is tried again next run.

**Result, per thread.** The summary of a thread is the first of these that any of its products has: `contradicted` (`unsupported`, then `above-source`, then `below-source`), `unknown`, `confirmed`. One supported product never confirms another.

Other fixed reasons for `unknown`: `no-source`, and `off`, which is never stored: with `verify = "off"` the CLI shows every result as `unknown` for `off` and reads and writes no cache, so turning the check back on resumes where it was. A curator's thread has no result: the curator override is ai-tools-alerts#c1g2. This slice does not read the claim tag; ai-tools-alerts#tavj uses it to tell a field-based claim from a reading.

**Budget and cache.** `verify.json` in the state directory, written whole with `state.write_json`:

```
{"version": 1, "ruleset": "<digest>",
 "kev": {"etag": "...", "at": 0},
 "sources": {"<id>": {"etag": "..." or null, "at": 0, "lowers": true,
                      "support": {"<product>": ["<level>", true]}, "names": ["<digest>"]}},
 "results": {"<state key>": {"at": 0, "products": {"<product>": {"result": "...", "why": "...", "source": "<level>" or null}}}}}
```

- `ruleset` is `ruleset.load().digest`, which covers the level table and the scope file. A file with another digest, another version, another shape, or that does not parse is an empty cache: no support, no result and no ETag computed under other rules is used, so the next read is a full one.
- The state key is the SHA-256 of the canonical JSON of the thread's first id, its sorted aliases (as `norm_id` returns them), its level and its sorted product names: the published state the result was computed for. Copies of one advisory in two channels share it.
- A thread is read when it has no result for its state key, or any of its products is `unknown` for `unread`. Other results stand until the published state or the ruleset changes (finding D7's rule).
- Threads waiting are taken highest level first, then longest untried. Each id is requested at most once a run. The KEV file is requested at most once a run and serves every CVE id. A request is counted before it is sent; at 10, or once 30 seconds have passed, the run stops and what is left stays as it was.
- Conditional requests. A request carries the stored ETag only when the support it would confirm is held under this ruleset (for KEV: every CVE id wanted this run has a support read at that ETag). A 304 then means the body whose 200 was parsed is still what the source serves, and the stored support is used. A 304 with no such support is a failed read. So every decisive result rests on a parsed 200 body; the 304 only says that body is current. An ETag is stored only when it matches `(W/)?"<1 to 128 printable ASCII characters, no quote>"`.
- Entries for threads and ids no longer current are dropped at each save.
- The run does not hold the state lock while it fetches: a pull started by the hook must not wait 30 seconds. Two runs at once each save a whole file; the later one wins, and the loss is a cached result.

### 2. Config

`verify` in `config.toml`: `"matched"` (default), `"all"` or `"off"`; anything else is a `ConfigError` naming the key. The default file gains a commented block.

- `matched`: only threads that match something installed on this machine are read.
- `all`: every current relay-bot thread, within the budget.
- `off`: no request; every result shows as `unknown`.

### 3. CLI

- `run` (not `--json`): after the pull and the match, `verify.run` for the configured mode, then the usual output. A failure of the check never changes the exit status of `run`.
- `verify`: the same check on the stored state, then one summary line (`source check: N confirmed, N contradicted, N not verified`) and the flagged lines.
- `check` and `plan` print, from the cache only, one line per flagged product after the matches: `source check: <id> is published at <level> for <product>; the source supports <level>` for `below-source` and `above-source`, and `source check: the source does not support <id> for <product>` for `unsupported`. `<id>` is the thread's first id as `norm_id` returned it (a thread without one is never flagged), the levels are the four fixed words, and `<product>` is printed only when it is a scope product name, else the fixed words `a product outside the scope file`. A CLI the trust root says is too old (`_min_cli`) prints no `below-source` line (revised design rule 8): its ruleset may be the one that is wrong.
- `check --json` and `run --json` add `"source_check": {"result", "why", "source_level"}` (or null) to each match, for the matched product, from the cache.

### 4. Documentation

README: a section "Checking alerts against the source" with the three endpoints, the limits, the three results and the privacy of each `verify` value: the KEV file is the same request for every member and names no alert; `matched` tells GitHub or OSV, by address, which advisories apply to tools on this machine; `all` asks about every alert, which hides which ones apply and takes more runs within the budget; `off` tells nobody anything and verifies nothing. CHANGELOG entry. `docs/design.md` is not changed: the revised design lives on ai-tools-alerts#h29n.

## Alternatives considered

- **Fetch the URL the alert cites.** Refused by finding D7: SSRF, a member census, a rate-limit weapon.
- **`urllib` with a redirect handler that refuses** (as `notify` does). `http.client` has no redirect code to get wrong and reads no proxy variables.
- **A socket timeout as the deadline.** It does not bound name lookup, and it restarts at every read. The worker thread with a bounded wait is how the poster already bounds its KEV fetch.
- **Take the highest level over every listed alias.** An alias is the bot's to write; an unrelated critical advisory for the same product would confirm a fabricated one.
- **One result per thread.** A product the source supports would confirm one it does not.
- **Store the reading's fields in the cache.** The issue forbids storing a string from a source. Levels and `lowers` per scope product, bound to the ruleset digest, are enough to compute any thread's result.
- **Never use a 304.** The issue asks for conditional requests with stored ETags. The rule above keeps every decisive result resting on a parsed 200 body.
- **Compare the claim's fields with the live fields.** The poster does not send claims yet, and its fields come from another page than the member reads (note from ai-tools-alerts#s6mt). A comparison of levels is what the D8 table needs.
- **Run the check in the hook.** The hook has a time budget and runs at every session start; the issue forbids it.
- **Re-read confirmed results on a timer.** Not in finding D7; it would spend the member's GitHub allowance on alerts that have not changed.

## Blast radius and rollback

New module, a new state file, one new config key, new output lines, one new JSON key per match, two small methods on `Ruleset`. No level, match, notification or auto-apply decision changes. Released readers ignore a state file they do not know. Rollback: revert the commit; `verify.json` is then an ignored file.

The new network traffic from a member's machine is at most 10 requests an hour to three named hosts. `verify = "off"` stops it.

## Assumes

- The hourly job runs `aitools-alerts run` and the session-start hook `aitools-alerts run --json`, as the shipped templates and hook do. A member who wrote their own hook with plain `run` gets the check there; the README says so.
- The relay bot names a product by its scope name (`poster.compose` writes `scope.name`).
- CISA serves the KEV file to a non-browser user agent with a declared length or chunked (open question 4 of the review; a `HEAD` on 2026-11-24 answered 200 with an ETag). If it does not, KEV results are `unknown`, which is the safe result.

## Open questions

None that block. For ai-tools-alerts#ny5g: the poster's `ghsa` reading must take `cvss_vector` and `repository` from the same response keys as section 1 or published and member levels will differ; a note goes on that issue.
