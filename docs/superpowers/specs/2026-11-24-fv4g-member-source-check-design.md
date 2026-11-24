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
3. Only typed fields are read. Nothing a response says is printed. What is stored from a response is: levels and booleans computed by the ruleset; the ETag, kept for the conditional request, only when it has the shape of an ETag; and the ids a response names, each only in the exact form of a CVE, GHSA or `MAL-` id, for the alias rule below. A test puts sentinel text in every other text field of the response fixtures and searches the state file and the output for it.
4. Every product of every thread checked has one of three results. `confirmed` and `contradicted` rest only on bodies that came with status 200, arrived whole (the length the response declared), parsed completely and passed the checks below, under the ruleset this reader runs now. If the read of a thread's first id failed, every product of the thread is `unknown`; if a related id's read failed, nothing is `confirmed` and nothing is contradicted downward (the one result that stands is "the source supports more", which rests on bodies that were read and which a missing one could only add to). A timeout, a redirect, 403, 404, 429, a 5xx, a parse error, a size overrun, a body shorter than its declared length (even when what arrived is complete JSON) and a 304 with nothing stored are each a failed read, tested one by one, and after each the levels `check` prints are the ones it printed before.
5. Product binding: a real exploited CVE whose KEV entry names another vendor's product, posted as a Claude Code alert, is `contradicted`. A thread that names a product the source supports and adds one it does not is `contradicted` for the added product, and the thread's summary is `contradicted`.
6. A stolen bot key cannot borrow authority, and neither can an attacker-written source. Which ids are the same advisory is taken only from a response that is itself an authority (the ruleset's `lowers: true`). A source the subject's attacker can write confirms nothing and contradicts nothing. Dropping an alias from a thread never turns a true alert into a contradiction. KEV not listing a CVE contradicts nothing.
7. `verify = matched | all | off` in the config, default `matched`. The README says what each tells CISA, GitHub and OSV about the member.
8. The check runs in `aitools-alerts run` (what the hourly job runs) and in a new `aitools-alerts verify`. It never runs in `run --json` (what the session-start hook runs), in `check`, `plan` or `notify`. A test runs each and counts requests.
9. `scripts/test-gate.sh` passes, with no test touching the network.

## Approach

### 1. One module, `aitools_alerts/verify.py`

It imports `ruleset`, `schema` and `state.write_json`. The poster does not import it.

**Ids.** `norm_id(text)` puts `CVE-` ids in upper case and `GHSA-` ids in the form the poster writes (`GHSA-` then lower case) and returns the id only when `ruleset.source_of` names a source for it and it is not synthetic (`schema.is_synthetic`); otherwise None. Two narrowings found in review:

- The poster's thread id is often a ledger key, `<CVE or GHSA id>:<scope slug>` (`CVE-2026-123158:openssh`). `norm_id` reads such a key as its id.
- Of OSV's ids only `MAL-` ones are looked up. `ruleset.source_of` accepts any `WORD-text` as an OSV id, which also fits internal keys (`LEAD-9a4d0dc65b79:docker`, `AITA-...`); those must never be sent to a third party, and the ruleset gives an OSV entry that is not `MAL-` no authority anyway (`notice`, `lowers: false`), so its read could decide nothing.

The thread's first id is the root's `id`, which no patch can change. A thread whose first id is None has the result `unknown` for `no-source` and is never read or flagged. Everywhere below, and in every line this slice prints, "id" means a value `norm_id` returned.

**URLs.** `url_of(id)` is one of three constants with the id percent-encoded into the last path segment:

| Source | URL | Limit |
|---|---|---|
| `kev` | `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` | 8 MB |
| `ghsa` | `https://api.github.com/advisories/<id>` | 256 KB |
| `osv` | `https://api.osv.dev/v1/vulns/<id>` | 256 KB |

No other function builds a URL, and no field of an event but `id` and `aliases` reaches this one.

**Related ids.** Aliases are the bot's to replace (note from ai-tools-alerts#s6mt), so an alias proves nothing by being listed, and a list the bot can shorten must not be what support depends on. Which other ids are the same advisory is the word of a source that is an authority (its record's `lowers` is true), never the bot's and never an attacker-written source's:

- First id a GHSA or `MAL-` id whose response is an authority: the ids that response names (`ghsa`: `cve_id` and `identifiers[].value`; `osv`: `aliases`) are read and counted, whether or not the thread lists them. The thread's aliases are not used. A response that is not an authority ties nothing: nothing it names is read.
- First id a CVE: KEV names no other id, so each GHSA or `MAL-` alias the thread lists is read, and counts only when its own response is an authority and names that CVE.

At most 3 related ids of a thread are read; more makes the thread incomplete. A response that names more than 50 ids is a failed read. The cache keeps the ids a response names, each only in the form `norm_id` returns.

Residue, stated: a CVE thread whose only support came through a listed alias loses it when the bot drops the alias. The result is then `unknown` when KEV does not list the CVE, and `contradicted` only when KEV lists the CVE for another product, which is what the binding rule says of that state. The reader keeping the widest alias set a thread has had is ai-tools-alerts#tavj's.

**Fetch.** `default_fetch(url, etag, limit, timeout) -> (status, etag, body)`:

- refuses a URL that is not `https://<one of the three hosts>/...` with no port and no userinfo;
- runs the request in a daemon thread and waits `timeout` seconds for it, no longer. Inside the thread the request has the same deadline: it is checked between connect, send, the header read and every body read, and the socket's timeout is set to what is left, so no phase restarts the clock. When the wait ends the thread is told to stop and its socket is shut (the socket is kept from the moment of connection, because `http.client` forgets it once a response that closes the connection takes it over); a name lookup cannot be interrupted, but nothing is sent once it returns. The engine passes `min(10, what is left of the run's 30 seconds)`;
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
- `lowers`: whether the reading is an authority about a product it does not name and about which ids are the same advisory: the `lowers` of the first row of the ruleset's source table that matches the reading with no product in hand (rows that need the product, `vendor_own`, do not match). New method `Ruleset.lowers(source, fields)`. A KEV entry that lists the CVE: true. KEV not listing it: false here, whatever the table says: the catalog holds what is known to be exploited and says nothing about the rest. A reviewed or malware GHSA: true. An unreviewed one: false;
- `names`: the ids the response names, for the rule above;
- `etag`, `at`.

**Result, per product.** For a relay-bot thread with published level `P`, each of its products is judged alone. A product whose name is not a scope product name (`Ruleset.products()`, new: the names the scope index resolves to) is `unknown` for `no-source`: this reader's scope file may be older than the feed's, and it cannot judge.

- A thread is `complete` when the first id and every related id were read well in this run (or confirmed current by a 304).
- `S` is the highest level any counted id gives the product through a class with `lowers` true, `none` when none does. Support from a class with `lowers` false is not a level: a source its subject's attacker can write confirms nothing.
- `may_lower` is true when every counted id's word on this product has `lowers` true: the product's own entry in `support` where there is one, else the reading's `lowers`.

In order:

| Case | Result | Why |
|---|---|---|
| `S` above `P` | `contradicted` | `below-source`: the source supports more than was published |
| not `complete` | `unknown` | `unread` |
| `S` equals `P` | `confirmed` | |
| `S` below `P`, not `may_lower` | `unknown` | `unauthoritative`: a source anyone can write, or KEV's silence, is all that says less |
| `S` is `none` | `contradicted` | `unsupported`: the source does not support this alert for this product |
| `S` is notice or high, `P` is critical | `contradicted` | `above-source`: a reading of prose never makes a critical |
| `S` is notice, `P` is high | `unknown` | `reading`: the level may rest on a reading, which no member can check (finding D2) |

"`S` above `P`" comes before the completeness test because it rests only on bodies that were read; a read that failed could add support and take none away. Every other decisive result needs every read. If the first id's read failed there are no records and the result is `unread`.

What a result does not cover: the affected range and the fixed version of the post. A post at the source's level for the source's product is `confirmed` whatever range it states. Comparing them is ai-tools-alerts#tavj's, where a narrowing is applied.

**Result, per thread.** The summary of a thread is the first of these that any of its products has: `contradicted` (`unsupported`, then `above-source`, then `below-source`), `unknown`, `confirmed`. One supported product never confirms another.

Other fixed reasons for `unknown`: `no-source`, and `off`, which is never stored: with `verify = "off"` the CLI shows every result as `unknown` for `off` and reads and writes no cache, so turning the check back on resumes where it was. A curator's thread has no result: the curator override is ai-tools-alerts#c1g2. This slice does not read the claim tag; ai-tools-alerts#tavj uses it to tell a field-based claim from a reading.

**Budget and cache.** `verify.json` in the state directory, written whole with `state.write_json`:

```
{"version": 2, "ruleset": "<digest>",
 "kev": {"etag": "...", "at": 0},
 "sources": {"<id>": {"etag": "..." or null, "at": 0, "lowers": true,
                      "support": {"<product>": ["<level>", true]}, "names": ["<id>"]}},
 "results": {"<state key>": {"at": 0, "products": {"<product>": {"result": "...", "why": "...", "source": "<level>" or null}}}}}
```

- `ruleset` is `ruleset.load().digest`, which covers the level table and the scope file. A file with another digest, another version, another shape, a value of the wrong kind anywhere, or that does not parse is an empty cache (never an exception: `run --json` reads it): no support, no result and no ETag computed under other rules is used, so the next read is a full one.
- The state key is the SHA-256 of the canonical JSON of the thread's first id, its sorted aliases (as `norm_id` returns them), its level and its sorted product names: the published state the result was computed for. Copies of one advisory in two channels share it.
- A thread is read when it has no result for its state key, or any of its products is `unknown` for `unread`. A `confirmed` result stands until the published state or the ruleset changes (finding D7's rule). Any other result is read again after 24 hours: a source read minutes before CISA listed the CVE, or before GitHub reviewed the advisory, must not stand for good.
- Threads waiting are taken longest untried first (never tried before any tried), then highest level, so threads that keep failing cannot hold the budget against the rest. The 30 seconds run from the start of the run and also end work that needs no request. Each id is requested at most once a run. The KEV file is requested at most once a run and serves every CVE id. A request is counted before it is sent; at 10, or once 30 seconds have passed, the run stops and what is left stays as it was.
- Conditional requests. A request carries the stored ETag only when the support it would confirm is held under this ruleset (for KEV: every CVE id wanted this run has a support read at that ETag). A 304 then means the body whose 200 was parsed is still what the source serves, and the stored support is used. A 304 with no such support is a failed read. So every decisive result rests on a parsed 200 body; the 304 only says that body is current. An ETag is stored only when it matches `(W/)?"<1 to 128 printable ASCII characters, no quote>"`.
- `version` is raised whenever a stored value changes meaning (2: KEV not listing a CVE is no authority), so nothing computed under an older meaning is reused.
- A thread the budget cut off after it had spent requests is marked as tried (its result stays as it was), so it does not come first again in every run.
- Entries for threads and ids no longer current are dropped at each save.
- The run does not hold the state lock while it fetches: a pull started by the hook must not wait 30 seconds. Two runs at once each save a whole file; the later one wins, and the loss is a cached result.

### 2. Config

`verify` in `config.toml`: `"matched"` (default), `"all"` or `"off"`; anything else is a `ConfigError` naming the key. The default file gains a commented block.

- `matched`: only threads that match something installed on this machine are read.
- `all`: every current relay-bot thread, within the budget.
- `off`: no request; every result shows as `unknown`.

### 3. CLI

- `run` (not `--json`): the pull, the match, the usual output and the notification first, then `verify.run` for the configured mode, then the flagged lines. A critical never waits for a source. A failure of the check is one fixed line on stderr and never changes the exit status of `run`.
- `verify`: the same check on the stored state, then one summary line (`source check: N confirmed, N contradicted, N not verified`) and the flagged lines.
- `check` and `plan` print, from the cache only, one line per flagged product after the matches: `source check: <id> is published at <level> for <product>; the source supports <level>` for `below-source` and `above-source`, and `source check: the source does not support <id> for <product>` for `unsupported`. `<id>` is the thread's first id as `norm_id` returned it (a thread without one is never flagged), the levels are the four fixed words, and `<product>` is a scope product name (a product outside the scope file is never flagged). A CLI the trust root says is too old (`_min_cli`) prints no such line (revised design rule 8): its ruleset and scope file may be the ones that are wrong.
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
