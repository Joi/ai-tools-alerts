# The poster signs only what an authoritative source says (h340)

## Problem

Finding H4 of the 2026-11-23 adversarial review. Anyone can publish a GitHub
advisory for a package they own named `claude-code-router`, severity high,
fixed in 99.0.0. `rules.scope_of` matches words in free text, so the name
resolves to the tier-1 product "Claude Code". `level_for` returns high with no
source check, `compose.root_post` accepts any https source, and the bot signs
"upgrade Claude Code to 99.0.0 or later". No key is needed.

Same root cause: a critical is "verified" when any allowlisted URL answers
200; an id of 128 free characters and an upstream title carry attacker wording
into the signed post; an unparseable fixed version yields "upgrade as the
source describes" beside a URL the attacker chose.

Operating assumption (ruled 2026-11-23): nobody is watching. Nothing here
waits for a person.

## Principle

The collector record is a pointer, not a statement. It says "look at this id,
for this product, at these URLs". Everything a post states (which product,
which ids, the fixed version, the range, the title, the severity word) is read
by the poster from the vendor's own page or from the CISA KEV catalog it
fetched itself. A field the poster cannot read from such a source is not
published.

## Success criteria

1. The `claude-code-router` advisory of the issue body yields no post, no held
   notice and no digest line naming Claude Code.
2. A product is resolved only by exact identity. No word, substring or prefix
   match exists in the code.
3. A candidate with no authoritative confirmation is not merged, rated, held
   or posted, at any level.
4. A fixed version, an affected range, a title and a severity word are
   published or used only when the poster read them from a labelled field of
   the authoritative source. The collector's `fixed`, `affected`, source
   titles and `advisory_severity` never reach a post.
5. A candidate's ids are cut to those the authoritative source itself assigns
   to the advisory before any merge or ledger lookup.
6. A signed post carries ids of the CVE or GHSA shape only, sources that are
   authoritative for the product only, and no action sentence when the fixed
   version cannot be expressed.
7. The advisory block format is unchanged: a v0.1.4 reader parses every post.
8. A fetch that failed, or a vendor page the poster could not parse, defers
   the candidate. It is never dropped for that and never posted.
9. Nothing composed before the gate existed is sent after it.
10. `scripts/test-gate.sh` is green, with the verification matrix below.

## Approach

### 1. Exact scope identity (`spec/scope.json` version 5, `schema.load_scope`, `rules.scope_of`)

- `match` is a list of exact identities: lowercase, single-spaced, each owned
  by one entry or component in the whole file (the loader refuses a
  duplicate). `match_mode`, `not_match` and the word and substring rules are
  deleted, with their code.
- `scope_of(text)`: NFKC, lowercase, Unicode dashes to `-`, whitespace runs to
  one space, trim, then dictionary lookup. A component resolves to itself.
  Unmatched text holding a tier-1 vendor word is still logged; the log
  decides nothing.
- Identity kinds: a product name (`claude code`), a repository slug
  (`anthropics/claude-code`), a package key (`npm:@anthropic-ai/claude-code`)
  and CISA KEV's `vendorProject product` (`anthropic claude code`).
- KEV coverage is listed, not assumed. The file carries the KEV form of every
  entry and component, including the ones today's word rule reached:
  `node.js node.js`, `containerd containerd`, `google chrome`,
  `google chromium v8`, `apple macos`, `apple safari`, `mozilla firefox`,
  `linux kernel`, `git git`, `docker desktop`, `openbsd openssh`,
  `tailscale tailscale`. A test pins each as resolving.
- A collector finding may carry `package: {"ecosystem", "name"}`. When the key
  is present the product text is `ecosystem:name` and the free-text `product`
  is not read; a malformed `package` skips the finding.
- Version 5 is the only version the loader reads. Member CLIs read the copy
  installed with them and use names and ecosystems only.

### 2. Authority (`authority` in `spec/scope.json`)

- Each entry (and optionally a component, replacing the entry's; `[]` means
  none) lists `authority`: lowercase URL prefixes `host/path/`. A GitHub
  prefix names one repository (`github.com/anthropics/claude-code/`), never an
  owner. A test pins that every prefix is inside `spec/primary-domains.json`
  and that every GitHub prefix has two path segments.
- `authoritative(url, scope)`: `schema.is_primary(url)`, not a root page, host
  plus path under one of the scope's prefixes. `github.com/advisories/…`,
  another repository and a distribution's tracker are authoritative for
  nobody else's product.

### 3. Evidence (`rules.evidence`, run by `Run.admit` on each candidate alone, before `ledger.merge`)

The candidate's primary id must match `BOT_ID` (a CVE or GHSA id, optionally
followed by `:` and a slug `[a-z0-9][a-z0-9.-]{0,31}`, the collector's thread
key); its base is the id without the slug. Three kinds of confirmation:

**KEV.** The candidate carries `exploited`, which only `from_kev` sets on a
fresh candidate, from the catalog this run fetched from CISA. A stored
candidate can be trusted to carry it because the migration (6) empties the
deferred list once, and from then on that list holds only candidates these
rules admitted or will re-admit. Confirmed ids: its CVE. Title: CISA's
`vulnerabilityName`. No fixed version, no range. Pages are still read for a
KEV candidate that cites one, for the fields only a page gives.

**A repository advisory page**, `github.com/<owner>/<repo>/security/advisories/<GHSA>`
under the scope's authority. The poster fetches the page and reads, from the
text before its "Description" heading, the labelled fields GitHub renders:
the GHSA id, "CVE ID", each "Package" or "Software" block (name, ecosystem,
"Affected versions", "Patched versions"), "Severity", and the page title. The
page confirms the candidate when all hold:
- it answers 200 and the fields parse (the GHSA of the URL is shown on it);
- the candidate's base id is the page's GHSA or its CVE ID;
- a block's package is this product: `scope_of("<ecosystem>:<name>")`
  resolves to the candidate's scope, or, where the block names no package
  registry (the "Software" label, or an ecosystem outside npm, pip, pypi, go,
  rust, cargo, maven, nuget, rubygems, composer, pub, swift, erlang, actions),
  `scope_of("<name>")` does. So an advisory for Claude Desktop in the
  `anthropics/claude-code` repository does not confirm a Claude Code candidate.

From a confirming page the poster takes: ids (the GHSA and the CVE ID);
`fixed`, the highest patched version over the matching blocks when every
patched value is a version the schema can express, else none; `affected`, the
range when exactly one block matches and the schema can express it, else
none; the title; the severity word.

**A vendor site page**: any other authoritative URL that has no query string
(a site can echo a query back) and is not on github.com. It confirms when it
answers 200 and its visible text (tags, attributes and scripts removed) holds
the candidate's base id and the product's name (`scope.name`), each as a
whole token. Confirmed ids: the base id only. It yields no fixed version,
range, title or severity, and the candidate it confirms is a notice whatever
the record says: a site page binds nothing by a field. (The first draft read
a fixed version from an Apple page title; the code review showed a record
could then pick an older branch's page, so no version is read from a site
page.)

A repository page is read only when it is whole: it ends with `</html>`, and
its CVE ID field holds a CVE id or "No known CVE". A page cut short, or one
that lost its sidebar, is not read, so text in a description cannot supply
the page's id. A 200 body over 1 MiB is a failed fetch, never a truncated
page.

Every source an adapter keeps is read (8 a candidate), 40 pages a run, one
fetch per URL per run, redirects only to URLs authoritative for the same
scope. When the run's budget ends, what is already confirmed stands (a KEV
entry never waits on a vendor page) and an unconfirmed candidate is deferred.
Deferred candidates take turns going first, by the hour, so pages that fail
on every run cannot starve one behind them.

### 4. What `Run.admit` passes on

- Not confirmed: dropped (`no authoritative source` in the `skipped:` stderr
  line). Primary id not of the shape: dropped (`id shape`).
- A fetch failed (no answer, 403, 408, 429, 5xx), a repository page answered
  200 but did not parse, or the page budget ran out, and nothing confirmed:
  deferred to the next run, with no age limit of its own (ai-tools-alerts#0dvh
  adds the age limit to the deferred list; the list is keyed by scope and id,
  so it does not grow with retries).
- Confirmed: the candidate goes on with
  - `aliases`: only those whose base is a confirmed id, plus the page's own
    GHSA and CVE ID. An alias the source does not assign is not kept, so it
    cannot merge threads, attach another advisory's fix or inherit KEV status;
  - `fixed`, `affected`, `source_title`: the page's, or CISA's title, or none.
    A patched value the schema cannot express is carried as "a fix exists,
    no version", so the post says a fix is listed and has no action line;
  - `advisory_severity`: the page's severity word and title;
  - `sources`: the page that confirmed it, the cisa.gov sources of a KEV
    candidate, and `github.com/advisories/<GHSA>` for a confirmed GHSA. No
    other URL is kept, the vendor's host included: nobody read it, and its
    path or query is text the record chose;
  - the collector's `advisory_severity`, `trojanized` and `injection_exec`
    only when a repository advisory page confirmed the candidate and the
    record is pure: every one of its sources is in the list above. A record
    that mixes in any other source, or one confirmed by a site page alone,
    keeps none of the three.
- The vendor's page carries the candidate's id and names only other packages:
  dropped, counted apart as `vendor page names another package` (an advisory
  for another product of that repository, or a package key the scope file
  lacks; the rollout issue says to read that count).
- `level_for` is unchanged in shape; its `source_ok` argument is "a page
  confirmed this advisory this run". `rules.http_status` and `rules.source_ok`
  are replaced by `rules.http_page`. `candidates._source_title` and
  `_apple_fixed` are deleted: `from_collector` sets no title and `fixed` and
  `affected` from a record are never used.

### 5. Signed wording (`compose`)

- `root_post` refuses a primary id that is not `BOT_ID`. Published aliases
  are bare CVE or GHSA ids.
- A fixed version the schema cannot express: "A fix is listed upstream; see
  the source." stays, the Action line is omitted, English and Japanese.
- The Source line and the block's sources are the authoritative ones (4).

### 6. State written before the gate

- The state file gains one key, `gate: 1`. A state without it is migrated on
  load, once: `deferred`, `held` and `withheld` are emptied and every outbox
  item of kind root, copy or reply that was not yet sent is removed (a sent
  one is only being recorded). A stderr line gives the counts. So an old
  malicious candidate, an old held notice and an old composed post cannot be
  sent by the new poster, and every deferred candidate from then on was
  admitted, or will be re-admitted, under these rules.
- The migration reaches the ledger too: each thread forgets the ids it
  learned without publishing them (anything not in its published advisory),
  all of its `learned_sources` and its source title (a digest line prints it,
  and it came from the record), since a later reply or digest would publish
  them or join threads by them. The input watermarks are reset, so the inputs
  are read again from the backfill floor and a genuine notice that was held
  or deferred comes back through the gate. A
  send whose outcome is unknown keeps its journal item: `pending` and
  `resolve` settle it as before.
- `plan_known`: sources a thread learned without publishing
  (`learned_sources`) are also filtered through `authoritative` before a
  reply can list them. Values a thread already published stay as published; a
  page-read fixed version replaces a stored one.

### 7. Verification matrix (tests)

| Case | Expect |
|---|---|
| H4: `claude-code-router`, high, fixed 99.0.0, own repository advisory | no root, no held notice, no digest line, nothing in the ledger |
| Same with product text `claude-code` | dropped: no authoritative source |
| Same with `package: npm:claude-code-router` | out of scope |
| Same, citing the vendor's page for another GHSA | dropped: the id is not the page's |
| Attacker GHSA A with alias vendor GHSA B, citing B's page | dropped: A is not the page's id |
| Record with primary id = the vendor's CVE, fixed 99.0.0, range `<99.0.0`, own title, an extra unrelated CVE alias, severity critical, `trojanized` | posts the vendor's advisory: fixed, range, title and severity are the page's; the extra alias is gone; `trojanized` ignored (the record is not pure) |
| Vendor page: "affects 1.0 to 2.0, fixed in 3.0"; record says fixed 2.0 | fixed is 3.0 |
| Advisory in the product's repository for another package (Claude Desktop) | dropped |
| Vendor GHSA page, candidate carries the CVE only | confirmed; the GHSA becomes an alias |
| Genuine vendor GHSA record (the live CVE-2026-88968 thread) | high, fix 2.1.251 from the page |
| KEV entries: Anthropic Claude Code, OpenBSD OpenSSH, Node.js Node.js, containerd containerd, Google Chrome, Apple macOS | resolve; tier 1 critical, tier 2 high, titled by CISA |
| KEV entry for vendor `musistudio`, product `claude-code-router` | out of scope |
| Vendor site page naming the id and the product | notice, whatever the record's severity and flags |
| Vendor-host URL nobody read, in the record's sources; a URL with a query that echoes it | not in the post; never fetched, confirms nothing |
| Repository URL spelled `github.com.`; a page cut short or without its CVE ID field | read as the same advisory page; not read |
| Vendor patched value `2.0.0-rc.1`, whole run | "A fix is listed upstream", no Action line (en, ja) |
| Two pages failing every run ahead of a healthy one, budget 2; KEV with the budget spent | the healthy one posts; the KEV entry posts |
| Page answers 503, then 200 | deferred, then posts; an 8-day-old candidate too |
| Repository page answers 200 with unknown markup | deferred, counted `advisory page not parsed` |
| 41st page of a run | deferred |
| Old state: a deferred candidate, a held notice, an unsent root, a withheld item, a sent-unrecorded root | the first four removed, the last recorded |
| Old ledger thread with learned non-authoritative sources gets a fix | the reply lists none of them |
| 128-character id; alias of another shape | root refused; alias not published |
| Unexpressible fixed version | no Action line (en, ja) |
| Every post composed in the suite | `schema.parse_post` reads it (the block has no new key) |
| Scope file: version 4, unknown key, duplicate identity, owner-level GitHub prefix, prefix outside primary-domains | refused |

Existing tests of word matching, `match_mode`, `not_match`, `http_status`,
`source_ok`, collector source titles and `_apple_fixed` are replaced by these.

## Alternatives considered

- A deny list of third-party names over word matching: the attacker picks the
  name.
- Checking that the record's version tokens appear on the vendor page (this
  spec's first draft): a token's presence says nothing of its role; a record
  could pick a vulnerable version off the page as "fixed". Rejected by the
  spec review; the poster now reads labelled fields.
- The GitHub REST API for repository advisories: structured, but unauthenticated
  calls are limited to 60 an hour per address, measured at zero remaining on
  this network on 2026-11-23; a token is a credential the poster does not
  hold. The public page answers.
- Owner-wide GitHub authority: an owner's other repositories and other
  packages would confirm the wrong product.
- A new block field naming the confirming source: v0.1.4 refuses unknown keys
  (h29n D12); left to s6mt and h29n.

## Blast radius and rollback

- Fewer posts. Text that used to word-match resolves only if listed; misses
  holding a tier-1 vendor word land in the review log.
- Advisories whose only source is a global GitHub advisory, NVD, a
  distribution tracker or news no longer post. That is the finding's fix.
- Products with no authority listed (Chrome, Chromium, Firefox, Fedora, the
  Linux kernel, skills.sh, mcp-remote) post from KEV only. An advisory a
  vendor publishes on its own site only (Cursor, Apple, an OpenSSH release
  note) posts as a notice in the digest, with no version.
- The repository-page reader depends on GitHub's labels ("Package",
  "Affected versions", "Patched versions", "CVE ID", "Severity"). If GitHub
  renames one, GitHub advisories defer and `advisory page not parsed` shows in
  every run's stderr; nothing false is posted. A fixture of a real page pins
  today's markup.
- Rollback: revert the merge commit, reinstall the poster, and remove the
  `gate` key from the state file. Until the key is removed the old poster
  refuses the state and sends nothing. The candidate shape is unchanged.

## Residual risk, stated

- A pure record confirmed by the vendor's repository advisory can still
  carry a model's reading (`trojanized`, `injection_exec`) of that advisory.
  Computing a critical from structured fields alone is ai-tools-alerts#s6mt.
- A vendor site page confirms by naming the id and the product. A page that
  lists another product's CVE beside this product's name, says the product is
  not affected, or echoes its own path with status 200 would confirm. The
  result is a digest notice with no version, never a high or a critical.
- The slug after `:` in an id is up to 32 characters of `[a-z0-9.-]` chosen
  upstream of the poster.
- Whether the private collector sends `package` is unknown from this
  repository.

## Overlap

- ai-tools-alerts#s6mt will build `spec/ruleset.json` with the
  authoritative-source table and the level function over structured fields;
  it replaces the `authority` lists and the page reader's place in the rule.
- ai-tools-alerts#8ke5 (landed): `compose.listable` stays.
- ai-tools-alerts#0dvh (in flight): the deferred list's age limit; rebase
  before review.

## Open questions

None that block.
