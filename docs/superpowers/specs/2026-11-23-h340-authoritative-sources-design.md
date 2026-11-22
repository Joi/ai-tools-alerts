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

## Success criteria

1. The `claude-code-router` advisory of the issue body yields no post, no held
   notice and no digest line naming Claude Code.
2. A product is resolved only by exact identity: the whole normalised product
   text equals an identity listed for the product, or the finding's package
   (`ecosystem:name`) equals one. No word, substring or prefix match exists in
   the code.
3. A candidate with no authoritative source for its product is dropped before
   it is merged, rated or held. This covers notice, high and critical.
4. A fixed version or an affected range is published only when every version
   in it appears on an authoritative page that also names the advisory.
5. A signed post carries: ids of the CVE or GHSA shape only; a source title
   only from the authoritative page that confirmed the advisory; sources that
   are authoritative for the product only; no action sentence when the fixed
   version cannot be expressed.
6. The advisory block format is unchanged, so a v0.1.4 reader parses every
   post this poster signs.
7. A transient fetch failure defers the candidate; it never drops it and
   never posts it.
8. `scripts/test-gate.sh` is green.

## Approach

### 1. Exact scope identity (`spec/scope.json` version 5, `schema.load_scope`, `rules.scope_of`)

- `match` becomes a list of exact identities: lowercase, trimmed, each owned
  by exactly one entry or component across the file (the loader refuses a
  duplicate). `match_mode`, `not_match`, the word rule and the substring rule
  are deleted, with their code.
- `scope_of(text)`: NFKC, lowercase, Unicode dashes to `-`, whitespace runs to
  one space (today's `_norm`), then dictionary lookup. A component resolves to
  the component, as today. Text that does not resolve but holds a tier-1 vendor
  word is still logged for review; the log changes nothing.
- A collector finding may carry `package: {"ecosystem": "npm", "name":
  "@anthropic-ai/claude-code"}`. When the key is present the candidate's
  product text is `ecosystem:name` and the free-text `product` is not read; a
  malformed `package` skips the finding. Identities such as
  `npm:@anthropic-ai/claude-code` sit in `match`.
- KEV: the text is CISA's `vendorProject` and `product` joined by a space, as
  today, compared whole (h29n D2). `anthropic claude code` and
  `openbsd openssh` are listed identities.
- Version 5 is the only version the loader reads, so an old poster cannot
  word-match the new file. Member CLIs read the copy installed with them
  (`inventory.py` uses names and ecosystems only).

### 2. Authority (`authority` in `spec/scope.json`, `rules.authoritative`, `rules.evidence`)

- Each entry (and, optionally, a component, replacing the entry's) lists
  `authority`: URL prefixes `host/path/` that are that product's own advisory
  locations, such as `github.com/anthropics/` and `anthropic.com/`. A test
  pins that every prefix is inside `spec/primary-domains.json` (host listed;
  a GitHub owner listed in `owners`).
- `authoritative(url, scope)`: `schema.is_primary(url)`, not a root page, and
  host plus path starts with one of the scope's prefixes. So
  `github.com/advisories/…` (anyone's advisory lands there), another owner's
  repository and a distribution's tracker are authoritative for nobody else's
  product.
- `evidence(c, scope, page)`, run on every in-scope candidate before the
  merge:
  - `c.exploited is True` (set only by `from_kev`, from the catalog this run
    fetched from CISA): authoritative by KEV. No fetch.
  - Otherwise each authoritative source URL is fetched (at most 3 per
    candidate, 40 pages per run, 1 MiB per page, redirects only to URLs
    authoritative for the same scope). A page confirms the advisory when it
    answers 200 and its body holds one of the candidate's advisory ids (CVE or
    GHSA, bounded so `CVE-2026-1234` is not found in `CVE-2026-12345`). For a
    `github.com/<owner>/<repo>/security/advisories/<GHSA>` URL the GHSA in the
    path must also be one of the candidate's own ids: the vendor's page for
    another advisory confirms nothing.
  - The same bodies are searched for the candidate's fixed version and every
    version in its affected range (bounded tokens).
- Applied by `main` before `ledger.merge`:
  - no KEV and no confirming page: dropped, counted in the `skipped:` stderr
    line as `no authoritative source`;
  - a fetch that failed (status 0, 429, 5xx) with nothing confirming: deferred
    to the next run while `observed_at` is under 7 days old, else dropped;
  - past the page budget: deferred;
  - `fixed` kept only if found on a confirming page; `affected` kept only if
    every version in it is found (`*` is never kept); `source_title` kept only
    when it came from the confirming URL (new `Candidate.title_url`);
    `sources` cut to those authoritative for the scope (plus cisa.gov sources
    of a KEV candidate), the confirming URL first.
- `level_for` is unchanged in shape. Its `source_ok` argument is now "a page
  confirmed this advisory", so the trojanized and injection clauses need a
  vendor page that names the id, and severity-tier1 and fix-rce-tier1 can only
  be reached by a candidate that passed the gate. `rules.http_status` and
  `rules.source_ok` are replaced by `rules.http_page`.
- `from_kev` takes CISA's `vulnerabilityName` as the source title (title URL:
  the catalog), since the collector's twin of a KEV entry no longer survives
  on a cisa.gov source alone.

### 3. Signed wording (`compose`)

- `compose.BOT_ID`: `CVE-\d{4}-\d{4,}` or `GHSA-xxxx-xxxx-xxxx`, optionally
  followed by `:` and a scope slug `[a-z0-9][a-z0-9.-]{0,31}` (the collector's
  thread key, live today as `CVE-2026-88968:claude-code`). `root_post` refuses
  any other primary id; `main` drops such a candidate first (`id shape`).
  Published aliases are bare CVE or GHSA ids only.
- A fixed version the schema cannot express: the body keeps "A fix is listed
  upstream; see the source." and has no Action line, in English and Japanese.
- The Source line and the block's sources are the authoritative ones (2).

## Alternatives considered

- Keep word matching and add a deny list of third-party names: the attacker
  picks the name; a deny list never ends.
- Keep free-text matching for KEV because CISA wrote it: a KEV entry for
  `claude-code-router` would still resolve to Claude Code (h29n D2).
- Trust the collector's `fixed` when the source URL is the vendor's: the
  collector record has one `fixed` per finding, not per source, and an
  attacker advisory can cite the vendor's page as a reference. Reading the
  version off the vendor's page is the only check the poster can make alone.
- Hold an unsourced notice instead of dropping it (8ke5's shape): it would sit
  in state under a product name with no authoritative page and reach nothing;
  dropping is the same outcome with less state.
- A new block field naming the confirming source: v0.1.4 refuses unknown keys
  (h29n D12); left to s6mt and h29n.

## Blast radius and rollback

- Fewer posts. Text that used to word-match ("Docker Desktop on Ubuntu",
  "openssh/openssh-portable 9.8") now resolves only if listed. Misses that hold
  a tier-1 vendor word land in the review log; the rollout issue names the log
  as the place to harvest identities from.
- Advisories whose only source is a global GitHub advisory, NVD, a
  distribution tracker or news no longer post. That is the finding's fix.
- Chrome, Chromium, Firefox, Fedora, the Linux kernel, skills.sh and
  mcp-remote have no authority listed (no allowlisted vendor host): they post
  from KEV only.
- State compatibility: `Candidate.title_url` is optional when a deferred
  candidate is loaded; threads and held notices are untouched. Leads already
  held are dropped by the next digest as today.
- Poster-side only; no reader change. Rollback is reverting the merge commit
  and reinstalling the poster.

## Residual risk, stated

- An attacker advisory that claims a real vendor CVE as an alias, and whose
  collector record cites the vendor's own page for that CVE, passes the gate:
  the page names the id. The post then describes a real advisory of that
  product; the attacker's fixed version and range are dropped (not on the
  page), their title is dropped, their sources are dropped. What they can
  still move is the severity word and the model-read flags, so the level.
  Closing that needs the level computed from structured vendor fields (s6mt).
- The slug after `:` in an id is up to 32 characters of `[a-z0-9.-]` chosen
  upstream of the poster.
- Whether the private collector sends `package` is unknown from this
  repository (the review's open question 4). Without it a registry advisory
  resolves only when its product text is a listed identity.

## Overlap

- ai-tools-alerts#s6mt will build `spec/ruleset.json` with the
  authoritative-source table; it moves or replaces the `authority` lists added
  here.
- ai-tools-alerts#8ke5 (landed): `compose.listable` stays; leads now never
  reach `hold`.
- ai-tools-alerts#0dvh (holds and age limit, in flight): touches the deferred
  list; rebase before review.

## Open questions

None that block. The rollout issue carries: reinstall the poster, ask the
collector for `package`, harvest the review log for identities.
