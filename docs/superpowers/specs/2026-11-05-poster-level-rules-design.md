# Poster level rules and scope matching (Task B2) — design

Kata: ai-tools-alerts#31x7. Parent plan: docs/plan.md, Task B2. Epic jibot-code#gr5b.
Depends on A2 (j153: `schema.load_scope`, `schema.is_primary`, `schema.Source`) and
B1 (6j8x: `poster.candidates.Candidate`). Blocks B3 (h2gf).

## Problem

The poster must decide, deterministically, whether a Candidate posts at all (scope)
and at which level (critical, high, notice). Critical interrupts every member, so the
rule that fires it is the most consequential code in the poster. The law is the
plan's Global Constraints and the design's "Severity and the critical rule":

- Critical fires only by rule: product in scope tier 1 and (KEV exploited, or a
  trojanized/malicious release confirmed by a primary source, or
  injection-to-execution with a fix).
- A critical whose cited primary source is not on the allowlist or did not fetch
  posts as `high` with "unverified".
- Scope tier 2 never posts critical. Items outside both tiers do not post.

## Success criteria

1. `aitools_alerts/poster/rules.py`, standard library only, exports `scope_of`,
   `level_for`, `source_ok`, `http_status`, `vendor_words`.
2. `python3 -c "from aitools_alerts.poster import rules; print(rules.scope_of('Anthropic Claude Code').tier, rules.scope_of('Ubuntu 24.04').tier, rules.scope_of('acme widget'))"`
   prints `1 2 None`.
3. `tests/poster/test_rules.py` has the plan's six tests
   (`test_kev_tier1_is_critical`, `test_kev_tier2_is_high`,
   `test_trojanized_without_primary_is_high_unverified`,
   `test_injection_exec_needs_fix`, `test_scope_match_is_pattern_based`,
   `test_out_of_scope_is_none`) plus tests for every reason code, the tier-2 cap,
   the hint never raising a level, `source_ok` and the redirect guard.
4. `poster.candidates.Source is schema.Source`; B1's tests stay green.
5. `scripts/test-gate.sh` passes with sockets blocked: a `tests/poster/conftest.py`
   autouse fixture makes any `socket.connect`/`getaddrinfo` in a poster test raise.

## Approach

### `scope_of(product_text, log=None, entries=None) -> ScopeEntry | None`

- Lowercase the text (`str.lower()`, after NFKC normalisation so full-width or
  compatibility characters cannot dodge a pattern) and test each entry's `match`
  patterns as plain substrings.
- Tier-1 entries are tried first, in file order, then tier-2: the first tier-1
  hit wins over any tier-2 hit ("Docker on Ubuntu" is tier 1).
- `entries` defaults to `schema.load_scope()`, loaded once and cached.
- Non-string or empty text returns None.
- Review Focus 4, the unmatched log: when nothing matches and the text contains a
  tier-1 vendor word as a whole token, the text is appended to `log` (a caller
  owned `list[str]`) — explicit, not module state. The vendor words
  (`vendor_words(entries)`) are the first word of each tier-1 entry's `name`
  ("claude", "codex", "cursor", "gemini", "hermes", "openclaw", "mcp", "clawhub",
  "node.js", "python", "go", "rust", "docker", "tailscale", "openssh", "git") plus
  the vendors behind them that the names do not spell: "anthropic", "openai",
  "anysphere", "nousresearch", "nous", "google".
  Token match (split on anything but letters, digits and `.`), so "go" does not
  hit "google" and "git" does not hit "digit". Over-logging is harmless: the log
  is for a human reading the ledger.

### `level_for(c, scope, source_ok) -> tuple[str, str]`

Order matters; the first rule that applies wins.

| # | condition | result |
|---|---|---|
| 0 | `scope is None` | `ValueError` (out of scope never posts; callers check `scope_of` first) |
| 1 | tier 1, `c.exploited` | `critical`, `kev-tier1` |
| 2 | tier 1, `c.trojanized`, source_ok | `critical`, `trojanized-primary` |
| 3 | tier 1, `c.injection_exec` and `c.fixed`, source_ok | `critical`, `injection-exec-fixed` |
| 4 | tier 1, rule 2 or 3 but not source_ok | `high`, `unverified` |
| 5 | tier 1, `c.fixed` and `advisory_severity` names code execution, credential theft/exposure or data loss | `high`, `fix-rce-tier1` |
| 6 | tier 2, `c.exploited` | `high`, `kev-tier2` |
| 7 | otherwise | `notice`, `notice` |

- The KEV clause needs no `source_ok`: the design calls it "mechanical and fires
  from the collector alone", and `Candidate.exploited` is True only from
  `candidates.from_kev` (B1), so a model-written record cannot forge it. The
  `unverified` downgrade applies to the two model-read clauses only, as the plan's
  interface states. A KEV candidate's own source is the cisa.gov catalog page,
  which is primary anyway.
- `source_ok` must be the bool `True` (`is True`), so a truthy non-bool from a
  careless caller cannot fire a critical.
- `c.fixed` is truthy only for a real version string (B1). `local_level_hint` is
  never read: it cannot raise a level.
- Tier 2 tops out at `high`, whatever the flags.
- A scope tier other than 1 or 2 raises `ValueError`.
- The severity regex (rule 5), case-insensitive, over the NFKC-normalised
  `advisory_severity` only: `code execution` / `code-execution`, `rce`,
  `command execution`, `command injection`, `arbitrary code`,
  `arbitrary command(s)`, `credential`, `token theft`, `secret exposure`, `data loss`,
  `data exfiltration`. `advisory_severity` is free text from B1 ("High; remote code
  execution" or a CVSS rating) — a plain rating such as "CRITICAL" alone does not
  make a high (the plan requires the code-execution/credential/data-loss reading).

### `source_ok(c, fetch) -> bool` and `http_status(url, timeout=10) -> int`

- `fetch(url, timeout) -> int` is a required parameter, so tests always inject one.
- For each source in order: skip unless `schema.is_primary(url)`; call
  `fetch(url, 10)`; a status of exactly 200 returns True. Any exception from
  `fetch` counts as a failure for that source, never propagates.
- A host's root page (path empty or `/`) never counts: it confirms nothing.
  That holds for a redirect target too.
- `http_status(url, timeout=10, opener=None)` is the production fetch. It
  refuses (0) a URL that is not `is_primary`. One wall-clock deadline of
  `timeout` seconds covers everything (DNS, HEAD, the fallback GET and every
  redirect): the fetch runs in a daemon thread joined for the time left, and 0
  is returned if it is still running; each request gets the time left as its
  socket timeout, none starts after the deadline, and an answer that completes
  after the deadline counts as 0.
- urllib's own redirect following is switched off (a handler whose
  `redirect_request` returns None, so a 3xx surfaces as an `HTTPError`), because
  CPython drains a redirect body before following it and counts distinct URLs,
  not hops. `http_status` follows redirects itself: `Location` resolved with
  `urljoin`, followed only when the target is `is_primary`, at most 5 hops
  counted per method; every response and error is closed without reading its
  body. HEAD first; on anything but 200, one GET with the same rules. Returns the
  final status, or 0 on a network error, a refused redirect, too many hops or the
  deadline. The `opener` parameter lets tests drive this loop with fake
  responses, offline.
- Residual: a worker thread stuck past the deadline keeps running until its
  socket timeout (or a slow DNS lookup) ends it; its answer is discarded. Daemon
  threads do not hold the process open.

### Source reconciliation

`candidates.py` drops its own `Source` dataclass and does
`from aitools_alerts.schema import Source` (re-exported: `candidates.Source` keeps
working). `schema.Source.published_at` has no default; every construction in B1
passes both arguments positionally, so nothing else changes.

## Review decisions (spec+plan pass 1)

- KEV and `source_ok` (rebutted): the Global Constraint's "a critical whose cited
  primary source ... did not fetch" is the check the design (line 47) attaches to
  the two clauses a model reads; it calls the KEV clause "mechanical and fires
  from the collector alone", and the plan's B2 interface puts `exploited` outside
  the `source_ok` conjunction. The poster's KEV input is the catalog it fetched
  from cisa.gov itself (B4), so the source has fetched by construction.
- Tier-1 precedence over tier 2 in mixed text (rebutted): the plan's interface
  prescribes it ("first tier-1 hit wins over tier 2"). Text naming a tier-1
  product is about that product too; missing a tier-1 critical costs more than
  an interrupt on mixed text. KEV text is `vendorProject product`, which rarely
  names two products.

## Review decisions (code pass 1)

- Tier 2 tops out at `kev-tier2` (decided): design.md's High line says "a vendor
  advisory with a fix and a plausible path to code execution ... in scope", which
  could include tier 2; the plan's B2 interface says "tier 1 with a fix", and the
  brief says to implement the plan exactly. Tier 2 exists so the feed does not
  carry every browser and OS fix the updater already handles, so a fixed tier-2
  RCE, or a trojanized tier-2 release, is `notice`. One directive reverses it.
- Index pages other than the root still pass `source_ok`: the poster cannot tell
  an advisory page from an index by URL alone. Root pages are refused.

## Alternatives considered

- `scope_of` returning a `ScopeResult(entry, unmatched_vendor)`: breaks the plan's
  interface (`-> ScopeEntry|None`) and the acceptance one-liner, which prints
  `scope_of('acme widget')` as `None`. The `log` argument keeps the interface.
- Module-level `rules.unmatched` list: hidden global state, rejected in the brief.
- Applying `source_ok` to the KEV clause too: stricter, but contradicts the
  design's "mechanical" KEV clause and the plan's interface; a cisa.gov outage
  would silently downgrade every KEV critical.
- Regex word-boundary on raw text for vendor words: `\bnode.js\b` and `\bgo\b`
  behave oddly around punctuation; token split is simpler to reason about.

## Blast radius / rollback

New module, one import change in candidates.py, one conftest. Nothing calls
`rules` yet (B3/B4 will). Rollback: revert the commit.

## Assumes

- B3/B4 call `scope_of` before `level_for` and drop `None`.
- B4 computes `source_ok` with `http_status` only for candidates where it can
  matter (tier 1, trojanized or injection_exec), to keep hourly runs fast; this
  module does not enforce that.
