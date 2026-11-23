# The level as a function of structured source fields (ai-tools-alerts#s6mt)

Findings D2, D3, D10 and D11 of the design review on ai-tools-alerts#h29n, and rules 1, 2, 4 and 8 of its revised design.

## Problem

`rules.level_for` decides how loudly an alert posts. Only its KEV clause reads a field. The other two critical clauses read `trojanized` and `injection_exec`, which a model set from advisory prose, and one high clause matches words in free text. A member's CLI has no model, so it cannot recompute those levels, and "the member re-verifies the level" (h29n rule 3) has nothing to compute against. Three more gaps follow from that:

- D3: nothing says which source may set which level. An OSV `MAL-` entry anyone can file would make a critical.
- D10: the function's inputs (level table, scope file, source table) have no version and no digest, so two CLIs can disagree and a thief can cite an older rule.
- D11: a hash of source fields cannot be checked without the fields, and two implementations will disagree on its input unless the form is fixed.

This slice builds the definition the poster recompute (ny5g) and the member check (fv4g) compute against. It puts nothing new on the wire (t8jr) and fetches nothing new.

## Success criteria

1. `spec/ruleset.json` holds the level table, the TTL per level and the authoritative-source table. One module, `aitools_alerts/ruleset.py`, evaluates it. It imports nothing from `aitools_alerts.poster`, so the CLI can import it; `poster/rules.py` imports it.
2. `rule(fields, product) == level` holds for every claim the poster builds (a seeded property test over generated candidates and evidence).
3. An OSV `MAL-` reading alone gives `high`; with a GitHub malware advisory reading for the same product the level is `critical`, because that reading is critical by itself. With an unrelated vendor advisory of low severity for the same product it stays `high`: no combination of readings gives more than the highest one gives alone.
4. A KEV reading for another vendor's product binds to no tier-1 product: the level for "Claude Code" is `none`.
5. A claim citing ruleset version 1 under which the level was lower is refused: by the offline check (the CLI computes with its own ruleset, never the one the claim names), and by `min_version` when a pin is given.
6. A claim citing a ruleset newer than the CLI's is `unknown`; a CLI whose ruleset is below the pin's `min_version`, or whose digest differs from the pin's at the same version, is `outdated` and judges nothing.
7. `spec/claim-vectors.json` gives claims with their exact canonical bytes and SHA-256. The top-level suite (the CLI's) and the poster suite both load it; the poster suite builds two of the vectors through `rules.claims_for` from a candidate and its evidence and gets the same bytes, one of them a page with no CWE data and the same package listed twice, given in reverse order.
8. A model's reading never makes a critical. The two returns of `level_for` that were `critical` by a flag (`trojanized-primary`, `injection-exec-fixed`) become `high`; every predicate stays as it is (tier 1 only; injection needs a fix; a tier-2 candidate with a flag is a notice; an injection candidate with no fix falls through to the other clauses). Every other level the poster computes today is unchanged. The tests in `tests/poster` that expect a critical made by a flag change to the new level and keep what they check besides (the hold of a high with no fix or range, the channel a high posts to, a later KEV listing raising the thread); the plan names each one. No other test changes.
9. `scripts/test-gate.sh` passes.

## Approach

### `spec/ruleset.json`

```
version      1
levels       ["notice", "high", "critical"]        ascending
ttl_days     {"critical": 14, "high": 30, "notice": 90}
tier_cap     {"1": "critical", "2": "high"}
reading_cap  "high"
fields       per source, the exact key set of a reading
sources      the authoritative-source table, first matching row classifies a reading
rules        the level table, first matching row for the reading's class gives its level
```

Readings. A reading is `(source, fields)`; `source` is `kev`, `ghsa` or `osv`. Every key of the source's field list is present; a value the source does not state is `null` (a list is empty). Values are the source's own strings, never a derived one.

| source | fields |
|---|---|
| `kev` | `cve_id`; `name`: CISA's `vendorProject` and `product`, each trimmed, joined by one space, or `null` when the catalog does not list the CVE |
| `ghsa` | `ghsa_id`, `type` (`reviewed`, `unreviewed`, `malware`), `withdrawn_at`, `repository` (`owner/repo`, lowercase, of the repository advisory it came from), `severity`, `cvss_vector`, `cwes` (`CWE-<n>`, sorted), `packages` |
| `osv` | `osv_id`, `withdrawn`, `packages` |

`packages` is a list of `{ecosystem, name, range, first_patched}`; `ecosystem` is the registry as the source names it, in lowercase (`npm`, `crates.io`, `debian:12`), and may be empty (a "Software" block names no registry). `withdrawn_at` and `withdrawn` are `null` or the UTC time the source states (`YYYY-MM-DDTHH:MM:SS[.fraction]Z`); any other text is a malformed reading, never a withdrawal. `cvss_vector` is `null` or a complete CVSS 3.0, 3.1 or 4.0 vector: every base metric of the version, each once, with a value the version defines (4.0 fixes their order; 3.0 and 3.1 allow any); a vector cut short or stating a metric twice is malformed. The order is total: ascending by the tuple (`ecosystem`, `name`, `range`, `first_patched`) compared by code point, a `null` counting as the empty string (a stated value is never empty). Two entries equal in all four are one entry: a list that repeats one is malformed. A builder sorts and drops repeats; a reader refuses a list that is not in this order. `cwes` likewise: ascending by code point, each once, and an advisory with no CWE data has `[]`, never `null`.

Binding (D2). A reading supports a product only by exact identity through the scope file, the same lookup h340 built: `kev` by `name`; `ghsa` and `osv` by `ecosystem:name`, or `name` alone when the ecosystem is empty. Nothing is matched in prose. A reading that binds no scope product supports nothing.

Source table (D3, revised design rule 2):

| class | source | when | alone | lowers |
|---|---|---|---|---|
| `kev` | kev | listed | critical | yes |
| `ghsa-malware` | ghsa | `type` is `malware` | critical | yes |
| `ghsa-vendor` | ghsa | `github.com/<repository>/` is one of the bound product's `authority` prefixes | critical | yes |
| `ghsa-reviewed` | ghsa | `type` is `reviewed` | high | yes |
| `ghsa-other` | ghsa | anything else | notice | no |
| `osv-mal` | osv | id starts `MAL-` | high | yes |
| `osv-other` | osv | anything else | notice | no |

`alone` caps what the class can set. There is no rule that adds two readings up. The review's "an OSV `MAL-` entry becomes critical only with a second source" holds because the second source (KEV, a GitHub malware advisory, the vendor's own advisory stating malicious code) is critical by its own row; an `osv-mal` reading beside a vendor advisory that states something else stays high. A rule that lifted on "any second reading for the same product" would let an attacker's `MAL-` entry borrow an unrelated real advisory, and neither source states a link to the other that a member could check. `lowers: no` marks a source its subject's attacker can write: it never sets above notice and its withdrawal or change justifies no lowering. A withdrawn reading (`withdrawn_at`, `withdrawn`) and an unlisted KEV reading support nothing: their level is `none`.

Level table, version 1. It keeps what the poster does today wherever a field can express it, and nothing else:

| class | when | level |
|---|---|---|
| `kev` | | critical |
| `ghsa-malware` | tier 1 | critical |
| `ghsa-vendor` | tier 1, `cwes` has CWE-506 (embedded malicious code) | critical |
| `ghsa-vendor` | tier 1, `severity` is `high` or `critical` | high |
| `ghsa-vendor`, `ghsa-reviewed` | tier 1, CVSS attack vector N or A, a code-execution or credential CWE, a package with a first patched version | high |
| `osv-mal` | tier 1 | high |
| any | | notice |

The result is capped by the class's `alone` and by the product's tier (`tier_cap`: tier 2 never reaches critical, as today).

`level(readings, product)`: the highest level any one reading gives the product; `none` when no reading supports it.

The loader refuses a ruleset whose version it does not know, an unknown key, an unknown condition, a level outside `levels`. A newer file is never half-understood.

### The claim (D11)

`{id, source, fields, ruleset, level, confirmed_at, checked_at}`. `id` is the advisory id the source is looked up by and equals the fields' own id; its shape decides the source (`CVE-` reads kev, `GHSA-` reads ghsa, anything else that is an OSV id reads osv). `ruleset` is the integer version. `level` is `critical`, `high`, `notice` or `none`. The two times are integer Unix seconds, `confirmed_at <= checked_at`.

Canonical form: the JSON object serialised with keys sorted by code point at every depth and no whitespace; integers only (no float); every string printable ASCII (U+0020 to U+007E), so the bytes are ASCII and the only escapes are the quote's and the backslash's. A source value with any other character cannot be carried: the reading is malformed and makes no claim. Unicode is left out whole (the delta review's finding): which characters exist and what they normalise to differs between the Unicode versions two readers run, and a name one reader folds to a product's identity and another does not would give two levels under one digest. Every identity in `spec/scope.json` is ASCII. The manifest and the checkpoint sign the same key order and separators. `ruleset.canonical(claim)` returns the bytes; `claim-vectors.json` carries them with their SHA-256.

The product is not in the tuple: it is the product of the alert the claim is signed with. `check_claim(claim, product)` is the offline check of the revised design's rule 4.

### Digest and pin (D10)

`digest` is the SHA-256 of the canonical form of `{"ruleset": <spec/ruleset.json>, "scope": <spec/scope.json>}`, so the level table, TTL table, source table and scope file have one digest.

A pin is `{version, sha256, min_version}` (the value the root-signed manifest will carry). `check_claim(claim, product, pin=None)` returns one verdict:

| verdict | when |
|---|---|
| `outdated` | a pin is given and the CLI's version is below `min_version`, or equals `version` with a different digest. The CLI judges nothing and says it is out of date |
| `refused` | the claim is malformed, or names a ruleset below the pin's `min_version` |
| `unknown` | the claim names a ruleset newer than the CLI's ("upgrade") |
| `mismatch` | the CLI's own ruleset gives a different level for the claim's fields and this product |
| `ok` | otherwise |

The CLI always computes with its own ruleset. A claim that names an older version gets no older rule.

### The poster

- `rules.evidence` already reads the vendor's repository advisory page by its labelled fields. `Evidence` gains `ghsa`, `repository` and `packages` (the blocks that are this product, as the page states them).
- A `kev` reading is made in one place, `candidates.from_kev`, from the catalog entry's own `vendorProject` and `product`. `main.gather` gives `from_kev` only the catalog this run read from CISA (or the operator's file), so the reading exists only when the catalog was read this run. `rules.evidence` sets `kev` from the candidate's `exploited` flag, which a merge and the state file carry across runs; that flag never makes a reading.
- A `ghsa` reading is made in `main.admit` when a repository advisory page confirmed the candidate by its fields (`rules.readings_for`). A vendor site page that only names the id yields none; that alert is a notice, which needs no support. Fields the page does not show are `null` (`type`, `cvss_vector`, `withdrawn_at`) or `[]` (`cwes`): the clauses that need them do not fire for the poster until ny5g reads the API endpoint. The page's severity word `moderate` is written `medium`, the API's word.
- The readings ride on the candidate (`Candidate.readings`, never written to the state file, like `severity_word`); `ledger.merge` joins its members'. A candidate deferred and read back from the state file has none: a catalog outage keeps the level `exploited` gives and makes no claim of a fresh confirmation. A merge whose first member is a collector record keeps that record's product text; the KEV reading still carries CISA's own name, since it was made before the merge.
- `rules.claims_for(c, scope, now)` turns the candidate's readings into claims.
- `level_for(c, scope, source_ok)` keeps its signature and reasons. The level is the highest of: the ruleset's level for the candidate's readings; the KEV class level when `exploited` is carried from the ledger with no reading this run (absence of a fresh reading lowers nothing, D4); a reading, capped at `reading_cap`. The reading clauses keep their predicates (success criterion 8): where the old code returned `critical` with `trojanized-primary` or `injection-exec-fixed` it returns `high` with reason `reading`; `unverified` is as today.
- `rules.basis(c, scope, level)` is `fields` when the readings alone give the level, else `reading`. t8jr carries it on the wire.

## Alternatives considered

- **Level logic in Python, `ruleset.json` holding only numbers.** Rejected: the digest would not cover the level table, which is what D10 asks it to cover.
- **Product inside the claim tuple.** Rejected: the issue fixes the tuple; the alert it is signed with already names the product, and a second copy is one more field to disagree.
- **Raw `vendorProject` and `product` as two KEV fields.** Rejected: the scope file defines the KEV identity as the two joined by one space, and that joined string is the only thing the binding reads. Two fields add nothing a member can check that one does not.
- **Replace `level_for` outright with 9kgk's consequence rules.** Out of scope: 9kgk owns the rule; this slice owns the mechanism and a version 1 that changes one thing, the reading-made critical.
- **Manifest `ruleset` key in this slice.** Split out: `manifest.parse_content` in every released reader refuses an unknown content key, so the reader change must ship in a release before the root signs such a manifest. `min_cli` is t8jr's.

## Assumes

- TTLs for `high` (30 days) and `notice` (90 days) are not stated in any design text; 14 days for critical is 9kgk's. r0ra and 9kgk amend the table with a version bump.
- CWE-506 on the vendor's own advisory is the field form of "trojanized release confirmed by a primary source". The code-execution and credential CWE list is CWE-77, 78, 94, 95, 96, 502, 522, 798. 9kgk owns both choices.
- GitHub's advisory API states the repository advisory an entry came from; fv4g confirms the field against the unauthenticated response before it relies on `ghsa-vendor`.

## Blast radius and rollback

Poster behaviour changes in one way: a candidate whose only critical clause was a model flag posts `high`. No wire format, state file, manifest or fetch changes. `ruleset.py`, the two spec files and `Candidate.readings` are additive. Rollback is a revert of the merge commit; the state file needs nothing.

No release or install is part of this slice. The poster host runs from a checkout; picking this up there is a rollout issue.

## Open questions

None blocking. Notes go to 9kgk (the version 1 table and what it owns), t8jr (`basis` and the claim's wire form), fv4g and ny5g (the poster reads a page, the member an API: `type`, `cvss_vector`, `cwes` are `null` in the poster's claims until the poster reads the same endpoint; aliases are still the bot's to patch, so the claim's `id` must be checked against the thread's first id).
