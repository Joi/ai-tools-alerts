# Poster candidate adapters (Task B1) — design

Kata: ai-tools-alerts#6j8x. Parent plan: docs/plan.md, Task B1. Epic jibot-code#gr5b.

## Problem

The fleet poster (Slice B) needs one normalized shape for "something that might be
posted" from three inputs: the live security-watch heartbeat's `run.json`, the CISA
KEV JSON, and the d9aa collector run record (schema_version 1). All three are
untrusted text: written by a model (heartbeat), by an outside agency (KEV) or by a
collector that reads outside feeds. The heartbeat and collector records also carry
private fleet detail (host names, evidence paths, observed versions, kata refs)
that must never reach a post (design: "Nothing private leaves the fleet").

## Success criteria

1. `from aitools_alerts.poster.candidates import Candidate, Source, from_heartbeat, from_kev, from_collector` imports with the standard library only.
2. `scripts/test-gate.sh` passes, with one test per adapter plus
   `test_heartbeat_adapter_never_emits_hosts_or_evidence` and
   `test_kev_adapter_filters_by_date_added`.
3. No committed fixture contains any of `host-a`, `host-b`, `host-d`, `host-e`,
   `host-f`, `host-c` (asserted by a test), and no serialized candidate contains a
   host name that appears anywhere in its input record.
4. Malformed input (wrong types, missing fields, bad JSON, unreadable file) never
   raises out of an adapter; each skipped item is counted by reason.

## Approach

`aitools_alerts/poster/candidates.py`, standard library only.

- `Source(url: str, published_at: str | None)` frozen dataclass. Defined here
  because `aitools_alerts/schema.py` (A2, j153) has not landed; B2 (31x7) makes one
  import the other. A URL is accepted only if `urllib.parse` gives scheme `https`
  or `http` and a non-empty host, and it has no whitespace or control characters.
- `Candidate` frozen dataclass with exactly the plan's fields:
  `id, aliases, product_text, advisory_severity, local_level_hint, exploited,
  trojanized, injection_exec, fixed, affected, sources, observed_at`.
  `aliases` and `sources` are tuples (immutable). `to_dict()` gives a JSON-ready dict.
- `CandidateList(list)`: the return type of all three adapters. It is a `list[Candidate]`
  (the plan's interface) and carries `skipped: collections.Counter` keyed by reason,
  so B4 can log what was dropped without the adapters raising.

### Shared rules (all adapters)

- Unknown keys are ignored. A field of the wrong type is treated as absent; a
  required field absent skips the item with a counted reason.
- **`exploited` is KEV-only.** Only `from_kev` sets `exploited=True`. The heartbeat
  and collector adapters always set `False`, whatever the input says, because B2
  receives the boolean without provenance and treats it as the KEV clause of the
  critical rule. A collector finding that KEV lists reaches B3 as a `from_kev`
  candidate too, and B3's alias merge carries the flag.
- `trojanized` and `injection_exec` are `True` only when the input value is the JSON
  boolean `true` (never a string). They are a model's reading by design (design.md:
  "the model step may fire them"), and B2 gates both on a fetched primary source.
- `local_level_hint`: the input `local_severity`, lowercased and stripped, kept only
  when it is one of `critical`, `high`, `medium`, `low`, `none`, `not_affected`,
  `out_of_scope`; anything else is `None`.
- Timestamps (`observed_at`, `Source.published_at`) are kept only when they match
  `YYYY-MM-DD` optionally followed by a time and zone; anything else is `None`.
- `fixed` and `affected` are advisory facts, not local observations. The heartbeat
  adapter never fills them (its records mix in host-observed versions). The collector
  adapter keeps `fixed` only when it is a concrete version (`v?` + digit, then
  `[0-9A-Za-z.+_-]`, at most 64 characters, no `x` or `*` wildcard component) and `affected` only when it is a version
  range: tokens over the same alphabet with `<>=!~^` operators, separated by `,`,
  `||` or spaces (at most 200); everything else,
  including "unknown" and "no fix", is `None`, so B2's "fix available" test cannot be
  satisfied by a sentinel.
- String fields are capped (ids and aliases at 200 characters, other text at 500)
  and items over the cap are skipped (ids) or truncated (free text); aliases keep at
  most 32 entries; sources at most 8.
- **Private-content guard.** A text field that contains a filesystem path
  (`/Users/`, `/home/`, `/private/`, `/var/`, `/tmp/`, `/etc/`, `~/` anywhere, so
  markdown backticks or quotes do not hide it, or a drive letter), or a kata ref
  (`word#xxxx`), in its literal or percent-decoded spelling, is dropped (`None`);
  when that field is the id or product_text, the candidate is skipped. Source URLs
  with userinfo are rejected; a fragment is stripped; the URL is split first and its
  path and query are then percent-decoded (up to three rounds) and rejected when they
  hold a host name, a path or a kata ref. A source whose host is an IP literal that
  is not globally routable (loopback, private, link-local, tailnet CGNAT), has no
  dot, or ends in `.local`, `.internal`, `.lan`, `.home.arpa`, `.ts.net`,
  `.vm.example` or `.localhost` is dropped. Path and kata-ref patterns are
  case-insensitive. A bare `#xxxx` with no project name is not treated as a kata ref.
- Any string holding a control, format (bidi override) or lone surrogate character
  is treated as absent. Timestamps must also parse with `datetime.fromisoformat`.
- **Host scrub.** Each adapter collects the host names its own input names — the
  record's `host_coverage[].host`, every finding's `hosts`, `affected_hosts` (strings
  or `{host: ...}` objects), `host`, and the middle segments of heartbeat keys of the
  form `<id>|<host>|<component>` (the second segment of a two-segment key) — plus
  `host` given as an object and `host_coverage` given as strings — and the six
  generic fleet names. Host-named nested
  keys (the heartbeat's `"<host>": "<note>"`) are never read, so they need no rule; a
  name is known as a host only when one of the listed fields names it. A field that
  names a host, case-insensitively and in literal or percent-decoded spelling, is
  dropped, not rewritten: a product or id that names a host is local narrative, not
  an advisory, so the candidate is skipped; advisory_severity, fixed, affected and
  aliases become `None` or are left out; a source URL is dropped. Names shorter than three characters are still
  scrubbed (over-scrubbing is the safe failure).
- **Backstop.** After building, the candidate's whole `to_dict()` JSON is checked
  against the host set and the private-content patterns; a hit skips the candidate
  (`private content`). This covers any field a later edit forgets.
- **Residual risk, stated.** `advisory_severity` and `product_text` are free text; a
  version number in them can be local rather than public, and no pattern tells the
  two apart once the host name is gone. Both are rule inputs: B2 matches scope on
  product_text and severity words on advisory_severity. B3 composes the post body
  from the id, aliases, the matched scope entry's display name, sources, fixed and
  the level, and echoes neither field verbatim (filed on B3, ai-tools-alerts#h2gf).
- **Bounded work.** `run.json` over 16 MiB is skipped unread; a decoder
  `RecursionError` is caught; the version-range check splits on `,`, `||` and
  whitespace and matches each token with a regex that has no adjacent unbounded
  repeats, so no input backtracks; and each item runs under a catch-all that counts
  `item error`, so nothing an item holds can raise out of an adapter.
- Fields the plan says to drop are never read into the candidate: `hosts`,
  `affected_hosts`, `evidence*`, `kata`, `owner`, `rationale`, `action`,
  `recommended_action`, `alert_decision`, and any other key.

### from_heartbeat(run_dir: Path)

Reads `run_dir / "run.json"`. Unreadable file or invalid JSON returns an empty list
with `skipped["run.json unreadable"]`. `findings` may be a dict (the live shape) or
a list. Per finding value (must be a dict):

- `id`: the value's `id` string; else the first string of `ids`; else the first
  `|`-segment of the dict key. The key's other segments are never used as id.
- `aliases`: `aliases` strings plus the remaining `ids` strings, deduplicated, id
  excluded.
- `product_text`: `product` if a string; else, for a key with three or more
  `|`-segments, the last segment (the component: `CoreGraphics`, `WebKit`); else
  the key itself when it differs from the id (`WordPress-7.1.4`); else the id. This
  is best-effort: the heartbeat has no product field today, and B2's scope matcher
  treats an unmatched product as out of scope, which is the safe direction.
- `sources`: exactly one, from `source` (string URL) with `published_at` when it is a
  string. No valid `source` skips the finding (`no source`): the meta entries
  (`other-leads`, `new-discovery-leads`) have none.
- `advisory_severity`, `observed_at`: per the shared rules; `fixed` and `affected` are always `None`.

`feeds.json` is not read by `from_heartbeat`: its `cisa-kev` block goes to `from_kev`.

### from_kev(kev_json: dict, since_date: str)

Accepts the CISA catalog shape (`vulnerabilities`) and the heartbeat's `feeds.json`
`cisa-kev` block (`items`). `since_date` is the caller's own value, so a value that
is not `YYYY-MM-DD` raises `ValueError` (a programming error, not untrusted input).
Per item: `cveID` must match `CVE-\d{4}-\d{4,}`; `dateAdded` must be a valid
`YYYY-MM-DD` date and `>= since_date`; `vendorProject` and `product` must be
non-empty strings. Then `exploited=True`, `product_text = vendorProject + " " + product`,
`observed_at = dateAdded`, `advisory_severity = None`, sources = the catalog URL
`https://www.cisa.gov/known-exploited-vulnerabilities-catalog` (published_at
`dateAdded`) followed by each valid http(s) URL found in `notes` (split on `;` and
whitespace), deduplicated. KEV entries carry no host data; the host scrub still
applies the six generic names.

### from_collector(record: dict)

Requires `schema_version == 1` (else empty, `skipped["schema_version"]`). Per entry of
`findings` (list of dicts): `id` (string, required), `aliases` (strings),
`product` → `product_text` (required), `sources` (list of `{url, published_at}`;
invalid entries dropped; none valid skips the finding), `observed_at`,
`advisory_severity`, `local_severity` → hint, `trojanized`/`injection_exec`
booleans, `fixed`/`affected` per the version grammar. `exploited` is ignored (KEV-only). `affected_hosts`, `owner`,
`rationale`, `recommended_action`, `confidence`, `exposure` are dropped.

### Fixtures

- `tests/fixtures/heartbeat/run.json`, `feeds.json`: from host-b
  `.../runs/2026-11-04T175014Z/`. Four findings kept (a host in the key, a host list
  with aliases, an alias-only finding, a finding with a host-named nested key) plus
  the `other-leads` meta entry; every fleet host renamed `host-A`, `host-B`, ...;
  every evidence path dropped; observed versions removed from free text; `alerts`
  emptied. `feeds.json` keeps the one KEV item and four HN items.
- `tests/fixtures/collector/run-record.json`: `run-levels.json` from
  amplifier-bundle-joi trimmed to four findings with hosts renamed the same way.

The real-name denylist used during redaction lives only in the session scratchpad.
The committed test checks the six generic fleet names, which are already public in
the fleet's open repos, and checks the fixture's own placeholder hosts.

### Packaging

`pyproject.toml` `[tool.setuptools] packages` gains `aitools_alerts.poster`, or an
installed wheel would omit the subpackage.

## Alternatives considered

- Return `(list, stats)` tuples: breaks the plan's `-> list[Candidate]` interface.
- Module-level skip counters or logging only: global state across calls; tests cannot
  read them cleanly.
- Infer `exploited` from heartbeat text ("CISA KEV"): would let a model's sentence
  trigger a critical. Rejected; KEV itself is read by `from_kev`.
- Drop any candidate whose text mentions a host instead of scrubbing: loses real
  advisories whose product field happens to be noisy. Scrubbing the text keeps the
  advisory and removes the name; an id that names a host is still dropped.

## Blast radius and rollback

New subpackage, tests and fixtures only, plus one line in `pyproject.toml`. Nothing
imports it yet (B2+ will). Rollback: revert the commit.

## Open questions

None blocking. B2 reconciles `Source` with `schema.Source` and decides how to log
`CandidateList.skipped`.
