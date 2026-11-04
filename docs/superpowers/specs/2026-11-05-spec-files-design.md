# Spec files and the advisory parser (Task A2, ai-tools-alerts#j153)

Date: 2026-11-05. Parent: docs/plan.md Task A2; design docs/design.md ("Post format", "Scope list", "Severity and the critical rule", "Trust manifest and action vocabulary").

## Problem

Every later task reads the same contract: the fenced JSON block at the end of a post (A4 matches it, A5 verifies and applies it, B2 levels candidates with the scope list and the primary-domain allowlist, B3 renders it). Nothing defines that contract yet. It must be one module with no third-party dependency, strict enough that a hostile or malformed block is rejected rather than half-read, and the primary-domain check must not let a user-content page on an allowlisted host stand in for a vendor advisory, because that check is what lets a model-read critical reach the interrupt channel.

## Success criteria

1. `spec/advisory.schema.json`, `spec/actions.json`, `spec/scope.json`, `spec/primary-domains.json` exist and load as JSON.
2. `python3 -c "from aitools_alerts.schema import VERBS, LEVELS; print(sorted(VERBS), sorted(LEVELS))"` prints the six verbs and three levels of the plan's Global Constraints.
3. `aitools_alerts/schema.py` exposes the names in the plan's Interfaces block with those exact dataclass fields.
4. `tests/test_schema.py` holds the seven plan tests plus the field-equals-required-keys test and the hardening tests below; `scripts/test-gate.sh` passes.
5. Standard library only; no change to `dependencies = []`.

## Approach

### Constants

`LEVELS = frozenset({"critical", "high", "notice"})`, `VERBS = frozenset({"upgrade", "disable_skill", "remove_mcp_server", "rotate_credential", "stop_using", "review_setting"})`, `ROLES = frozenset({"curator", "relay-bot"})`. Hard-coded in `schema.py`; a test asserts `actions.json` and the schema file's enums equal them, so the files and the code cannot drift.

### Dataclasses

Frozen dataclasses with exactly the plan's fields: `Advisory(id, aliases, level, advisory_severity, title, products, actions, sources, posted_by, posted_at, expires_at)`, `Product(name, ecosystem, affected, fixed)`, `Action(verb, target, value)`, `Source(url, published_at)`, `ScopeEntry(name, ecosystem, tier, match)`. Every Advisory field is a required key in the schema (nullable ones are required and may be `null`); a test asserts `{f.name for f in fields(Advisory)} == set(schema["required"])`, and the same for the three nested objects.

### Block extraction (`parse_post`)

A line scanner following CommonMark fence rules: outside a fence, a line indented at most three spaces with three or more backticks or tildes opens a fence (a backtick info string may not contain a backtick) and the rest of the line, stripped, is its info string; inside, a line indented at most three spaces made only of at least as many of the same character, plus trailing whitespace, closes it. Every fence is tracked, so an `aitools-alert` line quoted inside another fence (backtick or tilde, indented or not) does not open a block. Ours opens only at column 0, with backticks and info string exactly `aitools-alert`. An ours-fence still open at the end of the content is recorded as unfinished. `parse_post` returns `None` when there is no block, when the last block is unfinished, or when it is invalid. It never falls back to an earlier block: the last block is authoritative, and an invalid last block means the post's current state is unknown.

### Validation (hand-written, strict)

`validate(obj) -> Advisory` raises `ValueError` with a field path; `decode_block(text)` adds the JSON decoding and turns `json.JSONDecodeError` and `RecursionError` (deep nesting) into `ValueError`; `parse_post` turns `ValueError` into `None`, so no input raises. Rules, mirrored in `advisory.schema.json` where JSON Schema can express them; the schema's description lists the parser-only rules (duplicate keys, NaN/Infinity, nesting, the character rules, `expires_at >= posted_at`, the byte limit), and each of those has a runtime test:

- The block is a JSON object; duplicate keys anywhere are rejected (`object_pairs_hook`). Unknown keys are rejected at every level (`additionalProperties: false`); every listed key is required.
- `id`: `^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$`. `aliases`: list (≤ 50) of strings with the same pattern.
- `level` in LEVELS; `posted_by` in ROLES (A5 overrides it from the manifest; the parser only checks the shape).
- `advisory_severity`: null or text ≤ 64. `title`: text, 1–300.
- `products`: 1–50 objects. `name` text 1–200; `ecosystem` `^[a-z0-9][a-z0-9-]{0,63}$`; `fixed` null or a version: dotted integers (1–5 parts) with an optional lowercase suffix (`9.9p1`, `1.0rc1`); `affected` null, `*`, or one to four comparators (`<`, `<=`, `>`, `>=`, `=` and a version) joined by `,`. This is the grammar A4's compare reads; A4 treats anything it cannot compare as notify-only.
- `actions`: 0–20 objects. `verb` in VERBS; `target` and `value` (nullable) match `^[A-Za-z0-9~/.@][A-Za-z0-9 ._:/@+~=,-]{0,199}$`: no quotes, no shell metacharacters, no leading `-`.
- `sources`: 1–20 objects. `url` an `https://` URL with a host, ≤ 2048 chars; `published_at` null or `^\d{4}-\d{2}-\d{2}` followed by up to 32 of `[0-9T:.+Z-]`.
- `posted_at`: int ≥ 0; `expires_at`: null or int ≥ `posted_at`. `bool` is not accepted as int.
- "text" means a `str` with no character in Unicode category Cc (controls, including newline) or Cs (unpaired surrogates, which JSON `\ud800` escapes produce and UTF-8 cannot encode) and none of the bidi controls U+202A–U+202E, U+2066–U+2069.
- Whole block ≤ 64 KiB.

Why the version and argument patterns: A4/A5 print upgrade commands built from `fixed` and the target; refusing shell metacharacters, quotes, option-like prefixes and newlines in every field an action can reach means no later stage sees them. It is depth, not the defence: execution is never done from a post (Global Constraints), and A4/A5 build commands from fixed per-ecosystem templates with each argument passed as its own argv element.

### `render_post(adv, body)`

Validates `adv` (round-trips it through `validate`), emits `body.rstrip("\n")`, a blank line, then a ```` ```aitools-alert ```` fence with `json.dumps(asdict(adv), indent=2, ensure_ascii=False)` and a closing fence. It then parses its own output and raises `ValueError` if the result is not equal to `adv` — this catches a body with an unclosed fence that would swallow the block.

### Spec files

- `actions.json`: `{"verbs": [{"verb", "meaning", "target", "value"}]}` for the six verbs, per the design's list (`upgrade` target product, value minimum version; `disable_skill` skill name; `remove_mcp_server` server name; `rotate_credential` which credential; `stop_using` marketplace or package; `review_setting` setting path).
- `scope.json`: `{"entries": [{"name", "ecosystem", "tier", "match"}]}` with the plan's 16 tier-1 entries and 3 tier-2 entries, each `match` a non-empty list of lowercase substrings. `load_scope(path=SPEC_DIR/"scope.json")` validates (tier in {1,2}, match non-empty, every pattern lowercase and non-empty, no duplicate names) and raises `ValueError` otherwise.
- `primary-domains.json`: `{"domains": [{"host", "paths"?, "owners"?}]}`, the plan's 17 hosts. `github.com` carries `"paths": ["/advisories/", "*/security/advisories/"]` and an `owners` list (the vendors of the tier-1 products: anthropics, openai, google-gemini, nousresearch, openclaw, modelcontextprotocol, nodejs, python, golang, rust-lang, docker, moby, containerd, opencontainers, tailscale, git, openssh). `go.dev` carries `"paths": ["/security/", "/doc/security/", "/doc/devel/", "/blog/"]` because it also serves user-shared playground programs.
- `advisory.schema.json`: JSON Schema draft 2020-12 matching the rules above. It documents the contract; `schema.py` enforces it.

### `is_primary(url)`

True only when all hold: scheme `https`; no userinfo; port absent or 443; no control, surrogate or space character; hostname (lowercased, one trailing dot stripped) equals a listed host or `www.` + a listed host; and, for a host with `paths`, the path matches one of them. Path rules: the raw path must not contain `%`, `\`, an empty segment or a `.`/`..` segment; a pattern `/p/` is a segment prefix that must be followed by at least one more segment (`/advisories/` matches `/advisories/<id>`); `*/security/advisories/` matches `/<owner>/<repo>/security/advisories/<id>` only when `<owner>` (case-insensitive) is in the host's `owners`, because any repository owner can publish an advisory in their own repository. Query and fragment are ignored.

Decided: exact host (plus `www.`), not suffix matching. Suffix matching would admit `community.openai.com`, `forum.cursor.com`, `discuss.python.org` and `lists.debian.org`, which carry user-written posts. A wrongly rejected source costs only a downgrade from critical to high "unverified"; a wrongly accepted one pages every member. Exact host still does not establish publisher authority on a host that serves user content on its own paths, which is why `github.com` and `go.dev` are path-restricted (review pass 1). Hosts whose security pages live on a subdomain are listed by that subdomain (`kb.cert.org`, `support.apple.com`, `docs.docker.com`, `blog.google`).

### Spec file location

`SPEC_DIR = Path(__file__).resolve().parent.parent / "spec"`, the repo root, as the plan names it. Loaders take an optional path. Shipping the spec files inside an installed wheel is A5's packaging step (its `pipx install .` check); noted on ai-tools-alerts#0xrc rather than solved here.

## Alternatives considered

- jsonschema as a validator: rejected, Global Constraints forbid runtime dependencies.
- Falling back to an earlier valid block when the last is invalid: rejected, it would act on stale state.
- Accepting unknown keys for forward compatibility: rejected; v1 has one writer set (the manifest) and a schema change ships with a CLI release.
- Validating `ecosystem` against `scope.json`: rejected; it couples the parser to a file edited by pull request, and an unknown ecosystem simply matches no inventory in A4.
- Reply blocks with only changed fields (design, B3): out of A2's interface; `parse_post` handles full blocks. Noted on A5 (0xrc) so it adds a partial-block parser on this module.

## Blast radius and rollback

New files only (four JSON files, one module, one test file, fixtures, run artifacts). Nothing imports `schema` yet. Rollback is reverting the commit.

## Fixtures

`tests/fixtures/posts/`: `valid-critical.md` (Claude Code, `upgrade` to a fixed version, a GitHub repository advisory source), `no-info-string.md` (the same block under a plain ```` ```json ```` fence), `unknown-verb.md` (verb `run_command`). Identifiers are obviously synthetic (`AITA-TEST-0001`, `CVE-2099-0001`, `GHSA-test-test-test`); no host names, no keys.

## Open questions

None blocking.

## Changes from the code review (pass 1, Stage 1 and fresheyes)

These supersede the rules above where they differ.

- Lines split only on CR, LF and CRLF (CommonMark), never on U+2028, U+2029, form feed or the other `str.splitlines` separators. Text fields also reject categories Cf (zero-width and bidi), Zl and Zp; URLs reject Cc, Cf, Cs, Zs, Zl and Zp.
- `parse_post` returns None for content over 1 MiB characters. The scanner holds only the current `aitools-alert` candidate's body, drops it once it exceeds 64 KiB, and never buffers other fences' bodies.
- Action arguments are checked per verb. An `upgrade` value is a version (the `fixed` grammar). A `disable_skill` or `remove_mcp_server` target is one name, optionally `@scope/name`, with no path. No target or value contains ` -` (an option after a space) or `..`.
- `posted_at` and `expires_at` are at most 253402300799 (9999-12-31).
- A source URL must start with lowercase `https://`, the same rule the schema file states.
- `python.org` is path-restricted to `/news/security/`, `/dev/security/` and `/downloads/release/`, because it also hosts user-submitted job listings.
- `scope.json` drops `runc`, `rustc` and `cargo` as bare substrings, which matched "truncate", "trustcenter" and shipping trackers.
- `render_post` raises ValueError on a non-Advisory or non-str argument. The default primary-domain table is loaded once and cached.
- Notes for later tasks: `Advisory` is frozen but not hashable, because the plan mandates list fields, so A4 and A5 must not use it as a set member or dict key. B2 should still review KEV vendor strings that match no scope entry (Review Focus 4).
