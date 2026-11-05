# Plan: launch readiness (ai-tools-alerts#hgs0)

Spec: docs/superpowers/specs/2026-11-06-launch-readiness-design.md. One branch,
three chunks, in this order. Standard library only; pytest the only dev dep.

## Chunk 1 — kind-9 filter, no "(untitled)" entries

- [ ] `mirror/export_mirror.py`
  - `clean()` (~line 125): after `nostr.verify_event`, `if ev["kind"] != 9:
    counts["other_kind"] += 1; continue`. Docstring says why (NIP-29 admin
    events from the relay-bot key). Module docstring: "keeps only kind 9".
  - Constant `CHAT_KIND = 9`.
  - `_first_line`: return `None` for content with no non-blank line;
    `atom_doc` skips such a root (not counted in `entries`).
  - `summary_line`: add `other_kind={c['other_kind']}` after `bad_sig`.
- [ ] `tests/mirror/test_export.py`
  - `ev()` helper default `kind=9` (the existing tests used kind 1, which the
    filter now drops), with a `kind=` parameter.
  - New fixture builder `admin_rows()`: kinds 9000, 9001, 9005, 9007, 39000,
    39001, 39002, 40099 signed by `BOT_SEC` (a manifest key), no e tags, empty
    or JSON content as the relay writes them.
  - `test_admin_kinds_dropped_from_every_output`: feed and critical rows =
    admin rows + one advisory root; feed.json/critical.json events are kind 9
    only; Atom has exactly the advisory entry; no title "(untitled)"; summary
    counts `other_kind=8`.
  - `test_blank_root_is_not_an_atom_entry`: kind 9 root with content "  \n".
  - `test_filtered_mirror_is_accepted_by_the_cli_reader`: export into a dir
    with manifest signed by the test root; `pull.fetch(out.as_uri() + "/",
    State.load(tmp), root_pubkey=ROOT_PUB, now=...)` returns no error; the
    `pull.advisories` threads equal those from an export of the kind 9 rows
    alone (root ids, titles).
  - Update the write-order assertion (chunk 2 adds index.html).

Acceptance: `python3 -m pytest tests/mirror -q` green.

## Chunk 2 — index.html

- [ ] `mirror/export_mirror.py`
  - imports: `html`, `from aitools_alerts import pull`, `from
    aitools_alerts.state import State`.
  - constants: `PIPX_LINE = "pipx install git+https://github.com/Joi/ai-tools-alerts"`,
    `REPO_URL = "https://github.com/Joi/ai-tools-alerts"`, `RELAY_HOST =
    "buzz.ai-tools.md"`, `INDEX_LIMIT = 20`.
  - `_threads(events, m)`: `State(dir=Path("/nonexistent"), roots={TRUST_ROOT_PUBKEY:
    [m, {e["id"]: e for e in events}]}, manifest_root=TRUST_ROOT_PUBKEY)`;
    return `pull.advisories(st)`. (Module-level `TRUST_ROOT_PUBKEY` so the
    tests' monkeypatch applies.)
  - `_source(adv)`: first `schema.is_primary` url, else first source + flag.
  - `index_doc(events, m, channels, generated_at, mirror_url) -> bytes`: three
    sections as the spec says; newest first by root `created_at` then id;
    drop synthetic; cap 20; `_esc = html.escape(_xml_safe(s), quote=True)`.
  - `export`: write `index.html` after feed.json, before feed.atom; result
    gains `"index_advisories": n`; summary line prints `index advisories=`.
- [ ] tests
  - `test_index_page_lists_advisories`: two advisory roots, one retracted by
    a curator reply, one admin event; page has `Retracted: `, levels, dates,
    source hrefs, newest first; no "<script", no " on" attribute
    (regex `\son[a-z]+=`), three `<section` tags, `charset="utf-8"`, decodes
    as UTF-8.
  - `test_index_subscribe_block`: contains `--mirror-url`'s feed.atom URL,
    `PIPX_LINE`, `#security-feed`, `#security-critical`, `REPO_URL`; README
    contains `PIPX_LINE`.
  - `test_index_escapes_post_text`: a title with `<script>alert(1)</script>`
    renders escaped.
  - `test_index_empty`: no advisories → "No advisories yet."
  - `test_index_skips_synthetic`.
  - `NAMES` and write order include index.html.

Acceptance: `python3 -m pytest tests/mirror -q` green; open a generated page
from a fixture and read it.

## Chunk 3 — README Status

- [ ] `README.md` "## Status": live state (hourly poster on the fleet, mirror
  every 5 minutes at https://buzz.ai-tools.md/alerts/ with feed.atom and the
  page, digest daily at 09:00 Tokyo, critical posts within the hour), where
  design/plan/kata live, trust root paragraph kept. No fleet host names
  (grep the brief's host-name pattern over the diff).
- [ ] `ops/vm/README.md`: if it lists the exporter's files, add index.html.

## Verification

- `scripts/test-gate.sh` (whole suite) on the final head and again after any
  rebase.
- Host-name grep over `git diff origin/main...HEAD`.

## Rollback

Revert the branch's commits on main, then the coordinator updates the VM
checkout (the unit runs the checkout's script and never fetches). A reverted
exporter no longer writes index.html, so the last page would stay frozen with
stale advice: the coordinator removes `index.html` from the mirror directory
in the same step. Both are live-state steps outside this repo.

## Review amendments (spec+plan pass 1)

- Threads come from feed.json and critical.json together (the CLI pulls both),
  after the reader's 400-day whole-thread retention (`pull._retain`), with
  events past `schema.MAX_TIMESTAMP` left out.
- `export` refuses a `--mirror-url` that is not https with a host, or carries
  a quote, angle bracket, backslash or space; nothing is written.
- Added tests: cross-channel retraction, manifest `retracted` list, curator
  level change, aged-out thread, far-future advisory, rejected mirror URLs,
  a quoted source URL parsed back out of the `href` attribute.

## Directive c:yjb4ze amendments

- `clean(rows, m)`: `mf.role_of(m, pubkey) is None` → `not_poster`; summary
  line prints it. Tests: `test_only_current_manifest_posters_reach_the_mirror`
  (non-manifest reply, revoked poster's root, manifest root; checked across all
  four public files), the two existing tests that expected a stranger's event
  in feed.json updated.
- Atom `<subtitle>` (`ATOM_SUBTITLE`); page subscribe block: no-account list
  (Atom, feed.json, CLI, repo) and a members-only sentence for the channels.
  Tests: `test_atom_subtitle_points_agents_at_the_cli`,
  `test_index_says_channels_are_for_members`.
- README Status: members-only channels, public mirror.
