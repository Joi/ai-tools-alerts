# Launch readiness: kind-9 mirror, /alerts/ index page, README status (ai-tools-alerts#hgs0)

## Problem

Joi announces the service on a podcast that airs 2026-11-10. Three things a
listener meets today are broken:

1. `feed.atom` carries "(untitled)" entries with empty content. They are
   NIP-29 admin events (kinds 9000, 9001, 9005, 9007, and in feed.json also
   39000-39002 and 40099) signed by the relay-bot key: they have no e tag and
   a manifest pubkey, so `atom_doc` takes them for roots.
2. `https://buzz.ai-tools.md/alerts/` is a 404: nothing writes `index.html`.
3. README "Status" says the poster and the mirror are still being built.

## Success criteria

- feed.json, critical.json and feed.atom carry only kind 9 events; every other
  kind that verifies is dropped and counted (`other_kind=` in the summary line).
- No Atom entry has the title "(untitled)": a root with no non-blank line is
  not an entry.
- A fixture of kinds 9000/9001/9005/9007/39000/39001/39002/40099 signed by a
  manifest key, mixed with real kind 9 posts, exports to files that
  `aitools_alerts.pull.fetch` accepts (no error) and that
  `pull.advisories` reads to the same threads as the kind 9 rows alone.
- `export` writes `index.html` into --out (atomic, 0644, like the others):
  UTF-8, no `<script>`, no event-handler attributes, three `<section>`s:
  about (two sentences), latest advisories, subscribe.
- Advisories list: newest first, at most 20, one row each with level, title
  ("Retracted: " prefix for a retracted thread), date (UTC, YYYY-MM-DD of the
  root), primary source link (the first primary source, else the first source,
  marked "not a primary source"). Built with `pull.advisories` over both
  channels' events together (as the CLI pulls them), after the reader's
  400-day whole-thread retention, so the page shows what the CLI would trust
  (curator level changes, patches, retractions, the manifest's retracted
  list). Every accepted event takes part in the threads; only a root dated past `schema.MAX_TIMESTAMP` is left off (code review pass 1: filtering replies first missed a retraction the CLI applies). The CLI's
  size limits (8 MiB per file, 10,000 events) are not mirrored: past them the
  CLI refuses the whole mirror, which the page cannot express.
- `--mirror-url` must be https with a host and no quote, angle bracket,
  backslash or space; otherwise the export refuses and writes nothing.
  Synthetic advisories (`schema.is_synthetic`) are left off the page. With none
  left: "No advisories yet."
- Subscribe block: the Atom URL (`--mirror-url` + feed.atom), the pipx install
  line (the same string as the README; a test asserts the README contains it),
  the channel names `#security-feed` and `#security-critical` on
  buzz.ai-tools.md (from the keys of spec/channels.json), and
  https://github.com/Joi/ai-tools-alerts.
- All text in the page goes through `html.escape` after `_xml_safe`; hrefs are
  the schema-validated https URLs, escaped with quote=True.
- README "Status" describes the live state: hourly poster on the fleet, mirror
  every 5 minutes, digest daily at 09:00 Tokyo, critical posts within the hour.
  No fleet host names. The member install section stays.
- `scripts/test-gate.sh` passes.

## Approach

- `clean()`: after the signature check, a row whose `kind != 9` is counted
  `other_kind` and dropped. One place, so all three outputs and index.html
  follow. `summary_line` prints `other_kind=`.
- `atom_doc`: skip a root whose content has no non-blank line (the only way
  `_first_line` returns "(untitled)"); `_first_line` no longer returns that
  string.
- `index_doc(events_by_channel, m, channels, now, mirror_url) -> (bytes, count)`: builds
  an in-memory `state.State` with the export's manifest and events under the
  exporter's trust root and calls `pull.advisories`. Write order becomes
  manifest.json, critical.json, feed.json, index.html, feed.atom.
- Page structure: `<!DOCTYPE html>`, `<html lang="en">`, `<meta charset="utf-8">`,
  viewport meta, a small inline `<style>`, `<main>` with one `<section>` per
  block and an id on each (`about`, `advisories`, `subscribe`) so the Japanese
  section of ai-tools-alerts#yxd6 lands as one more `<section>`.

## Alternatives considered

- Filter only in `atom_doc`: the brief requires the filter in every output, and
  the JSON files carrying admin events is what the CLI ignores anyway; one
  filter in `clean` is simpler and covers index.html.
- Reimplement thread logic for the page: it would drift from the CLI.
  `pull.advisories` is the reader's own rule.
- Template file under templates/: one more file to ship to the VM; the
  exporter must stay a single checkout-run script. Inline string builder.

## Blast radius / rollback

The VM runs the exporter every 5 minutes from a checkout at bda19ae; this
change reaches it only when the coordinator updates that checkout. A bad
index.html is a static page; rollback is reverting the commit, updating the VM
checkout, and removing index.html from the mirror directory (a reverted
exporter does not write it, so it would otherwise stay frozen). Those last two
are the coordinator's live-state steps. Dropping non-kind-9 rows changes feed.json: the CLI never
read those kinds as advisories (kind 5/9005 are ignored, the rest have no
advisory block), so no member-visible change beyond the Atom fix.

Assumes: kind 9 is the only kind the poster and curators post (NIP-29 group
chat message), as the live channel shows.

## Open questions

None.

## Directive c:yjb4ze (2026-11-06), applied before the code review

The relay is members-only and the mirror is its only public surface.

- `clean(rows, m)` also drops a kind 9 event whose pubkey is not a poster in
  the current manifest (counted `not_poster`): a member's discussion reply and
  every post by a revoked poster (a key the manifest no longer lists) stay off
  feed.json, critical.json, the Atom and the page.
- index.html and README Status say the two Buzz channels are for ai-tools
  community members (relay reads need an auth token); the public gets the Atom
  feed, feed.json and the CLI, none of which needs an account. No join link,
  no intake instructions.
- The Atom feed has a `<subtitle>`: for humans and feed readers; agents use the
  CLI, which verifies signatures.

An advisory whose `expires_at` has passed (the CLI's `pull.active` hides it from `check`) is listed with "Expired: ".

## Directive c:bv22zx (2026-11-06), after the code review

Each channel file keeps its newest events within half of the CLI's limits
(`MAX_CHANNEL_EVENTS = 2000`, `MAX_CHANNEL_BYTES = 4 MiB` as the written
file), in their original query order. `cap()` keeps whole threads (a root and
every reply marked to it, in either channel) across both channels together,
newest thread first, so a kept root never loses a retraction or patch posted
in the other channel; a thread that does not fit is skipped and the next older
one tried, so one oversized event costs only its own thread (fresheyes on the
first cap commit); the dropped count is `capped=` in the
summary line. The Atom and the page are built from the capped events, so they
show what the CLI can read. No single poster can make the mirror unreadable.
