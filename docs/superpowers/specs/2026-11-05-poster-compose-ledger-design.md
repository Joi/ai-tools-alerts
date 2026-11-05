# B3: post composition and the advisory ledger (ai-tools-alerts#h2gf)

## Problem

The poster (B4, kfq6) needs two pieces it does not have: text to send, and a
record of what it already sent. The text leaves the fleet, so it must carry
only advisory, products, actions and sources, never host names, observed
versions or evidence paths (design, "nothing private leaves the fleet"). The
record stops a candidate seen twice, or a send whose outcome is unknown, from
interrupting members twice.

Contract inputs, from the issue comments:

- B1 (c:nkybkg, c:hhhxn9): `advisory_severity` and `product_text` are rule
  inputs, never post text; a version number in either can be a locally
  observed one. The product line comes from the matched ScopeEntry's display
  name. `exploited` is set only by the KEV adapter; the alias merge carries it
  to another candidate only when both resolve to the same ScopeEntry.
- A2 (c:cdny2a): `schema.render_post` takes a full Advisory and checks that the
  output parses back. A reply carrying only changed fields needs a patch
  contract that A2 does not define.
- B2 (c:ghcgfr): `level_for` returns `(level, reason)`; for reason
  `unverified` the body must carry the word "unverified". `scope_of(..., log)`
  appends unmatched tier-1 vendor text to a caller list, which the ledger keeps
  for review.

## Success criteria

1. `python3 -c "from aitools_alerts.poster import compose, ledger"` exits 0.
2. `scripts/test-gate.sh` passes, B1's and B2's poster tests included.
3. The six plan tests exist and pass: `test_root_post_body_has_four_lines_and_block`,
   `test_body_never_contains_host_names`, `test_reply_only_carries_changed_fields`,
   `test_digest_lists_every_item_once`, `test_ledger_alias_merge`,
   `test_pending_blocks_resend`.
4. The host-name test asserts against a denylist held in the test: invented
   names (`host-alpha`) plus a regular expression shaped like a fleet name,
   never a real fleet name.
5. Standard library only. Code and tests near 600 changed lines; the
   review-required fixes took it to about 880, kept as one landing (decided on
   the issue).

## Approach

### compose.py

`root_post(c, level, scope, *, posted_at=None) -> (str, Advisory)`.
`level` is what `rules.level_for` returns, `(level, reason)`; a bare level
string is accepted with reason `None`.

The Advisory is built from fields that are safe to publish:

| field | value |
|---|---|
| id | `c.id` (must match the schema id pattern, else ValueError) |
| aliases | `c.aliases` that match the id pattern, without `c.id`, deduplicated, at most 50 |
| level | the level |
| advisory_severity | `None`: a rule input, never published |
| title | `"<scope.name>: <kind> (<c.id>)"`, kind from the candidate's flags: known exploited vulnerability / trojanized release / injection to code execution / security advisory |
| products | one Product: `scope.name`, `scope.ecosystem`, affected and fixed converted to the schema grammar (below) |
| actions | `upgrade <scope.name> <fixed>` when a fixed version is known, else none |
| sources | the candidate's https sources that the schema accepts, primary sources first, at most 20; none left is a ValueError |
| posted_by | `relay-bot` |
| posted_at | `posted_at` or `int(time.time())` |
| expires_at | `None` |

Version conversion. `fixed`: an optional leading `v` is dropped and the rest
must match the schema's fixed grammar, else `None`. `affected`: the candidate's
range is split on commas and spaces; every token must be an operator from
`< <= > >= =` and a schema version, joined by commas, at most four; `||`, `!=`,
`~`, `^` or a bare version give `None` (the post says "versions not stated"
rather than guess).

The body is four lines, then `schema.render_post` appends the block:

1. `<LEVEL>: <title>`; when the reason is `unverified`, `HIGH (unverified: no primary source confirmed it): <title>`.
2. `Affected: <scope.name> <range in words>. Fixed in <fixed>.` or `... No fixed version is known yet.`
3. `Action: upgrade <scope.name> to <fixed> or later.` or `Action: no fix is published yet; watch this thread.`
   (the verb's plain words from `spec/actions.json`'s vocabulary).
4. `Source: <primary source URL>` (the first source on the primary-domain list, else the first source).

Defence in depth: every composed post is checked against
`candidates.FLEET_HOSTS` and the local host name (`socket.gethostname()`, its
first label too) and raises ValueError on a hit. Nothing is ever read from
`product_text`, `advisory_severity`, `local_level_hint` or `observed_at`.

`reply_post(prev, c, changes) -> str`. Patch contract (A5's rule, written down
here because A5 has not landed):

- The reply's fenced `aitools-alert` block is a JSON object holding only the
  changed fields. A key omitted is unchanged; a key present with `null` clears
  that field (only nullable fields: `advisory_severity`, `expires_at`; a
  non-nullable field set to null is invalid).
- Allowed keys: every Advisory field except `id` and `posted_by` (the thread
  root identifies the advisory; the manifest sets the role). An unknown key is
  invalid.
- Each field is validated, and the merged advisory (`prev` with the patch
  applied) must pass `schema.validate`; otherwise the patch is invalid and the
  reply changes nothing.
- `compose.apply_patch(prev, patch) -> Advisory` implements exactly this on a
  decoded object, and `compose.parse_reply(content, prev) -> Advisory | None`
  is the wire reader A5 should match: the last `aitools-alert` block (same
  fence rules and size cap as `schema`), JSON decoded with duplicate keys and
  NaN/Infinity refused, then `apply_patch`; anything invalid is None.

`reply_post(prev, c, changes, *, reason=None)` drops keys whose value equals
`prev`'s, refuses an empty patch, caps aliases at 50 and sources at 20 (the
ledger keeps every id), and, when products change without actions, sets the
upgrade action to the new fixed version. The merged advisory must also pass
the relay-bot publication rules, the same ones `root_post` follows: keys only
from level, title, products, actions, aliases, sources, expires_at (and
advisory_severity only to clear it); one product with the scope entry's name
and ecosystem; a title of the template form; the only action is upgrade to
`products[0].fixed`. With reason `unverified` the first line says
"Unverified: no primary source confirmed it." Then one templated line per
changed field, a source line from `c` (primary first), the block. It checks
its own output through `parse_reply`. The root's id is never patched: B4
keeps the stored root's id and passes a newly seen id as an alias.

The host-name guard also refuses a local path or kata ref anywhere in the
post (the candidate adapters' private-detail pattern).

`digest(advs_today, date) -> str`. One line `Daily digest for <date>: N
advisories.`, then sections Critical, High, Notice in that order (empty ones
omitted), each advisory once (deduplicated by id; the latest `posted_at`
wins), each line `- <title>. <fixed words>. <primary source>`. No block: a
digest is a list, not an advisory. With none: `Daily digest for <date>: no
advisories.` The same host-name check applies.

### ledger.py

`Ledger(path=~/.local/state/aitools-alerts-poster/ledger.json)` is a context
manager. Entering takes an exclusive non-blocking `fcntl.flock` on
`<path>.lock` (a second run is refused with LedgerError) and loads the file;
a missing file is an empty ledger, a malformed one is LedgerError (never send
without dedup). Every mutation writes the whole file atomically
(`tempfile.mkstemp` in the same directory, mode 0600, fsync, `os.replace`,
then fsync of the directory; any failure is LedgerError, so no send follows).
Methods called outside the context raise LedgerError.

File: `{"schema_version": 1, "entries": [...], "pending": [...], "expired": [...], "review": [...]}`.

`Entry(root_event_id, channel_ids, level, aliases, posted_at, last_change,
scope, exploited, advisory, replies)`. `channel_ids` maps channel name to the
event id there; `advisory` is the last full advisory as a dict, so B4 can
compose a reply.

- `lookup(aliases, scope=None) -> Entry | None`: the oldest entry sharing any
  id (case-insensitive); with `scope`, only entries for that scope name.
- `record_root(adv, root_event_id, channel_ids, scope, exploited, now)`:
  refuses when `lookup` already finds an entry for the same scope (that is a
  reply).
- `record_reply(root_event_id, adv, reply_ids, now, exploited=False)`: updates
  the entry's level, aliases (union), advisory, `last_change`, appends the
  reply ids; `exploited` only ever turns on.
- `pending(key, aliases, now)`: refuses (LedgerError) when an open pending
  entry has the same key or shares an alias; otherwise writes the entry to
  disk before returning, so B4 sends only after it returns.
- `clear_pending(key)`: removes it after a known outcome.
- `expire_pending(key, reason, now)`: only when the entry is at least 24 h
  old and the reason is non-empty; moves it to `expired` with the reason and
  logs a warning.
- `add_review(texts, now)`: B2's `log` entries, stripped of control
  characters, capped at 300 characters, deduplicated by text (`first_seen`,
  `last_seen`, `count`), at most 500 kept. This list stays on the fleet.

`merge(pairs, ledger=None) -> list[(Candidate, ScopeEntry)]`: candidates
are grouped first by scope name, then by shared id or alias within that
scope (union-find). Each group becomes one candidate: the first member's id,
and every other member's id and every alias as aliases, `exploited`/`trojanized`/`injection_exec` true when any member's is,
the first non-null `fixed` and `affected`, sources unioned. When a ledger is
given, an entry for the same scope sharing an alias also carries its
`exploited`. A candidate under another scope never inherits `exploited`, even
when it names the KEV CVE as an alias.

## Alternatives considered

- Put the patch reader in `schema.py`: A5 runs in parallel and may touch it;
  `compose.apply_patch` keeps this branch off shared files. A5 can import it
  or match it.
- Lock per call instead of per run: lookup then record would race between two
  runs; the whole run holds the lock, as security_route.py does.
- Publish `advisory_severity` in the block: B1 forbids it; the field stays
  null in relay-bot posts.
- Group candidates by alias across scopes: that is how a model-written finding
  listing a KEV CVE would inherit the KEV clause (B1 second note).

## Review decisions (spec+plan pass)

- Expiry after 24 h re-opens a resend. Kept: the brief prescribes it ("blocks
  a resend until cleared or explicitly expired after 24 h with a logged
  reason"). Expiry is the operator's reconciliation step; the reason and the
  `expired` record are its audit trail.
- Scope display names as product identity (Docker vs containerd/runc,
  aggregate MCP name). Kept: B1's note c:hhhxn9 sets the product line from the
  matched scope entry's display name. A per-component identity is a scope.json
  change, filed as a follow-up.
- `changes()` dropped: its id and union semantics were the source of two
  findings; `reply_post` already drops unchanged keys, and B4 owns the diff.

## Blast radius and rollback

New files only; nothing calls them until B4. Rollback is a revert of the
branch commits.

## Assumes

- B4 calls `pending` before each send and `clear_pending` after a known
  outcome; an unknown outcome is left pending.
- The digest hour and which advisories count as "today" are B4's.
