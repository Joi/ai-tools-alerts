# Poster: no leads in the digest, no source-only replies, one digest listing per advisory (8ke5)

Slice 1 of the v2 design (kata ai-tools-alerts#9mx8, first comment: "Redundancy",
"5. One post per action", "Do now" items 2 and 3). Approved by Joi on 2026-11-23.

## Problem

Measured on the live feed from 2026-11-05 to 11-22:

- 47% of digest lines are unverified leads (`- OpenSSH: 8 unrated leads.`, single
  `LEAD-...` lines whose only source is a Mastodon post). A member cannot act on any
  of them.
- 7 of 20 change replies say only "New sources listed." The OpenSSH thread
  CVE-2026-123158 received four such replies in two days, in both channels.
- One reply said "Also known as: CVE-2026-123158:openssh.": a ledger key published
  as an alias.
- The digest re-lists an advisory every day its thread receives any reply.
  CVE-2026-88968 (Claude Code) posted on 11-07 with its fix two hours later, and
  appeared again in the 11-10 and 11-11 digests: on 11-10 because of a source-only
  reply in the same run, on 11-11 because that reply's time equalled the 11-10
  digest's cutoff and the digest recorded no roots for that cutoff.

## Success criteria

1. `compose.digest` prints no line for an advisory whose id starts with `LEAD-`, or
   that has no primary source (`schema.is_primary` false for every source), in
   English and Japanese. No "N unrated leads" line exists. Such advisories are not
   counted in the head line's N. A held notice left out this way leaves the held list
   but is never marked digested, so a later sighting with a primary source is held
   again and listed; one confirmed while still held replaces its held snapshot.
2. `Run.plan_known` plans no reply when the only changed keys are `sources` and/or
   `aliases`, unless the candidate makes the thread newly exploited (KEV learned at
   the same level: design section 5 replies when "exploitation is confirmed", and
   4yr1's urgent Japanese action depends on it). Copies to a new channel are unaffected. The ledger keeps what was
   learned: ids by `add_ids` (as now) and sources in a new optional entry field
   `learned_sources`; the next reply with a real change carries both.
3. A digest lists a ledger advisory on the day it first posted, and again only on a
   day when a reply changed its level, fixed version or action list. A ledger entry
   gets an optional `listed_at` (the root's time, then the time of the last such
   reply); `entries_since` and the digest cutoff use it, falling back to
   `last_change` for entries written before this change. The digest's cutoff
   records the roots at the cutoff in every case, including when every item fit.
4. No alias of the form `<CVE or GHSA id>:<anything>` is published: not in a root
   post's block, not in a reply's `aliases` patch, not on an "Also known as:" line.
   An alias already published stays in the block's `aliases` list, because a
   reply's list replaces the reader's whole and a reply never removes an alias;
   the "Also known as:" line (English and Japanese) prints only the publishable
   aliases, so a key already in a contaminated thread is never shown again.
5. Acceptance (from the issue): a replay test built from events copied out of the
   live feed into `tests/fixtures/poster/`: the OpenSSH thread CVE-2026-123158 gets
   zero source-only replies; the CVE-2026-88968 fix reply still posts; the digests
   for 2026-11-10 and 2026-11-11 rebuilt under the new code hold no lead line and do
   not re-list CVE-2026-88968. `scripts/test-gate.sh` green.
6. Existing tests that assert the old behaviour are rewritten to the new rule, each
   keeping what it was there to cover: the lead and non-primary lines in
   `test_digest_groups_releases_and_leads` and `test_digest_ja_scaffold_and_groups`
   use primary sources or assert absence; tests that relied on an alias/source-only
   reply (`test_duplicate_alias_becomes_reply`, the alias-cap and stop-after-ids tests,
   and any Japanese retry or backlog test that does) get a fixed-version change so a
   real reply still exercises the path they test.

## Approach

- `compose.py`
  - `digest`: drop `LEAD-` ids and advisories with no primary source in the same
    filter that drops synthetic, retracted and expired ones.
  - Remove the lead group (`_group_key` "lead" branch, `_group_line` lead branch,
    the `leads` template strings): unreachable after the filter.
  - `_LEDGER_KEY = re.compile(r"(?:CVE-\d{4}-\d{4,}|GHSA(?:-[0-9a-z]{4}){3}):", re.I)`;
    `_ids` skips a match. `reply_post`'s alias union keeps every already-published
    alias and appends only new publishable ids, so a reply never drops one.
- `ledger.py`
  - `Entry` gains `listed_at: int | None = None` and `learned_sources: list | None = None`
    (optional, so ledgers on disk load; `_entry_ok` checks their types).
  - `Entry.listed` property: `listed_at` if set, else `last_change`.
  - `record_root` sets `listed_at=now`. `record_reply` sets `listed_at=now` when the
    level, `products[0].fixed` or `actions` differ from the stored advisory; otherwise
    it first writes `listed_at = e.get("listed_at", e["last_change"])`, so a legacy
    entry's effective listing time never moves with a range-only reply. It drops from
    `learned_sources` any url now in the advisory.
  - `learn_sources(root, sources)` appends unseen urls (capped at 20, the schema's
    source cap).
  - `entries_since` filters and sorts by `listed`.
- `main.py`
  - `plan_known`: candidate aliases to publish come from the candidate's ids and the
    entry's stored ids, filtered for publication; sources from the entry's
    `learned_sources` and the candidate's. If the changed keys are a subset of
    `{aliases, sources}` and the candidate is not newly exploited, record the
    publishable sources with `learn_sources` and plan no reply.
  - `hold`: an overlapping held notice with no primary source takes the new snapshot
    when that one has one. `digest`: a held notice `compose.listable` refuses leaves
    `held` without entering `digested`.
  - `digest`: use `e.listed` where it used `e.last_change`; when every ledger item
    fit, `roots` holds the roots whose `listed` equals the cutoff.

## Alternatives considered

- Update the stored advisory silently on a source-only change. Rejected: members'
  readers only learn state through replies, so the ledger and every reader would
  disagree, and the next real reply's patch would omit what the reader never got.
- Stop holding leads at all in `plan_new`. Rejected for this slice: the hold also
  dedups, and a held lead is acknowledged by the next digest anyway; the filter in
  `compose.digest` is the one place every digest passes, both languages.
- Track "digest-worthy" changes in the state file instead of the ledger. Rejected:
  the ledger already holds per-thread change times and is the digest's source.

## Blast radius and rollback

Poster only (the poster host, hourly). Readers (v0.1.4 on member machines) see fewer posts,
never a new block shape: no required key changes, reply patches stay the same
contract. Ledger entries gain two optional keys; an older poster would refuse a
ledger with them (`Entry(**e)` TypeError). Rollback, on the poster host, between
hourly runs (the run holds `ledger.json.lock`): revert the commits on main in the
primary checkout and pull; remove `listed_at` and `learned_sources` from every entry
of the CURRENT `ledger.json` (never restore an older copy: it would forget threads
and replies already posted and the next run would post them again); then
`uv tool install --force --reinstall <primary checkout path>`.

Assumes: a range-only correction (affected changes, fixed does not) still posts a
reply but does not re-list the advisory in the digest, as the issue's item 3 says.

## Open questions

None blocking.
