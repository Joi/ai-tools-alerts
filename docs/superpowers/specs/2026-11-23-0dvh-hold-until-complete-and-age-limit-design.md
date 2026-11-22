# Poster: hold a high until its fix is read, 7-day age limit, range and severity in the block, public ids only

Issue: ai-tools-alerts#0dvh, slice 3 of the v2 design (ai-tools-alerts#9mx8, first comment, section 5 "One post per action, and only when complete"). Builds on slice 1 (ai-tools-alerts#8ke5, landed at ba911f2). Folds ai-tools-alerts#6e20.

## Problem

The live feed shows three faults this slice removes.

1. **Posts before the facts.** On 2026-11-18 at 10:20Z three mcp-server-git advisories posted as roots saying "The source does not state a fixed version; check the vendor's advisory." An hour later the collector read the fix (2026.11.18) and the poster sent three replies, plus two more roots with the fix. On 2026-11-07, 16 roots at 02:20Z said "no fix" and 10 of them were corrected by replies at 04:20Z.
2. **Back-fill storms.** Every one of the 17 roots of 2026-11-07 (02:20Z and 04:20Z) names a primary source published between 2026-03-26 and 2026-10-26: 12 to 226 days before the poster first saw it. A newly added source produced a burst of real-time posts about old advisories.
3. **Internal ids in public text.** Every collector root's title and headline carries the ledger key, e.g. `Claude Code: security advisory (CVE-2026-103435:claude-code)`. The block's `advisory_severity` is null on every post, and `compose._publishable` refuses a reply that would set it.
4. **6e20.** The mirror page lists the OpenSSH critical (CVE-2026-123158) on two rows. The issue guessed an alias update; the live feed shows the real cause: a critical posts a root in `#security-feed` (f7dd5ed6) and a copy in `#security-critical` (1106d821). Each copy is its own root event, `pull.threads_from` makes a thread of each, and `export_mirror.index_doc` lists every thread.

## Success criteria

- **S1 hold.** A new high candidate that is not exploited and has neither a fixed version nor an affected range does not post on first sight. Each run re-evaluates it; it posts as soon as a fix or range is read, or when six hours have passed since first sight, with what is known then. A critical never waits. First sight is kept in the state file, so a restart neither resets nor loses the hold.
- **S2 age limit.** A new candidate whose primary source was published more than seven days before the poster first saw it never posts a real-time root, at any level. It is held for the digest at level notice, so the digest lists it in the Notice section. A later sighting that brings a fix updates the held notice, so the digest prints the fix.
- **S3 block.** `products[0].affected` is carried into the block whenever the candidate's range is expressible (unchanged behaviour, now tested from a collector fixture). `advisory_severity` is carried into the block when the candidate's value is one of `critical`, `high`, `medium`, `moderate`, `low` (case-folded); any other value stays null. `compose._publishable` no longer refuses a reply that sets it. "versions not stated" prints only when the candidate has no range at all; a range the schema cannot express prints "affected versions: see the source".
- **S4 public ids.** A new root's title and headline name the public id: `(CVE-2026-103435)`, never `(CVE-2026-103435:claude-code)`. The block's `id` stays the ledger key (the thread identity readers and the ledger match on). Aliases already exclude ledger keys (8ke5). Template-title checks (`_titles`, `_exploited`, `_ja_title`, `_group_key`) accept both forms, so threads posted before this change keep working.
- **S5 6e20.** The mirror page lists one row per advisory: the critical's feed root and its critical-channel copy are one row.
- **Acceptance replays** (tests/poster): replaying 2026-11-07 (17 roots, fixes two hours later) posts zero real-time roots; replaying 2026-11-18 (three roots at 10:20Z, fixes at 11:20Z, two more at 11:20Z) posts five roots, each once, each with `Fixed in 2026.11.18`, no reply, and no "check the vendor" text. Every post still parses with `schema.parse_post` / `compose.parse_reply` (v0.1.4 readers' parser), and each thread's id is its root event id.
- `scripts/test-gate.sh` green. Under 600 changed lines.
- Existing tests migrated: `test_live_replay.test_live_feed_replay` (its CVE-2026-88968 root is now aged: it is listed in the 11-08 digest's Notice section with its fix, and posts no root and no reply); `test_main` tests that index an immediate high root from a finding with neither fix nor range (`test_root_and_digest_carry_the_source_title`, `test_a_title_learned_later_posts_nothing_and_reaches_the_digest`, `test_a_fence_in_the_title_never_withholds_the_advisory`, `test_a_level_rise_copy_gets_the_exploited_flag`, `test_a_change_in_the_digest_run_is_listed_that_day_only`) give the finding a range. New focused tests: hold across a restart, the six-hour boundary, the waiting cap, field-preserving notice update, merged severity, legacy titles, mirror copies.

## Approach

### Hold (main.py, inputs.py)

- New state key `waiting`: `{"<scope>|<primary id casefold>": first_seen_epoch}`, one key per held candidate. `inputs.load_state` adds `{}` to a state written before it (as it does for `withheld` and `digest_ids`) and validates it (string keys, int values, at most `MAX_WAITING` = 2000 entries). The writer never exceeds the cap: when the map is full, a new candidate is not held and posts at once (the fail-open direction: a post without its fix, as today). The validator cap equals the writer cap, so the writer cannot produce a state its next run refuses.
- `Run.first_seen(scope, ids)`: the smallest time recorded under any of the candidate's ids, in `waiting` or as the `posted_at` of a held notice (root_post stamps a held notice with the run that held it), else `now`. So a notice first seen at six days that becomes high with a fix two days later is judged at six days, not eight.
- In `Run.plan_new`, before composing a high root: when `level == "high"`, `c.exploited is not True`, `c.fixed` and `c.affected` are both empty, and `now - first_seen < 6 h`, record first sight under every id, defer the candidate (`Run.defer`), count `waiting`, and plan nothing. The deferred candidate comes back next run through `state["deferred"]`, merged with any fresh sighting (fresh first, so the fresh fix wins, as `ledger.merge` already does).
- Exploited highs (KEV entries) do not wait: KEV never carries versions, so a hold only delays an exploited flaw by six hours.
- After planning, `waiting` keeps only keys of candidates still deferred, so a posted or dropped candidate leaves it; the map never grows past the deferred list.

### Age limit (main.py)

- `_published(c)`: the `published_at` of the first primary source among `compose._sources(c.sources)` (primary first), parsed as a date or timestamp; None when absent or unparsable.
- In `Run.plan_new`, for every level: when `_published(c)` is not None and `first_seen - published > 7 days`, compose at level notice and `hold()` it for the digest; count `aged`. No real-time root, no copy.
- `Run.hold`: when a held notice is seen again, field by field: a fixed version or a range the held copy lacks is taken from the new sighting; a field the new sighting omits keeps the held value; the upgrade action follows the resulting fixed version. A value the held copy already has is never replaced by a missing one; a different non-empty value replaces it (a correction).
- The published date also falls back to the held notice's primary source when the new sighting's primary source carries none, so a re-sighting with an undated source cannot take the real-time path while the notice is held. After the digest lists it, only its ids remain (`digested`); a later sighting with an undated source can then post. Accepted: the digest runs daily, and such a sighting has no date to judge.
- Not changed: the backfill floor (`observed_at < state["since"]`, fixed when the state is created) still drops candidates observed before the poster's first run. It is a separate, earlier rule; this slice judges what passes it.

### Block and wording (compose.py)

- `severity(v)`: `ledger.merge` joins differing members' words with `"; "` (the rules read all of them). The block carries the highest-ranked word of the joined value that is in `SEVERITIES` (critical > high > medium = moderate > low), else null; the joined text stays in the candidate for the rules.
- `root_post`: `advisory_severity=severity(c.advisory_severity)`; title `f"{scope.name}: {kind} ({public_form(c.id)})"`.
- `public_form(id)`: the id before the `:` of a ledger key, else the id.
- `_titles(name, adv_id)` returns the templates for both `adv_id` and `public_form(adv_id)`; `_exploited`, `_ja_title`, `_group_key` match both.
- `_publishable`: the refusal of any `advisory_severity` becomes a refusal of any value outside `SEVERITIES` (null still allowed), so a patch like `"seen at 2.0.77"` still raises.
- `plan_known`: a severity change alone posts no reply (design: reply only when the instruction changes); when a reply goes out for another reason and the severity differs, the patch carries it. `_change_line` / `_change_line_ja` say "Upstream severity: X." / "上流の深刻度: X。" (cleared keeps its line).
- `_words`: "versions not stated" only when the candidate has no range; a candidate range the schema cannot express gives ", affected versions: see the source" (`root_post` passes the raw value through a flag, as `fix_unexpressed` does for the fix).

### Mirror (export_mirror.py)

- `index_doc`: group threads by `(adv.id casefold, products[0].name)`. One row per group: the copy most recently changed (`Thread.updated_at`, ties to the newer root), so a curator's later amendment to either copy is what the row shows; the row reads Retracted when any copy is retracted; the row's date is the earliest root's.

## Alternatives considered

- **Hold in the ledger instead of the run state.** The ledger records what was posted; a candidate not yet posted has no thread. The state file already carries deferred candidates across runs, so the hold lives beside them.
- **Hold exploited highs too.** Rejected: KEV entries never gain a version, so they would always wait the full six hours.
- **Age limit only for high.** Rejected: the issue says "never posts a real-time root" without a level; a critical that old is already in the catalog.
- **Rewrite the block id to the public id.** Rejected: readers at v0.1.4 and the ledger match threads by the block id; changing it would split existing threads. The issue keeps the ledger key internal and this slice only removes it from public text.
- **Dedupe threads in `pull.threads_from` (6e20).** Rejected: the CLI counts each channel's root separately on purpose (a member may subscribe to one channel); the duplicate is a presentation fault of the page.

## Blast radius and rollback

- The poster on one Mac (uv tool install). A malformed `waiting` key fails state load as LedgerError, which sends nothing: the safe failure.
- State migration is additive. Rollback: revert on main, reinstall; the older poster refuses a state with the extra `waiting` key, so remove that key from the state file (one `jq 'del(.waiting)'`) before the first run of the old version.
- Readers: block keys unchanged; `advisory_severity` was already a nullable string in the schema.

## Assumes

- The collector (amplifier-bundle-joi#pww7, open) will put the range in `affected`, the fix in `fixed` and the severity word in `advisory_severity` of each finding. Until it lands, tests use fixtures that carry them.
- The OpenSSH root's two copies are the only source of 6e20's double row; no other duplicate case is in the live page.
