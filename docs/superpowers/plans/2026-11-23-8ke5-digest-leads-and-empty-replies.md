# Plan: 8ke5 digest leads and empty replies

Spec: `docs/superpowers/specs/2026-11-23-8ke5-digest-leads-and-empty-replies-design.md`.
Verification for every chunk: `python3 -m pytest -q tests/poster` (fast); the whole
gate `scripts/test-gate.sh` once at the end (public scan, then the full suite; it
needs `/opt/homebrew/bin/bash` 5 for the guard tests).

## Chunk 1: compose (no lead lines, no ledger-key aliases)

Files: `aitools_alerts/poster/compose.py`, `tests/poster/test_compose.py`.

- [ ] `digest()` (compose.py, the `latest = {...}` filter): also drop `a.id.startswith("LEAD-")`
      and `not any(schema.is_primary(s.url) for s in a.sources)`. Docstring: say so.
- [ ] Remove the lead branch of `_group_key` (the `LEAD-` lines), the `key[0] == "lead"`
      branch of `_group_line`, and the `leads=` entries of both `_DIGEST` templates.
- [ ] Add `_LEDGER_KEY` regex and `_public_id(a)`; `_ids` skips a ledger key.
- [ ] `reply_post`: for `aliases`, `v = old["aliases"] + [new publishable ids not already
      in old, case-folded]`, capped at 50, so an alias already published is never removed.
- [ ] `_change_line` and `_change_line_ja` "aliases": print only `_public_id` aliases (a
      contaminated thread's key stays in the JSON list, never on the line).
- [ ] Tests: replace `test_compose.py` lead-group assertions (the "12 unrated leads"
      test near line 264 and the high-lead test near line 298) with: a LEAD notice and a
      LEAD high get no line in either language and are not counted; an advisory with
      only a Mastodon source gets no line; `test_digest_groups_releases_and_leads` and
      `test_digest_ja_scaffold_and_groups` and the whole of
      `test_digest_groups_keep_marks_and_kinds_apart` (its release, synthetic, unverified,
      KEV and publication-guard parts) rewritten on primary-source fixtures
      (`support.apple.com`, `ubuntu.com` paths the allowlist takes) so their grouping
      coverage stays, with leads/non-primary asserted absent. With every listed advisory
      now holding a primary source, a group line's URL is always primary: "see the
      release" becomes unreachable and is removed from `_group_line` and both templates,
      and the tests expect "update available"; a root post's
      block drops `CVE-2026-123158:openssh` from aliases; a reply patch never adds it,
      keeps an already-published one in the JSON list, and leaves it off both "Also known
      as" lines.

Acceptance: the new tests pass; every other compose test unchanged and green.

## Chunk 2: ledger and planner (no source/alias-only replies; list once)

Files: `aitools_alerts/poster/ledger.py`, `aitools_alerts/poster/main.py`,
`tests/poster/test_ledger.py`, `tests/poster/test_main.py`.

- [ ] `Entry`: `listed_at: int | None = None`, `learned_sources: list | None = None`;
      `listed` property. `_entry_ok`: `listed_at` None or int; `learned_sources` None or a
      list of dicts with a str `url`.
- [ ] `record_root`: `listed_at=now`. `record_reply`: `listed_at=now` when level,
      `products[0].fixed` or `actions` changed against the stored advisory, else
      `listed_at = <the entry's effective listing time>` BEFORE `last_change` moves (a
      legacy entry's listing time is frozen). `listed_at` is never stored as null: the
      validator accepts it absent or an int, and refuses null, so absent is the only
      legacy form; test it; prune `learned_sources` urls the advisory now has.
- [ ] `learn_sources(root, sources)`: append unseen urls (not in the advisory, not
      already learned), at most 20 kept; save only on change.
- [ ] `entries_since(t)`: by `listed` (filter and sort). Docstring.
- [ ] `plan_known` (main.py ~547): ids to publish = candidate ids then `entry.aliases`,
      not in `prev_ids`, publishable (`compose._public_id`); `k.sources` = prev's, then
      `entry.learned_sources`, then the candidate's. After `changes` is built: if
      `changes and set(changes) <= {"aliases", "sources"}`, call `learn_sources` with the
      new sources and drop `changes` (copies still planned).
- [ ] `digest` (main.py ~643): `e.listed` for `e.last_change`; all-taken branch:
      `roots = [r for t, r in led_taken if t == cutoff]`.
- [ ] Tests: update `test_duplicate_alias_becomes_reply`,
      `test_alias_reply_survives_a_stop_after_ids_were_learned` and
      `test_ids_learned_past_the_alias_cap` to the new rule (alias/source-only → no reply;
      a later fix reply carries the alias and the source). New: a source-only update posts
      nothing and the next fix reply lists the learned source; a reply that only adds
      sources does not re-list the thread in the next digest (ledger written directly);
      a fix reply posted in the same run as the digest is listed that day and not the
      next; an old ledger entry without the new keys loads and uses `last_change`; a
      legacy entry already digested, then a range-only reply, is not re-listed. Any
      Japanese retry/backlog test in test_main.py that relied on an alias/source-only
      reply gets a fixed-version change instead, so its path stays covered.

Acceptance: poster tests green; ledgers on disk without the new keys load.

## Chunk 3: live-feed replay (acceptance)

Files: `tests/fixtures/poster/live-feed-2026-11-07-to-11.json` (10 events copied verbatim
from the live feed: the CVE-2026-88968 thread, the CVE-2026-123158 feed thread, the
11-10 and 11-11 digests), `tests/fixtures/poster/README.md`, `tests/poster/test_live_replay.py`.

- [ ] Replay through `main.run` with `main.gather` monkeypatched to return, at each live
      event's time, a candidate equal to the thread's state after that event
      (`compose.parse_reply` over the live replies), plus lead candidates parsed from the
      live digests' lead lines (single lines verbatim; "N unrated leads" as N leads with a
      Mastodon source). Plus one empty run at 09:20 Tokyo on every day from 11-07 to
      11-11, as the live hourly schedule had, so each day's digest is sent.
- [ ] Assert: the OpenSSH thread gets zero replies; the 88968 fix reply (11-07 04:20 UTC)
      posts with "Fixed in 2.1.251"; the 11-10 and 11-11 digests contain no `LEAD-` and no
      "unrated leads"; CVE-2026-88968 is listed on the day it posted (the 11-07 digest,
      sent in the run that posted it) and on the day of its fix (the 11-08 digest: its fix
      came after the 11-07 cutoff), and in no later digest (not 11-09, 11-10, 11-11).
- [ ] Verify the test fails on main's code (run it before chunks 1-2 land, or against
      `git stash`-free checkout of 0dba6fc in a scratch worktree) and passes after.

Acceptance: the replay test passes; `scripts/test-gate.sh` exit 0.

## Rollback

Between hourly runs on the poster host: revert the branch's commits on main in the
primary checkout and pull; strip `listed_at` and `learned_sources` from every entry of
the CURRENT `ledger.json` (never restore an older copy: it forgets threads already
posted); `uv tool install --force --reinstall <primary checkout path>`.
