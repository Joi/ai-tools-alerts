# Plan: 0dvh hold until complete, age limit, range and severity, public ids

Spec: docs/superpowers/specs/2026-11-23-0dvh-hold-until-complete-and-age-limit-design.md. Budget: under 600 changed lines (tests and fixture JSON aside from the line count of code and tests; the fixture is data).

## Chunk 1: hold and age limit (aitools_alerts/poster/main.py, inputs.py)

- [ ] inputs.py `_STATE_KEYS` gains `waiting`; `new_state` sets `{}`; `load_state` adds `{}` to an older state and validates `waiting` (dict, str keys containing `|`, int values, `len <= MAX_WAITING`).
- [ ] main.py constants `HOLD_SECONDS = 6*3600`, `AGE_LIMIT = 7*86400`; `SUMMARY` gains `waiting`, `aged` at the end (readers of the summary line key by name).
- [ ] main.py `_epoch(v)` (from `_observed`), `_published(c)` (first primary source of `compose._sources`), `_stated(v)`.
- [ ] `Run._held_for(scope, ids)`: the held notice entry under any of the ids, or None. `Run.first_seen(scope, ids)`: min of `waiting` under any id and the held notice's `adv.posted_at`, else now.
- [ ] `Run.plan_new`: age check first (any level but notice, not synthetic; published from the candidate, else from the held notice's primary source): level becomes notice, `aged` counted. Else the hold: high, not synthetic, not exploited, no fixed, no affected, `now - seen < HOLD_SECONDS`, and `waiting` below the cap or already holding this key: `waiting[scope|id] = seen`, save, defer, `waiting` counted, plan nothing.
- [ ] `Run.hold`: field-preserving update of a held notice (fixed, affected; actions follow fixed).
- [ ] `run()`: after `state["deferred"]` is replaced, `waiting` keeps only keys under a deferred candidate's ids.
- [ ] In the same chunk, before its verification (plan review): give the five test_main findings that are fix-less highs a range, so they post at once as their tests expect.
- Verify: `python3 -m pytest -q tests/poster/test_main.py tests/poster/test_inputs.py`.

## Chunk 2: block and titles (aitools_alerts/poster/compose.py)

- [ ] `public_form`, `SEVERITIES`, `severity()` (highest-ranked allowed word of a `"; "`-joined value), `range_unexpressed`.
- [ ] `root_post`: severity and public-form title; `_words(…, unexpressed)` and `_words_ja`; `root_post_ja(range_unexpressed=)`.
- [ ] `_titles`, `_exploited`, `_ja_title`, `_group_key` accept both id forms.
- [ ] `_publishable`: refuse severity outside `SEVERITIES`; `_change_line(_ja)` for a set severity.
- [ ] main.py `plan_known`: a reply that goes out for another reason carries a changed severity; severity alone posts nothing.
- [ ] Japanese range flag on every rendering path (plan review): `plan_new`'s root, `plan_known`'s copy and the whole advisory after a reply's changed lines all pass `range_unexpressed`; `plan_known` keeps a raw unexpressible range in `k` when none is known, so the flag survives into the update path.
- Verify: `python3 -m pytest -q tests/poster/test_compose.py`.

## Chunk 3: mirror one row per advisory (mirror/export_mirror.py, 6e20)

- [ ] `index_doc`: group by `(id casefold, product name)`; show the copy with the latest `updated_at` (tie: newer root); Retracted if any copy is; date of the earliest root; the INDEX_LIMIT counts rows.
- Verify: `python3 -m pytest -q tests/mirror`.

## Chunk 4: tests

- [ ] (The five test_main migrations moved to chunk 1.) Migrate `test_live_feed_replay` (CVE-2026-88968 aged: no root, no reply; 11-08 digest lists it under Notice with `fixed in 2.1.251`).
- [ ] tests/fixtures/poster/live-feed-2026-11-07-and-18.json: the 35 non-translation events of 11-07 02:20Z/04:20Z and 11-18 10:20Z/11:20Z, copied verbatim from the live feed.
- [ ] tests/poster/test_live_replay.py: `test_replay_11_07_posts_no_old_root` (17 roots, replies as fixes two hours later: zero real-time roots, `aged=17`); `test_replay_11_18_posts_each_once_with_its_fix` (five roots, each once, `Fixed in 2026.11.18`, no reply, no "check the vendor"; every root parses with `schema.parse_post`; titles carry public ids).
- [ ] test_main: hold across a restart (state reloaded between runs); posts at 6 h with what is known; a critical and an exploited high never wait; waiting cap posts at once; held notice keeps a fix when a later sighting brings only a range; merged `"critical; high"` severity publishes `critical`; a reply never posts for severity alone and carries it with a fix.
- [ ] test_main (plan review): an old critical posts in neither channel; a notice first seen at six days that becomes high two days later posts a root; a notice re-sighted with an undated primary source stays aged (held-source fallback); the delivered Japanese root says the range is in the source.
- [ ] test_compose: public-form title with the block id unchanged (the ledger key); a fix and severity reply to a root titled with its ledger key keeps id and title; legacy key-form title still matched by `_titles`/`_exploited`/`_ja_title`/`_group_key`; unexpressed range wording; severity outside the allowlist refused in a reply.
- [ ] test_inputs: a state without `waiting` loads; a malformed `waiting` is refused.
- [ ] tests/mirror: feed root and critical copy are one row; a curator amendment to the critical copy shows; a retraction of either shows Retracted.
- Verify: `scripts/test-gate.sh` (public scan, then the whole suite).

## Acceptance

Spec success criteria S1–S5 and both replays green; `git diff --stat origin/main` under 600 lines excluding the fixture JSON.

## Rollback

Revert the merge on main, pull, `jq 'del(.waiting)'` on the poster state between hourly runs, reinstall.
