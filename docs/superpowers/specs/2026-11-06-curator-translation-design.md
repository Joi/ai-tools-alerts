# Curator translation (phase 2 of the Japanese feed) — design

Kata: ai-tools-alerts#bq8v. Parent: jibot-code#gr5b. Builds on rd8t (templated
`lang: ja` replies, e566386) and yxd6 (the reader side).

## Problem

rd8t gives every relay-bot post a Japanese `lang: ja` reply from templates. A
curator's post or amendment is written by a person and carries free text (a
title, a `--note`), so templates cannot translate it, and a Japanese reader
sees the English. Joi decided on 2026-11-06 to translate curator free text
with one Claude API call per post or amendment.

Two facts the issue body did not account for:

1. **The poster never sees curator posts.** A curator signs and sends with
   `aitools-alerts curator`, straight to the relay. The poster reads only its
   own inputs (heartbeat, collector, KEV) and its own ledger.
2. **Readers ignore a relay-bot `lang:` reply on a curator thread.**
   `pull.threads_from` treats every relay-bot reply on a thread a curator
   posted or amended as discussion (decided in yxd6's review: "bot text never
   appears under a curator's attribution"). A bot translation of a curator
   post would therefore never be shown.
3. **`claude-sonnet-5-5` rejects `temperature`.** The Messages API returns 400
   for a non-default sampling value on Sonnet 5.5 (and, from API version
   2026-10-21, on every model). The request sends no `temperature`.

## Success criteria

- S1. With `translate_curator = true`, a curator root or amendment that
  arrives in the mirror after the poster's backfill floor gets one `lang: ja`
  reply from the poster, in the channel the curator event is in: to the root
  with no `of:` for a root, with `of: <amendment id>` for an amendment.
- S2. The Japanese body is the model's output followed by the line
  `（機械翻訳）`, so a reader can tell a machine translation from a curator's.
- S3. The output posts only when every URL, version string and id found in
  the source text appears unchanged in it (`translate.tokens`, deterministic);
  otherwise nothing is posted, the event is cached as `untranslated` and the
  summary's `untranslated` count goes up. It is never retried.
- S4. One call per event id: the outcome (`ok`, `untranslated`) is cached by
  event id in the translate state, for as long as the mirror holds the event
  (the cache is pruned to the mirror's events, never by count). A refusal or
  a cut-off answer (`stop_reason` other than `end_turn`) is `untranslated` at
  once. A service failure (timeout, 5xx, network) ends the pass and is tried
  on the next run; after `MAX_TRIES` (3) failures the event is
  `untranslated`, so one bad event never starves the rest.
- S4a. Persistence order: the call is counted first, then the journal item is
  saved, then the event is recorded `ok`. A run that stops between the last
  two leaves the item in the journal; the next run sees its key there and
  records `ok` without calling. A run that stops after a call and before the
  journal spends that call again on the next run (counted twice: accepted).
- S4b. The request never follows a redirect (the key is never re-sent).
- S5. A 401 or 403 sets `hold` in the translate state. While it is set no run
  reads the key or calls the API; the summary shows `translate=held`. Only a
  human clears it: `aitools-alerts-poster translate-clear-hold`.
- S6. At most 20 calls per UTC day, counted in the translate state before each
  call (a call that times out counts).
- S7. Each call has a 30 s wall-clock deadline (a daemon thread, as the KEV
  fetch has; urllib's timeout alone bounds each read, not the whole call),
  the mirror pull 120 s, and the whole pass stops starting calls after 300 s,
  so the ledger lock is never held long enough to block the next hourly run.
  The curator pass runs only after every English send and the final save of
  the run, and nothing it raises reaches the run's exit code, so it never
  delays or stops an English post.
- S8. The API key is read only when there is something to translate and the
  budget allows a call; through `get_secret` in a bash subprocess whose
  `SECRETS_CACHE_DIR` is a fresh unwritable directory (sign-manifest.py's
  pattern), passed on stdout, held in memory, never in argv, a file, a log or
  an exception message.
- S9. `translate_curator` defaults to false: with it off, no mirror pull, no
  key read, no call; the journal is as before, and the summary adds only
  `untranslated=0 translate_failed=0 translate=off` before `inputs=` (which
  stays last). Tests that pinned the old summary and the old reader rule are
  updated (tests/poster/test_main.py summary assertions keep `endswith
  inputs=…`; tests/test_pull.py and tests/mirror/test_export.py now expect
  the bot translation on a curator thread).
- S10. Readers keep a relay-bot `lang:` reply on a curator thread as that
  thread's translation unless a curator's translation exists for the same
  target (a curator's always wins, as today). No other relay-bot reply on a
  curator thread changes meaning.
- S11. Standard library only; tests use a fake `call` and never reach the
  network or a secret.

## Approach

### `aitools_alerts/poster/translate.py`

- `MODEL = "claude-sonnet-5-5"`, `TIMEOUT = 30`, `DAILY_CALLS = 20`,
  `API_URL = "https://api.anthropic.com/v1/messages"`, `MARK = "（機械翻訳）"`.
- `SYSTEM` — the fixed system prompt: translate the user's text into natural
  Japanese for a security alert feed; copy product names, version strings,
  ids (CVE, GHSA, event ids), URLs, commands and code exactly; never add,
  drop, explain or rewrite anything; keep the line structure; output only the
  translation.
- `tokens(text) -> set[str]`: URLs (`https?://` up to whitespace, trailing
  `.,;:)` stripped), ids (`CVE-YYYY-N+`, `GHSA-xxxx-xxxx-xxxx`, 64-hex ids,
  and `[A-Z][A-Z0-9]+-\d[\w.-]*` style ids such as `USN-1234-1`), and whole
  version strings and numbers as schema accepts them (`2.1.0`, `9.9p1`,
  `1.0rc1`, `22`, `v2.0.1-rc1`), never a prefix of one.
- `translate(text, *, call) -> str | None`: `out = call(SYSTEM, text)`; strip;
  None when empty or when any token of `text` is missing from `out`; else
  `out`. `call` raises `AuthError` on 401/403 (propagated) and `CallError` on
  anything else (propagated; the caller decides). The function itself does no
  I/O.
- `read_key(helper, runner=subprocess.run) -> str`: sign-manifest.py's
  `read_root_secret` reduced to this case: refuse root, `mkdtemp` + `chmod
  0o500`, prove it refuses a write, run `bash -c 'source "$H" && get_secret
  "$N"'` with `H`/`N` in the environment (`N=ANTHROPIC_API_KEY`), the old
  `ANTHROPIC_API_KEY` and bash startup/trace variables removed, stdin closed,
  output captured, 60 s timeout; then check the directory is still empty and
  remove it. One non-empty line or `CallError("api key unavailable")` — the
  message never includes output.
- `api_call(key) -> call`: a closure that POSTs JSON with urllib:
  headers `x-api-key`, `anthropic-version: 2023-06-01`, `content-type`;
  body `{"model": MODEL, "max_tokens": 4096, "system": SYSTEM,
  "output_config": {"effort": "low"}, "messages": [{"role": "user",
  "content": text}]}`. No `temperature` (400 on this model). HTTP 401/403 →
  `AuthError`; any other HTTP error, URLError, timeout, bad JSON →
  `CallError("http <code>" | "unreachable" | "bad response")`;
  `stop_reason != "end_turn"` (a refusal, `max_tokens`) → `""`, so the event
  is `untranslated` and never retried; an HTTP protocol error →
  `CallError("unreachable")`; no redirect is followed. The
  result is the joined text blocks. Error text never carries the key or the
  response body.

### Translate state

A separate file, `<ledger>.translate.json`, written with `inputs.write_json`
under the ledger lock (the run already holds it). Separate so that the
journal format (`load_state`'s exact key set) is unchanged and a rollback to
the previous poster reads its state as before.
`{"hold": null | {"at": int, "why": "http 401"}, "day": "YYYY-MM-DD",
"calls": int, "done": {event id: "ok" | "untranslated" | failed tries}}`,
`done` pruned to the event ids the mirror state still holds (the mirror keeps
a thread 400 days; an event it no longer holds is never selected again). A
malformed file: the curator pass does nothing that run and says so on stderr
(never a reset that would forget a hold). `Config.check_paths` includes the
translate file and the mirror directory.

### Which events

`Run.translate_curator(fetch=None, call=None)`, after `drain()`/planning/
`digest()`, the final `save()`, and before `drain_ja()` (so the new Japanese
items send in the same run):

1. Off, or `hold` set → return (summary `translate=off|held`).
2. Pull the mirror (`config.translate_mirror_url`, default
   `config.DEFAULT_MIRROR_URL`) into the member-style state directory
   `<ledger>.mirror/` with `pull.fetch` (signature and manifest checks
   unchanged). A pull error → `translate=mirror-error`, return.
3. For each verified event signed by a curator key (manifest role), oldest
   first, with `created_at >= state["since"]`, not in `done`, whose channel
   (`h` tag) is `feed` or `critical`:
   - a root: `schema.parse_post` succeeds → target the event, `of` none;
   - a reply whose root-marked `e` tag names a stored root, whose first line
     is `level: high|notice` or whose content has an `aitools-alert` block →
     target that root, `of` the reply.
   Retractions, translations and discussion are skipped.
4. Source text: the content before the block (`schema.render_post` puts the
   body, a blank line, then the fence). For an amendment (`Amended: …`/
   `level: …` plus the note), that text, a blank line, then the whole
   advisory as amended in English lines (level and title, affected and fixed
   per product, actions, sources; `pull.threads_from` over the events up to
   the amendment), because a change made only in the block (`--fixed`)
   would otherwise be missing from the Japanese while readers show the
   translation as current. Identical texts in one pass (a critical's two
   channel copies) share one call.
5. Budget: `calls >= 20` today → stop; else `calls += 1`, save, then read the
   key (once per run) and call.
6. `AuthError` → `hold`, save, `translate=held`, stderr names the clear
   command; stop. `CallError` → `translate_failed += 1`, the event's tries
   go up (at `MAX_TRIES`, `untranslated`), stop for this run.
   `None` → `done[eid] = "untranslated"`, `untranslated += 1`. Text →
   `compose.lang_reply(text + "\n\n" + MARK, of)` (its guard refuses hosts,
   paths and blocks: refused → `untranslated`), journaled as a `ja` item with
   key `curator:<event id>:<channel>:ja` through the same bounded journal path
   `_queue_ja` uses; `done[eid] = "ok"`.

`drain_ja` then sends it like every other Japanese reply (pending, resolve,
backlog cap all unchanged).

### Reader rule (`pull.threads_from`)

The discussion gate `if role != "curator" and t[3]: continue` lets a
`lang:` reply through to the translation branch, where the existing rule "a
relay-bot translation never replaces a curator's" still applies. Nothing else
changes: a relay-bot patch, level line or retract on a curator thread stays
discussion. The mirror exporter calls the same function.

### Config (`poster/inputs.py`)

`translate_curator: bool = False`; `translate_mirror_url: str =
DEFAULT_MIRROR_URL` (https or file URL, `config.check_mirror_url`);
`secrets_helper: Path | None` (absolute; required when `translate_curator`
is true, else a `ConfigError` at load). The helper path is deployment detail
and lives only in the config, as `relay_ssh_host` does.

### CLI and summary

`aitools-alerts-poster translate-clear-hold [--config]` removes the hold
under the ledger lock and prints when it was set and the status. The summary
gains `untranslated` and `translate_failed` counts and
`translate=<off|ok|held|key-error|mirror-error|state-error|error>`, all
before `inputs=`, which stays last. A missing or unreadable key is
`key-error` and is never charged to an event. An existing translate file
must hold exactly the four fields, each valid (`calls >= 0`), or the pass
fails closed (`state-error`). A translation longer than readers keep
(`pull.MAX_TRANSLATION_CHARS`, marker included) or a source over 6000
characters is `untranslated`. `check_paths` also refuses any file inside
the mirror directory. The bot's own `lang:` replies already in the mirror
count as done, so a lost translate file never reposts.

## Alternatives considered

- **Hold flag in the journal (`load_state`)**: one file, but every older
  poster refuses a state with an unknown key, so a rollback stops all posting.
  Rejected for the separate file.
- **Read the member CLI's state on the poster host** instead of pulling: ties
  the poster to a member install that may not exist or may lag. Rejected.
- **Leave the reader rule alone**: the translation would never be shown; the
  feature would spend API calls for nothing. Rejected.
- **A curator translates by hand**: the existing rule already lets a curator's
  `lang:` reply win; this design keeps that and fills the gap until then.
- **The Anthropic SDK**: a runtime dependency, forbidden by docs/plan.md.
- **`temperature: 0`**: rejected by the API on this model; the deterministic
  token check, not sampling, is what guards the output.

## Blast radius and rollback

Default off: deploying this changes nothing until the coordinator sets
`translate_curator = true` and `secrets_helper`. On: one extra mirror pull
per hour, up to 20 API calls a day, extra `lang: ja` replies. The reader
change affects every member CLI and the mirror's `feed.ja.atom` once they run
this version: a relay-bot `lang:` reply already on a curator thread now
shows (today there are none: rd8t's poster translates only its own threads).
Rollback: set `translate_curator = false` to stop translating. To reinstall
the previous version, first remove all three new keys (`translate_curator`,
`translate_mirror_url`, `secrets_helper`) from the config: the old
`load_config` refuses unknown keys and would stop all posting. The translate
file and mirror directory can be deleted. Already
posted Japanese replies stay; a curator `retract` or a curator `lang:` reply
replaces them for readers.

## Open questions

None blocking. The reader-rule change reverses a worker decision from yxd6's
review, not a ruling of Joi's; it is recorded as `decided:` on the issue.
