# Mirror freshness: warn when the newest trusted event or the manifest is old

Issue: ai-tools-alerts#544a (from the independent security read of 2026-11-06, finding 2).

## Problem

`pull._events_file` checks `generated_at` only as a string, and the manifest
check refuses only a manifest older than the floor. A mirror operator who
freezes the mirror, or replays old signed files, produces a successful pull
forever: every signature verifies, no new retraction or advisory arrives,
and the reader is never told. Alerts can be suppressed silently.

The poster already signs one event a day (the daily digest, a curator or
relay-bot post under the manifest), so a healthy mirror always carries a
trusted event less than about a day old. That digest is the signed
heartbeat; this task makes the reader look at it.

## Success criteria

1. A pull records, in `last_pull.json`, `newest_event_at` (the newest
   `created_at` among the stored events whose key the current manifest
   trusts; null when none) and `manifest_issued_at` (the manifest's issued
   time, epoch seconds). Both come from the state the pull leaves behind,
   on success and on failure.
2. `pull.stale_since(state, now)` returns null when the mirror is fresh,
   else an epoch time:
   - the newest trusted event's `created_at` when it is older than
     `STALE_EVENT_S` (3 days); with no trusted event at all, the manifest's
     issued time stands in for it (nothing has been heard since the
     manifest);
   - otherwise the manifest's issued time when it is older than
     `STALE_MANIFEST_S` (90 days);
   - null when nothing was ever pulled (no stored manifest: `check` already
     says "no successful pull yet").
   It reads the stored state, under `effective_manifest` (a newer bundled
   manifest's revocations apply), so it holds even when every later pull
   failed.
3. `aitools-alerts check` (and `run` without `--json`/`--quiet`, which
   prints check's output) prints one fixed line when stale:
   `warning: alerts may be stale since <ISO time>: no new signed post for over 3 days, or a trust manifest over 90 days old; the mirror may be frozen or replayed`
   (one template that is true for either condition; amended after the
   spec review).
   The time is formatted from the epoch value, never from mirror text. The
   exit status does not change.
4. `run --json` carries `"stale_since"`: null, or the ISO time
   (`YYYY-MM-DDTHH:MM:SSZ`).
5. The Claude Code hook prints one more fixed line when stale, and still
   always exits 0:
   `AITOOLS-ALERT: alerts may be stale (no new signed post for over 3 days, or a trust manifest over 90 days old); run aitools-alerts check`.
6. Tests: `tests/test_pull.py` (recording, thresholds, revoked key's events
   ignored, no events, never pulled); `tests/test_cli.py` (check line,
   check exit 0, run --json field); `tests/test_templates.py` (hook prints
   the line for a stale JSON, not for null, not for a post title that
   quotes the key).
7. Under 200 changed lines, excluding run artifacts.

## Approach

- `pull.py`: constants `STALE_EVENT_S = 3 * 86400`,
  `STALE_MANIFEST_S = 90 * 86400`; `freshness(state) -> (newest_event_at,
  manifest_issued_at)` and `stale_since(state, now)`; `_fetch.record`
  adds both freshness fields to `last_pull`.
- `cli.py`: `_stale_line` helper; `cmd_check` prints it after the "no
  successful pull" line; `cmd_run` adds `stale_since` to the JSON object.
- Hook: runs `aitools-alerts run --json` instead of `run --quiet`, keeps the
  JSON in a variable, prints the critical line on exit 2 as before, and the
  stale line when the JSON holds `"stale_since": "`. JSON escaping makes
  that match impossible from post text: inside a string value every `"` is
  written `\"`, so a title cannot contain the unescaped key followed by an
  unescaped quote. `--json` suppresses notify output on stdout exactly as
  `--quiet` does.
- README: the hook section names the second line and the `run --json`
  invocation. SKILL.md (both harnesses) and `snippets/AGENTS.md`: one bullet
  on `stale_since`.

## Alternatives considered

- **Change `check --json` from a list to an object carrying
  `stale_since`.** Rejected: `check --json` is a list that README and the
  skills read (`plan` takes its thread ids); an object breaks every
  consumer. `run --json` is already an object and is what the skills run.
- **A new exit status from `run` for stale.** Rejected: exit 2 is the
  critical signal for the hook, launchd and Hermes; a stale code would
  either mask a critical or read as a failure to callers that only expect
  0/1/2. The issue says warn, never fail.
- **A second CLI call in the hook (`check`).** Rejected: a second Python
  start and a second state read per session, for a value `run --json`
  already prints.
- **Check `generated_at` in the event files.** Rejected: it is unsigned, so
  the operator sets it freely. The signed event's `created_at` is the only
  time the operator cannot forge.
- **A manifest max-age field.** Out of scope (the issue's design note: a
  later manifest field).

## Assumes

- The poster's daily digest keeps posting at least once every 3 days. A
  quiet relay with no digest would warn; that is the intended signal.
- A signer can still post an event with a future or fresh `created_at`;
  a mirror operator cannot, which is the threat here.
- Limit: freshness proves the mirror is not frozen, not that it is
  complete. An operator who forwards the fresh digest while withholding one
  advisory or retraction is not detected; that needs a signed sequence or
  index, filed as a follow-up.

## Blast radius and rollback

Reader-only: pull's state record gains two keys (older readers ignore extra
keys in `last_pull.json`), check gains a line, run --json gains a key, the
hook gains a line. No signing, trust-root or verification logic changes.
Rollback: revert the commit; the next pull rewrites `last_pull.json`.

## Open questions

None blocking. Parallel work: ai-tools-alerts#fsmb changes the hook's PATH
and HOME resolution; this task changes only the invocation and the output
lines, and rebases late.
