# B4: relay transport and the `aitools-alerts-poster` command (ai-tools-alerts#kfq6)

## Problem

B1 to B3 built the poster's parts: candidate adapters, the level rule, post
composition and the advisory ledger. Nothing yet runs them, and nothing sends a
post. B4 adds the transport (one ssh call to the relay VM's `buzz-send` wrapper
per post) and the hourly command that turns inputs into posts: critical to
`#security-critical` then `#security-feed`, high to the feed, notice held for a
09:00 Asia/Tokyo digest. E2 (jibot-code#zhja) schedules it on host-b; E3 is the
live acceptance.

The contract is the issue's comments: B1 c:6mnrdz (KEV only from the poster's
own fetch), E1 c:7rsz33 (the VM send path), the thread rule m7ykef, B3 c:32fgjd
and c:rncpsk (compose and ledger API, reply patch), vy7y c:2bft42 (collector
record path).

## Success criteria

1. `transport.send(channel_id, content, reply_to=None, ssh=subprocess.run)`
   returns `SendResult(ok, event_id, exit_code, stderr, outcome)` and runs exactly
   `ssh -o BatchMode=yes -o ConnectTimeout=20 -o ServerAliveInterval=15
   -o ServerAliveCountMax=4 relay-vm.example
   '<shlex.join([/home/relay/bin/buzz-send, messages, send, --channel, <id>,
   --content, -, (--reply-to, <id>)])>'` with the content on stdin. No key, key
   path, `--private-key` or `--relay` appears in the poster's code (the VM
   wrapper `ops/vm/buzz-send`, E1's file, holds the key path by design; that is
   where the key stays). Tests never spawn ssh.
2. `SendResult.outcome` is `ok`, `failed` (the post certainly did not happen;
   retry next hour) or `unknown` (it may have happened; never resend until a
   human expires the pending entry). Mapping below.
3. `main.run(now, config)` implements the run below; `main.main(argv)` is the
   console script `aitools-alerts-poster` (`run [--config PATH]`), prints one
   summary line, exits 0 when every send of the run succeeded, 1 on any send
   failure, unknown outcome or LedgerError, 2 on a config error.
4. The eight named tests pass, with the full suite (`scripts/test-gate.sh`)
   green: `test_send_failure_leaves_advisory_unposted`,
   `test_critical_posts_to_both_channels_in_order`, `test_high_posts_to_feed_only`,
   `test_notice_waits_for_digest`, `test_duplicate_alias_becomes_reply`,
   `test_watermark_advances_only_on_success`, `test_kev_fetch_not_modified_uses_cache`,
   `test_unknown_outcome_keeps_pending`.
5. No message is sent twice by the poster's own logic, and no planned message is
   lost: every planned message is composed and journaled before the first send
   of its advisory, and survives a failure, an unknown outcome, a crash between
   writes and the source's watermark advancing.
6. Standard library only; Python 3.11.

## Transport

`aitools_alerts/poster/transport.py`, about 110 lines.

- Constants: `HOST = "relay-vm.example"`, `WRAPPER = "/home/relay/bin/buzz-send"`,
  `TIMEOUT = 120` seconds, `MAX_CONTENT = schema.MAX_POST_CHARS`.
- Argument checks raise `ValueError` before any ssh (a programmer error, not a
  send): `channel_id` must be a lowercase UUID, `reply_to` 64 lowercase hex,
  `content` a non-empty `str` within `MAX_CONTENT` and free of NUL.
- The remote command is one string, `shlex.join(remote_argv)`, so the remote
  shell sees each argument as one word; the local argv is a list (no local
  shell).
- `ssh(argv, input=content_bytes, capture_output=True, timeout=TIMEOUT)`; the
  default is `subprocess.run`. Tests pass a callable returning a
  `CompletedProcess`.
- Outcome mapping:
  - `TimeoutExpired` → `unknown` (the remote may have sent).
  - `OSError` starting ssh → `failed` (nothing ran).
  - exit 0 and stdout JSON object with `accepted` true and a 64-hex
    `event_id` → `ok`. Exit 0 with `accepted` false → `failed` (the relay
    refused it). Exit 0 with anything else → `unknown`.
  - exit 255: ssh's own error. `failed` only when stdout is empty and stderr
    has one of ssh's own connect-phase lines, anchored per line
    (`ssh: connect to host <h> port <n>: ...`, `ssh: Could not resolve hostname
    ...`, `<user@host>: Permission denied (...)`, `Host key verification
    failed.`), so the remote CLI's own text cannot match; otherwise `unknown`
    (the session dropped mid-command).
  - exit 0 with `accepted` false and a `duplicate:` message → `unknown` (the
    relay already holds the event, NIP-01).
  - Classification reads the whole stderr; only the stored copy is capped.
- ssh also gets `-T`, `-o RequestTTY=no`, `-o RemoteCommand=none` and `--`
  before the host, so no ssh_config entry can add a terminal or replace the
  command; a host starting with `-` is refused. `ssh=None` means the real ssh,
  looked up at call time; `tests/poster/conftest.py` replaces it with one that
  raises, so no poster test can reach the relay.
  - exit 2 (the Buzz CLI's network/relay/delivery-unknown code) is read from
    the CLI's own error line, the last stderr line that is a JSON object
    `{"error": <category>, "message": ...}` (`print_error` in
    crates/buzz-cli/src/error.rs). `network_error` → `failed` (the CLI keeps
    connect failures as Network and turns an ambiguous post-send failure into
    `delivery_unknown`); `relay_error` with status 400, 401, 403, 413, 422 or
    429 → `failed`; anything else (`delivery_unknown`, another status, no error
    line) → `unknown`. Free text in stderr never decides.
  - exit 1 (usage, not found, the wrapper's own refusals), 3 (auth or key),
    4 (other: raised before submit), 5 (conflict), 126 and 127 (the remote
    command could not start) → `failed`.
  - any other exit, a negative one (ssh killed by a signal) included →
    `unknown`: only an outcome that establishes non-delivery is `failed`.
- `stderr` is kept to its last 2000 characters, decoded with `replace`; the
  content is never echoed into it.

The event id comes from the CLI's JSON `event_id` (E1 verified the field). The
psql fallback in the plan is not built: `messages send` always prints the id
when it succeeds, and a success with no id is an `unknown`, which is the safe
reading.

Replies use `--reply-to <root event id in that channel>`. Buzz's SDK emits
`["e", root, "", "reply"]` for a direct reply (run manifest Notes), which both
readers accept (root-marked, else reply-marked). The coordinator note m7ykef
says B4 writes the root-marked tag; the CLI cannot emit that for a direct reply
without a fake parent, and the readers' rule already accepts the reply-marked
one, so this build uses `--reply-to` and says so on the issue.

## Inputs (`aitools_alerts/poster/inputs.py`)

### Config

TOML at `~/.config/aitools-alerts-poster/config.toml` (`tomllib`). Keys; `~`
expands; unknown keys and wrong types are a `ConfigError` (exit 2):

| key | type | default |
|---|---|---|
| `heartbeat_runs` | path | none: source skipped |
| `collector_runs` | path | none: source skipped |
| `ledger` | path | `~/.local/state/aitools-alerts-poster/ledger.json` |
| `kev_cache` | path | `~/.local/state/aitools-alerts-poster/kev.json` |
| `digest_hour` | int 0–23, Asia/Tokyo | `9` |
| `backfill_days` | int 0–30 | `2` |

Channel ids come from the packaged `spec/channels.json` (`feed`, `critical`).

### Run state

`<ledger dir>/poster-state.json`, written atomically (temp file, fsync,
rename, directory fsync) and only while the ledger's lock is held (the run
holds the ledger context throughout). A malformed state file is refused like a
malformed ledger: `LedgerError`, exit 1, nothing sent. Shape:

```
{"schema_version": 1,
 "since": int,                       # backfill floor, set on the first run
 "heartbeat": str|null, "collector": str|null, "kev_since": "YYYY-MM-DD"|null,
 "digest_date": "YYYY-MM-DD"|null, "digest_at": int,
 "held": [{"scope": str, "adv": advisory dict}],     # notices awaiting the digest
 "digested": ["<scope>|<id casefold>", ...],          # newest 5000
 "outbox": [item, ...]}
```

An outbox item: `{"key", "kind": "root"|"copy"|"reply"|"digest", "scope":
str|null, "ids": [str], "channel": "feed"|"critical", "text": str, "adv":
dict|null, "exploited": bool, "date": str|null, "sent": str|null}`.

### Sources

- Heartbeat: run dirs under `heartbeat_runs` named `YYYY-MM-DDTHHMMSSZ`, newer
  (lexically) than `state.heartbeat`, that hold a `run.json`, oldest first, at
  most 48; each through `candidates.from_heartbeat`. With no watermark yet, only
  the newest such dir (its `run.json` is cumulative).
- Collector: the lexically last `collector_runs/*T*Z/run-record.json` (date-only
  dirs never match); skipped when not newer than `state.collector`, when its
  `job.json` `steps.validate.out` is not `"ok"`, or when unreadable or over
  16 MB; else `candidates.from_collector`.
- KEV: fetched by the poster from
  `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`
  with `If-Modified-Since` from the cache's stored `Last-Modified`. The whole
  fetch (DNS, connect, headers, body) runs under one 90 s wall-clock deadline in
  a daemon thread, as `rules.http_status` does; a miss is a failed fetch, so a
  stalled server cannot hold the ledger lock past it. 200 → body read up to
  32 MB, parsed, cached atomically (`{"last_modified", "catalog"}`); 304 → the
  cached catalog; any error → KEV skipped this run, its watermark held. Only
  this catalog reaches `candidates.from_kev` (B1 c:6mnrdz); the heartbeat's
  `feeds.json` is never read. `since_date` is `state.kev_since`, or the UTC date
  `backfill_days` ago on the first run.
- Backfill floor: on the first run `state.since = now - backfill_days`. A
  candidate whose `observed_at` is before `since` and that the ledger does not
  know is dropped (counted `old`), so the first run does not post the
  heartbeat's whole history.

### Privacy guard

`candidates._PRIVATE` (B1, also compose's guard) gains `/Volumes/`, `/opt/`,
`/srv/`, `/mnt/`, `/root/`, `/usr/local/`, a drive letter followed by either
slash (`C:/`, `C:\`, but not `x://`), and a UNC prefix (`\\server`); tests show
source URLs carrying each, plain and percent-encoded, are dropped.
`/Library/`, `/Applications/` and `/System/Volumes/` are matched with their
capital (a second, case-sensitive pattern), so a local `/Library/Logs/...`
path is dropped while Apple's public `/library/` documentation URLs stay.
Over-matching drops a field or item, never posts it.

## The run (`aitools_alerts/poster/main.py`)

### Order of a run

1. Open the ledger (lock); load state. LedgerError → exit 1, nothing sent.
2. **Drain the outbox** (below), oldest first. A failed or unknown send stops
   the run here.
3. Gather candidates; apply the backfill floor; `rules.scope_of(...,
   log=review)`; `ledger.merge(pairs, ledger)` BEFORE `rules.level_for`.
4. For each merged candidate, **plan** its messages (below); a plan is
   journaled to the outbox in one state save, then drained at once.
5. The digest, when due, is planned and drained the same way.
6. `ledger.add_review(review)` when there is any.
7. Watermarks advance only when no send of this run failed or had an unknown
   outcome, no LedgerError occurred, and nothing was busy (a journaled item
   held back by a pending entry, or a candidate deferred because of one). A
   busy candidate's update (a promotion, a fix) is therefore read again once
   the send resolves; journaled work survives either way.

After one failed or unknown send, or any LedgerError, the run sends nothing
more: no further outbox item, plan or digest.

### Levels

`level, reason = rules.level_for(c, scope, False)`; when the reason is
`unverified` (only the clauses that need a primary source), recompute with
`rules.source_ok(c, rules.http_status)`. Same result as always fetching, fewer
fetches.

### Planning

Identity: `ids = [c.id, *c.aliases]` (merged). A candidate is **busy** when an
outbox item of the same scope shares an id (case-insensitive) or
`ledger.pending_for(ids)` is non-empty. A busy candidate is not planned; its ids
are unioned into every overlapping outbox item (saved), so a later candidate
that carries only a newly learned id still finds the item (the A, A/B, B case).
Counted `busy`.

No ledger entry (`ledger.lookup(ids, scope=scope.name)` is None):
- `notice`: `compose.root_post`; held unless any `"<scope>|<id>"` of it is in
  `held` or `digested`; else appended to `held`. No send.
- `high`: one item, `root` to `feed`.
- `critical`: `root` to `critical`, then `copy` to `feed` with the same text.

Known entry (`prev = schema.validate(entry.advisory)`):
- Level: `max(level, entry.level)`; a run never lowers one (a curator does).
- Canonical candidate `k = replace(c, id=prev.id, aliases=<prev's aliases, then ids it lacks>,
  fixed=<c.fixed if schema-expressible, else prev's fixed>, affected=<likewise>,
  sources=<prev's sources, then c's new ones>)`. Thread identity stays the
  stored root's id, so the template title matches what `reply_post` accepts,
  and a KEV-only candidate does not erase a known fix.
- `text, new = compose.root_post(k, (level, reason), scope, posted_at=prev.posted_at)`.
- Identity first: ids the ledger entry lacks are added to it at once
  (`Ledger.add_ids`, no post), so identity is learned even when the published
  alias list is at its cap of 50 and no reply can say so.
- `changes`: `level` and `title` when the level rises; `products` when `new`'s
  product differs from `prev`'s (a fix, or a corrected affected range with or
  without one; `k` keeps the stored fix and range when the candidate has none); `aliases` (the ids the
  ledger entry lacks) when `prev` has fewer than 50; `sources` (new URLs) when
  `prev` has fewer than 20.
- Items, in order: a `copy` of `text` to each channel the level needs
  (critical: `critical`, `feed`; high: `feed`) that `entry.channel_ids` lacks
  (a raised level, or a critical whose feed copy failed before journaling
  existed); then, if `changes`, one `reply` per channel the entry had, with
  `compose.reply_post(prev, k, changes, reason=...)` and the merged advisory
  `compose.parse_reply(reply, prev)` stored in the item.

Every message of a plan is composed before any is journaled. A `ValueError`
from compose withholds the whole advisory (counted `withheld`): nothing is
journaled, nothing sent.

### Draining an item

For each outbox item in order. An item with `sent` set goes straight to step 4
(its pending entry is its own). Otherwise it is skipped (counted `busy`) when
its ids are pending in the ledger or it shares ids with an earlier skipped item
(a copy never goes before its root):

1. If `sent` is set, the post happened but recording may not have: go to 4.
2. `ledger.pending(key, ids, now)`. Then `transport.send(channel id, text,
   reply_to)`, where `reply_to` (replies only) is the entry's root id in that
   channel, read from the ledger at send time.
3. `ok`: set `sent = event id`, save state. `failed`: `clear_pending`; the
   item stays for the next hour; stop. `unknown`: pending stays, the item
   stays; stop.
4. Record, idempotently: `root` → `record_root(adv, eid, {channel: eid},
   scope, exploited, ids)` unless the ledger already has the entry; `copy` →
   `add_channel(<entry root id>, channel, eid)` unless present; `reply` →
   `record_reply(<root id>, adv, {channel: eid}, ...)` unless a reply with that
   id is recorded; `digest` → `digest_date`, `digest_at` = the item's
   journaled cutoff, the item's journaled notice keys into `digested`, and
   only those notices removed from `held`.
5. `clear_pending(key)` if pending, while the sent item still exists; then
   remove the item and save state. A crash between the two leaves a `sent`
   item that step 4 finishes idempotently.

Crash windows: after the send and before step 3's save, the pending entry stays
and the item stays: the run treats it as in flight until a human expires the
pending entry (the irreducible window, B3's rule). After step 3 the journal
carries the event id, and the next run completes 4 and 5 without sending.

Expiring a pending entry (a human, `Ledger.expire_pending` with a reason) makes
its item send again on the next run. When the human has found the post was
delivered, the item must be dropped instead; a `resolve` subcommand that does
both is a follow-up issue (filed at landing), not this build.

### Digest

Due when the Asia/Tokyo hour (`zoneinfo`) is at or past `digest_hour` and
`digest_date` is not today's Tokyo date. Items: the held notices plus every
ledger entry whose `last_change` is after `digest_at`
(`Ledger.entries_since(t)`, a new read-only method), deduplicated by
`compose.digest`. One `digest` outbox item to `feed`, key `digest:<date>`,
whose `adv` journals the snapshot it was built from: the scoped notice keys and
the ledger cutoff (`now`). No digest is planned while any digest item is in the
outbox, so an unknown digest is never queued twice; when it later sends, it
acknowledges only its own snapshot. It posts once a day, even when it says
"no advisories". Built from the ledger, the
digest cannot miss a post that the ledger recorded, whatever crashed between
files.

### Summary

One line, for example `aitools-alerts-poster: candidates=12 in_scope=4 old=3
roots=1 copies=0 replies=0 held=2 withheld=0 busy=0 digest=0 failed=0
unknown=0`. Counts only; send errors go to stderr with the exit code and the
last 300 characters of stderr, never post text.

## Privacy

Every post is relay-bot (`compose` sets `posted_by`); readers never auto-apply
one. `compose` refuses any post naming a fleet host, this machine, a local path
or a kata ref; main adds nothing to composed text.

## Size and landing

Measured: transport plus tests 269 lines, inputs and the privacy guard plus
tests 509, the run plus tests 832 (376 of code, 447 of tests). Three landings on this
issue, each reviewed whole: (1) transport; (2) inputs and the privacy guard;
(3) the run, the outbox, `Ledger.entries_since`/`has_pending`, and the console
script. The third is over 600: the journal and the planner it serves cannot be
tested apart (every named test drives both), and the brief sized this task as
transport first, then main; recorded as a rebuttal on the issue.

## Alternatives rejected

- The plan's env form (`env BUZZ_PRIVATE_KEY_FILE=... buzz`): E1 replaced it
  with the wrapper, which holds the key; the plan's form would put a key path
  in the poster.
- The psql fallback for the event id: a second ssh and a query that guesses
  "newest by pubkey", racy against other jibot posts; the CLI prints the id.
- Building the reply's e tag ourselves: the CLI has no raw-tag option, and the
  reply-marked tag it emits is accepted.
- Recording each reply channel straight into the ledger with no journal: a
  failed second channel would never get its reply, because the next run sees
  the advisory already updated.
- Auto-expiring pending entries: the ledger requires a human reason.
- Lowering a level from the bot: only a curator lowers (A5's reader rule).

## Blast radius and rollback

New files, one read-only ledger method, wider private-path patterns, one
console script line. Nothing runs until E2 installs the launchd job; rollback
is a revert. The first live run can post publicly, so E2 runs it once by hand
first.

## Assumes

- `messages send` prints `event_id` on success (E1 verified).
- The heartbeat's `run.json` is cumulative, so reading the newest dir loses
  nothing; the ledger, the outbox, `held` and `digested` dedup the rest.
