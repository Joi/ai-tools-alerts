# Poster: a Japanese `lang: ja` reply for every relay-bot post

Kata: ai-tools-alerts#rd8t (parent epic jibot-code#gr5b). Reader side: ai-tools-alerts#yxd6 (mirror feed.ja.atom, CLI lang), built on the same format in parallel. Code: `aitools_alerts/poster/compose.py`, `poster/main.py`, `poster/inputs.py`.

## Problem

Joi asked on 2026-11-06 for a Japanese version of the feed. Every relay-bot post (a root, a change reply, the daily digest) is built from templates in `compose.py`; the only free text in them is product names, ids, versions and URLs. A Japanese rendering can therefore be deterministic: the same fields through Japanese templates, with no model call, no new dependency and no new secret.

## Format (coordinator decision 2026-11-06; written into docs/design.md "Post format")

A translation is a reply in the thread (e tag marked root) from a manifest key whose first line is `lang: ja`, an optional second line `of: <event id>` naming the event it translates (absent = the root), a blank line, then the Japanese body. It carries no aitools-alert block; a lang reply that carries one is ignored entirely by readers (never a patch). For one target the latest lang reply from a manifest key wins. A lang reply from a non-manifest key is discussion. A curator `retract` retracts the translations with the thread. The digest root gets a `lang: ja` reply too.

This run does not change the format. A question about it is a kata comment on the issue.

## Success criteria

- S1. After a root (critical, high) is sent and recorded, the poster sends, in the same channel, a reply to that root whose text is `lang: ja`, a blank line, and the Japanese root body. A critical's root and its feed copy each get one (two Japanese replies, one per channel, each replying to that channel's root event).
- S2. After a change reply is sent and recorded in a channel, the poster sends a reply to that channel's thread root whose text is `lang: ja`, `of: <the English reply's event id>`, a blank line, the Japanese change body, a blank line, and the whole current advisory in Japanese (the four root lines of the merged advisory). The last part follows the reader rule posted from ai-tools-alerts#yxd6 (c:yv1vtk): a reader keeps the translation of the thread's current version, so the newest translation must describe the whole advisory, not only what changed.
- S3. After the digest is sent, the poster sends a reply to the digest event: `lang: ja`, a blank line, the Japanese digest.
- S4. The Japanese reply is its own journal item keyed `<original key>:ja` (a change reply's key adds `:<English event id>`, since one thread takes many replies under one English key), created only once the original's event id is journaled and recorded, in the same state save that removes the original. Its in-flight ledger entry carries no aliases (so `pending_for` never matches it, whatever id a candidate carries) and `busy()` ignores Japanese items, so it never holds, defers or blocks an English item. A Japanese item whose event id is journaled is finished without a send. A ledger or journal error while sending Japanese replies is reported on stderr and counted, never the exit code. Japanese items are sent after every English send of the run. A failed Japanese send leaves the item in the journal for the next hour, stops further Japanese sends this run, and does not change the exit code, the watermarks or any English send. An unknown outcome stays pending for a human (`pending` / `resolve`), as for English posts.
- S5. A Japanese text that cannot be composed (compose raises) or would not be sendable drops only the Japanese reply; the English post is unchanged and still sends. No Japanese text holds an aitools-alert block; every Japanese text passes `compose._guard`.
- S6. Templates: level words critical 緊急, high 重要, notice 注意; Affected 影響, Fixed in 修正版, Action 対応, Source 出典; "No fixed version is known yet" and the digest scaffold in Japanese. Product names, ids, versions, URLs and the `SYNTHETIC TEST` and `unverified: no primary source confirmed it` marks stay as they are in English, including in the Japanese head line. The advisory title is rendered in Japanese when it is one of compose's template titles (the kind words; an `unverified ` prefix stays English, so a digest line or title change keeps the mark), else kept in English.
- S7. English output is byte-identical: every existing compose and main test passes unchanged, apart from the fake ssh routing `lang: ja` sends to their own list.
- S8. A state file written by the deployed poster (items without the new field) loads unchanged.
- S9. Tests in tests/poster for root, change, digest, both channels, retry, and the `of:` line. README: one paragraph. Under 400 changed lines (code, tests and docs, run artifacts excluded); stdlib only.

## Approach

### compose.py

- `_JA_LEVEL = {"critical": "緊急", "high": "重要", "notice": "注意"}`, Japanese kind words for the four `_KINDS`, Japanese range words (`未満`, `以下`, `超`, `以上`, `のみ`; `全バージョン`; `バージョン不明`).
- `_ja_title(adv)`: when `adv.title` is one of `_titles(name, id)`, the same title with the kind in Japanese (an `unverified ` prefix kept in English), the `SYNTHETIC TEST: ` mark and the id kept; otherwise the English title.
- `root_post_ja(adv, reason)`: the four lines of `root_post` in Japanese, from the validated Advisory `root_post` returned plus `reason`; the "fix listed upstream" case is carried by a flag (`unexpressed`). `root_post` itself is unchanged; main calls both.
- `reply_post_ja(merged, changed_keys, source_url, reason)`: one Japanese line per changed key, in `reply_post`'s order, the unverified line kept in English, then `出典: <url>`. No block.
- `digest(advs, date, lang="en")`: the existing function gains a `lang` switch over a small string table (header, empty header, section header, single line, lead and release group lines, withheld line). English strings are the current ones, so English output is byte-identical.
- `lang_reply(body, of=None)`: `lang: ja`, optional `of: <64-hex>`, blank line, body; refuses a body holding an aitools-alert fence (`schema._last_block(...) is not _NONE`) and runs `_guard`.

### main.py

- `_item(..., ja=None)` stores the Japanese body (without the header) under a new item key `ja`. `plan_new`, `plan_known` and `digest` compose it inside a try that sets `ja=None` on ValueError, so a Japanese failure never withholds the English item.
- `deliver` (English item): after `_record` and removal from the outbox, if `it.get("ja")`, append, in the same state save as the removal, a journal item `{"key": K, "kind": "ja", "scope": it["scope"], "ids": ["ja " + K], "channel": it["channel"], "text": lang_reply(it["ja"], of), "adv": None, "exploited": False, "date": None, "sent": None, "root": target}` where for a root, copy or digest `target = it["sent"]` and `of = None`, and for a reply `target` is the thread root in that channel and `of = it["sent"]`. `K` is `it["key"] + ":ja"`, and for a reply `it["key"] + ":ja:" + it["sent"]` (one thread takes many replies under one English key). A replayed English item (crash after send) creates it once (the key is unique in the outbox). At `MAX_JA` (200) Japanese items in the journal, the oldest one neither sent nor pending is dropped first, so a backlog never grows the journal past the size `load_state` accepts.
- `drain()` and `busy()` skip `ja` items; `drain_ja()` runs on the success path after the state, with the new watermarks and the replaced `deferred` list, is saved: for each `ja` item, oldest first, finish it without a send if its id is journaled, skip if pending; mark pending under its key with no aliases (it matches no advisory id); send with `reply_to=root`; ok → journal the id, clear pending, remove, count `ja`; failed → clear pending, move it last in the journal, count `ja_failed`, stop Japanese sends; unknown → keep pending, count `ja_failed`, stop. No `_Stop`; any exception is reported, never the exit code.
- `SUMMARY` gains `ja` and `ja_failed` (before `inputs=`).
- The target of a reply's Japanese item is read from the ledger thread (`_entry(it).channel_ids[channel]`), never from a variable set only on the send path, so a replayed item and `resolve --delivered` queue it too; the Japanese item then sends on the next run.
- `resolve --delivered` on a `ja` key records it by removing it from the journal (a `ja` item has no ledger thread record).

### inputs.py

`_KINDS` gains `ja`. `_item_ok` accepts an item with the old key set or the old set plus `ja` (None or a non-empty str). A `ja` item must have `adv is None`, `root` a 64-hex id, `date is None`, `ja` absent or None, and `scope` None or a non-empty str.

### docs

docs/design.md "Post format": the format paragraph above, verbatim. README: one paragraph for members.

## Alternatives considered

- Compose the Japanese text at delivery time from the item's `adv`: a copy item has no `adv`, and a reply's changed keys and unverified reason would have to be re-derived from the English text. Rejected: composing at plan time beside the English is simpler and keeps one source of truth.
- Send each Japanese reply right after its original inside `enqueue`: an ssh round trip per item before the next English send delays the English posts, and a failure would have to be kept from raising `_Stop`. Rejected for the end-of-run drain.
- A Japanese failure exits 1: the hourly job's exit status would report English trouble that does not exist. Rejected; the summary's `ja_failed` and a stderr line report it.
- A config switch to turn Japanese off: not asked for; the format and the sibling reader issue assume every post has one.

## Blast radius and rollback

The poster's journal gains a kind; the deployed poster at 47f9d7a would refuse a state file holding a `ja` item (its `_item_ok` does not know the kind), and an English item that carries a `ja` body has a key set it refuses too, so a rollback first waits for an empty outbox, or removes the `ja` items and `ja` fields from the state file by hand under the ledger lock. An English item with no Japanese body is written without the field. English posting is unaffected by any Japanese failure. Rollback: revert the commits and reinstall.

## Assumes

- `transport.send(channel, text, reply_to)` makes an e tag marked root to `reply_to` (the thread rules, directive 01M6MRNTMKYE93MC28Y687SYJZ); a Japanese reply to a change reply therefore replies to the thread root and names the change reply in `of:`.
- "Its own ledger item" is met by the in-flight ledger entry keyed `<key>:ja` plus the journal item; a sent Japanese reply is not added to the thread's `replies` list, which holds advisory changes only.
