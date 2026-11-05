# Plan: poster Japanese `lang: ja` replies

Spec: docs/superpowers/specs/2026-11-06-poster-japanese-replies-design.md. Kata ai-tools-alerts#rd8t.

## Chunk 1 — compose-ja (aitools_alerts/poster/compose.py)

- [ ] Tables beside the English ones: `_JA_LEVEL`, `_JA_KINDS` (aligned with `_KINDS`), `_JA_OPS` (aligned with `_OPS`).
- [ ] `_words_ja(affected)` → `（バージョン不明）`, `（全バージョン）`, `（1.0 以上、1.2 未満）`.
- [ ] `_ja_title(adv)`: match `adv.title` against each `(pre, kind)` of `_titles`; render `{mark}{name}: {未検証の if pre}{ja kind} ({id})`; else the English title.
- [ ] `root_post_ja(adv, reason, unexpressed)` → four Japanese lines (head with `SYNTHETIC TEST` and unverified marks in English; 影響/修正版; 対応; 出典).
- [ ] `reply_post_ja(merged, keys, source_url, reason)` → unverified line (English) + one Japanese line per key in `sorted(keys)` + `出典:`.
- [ ] `digest(advs, date, lang="en")` with a `_DIGEST` string table for `en` and `ja`; `_single` and `_group_line` take the table. English strings copied exactly.
- [ ] `lang_reply(body, of=None)`: header, refuse a block or a bad `of`, `_guard`.
- [ ] `root_post` returns unchanged; the `unexpressed` flag is recomputed by the caller via a small helper `fix_unexpressed(c)` (moved out of `root_post`, behaviour identical).

Verify: `python3 -m pytest tests/poster/test_compose.py -q` (existing pass unchanged) plus new tests below.

## Chunk 2 — journal-ja (main.py, inputs.py)

- [ ] inputs.py: `_KINDS |= {"ja"}`; `_item_ok` accepts keys `_ITEM_KEYS` or `_ITEM_KEYS | {"ja"}`; `ja` value None or non-empty str; a `ja`-kind branch (adv None, root hex, date None, no `ja` text, scope None or str) before the reply/root check.
- [ ] main.py `_item(..., ja=None)` writes `"ja": ja`.
- [ ] `_ja(fn, *a, **kw)` helper: call compose with positional and keyword arguments, return None on ValueError, KeyError or TypeError.
- [ ] `plan_new`: `ja = _ja(compose.root_post_ja, adv, reason, compose.fix_unexpressed(c))` for every root/copy item.
- [ ] `plan_known`: copies get the root-ja of `new`; replies get `_ja(compose.reply_post_ja, merged, patch keys, source url, reason)`. Patch keys come from the English reply's own block (`json.loads(schema._last_block(reply))`), so the Japanese lines name exactly what the English reply changed.
- [ ] `digest`: `ja = _ja(compose.digest, [...same items...], local.date(), lang="ja")`.
- [ ] `deliver`: after removal from the outbox, `self._queue_ja(it, reply_to)` (reply_to as computed for a reply; else `it["sent"]`), skipped when `ja` is falsy or the key is already journaled. `lang_reply` and `_item` checks inside a try: a ValueError drops the Japanese item (count `ja_failed`).
- [ ] `drain` skips `kind == "ja"`; `drain_ja()` after `digest()` in `run`; `deliver_ja(it)` as in the spec; `_record` is never called for `ja`.
- [ ] `SUMMARY += ("ja", "ja_failed")`.
- [ ] `resolve --delivered` with a `ja` item: skip the thread checks; `deliver` with `sent` set removes it (the `ja` branch at the top of `deliver`).

Verify: `python3 -m pytest tests/poster -q`.

## Chunk 3 — tests and docs

- [ ] tests/poster/test_main.py: `FakeSSH` routes `lang: ja` sends to `self.ja` (always ok unless `ja_queue` given), so existing `calls` assertions hold.
- [ ] New main tests: high root → one ja reply to the root event, no `of:`; critical → two ja replies, each to its channel's root; change reply in both channels → ja replies with `of:` = each English reply id, `reply_to` = that channel's root; digest → ja reply to the digest event; ja send fails → English sent, exit 0, item stays, next run sends it once, English not resent; ja unknown → pending under `<key>:ja`, English updates for the advisory still post next run; a state file without `ja` fields loads.
- [ ] New compose tests: root ja text (level word, 影響, 修正版, 対応, 出典, SYNTHETIC TEST kept, unverified kept), no-fix line, change lines, digest ja scaffold and group line, `lang_reply` header with and without `of:`, refusal of a block.
- [ ] docs/design.md "Post format": the format paragraph from the issue, verbatim, after the thread paragraph.
- [ ] README: one paragraph on the Japanese replies.

Verify: `python3 -m pytest tests -q`; `git diff origin/main --stat` under 400 lines excluding docs/superpowers; the fleet-host grep over added lines of code, tests and docs outside docs/superpowers (`git diff origin/main -- aitools_alerts tests README.md docs/design.md | grep '^+' | grep -Eic '<the six host names>'`) prints 0.

## Acceptance

S1–S9 of the spec; the whole suite green; English text of every existing test unchanged.

## Rollback

Revert the commits. Before reinstalling the old poster, the state file's outbox must hold no `ja` item (the old `_item_ok` refuses the kind).
