# Japanese feed, reader side (ai-tools-alerts#yxd6)

## Problem

Joi asked on 2026-11-06 for a Japanese version of the alert feed. The poster
(ai-tools-alerts#rd8t) will post a Japanese translation as a reply in every
thread. Nothing on the reader side reads those replies: the CLI shows English
only, the mirror writes one English Atom feed, and the subscribe page has no
Japanese section. A podcast announcement on 2026-11-10 points Japanese
listeners at the feed.

## The format (from the issue body; the poster writes the same)

A translation is a reply in a thread (e tag marked `root`) from a manifest
key:

```
lang: ja
of: <event id>          (optional; absent = the thread's root)

<Japanese body>
```

No aitools-alert block. A lang reply that carries one is ignored entirely,
never read as a patch. The latest lang reply from a manifest key per target
wins. From a non-manifest key it is discussion (pull already drops such keys).

## Approach

### Parsing: `pull.parse_translation(content) -> (lang, of, text) | None`

- Lines split on CommonMark line endings (`schema._LINES`), as everywhere else.
- Line 1, stripped, matches `lang:\s*([a-z]{2,8})`.
- Line 2, if it is not blank, must be `of:\s*([0-9a-f]{64})`; then a blank
  line. Anything else: not a translation (and still not a patch).
- Body: the rest, each line cleaned of the characters `schema._text` rejects
  in titles (bidi controls, categories Cc, Cf, Cs, Zl, Zp), so a translation
  cannot put a terminal escape or a bidi override on the member's screen;
  trailing whitespace and leading/trailing blank lines stripped; at most
  `MAX_TRANSLATION_CHARS` (8000). Empty after cleaning: None.
- Any aitools-alert fence (`schema._last_block(content) is not schema._NONE`,
  closed, unfinished or too large): None.
- `translation_title(text)`: the first non-blank line, at most 200 characters.

### Pull: `Thread.translations: dict[str, str]`

In `advisories` (now `threads_from(events, manifest)`, which the exporter
calls too), a reply whose first line starts with `lang:` is handled after the
discussion rule and before the retract, level and patch rules, and never
reaches them (so a lang reply with a block is never a patch, malformed or
not). It is kept, the latest per language in (created_at, id) order, when it
names the thread's current version: the root (`of` absent or the root id)
until a reply changes the advisory (a patch or a level change applied), then
that reply. Each change drops the translations before it, so a Japanese
reader never sees a superseded advisory beside current actions; English
shows until the poster translates the change (`of: <that reply's id>`).
`Thread.translated_at` keeps each kept translation's created_at. A relay-bot
translation never replaces a curator's (code review). The CLI merges the
copies of one advisory (a critical has a root per channel): the latest
translation per language wins.

Decided (review pass 1): the existing discussion rule applies unchanged. Once
a curator posted or amended a thread, a relay-bot lang reply is discussion,
so bot text never appears under a curator's attribution. Rejected: any
manifest key (bot text shown as the curator's word) and "a bot translates
until a curator does" (same problem until then).

A translation does not change `updated_at`, the level, the actions, or what
is retracted. A translated title of a synthetic id (`CVE-2099-*`) gets the
`SYNTHETIC TEST: ` mark as `schema.validate` gives the English one.

### Config: `lang`

`config.toml` gains `lang` (string, `"en"` or `"ja"`, default `"en"`); any
other value is a `ConfigError` naming the key. The template gets a commented
line.

### CLI

`Entry` gains `translations` (from the first root of the group). With
`lang = "ja"` and a `ja` translation:

- `check` (text): the Japanese title replaces the English one in each match
  line and in the "Critical advisories not installed here" list.
- `plan`: the Japanese title in the header line and in "nothing installed here
  is affected", then the Japanese body, each line quoted as `    > <line>`,
  before the `source:` line. The quote mark means a body line can never be
  read as a section header or a `command:` line (agents run only those); the
  skill line says so.
- `notify` (and `run`): `format_text` puts the Japanese title on the first line
  and the Japanese body after it; the rest (Affected, Action, Source) is
  unchanged, and only the body is shortened to fit `MAX_TEXT`; when the
  translated title itself would push those fields past `MAX_TEXT`, the
  English text is sent.

Without a translation for the configured language, everything is English as
today. Level words, ids, thread refs, product names, versions, `describe()`
lines, `command:` lines and `nothing was executed` are never translated.

`check --json` and `run --json` carry `"translations": {lang: text}` on every
match, whatever `lang` is set to.

### Mirror: `feed.ja.atom`

`atom_doc` takes `lang` (`"en"` default, byte-identical output, checked by
running the exporter before and after the change on one input and comparing
the bytes; `"ja"`). The
exporter writes `feed.ja.atom` after `feed.atom`. For `ja`: the same entries
in the same order; the feed `title` is `ai-tools セキュリティアラート`, its id
and self link are `feed.ja.atom`, `xml:lang="ja"` on the feed; an entry with a
Japanese translation of its root (same parse and same curator-over-bot rule as
pull: `pull.threads_from` over the feed channel's events) takes the
translation's title and body. A root with no advisory block (the daily
digest) takes the latest `lang: ja` reply naming it under the same discussion
and curator rules. A Japanese entry's `updated` is the later of the English
entry's and the thread's newest reply (one past it for a withdrawal), so a
translation, or a change that dropped one, makes readers fetch it again; an
entry without a translation otherwise reads as the English one. A retracted
root reads `撤回: <title>` (Japanese title when translated) with the
retraction's text as the body. The feed `updated` is the latest entry
`updated`. Entry
ids are `urn:nostr:event:<id>:ja`, so a reader subscribed to both feeds does
not merge the two languages as one entry.

### Subscribe page

The `index.html` hgs0 adds gets a `日本語` section: the same subscribe block in
Japanese with the `feed.ja.atom` link. Plain Japanese, no romaji.

### Skills

`skills/claude-code/aitools-alerts/SKILL.md`, the hermes skill and
`snippets/AGENTS.md` get one line: the advisory text may be shown in Japanese
when `lang = "ja"`; the commands `plan` prints are unchanged. The test that
keeps the snippet and the skill word for word the same stays green.

## Success criteria

1. tests/test_pull.py: a root translation is kept; latest wins; `of:` naming
   another event is not kept; a lang reply with an aitools-alert block changes
   nothing (no translation, no patch, even a valid one); a non-manifest key's
   lang reply is ignored; a relay-bot translation does not replace a curator
   one; control and bidi characters are removed.
2. tests/test_check.py / test_cli.py: `lang = "ja"` shows the Japanese title in
   check, plan and the notify text, the commands unchanged; English fallback
   without a translation; `check --json` carries `translations`; a bad `lang`
   is a config error.
3. tests/mirror: `feed.ja.atom` written; translated, untranslated and retracted
   entries; `feed.atom` unchanged by the change; the index has the 日本語
   section and the link.
4. `scripts/test-gate.sh` passes; under 400 changed lines.

## Blast radius and rollback

Reader-only. A member who never sets `lang` sees exactly today's output,
except that `--json` gains a key. The exporter writes one more file. Rollback:
revert the commits; the VM's next 5-minute run stops writing `feed.ja.atom`
(the stale file stays until removed by hand).

## Alternatives considered

- A separate Japanese field inside the aitools-alert block: rejected by the
  issue (the block is the signed machine contract; translations are prose).
- Keeping translations of every event in the thread: no consumer needs them
  today; the dict stays keyed by language as the issue specifies.

## Open questions

None blocking. If the poster's format in docs/design.md (rd8t) differs, the
issue body is the contract and the difference goes to rd8t.
