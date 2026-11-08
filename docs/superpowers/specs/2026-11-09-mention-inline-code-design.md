# An @token in a post renders as inline code (ai-tools-alerts#k5tr)

## Problem

From 2026-11-08 08:20Z the relay refused the daily digest on every run:
`mention '@modelcontextprotocol' does not match a current channel member`.
Four digest lines carried a source title (r7hr) naming an npm scoped package,
`@modelcontextprotocol/server-filesystem` and two others. The relay CLI
(buzz-sdk `mentions.rs`, `extract_at_mentions_with_known`) reads every `@` at
the start of the text or after ASCII whitespace as a member mention of the
following `[A-Za-z0-9._-]+` token and refuses a name it cannot resolve. It
skips inline backtick spans and fenced blocks first. The poster cannot pass
`--mention`: the relay's forced command accepts only the 7- or 9-argument
`messages send` shape.

## Success criteria

1. Every rendered body the poster composes (`root_post`, `root_post_ja`,
   `reply_post`, `reply_post_ja`, every `digest` line in both languages)
   carries no `@` after whitespace or at the start of a line outside an
   inline code span. The token stays exact: `@scope/pkg` becomes
   `` `@scope/pkg` ``, never a dropped `@` or a hidden character.
2. A source title cannot supply a backtick: `_upstream` removes every
   backtick from a title (r7hr already collapses runs in `candidates._title`;
   a title stored before that, in held or deferred state, passes through
   `_upstream` too). A backtick in a URL is percent-encoded (`%60`, the same
   URL) in the body text; any other backtick in a body is removed. The only
   backticks left in a body are the poster's own pairs.
3. An `@` not preceded by whitespace (a URL path `/@user/`, an e-mail
   address) is untouched.
4. The `aitools-alert` block is unchanged: the wrap runs on the body before
   `schema.render_post` or the reply block is appended.
5. A fixture shaped like the journaled 2026-11-08 digest (43 advisories, four
   lines with `@modelcontextprotocol/...` titles) renders, in English and
   Japanese, with no bare `@` token after whitespace.
6. `python3 -m pytest tests -q` passes; under 120 changed lines of code and
   tests.

## Approach

One function in `compose.py`, `_inline(text)`:

1. In each `https?://\S+` token, replace `` ` `` with `%60`; then remove every
   other backtick.
2. Wrap each match of `(?<!\S)@[A-Za-z0-9._-][!-_a-~]*` (an `@` at the start
   or after whitespace, then a relay token character, then printable ASCII
   other than a backtick or space) in backticks. Trailing sentence
   punctuation (`.,;:!?)]}'"`) stays outside the span, unless trimming would
   leave the bare `@`.

The function runs exactly once on each body (it is not idempotent: a second
pass reads our closing backtick as part of a URL inside a wrapped token). It is
applied to the body text: in `root_post` before `render_post`, in
`reply_post` before the block is appended, to the joined lines of
`root_post_ja` and `reply_post_ja`, and to each digest line before its
publication guard (so a removed backtick can never make a host name that
withholds the whole digest instead of one line). `_upstream` drops backticks
before its guard.

ASCII printable is the run's character class so that a Japanese full stop
(`。`) or other non-ASCII text after a token ends the span; the relay's own
token stops at the first character outside `[A-Za-z0-9._-]`, so any span that
covers that token's characters is enough.

## Alternatives considered

- Insert a zero-width or other hidden character between whitespace and `@`.
  Rejected by the issue: hidden characters are forbidden and make the token
  inexact for a reader who copies it.
- Drop the `@`. Rejected: the package name is the fact.
- Pass `--mention`. Not available: the relay's forced command allows only the
  7- or 9-argument send shape.
- Wrap only in `_upstream` (the title). Rejected: a scope entry name or any
  future field naming a scoped package would fail the same way; wrapping the
  rendered body covers every field.
- A longer backtick delimiter chosen per line (CommonMark rule). Rejected:
  the relay's code-region stripping is a simpler scanner whose pairing rule
  for multi-backtick spans is not known; owning every backtick in the body is
  certain under any pairing rule.

## Not in scope

- `lang_reply` bodies from curator translation (`translate_curator`): curator
  text is a person's post that the relay already accepted, and removing its
  backticks would change its own code spans. The outbox Japanese text passes
  through `lang_reply` already wrapped by the compose functions above.
- The run-wedging behaviour (ai-tools-alerts#8acj).
- Live state: the coordinator reinstalls after landing. A saved outbox item
  keeps its rendered text (`deliver()` sends `it["text"]` as stored), so this
  fix does not repair an item already journaled; the 2026-11-08 digest was
  repaired by hand at 20:50Z (issue body), and a refused item wedging the run
  is ai-tools-alerts#8acj. The fix covers every item composed after install,
  starting with the 2026-11-09 digest.

## Blast radius and rollback

Presentation only: post bodies change only where a whitespace-preceded `@` or
a backtick appears; the block, the ledger and identity are untouched.
Rollback is a revert of the one commit; text already sent stays as sent.
