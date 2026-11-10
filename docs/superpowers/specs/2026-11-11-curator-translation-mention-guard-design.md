# Curator translation: no bare @token in the Japanese reply (ai-tools-alerts#mz81)

## Problem

The relay reads an `@` at the start of the text or after ASCII whitespace,
followed by `[A-Za-z0-9._-]+`, as a member mention, and refuses a send that
names an unknown member. It skips code regions (inline backtick spans and
fenced blocks) first; its pairing rule for unusual backtick runs is not known
(k5tr spec, 2026-11-09-mention-inline-code-design.md).

k5tr made every poster-composed body safe with `compose._inline`, which owns
every backtick in the body. It left one path out: `main.translate_curator`.
That path sends a curator event's own text to the model, and for an amendment
appends `_advisory_text(adv)` (`Affected: <product name> ...`). A product
named `@modelcontextprotocol/inspector` comes back bare in the Japanese
output, goes through `compose.lang_reply` unchanged, and the relay refuses the
send. The curator's own text can name such a token too, and the model can drop
backticks the curator wrote.

`_inline` cannot be applied to the translation: it removes every backtick it
did not add, which breaks the curator's own code spans. Wrapping only outside
existing spans is unsafe when the text has a lone backtick or a backtick run,
because the relay may pair backticks differently and its code-region strip can
then leave a whitespace-preceded `@`.

## Success criteria

1. A curator root whose product is `@scope/pkg` (named in its body) and an
   amendment whose advisory names it both yield a Japanese reply in which no
   `@` that starts a token follows the start of a line or whitespace outside
   a code span.
2. A curator text with its own code spans (`` `npm i @scope/pkg` ``) keeps
   them byte for byte when the translation keeps them.
3. A translation with a lone backtick or a backtick run is never altered: it
   is posted unchanged when it holds no `@` the relay could read as a mention,
   and is not posted (counted untranslated) when it does.
4. Poster-composed replies (`_queue_ja`) and `compose._inline` behave as
   before; existing tests pass unchanged.
5. `scripts/test-gate.sh` (public scan, then `python3 -m pytest -q`) passes.

## Approach

A post-translation guard in `compose`, applied to the model's output before
`lang_reply`, plus nothing on the source side.

`compose.mention_safe(text) -> str | None`:

- **Regular text** — no run of two or more backticks anywhere, no
  backslash immediately before a backtick, and an even number of backticks on
  every line. The relay's scanner (buzz-sdk `strip_code_regions`: a backtick
  pairs with the next backtick on the same line, the span is replaced by one
  space, no escapes) pairs these backticks 1st with 2nd, 3rd with 4th, within
  each line; a line-crossing left-to-right scanner and CommonMark's
  equal-length rule pair them the same way. A backslash before a backtick is
  excluded because CommonMark reads it as an escape and the relay does not. Split
  each line on backticks; even-indexed parts are outside spans. Wrap every
  mention-shaped token in an outside part with the same wrapping `_inline`
  uses (factored out as `_wrap_mentions`; a token at the start of an outside
  part counts, since stripping the span before it could leave it
  whitespace-preceded). If the wrapped text now holds a backtick run (a
  wrapped token touching an existing span), return None. Otherwise return it;
  span contents are never touched.
- **Irregular text** — return it unchanged if it holds no `@` followed by
  `[A-Za-z0-9._-]` at the start, after whitespace or after a backtick (the
  only places a code-region strip can make a mention: a region ends in a
  backtick); otherwise None.

`translate_curator`: `body = compose.mention_safe(memo[text])`; None raises
the existing `ValueError` path, so the event is recorded `untranslated` and
counted, like a translation that loses a token. The source text sent to the
model is unchanged.

`decided:` post-translation guard with a regular/irregular split. Rejected:
(a) wrapping `_advisory_text` with `_inline` before translation and requiring
the spans in `translate.tokens` — it covers only the advisory half, not a
token in the curator's own text or a span the model drops, and it changes the
model input and the token contract for no gain once the output is guarded;
(b) wrapping mentions only when the translation has no backtick — it leaves
every curator text with a code span untranslated whenever it names an
`@token` outside the span, where the regular case can wrap safely.

## Blast radius and rollback

Only curator translations change: a reply that would have been refused by the
relay is now wrapped or not posted. Nothing touches roots, digests, the block,
the ledger or poster-composed replies. Rollback: `git revert <commit>` on main
and push; then on the poster Mac, in its clone of the repo pulled to that
main, `uv tool install --force --reinstall .` (the package argument is the
clone), as k5tr's notice did; the next launchd run uses it.

## Assumes

- The relay never reads an `@` preceded by a non-whitespace, non-backtick
  character as a mention, before or after its code-region strip (k5tr's
  reading of buzz-sdk `extract_at_mentions_with_known`; the source is not on
  this host).
- Python's `\s` is a superset of ASCII whitespace, so the guard may wrap a
  token after a full-width space that the relay would ignore: harmless.

## Open questions

None.
