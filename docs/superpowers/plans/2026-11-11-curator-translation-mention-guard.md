# Plan: curator translation mention guard (ai-tools-alerts#mz81)

Spec: docs/superpowers/specs/2026-11-11-curator-translation-mention-guard-design.md

One chunk, test first. Gate: `scripts/test-gate.sh` (public scan, then
`python3 -m pytest -q`).

## Chunk 1 — guard

### Files

- `aitools_alerts/poster/compose.py` (around lines 117-134, `_MENTION` and `_inline`)
- `aitools_alerts/poster/main.py` (around line 388, the `memo[text] is not None` block in `translate_curator`)
- `tests/poster/test_compose_mentions.py` — new unit tests for `mention_safe`
  (or appended to the existing compose test file that holds k5tr's `_inline` tests)
- `tests/poster/test_translate.py` — poster-pass tests through `cur.trun`

### Steps

- [ ] 1. Unit tests for `compose.mention_safe` (fail first: the function does not exist):
  - bare `@scope/pkg` after a space and at line start in text with no backtick → wrapped, rest unchanged;
  - trailing punctuation stays outside the span (`@scope/pkg.` → `` `@scope/pkg`. ``);
  - `https://example.invalid/@user` and `a@b.example` untouched;
  - already wrapped `` `@scope/pkg` `` → unchanged (idempotent: `mention_safe(mention_safe(x)) == mention_safe(x)`);
  - curator span `` `npm i @scope/pkg` `` plus a bare `@other/pkg` outside → span byte for byte, the outside one wrapped;
  - wrapped token touching a span (`` `code`@x ``, `` @x`code` ``) → None;
  - lone backtick, no `@` token → returned unchanged; lone backtick plus ` @x` → None; lone backtick plus `` `@x` `` → None;
  - fenced block (```` ``` ````) with `@x` → None, without → unchanged;
  - backslash-escaped backtick (the review's two cases: ``\` @scope/pkg ` `` and
    ``\`literal`npm i @scope/pkg --help` tail ` ``) → None, never altered;
  - Japanese text: `対象は@scope/pkg` (no whitespace before `@`) → unchanged; full-width space before `@` → wrapped.
  - Every non-None result passes the test's own independent checker
    `relay_mentions(text)`, a Python port of buzz-sdk `strip_code_regions`'s
    inline rule (a backtick pairs with the next backtick on the same line; the
    span becomes one space; a fenced block opened by ```` ``` ```` at a line
    start, after optional ASCII whitespace, runs to the end of its closing
    fence line, or to the end of text, and becomes one space) followed by its
    `@` rule with `known_names=[]` (start or ASCII whitespace, then
    `[A-Za-z0-9._-]`): it must return no names. It models the refusal the
    relay makes for an unknown ASCII name, the property the spec guarantees;
    a known member's name is a valid mention and out of scope.
- [ ] 2. Implement in `compose.py`: factor `_wrap_mentions(text)` out of `_inline` (same `wrap` closure, `_MENTION.sub`), `_inline` calls it; add `_LIVE_AT = re.compile(r"(?:^|(?<=[\s`]))@[A-Za-z0-9._-]")` and `mention_safe` per the spec. Run the new tests and the existing k5tr tests (`python3 -m pytest tests -q -k "inline or mention"`).
- [ ] 3. Poster-pass tests in `tests/poster/test_translate.py` (fail first):
  - root whose body names `@modelcontextprotocol/inspector`; the fake model returns the token bare → the journaled reply (`ssh.ja`) carries it wrapped and `bare()` holds;
  - amendment whose patched product is `@scope/pkg` (the `_advisory_text` path) → same;
  - curator text with its own code span, model keeps it → reply body equals the model output exactly (span intact);
  - model output with a lone backtick and a bare `@x` → no reply, ` untranslated=1 `;
  - model output with a lone backtick and no `@` → reply equals the output unchanged.
- [ ] 4. Wire in `main.translate_curator`: `safe = compose.mention_safe(memo[text])`; `if safe is None: raise ValueError("a mention the relay would refuse")`; `body = safe + "\n\n" + translate.MARK`. Nothing else changes (the source text sent to the model is unchanged).
- [ ] 5. `scripts/test-gate.sh` passes; `git diff --stat` under ~150 changed lines of code and tests.

### Acceptance

The spec's success criteria 1-5. Red before green: every `mention_safe` unit
test (the function does not exist on the parent), and the poster-pass wrapping
and rejection cases. The two poster-pass preservation cases (curator code span
kept; lone backtick with no `@`) already pass on the parent and stay as
regression tests. Every fake model output keeps the source's URL, version and
id tokens (`translate.tokens`), so a rejection comes from the new guard, not
from `translate.translate` returning None; the rejection test asserts the
call happened and the event is recorded `untranslated`.

### Rollback

`git revert <commit>` on main and push; then on the poster Mac, in its clone
pulled to that main, `uv tool install --force --reinstall .` (as k5tr's notice
did). The next launchd run uses it.

## After the chunk

- Commit; independent whole-branch review (fresheyes, `git diff origin/main...HEAD`) ∥ Stage-1 same-model pass; dispose of findings.
- Fast-forward main, push, close-out comment, `kata close` with `--commit`.
- Live: reinstall on the poster Mac from main; `notice:` comment naming the install and the revert. No live post fired to test.
