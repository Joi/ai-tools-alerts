# Plan: an @token renders as inline code (ai-tools-alerts#k5tr)

Spec: docs/superpowers/specs/2026-11-09-mention-inline-code-design.md

## Chunk 1 — compose-inline (one commit)

### Code: `aitools_alerts/poster/compose.py`

- [ ] Add, after `_guard`: `_URL_TOKEN = re.compile(r"https?://\S+")`,
      `_MENTION = re.compile(r"(?<!\S)@[A-Za-z0-9._-][!-_a-~]*")` and
      `_inline(text)`: percent-encode `` ` `` inside URL tokens, remove every
      other backtick, then wrap each `_MENTION` match in backticks with
      trailing `.,;:!?)]}'"` kept outside when at least one character
      follows the `@`.
- [ ] `_upstream`: remove backticks from the title (after the existing
      `"``"` / `"~~"` / newline refusals, before `_guard`).
- [ ] `root_post`: `schema.render_post(adv, _inline("\n".join(body)))`.
- [ ] `root_post_ja`: return `_inline("\n".join([...]))`.
- [ ] `reply_post_ja`: return `_inline("\n".join(body))`.
- [ ] `reply_post`: `out = _inline("\n".join(body)) + block...` (the block is
      appended after, unchanged; `parse_reply` round-trip unchanged).
- [ ] `digest`: per line, `lines.append(_guard(_inline(line)))`, so a line
      the guard refuses is withheld alone.

### Tests: `tests/poster/test_compose.py` (new section "k5tr")

- [ ] `test_inline_wraps_whitespace_at_tokens_only`: unit cases —
      `"see @scope/pkg."` → ``"see `@scope/pkg`."``; start of text and of a
      line; `https://mastodon.social/@user/1` and `a@b.c` untouched; a URL
      with a backtick gets `%60`; a stray backtick elsewhere removed; `"@ x"`
      untouched. `_inline` runs once per body (spec: not idempotent).
- [ ] `test_root_and_digest_wrap_a_scoped_package_title`: a candidate whose
      `source_title` names `@modelcontextprotocol/server-filesystem`: root
      (en and ja) and digest (en and ja) carry
      `` `@modelcontextprotocol/server-filesystem` ``; the parsed block equals
      the advisory and the block text equals the block of the same post with
      no title.
- [ ] `test_title_backtick_cannot_pair_with_ours`: title
      ``"a `b @scope/pkg c"`` → title line has exactly two backticks, around
      the token.
- [ ] `test_digest_shaped_like_2026_11_08_has_no_bare_mention`: 43
      high advisories (distinct ids, each its own line), four titled with the
      three `@modelcontextprotocol/...` package names (one twice); the head
      line says 43; exactly four wrapped tokens; en and ja digests have no match for `(?<!\S)@` outside backtick spans
      (strip `` `[^`]*` `` then search).
- [ ] `tests/poster/test_main.py::test_a_fence_in_the_title_never_withholds_the_advisory`
      (r7hr): its expected title line loses the lone backtick
      (`Race ~aitools-alert in Edit`); `_upstream` collapses the whitespace
      a removed backtick leaves.
- [ ] Each new test fails on the old `compose.py` (checked by swapping the
      file back to `HEAD`).
- [ ] `test_a_scoped_product_name_is_inline_code_in_roots_and_replies`: a
      scope entry named `@modelcontextprotocol/inspector` (schema `_NAME`
      allows a scoped name): the root head line, the English reply body and
      the Japanese reply and root carry the token in backticks; the reply
      block keeps the name unwrapped and parses back to the merged advisory.
      Removing either reply `_inline` call fails it (checked by mutation).

### Verification

- `python3 -m pytest tests/poster -q` while building.
- The repo has no `.repoman-managed` marker and no repoman registry row, so
  there is no scoped gate: the verification is the project's full suite,
  `python3 -m pytest tests -q` (the issue's acceptance command), run on the
  committed head.
- `git diff --stat origin/main` code+tests under 120 changed lines.

### Acceptance

Spec success criteria 1–6.

### Rollback

`git revert` of the chunk commit.
