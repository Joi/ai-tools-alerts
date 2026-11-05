# Plan: Japanese feed, reader side (ai-tools-alerts#yxd6)

Spec: docs/superpowers/specs/2026-11-06-japanese-feed-design.md. Budget: under
400 changed lines (code + tests). Standard library only.

## Chunk 1 — CLI

- [ ] `aitools_alerts/pull.py`
  - `MAX_TRANSLATION_CHARS = 8000`; `_LANG = re.compile(r"lang:\s*([a-z]{2,8})")`,
    `_OF = re.compile(r"of:\s*([0-9a-f]{64})")`.
  - `parse_translation(content) -> tuple[str, str | None, str] | None` and
    `translation_title(text) -> str` per the spec; both in `__all__`.
  - `Thread` gains `translations: dict = field(default_factory=dict)`.
  - `advisories` becomes `threads_from(events, m)` (the exporter calls it too).
    The root record gains `{lang: (text, at, by_curator)}` and the id of the
    current version (the root, then the last reply that changed the advisory).
    In the reply loop, AFTER the discussion check (a bot reply on a curator
    thread is discussion, lang replies included): if
    `_first_line(content).startswith("lang:")`, parse; if it parses, names the
    current version (`of` or the root id), and does not replace a curator's
    translation with a bot's, store it; `continue` in every case. A patch or
    level change clears the translations and becomes the current version.
- [ ] `aitools_alerts/config.py`: `LANGS = ("en", "ja")`; `Settings.lang = "en"`;
  `load` validates `lang`; TEMPLATE gains
  `# lang = "ja"   # show advisory text in Japanese where a translation exists`.
- [ ] `aitools_alerts/notify.py`: `format_text(adv, m=None, text=None)`: when
  `text` is given, the first line is `LEVEL: <translation_title(text)>` and the
  rest of the translation's lines follow it; then Affected/Action/Source as now.
- [ ] `aitools_alerts/cli.py`
  - `Entry.translations: dict` (from `c[0].translations`).
  - `_tr(t, s) -> str | None`: `t.translations.get(s.lang)` unless `s.lang == "en"`.
  - `_title(t, s)`: Japanese title or `t.adv.title`.
  - check text lines, the critical-not-installed list, plan header and the
    "nothing installed" line use `_title`; plan prints the body (lines after
    the title, each quoted `    > `) before `source:`.
  - `Entry.translations` merges the copies (the latest per language).
  - notify: when the translated title would not fit with Affected/Action/
    Source, the English text is sent.
  - `_notify` passes `_tr(t, s)` to `format_text`.
  - `_match_json` adds `"translations": dict(t.translations)`.
- [ ] Tests
  - tests/test_pull.py: root translation kept; latest wins; `of:` another id
    ignored, `of:` the root id kept; lang reply with a valid patch block changes
    neither the advisory nor translations; unknown key ignored; bot does not
    replace a curator translation, curator replaces bot; control/bidi removed;
    malformed (no blank line) ignored.
  - tests/test_cli.py: config `lang = "ja"`: check shows the Japanese title,
    plan shows title+body and the same `command:` line as English, notify
    text first line Japanese; English fallback when not translated;
    `check --json` has `translations`; `lang = "fr"` exits 1 naming `lang`.
  - tests/test_check.py: not touched unless a check-level test is needed
    (check.py itself does not change).
- Verify: `python3 -m pytest -q tests/test_pull.py tests/test_cli.py`.

## Chunk 2 — mirror (after `git fetch origin` and a rebase onto hgs0)

- [ ] `mirror/export_mirror.py`
  - Translations of advisory roots from `pull.threads_from` (the CLI's rule);
    roots with no block (a digest) take the latest `lang: ja` reply naming
    them under the same discussion and curator rules, in (created_at, id) order.
  - `atom_doc(..., lang="en")`: `ja` changes feed title/id/self link,
    `xml:lang`, entry id suffix `:ja`, title/body from the translation,
    `updated` = the later of the English entry's and the thread's newest
    reply (past it for a withdrawal), retraction prefix `撤回: `. `en` output
    byte-identical: checked against the e6594cf exporter on one input.
  - `export` writes `feed.ja.atom` right after `feed.atom`; result gains
    `atom_ja_entries` only if summary_line needs it (keep the summary as is).
  - index.html (hgs0's writer): add the 日本語 section with the Japanese
    subscribe block and the `feed.ja.atom` link.
- [ ] tests/mirror/test_export.py: the file set includes `feed.ja.atom`;
  translated / untranslated / retracted entries; a lang reply with a block not
  used; a stranger's translation not used; `feed.atom` unchanged with a
  translation present; index has `日本語` and `feed.ja.atom`.
- Verify: `python3 -m pytest -q tests/mirror`.

## Chunk 3 — skills

- [ ] One line in skills/claude-code/aitools-alerts/SKILL.md, the hermes
  skill and snippets/AGENTS.md (same words where test_templates requires).
- Verify: `python3 -m pytest -q tests/test_templates.py`.

## Whole result

- `scripts/test-gate.sh` (full suite) green; `git diff --stat origin/main`
  under 400 lines of code+tests; grep the diff for fleet host names; one
  fresheyes pass (gpt-6-astra) on the whole branch, then the brief's ending.

## Acceptance

Spec success criteria 1–4.

## Rollback

`git revert` the branch's commits on main.
