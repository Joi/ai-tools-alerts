# Plan: home from the password database, bounded hook PATH (ai-tools-alerts#fsmb)

Spec: docs/superpowers/specs/2026-11-06-home-from-passwd-design.md

## Chunk 1 — CLI paths (config.py, inventory.py, tests)

- [x] `aitools_alerts/config.py`: `import pwd`; add `home()` (passwd entry
      of `os.getuid()`, fallback `Path.home()` on KeyError or empty
      pw_dir); `config_dir()` (line 38) and `state_dir()` (line 50) use it;
      add `"home"` to `__all__`; module docstring says paths come from the
      password database, and tests patch `config.home`.
- [x] `config.py:142`: `telegram_token_file` expansion — `~` or `~/...`
      against `home()`, anything else `os.path.expanduser`.
- [x] `aitools_alerts/inventory.py:221`: default home `config.home()`
      (local import inside `collect`, keeping `collect` never-raises).
- [x] `tests/conftest.py` `home` fixture: also
      `monkeypatch.setattr(config, "home", lambda: h)`.
- [x] `tests/test_cli.py`: new test `test_paths_ignore_home`: with HOME set
      to a temp dir (no fixture patch), `config_dir`, `state_dir`,
      `key_path`, `Settings` default token path and a `~/x` token path are
      under `pwd.getpwuid(os.getuid()).pw_dir`, not the temp dir; and a
      patched `pwd.getpwuid` raising KeyError falls back to HOME.
- [x] `tests/test_inventory.py`: `collect()` with no `home` uses
      `config.home()` (patch it to the fixture home, HOME elsewhere; skills
      from the fixture are found).

Verify: `python3 -m pytest tests/test_cli.py tests/test_inventory.py tests/test_pull.py tests/test_curator.py -q`.

## Chunk 2 — hook (session-start.sh, tests/test_templates.py)

- [x] `hooks/claude-code/session-start.sh`: replace the PATH line with the
      spec's block between `# --- home: begin` / `# --- home: end` markers;
      header paragraph "HOME and PATH" replaces the PATH paragraph: the
      session's environment comes from the project's settings.json env
      block, so the hook takes HOME from the password database and runs the
      CLI with the launchd PATH only.
- [x] `tests/test_templates.py`: helper `_hook_copy(tmp_path, home)` writes
      the hook with the marked block replaced by `HOME=<home>; export HOME;
      PATH=...` (the same PATH line, kept from the real file) and returns
      its path; `_run_hook` and `test_hook_finds_the_cli_in_local_bin` put
      the stub in `<home>/.local/bin` and run the copy with a hostile PATH
      (`<tmp>/evil:/usr/bin:/bin`, holding a stub that writes a marker) —
      the good stub runs, the evil one does not.
- [x] New `test_hook_ignores_project_home_and_path`: run the real hook with
      HOME=`<project>` and PATH=`<project>/bin:/usr/bin:/bin`, stubs at
      `<project>/bin/aitools-alerts` and `<project>/.local/bin/aitools-alerts`
      that write a marker and exit 2; assert rc 0, no marker; stdout empty
      unless a real CLI is installed for the user (skip the stdout check
      then).
- [x] New `test_hook_home_block_reads_passwd`: run only the marked block
      plus `printf %s "$HOME|$PATH"` under `/bin/sh` with HOME=tmp; assert
      HOME = passwd home and PATH = the bounded list.
- [x] Marker-presence assertion so the copy helper fails loudly if the
      markers move.

Verify: `python3 -m pytest tests/test_templates.py -q`.

## Chunk 3 — README

- [x] README line 38: the hook searches the same dirs as the templates, and
      nothing else.
- [x] README hook section (after line 97): one paragraph — a project's
      `.claude/settings.json` env reaches the hook; the hook and the CLI
      take the home directory from the password database, not HOME, and the
      hook runs with the bounded PATH, so a project cannot choose the config,
      the state or the binary; a HOME that differs from the passwd home is
      not used.

## Amendments (spec review, and building)

See the spec's Amendments section; in the plan's terms: chunk 1 gains the
fail-closed `home()` and its two tests in tests/test_home.py, the conftest
change is an autouse fixture rather than a patch in `home`; chunk 2 gains
`env -i`, the all-digit check, and one real-hook probe test in place of the
two planned real-hook tests and the local-bin test (folded into
`_run_hook`); chunk 3 gains the absolute hook path.

## Acceptance

- `scripts/test-gate.sh` green.
- `git diff --numstat origin/main -- . ':!docs/superpowers'` under 200.
- Diff grep for fleet host names: 0 hits.

## Rollback

`git revert` the landed commit(s).
