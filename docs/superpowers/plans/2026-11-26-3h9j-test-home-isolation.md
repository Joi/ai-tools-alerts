# Plan: tests never touch the real home (3h9j)

Spec: docs/superpowers/specs/2026-11-26-3h9j-test-home-isolation-design.md

One chunk; test code only.

## Chunk 1 — session home, guarded resolver, child redirect, fingerprint

- [ ] `tests/home_env.py` (new)
  - `REAL_HOME`: `pwd.getpwuid(os.getuid()).pw_dir`, resolved; `None` without an entry.
  - `SESSION_HOME = mkdtemp(prefix="aitools-alerts-test-home-")`, resolved; `atexit` rmtree.
  - Refuse at import (raise `RuntimeError`) when `SESSION_HOME` is a guarded
    directory, below one, or above one.
  - `TEMP_ROOT = gettempdir()` resolved; `TEMP_EXEMPT = TEMP_ROOT` unless it is
    `REAL_HOME` or an ancestor of it, else `None`.
  - Write `SESSION_HOME/.pyhook/sitecustomize.py`: when
    `AITOOLS_ALERTS_TEST_HOME` is set, wrap `pwd.getpwuid` so the current uid's
    entry carries that home (`pwd.struct_passwd` with `pw_dir` replaced).
  - `ENV`: `HOME`, `XDG_{CONFIG,STATE,DATA,CACHE}_HOME`, `AITOOLS_ALERTS_TEST_HOME`,
    `PYTHONPATH` = pyhook dir + the existing `PYTHONPATH`; `os.environ.update(ENV)`.
  - `GUARDED`: reader config/state and poster config/state under `REAL_HOME`.
  - `under_real_home(p)`, `fingerprint(dirs=None)` (every entry, the directory
    itself included: relative path, type, mode, inode, size, mtime_ns, ctime_ns;
    no file is read), `changed(a, b)`.
  - `Guard`: `violations`, `check(p)` (record + `pytest.fail`), `home()`.
  - `PASSWD_HOME = config.home` (imported from `aitools_alerts`), then
    `SESSION = Guard()`; `config.home = SESSION.home`; `BASELINE = fingerprint()`.
- [ ] `tests/conftest.py`
  - `import home_env` right after `git_env` (before `aitools_alerts` imports).
  - `_home_from_env` becomes a generator fixture: re-set `ENV`, per-test `Guard`,
    patch `config.home`, fingerprint before/after, `pytest.fail` on violation
    or change.
  - `pytest_sessionfinish(session, exitstatus)`: on a `SESSION` violation or
    `changed(BASELINE, fingerprint())`, print the reason and set
    `session.exitstatus = 1`.
- [ ] `tests/test_home.py`: `REAL_HOME = home_env.PASSWD_HOME` (the guard is
  installed at conftest import now, so `config.home` there is the guard).
- [ ] `tests/test_home_guard.py` (new): criterion 6 cases —
  resolver refuses real home and a path below (with `Guard().check`, catching
  `pytest.fail.Exception` and resetting violations); accepts session home and
  a temp path; `under_real_home` with a monkeypatched `TEMP_EXEMPT=None`
  case; fingerprint diffs for created file, empty dir, chmod, same-size
  content change with restored mtime (on tmp dirs); env during a test has
  HOME and XDG under `SESSION_HOME`; a `sys.executable -c` child with the
  inherited env prints `config.home()` == `SESSION_HOME`.

Verification: `python3 -m pytest -q tests/test_home_guard.py tests/test_home.py
tests/test_cli.py`, then `scripts/test-gate.sh` (the repo gate; ~11 min).

Acceptance: spec criteria 1–7; the gate passes; `git diff` names no host, VM,
tailnet, home path or personal email (the public scan in the gate checks).

Rollback: revert the commit; nothing outside `tests/` and `docs/superpowers/`.
