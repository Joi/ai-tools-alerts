# Tests never touch the real home (3h9j)

## Problem

A test run on a fleet Mac rewrote the member's real
`~/.config/aitools-alerts/config.toml` (mirror_url pointing at a pytest temp
directory, `trust_root_override = true`) and filled the real state directory
with test data (`last_ok_at` in 2099). Every reader on that Mac then pulled
from a missing file mirror and said "no checkpoint". A second Mac has test data
in its real state directory too.

Two holes let that happen:

1. `config.home()` reads the password database, never `HOME`. `tests/conftest.py`
   patches it to `Path.home`, which reads `HOME` — but `HOME` is the real home
   for every test that does not take the `home` fixture. So any test that reaches
   `config.config_dir()`, `config_path()`, `key_path()` or `state_dir()` without
   that fixture (for example `State()` with no `dir`, or `cli.main(["init"])`)
   reads and writes the real member's files.
2. A subprocess the suite starts resolves its own home from the password database,
   so a child reader that is not redirected writes the real home whatever the
   parent patched. Nothing notices afterwards.

The poster's `inputs.py` and `ledger.py` also take `Path.home()` at import, so
their defaults are the real home whenever `HOME` is.

The test that did the damage (`test_probe_zero`) is in no ref of the clone and no
worktree; it was never pushed. The fix has to be structural, not a patch to one
test.

## Success criteria

1. From the import of `tests/conftest.py` (before collection, and so before any
   test module or import-time `Path.home()`) to the end of the session, `HOME`,
   `XDG_CONFIG_HOME`, `XDG_STATE_HOME`, `XDG_DATA_HOME` and `XDG_CACHE_HOME`
   point into a per-session temporary directory, removed at exit. If that
   directory would overlap a guarded real directory, the suite stops at import.
2. From that same import, `config.home` in the pytest process is a guarded
   resolver that returns `HOME`. Resolving it to the real home or below fails
   the test even inside code that catches `Exception` (a recorded violation,
   asserted at teardown; outside a test, at session end). A path under the
   session home is never the real home; a path under the system temporary
   directory is not either, unless that directory is the real home or contains
   it.
3. A Python child the suite starts with the inherited environment takes the
   session home as its password-database home before any of its code runs:
   `PYTHONPATH` carries a `sitecustomize` (chained to the one it shadows) that, when `AITOOLS_ALERTS_TEST_HOME`
   is set, makes `pwd.getpwuid` report that home for the current uid. So a child
   reader reads and writes the session home, not the real one, before any I/O.
   (A child started with `-I`, `-s` or a hand-built environment is not covered by
   this; the redirect in `tests/mirror_helpers.released_reader` and criterion 4
   cover those.)
4. Backstop: a test whose run creates, changes or deletes anything in the real
   reader config or state directory, or the poster's, fails, naming what changed.
   The fingerprint covers every entry (files and directories, the directory
   itself included): type, mode, inode, size, mtime and ctime. It reads no file
   (the config directory can hold the member's key); ctime moves on every write,
   chmod or utime, so a same-size change with a restored mtime still shows. It is taken at session start and
   compared at session end too, so collection and session-scoped fixtures are
   covered.
5. `tests/test_home.py`, which deliberately checks the password-database
   resolver, uses the original resolver kept by `home_env` over a stubbed
   password entry that names a temporary home; it never resolves the real one.
8. (Added after the code review.) An audit hook in the pytest process refuses
   any open, listing, create, remove, rename, chmod or utime of a path inside a
   guarded real directory before the I/O happens, judged by the path as written
   and by where it resolves (a link either way), relative to its dir_fd when
   one is given, and by the path an open descriptor names; the
   refusal is recorded on the running test's guard, or the session's during
   collection. This covers explicit paths (`config.load(path)`,
   `State.load(dir=...)`) that never call `config.home`.
9. A nested pytest run (a Python child inheriting the redirect) still knows the
   true real home: the child hook keeps the true `pwd.getpwuid` beside its
   replacement, and the hook's chaining skips every hook of its own kind, so two
   generations start without a recursion.
6. The guard is itself tested: the resolver refuses the real home and a path
   below it and accepts the session home and temp paths; a temp root that is or
   contains the real home exempts nothing; the fingerprint sees a created file,
   an empty directory, a mode change and a same-size content change; a Python
   child with the inherited environment reports the session home from
   `config.home()`.
7. `scripts/test-gate.sh` passes.

## Approach

A new `tests/home_env.py`, imported first by `tests/conftest.py` beside
`git_env` (same pattern: it acts at import):

- `REAL_HOME` (password database, resolved), `SESSION_HOME` (`mkdtemp`),
  `ENV` = `HOME` and the four XDG variables into it plus
  `AITOOLS_ALERTS_TEST_HOME` and a `PYTHONPATH` entry for
  `SESSION_HOME/.pyhook/sitecustomize.py`; set in `os.environ` at import,
  re-set per test; `atexit` removes the directory.
- `PASSWD_HOME` = the original `config.home`; `config.home` replaced at import by
  the session guard's resolver.
- `under_real_home(p)`, `fingerprint()`, `changed()` as described above.
- conftest's autouse fixture re-sets `ENV`, installs a per-test guard, takes the
  fingerprint, and on teardown fails on a violation or a changed fingerprint.
  `pytest_sessionfinish` fails the session (exit status 1) on a session-guard
  violation or a change since import.

## Not done, and why

- A child that is not Python, or Python with `-I`/`-S` or a hand-built
  environment, is outside both the audit hook and the pwd redirect: reads there
  are not caught, writes are caught by the fingerprint after the fact.
- Create-then-delete inside one test leaves no trace in a fingerprint; criteria
  2 and 3 are what stop the write before it happens.

## Alternatives considered

- **Fingerprint only at session end.** Cheaper, but names no test; the point is to
  find the culprit. Rejected.
- **Read `HOME` in `config.home()` when a test flag is set.** Puts test logic in
  the shipped reader and gives the environment a way to choose the config, which
  `config.home()` exists to refuse. Rejected.
- **Block writes with a read-only real home (chmod).** Changes the member's real
  files' modes and races with a live reader. Rejected.

## Blast radius and rollback

Test code only (`tests/`), plus the run artifacts. A `sitecustomize` (chained to the one it shadows) on `PYTHONPATH` affects Python children of the test run only. No shipped module changes.
Rollback: revert the commit.

Accepted risk: a live reader on the same machine that writes its state while the
suite runs (a session-start hook firing mid-run) makes the test that was running
fail with the fingerprint message. The message says so; a re-run passes. No
fleet Mac runs a reader during a gate today.

## Repair outside the repo (not part of the diff)

- The issue's Mac: restore `config.toml` to the default (live mirror URL) with
  `aitools-alerts init --force`, move the test-written state directory to the
  Trash, then `aitools-alerts pull` and `aitools-alerts run --json`, quoted in
  the kata issue. That Mac has no installed CLI, so it runs from the merged
  checkout with a three-line launcher that calls `aitools_alerts.cli.main`
  (the package has no `__main__`).
- The second Mac: its state directory holds only test data and it has no
  config; move the state directory to the Trash.
- Host names go in kata comments only, never in the repository.
