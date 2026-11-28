# Plan: Hermes's real version (ai-tools-alerts#1qy4)

Spec: `docs/superpowers/specs/2026-11-28-1qy4-hermes-real-version-design.md` (revised after its review pass). One chunk; about 200 changed lines.

## Chunk 1 — inventory

Files: `aitools_alerts/inventory.py`, `tests/test_inventory.py`, `CHANGELOG.md`.

### Tests first (`tests/test_inventory.py`, after `test_hermes_placeholder_version_is_no_version`, line 273)

Helper `hermes_home(tmp_path, version="0.0.0", stamp=None, git=False)` writes `pyproject.toml`, `install-stamp.json` (a dict is dumped as JSON, a str or bytes written as is) and an empty `.git` directory under `tmp_path/.hermes/hermes-agent`. A recording runner answers `rev-parse HEAD` and `tag --points-at` argvs from a dict and records every argv. A valid stamp is `{"commit": "ab"*20, "updateMechanism": "self", "baseVersion": "0.24.1", "distance": 0}`.

- [ ] valid stamp, no `.git` → `0.24.1`; nothing is run (the runner is never called with a `git` or `hermes` argv).
- [ ] `distance` `"0"` (string) is accepted; a UTF-8 BOM before the JSON is accepted.
- [ ] `.git` present, `rev-parse` answers the stamp's commit → `0.24.1`.
- [ ] each rejection falls through to the tag (`.git` present, `tag --points-at` answers `v0.23.1`, `rev-parse` answers the stamp's commit unless the case says otherwise), parametrized: commit all zeros; commit missing; mechanism `pip`; payload `light`; `baseVersion` `unknown`; `baseVersion` `0.24.1+3`; `baseVersion` `v0.24.1`; distance 3; distance absent; distance `true`; `dirty` true; not JSON; a JSON list; over 64 KiB (valid JSON padded with spaces); `rev-parse` names another commit; `rev-parse` fails (runner None).
- [ ] the intrinsic rejections (all but the two `rev-parse` cases) with no `.git` → version None; with no `.git`, a stamp is accepted without any `rev-parse` run (the first case).
- [ ] tags `v0.9.0`, `v0.10.0`, `v2026.1.5`, `v0.24.0-rc1`, `v01.2.3`, `v1.2` on `HEAD` → `0.10.0`; the argv is exactly `("git", "--no-optional-locks", "-c", "core.fsmonitor=false", "-C", <install>, "tag", "--points-at", "HEAD", "--list", "v[0-9]*")`.
- [ ] tag output of exactly 4096 characters (a valid `v0.23.1` first, padding lines after): version None, since a higher tag may be past the cap; output of 4095 characters is read.
- [ ] no `.git`: git is never run, version None. Runner answers None: version None.
- [ ] a real `pyproject.toml` version (`0.15.1`) with `.git` and a tag: `0.15.1`, and no git argv was run; a valid stamp beats a real project version.
- [ ] integration (skip when `shutil.which("git")` is None): a real repository at `~/.hermes/hermes-agent` (git run with `-c user.name=t -c user.email=t@example.invalid -c commit.gpgsign=false -c tag.gpgsign=false`), annotated tag `v0.23.0` on the only commit → `inventory.collect(home, apps_dirs=[])` with the default runner reads `0.23.0`; with `GIT_DIR` set (monkeypatch) to a second repository whose `HEAD` carries `v9.9.9`, still `0.23.0`; after one more commit, None.
- [ ] `default_runner` with a `git` argv passes an environment with no inherited `GIT_*` variable except `GIT_NO_LAZY_FETCH=1` and `GIT_TERMINAL_PROMPT=0` (monkeypatch `subprocess.run` and inspect `env`); a non-git argv keeps `env=None`.

### Code (`aitools_alerts/inventory.py`)

- [ ] constants: `MAX_STAMP_BYTES = 64 * 1024`; `_HERMES_RELEASE = re.compile(r"(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)")` (fullmatch; a tag is `v` plus this); `_HERMES_MECHANISMS = frozenset({"self", "app-installer", "electron-updater", "external", "microsoft-store"})`; `_HERMES_TAGS = ("git", "--no-optional-locks", "-c", "core.fsmonitor=false", "-C")`.
- [ ] `default_runner`: `env` is `None` for a non-git argv; for `argv[0] == "git"`, `os.environ` minus every `GIT_*` key, plus `GIT_NO_LAZY_FETCH=1`, `GIT_TERMINAL_PROMPT=0`.
- [ ] `_read(path, limit=MAX_CONFIG_BYTES)`.
- [ ] `_hermes_head(root, runner) -> str | None`: `git ... -C root rev-parse HEAD`, first line, 40 or 64 hex.
- [ ] `_hermes_stamp(root, runner) -> str | None`: spec rule 1; reads with `encoding utf-8-sig`; `distance` is `0` only when `(type(d) is int and d == 0) or d == "0"`; when `(root / ".git").exists()`, `_hermes_head` must equal the commit.
- [ ] `_hermes_tag(root, runner) -> str | None`: spec rule 3; highest by `tuple(int)`.
- [ ] `collect_hermes(home, name, runner=default_runner)`: project file check as today, then stamp, real project version, tag; docstring states "only an exact release is a version" and why git runs.
- [ ] `collect` (line 521): pass `runner`.
- [ ] module docstring: the Hermes probes are the only argvs that carry a path, the install directory under the home directory.

### CHANGELOG.md

- [ ] One paragraph at the top of `## Unreleased`: what changed, that a checkout between releases stays `may apply`, no wire/schema change, rollback is a revert.

## Verification

`python3 -m pytest tests/test_inventory.py -q`, then `scripts/test-gate.sh`.

## Acceptance

Each spec success criterion is one of the tests above; the gate passes.

## Rollback

Revert the commit.
