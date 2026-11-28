# Hermes's real version (ai-tools-alerts#1qy4)

## Problem

Since 0.23, Hermes's `pyproject.toml` says `version = "0.0.0"`. The release a user runs comes from an install stamp or from the nearest release tag (upstream `hermes_cli/version_info.py`). ai-tools-alerts#0xq6 reads only `pyproject.toml` and treats an all-zero version as no version, so on every current install each Hermes alert is `may apply`: it never interrupts, never sets exit 2 and never notifies. A critical Hermes advisory reaches no member running a current Hermes.

`hermes --version` is not an option: it checks for updates over the network.

## What upstream does (read 2026-11-28 from an installed copy)

`get_version_info()` resolves in this order:

1. **Install stamp**, `<install root>/install-stamp.json` (`pm.paths.install_stamp_path`). JSON object read as UTF-8 with an optional BOM. Ignored when: not an object; no `commit`, or `commit` empty or all zeros; `updateMechanism` not one of `self`, `app-installer`, `electron-updater`, `external`, `microsoft-store`; `payload` is `light`; or `source` is `git`, the stamp's directory has a `.git`, and `git rev-parse HEAD` there names another commit. The release is `baseVersion` (`unknown` when absent); `displayVersion` adds the distance.
2. **Live git**, when the checkout has `.git`: the version is the highest of the tags merged into `HEAD` that match `^v(0|[1-9]\d{0,2})\.(0|[1-9]\d*)\.(0|[1-9]\d*)$` (`STABLE_TAG_RE`). With none, a CalVer tag `vYYYY.M.D` and the version in that tag's `pyproject.toml`.
3. Otherwise unknown.

## Approach

`inventory.collect_hermes(home, name, runner)` keeps its install path, `~/.hermes/hermes-agent`, and its `project.name == "hermes-agent"` check, and reads the version in this order:

1. **The stamp**, `~/.hermes/hermes-agent/install-stamp.json`, at most 64 KiB, under upstream's rules above, with three stricter ones. Its `baseVersion` must be a stable `X.Y.Z` (the tag pattern without the `v`); its `distance` must be `0` (the integer or the string), and `dirty` must be false or absent. Otherwise the stamp gives no version and the next source is tried. When the install has a `.git`, `git rev-parse HEAD` must succeed and name the stamp's `commit`, whatever the stamp's `source`; a failed or different answer discards the stamp (upstream keeps a stamp when the check fails, and only checks `source: git` stamps).
2. **`pyproject.toml`'s version**, when it is not all zeros: a release before 0.23.
3. **A release tag on `HEAD`**, when `.git` exists: `git --no-optional-locks -c core.fsmonitor=false -C <install> tag --points-at HEAD --list v[0-9]*`. The highest line matching `STABLE_TAG_RE`, compared as integers, is the version. Output that reached the runner's 4096-character cap gives no version, since a higher tag may lie past the cap. No such tag, or a failed run: no version.
4. Otherwise the installation is listed with no version (`may apply`), as today.

`Installed.path` stays the `pyproject.toml` path: it names the install, not the source of the version.

**Only an exact release is a version.** A version that reads too high hides an alert for code that has the flaw. One that reads too low hides one too: the matcher drops an installation below an advisory's lower bound (`>=0.23.1,<0.24.0`), and a checkout a few commits past `v0.23.0` may already carry a flaw first released in 0.23.1. So the inventory reports a version only when the running code is a release: the stamp says distance 0 and clean, or a stable tag points at `HEAD`. Anything between releases stays `may apply`, as it is today. Upstream's default for an official checkout is the `stable` channel (`update_channel.py`: "Unconfigured official checkouts track `stable`"), which updates to release tags, so the common install is on a tag. A checkout that fetched a release commit without its tags stays `may apply`.

**Why git through the runner.** Which tag names the running commit is in git's refs, and peeling an annotated tag reads a tag object, which only git does safely (packed refs, loose refs, the object store). The argv is fixed apart from the install path, which comes from the home directory the inventory already reads, never from a post or a config value. `tag --points-at` and `rev-parse` walk no history, touch neither the index nor the working tree, run no hook and take no optional lock.

`default_runner` runs any `git` argv with every inherited `GIT_*` variable removed, so a `GIT_DIR`, `GIT_CONFIG_*`, `GIT_OBJECT_DIRECTORY` or alternates variable from a hook cannot point the read at another repository; it sets `GIT_NO_LAZY_FETCH=1` (a partial clone fetches nothing to peel a tag) and `GIT_TERMINAL_PROMPT=0`. With no fetch, git starts no transport or credential helper, so the runner's 5 s timeout ends the only process. Tests inject the runner, as they do for every other probe; one test sets `GIT_DIR` to another repository and checks it is ignored.

Not taken: the CalVer fallback (it needs `git show <tag>:pyproject.toml`, and a checkout with only CalVer tags has a real version in `pyproject.toml`, step 2); the nearest merged tag, upstream's base version (the lower bound above); `displayVersion` (`0.23.0+5` is not in the advisory grammar and would read as unparsable-version, which notifies on every alert); a dirty check of a git checkout (it needs `git status`, which refreshes the index; a checkout edited by hand is its owner's code); other install locations such as the managed `~/.hermes/installs/` tree (no stamp or `.git` there on the install examined).

## Success criteria

- A stamp with a valid commit, mechanism, `baseVersion` `0.24.1` and distance 0, beside a `0.0.0` `pyproject.toml` and no `.git`, gives Hermes `0.24.1`; no `hermes` argv is run.
- Each stamp rejection above (all-zero or missing commit, bad mechanism, `light` payload, `baseVersion` `unknown` or `0.24.1+3`, distance 3 or absent, dirty, not JSON, a JSON list, over 64 KiB, `.git` present and `rev-parse` naming another commit or failing) falls through to the next source.
- With no stamp, a `0.0.0` project file and `.git`, tags on `HEAD` `v0.9.0`, `v0.10.0`, `v2026.1.5`, `v0.24.0-rc1`, `v01.2.3` give `0.10.0`.
- A real `pyproject.toml` version is still read as before; a placeholder with no stamp and no `.git`, or no tag on `HEAD`, is still no version.
- A real repository in a test: a tag on `HEAD` gives its version; one commit past the tag gives no version; a `GIT_DIR` pointing at another repository tagged `v9.9.9` changes nothing.
- `scripts/test-gate.sh` passes.

## Blast radius and rollback

`aitools_alerts/inventory.py` only: `collect_hermes` gains a runner argument, `collect` passes its runner, and `default_runner` cleans the environment of a `git` argv (the existing `git --version` probe included, which reads nothing from it). No wire format, schema, manifest, ruleset, scope file or state file changes. On a current Hermes install, alerts that matched `may apply` now compare against a version: some become `affected` (and interrupt when critical), some `not affected`. Rollback is a revert.

## Open questions

None blocking. Assumes the stamp sits beside the code in a checkout (upstream's rule for every tree except a Nix-sealed one, which does not live at `~/.hermes/hermes-agent`).
