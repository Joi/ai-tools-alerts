# Public repo hygiene: fleet names out of code and docs (ai-tools-alerts#h6bx)

## Problem

The repo is public and is announced on 2026-11-10. Its tracked files name the
fleet's Macs, the relay VM's host name and login user, the wrapper and key-file
paths on that VM, and home-directory paths on the poster Mac. None is a
credential; together they map the posting pipeline. The issue's scan pattern
(the six fleet Mac names, the VM's domain and user, the home-directory prefix;
it lives only in `scripts/public-scan.sh`, which no scan reads) hits
37 tracked files: code (`poster/candidates.py`, `poster/transport.py`), tests
(`tests/poster/test_candidates.py`, `tests/poster/test_transport.py`,
`tests/test_templates.py`), the VM pieces (`ops/vm/README.md`,
`ops/vm/buzz-send`), the mirror units and exporter docstring, and the docs
(`docs/design.md`, `docs/plan.md`, `docs/superpowers/**`).

## Success criteria

1. `scripts/public-scan.sh` exits 0 on this branch and 1 when any tracked file
   (other than the script itself) matches the pattern; `scripts/test-gate.sh`
   runs it and fails when it fails.
2. No fleet host name, relay host, VM user or home path is in code. The poster
   reads them from its config:
   - `strip_hosts = [..]` — host names that drop a field or item (was
     `candidates.FLEET_HOSTS`); default empty.
   - `internal_host_suffixes = [..]` — extra source-host suffixes treated as
     internal, added to the generic built-in list (the VM domain suffix leaves the code);
     default empty.
   - `relay_ssh_host` — the ssh destination (was `transport.HOST`); default none.
   - `relay_send_wrapper` — absolute path of the wrapper on the VM (was
     `transport.WRAPPER`); default none.
3. `aitools-alerts-poster run` exits 2 with a config error, before the ledger
   opens or anything is sent, when `relay_ssh_host` or `relay_send_wrapper` is
   unset. `pending` and `resolve` do not need them.
4. `transport.send` and `transport.remote_argv` take host and wrapper as
   required arguments; no module default names a host or path.
5. `ops/vm/buzz-send` keeps its behaviour on the VM: the defaults become
   `$HOME`-relative (`$HOME/.buzz-keys/agent.nsec`, `$HOME/buzz/target/release/buzz`),
   which on the VM resolve to the same files.
6. Docs keep their technical content with generic names: "the poster Mac",
   "the relay VM", `<relay-vm>`, `<user>`, `~` or `$HOME` in place of home paths.
   Kura helper paths and the collector's state paths go.
7. The whole test suite passes. The brief's budget was under 400 changed lines; the
   deliverable is about 600 (tests asked for by the reviews account for most of the
   excess), and the overrun is recorded as `decided:` on ai-tools-alerts#h6bx.

## Approach

- `inputs.Config` gains the four fields; `load_config` validates them
  (string lists; suffixes start with "."; host matches `[A-Za-z0-9._@-]+` and
  does not start with "-"; wrapper is an absolute POSIX path with no whitespace
  or control characters). `Config.check_relay()` raises ConfigError when either
  relay key is missing.
- `candidates.FLEET_HOSTS` stays as the module's runtime list (default `()`) and
  a new `candidates.INTERNAL_SUFFIXES` (default `()`) joins the generic tuple;
  `main.run` sets both from the config at the start of each run
  (`candidates.configure(strip_hosts, suffixes)`). `compose._guard` already reads
  `candidates.FLEET_HOSTS` at call time, so compose.py (sibling rd8t's file) is
  untouched. The poster is a one-shot CLI process, so a module setting per run is
  safe; tests set it with monkeypatch.
- `main.run` calls `config.check_relay()` first and returns exit 2 with the
  error on stderr; `main()` does the same check after `load_config` for `run`.
  `Run.deliver` passes host and wrapper to `transport`.
- Tests use placeholder names (`relay.example.net`, `/opt/relay/bin/buzz-send`,
  `hostalpha`, `node-7`). `tests/test_templates.py` loses its host list (the
  public scan covers templates).
- Docs: name-only rewrites line by line; no paragraph restructuring. The
  "Post format" paragraph in docs/design.md is sibling rd8t's; only names change
  there.

## Alternatives considered

- Remove the whole `_INTERNAL_SUFFIXES` list from code: rejected; `.local`,
  `.internal`, `.lan`, `.home.arpa`, `.localhost` are generic and removing them
  weakens a default safety check. The VM domain suffix moves to config, and so
  (directive c:s5x5zq, which adds the tailnet domain to the scan) does the tailnet
  suffix; only the fleet runs the poster, so no member loses a default.

## Directive c:s5x5zq (addendum)

The scan also covers the tailnet name and domain, the persistent secrets cache
path, the two vault variable names and the pool's session paths. The docs use
`<ROOT_KEY_VAR>`, `<RELAY_KEY_VAR>`, `<persistent secrets cache>`, `<session scratchpad>`.
`scripts/sign-manifest.py` spelled the root key's vault variable and the
secrets-helper path, so it now takes both from the environment
(`AITOOLS_ALERTS_SECRET_NAME`, `AITOOLS_ALERTS_SECRETS_HELPER`), refuses before
any helper runs when either is missing or malformed, and passes them to bash in
its environment, never in the command text. This also closes ai-tools-alerts#2bf0.
The tailnet pattern is `\bts\.net\b`, not the bare `ts\.net`, which matched
`parts.netloc` in ordinary Python.
- Thread strip hosts through every adapter and compose as parameters: cleaner
  but touches compose.py and every call site, colliding with sibling rd8t today.
- Environment variables for the relay route: the poster's other settings are in
  config.toml; one place is easier to audit.
- Rewrite git history: out of scope (Joi's call, recorded on the issue).

## Blast radius and rollback

The live poster runs hourly at 47f9d7a. After this lands and the coordinator
reinstalls, a config without `relay_ssh_host`/`relay_send_wrapper` makes every
run exit 2 with nothing sent and nothing lost (watermarks do not move); a
config without `strip_hosts` lets fleet names through the candidate filter, but
`compose._guard` still refuses any post naming this machine's own host name.
The coordinator must therefore set all four keys to the current constants
before reinstalling. `ops/vm/buzz-send` changes bytes, so the installed copy
must be reinstalled to stay byte-identical (behaviour is the same). Rollback:
revert the commit and reinstall; the config keys are then unknown keys, so the
coordinator also removes them (load_config rejects unknown keys).

## Open questions

None blocking. Assumes the coordinator owns the live config and the VM
reinstall, per the issue.
