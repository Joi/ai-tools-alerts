# Plan: public repo hygiene (ai-tools-alerts#h6bx)

Spec: docs/superpowers/specs/2026-11-06-public-repo-hygiene-design.md. Base 47f9d7a.
Shell scripts longer than one line go to the scratchpad and run as files (jibot-code#y1f2).
"The pattern" below is the one in `scripts/public-scan.sh`; no other file spells it.

## Chunk C1 — config keys, code, tests

- [ ] `aitools_alerts/poster/inputs.py` `Config` (line ~58): add
  `strip_hosts: tuple[str, ...] = ()`, `internal_host_suffixes: tuple[str, ...] = ()`,
  `relay_ssh_host: str | None = None`, `relay_send_wrapper: str | None = None`;
  `check_relay()` raises `ConfigError("relay_ssh_host and relay_send_wrapper must be set")`.
  `load_config` (line ~81): lists of non-empty strings without whitespace or
  control characters (suffixes also start with "."), lowercased;
  `relay_ssh_host` matches `[A-Za-z0-9][A-Za-z0-9._@-]*`;
  `relay_send_wrapper` matches `/[A-Za-z0-9._/-]+`.
- [ ] `aitools_alerts/poster/candidates.py`: `FLEET_HOSTS = ()` with a comment that
  `main.run` fills it from `strip_hosts`; `INTERNAL_SUFFIXES = ()` from
  `internal_host_suffixes`; `_INTERNAL_SUFFIXES` loses the VM domain suffix; `_internal_host`
  checks both; `configure(strip_hosts, internal_suffixes)` sets both.
  `compose._guard` reads `candidates.FLEET_HOSTS` at call time: compose.py untouched.
- [ ] `aitools_alerts/poster/transport.py`: drop `HOST`/`WRAPPER`;
  `remote_argv(channel_id, reply_to=None, *, wrapper)` validates wrapper (absolute
  path, `ValueError` otherwise); `send(channel_id, content, reply_to=None, ssh=None, *,
  host, wrapper, timeout=TIMEOUT)`; module docstring names "the relay VM".
- [ ] `aitools_alerts/poster/main.py`: `run()` after `load_config`: `config.check_relay()`
  inside the try that returns `(2, summary)` with `error=config` and the message on
  stderr, before the ledger opens; then `candidates.configure(...)`. `Run.deliver`
  passes `wrapper=`/`host=` from `self.config`. `main()` `run` branch calls
  `cfg.check_relay()` inside its ConfigError try (exit 2).
- [ ] Tests: `tests/poster/test_transport.py` placeholders `relay.example.net`,
  `/opt/relay/bin/buzz-send`, `op@relay.example.net`; new tests: send without
  host/wrapper is a TypeError; a relative wrapper is a ValueError.
  `tests/poster/test_inputs.py`: the four keys load, bad values refused, defaults
  empty/None, `check_relay` refuses. `tests/poster/test_main.py`: every config of a
  run that should succeed (the env fixture, the TOML files the CLI tests write, the
  two replacement `Config(...)` calls) carries the relay keys; new tests: no relay
  keys → exit 2, no ssh call, no ledger file; a run from a loaded TOML config sends
  to exactly the configured destination and wrapper, and drops an item naming a
  configured strip host. `tests/poster/test_candidates.py`: placeholders for fleet
  names and the VM domain via an autouse fixture setting `candidates.FLEET_HOSTS` /
  `INTERNAL_SUFFIXES` with monkeypatch; home-path strings use an invented user; `tests/test_templates.py` drops the host list
  (the scan covers templates) and keeps the `/Users/`, `/home/` checks.
- Verify: `python3 -m pytest -q` passes.
- Acceptance: the pattern hits no file under `aitools_alerts/` or `tests/`.

## Chunk C2 — scrub non-code files; public scan in the gate

- [ ] `ops/vm/buzz-send`: header comment generic; defaults `$HOME/.buzz-keys/agent.nsec`
  and `$HOME/buzz/target/release/buzz` (same files on the VM). `tests/test_buzz_send.py`
  gains a run with a temporary HOME and no overrides, key and stub CLI at the default
  paths (key delivered, relay pinned, exit 0), and one with HOME unset (exit 1).
- [ ] `ops/vm/README.md`, `mirror/aitools-alerts-mirror.{service,timer}`,
  `mirror/export_mirror.py` docstring: `<relay-vm>`, `<user>`, `~/alerts-mirror`. In a
  command typed on the Mac the remote path is quoted (`ssh <relay-vm> '~/bin/buzz-send' ...`)
  so the local shell does not expand `~`.
- [ ] `docs/design.md`, `docs/plan.md`, `docs/superpowers/**`: replace names line by
  line: fleet Macs → "the poster Mac" / "the security-watch Mac" / "this Mac";
  VM host → `<relay-vm>`; VM user → `<user>`; `/home/<vm user>/` → `~/`;
  `/Users/<user>/...` paths → a repo-relative path or a description ("the jibot
  workspace's security-watch runbook", "the primary checkout"); Kura helper paths →
  "the Kura edit helper" / "the Kura secrets helper"; the collector's state paths →
  "the collector's state directory". Leak-grep commands in old plans become
  `scripts/public-scan.sh`. Keep the technical content.
- [ ] `scripts/public-scan.sh`: `git ls-files -z` minus itself, `grep -nIE` with the
  pattern; prints hits, exit 1 on a hit, 0 clean, 2 if not in a git checkout.
  `scripts/test-gate.sh` runs it before pytest and fails on non-zero.
- Verify: `scripts/public-scan.sh` → exit 0; a temp tracked file with a name → exit 1
  (in a scratch clone); `scripts/test-gate.sh` → exit 0.
- Acceptance: scan clean; under 400 changed lines in the deliverable
  (`git diff --shortstat origin/main -- . ':!docs/superpowers/*/2026-11-06-public-repo-hygiene*'`);
  this run's own spec, plan and manifest are records and are counted apart.

## Rollback

Revert the commits; the coordinator removes the four keys from the live config
(unknown keys are refused) and reinstalls; reinstall `ops/vm/buzz-send` on the VM.

## Out of scope (follow-up)

`scripts/sign-manifest.py` sources the Kura secrets helper by its path: code on the
signing path (credential handling); a follow-up issue moves it to an environment
setting rather than widening this run.
