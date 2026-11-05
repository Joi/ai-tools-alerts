# Plan: E3 live acceptance

Spec: docs/superpowers/specs/2026-11-05-e3-live-acceptance-design.md. Scripts live in the session scratchpad; none is committed. Every evidence line goes to docs/superpowers/runs/2026-11-05-e3-live-acceptance.md as it is produced.

## C1: manifest v2

- [ ] Mint the test key: a scratch script calls `aitools_alerts.nostr.keygen()`, writes the nsec to ~/.config/aitools-alerts/key.nsec with O_EXCL and mode 0600, prints the pubkey only. Verify: `stat -f %Lp` prints 600.
- [ ] Write the v2 content file (scratch): version 2, issued_at now, the two v1 posters plus `{"name": "test-curator-2026-11-05", "pubkey": <hex>, "role": "curator"}`.
- [ ] `python3 scripts/sign-manifest.py <content> --out trust/manifest.json`; it prints the event id only.
- [ ] Verify: `python3 -m pytest -q` (scripts/test-gate.sh) green; a scratch check loads trust/manifest.json through `aitools_alerts.manifest` and lists three posters.
- [ ] Commit trust/manifest.json with the spec, plan and run manifest. Independent review (fresheyes, gpt-6-astra) of the branch before landing.
- [ ] Land: fetch, rebase, gate, push branch, fast-forward main from the primary checkout, push main. Pull main on host-b.
- [ ] Ship: `notice:` on gs18; patched copy of cell-fleet's install-mirror.sh (unless qwar landed) run against /path/to/repos/ai-tools-alerts.
- [ ] Verify: `curl -s https://buzz.ai-tools.md/alerts/manifest.json` content version 2 within 5 minutes. Evidence line 1.

## C2: fresh-machine install

- [ ] Clean HOME-isolated venv in the scratchpad (`python3 -m venv`), `pip install git+https://github.com/Joi/ai-tools-alerts` (README "Without pipx" path), `init`, `pull`, `check`, transcript to a scratch file. HOME isolation keeps the real ~/.config/aitools-alerts untouched except the key file the brief names.
- [ ] Install the hook per README (copy to ~/.claude/hooks/, add the SessionStart entry). Back up ~/.claude/settings.json first.
- [ ] Evidence line 2 (mirror_url printed, transcript path).

## C3: curator halves of items 4 and 5

- [ ] `notice:` on gs18: a SYNTHETIC TEST critical from the test curator key to critical and feed, retracted in this session.
- [ ] `curator post --dry-run`, then live, SYNTHETIC TEST title, product matching an installed product, action upgrade.
- [ ] After the exporter cycle: `pull`; with `auto_apply = ["upgrade"]` in the clean config, `plan <id>` shows auto-apply; `run` executes nothing (exit code and output recorded).
- [ ] `curator retract <root id>`; `pull`; `check` no longer lists it. Evidence lines 4b and 5b.

## C4: akq9-dependent items (3, 4a, 5a, 6)

- [ ] Wait for akq9's landing comment on gs18 (re-probe `kata show ai-tools-alerts#akq9`).
- [ ] host-b: pull, `uv tool install --force --reinstall`, by-hand run away from :20 with `--kev-file` on the fixture. `notice:` first.
- [ ] Confirm posts (ledger event ids), `pull` shows them, hook line in a new Claude Code session, skill prepares and does not run, no iMessage (poster never messages; router dry-runs).
- [ ] `plan` for the relay-bot advisory: upgrade under prepare. Retract the relay-bot thread with the test key. `pull`, `check`.
- [ ] `run --digest-now` twice; first posts one digest, second sends nothing. Evidence lines 3, 4a, 5a, 6.

## C5: manifest v3

- [ ] Sign v3 with the v1 posters, land, ship, mirror serves v3, `pull` drops the curator post. Delete key file and venv (`trash`). Evidence line 7.

## C6: close-out

- [ ] Read `~/.local/state/security-watch/model-turns-<UTC date>` on host-b. Evidence line 8.
- [ ] Post all lines on gr5b and gs18; close gs18 with `--test`; restore ~/.claude/settings.json hook decision noted; /finish-worktree.

## Rollback

v3 is the rollback of v2. A failed ship leaves the v1 or v2 mirror live; the test key's deletion ends its use either way. The settings.json backup restores the hook change.
