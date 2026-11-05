# Plan: E3 live acceptance

Spec: docs/superpowers/specs/2026-11-05-e3-live-acceptance-design.md. Scripts live in the session scratchpad; none is committed. Every evidence line goes to docs/superpowers/runs/2026-11-05-e3-live-acceptance.md as it is produced.

## Environment

One environment for reader and publisher, on this Mac, under the real HOME: no ~/.config/aitools-alerts or ~/.local/state/aitools-alerts existed before this run, so the real HOME is a fresh member's HOME for this service. The CLI is the README's "Without pipx" venv at ~/.local/share/aitools-alerts, linked as ~/.local/bin/aitools-alerts; the session-start hook puts ~/.local/bin first on PATH, so a new Claude Code session runs this same install against this same state. The test key is ~/.config/aitools-alerts/key.nsec, where `curator` reads it. The base install proves the no-account reader path; the `[curator]` extra (websockets) is added to the same venv afterwards for the publisher steps.

The hook and the skill are not added to the fleet-managed ~/.claude/settings.json or ~/.claude/skills (both synced from dotfiles-private to every session on every Mac). The hook script goes to ~/.claude/hooks/ as the README says; the README's SessionStart entry and the skill go in a scratch project's .claude/settings.json and .claude/skills/, and the acceptance session starts in that project.

## C1: manifest v2

- [x] Mint the test key (pubkey printed only, file 0600).
- [x] Sign v2 (v1 posters plus test-curator-2026-11-05).
- [x] tests/test_manifest.py pins the exact committed release (version and poster tuples); the gate is green.
- [ ] Independent review (fresheyes, gpt-6-astra); fixes committed.
- [ ] Land: fetch, rebase, gate, push branch, fast-forward main from the primary checkout, push main. Pull main on the poster Mac.
- [ ] Ship: `notice:` on gs18; the patched copy of cell-fleet's install-mirror.sh (qwar open) against the primary checkout.
- [ ] Verify: the mirror's manifest.json content says version 2 within 5 minutes. Evidence line 1.

## C2: fresh-machine install

- [x] Base install, `init`, `pull`, `check`; transcript in the scratchpad.
- [x] Hook script in ~/.claude/hooks/; scratch project with the SessionStart entry and the skill.
- [ ] `pull` again after the ship: manifest v2 accepted. Evidence line 2.

## C3: test key on the relay; curator halves of items 4 and 5

- [ ] `notice:` on gs18: the test pubkey becomes a member of both channels (jibot owns them), removed in C5.
- [ ] `buzz-send channels add-member --channel <uuid> --pubkey <test> --role member`, each channel; `channels members` shows it.
- [ ] Add the `[curator]` extra to the venv.
- [ ] `notice:` on gs18: one SYNTHETIC TEST critical from the test key (Claude Code, affected `<=2.1.318`, fixed 2.1.999, action `upgrade:Claude Code:2.1.999`, alias CVE-2099-0001), retracted by advisory id in this session. Fixed 2.1.999 does not exist on npm, so even an agent that applied it would fail to install anything.
- [ ] `curator post --dry-run`, then live. Record both root event ids.
- [ ] After the next exporter cycle: `pull`; `check` lists it; `plan <advisory id>` with `auto_apply = []` (prepare) and with `auto_apply = ["upgrade"]` (auto-apply); `run` executes no remediation: its output says nothing was executed, Claude Code's version is unchanged afterwards, and no npm or upgrade process ran (inventory probes and the desktop notification's osascript are expected subprocesses). Restore `auto_apply = []`.
- [ ] `curator retract <advisory id>` (both roots); after the next exporter cycle `pull`; `check` no longer lists it. Evidence lines 4b and 5b.

## C4: akq9-dependent items (3, 4a, 5a, 6)

- [ ] Wait for akq9's landing comment on gs18 (re-probe `kata show ai-tools-alerts#akq9`).
- [ ] Before the run: the relay-bot synthetic thread can be retracted for good only by a curator who stays in the manifest. A test-key retraction is dropped with the key at v3 (pull._filter drops every event of a revoked key, its retraction replies included), and the relay-bot root, still trusted, comes back active for 400 days. So the relay-bot thread is retracted with Joi's key, by Joi, before v3 ships: park class a (a credential only Joi holds) with the exact command.
- [ ] the poster Mac: pull, `uv tool install --force --reinstall`, by-hand run away from :20 with `--kev-file` on the fixture. `notice:` first.
- [ ] Confirm the posts (ledger event ids), `pull` shows them, the hook line in a new Claude Code session started in the scratch project, the skill prepares and does not run, no iMessage (the poster never messages; the security-watch router on the poster Mac is `heartbeat`, so it dry-runs).
- [ ] `plan` for the relay-bot advisory under `auto_apply = ["upgrade"]`: upgrade under prepare. If the KEV fixture carries no fixed version the poster emits no upgrade action; record that as it is and file it.
- [ ] `run --digest-now` twice; the first posts one digest, the second sends nothing. Evidence lines 3, 4a, 5a, 6.

## C5: manifest v3 and cleanup

- [ ] Precondition: Joi's retraction of the relay-bot synthetic thread is on the mirror (C4). If it is not, v3 still ships (the test key must not stay trusted), but the run is incomplete: the `check` assertion below fails for that thread, gs18 stays open with the retraction as a named hand action and `needs-review`, and C6 does not close it.
- [ ] Sign v3 (the v1 posters), update the pinned test to version 3 with the poster set {Joi curator, jibot relay-bot} and a count of two, gate, land, ship, mirror serves v3; `pull` drops the test curator's events ("revoked" in the drop counts); `check` shows no synthetic advisory.
- [ ] `buzz-send channels remove-member` for the test pubkey, each channel.
- [ ] Delete the key file with `rm` (not `trash`: the Trash keeps the secret). Remove the venv, its link, ~/.config/aitools-alerts, ~/.local/state/aitools-alerts, the hook script and the scratch project. Evidence line 7.

## C6: close-out

- [ ] Read `<collector-state>/model-turns-<UTC date>` on the poster Mac. Evidence line 8.
- [ ] Post all lines on gr5b and gs18; close gs18 with `--test` only if every synthetic thread is retracted by a curator who stays trusted and verified on `check`; otherwise leave it open with `needs-review` and the remaining action. /finish-worktree.

## Failure cleanup (any step after the v2 ship)

Whatever fails, the run ends with: every synthetic thread it posted retracted by a curator who stays trusted, or listed on gs18 as an open hand action with the command; v3 shipped; the test key off the channels and its file deleted. A step that fails is a finding on ai-tools-alerts with its evidence. If v3 cannot ship, the key file is still deleted, which stops new posts under it; the posts already made stay trusted until v3 ships, and gs18 stays open with that as the remaining action.
