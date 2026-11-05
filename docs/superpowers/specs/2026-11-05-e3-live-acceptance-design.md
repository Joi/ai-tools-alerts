# E3: live acceptance of the ai-tools alert service

Kata: jibot-code#gs18 (epic jibot-code#gr5b). Brief: TASK-jibot-code#gs18.md. Design: docs/design.md "## Acceptance". Plan: docs/plan.md Task E3.

## Problem

Every component of the alert service has landed and runs live: the mirror at https://buzz.ai-tools.md/alerts/, the hourly poster, the member CLI with its curator subcommand, the hook and the skills. No one has yet run the design's acceptance list against the live system. Until that happens, "done" rests on unit tests.

## Success criteria

One evidence line per item, posted on jibot-code#gr5b and in this issue's close-out:

1. Manifest v2 adds a test curator key; the mirror serves version 2 within 5 minutes of the ship.
2. A clean venv on this Mac installs in README order, `init`, `pull` against the default mirror_url, `check`, with no account and no key; the session-start hook is installed per README.
3. A synthetic KEV run of the poster posts to #security-critical and #security-feed under jibot's key with SYNTHETIC TEST in the body; `pull` shows it; the hook prints its one line in a new Claude Code session; the skill prepares the upgrade without running it; no iMessage goes to Joi.
4. With `auto_apply = ["upgrade"]`, `plan` puts the relay-bot advisory's upgrade under prepare and the test curator's same advisory under auto-apply; `run` executes nothing.
5. `curator retract <advisory id>` (both roots of a critical) removes the curator thread (test key) and the relay-bot thread (Joi's key, see Departures) from `check` after `pull`.
6. `run --digest-now` posts one digest listing every feed item of the Tokyo day once, the synthetic one marked; a second call the same day sends nothing.
7. Manifest v3 removes the test key; the mirror serves v3; `pull` drops the test curator's events. The key file and the venv are deleted.
8. The model-turn counter on the security-watch host is absent or at most 4.

A non-listed key is shown ignored three ways: `curator post` refuses the test key under manifest v1, `pull` drops events from keys not in the manifest (the relay's own key on day one: "unknown-poster 11"), and after v3 it drops the test key's events as "revoked".

### Departures from the design's acceptance list (set by the dispatch brief)

- Design item 2 says Joi receives the iMessage. The brief asks for the opposite check: no iMessage, because the poster never messages and the security-watch runner on host-b is in `heartbeat` mode, where its router only dry-runs. The iMessage leg is the heartbeat cutover (amplifier-bundle-joi#vy7y), still open; this run does not cover it.
- Design item 6 says the curator advisory "does" apply. The CLI never applies anything: `plan` classifies and the agent applies. This run proves the classification (prepare for the relay bot, auto-apply for the curator) and that `run` executes nothing; that an agent then runs the auto-apply command is the skill's behaviour, not tested live.
- The relay-bot synthetic thread is retracted with Joi's key, not the test key (plan C4): a test-key retraction would be dropped with the key at v3 and the thread would come back active. The test key's retraction is proven on its own post.

Items 3, 4 (relay-bot half), 5 (relay-bot thread) and 6 need ai-tools-alerts#akq9 (`run --kev-file`, `run --digest-now`, the synthetic fixture), open at pickup.

## Approach

Run the eight items in the brief's order, with akq9-dependent items deferred until its landing comment appears; items 1, 2 and the curator halves of 4 and 5 go first.

- Keys: the test curator key is minted with `aitools_alerts.nostr.keygen` into ~/.config/aitools-alerts/key.nsec (0600) by a script that prints only the pubkey. The root key is read only by `scripts/sign-manifest.py` through Kura's get_secret.
- Manifest versions land on main by fast-forward (the repo is not repoman-managed), then ship to the relay VM with the installer (patched copy until jibot-code#qwar lands).
- Live posts: `notice:` on the issue before each, SYNTHETIC TEST in every body, retracted in the same session.
- Any failure is filed on ai-tools-alerts with its evidence, not fixed here, except a one-line doc fix.

## Alternatives considered

- Wait for akq9 before starting: rejected; items 1, 2 and the curator halves do not need it, and the brief allows the reorder.
- Force the digest by editing digest_date in the poster journal: rejected (E2's advice): it hand-edits live dedup state. The `--digest-now` flag from akq9 is the route.
- A curator post with Joi's key: rejected; his key is his. The test key stands in.

## Blast radius and rollback

- Manifest v2 adds one curator; rollback is v3 (step 7), which this run signs anyway. If v3 cannot ship, the key file is still deleted, so no new post can be made under it; posts already made stay trusted until v3 ships.
- Synthetic posts reach members of the two channels; each says SYNTHETIC TEST and is retracted in the session by a curator who stays in the manifest. The CLI drops retracted threads on the next pull.
- Revocation does not survive retraction: removing a curator drops its retraction replies too, so a thread it retracted that another trusted key posted comes back (filed on ai-tools-alerts). Hence Joi's key for the relay-bot thread.
- The digest is a plain-text post by jibot with no advisory block; it lists the synthetic item marked SYNTHETIC TEST, as the brief requires. The CLI never acts on it and v3 does not remove it. It stays on the relay as the record of the check.
- The test key becomes a member of both channels so the relay accepts its posts; it is removed in step 7.
- The installer recreates the caddy container on the relay VM for a few seconds; `notice:` first.

## Assumes

- The relay sends a NIP-42 AUTH challenge to the curator CLI (A7 left this untested; a failure is a finding).
- The mirror exporter includes posts from a key only once the manifest that lists it is on the VM.

## Open questions

None blocking.
