# Changelog

## Unreleased

An alert whose source names no fixed version no longer says that no fix is published. CISA's Known Exploited Vulnerabilities catalogue carries no version data, so on 2026-11-10 the Chromium and OpenSSH alerts said "no fix is published yet" while both vendors had shipped one. Such an alert now says the source does not state a fixed version, tells the reader to check the vendor for an update, and, for a known-exploited item, to update now if a release is out; the Japanese twin and the digest line say the same. A curator post with no fixed version says "No fixed version stated." The "Fixed in" wording and the wording for a fix the schema cannot express are unchanged.

## 0.1.4 — 2026-11-06

The release signer's principal in `trust/allowed_signers` is the maintainer's GitHub no-reply address instead of a personal email; the earlier signed tags (v0.1.1 to v0.1.3) were re-signed with the same key under that principal, so `git tag -v` with the current `trust/allowed_signers` verifies all of them. The commit history's author address changed the same way. No code change. Tagged `v0.1.4`, signed.

## 0.1.3 — 2026-11-06

README: a "Whom you are trusting" section states that the project's authority rests on Joi Ito and what bounds the trust a member extends. No code change. Tagged `v0.1.3`, signed.

## 0.1.2 — 2026-11-06

README: a "Who this is for" section separates the ai-tools community (the Buzz channels) from everyone else (the public mirror, the feeds and the CLI, no account). No code change. Tagged `v0.1.2`, signed.

## 0.1.1 — 2026-11-06

First signed release, tagged `v0.1.1`. Install it with
`pipx install git+https://github.com/Joi/ai-tools-alerts@v0.1.1`.

- Release tags are signed from v0.1.1 with an SSH key on the GitHub account; v0.1.0 stays unsigned. `trust/allowed_signers` and the README's "Verify the release" show how to check a tag and install from the verified checkout; the mirror page carries the key's fingerprint.

- The CLI takes its home from the password database, not `HOME`, and the session-start hook runs it with a fixed PATH and environment. If you installed the hook from 0.1.0, copy it again and change its `command` in `~/.claude/settings.json` to the absolute path (README).

## 0.1.0 — 2026-11-06

First release, tagged `v0.1.0`. Install it with
`pipx install git+https://github.com/Joi/ai-tools-alerts@v0.1.0`.

- `aitools-alerts`: verifies each alert's signature against the trust
  manifest, matches it against what is installed, and prints the fix
  (`init`, `run`, `plan`, `keygen`, `curator`); English and Japanese.
- `aitools-alerts-poster`: composes and posts advisories to the relay.
- `mirror/export_mirror.py`: the signed static mirror at
  `https://buzz.ai-tools.md/alerts/` (JSON, Atom in two languages, an index
  page, the manifest, and `root.pub`).
- Trust root `afb55ca02209ca12e980bba67262f478b7977b6fdc6bbaf8c3b9fb96983c78a4`,
  also in `trust/root.pub` and at `https://buzz.ai-tools.md/alerts/root.pub`.
