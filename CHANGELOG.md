# Changelog

## Unreleased

The CLI accepts an event only when it is a kind 9 message with one `h` tag naming an alert channel in `spec/channels.json`. Before, anything a poster's key had ever signed, anywhere, could be served by the mirror as an alert, a patch or a retraction (security review of 2026-11-23, finding M3). It also refuses a new event dated more than 10 minutes ahead of the local clock: one event dated years ahead used to count as fresh news for years and silenced the warning about a frozen mirror (finding H2). Events already stored are kept whatever their date, so a clock that jumps back cannot undo a stored retraction; they only stop counting as fresh news. The pull summary counts both as `not-channel-post` and `future-dated`. The mirror exporter publishes neither kind of event, which protects installed v0.1.4 readers from the future-dated one.

The CLI now checks that the feed is complete, not only that each post is signed (security review of 2026-11-23, finding H2). Every pull also fetches a certificate from the trust root naming the checkpoint key, and a checkpoint from that key listing the posts that exist. A new post is admitted only when a checkpoint lists it; a mirror that lacks a listed post is refused (`mirror incomplete`); an older checkpoint or certificate is refused; a post the CLI has applied stays applied, so no checkpoint can take a retraction away. The manifest and the certificate are also fetched from a second origin (this repository; `second_origin` in `config.toml`), and the higher manifest wins. `stale_since` now means no fresh checkpoint, in place of the 3-day and 90-day rules. A new state `unverified` (in `check`, `plan` and `run --json`) says why the CLI cannot vouch for completeness: the last pull failed, no fresh checkpoint, an expired certificate. While it holds, `plan` lists nothing under auto-apply. The session-start hook's second line now reads "stale or unverified"; a hook copied from an earlier release still fires, because `stale_since` is non-null in every unverified state. This CLI must not be released before the mirror serves the two new files: until then every pull ends `no checkpoint key certificate`.

The fleet side of the checkpoint: the poster signs one at the end of every run with a key that stays on its own machine (`checkpoint_key_file`, `aitools-alerts-poster checkpoint-keygen`), listing the posts on the mirror and every post the relay acknowledged until the mirror shows it; the relay VM gains one guarded command that only stores it (`ops/vm/mirror-put`); the mirror exporter publishes the certificate and the checkpoint only after verifying them, and the checkpoint only together with every post it lists (`--checkpoint-key`, `--inbox`). None of it is active until the poster's config and the VM are set up (`ops/vm/README.md`).

Two signed documents are defined for that (`aitools_alerts/checkpoint.py`): a certificate, signed by the trust root, naming the one key that may sign feed checkpoints, and the checkpoint itself, which lists the events that exist so that a mirror cannot leave one out unnoticed (security review of 2026-11-23, finding H2). `scripts/sign-checkpoint-key.py` signs the certificate. Installed readers (0.1.5 and earlier) never fetch them.

## 0.1.5 — 2026-11-23

The install path is pinned to a commit. The README and the Quick install prompt name the release tag and its 40-character commit, and both checks (`git tag -v` against `trust/allowed_signers`, and `git rev-parse <tag>^{commit}` compared with that commit) come before any install command; a failed check means install nothing. The lines that installed from a tag name or from the unsigned v0.1.0 are gone, and the README's "Install" section installs whatever verified checkout it runs in. The README on the default branch pins the latest release; the README inside a release pins the one before it, since a commit cannot name its own hash. The mirror page's install line follows the README's.

The build backend is pinned to `setuptools==80.9.0`. `ops/vm/README.md` takes every file it installs on the relay VM from one export of the verified release, never from a checkout or a branch. `SECURITY.md` asks for reports through GitHub's private vulnerability reporting, and `.github/CODEOWNERS` names the owner of the trust, spec, ops, hook, skill and snippet files. `scripts/public-scan.sh` also scans history: every object reachable from every ref, commit messages and identities included.

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
