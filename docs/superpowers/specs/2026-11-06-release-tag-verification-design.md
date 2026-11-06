# Release tag verification: allowed_signers and README

Kata: ai-tools-alerts#b9mz. Decision: c:837bzb (2026-11-06).

## Problem

v0.1.0 was tagged unsigned. The trust root is pinned in the code a member
installs, so the tag is what a member trusts, and nothing lets them check who
made it. The release Mac now signs tags with an SSH key that is on Joi's
GitHub account as both an authentication and a signing key (c:837bzb). The
repository has to publish that key in a form `git tag -v` reads and tell
members how to run the check, and how to install exactly what they checked.
The coordinator cuts v0.1.1 signed after this lands; this task cuts no tag.

## Success criteria

1. `trust/allowed_signers` is byte for byte the line in c:837bzb plus one
   newline:
   `19930+Joi@users.noreply.github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL3Wufipxot75mXmXHbCsK0PYDG9McQzlxx0NKSq2fZ5`
2. README, install section, opens with a `### Verify the release`
   subsection, before any install command (amended after the plan delta:
   verify block alone; the install block after the checks is
   `git checkout --detach 'refs/tags/v0.1.1^{commit}' && pipx install --force .`
   so a branch named like the tag cannot be installed and an existing 0.1.0
   is replaced; the unsigned v0.1.0 pipx line follows, labelled as such), with:
   - v0.1.0 is unsigned, v0.1.1 is the first signed tag;
   - the commands: clone, `git -c gpg.ssh.allowedSignersFile=trust/allowed_signers tag -v v0.1.1`,
     then `git checkout v0.1.1 && pipx install .`, so the bytes installed
     are the bytes verified (installing by URL fetches the tag again);
   - pass = exit 0 and the line `Good "git" signature for 19930+Joi@users.noreply.github.com with
     ED25519 key SHA256:DS1FNZqf0HglC1QEQ50LS4AJny8P8MxvrHRj4vPEqaA`;
     `No principal matched` (a good signature by a key not in the file) and
     `no signature found` are failures (measured, run manifest Notes);
   - the hook, template and skill commands below run from that checkout;
   - the trust assumption, stated: the file and the tag come from the same
     repository, so the check alone shows only that they agree. Compare the
     full fingerprint with the copy on the mirror page, served from the relay
     VM, not GitHub; GitHub's Verified badge on the tag and
     `https://github.com/Joi.keys` are further checks that depend on the
     GitHub account alone. A missing mirror copy is not a pass: wait for it.
3. The mirror index's subscribe section has one line giving the full
   fingerprint and linking to
   `https://github.com/Joi/ai-tools-alerts#verify-the-release`; the Japanese
   section gets the matching line in Japanese.
4. CHANGELOG.md "Unreleased" names the signing change and the new file.
5. Tests pin: the file's exact bytes; the exporter's fingerprint constant
   equals the SHA256 fingerprint computed from the key in the file (so the
   mirror cannot carry a different key than the repo); the subscribe and
   Japanese sections carry the fingerprint and the link; README carries the
   heading, the verify command, the install-from-checkout line and the
   fingerprint.
6. The gate (`scripts/test-gate.sh`: public scan + pytest) passes, apart from
   the known failure ai-tools-alerts#rvw5 if it is still open.
7. Under 80 changed lines outside docs/superpowers, counted on the committed
   diff (`git diff --stat origin/main...HEAD -- . ':!docs/superpowers'`), as the earlier runs on this
   build counted (fzr2's run manifest: the budget excludes the /do-it
   artifacts).

## Approach

- New file `trust/allowed_signers`, one line.
- README: the subsection as above. The existing `pipx install …@v0.1.0`
  line stays (the version bump belongs to the release, not this task); the
  new text says v0.1.0 is unsigned.
- `mirror/export_mirror.py`: `VERIFY_URL = REPO_URL + "#verify-the-release"`
  and `RELEASE_SIGNER_FP = "SHA256:DS1F…"`; one `<li>` in each of the
  subscribe and ja lists, escaped with `_esc`.
- Tests in `tests/mirror/test_export.py`.

Assumes: the coordinator signs v0.1.1 with the key in c:837bzb and pushes it;
until then the README command fails with "tag not found", which the README
covers by naming v0.1.1 as the first signed tag. The mirror page carries the
fingerprint only after the VM is next deployed from a commit that has it.

## Alternatives considered

- A dedicated signing key: rejected in c:837bzb.
- Verifying the tag from the CLI: out of scope; pipx does not verify
  signatures, and the CLI already verifies every alert by the pinned root.
- `namespaces="git"` on the allowed_signers line: c:837bzb says "exactly the
  line"; not added.
- `Joi.keys` as the independent origin: rejected as the main check, it is
  the same GitHub account; kept as a further check.
- Bumping the install lines to v0.1.1 now: the tag does not exist yet and
  `PIPX_LINE` is tied to `__version__` by a test; the release does it.

## Blast radius / rollback

Docs, one data file, one line in each list of the mirror page, tests. No key
is created, no tag cut, no live deploy. Rollback: revert the commit.

## Open questions

None.
