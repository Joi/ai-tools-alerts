# Plan: release tag verification (ai-tools-alerts#b9mz)

Spec: docs/superpowers/specs/2026-11-06-release-tag-verification-design.md.
One chunk; under 80 changed lines outside docs/superpowers, counted on the
committed diff.

## Amendment after the plan delta (pass 2, three BLOCKERs)

The README text below was replaced as built: `### Verify the release`
comes first under "For members: install"; the verify command is a block of
its own; the checks (exit 0, principal line, mirror fingerprint) come next;
then the install block
`git checkout --detach 'refs/tags/v0.1.1^{commit}' && pipx install --force .`
plus `init` (first install) and `run`; then the unsigned v0.1.0 pipx block,
labelled. The README test asserts the detached checkout line. Proven in the
scratchpad: with a branch named `v0.1.1`, `git checkout v0.1.1` lands on the
branch, the detached `refs/tags/...^{commit}` form on the tagged commit.

## Chunk 1: trust file, README, mirror line, CHANGELOG, tests

- [ ] `trust/allowed_signers` (new): the one line from c:837bzb plus one
      newline.
- [ ] `README.md`: insert `### Verify the release` after the pipx code block
      (ends at line 35) and before the "Without pipx" paragraph (line 38).
      Text:

      From v0.1.1 on, release tags are signed with an SSH key on Joi's
      GitHub account; v0.1.0 is unsigned. To check a tag and install exactly
      what you checked:

      ```
      git clone https://github.com/Joi/ai-tools-alerts && cd ai-tools-alerts && git -c gpg.ssh.allowedSignersFile=trust/allowed_signers tag -v v0.1.1
      git checkout v0.1.1 && pipx install .
      ```

      It passes only if it exits 0 and prints
      `Good "git" signature for 19930+Joi@users.noreply.github.com with ED25519 key SHA256:DS1FNZqf0HglC1QEQ50LS4AJny8P8MxvrHRj4vPEqaA`.
      `No principal matched` or `no signature found` is a failure: do not
      install. Run the hook, template and skill commands below from this
      checkout.

      `trust/allowed_signers` comes from the same repository as the tag, so
      the check alone shows only that the two agree. Compare the full
      fingerprint with the copy on the mirror page,
      `https://buzz.ai-tools.md/alerts/`, which the relay VM serves, not
      GitHub; a missing copy is not a pass: wait for it. GitHub's tags page
      shows the tag as Verified, and `https://github.com/Joi.keys` lists the
      key; both depend on the GitHub account alone.
- [ ] `mirror/export_mirror.py`: after `REPO_URL`:
      `VERIFY_URL = REPO_URL + "#verify-the-release"` and
      `RELEASE_SIGNER_FP = "SHA256:DS1FNZqf0HglC1QEQ50LS4AJny8P8MxvrHRj4vPEqaA"  # trust/allowed_signers`.
      In the subscribe `<ul>` after the CLI item:
      `<li>Release tags from v0.1.1 are signed by the SSH key <code>{_esc(RELEASE_SIGNER_FP)}</code>; how to check one before you install: <a href="{_esc(VERIFY_URL)}">{_esc(VERIFY_URL)}</a></li>`.
      In the ja `<ul>` after the CLI item:
      `<li>v0.1.1 以降のリリースタグは SSH 鍵 <code>…FP…</code> で署名されています。インストールの前に確かめる方法: <a href=…>…</a></li>`.
- [ ] `CHANGELOG.md` Unreleased: one bullet: release tags are signed from
      v0.1.1 with an SSH key on the GitHub account; `trust/allowed_signers`
      and README "Verify the release" show how to check one and install from
      the verified checkout; the mirror page carries the key's fingerprint;
      v0.1.0 stays unsigned.
- [ ] `tests/mirror/test_export.py`:
      - `test_index_subscribe_block`: `f'href="{em.VERIFY_URL}"' in sub`,
        `em.RELEASE_SIGNER_FP in sub`,
        `em.VERIFY_URL == em.REPO_URL + "#verify-the-release"`.
      - the ja test (line ~886): `em.VERIFY_URL in ja and em.RELEASE_SIGNER_FP in ja`.
      - new `test_release_signer_file_matches_mirror_and_readme`:
        `(ROOT / "trust/allowed_signers").read_bytes() == b"19930+Joi@users.noreply.github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL3Wufipxot75mXmXHbCsK0PYDG9McQzlxx0NKSq2fZ5\n"`;
        fingerprint computed with `"SHA256:" + base64.b64encode(hashlib.sha256(base64.b64decode(blob)).digest()).decode().rstrip("=")`
        equals `em.RELEASE_SIGNER_FP`; README contains `### Verify the release`,
        `git -c gpg.ssh.allowedSignersFile=trust/allowed_signers tag -v v0.1.1`,
        `git checkout v0.1.1 && pipx install .`, and `em.RELEASE_SIGNER_FP`.
- [x] Proof of the command form (done before the plan review; run manifest
      Notes): scratch dir, `ssh-keygen -q -t ed25519 -N '' -f <scratch>/key`,
      a tag signed with `-c gpg.format=ssh -c user.signingkey=<scratch>/key.pub`.
      With the key in the allowed signers file: exit 0 and `Good "git"
      signature for <principal>`. With a file not naming it: exit 1, `No
      principal matched`. Unsigned tag: exit 1, `no signature found`. The
      scratch key was deleted.

### Verification

- `git add` the new file, commit, then:
- `python3 -m pytest -q tests/mirror/test_export.py`
- `scripts/test-gate.sh` (public scan over `git ls-files`, then the full
  suite); a failure of
  `tests/poster/test_main.py::test_digest_id_recorded_and_printed` is the
  known ai-tools-alerts#rvw5 if that issue is still open.
- `git diff --stat origin/main...HEAD -- . ':!docs/superpowers'` under 80.

### Acceptance

Spec success criteria 1–7.

### Rollback

`git revert` the commit; nothing outside the repo changes.
