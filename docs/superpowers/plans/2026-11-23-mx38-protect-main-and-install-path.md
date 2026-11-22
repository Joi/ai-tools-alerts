# Plan: mx38 protect main and the install path

Spec: `docs/superpowers/specs/2026-11-23-mx38-protect-main-and-install-path-design.md`. Gate: `scripts/test-gate.sh` (the public scan, then pytest). Branch: `mx38-protect-main-and-the-install-path`. Not repoman-managed.

Constants used below: previous release `v0.1.4` = `git rev-parse 'v0.1.4^{commit}'` (read it, never type it from memory); new release `v0.1.5`.

## Chunk 0: signing before the first commit

- [ ] On each of the three Macs, check `ssh-keygen -lf <release key>.pub` against `ssh-keygen -lf trust/allowed_signers`'s key; they must match.
- [ ] Set repo-local config in each primary checkout: `gpg.format=ssh`, `user.signingkey=<abs .pub path>`, `commit.gpgsign=true`, `tag.gpgsign=true`, `gpg.ssh.allowedSignersFile=<abs checkout>/trust/allowed_signers`. On the two remote Macs, `git pull --ff-only` on main as well.
- [ ] Verify: in this worktree, `git commit` then `git log --show-signature -1` shows `Good "git" signature for 19930+Joi@users.noreply.github.com`.
- [ ] Verify on each remote Mac too: in the primary checkout, sign a dangling commit (`git commit-tree -S HEAD^{tree} -p HEAD -m probe`, which moves no ref) and `git verify-commit` it; exit 0 with the principal line. This proves the private key is usable there, not only that the config is set.
- [ ] GitHub acceptance: after the branch is pushed, `gh api repos/Joi/ai-tools-alerts/commits/<sha> --jq .commit.verification` reports `verified: true` for EVERY branch commit (`git rev-list origin/main..HEAD`), not only the last. If any reads false (the key not registered as a signing key on the account), stop before the ruleset step.
- [ ] Record the commands and their results in a kata comment on mx38 (host names go there, not in the repo).

## Chunk 1: install path

Files: `README.md` (lines 37–100 today), `mirror/export_mirror.py:64`, `tests/mirror/test_export.py:568-569`, `pyproject.toml:2`, `ops/vm/README.md:25-45,80-90`, `aitools_alerts/__init__.py:3`, `CHANGELOG.md`.

- [ ] `mirror/export_mirror.py`: replace `PIPX_LINE` with
  `RELEASE_TAG = "v0.1.4"`, `RELEASE_COMMIT = "<40-hex of v0.1.4>"`, `PIPX_LINE = f"pipx install git+{REPO_URL}@{RELEASE_COMMIT}"` (define after `REPO_URL`). The page text at :534 and :546 adds "release <tag>, commit <commit>" before the line. Keep the existing Japanese structure.
- [ ] README:
  - Quick install prompt names `v0.1.4` and its commit; steps: clone, `git -c gpg.ssh.allowedSignersFile=trust/allowed_signers tag -v v0.1.4` with the principal and fingerprint, `git rev-parse 'v0.1.4^{commit}'` equals the commit, `git checkout --detach <commit>`, then read the rest of the instructions from that checkout only; stop on any failure.
  - Root check link → `blob/<commit>/trust/root.pub`.
  - Verify section: tag -v, then commit compare, then the mirror fingerprint check; then `git checkout --detach <commit>`, or the `PIPX_LINE` as the remote alternative. Both come after the checks.
  - New "### Install" section: `pipx install --force .` from the verified checkout, init, run; no tag, no commit, no checkout (a release tree's README pins the release before it, and the Quick install prompt hands over to this section).
  - Delete the "pin the tag" block (:78-84) and both v0.1.0 references (:86, :100). Without-pipx line: from the verified checkout only.
  - Replace "Install from a release tag ... not from the default branch" with "Install the pinned commit".
  - Each release's pin line: one sentence saying the README on `main` pins the latest release, and that the README inside a release tag pins the release before it.
- [ ] `pyproject.toml`: `requires = ["setuptools==80.9.0"]`.
- [ ] `ops/vm/README.md`: a "Release files" section after the header: fetch tags, `tag -v`, commit compare, `git archive <commit> | tar -x -C "$rel"`. `buzz-send` is copied from `$rel` and its hash compared with `$rel`'s; the guard, sudoers file and Match block come from `$rel/ops/vm/`; the exporter is `install-mirror.sh "$rel"`. Delete `origin/main`.
- [ ] Version: `pyproject.toml` and `__init__.py` → `0.1.5`. CHANGELOG `## 0.1.5 — 2026-11-23` with the Unreleased entry folded in, plus this release's lines.
- [ ] Tests (`tests/mirror/test_export.py` and a new `tests/test_install_path.py`):
  - `PIPX_LINE` appears in the README and in the page's subscribe block; `RELEASE_COMMIT` is 40 lowercase hex; the README names `RELEASE_TAG` and `RELEASE_COMMIT`; no README line matches `@v\d` or `pipx install git+...@(main|v)`; no README line names `v0.1.0`.
  - README: the first `tag -v` appears before the first `pipx install` and before the first `pip install`; the Quick install block names the tag, the commit and "stop".
  - `ops/vm/README.md` does not contain `origin/main`; its Release files section names the tag, commit, `tag -v`, `rev-parse` and `archive <commit>`; every installed file is taken from `$rel`.
  - The README's Install section has no `git checkout`, no 40-hex and no `@v`.
  - The signer test (`tests/mirror/test_export.py:585-587`) moves from `__version__` to `RELEASE_TAG` and `RELEASE_COMMIT`.
  - If `git` exists and `RELEASE_TAG` resolves in the repo, `rev-parse RELEASE_TAG^{commit}` equals `RELEASE_COMMIT`; otherwise skip.
  - `pyproject.toml` build requires matches `^setuptools==\d+\.\d+\.\d+$`.
- [ ] Verify: `python3 -m pytest -q tests/mirror tests/test_install_path.py`; `python3 -m pip wheel --no-deps -w <scratch> .` succeeds (it fetches setuptools 80.9.0).

Acceptance: spec criteria 1–5.

## Chunk 2: SECURITY.md, CODEOWNERS

- [ ] `SECURITY.md`: report through https://github.com/Joi/ai-tools-alerts/security/advisories/new; in scope: the CLI, trust root and manifest, the poster, the hook and skills, the install instructions; do not open a public issue. Plain prose, no host detail.
- [ ] `.github/CODEOWNERS`: `/trust/ /spec/ /ops/ /hooks/ /skills/ /snippets/ /README.md /pyproject.toml /SECURITY.md /.github/` → `@Joi`.
- [ ] Test: CODEOWNERS covers each of the eight paths in the spec.

## Chunk 3: public scan over history

File: `scripts/public-scan.sh` (python embedded), `tests/test_public_scan.py`.

- [ ] Keep the tip pass as it is, but record its result instead of exiting.
- [ ] Known file: `PUBLIC_SCAN_KNOWN` or `~/.config/aitools-alerts/public-scan.known`. Missing counts as empty. Each non-comment line must be 40 or 64 hex, or exit 2.
- [ ] History pass: `git rev-list --objects --all` (oid, optional path); `git for-each-ref --format='%(objectname) %(objecttype) %(refname)'` (ref names; tag objects added to the object set). A repository without commits yields nothing. Read objects through one `git cat-file --batch` process (writer thread, as in the prototype). Per object:
  - `GIT_NO_REPLACE_OBJECTS=1` for every git call.
  - blob: each line → `"<oid> blob <path>:<n>: <text>"` (rev-list's path is a label only)
  - commit and tag: each line of the raw object → `"<oid> commit:<n>: <text>"`
  - tree: each entry name, parsed from the raw tree → `"<oid> tree entry <name>"`
  - full paths: `git diff-tree --stdin -r -m --root --no-renames --diff-filter=A -z` over `rev-list --all` → `"<commit> path <path>"`, known through that commit.
  - ref name hit: `"ref <refname>"`, never known-listable (ref names change), always fails.
- [ ] Known handling: a hit whose oid is in the known set → count only; stderr summary `public-scan: N known history hits in M objects (listed in <file>)`.
- [ ] `--hit-ids`: print the sorted unique oids of unlisted history hits, one per line, with exit 0 when there are none and 1 otherwise. Never print content.
- [ ] git failure in the history pass → exit 2.
- [ ] Exit: max over the passes with 2 > 1 > 0.
- [ ] Tests (added): a renamed file's old name; a replace ref over a leaking blob; a known tree not covering the same name in a new tree; --hit-ids hiding tip detail; a term spanning directories; a path added by a merge.
- [ ] Tests: a hit only in an earlier commit's blob (removed at the tip) fails and prints the oid; a hit in a commit message fails; a hit in an author name fails; a hit in an annotated tag message fails; a hit in a branch name fails; a listed oid passes with the summary line and no term in stdout or stderr; a bad known-file line exits 2; `--hit-ids` prints ids only; a repo with no commits still passes (existing tests). The test fixture commits with `-c user.name=t -c user.email=t@example.invalid -c commit.gpgsign=false`.
- [ ] Verify: `python3 -m pytest -q tests/test_public_scan.py`. Then build the known file as a BASELINE, never by auto-exempting: on this Mac, `--hit-ids` before any branch commit existed, then check that no listed id is reachable from `origin/main..HEAD` (`git rev-list --objects origin/main..HEAD` ∩ known = ∅). On each remote Mac, after pulling main: `--hit-ids` there; add only the ids that are in this Mac's baseline or reachable only from that Mac's local branches that predate 2026-11-23 (`git for-each-ref --format='%(committerdate:iso) %(refname)'`). Any other id is investigated, not added. Confirm `scripts/test-gate.sh` passes on all three Macs. Put the counts, never the content, on tppb.

Acceptance: spec criterion 7.

## Chunk 4: land, tag, protect, pin

- [ ] Gate: `scripts/test-gate.sh` passes on the committed branch.
- [ ] Review: one fresheyes whole-branch pass (`FRESHEYES_GPT_MODEL=gpt-6-astra` via `DO_IT_REVIEW_GPT_MODEL`), Stage 1 in parallel; record the reviewed HEAD; fix, or rebut; one delta pass `--since <reviewed head>` if a BLOCKER fix changed behaviour.
- [ ] Record `R = git rev-parse HEAD` of the final gated, reviewed branch head: the release commit is R (it carries every change; earlier branch commits such as the version bump alone are incomplete).
- [ ] Push the branch; check every branch commit reads `verified: true` on GitHub (Chunk 0); `gh pr create`; `gh pr merge --merge` (a merge commit keeps R's hash; squash would not).
- [ ] `git fetch origin`; confirm the PR state is MERGED and `git merge-base --is-ancestor R origin/main`; then `git tag -s v0.1.5 -m "ai-tools-alerts 0.1.5" R`; `git -c gpg.ssh.allowedSignersFile=trust/allowed_signers tag -v v0.1.5` passes with the principal line; `test "$(git rev-parse 'v0.1.5^{commit}')" = R`; push the tag; read back `git ls-remote origin refs/tags/v0.1.5^{}` = R.
- [ ] Comment on 8ke5 (landed; rule going on). Comment on each open slice of 9mx8.
- [ ] Read the ruleset (`GET .../rulesets/27857669`), keep its name, target, enforcement, conditions and bypass_actors, and `PUT` it (the update method; PATCH does not exist for rulesets) with rules `non_fast_forward`, `deletion`, `required_signatures`, `pull_request` (`required_approving_review_count: 0`, `dismiss_stale_reviews_on_push: false`, `require_code_owner_review: false`, `require_last_push_approval: false`, `required_review_thread_resolution: false`, `allowed_merge_methods: ["merge","squash"]`). Read it back and check the four rules, zero approvals, the merge methods and an empty bypass list. Post a `notice:` comment with the result.
- [ ] Prove it: `git fetch origin`; make a NEW signed empty commit whose parent is the current `origin/main` tip (`git commit-tree -S origin/main^{tree} -p origin/main -m probe`); check it differs from the tip and verifies locally; `git push origin <probe>:refs/heads/main` must be refused with a message that names the pull-request rule (GH013 "Changes must be made through a pull request"). Then `git ls-remote origin refs/heads/main` is unchanged. Record both.
- [ ] Pin commit on a new branch from `origin/main`: `RELEASE_TAG="v0.1.5"`, `RELEASE_COMMIT=R` in export_mirror, README, ops/vm/README; gate; push; PR; merge under the new rules (doc-only; the reviewed sha named in prose); check GitHub's merge commit reads verified.
- [ ] Remote Macs: `git pull --ff-only` on main, then the known-file step of Chunk 3 and the gate. The poster is reinstalled once (`uv tool install --force --reinstall`) so its version reads 0.1.5; no poster code changed in this branch.
- [ ] Close-out comment and close mx38 on the merge commit.

Rollback: revert PRs; `PUT` the ruleset back to the two rules; a tag cannot be removed, so a bad v0.1.5 is superseded by v0.1.6.
