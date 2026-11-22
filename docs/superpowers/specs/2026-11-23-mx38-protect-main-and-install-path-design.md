# mx38: protect main and the install path (C1, strict)

## Problem

The adversarial review of 2026-11-23 (finding C1) showed that one stolen GitHub credential could ship attacker code to members three ways: move a release tag, push to `main` (the Quick install prompt reads the default branch), or edit `ops/vm/buzz-send`, which the VM procedure checks against `origin/main`. The maintainer ruled "strict": `main` gets full protection, and nothing in the service may depend on his attention.

Already live: a ruleset on `main` blocks force-push and deletion, a ruleset on every tag blocks update and deletion, Actions accept only GitHub-owned actions pinned by SHA, and private vulnerability reporting is on. Still open: signed commits, pull requests only, an install path pinned to a commit and checked before install, the VM check, SECURITY.md and CODEOWNERS, and a public scan that reads history (M6), not only the tip.

## Success criteria

1. Every install line in `README.md` names a signed tag and its 40-hex commit. The verification (`git tag -v` against `trust/allowed_signers`, then `git rev-parse <tag>^{commit}` compared with the hash) comes before any install command. No line installs from a branch, from a tag name alone, or from the unsigned v0.1.0.
2. The Quick install prompt names the tag and the commit, and tells the agent to stop if either check fails, then to follow the verified checkout's README from its "Install" section on. That section names no tag and no commit and checks nothing out, so following it inside a release tree installs that tree, not the earlier release its own verify section pins. A test checks that the Install section has no `git checkout`, no 40-hex commit and no `@v` tag.
3. `mirror/export_mirror.py` `PIPX_LINE` is the README's install line verbatim: `pipx install git+https://github.com/Joi/ai-tools-alerts@<commit>`. A test checks that the README names the same tag and commit, and that the tag, when present in the checkout, resolves to that commit.
4. `pyproject.toml` pins the build backend to one exact version (L3).
5. `ops/vm/README.md` takes every file it installs on the VM (`buzz-send`, the login guard, the sudoers file, the sshd Match block, and the exporter copy) from one verified export: `git tag -v`, the commit comparison, then `git archive <commit>` into `$rel`. No install step copies from a checkout, and the page never names `origin/main`. Tests check both, and that the page pins the same tag and commit as the README.
6. `SECURITY.md` points to private vulnerability reporting. `.github/CODEOWNERS` names the owner for `trust/`, `spec/`, `ops/`, `hooks/`, `skills/`, `snippets/`, `README.md` and `pyproject.toml`.
7. `scripts/public-scan.sh` also scans every object reachable from every ref, as stored (`GIT_NO_REPLACE_OBJECTS=1`, so a replace ref cannot show sanitized content in place of the real object): each blob's content, each tree's entry names (lossless, so a renamed file's old name is still read), each commit's raw object (author, committer, message), each annotated tag (tagger, message), and every ref name. A hit in an object listed in a private known-hits file is counted and not printed; any other hit fails. A name is exempt only through the tree that holds it, so the same name in a new tree fails. A ref name is never exempt. Tests cover each object kind, a rename, a replace ref, a name in a new tree and the known-hits file.
8. Release v0.1.5 is cut as a signed tag on the commit that carries 1–7. A second commit, landed by pull request after the rule is on, pins README, `PIPX_LINE` and `ops/vm/README.md` to v0.1.5 and its commit.
9. Live settings: ruleset 27857669 gains `required_signatures` and `pull_request` (0 approvals; merge or squash only, since a GitHub rebase merge writes unsigned commits). A direct push to `main` is refused afterwards, and the refusal is recorded.

### What the rules do not stop

GitHub's `required_signatures` accepts any signature GitHub verifies, and GitHub signs the merge and squash commits it makes itself. With one account and zero required approvals, a stolen token that can open and merge a pull request can still change `main`, the Quick install prompt included. What this issue adds against that token is: a pinned commit that a moved tag or a pushed branch cannot change; client-side checks of the tag against the release key, with the fingerprint cross-checked on the mirror; and an audit trail, since every change is a pull request. Two things would close the rest, and both lie outside this repository's contents: a second origin for the prompt and the pin (the mirror page, filled at deploy time from the verified release; the VM installer lives in another repository), and a required status check that verifies each commit's signer against `trust/allowed_signers` on the base branch. Both are filed as follow-ups. The maintainer's hand actions in the review (a tag key that is not a login key, a third origin) remain his.
10. The primary checkouts on the three fleet Macs that land on this repo sign commits and tags with the release key (repo-local config). Each open slice of 9mx8 gets one comment saying `main` takes pull requests and signed commits only.

## Approach

### Install path: pin the latest existing release

A commit cannot contain its own hash, so the README inside a release tag cannot name that tag's commit. The README and `PIPX_LINE` therefore always pin the latest release that exists when they are written. Each release is two commits:

1. The release commit: the change, the version bump, CHANGELOG. Its README still pins the previous release (here v0.1.4 and its commit). It is tagged, signed.
2. The pin commit, after the tag: README, `PIPX_LINE` and `ops/vm/README.md` name the new tag and its commit. No code change.

The pin is held in three constants: `RELEASE_TAG` and `RELEASE_COMMIT` in `mirror/export_mirror.py`, with `PIPX_LINE` built from them. Tests read the README for the same tag, commit and line, and, where `git` and the tag are present in the checkout, check that `git rev-parse <tag>^{commit}` equals the commit. Two existing assertions tie the pin to `__version__` and move to the constants: `PIPX_LINE.endswith("@v" + __version__)` (`tests/mirror/test_export.py:569`) and the signer test's `tag -v v<__version__>` and tag-name checkout (`:585-587`). Both states pass the tests: the release commit (version 0.1.5, pin v0.1.4) and the pin commit (version 0.1.5, pin v0.1.5).

The mirror is deployed from a release tag, so its page names the release before the one deployed. Its job as a second origin is the fingerprint and the root; a mirror-side pin is a follow-up (see What the rules do not stop).

README changes:
- Quick install prompt: names the tag and commit; the agent clones, verifies the tag, compares the commit, checks out that commit and reads the rest of the instructions from that checkout only; it stops on any failure.
- "Verify the release": unchanged in substance (tag -v with the principal and fingerprint, the mirror cross-check), plus the commit comparison. It names the pinned tag.
- The pinned checkout (`git checkout --detach <commit>`) and the pinned remote install (`pipx install git+...@<commit>`, the line that `PIPX_LINE` repeats) sit in "Verify the release", after the checks. The "Install" section, which the Quick install prompt hands over to, installs only the checkout it runs in (`pipx install --force .`) and names no tag or commit.
- The `trust/root.pub` link names the commit, not the tag.
- The v0.1.0 lines (`README.md:86` and `:100`) go, as does the "pin the tag" wording.

`pyproject.toml`: `requires = ["setuptools==80.9.0"]`. That version supports PEP 639's `license = "MIT"`, which needs 77 or later, and it has been out for months. An exact pin is what `build-system.requires` can express; it takes no hash. The pin is checked by building a wheel locally.

### ops/vm/README.md

A new "Release files" section comes first: fetch tags, `git tag -v <tag>` against `trust/allowed_signers`, compare `rev-parse <tag>^{commit}` with the pinned commit, then `git archive <commit> | tar -x -C "$rel"`. Every install step copies from `$rel`: `buzz-send` (its installed hash compared with `$rel`'s), the guard (hash compared too), the sudoers file, the Match block, and the exporter copy (`install-mirror.sh "$rel"`). The pin is the README's, kept in step by the pin commit and checked by a test.

### SECURITY.md, CODEOWNERS

`SECURITY.md` asks for reports through GitHub's private vulnerability reporting (`/security/advisories/new`) and says what is in scope. `.github/CODEOWNERS` names `@Joi` for the eight paths in criterion 6. Code-owner review is not required by the ruleset, because the repository has one account and an owner cannot approve their own pull request. CODEOWNERS records ownership and requests review once a second maintainer exists.

### Public scan over history

`scripts/public-scan.sh` keeps the tip scan as it is and adds a history pass:

- `git rev-list --objects --all` lists every commit, tree and blob reachable from any ref, with `GIT_NO_REPLACE_OBJECTS=1` set for every git call. `git for-each-ref` adds annotated tag objects and the ref names. `git cat-file --batch` reads each object once.
- It scans each blob's content line by line, each tree's entry names parsed from the raw tree object (rev-list's path is used only as a label), each commit and tag object raw (identity lines and message), and each ref name.
- Full paths: a term can span directories (`a/b`), which no single tree entry holds. `git diff-tree --stdin -r -m --root --no-renames --diff-filter=A` over every commit lists each path where it was added (the root commit against nothing, a merge against each parent), so every path that ever existed is scanned whole. Such a hit is known through the commit that added the path.
- The known-hits file, `$PUBLIC_SCAN_KNOWN` or else `~/.config/aitools-alerts/public-scan.known` (untracked, like the terms file), holds one object id per line, with `#` comments. A hit in a listed object counts toward one stderr summary line and prints no detail. Unlisted hits print as `<oid> <kind> [<path>]:<line>: <text>` and exit 1. A missing known file counts as empty. An unreadable file or a bad line exits 2.
- `--hit-ids` prints the ids of every unlisted history hit and nothing else: no tip detail and no ref name either, though those still set the exit code. The operator records the detail on the private tracker, then appends the ids to the known file.
- Output boundary: without `--hit-ids`, hit detail goes to stdout for the person running the scan, as the tip pass does today. The script's header says that this detail never goes into a public file, commit or pull request. The gate runs on the fleet Macs, and nothing publishes its output.
- The tip pass runs first, then the history pass, and the exit codes combine: 2 wins over 1, and 1 over 0.

Objects already in history that match the terms go into the known file on each fleet Mac that has the terms file, and only their counts go on the private tracker. The detail stays off every public surface. Known objects that only local refs reach are counted on stderr, because pushing those refs would publish them.

Assumes: a history leak that already exists cannot be removed while the force-push block stands; tppb owns that removal (a hand action with GitHub Support or a rewrite). The scan's job is to stop new leaks.

### Live settings and signing (outside the diff)

- Signing: in each Mac's primary checkout, set `gpg.format ssh`, `user.signingkey <the release key's public half, absolute path>`, `commit.gpgsign true`, `tag.gpgsign true` and `gpg.ssh.allowedSignersFile` (absolute path to the checkout's `trust/allowed_signers`). Worktrees share the config. Before setting it, check that the key's fingerprint matches `trust/allowed_signers` on each Mac. The steps go in a kata comment, never the repo.
- Order: land this branch by PR with a merge commit (so the signed release commit keeps its hash), tag v0.1.5 on it, add `required_signatures` and `pull_request` to 27857669, check that a direct push to `main` is refused, then land the pin commit by PR under the new rules. Before the rule goes on, confirm that 8ke5 is landed (its commits are on `main`) and comment on it.

## Alternatives considered

- **Install by tag name only, verified.** Rejected: C1's fix and the brief both require the commit hash, so a moved tag fails the check even when its signature is valid.
- **Write the release hash into the mirror at deploy time** (a file the operator writes on the VM). Rejected for now: it needs a change in the other repository's installer, and the mirror's job as a second origin is the fingerprint and the root. A pin lag of one commit per release costs less.
- **Require code-owner review.** Rejected: with one account it can never be satisfied, and the strict ruling says nothing may depend on the maintainer's attention.
- **Built-in generic patterns and an author-email check in the scan** (M6's full fix, with a pre-push hook). Not in this issue: the brief asks for a history scan. Filed as a follow-up.
- **Scan only public refs.** Rejected: the brief says every ref, and local branches holding pre-rewrite objects are the `push --all` risk that tppb item 4 names.

## Blast radius and rollback

- Repo changes are docs, constants, a build pin and a gate script. Rollback is a revert PR. The scan change can fail the gate on a Mac that lacks the known-hits file; the fix is to copy the file there, or to revert.
- Ruleset changes are live and reversible by `gh api` PATCH. With the rules on, a session that cannot sign or open a PR cannot land; the fix is the signing config.
- Tag v0.1.5 is permanent, because tags are immutable now. It carries the code landed since v0.1.4 (the 8ke5 poster changes and the KEV wording) plus this issue's docs; a mistake in it is fixed by v0.1.6.
- Members on v0.1.4 are unaffected. This branch changes only `__version__` in `aitools_alerts/`. The poster already runs the code on `main`; it is reinstalled once so that its version reads 0.1.5.

## Open questions

None that block the work. The signing key is also a login key on the account (C1); separating the two is one of the maintainer's hand actions in the review and stays out of scope here.
