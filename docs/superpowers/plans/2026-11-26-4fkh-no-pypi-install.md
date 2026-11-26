# Plan: 4fkh no PyPI install

Spec: docs/superpowers/specs/2026-11-26-4fkh-no-pypi-install-design.md

## Chunk 1: text, hint, guard test

- [x] `README.md:97`: replace "There is no package on PyPI; install only as
      above." with the spec's two sentences.
- [x] `aitools_alerts/relay.py:30`: new `INSTALL_HINT` (spec).
- [x] `tests/test_curator.py:265`: assert `pipx install --force '.[curator]'`
      is in stderr and `pip install 'aitools-alerts` is not.
- [x] `tests/test_install_path.py`: `test_no_install_by_the_package_name`
      walks README.md, SECURITY.md, CHANGELOG.md and the text files under
      `aitools_alerts/`, `skills/`, `snippets/`, `hooks/`, `templates/`,
      `mirror/`; fails on `pipx? install ['"]?aitools[-_]alerts` and on a line
      naming PyPI together with "coming" or "will be published"; and asserts the
      README says "do not install from PyPI".
- [x] `CHANGELOG.md` Unreleased: one entry.

Verification: `scripts/test-gate.sh` (exit 0); the new test fails when the old
hint is restored (mutation, by hand, reverted).

Acceptance: spec success criteria 1 to 5.

Rollback: revert the commit.

## Landing

Commit (signed, no-reply address), push the branch, one independent review
(fresheyes, whole branch, covering spec, plan and code in one pass), PR, merge
with `gh pr merge <n> --merge --author-email '19930+Joi@users.noreply.github.com'`,
close 4fkh on the merge commit. Review PR #2 with one comment.
