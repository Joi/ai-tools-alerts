# Release v0.1.0: tagged install line, root.pub at a second origin

Kata: ai-tools-alerts#fzr2 (parent jibot-code#gr5b). Finding 4 of the
2026-11-06 independent security read.

## Problem

`README.md` installs `git+https://github.com/Joi/ai-tools-alerts` with no
ref, and `aitools_alerts/__init__.py` pins the trust root in that same code.
Whoever controls the default branch controls the root every new install
trusts, and a member has nothing to compare the root against except the same
repository.

## Success criteria

1. Tag `v0.1.0` (annotated) on the landed head; pushed with
   `git push origin v0.1.0`. Signed when git on the worker Mac has a signing
   key configured (`gpg.format`, `user.signingkey`); otherwise unsigned, and
   the close comment says so. No key is created. At dispatch,
   `git config --show-origin --get-regexp 'gpg|sign'` prints nothing, so the
   tag is unsigned; a follow-up for Joi signs a later tag.
2. Every install line pins the tag: README `pipx install
   git+https://github.com/Joi/ai-tools-alerts@v0.1.0`, the README's
   no-pipx `pip install` line, and `export_mirror.PIPX_LINE`, which the
   mirror index prints in both its English and Japanese subscribe blocks.
   The existing test keeps `PIPX_LINE` equal to the README's.
3. The README names PyPI (`aitools-alerts`) as coming, with no install line.
4. The exporter writes `root.pub` into `--out` beside `manifest.json`: the
   bytes of the checkout's `trust/root.pub`. It refuses (exit 1, nothing
   written) when that file is unreadable or its stripped text is not
   `TRUST_ROOT_PUBKEY`, the key it just verified the manifest with, so the
   mirror never publishes a root other than the one it checked. Tests: the
   file is written byte-identical; a mismatching root.pub refuses and writes
   nothing.
5. README says how to compare the root at three places: the hex in the
   README, `trust/root.pub` at the tag on GitHub, and
   `https://buzz.ai-tools.md/alerts/root.pub` (served by the relay VM,
   a different host from GitHub).
6. `ops/vm/README.md` gains a short section: the VM's exporter copy is
   deployed by pinned commit through cell-fleet's `install-mirror.sh`
   (one unpacked copy per install under `~/.ai-tools-alerts.d/<id>`,
   `~/ai-tools-alerts` a symlink to it), never a `git pull` on the VM.
7. `CHANGELOG.md` with a 0.1.0 entry (the release note). `pyproject.toml`
   and `__version__` already say 0.1.0; unchanged.
8. Under 200 changed lines, excluding the three run artifacts. Full test
   suite passes (`python3 -m pytest -q`).

## Approach

- `mirror/export_mirror.py`: `ROOT_PUB = REPO / "trust" / "root.pub"`;
  a `check_root_pub()` beside `check_manifest()` returns the bytes or raises
  `ExportError`; `export()` reads it before writing anything and appends
  `("root.pub", raw)` right after `manifest.json`. Docstring lists the file.
  `export()` gains a keyword `root_pub=ROOT_PUB` so a test can point it at a
  mismatching file.
- `PIPX_LINE` gains `@v0.1.0`.
- README install section and trust-root paragraph; CHANGELOG.md new.
- `ops/vm/README.md`: one new section at the end ("The exporter copy"),
  touching nothing else, because ai-tools-alerts#w75s edits the same file
  in parallel.

## Alternatives considered

- Write `TRUST_ROOT_PUBKEY + "\n"` instead of the file's bytes: the issue
  asks for the bytes of `trust/root.pub`; the equality check gives the same
  guarantee and keeps the published file identical to the tagged one.
- Publish a GitHub Release object: outward-facing publishing beyond what the
  brief asks; CHANGELOG.md is the release note, and the tag page on GitHub
  shows the annotated tag message.
- Pin by commit SHA in the README: the issue names a tag; a tag is readable
  and the README tells members how to check the root independently.

## Blast radius and rollback

Docs, one exporter file and its tests. Revert the commit; delete the tag with
`git push origin :refs/tags/v0.1.0` if it must go. The VM serves `root.pub`
only after the next `install-mirror.sh` run with a checkout that has this
change; until then the URL returns 404. That redeploy is live state on the
VM and outside this task: a follow-up issue carries it.

## Notes

- Assumes the mirror's Caddy serves any file in `~/alerts-mirror`
  (`/alerts/*` -> `/srv/alerts`, cell-fleet `compose.override.yml`), so no
  Caddy change is needed for `root.pub`.
- Live parallel work: ai-tools-alerts#w75s edits `ops/vm/README.md`;
  rebase late.
