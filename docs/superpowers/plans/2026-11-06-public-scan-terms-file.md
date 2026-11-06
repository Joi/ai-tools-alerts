# Plan: public-scan reads its terms from an untracked file

Spec: docs/superpowers/specs/2026-11-06-public-scan-terms-file-design.md
Kata: ai-tools-alerts#a5hk. One chunk; one commit for the deliverable.

## Chunk 1 — scanner, tests, README

- [ ] `scripts/public-scan.sh`
  - Header comment (lines 2-7): say the terms come from `$PUBLIC_SCAN_TERMS`
    or `~/.config/aitools-alerts/public-scan.terms`, one regex fragment per
    line, `#` comments; missing, empty or bad file is exit 2; the file is
    scanned like any other. Remove "the only place the pattern is spelled".
  - Lines 11-14: replace `PATTERN`/`SELF` with a loader: path from the
    environment or the default via `os.path.expanduser`; read bytes; keep
    stripped lines that are non-empty and do not start with `#`; join as
    `(?:f)|(?:g)`; `re.compile(..., re.I)`. On `OSError`, no fragment, or
    a compile failure (`re.error`, `OverflowError`, `RecursionError`,
    `ValueError`): `public-scan: <reason>: <path>` (missing names the variable
    to set) on stderr, exit 2.
  - Remove the `if path == SELF: continue` skip.
- [ ] `tests/test_public_scan.py`
  - Drop `NAME` and the constructed real terms. A fixture writes a terms file
    in `tmp_path` (outside the repo) with `example-forbidden-term`,
    `\bforbidden\.example\b` and a `#` comment; `scan()` passes
    `PUBLIC_SCAN_TERMS` in `env`.
  - Cases: clean passes; hits (upper case, space in file name, binary, file
    name, word-bounded fragment); `netloc`-style near miss stays clean; a term
    in the scanner itself is caught (self-skip gone); unreadable tracked file
    is 2; gate passes 1 through; missing file is 2 with the path on stderr;
    empty and comment-only files are 2; bad fragments (unclosed group, huge
    repetition) are 2; `(?!)` as the only term passes; with the variable
    unset, `HOME=<tmp>` reads `<tmp>/.config/aitools-alerts/public-scan.terms`.
- [ ] `README.md` "Tests" section: one paragraph for contributors (private
  terms file on the maintainers' machines; exit 2 without it; set
  `PUBLIC_SCAN_TERMS` to a file whose fragments match nothing in the tree,
  such as `(?!)`, to run the rest; a fixture term would match the tests).
- [ ] `scripts/test-gate.sh`: unchanged (`git diff --quiet origin/main -- scripts/test-gate.sh`).

## Verification

1. Scratch file (never tracked) holding the 541a6e8 fragments, one per line;
   `PUBLIC_SCAN_TERMS=<it> scripts/test-gate.sh` exits 0.
2. A scratch script runs `git grep -nIiP '<old regex>'` on HEAD: exit 1, no
   output (exit 2 is an error).
3. `scripts/public-scan.sh` with the variable pointing at a missing path:
   exit 2, the path in the message.
4. The ADDED lines of the diff (`git diff origin/main | grep '^+'`) hold none
   of the old terms; the deleted lines hold them by design.
5. `printf '(?!)\n'` as the terms file: `scripts/test-gate.sh` exits 0 (the
   README's contributor example).
6. `git diff --stat origin/main -- scripts tests README.md`: under 150 lines.

## Acceptance

Spec criteria 1-9 hold; independent review findings disposed of.

## Rollback

`git revert` the deliverable commit.
